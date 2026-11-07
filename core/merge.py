"""Multi-sample merging: one signature from several builds of one function.

Merging is the M4 answer to cross-optimisation and cross-architecture recall:
no single build carries every feature, but the intersection is stable and the
differences are real. The rules (spec §8):

* Features present in **every** sample stay required and keep full weight.
* Features present in a **strict subset** are demoted: optional, half weight.
  Different bucket values of the same shape feature therefore widen the match
  instead of failing it — each observed value stays as optional evidence.
* Anchors are only chosen among features every sample actually contains, so
  Tier 0 cannot trigger on bytes a sample does not have.
* The merged signature must self-test against **every** sample (rule 7); a
  signature that cannot be re-found in one of its own samples is refused.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from core.errors import SelfTestError, SigToolError
from core.features import Feature
from core.generate import GenerationResult, generate
from core.match import Match, self_test
from core.recover import RecoveryLimits
from core.score import (
    ScoredFeature,
    choose_thresholds,
    confidence_for,
    score_features,
    select_anchors,
)
from core.sigfile import Signature, SignatureFeature
from core.source import ByteSource
from core.validate import quality_report

#: Weight multiplier for features that only some samples carry.
DEMOTE_FACTOR: Final[float] = 0.5


class MergeError(SigToolError):
    """The samples cannot be merged into one honest signature."""


@dataclass(frozen=True, slots=True)
class MergeSample:
    """One build of the function to merge."""

    source: ByteSource
    addr: int
    opt: str | None = None
    tool: str | None = None


def merge(
    samples: Sequence[MergeSample],
    *,
    name: str | None = None,
    limits: RecoveryLimits | None = None,
) -> GenerationResult:
    """Merge the samples into one signature and self-test it on every sample."""
    if len(samples) < 2:
        raise MergeError("merging needs at least two samples")
    results = [
        generate(sample.source, sample.addr, opt=sample.opt, tool=sample.tool, limits=limits)
        for sample in samples
    ]
    if name is None:
        name = results[0].signature.name

    per_sample = [{feature.key: feature for feature in _features_of(result)} for result in results]
    counts: Counter[str] = Counter()
    for features in per_sample:
        # Counter.update would treat dict values as counts; count the keys.
        counts.update(features.keys())

    scored = _merged_score(counts, per_sample)
    stable = {key for key, count in counts.items() if count == len(samples)}
    anchors = tuple(key for key in select_anchors(scored) if key in stable)
    thresholds = choose_thresholds(
        anchor_count=len(anchors),
        required_count=sum(1 for item in scored if item.required),
    )
    confidence = confidence_for(
        multi_arch=len({sample.source.arch for sample in samples}) > 1,
        is_small=all(result.report.verdict == "small" for result in results),
        anchor_count=len(anchors),
    )
    signature = Signature(
        name=name,
        features=tuple(
            SignatureFeature(
                kind=item.feature.kind,
                value=item.feature.value,
                weight=item.weight,
                required=item.required,
            )
            for item in scored
        ),
        anchors=anchors,
        match_threshold=thresholds.match,
        min_distinct=thresholds.min_distinct,
        confidence=confidence,
        provenance=tuple(result.signature.provenance[0] for result in results),
    )

    match: Match | None = None
    for sample, result in zip(samples, results, strict=True):
        try:
            match = self_test(signature, sample.source, result.match.address, limits=limits)
        except SelfTestError as error:
            raise MergeError(
                f"merged signature {name!r} failed self-test on a "
                f"{sample.source.arch.value} sample: {error}"
            ) from error
    assert match is not None  # samples is non-empty

    report = quality_report(
        scored=scored,
        anchors=anchors,
        confidence=confidence,
        instruction_count=max(_instruction_hint(result) for result in results),
        degraded=any(_degraded(result) for result in results),
    )
    return GenerationResult(signature=signature, report=report, match=match)


def _merged_score(
    counts: Counter[str], per_sample: list[dict[str, Feature]]
) -> tuple[ScoredFeature, ...]:
    """Weight the union of features, demoting the ones not every sample has."""
    total = len(per_sample)
    union: dict[str, Feature] = {}
    for features in per_sample:
        for key, feature in features.items():
            union.setdefault(key, feature)
    scored = list(score_features(sorted(union.values(), key=lambda feature: feature.key)))
    demoted: list[ScoredFeature] = []
    for item in scored:
        present_everywhere = counts[item.key] == total
        if present_everywhere:
            demoted.append(item)
            continue
        # Demote: optional, and never allowed to carry the signature alone.
        demoted.append(
            ScoredFeature(
                feature=item.feature,
                weight=max(0.001, round(item.weight * DEMOTE_FACTOR, 3)),
                required=False,
            )
        )
    demoted.sort(key=lambda item: (item.feature.kind, item.feature.value))
    return tuple(demoted)


def _features_of(result: GenerationResult) -> tuple[Feature, ...]:
    return tuple(Feature(feature.kind, feature.value) for feature in result.signature.features)


def _instruction_hint(result: GenerationResult) -> int:
    hint = result.match.end - result.match.address
    return max(int(hint), 0)


def _degraded(result: GenerationResult) -> bool:
    return any("recovery was partial" in note for note in result.report.notes)
