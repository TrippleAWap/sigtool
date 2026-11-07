"""Single entry point: address plus byte source in, signature and report out.

``generate`` is deliberately thin. It composes the one shared extractor with
scoring, document serialisation, and the quality report, and adds only
provenance. Every front-end calls this function so the CLI, IDA plugin, and
future scanner cannot diverge.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from core.features import Feature, extract
from core.match import Match, self_test
from core.recover import RecoveryLimits, recover
from core.score import (
    ScoredFeature,
    choose_thresholds,
    confidence_for,
    score_features,
    select_anchors,
)
from core.sigfile import SampleProvenance, Signature, SignatureFeature
from core.source import ByteSource
from core.validate import QualityReport, quality_report

DEFAULT_NAME_PREFIX: Final[str] = "sub_"


@dataclass(frozen=True, slots=True)
class GenerationResult:
    signature: Signature
    report: QualityReport
    #: The self-test match that allowed this signature to be emitted.
    match: Match

    def to_yaml(self) -> str:
        return self.signature.to_yaml()


def generate(
    source: ByteSource,
    addr: int,
    *,
    name: str | None = None,
    opt: str | None = None,
    tool: str | None = None,
    idf: Mapping[str, float] | None = None,
    limits: RecoveryLimits | None = None,
) -> GenerationResult:
    """Generate a signature for the function containing ``addr``.

    ``opt`` and ``tool`` are provenance only; they never affect features or
    weights, so signatures stay comparable across build settings.
    """
    recovered = recover(source, addr, limits=limits)
    features: tuple[Feature, ...] = extract(source, recovered)
    scored: tuple[ScoredFeature, ...] = score_features(features, idf=idf)
    anchors = select_anchors(scored)
    required_count = sum(1 for item in scored if item.required)
    thresholds = choose_thresholds(anchor_count=len(anchors), required_count=required_count)
    confidence = confidence_for(
        multi_arch=False,
        is_small=recovered.is_small,
        anchor_count=len(anchors),
    )

    module = source.module_for(addr)
    rva = addr - module.base if module is not None else 0
    sample = SampleProvenance(
        arch=source.arch.value,
        module=module.name if module is not None else "image",
        rva=rva,
        opt=opt,
        tool=tool,
    )
    signature = Signature(
        name=name or _default_name(source, addr, module_name=sample.module, rva=rva),
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
        provenance=(sample,),
    )
    report = quality_report(
        scored=scored,
        anchors=anchors,
        confidence=confidence,
        instruction_count=recovered.instruction_count,
        degraded=recovered.degraded,
    )
    # Rule 7: never emit a signature the reference matcher cannot re-find
    # (or, when the matcher cannot reach the function, one that does not
    # describe its bytes exactly).
    match = self_test(signature, source, recovered.start, limits=limits)
    return GenerationResult(signature=signature, report=report, match=match)


def _default_name(source: ByteSource, addr: int, *, module_name: str, rva: int) -> str:
    symbol = source.name_for_address(addr)
    if symbol:
        return symbol
    return f"{DEFAULT_NAME_PREFIX}{module_name}+0x{rva:x}"
