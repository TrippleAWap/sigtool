"""Deterministic feature weighting, anchor selection, and match thresholds.

Weights express *evidence*, not identity. Data features (strings, constants,
callees) carry the signature; shape features only corroborate, so they are
optional and light. Every weight is rounded and every ordering is explicit, so
the same input yields the same document on any machine.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from core.features import (
    FEATURE_KINDS,
    KIND_CALLEE,
    KIND_CFG,
    KIND_CONST,
    KIND_OPS,
    KIND_STR,
    Feature,
)

# Base discriminative power per kind. Shape features are deliberately weak: a
# bucket match is common and must never carry a signature on its own.
BASE_WEIGHTS: Final[Mapping[str, float]] = {
    KIND_STR: 1.0,
    KIND_CALLEE: 0.9,
    KIND_CONST: 0.7,
    KIND_CFG: 0.25,
    KIND_OPS: 0.15,
}

DATA_KINDS: Final[frozenset[str]] = frozenset({KIND_STR, KIND_CONST, KIND_CALLEE})
OPTIONAL_KINDS: Final[frozenset[str]] = frozenset({KIND_CFG, KIND_OPS})

MAX_ANCHORS: Final[int] = 4
WEIGHT_DECIMALS: Final[int] = 3
MIN_WEIGHT: Final[float] = 0.001

# A signature with fewer anchors can only be matched by weighted comparison, so
# it needs more of its evidence to line up.
MATCH_THRESHOLD_TWO_ANCHORS: Final[float] = 0.75
MATCH_THRESHOLD_ONE_ANCHOR: Final[float] = 0.85
MATCH_THRESHOLD_NO_ANCHORS: Final[float] = 0.95

# min_distinct is capped: beyond three independent features, extra requirements
# mostly hurt recall on edited code.
MAX_MIN_DISTINCT: Final[int] = 3


@dataclass(frozen=True, slots=True)
class ScoredFeature:
    """A feature with its weight and whether a match must include it."""

    feature: Feature
    weight: float
    required: bool

    @property
    def key(self) -> str:
        return feature_key(self.feature)


@dataclass(frozen=True, slots=True)
class Thresholds:
    match: float
    min_distinct: int


def feature_key(feature: Feature) -> str:
    """Canonical anchor form: ``kind:value``."""
    return f"{feature.kind}:{feature.value}"


def build_idf(feature_sets: Iterable[Sequence[Feature]]) -> dict[str, float]:
    """Inverse document frequency per feature key over a reference corpus.

    ``idf = ln((N + 1) / (df + 1)) + 1`` keeps common features near 1.0 and
    boosts rare ones. The result is key-sorted so callers cannot leak mapping
    order into output.
    """
    documents = list(feature_sets)
    if not documents:
        return {}
    document_frequency: Counter[str] = Counter()
    for features in documents:
        for key in {feature_key(feature) for feature in features}:
            document_frequency[key] += 1
    total = len(documents)
    weights = {
        key: round(math.log((total + 1) / (count + 1)) + 1.0, WEIGHT_DECIMALS)
        for key, count in document_frequency.items()
    }
    return dict(sorted(weights.items()))


def score_features(
    features: Sequence[Feature],
    *,
    idf: Mapping[str, float] | None = None,
) -> tuple[ScoredFeature, ...]:
    """Assign weights and required flags, sorted by ``(kind, value)``."""
    scored: list[ScoredFeature] = []
    for feature in features:
        if feature.kind not in FEATURE_KINDS:
            raise ValueError(f"unknown feature kind {feature.kind!r}")
        weight = BASE_WEIGHTS[feature.kind] * _rarity(feature)
        if idf is not None:
            weight *= idf.get(feature_key(feature), 1.0)
        scored.append(
            ScoredFeature(
                feature=feature,
                weight=max(MIN_WEIGHT, round(weight, WEIGHT_DECIMALS)),
                required=feature.kind not in OPTIONAL_KINDS,
            )
        )
    scored.sort(key=lambda item: (item.feature.kind, item.feature.value))
    return tuple(scored)


def _rarity(feature: Feature) -> float:
    """Small multipliers for features that are inherently more specific."""
    if feature.kind == KIND_STR:
        # Longer literals are rarer and survive edits better.
        return 1.0 + min(0.5, len(feature.value) / 80.0)
    if feature.kind == KIND_CONST:
        try:
            value = int(feature.value, 16)
        except ValueError:
            return 1.0
        # Small constants are ubiquitous in compiler output.
        return 0.6 if value < 0x100 else 1.0
    return 1.0


def select_anchors(scored: Sequence[ScoredFeature], *, limit: int = MAX_ANCHORS) -> tuple[str, ...]:
    """Pick the rarest, heaviest data features as Tier 0 anchors.

    Anchors are ordered by weight (desc), then kind and value, so the list is
    stable for identical input. Fewer than two anchors is normal for small
    functions and is reported in the quality verdict.
    """
    data = [item for item in scored if item.feature.kind in DATA_KINDS]
    data.sort(key=lambda item: (-item.weight, item.feature.kind, item.feature.value))
    return tuple(item.key for item in data[:limit])


def choose_thresholds(*, anchor_count: int, required_count: int) -> Thresholds:
    if anchor_count >= 2:
        match = MATCH_THRESHOLD_TWO_ANCHORS
    elif anchor_count == 1:
        match = MATCH_THRESHOLD_ONE_ANCHOR
    else:
        match = MATCH_THRESHOLD_NO_ANCHORS
    return Thresholds(
        match=match,
        min_distinct=max(1, min(MAX_MIN_DISTINCT, required_count)),
    )


def confidence_for(*, multi_arch: bool, is_small: bool, anchor_count: int) -> str:
    """Confidence tag stored in the signature (see spec §7)."""
    if is_small or anchor_count == 0:
        return "low"
    return "multi-arch" if multi_arch else "single-arch"


def required_weight(scored: Sequence[ScoredFeature]) -> float:
    """Total weight of the features a match must include."""
    total = sum(item.weight for item in scored if item.required)
    return round(total, WEIGHT_DECIMALS)
