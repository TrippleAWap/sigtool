"""Quality report for a signature at generation time.

This reports what can be measured without a matcher: how much independent
evidence the signature carries, whether it can be anchored, and whether recovery
was complete. Self-test against the reference matcher and false-positive scans
arrive with ``core/match.py`` in M3 (PLAN.md milestones).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from core.score import DATA_KINDS, ScoredFeature, required_weight

STRONG_MIN_DATA_FEATURES: Final[int] = 2
STRONG_MIN_DATA_KINDS: Final[int] = 2
STRONG_MIN_ANCHORS: Final[int] = 2
SMALL_FUNCTION_INSTRUCTIONS: Final[int] = 12


@dataclass(frozen=True, slots=True)
class QualityReport:
    """Verdict and supporting counts for one generated signature."""

    verdict: str
    confidence: str
    data_features: int
    required_features: int
    optional_features: int
    anchor_count: int
    evidence: float
    notes: tuple[str, ...]

    @property
    def is_strong(self) -> bool:
        return self.verdict == "strong"


def quality_report(
    *,
    scored: Sequence[ScoredFeature],
    anchors: Sequence[str],
    confidence: str,
    instruction_count: int,
    degraded: bool,
) -> QualityReport:
    """Classify a signature as ``strong``, ``weak``, or ``small``.

    ``strong`` requires at least two anchors, two data features, and two
    different data kinds. ``small`` is reserved for functions with too few
    instructions to anchor; everything else is ``weak``.
    """
    data = [item for item in scored if item.feature.kind in DATA_KINDS]
    data_kinds = {item.feature.kind for item in data}
    required = [item for item in scored if item.required]
    optional = [item for item in scored if not item.required]
    is_small = instruction_count <= SMALL_FUNCTION_INSTRUCTIONS

    notes: list[str] = []
    if degraded:
        notes.append("recovery was partial; bounds may be truncated")
    if is_small:
        notes.append(
            f"small function ({instruction_count} instructions); match with neighbour context"
        )
    if not anchors:
        notes.append("no data anchors; Tier 0 cannot trigger")
    elif len(anchors) < STRONG_MIN_ANCHORS:
        notes.append("only one data anchor; Tier 0 shortlist is broad")
    if not data:
        notes.append("no string, constant, or callee features")
    if len(data_kinds) < STRONG_MIN_DATA_KINDS:
        notes.append("evidence comes from a single feature kind")
    if confidence == "low":
        notes.append("signature carries low confidence")

    if is_small:
        verdict = "small"
    elif (
        len(anchors) >= STRONG_MIN_ANCHORS
        and len(data) >= STRONG_MIN_DATA_FEATURES
        and len(data_kinds) >= STRONG_MIN_DATA_KINDS
        and not degraded
    ):
        verdict = "strong"
    else:
        verdict = "weak"

    return QualityReport(
        verdict=verdict,
        confidence=confidence,
        data_features=len(data),
        required_features=len(required),
        optional_features=len(optional),
        anchor_count=len(anchors),
        evidence=required_weight(scored),
        notes=tuple(notes),
    )
