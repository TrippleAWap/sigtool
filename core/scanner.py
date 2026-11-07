"""Runtime reference scanner: page hashing, incremental passes, budgets.

The scanner wraps the reference matcher for live use (M6). Everything
expensive is made incremental:

* **Page hashing** — every region is split into 4 KiB pages; a page's CRC-32
  identifies it across passes. A region whose pages are all unchanged is
  skipped entirely, and its matches carry over.
* **Prioritization** — regions are scanned private-memory first, then modified
  or newly executable ones, then untouched module pages.
* **Reference index** — the data-reference index is built per region and
  re-indexed only when that region changes, so string-anchor discovery stays
  incremental too.
* **Budgets** — Tier 0 (needle search) always runs; Tier 1 (recovery) is
  rate-limited per pass by :class:`core.match.RecoveryBudget`.

The scanner never writes, never suspends, and reads only through the
``ByteSource`` (AGENTS.md rule 9). All state is deterministic: hashes are
CRC-32 over page bytes — never Python's salted ``hash()`` (rule 3) — and they
are never persisted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final
from zlib import crc32

from core.match import (
    Match,
    RecoveryBudget,
    ReferenceIndex,
    region_anchor_hits,
    scan_candidates,
)
from core.sigfile import Signature
from core.source import ByteSource, Region

PAGE_BITS: Final[int] = 12
PAGE_SIZE: Final[int] = 1 << PAGE_BITS

# Region priorities: private memory first, then changed image memory, then
# unchanged image memory (the common incremental case).
PRIORITY_PRIVATE: Final[int] = 0
PRIORITY_CHANGED: Final[int] = 1
PRIORITY_UNCHANGED: Final[int] = 2


@dataclass(frozen=True, slots=True)
class ScanHit:
    """One accepted match with the pass that produced it."""

    signature_id: str
    name: str
    address: int
    end: int
    score: float
    region: str
    first_seen: int


@dataclass(slots=True)
class _SignatureState:
    """Cached Tier 0 hits and matches for one signature."""

    hits: dict[int, list[tuple[int, str]]] = field(default_factory=dict)
    matches: tuple[Match, ...] = ()
    first_seen: dict[int, int] = field(default_factory=dict)


@dataclass(slots=True)
class _RegionState:
    """One region's page hashes and change classification for this pass."""

    region: Region
    hashes: tuple[int, ...]
    private: bool
    changed: bool
    new: bool


@dataclass(slots=True)
class ScanReport:
    """What one pass did; the profile script records these counters."""

    pass_number: int
    hits: tuple[ScanHit, ...]
    new_hits: int
    regions_scanned: int
    regions_skipped: int
    regions_private: int
    pages_hashed: int
    budget_remaining: int
    budget_exhausted: bool
    index_instructions: int
    index_truncated: bool


def _priority(state: _RegionState) -> int:
    if state.private:
        return PRIORITY_PRIVATE
    if state.changed:
        return PRIORITY_CHANGED
    return PRIORITY_UNCHANGED


class SignatureScanner:
    """Incrementally match a fixed signature set against one source."""

    def __init__(
        self,
        source: ByteSource,
        signatures: Sequence[Signature],
        *,
        budget: RecoveryBudget | None = None,
        index: ReferenceIndex | None = None,
    ) -> None:
        if not signatures:
            raise ValueError("the scanner needs at least one signature")
        self._source = source
        # Signature identities are precomputed once: `signature_id` serialises
        # the whole document to YAML, which is far too expensive to repeat per
        # pass (measured: it dominated an otherwise skipped pass).
        self._signatures: tuple[tuple[Signature, str], ...] = tuple(
            (signature, signature.signature_id) for signature in signatures
        )
        self._pass_budget = budget if budget is not None else RecoveryBudget()
        self._index = index if index is not None else ReferenceIndex()
        self._owns_index = index is None
        self._regions: dict[int, _RegionState] = {}
        self._states: dict[str, _SignatureState] = {
            signature_id: _SignatureState() for _, signature_id in self._signatures
        }
        self._pass = 0

    @property
    def index(self) -> ReferenceIndex:
        return self._index

    def scan_pass(self) -> ScanReport:
        """Run one incremental pass; unchanged regions carry matches over."""
        self._pass += 1
        regions = self._classify()
        budget = RecoveryBudget(remaining=self._pass_budget.remaining)

        private = 0
        regions_scanned = 0
        regions_skipped = 0
        for region_state in sorted(
            regions.values(), key=lambda item: (_priority(item), item.region.start)
        ):
            if region_state.private:
                private += 1
            if region_state.changed:
                regions_scanned += 1
                if self._owns_index and region_state.region.executable:
                    self._index.index_region(self._source, region_state.region)
            else:
                regions_skipped += 1

        budget_exhausted = False
        for signature, signature_id in self._signatures:
            state = self._states[signature_id]
            hits, recomputed = self._signature_hits(signature, regions, state)
            if not recomputed:
                continue
            state.matches = scan_candidates(
                self._source,
                signature,
                [hit for per_region in hits.values() for hit in per_region],
                budget=budget,
            )
            for match in state.matches:
                state.first_seen.setdefault(match.address, self._pass)
            state.first_seen = {
                address: seen
                for address, seen in state.first_seen.items()
                if any(match.address == address for match in state.matches)
            }
            if budget.remaining <= 0:
                budget_exhausted = True

        report_hits: list[ScanHit] = []
        new_hits = 0
        for signature, signature_id in self._signatures:
            signature_state = self._states[signature_id]
            for match in signature_state.matches:
                first_seen = signature_state.first_seen.get(match.address, self._pass)
                if first_seen == self._pass:
                    new_hits += 1
                report_hits.append(
                    ScanHit(
                        signature_id=signature_id,
                        name=signature.name,
                        address=match.address,
                        end=match.end,
                        score=match.score,
                        region=self._region_name(match.address, regions),
                        first_seen=first_seen,
                    )
                )
        report_hits.sort(key=lambda hit: (hit.first_seen, hit.name, hit.address))

        self._pass_budget.remaining = budget.remaining
        return ScanReport(
            pass_number=self._pass,
            hits=tuple(report_hits),
            new_hits=new_hits,
            regions_scanned=regions_scanned,
            regions_skipped=regions_skipped,
            regions_private=private,
            pages_hashed=sum(len(state.hashes) for state in regions.values()),
            budget_remaining=budget.remaining,
            budget_exhausted=budget_exhausted,
            index_instructions=self._index.instructions,
            index_truncated=self._index.truncated,
        )

    # -- internals ---------------------------------------------------------

    def _classify(self) -> dict[int, _RegionState]:
        """Refresh per-region page hashes; classify new, changed, and gone."""
        current: dict[int, _RegionState] = {}
        for region in self._source.regions():
            hashes = tuple(
                crc32(bytes(region.data[offset : offset + PAGE_SIZE]))
                for offset in range(0, region.size, PAGE_SIZE)
            )
            previous = self._regions.get(region.start)
            private = self._source.module_for(region.start) is None
            if previous is not None and previous.hashes == hashes:
                current[region.start] = _RegionState(
                    region=region, hashes=hashes, private=private, changed=False, new=False
                )
            else:
                current[region.start] = _RegionState(
                    region=region,
                    hashes=hashes,
                    private=private,
                    # New regions are scanned this pass like modified ones;
                    # `new` keeps the distinction for the report.
                    changed=True,
                    new=previous is None,
                )
        for start in self._regions:
            if start not in current:
                self._index.drop_region(start)
                for state in self._states.values():
                    state.hits.pop(start, None)
        self._regions = current
        return current

    def _signature_hits(
        self,
        signature: Signature,
        regions: dict[int, _RegionState],
        state: _SignatureState,
    ) -> tuple[dict[int, list[tuple[int, str]]], bool]:
        """Anchor hits for one signature, recomputing only changed regions."""
        changed = {start for start, region in regions.items() if region.changed}
        touched = set(state.hits) & changed
        if self._pass > 1 and not touched:
            return state.hits, False

        hits: dict[int, list[tuple[int, str]]] = {}
        for start, region_state in sorted(regions.items()):
            if not region_state.changed and start in state.hits:
                hits[start] = state.hits[start]
            else:
                hits[start] = region_anchor_hits(region_state.region, signature)
        state.hits = hits
        return hits, True

    def _region_name(self, address: int, regions: dict[int, _RegionState]) -> str:
        state = regions.get(address)
        if state is not None:
            return state.region.name
        for start in sorted(regions, reverse=True):
            if start <= address:
                return regions[start].region.name
        return "unknown"
