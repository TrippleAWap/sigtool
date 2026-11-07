"""Runtime scanner tests: incrementalism, priorities, budgets, and the index."""

from __future__ import annotations

from dataclasses import replace
from typing import Final

import pytest

from core.arch import Arch
from core.generate import generate
from core.match import Match, RecoveryBudget, ReferenceIndex, scan, self_test
from core.scanner import PAGE_SIZE, SignatureScanner
from core.sigfile import SampleProvenance, Signature, SignatureFeature
from core.source import MemorySource, Module, Region
from tests.support import strong_source

CODE: Final[bytes] = (
    b"\x48\x8d\x3d"
    + (0x2000 - 0x1007).to_bytes(4, "little", signed=True)
    + b"\xb8\x78\x56\x34\x12\xc3"
)
SECOND: Final[bytes] = b"\x31\xc0\xc3"  # xor eax, eax; ret
BANNER: Final[bytes] = b"generate banner literal\x00"
SECOND_ADDR: Final[int] = 0x1060


def make_source(*, with_helper: bool = True) -> MemorySource:
    text = CODE + b"\x00" * (SECOND_ADDR - 0x1000 - len(CODE)) + SECOND
    text_region = Region("text", 0x1000, len(text), text, executable=True)
    rodata = Region("rodata", 0x2000, len(BANNER), BANNER)
    module = Module(
        name="fixture",
        base=0x1000,
        size=0x2000 + len(BANNER) - 0x1000,
        regions=(text_region, rodata),
        exports={"helper": SECOND_ADDR} if with_helper else {},
        functions={SECOND_ADDR: "second_fn"} if with_helper else {},
    )
    return MemorySource(Arch.X64, [text_region, rodata], [module])


class MutableSource(MemorySource):
    """A MemorySource whose regions can change between scanner passes."""

    def __init__(self) -> None:
        text = CODE + b"\x00" * (SECOND_ADDR - 0x1000 - len(CODE)) + SECOND
        self._live: list[Region] = [
            Region("text", 0x1000, len(text), text, executable=True),
            Region("rodata", 0x2000, len(BANNER), BANNER),
        ]
        super().__init__(Arch.X64, tuple(self._live))

    def regions(self) -> tuple[Region, ...]:
        return tuple(self._live)

    def mutate_text(self, data: bytes) -> None:
        self._live[0] = replace(self._live[0], data=data)


def two_signatures() -> tuple[Signature, Signature]:
    source = make_source()
    first = generate(source, 0x1000, name="target").signature
    second = generate(source, SECOND_ADDR, name="second_fn").signature
    return first, second


def test_first_pass_finds_matches_and_second_pass_skips_everything() -> None:
    source = make_source()
    first, second = two_signatures()
    scanner = SignatureScanner(source, [first, second])

    report = scanner.scan_pass()
    assert report.pass_number == 1
    assert report.new_hits == 2
    assert {hit.name for hit in report.hits} == {"target", "second_fn"}
    assert report.regions_skipped == 0

    again = scanner.scan_pass()
    assert again.pass_number == 2
    assert again.regions_scanned == 0
    assert again.regions_skipped == report.regions_scanned + report.regions_skipped
    assert again.new_hits == 0
    assert [hit.address for hit in again.hits] == [hit.address for hit in report.hits]
    assert all(hit.first_seen == 1 for hit in again.hits)


def test_modified_region_is_rescanned_and_new_hits_reported() -> None:
    source = MutableSource()
    scanner = SignatureScanner(source, [generate(source, 0x1000, name="target").signature])
    first = scanner.scan_pass()
    assert first.new_hits == 1

    # Patching an unrelated byte changes the page hash and forces a rescan,
    # which keeps the match (the function is still there). The match is not
    # "new": first_seen stays at the pass that first observed the function.
    source.mutate_text(CODE[:-1] + b"\x90")
    second = scanner.scan_pass()
    assert second.regions_scanned >= 1
    assert any(hit.name == "target" and hit.address == 0x1000 for hit in second.hits)
    assert second.new_hits == 0
    assert all(hit.first_seen == 1 for hit in second.hits)

    # An unchanged pass carries the match without rescanning.
    third = scanner.scan_pass()
    assert third.regions_scanned == 0
    assert third.new_hits == 0
    assert any(hit.address == 0x1000 for hit in third.hits)


def test_private_regions_are_prioritized_before_image_regions() -> None:
    source = make_source()
    private_code = Region("injected", 0x9000, len(CODE), CODE, executable=True)
    private_source = MemorySource(
        Arch.X64,
        [*source.regions(), private_code],
        [*source.modules()],
    )
    injected = generate(MemorySource(Arch.X64, [private_code]), 0x9000, name="injected_fn")
    scanner = SignatureScanner(private_source, [injected.signature])

    report = scanner.scan_pass()
    assert report.regions_private == 1
    # The private region is scanned even though it sorts last by address.
    assert any(hit.address == 0x9000 for hit in report.hits)


def test_budget_limits_recoveries_across_signatures() -> None:
    source = make_source()
    first, second = two_signatures()
    # Three candidates exist (hint start 0x1060, swept 0x1000 and 0x1007); a
    # budget of two must reach `target` (second candidate) and stop there.
    scanner = SignatureScanner(source, [first, second], budget=RecoveryBudget(remaining=2))

    report = scanner.scan_pass()
    assert report.budget_exhausted
    assert report.budget_remaining == 0
    found = {hit.name for hit in report.hits}
    assert "target" in found
    assert "second_fn" not in found


def test_reference_index_discovers_string_only_signatures() -> None:
    source = strong_source()
    string_only = Signature(
        name="by_banner",
        features=(
            SignatureFeature("str", "generate banner literal", 1.2, True),
            SignatureFeature("cfg", "blocks:1", 0.25, False),
        ),
        anchors=("str:generate banner literal",),
        match_threshold=0.75,
        min_distinct=1,
        confidence="single-arch",
        provenance=(SampleProvenance("x64", "fixture", 0x1000, opt="O2", tool="test"),),
    )

    # Without the index, a string anchor cannot produce a hint-free candidate.
    assert scan(source, string_only, hints=False) == ()

    index = ReferenceIndex()
    for region in source.regions():
        index.index_region(source, region)
    matches = scan(source, string_only, hints=False, index=index)
    assert [match.address for match in matches] == [0x1000]


def test_reference_index_sweeps_with_resync_and_reports_truncation() -> None:
    garbage = Region("junk", 0x3000, 0x2000, b"\xff" * 0x2000, executable=True)
    source = make_source()
    index = ReferenceIndex()
    index.index_region(source, garbage)

    assert index.truncated  # the resync budget capped the sweep
    assert index.referencers(0x2000) == ()  # the garbage region added nothing


def test_index_is_per_region_and_survives_independent_updates() -> None:
    source = make_source()
    index = ReferenceIndex()
    regions = list(source.regions())
    counts = [index.index_region(source, region) for region in regions]

    assert counts[0] > 0  # the text region was indexed
    assert index.referencers(0x2000) == (0x1000,)
    index.drop_region(regions[0].start)
    assert index.referencers(0x2000) == ()
    assert not index.truncated


def test_self_test_uses_the_index_for_string_only_signatures() -> None:
    source = strong_source()
    string_only = Signature(
        name="by_banner",
        features=(SignatureFeature("str", "generate banner literal", 1.2, True),),
        anchors=("str:generate banner literal",),
        match_threshold=0.75,
        min_distinct=1,
        confidence="single-arch",
        provenance=(SampleProvenance("x64", "fixture", 0x1000, opt="O2", tool="test"),),
    )
    match: Match = self_test(string_only, source, 0x1000)
    assert match.address == 0x1000


def test_scanner_refuses_an_empty_signature_set() -> None:
    with pytest.raises(ValueError, match="at least one signature"):
        SignatureScanner(make_source(), [])


def test_page_size_is_power_of_two() -> None:
    assert PAGE_SIZE == 4096


def test_signature_identity_is_stable_through_the_scanner() -> None:
    source = make_source()
    signature = generate(source, 0x1000, name="target").signature
    scanner = SignatureScanner(source, [signature])
    report = scanner.scan_pass()

    hit = next(hit for hit in report.hits if hit.name == "target")
    assert hit.signature_id == signature.signature_id
    assert hit.address == 0x1000
    assert hit.score == 1.0
