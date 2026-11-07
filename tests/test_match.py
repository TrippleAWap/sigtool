"""Reference matcher tests: needles, scoring, scanning, and self-test."""

from __future__ import annotations

import pytest

from core.errors import SelfTestError
from core.features import Feature
from core.generate import generate
from core.match import (
    accepts,
    anchor_needles,
    compare,
    scan,
    self_test,
)
from core.sigfile import SampleProvenance, Signature, SignatureFeature
from tests.support import HELPER, deep_source, strong_source, tiny_source


def signature_for(*, name: str = "fixture_fn", **overrides: object) -> Signature:
    values: dict[str, object] = {
        "name": name,
        "features": (
            SignatureFeature("const", "0x1234", 0.7, True),
            SignatureFeature("ops", "ret:1", 0.15, False),
            SignatureFeature("str", "banner literal", 1.2, True),
        ),
        "anchors": ("str:banner literal", "const:0x1234"),
        "match_threshold": 0.75,
        "min_distinct": 2,
        "confidence": "single-arch",
        "provenance": (SampleProvenance("x64", "fixture", 0x1200, opt="O2", tool="test"),),
    }
    values.update(overrides)
    return Signature(**values)  # type: ignore[arg-type]


def test_const_anchors_are_indexed_in_both_byte_orders() -> None:
    needles = anchor_needles(signature_for())
    const = [needle.data for needle in needles if needle.key == "const:0x1234"]
    assert b"\x34\x12\x00\x00" in const
    assert b"\x00\x00\x12\x34" in const
    assert all(needle.executable for needle in needles if needle.key.startswith("const:"))


def test_string_anchors_are_indexed_narrow_and_wide() -> None:
    needles = anchor_needles(signature_for())
    data = [needle.data for needle in needles if needle.key == "str:banner literal"]
    assert b"banner literal" in data
    assert "banner literal".encode("utf-16-le") in data
    assert all(not needle.executable for needle in needles if needle.key.startswith("str:"))


def test_small_constants_and_callees_are_not_searchable() -> None:
    signature = signature_for(
        features=(
            SignatureFeature("const", "0x5", 0.42, True),
            SignatureFeature("callee", "helper", 0.9, True),
        ),
        anchors=("const:0x5", "callee:helper"),
        min_distinct=1,
    )
    assert anchor_needles(signature) == ()


def test_escaped_and_hashed_strings() -> None:
    escaped = signature_for(
        features=(SignatureFeature("str", 'say \\"hi\\"', 1.2, True),),
        anchors=('str:say \\"hi\\"',),
        min_distinct=1,
    )
    assert b'say "hi"' in {needle.data for needle in anchor_needles(escaped)}

    hashed = signature_for(
        features=(SignatureFeature("str", "long:abc123", 1.2, True),),
        anchors=("str:long:abc123",),
        min_distinct=1,
    )
    assert anchor_needles(hashed) == ()


def test_full_match_scores_one() -> None:
    signature = signature_for()
    result = compare(
        signature,
        (
            Feature("const", "0x1234"),
            Feature("str", "banner literal"),
            Feature("ops", "ret:1"),
        ),
    )
    assert result.score == 1.0
    assert result.matched_required == 2


def test_missing_evidence_lowers_the_score() -> None:
    signature = signature_for()
    result = compare(signature, (Feature("str", "banner literal"),))
    assert result.score == pytest.approx(1.2 / 1.9, abs=1e-3)
    assert result.matched_required == 1


def test_missing_optional_feature_does_not_lower_the_score() -> None:
    signature = signature_for()
    with_optional = compare(
        signature,
        (Feature("const", "0x1234"), Feature("str", "banner literal"), Feature("ops", "ret:1")),
    )
    without_optional = compare(
        signature, (Feature("const", "0x1234"), Feature("str", "banner literal"))
    )
    assert with_optional.score == without_optional.score == 1.0


def test_threshold_and_min_distinct_both_gate() -> None:
    signature = signature_for(min_distinct=2)
    one_feature = compare(signature, (Feature("str", "banner literal"),))
    assert one_feature.score >= 0.5
    assert not accepts(signature, one_feature)

    permissive = signature_for(min_distinct=1, match_threshold=0.5)
    assert accepts(permissive, one_feature)


def test_scan_finds_the_generated_function() -> None:
    result = generate(strong_source(), 0x1000, opt="O2")
    matches = scan(strong_source(), result.signature)
    assert matches
    assert matches[0].address == 0x1000
    assert matches[0].score == 1.0


def test_scan_finds_the_function_without_symbol_hints() -> None:
    source = strong_source(with_hints=False)
    signature = generate(source, 0x1000).signature
    assert [match.address for match in scan(source, signature)] == [0x1000]


def test_hints_flag_controls_whether_symbol_starts_are_used() -> None:
    source = deep_source()
    signature = generate(source, 0x1000).signature

    # Hinted: function_starts reaches the prologue even though the anchor
    # constant sits beyond the backward-sweep window.
    assert [match.address for match in scan(source, signature, hints=True)] == [0x1000]

    # Hint-free: only the sweep can reach the function, and the window is too
    # short, so the accepted matches (if any) start inside the padding.
    hint_free = scan(source, signature, hints=False)
    assert 0x1000 not in {match.address for match in hint_free}


def test_scan_reports_one_match_per_span() -> None:
    signature = generate(strong_source(), 0x1000).signature
    matches = scan(strong_source(), signature)
    spans = [(match.address, match.end) for match in matches]
    for index, (start, end) in enumerate(spans):
        for other_start, other_end in spans[index + 1 :]:
            assert not (start < other_end and other_start < end)


def test_scan_returns_nothing_for_an_unrelated_image() -> None:
    signature = generate(strong_source(), 0x1000).signature
    assert scan(tiny_source(), signature) == ()


def test_scan_is_deterministic() -> None:
    signature = generate(strong_source(), 0x1000).signature
    first = scan(strong_source(), signature)
    second = scan(strong_source(), signature)
    assert first == second


def test_self_test_accepts_the_sampled_function() -> None:
    result = generate(strong_source(), 0x1000)
    match = self_test(result.signature, strong_source(), 0x1000)
    assert match.address == 0x1000


def test_self_test_rejects_a_signature_that_cannot_be_refound() -> None:
    signature = generate(strong_source(), 0x1000).signature
    with pytest.raises(SelfTestError):
        self_test(signature, tiny_source(), 0x1000)


def test_self_test_reports_a_wrong_start() -> None:
    signature = generate(strong_source(), 0x1000).signature
    with pytest.raises(SelfTestError):
        self_test(signature, strong_source(), HELPER)
