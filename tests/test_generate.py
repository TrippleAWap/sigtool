"""End-to-end generation: address in, deterministic signature and report out."""

from __future__ import annotations

from core.generate import generate
from core.score import ScoredFeature
from core.sigfile import Signature
from core.validate import quality_report
from tests.support import strong_source, tiny_source


def test_generate_produces_a_strong_signature() -> None:
    result = generate(strong_source(), 0x1000, opt="O2", tool="test")
    signature = result.signature

    assert signature.confidence == "single-arch"
    assert signature.match_threshold == 0.75
    assert len(signature.anchors) == 4
    assert "str:generate banner literal" in signature.anchors
    assert result.report.verdict == "strong"
    assert result.report.anchor_count == 4
    assert result.report.data_features >= 3


def test_generate_names_unnamed_functions_by_module_rva() -> None:
    signature = generate(strong_source(), 0x1000).signature
    assert signature.name == "sub_gen+0x0"


def test_generate_uses_symbol_names_when_available() -> None:
    signature = generate(strong_source(), 0x1030).signature
    assert signature.name == "helper"


def test_generated_yaml_round_trips() -> None:
    signature = generate(strong_source(), 0x1000, opt="O2").signature
    assert Signature.from_yaml(signature.to_yaml()) == signature


def test_generation_is_deterministic() -> None:
    first = generate(strong_source(), 0x1000, opt="O2", tool="test")
    second = generate(strong_source(), 0x1000, opt="O2", tool="test")
    assert first.signature.to_yaml() == second.signature.to_yaml()
    assert first.signature.signature_id == second.signature.signature_id


def test_yaml_contains_no_absolute_addresses_or_paths() -> None:
    text = generate(strong_source(), 0x1000).signature.to_yaml()
    assert "0x1000" not in text
    assert "0x1030" not in text
    assert "0x2000" not in text
    assert "\\" not in text


def test_small_function_is_low_confidence() -> None:
    result = generate(tiny_source(), 0x1000)

    assert result.signature.confidence == "low"
    assert result.report.verdict == "small"
    assert any("small function" in note for note in result.report.notes)


def test_quality_report_verdicts() -> None:
    def scored(kind: str, value: str, weight: float) -> ScoredFeature:
        from core.features import Feature

        return ScoredFeature(Feature(kind, value), weight, True)

    strong = quality_report(
        scored=(scored("str", "a literal", 1.0), scored("const", "0x1234", 0.7)),
        anchors=("str:a literal", "const:0x1234"),
        confidence="single-arch",
        instruction_count=40,
        degraded=False,
    )
    assert strong.verdict == "strong"
    assert strong.is_strong

    weak = quality_report(
        scored=(scored("str", "a literal", 1.0),),
        anchors=(),
        confidence="low",
        instruction_count=40,
        degraded=False,
    )
    assert weak.verdict == "weak"
    assert any("no data anchors" in note for note in weak.notes)

    degraded = quality_report(
        scored=(scored("str", "a literal", 1.0), scored("const", "0x1234", 0.7)),
        anchors=("str:a literal", "const:0x1234"),
        confidence="single-arch",
        instruction_count=40,
        degraded=True,
    )
    assert degraded.verdict == "weak"
    assert any("recovery was partial" in note for note in degraded.notes)
