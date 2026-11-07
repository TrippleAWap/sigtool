"""End-to-end generation: address in, deterministic signature and report out."""

from __future__ import annotations

from core.arch import Arch
from core.generate import generate
from core.score import ScoredFeature
from core.sigfile import Signature
from core.source import MemorySource, Module, Region
from core.validate import quality_report


def build_source() -> MemorySource:
    """A 15-instruction function with a string, many constants, and a callee."""
    code = bytearray(b"\x48\x8d\x3d" + (0x2000 - 0x1007).to_bytes(4, "little", signed=True))
    code += b"\xb8\x34\x12\x00\x00"  # mov eax, 0x1234
    for opcode, immediate in (
        (b"\x05", 0x1111),
        (b"\x2d", 0x2222),
        (b"\x35", 0x3333),
        (b"\x0d", 0x4444),
        (b"\x25", 0x5555),
    ):
        code += opcode + immediate.to_bytes(4, "little")
    code += b"\x69\xc0" + (0x6666).to_bytes(4, "little")  # imul eax, eax, 0x6666
    for opcode, immediate in (
        (b"\x05", 0x7777),
        (b"\x2d", 0x8888),
        (b"\x35", 0x9999),
        (b"\x0d", 0xAAAA),
        (b"\x25", 0xBBBB),
    ):
        code += opcode + immediate.to_bytes(4, "little")
    call_address = 0x1000 + len(code)
    code += b"\xe8" + (0x1030 - (call_address + 5)).to_bytes(4, "little", signed=True)
    code += b"\xc3"

    text = bytes(code) + b"\x00" * (0x1030 - (0x1000 + len(code))) + b"\xc3"
    rodata = b"generate banner literal\x00"
    regions = [
        Region("text", 0x1000, len(text), text, executable=True),
        Region("rodata", 0x2000, len(rodata), rodata),
    ]
    module = Module(
        name="gen",
        base=0x1000,
        size=0x2000 + len(rodata) - 0x1000,
        regions=tuple(regions),
        exports={"helper": 0x1030},
        functions={0x1030: "helper"},
    )
    return MemorySource(Arch.X64, regions, [module])


def test_generate_produces_a_strong_signature() -> None:
    result = generate(build_source(), 0x1000, opt="O2", tool="test")
    signature = result.signature

    assert signature.confidence == "single-arch"
    assert signature.match_threshold == 0.75
    assert len(signature.anchors) == 4
    assert "str:generate banner literal" in signature.anchors
    assert result.report.verdict == "strong"
    assert result.report.anchor_count == 4
    assert result.report.data_features >= 3


def test_generate_names_unnamed_functions_by_module_rva() -> None:
    signature = generate(build_source(), 0x1000).signature
    assert signature.name == "sub_gen+0x0"


def test_generate_uses_symbol_names_when_available() -> None:
    signature = generate(build_source(), 0x1030).signature
    assert signature.name == "helper"


def test_generated_yaml_round_trips() -> None:
    signature = generate(build_source(), 0x1000, opt="O2").signature
    assert Signature.from_yaml(signature.to_yaml()) == signature


def test_generation_is_deterministic() -> None:
    first = generate(build_source(), 0x1000, opt="O2", tool="test")
    second = generate(build_source(), 0x1000, opt="O2", tool="test")
    assert first.signature.to_yaml() == second.signature.to_yaml()
    assert first.signature.signature_id == second.signature.signature_id


def test_yaml_contains_no_absolute_addresses_or_paths() -> None:
    text = generate(build_source(), 0x1000).signature.to_yaml()
    assert "0x1000" not in text
    assert "0x1030" not in text
    assert "0x2000" not in text
    assert "\\" not in text


def test_small_function_is_low_confidence() -> None:
    code = b"\x31\xc0\xc3"  # xor eax, eax; ret
    region = Region("text", 0x1000, len(code), code, executable=True)
    module = Module(name="tiny", base=0x1000, size=len(code), regions=(region,))
    result = generate(MemorySource(Arch.X64, [region], [module]), 0x1000)

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
