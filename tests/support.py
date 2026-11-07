"""Shared synthetic images for generation and matching tests."""

from __future__ import annotations

from core.arch import Arch
from core.source import MemorySource, Module, Region


def strong_source(*, with_hints: bool = False) -> MemorySource:
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
    hints = ((0x1000, 0x1030), (0x1030, 0x1031)) if with_hints else ()
    return MemorySource(Arch.X64, regions, [module], hints=hints)


def tiny_source() -> MemorySource:
    """A three-instruction function with no data features."""
    code = b"\x31\xc0\xc3"  # xor eax, eax; ret
    region = Region("text", 0x1000, len(code), code, executable=True)
    module = Module(name="tiny", base=0x1000, size=len(code), regions=(region,))
    return MemorySource(Arch.X64, [region], [module])
