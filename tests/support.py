"""Shared synthetic images for generation and matching tests."""

from __future__ import annotations

from core.arch import Arch
from core.source import MemorySource, Module, Region

HELPER = 0x1060


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
    code += b"\xe8" + (HELPER - (call_address + 5)).to_bytes(4, "little", signed=True)
    code += b"\xc3"  # function ends here; the callee follows the padding
    code += b"\x00" * (HELPER - len(code) - 0x1000)
    code += b"\xc3"
    text = bytes(code)
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
        exports={"helper": HELPER},
        functions={HELPER: "helper"},
    )
    hints = ((0x1000, HELPER), (HELPER, HELPER + 1)) if with_hints else ()
    return MemorySource(Arch.X64, regions, [module], hints=hints)


def deep_source() -> MemorySource:
    """A function whose only constants sit past the 512-byte backward sweep.

    With symbol hints the matcher reaches ``0x1000`` from ``function_starts``;
    hint-free, the sweep from the constant hit cannot walk back far enough, so
    discovery fails. Used to prove the ``hints`` flag actually changes reach.
    """
    code = bytearray(b"\x48\x8d\x3d" + (0x2000 - 0x1007).to_bytes(4, "little", signed=True))
    code += b"\x90" * 600  # nop padding; the sweep window is 512 bytes
    code += b"\xb8\x34\x12\x00\x00"  # mov eax, 0x1234
    code += b"\x05\x11\x11\x00\x00"  # add eax, 0x1111
    code += b"\xc3"
    text = bytes(code)
    rodata = b"generate banner literal\x00"
    regions = [
        Region("text", 0x1000, len(text), text, executable=True),
        Region("rodata", 0x2000, len(rodata), rodata),
    ]
    module = Module(
        name="deep",
        base=0x1000,
        size=0x2000 + len(rodata) - 0x1000,
        regions=tuple(regions),
        functions={0x1000: "deep_fn"},
    )
    return MemorySource(Arch.X64, regions, [module])


def tiny_source() -> MemorySource:
    """A three-instruction function with no data features."""
    code = b"\x31\xc0\xc3"  # xor eax, eax; ret
    region = Region("text", 0x1000, len(code), code, executable=True)
    module = Module(name="tiny", base=0x1000, size=len(code), regions=(region,))
    return MemorySource(Arch.X64, [region], [module])
