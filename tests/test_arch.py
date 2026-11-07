"""Architecture and container detection tests."""

from __future__ import annotations

import struct

import pytest

from core.arch import Arch, detect, detect_elf, detect_pe, ensure_supported
from core.errors import SourceFormatError, UnsupportedArchError


def elf_header(machine: int, elf_class: int = 2) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, 2)  # ET_EXEC
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def pe_header(machine: int) -> bytes:
    header = bytearray(0x80)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, machine)
    return bytes(header)


@pytest.mark.parametrize(
    ("machine", "expected"),
    [(0x3E, Arch.X64), (0xB7, Arch.ARM64), (0x28, Arch.ARM32)],
)
def test_elf_machine_detection(machine: int, expected: Arch) -> None:
    assert detect_elf(elf_header(machine, 1 if expected is Arch.ARM32 else 2)) is expected


@pytest.mark.parametrize(
    ("machine", "expected"),
    [(0x8664, Arch.X64), (0xAA64, Arch.ARM64), (0x01C4, Arch.ARM32)],
)
def test_pe_machine_detection(machine: int, expected: Arch) -> None:
    assert detect_pe(pe_header(machine)) is expected


def test_x86_32_is_rejected_not_decoded_as_x64() -> None:
    with pytest.raises(UnsupportedArchError):
        detect_elf(elf_header(0x03, 1))
    with pytest.raises(UnsupportedArchError):
        detect_pe(pe_header(0x014C))


def test_unknown_format_is_a_source_error() -> None:
    with pytest.raises(SourceFormatError):
        detect(b"not an image at all")


def test_arm32_detected_but_not_supported_until_m4() -> None:
    arch = detect_elf(elf_header(0x28, 1))
    assert arch is Arch.ARM32
    with pytest.raises(UnsupportedArchError):
        ensure_supported(arch)


def test_arch_properties() -> None:
    assert Arch.X64.pointer_size == 8
    assert Arch.ARM32.pointer_size == 4
    assert Arch.THUMB.is_arm
    assert Arch.ARM64.insn_align == 4
    assert Arch.X64.insn_align == 1
    assert ensure_supported(Arch.ARM64) is Arch.ARM64
