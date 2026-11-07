"""Architecture identifiers, Capstone setup, and container format detection.

x86-64 and AArch64 have full normalization. ARM32 images (ELF ``EM_ARM``) are
extracted with per-address mode: ELF symbol values carry the Thumb bit, so a
single image can mix ARM and Thumb functions. Container types that are Thumb
everywhere (PE ``0x01c2``/``0x01c4``) map to ``Arch.THUMB``.
"""

from __future__ import annotations

import struct
from enum import Enum
from functools import cache
from typing import Final

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
)

from core.errors import SourceFormatError, UnsupportedArchError


class Arch(str, Enum):
    X64 = "x64"
    ARM64 = "arm64"
    ARM32 = "arm32"
    THUMB = "thumb"

    @property
    def pointer_size(self) -> int:
        return 8 if self in (Arch.X64, Arch.ARM64) else 4

    @property
    def is_arm(self) -> bool:
        return self in (Arch.ARM32, Arch.THUMB)

    @property
    def insn_align(self) -> int:
        """Minimum instruction alignment; recovery uses it for target checks."""
        return 4 if self in (Arch.ARM64, Arch.ARM32, Arch.THUMB) else 1


FEATURE_ARCHS: Final[tuple[Arch, ...]] = (Arch.X64, Arch.ARM64, Arch.ARM32, Arch.THUMB)


def ensure_supported(arch: Arch) -> Arch:
    """Raise unless ``arch`` has a normalization implementation."""
    if arch not in FEATURE_ARCHS:
        raise UnsupportedArchError(f"{arch.value} feature extraction is not implemented")
    return arch


@cache
def capstone_for(arch: Arch) -> Cs:
    """Return a configured Capstone disassembler.

    The instance is cached, so callers must not mutate it. sigtool is
    single-threaded; a future scanner creates one instance per thread.
    """
    if arch is Arch.X64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch is Arch.ARM64:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    elif arch is Arch.ARM32:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    else:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


ELF_MACHINE_X86_64: Final[int] = 0x3E
ELF_MACHINE_ARM: Final[int] = 0x28
ELF_MACHINE_AARCH64: Final[int] = 0xB7
ELF_MACHINE_I386: Final[int] = 0x03

PE_MACHINE_AMD64: Final[int] = 0x8664
PE_MACHINE_ARM64: Final[int] = 0xAA64
PE_MACHINE_I386: Final[int] = 0x014C
PE_MACHINE_ARMNT: Final[int] = 0x01C4
PE_MACHINE_ARM: Final[int] = 0x01C0
PE_MACHINE_THUMB: Final[int] = 0x01C2

MACHO_CPU_X86_64: Final[int] = 0x01000007
MACHO_CPU_ARM64: Final[int] = 0x0100000C
MACHO_CPU_I386: Final[int] = 0x00000007

_MACHO_MAGICS_LE: Final[frozenset[bytes]] = frozenset({b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"})


def detect_elf(data: bytes) -> Arch:
    """Read ``e_machine`` from an ELF header (little- or big-endian)."""
    if len(data) < 20 or not data.startswith(b"\x7fELF"):
        raise SourceFormatError("not an ELF image")
    order = "<" if data[5:6] != b"\x02" else ">"
    machine = struct.unpack_from(f"{order}H", data, 18)[0]
    if machine == ELF_MACHINE_X86_64:
        return Arch.X64
    if machine == ELF_MACHINE_AARCH64:
        return Arch.ARM64
    if machine == ELF_MACHINE_ARM:
        return Arch.ARM32
    if machine == ELF_MACHINE_I386:
        raise UnsupportedArchError(
            "32-bit x86 targets are unsupported in v1 (do not decode as x64)"
        )
    raise UnsupportedArchError(f"unsupported ELF machine 0x{machine:x}")


def detect_pe(data: bytes) -> Arch:
    """Read the COFF machine type from a PE image."""
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise SourceFormatError("not a PE image")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[lfanew : lfanew + 4] != b"PE\0\0":
        raise SourceFormatError("PE signature missing")
    machine = struct.unpack_from("<H", data, lfanew + 4)[0]
    if machine == PE_MACHINE_AMD64:
        return Arch.X64
    if machine == PE_MACHINE_ARM64:
        return Arch.ARM64
    if machine in (PE_MACHINE_I386,):
        raise UnsupportedArchError(
            "32-bit x86 / WOW64 images are unsupported in v1 (do not decode as x64)"
        )
    if machine == PE_MACHINE_ARM:
        return Arch.ARM32
    if machine in (PE_MACHINE_THUMB, PE_MACHINE_ARMNT):
        # Windows arm32 images are Thumb-2; the per-address mode override in a
        # source can still mark individual ARM symbols.
        return Arch.THUMB
    raise UnsupportedArchError(f"unsupported PE machine 0x{machine:04x}")


def detect_macho(data: bytes) -> Arch:
    """Read ``cputype`` from a little-endian Mach-O header."""
    if len(data) < 8 or data[:4] not in _MACHO_MAGICS_LE:
        raise SourceFormatError("not a little-endian Mach-O image")
    cputype = struct.unpack_from("<I", data, 4)[0]
    if cputype == MACHO_CPU_X86_64:
        return Arch.X64
    if cputype == MACHO_CPU_ARM64:
        return Arch.ARM64
    if cputype == MACHO_CPU_I386:
        raise UnsupportedArchError("32-bit x86 Mach-O images are unsupported in v1")
    raise UnsupportedArchError(f"unsupported Mach-O cputype 0x{cputype:08x}")


def detect(data: bytes) -> Arch:
    """Identify the architecture of an image from its container header."""
    if data.startswith(b"\x7fELF"):
        return detect_elf(data)
    if data.startswith(b"MZ"):
        return detect_pe(data)
    if data[:4] in _MACHO_MAGICS_LE:
        return detect_macho(data)
    raise SourceFormatError("unrecognised image format (expected ELF, PE, or Mach-O)")
