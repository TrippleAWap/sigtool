"""Image-file byte source for ELF and PE containers.

Relocatable ELF objects (``ET_REL``) have no virtual addresses, so their
sections are placed at ``ELF_PLACE_BASE + file offset``. The placement is
injective (no two sections share file bytes) and keeps intra-object references
resolvable without linking.
"""

from __future__ import annotations

import struct
from bisect import bisect_right
from pathlib import Path
from typing import Final

from core.arch import Arch, detect
from core.errors import ReadError, SourceFormatError
from core.source import ByteSource, Module, Region

ELF_PLACE_BASE: Final[int] = 0x1000_0000

ELF_SHT_SYMTAB: Final[int] = 2
ELF_SHT_RELA: Final[int] = 4
ELF_SHT_NOBITS: Final[int] = 8
ELF_SHT_REL: Final[int] = 9
ELF_SHT_DYNSYM: Final[int] = 11
ELF_SHF_WRITE: Final[int] = 0x1
ELF_SHF_ALLOC: Final[int] = 0x2
ELF_SHF_EXECINSTR: Final[int] = 0x4
ELF_STT_FUNC: Final[int] = 2
ELF_ET_REL: Final[int] = 1

PE_SECTION_HEADER_SIZE: Final[int] = 40

Bounds = list[tuple[int, int]]
SymbolTable = tuple[bytes, bytes]  # (raw symbol entries, string table)


class FileSource(ByteSource):
    """A read-only view of one ELF or PE image."""

    def __init__(
        self,
        arch: Arch,
        regions: tuple[Region, ...],
        module: Module,
        function_bounds: tuple[tuple[int, int], ...] = (),
    ) -> None:
        self._arch = arch
        self._regions = tuple(sorted(regions, key=lambda region: region.start))
        self._module = module
        self._bounds = tuple(sorted(function_bounds))
        self._bounds_starts = [start for start, _ in self._bounds]

    @classmethod
    def from_path(cls, path: str | Path) -> FileSource:
        file_path = Path(path)
        return cls.from_bytes(file_path.read_bytes(), file_path.name)

    @classmethod
    def from_bytes(cls, data: bytes, name: str = "image") -> FileSource:
        arch = detect(data)
        if data.startswith(b"\x7fELF"):
            regions, module, bounds = _parse_elf(data, name)
        elif data.startswith(b"MZ"):
            regions, module, bounds = _parse_pe(data, name)
        else:
            raise SourceFormatError("FileSource supports ELF and PE images only")
        return cls(arch, regions, module, bounds)

    @property
    def arch(self) -> Arch:
        return self._arch

    def regions(self) -> tuple[Region, ...]:
        return self._regions

    def modules(self) -> tuple[Module, ...]:
        return (self._module,)

    def read(self, addr: int, size: int) -> bytes:
        if size < 0 or size > 0x1_0000:
            raise ReadError(f"refusing read of {size} bytes")
        if size == 0:
            return b""
        chunks: list[bytes] = []
        cursor = addr
        remaining = size
        for region in self._regions:
            if remaining == 0:
                break
            if not region.contains(cursor):
                continue
            take = min(remaining, region.end - cursor)
            chunks.append(region.read(cursor, take))
            cursor += take
            remaining -= take
        if remaining:
            raise ReadError(f"read of {size} bytes at 0x{addr:x} is unmapped")
        return b"".join(chunks)

    def function_starts(self) -> tuple[int, ...]:
        """Symbol starts from the ELF symbol table or PE function table."""
        return tuple(start for start, _ in self._bounds)

    def hint_function(self, addr: int) -> tuple[int, int] | None:
        """Symbol bounds from the ELF symbol table, if they cover ``addr``."""
        if not self._bounds:
            return None
        index = bisect_right(self._bounds_starts, addr) - 1
        if index < 0:
            return None
        start, end = self._bounds[index]
        return (start, end) if start <= addr < end else None


# -- ELF ---------------------------------------------------------------------


def _parse_elf(
    data: bytes, name: str
) -> tuple[tuple[Region, ...], Module, tuple[tuple[int, int], ...]]:
    if len(data) < 0x34:
        raise SourceFormatError("truncated ELF header")
    elf_class = data[4]
    if data[5] != 1:
        raise SourceFormatError("big-endian ELF images are not supported yet")
    if elf_class not in (1, 2):
        raise SourceFormatError("invalid ELF class")
    is64 = elf_class == 2

    e_type = struct.unpack_from("<H", data, 16)[0]
    if is64:
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        sh_format = "<IIQQQQIIQQ"
        sym_format = "<IBBHQQ"
        sym_entry_size = 24
    else:
        e_shoff = struct.unpack_from("<I", data, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", data, 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]
        sh_format = "<IIIIIIIIII"
        sym_format = "<IIIBBH"
        sym_entry_size = 16
    sh_struct_size = struct.calcsize(sh_format)
    if e_shoff == 0 or e_shnum == 0 or e_shentsize < sh_struct_size:
        raise SourceFormatError("ELF image has no usable section table")

    sections: list[dict[str, int]] = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + sh_struct_size > len(data):
            raise SourceFormatError("truncated ELF section table")
        values = struct.unpack_from(sh_format, data, offset)
        sections.append(
            {
                "name_off": values[0],
                "type": values[1],
                "flags": values[2],
                "addr": values[3],
                "offset": values[4],
                "size": values[5],
                "link": values[6],
                "info": values[7],
                "entsize": values[9],
            }
        )

    if e_shstrndx >= len(sections):
        raise SourceFormatError("invalid ELF section-name table index")
    name_table = _section_bytes(data, sections[e_shstrndx])
    names = [_cstr(name_table, section["name_off"]) for section in sections]

    places: dict[int, int] = {}
    regions: list[Region] = []
    for index, section in enumerate(sections):
        if not section["flags"] & ELF_SHF_ALLOC or section["size"] == 0:
            continue
        if e_type == ELF_ET_REL:
            start = ELF_PLACE_BASE + section["offset"]
        else:
            start = section["addr"]
            if start == 0:
                continue
        places[index] = start
        regions.append(
            Region(
                name=names[index] or f"section{index}",
                start=start,
                size=section["size"],
                data=_section_bytes(data, section),
                executable=bool(section["flags"] & ELF_SHF_EXECINSTR),
                writable=bool(section["flags"] & ELF_SHF_WRITE),
            )
        )
    if not regions:
        raise SourceFormatError("ELF image has no allocatable sections")

    sym_struct_size = struct.calcsize(sym_format)
    symbols: list[tuple[str, int, int, int, int]] = []
    tables: dict[int, SymbolTable] = {}
    for index, section in enumerate(sections):
        if section["type"] not in (ELF_SHT_SYMTAB, ELF_SHT_DYNSYM):
            continue
        if section["link"] >= len(sections):
            continue
        raw = _section_bytes(data, section)
        strings = _section_bytes(data, sections[section["link"]])
        tables[index] = (raw, strings)
        entry_size = section["entsize"] or sym_entry_size
        if entry_size < sym_struct_size:
            continue
        for symbol_index in range(len(raw) // entry_size):
            offset = symbol_index * entry_size
            if offset + sym_struct_size > len(raw):
                break
            if is64:
                st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(
                    sym_format, raw, offset
                )
            else:
                st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack_from(
                    sym_format, raw, offset
                )
            symbol_name = _cstr(strings, st_name)
            if st_shndx != 0 and symbol_name:
                symbols.append((symbol_name, st_value, st_info, st_shndx, st_size))

    imports: dict[int, str] = {}
    for section in sections:
        if section["type"] not in (ELF_SHT_RELA, ELF_SHT_REL):
            continue
        rel_format = "<QQq" if is64 else "<IIi"
        rel_struct_size = struct.calcsize(rel_format)
        entry_size = section["entsize"] or rel_struct_size
        if entry_size < rel_struct_size:
            continue
        raw = _section_bytes(data, section)
        for rel_index in range(len(raw) // entry_size):
            offset = rel_index * entry_size
            if offset + rel_struct_size > len(raw):
                break
            r_offset, r_info, _addend = struct.unpack_from(rel_format, raw, offset)
            symbol_index = (r_info >> 32) if is64 else (r_info >> 8)
            target = _symbol_name(tables, section["link"], symbol_index, is64, sym_format)
            if not target:
                continue
            if e_type == ELF_ET_REL:
                base = places.get(section["info"])
                if base is None:
                    continue
                slot = base + r_offset
            else:
                slot = r_offset
            imports.setdefault(slot, target)

    functions: dict[int, str] = {}
    exports: dict[str, int] = {}
    bounds: list[tuple[int, int]] = []
    for symbol_name, value, info, shndx, size in symbols:
        base = places.get(shndx)
        if base is None:
            continue
        address = base + value if e_type == ELF_ET_REL else value
        if info & 0xF == ELF_STT_FUNC:
            functions.setdefault(address, symbol_name)
            if size > 0:
                bounds.append((address, address + size))
        if info >> 4 in (1, 2):
            exports.setdefault(symbol_name, address)

    module_start = min(region.start for region in regions)
    module_end = max(region.end for region in regions)
    module = Module(
        name=Path(name).stem or "image",
        base=module_start,
        size=module_end - module_start,
        path=name,
        regions=tuple(regions),
        exports=exports,
        functions=functions,
        imports=imports,
    )
    return tuple(regions), module, tuple(sorted(bounds))


def _section_bytes(data: bytes, section: dict[str, int]) -> bytes:
    if section["type"] == ELF_SHT_NOBITS:
        return b"\x00" * section["size"]
    start = section["offset"]
    end = start + section["size"]
    if end > len(data):
        raise SourceFormatError("ELF section exceeds file size")
    return data[start:end]


def _symbol_name(
    tables: dict[int, SymbolTable],
    table_index: int,
    symbol_index: int,
    is64: bool,
    sym_format: str,
) -> str | None:
    entry = tables.get(table_index)
    if entry is None:
        return None
    raw, strings = entry
    entry_size = 24 if is64 else 16
    offset = symbol_index * entry_size
    if offset + 4 > len(raw):
        return None
    (st_name,) = struct.unpack_from("<I", raw, offset)
    return _cstr(strings, st_name)


def _cstr(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", "replace")


# -- PE ---------------------------------------------------------------------


def _parse_pe(
    data: bytes, name: str
) -> tuple[tuple[Region, ...], Module, tuple[tuple[int, int], ...]]:
    if len(data) < 0x40:
        raise SourceFormatError("truncated DOS header")
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if lfanew + 24 > len(data) or data[lfanew : lfanew + 4] != b"PE\0\0":
        raise SourceFormatError("PE signature missing")
    coff = lfanew + 4
    number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_of_optional = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if optional + size_of_optional > len(data) or size_of_optional < 96:
        raise SourceFormatError("truncated PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        count_offset = optional + 108
        dirs_offset = optional + 112
        thunk_size = 8
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
        count_offset = optional + 92
        dirs_offset = optional + 96
        thunk_size = 4
    else:
        raise SourceFormatError(f"unknown PE optional header magic 0x{magic:x}")
    number_of_dirs = struct.unpack_from("<I", data, count_offset)[0]

    headers_end = optional + size_of_optional
    sections: list[tuple[str, int, int, int]] = []  # (name, rva, span, raw_ptr)
    regions: list[Region] = []
    for index in range(number_of_sections):
        offset = headers_end + index * PE_SECTION_HEADER_SIZE
        if offset + PE_SECTION_HEADER_SIZE > len(data):
            raise SourceFormatError("truncated PE section table")
        section_name = data[offset : offset + 8].rstrip(b"\x00").decode("latin-1") or f"s{index}"
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        span = max(virtual_size, raw_size)
        if span == 0:
            continue
        payload = data[raw_ptr : raw_ptr + min(raw_size, span)]
        if len(payload) < span:
            payload = payload + b"\x00" * (span - len(payload))
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        sections.append((section_name, virtual_address, span, raw_ptr))
        regions.append(
            Region(
                name=section_name,
                start=image_base + virtual_address,
                size=span,
                data=payload,
                executable=bool(characteristics & 0x20000000),
                writable=bool(characteristics & 0x80000000),
            )
        )
    if not regions:
        raise SourceFormatError("PE image has no sections")

    def rva_to_offset(rva: int) -> int | None:
        for _section_name, virtual_address, span, raw_ptr in sections:
            if virtual_address <= rva < virtual_address + span:
                return raw_ptr + (rva - virtual_address)
        return None

    exports: dict[str, int] = {}
    functions: dict[int, str] = {}
    imports: dict[int, str] = {}

    if number_of_dirs > 0:
        export_rva, export_size = struct.unpack_from("<II", data, dirs_offset)
        if export_rva and export_size:
            _parse_pe_exports(data, rva_to_offset, image_base, export_rva, exports, functions)
    if number_of_dirs > 1:
        import_rva, import_size = struct.unpack_from("<II", data, dirs_offset + 8)
        if import_rva and import_size:
            _parse_pe_imports(data, rva_to_offset, image_base, import_rva, thunk_size, imports)

    module_start = min(region.start for region in regions)
    module_end = max(region.end for region in regions)
    module = Module(
        name=Path(name).stem or "image",
        base=module_start,
        size=module_end - module_start,
        path=name,
        regions=tuple(regions),
        exports=exports,
        functions=functions,
        imports=imports,
    )
    # PE exports carry no size, so there are no symbol bounds to hint recovery.
    return tuple(regions), module, ()


def _parse_pe_exports(
    data: bytes,
    rva_to_offset: object,
    image_base: int,
    export_rva: int,
    exports: dict[str, int],
    functions: dict[int, str],
) -> None:
    if not callable(rva_to_offset):
        return
    base_offset = rva_to_offset(export_rva)
    if base_offset is None or base_offset + 40 > len(data):
        return
    (
        _characteristics,
        _timestamp,
        _major,
        _minor,
        _name_rva,
        _ordinal_base,
        number_of_functions,
        number_of_names,
        address_of_functions,
        address_of_names,
        address_of_ordinals,
    ) = struct.unpack_from("<IIHHIIIIIII", data, base_offset)
    functions_offset = rva_to_offset(address_of_functions)
    names_offset = rva_to_offset(address_of_names)
    ordinals_offset = rva_to_offset(address_of_ordinals)
    if functions_offset is None or names_offset is None or ordinals_offset is None:
        return
    for index in range(min(number_of_names, number_of_functions, 65536)):
        name_entry = names_offset + index * 4
        ordinal_entry = ordinals_offset + index * 2
        if name_entry + 4 > len(data) or ordinal_entry + 2 > len(data):
            break
        (name_rva,) = struct.unpack_from("<I", data, name_entry)
        (ordinal,) = struct.unpack_from("<H", data, ordinal_entry)
        name_offset = rva_to_offset(name_rva)
        if name_offset is None or ordinal >= number_of_functions:
            continue
        function_entry = functions_offset + ordinal * 4
        if function_entry + 4 > len(data):
            continue
        symbol = _cstr(data, name_offset)
        if not symbol:
            continue
        (function_rva,) = struct.unpack_from("<I", data, function_entry)
        address = image_base + function_rva
        exports.setdefault(symbol, address)
        functions.setdefault(address, symbol)


def _parse_pe_imports(
    data: bytes,
    rva_to_offset: object,
    image_base: int,
    import_rva: int,
    thunk_size: int,
    imports: dict[int, str],
) -> None:
    if not callable(rva_to_offset):
        return
    descriptor_offset = rva_to_offset(import_rva)
    if descriptor_offset is None:
        return
    for index in range(4096):
        offset = descriptor_offset + index * 20
        if offset + 20 > len(data):
            return
        original_thunk, _timestamp, _forwarder, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", data, offset
        )
        if original_thunk == 0 and name_rva == 0 and first_thunk == 0:
            return
        name_offset = rva_to_offset(name_rva)
        if name_offset is None:
            continue
        dll = Path(_cstr(data, name_offset)).stem
        thunk_offset = rva_to_offset(original_thunk or first_thunk)
        if thunk_offset is None:
            continue
        for slot in range(4096):
            entry = thunk_offset + slot * thunk_size
            if entry + thunk_size > len(data):
                break
            if thunk_size == 8:
                (value,) = struct.unpack_from("<Q", data, entry)
                ordinal_flag = 1 << 63
            else:
                (value,) = struct.unpack_from("<I", data, entry)
                ordinal_flag = 1 << 31
            if value == 0:
                break
            if value & ordinal_flag:
                symbol = f"#{value & 0xFFFF}"
            else:
                hint_offset = rva_to_offset(value & 0x7FFF_FFFF)
                if hint_offset is None:
                    break
                symbol = _cstr(data, hint_offset + 2)
            address = image_base + first_thunk + slot * thunk_size
            imports.setdefault(address, f"{dll}!{symbol}")
