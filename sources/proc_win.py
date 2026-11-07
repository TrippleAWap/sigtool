"""Read-only live-process byte source for Windows x64 and ARM64 targets.

The source never writes to, suspends, or injects into the target: it opens the
process with ``PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`` and uses
``ReadProcessMemory`` for every byte it returns (AGENTS.md rule 9).

``regions()`` deliberately exposes only readable, non-writable module image
pages. Those are where Tier 0 anchors live, and materialising them lets the
reference matcher keep its simple ``bytes.find`` scan; heap, stack, and writable
data stay lazily readable through :meth:`read` but are not anchor-scanned. Every
materialised region is capped, so a hostile or enormous image cannot make
generation read unbounded memory (rule 8).

32-bit (WOW64) processes are detected and rejected rather than decoded as x64.
"""

from __future__ import annotations

import ctypes
import sys
from bisect import bisect_right
from ctypes import POINTER, byref, c_int, c_size_t, c_ulong, c_ulonglong, c_ushort, c_void_p
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from core.arch import Arch
from core.errors import ProcessError, ReadError, UnsupportedArchError
from core.source import ByteSource, Module, Region
from core.spec import MAX_READ_BYTES

# Access rights and memory constants from winnt.h / processthreadsapi.h.
PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
PROCESS_VM_READ: Final[int] = 0x0010
MEM_COMMIT: Final[int] = 0x1000
LIST_MODULES_ALL: Final[int] = 0x03

PAGE_NOACCESS: Final[int] = 0x01
PAGE_READONLY: Final[int] = 0x02
PAGE_READWRITE: Final[int] = 0x04
PAGE_WRITECOPY: Final[int] = 0x08
PAGE_EXECUTE: Final[int] = 0x10
PAGE_EXECUTE_READ: Final[int] = 0x20
PAGE_EXECUTE_READWRITE: Final[int] = 0x40
PAGE_EXECUTE_WRITECOPY: Final[int] = 0x80
PAGE_GUARD: Final[int] = 0x100

READABLE_PROTECTIONS: Final[frozenset[int]] = frozenset(
    {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }
)
EXECUTABLE_PROTECTIONS: Final[frozenset[int]] = frozenset(
    {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}
)
WRITABLE_PROTECTIONS: Final[frozenset[int]] = frozenset(
    {PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}
)

IMAGE_FILE_MACHINE_I386: Final[int] = 0x014C
IMAGE_FILE_MACHINE_AMD64: Final[int] = 0x8664
IMAGE_FILE_MACHINE_ARMNT: Final[int] = 0x01C4
IMAGE_FILE_MACHINE_ARM64: Final[int] = 0xAA64

MACHINE_ARCH: Final[dict[int, Arch]] = {
    IMAGE_FILE_MACHINE_AMD64: Arch.X64,
    IMAGE_FILE_MACHINE_ARM64: Arch.ARM64,
}

MAX_REGIONS: Final[int] = 65536
MAX_MODULES: Final[int] = 4096
MAX_PE_HEADER_BYTES: Final[int] = 0x1000
MAX_PE_SECTIONS: Final[int] = 256
MAX_PE_EXPORTS: Final[int] = 65536
MAX_PE_IMPORTS: Final[int] = 4096
MAX_IMPORT_THUNKS: Final[int] = 4096
MAX_PE_NAME: Final[int] = 512
MAX_ANCHOR_REGION_BYTES: Final[int] = 32 * 1024 * 1024
MAX_ANCHOR_BYTES: Final[int] = 128 * 1024 * 1024


class _MemoryBasicInformation64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", c_ulong),
        ("_alignment1", c_ulong),
        ("RegionSize", c_ulonglong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ("_alignment2", c_ulong),
    ]


class _MemoryBasicInformation32(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", c_ulong),
        ("AllocationBase", c_ulong),
        ("AllocationProtect", c_ulong),
        ("RegionSize", c_ulong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
    ]


_MemoryBasicInformation = (
    _MemoryBasicInformation64 if ctypes.sizeof(c_void_p) == 8 else _MemoryBasicInformation32
)


class _ModuleInformation(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", c_void_p),
        ("SizeOfImage", c_ulong),
        ("EntryPoint", c_void_p),
    ]


class _SystemInfo(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", c_ushort),
        ("wReserved", c_ushort),
        ("dwPageSize", c_ulong),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask", c_size_t),
        ("dwNumberOfProcessors", c_ulong),
        ("dwProcessorType", c_ulong),
        ("dwAllocationGranularity", c_ulong),
        ("wProcessorLevel", c_ushort),
        ("wProcessorRevision", c_ushort),
    ]


_PROCESSOR_ARCHITECTURE_AMD64: Final[int] = 9
_PROCESSOR_ARCHITECTURE_ARM64: Final[int] = 12

_kernel32: Any = None
_psapi: Any = None
_signatures_ready = False


def _api() -> tuple[Any, Any]:
    """Load the Win32 entry points once, with explicit signatures."""
    global _kernel32, _psapi, _signatures_ready
    if sys.platform != "win32":
        raise ProcessError("live-process sources are only implemented for Windows")
    if _kernel32 is None or _psapi is None:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    if not _signatures_ready:
        _setup_signatures(_kernel32, _psapi)
        _signatures_ready = True
    return _kernel32, _psapi


def _setup_signatures(kernel32: Any, psapi: Any) -> None:
    kernel32.OpenProcess.argtypes = [c_ulong, c_int, c_ulong]
    kernel32.OpenProcess.restype = c_void_p
    kernel32.CloseHandle.argtypes = [c_void_p]
    kernel32.CloseHandle.restype = c_int
    kernel32.ReadProcessMemory.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_size_t,
        POINTER(c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = c_int
    kernel32.VirtualQueryEx.argtypes = [
        c_void_p,
        c_void_p,
        POINTER(_MemoryBasicInformation),
        c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = c_size_t
    kernel32.GetNativeSystemInfo.argtypes = [POINTER(_SystemInfo)]

    psapi.EnumProcessModulesEx.argtypes = [
        c_void_p,
        POINTER(c_void_p),
        c_ulong,
        POINTER(c_ulong),
        c_ulong,
    ]
    psapi.EnumProcessModulesEx.restype = c_int
    psapi.GetModuleInformation.argtypes = [
        c_void_p,
        c_void_p,
        POINTER(_ModuleInformation),
        c_ulong,
    ]
    psapi.GetModuleInformation.restype = c_int
    psapi.GetModuleFileNameExW.argtypes = [c_void_p, c_void_p, ctypes.c_wchar_p, c_ulong]
    psapi.GetModuleFileNameExW.restype = c_ulong


def arch_for_machine(machine: int) -> Arch:
    """Map a PE machine type to a supported :class:`Arch`.

    Raises :class:`UnsupportedArchError` for 32-bit machines, so a WOW64 target
    is rejected explicitly instead of being decoded as x64 (PLAN.md section 4).
    """
    arch = MACHINE_ARCH.get(machine)
    if arch is not None:
        return arch
    if machine in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARMNT):
        raise UnsupportedArchError(
            f"32-bit process machine 0x{machine:x} is not supported; "
            "WOW64 and 32-bit targets are rejected (PLAN.md section 4)"
        )
    raise UnsupportedArchError(f"unsupported process machine 0x{machine:x}")


def _last_error(what: str) -> ProcessError:
    # typeshed only declares ctypes.get_last_error on Windows, though the
    # function exists wherever ctypes does; route through Any so the module
    # type-checks on every platform.
    platform_ctypes: Any = ctypes
    return ProcessError(f"{what} failed (Windows error {platform_ctypes.get_last_error()})")


@dataclass(frozen=True, slots=True)
class _MemoryRange:
    start: int
    size: int
    readable: bool
    executable: bool
    writable: bool

    @property
    def end(self) -> int:
        return self.start + self.size


class WindowsProcessSource(ByteSource):
    """Read-only view of one live Windows process."""

    def __init__(
        self,
        pid: int,
        handle: int,
        arch: Arch,
        kernel32: Any,
        psapi: Any,
    ) -> None:
        self._pid = pid
        self._handle = handle
        self._arch = arch
        self._kernel32 = kernel32
        self._psapi = psapi
        self._modules: tuple[Module, ...] = ()
        self._ranges: tuple[_MemoryRange, ...] = ()
        self._range_starts: list[int] = []
        self._sections: dict[int, tuple[tuple[str, int, int], ...]] = {}
        self._anchor_regions: tuple[Region, ...] | None = None

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(cls, pid: int) -> WindowsProcessSource:
        """Open ``pid`` read-only and enumerate its architecture and modules."""
        if pid <= 0:
            raise ProcessError(f"invalid process id {pid}")
        kernel32, psapi = _api()
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid,
        )
        if not handle:
            raise _last_error(f"OpenProcess({pid})")
        source = cls(pid, int(handle), Arch.X64, kernel32, psapi)
        try:
            source._arch = _process_arch(kernel32, source._handle)
            if source._arch is Arch.X64 and ctypes.sizeof(c_void_p) < 8:
                raise UnsupportedArchError("a 32-bit Python cannot read a 64-bit process")
            source._modules = source._enumerate_modules()
            source._ranges = source._enumerate_ranges()
            source._range_starts = [memory.start for memory in source._ranges]
        except BaseException:
            source.close()
            raise
        if not source._modules:
            source.close()
            raise ProcessError(f"process {pid} has no enumerable modules")
        return source

    def __enter__(self) -> WindowsProcessSource:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = 0
            self._anchor_regions = ()

    @property
    def pid(self) -> int:
        return self._pid

    # -- ByteSource --------------------------------------------------------

    @property
    def arch(self) -> Arch:
        return self._arch

    def modules(self) -> tuple[Module, ...]:
        return self._modules

    def function_starts(self) -> tuple[int, ...]:
        starts: set[int] = set()
        for module in self._modules:
            starts.update(module.functions)
        return tuple(sorted(starts))

    def read(self, addr: int, size: int) -> bytes:
        if size < 0 or size > MAX_READ_BYTES:
            raise ReadError(f"refusing read of {size} bytes")
        if size == 0:
            return b""
        if not self._handle:
            raise ReadError("the process handle is closed")
        buffer = ctypes.create_string_buffer(size)
        read = c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            self._handle,
            c_void_p(addr),
            buffer,
            size,
            byref(read),
        )
        if not ok or read.value != size:
            raise ReadError(f"read of {size} bytes at 0x{addr:x} failed")
        return buffer.raw[:size]

    def read_partial(self, addr: int, size: int) -> bytes:
        """Bounded contiguous read that stops at an unreadable boundary."""
        remaining = min(max(size, 0), MAX_READ_BYTES)
        chunks: list[bytes] = []
        cursor = addr
        while remaining > 0:
            memory = self._range_at(cursor)
            if memory is None or not memory.readable:
                break
            take = min(remaining, memory.end - cursor, MAX_READ_BYTES)
            try:
                chunk = self.read(cursor, take)
            except ReadError:
                break
            chunks.append(chunk)
            cursor += take
            remaining -= take
        return b"".join(chunks)

    def is_mapped(self, addr: int, size: int = 1) -> bool:
        memory = self._range_at(addr)
        if memory is None:
            return False
        return size <= 0 or addr + size <= memory.end

    def is_executable(self, addr: int) -> bool:
        memory = self._range_at(addr)
        return bool(memory and memory.executable)

    def regions(self) -> tuple[Region, ...]:
        """Readable, non-writable module pages, materialised within fixed caps.

        The matcher scans anchors here. Other committed memory is still
        readable through :meth:`read`; it is not exposed as an anchor region so
        that a large managed heap cannot turn Tier 0 into an unbounded read.
        """
        if self._anchor_regions is None:
            self._anchor_regions = self._build_anchor_regions()
        return self._anchor_regions

    # -- enumeration -------------------------------------------------------

    def _enumerate_modules(self) -> tuple[Module, ...]:
        capacity = 1024
        needed = c_ulong(0)
        handles: list[int] = []
        for _ in range(8):
            array = (c_void_p * capacity)()
            if not self._psapi.EnumProcessModulesEx(
                self._handle,
                array,
                ctypes.sizeof(array),
                byref(needed),
                LIST_MODULES_ALL,
            ):
                raise _last_error(f"EnumProcessModulesEx({self._pid})")
            count = min(needed.value // ctypes.sizeof(c_void_p), capacity, MAX_MODULES)
            handles = [int(handle) for handle in array[:count] if handle]
            if needed.value <= ctypes.sizeof(array) or count >= MAX_MODULES:
                break
            capacity = min(needed.value // ctypes.sizeof(c_void_p) + 16, MAX_MODULES)

        modules: list[Module] = []
        for handle in handles:
            info = _ModuleInformation()
            if not self._psapi.GetModuleInformation(
                self._handle,
                c_void_p(handle),
                byref(info),
                ctypes.sizeof(info),
            ):
                continue
            base = int(info.lpBaseOfDll or 0)
            size = int(info.SizeOfImage)
            if base <= 0 or size <= 0:
                continue
            path = self._module_path(handle)
            name = Path(path).name or f"module_{base:x}"
            exports, functions, imports, sections = self._pe_metadata(base, size)
            self._sections[base] = sections
            modules.append(
                Module(
                    name=name,
                    base=base,
                    size=size,
                    path=path or None,
                    exports=exports,
                    functions=functions,
                    imports=imports,
                )
            )
        modules.sort(key=lambda module: module.base)
        return tuple(modules)

    def _module_path(self, handle: int) -> str:
        buffer = ctypes.create_unicode_buffer(1024)
        copied = self._psapi.GetModuleFileNameExW(
            self._handle,
            c_void_p(handle),
            buffer,
            len(buffer),
        )
        return buffer.value if copied else ""

    def _enumerate_ranges(self) -> tuple[_MemoryRange, ...]:
        ranges: list[_MemoryRange] = []
        address = 0
        for _ in range(MAX_REGIONS):
            info = _MemoryBasicInformation()
            if not self._kernel32.VirtualQueryEx(
                self._handle,
                c_void_p(address),
                byref(info),
                ctypes.sizeof(info),
            ):
                break
            base = int(info.BaseAddress)
            size = int(info.RegionSize)
            if size <= 0:
                break
            protect = int(info.Protect)
            base_protect = protect & 0xFF
            if (
                int(info.State) == MEM_COMMIT
                and (protect & PAGE_GUARD) == 0
                and base_protect in READABLE_PROTECTIONS
            ):
                ranges.append(
                    _MemoryRange(
                        start=base,
                        size=size,
                        readable=True,
                        executable=base_protect in EXECUTABLE_PROTECTIONS,
                        writable=base_protect in WRITABLE_PROTECTIONS,
                    )
                )
            following = base + size
            if following <= address:
                break
            address = following
        return tuple(ranges)

    def _build_anchor_regions(self) -> tuple[Region, ...]:
        regions: list[Region] = []
        budget = MAX_ANCHOR_BYTES
        for memory in self._ranges:
            if not memory.readable or memory.writable:
                continue
            module = self._module_at(memory.start)
            if module is None:
                continue
            if memory.size > MAX_ANCHOR_REGION_BYTES or memory.size > budget:
                continue
            data = self._read_filled(memory.start, memory.size)
            budget -= len(data)
            rva = memory.start - module.base
            regions.append(
                Region(
                    name=self._section_name(module.base, rva) or f"{module.name}+0x{rva:x}",
                    start=memory.start,
                    size=memory.size,
                    data=data,
                    executable=memory.executable,
                )
            )
        return tuple(regions)

    def _read_filled(self, addr: int, size: int) -> bytes:
        """Read a module range, zero-filling pages the target will not share."""
        data = bytearray(size)
        for offset in range(0, size, MAX_READ_BYTES):
            take = min(MAX_READ_BYTES, size - offset)
            try:
                chunk = self.read(addr + offset, take)
            except ReadError:
                continue
            data[offset : offset + len(chunk)] = chunk
        return bytes(data)

    # -- lookups -----------------------------------------------------------

    def _range_at(self, addr: int) -> _MemoryRange | None:
        index = bisect_right(self._range_starts, addr) - 1
        if index < 0:
            return None
        memory = self._ranges[index]
        return memory if addr < memory.end else None

    def _module_at(self, addr: int) -> Module | None:
        for module in self._modules:
            if module.contains(addr):
                return module
        return None

    def _section_name(self, module_base: int, rva: int) -> str | None:
        for name, section_rva, span in self._sections.get(module_base, ()):
            if section_rva <= rva < section_rva + span:
                return name
        return None

    # -- PE metadata -------------------------------------------------------

    def _pe_metadata(
        self, base: int, size: int
    ) -> tuple[
        dict[str, int],
        dict[int, str],
        dict[int, str],
        tuple[tuple[str, int, int], ...],
    ]:
        """Read export, import, and section metadata from the mapped image.

        Every loop and every read is bounded: the target image is untrusted
        input, so a corrupt header returns empty metadata instead of walking
        arbitrary memory.
        """
        exports: dict[str, int] = {}
        functions: dict[int, str] = {}
        imports: dict[int, str] = {}

        dos = self.try_read(base, 0x40)
        if dos is None or len(dos) < 0x40 or dos[:2] != b"MZ":
            return exports, functions, imports, ()
        lfanew = _u32(dos, 0x3C)
        if lfanew < 0x40 or lfanew + 24 > min(size, MAX_PE_HEADER_BYTES):
            return exports, functions, imports, ()

        header = self.try_read(base + lfanew, 24)
        if header is None or len(header) < 24 or header[:4] != b"PE\0\0":
            return exports, functions, imports, ()
        number_of_sections = _u16(header, 4 + 2)
        size_of_optional = _u16(header, 4 + 16)
        if size_of_optional < 96 or size_of_optional > MAX_PE_HEADER_BYTES:
            return exports, functions, imports, ()

        optional = self.try_read(base + lfanew + 24, min(size_of_optional, MAX_PE_HEADER_BYTES))
        if optional is None or len(optional) < min(size_of_optional, 96):
            return exports, functions, imports, ()
        magic = _u16(optional, 0)
        if magic == 0x20B:
            count_offset, dirs_offset, thunk_size = 108, 112, 8
        elif magic == 0x10B:
            count_offset, dirs_offset, thunk_size = 92, 96, 4
        else:
            return exports, functions, imports, ()
        if len(optional) < dirs_offset:
            return exports, functions, imports, ()
        number_of_dirs = _u32(optional, count_offset)

        sections: list[tuple[str, int, int]] = []
        section_table = base + lfanew + 24 + size_of_optional
        for index in range(min(number_of_sections, MAX_PE_SECTIONS)):
            entry = self.try_read(section_table + index * 40, 40)
            if entry is None or len(entry) < 40:
                break
            name = entry[:8].rstrip(b"\x00").decode("latin-1") or f"s{index}"
            virtual_size = _u32(entry, 8)
            virtual_address = _u32(entry, 12)
            raw_size = _u32(entry, 16)
            span = max(virtual_size, raw_size)
            if span:
                sections.append((name, virtual_address, span))

        if number_of_dirs > 0:
            export_rva = _u32(optional, dirs_offset)
            export_size = _u32(optional, dirs_offset + 4)
            if export_rva and export_size:
                self._pe_exports(
                    base,
                    size,
                    export_rva,
                    export_size,
                    exports,
                    functions,
                )
        if number_of_dirs > 1:
            import_rva = _u32(optional, dirs_offset + 8)
            if import_rva:
                self._pe_imports(base, size, import_rva, thunk_size, imports)

        return exports, functions, imports, tuple(sections)

    def _pe_exports(
        self,
        base: int,
        image_size: int,
        export_rva: int,
        export_size: int,
        exports: dict[str, int],
        functions: dict[int, str],
    ) -> None:
        directory = self.try_read(base + export_rva, 40)
        if directory is None or len(directory) < 40:
            return
        number_of_functions = _u32(directory, 20)
        number_of_names = _u32(directory, 24)
        functions_rva = _u32(directory, 28)
        names_rva = _u32(directory, 32)
        ordinals_rva = _u32(directory, 36)
        count = min(number_of_functions, number_of_names, MAX_PE_EXPORTS)
        for index in range(count):
            name_entry = self.try_read(base + names_rva + index * 4, 4)
            ordinal_entry = self.try_read(base + ordinals_rva + index * 2, 2)
            if name_entry is None or ordinal_entry is None:
                break
            name_rva = _u32(name_entry, 0)
            ordinal = _u16(ordinal_entry, 0)
            if ordinal >= number_of_functions:
                continue
            function_entry = self.try_read(base + functions_rva + ordinal * 4, 4)
            if function_entry is None:
                continue
            function_rva = _u32(function_entry, 0)
            if function_rva == 0:
                continue
            # A forwarder is an RVA into the export directory, not code.
            if export_rva <= function_rva < export_rva + export_size:
                continue
            if function_rva >= image_size or name_rva >= image_size:
                continue
            name = self._read_cstr(base + name_rva)
            if not name:
                continue
            address = base + function_rva
            exports.setdefault(name, address)
            functions.setdefault(address, name)

    def _pe_imports(
        self,
        base: int,
        image_size: int,
        import_rva: int,
        thunk_size: int,
        imports: dict[int, str],
    ) -> None:
        for index in range(MAX_PE_IMPORTS):
            descriptor = self.try_read(base + import_rva + index * 20, 20)
            if descriptor is None or len(descriptor) < 20:
                return
            original_thunk = _u32(descriptor, 0)
            name_rva = _u32(descriptor, 12)
            first_thunk = _u32(descriptor, 16)
            if original_thunk == 0 and name_rva == 0 and first_thunk == 0:
                return
            if name_rva == 0 or name_rva >= image_size:
                continue
            if first_thunk == 0 or first_thunk >= image_size:
                continue
            dll = Path(self._read_cstr(base + name_rva)).stem
            if not dll:
                continue
            thunk_rva = original_thunk or first_thunk
            if thunk_rva == 0 or thunk_rva >= image_size:
                continue
            for slot in range(MAX_IMPORT_THUNKS):
                entry = self.try_read(base + thunk_rva + slot * thunk_size, thunk_size)
                if entry is None or len(entry) < thunk_size:
                    break
                value = _u64(entry, 0) if thunk_size == 8 else _u32(entry, 0)
                if value == 0:
                    break
                high_bit = 1 << (thunk_size * 8 - 1)
                if value & high_bit:
                    symbol = f"#{value & 0xFFFF}"
                else:
                    hint_rva = value & 0x7FFF_FFFF
                    if hint_rva + 2 >= image_size:
                        break
                    symbol = self._read_cstr(base + hint_rva + 2)
                    if not symbol:
                        continue
                address = base + first_thunk + slot * thunk_size
                imports.setdefault(address, f"{dll}!{symbol}")

    def _read_cstr(self, addr: int, limit: int = MAX_PE_NAME) -> str:
        data = self.try_read(addr, limit)
        if not data:
            return ""
        end = data.find(b"\x00")
        if end < 0:
            end = len(data)
        return data[:end].decode("utf-8", "replace")


def _process_arch(kernel32: Any, handle: int) -> Arch:
    process_machine = c_ushort(0)
    native_machine = c_ushort(0)
    is_wow64_process2 = getattr(kernel32, "IsWow64Process2", None)
    if is_wow64_process2 is not None:
        is_wow64_process2.argtypes = [
            c_void_p,
            POINTER(c_ushort),
            POINTER(c_ushort),
        ]
        is_wow64_process2.restype = c_int
        if is_wow64_process2(handle, byref(process_machine), byref(native_machine)):
            machine = int(process_machine.value) or int(native_machine.value)
            return arch_for_machine(machine)

    # Windows 7 fallback: the host is 64-bit here (the project ships 64-bit
    # Python), and IsWow64Process only needs to catch a 32-bit guest.
    is_wow64 = getattr(kernel32, "IsWow64Process", None)
    if is_wow64 is not None:
        is_wow64.argtypes = [c_void_p, POINTER(c_int)]
        is_wow64.restype = c_int
        wow64 = c_int(0)
        if is_wow64(handle, byref(wow64)) and wow64.value:
            raise UnsupportedArchError(
                "32-bit (WOW64) processes are not supported (PLAN.md section 4)"
            )

    info = _SystemInfo()
    kernel32.GetNativeSystemInfo(byref(info))
    host_machine = {
        _PROCESSOR_ARCHITECTURE_AMD64: IMAGE_FILE_MACHINE_AMD64,
        _PROCESSOR_ARCHITECTURE_ARM64: IMAGE_FILE_MACHINE_ARM64,
    }.get(int(info.wProcessorArchitecture))
    if host_machine is None:
        raise UnsupportedArchError(
            f"unsupported host processor architecture {int(info.wProcessorArchitecture)}"
        )
    return arch_for_machine(host_machine)


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return int.from_bytes(data[offset : offset + 8], "little")
