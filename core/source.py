"""The ``ByteSource`` contract.

Everything in ``core`` reaches target bytes through this interface, so the same
extractor runs against a live process, an image file, or IDA without knowing
which. Sources own all OS- and tool-specific access.
"""

from __future__ import annotations

import abc
from bisect import bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from core.arch import Arch
from core.errors import ReadError


@dataclass(frozen=True, slots=True)
class Region:
    """A contiguous mapped range with bytes attached."""

    name: str
    start: int
    size: int
    data: bytes
    executable: bool = False
    writable: bool = False

    @property
    def end(self) -> int:
        return self.start + self.size

    def contains(self, addr: int, length: int = 1) -> bool:
        if length <= 0:
            return self.start <= addr < self.end
        return self.start <= addr and addr + length <= self.end

    def read(self, addr: int, size: int) -> bytes:
        if not self.contains(addr, size):
            raise ReadError(f"read of {size} bytes at 0x{addr:x} is outside {self.name}")
        begin = addr - self.start
        return self.data[begin : begin + size]


@dataclass(frozen=True, slots=True)
class Module:
    """A loaded image and the names that can be resolved inside it."""

    name: str
    base: int
    size: int
    path: str | None = None
    regions: tuple[Region, ...] = ()
    # name -> address for exported/dynamic symbols
    exports: Mapping[str, int] = field(default_factory=dict)
    # address -> name for defined function symbols
    functions: Mapping[int, str] = field(default_factory=dict)
    # address -> "module!symbol" for import thunks and IAT/GOT slots
    imports: Mapping[int, str] = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int, length: int = 1) -> bool:
        if length <= 0:
            return self.base <= addr < self.end
        return self.base <= addr and addr + length <= self.end

    def rva(self, addr: int) -> int:
        return addr - self.base

    def name_at(self, addr: int) -> str | None:
        """Return the symbol name defined exactly at ``addr``, if any."""
        if addr in self.imports:
            return self.imports[addr]
        if addr in self.functions:
            return self.functions[addr]
        for name, value in self.exports.items():
            if value == addr:
                return name
        return None


class ByteSource(abc.ABC):
    """Read-only view of the bytes and metadata of one target image."""

    @property
    @abc.abstractmethod
    def arch(self) -> Arch: ...

    @abc.abstractmethod
    def read(self, addr: int, size: int) -> bytes:
        """Read ``size`` bytes at ``addr`` or raise :class:`ReadError`."""

    @abc.abstractmethod
    def regions(self) -> Sequence[Region]: ...

    @abc.abstractmethod
    def modules(self) -> Sequence[Module]: ...

    def hint_function(self, addr: int) -> tuple[int, int] | None:
        """Optional known function bounds ``(start, end)`` from the front-end."""
        return None

    def function_starts(self) -> Sequence[int]:
        """Optional known function entry points.

        Sources that can enumerate symbols override this so the reference
        matcher can compare candidates exactly. The result is never treated as
        exhaustive: sources without symbol information return nothing and the
        matcher falls back to scanning.
        """
        return ()

    # -- helpers built on the contract -------------------------------------

    def try_read(self, addr: int, size: int) -> bytes | None:
        try:
            return self.read(addr, size)
        except ReadError:
            return None

    def read_partial(self, addr: int, size: int) -> bytes:
        """Read up to ``size`` contiguous bytes, stopping at an unmapped edge.

        Decoders use this so a block that runs into the end of a code region
        yields the instructions that are present instead of failing outright.
        The read is bounded by ``spec.MAX_READ_BYTES``.
        """
        from core.spec import MAX_READ_BYTES

        remaining = min(size, MAX_READ_BYTES)
        chunks: list[bytes] = []
        cursor = addr
        while remaining > 0:
            region = self.region_for(cursor)
            if region is None:
                break
            take = min(remaining, region.end - cursor)
            chunks.append(region.read(cursor, take))
            cursor += take
            remaining -= take
        return b"".join(chunks)

    def region_for(self, addr: int) -> Region | None:
        for region in self.regions():
            if region.contains(addr):
                return region
        return None

    def module_for(self, addr: int) -> Module | None:
        for module in self.modules():
            if module.contains(addr):
                return module
        return None

    def is_mapped(self, addr: int, size: int = 1) -> bool:
        if size <= 0:
            return self.region_for(addr) is not None
        return any(region.contains(addr, size) for region in self.regions())

    def is_executable(self, addr: int) -> bool:
        region = self.region_for(addr)
        return bool(region and region.executable)

    def name_for_address(self, addr: int) -> str | None:
        """Resolve a symbol defined at ``addr`` across all modules."""
        for module in self.modules():
            if module.contains(addr):
                name = module.name_at(addr)
                if name is not None:
                    return name
        return None

    def label_for_address(self, addr: int) -> str | None:
        """Symbol name, else ``module+rva``; ``None`` if the address is unmapped.

        Unmapped addresses return ``None`` rather than the raw address so that
        ASLR does not leak into signatures.
        """
        name = self.name_for_address(addr)
        if name is not None:
            return name
        module = self.module_for(addr)
        if module is None:
            return None
        return f"{module.name}+0x{module.rva(addr):x}"


class MemorySource(ByteSource):
    """A ``ByteSource`` over explicit regions, used by tests and live sources."""

    def __init__(
        self,
        arch: Arch,
        regions: Iterable[Region],
        modules: Iterable[Module] = (),
        hints: Iterable[tuple[int, int]] = (),
    ) -> None:
        self._arch = arch
        self._regions: tuple[Region, ...] = tuple(sorted(regions, key=lambda r: r.start))
        self._modules: tuple[Module, ...] = tuple(sorted(modules, key=lambda m: m.base))
        self._hints: tuple[tuple[int, int], ...] = tuple(sorted(hints))
        self._hint_starts = [start for start, _ in self._hints]

    def function_starts(self) -> Sequence[int]:
        starts = {start for start, _ in self._hints}
        for module in self._modules:
            starts.update(module.functions)
            starts.update(module.exports.values())
        return tuple(sorted(starts))

    def hint_function(self, addr: int) -> tuple[int, int] | None:
        if not self._hints:
            return None
        index = bisect_right(self._hint_starts, addr) - 1
        if index < 0:
            return None
        start, end = self._hints[index]
        return (start, end) if start <= addr < end else None

    @property
    def arch(self) -> Arch:
        return self._arch

    def regions(self) -> Sequence[Region]:
        return self._regions

    def modules(self) -> Sequence[Module]:
        return self._modules

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
            raise ReadError(f"read of {size} bytes at 0x{addr:x} crosses unmapped memory")
        return b"".join(chunks)
