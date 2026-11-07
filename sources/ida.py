"""IDA byte source: one function's bytes and names out of an IDA database.

The IDA SDK stays behind the :class:`IdaApi` facade, so ``core/`` never sees it
(AGENTS.md rule 1) and the source is testable without an IDA installation:
tests inject a fake API. :meth:`IdaSource.from_ida` builds the real facade and
is the only place that imports ``ida_*`` modules.

IDA function bounds are passed to recovery as hints, which makes IDA the
authoritative bounder; when recovery disagrees with IDA, the disagreement is
reported (see :func:`bounds_disagreement`) instead of silently trusted.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from core.arch import Arch
from core.errors import ReadError, SourceFormatError, UnsupportedArchError
from core.source import ByteSource, Module, Region
from core.spec import MAX_READ_BYTES

# Segment materialization caps: an IDB can contain huge NOBITS segments, and a
# scanner-like source must not read unbounded memory (AGENTS.md rule 8).
MAX_REGION_BYTES: Final[int] = 64 * 1024 * 1024
MAX_TOTAL_BYTES: Final[int] = 256 * 1024 * 1024

_Reader = Callable[[int, int], "bytes | None"]


class IdaApi(Protocol):
    """The narrow slice of the IDA SDK this source needs."""

    def image_name(self) -> str: ...

    def arch(self) -> Arch: ...

    def segments(self) -> Sequence[tuple[str, int, int, bool]]:
        """``(name, start, end, executable)`` for every segment."""
        ...

    def read(self, addr: int, size: int) -> bytes | None:
        """Segment bytes at ``addr``; ``None`` when nothing is readable."""
        ...

    def functions(self) -> Sequence[tuple[int, int, str, bool]]:
        """``(start, end, name, thumb)`` for every IDA function."""
        ...

    def names(self) -> dict[int, str]:
        """Every named address in the database (functions and data)."""
        ...


@dataclass(frozen=True, slots=True)
class _Function:
    start: int
    end: int
    name: str
    thumb: bool


class IdaSource(ByteSource):
    """A read-only view of the IDB that currently hosts the caller."""

    def __init__(self, api: IdaApi) -> None:
        self._api = api
        self._arch = api.arch()
        if self._arch not in (Arch.X64, Arch.ARM64, Arch.ARM32, Arch.THUMB):
            raise UnsupportedArchError(f"{self._arch.value} is not supported in IDA")

        self._regions: tuple[Region, ...] = self._materialize(api.segments(), api.read)
        if not self._regions:
            raise SourceFormatError("the IDB has no loadable segments")

        self._functions: tuple[_Function, ...] = tuple(
            _Function(start, end, name, thumb)
            for start, end, name, thumb in api.functions()
            if end > start
        )
        self._function_starts: tuple[int, ...] = tuple(
            sorted(function.start for function in self._functions)
        )
        functions: dict[int, str] = {}
        exports: dict[int, str] = {}
        for function in self._functions:
            functions[function.start] = function.name
            exports[function.start] = function.name
        for addr, name in api.names().items():
            exports.setdefault(addr, name)
        self._module = Module(
            name=self._module_name(api.image_name()),
            base=min(region.start for region in self._regions),
            size=max(region.end for region in self._regions)
            - min(region.start for region in self._regions),
            exports={name: addr for addr, name in exports.items()},
            functions=functions,
        )
        self._thumb_ranges: tuple[tuple[int, int], ...] = tuple(
            (function.start, function.end) for function in self._functions if function.thumb
        )

    @classmethod
    def from_ida(cls) -> IdaSource:
        """Build the source for the IDB the plugin is running in."""
        return cls(_sdk_api())

    # -- ByteSource --------------------------------------------------------

    @property
    def arch(self) -> Arch:
        return self._arch

    def regions(self) -> tuple[Region, ...]:
        return self._regions

    def modules(self) -> tuple[Module, ...]:
        return (self._module,)

    def read(self, addr: int, size: int) -> bytes:
        if size < 0 or size > MAX_READ_BYTES:
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
        return self._function_starts

    def hint_function(self, addr: int) -> tuple[int, int] | None:
        """IDA function bounds: the authoritative bounder for this source."""
        for function in self._functions:
            if function.start <= addr < function.end:
                return (function.start, function.end)
        return None

    def is_thumb(self, addr: int) -> bool:
        if self._arch is Arch.THUMB:
            return True
        return any(low <= addr < high for low, high in self._thumb_ranges)

    # -- helpers -----------------------------------------------------------

    def bounds_disagreement(
        self, addr: int, recovered_start: int, recovered_end: int
    ) -> str | None:
        """Human-readable note when recovery and IDA disagree on bounds."""
        hint = self.hint_function(addr)
        if hint is None:
            return "IDA has no function bounds at this address; recovery guessed the end"
        start, end = hint
        if recovered_start == start and recovered_end == end:
            return None
        return (
            f"recovery bounds 0x{recovered_start:x}..0x{recovered_end:x} disagree with "
            f"IDA's function 0x{start:x}..0x{end:x}"
        )

    def _materialize(
        self, segments: Sequence[tuple[str, int, int, bool]], read: _Reader
    ) -> tuple[Region, ...]:
        regions: list[Region] = []
        budget = MAX_TOTAL_BYTES
        for name, start, end, executable in segments:
            size = end - start
            if size <= 0 or size > MAX_REGION_BYTES or size > budget:
                continue
            data = read(start, size)
            if data is None:
                continue
            if len(data) < size:
                # Unreadable tails (NOBITS, failed pages) stay zero-filled so
                # the region keeps its mapped shape.
                data = data + bytes(size - len(data))
            regions.append(
                Region(name=name, start=start, size=size, data=data, executable=executable)
            )
            budget -= size
        regions.sort(key=lambda region: region.start)
        return tuple(regions)

    @staticmethod
    def _module_name(image_name: str) -> str:
        # IDA's root filename is the original binary; the module name is the
        # stem, exactly like FileSource, so provenance matches the CLI.
        stem = image_name.replace("\\", "/").rsplit("/", 1)[-1]
        stem = stem.rsplit(".", 1)[0] if "." in stem else stem
        return stem or "idb"


def _sdk_api() -> IdaApi:
    """Build the real facade; called only inside IDA."""
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_segment
    import idautils

    class _SdkApi:
        def image_name(self) -> str:
            import ida_nalt

            return str(ida_nalt.get_root_filename())

        def arch(self) -> Arch:
            is64 = bool(ida_ida.inf_is_64bit())
            procname = str(ida_ida.inf_get_procname())
            if procname == "metapc":
                if not is64:
                    raise UnsupportedArchError(
                        "32-bit x86 IDBs are unsupported in v1 (do not decode as x64)"
                    )
                return Arch.X64
            if procname == "arm":
                return Arch.ARM64 if is64 else Arch.ARM32
            raise UnsupportedArchError(f"unsupported IDA processor {procname!r}")

        def segments(self) -> Sequence[tuple[str, int, int, bool]]:
            result: list[tuple[str, int, int, bool]] = []
            for index in range(int(ida_segment.get_segm_qty())):
                segment = ida_segment.getnseg(index)
                if segment is None:
                    continue
                result.append(
                    (
                        str(ida_segment.get_segm_name(segment)),
                        int(segment.start_ea),
                        int(segment.end_ea),
                        bool(segment.perm & ida_segment.SEGPERM_EXEC),
                    )
                )
            return result

        def read(self, addr: int, size: int) -> bytes | None:
            data = ida_bytes.get_bytes(addr, size)
            if data is None:
                return None
            return bytes(data)

        def functions(self) -> Sequence[tuple[int, int, str, bool]]:
            thumb_flag = int(ida_funcs.FUNC_THUMB)
            result: list[tuple[int, int, str, bool]] = []
            for index in range(int(ida_funcs.get_func_qty())):
                function = ida_funcs.getn_func(index)
                if function is None:
                    continue
                result.append(
                    (
                        int(function.start_ea),
                        int(function.end_ea),
                        str(ida_funcs.get_func_name(function.start_ea)),
                        bool(function.flags & thumb_flag),
                    )
                )
            return result

        def names(self) -> dict[int, str]:
            return {int(ea): str(name) for ea, name in idautils.Names()}

    return _SdkApi()
