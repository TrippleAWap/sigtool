"""IDA source tests: a fake SDK api stands in for an IDA installation."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from core.arch import Arch
from core.generate import generate
from core.sigfile import Signature
from sources.file import FileSource
from sources.ida import IdaSource

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "build"


class FakeApi:
    """The IdaApi protocol over in-memory bytes, functions, and names."""

    def __init__(
        self,
        segments: Sequence[tuple[str, int, bytes, bool]],
        functions: Sequence[tuple[int, int, str, bool]],
        names: dict[int, str] | None = None,
        arch_value: Arch = Arch.X64,
        image: str = "fixture.elf",
    ) -> None:
        self.memory: dict[int, bytes] = {}
        self._segments: list[tuple[str, int, int, bool]] = []
        for name, start, data, executable in segments:
            aligned = start & ~0xF
            pad = start - aligned
            self.memory[aligned] = bytes(pad) + data
            self._segments.append((name, aligned, aligned + pad + len(data), executable))
        self._functions = list(functions)
        self._names = dict(names or {})
        self._arch = arch_value
        self._image = image

    def image_name(self) -> str:
        return self._image

    def arch(self) -> Arch:
        return self._arch

    def segments(self) -> Sequence[tuple[str, int, int, bool]]:
        return self._segments

    def read(self, addr: int, size: int) -> bytes | None:
        chunks: list[bytes] = []
        cursor = addr
        remaining = size
        while remaining > 0:
            page = self.memory.get(cursor)
            if page is None:
                break
            take = min(remaining, len(page))
            chunks.append(page[:take])
            cursor += take
            remaining -= take
        return b"".join(chunks) or None

    def functions(self) -> Sequence[tuple[int, int, str, bool]]:
        return self._functions

    def names(self) -> dict[int, str]:
        return self._names


def api_from_regions(
    arch: Arch,
    regions: Sequence[tuple[str, int, bytes, bool]],
    functions: Sequence[tuple[int, int, str, bool]],
    names: dict[int, str] | None = None,
) -> FakeApi:
    return FakeApi(segments=regions, functions=functions, names=names, arch_value=arch)


def test_ida_source_satisfies_the_bytesource_contract() -> None:
    api = api_from_regions(
        Arch.X64,
        [
            ("text", 0x1000, b"\xc3" * 16, True),
            ("rodata", 0x2000, b"banner literal\x00", False),
        ],
        [(0x1000, 0x1010, "only_fn", False)],
        names={0x2000: "banner"},
    )
    source = IdaSource(api)

    assert source.arch is Arch.X64
    assert source.modules()[0].name == "fixture"
    assert source.read(0x1000, 4) == b"\xc3" * 4
    assert source.read(0x2000, 6) == b"banner"
    assert source.is_executable(0x1000)
    assert not source.is_executable(0x2000)
    assert source.function_starts() == (0x1000,)
    assert source.hint_function(0x1008) == (0x1000, 0x1010)
    assert source.hint_function(0x1010) is None
    assert not source.is_thumb(0x1000)

    with pytest.raises(Exception, match="unmapped"):
        source.read(0x9000, 4)


def test_thumb_functions_track_the_ida_mode_flag() -> None:
    api = api_from_regions(
        Arch.ARM32,
        [("text", 0x1000, b"\x00" * 32, True)],
        [
            (0x1000, 0x1010, "arm_fn", False),
            (0x1010, 0x1020, "thumb_fn", True),
        ],
    )
    source = IdaSource(api)

    assert not source.is_thumb(0x1004)
    assert source.is_thumb(0x1014)
    # IDA reports Thumb function starts at their byte address; the mode comes
    # from the FUNC_THUMB flag, not the low bit.
    assert source.function_starts() == (0x1000, 0x1010)


def test_generation_matches_the_file_path_for_the_same_inputs() -> None:
    """The M5 exit criterion: same bytes and names, same signature as the CLI."""
    vector_path = Path(__file__).parent / "vectors" / "x64-O2.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    regions = [
        (
            str(section["name"]),
            int(section["addr"]),
            bytes.fromhex(str(section["bytes"])),
            bool(section["executable"]),
        )
        for section in vector["sections"]
    ]
    functions = [
        (int(info["entry"]), int(info["end"]), name, False)
        for name, info in vector["functions"].items()
    ]
    names = {int(info["entry"]): name for name, info in vector["functions"].items()}
    source = IdaSource(api_from_regions(Arch.X64, regions, functions, names))

    for name, info in vector["functions"].items():
        if name == "_start":
            continue
        result = generate(source, int(info["entry"]))
        assert result.signature.name == name
        assert [feature.value for feature in result.signature.features] == [
            feature["value"] for feature in info["features"]
        ], name


def test_generation_identity_with_file_source_on_the_corpus() -> None:
    """Over a real image, the IDA path and the CLI path emit byte-identical YAML."""
    path = CORPUS / "x64" / "O2" / "parser.elf"
    if not path.exists():
        pytest.skip("corpus not built; run python corpus/build.py")
    image = FileSource.from_path(path)
    module = image.modules()[0]

    class CorpusApi:
        def image_name(self) -> str:
            # IDA's root filename is the original binary, matching the CLI.
            return path.name

        def arch(self) -> Arch:
            return image.arch

        def segments(self) -> Sequence[tuple[str, int, int, bool]]:
            return [
                (region.name, region.start, region.end, region.executable)
                for region in image.regions()
            ]

        def read(self, addr: int, size: int) -> bytes | None:
            try:
                return image.read(addr, size)
            except Exception:
                return None

        def functions(self) -> Sequence[tuple[int, int, str, bool]]:
            result = []
            for addr, name in sorted(module.functions.items()):
                bounds = image.hint_function(addr)
                if bounds is None:
                    continue
                result.append((addr, bounds[1], name, False))
            return result

        def names(self) -> dict[int, str]:
            return {addr: name for name, addr in module.exports.items()}

    source = IdaSource(CorpusApi())
    for addr in sorted(module.functions)[:5]:
        from_ida = generate(source, addr)
        from_file = generate(image, addr)
        assert from_ida.signature.to_yaml() == from_file.signature.to_yaml()


def test_bounds_disagreement_is_reported_not_hidden() -> None:
    api = api_from_regions(
        Arch.X64,
        [("text", 0x1000, b"\xc3" * 16, True)],
        [(0x1000, 0x1004, "short_fn", False)],
    )
    source = IdaSource(api)

    assert source.bounds_disagreement(0x1000, 0x1000, 0x1004) is None
    note = source.bounds_disagreement(0x1000, 0x1000, 0x1010)
    assert note is not None and "disagree" in note
    # An address outside every IDA function has no bounds to agree with.
    assert "no function bounds" in (source.bounds_disagreement(0x1010, 0x1010, 0x1014) or "")


def test_oversized_reads_are_refused() -> None:
    api = api_from_regions(
        Arch.X64,
        [("text", 0x1000, b"\x00" * 32, True)],
        [(0x1000, 0x1020, "fn", False)],
    )
    source = IdaSource(api)
    with pytest.raises(Exception, match="refusing read"):
        source.read(0x1000, 1 << 20)


def test_signature_round_trip_from_an_ida_source(tmp_path: Path) -> None:
    api = api_from_regions(
        Arch.X64,
        [
            ("text", 0x1000, b"\xb8\x34\x12\x00\x00\xc3", True),
            ("rodata", 0x2000, b"banner literal\x00", False),
        ],
        [(0x1000, 0x1006, "fn", False)],
    )
    source = IdaSource(api)
    result = generate(source, 0x1000)
    restored = Signature.from_yaml(result.to_yaml())
    assert restored.signature_id == result.signature.signature_id
