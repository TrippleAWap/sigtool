"""Shared test helpers: build a ``MemorySource`` from a golden vector."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.arch import Arch  # noqa: E402
from core.source import MemorySource, Module, Region  # noqa: E402

VECTOR_DIR = ROOT / "tests" / "vectors"


def load_vector(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def vector_paths() -> list[Path]:
    return sorted(VECTOR_DIR.glob("*.json"))


def source_from_vector(vector: dict[str, object]) -> MemorySource:
    arch = Arch(str(vector["arch"]).replace("-pac", "").replace("-cet", ""))
    regions: list[Region] = []
    for section in vector["sections"]:  # type: ignore[union-attr]
        regions.append(
            Region(
                name=str(section["name"]),
                start=int(section["addr"]),
                size=len(bytes.fromhex(str(section["bytes"]))),
                data=bytes.fromhex(str(section["bytes"])),
                executable=bool(section["executable"]),
            )
        )
    base = min(region.start for region in regions)
    end = max(region.end for region in regions)
    functions = {
        int(info["entry"]): name
        for name, info in vector["functions"].items()  # type: ignore[union-attr]
    }
    module = Module(
        name="fixture",
        base=base,
        size=end - base,
        regions=tuple(regions),
        functions=functions,
        exports={name: address for address, name in functions.items()},
    )
    hints = [
        (int(info["entry"]), int(info.get("end", int(info["entry"]))))
        for info in vector["functions"].values()  # type: ignore[union-attr]
    ]
    return MemorySource(arch, regions, [module], hints=hints)


@pytest.fixture(params=vector_paths(), ids=lambda path: path.stem)
def vector(request: pytest.FixtureRequest) -> dict[str, object]:
    path: Path = request.param
    return load_vector(path)


@pytest.fixture
def vector_source(vector: dict[str, object]) -> MemorySource:
    return source_from_vector(vector)
