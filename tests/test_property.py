"""Property tests: ASLR invariance, determinism, and hostile-byte safety."""

from __future__ import annotations

import random

import pytest

from core.arch import Arch
from core.errors import DecodeError, SigToolError
from core.features import extract
from core.normalize import Normalizer
from core.recover import RecoveryLimits, recover
from core.source import MemorySource, Module, Region

SHIFT = 0x7_0000_0000


def shifted(source: MemorySource, delta: int) -> MemorySource:
    regions = [
        Region(
            name=region.name,
            start=region.start + delta,
            size=region.size,
            data=region.data,
            executable=region.executable,
            writable=region.writable,
        )
        for region in source.regions()
    ]
    module = source.modules()[0]
    shifted_module = Module(
        name=module.name,
        base=module.base + delta,
        size=module.size,
        regions=tuple(regions),
        exports={name: address + delta for name, address in module.exports.items()},
        functions={address + delta: name for address, name in module.functions.items()},
    )
    return MemorySource(source.arch, regions, [shifted_module])


@pytest.mark.parametrize("function", ["loop_sum", "banner_direct", "classify"])
def test_same_code_at_two_bases_yields_identical_features(
    vector: dict[str, object], vector_source: MemorySource, function: str
) -> None:
    info = vector["functions"].get(function)  # type: ignore[union-attr]
    if info is None:
        pytest.skip(f"{function} not present in this vector")
    original = extract(vector_source, recover(vector_source, int(info["entry"])))
    moved_source = shifted(vector_source, SHIFT)
    moved = extract(moved_source, recover(moved_source, int(info["entry"]) + SHIFT))
    assert moved == original


def test_normalization_is_deterministic(
    vector_source: MemorySource, vector: dict[str, object]
) -> None:
    info = next(iter(vector["functions"].values()))  # type: ignore[union-attr]
    entry = int(info["entry"])
    normalizer = Normalizer(vector_source)
    first = normalizer.decode_block(entry, 256)
    second = Normalizer(vector_source).decode_block(entry, 256)
    assert first == second


def test_extraction_is_deterministic(
    vector_source: MemorySource, vector: dict[str, object]
) -> None:
    info = next(iter(vector["functions"].values()))  # type: ignore[union-attr]
    entry = int(info["entry"])
    assert extract(vector_source, recover(vector_source, entry)) == extract(
        vector_source, recover(vector_source, entry)
    )


@pytest.mark.parametrize("arch", [Arch.X64, Arch.ARM64])
def test_random_bytes_never_crash_recovery(arch: Arch) -> None:
    rng = random.Random(0x51670)
    for _ in range(40):
        data = bytes(rng.randrange(256) for _ in range(2048))
        region = Region("blob", 0x1000, len(data), data, executable=True)
        module = Module(name="blob", base=0x1000, size=len(data), regions=(region,))
        source = MemorySource(arch, [region], [module])
        try:
            recovered = recover(
                source, 0x1000, limits=RecoveryLimits(max_instructions=2000, max_blocks=64)
            )
        except DecodeError:
            continue
        except SigToolError:
            continue
        assert recovered.block_count <= 64
        assert recovered.instruction_count <= 4096 * 4


@pytest.mark.parametrize("arch", [Arch.X64, Arch.ARM64])
def test_truncated_region_never_reads_past_the_end(arch: Arch) -> None:
    data = b"\x90" * 3
    region = Region("tiny", 0x1000, len(data), data, executable=True)
    module = Module(name="tiny", base=0x1000, size=len(data), regions=(region,))
    source = MemorySource(arch, [region], [module])
    try:
        recovered = recover(source, 0x1000)
    except DecodeError:
        return
    assert recovered.end <= 0x1004
