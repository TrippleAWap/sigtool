"""Feature extraction unit tests: strings, constants, buckets, and shape."""

from __future__ import annotations

import pytest

from core.arch import Arch
from core.features import Feature, extract, string_at
from core.recover import recover
from core.source import MemorySource, Module, Region
from core.spec import bucket, bucket_range


def make_source(
    code: bytes, data: bytes = b"", base: int = 0x1000, data_base: int = 0x2000
) -> MemorySource:
    regions = [Region("text", base, len(code), code, executable=True)]
    if data:
        regions.append(Region("rodata", data_base, len(data), data))
    module = Module(
        name="fixture",
        base=base,
        size=(data_base + len(data) - base) if data else len(code),
        regions=tuple(regions),
    )
    return MemorySource(Arch.X64, regions, [module])


def lea_to(target: int, insn_addr: int = 0x1000) -> bytes:
    disp = target - (insn_addr + 7)
    return b"\x48\x8d\x3d" + disp.to_bytes(4, "little", signed=True)


def test_string_reference_becomes_str_feature() -> None:
    data = b"hello sigtool\0"
    code = lea_to(0x2000) + b"\xc3"
    source = make_source(code, data)
    features = extract(source, recover(source, 0x1000))
    assert Feature("str", "hello sigtool") in features


def test_adjacent_strings_are_separate_features() -> None:
    data = b"first literal\0second literal\0"
    code = lea_to(0x2000) + b"\x90" + lea_to(0x2000 + 14, 0x1008) + b"\xc3"
    source = make_source(code, data)
    values = {f.value for f in extract(source, recover(source, 0x1000)) if f.kind == "str"}
    assert values == {"first literal", "second literal"}


def test_short_or_binary_data_is_not_a_string() -> None:
    data = b"abc\0" + bytes(range(256))
    source = make_source(b"\xc3", data)
    assert string_at(source, 0x2000) is None
    assert string_at(source, 0x2004) is None


def test_wide_string_is_detected() -> None:
    data = "wide".encode("utf-16-le") + b"\x00\x00"
    source = make_source(b"\xc3", data)
    assert string_at(source, 0x2000) == "w:wide"


def test_executable_memory_is_never_read_as_string() -> None:
    source = make_source(b"readable text\0")
    assert string_at(source, 0x1000) is None


def test_pointer_constants_are_dropped() -> None:
    # movabs rax, 0x2000 materialises an address inside the module.
    code = b"\x48\xb8" + (0x2000).to_bytes(8, "little") + b"\xc3"
    source = make_source(code, b"payload\0")
    features = extract(source, recover(source, 0x1000))
    assert all(f.value != "0x2000" for f in features)
    assert Feature("const", "0x2000") not in features


def test_non_pointer_constant_is_kept() -> None:
    code = b"\x48\xb8" + (0xDEAD_BEEF).to_bytes(8, "little") + b"\xc3"
    source = make_source(code)
    features = extract(source, recover(source, 0x1000))
    assert Feature("const", "0xdeadbeef") in features


def test_cfg_and_ops_features_are_present() -> None:
    source = make_source(b"\x55\x48\x89\xe5\xc3")  # push rbp; mov rbp,rsp; ret
    features = extract(source, recover(source, 0x1000))
    cfg = {f.value for f in features if f.kind == "cfg"}
    assert any(value.startswith("blocks:") for value in cfg)
    assert any(value.startswith("edges:") for value in cfg)
    assert any(value.startswith("loops:") for value in cfg)
    assert any(f.kind == "ops" and f.value.startswith("ret:") for f in features)


def test_features_are_sorted_and_unique() -> None:
    source = make_source(b"\x90\xc3")
    features = extract(source, recover(source, 0x1000))
    assert list(features) == sorted(set(features))


@pytest.mark.parametrize(
    ("value", "index"),
    [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 5), (7, 6), (200, 14), (10_000, 14)],
)
def test_bucket_boundaries(value: int, index: int) -> None:
    assert bucket(value) == index


def test_bucket_range_covers_value() -> None:
    for value in (0, 1, 5, 12, 50, 500):
        low, high = bucket_range(bucket(value))
        assert low <= value
        assert high == -1 or value <= high
