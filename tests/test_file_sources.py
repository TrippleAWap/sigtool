"""File-source tests against real compiler output (ELF object, ELF image, PE image)."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from core.features import Feature, extract
from core.recover import recover
from sources.file import FileSource

SOURCE = r"""
const char *file_msg = "file source banner literal";

int add_two(int a, int b) { return a + b; }
int calc(int x) { return add_two(x, 0x1234); }
const char *banner(void) { return file_msg; }
const char *direct(void) { return "object direct literal"; }
const char *direct2(void) { return "object second literal"; }
void _start(void) {}
"""


def build(tmp_path, compiler: str, *flags: str) -> bytes:
    source = tmp_path / "fixture.c"
    source.write_text(SOURCE)
    target = tmp_path / "fixture.out"
    subprocess.run(
        [compiler, *flags, str(source), "-o", str(target)], check=True, capture_output=True
    )
    return target.read_bytes()


def symbols(source: FileSource) -> dict[str, int]:
    module = source.modules()[0]
    return {name: address for address, name in module.functions.items()}


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_elf_object_source(tmp_path) -> None:
    data = build(tmp_path, "clang", "--target=x86_64-linux-gnu", "-O2", "-c")
    source = FileSource.from_bytes(data, "fixture.o")
    assert source.arch.value == "x64"
    names = symbols(source)
    assert "direct" in names, names

    # A relocatable object has no applied relocations, so its cross-section
    # string reference is unresolved: the encoding carries a zero displacement.
    # Recovery must still work inside the section and produce shape features.
    address = names["direct"]
    recovered = recover(source, address)
    features = extract(source, recovered)
    assert recovered.block_count == 1
    assert Feature("ops", "move:1") in features
    assert Feature("ops", "ret:1") in features


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang not installed")
def test_elf_image_resolves_callee_names(tmp_path) -> None:
    # -O0 keeps the call to add_two; at -O2 it is inlined and no callee remains.
    data = build(
        tmp_path,
        "clang",
        "--target=x86_64-linux-gnu",
        "-O0",
        "-nostdlib",
        "-static",
        "-fuse-ld=lld",
        "-Wl,-e,_start",
    )
    source = FileSource.from_bytes(data, "fixture.elf")
    names = symbols(source)
    assert "calc" in names and "add_two" in names

    features = extract(source, recover(source, names["calc"]))
    callees = {feature.value for feature in features if feature.kind == "callee"}
    assert "add_two" in callees, callees


@pytest.mark.skipif(
    shutil.which("x86_64-w64-mingw32-gcc") is None, reason="mingw-w64 not installed"
)
def test_pe_image_source(tmp_path) -> None:
    data = build(
        tmp_path,
        "x86_64-w64-mingw32-gcc",
        "-O2",
        "-nostdlib",
        "-Wl,--entry,_start",
        "-Wl,--export-all-symbols",
        "-Wl,--no-insert-timestamp",
    )
    source = FileSource.from_bytes(data, "fixture.exe")
    assert source.arch.value == "x64"
    module = source.modules()[0]
    assert any(region.name for region in source.regions())
    assert "add_two" in module.exports, list(module.exports)[:10]

    address = module.exports["add_two"]
    features = extract(source, recover(source, address))
    assert any(feature.kind == "ops" for feature in features)
