"""Build the cross-compiled corpus and its ground-truth map.

    python corpus/build.py

Requires clang with cross targets and ld.lld. Outputs:

    corpus/build/<arch>/<opt>/<source>.elf
    corpus/build/ground_truth.json

Binaries are never committed (see .gitignore). The ground truth is the symbol
table's function ranges, which are exact for non-inlined, non-aliased symbols;
that matches the M1 exit criterion without needing a DWARF reader.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BUILD = ROOT / "corpus" / "build"
SOURCES = sorted((ROOT / "corpus" / "src").glob("*.c"))
NEGATIVE_SOURCES = sorted((ROOT / "corpus" / "negative").glob("*.c"))
NEGATIVE_OPT = "-O2"

TARGETS = {
    "x64": ("x86_64-linux-gnu", ()),
    "arm64": ("aarch64-linux-gnu", ()),
    "arm32": ("armv7-linux-gnueabihf", ()),
    "thumb": ("armv7-linux-gnueabihf", ("-mthumb",)),
}
OPT_LEVELS = ("-O0", "-O2", "-Os")


def find_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        raise SystemExit(f"{name} not found in PATH")
    return tool


def function_symbols(readelf: str, binary: Path, arch: str) -> list[tuple[str, int, int]]:
    """`.symtab` FUNC symbols as (name, start, size), one per address.

    ARM ELF marks Thumb functions with the low address bit; the start is the
    instruction address, so the bit is cleared there and only there.
    """
    text = subprocess.run(
        [readelf, "-sW", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    by_address: dict[int, tuple[str, int]] = {}
    in_symtab = False
    for line in text.splitlines():
        if line.startswith("Symbol table"):
            in_symtab = "'.symtab'" in line
            continue
        parts = line.split()
        if not in_symtab or len(parts) < 8 or parts[3] != "FUNC" or parts[6] == "UND":
            continue
        start = int(parts[1], 16)
        if arch in ("arm32", "thumb"):
            start &= ~1
        by_address[start] = (parts[7].split("@")[0], int(parts[2], 0))
    return [(name, start, size) for start, (name, size) in by_address.items()]


def build(
    clang: str,
    arch: str,
    target: str,
    opt: str,
    source: Path,
    *,
    root: Path = BUILD,
    extra: tuple[str, ...] = (),
) -> Path | None:
    outdir = root / arch / opt.strip("-")
    outdir.mkdir(parents=True, exist_ok=True)
    binary = outdir / f"{source.stem}.elf"
    command = [
        clang,
        f"--target={target}",
        opt,
        "-g",
        "-nostdlib",
        "-static",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fuse-ld=lld",
        "-Wl,-e,_start",
        *extra,
        str(source),
        "-o",
        str(binary),
    ]
    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0:
        print(f"  skip {arch} {opt} {source.name}: {result.stderr.decode(errors='replace')[:200]}")
        return None
    return binary


def describe(readelf: str, binary: Path, arch: str) -> dict[str, object]:
    symbols = function_symbols(readelf, binary, arch)
    functions = [
        {"name": name, "start": start, "size": size}
        for name, start, size in sorted(symbols)
        if size > 0
    ]
    return {
        "path": binary.relative_to(BUILD).as_posix(),
        "arch": arch,
        "functions": functions,
        "total_symbols": len(symbols),
    }


CORPUS = ROOT / "corpus"


def describe_negative(binary: Path, arch: str) -> dict[str, object]:
    """A negative sample needs only its location and architecture."""
    return {"path": binary.relative_to(BUILD).as_posix(), "arch": arch}


def main() -> int:
    clang = find_tool("clang")
    readelf = find_tool("llvm-readelf")
    if not SOURCES:
        raise SystemExit("no corpus sources under corpus/src")
    BUILD.mkdir(parents=True, exist_ok=True)
    binaries: list[dict[str, object]] = []
    for arch, (target, extra) in TARGETS.items():
        for opt in OPT_LEVELS:
            for source in SOURCES:
                binary = build(clang, arch, target, opt, source, extra=extra)
                if binary is None:
                    continue
                binaries.append(describe(readelf, binary, arch))
    if not binaries:
        raise SystemExit("no corpus binaries were built")

    negative: list[dict[str, object]] = []
    for arch, (target, extra) in TARGETS.items():
        for source in NEGATIVE_SOURCES:
            binary = build(
                clang, arch, target, NEGATIVE_OPT, source, root=BUILD / "negative", extra=extra
            )
            if binary is None:
                continue
            negative.append(describe_negative(binary, arch))

    covered = sum(len(entry["functions"]) for entry in binaries)
    total = sum(int(entry["total_symbols"]) for entry in binaries)
    ground_truth = {
        "binaries": binaries,
        "coverage": (covered / total) if total else 0.0,
        "negative": negative,
    }
    (BUILD / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"built {len(binaries)} binaries, {covered}/{total} functions with sizes")
    print(f"coverage {ground_truth['coverage']:.3f}")
    print(f"negative corpus: {len(negative)} binaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
