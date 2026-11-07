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
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.arch import UnsupportedArchError  # noqa: E402
from sources.file import FileSource  # noqa: E402

BUILD = ROOT / "corpus" / "build"
SOURCES = sorted((ROOT / "corpus" / "src").glob("*.c"))
NEGATIVE_SOURCES = sorted((ROOT / "corpus" / "negative").glob("*.c"))
NEGATIVE_OPT = "-O2"

TARGETS = {
    "x64": "x86_64-linux-gnu",
    "arm64": "aarch64-linux-gnu",
    "arm32": "armv7-linux-gnueabihf",
}
OPT_LEVELS = ("-O0", "-O2", "-Os")


def find_clang() -> str:
    clang = shutil.which("clang")
    if clang is None:
        raise SystemExit("clang not found in PATH")
    return clang


def build(
    clang: str, arch: str, target: str, opt: str, source: Path, *, root: Path = BUILD
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
        str(source),
        "-o",
        str(binary),
    ]
    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0:
        print(f"  skip {arch} {opt} {source.name}: {result.stderr.decode(errors='replace')[:200]}")
        return None
    return binary


def describe(binary: Path) -> dict[str, object]:
    image = FileSource.from_path(binary)
    module = image.modules()[0]
    functions = []
    for address, name in sorted(module.functions.items(), key=lambda item: item[1]):
        bounds = image.hint_function(address)
        if bounds is None:
            continue
        functions.append({"name": name, "start": bounds[0], "size": bounds[1] - bounds[0]})
    return {
        "path": binary.relative_to(BUILD).as_posix(),
        "arch": image.arch.value,
        "functions": functions,
        "total_symbols": len(module.functions),
    }


CORPUS = ROOT / "corpus"


def describe_negative(binary: Path) -> dict[str, object]:
    """A negative sample needs only its location and architecture."""
    return {
        "path": binary.relative_to(BUILD).as_posix(),
        "arch": FileSource.from_path(binary).arch.value,
    }


def main() -> int:
    clang = find_clang()
    if not SOURCES:
        raise SystemExit("no corpus sources under corpus/src")
    BUILD.mkdir(parents=True, exist_ok=True)
    binaries: list[dict[str, object]] = []
    for arch, target in TARGETS.items():
        for opt in OPT_LEVELS:
            for source in SOURCES:
                binary = build(clang, arch, target, opt, source)
                if binary is None:
                    continue
                try:
                    binaries.append(describe(binary))
                except UnsupportedArchError as error:
                    print(f"  skip {binary.name}: {error}")
    if not binaries:
        raise SystemExit("no corpus binaries were built")

    negative: list[dict[str, object]] = []
    for arch, target in TARGETS.items():
        for source in NEGATIVE_SOURCES:
            binary = build(clang, arch, target, NEGATIVE_OPT, source, root=BUILD / "negative")
            if binary is None:
                continue
            try:
                negative.append(describe_negative(binary))
            except UnsupportedArchError as error:
                print(f"  skip {binary.name}: {error}")

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
