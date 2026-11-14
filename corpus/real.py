"""Build the real-library corpus: pinned open-source C libraries, cross-compiled.

    python corpus/real.py                  # fetch (sha256-pinned), build, write ground truth
    python corpus/real.py --max-functions 0  # keep every common function

Outputs, never committed:

    corpus/third_party/<archive and extracted sources>
    corpus/build-real/<arch>/<compiler>-<opt>/<library>.so
    corpus/build-real/stripped/<arch>/<compiler>-<opt>/<library>.so  (llvm-strip --strip-all)
    corpus/build-real/ground_truth.json   (same schema as corpus/build/, plus "stripped")

Hint-free recall is measured on the stripped copies: `--strip-all` removes
.symtab exactly as a distro strip does and keeps .dynsym, which dynamic
linking needs. Scanning the unstripped file without hints would still leak
local symbol names into callee features and Thumb-mode detection.

Every library is built by two compiler families. clang runs on the host and
links a shared object with no libc (calls stay undefined PLT imports), with
headers from the declarations-only shim in corpus/shim/include. GCC 12 runs in
the corpus/docker image against real glibc headers and links libc normally,
as a distro build would. Measuring across both is what keeps the numbers from
describing one compiler's code generation. Ground truth is
the ELF symbol table (FUNC, defined, non-zero size), restricted to names that
exist exactly once in every build of a library, so each recall attempt has a
true answer on every architecture and optimization level. A deterministic
subset (by CRC-32 of the name) keeps the bench fast; the libraries double as
each other's false-positive corpus.

The purpose-written corpus in corpus/build/ stays for golden-scale checks;
this one is what the cross-architecture numbers should be read from.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
THIRD_PARTY = CORPUS / "third_party"
BUILD = CORPUS / "build-real"
SHIM = CORPUS / "shim" / "include"

TARGETS = {
    "x64": ("x86_64-linux-gnu", ()),
    "arm64": ("aarch64-linux-gnu", ()),
    "arm32": ("armv7-linux-gnueabihf", ("-marm",)),
    "thumb": ("armv7-linux-gnueabihf", ("-mthumb",)),
}
# GCC driver per arch inside the docker image; armhf defaults to Thumb-2, so
# ARM mode is requested explicitly.
GCC = {
    "x64": ("gcc", ()),
    "arm64": ("aarch64-linux-gnu-gcc", ()),
    "arm32": ("arm-linux-gnueabihf-gcc", ("-marm", "-march=armv7-a", "-mfpu=vfpv3-d16")),
    "thumb": ("arm-linux-gnueabihf-gcc", ("-mthumb", "-march=armv7-a", "-mfpu=vfpv3-d16")),
}
COMPILERS = ("clang", "gcc")
DOCKER_IMAGE = "sigtool-gcc-cross"
OPT_LEVELS = ("-O0", "-O2", "-Os")
DEFAULT_MAX_FUNCTIONS = 150


@dataclass(frozen=True)
class Library:
    name: str
    url: str
    sha256: str
    root: str
    sources: tuple[str, ...]
    includes: tuple[str, ...] = ()
    defines: tuple[str, ...] = ()
    exclude: tuple[str, ...] = field(default=())


LIBRARIES = (
    Library(
        "zlib",
        "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
        "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
        "zlib-1.3.1",
        ("*.c",),
        includes=(".",),
        defines=("Z_HAVE_UNISTD_H",),
    ),
    Library(
        "lz4",
        "https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz",
        "537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b",
        "lz4-1.10.0",
        ("lib/lz4.c", "lib/lz4hc.c", "lib/lz4frame.c", "lib/xxhash.c"),
        includes=("lib",),
    ),
    Library(
        "cjson",
        "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz",
        "3aa806844a03442c00769b83e99970be70fbef03735ff898f4811dd03b9f5ee5",
        "cJSON-1.7.18",
        ("cJSON.c", "cJSON_Utils.c"),
        includes=(".",),
    ),
    Library(
        "lua",
        "https://www.lua.org/ftp/lua-5.4.7.tar.gz",
        "9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30",
        "lua-5.4.7",
        ("src/*.c",),
        includes=("src",),
        exclude=("src/lua.c", "src/luac.c"),
    ),
    Library(
        "sqlite",
        "https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip",
        "77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784",
        "sqlite-amalgamation-3460100",
        ("sqlite3.c",),
        includes=(".",),
        # No OS layer: the shim has no POSIX file or thread API, and the VFS
        # is irrelevant to function identity.
        defines=(
            "SQLITE_OS_OTHER=1",
            "SQLITE_THREADSAFE=0",
            "SQLITE_OMIT_LOAD_EXTENSION=1",
        ),
    ),
)


def fetch(library: Library) -> Path:
    THIRD_PARTY.mkdir(parents=True, exist_ok=True)
    archive = THIRD_PARTY / "dl" / library.url.rsplit("/", 1)[-1]
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        print(f"fetch {library.url}")
        with urllib.request.urlopen(library.url, timeout=120) as response:
            archive.write_bytes(response.read())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != library.sha256:
        archive.unlink()
        raise SystemExit(f"{archive.name}: sha256 {digest} != pinned {library.sha256}")
    root = THIRD_PARTY / library.root
    if not root.exists():
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(THIRD_PARTY)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(THIRD_PARTY, filter="data")
    return root


def sources(library: Library, root: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in library.sources:
        found.extend(sorted(root.glob(pattern)))
    excluded = {root / item for item in library.exclude}
    return [path for path in found if path not in excluded]


def output_path(library: Library, arch: str, compiler: str, opt: str) -> Path:
    outdir = BUILD / arch / f"{compiler}-{opt.strip('-')}"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir / f"{library.name}.so"


def up_to_date(output: Path, library: Library, root: Path) -> bool:
    """The output is newer than every input that can change it."""
    if not output.exists():
        return False
    inputs = [*sources(library, root), Path(__file__), *SHIM.rglob("*.h")]
    for include in library.includes:
        inputs.extend((root / include).glob("*.h"))
    built = output.stat().st_mtime
    return all(path.stat().st_mtime <= built for path in inputs)


def build_clang(clang: str, library: Library, root: Path, arch: str, opt: str) -> Path | None:
    target, extra = TARGETS[arch]
    output = output_path(library, arch, "clang", opt)
    if up_to_date(output, library, root):
        return output
    command = [
        clang,
        f"--target={target}",
        opt,
        *extra,
        "-fPIC",
        "-shared",
        "-nostdlib",
        "-nostdlibinc",
        "-isystem",
        str(SHIM),
        "-fuse-ld=lld",
        "-Wl,--build-id=none",
        "-w",
        *(f"-I{root / include}" for include in library.includes),
        *(f"-D{define}" for define in library.defines),
        *(str(path) for path in sources(library, root)),
        "-o",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        print(f"  FAIL clang {library.name} {arch} {opt}:\n{result.stderr[-3000:]}")
        return None
    return output


def build_gcc(library: Library, root: Path) -> dict[tuple[str, str], Path]:
    """Every GCC build of one library in a single container run."""
    lines = ["set -u"]
    outputs: dict[tuple[str, str], Path] = {}
    for arch, (driver, extra) in GCC.items():
        for opt in OPT_LEVELS:
            output = output_path(library, arch, "gcc", opt)
            outputs[(arch, opt)] = output
            if up_to_date(output, library, root):
                continue
            container_out = "/work/" + output.relative_to(CORPUS).as_posix()
            container_root = "/work/" + root.relative_to(CORPUS).as_posix()
            files = " ".join(
                f"{container_root}/{path.relative_to(root).as_posix()}"
                for path in sources(library, root)
            )
            flags = " ".join(
                [opt, *extra, "-fPIC", "-shared", "-w", "-Wl,--build-id=none"]
                + [f"-I{container_root}/{include}" for include in library.includes]
                + [f"-D{define}" for define in library.defines]
            )
            # Independent builds run as concurrent jobs inside one container.
            lines.append(
                f"( {driver} {flags} {files} -o {container_out} -lm "
                f"|| echo FAIL gcc {library.name} {arch} {opt} ) &"
            )
    if len(lines) == 1:
        return outputs
    lines.append("wait")
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{CORPUS}:/work",
        DOCKER_IMAGE,
        "sh",
        "-c",
        "\n".join(lines),
    ]
    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    if result.returncode != 0 or "FAIL" in result.stdout:
        print(result.stdout[-2000:], result.stderr[-3000:])
    return {key: path for key, path in outputs.items() if path.exists()}


def function_symbols(readelf: str, binary: Path, arch: str) -> dict[str, tuple[int, int]]:
    """Defined FUNC symbols with a size, minus names that occur twice."""
    text = subprocess.run(
        [readelf, "-sW", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    symbols: dict[str, tuple[int, int]] = {}
    duplicate: set[str] = set()
    in_symtab = False
    for line in text.splitlines():
        if line.startswith("Symbol table"):
            # .dynsym repeats exported functions; .symtab is the complete list.
            in_symtab = "'.symtab'" in line
            continue
        parts = line.split()
        if not in_symtab or len(parts) < 8 or parts[3] != "FUNC" or parts[6] == "UND":
            continue
        size = int(parts[2], 0)
        if size == 0:
            continue
        # ARM ELF marks Thumb functions with the low address bit. Only there:
        # x86-64 functions at O0/Os often start at odd addresses.
        start = int(parts[1], 16)
        if arch in ("arm32", "thumb"):
            start &= ~1
        name = parts[7].split("@")[0]
        if name in symbols and symbols[name][0] != start:
            duplicate.add(name)
        symbols[name] = (start, size)
    for name in duplicate:
        del symbols[name]
    return symbols


def strip(llvm_strip: str, binary: Path) -> Path:
    stripped = BUILD / "stripped" / binary.relative_to(BUILD)
    stripped.parent.mkdir(parents=True, exist_ok=True)
    if not stripped.exists() or stripped.stat().st_mtime < binary.stat().st_mtime:
        subprocess.run([llvm_strip, "--strip-all", str(binary), "-o", str(stripped)], check=True)
    return stripped


def select(names: set[str], limit: int) -> list[str]:
    """Deterministic subset, independent of build order and Python's hash()."""
    ranked = sorted(names, key=lambda name: (zlib.crc32(name.encode()), name))
    return sorted(ranked if limit <= 0 else ranked[:limit])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-functions", type=int, default=DEFAULT_MAX_FUNCTIONS)
    parser.add_argument("--library", action="append", help="limit to named libraries")
    parser.add_argument(
        "--compiler", action="append", choices=COMPILERS, help="limit to one compiler family"
    )
    args = parser.parse_args(argv)
    args.compiler = tuple(args.compiler or COMPILERS)

    clang = shutil.which("clang")
    readelf = shutil.which("llvm-readelf")
    llvm_strip = shutil.which("llvm-strip")
    if clang is None or readelf is None or llvm_strip is None:
        raise SystemExit("clang, llvm-readelf, and llvm-strip must be on PATH")

    libraries = [lib for lib in LIBRARIES if not args.library or lib.name in args.library]
    roots = {library.name: fetch(library) for library in libraries}

    # Every build is independent: clang jobs per (library, arch, opt) and one
    # container per library (itself running its builds concurrently) share
    # one pool sized to the machine.
    clang_jobs = {}
    gcc_jobs = {}
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        for library in libraries:
            root = roots[library.name]
            if "gcc" in args.compiler:
                gcc_jobs[library.name] = pool.submit(build_gcc, library, root)
            if "clang" in args.compiler:
                for arch in TARGETS:
                    for opt in OPT_LEVELS:
                        clang_jobs[(library.name, arch, opt)] = pool.submit(
                            build_clang, clang, library, root, arch, opt
                        )

    binaries: list[dict[str, object]] = []
    for library in libraries:
        built: dict[tuple[str, str], dict[str, tuple[int, int]]] = {}
        for (name, arch, opt), job in sorted(clang_jobs.items()):
            output = job.result()
            if name == library.name and output is not None:
                built[(arch, f"clang-{opt.strip('-')}")] = function_symbols(readelf, output, arch)
        if library.name in gcc_jobs:
            for (arch, opt), output in gcc_jobs[library.name].result().items():
                built[(arch, f"gcc-{opt.strip('-')}")] = function_symbols(readelf, output, arch)
        if len(built) != len(TARGETS) * len(OPT_LEVELS) * len(args.compiler):
            print(f"  {library.name}: some builds failed; skipped from ground truth")
            continue
        common = set.intersection(*(set(symbols) for symbols in built.values()))
        chosen = select(common, args.max_functions)
        print(f"{library.name}: {len(common)} common functions, {len(chosen)} selected")
        for (arch, opt), symbols in sorted(built.items()):
            stripped = strip(llvm_strip, BUILD / arch / opt / f"{library.name}.so")
            binaries.append(
                {
                    "path": f"{arch}/{opt}/{library.name}.so",
                    "stripped": stripped.relative_to(BUILD).as_posix(),
                    "arch": arch,
                    "library": library.name,
                    "functions": [
                        {"name": name, "start": symbols[name][0], "size": symbols[name][1]}
                        for name in chosen
                    ],
                    "total_symbols": len(symbols),
                }
            )

    BUILD.mkdir(parents=True, exist_ok=True)
    document = {"binaries": binaries, "negative": []}
    (BUILD / "ground_truth.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
