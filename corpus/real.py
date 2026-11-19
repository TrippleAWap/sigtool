"""Build the real-library corpus: pinned open-source C libraries, cross-compiled.

    python corpus/real.py                  # fetch (sha256-pinned), build, write ground truth
    python corpus/real.py --max-functions 0  # keep every common function
    python corpus/real.py --heldout        # held-out libraries into corpus/build-heldout/
    python corpus/real.py --world          # real-world build profiles into corpus/build-world/
    python corpus/real.py --pe             # PE DLLs into corpus/build-pe/, corpus/build-pe-mixed/

Outputs, never committed:

    corpus/third_party/<archive and extracted sources>
    corpus/build-real/<arch>/<compiler>-<opt>/<library>.so
    corpus/build-real/stripped/<arch>/<compiler>-<opt>/<library>.so  (llvm-strip --strip-all)
    corpus/build-real/ground_truth.json   (same schema as corpus/build/, plus "stripped")

--heldout swaps the library list (zstd, libyaml, mbedtls) and the output
directory (corpus/build-heldout/, same layout) and keeps everything else, so
the held-out numbers come from exactly the same build matrix. Those libraries
are never used for tuning; they are measured at milestone exits only.

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

--world builds the tuning libraries with gcc only, at -O2, in the profiles
real binaries come in (WORLD_PROFILES): distro hardening flags, -O3, LTO, a
PIE and a static executable linking the library, and the previous upstream
release. Build names keep the `<profile>-<level>` form the bench reads, so
the bench's "other compiler" row there means "other profile, same level".
It is a separate tier, outside the weekly gate (docs/real-world-plan.md RW4).

--pe builds the tuning libraries as Windows DLLs into corpus/build-pe/ with
the host clang for x86_64- and aarch64-pc-windows-msvc, linked by lld-link
(`lld -flavor link`), with no Windows SDK: the shim plus the Windows headers
in corpus/shim/include-win, and import libraries generated per DLL from the
symbols its objects leave undefined, so CRT calls become ucrtbase.dll imports
(through `jmp [__imp_X]` thunks) and Win32 calls kernel32.dll imports (direct
`call [__imp_X]`, as the SDK declares them dllimport), as in a real DLL. Each
library exports its public API only, through its own Windows DLL mechanism
(PE_DEFINES, PE_DEF_FILES), and links the CRT pieces an MSVC DLL takes
statically (PE_CRT). Builds: -O0, -O2, -Os, plus -O2 with /GS
(`clang+gs`) and with /guard:cf (`clang+cfg`). Ground truth comes from the
lld-link map (functions in CODE sections of the library's own objects; VAs),
restricted like the ELF builds to names unique in every build. A PE file has
no symbol table, so there is nothing to strip: "stripped" names the same
file. Each DLL also gets LIB.functions.json, every defined function, for
examples/start_recall.rs. corpus/build-pe-mixed/ then pairs the ELF clang
builds of corpus/build-real (x64, arm64) with the plain PE builds, renamed
`clang+pe-<level>`, under one ground truth, so the bench measures ELF
signatures found in PE images and back without code changes.

The purpose-written corpus in corpus/build/ stays for golden-scale checks;
this one is what the cross-architecture numbers should be read from.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
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
HELDOUT_BUILD = CORPUS / "build-heldout"
WORLD_BUILD = CORPUS / "build-world"
PE_BUILD = CORPUS / "build-pe"
PE_MIXED_BUILD = CORPUS / "build-pe-mixed"
SHIM = CORPUS / "shim" / "include"
SHIM_WINDOWS = CORPUS / "shim" / "include-win"

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
# The --world tier strips with the target's binutils, as a distro build
# does: llvm-strip refuses gcc's static ARM executables (a `.rel.dyn` whose
# link field names no symbol table).
STRIP = {
    "x64": "strip",
    "arm64": "aarch64-linux-gnu-strip",
    "arm32": "arm-linux-gnueabihf-strip",
    "thumb": "arm-linux-gnueabihf-strip",
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

# Held out from tuning (PLAN.md §5): measured only at milestone exits, so a
# rule fitted to LIBRARIES cannot also have been fitted to these.
HELDOUT = (
    Library(
        "zstd",
        "https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz",
        "8c29e06cf42aacc1eafc4077ae2ec6c6fcb96a626157e0593d5e82a34fd403c1",
        "zstd-1.5.6",
        (
            "lib/common/*.c",
            "lib/compress/*.c",
            "lib/decompress/*.c",
            "lib/dictBuilder/*.c",
        ),
        includes=("lib", "lib/common"),
        # The x86-64 Huffman decoder is hand-written assembly on that arch
        # only; the C path keeps the function set the same on every target.
        defines=("ZSTD_DISABLE_ASM=1",),
    ),
    Library(
        "libyaml",
        "https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz",
        "c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4",
        "yaml-0.2.5",
        ("src/*.c",),
        includes=("include", "src"),
        # What configure would write to config.h.
        defines=(
            "YAML_VERSION_MAJOR=0",
            "YAML_VERSION_MINOR=2",
            "YAML_VERSION_PATCH=5",
            'YAML_VERSION_STRING="0.2.5"',
        ),
    ),
    Library(
        "mbedtls",
        "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2",
        "8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca",
        "mbedtls-3.6.2",
        ("library/*.c",),
        includes=("include", "library"),
        # The socket layer is OS glue (BSD sockets, not in the shim) and is
        # irrelevant to function identity, as SQLite's VFS is.
        exclude=("library/net_sockets.c",),
    ),
)


# The release before each tuning library's pin, for the version-drift
# profile: the same function one upstream release apart, as a user porting
# names from an analysed build to the next one meets it.
PREVIOUS = {
    "zlib": Library(
        "zlib",
        "https://zlib.net/fossils/zlib-1.2.13.tar.gz",
        "b3a24de97a8fdbc835b9833169501030b8977031bcb54b3b3ac13740f846ab30",
        "zlib-1.2.13",
        ("*.c",),
        includes=(".",),
        defines=("Z_HAVE_UNISTD_H",),
    ),
    "lz4": Library(
        "lz4",
        "https://github.com/lz4/lz4/releases/download/v1.9.4/lz4-1.9.4.tar.gz",
        "0b0e3aa07c8c063ddf40b082bdf7e37a1562bda40a0ff5272957f3e987e0e54b",
        "lz4-1.9.4",
        ("lib/lz4.c", "lib/lz4hc.c", "lib/lz4frame.c", "lib/xxhash.c"),
        includes=("lib",),
    ),
    "cjson": Library(
        "cjson",
        "https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.15.tar.gz",
        "5308fd4bd90cef7aa060558514de6a1a4a0819974a26e6ed13973c5f624c24b2",
        "cJSON-1.7.15",
        ("cJSON.c", "cJSON_Utils.c"),
        includes=(".",),
    ),
    "lua": Library(
        "lua",
        "https://www.lua.org/ftp/lua-5.4.6.tar.gz",
        "7d5ea1b9cb6aa0b59ca3dde1c6adcb57ef83a1ba8e5432c0ecd06bf439b3ad88",
        "lua-5.4.6",
        ("src/*.c",),
        includes=("src",),
        exclude=("src/lua.c", "src/luac.c"),
    ),
    "sqlite": Library(
        "sqlite",
        "https://www.sqlite.org/2023/sqlite-amalgamation-3440200.zip",
        "833be89b53b3be8b40a2e3d5fedb635080e3edb204957244f3d6987c2bb2345f",
        "sqlite-amalgamation-3440200",
        ("sqlite3.c",),
        includes=(".",),
        defines=(
            "SQLITE_OS_OTHER=1",
            "SQLITE_THREADSAFE=0",
            "SQLITE_OMIT_LOAD_EXTENSION=1",
        ),
    ),
}

# Debian's hardening flags (dpkg-buildflags with hardening=+all, minus -g and
# the prefix maps, which do not change code); arm32 has no branch protection.
HARDENED = (
    "-fstack-protector-strong",
    "-fstack-clash-protection",
    "-D_FORTIFY_SOURCE=2",
)
HARDENED_ARCH = {
    "x64": ("-fcf-protection",),
    "arm64": ("-mbranch-protection=standard",),
    "arm32": (),
    "thumb": (),
}
HARDENED_LINK = ("-Wl,-z,relro", "-Wl,-z,now")


@dataclass(frozen=True)
class Profile:
    """One build profile of the --world tier."""

    name: str
    opt: str
    # "shared": a shared object. "pie" / "static": an executable linking every
    # library source with a stub main; its functions are not exported, so the
    # stripped copy names none of them.
    link: str = "shared"
    hardened: bool = False
    lto: bool = False
    previous: bool = False


WORLD_PROFILES = (
    Profile("gcc", "-O2"),
    Profile("gcc", "-O3"),
    Profile("gcc+hardened", "-O2", hardened=True),
    Profile("gcc+lto", "-O2", lto=True),
    Profile("gcc+pie", "-O2", link="pie"),
    Profile("gcc+static", "-O2", link="static"),
    Profile("gcc+previous", "-O2", previous=True),
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


def output_path(build: Path, library: Library, arch: str, compiler: str, opt: str) -> Path:
    outdir = build / arch / f"{compiler}-{opt.strip('-')}"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir / f"{library.name}.so"


def up_to_date(output: Path, library: Library, root: Path) -> bool:
    """The output is newer than every input that can change it."""
    if not output.exists():
        return False
    inputs = [
        *sources(library, root),
        Path(__file__),
        *SHIM.rglob("*.h"),
        *SHIM_WINDOWS.rglob("*.h"),
    ]
    for include in library.includes:
        inputs.extend((root / include).glob("*.h"))
    built = output.stat().st_mtime
    return all(path.stat().st_mtime <= built for path in inputs)


def build_clang(
    clang: str, build: Path, library: Library, root: Path, arch: str, opt: str
) -> Path | None:
    target, extra = TARGETS[arch]
    output = output_path(build, library, arch, "clang", opt)
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


def build_gcc(build: Path, library: Library, root: Path) -> dict[tuple[str, str], Path]:
    """Every GCC build of one library in a single container run."""
    lines = ["set -u"]
    outputs: dict[tuple[str, str], Path] = {}
    for arch, (driver, extra) in GCC.items():
        for opt in OPT_LEVELS:
            output = output_path(build, library, arch, "gcc", opt)
            outputs[(arch, opt)] = output
            if up_to_date(output, library, root):
                continue
            container_out = "/work/" + output.relative_to(CORPUS).as_posix()
            container_root = "/work/" + root.relative_to(CORPUS).as_posix()
            files = " ".join(
                f"{container_root}/{path.relative_to(root).as_posix()}"
                for path in sources(library, root)
            )
            # Quoted: string-valued defines (libyaml's version) carry quotes.
            flags = " ".join(
                shlex.quote(flag)
                for flag in [opt, *extra, "-fPIC", "-shared", "-w", "-Wl,--build-id=none"]
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
    # The script goes in on stdin: with every source of zstd or mbedtls on
    # twelve command lines it exceeds the Windows 32 KiB argv limit. Bytes,
    # not text mode, so Windows does not turn the newlines into CRLF for sh.
    command = ["docker", "run", "--rm", "-i", "-v", f"{CORPUS}:/work", DOCKER_IMAGE, "sh", "-s"]
    script = ("\n".join(lines) + "\n").encode()
    result = subprocess.run(command, input=script, capture_output=True)
    stdout = result.stdout.decode(errors="replace")
    if result.returncode != 0 or "FAIL" in stdout:
        print(stdout[-2000:], result.stderr.decode(errors="replace")[-3000:])
    return {key: path for key, path in outputs.items() if path.exists()}


# An executable resolves every reference at link time, so what a shared
# object leaves to its host is supplied here: SQLite built with
# SQLITE_OS_OTHER expects the embedder's OS layer.
EXECUTABLE_STUBS = {
    "sqlite": "int sqlite3_os_init(void) { return 0; } int sqlite3_os_end(void) { return 0; }",
}


def world_path(library: Library, arch: str, profile: Profile) -> Path:
    outdir = WORLD_BUILD / arch / f"{profile.name}-{profile.opt.strip('-')}"
    outdir.mkdir(parents=True, exist_ok=True)
    # One file name for every profile: the bench pairs builds by file name.
    return outdir / f"{library.name}.elf"


def build_world(library: Library, roots: dict[bool, Path]) -> dict[tuple[str, str], Path]:
    """Every --world build of one library in a single container run."""
    main = "int main(void) { return 0; } " + EXECUTABLE_STUBS.get(library.name, "")
    lines = ["set -u", f"printf %s {shlex.quote(main)} > /tmp/main.c"]
    outputs: dict[tuple[str, str], Path] = {}
    for arch, (driver, extra) in GCC.items():
        for profile in WORLD_PROFILES:
            root = roots[profile.previous]
            built = PREVIOUS[library.name] if profile.previous else library
            output = world_path(library, arch, profile)
            outputs[(arch, f"{profile.name}-{profile.opt.strip('-')}")] = output
            stripped = WORLD_BUILD / "stripped" / output.relative_to(WORLD_BUILD)
            stripped.parent.mkdir(parents=True, exist_ok=True)
            if stripped.exists() and stripped.stat().st_mtime >= Path(__file__).stat().st_mtime:
                continue
            container_out = "/work/" + output.relative_to(CORPUS).as_posix()
            container_stripped = "/work/" + stripped.relative_to(CORPUS).as_posix()
            container_root = "/work/" + root.relative_to(CORPUS).as_posix()
            files = " ".join(
                f"{container_root}/{path.relative_to(root).as_posix()}"
                for path in sources(built, root)
            )
            flags = [profile.opt, *extra, "-w", "-Wl,--build-id=none"]
            if profile.hardened:
                flags += [*HARDENED, *HARDENED_ARCH[arch], *HARDENED_LINK]
            if profile.lto:
                flags += ["-flto=auto"]
            if profile.link == "shared":
                flags += ["-fPIC", "-shared"]
            elif profile.link == "pie":
                flags += ["-fPIE", "-pie", "/tmp/main.c"]
            else:
                flags += ["-static", "/tmp/main.c"]
            flags += [f"-I{container_root}/{include}" for include in built.includes]
            flags += [f"-D{define}" for define in built.defines]
            quoted = " ".join(shlex.quote(flag) for flag in flags)
            lines.append(
                f"( {driver} {quoted} {files} -o {container_out} -lm "
                f"&& {STRIP[arch]} --strip-all {container_out} -o {container_stripped} "
                f"|| echo FAIL world {library.name} {arch} {profile.name}{profile.opt} ) &"
            )
    if len(lines) == 2:
        return outputs
    lines.append("wait")
    command = ["docker", "run", "--rm", "-i", "-v", f"{CORPUS}:/work", DOCKER_IMAGE, "sh", "-s"]
    script = ("\n".join(lines) + "\n").encode()
    result = subprocess.run(command, input=script, capture_output=True)
    stdout = result.stdout.decode(errors="replace")
    if result.returncode != 0 or "FAIL" in stdout:
        print(stdout[-2000:], result.stderr.decode(errors="replace")[-3000:])
    return {key: path for key, path in outputs.items() if path.exists()}


def main_world(args: argparse.Namespace, readelf: str) -> int:
    libraries = [lib for lib in LIBRARIES if not args.library or lib.name in args.library]
    roots = {
        library.name: {False: fetch(library), True: fetch(PREVIOUS[library.name])}
        for library in libraries
    }
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        jobs = {
            library.name: pool.submit(build_world, library, roots[library.name])
            for library in libraries
        }
    binaries: list[dict[str, object]] = []
    for library in libraries:
        outputs = jobs[library.name].result()
        expected = len(GCC) * len(WORLD_PROFILES)
        if len(outputs) != expected:
            print(f"  {library.name}: {expected - len(outputs)} builds failed; skipped")
            continue
        built = {key: function_symbols(readelf, path, key[0]) for key, path in outputs.items()}
        # Functions present in every profile, the previous release included:
        # one added or removed between releases has no true answer.
        common = set.intersection(*(set(symbols) for symbols in built.values()))
        chosen = select(common, args.max_functions)
        print(f"{library.name}: {len(common)} common functions, {len(chosen)} selected")
        for (arch, build_name), symbols in sorted(built.items()):
            binary = outputs[(arch, build_name)]
            stripped = WORLD_BUILD / "stripped" / binary.relative_to(WORLD_BUILD)
            binaries.append(
                {
                    "path": binary.relative_to(WORLD_BUILD).as_posix(),
                    "stripped": stripped.relative_to(WORLD_BUILD).as_posix(),
                    "arch": arch,
                    "library": library.name,
                    "functions": [
                        {"name": name, "start": symbols[name][0], "size": symbols[name][1]}
                        for name in chosen
                    ],
                    "total_symbols": len(symbols),
                }
            )
    WORLD_BUILD.mkdir(parents=True, exist_ok=True)
    document = {"binaries": binaries, "negative": []}
    (WORLD_BUILD / "ground_truth.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


# -- PE tier (--pe) -----------------------------------------------------------

PE_TARGETS = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}
PE_MACHINES = {"x64": "x64", "arm64": "arm64"}


@dataclass(frozen=True)
class PeProfile:
    """One build of the --pe tier: an optimization level plus MSVC options."""

    name: str
    opt: str
    # /GS: the MSVC stack cookie (__security_cookie / __security_check_cookie).
    gs: bool = False
    # /guard:cf: indirect calls through the CFG check or dispatch pointer, and
    # the guard tables in the load config.
    cfg: bool = False


PE_PROFILES = (
    PeProfile("clang", "-O0"),
    PeProfile("clang", "-O2"),
    PeProfile("clang", "-Os"),
    PeProfile("clang+gs", "-O2", gs=True),
    PeProfile("clang+cfg", "-O2", cfg=True),
)

# Each library's own Windows DLL export mechanism, as its Windows makefiles
# use it: only the public API is exported, unlike the ELF builds, whose
# default visibility exports every non-static function. zlib exports through
# win32/zlib.def; the others mark the API with __declspec(dllexport). These
# replace the ELF defines: zlib's Z_HAVE_UNISTD_H is what configure writes on
# POSIX, not on Windows.
PE_DEFINES = {
    "zlib": (),
    "lz4": ("LZ4_DLL_EXPORT=1",),
    "cjson": ("CJSON_EXPORT_SYMBOLS",),
    "lua": ("LUA_BUILD_AS_DLL",),
    "sqlite": (
        "SQLITE_OS_OTHER=1",
        "SQLITE_THREADSAFE=0",
        "SQLITE_OMIT_LOAD_EXTENSION=1",
        "SQLITE_API=__declspec(dllexport)",
    ),
}
PE_DEF_FILES = {"zlib": "win32/zlib.def"}

# What an MSVC-built DLL links statically from the CRT (vcruntime and the
# CRT startup objects) rather than importing: the floating-point marker,
# stack probe, /GS cookie and its check, the CFG check and dispatch
# pointers, and the load config that points the loader at the cookie and the
# guard tables lld-link synthesizes. Bodies are placeholders with the real
# calling conventions; the code that matters is the library's.
PE_CRT = r"""
int _fltused = 0x9875;
void __chkstk(void) {}
unsigned long long __security_cookie = 0x2b992ddfa232ull;
void __security_check_cookie(unsigned long long cookie) {
  if (cookie != __security_cookie) __builtin_trap();
}
static void guard_check_icall_nop(void *target) { (void)target; }
#if defined(__x86_64__)
void guard_dispatch_icall_nop(void);
__asm__(".text\n.globl guard_dispatch_icall_nop\nguard_dispatch_icall_nop:\n  jmp *%rax\n");
#else
static void guard_dispatch_icall_nop(void) {}
#endif
void (*__guard_check_icall_fptr)(void *) = guard_check_icall_nop;
void (*__guard_dispatch_icall_fptr)(void) = guard_dispatch_icall_nop;
/* IMAGE_LOAD_CONFIG_DIRECTORY64 up to the long-jump target table (192
   bytes), in assembly: GuardFlags is a 32-bit field holding an absolute
   linker symbol, which C cannot initialize. */
__asm__(
  ".section .rdata,\"dr\"\n.globl _load_config_used\n.p2align 3\n_load_config_used:\n"
  ".long 192, 0\n.short 0, 0\n.long 0, 0, 0\n.quad 0, 0, 0, 0, 0, 0\n.long 0\n.short 0, 0\n"
  ".quad 0, __security_cookie, 0, 0\n"
  ".quad __guard_check_icall_fptr, __guard_dispatch_icall_fptr\n"
  ".quad __guard_fids_table, __guard_fids_count\n"
  ".long __guard_flags\n.short 0, 0\n.long 0, 0\n"
  ".quad __guard_iat_table, __guard_iat_count, __guard_longjmp_table, __guard_longjmp_count\n"
  ".text\n");
"""


def pe_path(library: Library, arch: str, profile: PeProfile) -> Path:
    outdir = PE_BUILD / arch / f"{profile.name}-{profile.opt.strip('-')}"
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir / f"{library.name}.dll"


def run(command: list[str], what: str) -> bool:
    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    if result.returncode != 0:
        print(f"  FAIL {what}:\n{(result.stdout + result.stderr)[-3000:]}")
    return result.returncode == 0


def nm_undefined(nm: str, objects: list[Path]) -> set[str]:
    """Symbols `objects` reference and none of them defines."""
    text = subprocess.run(
        [nm, "--extern-only", *map(str, objects)], capture_output=True, text=True, check=True
    ).stdout
    defined: set[str] = set()
    undefined: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("U", "w"):
            undefined.add(parts[1])
        elif len(parts) == 3:
            defined.add(parts[2])
    return undefined - defined


def import_library(lld: str, arch: str, dll: str, names: list[str], out: Path) -> bool:
    """An import library for `dll` exporting `names`, as an SDK .lib provides."""
    definition = out.with_suffix(".def")
    definition.write_text(
        f"LIBRARY {dll}\nEXPORTS\n" + "".join(f"  {name}\n" for name in names), encoding="utf-8"
    )
    return run(
        [
            lld,
            "-flavor",
            "link",
            "/lib",
            f"/machine:{PE_MACHINES[arch]}",
            f"/def:{definition}",
            f"/out:{out}",
        ],
        f"implib {dll} {arch}",
    )


def build_pe(
    clang: str, lld: str, nm: str, library: Library, root: Path, arch: str, profile: PeProfile
) -> Path | None:
    """One PE DLL, its linker map, and the import libraries it links."""
    output = pe_path(library, arch, profile)
    mapfile = output.with_suffix(".map")
    if up_to_date(output, library, root) and mapfile.exists():
        return output
    work = PE_BUILD / "obj" / arch / output.parent.name / library.name
    work.mkdir(parents=True, exist_ok=True)
    flags = [
        f"--target={PE_TARGETS[arch]}",
        profile.opt,
        "-nostdlibinc",
        "-isystem",
        str(SHIM_WINDOWS),
        "-isystem",
        str(SHIM),
        "-w",
    ]
    if profile.gs:
        # clang-cl's /GS; on an MSVC target it emits the cookie check.
        flags.append("-fstack-protector-strong")
    if profile.cfg:
        flags += ["-Xclang", "-cfguard"]
    # SQLite's MSVC path includes <Windows.h>; the shim's file is windows.h,
    # and one directory cannot hold both on a case-insensitive checkout.
    case = PE_BUILD / "include-case"
    case.mkdir(parents=True, exist_ok=True)
    (case / "Windows.h").write_text("#include <windows.h>\n", encoding="utf-8")
    flags += ["-isystem", str(case)]
    crt_source = work / "crt.c"
    crt_source.write_text(PE_CRT, encoding="utf-8")
    crt = work / "crt.obj"
    if not run([clang, *flags, "-O2", "-c", str(crt_source), "-o", str(crt)], f"crt {arch}"):
        return None
    objects: list[Path] = []
    for index, path in enumerate(sources(library, root)):
        # Indexed: lua and zlib have no clashing stems, but nothing forbids one.
        obj = work / f"{index:03}-{path.stem}.obj"
        command = [
            clang,
            *flags,
            *(f"-I{root / include}" for include in library.includes),
            *(f"-D{define}" for define in PE_DEFINES[library.name]),
            "-c",
            str(path),
            "-o",
            str(obj),
        ]
        if not run(command, f"pe {library.name} {arch} {profile.name}{profile.opt} {path.name}"):
            return None
        objects.append(obj)
    undefined = nm_undefined(nm, [*objects, crt])
    # __declspec(dllimport) declarations (windows.h) reference __imp_X; the
    # rest are the CRT functions the shim declares without it, which lld-link
    # reaches through a `jmp [__imp_X]` thunk, as MSVC does for memcpy.
    kernel32 = sorted(name[len("__imp_") :] for name in undefined if name.startswith("__imp_"))
    ucrt = sorted(
        name
        for name in undefined
        if not name.startswith("__imp_") and not name.startswith("__guard_")
    )
    libs = []
    for dll, names in (("ucrtbase.dll", ucrt), ("kernel32.dll", kernel32)):
        if names:
            lib = work / f"{dll.split('.')[0]}.lib"
            if not import_library(lld, arch, dll, names, lib):
                return None
            libs.append(lib)
    command = [
        lld,
        "-flavor",
        "link",
        "/dll",
        "/noentry",
        "/nodefaultlib",
        # A hash of the inputs instead of the link time in the headers.
        "/Brepro",
        f"/machine:{PE_MACHINES[arch]}",
        f"/out:{output}",
        f"/map:{mapfile}",
        *map(str, objects),
        str(crt),
        *map(str, libs),
    ]
    if library.name in PE_DEF_FILES:
        command.append(f"/def:{root / PE_DEF_FILES[library.name]}")
    if profile.cfg:
        command.append("/guard:cf")
    if not run(command, f"link {library.name} {arch} {profile.name}{profile.opt}"):
        return None
    # lld-link writes the export library beside the DLL; it is not corpus.
    for leftover in (output.with_suffix(".lib"), output.with_suffix(".exp")):
        leftover.unlink(missing_ok=True)
    return output


def pe_functions(mapfile: Path, objects: set[str]) -> dict[str, tuple[int, int]]:
    """Functions of the library's own objects from an lld-link map, by name.

    Addresses are virtual (`Rva+Base`), as the bench reports them. A map
    gives no sizes; a function's size runs to the next function or the end
    of its section, so it includes alignment padding. Names defined twice
    (same-named statics in two objects) and functions folded onto one
    address by /OPT:ICF (lld-link's default without /debug, as MSVC's) have
    no single true answer and are dropped.
    """
    # lld-link's map marks no symbol as a function: code is what lies in a
    # section of class CODE.
    lengths: dict[int, int] = {}
    entries: list[tuple[int, int, str, str, int]] = []
    for line in mapfile.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 4 or ":" not in parts[0]:
            continue
        try:
            section, offset = (int(field, 16) for field in parts[0].split(":"))
        except ValueError:
            continue
        if parts[3] == "CODE":
            length = int(parts[1].rstrip("H"), 16)
            lengths[section] = max(lengths.get(section, 0), offset + length)
        elif section in lengths:
            address = int(parts[2], 16)
            entries.append((section, offset, parts[1], parts[3].rsplit(":", 1)[-1], address))
    starts: dict[int, list[int]] = {}
    ends: dict[int, int] = {}
    owned: dict[str, set[int]] = {}
    for section, offset, name, obj, address in entries:
        starts.setdefault(section, []).append(address)
        if section in lengths:
            ends[section] = address - offset + lengths[section]
        if obj in objects:
            owned.setdefault(name, set()).add(address)
    names_at: dict[int, int] = {}
    for addresses in owned.values():
        for address in addresses:
            names_at[address] = names_at.get(address, 0) + 1
    section_of = {address: section for section, _, _, _, address in entries}
    result: dict[str, tuple[int, int]] = {}
    for name, addresses in owned.items():
        if len(addresses) != 1:
            continue
        (address,) = addresses
        if names_at[address] > 1:
            continue
        section = section_of[address]
        following = [start for start in starts[section] if start > address]
        end = min(following) if following else ends.get(section, address)
        result[name] = (address, end - address)
    return result


def main_pe(args: argparse.Namespace, clang: str) -> int:
    lld = shutil.which("lld")
    nm = shutil.which("llvm-nm")
    if lld is None or nm is None:
        raise SystemExit("--pe needs lld (run as lld-link via -flavor link) and llvm-nm on PATH")
    libraries = [lib for lib in LIBRARIES if not args.library or lib.name in args.library]
    roots = {library.name: fetch(library) for library in libraries}
    builds = [(arch, profile) for arch in PE_TARGETS for profile in PE_PROFILES]
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        jobs = {
            (library.name, arch, profile): pool.submit(
                build_pe, clang, lld, nm, library, roots[library.name], arch, profile
            )
            for library in libraries
            for arch, profile in builds
        }
    binaries: list[dict[str, object]] = []
    for library in libraries:
        outputs = {
            (arch, f"{profile.name}-{profile.opt.strip('-')}"): jobs[
                (library.name, arch, profile)
            ].result()
            for arch, profile in builds
        }
        if any(output is None for output in outputs.values()):
            print(f"  {library.name}: some PE builds failed; skipped from ground truth")
            continue
        objects = {
            f"{index:03}-{path.stem}.obj"
            for index, path in enumerate(sources(library, roots[library.name]))
        }
        built = {
            key: pe_functions(output.with_suffix(".map"), objects)
            for key, output in outputs.items()
        }
        for key, output in outputs.items():
            # Every defined function of the image (the CRT glue included,
            # import thunks not), for start recall (examples/start_recall.rs);
            # a PE file has no symbol table to read them back from.
            functions = pe_functions(output.with_suffix(".map"), objects | {"crt.obj"})
            listing = [
                {"name": name, "start": start, "size": size}
                for name, (start, size) in sorted(functions.items(), key=lambda item: item[1])
            ]
            outputs[key].with_suffix(".functions.json").write_text(
                json.dumps(listing, indent=1) + "\n", encoding="utf-8"
            )
        common = set.intersection(*(set(functions) for functions in built.values()))
        chosen = select(common, args.max_functions)
        print(f"{library.name}: {len(common)} common PE functions, {len(chosen)} selected")
        for (arch, build_name), functions in sorted(built.items()):
            path = outputs[(arch, build_name)].relative_to(PE_BUILD).as_posix()
            binaries.append(
                {
                    "path": path,
                    # A PE image has no .symtab to strip: what a hint-free
                    # scan may not read (names and bounds) is in the map and
                    # never in the file, so both modes scan the same file.
                    "stripped": path,
                    "arch": arch,
                    "library": library.name,
                    "functions": [
                        {"name": name, "start": functions[name][0], "size": functions[name][1]}
                        for name in chosen
                    ],
                    "total_symbols": len(functions),
                }
            )
    PE_BUILD.mkdir(parents=True, exist_ok=True)
    document = {"binaries": binaries, "negative": []}
    (PE_BUILD / "ground_truth.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_pe_mixed(binaries)
    return 0


# The PE profiles paired with the ELF clang builds of the real corpus in
# corpus/build-pe-mixed: one level each, so ELF and PE builds of a level
# differ only in container (and its ABI: Windows x64 passes arguments in
# rcx/rdx/r8/r9 and `long` is 32-bit).
PE_MIXED = {"clang-O0": "clang+pe-O0", "clang-O2": "clang+pe-O2", "clang-Os": "clang+pe-Os"}


def place(source: Path, target: Path) -> None:
    """`target` as a hard link to `source` (a copy across file systems)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def write_pe_mixed(pe_binaries: list[dict[str, object]]) -> None:
    """ELF (corpus/build-real, clang) and PE builds of each library in one corpus.

    The bench pairs builds by arch, build directory, and file stem, so with
    both containers under one ground truth it measures ELF signatures found
    in PE images and back. Functions are those both ground truths list.
    """
    elf_truth = BUILD / "ground_truth.json"
    if not elf_truth.exists():
        print(f"no {elf_truth}; run corpus/real.py first for {PE_MIXED_BUILD.name}")
        return
    built = {str(binary["library"]) for binary in pe_binaries}
    elf_binaries = [
        binary
        for binary in json.loads(elf_truth.read_text(encoding="utf-8"))["binaries"]
        if binary["library"] in built
    ]
    # (image, its stripped copy, path in the mixed corpus, ground truth entry)
    entries: list[tuple[Path, Path, str, dict[str, object]]] = []
    for binary in elf_binaries:
        arch, build_name, _ = str(binary["path"]).split("/")
        if arch in PE_TARGETS and build_name in PE_MIXED:
            image = BUILD / str(binary["path"])
            entries.append((image, BUILD / str(binary["stripped"]), str(binary["path"]), binary))
    for binary in pe_binaries:
        arch, build_name, name = str(binary["path"]).split("/")
        if build_name in PE_MIXED:
            image = PE_BUILD / str(binary["path"])
            entries.append((image, image, f"{arch}/{PE_MIXED[build_name]}/{name}", binary))
    by_library: dict[str, list[set[str]]] = {}
    for *_, binary in entries:
        names = {str(function["name"]) for function in binary["functions"]}
        by_library.setdefault(str(binary["library"]), []).append(names)
    common = {library: set.intersection(*names) for library, names in by_library.items()}
    binaries: list[dict[str, object]] = []
    for image, stripped, path, binary in entries:
        place(image, PE_MIXED_BUILD / path)
        stripped_path = path if stripped == image else f"stripped/{path}"
        if stripped != image:
            place(stripped, PE_MIXED_BUILD / stripped_path)
        keep = common[str(binary["library"])]
        binaries.append(
            {
                **binary,
                "path": path,
                "stripped": stripped_path,
                "functions": [f for f in binary["functions"] if f["name"] in keep],
            }
        )
    binaries.sort(key=lambda binary: str(binary["path"]))
    document = {"binaries": binaries, "negative": []}
    PE_MIXED_BUILD.mkdir(parents=True, exist_ok=True)
    (PE_MIXED_BUILD / "ground_truth.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    for library, names in sorted(common.items()):
        print(f"{PE_MIXED_BUILD.name}: {library}: {len(names)} functions in ELF and PE")


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


def strip(llvm_strip: str, build: Path, binary: Path) -> Path:
    stripped = build / "stripped" / binary.relative_to(build)
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
    parser.add_argument(
        "--heldout",
        action="store_true",
        help=f"build the held-out libraries into {HELDOUT_BUILD.relative_to(ROOT).as_posix()}/",
    )
    parser.add_argument(
        "--world",
        action="store_true",
        help=f"build the real-world profiles into {WORLD_BUILD.relative_to(ROOT).as_posix()}/",
    )
    parser.add_argument(
        "--pe",
        action="store_true",
        help=f"build PE DLLs into {PE_BUILD.relative_to(ROOT).as_posix()}/ and pair them with"
        f" the ELF clang builds in {PE_MIXED_BUILD.relative_to(ROOT).as_posix()}/",
    )
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="parallel builds")
    args = parser.parse_args(argv)
    args.compiler = tuple(args.compiler or COMPILERS)
    catalog, build = (HELDOUT, HELDOUT_BUILD) if args.heldout else (LIBRARIES, BUILD)

    clang = shutil.which("clang")
    readelf = shutil.which("llvm-readelf")
    llvm_strip = shutil.which("llvm-strip")
    if clang is None or readelf is None or llvm_strip is None:
        raise SystemExit("clang, llvm-readelf, and llvm-strip must be on PATH")
    if args.world:
        return main_world(args, readelf)
    if args.pe:
        return main_pe(args, clang)

    libraries = [lib for lib in catalog if not args.library or lib.name in args.library]
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
                gcc_jobs[library.name] = pool.submit(build_gcc, build, library, root)
            if "clang" in args.compiler:
                for arch in TARGETS:
                    for opt in OPT_LEVELS:
                        clang_jobs[(library.name, arch, opt)] = pool.submit(
                            build_clang, clang, build, library, root, arch, opt
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
            stripped = strip(llvm_strip, build, build / arch / opt / f"{library.name}.so")
            binaries.append(
                {
                    "path": f"{arch}/{opt}/{library.name}.so",
                    "stripped": stripped.relative_to(build).as_posix(),
                    "arch": arch,
                    "library": library.name,
                    "functions": [
                        {"name": name, "start": symbols[name][0], "size": symbols[name][1]}
                        for name in chosen
                    ],
                    "total_symbols": len(symbols),
                }
            )

    build.mkdir(parents=True, exist_ok=True)
    document = {"binaries": binaries, "negative": []}
    (build / "ground_truth.json").write_text(
        json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
