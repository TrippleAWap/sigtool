"""Golden-vector generator: real compiler output in, feature records out.

Run ``python tests/vectors/generate.py`` after changing normalization or feature
semantics, review the diff, and commit the vectors with the change.

A vector is not a binary. It stores the fixture's section bytes and addresses,
so the test can rebuild a ``MemorySource`` and run the real extractor; the
expected features are stored alongside for comparison. This script compiles
the fixture with clang + ld.lld, takes sections and symbol bounds from the
native ``vector_skeleton`` example, and then runs the golden test in bless mode
(``SIGTOOL_BLESS=1 cargo test --test golden``) to fill in the records.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native"
VECTOR_DIR = Path(__file__).resolve().parent

FIXTURE = r"""
typedef unsigned long size_t;
typedef unsigned short char16_t;

const char *kernel_msg = "kernel banner literal";
const char *ui_msg = "ui banner literal";
int global_counter = 7;
unsigned global_mask = 0x80000000u;

int compute(int x) { return x * 0x1234 + 0x5678; }
int call_one(int x) { return compute(x) + 1; }
int call_two(int x) { return compute(x) - 0x99; }
const char *banner(void) { return kernel_msg; }
const char *banner_direct(void) { return "direct banner literal"; }
int get_counter(void) { return global_counter; }
unsigned mask_value(void) { return global_mask; }

int loop_sum(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += i * 3;
    }
    return total;
}

int branchy(int x) {
    if (x > 10) {
        return compute(x);
    }
    if (x < -10) {
        return -1;
    }
    return x;
}

int classify(int code) {
    switch (code) {
    case 0: return 11;
    case 1: return 23;
    case 2: return 37;
    case 3: return 41;
    case 4: return 53;
    case 5: return 67;
    case 6: return 79;
    case 7: return 83;
    default: return -1;
    }
}

const char16_t *wide_banner(void) { return u"wide banner literal"; }

unsigned long long mix(unsigned long long a, unsigned long long b) {
    a ^= b << 21;
    b ^= a >> 17;
    a += b * 0x9E3779B97F4A7C15ull;
    return a ^ (b << 7);
}

int recurse(int n) { return n <= 1 ? 1 : n * recurse(n - 1); }

void _start(void) {}
"""

TARGETS = {
    "x64": ("x86_64-linux-gnu", ()),
    "arm64": ("aarch64-linux-gnu", ()),
    "arm64-pac": ("aarch64-linux-gnu", ("-mbranch-protection=standard",)),
    "x64-cet": ("x86_64-linux-gnu", ("-fcf-protection=full",)),
    "arm32": ("armv7-linux-gnueabihf", ()),
    "thumb": ("armv7-linux-gnueabihf", ("-mthumb",)),
}
OPT_LEVELS = ("-O0", "-O2", "-Os")
FUNCTIONS = (
    "compute",
    "call_one",
    "call_two",
    "banner",
    "banner_direct",
    "get_counter",
    "mask_value",
    "loop_sum",
    "branchy",
    "classify",
    "wide_banner",
    "mix",
    "recurse",
)


def find_clang() -> str:
    clang = shutil.which("clang")
    if clang is None:
        raise SystemExit("clang not found in PATH; install LLVM to regenerate vectors")
    return clang


def build_vector(
    clang: str, skeleton: Path, arch: str, opt: str, workdir: Path
) -> dict[str, object]:
    target, extra = TARGETS[arch]
    source = workdir / "fixture.c"
    source.write_text(FIXTURE)
    binary = workdir / f"fixture-{arch}{opt}.elf"
    command = [
        clang,
        f"--target={target}",
        opt,
        "-g",
        "-nostdlib",
        "-static",
        "-fuse-ld=lld",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        *extra,
        "-Wl,-e,_start",
        str(source),
        "-o",
        str(binary),
    ]
    subprocess.run(command, check=True, capture_output=True)
    result = subprocess.run(
        [str(skeleton), str(binary), *FUNCTIONS], check=True, capture_output=True, text=True
    )
    vector: dict[str, object] = json.loads(result.stdout)
    vector.update({"arch": arch, "opt": opt, "target": target, "flags": list(extra)})
    return vector


def build_skeleton() -> Path:
    subprocess.run(
        ["cargo", "build", "--release", "--example", "vector_skeleton"], check=True, cwd=NATIVE
    )
    target = Path(os.environ.get("CARGO_TARGET_DIR", NATIVE / "target"))
    if not target.is_absolute():
        target = NATIVE / target
    name = "vector_skeleton.exe" if os.name == "nt" else "vector_skeleton"
    return target / "release" / "examples" / name


def main() -> int:
    clang = find_clang()
    skeleton = build_skeleton()
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        workdir = Path(temp)
        for arch in TARGETS:
            for opt in OPT_LEVELS:
                vector = build_vector(clang, skeleton, arch, opt, workdir)
                name = f"{arch}{opt}.json"
                (VECTOR_DIR / name).write_text(
                    json.dumps(vector, indent=1, sort_keys=True) + "\n", encoding="utf-8"
                )
                print(f"wrote {name}: {len(vector['functions'])} functions")  # type: ignore[arg-type]
    bless = dict(os.environ, SIGTOOL_BLESS="1")
    subprocess.run(
        ["cargo", "test", "--release", "--test", "golden"], check=True, cwd=NATIVE, env=bless
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
