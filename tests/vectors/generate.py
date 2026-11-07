"""Golden-vector generator: real compiler output in, feature records out.

Run ``python tests/vectors/generate.py`` after changing normalization or feature
semantics, review the diff, and commit the vectors with the change.

A vector is not a binary. It stores the fixture's section bytes and addresses,
so the test can rebuild a ``MemorySource`` and run the real extractor; the
expected features are stored alongside for comparison.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.features import extract  # noqa: E402
from core.recover import recover  # noqa: E402
from core.spec import SPEC_VERSION  # noqa: E402
from sources.file import FileSource  # noqa: E402

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


def build_vector(clang: str, arch: str, opt: str, workdir: Path) -> dict[str, object]:
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
    # A fixed module name keeps `module+rva` callee labels stable across builds
    # and independent of the temporary output path.
    image = FileSource.from_bytes(binary.read_bytes(), "fixture.elf")
    module = image.modules()[0]

    sections = []
    for region in image.regions():
        if not region.data:
            continue
        sections.append(
            {
                "name": region.name,
                "addr": region.start,
                "executable": region.executable,
                "bytes": region.data.hex(),
            }
        )

    functions: dict[str, object] = {}
    for address, name in sorted(module.functions.items(), key=lambda item: item[1]):
        if name not in FUNCTIONS or name in functions:
            continue
        recovered = recover(image, address)
        features = extract(image, recovered)
        bounds = image.hint_function(address)
        functions[name] = {
            "entry": address,
            "end": bounds[1] if bounds else address + recovered.size,
            "blocks": recovered.block_count,
            "edges": recovered.edge_count,
            "loops": recovered.loop_count,
            "degraded": recovered.degraded,
            "features": [{"kind": feature.kind, "value": feature.value} for feature in features],
        }

    return {
        "spec_version": SPEC_VERSION,
        "arch": arch,
        "opt": opt,
        "target": target,
        "flags": list(extra),
        "sections": sections,
        "functions": functions,
    }


def main() -> int:
    clang = find_clang()
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        workdir = Path(temp)
        for arch in TARGETS:
            for opt in OPT_LEVELS:
                vector = build_vector(clang, arch, opt, workdir)
                name = f"{arch}{opt}.json"
                (VECTOR_DIR / name).write_text(
                    json.dumps(vector, indent=1, sort_keys=True) + "\n", encoding="utf-8"
                )
                print(f"wrote {name}: {len(vector['functions'])} functions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
