"""Compare the Python and native scan profiles on the binaries both scanned.

    python profile_scan.py --no-live --no-profiler --json corpus/scan-profile-python.json
    cargo run --release --example profile_scan --manifest-path native/Cargo.toml \\
        -- --json corpus/scan-profile-native.json
    python compare_scan_profile.py

Both profilers emit per-binary JSON with the same counters and the same
workload (signature set generated from every function start of the binary, one
full pass plus one incremental pass, Tier 1 budget 100_000). This script joins
them on the binary path tail and reports throughput. It also checks that both
sides produced the same signature count, hit count, and index instruction count
per binary, so a timing difference cannot come from measuring different work.

The native port decodes x64 and arm64, but the committed throughput baseline is
x64-only, so the join is over the x64 corpus slice and the Python rows for
arm64/arm32/thumb are ignored. The live-process workload in
`profile_scan.py` has no native counterpart yet (there is no native PID
source), so it is not compared here.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CORPUS_JSON = Path("corpus/scan-profile-python.json")
NATIVE_JSON = Path("corpus/scan-profile-native.json")


def binary_key(path: str) -> str:
    """`arch/opt/file`, the part both profilers spell the same way."""
    parts = path.replace("\\", "/").rstrip("/").split("/")
    return "/".join(parts[-3:])


def load(path: Path) -> dict[str, dict[str, object]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {binary_key(str(entry["path"])): entry for entry in document["corpus"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", type=Path, default=CORPUS_JSON)
    parser.add_argument("--native", type=Path, default=NATIVE_JSON)
    args = parser.parse_args(argv)

    python = load(args.python)
    native = load(args.native)
    shared = sorted(set(python) & set(native))
    if not shared:
        print("no shared binaries; both sides must profile the same corpus", file=sys.stderr)
        return 2

    print(f"{'binary':28s} {'python':>10s} {'native':>10s} {'speedup':>8s}  workload")
    total_python = 0.0
    total_native = 0.0
    mismatched: list[str] = []
    for key in shared:
        left = python[key]
        right = native[key]
        seconds_python = float(left["full_pass_seconds"])  # type: ignore[arg-type]
        seconds_native = float(right["full_pass_seconds"])  # type: ignore[arg-type]
        total_python += seconds_python
        total_native += seconds_native
        parity = all(
            left[field] == right[field] for field in ("signatures", "hits", "index_instructions")
        )
        if not parity:
            mismatched.append(key)
        print(
            f"{key:28s} {seconds_python * 1000:8.1f}ms {seconds_native * 1000:8.1f}ms "
            f"{seconds_python / max(seconds_native, 1e-9):7.1f}x  "
            f"{'same' if parity else 'DIFFERS'}"
        )

    bytes_scanned = sum(int(native[key]["bytes_scanned"]) for key in shared)  # type: ignore[arg-type]
    incremental_python = sum(
        float(python[key]["incremental_pass_seconds"])
        for key in shared  # type: ignore[arg-type]
    )
    incremental_native = sum(
        float(native[key]["incremental_pass_seconds"])
        for key in shared  # type: ignore[arg-type]
    )

    print()
    print(f"binaries compared:  {len(shared)}  ({bytes_scanned / 1024:.1f} KiB of image)")
    print(
        f"full pass:          python {total_python * 1000:.1f} ms  "
        f"native {total_native * 1000:.1f} ms  "
        f"{total_python / max(total_native, 1e-9):.1f}x"
    )
    print(
        f"incremental pass:   python {incremental_python * 1000:.2f} ms  "
        f"native {incremental_native * 1000:.2f} ms  "
        f"{incremental_python / max(incremental_native, 1e-6):.1f}x"
    )

    if mismatched:
        print()
        print(f"workload mismatch on: {', '.join(mismatched)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
