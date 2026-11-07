"""Scan-cost profile: throughput, CPU cost, and hot spots (M6 exit evidence).

    python profile_scan.py                     # corpus + live process (Windows)
    python profile_scan.py --json profile.json
    python profile_scan.py --no-live           # corpus only

Workload, per corpus binary: build the signature set for that binary, then run
one full scanner pass (page hashing, index build, recovery) and one incremental
pass (everything unchanged). On Windows, a third workload scans the running
interpreter with signatures generated from its own modules — a representative
live process. cProfile captures the full pass; the top functions are the hot
spots. Numbers land in docs/scanner-profile.md.
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import pstats
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from core.generate import generate
from core.match import RecoveryBudget
from core.scanner import PAGE_SIZE, SignatureScanner
from core.sigfile import Signature
from sources.file import FileSource

CORPUS = Path("corpus/build")
SUPPORTED_ARCHES = ("x64", "arm64", "arm32")


@dataclass
class BinaryProfile:
    path: str
    arch: str
    bytes_scanned: int
    signatures: int
    full_pass_seconds: float
    incremental_pass_seconds: float
    regions_skipped: int
    pages_hashed: int
    index_instructions: int
    recoveries_budget: int
    hits: int


def load_ground_truth(root: Path) -> list[dict[str, object]]:
    path = root / "ground_truth.json"
    if not path.exists():
        print(f"no corpus under {root}; run python corpus/build.py", file=sys.stderr)
        raise SystemExit(2)
    document = json.loads(path.read_text(encoding="utf-8"))
    return [entry for entry in document["binaries"] if isinstance(entry, dict)]


def profile_binary(path: Path) -> BinaryProfile:
    image = FileSource.from_path(path)
    signatures: list[Signature] = []
    module = image.modules()[0]
    for addr in sorted(module.functions):
        try:
            signatures.append(generate(image, addr).signature)
        except Exception:
            continue

    budget = RecoveryBudget(remaining=100_000)
    scanner = SignatureScanner(image, signatures, budget=budget)

    start = time.perf_counter()
    full = scanner.scan_pass()
    full_seconds = time.perf_counter() - start

    start = time.perf_counter()
    second = scanner.scan_pass()
    incremental_seconds = time.perf_counter() - start

    bytes_scanned = sum(region.size for region in image.regions())
    return BinaryProfile(
        path=str(path),
        arch=image.arch.value,
        bytes_scanned=bytes_scanned,
        signatures=len(signatures),
        full_pass_seconds=full_seconds,
        incremental_pass_seconds=incremental_seconds,
        regions_skipped=full.regions_skipped + second.regions_skipped,
        pages_hashed=full.pages_hashed,
        index_instructions=full.index_instructions,
        recoveries_budget=100_000 - full.budget_remaining,
        hits=len(full.hits),
    )


def profile_live(signatures: list[Signature]) -> dict[str, object] | None:
    """Scan this process with signatures generated from its own modules."""
    if sys.platform != "win32":
        return None
    from sources.proc_win import WindowsProcessSource

    with WindowsProcessSource.open(_current_pid()) as source:
        budget = RecoveryBudget(remaining=20_000)
        scanner = SignatureScanner(source, signatures, budget=budget)
        cpu_before = time.process_time()
        start = time.perf_counter()
        report = scanner.scan_pass()
        full_seconds = time.perf_counter() - start
        full_cpu = time.process_time() - cpu_before
        start = time.perf_counter()
        scanner.scan_pass()
        incremental_seconds = time.perf_counter() - start
        incremental_cpu = time.process_time() - cpu_before - full_cpu
        bytes_scanned = sum(region.size for region in source.regions())
        return {
            "pid": _current_pid(),
            "regions": len(source.regions()),
            "bytes_scanned": bytes_scanned,
            "signatures": len(signatures),
            "full_pass_seconds": round(full_seconds, 4),
            "full_pass_cpu_seconds": round(full_cpu, 4),
            "index_instructions": report.index_instructions,
            "index_truncated": report.index_truncated,
            "recoveries_budget": 20_000 - report.budget_remaining,
            "hits": len(report.hits),
            "incremental_pass_seconds": round(incremental_seconds, 4),
            "incremental_cpu_seconds": round(max(incremental_cpu, 0.0), 4),
        }


def _current_pid() -> int:
    import os

    return os.getpid()


def live_signatures(limit: int = 24) -> list[Signature]:
    """Generate signatures from a few exported functions of this process."""

    from sources.proc_win import WindowsProcessSource

    with WindowsProcessSource.open(_current_pid()) as source:
        signatures: list[Signature] = []
        for module in source.modules():
            for addr in sorted(module.exports.values()):
                if len(signatures) >= limit:
                    return signatures
                try:
                    signatures.append(generate(source, addr).signature)
                except Exception:
                    continue
        return signatures


def top_hot_spots(profiler: cProfile.Profile, count: int = 12) -> list[str]:
    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.sort_stats("cumulative").print_stats(count)
    lines = stream.getvalue().splitlines()
    return [line for line in lines if line.strip()][: count + 6]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--no-live", action="store_true")
    parser.add_argument("--live-signatures", type=int, default=24)
    args = parser.parse_args(argv)

    binaries = [
        entry for entry in load_ground_truth(args.corpus) if entry["arch"] in SUPPORTED_ARCHES
    ]

    profiles: list[BinaryProfile] = []
    profiler = cProfile.Profile()
    largest = max(
        (args.corpus / str(entry["path"]) for entry in binaries),
        key=lambda path: path.stat().st_size,
    )
    for entry in binaries:
        path = args.corpus / str(entry["path"])
        if path == largest:
            # Profile the largest binary in detail; others run unprofiled.
            profiler.enable()
            profiles.append(profile_binary(path))
            profiler.disable()
        else:
            profiles.append(profile_binary(path))

    live: dict[str, object] | None = None
    if not args.no_live:
        with_live = live_signatures(args.live_signatures)
        live = profile_live(with_live)

    total_bytes = sum(profile.bytes_scanned for profile in profiles)
    total_seconds = sum(profile.full_pass_seconds for profile in profiles)
    total_incremental = sum(profile.incremental_pass_seconds for profile in profiles)

    print(f"corpus binaries profiled: {len(profiles)}")
    print(f"total bytes scanned:      {total_bytes / 1024 / 1024:.2f} MiB")
    print(
        f"full pass:                {total_seconds:.3f}s  "
        f"({total_bytes / max(total_seconds, 1e-9) / 1024 / 1024:.2f} MiB/s)"
    )
    print(
        f"incremental pass:         {total_incremental:.3f}s  "
        f"({total_seconds / max(total_incremental, 1e-9):.1f}x faster)"
    )
    print(f"page size:                {PAGE_SIZE} bytes")
    print(f"index instructions:       {sum(p.index_instructions for p in profiles)}")
    print()
    for profile in profiles:
        print(
            f"  {profile.path:32s} {profile.arch:6s} "
            f"{profile.bytes_scanned / 1024:8.1f} KiB  {profile.signatures:3d} sigs  "
            f"full {profile.full_pass_seconds * 1000:8.1f} ms  "
            f"incr {profile.incremental_pass_seconds * 1000:8.1f} ms  "
            f"hits {profile.hits}"
        )
    if live is not None:
        print()
        print("live process:")
        for key, value in live.items():
            print(f"  {key:24s} {value}")

    hot = top_hot_spots(profiler)
    print()
    print("hot spots (largest binary, cumulative):")
    for line in hot:
        print(f"  {line}")

    if args.json is not None:
        args.json.write_text(
            json.dumps(
                {
                    "corpus": [vars(profile) for profile in profiles],
                    "live": live,
                    "totals": {
                        "bytes_scanned": total_bytes,
                        "full_pass_seconds": total_seconds,
                        "incremental_pass_seconds": total_incremental,
                        "mib_per_second": total_bytes / max(total_seconds, 1e-9) / 1024 / 1024,
                    },
                    "hot_spots": hot,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
