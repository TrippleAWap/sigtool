"""Corpus harness: cross-optimization recall and false positives.

Generation self-tests every signature, so this harness answers the other M3
questions: does a signature still match the same function built at a different
optimization level, and does it match functions in unrelated binaries?

Run after ``python corpus/build.py``:

    python bench.py
    python bench.py --json corpus/report.json

The negative corpus planned in M0 does not exist yet, so false positives are
measured against corpus binaries built from other source files. Reported
recall and FP numbers are therefore a floor standard, not the final metric.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from core.errors import SigToolError
from core.generate import generate
from core.match import scan
from core.sigfile import Signature
from sources.file import FileSource

DEFAULT_CORPUS = Path("corpus/build")
SUPPORTED_ARCHES = ("x64", "arm64")


@dataclass(frozen=True, slots=True)
class Sample:
    """One generated signature plus where it came from."""

    arch: str
    source_file: str
    opt: str
    name: str
    start: int
    signature: Signature
    verdict: str


@dataclass(frozen=True, slots=True)
class RecallCell:
    arch: str
    source_opt: str
    target_opt: str
    hits: int
    attempts: int

    @property
    def rate(self) -> float:
        return self.hits / self.attempts if self.attempts else 0.0


@dataclass(frozen=True, slots=True)
class FalsePositiveCell:
    arch: str
    signatures: int
    signatures_with_hits: int
    hits: int

    @property
    def rate(self) -> float:
        return self.signatures_with_hits / self.signatures if self.signatures else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--json", type=Path, default=None, help="write a JSON report")
    parser.add_argument(
        "--arch", action="append", choices=SUPPORTED_ARCHES, help="limit to one arch"
    )
    args = parser.parse_args(argv)

    binaries = _load_ground_truth(args.corpus)
    if not binaries:
        print(
            f"no corpus binaries under {args.corpus}; run python corpus/build.py", file=sys.stderr
        )
        return 2

    arches = tuple(args.arch) if args.arch else SUPPORTED_ARCHES
    binaries = [entry for entry in binaries if entry["arch"] in arches]
    sources = {path: FileSource.from_path(args.corpus / path) for path in _paths(binaries)}

    samples, refused = _build_samples(binaries, sources)
    recall = _recall(samples, binaries, sources)
    false_positives = _false_positives(samples, binaries, sources)

    _report(samples, refused, recall, false_positives)

    if args.json is not None:
        args.json.write_text(
            json.dumps(
                {
                    "samples": [
                        {
                            "arch": sample.arch,
                            "source_file": sample.source_file,
                            "opt": sample.opt,
                            "name": sample.name,
                            "verdict": sample.verdict,
                            "signature_id": sample.signature.signature_id,
                        }
                        for sample in samples
                    ],
                    "refused": refused,
                    "recall": [
                        {
                            "arch": cell.arch,
                            "source_opt": cell.source_opt,
                            "target_opt": cell.target_opt,
                            "hits": cell.hits,
                            "attempts": cell.attempts,
                        }
                        for cell in recall
                    ],
                    "false_positives": [
                        {
                            "arch": cell.arch,
                            "signatures": cell.signatures,
                            "signatures_with_hits": cell.signatures_with_hits,
                            "hits": cell.hits,
                        }
                        for cell in false_positives
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    return 1 if refused else 0


# -- corpus loading ----------------------------------------------------------


def _load_ground_truth(root: Path) -> list[dict[str, object]]:
    path = root / "ground_truth.json"
    if not path.exists():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    return [entry for entry in document["binaries"] if isinstance(entry, dict)]


def _paths(binaries: list[dict[str, object]]) -> list[str]:
    return sorted({str(entry["path"]) for entry in binaries})


def _build_samples(
    binaries: list[dict[str, object]], sources: dict[str, FileSource]
) -> tuple[list[Sample], int]:
    samples: list[Sample] = []
    refused = 0
    for entry in binaries:
        arch = str(entry["arch"])
        path = str(entry["path"])
        source_file, opt = _split_path(path)
        source = sources[path]
        for function in entry["functions"]:  # type: ignore[union-attr]
            try:
                result = generate(source, int(function["start"]), opt=opt, tool="clang")
            except SigToolError:
                refused += 1
                continue
            samples.append(
                Sample(
                    arch=arch,
                    source_file=source_file,
                    opt=opt,
                    name=str(function["name"]),
                    start=int(function["start"]),
                    signature=result.signature,
                    verdict=result.report.verdict,
                )
            )
    return samples, refused


def _split_path(path: str) -> tuple[str, str]:
    parts = Path(path).parts
    return (Path(parts[-1]).stem, parts[-2]) if len(parts) >= 2 else (Path(path).stem, "default")


# -- measurements ------------------------------------------------------------


def _recall(
    samples: list[Sample],
    binaries: list[dict[str, object]],
    sources: dict[str, FileSource],
) -> list[RecallCell]:
    targets = _function_table(binaries)
    cells: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    cache: dict[tuple[int, str], tuple[int, ...]] = {}

    for index, sample in enumerate(samples):
        for path, functions in targets.items():
            arch, source_file, opt = _kind(path)
            if arch != sample.arch or source_file != sample.source_file:
                continue
            expected = functions.get(sample.name)
            if expected is None:
                continue
            addresses = cache.get((index, path))
            if addresses is None:
                addresses = _scan_addresses(sample.signature, sources[path])
                cache[(index, path)] = addresses
            cell = cells[(sample.arch, sample.opt, opt)]
            cell[1] += 1
            if expected in addresses:
                cell[0] += 1

    return [
        RecallCell(arch, source_opt, target_opt, hits, attempts)
        for (arch, source_opt, target_opt), (hits, attempts) in sorted(cells.items())
    ]


def _false_positives(
    samples: list[Sample],
    binaries: list[dict[str, object]],
    sources: dict[str, FileSource],
) -> list[FalsePositiveCell]:
    strong = [sample for sample in samples if sample.verdict == "strong"]
    others = defaultdict(list)
    for entry in binaries:
        arch, source_file, _opt = _kind(str(entry["path"]))
        others[(arch, source_file)].append(str(entry["path"]))

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for sample in strong:
        bucket = counts[sample.arch]
        bucket[0] += 1
        hits = 0
        # The signature's own source file is a recall measurement, not an FP.
        for (arch, source_file), paths in others.items():
            if arch != sample.arch or source_file == sample.source_file:
                continue
            for path in paths:
                hits += len(_scan_addresses(sample.signature, sources[path]))
        bucket[2] += hits
        if hits:
            bucket[1] += 1

    return [
        FalsePositiveCell(arch, signatures, with_hits, hits)
        for arch, (signatures, with_hits, hits) in sorted(counts.items())
    ]


def _function_table(
    binaries: list[dict[str, object]],
) -> dict[str, dict[str, int]]:
    table: dict[str, dict[str, int]] = {}
    for entry in binaries:
        path = str(entry["path"])
        table[path] = {
            str(function["name"]): int(function["start"])
            for function in entry["functions"]  # type: ignore[union-attr]
        }
    return table


def _kind(path: str) -> tuple[str, str, str]:
    """``(arch, source file stem, opt level)`` from ``arch/opt/file.elf``."""
    parts = Path(path).parts
    source_file = Path(parts[-1]).stem
    opt = parts[-2] if len(parts) >= 2 else "default"
    arch = parts[0] if len(parts) >= 3 else "x64"
    return arch, source_file, opt


def _scan_addresses(signature: Signature, source: FileSource) -> tuple[int, ...]:
    return tuple(match.address for match in scan(source, signature))


# -- reporting ---------------------------------------------------------------


def _report(
    samples: list[Sample],
    refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
) -> None:
    verdicts = Counter(sample.verdict for sample in samples)
    per_arch: dict[str, Counter[str]] = defaultdict(Counter)
    for sample in samples:
        per_arch[sample.arch][sample.verdict] += 1

    print(f"signatures: {len(samples)}  refused by self-test: {refused}")
    print(f"verdicts: {dict(sorted(verdicts.items()))}")
    for arch, counts in sorted(per_arch.items()):
        print(f"  {arch}: strong={counts['strong']} weak={counts['weak']} small={counts['small']}")

    print("\nrecall (same function, same and cross optimization level)")
    for cell in recall:
        marker = "" if cell.source_opt != cell.target_opt else "  (same build)"
        print(
            f"  {cell.arch} {cell.source_opt}->{cell.target_opt}: "
            f"{cell.hits}/{cell.attempts} = {cell.rate:.3f}{marker}"
        )
    same = [cell for cell in recall if cell.source_opt == cell.target_opt]
    cross = [cell for cell in recall if cell.source_opt != cell.target_opt]
    _print_total("same build", same)
    _print_total("cross build", cross)

    print("\nfalse positives (strong signatures vs unrelated source file)")
    if not false_positives:
        print("  no strong signatures to test")
    for cell in false_positives:
        print(
            f"  {cell.arch}: {cell.signatures_with_hits}/{cell.signatures} signatures "
            f"with hits = {cell.rate:.3f}, total hits {cell.hits}"
        )


def _print_total(label: str, cells: list[RecallCell]) -> None:
    hits = sum(cell.hits for cell in cells)
    attempts = sum(cell.attempts for cell in cells)
    rate = hits / attempts if attempts else 0.0
    print(f"  total {label}: {hits}/{attempts} = {rate:.3f}")


if __name__ == "__main__":
    sys.exit(main())
