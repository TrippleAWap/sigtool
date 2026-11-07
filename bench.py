"""Corpus harness: cross-optimization recall and false positives.

Generation self-tests every signature, so this harness answers the other M3
questions: does a signature still match the same function built at a different
optimization level, and does it match functions in unrelated binaries?

Run after ``python corpus/build.py``:

    python bench.py
    python bench.py --json corpus/report.json
    python bench.py --baseline tests/baseline/bench.json
    python bench.py --save-baseline tests/baseline/bench.json

The baseline is the compact metrics document written by ``--save-baseline``;
``--baseline`` fails when per-arch recall drops or false positives rise beyond
``--tolerance``. Rates are compared rather than counts because a different clang
rebuild changes which functions exist.

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
from core.spec import SPEC_VERSION
from sources.file import FileSource

DEFAULT_CORPUS = Path("corpus/build")
# The corpus is rebuilt by whichever clang CI provides, so cross-build rates move
# a little between compiler versions (clang 18 vs 22 differs by about 0.02 here).
# Five points still catches a real regression without pinning a toolchain.
DEFAULT_TOLERANCE = 0.05
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
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="compare recall and false positives against a saved baseline",
    )
    parser.add_argument(
        "--save-baseline",
        type=Path,
        default=None,
        help="write a compact baseline for later --baseline comparisons",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=DEFAULT_TOLERANCE,
        help=f"allowed recall drop / false-positive increase (default {DEFAULT_TOLERANCE})",
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

    if args.save_baseline is not None:
        _save_baseline(args.save_baseline, len(samples), refused, recall, false_positives)
        print(f"\nwrote baseline {args.save_baseline}")

    failures: list[str] = []
    if args.baseline is not None:
        failures = _compare(args.baseline, refused, recall, false_positives, args.tolerance)
        print()
        if failures:
            print(f"baseline comparison: FAILED ({args.baseline})")
            for failure in failures:
                print(f"  {failure}")
        else:
            print(f"baseline comparison: OK within {args.tolerance:.2f} ({args.baseline})")

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
                    "recall": _recall_document(recall),
                    "false_positives": _false_positive_document(false_positives),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    return 1 if refused or failures else 0


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


# -- baselines ---------------------------------------------------------------


def _save_baseline(
    path: Path,
    signatures: int,
    refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
) -> None:
    """Write the compact metrics that :func:`_compare` reads.

    Sample-level detail belongs in ``--json`` output; a baseline is a reviewable
    set of numbers, so signature ids and file paths stay out of it.
    """
    document = {
        "spec_version": SPEC_VERSION,
        "signatures": signatures,
        "refused": refused,
        "recall": _recall_document(recall),
        "false_positives": _false_positive_document(false_positives),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _compare(
    path: Path,
    refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
    tolerance: float,
) -> list[str]:
    """Return the regressions that exceed ``tolerance``.

    Rates are compared rather than raw counts because rebuilding the corpus with
    a different clang can legitimately change which functions exist.
    """
    if not path.exists():
        return [f"no baseline file at {path}"]
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"could not read baseline {path}: {error}"]
    if not isinstance(baseline, dict):
        return [f"baseline {path} is not a JSON object"]

    version = str(baseline.get("spec_version", ""))
    if version != SPEC_VERSION:
        return [f"baseline spec version {version!r} is not {SPEC_VERSION!r}"]

    baseline_recall = _read_recall(baseline.get("recall"))
    baseline_fp = _read_false_positives(baseline.get("false_positives"))
    if baseline_recall is None or baseline_fp is None:
        return [f"baseline {path} has no recall or false_positives list"]

    failures: list[str] = []
    base_refused = _as_int(baseline.get("refused"))
    if refused > base_refused:
        failures.append(f"self-test refusals {refused} > baseline {base_refused}")

    baseline_arches = {cell.arch for cell in baseline_recall}
    current_arches = {cell.arch for cell in recall}
    for arch in sorted(baseline_arches - current_arches):
        failures.append(f"{arch}: missing from the current run")
    for arch in sorted(baseline_arches & current_arches):
        for label, same_build in (("same-build", True), ("cross-build", False)):
            base = _recall_rate(baseline_recall, arch, same_build)
            current = _recall_rate(recall, arch, same_build)
            if base is None:
                continue
            if current is None:
                failures.append(f"{arch} {label} recall: no attempts in the current run")
            elif current + tolerance < base:
                failures.append(
                    f"{arch} {label} recall {current:.3f} < baseline {base:.3f} - {tolerance:.2f}"
                )
        base_fp_rate = _fp_rate(baseline_fp, arch)
        current_fp_rate = _fp_rate(false_positives, arch)
        if base_fp_rate is None:
            continue
        if current_fp_rate is None:
            failures.append(f"{arch} false positives: no strong signatures in the current run")
        elif current_fp_rate > base_fp_rate + tolerance:
            failures.append(
                f"{arch} false-positive rate {current_fp_rate:.3f} > "
                f"baseline {base_fp_rate:.3f} + {tolerance:.2f}"
            )
    return failures


def _recall_document(cells: list[RecallCell]) -> list[dict[str, object]]:
    return [
        {
            "arch": cell.arch,
            "source_opt": cell.source_opt,
            "target_opt": cell.target_opt,
            "hits": cell.hits,
            "attempts": cell.attempts,
        }
        for cell in cells
    ]


def _false_positive_document(cells: list[FalsePositiveCell]) -> list[dict[str, object]]:
    return [
        {
            "arch": cell.arch,
            "signatures": cell.signatures,
            "signatures_with_hits": cell.signatures_with_hits,
            "hits": cell.hits,
        }
        for cell in cells
    ]


def _read_recall(value: object) -> list[RecallCell] | None:
    if not isinstance(value, list):
        return None
    cells: list[RecallCell] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        cells.append(
            RecallCell(
                str(item.get("arch", "")),
                str(item.get("source_opt", "")),
                str(item.get("target_opt", "")),
                _as_int(item.get("hits")),
                _as_int(item.get("attempts")),
            )
        )
    return cells


def _read_false_positives(value: object) -> list[FalsePositiveCell] | None:
    if not isinstance(value, list):
        return None
    cells: list[FalsePositiveCell] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        cells.append(
            FalsePositiveCell(
                str(item.get("arch", "")),
                _as_int(item.get("signatures")),
                _as_int(item.get("signatures_with_hits")),
                _as_int(item.get("hits")),
            )
        )
    return cells


def _as_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _recall_rate(cells: list[RecallCell], arch: str, same_build: bool) -> float | None:
    selected = [
        cell
        for cell in cells
        if cell.arch == arch and (cell.source_opt == cell.target_opt) == same_build
    ]
    attempts = sum(cell.attempts for cell in selected)
    return sum(cell.hits for cell in selected) / attempts if attempts else None


def _fp_rate(cells: list[FalsePositiveCell], arch: str) -> float | None:
    selected = [cell for cell in cells if cell.arch == arch]
    signatures = sum(cell.signatures for cell in selected)
    if not signatures:
        return None
    return sum(cell.signatures_with_hits for cell in selected) / signatures


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
