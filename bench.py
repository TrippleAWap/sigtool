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

False positives are measured two ways: against corpus binaries built from
other source files, and against the dedicated negative corpus under
`corpus/negative/`. Recall is measured twice per arch and opt level: hinted
(the target's symbol table may seed candidate starts) and hint-free
(candidates must come from anchor bytes and the backward sweep alone, as a
scanner without symbols sees the target).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from core.errors import SigToolError
from core.generate import generate
from core.match import scan
from core.merge import MergeSample, merge
from core.sigfile import Signature
from core.spec import SPEC_VERSION
from sources.file import FileSource

DEFAULT_CORPUS = Path("corpus/build")
# The corpus is rebuilt by whichever clang CI provides, so cross-build rates move
# a little between compiler versions (clang 18 vs 22 differs by about 0.02 here).
# Five points still catches a real regression without pinning a toolchain.
DEFAULT_TOLERANCE = 0.05
SUPPORTED_ARCHES = ("x64", "arm64", "arm32")
MERGED_ARCH: Final[str] = "merged"

# Discovery modes: "hinted" lets the matcher use the target's symbol table as
# candidate starts (comparison quality); "hint-free" forbids them, so a match
# has to be found from anchor bytes alone (discovery, as a scanner sees it).
HINTED: Final[str] = "hinted"
HINT_FREE: Final[str] = "hint-free"
DISCOVERY_MODES: Final[tuple[str, ...]] = (HINTED, HINT_FREE)


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
    discovery: str
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
    negatives = [entry for entry in _load_negative(args.corpus) if entry["arch"] in arches]
    sources = {path: FileSource.from_path(args.corpus / path) for path in _paths(binaries)}
    for path in _paths(negatives):
        sources.setdefault(path, FileSource.from_path(args.corpus / path))

    samples, refused = _build_samples(binaries, sources)
    recall = _recall(samples, binaries, sources, hints=True, discovery=HINTED)
    recall += _recall(samples, binaries, sources, hints=False, discovery=HINT_FREE)
    false_positives = _false_positives(samples, binaries, sources)
    negative_false_positives = _negative_false_positives(samples, negatives, sources)

    merged, merged_refused = _build_merged_samples(binaries, sources)
    recall += _merged_recall(merged, binaries, sources)
    false_positives += _false_positives(merged, binaries, sources)
    negative_false_positives += _negative_false_positives(merged, negatives, sources)
    samples += merged

    _report(samples, refused, merged_refused, recall, false_positives, negative_false_positives)

    if args.save_baseline is not None:
        _save_baseline(
            args.save_baseline,
            len(samples),
            refused,
            recall,
            false_positives,
            negative_false_positives,
            merged_refused=merged_refused,
        )
        print(f"\nwrote baseline {args.save_baseline}")

    failures: list[str] = []
    if args.baseline is not None:
        failures = _compare(
            args.baseline,
            refused,
            recall,
            false_positives,
            negative_false_positives,
            args.tolerance,
        )
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
                    "merged_refused": merged_refused,
                    "recall": _recall_document(recall),
                    "false_positives": _false_positive_document(false_positives),
                    "negative_false_positives": _false_positive_document(negative_false_positives),
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


def _load_negative(root: Path) -> list[dict[str, object]]:
    path = root / "ground_truth.json"
    if not path.exists():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document.get("negative", [])
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


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
    *,
    hints: bool,
    discovery: str,
) -> list[RecallCell]:
    targets = _function_table(binaries)
    cells: dict[tuple[str, str, str, str], list[int]] = defaultdict(lambda: [0, 0])
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
                addresses = _scan_addresses(sample.signature, sources[path], hints=hints)
                cache[(index, path)] = addresses
            cell = cells[(sample.arch, sample.opt, opt, discovery)]
            cell[1] += 1
            if expected in addresses:
                cell[0] += 1

    return [
        RecallCell(arch, source_opt, target_opt, discovery, hits, attempts)
        for (arch, source_opt, target_opt, discovery), (hits, attempts) in sorted(cells.items())
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
        # A merged signature is cross-arch by construction, so every target
        # architecture is in scope for it.
        for (arch, source_file), paths in others.items():
            if source_file == sample.source_file:
                continue
            if sample.arch != MERGED_ARCH and arch != sample.arch:
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


def _negative_false_positives(
    samples: list[Sample],
    negatives: list[dict[str, object]],
    sources: dict[str, FileSource],
) -> list[FalsePositiveCell]:
    """Scan strong signatures against the M0 negative corpus binaries."""
    strong = [sample for sample in samples if sample.verdict == "strong"]
    by_arch: dict[str, list[str]] = defaultdict(list)
    for entry in negatives:
        by_arch[str(entry["arch"])].append(str(entry["path"]))

    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for sample in strong:
        bucket = counts[sample.arch]
        bucket[0] += 1
        hits = 0
        # A merged signature is cross-arch by construction: every negative
        # architecture is a valid target for it.
        target_arches = list(by_arch) if sample.arch == MERGED_ARCH else [sample.arch]
        for arch in sorted(target_arches):
            for path in by_arch.get(arch, []):
                hits += len(_scan_addresses(sample.signature, sources[path]))
        bucket[2] += hits
        if hits:
            bucket[1] += 1

    return [
        FalsePositiveCell(arch, signatures, with_hits, hits)
        for arch, (signatures, with_hits, hits) in sorted(counts.items())
    ]


def _build_merged_samples(
    binaries: list[dict[str, object]],
    sources: dict[str, FileSource],
) -> tuple[list[Sample], int]:
    """Merge x64 and arm64 samples of each function into cross-arch signatures.

    This is the M4 exit measurement: a signature merged from two architectures
    must still match the same function in the third (arm32) and in builds at
    other optimization levels.
    """
    starts: dict[str, dict[tuple[str, str], int]] = defaultdict(dict)
    files: dict[str, str] = {}
    sources_by_key: dict[tuple[str, str, str], FileSource] = {}
    for entry in binaries:
        arch, source_file, opt = _kind(str(entry["path"]))
        path = str(entry["path"])
        sources_by_key[(arch, source_file, opt)] = sources[path]
        for function in entry["functions"]:  # type: ignore[union-attr]
            name = str(function["name"])
            starts[name][(arch, opt)] = int(function["start"])
            files[name] = source_file

    samples: list[Sample] = []
    refused = 0
    for name in sorted(starts):
        opts = sorted({opt for arch, opt in starts[name] if arch in ("x64", "arm64")})
        for opt in opts:
            x64 = starts[name].get(("x64", opt))
            arm64 = starts[name].get(("arm64", opt))
            source_x64 = sources_by_key.get(("x64", files[name], opt))
            source_arm64 = sources_by_key.get(("arm64", files[name], opt))
            if None in (x64, arm64, source_x64, source_arm64):
                continue
            try:
                result = merge(
                    [
                        MergeSample(source_x64, int(x64), opt=opt, tool="clang"),
                        MergeSample(source_arm64, int(arm64), opt=opt, tool="clang"),
                    ],
                    name=name,
                )
            except SigToolError:
                refused += 1
                continue
            samples.append(
                Sample(
                    arch=MERGED_ARCH,
                    source_file=files[name],
                    opt=opt,
                    name=name,
                    start=0,
                    signature=result.signature,
                    verdict=result.report.verdict,
                )
            )
    return samples, refused


def _merged_recall(
    merged: list[Sample],
    binaries: list[dict[str, object]],
    sources: dict[str, FileSource],
) -> list[RecallCell]:
    """Merged-signature recall against every same-file target build."""
    starts: dict[tuple[str, str, str], int] = {}
    for entry in binaries:
        arch, source_file, opt = _kind(str(entry["path"]))
        for function in entry["functions"]:  # type: ignore[union-attr]
            starts[(str(function["name"]), arch, opt)] = int(function["start"])

    cells: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    cache: dict[tuple[int, str], tuple[int, ...]] = {}
    for index, sample in enumerate(merged):
        for entry in binaries:
            arch, source_file, opt = _kind(str(entry["path"]))
            if source_file != sample.source_file:
                continue
            expected = starts.get((sample.name, arch, opt))
            if expected is None:
                continue
            path = str(entry["path"])
            addresses = cache.get((index, path))
            if addresses is None:
                addresses = _scan_addresses(sample.signature, sources[path])
                cache[(index, path)] = addresses
            cell = cells[(f"{MERGED_ARCH}->{arch}", sample.opt, opt)]
            cell[1] += 1
            if expected in addresses:
                cell[0] += 1

    return [
        RecallCell(arch, source_opt, target_opt, HINTED, hits, attempts)
        for (arch, source_opt, target_opt), (hits, attempts) in sorted(cells.items())
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


def _scan_addresses(
    signature: Signature, source: FileSource, *, hints: bool = True
) -> tuple[int, ...]:
    return tuple(match.address for match in scan(source, signature, hints=hints))


# -- baselines ---------------------------------------------------------------


def _save_baseline(
    path: Path,
    signatures: int,
    refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
    negative_false_positives: list[FalsePositiveCell],
    *,
    merged_refused: int = 0,
) -> None:
    """Write the compact metrics that :func:`_compare` reads.

    Sample-level detail belongs in ``--json`` output; a baseline is a reviewable
    set of numbers, so signature ids and file paths stay out of it.
    ``merged_refused`` is recorded for review but never gated: refusing a pair
    that cannot be honestly merged is the design working, not a regression.
    """
    document = {
        "spec_version": SPEC_VERSION,
        "signatures": signatures,
        "refused": refused,
        "merged_refused": merged_refused,
        "recall": _recall_document(recall),
        "false_positives": _false_positive_document(false_positives),
        "negative_false_positives": _false_positive_document(negative_false_positives),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _compare(
    path: Path,
    refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
    negative_false_positives: list[FalsePositiveCell],
    tolerance: float,
) -> list[str]:
    """Return the regressions that exceed ``tolerance``.

    Rates are compared rather than raw counts because rebuilding the corpus with
    a different clang can legitimately change which functions exist. Merged
    refusals are informational only (see :func:`_save_baseline`), and merged
    false positives are reported but not gated: the merged FP budget is unmet
    by design (PLAN.md section 12), and on this corpus the denominator is 13-15
    strong merged signatures, so one compiler-version swing moves the rate by
    more than any useful tolerance. Single-arch false positives stay hard-gated
    at zero tolerance for an increase above ``tolerance``.
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
    baseline_negative = _read_false_positives(baseline.get("negative_false_positives"))
    if baseline_recall is None or baseline_fp is None or baseline_negative is None:
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
        for discovery in DISCOVERY_MODES:
            for label, same_build in (("same-build", True), ("cross-build", False)):
                base = _recall_rate(baseline_recall, arch, same_build, discovery)
                current = _recall_rate(recall, arch, same_build, discovery)
                if base is None:
                    continue
                if current is None:
                    failures.append(
                        f"{arch} {discovery} {label} recall: no attempts in the current run"
                    )
                elif current + tolerance < base:
                    failures.append(
                        f"{arch} {discovery} {label} recall {current:.3f} < "
                        f"baseline {base:.3f} - {tolerance:.2f}"
                    )

    _compare_false_positives(
        "cross-source false positives", baseline_fp, false_positives, tolerance, failures
    )
    _compare_false_positives(
        "negative false positives", baseline_negative, negative_false_positives, tolerance, failures
    )
    return failures


def _compare_false_positives(
    label: str,
    baseline: list[FalsePositiveCell],
    current: list[FalsePositiveCell],
    tolerance: float,
    failures: list[str],
) -> None:
    """Compare per-arch false-positive rates; the ``merged`` bucket never gates.

    A merged signature's evidence is the sample intersection by design, so its
    FP budget is a tracked open item (PLAN.md section 12) rather than a
    regression gate; on this corpus its denominator is 13-15 strong signatures,
    too small to gate across compiler versions.
    """
    baseline_arches = {cell.arch for cell in baseline} - {MERGED_ARCH}
    current_arches = {cell.arch for cell in current}
    for arch in sorted(baseline_arches - current_arches):
        failures.append(f"{label} {arch}: missing from the current run")
    for arch in sorted(baseline_arches & current_arches):
        base = _fp_rate(baseline, arch)
        now = _fp_rate(current, arch)
        if base is None:
            continue
        if now is None:
            failures.append(f"{label} {arch}: no strong signatures in the current run")
        elif now > base + tolerance:
            failures.append(
                f"{label} {arch} rate {now:.3f} > baseline {base:.3f} + {tolerance:.2f}"
            )


def _recall_document(cells: list[RecallCell]) -> list[dict[str, object]]:
    return [
        {
            "arch": cell.arch,
            "source_opt": cell.source_opt,
            "target_opt": cell.target_opt,
            "discovery": cell.discovery,
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
        discovery = item.get("discovery")
        if not isinstance(discovery, str):
            return None  # a baseline from before the discovery split is unusable
        cells.append(
            RecallCell(
                str(item.get("arch", "")),
                str(item.get("source_opt", "")),
                str(item.get("target_opt", "")),
                discovery,
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


def _recall_rate(
    cells: list[RecallCell], arch: str, same_build: bool, discovery: str
) -> float | None:
    selected = [
        cell
        for cell in cells
        if cell.arch == arch
        and cell.discovery == discovery
        and (cell.source_opt == cell.target_opt) == same_build
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
    merged_refused: int,
    recall: list[RecallCell],
    false_positives: list[FalsePositiveCell],
    negative_false_positives: list[FalsePositiveCell],
) -> None:
    verdicts = Counter(sample.verdict for sample in samples)
    per_arch: dict[str, Counter[str]] = defaultdict(Counter)
    for sample in samples:
        per_arch[sample.arch][sample.verdict] += 1

    print(f"signatures: {len(samples)}  refused by self-test: {refused}")
    if merged_refused:
        print(f"merged pairs refused honestly (cannot self-test on a sample): {merged_refused}")
    print(f"verdicts: {dict(sorted(verdicts.items()))}")
    for arch, counts in sorted(per_arch.items()):
        print(f"  {arch}: strong={counts['strong']} weak={counts['weak']} small={counts['small']}")

    for discovery in DISCOVERY_MODES:
        mode_cells = [cell for cell in recall if cell.discovery == discovery]
        print(f"\nrecall ({discovery}: same function, same and cross optimization level)")
        for cell in mode_cells:
            marker = "" if cell.source_opt != cell.target_opt else "  (same build)"
            print(
                f"  {cell.arch} {cell.source_opt}->{cell.target_opt}: "
                f"{cell.hits}/{cell.attempts} = {cell.rate:.3f}{marker}"
            )
        same = [cell for cell in mode_cells if cell.source_opt == cell.target_opt]
        cross = [cell for cell in mode_cells if cell.source_opt != cell.target_opt]
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

    print("\nnegative corpus (strong signatures vs unrelated clean binaries)")
    if not negative_false_positives:
        print("  no strong signatures to test")
    for cell in negative_false_positives:
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
