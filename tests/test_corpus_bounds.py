"""Corpus regression: recovered bounds must match symbol sizes.

The corpus is built locally (binaries are never committed):

    python corpus/build.py
    pytest tests/test_corpus_bounds.py

The test is skipped when no corpus is present.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.arch import Arch
from core.recover import recover
from core.source import MemorySource
from sources.file import FileSource

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "build"
GROUND_TRUTH = CORPUS / "ground_truth.json"
MIN_AGREEMENT = 0.90  # PLAN.md M1 exit criterion


def load_ground_truth() -> dict[str, object]:
    if not GROUND_TRUTH.exists():
        pytest.skip("corpus not built; run python corpus/build.py")
    return json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))


def test_recovered_bounds_match_symbol_sizes() -> None:
    truth = load_ground_truth()
    checked = 0
    matched = 0
    mismatches: list[str] = []
    for entry in truth["binaries"]:  # type: ignore[index]
        path = CORPUS / str(entry["path"])
        arch = Arch(str(entry["arch"]))
        if arch not in (Arch.X64, Arch.ARM64, Arch.ARM32):
            continue
        image = FileSource.from_path(path)
        # No symbol-size hint: this measures recovery as a scanner would run it,
        # rather than letting the ground truth bound the walk. arm32/thumb mode
        # still follows the image's symbols, as a scanner's mode table would.
        thumb_ranges = tuple(
            (int(function["start"]), int(function["start"]) + int(function["size"]))
            for function in entry["functions"]  # type: ignore[union-attr]
            if image.is_thumb(int(function["start"]))
        )
        source = MemorySource(
            image.arch, image.regions(), image.modules(), thumb_ranges=thumb_ranges
        )
        for function in entry["functions"]:
            start = int(function["start"])
            end = start + int(function["size"])
            try:
                recovered = recover(source, start)
            except Exception as error:  # reported as a mismatch, not a crash
                mismatches.append(f"{path.name}:{function['name']}: {error}")
                checked += 1
                continue
            checked += 1
            if recovered.end == end:
                matched += 1
            else:
                mismatches.append(
                    f"{path.name}:{function['name']} recovered 0x{recovered.end:x} "
                    f"expected 0x{end:x}"
                )
    assert checked, "ground truth contained no supported-arch functions"
    agreement = matched / checked
    assert agreement >= MIN_AGREEMENT, (
        f"bounds agreement {agreement:.3f} below {MIN_AGREEMENT:.2f}\n" + "\n".join(mismatches[:25])
    )


def test_ground_truth_coverage_meets_the_m0_criterion() -> None:
    truth = load_ground_truth()
    coverage = float(truth["coverage"])  # type: ignore[index]
    assert coverage >= 0.95, f"ground-truth coverage {coverage:.3f} below 0.95"
