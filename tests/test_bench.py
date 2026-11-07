"""Corpus harness plumbing tests (the harness itself needs built binaries)."""

from __future__ import annotations

import json
from pathlib import Path

from bench import (
    DEFAULT_TOLERANCE,
    FalsePositiveCell,
    RecallCell,
    _compare,
    _kind,
    _save_baseline,
    _split_path,
    main,
)
from core.spec import SPEC_VERSION


def _recall(arch: str = "x64", *, source_opt: str = "O2", target_opt: str = "O2") -> RecallCell:
    return RecallCell(arch, source_opt, target_opt, 10, 10)


def _false_positive(arch: str = "x64", *, signatures_with_hits: int = 0) -> FalsePositiveCell:
    return FalsePositiveCell(arch, 10, signatures_with_hits, signatures_with_hits)


def _saved(tmp_path: Path) -> Path:
    path = tmp_path / "baseline.json"
    _save_baseline(path, 10, 0, [_recall()], [_false_positive()])
    return path


def test_path_parts_follow_the_corpus_layout() -> None:
    assert _split_path("x64/O2/loops.elf") == ("loops", "O2")
    assert _kind("arm64/Os/parser.elf") == ("arm64", "parser", "Os")


def test_missing_corpus_is_a_usage_error(tmp_path: Path) -> None:
    assert main(["--corpus", str(tmp_path)]) == 2


def test_baseline_round_trip_without_changes(tmp_path: Path) -> None:
    baseline = _saved(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))

    assert document["spec_version"] == SPEC_VERSION
    assert "samples" not in document
    assert _compare(baseline, 0, [_recall()], [_false_positive()], DEFAULT_TOLERANCE) == []


def test_baseline_rejects_a_recall_drop(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    _save_baseline(
        path,
        20,
        0,
        [RecallCell("x64", "O2", "O2", 10, 10), RecallCell("x64", "O2", "Os", 10, 10)],
        [_false_positive()],
    )
    dropped = [RecallCell("x64", "O2", "O2", 5, 10), RecallCell("x64", "O2", "Os", 5, 10)]

    failures = _compare(path, 0, dropped, [_false_positive()], DEFAULT_TOLERANCE)

    assert any("same-build recall" in failure for failure in failures)
    assert any("cross-build recall" in failure for failure in failures)


def test_baseline_tolerance_absorbs_a_small_recall_drop(tmp_path: Path) -> None:
    baseline = _saved(tmp_path)
    slightly_worse = [RecallCell("x64", "O2", "O2", 99, 100)]

    assert _compare(baseline, 0, slightly_worse, [_false_positive()], 0.02) == []
    assert _compare(baseline, 0, slightly_worse, [_false_positive()], 0.005)


def test_baseline_rejects_a_false_positive_increase(tmp_path: Path) -> None:
    baseline = _saved(tmp_path)
    noisy = [_false_positive(signatures_with_hits=10)]

    failures = _compare(baseline, 0, [_recall()], noisy, DEFAULT_TOLERANCE)

    assert any("false-positive rate" in failure for failure in failures)


def test_baseline_rejects_extra_refusals(tmp_path: Path) -> None:
    baseline = _saved(tmp_path)

    failures = _compare(baseline, 1, [_recall()], [_false_positive()], DEFAULT_TOLERANCE)

    assert any("refusals" in failure for failure in failures)


def test_baseline_requires_the_current_spec_version(tmp_path: Path) -> None:
    baseline = _saved(tmp_path)
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document["spec_version"] = "0"
    baseline.write_text(json.dumps(document), encoding="utf-8")

    failures = _compare(baseline, 0, [_recall()], [_false_positive()], DEFAULT_TOLERANCE)

    assert any("spec version" in failure for failure in failures)


def test_baseline_reports_a_missing_arch(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    _save_baseline(
        path,
        20,
        0,
        [_recall("x64"), _recall("arm64")],
        [_false_positive("x64"), _false_positive("arm64")],
    )

    failures = _compare(path, 0, [_recall("x64")], [_false_positive("x64")], DEFAULT_TOLERANCE)

    assert any("arm64" in failure and "missing" in failure for failure in failures)
