"""Corpus harness plumbing tests (the harness itself needs built binaries)."""

from __future__ import annotations

from pathlib import Path

from bench import _kind, _split_path, main


def test_path_parts_follow_the_corpus_layout() -> None:
    assert _split_path("x64/O2/loops.elf") == ("loops", "O2")
    assert _kind("arm64/Os/parser.elf") == ("arm64", "parser", "Os")


def test_missing_corpus_is_a_usage_error(tmp_path: Path) -> None:
    assert main(["--corpus", str(tmp_path)]) == 2
