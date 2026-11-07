"""CLI front-end: address resolution, output routing, and exit codes.

End-to-end cases use the locally built corpus and skip when it is absent, so no
addresses or paths are hardcoded (AGENTS.md: build the corpus first).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import cli
from core.errors import SelfTestError
from core.sigfile import Signature
from sources.file import FileSource
from tests.support import HELPER, strong_source

CORPUS = Path(__file__).resolve().parents[1] / "corpus" / "build"
GROUND_TRUTH = CORPUS / "ground_truth.json"


# -- unit cases --------------------------------------------------------------


def test_parse_address_accepts_decimal_and_hex() -> None:
    assert cli._parse_address("4096", "--addr") == 4096
    assert cli._parse_address("0x1000", "--addr") == 4096
    assert cli._parse_address("0X1_000", "--addr") == 4096


def test_parse_address_rejects_bad_text_and_negatives() -> None:
    with pytest.raises(cli.CliError):
        cli._parse_address("not-a-number", "--addr")
    with pytest.raises(cli.CliError):
        cli._parse_address("-0x10", "--addr")


def test_rva_resolves_against_the_module_base() -> None:
    source = strong_source()
    args = cli._parser().parse_args(
        ["gen", "--file", "unused", "--module", "gen", "--rva", f"0x{HELPER - 0x1000:x}"]
    )
    assert cli._resolve_address(source, args) == HELPER


def test_module_lookup_is_case_insensitive_and_reports_unknown_names() -> None:
    source = strong_source()
    assert cli._find_module(source, "GEN").name == "gen"
    with pytest.raises(cli.CliError, match="unknown module"):
        cli._find_module(source, "missing")


def test_addr_and_module_together_is_a_usage_error() -> None:
    source = strong_source()
    args = cli._parser().parse_args(
        ["gen", "--file", "unused", "--addr", "0x1000", "--module", "gen"]
    )
    with pytest.raises(cli.CliError, match="--module applies to --rva"):
        cli._resolve_address(source, args)


def test_missing_image_is_a_usage_error(tmp_path: Path) -> None:
    assert cli.main(["gen", "--file", str(tmp_path / "missing.elf"), "--addr", "0x0"]) == 2


def test_self_test_failure_refuses_to_emit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path, _name, start = _corpus_function("x64", "O2", "loops")

    def fail(*args: object, **kwargs: object) -> Any:
        raise SelfTestError("signature did not match")

    monkeypatch.setattr(cli, "generate", fail)
    code = cli.main(["gen", "--file", str(path), "--addr", hex(start)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_SELF_TEST
    assert captured.out == ""
    assert "refusing to emit" in captured.err


# -- corpus end-to-end cases -------------------------------------------------


def test_corpus_generation_writes_yaml_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    path, name, start = _corpus_function("x64", "O2", "loops")
    code = cli.main(["gen", "--file", str(path), "--addr", hex(start), "--opt", "O2"])
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    signature = Signature.from_yaml(captured.out)
    assert signature.name == name
    assert name in captured.err
    assert "self-test" in captured.err


def test_corpus_output_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    path, _name, start = _corpus_function("x64", "O2", "loops")
    argv = ["gen", "--file", str(path), "--addr", hex(start)]
    assert cli.main(argv) == cli.EXIT_OK
    first = capsys.readouterr().out
    assert cli.main(argv) == cli.EXIT_OK
    second = capsys.readouterr().out
    assert first == second


def test_output_and_json_report_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path, name, start = _corpus_function("x64", "O2", "loops")
    yaml_path = tmp_path / "function.yaml"
    json_path = tmp_path / "report.json"

    code = cli.main(
        [
            "gen",
            "--file",
            str(path),
            "--addr",
            hex(start),
            "--output",
            str(yaml_path),
            "--json-report",
            str(json_path),
        ]
    )
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert captured.out == ""
    assert Signature.from_yaml(yaml_path.read_text(encoding="utf-8")).name == name
    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["name"] == name
    assert document["arch"] == "x64"
    assert document["self_test"]["score"] == 1.0
    assert document["verdict"] in {"strong", "weak", "small"}


def test_unsupported_arch_exits_three(capsys: pytest.CaptureFixture[str]) -> None:
    path, _name, start = _corpus_function("arm32", "O2", "loops")
    code = cli.main(["gen", "--file", str(path), "--addr", hex(start)])
    captured = capsys.readouterr()

    assert code == cli.EXIT_UNSUPPORTED
    assert captured.out == ""
    assert "unsupported target" in captured.err


# -- corpus helpers ----------------------------------------------------------


def _corpus_function(arch: str, opt: str, stem: str) -> tuple[Path, str, int]:
    if not GROUND_TRUTH.exists():
        pytest.skip("corpus not built; run python corpus/build.py")
    document = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    relative = f"{arch}/{opt}/{stem}.elf"
    for entry in document["binaries"]:
        if str(entry["path"]) != relative:
            continue
        functions = [item for item in entry["functions"] if item["name"] != "_start"]
        if not functions:
            pytest.skip(f"{relative} has no named functions")
        function = functions[0]
        return CORPUS / relative, str(function["name"]), int(function["start"])
    pytest.skip(f"{relative} is not in the ground truth")


def test_module_flag_accepts_the_image_name(capsys: pytest.CaptureFixture[str]) -> None:
    path, name, start = _corpus_function("x64", "O2", "loops")
    image = FileSource.from_path(path)
    module = image.modules()[0]
    rva = start - module.base

    code = cli.main(["gen", "--file", str(path), "--module", module.name, "--rva", hex(rva)])
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert Signature.from_yaml(captured.out).name == name
