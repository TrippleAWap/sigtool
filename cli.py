"""Command-line front-end for sigtool.

The CLI is thin by contract (AGENTS.md rule 2): it resolves a ``ByteSource`` and
an address, calls :func:`core.generate.generate`, and formats the result. No
feature, scoring, matching, or serialisation logic lives here.

    sigtool gen --file image.elf --addr 0x1000
    sigtool gen --file image.elf --module image.elf --rva 0x1000
    sigtool gen --pid 1234 --addr 0x7ff6_0000_1000
    sigtool gen --pid 1234 --module kernel32.dll --rva 0x1000 --output function.yaml

The signature YAML goes to stdout (or ``--output``) so it can be piped; the
quality report goes to stderr. ``--json-report`` also writes the report as JSON.

PID mode is read-only and currently Windows-only; opening a 32-bit or WOW64
target exits with code ``3`` instead of decoding it as x64.

Exit codes:

* ``0`` success
* ``2`` usage or input error (missing file, bad address, unmapped address, ...)
* ``3`` unsupported target architecture or mode
* ``4`` self-test failed, so no signature was emitted (AGENTS.md rule 7)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from core.errors import SelfTestError, SigToolError, UnsupportedArchError
from core.generate import GenerationResult, generate
from core.source import ByteSource, Module
from sources.file import FileSource

EXIT_OK: Final[int] = 0
EXIT_ERROR: Final[int] = 2
EXIT_UNSUPPORTED: Final[int] = 3
EXIT_SELF_TEST: Final[int] = 4


class CliError(SigToolError):
    """A front-end input problem: bad address, unknown module, or bad option."""


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "gen":
        return _generate(args)
    parser.error(f"unknown command {args.command!r}")
    return EXIT_ERROR


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigtool",
        description="Generate architecture-independent function signatures.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    gen = commands.add_parser(
        "gen",
        help="generate a signature for one function",
        description="Generate a signature for the function containing an address.",
    )
    source = gen.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="ELF or PE image")
    source.add_argument("--pid", type=int, metavar="PID", help="live process id (Windows)")
    target = gen.add_mutually_exclusive_group(required=True)
    target.add_argument("--addr", metavar="ADDR", help="absolute address, e.g. 0x1000")
    target.add_argument("--rva", metavar="RVA", help="module-relative address")
    gen.add_argument(
        "--module",
        metavar="NAME",
        help="module name for --rva (optional when the image has one module)",
    )
    gen.add_argument("--name", help="signature name (default: symbol or module+rva)")
    gen.add_argument("--opt", help="provenance only: optimization level, e.g. O2")
    gen.add_argument("--tool", help="provenance only: compiler or tool name")
    gen.add_argument("--output", type=Path, help="write signature YAML here instead of stdout")
    gen.add_argument("--json-report", type=Path, help="write the quality report as JSON")
    return parser


def _generate(args: argparse.Namespace) -> int:
    try:
        with _open_source(args) as source:
            addr = _resolve_address(source, args)
            result = generate(source, addr, name=args.name, opt=args.opt, tool=args.tool)
            _write_outputs(source, result, args)
    except UnsupportedArchError as error:
        _error(f"unsupported target: {error}")
        return EXIT_UNSUPPORTED
    except SelfTestError as error:
        _error(f"self-test failed, refusing to emit a signature: {error}")
        return EXIT_SELF_TEST
    except (SigToolError, OSError) as error:
        _error(str(error))
        return EXIT_ERROR
    return EXIT_OK


@contextmanager
def _open_source(args: argparse.Namespace) -> Iterator[ByteSource]:
    if args.pid is not None:
        from sources.proc_win import WindowsProcessSource

        with WindowsProcessSource.open(args.pid) as source:
            yield source
        return
    if args.file is None:
        raise CliError("one of --file or --pid is required")
    yield _load_file(args.file)


def _load_file(path: Path) -> FileSource:
    if not path.is_file():
        raise CliError(f"no such image file: {path}")
    return FileSource.from_path(path)


def _resolve_address(source: ByteSource, args: argparse.Namespace) -> int:
    if args.addr is not None:
        if args.module is not None:
            raise CliError("--module applies to --rva, not --addr")
        addr = _parse_address(args.addr, "--addr")
        if not source.is_mapped(addr):
            raise CliError(f"address 0x{addr:x} is not mapped in the image")
        return addr

    if args.rva is None:
        raise CliError("one of --addr or --rva is required")
    module = _find_module(source, args.module)
    rva = _parse_address(args.rva, "--rva")
    addr = module.base + rva
    if not module.contains(addr):
        raise CliError(f"rva 0x{rva:x} is outside module {module.name!r} (size 0x{module.size:x})")
    if not source.is_mapped(addr):
        raise CliError(f"module+rva {module.name}+0x{rva:x} is not mapped")
    return addr


def _find_module(source: ByteSource, name: str | None) -> Module:
    modules = list(source.modules())
    if not modules:
        raise CliError("the image has no modules")
    if name is None:
        if len(modules) == 1:
            return modules[0]
        names = ", ".join(module.name for module in modules)
        raise CliError(f"--module is required; the image has several modules: {names}")
    for module in modules:
        if module.name == name:
            return module
    folded = [module for module in modules if module.name.casefold() == name.casefold()]
    if len(folded) == 1:
        return folded[0]
    names = ", ".join(module.name for module in modules)
    raise CliError(f"unknown module {name!r}; the image has: {names}")


def _parse_address(text: str, option: str) -> int:
    try:
        value = int(text.strip(), 0)
    except ValueError as error:
        raise CliError(
            f"{option} expects a decimal or 0x-prefixed address, got {text!r}"
        ) from error
    if value < 0:
        raise CliError(f"{option} must not be negative")
    return value


def _write_outputs(source: ByteSource, result: GenerationResult, args: argparse.Namespace) -> None:
    text = result.to_yaml()
    if args.output is None:
        sys.stdout.write(text)
        destination = "stdout"
    else:
        args.output.write_text(text, encoding="utf-8")
        destination = str(args.output)

    report = _report(source, result, destination)
    sys.stderr.write(report + "\n")

    if args.json_report is not None:
        args.json_report.write_text(
            json.dumps(_report_document(source, result), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _report(source: ByteSource, result: GenerationResult, destination: str) -> str:
    signature = result.signature
    report = result.report
    label = source.label_for_address(result.match.address) or f"0x{result.match.address:x}"
    lines = [
        f"signature {signature.name}  ({signature.signature_id})",
        (f"arch {source.arch.value}  verdict {report.verdict}  confidence {signature.confidence}"),
        (
            f"features {len(signature.features)} (required {report.required_features}, "
            f"optional {report.optional_features})  anchors {report.anchor_count}  "
            f"evidence {report.evidence:.3f}"
        ),
        (f"self-test {label}  score {result.match.score:.3f}  matched {len(result.match.matched)}"),
        f"yaml {destination}",
    ]
    if report.notes:
        lines.append("notes:")
        lines.extend(f"  - {note}" for note in report.notes)
    return "\n".join(lines)


def _report_document(source: ByteSource, result: GenerationResult) -> dict[str, object]:
    signature = result.signature
    report = result.report
    return {
        "signature_id": signature.signature_id,
        "name": signature.name,
        "arch": source.arch.value,
        "verdict": report.verdict,
        "confidence": signature.confidence,
        "features": len(signature.features),
        "required_features": report.required_features,
        "optional_features": report.optional_features,
        "anchors": report.anchor_count,
        "evidence": round(report.evidence, 6),
        "self_test": {
            "at": source.label_for_address(result.match.address) or f"0x{result.match.address:x}",
            "score": result.match.score,
            "matched": len(result.match.matched),
        },
        "notes": list(report.notes),
    }


def _error(message: str) -> None:
    sys.stderr.write(f"sigtool: {message}\n")


if __name__ == "__main__":
    sys.exit(main())
