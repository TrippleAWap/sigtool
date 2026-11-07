# sigtool

Architecture-independent function signatures, generated from a live process, an
image file, or an IDA function, and matched at runtime.

Signatures are **feature sets, not byte patterns**: strings, normalized
constants, resolved callee names, coarse CFG shape, and a bucketed op-class
histogram. One shared extractor produces features for generation and scanning.

Read [`PLAN.md`](PLAN.md) for scope and milestones, [`spec/SPEC.md`](spec/SPEC.md)
for the signature spec, and [`AGENTS.md`](AGENTS.md) for contribution rules.

## Status

| Milestone | State |
|---|---|
| M0 spec and corpus | started: spec v1 written, corpus build script and samples present |
| M1 extraction (x64, AArch64) | implemented and passing: bounds agreement 1.00 on x64, 0.94 on arm64 (criterion 0.90) |
| M2 generation | core, file CLI, and Windows PID mode implemented; Linux process source pending |
| M3 validation harness | reference matcher and mandatory self-test implemented; corpus recall/FP harness in `bench.py` with a committed baseline and CI gate; negative corpus still M0 work |

ARM32/Thumb are detected and rejected with a clear error until M4.

## Install and check

```bash
pip install -e .[dev]
pytest
ruff format --check . && ruff check .
mypy core sources
```

Golden vectors are regenerated from real compiler output (needs `clang` with
`ld.lld`, LLVM 15+):

```bash
python tests/vectors/generate.py
```

The corpus (bounds ground truth) is built locally; binaries are never committed:

```bash
python corpus/build.py
pytest tests/test_corpus_bounds.py
python bench.py                      # recall per arch/opt level, false positives
python bench.py --json corpus/report.json
python bench.py --baseline tests/baseline/bench.json  # fail on regression
python bench.py --save-baseline tests/baseline/bench.json  # update, review diff
```

Generate a signature from an image file or a live Windows process:

```bash
sigtool gen --file corpus/build/x64/O2/loops.elf --addr 0x201340
sigtool gen --file image.so --module image.so --rva 0x1340 --output fn.yaml
sigtool gen --pid 1234 --module kernel32.dll --rva 0x1000
```

PID mode is read-only and Windows-only for now. 32-bit and WOW64 targets exit
with code `3` instead of being decoded as x64.

The YAML signature goes to stdout (or `--output`); the quality report goes to
stderr. `--json-report PATH` writes the report as JSON. Exit codes: `0` success,
`2` usage/input error, `3` unsupported architecture, `4` self-test failure
(no signature emitted).

Current harness numbers (x64 and arm64, two source files, clang 18): 102/102
signatures pass self-test, same-build recall 1.000, cross-optimization recall
0.427, and zero false positives for 40 strong signatures against unrelated
binaries. Compiler version shifts cross-build recall by about two points (clang
22 gives 0.448). The negative corpus is still M0 work, so the FP number is a
floor.

CI (`.github/workflows/ci.yml`) runs format, lint, types, the spec-version check,
the corpus build, pytest, and the baseline regression on Linux, plus the live
Windows PID-mode tests on a Windows runner.

## Layout

```
core/       source, arch, normalize, recover, features, score, sigfile, validate, generate, match
sources/    file (ELF, PE), proc_win (read-only live Windows process); IDA follows
spec/       signature spec and changelog
corpus/     build script, C samples, ground truth (binaries ignored)
tests/      vectors/ (golden), unit, property, live/ (Windows process tests)
cli.py      front-end: file images and Windows PID mode
```
