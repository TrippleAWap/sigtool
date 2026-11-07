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
| M2 generation | core implemented: weighted deterministic YAML plus quality report; CLI and process sources pending |
| M3 validation harness | not started |

ARM32/Thumb are detected and rejected with a clear error until M4.

## Install and check

```bash
pip install -e .[dev]
pytest
ruff format . && ruff check .
mypy core
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
```

## Layout

```
core/       source, arch, normalize, recover, features, score, sigfile, validate, generate
            (match lands in M3)
sources/    file (ELF, PE); live-process and IDA sources follow
spec/       signature spec and changelog
corpus/     build script, C samples, ground truth (binaries ignored)
tests/      vectors/ (golden), unit, property, live/ later
```
