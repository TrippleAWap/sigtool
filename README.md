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
| M0 spec and corpus | corpus complete: spec v1 written, positive corpus with 1.000 symbol coverage, negative corpus built at `-O2` per arch; real-library samples deferred pending the licensing decision |
| M1 extraction (x64, AArch64, ARM32/Thumb) | implemented and passing: bounds agreement 1.00 on x64, 0.94 on arm64, 0.98 across arm32 and thumb (criterion 0.90) |
| M2 generation | core, file CLI, and Windows PID mode implemented; Linux process source pending |
| M3 validation harness | implemented: reference matcher with hint-free discovery, mandatory self-test, recall/FP harness in `bench.py` with a committed baseline and CI gate, negative-corpus FP scan at 0 hits |
| M4 cross-arch | implemented: ARM32/Thumb extraction, multi-sample merging (`sigtool merge`), auto-locate (`sigtool locate`); merged cross-arch recall 0.707 same-opt / FP budget unmet — see PLAN §12 |
| M5 IDA plugin | implemented: `IdaSource` over an injectable IDA facade with bounds hints and disagreement notes; generate/merge/locate actions; output test-verified identical to the CLI (UI glue untested in CI — no IDA host) |
| M6 reference scanner | implemented: page-hashed incremental scanner, private/changed/untouched priority, shared recovery budget, per-region data-reference index for string anchors; profile recorded in PLAN §12 |
| M7 native port | implemented for x64, arm64, arm32, and thumb in Rust under `native/`: extractor, matcher, scanner, signature document, CLI (gen/locate/scan/merge/db), and mmap-friendly binary DB; parity-tested against the Python golden vectors (all four architectures), x64 corpus, sampled arm64/arm32/thumb `gen` output, and merged output, and measured at 37.8x the Python scanner's full-pass throughput; ARM32/Thumb decode through Capstone (the reference's engine), so the whole instruction set is covered; PID and IDA ports are follow-ups |

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

Generate a signature from an image file or a live Windows process, merge
samples of one function, and locate a signature in another binary:

```bash
sigtool gen --file corpus/build/x64/O2/loops.elf --addr 0x201340
sigtool gen --file image.so --module image.so --rva 0x1340 --output fn.yaml
sigtool gen --pid 1234 --module kernel32.dll --rva 0x1000
sigtool merge --sample x64.elf:0x1000 --sample arm64.so:0x1340 --name fn
sigtool locate --signature fn.yaml --file other.so --json matches.json
```

PID mode is read-only and Windows-only for now. 32-bit and WOW64 targets exit
with code `3` instead of being decoded as x64.

The YAML signature goes to stdout (or `--output`); the quality report goes to
stderr. `--json-report PATH` writes the report as JSON. Exit codes: `0` success,
`1` locate found no match, `2` usage/input error, `3` unsupported architecture,
`4` self-test failure (no signature emitted).

Current harness numbers (clang 18, three arches plus thumb builds, two source
files): single-arch signatures pass self-test with zero false positives for all
strong signatures on every arch. Recall is reported per discovery mode: hinted
same-build 1.000, hinted cross-opt best on arm32 (0.583), hint-free near zero
(0.098 same-build) because only about a fifth of signatures carry a searchable
code anchor. Merged x64+arm64 signatures keep same-arch recall at 1.000 and
reach 0.707 same-opt on arm32, but they hit unrelated binaries (4/15 strong
cross-source) because the merged required set is the sample intersection.
Compiler version moves hinted cross-opt rates by a couple of points. Both
gaps are tracked in `tests/baseline/bench.json` and analysed in PLAN §12.

CI (`.github/workflows/ci.yml`) runs format, lint, types, the spec-version check,
the corpus build, pytest, and the baseline regression on Linux, plus the live
Windows PID-mode tests on a Windows runner, plus the native Rust format, clippy,
and parity tests (golden vectors, scanner behaviour, and the x64 corpus slice)
on Linux. Recall is tracked per discovery mode (hinted and hint-free).

### Native port

`native/` is a Rust implementation of the spec for x64 and arm64 (`iced-x86`
and `yaxpeax-arm` for decoding). It mirrors the Python reference (decoder,
normalization, recovery, features, scoring, signature document, matcher,
scanner) and adds a binary signature DB:

```bash
cd native
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets
cargo run --release -- gen --file ../corpus/build/x64/O2/loops.elf --addr 0x201250
cargo run --release -- locate --signature fn.yaml --file other.so
cargo run --release -- merge --sample a.elf:0x1000 --sample b.elf:0x2c40 --name fn
cargo run --release -- scan --file image.so --signature fn.yaml
cargo run --release -- scan --file image.so --db signatures.db
cargo run --release -- db build --signature fn.yaml --output signatures.db
cargo run --release --example profile_scan      # scan-cost profile on the x64 corpus
```

Scan cost is measured, not assumed. `native/examples/profile_scan.rs` mirrors
`profile_scan.py --no-live --no-profiler`, and `compare_scan_profile.py` joins
the two JSON profiles to report throughput on the binaries both implementations
scan. On the same six x64 corpus binaries with identical signature sets: full
pass 1503.4 ms vs 39.7 ms (37.8x, 18-49x per binary) and incremental pass
0.52 ms vs 0.11 ms. The live-process workload is still Python-only because the
native port has no PID source yet.

Merging follows the same rules as the Python front-end: `merge --sample` takes
repeated `IMAGE:ADDR` samples, features only some samples carry are demoted to
optional half weight, and a merged signature that cannot be re-found in one of
its own samples is refused (exit `2`) instead of being emitted. On the corpus
pairs both implementations can merge, the YAML is byte-identical.

The native CLI uses the same exit codes as `sigtool` and refuses non-x64 images
with code `3` rather than decoding them with the wrong tables. `db build`
writes the mmap-friendly format described in SPEC §10; the header carries the
spec version, so a DB from another feature spec is refused.

### In IDA

`ida_plugin.py` adds sigtool to IDA (8.4+ / 9.x, Python 3.10+, capstone from
pip): install the package into IDA's Python (`pip install -e .`), then copy
`ida_plugin.py` into the user plugins directory (`%IDAUSR%/plugins`). Actions
appear under Edit > Plugins and on the right-click menus of the disassembly
and Functions views:

* **generate signature here** — quality report (including any
  recovery/IDA-bounds disagreement), save as YAML, then optionally merge
  further samples (an image file or a live Windows PID) into a multi-arch
  signature without leaving IDA.
* **locate signature in this IDB** — scan the database with a saved signature
  and jump to the best match.

Output is byte-identical to the CLI for the same inputs; the plugin is UI
glue only.

## Layout

```
core/       source, arch, normalize, recover, features, score, sigfile, validate, generate, match, merge
sources/    file (ELF, PE), proc_win (read-only live Windows process), ida (IDB)
spec/       signature spec and changelog
corpus/     build script, C samples, ground truth (binaries ignored)
tests/      vectors/ (golden), unit, property, live/ (Windows process tests)
cli.py      front-end: gen, merge, and locate over files and Windows PID mode
ida_plugin.py  IDA front-end (UI glue only)
```
