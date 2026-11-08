# AGENTS.md

Instructions for AI coding agents working on **sigtool**: architecture-independent function signatures, generated from a live process or an IDA function and matched at runtime. Read `PLAN.md` first; it is the source of truth for scope, milestones, and design decisions.

This repo starts from a spec and plan, so commands below are the intended conventions. If a command does not exist yet, create it as part of the task that needs it and update this file.

## Project in one paragraph

Signatures are **feature sets, not byte patterns**: strings, normalized constants, resolved callee names, coarse CFG shape, and a bucketed op-class histogram. One shared extractor produces features for both signature generation and scanning. Supported architectures: x86-64 (reference implementation), AArch64, then ARM32/Thumb. Front-ends (CLI, IDA plugin) are thin and only supply bytes, an address, arch info, and optional names.

## Repo layout

```
core/       ByteSource, arch, normalize, recover, features, score, sigfile, validate, match
sources/    proc_win, proc_linux, file, ida
cli.py      CLI front-end
ida_plugin.py  IDA front-end (UI glue only)
native/     Rust port of the spec (library + `sigtool-native` CLI)
spec/       written signature spec and changelog
corpus/     build scripts and ground-truth maps (binaries are not committed)
tests/      vectors/ (golden), property/, live/
```

## Hard rules (do not break these)

1. **`core/` never imports IDA or OS-specific APIs.** All memory and module access goes through the `ByteSource` interface. IDA and process code live in `sources/` and the front-ends.
2. **One extractor per implementation.** Generation and scanning must call the same feature code. The Rust port under `native/` is a parity-tested port of the reference extractor (golden vectors and corpus results), not a fork that may drift; a change to feature semantics lands in both, or the spec version changes. Never reimplement feature extraction in a front-end.
3. **Determinism.** Same input must produce byte-identical signatures: fixed hash seeds, sorted features, no dict or set ordering leaks, no timestamps or absolute paths in output. Run twice and diff when touching output code.
4. **No absolute addresses in features.** Drop any immediate or displacement that falls inside a mapped module range. Store `module+rva` in provenance only.
5. **Every signature file carries the spec version.** Changing feature semantics, canonicalization, or hashing means bumping the spec version and updating `spec/` and the changelog.
6. **No IR lifting, symbolic execution, or learned models in the scan path.** Capstone in Python and `iced-x86` in the native port, plus per-arch normalization tables only.
7. **Never emit a signature that fails self-test.** Small functions are allowed but get a `confidence: low` tag and rely on neighbor context; they are not refused.
8. **Treat target process memory as untrusted input.** Decoders and recovery must never crash, hang, or read unbounded data on random or truncated bytes. Bound all descent, loops, and reads.
9. **Read-only access to target processes.** The tool never writes to, suspends, or injects into a target.

## Architecture-specific requirements

Normalization must make these cases produce the same feature records across architectures:

- **x86-64:** RIP-relative operands resolve to one address; `movabs` and sign-extended immediates normalize to one constant; multi-byte NOPs, `int3` padding, `mov edi, edi`, and `endbr64` are ignored; jump tables, tail calls, and noreturn calls handled in recovery; `jmp [rip+x]` thunks resolved. 32-bit and WOW64 processes are detected and rejected, never decoded as x64.
- **AArch64:** `adrp`+`add`/`ldr` pairs resolve to one address; `movz`/`movk` chains collapse to one constant; `bti` and pointer-authentication instructions ignored; veneers and `ldr x16`/`br x16` trampolines resolved.
- **ARM32/Thumb:** mode tracked per address (low pointer bit, `bx`/`blx`); `movw`/`movt` collapse to one constant; literal-pool loads resolve to the value and pool data is excluded from code; IT blocks and predication normalized.
- **Endianness:** little-endian first; data anchors indexed in both byte orders.

x86-64 passes golden vectors first and is the reference the other architectures are checked against.

## Conventions

- **Language:** Python 3.10+ for the reference implementation, with type hints on all public functions. Dependencies: `capstone`, `pyyaml`, plus the standard library. Keep dependencies minimal; `core/` must be installable into IDA's bundled Python with `pip`. The native port is Rust (`iced-x86`, `yaxpeax-arm`, `blake2b_simd`, `serde`, `memmap2`, `crc32fast`, `clap`).
- **Style:** Python: format with `ruff format`, lint with `ruff check`, type-check with `mypy` (strict on `core/`). Rust: `cargo fmt --all`, `cargo clippy --all-targets`.
- **Naming:** feature kinds are `str`, `const`, `callee`, `cfg`, `ops`. Arch identifiers: `x64`, `arm64`, `arm32`, `thumb`.
- **Errors:** raise specific exceptions from `core`; front-ends translate them to exit codes and UI messages. The CLI exits non-zero on failed self-test or unsupported target.
- **Hashing:** use the hash function and seeds fixed in `spec/`. Never use Python's built-in `hash()` for anything persisted.
- **Comments:** explain why a normalization rule exists (which compiler or architecture quirk), not what the line does.

## Commands

```
pip install -e .[dev]               # install with dev tools
python -m pytest                    # unit, property, and golden tests
python -m pytest tests/live         # live-process tests (needs a supported host)
python -m ruff format . && python -m ruff check .
python -m mypy core sources         # type check
python tests/vectors/generate.py    # regenerate golden vectors (clang + ld.lld)
python corpus/build.py              # rebuild corpus + ground truth (clang + ld.lld)
python bench.py                     # corpus recall/FP report (M3)
python bench.py --baseline tests/baseline/bench.json  # fail on regression
python bench.py --save-baseline tests/baseline/bench.json  # update baseline, review diff
python profile_scan.py --no-live --no-profiler --json corpus/scan-profile-python.json  # scan cost
sigtool gen --file IMAGE --addr A   # generate a signature from an ELF/PE image
sigtool gen --file IMAGE --module M --rva R  # module+rva addressing
sigtool gen --pid P --addr A        # generate a signature from a live Windows process (read-only)
sigtool merge --sample F1:A1 --sample F2:A2 --name N  # merge samples of one function
sigtool locate --signature S.yaml --file IMAGE  # find a signature in a second image
python -c "from core.generate import generate"  # library use; front-ends call this

cd native
cargo test                          # native parity: golden, scanner, x64 corpus
cargo fmt --all && cargo clippy --all-targets
cargo run --release -- gen --file IMAGE --addr A
cargo run --release -- locate --signature S.yaml --file IMAGE
cargo run --release -- merge --sample IMAGE1:ADDR --sample IMAGE2:ADDR --name N
cargo run --release -- scan --file IMAGE --signature S.yaml
cargo run --release -- scan --file IMAGE --db signatures.db
cargo run --release --example profile_scan  # native scan cost, same corpus workload
python compare_scan_profile.py      # Python vs native throughput, per binary
cargo run --release -- db build --signature S.yaml --output signatures.db
```

`tests/vectors/*.json` and `corpus/build/` are generated, not hand-written.
Regenerate vectors after any normalization or feature change and review the diff;
commit the vectors, never the corpus binaries.

## Testing requirements

- **Golden vectors** (`tests/vectors/`): bytes in, feature records out, per architecture (x64, arm64 with PAC, x64 with CET, arm32, thumb). Never hand-edit; regenerate with `python tests/vectors/generate.py` and review the diff. A vector change must be justified in the PR description. Vectors are generated from real clang + lld output, not hand-written snippets.
- **Property tests:** normalization is idempotent; the same code at two ASLR bases yields identical features; random bytes never crash recovery.
- **Corpus regression:** recall (per discovery mode: hinted and hint-free) and false-positive numbers are compared against `tests/baseline/bench.json` with a 0.05 tolerance (compiler versions move cross-build rates by about 0.02); a drop or an FP increase fails `bench.py --baseline` and CI. `bench.py` scans strong signatures against the negative corpus (`corpus/negative/`) as well as unrelated source files, and both FP rates are gated; merged-pair refusals are reported but never gate (refusing an unmergeable pair is the design working). Update the baseline only for an intentional improvement, with `--save-baseline`, and review the diff. `tests/test_corpus_bounds.py` measures recovered bounds against ELF symbol sizes without a size hint across x64, arm64, arm32, and thumb, and requires at least 0.90 agreement (M1 exit criterion); it also checks ground-truth coverage against the M0 0.95 criterion.
- **Native parity tests** (`native/tests/`): the Rust port must reproduce the Python reference. `golden.rs` replays the x64 and arm64 golden vectors, `scanner.rs` mirrors `tests/test_scanner.py`, `merge.rs` mirrors `tests/test_merge.py`, and `corpus.rs` reproduces the x64 slice of `bench.py` against `tests/baseline/bench.json` with the same 0.05 tolerance. A feature, normalization, scoring, or matching change lands in both implementations and keeps these green; the corpus test skips when `corpus/build/` is absent. ARM32/Thumb are not ported yet, so the native CLI must exit `3` for them rather than decoding with the wrong tables.
- **Spec version check:** `tests/test_spec.py` asserts that `SPEC_VERSION`, `HASH_PERSON`, `spec/SPEC.md`, and `spec/CHANGELOG.md` agree.
- **Live tests:** scripted target processes with known functions, including a hooked function and an injected region. These need a real or QEMU user-mode host for each architecture.
- New normalization rules need a vector from at least one real compiler output, not just a hand-written snippet.

## Workflow for agents

1. Check `PLAN.md` for the current milestone. Do not start work belonging to a later milestone unless asked.
2. Make small, reviewable changes. One normalization rule or one source implementation per change where possible.
3. Run `pytest`, `ruff`, and `mypy` before declaring a task done. If the task touches features or normalization, also run the corpus benchmark and report the recall and false-positive deltas.
4. Update `PLAN.md`, `spec/`, and this file when a decision or convention changes.
5. If a request conflicts with a hard rule above, stop and ask instead of working around it.

## Do not

- Commit binaries from `corpus/` or any sample from a real malware family.
- Add network access, telemetry, or auto-updating to the tool or scanner.
- Hardcode paths, PIDs, or addresses in tests.
- Loosen a match threshold or a test tolerance to make a failing test pass; find the cause instead.
- Add an IDA, Ghidra, or OS-specific import to `core/`.

## Current implementation state

M1 is implemented for x64, AArch64, ARM32, and Thumb: `core/source.py`,
`core/arch.py`, `core/normalize.py`, `core/recover.py`, `core/features.py`,
and `sources/file.py` (ELF and PE). ARM32/Thumb mode is tracked per address
via the ELF Thumb bit; there are no remaining rejected architectures for file
extraction (32-bit x86 is rejected by design, never decoded as x64).

M2 core is implemented: `core/score.py`, `core/sigfile.py`, `core/validate.py`,
and `core/generate.py`. `generate(source, addr)` is the single generation entry
point; front-ends must not recombine scoring and serialisation themselves.

M3 is implemented: `core/match.py` is the reference matcher (anchor needles,
candidate starts, weighted comparison); `generate` self-tests every signature
and raises `SelfTestError` instead of emitting one it cannot re-find.
`scan(..., hints=False)` is the hint-free discovery mode (sweep-only
candidates, recovery without symbol bounds). `bench.py` reports recall per
discovery mode plus both false-positive rates, and compares against
`tests/baseline/bench.json` (`--baseline`, 0.05 tolerance; `--save-baseline`
to update intentionally). `.github/workflows/ci.yml` runs lint, types, the
spec-version check, the corpus build and regression on Linux, plus the live
PID-mode tests on Windows. `cli.py` is the front-end (`gen`, `merge`, and
`locate` over `--file`/`--pid`); it emits YAML on stdout plus a quality
report on stderr. `sources/proc_win.py` is the read-only Windows process
source; Linux PID mode is still pending. The M3 exit criteria are met.

M4 is implemented: `core/normalize.py` extracts ARM32 and Thumb (per-address
mode from the ELF Thumb bit, condition stripping, `it`-block normalization,
`movw`/`movt` and `mvn` materialization, literal pools with pool cells
extending function bounds). `core/merge.py` merges samples of one function
(intersect stable features, demote subset features, mandatory per-sample
self-test) behind `sigtool merge`; `sigtool locate` re-finds a signature in a
second image or process. The bench measures merged recall and FP per target
arch (`merged->arm32`, ...). Cross-arch recall targets and the merged FP
budget are **not met** on the purpose-written corpus; the numbers and causes
are recorded in `PLAN.md` section 12.

M5 is implemented: `sources/ida.py` exposes `IdaSource` over an injectable
`IdaApi` facade (the only IDA-SDK import site; tests inject a fake), with IDA
function bounds as recovery hints and an explicit
`bounds_disagreement` note. `ida_plugin.py` is the thin UI glue: generate
here (report dialog, save, add file/PID sample, merge), and locate in this
IDB. Pinned hosts: IDA 8.4+/9.x, Python 3.10+, capstone from pip. The exit
criterion "output identical to CLI for the same inputs" is test-verified
(`tests/test_ida_source.py`, over golden vectors and corpus binaries); the
dialog and menu glue itself is not exercised by CI because no IDA host runs
there.
See `PLAN.md` section 12.

M6 is implemented: `core/scanner.py` (`SignatureScanner`, `ScanReport`, CRC-32
page hashing, private/changed/untouched region priority), `RecoveryBudget` for
Tier 1, and `ReferenceIndex` for string-anchor discovery with bounded sweeps.
`profile_scan.py` measures full and incremental passes; the measured hot spot
is Capstone decode in the index. See `PLAN.md` section 12.

M7 is implemented for x64 and arm64 in Rust under `native/`: `sigtool-native`
mirrors the reference extractor, matcher, scanner, and signature document, and
adds a binary signature DB (`native/src/db.rs`, SPEC.md §10). Parity is
test-verified against the x64 and arm64 golden vectors, `tests/test_scanner.py`,
and the x64 corpus slice of `tests/baseline/bench.json`; all 51 x64 corpus
signature ids match Python, the arm64 corpus slice produces byte-identical
`gen` YAML, and `merge` reproduces the Python front-end's merged YAML byte for
byte. AArch64 decodes through `yaxpeax-arm` (`native/src/arm64.rs`); ARM32/Thumb
decoding, live-PID sources, and the IDA adapter are not ported yet, and the CLI
exits `3` for those images. Corpus throughput is measured against the Python
scanner on identical workloads: 37.8x faster on the full pass (1503.4 ms vs
39.7 ms over six x64 binaries) and 4.9x on the incremental pass. See `PLAN.md`
section 12.

## Open decisions (ask before assuming)

These are unresolved in `PLAN.md` section 10: whether the first arch pair is x64 plus ARM64, target type (library code vs malware families), eventual scanner host architectures, supported IDA versions, and licensing of signatures and the corpus. The PID-mode OS question is resolved: Windows x64 first (M2), Linux after.
