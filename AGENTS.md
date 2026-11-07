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
spec/       written signature spec and changelog
corpus/     build scripts and ground-truth maps (binaries are not committed)
tests/      vectors/ (golden), property/, live/
```

## Hard rules (do not break these)

1. **`core/` never imports IDA or OS-specific APIs.** All memory and module access goes through the `ByteSource` interface. IDA and process code live in `sources/` and the front-ends.
2. **One extractor.** Generation and scanning must call the same feature code. Never fork or reimplement feature extraction for a front-end.
3. **Determinism.** Same input must produce byte-identical signatures: fixed hash seeds, sorted features, no dict or set ordering leaks, no timestamps or absolute paths in output. Run twice and diff when touching output code.
4. **No absolute addresses in features.** Drop any immediate or displacement that falls inside a mapped module range. Store `module+rva` in provenance only.
5. **Every signature file carries the spec version.** Changing feature semantics, canonicalization, or hashing means bumping the spec version and updating `spec/` and the changelog.
6. **No IR lifting, symbolic execution, or learned models in the scan path.** Capstone plus per-arch normalization tables only.
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

- **Language:** Python 3.10+ for v1, with type hints on all public functions. Dependencies: `capstone`, `pyyaml`, plus the standard library. Keep dependencies minimal; `core/` must be installable into IDA's bundled Python with `pip`.
- **Style:** format with `ruff format`, lint with `ruff check`, type-check with `mypy` (strict on `core/`).
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
python -m sigtool.bench             # corpus recall/FP report (M3)
sigtool gen --pid P --addr A        # generate a signature from a live process (M2)
```

`tests/vectors/*.json` and `corpus/build/` are generated, not hand-written.
Regenerate vectors after any normalization or feature change and review the diff;
commit the vectors, never the corpus binaries.

## Testing requirements

- **Golden vectors** (`tests/vectors/`): bytes in, feature records out, per architecture. Never hand-edit; regenerate with `python tests/vectors/generate.py` and review the diff. A vector change must be justified in the PR description. Vectors are generated from real clang + lld output (x64 and arm64 at -O0/-O2/-Os, plus CET and PAC variants), not hand-written snippets.
- **Property tests:** normalization is idempotent; the same code at two ASLR bases yields identical features; random bytes never crash recovery.
- **Corpus regression:** recall and false-positive numbers are compared against the committed baseline. A drop beyond tolerance fails CI. `tests/test_corpus_bounds.py` measures recovered bounds against ELF symbol sizes without a size hint, and requires at least 0.90 agreement (M1 exit criterion).
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

M1 is implemented for x64 and AArch64: `core/source.py`, `core/arch.py`,
`core/normalize.py`, `core/recover.py`, `core/features.py`, and
`sources/file.py` (ELF and PE). ARM32/Thumb are detected but rejected with
`UnsupportedArchError` until M4. Score, sigfile, validate, match, the CLI, and
process sources are M2/M3 work and do not exist yet. See `PLAN.md` section 12.

## Open decisions (ask before assuming)

These are unresolved in `PLAN.md` section 10: which OS to support first for PID mode, whether the first arch pair is x64 plus ARM64, target type (library code vs malware families), eventual scanner host architectures, supported IDA versions, and licensing of signatures and the corpus.
