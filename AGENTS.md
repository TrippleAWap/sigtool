# AGENTS.md

Instructions for AI coding agents working on **sigtool**: architecture-independent function signatures, generated from an image file, a live process, or an IDA function, and matched at runtime. The product is the Rust crate under `native/` (library plus the `sigtool-native` CLI). Read `PLAN.md` for scope, decisions, and measured status, and `spec/SPEC.md` for the signature format.

The goal everything is measured against: **find a function across architectures, compilers, and optimization levels, including in stripped binaries without symbol hints (hint-free mode).** Rules, weights, and normalizations may change when the corpus numbers say so; the spec version and changelog record each change.

## Project in one paragraph

Signatures are **feature sets, not byte patterns**: strings, normalized constants, portable callee names, coarse CFG shape, and a bucketed op-class histogram. One shared extractor produces features for both signature generation and scanning. Supported architectures: x86-64, AArch64, ARM32, and Thumb. Front-ends (CLI, IDA plugin) are thin and only supply bytes, an address, and arch info; the IDA plugin shells out to `sigtool-native`.

## Repo layout

```
native/        Rust crate: sources (elf.rs: ELF/PE files, proc_win.rs: live Windows
               processes), arch decoders, normalize, recover, features, score,
               sigfile, validate, matcher, merge, scanner, db, bench, CLI (main.rs)
ida_plugin.py  IDA front-end: UI glue over the sigtool-native CLI
spec/          signature spec and changelog
corpus/        build scripts (build.py: toy corpus; real.py: pinned real libraries
               with clang and gcc), ground truth; binaries are never committed
tests/         vectors/ (golden, generated), baseline/ (bench baselines)
```

The Python reference implementation (`core/`, `sources/`, `cli.py`, `bench.py`) was a prototype and has been removed; Python remains only for build scripts and the IDA plugin.

## Hard rules (do not break these)

1. **The library never depends on IDA or on OS APIs outside a source module.** All memory and module access goes through the `ByteSource` trait (`native/src/source.rs`). OS-specific code lives in source modules (`proc_win.rs`) behind `cfg`, and must compile to a stub elsewhere.
2. **One extractor.** Generation and scanning call the same feature code, and a front-end never reimplements feature extraction.
3. **Determinism.** Same input must produce byte-identical signatures: fixed hash seeds, sorted features, no map ordering leaks, no timestamps or absolute paths in output. Run twice and diff when touching output code.
4. **No absolute addresses in features.** Drop any immediate or displacement that falls inside a mapped module range. Store `module+rva` (relative to the image base) in provenance only.
5. **Every signature file carries the spec version.** Changing feature semantics, canonicalization, or hashing means bumping `SPEC_VERSION` (`native/src/spec.rs`) and updating `spec/SPEC.md` and `spec/CHANGELOG.md`.
6. **No IR lifting, symbolic execution, or learned models in the scan path.** Decoders are chosen per architecture on merit (`iced-x86` for x64, `yaxpeax-arm` for AArch64, Capstone for ARM32/Thumb), plus per-arch normalization tables.
7. **Never emit a signature that fails self-test.** Small functions get `confidence: low` and are not refused.
8. **Treat target bytes as untrusted input.** Decoders, recovery, start synthesis, and parsers must never crash, hang, or read unbounded data on random or truncated bytes. Bound all descent, loops, and reads.
9. **Read-only access to target processes.** Open with query and VM-read rights only; never write to, suspend, or inject into a target. 32-bit and WOW64 processes are rejected, never decoded as x64.
10. **Hint-free means hint-free.** In hint-free mode the matcher may use only what survives `strip --strip-all`: unwind tables (`.eh_frame`, `.ARM.exidx`, `.pdata`), dynamic symbols and imports, relocations, and code evidence. Never read `.symtab` names or bounds of the binary being searched; the bench scans the stripped copy to enforce this.

## Architecture-specific requirements

Normalization must make these cases produce the same feature records across architectures:

- **x86-64:** RIP-relative operands resolve to one address; constants become 32-bit words (sign-extended 32-bit values are their low word, 64-bit values split into words); multi-byte NOPs, `int3` padding, `mov edi, edi`, and `endbr64` are ignored; jump tables, tail calls, and noreturn calls handled in recovery; `jmp [rip+x]` thunks and PLT stubs resolve to the import they load.
- **AArch64:** `adrp`+`add`/`ldr` pairs resolve to one address; `movz`/`movk` chains collapse to words even when other instructions are scheduled between them; `bti` and pointer-authentication instructions ignored; PLT entries, veneers, and `x16`/`x17` trampolines resolved.
- **ARM32/Thumb:** mode tracked per address (ELF Thumb bit, or the mode map for stripped images); `movw`/`movt` collapse to one constant; literal-pool loads resolve to the value and pool data is excluded from code; PIC `add rd, pc` and `ldr rd, [pc, rm]` resolve to the address; IT blocks and predication normalized; EABI arithmetic helpers dropped.
- **Callees:** only names a stripped copy keeps are required (imports, `.dynsym` exports); `.symtab`-only names are optional; calls into other images are low-information (`*!name`).
- **Endianness:** little-endian first; data anchors indexed in both byte orders.

## Conventions

- **Rust:** `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`. Dependencies: `iced-x86`, `yaxpeax-arm`, `capstone`, `blake2b_simd`, `serde`, `serde_json`, `memmap2`, `crc32fast`, `clap`; Capstone builds its bundled C library, so a C toolchain is required. Windows APIs are declared with `extern "system"` FFI, not a crate.
- **Python (tooling only):** `ruff format` and `ruff check` over `corpus/`, `tests/vectors/`, and `ida_plugin.py`.
- **Naming:** feature kinds are `str`, `const`, `callee`, `cfg`, `ops`. Arch identifiers: `x64`, `arm64`, `arm32`, `thumb`.
- **Errors:** specific error types in the library; the CLI translates them to exit codes (`0` ok, `1` locate found nothing, `2` usage/input, `3` unsupported architecture or target, `4` self-test failure).
- **Hashing:** the hash function and personalization fixed in `spec/`.
- **Comments:** explain why a rule exists (which compiler or architecture quirk), not what the line does.

## Commands

```
cd native
cargo fmt --all && cargo clippy --all-targets -- -D warnings
cargo test --release                # golden, scanner, merge, CLI addressing, toy corpus, live PID (Windows)
cargo run --release -- gen --file IMAGE --addr A          # or --rva R (from the image base), --module M
cargo run --release -- gen --pid P --addr A               # or --module M --rva R; live Windows process, read-only
cargo run --release -- locate --signature S.yaml --file IMAGE --json M.json   # or --pid P
cargo run --release -- scan --file IMAGE --signature S.yaml   # or --db signatures.db, --pid P
cargo run --release -- merge --sample IMAGE1:ADDR --sample IMAGE2:+RVA --name N
cargo run --release -- db build --signature S.yaml --output signatures.db
cargo run --release -- bench --baseline ../tests/baseline/native-bench.json       # toy corpus gate
cargo run --release -- bench --save-baseline ../tests/baseline/native-bench.json  # intentional improvement
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 \
    --baseline ../tests/baseline/native-real-bench.json   # real corpus (stripped targets, both modes)
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 --discovery hint-free \
    --arch x64 --arch arm64 --no-fp                         # quick hint-free slice
cargo run --release --example profile_scan                  # scan cost

python corpus/build.py              # toy corpus + ground truth (clang + ld.lld + llvm-readelf)
python corpus/real.py               # real libraries: clang on the host, gcc via corpus/docker
python tests/vectors/generate.py    # regenerate golden vectors (clang + ld.lld), then bless
SIGTOOL_BLESS=1 cargo test --test golden   # rewrite expected records from the extractor
```

`tests/vectors/*.json`, `corpus/build/`, and `corpus/build-real/` are generated, not hand-written. Regenerate vectors after any normalization or feature change and review the diff; commit the vectors, never the corpus binaries.

## Testing requirements

- **Golden vectors** (`tests/vectors/`): bytes in, feature records out, for x64, x64 with CET, arm64, arm64 with PAC, arm32, and thumb at `-O0/-O2/-Os`, from real clang + lld output. Never hand-edit; regenerate and bless, and justify every record change in the commit or PR.
- **Toy corpus gate** (`native/tests/corpus.rs`, `bench --baseline tests/baseline/native-bench.json`): recall per discovery mode and false-positive rates against the baseline with a 0.05 tolerance. The baseline is compiler-specific (currently clang/LLVM 22; CI pins it), because compiler versions move small cells by more than the tolerance. Update the baseline only for an intentional improvement or a compiler change, with `--save-baseline`, and review the diff.
- **Real corpus** (`corpus/build-real`, `tests/baseline/native-real-bench.json`): zlib, lz4, cJSON, Lua, and SQLite built with clang and gcc at `-O0/-O2/-Os` for all four architectures. This is the corpus the cross-arch and hint-free numbers are read from; run it before and after any matcher, feature, or normalization change and report the deltas. It is not in CI (it needs the gcc cross image).
- **Property and robustness:** normalization is idempotent; the same code at two bases yields identical features; random bytes never crash recovery or start synthesis.
- **Live tests** (`native/tests/live_proc_win.rs`, Windows): a spawned helper process with a known function; checks read-only access, WOW64 rejection, and that `gen`/`locate`/`scan --pid` find it.
- New normalization rules need a vector or corpus case from real compiler output, not just a hand-written snippet.

## Workflow for agents

1. Check `PLAN.md` section 12 for current status and open work.
2. Make small, reviewable changes: one normalization rule, one source, or one matcher rule per change where possible.
3. Before declaring a task done, in `native/`: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test --release`, and the toy bench gate. If the task touches features, normalization, discovery, or matching, also run the real corpus and report recall and false-positive deltas per discovery mode.
4. Update `PLAN.md`, `spec/`, and this file when a decision or convention changes.
5. If a request conflicts with a hard rule above, stop and ask instead of working around it.

## Do not

- Commit binaries from `corpus/` or any sample from a real malware family.
- Add network access, telemetry, or auto-updating to the tool or scanner.
- Hardcode paths, PIDs, or addresses in tests.
- Loosen a match threshold or a test tolerance to make a failing test pass; find the cause instead.
- Let hint-free discovery read `.symtab` of the searched binary.
