# AGENTS.md

Instructions for AI coding agents working on **sigtool**: architecture-independent function signatures, generated from an image file, a live process, or an IDA function, and matched at runtime. The product is the Rust crate under `native/` (library plus the `sigtool-native` CLI). Read `PLAN.md` for the mission, v1.0 goals, project rules, and milestones, and `spec/SPEC.md` for the signature format. `docs/history/PLAN-v0.5.md` has the earlier milestones and how each number was reached.

The goal everything is measured against: **find a function across architectures, compilers, and optimization levels, including in stripped binaries without symbol hints (hint-free mode).** Rules, weights, and normalizations may change when the corpus numbers say so; the spec version and changelog record each change.

## Project in one paragraph

Signatures are **feature sets, not byte patterns**: strings, normalized constants, portable callee names, coarse CFG shape, and a bucketed op-class histogram, plus the strings and constants of the function's call-graph neighbours for small functions with no evidence of their own. Candidates also carry their small direct callees' evidence as inherited `inl:` keys, credited at half weight, so inlining a helper does not move a match (signatures sign own features only). One shared extractor produces features for both signature generation and scanning. Supported architectures: x86-64, AArch64, ARM32, and Thumb. Front-ends (CLI, IDA plugin) are thin and only supply bytes, an address, and arch info; the IDA plugin shells out to `sigtool-native`.

## Repo layout

```
native/        Rust crate: sources (elf.rs: ELF/PE files, proc_win.rs: live Windows
               processes), arch decoders, normalize, recover, features, score,
               sigfile, validate, matcher, merge, scanner, db, bench, CLI (main.rs);
               native/fuzz/ is a separate cargo-fuzz crate (nightly only)
ida_plugin.py  IDA front-end: UI glue over the sigtool-native CLI
packaging/     ida-plugin.json (HCLI / Plugin Manager manifest) and package.py, which
               builds the per-platform plugin zip and CLI archive for a release
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
4. **No absolute addresses in features.** Drop a value the code uses as an address: a PC-relative or absolute memory reference, or, in an image that can be loaded anywhere (ELF shared object or PIE), a word a dynamic relocation writes. Keep every other value as a normalized constant, even inside the module span (a shared object maps at 0); images without a relocation table keep the module-range test (`spec/SPEC.md` §2.2). The same code at two bases must yield identical features. Store `module+rva` (relative to the image base) in provenance only. (Relaxed from "drop anything inside the module range" by the user on 2026-11-17.)
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

- **Rust:** `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`. Dependencies: `iced-x86`, `yaxpeax-arm`, `capstone`, `blake2b_simd`, `serde`, `serde_json`, `serde_norway` (YAML; the maintained fork of the deprecated `serde_yaml`), `memmap2`, `crc32fast`, `clap`; Capstone builds its bundled C library, so a C toolchain is required. Windows APIs are declared with `extern "system"` FFI, not a crate. `libfuzzer-sys` is a dependency of the separate `native/fuzz` crate only, never of the library.
- **Python (tooling only):** `ruff format` and `ruff check` over `corpus/`, `packaging/`, `tests/vectors/`, `tests/test_ida_plugin.py`, `tests/ida_cli_smoke.py`, and `ida_plugin.py`; `python -m unittest tests/test_ida_plugin.py` tests the plugin's IDA-free parts with stubbed IDA modules. `python tests/ida_cli_smoke.py --corpus corpus/build-real` (after `cargo build --release`) runs the plugin's generate, merge, locate, sign-all, and apply-names actions end to end against the real CLI, with fake IDA modules modelling the IDB from `ground_truth.json` (sign clang-O2 x64 zlib, apply to stripped gcc-O2 by default; `--arch`, `--library`, `--sign`, `--apply` pick others). It checks the plugin-to-CLI contract, not IDA's UI or API; run the plugin in a licensed IDA before calling a plugin change done.
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
cargo run --release -- locate --signature S.yaml --file IMAGE --json M.json   # or --pid P; --discovery auto|hinted|hint-free
cargo run --release -- scan --file IMAGE --signature S.yaml   # or --db signatures.db, --pid P
cargo run --release -- merge --sample IMAGE1:ADDR --sample IMAGE2:+RVA --name N
cargo run --release -- db build --signature S.yaml --output signatures.db
cargo run --release -- db build --file IMAGE --functions F.json --report R.json --output signatures.db
                                    # sign a [{"rva", "name"}] list in one run (the IDA plugin's sign-all)
cargo run --release -- bench --baseline ../tests/baseline/native-bench.json       # toy corpus gate
cargo run --release -- bench --save-baseline ../tests/baseline/native-bench.json  # intentional improvement
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 --joint \
    --baseline ../tests/baseline/native-real-bench.json   # real corpus (stripped targets, both modes, joint sets)
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 --discovery hint-free \
    --fp-report fp.jsonl                                  # log FP hits and recall scans for offline simulation
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 --discovery hint-free \
    --arch x64 --arch arm64 --no-fp                         # quick hint-free slice
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 24 --sample-seed N \
    --joint                                                 # fresh function sample (milestone exits)
cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 --joint --discovery hint-free \
    --no-fp --joint-report joint.jsonl                    # log joint cells (pairs, call graph) for offline simulation
cargo run --release --example profile_scan                  # scan cost
cargo run --release --example profile_gen -- IMAGE ADDR [TARGET]   # gen / hint-free phase timings
cargo run --release --example profile_g5 -- gen IMAGE SIGS.db [COUNT]   # then: scan STRIPPED SIGS.db (G5 cost)
cargo run --release --example cross_fp -- ../corpus/build-real 4 [HITS.jsonl]   # cross-ISA false hits
                                    # (bench FP scans are same-arch only); run for any cross-ISA matcher rule
cargo run --release --example in_module_consts -- ../corpus/build-real   # in-range constants kept per arch
SIGTOOL_THREADS=1 cargo run --release -- bench ...          # one thread (determinism checks)
SIGTOOL_REQUIRE_TOOLS=1 cargo test --release   # fail, not skip, tests whose LLVM tools are missing (CI)
cargo test --release --test hostile_inputs      # deterministic hostile images, signatures, DBs, raw code
SIGTOOL_FUZZ_SEEDS=fuzz/corpus cargo test --release --test hostile_inputs write_fuzz_seeds   # seed corpora
cargo +nightly fuzz run image -- -max_total_time=60 -timeout=10   # targets: image, signature, db, code
                                    # (cargo install cargo-fuzz; crashes land in fuzz/artifacts/TARGET/)
cargo +nightly fuzz run image fuzz/artifacts/image/crash-...      # replay one crash

python packaging/package.py --platform windows-x86_64 --binary native/target/release/sigtool-native.exe \
    --out dist                      # plugin zip + CLI archive for one platform (release.yml runs it per target)
python corpus/build.py              # toy corpus + ground truth (clang + ld.lld + llvm-readelf)
python corpus/real.py               # real libraries: clang on the host, gcc via corpus/docker
python corpus/real.py --heldout     # held-out libraries into corpus/build-heldout (milestone exits only)
python corpus/real.py --world       # real-world profiles (hardened, -O3, LTO, PIE, static, previous release)
                                    # into corpus/build-world; bench it with --corpus ../corpus/build-world
python tests/vectors/generate.py    # regenerate golden vectors (clang + ld.lld), then bless
SIGTOOL_BLESS=1 cargo test --test golden   # rewrite expected records from the extractor
```

`tests/vectors/*.json`, `corpus/build/`, and `corpus/build-real/` are generated, not hand-written. Regenerate vectors after any normalization or feature change and review the diff; commit the vectors, never the corpus binaries.

## Testing requirements

- **Golden vectors** (`tests/vectors/`): bytes in, feature records out, for x64, x64 with CET, arm64, arm64 with PAC, arm32, and thumb at `-O0/-O2/-Os`, plus `-fPIC -shared` objects (`*-pic-*`, with their relocation slots) for all four architectures, from real clang + lld output. `golden.rs` loads each PIC vector at two bases and requires identical features. Never hand-edit; regenerate and bless, and justify every record change in the commit or PR.
- **Toy corpus gate** (`native/tests/corpus.rs`, `bench --baseline tests/baseline/native-bench.json`): recall per discovery mode and false-positive rates against the baseline with a 0.05 tolerance. The baseline is compiler-specific (currently LLVM 22.1.5, which CI installs from the pinned release archive), because even patch releases move small cells by more than the tolerance. Update the baseline only for an intentional improvement or a compiler change, with `--save-baseline`, and review the diff.
- **Real corpus** (`corpus/build-real`, `tests/baseline/native-real-bench.json`): zlib, lz4, cJSON, Lua, and SQLite built with clang and gcc at `-O0/-O2/-Os` for all four architectures. This is the corpus the cross-arch and hint-free numbers are read from; run it before and after any matcher, feature, or normalization change and report the deltas. It is not in the per-push CI (it needs the gcc cross image); `.github/workflows/real-bench.yml` builds it and runs the `--joint` bench against the baseline weekly.
- **Held-out corpus** (`corpus/build-heldout`, `real.py --heldout`): zstd, libyaml, and mbedtls, same matrix. Never tune on it or read it while choosing a rule; run it only at milestone exits and record the numbers in `PLAN.md` §8.
- **Property and robustness:** normalization is idempotent; the same code at two bases yields identical features (`relocatable_vectors_give_identical_features_at_two_bases`); random bytes never crash recovery or start synthesis. `native/tests/hostile_inputs.rs` (stable, fixed seeds, no new dependencies) builds minimal ELF64 x86-64/AArch64, ELF32 ARM, and PE32+ images, a signature, and a DB, sets every recorded header field to edge values, corrupts and truncates them, and feeds golden-vector code to recovery; nothing may panic. The cargo-fuzz targets in `native/fuzz` (`image`, `signature`, `db`, `code`) call the same drivers (`native/tests/hostile/mod.rs`), and the `fuzz` CI job runs each for 60 s on every push.
- **Live tests** (`native/tests/live_proc_win.rs`, Windows): a spawned helper process with a known function; checks read-only access, WOW64 rejection, and that `gen`/`locate`/`scan --pid` find it.
- New normalization rules need a vector or corpus case from real compiler output, not just a hand-written snippet.

## Workflow for agents

1. Check `PLAN.md` §6 (milestones) and §8 (status) for open work, and follow the rules in `PLAN.md` §4: measure on the real corpus, simulate before building, never tune on the held-out corpus, precision before recall.
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
