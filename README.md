# sigtool

Architecture-independent function signatures: sign a function once (from an
image file, a live process, or IDA) and find it again in another build, for
another architecture, compiler, or optimization level, including in stripped
binaries.

Signatures are **feature sets, not byte patterns**: strings, constants
normalized to 32-bit words, portable callee names (imports and exports, with
PLT stubs and veneers resolved), coarse CFG shape, and a bucketed op-class
histogram. One extractor produces features for generation and scanning.
Supported architectures: x86-64, AArch64, ARM32, and Thumb.

Read [`spec/SPEC.md`](spec/SPEC.md) for the signature format,
[`PLAN.md`](PLAN.md) for decisions and measured status, and
[`AGENTS.md`](AGENTS.md) for contribution rules.

## Build

```bash
cd native
cargo build --release        # needs a C toolchain (Capstone builds its bundled C library)
cargo test --release
```

## Use

```bash
sigtool-native gen --file libfoo.so --addr 0x12340 --output fn.yaml
sigtool-native gen --file libfoo.so --rva 0x12340          # RVA from the image base
sigtool-native gen --pid 1234 --module kernel32 --rva 0x1000  # live Windows process, read-only
sigtool-native merge --sample x64/libfoo.so:0x12340 --sample arm64/libfoo.so:+0x10c80 --output fn.yaml
sigtool-native locate --signature fn.yaml --file other/libfoo.so --json matches.json
sigtool-native scan --file image.so --db signatures.db
sigtool-native db build --signature fn.yaml --output signatures.db
```

The YAML signature goes to stdout (or `--output`), the quality report to
stderr (`--json-report` for JSON). Exit codes: `0` success, `1` locate found
nothing, `2` usage or input error, `3` unsupported architecture or target
(including 32-bit and WOW64 processes), `4` self-test failure.

Hint-free discovery uses only what survives `strip --strip-all`: unwind
tables (`.eh_frame`, `.ARM.exidx`, `.pdata`), function starts synthesized from
code evidence where tables are missing (stripped ARM), dynamic symbols,
relocations, and the code itself.

### In IDA

`ida_plugin.py` (IDA 8.4+ / 9.x) is a thin wrapper over `sigtool-native`: put
the binary on `PATH` (or set `SIGTOOL_NATIVE`) and copy the file into
`%IDAUSR%/plugins`. It adds **generate signature here** (report, save, merge
more samples) and **locate signature in this IDB** to Edit > Plugins and the
disassembly and Functions context menus. Addresses cross the boundary as RVAs,
so rebased databases work, and a signature made in IDA is byte-identical to
one made with the CLI.

## Measure

```bash
python corpus/build.py                     # toy corpus (CI gate), LLVM 22
cd native && cargo run --release -- bench --baseline ../tests/baseline/native-bench.json

docker build -t sigtool-gcc-cross corpus/docker
python corpus/real.py                      # zlib, lz4, cJSON, Lua, SQLite; clang + gcc; stripped copies
cd native && cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 \
    --baseline ../tests/baseline/native-real-bench.json
```

Real corpus, top-1 recall (the right function ranked first), 4 functions per
library per build, targets stripped for hint-free scans:

| Search | hinted | hint-free (stripped) |
|---|---|---|
| same arch, same build | 0.671 | 0.810 |
| same arch, other compiler (clang ↔ gcc) | 0.354 | 0.294 |
| same arch, other optimization level | 0.296 | 0.246 |
| other arch, one sample, same level | 0.326 | 0.293 |
| other arch, one sample, other compiler | 0.263 | 0.198 |
| merged x64+arm64 signature, same level | 0.593 | 0.639 |
| merged, held-out arch, same level | 0.454 | 0.371 |

False positives: strong signatures 0.072 against other corpus libraries,
0.000 against the negative corpus; any-verdict hint-free 0.250. Hinted scans
may use the target's symbols. Hint-free scans of stripped targets compare
every unwind entry, while hinted scans start from anchor hits; that is
probably why hint-free is ahead on same-arch searches.

See `PLAN.md` section 13 for how these were reached and what limits them.

## Layout

```
native/        the product: Rust library + sigtool-native CLI
ida_plugin.py  IDA front-end over the CLI
spec/          signature spec and changelog
corpus/        toy and real corpus build scripts (binaries are never committed)
tests/         golden vectors, bench baselines
```
