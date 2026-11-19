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
sigtool-native locate --signature fn.yaml --file stripped.so --discovery hint-free  # default auto
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

`ida_plugin.py` (IDA 8.4+ / 9.x) is a thin wrapper over `sigtool-native`: copy
the file into `%IDAUSR%/plugins` with the binary next to it (or put the binary
on `PATH`, or set `SIGTOOL_NATIVE`; the copy next to the plugin wins over
`PATH`). It adds **generate signature here** (report, save, merge
more samples) and **locate signature in this IDB** to Edit > Plugins and the
disassembly and Functions context menus. Addresses cross the boundary as RVAs,
so rebased databases work, and a signature made in IDA is byte-identical to
one made with the CLI.

## Measure

```bash
python corpus/build.py                     # toy corpus (CI gate), LLVM 22.1.5
cd native && cargo run --release -- bench --baseline ../tests/baseline/native-bench.json

docker build -t sigtool-gcc-cross corpus/docker
python corpus/real.py                      # zlib, lz4, cJSON, Lua, SQLite; clang + gcc; stripped copies
cd native && cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 \
    --baseline ../tests/baseline/native-real-bench.json
```

The numbers below come from the real-corpus baseline
(`tests/baseline/native-real-bench.json`, spec v5, saved in commit `0e28cbf`
on 2026-11-17 and recorded in `PLAN.md` §8 on 2026-11-18). The bench ran with
`--max-functions 4 --joint` over the tuning corpus: zlib, lz4, cJSON, Lua, and
SQLite, built by clang and gcc at `-O0/-O2/-Os` for all four architectures.
Hint-free scans search the stripped copies.

Top-1 recall: the expected function is the single best match, and ties count
as misses.

| Search | hinted | hint-free (stripped) |
|---|---|---|
| same arch, same build | 0.690 | 0.835 |
| same arch, other compiler (clang ↔ gcc), same level | 0.406 | 0.412 |
| same arch, other optimization level | 0.357 | 0.365 |
| other arch, one sample, same build settings | 0.374 | 0.433 |
| other arch, one sample, other compiler, same level | 0.307 | 0.287 |
| other arch, one sample, other optimization level | 0.270 | 0.259 |
| merged x64+arm64 signature, same build settings | 0.595 | 0.711 |
| merged, held-out arch (ARM32, Thumb), same build settings | 0.490 | 0.558 |

Whole-module sets (`bench --joint`, hint-free, signatures from one clang-O2
x64 module resolved together through call-graph links): other arch same build
0.810, other arch other compiler 0.630, other arch other optimization level
0.531, same arch other compiler 0.714.

False positives, as the share of signatures with an accepted match in an
unrelated library: strong signatures 0.000 against the other corpus libraries
and 0.000 against the negative corpus; any verdict, hinted 0.075 and
hint-free 0.115. Precision of `identified` answers (correct over all
identified answers, including those in images without the function):
hint-free 0.993, hinted 0.994.

Hinted scans may use the target's symbols. Hint-free scans of stripped
targets compare every unwind entry, while hinted scans start from anchor
hits; that is probably why hint-free is ahead on same-build searches.

The held-out corpus (zstd, libyaml, mbedtls; never used for tuning) was last
measured at spec v4 on 2026-11-16, before the in-module constant, FP
reduction, and strong FP rules: hint-free same build 0.896, other compiler
0.368, other arch 0.414; FP strong 0.113, any verdict 0.080, hint-free
0.054.

See `PLAN.md` §8 for how each number moved, `docs/history/PLAN-v0.5.md`
section 13 for the earlier history, and `PLAN.md` for the v1.0 goals and the
milestones toward them.

## Limitations

- **Input formats:** ELF and PE images only. Mach-O files are rejected. The
  release builds a macOS binary (macos-aarch64) beside Linux and Windows
  (x86-64 and AArch64), but it still reads only ELF and PE files.
- **Architectures:** x86-64, AArch64, ARM32, and Thumb. No 32-bit x86;
  32-bit and WOW64 processes are rejected.
- **Live processes:** Windows only. There is no Linux `/proc` source yet.
- **Corpora are C only.** Tuning: zlib, lz4, cJSON, Lua, SQLite. Held-out:
  zstd, libyaml, mbedtls. C++ templates, vtables, and duplicated template
  instantiations are untested.
- **Image size:** the largest tuning-corpus image is arm64 gcc-O0 SQLite,
  about 1.3 MB; held-out zstd at `-O0` reaches about 2.1 MB. Scans have
  fixed budgets: 4M indexed instructions (and 4M decoded for hint-free
  discovery), 65,536 unwind candidates, and a 128 MiB start-sweep byte
  budget. Larger images can run out of one; when that happens the CLI prints
  a warning on stderr and lists the budget in the `truncated` field of its
  JSON output (`locate --json`, `scan --json`, `gen`/`merge --json-report`,
  `db build --report`).
- **Held-out false positives** were last measured at spec v4 (2026-11-16:
  strong FP 0.113) and predate the later rule changes.
- **IDA plugin:** tested only against stubbed IDA modules
  (`tests/test_ida_plugin.py`, `tests/ida_cli_smoke.py`), not in a licensed
  IDA. Its dialogs, choosers, and menus are unexercised.

## Layout

```
native/        the product: Rust library + sigtool-native CLI
ida_plugin.py  IDA front-end over the CLI
spec/          signature spec and changelog
corpus/        toy and real corpus build scripts (binaries are never committed)
tests/         golden vectors, bench baselines
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option. Release archives include both
files.
