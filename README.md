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
sigtool-native locate --signature fn.yaml --file stripped.so --explain --expect 0x4f20  # why (not) here
sigtool-native locate --signature fn.yaml --raw text.bin --arch thumb --base 0x8000  # raw code blob
sigtool-native scan --file image.so --db signatures.db
sigtool-native scan --pid 1234 --db signatures.db --module foo  # live process, hint-free per module
sigtool-native scan --path firmware/ --recursive --db signatures.db --jsonl hits.jsonl  # batch
sigtool-native db build --signature fn.yaml --output signatures.db
sigtool-native db build --file libfoo.so --functions names.json --report built.json --output signatures.db
sigtool-native db info signatures.db         # spec version, counts by confidence and arch
sigtool-native db list signatures.db --json  # name, signature id, arches, confidence
```

The YAML signature goes to stdout (or `--output`), the quality report to
stderr (`--json-report` for JSON). Exit codes: `0` success, `1` locate found
nothing, `2` usage or input error, `3` unsupported architecture or target
(including 32-bit and WOW64 processes), `4` self-test failure.

Reports (`gen --json-report`, `merge --json-report`, `db build --report`)
record each input image as `input` (`inputs`, one per sample, for merge): its
`sha256`, `size`, and the ELF GNU `build_id` or the PE `pdb_guid` and
`pdb_age` when the image carries one. `db build --report` also records the
`--functions` list's `sha256` and `size` as `functions_list`. Signatures and
DBs never hold any of this, so they stay byte-identical across copies of an
image. `gen --pid` reports `input: null`.

`scan --path DIR --jsonl OUT` loads the signatures once and scans every
regular file in `DIR` (`--recursive` for subdirectories; symlinks and special
files are skipped, and so is `OUT` itself). It writes one JSON object per
file, sorted by the `/`-separated relative path: `path`, `sha256`, `size`,
`arch`, `discovery`, `status`, `error`, `truncated`, and `hits` as `scan
--json` writes them. `status` is `ok`, `unsupported` (not ELF or PE, or an
unsupported architecture), `error` (unreadable or malformed; a subdirectory
that cannot be listed also gets an `error` line), or `budget-exhausted` (a
scan work budget ran out, listed in `truncated`; never a timeout). Only the
first four bytes of a file decide whether it is an image; a file that is not
is hashed in bounded chunks for its `sha256` and never loaded whole, and an
image larger than 1 GiB is `unsupported` with no `sha256`. A file's
status does not change the exit code: the run exits `0` when every file got a
line, hits or not, and `2` when `DIR`, the signatures, or `OUT` cannot be
used. The output is byte-identical across runs and thread counts.

`scan --pid` and `locate --pid` (Windows) read the process read-only and scan
it one loaded module at a time, hint-free: a process names no local
function, only exports and `.pdata`, so each module is matched as the
stripped file of that module would be, with its own frequencies, trust gates,
rivals, and joint resolution, and the matches carry `module` and `rva`.
`--module NAME` scans one module only, which also bounds the work: every
module's code is decoded and every `.pdata` function recovered.
`--discovery hinted` keeps the older path (`.pdata` bounds as symbol bounds,
candidates from anchor bytes only), which finds little: see `bench
--process-like` below. When two modules both hold an identified-looking
match (a library linked in and also loaded as a DLL), the weaker one is the
first's rival, so the answer is `candidate` unless one copy is clearly closer.

`locate --explain` prints, after the match list, why the matcher accepted or
rejected the best match, or the function at `--expect RVA`: the signature
features it matched, holds only through a small callee (`inl:`), or missed
(`!` marks required ones), the neighbour keys its callers and callees share,
the chance estimate, and each gate in the order the scan applies it (candidate
start, score against the threshold, `min_distinct`, shape or its neighbour
waiver, then the hinted floors or the hint-free similarity, anchoring, chance,
neighbour and evidence gates), with the first that failed as `decided`. For the
first match it also says why the answer is not `identified` (tie, waived
shape gate, rival, answer similarity floor). Under `--json` the same is an
`explain` object. The gates are the matcher's own functions; nothing is
re-derived. Files only (`--file`, `--raw`), not `--pid`.

`--raw FILE --arch x64|arm64|arm32|thumb --base ADDR` (on `gen`, `locate`, and
`scan`) maps a code blob with no container, such as firmware or a dump of one
code region, as one executable region at `ADDR`. It has no symbols,
relocations, or unwind tables, so discovery is hint-free (`--discovery hinted`
is refused), every value inside the blob's range counts as an address
(SPEC.md §2.2, images without a relocation table), and function starts are
synthesized from the code. Data outside the blob (strings in `.rodata`) is not
there to match. Blobs over 1 GiB are refused.

A DB or signature written for another spec version is refused (exit `2`), and
the error says how to rebuild: `db build --file IMAGE --functions F.json`
re-signs a DB's functions from their image, and `gen` or `merge` regenerates
a signature.

Hint-free discovery uses only what survives `strip --strip-all`: unwind
tables (`.eh_frame`, `.ARM.exidx`, `.pdata`), function starts synthesized from
code evidence where tables are missing (stripped ARM), dynamic symbols,
relocations, and the code itself.

ELF files are read as the loader reads them. Packed relocations (lld
`-z pack-relative-relocs`, Android `--pack-dyn-relocs=android`) count like
their unpacked twins. An image without section headers (`llvm-objcopy
--strip-sections`, common in firmware) is read from its program headers:
`PT_LOAD` segments, the `PT_DYNAMIC` tables, and the unwind tables behind
`PT_GNU_EH_FRAME` and `PT_ARM_EXIDX`. Without sections, data that shares an
executable segment with code is swept as code. GNU ld puts `.rodata` there
on ARM and AArch64, so results can differ from the `--strip-all` copy. On
the real corpus the first hint-free match was the same for 453 of 480
signatures: all 300 on lld-linked and x86-64 images, and 153 of 180 on GNU
ld ARM32, Thumb, and AArch64 images (`examples/sectionless.rs`).

### In IDA

`ida_plugin.py` is a thin front-end over `sigtool-native`. It never extracts
features itself: it hands the CLI an image file and module-relative
addresses (RVAs, so rebased databases work) and shows the JSON that comes
back. A signature made in IDA is byte-identical to one made with
`sigtool-native gen --file IMAGE --rva RVA`.

**Not yet run in a real IDA.** No IDA version has run the plugin yet
(`PLAN.md`, M12). It is checked against the IDAPython API sources, by unit
tests over stubbed IDA modules (`tests/test_ida_plugin.py`), and by
`tests/ida_cli_smoke.py`, which runs every action against the real CLI with
a fake IDB. How the dialogs, choosers, menus, and wait box look and behave in
IDA is unverified.

**Install.**

- **IDA 9.0 and later:** use the release's
  `sigtool-ida-plugin-<version>-<platform>.zip`. It is in the HCLI / Plugin
  Manager format and bundles the plugin with its `sigtool-native` binary.
  The manifest (`packaging/ida-plugin.json`) lists 9.x versions only,
  because older IDAs ignore that folder layout.
- **IDA 8.4:** copy `ida_plugin.py` into `%IDAUSR%/plugins` and put
  `sigtool-native` next to it. This flat install should work but has not been
  tested.

The packaged plugin needs IDAPython 3.10 or later; the flat 8.4 install also
runs on Python 3.8. The binary is found through `SIGTOOL_NATIVE`, then
next to the plugin, then on `PATH`; the copy next to the plugin beats `PATH`.
On first use the plugin warns when the binary writes a different signature
spec than it expects.

**Opening it.** Ctrl-Alt-G, or Edit > Plugins > sigtool, opens the action
menu. It has one radio row per action, the signatures DB that apply-names
reads, and **Configure settings**, and it remembers the last action and the
last DB applied or signed. Sign-all and generate on a selection write this
IDB's own DB (`sigtool/<IDB name>.db` beside the IDB, `<IDB name>.selection.db`
for a selection, so two IDBs of same-named inputs keep separate DBs) unless you type another
path into the field, and they ask before replacing a DB that is not this
IDB's own.
The actions also appear in a top-level `sigtool` menu (or under Edit >
Plugins when IDA cannot add one) and on the right-click menus of the
disassembly, pseudocode, and Functions views. In the Functions view they act
on the selected rows.

| Action | What it does |
| --- | --- |
| generate signature | Signs the function under the cursor. By default the signature is copied to the clipboard and saved as `sigtool/<function>.yaml` beside the IDB, and the Output window shows its quality (for example `weak, single-arch`). With several rows selected in the Functions view, signs them into this IDB's `.selection.db` instead. |
| merge with another build | Signs the function together with the same function in other image files, each given as an address or `+RVA`, into one multi-arch signature. |
| locate signature in this IDB | Scans hint-free with the signature on the clipboard, or else a file. The match list shows IDA's current names. The plugin jumps only to an `identified` best match; for a `candidate` or `shape-only` best match it opens the list instead. Right-click a row and pick **explain this row** to see why that row matched. |
| explain the locate result at the cursor | Runs `locate --explain --expect <RVA>` for the function under the cursor (or the cursor itself outside any function) and shows the result in a text view: the deciding gate, each gate's result, the score against the threshold, the reason an answer was withheld, and the matched, inherited, and missed keys (required ones listed separately). |
| sign all named functions to a DB | Signs every function with a meaningful name in one `db build --file IMAGE --functions LIST` run. It skips `sub_*` and other IDA dummy names, thunks, externs, and stubs under five bytes. The summary counts verdicts and confidence levels and lists the functions it skipped. |
| apply names from a DB | Runs `scan --db --discovery hint-free`, which resolves the signatures of one module jointly, then proposes renames in a chooser. `identified` answers start selected, except ones that would replace a user name. `candidate` matches (and `shape-only` ones, if that setting is on) are listed unselected, with Withheld and Matched columns, for review. The plugin skips a name already used elsewhere in the IDB, two signatures claiming one address, and one name claiming two addresses. Each rename adds a comment line `sigtool: NEW (was OLD) from DB (...)`. A later apply replaces sigtool's own earlier names the way it replaces dummy names, but never the analyst's names. The wait box shows the elapsed time, plus the scan phase and progress when the CLI supports `scan --progress`. |
| revert sigtool names | Uses those comment lines to restore the old name of every function that still has the name sigtool gave it. A dummy old name is cleared instead, so IDA regenerates it. A function renamed twice reverts one step per run. |
| show a DB's contents | Lists the DB's signatures (`db list --json`): name, signature id, arches, and confidence, with the `db info` summary as the title. Apply also writes that summary to the Output window before it scans. |

When a scan runs out of a work budget (see [Limitations](#limitations)), the
locate and apply warnings and list titles, and the sign-all summary, say
`incomplete: budgets ran out: ...`. In that case "no match" is not a real
negative. The CLI's own warning lines go to the Output window.

**Settings**, kept in IDA's registry: copy new signatures to the clipboard;
save signatures and DBs in a `sigtool` folder beside the IDB without a
dialog; show the quality report in a dialog; locate the signature on the
clipboard; auto jump to an identified best match; list every match; confirm
renames in a list; also preselect renames that replace user names; also list
shape-only matches for review. All are on by default except the report
dialog and the last two.

**The image the CLI reads.** The IDB is all the plugin needs:

- **The input file**, when it is on disk: the path IDA recorded, or a file
  of the same name beside the IDB (for an IDB copied to another machine or
  folder). A file is used only when its SHA-256 matches the one IDA stored.
  A file found somewhere new is recorded in the IDB.
- **An image rebuilt from the IDB**, otherwise: every byte IDA loaded, with
  patches reverted, back at its file offset. ELF gets a section table made
  from the segments, and PE gets its NT headers from IDA's copy. Signatures
  from a rebuilt image are byte-identical to ones from the stripped file
  (ELF) or from the file itself (PE).

A file dialog asks for the input file only when neither works.

## Measure

```bash
python corpus/build.py                     # toy corpus (CI gate), LLVM 22.1.5
cd native && cargo run --release -- bench --baseline ../tests/baseline/native-bench.json

docker build -t sigtool-gcc-cross corpus/docker
python corpus/real.py                      # zlib, lz4, cJSON, Lua, SQLite; clang + gcc; stripped copies
cd native && cargo run --release -- bench --corpus ../corpus/build-real --max-functions 4 \
    --joint --process-like --baseline ../tests/baseline/native-real-bench.json
cd native && cargo run --release -- bench --corpus ../corpus/build-real --max-functions 24 \
    --sample-seed 7                        # another function sample (milestone exits)
```

`--process-like` scans each stripped target the way `scan --pid` scans a live
process: no symbol starts, only the unwind table's own entries (none of the
starts a file source synthesizes from code), hint-free per module through the
same code as the CLI (`scanner::scan_modules`). Its recall, `identified`
precision, and false-positive rows are reported as discovery `process`, and
the real baseline gates them, so run the gate with the flag. On the real
corpus (spec v6, `--max-functions 4 --joint`), x64 and arm64 targets give
exactly the stripped file's hint-free numbers (top-1 1217 + 1351 of 7044,
the same identified answers and false positives). ARM32 and Thumb targets
lose most of theirs (top-1 869 of 7044, against 2469 for the file): their
`.ARM.exidx` lists few functions on its own, and the file source's
synthesized starts make up the rest. Live processes are x64 and arm64 only,
so that gap is not one a user meets today. Over all targets: top-1 3437 of
14088 = 0.244 (hint-free file 0.358; the hinted scanner path it replaces
0.010), identified precision 2402/2486 = 0.966, strong FP 2/121, any-verdict
FP 93/587 (hint-free file 0/121 and 66/587); every extra error is on an ARM
target (see `PLAN.md` §8).

The text report prints every rate as `k/n = rate [low, high]`, with the 95%
Wilson interval, and each false-positive cell with the number and size of the
images it scanned. A baseline comparison fails a false-positive cell the
baseline measured when the current run scanned no images for it; a cell
neither run measured (the real corpus has no negative set) is not gated. `--max-functions N` keeps the N functions per binary with
the lowest CRC-32 of the name; `--sample-seed S` ranks by CRC-32 of the
seed's eight little-endian bytes followed by the name instead.

The numbers below come from the real-corpus baseline
(`tests/baseline/native-real-bench.json`, spec v6, saved on 2026-11-19 and
recorded in `PLAN.md` §8). The bench ran with `--max-functions 4 --joint` over
the tuning corpus: zlib, lz4, cJSON, Lua, and SQLite, built by clang and gcc at
`-O0/-O2/-Os` for all four architectures. Hint-free scans search the stripped
copies.

Top-1 recall: the expected function is the single best match, and ties count
as misses.

| Search | hinted | hint-free (stripped) |
|---|---|---|
| same arch, same build | 0.688 | 0.838 |
| same arch, other compiler (clang ↔ gcc), same level | 0.425 | 0.427 |
| same arch, other optimization level | 0.362 | 0.368 |
| other arch, one sample, same build settings | 0.386 | 0.446 |
| other arch, one sample, other compiler, same level | 0.323 | 0.302 |
| other arch, one sample, other optimization level | 0.285 | 0.267 |
| merged x64+arm64 signature, same build settings | 0.603 | 0.715 |
| merged, held-out arch (ARM32, Thumb), same build settings | 0.500 | 0.565 |

Whole-module sets (`bench --joint`, hint-free, signatures from one clang-O2
x64 module resolved together through call-graph links): other arch same build
0.808, other arch other compiler 0.634, other arch other optimization level
0.533, same arch other compiler 0.726.

False positives, as the share of signatures with an accepted match in an
unrelated library: strong signatures 0.000 against the other corpus libraries
and 0.000 against the negative corpus; any verdict, hinted 0.083 and
hint-free 0.112. Precision of `identified` answers (correct over all
identified answers, including those in images without the function):
hint-free 0.993, hinted 0.995.

Real-world build profiles (`python corpus/real.py --world`: the tuning
libraries built by gcc 12 as plain, `-O3`, Debian-hardened, LTO, PIE and
static executables, and the previous upstream release), signing the plain
`-O2` shared object, hint-free top-1 on the same arch (80 attempts per row):
same build 0.938, LTO 0.838, previous release 0.838, hardened 0.812, `-O3`
0.787, PIE executable 0.700, static executable 0.613. Identified precision
there is 0.988 hint-free and 0.997 hinted.

Needle in a host (`python corpus/real.py --host`: all five tuning libraries
linked by gcc 12 `-O2` into one static executable per arch with
`--gc-sections`, 1.1-1.9 MB of code), signing the plain `-O2` shared object,
hint-free top-1 on the same arch: 0.642 into the host (x64 0.708, arm64
0.767, arm32 0.551, Thumb 0.540; 692 attempts per arch) and 0.487 into an
LTO host, against 0.905 for the same build. On hosts linking every library
but the signature's own, signatures from the shared objects get 0.18 (x64)
to 0.94 (Thumb) accepted hits per signature per MB of code, and identified
answers in unrelated images come to 0.0025 per signature per MB (goal
0.001). A hint-free scan of 1000 signatures over the x64 `-O0` host
(2.4 MB of code) takes 10.9 s on 2 threads at 167 MB peak memory, and no
budget runs out at these sizes (`examples/profile_scale.rs`).
PE DLLs (`python corpus/real.py --pe`: the tuning libraries built by clang
and lld-link for x64 and arm64 Windows, `-O0/-O2/-Os` plus `/GS` and
`/guard:cf`, exporting only the public API), hint-free top-1: same arch same
build 0.725 (200 attempts), other arch same build 0.415; strong FP 0.000.
Signing a clang ELF build and searching the PE build of the same level
(`corpus/build-pe-mixed`): 0.533 on the same arch, against 0.833 ELF to
ELF and 0.733 PE to ELF (120 attempts each). `PLAN.md` §8 lists what
causes the gap.

Hinted scans may use the target's symbols. Hint-free scans of stripped
targets compare every unwind entry, while hinted scans start from anchor
hits; that is probably why hint-free is ahead on same-build searches.

The held-out corpus (zstd, libyaml, mbedtls; never used for tuning), measured
once at spec v6 on 2026-11-19, hint-free top-1: same build 0.962, other
compiler 0.618, other arch 0.646, other arch other compiler 0.520; FP strong
0.000, any verdict 0.078, hint-free 0.126; identified precision 0.991.

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
