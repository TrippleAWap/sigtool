# Cross-Architecture Code Signatures: Project Plan

*Working name: sigtool. Plan version 0.4.*

## 1. Goal and scope

Build a system that generates architecture-independent signatures for functions and scans for them at runtime.

**Deliverables**

1. A **core library** that decodes, normalizes, extracts features, scores, and writes signatures.
2. A **CLI** that takes a PID and an address and emits a signature plus a quality report.
3. An **IDA plugin** that does the same from a selected function.
4. A **signature spec** (versioned, tool-neutral) and a **reference runtime matcher**.
5. A **regression corpus** and test harness that measure recall and false positives per release.

**Non-goals for v1**

- IR lifting, symbolic execution, or learned embeddings in any hot path.
- Arbitrary function matching between unrelated binaries (v1 targets known library or family code).
- Guaranteed recall on small functions. They are signed with a low-confidence tag and matched using neighbor context (section 4).
- A production-speed scanner. v1 ships a Python reference matcher; the fast scanner is a later phase.

## 2. Key design decisions (locked)

| Decision | Choice | Reason |
|---|---|---|
| Matching basis | Features, not bytes | Bytes are architecture specific |
| Extractor | One shared extractor for generation and scanning | Avoids train/serve skew |
| Decoder | Capstone (x86-64, ARM32, Thumb, AArch64) plus small normalization tables | No lifter dependency, cheap, stable |
| Core language | Python for v1 | Runs inside IDAPython and the CLI unchanged |
| Fuzzy tier | Weighted feature match against anchor-shortlisted candidates; MinHash/LSH optional | Complexity vs speed balance |
| Signature format | Human-readable source form (YAML) compiled to a binary DB | Diffable and reviewable |
| Determinism | Fixed hash seeds, sorted features, versioned spec | Reproducible signatures |
| Tool coupling | Front-ends only supply bytes, address, arch, optional names | Signatures survive tool changes |

## 3. Architecture

```
core
 ├─ source.py     ByteSource interface
 ├─ arch.py       arch/mode detection, Capstone setup
 ├─ normalize.py  per-arch constant and pointer normalization
 ├─ recover.py    bounded recursive descent, function bounds
 ├─ features.py   strings, callees, consts, CFG counts, op-class histogram
 ├─ score.py      IDF weights, anchor selection, thresholds
 ├─ sigfile.py    YAML <-> canonical bytes, spec versioning
 ├─ validate.py   self-test, FP scan, quality report
 └─ match.py      reference matcher (Tier 0 -> 1 -> 2)
sources: proc_win, proc_linux, file (PE/ELF/Mach-O), ida
front-ends: cli.py, ida_plugin.py
```

**ByteSource contract:** `arch`, `read(addr, n)`, `regions()`, `modules()` with export maps, and an optional `hint_function(addr)`. `generate(source, addr) -> (Signature, QualityReport)` is the single entry point.

## 4. Signature spec v1

**Feature kinds**

- `str`: string literals referenced by the function.
- `const`: materialized constants, normalized across arch (x86 imm32, ARM movw/movt, ARM64 movz/movk collapse to one value). Pointer-like values are dropped.
- `callee`: resolved export or import names; `module+rva` fallback.
- `cfg`: block, edge, and loop counts stored as ranges.
- `ops`: histogram over about 14 op classes, bucketed, stored as ranges.

**Per-signature fields:** spec version, name, anchors (rarest 2-4 data features), feature list with weights, required vs optional flag per feature, match threshold, minimum distinct features, provenance (samples, arch, opt level, tool version), confidence tag (`single-arch` or `multi-arch`).

**Matching tiers**

- **Tier 0:** data anchors (strings, constant tables) via Aho-Corasick, indexed in both endiannesses.
- **Tier 1:** bounded decode around anchor hits, feature extraction on the candidate.
- **Tier 2:** weighted comparison against the shortlisted signatures only.

**Small functions.** Small functions are signable. They have little data to anchor on, so Tier 0 cannot trigger them. Their signatures instead add context features: the matched names of their callers and callees, their position among neighbors in the module, and a tight op-class sequence. They are matched near an already matched function, and a standalone hit is reported with a `confidence: low` tag.

**ARM support is first-class from M1, not a later add-on.** The arch layer, normalization tables, and tests are written for AArch64 alongside x64, and ARM32/Thumb follows in M4. Specific requirements:

- **AArch64 constants and pointers:** `adrp` plus `add` or `ldr` pairs resolve to one address (a string reference or a pointer, so they are masked or treated as anchors). `movz`/`movk` chains collapse to a single constant.
- **AArch64 hardening:** `bti`, `paciasp`, `autiasp`, and other pointer-authentication instructions are ignored by features, so signed (arm64e or PAC-enabled) builds match unsigned ones.
- **Thumb and ARM32:** the mode is tracked per address (low bit of pointers, `bx`/`blx` interworking). `movw`/`movt` pairs collapse to one constant, literal-pool loads resolve to the pooled value, and pool data is excluded from code. IT blocks and conditional execution are normalized so CFG shape and op counts stay comparable to the AArch64 and x64 builds.
- **Thunks and veneers:** linker veneers, PLT stubs, and `ldr x16`/`br x16` trampolines are recognized and resolved to their real target, so callee names stay accurate.
- **Endianness:** little-endian first. Big-endian ARM is flagged as unsupported for features but data anchors are still indexed in both byte orders.
- **Hosts:** PID mode must run on ARM hosts, not just analyze ARM code from x64. Order: ARM64 Linux and Android, then Windows on ARM, then macOS on Apple Silicon (which needs extra permissions for reading another process).
- **Tests:** golden vectors per architecture, and live-process tests on real ARM hardware or QEMU user-mode in CI.

**x86-64 support is the reference implementation from M1.** It is the first architecture to pass the golden vectors, and the other architectures are checked against it. Specific requirements:

- **Addressing and constants:** RIP-relative `lea`/`mov` operands resolve to one address (string reference or pointer, masked or used as anchors). `movabs` 64-bit immediates and 32-bit sign-extended immediates normalize to the same constant, and absolute addresses inside mapped modules are dropped.
- **Padding and alignment:** multi-byte NOPs, `int3` padding, and hot-patch prologues (`mov edi, edi`) are skipped when recovering bounds and ignored by features. `endbr64` (CET) is treated as a no-op, so CET and non-CET builds match.
- **Control flow:** jump tables (bounded by the index check), tail-call `jmp`s to other functions, and noreturn calls (`exit`, `abort`, `__stack_chk_fail`) are handled in recovery so block and edge counts stay correct.
- **Thunks and imports:** `jmp [rip+x]` IAT and PLT/GOT stubs, and incremental-link jump thunks, are resolved to their real target so callee names stay accurate.
- **ABI differences:** Windows x64 and System V use different argument registers and shadow-space conventions. Features avoid register identity, and op-class histograms are bucketed so spill and prologue differences do not change the result.
- **Vector code:** SSE, AVX, and AVX-512 instructions map to a small set of vector op classes, so compiler-vectorized loops compare sensibly against scalar ARM builds.
- **32-bit processes:** WOW64 and 32-bit x86 processes are detected and reported as unsupported for generation in v1, rather than being decoded as x64 by mistake.
- **Hosts:** Windows x64 and Linux x86-64 first. macOS on Intel and Rosetta-translated processes are out of scope for v1.
- **Tests:** golden vectors for MSVC, GCC, and Clang output at -O0, -O2, and -Os, plus live-process tests with a hooked function and an injected region.

## 5. Milestones

Each milestone has an exit criterion. Do not start the next until the current one passes.

### M0: Spec and test corpus (week 1-2)

- Write the spec document: feature kinds, canonicalization rules, hash function and seeds, file layout.
- Cross-compile 5-8 open-source libraries (zlib, libpng, sqlite, mbedTLS, busybox subset, and similar) for x64, ARM64, ARM32/Thumb at -O0, -O2, -Os, with DWARF.
- Build the ground-truth map: function name to address per binary.
- Assemble a **negative corpus** of unrelated clean binaries on each arch.

**Exit:** corpus builds reproducibly from one script; ground-truth map covers at least 95 percent of non-inlined functions.

### M1: Core extraction on x64 and AArch64 (week 2-5)

- `source` interface and `file` source (PE/ELF).
- `arch`, `normalize`, `recover`, `features` for x64 and AArch64 (ARM32 and Thumb follow in M4).
- Golden test vectors: bytes in, feature records out, checked into the repo.

**Exit:** recovered function bounds match DWARF bounds on at least 90 percent of corpus functions on both x64 and AArch64; golden vectors stable across runs and machines.

### M2: Single-sample generation and CLI on a live process (week 4-6)

- `proc_win` and/or `proc_linux` sources (see open questions).
- Module and export map parsing, pointer masking, trampoline/hook detection with on-disk fallback.
- `score`, `sigfile`, anchor selection, thresholds.
- CLI: `sigtool gen --pid P --addr A`, `module+rva` addressing, quality report, exit codes.

**Exit:** end-to-end generation from a live process; deterministic output (byte-identical on rerun).

### M3: Validation harness (week 6-7)

- Self-test: run the reference matcher against the source and require a hit at the original address.
- FP scan against the negative corpus.
- Quality verdicts: strong, weak, small (signed with a low-confidence tag).
- Corpus recall report per arch and opt level.

**Exit:** the tool refuses to emit signatures that fail self-test; FP rate reported per signature; CI runs the full harness.

### M4: Cross-arch (week 7-10)

- ARM32 and Thumb normalization, building on the AArch64 support from M1 (mode handling, literal pools, IT blocks, predication).
- Multi-sample merging: intersect stable features, widen numeric ranges, demote single-sample features.
- Auto-locate a function in a second binary using Tier 0/1 and confirm interactively.

**Exit:** signatures generated from x64 plus ARM64 samples match the ARM32 build of the same function at target recall (see section 6) with FP within budget.

### M5: IDA plugin (week 10-11)

- Action on Functions window and disassembly menu.
- `IdaSource` with IDA function bounds as hint; disagreement display.
- Quality report dialog; Save; Add sample (other IDB, file, or PID); optional live-debugger memory.
- Pin supported IDA version(s) and a pip-install path for Capstone.

**Exit:** a user can produce a multi-arch signature without leaving IDA; output identical to CLI for the same inputs.

### M6: Reference matcher and runtime hardening (week 11-13)

- Reference scanner: page hashing, incremental scan, prioritization of private, newly executable, or modified regions, per-module export cache.
- Budgeting: Tier 0 always on, Tier 1 rate-limited.
- Profile and record the numbers that justify the native port.

**Exit:** measured throughput and CPU cost on a representative process set; documented hot spots.

### M7: Native scanner port (implemented in Rust, x64 first)

- Rust crate under `native/` (`sigtool-native`) implementing the spec:
  decoder/normalizer/recovery/features, signature documents, matcher, scanner,
  and a CLI (`gen`, `locate`, `scan`, `db build`).
- Validated against the Python golden vectors and the x64 corpus results; the
  remaining architectures are follow-up ports (see section 12).
- Binary DB format with an mmap-friendly layout (SPEC.md §10).

### Optional later phases

- Call-graph propagation to corroborate small-function matches (needed for small-function support, so schedule it right after M4).
- MinHash/LSH tier for anchor-free matching.
- Ghidra and Binary Ninja front-ends (thin adapters over the same core).
- Optional IR-derived feature tier, versioned separately.

## 6. Success metrics (set targets after M0 baseline)

- **Recall** per tier, arch, and opt level on non-inlined, signable functions.
- **False positive rate** on the negative corpus: target zero hits for "strong" signatures.
- **Generation time** from address to signature: interactive (a few seconds).
- **Scan cost** (M6 onward): CPU percent and latency per scan pass.
- **Reproducibility:** identical signature bytes across machines for identical input.

Proposed starting targets, to be revised once real baselines exist: at least 90 percent recall on signable functions at the same opt level across arches, at least 70 percent across opt levels, zero FPs for strong signatures.

## 7. Testing strategy

- **Golden vectors** for extractor output per arch; any change requires an explicit regeneration and review.
- **Property tests:** normalization is idempotent; ASLR-shifted copies of the same code yield identical features.
- **Corpus regression in CI:** recall and FP numbers tracked per commit; a drop beyond a tolerance fails the build.
- **Live process tests:** scripted target processes with known functions, including a hooked function and a packed/injected region.
- **Fuzz the decoder front:** random bytes and truncated regions must never crash recovery.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Bad function bounds produce bad signatures | Show recovered blocks, compare to IDA hints, require confirmation; DWARF-checked in tests |
| Optimization level hurts more than arch | Per-tier weights, ranges from multiple -O levels, rely on strings/consts/callees |
| Inlining and LTO | Required vs optional features; subset matching; accept lower recall |
| Thumb/ARM mode errors | Explicit mode in `ByteSource`; mode-independent features; dedicated tests |
| In-memory code differs from disk (hooks, relocations) | Pointer masking; trampoline detection; on-disk fallback |
| Python too slow for scanning | Expected; Python is the reference, M6 measures, M7 ports |
| IDA API drift | Plugin is thin glue; core has no IDA imports |
| Signature spec churn | Spec version in every file; keep raw feature records so sketches and weights can be regenerated |
| Weak signatures shipped | Small functions get a low-confidence tag and need neighbor corroboration; mandatory self-test and FP scan |

## 9. Repo layout and tooling

```
sigtool/
  core/ sources/ cli.py ida_plugin.py
  spec/        written spec, changelog
  corpus/      build scripts, ground-truth maps (binaries not committed)
  tests/       vectors/, property/, live/
  docs/
  AGENTS.md
  PLAN.md
```

CI: lint, unit and golden tests, spec-version check, and a corpus regression job
that rebuilds the corpus and compares against the committed baseline.

## 10. Open questions to resolve before M2

1. **OS for PID mode first:** **resolved** — Windows x64 first (M2, implemented in
   `sources/proc_win.py`), Linux after. This unblocked local live tests; the
   ARM64 Linux/Android host order in section 4 is unchanged.
2. **Architecture pair first:** x64 plus ARM64 (proposed), with ARM32/Thumb after?
3. **Targets:** known library code, malware families, or both? This changes anchor strategy and negative corpus content.
4. **Scanner host architectures:** which platforms must the eventual scanner run on?
5. **IDA version(s)** to support.
6. **Licensing and distribution** of signatures and the corpus.

## 11. Rough timeline

About 12-14 weeks to a working generator, IDA plugin, and reference scanner for one engineer; the native scanner is scoped separately after M6 measurements. The schedule assumes the corpus build (M0) goes smoothly, since everything downstream depends on it.

## 12. Implementation status

Updated during M2.

**M0 — complete except real-library samples (licensing is an open decision).**

- `spec/SPEC.md` and `spec/CHANGELOG.md` define feature kinds, canonical forms,
  ignored instructions, buckets, hashing, and the recovery contract.
- `corpus/build.py` cross-compiles `corpus/src/*.c` for x64, arm64, and arm32 at
  `-O0`, `-O2`, `-Os` and writes symbol-table ground truth. Current run: 18
  binaries, 153/153 functions sized, coverage 1.000.
- The negative corpus exists: `corpus/negative/*.c` (codec, slot store, integer
  math) builds at `-O2` for all three targets into `build/negative/`, listed
  under the `negative` key of `ground_truth.json`. The samples are purpose-written
  and unrelated to `corpus/src`; real-library negatives (zlib and friends) are
  deferred until the licensing question in section 10 is decided.
- Deviation: the samples are purpose-written freestanding C, not yet the planned
  zlib/libpng/sqlite/mbedTLS set. Both corpora stay purpose-written until that
  decision. Ground truth comes from ELF symbol sizes rather than DWARF;
  symbol sizes are exact for non-inlined symbols and need no DWARF reader.

**M1 — implemented for x64 and AArch64.**

- `core/source.py` (ByteSource, regions, modules, in-memory source),
  `sources/file.py` (ELF incl. `ET_REL`, PE exports/imports),
  `core/arch.py` (detection, Capstone setup, unsupported-arch rejection),
  `core/normalize.py`, `core/recover.py`, `core/features.py`.
- Golden vectors in `tests/vectors/` are regenerated from real clang + lld output
  (`tests/vectors/generate.py`) for x64 and arm64 at `-O0/-O2/-Os`, plus AArch64
  `-mbranch-protection=standard` and x64 `-fcf-protection=full` variants, so the
  hardening rules are checked against compiler output.
- Bounds agreement on the corpus with no symbol-size hint: x64 51/51 (1.000),
  arm64 48/51 (0.941); the M1 exit criterion is 0.90. ARM32/Thumb are detected
  and rejected until M4.
- Property tests cover ASLR invariance, normalization idempotence/determinism,
  and hostile-byte recovery.

**M2 — implemented for the core, the CLI, and Windows PID mode.**

- `core/score.py` assigns base weights per kind, string and constant rarity
  multipliers, and optional IDF from a reference corpus; it selects up to four
  data anchors and derives match thresholds and `min_distinct`.
- `core/sigfile.py` holds the validated document, canonical YAML, and a
  BLAKE2b identity over that text. `core/validate.py` produces the quality
  report (`strong` / `weak` / `small`).
- `core/generate.py` is the single entry point: source plus address in,
  signature and report out. Front-ends must call it rather than recombine the
  pieces.
- `cli.py` is the thin front-end: `gen --file IMAGE --addr A` or
  `gen --pid P --addr A`, both accepting `--module M --rva R` instead of
  `--addr`. YAML goes to stdout (or `--output`), the quality report to stderr
  (`--json-report` for JSON), and exit codes are `0` success, `2` usage/input
  error, `3` unsupported arch, `4` self-test failure.
- `sources/proc_win.py` opens Windows targets read-only, rejects 32-bit/WOW64
  processes, and parses module export/import maps from the mapped image. Anchor
  regions are readable module pages only, capped at 32 MiB per region and
  128 MiB total; everything committed remains readable through `read`.
- Live tests spawn a child process with an injected executable page and check
  reads, module metadata, deterministic generation, and `--pid` end to end.
- Sample output for `collatz_length` (x64, `-O2`) is `weak`: it has only two
  constants and no strings or callees. That is the honest verdict, not a bug —
  shape features are optional and cannot anchor.
- Not done in M2: the Linux process source, on-disk fallback for pages the
  target will not share, and the IDA plugin.

**M3 — implemented; cross-opt recall target not yet met (M4's multi-sample
merging is the planned fix).**

- `core/match.py`: Tier 0 anchor needles (constants in both byte orders, strings
  narrow and UTF-16LE), Tier 1 candidates from known function starts plus a
  bounded backward instruction sweep from constant hits, and Tier 2 weighted
  comparison gated by `thresholds.match` and `min_distinct`. Overlapping spans
  collapse to one match.
- `core/generate.py` now runs the matcher against the sampled function and
  raises `SelfTestError` rather than emit a signature it cannot re-find (rule 7).
- Real corpus check: 32/32 functions across x64 and arm64 at `-O2` (two source
  files each) pass self-test in under two seconds total.
- Known gap: string anchors only rank candidates, so discovering code that
  references a string needs the M6 data-reference index; until then a source
  that cannot enumerate function starts also cannot self-test a string-only
  signature, and generation refuses rather than guessing.
- `bench.py` measures recall per arch and optimization level plus false
  positives. Current run (x64 and arm64, `loops.elf` and `parser.elf`, clang 18):
  102/102 signatures pass self-test, same-build recall 1.000, cross-build
  recall 0.427 (82/192), and 0 of 40 strong signatures hit an unrelated
  binary. Clang 22 gives 0.448 cross-build, so compiler version moves the
  number by about two points. The 70 percent cross-opt target in section 6 is
  **not met**; multi-sample merging in M4 is the planned fix, and thresholds
  were not loosened to move the number.
- `bench.py --baseline tests/baseline/bench.json` compares per-arch same-build
  recall, cross-build recall, false-positive rate, and refusal count against a
  committed baseline, failing on a drop or FP increase beyond 0.05
  (`--save-baseline` updates it intentionally). The tolerance covers
  compiler-version variation; rates are compared instead of raw counts because
  a different clang changes which functions exist.
- The M0 negative corpus (`corpus/negative/*.c`, nine binaries across x64, arm64,
  and arm32) is built by `corpus/build.py`, and `bench.py` scans every strong
  signature against it. Current result: 0 hits for all 40 strong signatures.
  Both FP measurements are compared against the baseline in CI.
- Hint-free discovery is implemented and measured (spec §8, `scan(hints=False)`):
  candidate starts come only from the backward sweep and recovery runs without
  symbol bounds. The harness reports recall per discovery mode. Hinted:
  same-build 1.000, cross-build 0.427. Hint-free: same-build 0.088 (9/102),
  cross-build 0.036 (7/192) — honest numbers, not a defect: only 22/102
  signatures have any searchable code anchor, and the sweep reaches the
  prologue in 19 of those. arm64 is 0.000 because `movz`/`movk` split constants
  never appear as contiguous bytes, so byte needles cannot hit; instruction
  aware Tier 0 anchors are M4/M6 work.
- `.github/workflows/ci.yml` runs format, lint, types, the corpus build, tests,
  and the baseline regression on Linux, and the live process tests on Windows.
  `tests/test_spec.py` checks that `SPEC_VERSION`, the hash person string, and
  the written spec and changelog agree.
- M3 exit criteria are met: self-test refusal, FP rates reported against both
  the negative corpus and unrelated source files, and CI running the full
  harness.

**M4 — implemented; cross-arch recall targets not yet met.**

- ARM32 and Thumb extraction is implemented: per-address mode from the ELF
  Thumb bit (sources canonicalize code addresses to the byte address),
  condition-suffix stripping with `it`-block normalization, `movw`/`movt` and
  `mvn` materialization, literal-pool resolution, and pool cells extending
  function bounds (arm32 pools are inline and symbol sizes count them).
  Bounds agreement on the corpus with no symbol-size hint: arm32 51/51 (1.000)
  and thumb 50/51, on top of x64 1.000 and arm64 0.941; the corpus-bounds gate
  now includes arm32 and thumb (0.90 criterion). Golden vectors include arm32
  and thumb (`-mthumb`) at `-O0/-O2/-Os`; the corpus grew to 24 binaries plus
  12 negative ones, and the ASLR property test relocates arm32 pool pointers
  like a loader would.
- Multi-sample merging (`core/merge.py`, `sigtool merge`): features in every
  sample stay required, subset features are demoted to optional half weight,
  anchors come only from stable features, and the merged document must
  self-test on every sample (7 of 48 merges on this corpus are refused that
  way, which is the design working). `sigtool locate` scans a second image or
  process with an existing signature.
- Measured (x64+arm64 merged samples, clang 18): merged same-arch recall is
  1.000 (merging loses nothing), merged same-opt recall on arm32 0.707
  (29/41), cross-opt 0.476; arm32 single-arch cross-opt recall 0.583, the best
  of the three arches. The 90/70 percent targets in section 6 are **not met**.
  Two causes, both measured: a 64-bit constant splits across two arm32
  registers so the halves never join the x64/arm64 feature (mix64), and the
  merged required set is the sample intersection, which arm32 builds diverge
  from half the time. Instruction-aware Tier 0 anchors (M6) and the
  real-library corpus (licensing decision) are the planned fixes.
- False positives: single-arch signatures stay clean (0 hits for all strong
  signatures, all arches). Merged signatures hit unrelated binaries: 4/15
  strong cross-source, 2/15 on the negative corpus. The intersection required
  set is weaker evidence than a single sample's full set, so the zero-FP
  budget is **not met** for merged signatures; the harness gates and reports
  them separately so the trade stays visible.
- Not done in M4: multi-sample merging from more than two arches in one call
  is supported by `merge()` but only the x64+arm64 pair is measured; the IDA
  plugin (M5) is the next milestone.

**M5 — implemented; the dialog glue needs an IDA host to exercise.**

- `sources/ida.py` exposes `IdaSource` behind an injectable `IdaApi` facade:
  the only IDA-SDK import site (AGENTS.md rule 1), so tests inject a fake and
  CI never needs IDA. IDA function bounds are recovery hints, making IDA the
  authoritative bounder; `bounds_disagreement` reports divergence explicitly.
- `ida_plugin.py` is UI glue: a generate action on the disassembly, Functions,
  and pseudocode right-click menus plus Edit > Plugins (quality report, save
  YAML, add file/PID samples, merge without leaving IDA), and a locate action
  that scans the current IDB with a saved signature and jumps to the match.
- Pinned hosts: IDA 8.4+/9.x with Python 3.10+, capstone installed via pip.
- Exit criterion: "output identical to CLI for the same inputs" is
  test-verified two ways in `tests/test_ida_source.py` — against every golden
  vector's recorded features and, over corpus binaries, byte-identical YAML
  from `IdaSource` and `FileSource` for the same function. The dialog and
  menu glue cannot run in CI (no IDA host); it is deliberately thin, and the
  first IDA-session check should follow `README.md` "In IDA".

**Not started:** native live-PID sources and a native IDA adapter, plus VFP/NEON
coverage for the native ARM32/Thumb decoder. Everything else through M7 is
implemented, including native `merge` and all four target architectures.

**M6 — implemented; native port is the follow-on (M7).**

- `core/scanner.py` (`SignatureScanner`, `ScanReport`, page hashing via CRC-32
  over 4 KiB pages, region prioritization: private first, then changed image,
  then untouched), `RecoveryBudget` in `core/match.py` for Tier 1 rate-limiting,
  `ReferenceIndex` with a global instruction budget (200 K) plus resync cap (4 K)
  per lifetime, and per-region drop-and-rebuild so freed regions do not keep the
  index growing. Tier 0 runs on every pass; Tier 1 degrades to fewer candidates
  rather than overrun. Signature identities are pre-computed once at construction
  instead of serialized per lookup (measured: dominated a skipped incremental
  pass at 11 ms/pass before the fix).
- `_candidate_starts` ranks exact hint starts first, swept starts ascending-by-address
  (prologue-first), distant candidates last. This reduces wasted recoveries on
  mid-function starts that share an anchor but precede the actual function
  prologue.
- Self-test falls back to building a temporary index when no anchor or known
  function start can reach a string-only signature's target, so generators from
  symbol-rich sources still get acceptance without giving up early.
- `profile_scan.py`: full-profile and incremental passes on the corpus (per binary)
  plus live-process scanning against this interpreter's modules. CPU time is
  tracked separately from wall-clock; top hot spots report cumulative caller
  chains.
- Measured: Python reference scanner on Windows x64, interpreter process (44 MiB
  address space, 138 regions, 16 signatures): full pass 98 s CPU / 99.7 s wall,
  200 K indexed instructions (truncated, confirming the budget caps large
  address spaces); second pass 16 ms wall with unchanged-page skipping alone.
  Corpus profile shows Capstone decode inside `ReferenceIndex.index_region` as the
  dominant cost on small binaries, candidate recovery as secondary. The
  `corpus/scan-profile.json` file holds the raw numbers.
- Exit criterion met: throughput and CPU cost measured on a representative
  process set (the running interpreter at `-O2` scale), hot spots documented in
  `profile_scan.py --json corpus/scan-profile.json`. M7 ports to C/Rust.

**M7 — implemented for x64, arm64, arm32, and thumb in Rust.**

- `native/` is a separate crate (`sigtool-native`) that mirrors `core/`:
  `source.rs`, `arch.rs`, `elf.rs` (ELF/PE `FileSource`), `normalize.rs`,
  `recover.rs`, `features.rs`, `sigfile.rs`, `score.rs`, `validate.rs`,
  `generate.rs`, `matcher.rs`, `scanner.rs`, `db.rs`, and `main.rs`. It uses
  `iced-x86` for decoding, `blake2b_simd` for the spec hash, and `serde_yaml`
  for the canonical document. No IDA or OS-specific code enters the library;
  the CLI is the only front-end.
- Parity is checked, not assumed. `native/tests/golden.rs` replays the x64
  and arm64 golden vectors (features, CFG blocks/edges/loops, degraded flags).
  `native/tests/scanner.rs` mirrors `tests/test_scanner.py` (page skipping,
  private-first priority, shared budget, reference index, truncation,
  string-only discovery, stable `signature_id`). `native/tests/corpus.rs`
  reproduces the x64 slice of `bench.py` and compares it to
  `tests/baseline/bench.json` with the same 0.05 tolerance.
- Measured on the generated x64 corpus: all 51 generated signature ids are
  byte-identical to Python, every recall cell matches the baseline exactly
  (hinted same-build 1.000, cross-build 37/96 = 0.385; hint-free same-build
  9/51 = 0.176, cross-build 8/96 = 0.083), and false positives are 0/17
  cross-source and 0/17 negative.
- Binary DB (`native/src/db.rs`, SPEC.md §10): 64-byte header (magic
  `SIGTDB\0\1`, format version, header/record sizes, flags, spec version,
  record count, spec/records/blob offsets, blob length, table CRC-32),
  40-byte records sorted by `signature_id`, and a padded blob of id, name, and
  canonical YAML. `DbView` validates structure once and reads payloads
  zero-copy; `MappedDb` maps the file read-only with `memmap2`. The spec
  version is part of the header, so a DB from another feature spec is refused.
- CLI: `sigtool-native gen`, `locate`, `scan` (YAML or `--db`), `merge`, and
  `db build`. Exit codes match the Python front-end: `0` success, `1` no
  match, `2` usage/input, `3` unsupported arch, `4` self-test refusal.
  `cargo fmt --all`, `cargo clippy --all-targets`, and `cargo test` are clean.
- Multi-sample `merge` is ported (`native/src/merge.rs`, `sigtool-native merge
  --sample FILE:ADDR ...`): features present in every sample stay required,
  subset features are demoted to optional half weight, anchors come only from
  stable features, and the merged document must self-test on every sample. Like
  the Python front-end, a refusal exits `2`. `native/tests/merge.rs` mirrors
  `tests/test_merge.py` and pins one merged document to the Python reference
  byte for byte; over the corpus pair `x64/O0/loops.elf` + `x64/O2/loops.elf`,
  all seven functions that merge successfully emit identical YAML in both
  implementations, and the one unmergeable pair (`_start`) is refused by both
  with the same message and exit code.
- AArch64 is ported (`native/src/arm64.rs`) with `yaxpeax-arm` in place of
  Capstone: `adrp` page deltas and `adr`/branch pc deltas are rebased onto
  absolute addresses, `adrp`+`add`/`ldr` pairs resolve to one reference,
  `movz`/`movk`/`movn` chains collapse to one constant, `[pc, #imm]` literal
  pools are distinguished from `[sp, #imm]` by the literal-load encoding, and
  the kind/class tables are the same as the reference. The golden test replays
  every arm64 vector (`arm64-O0/O2/Os` and the `-mbranch-protection=standard`
  PAC build), and `gen` on the arm64 corpus slice emits YAML byte-identical to
  the Python front-end for every sampled function (5/5 across `-O0` and `-O2`).
- ARM32 and Thumb are ported (`native/src/arm32.rs`) through `yaxpeax-arm`'s
  `armv7` decoder, with mode tracked per address: `movw`/`movt` pairs collapse
  to one constant, literal-pool loads resolve to the pooled value and extend
  function bounds, `adr` and branch deltas are rebased onto absolute addresses,
  condition suffixes and IT blocks are normalized, and the kind/class tables
  are the same as the reference. `recover` accepts all four architectures.
  Thumb branch targets are computed from the raw halfwords because yaxpeax's
  16-bit conditional delta does not match the encoding, and ITSTATE is tracked
  locally because yaxpeax leaves predication on the `it` instruction rather
  than marking the following instructions conditional. The golden test replays
  every arm32 and thumb vector, and `gen` on sampled arm32/thumb corpus
  functions (4/4 across `-O0` and `-O2`) emits YAML byte-identical to the
  Python front-end, except for the functions the decoder cannot represent: `yaxpeax-arm` 0.5 has no VFP/NEON instructions, so
  the auto-vectorized `recurse` builds at `-O2/-Os` are skipped by name in
  `golden.rs` and are the one known parity gap.
- Not ported yet: live-PID sources and the IDA adapter. `gen`/`locate`/`scan`/
  `merge` return exit code `3` only for an unknown architecture. The Python
  implementation remains the reference for those paths.
- Throughput is measured against the Python reference on the same corpus
  workload: `native/examples/profile_scan.rs` mirrors
  `profile_scan.py --no-live --no-profiler`, and `compare_scan_profile.py` joins
  the two JSON profiles. Six x64 binaries, the same signature sets, Tier 1
  budget 100 000, one full and one incremental pass: Python 1503.4 ms vs native
  39.7 ms on the full pass (37.8x, 18-49x per binary) and 0.52 ms vs 0.11 ms on
  the incremental pass (4.9x). The comparison script also verifies workload
  parity, so the ratio is not measuring different work: both sides generate the
  same signature count and report the same hits and index instruction count for
  every binary. The corpus is small (12 KiB of image), so this measures
  per-instruction decode and dispatch cost rather than page-hashing throughput
  at address-space scale, and the M6 live-process workload (98 s Python full
  pass over a 44 MiB address space) still has no native counterpart because
  there is no native PID source.
