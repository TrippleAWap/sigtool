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

### M7: Native scanner port (later, scoped after M6)

- C++ or Rust scanner implementing the spec, validated against the Python golden vectors and corpus results.
- Binary DB format with mmap-friendly layout.

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

**M0 — started.**

- `spec/SPEC.md` and `spec/CHANGELOG.md` define feature kinds, canonical forms,
  ignored instructions, buckets, hashing, and the recovery contract.
- `corpus/build.py` cross-compiles `corpus/src/*.c` for x64, arm64, and arm32 at
  `-O0`, `-O2`, `-Os` and writes symbol-table ground truth. Current run: 18
  binaries, 153/153 functions sized, coverage 1.000.
- Deviation: the samples are purpose-written freestanding C, not yet the planned
  zlib/libpng/sqlite/mbedTLS set, and the negative corpus does not exist. Both
  remain M0 work. Ground truth comes from ELF symbol sizes rather than DWARF;
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

**M3 — implemented; recall target not yet met.**

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
- `.github/workflows/ci.yml` runs format, lint, types, the corpus build, tests,
  and the baseline regression on Linux, and the live process tests on Windows.
  `tests/test_spec.py` checks that `SPEC_VERSION`, the hash person string, and
  the written spec and changelog agree.
- Remaining M3 work: the negative corpus (still M0) and a hint-free discovery
  mode (the harness currently uses ELF symbols as candidates, so it measures
  comparison quality rather than discovery).

**Not started:** M4 onward.
