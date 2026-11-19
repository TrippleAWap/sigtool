# sigtool: Project Plan

*Plan version 1.0 (2026-11-14). It replaces plan v0.5, which is kept with its
milestone history and measurements in
[`docs/history/PLAN-v0.5.md`](docs/history/PLAN-v0.5.md). The signature format
is specified in [`spec/SPEC.md`](spec/SPEC.md); agent instructions are in
[`AGENTS.md`](AGENTS.md).*

## 1. Mission

**Find the same function in another binary, whatever architecture, compiler,
or optimization level built it, including in stripped binaries without symbol
hints, and say honestly how sure we are.**

The product is the Rust crate under `native/`: a library and the
`sigtool-native` CLI. The IDA plugin and any later front-ends are thin
clients of the CLI.

### Who it is for

| User | Has | Wants | Mode |
|---|---|---|---|
| Reverse engineer porting work | An analysed binary (symbols or an IDB) and a new build, another architecture, or a stripped release of the same software | Their names and notes on the new binary | Whole-module signature set, joint resolution |
| Analyst hunting a known routine | One function (a vulnerable parser, a crypto core, a malware routine) | Every binary that contains it, across firmware for several CPUs | One signature or a small DB, hint-free scan of many images |
| Runtime defender | A signature DB | Whether a live process contains the code, without touching it | Read-only process source, incremental scanner |

All three need the same thing first: **when the tool says it found the
function, it is right**. A missed function costs the user time; a wrong one
costs their trust and can send an analysis the wrong way.

## 2. Goals for v1.0

Every goal is a number the bench measures. "Now" is the current baseline
(2026-11-18, spec v5, `integrate-matcher`; strong FP from `strong-fp-floor`). All recall figures are top-1: the expected function must be the
single best match, and ties count as misses. Hint-free figures scan
`strip --strip-all` copies.

### G1. Find: one signature (real corpus, hint-free)

| Search | Now | v1.0 |
|---|---|---|
| Same arch, same build | 0.835 | 0.95 |
| Same arch, other compiler, same level | 0.412 | 0.55 |
| Same arch, other optimization level | 0.365 | 0.45 |
| Other arch, same build settings | 0.433 | 0.60 |
| Other arch, other compiler | 0.287 | 0.45 |
| Other arch, other optimization level | 0.259 | 0.35 |
| Merged x64+arm64 signature, held-out arch, same level | 0.558 | 0.70 |

### G2. Find: whole-module sets (real corpus, hint-free, `bench --joint`)

| Search | Now | v1.0 |
|---|---|---|
| Other arch, same build settings | 0.810 | 0.85 |
| Other arch, other compiler | 0.630 | 0.65 |
| Other arch, other optimization level | 0.531 | 0.50 |
| Same arch, other compiler | 0.714 | 0.70 |

### G3. Trust

| Measure | Now | v1.0 |
|---|---|---|
| Precision of `identified` top-1 answers (correct / all identified answers, including those in images without the function) | hint-free 0.993, hinted 0.994 | ≥ 0.98 |
| Hint-free any-verdict false-positive rate (signatures with any accepted match in an unrelated library) | 0.115 | ≤ 0.05 |
| Strong-signature false-positive rate, corpus | 0.000 | ≤ 0.01 |
| Strong-signature false-positive rate, negative corpus | 0.000 | 0.000 |
| Joint resolution false hits in unrelated libraries | equal to scanned alone in every library | no higher than the same set scanned alone |

### G4. Generalize

| Measure | Now | v1.0 |
|---|---|---|
| Held-out corpus (libraries never used for tuning, §5) vs. tuning corpus, every G1-G3 row | no held-out corpus | within 0.05 |
| Function-start recall on stripped images, every arch | 0.95-0.996 | ≥ 0.99 at ≥ 0.999 precision |

### G5. Cost

Set as hard gates after M8 measures them; until then they are targets.

| Measure | v1.0 |
|---|---|
| `gen` for one function, including the whole-image index, on a 1.5 MB image | ≤ 2 s |
| Hint-free `scan` of a 150-signature module set against a 1.5 MB stripped image, 8 cores | ≤ 10 s |
| Peak memory for that scan | ≤ 2 GB |
| Full real-corpus bench with `--joint`, 8 cores | ≤ 30 min |

### G6. Quality

- Byte-identical signatures for identical input on Linux and Windows.
- No crash, hang, or unbounded read on random, truncated, or hostile bytes
  (fuzzed in CI: the `fuzz` job runs the cargo-fuzz targets in `native/fuzz`
  (`image`, `signature`, `db`, `code`) for 60 s each on every push, and
  `native/tests/hostile_inputs.rs` runs fixed-seed header-field, corruption,
  and truncation cases through the same drivers in `cargo test`).
- Every user-visible behaviour covered by a test built from real compiler
  output.

## 3. Non-goals

- IR lifting, symbolic execution, emulation, or learned models in the scan
  path. They may be explored offline, never shipped in the matcher.
- Matching functions that are not the same source code. Similar algorithms
  written independently are out of scope.
- Defeating deliberate obfuscation or packing. Unpacked memory from a live
  process is in scope; virtualized code is not.
- Writing to, suspending, or injecting into a target process, ever.
- Network access, telemetry, or auto-update in the tool.
- Recovering every inlined copy of a function: an inlined body is part of its
  caller.

## 4. Rules

These bind every change, by people or agents. When a rule and a goal
conflict, the rule wins; change the rule explicitly, in this file, with the
reason.

### Measurement

1. **The corpus decides.** A change to features, normalization, discovery,
   matching, or resolution lands with before/after numbers from the real
   corpus in both discovery modes, in the commit message. "Should help" is
   not evidence.
2. **Simulate before building.** When a rule can be evaluated on logged data
   (`bench --fp-report` writes every false-positive hit and every hint-free
   recall scan), sweep it offline first and build only the winner. Record the
   values that lost and why.
3. **Every constant has a measurement.** A threshold, floor, cap, or weight
   carries a comment with what was measured and what the alternatives cost.
   No magic numbers.
4. **Do not tune on the held-out corpus.** It is measured at milestone exits
   only (§5). If a held-out number drives a change, that library moves into
   the tuning corpus and a new one is held out.
5. **Never game the metric.** Top-1 means strictly first; a tie is a miss.
   Never break ties in a way that happens to favour the expected answer, read
   names or bounds of the searched binary in hint-free mode, or special-case
   corpus libraries.
6. **Baselines move only forward.** Re-save a baseline only for an
   intentional improvement or a toolchain change, and say which in the commit.
   Individual cells may drop within the tolerance when aggregates rise; name
   the cells that dropped and why.

### Precision and honesty

7. **Precision before recall.** A change that raises any false-positive rate
   beyond the tolerance needs a recall gain that justifies it, stated in the
   commit. When in doubt, abstain: "not found" beats a wrong answer.
8. **`identified` is a promise.** A match is labelled `identified` only on
   evidence that names a function: a string, an in-image callee, a
   distinctive constant, a shared neighbour key, or call-graph votes. Shape
   alone is `shape-only`, always.
9. **Report what was measured, not what was hoped.** Docs, commit messages,
   and reports state the number, the corpus, and the mode. Unmeasured claims
   are marked as such.

### Hint-free and input safety

10. **Hint-free means hint-free.** Hint-free discovery uses only what survives
    `strip --strip-all`: code, unwind tables, dynamic symbols and imports,
    relocations. Never `.symtab`, never DWARF, never the target function's
    own exported name as evidence. The bench scans stripped copies to enforce
    this.
11. **Target bytes are hostile.** Every decode, walk, and parse is bounded
    (instructions, bytes, rounds, neighbours) and never panics on random or
    truncated input.
12. **Processes are read-only.** Query and VM-read rights only; 32-bit and
    WOW64 targets are rejected, not misdecoded.

### Engineering

13. **One extractor.** Generation and matching share the feature code. A
    front-end never computes features.
14. **Deterministic output.** Same input, same bytes: sorted features, fixed
    hash seeds, no map-order leaks, no timestamps or paths. Check by running
    twice when touching output.
15. **No absolute addresses in evidence.** Addresses become module RVAs and
    live in provenance (`provenance`, `links`) only. A value is an address
    when the code uses it as one (PC-relative or memory reference, or a
    relocated word in a shared object or PIE), not because it falls inside
    the module span; other values are constants (`spec/SPEC.md` §2.2), and
    the same code at two bases gives identical features. Decided by the user
    on 2026-11-17, replacing "drop every in-range value".
16. **The spec is versioned.** A change to feature semantics, the document,
    or acceptance bumps `SPEC_VERSION`, updates `spec/SPEC.md` and
    `spec/CHANGELOG.md`, and regenerates vectors. Old documents are refused,
    not reinterpreted.
17. **Small, single-purpose commits.** One normalization rule, one matcher
    rule, or one source per change where possible; each commit passes fmt,
    clippy, tests, and the toy gate on its own.
18. **Tests from real compilers.** New behaviour gets a test built from real
    clang or gcc output (golden vector, corpus case, or CLI test), not a
    hand-written byte string alone.

## 5. Measurement protocol

### Corpora

| Corpus | Contents | Used for | Where |
|---|---|---|---|
| Toy | Freestanding sources, clang only, 4 arches × 3 levels | CI gate, quick checks | `corpus/build`, CI |
| Real (tuning) | zlib, lz4, cJSON, Lua, SQLite; clang and gcc; 4 arches × 3 levels; stripped copies | Every change (§4 rule 1) | `corpus/build-real` |
| Held-out | zstd 1.5.6, libyaml 0.2.5, mbedtls 3.6.2; never used for tuning; same matrix (`real.py --heldout`) | Milestone exits only | `corpus/build-heldout` |
| Negative | Unrelated purpose-written code | False positives | `corpus/negative` |

Pinned toolchains: LLVM 22.1.5 (CI installs the exact release) and GCC 12
(`corpus/docker`). A toolchain change is its own commit with re-saved
baselines.

### Metrics

- **Top-1 recall** per cell `(source arch, target arch, source build, target
  build, discovery)`, aggregated into the G1 rows. "Found" (anywhere in the
  match list) is reported but is not a goal.
- **False-positive rates** (G3) on unrelated libraries and the negative
  corpus, per verdict.
- **Joint recall and joint false hits** (G2, G3) from `bench --joint`.
- **Identified precision and abstention** (G3, added in M8).
- **Cost** (G5, added in M8).

### Gates

- CI: fmt, clippy, all tests (including live process tests on Windows), and
  the toy bench against its baseline with tolerance 0.05.
- Before merging matcher, feature, or normalization work: the real corpus
  with `--joint` against `tests/baseline/native-real-bench.json`.
- Weekly (`.github/workflows/real-bench.yml`): the real corpus built with
  both compilers and benched with `--joint` against its baseline.
- Milestone exit: the held-out corpus, recorded in §8.

## 6. Milestones

Ordered by what unblocks the most. Each has exit criteria; a milestone is
done when they hold and are recorded in §8.

The real-world plan ([`docs/real-world-plan.md`](docs/real-world-plan.md),
2026-11-19) adds milestones RW1-RW8 for binaries the corpus does not yet
cover (other versions, distro and hardened builds, executables, PE, large
hosts, live processes) and orders them ahead of further M10 tuning.

### M8. Honest measurement (next)

Before tuning further, make sure the numbers can be trusted.

- Held-out corpus: three more libraries (candidates: zstd, libyaml, mbedtls)
  built with the same matrix, pinned by sha256, never used for tuning.
- Bench metrics for identified precision, abstention (no identified answer in
  images without the function), and cost (wall time, peak memory per phase).
- Per-library breakdown, so one library cannot hide another's regression.
- A scheduled CI workflow that builds the real corpus (GCC image included)
  and runs the real bench weekly against the baseline.
- Re-run the held-out corpus after the latest rules: it was last measured at
  v4 (2026-11-16, strong FP 0.113), before in-module constants, FP
  reduction, the integration label rules, and the strong FP floor.

*Exit:* all G1-G5 measures appear in the baseline; held-out numbers are
recorded; the weekly job is green.

### M9. Coverage gaps

Functions the tool cannot see cannot be found.

- Thumb-2 lld thunks and Thumb PLT stubs (the arm64→Thumb gcc cells that
  lost recall to incomplete Thumb call graphs).
- AArch64 `-fno-plt` calls, gcc `.part.N` and `.cold` splits (merge the
  fragments into their function), functions after noreturn calls without a
  prologue, PE images without `.pdata`.
- A Linux process source (`/proc/PID/mem`, read-only) beside `proc_win.rs`.

*Exit:* each gap has a corpus or CLI case; function-start recall ≥ 0.99 on
every arch (G4).

*Non-goals for now (not in v1.0; revisit after M14):* Mach-O input
(`FileSource` reads ELF and PE only, though a macOS binary is released) and
32-bit x86 (32-bit and WOW64 processes stay rejected).

### M10. Cross-build robustness

The largest gap is other-compiler and cross-optimization recall (0.18-0.30).
Inlining and block layout change what a function looks like; the evidence
must survive them.

- Inline-invariant evidence: a function's strings, constants, and imports
  together with those of its small direct callees, so inlining a helper does
  not move the evidence.
- Switch and comparison constants as their own features; jump-table sizes.
- Coarser, layout-independent shape (loop nesting, call count buckets) where
  the corpus shows the current CFG buckets differ across compilers.
- Each feature lands alone, measured, with a vector from real compiler output.
- A C++ library in the real corpus (templates, vtables, duplicated template
  instantiations); every corpus library is C today.

*Exit:* the G1 other-compiler and cross-opt rows reach their v1.0 targets on
the tuning corpus and within 0.05 on the held-out corpus.

### M11. Joint resolution 2.0

- Global assignment instead of greedy rounds: score every (signature,
  candidate) pair and solve for the most consistent mapping.
- Use call order and call counts, not just adjacency.
- Joint resolution in hinted mode, in `locate` against a module DB, and for
  merged signature sets.
- IDA workflow: sign a whole IDB, apply the resolved names to another.

*Exit:* G2 targets on the tuning corpus; joint false hits no higher than
alone (G3).

### M12. Trust and explanation

- Calibrated confidence per match (an estimated probability, fitted on the
  tuning corpus, checked on held-out), with a default abstention threshold.
- `--explain`: which features, neighbour keys, and links decided the match.
- The IDA plugin tested in a current IDA release.

*Exit:* G3 identified precision ≥ 0.98 on tuning and held-out corpora.

### M13. Scale

- Signature DB of 100k functions: inverted index from anchors and neighbour
  keys to signatures, so a scan touches only plausible signatures.
- Incremental hint-free scanning of live processes.
- G5 cost targets as CI gates.

*Exit:* G5 met; a 100k-signature scan of a 50 MB image is measured and
documented.

### M14. v1.0 release

- Spec frozen as the v1 format; DB compatibility promise documented.
- Release binaries for Linux and Windows (x64, arm64), `cargo install`.
  Tagged builds and the IDA plugin bundles: `.github/workflows/release.yml`
  (§8).
- User documentation for the three workflows in §1.

*Exit:* every G1-G6 goal met on the held-out corpus.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Overfitting thresholds to five libraries | Held-out corpus (M8), rule 4, simulation logs kept with the decision |
| Recall gains bought with false positives | Rule 7, FP gates, identified precision as a goal |
| Compiler upgrades move every number | Pinned toolchains; a toolchain change is its own commit |
| Inlining and LTO erase function boundaries | Inline-invariant evidence (M10); accept that fully inlined copies are not findable |
| Call-graph gaps on one arch skew joint resolution | Coverage first (M9); per-arch cells in the joint bench |
| Slow benches discourage measuring | Cost metrics (M8), caching, a fast slice for iteration |
| Hostile inputs | Bounds everywhere (rule 11), cargo-fuzz targets run in CI (`native/fuzz`), fixed-seed hostile-input test (`native/tests/hostile_inputs.rs`) |
| Spec churn breaks users' DBs | Versioned documents, refuse old versions, freeze at v1.0 |

## 8. Status

As of 2026-11-18, `strong-fp-floor` branch, spec v5.

- Single signature, hint-free top-1: the "Now" column of G1. Hinted top-1:
  same build 0.690, other arch 0.374, other arch other compiler 0.307.
- Whole-module sets: the "Now" column of G2.
- False positives: strong 0.000 (corpus) and 0.000 (negative), any-verdict
  hinted 0.075, hint-free 0.115.
- What moved the numbers, in order, with measurements:
  [`docs/history/PLAN-v0.5.md`](docs/history/PLAN-v0.5.md) §13 and
  [`spec/CHANGELOG.md`](spec/CHANGELOG.md).
- M8 (2026-11-15):
  - Bench reports identified precision and abstention, per-phase cost and
    peak memory, and top-1 per library (gated at >= 20 attempts); both
    baselines carry them. Identified precision, tuning corpus: hint-free
    0.848, hinted 0.687 (target >= 0.98).
  - Held-out corpus (zstd, libyaml, mbedtls) built and measured once.
    Hint-free top-1, held-out vs tuning: same build 0.889 / 0.810, other
    compiler 0.372 / 0.304, cross opt 0.370 / 0.249, other arch 0.395 /
    0.300, other arch other compiler 0.286 / 0.210, other arch cross opt
    0.288 / 0.181, merged held-out arch 0.389 / 0.392. Hint-free FP 0.057 /
    0.163; identified precision hint-free 0.897, hinted 0.883. No row is
    worse on held-out by more than 0.003.
  - Cost: ARM32/Thumb blocks decoded from a growing prefix with one cached
    Capstone handle (whole-image index on stripped Thumb sqlite 77 s ->
    2.8 s), x64 names from static tables, indexes and multi-signature scans
    in parallel. `gen` on stripped gcc-O2 sqlite: x64 0.28 s, Thumb 1.83 s
    (G5 <= 2 s). Full real bench with `--joint`: ~130 s on 8 cores, peak
    0.93 GB (G5 <= 30 min).
  - Determinism: `similarity` summed weights in `HashMap` order, so tied
    lookalikes ranked differently between runs; fixed, and two full real
    benches now give identical reports.
  - G5 150-signature hint-free scan (`examples/profile_g5.rs`: signatures
    from 150 gcc-O2 sqlite functions, scanned against stripped clang-O2
    sqlite, 3 threads on a shared 8-core machine): x64 (1.13 MB) 6.5 s ->
    0.8 s, Thumb (0.73 MB) 50.4 s -> 1.4 s, peak 58 / 62 MB (G5 <= 10 s,
    <= 2 GB). From ARM32/Thumb blocks decoded instruction by instruction
    instead of by prefix (4x fewer Capstone decodes), one parallel sweep for
    both whole-image indexes, signature keys formatted once per scan, a
    first-byte skip in Tier 0, and frequencies built before candidates.
    Every output is unchanged (toy and real-slice bench reports, match
    digests, generated DBs). No 1.5 MB stripped image is in the corpus;
    the largest is x64 clang-O2 sqlite.
  - Open for M8 exit: the weekly workflow (`real-bench.yml`) has not run
    yet.
  - RW2 bench honesty (2026-11-19, `rw/bench-honesty`): FP cells record
    `targets` and `target_bytes`, and `compare` fails a gated FP cell that
    scanned no image; every rate in the text report carries n and a 95%
    Wilson interval (gating unchanged); `bench --sample-seed N` draws
    another function sample; samples record their real compiler (gcc
    samples had `tool: clang`), which changes only their `signature_id`.
    Toy and real (`--max-functions 4 --joint`) reports are identical before
    and after except for the new fields; two toy runs are identical. Real
    corpus, per arch: corpus FP cells scan 30 images (7-11 MiB; merged 120,
    38 MiB). The real corpus has no negative set, so its 10 negative FP
    cells (strong and any verdict) scanned 0 images and now fail the real
    baseline comparison; every other cell passes. They stay failing until
    the real negative set (RW2) lands or the user agrees to drop them from
    the baseline (rule 6). Example interval: hint-free identified precision,
    toy corpus, 552/584 = 0.945 [0.924, 0.961].
- M12, trust labels (2026-11-16, tuning corpus only): `identified` now
  needs an untied first match similar enough for its evidence, and
  shape-only matches need similarity 0.3 (hinted too, with 6 features).
  Identified precision hint-free 0.981, hinted 0.987; FP hint-free 0.163 ->
  0.156, hinted any-verdict 0.196 -> 0.113, strong 0.072 -> 0.042; top-1
  unchanged hint-free, +10 hits hinted. Not yet run on held-out.
- M10 (started 2026-11-16, `m10-cross-build` branch):
  - Miss diagnosis (`examples/diagnose_cross`: the bench's signatures
    compared with the stripped target's true function, hint-free; 20
    functions x 24 builds at `--max-functions 4`). The true function is
    almost never outranked (0.5-2.7%) or missing from the candidates
    (0.8-1.9%); it fails acceptance. Other compiler / cross opt / other arch
    / other arch other compiler / other arch cross opt: score below threshold
    0.18 / 0.25 / 0.17 / 0.26 / 0.31, `min_distinct` or shape gate 0.42 /
    0.42 / 0.45 / 0.47 / 0.45, hint-free gates 0.04.
  - 62% of those signatures (45% at `--max-functions 24`) have no
    identifying required feature, and only 49% have neighbour keys. Their
    shape gate cannot pass cross-build: on true pairs each `ops` bucket
    disagrees 55-98% of the time, `cfg:blocks`/`edges` 48%, `cfg:loops`
    30-34%. Coarser buckets (±1) simulated +0.05-0.07 acceptance, but these
    signatures are where every false positive comes from; not built.
  - Inlining: when a signature with identifying evidence fails a cross-opt
    target (x64+arm64, 24 functions per image), 65% of its missing required
    strings sit in one of the target's direct callees (callee names 57%,
    distinctive constants 27%). Built as
    inherited evidence at half credit (SPEC.md §1.4): full real bench G1
    hint-free other compiler 0.304 -> 0.312, cross opt 0.249 -> 0.253, other
    arch 0.300 -> 0.301, other arch other compiler 0.210 -> 0.211, other
    arch cross opt 0.181 -> 0.180; G2 joint other arch other compiler 0.313
    -> 0.338, other arch cross opt 0.266 -> 0.296, same arch other compiler
    0.437 -> 0.478, other arch same build 0.537 -> 0.534; FP rates
    unchanged, identified precision hint-free 0.848 -> 0.843. Cells below
    tolerance: arm64 clang-O2 -> gcc-Os hint-free top-1 0.400 -> 0.350 (one
    function of 20), joint lua x64 -> arm32 clang-O2 -> gcc-O2 0.373 ->
    0.320 (84 joint cells up, 11 down). Full credit gained 4-6 points on
    the x64+arm64 slice but raised the hint-free FP rate 0.125 -> 0.155.
  - Lost: near-zero constants optional beside identifying evidence (+0.03-
    0.05 cross-opt top-1 on x64+arm64, lower FP rates) fails the toy gate:
    hint-free identified precision 0.938 -> 0.876 and x64->arm64 Os cells
    -0.06, because inliners of a helper then match its signature. Strings-
    only condition simulated no gain.
  - In-module constants (decided by the user on 2026-11-17; spec v5,
    `in-module-constants` branch): the pointer test dropped every constant
    inside the module span, and a shared object maps at 0, so in-range
    numbers (zlib's 0xfff1, LZ4 sizes) vanished, differently per build and
    per base. AGENTS.md hard rule 4 and rule 15 now drop a value only when
    the code uses it as an address; in an ELF shared object or PIE that is a
    word a dynamic relocation writes (SPEC.md §2.2). 20-30% of functions
    gain an in-range `const` record. The neighbour answer floor rose 0.3 ->
    0.42 to keep identified precision (twins now share resolved neighbour
    strings). Full real bench (`--max-functions 4 --joint`) vs v4:
    hint-free top-1 other compiler 0.308 -> 0.392, cross opt 0.254 -> 0.344,
    other arch 0.306 -> 0.374, other arch other compiler 0.216 -> 0.270,
    other arch cross opt 0.183 -> 0.237; hinted other arch 0.329 -> 0.365;
    G2 joint other arch same build 0.777 -> 0.793, other compiler 0.571 ->
    0.624, cross opt 0.466 -> 0.522; FP strong 0.040 -> 0.017, any-verdict
    0.111 -> 0.105, hint-free 0.154 -> 0.117, negative 0.000; identified
    precision hint-free 0.981 -> 0.981 (correct answers 2747 -> 3321),
    hinted 0.987 -> 0.989 (1774 -> 2349). Lost variants (memory-base drop,
    exact-start drop, features-only, other floors) in `spec/CHANGELOG.md`.
    Open: 61 cells dropped past tolerance, mostly merged signatures into
    32-bit targets, from struct field offsets that differ between 64- and
    32-bit layouts, which the signature now requires. Not run on held-out.
  - Recovery is not the cause: hint-free coverage of ground-truth bodies is
    0.94-1.00 per image and indirect (switch) jumps occur in 0-9% of
    functions (`examples/recovery_coverage`).
- M11, joint resolution 2.0 (2026-11-16, tuning corpus only): a global
  one-to-one assignment over every (signature, function) pair with
  similarity >= 0.2, weighed by similarity, call-graph degree, and the scan's
  identified answer, refined by preserved links, and trusted only when it
  preserves >= 6 link ends and a fifth of those it could (SPEC.md §8).
  Simulated first on a `bench --joint-report` dump; losing variants in
  `spec/CHANGELOG.md`. G2 hint-free: other arch same build 0.537 -> 0.771,
  other compiler 0.313 -> 0.527, other opt 0.265 -> 0.430, same arch other
  compiler 0.437 -> 0.670; joint false hits equal to scanned-alone in every
  library (zlib 10 -> 8). `joint:0` answers (no preserved link) are about
  half right and are not identifying; `joint:N>=1` answers 0.84. G2 targets
  not met: 7% of true functions are below the 0.2 pair floor in the same
  build and 30% across compilers, so the rest is feature work (M10).
  Not yet run on held-out.
- M11, IDA workflow (2026-11-17): the plugin signs every meaningfully named
  function of an IDB into one DB (`db build --file IMAGE --functions LIST`,
  one run sharing one scan context) and applies a DB to another IDB through
  `scan --db --discovery hint-free` (joint resolution), renaming only
  `identified` answers after a chooser confirms them. `scan --json` hits now
  carry `module` and `rva`.
- M12, IDA plugin (2026-11-17): still not run in a real IDA; the local IDA
  9.2 install could not be used. Checked against the IDA 9.2 IDAPython API
  sources instead, which showed three bugs now fixed: the rename chooser
  called `Choose.show()` (the method is `Show(modal=True)`, and a modal
  multi-select chooser reports its rows through `OnSelectLine`, not its return
  value), `ask_file` got a fourth argument (it takes for_saving, a mask or
  default name, and a prompt), and the menu path named a nonexistent item
  instead of `Edit/Plugins/`. Locate now runs behind the cancellable wait box
  and lists matches in a non-modal chooser; applied renames get a function
  comment (signature id, score, evidence) and a results chooser; the plugin
  prefers the `sigtool-native` next to it over PATH and warns when
  `--version` (now `0.1.0 (spec 4)`) reports another spec.
  `tests/ida_cli_smoke.py` drives every action against the real CLI with fake
  IDA modules: x64 zlib clang-O2 -> stripped gcc-O2 signs 120/120 and renames
  17 non-exported functions, 15 right (`deflate_fast` and `deflate_slow` swap,
  both `identified`); arm64 lz4 clang-O2 -> gcc-Os 9 of 9 right (a tenth
  `identified` hit at +0x170c0, where the IDB has no function, is skipped:
  apply-names renames only a function starting at the match, or code IDA
  agrees to start one at); arm32 cJSON
  gcc-O2 -> clang-O2 9 of 9. IDA's UI paths (dialogs, choosers, wait box,
  context menus) remain unexercised.
- v4 (2026-11-16): M9 coverage, M10 inherited evidence, M12 trust labels,
  and M11 joint assignment merged and measured together (full real bench,
  `--max-functions 4 --joint`; baselines re-saved for the version). Against
  the v3 baseline: hint-free top-1 3637 -> 3704 hits, hinted 4127 -> 4177;
  identified precision hint-free 0.851 -> 0.981, hinted 0.687 -> 0.987; FP
  hint-free 0.163 -> 0.154, hinted any-verdict 0.196 -> 0.111, strong 0.072
  -> 0.040. Joint rows together are below M11's own measurement (other arch
  other compiler 0.493 vs 0.527, other arch cross opt 0.402 vs 0.430, same
  arch other compiler 0.633 vs 0.670); the interaction with inherited
  evidence is not yet explained. Cells that dropped past tolerance: arm64
  clang-O2 -> gcc-Os hint-free top-1 0.400 -> 0.350 and merged->thumb
  clang-O2 hinted top-1 0.471 -> 0.412 (one function each), and 76 hinted
  found-anywhere cells (shape-only lookalikes below the top removed by the
  trust floors; hinted found 4903 -> 4680). Full bench 221 s on 8 cores,
  peak 1.06 GB.
- Held-out at v4 (2026-11-16, measured once, nothing tuned on it), M8 ->
  v4, hint-free top-1: same build 0.889 -> 0.896, other compiler 0.372 ->
  0.368, cross opt 0.370 -> 0.374, other arch 0.395 -> 0.414, other arch
  other compiler 0.286 -> 0.307, other arch cross opt 0.288 -> 0.302, merged
  held-out arch 0.389 -> 0.413. Identified precision hint-free 0.897 ->
  0.981, hinted 0.883 -> 0.988. FP hint-free 0.057 -> 0.054, any-verdict
  0.080, strong 0.113 (14 of 124 strong signatures; not measured at M8, and
  0.07 above tuning: the one G4 row outside 0.05). Joint: other arch same
  build 0.779, other arch other compiler 0.556, other arch cross opt 0.533,
  same arch other compiler 0.702; joint false hits equal scanned alone.
- Joint after v4 (2026-11-16, `joint-inherited` branch, tuning corpus only):
  the joint-vs-M11 gap was joint resolution's own similarity copy counting
  candidates' inherited `inl:` keys as extra weight, which pushed true
  pairs below the 0.2 floor. With the scan's similarity, G2 hint-free: other
  arch same build 0.763 -> 0.777, other compiler 0.493 -> 0.571, other opt
  0.402 -> 0.466, same arch other compiler 0.633 -> 0.702; joint false hits
  unchanged (equal to scanned-alone); every other report section unchanged.
  Cost: inherited evidence cached per callee and acceptance decided before
  building match results, outputs unchanged; full real bench `--joint`
  66 s on 8 cores (idle machine; 221 s recorded at v4 under load),
  peak 1.10 GB; confirmed on main (64 s), real baseline re-saved for the
  joint section. Not yet run on held-out.
- M14, release builds (2026-11-17, `release-ci` branch): a `v*` tag runs
  `.github/workflows/release.yml`, which builds `sigtool-native` for
  linux-x86_64, linux-aarch64, windows-x86_64, windows-aarch64, and
  macos-aarch64 (arm64 Linux and Windows cross-compiled; arm64 runners are
  not free for private repos; Linux inside `ubuntu:22.04` and gated at
  glibc 2.35), packages each with `packaging/package.py`
  into an HCLI / Plugin Manager plugin zip (`sigtool/` with
  `ida-plugin.json` listing that one platform, `ida_plugin.py`, and the
  binary beside it) plus a standalone CLI archive, lints the plugin zip with
  `hcli plugin lint`, and uploads everything with `SHA256SUMS` to the
  release. `workflow_dispatch` builds the same artifacts without publishing.
  The repository manifest lives in `packaging/` so the source zipball is
  not indexed as a plugin without its binary. Not yet run in CI.
- Cross-ISA shape (2026-11-17, `cross-arch` branch, tuning corpus only):
  low-information signatures scanned in another ISA family (`x64`, `arm64`,
  `arm32` with Thumb) also corroborate shape on the ISA-stable dimensions
  (`cfg:*`, `ops:branch/call/cond/ret/store`) when 4 distinct required
  features match (SPEC.md §8). Full real bench `--joint`, hint-free top-1:
  other arch same build 0.306 -> 0.342, other arch other compiler 0.216 ->
  0.219, other arch cross opt 0.183 -> 0.184, merged held-out arch 0.397 ->
  0.448; hinted other arch same build 0.329 -> 0.338; 48 hint-free and 20
  hinted top-1 cells up, none down; FP rates and identified answers
  unchanged; joint rows unchanged at three decimals. Cross-ISA false hits,
  which the bench does not measure (`examples/cross_fp`): 66 -> 70 of 1200
  (signature, target arch) pairs, none identified. G1 cross-arch targets
  remain far off: the stable dimensions only recover pairs whose required
  evidence already matches; the rest is feature work. Not yet run on
  held-out. Real baseline re-saved for it (no cell dropped).
- FP reduction (2026-11-17, `fp-reduction` branch, tuning corpus only,
  full real bench `--joint`; v5 draft in `spec/CHANGELOG.md`,
  `SPEC_VERSION` still 4): `strong` needs 2 identifying required features
  (173 -> 87 strong signatures, strong FP 0.040 -> 0.011, a label only:
  nothing else moves), and a match holding none of the signature's
  identifying required features needs similarity 0.25 (strong FP 0.011 ->
  0.000, hint-free any-verdict 0.154 -> 0.146, hinted 0.111 -> 0.109, joint
  sets' false hits cjson 21 -> 20 and zlib 8 -> 6; hint-free top-1 3704 ->
  3705, hinted 4177 -> 4176; merged->arm64 clang-O2 -> clang-O0 hint-free
  0.412 -> 0.353, one function). 0.22 was benched and lost (keeps that
  function, removes none of the joint false hits). The G3 hint-free ceiling
  (0.05) is still far: of the 84 hint-free signatures with false hits, 74
  have no identifying required feature (shape and small constants only), 8
  match unanchored at similarity >= 0.25, and 2 hold one. Not yet run on
  held-out.
- Joint tail-call edges (2026-11-17, `merged-joint` branch, tuning corpus
  only): joint resolution's callers now include tail callers, so `out:`
  links to tail-called neighbours earn the link bonus. G2 hint-free: other
  arch same build 0.777 -> 0.792, other compiler 0.571 -> 0.579, other opt
  0.466 -> 0.475, same arch other compiler 0.702 -> 0.709, same arch other
  opt 0.540 -> 0.545; joint false hits unchanged (46, equal to scanned
  alone); every G1, FP, and precision line unchanged. G1 merged held-out
  arch hint-free top-1 stays 0.397: of 388 merged -> arm32/thumb scans
  (`examples/diagnose_merged`), 130 are top-1 and 140 fail only the shape
  gate (score and required evidence pass, shape agreement below 0.8; 27 of
  them reach 0.7, 62 reach 0.6). Loosening that gate needs an FP simulation
  first; not built. Not yet run on held-out.
- Integration (2026-11-18, `integrate-matcher` branch, tuning corpus only):
  `fp-reduction`, `merged-joint`, `in-module-constants`, and
  `cross-compiler`'s shape waiver merged onto `native-first`
  (`cross-compiler`'s ARM32 PIC change was not merged: in-module constants
  resolve those offsets through relocations, and its extra absolute
  reference read string tails out of `.dynstr`). Merged as is, hint-free
  identified precision was 0.974 (3497 / 3592). Two label rules, simulated
  on `--fp-report` logs first (`spec/CHANGELOG.md` v5, with the losers):
  waived matches are never `identified` (0.974 -> 0.981: the waiver's 31
  wrong answers include 15 in unrelated libraries on neighbour constants
  `0x10000` and `0xffff`), and a first match with a rival holding the same
  identifying keys within similarity 0.1 is a `candidate` (0.981 -> 0.993,
  hinted 0.989 -> 0.994; source twins such as
  `cJSONUtils_GeneratePatches` / `..CaseSensitive`). Only labels and joint
  seeds move. Against the `native-first` baseline (full real bench
  `--joint`), hint-free top-1: same build 0.817 -> 0.835, other compiler
  0.308 -> 0.412, cross opt 0.254 -> 0.365, other arch 0.342 -> 0.433,
  other arch other compiler 0.219 -> 0.287, other arch cross opt 0.184 ->
  0.259, merged held-out arch 0.448 -> 0.558 (3778 -> 4879 hits; hinted
  4197 -> 4750). G2: 0.777 -> 0.810, 0.571 -> 0.630, 0.466 -> 0.531, 0.702
  -> 0.714; joint false hits equal scanned alone (46 -> 41). Identified
  precision hint-free 0.981 -> 0.993 (2747 -> 3163 correct), hinted 0.987
  -> 0.994. FP hint-free 0.154 -> 0.115, any-verdict 0.111 -> 0.105,
  strong 0.040 -> 0.025: the three strong false positives are hinted
  `LZ4_loadDict` / `inflateCopy` matches at similarity 0.01-0.12, anchored
  by `0x10000` / `0x558` now that in-module constants are kept, which
  `fp-reduction`'s unanchored floor no longer reaches (a hinted similarity
  floor of 0.13 removes all three with no top-1 loss in a quick
  simulation; not built). Cells below tolerance: listed in the baseline
  commit (mostly in-module constants' 32-bit-target and merged cells).
  Not yet run on held-out.
- Strong FP (2026-11-18, `strong-fp-floor` branch, tuning corpus only): a
  hinted match whose identifying keys are all constants needs similarity
  0.2, the floor every hint-free match has (SPEC.md §8). Simulated on the
  v5 `--fp-report` logs first (sweep and losers in `spec/CHANGELOG.md` v5):
  every constant-anchored hinted hit in an unrelated library is below 0.19,
  the lowest such true top-1 match 0.223. The integration entry's 0.13 on
  every hinted match also keeps top-1, but sits 0.002 below a true
  callee-anchored match (0.132) and leaves any-verdict at 0.081. Full real
  bench `--joint`: strong FP 0.025 -> 0.000 (G3 met on the tuning corpus),
  hinted any-verdict 0.105 -> 0.075, negative 0.000; every top-1 cell,
  hint-free cell, identified precision (0.993 / 0.994), and joint row
  unchanged. Dropped past tolerance: one hinted found-anywhere cell,
  merged->arm64 clang-O0 -> gcc-O2 0.562 -> 0.500 (a second-ranked true
  match at 0.193). Held-out strong FP was 0.113 at v4; not yet re-run.
- Next: M8 exit (weekly workflow green), strong FP on the held-out corpus
  (milestone exit), and pointer-width-dependent constants (M10).
