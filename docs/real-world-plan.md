# Real-world use: plan

*Plan, 2026-11-19, written against `native-first` at b79da58 (spec v5) and adopted the same day; progress is recorded in `PLAN.md` §8. In the diagnosis, **verified** means read in the code, **audit** means reported by a gap audit and not re-checked, and **inferred** means not measured.*

## Progress (2026-11-19)

Landed on `real-world` (details and numbers in `PLAN.md` §8): RW1; RW2 except
the build metadata in ground truth and the real negative set; RW3's floors and
error paths; RW4's gcc profile tier
(`--world`) with spec v6's executable-callee rule and the x86 `rbp` fix it
exposed; RW7's packed relocations and section-less ELF; RW8's batch scan,
image identity and `db info`/`list`. On `rw/trust-tools`: RW3's process-path
bench cell (`bench --process-like`, measured, ungated: top-1 0.010 against
0.353 file hinted, because the scanner path has no candidate list), RW7 raw
blobs (`--raw`), RW8 `locate --explain` / `--expect`. Open: RW3 routing `scan`
and `locate` through `scan_in` per module (now measured as the fix the process
path needs); RW4 distro packages, C++, joint drift; RW5; RW6; RW7 the IDA
plugin's `--raw` fallback; RW8 generation warnings.

RW6 measurement, on `rw/scale` (numbers in `PLAN.md` §8):

- Needle in a host: `corpus/real.py --host` links the five tuning libraries
  into one static gcc `-O2` executable per arch (`--gc-sections`), plus an
  LTO host and leave-one-out hosts as true negatives. Hint-free same-arch
  top-1 from the `-O2` shared object: 0.642 into the host, 0.487 into the
  LTO host, 0.905 same build. Accepted hits on the negatives per signature
  per MB of code: x64 0.176 to Thumb 0.943; identified answers in unrelated
  images 0.0025 per signature per MB (goal 0.001).
- Scale harness: `examples/profile_scale.rs`. The x64 `-O0` host (2.4 MB of
  code) with 1, 150 and 1000 signatures of its own functions scans in 0.6,
  2.1 and 10.9 s on 2 threads, at 130-167 MB peak.
- No cap truncates at these sizes (instructions at 15% of 4M, candidates
  at 8% of 65,536, joint pairs at 8% of 2^26), so none of the six fixes
  was started: the plan's 10-150 MB targets need sources larger than the
  tuning libraries.
image identity and `db info`/`list`; RW5a's clang + lld-link PE tier
(`--pe`, x64 and arm64, `/GS` and `/guard:cf` variants, an ELF+PE mixed
corpus, `.pdata` start recall; four matcher findings recorded, none fixed).
Open: RW4 distro packages, C++, joint drift; RW5a MinGW builds and PDB
ground truth; RW5 `.reloc`, delay-load imports, RW5b; RW6; RW7 raw blobs;
RW8 `--explain` and generation warnings.

## 1. Diagnosis

Every number in §8 comes from images we compile ourselves, and they are all the same kind: PIC ELF shared objects (`corpus/real.py:231`, `-shared` at `:258` and `:298`). The clang builds link no libc (`real.py:25`). Each library is pinned to one version, and it is all C. Ground truth keeps only functions that occur exactly once in all 24 builds (`real.py:424`). That filter removes clones, template duplicates and folded functions. These cases are never measured:

- the next release of the same library, which is user 1's first case;
- distro hardening, LTO, `-O3`, older gcc;
- PIE, `ET_EXEC` and static executables;
- PE files of any kind, and C++ with identical-code folding;
- whole-IDB sign-all applied to a newer build. The joint bench always signs from `("x64", "clang-O2")` (verified `bench.rs:904`).

The measurements are also thin:

- **Fixed sample.** The real gate signs the first 4 functions per library by CRC-32 (`bench.rs:413-425`, `--max-functions 4` at `real-bench.yml:82`). §8 has 87 strong signatures, about 22 per arch. With 0 hits, the rule-of-three upper bound is 3/22 ≈ 0.14 per arch and 3/87 ≈ 0.034 pooled. No current corpus can show strong FP ≤ 0.01, which needs about 300 strong signatures.
- **No negatives.** The real corpus writes `"negative": []` (`real.py:444`).
- **Caps never reached.** The largest image is 1.13 MB, so these silent caps never trigger:
  - 65,536 hint-free candidates, taken in address order (`matcher.rs:32`, `:2605-2609`);
  - a 4M-instruction index (`matcher.rs:46`, `:52`);
  - joint resolution skipped above 2^26 pairs (`joint.rs:76`, `:426`);
  - 32 MB and 128 MB process ranges (`proc_win.rs:91`, `:487`).
- **M8 is not exited.** The weekly `real-bench.yml` has never run (§8). Held-out strong FP (0.113, the one G4 row outside 0.05) has not been re-run since v4.

The runtime defender's path is not the one the bench measures:

- `scan --pid` and hinted `scan` build one `SignatureScanner` and call `scan_pass()` once (verified `main.rs:723-725`). That scanner calls `scan_candidates` with no index or cache (`scanner.rs:194-203`), while the bench measures `scan_in` (audit: `bench.rs:301`).
- Routing the process path through `scan_in` would not be enough. The hinted floors (`MIN_SHAPE_ONLY_SIMILARITY`, `MIN_CONSTANT_ANCHORED_SIMILARITY`) return early when `function_starts().len() < 32` (verified `matcher.rs:1238`, `:730`). `proc_win` never overrides `function_starts`: the only overrides are `elf.rs:210` and `source.rs:163`/`:326`. A live process therefore counts as a small image and skips both floors.
- Inferred: a PE file on disk scanned with `--discovery hinted` has the same exemption.
- Either way, G3 precision says nothing about `scan --pid`.

Hostile headers can still abort a batch run:

- An ELF `NOBITS` section allocates its declared size (`elf.rs:770-771`).
- A PE section is resized to its declared virtual size (`elf.rs:1070-1071`).
- `native-first` has no fuzz job, although G6 says "fuzzed in CI".
- The fixes are on the unmerged `report-gaps` branch (1f7687f, 416593c, 66e8fa2, 83f7f7d; merge base b79da58).

**In short:** the numbers cover one container, one version, two plain toolchains, small C images and the bench's own scan path. Real users hit all the cases left out, and several fail silently.

## 2. New and changed goal rows (for §2)

Targets marked *(proposed)* need the user's OK. "Unmeasured" means no harness exists yet.

| Goal | Row | Now | v1.0 |
|---|---|---|---|
| G1 | Other source version, function source unchanged | unmeasured | within 0.05 of "same build" *(proposed)* |
| G1 | Other source version, function source changed | unmeasured | reported only |
| G1 | Distro package (trixie) vs self-built gcc, same version, same level | unmeasured | reported; target after first measurement |
| G1 | Hardened, `-O3` or LTO profile vs plain, same compiler | unmeasured | within 0.05 of "same level" *(proposed)* |
| G1 | Shared object → PIE, `ET_EXEC` or static executable | static host of all five libraries 0.642 vs same build 0.905, hint-free same arch (RW6) | within 0.05 of "same build" *(proposed)* |
| G1 | PE (clang-cl, MinGW) ↔ ELF, same source | unmeasured | reported; target after RW5 |
| G2 | Joint signed on release N, resolved on N+1: identified precision (apply-names headline) | unmeasured | ≥ 0.98 *(proposed)* |
| G2 | Same, identified answers for functions absent from N+1 | unmeasured | ≤ 0.02 of answers *(proposed)* |
| G3 | Identified precision, real-world tier (drift, distro, flags, C++/ICF) | unmeasured | ≥ 0.98 |
| G3 | Identified precision on the process path (`scan --pid`, `.pdata`-only source) | ungated (`matcher.rs:1238`) | same as hinted file target |
| G3 | Accepted hits per signature per MB of unrelated code, per verdict | identified 0.0025/MB; any verdict 0.18 (x64) to 0.94 (Thumb)/MB on host negatives (RW6) | identified ≤ 0.001/MB; others after measurement |
| G3 | Strong FP on a real negative set | 0 targets scanned | 0.000 with ≥ 5 MB per arch |
| G3 (change) | Rates carry n and a Wilson 95% interval | point estimates | reported; gating is Decision 1 |
| G4 | Start recall on section-less ELF vs `strip --strip-all` | 0, refused (`elf.rs:407-411`) | within 0.01 |
| G4 | Start recall on a raw blob | 0, refused | reported |
| G5 | Index coverage on a 50 MB image | 1.0 at 2.4 MB (590K of 4M instructions); inferred cap at ~16 MB of x64 | 1.0 |
| G5 | Hint-free scan: 150 signatures, 50 MB stripped, 8 cores | 2.4 MB x64, 2 threads: 2.1 s, 134 MB (50 MB unmeasured) | ≤ 60 s, ≤ 2 GB *(proposed)* |
| G5 | `db build --functions`: 1k and 5k functions on 50 MB | 1k on 2.4 MB: 4.6 s, 126 MB (50 MB unmeasured) | reported; target after first measurement |
| G6 (fix) | Fuzzed in CI | false on `native-first` | 60 s per target per push; long campaign on home server |

"Within 0.05" is a point comparison. It stays that way unless Decision 1 changes it.

## 3. Milestones

**Order:** RW1 → RW2 → M8 exit (first green weekly run) → RW3 → RW4 and RW5 in parallel → RW6 → RW7 → RW8. Further M10 feature tuning waits for RW4's numbers. M9's Linux `/proc` source follows RW3, because it is user 3's only non-Windows path.

Every milestone exit includes the held-out run (§4 rule 4), and the first one re-measures held-out strong FP. Every matcher candidate goes through `--fp-report` simulation and `examples/cross_fp` before it is built. Every change to locate or scan output reruns `tests/ida_cli_smoke.py`, plus one licensed-IDA run. Corpus binaries, distro packages and dbgsym live in an uncommitted cache on the home server, and heavy runs happen there.

### RW1. Land hostile-input hardening (M8 / G6; P0)

*Why:* a batch run dies on one malformed file (rule 11).

- Review `report-gaps` on its own before merging. It contains:
  - bounded header allocations;
  - `coverage.rs` budget reporting (`Budget::ReferenceIndex`, `Discovery`, `UnwindCandidates`, `StartSweep`, `UnwindEntries`, `Recoveries`);
  - cargo-fuzz targets with a 60 s CI job (83f7f7d), and `tests/hostile_inputs.rs`;
  - the `serde_yaml` → `serde_norway` swap (765e155);
  - the README, plus new `LICENSE-APACHE` and `LICENSE-MIT` (bb9e14b);
  - PLAN edits: an M8 held-out bullet and a Mach-O / 32-bit x86 non-goal. Keep these and do not duplicate them here.
- Check the YAML swap byte for byte. `signature_id` is the digest of `to_yaml()` (verified `sigfile.rs:244-246`). Compare signature YAML, DB bytes and scan JSON before and after 765e155 for the golden vectors, a toy DB and a real-slice DB. If anything differs, the swap is a document change (rule 16) and goes back to the user.
- Extend the existing `Budget` enum, not a parallel report, with `MAX_HITS_PER_ANCHOR`, `MAX_CANDIDATE_STARTS` (`matcher.rs:29-30`), joint `MAX_PAIRS` skips and process ranges skipped for size (`proc_win.rs:487`).
- Add a `scan` fuzz target: hostile image bytes against 8 golden signatures, hint-free plus joint, with `-rss_limit_mb=1024`.
- Run the long campaign weekly on the home server, not in Actions, because the minutes do not fit. Each crash becomes a `hostile_inputs.rs` case.

*Exit:* the YAML, DB and JSON digests are identical, or the user has signed off on the difference; the per-push fuzz job is green; G6 "fuzzed in CI" is true.

*Effort:* S for the merge, M for the rest.

### RW2. Honest bench (M8; P0)

*Why:* new variants must not leak into existing rows, and a gate must not pass on an empty cell.

- **Build metadata in `ground_truth.json`.** Record compiler, version, level, flags profile, container, source version, origin and configure defines. Derive cells from these fields (audit: `bench.rs:38-45`). Existing reports must stay byte-identical.
- **Pin the docker toolchain.** Pin the docker base image by digest and pin the apt versions (`corpus/docker/Dockerfile:7-12`). This lands as a toolchain commit before any drift comparison.
- **Empty cells.** `FalsePositiveCell` gains `targets` and `target_bytes`, and `compare()` fails a gated cell that scanned 0 targets.
- **Real negative set.** Add 5-10 MB per arch of unrelated C, built with the same matrix. It must be disjoint from the held-out libraries and checked for vendored code.
- **Intervals.** Print Wilson intervals and n for every rate. Use the lower bound for ≥ goals and the upper bound for ≤ goals. Gating stays on the 0.05 point comparison until Decision 1.
- **`--sample-seed`.** Select functions by CRC of seed‖name. Milestone exits use a fresh seed at `--max-functions 24`.
- **Compiler name.** Fix the hardcoded `Some("clang")` (verified `bench.rs:530`) in its own commit. It changes `signature_id` for every gcc sample (`sigfile.rs:245`), so first check that nothing but ids moves and look for id-keyed tie-breaks. Re-save the baseline only with the user's OK (rule 6).

*Exit:* every G3 row in §8 names its corpus, n and interval; no gated cell is empty.

*Effort:* S per item.

### RW3. Gated process path (M12; P0 for the defender, L)

*Why:* the defender's matches currently skip the trust gates that G3 measures.

- **Small-image exemption.** Base the exemption at `matcher.rs:1238` on unwind entries or candidate count (`.pdata` for processes and PE), not on `function_starts()` alone. Treating processes as unstripped is a deliberate choice (`source.rs:167-171`), so this is a design change and needs review.
- **Bench cell.** Add a hinted cell that scans PE or process-like sources through a `ByteSource` exposing only `.pdata` bounds, the way `proc_win` does.
- **Route `scan` and `locate` through `scan_in`,** one commit each:
  1. a per-module `ScanContext` for processes, because frequencies, trust gates and joint grouping assume one image (`matcher.rs:1224-1240`, `joint.rs:420-426`);
  2. file `scan` parity with the bench;
  3. `locate` parity. The plugin calls `scan(...)` today (`main.rs:594-595`);
  4. an `ida_cli_smoke` rerun.

  Measure process-scan cost before making this the default.
- **Error paths.**
  - Refuse PE ARMNT with exit 3. It maps to `Arm32` (verified `arch.rs:98`), and without a mode map `is_thumb` is false (`elf.rs:238-250`). Not checked: whether PE parsing sets `code_pointers`.
  - Check `EI_DATA` in `arch::detect` before it reads `e_machine` little-endian (verified `arch.rs:78`), so big-endian files reach the existing error at `elf.rs:378-382`. This is S.
- **Latent, deferred to the `--watch` item.** The recovery budget is never refilled (`scanner.rs:158`, `:252`), and untouched regions are skipped (`scanner.rs:316-319`). Only tests call `scan_pass` more than once (`tests/scanner.rs:235-279`). When fixed, use a per-pass total plus a per-signature share, both reported.

*Exit:* the process-path G3 row is measured; CLI and bench digests are equal; the plugin smoke test passes.

### RW4. Real-world corpus tier (M8 / M10; P0, L)

*Why:* users 1 and 2 scan releases, distro builds and hardened code. Each item is its own corpus commit carrying ground truth only (rule 10). The tier runs as a separate `--corpus` run, outside the weekly gate at first. Every target is run through `llvm-strip --strip-all`, and the bench asserts that no `.symtab` or `.gnu_debugdata` is left.

- **Version drift.** Add one or two earlier sha256-pinned releases per tuning library, joined on library and name.
  - Tag each pair source-unchanged or source-changed using clang AST ranges. This is its own M item, validated on a known-unchanged set.
  - Held-out drift (zstd, mbedtls) stays held out.
- **Joint drift (G2).** Sign the whole module on N, including functions absent in N+1, and resolve on N+1. Also rotate `JOINT_SOURCE` over one gcc build and one non-x64 build.
- **Flag profiles, mapped per arch.**
  - Hardened, from Debian's `dpkg-buildflags` inside docker, so it matches distro flags exactly.
  - `-fcf-protection` on x64 and `-mbranch-protection` on arm64; arm32 has no equivalent.
  - `-O3`, and `-flto` / `-flto=thin`.
  - gcc 9 for arm32, Thumb and arm64, reported only (firmware toolchains).
- **Containers.** Build PIE, `-no-pie` and glibc `-static` (`libc.a` from `libc6-dev-*-cross`) with gcc first. The clang builds are `-nostdlib` with a shim (`real.py:25`, `:258-260`), so clang containers need a sysroot (Decision 9). Also build ARM32/Thumb `ET_EXEC` without unwind tables.
- **Distro packages.**
  - Debian trixie for same-version cells: the pins at `real.py:100-134` match trixie.
  - bookworm for drift pairs only. Its gcc 12 is our own gcc (`Dockerfile:7`).
  - Fetch by sha256 from snapshot.debian.org (Decision 2). Ground truth comes from dbgsym matched by build-id.
  - This tier has no hinted cells; any later hinted cell would use dynsym only.
- **C++.** Add one pinned C++ library (fmt, snappy or re2) with the same matrix plus an `--icf=all` link. Duplicates go in ground truth as an any-of set, and templated and folded functions are reported separately.
- **Outcomes per pair.** Record present, clone-of (`.isra`, `.constprop`, `.part`, `.cold`) or absent. Report clone recall separately and abstention on absent functions. Split recall by whether the signature has required callee features.

*Exit:* every new row in §2 has a number in §8.

*Candidates* (simulate and run `cross_fp` only; none are built here): `__X_chk` → `X` callee canonicalization, SQLite `__LINE__` constants, and optional callee keys in static targets. All three change features or acceptance, so each needs a spec bump (rule 16). The amalgamation's `__LINE__` count was not re-checked: the file is downloaded, not in the repo.

### RW5. PE tier (M8 / M9; P0 for user 3)

*Why:* every live target is a Windows process (`proc_win.rs` is the only live source), and its modules are mostly MSVC-built PE.

- **RW5a, unblocked.** Build the five libraries as PE DLLs with the pinned LLVM 22.1.5: `clang-cl` + `lld-link`, x64 and arm64, with `/GS` and `/guard:cf` on and off. Add MinGW gcc builds. Report PE↔ELF cells and `.pdata` start recall. Ground truth comes from PDB, read with the pinned `llvm-pdbutil`.
- **PE `.reloc`** as `Module.relocations`, shared with `proc_win`, then delay-load imports. Both change features (rule 4 relocation set, callees), so each needs a spec bump and vectors.
- **RW5b, real MSVC** (Decision 4). Install a pinned Build Tools version from its channel manifest, or use a self-hosted runner, so the hosted image cannot drift the toolset. Normalize CFG dispatch, the security cookie or `__chkstk` only after measuring, one rule per commit.

*Exit:* the PE cells are in §8.

*Effort:* M for 5a, L for 5b.

### RW6. Large haystacks and scale (M13 / G3 / G5; P0 to measure, P1 to fix)

*Why:* user 2 scans firmware and applications, user 3 scans 20-150 MB modules, and FP on 1 MB libraries predicts neither.

- **Wild negatives.** About 10 pinned large distro binaries (libLLVM, libcrypto, Qt5Core, libavcodec) for x64, arm64 and armhf. Use dbgsym to confirm they embed no corpus library. Report hits per signature per MB, by verdict.
- **Needle in a host.** Link the tuning libraries' static archives with `--gc-sections` (plus an LTO variant) into a large PIE. This runs after RW4's static cell.
- **Scale harness.**
  - Targets of 10, 50 and 150 MB; DBs of 1k, 10k and 100k signatures; plus `db build --functions` cost.
  - Gate on deterministic counters: instructions decoded, candidates, peak allocations. Report time from a fixed protocol (idle check, median of 5 runs, fixed `SIGTOOL_THREADS`) without gating on it. Timings swing 3x under load (§8: 221 s vs 66 s).
- **Fixes, each measured on the harness:**
  1. stream the sweep (audit: `sweep.rs:43-55`);
  2. scale index budgets as a pure function of the image and explicit flags, never of detected RAM;
  3. select candidates from `Frequencies.postings`;
  4. build sparse joint rows from postings;
  5. a per-image Tier-0 anchor index;
  6. key interning.

  Fixes 1, 2, 5 and 6 must leave digests unchanged. Fixes 3 and 4 change results on large images by design: they are matcher changes under rules 1 and 2, simulated first. Fix 3 may need a spec bump.

*Exit:* toy and real digests are unchanged; large-tier recall, FP and `cross_fp` deltas are recorded; index coverage is 1.0 at 50 MB; the G5 rows are measured.

### RW7. Input coverage (M9; P1)

*Why:* IoT, Android and firmware analysts get a refusal today, not degraded recall.

- **Section-less ELF.** Take regions from `PT_LOAD`. Take symbols and relocations from `PT_DYNAMIC` (`DT_SYMTAB`, bounded by the hash tables; `DT_RELA`, `REL`, `JMPREL`, `RELR`). Take starts from `PT_GNU_EH_FRAME` and `PT_ARM_EXIDX`. All of these survive strip (rule 10).
- **`SHT_RELR` and Android APS2.** Only RELA and REL are parsed today (verified `elf.rs:574`). Parsing these changes which words count as relocated, and so which constants are dropped (SPEC §2.2). Add lld `-z pack-relative-relocs` and `--pack-dyn-relocs=android` vectors that must equal their unpacked twins. Bump the spec if they do not.
- **`RawSource`.** `--raw FILE --arch A --base ADDR`, hint-free, using the module-range test. Add the Cortex-M vector-table start source only after a pinned `clang --target=thumbv7m-none-eabi` build exists (rule 18).
- **IDA plugin.** When the IDB was loaded as a binary, or its input file is missing (`ida_plugin.py:439-441`), fall back to `--raw` with the IDB's image base.

*Exit:* each source has a CLI test on real lld output, and the ELF real bench is unchanged.

### RW8. Workflows and DB lifecycle (M12 / M14; P1)

- **Batch scan.** `scan --path DIR [--recursive] --jsonl OUT` loads the DB once. Output is sorted relative paths with sha256, arch, mode and status. Status is ok, unsupported, error, or budget-exhausted; it comes from work budgets, never from wall time.
- **Image identity.** `gen --json-report` and `db build --report` record the input's sha256, ELF build-id or PE debug GUID, and the `--functions` list used. A DB is refused on any spec mismatch (verified `db.rs:229-231`). Document `db build --file --functions` as the rebuild path, and make the mismatch error name it. The document format does not change.
- **`--explain` and `--expect RVA`** reuse `explain_candidates` (`matcher.rs:1626`) instead of copying the gates (rule 13). Add `similarity`, `rival` and joint counts to the JSON, and add `db info` and `db list`.
- **Generation warnings.** Self rank, with the hint-free rank computed on an in-memory stripped view. These are warnings only (rule 7).
- **Docs.** One workflow page per §1 user. The user-2 page states that MIPS, PowerPC and big-endian are unsupported.

*Exit:* CLI tests for each command; batch output identical across two runs and with `SIGTOOL_THREADS=1`; the plugin smoke test passes.

**P3 polish, after RW6:**

- `--fail-on`, which changes the AGENTS exit-code contract and the plugin's expectations in the same commit;
- `db export`, `merge` and `remove`;
- a README table generated from the baseline;
- a "looks packed" note: thresholds measured on wild negatives, UPX pinned, RW4 executables as inputs;
- a YAML, DB and JSON digest-equality row across linux-x86_64, windows-x86_64 and macos-aarch64. The arm64 targets are cross-built and never run in CI.

## 4. Deferred and out of scope

| Item | Status | Reason |
|---|---|---|
| Mach-O, 32-bit x86 | Non-goal | Already in the `report-gaps` PLAN diff; `LC_FUNCTION_STARTS` would also need a rule-10 decision |
| MIPS, PowerPC, big-endian | Out of scope | Error message only (RW3); stated in the user-2 docs |
| Rust and Go binaries | Scope statement only | Mangling, monomorphization and runtime-heavy code; not measured |
| `.o`, `.ko`, `.a` relocation | After RW7 | Needs deterministic placement (rule 14) |
| Minidump and ELF core | After RW3 and RW7 | Builds on both |
| `--include-private`, `--watch` | After RW3 | `--watch` takes on the latent scanner bugs |
| Calibrated `p_correct` table | Decision 6 | Close to hard rule 6; output-only if approved |
| Shipped background frequency table | After RW6 data | Acceptance change, so a spec bump |
| Aho-Corasick, C ABI or pyo3 binding | Rejected for now | New dependency; §1 says front-ends are CLI clients |
| Signature `meta:` and bundles | M14 | One spec bump with the compatibility promise |
| Sweeping `score.rs:15-35` | M12, before calibration | Rule 3 |

## 5. Decisions

Taken on 2026-11-19 (the user delegated them):

1. **Intervals.** Report n and a Wilson 95% interval beside every rate; gates stay on the 0.05 point comparison. A goal counts as met only when its point estimate meets it and the report states n.
2. **Network in corpus scripts.** Allowed in the corpus build scripts only (they already download pinned sources), always pinned by sha256 and cached. The tool and scanner stay offline. Held-out libraries get no distro tier until a milestone exit asks for one.
3. **`serde_norway`.** Accepted with #1, whose old-vs-new check found YAML, DB and report outputs byte-identical.
4. **Licence.** The MIT/Apache files landed with #1.
5. **MSVC (RW5b).** Deferred; RW5a (clang-cl, MinGW) first.
6. **Calibration.** Deferred until the real-world tier exists (M12).
7. **Targets.** The *(proposed)* rows in §2 are adopted as written.
8. **Baselines.** Re-saved only when a change moves nothing but ids or labels it intends to move, with the moved cells named in the commit.
9. **Clang containers.** gcc-only for now.

## 6. First steps (each one commit or PR, built and tested on the home server)

1. ~~Merge `report-gaps`~~: done as #1 (2026-11-19); the IDA plugin rework (#2) was merged into `report-gaps` after it closed and is carried onto `native-first` by `real-world`.
2. **`native/src/bench.rs: Report targets scanned per FP cell and fail empty gated cells`** (RW2).
3. **`corpus/docker/Dockerfile: Pin the base image digest and apt versions`**, then **`corpus/real.py: Record build metadata per binary in ground truth`**, with reports byte-identical (RW2).
4. **Trigger `real-bench.yml` once** and record the result, to exit M8.
5. **`native/src/arch.rs: Refuse PE ARMNT and check EI_DATA before e_machine`**, with a CLI test for exit 3 (RW3).
6. **`native/src/matcher.rs: Base the hinted small-image exemption on unwind entries`**, simulated with `--fp-report` and checked with a `.pdata`-only bench cell first (RW3).

**Verified in code:**

- `elf.rs:210`, `:238-250`, `:378-382`, `:407-411`, `:574`, `:770-771`, `:1070-1071`
- `arch.rs:78`, `:98`
- `source.rs:163`, `:167-171`, `:326`
- `main.rs:594-595`, `:723-725`
- `matcher.rs:29-52`, `:730`, `:1224-1240`, `:2605-2609`
- `scanner.rs:158`, `:194-203`, `:252`, `:316-319`
- `joint.rs:76`, `:426`
- `bench.rs:413-425`, `:530`, `:904`
- `sigfile.rs:244-246`
- `db.rs:229-231`
- `proc_win.rs:91`, `:487`
- `real.py:25`, `:100-134`, `:231`, `:258`, `:298`, `:424`, `:444`
- `ida_plugin.py:439-441`
- the `report-gaps` log

All other references come from audits and were not re-checked.