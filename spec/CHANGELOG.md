# Spec changelog

## v6 — real-world targets

`SPEC_VERSION` is `6`. Feature records are unchanged; acceptance changes for
targets that name no function, so v5 documents and DBs are refused (rule 16)
and must be regenerated or rebuilt (`db build --file IMAGE --functions F`).

### Callees in targets that name no function

* A required `callee` without `!` is optional when the target's modules name
  no defined function (SPEC.md §8, "Targets that name no function"), and stays
  identifying for the anchoring floor.
* Measured on the new real-world tier (`corpus/real.py --world`: the tuning
  libraries built with gcc 12 as plain, `-O3`, hardened, LTO, PIE and static
  executable, and the previous release; `bench --corpus ../corpus/build-world
  --max-functions 4`), signing the plain `-O2` shared object, hint-free same
  arch top-1: PIE 0.613 -> 0.700, static 0.525 -> 0.613, merged into PIE
  0.542 -> 0.583; every shared-object target cell unchanged. Hint-free top-1
  hits over the tier 9672 -> 9827. Strong FP 0.043 and hinted any-verdict FP
  0.070 unchanged; hint-free any-verdict FP 0.105 -> 0.132 (within the 0.05
  tolerance; the new hits are in unrelated PIE and static images); identified
  precision hint-free 0.973 -> 0.972 (5968 -> 6099 correct). The real corpus
  (`--max-functions 4 --joint`) is byte-identical apart from cost: every
  target there is a shared object.
* Lost: waiving a callee in any target that lacks its name. Unrelated
  libraries lack it too, so on the real corpus any-verdict FP rose arm32 0.117
  -> 0.217, arm64 0.083 -> 0.158, merged 0.019 -> 0.087, failing the gate.
  Waived callees also left signatures with no identifying key, which the
  anchoring floor then let through; they now stay identifying.

## v5 — in-module constants, matcher and trust rules

`SPEC_VERSION` is `5`. `const` records change for ELF shared objects and
PIEs, so a v4 document or DB is refused. The matching, trust-label, and
joint rules below were developed on separate branches from v4 and merged
with it (`integrate-matcher`); each entry gives the numbers it was measured
with, and the last section the combined result.

### In-module constants

* A value is an address only when the code uses it as one (SPEC.md §2.2):
  PC-relative or absolute memory references, as before, and in an image that
  can be loaded anywhere (ELF `ET_DYN`), a word a dynamic relocation writes
  (the literal-pool cell, or the bytes of an x86 immediate). Every other
  value is a constant even inside the module span. v4 dropped every value
  inside the span; a shared object maps at 0, so it lost real constants
  (zlib's `0xfff1`, LZ4 sizes, `0x10000`), differently per build (image sizes
  differ) and per load base. Images without a relocation table (`ET_EXEC`,
  relocatable objects, PE, live processes) keep the range test. Decided by
  the user on 2026-11-17 (AGENTS.md hard rule 4, PLAN.md rule 15).
* ARM32/Thumb: an unrelocated in-image pool word now stays pending, so gcc's
  PIC `ldr r0, =.LC0-(.LPIC0+8); add r0, pc, r0` resolves to the string
  instead of to the raw offset. (The `cross-compiler` branch had resolved
  the same offsets while also keeping the word as an absolute reference,
  which read string tails out of `.dynstr`; that change was not merged.) `ldr rd, [pc, rm]` resolves its GOT slot before the offset
  register is flushed; before, a GOT offset outside the span leaked as a
  constant (`0x103d4` in the `arm32-pic` vectors at a high base).
* AArch64: a load from an `adrp` page into another register leaves the page
  in its base register, so the PLT stub's `ldr x17, [x16, #o]; add x16, x16,
  #o` resolves the `add` instead of flushing `#o` as a constant.
* New golden vectors: the fixture as `-fPIC -shared` objects (`*-pic-*`) for
  all four architectures, with their relocation slots; `golden.rs` loads each
  at 0 and at `0x40000000` and requires identical features.
* An identified answer resting on a direct neighbour's evidence (or joint
  votes) needs similarity 0.42 instead of 0.3
  (`MIN_ANSWER_SIMILARITY_NEIGHBOUR`). The resolved PIC strings and kept
  constants give twins and thin wrappers shared neighbour evidence
  (`cJSONUtils_GeneratePatches` and its `CaseSensitive` sibling call the same
  helper), which at 0.3 lowered hint-free identified precision 0.981 ->
  0.970. Only the label and the joint seed move; top-1 recall does not.

Simulated first (`examples/in_module_consts`: in-range values the variants
keep on the stripped real corpus, all 16272 ground-truth functions; then the
full real bench per variant behind a temporary switch, `--max-functions 4
--joint`, 2 threads). Under the relocation rule 20-30% of functions gain an
in-range `const` record (x64 797, arm64 997, arm32 1138, Thumb 1115 of 4068
each); no text relocation occurs in the corpus, so no immediate is dropped
for its relocation. Variants (hint-free top-1 same arch other compiler /
cross opt / other arch, hint-free FP, identified precision hint-free):

| variant | other compiler | cross opt | other arch | FP | id. precision |
|---|---|---|---|---|---|
| v4 range test | 0.308 | 0.254 | 0.306 | 0.154 | 0.981 |
| relocation rule (built) | 0.392 | 0.344 | 0.374 | 0.117 | 0.970 |
| + drop pending values used as an ARM32 memory base or index | 0.392 | 0.344 | 0.376 | 0.117 | 0.969 |
| + drop values equal to a string, section, unwind, or export start | 0.390 | 0.343 | 0.376 | 0.117 | 0.969 |
| decoders keep the range test, features only | 0.365 | 0.317 | 0.335 | 0.146 | 0.976 |

Lost: the memory-base/index drop moved no row by more than 0.002 (the
`ldr rd, [pc, rm]` fix already covers the GOT offsets it targeted). The
exact-start test lowered strong FP 0.017 -> 0.012 but cost joint cross arch
cross opt 0.522 -> 0.511 and same arch cross opt 0.587 -> 0.572, and depends
on the load base (a value is an RVA-exact start only at base 0). Features-only
keeps the pool words as references and the PIC offsets broken: about half
the gain.

Measured (built rule against the v4 baseline, real corpus, `--max-functions
4 --joint`): hint-free top-1 same build 0.817 -> 0.835, other compiler 0.308
-> 0.392, cross opt 0.254 -> 0.344, other arch 0.306 -> 0.374, other arch
other compiler 0.216 -> 0.270, other arch cross opt 0.183 -> 0.237, merged
held-out arch 0.397 -> 0.456; hinted other arch 0.329 -> 0.365. FP strong
0.040 -> 0.017, any-verdict 0.111 -> 0.105, hint-free 0.154 -> 0.117,
negative 0.000. Identified answers hint-free 2801 -> 3787 (correct 2747 ->
3672), precision 0.981 -> 0.970; hinted 1797 -> 2375 (correct 1774 ->
2349), 0.987 -> 0.989. Joint (G2) other
arch same build 0.777 -> 0.792, other compiler 0.571 -> 0.625, cross opt
0.466 -> 0.523, same arch cross opt 0.540 -> 0.587, same arch other compiler
0.702 -> 0.708. 61 cells dropped past tolerance (23 hint-free, 38 hinted;
60 recall cells, 42 of them from merged signatures and 39 into a 32-bit
target, `->thumb` 27 and `->arm32` 12, plus the hinted zlib library row
merged held-out arch same level 0.592 -> 0.512; one or two functions
each): struct
field offsets now kept differ between 64- and 32-bit layouts (zlib
`inflateCopy`: `0x1be4`/`0x1bf8`/`0x558` on arm64, `0x1bc0`/`0x1bd0`/`0x534`
on Thumb), and the 64-bit signature requires them. In the diagnosis
(`examples/diagnose_cross`, 4 functions per image) acceptance of the true
function rose in all 16 arch pairs (thumb -> thumb 0.253 -> 0.415, arm64 ->
thumb 0.283 -> 0.321) and fell for 110 of 11040 pairs.

Neighbour answer floor, simulated on the v5 hint-free logs (`bench
--fp-report`; hinted answers do not move between 0.3 and 0.5), correct /
wrong identified answers: 0.3 3672 / 115 (0.970), 0.4 3375 / 74 (0.979),
0.42 3321 / 64 (0.981, built), 0.45 3256 / 57 (0.983), 0.5 3158 / 48
(0.985). Of the 73 wrong answers new at 0.3, 46 are
`cJSONUtils_GeneratePatches` landing on its sibling: v4 resolved the arm32
gcc PIC strings to string tails (`SON_InsertItemInArray`), so the
neighbour keys never matched. Built and measured (same bench): hint-free
identified precision 0.970 -> 0.981 (answers 3787 -> 3385, correct 3672 ->
3321; v4 had 2801 / 2747), every G1 row and FP rate unchanged, joint rows within
0.001 (cross arch cross opt 0.523 -> 0.522, other compiler 0.625 -> 0.624,
same build 0.792 -> 0.793, same arch cross opt 0.587 -> 0.588).

### Strong verdict and unanchored matches (measured on v4)

Measured on the tuning corpus only (`corpus/build-real`, `bench
--max-functions 4 --joint --fp-report`, simulated offline on the logged
scans, then built and benched).

* `strong` needs at least 2 required features that identify a function by
  themselves (`validate::STRONG_MIN_IDENTIFYING`). All 7 strong signatures
  with a corpus false positive had exactly one (a hash constant or an
  in-image callee) beside `memset`/`memcpy` and the constants 0-5, and every
  false hit matched without it. 87 of 173 signatures stay strong, with 1
  false positive (0.011); 3 identifying features keep 85 with none; 1
  changes nothing.
* Unanchored matches (the signature has identifying required features, the
  match holds none of them) need similarity 0.25 in both modes
  (`matcher::MIN_UNANCHORED_SIMILARITY`). Measured (full real bench,
  `--joint`): hint-free any-verdict FP 0.154 -> 0.146, hinted any-verdict
  0.111 -> 0.109, strong 0.011 -> 0.000 (under the rule above), joint sets'
  false-hit signatures cjson 21 -> 20 and zlib 8 -> 6, hint-free top-1 3704
  -> 3705, hinted 4177 -> 4176. Dropped past tolerance: merged->arm64
  clang-O2 -> clang-O0 hint-free top-1 0.412 -> 0.353 (`pagerWriteLargeSector`,
  a true match at similarity 0.228). Lost: 0.22 (built and benched) sits in
  the single signatures' gap (their false hits reach 0.218) and keeps that
  match and hinted 4177, but removes none of the joint sets' false hits
  (0.232-0.244); simulated 0.3 costs 8 hint-free top-1, 0.35 costs 15 / 27
  for 3 more signatures, rejecting every unanchored match 107 / 102; 0.21
  removes 1 of the 5 hint-free signatures.

### Cross-ISA shape corroboration (measured on v4)

* A low-information signature scanned in an image of another ISA family
  (`x64`, `arm64`, `arm32`; Thumb is `arm32`) also corroborates its shape on
  the ISA-stable dimensions alone (`cfg:blocks`, `cfg:edges`, `cfg:loops`,
  `ops:branch`, `ops:call`, `ops:cond`, `ops:ret`, `ops:store`) when the
  candidate matches at least 4 distinct required features (SPEC.md §8).
  Diagnosis (`examples/diagnose_cross`, the 1200 true cross-ISA same-build
  pairs at `--max-functions 4`): 61% of those signatures are
  low-information, and of the 761 true pairs that failed acceptance, 297
  failed only the shape gate; across ISAs the `stack`, `arith`, `logic`,
  `load`, `move` buckets of the true function agree 0.12-0.36 of the time,
  `cfg:loops` and `ops:call` 0.82-0.88.
* Real corpus, `bench --max-functions 4 --joint`, hint-free top-1: other
  arch same build 0.306 -> 0.342, other arch other compiler 0.216 -> 0.219,
  other arch cross opt 0.183 -> 0.184, merged same opt 0.652 -> 0.678,
  merged held-out arch same opt 0.397 -> 0.448; hinted: other arch same
  build 0.329 -> 0.338, merged held-out arch same opt 0.448 -> 0.464. Top-1
  cells up 48 hint-free and 20 hinted, none down; same-arch rows, every
  false-positive rate, and identified answers (hint-free 2747/2801, hinted
  1774/1797) unchanged; joint top-1 8470 -> 8472 of 15594 (scanned alone
  4165 -> 4227; other arch same build 0.458 -> 0.476). The bench measures
  false positives in the signature's own arch only, so cross-ISA false hits
  were measured separately (`examples/cross_fp`: each sample signature
  scanned hint-free against the other libraries' stripped images in the
  other ISA families, same build): 66 -> 70 of 1200 (signature, target
  arch) pairs with a hit (0.055 -> 0.058), hits 413 -> 417, 0 identified
  answers before and after.
* Swept offline (true cross-ISA pairs accepted, `diagnose_cross`; false hit
  pairs of 1200, `cross_fp`, both from a build with no floor), same build:
  off 0.366 / 66; floor 0 0.475 / 172; 2 0.447 / 132; 3 0.426 / 96; 4 0.410
  / 70; 5 0.388 / 66; 6 0.376 / 66; every stable dimension instead of 0.8,
  no floor 0.393 / 108, floor 4 0.369 / 66; at floor 4, `ops:cmp` added
  0.398 / 68, `ops:store` dropped 0.412 / 70, `ops:store` and `ops:branch`
  dropped 0.415 / 70 (2-6 pairs; not built). Floor 4 keeps the false hits
  within 0.003 of the rule's absence (all shape-only) for 0.022 more
  acceptance than floor 5.

### Joint tail-call edges (measured on v4)

* The call graph joint resolution reads is symmetric: a function's callers
  are its direct-call sites plus every candidate whose callees include it.
  Callees held tail calls and callers did not (the code index records call
  instructions only), so an `out:` link to a tail-called neighbour was
  counted by the module gate but never earned the link bonus, and thin
  wrappers of different helpers stayed tied. Simulated on the v4 joint
  dump, then measured on the full real corpus (`bench --max-functions 4
  --joint`, hint-free joint section, top-1 of 2034 / 2034 / 8136 / 678 /
  2712): other arch same build 1580 -> 1611 (0.777 -> 0.792), other
  compiler 1161 -> 1178 (0.571 -> 0.579), other arch cross opt 3788 -> 3868
  (0.466 -> 0.475), same arch other compiler 476 -> 481 (0.702 -> 0.709),
  same arch cross opt 1465 -> 1477 (0.540 -> 0.545). Joint false hits in
  unrelated libraries unchanged (46 placements, equal to scanned alone in
  every library); wrong joint top-1 answers 4515 -> 4495. Every other bench
  section unchanged. Capping the merged caller list at 16 like
  `callers_of` gained less in simulation (0.789 / 0.576 / 0.471).

### Shape waiver on a shared neighbour key (measured on v4)

* Hint-free acceptance (SPEC.md §8): a low-information signature's
  candidate that fails only shape corroboration is accepted when it shares
  a neighbour key and reaches similarity 0.4. Full real bench
  (`--max-functions 4 --joint`) on top of the unmerged ARM32 PIC change, hint-free
  top-1: other compiler 0.335 -> 0.356, cross opt 0.282 -> 0.303, other
  arch 0.351 -> 0.387, other arch other compiler 0.253 -> 0.267, other arch
  cross opt 0.224 -> 0.243, merged held-out arch 0.459 -> 0.521, same build
  0.835 unchanged (4208 -> 4487 hits); hinted unchanged. Every FP rate and
  joint false hits unchanged; joint rows within 0.001. Identified precision
  hint-free 0.973 -> 0.969: 21 of the 225 waived identified answers are
  wrong, 13 of them `LZ4_loadDict` on one shared caller constant. Floors
  swept offline on the waived matches (`bench --fp-report`): 0.45 4379 hits,
  precision 0.970; 0.5 4296, 0.971; 0.6 4221, 0.972; at least two neighbour
  keys 4222, 0.972; a direct callee's key 4228, 0.973. Rejecting waived
  matches whose only neighbour key is one caller constant keeps all 4487
  hits at precision 0.972, but rests on that one function: not built.
  Earlier x64 + arm64 slice simulation (before that change, not
  re-measured): no floor and 0.3 / 0.35 lost precision.

### Trust labels after the merge (measured on v5)

Simulated on the merged tree's logs (`bench --fp-report`, both modes), then
built and benched; only labels and the joint seeds move, never top-1.

* A waived match (above) is never `identified` unless joint resolution
  placed it with preserved links (`joint:N`, `N ≥ 1`). Waived answers were
  175 correct and 31 wrong hint-free: `LZ4_loadDict` 13 in lz4 and 11 in
  unrelated libraries on the neighbour constant `0x10000` (kept since
  in-module constants), `adler32_combine` 4 unrelated on `0xffff`.
  Identified precision hint-free 0.974 -> 0.981 (3497 / 3592 -> 3322 /
  3386), hinted 0.989 unchanged; joint other arch cross opt 0.528 -> 0.529,
  same build 0.808 -> 0.809.
* A first match with a close *rival* is a `candidate` (SPEC.md §8): another
  function holding every identifying key it holds (own keys from the
  frequency postings; call-graph siblings for neighbour-only evidence) and
  resembling the signature within 0.1 of it (`matcher::RIVAL_MARGIN`).
  `cJSONUtils_GeneratePatches` and its `CaseSensitive` twin hold the same
  keys; gcc's arm32 copy materialises its `false` argument from a
  comparison (`moveq r6, #1`), so its signature requires `0x1` and lands on
  the twin, with the true function as the rival. Swept, precision hint-free
  / hinted (correct answers): none 0.981 (3322) / 0.989 (2349); 0.02 0.982
  (3316) / 0.991 (2348); 0.05 0.986 (3244) / 0.993 (2345); 0.1, built,
  0.993 (3163) / 0.994 (2267); 0.2 0.993 (3015) / 0.995 (2185). The answers
  with a rival 0.05-0.1 below were 77% right hint-free (81 / 24), short of
  the promise; the 0.1-0.2 band was 148 correct for 1 wrong. Measured:
  hint-free 0.981 -> 0.993 (3163 / 3184), hinted 0.989 -> 0.994 (2267 /
  2280); joint other arch cross opt 0.529 -> 0.531, other compiler 0.629 ->
  0.630, same build 0.809 -> 0.810, same arch cross opt 0.592 -> 0.593;
  every FP rate and top-1 cell unchanged. Lost, simulated first on the v4
  `cross-compiler` logs (neighbour floor 0.3): requiring the
  runner-up in the ranked list to hold a superset of the first's
  identifying keys (any margin) cost 289-702 correct answers for 15-38
  wrong, because ordinary library siblings share callees too, and it misses
  twins the acceptance gates removed; relabelling neighbour-only answers
  with fewer than two keys cost 364 correct for 22 wrong.

### Combined (measured on v5)

Real corpus, `bench --max-functions 4 --joint`, against the `native-first`
v4 baseline (cross-ISA shape included): hint-free top-1 same build 0.817 ->
0.835, other compiler 0.308 -> 0.412, cross opt 0.254 -> 0.365, other arch
0.342 -> 0.433, other arch other compiler 0.219 -> 0.287, other arch cross
opt 0.184 -> 0.259, merged held-out arch 0.448 -> 0.558 (3778 -> 4879
hits); hinted 4197 -> 4750 hits. Joint other arch same build 0.777 ->
0.810, other compiler 0.571 -> 0.630, cross opt 0.466 -> 0.531, same arch
other compiler 0.702 -> 0.714; joint false hits equal scanned alone (46 ->
41). Identified precision hint-free 0.981 -> 0.993 (2747 / 2801 -> 3163 /
3184), hinted 0.987 -> 0.994 (1774 / 1797 -> 2267 / 2280). FP hint-free
0.154 -> 0.115, hinted any-verdict 0.111 -> 0.105, strong 0.040 -> 0.025,
negative 0.000.

### Constant-anchored hinted matches (measured on v5)

A matcher rule; the document and `SPEC_VERSION` (5) are unchanged.

* A hinted match whose identifying keys are all constants needs similarity
  0.2 (`matcher::MIN_CONSTANT_ANCHORED_SIMILARITY`, the `MIN_SIMILARITY`
  floor hint-free mode applies to every match). The three strong false
  positives at v5 were `LZ4_loadDict` (Thumb, and merged x64+arm64) in
  sqlite on `0x10000` / `0x4000`, and merged `inflateCopy` in lz4 on
  `0x558`, at similarity 0.01-0.12: in-module constants are kept since v5,
  and these values also occur in unrelated code.
* Simulated on the v5 logs (`bench --max-functions 4 --joint --fp-report`,
  hinted recall scans and unrelated-library hits), then built. Every
  constant-anchored hinted hit in an unrelated library is below 0.19 (172
  hits); the lowest constant-anchored true top-1 match is 0.223
  (`inflateCodesUsed`). Swept (hinted top-1 hits of 4750, strong FP,
  hinted any-verdict FP): floor on constant-anchored matches 0.1 4750 /
  0.008 / 0.087; 0.13 4750 / 0.000 / 0.081; 0.15 4750 / 0.000 / 0.077; 0.2
  and 0.22 4750 / 0.000 / 0.075; 0.25 4748 / 0.000 / 0.075. The same floor
  on every hinted match: 0.1 4750 / 0.008 / 0.087; 0.13 4750 / 0.000 /
  0.081, 0.002 below a true callee-anchored top-1 match
  (`pagerWriteLargeSector` across ISAs at 0.132); 0.15 4743; 0.2 4703 /
  0.000 / 0.075. Restricting it to matches holding an identifying required
  feature gives the constant-only numbers to 0.18 and costs 1 top-1 hit at
  0.2. Identified precision does not move in any variant (those matches
  are never answers).
* Measured (full real bench, `--max-functions 4 --joint`): strong FP 0.025
  -> 0.000 (3 -> 0 of 121), hinted any-verdict 0.105 -> 0.075 (61 -> 44 of
  583), negative 0.000; every top-1 cell in both modes, every hint-free
  cell, identified precision (hint-free 0.993, hinted 0.994), and the joint
  section unchanged. One hinted found-anywhere cell dropped past tolerance:
  merged->arm64 clang-O0 -> gcc-O2 0.562 -> 0.500, merged `inflateCodesUsed`
  in gcc-O2 zlib, a true match ranked second at similarity 0.193 (below a
  wrong first match at 0.330; it was never top-1).

## v4 — coverage, inherited evidence, trust labels, joint assignment

`SPEC_VERSION` is `4`. Feature records change (inherited `inl:` records,
thunk and `-fno-plt` callees, the stripped ARM32 mode map), and acceptance,
evidence labels, and joint resolution change, so a v3 document or DB is
refused rather than matched with different semantics.

### Coverage (M9)

* Stripped ARM32 mode map: an even (ARM) relocated pointer into code whose
  region votes Thumb marks ARM mode only when it is word-aligned and its own
  words vote ARM. GCC computed-goto tables (lua's `luaV_execute`) are
  relocated like function pointers but name even labels inside Thumb
  functions; before, each one switched the rest of that function to ARM
  decoding, so features of such functions in stripped Thumb images change.
* Callees through lld Thumb-2 and ARM PI thunks (`movw`/`movt ip`, `add ip,
  pc`, `bx ip`) resolve to what the thunk reaches (usually a PLT entry, so
  the import name). Before, a stripped image recorded the thunk's address
  and an unstripped one its `.symtab` name (`__ThumbV7PILongThunk_f`);
  linker thunk and veneer names no longer stop thunk following. Affects
  `callee` records of clang/lld ARM32 and Thumb shared objects.
* AArch64 calls through a register loaded from a page-relative pointer slot
  (`adrp xN; ldr xN, [xN, #lo]; blr xN`, the `-fno-plt` form, and `br xN`
  tail calls) record the callee the slot names (an import, else the
  pointer it holds), like x86-64 `call [rip+slot]`. Any other use of the
  register in between, or a control transfer, drops the slot.

### Inline-invariant evidence (M10)

* Inline-invariant evidence (SPEC.md §1.4): a function's features also carry
  the `str`, `const`, and `callee` features of its small direct callees (at
  most 80 instructions, at most 32 callees), as *inherited* records with
  keys prefixed `inl:`. Signatures are still generated from own features
  only; the matcher credits a signature feature the candidate holds only as
  inherited at 0.5 of its weight (score and similarity), never as distinct
  required evidence, never as identifying or a named callee. Neighbour keys
  use own features only. Measured hint-free on the stripped real corpus
  (x64 + arm64): with `--max-functions 4`, other compiler 0.400 -> 0.408,
  cross opt 0.302 -> 0.307, other arch other compiler 0.292 -> 0.296, merged
  cross opt 0.353 -> 0.363, FP rate 0.125 unchanged, identified precision
  0.891 -> 0.888; with `--max-functions 24` (recall only), other compiler
  0.460 -> 0.467, cross opt 0.353 -> 0.365, other arch other compiler
  0.368 -> 0.379, other arch cross opt 0.301 -> 0.312, identified precision
  0.878 -> 0.876. Full credit (inherited keys matched like own ones) gained
  4-6 points of top-1 but cost 0.03 FP rate and 0.025-0.05 identified
  precision: every caller of a small function then matched its signature.

### Trust labels and shape-only floors (M12)

* Shape-only matches need similarity at least 0.3 in both discovery modes,
  and hinted shape-only matches need the 6 matched features hint-free already
  required, on images with at least 32 known functions (SPEC.md §8).
* Evidence labels (SPEC.md §8): `identified` is reserved for the first match
  when it is untied and similar enough for the evidence it rests on;
  `candidate` is new, for identifying evidence that is not the answer.
* Real corpus (`--max-functions 4`): identified precision hint-free 0.848 ->
  0.981, hinted 0.687 -> 0.987; FP hint-free 0.163 -> 0.156, hinted
  any-verdict 0.196 -> 0.113, strong 0.072 -> 0.042. Top-1 recall: hint-free
  unchanged, hinted 4127 -> 4137 hits; hinted found-anywhere 4903 -> 4637
  (shape-only lookalikes below the top removed).

### Joint resolution 2.0 (M11)

Joint resolution's output semantics change; feature records, the signature
document, and single-signature acceptance do not (SPEC.md §8).

* Greedy pinning rounds are replaced by a one-to-one assignment of each
  module's signatures to every target function with similarity at least
  0.2, weighed by similarity, call-graph degree agreement, and the scan's
  `identified` answer, refined by preserved links, and trusted only when it
  preserves at least 6 link ends and a fifth of those it could.
* `joint:N` now counts links the mapping preserves; `joint:0` (placed without
  a preserved link) ranks first but is not identifying. Seeds use
  `identified_answer`; the release step is gone (no measurable effect).
* Real corpus, hint-free, `bench --joint` (x64 clang-O2 module sets): other
  arch same build 0.537 -> 0.771, other arch other compiler 0.313 -> 0.527,
  other arch other opt 0.265 -> 0.430, same arch other compiler 0.437 ->
  0.670, same arch other opt 0.346 -> 0.499. Joint false hits in unrelated
  libraries equal scanned-alone in every library (zlib 10 -> 8 of 480).
* Rejected in simulation (`bench --joint-report`): global best-first pinning
  (+0.002), Hungarian instead of greedy (within 0.003), sibling relations
  through a shared unsigned neighbour as a bonus (-0.02 to -0.05) or as
  acceptance (zlib false hits 8 -> 18), pair floors 0.15 / 0.1 (false hits
  46 -> 259 / 639), accepting graph-supported placements without the module
  gate (zlib 8 -> 10), and breaking weight ties by address (+0.005, but a
  guess). Call order is not in the signature (`links` are sorted sets), so
  only order-free degrees are used.
* Fix, before v4 was published: joint resolution weighs (signature,
  function) pairs by the scan's similarity (§8), inherited keys included
  at `INHERITED_CREDIT`. Its own copy of the formula predated inherited evidence and counted every `inl:`
  key of a candidate as extra weight, so callers of small helpers (the true
  function among them) lost similarity and fell below the 0.2 pair floor.
  Real corpus, hint-free, `--max-functions 4 --joint`, G2 rows (v4 baseline
  -> now): other arch same build 0.763 -> 0.777, other arch other compiler
  0.493 -> 0.571, other arch cross opt 0.402 -> 0.466, same arch other
  compiler 0.633 -> 0.702, same arch cross opt 0.469 -> 0.540; joint false
  hits in unrelated libraries unchanged and equal to scanned-alone. Lost:
  own-feature similarity only (inherited keys ignored on both sides) reached
  0.777 / 0.536 / 0.434 / 0.671; the 0.2 floor re-measured (0.15 joint false
  hits cjson 0.049 -> 0.407, lz4 0.015 -> 0.128, zlib 0.017 -> 0.158; 0.25
  0.760 / 0.497 / 0.416 / 0.683).

## v1 — M1 extraction

Initial spec, implementing docs/history/PLAN-v0.5.md section 4 for x86-64 and AArch64.

* Feature kinds `str`, `const`, `callee`, `cfg`, `ops` with canonical text forms.
* 14 instruction classes with ABI-independent `stack` and `vector` buckets.
* Ignored-instruction sets for x86-64 padding/hot-patch/CET and AArch64
  padding/PAC/BTI.
* Address normalization for RIP-relative operands, `adrp` pairs, literal pools,
  and pointer-valued constants.
* Constant sign-extension rule and constant-source instruction allowlists.
* BLAKE2b-16 with `person="sigtool.v1"` for hashed values.
* Bounded recovery budgets and the tail-call rule.

## v1 — M2 scoring and signature document

Adds the generation-time half of the format. Extraction is unchanged, so
feature records, golden vectors, and bounds are unaffected and `SPEC_VERSION`
stays `1`.

* Fixed field order for the signature document (SPEC.md §7), canonical YAML as
  the identity, and a strict reader that rejects a foreign `spec_version`,
  unknown kinds, duplicate features, unknown anchors, and path-like module
  names.
* Base weights per kind, string and constant rarity multipliers, and optional
  corpus IDF; shape features are optional and never anchors.
* Anchor selection (up to four data features), tier-dependent match thresholds
  (0.75 with two or more anchors, 0.85 with one, 0.95 with none), and
  `min_distinct` clamped to 1–3.
* Confidence tags `single-arch`, `multi-arch`, `low`.
* Quality report with `strong`, `weak`, and `small` verdicts.

## v1 — M4 cross-arch

* ARM32 and Thumb extraction: per-address mode from the ELF Thumb bit,
  condition-suffix stripping, `it`-block normalization, `movw`/`movt` and
  `mvn` materialization, literal-pool resolution with pool cells extending
  function bounds (SPEC.md §1.3, §2, §3).
* Multi-sample merging: intersect stable features, demote subset features to
  optional half weight, stable anchors only, mandatory self-test on every
  sample (SPEC.md §8).
* `locate` command semantics: scan a second image or process with an existing
  signature and report accepted matches, best first.

## v1 — M6 reference scanner

* Tier 1 rate-limiting: `RecoveryBudget(remaining=N)` shared across all signatures
  in one scan pass; Tier 0 is un-budgeted.
* `ReferenceIndex`: per-region executable sweep (bounded at 200 K instructions
  and 4096 resyncs per index lifetime, global budget) recording data-address to
  referencing-instruction map so string anchors become candidates through the
  code that uses them. Changed regions re-index subtract their old count before
  adding the new one.
* Page hashing (CRC-32 over 4 KiB pages): unchanged regions skip Tier 0 and
  Tier 1 entirely on later passes. Private-memory regions are scanned first,
  then changed image regions, then untouched ones.
* Signature identities (`signature_id`) are pre-computed once at construction
  rather than serialized per lookup; a skipped incremental pass costs fractions
  of a millisecond instead of tens of milliseconds.
* `_candidate_starts` now ranks exact hint starts first and swept starts
  ascending-by-address (prologue-first), reducing wasted recoveries on
  mid-function candidates.
* Self-test falls back to index-based discovery for string-only signatures when
  neither anchors nor known function starts can reach the target.

Measured (Python reference, Windows x64 interpreter, 44 MiB address space, 138
regions, 16 signatures): full pass 98 s CPU / 0.83 s wall, 200 K indexed
instructions (truncated); second pass 16 ms wall with page hashing alone. The
corpus profile shows the dominant hot spot is Capstone decode inside
`ReferenceIndex.index_region`, not candidate recovery. The native port (M7) is
the planned follow-on.

## v1 — M3 reference matcher

* Anchor needles per kind, with the searchable encodings and the constants that
  are deliberately not searchable (SPEC.md §8).
* Candidate generation from known function starts plus a bounded backward
  instruction sweep from constant hits, ranked and capped.
* Hint-free discovery mode (`hints=False`): no symbol starts, no symbol bounds
  during recovery; candidates come from the sweep alone. Reported separately by
  the harness so comparison quality and discovery are distinct measurements.
* Weighted comparison where optional features can only add evidence, gated by
  `thresholds.match` and `min_distinct`; overlapping spans collapse to one
  match.
* Self-test rule: generation runs the matcher and refuses to emit a signature
  that is not accepted at the sampled function start. When no anchor or known
  function start can reach the function, the weaker structural check applies
  instead (the signature must still describe those bytes exactly).

Not yet specified: `multi-arch` merging, a data-reference index for string
candidate discovery, and reference-scanner budgets (M4–M6).

## v1 — M7 native scanner port

Adds a Rust implementation under `native/` that implements the same spec for
x64. Feature semantics, canonicalization, hashing, weights, and thresholds are
unchanged, so `SPEC_VERSION` stays `1` and the golden vectors are unaffected.

* Native extractor, matcher, scanner, merge, and signature document mirror the
  Python reference and are parity-tested against the x64 golden vectors,
  `tests/test_scanner.py`, and the x64 corpus slice of
  `tests/baseline/bench.json`. All 51 x64 corpus signature ids are identical
  to Python.
* `iced-x86` replaces Capstone as the x64 decoder and `yaxpeax-arm` replaces it
  for AArch64; per-arch normalization rules are the same tables, including
  `adrp`/`adr` address rebasing, ARM32/Thumb literal pooling, `movw`/`movt`
  materialization, and IT-block normalization. Feature semantics are unchanged,
  so `SPEC_VERSION` stays `1`. ARM32 and Thumb decode through Capstone, the same
  engine as the Python reference, so the ARMv7 media group and VFP/NEON decode
  identically; `iced-x86` handles x64 and `yaxpeax-arm` AArch64, and every
  arm32/thumb golden vector matches with no skips.
* Binary signature database (SPEC.md §10): a deterministic, mmap-friendly file
  with a 64-byte header, a 40-byte-record table sorted by `signature_id`, and a
  padded payload blob. The header carries `SPEC_VERSION`, and table/payload
  CRC-32 checks detect corruption.
* CLI (`sigtool-native`): `gen`, `locate`, `scan` (YAML or `--db`), `merge`,
  and `db build`, with the same exit-code contract as the Python front-end.
  `merge` emits the same document as the Python implementation for the same
  samples; no feature, weight, or threshold semantics changed.

## v1 — native matcher precision

Matching and reporting only; extraction, feature records, and the signature
document are unchanged, so `SPEC_VERSION` stays `1`.

* Shape corroboration for low-information signatures (SPEC.md §8). On the
  corpus it halves any-verdict false positives (0.227 → 0.113 against other
  sources, 0.263 → 0.105 against the negative corpus) and raises top-1 recall.
* The `strong` verdict counts only required data features, so a merged
  signature is no longer strong on features one sample lacks.

## v3 — neighbour evidence

`SPEC_VERSION` is `3`. Feature records are unchanged; the signature document
gains `neighbours`, and hint-free acceptance changes, so a v2 document is
refused rather than matched without the evidence it lacks.

* `neighbours` (SPEC.md §7): identifying `str` and `const` keys of the
  function's callers and callees, up to two hops. Calls through a PLT stub to
  an export the image defines itself reach that export.
* Hint-free acceptance (SPEC.md §8): shape-only matches need 6 matched
  features unless they share a neighbour key; a shape-only match sharing no
  neighbour key is rejected when the signature has at least 2; shared keys
  rank first and are reported as `near:` keys. On the stripped real corpus
  this took the hint-free FP rate from 0.203 to 0.163 with every aggregate
  top-1 row equal or higher.
* `links` (SPEC.md §7): direct callers and callees as module RVAs, and joint
  resolution (SPEC.md §8) for signature sets from one module. Whole-module
  sets from the x64 clang-O2 build, scanned hint-free in every other stripped
  build of the same library, gain 8-10 points of top-1 (cross-arch other
  compiler 0.233 -> 0.313, cross-arch cross-opt 0.188 -> 0.266); false hits
  in unrelated libraries are unchanged except zlib (0.021 -> 0.025). A 0.1
  similarity floor gained 1-2 more points but tripled zlib's false hits.

## v2 — portable features

`SPEC_VERSION` is `2`. Constant words and portable callees change feature
records, so a v1 signature or DB is refused rather than matched with different
semantics. The hash domain (`person="sigtool.v1"`) is unchanged: hashing did
not change, only what is hashed. The Python prototype under `core/` was
removed; the native crate is the only implementation of this spec.

### Constant words

Changes `const` feature values (SPEC.md §3).

* Every constant is recorded as 32-bit words. A value that is the zero- or
  sign-extension of a 32-bit value is its low word; any other value is its
  non-zero high and low words. x86-64 and AArch64 sign-extend 32-bit
  immediates while ARM32 holds them in one register, and a 64-bit value is one
  `movabs` on x86-64, a `movz`/`movk` chain on AArch64, and two registers on
  ARM32; all of them now yield the same features.
* Low-information constants (§8) include words within `0x100` below `2^32`,
  the 32-bit form of small negative values.
* The hint-free code index keys constants by the same words, so a decoded
  `movabs` still lands on a signature anchored on either half.
* A partial `movw`/`movt` or `movz`/`movk` value stays pending until an
  instruction names its register (or a new materialization replaces it, a
  control transfer, or the block end), instead of flushing at the next
  unrelated instruction. clang `-O2`/`-Os` schedule other work between the
  halves, which split `0x7f4a7c15` into `0x7c15` and `0x7f4a0000` on ARM32
  and Thumb.
* ARM32/Thumb PIC `add rd, pc, rm` and `add rd, pc` consume the pooled offset
  as an address before pending constants flush, with the unaligned Thumb PC
  for the register form. Previously the offset leaked as a build-specific
  `const` (`0xfffeff36`) and the string it addressed was lost.

### Portable callees

Changes `callee` feature semantics (SPEC.md §2.1).

* Only calls and jumps that leave the function produce callees; a jump into
  the function's own body is control flow.
* Only names are callees. The `module+0x<rva>` fallback is gone: it is a layout
  address and matched nothing outside its own build.
* Import stubs resolve to the import they load, checking the slot's relocation
  before reading it (a lazily bound slot points back into the PLT): x86-64
  `jmp [rip+slot]` after `endbr64`, AArch64 PLT entries and veneers (with
  `bti`), ARM PLT entries (short and long, with a Thumb `bx pc` prefix) and
  veneers. Before this, every PLT call on every architecture became a
  `module+rva` label, and ARM32 imports were never read at all (8-byte
  `Elf32_Rel` entries were rejected as too short).
* Callees named only by `.symtab` (local functions) are optional and never
  anchors; imports and dynamic exports stay required. ELF exports are the
  `.dynsym` definitions, the names `strip` keeps.
* ARM EABI / libgcc arithmetic helpers are dropped; EABI memory helpers are
  renamed to the libc call.
* A matched callee name (required or optional) satisfies shape corroboration
  (SPEC.md §8), as a required callee always did.
* Calls into other images are written `*!name` (ELF) or `module!name` (PE)
  and are low-information: never anchors, not identifying for shape
  corroboration. Resolving PLT calls made `memcpy`/`free` match across
  unrelated libraries; with this rule the real-corpus strong FP rate is 0.094
  (0.081 before the callee changes, 0.374 without the rule).
* Golden vectors: 57 callee records removed, all `fixture+0x<rva>` labels
  (intra-function jumps); no named callee changed.

### Image-relative RVAs

`rva` in provenance and `module+rva` labels are relative to the image base:
the lowest `PT_LOAD` address for linked ELF images and `ImageBase` for PE,
the values readelf and disassemblers use. Before, the base was the lowest
mapped section, which put PE RVAs 0x1000 off and made `--rva` disagree with
IDA. Relocatable objects keep the lowest placed section.
