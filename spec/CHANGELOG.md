# Spec changelog

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

## Unreleased — trust labels and shape-only floors

Acceptance and reporting change; feature records and the signature document
do not. Not yet versioned: whether this needs a `SPEC_VERSION` bump is open
(a v3 document matches with stricter acceptance, not different semantics).

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
