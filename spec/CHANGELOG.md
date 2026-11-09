# Spec changelog

## v1 — M1 extraction

Initial spec, implementing PLAN.md section 4 for x86-64 and AArch64.

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
  so `SPEC_VERSION` stays `1`. ARM32 and Thumb are decoded through
  `yaxpeax-arm`'s ARMv7 module, which has no VFP/NEON instructions, so
  auto-vectorized functions are one decoding gap and the ARMv7 media group
  (`uxtb`, `uxth`, `rev`, `rbit`, `usat`, parallel add/sub) is the other; every
  arm32/thumb golden vector that does not use them matches the reference, and
  the CLI decodes all four architectures.
* Binary signature database (SPEC.md §10): a deterministic, mmap-friendly file
  with a 64-byte header, a 40-byte-record table sorted by `signature_id`, and a
  padded payload blob. The header carries `SPEC_VERSION`, and table/payload
  CRC-32 checks detect corruption.
* CLI (`sigtool-native`): `gen`, `locate`, `scan` (YAML or `--db`), `merge`,
  and `db build`, with the same exit-code contract as the Python front-end.
  `merge` emits the same document as the Python implementation for the same
  samples; no feature, weight, or threshold semantics changed.
