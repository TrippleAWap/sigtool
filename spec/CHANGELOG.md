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

## v1 — M3 reference matcher

* Anchor needles per kind, with the searchable encodings and the constants that
  are deliberately not searchable (SPEC.md §8).
* Candidate generation from known function starts plus a bounded backward
  instruction sweep from constant hits, ranked and capped.
* Weighted comparison where optional features can only add evidence, gated by
  `thresholds.match` and `min_distinct`; overlapping spans collapse to one
  match.

Not yet specified: `multi-arch` merging, a data-reference index for string
candidate discovery, and reference-scanner budgets (M4–M6).
