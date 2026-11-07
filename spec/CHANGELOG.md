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

Not yet specified: signature YAML fields beyond the outline in SPEC.md §7,
weights and thresholds (M2), and match thresholds per tier (M3).
