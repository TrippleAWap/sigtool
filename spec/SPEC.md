# Signature spec v1

Status: draft for M1 (extraction). Generation, scoring, and matching fields are
specified in outline and completed in M2/M3.

A signature is a **set of features**, not a byte pattern. Features describe what
a function does in an architecture-neutral way: the strings it references, the
constants it materialises, the functions it calls, its coarse control-flow
shape, and its instruction-class histogram. One extractor produces features for
both signing and scanning, so the two can never drift apart.

## 1. Feature kinds

| Kind | Value form | Meaning |
|---|---|---|
| `str` | text, or `w:` + text for UTF-16LE, or `long:` + digest | String literal referenced by the function |
| `const` | `0x` + lowercase hex | Materialised constant, pointer values removed |
| `callee` | symbol name, `module!import`, or `module+0x<rva>` | Resolved call target |
| `cfg` | `blocks:<b>`, `edges:<b>`, `loops:<b>` | Coarse control-flow shape |
| `ops` | `<op-class>:<b>` | Bucketed histogram over 14 instruction classes |

`<b>` is a bucket index (§4). Features are stored sorted by `(kind, value)` and
deduplicated; no ordering may depend on hash iteration.

### 1.1 Instruction classes

`move`, `arith`, `mul`, `logic`, `cmp`, `load`, `store`, `stack`, `branch`,
`call`, `ret`, `cond`, `vector`, `misc`.

Rules that make classes comparable across architectures:

* Load/store is decided by operand direction; accesses whose base or index is
  the stack or frame pointer become `stack`, so ABI prologues and Windows
  shadow space do not change the histogram.
* Any FP/SIMD register use makes the instruction `vector`, so SSE/AVX/AVX-512 and
  NEON/FP collapse into one class.
* Conditional move/select is `move`; setcc-style flag materialisation is `cond`.

### 1.2 Ignored instructions

These never contribute a feature, an op count, or function bounds:

* **x86-64:** `nop` (all multi-byte forms), `endbr64`/`endbr32`, `int3`
  padding, `mov reg, reg` (hot-patch prologue), `fnop`.
* **AArch64:** `nop`, `bti`, `hint`, `paciasp`/`autiasp`, `pacibsp`/`autibsp`,
  `paciaz`/`autiaz`, `pacibz`/`autibz`, `xpaclri`.

This is what makes CET and PAC builds match plain builds.

## 2. Address normalization

Rule 4 of AGENTS.md: **no absolute address may appear in a feature.**

* x86-64 RIP-relative operands resolve to `insn.address + insn.size + disp`.
  The result is a *data reference*, never a constant.
* AArch64 `adrp` pages are resolved when the page register is consumed by
  `add`/`sub` (address of a string or table) or `ldr`/`str` (a pointer cell).
  An unconsumed `adrp` page is discarded as an address.
* AArch64 `ldr` from a literal pool resolves to the pool value: a pointer becomes
  a reference to the pool cell; a non-pointer value becomes a constant.
* Absolute x86 displacements and immediates are used only when they fall inside
  a mapped module, and then only as data references.
* A constant whose value lies inside a mapped module is dropped entirely.

Data references are anchors for Tier 0 (§6) and are never stored as values.

Relocatable ELF objects (`ET_REL`) have no applied relocations, so a reference
across sections is encoded as a zero displacement and resolves to nothing. Sign
from a linked image (or let the front-end apply relocations) when data anchors
matter; this is a property of the object format, not of the extractor.

## 3. Constant canonicalization

* Constants are stored as unsigned 64-bit values, printed as `0x%x`.
* Values in the 32-bit range are sign-extended to 64 bits, so `mov rax, -1`,
  `mov eax, -1`, `mov rdi, -1`, and AArch64 `movn w0, #0` all yield
  `0xffffffffffffffff`.
  A genuine unsigned 32-bit mask with the top bit set collapses onto the same
  value; constants are supporting evidence, so the ambiguity is accepted.
* Only materialisation and comparison/mask instructions contribute constants:
  x86-64 `mov*`, `cmp`, `test`, `and`, `or`, `xor`, `imul`; AArch64
  `mov`/`movz`/`movk`/`movn` chains and immediate operands of `cmp`/`cmn`/
  `tst`/`and`/`orr`/`eor`/`add`/`sub`.
* Immediates that encode ABI or addressing are excluded: anything touching the
  stack or frame pointer, and shift amounts.

## 4. Buckets

`BUCKET_BOUNDS = (0, 1, 2, 3, 4, 6, 9, 13, 19, 28, 40, 60, 90, 135, 200)`;
bucket index is the first bound `>= value`, clamped to the last index.

| Bucket | Counts | Bucket | Counts |
|---|---|---|---|
| 0 | 0 | 8 | 14–19 |
| 1 | 1 | 9 | 20–28 |
| 2 | 2 | 10 | 29–40 |
| 3 | 3 | 11 | 41–60 |
| 4 | 4 | 12 | 61–90 |
| 5 | 5–6 | 13 | 91–135 |
| 6 | 7–9 | 14 | 136+ |
| 7 | 10–13 | | |

Sparse buckets absorb small count differences between compilers, optimization
levels, and architectures.

## 5. String literals

* Only non-executable memory is considered; code and jump tables cannot
  masquerade as anchors.
* A narrow string is at least 4 printable ASCII bytes (0x20–0x7e) followed by
  NUL; a wide string is at least 4 such bytes as UTF-16LE followed by a zero
  code unit.
* Strings are escaped (`\\`, `\"`); wide strings carry the `w:` prefix so they
  never collide with narrow ones.
* At most 120 characters are stored. A longer literal is stored as
  `long:` + `digest(prefix)` (wide: `w:long:` + digest) so identity survives
  without unbounded values.

## 6. Hashing

* Hash: BLAKE2b, `digest_size=16`, `person=b"sigtool.v1"`.
* Python's `hash()` is never used for persisted data.
* The hash is used for over-long string values and, from M2, for signature ids.

## 7. Signature document

Generation produces one YAML document per function (`core/sigfile.py`). The
canonical YAML text is the signature's identity: its BLAKE2b-16 digest is the
`signature_id`, so the byte form must stay stable.

```yaml
spec_version: '1'
name: parse_record
confidence: single-arch
anchors:
- str:record magic mismatch
- const:0x52454344
thresholds:
  match: 0.75
  min_distinct: 2
features:
- kind: const
  value: '0x52454344'
  weight: 0.7
  required: true
- kind: str
  value: record magic mismatch
  weight: 1.263
  required: true
provenance:
- arch: x64
  module: fixture
  rva: '0x1200'
  opt: O2
  tool: clang 22.1.5
```

Rules:

* Field order is fixed as above; `features` are sorted by `(kind, value)` and
  anchors by descending weight, then `(kind, value)`.
* `spec_version` is a string and must equal `core.spec.SPEC_VERSION`; a reader
  rejects any other value rather than guessing.
* `arch` is not a top-level list. One document describes one sample; multiple
  architectures are combined by merging provenance and promoting `confidence`
  to `multi-arch` (M3).
* `module` is a file name, never a path, and `rva` is relative to that module.
  No absolute address from the target process may appear anywhere in the YAML.
* `opt` and `tool` are provenance only. They never influence features, weights,
  thresholds, or identity.
* Weights are rounded to three decimals and never reach zero (floor `0.001`).

### Weights

`weight = base(kind) * rarity(value) * idf(key)`, where `idf` defaults to 1.0
unless a reference corpus is supplied (`core.score.build_idf`).

| kind | base | anchors | required |
| --- | --- | --- | --- |
| `str` | 1.0 | yes | yes |
| `callee` | 0.9 | yes | yes |
| `const` | 0.7 | yes | yes |
| `cfg` | 0.25 | no | no |
| `ops` | 0.15 | no | no |

Rarity multipliers: strings get `1 + min(0.5, len/80)` because longer literals
are rarer and survive edits; constants below `0x100` get `0.6` because small
immediates are ubiquitous; everything else gets `1.0`. IDF is
`ln((N+1)/(df+1)) + 1` over a reference corpus, so common features stay near 1.0
and rare ones are boosted.

Shape features (`cfg`, `ops`) are always optional. A bucket match is common and
must never carry a signature on its own.

### Anchors and thresholds

Anchors are the heaviest data features (`str`, `const`, `callee`), at most four.
They are the Tier 0 prefilter, so the required weight and the threshold both
depend on how many exist:

| anchors | `thresholds.match` |
| --- | --- |
| 2 or more | 0.75 |
| 1 | 0.85 |
| 0 | 0.95 |

`min_distinct = clamp(required_count, 1, 3)`: a match must satisfy that many
distinct required features. Capping at three preserves recall on edited code.

### Confidence

`confidence` is `low` when the function is small (at most 12 instructions) or
has no anchors; otherwise it is `single-arch` until M3 merges a second
architecture, then `multi-arch`. Low-confidence signatures are still emitted
and rely on neighbour context (§8).

### Quality report

`core/validate.py` reports what is measurable without a matcher:

* `strong` — at least 2 anchors, 2 data features, 2 different data kinds, and
  complete recovery.
* `small` — at most 12 instructions; match with neighbour context.
* `weak` — everything else. Notes name the specific deficit (no anchors, one
  anchor, single feature kind, partial recovery, low confidence).

The report is advisory generation-time information; it is not stored in the
signature and cannot change it. Self-test against the matcher arrives with M3.

Every document carries `spec_version`. Changing feature semantics,
canonicalization, buckets, hashing, weights, or thresholds requires a version
bump and a changelog entry.

## 8. Matching tiers (M3/M6)

* **Tier 0** — data anchors via Aho-Corasick, indexed in both byte orders.
* **Tier 1** — bounded decode and feature extraction around anchor hits.
* **Tier 2** — weighted comparison against the shortlisted signatures only.

Small functions cannot anchor in Tier 0; their signatures add caller/callee
names, neighbour position, and a tight op-class sequence, and match near an
already-matched function. A standalone hit on a small signature is reported
with `confidence: low`.

## 9. Recovery contract

Recovery is bounded by `MAX_FUNCTION_BYTES`, `MAX_BLOCK_BYTES`,
`MAX_INSTRUCTIONS`, and `MAX_BLOCKS`. It stops a block on undecodable bytes or a
budget limit and marks the function `degraded`; it never guesses. A direct jump
onto a known other symbol, or outside the symbol's range, is treated as a tail
call and not followed. Trailing alignment padding is trimmed so recovered bounds
are comparable to symbol sizes.
