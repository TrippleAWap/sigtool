# Signature spec v4

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
| `callee` | symbol name or `module!import` (§2.1) | Named target of a call or tail call |
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
* **ARM32/Thumb:** `nop`, `hint`, and every `it`/`itt`/`ite`... block header.
  The block header carries predication only; the instructions inside it are
  normalized by their base mnemonic.

This is what makes CET and PAC builds match plain builds.

### 1.3 ARM32 and Thumb mode

An ELF `EM_ARM` image is one *arch* (`arm32`) whose functions may be ARM or
Thumb. ELF symbol values carry the Thumb bit; sources canonicalize code
addresses to the byte address (low bit cleared) and expose the mode per
address (`ByteSource.is_thumb`). Condition codes are reported by Capstone and
stripped from mnemonics for classification, so `add`/`addeq`/`addlo` are one
class; a conditional return (`bxeq lr`, `popeq {..., pc}`) is a conditional
exit with fall-through, never an unconditional terminator. PE images use the
container mode (`0x01c0` ARM, `0x01c2`/`0x01c4` Thumb).

### 1.4 Inline-invariant evidence

Whether a helper is inlined differs between compilers and optimization
levels, and inlining moves the helper's strings, constants, and calls into
its caller. A signature taken where the helper was inlined demands those
keys; a target that kept the call out of line holds them one call away. The
extracted features therefore also carry the `str`, `const`, and `callee`
features of the function's *small direct callees*, as *inherited* records
(optional, key prefixed `inl:`, e.g. `inl:const:0x5678`):

* A direct callee is the target of a call or tail call that leaves the
  function and lands in executable code of the image. A call through a PLT
  stub to an export the image defines reaches the export's definition; an
  import the image does not define is no callee here. At most
  `MAX_INLINE_CALLEES` (32) callees are read, lowest address first.
* A callee is small when its recovery, without symbol hints (unwind bounds
  only, so a signed image and its stripped copy agree), completes within
  `MAX_INLINE_CALLEE_INSTRUCTIONS` (80) instructions and as many blocks.
* Only the callee's own features are inherited (one hop). A key the function
  has itself is not inherited again.
* Inherited records are candidate-side evidence. Generation signs own
  features only, so a signature never carries `inl:` keys; neighbour keys
  (§7) are built from own features only.
* In matching (§8), a signature feature the candidate holds only as
  inherited earns `INHERITED_CREDIT` (0.5) of its weight in the score and in
  similarity. It does not count toward `min_distinct`, is reported in
  `matched` with its `inl:` prefix, and is neither identifying nor a named
  callee. 0.5 is below every match threshold, so a caller of a small function
  cannot match that function's signature on inherited keys alone; at full
  credit every such caller did, and the hint-free FP rate rose by 0.03.

## 2. Address normalization

Rule 4 of AGENTS.md: **no absolute address may appear in a feature.**

* x86-64 RIP-relative operands resolve to `insn.address + insn.size + disp`.
  The result is a *data reference*, never a constant.
* AArch64 `adrp` pages are resolved when the page register is consumed by
  `add`/`sub` (address of a string or table) or `ldr`/`str` (a pointer cell).
  An unconsumed `adrp` page is discarded as an address.
* AArch64 `ldr` from a literal pool resolves to the pool value: a pointer becomes
  a reference to the pool cell; a non-pointer value becomes a constant.
* ARM32/Thumb `ldr rd, [pc, #imm]` resolves against the literal pool (Thumb PC
  is `align(addr + 4, 4)`, ARM PC is `addr + 8`): a pool value inside the image
  becomes a reference to its target, any other word becomes a 32-bit constant.
  The referenced cell extends the function bounds, because arm32 pools sit
  inline after the last instruction and symbol sizes count them.
* ARM32/Thumb `add rd, pc, rm` (and the Thumb two-operand `add rd, pc`) resolves
  against a previously pooled offset, like the AArch64 `adrp`+`add` pair. The
  register form reads the PC unaligned (Thumb `addr + 4`, ARM `addr + 8`). The
  pooled offset is consumed as an address, never flushed as a constant.
* ARM32 `movw`/`movt` pairs and `mvn rd, #imm` collapse into one constant each,
  matching AArch64 `movz`/`movk` chains and `movn`. A partial value stays
  pending in its register until an instruction names that register, a new
  `movw`/`movz`/`mov`/`movn`/`mvn` replaces it, a control transfer, or the block
  end; an instruction that does not name the register leaves it pending, so a
  pair the compiler scheduled apart still collapses into one constant.
* Absolute x86 displacements and immediates are used only when they fall inside
  a mapped module, and then only as data references.
* A constant whose value lies inside a mapped module is dropped entirely.

Data references are anchors for Tier 0 (§6) and are never stored as values.

### 2.1 Callees

A `callee` is the *name* of what a call, or a jump that leaves the function,
reaches. Names are the only callee form: an unnamed target's address (or a
`module+rva` label) differs per build, so it is never a feature.

* **Calls and tail calls only.** A direct jump whose target lies inside the
  recovered function is control flow, not a callee, even when the target
  carries a name (a loop back onto the entry).
* **Stubs resolve to the import they load.** A branch into an import stub
  follows the stub to the pointer slot it jumps through; a slot carrying an
  import relocation (`R_*_JUMP_SLOT`, `R_*_GLOB_DAT`, a PE IAT entry) names the
  callee, before the slot is read, because a lazily bound slot points back
  into the PLT. Recognised stubs: x86-64 `jmp [rip+slot]` (after `endbr64`);
  AArch64 `adrp x16; ldr x17, [x16, #o]; [add x16;] br x17` (after `bti`);
  ARM `add ip, pc, #A; add ip, ip, #B; [add ip, ip, #C;] ldr pc, [ip, #D]!`,
  lld's long `ldr ip, L; add ip, ip, pc; ldr pc, [ip]`, optionally behind a
  Thumb `bx pc; nop`. Veneers resolve to their target: AArch64 `adrp x16; add
  x16; br x16` and `ldr x16, =T; br x16`, ARM `ldr pc, [pc, #-4]` and `movw
  ip; movt ip; bx ip`. Only the veneer scratch registers (`x16`/`x17`, `ip`)
  are accepted. A slot without a relocation is read and followed, at most
  `MAX_THUNK_HOPS` (4) times.
* **Runtime helpers are arithmetic.** ARM EABI and libgcc/compiler-rt helpers
  that stand in for one instruction on other targets (`__aeabi_uidivmod`,
  `__aeabi_d*`, `__udivsi3`, `__divti3`, ...: a `__` name of at most 16
  characters ending in a libgcc mode suffix such as `si3`, `di3`, `df2`) are
  not callees. The EABI memory helpers are the libc call they implement:
  `__aeabi_memcpy*` is `memcpy`, `__aeabi_memmove*` is `memmove`, and
  `__aeabi_memset*` / `__aeabi_memclr*` are `memset`.
* **Calls into other images are low-information.** An import the image does
  not define itself (no `.dynsym` definition; every PE import) is written in
  the `module!import` form; ELF does not record the providing library, so the
  module is `*` (`*!memcpy`). A shared object's call to its own export
  through the PLT keeps the plain name. A callee value containing `!` is never
  an anchor and, like a small constant, does not make a signature
  high-information or corroborate a match (§8): `memcpy` and `free` are
  called by unrelated code everywhere.
* **Portable names are required, local names optional.** A name is portable
  when it survives `strip`: an import, or a symbol the image exports (ELF:
  defined in `.dynsym`; an `ET_REL` object without `.dynsym` uses its global
  `.symtab` symbols). A callee known only from `.symtab` (a `static` or hidden
  function) is emitted with `required: false`: it adds evidence when the
  target still has symbols and costs nothing when it is stripped. Optional
  callees are never anchors (§7) and do not make a signature high-information,
  but a candidate that matches one is corroborated (§8). Portability is decided on the resolved name,
  before the helper rename above.

Relocatable ELF objects (`ET_REL`) have no applied relocations, so a reference
across sections is encoded as a zero displacement and resolves to nothing. Sign
from a linked image (or let the front-end apply relocations) when data anchors
matter; this is a property of the object format, not of the extractor.

## 3. Constant canonicalization

* Constants are recorded as unsigned 32-bit *words*, printed as `0x%x`. The
  same source constant is a sign-extended 64-bit register value on x86-64 and
  AArch64 but a 32-bit register (or a pair of them) on ARM32, so a word is the
  only form every architecture can produce.
* Each materialised value is first taken as 64 bits: an immediate of 32 bits
  or fewer is sign-extended, a `movabs`, a `movz`/`movk` chain, or a 64-bit
  literal-pool load keeps its full value. The pointer rule (§2) applies to
  that 64-bit value. It then becomes features as follows:
  * a value that is the zero- or sign-extension of a 32-bit value is its low
    word, so `mov rax, -1`, `mov eax, -1`, AArch64 `movn w0, #0` and
    `movn x0, #0`, and ARM32 `mvn r0, #0` all yield `0xffffffff`, and
    `0xffffffff94d049bb` (x86-64) meets `0x94d049bb` (ARM32);
  * any other value is its high and low words, each a separate `const`
    feature, and a zero word is dropped. `movabs rax, 0x94d049bb133111eb`, the
    equivalent AArch64 chain, and the ARM32 pair of 32-bit halves all yield
    `0x94d049bb` and `0x133111eb`; an AArch64 chain split by an interleaved
    instruction (`0x94d049bb00000000` plus `0x133111eb`) yields the same two.
  A genuine unsigned 32-bit mask and the sign-extended negative with the same
  low word collapse onto one value; constants are supporting evidence, so the
  ambiguity is accepted.
* A word within `0x100` of zero in either direction (`< 0x100`, or
  `>= 0xffffff00`) is low-information for shape corroboration (§8): it does
  not by itself excuse a signature from it.
* Only materialisation and comparison/mask instructions contribute constants:
  x86-64 `mov*`, `cmp`, `test`, `and`, `or`, `xor`, `imul`; AArch64
  `mov`/`movz`/`movk`/`movn` chains and immediate operands of `cmp`/`cmn`/
  `tst`/`and`/`orr`/`eor`/`add`/`sub`; ARM32 `movw`/`movt` pairs, `mvn rd, #imm`,
  literal-pool words, and immediate operands of the same comparison and
  arithmetic mnemonics (condition suffixes stripped).
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
* No language-runtime hash (randomized or seed-dependent) is used for persisted data.
* The hash is used for over-long string values and, from M2, for signature ids.

## 7. Signature document

Generation produces one YAML document per function (`native/src/sigfile.rs`). The
canonical YAML text is the signature's identity: its BLAKE2b-16 digest is the
`signature_id`, so the byte form must stay stable.

```yaml
spec_version: '3'
name: parse_record
confidence: single-arch
anchors:
- str:record magic mismatch
- const:0x52454344
neighbours:
- in:str:bad header
- out2:const:0x9e3779b1
links:
- in:0x1840
- out:0x11a0
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
* `spec_version` is a string and must equal `SPEC_VERSION` (`native/src/spec.rs`); a reader
  rejects any other value rather than guessing.
* `arch` is not a top-level list. One document describes one sample; multiple
  architectures are combined by merging provenance and promoting `confidence`
  to `multi-arch` (M3).
* `module` is a file name, never a path, and `rva` is relative to that module.
  No absolute address from the target process may appear anywhere in the YAML.
* `opt` and `tool` are provenance only. They never influence features, weights,
  thresholds, or identity.
* Weights are rounded to three decimals and never reach zero (floor `0.001`).
* `neighbours` and `links` are omitted when empty (see below).

### Links

`links` records the function's direct callers (`in:RVA`) and callees
(`out:RVA`) as RVAs in the first sample's module, lowercase hex without
leading zeros, sorted as text, at most 32. They are provenance, not evidence:
they never affect a match on their own, and they only mean something to other
signatures from the same module, found by `(module, rva)` of their first
sample. A merged signature keeps its first sample's links. Joint resolution
(§8) uses them.

### Neighbours

A small function often has no identifying feature of its own, but its
callers and callees do. `neighbours` lists identifying keys of the function's
call-graph neighbours, as `HOP:KIND:VALUE`:

* `HOP` is `out` (a direct callee), `in` (a direct caller), or `out2`/`in2`
  (one hop further in the same direction).
* `KIND:VALUE` is a `str` feature or a `const` feature that is not
  low-information (§8), exactly as the neighbour's own feature key.
* Calls are direct calls and tail calls that leave the function. Imports are
  not neighbours. A call through a PLT stub to an export the image defines
  itself (`-fPIC` shared objects call their own exports that way) reaches the
  export's definition. Callers come from a whole-image pass over direct call
  sites; a call site's function is its symbol bounds (hinted) or unwind entry.
* At most 16 neighbours per direction and hop 1, 64 per direction at hop 2,
  are read, nearest address first; at most 64 keys are kept, hop 1 first,
  then sorted. Merged signatures keep the sorted union of their samples'
  keys, truncated to 64.
* Neighbour keys are never features: they do not enter score, similarity,
  anchors, or shape corroboration. Only image sources that build a whole-image
  index produce them; a signature from a live process has none.

### Weights

`weight = base(kind) * rarity(value) * idf(key)`, where `idf` defaults to 1.0
unless a reference corpus is supplied (`native/src/score.rs`).

| kind | base | anchors | required |
| --- | --- | --- | --- |
| `str` | 1.0 | yes | yes |
| `callee` | 0.9 | yes (portable only) | portable only (§2.1) |
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

Anchors are the heaviest required data features (`str`, `const`, `callee`), at
most four; an optional feature is never an anchor.
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

`native/src/validate.rs` reports what is measurable without a matcher:

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

## 8. Matching

`native/src/matcher.rs` is the matcher. It uses the same extractor as
generation and never decodes with its own tables.

* **Tier 0 — anchors as bytes.** `const` anchors are searched at 4 and 8 bytes
  in both byte orders because a value may be materialized by `mov` or
  `movabs`; constants below `0x100` are not searchable (they match almost
  anywhere). `str` anchors are searched narrow (Latin-1) and as UTF-16LE;
  hashed `long:` literals are not searchable. Constant needles are searched in
  executable regions, string needles in data regions. `callee` anchors are
  names and are compared only after recovery, where symbol resolution has
  already happened.
* **Tier 1 — candidates.** Known function starts from the source
  (`ByteSource.function_starts`) are candidates; for every constant hit that no
  symbol covers, the matcher also sweeps backwards over real instruction
  boundaries (bounded window) and offers those starts. Candidates are ranked by
  proximity to a constant hit, then by address, and capped at 256 per
  signature. Each candidate is recovered with the same bounded recovery used
  for generation.
* **Hint-free discovery.** Scanning may forbid symbol hints entirely
  (`scan(..., hints=False)`): candidate starts come only from the backward
  sweep, and recovery runs without symbol bounds. This is the mode a scanner
  without symbols runs in; the harness reports recall for both modes so
  comparison quality (hinted) and discovery (hint-free) are separate numbers.
* **Tier 0 budgeting.** Tier 0 always runs; Tier 1 is rate-limited by
   `RecoveryBudget(remaining=N)`, shared across all signatures in one scan
   pass. A signature whose candidates exhaust the budget before its first match
   is recorded as found-by-recovery-count, not missed. Tier 0 never runs out.
* **Data-reference index.** String anchors live in data pages, so they cannot
   seed candidate starts directly: nothing in Tier 0 points at the code that
   uses them. `ReferenceIndex` closes that gap by sweeping each executable
   region once (bounded at 200 K instructions and 4096 resyncs per index
   lifetime) and recording which instructions reference which data addresses.
   A string hit becomes a candidate through the referencing instruction, ranked
   the same way as any code anchor. The index is global-budgeted, not per-region,
   so re-indexing a changed region subtracts its old count before adding the
   new one. Each region is tracked separately so a runtime scanner can drop a
   freed region and rebuild the merged map incrementally.
* **Tier 2 — comparison.** Accepted only when every gate passes:
  `score >= thresholds.match`, `matched_required >= min_distinct`, and, for a
  low-information signature, shape corroboration.
* **Shape corroboration.** A signature is low-information when none of its
  required features is a `str`, a `callee` without `!`, or a `const` whose magnitude
  (either sign, as a 32-bit word per §3) is at least `0x100`. Constants such as loop steps, field offsets, and
  `-8` stack alignment occur in most functions, and on the corpus every false
  positive came from such a signature. Its candidate must also agree with at
  least 0.8 of the signature's shape dimensions. A dimension is a shape key
  without its bucket (`cfg:blocks`, `ops:arith`, ...); it agrees when any of the
  signature's buckets for it matched, so a merged signature carrying one bucket
  per sample architecture still corroborates on each of them. A candidate that
  matched any `callee` feature without `!`, required or optional, needs no shape
  agreement: a matched name identifies the function (§2.1).

Score definition, rounded to six decimals:

```
score = min(1, (matched_required_weight + matched_optional_weight) / required_weight)
```

A feature matched only through an inherited `inl:` key (§1.4) contributes
`0.5 * weight` to the matched weight and is not counted in
`matched_required`.

Optional features can only add evidence: the denominator is the required
weight, so a candidate that lost a required feature scores below the threshold
instead of being rejected outright (subset matching). Matches are sorted by
descending score then address, and overlapping spans collapse to the best
match, so one function is reported once even when a sweep can recover its body
from an interior address.

**Hint-free acceptance.** On an image with frequency estimates (at least 32
unwind-table functions), a hint-free match must also pass:

* similarity at least 0.2, and the chance gate (at most 1.0 expected chance
  matches) unless the match shares a neighbour key: the gate prices only the
  candidate's own keys;
* *shape-only* matches, those whose matched keys hold no identifying key (a
  `str`, a `callee` without `!`, or a `const` at least `0x100` from zero), need
  at least 6 matched features, unless they share a neighbour key;
* a shape-only match that shares none of the signature's neighbour keys is
  rejected when the signature has at least 2 of them;
* a shape-only match needs similarity at least 0.3.

**Hinted acceptance.** On an image with at least 32 known function starts, a
hinted match that is shape-only needs at least 6 matched features and
similarity at least 0.3, as in hint-free mode; the chance and neighbour gates
are hint-free only.

**Evidence labels.** Each match in a ranked list carries one label:

* `identified`: the first match, not tied with the second, with an
  identifying key, and with similarity at least 0.3 when no `str` matched
  but a direct neighbour key (`near:in:`, `near:out:`) or a `joint:N` key
  with `N ≥ 1` did, or at least 0.7 when only callees, constants, or two-hop neighbour
  keys identify it (a matched `str` needs no floor);
* `candidate`: identifying keys, but not the answer (not first, tied, or
  below its floor);
* `shape-only`: no identifying key.

The candidate's neighbour keys are computed the same way as at generation, on
the target. Shared keys are reported in `matched` as `near:HOP:KIND:VALUE` and
count as identifying. Hint-free matches are ranked by the number of shared
neighbour keys, then similarity, then score.

**Joint resolution.** Signatures from one module scanned together
(`scan` with several signatures, hint-free) are resolved as a one-to-one
assignment of the module's signatures to the target's functions
(`native/src/joint.rs`). Signatures are grouped by the module of their first
sample; a group with no link between two of its signatures is left as
scanned.

1. Candidates are the target's unwind entries (hint-free) or function starts
   (hinted) and their direct call targets. A (signature, function) pair is
   weighed when its similarity (as in the scan, inherited `inl:` keys
   credited at `INHERITED_CREDIT` and not counted as extra weight, §1.4) is
   at least 0.2; the full acceptance gate is
   not required, because across compilers the required features are exactly
   what changed and the call graph checks the placement instead. Its base
   weight is the similarity plus `0.2 × (1/(1+|Δout|) + 1/(1+|Δin|)) / 2`,
   where `Δout` and `Δin` compare the signature's `out:` and `in:` link
   counts with the function's callees and callers in the target. The pair
   holding a signature's scan answer (its `identified` first match) gains
   0.3.
2. The mapping is built greedily: pairs by weight, highest first (ties by
   signature order, then address), each taken when neither its signature nor
   its function is taken yet.
3. Refinement, at most 4 rounds until the mapping stops changing: every pair
   gains 0.3 per link of its signature that the current placement of the
   linked signature would preserve (an `out:` link is preserved when the
   function calls the neighbour's placement, an `in:` link when it is called
   by it), and the mapping is rebuilt from the new weights. "Calls" includes
   tail calls: a function's callers are its direct-call sites plus every
   candidate whose callees (calls and tail calls) include it, so both ends of
   a link read the same edge.
4. Module gate: the mapping is used only when it preserves at least 6 link
   ends (each link counts once per signature recording it) and at least 0.2
   of the link ends whose two signatures it placed. Otherwise every match
   list is left as scanned.
5. A placed signature whose function outweighs every function no other
   signature took is reported with that function first, marked `joint:N` in
   `matched`, where `N` is the number of its links the mapping preserves. A
   free function of equal weight is a tie and leaves the list as scanned.

A joint placement ranks above every other match (`joint:N` ranks by `1 + N`
before neighbour keys). `joint:N` with `N ≥ 1` counts as identifying, with
the 0.3 answer floor of direct neighbour keys; `joint:0` (placed by
similarity and the one-to-one constraint alone) does not.

**Self-test.** Generation runs the matcher on the same source and requires an
accepted match at the recovered function start; a signature that cannot be
re-found is never emitted (AGENTS.md rule 7).

**Known limitation.** String anchors became discoverable with the M6 data-reference
index (`ReferenceIndex`); they still rank through the index rather than seeding
candidates directly, so scanning a source without an index finds the function but
does not know which candidate to recover first.

Small functions cannot anchor in Tier 0; their signatures add caller/callee
names, neighbour position, and a tight op-class sequence, and match near an
already-matched function. A standalone hit on a small signature is reported
with `confidence: low`.

### Merging samples (multi-arch signatures)

`native/src/merge.rs` combines two or more samples of one function — different
optimization levels, different architectures — into one document:

* A feature present in **every** sample keeps its weight and, for data kinds,
  stays required.
* A feature present in a **strict subset** of samples is demoted: optional,
  half weight. Divergent bucket values therefore widen the match instead of
  failing it — every observed value remains as optional evidence.
* Anchors are chosen only among features every sample carries, so Tier 0
  cannot trigger on bytes a sample does not contain.
* `confidence` is `multi-arch` when the samples span more than one arch.
* The merged document must self-test against **every** sample; a merge that
  cannot re-find one of its own samples is refused (AGENTS.md rule 7).

Merged signatures trade precision for recall: the required set is the
intersection of the samples, which is weaker evidence than any single
sample's full set. The harness measures both (per-arch and merged recall and
false positives) so the trade stays visible.

## 9. Recovery contract

Recovery is bounded by `MAX_FUNCTION_BYTES`, `MAX_BLOCK_BYTES`,
`MAX_INSTRUCTIONS`, and `MAX_BLOCKS`. It stops a block on undecodable bytes or a
budget limit and marks the function `degraded`; it never guesses. A direct jump
onto a known other symbol, or outside the symbol's range, is treated as a tail
call and not followed. Trailing alignment padding is trimmed so recovered bounds
are comparable to symbol sizes.

## 10. Binary signature database

The native scanner stores many signature documents in one immutable file so it
can map them read-only instead of parsing YAML per scan
(`native/src/db.rs`). The format is a container only: the canonical YAML
payload remains the identity, and `signature_id` is recomputed from the payload
when a record is read. All integers are little-endian.

```text
header (64 bytes)
spec version string (padded to 8)
record table (record_count * 40 bytes)
blob: id, name, canonical YAML payload per record, each padded to 8
```

Header fields:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `SIGTDB\0\1` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | header size (`64`) |
| 12 | 4 | flags (`0`) |
| 16 | 2 | spec version length |
| 18 | 2 | record size (`40`) |
| 20 | 4 | record count |
| 24 | 8 | spec version offset |
| 32 | 8 | record table offset |
| 40 | 8 | blob offset |
| 48 | 8 | blob length |
| 56 | 4 | record-table CRC-32 |
| 60 | 4 | reserved (`0`) |

Each 40-byte record points into the blob with absolute file offsets:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | signature id offset |
| 8 | 4 | signature id length |
| 12 | 4 | name length |
| 16 | 8 | name offset |
| 24 | 8 | payload offset |
| 32 | 4 | payload length |
| 36 | 4 | payload CRC-32 |

Records are sorted by `signature_id`, so a mapped DB can be binary-searched
without allocating. The reader validates the header, bounds, sort order, and
table CRC when it opens the file; payload CRCs and the id-versus-payload check
run when a record is read. A DB whose header spec version differs from
`SPEC_VERSION` is refused rather than interpreted with different semantics.
Encoding is deterministic: identical signature sets produce identical bytes
regardless of insertion order.
