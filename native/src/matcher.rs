//! Reference matcher: anchor prefilter, bounded recovery, weighted comparison.
//!
//! The matcher is deliberately thin over the same extractor used for generation
//! (AGENTS.md rule 2). It never decodes instructions itself: candidates are
//! recovered with [`crate::recover`] and compared with features from
//! [`crate::features`].
//!
//! Tiers (spec §8):
//!
//! * Tier 0 turns data anchors into byte needles and finds candidate hit addresses.
//! * Tier 1 recovers a bounded function at each candidate start.
//! * Tier 2 compares the recovered feature set against the signature and accepts
//!   it when the weighted score and `min_distinct` both pass.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};

use crate::errors::SelfTestError;
use crate::features::{
    const_words, extract, extract_with, Feature, FeatureKind, InlineCache, INHERITED_PREFIX,
};
use crate::normalize::{Kind, Normalizer};
use crate::recover::{recover, RecoveryLimits};
use crate::score::score_features;
use crate::sigfile::Signature;
use crate::source::{ByteSource, Region};
use crate::sweep::{RegionSweep, Step};

pub const MAX_HITS_PER_ANCHOR: usize = 16;
pub const MAX_CANDIDATE_STARTS: usize = 256;
/// Hint-free candidate cap when the image has unwind entries (rule 8 bound).
pub const MAX_UNWIND_CANDIDATES: usize = 1 << 16;
pub const MAX_MATCHES: usize = 32;
pub const BACKWARD_SWEEP_BYTES: u64 = 512;
pub const SCORE_DECIMALS: usize = 6;

/// Tier 1 rate limit for the runtime scanner: candidate recoveries allowed per
/// pass. Tier 0 needle search is never budgeted.
pub const DEFAULT_MAX_RECOVERIES: usize = 4_096;

/// Reference-index budgets: a linear sweep indexes whole regions at once, so
/// the instruction count must be bounded (AGENTS.md rule 8), and a run of
/// undecodable bytes must not cost one resync per byte.
// Sized for real shared libraries (SQLite is ~600K instructions per arch):
// a smaller budget silently left most of a large image unindexed.
pub const MAX_INDEX_INSTRUCTIONS: usize = 4_000_000;
pub const MAX_INDEX_RESYNCS: usize = 4_096;

/// Hint-free discovery pass: instructions decoded while collecting boundaries,
/// call targets, and constant references. Bounded like the reference index for
/// the same reason (rule 8).
pub const MAX_DISCOVERY_INSTRUCTIONS: usize = 4_000_000;

/// One- and two-byte immediates occur everywhere; searching for them produces
/// noise without narrowing anything, so they are not used as needles.
pub const MIN_SEARCHABLE_CONST: u64 = 0x100;
pub const MAX_CONST_BITS: u32 = 64;

/// One anchor encoded as bytes, with the kind of region it can appear in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needle {
    pub key: String,
    pub data: Vec<u8>,
    pub executable: bool,
}

/// Weighted comparison of one candidate against a signature.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchScore {
    pub score: f64,
    pub matched: Vec<String>,
    pub matched_required: usize,
}

/// An accepted match: where it is and how strongly it scored.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub address: u64,
    pub end: u64,
    pub score: f64,
    /// Weighted Jaccard of signature and candidate features; ranks matches.
    pub similarity: f64,
    pub matched: Vec<String>,
    /// Similarity of the closest other function in the image that holds
    /// every identifying key this match holds ([`ScanContext::rival`]).
    /// Set by [`scan_in`] on its first match only.
    pub rival: Option<f64>,
    /// Accepted only because a shared neighbour key waived the shape gate
    /// (see [`MIN_WAIVED_SHAPE_SIMILARITY`]).
    pub waived: bool,
}

/// Encode the signature's data anchors for Tier 0 scanning.
///
/// Constants are indexed in both byte orders at both natural widths because a
/// materialization may use `mov` or `movabs`. Strings are indexed narrow and
/// as UTF-16LE, since one binary may store either. Hashed long literals are not
/// searchable and are skipped.
pub fn anchor_needles(signature: &Signature) -> Vec<Needle> {
    let mut needles: Vec<Needle> = Vec::new();
    for anchor in &signature.anchors {
        let (kind, value) = split_anchor(anchor);
        match kind {
            Some(FeatureKind::Const) => {
                for data in const_needles(value) {
                    needles.push(Needle {
                        key: anchor.clone(),
                        data,
                        executable: true,
                    });
                }
            }
            Some(FeatureKind::Str) => {
                for data in string_needles(value) {
                    needles.push(Needle {
                        key: anchor.clone(),
                        data,
                        executable: false,
                    });
                }
            }
            // Callee anchors are names, not bytes: Tier 2 compares them after
            // recovery, where symbol resolution has already happened.
            _ => {}
        }
    }
    needles.sort_by(|left, right| {
        (left.key.as_str(), left.executable, left.data.as_slice()).cmp(&(
            right.key.as_str(),
            right.executable,
            right.data.as_slice(),
        ))
    });
    needles
}

fn split_anchor(anchor: &str) -> (Option<FeatureKind>, &str) {
    match anchor.split_once(':') {
        Some((kind, value)) => (FeatureKind::parse(kind), value),
        None => (None, ""),
    }
}

/// Score a candidate feature set against `signature`.
///
/// Optional features add weight when present but never lower the score; the
/// denominator is the required weight, so a candidate missing evidence scores
/// below the threshold instead of being rejected outright.
pub fn compare(signature: &Signature, features: &[Feature]) -> MatchScore {
    let present: HashSet<String> = features.iter().map(Feature::key).collect();
    compare_keys(signature, &present)
}

/// Fraction of a signature feature's weight earned when the candidate holds
/// the key only through a small callee (SPEC.md §1.4). Below every match
/// threshold (0.75), so a caller of a small function never matches that
/// function's signature on inherited keys alone.
pub const INHERITED_CREDIT: f64 = 0.5;

/// [`compare`] against a candidate's precomputed key set.
pub fn compare_keys(signature: &Signature, present: &HashSet<String>) -> MatchScore {
    compare_with_keys(signature, &feature_keys(signature), present)
}

/// The signature's feature keys in document order, each with its inherited
/// form (SPEC.md §1.4).
fn feature_keys(signature: &Signature) -> Vec<(String, String)> {
    signature
        .features
        .iter()
        .map(|feature| {
            let key = feature.key();
            let inherited = format!("{INHERITED_PREFIX}{key}");
            (key, inherited)
        })
        .collect()
}

/// [`compare_keys`] with the signature's keys (from [`feature_keys`]) built
/// once: a hint-free scan compares one signature with every function in the
/// image, and formatting each key again per candidate was most of the cost.
fn compare_with_keys(
    signature: &Signature,
    keys: &[(String, String)],
    present: &HashSet<String>,
) -> MatchScore {
    let matched: Vec<(&crate::sigfile::SignatureFeature, &String)> = signature
        .features
        .iter()
        .zip(keys)
        .filter(|(_, (key, _))| present.contains(key))
        .map(|(feature, (key, _))| (feature, key))
        .collect();
    // Keys the candidate holds only through a small callee (SPEC.md §1.4):
    // discounted, and never counted as distinct required evidence.
    let inherited: Vec<(&crate::sigfile::SignatureFeature, &String)> = signature
        .features
        .iter()
        .zip(keys)
        .filter(|(_, (key, inherited))| !present.contains(key) && present.contains(inherited))
        .map(|(feature, (_, inherited))| (feature, inherited))
        .collect();
    let mut required_weight: f64 = signature
        .features
        .iter()
        .filter(|feature| feature.required)
        .map(|feature| feature.weight)
        .sum();
    if required_weight <= 0.0 {
        required_weight = signature
            .features
            .iter()
            .map(|feature| feature.weight)
            .sum();
    }
    let matched_required = matched
        .iter()
        .filter(|(feature, _)| feature.required)
        .count();
    if required_weight <= 0.0 {
        return MatchScore {
            score: 0.0,
            matched: Vec::new(),
            matched_required: 0,
        };
    }
    let total: f64 = matched
        .iter()
        .map(|(feature, _)| feature.weight)
        .sum::<f64>()
        + inherited
            .iter()
            .map(|(feature, _)| feature.weight * INHERITED_CREDIT)
            .sum::<f64>();
    let score = round_to((total / required_weight).min(1.0), SCORE_DECIMALS);
    let mut matched_keys: Vec<String> = matched
        .iter()
        .map(|(_, key)| (*key).clone())
        .chain(inherited.iter().map(|(_, inherited)| (*inherited).clone()))
        .collect();
    matched_keys.sort();
    MatchScore {
        score,
        matched: matched_keys,
        matched_required,
    }
}

/// A signature prepared for comparison with many candidates: its keys
/// ([`feature_keys`]) and everything [`accepts`] reads from it, per feature.
///
/// A hint-free scan compares a signature with every function of the image
/// and accepts a handful; [`compare_with_keys`] then [`accepts`] built the
/// matched key list (a `String` clone per key, then a sort), formatted the
/// score, and grouped the shape keys into dimensions by string for every one
/// of them. [`ScanKeys::accept`] decides from per-feature flags and builds
/// the [`MatchScore`] only for an accepted candidate, with the same sums in
/// the same order, so the result is identical.
struct ScanKeys {
    keys: Vec<(String, String)>,
    /// Required weight after the all-features fallback of
    /// [`compare_with_keys`].
    required_weight: f64,
    required_count: usize,
    needs_shape: bool,
    /// Per feature: a callee that names a function ([`accepts`]' `named`).
    named: Vec<bool>,
    /// Per feature: index of its shape dimension (`cfg:blocks`), if a shape
    /// key.
    dimension: Vec<Option<usize>>,
    dimensions: usize,
    /// Per dimension: one of [`CROSS_ISA_SHAPE_DIMENSIONS`].
    isa_stable: Vec<bool>,
    /// The target's ISA family is none of the signature's samples'.
    cross_isa: bool,
}

impl ScanKeys {
    fn new(signature: &Signature, cross_isa: bool) -> ScanKeys {
        let keys = feature_keys(signature);
        let mut required_weight: f64 = signature
            .features
            .iter()
            .filter(|feature| feature.required)
            .map(|feature| feature.weight)
            .sum();
        if required_weight <= 0.0 {
            required_weight = signature
                .features
                .iter()
                .map(|feature| feature.weight)
                .sum();
        }
        let mut dimensions: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let dimension = signature
            .features
            .iter()
            .zip(&keys)
            .map(|(feature, (key, _))| {
                if !matches!(feature.kind, FeatureKind::Cfg | FeatureKind::Ops) {
                    return None;
                }
                let name = key.rsplit_once(':').map(|(head, _)| head).unwrap_or(key);
                let next = dimensions.len();
                Some(*dimensions.entry(name.to_string()).or_insert(next))
            })
            .collect();
        ScanKeys {
            required_weight,
            required_count: signature
                .features
                .iter()
                .filter(|feature| feature.required)
                .count(),
            needs_shape: needs_shape_corroboration(signature),
            named: signature
                .features
                .iter()
                .map(|feature| {
                    feature.kind == FeatureKind::Callee && !low_information_callee(&feature.value)
                })
                .collect(),
            dimension,
            isa_stable: {
                let mut stable = vec![false; dimensions.len()];
                for (name, index) in &dimensions {
                    stable[*index] = CROSS_ISA_SHAPE_DIMENSIONS.contains(&name.as_str());
                }
                stable
            },
            dimensions: dimensions.len(),
            cross_isa,
            keys,
        }
    }

    /// `compare_with_keys` when [`accepts`] takes it, else `None`.
    /// `waive_shape` is asked only when the shape gate alone would reject
    /// the candidate (see [`scan_in`]).
    fn accept(
        &self,
        signature: &Signature,
        present: &HashSet<String>,
        waive_shape: &dyn Fn() -> bool,
    ) -> Option<MatchScore> {
        if self.required_weight <= 0.0 {
            let result = compare_with_keys(signature, &self.keys, present);
            return accepts_on(signature, &result, self.cross_isa).then_some(result);
        }
        // 1: the candidate holds the key itself; 2: only inherited.
        let state: Vec<u8> = self
            .keys
            .iter()
            .map(|(key, inherited)| {
                if present.contains(key) {
                    1
                } else if present.contains(inherited) {
                    2
                } else {
                    0
                }
            })
            .collect();
        let held = |wanted: u8| {
            signature
                .features
                .iter()
                .zip(&state)
                .filter(move |(_, state)| **state == wanted)
                .map(|(feature, _)| feature)
        };
        let total: f64 = held(1).map(|feature| feature.weight).sum::<f64>()
            + held(2)
                .map(|feature| feature.weight * INHERITED_CREDIT)
                .sum::<f64>();
        let raw = (total / self.required_weight).min(1.0);
        // Rounding to SCORE_DECIMALS moves a value by at most half a unit of
        // the last decimal, so a value this far below the threshold fails it
        // rounded too, and is not formatted.
        if raw < signature.match_threshold - 1e-6 {
            return None;
        }
        let score = round_to(raw, SCORE_DECIMALS);
        let matched_required = held(1).filter(|feature| feature.required).count();
        if score < signature.match_threshold
            || matched_required < signature.min_distinct.min(self.required_count)
        {
            return None;
        }
        let named = self
            .named
            .iter()
            .zip(&state)
            .any(|(named, state)| *named && *state == 1);
        if self.needs_shape && !named && self.dimensions > 0 {
            let mut agrees = vec![false; self.dimensions];
            for (dimension, state) in self.dimension.iter().zip(&state) {
                if let Some(dimension) = dimension {
                    agrees[*dimension] |= *state == 1;
                }
            }
            let agreement = |stable_only: bool| {
                let counted: Vec<bool> = agrees
                    .iter()
                    .zip(&self.isa_stable)
                    .filter(|(_, stable)| !stable_only || **stable)
                    .map(|(agrees, _)| *agrees)
                    .collect();
                if counted.is_empty() {
                    0.0
                } else {
                    counted.iter().filter(|agrees| **agrees).count() as f64 / counted.len() as f64
                }
            };
            let corroborated = agreement(false) >= MIN_SHAPE_AGREEMENT
                || (self.cross_isa
                    && matched_required >= MIN_CROSS_ISA_REQUIRED
                    && agreement(true) >= MIN_SHAPE_AGREEMENT);
            if !corroborated && !waive_shape() {
                return None;
            }
        }
        let mut matched: Vec<String> = self
            .keys
            .iter()
            .zip(&state)
            .filter(|(_, state)| **state == 1)
            .map(|((key, _), _)| key.clone())
            .chain(
                self.keys
                    .iter()
                    .zip(&state)
                    .filter(|(_, state)| **state == 2)
                    .map(|((_, inherited), _)| inherited.clone()),
            )
            .collect();
        matched.sort();
        Some(MatchScore {
            score,
            matched,
            matched_required,
        })
    }
}

/// Shape dimensions (`cfg:blocks`, `ops:arith`, ...) a candidate must agree
/// with when the signature's data evidence is low-information.
///
/// Measured on the corpus: 0.7-1.0 give the same single-arch FP rate, and
/// above 0.8 merged signatures start failing self-test on their own samples
/// (an op class one architecture lacks is a dimension that sample cannot
/// agree with), so 0.8 is the strictest value that costs no merges.
pub const MIN_SHAPE_AGREEMENT: f64 = 0.8;

/// Shape dimensions that keep their bucket when the instruction set changes.
///
/// x86-64 folds loads into arithmetic and pushes one register per
/// instruction, AArch64 pairs registers in `stp`/`ldp` and has
/// compare-and-branch, ARM32 saves every register in one `push` and
/// predicates; so the `move`, `arith`, `logic`, `load`, `stack`, `cmp`,
/// `mul`, `vector`, and `misc` counts of one source function differ by ISA,
/// not by function. Measured on the real corpus (`examples/diagnose_cross`,
/// 1200 true pairs across ISA families, same build, `--max-functions 4`):
/// exact bucket agreement of the true function is 0.88 `cfg:loops`, 0.82
/// `ops:call`, 0.74 `ops:ret` and `ops:cond`, 0.71 `cfg:blocks`, 0.69
/// `cfg:edges`, 0.57 `ops:branch`, 0.53 `ops:cmp`, 0.50 `ops:store`, and at
/// most 0.36 for the rest (`ops:stack` 0.12, `ops:misc` 0.05). Simulated
/// acceptance of those pairs at the floor below, with 0.410 for this set:
/// adding `ops:cmp` 0.398, dropping `ops:store` 0.412, dropping `ops:store`
/// and `ops:branch` 0.415, false hits equal; the differences are 2-6 pairs,
/// so the set stays as built and measured.
pub const CROSS_ISA_SHAPE_DIMENSIONS: [&str; 8] = [
    "cfg:blocks",
    "cfg:edges",
    "cfg:loops",
    "ops:branch",
    "ops:call",
    "ops:cond",
    "ops:ret",
    "ops:store",
];

/// True when no sample of the signature comes from the target's instruction
/// set, so only [`CROSS_ISA_SHAPE_DIMENSIONS`] corroborate its shape. ARM and
/// Thumb code are one ISA family here: an ELF image holds both under one
/// `arm32` arch (SPEC.md §1.3), and their op-class buckets agree like one
/// arch's builds do.
pub fn cross_isa(signature: &Signature, target: crate::arch::Arch) -> bool {
    fn family(arch: &str) -> &str {
        if arch == "thumb" {
            "arm32"
        } else {
            arch
        }
    }
    let target = family(target.as_str());
    !signature
        .provenance
        .iter()
        .any(|sample| family(&sample.arch) == target)
}

/// Distinct required features a cross-ISA candidate must match before
/// [`CROSS_ISA_SHAPE_DIMENSIONS`] alone may corroborate its shape.
///
/// The stable dimensions are few and coarse, so on their own they let tiny
/// lookalikes through. Simulated on the real corpus (true cross-ISA
/// same-build pairs from `examples/diagnose_cross`; false hits from
/// `examples/cross_fp`: every sample signature scanned hint-free against the
/// other libraries' stripped images in the other ISA families, same build,
/// counted as (signature, target arch) pairs with a hit, of 1200): without
/// the rule 0.366 accepted and 66 false; no floor 0.475 and 172; 2, 0.447
/// and 132; 3, 0.426 and 96; 4, 0.410 and 70; 5, 0.388 and 66; 6, 0.376 and
/// 66. 4 costs 4 false pairs (all shape-only, none identified) for 0.022
/// more acceptance than 5.
pub const MIN_CROSS_ISA_REQUIRED: usize = 4;

/// A constant within a byte of zero (either sign) is compiler boilerplate:
/// loop steps, field offsets, `-8` stack alignment. It identifies nothing.
pub fn low_information_const(value: &str) -> bool {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    match u64::from_str_radix(digits, 16) {
        // Constants are 32-bit words (SPEC.md §3), so a small negative value is
        // near 2^32; the 64-bit test still covers documents that predate that.
        Ok(number) => {
            number < MIN_SEARCHABLE_CONST
                || number.wrapping_neg() < MIN_SEARCHABLE_CONST
                || (0x1_0000_0000 - MIN_SEARCHABLE_CONST..=0xFFFF_FFFF).contains(&number)
        }
        Err(_) => false,
    }
}

/// A call into another image (`module!import`, `*!` when the module is
/// unknown): `memcpy` or `free` is called by unrelated code everywhere, so like
/// a small constant it supports a match but identifies nothing. Measured on
/// the real corpus, counting them as identifying raised the strong
/// cross-library FP rate from 0.081 to 0.374.
pub fn low_information_callee(value: &str) -> bool {
    value.contains('!')
}

/// True when no required feature identifies the function by itself: every
/// required feature is a small constant, or there are none (shape-only
/// signatures of tiny functions). The corpus bench showed that every false
/// positive came from such a signature, typically one whose evidence was the
/// constants 1 and 2.
pub fn needs_shape_corroboration(signature: &Signature) -> bool {
    !signature.features.iter().any(|feature| {
        feature.required
            && match feature.kind {
                FeatureKind::Str => true,
                FeatureKind::Callee => !low_information_callee(&feature.value),
                FeatureKind::Const => !low_information_const(&feature.value),
                _ => false,
            }
    })
}

/// Fraction of the signature's shape dimensions the candidate agrees with.
///
/// A dimension is a shape key without its bucket (`cfg:blocks:4` is dimension
/// `cfg:blocks`). It agrees when any of the signature's buckets for it was
/// matched, which keeps merged signatures (one bucket per sample
/// architecture) usable on every architecture they were merged from.
pub fn shape_agreement(signature: &Signature, matched: &[String]) -> f64 {
    shape_agreement_on(signature, matched, false)
}

/// [`shape_agreement`], over [`CROSS_ISA_SHAPE_DIMENSIONS`] only when
/// `stable_only`.
pub fn shape_agreement_on(signature: &Signature, matched: &[String], stable_only: bool) -> f64 {
    let matched: HashSet<&str> = matched.iter().map(String::as_str).collect();
    let mut dimensions: std::collections::BTreeMap<String, bool> =
        std::collections::BTreeMap::new();
    for feature in &signature.features {
        if !matches!(feature.kind, FeatureKind::Cfg | FeatureKind::Ops) {
            continue;
        }
        let key = feature.key();
        let dimension = key
            .rsplit_once(':')
            .map(|(head, _)| head)
            .unwrap_or(&key)
            .to_string();
        if stable_only && !CROSS_ISA_SHAPE_DIMENSIONS.contains(&dimension.as_str()) {
            continue;
        }
        let agrees = matched.contains(key.as_str());
        let entry = dimensions.entry(dimension).or_insert(false);
        *entry |= agrees;
    }
    if dimensions.is_empty() {
        return if stable_only { 0.0 } else { 1.0 };
    }
    dimensions.values().filter(|agrees| **agrees).count() as f64 / dimensions.len() as f64
}

/// Apply the gates: weighted threshold, minimum distinct evidence, and shape
/// corroboration for low-information signatures.
///
/// The distinct gate is vacuous for a signature with no required features
/// (shape-only signatures of very small functions), which would otherwise be
/// unable to match at all.
pub fn accepts(signature: &Signature, result: &MatchScore) -> bool {
    accepts_on(signature, result, false)
}

/// [`accepts`] on a target whose ISA family `cross_isa` ([`cross_isa`]) says
/// no sample of the signature shares.
pub fn accepts_on(signature: &Signature, result: &MatchScore, cross_isa: bool) -> bool {
    acceptance_gates(signature, result, cross_isa)
        .iter()
        .all(|(_, passed)| *passed)
}

/// The [`accepts_on`] gates in order, each `(name, passed)`: `score`
/// (the match threshold), `min_distinct` (distinct required features), and
/// `shape` (corroboration of low-information signatures). `locate
/// --explain` reports them one by one.
pub fn acceptance_gates(
    signature: &Signature,
    result: &MatchScore,
    cross_isa: bool,
) -> [(&'static str, bool); 3] {
    let required_count = signature
        .features
        .iter()
        .filter(|feature| feature.required)
        .count();
    // A matched callee name identifies the function even when it is optional
    // (a local callee only `.symtab` names): it corroborates like a required
    // one. On a stripped target it cannot match, and the shape gate applies.
    let named = result.matched.iter().any(|key| {
        key.strip_prefix("callee:")
            .is_some_and(|value| !low_information_callee(value))
    });
    let shape = !needs_shape_corroboration(signature)
        || named
        || shape_agreement(signature, &result.matched) >= MIN_SHAPE_AGREEMENT
        || (cross_isa
            && result.matched_required >= MIN_CROSS_ISA_REQUIRED
            && shape_agreement_on(signature, &result.matched, true) >= MIN_SHAPE_AGREEMENT);
    [
        ("score", result.score >= signature.match_threshold),
        (
            "min_distinct",
            result.matched_required >= signature.min_distinct.min(required_count),
        ),
        ("shape", shape),
    ]
}

/// Find accepted matches for `signature` in `source`, best first.
///
/// `hints = false` is the hint-free discovery mode: known function starts and
/// front-end bounds are ignored, so candidates come from anchor hits, decoded
/// constant values and instruction boundaries (`CodeIndex`), and direct call
/// targets (exact entries recovered from code, not symbols). `index` adds the
/// data-reference index, which turns string-anchor hits into candidates.
pub fn scan<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    limits: Option<RecoveryLimits>,
    max_candidates: usize,
    hints: bool,
    index: Option<&ReferenceIndex>,
) -> Vec<Match> {
    let hits = anchor_hits(source, signature);
    scan_candidates(
        source,
        signature,
        &hits,
        limits,
        max_candidates,
        hints,
        index,
        None,
    )
}

/// Tier 1 rate limit: candidate recoveries still allowed (M6 budgeting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBudget {
    pub remaining: usize,
}

impl Default for RecoveryBudget {
    fn default() -> Self {
        RecoveryBudget {
            remaining: DEFAULT_MAX_RECOVERIES,
        }
    }
}

/// Match one signature from precomputed Tier 0 anchor hits.
#[allow(clippy::too_many_arguments)]
pub fn scan_candidates<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    hits: &[(u64, String)],
    limits: Option<RecoveryLimits>,
    max_candidates: usize,
    hints: bool,
    index: Option<&ReferenceIndex>,
    budget: Option<&mut RecoveryBudget>,
) -> Vec<Match> {
    scan_candidates_with(
        source,
        signature,
        hits,
        limits,
        max_candidates,
        hints,
        index,
        None,
        None,
        budget,
        None,
    )
}

/// Per-image indexes for scanning many signatures against one image.
///
/// Both are whole-image passes. Building them per signature made hint-free
/// scanning cost one full decode of the image per signature; a context builds
/// them once and every [`scan_in`] call shares them.
#[derive(Debug)]
pub struct ScanContext {
    pub references: ReferenceIndex,
    pub code: CodeIndex,
    pub features: FeatureCache,
    /// Per-image feature frequencies, `[hint-free, hinted]`, built on first use.
    frequencies: [OnceLock<Option<Frequencies>>; 2],
    /// Every function name the image can give a callee, built on first use
    /// ([`unnamed_callees_optional`]).
    callee_names: OnceLock<HashSet<String>>,
}

/// How many of an image's functions carry each feature key.
#[derive(Debug)]
pub struct Frequencies {
    pub functions: usize,
    pub document_frequency: HashMap<String, u32>,
    /// Per key, the ordinals of the functions carrying it, ascending.
    pub postings: HashMap<String, Vec<u32>>,
    /// Start address of each ordinal.
    pub starts: Vec<u64>,
}

/// Images with fewer known functions give no usable frequency estimate.
pub const MIN_FREQUENCY_FUNCTIONS: usize = 32;

/// A match is rejected when more than this many of the image's functions
/// would be expected to carry all of its matched features by chance.
pub const MAX_CHANCE_MATCHES: f64 = 1.0;

impl Frequencies {
    fn build<S: ByteSource + ?Sized>(
        source: &S,
        cache: &FeatureCache,
        hints: bool,
    ) -> Option<Frequencies> {
        let starts: Vec<u64> = if hints {
            source.function_starts()
        } else {
            source
                .unwind_entries()
                .iter()
                .map(|(start, _)| *start)
                .collect()
        };
        if starts.len() < MIN_FREQUENCY_FUNCTIONS {
            return None;
        }
        // Recovering every function is the expensive part and each start is
        // independent; counting afterwards keeps the table order-free.
        let recovered = crate::parallel::map(starts.len(), |index| {
            cache.get_or_recover(source, starts[index], hints)
        });
        let mut document_frequency: HashMap<String, u32> = HashMap::new();
        let mut postings: HashMap<String, Vec<u32>> = HashMap::new();
        let mut functions = 0usize;
        let mut ordinal_starts: Vec<u64> = Vec::new();
        for candidate in recovered.into_iter().flatten() {
            let ordinal = functions as u32;
            functions += 1;
            ordinal_starts.push(candidate.start);
            for key in &candidate.keys {
                *document_frequency.entry(key.clone()).or_insert(0) += 1;
                postings.entry(key.clone()).or_default().push(ordinal);
            }
        }
        (functions >= MIN_FREQUENCY_FUNCTIONS).then_some(Frequencies {
            functions,
            document_frequency,
            postings,
            starts: ordinal_starts,
        })
    }

    /// How many of the image's functions carry every one of the candidate's
    /// own keys in `matched` (neighbour and joint keys are not the
    /// candidate's own and are skipped): the exact count the independence
    /// estimate of [`Frequencies::chance_matches`] approximates.
    pub fn carriers(&self, matched: &[String]) -> usize {
        let mut lists: Vec<&Vec<u32>> = Vec::new();
        for key in matched {
            if key.starts_with(NEIGHBOUR_PREFIX) || key.starts_with("joint:") {
                continue;
            }
            match self.postings.get(key) {
                Some(list) => lists.push(list),
                None => return 0,
            }
        }
        let Some((first, rest)) = lists.split_first() else {
            return self.functions;
        };
        first
            .iter()
            .filter(|ordinal| rest.iter().all(|list| list.binary_search(ordinal).is_ok()))
            .count()
    }

    /// Expected number of the image's functions that contain every key in
    /// `matched`, treating features as independent: `N * prod(df / N)`.
    pub fn chance_matches(&self, matched: &[String]) -> f64 {
        let total = self.functions as f64;
        let mut expected = total;
        for key in matched {
            let count = self
                .document_frequency
                .get(key)
                .copied()
                .unwrap_or(1)
                .max(1);
            expected *= f64::from(count) / total;
        }
        expected
    }
}

/// The function a direct call reaches, for the call graph: `None` for an
/// import (`memcpy` is no neighbour), and through the PLT for a call to an
/// export the image defines itself. `-fPIC` shared objects call their own
/// exported functions through PLT stubs (symbol interposition), so without
/// this an exported function has no callers. The PLT relocation and the
/// dynamic symbol both survive stripping.
fn call_destination<S: ByteSource + ?Sized>(
    source: &S,
    target: u64,
    callee: Option<&str>,
) -> Option<u64> {
    let Some(name) = callee else {
        return Some(target);
    };
    for module in source.modules() {
        if let Some((_, address)) = module.exports.iter().find(|(export, _)| export == name) {
            return Some(*address);
        }
    }
    let imported = source
        .modules()
        .iter()
        .any(|module| module.imports.values().any(|import| import == name));
    (!imported).then_some(target)
}

/// Neighbours per direction whose evidence is collected, nearest addresses
/// first: bounds the cost on hub functions called from everywhere.
pub const MAX_NEIGHBOURS: usize = 16;

pub use crate::spec::MAX_NEIGHBOUR_KEYS;

/// A shape-only hint-free match is rejected when the signature has at least
/// this many neighbour keys and the candidate's neighbours share none.
/// Simulated on the stripped real corpus (`bench --fp-report`): 1 cuts more
/// false positives but costs merged and cross-compiler recall; 2 cuts the
/// FP rate 0.203 -> 0.163 with no top-1 cell lower.
pub const MIN_NEIGHBOURS_TO_REJECT: usize = 2;

impl ScanContext {
    /// Direct callees of the function at `start` (call and tail-call
    /// targets in the image, imports excluded), nearest first, at most
    /// [`MAX_NEIGHBOURS`].
    pub fn callees_of<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        start: u64,
        hints: bool,
    ) -> Vec<u64> {
        self.features
            .get_or_recover(source, start, hints)
            .map(|found| found.calls.iter().copied().take(MAX_NEIGHBOURS).collect())
            .unwrap_or_default()
    }

    /// Functions with a direct call to `start`, by the enclosing symbol
    /// bounds (hinted) or unwind entry, sorted, at most [`MAX_NEIGHBOURS`].
    pub fn callers_of<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        start: u64,
        hints: bool,
    ) -> Vec<u64> {
        let mut found: Vec<u64> = self
            .code
            .callers
            .get(&start)
            .into_iter()
            .flatten()
            .filter_map(|site| {
                let enclosing = if hints {
                    source.hint_function(*site)
                } else {
                    None
                }
                .or_else(|| source.unwind_function(*site));
                enclosing.map(|(caller, _)| caller)
            })
            .filter(|caller| *caller != start)
            .collect();
        found.sort_unstable();
        found.dedup();
        found.truncate(MAX_NEIGHBOURS);
        found
    }

    /// `(size in bytes, direct callees)` of each direct caller of the
    /// function at `start`. Diagnostic (`bench --fp-report`): a thin wrapper
    /// caller is the one function a signature of the wrapper, signed where
    /// the callee was inlined into it, can also mean.
    pub fn caller_shapes<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        start: u64,
        hints: bool,
    ) -> Vec<(u64, usize)> {
        self.callers_of(source, start, hints)
            .into_iter()
            .filter_map(|caller| self.features.get_or_recover(source, caller, hints))
            .map(|caller| (caller.end.saturating_sub(caller.start), caller.calls.len()))
            .collect()
    }

    /// Identifying keys of the function at `start`'s call-graph neighbours:
    /// `out:` its direct callees, `in:` its callers, `out2:`/`in2:` one hop
    /// further. Strings and distinctive constants survive stripping and
    /// differ little across architectures, so a small function with no
    /// evidence of its own can borrow its neighbours'. Nearest hops first,
    /// at most [`MAX_NEIGHBOUR_KEYS`].
    pub fn neighbour_keys<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        start: u64,
        hints: bool,
    ) -> Vec<String> {
        let mut keys = Vec::new();
        let Some(candidate) = self.features.get_or_recover(source, start, hints) else {
            return keys;
        };
        let callees = |of: u64| self.callees_of(source, of, hints);
        let callers = |of: u64| self.callers_of(source, of, hints);
        let me = candidate.start;
        let out1 = callees(me);
        let in1 = callers(me);
        let hop2 = |first: &[u64], next: &dyn Fn(u64) -> Vec<u64>| -> Vec<u64> {
            let mut found: Vec<u64> = first
                .iter()
                .flat_map(|n| next(*n))
                .filter(|n| *n != me && !first.contains(n))
                .collect();
            found.sort_unstable();
            found.dedup();
            found.truncate(4 * MAX_NEIGHBOURS);
            found
        };
        let out2 = hop2(&out1, &callees);
        let in2 = hop2(&in1, &callers);
        let hops: [(&[u64], &[u64], &str); 2] = [(&out1, &in1, ""), (&out2, &in2, "2")];
        for (outgoing, incoming, hop) in hops {
            let mut found = std::collections::BTreeSet::new();
            for (direction, neighbours) in [("out", outgoing), ("in", incoming)] {
                for neighbour in neighbours.iter().filter(|n| **n != me) {
                    let Some(other) = self.features.get_or_recover(source, *neighbour, hints)
                    else {
                        continue;
                    };
                    // Own evidence only: a neighbour's inherited callee
                    // evidence (optional) is the next hop, not this one.
                    for feature in other.features.iter().filter(|f| !f.inherited) {
                        let identifying = match feature.kind {
                            FeatureKind::Str => true,
                            FeatureKind::Const => !low_information_const(&feature.value),
                            _ => false,
                        };
                        if identifying {
                            found.insert(format!("{direction}{hop}:{}", feature.key()));
                        }
                    }
                }
            }
            keys.extend(found);
        }
        keys.truncate(MAX_NEIGHBOUR_KEYS);
        keys
    }

    /// Hint-free `(functions, log10 of each matched key's frequency)`, when
    /// frequencies were built. Diagnostic for the bench report.
    pub fn key_frequencies(&self, matched: &[String]) -> Option<(usize, Vec<f64>)> {
        let frequencies = self.frequencies[0].get()?.as_ref()?;
        let total = frequencies.functions as f64;
        Some((
            frequencies.functions,
            matched
                .iter()
                .map(|key| {
                    let count = frequencies
                        .document_frequency
                        .get(key)
                        .copied()
                        .unwrap_or(1)
                        .max(1);
                    (f64::from(count) / total).log10()
                })
                .collect(),
        ))
    }

    /// Hint-free [`Frequencies::carriers`] of `matched`, when frequencies were
    /// built. Diagnostic for the bench report.
    pub fn key_carriers(&self, matched: &[String]) -> Option<usize> {
        Some(self.frequencies[0].get()?.as_ref()?.carriers(matched))
    }

    /// Build the image's feature frequencies now instead of on the first
    /// accepted match. A multi-signature scan calls this before scanning in
    /// parallel, so the table is built across all cores once rather than by
    /// whichever worker gets there first while the others wait on it.
    pub fn prepare_frequencies<S: ByteSource + ?Sized>(&self, source: &S, hints: bool) {
        self.frequencies[usize::from(hints)]
            .get_or_init(|| Frequencies::build(source, &self.features, hints));
    }

    /// Similarity to `signature` of the closest other function in the image
    /// that holds every identifying key `found` matched: its own keys (held
    /// directly or inherited) and its shared neighbour keys. Such a function
    /// is a rival the evidence cannot tell apart from `found`; only shape
    /// separates them. Candidates are the functions carrying every own
    /// identifying key (from the frequency postings) or, when the match has
    /// only neighbour keys, its call-graph siblings (the other callees of
    /// its callers and the other callers of its callees). At most
    /// [`MAX_RIVALS`] are compared. `None` when there is none, when the
    /// match has no identifying key, or on images too small for
    /// frequencies.
    pub fn rival<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        signature: &Signature,
        found: &Match,
        hints: bool,
    ) -> Option<f64> {
        let own: Vec<&str> = found
            .matched
            .iter()
            .filter(|key| {
                identifying_key(key)
                    && !key.starts_with(NEIGHBOUR_PREFIX)
                    && !key.starts_with("joint:")
            })
            .map(String::as_str)
            .collect();
        let near: Vec<&str> = found
            .matched
            .iter()
            .filter_map(|key| key.strip_prefix(NEIGHBOUR_PREFIX))
            .collect();
        if own.is_empty() && near.is_empty() {
            return None;
        }
        let frequencies = self.frequencies[usize::from(hints)]
            .get_or_init(|| Frequencies::build(source, &self.features, hints))
            .as_ref()?;
        let mut pool: Vec<u64> = if own.is_empty() {
            let mut siblings: Vec<u64> = Vec::new();
            for caller in self.callers_of(source, found.address, hints) {
                siblings.extend(self.callees_of(source, caller, hints));
            }
            for callee in self.callees_of(source, found.address, hints) {
                siblings.extend(self.callers_of(source, callee, hints));
            }
            siblings
        } else {
            let carriers = |key: &str| -> Vec<u32> {
                let mut list: Vec<u32> = [key.to_string(), format!("{INHERITED_PREFIX}{key}")]
                    .iter()
                    .filter_map(|key| frequencies.postings.get(key))
                    .flatten()
                    .copied()
                    .collect();
                list.sort_unstable();
                list.dedup();
                list
            };
            let lists: Vec<Vec<u32>> = own.iter().map(|key| carriers(key)).collect();
            let (first, rest) = lists.split_first()?;
            first
                .iter()
                .filter(|ordinal| rest.iter().all(|list| list.binary_search(ordinal).is_ok()))
                .filter_map(|ordinal| frequencies.starts.get(*ordinal as usize).copied())
                .collect()
        };
        pool.retain(|start| *start != found.address);
        pool.sort_unstable();
        pool.dedup();
        pool.truncate(MAX_RIVALS);
        let mut best: Option<f64> = None;
        for start in pool {
            let Some(candidate) = self.features.get_or_recover(source, start, hints) else {
                continue;
            };
            // Overlapping recoveries of the match itself are not rivals.
            if candidate.start < found.end && found.address < candidate.end {
                continue;
            }
            if !near.is_empty() {
                let keys = self.neighbour_keys(source, start, hints);
                if !near.iter().all(|key| keys.iter().any(|held| held == key)) {
                    continue;
                }
            }
            let similar = similarity(signature, &candidate.weighted);
            if best.is_none_or(|best| similar > best) {
                best = Some(similar);
            }
        }
        best
    }

    pub fn build<S: ByteSource + ?Sized>(source: &S) -> ScanContext {
        // The reference and code indexes are the same linear sweep read two
        // ways, so one decode of each region feeds both. Each keeps its own
        // budgets and stops exactly where its own sweep would have.
        let mut references = ReferenceIndex::default();
        let mut code = CodeIndexBuild::default();
        for region in source.regions().iter().filter(|region| region.executable) {
            let mut reference_build = references.begin_region(region);
            if reference_build.is_none() && code.done {
                continue;
            }
            let mut sweep = RegionSweep::new(source, region);
            while !sweep.at_end() {
                let reference_active = reference_build.as_mut().is_some_and(|build| build.wants());
                let code_active = code.wants();
                if !reference_active && !code_active {
                    break;
                }
                let Some(step) = sweep.next_step() else {
                    break;
                };
                if reference_active {
                    if let Some(build) = reference_build.as_mut() {
                        build.feed(&step);
                    }
                }
                if code_active {
                    code.feed(source, &step);
                }
            }
            if let Some(build) = reference_build {
                references.finish_region(region, build);
            }
            code.finish_region(region);
        }
        references.rebuild_merged();
        ScanContext {
            references,
            code: code.finish(),
            features: FeatureCache::default(),
            frequencies: [OnceLock::new(), OnceLock::new()],
            callee_names: OnceLock::new(),
        }
    }
}

/// `signature` with the required callees a target that names no function
/// cannot hold made optional, or `None` when nothing changes.
///
/// A callee key without `!` names a function of the signed image itself,
/// resolved through that image's dynamic exports. A shared object exports
/// its functions, but the same code linked into an executable (PIE or
/// static) or built with hidden visibility exports none of them: the call
/// is there, its name is not. Demanding the key then rejects the true
/// function on evidence the target can never show. On the `--world` tier,
/// same arch hint-free, every acceptance failure of a shared-object
/// signature in PIE and static targets that lacked a required feature
/// lacked such a callee (11 of 40 PIE and 13 of 40 static pairs,
/// `examples/diagnose_cross`). The key still counts when present.
fn unnamed_callees_optional<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    context: &ScanContext,
) -> Option<Signature> {
    let unnamed = |feature: &crate::sigfile::SignatureFeature| {
        feature.required
            && feature.kind == FeatureKind::Callee
            && !low_information_callee(&feature.value)
    };
    if !signature.features.iter().any(unnamed) {
        return None;
    }
    // Only a target that names no function of its own: one that names some
    // (a shared object) and lacks this one is evidence the function is not
    // there. Waiving in every target that lacked the name doubled the real
    // corpus's any-verdict false positives (arm32 0.117 -> 0.217), because
    // unrelated libraries lack it too.
    let names = context.callee_names.get_or_init(|| {
        source
            .modules()
            .iter()
            .flat_map(|module| {
                module
                    .exports
                    .iter()
                    .map(|(name, _)| name)
                    .chain(module.functions.values())
            })
            .filter_map(|name| crate::features::canonical_callee(name))
            .map(str::to_string)
            .collect()
    });
    if !names.is_empty() {
        return None;
    }
    // Optional, not dropped: measured on the `--world` tier against the
    // gcc-O2 shared object, hint-free. Optional gave PIE / static same-arch
    // top-1 0.700 / 0.613 (from 0.613 / 0.525) with the hint-free
    // any-verdict FP rate 0.105 -> 0.132. Dropping the keys gave 0.713 /
    // 0.625 but 0.167, past the tolerance: a signature whose only
    // identifying keys were these names is left with shape alone, and
    // lookalikes in unrelated executables match it. Dropping them only when
    // other identifying keys remain gave 0.625 / 0.537 at 0.134.
    let mut adapted = signature.clone();
    for feature in &mut adapted.features {
        if unnamed(feature) {
            feature.required = false;
        }
    }
    Some(adapted)
}

/// [`scan`] with the image's shared indexes: string anchors seed candidates
/// through the reference index in both modes, and hint-free discovery reuses
/// the code index instead of rebuilding it.
pub fn scan_in<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    context: &ScanContext,
    hints: bool,
) -> Vec<Match> {
    // The keys a target cannot name stay identifying: a match that holds
    // none of the rest still needs `MIN_UNANCHORED_SIMILARITY`, so the
    // lighter required set does not admit lookalikes.
    let identifying = identifying_required(signature);
    let adapted = unnamed_callees_optional(source, signature, context);
    let signature = adapted.as_ref().unwrap_or(signature);
    let mut matches = scan_in_ranked(source, signature, &identifying, context, hints);
    // Only the first match can be an answer, so only it needs a rival.
    if let Some(first) = matches.first() {
        if identified(first) {
            let rival = context.rival(source, signature, first, hints);
            matches[0].rival = rival;
        }
    }
    matches
}

/// Most functions [`ScanContext::rival`] compares with a match. Bounded
/// because a common key's carriers can be most of an image.
pub const MAX_RIVALS: usize = 64;

fn scan_in_ranked<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    identifying: &[String],
    context: &ScanContext,
    hints: bool,
) -> Vec<Match> {
    // Hint-free candidates are the image's unwind entries, which the
    // frequency table below recovers anyway. Building it first recovers
    // them on every core; the candidate loop then finds them cached instead
    // of recovering each in turn (single-signature `locate` on stripped
    // Thumb sqlite spent most of its scan there).
    if !hints {
        context.prepare_frequencies(source, hints);
    }
    let hits = anchor_hits(source, signature);
    let signature_neighbours: HashSet<&str> =
        signature.neighbours.iter().map(String::as_str).collect();
    // Hint-free, a candidate of a low-information signature that fails only
    // the shape gate is still offered when it shares one of the signature's
    // neighbour keys: across compilers and levels the shape buckets are what
    // changes, while the strings and constants of the callers and callees
    // stay. The neighbour gates below then treat it like any match with
    // shared neighbour evidence. It must also reach
    // `MIN_WAIVED_SHAPE_SIMILARITY`.
    let shares_neighbour = |start: u64, similarity: f64| {
        shares_neighbour_key(
            source,
            context,
            &signature_neighbours,
            start,
            similarity,
            hints,
        )
    };
    let waiver: Option<&dyn Fn(u64, f64) -> bool> = (frequency_gated(source, context, hints)
        && !signature_neighbours.is_empty())
    .then_some(&shares_neighbour);
    let matches = scan_candidates_with(
        source,
        signature,
        &hits,
        None,
        MAX_CANDIDATE_STARTS,
        hints,
        Some(&context.references),
        Some(&context.code),
        Some(&context.features),
        None,
        waiver,
    );
    // Image-relative specificity: a match made only of features that many of
    // this image's functions carry (common imports, boilerplate constants,
    // frequent shape buckets) is coincidence, not identification. Applied to
    // hint-free scans only, where it was measured: a stripped image's whole
    // function list is compared, so coincidences are frequent there. Images
    // too small for frequencies keep every accepted match.
    if hints {
        // Hinted scans skip the frequency gates, but a shape-only lookalike
        // is no less a coincidence in an unstripped image: the hinted
        // candidate list is every symbol start, so the same floors apply
        // (measured: see `MIN_SHAPE_ONLY_SIMILARITY`), and a match resting
        // on constants alone needs hint-free's similarity floor (see
        // `MIN_CONSTANT_ANCHORED_SIMILARITY`). Small images are exempt for
        // the same reason as in hint-free mode.
        return hinted_floors_with(source, identifying, matches);
    }
    let frequencies = context.frequencies[usize::from(hints)]
        .get_or_init(|| Frequencies::build(source, &context.features, hints));
    let Some(frequencies) = frequencies else {
        return matches;
    };
    let mut kept: Vec<Match> = matches
        .into_iter()
        .filter_map(|found| {
            hint_free_floors(
                source,
                signature,
                &signature_neighbours,
                identifying,
                context,
                frequencies,
                found,
            )
            .ok()
        })
        .collect();
    // Shared neighbour evidence ranks first: among lookalikes with similar
    // shape, the one wired to the same strings and constants is the function.
    kept.sort_by(|left, right| {
        rank_key(right)
            .partial_cmp(&rank_key(left))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.address.cmp(&right.address))
    });
    kept
}

/// Whether the hint-free gates that need frequencies apply: hint-free, on
/// an image large enough for them.
fn frequency_gated<S: ByteSource + ?Sized>(source: &S, context: &ScanContext, hints: bool) -> bool {
    !hints
        && context.frequencies[usize::from(hints)]
            .get_or_init(|| Frequencies::build(source, &context.features, hints))
            .is_some()
}

/// The shape waiver of [`scan_in`]: a candidate similar enough
/// ([`MIN_WAIVED_SHAPE_SIMILARITY`]) whose call-graph neighbours carry one
/// of the signature's neighbour keys.
fn shares_neighbour_key<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signature_neighbours: &HashSet<&str>,
    start: u64,
    similarity: f64,
    hints: bool,
) -> bool {
    similarity >= MIN_WAIVED_SHAPE_SIMILARITY
        && context
            .neighbour_keys(source, start, hints)
            .iter()
            .any(|key| signature_neighbours.contains(key.as_str()))
}

/// The hint-free gates after acceptance, in order, on an image with
/// `frequencies`: the match with its shared neighbour keys added, or the
/// name of the gate that rejected it (`similarity`, `anchoring`, `chance`,
/// `neighbours`, `evidence`; `locate --explain` reports it).
fn hint_free_floors<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    signature_neighbours: &HashSet<&str>,
    identifying: &[String],
    context: &ScanContext,
    frequencies: &Frequencies,
    mut found: Match,
) -> Result<Match, &'static str> {
    let hints = false;
    if found.similarity < MIN_SIMILARITY {
        return Err("similarity");
    }
    if !anchored_enough(identifying, &found) {
        return Err("anchoring");
    }
    let own_evidence = identified(&found);
    let shared: Vec<String> = if signature_neighbours.is_empty() {
        Vec::new()
    } else {
        context
            .neighbour_keys(source, found.address, hints)
            .into_iter()
            .filter(|key| signature_neighbours.contains(key.as_str()))
            .map(|key| format!("{NEIGHBOUR_PREFIX}{key}"))
            .collect()
    };
    // The chance gate prices only the candidate's own keys. A shared
    // neighbour key is evidence it does not see: a one-block helper has the
    // commonest shape in the image, yet only one such helper is called from
    // the function holding the signature's string.
    if shared.is_empty() && !specific(frequencies, &found) {
        return Err("chance");
    }
    // A function whose neighbours carry evidence is expected to keep some of
    // it: a shape-only lookalike elsewhere shares none.
    if !own_evidence && shared.is_empty() && signature.neighbours.len() >= MIN_NEIGHBOURS_TO_REJECT
    {
        return Err("neighbours");
    }
    if !shared.is_empty() {
        found.matched.extend(shared);
        found.matched.sort();
    } else if !enough_evidence(&found) {
        return Err("evidence");
    }
    Ok(found)
}

/// Functions an image is known to have, for telling a small image from a
/// large one: symbol starts or unwind entries, whichever is more. A live
/// process names no symbol starts, only `.pdata` bounds, so counting starts
/// alone exempted every process scan from the hinted floors.
fn known_functions<S: ByteSource + ?Sized>(source: &S) -> usize {
    source
        .function_starts()
        .len()
        .max(source.unwind_entries().len())
}

/// The trust floors every hinted match passes ([`scan_in`]): a shape-only
/// lookalike needs [`MIN_SHAPE_ONLY_SIMILARITY`], a match holding none of
/// the signature's identifying keys [`MIN_UNANCHORED_SIMILARITY`], and one
/// resting on constants alone [`MIN_CONSTANT_ANCHORED_SIMILARITY`]. Images
/// with fewer than [`MIN_FREQUENCY_FUNCTIONS`] known functions keep every
/// match, as in hint-free mode. Shared with the incremental scanner, so a
/// process scan is held to the floors the bench measures on files.
pub fn hinted_floors<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    matches: Vec<Match>,
) -> Vec<Match> {
    hinted_floors_with(source, &identifying_required(signature), matches)
}

fn hinted_floors_with<S: ByteSource + ?Sized>(
    source: &S,
    identifying: &[String],
    matches: Vec<Match>,
) -> Vec<Match> {
    if !hinted_floors_apply(source) {
        return matches;
    }
    matches
        .into_iter()
        .filter(|found| hinted_floor(identifying, found).is_ok())
        .collect()
}

/// Whether [`hinted_floors`] judges matches in `source` at all: small
/// images are exempt.
pub fn hinted_floors_apply<S: ByteSource + ?Sized>(source: &S) -> bool {
    known_functions(source) >= MIN_FREQUENCY_FUNCTIONS
}

/// The [`hinted_floors`] gates in order: `Ok`, or the name of the gate that
/// rejects `found` (`evidence`, `anchoring`, `constants`).
fn hinted_floor(identifying: &[String], found: &Match) -> Result<(), &'static str> {
    if !enough_evidence(found) {
        Err("evidence")
    } else if !anchored_enough(identifying, found) {
        Err("anchoring")
    } else if !constants_enough(found) {
        Err("constants")
    } else {
        Ok(())
    }
}

/// Similarity a hint-free candidate needs when a shared neighbour key, not
/// shape agreement, corroborates a low-information signature ([`scan_in`]).
/// Measured on the full stripped real corpus (`bench --max-functions 4
/// --joint`): at 0.4 hint-free top-1 hits 4208 -> 4487 with every FP rate
/// unchanged, identified precision 0.973 -> 0.969 (21 of 225 waived
/// identified answers wrong). Higher floors swept offline on the logged
/// waived matches (`bench --fp-report`): 0.45 4379 hits, precision 0.970;
/// 0.5 4296, 0.971; 0.6 4221, 0.972. An earlier x64 + arm64 slice
/// simulation found that lower floors (none, 0.3, 0.35) cost precision and,
/// with no floor, one more FP signature (a two-hop `0x7fffffff`).
///
/// A waived match is never `identified` ([`identified_answer`]): the shape
/// that failed plus a shared neighbour key is a candidate, not a name
/// (PLAN.md §4 rule 8). At spec v5 waived answers were 175 correct and 31
/// wrong hint-free (11 of those in unrelated libraries, on neighbour
/// constants like `0x10000`), so labelling them `candidate` raises
/// identified precision 0.974 -> 0.981; top-1 is unchanged.
pub const MIN_WAIVED_SHAPE_SIMILARITY: f64 = 0.4;

/// Prefix of a matched neighbour key in [`Match::matched`].
pub const NEIGHBOUR_PREFIX: &str = "near:";

/// Neighbour keys a match shares with its signature.
pub fn corroboration(found: &Match) -> usize {
    found
        .matched
        .iter()
        .filter(|key| key.starts_with(NEIGHBOUR_PREFIX))
        .count()
}

/// How matches are ordered, best first: placement by joint resolution and
/// the links it preserves ([`crate::joint::rank`]), shared neighbour
/// evidence, similarity, then score. Two matches with equal keys are a tie.
pub fn rank_key(found: &Match) -> (usize, usize, f64, f64) {
    (
        crate::joint::rank(found),
        corroboration(found),
        found.similarity,
        found.score,
    )
}

/// A matched key that identifies a function by itself: a string, a callee
/// inside the image, or a constant away from zero.
pub fn identifying_key(key: &str) -> bool {
    match key.split_once(':') {
        Some(("str", _)) => true,
        Some(("near", _)) => true,
        // `joint:0` is a placement by similarity and the one-to-one mapping
        // alone; only preserved call-graph links identify.
        Some(("joint", votes)) => votes != "0",
        Some(("callee", value)) => !low_information_callee(value),
        Some(("const", value)) => !low_information_const(value),
        _ => false,
    }
}

/// Matched features a hint-free match needs when none of them identifies the
/// function. Measured on the stripped real corpus (`bench --fp-report`):
/// every false positive but two matched only low-information keys, and those
/// with fewer than 6 (three CFG buckets, a couple of op classes, constant 0)
/// were all coincidences: 6 cut the hint-free FP rate 0.250 -> 0.203 without
/// moving any top-1 cell; each further step trades recall for precision at
/// the same rate as a similarity floor or a recalibrated chance gate. Like
/// the chance gate it applies only to images large enough for frequencies:
/// in a few dozen functions coincidences are rare, and the toy corpus's tiny
/// functions have fewer than 6 features to match.
pub const MIN_LOW_INFORMATION_MATCHED: usize = 6;

/// Minimum similarity of a shape-only match (no identifying key), in both
/// discovery modes, on images large enough for frequencies. Simulated on the
/// real corpus (`bench --fp-report`, both modes logged, max 4 functions):
/// 0.3 moves no hint-free top-1 answer and cuts the hint-free any-verdict FP
/// rate 0.163 -> 0.156; in hinted mode, together with the 6-feature minimum
/// that hint-free already applied, top-1 hits rise 4127 -> 4137 (a shape-only
/// lookalike no longer outranks the function) and the any-verdict FP rate
/// falls 0.196 -> 0.113, strong 0.072 -> 0.042. 0.35 costs 4 hint-free and
/// 22 hinted top-1 hits for 0.146 / 0.099; 0.4 costs 31 and 47 for 0.137 /
/// 0.090; requiring 7 matched features instead of 6 costs 26 and 37.
pub const MIN_SHAPE_ONLY_SIMILARITY: f64 = 0.3;

/// Whether a match rests on evidence that identifies a function (see
/// [`identifying_key`]) rather than only shape and near-zero constants.
/// Front-ends report it: a shape-only match of a small function is often
/// right in its own library, but the same evidence also fires on lookalikes
/// in unrelated code.
pub fn identified(found: &Match) -> bool {
    found.matched.iter().any(|key| identifying_key(key))
}

/// Similarity an identified first match needs to be the answer when its
/// evidence is a direct neighbour's (`near:in:`, `near:out:`) or call-graph
/// votes (`joint:`) rather than a string of its own; anything weaker (callees,
/// constants, two-hop neighbours) needs [`MIN_ANSWER_SIMILARITY`]. A matched
/// string needs no floor: no identified first match with a string was wrong
/// in either mode. Simulated on the real corpus (both modes logged, after the
/// shape-only floor): labelling every untied identified first match gives
/// precision hint-free 0.886, hinted 0.722. With these floors at 0.3 / 0.7:
/// 0.981 / 0.987, with 2715 / 1759 correct answers kept of 3087 / 3619 (top-1
/// recall is unchanged: only the label moves). Neighbour floor 0.2 gives
/// 0.963 hint-free (five answers in unrelated images), 0.4 gives 0.985 but
/// drops 219 correct hint-free answers. Other floor 0.6: 0.978 / 0.977;
/// 0.65: 0.980 / 0.986, under target hint-free; 0.75: 0.984 / 0.990 for 30 /
/// 116 fewer correct answers. `joint:` votes are not in the single-signature
/// bench; they rank with direct neighbours because both are call-graph
/// evidence. Not yet checked on the held-out corpus.
///
/// Re-simulated at spec v5 (`bench --fp-report`, hint-free; hinted answers
/// do not move between 0.3 and 0.5): resolved ARM PIC strings and in-module
/// constants give twins (`cJSONUtils_GeneratePatches` and its
/// `CaseSensitive` sibling call the same helper) and wrappers shared
/// neighbour evidence, so 0.3 fell to 0.970 (3672 correct, 115 wrong). 0.42
/// gives 0.981 (3321 / 64); 0.40: 0.979 (3375 / 74); 0.45: 0.983 (3256 /
/// 57); 0.5: 0.985 (3158 / 48). v5 at 0.42 still has more correct
/// answers than v4 at 0.3 (2747 / 54); on the v4 logs 0.42 gives 0.985
/// (2485 / 37).
pub const MIN_ANSWER_SIMILARITY_NEIGHBOUR: f64 = 0.42;

/// See [`MIN_ANSWER_SIMILARITY_NEIGHBOUR`].
pub const MIN_ANSWER_SIMILARITY: f64 = 0.7;

/// A first match is no answer when a rival ([`ScanContext::rival`]) holding
/// the same identifying keys resembles the signature within this much of
/// it: source twins (`cJSONUtils_GeneratePatches` and its `CaseSensitive`
/// sibling, which differ in one boolean argument) then rest on shape alone.
/// Simulated on the real corpus at spec v5 (`bench --fp-report`, both
/// modes, after waived matches lost the label), identified precision
/// hint-free / hinted with correct answers kept: no rival rule 0.981
/// (3322) / 0.989 (2349); 0.02 0.982 (3316) / 0.991 (2348); 0.05 0.986
/// (3244) / 0.993 (2345); 0.1 0.993 (3163) / 0.994 (2267); 0.2 0.993
/// (3015) / 0.995 (2185). Answers whose rival lies 0.05-0.1 below were 77%
/// right hint-free (81 correct, 24 wrong), short of the promise; the
/// 0.1-0.2 band 148 correct for 1 wrong.
pub const RIVAL_MARGIN: f64 = 0.1;

/// What a match in a ranked list can be trusted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The first match, alone at the top, on evidence that names a function
    /// and resembling the signature enough to be the answer.
    Identified,
    /// Identifying evidence, but not a trusted answer: not first, tied for
    /// first, or too dissimilar for the evidence it rests on.
    Candidate,
    /// Only shape, near-zero constants, and imports matched.
    ShapeOnly,
}

impl Evidence {
    pub fn label(self) -> &'static str {
        match self {
            Evidence::Identified => "identified",
            Evidence::Candidate => "candidate",
            Evidence::ShapeOnly => "shape-only",
        }
    }
}

/// Whether the first of `matches` (ranked best first) is an identified
/// answer: identifying evidence, strictly first (a tie is no answer), and
/// similar enough for the kind of evidence it rests on.
pub fn identified_answer(matches: &[Match]) -> bool {
    answer_gate(matches).is_ok()
}

/// [`identified_answer`] with the reason: `Ok`, or the name of the rule
/// that withholds the label (`none`, `not-identified`, `tie`, `waived`,
/// `rival`, `answer-similarity`; `locate --explain` reports it).
pub fn answer_gate(matches: &[Match]) -> Result<(), &'static str> {
    let Some(first) = matches.first() else {
        return Err("none");
    };
    if !identified(first) {
        return Err("not-identified");
    }
    if matches
        .get(1)
        .is_some_and(|next| rank_key(next) == rank_key(first))
    {
        return Err("tie");
    }
    // Preserved call-graph links are evidence of their own; without them a
    // waived shape gate or a rival the evidence cannot tell apart leaves
    // only shape to name the function.
    if crate::joint::votes(first) == 0 {
        if first.waived {
            return Err("waived");
        }
        if first
            .rival
            .is_some_and(|rival| rival >= first.similarity - RIVAL_MARGIN)
        {
            return Err("rival");
        }
    }
    if first.similarity >= answer_floor(first) {
        Ok(())
    } else {
        Err("answer-similarity")
    }
}

/// The similarity an identified first match needs for the evidence it
/// rests on (see [`MIN_ANSWER_SIMILARITY_NEIGHBOUR`]).
pub fn answer_floor(first: &Match) -> f64 {
    let named_by_string = first.matched.iter().any(|key| key.starts_with("str:"));
    if named_by_string {
        0.0
    } else if first
        .matched
        .iter()
        .any(|key| key.starts_with("near:in:") || key.starts_with("near:out:"))
        || crate::joint::votes(first) > 0
    {
        MIN_ANSWER_SIMILARITY_NEIGHBOUR
    } else {
        MIN_ANSWER_SIMILARITY
    }
}

/// The [`Evidence`] of `matches[index]` in a list ranked best first.
pub fn evidence(matches: &[Match], index: usize) -> Evidence {
    if index == 0 && identified_answer(matches) {
        Evidence::Identified
    } else if matches.get(index).is_some_and(identified) {
        Evidence::Candidate
    } else {
        Evidence::ShapeOnly
    }
}

fn enough_evidence(found: &Match) -> bool {
    identified(found)
        || (found.matched.len() >= MIN_LOW_INFORMATION_MATCHED
            && found.similarity >= MIN_SHAPE_ONLY_SIMILARITY)
}

/// Minimum similarity for any accepted match. Measured on stripped x64 and
/// arm64: 0.2 keeps every single-arch and cross-arch top-1 cell and cuts
/// merged hint-free false positives 0.242 -> 0.141; 0.3 starts losing true
/// cross-compiler matches, whose similarity is genuinely low.
pub const MIN_SIMILARITY: f64 = 0.2;

/// Minimum similarity of an *unanchored* match, in both discovery modes, on
/// images large enough for frequencies: the signature has required features
/// that identify a function ([`identifying_key`]), and the match holds none
/// of them (an inherited `inl:` copy does not count), so it reached the
/// threshold on imports, near-zero constants, and shape alone. The function
/// is expected to keep some of what identifies it. Measured on the real
/// corpus (full bench, `--max-functions 4 --joint --fp-report`): the single
/// signatures' unanchored false hits reach similarity 0.218 at most (5
/// hint-free signatures, and a merged `LZ4_loadDict` at 0.08 in hinted mode,
/// the last strong false positive); the whole-module sets' reach 0.244
/// (cjson, zlib); the lowest unanchored true matches are 0.228 hint-free and
/// 0.249 hinted. Both 0.22 and 0.25 were built and benched. At 0.25:
/// hint-free any-verdict FP 0.154 -> 0.146, hinted 0.111 -> 0.109, strong
/// 0.011 -> 0.000 (under the two-identifying-feature `strong` rule), joint
/// sets' false-hit signatures cjson 21 -> 20 and zlib 8 -> 6, hint-free
/// top-1 3704 -> 3705 (two lookalikes removed, the 0.228 match lost),
/// hinted 4177 -> 4176. 0.22 keeps both low true matches (hinted 4177) but
/// none of the joint sets' false hits; precision first (PLAN.md §4 rule 7).
/// Simulated: 0.27 costs 4 hint-free top-1 hits, 0.3 costs 8, 0.35 costs 15
/// and 27 hinted for 3 more signatures, rejecting every unanchored match
/// 107 / 102; 0.21 removes 1 of the 5 hint-free signatures, 0.2 none.
pub const MIN_UNANCHORED_SIMILARITY: f64 = 0.25;

/// Minimum similarity of a hinted match whose identifying evidence is
/// constants alone (no string, in-image callee, or neighbour key), on images
/// large enough for frequencies. It is the floor hint-free mode already
/// applies to every match ([`MIN_SIMILARITY`]); hinted mode had none, so a
/// distinctive-looking constant carried a match at any similarity. Since
/// in-module constants are kept (spec v5) `LZ4_loadDict`'s `0x10000` and
/// `0x4000` and `inflateCopy`'s `0x558` occur in sqlite
/// and lz4 too, and those hits at similarity 0.01-0.12 were
/// the three strong false positives (0.025).
///
/// Simulated on the real corpus (`bench --max-functions 4 --joint
/// --fp-report`, hinted recall scans and unrelated-library hits): every
/// constant-anchored hit in an unrelated library is below 0.19 (172 hits),
/// the lowest constant-anchored true top-1 match is 0.223
/// (`inflateCodesUsed`), and the lowest true one at any rank 0.193. At 0.2:
/// strong FP 0.025 -> 0.000, hinted any-verdict 0.105 -> 0.075, top-1
/// unchanged (4750), one true match below the top lost. Lost: the same floor
/// on every hinted match costs 47 top-1 hits (callee-anchored true matches
/// reach down to 0.132, `pagerWriteLargeSector` across ISAs); on every match
/// 0.13 is the highest that keeps top-1 (strong 0.000, any-verdict 0.081)
/// but sits 0.002 below that true match; constants-only 0.15 leaves
/// any-verdict 0.077, and 0.25 costs 2 top-1 hits (`inflateCodesUsed`).
pub const MIN_CONSTANT_ANCHORED_SIMILARITY: f64 = MIN_SIMILARITY;

/// Whether `found` is identified by constants alone.
fn constant_anchored(found: &Match) -> bool {
    let mut identifying = found
        .matched
        .iter()
        .filter(|key| identifying_key(key))
        .peekable();
    identifying.peek().is_some() && identifying.all(|key| key.starts_with("const:"))
}

/// Whether a hinted `found` is not [`constant_anchored`], or else similar
/// enough (see [`MIN_CONSTANT_ANCHORED_SIMILARITY`]).
fn constants_enough(found: &Match) -> bool {
    !constant_anchored(found) || found.similarity >= MIN_CONSTANT_ANCHORED_SIMILARITY
}

/// The signature's required features that identify a function by
/// themselves, as keys.
fn identifying_required(signature: &Signature) -> Vec<String> {
    signature
        .features
        .iter()
        .filter(|feature| feature.required)
        .map(|feature| feature.key())
        .filter(|key| identifying_key(key))
        .collect()
}

/// Whether `found` holds one of the signature's identifying required
/// features, or else is similar enough to stand without them (see
/// [`MIN_UNANCHORED_SIMILARITY`]).
fn anchored_enough(identifying: &[String], found: &Match) -> bool {
    identifying.is_empty()
        || found.similarity >= MIN_UNANCHORED_SIMILARITY
        || identifying.iter().any(|key| found.matched.contains(key))
}

fn specific(frequencies: &Frequencies, found: &Match) -> bool {
    found.similarity >= MIN_SIMILARITY
        && frequencies.chance_matches(&found.matched) <= MAX_CHANCE_MATCHES
}

/// The candidate starts [`scan_in`] would try, in order. Diagnostic: it
/// separates "the start was never a candidate" from "it was, but did not
/// match" when a scan misses.
pub fn explain_candidates<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    context: &ScanContext,
    hints: bool,
) -> Vec<u64> {
    let hits = anchor_hits(source, signature);
    candidate_starts(
        source,
        signature,
        &hits,
        MAX_CANDIDATE_STARTS,
        hints,
        Some(&context.references),
        Some(&context.code),
    )
}

/// One matcher gate as [`explain`] saw it: its name, whether the candidate
/// passed, and the value compared with the threshold where there is one.
#[derive(Debug, Clone, PartialEq)]
pub struct GateResult {
    pub gate: &'static str,
    pub passed: bool,
    pub value: Option<f64>,
    pub needed: Option<f64>,
}

/// Why [`scan_in`] did or did not return the function at one address, for
/// `locate --explain`. Every gate result comes from the matcher's own gate
/// functions; the ranked list, rank, evidence label, and rival are
/// [`scan_in`]'s own answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Explanation {
    pub address: u64,
    /// The recovered function's bounds, when recovery succeeded.
    pub start: Option<u64>,
    pub end: Option<u64>,
    /// The address is one of the candidate starts the scan tries
    /// ([`explain_candidates`]).
    pub candidate: bool,
    pub score: f64,
    pub similarity: f64,
    /// Signature keys the candidate holds itself.
    pub matched: Vec<String>,
    /// Signature keys the candidate holds only through a small callee
    /// (`inl:`, credited at [`INHERITED_CREDIT`]).
    pub inherited: Vec<String>,
    /// Signature keys it lacks, each with whether it is required.
    pub missed: Vec<(String, bool)>,
    pub matched_required: usize,
    pub required: usize,
    /// Required callees made optional because the target names no
    /// function ([`unnamed_callees_optional`]).
    pub optional_callees: Vec<String>,
    /// The signature's neighbour keys the candidate's call-graph neighbours
    /// carry, and those they do not.
    pub neighbours_shared: Vec<String>,
    pub neighbours_missed: Vec<String>,
    pub cross_isa: bool,
    /// Gates in the order the scan applies them, up to the first that
    /// failed.
    pub gates: Vec<GateResult>,
    /// The first failed gate, `ranked-out` when every gate passed but the
    /// match was deduplicated or fell past [`MAX_MATCHES`], else `accepted`.
    pub decided: String,
    /// Position in [`scan_in`]'s ranked list.
    pub rank: Option<usize>,
    pub matches: usize,
    /// [`Evidence`] label at that rank.
    pub evidence: Option<&'static str>,
    /// For the first match, why it is not `identified` ([`answer_gate`]).
    pub answer_withheld: Option<&'static str>,
    pub answer_floor: Option<f64>,
    pub rival: Option<f64>,
    /// Hint-free: expected chance carriers of the matched keys and the
    /// exact count, on images with frequencies.
    pub chance: Option<f64>,
    pub carriers: Option<usize>,
}

/// Explain [`scan_in`]'s verdict on the function at `address` (see
/// [`Explanation`]). Recovers it through the context's cache, so the
/// candidate compared is the one the scan compared.
pub fn explain<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    context: &ScanContext,
    hints: bool,
    address: u64,
) -> Explanation {
    let matches = scan_in(source, signature, context, hints);
    let rank = matches.iter().position(|found| found.address == address);
    let identifying = identifying_required(signature);
    let adapted = unnamed_callees_optional(source, signature, context);
    let adapted_signature = adapted.as_ref().unwrap_or(signature);
    let optional_callees = match &adapted {
        Some(adapted) => signature
            .features
            .iter()
            .zip(&adapted.features)
            .filter(|(before, after)| before.required && !after.required)
            .map(|(before, _)| before.key())
            .collect(),
        None => Vec::new(),
    };
    let candidate =
        explain_candidates(source, adapted_signature, context, hints).contains(&address);
    let cross = cross_isa(adapted_signature, source.arch());
    let mut explanation = Explanation {
        address,
        start: None,
        end: None,
        candidate,
        score: 0.0,
        similarity: 0.0,
        matched: Vec::new(),
        inherited: Vec::new(),
        missed: Vec::new(),
        matched_required: 0,
        required: adapted_signature
            .features
            .iter()
            .filter(|feature| feature.required)
            .count(),
        optional_callees,
        neighbours_shared: Vec::new(),
        neighbours_missed: Vec::new(),
        cross_isa: cross,
        gates: Vec::new(),
        decided: String::new(),
        rank,
        matches: matches.len(),
        evidence: rank.map(|index| evidence(&matches, index).label()),
        answer_withheld: (rank == Some(0))
            .then(|| answer_gate(&matches).err())
            .flatten(),
        answer_floor: (rank == Some(0)).then(|| answer_floor(&matches[0])),
        rival: (rank == Some(0)).then(|| matches[0].rival).flatten(),
        chance: None,
        carriers: None,
    };
    explanation.gates.push(GateResult {
        gate: "candidate",
        passed: candidate,
        value: None,
        needed: None,
    });
    explain_gates(
        source,
        adapted_signature,
        &identifying,
        context,
        hints,
        address,
        &mut explanation,
    );
    explanation.decided = match explanation.gates.iter().find(|gate| !gate.passed) {
        Some(failed) => failed.gate.to_string(),
        None if rank.is_none() => "ranked-out".to_string(),
        None => "accepted".to_string(),
    };
    explanation
}

/// The gates after the candidate check, for [`explain`].
fn explain_gates<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    identifying: &[String],
    context: &ScanContext,
    hints: bool,
    address: u64,
    explanation: &mut Explanation,
) {
    let gate =
        |name: &'static str, passed: bool, value: Option<f64>, needed: Option<f64>| GateResult {
            gate: name,
            passed,
            value,
            needed,
        };
    let Some(found) = context.features.get_or_recover(source, address, hints) else {
        explanation.gates.push(gate("recovery", false, None, None));
        return;
    };
    explanation.start = Some(found.start);
    explanation.end = Some(found.end);
    let result = compare_keys(signature, &found.keys);
    let similar = similarity(signature, &found.weighted);
    explanation.score = result.score;
    explanation.similarity = similar;
    explanation.matched_required = result.matched_required;
    for feature in &signature.features {
        let key = feature.key();
        let inherited = format!("{INHERITED_PREFIX}{key}");
        if found.keys.contains(&key) {
            explanation.matched.push(key);
        } else if found.keys.contains(&inherited) {
            explanation.inherited.push(inherited);
        } else {
            explanation.missed.push((key, feature.required));
        }
    }
    let signature_neighbours: HashSet<&str> =
        signature.neighbours.iter().map(String::as_str).collect();
    if !signature_neighbours.is_empty() {
        let held: HashSet<String> = context
            .neighbour_keys(source, found.start, hints)
            .into_iter()
            .collect();
        for key in &signature.neighbours {
            if held.contains(key) {
                explanation.neighbours_shared.push(key.clone());
            } else {
                explanation.neighbours_missed.push(key.clone());
            }
        }
    }
    let required_count = explanation.required;
    let [score, distinct, shape] = acceptance_gates(signature, &result, explanation.cross_isa);
    explanation.gates.push(gate(
        score.0,
        score.1,
        Some(result.score),
        Some(signature.match_threshold),
    ));
    if !score.1 {
        return;
    }
    explanation.gates.push(gate(
        distinct.0,
        distinct.1,
        Some(result.matched_required as f64),
        Some(signature.min_distinct.min(required_count) as f64),
    ));
    if !distinct.1 {
        return;
    }
    // The agreement only counts for a signature that needs corroboration;
    // for the others the gate passes whatever it is.
    let corroborate = needs_shape_corroboration(signature);
    explanation.gates.push(gate(
        shape.0,
        shape.1,
        corroborate.then(|| shape_agreement(signature, &result.matched)),
        corroborate.then_some(MIN_SHAPE_AGREEMENT),
    ));
    let mut waived = false;
    if !shape.1 {
        waived = frequency_gated(source, context, hints)
            && !signature_neighbours.is_empty()
            && shares_neighbour_key(
                source,
                context,
                &signature_neighbours,
                found.start,
                similar,
                hints,
            );
        // The waiver stands in for the failed shape gate.
        explanation.gates.pop();
        explanation.gates.push(gate(
            "shape-waiver",
            waived,
            Some(similar),
            Some(MIN_WAIVED_SHAPE_SIMILARITY),
        ));
        if !waived {
            return;
        }
    }
    let candidate = Match {
        address: found.start,
        end: found.end,
        score: result.score,
        similarity: similar,
        matched: result.matched,
        rival: None,
        waived,
    };
    let needed = |name: &str| match name {
        "similarity" => Some(MIN_SIMILARITY),
        "anchoring" => Some(MIN_UNANCHORED_SIMILARITY),
        "constants" => Some(MIN_CONSTANT_ANCHORED_SIMILARITY),
        "evidence" => Some(MIN_SHAPE_ONLY_SIMILARITY),
        _ => None,
    };
    if hints {
        if !hinted_floors_apply(source) {
            explanation
                .gates
                .push(gate("small-image-exempt", true, None, None));
            return;
        }
        match hinted_floor(identifying, &candidate) {
            Ok(()) => explanation
                .gates
                .push(gate("hinted-floors", true, Some(similar), None)),
            Err(name) => explanation
                .gates
                .push(gate(name, false, Some(similar), needed(name))),
        }
        return;
    }
    let Some(frequencies) = context.frequencies[0]
        .get_or_init(|| Frequencies::build(source, &context.features, hints))
        .as_ref()
    else {
        explanation
            .gates
            .push(gate("small-image-exempt", true, None, None));
        return;
    };
    explanation.chance = Some(frequencies.chance_matches(&candidate.matched));
    explanation.carriers = Some(frequencies.carriers(&candidate.matched));
    match hint_free_floors(
        source,
        signature,
        &signature_neighbours,
        identifying,
        context,
        frequencies,
        candidate,
    ) {
        Ok(_) => explanation
            .gates
            .push(gate("hint-free-floors", true, Some(similar), None)),
        Err("chance") => explanation.gates.push(gate(
            "chance",
            false,
            explanation.chance,
            Some(MAX_CHANCE_MATCHES),
        )),
        Err("neighbours") => explanation.gates.push(gate(
            "neighbours",
            false,
            Some(signature.neighbours.len() as f64),
            Some(MIN_NEIGHBOURS_TO_REJECT as f64),
        )),
        Err(name) => explanation
            .gates
            .push(gate(name, false, Some(similar), needed(name))),
    }
}

/// A recovered candidate function reduced to what comparison needs.
#[derive(Debug)]
pub struct Candidate {
    pub start: u64,
    pub end: u64,
    pub features: Vec<Feature>,
    pub keys: HashSet<String>,
    pub weighted: Vec<(String, f64)>,
    /// Direct call and tail-call targets inside the image, sorted: the
    /// function's callees, whose own evidence can corroborate it.
    pub calls: Vec<u64>,
}

impl Candidate {
    fn recover<S: ByteSource + ?Sized>(
        source: &S,
        start: u64,
        limits: Option<RecoveryLimits>,
        hints: bool,
        inline: Option<&InlineCache>,
    ) -> Option<Candidate> {
        let recovered = recover(source, start, limits, hints).ok()?;
        let features = extract_with(source, &recovered, inline);
        let (body_start, body_end) = (recovered.start(), recovered.end());
        let mut calls: Vec<u64> = recovered
            .blocks
            .iter()
            .flat_map(|block| block.insns.iter())
            .filter(|insn| matches!(insn.kind, Kind::Call | Kind::NoreturnCall | Kind::Jump))
            .filter_map(|insn| {
                let target = call_destination(source, insn.target?, insn.callee.as_deref())?;
                let outside = target < body_start || target >= body_end;
                (outside && source.is_executable(target)).then_some(target)
            })
            .collect();
        calls.sort_unstable();
        calls.dedup();
        Some(Candidate {
            start: body_start,
            end: body_end,
            weighted: weigh(&features),
            keys: features.iter().map(Feature::key).collect(),
            features,
            calls,
        })
    }
}

/// `(start, hints)` to the recovered candidate, or `None` when recovery failed.
type CandidateMap = HashMap<(u64, bool), Option<Arc<Candidate>>>;

/// Recovered candidates per `(start, hints)`, shared across signatures.
///
/// Recovery and extraction are deterministic functions of the image bytes, so
/// a candidate start yields the same features for every signature. Scanning
/// many signatures over one image recovers the same symbol starts and sweep
/// boundaries again and again; caching them turns that into one recovery per
/// start. Bounded by the number of distinct candidate starts, which the
/// per-signature cap and the image size already bound.
#[derive(Debug, Default)]
pub struct FeatureCache {
    entries: RwLock<CandidateMap>,
    inline: InlineCache,
}

impl FeatureCache {
    pub(crate) fn get_or_recover<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        start: u64,
        hints: bool,
    ) -> Option<Arc<Candidate>> {
        if let Some(entry) = self
            .entries
            .read()
            .expect("feature cache")
            .get(&(start, hints))
        {
            return entry.clone();
        }
        let candidate =
            Candidate::recover(source, start, None, hints, Some(&self.inline)).map(Arc::new);
        self.entries
            .write()
            .expect("feature cache")
            .insert((start, hints), candidate.clone());
        candidate
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_candidates_with<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    hits: &[(u64, String)],
    limits: Option<RecoveryLimits>,
    max_candidates: usize,
    hints: bool,
    index: Option<&ReferenceIndex>,
    code: Option<&CodeIndex>,
    cache: Option<&FeatureCache>,
    budget: Option<&mut RecoveryBudget>,
    shape_waiver: Option<&dyn Fn(u64, f64) -> bool>,
) -> Vec<Match> {
    let mut matches: Vec<Match> = Vec::new();
    let mut budget = budget;
    let keys = ScanKeys::new(signature, cross_isa(signature, source.arch()));
    for start in candidate_starts(source, signature, hits, max_candidates, hints, index, code) {
        if let Some(remaining) = budget.as_mut() {
            if remaining.remaining == 0 {
                break;
            }
            remaining.remaining -= 1;
        }
        let candidate = match cache {
            Some(cache) if limits.is_none() => cache.get_or_recover(source, start, hints),
            _ => Candidate::recover(source, start, limits, hints, cache.map(|c| &c.inline))
                .map(Arc::new),
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let waived = std::cell::Cell::new(false);
        let waive = || {
            let waive = shape_waiver.is_some_and(|waiver| {
                waiver(candidate.start, similarity(signature, &candidate.weighted))
            });
            waived.set(waive);
            waive
        };
        if let Some(result) = keys.accept(signature, &candidate.keys, &waive) {
            matches.push(Match {
                address: candidate.start,
                end: candidate.end,
                score: result.score,
                similarity: similarity(signature, &candidate.weighted),
                matched: result.matched,
                rival: None,
                waived: waived.get(),
            });
        }
    }
    // Rank by similarity first: `score` saturates at 1.0 for every candidate
    // holding the required features, so in a real library dozens of related
    // functions tie on it. Similarity also charges the candidate's own extra
    // features, which separates the function from its look-alikes.
    matches.sort_by(|left, right| {
        right
            .similarity
            .total_cmp(&left.similarity)
            .then(right.score.total_cmp(&left.score))
            .then(left.address.cmp(&right.address))
    });
    dedupe(matches).into_iter().take(MAX_MATCHES).collect()
}

/// Data-address to referencing-instruction map over executable regions.
///
/// String anchors can only rank candidates: their bytes live in data pages, so
/// nothing in Tier 0 points at the code that uses them. The index closes that
/// gap by sweeping each executable region once (bounded, with resync) and
/// recording which instructions reference which data addresses.
///
/// The instruction budget is **global for the index's lifetime**, not per
/// region: a large address space is indexed incrementally across passes, and
/// `truncated` reports when the budget ran out. The map is per-region so a
/// runtime scanner re-indexes only regions that changed.
#[derive(Debug, Clone)]
pub struct ReferenceIndex {
    max_instructions: usize,
    by_region: HashMap<u64, HashMap<u64, Vec<u64>>>,
    region_counts: HashMap<u64, usize>,
    merged: HashMap<u64, Vec<u64>>,
    pub instructions: usize,
    pub truncated: bool,
}

/// One region of a [`ReferenceIndex`] being swept.
struct ReferenceBuild {
    budget: usize,
    count: usize,
    resyncs: usize,
    truncated: bool,
    refs: HashMap<u64, Vec<u64>>,
}

impl ReferenceBuild {
    /// Whether the region's sweep may take another step.
    fn wants(&mut self) -> bool {
        if self.count >= self.budget || self.resyncs >= MAX_INDEX_RESYNCS {
            self.truncated = true;
            return false;
        }
        true
    }

    fn feed(&mut self, step: &Step) {
        let Some(insns) = step else {
            self.resyncs += 1;
            return;
        };
        for insn in insns {
            self.count += 1;
            for reference in &insn.refs {
                self.refs.entry(reference.addr).or_default().push(insn.addr);
            }
        }
    }
}

impl Default for ReferenceIndex {
    fn default() -> Self {
        ReferenceIndex::new(MAX_INDEX_INSTRUCTIONS)
    }
}

impl ReferenceIndex {
    pub fn new(max_instructions: usize) -> ReferenceIndex {
        ReferenceIndex {
            max_instructions,
            by_region: HashMap::new(),
            region_counts: HashMap::new(),
            merged: HashMap::new(),
            instructions: 0,
            truncated: false,
        }
    }

    /// The instruction budget this index was built with.
    pub fn max_instructions(&self) -> usize {
        self.max_instructions
    }

    /// Instruction addresses that reference `addr`, sorted.
    pub fn referencers(&self, addr: u64) -> &[u64] {
        self.merged.get(&addr).map(Vec::as_slice).unwrap_or(&[])
    }

    /// (Re)index one executable region; returns the instructions indexed.
    pub fn index_region<S: ByteSource + ?Sized>(&mut self, source: &S, region: &Region) -> usize {
        let Some(mut build) = self.begin_region(region) else {
            self.rebuild_merged();
            return 0;
        };
        let mut sweep = RegionSweep::new(source, region);
        while !sweep.at_end() && build.wants() {
            let Some(step) = sweep.next_step() else {
                break;
            };
            build.feed(&step);
        }
        let count = build.count;
        self.finish_region(region, build);
        self.rebuild_merged();
        count
    }

    /// Forget `region`'s old entry and start indexing it, or `None` when it
    /// is not executable or the budget is spent.
    fn begin_region(&mut self, region: &Region) -> Option<ReferenceBuild> {
        self.by_region.remove(&region.start);
        self.instructions -= self.region_counts.remove(&region.start).unwrap_or(0);
        if !region.executable {
            return None;
        }
        let budget = self.max_instructions.saturating_sub(self.instructions);
        if budget == 0 {
            self.truncated = true;
            return None;
        }
        Some(ReferenceBuild {
            budget,
            count: 0,
            resyncs: 0,
            truncated: false,
            refs: HashMap::new(),
        })
    }

    fn finish_region(&mut self, region: &Region, build: ReferenceBuild) {
        self.truncated |= build.truncated;
        self.instructions += build.count;
        self.region_counts.insert(region.start, build.count);
        let region_refs = build
            .refs
            .into_iter()
            .map(|(addr, mut addrs)| {
                addrs.sort_unstable();
                addrs.dedup();
                (addr, addrs)
            })
            .collect();
        self.by_region.insert(region.start, region_refs);
    }

    /// Forget one region (the scanner calls this when it is freed).
    pub fn drop_region(&mut self, region_start: u64) {
        if self.by_region.remove(&region_start).is_some() {
            self.instructions -= self.region_counts.remove(&region_start).unwrap_or(0);
            self.rebuild_merged();
        }
    }

    fn rebuild_merged(&mut self) {
        let mut merged: HashMap<u64, Vec<u64>> = HashMap::new();
        for region_refs in self.by_region.values() {
            for (addr, addrs) in region_refs {
                merged.entry(*addr).or_default().extend_from_slice(addrs);
            }
        }
        for addrs in merged.values_mut() {
            addrs.sort_unstable();
            addrs.dedup();
        }
        self.merged = merged;
    }
}

/// Keep the best match per overlapping span.
///
/// A sweep can recover the same body from an interior address, which scores
/// almost as well. Reporting one function once keeps the hit list meaningful.
fn dedupe(matches: Vec<Match>) -> Vec<Match> {
    let mut kept: Vec<Match> = Vec::new();
    for candidate in matches {
        let overlaps = kept
            .iter()
            .any(|other| candidate.address < other.end && other.address < candidate.end);
        if !overlaps {
            kept.push(candidate);
        }
    }
    kept
}

/// Require `signature` to match the function at `start`.
///
/// Returns [`SelfTestError`] when the matcher had a way to reach `start` but did
/// not accept a match there. When neither anchors, known function starts, nor
/// (for string anchors) the data-reference index can reach it, the matcher
/// cannot rediscover the function at all, so only the weaker structural check
/// (does the signature still describe these bytes exactly?) is applied; that is
/// a matcher limitation, not a signature defect.
pub fn self_test<S: ByteSource + ?Sized>(
    signature: &Signature,
    source: &S,
    start: u64,
    limits: Option<RecoveryLimits>,
    max_candidates: usize,
) -> Result<Match, SelfTestError> {
    let mut matches = scan(source, signature, limits, max_candidates, true, None);
    if let Some(found) = matches.iter().find(|item| item.address == start) {
        return Ok(found.clone());
    }

    let hits = anchor_hits(source, signature);
    let mut candidates =
        candidate_starts(source, signature, &hits, max_candidates, true, None, None);
    if !candidates.contains(&start) && hits.iter().any(|(_, key)| key.starts_with("str:")) {
        // String anchors only rank through the reference index; build it once
        // before declaring the function unreachable.
        let mut index = ReferenceIndex::default();
        for region in source.regions() {
            if region.executable {
                index.index_region(source, region);
            }
        }
        candidates = candidate_starts(
            source,
            signature,
            &hits,
            max_candidates,
            true,
            Some(&index),
            None,
        );
        if candidates.contains(&start) {
            matches = scan_candidates(
                source,
                signature,
                &hits,
                limits,
                max_candidates,
                true,
                Some(&index),
                None,
            );
            if let Some(found) = matches.iter().find(|item| item.address == start) {
                return Ok(found.clone());
            }
            let detail = if matches.is_empty() {
                "no candidate matched anywhere in the image".to_string()
            } else {
                format!(
                    "best accepted match was at another function (score {:.3})",
                    matches[0].score
                )
            };
            return Err(SelfTestError(format!(
                "signature {:?} failed self-test at 0x{start:x}: {detail}",
                signature.name
            )));
        }
    }

    if candidates.contains(&start) {
        let detail = if matches.is_empty() {
            "no candidate matched anywhere in the image".to_string()
        } else {
            format!(
                "best accepted match was at another function (score {:.3})",
                matches[0].score
            )
        };
        return Err(SelfTestError(format!(
            "signature {:?} failed self-test at 0x{start:x}: {detail}",
            signature.name
        )));
    }

    structural_self_test(signature, source, start, limits)
}

/// [`self_test`] through an image's shared [`ScanContext`].
///
/// The reference index is already built, so string anchors seed candidates up
/// front instead of costing a whole-image index per generated signature (the
/// dominant generation cost on real libraries), and recovered candidates come
/// from the shared cache.
pub fn self_test_in<S: ByteSource + ?Sized>(
    signature: &Signature,
    source: &S,
    start: u64,
    limits: Option<RecoveryLimits>,
    max_candidates: usize,
    context: &ScanContext,
) -> Result<Match, SelfTestError> {
    let hits = anchor_hits(source, signature);
    let references = Some(&context.references);
    let code = Some(&context.code);
    let matches = scan_candidates_with(
        source,
        signature,
        &hits,
        limits,
        max_candidates,
        true,
        references,
        code,
        Some(&context.features),
        None,
        None,
    );
    if let Some(found) = matches.iter().find(|item| item.address == start) {
        return Ok(found.clone());
    }
    let candidates = candidate_starts(
        source,
        signature,
        &hits,
        max_candidates,
        true,
        references,
        code,
    );
    if candidates.contains(&start) {
        let detail = if matches.is_empty() {
            "no candidate matched anywhere in the image".to_string()
        } else {
            format!(
                "best accepted match was at another function (score {:.3})",
                matches[0].score
            )
        };
        return Err(SelfTestError(format!(
            "signature {:?} failed self-test at 0x{start:x}: {detail}",
            signature.name
        )));
    }
    structural_self_test(signature, source, start, limits)
}

/// The matcher cannot reach `start`: require the signature to describe the
/// bytes there exactly.
fn structural_self_test<S: ByteSource + ?Sized>(
    signature: &Signature,
    source: &S,
    start: u64,
    limits: Option<RecoveryLimits>,
) -> Result<Match, SelfTestError> {
    let recovered = recover(source, start, limits, true)
        .map_err(|error| SelfTestError(format!("cannot recover 0x{start:x}: {error}")))?;
    let result = compare(signature, &extract(source, &recovered));
    let required = signature
        .features
        .iter()
        .filter(|feature| feature.required)
        .count();
    if result.score < 1.0 || result.matched_required != required {
        return Err(SelfTestError(format!(
            "signature {:?} does not describe the function at 0x{start:x}",
            signature.name
        )));
    }
    let weighted = weigh(&extract(source, &recovered));
    Ok(Match {
        address: recovered.start(),
        end: recovered.end(),
        score: result.score,
        similarity: similarity(signature, &weighted),
        matched: result.matched,
        rival: None,
        waived: false,
    })
}

/// Candidate features with the weights generation would give them.
fn weigh(features: &[Feature]) -> Vec<(String, f64)> {
    score_features(features, None)
        .into_iter()
        .map(|item| (item.key(), item.weight))
        .collect()
}

/// Weighted Jaccard between a signature and a candidate.
///
/// `sum(signature weight of shared keys) / (sum(signature weights) +
/// sum(candidate weights of keys the signature lacks))`. The true function
/// shares the signature's portable evidence and adds little of its own; a
/// larger function that merely contains the same strings or constants pays for
/// everything else it holds.
pub fn similarity(signature: &Signature, candidate: &[(String, f64)]) -> f64 {
    SimilarityKeys::new(signature).similarity(candidate)
}

/// A signature's key weights for [`similarity`], built once so a caller
/// comparing one signature with many candidates (joint resolution) does not
/// rebuild the map per candidate, and cannot drift from the scan's rule.
pub struct SimilarityKeys {
    wanted: HashMap<String, f64>,
    total: f64,
}

impl SimilarityKeys {
    pub fn new(signature: &Signature) -> SimilarityKeys {
        SimilarityKeys {
            wanted: signature
                .features
                .iter()
                .map(|feature| (feature.key(), feature.weight))
                .collect(),
            // Summed in document order: a `HashMap` iterates in a per-process
            // random order, and the last-bit difference flipped `round_to` at
            // a .5 boundary, so two runs ranked tied lookalikes differently.
            // Keys are unique (`Signature::validate`), so this is the same sum.
            total: signature
                .features
                .iter()
                .map(|feature| feature.weight)
                .sum(),
        }
    }

    pub fn similarity(&self, candidate: &[(String, f64)]) -> f64 {
        let mut shared = 0.0;
        let mut extra = 0.0;
        for (key, weight) in candidate {
            // An inherited key is the callee's, not extra weight of the
            // candidate's own; it shares at the inherited discount.
            if let Some(base) = key.strip_prefix(INHERITED_PREFIX) {
                if let Some(signature_weight) = self.wanted.get(base) {
                    shared += signature_weight * INHERITED_CREDIT;
                }
                continue;
            }
            match self.wanted.get(key) {
                Some(signature_weight) => shared += signature_weight,
                None => extra += weight,
            }
        }
        let denominator = self.total + extra;
        if denominator <= 0.0 {
            0.0
        } else {
            round_to(shared / denominator, SCORE_DECIMALS)
        }
    }

    /// [`Self::similarity`] when it is at least `floor`, else `None`: the
    /// same value, without finishing the sum or formatting the rounding for
    /// a candidate that cannot reach the floor. Joint resolution weighs a
    /// module's every signature against every function of the target and
    /// keeps a few pairs per signature.
    pub fn similarity_at_least(&self, candidate: &[(String, f64)], floor: f64) -> Option<f64> {
        if self.total <= 0.0 {
            let value = self.similarity(candidate);
            return (value >= floor).then_some(value);
        }
        // Rounding moves a value by at most half a unit of the last decimal,
        // so below this margin the rounded value is below `floor` too.
        let margin = floor - 1e-6;
        let mut shared = 0.0;
        let mut extra = 0.0;
        for (key, weight) in candidate {
            if let Some(base) = key.strip_prefix(INHERITED_PREFIX) {
                if let Some(signature_weight) = self.wanted.get(base) {
                    shared += signature_weight * INHERITED_CREDIT;
                }
                continue;
            }
            match self.wanted.get(key) {
                Some(signature_weight) => shared += signature_weight,
                None => {
                    extra += weight;
                    // Each signature key is shared at most once, so `shared`
                    // ends at most `total`, and extra weight only grows.
                    if self.total < margin * (self.total + extra) {
                        return None;
                    }
                }
            }
        }
        let value = shared / (self.total + extra);
        if value < margin {
            return None;
        }
        let value = round_to(value, SCORE_DECIMALS);
        (value >= floor).then_some(value)
    }
}

// -- Tier 0 ------------------------------------------------------------------

/// Tier 0 for one region: anchor needle occurrences, capped per needle.
pub fn region_anchor_hits(region: &Region, signature: &Signature) -> Vec<(u64, String)> {
    let mut hits: Vec<(u64, String)> = Vec::new();
    for needle in anchor_needles(signature) {
        if region.executable != needle.executable || region.data.len() < needle.data.len() {
            continue;
        }
        for address in find_all(&region.data, &needle.data, MAX_HITS_PER_ANCHOR) {
            hits.push((region.start + address as u64, needle.key.clone()));
        }
    }
    hits.sort();
    hits
}

fn anchor_hits<S: ByteSource + ?Sized>(source: &S, signature: &Signature) -> Vec<(u64, String)> {
    let mut hits: Vec<(u64, String)> = Vec::new();
    for region in source.regions() {
        hits.extend(region_anchor_hits(region, signature));
    }
    hits.sort();
    hits
}

/// Bounded occurrence search inside one region.
fn find_all(data: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    let mut found = Vec::new();
    if needle.is_empty() || needle.len() > data.len() {
        return found;
    }
    let mut cursor = 0usize;
    while found.len() < limit {
        let Some(offset) = find_at(data, needle, cursor) else {
            break;
        };
        found.push(offset);
        cursor = offset + 1;
    }
    found
}

/// First occurrence of `needle` in `data` at or after `start`.
///
/// Every signature searches the whole image for each anchor needle, so this
/// skips ahead to the next occurrence of the needle's first byte and only
/// compares the rest there; comparing the full needle at every offset made
/// Tier 0 most of a hint-free multi-signature scan.
fn find_at(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    let last = data.len().checked_sub(needle.len())?;
    let Some((first, rest)) = needle.split_first() else {
        return (start <= last).then_some(start);
    };
    let mut index = start;
    while index <= last {
        index += data[index..=last].iter().position(|byte| byte == first)?;
        if data[index + 1..index + needle.len()] == *rest {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn const_needles(value: &str) -> Vec<Vec<u8>> {
    let Some(number) = parse_hex(value) else {
        return Vec::new();
    };
    if number < MIN_SEARCHABLE_CONST || 64 - number.leading_zeros() > MAX_CONST_BITS {
        return Vec::new();
    }
    let low = (number & 0xFFFF_FFFF) as u32;
    let mut encodings: Vec<Vec<u8>> = vec![low.to_le_bytes().to_vec(), low.to_be_bytes().to_vec()];
    if number > 0xFFFF_FFFF {
        encodings.push(number.to_le_bytes().to_vec());
        encodings.push(number.to_be_bytes().to_vec());
    }
    encodings.sort();
    encodings
}

fn parse_hex(value: &str) -> Option<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16).ok()
}

fn string_needles(value: &str) -> Vec<Vec<u8>> {
    let Some(text) = unescape(value) else {
        return Vec::new();
    };
    let wide = value.starts_with("w:");
    let text = if wide { &text[2..] } else { &text };
    let mut encodings: Vec<Vec<u8>> = Vec::new();
    if wide {
        encodings.push(utf16le(text));
    } else {
        encodings.push(latin1(text));
        encodings.push(utf16le(text));
    }
    encodings.retain(|encoding| !encoding.is_empty());
    encodings.sort();
    encodings
}

/// Reverse [`crate::features`]'s escape rule; `None` for hashed long literals.
fn unescape(value: &str) -> Option<String> {
    if value.starts_with("long:") || value.starts_with("w:long:") {
        return None;
    }
    let mut chars = String::with_capacity(value.len());
    let mut iter = value.chars();
    while let Some(character) = iter.next() {
        if character == '\\' {
            if let Some(next) = iter.next() {
                chars.push(next);
            }
        } else {
            chars.push(character);
        }
    }
    Some(chars)
}

fn latin1(text: &str) -> Vec<u8> {
    text.chars()
        .filter(|character| (*character as u32) <= 0xFF)
        .map(|character| character as u32 as u8)
        .collect()
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

// -- Tier 1 ------------------------------------------------------------------

/// Candidate function starts, ranked for the fewest wasted recoveries.
///
/// With `use_hints` (the default), sources that can enumerate symbols give
/// exact starts; those are tried first. Otherwise -- and additionally -- the
/// matcher sweeps backwards from each anchor landmark over real instruction
/// boundaries; among swept starts the **earliest** ranks first, because the
/// prologue precedes the anchor while a mid-body start is a false prologue.
/// When an `index` is supplied, string-anchor hits become landmarks through
/// the instructions that reference them (the M6 data-reference index).
fn candidate_starts<S: ByteSource + ?Sized>(
    source: &S,
    signature: &Signature,
    hits: &[(u64, String)],
    max_candidates: usize,
    use_hints: bool,
    index: Option<&ReferenceIndex>,
    shared_code: Option<&CodeIndex>,
) -> Vec<u64> {
    let code_hits: Vec<u64> = unique_sorted(
        hits.iter()
            .filter(|(address, _)| source.is_executable(*address))
            .map(|(address, _)| *address)
            .collect(),
    );
    let data_hits: Vec<u64> = unique_sorted(
        hits.iter()
            .filter(|(address, _)| !source.is_executable(*address))
            .map(|(address, _)| *address)
            .collect(),
    );
    let mut landmarks = code_hits.clone();
    if let Some(index) = index {
        for data_addr in &data_hits {
            landmarks.extend_from_slice(index.referencers(*data_addr));
        }
    }
    landmarks.sort_unstable();

    // Hint-free discovery gets one bounded linear pass over the code. Constants
    // are matched by decoded value, so an immediate narrower than four bytes
    // still lands (byte needles only know 4/8-byte encodings), boundaries come
    // from real decoding instead of a restart that can desync and stop short of
    // the landmark, and direct call targets are exact entries. A value
    // materialized too often to identify a function is not used as a landmark.
    let built;
    let code: Option<&CodeIndex> = if use_hints {
        None
    } else if let Some(shared) = shared_code {
        Some(shared)
    } else {
        built = CodeIndex::build(source);
        Some(&built)
    };
    let const_landmarks: Vec<u64> = match code {
        Some(code) => signature
            .anchors
            .iter()
            .filter_map(|anchor| match split_anchor(anchor) {
                (Some(FeatureKind::Const), value) => parse_hex(value),
                _ => None,
            })
            .flat_map(|value| {
                let references = code.const_referencers(value);
                if references.len() > MAX_HITS_PER_ANCHOR {
                    Vec::new()
                } else {
                    references.to_vec()
                }
            })
            .collect(),
        None => Vec::new(),
    };
    landmarks.extend_from_slice(&const_landmarks);
    landmarks.sort_unstable();
    landmarks.dedup();

    let mut hint_starts: HashSet<u64> = HashSet::new();
    let mut swept_starts: HashSet<u64> = HashSet::new();
    if use_hints {
        hint_starts.extend(
            source
                .function_starts()
                .into_iter()
                .filter(|start| source.is_executable(*start)),
        );
    } else if let Some(code) = &code {
        // Without symbols, a direct call target is still an exact function
        // entry, while a backward sweep only guesses one from an interior
        // landmark. The reference has no such source in hint-free mode, so its
        // string-only signatures find nothing; this is a deliberate native
        // improvement (measured in `docs/history/PLAN-v0.5.md` section 12).
        hint_starts.extend(code.call_targets.iter().copied());
    }
    // Unwind entries are exact function starts that survive stripping. The
    // entry enclosing a landmark is the function that holds it, so it is
    // tried before anything a backward sweep can only guess.
    if !use_hints {
        hint_starts.extend(source.unwind_entries().iter().map(|(start, _)| *start));
    }
    let mut enclosing: HashSet<u64> = HashSet::new();
    // Only an entry with a known end proves it encloses the address. The
    // last synthesized start (no table, no next start) is open-ended, and
    // trusting it would replace every sweep in the image with one guess.
    let unwind_enclosing = |address: u64| -> Option<u64> {
        if use_hints {
            None
        } else {
            source
                .unwind_function(address)
                .filter(|(_, end)| *end != 0)
                .map(|(start, _)| start)
        }
    };
    // Known starts are only a shortcut when they cover the hit; otherwise the
    // matcher still has to find the enclosing function from the bytes.
    for address in &code_hits {
        let hint = if use_hints {
            source.hint_function(*address)
        } else {
            None
        };
        match hint {
            Some((start, _)) => {
                hint_starts.insert(start);
            }
            None => {
                if let Some(start) = unwind_enclosing(*address) {
                    enclosing.insert(start);
                    continue;
                }
                let starts = match &code {
                    Some(code) => code.swept_starts(source, *address),
                    None => swept_starts_from(source, *address),
                };
                swept_starts.extend(starts);
            }
        }
    }
    // A const landmark is the instruction that materialises the value; the
    // enclosing function starts at or before it, like any other anchor.
    for reference in const_landmarks {
        if let Some(start) = unwind_enclosing(reference) {
            enclosing.insert(start);
            continue;
        }
        let starts = match &code {
            Some(code) => code.swept_starts(source, reference),
            None => swept_starts_from(source, reference),
        };
        swept_starts.extend(starts);
    }
    if let Some(index) = index {
        for data_addr in &data_hits {
            for reference in index.referencers(*data_addr) {
                // Same shortcut as code hits: a symbol that covers the
                // referencing instruction is its function. Without it every
                // string reference cost a backward decode sweep, which made
                // hinted scans of real libraries ~5x slower than hint-free.
                if let Some((start, _)) = use_hints
                    .then(|| source.hint_function(*reference))
                    .flatten()
                {
                    hint_starts.insert(start);
                    continue;
                }
                if let Some(start) = unwind_enclosing(*reference) {
                    enclosing.insert(start);
                    continue;
                }
                let starts = match &code {
                    Some(code) => code.swept_starts(source, *reference),
                    None => swept_starts_from(source, *reference),
                };
                swept_starts.extend(starts);
            }
        }
    }
    if hint_starts.is_empty() && swept_starts.is_empty() && enclosing.is_empty() {
        return Vec::new();
    }
    let mut ordered: Vec<u64> = enclosing.iter().copied().collect();
    ordered.sort_unstable();
    ordered.extend(
        rank(hint_starts, swept_starts, &landmarks)
            .into_iter()
            .filter(|start| !enclosing.contains(start)),
    );
    // With an unwind table the candidate set is the image's real function
    // list, so every entry is worth comparing: recovered candidates are
    // cached per image and comparison is a set lookup per signature feature.
    // Without one, the cap keeps backward-sweep guesses bounded.
    let cap = if use_hints {
        max_candidates
    } else {
        max_candidates.max(source.unwind_entries().len().min(MAX_UNWIND_CANDIDATES))
    };
    ordered.truncate(cap);
    ordered
}

/// Code facts gathered in one resynchronizing linear pass over executable areas.
///
/// Byte needles find a constant only by encoding, so an immediate written in
/// fewer than four bytes is invisible to them. A backward sweep restarted a
/// fixed window before a landmark can also start mid-instruction, desync, and
/// stop before reaching the landmark. This pass decodes each executable region
/// once, resynchronizing past undecodable bytes, and records real instruction
/// boundaries, direct call targets, and the instructions that materialize each
/// constant value. It is bounded by [`MAX_DISCOVERY_INSTRUCTIONS`] and
/// [`MAX_INDEX_RESYNCS`], so a hostile image cannot make it run unbounded
/// (AGENTS.md rule 8).
#[derive(Debug, Default)]
pub struct CodeIndex {
    boundaries: HashMap<u64, Vec<u64>>,
    call_targets: HashSet<u64>,
    /// Direct call target to the call sites that reach it.
    callers: HashMap<u64, Vec<u64>>,
    const_refs: HashMap<u64, Vec<u64>>,
    /// Instructions decoded by the pass.
    decoded: usize,
    /// The pass stopped at a budget with code left to decode.
    truncated: bool,
}

/// A [`CodeIndex`] being swept. Its budgets are global across regions:
/// once one runs out, the pass ends and the region it stopped in keeps no
/// boundaries, as the swept fallback in [`CodeIndex::swept_starts`] expects.
#[derive(Default)]
struct CodeIndexBuild {
    index: CodeIndex,
    boundaries: Vec<u64>,
    decoded: usize,
    resyncs: usize,
    done: bool,
}

impl CodeIndexBuild {
    fn wants(&mut self) -> bool {
        if self.decoded >= MAX_DISCOVERY_INSTRUCTIONS || self.resyncs >= MAX_INDEX_RESYNCS {
            self.done = true;
        }
        !self.done
    }

    fn feed<S: ByteSource + ?Sized>(&mut self, source: &S, step: &Step) {
        let Some(insns) = step else {
            self.resyncs += 1;
            return;
        };
        for insn in insns {
            self.decoded += 1;
            if !insn.padding {
                self.boundaries.push(insn.addr);
            }
            if matches!(insn.kind, Kind::Call | Kind::NoreturnCall) {
                if let Some(target) = insn.target {
                    if source.is_executable(target) {
                        self.index.call_targets.insert(target);
                    }
                    if let Some(callee) = call_destination(source, target, insn.callee.as_deref()) {
                        self.index
                            .callers
                            .entry(callee)
                            .or_default()
                            .push(insn.addr);
                    }
                }
            }
            for value in insn.consts.iter().flat_map(|value| const_words(*value)) {
                self.index
                    .const_refs
                    .entry(value)
                    .or_default()
                    .push(insn.addr);
            }
        }
    }

    fn finish_region(&mut self, region: &Region) {
        let mut boundaries = std::mem::take(&mut self.boundaries);
        if self.done {
            return;
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        self.index.boundaries.insert(region.start, boundaries);
    }

    fn finish(self) -> CodeIndex {
        let mut index = self.index;
        index.decoded = self.decoded;
        index.truncated = self.done;
        for references in index.const_refs.values_mut() {
            references.sort_unstable();
            references.dedup();
        }
        index
    }
}

impl CodeIndex {
    pub fn build<S: ByteSource + ?Sized>(source: &S) -> CodeIndex {
        let mut build = CodeIndexBuild::default();
        for region in source.regions().iter().filter(|region| region.executable) {
            if build.done {
                break;
            }
            let mut sweep = RegionSweep::new(source, region);
            while !sweep.at_end() && build.wants() {
                let Some(step) = sweep.next_step() else {
                    break;
                };
                build.feed(source, &step);
            }
            build.finish_region(region);
        }
        build.finish()
    }

    /// Instructions the discovery pass decoded.
    pub fn decoded(&self) -> usize {
        self.decoded
    }

    /// Whether the pass stopped at [`MAX_DISCOVERY_INSTRUCTIONS`] or
    /// [`MAX_INDEX_RESYNCS`] before the end of the executable regions.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Instructions that materialize `value`, sorted and deduplicated.
    fn const_referencers(&self, value: u64) -> &[u64] {
        self.const_refs
            .get(&value)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Instruction boundaries in the sweep window ending at `address`.
    ///
    /// Falls back to a local decode when the pass stopped before indexing this
    /// region, so truncation degrades to the previous behaviour instead of
    /// losing candidates outright.
    fn swept_starts<S: ByteSource + ?Sized>(&self, source: &S, address: u64) -> Vec<u64> {
        let Some(region) = source.region_for(address) else {
            return Vec::new();
        };
        let Some(boundaries) = self.boundaries.get(&region.start) else {
            return swept_starts_from(source, address);
        };
        let low = address.saturating_sub(BACKWARD_SWEEP_BYTES);
        let first = boundaries.partition_point(|boundary| *boundary < low);
        boundaries[first..]
            .iter()
            .copied()
            .take_while(|boundary| *boundary <= address)
            .collect()
    }
}

/// Instruction starts in a bounded window ending at `address`.
fn swept_starts_from<S: ByteSource + ?Sized>(source: &S, address: u64) -> Vec<u64> {
    let Some(region) = source.region_for(address) else {
        return Vec::new();
    };
    let normalizer = Normalizer::new(source);
    let mut cursor = region
        .start
        .max(address.saturating_sub(BACKWARD_SWEEP_BYTES));
    let mut starts = Vec::new();
    while cursor <= address {
        let Some(insn) = normalizer.normalize_one(cursor) else {
            break;
        };
        if insn.size == 0 {
            break;
        }
        // Alignment filler before a function is not the function: starting
        // there makes recovery fall through into the real entry and accept a
        // match whose span begins at the padding, so the entry is never
        // reported. Skip the filler boundary and offer the first real one.
        if !insn.padding {
            starts.push(cursor);
        }
        cursor += insn.size as u64;
    }
    starts
}

/// Order candidate starts for the fewest wasted recoveries.
///
/// Exact starts (symbols when hinted, direct call targets otherwise) come first,
/// closest to a landmark; swept starts follow, earliest address first, since the
/// prologue precedes the anchor that found them. Distant candidates of both
/// kinds rank last, by address.
fn rank(hint_starts: HashSet<u64>, swept_starts: HashSet<u64>, landmarks: &[u64]) -> Vec<u64> {
    // (near, kind, sort_key, start)
    let mut ranked: Vec<(u8, u8, u64, u64)> = Vec::new();
    for start in hint_starts {
        let distance = distance_to_landmark(start, landmarks);
        let near = distance.is_some_and(|distance| distance <= 0x1_0000);
        ranked.push((if near { 0 } else { 1 }, 0, distance.unwrap_or(0), start));
    }
    for start in swept_starts {
        let distance = distance_to_landmark(start, landmarks);
        let near = distance.is_some_and(|distance| distance <= 0x1_0000);
        // Ascending address: the earliest boundary is the best prologue guess.
        ranked.push((if near { 0 } else { 1 }, 1, start, start));
    }
    ranked.sort_unstable();
    ranked.into_iter().map(|(_, _, _, start)| start).collect()
}

fn distance_to_landmark(start: u64, landmarks: &[u64]) -> Option<u64> {
    if landmarks.is_empty() {
        return None;
    }
    let index = landmarks.partition_point(|landmark| *landmark < start);
    let mut best: Option<u64> = None;
    for probe in [index.checked_sub(1), Some(index)].into_iter().flatten() {
        if let Some(landmark) = landmarks.get(probe) {
            let distance = landmark.abs_diff(start);
            best = Some(best.map_or(distance, |current| current.min(distance)));
        }
    }
    best
}

fn unique_sorted(mut values: Vec<u64>) -> Vec<u64> {
    values.sort_unstable();
    values.dedup();
    values
}

fn round_to(value: f64, decimals: usize) -> f64 {
    // Rust's fixed-precision formatter rounds the decimal representation, which
    // is the same operation Python's `round(float, n)` performs for these
    // non-tie scores.
    format!("{value:.decimals$}")
        .parse::<f64>()
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_needles_cover_both_orders_and_widths() {
        let needles = const_needles("0x1122334455667788");
        assert_eq!(needles.len(), 4);
        assert!(needles.contains(&0x5566_7788u32.to_le_bytes().to_vec()));
        assert!(needles.contains(&0x5566_7788u32.to_be_bytes().to_vec()));
        assert!(needles.contains(&0x1122_3344_5566_7788u64.to_le_bytes().to_vec()));
        assert!(needles.contains(&0x1122_3344_5566_7788u64.to_be_bytes().to_vec()));
    }

    #[test]
    fn small_constants_are_not_searchable() {
        assert!(const_needles("0xff").is_empty());
    }

    #[test]
    fn find_all_agrees_with_a_naive_search() {
        // Few distinct bytes, so needles overlap and recur everywhere.
        let mut state = 0x2545_f491_u32;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state % 3) as u8
            })
            .collect();
        let naive = |needle: &[u8], limit: usize| -> Vec<usize> {
            (0..=data.len().saturating_sub(needle.len()))
                .filter(|index| data[*index..].starts_with(needle))
                .take(limit)
                .collect()
        };
        for length in 1..=6 {
            for offset in [0usize, 17, 1000, data.len() - length] {
                let needle = &data[offset..offset + length];
                for limit in [1, MAX_HITS_PER_ANCHOR, usize::MAX] {
                    assert_eq!(find_all(&data, needle, limit), naive(needle, limit));
                }
            }
        }
        assert_eq!(find_at(&data, &data[4090..], 4091), None);
        assert_eq!(find_at(b"ab", b"abc", 0), None);
    }

    #[test]
    fn string_needles_are_narrow_and_wide() {
        let needles = string_needles("abcd");
        assert!(needles.contains(&b"abcd".to_vec()));
        assert!(needles.contains(&b"a\0b\0c\0d\0".to_vec()));
    }

    #[test]
    fn unescape_reverses_quotes() {
        assert_eq!(unescape("a\\\"b\\\\c").as_deref(), Some("a\"b\\c"));
        assert_eq!(unescape("long:abc"), None);
    }

    /// A low-information signature from `arch`: four small required
    /// constants, three ISA-stable shape dimensions and three ISA-specific
    /// ones.
    fn small_constant_signature(arch: &str) -> Signature {
        let feature = |kind, value: &str, weight, required| crate::sigfile::SignatureFeature {
            kind,
            value: value.to_string(),
            weight,
            required,
        };
        let mut features = vec![
            feature(FeatureKind::Cfg, "blocks:3", 0.25, false),
            feature(FeatureKind::Cfg, "edges:3", 0.25, false),
            feature(FeatureKind::Cfg, "loops:0", 0.25, false),
            feature(FeatureKind::Ops, "load:4", 0.15, false),
            feature(FeatureKind::Ops, "move:5", 0.15, false),
            feature(FeatureKind::Ops, "stack:5", 0.15, false),
        ];
        for value in ["0x1", "0x2", "0x4", "0x8"] {
            features.push(feature(FeatureKind::Const, value, 0.42, true));
        }
        features.sort_by(|a, b| (a.kind, &a.value).cmp(&(b.kind, &b.value)));
        Signature::new(
            "small",
            features,
            Vec::new(),
            0.75,
            3,
            "low",
            vec![crate::sigfile::SampleProvenance {
                arch: arch.to_string(),
                module: "m".to_string(),
                rva: 0x1000,
                opt: None,
                tool: None,
            }],
        )
        .unwrap()
    }

    #[test]
    fn cross_isa_candidates_corroborate_on_stable_dimensions_with_enough_evidence() {
        use crate::arch::Arch;
        let signature = small_constant_signature("x64");
        assert!(cross_isa(&signature, Arch::Arm64));
        assert!(!cross_isa(&signature, Arch::X64));
        assert!(!cross_isa(&small_constant_signature("thumb"), Arch::Arm32));
        // An arm64 candidate: the same CFG, but other load/move/stack buckets.
        let shape = ["cfg:blocks:3", "cfg:edges:3", "cfg:loops:0"];
        let candidate = |constants: &[&str]| -> HashSet<String> {
            shape
                .iter()
                .chain(constants)
                .chain(&["ops:load:3", "ops:move:3", "ops:stack:3"])
                .map(|key| key.to_string())
                .collect()
        };
        let four = candidate(&["const:0x1", "const:0x2", "const:0x4", "const:0x8"]);
        let three = candidate(&["const:0x1", "const:0x2", "const:0x4"]);
        for (present, cross, expected) in [
            // Same ISA: 3 of 6 dimensions agree, below 0.8.
            (&four, false, false),
            // Across ISAs, the stable dimensions all agree, with 4 required.
            (&four, true, true),
            // Three required features are not enough to drop the rest.
            (&three, true, false),
        ] {
            let result = compare_keys(&signature, present);
            assert_eq!(accepts_on(&signature, &result, cross), expected);
            let keys = ScanKeys::new(&signature, cross);
            assert_eq!(
                keys.accept(&signature, present, &|| false).is_some(),
                expected
            );
        }
    }

    fn found(address: u64, similarity: f64, matched: &[&str]) -> Match {
        Match {
            address,
            end: address + 4,
            score: 1.0,
            similarity,
            matched: matched.iter().map(|key| key.to_string()).collect(),
            rival: None,
            waived: false,
        }
    }

    #[test]
    fn an_answer_is_first_untied_and_similar_enough_for_its_evidence() {
        // A string names the function at any accepted similarity.
        assert!(identified_answer(&[found(1, 0.2, &["str:x"])]));
        // A callee needs the high floor; a direct neighbour key the low one.
        assert!(!identified_answer(&[found(1, 0.5, &["callee:f"])]));
        assert!(identified_answer(&[found(1, 0.7, &["callee:f"])]));
        assert!(identified_answer(&[found(1, 0.45, &["near:in:str:x"])]));
        assert!(!identified_answer(&[found(1, 0.4, &["near:in:str:x"])]));
        assert!(!identified_answer(&[found(1, 0.45, &["near:in2:str:x"])]));
        // Shape alone is never an answer, and a tie is no answer.
        assert!(!identified_answer(&[found(1, 1.0, &["cfg:blocks:1"])]));
        assert!(!identified_answer(&[]));
        let tied = [found(1, 0.9, &["str:x"]), found(2, 0.9, &["str:x"])];
        assert!(!identified_answer(&tied));
        assert_eq!(evidence(&tied, 0), Evidence::Candidate);
        let ranked = [found(1, 0.9, &["str:x"]), found(2, 0.8, &["cfg:blocks:1"])];
        assert_eq!(evidence(&ranked, 0), Evidence::Identified);
        assert_eq!(evidence(&ranked, 1), Evidence::ShapeOnly);
    }

    #[test]
    fn a_waived_shape_or_a_close_rival_is_no_answer() {
        let waived = Match {
            waived: true,
            ..found(1, 0.9, &["str:x"])
        };
        assert!(!identified_answer(&[waived]));
        assert_eq!(
            evidence(&[found(1, 0.9, &["str:x"])], 0),
            Evidence::Identified
        );
        let twin = Match {
            rival: Some(0.9 - RIVAL_MARGIN),
            ..found(1, 0.9, &["str:x"])
        };
        assert_eq!(evidence(&[twin], 0), Evidence::Candidate);
        let apart = Match {
            rival: Some(0.9 - RIVAL_MARGIN - 0.01),
            ..found(1, 0.9, &["str:x"])
        };
        assert!(identified_answer(&[apart]));
        // Preserved call-graph links still name it.
        let placed = Match {
            waived: true,
            rival: Some(0.9),
            ..found(1, 0.9, &["str:x", "joint:2"])
        };
        assert!(identified_answer(&[placed]));
    }

    #[test]
    fn an_unanchored_match_needs_similarity() {
        // Merged x64+arm64 `LZ4_loadDict` (lz4, clang -O2) from the real
        // corpus: its identifying required features are two constants. A
        // hinted scan of arm32 sqlite matched a function on `memset`, small
        // constants, and an optional division constant, at similarity 0.068.
        let identifying = vec![
            "const:0xbb000000".to_string(),
            "const:0xcf1bbcdc".to_string(),
        ];
        let lookalike = [
            "callee:*!memset",
            "const:0x0",
            "const:0x2",
            "const:0x3",
            "const:0xaaaaaaab",
        ];
        assert!(!anchored_enough(&identifying, &found(1, 0.068, &lookalike)));
        assert!(anchored_enough(
            &identifying,
            &found(1, MIN_UNANCHORED_SIMILARITY, &lookalike)
        ));
        // Holding one of them is enough at any similarity; an inherited copy
        // is not the function's own.
        assert!(anchored_enough(
            &identifying,
            &found(1, 0.068, &["const:0xbb000000"])
        ));
        assert!(!anchored_enough(
            &identifying,
            &found(1, 0.068, &["inl:const:0xbb000000"])
        ));
        // A signature without identifying evidence is left to the shape gates.
        assert!(anchored_enough(&[], &found(1, 0.068, &lookalike)));
    }

    #[test]
    fn a_constant_anchored_hinted_match_needs_similarity() {
        // Thumb `LZ4_loadDict` (lz4, clang -O2), a strong signature, in a
        // hinted scan of Thumb sqlite (clang -O2), from the real corpus: it
        // holds the identifying constants 0x10000 and 0x4000, at similarity
        // 0.121.
        let lookalike = [
            "callee:*!memset",
            "const:0x0",
            "const:0x10000",
            "const:0x14",
            "const:0x2",
            "const:0x3",
            "const:0x4",
            "const:0x4000",
        ];
        assert!(constant_anchored(&found(1, 0.121, &lookalike)));
        assert!(!constants_enough(&found(1, 0.121, &lookalike)));
        // The lowest constant-anchored true top-1 match: arm32
        // `inflateCodesUsed` (zlib, clang -O0) in Thumb zlib (clang -O2).
        let codes_used = ["const:0x0", "const:0x534", "const:0xffffffff", "ops:ret:2"];
        assert!(constants_enough(&found(1, 0.226, &codes_used)));
        // An in-image callee names the function at any similarity: arm64
        // `pagerWriteLargeSector` (sqlite, clang -Os) in Thumb sqlite.
        let pager = [
            "callee:pager_write",
            "const:0x1",
            "const:0x4",
            "const:0x8",
            "ops:ret:2",
        ];
        assert!(!constant_anchored(&found(1, 0.132, &pager)));
        assert!(constants_enough(&found(1, 0.132, &pager)));
        // Shape-only matches are left to their own floor.
        let shape = ["const:0x1", "ops:ret:2"];
        assert!(!constant_anchored(&found(1, 0.1, &shape)));
    }
}
