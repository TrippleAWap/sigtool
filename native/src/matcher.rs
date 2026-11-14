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
use crate::features::{const_words, extract, Feature, FeatureKind};
use crate::normalize::{Kind, Normalizer};
use crate::recover::{recover, RecoveryLimits};
use crate::score::score_features;
use crate::sigfile::Signature;
use crate::source::{ByteSource, Region};

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

/// [`compare`] against a candidate's precomputed key set.
pub fn compare_keys(signature: &Signature, present: &HashSet<String>) -> MatchScore {
    let matched: Vec<&crate::sigfile::SignatureFeature> = signature
        .features
        .iter()
        .filter(|feature| present.contains(&feature.key()))
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
    let matched_required = matched.iter().filter(|feature| feature.required).count();
    if required_weight <= 0.0 {
        return MatchScore {
            score: 0.0,
            matched: Vec::new(),
            matched_required: 0,
        };
    }
    let total: f64 = matched.iter().map(|feature| feature.weight).sum();
    let score = round_to((total / required_weight).min(1.0), SCORE_DECIMALS);
    let mut matched_keys: Vec<String> = matched.iter().map(|feature| feature.key()).collect();
    matched_keys.sort();
    MatchScore {
        score,
        matched: matched_keys,
        matched_required,
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
        let agrees = matched.contains(key.as_str());
        let entry = dimensions.entry(dimension).or_insert(false);
        *entry |= agrees;
    }
    if dimensions.is_empty() {
        return 1.0;
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
    result.score >= signature.match_threshold
        && result.matched_required >= signature.min_distinct.min(required_count)
        && (!needs_shape_corroboration(signature)
            || named
            || shape_agreement(signature, &result.matched) >= MIN_SHAPE_AGREEMENT)
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
}

/// How many of an image's functions carry each feature key.
#[derive(Debug)]
pub struct Frequencies {
    pub functions: usize,
    pub document_frequency: HashMap<String, u32>,
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
        let mut document_frequency: HashMap<String, u32> = HashMap::new();
        let mut functions = 0usize;
        for start in starts {
            let Some(candidate) = cache.get_or_recover(source, start, hints) else {
                continue;
            };
            functions += 1;
            for key in &candidate.keys {
                *document_frequency.entry(key.clone()).or_insert(0) += 1;
            }
        }
        (functions >= MIN_FREQUENCY_FUNCTIONS).then_some(Frequencies {
            functions,
            document_frequency,
        })
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
                    for feature in &other.features {
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

    pub fn build<S: ByteSource + ?Sized>(source: &S) -> ScanContext {
        let mut references = ReferenceIndex::default();
        for region in source.regions() {
            if region.executable {
                references.index_region(source, region);
            }
        }
        ScanContext {
            references,
            code: CodeIndex::build(source),
            features: FeatureCache::default(),
            frequencies: [OnceLock::new(), OnceLock::new()],
        }
    }
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
    let hits = anchor_hits(source, signature);
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
    );
    // Image-relative specificity: a match made only of features that many of
    // this image's functions carry (common imports, boilerplate constants,
    // frequent shape buckets) is coincidence, not identification. Applied to
    // hint-free scans only, where it was measured: a stripped image's whole
    // function list is compared, so coincidences are frequent there. Images
    // too small for frequencies keep every accepted match.
    if hints {
        return matches;
    }
    let frequencies = context.frequencies[usize::from(hints)]
        .get_or_init(|| Frequencies::build(source, &context.features, hints));
    let Some(frequencies) = frequencies else {
        return matches;
    };
    let signature_neighbours: HashSet<&str> =
        signature.neighbours.iter().map(String::as_str).collect();
    let mut kept: Vec<Match> = matches
        .into_iter()
        .filter(|found| found.similarity >= MIN_SIMILARITY)
        .filter_map(|mut found| {
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
            // neighbour key is evidence it does not see: a one-block helper
            // has the commonest shape in the image, yet only one such helper
            // is called from the function holding the signature's string.
            if shared.is_empty() && !specific(frequencies, &found) {
                return None;
            }
            // A function whose neighbours carry evidence is expected to keep
            // some of it: a shape-only lookalike elsewhere shares none.
            if !own_evidence
                && shared.is_empty()
                && signature.neighbours.len() >= MIN_NEIGHBOURS_TO_REJECT
            {
                return None;
            }
            if !shared.is_empty() {
                found.matched.extend(shared);
                found.matched.sort();
            } else if !enough_evidence(&found) {
                return None;
            }
            Some(found)
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

/// How matches are ordered, best first: call-graph votes from joint
/// resolution ([`crate::joint`]), shared neighbour evidence, similarity, then
/// score. Two matches with equal keys are a tie.
pub fn rank_key(found: &Match) -> (usize, usize, f64, f64) {
    (
        crate::joint::votes(found),
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
        Some(("joint", _)) => true,
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

/// Whether a match rests on evidence that identifies a function (see
/// [`identifying_key`]) rather than only shape and near-zero constants.
/// Front-ends report it: a shape-only match of a small function is often
/// right in its own library, but the same evidence also fires on lookalikes
/// in unrelated code.
pub fn identified(found: &Match) -> bool {
    found.matched.iter().any(|key| identifying_key(key))
}

fn enough_evidence(found: &Match) -> bool {
    found.matched.len() >= MIN_LOW_INFORMATION_MATCHED
        || found.matched.iter().any(|key| identifying_key(key))
}

/// Minimum similarity for any accepted match. Measured on stripped x64 and
/// arm64: 0.2 keeps every single-arch and cross-arch top-1 cell and cuts
/// merged hint-free false positives 0.242 -> 0.141; 0.3 starts losing true
/// cross-compiler matches, whose similarity is genuinely low.
pub const MIN_SIMILARITY: f64 = 0.2;

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
    ) -> Option<Candidate> {
        let recovered = recover(source, start, limits, hints).ok()?;
        let features = extract(source, &recovered);
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
        let candidate = Candidate::recover(source, start, None, hints).map(Arc::new);
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
) -> Vec<Match> {
    let mut matches: Vec<Match> = Vec::new();
    let mut budget = budget;
    for start in candidate_starts(source, signature, hits, max_candidates, hints, index, code) {
        if let Some(remaining) = budget.as_mut() {
            if remaining.remaining == 0 {
                break;
            }
            remaining.remaining -= 1;
        }
        let candidate = match cache {
            Some(cache) if limits.is_none() => cache.get_or_recover(source, start, hints),
            _ => Candidate::recover(source, start, limits, hints).map(Arc::new),
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let result = compare_keys(signature, &candidate.keys);
        if accepts(signature, &result) {
            matches.push(Match {
                address: candidate.start,
                end: candidate.end,
                score: result.score,
                similarity: similarity(signature, &candidate.weighted),
                matched: result.matched,
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

    /// Instruction addresses that reference `addr`, sorted.
    pub fn referencers(&self, addr: u64) -> &[u64] {
        self.merged.get(&addr).map(Vec::as_slice).unwrap_or(&[])
    }

    /// (Re)index one executable region; returns the instructions indexed.
    pub fn index_region<S: ByteSource + ?Sized>(&mut self, source: &S, region: &Region) -> usize {
        self.by_region.remove(&region.start);
        self.instructions -= self.region_counts.remove(&region.start).unwrap_or(0);
        if !region.executable {
            self.rebuild_merged();
            return 0;
        }
        let budget = self.max_instructions.saturating_sub(self.instructions);
        if budget == 0 {
            self.truncated = true;
            self.rebuild_merged();
            return 0;
        }

        let normalizer = Normalizer::new(source);
        let mut refs: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut count = 0usize;
        let mut resyncs = 0usize;
        let mut cursor = region.start;
        while cursor < region.end() {
            if count >= budget || resyncs >= MAX_INDEX_RESYNCS {
                self.truncated = true;
                break;
            }
            let span = (region.end() - cursor).min(0x1000) as usize;
            let insns = normalizer.decode_block(cursor, span);
            if insns.is_empty() {
                cursor += 1;
                resyncs += 1;
                continue;
            }
            for insn in &insns {
                count += 1;
                for reference in &insn.refs {
                    refs.entry(reference.addr).or_default().push(insn.addr);
                }
            }
            let last = insns.last().expect("non-empty");
            cursor = last.addr + last.size as u64;
        }
        self.instructions += count;
        self.region_counts.insert(region.start, count);
        let region_refs = refs
            .into_iter()
            .map(|(addr, mut addrs)| {
                addrs.sort_unstable();
                addrs.dedup();
                (addr, addrs)
            })
            .collect();
        self.by_region.insert(region.start, region_refs);
        self.rebuild_merged();
        count
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
    let wanted: HashMap<String, f64> = signature
        .features
        .iter()
        .map(|feature| (feature.key(), feature.weight))
        .collect();
    let total: f64 = wanted.values().sum();
    let mut shared = 0.0;
    let mut extra = 0.0;
    for (key, weight) in candidate {
        match wanted.get(key) {
            Some(signature_weight) => shared += signature_weight,
            None => extra += weight,
        }
    }
    let denominator = total + extra;
    if denominator <= 0.0 {
        0.0
    } else {
        round_to(shared / denominator, SCORE_DECIMALS)
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

fn find_at(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.len() > data.len() {
        return None;
    }
    (start..=data.len() - needle.len()).find(|index| &data[*index..*index + needle.len()] == needle)
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
}

impl CodeIndex {
    pub fn build<S: ByteSource + ?Sized>(source: &S) -> CodeIndex {
        let normalizer = Normalizer::new(source);
        let mut index = CodeIndex::default();
        let mut decoded = 0usize;
        let mut resyncs = 0usize;
        'regions: for region in source.regions() {
            if !region.executable {
                continue;
            }
            let mut boundaries: Vec<u64> = Vec::new();
            let mut cursor = region.start;
            while cursor < region.end() {
                if decoded >= MAX_DISCOVERY_INSTRUCTIONS || resyncs >= MAX_INDEX_RESYNCS {
                    break 'regions;
                }
                let span = (region.end() - cursor).min(0x1000) as usize;
                let insns = normalizer.decode_block(cursor, span);
                if insns.is_empty() {
                    cursor += 1;
                    resyncs += 1;
                    continue;
                }
                for insn in &insns {
                    decoded += 1;
                    if !insn.padding {
                        boundaries.push(insn.addr);
                    }
                    if matches!(insn.kind, Kind::Call | Kind::NoreturnCall) {
                        if let Some(target) = insn.target {
                            if source.is_executable(target) {
                                index.call_targets.insert(target);
                            }
                            if let Some(callee) =
                                call_destination(source, target, insn.callee.as_deref())
                            {
                                index.callers.entry(callee).or_default().push(insn.addr);
                            }
                        }
                    }
                    for value in insn.consts.iter().flat_map(|value| const_words(*value)) {
                        index.const_refs.entry(value).or_default().push(insn.addr);
                    }
                }
                let last = insns.last().expect("non-empty");
                cursor = last.addr + last.size as u64;
            }
            boundaries.sort_unstable();
            boundaries.dedup();
            index.boundaries.insert(region.start, boundaries);
        }
        for references in index.const_refs.values_mut() {
            references.sort_unstable();
            references.dedup();
        }
        index
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
}
