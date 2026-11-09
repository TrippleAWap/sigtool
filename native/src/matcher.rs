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

use crate::errors::SelfTestError;
use crate::features::{extract, Feature, FeatureKind};
use crate::normalize::{Kind, Normalizer};
use crate::recover::{recover, RecoveryLimits};
use crate::sigfile::Signature;
use crate::source::{ByteSource, Region};

pub const MAX_HITS_PER_ANCHOR: usize = 16;
pub const MAX_CANDIDATE_STARTS: usize = 256;
pub const MAX_MATCHES: usize = 32;
pub const BACKWARD_SWEEP_BYTES: u64 = 512;
pub const SCORE_DECIMALS: usize = 6;

/// Tier 1 rate limit for the runtime scanner: candidate recoveries allowed per
/// pass. Tier 0 needle search is never budgeted.
pub const DEFAULT_MAX_RECOVERIES: usize = 4_096;

/// Reference-index budgets: a linear sweep indexes whole regions at once, so
/// the instruction count must be bounded (AGENTS.md rule 8), and a run of
/// undecodable bytes must not cost one resync per byte.
pub const MAX_INDEX_INSTRUCTIONS: usize = 200_000;
pub const MAX_INDEX_RESYNCS: usize = 4_096;

/// Hint-free discovery fallback: instructions decoded while collecting direct
/// call targets. Bounded like the reference index for the same reason (rule 8).
pub const MAX_CALL_DISCOVERY_INSTRUCTIONS: usize = 50_000;

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

/// Apply both gates: weighted threshold and minimum distinct evidence.
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
    result.score >= signature.match_threshold
        && result.matched_required >= signature.min_distinct.min(required_count)
}

/// Find accepted matches for `signature` in `source`, best first.
///
/// `hints = false` is the hint-free discovery mode: known function starts and
/// front-end bounds are ignored, so candidates come from anchor hits, the
/// bounded backward sweep, and direct call targets (exact entries recovered from
/// code, not symbols). `index` adds the data-reference index, which turns
/// string-anchor hits into candidates.
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
    let mut matches: Vec<Match> = Vec::new();
    let mut budget = budget;
    for start in candidate_starts(source, hits, max_candidates, hints, index) {
        if let Some(remaining) = budget.as_mut() {
            if remaining.remaining == 0 {
                break;
            }
            remaining.remaining -= 1;
        }
        let recovered = match recover(source, start, limits, hints) {
            Ok(recovered) => recovered,
            Err(_) => continue,
        };
        let result = compare(signature, &extract(source, &recovered));
        if accepts(signature, &result) {
            matches.push(Match {
                address: recovered.start(),
                end: recovered.end(),
                score: result.score,
                matched: result.matched,
            });
        }
    }
    matches.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
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
    let mut candidates = candidate_starts(source, &hits, max_candidates, true, None);
    if !candidates.contains(&start) && hits.iter().any(|(_, key)| key.starts_with("str:")) {
        // String anchors only rank through the reference index; build it once
        // before declaring the function unreachable.
        let mut index = ReferenceIndex::default();
        for region in source.regions() {
            if region.executable {
                index.index_region(source, region);
            }
        }
        candidates = candidate_starts(source, &hits, max_candidates, true, Some(&index));
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
    Ok(Match {
        address: recovered.start(),
        end: recovered.end(),
        score: result.score,
        matched: result.matched,
    })
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
    hits: &[(u64, String)],
    max_candidates: usize,
    use_hints: bool,
    index: Option<&ReferenceIndex>,
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

    let mut hint_starts: HashSet<u64> = HashSet::new();
    let mut swept_starts: HashSet<u64> = HashSet::new();
    if use_hints {
        hint_starts.extend(
            source
                .function_starts()
                .into_iter()
                .filter(|start| source.is_executable(*start)),
        );
    } else {
        // Without symbols, a direct call target is still an exact function
        // entry, while a backward sweep only guesses one from an interior
        // landmark. The reference has no such source in hint-free mode, so its
        // string-only signatures find nothing; this is a deliberate native
        // improvement (measured in `PLAN.md` section 12). One bounded linear
        // decode pass per hint-free scan pays for it.
        hint_starts.extend(call_target_starts(source));
    }
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
            None => swept_starts.extend(swept_starts_from(source, *address)),
        }
    }
    if let Some(index) = index {
        for data_addr in &data_hits {
            for reference in index.referencers(*data_addr) {
                swept_starts.extend(swept_starts_from(source, *reference));
            }
        }
    }
    if hint_starts.is_empty() && swept_starts.is_empty() {
        return Vec::new();
    }
    rank(hint_starts, swept_starts, &landmarks)
        .into_iter()
        .take(max_candidates)
        .collect()
}

/// Starts of functions reachable through a direct call, from one bounded sweep.
///
/// Hint-free discovery otherwise depends on the signature finding a code
/// landmark: a constant's bytes or a string's referencer. String-only
/// signatures have neither when no reference index is supplied, and a landmark
/// further than [`BACKWARD_SWEEP_BYTES`] into the body gives the sweep the wrong
/// prologue. A called function's entry is in the code regardless of which
/// anchors its signature happens to carry, so call targets recover those cases
/// without trusting symbols (which hint-free mode deliberately ignores).
fn call_target_starts<S: ByteSource + ?Sized>(source: &S) -> Vec<u64> {
    let normalizer = Normalizer::new(source);
    let mut starts: HashSet<u64> = HashSet::new();
    let mut decoded = 0usize;
    let mut resyncs = 0usize;
    'regions: for region in source.regions() {
        if !region.executable {
            continue;
        }
        let mut cursor = region.start;
        while cursor < region.end() {
            if decoded >= MAX_CALL_DISCOVERY_INSTRUCTIONS || resyncs >= MAX_INDEX_RESYNCS {
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
                if matches!(insn.kind, Kind::Call | Kind::NoreturnCall) {
                    if let Some(target) = insn.target {
                        if source.is_executable(target) {
                            starts.insert(target);
                        }
                    }
                }
            }
            let last = insns.last().expect("non-empty");
            cursor = last.addr + last.size as u64;
        }
    }
    let mut out: Vec<u64> = starts.into_iter().collect();
    out.sort_unstable();
    out
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
        starts.push(cursor);
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
