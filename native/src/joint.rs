//! Joint resolution: a set of signatures from one module, scanned together.
//!
//! Each signature records its function's direct callers and callees as
//! `links` (module RVAs, SPEC.md §7). A signature whose best match is
//! identified and unambiguous pins its function in the target; a linked
//! signature must then match among that function's callers or callees in the
//! target's call graph. That turns a small function with no evidence of its
//! own, which alone matches every lookalike in the image, into the one
//! lookalike wired to an already-found function. Pinning repeats until
//! nothing changes, so evidence propagates along call chains.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::matcher::{compare_keys, identified, rank_key, similarity, Match, ScanContext};
use crate::sigfile::{parse_link, Signature};
use crate::source::ByteSource;

/// Prefix of the call-graph vote count in [`Match::matched`].
pub const JOINT_PREFIX: &str = "joint:";

/// Propagation rounds; each round can only pin more signatures, so this
/// bounds the work on a long call chain (AGENTS.md rule 8).
pub const MAX_ROUNDS: usize = 8;

/// Minimum similarity of a linked candidate. The call graph narrows the
/// choice to an anchor's few callers or callees, so the full acceptance gate
/// (threshold, `min_distinct`) is not required: across compilers it rejected
/// the true function in nearly every case where it was in the linked set,
/// because the required features are exactly what changed. Within the set,
/// the most similar candidate is taken.
pub const JOINT_MIN_SIMILARITY: f64 = 0.2;

/// Call-graph votes a match received from joint resolution (0 if none).
pub fn votes(found: &Match) -> usize {
    found
        .matched
        .iter()
        .find_map(|key| key.strip_prefix(JOINT_PREFIX))
        .and_then(|count| count.parse().ok())
        .unwrap_or(0)
}

/// An identified best match with nothing tied with it.
fn pins(matches: &[Match]) -> Option<u64> {
    let best = matches.first()?;
    let alone = matches
        .get(1)
        .is_none_or(|next| rank_key(next) < rank_key(best));
    (identified(best) && alone).then_some(best.address)
}

/// The target functions a link from a function pinned at `anchor` allows:
/// `callee` links (`out:`) name functions the anchor calls.
fn linked<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    anchor: u64,
    callee: bool,
    hints: bool,
) -> Vec<u64> {
    if callee {
        context.callees_of(source, anchor, hints)
    } else {
        context.callers_of(source, anchor, hints)
    }
}

/// Re-rank `matches` (one list per signature, best first) using the links
/// between `signatures`. A signature with a linked, pinned neighbour gets the
/// most similar candidate among that neighbour's callers or callees as its
/// first match, marked `joint:VOTES`; signatures without links are untouched.
pub fn resolve<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signatures: &[Signature],
    matches: &mut [Vec<Match>],
    hints: bool,
) {
    // Link targets are RVAs in the signature's own module, so a signature is
    // found again by (module, rva) of its first sample.
    let mut by_origin: HashMap<(&str, u64), usize> = HashMap::new();
    for (index, signature) in signatures.iter().enumerate() {
        if let Some(sample) = signature.provenance.first() {
            by_origin.insert((sample.module.as_str(), sample.rva), index);
        }
    }
    // (callee, other signature) per signature, for links inside the set.
    let edges: Vec<Vec<(bool, usize)>> = signatures
        .iter()
        .map(|signature| {
            let module = signature
                .provenance
                .first()
                .map(|sample| sample.module.as_str())
                .unwrap_or("");
            signature
                .links
                .iter()
                .filter_map(|link| {
                    let (callee, rva) = parse_link(link)?;
                    by_origin.get(&(module, rva)).map(|other| (callee, *other))
                })
                .collect()
        })
        .collect();

    let mut pinned: Vec<Option<u64>> = matches.iter().map(|found| pins(found)).collect();
    // An anchor whose links all contradict the other anchors is a confident
    // lookalike, not the function: release it so the graph can place it.
    let released: Vec<usize> = (0..signatures.len())
        .filter(|index| {
            let Some(anchor) = pinned[*index] else {
                return false;
            };
            let (mut agree, mut disagree) = (0, 0);
            for (callee, other) in &edges[*index] {
                if let Some(theirs) = pinned[*other] {
                    if linked(source, context, anchor, *callee, hints).contains(&theirs) {
                        agree += 1;
                    } else {
                        disagree += 1;
                    }
                }
            }
            disagree > 0 && agree == 0
        })
        .collect();
    for index in released {
        pinned[index] = None;
    }

    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for index in 0..signatures.len() {
            if pinned[index].is_some() {
                continue;
            }
            let taken: HashSet<u64> = pinned.iter().flatten().copied().collect();
            let mut votes: BTreeMap<u64, usize> = BTreeMap::new();
            for (callee, other) in &edges[index] {
                let Some(anchor) = pinned[*other] else {
                    continue;
                };
                // This function calls `other` when the link is `out:`, so it
                // is among the anchor's callers; `in:` the reverse.
                for candidate in linked(source, context, anchor, !*callee, hints) {
                    *votes.entry(candidate).or_insert(0) += 1;
                }
            }
            let signature = &signatures[index];
            let mut best: Vec<Match> = votes
                .into_iter()
                .filter(|(address, _)| !taken.contains(address))
                .filter_map(|(address, count)| {
                    let candidate = context.features.get_or_recover(source, address, hints)?;
                    let similar = similarity(signature, &candidate.weighted);
                    (similar >= JOINT_MIN_SIMILARITY).then(|| {
                        let result = compare_keys(signature, &candidate.keys);
                        let mut matched = result.matched;
                        matched.push(format!("{JOINT_PREFIX}{count}"));
                        matched.sort();
                        Match {
                            address: candidate.start,
                            end: candidate.end,
                            score: result.score,
                            similarity: similar,
                            matched,
                        }
                    })
                })
                .collect();
            best.sort_by(|left, right| {
                rank_key(right)
                    .partial_cmp(&rank_key(left))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(left.address.cmp(&right.address))
            });
            let Some(winner) = best.first() else {
                continue;
            };
            // Two linked candidates that tie are no better than one guess.
            if best
                .get(1)
                .is_some_and(|next| rank_key(next) == rank_key(winner))
            {
                continue;
            }
            let winner = winner.clone();
            pinned[index] = Some(winner.address);
            let rest: Vec<Match> = std::mem::take(&mut matches[index])
                .into_iter()
                .filter(|found| found.address != winner.address)
                .collect();
            matches[index] = std::iter::once(winner).chain(rest).collect();
            changed = true;
        }
        if !changed {
            break;
        }
    }
}
