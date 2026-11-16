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

/// `(callee, other signature)` per signature, for links inside the set.
fn set_edges(signatures: &[Signature]) -> Vec<Vec<(bool, usize)>> {
    // Link targets are RVAs in the signature's own module, so a signature is
    // found again by (module, rva) of its first sample.
    let mut by_origin: HashMap<(&str, u64), usize> = HashMap::new();
    for (index, signature) in signatures.iter().enumerate() {
        if let Some(sample) = signature.provenance.first() {
            by_origin.insert((sample.module.as_str(), sample.rva), index);
        }
    }
    signatures
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
        .collect()
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
    let edges = set_edges(signatures);
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

/// Weighted Jaccard of one signature against many candidates, with the
/// signature's key map built once ([`similarity`] rebuilds it per call).
/// Sums in the same order and rounds the same way, so the values are equal.
struct Prepared {
    wanted: HashMap<String, f64>,
    total: f64,
}

impl Prepared {
    fn new(signature: &Signature) -> Prepared {
        Prepared {
            wanted: signature
                .features
                .iter()
                .map(|feature| (feature.key(), feature.weight))
                .collect(),
            total: signature
                .features
                .iter()
                .map(|feature| feature.weight)
                .sum(),
        }
    }

    fn similarity(&self, candidate: &[(String, f64)]) -> f64 {
        let mut shared = 0.0;
        let mut extra = 0.0;
        for (key, weight) in candidate {
            match self.wanted.get(key) {
                Some(signature_weight) => shared += signature_weight,
                None => extra += weight,
            }
        }
        let denominator = self.total + extra;
        if denominator <= 0.0 {
            0.0
        } else {
            let value = shared / denominator;
            format!("{value:.6}").parse::<f64>().unwrap_or(value)
        }
    }
}

/// Everything joint resolution can see in one target, for offline
/// simulation of assignment rules (`bench --joint-report`): the set's links,
/// each signature's scan matches, the target's call graph over its unwind
/// entries (hint-free) or function starts, and every (signature, function)
/// pair with similarity at least [`JOINT_MIN_SIMILARITY`].
pub fn report<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signatures: &[Signature],
    matches: &[Vec<Match>],
    hints: bool,
) -> serde_json::Value {
    use serde_json::json;
    let edges = set_edges(signatures);
    let mut nodes: Vec<u64> = if hints {
        source.function_starts()
    } else {
        source
            .unwind_entries()
            .iter()
            .map(|(start, _)| *start)
            .collect()
    };
    nodes.sort_unstable();
    nodes.dedup();
    let recovered = crate::parallel::map(nodes.len(), |index| {
        context.features.get_or_recover(source, nodes[index], hints)
    });
    // Call targets that are not unwind entries still receive votes.
    let mut all: Vec<u64> = recovered
        .iter()
        .flatten()
        .flat_map(|candidate| candidate.calls.iter().copied())
        .chain(nodes.iter().copied())
        .collect();
    all.sort_unstable();
    all.dedup();
    let graph: Vec<serde_json::Value> = crate::parallel::map(all.len(), |index| {
        let address = all[index];
        let candidate = context.features.get_or_recover(source, address, hints);
        json!({
            "a": address,
            "s": candidate.as_ref().map(|c| c.start),
            "out": context.callees_of(source, address, hints),
            "in": context.callers_of(source, address, hints),
            "n": candidate.as_ref().map_or(0, |c| c.calls.len()),
        })
    });
    let prepared: Vec<Prepared> = signatures.iter().map(Prepared::new).collect();
    let pairs: Vec<serde_json::Value> = crate::parallel::map(signatures.len(), |index| {
        let signature = &signatures[index];
        let mut row = Vec::new();
        for address in &all {
            let Some(candidate) = context.features.get_or_recover(source, *address, hints) else {
                continue;
            };
            if candidate.start != *address {
                continue;
            }
            let similar = prepared[index].similarity(&candidate.weighted);
            if similar < JOINT_MIN_SIMILARITY {
                continue;
            }
            let result = compare_keys(signature, &candidate.keys);
            let found = Match {
                address: candidate.start,
                end: candidate.end,
                score: result.score,
                similarity: similar,
                matched: result.matched,
            };
            let has_str = found.matched.iter().any(|key| key.starts_with("str:"));
            row.push(json!([
                candidate.start,
                similar,
                found.score,
                identified(&found),
                has_str
            ]));
        }
        serde_json::Value::Array(row)
    });
    let scanned: Vec<serde_json::Value> = matches
        .iter()
        .map(|found| {
            let rows: Vec<serde_json::Value> = found
                .iter()
                .map(|m| {
                    let (votes, near, similar, score) = rank_key(m);
                    let has_str = m.matched.iter().any(|key| key.starts_with("str:"));
                    json!([
                        m.address,
                        similar,
                        score,
                        near,
                        votes,
                        identified(m),
                        has_str
                    ])
                })
                .collect();
            json!({"answer": crate::matcher::identified_answer(found), "m": rows})
        })
        .collect();
    let edges: Vec<serde_json::Value> = edges
        .iter()
        .map(|list| {
            json!(list
                .iter()
                .map(|(callee, other)| json!([callee, other]))
                .collect::<Vec<_>>())
        })
        .collect();
    json!({
        "edges": edges,
        "features": signatures.iter().map(|s| s.features.len()).collect::<Vec<_>>(),
        "neighbours": signatures.iter().map(|s| s.neighbours.len()).collect::<Vec<_>>(),
        "links": signatures.iter().map(|s| &s.links).collect::<Vec<_>>(),
        "graph": graph,
        "pairs": pairs,
        "scan": scanned,
    })
}
