//! Joint resolution: a set of signatures from one module, scanned together.
//!
//! Each signature records its function's direct callers and callees as
//! `links` (module RVAs, SPEC.md §7). Scanned alone, a small function with no
//! evidence of its own matches every lookalike in the image; scanned as part
//! of its module, it is the one lookalike that fits the module's call graph.
//!
//! Resolution is a global one-to-one assignment of signatures to the target's
//! functions (SPEC.md §8): every (signature, function) pair is weighed by
//! similarity, agreement of call-graph degree, and a bonus for the scan's own
//! identified answer, then refined by how many of the signature's links the
//! current assignment of its neighbours preserves. The mapping is trusted only
//! when it preserves enough of the set's links to show the module is present,
//! which keeps joint answers out of unrelated images.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::matcher::{
    compare_keys, identified, identified_answer, rank_key, Candidate, Match, ScanContext,
    SimilarityKeys,
};
use crate::sigfile::{parse_link, Signature};
use crate::source::ByteSource;

/// Prefix of the joint key in [`Match::matched`]: `joint:N` marks a match
/// placed by joint resolution, with `N` of the signature's links preserved by
/// the mapping. `joint:0` was placed by similarity and the one-to-one
/// constraint alone and is not identifying evidence.
pub const JOINT_PREFIX: &str = "joint:";

/// Minimum similarity of a (signature, function) pair the assignment may use.
/// Measured on the real corpus joint dump (`bench --joint-report`): 0.15 or
/// 0.1 lets the mapping preserve enough links by chance in unrelated
/// libraries to pass the module gate (joint false hits 46 -> 259 or 639 of
/// 2862 signatures), 0.25 loses 0.04-0.05 recall in the cross-compiler rows.
/// Re-measured with inherited keys credited as in the scan (v4 corpus,
/// hint-free): 0.15 raises cjson/lz4/zlib joint false hits 0.049/0.015/0.017
/// -> 0.407/0.128/0.158; 0.25 loses 0.02-0.07 on every G2 row.
pub const JOINT_MIN_SIMILARITY: f64 = 0.2;

/// Weight added to the pair a signature's scan identified (its untied
/// [`identified_answer`]). Small, so the call graph can still overrule a
/// confident lookalike: 0.1-1.0 moved the G2 rows by at most 0.01; without
/// it same-build cross-arch recall drops 0.771 -> 0.761.
pub const SEED_BONUS: f64 = 0.3;

/// Weight added per link the neighbours' current assignment preserves.
/// 0.2-0.8 all land within 0.01 of each other; 0.3 is the best of them.
pub const LINK_BONUS: f64 = 0.3;

/// Weight of call-graph degree agreement: the mean of `1 / (1 + |Δ|)` over
/// the signature's `out:`/`in:` link counts against the candidate's callees
/// and callers in the target. A degree is an order-free call count that
/// survives architecture changes, and breaks ties between lookalikes with
/// identical features: +0.01-0.02 on every G2 row; exact-equality or
/// out-degree-only variants gain less.
pub const DEGREE_BONUS: f64 = 0.2;

/// Refinement rounds; the mapping usually settles in two or three.
pub const MAX_ROUNDS: usize = 4;

/// Module gate: the final mapping must preserve at least this many links
/// (counted from both ends, so three links seen by both signatures) ...
pub const MIN_PRESERVED_LINKS: usize = 6;

/// ... and at least this fraction of the links whose two ends it assigned.
/// In unrelated libraries the mapping preserved at most 5 link ends and
/// 0.18 of them; where the module is present it preserved 6 or more in
/// every cell but 13 weak sqlite cells (gcc or -O0 targets, a quarter of
/// their mapping right), which joint resolution then leaves alone.
pub const MIN_PRESERVED_FRACTION: f64 = 0.2;

/// Bound on (signature, function) pairs weighed per module (AGENTS.md rule
/// 8): a larger group is left as scanned.
pub const MAX_PAIRS: usize = 1 << 26;

/// Links of a joint match preserved by the mapping (0 if none or not joint).
pub fn votes(found: &Match) -> usize {
    found
        .matched
        .iter()
        .find_map(|key| key.strip_prefix(JOINT_PREFIX))
        .and_then(|count| count.parse().ok())
        .unwrap_or(0)
}

/// How a match ranks for joint resolution: 0 for a match it did not place,
/// `1 + votes` for one it did, so its answer is first even with no links.
pub fn rank(found: &Match) -> usize {
    if found
        .matched
        .iter()
        .any(|key| key.starts_with(JOINT_PREFIX))
    {
        1 + votes(found)
    } else {
        0
    }
}

/// The target's call graph as joint resolution reads it: each function's
/// callees ([`ScanContext::callees_of`]) and its callers, where the callers
/// are [`ScanContext::callers_of`] plus every function of the universe whose
/// callees include it.
///
/// `callers_of` comes from the code index's call sites, which hold direct
/// calls only, while `callees_of` also holds tail calls (`b`/`jmp` to a
/// function, as clang emits for thin wrappers such as cJSON's
/// `cJSONUtils_GenerateMergePatch`). Without the reverse edges an `out:`
/// link to a tail-called neighbour was counted as preserved by the module
/// gate but never earned [`LINK_BONUS`], so identical wrappers of different
/// helpers stayed tied on similarity. Simulated on the real corpus joint dump
/// (`bench --joint-report`, v4, hint-free) and confirmed by the full real
/// bench (`--max-functions 4 --joint`): other arch same build 0.777 ->
/// 0.792, other compiler 0.571 -> 0.579, other opt 0.466 -> 0.475, same arch
/// other compiler 0.702 -> 0.709, same arch other opt 0.540 -> 0.545; joint
/// false hits unchanged in every library. Capping the merged caller list at
/// [`crate::matcher::MAX_NEIGHBOURS`] like `callers_of` gains less (0.789 /
/// 0.576 / 0.471).
struct CallGraph {
    callees: HashMap<u64, Vec<u64>>,
    callers: HashMap<u64, Vec<u64>>,
}

impl CallGraph {
    fn build<S: ByteSource + ?Sized>(
        source: &S,
        context: &ScanContext,
        functions: &[Arc<Candidate>],
        hints: bool,
    ) -> (CallGraph, Vec<(usize, usize)>) {
        let starts: Vec<u64> = functions.iter().map(|candidate| candidate.start).collect();
        let lists: Vec<(Vec<u64>, Vec<u64>)> = crate::parallel::map(starts.len(), |index| {
            (
                context.callees_of(source, starts[index], hints),
                context.callers_of(source, starts[index], hints),
            )
        });
        let mut callers: HashMap<u64, Vec<u64>> = HashMap::new();
        for (start, (_, into)) in starts.iter().zip(&lists) {
            callers
                .entry(*start)
                .or_default()
                .extend(into.iter().copied());
        }
        for (start, (out, _)) in starts.iter().zip(&lists) {
            for callee in out {
                if callee != start {
                    callers.entry(*callee).or_default().push(*start);
                }
            }
        }
        for list in callers.values_mut() {
            list.sort_unstable();
            list.dedup();
        }
        // Degree agreement keeps the context's own counts, as measured.
        let degrees = lists
            .iter()
            .map(|(out, into)| (out.len(), into.len()))
            .collect();
        let callees = starts
            .into_iter()
            .zip(lists)
            .map(|(start, (out, _))| (start, out))
            .collect();
        (CallGraph { callees, callers }, degrees)
    }

    /// The target functions a link from a function placed at `anchor` allows:
    /// `callee` links (`out:`) name functions the anchor calls.
    /// A seeded scan answer outside the universe falls back to the context.
    fn linked<S: ByteSource + ?Sized>(
        &self,
        source: &S,
        context: &ScanContext,
        anchor: u64,
        callee: bool,
        hints: bool,
    ) -> Vec<u64> {
        let map = if callee { &self.callees } else { &self.callers };
        match map.get(&anchor) {
            Some(list) => list.clone(),
            None if callee => context.callees_of(source, anchor, hints),
            None => context.callers_of(source, anchor, hints),
        }
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
            let module = module_of(signature);
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

fn module_of(signature: &Signature) -> &str {
    signature
        .provenance
        .first()
        .map(|sample| sample.module.as_str())
        .unwrap_or("")
}

/// Every function of the target a signature can be assigned to: unwind
/// entries (hint-free) or function starts (hinted), plus the direct call
/// targets of those, each where recovery starts at that address.
fn universe<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    hints: bool,
) -> Vec<Arc<Candidate>> {
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
    // A call target without an unwind entry (a leaf the toolchain emitted
    // no CFI for) is still a function the call graph names.
    let mut all: Vec<u64> = recovered
        .iter()
        .flatten()
        .flat_map(|candidate| candidate.calls.iter().copied())
        .chain(nodes.iter().copied())
        .collect();
    all.sort_unstable();
    all.dedup();
    crate::parallel::map(all.len(), |index| {
        context
            .features
            .get_or_recover(source, all[index], hints)
            .filter(|candidate| candidate.start == all[index])
    })
    .into_iter()
    .flatten()
    .collect()
}

/// One signature's weighable pairs, sorted by address: `(address,
/// similarity, base weight)`.
type Row = Vec<(u64, f64, f64)>;

/// Highest weight first, then signature and address order: the order the
/// greedy assignment takes pairs in, independent of map iteration.
fn greedy(rows: &[Row], weights: &[Vec<f64>]) -> Vec<Option<u64>> {
    let mut pairs: Vec<(f64, usize, u64)> = rows
        .iter()
        .zip(weights)
        .enumerate()
        .flat_map(|(local, (row, weight))| {
            row.iter()
                .zip(weight)
                .map(move |((address, _, _), w)| (*w, local, *address))
        })
        .collect();
    pairs.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(&right.2))
    });
    let mut mapping = vec![None; rows.len()];
    let mut used: HashSet<u64> = HashSet::new();
    for (_, local, address) in pairs {
        if mapping[local].is_none() && !used.contains(&address) {
            mapping[local] = Some(address);
            used.insert(address);
        }
    }
    mapping
}

/// One module's signatures (global indices `group`) and what assigning them
/// needs.
struct Group<'a, S: ?Sized> {
    source: &'a S,
    context: &'a ScanContext,
    hints: bool,
    group: &'a [usize],
    /// Global signature index to position in `group`.
    position: HashMap<usize, usize>,
    edges: &'a [Vec<(bool, usize)>],
    graph: &'a CallGraph,
    rows: Vec<Row>,
}

impl<S: ByteSource + ?Sized> Group<'_, S> {
    fn start(&self, address: u64) -> Option<u64> {
        self.context
            .features
            .get_or_recover(self.source, address, self.hints)
            .map(|candidate| candidate.start)
    }

    /// Base weights plus [`LINK_BONUS`] per link of each signature that the
    /// current `mapping` of its neighbour would preserve at that candidate.
    fn agreement(&self, mapping: &[Option<u64>]) -> Vec<Vec<f64>> {
        let mut weights: Vec<Vec<f64>> = self
            .rows
            .iter()
            .map(|row| row.iter().map(|(_, _, base)| *base).collect())
            .collect();
        for (local, index) in self.group.iter().enumerate() {
            for (callee, other) in &self.edges[*index] {
                let Some(theirs) = self.position.get(other).and_then(|at| mapping[*at]) else {
                    continue;
                };
                // This function calls `other` when the link is `out:`, so it
                // is among the neighbour's callers; `in:` the reverse.
                for candidate in
                    self.graph
                        .linked(self.source, self.context, theirs, !*callee, self.hints)
                {
                    let Some(start) = self.start(candidate) else {
                        continue;
                    };
                    if let Ok(at) = self.rows[local].binary_search_by_key(&start, |entry| entry.0) {
                        weights[local][at] += LINK_BONUS;
                    }
                }
            }
        }
        weights
    }

    /// Links of signature `local` preserved by placing it at `address`.
    fn preserved(&self, local: usize, address: u64, mapping: &[Option<u64>]) -> usize {
        let index = self.group[local];
        let mut neighbours: [Option<Vec<u64>>; 2] = [None, None];
        let mut count = 0;
        for (callee, other) in &self.edges[index] {
            let Some(theirs) = self.position.get(other).and_then(|at| mapping[*at]) else {
                continue;
            };
            let list = neighbours[usize::from(*callee)].get_or_insert_with(|| {
                self.graph
                    .linked(self.source, self.context, address, *callee, self.hints)
            });
            if list.contains(&theirs) {
                count += 1;
            }
        }
        count
    }

    /// Link ends (preserved, assigned at both ends) under `mapping`.
    fn link_ends(&self, mapping: &[Option<u64>]) -> (usize, usize) {
        let (mut kept, mut total) = (0, 0);
        for (local, address) in mapping.iter().enumerate() {
            let Some(address) = address else {
                continue;
            };
            total += self.edges[self.group[local]]
                .iter()
                .filter(|(_, other)| {
                    self.position
                        .get(other)
                        .is_some_and(|at| mapping[*at].is_some())
                })
                .count();
            kept += self.preserved(local, *address, mapping);
        }
        (kept, total)
    }
}

/// Re-rank `matches` (one list per signature, best first) by a joint
/// assignment of each module's signatures to the target's functions. A
/// signature the trusted mapping places uniquely gets that function as its
/// first match, marked `joint:N` with the links the mapping preserves;
/// everything else is left as scanned.
pub fn resolve<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signatures: &[Signature],
    matches: &mut [Vec<Match>],
    hints: bool,
) {
    let edges = set_edges(signatures);
    let mut modules: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, signature) in signatures.iter().enumerate() {
        modules.entry(module_of(signature)).or_default().push(index);
    }
    // Only a module with links inside the set has a call graph to check the
    // mapping against; without one there is no gate, so nothing to trust.
    let groups: Vec<Vec<usize>> = modules
        .into_values()
        .filter(|group| group.iter().any(|index| !edges[*index].is_empty()))
        .collect();
    if groups.is_empty() {
        return;
    }
    let functions = universe(source, context, hints);
    let (graph, degrees) = CallGraph::build(source, context, &functions, hints);
    for group in &groups {
        if group.len().saturating_mul(functions.len()) > MAX_PAIRS {
            continue;
        }
        resolve_group(
            source, context, signatures, matches, hints, &edges, &graph, group, &functions,
            &degrees,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_group<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signatures: &[Signature],
    matches: &mut [Vec<Match>],
    hints: bool,
    edges: &[Vec<(bool, usize)>],
    graph: &CallGraph,
    group: &[usize],
    functions: &[Arc<Candidate>],
    degrees: &[(usize, usize)],
) {
    let prepared: Vec<SimilarityKeys> = group
        .iter()
        .map(|index| SimilarityKeys::new(&signatures[*index]))
        .collect();
    let mut rows: Vec<Row> = crate::parallel::map(group.len(), |local| {
        let signature = &signatures[group[local]];
        let links = signature.links.iter().filter_map(|link| parse_link(link));
        let (out, into) = links.fold((0usize, 0usize), |(out, into), (callee, _)| {
            if callee {
                (out + 1, into)
            } else {
                (out, into + 1)
            }
        });
        functions
            .iter()
            .zip(degrees)
            .filter_map(|(candidate, (callees, callers))| {
                let similar = prepared[local]
                    .similarity_at_least(&candidate.weighted, JOINT_MIN_SIMILARITY)?;
                let degree = 1.0 / (1.0 + out.abs_diff(*callees) as f64)
                    + 1.0 / (1.0 + into.abs_diff(*callers) as f64);
                Some((
                    candidate.start,
                    similar,
                    similar + DEGREE_BONUS * degree / 2.0,
                ))
            })
            .collect()
    });
    // The scan's own trusted answer is a seed: it starts ahead, but the call
    // graph can overrule it.
    for (local, index) in group.iter().enumerate() {
        let found = &matches[*index];
        if !identified_answer(found) {
            continue;
        }
        let address = found[0].address;
        match rows[local].binary_search_by_key(&address, |entry| entry.0) {
            Ok(at) => rows[local][at].2 += SEED_BONUS,
            Err(at) => rows[local].insert(at, (address, found[0].similarity, SEED_BONUS)),
        }
    }
    let state = Group {
        source,
        context,
        hints,
        group,
        position: group
            .iter()
            .enumerate()
            .map(|(local, index)| (*index, local))
            .collect(),
        edges,
        graph,
        rows,
    };
    let base: Vec<Vec<f64>> = state
        .rows
        .iter()
        .map(|row| row.iter().map(|(_, _, base)| *base).collect())
        .collect();
    let mut mapping = greedy(&state.rows, &base);
    for _ in 0..MAX_ROUNDS {
        let next = greedy(&state.rows, &state.agreement(&mapping));
        if next == mapping {
            break;
        }
        mapping = next;
    }
    let (kept, total) = state.link_ends(&mapping);
    if kept < MIN_PRESERVED_LINKS || (kept as f64) < MIN_PRESERVED_FRACTION * total as f64 {
        return;
    }
    let weights = state.agreement(&mapping);
    let owned: HashSet<u64> = mapping.iter().flatten().copied().collect();
    for (local, index) in group.iter().enumerate() {
        let Some(address) = mapping[local] else {
            continue;
        };
        let row = &state.rows[local];
        let Ok(at) = row.binary_search_by_key(&address, |entry| entry.0) else {
            continue;
        };
        // A free candidate weighing as much is an equally good placement:
        // no answer rather than a guess.
        let weight = weights[local][at];
        let tied = row
            .iter()
            .zip(&weights[local])
            .any(|((other, _, _), w)| *other != address && *w >= weight && !owned.contains(other));
        if tied {
            continue;
        }
        let preserved = state.preserved(local, address, &mapping);
        let signature = &signatures[*index];
        let found = &mut matches[*index];
        let mut placed = match found.iter().position(|m| m.address == address) {
            Some(position) => found.remove(position),
            None => {
                let Some(candidate) = context.features.get_or_recover(source, address, hints)
                else {
                    continue;
                };
                let result = compare_keys(signature, &candidate.keys);
                Match {
                    address,
                    end: candidate.end,
                    score: result.score,
                    similarity: row[at].1,
                    matched: result.matched,
                    waived: false,
                }
            }
        };
        placed.matched.retain(|key| !key.starts_with(JOINT_PREFIX));
        placed.matched.push(format!("{JOINT_PREFIX}{preserved}"));
        placed.matched.sort();
        found.insert(0, placed);
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
    let functions = universe(source, context, hints);
    let mut nodes: Vec<u64> = functions
        .iter()
        .flat_map(|candidate| candidate.calls.iter().copied())
        .chain(functions.iter().map(|candidate| candidate.start))
        .collect();
    nodes.sort_unstable();
    nodes.dedup();
    let graph: Vec<serde_json::Value> = crate::parallel::map(nodes.len(), |index| {
        let address = nodes[index];
        let candidate = context.features.get_or_recover(source, address, hints);
        json!({
            "a": address,
            "s": candidate.as_ref().map(|c| c.start),
            "out": context.callees_of(source, address, hints),
            "in": context.callers_of(source, address, hints),
            "n": candidate.as_ref().map_or(0, |c| c.calls.len()),
        })
    });
    let prepared: Vec<SimilarityKeys> = signatures.iter().map(SimilarityKeys::new).collect();
    let pairs: Vec<serde_json::Value> = crate::parallel::map(signatures.len(), |index| {
        let signature = &signatures[index];
        let mut row = Vec::new();
        for candidate in &functions {
            let Some(similar) =
                prepared[index].similarity_at_least(&candidate.weighted, JOINT_MIN_SIMILARITY)
            else {
                continue;
            };
            let result = compare_keys(signature, &candidate.keys);
            let found = Match {
                address: candidate.start,
                end: candidate.end,
                score: result.score,
                similarity: similar,
                matched: result.matched,
                waived: false,
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
            json!({"answer": identified_answer(found), "m": rows})
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
