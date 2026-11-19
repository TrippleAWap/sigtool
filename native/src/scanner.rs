//! Runtime reference scanner: page hashing, incremental passes, budgets.
//!
//! The scanner wraps the reference matcher for live use. Everything expensive is
//! made incremental:
//!
//! * **Page hashing** -- every region is split into 4 KiB pages; a page's CRC-32
//!   identifies it across passes. A region whose pages are all unchanged is
//!   skipped entirely, and its matches carry over.
//! * **Prioritization** -- regions are scanned private-memory first, then
//!   modified or newly executable ones, then untouched module pages.
//! * **Reference index** -- the data-reference index is built per region and
//!   re-indexed only when that region changes, so string-anchor discovery stays
//!   incremental too.
//! * **Budgets** -- Tier 0 (needle search) always runs; Tier 1 (recovery) is
//!   rate-limited per pass by [`crate::matcher::RecoveryBudget`].
//!
//! The scanner never writes, never suspends, and reads only through the
//! [`ByteSource`] (AGENTS.md rule 9). All state is deterministic: hashes are
//! CRC-32 over page bytes -- never a salted hash (rule 3) -- and they are never
//! persisted.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::coverage::Coverage;
use crate::errors::SignatureError;
use crate::matcher::{
    hinted_floors, identified, rank_key, region_anchor_hits, scan_candidates, scan_in, Match,
    RecoveryBudget, ReferenceIndex, ScanContext, MAX_CANDIDATE_STARTS,
};
use crate::sigfile::Signature;
use crate::source::{ByteSource, ModuleView, Region};

/// Every signature against one image's shared context, best match first per
/// signature, in signature order. Hint-free, the signatures of one module
/// are then resolved jointly through their call-graph links (measured
/// hint-free only, `bench --joint`). The path of `scan --file` and of each
/// module of a process ([`scan_modules`]).
pub fn scan_all<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    signatures: &[Signature],
    hints: bool,
) -> Vec<Vec<Match>> {
    // Signatures share only the context's caches, so they scan in parallel;
    // results keep signature order.
    if signatures.len() > 1 {
        context.prepare_frequencies(source, hints);
    }
    let mut all: Vec<Vec<Match>> = crate::parallel::map(signatures.len(), |index| {
        scan_in(source, &signatures[index], context, hints)
    });
    if !hints {
        crate::joint::resolve(source, context, signatures, &mut all, false);
    }
    all
}

/// [`scan_all`], hint-free, over each module of `source` on its own
/// ([`ModuleView`]), merged into one ranked list per signature: the path
/// `scan --pid` and `locate --pid` take, and the one `bench --process-like`
/// measures. A process names no local function, so per module this is the
/// scan a stripped file of that module gets, minus the starts a file source
/// synthesizes from code.
///
/// `only` keeps the module with that base. `contexts`, one cell per entry of
/// `source.modules()`, keeps each module's context for a caller that scans
/// the same source again (the bench); without it each module's context is
/// dropped before the next is built, so a process holds one at a time.
/// Every module's budgets go to `coverage`.
pub fn scan_modules<S: ByteSource + ?Sized>(
    source: &S,
    signatures: &[Signature],
    only: Option<u64>,
    contexts: Option<&[OnceLock<ScanContext>]>,
    coverage: &mut Coverage,
) -> Vec<Vec<Match>> {
    let mut per_module: Vec<Vec<Vec<Match>>> = Vec::new();
    for (index, module) in source.modules().iter().enumerate() {
        if only.is_some_and(|base| base != module.base) {
            continue;
        }
        let view = ModuleView::new(source, module);
        // A module none of whose code was read (a data-only image, or pages
        // past the source's read budget) has nothing to match.
        if !view.regions().iter().any(|region| region.executable) {
            continue;
        }
        let built;
        let context = match contexts.and_then(|cells| cells.get(index)) {
            Some(cell) => cell.get_or_init(|| ScanContext::build(&view)),
            None => {
                built = ScanContext::build(&view);
                &built
            }
        };
        coverage.add_context(context);
        coverage.add_source(&view, false);
        per_module.push(scan_all(&view, context, signatures, false));
    }
    let mut lists: Vec<Vec<Vec<Match>>> = signatures.iter().map(|_| Vec::new()).collect();
    for module in per_module {
        for (list, matches) in lists.iter_mut().zip(module) {
            if !matches.is_empty() {
                list.push(matches);
            }
        }
    }
    lists.into_iter().map(merge_modules).collect()
}

/// One signature's per-module lists (each ranked, in module order) as one
/// list: modules ordered by their best match's rank, ties in module order,
/// each module's own order kept, so a single module's list is unchanged.
///
/// Each module was judged as its own image, so two modules can each hold an
/// identified best match (a library linked into the executable and loaded
/// as a DLL too). The other modules' identified best matches are then the
/// first one's rivals ([`crate::matcher::RIVAL_MARGIN`]): the answer stands
/// only when it is clearly the better match, as within one image.
fn merge_modules(mut lists: Vec<Vec<Match>>) -> Vec<Match> {
    if lists.len() <= 1 {
        return lists.pop().unwrap_or_default();
    }
    lists.sort_by(|left, right| {
        rank_key(&right[0])
            .partial_cmp(&rank_key(&left[0]))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let rival = lists[1..]
        .iter()
        .map(|list| &list[0])
        .filter(|best| identified(best))
        .map(|best| best.similarity)
        .reduce(f64::max);
    let mut merged: Vec<Match> = lists.into_iter().flatten().collect();
    if let Some(rival) = rival {
        let first = &mut merged[0];
        if identified(first) {
            first.rival = Some(first.rival.map_or(rival, |own| own.max(rival)));
        }
    }
    merged
}

pub const PAGE_BITS: u32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;

// Region priorities: private memory first, then changed image memory, then
// unchanged image memory (the common incremental case).
pub const PRIORITY_PRIVATE: u8 = 0;
pub const PRIORITY_CHANGED: u8 = 1;
pub const PRIORITY_UNCHANGED: u8 = 2;

/// One accepted match with the pass that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanHit {
    pub signature_id: String,
    pub name: String,
    pub address: u64,
    pub end: u64,
    pub score: f64,
    pub region: String,
    pub first_seen: usize,
    /// What the match can be trusted for ([`crate::matcher::evidence`]).
    pub evidence: crate::matcher::Evidence,
}

/// Cached Tier 0 hits and matches for one signature.
#[derive(Debug, Clone, Default)]
struct SignatureState {
    hits: HashMap<u64, Vec<(u64, String)>>,
    matches: Vec<Match>,
    first_seen: HashMap<u64, usize>,
}

/// One region's page hashes and change classification for this pass.
#[derive(Debug, Clone)]
struct RegionState {
    region: Region,
    hashes: Vec<u32>,
    private: bool,
    changed: bool,
}

/// What one pass did; the profile script records these counters.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanReport {
    pub pass_number: usize,
    pub hits: Vec<ScanHit>,
    pub new_hits: usize,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub regions_private: usize,
    pub pages_hashed: usize,
    pub budget_remaining: usize,
    pub budget_exhausted: bool,
    pub index_instructions: usize,
    pub index_truncated: bool,
}

fn priority(state: &RegionState) -> u8 {
    if state.private {
        PRIORITY_PRIVATE
    } else if state.changed {
        PRIORITY_CHANGED
    } else {
        PRIORITY_UNCHANGED
    }
}

/// Incrementally match a fixed signature set against one source.
pub struct SignatureScanner<'a, S: ByteSource + ?Sized> {
    source: &'a S,
    signatures: Vec<(Signature, String)>,
    pass_budget: RecoveryBudget,
    index: ReferenceIndex,
    owns_index: bool,
    regions: HashMap<u64, RegionState>,
    states: HashMap<String, SignatureState>,
    pass: usize,
}

impl<'a, S: ByteSource + ?Sized> SignatureScanner<'a, S> {
    pub fn new(
        source: &'a S,
        signatures: Vec<Signature>,
        budget: Option<RecoveryBudget>,
        index: Option<ReferenceIndex>,
    ) -> Result<SignatureScanner<'a, S>, SignatureError> {
        if signatures.is_empty() {
            return Err(SignatureError(
                "the scanner needs at least one signature".into(),
            ));
        }
        // Signature identities are precomputed once: `signature_id` serialises
        // the whole document to YAML, which is far too expensive to repeat per
        // pass.
        let signatures = signatures
            .into_iter()
            .map(|signature| {
                let id = signature.signature_id()?;
                Ok((signature, id))
            })
            .collect::<Result<Vec<_>, SignatureError>>()?;
        let states = signatures
            .iter()
            .map(|(_, id)| (id.clone(), SignatureState::default()))
            .collect();
        let owns_index = index.is_none();
        Ok(SignatureScanner {
            source,
            signatures,
            pass_budget: budget.unwrap_or_default(),
            index: index.unwrap_or_default(),
            owns_index,
            regions: HashMap::new(),
            states,
            pass: 0,
        })
    }

    pub fn index(&self) -> &ReferenceIndex {
        &self.index
    }

    /// The ranked matches the last pass left for the `index`-th signature
    /// (in the order given to [`SignatureScanner::new`]), with the
    /// similarity and matched keys a [`ScanHit`] drops; empty before the
    /// first pass or past the end.
    pub fn matches(&self, index: usize) -> &[Match] {
        self.signatures
            .get(index)
            .and_then(|(_, id)| self.states.get(id))
            .map_or(&[], |state| state.matches.as_slice())
    }

    /// Run one incremental pass; unchanged regions carry matches over.
    pub fn scan_pass(&mut self) -> ScanReport {
        self.pass += 1;
        let regions = self.classify();
        let mut budget = RecoveryBudget {
            remaining: self.pass_budget.remaining,
        };

        let mut private = 0usize;
        let mut regions_scanned = 0usize;
        let mut regions_skipped = 0usize;
        let mut ordered: Vec<&RegionState> = regions.values().collect();
        ordered.sort_by_key(|state| (priority(state), state.region.start));
        for state in ordered {
            if state.private {
                private += 1;
            }
            if state.changed {
                regions_scanned += 1;
                if self.owns_index && state.region.executable {
                    self.index.index_region(self.source, &state.region);
                }
            } else {
                regions_skipped += 1;
            }
        }

        let mut budget_exhausted = false;
        for (signature, signature_id) in &self.signatures {
            let state = self
                .states
                .get_mut(signature_id)
                .expect("state exists for every signature");
            let (hits, recomputed) = Self::signature_hits(signature, &regions, state, self.pass);
            if !recomputed {
                continue;
            }
            let flat: Vec<(u64, String)> = hits
                .values()
                .flat_map(|per_region| per_region.iter().cloned())
                .collect();
            // The floors `scan_in` applies to hinted file scans; without them
            // a process scan accepted shape-only lookalikes the bench's
            // precision numbers never saw.
            let candidates = scan_candidates(
                self.source,
                signature,
                &flat,
                None,
                MAX_CANDIDATE_STARTS,
                true,
                None,
                Some(&mut budget),
            );
            state.matches = hinted_floors(self.source, signature, candidates);
            for matched in &state.matches {
                state.first_seen.entry(matched.address).or_insert(self.pass);
            }
            let addresses: HashSet<u64> = state.matches.iter().map(|item| item.address).collect();
            state
                .first_seen
                .retain(|address, _| addresses.contains(address));
            if budget.remaining == 0 {
                budget_exhausted = true;
            }
        }

        let mut report_hits: Vec<ScanHit> = Vec::new();
        let mut new_hits = 0usize;
        for (signature, signature_id) in &self.signatures {
            let state = self
                .states
                .get(signature_id)
                .expect("state exists for every signature");
            for (index, matched) in state.matches.iter().enumerate() {
                let first_seen = state
                    .first_seen
                    .get(&matched.address)
                    .copied()
                    .unwrap_or(self.pass);
                if first_seen == self.pass {
                    new_hits += 1;
                }
                report_hits.push(ScanHit {
                    signature_id: signature_id.clone(),
                    name: signature.name.clone(),
                    address: matched.address,
                    end: matched.end,
                    score: matched.score,
                    region: region_name(matched.address, &regions),
                    first_seen,
                    evidence: crate::matcher::evidence(&state.matches, index),
                });
            }
        }
        report_hits.sort_by(|left, right| {
            (left.first_seen, left.name.as_str(), left.address).cmp(&(
                right.first_seen,
                right.name.as_str(),
                right.address,
            ))
        });

        self.pass_budget.remaining = budget.remaining;
        ScanReport {
            pass_number: self.pass,
            hits: report_hits,
            new_hits,
            regions_scanned,
            regions_skipped,
            regions_private: private,
            pages_hashed: regions.values().map(|state| state.hashes.len()).sum(),
            budget_remaining: budget.remaining,
            budget_exhausted,
            index_instructions: self.index.instructions,
            index_truncated: self.index.truncated,
        }
    }

    // -- internals ---------------------------------------------------------

    /// Refresh per-region page hashes; classify new, changed, and gone.
    fn classify(&mut self) -> HashMap<u64, RegionState> {
        let mut current: HashMap<u64, RegionState> = HashMap::new();
        for region in self.source.regions() {
            let hashes: Vec<u32> = region.data.chunks(PAGE_SIZE).map(crc32fast::hash).collect();
            let previous = self.regions.get(&region.start);
            let private = self.source.module_for(region.start).is_none();
            let unchanged = previous.is_some_and(|state| state.hashes == hashes);
            current.insert(
                region.start,
                RegionState {
                    region: region.clone(),
                    hashes,
                    private,
                    changed: !unchanged,
                },
            );
        }
        let gone: Vec<u64> = self
            .regions
            .keys()
            .filter(|start| !current.contains_key(start))
            .copied()
            .collect();
        for start in gone {
            self.index.drop_region(start);
            for state in self.states.values_mut() {
                state.hits.remove(&start);
            }
        }
        self.regions = current.clone();
        current
    }

    /// Anchor hits for one signature, recomputing only changed regions.
    fn signature_hits(
        signature: &Signature,
        regions: &HashMap<u64, RegionState>,
        state: &mut SignatureState,
        pass: usize,
    ) -> (HashMap<u64, Vec<(u64, String)>>, bool) {
        let changed: HashSet<u64> = regions
            .iter()
            .filter(|(_, region)| region.changed)
            .map(|(start, _)| *start)
            .collect();
        let touched = state.hits.keys().any(|start| changed.contains(start));
        if pass > 1 && !touched {
            return (state.hits.clone(), false);
        }

        let mut hits: HashMap<u64, Vec<(u64, String)>> = HashMap::new();
        let mut ordered: Vec<(&u64, &RegionState)> = regions.iter().collect();
        ordered.sort_by_key(|(start, _)| **start);
        for (start, region_state) in ordered {
            if !region_state.changed {
                if let Some(previous) = state.hits.get(start) {
                    hits.insert(*start, previous.clone());
                    continue;
                }
            }
            hits.insert(*start, region_anchor_hits(&region_state.region, signature));
        }
        state.hits = hits.clone();
        (hits, true)
    }
}

fn region_name(address: u64, regions: &HashMap<u64, RegionState>) -> String {
    if let Some(state) = regions.get(&address) {
        return state.region.name.clone();
    }
    let mut starts: Vec<u64> = regions.keys().copied().collect();
    starts.sort_unstable_by(|left, right| right.cmp(left));
    for start in starts {
        if start <= address {
            return regions[&start].region.name.clone();
        }
    }
    "unknown".to_string()
}
