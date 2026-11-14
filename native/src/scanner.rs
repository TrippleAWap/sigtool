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

use crate::errors::SignatureError;
use crate::matcher::{
    region_anchor_hits, scan_candidates, Match, RecoveryBudget, ReferenceIndex,
    MAX_CANDIDATE_STARTS,
};
use crate::sigfile::Signature;
use crate::source::{ByteSource, Region};

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
    /// The match rests on identifying evidence ([`crate::matcher::identified`]).
    pub identified: bool,
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
            state.matches = scan_candidates(
                self.source,
                signature,
                &flat,
                None,
                MAX_CANDIDATE_STARTS,
                true,
                None,
                Some(&mut budget),
            );
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
            for matched in &state.matches {
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
                    identified: crate::matcher::identified(matched),
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
