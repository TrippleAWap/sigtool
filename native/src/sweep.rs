//! The resynchronizing linear sweep behind the whole-image indexes.
//!
//! The reference index and the code index both walk each executable region
//! the same way: decode a block at the cursor, move past its last
//! instruction, or skip one byte when nothing decodes. A [`RegionSweep`]
//! yields those steps once, so both indexes can be built from one decode of
//! the image instead of two.
//!
//! Each step depends only on its cursor, so the region can also be decoded
//! speculatively in parallel: every chunk is swept from its own first byte,
//! and the sequential walk takes a step from that table whenever the cursor
//! lands on a cursor the chunk visited (linear sweeps resynchronize within a
//! few instructions) and decodes the step itself otherwise. The walk visits
//! exactly the cursors a sequential sweep visits and gets the same
//! instructions at each, so the indexes are identical to a sequential build
//! (AGENTS.md rule 3).

use crate::matcher::MAX_INDEX_RESYNCS;
use crate::normalize::{Insn, Normalizer};
use crate::source::{ByteSource, Region};

/// Bytes decoded per step at most, like a page of code.
const STEP_BYTES: u64 = 0x1000;

/// Bytes per speculative chunk. Small enough that chunks balance across
/// workers on a 1 MB image, large enough that the few steps decoded twice
/// where a chunk starts out of sync stay negligible.
const CHUNK_BYTES: u64 = 0x4000;

/// One sweep step: the block decoded at the cursor, or `None` when nothing
/// decodes there and the sweep skips one byte.
pub(crate) type Step = Option<Vec<Insn>>;

pub(crate) struct RegionSweep<'a, S: ByteSource + ?Sized> {
    region: &'a Region,
    normalizer: Normalizer<'a, S>,
    cursor: u64,
    /// Speculatively decoded `(cursor, block)` steps, sorted by cursor; an
    /// empty block is a resync step.
    decoded: Vec<(u64, Vec<Insn>)>,
}

impl<'a, S: ByteSource + ?Sized> RegionSweep<'a, S> {
    pub(crate) fn new(source: &'a S, region: &'a Region) -> RegionSweep<'a, S> {
        let decoded = if crate::parallel::workers() > 1 && region.size() as u64 > CHUNK_BYTES {
            speculate(source, region)
        } else {
            Vec::new()
        };
        RegionSweep {
            region,
            normalizer: Normalizer::new(source),
            cursor: region.start,
            decoded,
        }
    }

    pub(crate) fn at_end(&self) -> bool {
        self.cursor >= self.region.end()
    }

    /// The step at the cursor, then advance past it.
    pub(crate) fn next_step(&mut self) -> Option<Step> {
        if self.at_end() {
            return None;
        }
        let insns = match self
            .decoded
            .binary_search_by_key(&self.cursor, |(cursor, _)| *cursor)
        {
            Ok(index) => std::mem::take(&mut self.decoded[index].1),
            Err(_) => decode_at(&self.normalizer, self.region, self.cursor),
        };
        match insns.last() {
            Some(last) => {
                self.cursor = last.addr + last.size as u64;
                Some(Some(insns))
            }
            None => {
                self.cursor += 1;
                Some(None)
            }
        }
    }
}

fn decode_at<S: ByteSource + ?Sized>(
    normalizer: &Normalizer<'_, S>,
    region: &Region,
    cursor: u64,
) -> Vec<Insn> {
    let span = (region.end() - cursor).min(STEP_BYTES) as usize;
    normalizer.decode_block(cursor, span)
}

/// Sweep every chunk of `region` from its own start, in parallel. A chunk
/// stops at the next chunk's start, or after as many resyncs as a whole
/// sweep may make, so undecodable bytes cost no more than sequentially
/// (AGENTS.md rule 8).
fn speculate<S: ByteSource + ?Sized>(source: &S, region: &Region) -> Vec<(u64, Vec<Insn>)> {
    let chunks = (region.size() as u64).div_ceil(CHUNK_BYTES) as usize;
    let swept = crate::parallel::map(chunks, |chunk| {
        let normalizer = Normalizer::new(source);
        let mut cursor = region.start + chunk as u64 * CHUNK_BYTES;
        let stop = (cursor + CHUNK_BYTES).min(region.end());
        let mut steps = Vec::new();
        let mut resyncs = 0usize;
        while cursor < stop && resyncs < MAX_INDEX_RESYNCS {
            let insns = decode_at(&normalizer, region, cursor);
            let next = match insns.last() {
                Some(last) => last.addr + last.size as u64,
                None => {
                    resyncs += 1;
                    cursor + 1
                }
            };
            steps.push((cursor, insns));
            cursor = next;
        }
        steps
    });
    // Chunk k's cursors lie in [start_k, start_k+1), so the concatenation
    // is sorted and has no duplicates.
    swept.into_iter().flatten().collect()
}
