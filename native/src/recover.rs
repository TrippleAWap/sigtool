//! Bounded recursive-descent recovery of function bounds and shape.
//!
//! Recovery walks from a function entry, decoding straight-line runs and
//! following direct branches inside the function. It is deliberately
//! conservative: every budget is bounded, undecodable bytes end a block instead
//! of raising, and a jump that leaves the symbol's range is treated as a tail
//! call rather than followed.

use std::collections::{BTreeMap, HashMap};

use crate::arch::Arch;
use crate::errors::DecodeError;
use crate::normalize::{Insn, Kind, Normalizer, OpClass};
use crate::source::ByteSource;
use crate::spec::{MAX_BLOCKS, MAX_BLOCK_BYTES, MAX_FUNCTION_BYTES, MAX_INSTRUCTIONS};

/// One straight-line run of instructions and where control goes next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub insns: Vec<Insn>,
    pub successors: Vec<u64>,
    pub terminated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFunction {
    pub entry: u64,
    pub arch: Arch,
    pub blocks: Vec<Block>,
    pub degraded: bool,
    /// End of the function's inline literal pool (ARM32); 0 elsewhere.
    pub pool_end: u64,
}

impl RecoveredFunction {
    pub fn start(&self) -> u64 {
        self.blocks
            .first()
            .map(|block| block.start)
            .unwrap_or(self.entry)
    }

    pub fn end(&self) -> u64 {
        self.blocks
            .iter()
            .map(|block| block.end)
            .max()
            .unwrap_or(self.entry)
            .max(self.pool_end)
    }

    pub fn size(&self) -> u64 {
        self.end().saturating_sub(self.start())
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn edge_count(&self) -> usize {
        self.blocks.iter().map(|block| block.successors.len()).sum()
    }

    pub fn loop_count(&self) -> usize {
        let starts: Vec<u64> = self.blocks.iter().map(|block| block.start).collect();
        self.blocks
            .iter()
            .flat_map(|block| {
                block
                    .successors
                    .iter()
                    .map(move |succ| (block.start, *succ))
            })
            .filter(|(start, succ)| *succ <= *start && starts.contains(succ))
            .count()
    }

    pub fn instruction_count(&self) -> usize {
        self.blocks.iter().map(|block| block.insns.len()).sum()
    }

    pub fn is_small(&self) -> bool {
        self.instruction_count() <= 12
    }

    pub fn op_counts(&self) -> HashMap<OpClass, usize> {
        let mut counts: HashMap<OpClass, usize> = HashMap::new();
        for block in &self.blocks {
            for insn in &block.insns {
                if insn.kind != Kind::Ignored {
                    *counts.entry(insn.op).or_insert(0) += 1;
                }
            }
        }
        counts
    }
}

/// Budgets applied to untrusted bytes; tests shrink them deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLimits {
    pub max_function_bytes: u64,
    pub max_block_bytes: u64,
    pub max_instructions: usize,
    pub max_blocks: usize,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        RecoveryLimits {
            max_function_bytes: MAX_FUNCTION_BYTES,
            max_block_bytes: MAX_BLOCK_BYTES,
            max_instructions: MAX_INSTRUCTIONS,
            max_blocks: MAX_BLOCKS,
        }
    }
}

/// Recover the function containing `addr` from `source`.
///
/// `hints = false` ignores front-end function bounds, as a scanner without
/// symbols would; the walk then ends at the first terminator or budget edge.
pub fn recover<S: ByteSource + ?Sized>(
    source: &S,
    addr: u64,
    limits: Option<RecoveryLimits>,
    hints: bool,
) -> Result<RecoveredFunction, DecodeError> {
    let arch = source.arch();
    if !matches!(arch, Arch::X64 | Arch::Arm64 | Arch::Arm32 | Arch::Thumb) {
        return Err(DecodeError(format!(
            "{} feature extraction is not implemented in the native port yet",
            arch
        )));
    }
    let bounds = limits.unwrap_or_default();

    let hint = if hints {
        source.hint_function(addr)
    } else {
        None
    };
    let hinted = hint.is_some_and(|(start, end)| start <= addr && addr < end);
    let function_end = match hint {
        Some((_, end)) if hinted => end,
        _ => addr.saturating_add(bounds.max_function_bytes),
    };
    if function_end <= addr {
        return Err(DecodeError(format!(
            "function bounds for 0x{addr:x} are empty"
        )));
    }

    let inside = |target: u64| addr <= target && target < function_end;
    let is_tail_target = |target: u64| -> bool {
        // Authoritative symbol bounds define the function, so a symbol inside
        // the range is still ours. Without bounds, a jump onto another symbol
        // is a tail call and must not be followed into unrelated code.
        if hinted {
            return false;
        }
        target != addr && source.name_for_address(target).is_some()
    };

    let normalizer = Normalizer::new(source);
    let mut blocks: HashMap<u64, Block> = HashMap::new();
    let mut queue: Vec<u64> = vec![addr];
    let mut cursor = 0usize;
    let mut degraded = false;

    while cursor < queue.len() {
        let start = queue[cursor];
        cursor += 1;
        if blocks.contains_key(&start) || !inside(start) {
            continue;
        }
        if blocks.len() >= bounds.max_blocks {
            degraded = true;
            break;
        }

        let available = bounds.max_block_bytes.min(function_end - start);
        let mut decoded = normalizer.decode_block(start, available as usize);
        // Alignment padding after the last real instruction is not part of the
        // function body; trimming it keeps bounds comparable to symbol sizes.
        while decoded
            .last()
            .is_some_and(|insn| insn.kind == Kind::Ignored)
        {
            decoded.pop();
        }
        if decoded.is_empty() {
            continue;
        }

        let last = decoded.last().expect("non-empty");
        let block_end = last.addr + last.size as u64;
        let terminated = last.kind.is_terminating();
        let mut successors: Vec<u64> = Vec::new();

        match last.kind {
            Kind::CondJump => {
                if let Some(target) = last.target {
                    if inside(target) {
                        successors.push(target);
                    }
                }
                if inside(block_end) {
                    successors.push(block_end);
                }
            }
            Kind::Jump => {
                if let Some(target) = last.target {
                    if inside(target) && !is_tail_target(target) {
                        successors.push(target);
                    }
                }
            }
            Kind::Ret | Kind::Trap | Kind::NoreturnCall => {}
            _ => {
                // Ran out of budget or bytes without a terminator: stop here and
                // mark the recovery as partial rather than guessing.
                degraded = true;
            }
        }
        dedupe_in_place(&mut successors);

        let block = Block {
            start,
            end: block_end,
            insns: decoded,
            successors,
            terminated,
        };
        let successors = block.successors.clone();
        blocks.insert(start, block);
        for successor in successors {
            if !blocks.contains_key(&successor) {
                queue.push(successor);
            }
        }
    }

    if blocks.is_empty() || !blocks.contains_key(&addr) {
        return Err(DecodeError(format!(
            "no instructions recovered at 0x{addr:x}"
        )));
    }

    let ordered: Vec<Block> = BTreeMap::from_iter(blocks).into_values().collect();
    let instruction_count: usize = ordered.iter().map(|block| block.insns.len()).sum();
    if instruction_count > bounds.max_instructions {
        degraded = true;
    }
    // ARM32 pools sit inline after the last instruction and are part of the
    // function; every other architecture leaves `pool_end` at 0.
    let pool_end = ordered
        .iter()
        .flat_map(|block| block.insns.iter())
        .map(|insn| insn.pool_end)
        .max()
        .unwrap_or(0);
    Ok(RecoveredFunction {
        entry: addr,
        arch,
        blocks: ordered,
        degraded,
        pool_end,
    })
}

fn dedupe_in_place(values: &mut Vec<u64>) {
    let mut seen: Vec<u64> = Vec::with_capacity(values.len());
    values.retain(|value| {
        if seen.contains(value) {
            false
        } else {
            seen.push(*value);
            true
        }
    });
}
