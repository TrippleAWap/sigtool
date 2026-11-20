//! Which scan budgets ran out.
//!
//! Every whole-image pass is bounded (AGENTS.md rule 8), and a pass that hits
//! its bound stops quietly: matches past that point are simply not found. A
//! [`Coverage`] collects the budgets one command exhausted so the CLI can say
//! its answer may be incomplete. It only reads state the passes already keep;
//! no cap, candidate, score, or signature depends on it.

use crate::matcher::{
    CodeIndex, ReferenceIndex, ScanContext, MAX_DISCOVERY_INSTRUCTIONS, MAX_INDEX_RESYNCS,
    MAX_UNWIND_CANDIDATES,
};
use crate::scanner::ScanReport;
use crate::source::ByteSource;
use crate::starts::MAX_START_SWEEP_BYTES;
use crate::unwind::MAX_UNWIND_ENTRIES;

/// One bounded pass. The order is the report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Budget {
    /// Function-start synthesis sweep over code without an unwind table.
    StartSweep,
    /// Merged unwind and synthesized function starts kept per image.
    UnwindEntries,
    /// Data-reference index (string anchors to the code that uses them).
    ReferenceIndex,
    /// Hint-free discovery pass (instruction boundaries, call targets,
    /// constant references).
    Discovery,
    /// Unwind entries a hint-free scan compares per signature.
    UnwindCandidates,
    /// Candidate recoveries one runtime-scanner pass may spend.
    Recoveries,
    /// (signature, function) pairs joint resolution weighs per module group
    /// ([`crate::joint::MAX_PAIRS`]); a larger group is left as scanned.
    JointPairs,
}

impl Budget {
    /// Stable identifier used in JSON output.
    pub fn key(self) -> &'static str {
        match self {
            Budget::StartSweep => "start_sweep",
            Budget::UnwindEntries => "unwind_entries",
            Budget::ReferenceIndex => "reference_index",
            Budget::Discovery => "discovery",
            Budget::UnwindCandidates => "unwind_candidates",
            Budget::Recoveries => "recoveries",
            Budget::JointPairs => "joint_pairs",
        }
    }
}

/// A budget that ran out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exhausted {
    pub budget: Budget,
    /// The cap, in the budget's unit: bytes for [`Budget::StartSweep`],
    /// instructions for the indexes, pairs for [`Budget::JointPairs`],
    /// entries or candidates otherwise.
    pub limit: usize,
    /// What the pass counted, in the same unit, when it keeps a count:
    /// instructions indexed, entries kept, (for [`Budget::UnwindCandidates`])
    /// unwind entries available, or (for [`Budget::JointPairs`]) the pairs
    /// of the largest group skipped. `None` when
    /// the pass does not record one.
    pub count: Option<usize>,
}

impl Exhausted {
    /// One line for stderr, without a trailing newline.
    pub fn warning(&self) -> String {
        let count = self.count.unwrap_or(0);
        match self.budget {
            Budget::StartSweep => format!(
                "warning: function-start synthesis ran out of its {}-byte sweep budget; \
                 functions in the code it skipped may be missing from hint-free discovery",
                self.limit
            ),
            Budget::UnwindEntries => format!(
                "warning: function starts capped at {} entries; \
                 functions past that point may be missing from hint-free discovery",
                self.limit
            ),
            Budget::ReferenceIndex if count >= self.limit => format!(
                "warning: reference index stopped at {} instructions; \
                 matches and call-graph evidence past that point may be missing",
                self.limit
            ),
            Budget::ReferenceIndex => format!(
                "warning: reference index stopped after {MAX_INDEX_RESYNCS} undecodable runs \
                 in one region ({count} instructions indexed); \
                 matches and call-graph evidence past that point may be missing"
            ),
            Budget::Discovery if count >= self.limit => format!(
                "warning: discovery index stopped at {} instructions; \
                 matches and call-graph evidence past that point may be missing",
                self.limit
            ),
            Budget::Discovery => format!(
                "warning: discovery index stopped after {MAX_INDEX_RESYNCS} undecodable runs \
                 ({count} instructions decoded); \
                 matches and call-graph evidence past that point may be missing"
            ),
            Budget::UnwindCandidates => format!(
                "warning: hint-free scan compares at most {} of {count} function starts; \
                 matches among the rest may be missing",
                self.limit
            ),
            Budget::Recoveries => format!(
                "warning: scan pass spent its budget of {} candidate recoveries; \
                 signatures scanned after that may be missing matches",
                self.limit
            ),
            Budget::JointPairs => format!(
                "warning: joint resolution skipped a module's {count} signature-function \
                 pairs (cap {}); its signatures keep their single-signature matches",
                self.limit
            ),
        }
    }
}

/// The budgets one command exhausted, at most one entry per [`Budget`],
/// sorted by [`Budget`]. Empty when every budgeted pass the command ran
/// completed. That is not a claim about passes it did not run: hinted
/// `locate` and `gen --pid` build no image index. The per-signature
/// candidate cap is not a budget and is never reported: candidates are
/// ranked (functions holding a landmark first, then by distance to one) and
/// the cap drops the least likely, which happens on nearly every image.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    exhausted: Vec<Exhausted>,
}

impl Coverage {
    pub fn new() -> Coverage {
        Coverage::default()
    }

    /// Budgets that ran out, in [`Budget`] order.
    pub fn exhausted(&self) -> &[Exhausted] {
        &self.exhausted
    }

    pub fn is_complete(&self) -> bool {
        self.exhausted.is_empty()
    }

    /// One stderr line per exhausted budget.
    pub fn warnings(&self) -> Vec<String> {
        self.exhausted.iter().map(Exhausted::warning).collect()
    }

    /// Record `entry`; a budget already recorded keeps its first entry.
    pub fn push(&mut self, entry: Exhausted) {
        if let Some(item) = self
            .exhausted
            .iter_mut()
            .find(|item| item.budget == entry.budget)
        {
            // One entry per budget, counting the largest overrun: several
            // modules of a process can each skip a joint group.
            if entry.count > item.count {
                item.count = entry.count;
            }
            return;
        }
        self.exhausted.push(entry);
        self.exhausted.sort_by_key(|item| item.budget);
    }

    /// Both indexes of a shared scan context.
    pub fn add_context(&mut self, context: &ScanContext) {
        self.add_reference_index(&context.references);
        self.add_code_index(&context.code);
    }

    pub fn add_reference_index(&mut self, index: &ReferenceIndex) {
        if index.truncated {
            self.push(Exhausted {
                budget: Budget::ReferenceIndex,
                limit: index.max_instructions(),
                count: Some(index.instructions),
            });
        }
    }

    pub fn add_code_index(&mut self, index: &CodeIndex) {
        if index.truncated() {
            self.push(Exhausted {
                budget: Budget::Discovery,
                limit: MAX_DISCOVERY_INSTRUCTIONS,
                count: Some(index.decoded()),
            });
        }
    }

    /// The image's own start lists, which only hint-free discovery reads;
    /// a hinted scan (`hints`) takes its starts from symbols instead.
    pub fn add_source<S: ByteSource + ?Sized>(&mut self, source: &S, hints: bool) {
        if hints {
            return;
        }
        if source.start_sweep_truncated() {
            self.push(Exhausted {
                budget: Budget::StartSweep,
                limit: MAX_START_SWEEP_BYTES,
                count: None,
            });
        }
        let entries = source.unwind_entries().len();
        // Every list is truncated to exactly this many, so reaching it means
        // entries were dropped (or, rarely, that there were exactly that many).
        if entries >= MAX_UNWIND_ENTRIES {
            self.push(Exhausted {
                budget: Budget::UnwindEntries,
                limit: MAX_UNWIND_ENTRIES,
                count: Some(entries),
            });
        }
        // Hint-free candidates include every unwind entry, so more entries
        // than the cap always drops some (`matcher::candidate_starts`).
        if entries > MAX_UNWIND_CANDIDATES {
            self.push(Exhausted {
                budget: Budget::UnwindCandidates,
                limit: MAX_UNWIND_CANDIDATES,
                count: Some(entries),
            });
        }
    }

    /// A module group joint resolution skipped as too large.
    pub fn add_joint(&mut self, skipped: Option<crate::joint::SkippedGroup>) {
        if let Some(skipped) = skipped {
            self.push(Exhausted {
                budget: Budget::JointPairs,
                limit: skipped.limit,
                count: Some(skipped.pairs),
            });
        }
    }

    /// A runtime-scanner pass that ran out of recoveries; `limit` is the
    /// budget the scanner was given.
    pub fn add_scan_report(&mut self, report: &ScanReport, limit: usize) {
        if report.budget_exhausted {
            self.push(Exhausted {
                budget: Budget::Recoveries,
                limit,
                count: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Arch;
    use crate::matcher::MAX_INDEX_INSTRUCTIONS;
    use crate::source::{MemorySource, Region};

    /// One x86-64 code region filled with `byte`.
    fn code(byte: u8, length: usize) -> MemorySource {
        let region = Region::new(".text", 0x1000, vec![byte; length], true, false);
        MemorySource::new(Arch::X64, vec![region], Vec::new(), Vec::new(), Vec::new())
    }

    /// `ret` runs: each sweep step decodes one instruction and stops, so a
    /// budget is checked after every instruction.
    fn rets(length: usize) -> MemorySource {
        code(0xc3, length)
    }

    #[test]
    fn a_tiny_reference_budget_is_reported() {
        let source = rets(256);
        let mut index = ReferenceIndex::new(8);
        for region in source.regions() {
            index.index_region(&source, region);
        }
        assert!(index.truncated);
        let mut coverage = Coverage::new();
        coverage.add_reference_index(&index);
        assert_eq!(coverage.exhausted().len(), 1);
        let entry = &coverage.exhausted()[0];
        assert_eq!(entry.budget, Budget::ReferenceIndex);
        assert_eq!(entry.limit, 8);
        assert_eq!(entry.count, Some(index.instructions));
        assert_eq!(
            entry.warning(),
            "warning: reference index stopped at 8 instructions; \
             matches and call-graph evidence past that point may be missing"
        );
    }

    #[test]
    fn a_small_image_exhausts_nothing() {
        let source = rets(256);
        let context = ScanContext::build(&source);
        assert!(!context.references.truncated);
        assert!(!context.code.truncated());
        assert!(context.code.decoded() > 0);
        assert!(context.references.instructions <= MAX_INDEX_INSTRUCTIONS);
        let mut coverage = Coverage::new();
        coverage.add_context(&context);
        coverage.add_source(&source, false);
        assert!(coverage.is_complete(), "{coverage:?}");
        assert!(coverage.warnings().is_empty());
    }

    #[test]
    fn undecodable_code_exhausts_both_resync_budgets() {
        // `push es` (0x06) is invalid in 64-bit mode, so every byte is a
        // resync and both passes stop at `MAX_INDEX_RESYNCS`.
        let source = code(0x06, 2 * MAX_INDEX_RESYNCS);
        let context = ScanContext::build(&source);
        assert!(context.references.truncated);
        assert!(context.code.truncated());
        let mut coverage = Coverage::new();
        coverage.add_context(&context);
        let budgets: Vec<Budget> = coverage.exhausted().iter().map(|e| e.budget).collect();
        assert_eq!(budgets, [Budget::ReferenceIndex, Budget::Discovery]);
        let warnings = coverage.warnings();
        assert!(warnings[0].contains("undecodable runs"), "{warnings:?}");
        assert!(warnings[1].starts_with("warning: discovery index stopped after"));
    }

    #[test]
    fn entries_are_unique_and_in_budget_order() {
        let mut coverage = Coverage::new();
        for budget in [
            Budget::Recoveries,
            Budget::ReferenceIndex,
            Budget::Recoveries,
        ] {
            coverage.push(Exhausted {
                budget,
                limit: 1,
                count: None,
            });
        }
        let budgets: Vec<Budget> = coverage.exhausted().iter().map(|e| e.budget).collect();
        assert_eq!(budgets, [Budget::ReferenceIndex, Budget::Recoveries]);
    }
}
