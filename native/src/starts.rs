//! Function starts synthesized from evidence that survives stripping.
//!
//! Unwind tables give exact entries on most images (`unwind`), but not all:
//! lld and GNU ld merge identical adjacent `.ARM.exidx` entries, so clang
//! ARM32/Thumb images keep only about half of their starts, and Debian armhf
//! GCC emits no unwind tables for C at all. Without symbols, the remaining
//! starts come from what the image still holds:
//!
//! - pointers to code: `.dynsym` function values and relative relocations
//!   (function-pointer tables, init arrays, vtables);
//! - code addresses formed position-independently (`ldr rX, =off` or
//!   `movw`/`movt`, then `add rX, pc`), how PIC code takes a function's
//!   address for a callback;
//! - direct call targets (`bl`/`blx`), decoded in the mode the image's
//!   [`ModeMap`](crate::arm_mode::ModeMap) gives each address;
//! - the first instruction after an unconditional terminator, past alignment
//!   padding and literal pools, when no local branch reaches it: compilers
//!   lay functions out back to back, so unreachable code after a return is
//!   the next function.
//!
//! A bogus start inside a function becomes a false scan candidate and cuts
//! the function it lands in short, so each rule is kept only where it
//! measured precise on the real corpus (see `docs/history/PLAN-v0.5.md` section 12).
//!
//! The image is untrusted (AGENTS.md rule 8): sweeps are linear and capped in
//! bytes, inline tables are capped in entries, and every read is
//! bounds-checked.

use std::collections::BTreeMap;

use crate::arch::Arch;
use crate::source::Region;
use crate::stubs::{arm32_stub, MAX_STUB_BYTES};
use crate::unwind::{UnwindEntry, MAX_UNWIND_ENTRIES};

/// Upper bound on bytes examined by all sweeps of one image (two passes).
pub const MAX_START_SWEEP_BYTES: usize = 128 << 20;
/// Upper bound on entries read from one inline jump table.
const MAX_TABLE_ENTRIES: usize = 4096;
/// Largest distance, in bytes, from the instruction that loads a PIC offset
/// to the `add rX, pc` that uses it. Real corpus, stripped arm32 + thumb,
/// recall by window (no window added a false start): 0 (rule off) 0.9836 /
/// 0.9758, 8 bytes 0.9901 / 0.9841, 16 bytes 0.9936 / 0.9851, 32 bytes
/// 0.9941 / 0.9853, and 64 or 256 bytes no further gain.
const PIC_WINDOW: u64 = 32;
/// Distinct targets in one gap that make a pointer run a label table
/// ([`label_tables`]). Real corpus, stripped arm32 recall/precision by
/// value: rule off 0.9941/0.9735 (lua's 83-label `luaV_execute` table in
/// every build), 2: 0.9873/0.9995, 4: 0.9918, 8: 0.9933 (function tables
/// with 8-15 adjacent pointer-only callbacks lose them), 16 and 32:
/// 0.9941/0.9995. 32 keeps a margin over the largest such callback group.
pub const MIN_LABEL_RUN: usize = 32;

/// What the sweep found, kept apart so each rule can be measured.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// Pointers into scanned code (mode bit cleared).
    pub pointers: Vec<u64>,
    /// Direct call targets whose mode agrees with the map.
    pub calls: Vec<u64>,
    /// Position-independent code addresses (`ldr rX, =off` or `movw`/`movt`,
    /// then `add rX, pc`) whose mode agrees with the map.
    pub pic_refs: Vec<u64>,
    /// First instruction after a terminator, padding, and pools.
    pub after_terminator: Vec<u64>,
    /// After-terminator positions holding a linker thunk or veneer
    /// (`stubs::arm32_stub`): lld's Thumb-2 thunks sit back to back at the
    /// end of `.text`, reached only by `b.w` tail calls, and open with no
    /// prologue.
    pub stubs: Vec<u64>,
    /// First instruction after a literal pool that the sweep reached by
    /// falling through: code before a pool never falls into it, so the
    /// instruction before was a call that does not return.
    pub after_pool: Vec<u64>,
    /// Start of each scanned code region (after padding).
    pub region_starts: Vec<u64>,
    /// Non-call branch targets: target -> (conditional, unconditional) count.
    pub branches: BTreeMap<u64, (u32, u32)>,
    /// Instruction boundaries holding a frame-saving prologue.
    pub prologues: Vec<u64>,
    /// Literal pools and inline tables, `[start, end)`, sorted and merged.
    pub data: Vec<(u64, u64)>,
}

/// Executable regions that hold compiled functions: not the PLT, whose stubs
/// are linker-made and have no symbol of their own.
fn scanned(region: &Region) -> bool {
    region.executable && !region.name.starts_with(".plt") && region.name != ".iplt"
}

/// Collect start evidence for an ELF image.
pub fn evidence(
    arch: Arch,
    regions: &[Region],
    pointers: &[u64],
    is_thumb: &dyn Fn(u64) -> bool,
) -> Evidence {
    let mut code: Vec<&Region> = regions.iter().filter(|r| scanned(r)).collect();
    code.sort_by_key(|region| region.start);
    let in_code = |address: u64| {
        code.iter()
            .any(|region| region.start <= address && address < region.end())
    };
    let mut found = Evidence::default();
    let arm = matches!(arch, Arch::Arm32 | Arch::Thumb);
    let mask = if arm { !1u64 } else { !0u64 };
    found.pointers = pointers
        .iter()
        // A function pointer carries its callee's mode in bit 0; a
        // computed-goto label (`&&label`) is relocated the same way but is
        // always even, so in Thumb code its mode disagrees with the map.
        .filter(|pointer| !arm || is_thumb(*pointer & !1) == (*pointer & 1 != 0))
        .map(|pointer| pointer & mask)
        .filter(|address| in_code(*address))
        .collect();
    if arm {
        let mut budget = MAX_START_SWEEP_BYTES;
        // Pass one finds literal pools; pass two sweeps again skipping them,
        // so pool words are never decoded as instructions.
        let mut data: Vec<(u64, u64)> = Vec::new();
        for pass in 0..2 {
            let mut walk = ArmWalk {
                data: &data,
                found: Evidence::default(),
            };
            for region in &code {
                if budget < region.data.len() {
                    break;
                }
                budget -= region.data.len();
                walk.region(region, is_thumb);
            }
            let mut swept = walk.found;
            let mut found_data = std::mem::take(&mut swept.data);
            found_data.retain(|(start, _)| in_code(*start));
            data = merge_ranges(found_data);
            if pass == 1 {
                found.calls = swept.calls;
                found.pic_refs = swept.pic_refs;
                found.after_terminator = swept.after_terminator;
                found.stubs = swept.stubs;
                found.after_pool = swept.after_pool;
                found.region_starts = swept.region_starts;
                found.branches = swept.branches;
                found.prologues = swept.prologues;
            }
        }
        found.data = data;
        // A call is evidence only when the mode it implies is the mode the
        // image map gives its target: a pool word decoding as `bl` rarely
        // lands on code of the right mode.
        found.calls.retain(|target| in_code(*target & !1));
        let calls = std::mem::take(&mut found.calls);
        found.calls = calls
            .into_iter()
            .filter(|target| is_thumb(target & !1) == (target & 1 != 0))
            .map(|target| target & !1)
            .collect();
        // A PIC address carries its target's mode bit like a function
        // pointer (GCC and clang emit `sym - (.LPIC + 4)`, `sym` Thumb-marked),
        // so it must agree with the map too.
        let pic_refs = std::mem::take(&mut found.pic_refs);
        found.pic_refs = pic_refs
            .into_iter()
            .filter(|target| in_code(*target & !1))
            .filter(|target| is_thumb(target & !1) == (target & 1 != 0))
            .map(|target| target & !1)
            .collect();
        let data = found.data.clone();
        let outside_data = |address: &u64| !in_ranges(&data, *address);
        found.calls.retain(outside_data);
        found.pointers.retain(outside_data);
        found.pic_refs.retain(outside_data);
    } else if arch == Arch::Arm64 {
        let mut budget = MAX_START_SWEEP_BYTES;
        for region in &code {
            if budget < region.data.len() {
                break;
            }
            budget -= region.data.len();
            arm64_region(region, &mut found);
        }
        found.calls.retain(|target| in_code(*target));
    }
    for list in [
        &mut found.pointers,
        &mut found.calls,
        &mut found.pic_refs,
        &mut found.after_terminator,
        &mut found.stubs,
        &mut found.after_pool,
        &mut found.region_starts,
        &mut found.prologues,
    ] {
        list.sort_unstable();
        list.dedup();
        list.truncate(MAX_UNWIND_ENTRIES);
    }
    found
}

/// The synthesized starts this module stands behind, from `evidence`.
///
/// Measured on the real corpus against `.symtab` (all FUNC symbols,
/// `docs/history/PLAN-v0.5.md` section 12): pointers and mode-checked calls are 0.998-1.000 precise; an
/// after-terminator start that opens with a frame-saving prologue and is not
/// the target of a conditional branch is 0.999-1.000 precise. Without the
/// prologue the same position is 0.19-0.99 precise depending on compiler (case
/// blocks after a `b` or a `pop {pc}` look identical to leaf functions), so
/// leaf functions are left to the call and pointer evidence. Unconditional
/// branch references are allowed because they are tail calls.
pub fn synthesize(found: &Evidence) -> Vec<u64> {
    let mut starts: Vec<u64> = Vec::new();
    starts.extend(&found.pointers);
    starts.extend(&found.calls);
    starts.extend(&found.pic_refs);
    starts.extend(&found.region_starts);
    starts.extend(&found.stubs);
    // A pool reached by falling through follows a call that never returns
    // (`bl luaG_typeerror`), so the next function opens there with no
    // terminator before it. Real corpus, stripped arm32 / thumb recall:
    // 0.9941 / 0.9942 -> 0.9947 / 0.9948 with no false start. The same
    // test after every call found one function fewer than this and admits
    // positions that do return, so it was not kept.
    for address in found.after_terminator.iter().chain(&found.after_pool) {
        let prologue = found.prologues.binary_search(address).is_ok();
        let conditional = found
            .branches
            .get(address)
            .is_some_and(|(conditional, _)| *conditional > 0);
        if prologue && !conditional {
            starts.push(*address);
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts.truncate(MAX_UNWIND_ENTRIES);
    starts
}

/// Pointer targets that are code labels, not functions: GCC computed-goto
/// tables (`static void *disptab[] = { &&L_OP_MOVE, ... }`, lua's
/// `luaV_execute`) are relocated exactly like function-pointer tables, but
/// every entry lands inside one function. Within one run of consecutive
/// `slots` (`(slot, pointer)`, `slot_size` apart), at least
/// [`MIN_LABEL_RUN`] distinct targets that fall between the same two
/// consecutive `known` starts (evidence other than pointers, and unwind
/// entries), and are not known themselves, are returned as labels. A real
/// function-pointer table spans functions that have starts of their own.
pub fn label_tables(slots: &[(u64, u64)], slot_size: u64, known: &[u64]) -> Vec<u64> {
    let mut known = known.to_vec();
    known.sort_unstable();
    known.dedup();
    let mut slots = slots.to_vec();
    slots.sort_unstable();
    slots.dedup_by_key(|(slot, _)| *slot);
    let mut labels = Vec::new();
    let mut flush = |run: &[(u64, u64)]| {
        if run.len() < MIN_LABEL_RUN {
            return;
        }
        // Group the run's targets by the gap between known starts they fall
        // in; adjacent tables share a run, so a gap rather than the whole
        // run must hold them.
        let mut gaps: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
        for (_, pointer) in run {
            let target = pointer & !1;
            if known.binary_search(&target).is_err() {
                let gap = known.partition_point(|start| *start <= target);
                gaps.entry(gap).or_default().push(target);
            }
        }
        for mut targets in gaps.into_values() {
            // A table repeating one callback (`{noop, noop, ...}`) names one
            // function, so only distinct targets count.
            targets.sort_unstable();
            targets.dedup();
            if targets.len() >= MIN_LABEL_RUN {
                labels.extend(targets);
            }
        }
    };
    let mut begin = 0usize;
    for index in 1..=slots.len() {
        let continues =
            index < slots.len() && slots[index].0 == slots[index - 1].0.wrapping_add(slot_size);
        if !continues {
            flush(&slots[begin..index]);
            begin = index;
        }
    }
    labels.sort_unstable();
    labels.dedup();
    labels
}

/// Merge `synthesized` starts into unwind `table` entries.
///
/// Table entries always win. With `exact_ends` (`.eh_frame`, `.pdata`) each
/// entry's extent is authoritative, so a synthesized start inside one is
/// dropped; without (`.ARM.exidx`, whose ends are only the next entry's
/// start) every end is recomputed as the next merged start. A synthesized
/// entry ends at the next start, or is open (`0`) when it is the last one.
pub fn merge(table: &[UnwindEntry], synthesized: &[u64], exact_ends: bool) -> Vec<UnwindEntry> {
    let mut starts: Vec<(u64, u64, bool)> = table
        .iter()
        .map(|(start, end)| (*start, *end, true))
        .collect();
    for start in synthesized {
        let index = table.partition_point(|(entry, _)| *entry <= *start);
        if index > 0 {
            let (entry, end) = table[index - 1];
            if entry == *start || (exact_ends && *start < end) {
                continue;
            }
        }
        starts.push((*start, 0, false));
    }
    starts.sort_unstable();
    starts.dedup_by_key(|(start, _, _)| *start);
    starts.truncate(MAX_UNWIND_ENTRIES);
    let mut entries = Vec::with_capacity(starts.len());
    for (index, (start, end, from_table)) in starts.iter().enumerate() {
        let next = starts.get(index + 1).map_or(0, |(next, _, _)| *next);
        let end = if *from_table && exact_ends {
            *end
        } else {
            next
        };
        entries.push((*start, end));
    }
    entries
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn in_ranges(ranges: &[(u64, u64)], address: u64) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= address);
    index > 0 && address < ranges[index - 1].1
}

fn range_end(ranges: &[(u64, u64)], address: u64) -> Option<u64> {
    let index = ranges.partition_point(|(start, _)| *start <= address);
    (index > 0 && address < ranges[index - 1].1).then(|| ranges[index - 1].1)
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    i64::from(((value << shift) as i32) >> shift)
}

fn word_at(region: &Region, address: u64) -> Option<u32> {
    let offset = usize::try_from(address.checked_sub(region.start)?).ok()?;
    let bytes = region.data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn half_at(region: &Region, address: u64) -> Option<u16> {
    let offset = usize::try_from(address.checked_sub(region.start)?).ok()?;
    let bytes = region.data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// One decoded ARM32/Thumb instruction, reduced to what start finding needs.
#[derive(Default)]
struct Step {
    size: u64,
    /// Unconditional transfer that never falls through.
    terminator: bool,
    /// `(target, conditional)` of a non-call direct branch.
    branch: Option<(u64, bool)>,
    /// Call target with the Thumb bit set when the callee is Thumb.
    call: Option<u64>,
    /// `[start, end)` read by a pc-relative load.
    literal: Option<(u64, u64)>,
    /// Inline jump table: its case targets and its data `[start, end)`.
    table: Option<(Vec<u64>, u64, u64)>,
    prologue: bool,
    /// ARM `adr rD, label`: `(rD, label)`.
    adr: Option<(usize, u64)>,
    /// ARM `add pc, rB, rM`: `rB`, the base of a relative jump table.
    pc_add: Option<usize>,
    /// Thumb `it`: instructions it predicates.
    it_count: u32,
    /// `(rD, value)` written by a pc-relative literal load or a `movw`.
    load: Option<(usize, u32)>,
    /// `(rD, high half)` written by a `movt`.
    movt: Option<(usize, u32)>,
    /// `add rD, pc` forms: `(rD, rM, pc)`, the register holding the offset
    /// and the pc value the add reads.
    pc_relative: Option<(usize, usize, u64)>,
}

struct ArmWalk<'a> {
    data: &'a [(u64, u64)],
    found: Evidence,
}

impl ArmWalk<'_> {
    fn region(&mut self, region: &Region, is_thumb: &dyn Fn(u64) -> bool) {
        let mut thumb = is_thumb(region.start);
        let mut cursor = self.skip_gap(region, region.start, thumb);
        if let Some(start) = cursor {
            self.found.region_starts.push(start);
        }
        let mut it_left = 0u32;
        let mut skip: Option<(u64, u64)> = None;
        let mut adr: [Option<(u64, u64)>; 16] = [None; 16];
        // Offsets loaded for a later `add rX, pc`: `(value, address)`.
        let mut offsets: [Option<(u32, u64)>; 16] = [None; 16];
        while let Some(address) = cursor {
            if let Some(end) = range_end(self.data, address) {
                if let Some(start) = self.skip_gap(region, end, is_thumb(end)) {
                    self.found.after_pool.push(start);
                }
                cursor = Some(end);
                continue;
            }
            if let Some((start, end)) = skip {
                if address >= start {
                    skip = None;
                    if address < end {
                        cursor = Some(end);
                        continue;
                    }
                }
            }
            if address >= region.end() {
                break;
            }
            let step = if thumb {
                thumb_step(region, address)
            } else {
                arm_step(region, address)
            };
            let Some(step) = step else {
                // Misaligned for the mode, or a truncated tail: resynchronize
                // (the loop stops at the region end).
                cursor = Some(if thumb {
                    (address + 2) & !1
                } else {
                    (address + 4) & !3
                });
                continue;
            };
            let predicated = it_left > 0;
            it_left = if step.it_count > 0 {
                step.it_count
            } else {
                it_left.saturating_sub(1)
            };
            if step.prologue {
                self.found.prologues.push(address);
            }
            if let Some((register, label)) = step.adr {
                adr[register] = Some((label, address));
            }
            if let Some((register, value)) = step.load {
                offsets[register] = Some((value, address));
            }
            if let Some((register, high)) = step.movt {
                offsets[register] = offsets[register]
                    .filter(|(value, _)| *value <= 0xffff)
                    .map(|(value, at)| (value | (high << 16), at));
            }
            if let Some((register, source, pc)) = step.pc_relative {
                if let Some((value, at)) = offsets[source] {
                    if address - at <= PIC_WINDOW {
                        self.found
                            .pic_refs
                            .push(pc.wrapping_add(u64::from(value)) & 0xffff_ffff);
                    }
                }
                offsets[register] = None;
            }
            let mut step = step;
            if let Some(base) = step.pc_add {
                // clang: `adr rB, table; ldr rX, [rB, rI, lsl #2]; add pc, rB,
                // rX`, a table of offsets from its own start.
                if let Some((label, at)) = adr[base] {
                    if address - at <= 16 {
                        step.table = Some(relative_table(region, label));
                    }
                }
            }
            if let Some((target, conditional)) = step.branch {
                let entry = self.found.branches.entry(target).or_insert((0, 0));
                if conditional || predicated {
                    entry.0 = entry.0.saturating_add(1);
                } else {
                    entry.1 = entry.1.saturating_add(1);
                }
            }
            if let Some(target) = step.call {
                self.found.calls.push(target);
            }
            if let Some(range) = step.literal {
                self.found.data.push(range);
            }
            let mut next = address + step.size;
            if let Some((targets, start, end)) = step.table {
                for target in targets {
                    let entry = self.found.branches.entry(target & !1).or_insert((0, 0));
                    entry.0 = entry.0.saturating_add(1);
                }
                if end > start {
                    self.found.data.push((start, end));
                    if start <= next {
                        next = next.max(end);
                    } else {
                        // ARM dispatch tables start one word later, after
                        // the default-case branch.
                        skip = Some((start, end));
                    }
                }
            }
            if step.terminator && !predicated {
                adr = [None; 16];
                offsets = [None; 16];
                thumb = is_thumb(next);
                cursor = self.skip_gap(region, next, thumb);
                if let Some(start) = cursor {
                    thumb = is_thumb(start);
                    self.found.after_terminator.push(start);
                    let offset = (start - region.start) as usize;
                    let end = region.data.len().min(offset + MAX_STUB_BYTES);
                    if arm32_stub(start, &region.data[offset..end]).is_some() {
                        self.found.stubs.push(start);
                    }
                }
                it_left = 0;
            } else {
                cursor = Some(next);
            }
        }
    }

    /// Skip alignment padding and known pools from `address`; `None` at the
    /// end of the region. Every step advances, so this is linear in the
    /// region.
    fn skip_gap(&self, region: &Region, mut address: u64, thumb: bool) -> Option<u64> {
        loop {
            if let Some(end) = range_end(self.data, address) {
                address = end;
                continue;
            }
            if !thumb && address & 3 != 0 {
                address = (address + 3) & !3;
                continue;
            }
            if thumb && address & 1 != 0 {
                address += 1;
                continue;
            }
            if address >= region.end() {
                return None;
            }
            let padding = if thumb {
                half_at(region, address).is_some_and(|half| {
                    // `nop`, zero fill, and lld's 0xd4d4 / `udf` trap fill.
                    matches!(half, 0xbf00 | 0x0000 | 0xd4d4 | 0xdefe)
                })
            } else {
                word_at(region, address).is_some_and(|word| {
                    matches!(
                        word,
                        0xe320_f000 | 0xe1a0_0000 | 0x0000_0000 | 0xd4d4_d4d4 | 0xe7fe_defe
                    )
                })
            };
            if !padding {
                return Some(address);
            }
            address += if thumb { 2 } else { 4 };
        }
    }
}

/// AArch64: fixed-width words, no literal pools in compiled code (jump
/// tables live in `.rodata`), so one linear pass suffices.
fn arm64_region(region: &Region, found: &mut Evidence) {
    // A section starts a function as is: crti's `_init`/`_fini` open with a
    // `nop` (a BTI landing-pad slot), which is part of the function.
    if region.data.len() >= 4 {
        found.region_starts.push(region.start);
    }
    let mut after_terminator = false;
    for (index, chunk) in region.data.as_chunks::<4>().0.iter().enumerate() {
        let address = region.start + index as u64 * 4;
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        // `nop`, zero fill (`udf #0`).
        if after_terminator && matches!(word, 0xd503_201f | 0x0000_0000) {
            continue;
        }
        if after_terminator {
            found.after_terminator.push(address);
        }
        after_terminator = false;
        let relative = |bits: u32, shift: u32| {
            address
                .wrapping_add((sign_extend((word >> shift) & ((1 << bits) - 1), bits) << 2) as u64)
        };
        let mut record = |target: u64, conditional: bool| {
            let entry = found.branches.entry(target).or_insert((0, 0));
            if conditional {
                entry.0 = entry.0.saturating_add(1);
            } else {
                entry.1 = entry.1.saturating_add(1);
            }
        };
        if word & 0xfc00_0000 == 0x9400_0000 {
            found.calls.push(relative(26, 0));
        } else if word & 0xfc00_0000 == 0x1400_0000 {
            record(relative(26, 0), false);
            after_terminator = true;
        } else if word & 0xff00_0010 == 0x5400_0000 || word & 0x7e00_0000 == 0x3400_0000 {
            // `b.cond`, `cbz`/`cbnz`.
            record(relative(19, 5), true);
        } else if word & 0x7e00_0000 == 0x3600_0000 {
            // `tbz`/`tbnz`.
            record(relative(14, 5), true);
        } else if word & 0xffff_fc1f == 0xd65f_0000
            || word & 0xffff_fc1f == 0xd61f_0000
            || matches!(word, 0xd65f_0bff | 0xd65f_0fff)
        {
            // `ret`, `br`, `retaa`/`retab`.
            after_terminator = true;
        }
        // `paciasp`, `pacibsp`, `bti c`, `bti jc`, `stp x29, x30, [sp, #-N]!`,
        // `sub sp, sp, #N`.
        if matches!(word, 0xd503_233f | 0xd503_237f | 0xd503_245f | 0xd503_24df)
            || word & 0xffc0_7fff == 0xa980_7bfd
            || word & 0xff80_03ff == 0xd100_03ff
        {
            found.prologues.push(address);
        }
    }
}

fn arm_step(region: &Region, address: u64) -> Option<Step> {
    if address & 3 != 0 {
        return None;
    }
    let word = word_at(region, address)?;
    let pc = address.wrapping_add(8);
    let mut step = Step {
        size: 4,
        ..Step::default()
    };
    let cond = word >> 28;
    if cond == 0xf {
        if word >> 25 == 0x7d {
            let offset = sign_extend(word & 0x00ff_ffff, 24) << 2;
            let half = u64::from((word >> 24) & 1) << 1;
            step.call = Some(pc.wrapping_add(offset as u64).wrapping_add(half) | 1);
        }
        return Some(step);
    }
    let always = cond == 0xe;
    if (word >> 25) & 7 == 5 {
        let target = pc.wrapping_add((sign_extend(word & 0x00ff_ffff, 24) << 2) as u64);
        if word & (1 << 24) != 0 {
            step.call = Some(target);
        } else {
            step.branch = Some((target, !always));
            step.terminator = always;
        }
    } else if word & 0x0fff_fff0 == 0x012f_ff10 || word & 0x0fef_fff0 == 0x01a0_f000 {
        // `bx rM`, `mov pc, rM`.
        step.terminator = always;
    } else if word & 0x0e10_8000 == 0x0810_8000 {
        // `ldm`/`pop` with pc in the list.
        step.terminator = always;
    } else if word & 0x0fff_fff0 == 0x079f_f100 {
        // `ldr pc, [pc, rM, lsl #2]`: a table of absolute case addresses.
        step.table = Some(word_table(region, pc, region.start, region.end()));
        step.terminator = always;
    } else if word & 0x0fff_fff0 == 0x008f_f100 {
        // `add pc, pc, rM, lsl #2`: GCC's PIC switch, a table of `b` words
        // (whose targets are case blocks) right after the dispatch.
        step.table = Some(branch_table(region, pc));
        step.terminator = always;
    } else if word & 0x0ff0_fff0 == 0x0080_f000 {
        step.pc_add = always.then_some(((word >> 16) & 0xf) as usize);
        step.terminator = always;
    } else if word & 0x0fef_0000 == 0x028f_0000 || word & 0x0fef_0000 == 0x024f_0000 {
        // `adr rD, label` (`add`/`sub rD, pc, #imm`).
        let imm = (word & 0xff).rotate_right(((word >> 8) & 0xf) * 2);
        let label = if word & 0x0080_0000 != 0 {
            pc.wrapping_add(u64::from(imm))
        } else {
            pc.wrapping_sub(u64::from(imm))
        };
        step.adr = Some((((word >> 12) & 0xf) as usize, label));
    } else if word & 0x0c50_f000 == 0x0410_f000 {
        // `ldr pc, [...]`.
        step.terminator = always;
    } else if word & 0x0f7f_0000 == 0x051f_0000 {
        step.literal = literal(pc, word & 0xfff, word & (1 << 23) != 0, 4);
        if let Some((start, _)) = step.literal {
            step.load = word_at(region, start).map(|value| (((word >> 12) & 0xf) as usize, value));
        }
    } else if word & 0x0ff0_0000 == 0x0300_0000 || word & 0x0ff0_0000 == 0x0340_0000 {
        // `movw`/`movt rD, #imm16`.
        let register = ((word >> 12) & 0xf) as usize;
        let imm = ((word >> 4) & 0xf000) | (word & 0xfff);
        if word & 0x0040_0000 == 0 {
            step.load = Some((register, imm));
        } else {
            step.movt = Some((register, imm));
        }
    } else if word & 0x0fff_0ff0 == 0x008f_0000 {
        // `add rD, pc, rM`.
        step.pc_relative = Some((((word >> 12) & 0xf) as usize, (word & 0xf) as usize, pc));
    } else if word & 0x0ff0_0fff == 0x0080_000f {
        // `add rD, rN, pc`.
        step.pc_relative = Some((
            ((word >> 12) & 0xf) as usize,
            ((word >> 16) & 0xf) as usize,
            pc,
        ));
    } else if word & 0x0f7f_00f0 == 0x014f_00d0 {
        let offset = ((word >> 4) & 0xf0) | (word & 0xf);
        step.literal = literal(pc, offset, word & (1 << 23) != 0, 8);
    } else if word & 0x0f3f_0e00 == 0x0d1f_0a00 {
        let size = if word & 0x100 != 0 { 8 } else { 4 };
        step.literal = literal(pc, (word & 0xff) * 4, word & (1 << 23) != 0, size);
    }
    if word & 0xffff_4000 == 0xe92d_4000 || word == 0xe52d_e004 {
        step.prologue = true;
    }
    Some(step)
}

fn literal(base: u64, offset: u32, up: bool, size: u64) -> Option<(u64, u64)> {
    let start = if up {
        base.checked_add(u64::from(offset))?
    } else {
        base.checked_sub(u64::from(offset))?
    };
    Some((start, start.checked_add(size)?))
}

/// Absolute-address table at `base`: entries continue while they point into
/// the region and do not run into the earliest case target.
fn word_table(region: &Region, base: u64, low: u64, high: u64) -> (Vec<u64>, u64, u64) {
    let mut targets = Vec::new();
    let mut cursor = base;
    let mut limit = high;
    while targets.len() < MAX_TABLE_ENTRIES && cursor + 4 <= limit {
        let Some(word) = word_at(region, cursor) else {
            break;
        };
        let target = u64::from(word) & !1;
        if target < low || target >= high {
            break;
        }
        targets.push(u64::from(word));
        if target > cursor {
            limit = limit.min(target);
        }
        cursor += 4;
    }
    (targets, base, cursor)
}

/// Table of offsets from its own start `base`: entries continue while their
/// targets stay in the region and the table has not reached the earliest
/// case after it.
fn relative_table(region: &Region, base: u64) -> (Vec<u64>, u64, u64) {
    let mut targets = Vec::new();
    let mut cursor = base;
    let mut limit = region.end();
    while targets.len() < MAX_TABLE_ENTRIES && cursor + 4 <= limit {
        let Some(word) = word_at(region, cursor) else {
            break;
        };
        let target = base.wrapping_add(i64::from(word as i32) as u64);
        if target < region.start || target >= region.end() || target & 3 != 0 {
            break;
        }
        targets.push(target);
        if target > cursor {
            limit = limit.min(target);
        }
        cursor += 4;
    }
    (targets, base, cursor)
}

/// Table of unconditional ARM `b` words at `base`.
fn branch_table(region: &Region, base: u64) -> (Vec<u64>, u64, u64) {
    let mut targets = Vec::new();
    let mut cursor = base;
    while targets.len() < MAX_TABLE_ENTRIES {
        let Some(word) = word_at(region, cursor) else {
            break;
        };
        if word >> 24 != 0xea {
            break;
        }
        let offset = sign_extend(word & 0x00ff_ffff, 24) << 2;
        targets.push(cursor.wrapping_add(8).wrapping_add(offset as u64));
        cursor += 4;
    }
    (targets, base, cursor)
}

/// Thumb `tbb`/`tbh` table at `base`: entries continue until the table runs
/// into the earliest case target (cases follow the table).
fn thumb_table(region: &Region, base: u64, halfwords: bool) -> (Vec<u64>, u64, u64) {
    let mut targets = Vec::new();
    let mut cursor = base;
    let mut limit = region.end();
    let width = if halfwords { 2 } else { 1 };
    while targets.len() < MAX_TABLE_ENTRIES && cursor + width <= limit {
        let Some(offset) = usize::try_from(cursor - region.start).ok() else {
            break;
        };
        let entry = if halfwords {
            match region.data.get(offset..offset + 2) {
                Some(bytes) => u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                None => break,
            }
        } else {
            match region.data.get(offset) {
                Some(byte) => u64::from(*byte),
                None => break,
            }
        };
        let target = base + entry * 2;
        if target < cursor + width {
            break;
        }
        targets.push(target);
        limit = limit.min(target);
        cursor += width;
    }
    (targets, base, (cursor + 1) & !1)
}

fn thumb_step(region: &Region, address: u64) -> Option<Step> {
    if address & 1 != 0 {
        return None;
    }
    let hw1 = half_at(region, address)?;
    let pc = address.wrapping_add(4);
    let aligned_pc = pc & !3;
    if hw1 >> 11 < 0x1d {
        let mut step = Step {
            size: 2,
            ..Step::default()
        };
        if hw1 & 0xff00 == 0xbf00 && hw1 & 0xf != 0 {
            step.it_count = 4 - (hw1 & 0xf).trailing_zeros();
        } else if hw1 >> 12 == 0xd && (hw1 >> 8) & 0xf < 0xe {
            let offset = sign_extend(u32::from(hw1 & 0xff), 8) << 1;
            step.branch = Some((pc.wrapping_add(offset as u64), true));
        } else if hw1 >> 11 == 0x1c {
            let offset = sign_extend(u32::from(hw1 & 0x7ff), 11) << 1;
            step.branch = Some((pc.wrapping_add(offset as u64), false));
            step.terminator = true;
        } else if hw1 & 0xf500 == 0xb100 {
            let offset = (u64::from((hw1 >> 9) & 1) << 6) | (u64::from((hw1 >> 3) & 0x1f) << 1);
            step.branch = Some((pc.wrapping_add(offset), true));
        } else if hw1 & 0xff80 == 0x4700 || hw1 & 0xff87 == 0x4687 || hw1 & 0xff00 == 0xbd00 {
            // `bx rM`, `mov pc, rM`, `pop {..., pc}`.
            step.terminator = true;
        } else if hw1 & 0xf800 == 0x4800 {
            step.literal = literal(aligned_pc, u32::from(hw1 & 0xff) * 4, true, 4);
            if let Some((start, _)) = step.literal {
                step.load =
                    word_at(region, start).map(|value| (usize::from((hw1 >> 8) & 7), value));
            }
        } else if hw1 & 0xff78 == 0x4478 {
            // `add rDN, pc`.
            let register = usize::from((hw1 & 7) | ((hw1 >> 4) & 8));
            step.pc_relative = Some((register, register, pc));
        } else if hw1 & 0xff00 == 0xb500 {
            step.prologue = true;
        }
        return Some(step);
    }
    let hw2 = half_at(region, address + 2)?;
    let mut step = Step {
        size: 4,
        ..Step::default()
    };
    if hw1 >> 11 == 0x1e && hw2 & 0x8000 != 0 {
        let s = u32::from((hw1 >> 10) & 1);
        let j1 = u32::from((hw2 >> 13) & 1);
        let j2 = u32::from((hw2 >> 11) & 1);
        let i1 = !(j1 ^ s) & 1;
        let i2 = !(j2 ^ s) & 1;
        let long = (s << 24)
            | (i1 << 23)
            | (i2 << 22)
            | (u32::from(hw1 & 0x3ff) << 12)
            | (u32::from(hw2 & 0x7ff) << 1);
        let long = sign_extend(long, 25);
        match hw2 & 0xd000 {
            0xd000 => step.call = Some(pc.wrapping_add(long as u64) | 1),
            0xc000 if hw2 & 1 == 0 => step.call = Some(aligned_pc.wrapping_add(long as u64)),
            0x9000 => {
                step.branch = Some((pc.wrapping_add(long as u64), false));
                step.terminator = true;
            }
            0x8000 if (hw1 >> 6) & 0xf < 0xe => {
                let short = (s << 20)
                    | (j2 << 19)
                    | (j1 << 18)
                    | (u32::from(hw1 & 0x3f) << 12)
                    | (u32::from(hw2 & 0x7ff) << 1);
                let short = sign_extend(short, 21);
                step.branch = Some((pc.wrapping_add(short as u64), true));
            }
            _ => {}
        }
    } else if hw1 == 0xe8bd && hw2 & 0x8000 != 0 {
        // `pop.w {..., pc}`.
        step.terminator = true;
    } else if hw1 & 0xff70 == 0xf850 && hw2 >> 12 == 0xf {
        // `ldr.w pc, [...]`.
        step.terminator = true;
    } else if hw1 == 0xe8df && hw2 & 0xffe0 == 0xf000 {
        // `tbb`/`tbh [pc, rM]`: the table follows the instruction.
        step.table = Some(thumb_table(region, pc, hw2 & 0x10 != 0));
        step.terminator = true;
    } else if hw1 & 0xff7f == 0xf85f {
        step.literal = literal(aligned_pc, u32::from(hw2 & 0xfff), hw1 & 0x80 != 0, 4);
        if let Some((start, _)) = step.literal {
            step.load = word_at(region, start).map(|value| (usize::from(hw2 >> 12), value));
        }
    } else if hw1 & 0xfb70 == 0xf240 && hw2 & 0x8000 == 0 {
        // `movw`/`movt rD, #imm16` (T3; bit 7 of the first halfword picks
        // `movt`).
        let register = usize::from((hw2 >> 8) & 0xf);
        let imm = (u32::from(hw1 & 0xf) << 12)
            | (u32::from((hw1 >> 10) & 1) << 11)
            | (u32::from((hw2 >> 12) & 7) << 8)
            | u32::from(hw2 & 0xff);
        if hw1 & 0x0080 == 0 {
            step.load = Some((register, imm));
        } else {
            step.movt = Some((register, imm));
        }
    } else if hw1 & 0xff7f == 0xe95f {
        step.literal = literal(aligned_pc, u32::from(hw2 & 0xff) * 4, hw1 & 0x80 != 0, 8);
    } else if hw1 & 0xff3f == 0xed1f && hw2 & 0x0e00 == 0x0a00 {
        let size = if hw2 & 0x100 != 0 { 8 } else { 4 };
        step.literal = literal(aligned_pc, u32::from(hw2 & 0xff) * 4, hw1 & 0x80 != 0, size);
    } else if (hw1 == 0xe92d && hw2 & 0x4000 != 0) || (hw1 == 0xf84d && hw2 == 0xed04) {
        step.prologue = true;
    }
    Some(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str, start: u64, data: Vec<u8>, executable: bool) -> Region {
        Region::new(name, start, data, executable, false)
    }

    fn halves(words: &[u16]) -> Vec<u8> {
        words.iter().flat_map(|half| half.to_le_bytes()).collect()
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn label_tables_need_many_distinct_targets_in_one_gap() {
        let known = [0x1000, 0x9000, 0xa000];
        // 40 labels inside the function at 0x1000, then a function table
        // whose targets each have a start, all in one run of slots.
        let mut slots: Vec<(u64, u64)> =
            (0..40).map(|i| (0x20000 + i * 4, 0x1100 + i * 8)).collect();
        slots.push((0x20000 + 40 * 4, 0x9000));
        slots.push((0x20000 + 41 * 4, 0xa000));
        let labels = label_tables(&slots, 4, &known);
        assert_eq!(labels.len(), 40);
        assert!(!labels.contains(&0x9000));
        // One callback repeated is one function, not a table of labels.
        let repeated: Vec<(u64, u64)> = (0..40).map(|i| (0x30000 + i * 4, 0x1100)).collect();
        assert!(label_tables(&repeated, 4, &known).is_empty());
        // Labels spread over gaps, or slots that are not consecutive, stay.
        let spread: Vec<(u64, u64)> = (0..40).map(|i| (0x30000 + i * 8, 0x1100 + i * 8)).collect();
        assert!(label_tables(&spread, 4, &known).is_empty());
    }

    #[test]
    fn thumb_prologue_after_return_starts_a_function() {
        let code = halves(&[
            0xb510, // 0x1000 push {r4, lr}
            0xbd10, // 0x1002 pop {r4, pc}
            0xb500, // 0x1004 push {lr}: a new function
            0xbd00, // 0x1006 pop {pc}
            0x4770, // 0x1008 bx lr: no prologue, left to other evidence
            0xbf00, // 0x100a nop (alignment)
            0xb538, // 0x100c push {r3, r4, r5, lr}, but a loop head:
            0xd1fd, // 0x100e bne 0x100c
            0xbd38, // 0x1010 pop {r3, r4, r5, pc}
        ]);
        let regions = vec![region(".text", 0x1000, code, true)];
        let found = evidence(Arch::Arm32, &regions, &[], &|_| true);
        assert_eq!(synthesize(&found), vec![0x1000, 0x1004]);
    }

    #[test]
    fn arm_literal_pool_is_not_code() {
        let code = words(&[
            0xe92d_4010, // 0x2000 push {r4, lr}
            0xe59f_0000, // 0x2004 ldr r0, [pc, #0] -> 0x200c
            0xe8bd_8010, // 0x2008 pop {r4, pc}
            0xe92d_4000, // 0x200c pool word that reads as `push {lr}`
            0xe92d_4800, // 0x2010 push {r11, lr}: the next function
            0xe12f_ff1e, // 0x2014 bx lr
        ]);
        let regions = vec![region(".text", 0x2000, code, true)];
        let found = evidence(Arch::Arm32, &regions, &[], &|_| false);
        assert_eq!(found.data, vec![(0x200c, 0x2010)]);
        assert_eq!(synthesize(&found), vec![0x2000, 0x2010]);
    }

    #[test]
    fn calls_and_pointers_need_the_right_mode() {
        let code = words(&[
            0xeb00_0002, // 0x3000 bl 0x3010 (ARM -> ARM)
            0xfa00_0002, // 0x3004 blx 0x3014 (ARM -> Thumb), but 0x3014 is ARM
            0xe12f_ff1e, // 0x3008 bx lr
            0xe320_f000, // 0x300c nop
            0xe12f_ff1e, // 0x3010 bx lr
            0xe12f_ff1e, // 0x3014 bx lr
        ]);
        let regions = vec![region(".text", 0x3000, code, true)];
        let found = evidence(Arch::Arm32, &regions, &[0x3008, 0x9000], &|_| false);
        assert_eq!(found.calls, vec![0x3010]);
        assert_eq!(found.pointers, vec![0x3008]);
    }

    #[test]
    fn table_entries_win_and_ends_follow_the_next_start() {
        // `.eh_frame`: exact extents, so a start inside one is dropped.
        assert_eq!(
            merge(&[(0x1000, 0x1100)], &[0x1050, 0x1100, 0x1200], true),
            vec![(0x1000, 0x1100), (0x1100, 0x1200), (0x1200, 0)]
        );
        // `.ARM.exidx`: ends are only the next entry, so they are recomputed.
        assert_eq!(
            merge(&[(0x1000, 0x1200), (0x1200, 0)], &[0x1050, 0x1200], false),
            vec![(0x1000, 0x1050), (0x1050, 0x1200), (0x1200, 0)]
        );
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for round in 0..64 {
            let length = 1 + (round * 997) % 8192;
            let data: Vec<u8> = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let regions = vec![
                region(".text", 0x1000 + round as u64, data.clone(), true),
                region(".data", 0x20_0000, data.clone(), false),
            ];
            let pointers: Vec<u64> = data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|w| u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]])))
                .collect();
            for arch in [Arch::Arm32, Arch::Thumb, Arch::X64, Arch::Arm64] {
                for thumb in [false, true] {
                    let found = evidence(arch, &regions, &pointers, &|_| thumb);
                    let starts = synthesize(&found);
                    let _ = merge(&[(0x1000, 0x1100)], &starts, true);
                    let _ = merge(&[(0x1000, 0)], &starts, false);
                }
            }
        }
    }
}
