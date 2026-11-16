//! ARM versus Thumb mode for ARM32 images whose `.symtab` was stripped.
//!
//! With symbols, the low bit of each `STT_FUNC` value gives a function's mode.
//! `strip --strip-all` removes `.symtab` and with it every local function and
//! the `$a`/`$t`/`$d` mapping symbols, so the mode has to come from what the
//! loader still needs, plus the bytes themselves. Measured on the real corpus
//! (clang + lld and gcc + GNU ld, `-marm` and `-mthumb`, O0/O2/Os):
//!
//! - `.dynsym` function values keep the Thumb bit: 100% agreement, ~24% of
//!   functions.
//! - `R_ARM_RELATIVE` slots that point into code (function-pointer tables,
//!   init arrays) keep the Thumb bit: 100% agreement, ~11% of functions.
//! - `.ARM.exidx` prel31 targets never carry the Thumb bit (both linkers clear
//!   it, and gcc builds without unwind tables have almost no entries), so they
//!   are no mode evidence and are not used here.
//! - Direct calls: from ARM code `bl` stays in ARM and `blx imm` switches to
//!   Thumb; from Thumb code `bl` stays in Thumb and `blx imm` switches to ARM.
//!   These reach local functions no table names.
//! - Condition field: ARM code executes almost everything unconditionally, so
//!   at least 74% of its aligned words have condition `AL` (0xE) in bits
//!   28-31, while the same bits of Thumb code are 0xE in at most 18% of words.
//!   This separates every executable section in the corpus, including the
//!   ARM-mode `.plt`, `.init`, and `.fini` of Thumb images.
//!
//! An address takes the mode of the nearest mark at or before it in its
//! region; before the first mark, the region's condition-field vote decides.
//! Call targets are only accepted when the condition-field vote over the
//! target's first words agrees with the mode the call implies, so a literal
//! pool word that happens to decode as a call cannot flip a function.
//!
//! The image is untrusted (AGENTS.md rule 8): sweeps are linear, capped in
//! bytes, and every read is bounds-checked; the mark list is capped too.

use std::collections::BTreeMap;

use crate::source::Region;

/// Upper bound on mode marks kept for one image.
pub const MAX_MODE_MARKS: usize = 1 << 20;
/// Upper bound on bytes examined by all call-site sweeps of one image.
pub const MAX_SWEEP_BYTES: usize = 64 << 20;
/// Upper bound on words counted by one region's condition-field vote.
const MAX_VOTE_WORDS: usize = 1 << 20;
/// Words a call target's local condition-field vote looks at.
const TARGET_VOTE_WORDS: usize = 16;
/// Call-site sweep passes: the second one decodes code that the first one
/// discovered to be in the other mode.
const SWEEP_PASSES: usize = 2;

/// Per-address instruction-set state for a stripped ARM32 image.
#[derive(Debug, Clone, Default)]
pub struct ModeMap {
    /// `(start, end, thumb)` per executable region, the region-wide vote.
    regions: Vec<(u64, u64, bool)>,
    /// `(address, thumb)`, sorted by address, unique.
    marks: Vec<(u64, bool)>,
}

impl ModeMap {
    /// Build the map from `regions` and exact pointers to code whose low bit
    /// encodes the mode (dynamic symbols, relocated function pointers).
    pub fn build(regions: &[Region], pointers: &[u64]) -> ModeMap {
        let mut code: Vec<&Region> = regions.iter().filter(|r| r.executable).collect();
        code.sort_by_key(|region| region.start);
        let votes: Vec<(u64, u64, bool)> = code
            .iter()
            .map(|region| {
                (
                    region.start,
                    region.end(),
                    !mostly_arm(&region.data, MAX_VOTE_WORDS),
                )
            })
            .collect();
        let in_code = |address: u64| {
            votes
                .iter()
                .any(|(start, end, _)| *start <= address && address < *end)
        };

        let mut pointers = pointers.to_vec();
        pointers.sort_unstable();
        let mut exact: BTreeMap<u64, bool> = BTreeMap::new();
        for pointer in &pointers {
            let address = pointer & !1;
            if !in_code(address) || exact.len() >= MAX_MODE_MARKS {
                continue;
            }
            // GCC's computed-goto tables (`&&label`, lua's `luaV_execute`
            // dispatch) are relocated like function pointers, but a label
            // address never carries the Thumb bit. An even pointer into Thumb
            // code therefore claims ARM mode for a label inside a Thumb
            // function; it is believed only when the target is word-aligned
            // and its own words vote ARM, as a call target must.
            let claims_arm = pointer & 1 == 0;
            let region_thumb = votes
                .iter()
                .find(|(start, end, _)| *start <= address && address < *end)
                .is_some_and(|(_, _, thumb)| *thumb);
            if claims_arm && region_thumb {
                let local_arm = code
                    .iter()
                    .find(|r| r.start <= address && address < r.end())
                    .is_some_and(|region| {
                        let offset = (address - region.start) as usize;
                        mostly_arm(&region.data[offset..], TARGET_VOTE_WORDS)
                    });
                if address & 3 != 0 || !local_arm {
                    continue;
                }
            }
            // A table naming one address in both modes is malformed; the
            // lower pointer (ARM) wins, deterministically.
            exact.entry(address).or_insert(pointer & 1 != 0);
        }

        let mut map = ModeMap {
            regions: votes.clone(),
            marks: exact.iter().map(|(a, t)| (*a, *t)).collect(),
        };
        let mut budget = MAX_SWEEP_BYTES;
        for _ in 0..SWEEP_PASSES {
            let mut calls: BTreeMap<u64, (u32, u32)> = BTreeMap::new();
            for region in &code {
                map.sweep(region, &mut budget, &mut calls);
            }
            let mut marks = exact.clone();
            for (target, (arm, thumb)) in calls {
                if marks.len() >= MAX_MODE_MARKS {
                    break;
                }
                if marks.contains_key(&target) || arm == thumb {
                    continue;
                }
                let wants_thumb = thumb > arm;
                let Some(region) = code.iter().find(|r| r.start <= target && target < r.end())
                else {
                    continue;
                };
                let offset = (target - region.start) as usize;
                if mostly_arm(&region.data[offset..], TARGET_VOTE_WORDS) == wants_thumb {
                    continue;
                }
                marks.insert(target, wants_thumb);
            }
            map.marks = marks.into_iter().collect();
        }
        map
    }

    /// Whether `addr` decodes as Thumb.
    pub fn is_thumb(&self, addr: u64) -> bool {
        let Some(&(start, end, default)) = self
            .regions
            .iter()
            .find(|(start, end, _)| *start <= addr && addr < *end)
        else {
            return false;
        };
        let index = self.marks.partition_point(|(mark, _)| *mark <= addr);
        match index.checked_sub(1).map(|i| self.marks[i]) {
            Some((mark, thumb)) if mark >= start && mark < end => thumb,
            _ => default,
        }
    }

    /// Collect direct-call targets from `region`, decoding each stretch in the
    /// mode the current map gives it.
    fn sweep(&self, region: &Region, budget: &mut usize, calls: &mut BTreeMap<u64, (u32, u32)>) {
        let mut cuts: Vec<u64> = vec![region.start];
        let first = self.marks.partition_point(|(mark, _)| *mark < region.start);
        cuts.extend(
            self.marks[first..]
                .iter()
                .map(|(mark, _)| *mark)
                .take_while(|mark| *mark < region.end()),
        );
        cuts.dedup();
        for (index, start) in cuts.iter().enumerate() {
            let end = cuts.get(index + 1).copied().unwrap_or(region.end());
            let length = (end - start) as usize;
            if *budget < length {
                return;
            }
            *budget -= length;
            let offset = (start - region.start) as usize;
            let bytes = &region.data[offset..offset + length];
            let mut record = |target: u64, thumb: bool| {
                if self.in_code(target) {
                    let entry = calls.entry(target).or_insert((0, 0));
                    if thumb {
                        entry.1 = entry.1.saturating_add(1);
                    } else {
                        entry.0 = entry.0.saturating_add(1);
                    }
                }
            };
            if self.is_thumb(*start) {
                thumb_calls(bytes, *start, &mut record);
            } else {
                arm_calls(bytes, *start, &mut record);
            }
        }
    }

    fn in_code(&self, address: u64) -> bool {
        self.regions
            .iter()
            .any(|(start, end, _)| *start <= address && address < *end)
    }
}

/// Whether at least half of the first `limit` aligned words of `bytes` carry
/// the ARM `AL` condition. Empty input counts as ARM, the ARM32 default.
fn mostly_arm(bytes: &[u8], limit: usize) -> bool {
    let mut total = 0usize;
    let mut always = 0usize;
    for word in bytes.as_chunks::<4>().0.iter().take(limit) {
        total += 1;
        if word[3] >> 4 == 0xE {
            always += 1;
        }
    }
    always * 2 >= total
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    i64::from(((value << shift) as i32) >> shift)
}

/// ARM `bl` (same mode) and `blx imm` (to Thumb) in word-aligned `bytes`.
fn arm_calls(bytes: &[u8], base: u64, record: &mut impl FnMut(u64, bool)) {
    let skip = ((4 - (base & 3)) & 3) as usize;
    let Some(aligned) = bytes.get(skip..) else {
        return;
    };
    for (index, word) in aligned.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        let pc = (base + skip as u64 + index as u64 * 4).wrapping_add(8);
        let offset = sign_extend(word & 0x00ff_ffff, 24) << 2;
        if word >> 25 == 0x7d {
            let half = u64::from((word >> 24) & 1) << 1;
            record(pc.wrapping_add(offset as u64).wrapping_add(half), true);
        } else if word >> 28 != 0xf && (word >> 24) & 0xf == 0xb {
            record(pc.wrapping_add(offset as u64), false);
        }
    }
}

/// Thumb-2 `bl` (same mode) and `blx imm` (to ARM) in halfword-aligned `bytes`.
fn thumb_calls(bytes: &[u8], base: u64, record: &mut impl FnMut(u64, bool)) {
    let mut pos = (base & 1) as usize;
    while pos + 2 <= bytes.len() {
        let hw1 = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
        if hw1 >> 11 < 0x1d {
            pos += 2;
            continue;
        }
        let Some(second) = bytes.get(pos + 2..pos + 4) else {
            break;
        };
        let hw2 = u16::from_le_bytes([second[0], second[1]]);
        if hw1 >> 11 == 0x1e && hw2 & 0xc000 == 0xc000 {
            let s = u32::from(hw1 >> 10) & 1;
            let j1 = u32::from(hw2 >> 13) & 1;
            let j2 = u32::from(hw2 >> 11) & 1;
            let i1 = !(j1 ^ s) & 1;
            let i2 = !(j2 ^ s) & 1;
            let high = (s << 24) | (i1 << 23) | (i2 << 22) | (u32::from(hw1 & 0x3ff) << 12);
            let pc = (base + pos as u64).wrapping_add(4);
            if hw2 & 0x1000 != 0 {
                let offset = sign_extend(high | (u32::from(hw2 & 0x7ff) << 1), 25);
                record(pc.wrapping_add(offset as u64), true);
            } else if hw2 & 1 == 0 {
                let offset = sign_extend(high | (u32::from(hw2 & 0x7fe) << 1), 25);
                record((pc & !3).wrapping_add(offset as u64), false);
            }
        }
        pos += 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(start: u64, data: Vec<u8>) -> Region {
        Region::new(".text", start, data, true, false)
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn halfwords(halfwords: &[u16]) -> Vec<u8> {
        halfwords.iter().flat_map(|h| h.to_le_bytes()).collect()
    }

    #[test]
    fn condition_vote_tells_arm_from_thumb() {
        // push {r4, lr}; mov r4, r0; pop {r4, pc}
        let arm = words(&[0xe92d_4010, 0xe1a0_4000, 0xe8bd_8010]);
        // push {r4, lr}; mov r4, r0; pop {r4, pc}; nop
        let thumb = halfwords(&[0xb510, 0x4604, 0xbd10, 0xbf00]);
        assert!(!ModeMap::build(&[code(0x1000, arm)], &[]).is_thumb(0x1000));
        assert!(ModeMap::build(&[code(0x1000, thumb)], &[]).is_thumb(0x1000));
    }

    #[test]
    fn pointer_low_bit_marks_thumb_until_the_next_mark() {
        let data = words(&[0xe1a0_0000; 64]);
        let map = ModeMap::build(&[code(0x1000, data)], &[0x1041, 0x1080]);
        assert!(!map.is_thumb(0x1000));
        assert!(map.is_thumb(0x1040));
        assert!(map.is_thumb(0x107e));
        assert!(!map.is_thumb(0x1080));
        assert!(!map.is_thumb(0x9000), "outside code");
    }

    #[test]
    fn even_pointer_into_thumb_code_is_a_label_not_arm() {
        let data = halfwords(&[0xb510, 0x4604, 0xbd10, 0xbf00].repeat(16));
        // 0x1022 is not word-aligned; 0x1040 is, but its words vote Thumb.
        let map = ModeMap::build(&[code(0x1000, data)], &[0x1001, 0x1022, 0x1040]);
        assert!(map.is_thumb(0x1022));
        assert!(map.is_thumb(0x1040));
    }

    #[test]
    fn arm_blx_marks_a_thumb_callee() {
        // ARM code at 0x1000: blx +0x38 (-> 0x1040 Thumb), then movs.
        let mut data = words(&[0xfa00_000e]);
        data.extend(words(&[0xe1a0_0000; 15]));
        data.extend(halfwords(&[0xb510, 0x4604, 0xbd10, 0xbf00].repeat(2)));
        let map = ModeMap::build(&[code(0x1000, data)], &[]);
        assert!(!map.is_thumb(0x1000));
        assert!(map.is_thumb(0x1040));
    }

    #[test]
    fn thumb_blx_marks_an_arm_callee() {
        // Thumb code at 0x1000: blx to 0x1040 (ARM), then Thumb padding.
        let mut data = halfwords(&[0xf000, 0xe81e]);
        data.extend(halfwords(&[0xbf00; 30]));
        data.extend(words(&[0xe1a0_0000; 16]));
        let map = ModeMap::build(&[code(0x1000, data)], &[0x1001]);
        assert!(map.is_thumb(0x1000));
        assert!(!map.is_thumb(0x1040));
    }

    #[test]
    fn random_and_truncated_bytes_never_panic() {
        let mut state = 0x9e37_79b9u32;
        for size in [0usize, 1, 2, 3, 5, 7, 64, 4097, 1 << 16] {
            let data: Vec<u8> = (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let pointers: Vec<u64> = (0..32u64).map(|i| 0x1000 + i * 37).collect();
            let regions = vec![code(0x1000, data.clone()), code(0x1003 + size as u64, data)];
            let map = ModeMap::build(&regions, &pointers);
            let again = ModeMap::build(&regions, &pointers);
            for addr in (0x0ff0..0x1000 + 2 * size as u64 + 16).step_by(7) {
                assert_eq!(map.is_thumb(addr), again.is_thumb(addr), "deterministic");
            }
        }
    }
}
