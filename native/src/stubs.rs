//! Recognise ARM import stubs and veneers from their raw encodings.
//!
//! A call into a PLT stub or a linker veneer must resolve to the function the
//! stub reaches, not to the stub's own address: the stub is placed by the
//! linker, so its address differs per build, while the import name it loads
//! survives stripping and is the same on every architecture. The x86-64
//! normalizer reads `jmp [rip+slot]` stubs directly; the ARM stubs need two to
//! four instructions to form the slot address, so they are matched here on
//! their fixed encodings. Only the scratch registers the ABIs reserve for
//! veneers (`x16`/`x17` on AArch64, `ip` on ARM32) are accepted, so ordinary
//! code that happens to start with an address computation is never mistaken
//! for a stub.

/// Where a stub sends control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubExit {
    /// The stub jumps through this pointer slot (GOT entry): an import when the
    /// slot carries a relocation, otherwise read the pointer.
    Slot(u64),
    /// The stub jumps straight to this address (a range-extension veneer).
    Direct(u64),
}

/// Longest stub the matchers read, in bytes.
pub const MAX_STUB_BYTES: usize = 20;

fn words(data: &[u8]) -> Vec<u32> {
    data.as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// AArch64 PLT entries and veneers (lld and GNU ld forms, with optional BTI).
///
/// * `adrp x16, P; ldr x17, [x16, #o]; add x16, x16, #o; br x17` (PLT)
/// * `adrp x16, P; add x16, x16, #o; br x16` (range-extension veneer)
/// * `ldr x16, #literal; br x16` (absolute veneer; the literal holds the target)
pub fn arm64_stub(addr: u64, data: &[u8]) -> Option<StubExit> {
    let all = words(data);
    let mut index = 0usize;
    let mut pc = addr;
    // `bti c` / `bti j` / `bti jc` land on BTI-enabled PLTs.
    if all
        .first()
        .is_some_and(|word| word & 0xFFFF_FF3F == 0xD503_241F)
    {
        index = 1;
        pc += 4;
    }
    let rest = &all[index.min(all.len())..];
    let first = *rest.first()?;
    if first & 0xFF00_001F == 0x5800_0010 {
        // ldr x16, #imm19*4
        if rest.get(1) != Some(&0xD61F_0200) {
            return None;
        }
        let offset = sign_extend(u64::from((first >> 5) & 0x7FFFF), 19) * 4;
        return Some(StubExit::Slot(pc.wrapping_add_signed(offset)));
    }
    if first & 0x9F00_001F != 0x9000_0010 {
        return None;
    }
    let immlo = u64::from((first >> 29) & 0x3);
    let immhi = u64::from((first >> 5) & 0x7FFFF);
    let page = (pc & !0xFFF).wrapping_add_signed(sign_extend((immhi << 2) | immlo, 21) << 12);
    let second = *rest.get(1)?;
    if second & 0xFFC0_03FF == 0xF940_0211 {
        // ldr x17, [x16, #imm12*8]; the optional `add x16` only feeds the
        // lazy resolver.
        let slot = page.wrapping_add(u64::from((second >> 10) & 0xFFF) * 8);
        let mut cursor = 2;
        if rest
            .get(cursor)
            .is_some_and(|word| word & 0xFF80_03FF == 0x9100_0210)
        {
            cursor += 1;
        }
        return (rest.get(cursor) == Some(&0xD61F_0220)).then_some(StubExit::Slot(slot));
    }
    if second & 0xFF80_03FF == 0x9100_0210 && rest.get(2) == Some(&0xD61F_0200) {
        let shift = if second & (1 << 22) != 0 { 12 } else { 0 };
        let offset = u64::from((second >> 10) & 0xFFF) << shift;
        return Some(StubExit::Direct(page.wrapping_add(offset)));
    }
    None
}

fn arm_immediate(word: u32) -> u64 {
    let rotate = ((word >> 8) & 0xF) * 2;
    u64::from((word & 0xFF).rotate_right(rotate))
}

/// ARM32 PLT entries and veneers in ARM state.
///
/// * `add ip, pc, #A; add ip, ip, #B; [add ip, ip, #C;] ldr pc, [ip, #D]!`
///   (GNU ld and lld short and long PLT entries)
/// * `ldr ip, L; add ip, ip, pc; ldr pc, [ip]; L: .word off` (lld long PLT)
/// * `ldr pc, [pc, #-4]; .word target` (absolute veneer)
/// * `movw ip, #lo; movt ip, #hi; bx ip` (lld ARM thunk)
///
/// A Thumb caller may reach the ARM entry through `bx pc; nop`, which is
/// skipped. Matching does not depend on the per-address mode: these word
/// sequences are not plausible Thumb code.
pub fn arm32_stub(addr: u64, data: &[u8]) -> Option<StubExit> {
    let mut addr = addr;
    let mut data = data;
    // `bx pc; nop` (0x4778 0x46c0): Thumb-to-ARM switch in front of a PLT.
    if data.len() >= 4 && data[..4] == [0x78, 0x47, 0xC0, 0x46] {
        addr += 4;
        data = &data[4..];
    }
    let all = words(data);
    let first = *all.first()?;
    let mask = 0xFFFF_FFFF_u64;
    if first == 0xE51F_F004 {
        return Some(StubExit::Slot((addr + 4) & mask));
    }
    if first == 0xE59F_C004 && all.get(1) == Some(&0xE08C_C00F) && all.get(2) == Some(&0xE59C_F000)
    {
        let offset = u64::from(*all.get(3)?);
        return Some(StubExit::Slot((addr + 4 + 8).wrapping_add(offset) & mask));
    }
    if first & 0xFFF0_F000 == 0xE300_C000 {
        let second = *all.get(1)?;
        if second & 0xFFF0_F000 != 0xE340_C000 {
            return None;
        }
        let low = ((first >> 4) & 0xF000) | (first & 0xFFF);
        let high = ((second >> 4) & 0xF000) | (second & 0xFFF);
        let value = u64::from((high << 16) | low);
        return match (all.get(2), all.get(3)) {
            (Some(&0xE12F_FF1C), _) => Some(StubExit::Direct(value & !1)),
            // lld `__ARMV7PILongThunk_`: `add ip, ip, pc` reads its own
            // address + 8.
            (Some(&0xE08C_C00F), Some(&0xE12F_FF1C)) => Some(StubExit::Direct(
                value.wrapping_add(addr + 8 + 8) & mask & !1,
            )),
            _ => None,
        };
    }
    if let Some(exit) = thumb_thunk(addr, data) {
        return Some(exit);
    }
    if first & 0xFFFF_F000 != 0xE28F_C000 {
        return None;
    }
    let mut value = (addr + 8).wrapping_add(arm_immediate(first));
    for word in all.iter().skip(1).take(3) {
        if word & 0xFFFF_F000 == 0xE28C_C000 {
            value = value.wrapping_add(arm_immediate(*word));
            continue;
        }
        // ldr pc, [ip, #imm12] with or without writeback.
        if word & 0xFFFF_F000 == 0xE5BC_F000 || word & 0xFFFF_F000 == 0xE59C_F000 {
            return Some(StubExit::Slot(
                value.wrapping_add(u64::from(word & 0xFFF)) & mask,
            ));
        }
        return None;
    }
    None
}

/// Whether `name` is a linker-made thunk or veneer symbol (lld
/// `__ThumbV7PILongThunk_f`, `__AArch64ADRPThunk_f`; GNU ld `__f_veneer`,
/// `__f_from_thumb`, `__f_from_arm`). Only unstripped images carry these.
pub fn linker_thunk_name(name: &str) -> bool {
    name.starts_with("__")
        && (name.contains("Thunk_")
            || name.ends_with("_veneer")
            || name.ends_with("_from_thumb")
            || name.ends_with("_from_arm"))
}

/// lld Thumb-2 thunks, which reach a callee (often its PLT entry) that a
/// `b.w`/`bl` cannot, or one in the other mode:
///
/// * `movw ip, #lo; movt ip, #hi; add ip, pc; bx ip` (`__ThumbV7PILongThunk_`;
///   the `add` reads its own address + 4)
/// * `movw ip, #lo; movt ip, #hi; bx ip` (`__Thumbv7ABSLongThunk_`)
fn thumb_thunk(addr: u64, data: &[u8]) -> Option<StubExit> {
    let half = |index: usize| {
        data.get(index * 2..index * 2 + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    // T3 `movw`/`movt` with `rd = ip`: the immediate is i:imm4:imm3:imm8.
    let immediate = |hw1: u16, hw2: u16| {
        (u32::from(hw1 & 0xF) << 12)
            | (u32::from((hw1 >> 10) & 1) << 11)
            | (u32::from((hw2 >> 12) & 7) << 8)
            | u32::from(hw2 & 0xFF)
    };
    let (w1, w2, t1, t2) = (half(0)?, half(1)?, half(2)?, half(3)?);
    if w1 & 0xFBF0 != 0xF240 || w2 & 0x8F00 != 0x0C00 {
        return None;
    }
    if t1 & 0xFBF0 != 0xF2C0 || t2 & 0x8F00 != 0x0C00 {
        return None;
    }
    let value = u64::from((immediate(t1, t2) << 16) | immediate(w1, w2));
    match (half(4)?, half(5)) {
        (0x4760, _) => Some(StubExit::Direct(value & !1)),
        (0x44FC, Some(0x4760)) => Some(StubExit::Direct(
            value.wrapping_add(addr + 8 + 4) & 0xFFFF_FFFF & !1,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn arm64_plt_entry_resolves_its_got_slot() {
        // lld: lua_type@plt at 0x51650 loads 0x73000 + 0x4c0.
        let data = bytes(&[0xD000_0110, 0xF942_6211, 0x9113_0210, 0xD61F_0220]);
        assert_eq!(arm64_stub(0x51650, &data), Some(StubExit::Slot(0x734C0)));
    }

    #[test]
    fn arm64_bti_prefix_and_veneers() {
        let plt = bytes(&[0xD503_245F, 0xD000_0110, 0xF942_6211, 0xD61F_0220]);
        assert_eq!(arm64_stub(0x5164C, &plt), Some(StubExit::Slot(0x734C0)));
        let veneer = bytes(&[0x9000_0010, 0x9100_4210, 0xD61F_0200]);
        assert_eq!(arm64_stub(0x1000, &veneer), Some(StubExit::Direct(0x1010)));
        let literal = bytes(&[0x5800_0050, 0xD61F_0200]);
        assert_eq!(arm64_stub(0x1000, &literal), Some(StubExit::Slot(0x1008)));
    }

    #[test]
    fn arm64_ordinary_code_is_not_a_stub() {
        // adrp x0 (not x16) followed by a load.
        let data = bytes(&[0xD000_0100, 0xF942_6000, 0xD65F_03C0]);
        assert_eq!(arm64_stub(0x1000, &data), None);
    }

    #[test]
    fn arm32_plt_entry_resolves_its_got_slot() {
        // luaL_addvalue@plt at 0x37f30 in the Thumb build: ARM-state entry.
        let data = bytes(&[0xE28F_C600, 0xE28C_CA21, 0xE5BC_F34C]);
        // pc+8 = 0x37f38; + 0 + 0x21000 + 0x34c.
        assert_eq!(arm32_stub(0x37F30, &data), Some(StubExit::Slot(0x59284)));
    }

    #[test]
    fn arm32_veneers_and_thumb_prefix() {
        let absolute = bytes(&[0xE51F_F004, 0x0001_2345]);
        assert_eq!(arm32_stub(0x1000, &absolute), Some(StubExit::Slot(0x1004)));
        let thunk = bytes(&[0xE301_C234, 0xE340_C005, 0xE12F_FF1C]);
        assert_eq!(arm32_stub(0x1000, &thunk), Some(StubExit::Direct(0x5_1234)));
        let mut prefixed = vec![0x78, 0x47, 0xC0, 0x46];
        prefixed.extend(bytes(&[0xE28F_C600, 0xE28C_CA21, 0xE5BC_F34C]));
        assert_eq!(
            arm32_stub(0x37F2C, &prefixed),
            Some(StubExit::Slot(0x59284))
        );
    }

    fn halves(halfwords: &[u16]) -> Vec<u8> {
        halfwords
            .iter()
            .flat_map(|half| half.to_le_bytes())
            .collect()
    }

    #[test]
    fn thumb_lld_thunks_resolve_their_target() {
        // __ThumbV7PILongThunk_cJSON_DetachItemViaPointer at 0x1495c in
        // thumb/clang-Os/cjson.so (lld): 0x208 + 0x14968 (pc of the add) is
        // the PLT entry at 0x14b70.
        let pi = halves(&[0xF240, 0x2C08, 0xF2C0, 0x0C00, 0x44FC, 0x4760]);
        assert_eq!(arm32_stub(0x1495C, &pi), Some(StubExit::Direct(0x14B70)));
        let absolute = halves(&[0xF241, 0x2C35, 0xF2C0, 0x0C05, 0x4760]);
        assert_eq!(
            arm32_stub(0x1000, &absolute),
            Some(StubExit::Direct(0x5_1234))
        );
        // ARM `__ARMV7PILongThunk_`: movw ip; movt ip; add ip, ip, pc; bx ip.
        let arm = bytes(&[0xE300_C100, 0xE340_C000, 0xE08C_C00F, 0xE12F_FF1C]);
        assert_eq!(arm32_stub(0x2000, &arm), Some(StubExit::Direct(0x2110)));
    }

    #[test]
    fn thumb_address_computation_into_another_register_is_not_a_thunk() {
        // movw r0; movt r0; add r0, pc; bx r0
        let code = halves(&[0xF240, 0x2008, 0xF2C0, 0x0000, 0x4478, 0x4700]);
        assert_eq!(arm32_stub(0x1000, &code), None);
        assert!(linker_thunk_name("__ThumbV7PILongThunk_memcpy"));
        assert!(!linker_thunk_name("__aeabi_idiv"));
    }

    #[test]
    fn arm32_ordinary_code_is_not_a_stub() {
        // push {r4, lr}; add r4, pc, #8
        let data = bytes(&[0xE92D_4010, 0xE28F_4008]);
        assert_eq!(arm32_stub(0x1000, &data), None);
        assert_eq!(arm32_stub(0x1000, &[0x00, 0x01]), None);
    }
}
