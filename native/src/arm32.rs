//! ARM32 and Thumb decoding and normalization for the native port.
//!
//! The rules mirror `core/normalize.py` (`_arm32`, `_arm32_materialize`,
//! `_arm32_literal_load`, `_arm32_pc_add`, `_arm32_class`). yaxpeax-arm plays
//! the part of Capstone, so the projection below reads the same facts the
//! reference reads off `CsInsn`: the stripped condition suffix, the PC-relative
//! literal pool, and the `movw`/`movt` chain. Decoder differences handled here
//! rather than downstream:
//!
//! * One decoder serves both modes, so `is_thumb` at the block start picks the
//!   mode for every instruction in that block.
//! * Capstone reports absolute branch targets and `adr` values; yaxpeax
//!   reports pc-relative deltas, which are rebased onto addresses here.
//! * `[pc, #imm]` literal loads arrive as an offset from the decoded PC value,
//!   which differs between ARM (`addr + 8`) and Thumb (`(addr + 4) & ~3`).

use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand};

use crate::normalize::{
    canonical_const, sorted_unique, ArmState, DataRef, Insn, Kind, Normalizer, OpClass,
    PendingValue, MASK32,
};
use crate::source::ByteSource;

const PC: u8 = 15;
const LR: u8 = 14;
const SP: u8 = 13;

const ARM32_IGNORED: &[&str] = &["nop", "hint"];
const ARM32_TRAP: &[&str] = &["udf", "svc"];
const ARM32_MUL: &[&str] = &[
    "mul", "mla", "mls", "umull", "umlal", "smull", "smlal", "sdiv", "udiv",
];
const ARM32_LOGIC: &[&str] = &[
    "and", "orr", "eor", "bic", "lsl", "lsr", "asr", "ror", "rrx", "clz", "rbit", "pkhbt", "pkhtb",
];
const ARM32_CMP: &[&str] = &["cmp", "cmn", "tst", "teq"];
const ARM32_ARITH: &[&str] = &["add", "sub", "adc", "sbc", "rsb", "qadd", "qsub"];
const ARM32_MOVE: &[&str] = &[
    "mov", "mvn", "adr", "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw", "uxtah", "sxtab", "rev",
    "rev16", "revsh", "rbit", "sel", "clz", "bfc", "bfi", "sbfx", "ubfx",
];
const ARM32_LOAD_PREFIXES: &[&str] = &["ldr", "ldm", "ldrex", "ldrd"];
const ARM32_STORE_PREFIXES: &[&str] = &["str", "stm", "strex", "strd"];
const ARM32_BRANCH_TABLE: &[&str] = &["tbb", "tbh"];
const ARM32_CONDITIONAL_JUMPS: &[&str] = &["cbz", "cbnz"];

fn condition_suffix(condition: ConditionCode) -> Option<&'static str> {
    match condition {
        ConditionCode::EQ => Some("eq"),
        ConditionCode::NE => Some("ne"),
        ConditionCode::HS => Some("hs"),
        ConditionCode::LO => Some("lo"),
        ConditionCode::MI => Some("mi"),
        ConditionCode::PL => Some("pl"),
        ConditionCode::VS => Some("vs"),
        ConditionCode::VC => Some("vc"),
        ConditionCode::HI => Some("hi"),
        ConditionCode::LS => Some("ls"),
        ConditionCode::GE => Some("ge"),
        ConditionCode::LT => Some("lt"),
        ConditionCode::GT => Some("gt"),
        ConditionCode::LE => Some("le"),
        _ => None,
    }
}

/// Strip the Thumb width marker and the condition suffix from the mnemonic.
///
/// The suffix is removed only when the decoder reports a condition, so
/// mnemonics that merely end in a condition pair (`umlal`, `mls`) survive.
fn arm32_mnemonic(raw: &Instruction) -> (String, bool) {
    let text = raw.to_string();
    let mut mnemonic = text
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    for marker in [".w", ".n"] {
        if let Some(stripped) = mnemonic.strip_suffix(marker) {
            mnemonic = stripped.to_owned();
        }
    }
    if let Some(suffix) = condition_suffix(raw.condition) {
        if let Some(stripped) = mnemonic.strip_suffix(suffix) {
            return (stripped.to_owned(), true);
        }
    }
    (mnemonic, false)
}

fn reg_of(operand: &Operand) -> Option<u8> {
    match operand {
        Operand::Reg(register) | Operand::RegWBack(register, _) => Some(register.number()),
        _ => None,
    }
}

/// Base register and byte offset of a memory operand.
fn mem_of(operand: &Operand) -> Option<(u8, i64)> {
    match operand {
        Operand::RegDeref(base) => Some((base.number(), 0)),
        Operand::RegDerefPostindexOffset(base, offset, add, _)
        | Operand::RegDerefPreindexOffset(base, offset, add, _) => {
            let offset = i64::from(*offset);
            Some((base.number(), if *add { offset } else { -offset }))
        }
        _ => None,
    }
}

fn imm_of(operand: &Operand) -> Option<u64> {
    match operand {
        Operand::Imm12(value) => Some(u64::from(*value)),
        Operand::Imm32(value) => Some(u64::from(*value)),
        _ => None,
    }
}

fn reg_list(operand: &Operand) -> Option<u16> {
    match operand {
        Operand::RegList(mask) => Some(*mask),
        _ => None,
    }
}

/// PC value the instruction sees, per the ARM and Thumb pipeline rules.
/// Is this the ARM/Thumb `movw`/`movt` (move wide immediate) encoding?
///
/// yaxpeax decodes `movw` as a plain `MOV` with an immediate, but Capstone — and
/// therefore the reference — names the width, and the two ends of a
/// `movw`/`movt` pair materialise one constant instead of two.
fn move_wide(thumb: bool, word: u32) -> Option<&'static str> {
    if thumb {
        let first = (word & 0xFFFF) as u16;
        return match first & 0xFBF0 {
            0xF240 => Some("movw"),
            0xF2C0 => Some("movt"),
            _ => None,
        };
    }
    // ARM move-wide immediate: bits 27..20 are 0011 0000 (movw) or
    // 0011 0100 (movt); the data-processing `mov rd, #imm` has 0011 101x.
    match word & 0x0FF0_0000 {
        0x0300_0000 => Some("movw"),
        0x0340_0000 => Some("movt"),
        _ => None,
    }
}

/// Capstone names a shifted register move by the shift (`lsl r0, r0, #4`);
/// yaxpeax keeps it as `mov rd, rm, lsl 4`, so the display carries the alias.
fn shift_alias(text: &str) -> Option<&'static str> {
    text.split([' ', ',', '.']).find_map(|token| match token {
        "lsl" => Some("lsl"),
        "lsr" => Some("lsr"),
        "asr" => Some("asr"),
        "ror" => Some("ror"),
        "rrx" => Some("rrx"),
        _ => None,
    })
}

fn pc_value(addr: u64, thumb: bool) -> u64 {
    if thumb {
        (addr + 4) & !3
    } else {
        addr + 8
    }
}

/// Thumb branch target from the raw halfwords.
///
/// yaxpeax's 16-bit conditional delta does not match the encoding (an `imm8`
/// branch with `imm8 = 5` arrives as 6), so the target is computed here with
/// the architectural `pc + 4 + offset` rule instead. Handles the 16-bit
/// conditional and unconditional forms plus the 32-bit `b.w`/`bl` pair.
fn thumb_branch_target(addr: u64, word: u32, size: usize) -> Option<u64> {
    if size == 2 {
        let hw = (word & 0xFFFF) as u16;
        if hw >> 12 == 0xD && ((hw >> 8) & 0xF) < 0xE {
            let offset = i64::from(hw as i8) * 2;
            return Some(addr.wrapping_add(4).wrapping_add_signed(offset));
        }
        if hw >> 11 == 0b0001_1100 {
            let imm = ((hw & 0x7FF) as i16) << 5 >> 5;
            return Some(addr.wrapping_add(4).wrapping_add_signed(i64::from(imm) * 2));
        }
        // CBZ/CBNZ: forward-only, zero-extended `i:imm5:0`, so the sign rules
        // above do not apply. `i` is bit 9 and the immediate is bits 7..3.
        if hw & 0xF500 == 0xB100 {
            let i = u64::from((hw >> 9) & 1);
            let imm5 = u64::from((hw >> 3) & 0x1F);
            return Some(addr.wrapping_add(4).wrapping_add((i << 6) | (imm5 << 1)));
        }
        return None;
    }
    if size != 4 || (word & 0xFFFF) >> 11 != 0b11110 {
        return None;
    }
    let hw1 = word & 0xFFFF;
    let hw2 = word >> 16;
    let s = ((hw1 >> 10) & 1) as i32;
    let j1 = ((hw2 >> 13) & 1) as i32;
    let j2 = ((hw2 >> 11) & 1) as i32;
    let i1 = (j1 ^ s) ^ 1;
    let i2 = (j2 ^ s) ^ 1;
    let imm10 = (hw1 & 0x3FF) as i32;
    let imm11 = (hw2 & 0x7FF) as i32;
    let offset = ((s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)) << 7 >> 7;
    Some(addr.wrapping_add(4).wrapping_add_signed(i64::from(offset)))
}

fn branch_target(addr: u64, thumb: bool, word: u32, size: usize, ops: &[&Operand]) -> Option<u64> {
    if thumb {
        if let Some(target) = thumb_branch_target(addr, word, size) {
            return Some(target);
        }
    }
    // yaxpeax reports the branch delta in instruction units relative to the
    // instruction address (its display shows the same value Capstone reports as
    // an absolute target minus this address), so ARM (4-byte) and Thumb
    // (2-byte) branches scale differently and no pipeline offset is added.
    for operand in ops {
        match operand {
            Operand::BranchOffset(delta) => {
                return Some(addr.wrapping_add_signed(i64::from(*delta) * 4));
            }
            Operand::BranchThumbOffset(delta) => {
                return Some(addr.wrapping_add_signed(i64::from(*delta) * 2));
            }
            _ => {}
        }
    }
    ops.iter().find_map(|operand| imm_of(operand))
}

/// `adr` reports an address directly, or a pc-relative delta to rebase.
fn adr_target(addr: u64, thumb: bool, word: u32, size: usize, ops: &[&Operand]) -> Option<u64> {
    branch_target(addr, thumb, word, size, ops)
}

fn moves_pc(ops: &[&Operand]) -> bool {
    ops.len() >= 2 && reg_of(ops[0]) == Some(PC) && reg_of(ops[1]) == Some(LR)
}

fn touches_stack_pointer(ops: &[&Operand]) -> bool {
    ops.iter().any(|operand| {
        reg_of(operand) == Some(SP) || mem_of(operand).is_some_and(|(base, _)| base == SP)
    })
}

fn arm32_is_ret(mnemonic: &str, ops: &[&Operand]) -> bool {
    if mnemonic == "bx" {
        return ops.first().and_then(|operand| reg_of(operand)) == Some(LR);
    }
    if mnemonic == "pop" || mnemonic.starts_with("ldm") {
        return ops.iter().any(|operand| {
            reg_of(operand) == Some(PC)
                || reg_list(operand).is_some_and(|mask| mask & (1 << 15) != 0)
        });
    }
    false
}

fn arm32_class(mnemonic: &str, conditional: bool, ops: &[&Operand]) -> OpClass {
    if arm32_is_ret(mnemonic, ops) {
        return if conditional {
            OpClass::Cond
        } else {
            OpClass::Ret
        };
    }
    if mnemonic == "b" || mnemonic == "bx" || ARM32_BRANCH_TABLE.contains(&mnemonic) {
        return if conditional {
            OpClass::Cond
        } else {
            OpClass::Branch
        };
    }
    if mnemonic == "bl" || mnemonic == "blx" || mnemonic == "blr" {
        return OpClass::Call;
    }
    if ARM32_CONDITIONAL_JUMPS.contains(&mnemonic) {
        return OpClass::Cond;
    }
    if ARM32_TRAP.contains(&mnemonic) {
        return OpClass::Misc;
    }
    if mnemonic == "pop" || mnemonic == "push" {
        return OpClass::Stack;
    }
    if ARM32_CMP.contains(&mnemonic) {
        return OpClass::Cmp;
    }
    if ARM32_MUL.contains(&mnemonic) {
        return OpClass::Mul;
    }
    if ARM32_LOGIC.contains(&mnemonic) {
        return OpClass::Logic;
    }
    if ARM32_ARITH.contains(&mnemonic) {
        return OpClass::Arith;
    }
    if ARM32_MOVE.contains(&mnemonic) {
        return OpClass::Move;
    }
    // Flag-setting forms (`movs`, `adds`, `lsrs`, ...) classify as their base
    // mnemonic; `mls` and friends are already matched above.
    let base = mnemonic.strip_suffix('s').unwrap_or(mnemonic);
    if ARM32_MUL.contains(&base) {
        return OpClass::Mul;
    }
    if ARM32_LOGIC.contains(&base) {
        return OpClass::Logic;
    }
    if ARM32_ARITH.contains(&base) {
        return OpClass::Arith;
    }
    if ARM32_MOVE.contains(&base) {
        return OpClass::Move;
    }
    if ARM32_CMP.contains(&base) {
        return OpClass::Cmp;
    }
    let is_store = ARM32_STORE_PREFIXES
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix));
    if is_store {
        return if touches_stack_pointer(ops) {
            OpClass::Stack
        } else {
            OpClass::Store
        };
    }
    let is_load = ARM32_LOAD_PREFIXES
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix));
    if is_load {
        return if touches_stack_pointer(ops) {
            OpClass::Stack
        } else {
            OpClass::Load
        };
    }
    if touches_stack_pointer(ops) {
        return OpClass::Stack;
    }
    OpClass::Misc
}

fn arm32_stack_exit(ops: &[&Operand], conditional: bool, exits: bool) -> Kind {
    if exits
        && ops.iter().any(|operand| {
            reg_of(operand) == Some(PC)
                || reg_list(operand).is_some_and(|mask| mask & (1 << 15) != 0)
        })
    {
        return if conditional {
            Kind::CondJump
        } else {
            Kind::Ret
        };
    }
    Kind::Normal
}

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    pub(crate) fn arm32_block(&self, addr: u64, max_bytes: usize, depth: usize) -> Vec<Insn> {
        let base = addr & !1; // the Thumb bit is metadata, never a byte offset
        let data = self.source.read_partial(base, max_bytes);
        if data.is_empty() {
            return Vec::new();
        }
        let thumb = self.source.is_thumb(base);
        let mut decoder = InstDecoder::default();
        decoder.set_thumb_mode(thumb);

        let mut state = ArmState::default();
        let mut out: Vec<Insn> = Vec::new();
        let mut offset = 0usize;
        // ITSTATE: yaxpeax leaves predication on the `it` instruction, while
        // Capstone (and therefore the reference) marks the following one to
        // four instructions conditional. Only the flag matters for feature
        // extraction, so the mask is just advanced.
        let mut it_mask: Option<u8> = None;
        while offset < data.len() {
            let mut reader = U8Reader::new(&data[offset..]);
            // yaxpeax returns `Incomplete` for whole instruction groups it does
            // not implement (VFP/NEON, the ARMv7 media group), so an error ends
            // the block rather than being retried at another offset.
            let Ok(raw) = decoder.decode(&mut reader) else {
                break;
            };
            let size = raw.len().to_const() as usize;
            if size == 0 || offset + size > data.len() {
                break;
            }
            let mut word = 0u32;
            if offset + 4 <= data.len() {
                word = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
            }
            let hw = word & 0xFFFF;
            let is_it = thumb && size == 2 && hw & 0xFF00 == 0xBF00 && hw & 0xF != 0;
            let in_it = it_mask.is_some();
            if is_it {
                it_mask = Some((hw & 0xF) as u8);
            } else if let Some(mask) = it_mask {
                let next = (mask << 1) & 0xF;
                it_mask = if next == 0 { None } else { Some(next) };
            }
            let insn = self.arm32(
                &raw,
                base + offset as u64,
                size,
                thumb,
                word,
                in_it,
                &mut state,
                depth,
            );
            let terminating = insn.kind.is_terminating();
            out.push(insn);
            offset += size;
            if terminating {
                break;
            }
        }

        let pending = state.take_consts();
        if !pending.is_empty() {
            if let Some(last) = out.last_mut() {
                let mut consts = last.consts.clone();
                consts.extend(pending);
                last.consts = sorted_unique(consts);
            }
        }
        state.clear();
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn arm32(
        &self,
        raw: &Instruction,
        addr: u64,
        size: usize,
        thumb: bool,
        word: u32,
        in_it: bool,
        state: &mut ArmState,
        depth: usize,
    ) -> Insn {
        let (mut mnemonic, display_conditional) = arm32_mnemonic(raw);
        let conditional = display_conditional || in_it;
        // ARM has no `adr` encoding: `add rd, pc, #imm` is a pseudo-instruction
        // that Capstone keeps as `add`. yaxpeax aliases it to `adr`, so undo
        // that in ARM mode; Thumb really does have the alias, and the reference
        // treats `adr` there as an absolute address.
        if !thumb && mnemonic == "adr" {
            mnemonic = "add".to_owned();
        }
        if let Some(wide) = move_wide(thumb, word) {
            mnemonic = wide.to_owned();
        } else if (mnemonic == "mov" || mnemonic == "movs") && !matches!(raw.opcode, Opcode::MOVT) {
            if let Some(alias) = shift_alias(&raw.to_string()) {
                mnemonic = alias.to_owned();
            }
        }
        let ops: Vec<&Operand> = raw
            .operands
            .iter()
            .filter(|operand| !matches!(operand, Operand::Nothing))
            .collect();

        // IT blocks carry predication only; their instructions keep the
        // condition suffix, which `arm32_mnemonic` strips above.
        if ARM32_IGNORED.contains(&mnemonic.as_str()) || mnemonic.starts_with("it") {
            return Insn::ignored(addr, size);
        }

        if mnemonic == "movw" || mnemonic == "movt" {
            if let (Some(destination), Some(immediate)) = (
                ops.first().and_then(reg_of_op),
                ops.get(1).and_then(|op| imm_of(op)),
            ) {
                let value = if mnemonic == "movt" {
                    let previous = state
                        .take(u16::from(destination))
                        .filter(|pending| !pending.is_page)
                        .map_or(0, |pending| pending.value);
                    previous | ((immediate & 0xFFFF) << 16)
                } else {
                    immediate & 0xFFFF
                };
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value: value & MASK32,
                        is_page: false,
                        width: 4,
                    },
                );
                return Insn::normal(addr, size, OpClass::Move);
            }
        }

        if mnemonic == "mvn" {
            // `-x` is materialised as `mvn rd, #~x`; mirror AArch64 `movn`.
            // yaxpeax prints the immediate form as `mvn rd, rd, #imm`, so the
            // immediate is located anywhere in the operand list.
            let immediate = ops.iter().find_map(|operand| imm_of(operand));
            if let (Some(destination), Some(immediate)) =
                (ops.first().and_then(reg_of_op), immediate)
            {
                let value = (!(immediate & MASK32)) & MASK32;
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value,
                        is_page: false,
                        width: 4,
                    },
                );
                return Insn::normal(addr, size, OpClass::Move);
            }
        }

        // Indirect exits that consume a pooled address must read register state
        // before the pending flush below deletes it.
        let mut indirect_target = None;
        if matches!(mnemonic.as_str(), "bx" | "blx" | "blr") {
            if let Some(register) = ops.last().and_then(|operand| reg_of(operand)) {
                if let Some(held) = state.take(u16::from(register)) {
                    if !held.is_page {
                        indirect_target = Some(held.value);
                    }
                }
            }
        }

        let pending = state.take_consts();
        let mut refs: Vec<DataRef> = Vec::new();
        let mut callee: Option<String> = None;
        let mut target: Option<u64> = None;
        let mut kind = Kind::Normal;
        let mut pool_end = 0u64;

        if mnemonic == "adr" {
            if let Some(value) = adr_target(addr, thumb, word, size, &ops) {
                refs.push(DataRef {
                    addr: value,
                    width: 1,
                });
            }
        } else {
            pool_end = self.arm32_literal_load(&ops, &mnemonic, addr, thumb, state, &mut refs);
            if pool_end == 0 {
                self.arm32_pc_add(&ops, &mnemonic, addr, thumb, state, &mut refs);
            }
            if matches!(mnemonic.as_str(), "pop" | "push")
                || mnemonic.starts_with("ldm")
                || mnemonic.starts_with("stm")
            {
                let exits = mnemonic == "pop" || mnemonic.starts_with("ldm");
                kind = arm32_stack_exit(&ops, conditional, exits);
            } else if mnemonic == "b" {
                kind = if conditional {
                    Kind::CondJump
                } else {
                    Kind::Jump
                };
                target = branch_target(addr, thumb, word, size, &ops);
                if kind == Kind::Jump {
                    callee = self.callee_name(target, depth);
                }
            } else if mnemonic == "bx" {
                if indirect_target.is_some() {
                    kind = Kind::Jump;
                    target = indirect_target;
                } else if ops.first().and_then(|operand| reg_of(operand)) == Some(LR) {
                    kind = if conditional {
                        Kind::CondJump
                    } else {
                        Kind::Ret
                    };
                } else {
                    kind = Kind::Jump;
                }
            } else if matches!(mnemonic.as_str(), "bl" | "blx" | "blr") {
                kind = Kind::Call;
                target = branch_target(addr, thumb, word, size, &ops).or(indirect_target);
                if target.is_some() {
                    callee = self.callee_name(target, depth);
                }
                if self.noreturn(callee.as_deref()) {
                    kind = Kind::NoreturnCall;
                }
            } else if ARM32_CONDITIONAL_JUMPS.contains(&mnemonic.as_str()) {
                kind = Kind::CondJump;
                // `cbz`/`cbnz` are forward-only, so the raw halfword path above
                // is the only correct source for the target.
                target = branch_target(addr, thumb, word, size, &ops);
            } else if ARM32_BRANCH_TABLE.contains(&mnemonic.as_str()) {
                kind = Kind::Jump;
            } else if ARM32_TRAP.contains(&mnemonic.as_str()) {
                kind = Kind::Trap;
            } else if mnemonic == "mov" && moves_pc(&ops) {
                kind = Kind::Ret;
            }
        }

        let mut consts = pending;
        if kind == Kind::Normal && !touches_stack_pointer(&ops) {
            consts.extend(
                ops.iter()
                    .filter_map(|operand| imm_of(operand))
                    .map(|immediate| canonical_const(immediate, 4)),
            );
        }

        Insn {
            addr,
            size,
            op: arm32_class(&mnemonic, conditional, &ops),
            kind,
            consts: sorted_unique(consts),
            refs,
            callee,
            target,
            pool_end,
        }
    }

    /// Resolve `ldr rd, [pc, #imm]` against the function's literal pool.
    ///
    /// A pool cell holding a pointer becomes a reference to the target (the
    /// string or table the compiler pooled); any other word becomes a pending
    /// 32-bit constant, matching how `movw`/`movt` pairs flush. Returns the end
    /// of the referenced cell, or 0 when this is not a literal load.
    fn arm32_literal_load(
        &self,
        ops: &[&Operand],
        mnemonic: &str,
        addr: u64,
        thumb: bool,
        state: &mut ArmState,
        refs: &mut Vec<DataRef>,
    ) -> u64 {
        if mnemonic != "ldr" || ops.len() < 2 {
            return 0;
        }
        for (index, operand) in ops.iter().enumerate() {
            let Some((base, offset)) = mem_of(operand) else {
                continue;
            };
            if base != PC {
                continue;
            }
            if index == 0 {
                return 0;
            }
            let Some(destination) = reg_of(ops[index - 1]) else {
                return 0;
            };
            let literal = pc_value(addr, thumb).wrapping_add_signed(offset);
            let Some(value) = self.read_pointer32(literal) else {
                return 0;
            };
            if self.source.module_for(value).is_some() {
                refs.push(DataRef {
                    addr: value,
                    width: 4,
                });
            } else {
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value,
                        is_page: false,
                        width: 4,
                    },
                );
            }
            return literal + 4;
        }
        0
    }

    /// Resolve `add rd, pc, rm` / `add rd, pc` against a pooled offset.
    ///
    /// Position-independent arm32 code materialises a page offset into a
    /// register and adds the PC; the sum is the data address, so it becomes a
    /// reference exactly like AArch64's `adrp`+`add` pair.
    fn arm32_pc_add(
        &self,
        ops: &[&Operand],
        mnemonic: &str,
        addr: u64,
        thumb: bool,
        state: &mut ArmState,
        refs: &mut Vec<DataRef>,
    ) {
        if !ops.iter().any(|operand| reg_of(operand) == Some(PC)) {
            return;
        }
        let base = pc_value(addr, thumb);
        let subtracting = mnemonic.starts_with('s') || mnemonic.starts_with('r');
        let immediate = ops.iter().find_map(|operand| imm_of(operand));
        for operand in ops.iter().skip(1) {
            let Some(register) = reg_of(operand) else {
                continue;
            };
            if register == PC {
                continue;
            }
            let Some(held) = state.take(u16::from(register)) else {
                continue;
            };
            if held.is_page {
                continue;
            }
            let resolved = if subtracting {
                base.wrapping_sub(held.value)
            } else {
                base.wrapping_add(held.value)
            } & MASK32;
            refs.push(DataRef {
                addr: resolved,
                width: 4,
            });
            // Keep an address marker so the intermediate never flushes as a
            // constant, but let later arithmetic still see the value.
            if let Some(destination) = ops.first().and_then(|operand| reg_of(operand)) {
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value: resolved,
                        is_page: true,
                        width: 4,
                    },
                );
            }
            return;
        }
        if let Some(destination) = ops.first().and_then(|operand| reg_of(operand)) {
            if let Some(immediate) = immediate {
                let resolved = if subtracting {
                    base.wrapping_sub(immediate)
                } else {
                    base.wrapping_add(immediate)
                } & MASK32;
                refs.push(DataRef {
                    addr: resolved,
                    width: 4,
                });
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value: resolved,
                        is_page: true,
                        width: 4,
                    },
                );
            } else {
                state.insert(
                    u16::from(destination),
                    PendingValue {
                        value: base,
                        is_page: true,
                        width: 4,
                    },
                );
            }
        }
    }
}

/// `reg_of` for an `Option<&Operand>` from the filtered operand list.
fn reg_of_op(operand: &&Operand) -> Option<u8> {
    reg_of(operand)
}
