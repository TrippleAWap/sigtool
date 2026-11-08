//! AArch64 decoding and normalization for the native port.
//!
//! The rules mirror `core/normalize.py` (`_arm`, `_arm_materialize`,
//! `_arm_class`, `_arm_immediate_consts`). yaxpeax-arm plays the part of
//! Capstone, so the projection below reads the same facts the reference reads
//! off `CsInsn`: register width, stack-pointer use, literal pools, and
//! materialised constants. Two decoder differences are handled here rather
//! than downstream:
//!
//! * `adrp` reports a page delta and `adr`/branches report a pc delta, where
//!   Capstone reports absolute addresses.
//! * A `[pc, #imm]` literal load and a `[sp, #imm]` access both arrive as base
//!   register 31, so the literal-load encoding decides between them.

use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{Instruction, Opcode, Operand, SizeCode};

use crate::normalize::{
    canonical_const, sorted_unique, DataRef, Insn, Kind, Normalizer, OpClass, MASK32, MASK64,
};
use crate::source::ByteSource;

const ARM64_IGNORED: &[&str] = &[
    "nop", "bti", "hint", "paciasp", "autiasp", "pacibsp", "autibsp", "paciaz", "autiaz", "pacibz",
    "autibz", "xpaclri",
];

const ARM64_RET: &[&str] = &[
    "ret", "retaa", "retab", "retbb", "retba", "eret", "eretaa", "eretab",
];

const ARM64_TRAP: &[&str] = &["brk", "hlt", "udf"];

const ARM64_MUL: &[&str] = &[
    "mul", "madd", "msub", "mneg", "smull", "umull", "smulh", "umulh", "sdiv", "udiv", "smaddl",
    "umaddl", "smsubl", "umsubl", "sqdmulh", "sqrdmulh",
];

const ARM64_LOGIC: &[&str] = &[
    "and", "ands", "orr", "orn", "eor", "eon", "bic", "bics", "lsl", "lsr", "asr", "ror", "mvn",
    "extr",
];

const ARM64_CMP: &[&str] = &["cmp", "cmn", "ccmp", "ccmn", "tst"];

const ARM64_MOVE: &[&str] = &[
    "mov", "movz", "movk", "movn", "adr", "adrp", "csel", "csinc", "csinv", "csneg", "cset",
    "csetm", "sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw",
];

const ARM64_ARITH: &[&str] = &[
    "add", "adds", "sub", "subs", "adc", "adcs", "sbc", "sbcs", "neg", "negs", "ngc", "ngcs",
];

const ARM64_LOAD_PREFIXES: &[&str] = &[
    "ldr", "ldur", "ldp", "ldnp", "ldar", "ldxr", "ldaxr", "ld1", "ld2", "ld3", "ld4",
];

const ARM64_STORE_PREFIXES: &[&str] = &[
    "str", "stur", "stp", "stnp", "stlr", "stxr", "st1", "st2", "st3", "st4",
];

const ARM64_LITERAL_LOADS: &[&str] = &["ldr", "ldrsw", "prfm", "ldrq"];

const ARM64_SHIFT_MNEMONICS: &[&str] = &["lsl", "lsr", "asr", "ror", "extr", "ubfm", "sbfm", "bfm"];

const ARM64_CALLS: &[&str] = &["bl", "blr", "blraa", "blraaz", "blrab", "blrabz"];

const ARM64_COND_BRANCHES: &[&str] = &["cbz", "cbnz", "tbz", "tbnz"];

const ARM64_FP_PREFIXES: &[&str] = &[
    "fmov", "fadd", "fsub", "fmul", "fdiv", "fcmp", "fcvt", "scvtf", "ucvtf",
];

/// A register value materialised in the block but not yet observed.
#[derive(Clone, Copy)]
struct PendingValue {
    value: u64,
    is_page: bool,
    width: usize,
}

/// Register values produced by `adrp`, `movz`/`movk` chains, and literal
/// loads, kept until the instruction that consumes them (or the block end).
#[derive(Default)]
struct ArmState {
    values: Vec<(u16, PendingValue)>,
}

impl ArmState {
    fn insert(&mut self, register: u16, pending: PendingValue) {
        match self.values.iter_mut().find(|(slot, _)| *slot == register) {
            Some(slot) => slot.1 = pending,
            None => self.values.push((register, pending)),
        }
    }

    fn get(&self, register: u16) -> Option<PendingValue> {
        self.values
            .iter()
            .find(|(slot, _)| *slot == register)
            .map(|(_, pending)| *pending)
    }

    fn take(&mut self, register: u16) -> Option<PendingValue> {
        let index = self.values.iter().position(|(slot, _)| *slot == register)?;
        Some(self.values.swap_remove(index).1)
    }

    /// Consume pending constants, keeping unresolved `adrp` pages: a page that
    /// is never consumed is an address and must never flush as a constant.
    fn take_consts(&mut self) -> Vec<u64> {
        let mut values: Vec<u64> = self
            .values
            .iter()
            .filter(|(_, pending)| !pending.is_page)
            .map(|(_, pending)| canonical_const(pending.value, pending.width))
            .collect();
        values.sort_unstable();
        self.values.retain(|(_, pending)| pending.is_page);
        values
    }

    fn clear(&mut self) {
        self.values.clear();
    }
}

#[derive(Clone, Copy)]
struct RegRef {
    number: u16,
    width: usize,
    is_sp: bool,
}

fn register_width(size: SizeCode) -> usize {
    match size {
        SizeCode::X => 8,
        _ => 4,
    }
}

fn reg_ref(operand: &Operand) -> Option<RegRef> {
    match operand {
        // `Register(_, 31)` is the zero register; `RegisterOrSP(_, 31)` is the
        // stack pointer, which is why the two variants are kept apart.
        Operand::Register(size, number) => Some(RegRef {
            number: *number,
            width: register_width(*size),
            is_sp: false,
        }),
        Operand::RegisterOrSP(size, number) => Some(RegRef {
            number: *number,
            width: register_width(*size),
            is_sp: *number == 31,
        }),
        _ => None,
    }
}

fn is_simd(operand: &Operand) -> bool {
    matches!(
        operand,
        Operand::SIMDRegister(..)
            | Operand::SIMDRegisterElements(..)
            | Operand::SIMDRegisterElementsLane(..)
    )
}

/// Immediate value and shift for the operand forms an immediate can take.
fn imm_shift(operand: &Operand) -> Option<(u64, u32)> {
    match operand {
        Operand::Immediate(value) => Some((u64::from(*value), 0)),
        Operand::Imm64(value) => Some((*value, 0)),
        Operand::Imm16(value) => Some((u64::from(*value), 0)),
        Operand::ImmShift(value, shift) => Some((u64::from(*value), u32::from(*shift))),
        Operand::ImmShiftMSL(value, shift) => Some((u64::from(*value), u32::from(*shift))),
        _ => None,
    }
}

fn pc_offset(operand: &Operand) -> Option<i64> {
    match operand {
        Operand::PCOffset(offset) => Some(*offset),
        _ => None,
    }
}

/// Base register and byte offset of a memory operand.
fn mem_ref(operand: &Operand) -> Option<(u16, i64)> {
    match operand {
        Operand::RegPreIndex(base, offset, _) => Some((*base, i64::from(*offset))),
        Operand::RegPostIndex(base, offset) => Some((*base, i64::from(*offset))),
        Operand::RegPostIndexReg(base, _) => Some((*base, 0)),
        Operand::RegRegOffset(base, _, _, _, _) => Some((*base, 0)),
        _ => None,
    }
}

/// LDR (literal) encodes `opc 011 V 00 imm19 Rt`; nothing else with base
/// register 31 can be a stack access, so the encoding decides.
fn is_literal_encoding(word: u32) -> bool {
    (word >> 27) & 0x7 == 0b011 && (word >> 24) & 0x3 == 0
}

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    pub(crate) fn arm64_block(&self, addr: u64, max_bytes: usize, depth: usize) -> Vec<Insn> {
        if max_bytes == 0 {
            return Vec::new();
        }
        let data = self.source.read_partial(addr, max_bytes);
        let mut out: Vec<Insn> = Vec::new();
        let mut state = ArmState::default();
        let mut offset = 0usize;
        while offset + 4 <= data.len() {
            let chunk = &data[offset..offset + 4];
            let mut reader = U8Reader::new(chunk);
            let Ok(raw) = self.arm64.decode(&mut reader) else {
                break;
            };
            let insn = self.arm64(&raw, addr + offset as u64, chunk, depth, &mut state);
            let terminating = insn.kind.is_terminating();
            out.push(insn);
            if terminating {
                break;
            }
            offset += 4;
        }
        let pending = state.take_consts();
        if !pending.is_empty() {
            if let Some(last) = out.last_mut() {
                last.consts.extend(pending);
                last.consts.sort_unstable();
                last.consts.dedup();
            }
        }
        state.clear();
        out
    }

    fn arm64(
        &self,
        raw: &Instruction,
        pc: u64,
        bytes: &[u8],
        depth: usize,
        state: &mut ArmState,
    ) -> Insn {
        let text = raw.to_string();
        let mnemonic = text.split(' ').next().unwrap_or_default().to_string();
        let mnemonic = mnemonic.as_str();
        let ops = &raw.operands;
        let addr = pc;
        let size = 4usize;
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let touches_stack_pointer = arm64_touches_stack_pointer(ops, mnemonic, word);

        if ARM64_IGNORED.contains(&mnemonic) {
            return Insn::ignored(addr, size);
        }

        if mnemonic == "adrp" {
            if let (Some(destination), Some(offset)) = (reg_ref(&ops[0]), pc_offset(&ops[1])) {
                state.insert(
                    destination.number,
                    PendingValue {
                        value: adrp_page(addr, offset),
                        is_page: true,
                        width: 8,
                    },
                );
                return Insn::normal(addr, size, OpClass::Move);
            }
        }

        if matches!(mnemonic, "mov" | "movz" | "movn" | "movk")
            && ops[1..].iter().any(|operand| imm_shift(operand).is_some())
        {
            if let Some(materialized) = self.arm64_materialize(raw, mnemonic, addr, state) {
                return materialized;
            }
        }

        if mnemonic == "adr" {
            if let Some(offset) = pc_offset(&ops[1]) {
                // ADR reaches nearby data directly, so the target is an address.
                return Insn {
                    refs: vec![DataRef {
                        addr: rel(addr, offset),
                        width: 1,
                    }],
                    ..Insn::normal(addr, size, OpClass::Move)
                };
            }
        }

        if mnemonic.starts_with("br") && mnemonic != "brk" {
            // `br x16` after a literal load is a veneer; follow it when possible.
            let call = mnemonic.starts_with("blr");
            let mut target = None;
            if let Some(register) = reg_ref(&ops[0]) {
                if let Some(held) = state.take(register.number) {
                    if !held.is_page {
                        target = Some(held.value);
                    }
                }
            }
            let op = if call { OpClass::Call } else { OpClass::Branch };
            return Insn {
                kind: if call { Kind::Call } else { Kind::Jump },
                callee: if call {
                    self.callee_name(target, depth)
                } else {
                    None
                },
                target,
                ..Insn::normal(addr, size, op)
            };
        }

        let pending = state.take_consts();
        let mut refs: Vec<DataRef> = Vec::new();

        // adrp + add/sub: one resolved address, never a constant.
        if matches!(mnemonic, "add" | "sub") && ops.len() >= 3 {
            if let (Some(base), Some((immediate, 0))) = (reg_ref(&ops[1]), imm_shift(&ops[2])) {
                if let Some(page) = state.get(base.number) {
                    if page.is_page {
                        state.take(base.number);
                        let resolved = if mnemonic == "add" {
                            page.value.wrapping_add(immediate)
                        } else {
                            page.value.wrapping_sub(immediate)
                        };
                        return Insn {
                            consts: sorted_unique(pending),
                            refs: vec![DataRef {
                                addr: resolved,
                                width: 1,
                            }],
                            ..Insn::normal(addr, size, OpClass::Move)
                        };
                    }
                }
            }
        }

        if let (Some(destination), Some((base, offset))) = (reg_ref(&ops[0]), mem_ref(&ops[1])) {
            let width = destination.width;
            if let Some(page) = state.get(base) {
                if page.is_page {
                    state.take(base);
                    refs.push(DataRef {
                        addr: page.value.wrapping_add_signed(offset),
                        width,
                    });
                }
            } else if base == 31
                && ARM64_LITERAL_LOADS.contains(&mnemonic)
                && is_literal_encoding(word)
            {
                let literal = rel(addr, offset);
                let value = if width == 8 {
                    self.read_pointer(Some(literal))
                } else {
                    self.read_pointer32(literal)
                };
                if let Some(value) = value {
                    if self.source.module_for(value).is_some() {
                        // The pool cell holds a pointer; the cell is the anchor.
                        refs.push(DataRef {
                            addr: literal,
                            width,
                        });
                    } else {
                        state.insert(
                            destination.number,
                            PendingValue {
                                value,
                                is_page: false,
                                width,
                            },
                        );
                    }
                }
            }
        }

        let mut kind = Kind::Normal;
        let mut callee = None;
        let mut target = None;
        if mnemonic == "b" {
            kind = Kind::Jump;
            target = branch_target(addr, ops);
            callee = self.callee_name(target, depth);
        } else if mnemonic.starts_with("b.") || ARM64_COND_BRANCHES.contains(&mnemonic) {
            kind = Kind::CondJump;
            target = branch_target(addr, ops);
        } else if ARM64_CALLS.contains(&mnemonic) {
            kind = Kind::Call;
            target = branch_target(addr, ops);
            if target.is_some() {
                callee = self.callee_name(target, depth);
            }
            if self.noreturn(callee.as_deref()) {
                kind = Kind::NoreturnCall;
            }
        } else if ARM64_RET.contains(&mnemonic) {
            kind = Kind::Ret;
        } else if ARM64_TRAP.contains(&mnemonic) {
            kind = Kind::Trap;
        }

        let mut consts = pending;
        if kind == Kind::Normal {
            consts.extend(arm64_immediate_consts(raw, mnemonic, touches_stack_pointer));
        }

        Insn {
            addr,
            size,
            op: arm64_class(mnemonic, ops, touches_stack_pointer),
            kind,
            consts: sorted_unique(consts),
            refs,
            callee,
            target,
            pool_end: 0,
        }
    }

    fn arm64_materialize(
        &self,
        raw: &Instruction,
        mnemonic: &str,
        addr: u64,
        state: &mut ArmState,
    ) -> Option<Insn> {
        let ops = &raw.operands;
        let destination = reg_ref(&ops[0])?;
        let width = destination.width;
        let mask = if width == 8 { MASK64 } else { MASK32 };
        let (immediate, shift) = ops[1..].iter().find_map(imm_shift)?;

        let value = if matches!(&raw.opcode, Opcode::MOVK) {
            let base = state
                .take(destination.number)
                .filter(|pending| !pending.is_page)
                .map_or(0, |pending| pending.value);
            base | ((immediate & 0xFFFF) << shift)
        } else if matches!(&raw.opcode, Opcode::MOVN) || mnemonic == "movn" {
            !(immediate << shift)
        } else {
            immediate << shift
        };

        state.insert(
            destination.number,
            PendingValue {
                value: value & mask,
                is_page: false,
                width,
            },
        );
        Some(Insn::normal(addr, 4, OpClass::Move))
    }

    fn read_pointer32(&self, addr: u64) -> Option<u64> {
        let data = self.source.try_read(addr, 4)?;
        if data.len() < 4 {
            return None;
        }
        Some(u64::from(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ])))
    }
}

fn rel(pc: u64, offset: i64) -> u64 {
    pc.wrapping_add_signed(offset)
}

fn branch_target(addr: u64, ops: &[Operand; 4]) -> Option<u64> {
    ops.iter()
        .find_map(pc_offset)
        .map(|offset| rel(addr, offset))
}

/// Resolve an `adrp` page: the decoder reports the page delta, not the page.
fn adrp_page(addr: u64, offset: i64) -> u64 {
    (addr & !0xFFF).wrapping_add_signed(offset)
}

fn arm64_immediate_consts(
    raw: &Instruction,
    mnemonic: &str,
    touches_stack_pointer: bool,
) -> Vec<u64> {
    if ARM64_SHIFT_MNEMONICS.contains(&mnemonic) || touches_stack_pointer {
        return Vec::new();
    }
    let _ = raw;
    raw.operands
        .iter()
        .filter_map(imm_shift)
        .map(|(value, shift)| canonical_const(value.wrapping_shl(shift), 8))
        .collect()
}

fn arm64_touches_stack_pointer(ops: &[Operand; 4], mnemonic: &str, word: u32) -> bool {
    if ops.iter().any(|operand| {
        reg_ref(operand).is_some_and(|register| register.is_sp)
            || (register_may_be_stack_pointer(operand))
    }) {
        return true;
    }
    for operand in ops.iter() {
        if let Some((base, _)) = mem_ref(operand) {
            if base != 31 {
                continue;
            }
            let literal = ARM64_LITERAL_LOADS.contains(&mnemonic) && is_literal_encoding(word);
            if !literal {
                return true;
            }
        }
    }
    false
}

/// `RegisterOrSP(_, 31)` is the stack pointer; plain `Register(_, 31)` is not.
fn register_may_be_stack_pointer(operand: &Operand) -> bool {
    matches!(operand, Operand::RegisterOrSP(_, 31))
}

fn arm64_class(mnemonic: &str, ops: &[Operand; 4], touches_stack_pointer: bool) -> OpClass {
    if ops.iter().any(is_simd) {
        return OpClass::Vector;
    }
    if mnemonic == "b" {
        return OpClass::Branch;
    }
    if mnemonic.starts_with("br") && mnemonic != "brk" {
        return if mnemonic.starts_with("blr") {
            OpClass::Call
        } else {
            OpClass::Branch
        };
    }
    if mnemonic.starts_with("b.") || ARM64_COND_BRANCHES.contains(&mnemonic) {
        return OpClass::Cond;
    }
    if ARM64_CALLS.contains(&mnemonic) {
        return OpClass::Call;
    }
    if ARM64_RET.contains(&mnemonic) {
        return OpClass::Ret;
    }
    if ARM64_CMP.contains(&mnemonic) {
        return OpClass::Cmp;
    }
    if ARM64_MUL.contains(&mnemonic) {
        return OpClass::Mul;
    }
    if ARM64_LOGIC.contains(&mnemonic) {
        return OpClass::Logic;
    }
    if ARM64_ARITH.contains(&mnemonic) {
        return OpClass::Arith;
    }
    if ARM64_MOVE.contains(&mnemonic) {
        return OpClass::Move;
    }
    if ARM64_STORE_PREFIXES
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix))
    {
        return if touches_stack_pointer {
            OpClass::Stack
        } else {
            OpClass::Store
        };
    }
    if ARM64_LOAD_PREFIXES
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix))
    {
        return if touches_stack_pointer {
            OpClass::Stack
        } else {
            OpClass::Load
        };
    }
    if ARM64_FP_PREFIXES
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix))
    {
        return OpClass::Vector;
    }
    if touches_stack_pointer {
        return OpClass::Stack;
    }
    OpClass::Misc
}
