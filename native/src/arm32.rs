//! ARM32 and Thumb decoding and normalization for the native port.
//!
//! The projection mirrors `core/normalize.py` (`_arm32`, `_arm32_materialize`,
//! `_arm32_literal_load`, `_arm32_pc_add`, `_arm32_class`) function for
//! function. Decoding goes through Capstone, the same engine the reference
//! uses, so mnemonic spellings (shifted-register aliases, `.w` markers),
//! condition codes, and operand shapes arrive identically instead of being
//! reconstructed from another decoder's output.
//!
//! Unlike x64 (`iced-x86`) and AArch64 (`yaxpeax-arm`), ARM32/Thumb needs the C
//! decoder: `yaxpeax-arm` 0.5 returns `DecodeError::Incomplete` for the whole
//! ARMv7 media group and has no VFP/NEON instructions, and those two gaps cover
//! ordinary compiled code (`uxth`, vectorized loops).

use capstone::arch::arm::{ArchMode, ArmCC, ArmOperandType, ArmReg};
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::{Capstone, Insn as CsInsn, RegId};

use crate::normalize::{
    canonical_const, is_address, sorted_unique, ArmState, DataRef, Insn, Kind, Normalizer, OpClass,
    PendingValue, MASK32,
};
use crate::source::ByteSource;
use crate::spec::MAX_THUNK_HOPS;

const PC: RegId = RegId(ArmReg::ARM_REG_PC as u16);
const LR: RegId = RegId(ArmReg::ARM_REG_LR as u16);
const SP: RegId = RegId(ArmReg::ARM_REG_SP as u16);

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

/// One operand, reduced to the facts the reference reads off `CsInsn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmOp {
    Reg(RegId),
    Imm(i64),
    Mem {
        base: RegId,
        index: RegId,
        disp: i64,
    },
}

fn reg_key(reg: RegId) -> u16 {
    reg.0
}

fn is_vector_reg(cs: &Capstone, reg: RegId) -> bool {
    let Some(name) = cs.reg_name(reg) else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    matches!(first, 'v' | 'q' | 'd' | 's' | 'b' | 'h')
        && name.len() > 1
        && chars.all(|ch| ch.is_ascii_digit())
}

fn arm_capstone(thumb: bool) -> Option<Capstone> {
    let mode = if thumb {
        ArchMode::Thumb
    } else {
        ArchMode::Arm
    };
    Capstone::new().arm().mode(mode).detail(true).build().ok()
}

fn cc_suffix(cc: ArmCC) -> Option<&'static str> {
    Some(match cc {
        ArmCC::ARM_CC_EQ => "eq",
        ArmCC::ARM_CC_NE => "ne",
        ArmCC::ARM_CC_HS => "hs",
        ArmCC::ARM_CC_LO => "lo",
        ArmCC::ARM_CC_MI => "mi",
        ArmCC::ARM_CC_PL => "pl",
        ArmCC::ARM_CC_VS => "vs",
        ArmCC::ARM_CC_VC => "vc",
        ArmCC::ARM_CC_HI => "hi",
        ArmCC::ARM_CC_LS => "ls",
        ArmCC::ARM_CC_GE => "ge",
        ArmCC::ARM_CC_LT => "lt",
        ArmCC::ARM_CC_GT => "gt",
        ArmCC::ARM_CC_LE => "le",
        _ => return None,
    })
}

/// Strip the Thumb width marker and the condition suffix from the mnemonic.
///
/// The suffix is removed only when the decoder reports a condition, so
/// mnemonics that merely end in a condition pair (`umlal`, `mls`) survive.
fn arm32_mnemonic(raw: &CsInsn<'_>, cc: ArmCC) -> (String, bool) {
    let mut mnemonic = raw.mnemonic().unwrap_or_default().to_owned();
    if let Some(stripped) = mnemonic
        .strip_suffix(".w")
        .or_else(|| mnemonic.strip_suffix(".n"))
    {
        mnemonic = stripped.to_owned();
    }
    if cc == ArmCC::ARM_CC_AL || cc == ArmCC::ARM_CC_INVALID {
        return (mnemonic, false);
    }
    if let Some(suffix) = cc_suffix(cc) {
        if let Some(stripped) = mnemonic.strip_suffix(suffix) {
            return (stripped.to_owned(), true);
        }
    }
    (mnemonic, false)
}

/// Capstone expands a register list (`pop {r4, pc}`) into one `Reg` per entry.
fn arm_operands(cs: &Capstone, detail: &capstone::InsnDetail<'_>) -> (Vec<ArmOp>, bool) {
    let arch = detail.arch_detail();
    let mut ops = Vec::new();
    let mut vector = false;
    for operand in arch.operands() {
        let ArchOperand::ArmOperand(operand) = operand else {
            continue;
        };
        match operand.op_type {
            ArmOperandType::Reg(reg) => {
                vector |= is_vector_reg(cs, reg);
                ops.push(ArmOp::Reg(reg));
            }
            ArmOperandType::Imm(value) => ops.push(ArmOp::Imm(i64::from(value))),
            ArmOperandType::Mem(mem) => ops.push(ArmOp::Mem {
                base: mem.base(),
                index: mem.index(),
                disp: i64::from(mem.disp()),
            }),
            _ => {}
        }
    }
    (ops, vector)
}

fn arm_target(ops: &[ArmOp]) -> Option<u64> {
    ops.iter().rev().find_map(|operand| match operand {
        ArmOp::Imm(value) => Some(*value as u64),
        _ => None,
    })
}

/// Registers an instruction names, read or written, as `ArmState` keys.
fn mentioned_registers(ops: &[ArmOp]) -> Vec<u16> {
    let mut registers = Vec::new();
    for operand in ops {
        match operand {
            ArmOp::Reg(reg) => registers.push(reg_key(*reg)),
            ArmOp::Mem { base, index, .. } => {
                registers.push(reg_key(*base));
                registers.push(reg_key(*index));
            }
            ArmOp::Imm(_) => {}
        }
    }
    registers
}

fn touches_stack_pointer(ops: &[ArmOp]) -> bool {
    ops.iter().any(|operand| match operand {
        ArmOp::Reg(reg) => *reg == SP,
        ArmOp::Mem { base, .. } => *base == SP,
        ArmOp::Imm(_) => false,
    })
}

fn moves_pc(ops: &[ArmOp]) -> bool {
    matches!(
        (ops.first(), ops.get(1)),
        (Some(ArmOp::Reg(destination)), Some(ArmOp::Reg(source)))
            if *destination == PC && *source == LR
    )
}

fn arm32_is_ret(mnemonic: &str, ops: &[ArmOp]) -> bool {
    if mnemonic == "bx" {
        return matches!(ops.first(), Some(ArmOp::Reg(reg)) if *reg == LR);
    }
    if mnemonic == "pop" || mnemonic.starts_with("ldm") {
        return ops
            .iter()
            .any(|operand| matches!(operand, ArmOp::Reg(reg) if *reg == PC));
    }
    false
}

fn starts_with_any(mnemonic: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| mnemonic.starts_with(prefix))
}

fn arm32_class(mnemonic: &str, conditional: bool, ops: &[ArmOp], vector: bool) -> OpClass {
    if vector {
        return OpClass::Vector;
    }
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
    if matches!(mnemonic, "bl" | "blx" | "blr") {
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
    if starts_with_any(mnemonic, ARM32_STORE_PREFIXES) {
        return if touches_stack_pointer(ops) {
            OpClass::Stack
        } else {
            OpClass::Store
        };
    }
    if starts_with_any(mnemonic, ARM32_LOAD_PREFIXES) {
        return if touches_stack_pointer(ops) {
            OpClass::Stack
        } else {
            OpClass::Load
        };
    }
    if touches_stack_pointer(ops) {
        OpClass::Stack
    } else {
        OpClass::Misc
    }
}

/// PC value the instruction sees, per the ARM and Thumb pipeline rules.
fn pc_value(addr: u64, thumb: bool) -> u64 {
    if thumb {
        (addr + 4) & !3
    } else {
        addr + 8
    }
}

fn arm32_immediate_consts(ops: &[ArmOp]) -> Vec<u64> {
    if touches_stack_pointer(ops) {
        return Vec::new();
    }
    ops.iter()
        .filter_map(|operand| match operand {
            ArmOp::Imm(value) => Some(canonical_const(*value as u64, 4)),
            _ => None,
        })
        .collect()
}

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    pub(crate) fn arm32_block(&self, base: u64, max_bytes: usize, depth: usize) -> Vec<Insn> {
        self.arm32_decode(base, max_bytes, depth, usize::MAX)
    }

    /// The first instruction at `addr`, for stub detection, which reads only
    /// its kind and target. Those never depend on the instructions after it,
    /// while decoding the rest of its block cost a stub check per call site
    /// several decodes. Its `consts` can differ from the block's first
    /// instruction: pending values fold into the last instruction decoded.
    pub(crate) fn arm32_first(&self, addr: u64, max_bytes: usize, depth: usize) -> Option<Insn> {
        self.arm32_decode(addr, max_bytes, depth, 1)
            .into_iter()
            .next()
    }

    fn arm32_decode(&self, base: u64, max_bytes: usize, depth: usize, limit: usize) -> Vec<Insn> {
        if max_bytes == 0 {
            return Vec::new();
        }
        let data = self.source.read_partial(base, max_bytes);
        if data.is_empty() {
            return Vec::new();
        }
        let thumb = self.source.is_thumb(base);
        // Resolving a branch's callee decodes the target one level deeper
        // while this block is still being iterated, and a nested decode
        // resets the IT-block state the handle carries. Each depth gets its
        // own handle, so a nested decode never disturbs this one.
        let slot = depth.min(ARM32_HANDLE_DEPTHS - 1);
        let Some(cs) = self.arm32[usize::from(thumb)][slot]
            .get_or_init(|| arm_capstone(thumb))
            .as_ref()
        else {
            return Vec::new();
        };
        // A block ends at its first terminator, usually a few instructions
        // in, while the span is up to a page. Disassembling a prefix of the
        // span with detail still decoded about four instructions for every
        // one kept on Thumb sqlite, so step through it one instruction at a
        // time and stop at the terminator. `cs_disasm_iter` continues the
        // IT-block state the handle carries while `cs_disasm` resets it, so
        // an empty `cs_disasm` first gives the walk the state a fresh
        // disassembly of the span starts from: the result is the same
        // instructions the full span would give.
        if cs.disasm_all(&[], base).is_err() {
            return Vec::new();
        }
        let Ok(mut instructions) = cs.disasm_iter(&data, base) else {
            return Vec::new();
        };
        let mut state = ArmState::default();
        let mut out: Vec<Insn> = Vec::new();
        while let Some(raw) = instructions.next() {
            if raw.len() == 0 {
                break;
            }
            let Ok(detail) = cs.insn_detail(&raw) else {
                break;
            };
            let cc = match detail.arch_detail() {
                ArchDetail::ArmDetail(arm) => arm.cc(),
                _ => ArmCC::ARM_CC_INVALID,
            };
            let (ops, vector) = arm_operands(cs, &detail);
            let insn = self.arm32(&raw, &ops, cc, vector, thumb, &mut state, depth);
            let terminating = insn.kind.is_terminating();
            out.push(insn);
            if terminating || out.len() >= limit {
                break;
            }
        }
        finish_block(out, state)
    }
}

/// Capstone handles per mode: the block itself plus one per nested stub
/// decode, which [`MAX_THUNK_HOPS`] bounds.
pub(crate) const ARM32_HANDLE_DEPTHS: usize = MAX_THUNK_HOPS + 2;

/// Fold constants still pending at the end of a block into its last
/// instruction.
fn finish_block(mut out: Vec<Insn>, mut state: ArmState) -> Vec<Insn> {
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

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    #[allow(clippy::too_many_arguments)]
    fn arm32(
        &self,
        raw: &CsInsn<'_>,
        ops: &[ArmOp],
        cc: ArmCC,
        vector: bool,
        thumb: bool,
        state: &mut ArmState,
        depth: usize,
    ) -> Insn {
        let addr = raw.address();
        let size = raw.len();
        let (mnemonic, conditional) = arm32_mnemonic(raw, cc);

        if ARM32_IGNORED.contains(&mnemonic.as_str()) || mnemonic.starts_with("it") {
            // `nop` is alignment filler; `hint`/`it` are real code and keep
            // their address as a candidate start.
            // IT blocks carry predication only; Capstone already marked the
            // covered instructions conditional, so the marker is dropped.
            return if mnemonic == "nop" {
                Insn::filler(addr, size)
            } else {
                Insn::ignored(addr, size)
            };
        }

        if let Some(insn) = self.arm32_materialize(ops, &mnemonic, addr, size, state) {
            return insn;
        }

        if mnemonic == "mvn" {
            // `-x` is materialised as `mvn rd, #~x`; mirror AArch64 `movn`.
            if let (Some(&ArmOp::Reg(destination)), Some(&ArmOp::Imm(immediate))) =
                (ops.first(), ops.get(1))
            {
                let value = (!(immediate as u64 & MASK32)) & MASK32;
                let replaced = state.take_consts_in(&[reg_key(destination)]);
                state.insert(
                    reg_key(destination),
                    PendingValue {
                        value,
                        is_page: false,
                        width: 4,
                    },
                );
                return Insn {
                    consts: replaced,
                    ..Insn::normal(addr, size, OpClass::Move)
                };
            }
        }

        // Indirect exits that consume a pooled address must read register state
        // before the pending flush below deletes it.
        let mut indirect_target = None;
        if matches!(mnemonic.as_str(), "bx" | "blx" | "blr") {
            if let Some(&ArmOp::Reg(register)) = ops.last() {
                if let Some(held) = state.take(reg_key(register)) {
                    if !held.is_page {
                        indirect_target = Some(held.value);
                    }
                }
            }
        }

        let mut refs: Vec<DataRef> = Vec::new();
        // PIC code pools a PC-relative offset and then adds the PC to it; the
        // pooled offset must reach the add as an address, not flush first as
        // a constant (that leaked a build-specific offset and lost the string).
        let pc_arithmetic = mnemonic != "adr"
            && ["add", "sub", "rsb"]
                .iter()
                .any(|prefix| mnemonic.starts_with(prefix));
        if pc_arithmetic {
            self.arm32_pc_add(ops, &mnemonic, addr, thumb, state, &mut refs);
        }

        // `ldr rd, [pc, rm]` resolves the pooled offset in `rm` to a GOT slot
        // below; flushing it first would leak the build-specific offset as a
        // constant.
        let pc_index = ops.iter().find_map(|operand| match operand {
            ArmOp::Mem { base, index, .. } if *base == PC && index.0 != 0 => Some(reg_key(*index)),
            _ => None,
        });
        let mut mentioned = mentioned_registers(ops);
        mentioned.retain(|register| Some(*register) != pc_index);
        let mut pending = state.take_consts_in(&mentioned);
        let mut callee: Option<String> = None;
        let mut target: Option<u64> = None;
        let mut kind = Kind::Normal;
        let mut pool_end = 0u64;

        if mnemonic == "adr" {
            if let Some(&ArmOp::Imm(value)) = ops.get(1) {
                refs.push(DataRef {
                    addr: value as u64,
                    width: 1,
                });
            }
        } else {
            pool_end = self.arm32_literal_load(ops, &mnemonic, addr, thumb, state, &mut refs);
            if pool_end == 0 && !pc_arithmetic {
                self.arm32_pc_add(ops, &mnemonic, addr, thumb, state, &mut refs);
            }
            if mnemonic == "pop"
                || mnemonic == "push"
                || mnemonic.starts_with("ldm")
                || mnemonic.starts_with("stm")
            {
                let exits = mnemonic == "pop" || mnemonic.starts_with("ldm");
                kind = arm32_stack_exit(ops, conditional, exits);
            } else if mnemonic == "b" {
                kind = if conditional {
                    Kind::CondJump
                } else {
                    Kind::Jump
                };
                target = arm_target(ops);
                if kind == Kind::Jump {
                    callee = self.callee_name(target, depth);
                }
            } else if mnemonic == "bx" {
                if indirect_target.is_some() {
                    kind = Kind::Jump;
                    target = indirect_target;
                } else if matches!(ops.first(), Some(ArmOp::Reg(reg)) if *reg == LR) {
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
                target = ops
                    .last()
                    .and_then(|operand| match operand {
                        ArmOp::Imm(value) => Some(*value as u64),
                        _ => None,
                    })
                    .or(indirect_target);
                if target.is_some() {
                    callee = self.callee_name(target, depth);
                }
                if self.noreturn(callee.as_deref()) {
                    kind = Kind::NoreturnCall;
                }
            } else if ARM32_CONDITIONAL_JUMPS.contains(&mnemonic.as_str()) {
                kind = Kind::CondJump;
                target = arm_target(ops);
            } else if ARM32_BRANCH_TABLE.contains(&mnemonic.as_str()) {
                kind = Kind::Jump;
            } else if ARM32_TRAP.contains(&mnemonic.as_str()) {
                kind = Kind::Trap;
            } else if mnemonic == "mov" && moves_pc(ops) {
                kind = Kind::Ret;
            }
        }

        if kind != Kind::Normal {
            // Control transfers end the window in which a partial value can
            // still be completed; calls also clobber the argument registers.
            pending.extend(state.take_consts());
        }
        let mut consts = pending;
        if kind == Kind::Normal {
            consts.extend(arm32_immediate_consts(ops));
        }

        Insn {
            addr,
            size,
            op: arm32_class(&mnemonic, conditional, ops, vector),
            kind,
            consts: sorted_unique(consts),
            refs,
            callee,
            target,
            pool_end,
            padding: false,
        }
    }

    /// `movw`/`movt` materialise one 32-bit constant across two instructions.
    fn arm32_materialize(
        &self,
        ops: &[ArmOp],
        mnemonic: &str,
        addr: u64,
        size: usize,
        state: &mut ArmState,
    ) -> Option<Insn> {
        if mnemonic != "movw" && mnemonic != "movt" {
            return None;
        }
        let (Some(&ArmOp::Reg(destination)), Some(&ArmOp::Imm(immediate))) =
            (ops.first(), ops.get(1))
        else {
            return None;
        };
        let value = if mnemonic == "movt" {
            let previous = state
                .take(reg_key(destination))
                .filter(|pending| !pending.is_page)
                .map_or(0, |pending| pending.value);
            previous | (((immediate as u64) & 0xFFFF) << 16)
        } else {
            (immediate as u64) & 0xFFFF
        };
        // `movw` starts a new value; one still pending in the register was
        // complete and is evidence, not something to overwrite silently.
        let replaced = state.take_consts_in(&[reg_key(destination)]);
        state.insert(
            reg_key(destination),
            PendingValue {
                value: value & MASK32,
                is_page: false,
                width: 4,
            },
        );
        Some(Insn {
            consts: replaced,
            ..Insn::normal(addr, size, OpClass::Move)
        })
    }

    /// Resolve `ldr rd, [pc, #imm]` against the function's literal pool.
    ///
    /// A pool cell holding a pointer becomes a reference to the target (the
    /// string or table the compiler pooled); any other word becomes a pending
    /// 32-bit constant, matching how `movw`/`movt` pairs flush. Returns the end
    /// of the referenced cell, or 0 when this is not a literal load.
    fn arm32_literal_load(
        &self,
        ops: &[ArmOp],
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
            let ArmOp::Mem {
                base,
                index: offset_register,
                disp,
            } = operand
            else {
                continue;
            };
            if *base != PC {
                continue;
            }
            if index == 0 {
                return 0;
            }
            // GCC's arm32 PIC loads a global through `ldr rd, [pc, rm]` with a
            // pooled offset in `rm`. The word at the PC is the next instruction,
            // not pool data, so resolve the slot from the offset or record nothing.
            if offset_register.0 != 0 {
                if let Some(held) = state.take(reg_key(*offset_register)) {
                    if !held.is_page && !thumb {
                        refs.push(DataRef {
                            addr: addr.wrapping_add(8).wrapping_add(held.value) & MASK32,
                            width: 4,
                        });
                    }
                }
                return 0;
            }
            let ArmOp::Reg(destination) = ops[index - 1] else {
                return 0;
            };
            let literal = pc_value(addr, thumb).wrapping_add_signed(*disp);
            let Some(value) = self.read_pointer32(literal) else {
                return 0;
            };
            if is_address(self.source, literal, 4, value) {
                refs.push(DataRef {
                    addr: value,
                    width: 4,
                });
            } else {
                state.insert(
                    reg_key(destination),
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
        ops: &[ArmOp],
        mnemonic: &str,
        addr: u64,
        thumb: bool,
        state: &mut ArmState,
        refs: &mut Vec<DataRef>,
    ) {
        if !ops
            .iter()
            .any(|operand| matches!(operand, ArmOp::Reg(reg) if *reg == PC))
        {
            return;
        }
        let base = pc_value(addr, thumb);
        let subtracting = mnemonic.starts_with('s') || mnemonic.starts_with('r');
        let immediate = ops.iter().find_map(|operand| match operand {
            ArmOp::Imm(value) => Some(*value as u64),
            _ => None,
        });
        // The Thumb two-operand form `add rd, pc` reads the offset from `rd`.
        let sources = if ops.len() == 2 { 0 } else { 1 };
        for operand in ops.iter().skip(sources) {
            let ArmOp::Reg(register) = operand else {
                continue;
            };
            if *register == PC {
                continue;
            }
            let Some(held) = state.take(reg_key(*register)) else {
                continue;
            };
            if held.is_page {
                continue;
            }
            // Only literal loads and `adr` see the word-aligned PC; a Thumb
            // register add reads it unaligned, so the PIC `add rd, pc` would
            // otherwise land two bytes early whenever it sits at addr % 4 == 2.
            let register_base = if thumb { addr + 4 } else { base };
            let resolved = if subtracting {
                register_base.wrapping_sub(held.value)
            } else {
                register_base.wrapping_add(held.value)
            } & MASK32;
            refs.push(DataRef {
                addr: resolved,
                width: 4,
            });
            // Keep an address marker so the intermediate never flushes as a
            // constant, but let later arithmetic still see the value.
            if let Some(&ArmOp::Reg(destination)) = ops.first() {
                state.insert(
                    reg_key(destination),
                    PendingValue {
                        value: resolved,
                        is_page: true,
                        width: 4,
                    },
                );
            }
            return;
        }
        if let Some(&ArmOp::Reg(destination)) = ops.first() {
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
                    reg_key(destination),
                    PendingValue {
                        value: resolved,
                        is_page: true,
                        width: 4,
                    },
                );
            } else {
                state.insert(
                    reg_key(destination),
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

/// `pop {..., pc}` and `ldm ... pc` return; everything else is stack.
///
/// A conditional return is a conditional exit, never an unconditional
/// terminator: the block continues when the predicate is false.
fn arm32_stack_exit(ops: &[ArmOp], conditional: bool, exits: bool) -> Kind {
    if exits
        && ops
            .iter()
            .any(|operand| matches!(operand, ArmOp::Reg(reg) if *reg == PC))
    {
        return if conditional {
            Kind::CondJump
        } else {
            Kind::Ret
        };
    }
    Kind::Normal
}
