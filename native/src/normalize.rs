//! Instruction normalization: project x86-64 and AArch64 onto one vocabulary.
//!
//! Two rules drive everything here:
//!
//! * Features must not contain addresses. RIP-relative operands and absolute
//!   displacements are resolved to a target address, then either kept as a
//!   data reference (an anchor) or dropped.
//! * Instructions that compilers or mitigations insert for alignment,
//!   hardening, or patching carry no signal, so they are marked `Ignored`.
//!
//! The rules mirror `core/normalize.py`; iced-x86 and yaxpeax-arm replace
//! Capstone, so the mnemonic and operand projections are kept explicit.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use yaxpeax_arm::armv8::a64::InstDecoder;

use crate::arch::Arch;
use crate::source::ByteSource;
use crate::spec::MAX_THUNK_HOPS;

pub const MASK64: u64 = u64::MAX;
pub const MASK32: u64 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpClass {
    Move,
    Arith,
    Mul,
    Logic,
    Cmp,
    Load,
    Store,
    Stack,
    Branch,
    Call,
    Ret,
    Cond,
    Vector,
    Misc,
}

impl OpClass {
    pub fn as_str(self) -> &'static str {
        match self {
            OpClass::Move => "move",
            OpClass::Arith => "arith",
            OpClass::Mul => "mul",
            OpClass::Logic => "logic",
            OpClass::Cmp => "cmp",
            OpClass::Load => "load",
            OpClass::Store => "store",
            OpClass::Stack => "stack",
            OpClass::Branch => "branch",
            OpClass::Call => "call",
            OpClass::Ret => "ret",
            OpClass::Cond => "cond",
            OpClass::Vector => "vector",
            OpClass::Misc => "misc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Normal,
    Ignored,
    Call,
    NoreturnCall,
    Jump,
    CondJump,
    Ret,
    Trap,
}

impl Kind {
    pub fn is_terminating(self) -> bool {
        matches!(self, Kind::Ret | Kind::Jump | Kind::CondJump | Kind::Trap)
    }
}

/// A reference to bytes outside the instruction stream (string, table, slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRef {
    pub addr: u64,
    pub width: usize,
}

/// One instruction reduced to architecture-neutral facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    pub addr: u64,
    pub size: usize,
    pub op: OpClass,
    pub kind: Kind,
    pub consts: Vec<u64>,
    pub refs: Vec<DataRef>,
    pub callee: Option<String>,
    pub target: Option<u64>,
    /// End of a literal-pool cell this instruction reads (ARM32 only).
    pub pool_end: u64,
}

impl Insn {
    pub fn normal(addr: u64, size: usize, op: OpClass) -> Insn {
        Insn {
            addr,
            size,
            op,
            kind: Kind::Normal,
            consts: Vec::new(),
            refs: Vec::new(),
            callee: None,
            target: None,
            pool_end: 0,
        }
    }

    pub fn ignored(addr: u64, size: usize) -> Insn {
        Insn {
            addr,
            size,
            op: OpClass::Misc,
            kind: Kind::Ignored,
            consts: Vec::new(),
            refs: Vec::new(),
            callee: None,
            target: None,
            pool_end: 0,
        }
    }
}

/// A register value materialised in a block but not yet observed.
#[derive(Clone, Copy)]
pub(crate) struct PendingValue {
    pub(crate) value: u64,
    pub(crate) is_page: bool,
    pub(crate) width: usize,
}

/// Register values produced by `adrp`, `movz`/`movk` chains, literal loads, and
/// `movw`/`movt` pairs, kept until the instruction that consumes them (or the
/// block end).
#[derive(Default)]
pub(crate) struct ArmState {
    values: Vec<(u16, PendingValue)>,
}

impl ArmState {
    pub(crate) fn insert(&mut self, register: u16, pending: PendingValue) {
        match self.values.iter_mut().find(|(slot, _)| *slot == register) {
            Some(slot) => slot.1 = pending,
            None => self.values.push((register, pending)),
        }
    }

    pub(crate) fn get(&self, register: u16) -> Option<PendingValue> {
        self.values
            .iter()
            .find(|(slot, _)| *slot == register)
            .map(|(_, pending)| *pending)
    }

    pub(crate) fn take(&mut self, register: u16) -> Option<PendingValue> {
        let index = self.values.iter().position(|(slot, _)| *slot == register)?;
        Some(self.values.swap_remove(index).1)
    }

    /// Consume pending constants, keeping unresolved page markers: a page that
    /// is never consumed is an address and must never flush as a constant.
    pub(crate) fn take_consts(&mut self) -> Vec<u64> {
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

    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }
}

/// Normalise an immediate so equal source constants compare equal.
///
/// Compilers materialise `-1` as `mov rax, -1` on one path and `mov eax, -1`
/// on another; both must hash the same. Values in the 32-bit range are stored
/// sign-extended to 64 bits.
pub fn canonical_const(value: u64, width: usize) -> u64 {
    let value = value & MASK64;
    if width > 4 {
        return value;
    }
    let narrow = value & MASK32;
    if narrow & 0x8000_0000 != 0 {
        (narrow.wrapping_sub(0x1_0000_0000)) & MASK64
    } else {
        narrow
    }
}

const X86_STACK_REGS: [&str; 6] = ["rsp", "esp", "sp", "rbp", "ebp", "sbp"];

const NORETURN_NAMES: [&str; 20] = [
    "exit",
    "_exit",
    "quick_exit",
    "abort",
    "longjmp",
    "siglongjmp",
    "terminate",
    "__cxa_throw",
    "__cxa_rethrow",
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__assert_fail",
    "__assert_rtn",
    "__fortify_fail",
    "panic",
    "ExitProcess",
    "ExitThread",
    "TerminateProcess",
    "RaiseException",
    "__security_failfast",
];

#[derive(Debug, Clone, Copy)]
enum Operand {
    Reg(Register),
    Imm {
        value: u64,
        width: usize,
    },
    Branch(u64),
    Mem {
        base: Register,
        index: Register,
        disp: u64,
        size: usize,
    },
}

pub struct Normalizer<'a, S: ByteSource + ?Sized> {
    pub(crate) source: &'a S,
    pub(crate) arm64: InstDecoder,
}

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    pub fn new(source: &'a S) -> Normalizer<'a, S> {
        Normalizer {
            source,
            arm64: InstDecoder::default(),
        }
    }

    /// Decode a straight-line run starting at `addr`, stopping at a terminator.
    pub fn decode_block(&self, addr: u64, max_bytes: usize) -> Vec<Insn> {
        self.decode_block_depth(addr, max_bytes, 0)
    }

    fn decode_block_depth(&self, addr: u64, max_bytes: usize, depth: usize) -> Vec<Insn> {
        if max_bytes == 0 {
            return Vec::new();
        }
        if self.source.arch() == Arch::Arm64 {
            return self.arm64_block(addr, max_bytes, depth);
        }
        if self.source.arch().is_arm() {
            return self.arm32_block(addr, max_bytes, depth);
        }
        let data = self.source.read_partial(addr, max_bytes);
        if data.is_empty() {
            return Vec::new();
        }
        let mut decoder = Decoder::with_ip(64, &data, addr, DecoderOptions::NONE);
        let mut out = Vec::new();
        while decoder.can_decode() {
            let mut raw = Instruction::default();
            decoder.decode_out(&mut raw);
            if raw.is_invalid() {
                break;
            }
            let insn = self.x86(&raw, depth);
            let terminating = insn.kind.is_terminating();
            out.push(insn);
            if terminating {
                break;
            }
        }
        out
    }

    /// Decode exactly one instruction; used for thunk following.
    pub fn normalize_one(&self, addr: u64) -> Option<Insn> {
        self.normalize_one_depth(addr, 0)
    }

    fn normalize_one_depth(&self, addr: u64, depth: usize) -> Option<Insn> {
        self.decode_block_depth(addr, 16, depth).into_iter().next()
    }

    pub(crate) fn callee_name(&self, target: Option<u64>, depth: usize) -> Option<String> {
        let target = target?;
        let resolved = self.follow_thunk(target, depth)?;
        self.source.label_for_address(resolved)
    }

    pub(crate) fn read_pointer(&self, addr: Option<u64>) -> Option<u64> {
        let addr = addr?;
        let size = self.source.arch().pointer_size();
        let data = self.source.try_read(addr, size)?;
        if data.len() < size {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes[..size].copy_from_slice(&data[..size]);
        Some(u64::from_le_bytes(bytes))
    }

    fn import_name(&self, addr: u64) -> Option<String> {
        for module in self.source.modules() {
            if module.contains(addr, 1) {
                if let Some(name) = module.imports.get(&addr) {
                    return Some(name.clone());
                }
            }
        }
        None
    }

    /// Resolve a callee through an IAT/GOT slot or a pointer cell.
    fn slot_callee(&self, slot: Option<u64>, depth: usize) -> Option<String> {
        let slot = slot?;
        if let Some(name) = self.import_name(slot) {
            return Some(name);
        }
        self.callee_name(self.read_pointer(Some(slot)), depth)
    }

    /// Resolve jump thunks, PLT stubs, and `ldr x16; br x16` veneers.
    fn follow_thunk(&self, target: u64, depth: usize) -> Option<u64> {
        if depth >= MAX_THUNK_HOPS {
            return Some(target);
        }
        let mut current = target;
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..MAX_THUNK_HOPS {
            if seen.contains(&current) {
                return Some(current);
            }
            seen.push(current);
            if self.source.name_for_address(current).is_some() {
                return Some(current);
            }
            let Some(first) = self.normalize_one_depth(current, depth + 1) else {
                return Some(current);
            };
            if first.kind != Kind::Jump {
                return Some(current);
            }
            if let Some(next) = first.target {
                current = next;
                continue;
            }
            if let Some(reference) = first.refs.first() {
                if let Some(next) = self.read_pointer(Some(reference.addr)) {
                    current = next;
                    continue;
                }
            }
            return Some(current);
        }
        Some(current)
    }

    pub(crate) fn noreturn(&self, callee: Option<&str>) -> bool {
        let Some(callee) = callee else {
            return false;
        };
        let symbol = callee.rsplit('!').next().unwrap_or(callee);
        let symbol = symbol.split('@').next().unwrap_or(symbol);
        let symbol = symbol.trim_start_matches('_');
        NORETURN_NAMES.contains(&symbol)
    }

    // -- x86-64 ------------------------------------------------------------

    fn x86(&self, raw: &Instruction, depth: usize) -> Insn {
        let mnemonic = mnemonic_name(raw.mnemonic());
        let operands = collect_operands(raw);
        let addr = raw.ip();
        let size = raw.len();

        if is_x86_ignored(&mnemonic) || x86_is_hotpatch(&mnemonic, &operands) {
            return Insn::ignored(addr, size);
        }

        let mut kind = Kind::Normal;
        let mut refs: Vec<DataRef> = Vec::new();
        let mut consts: Vec<u64> = Vec::new();
        let mut callee: Option<String> = None;
        let mut target: Option<u64> = None;

        for operand in &operands {
            if let Operand::Mem {
                base,
                disp,
                size: width,
                ..
            } = *operand
            {
                if base == Register::RIP {
                    refs.push(DataRef {
                        addr: raw.ip_rel_memory_address(),
                        width: width.max(1),
                    });
                } else if base == Register::None
                    && disp != 0
                    && self.source.module_for(disp).is_some()
                {
                    // A naked absolute displacement is only useful as a
                    // reference; otherwise it is an address and must not leak
                    // into features.
                    refs.push(DataRef {
                        addr: disp,
                        width: width.max(1),
                    });
                }
            }
        }

        if mnemonic == "call" || mnemonic == "lcall" {
            kind = Kind::Call;
            match operands.first() {
                Some(Operand::Imm { value, .. }) | Some(Operand::Branch(value)) => {
                    target = Some(*value);
                    callee = self.callee_name(target, depth);
                }
                Some(Operand::Mem { .. }) => {
                    callee = self.slot_callee(refs.first().map(|reference| reference.addr), depth);
                }
                _ => {}
            }
            if self.noreturn(callee.as_deref()) {
                kind = Kind::NoreturnCall;
            }
        } else if mnemonic == "jmp" || mnemonic == "ljmp" {
            kind = Kind::Jump;
            match operands.first() {
                Some(Operand::Imm { value, .. }) | Some(Operand::Branch(value)) => {
                    target = Some(*value);
                    callee = self.callee_name(target, depth);
                }
                Some(Operand::Mem { .. }) => {
                    callee = self.slot_callee(refs.first().map(|reference| reference.addr), depth);
                }
                _ => {}
            }
        } else if mnemonic.starts_with('j') || mnemonic.starts_with("loop") {
            kind = Kind::CondJump;
            if let Some(Operand::Imm { value, .. }) | Some(Operand::Branch(value)) =
                operands.first()
            {
                target = Some(*value);
            }
        } else if is_x86_trap(&mnemonic) {
            kind = Kind::Trap;
        } else if is_x86_ret(&mnemonic) {
            kind = Kind::Ret;
        }

        for operand in &operands {
            if let Operand::Imm { value, width } = *operand {
                if self.x86_const_candidate(&mnemonic, &operands) {
                    consts.push(canonical_const(value, width));
                }
            }
        }

        Insn {
            addr,
            size,
            op: self.x86_class(raw, &mnemonic, &operands),
            kind,
            consts: sorted_unique(consts),
            refs,
            callee,
            target,
            pool_end: 0,
        }
    }

    fn x86_const_candidate(&self, mnemonic: &str, operands: &[Operand]) -> bool {
        if !is_x86_const_mnemonic(mnemonic) {
            return false;
        }
        // Stack adjustments and frame arithmetic encode ABI, not program logic.
        !x86_touches_stack_pointer(operands)
    }

    fn x86_class(&self, raw: &Instruction, mnemonic: &str, operands: &[Operand]) -> OpClass {
        if x86_is_vector(operands) {
            return OpClass::Vector;
        }
        if mnemonic == "jmp" || mnemonic == "ljmp" {
            return OpClass::Branch;
        }
        if mnemonic.starts_with('j') || mnemonic.starts_with("loop") {
            return OpClass::Cond;
        }
        if mnemonic == "call" || mnemonic == "lcall" {
            return OpClass::Call;
        }
        if is_x86_ret(mnemonic) {
            return OpClass::Ret;
        }
        if matches!(mnemonic, "push" | "pop" | "enter" | "leave") {
            return OpClass::Stack;
        }
        if mnemonic.starts_with("cmov") {
            return OpClass::Move;
        }
        if mnemonic.len() == 4 && mnemonic.starts_with("set") {
            return OpClass::Cond;
        }
        let memory = x86_memory_class(operands);
        if mnemonic == "cmp" || mnemonic == "test" {
            return OpClass::Cmp;
        }
        if is_x86_mul(mnemonic) {
            return OpClass::Mul;
        }
        if is_x86_logic(mnemonic) {
            return OpClass::Logic;
        }
        if is_x86_arith(mnemonic) {
            return OpClass::Arith;
        }
        if mnemonic.starts_with("mov") || mnemonic == "xchg" || mnemonic == "bswap" {
            return memory.unwrap_or(OpClass::Move);
        }
        if mnemonic == "lea" {
            // Address materialisation, matching AArch64 `adrp`+`add`.
            return OpClass::Move;
        }
        if mnemonic.starts_with("stos") {
            return OpClass::Store;
        }
        if mnemonic.starts_with("movs")
            || mnemonic.starts_with("lods")
            || mnemonic.starts_with("scas")
            || mnemonic.starts_with("cmps")
        {
            return OpClass::Load;
        }
        let _ = raw;
        memory.unwrap_or(OpClass::Misc)
    }
}

pub(crate) fn sorted_unique(mut values: Vec<u64>) -> Vec<u64> {
    values.sort_unstable();
    values.dedup();
    values
}

fn mnemonic_name(mnemonic: Mnemonic) -> String {
    format!("{mnemonic:?}").to_ascii_lowercase()
}

fn register_name(register: Register) -> String {
    if register == Register::None {
        return String::new();
    }
    if register.is_st() {
        // Capstone renders x87 registers as `st(0)`; keep that spelling so the
        // vector-register prefix rule is identical across decoders.
        return format!("st({})", register.number());
    }
    format!("{register:?}").to_ascii_lowercase()
}

fn collect_operands(raw: &Instruction) -> Vec<Operand> {
    let mut operands = Vec::with_capacity(raw.op_count() as usize);
    let memory_size = raw.memory_size().size();
    for index in 0..raw.op_count() {
        let kind = raw.op_kind(index);
        let operand = match kind {
            OpKind::Register => Operand::Reg(raw.op_register(index)),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Operand::Branch(raw.near_branch_target())
            }
            OpKind::Immediate8 | OpKind::Immediate8_2nd => Operand::Imm {
                value: raw.immediate(index),
                width: 1,
            },
            OpKind::Immediate16 | OpKind::Immediate8to16 => Operand::Imm {
                value: raw.immediate(index),
                width: 2,
            },
            OpKind::Immediate32 | OpKind::Immediate8to32 => Operand::Imm {
                value: raw.immediate(index),
                width: 4,
            },
            OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
                Operand::Imm {
                    value: raw.immediate(index),
                    width: 8,
                }
            }
            OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => Operand::Mem {
                base: memory_base(kind, raw.memory_base()),
                index: raw.memory_index(),
                disp: raw.memory_displacement64(),
                size: memory_size,
            },
            _ => continue,
        };
        operands.push(operand);
    }
    operands
}

fn memory_base(kind: OpKind, stored: Register) -> Register {
    match kind {
        OpKind::MemorySegSI => Register::SI,
        OpKind::MemorySegESI => Register::ESI,
        OpKind::MemorySegRSI => Register::RSI,
        OpKind::MemorySegDI => Register::DI,
        OpKind::MemorySegEDI => Register::EDI,
        OpKind::MemorySegRDI => Register::RDI,
        OpKind::MemoryESDI => Register::DI,
        OpKind::MemoryESEDI => Register::EDI,
        OpKind::MemoryESRDI => Register::RDI,
        _ => stored,
    }
}

fn x86_is_hotpatch(mnemonic: &str, operands: &[Operand]) -> bool {
    // `mov edi, edi` is five bytes a prologue hooks into; it carries no signal.
    // A same-register `test`/`cmp` is real comparison code, so the mnemonic
    // gate matters.
    if mnemonic != "mov" || operands.len() != 2 {
        return false;
    }
    match (operands[0], operands[1]) {
        (Operand::Reg(first), Operand::Reg(second)) => first == second,
        _ => false,
    }
}

fn x86_touches_stack_pointer(operands: &[Operand]) -> bool {
    operands.iter().any(|operand| match *operand {
        Operand::Reg(register) => X86_STACK_REGS.contains(&register_name(register).as_str()),
        Operand::Mem { base, index, .. } => {
            X86_STACK_REGS.contains(&register_name(base).as_str())
                || X86_STACK_REGS.contains(&register_name(index).as_str())
        }
        _ => false,
    })
}

fn x86_is_vector(operands: &[Operand]) -> bool {
    operands.iter().any(|operand| match *operand {
        Operand::Reg(register) => {
            let name = register_name(register);
            name.starts_with("xmm")
                || name.starts_with("ymm")
                || name.starts_with("zmm")
                || name.starts_with("mm")
                || name.starts_with("st(")
                || name.starts_with('k')
        }
        _ => false,
    })
}

fn x86_memory_class(operands: &[Operand]) -> Option<OpClass> {
    for (index, operand) in operands.iter().enumerate() {
        if let Operand::Mem {
            base, index: idx, ..
        } = *operand
        {
            let base_name = register_name(base);
            let index_name = register_name(idx);
            if X86_STACK_REGS.contains(&base_name.as_str())
                || X86_STACK_REGS.contains(&index_name.as_str())
            {
                return Some(OpClass::Stack);
            }
            return Some(if index == 0 {
                OpClass::Store
            } else {
                OpClass::Load
            });
        }
    }
    None
}

fn is_x86_ignored(mnemonic: &str) -> bool {
    matches!(mnemonic, "nop" | "endbr64" | "endbr32" | "int3" | "fnop")
}

fn is_x86_ret(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ret" | "retf" | "retn" | "iret" | "iretd" | "iretq" | "sysret" | "sysexit"
    )
}

fn is_x86_trap(mnemonic: &str) -> bool {
    matches!(mnemonic, "ud2" | "hlt" | "int" | "int1")
}

fn is_x86_mul(mnemonic: &str) -> bool {
    matches!(mnemonic, "imul" | "mul" | "idiv" | "div")
}

fn is_x86_logic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "and"
            | "or"
            | "xor"
            | "not"
            | "neg"
            | "shl"
            | "shr"
            | "sar"
            | "sal"
            | "rol"
            | "ror"
            | "rcl"
            | "rcr"
            | "bt"
            | "bts"
            | "btr"
            | "btc"
            | "bsf"
            | "bsr"
            | "lzcnt"
            | "tzcnt"
            | "popcnt"
            | "andn"
            | "bextr"
            | "blsi"
            | "blsr"
            | "blsmsk"
    )
}

fn is_x86_arith(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "add" | "sub" | "adc" | "sbb" | "inc" | "dec" | "xadd"
    )
}

fn is_x86_const_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov"
            | "movabs"
            | "movzx"
            | "movsx"
            | "movsxd"
            | "cmp"
            | "test"
            | "and"
            | "or"
            | "xor"
            | "imul"
            | "add"
            | "sub"
            | "adc"
            | "sbb"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_const_is_idempotent() {
        assert_eq!(canonical_const(0xFFFF_FFFF, 4), u64::MAX);
        assert_eq!(canonical_const(u64::MAX, 4), u64::MAX);
        assert_eq!(canonical_const(0x8000_0000, 4), 0xFFFF_FFFF_8000_0000);
        assert_eq!(canonical_const(0x1_0000_0000, 8), 0x1_0000_0000);
    }

    #[test]
    fn mnemonic_spelling_matches_capstone_projection() {
        assert_eq!(mnemonic_name(Mnemonic::Jne), "jne");
        assert_eq!(mnemonic_name(Mnemonic::Endbr64), "endbr64");
        assert_eq!(mnemonic_name(Mnemonic::Movsxd), "movsxd");
        assert_eq!(mnemonic_name(Mnemonic::Iretd), "iretd");
    }
}
