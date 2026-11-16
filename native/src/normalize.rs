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
use crate::arm32::ARM32_HANDLE_DEPTHS;
use crate::source::ByteSource;
use crate::spec::MAX_THUNK_HOPS;
use crate::stubs::{arm32_stub, arm64_stub, StubExit, MAX_STUB_BYTES};

/// What a branch target resolves to after following stubs.
enum Resolved {
    Import(String),
    Address(u64),
}

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
    /// Filler rather than a real entry marker. Alignment NOPs and `int3`
    /// padding are skipped by features, but they are not where a function
    /// starts; `endbr64`, `bti`, and `mov edi, edi` are ignored for features
    /// yet do mark an entry, so they stay false. Candidate discovery uses this
    /// to avoid reporting a function at the padding before it.
    pub padding: bool,
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
            padding: false,
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
            padding: false,
        }
    }

    /// An ignored instruction that is alignment filler, not an entry marker.
    pub fn filler(addr: u64, size: usize) -> Insn {
        Insn {
            padding: true,
            ..Insn::ignored(addr, size)
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
    /// Registers loaded from a page-relative pointer slot (`adrp` + `ldr`),
    /// with the slot: `-fno-plt` calls go `ldr x8, [x8, :got_lo12:f]; blr
    /// x8`, so the slot names the callee.
    slots: Vec<(u16, u64)>,
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

    /// Consume the pending constants held in `registers` only.
    ///
    /// Compilers schedule other work between the halves of a `movw`/`movt`
    /// pair or a `movz`/`movk` chain, so an instruction that does not name a
    /// register must leave that register's partial value pending; flushing it
    /// would split one constant into two unrelated fragments.
    pub(crate) fn take_consts_in(&mut self, registers: &[u16]) -> Vec<u64> {
        let mut values: Vec<u64> = Vec::new();
        self.values.retain(|(register, pending)| {
            if pending.is_page || !registers.contains(register) {
                return true;
            }
            values.push(canonical_const(pending.value, pending.width));
            false
        });
        values.sort_unstable();
        values
    }

    pub(crate) fn clear(&mut self) {
        self.values.clear();
        self.slots.clear();
    }

    pub(crate) fn insert_slot(&mut self, register: u16, slot: u64) {
        self.forget_slots(&[register]);
        self.slots.push((register, slot));
    }

    pub(crate) fn take_slot(&mut self, register: u16) -> Option<u64> {
        let index = self.slots.iter().position(|(held, _)| *held == register)?;
        Some(self.slots.swap_remove(index).1)
    }

    pub(crate) fn clear_slots(&mut self) {
        self.slots.clear();
    }

    /// Any other use of a register may overwrite it, so its slot is dropped.
    pub(crate) fn forget_slots(&mut self, registers: &[u16]) {
        self.slots.retain(|(held, _)| !registers.contains(held));
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
    /// Capstone handles for ARM32 `[arm, thumb]`, one per decode depth
    /// (see `arm32_block`), opened on first use: opening one allocates and
    /// initialises the decoder tables, which cost more than decoding a
    /// typical basic block.
    pub(crate) arm32: [[ArmHandle; ARM32_HANDLE_DEPTHS]; 2],
}

type ArmHandle = std::cell::OnceCell<Option<capstone::Capstone>>;

impl<'a, S: ByteSource + ?Sized> Normalizer<'a, S> {
    pub fn new(source: &'a S) -> Normalizer<'a, S> {
        Normalizer {
            source,
            arm64: InstDecoder::default(),
            arm32: Default::default(),
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

    /// Name the function a direct branch reaches, through stubs and veneers.
    ///
    /// Only names are returned: an unnamed target's `module+rva` label is a
    /// layout address, which never matches another build and must not become
    /// a feature.
    pub(crate) fn callee_name(&self, target: Option<u64>, depth: usize) -> Option<String> {
        match self.follow_thunk(target?, depth) {
            Resolved::Import(name) => Some(name),
            Resolved::Address(address) => self.source.name_for_address(address),
        }
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
    pub(crate) fn slot_callee(&self, slot: Option<u64>, depth: usize) -> Option<String> {
        let slot = slot?;
        if let Some(name) = self.import_name(slot) {
            return Some(name);
        }
        self.callee_name(self.read_pointer(Some(slot)), depth)
    }

    /// Resolve jump thunks, PLT stubs, and veneers to an import or a target.
    ///
    /// Each hop checks the slot a stub jumps through for an import relocation
    /// before reading it: with lazy binding the slot still points back into
    /// the PLT, so reading it would only find the resolver trampoline.
    fn follow_thunk(&self, target: u64, depth: usize) -> Resolved {
        if depth >= MAX_THUNK_HOPS {
            return Resolved::Address(target);
        }
        let mut current = target;
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..MAX_THUNK_HOPS {
            if seen.contains(&current) {
                break;
            }
            seen.push(current);
            // Linker thunks keep a `.symtab` name in unstripped images
            // (`__ThumbV7PILongThunk_f`, `__f_veneer`); stopping there would
            // name the thunk, which a stripped copy cannot, instead of `f`.
            if self
                .source
                .name_for_address(current)
                .is_some_and(|name| !crate::stubs::linker_thunk_name(&name))
            {
                break;
            }
            let next = match self.stub_exit(current, depth) {
                Some(StubExit::Direct(next)) => next,
                Some(StubExit::Slot(slot)) => {
                    if let Some(name) = self.import_name(slot) {
                        return Resolved::Import(name);
                    }
                    match self.read_pointer(Some(slot)) {
                        Some(next) => next,
                        None => break,
                    }
                }
                None => break,
            };
            // A pointer into Thumb code carries the interworking bit.
            current = if self.source.arch().is_arm() {
                next & !1
            } else {
                next
            };
        }
        Resolved::Address(current)
    }

    /// Where the stub at `addr` jumps, if `addr` holds one.
    fn stub_exit(&self, addr: u64, depth: usize) -> Option<StubExit> {
        match self.source.arch() {
            Arch::Arm64 | Arch::Arm32 | Arch::Thumb => {
                let data = self.source.read_partial(addr, MAX_STUB_BYTES);
                let matched = if self.source.arch() == Arch::Arm64 {
                    arm64_stub(addr, &data)
                } else {
                    arm32_stub(addr, &data)
                };
                if matched.is_some() {
                    return matched;
                }
                // Any other single-branch thunk the decoder resolves.
                let first = if self.source.arch() == Arch::Arm64 {
                    self.normalize_one_depth(addr, depth + 1)?
                } else {
                    self.arm32_first(addr, 16, depth + 1)?
                };
                (first.kind == Kind::Jump)
                    .then_some(first.target)
                    .flatten()
                    .map(StubExit::Direct)
            }
            _ => {
                // `endbr64` (and `bnd`-prefixed IBT PLTs) precede the jump.
                let first = self
                    .decode_block_depth(addr, 16, depth + 1)
                    .into_iter()
                    .find(|insn| insn.kind != Kind::Ignored)?;
                if first.kind != Kind::Jump {
                    return None;
                }
                if let Some(next) = first.target {
                    return Some(StubExit::Direct(next));
                }
                first
                    .refs
                    .first()
                    .map(|reference| StubExit::Slot(reference.addr))
            }
        }
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

        if is_x86_ignored(mnemonic) || x86_is_hotpatch(mnemonic, &operands) {
            // Multi-byte NOPs and `int3` are alignment filler; `endbr64` and the
            // `mov edi, edi` hot-patch mark a real entry and keep their address.
            return if mnemonic == "nop" || mnemonic == "int3" {
                Insn::filler(addr, size)
            } else {
                Insn::ignored(addr, size)
            };
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

        // Capstone spells CET's `notrack` prefix into the mnemonic
        // ("notrack jmp"), so the reference never enters its branch arm and
        // reads the instruction as ordinary flow. iced drops the prefix and
        // reports a plain jump; restore the reference reading so recovery does
        // not stop at a jump the reference continues past.
        if raw.segment_prefix() == Register::DS && (mnemonic == "jmp" || mnemonic == "call") {
            return Insn {
                addr,
                size,
                op: OpClass::Misc,
                kind: Kind::Normal,
                consts: Vec::new(),
                refs,
                callee: None,
                target: None,
                pool_end: 0,
                padding: false,
            };
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
        } else if is_x86_trap(mnemonic) {
            kind = Kind::Trap;
        } else if is_x86_ret(mnemonic) {
            kind = Kind::Ret;
        }

        for operand in &operands {
            if let Operand::Imm { value, width } = *operand {
                if self.x86_const_candidate(mnemonic, &operands) {
                    consts.push(canonical_const(value, width));
                }
            }
        }

        Insn {
            addr,
            size,
            op: self.x86_class(raw, mnemonic, &operands),
            kind,
            consts: sorted_unique(consts),
            refs,
            callee,
            target,
            pool_end: 0,
            padding: false,
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

/// Lowercase mnemonic spelling, from a table built once: formatting the
/// enum's `Debug` name per decoded instruction was a measurable share of a
/// whole-image x64 sweep.
fn mnemonic_name(mnemonic: Mnemonic) -> &'static str {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        Mnemonic::values()
            .map(|value| format!("{value:?}").to_ascii_lowercase())
            .collect()
    })[mnemonic as usize]
        .as_str()
}

/// Lowercase register spelling, from a table built once (see
/// [`mnemonic_name`]).
fn register_name(register: Register) -> &'static str {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        Register::values()
            .map(|value| {
                if value == Register::None {
                    String::new()
                } else if value.is_st() {
                    // Capstone renders x87 registers as `st(0)`; keep that
                    // spelling so the vector-register prefix rule is identical
                    // across decoders.
                    format!("st({})", value.number())
                } else {
                    format!("{value:?}").to_ascii_lowercase()
                }
            })
            .collect()
    })[register as usize]
        .as_str()
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
        Operand::Reg(register) => X86_STACK_REGS.contains(&register_name(register)),
        Operand::Mem { base, index, .. } => {
            X86_STACK_REGS.contains(&register_name(base))
                || X86_STACK_REGS.contains(&register_name(index))
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
            if X86_STACK_REGS.contains(&base_name) || X86_STACK_REGS.contains(&index_name) {
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
