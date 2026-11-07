"""Instruction normalization: project every architecture onto one vocabulary.

Two rules drive everything here:

* Features must not contain addresses. RIP-relative operands, ``adrp`` pages,
  and absolute displacements are resolved to a target address, then either kept
  as a data reference (an anchor) or dropped. Only the reference address is
  recorded, never an immediate that happens to be an address.
* Instructions that compilers or mitigations insert for alignment, hardening, or
  patching carry no signal, so they are marked ``ignored`` and never become
  features. That keeps CET/PAC builds matching non-CET/PAC ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Final

from capstone import Cs, CsInsn
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from capstone.arm_const import (
    ARM_CC_AL,
    ARM_CC_EQ,
    ARM_CC_INVALID,
    ARM_CC_NE,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_REG_LR,
    ARM_REG_PC,
    ARM_REG_SP,
)
from capstone.x86_const import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
)

from core.arch import Arch, capstone_for, ensure_supported
from core.source import ByteSource
from core.spec import MAX_THUNK_HOPS

OP_CLASSES: Final[tuple[str, ...]] = (
    "move",
    "arith",
    "mul",
    "logic",
    "cmp",
    "load",
    "store",
    "stack",
    "branch",
    "call",
    "ret",
    "cond",
    "vector",
    "misc",
)

IGNORED: Final[str] = "ignored"
NORMAL: Final[str] = "normal"
CALL: Final[str] = "call"
NORETURN_CALL: Final[str] = "noreturn_call"
JUMP: Final[str] = "jump"
COND_JUMP: Final[str] = "cond_jump"
RET: Final[str] = "ret"
TRAP: Final[str] = "trap"

TERMINATING_KINDS: Final[frozenset[str]] = frozenset({RET, JUMP, COND_JUMP, TRAP})

MASK64: Final[int] = (1 << 64) - 1
MASK32: Final[int] = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class DataRef:
    """A reference to bytes outside the instruction stream (string, table, slot)."""

    addr: int
    width: int = 1


@dataclass(frozen=True, slots=True)
class Insn:
    """One instruction reduced to architecture-neutral facts."""

    addr: int
    size: int
    op: str
    kind: str
    consts: tuple[int, ...] = ()
    refs: tuple[DataRef, ...] = ()
    callee: str | None = None
    target: int | None = None
    # End of a literal-pool cell this instruction reads (arm32 inline pools);
    # recovery extends function bounds over the cell so bounds stay comparable
    # with symbol sizes, which count the pool as part of the function.
    pool_end: int = 0


def canonical_const(value: int, width: int = 8) -> int:
    """Normalise an immediate so equal source constants compare equal.

    Compilers materialise ``-1`` as ``mov rax, -1`` on one path and
    ``mov eax, -1`` on another; both must hash the same. Values in the 32-bit
    range are therefore stored sign-extended to 64 bits. A genuine unsigned
    32-bit mask with the high bit set collapses onto the same value, which is an
    accepted loss: constants are supporting evidence, never identity.
    """
    value &= MASK64
    if width > 4:
        return value
    # Capstone already sign-extends negative immediates, so reduce to 32 bits
    # before sign-extending again; this keeps the rule idempotent.
    narrow = value & MASK32
    if narrow & 0x8000_0000:
        return (narrow - 0x1_0000_0000) & MASK64
    return narrow


_X86_IGNORED: Final[frozenset[str]] = frozenset({"nop", "endbr64", "endbr32", "int3", "fnop"})
_X86_RET: Final[frozenset[str]] = frozenset(
    {"ret", "retf", "retn", "iret", "iretd", "iretq", "sysret", "sysexit"}
)
_X86_TRAP: Final[frozenset[str]] = frozenset({"ud2", "hlt", "int", "int1"})
_X86_MUL: Final[frozenset[str]] = frozenset({"imul", "mul", "idiv", "div"})
_X86_LOGIC: Final[frozenset[str]] = frozenset(
    {
        "and",
        "or",
        "xor",
        "not",
        "neg",
        "shl",
        "shr",
        "sar",
        "sal",
        "rol",
        "ror",
        "rcl",
        "rcr",
        "bt",
        "bts",
        "btr",
        "btc",
        "bsf",
        "bsr",
        "lzcnt",
        "tzcnt",
        "popcnt",
        "andn",
        "bextr",
        "blsi",
        "blsr",
        "blsmsk",
    }
)
_X86_ARITH: Final[frozenset[str]] = frozenset({"add", "sub", "adc", "sbb", "inc", "dec", "xadd"})
_X86_CONST_MNEMONICS: Final[frozenset[str]] = frozenset(
    {
        "mov",
        "movabs",
        "movzx",
        "movsx",
        "movsxd",
        "cmp",
        "test",
        "and",
        "or",
        "xor",
        "imul",
        "add",
        "sub",
        "adc",
        "sbb",
    }
)
_X86_STACK_REGS: Final[frozenset[str]] = frozenset({"rsp", "esp", "sp", "rbp", "ebp", "sbp"})

_ARM64_IGNORED: Final[frozenset[str]] = frozenset(
    {
        "nop",
        "bti",
        "hint",
        "paciasp",
        "autiasp",
        "pacibsp",
        "autibsp",
        "paciaz",
        "autiaz",
        "pacibz",
        "autibz",
        "xpaclri",
    }
)
_ARM64_RET: Final[frozenset[str]] = frozenset(
    {"ret", "retaa", "retab", "retbb", "retba", "eret", "eretaa", "eretab"}
)
_ARM64_TRAP: Final[frozenset[str]] = frozenset({"brk", "hlt", "udf"})
_ARM64_MUL: Final[frozenset[str]] = frozenset(
    {
        "mul",
        "madd",
        "msub",
        "mneg",
        "smull",
        "umull",
        "smulh",
        "umulh",
        "sdiv",
        "udiv",
        "smaddl",
        "umaddl",
        "smsubl",
        "umsubl",
        "sqdmulh",
        "sqrdmulh",
    }
)
_ARM64_LOGIC: Final[frozenset[str]] = frozenset(
    {
        "and",
        "ands",
        "orr",
        "orn",
        "eor",
        "eon",
        "bic",
        "bics",
        "lsl",
        "lsr",
        "asr",
        "ror",
        "mvn",
        "extr",
    }
)
_ARM64_CMP: Final[frozenset[str]] = frozenset({"cmp", "cmn", "ccmp", "ccmn", "tst"})
_ARM64_MOVE: Final[frozenset[str]] = frozenset(
    {
        "mov",
        "movz",
        "movk",
        "movn",
        "adr",
        "adrp",
        "csel",
        "csinc",
        "csinv",
        "csneg",
        "cset",
        "csetm",
        "sxtb",
        "sxth",
        "sxtw",
        "uxtb",
        "uxth",
        "uxtw",
    }
)
_ARM64_ARITH: Final[frozenset[str]] = frozenset(
    {"add", "adds", "sub", "subs", "adc", "adcs", "sbc", "sbcs", "neg", "negs", "ngc", "ngcs"}
)
_ARM64_LOAD_PREFIXES: Final[tuple[str, ...]] = (
    "ldr",
    "ldur",
    "ldp",
    "ldnp",
    "ldar",
    "ldxr",
    "ldaxr",
    "ld1",
    "ld2",
    "ld3",
    "ld4",
)
_ARM64_STORE_PREFIXES: Final[tuple[str, ...]] = (
    "str",
    "stur",
    "stp",
    "stnp",
    "stlr",
    "stxr",
    "st1",
    "st2",
    "st3",
    "st4",
)
_ARM64_LITERAL_LOADS: Final[frozenset[str]] = frozenset({"ldr", "ldrsw", "prfm", "ldrq"})
_ARM64_SHIFT_MNEMONICS: Final[frozenset[str]] = frozenset(
    {"lsl", "lsr", "asr", "ror", "extr", "ubfm", "sbfm", "bfm"}
)

_VECTOR_REG = re.compile(r"^[vqdsbh]\d+$")
_X86_VECTOR_PREFIXES: Final[tuple[str, ...]] = ("xmm", "ymm", "zmm", "mm", "st(", "k")

# -- ARM32 / Thumb ------------------------------------------------------------
# Condition codes carry no signal (a build flips between branches and predicated
# instructions as it inlines), so the suffix is stripped for classification and
# a conditional return or tail exit is treated as a conditional jump with a
# fall-through, never as an unconditional terminator.

_CC_SUFFIXES: Final[dict[int, str]] = {
    ARM_CC_EQ: "eq",
    ARM_CC_NE: "ne",
    3: "hs",
    4: "lo",
    5: "mi",
    6: "pl",
    7: "vs",
    8: "vc",
    9: "hi",
    10: "ls",
    11: "ge",
    12: "lt",
    13: "gt",
    14: "le",
}

_ARM32_IGNORED: Final[frozenset[str]] = frozenset({"nop", "hint"})
_ARM32_TRAP: Final[frozenset[str]] = frozenset({"udf", "svc"})
_ARM32_MUL: Final[frozenset[str]] = frozenset(
    {"mul", "mla", "mls", "umull", "umlal", "smull", "smlal", "sdiv", "udiv"}
)
_ARM32_LOGIC: Final[frozenset[str]] = frozenset(
    {"and", "orr", "eor", "bic", "lsl", "lsr", "asr", "ror", "rrx", "clz", "rbit", "pkhbt", "pkhtb"}
)
_ARM32_CMP: Final[frozenset[str]] = frozenset({"cmp", "cmn", "tst", "teq"})
_ARM32_ARITH: Final[frozenset[str]] = frozenset({"add", "sub", "adc", "sbc", "rsb", "qadd", "qsub"})
_ARM32_MOVE: Final[frozenset[str]] = frozenset(
    {
        "mov",
        "mvn",
        "adr",
        "uxtb",
        "uxth",
        "uxtw",
        "sxtb",
        "sxth",
        "sxtw",
        "uxtah",
        "sxtab",
        "rev",
        "rev16",
        "revsh",
        "rbit",
        "sel",
        "clz",
        "bfc",
        "bfi",
        "sbfx",
        "ubfx",
    }
)
_ARM32_LOAD_PREFIXES: Final[tuple[str, ...]] = (
    "ldr",
    "ldm",
    "ldrex",
    "ldrd",
)
_ARM32_STORE_PREFIXES: Final[tuple[str, ...]] = (
    "str",
    "stm",
    "strex",
    "strd",
)
_ARM32_BRANCH_TABLE: Final[frozenset[str]] = frozenset({"tbb", "tbh"})
_ARM32_CONDITIONAL_JUMPS: Final[frozenset[str]] = frozenset({"cbz", "cbnz"})
_ARM32_WIDTH_4: Final[int] = 4

NORETURN_NAMES: Final[frozenset[str]] = frozenset(
    {
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
    }
)


def _base_callee_name(name: str) -> str:
    """Reduce a resolved callee to the symbol part used for noreturn matching."""
    symbol = name.rsplit("!", 1)[-1]
    symbol = symbol.split("@", 1)[0]
    return symbol.lstrip("_")


@dataclass(slots=True)
class _PendingValue:
    value: int
    is_page: bool
    width: int


class _ArmState:
    """Register values materialised but not yet observed as constants."""

    def __init__(self) -> None:
        self.values: dict[int, _PendingValue] = {}

    def take_consts(self) -> tuple[int, ...]:
        """Consume pending constants, keeping unresolved ``adrp`` pages.

        A page that is never consumed is an address, so it must never be
        flushed as a constant; pages are dropped with :meth:`clear`.
        """
        values = tuple(
            sorted(
                canonical_const(item.value, item.width)
                for item in self.values.values()
                if not item.is_page
            )
        )
        for register in [r for r, item in self.values.items() if not item.is_page]:
            del self.values[register]
        return values

    def clear(self) -> None:
        self.values.clear()


class Normalizer:
    """Decodes and normalizes instructions for one ``ByteSource``."""

    def __init__(self, source: ByteSource) -> None:
        self.source = source
        self.arch = ensure_supported(source.arch)
        self._md: Cs = capstone_for(self.arch)
        self._md_arm32: Cs | None = capstone_for(Arch.ARM32) if self.arch is Arch.ARM32 else None
        self._md_thumb: Cs | None = (
            capstone_for(Arch.THUMB) if self.arch in (Arch.ARM32, Arch.THUMB) else None
        )
        self._follow_depth = 0

    # -- public API --------------------------------------------------------

    def decode_block(self, addr: int, max_bytes: int) -> tuple[Insn, ...]:
        """Decode a straight-line run starting at ``addr``, stopping at a terminator.

        Decoding is bounded by ``max_bytes`` and by ``MAX_THUNK_HOPS`` recursion;
        random or truncated bytes simply produce fewer instructions.
        """
        if max_bytes <= 0:
            return ()
        if self.arch in (Arch.ARM32, Arch.THUMB):
            return self._decode_arm32_block(addr, max_bytes)

        data = self.source.read_partial(addr, max_bytes)
        if not data:
            return ()

        out: list[Insn] = []
        if self.arch is Arch.X64:
            for raw in self.md.disasm(data, addr):
                insn = self._x86(raw)
                out.append(insn)
                if insn.kind in TERMINATING_KINDS:
                    break
            return tuple(out)

        state = _ArmState()
        for raw in self.md.disasm(data, addr):
            insn = self._arm(raw, state)
            out.append(insn)
            if insn.kind in TERMINATING_KINDS:
                break
        pending = state.take_consts()
        if pending and out:
            last = out[-1]
            merged = tuple(sorted(set(last.consts) | set(pending)))
            out[-1] = replace(last, consts=merged)
        state.clear()
        return tuple(out)

    def _decode_arm32_block(self, addr: int, max_bytes: int) -> tuple[Insn, ...]:
        base = addr & ~1  # the Thumb bit is metadata, never a byte offset
        data = self.source.read_partial(base, max_bytes)
        if not data:
            return ()
        decoder = self._md_thumb if self.source.is_thumb(base) else self._md_arm32
        assert decoder is not None  # ensured in __init__ for the arm32 family
        state = _ArmState()
        out: list[Insn] = []
        for raw in decoder.disasm(data, base):
            insn = self._arm32(raw, state)
            out.append(insn)
            if insn.kind in TERMINATING_KINDS:
                break
        pending = state.take_consts()
        if pending and out:
            last = out[-1]
            merged = tuple(sorted(set(last.consts) | set(pending)))
            out[-1] = replace(last, consts=merged)
        state.clear()
        return tuple(out)

    def normalize_one(self, addr: int) -> Insn | None:
        """Decode exactly one instruction; used for thunk following."""
        insns = self.decode_block(addr, 16)
        return insns[0] if insns else None

    @property
    def md(self) -> Cs:
        return self._md

    # -- shared helpers ----------------------------------------------------

    def _callee_name(self, target: int | None) -> str | None:
        if target is None:
            return None
        resolved = self._follow_thunk(target)
        if resolved is None:
            return None
        return self.source.label_for_address(resolved)

    def _read_pointer(self, addr: int | None) -> int | None:
        if addr is None:
            return None
        size = self.source.arch.pointer_size
        data = self.source.try_read(addr, size)
        if data is None or len(data) < size:
            return None
        return int.from_bytes(data, "little")

    def _import_name(self, addr: int) -> str | None:
        for module in self.source.modules():
            if module.contains(addr):
                return module.imports.get(addr)
        return None

    def _slot_callee(self, slot: int | None) -> str | None:
        """Resolve a callee through an IAT/GOT slot or a pointer cell."""
        if slot is None:
            return None
        name = self._import_name(slot)
        if name is not None:
            return name
        return self._callee_name(self._read_pointer(slot))

    def _follow_thunk(self, target: int) -> int | None:
        """Resolve jump thunks, PLT stubs, and ``ldr x16; br x16`` veneers."""
        current: int | None = target
        seen: set[int] = set()
        if self._follow_depth >= MAX_THUNK_HOPS:
            return current
        self._follow_depth += 1
        try:
            for _ in range(MAX_THUNK_HOPS):
                if current is None or current in seen:
                    return current
                seen.add(current)
                if self.source.name_for_address(current) is not None:
                    return current
                first = self.normalize_one(current)
                if first is None or first.kind != JUMP:
                    return current
                if first.target is not None:
                    current = first.target
                    continue
                if first.refs:
                    current = self._read_pointer(first.refs[0].addr)
                    continue
                return current
            return current
        finally:
            self._follow_depth -= 1

    @staticmethod
    def _noreturn(callee: str | None) -> bool:
        return bool(callee) and _base_callee_name(callee or "") in NORETURN_NAMES

    # -- x86-64 ------------------------------------------------------------

    def _x86(self, raw: CsInsn) -> Insn:
        mnemonic = raw.mnemonic
        ops = raw.operands
        addr, size = raw.address, raw.size

        if mnemonic in _X86_IGNORED or self._x86_is_hotpatch(raw):
            return Insn(addr, size, "misc", IGNORED)

        kind = NORMAL
        refs: list[DataRef] = []
        consts: list[int] = []
        callee: str | None = None
        target: int | None = None

        for op in ops:
            if op.type != X86_OP_MEM:
                continue
            if op.mem.base == X86_REG_RIP:
                refs.append(DataRef(addr + size + op.mem.disp, max(1, op.size)))
            elif (
                op.mem.base == 0 and op.mem.disp and self.source.module_for(op.mem.disp) is not None
            ):
                # A naked absolute displacement is only useful as a reference;
                # otherwise it is an address and must not leak into features.
                refs.append(DataRef(op.mem.disp, max(1, op.size)))

        if mnemonic in ("call", "lcall"):
            kind = CALL
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
                callee = self._callee_name(target)
            elif ops and ops[0].type == X86_OP_MEM:
                callee = self._slot_callee(refs[0].addr if refs else None)
            if self._noreturn(callee):
                kind = NORETURN_CALL
        elif mnemonic == "jmp" or mnemonic == "ljmp":
            kind = JUMP
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
                callee = self._callee_name(target)
            elif ops and ops[0].type == X86_OP_MEM:
                callee = self._slot_callee(refs[0].addr if refs else None)
        elif mnemonic.startswith("j") or mnemonic.startswith("loop"):
            kind = COND_JUMP
            if ops and ops[0].type == X86_OP_IMM:
                target = ops[0].imm
        elif mnemonic in _X86_TRAP:
            kind = TRAP
        elif mnemonic in _X86_RET:
            kind = RET

        for op in ops:
            if op.type == X86_OP_IMM and self._x86_const_candidate(raw, op.size):
                consts.append(canonical_const(op.imm, op.size))

        return Insn(
            addr=addr,
            size=size,
            op=self._x86_class(raw),
            kind=kind,
            consts=tuple(sorted(set(consts))),
            refs=tuple(refs),
            callee=callee,
            target=target,
        )

    @staticmethod
    def _x86_is_hotpatch(raw: CsInsn) -> bool:
        # `mov edi, edi` is five bytes a prologue hooks into; it carries no signal.
        if raw.mnemonic != "mov" or len(raw.operands) != 2:
            return False
        first, second = raw.operands
        return bool(
            first.type == X86_OP_REG and second.type == X86_OP_REG and first.reg == second.reg
        )

    def _x86_const_candidate(self, raw: CsInsn, width: int) -> bool:
        if raw.mnemonic not in _X86_CONST_MNEMONICS:
            return False
        # Stack adjustments and frame arithmetic encode ABI, not program logic.
        return not self._x86_touches_stack_pointer(raw)

    @staticmethod
    def _x86_touches_stack_pointer(raw: CsInsn) -> bool:
        for op in raw.operands:
            if op.type == X86_OP_REG and raw.reg_name(op.reg) in _X86_STACK_REGS:
                return True
            if op.type == X86_OP_MEM:
                base = raw.reg_name(op.mem.base) if op.mem.base else ""
                index = raw.reg_name(op.mem.index) if op.mem.index else ""
                if base in _X86_STACK_REGS or index in _X86_STACK_REGS:
                    return True
        return False

    @staticmethod
    def _x86_vector(raw: CsInsn) -> bool:
        for op in raw.operands:
            if op.type == X86_OP_REG:
                name = raw.reg_name(op.reg) or ""
                if name.startswith(_X86_VECTOR_PREFIXES):
                    return True
        return False

    def _x86_class(self, raw: CsInsn) -> str:
        mnemonic = raw.mnemonic
        if self._x86_vector(raw):
            return "vector"
        if mnemonic in ("jmp", "ljmp"):
            return "branch"
        if mnemonic.startswith("j") or mnemonic.startswith("loop"):
            return "cond"
        if mnemonic in ("call", "lcall"):
            return "call"
        if mnemonic in _X86_RET:
            return "ret"
        if mnemonic in ("push", "pop", "enter", "leave"):
            return "stack"
        if mnemonic.startswith("cmov"):
            return "move"
        if len(mnemonic) == 4 and mnemonic.startswith("set"):
            return "cond"
        memory = self._x86_memory_class(raw)
        if mnemonic in ("cmp", "test"):
            return "cmp"
        if mnemonic in _X86_MUL:
            return "mul"
        if mnemonic in _X86_LOGIC:
            return "logic"
        if mnemonic in _X86_ARITH:
            return "arith"
        if mnemonic.startswith("mov") or mnemonic in ("xchg", "bswap"):
            return memory or "move"
        if mnemonic == "lea":
            # Address materialisation, matching AArch64 `adrp`+`add`.
            return "move"
        if mnemonic.startswith("stos"):
            return "store"
        if mnemonic.startswith(("movs", "lods", "scas", "cmps")):
            return "load"
        return memory or "misc"

    def _x86_memory_class(self, raw: CsInsn) -> str | None:
        for index, op in enumerate(raw.operands):
            if op.type != X86_OP_MEM:
                continue
            base = raw.reg_name(op.mem.base) if op.mem.base else ""
            index_reg = raw.reg_name(op.mem.index) if op.mem.index else ""
            if base in _X86_STACK_REGS or index_reg in _X86_STACK_REGS:
                return "stack"
            return "store" if index == 0 else "load"
        return None

    # -- AArch64 -----------------------------------------------------------

    def _arm(self, raw: CsInsn, state: _ArmState) -> Insn:
        mnemonic = raw.mnemonic
        ops = raw.operands
        addr, size = raw.address, raw.size

        if mnemonic in _ARM64_IGNORED:
            return Insn(addr, size, "misc", IGNORED)

        if mnemonic == "adrp" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            state.values[ops[0].reg] = _PendingValue(
                value=self._adrp_page(raw, ops[1].imm), is_page=True, width=8
            )
            return Insn(addr, size, "move", NORMAL)

        if mnemonic in ("movz", "movn", "movk") or (
            mnemonic == "mov" and len(ops) >= 2 and ops[1].type == ARM64_OP_IMM
        ):
            return self._arm_materialize(raw, state)

        if mnemonic == "adr" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
            # ADR reaches nearby data directly, so the immediate is an address.
            return Insn(addr, size, "move", NORMAL, (), (DataRef(ops[1].imm, 1),))

        if mnemonic.startswith("br") and mnemonic != "brk":
            # `br x16` after a literal load is a veneer; follow it when possible.
            br_kind = CALL if mnemonic.startswith("blr") else JUMP
            br_target: int | None = None
            if ops and ops[0].type == ARM64_OP_REG:
                held = state.values.pop(ops[0].reg, None)
                if held is not None and not held.is_page:
                    br_target = held.value
            br_callee = self._callee_name(br_target) if br_kind == CALL else None
            br_op = "call" if br_kind == CALL else "branch"
            return Insn(addr, size, br_op, br_kind, (), (), br_callee, br_target)

        pending = state.take_consts()
        refs: list[DataRef] = []
        callee: str | None = None
        target = None
        kind = NORMAL

        # adrp + add/sub: one resolved address, never a constant.
        if (
            mnemonic in ("add", "sub")
            and len(ops) >= 3
            and ops[1].type == ARM64_OP_REG
            and ops[2].type == ARM64_OP_IMM
            and ops[1].reg in state.values
            and state.values[ops[1].reg].is_page
        ):
            page = state.values.pop(ops[1].reg)
            resolved = page.value + ops[2].imm if mnemonic == "add" else page.value - ops[2].imm
            refs.append(DataRef(resolved, 1))
            return Insn(addr, size, "move", NORMAL, pending, tuple(refs), None, None)

        if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM and ops[0].type == ARM64_OP_REG:
            width = self._arm_reg_width(raw, ops[0].reg)
            mem = ops[1].mem
            base = mem.base
            if base in state.values and state.values[base].is_page:
                page = state.values.pop(base)
                refs.append(DataRef(page.value + mem.disp, width))
            elif (base == 0 or raw.reg_name(base) == "pc") and mnemonic in _ARM64_LITERAL_LOADS:
                literal = addr + mem.disp
                value = self._read_pointer(literal) if width == 8 else self._read_pointer32(literal)
                if value is not None:
                    if self.source.module_for(value) is not None:
                        # The pool cell holds a pointer; the cell is the anchor.
                        refs.append(DataRef(literal, width))
                    else:
                        state.values[ops[0].reg] = _PendingValue(
                            value=value, is_page=False, width=width
                        )

        if mnemonic == "b":
            kind = JUMP
            target = self._arm_target(raw)
            callee = self._callee_name(target)
        elif mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            kind = COND_JUMP
            target = self._arm_target(raw)
        elif mnemonic in ("bl", "blr", "blraa", "blraaz", "blrab", "blrabz"):
            kind = CALL
            target = self._arm_target(raw)
            if target is not None:
                callee = self._callee_name(target)
            if self._noreturn(callee):
                kind = NORETURN_CALL
        elif mnemonic in _ARM64_RET:
            kind = RET
        elif mnemonic in _ARM64_TRAP:
            kind = TRAP

        consts = list(pending)
        if kind == NORMAL:
            consts.extend(self._arm_immediate_consts(raw))

        return Insn(
            addr=addr,
            size=size,
            op=self._arm_class(raw),
            kind=kind,
            consts=tuple(sorted(set(consts))),
            refs=tuple(refs),
            callee=callee,
            target=target,
        )

    def _arm_materialize(self, raw: CsInsn, state: _ArmState) -> Insn:
        mnemonic = raw.mnemonic
        ops = raw.operands
        reg = ops[0].reg
        width = self._arm_reg_width(raw, reg)
        mask = MASK64 if width == 8 else MASK32

        # Capstone renders `movk x0, #imm, lsl #16` with the shift only in
        # op_str, so the shift comes from the encoding (bits 22:21).
        shift = self._arm_mov_shift(raw)
        if mnemonic == "movk":
            previous = state.values.pop(reg, None)
            base_value = previous.value if previous is not None and not previous.is_page else 0
            value = base_value | ((ops[1].imm & 0xFFFF) << shift)
            state.values[reg] = _PendingValue(value & mask, False, width)
            return Insn(raw.address, raw.size, "move", NORMAL)

        immediate = ops[1].imm
        value = ~(immediate << shift) if mnemonic == "movn" else immediate << shift
        state.values[reg] = _PendingValue(value & mask, False, width)
        return Insn(raw.address, raw.size, "move", NORMAL)

    def _arm_immediate_consts(self, raw: CsInsn) -> list[int]:
        if raw.mnemonic in _ARM64_SHIFT_MNEMONICS:
            return []
        if self._arm_touches_stack_pointer(raw):
            return []
        consts: list[int] = []
        for op in raw.operands:
            if op.type == ARM64_OP_IMM:
                consts.append(canonical_const(op.imm, getattr(op, "size", 8) or 8))
        return consts

    @staticmethod
    def _arm_touches_stack_pointer(raw: CsInsn) -> bool:
        for op in raw.operands:
            if op.type == ARM64_OP_REG and raw.reg_name(op.reg) in ("sp", "wsp"):
                return True
            if op.type == ARM64_OP_MEM and raw.reg_name(op.mem.base) in ("sp", "wsp"):
                return True
        return False

    @staticmethod
    def _arm_target(raw: CsInsn) -> int | None:
        for op in raw.operands:
            if op.type == ARM64_OP_IMM:
                return int(op.imm)
        return None

    @staticmethod
    def _adrp_page(raw: CsInsn, imm: int) -> int:
        """Resolve an ``adrp`` page regardless of whether Capstone absolutised it."""
        address = int(raw.address)
        value = int(imm)
        page = value & ~0xFFF
        if page == 0 and address & ~0xFFF:
            # Some Capstone builds report the raw page delta instead.
            delta = value << 12 if -0x10000 < value < 0x10000 else value
            return (address & ~0xFFF) + delta
        return page

    @staticmethod
    def _arm_mov_shift(raw: CsInsn) -> int:
        data = raw.bytes
        if len(data) < 4:
            return 0
        word = int.from_bytes(data[:4], "little")
        return ((word >> 21) & 0x3) * 16

    def _read_pointer32(self, addr: int) -> int | None:
        data = self.source.try_read(addr, 4)
        if data is None or len(data) < 4:
            return None
        return int.from_bytes(data[:4], "little")

    @staticmethod
    def _arm_reg_width(raw: CsInsn, reg: int) -> int:
        name = raw.reg_name(reg) or ""
        if name.startswith("w") or name in ("wsp",):
            return 4
        return 8

    @staticmethod
    def _arm_vector(raw: CsInsn) -> bool:
        for op in raw.operands:
            if op.type == ARM64_OP_REG:
                name = raw.reg_name(op.reg) or ""
                if _VECTOR_REG.match(name):
                    return True
        return False

    def _arm_class(self, raw: CsInsn) -> str:
        mnemonic = raw.mnemonic
        if self._arm_vector(raw):
            return "vector"
        if mnemonic == "b":
            return "branch"
        if mnemonic.startswith("br") and mnemonic != "brk":
            return "call" if mnemonic.startswith("blr") else "branch"
        if mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            return "cond"
        if mnemonic in ("bl", "blr", "blraa", "blraaz", "blrab", "blrabz"):
            return "call"
        if mnemonic in _ARM64_RET:
            return "ret"
        if mnemonic in _ARM64_CMP:
            return "cmp"
        if mnemonic in _ARM64_MUL:
            return "mul"
        if mnemonic in _ARM64_LOGIC:
            return "logic"
        if mnemonic in _ARM64_ARITH:
            return "arith"
        if mnemonic in _ARM64_MOVE:
            return "move"
        if mnemonic.startswith(_ARM64_STORE_PREFIXES):
            return "stack" if self._arm_touches_stack_pointer(raw) else "store"
        if mnemonic.startswith(_ARM64_LOAD_PREFIXES):
            return "stack" if self._arm_touches_stack_pointer(raw) else "load"
        if mnemonic.startswith(
            ("fmov", "fadd", "fsub", "fmul", "fdiv", "fcmp", "fcvt", "scvtf", "ucvtf")
        ):
            return "vector"
        if self._arm_touches_stack_pointer(raw):
            return "stack"
        return "misc"

    # -- ARM32 / Thumb -----------------------------------------------------

    @staticmethod
    def _arm32_mnemonic(raw: CsInsn) -> tuple[str, bool]:
        """Strip the condition suffix and Thumb ``.w`` width marker.

        Capstone reports the condition in ``insn.cc``; a conditional suffix is
        only removed when Capstone says the instruction is conditional, so
        mnemonics that merely end in a condition pair (``umlal``, ``mls``)
        survive untouched.
        """
        mnemonic = raw.mnemonic
        if mnemonic.endswith(".w") or mnemonic.endswith(".n"):
            mnemonic = mnemonic[:-2]
        cc = getattr(raw, "cc", ARM_CC_AL)
        suffix = _CC_SUFFIXES.get(cc) if cc not in (ARM_CC_AL, ARM_CC_INVALID) else None
        if suffix and mnemonic.endswith(suffix):
            return mnemonic[: -len(suffix)], True
        return mnemonic, False

    def _arm32(self, raw: CsInsn, state: _ArmState) -> Insn:
        mnemonic, conditional = self._arm32_mnemonic(raw)
        ops = raw.operands
        addr, size = raw.address, raw.size

        if mnemonic in _ARM32_IGNORED or mnemonic.startswith("it"):
            # IT blocks carry predication only; their instructions keep the
            # condition suffix, which is stripped above.
            return Insn(addr, size, "misc", IGNORED)

        if mnemonic in ("movw", "movt") and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            return self._arm32_materialize(raw, state, mnemonic, ops[1].imm)

        if mnemonic == "mvn" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            # `-x` is materialised as `mvn rd, #~x`; mirror AArch64 `movn`.
            value = ~(ops[1].imm & MASK32) & MASK32
            state.values[ops[0].reg] = _PendingValue(value, False, _ARM32_WIDTH_4)
            return Insn(addr, size, "move", NORMAL)

        # Indirect exits that consume a pooled address must read register state
        # before the pending flush below deletes it.
        indirect_target: int | None = None
        if mnemonic in ("bx", "blx", "blr") and ops and ops[-1].type == ARM_OP_REG:
            held = state.values.pop(ops[-1].reg, None)
            if held is not None and not held.is_page:
                indirect_target = held.value

        pending = state.take_consts()
        refs: list[DataRef] = []
        callee: str | None = None
        target: int | None = None
        kind = NORMAL

        pool_end = 0
        if mnemonic == "adr" and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            refs.append(DataRef(ops[1].imm, 1))
        else:
            pool_end = self._arm32_literal_load(raw, mnemonic, state, refs)
            if not pool_end:
                self._arm32_pc_add(raw, mnemonic, state, refs)
            if mnemonic in ("pop", "push") or mnemonic.startswith(("ldm", "stm")):
                exits = mnemonic == "pop" or mnemonic.startswith("ldm")
                kind = self._arm32_stack_exit(raw, conditional, exits)
            elif mnemonic == "b":
                kind = COND_JUMP if conditional else JUMP
                target = self._arm32_target(raw)
                if kind == JUMP:
                    callee = self._callee_name(target)
            elif mnemonic == "bx":
                if indirect_target is not None:
                    kind, target = JUMP, indirect_target
                elif ops and ops[0].type == ARM_OP_REG and ops[0].reg == ARM_REG_LR:
                    kind = COND_JUMP if conditional else RET
                else:
                    kind = JUMP
            elif mnemonic in ("bl", "blx", "blr"):
                kind = CALL
                target = ops[-1].imm if ops and ops[-1].type == ARM_OP_IMM else indirect_target
                if target is not None:
                    callee = self._callee_name(target)
                if self._noreturn(callee):
                    kind = NORETURN_CALL
            elif mnemonic in _ARM32_CONDITIONAL_JUMPS:
                kind = COND_JUMP
                target = self._arm32_target(raw)
            elif mnemonic in _ARM32_BRANCH_TABLE:
                kind = JUMP
            elif mnemonic in _ARM32_TRAP:
                kind = TRAP
            elif mnemonic == "mov" and self._arm32_moves_pc(raw):
                kind = RET

        consts = list(pending)
        if kind == NORMAL:
            consts.extend(self._arm32_immediate_consts(raw))

        return Insn(
            addr=addr,
            size=size,
            op=self._arm32_class(raw, mnemonic, conditional),
            kind=kind,
            consts=tuple(sorted(set(consts))),
            refs=tuple(refs),
            callee=callee,
            target=target,
            pool_end=pool_end,
        )

    def _arm32_materialize(self, raw: CsInsn, state: _ArmState, mnemonic: str, imm: int) -> Insn:
        reg = raw.operands[0].reg
        if mnemonic == "movt":
            previous = state.values.pop(reg, None)
            base = previous.value if previous is not None and not previous.is_page else 0
            value = base | ((imm & 0xFFFF) << 16)
        else:
            value = imm & 0xFFFF
        state.values[reg] = _PendingValue(value & MASK32, False, _ARM32_WIDTH_4)
        return Insn(raw.address, raw.size, "move", NORMAL)

    def _arm32_literal_load(
        self, raw: CsInsn, mnemonic: str, state: _ArmState, refs: list[DataRef]
    ) -> int:
        """Resolve ``ldr rd, [pc, #imm]`` against the function's literal pool.

        A pool cell holding a pointer becomes a reference to the target (the
        string or table the compiler pooled); any other word becomes a pending
        32-bit constant, matching how ``movw``/``movt`` pairs flush. Returns
        the end of the referenced cell, or 0 when this is not a literal load.
        """
        if mnemonic != "ldr" or len(raw.operands) < 2:
            return 0
        for index, op in enumerate(raw.operands):
            if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
                continue
            destination = raw.operands[index - 1] if index > 0 else None
            if destination is None or destination.type != ARM_OP_REG:
                return 0
            pc = (raw.address + 4) & ~0x3 if self.source.is_thumb(raw.address) else raw.address + 8
            literal = int(pc + op.mem.disp)
            value = self._read_pointer32(literal)
            if value is None:
                return 0
            if self.source.module_for(value) is not None:
                refs.append(DataRef(value, _ARM32_WIDTH_4))
            else:
                state.values[destination.reg] = _PendingValue(value, False, _ARM32_WIDTH_4)
            return literal + _ARM32_WIDTH_4
        return 0

    def _arm32_pc_add(
        self, raw: CsInsn, mnemonic: str, state: _ArmState, refs: list[DataRef]
    ) -> bool:
        """Resolve ``add rd, pc, rm`` / ``add rd, pc`` against a pooled offset.

        Position-independent arm32 code materialises a page offset into a
        register and adds the PC; the sum is the data address, so it becomes a
        reference exactly like AArch64's ``adrp``+``add`` pair.
        """
        ops = raw.operands
        if not ops or not any(op.type == ARM_OP_REG and op.reg == ARM_REG_PC for op in ops):
            return False
        base = (raw.address + 4) & ~0x3 if self.source.is_thumb(raw.address) else raw.address + 8
        subtracting = mnemonic.startswith("s") or mnemonic.startswith("r")
        immediate = next((op.imm for op in ops if op.type == ARM_OP_IMM), None)
        for op in ops[1:]:
            if op.type == ARM_OP_REG and op.reg == ARM_REG_PC:
                continue
            held = state.values.pop(op.reg, None)
            if held is None or held.is_page:
                continue
            resolved = base - held.value if subtracting else base + held.value
            refs.append(DataRef(resolved & MASK32, _ARM32_WIDTH_4))
            # Keep an address marker so the intermediate never flushes as a
            # constant, but let later arithmetic still see the value.
            if ops[0].type == ARM_OP_REG:
                state.values[ops[0].reg] = _PendingValue(resolved & MASK32, True, _ARM32_WIDTH_4)
            return True
        if immediate is not None and ops[0].type == ARM_OP_REG:
            resolved = base - immediate if subtracting else base + immediate
            refs.append(DataRef(resolved & MASK32, _ARM32_WIDTH_4))
            state.values[ops[0].reg] = _PendingValue(resolved & MASK32, True, _ARM32_WIDTH_4)
        elif ops[0].type == ARM_OP_REG:
            state.values[ops[0].reg] = _PendingValue(base, True, _ARM32_WIDTH_4)
        return True

    @staticmethod
    def _arm32_stack_exit(raw: CsInsn, conditional: bool, exits: bool) -> str:
        """``pop {..., pc}`` and ``ldm ... pc`` return; everything else is stack.

        A conditional return is a conditional exit, never an unconditional
        terminator: the block continues when the predicate is false.
        """
        if exits and any(op.type == ARM_OP_REG and op.reg == ARM_REG_PC for op in raw.operands):
            return COND_JUMP if conditional else RET
        return NORMAL

    @staticmethod
    def _arm32_moves_pc(raw: CsInsn) -> bool:
        """Old-style ``mov pc, lr`` return."""
        if len(raw.operands) < 2:
            return False
        destination, source = raw.operands[0], raw.operands[1]
        return bool(
            destination.type == ARM_OP_REG
            and destination.reg == ARM_REG_PC
            and source.type == ARM_OP_REG
            and source.reg == ARM_REG_LR
        )

    @staticmethod
    def _arm32_immediate_consts(raw: CsInsn) -> list[int]:
        if Normalizer._arm32_touches_stack_pointer(raw):
            return []
        return [
            canonical_const(op.imm, _ARM32_WIDTH_4) for op in raw.operands if op.type == ARM_OP_IMM
        ]

    @staticmethod
    def _arm32_touches_stack_pointer(raw: CsInsn) -> bool:
        for op in raw.operands:
            if op.type == ARM_OP_REG and (op.reg == ARM_REG_SP or raw.reg_name(op.reg) == "sp"):
                return True
            if op.type == ARM_OP_MEM and raw.reg_name(op.mem.base) in ("sp",):
                return True
        return False

    @staticmethod
    def _arm32_target(raw: CsInsn) -> int | None:
        for op in reversed(raw.operands):
            if op.type == ARM_OP_IMM:
                return int(op.imm)
        return None

    def _arm32_class(self, raw: CsInsn, mnemonic: str, conditional: bool) -> str:
        if self._arm_vector(raw):
            return "vector"
        if self._arm32_is_ret(raw, mnemonic):
            return "cond" if conditional else "ret"
        if mnemonic in ("b", "bx") or mnemonic in _ARM32_BRANCH_TABLE:
            return "cond" if conditional else "branch"
        if mnemonic in ("bl", "blx", "blr"):
            return "call"
        if mnemonic in _ARM32_CONDITIONAL_JUMPS:
            return "cond"
        if mnemonic in _ARM32_TRAP:
            return "misc"
        if mnemonic in ("pop", "push"):
            return "stack"
        if mnemonic in _ARM32_CMP:
            return "cmp"
        if mnemonic in _ARM32_MUL:
            return "mul"
        if mnemonic in _ARM32_LOGIC:
            return "logic"
        if mnemonic in _ARM32_ARITH:
            return "arith"
        if mnemonic in _ARM32_MOVE:
            return "move"
        # Flag-setting forms (`movs`, `adds`, `lsrs`, ...) classify as their
        # base mnemonic; `mls` and friends are already matched above.
        base = mnemonic[:-1] if mnemonic.endswith("s") else mnemonic
        if base in _ARM32_MUL:
            return "mul"
        if base in _ARM32_LOGIC:
            return "logic"
        if base in _ARM32_ARITH:
            return "arith"
        if base in _ARM32_MOVE:
            return "move"
        if base in _ARM32_CMP:
            return "cmp"
        if mnemonic.startswith(_ARM32_STORE_PREFIXES):
            return "stack" if self._arm32_touches_stack_pointer(raw) else "store"
        if mnemonic.startswith(_ARM32_LOAD_PREFIXES):
            return "stack" if self._arm32_touches_stack_pointer(raw) else "load"
        if self._arm32_touches_stack_pointer(raw):
            return "stack"
        return "misc"

    @staticmethod
    def _arm32_is_ret(raw: CsInsn, mnemonic: str) -> bool:
        if mnemonic == "bx":
            ops = raw.operands
            return bool(ops and ops[0].type == ARM_OP_REG and ops[0].reg == ARM_REG_LR)
        if mnemonic == "pop" or mnemonic.startswith("ldm"):
            return any(op.type == ARM_OP_REG and op.reg == ARM_REG_PC for op in raw.operands)
        return False
