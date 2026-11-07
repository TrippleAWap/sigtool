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
        self._follow_depth = 0

    # -- public API --------------------------------------------------------

    def decode_block(self, addr: int, max_bytes: int) -> tuple[Insn, ...]:
        """Decode a straight-line run starting at ``addr``, stopping at a terminator.

        Decoding is bounded by ``max_bytes`` and by ``MAX_THUNK_HOPS`` recursion;
        random or truncated bytes simply produce fewer instructions.
        """
        if max_bytes <= 0:
            return ()
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
