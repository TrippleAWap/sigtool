"""Unit tests for normalization rules, using real compiler byte sequences."""

from __future__ import annotations

from core.arch import Arch
from core.normalize import COND_JUMP, IGNORED, NORMAL, RET, Normalizer, canonical_const
from core.source import MemorySource, Module, Region

# Bytes below are copied from clang 22 output for x86_64 (`-O2`, `-O0`) and are
# the minimal encodings a vector would otherwise cover.
ENDBR64_RET = bytes.fromhex("f30f1efa" + "c3")
LEA_RIP = bytes.fromhex("488d3d05000000" + "c3")  # lea rdi, [rip+5]; ret
MOV_NEG = bytes.fromhex("b8ffffffff" + "c3")  # mov eax, -1; ret
MOVABS_NEG = bytes.fromhex("48c7c0ffffffff" + "c3")  # mov rax, -1; ret
PADDING = bytes.fromhex("909090" + "c3")  # 3x nop; ret
HOTPATCH = bytes.fromhex("8bff" + "c3")  # mov edi, edi; ret
CALL_SELF = bytes.fromhex("e8fbffffff" + "c3")  # call rel32 to itself; ret
CALL_IAT = bytes.fromhex("ff150a000000" + "c3")  # call [rip+0xa]; ret


def x64_source(
    code: bytes,
    *,
    base: int = 0x1000,
    imports: dict[int, str] | None = None,
    exports: dict[str, int] | None = None,
    size: int | None = None,
) -> MemorySource:
    if size is not None and size > len(code):
        code = code + b"\x00" * (size - len(code))
    region = Region("text", base, len(code), code, executable=True)
    module = Module(
        name="fixture",
        base=base,
        size=len(code),
        regions=(region,),
        imports=imports or {},
        exports=exports or {},
    )
    return MemorySource(Arch.X64, [region], [module])


def test_canonical_const_unifies_sign_extended_values() -> None:
    assert canonical_const(0xFFFFFFFF, 4) == canonical_const(-1, 8) == 0xFFFF_FFFF_FFFF_FFFF
    assert canonical_const(0x1234, 4) == 0x1234
    assert canonical_const(0x1234, 8) == 0x1234


def test_endbr64_and_nops_are_ignored() -> None:
    insns = Normalizer(x64_source(ENDBR64_RET)).decode_block(0x1000, 64)
    assert [insn.kind for insn in insns] == ["ignored", "ret"]


def test_hotpatch_prologue_is_ignored() -> None:
    insns = Normalizer(x64_source(HOTPATCH)).decode_block(0x1000, 64)
    assert insns[0].kind == "ignored"


def test_rip_relative_operand_resolves_to_target_address() -> None:
    insns = Normalizer(x64_source(LEA_RIP)).decode_block(0x1000, 64)
    assert insns[0].refs[0].addr == 0x1000 + 7 + 5
    assert insns[0].consts == ()


def test_movabs_and_mov_imm32_share_one_constant() -> None:
    a = Normalizer(x64_source(MOV_NEG)).decode_block(0x1000, 64)[0].consts
    b = Normalizer(x64_source(MOVABS_NEG)).decode_block(0x1000, 64)[0].consts
    assert a == b == (0xFFFF_FFFF_FFFF_FFFF,)


def test_padding_does_not_reach_features() -> None:
    insns = Normalizer(x64_source(PADDING)).decode_block(0x1000, 64)
    assert [insn.kind for insn in insns] == ["ignored", "ignored", "ignored", "ret"]


def test_direct_call_resolves_to_module_rva_label() -> None:
    source = x64_source(CALL_SELF, exports={"target": 0x1000})
    insns = Normalizer(source).decode_block(0x1000, 64)
    assert insns[0].kind == "call"
    assert insns[0].target == 0x1000
    assert insns[0].callee == "target"


def test_indirect_call_resolves_through_import_slot() -> None:
    slot = 0x1000 + 6 + 0xA
    source = x64_source(CALL_IAT, imports={slot: "kernel32!CreateFileW"}, size=0x40)
    insns = Normalizer(source).decode_block(0x1000, 64)
    assert insns[0].kind == "call"
    assert insns[0].callee == "kernel32!CreateFileW"


def test_noreturn_callee_marks_block_end() -> None:
    code = bytes.fromhex("e800000000" + "c3")  # call next; ret
    source = x64_source(code, exports={"abort": 0x1005})
    insns = Normalizer(source).decode_block(0x1000, 64)
    assert insns[0].kind == "noreturn_call"


def test_thumb_normalizes_it_blocks_and_conditional_returns() -> None:
    # push {r4, lr}; itt eq; movs r0, #1; bx lr; movs r0, #0; pop {r4, pc}
    code = bytes.fromhex("10b504bf01207047002010bd")
    region = Region("t", 0x1000, len(code), code, executable=True)
    normalizer = Normalizer(MemorySource(Arch.THUMB, [region]))

    # A conditional `bx eq lr` ends this block like any conditional jump; the
    # fall-through is a separate block.
    first = normalizer.decode_block(0x1000, 64)
    assert [insn.kind for insn in first] == [NORMAL, IGNORED, NORMAL, COND_JUMP]
    assert [insn.op for insn in first] == ["stack", "misc", "move", "cond"]

    tail = normalizer.decode_block(0x1008, 64)
    assert [insn.kind for insn in tail] == [NORMAL, RET]
    assert tail[1].op == "ret"  # pop {..., pc}


def test_normalizer_supports_arm32_and_thumb() -> None:
    assert Normalizer(MemorySource(Arch.THUMB, [])) is not None
    assert Normalizer(MemorySource(Arch.ARM32, [])) is not None
