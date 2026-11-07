"""Bounded recursive-descent recovery of function bounds and shape.

Recovery walks from a function entry, decoding straight-line runs and following
direct branches inside the function. It is deliberately conservative: every
budget is bounded, undecodable bytes end a block instead of raising, and a jump
that leaves the symbol's range is treated as a tail call rather than followed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Final

from core.arch import Arch, ensure_supported
from core.errors import DecodeError
from core.normalize import Insn, Normalizer
from core.source import ByteSource
from core.spec import (
    MAX_BLOCK_BYTES,
    MAX_BLOCKS,
    MAX_FUNCTION_BYTES,
    MAX_INSTRUCTIONS,
)

TERMINATING_KINDS: Final[frozenset[str]] = frozenset({"ret", "jump", "cond_jump", "trap"})


@dataclass(frozen=True, slots=True)
class Block:
    """One straight-line run of instructions and where control goes next."""

    start: int
    end: int
    insns: tuple[Insn, ...]
    successors: tuple[int, ...]
    terminated: bool


@dataclass(frozen=True, slots=True)
class RecoveredFunction:
    entry: int
    arch: Arch
    blocks: tuple[Block, ...]
    degraded: bool = False

    @property
    def start(self) -> int:
        return self.blocks[0].start if self.blocks else self.entry

    @property
    def end(self) -> int:
        return max((block.end for block in self.blocks), default=self.entry)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return sum(len(block.successors) for block in self.blocks)

    @property
    def loop_count(self) -> int:
        starts = {block.start for block in self.blocks}
        return sum(
            1
            for block in self.blocks
            for succ in block.successors
            if succ in starts and succ <= block.start
        )

    @property
    def instruction_count(self) -> int:
        return sum(len(block.insns) for block in self.blocks)

    @property
    def is_small(self) -> bool:
        return self.instruction_count <= 12

    def op_counts(self) -> Counter[str]:
        counts: Counter[str] = Counter()
        for block in self.blocks:
            for insn in block.insns:
                if insn.kind != "ignored":
                    counts[insn.op] += 1
        return counts


@dataclass(frozen=True, slots=True)
class RecoveryLimits:
    """Budgets applied to untrusted bytes; tests shrink them deliberately."""

    max_function_bytes: int = MAX_FUNCTION_BYTES
    max_block_bytes: int = MAX_BLOCK_BYTES
    max_instructions: int = MAX_INSTRUCTIONS
    max_blocks: int = MAX_BLOCKS


def recover(
    source: ByteSource,
    addr: int,
    *,
    limits: RecoveryLimits | None = None,
) -> RecoveredFunction:
    """Recover the function containing ``addr`` from ``source``."""
    arch = ensure_supported(source.arch)
    bounds = limits or RecoveryLimits()

    hint = source.hint_function(addr)
    hinted = hint is not None and hint[0] <= addr < hint[1]
    function_end = hint[1] if hinted and hint is not None else addr + bounds.max_function_bytes
    if addr < 0 or function_end <= addr:
        raise DecodeError(f"function bounds for 0x{addr:x} are empty")

    def inside(target: int) -> bool:
        return addr <= target < function_end

    def is_tail_target(target: int) -> bool:
        # Authoritative symbol bounds define the function, so a symbol inside the
        # range is still ours. Without bounds, a jump onto another symbol is a
        # tail call and must not be followed into unrelated code.
        if hinted:
            return False
        return target != addr and source.name_for_address(target) is not None

    normalizer = Normalizer(source)
    blocks: dict[int, Block] = {}
    queue: list[int] = [addr]
    cursor = 0
    degraded = False

    while cursor < len(queue):
        start = queue[cursor]
        cursor += 1
        if start in blocks or not inside(start):
            continue
        if len(blocks) >= bounds.max_blocks:
            degraded = True
            break

        available = min(bounds.max_block_bytes, function_end - start)
        decoded = list(normalizer.decode_block(start, available))
        # Alignment padding after the last real instruction is not part of the
        # function body; trimming it keeps bounds comparable to symbol sizes.
        while decoded and decoded[-1].kind == "ignored":
            decoded.pop()
        if not decoded:
            continue

        last = decoded[-1]
        block_end = last.addr + last.size
        terminated = last.kind in TERMINATING_KINDS
        successors: list[int] = []

        if last.kind == "cond_jump":
            if last.target is not None and inside(last.target):
                successors.append(last.target)
            if inside(block_end):
                successors.append(block_end)
        elif last.kind == "jump":
            if last.target is not None and inside(last.target) and not is_tail_target(last.target):
                successors.append(last.target)
        elif last.kind in ("ret", "trap", "noreturn_call"):
            pass
        else:
            # Ran out of budget or bytes without a terminator: stop here and
            # mark the recovery as partial rather than guessing.
            degraded = True

        block = Block(
            start=start,
            end=block_end,
            insns=tuple(decoded),
            successors=tuple(dict.fromkeys(successors)),
            terminated=terminated,
        )
        blocks[start] = block
        for successor in block.successors:
            if successor not in blocks:
                queue.append(successor)

    if not blocks or addr not in blocks:
        raise DecodeError(f"no instructions recovered at 0x{addr:x}")

    ordered = tuple(blocks[start] for start in sorted(blocks))
    if sum(len(block.insns) for block in ordered) > bounds.max_instructions:
        degraded = True
    return RecoveredFunction(entry=addr, arch=arch, blocks=ordered, degraded=degraded)
