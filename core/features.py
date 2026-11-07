"""Feature extraction: the single extractor used for signing and scanning.

Feature kinds are fixed by the spec (``str``, ``const``, ``callee``, ``cfg``,
``ops``). Output is sorted and free of addresses, so two runs on the same bytes
produce identical records, and ASLR-shifted copies produce identical records.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Final

from core.recover import RecoveredFunction
from core.source import ByteSource
from core.spec import SPEC_VERSION, STR_MAX_LEN, STR_MIN_LEN, bucket, digest

KIND_STR: Final[str] = "str"
KIND_CONST: Final[str] = "const"
KIND_CALLEE: Final[str] = "callee"
KIND_CFG: Final[str] = "cfg"
KIND_OPS: Final[str] = "ops"

FEATURE_KINDS: Final[tuple[str, ...]] = (
    KIND_STR,
    KIND_CONST,
    KIND_CALLEE,
    KIND_CFG,
    KIND_OPS,
)


@dataclass(frozen=True, slots=True, order=True)
class Feature:
    """One comparable fact about a function.

    ``required`` distinguishes features that must match from ones that only add
    evidence; M1 marks every feature required and multi-sample merging (M4) will
    demote unstable ones.
    """

    kind: str
    value: str
    required: bool = True

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


def extract(source: ByteSource, func: RecoveredFunction) -> tuple[Feature, ...]:
    """Extract the full feature set for a recovered function."""
    strings: set[str] = set()
    consts: set[int] = set()
    callees: set[str] = set()
    ops: Counter[str] = Counter()

    for block in func.blocks:
        for insn in block.insns:
            if insn.kind == "ignored":
                continue
            ops[insn.op] += 1
            for value in insn.consts:
                if not _is_pointer(source, value):
                    consts.add(value)
            for ref in insn.refs:
                text = string_at(source, ref.addr)
                if text is not None:
                    strings.add(text)
            if insn.callee:
                callees.add(insn.callee)

    features: list[Feature] = []
    features.extend(Feature(KIND_STR, text) for text in sorted(strings))
    features.extend(Feature(KIND_CONST, f"0x{value:x}") for value in sorted(consts))
    features.extend(Feature(KIND_CALLEE, name) for name in sorted(callees))
    features.append(Feature(KIND_CFG, f"blocks:{bucket(func.block_count)}"))
    features.append(Feature(KIND_CFG, f"edges:{bucket(func.edge_count)}"))
    features.append(Feature(KIND_CFG, f"loops:{bucket(func.loop_count)}"))
    features.extend(
        Feature(KIND_OPS, f"{op}:{bucket(count)}") for op, count in sorted(ops.items()) if count
    )
    return tuple(sorted(features))


def _is_pointer(source: ByteSource, value: int) -> bool:
    """Absolute addresses inside a mapped module must never become features."""
    if value == 0:
        return False
    return source.module_for(value) is not None


def string_at(source: ByteSource, addr: int, *, limit: int = STR_MAX_LEN) -> str | None:
    """Return the string literal at ``addr``, or ``None`` if it is not one.

    Only non-executable memory is considered, so jump-table and code references
    cannot masquerade as string anchors.
    """
    if addr <= 0 or source.is_executable(addr):
        return None
    # Partial read: the literal may end exactly at a section boundary.
    data = source.read_partial(addr, (limit + 1) * 2)
    if not data:
        return None
    narrow = _scan_narrow(data, limit)
    if narrow is not None:
        return narrow
    return _scan_wide(data, limit)


def _scan_narrow(data: bytes, limit: int) -> str | None:
    chars: list[str] = []
    terminated = False
    for index, byte in enumerate(data):
        if byte == 0:
            terminated = True
            break
        if not 0x20 <= byte <= 0x7E:
            return None
        if len(chars) < limit:
            chars.append(chr(byte))
        else:
            # Over-long literal: keep a stable digest of the prefix we read.
            return "long:" + digest(bytes(data[: index + 1]).decode("latin-1"))
    if not terminated or len(chars) < STR_MIN_LEN:
        return None
    return _escape("".join(chars))


def _scan_wide(data: bytes, limit: int) -> str | None:
    """Detect UTF-16LE literals: printable ASCII low bytes with zero high bytes."""
    chars: list[str] = []
    truncated = False
    index = 0
    while index + 1 < len(data):
        low, high = data[index], data[index + 1]
        if low == 0 and high == 0:
            if len(chars) < STR_MIN_LEN:
                return None
            return "w:" + _escape("".join(chars))
        if high != 0 or not 0x20 <= low <= 0x7E:
            return None
        if len(chars) >= limit:
            truncated = True
            break
        chars.append(chr(low))
        index += 2
    if truncated:
        return "w:long:" + digest(bytes(data[: 2 * limit]).decode("latin-1"))
    return None


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def feature_dicts(features: tuple[Feature, ...]) -> list[dict[str, object]]:
    """Serialise features for JSON golden vectors (spec version included)."""
    return [
        {
            "kind": feature.kind,
            "value": feature.value,
            "required": feature.required,
            "spec": SPEC_VERSION,
        }
        for feature in features
    ]
