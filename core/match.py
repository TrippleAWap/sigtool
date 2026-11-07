"""Reference matcher: anchor prefilter, bounded recovery, weighted comparison.

The matcher is deliberately thin over the same extractor used for generation
(AGENTS.md rule 2). It never decodes instructions itself: candidates are
recovered with ``core.recover`` and compared with features from
``core.features``.

Tiers (spec §8):

* Tier 0 turns data anchors into byte needles and finds candidate hit addresses.
* Tier 1 recovers a bounded function at each candidate start.
* Tier 2 compares the recovered feature set against the signature and accepts
  it when the weighted score and ``min_distinct`` both pass.

String anchors are searched in data regions, so their hits only rank
candidates; constant anchors are searched in code and can locate a function
start directly. Discovering code that references a string needs the reference
index that lands with the M6 scanner, which is why known function starts are
used as candidates when the source can enumerate them.
"""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from core.errors import DecodeError, SelfTestError
from core.features import KIND_CONST, KIND_STR, Feature, extract
from core.normalize import Normalizer
from core.recover import RecoveryLimits, recover
from core.sigfile import Signature
from core.source import ByteSource, Region

MAX_HITS_PER_ANCHOR: Final[int] = 16
MAX_CANDIDATE_STARTS: Final[int] = 256
MAX_MATCHES: Final[int] = 32
BACKWARD_SWEEP_BYTES: Final[int] = 512
SCORE_DECIMALS: Final[int] = 6

# One- and two-byte immediates occur everywhere; searching for them produces
# noise without narrowing anything, so they are not used as needles.
MIN_SEARCHABLE_CONST: Final[int] = 0x100
MAX_CONST_BITS: Final[int] = 64


@dataclass(frozen=True, slots=True)
class Needle:
    """One anchor encoded as bytes, with the kind of region it can appear in."""

    key: str
    data: bytes
    executable: bool


@dataclass(frozen=True, slots=True)
class MatchScore:
    """Weighted comparison of one candidate against a signature."""

    score: float
    matched: tuple[str, ...]
    matched_required: int


@dataclass(frozen=True, slots=True)
class Match:
    """An accepted match: where it is and how strongly it scored."""

    address: int
    end: int
    score: float
    matched: tuple[str, ...]


def anchor_needles(signature: Signature) -> tuple[Needle, ...]:
    """Encode the signature's data anchors for Tier 0 scanning.

    Constants are indexed in both byte orders at both natural widths because a
    materialization may use ``mov`` or ``movabs``. Strings are indexed narrow and
    as UTF-16LE, since one binary may store either. Hashed long literals are not
    searchable and are skipped.
    """
    needles: list[Needle] = []
    for anchor in signature.anchors:
        kind, _, value = anchor.partition(":")
        if kind == KIND_CONST:
            for data in _const_needles(value):
                needles.append(Needle(anchor, data, executable=True))
        elif kind == KIND_STR:
            for data in _string_needles(value):
                needles.append(Needle(anchor, data, executable=False))
        # Callee anchors are names, not bytes: Tier 2 compares them after
        # recovery, where symbol resolution has already happened.
    needles.sort(key=lambda needle: (needle.key, needle.executable, needle.data))
    return tuple(needles)


def compare(signature: Signature, features: Sequence[Feature]) -> MatchScore:
    """Score a candidate feature set against ``signature``.

    Optional features add weight when present but never lower the score; the
    denominator is the required weight, so a candidate missing evidence scores
    below the threshold instead of being rejected outright.
    """
    present = {feature.key for feature in features}
    matched = [feature for feature in signature.features if feature.key in present]
    required_weight = sum(feature.weight for feature in signature.features if feature.required)
    if required_weight <= 0:
        required_weight = sum(feature.weight for feature in signature.features)
    matched_required = sum(1 for feature in matched if feature.required)
    if required_weight <= 0:
        return MatchScore(0.0, (), 0)
    total = sum(feature.weight for feature in matched)
    score = round(min(1.0, total / required_weight), SCORE_DECIMALS)
    return MatchScore(
        score=score,
        matched=tuple(sorted(feature.key for feature in matched)),
        matched_required=matched_required,
    )


def accepts(signature: Signature, result: MatchScore) -> bool:
    """Apply both gates: weighted threshold and minimum distinct evidence.

    The distinct gate is vacuous for a signature with no required features
    (shape-only signatures of very small functions), which would otherwise be
    unable to match at all.
    """
    required_count = sum(1 for feature in signature.features if feature.required)
    return result.score >= signature.match_threshold and result.matched_required >= min(
        signature.min_distinct, required_count
    )


def scan(
    source: ByteSource,
    signature: Signature,
    *,
    limits: RecoveryLimits | None = None,
    max_candidates: int = MAX_CANDIDATE_STARTS,
) -> tuple[Match, ...]:
    """Find accepted matches for ``signature`` in ``source``, best first."""
    hits = _anchor_hits(source, signature)
    matches: list[Match] = []
    for start in _candidate_starts(source, hits, max_candidates=max_candidates):
        try:
            recovered = recover(source, start, limits=limits)
        except DecodeError:
            continue
        result = compare(signature, extract(source, recovered))
        if accepts(signature, result):
            matches.append(
                Match(
                    address=recovered.start,
                    end=recovered.end,
                    score=result.score,
                    matched=result.matched,
                )
            )
    matches.sort(key=lambda match: (-match.score, match.address))
    return _dedupe(matches)[:MAX_MATCHES]


def _dedupe(matches: Sequence[Match]) -> tuple[Match, ...]:
    """Keep the best match per overlapping span.

    A sweep can recover the same body from an interior address, which scores
    almost as well. Reporting one function once keeps the hit list meaningful.
    """
    kept: list[Match] = []
    for match in matches:
        if any(
            match.address < kept_match.end and kept_match.address < match.end for kept_match in kept
        ):
            continue
        kept.append(match)
    return tuple(kept)


def self_test(
    signature: Signature,
    source: ByteSource,
    start: int,
    *,
    limits: RecoveryLimits | None = None,
    max_candidates: int = MAX_CANDIDATE_STARTS,
) -> Match:
    """Require ``signature`` to match the function at ``start``.

    Raises :class:`SelfTestError` when the matcher had a way to reach ``start``
    but did not accept a match there. When no anchor or known function start
    can reach it, the matcher cannot rediscover the function at all, so only
    the weaker structural check (does the signature still describe these bytes
    exactly?) is applied; that is a matcher limitation, not a signature defect,
    and M6's reference scanner removes it.
    """
    matches = scan(source, signature, limits=limits, max_candidates=max_candidates)
    for match in matches:
        if match.address == start:
            return match

    candidates = _candidate_starts(
        source,
        _anchor_hits(source, signature),
        max_candidates=max_candidates,
    )
    if start in candidates:
        if not matches:
            detail = "no candidate matched anywhere in the image"
        else:
            detail = f"best accepted match was at another function (score {matches[0].score:.3f})"
        raise SelfTestError(
            f"signature {signature.name!r} failed self-test at 0x{start:x}: {detail}"
        )

    recovered = recover(source, start, limits=limits)
    result = compare(signature, extract(source, recovered))
    required = sum(1 for feature in signature.features if feature.required)
    if result.score < 1.0 or result.matched_required != required:
        raise SelfTestError(
            f"signature {signature.name!r} does not describe the function at 0x{start:x}"
        )
    return Match(
        address=recovered.start,
        end=recovered.end,
        score=result.score,
        matched=result.matched,
    )


# -- Tier 0 ------------------------------------------------------------------


def _anchor_hits(source: ByteSource, signature: Signature) -> tuple[tuple[int, str], ...]:
    hits: list[tuple[int, str]] = []
    for needle in anchor_needles(signature):
        for region in source.regions():
            if region.executable != needle.executable or len(region.data) < len(needle.data):
                continue
            hits.extend(
                (address, needle.key)
                for address in _find_all(region, needle.data, MAX_HITS_PER_ANCHOR)
            )
    hits.sort()
    return tuple(hits)


def _find_all(region: Region, needle: bytes, limit: int) -> tuple[int, ...]:
    """Bounded occurrence search inside one region."""
    found: list[int] = []
    if not needle:
        return ()
    cursor = 0
    while len(found) < limit:
        index = region.data.find(needle, cursor)
        if index < 0:
            break
        found.append(region.start + index)
        cursor = index + 1
    return tuple(found)


def _const_needles(value: str) -> tuple[bytes, ...]:
    try:
        number = int(value, 16)
    except ValueError:
        return ()
    if number < MIN_SEARCHABLE_CONST or number.bit_length() > MAX_CONST_BITS:
        return ()
    low = number & 0xFFFF_FFFF
    encodings = {low.to_bytes(4, "little"), low.to_bytes(4, "big")}
    if number > 0xFFFF_FFFF:
        encodings.add(number.to_bytes(8, "little"))
        encodings.add(number.to_bytes(8, "big"))
    return tuple(sorted(encodings))


def _string_needles(value: str) -> tuple[bytes, ...]:
    text = _unescape(value)
    if text is None:
        return ()
    wide = value.startswith("w:")
    if wide:
        text = text[2:]
    encodings: set[bytes] = set()
    if wide:
        encodings.add(text.encode("utf-16-le", "ignore"))
    else:
        encodings.add(text.encode("latin-1", "ignore"))
        encodings.add(text.encode("utf-16-le", "ignore"))
    return tuple(sorted(encoding for encoding in encodings if encoding))


def _unescape(value: str) -> str | None:
    """Reverse ``core.features._escape``; ``None`` for hashed long literals."""
    if value.startswith("long:") or value.startswith("w:long:"):
        return None
    chars: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            chars.append(value[index + 1])
            index += 2
            continue
        chars.append(char)
        index += 1
    return "".join(chars)


# -- Tier 1 ------------------------------------------------------------------


def _candidate_starts(
    source: ByteSource, hits: Sequence[tuple[int, str]], *, max_candidates: int
) -> tuple[int, ...]:
    """Candidate function starts, ranked by closeness to a code-side anchor hit.

    Sources that can enumerate symbols give exact starts. Otherwise the matcher
    sweeps backwards from each code hit over real instruction boundaries, so a
    function whose constant was found mid-body can still be recovered from its
    prologue.
    """
    code_hits = sorted({address for address, _ in hits if source.is_executable(address)})
    starts = {start for start in source.function_starts() if source.is_executable(start)}
    # Known starts are only a shortcut when they cover the hit; otherwise the
    # matcher still has to find the enclosing function from the bytes.
    for address in code_hits:
        hint = source.hint_function(address)
        if hint is not None:
            starts.add(hint[0])
        else:
            starts.update(_swept_starts(source, address))
    if not starts:
        return ()
    return _rank(starts, code_hits)[:max_candidates]


def _swept_starts(source: ByteSource, address: int) -> tuple[int, ...]:
    """Instruction starts in a bounded window ending at ``address``."""
    region = source.region_for(address)
    if region is None:
        return ()
    normalizer = Normalizer(source)
    cursor = max(region.start, address - BACKWARD_SWEEP_BYTES)
    starts: list[int] = []
    while cursor <= address:
        insn = normalizer.normalize_one(cursor)
        if insn is None or insn.size <= 0:
            break
        starts.append(cursor)
        cursor += insn.size
    return tuple(starts)


def _rank(starts: Iterable[int], code_hits: Sequence[int]) -> tuple[int, ...]:
    """Order starts by proximity to a code anchor, then by address."""
    ranked: list[tuple[int, int, int]] = []
    for start in sorted(set(starts)):
        index = bisect_left(code_hits, start)
        best = min(
            (
                abs(code_hits[probe] - start)
                for probe in (index - 1, index)
                if 0 <= probe < len(code_hits)
            ),
            default=None,
        )
        near = best is not None and best <= 0x1_0000
        ranked.append((0 if near else 1, best if near and best is not None else 0, start))
    ranked.sort()
    return tuple(start for _, _, start in ranked)
