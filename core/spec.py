"""Spec-level constants.

Every value here is part of the signature spec: changing a bucket boundary, a
hash person string, or a string-length limit changes feature records and
therefore requires bumping ``SPEC_VERSION`` and editing ``spec/``.
"""

from __future__ import annotations

from hashlib import blake2b
from typing import Final

SPEC_VERSION: Final[str] = "1"

# blake2b personalization fixes the hash domain; never use Python's hash() for
# anything that is persisted (it is salted per process).
HASH_PERSON: Final[bytes] = b"sigtool.v1"
HASH_DIGEST_SIZE: Final[int] = 16

# Bucket index = number of bounds <= value - 1, so a value of 0 lands in bucket
# 0 and anything above the last bound lands in the last bucket. Sparse buckets
# absorb small count differences between compilers and architectures.
BUCKET_BOUNDS: Final[tuple[int, ...]] = (0, 1, 2, 3, 4, 6, 9, 13, 19, 28, 40, 60, 90, 135, 200)

STR_MIN_LEN: Final[int] = 4
STR_MAX_LEN: Final[int] = 120

# Recovery budgets. These bound work on untrusted, possibly-random bytes.
MAX_FUNCTION_BYTES: Final[int] = 0x1_0000
MAX_BLOCK_BYTES: Final[int] = 0x1000
MAX_INSTRUCTIONS: Final[int] = 20_000
MAX_BLOCKS: Final[int] = 512
MAX_READ_BYTES: Final[int] = 0x1_0000
MAX_THUNK_HOPS: Final[int] = 4


def digest(text: str) -> str:
    """Return the spec-defined hex digest used for over-long feature values."""
    return blake2b(
        text.encode("utf-8", "surrogatepass"),
        digest_size=HASH_DIGEST_SIZE,
        person=HASH_PERSON,
    ).hexdigest()


def bucket(value: int) -> int:
    """Map a count to its bucket index (see ``BUCKET_BOUNDS``)."""
    if value <= 0:
        return 0
    index = 0
    for index, bound in enumerate(BUCKET_BOUNDS):
        if value <= bound:
            return index
    return len(BUCKET_BOUNDS) - 1


def bucket_range(index: int) -> tuple[int, int]:
    """Return the ``(low, high)`` range covered by a bucket (``high=-1``: open)."""
    if index <= 0:
        return (0, BUCKET_BOUNDS[0])
    if index >= len(BUCKET_BOUNDS) - 1:
        return (BUCKET_BOUNDS[-2] + 1, -1)
    return (BUCKET_BOUNDS[index - 1] + 1, BUCKET_BOUNDS[index])
