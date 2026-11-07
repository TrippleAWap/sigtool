"""Tool-neutral signature core: one extractor for generation and scanning.

Import rules: nothing here may import IDA modules or OS-specific APIs (see
AGENTS.md rule 1). All target access goes through :class:`core.source.ByteSource`.
"""

from __future__ import annotations

__all__ = ["SPEC_VERSION"]

from core.spec import SPEC_VERSION
