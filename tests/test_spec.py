"""The written spec, the hash domain, and the code must agree on one version.

A spec-version drift is a compatibility bug: readers reject foreign versions, so
a mismatch between ``core.spec`` and ``spec/`` would make the tool unable to read
its own output. CI runs these checks on every change.
"""

from __future__ import annotations

from pathlib import Path

from core.spec import HASH_DIGEST_SIZE, HASH_PERSON, SPEC_VERSION

ROOT = Path(__file__).resolve().parents[1]


def test_hash_domain_matches_the_spec_version() -> None:
    assert f"sigtool.v{SPEC_VERSION}".encode() == HASH_PERSON


def test_written_spec_declares_the_current_version() -> None:
    text = (ROOT / "spec" / "SPEC.md").read_text(encoding="utf-8")

    assert text.splitlines()[0] == f"# Signature spec v{SPEC_VERSION}"
    assert f'person=b"sigtool.v{SPEC_VERSION}"' in text
    assert f"`digest_size={HASH_DIGEST_SIZE}`" in text


def test_changelog_has_an_entry_for_the_current_version() -> None:
    text = (ROOT / "spec" / "CHANGELOG.md").read_text(encoding="utf-8")

    assert f"## v{SPEC_VERSION} " in text
