"""Signature document tests: canonical YAML, round trip, and validation."""

from __future__ import annotations

import pytest

from core.errors import SignatureError
from core.sigfile import SampleProvenance, Signature, SignatureFeature
from core.spec import SPEC_VERSION


def make_signature(**overrides: object) -> Signature:
    values: dict[str, object] = {
        "name": "fixture_fn",
        "features": (
            SignatureFeature("const", "0x1234", 0.7, True),
            SignatureFeature("ops", "ret:1", 0.15, False),
            SignatureFeature("str", "banner literal", 1.2, True),
        ),
        "anchors": ("str:banner literal", "const:0x1234"),
        "match_threshold": 0.75,
        "min_distinct": 2,
        "confidence": "single-arch",
        "provenance": (SampleProvenance("x64", "fixture", 0x1200, opt="O2", tool="test"),),
    }
    values.update(overrides)
    return Signature(**values)  # type: ignore[arg-type]


def test_round_trip_is_exact() -> None:
    signature = make_signature()
    assert Signature.from_yaml(signature.to_yaml()) == signature


def test_yaml_is_byte_stable() -> None:
    signature = make_signature()
    assert signature.to_yaml() == signature.to_yaml()
    assert signature.signature_id == signature.signature_id


def test_yaml_has_canonical_field_order() -> None:
    text = make_signature().to_yaml()
    positions = [
        text.index(f"{key}:")
        for key in ("spec_version", "name", "confidence", "anchors", "thresholds", "features")
    ]
    assert positions == sorted(positions)


def test_yaml_excludes_absolute_addresses_and_paths() -> None:
    text = make_signature().to_yaml()
    assert "rva: '0x1200'" in text or "rva: 0x1200" in text
    assert "\\" not in text


def test_spec_version_mismatch_is_rejected() -> None:
    text = make_signature().to_yaml()
    lines = [
        "spec_version: '999'" if line.startswith("spec_version:") else line
        for line in text.splitlines()
    ]
    with pytest.raises(SignatureError):
        Signature.from_yaml("\n".join(lines) + "\n")


def test_unknown_feature_kind_is_rejected() -> None:
    with pytest.raises(SignatureError):
        make_signature(features=(SignatureFeature("bytes", "deadbeef", 1.0, True),))


def test_duplicate_feature_is_rejected() -> None:
    duplicate = SignatureFeature("str", "banner literal", 1.0, True)
    with pytest.raises(SignatureError):
        make_signature(features=(duplicate, duplicate))


def test_anchor_must_exist_in_features() -> None:
    with pytest.raises(SignatureError):
        make_signature(anchors=("str:not present",))


def test_provenance_rejects_paths() -> None:
    with pytest.raises(SignatureError):
        make_signature(provenance=(SampleProvenance("x64", "C:\\build\\fixture.exe", 0x1000),))


def test_invalid_threshold_is_rejected() -> None:
    with pytest.raises(SignatureError):
        make_signature(match_threshold=0.0)


def test_non_mapping_document_is_rejected() -> None:
    with pytest.raises(SignatureError):
        Signature.from_yaml("- just\n- a list\n")


def test_invalid_yaml_is_rejected() -> None:
    with pytest.raises(SignatureError):
        Signature.from_yaml("spec_version: [unterminated")


def test_loaded_signature_redumps_identically() -> None:
    signature = make_signature()
    text = signature.to_yaml()
    assert Signature.from_yaml(text).to_yaml() == text


def test_spec_version_is_current() -> None:
    assert make_signature().spec_version == SPEC_VERSION
