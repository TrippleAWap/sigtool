"""The signature document: canonical YAML, validation, and stable identity.

The YAML form is the reviewed, diffable source of truth; the canonical bytes of
that text are the signature identity. Nothing here may include timestamps,
absolute paths, or absolute addresses (AGENTS.md rules 3 and 4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import yaml

from core.errors import SignatureError
from core.features import FEATURE_KINDS
from core.spec import SPEC_VERSION, digest

CONFIDENCE_TAGS: Final[frozenset[str]] = frozenset({"single-arch", "multi-arch", "low"})
MAX_ANCHORS: Final[int] = 8
MAX_WEIGHT: Final[float] = 10.0


@dataclass(frozen=True, slots=True)
class SignatureFeature:
    """One weighted feature inside a signature."""

    kind: str
    value: str
    weight: float
    required: bool = True

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True, slots=True)
class SampleProvenance:
    """Where one sample came from: module name and RVA, never a path."""

    arch: str
    module: str
    rva: int
    opt: str | None = None
    tool: str | None = None


@dataclass(frozen=True, slots=True)
class Signature:
    """A generation-time signature and its match parameters."""

    name: str
    features: tuple[SignatureFeature, ...]
    anchors: tuple[str, ...]
    match_threshold: float
    min_distinct: int
    confidence: str
    provenance: tuple[SampleProvenance, ...]
    spec_version: str = SPEC_VERSION

    def __post_init__(self) -> None:
        if self.spec_version != SPEC_VERSION:
            raise SignatureError(
                f"signature spec version {self.spec_version!r} is not {SPEC_VERSION!r}"
            )
        if not self.name:
            raise SignatureError("signature name must not be empty")
        if not self.features:
            raise SignatureError("signature must contain at least one feature")
        if self.confidence not in CONFIDENCE_TAGS:
            raise SignatureError(f"unknown confidence tag {self.confidence!r}")
        if not 0.0 < self.match_threshold <= 1.0:
            raise SignatureError("match threshold must be in (0, 1]")
        if not 1 <= self.min_distinct <= len(self.features):
            raise SignatureError("min_distinct must be between 1 and the feature count")
        if not self.provenance:
            raise SignatureError("signature needs at least one provenance sample")

        seen: set[str] = set()
        for feature in self.features:
            if feature.kind not in FEATURE_KINDS:
                raise SignatureError(f"unknown feature kind {feature.kind!r}")
            if feature.key in seen:
                raise SignatureError(f"duplicate feature {feature.key!r}")
            seen.add(feature.key)
            if not 0.0 < feature.weight <= MAX_WEIGHT:
                raise SignatureError(f"feature {feature.key!r} has an invalid weight")

        if len(self.anchors) > MAX_ANCHORS:
            raise SignatureError("too many anchors")
        for anchor in self.anchors:
            if anchor not in seen:
                raise SignatureError(f"anchor {anchor!r} is not one of the features")

        for sample in self.provenance:
            if "/" in sample.module or "\\" in sample.module:
                raise SignatureError("provenance module must be a name, not a path")
            if sample.rva < 0:
                raise SignatureError("provenance rva must not be negative")

    # -- serialisation -----------------------------------------------------

    def to_yaml(self) -> str:
        """Canonical YAML text; the same signature always serialises identically."""
        features = sorted(self.features, key=lambda feature: (feature.kind, feature.value))
        document: dict[str, Any] = {
            "spec_version": self.spec_version,
            "name": self.name,
            "confidence": self.confidence,
            "anchors": list(self.anchors),
            "thresholds": {
                "match": self.match_threshold,
                "min_distinct": self.min_distinct,
            },
            "features": [
                {
                    "kind": feature.kind,
                    "value": feature.value,
                    "weight": feature.weight,
                    "required": feature.required,
                }
                for feature in features
            ],
            "provenance": [_provenance_document(sample) for sample in self.provenance],
        }
        return yaml.safe_dump(
            document,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
            width=1000,
        )

    def canonical_bytes(self) -> bytes:
        return self.to_yaml().encode("utf-8")

    @property
    def signature_id(self) -> str:
        """Stable identity: spec digest of the canonical YAML text."""
        return digest(self.to_yaml())

    @classmethod
    def from_yaml(cls, text: str) -> Signature:
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise SignatureError(f"invalid signature YAML: {error}") from error
        document = _as_dict(raw, "signature")

        features = tuple(
            SignatureFeature(
                kind=_as_str(item.get("kind"), "feature.kind"),
                value=_as_str(item.get("value"), "feature.value"),
                weight=_as_float(item.get("weight"), "feature.weight"),
                required=_as_bool(item.get("required", True), "feature.required"),
            )
            for item in (
                _as_dict(entry, "feature")
                for entry in _as_list(document.get("features"), "features")
            )
        )
        thresholds = _as_dict(document.get("thresholds"), "thresholds")
        provenance = tuple(
            SampleProvenance(
                arch=_as_str(item.get("arch"), "provenance.arch"),
                module=_as_str(item.get("module"), "provenance.module"),
                rva=_as_rva(item.get("rva")),
                opt=_as_optional_str(item.get("opt")),
                tool=_as_optional_str(item.get("tool")),
            )
            for item in (
                _as_dict(entry, "provenance")
                for entry in _as_list(document.get("provenance"), "provenance")
            )
        )
        return cls(
            spec_version=_as_str(document.get("spec_version"), "spec_version"),
            name=_as_str(document.get("name"), "name"),
            confidence=_as_str(document.get("confidence"), "confidence"),
            anchors=tuple(
                _as_str(anchor, "anchor")
                for anchor in _as_list(document.get("anchors", []), "anchors")
            ),
            match_threshold=_as_float(thresholds.get("match"), "thresholds.match"),
            min_distinct=_as_int(thresholds.get("min_distinct"), "thresholds.min_distinct"),
            features=features,
            provenance=provenance,
        )


def _provenance_document(sample: SampleProvenance) -> dict[str, object]:
    document: dict[str, object] = {
        "arch": sample.arch,
        "module": sample.module,
        "rva": f"0x{sample.rva:x}",
    }
    if sample.opt is not None:
        document["opt"] = sample.opt
    if sample.tool is not None:
        document["tool"] = sample.tool
    return document


def _as_dict(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SignatureError(f"{what} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _as_list(value: object, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise SignatureError(f"{what} must be a list")
    return value


def _as_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise SignatureError(f"{what} must be a string")
    return value


def _as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SignatureError("optional provenance fields must be strings")
    return value


def _as_bool(value: object, what: str) -> bool:
    if not isinstance(value, bool):
        raise SignatureError(f"{what} must be a boolean")
    return value


def _as_float(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SignatureError(f"{what} must be a number")
    return float(value)


def _as_int(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SignatureError(f"{what} must be an integer")
    return value


def _as_rva(value: object) -> int:
    if isinstance(value, bool):
        raise SignatureError("provenance.rva must be an integer or hex string")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise SignatureError(f"invalid provenance rva {value!r}") from error
    raise SignatureError("provenance.rva must be an integer or hex string")
