"""Golden vector regression: fixture images must yield the recorded features."""

from __future__ import annotations

from core.features import extract
from core.recover import recover
from core.source import MemorySource


def test_vector_matches_recorded_features(
    vector: dict[str, object], vector_source: MemorySource
) -> None:
    assert vector["functions"], "vector contains no functions"
    for name, info in vector["functions"].items():
        assert isinstance(info, dict)
        recovered = recover(vector_source, int(info["entry"]))
        features = extract(vector_source, recovered)
        assert [{"kind": f.kind, "value": f.value} for f in features] == info["features"], name
        assert recovered.block_count == info["blocks"], name
        assert recovered.edge_count == info["edges"], name
        assert recovered.loop_count == info["loops"], name


def test_features_contain_no_addresses(
    vector: dict[str, object], vector_source: MemorySource
) -> None:
    """Every const feature must be a value, never an address inside the image."""
    for info in vector["functions"].values():
        assert isinstance(info, dict)
        for feature in info["features"]:
            if feature["kind"] != "const":
                continue
            value = int(feature["value"], 16)
            assert vector_source.module_for(value) is None, feature
