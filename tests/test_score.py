"""Scoring tests: weight ordering, IDF, anchors, thresholds, confidence."""

from __future__ import annotations

from core.features import Feature
from core.score import (
    DATA_KINDS,
    ScoredFeature,
    build_idf,
    choose_thresholds,
    confidence_for,
    score_features,
    select_anchors,
)

FEATURES = (
    Feature("callee", "helper"),
    Feature("cfg", "blocks:1"),
    Feature("const", "0x1234"),
    Feature("ops", "ret:1"),
    Feature("str", "banner literal"),
)


def test_data_features_are_required_and_shape_features_optional() -> None:
    scored = {item.feature.kind: item for item in score_features(FEATURES)}
    assert scored["str"].required
    assert scored["const"].required
    assert scored["callee"].required
    assert not scored["cfg"].required
    assert not scored["ops"].required


def test_weights_follow_kind_priority() -> None:
    scored = {item.feature.kind: item.weight for item in score_features(FEATURES)}
    assert scored["str"] > scored["callee"] > scored["const"] > scored["cfg"] > scored["ops"]


def test_scoring_is_sorted_and_deterministic() -> None:
    first = score_features(FEATURES)
    second = score_features(tuple(reversed(FEATURES)))
    assert first == second
    assert list(first) == sorted(first, key=lambda item: (item.feature.kind, item.feature.value))


def test_idf_boosts_rare_features() -> None:
    common = Feature("str", "common literal")
    rare = Feature("str", "rare literal")
    idf = build_idf(
        [
            (common, rare),
            (common,),
            (common,),
        ]
    )
    weights = {item.feature.value: item.weight for item in score_features((common, rare), idf=idf)}
    assert weights["rare literal"] > weights["common literal"]


def test_idf_is_key_sorted() -> None:
    idf = build_idf([(Feature("str", "a literal"),), (Feature("str", "b literal"),)])
    assert list(idf) == sorted(idf)


def test_idf_of_empty_corpus_is_empty() -> None:
    assert build_idf([]) == {}


def test_anchors_are_data_features_ordered_by_weight() -> None:
    scored = score_features(
        (*FEATURES, Feature("str", "a much longer and rarer banner literal here"))
    )
    anchors = select_anchors(scored)
    assert len(anchors) == 4
    kinds = {anchor.split(":", 1)[0] for anchor in anchors}
    assert kinds <= DATA_KINDS
    assert "cfg:" not in " ".join(anchors)
    assert "ops:" not in " ".join(anchors)
    weights = {item.key: item.weight for item in scored}
    assert [weights[anchor] for anchor in anchors] == sorted(
        (weights[anchor] for anchor in anchors), reverse=True
    )


def test_anchor_limit_is_respected() -> None:
    scored = score_features(tuple(Feature("const", f"0x{value:x}") for value in range(10, 20)))
    assert len(select_anchors(scored)) == 4


def test_thresholds_depend_on_anchor_count() -> None:
    assert choose_thresholds(anchor_count=2, required_count=4).match == 0.75
    assert choose_thresholds(anchor_count=1, required_count=4).match == 0.85
    assert choose_thresholds(anchor_count=0, required_count=4).match == 0.95


def test_min_distinct_is_capped_and_lower_bounded() -> None:
    assert choose_thresholds(anchor_count=0, required_count=0).min_distinct == 1
    assert choose_thresholds(anchor_count=2, required_count=2).min_distinct == 2
    assert choose_thresholds(anchor_count=2, required_count=9).min_distinct == 3


def test_confidence_tags() -> None:
    assert confidence_for(multi_arch=True, is_small=False, anchor_count=2) == "multi-arch"
    assert confidence_for(multi_arch=True, is_small=True, anchor_count=2) == "low"
    assert confidence_for(multi_arch=False, is_small=False, anchor_count=1) == "single-arch"
    assert confidence_for(multi_arch=False, is_small=False, anchor_count=0) == "low"


def test_scored_feature_key_matches_anchor_form() -> None:
    scored = ScoredFeature(feature=Feature("str", "x y z"), weight=1.0, required=True)
    assert scored.key == "str:x y z"
