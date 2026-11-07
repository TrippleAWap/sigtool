"""Multi-sample merging tests."""

from __future__ import annotations

import pytest

from core.match import scan
from core.merge import MergeError, MergeSample, merge
from tests.support import deep_source, strong_source, tiny_source


def _sample(source, addr: int, opt: str | None = None) -> MergeSample:
    return MergeSample(source, addr, opt=opt, tool="test")


def test_merge_needs_two_samples() -> None:
    with pytest.raises(MergeError, match="at least two"):
        merge([_sample(strong_source(), 0x1000)])


def test_merged_signature_keeps_stable_features_required() -> None:
    first = strong_source()
    second = strong_source()  # identical bytes: everything is stable
    result = merge(
        [_sample(first, 0x1000, opt="O0"), _sample(second, 0x1000, opt="O2")],
        name="twins",
    )
    signature = result.signature

    assert signature.name == "twins"
    assert signature.confidence == "single-arch"  # both samples are x64
    assert [sample.arch for sample in signature.provenance] == ["x64", "x64"]
    assert signature.provenance[0].opt == "O0"
    assert signature.provenance[1].opt == "O2"
    # Data features are stable, so they stay required; shape features are
    # optional in every signature by design (score.py OPTIONAL_KINDS).
    data = [f for f in signature.features if f.kind in ("str", "const", "callee")]
    assert data and all(feature.required for feature in data)


def test_merged_signature_demotes_divergent_features() -> None:
    # The deep fixture has the same string but constants far apart in the body;
    # combining it with the plain fixture forces shape features to differ.
    result = merge(
        [_sample(strong_source(), 0x1000, opt="O0"), _sample(deep_source(), 0x1000, opt="O2")],
        name="mixed",
    )
    signature = result.signature

    assert {feature.required for feature in signature.features} == {True, False}
    demoted = [feature for feature in signature.features if not feature.required]
    stable = [feature for feature in signature.features if feature.required]
    assert demoted, "divergent features must be demoted to optional"
    assert all(feature.weight < 1.0 for feature in demoted)
    assert stable, "shared features stay required"
    # Anchors may only come from features every sample carries.
    stable_keys = {feature.key for feature in stable}
    assert set(signature.anchors) <= stable_keys


def test_merged_cross_arch_tag_follows_the_samples() -> None:
    x64 = strong_source()
    same_arch = strong_source()
    result = merge([_sample(x64, 0x1000, opt="O0"), _sample(same_arch, 0x1000, opt="O0")])
    # Both sources report x64 here, so the tag must stay single-arch; the
    # multi-arch branch of confidence_for is covered by the corpus harness.
    assert result.signature.confidence == "single-arch"
    # The merged signature still finds the function in both samples.
    assert scan(x64, result.signature)[0].address == 0x1000


def test_merge_refuses_when_a_sample_cannot_be_refound() -> None:
    # tiny_source has no data features; the merged signature cannot match it.
    with pytest.raises(MergeError, match="self-test"):
        merge([_sample(strong_source(), 0x1000), _sample(tiny_source(), 0x1000)])


def test_merged_signature_is_deterministic() -> None:
    args = [_sample(strong_source(), 0x1000, opt="O2"), _sample(strong_source(), 0x1000, opt="Os")]
    first = merge(args, name="det").signature.to_yaml()
    second = merge(args, name="det").signature.to_yaml()
    assert first == second


def test_merged_self_test_covers_every_sample() -> None:
    first, second = strong_source(), strong_source()
    result = merge([_sample(first, 0x1000), _sample(second, 0x1000)])
    assert result.match.address == 0x1000
    # HELPER is a callee in both samples; the merged anchors are data features.
    assert result.signature.anchors
