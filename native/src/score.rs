//! Deterministic feature weighting, anchor selection, and match thresholds.
//!
//! Weights express *evidence*, not identity. Data features (strings, constants,
//! callees) carry the signature; shape features only corroborate, so they are
//! optional and light. Every weight is rounded and every ordering is explicit,
//! so the same input yields the same document on any machine.

use std::collections::{HashMap, HashSet};

use crate::features::{Feature, FeatureKind};
use crate::sigfile::SignatureFeature;

/// Base discriminative power per kind. Shape features are deliberately weak: a
/// bucket match is common and must never carry a signature on its own.
pub const BASE_WEIGHTS: [(FeatureKind, f64); 5] = [
    (FeatureKind::Str, 1.0),
    (FeatureKind::Callee, 0.9),
    (FeatureKind::Const, 0.7),
    (FeatureKind::Cfg, 0.25),
    (FeatureKind::Ops, 0.15),
];

pub const DATA_KINDS: [FeatureKind; 3] =
    [FeatureKind::Str, FeatureKind::Const, FeatureKind::Callee];
pub const OPTIONAL_KINDS: [FeatureKind; 2] = [FeatureKind::Cfg, FeatureKind::Ops];

pub const MAX_ANCHORS: usize = 4;
pub const WEIGHT_DECIMALS: usize = 3;
pub const MIN_WEIGHT: f64 = 0.001;

/// A signature with fewer anchors can only be matched by weighted comparison,
/// so it needs more of its evidence to line up.
pub const MATCH_THRESHOLD_TWO_ANCHORS: f64 = 0.75;
pub const MATCH_THRESHOLD_ONE_ANCHOR: f64 = 0.85;
pub const MATCH_THRESHOLD_NO_ANCHORS: f64 = 0.95;

/// `min_distinct` is capped: beyond three independent features, extra
/// requirements mostly hurt recall on edited code.
pub const MAX_MIN_DISTINCT: usize = 3;

/// A feature with its weight and whether a match must include it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredFeature {
    pub feature: Feature,
    pub weight: f64,
    pub required: bool,
}

impl ScoredFeature {
    pub fn key(&self) -> String {
        feature_key(&self.feature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub match_threshold: f64,
    pub min_distinct: usize,
}

/// Canonical anchor form: `kind:value`.
pub fn feature_key(feature: &Feature) -> String {
    feature.key()
}

/// Inverse document frequency per feature key over a reference corpus.
///
/// `idf = ln((N + 1) / (df + 1)) + 1` keeps common features near 1.0 and
/// boosts rare ones.
pub fn build_idf<'a, I>(feature_sets: I) -> HashMap<String, f64>
where
    I: IntoIterator<Item = &'a [Feature]>,
{
    let documents: Vec<&[Feature]> = feature_sets.into_iter().collect();
    if documents.is_empty() {
        return HashMap::new();
    }
    let mut document_frequency: HashMap<String, usize> = HashMap::new();
    for features in &documents {
        let keys: HashSet<String> = features.iter().map(Feature::key).collect();
        for key in keys {
            *document_frequency.entry(key).or_insert(0) += 1;
        }
    }
    let total = documents.len() as f64;
    let mut weights: HashMap<String, f64> = document_frequency
        .into_iter()
        .map(|(key, count)| {
            let value = ((total + 1.0) / (count as f64 + 1.0)).ln() + 1.0;
            (key, round_to(value, WEIGHT_DECIMALS))
        })
        .collect();
    weights.retain(|_, _| true);
    weights
}

/// Assign weights and required flags, sorted by `(kind, value)`.
pub fn score_features(
    features: &[Feature],
    idf: Option<&HashMap<String, f64>>,
) -> Vec<ScoredFeature> {
    let mut scored: Vec<ScoredFeature> = features
        .iter()
        .map(|feature| {
            let mut weight = base_weight(feature.kind) * rarity(feature);
            if let Some(idf) = idf {
                weight *= idf.get(&feature_key(feature)).copied().unwrap_or(1.0);
            }
            ScoredFeature {
                feature: feature.clone(),
                weight: MIN_WEIGHT.max(round_to(weight, WEIGHT_DECIMALS)),
                required: feature.required && !OPTIONAL_KINDS.contains(&feature.kind),
            }
        })
        .collect();
    scored.sort_by(|left, right| {
        (left.feature.kind, left.feature.value.as_str())
            .cmp(&(right.feature.kind, right.feature.value.as_str()))
    });
    scored
}

fn base_weight(kind: FeatureKind) -> f64 {
    BASE_WEIGHTS
        .iter()
        .find(|(candidate, _)| *candidate == kind)
        .map(|(_, weight)| *weight)
        .unwrap_or(0.0)
}

/// Small multipliers for features that are inherently more specific.
fn rarity(feature: &Feature) -> f64 {
    match feature.kind {
        FeatureKind::Str => {
            // Longer literals are rarer and survive edits better.
            1.0 + (feature.value.len() as f64 / 80.0).min(0.5)
        }
        FeatureKind::Const => {
            let value = parse_hex(&feature.value);
            match value {
                // Small constants are ubiquitous in compiler output.
                Some(value) if value < 0x100 => 0.6,
                _ => 1.0,
            }
        }
        _ => 1.0,
    }
}

fn parse_hex(value: &str) -> Option<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16).ok()
}

/// Pick the rarest, heaviest data features as Tier 0 anchors.
///
/// Anchors are ordered by weight (desc), then kind and value, so the list is
/// stable for identical input.
pub fn select_anchors(scored: &[ScoredFeature], limit: usize) -> Vec<String> {
    let mut data: Vec<&ScoredFeature> = scored
        .iter()
        .filter(|item| DATA_KINDS.contains(&item.feature.kind))
        // An optional feature may be absent from a correct match, so it
        // cannot stand for the signature.
        .filter(|item| item.required)
        // A call into another library (`memcpy`, `free`) is common to
        // unrelated functions; it must not lower the match threshold.
        .filter(|item| {
            !(item.feature.kind == FeatureKind::Callee && item.feature.value.contains('!'))
        })
        .collect();
    data.sort_by(|left, right| {
        right
            .weight
            .partial_cmp(&left.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.feature.kind.cmp(&right.feature.kind))
            .then(left.feature.value.cmp(&right.feature.value))
    });
    data.into_iter()
        .take(limit)
        .map(ScoredFeature::key)
        .collect()
}

pub fn choose_thresholds(anchor_count: usize, required_count: usize) -> Thresholds {
    let match_threshold = if anchor_count >= 2 {
        MATCH_THRESHOLD_TWO_ANCHORS
    } else if anchor_count == 1 {
        MATCH_THRESHOLD_ONE_ANCHOR
    } else {
        MATCH_THRESHOLD_NO_ANCHORS
    };
    Thresholds {
        match_threshold,
        min_distinct: 1.max(MAX_MIN_DISTINCT.min(required_count)),
    }
}

/// Confidence tag stored in the signature (see spec §7).
pub fn confidence_for(multi_arch: bool, is_small: bool, anchor_count: usize) -> String {
    if is_small || anchor_count == 0 {
        return "low".to_string();
    }
    if multi_arch {
        "multi-arch".to_string()
    } else {
        "single-arch".to_string()
    }
}

/// Total weight of the features a match must include.
pub fn required_weight(scored: &[ScoredFeature]) -> f64 {
    let total: f64 = scored
        .iter()
        .filter(|item| item.required)
        .map(|item| item.weight)
        .sum();
    round_to(total, WEIGHT_DECIMALS)
}

/// Convert a scored feature into its document form.
pub fn signature_feature(item: &ScoredFeature) -> SignatureFeature {
    SignatureFeature {
        kind: item.feature.kind,
        value: item.feature.value.clone(),
        weight: item.weight,
        required: item.required,
    }
}

fn round_to(value: f64, decimals: usize) -> f64 {
    format!("{value:.decimals$}")
        .parse::<f64>()
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_matches_python_half_even() {
        assert_eq!(round_to(1.0 + 21.0 / 80.0, 3), 1.262);
        assert_eq!(round_to(1.0 + 4.0 / 80.0, 3), 1.05);
    }

    #[test]
    fn thresholds_follow_anchor_count() {
        assert_eq!(choose_thresholds(2, 3).match_threshold, 0.75);
        assert_eq!(choose_thresholds(1, 3).match_threshold, 0.85);
        assert_eq!(choose_thresholds(0, 3).match_threshold, 0.95);
        assert_eq!(choose_thresholds(2, 9).min_distinct, 3);
    }
}
