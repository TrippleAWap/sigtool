//! Quality report for a signature at generation time.
//!
//! This reports what can be measured without a matcher: how much independent
//! evidence the signature carries, whether it can be anchored, and whether
//! recovery was complete. Self-test against the reference matcher is run by
//! [`crate::generate`].

use std::collections::HashSet;

use crate::features::FeatureKind;
use crate::matcher::identifying_key;
use crate::score::{required_weight, ScoredFeature, DATA_KINDS};

pub const STRONG_MIN_DATA_FEATURES: usize = 2;
pub const STRONG_MIN_DATA_KINDS: usize = 2;
pub const STRONG_MIN_ANCHORS: usize = 2;
/// Required features that identify a function by themselves
/// ([`crate::matcher::identifying_key`]: a string, a callee inside the
/// image, a constant at least `0x100` from zero) that a `strong` signature
/// needs. Imports and near-zero constants count as data features and
/// anchors, but a match can satisfy the threshold with them alone, so a
/// signature resting on one identifying feature plus `memset` and the
/// constants 0-4 is matched in unrelated code without it. Measured on the
/// real corpus (`bench --fp-report`, hinted, max 4 functions): all 7 strong
/// signatures with a false positive had exactly one identifying required
/// feature (one merged signature had two, its false hit matched neither);
/// requiring 2 keeps 87 of 173 strong signatures with 1 false positive
/// (0.011, 0.000 with the unanchored-similarity floor of the matcher); 3
/// keeps 85 with none; 1 changes nothing.
pub const STRONG_MIN_IDENTIFYING: usize = 2;
pub const SMALL_FUNCTION_INSTRUCTIONS: usize = 12;

/// Verdict and supporting counts for one generated signature.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityReport {
    pub verdict: String,
    pub confidence: String,
    pub data_features: usize,
    pub required_features: usize,
    pub optional_features: usize,
    pub anchor_count: usize,
    pub evidence: f64,
    pub notes: Vec<String>,
}

impl QualityReport {
    pub fn is_strong(&self) -> bool {
        self.verdict == "strong"
    }
}

/// Classify a signature as `strong`, `weak`, or `small`.
///
/// `strong` requires at least two anchors, two data features, two different
/// data kinds, and two required features that identify a function by
/// themselves. `small` is reserved for functions with too few instructions to
/// anchor; everything else is `weak`.
pub fn quality_report(
    scored: &[ScoredFeature],
    anchors: &[String],
    confidence: &str,
    instruction_count: usize,
    degraded: bool,
) -> QualityReport {
    // Only required data features are evidence a match must carry. A merged
    // signature demotes features one sample lacks to optional; counting those
    // labelled `fibonacci` strong on the constants 1 and 2 plus an x64-only
    // callee, and it then matched in every negative binary.
    let data: Vec<&ScoredFeature> = scored
        .iter()
        .filter(|item| item.required && DATA_KINDS.contains(&item.feature.kind))
        .collect();
    let data_kinds: HashSet<FeatureKind> = data.iter().map(|item| item.feature.kind).collect();
    let identifying = data
        .iter()
        .filter(|item| identifying_key(&item.key()))
        .count();
    let required = scored.iter().filter(|item| item.required).count();
    let optional = scored.iter().filter(|item| !item.required).count();
    let is_small = instruction_count <= SMALL_FUNCTION_INSTRUCTIONS;

    let mut notes: Vec<String> = Vec::new();
    if degraded {
        notes.push("recovery was partial; bounds may be truncated".to_string());
    }
    if is_small {
        notes.push(format!(
            "small function ({instruction_count} instructions); match with neighbour context"
        ));
    }
    if anchors.is_empty() {
        notes.push("no data anchors; Tier 0 cannot trigger".to_string());
    } else if anchors.len() < STRONG_MIN_ANCHORS {
        notes.push("only one data anchor; Tier 0 shortlist is broad".to_string());
    }
    if data.is_empty() {
        notes.push("no string, constant, or callee features".to_string());
    }
    if data_kinds.len() < STRONG_MIN_DATA_KINDS {
        notes.push("evidence comes from a single feature kind".to_string());
    }
    if identifying < STRONG_MIN_IDENTIFYING {
        notes.push(format!(
            "{identifying} identifying required feature(s); imports and near-zero constants identify nothing"
        ));
    }
    if confidence == "low" {
        notes.push("signature carries low confidence".to_string());
    }

    let verdict = if is_small {
        "small"
    } else if anchors.len() >= STRONG_MIN_ANCHORS
        && data.len() >= STRONG_MIN_DATA_FEATURES
        && data_kinds.len() >= STRONG_MIN_DATA_KINDS
        && identifying >= STRONG_MIN_IDENTIFYING
        && !degraded
    {
        "strong"
    } else {
        "weak"
    };

    QualityReport {
        verdict: verdict.to_string(),
        confidence: confidence.to_string(),
        data_features: data.len(),
        required_features: required,
        optional_features: optional,
        anchor_count: anchors.len(),
        evidence: required_weight(scored),
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::Feature;

    fn required(kind: FeatureKind, value: &str, weight: f64) -> ScoredFeature {
        ScoredFeature {
            feature: Feature::new(kind, value),
            weight,
            required: true,
        }
    }

    // Required evidence of `LZ4_loadDict` (lz4, arm32, clang -O2) from the
    // real corpus: an import, four near-zero constants, and one hash
    // constant. Labelled strong before, it matched functions in sqlite and
    // zlib on the import and the small constants alone.
    fn lz4_load_dict() -> Vec<ScoredFeature> {
        vec![
            required(FeatureKind::Callee, "*!memset", 0.9),
            required(FeatureKind::Const, "0x9e3779b1", 0.7),
            required(FeatureKind::Const, "0x0", 0.42),
            required(FeatureKind::Const, "0x2", 0.42),
            required(FeatureKind::Const, "0x3", 0.42),
            required(FeatureKind::Const, "0x4", 0.42),
        ]
    }

    fn anchors() -> Vec<String> {
        vec![
            "callee:*!memset".to_string(),
            "const:0x9e3779b1".to_string(),
            "const:0x0".to_string(),
            "const:0x2".to_string(),
        ]
    }

    #[test]
    fn one_identifying_feature_is_not_strong() {
        let report = quality_report(&lz4_load_dict(), &anchors(), "single-arch", 40, false);
        assert_eq!(report.verdict, "weak");
        assert!(report
            .notes
            .iter()
            .any(|note| note.starts_with("1 identifying")));
    }

    #[test]
    fn two_identifying_features_are_strong() {
        let mut scored = lz4_load_dict();
        scored.push(required(FeatureKind::Str, "dictionary too large", 1.25));
        let report = quality_report(&scored, &anchors(), "single-arch", 40, false);
        assert_eq!(report.verdict, "strong");
    }
}
