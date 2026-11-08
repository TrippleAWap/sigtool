//! Quality report for a signature at generation time.
//!
//! This reports what can be measured without a matcher: how much independent
//! evidence the signature carries, whether it can be anchored, and whether
//! recovery was complete. Self-test against the reference matcher is run by
//! [`crate::generate`].

use std::collections::HashSet;

use crate::features::FeatureKind;
use crate::score::{required_weight, ScoredFeature, DATA_KINDS};

pub const STRONG_MIN_DATA_FEATURES: usize = 2;
pub const STRONG_MIN_DATA_KINDS: usize = 2;
pub const STRONG_MIN_ANCHORS: usize = 2;
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
/// `strong` requires at least two anchors, two data features, and two different
/// data kinds. `small` is reserved for functions with too few instructions to
/// anchor; everything else is `weak`.
pub fn quality_report(
    scored: &[ScoredFeature],
    anchors: &[String],
    confidence: &str,
    instruction_count: usize,
    degraded: bool,
) -> QualityReport {
    let data: Vec<&ScoredFeature> = scored
        .iter()
        .filter(|item| DATA_KINDS.contains(&item.feature.kind))
        .collect();
    let data_kinds: HashSet<FeatureKind> = data.iter().map(|item| item.feature.kind).collect();
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
    if confidence == "low" {
        notes.push("signature carries low confidence".to_string());
    }

    let verdict = if is_small {
        "small"
    } else if anchors.len() >= STRONG_MIN_ANCHORS
        && data.len() >= STRONG_MIN_DATA_FEATURES
        && data_kinds.len() >= STRONG_MIN_DATA_KINDS
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
