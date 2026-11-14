//! Multi-sample merging: one signature from several builds of one function.
//!
//! Merging is the M4 answer to cross-optimisation and cross-architecture
//! recall: no single build carries every feature, but the intersection is
//! stable and the differences are real. The rules (spec §8), mirrored from
//! `core/merge.py`:
//!
//! * Features present in **every** sample stay required and keep full weight.
//! * Features present in a **strict subset** are demoted: optional, half
//!   weight. Different bucket values of the same shape feature therefore widen
//!   the match instead of failing it.
//! * Anchors are only chosen among features every sample contains, so Tier 0
//!   cannot trigger on bytes a sample does not have.
//! * The merged signature must self-test against **every** sample (rule 7); a
//!   signature that cannot be re-found in one of its own samples is refused.

use std::collections::{BTreeMap, BTreeSet};

use crate::errors::MergeError;
use crate::features::Feature;
use crate::generate::{generate_in, GenerationResult};
use crate::matcher::{self_test, ScanContext, MAX_CANDIDATE_STARTS, MAX_NEIGHBOUR_KEYS};
use crate::recover::RecoveryLimits;
use crate::score::{
    choose_thresholds, confidence_for, score_features, select_anchors, signature_feature,
    ScoredFeature, MAX_ANCHORS, MIN_WEIGHT, WEIGHT_DECIMALS,
};
use crate::sigfile::Signature;
use crate::source::ByteSource;
use crate::validate::quality_report;

/// Weight multiplier for features that only some samples carry.
pub const DEMOTE_FACTOR: f64 = 0.5;

/// One build of the function to merge.
pub struct MergeSample<'a> {
    pub source: &'a dyn ByteSource,
    pub addr: u64,
    pub opt: Option<&'a str>,
    pub tool: Option<&'a str>,
}

/// Merge the samples into one signature and self-test it on every sample.
pub fn merge(
    samples: &[MergeSample<'_>],
    name: Option<&str>,
    limits: Option<RecoveryLimits>,
) -> Result<GenerationResult, MergeError> {
    merge_in(samples, &[], name, limits)
}

/// [`merge`] with each sample's image [`ScanContext`] (by position; missing
/// entries mean none). The contexts supply the call graph, so the merged
/// signature carries the union of the samples' neighbour keys.
pub fn merge_in(
    samples: &[MergeSample<'_>],
    contexts: &[Option<&ScanContext>],
    name: Option<&str>,
    limits: Option<RecoveryLimits>,
) -> Result<GenerationResult, MergeError> {
    if samples.len() < 2 {
        return Err(MergeError("merging needs at least two samples".into()));
    }
    let results: Vec<GenerationResult> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            generate_in(
                sample.source,
                sample.addr,
                None,
                sample.opt,
                sample.tool,
                None,
                limits,
                contexts.get(index).copied().flatten(),
            )
            .map_err(|error| MergeError(format!("sample generation failed: {error}")))
        })
        .collect::<Result<Vec<_>, MergeError>>()?;
    let name = name
        .map(str::to_string)
        .unwrap_or_else(|| results[0].signature.name.clone());

    let per_sample: Vec<BTreeMap<String, Feature>> = results
        .iter()
        .map(|result| {
            result
                .signature
                .features
                .iter()
                .map(|item| {
                    // Keep the sample's own optional marks (local callees).
                    let mut feature = Feature::new(item.kind, item.value.clone());
                    feature.required = item.required;
                    (feature.key(), feature)
                })
                .collect()
        })
        .collect();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for features in &per_sample {
        for key in features.keys() {
            *counts.entry(key.clone()).or_insert(0) += 1;
        }
    }

    // The union keeps the first sample's copy of each feature; scoring and the
    // final sort then make the document independent of sample order.
    let mut union: BTreeMap<String, Feature> = BTreeMap::new();
    for features in &per_sample {
        for (key, feature) in features {
            union.entry(key.clone()).or_insert_with(|| feature.clone());
        }
    }
    let union: Vec<Feature> = union.into_values().collect();
    let mut scored: Vec<ScoredFeature> = score_features(&union, None)
        .into_iter()
        .map(|item| {
            let present_everywhere = counts.get(&item.key()).copied().unwrap_or(0) == samples.len();
            if present_everywhere {
                return item;
            }
            // Demote: optional, and never allowed to carry the signature alone.
            ScoredFeature {
                feature: item.feature,
                weight: MIN_WEIGHT
                    .max(round_decimals(item.weight * DEMOTE_FACTOR, WEIGHT_DECIMALS)),
                required: false,
            }
        })
        .collect();
    scored.sort_by(|left, right| {
        (left.feature.kind, left.feature.value.as_str())
            .cmp(&(right.feature.kind, right.feature.value.as_str()))
    });

    let stable: BTreeSet<String> = counts
        .iter()
        .filter(|(_, count)| **count == samples.len())
        .map(|(key, _)| key.clone())
        .collect();
    let anchors: Vec<String> = select_anchors(&scored, MAX_ANCHORS)
        .into_iter()
        .filter(|key| stable.contains(key))
        .collect();
    let required_count = scored.iter().filter(|item| item.required).count();
    let thresholds = choose_thresholds(anchors.len(), required_count);
    let first_arch = samples[0].source.arch();
    let multi_arch = samples
        .iter()
        .any(|sample| sample.source.arch() != first_arch);
    let is_small = results
        .iter()
        .all(|result| result.report.verdict == "small");
    let confidence = confidence_for(multi_arch, is_small, anchors.len());
    let error_name = name.clone();
    let mut signature = Signature::new(
        name,
        scored.iter().map(signature_feature).collect(),
        anchors.clone(),
        thresholds.match_threshold,
        thresholds.min_distinct,
        confidence.clone(),
        results
            .iter()
            .map(|result| result.signature.provenance[0].clone())
            .collect(),
    )
    .map_err(|error| MergeError(error.to_string()))?;
    // Any sample's neighbours may be what a target keeps: an architecture
    // that inlines a callee loses its evidence, another keeps it.
    let neighbours: BTreeSet<String> = results
        .iter()
        .flat_map(|result| result.signature.neighbours.iter().cloned())
        .collect();
    signature.neighbours = neighbours.into_iter().take(MAX_NEIGHBOUR_KEYS).collect();
    signature
        .validate()
        .map_err(|error| MergeError(error.to_string()))?;

    let mut matched = None;
    for (sample, result) in samples.iter().zip(results.iter()) {
        match self_test(
            &signature,
            sample.source,
            result.matched.address,
            limits,
            MAX_CANDIDATE_STARTS,
        ) {
            Ok(found) => matched = Some(found),
            Err(error) => {
                return Err(MergeError(format!(
                    "merged signature {error_name:?} failed self-test on a {} sample: {error}",
                    sample.source.arch()
                )))
            }
        }
    }
    let matched = matched.expect("merge has at least two samples");

    let instruction_count = results
        .iter()
        .map(|result| result.matched.end.saturating_sub(result.matched.address))
        .max()
        .unwrap_or(0) as usize;
    let degraded = results.iter().any(|result| {
        result
            .report
            .notes
            .iter()
            .any(|note| note.contains("recovery was partial"))
    });
    let report = quality_report(&scored, &anchors, &confidence, instruction_count, degraded);
    Ok(GenerationResult {
        signature,
        report,
        matched,
    })
}

fn round_decimals(value: f64, decimals: usize) -> f64 {
    format!("{value:.decimals$}")
        .parse::<f64>()
        .unwrap_or(value)
}
