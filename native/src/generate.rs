//! Single entry point: address plus byte source in, signature and report out.
//!
//! `generate` is deliberately thin. It composes the one shared extractor with
//! scoring, document serialisation, and the quality report, and adds only
//! provenance. Every front-end calls this function so the CLI, IDA plugin, and
//! scanner cannot diverge.

use std::collections::HashMap;
use std::fmt;

use crate::errors::{DecodeError, SelfTestError, SignatureError};
use crate::features::extract;
use crate::matcher::{self_test, Match, MAX_CANDIDATE_STARTS};
use crate::recover::{recover, RecoveryLimits};
use crate::score::{
    choose_thresholds, confidence_for, score_features, select_anchors, signature_feature,
    MAX_ANCHORS,
};
use crate::sigfile::{SampleProvenance, Signature};
use crate::source::ByteSource;
use crate::validate::{quality_report, QualityReport};

pub const DEFAULT_NAME_PREFIX: &str = "sub_";

#[derive(Debug)]
pub enum GenerateError {
    Decode(DecodeError),
    Signature(SignatureError),
    SelfTest(SelfTestError),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateError::Decode(error) => write!(f, "{error}"),
            GenerateError::Signature(error) => write!(f, "{error}"),
            GenerateError::SelfTest(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for GenerateError {}

impl From<DecodeError> for GenerateError {
    fn from(error: DecodeError) -> Self {
        GenerateError::Decode(error)
    }
}

impl From<SignatureError> for GenerateError {
    fn from(error: SignatureError) -> Self {
        GenerateError::Signature(error)
    }
}

impl From<SelfTestError> for GenerateError {
    fn from(error: SelfTestError) -> Self {
        GenerateError::SelfTest(error)
    }
}

/// A generated signature, its quality report, and the self-test that allowed it.
#[derive(Debug, Clone)]
pub struct GenerationResult {
    pub signature: Signature,
    pub report: QualityReport,
    pub matched: Match,
}

impl GenerationResult {
    pub fn to_yaml(&self) -> Result<String, SignatureError> {
        self.signature.to_yaml()
    }
}

/// Generate a signature for the function containing `addr`.
///
/// `opt` and `tool` are provenance only; they never affect features or weights,
/// so signatures stay comparable across build settings.
pub fn generate<S: ByteSource + ?Sized>(
    source: &S,
    addr: u64,
    name: Option<&str>,
    opt: Option<&str>,
    tool: Option<&str>,
    idf: Option<&HashMap<String, f64>>,
    limits: Option<RecoveryLimits>,
) -> Result<GenerationResult, GenerateError> {
    let recovered = recover(source, addr, limits, true)?;
    let features = extract(source, &recovered);
    let scored = score_features(&features, idf);
    let anchors = select_anchors(&scored, MAX_ANCHORS);
    let required_count = scored.iter().filter(|item| item.required).count();
    let thresholds = choose_thresholds(anchors.len(), required_count);
    let confidence = confidence_for(false, recovered.is_small(), anchors.len());

    let module = source.module_for(addr);
    let rva = module
        .map(|module| addr.wrapping_sub(module.base))
        .unwrap_or(0);
    let sample = SampleProvenance {
        arch: source.arch().as_str().to_string(),
        module: module
            .map(|module| module.name.clone())
            .unwrap_or_else(|| "image".to_string()),
        rva,
        opt: opt.map(str::to_string),
        tool: tool.map(str::to_string),
    };
    let default_name = default_name(source, addr, &sample.module, rva);
    let signature = Signature::new(
        name.unwrap_or(&default_name),
        scored.iter().map(signature_feature).collect(),
        anchors.clone(),
        thresholds.match_threshold,
        thresholds.min_distinct,
        confidence.clone(),
        vec![sample],
    )?;
    let report = quality_report(
        &scored,
        &anchors,
        &confidence,
        recovered.instruction_count(),
        recovered.degraded,
    );
    // Rule 7: never emit a signature the reference matcher cannot re-find (or,
    // when the matcher cannot reach the function, one that does not describe
    // its bytes exactly).
    let matched = self_test(
        &signature,
        source,
        recovered.start(),
        limits,
        MAX_CANDIDATE_STARTS,
    )?;
    Ok(GenerationResult {
        signature,
        report,
        matched,
    })
}

fn default_name<S: ByteSource + ?Sized>(
    source: &S,
    addr: u64,
    module_name: &str,
    rva: u64,
) -> String {
    if let Some(symbol) = source.name_for_address(addr) {
        return symbol;
    }
    format!("{DEFAULT_NAME_PREFIX}{module_name}+0x{rva:x}")
}
