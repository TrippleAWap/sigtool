//! The signature document: canonical YAML, validation, and stable identity.
//!
//! The YAML form is the reviewed, diffable source of truth; the canonical
//! bytes of that text are the signature identity. Nothing here may include
//! timestamps, absolute paths, or absolute addresses (AGENTS.md rules 3 and 4).
//!
//! The native reader accepts the same documents the Python reference writes,
//! and its canonical writer reproduces the reference byte layout so the
//! `signature_id` digest is stable across both implementations.

use std::collections::HashSet;

use serde::Serialize;
use serde_yaml::Value;

use crate::errors::SignatureError;
use crate::features::{FeatureKind, FEATURE_KINDS};
use crate::spec::{digest, SPEC_VERSION};

pub const CONFIDENCE_TAGS: [&str; 3] = ["single-arch", "multi-arch", "low"];
pub const MAX_ANCHORS: usize = 8;
pub const MAX_WEIGHT: f64 = 10.0;

/// One weighted feature inside a signature.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureFeature {
    pub kind: FeatureKind,
    pub value: String,
    pub weight: f64,
    pub required: bool,
}

impl SignatureFeature {
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
}

/// Where one sample came from: module name and RVA, never a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleProvenance {
    pub arch: String,
    pub module: String,
    pub rva: u64,
    pub opt: Option<String>,
    pub tool: Option<String>,
}

/// A generation-time signature and its match parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub name: String,
    pub features: Vec<SignatureFeature>,
    pub anchors: Vec<String>,
    /// Identifying keys of the function's call-graph neighbours (SPEC.md §7),
    /// sorted: `in:`/`out:` for callers/callees, `in2:`/`out2:` one hop on.
    pub neighbours: Vec<String>,
    /// The function's direct callers (`in:RVA`) and callees (`out:RVA`) in
    /// the first sample's module, sorted (SPEC.md §7). Provenance, not
    /// evidence: a set of signatures from one module is resolved jointly
    /// through them.
    pub links: Vec<String>,
    pub match_threshold: f64,
    pub min_distinct: usize,
    pub confidence: String,
    pub provenance: Vec<SampleProvenance>,
    pub spec_version: String,
}

impl Signature {
    /// Construct and validate a signature with the current spec version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        features: Vec<SignatureFeature>,
        anchors: Vec<String>,
        match_threshold: f64,
        min_distinct: usize,
        confidence: impl Into<String>,
        provenance: Vec<SampleProvenance>,
    ) -> Result<Signature, SignatureError> {
        let signature = Signature {
            name: name.into(),
            features,
            anchors,
            neighbours: Vec::new(),
            links: Vec::new(),
            match_threshold,
            min_distinct,
            confidence: confidence.into(),
            provenance,
            spec_version: SPEC_VERSION.to_string(),
        };
        signature.validate()?;
        Ok(signature)
    }

    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.spec_version != SPEC_VERSION {
            return Err(SignatureError(format!(
                "signature spec version {:?} is not {:?}",
                self.spec_version, SPEC_VERSION
            )));
        }
        if self.name.is_empty() {
            return Err(SignatureError("signature name must not be empty".into()));
        }
        if self.features.is_empty() {
            return Err(SignatureError(
                "signature must contain at least one feature".into(),
            ));
        }
        if !CONFIDENCE_TAGS.contains(&self.confidence.as_str()) {
            return Err(SignatureError(format!(
                "unknown confidence tag {:?}",
                self.confidence
            )));
        }
        if !(self.match_threshold > 0.0 && self.match_threshold <= 1.0) {
            return Err(SignatureError("match threshold must be in (0, 1]".into()));
        }
        if self.min_distinct < 1 || self.min_distinct > self.features.len() {
            return Err(SignatureError(
                "min_distinct must be between 1 and the feature count".into(),
            ));
        }
        if self.provenance.is_empty() {
            return Err(SignatureError(
                "signature needs at least one provenance sample".into(),
            ));
        }

        let mut seen: HashSet<String> = HashSet::new();
        for feature in &self.features {
            if !FEATURE_KINDS.contains(&feature.kind) {
                return Err(SignatureError(format!(
                    "unknown feature kind {:?}",
                    feature.kind.as_str()
                )));
            }
            let key = feature.key();
            if !seen.insert(key.clone()) {
                return Err(SignatureError(format!("duplicate feature {key:?}")));
            }
            if !(feature.weight > 0.0 && feature.weight <= MAX_WEIGHT) {
                return Err(SignatureError(format!(
                    "feature {key:?} has an invalid weight"
                )));
            }
        }

        if self.anchors.len() > MAX_ANCHORS {
            return Err(SignatureError("too many anchors".into()));
        }
        for anchor in &self.anchors {
            if !seen.contains(anchor) {
                return Err(SignatureError(format!(
                    "anchor {anchor:?} is not one of the features"
                )));
            }
        }

        if self.neighbours.len() > crate::spec::MAX_NEIGHBOUR_KEYS {
            return Err(SignatureError("too many neighbour keys".into()));
        }
        if self.neighbours.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SignatureError(
                "neighbour keys must be sorted and unique".into(),
            ));
        }
        for key in &self.neighbours {
            let (hop, feature) = key.split_once(':').unwrap_or(("", ""));
            let kind = feature.split_once(':').map(|(kind, _)| kind);
            if !matches!(hop, "in" | "out" | "in2" | "out2")
                || !matches!(kind, Some("str" | "const"))
            {
                return Err(SignatureError(format!("invalid neighbour key {key:?}")));
            }
        }

        if self.links.len() > crate::spec::MAX_LINKS {
            return Err(SignatureError("too many links".into()));
        }
        if self.links.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SignatureError("links must be sorted and unique".into()));
        }
        if let Some(bad) = self.links.iter().find(|link| parse_link(link).is_none()) {
            return Err(SignatureError(format!("invalid link {bad:?}")));
        }

        for sample in &self.provenance {
            if sample.module.contains('/') || sample.module.contains('\\') {
                return Err(SignatureError(
                    "provenance module must be a name, not a path".into(),
                ));
            }
        }
        Ok(())
    }

    // -- serialisation -----------------------------------------------------

    /// Canonical YAML text; the same signature always serialises identically.
    pub fn to_yaml(&self) -> Result<String, SignatureError> {
        let mut features: Vec<&SignatureFeature> = self.features.iter().collect();
        features.sort_by(|left, right| {
            (left.kind, left.value.as_str()).cmp(&(right.kind, right.value.as_str()))
        });

        let document = Document {
            spec_version: &self.spec_version,
            name: &self.name,
            confidence: &self.confidence,
            anchors: &self.anchors,
            neighbours: &self.neighbours,
            links: &self.links,
            thresholds: ThresholdsDocument {
                match_threshold: self.match_threshold,
                min_distinct: self.min_distinct,
            },
            features: features
                .into_iter()
                .map(|feature| FeatureDocument {
                    kind: feature.kind.as_str(),
                    value: &feature.value,
                    weight: feature.weight,
                    required: feature.required,
                })
                .collect(),
            provenance: self
                .provenance
                .iter()
                .map(ProvenanceDocument::from)
                .collect(),
        };
        serde_yaml::to_string(&document).map_err(|error| SignatureError(format!("{error}")))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SignatureError> {
        Ok(self.to_yaml()?.into_bytes())
    }

    /// Stable identity: spec digest of the canonical YAML text.
    pub fn signature_id(&self) -> Result<String, SignatureError> {
        Ok(digest(&self.to_yaml()?))
    }

    pub fn from_yaml(text: &str) -> Result<Signature, SignatureError> {
        let raw: Value = serde_yaml::from_str(text)
            .map_err(|error| SignatureError(format!("invalid signature YAML: {error}")))?;
        let document = as_mapping(&raw, "signature")?;

        let features = as_sequence(field(document, "features"), "features")?
            .iter()
            .map(|entry| {
                let item = as_mapping(entry, "feature")?;
                Ok(SignatureFeature {
                    kind: parse_kind(field(item, "kind"))?,
                    value: as_str(field(item, "value"), "feature.value")?.to_string(),
                    weight: as_f64(field(item, "weight"), "feature.weight")?,
                    required: match field(item, "required") {
                        Some(value) => as_bool(value, "feature.required")?,
                        None => true,
                    },
                })
            })
            .collect::<Result<Vec<_>, SignatureError>>()?;

        let thresholds = as_mapping(
            field(document, "thresholds")
                .ok_or_else(|| SignatureError("thresholds must be a mapping".into()))?,
            "thresholds",
        )?;
        let provenance = as_sequence(field(document, "provenance"), "provenance")?
            .iter()
            .map(|entry| {
                let item = as_mapping(entry, "provenance")?;
                Ok(SampleProvenance {
                    arch: as_str(field(item, "arch"), "provenance.arch")?.to_string(),
                    module: as_str(field(item, "module"), "provenance.module")?.to_string(),
                    rva: as_rva(field(item, "rva"))?,
                    opt: as_optional_str(field(item, "opt"))?,
                    tool: as_optional_str(field(item, "tool"))?,
                })
            })
            .collect::<Result<Vec<_>, SignatureError>>()?;

        let anchors = match field(document, "anchors") {
            Some(value) => as_sequence(Some(value), "anchors")?
                .iter()
                .map(|anchor| Ok(as_str(Some(anchor), "anchor")?.to_string()))
                .collect::<Result<Vec<_>, SignatureError>>()?,
            None => Vec::new(),
        };

        let neighbours = match field(document, "neighbours") {
            Some(value) => as_sequence(Some(value), "neighbours")?
                .iter()
                .map(|key| Ok(as_str(Some(key), "neighbour")?.to_string()))
                .collect::<Result<Vec<_>, SignatureError>>()?,
            None => Vec::new(),
        };

        let links = match field(document, "links") {
            Some(value) => as_sequence(Some(value), "links")?
                .iter()
                .map(|link| Ok(as_str(Some(link), "link")?.to_string()))
                .collect::<Result<Vec<_>, SignatureError>>()?,
            None => Vec::new(),
        };

        let signature = Signature {
            spec_version: as_str(field(document, "spec_version"), "spec_version")?.to_string(),
            name: as_str(field(document, "name"), "name")?.to_string(),
            confidence: as_str(field(document, "confidence"), "confidence")?.to_string(),
            anchors,
            neighbours,
            links,
            match_threshold: as_f64(field(thresholds, "match"), "thresholds.match")?,
            min_distinct: as_usize(field(thresholds, "min_distinct"), "thresholds.min_distinct")?,
            features,
            provenance,
        };
        signature.validate()?;
        Ok(signature)
    }
}

/// `(callee, rva)` from `in:0x1A0` / `out:0x1A0`: `callee` is true for
/// `out`, a function the signature's function calls.
pub fn parse_link(link: &str) -> Option<(bool, u64)> {
    let (direction, rva) = link.split_once(':')?;
    let callee = match direction {
        "out" => true,
        "in" => false,
        _ => return None,
    };
    let digits = rva.strip_prefix("0x")?;
    // Canonical lowercase hex without leading zeros, so text order is unique.
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return None;
    }
    u64::from_str_radix(digits, 16)
        .ok()
        .map(|value| (callee, value))
}

#[derive(Serialize)]
struct Document<'a> {
    spec_version: &'a str,
    name: &'a str,
    confidence: &'a str,
    anchors: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    neighbours: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    links: &'a [String],
    thresholds: ThresholdsDocument,
    features: Vec<FeatureDocument<'a>>,
    provenance: Vec<ProvenanceDocument<'a>>,
}

#[derive(Serialize)]
struct ThresholdsDocument {
    #[serde(rename = "match")]
    match_threshold: f64,
    min_distinct: usize,
}

#[derive(Serialize)]
struct FeatureDocument<'a> {
    kind: &'a str,
    value: &'a str,
    weight: f64,
    required: bool,
}

#[derive(Serialize)]
struct ProvenanceDocument<'a> {
    arch: &'a str,
    module: &'a str,
    rva: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<&'a str>,
}

impl<'a> From<&'a SampleProvenance> for ProvenanceDocument<'a> {
    fn from(sample: &'a SampleProvenance) -> ProvenanceDocument<'a> {
        ProvenanceDocument {
            arch: &sample.arch,
            module: &sample.module,
            rva: format!("0x{:x}", sample.rva),
            opt: sample.opt.as_deref(),
            tool: sample.tool.as_deref(),
        }
    }
}

fn field<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn as_mapping<'a>(value: &'a Value, what: &str) -> Result<&'a serde_yaml::Mapping, SignatureError> {
    value
        .as_mapping()
        .ok_or_else(|| SignatureError(format!("{what} must be a mapping")))
}

fn as_sequence<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a Vec<Value>, SignatureError> {
    value
        .and_then(Value::as_sequence)
        .ok_or_else(|| SignatureError(format!("{what} must be a list")))
}

fn as_str<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a str, SignatureError> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| SignatureError(format!("{what} must be a string")))
}

fn as_optional_str(value: Option<&Value>) -> Result<Option<String>, SignatureError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(SignatureError(
            "optional provenance fields must be strings".into(),
        )),
    }
}

fn as_bool(value: &Value, what: &str) -> Result<bool, SignatureError> {
    value
        .as_bool()
        .ok_or_else(|| SignatureError(format!("{what} must be a boolean")))
}

fn as_f64(value: Option<&Value>, what: &str) -> Result<f64, SignatureError> {
    match value {
        Some(Value::Number(number)) => number
            .as_f64()
            .ok_or_else(|| SignatureError(format!("{what} must be a number"))),
        _ => Err(SignatureError(format!("{what} must be a number"))),
    }
}

fn as_usize(value: Option<&Value>, what: &str) -> Result<usize, SignatureError> {
    let number = value
        .and_then(Value::as_u64)
        .ok_or_else(|| SignatureError(format!("{what} must be an integer")))?;
    Ok(number as usize)
}

fn as_rva(value: Option<&Value>) -> Result<u64, SignatureError> {
    match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| SignatureError("provenance.rva must not be negative".into())),
        Some(Value::String(text)) => parse_int(text)
            .ok_or_else(|| SignatureError(format!("invalid provenance rva {text:?}"))),
        _ => Err(SignatureError(
            "provenance.rva must be an integer or hex string".into(),
        )),
    }
}

fn parse_kind(value: Option<&Value>) -> Result<FeatureKind, SignatureError> {
    let text = as_str(value, "feature.kind")?;
    FeatureKind::parse(text).ok_or_else(|| SignatureError(format!("unknown feature kind {text:?}")))
}

fn parse_int(text: &str) -> Option<u64> {
    let text = text.trim();
    let (radix, digits) =
        if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, rest)
        } else if let Some(rest) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (8, rest)
        } else if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (2, rest)
        } else {
            (10, text)
        };
    u64::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Signature {
        Signature::new(
            "banner_direct",
            vec![
                SignatureFeature {
                    kind: FeatureKind::Cfg,
                    value: "blocks:1".into(),
                    weight: 0.25,
                    required: false,
                },
                SignatureFeature {
                    kind: FeatureKind::Str,
                    value: "direct banner literal".into(),
                    weight: 1.262,
                    required: true,
                },
            ],
            vec!["str:direct banner literal".into()],
            0.85,
            1,
            "low",
            vec![SampleProvenance {
                arch: "x64".into(),
                module: "fixture".into(),
                rva: 0x1110,
                opt: None,
                tool: None,
            }],
        )
        .expect("valid signature")
    }

    #[test]
    fn round_trips_through_yaml() {
        let signature = sample();
        let text = signature.to_yaml().expect("yaml");
        let parsed = Signature::from_yaml(&text).expect("parse");
        assert_eq!(parsed, signature);
    }

    #[test]
    fn canonical_yaml_matches_python_reference() {
        // Produced by the Python reference for the same signature.
        let expected = "spec_version: '4'\nname: banner_direct\nconfidence: low\nanchors:\n- str:direct banner literal\nthresholds:\n  match: 0.85\n  min_distinct: 1\nfeatures:\n- kind: cfg\n  value: blocks:1\n  weight: 0.25\n  required: false\n- kind: str\n  value: direct banner literal\n  weight: 1.262\n  required: true\nprovenance:\n- arch: x64\n  module: fixture\n  rva: '0x1110'\n";
        assert_eq!(sample().to_yaml().expect("yaml"), expected);
    }

    #[test]
    fn rejects_duplicate_features() {
        let mut signature = sample();
        signature.features.push(signature.features[0].clone());
        assert!(signature.validate().is_err());
    }
}
