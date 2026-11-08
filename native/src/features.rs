//! Feature extraction: the single extractor used for signing and scanning.
//!
//! Feature kinds are fixed by the spec (`str`, `const`, `callee`, `cfg`,
//! `ops`). Output is sorted and free of addresses, so two runs on the same
//! bytes produce identical records, and ASLR-shifted copies produce identical
//! records.

use std::collections::{HashMap, HashSet};

use crate::normalize::{Kind, OpClass};
use crate::recover::RecoveredFunction;
use crate::source::ByteSource;
use crate::spec::{bucket, digest, STR_MAX_LEN, STR_MIN_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FeatureKind {
    // Declaration order is the lexicographic order of the spec's kind strings,
    // which is the order the reference implementation sorts records in.
    Callee,
    Cfg,
    Const,
    Ops,
    Str,
}

impl FeatureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FeatureKind::Callee => "callee",
            FeatureKind::Cfg => "cfg",
            FeatureKind::Const => "const",
            FeatureKind::Ops => "ops",
            FeatureKind::Str => "str",
        }
    }

    pub fn parse(value: &str) -> Option<FeatureKind> {
        match value {
            "callee" => Some(FeatureKind::Callee),
            "cfg" => Some(FeatureKind::Cfg),
            "const" => Some(FeatureKind::Const),
            "ops" => Some(FeatureKind::Ops),
            "str" => Some(FeatureKind::Str),
            _ => None,
        }
    }
}

pub const FEATURE_KINDS: [FeatureKind; 5] = [
    FeatureKind::Str,
    FeatureKind::Const,
    FeatureKind::Callee,
    FeatureKind::Cfg,
    FeatureKind::Ops,
];

/// One comparable fact about a function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Feature {
    pub kind: FeatureKind,
    pub value: String,
    pub required: bool,
}

impl Feature {
    pub fn new(kind: FeatureKind, value: impl Into<String>) -> Feature {
        Feature {
            kind,
            value: value.into(),
            required: true,
        }
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.value)
    }
}

/// Extract the full feature set for a recovered function.
pub fn extract<S: ByteSource + ?Sized>(source: &S, func: &RecoveredFunction) -> Vec<Feature> {
    let mut strings: HashSet<String> = HashSet::new();
    let mut consts: HashSet<u64> = HashSet::new();
    let mut callees: HashSet<String> = HashSet::new();
    let mut ops: HashMap<OpClass, usize> = HashMap::new();

    for block in &func.blocks {
        for insn in &block.insns {
            if insn.kind == Kind::Ignored {
                continue;
            }
            *ops.entry(insn.op).or_insert(0) += 1;
            for value in &insn.consts {
                if !is_pointer(source, *value) {
                    consts.insert(*value);
                }
            }
            for reference in &insn.refs {
                if let Some(text) = string_at(source, reference.addr) {
                    strings.insert(text);
                }
            }
            if let Some(callee) = &insn.callee {
                callees.insert(callee.clone());
            }
        }
    }

    let mut features: Vec<Feature> = Vec::new();
    let mut string_values: Vec<String> = strings.into_iter().collect();
    string_values.sort();
    features.extend(
        string_values
            .into_iter()
            .map(|value| Feature::new(FeatureKind::Str, value)),
    );

    let mut const_values: Vec<u64> = consts.into_iter().collect();
    const_values.sort_unstable();
    features.extend(
        const_values
            .into_iter()
            .map(|value| Feature::new(FeatureKind::Const, format!("0x{value:x}"))),
    );

    let mut callee_values: Vec<String> = callees.into_iter().collect();
    callee_values.sort();
    features.extend(
        callee_values
            .into_iter()
            .map(|value| Feature::new(FeatureKind::Callee, value)),
    );

    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("blocks:{}", bucket(func.block_count())),
    ));
    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("edges:{}", bucket(func.edge_count())),
    ));
    features.push(Feature::new(
        FeatureKind::Cfg,
        format!("loops:{}", bucket(func.loop_count())),
    ));

    let mut op_values: Vec<(String, usize)> = ops
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(op, count)| (op.as_str().to_string(), count))
        .collect();
    op_values.sort();
    features.extend(
        op_values
            .into_iter()
            .map(|(op, count)| Feature::new(FeatureKind::Ops, format!("{op}:{}", bucket(count)))),
    );

    features.sort();
    features
}

/// Absolute addresses inside a mapped module must never become features.
fn is_pointer<S: ByteSource + ?Sized>(source: &S, value: u64) -> bool {
    if value == 0 {
        return false;
    }
    source.module_for(value).is_some()
}

/// Return the string literal at `addr`, or `None` if it is not one.
///
/// Only non-executable memory is considered, so jump-table and code references
/// cannot masquerade as string anchors.
pub fn string_at<S: ByteSource + ?Sized>(source: &S, addr: u64) -> Option<String> {
    string_at_limit(source, addr, STR_MAX_LEN)
}

pub fn string_at_limit<S: ByteSource + ?Sized>(
    source: &S,
    addr: u64,
    limit: usize,
) -> Option<String> {
    if addr == 0 || source.is_executable(addr) {
        return None;
    }
    // Partial read: the literal may end exactly at a section boundary.
    let data = source.read_partial(addr, (limit + 1) * 2);
    if data.is_empty() {
        return None;
    }
    if let Some(narrow) = scan_narrow(&data, limit) {
        return Some(narrow);
    }
    scan_wide(&data, limit)
}

fn scan_narrow(data: &[u8], limit: usize) -> Option<String> {
    let mut chars: Vec<char> = Vec::new();
    let mut terminated = false;
    for (index, byte) in data.iter().enumerate() {
        if *byte == 0 {
            terminated = true;
            break;
        }
        if !(0x20..=0x7E).contains(byte) {
            return None;
        }
        if chars.len() < limit {
            chars.push(char::from(*byte));
        } else {
            // Over-long literal: keep a stable digest of the prefix we read.
            return Some(format!("long:{}", digest(&latin1(&data[..=index]))));
        }
    }
    if !terminated || chars.len() < STR_MIN_LEN {
        return None;
    }
    Some(escape(&chars.into_iter().collect::<String>()))
}

/// Detect UTF-16LE literals: printable ASCII low bytes with zero high bytes.
fn scan_wide(data: &[u8], limit: usize) -> Option<String> {
    let mut chars: Vec<char> = Vec::new();
    let mut truncated = false;
    let mut index = 0usize;
    while index + 1 < data.len() {
        let low = data[index];
        let high = data[index + 1];
        if low == 0 && high == 0 {
            if chars.len() < STR_MIN_LEN {
                return None;
            }
            return Some(format!(
                "w:{}",
                escape(&chars.into_iter().collect::<String>())
            ));
        }
        if high != 0 || !(0x20..=0x7E).contains(&low) {
            return None;
        }
        if chars.len() >= limit {
            truncated = true;
            break;
        }
        chars.push(char::from(low));
        index += 2;
    }
    if truncated {
        return Some(format!("w:long:{}", digest(&latin1(&data[..2 * limit]))));
    }
    None
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Interpret bytes as Latin-1 and return the corresponding Rust string.
///
/// Python's over-long literal digest decodes with `latin-1` and then hashes the
/// UTF-8 encoding of that string; mapping each byte to a code point is the
/// same operation.
fn latin1(data: &[u8]) -> String {
    data.iter().map(|byte| char::from(*byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_strings_require_termination_and_length() {
        assert_eq!(scan_narrow(b"abcd\0", 120).as_deref(), Some("abcd"));
        assert_eq!(scan_narrow(b"abc\0", 120), None);
        assert_eq!(scan_narrow(b"abcd", 120), None);
        assert_eq!(scan_narrow(b"ab\x01cd\0", 120), None);
    }

    #[test]
    fn wide_strings_are_tagged() {
        assert_eq!(
            scan_wide(b"a\0b\0c\0d\0\0\0", 120).as_deref(),
            Some("w:abcd")
        );
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(
            scan_narrow(b"a\"b\\c\0", 120).as_deref(),
            Some("a\\\"b\\\\c")
        );
    }
}
