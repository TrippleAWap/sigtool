//! Multi-sample merging parity: the native merge must reproduce the Python
//! reference's document and its refusal behaviour.
//!
//! These mirror `tests/test_merge.py`, over the same synthetic images from
//! `tests/support.py`. The golden document is the YAML the Python reference
//! emits for the identical fixture pair, so a weight, ordering, or demotion
//! change shows up as a byte diff rather than as a plausible-looking signature.

use sigtool_native::arch::Arch;
use sigtool_native::matcher::scan;
use sigtool_native::merge::{merge, MergeSample};
use sigtool_native::source::{MemorySource, Module, Region};

const HELPER: u64 = 0x1060;
const BANNER: &[u8] = b"generate banner literal\x00";

fn strong_source() -> MemorySource {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x8d, 0x3d]);
    // 4-byte displacement field: an i64 would append four stray zero bytes that
    // decode as `add [rax], al` and change the op histogram.
    code.extend_from_slice(&(0x2000i32 - 0x1007).to_le_bytes());
    code.extend_from_slice(&[0xb8, 0x34, 0x12, 0x00, 0x00]);
    for (opcode, immediate) in [
        (0x05u8, 0x1111u32),
        (0x2d, 0x2222),
        (0x35, 0x3333),
        (0x0d, 0x4444),
        (0x25, 0x5555),
    ] {
        code.push(opcode);
        code.extend_from_slice(&immediate.to_le_bytes());
    }
    code.extend_from_slice(&[0x69, 0xc0]);
    code.extend_from_slice(&0x6666u32.to_le_bytes());
    for (opcode, immediate) in [
        (0x05u8, 0x7777u32),
        (0x2d, 0x8888),
        (0x35, 0x9999),
        (0x0d, 0xaaaa),
        (0x25, 0xbbbb),
    ] {
        code.push(opcode);
        code.extend_from_slice(&immediate.to_le_bytes());
    }
    let call_address = 0x1000 + code.len() as u64;
    code.push(0xe8);
    let displacement = HELPER as i64 - (call_address as i64 + 5);
    code.extend_from_slice(&(displacement as i32).to_le_bytes());
    code.push(0xc3);
    code.resize((HELPER - 0x1000) as usize, 0);
    code.push(0xc3);

    let text = Region::new("text", 0x1000, code, true, false);
    let rodata = Region::new("rodata", 0x2000, BANNER.to_vec(), false, false);
    let mut functions = std::collections::HashMap::new();
    functions.insert(HELPER, "helper".to_string());
    let module = Module {
        name: "gen".to_string(),
        base: 0x1000,
        image_base: 0x1000,
        size: 0x2000 + BANNER.len() as u64 - 0x1000,
        path: None,
        exports: vec![("helper".to_string(), HELPER)],
        functions,
        imports: std::collections::HashMap::new(),
    };
    MemorySource::new(
        Arch::X64,
        vec![text, rodata],
        vec![module],
        Vec::new(),
        Vec::new(),
    )
}

/// A function whose only constants sit past the 512-byte backward sweep.
fn deep_source() -> MemorySource {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x8d, 0x3d]);
    // 4-byte displacement field: an i64 would append four stray zero bytes that
    // decode as `add [rax], al` and change the op histogram.
    code.extend_from_slice(&(0x2000i32 - 0x1007).to_le_bytes());
    code.extend_from_slice(&[0x90; 600]);
    code.extend_from_slice(&[0xb8, 0x34, 0x12, 0x00, 0x00]);
    code.extend_from_slice(&[0x05, 0x11, 0x11, 0x00, 0x00]);
    code.push(0xc3);

    let text = Region::new("text", 0x1000, code, true, false);
    let rodata = Region::new("rodata", 0x2000, BANNER.to_vec(), false, false);
    let mut functions = std::collections::HashMap::new();
    functions.insert(0x1000, "deep_fn".to_string());
    let module = Module {
        name: "deep".to_string(),
        base: 0x1000,
        image_base: 0x1000,
        size: 0x2000 + BANNER.len() as u64 - 0x1000,
        path: None,
        exports: Vec::new(),
        functions,
        imports: std::collections::HashMap::new(),
    };
    MemorySource::new(
        Arch::X64,
        vec![text, rodata],
        vec![module],
        Vec::new(),
        Vec::new(),
    )
}

/// A three-instruction function with no data features.
fn tiny_source() -> MemorySource {
    let code = vec![0x31, 0xc0, 0xc3];
    let text = Region::new("text", 0x1000, code, true, false);
    let module = Module {
        name: "tiny".to_string(),
        base: 0x1000,
        image_base: 0x1000,
        size: 3,
        path: None,
        exports: Vec::new(),
        functions: std::collections::HashMap::new(),
        imports: std::collections::HashMap::new(),
    };
    MemorySource::new(
        Arch::X64,
        vec![text.clone()],
        vec![module],
        Vec::new(),
        Vec::new(),
    )
}

/// The YAML `core.merge.merge` produces for these two strong samples.
const TWINS_YAML: &str = r#"spec_version: '4'
name: twins
confidence: single-arch
anchors:
- str:generate banner literal
- callee:helper
- const:0x2222
- const:0x3333
thresholds:
  match: 0.75
  min_distinct: 3
features:
- kind: callee
  value: helper
  weight: 0.9
  required: true
- kind: cfg
  value: blocks:1
  weight: 0.25
  required: false
- kind: cfg
  value: edges:0
  weight: 0.25
  required: false
- kind: cfg
  value: loops:0
  weight: 0.25
  required: false
- kind: const
  value: '0x2222'
  weight: 0.7
  required: true
- kind: const
  value: '0x3333'
  weight: 0.7
  required: true
- kind: const
  value: '0x4444'
  weight: 0.7
  required: true
- kind: const
  value: '0x5555'
  weight: 0.7
  required: true
- kind: const
  value: '0x6666'
  weight: 0.7
  required: true
- kind: const
  value: '0x7777'
  weight: 0.7
  required: true
- kind: const
  value: '0x8888'
  weight: 0.7
  required: true
- kind: const
  value: '0x9999'
  weight: 0.7
  required: true
- kind: const
  value: '0xaaaa'
  weight: 0.7
  required: true
- kind: const
  value: '0xbbbb'
  weight: 0.7
  required: true
- kind: ops
  value: arith:4
  weight: 0.15
  required: false
- kind: ops
  value: call:1
  weight: 0.15
  required: false
- kind: ops
  value: logic:5
  weight: 0.15
  required: false
- kind: ops
  value: move:2
  weight: 0.15
  required: false
- kind: ops
  value: mul:1
  weight: 0.15
  required: false
- kind: ops
  value: ret:1
  weight: 0.15
  required: false
- kind: str
  value: generate banner literal
  weight: 1.288
  required: true
provenance:
- arch: x64
  module: gen
  rva: '0x0'
  opt: O0
  tool: test
- arch: x64
  module: gen
  rva: '0x0'
  opt: O2
  tool: test
"#;

#[test]
fn merge_needs_two_samples() {
    let source = strong_source();
    let error = merge(
        &[MergeSample {
            source: &source,
            addr: 0x1000,
            opt: None,
            tool: None,
        }],
        None,
        None,
    )
    .expect_err("one sample must be refused");
    assert!(error.to_string().contains("at least two"), "{error}");
}

#[test]
fn twins_match_the_python_reference_document() {
    let (first, second) = (strong_source(), strong_source());
    let result = merge(
        &[
            MergeSample {
                source: &first,
                addr: 0x1000,
                opt: Some("O0"),
                tool: Some("test"),
            },
            MergeSample {
                source: &second,
                addr: 0x1000,
                opt: Some("O2"),
                tool: Some("test"),
            },
        ],
        Some("twins"),
        None,
    )
    .expect("merge");
    assert_eq!(result.signature.to_yaml().expect("yaml"), TWINS_YAML);
}

#[test]
fn merged_signature_keeps_stable_features_required() {
    let (first, second) = (strong_source(), strong_source());
    let result = merge(
        &[
            MergeSample {
                source: &first,
                addr: 0x1000,
                opt: Some("O0"),
                tool: Some("test"),
            },
            MergeSample {
                source: &second,
                addr: 0x1000,
                opt: Some("O2"),
                tool: Some("test"),
            },
        ],
        Some("twins"),
        None,
    )
    .expect("merge");
    let signature = result.signature;

    assert_eq!(signature.name, "twins");
    assert_eq!(signature.confidence, "single-arch");
    let archs: Vec<&str> = signature
        .provenance
        .iter()
        .map(|sample| sample.arch.as_str())
        .collect();
    assert_eq!(archs, vec!["x64", "x64"]);
    assert_eq!(signature.provenance[0].opt.as_deref(), Some("O0"));
    assert_eq!(signature.provenance[1].opt.as_deref(), Some("O2"));
    // Stable data features stay required; shape features are optional by design.
    let data_required: Vec<bool> = signature
        .features
        .iter()
        .filter(|feature| ["str", "const", "callee"].contains(&feature.kind.as_str()))
        .map(|feature| feature.required)
        .collect();
    assert!(!data_required.is_empty());
    assert!(data_required.iter().all(|required| *required));
}

#[test]
fn merged_signature_demotes_divergent_features() {
    let (strong, deep) = (strong_source(), deep_source());
    let result = merge(
        &[
            MergeSample {
                source: &strong,
                addr: 0x1000,
                opt: Some("O0"),
                tool: Some("test"),
            },
            MergeSample {
                source: &deep,
                addr: 0x1000,
                opt: Some("O2"),
                tool: Some("test"),
            },
        ],
        Some("mixed"),
        None,
    )
    .expect("merge");
    let signature = result.signature;

    let demoted: Vec<_> = signature
        .features
        .iter()
        .filter(|feature| !feature.required)
        .collect();
    let stable: Vec<_> = signature
        .features
        .iter()
        .filter(|feature| feature.required)
        .collect();
    assert!(!demoted.is_empty(), "divergent features are demoted");
    assert!(!stable.is_empty(), "shared features stay required");
    assert!(demoted.iter().all(|feature| feature.weight < 1.0));
    // Anchors may only come from features every sample carries.
    let stable_keys: Vec<String> = stable.iter().map(|feature| feature.key()).collect();
    assert!(signature
        .anchors
        .iter()
        .all(|anchor| stable_keys.contains(anchor)));
}

#[test]
fn merged_confidence_follows_the_samples() {
    let (first, second) = (strong_source(), strong_source());
    let result = merge(
        &[
            MergeSample {
                source: &first,
                addr: 0x1000,
                opt: Some("O0"),
                tool: None,
            },
            MergeSample {
                source: &second,
                addr: 0x1000,
                opt: Some("O0"),
                tool: None,
            },
        ],
        None,
        None,
    )
    .expect("merge");
    assert_eq!(result.signature.confidence, "single-arch");
    // The merged signature still finds the function in both samples.
    let matches = scan(&first, &result.signature, None, 256, true, None);
    assert_eq!(matches[0].address, 0x1000);
}

#[test]
fn merge_refuses_when_a_sample_cannot_be_refound() {
    let (strong, tiny) = (strong_source(), tiny_source());
    let error = merge(
        &[
            MergeSample {
                source: &strong,
                addr: 0x1000,
                opt: None,
                tool: None,
            },
            MergeSample {
                source: &tiny,
                addr: 0x1000,
                opt: None,
                tool: None,
            },
        ],
        None,
        None,
    )
    .expect_err("a sample with no data features cannot be merged");
    assert!(error.to_string().contains("self-test"), "{error}");
}

#[test]
fn merged_signature_is_deterministic() {
    let (first, second) = (strong_source(), strong_source());
    let samples = [
        MergeSample {
            source: &first,
            addr: 0x1000,
            opt: Some("O2"),
            tool: None,
        },
        MergeSample {
            source: &second,
            addr: 0x1000,
            opt: Some("Os"),
            tool: None,
        },
    ];
    let once = merge(&samples, Some("det"), None)
        .expect("merge")
        .signature
        .to_yaml()
        .expect("yaml");
    let twice = merge(&samples, Some("det"), None)
        .expect("merge")
        .signature
        .to_yaml()
        .expect("yaml");
    assert_eq!(once, twice);
}

#[test]
fn merged_self_test_covers_every_sample() {
    let (first, second) = (strong_source(), strong_source());
    let result = merge(
        &[
            MergeSample {
                source: &first,
                addr: 0x1000,
                opt: None,
                tool: None,
            },
            MergeSample {
                source: &second,
                addr: 0x1000,
                opt: None,
                tool: None,
            },
        ],
        None,
        None,
    )
    .expect("merge");
    assert_eq!(result.matched.address, 0x1000);
    assert!(!result.signature.anchors.is_empty());
}
