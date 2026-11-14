//! Runtime scanner parity: incrementalism, priorities, budgets, and the index.
//!
//! These mirror `tests/test_scanner.py`. The synthetic images are built the
//! same way so the native scanner is checked against the reference behaviour,
//! not just against itself.

use std::sync::atomic::{AtomicUsize, Ordering};

use sigtool_native::arch::Arch;
use sigtool_native::features::FeatureKind;
use sigtool_native::generate::generate;
use sigtool_native::matcher::{scan, self_test, RecoveryBudget, ReferenceIndex};
use sigtool_native::scanner::{SignatureScanner, PAGE_SIZE};
use sigtool_native::sigfile::{SampleProvenance, Signature, SignatureFeature};
use sigtool_native::source::{ByteSource, MemorySource, Module, Region};

const CODE_LEA: &[u8] = &[0x48, 0x8d, 0x3d];
const SECOND_ADDR: u64 = 0x1060;
const BANNER: &[u8] = b"generate banner literal\x00";

fn code() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(CODE_LEA);
    out.extend_from_slice(&(0x2000i64 - 0x1007).to_le_bytes());
    // mov eax, 0x12345678; ret
    out.extend_from_slice(&[0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3]);
    out
}

fn second() -> Vec<u8> {
    vec![0x31, 0xc0, 0xc3]
}

fn make_source(with_helper: bool) -> MemorySource {
    let mut text = code();
    text.resize((SECOND_ADDR - 0x1000) as usize, 0);
    text.extend_from_slice(&second());
    let text_region = Region::new("text", 0x1000, text, true, false);
    let rodata = Region::new("rodata", 0x2000, BANNER.to_vec(), false, false);

    let mut functions = std::collections::HashMap::new();
    let mut exports = Vec::new();
    if with_helper {
        functions.insert(SECOND_ADDR, "second_fn".to_string());
        exports.push(("helper".to_string(), SECOND_ADDR));
    }
    let module = Module {
        name: "fixture".to_string(),
        base: 0x1000,
        image_base: 0x1000,
        size: 0x2000 + BANNER.len() as u64 - 0x1000,
        path: None,
        exports,
        functions,
        imports: std::collections::HashMap::new(),
    };
    MemorySource::new(
        Arch::X64,
        vec![text_region, rodata],
        vec![module],
        Vec::new(),
        Vec::new(),
    )
}

fn two_signatures() -> (Signature, Signature) {
    let source = make_source(true);
    let first = generate(&source, 0x1000, Some("target"), None, None, None, None)
        .expect("target signature")
        .signature;
    let second = generate(
        &source,
        SECOND_ADDR,
        Some("second_fn"),
        None,
        None,
        None,
        None,
    )
    .expect("second signature")
    .signature;
    (first, second)
}

/// A source whose region bytes can change between scanner passes.
///
/// Both variants are precomputed, so `regions()` can keep returning a borrowed
/// slice while the active variant is swapped through an atomic index.
struct MutableSource {
    variants: [Vec<Region>; 2],
    generation: AtomicUsize,
}

impl MutableSource {
    fn new() -> MutableSource {
        let mut text = code();
        text.resize((SECOND_ADDR - 0x1000) as usize, 0);
        text.extend_from_slice(&second());
        let original = Region::new("text", 0x1000, text.clone(), true, false);
        let rodata = Region::new("rodata", 0x2000, BANNER.to_vec(), false, false);

        // One byte patched: the page hash changes but the function survives.
        let mut patched = text;
        let last = patched.len() - 1;
        patched[last] = 0x90;
        let mutated = Region::new("text", 0x1000, patched, true, false);

        MutableSource {
            variants: [vec![original, rodata.clone()], vec![mutated, rodata]],
            generation: AtomicUsize::new(0),
        }
    }

    fn mutate_text(&self) {
        self.generation.store(1, Ordering::SeqCst);
    }
}

impl ByteSource for MutableSource {
    fn arch(&self) -> Arch {
        Arch::X64
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, sigtool_native::errors::ReadError> {
        sigtool_native::source::read_regions(self.regions(), addr, size)
    }

    fn regions(&self) -> &[Region] {
        &self.variants[self.generation.load(Ordering::SeqCst)]
    }

    fn modules(&self) -> &[Module] {
        &[]
    }
}

/// The 15-instruction function from `tests/support.py::strong_source`.
fn strong_source() -> MemorySource {
    let mut code = Vec::new();
    code.extend_from_slice(CODE_LEA);
    code.extend_from_slice(&(0x2000i64 - 0x1007).to_le_bytes());
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
    let helper = 0x1060u64;
    let call_address = 0x1000 + code.len() as u64;
    code.push(0xe8);
    let displacement = helper as i64 - (call_address as i64 + 5);
    code.extend_from_slice(&(displacement as i32).to_le_bytes());
    code.push(0xc3);
    code.resize((helper - 0x1000) as usize, 0);
    code.push(0xc3);

    let text = Region::new("text", 0x1000, code, true, false);
    let rodata = Region::new("rodata", 0x2000, BANNER.to_vec(), false, false);
    let mut functions = std::collections::HashMap::new();
    functions.insert(helper, "helper".to_string());
    let module = Module {
        name: "gen".to_string(),
        base: 0x1000,
        image_base: 0x1000,
        size: 0x2000 + BANNER.len() as u64 - 0x1000,
        path: None,
        exports: vec![("helper".to_string(), helper)],
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

fn string_only_signature() -> Signature {
    Signature::new(
        "by_banner",
        vec![
            SignatureFeature {
                kind: FeatureKind::Str,
                value: "generate banner literal".to_string(),
                weight: 1.2,
                required: true,
            },
            SignatureFeature {
                kind: FeatureKind::Cfg,
                value: "blocks:1".to_string(),
                weight: 0.25,
                required: false,
            },
        ],
        vec!["str:generate banner literal".to_string()],
        0.75,
        1,
        "single-arch",
        vec![SampleProvenance {
            arch: "x64".to_string(),
            module: "fixture".to_string(),
            rva: 0x1000,
            opt: Some("O2".to_string()),
            tool: Some("test".to_string()),
        }],
    )
    .expect("valid signature")
}

#[test]
fn first_pass_finds_matches_and_second_pass_skips_everything() {
    let source = make_source(true);
    let (first, second) = two_signatures();
    let mut scanner = SignatureScanner::new(&source, vec![first, second], None, None).unwrap();

    let report = scanner.scan_pass();
    assert_eq!(report.pass_number, 1);
    assert_eq!(report.new_hits, 2);
    let names: std::collections::HashSet<&str> =
        report.hits.iter().map(|hit| hit.name.as_str()).collect();
    assert_eq!(names, ["target", "second_fn"].into_iter().collect());
    assert_eq!(report.regions_skipped, 0);

    let again = scanner.scan_pass();
    assert_eq!(again.pass_number, 2);
    assert_eq!(again.regions_scanned, 0);
    assert_eq!(
        again.regions_skipped,
        report.regions_scanned + report.regions_skipped
    );
    assert_eq!(again.new_hits, 0);
    let first_addresses: Vec<u64> = report.hits.iter().map(|hit| hit.address).collect();
    let again_addresses: Vec<u64> = again.hits.iter().map(|hit| hit.address).collect();
    assert_eq!(again_addresses, first_addresses);
    assert!(again.hits.iter().all(|hit| hit.first_seen == 1));
}

#[test]
fn modified_region_is_rescanned_and_new_hits_reported() {
    let source = MutableSource::new();
    let signature = generate(&source, 0x1000, Some("target"), None, None, None, None)
        .expect("signature")
        .signature;
    let mut scanner = SignatureScanner::new(&source, vec![signature], None, None).unwrap();
    let first = scanner.scan_pass();
    assert_eq!(first.new_hits, 1);

    source.mutate_text();
    let second = scanner.scan_pass();
    assert!(second.regions_scanned >= 1);
    assert!(second
        .hits
        .iter()
        .any(|hit| hit.name == "target" && hit.address == 0x1000));
    assert_eq!(second.new_hits, 0);
    assert!(second.hits.iter().all(|hit| hit.first_seen == 1));

    let third = scanner.scan_pass();
    assert_eq!(third.regions_scanned, 0);
    assert_eq!(third.new_hits, 0);
    assert!(third.hits.iter().any(|hit| hit.address == 0x1000));
}

#[test]
fn private_regions_are_prioritized_before_image_regions() {
    let source = make_source(true);
    let private_code = Region::new("injected", 0x9000, code(), true, false);
    let mut regions: Vec<Region> = source.regions().to_vec();
    regions.push(private_code.clone());
    let private_source = MemorySource::new(
        Arch::X64,
        regions,
        source.modules().to_vec(),
        Vec::new(),
        Vec::new(),
    );
    let injected_source = MemorySource::simple(Arch::X64, vec![private_code]);
    let injected = generate(
        &injected_source,
        0x9000,
        Some("injected_fn"),
        None,
        None,
        None,
        None,
    )
    .expect("injected signature")
    .signature;

    let mut scanner = SignatureScanner::new(&private_source, vec![injected], None, None).unwrap();
    let report = scanner.scan_pass();
    assert_eq!(report.regions_private, 1);
    assert!(report.hits.iter().any(|hit| hit.address == 0x9000));
}

#[test]
fn budget_limits_recoveries_across_signatures() {
    let source = make_source(true);
    let (first, second) = two_signatures();
    let mut scanner = SignatureScanner::new(
        &source,
        vec![first, second],
        Some(RecoveryBudget { remaining: 2 }),
        None,
    )
    .unwrap();

    let report = scanner.scan_pass();
    assert!(report.budget_exhausted);
    assert_eq!(report.budget_remaining, 0);
    let names: std::collections::HashSet<&str> =
        report.hits.iter().map(|hit| hit.name.as_str()).collect();
    assert!(names.contains("target"));
    assert!(!names.contains("second_fn"));
}

#[test]
fn reference_index_discovers_string_only_signatures() {
    let source = strong_source();
    let signature = string_only_signature();

    // Without the index, a string anchor cannot produce a hint-free candidate.
    assert!(scan(&source, &signature, None, 256, false, None).is_empty());

    let mut index = ReferenceIndex::default();
    for region in source.regions() {
        index.index_region(&source, region);
    }
    let matches = scan(&source, &signature, None, 256, false, Some(&index));
    let addresses: Vec<u64> = matches.iter().map(|item| item.address).collect();
    assert_eq!(addresses, vec![0x1000]);
}

#[test]
fn reference_index_sweeps_with_resync_and_reports_truncation() {
    let garbage = Region::new("junk", 0x3000, vec![0xff; 0x2000], true, false);
    let source = make_source(true);
    let mut index = ReferenceIndex::default();
    index.index_region(&source, &garbage);

    assert!(index.truncated);
    assert!(index.referencers(0x2000).is_empty());
}

#[test]
fn index_is_per_region_and_survives_independent_updates() {
    let source = make_source(true);
    let mut index = ReferenceIndex::default();
    let regions: Vec<Region> = source.regions().to_vec();
    let counts: Vec<usize> = regions
        .iter()
        .map(|region| index.index_region(&source, region))
        .collect();

    assert!(counts[0] > 0);
    assert_eq!(index.referencers(0x2000), &[0x1000]);
    index.drop_region(regions[0].start);
    assert!(index.referencers(0x2000).is_empty());
    assert!(!index.truncated);
}

#[test]
fn self_test_uses_the_index_for_string_only_signatures() {
    let source = strong_source();
    let signature = Signature::new(
        "by_banner",
        vec![SignatureFeature {
            kind: FeatureKind::Str,
            value: "generate banner literal".to_string(),
            weight: 1.2,
            required: true,
        }],
        vec!["str:generate banner literal".to_string()],
        0.75,
        1,
        "single-arch",
        vec![SampleProvenance {
            arch: "x64".to_string(),
            module: "fixture".to_string(),
            rva: 0x1000,
            opt: Some("O2".to_string()),
            tool: Some("test".to_string()),
        }],
    )
    .expect("valid signature");
    let matched = self_test(&signature, &source, 0x1000, None, 256).expect("self-test");
    assert_eq!(matched.address, 0x1000);
}

#[test]
fn scanner_refuses_an_empty_signature_set() {
    let source = make_source(true);
    assert!(SignatureScanner::new(&source, Vec::new(), None, None).is_err());
}

#[test]
fn page_size_is_power_of_two() {
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn signature_identity_is_stable_through_the_scanner() {
    let source = make_source(true);
    let signature = generate(&source, 0x1000, Some("target"), None, None, None, None)
        .expect("signature")
        .signature;
    let expected_id = signature.signature_id().expect("id");
    let mut scanner = SignatureScanner::new(&source, vec![signature], None, None).unwrap();
    let report = scanner.scan_pass();

    let hit = report
        .hits
        .iter()
        .find(|hit| hit.name == "target")
        .expect("target hit");
    assert_eq!(hit.signature_id, expected_id);
    assert_eq!(hit.address, 0x1000);
    assert_eq!(hit.score, 1.0);
}
