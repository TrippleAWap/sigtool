//! Corpus gate: recall per discovery mode (single-arch and merged) and both
//! false-positive rates must not regress against the committed native
//! baseline, `tests/baseline/native-bench.json`, beyond the bench tolerance.
//!
//! This is the same measurement as `sigtool-native bench --baseline`. The
//! corpus is generated (not committed), so the test skips when
//! `corpus/build/ground_truth.json` is absent.

use std::path::{Path, PathBuf};

use sigtool_native::bench::{self, BenchReport, DEFAULT_TOLERANCE};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

#[test]
fn corpus_does_not_regress_against_the_native_baseline() {
    let corpus = bench::default_corpus(&repo_root());
    if !corpus.join("ground_truth.json").is_file() {
        eprintln!(
            "skipping corpus gate: {} has no ground_truth.json (run python corpus/build.py)",
            corpus.display()
        );
        return;
    }
    let report = bench::run(&corpus, &[]).expect("bench run");
    eprintln!("{}", bench::render(&report));
    assert_eq!(report.refused, 0, "generation refused samples");

    let baseline_path = repo_root()
        .join("tests")
        .join("baseline")
        .join("native-bench.json");
    let baseline: BenchReport =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).expect("native baseline"))
            .expect("native baseline json");
    let failures = bench::compare(&baseline, &report, DEFAULT_TOLERANCE);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn bench_report_is_deterministic() {
    let corpus = bench::default_corpus(&repo_root());
    if !corpus.join("ground_truth.json").is_file() {
        return;
    }
    let arches = ["x64".to_string()];
    let mut first = bench::run(&corpus, &arches).expect("first run");
    let mut second = bench::run(&corpus, &arches).expect("second run");
    // Wall time and memory are measured, not computed; everything else must match.
    assert!(first.cost.is_some() && second.cost.is_some());
    first.cost = None;
    second.cost = None;
    assert_eq!(first, second, "parallel bench must be deterministic");
}

/// `bench --process-like` measures the live-process scan path as its own
/// discovery mode, recall and false positives, deterministically, and
/// leaves the file modes' cells as a run without it reports them.
#[test]
fn process_like_cells_are_measured_and_deterministic() {
    let corpus = bench::default_corpus(&repo_root());
    if !corpus.join("ground_truth.json").is_file() {
        return;
    }
    // x64: the process path finds functions only from anchor bytes in code
    // (the scanner hands the matcher no reference index, so string anchors
    // seed nothing), and on the toy corpus only x64 immediates land as
    // bytes.
    let options = bench::BenchOptions {
        arches: vec!["x64".to_string()],
        process: true,
        ..bench::BenchOptions::default()
    };
    let mut first = bench::run_with(&corpus, &options).expect("first run");
    let mut second = bench::run_with(&corpus, &options).expect("second run");
    first.cost = None;
    second.cost = None;
    assert_eq!(first, second, "process cells must be deterministic");

    let process: Vec<_> = first
        .recall
        .iter()
        .filter(|cell| cell.discovery == bench::PROCESS)
        .collect();
    assert!(!process.is_empty(), "no process recall cells");
    assert!(
        process.iter().any(|cell| cell.top_hits > 0),
        "the process path found nothing"
    );
    assert!(first
        .identified
        .iter()
        .any(|cell| cell.discovery == bench::PROCESS && cell.unrelated_scans > 0));
    assert!(
        first
            .process_any_false_positives
            .iter()
            .all(|cell| cell.targets > 0),
        "a process FP cell scanned nothing"
    );

    let mut plain = bench::run_with(
        &corpus,
        &bench::BenchOptions {
            process: false,
            ..options
        },
    )
    .expect("plain run");
    plain.cost = None;
    first.recall.retain(|cell| cell.discovery != bench::PROCESS);
    first
        .identified
        .retain(|cell| cell.discovery != bench::PROCESS);
    first.process_false_positives.clear();
    first.process_any_false_positives.clear();
    assert_eq!(first, plain, "--process-like moved a file-mode cell");
}
