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

/// A host image linking several libraries is listed once per library with
/// `members` (`corpus/real.py --host`): each entry pairs with that library's
/// own builds, and no FP scan reads an image that links the signature's own
/// library. Built from the toy corpus: the "host" is a copy of `loops.elf`
/// said to link `loops` and `parser`, and the negative a copy of
/// `parser.elf` linking `parser` only.
#[test]
fn host_entries_pair_by_library_and_skip_their_members() {
    let corpus = bench::default_corpus(&repo_root());
    let Ok(text) = std::fs::read_to_string(corpus.join("ground_truth.json")) else {
        return;
    };
    let document: serde_json::Value = serde_json::from_str(&text).expect("ground truth");
    let entry = |path: &str| {
        document["binaries"]
            .as_array()
            .expect("binaries")
            .iter()
            .find(|entry| entry["path"] == path)
            .cloned()
            .expect("toy corpus entry")
    };
    let loops = entry("x64/O2/loops.elf");
    let parser = entry("x64/O2/parser.elf");
    let dir = std::env::temp_dir().join(format!("sigtool-host-bench-{}", std::process::id()));
    let place = |from: &str, to: &str| {
        let target = dir.join(to);
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        std::fs::copy(corpus.join(from), target).expect("copy");
    };
    place("x64/O2/loops.elf", "x64/O2/loops.elf");
    place("x64/O2/parser.elf", "x64/O2/parser.elf");
    place("x64/O2/loops.elf", "x64/host-O2/host.elf");
    place("x64/O2/parser.elf", "negative/x64/host-O2/host.elf");
    let host = |library: &str, functions: &serde_json::Value| {
        serde_json::json!({
            "path": "x64/host-O2/host.elf",
            "library": library,
            "members": ["loops", "parser"],
            "functions": functions,
        })
    };
    let ground_truth = serde_json::json!({
        "binaries": [
            loops,
            parser,
            host("loops", &loops["functions"]),
            host("parser", &serde_json::json!([])),
        ],
        "negative": [{
            "path": "negative/x64/host-O2/host.elf",
            "members": ["parser"],
        }],
    });
    std::fs::write(dir.join("ground_truth.json"), ground_truth.to_string()).expect("write");
    let report = bench::run_with(&dir, &bench::BenchOptions::default());
    std::fs::remove_dir_all(&dir).expect("clean up");
    let report = report.expect("bench run");
    assert_eq!(report.refused, 0);

    // Loops signatures, from O2 and from the host itself, find loops there;
    // the host's parser entry lists nothing, so parser never pairs with it.
    let functions = loops["functions"].as_array().expect("functions").len();
    let host_attempts: usize = report
        .recall
        .iter()
        .filter(|c| c.arch == "x64" && c.target_opt == "host-O2" && c.discovery == "hint-free")
        .map(|c| c.attempts)
        .sum();
    assert_eq!(host_attempts, 2 * functions);
    let into_host = report
        .recall
        .iter()
        .find(|c| c.source_opt == "O2" && c.target_opt == "host-O2" && c.discovery == "hint-free")
        .expect("O2 -> host cell");
    assert!(into_host.top_hits > 0);
    // Loops signatures scan parser.elf and the negative, parser signatures
    // loops.elf; the host links both libraries, so no FP scan reads it.
    let hint_free = &report.hint_free_false_positives;
    assert!(hint_free.iter().any(|cell| cell.arch == "x64"));
    for cell in hint_free.iter().filter(|cell| cell.arch == "x64") {
        assert_eq!(cell.targets, 3, "loops.elf, parser.elf and the negative");
    }
    // The negative links parser, so only loops signatures scan it.
    for cell in report
        .any_negative_false_positives
        .iter()
        .filter(|cell| cell.arch == "x64")
    {
        assert_eq!(cell.targets, 1);
    }
}
