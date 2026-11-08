//! Corpus parity: the native extractor and matcher must reproduce the Python
//! reference's x64 corpus results.
//!
//! `bench.py` measures recall per discovery mode and false positives against
//! `tests/baseline/bench.json`. This test runs the x64 slice of the same
//! measurement with the native implementation and compares the aggregate rates
//! to that baseline within the same 0.05 tolerance. The corpus is generated (not
//! committed), so the test skips when `corpus/build/ground_truth.json` is absent.
//!
//! ARM64/ARM32/Thumb are follow-up ports; this test deliberately scopes to x64,
//! the reference architecture.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate;
use sigtool_native::matcher::{scan, MAX_CANDIDATE_STARTS};
use sigtool_native::sigfile::Signature;

const TOLERANCE: f64 = 0.05;
const HINTED: &str = "hinted";
const HINT_FREE: &str = "hint-free";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn corpus_root() -> PathBuf {
    repo_root().join("corpus").join("build")
}

struct Sample {
    source_file: String,
    opt: String,
    name: String,
    signature: Signature,
    verdict: String,
}

#[derive(Default)]
struct Cell {
    hits: usize,
    attempts: usize,
}

fn split_path(path: &str) -> (String, String, String) {
    let parts: Vec<&str> = path.split('/').collect();
    let source_file = Path::new(parts.last().expect("file"))
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("")
        .to_string();
    let opt = parts
        .get(parts.len().saturating_sub(2))
        .copied()
        .unwrap_or("default")
        .to_string();
    let arch = parts.first().copied().unwrap_or("x64").to_string();
    (arch, source_file, opt)
}

fn source_path(path: &str) -> PathBuf {
    corpus_root().join(path)
}

fn functions(entry: &Value) -> Vec<(String, u64)> {
    entry["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|function| {
            (
                function["name"].as_str().expect("name").to_string(),
                function["start"].as_u64().expect("start"),
            )
        })
        .collect()
}

#[test]
fn x64_corpus_matches_the_python_baseline() {
    let ground_truth_path = corpus_root().join("ground_truth.json");
    if !ground_truth_path.is_file() {
        eprintln!(
            "skipping corpus parity: {} is absent (run python corpus/build.py)",
            ground_truth_path.display()
        );
        return;
    }
    let ground_truth: Value =
        serde_json::from_str(&std::fs::read_to_string(&ground_truth_path).expect("ground truth"))
            .expect("ground truth json");
    let binaries: Vec<&Value> = ground_truth["binaries"]
        .as_array()
        .expect("binaries")
        .iter()
        .filter(|entry| entry["arch"].as_str() == Some("x64"))
        .collect();
    assert!(!binaries.is_empty(), "no x64 corpus binaries");

    let mut sources: HashMap<String, FileSource> = HashMap::new();
    for entry in &binaries {
        let path = entry["path"].as_str().expect("path");
        sources.insert(
            path.to_string(),
            FileSource::from_path(source_path(path)).expect("corpus image"),
        );
    }
    for entry in ground_truth["negative"].as_array().expect("negative") {
        if entry["arch"].as_str() != Some("x64") {
            continue;
        }
        let path = entry["path"].as_str().expect("path");
        sources.insert(
            path.to_string(),
            FileSource::from_path(source_path(path)).expect("negative image"),
        );
    }

    // -- samples ---------------------------------------------------------
    let mut samples: Vec<Sample> = Vec::new();
    let mut refused = 0usize;
    for entry in &binaries {
        let path = entry["path"].as_str().expect("path");
        let (_arch, source_file, opt) = split_path(path);
        let source = &sources[path];
        for (name, start) in functions(entry) {
            match generate(source, start, None, Some(&opt), Some("clang"), None, None) {
                Ok(result) => samples.push(Sample {
                    source_file: source_file.clone(),
                    opt: opt.clone(),
                    name,
                    signature: result.signature,
                    verdict: result.report.verdict,
                }),
                Err(_) => refused += 1,
            }
        }
    }
    assert_eq!(refused, 0, "native generation refused {refused} samples");

    // -- recall ----------------------------------------------------------
    let mut function_table: HashMap<String, HashMap<String, u64>> = HashMap::new();
    for entry in &binaries {
        let path = entry["path"].as_str().expect("path").to_string();
        function_table.insert(path, functions(entry).into_iter().collect());
    }
    let mut cells: BTreeMap<(String, String, String), Cell> = BTreeMap::new();
    for sample in &samples {
        for (path, table) in &function_table {
            let (_arch, source_file, target_opt) = split_path(path);
            if source_file != sample.source_file {
                continue;
            }
            let Some(expected) = table.get(&sample.name) else {
                continue;
            };
            for (discovery, hints) in [(HINTED, true), (HINT_FREE, false)] {
                let source = &sources[path];
                let addresses: Vec<u64> = scan(
                    source,
                    &sample.signature,
                    None,
                    MAX_CANDIDATE_STARTS,
                    hints,
                    None,
                )
                .into_iter()
                .map(|matched| matched.address)
                .collect();
                let cell = cells
                    .entry((
                        sample.opt.clone(),
                        target_opt.clone(),
                        discovery.to_string(),
                    ))
                    .or_default();
                cell.attempts += 1;
                if addresses.contains(expected) {
                    cell.hits += 1;
                }
            }
        }
    }

    // -- false positives -------------------------------------------------
    let strong: Vec<&Sample> = samples
        .iter()
        .filter(|sample| sample.verdict == "strong")
        .collect();
    assert!(!strong.is_empty(), "no strong x64 signatures");
    let mut fp_signatures = 0usize;
    let mut fp_with_hits = 0usize;
    let mut fp_hits = 0usize;
    for sample in &strong {
        fp_signatures += 1;
        let mut hits = 0usize;
        for entry in &binaries {
            let path = entry["path"].as_str().expect("path");
            let (_arch, source_file, _opt) = split_path(path);
            if source_file == sample.source_file {
                continue;
            }
            hits += scan(
                &sources[path],
                &sample.signature,
                None,
                MAX_CANDIDATE_STARTS,
                true,
                None,
            )
            .len();
        }
        fp_hits += hits;
        if hits > 0 {
            fp_with_hits += 1;
        }
    }

    let mut negative_signatures = 0usize;
    let mut negative_with_hits = 0usize;
    let mut negative_hits = 0usize;
    for sample in &strong {
        negative_signatures += 1;
        let mut hits = 0usize;
        for entry in ground_truth["negative"].as_array().expect("negative") {
            if entry["arch"].as_str() != Some("x64") {
                continue;
            }
            let path = entry["path"].as_str().expect("path");
            hits += scan(
                &sources[path],
                &sample.signature,
                None,
                MAX_CANDIDATE_STARTS,
                true,
                None,
            )
            .len();
        }
        negative_hits += hits;
        if hits > 0 {
            negative_with_hits += 1;
        }
    }

    // -- compare to the Python baseline ----------------------------------
    let baseline_path = repo_root()
        .join("tests")
        .join("baseline")
        .join("bench.json");
    let baseline: Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).expect("baseline"))
            .expect("baseline json");
    assert_eq!(
        baseline["spec_version"].as_str(),
        Some(sigtool_native::spec::SPEC_VERSION),
        "baseline spec version"
    );

    let mut failures: Vec<String> = Vec::new();
    for cell in baseline["recall"].as_array().expect("recall") {
        if cell["arch"].as_str() != Some("x64") {
            continue;
        }
        let key = (
            cell["source_opt"].as_str().expect("source_opt").to_string(),
            cell["target_opt"].as_str().expect("target_opt").to_string(),
            cell["discovery"].as_str().expect("discovery").to_string(),
        );
        let expected_rate =
            cell["hits"].as_u64().unwrap() as f64 / cell["attempts"].as_u64().unwrap() as f64;
        match cells.get(&key) {
            None => failures.push(format!("missing recall cell {key:?}")),
            Some(current) => {
                let rate = current.hits as f64 / current.attempts as f64;
                if rate + TOLERANCE < expected_rate {
                    failures.push(format!(
                        "{key:?} recall {:.3} < baseline {:.3} - {TOLERANCE:.2}",
                        rate, expected_rate
                    ));
                }
                // Print every cell so a run records the parity evidence.
                eprintln!(
                    "recall {key:?}: {}/{} = {:.3} (python {:.3})",
                    current.hits, current.attempts, rate, expected_rate
                );
            }
        }
    }

    let baseline_fp = baseline["false_positives"]
        .as_array()
        .expect("false_positives")
        .iter()
        .find(|cell| cell["arch"].as_str() == Some("x64"))
        .expect("x64 false positives");
    let baseline_fp_rate = baseline_fp["signatures_with_hits"].as_u64().unwrap() as f64
        / baseline_fp["signatures"].as_u64().unwrap() as f64;
    let fp_rate = fp_with_hits as f64 / fp_signatures as f64;
    eprintln!(
        "false positives: {fp_with_hits}/{fp_signatures} = {fp_rate:.3} \
         (python {baseline_fp_rate:.3}, {fp_hits} total hits)"
    );
    if fp_rate > baseline_fp_rate + TOLERANCE {
        failures.push(format!(
            "cross-source false positives {fp_rate:.3} > baseline {baseline_fp_rate:.3} + {TOLERANCE:.2}"
        ));
    }

    let baseline_negative = baseline["negative_false_positives"]
        .as_array()
        .expect("negative_false_positives")
        .iter()
        .find(|cell| cell["arch"].as_str() == Some("x64"))
        .expect("x64 negative false positives");
    let baseline_negative_rate = baseline_negative["signatures_with_hits"].as_u64().unwrap() as f64
        / baseline_negative["signatures"].as_u64().unwrap() as f64;
    let negative_rate = negative_with_hits as f64 / negative_signatures as f64;
    eprintln!(
        "negative false positives: {negative_with_hits}/{negative_signatures} = \
         {negative_rate:.3} (python {baseline_negative_rate:.3}, {negative_hits} total hits)"
    );
    if negative_rate > baseline_negative_rate + TOLERANCE {
        failures.push(format!(
            "negative false positives {negative_rate:.3} > baseline {baseline_negative_rate:.3} + {TOLERANCE:.2}"
        ));
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
