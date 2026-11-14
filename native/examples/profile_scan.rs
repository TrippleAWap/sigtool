//! Scan-cost profile for the native scanner.
//!
//! For every x64 corpus binary it generates the signature set for that binary,
//! then times one full scanner pass (page hashing, index build, recovery) and
//! one incremental pass (everything unchanged). The workload and budget are the
//! ones the removed Python `profile_scan.py` used, so numbers recorded in
//! `PLAN.md` section 12 stay comparable.
//!
//! ```text
//! cargo run --release --example profile_scan
//! cargo run --release --example profile_scan -- --json ../corpus/scan-profile-native.json
//! ```
//!
//! The corpus is generated, not committed: run `python corpus/build.py` first.
//! The committed throughput baseline is x64-only, so this measures the x64
//! slice even though the decoder also handles arm64, arm32, and thumb.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use serde_json::Value;

use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate;
use sigtool_native::matcher::RecoveryBudget;
use sigtool_native::scanner::SignatureScanner;
use sigtool_native::sigfile::Signature;
use sigtool_native::source::ByteSource;

/// Same Tier 1 budget as `profile_scan.py::profile_binary`.
const CORPUS_BUDGET: usize = 100_000;

struct BinaryProfile {
    path: String,
    arch: String,
    bytes_scanned: u64,
    signatures: usize,
    full_pass_seconds: f64,
    incremental_pass_seconds: f64,
    regions_skipped: usize,
    pages_hashed: usize,
    index_instructions: usize,
    recoveries_budget: usize,
    hits: usize,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn profile_binary(path: &Path) -> Result<BinaryProfile, String> {
    let image = FileSource::from_path(path).map_err(|error| error.to_string())?;

    // Generate from every known function start, exactly like the Python
    // profile; refusals are skipped so both sides time the same signature set.
    let mut starts: Vec<u64> = image
        .modules()
        .first()
        .map(|module| module.functions.keys().copied().collect())
        .unwrap_or_default();
    starts.sort_unstable();

    let mut signatures: Vec<Signature> = Vec::new();
    for addr in starts {
        if let Ok(result) = generate(&image, addr, None, None, None, None, None) {
            signatures.push(result.signature);
        }
    }

    let signature_count = signatures.len();
    let mut scanner = SignatureScanner::new(
        &image,
        signatures,
        Some(RecoveryBudget {
            remaining: CORPUS_BUDGET,
        }),
        None,
    )
    .map_err(|error| error.to_string())?;

    let start = Instant::now();
    let full = scanner.scan_pass();
    let full_seconds = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let second = scanner.scan_pass();
    let incremental_seconds = start.elapsed().as_secs_f64();

    Ok(BinaryProfile {
        path: path.display().to_string(),
        arch: image.arch().as_str().to_string(),
        bytes_scanned: image
            .regions()
            .iter()
            .map(|region| region.data.len() as u64)
            .sum(),
        signatures: signature_count,
        full_pass_seconds: full_seconds,
        incremental_pass_seconds: incremental_seconds,
        regions_skipped: full.regions_skipped + second.regions_skipped,
        pages_hashed: full.pages_hashed,
        index_instructions: full.index_instructions,
        recoveries_budget: CORPUS_BUDGET - full.budget_remaining,
        hits: full.hits.len(),
    })
}

fn main() -> ExitCode {
    let mut corpus = repo_root().join("corpus").join("build");
    let mut json_path: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => match args.next() {
                Some(value) => corpus = PathBuf::from(value),
                None => {
                    eprintln!("--corpus expects a directory");
                    return ExitCode::from(2);
                }
            },
            "--json" => match args.next() {
                Some(value) => json_path = Some(PathBuf::from(value)),
                None => {
                    eprintln!("--json expects a file path");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!(
                    "usage: profile_scan [--corpus DIR] [--json FILE]\n\
                     \n\
                     times a full and an incremental native scanner pass per x64 corpus binary"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }

    let ground_truth_path = corpus.join("ground_truth.json");
    if !ground_truth_path.is_file() {
        eprintln!(
            "no corpus under {}; run python corpus/build.py",
            corpus.display()
        );
        return ExitCode::from(2);
    }
    let document: Value = match std::fs::read_to_string(&ground_truth_path)
        .map_err(|error| error.to_string())
        .and_then(|text| serde_json::from_str(&text).map_err(|error| error.to_string()))
    {
        Ok(document) => document,
        Err(error) => {
            eprintln!("cannot read {}: {error}", ground_truth_path.display());
            return ExitCode::from(2);
        }
    };
    let entries: Vec<&Value> = document["binaries"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry["arch"].as_str() == Some("x64"))
                .collect()
        })
        .unwrap_or_default();
    if entries.is_empty() {
        eprintln!("no x64 corpus binaries in {}", ground_truth_path.display());
        return ExitCode::from(2);
    }

    let mut profiles: Vec<BinaryProfile> = Vec::new();
    for entry in entries {
        let Some(relative) = entry["path"].as_str() else {
            continue;
        };
        let path = corpus.join(relative);
        match profile_binary(&path) {
            Ok(profile) => profiles.push(profile),
            Err(error) => {
                eprintln!("cannot profile {}: {error}", path.display());
                return ExitCode::from(2);
            }
        }
    }

    let total_bytes: u64 = profiles.iter().map(|profile| profile.bytes_scanned).sum();
    let total_seconds: f64 = profiles
        .iter()
        .map(|profile| profile.full_pass_seconds)
        .sum();
    let total_incremental: f64 = profiles
        .iter()
        .map(|profile| profile.incremental_pass_seconds)
        .sum();
    let mib_per_second = total_bytes as f64 / total_seconds.max(1e-9) / 1024.0 / 1024.0;

    println!("corpus binaries profiled: {}", profiles.len());
    println!(
        "total bytes scanned:      {:.2} MiB",
        total_bytes as f64 / 1024.0 / 1024.0
    );
    println!("full pass:                {total_seconds:.3}s  ({mib_per_second:.2} MiB/s)");
    println!(
        "incremental pass:         {total_incremental:.3}s  ({:.1}x faster)",
        total_seconds / total_incremental.max(1e-9)
    );
    println!(
        "index instructions:       {}",
        profiles
            .iter()
            .map(|profile| profile.index_instructions)
            .sum::<usize>()
    );
    println!();
    for profile in &profiles {
        println!(
            "  {:32} {:6} {:8.1} KiB  {:3} sigs  full {:8.1} ms  incr {:8.1} ms  hits {}",
            profile.path,
            profile.arch,
            profile.bytes_scanned as f64 / 1024.0,
            profile.signatures,
            profile.full_pass_seconds * 1000.0,
            profile.incremental_pass_seconds * 1000.0,
            profile.hits,
        );
    }

    if let Some(path) = json_path {
        let corpus_entries: Vec<Value> = profiles
            .iter()
            .map(|profile| {
                serde_json::json!({
                    "path": profile.path,
                    "arch": profile.arch,
                    "bytes_scanned": profile.bytes_scanned,
                    "signatures": profile.signatures,
                    "full_pass_seconds": profile.full_pass_seconds,
                    "incremental_pass_seconds": profile.incremental_pass_seconds,
                    "regions_skipped": profile.regions_skipped,
                    "pages_hashed": profile.pages_hashed,
                    "index_instructions": profile.index_instructions,
                    "recoveries_budget": profile.recoveries_budget,
                    "hits": profile.hits,
                })
            })
            .collect();
        let totals = serde_json::json!({
            "bytes_scanned": total_bytes,
            "full_pass_seconds": total_seconds,
            "incremental_pass_seconds": total_incremental,
            "mib_per_second": mib_per_second,
        });
        let document = serde_json::json!({
            "implementation": "native",
            "corpus": corpus_entries,
            "totals": totals,
        });
        let text = match serde_json::to_string_pretty(&document) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("cannot encode JSON: {error}");
                return ExitCode::from(2);
            }
        };
        if let Err(error) = std::fs::write(&path, format!("{text}\n")) {
            eprintln!("cannot write {}: {error}", path.display());
            return ExitCode::from(2);
        }
    }

    ExitCode::SUCCESS
}
