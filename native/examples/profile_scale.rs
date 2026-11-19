//! Scale harness: what a hint-free DB scan of one large image costs, and
//! whether any whole-image budget cut it short (PLAN.md G5,
//! docs/real-world-plan.md RW6).
//!
//! ```text
//! cargo run --release --example profile_scale -- functions IMAGE COUNT OUT.json
//! cargo run --release -- db build --file IMAGE --functions OUT.json --output SIGS.db
//! cargo run --release --example profile_scale -- run STRIPPED SIGS.db [RUNS]
//! ```
//!
//! `functions` writes COUNT of IMAGE's symbol starts, evenly spaced, as a
//! `db build --functions` list, so the DB holds real signatures of the
//! image's own functions (the unstripped image's symbols choose generation
//! addresses only). `run` scans STRIPPED with the DB as `scan --db
//! --discovery hint-free` does (one context, frequencies, every signature,
//! joint resolution) RUNS times (default 3), each in its own process so peak
//! memory is that run's, and prints the median wall time per phase, the
//! largest peak RSS, and the deterministic counters: instructions decoded by
//! each index, function starts, candidates compared, joint pairs, the
//! budgets that ran out, and a digest of every match, which must agree
//! across runs. Time it at a fixed `SIGTOOL_THREADS` on an idle machine;
//! the counters do not depend on either.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use serde_json::{json, Value};

use sigtool_native::coverage::Coverage;
use sigtool_native::db::MappedDb;
use sigtool_native::elf::FileSource;
use sigtool_native::joint::{universe, MAX_PAIRS};
use sigtool_native::matcher::{explain_candidates, scan_in, Match, ScanContext};
use sigtool_native::memory::peak_memory_bytes;
use sigtool_native::sigfile::Signature;
use sigtool_native::source::ByteSource;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("functions") if args.len() == 4 => functions(&args[1], &args[2], &args[3]),
        Some("scan") if args.len() == 3 => println!("{}", scan(&args[1], &args[2])),
        Some("run") if args.len() >= 3 => run(&args[1], &args[2], args.get(3)),
        _ => {
            eprintln!(
                "usage: profile_scale functions IMAGE COUNT OUT.json \
                 | run STRIPPED SIGS.db [RUNS] | scan STRIPPED SIGS.db"
            );
            std::process::exit(2);
        }
    }
}

fn functions(image: &str, count: &str, output: &str) {
    let count: usize = count.parse().expect("count");
    let source = FileSource::from_path(image).expect("image");
    let mut starts: Vec<u64> = source
        .function_starts()
        .into_iter()
        .filter(|start| source.is_executable(*start))
        .collect();
    starts.sort_unstable();
    starts.dedup();
    // Evenly spaced from the middle of each stride, so a small list samples
    // the whole image rather than the startup code the linker placed first.
    let step = (starts.len() as f64 / count.max(1) as f64).max(1.0);
    let chosen: Vec<u64> = (0..count.min(starts.len()))
        .map(|index| starts[(((index as f64 + 0.5) * step) as usize).min(starts.len() - 1)])
        .collect();
    let module = source.modules().first().expect("module");
    let list: Vec<Value> = chosen
        .iter()
        .map(|start| {
            json!({
                "rva": format!("0x{:x}", module.rva(*start)),
                "name": module.name_at(*start),
            })
        })
        .collect();
    std::fs::write(output, Value::Array(list).to_string()).expect("write list");
    println!("{} of {} function starts", chosen.len(), starts.len());
}

/// One scan; a JSON line of timings and counters.
fn scan(target: &str, db: &str) -> Value {
    let total = Instant::now();
    let mapped = MappedDb::open(Path::new(db)).expect("db");
    let signatures: Vec<Signature> = mapped
        .view()
        .expect("db view")
        .signatures()
        .expect("signatures");
    let mut phases = serde_json::Map::new();
    let mut phase = |name: &str, clock: Instant| {
        phases.insert(name.to_string(), json!(clock.elapsed().as_secs_f64()));
    };

    let clock = Instant::now();
    let source = FileSource::from_path(target).expect("target");
    phase("load", clock);
    let clock = Instant::now();
    let context = ScanContext::build(&source);
    phase("context", clock);
    let clock = Instant::now();
    context.prepare_frequencies(&source, false);
    phase("frequencies", clock);
    let clock = Instant::now();
    let mut all: Vec<Vec<Match>> = sigtool_native::parallel::map(signatures.len(), |index| {
        scan_in(&source, &signatures[index], &context, false)
    });
    phase("scan", clock);
    let clock = Instant::now();
    sigtool_native::joint::resolve(&source, &context, &signatures, &mut all, false);
    phase("joint", clock);
    let seconds = total.elapsed().as_secs_f64();
    // Read now: the counters below recover nothing new, but their lists
    // still allocate.
    let peak = peak_memory_bytes();

    let mut digest = crc32fast::Hasher::new();
    let mut matches = 0usize;
    let mut found = 0usize;
    for (signature, list) in signatures.iter().zip(&all) {
        digest.update(signature.name.as_bytes());
        found += usize::from(!list.is_empty());
        for hit in list {
            matches += 1;
            let line = format!(
                "{:x} {:x} {:?} {:?} {:?}\n",
                hit.address, hit.end, hit.score, hit.similarity, hit.matched
            );
            digest.update(line.as_bytes());
        }
    }
    // Candidates each signature is compared against: the start list the
    // scan above walked, recomputed outside the timed phases.
    let candidates: Vec<usize> = sigtool_native::parallel::map(signatures.len(), |index| {
        explain_candidates(&source, &signatures[index], &context, false).len()
    });
    // Joint resolution weighs each module's signatures against every
    // function it can assign; above MAX_PAIRS a module is left as scanned.
    let mut modules: std::collections::BTreeMap<&str, usize> = Default::default();
    for signature in &signatures {
        let module = signature
            .provenance
            .first()
            .map(|sample| sample.module.as_str())
            .unwrap_or("");
        *modules.entry(module).or_default() += 1;
    }
    let functions = universe(&source, &context, false).len();
    let largest = modules.values().copied().max().unwrap_or(0);
    let mut coverage = Coverage::new();
    coverage.add_context(&context);
    coverage.add_source(&source, false);
    let mut truncated: Vec<String> = coverage
        .exhausted()
        .iter()
        .map(|entry| entry.budget.key().to_string())
        .collect();
    if largest.saturating_mul(functions) > MAX_PAIRS {
        truncated.push("joint_pairs".to_string());
    }
    let code_bytes: u64 = source
        .regions()
        .iter()
        .filter(|region| region.executable)
        .map(|region| region.size() as u64)
        .sum();
    json!({
        "seconds": seconds,
        "phases": phases,
        "peak_rss_bytes": peak,
        "signatures": signatures.len(),
        "with_match": found,
        "matches": matches,
        "digest": format!("{:08x}", digest.finalize()),
        "code_bytes": code_bytes,
        "reference_instructions": context.references.instructions,
        "discovery_instructions": context.code.decoded(),
        "unwind_entries": source.unwind_entries().len(),
        "candidates": candidates.iter().sum::<usize>(),
        "max_candidates": candidates.iter().copied().max().unwrap_or(0),
        "joint_functions": functions,
        "joint_pairs": largest.saturating_mul(functions),
        "truncated": truncated,
    })
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn run(target: &str, db: &str, runs: Option<&String>) {
    let runs: usize = runs.map_or(3, |value| value.parse().expect("runs"));
    let exe = std::env::current_exe().expect("current exe");
    let results: Vec<Value> = (0..runs.max(1))
        .map(|_| {
            let output = Command::new(&exe)
                .args(["scan", target, db])
                .output()
                .expect("spawn scan");
            assert!(output.status.success(), "scan run failed");
            serde_json::from_slice(&output.stdout).expect("scan json")
        })
        .collect();
    let first = &results[0];
    for result in &results[1..] {
        assert_eq!(result["digest"], first["digest"], "runs disagree");
    }
    let mut summary = first.clone();
    summary["runs"] = json!(results.len());
    summary["seconds"] = json!(median(
        results
            .iter()
            .map(|r| r["seconds"].as_f64().unwrap_or(0.0))
            .collect()
    ));
    for name in ["load", "context", "frequencies", "scan", "joint"] {
        summary["phases"][name] = json!(median(
            results
                .iter()
                .map(|r| r["phases"][name].as_f64().unwrap_or(0.0))
                .collect()
        ));
    }
    summary["peak_rss_bytes"] = json!(results
        .iter()
        .filter_map(|r| r["peak_rss_bytes"].as_u64())
        .max());
    println!("{summary}");
}
