//! Corpus benchmark: recall per discovery mode, merged recall, and both
//! false-positive rates, measured with the native implementation alone.
//!
//! The corpus layout is `corpus/build/<arch>/<opt>/<file>.elf` plus
//! `ground_truth.json` (written by `corpus/build.py`). The architecture is
//! taken from the path, not the ground-truth `arch` field, because the Thumb
//! builds are recorded there as `arm32`; keying on the field would scan Thumb
//! signatures against ARM-mode code and mix two measurements in one cell.
//!
//! Every scan is independent, so the work is spread over a scoped thread pool;
//! results are collected into sorted maps, so the report is deterministic
//! regardless of thread scheduling (AGENTS.md rule 3).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::elf::FileSource;
use crate::generate::generate;
use crate::matcher::{scan, MAX_CANDIDATE_STARTS};
use crate::merge::{merge, MergeSample};
use crate::sigfile::Signature;
use crate::spec::SPEC_VERSION;

/// Recall drop / FP increase tolerated by [`compare`]. Rebuilding the corpus
/// with another clang moves cross-build rates by about 0.02.
pub const DEFAULT_TOLERANCE: f64 = 0.05;
pub const HINTED: &str = "hinted";
pub const HINT_FREE: &str = "hint-free";
pub const MERGED: &str = "merged";
/// Architectures merged into one cross-arch signature per function and opt.
const MERGE_ARCHES: [&str; 2] = ["x64", "arm64"];

/// One recall cell: signatures from `arch`/`source_opt` scanned against the
/// same function built at `target_opt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallCell {
    pub arch: String,
    pub source_opt: String,
    pub target_opt: String,
    pub discovery: String,
    pub hits: usize,
    pub attempts: usize,
}

impl RecallCell {
    pub fn rate(&self) -> f64 {
        ratio(self.hits, self.attempts)
    }
    fn key(&self) -> (String, String, String, String) {
        (
            self.arch.clone(),
            self.source_opt.clone(),
            self.target_opt.clone(),
            self.discovery.clone(),
        )
    }
}

/// Strong signatures of one arch scanned against code they must not match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalsePositiveCell {
    pub arch: String,
    pub signatures: usize,
    pub signatures_with_hits: usize,
    pub hits: usize,
}

impl FalsePositiveCell {
    pub fn rate(&self) -> f64 {
        ratio(self.signatures_with_hits, self.signatures)
    }
}

/// The compact, reviewable metrics document (also the baseline format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    pub spec_version: String,
    pub signatures: usize,
    pub refused: usize,
    pub merged_refused: usize,
    /// `arch -> verdict -> count`.
    pub verdicts: BTreeMap<String, BTreeMap<String, usize>>,
    pub recall: Vec<RecallCell>,
    pub false_positives: Vec<FalsePositiveCell>,
    pub negative_false_positives: Vec<FalsePositiveCell>,
    /// The same two measurements over every signature, whatever its verdict.
    /// A verdict is a promise about strong signatures only; these show how
    /// precise the matcher is for the weak and small ones a user still ships.
    #[serde(default)]
    pub any_false_positives: Vec<FalsePositiveCell>,
    #[serde(default)]
    pub any_negative_false_positives: Vec<FalsePositiveCell>,
}

/// One generated signature and where it came from.
struct Sample {
    arch: String,
    source_file: String,
    opt: String,
    name: String,
    signature: Signature,
    verdict: String,
}

/// One corpus image with its ground-truth function starts.
struct Target {
    arch: String,
    source_file: String,
    opt: String,
    source: FileSource,
    functions: BTreeMap<String, u64>,
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// `(arch, opt, file stem)` from `arch/opt/file.elf` or `negative/arch/opt/file.elf`.
fn kind(path: &str) -> (String, String, String) {
    let parts: Vec<&str> = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != "negative")
        .collect();
    let stem = Path::new(parts.last().copied().unwrap_or(""))
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("")
        .to_string();
    let opt = if parts.len() >= 2 {
        parts[parts.len() - 2]
    } else {
        "default"
    };
    let arch = if parts.len() >= 3 { parts[0] } else { "x64" };
    (arch.to_string(), opt.to_string(), stem)
}

fn load_targets(
    corpus: &Path,
    entries: &[Value],
    arches: &BTreeSet<String>,
) -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or("ground truth entry without a path")?;
        let (arch, opt, source_file) = kind(path);
        if !arches.is_empty() && !arches.contains(&arch) {
            continue;
        }
        let source =
            FileSource::from_path(corpus.join(path)).map_err(|error| format!("{path}: {error}"))?;
        let functions = entry["functions"]
            .as_array()
            .map(|functions| {
                functions
                    .iter()
                    .filter_map(|function| {
                        Some((
                            function["name"].as_str()?.to_string(),
                            function["start"].as_u64()?,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        targets.push(Target {
            arch,
            source_file,
            opt,
            source,
            functions,
        });
    }
    targets
        .sort_by(|a, b| (&a.arch, &a.opt, &a.source_file).cmp(&(&b.arch, &b.opt, &b.source_file)));
    Ok(targets)
}

/// Run `job(i)` for every `i < count` on all cores; results keep index order.
fn parallel<T: Send, F: Fn(usize) -> T + Sync>(count: usize, job: F) -> Vec<T> {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(count.max(1));
    let next = AtomicUsize::new(0);
    let slots: Mutex<Vec<Option<T>>> = Mutex::new((0..count).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                let value = job(index);
                slots.lock().expect("bench slots")[index] = Some(value);
            });
        }
    });
    slots
        .into_inner()
        .expect("bench slots")
        .into_iter()
        .map(|slot| slot.expect("every job ran"))
        .collect()
}

fn scan_addresses(source: &FileSource, signature: &Signature, hints: bool) -> Vec<u64> {
    scan(source, signature, None, MAX_CANDIDATE_STARTS, hints, None)
        .into_iter()
        .map(|matched| matched.address)
        .collect()
}

/// Measure the corpus under `corpus` (the directory holding `ground_truth.json`).
/// `arches` limits the run; empty means every architecture present.
pub fn run(corpus: &Path, arches: &[String]) -> Result<BenchReport, String> {
    let ground_truth_path = corpus.join("ground_truth.json");
    let text = std::fs::read_to_string(&ground_truth_path).map_err(|error| {
        format!(
            "{}: {error} (run python corpus/build.py)",
            ground_truth_path.display()
        )
    })?;
    let document: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let arches: BTreeSet<String> = arches.iter().cloned().collect();
    let empty = Vec::new();
    let targets = load_targets(
        corpus,
        document["binaries"].as_array().unwrap_or(&empty),
        &arches,
    )?;
    let negatives = load_targets(
        corpus,
        document["negative"].as_array().unwrap_or(&empty),
        &arches,
    )?;
    if targets.is_empty() {
        return Err(format!("no corpus binaries under {}", corpus.display()));
    }

    // -- single-arch samples ------------------------------------------------
    let jobs: Vec<(usize, String, u64)> = targets
        .iter()
        .enumerate()
        .flat_map(|(index, target)| {
            target
                .functions
                .iter()
                .map(move |(name, start)| (index, name.clone(), *start))
        })
        .collect();
    let generated = parallel(jobs.len(), |job| {
        let (index, name, start) = &jobs[job];
        let target = &targets[*index];
        generate(
            &target.source,
            *start,
            None,
            Some(&target.opt),
            Some("clang"),
            None,
            None,
        )
        .ok()
        .map(|result| Sample {
            arch: target.arch.clone(),
            source_file: target.source_file.clone(),
            opt: target.opt.clone(),
            name: name.clone(),
            verdict: result.report.verdict.clone(),
            signature: result.signature,
        })
    });
    let refused = generated.iter().filter(|sample| sample.is_none()).count();
    let samples: Vec<Sample> = generated.into_iter().flatten().collect();

    // -- merged samples -----------------------------------------------------
    let mut merge_jobs: Vec<(String, String, String, usize, u64, usize, u64)> = Vec::new();
    let find = |arch: &str, file: &str, opt: &str| {
        targets
            .iter()
            .position(|t| t.arch == arch && t.source_file == file && t.opt == opt)
    };
    for target in targets.iter().filter(|t| t.arch == MERGE_ARCHES[0]) {
        let Some(other) = find(MERGE_ARCHES[1], &target.source_file, &target.opt) else {
            continue;
        };
        let first = find(MERGE_ARCHES[0], &target.source_file, &target.opt).expect("self");
        for (name, start) in &target.functions {
            if let Some(other_start) = targets[other].functions.get(name) {
                merge_jobs.push((
                    target.source_file.clone(),
                    target.opt.clone(),
                    name.clone(),
                    first,
                    *start,
                    other,
                    *other_start,
                ));
            }
        }
    }
    merge_jobs.sort();
    let merged_results = parallel(merge_jobs.len(), |job| {
        let (file, opt, name, a, a_start, b, b_start) = &merge_jobs[job];
        let pair = [
            MergeSample {
                source: &targets[*a].source,
                addr: *a_start,
                opt: Some(opt),
                tool: Some("clang"),
            },
            MergeSample {
                source: &targets[*b].source,
                addr: *b_start,
                opt: Some(opt),
                tool: Some("clang"),
            },
        ];
        merge(&pair, Some(name), None).ok().map(|result| Sample {
            arch: MERGED.to_string(),
            source_file: file.clone(),
            opt: opt.clone(),
            name: name.clone(),
            verdict: result.report.verdict.clone(),
            signature: result.signature,
        })
    });
    let merged_refused = merged_results.iter().filter(|s| s.is_none()).count();
    let merged: Vec<Sample> = merged_results.into_iter().flatten().collect();

    let mut verdicts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let all: Vec<&Sample> = samples.iter().chain(merged.iter()).collect();
    for sample in &all {
        *verdicts
            .entry(sample.arch.clone())
            .or_default()
            .entry(sample.verdict.clone())
            .or_default() += 1;
    }

    // -- recall -------------------------------------------------------------
    // (sample index, target index, hints): one scan each.
    let mut recall_jobs: Vec<(usize, usize, bool)> = Vec::new();
    for (s, sample) in all.iter().enumerate() {
        for (t, target) in targets.iter().enumerate() {
            let arch_ok = sample.arch == MERGED || sample.arch == target.arch;
            if arch_ok
                && target.source_file == sample.source_file
                && target.functions.contains_key(&sample.name)
            {
                recall_jobs.push((s, t, true));
                recall_jobs.push((s, t, false));
            }
        }
    }
    let recall_hits = parallel(recall_jobs.len(), |job| {
        let (s, t, hints) = recall_jobs[job];
        let sample = all[s];
        let target = &targets[t];
        scan_addresses(&target.source, &sample.signature, hints)
            .contains(&target.functions[&sample.name])
    });
    let mut cells: BTreeMap<(String, String, String, String), (usize, usize)> = BTreeMap::new();
    for ((s, t, hints), hit) in recall_jobs.iter().zip(&recall_hits) {
        let sample = all[*s];
        let target = &targets[*t];
        let arch = if sample.arch == MERGED {
            format!("{MERGED}->{}", target.arch)
        } else {
            sample.arch.clone()
        };
        let discovery = if *hints { HINTED } else { HINT_FREE };
        let cell = cells
            .entry((
                arch,
                sample.opt.clone(),
                target.opt.clone(),
                discovery.to_string(),
            ))
            .or_default();
        cell.1 += 1;
        if *hit {
            cell.0 += 1;
        }
    }
    let recall = cells
        .into_iter()
        .map(
            |((arch, source_opt, target_opt, discovery), (hits, attempts))| RecallCell {
                arch,
                source_opt,
                target_opt,
                discovery,
                hits,
                attempts,
            },
        )
        .collect();

    // -- false positives ----------------------------------------------------
    // Corpus FP: other source files of the same arch (any arch for merged).
    let strong: Vec<&Sample> = all
        .iter()
        .copied()
        .filter(|s| s.verdict == "strong")
        .collect();
    let corpus_targets = |sample: &Sample| -> Vec<&Target> {
        targets
            .iter()
            .filter(|t| {
                t.source_file != sample.source_file
                    && (sample.arch == MERGED || t.arch == sample.arch)
            })
            .collect()
    };
    let negative_targets = |sample: &Sample| -> Vec<&Target> {
        negatives
            .iter()
            .filter(|t| sample.arch == MERGED || t.arch == sample.arch)
            .collect()
    };
    let false_positives = false_positive_cells(&strong, corpus_targets);
    let negative_false_positives = false_positive_cells(&strong, negative_targets);
    let any_false_positives = false_positive_cells(&all, corpus_targets);
    let any_negative_false_positives = false_positive_cells(&all, negative_targets);

    Ok(BenchReport {
        spec_version: SPEC_VERSION.to_string(),
        signatures: all.len(),
        refused,
        merged_refused,
        verdicts,
        recall,
        false_positives,
        negative_false_positives,
        any_false_positives,
        any_negative_false_positives,
    })
}

fn false_positive_cells<'t, F>(strong: &[&Sample], targets_for: F) -> Vec<FalsePositiveCell>
where
    F: Fn(&Sample) -> Vec<&'t Target> + Sync,
{
    let jobs: Vec<(usize, &'t Target)> = strong
        .iter()
        .enumerate()
        .flat_map(|(index, sample)| targets_for(sample).into_iter().map(move |t| (index, t)))
        .collect();
    let hits = parallel(jobs.len(), |job| {
        let (index, target) = jobs[job];
        scan_addresses(&target.source, &strong[index].signature, true).len()
    });
    let mut per_sample = vec![0usize; strong.len()];
    for ((index, _), count) in jobs.iter().zip(hits) {
        per_sample[*index] += count;
    }
    let mut cells: BTreeMap<String, FalsePositiveCell> = BTreeMap::new();
    for (sample, count) in strong.iter().zip(per_sample) {
        let cell = cells
            .entry(sample.arch.clone())
            .or_insert_with(|| FalsePositiveCell {
                arch: sample.arch.clone(),
                signatures: 0,
                signatures_with_hits: 0,
                hits: 0,
            });
        cell.signatures += 1;
        cell.hits += count;
        if count > 0 {
            cell.signatures_with_hits += 1;
        }
    }
    cells.into_values().collect()
}

/// Regressions of `current` against `baseline` beyond `tolerance`.
///
/// Rates, not counts, are compared because a different clang changes which
/// functions exist. Every recall cell (both discovery modes, merged included)
/// and every FP cell (merged included) is gated; generation refusals must not
/// grow. Merged-pair refusals are informational: refusing a pair that cannot
/// be merged honestly is the design working.
pub fn compare(baseline: &BenchReport, current: &BenchReport, tolerance: f64) -> Vec<String> {
    let mut failures = Vec::new();
    if baseline.spec_version != current.spec_version {
        failures.push(format!(
            "spec version {} differs from baseline {}; re-save the baseline",
            current.spec_version, baseline.spec_version
        ));
    }
    if current.refused > baseline.refused {
        failures.push(format!(
            "generation refused {} samples (baseline {})",
            current.refused, baseline.refused
        ));
    }
    let now: BTreeMap<_, _> = current.recall.iter().map(|c| (c.key(), c)).collect();
    for cell in &baseline.recall {
        match now.get(&cell.key()) {
            None => failures.push(format!("missing recall cell {:?}", cell.key())),
            Some(current) if current.rate() + tolerance < cell.rate() => failures.push(format!(
                "recall {:?}: {:.3} < baseline {:.3} - {tolerance:.2}",
                cell.key(),
                current.rate(),
                cell.rate()
            )),
            Some(_) => {}
        }
    }
    for (label, base, now) in [
        (
            "false positives",
            &baseline.false_positives,
            &current.false_positives,
        ),
        (
            "negative false positives",
            &baseline.negative_false_positives,
            &current.negative_false_positives,
        ),
        (
            "any-verdict false positives",
            &baseline.any_false_positives,
            &current.any_false_positives,
        ),
        (
            "any-verdict negative false positives",
            &baseline.any_negative_false_positives,
            &current.any_negative_false_positives,
        ),
    ] {
        for cell in base {
            let Some(current) = now.iter().find(|c| c.arch == cell.arch) else {
                failures.push(format!("missing {label} cell {}", cell.arch));
                continue;
            };
            if current.rate() > cell.rate() + tolerance {
                failures.push(format!(
                    "{label} {}: {:.3} > baseline {:.3} + {tolerance:.2}",
                    cell.arch,
                    current.rate(),
                    cell.rate()
                ));
            }
        }
    }
    failures
}

/// PLAN.md section 6 targets, evaluated on a report. Informational: the gate
/// is [`compare`]; this says how far the tool is from "done".
pub fn targets(report: &BenchReport) -> Vec<(String, f64, f64, bool)> {
    let mut out = Vec::new();
    let mut rate = |name: &str, filter: &dyn Fn(&RecallCell) -> bool, goal: f64| {
        let (hits, attempts) = report
            .recall
            .iter()
            .filter(|c| filter(c))
            .fold((0, 0), |(h, a), c| (h + c.hits, a + c.attempts));
        let value = ratio(hits, attempts);
        out.push((name.to_string(), value, goal, value >= goal));
    };
    for discovery in [HINTED, HINT_FREE] {
        rate(
            &format!("same-opt recall, single arch, {discovery}"),
            &|c| {
                c.discovery == discovery
                    && !c.arch.starts_with(MERGED)
                    && c.source_opt == c.target_opt
            },
            0.90,
        );
        rate(
            &format!("cross-opt recall, single arch, {discovery}"),
            &|c| {
                c.discovery == discovery
                    && !c.arch.starts_with(MERGED)
                    && c.source_opt != c.target_opt
            },
            0.70,
        );
        rate(
            &format!("same-opt recall, merged, {discovery}"),
            &|c| {
                c.discovery == discovery
                    && c.arch.starts_with(MERGED)
                    && c.source_opt == c.target_opt
            },
            0.90,
        );
    }
    for (label, cells) in [
        ("strong FP rate (corpus)", &report.false_positives),
        (
            "strong FP rate (negative)",
            &report.negative_false_positives,
        ),
    ] {
        let (with, total) = cells.iter().fold((0, 0), |(w, t), c| {
            (w + c.signatures_with_hits, t + c.signatures)
        });
        let value = ratio(with, total);
        out.push((label.to_string(), value, 0.0, with == 0));
    }
    // Not a section 6 target: precision of every shipped signature, whatever
    // its verdict. The aim is "as low as recall allows".
    for (label, cells) in [
        ("any-verdict FP rate (corpus)", &report.any_false_positives),
        (
            "any-verdict FP rate (negative)",
            &report.any_negative_false_positives,
        ),
    ] {
        let (with, total) = cells.iter().fold((0, 0), |(w, t), c| {
            (w + c.signatures_with_hits, t + c.signatures)
        });
        out.push((label.to_string(), ratio(with, total), 0.0, with == 0));
    }
    out
}

/// Human-readable report, the same shape `bench.py` printed.
pub fn render(report: &BenchReport) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "signatures: {}  refused: {}  merged pairs refused: {}",
        report.signatures, report.refused, report.merged_refused
    );
    for (arch, counts) in &report.verdicts {
        let line: Vec<String> = counts.iter().map(|(v, n)| format!("{v}={n}")).collect();
        let _ = writeln!(text, "  {arch}: {}", line.join(" "));
    }
    for discovery in [HINTED, HINT_FREE] {
        let _ = writeln!(text, "\nrecall ({discovery})");
        let (mut same, mut cross) = ((0, 0), (0, 0));
        for cell in report.recall.iter().filter(|c| c.discovery == discovery) {
            let same_build = cell.source_opt == cell.target_opt;
            let _ = writeln!(
                text,
                "  {} {}->{}: {}/{} = {:.3}{}",
                cell.arch,
                cell.source_opt,
                cell.target_opt,
                cell.hits,
                cell.attempts,
                cell.rate(),
                if same_build { "  (same build)" } else { "" }
            );
            let bucket = if same_build { &mut same } else { &mut cross };
            bucket.0 += cell.hits;
            bucket.1 += cell.attempts;
        }
        let _ = writeln!(
            text,
            "  total same build: {}/{} = {:.3}\n  total cross build: {}/{} = {:.3}",
            same.0,
            same.1,
            ratio(same.0, same.1),
            cross.0,
            cross.1,
            ratio(cross.0, cross.1)
        );
    }
    for (label, cells) in [
        (
            "false positives (strong vs other corpus sources)",
            &report.false_positives,
        ),
        (
            "false positives (strong vs negative corpus)",
            &report.negative_false_positives,
        ),
        (
            "false positives (any verdict vs other corpus sources)",
            &report.any_false_positives,
        ),
        (
            "false positives (any verdict vs negative corpus)",
            &report.any_negative_false_positives,
        ),
    ] {
        let _ = writeln!(text, "\n{label}");
        for cell in cells {
            let _ = writeln!(
                text,
                "  {}: {}/{} = {:.3}, total hits {}",
                cell.arch,
                cell.signatures_with_hits,
                cell.signatures,
                cell.rate(),
                cell.hits
            );
        }
    }
    let _ = writeln!(text, "\ntargets (PLAN.md section 6)");
    for (name, value, goal, met) in targets(report) {
        let _ = writeln!(
            text,
            "  [{}] {name}: {value:.3} (target {}{goal:.2})",
            if met { "met" } else { "   " },
            if goal == 0.0 { "=" } else { ">=" }
        );
    }
    text
}

/// Default corpus location relative to the repository root.
pub fn default_corpus(repo_root: &Path) -> PathBuf {
    repo_root.join("corpus").join("build")
}
