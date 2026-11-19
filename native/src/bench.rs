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
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::elf::FileSource;
use crate::generate::generate_in;
use crate::matcher::{identified_answer, rank_key, scan_in, Match, ScanContext};
use crate::merge::{merge_in, MergeSample};
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

/// `clang-O2` -> `O2`; a bare `O2` (single-compiler corpus) is its own level.
fn level(opt: &str) -> &str {
    opt.rsplit_once('-').map_or(opt, |(_, level)| level)
}

/// The compiler of a build, recorded as the signature's provenance `tool`:
/// `gcc-O2` -> `gcc`. A bare level is the toy corpus, which
/// `corpus/build.py` builds with clang only.
fn compiler(opt: &str) -> &str {
    opt.split_once('-')
        .map_or("clang", |(compiler, _)| compiler)
}

/// Same optimization level, built by a different compiler.
fn other_compiler(cell: &RecallCell) -> bool {
    cell.source_opt != cell.target_opt && level(&cell.source_opt) == level(&cell.target_opt)
}

/// Selects the recall cells of one target group.
type CellFilter<'a> = &'a dyn Fn(&RecallCell) -> bool;

/// `(arch or source->target, source opt, target opt, discovery)`.
type CellKey = (String, String, String, String);

/// One recall cell: signatures from `arch`/`source_opt` scanned against the
/// same function built at `target_opt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecallCell {
    pub arch: String,
    pub source_opt: String,
    pub target_opt: String,
    pub discovery: String,
    pub hits: usize,
    /// Hits where the expected function is the single best match: the
    /// scanner's answer, not merely one of many places a loose signature fits.
    #[serde(default)]
    pub top_hits: usize,
    pub attempts: usize,
}

impl RecallCell {
    pub fn rate(&self) -> f64 {
        ratio(self.hits, self.attempts)
    }
    pub fn top_rate(&self) -> f64 {
        ratio(self.top_hits, self.attempts)
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
    /// Distinct images the cell's signatures were scanned against. A cell
    /// that scanned nothing has rate 0 by construction, so [`compare`] fails
    /// it instead of letting it pass. Baselines saved before it was recorded
    /// load as 0; only the current run's count is checked.
    #[serde(default)]
    pub targets: usize,
    /// File bytes of those images (the stripped copies for hint-free scans).
    #[serde(default)]
    pub target_bytes: u64,
}

impl FalsePositiveCell {
    pub fn rate(&self) -> f64 {
        ratio(self.signatures_with_hits, self.signatures)
    }
}

/// Joint resolution against one target build: top-1 over every function of
/// the source module, scanned alone and then resolved together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointCell {
    /// Source library. Baselines saved before it was recorded leave it empty;
    /// their cells are matched by order instead (see [`compare`]).
    #[serde(default)]
    pub library: String,
    /// `source->target` architectures.
    pub arch: String,
    pub source_opt: String,
    pub target_opt: String,
    pub attempts: usize,
    pub independent_top: usize,
    pub joint_top: usize,
}

/// Signatures of one module with any accepted match in an unrelated library.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JointFalsePositiveCell {
    pub library: String,
    pub signatures: usize,
    pub independent_with_hits: usize,
    pub joint_with_hits: usize,
}

/// Top-1 answers labelled `identified` in one discovery mode (G3): the
/// answers a user is told to trust, in images with and without the function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentifiedCell {
    pub discovery: String,
    /// Recall scans (the image holds the function) whose first match is
    /// identified.
    pub answers: usize,
    /// Of those, answers at the expected start and strictly first; a tie for
    /// first is not correct (PLAN.md rule 5), so precision is a lower bound.
    pub correct: usize,
    /// False-positive scans: images that do not hold the function.
    pub unrelated_scans: usize,
    /// False-positive scans whose first match is identified: always wrong.
    pub unrelated_answers: usize,
}

impl IdentifiedCell {
    /// Correct identified answers over every identified answer, including
    /// those in images without the function.
    pub fn precision(&self) -> f64 {
        ratio(self.correct, self.answers + self.unrelated_answers)
    }
    /// Scans of images without the function that give no identified answer.
    pub fn abstention(&self) -> f64 {
        ratio(
            self.unrelated_scans - self.unrelated_answers,
            self.unrelated_scans,
        )
    }
}

/// Top-1 recall of one library in one G1 row (PLAN.md §2), so one library
/// cannot hide another's regression in the aggregate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LibraryRecallCell {
    pub library: String,
    pub discovery: String,
    pub row: String,
    pub top_hits: usize,
    pub attempts: usize,
}

impl LibraryRecallCell {
    pub fn top_rate(&self) -> f64 {
        ratio(self.top_hits, self.attempts)
    }
}

/// Library cells are gated only when both runs made at least this many
/// attempts. At 20 one flipped answer moves the rate by exactly the 0.05
/// tolerance, which does not fail; smaller cells would fail on one flip, and
/// a library-wide regression still shows in its larger rows and in the
/// aggregate recall cells.
pub const MIN_LIBRARY_ATTEMPTS: usize = 20;

/// The G1 row (PLAN.md §2) a recall cell counts toward, from its
/// `arch`/`source->target` label and builds; `None` for cells no row covers
/// (merged signatures scanned in one of their own architectures, or at
/// another level).
fn g1_row(arch: &str, source_opt: &str, target_opt: &str) -> Option<&'static str> {
    let same_build = source_opt == target_opt;
    let same_level = level(source_opt) == level(target_opt);
    if arch.starts_with(MERGED) {
        let held_out = !MERGE_ARCHES
            .iter()
            .any(|own| arch == format!("{MERGED}->{own}"));
        return (held_out && same_level).then_some("merged x64+arm64, held-out arch, same level");
    }
    Some(match (arch.contains("->"), same_build, same_level) {
        (false, true, _) => "same arch, same build",
        (false, false, true) => "same arch, other compiler, same level",
        (false, false, false) => "same arch, other optimization level",
        (true, true, _) => "other arch, same build settings",
        (true, false, true) => "other arch, other compiler",
        (true, false, false) => "other arch, other optimization level",
    })
}

/// Wall time of one bench phase and the process's peak memory at its end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseCost {
    pub phase: String,
    pub millis: u64,
    /// Peak resident memory of the whole run up to the end of this phase;
    /// `None` where the OS does not report it.
    pub peak_memory_bytes: Option<u64>,
}

/// What a bench run cost (G5). Machine-dependent, so [`compare`] never gates
/// on it; it is reported until M8 measures enough runs to set gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cost {
    /// Worker threads the scans were spread over.
    pub threads: usize,
    /// In execution order.
    pub phases: Vec<PhaseCost>,
    pub total_millis: u64,
    pub peak_memory_bytes: Option<u64>,
}

/// The compact, reviewable metrics document (also the baseline format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchReport {
    pub spec_version: String,
    /// `--sample-seed` of the run; absent for the default, name-only sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_seed: Option<u64>,
    /// True when every hint-free scan ran on a `strip --strip-all` copy.
    #[serde(default)]
    pub hint_free_stripped: bool,
    /// Any-verdict false positives of hint-free scans (unrelated sources plus
    /// the negative corpus), on stripped targets when available.
    #[serde(default)]
    pub hint_free_false_positives: Vec<FalsePositiveCell>,
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
    /// `bench --joint`: whole-module signature sets resolved jointly.
    #[serde(default)]
    pub joint: Vec<JointCell>,
    #[serde(default)]
    pub joint_false_positives: Vec<JointFalsePositiveCell>,
    /// Identified precision and abstention per discovery mode (G3).
    #[serde(default)]
    pub identified: Vec<IdentifiedCell>,
    /// Top-1 recall per `(library, discovery, G1 row)`.
    #[serde(default)]
    pub library_recall: Vec<LibraryRecallCell>,
    /// Wall time and peak memory per phase; informational, never compared.
    #[serde(default)]
    pub cost: Option<Cost>,
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
    /// Every ground-truth function, before `--max-functions` trims `functions`.
    all_functions: BTreeMap<String, u64>,
    /// Whole-image indexes, built on first use and shared by every scan.
    context: OnceLock<ScanContext>,
    /// The same image after `strip --strip-all`, when the corpus has one.
    stripped: Option<(FileSource, OnceLock<ScanContext>)>,
    /// File size of the image and of its stripped copy, for FP cell sizes.
    bytes: u64,
    stripped_bytes: Option<u64>,
}

impl Target {
    /// Hint-free scans run on the stripped copy when there is one: ignoring
    /// hints on the unstripped file still leaks `.symtab` names into callee
    /// features and Thumb-mode detection.
    fn scan(&self, signature: &Signature, hints: bool) -> Vec<Match> {
        let (source, context) = self.scan_source(hints);
        scan_in(source, signature, context, hints)
    }

    /// File size of the image [`Target::scan`] reads in this mode.
    fn scanned_bytes(&self, hints: bool) -> u64 {
        match (self.stripped_bytes, hints) {
            (Some(bytes), false) => bytes,
            _ => self.bytes,
        }
    }

    fn scan_source(&self, hints: bool) -> (&FileSource, &ScanContext) {
        match (&self.stripped, hints) {
            (Some((source, context)), false) => {
                (source, context.get_or_init(|| ScanContext::build(source)))
            }
            _ => (
                &self.source,
                self.context
                    .get_or_init(|| ScanContext::build(&self.source)),
            ),
        }
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Wilson score interval at 95% for `successes` of `n`; `(0, 1)` for `n = 0`.
/// Corpus cells hold tens of samples, where the normal approximation's
/// interval leaves [0, 1] and collapses to a point at rates 0 and 1.
fn wilson(successes: usize, n: usize) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    const Z: f64 = 1.959_963_984_540_054;
    let n = n as f64;
    let p = successes as f64 / n;
    let z2 = Z * Z;
    let denominator = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / denominator;
    let half = Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denominator;
    ((centre - half).max(0.0), (centre + half).min(1.0))
}

/// `k/n = rate [low, high]`: the rate with its n and 95% Wilson interval.
fn rate_text(successes: usize, n: usize) -> String {
    let (low, high) = wilson(successes, n);
    format!(
        "{successes}/{n} = {:.3} [{low:.3}, {high:.3}]",
        ratio(successes, n)
    )
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
    max_functions: usize,
    sample_seed: Option<u64>,
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
        let file_size = |path: &str| {
            std::fs::metadata(corpus.join(path))
                .map(|metadata| metadata.len())
                .map_err(|error| format!("{path}: {error}"))
        };
        let bytes = file_size(path)?;
        let stripped_bytes = entry["stripped"].as_str().map(file_size).transpose()?;
        let stripped = match entry["stripped"].as_str() {
            Some(stripped) => Some((
                FileSource::from_path(corpus.join(stripped))
                    .map_err(|error| format!("{stripped}: {error}"))?,
                OnceLock::new(),
            )),
            None => None,
        };
        let functions: BTreeMap<String, u64> = entry["functions"]
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
        let all_functions = functions.clone();
        let functions = limit_functions(functions, max_functions, sample_seed);
        targets.push(Target {
            arch,
            source_file,
            opt,
            source,
            functions,
            all_functions,
            context: OnceLock::new(),
            stripped,
            bytes,
            stripped_bytes,
        });
    }
    targets
        .sort_by(|a, b| (&a.arch, &a.opt, &a.source_file).cmp(&(&b.arch, &b.opt, &b.source_file)));
    Ok(targets)
}

/// Run `job(i)` for every `i < count` on all cores; results keep index order.
fn parallel<T: Send, F: Fn(usize) -> T + Sync>(count: usize, job: F) -> Vec<T> {
    // The shared pool marks its workers, so the library's own parallel
    // phases (index build, frequencies) run sequentially inside a bench cell
    // instead of oversubscribing every core per cell.
    crate::parallel::map(count, job)
}

/// Keep the first `limit` functions by CRC-32 of the name (0 keeps all). The
/// choice depends only on names, so every build of a library keeps the same set.
/// A `seed` ranks by CRC-32 of its little-endian bytes followed by the name
/// instead: a different sample of the same libraries, so a milestone exit is
/// not measured only on the functions every change was tuned against.
fn limit_functions(
    functions: BTreeMap<String, u64>,
    limit: usize,
    seed: Option<u64>,
) -> BTreeMap<String, u64> {
    if limit == 0 || functions.len() <= limit {
        return functions;
    }
    let rank = |name: &str| match seed {
        None => crc32fast::hash(name.as_bytes()),
        Some(seed) => {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&seed.to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.finalize()
        }
    };
    let mut ranked: Vec<(u32, String, u64)> = functions
        .into_iter()
        .map(|(name, start)| (rank(&name), name, start))
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .take(limit)
        .map(|(_, name, start)| (name, start))
        .collect()
}

/// Measure the corpus under `corpus` (the directory holding `ground_truth.json`).
/// `arches` limits the run; empty means every architecture present.
pub fn run(corpus: &Path, arches: &[String]) -> Result<BenchReport, String> {
    run_with(
        corpus,
        &BenchOptions {
            arches: arches.to_vec(),
            ..BenchOptions::default()
        },
    )
}

/// What a bench run measures.
#[derive(Debug, Clone, Default)]
pub struct BenchOptions {
    /// Architectures to load; empty means all.
    pub arches: Vec<String>,
    /// Ground-truth functions kept per binary; 0 keeps all.
    pub max_functions: usize,
    /// Rank functions for `max_functions` by CRC-32 of seed and name instead
    /// of name alone (see [`limit_functions`]).
    pub sample_seed: Option<u64>,
    /// Only this discovery mode (`hinted` or `hint-free`); `None` runs both.
    pub discovery: Option<String>,
    /// Skip both false-positive measurements (recall-only iteration).
    pub skip_false_positives: bool,
    /// Write every hint-free false-positive hit here as one JSON object per line.
    pub fp_report: Option<PathBuf>,
    /// Also measure joint resolution of whole-module signature sets.
    pub joint: bool,
    /// Write what joint resolution saw in each joint cell here, one JSON
    /// object per line (see [`crate::joint::report`]).
    pub joint_report: Option<PathBuf>,
}

/// [`run`] with explicit [`BenchOptions`].
pub fn run_with(corpus: &Path, options: &BenchOptions) -> Result<BenchReport, String> {
    let arches = &options.arches;
    let max_functions = options.max_functions;
    let mut phases = Phases::start();
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
        max_functions,
        options.sample_seed,
    )?;
    let negatives = load_targets(
        corpus,
        document["negative"].as_array().unwrap_or(&empty),
        &arches,
        max_functions,
        options.sample_seed,
    )?;
    if targets.is_empty() {
        return Err(format!("no corpus binaries under {}", corpus.display()));
    }

    phases.done("load");
    // Build every image's indexes up front, one image per worker. Built
    // lazily, jobs for the same image are adjacent, so every worker blocked
    // on one OnceLock while a single thread built it.
    let images: Vec<&Target> = targets.iter().chain(negatives.iter()).collect();
    parallel(images.len(), |index| {
        let target = images[index];
        target
            .context
            .get_or_init(|| ScanContext::build(&target.source));
        if let Some((source, context)) = &target.stripped {
            if options.discovery.as_deref() != Some(HINTED) {
                context.get_or_init(|| ScanContext::build(source));
            }
        }
    });
    phases.done("indexes");
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
        let context = target
            .context
            .get_or_init(|| ScanContext::build(&target.source));
        generate_in(
            &target.source,
            *start,
            None,
            Some(&target.opt),
            Some(compiler(&target.opt)),
            None,
            None,
            Some(context),
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

    phases.done("samples");
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
                tool: Some(compiler(opt)),
            },
            MergeSample {
                source: &targets[*b].source,
                addr: *b_start,
                opt: Some(opt),
                tool: Some(compiler(opt)),
            },
        ];
        let contexts: Vec<Option<&ScanContext>> = [*a, *b]
            .iter()
            .map(|index| {
                let target = &targets[*index];
                Some(
                    target
                        .context
                        .get_or_init(|| ScanContext::build(&target.source)),
                )
            })
            .collect();
        merge_in(&pair, &contexts, Some(name), None)
            .ok()
            .map(|result| Sample {
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

    phases.done("merge");
    // -- recall -------------------------------------------------------------
    // (sample index, target index, hints): one scan each.
    let mut recall_jobs: Vec<(usize, usize, bool)> = Vec::new();
    for (s, sample) in all.iter().enumerate() {
        for (t, target) in targets.iter().enumerate() {
            // Every architecture is a target: same-arch cells measure
            // comparison quality, `a->b` cells measure the actual goal,
            // finding one function across architectures.
            if target.source_file == sample.source_file
                && target.functions.contains_key(&sample.name)
            {
                for hints in [true, false] {
                    let mode = if hints { HINTED } else { HINT_FREE };
                    if options.discovery.as_deref().is_none_or(|only| only == mode) {
                        recall_jobs.push((s, t, hints));
                    }
                }
            }
        }
    }
    let recall_hits = parallel(recall_jobs.len(), |job| {
        let (s, t, hints) = recall_jobs[job];
        let sample = all[s];
        let target = &targets[t];
        let expected = target.functions[&sample.name];
        let matches = target.scan(&sample.signature, hints);
        let found = matches.iter().any(|m| m.address == expected);
        // Matches are sorted best first; a tie for first is ambiguous.
        let top = top_is(&matches, expected);
        let answer = identified_answer(&matches);
        let kept = if options.fp_report.is_some() {
            matches
        } else {
            Vec::new()
        };
        (found, top, kept, answer)
    });
    if let Some(path) = &options.fp_report {
        // Hint-free scans go to `<path>.recall`, hinted ones to
        // `<path>.recall-hinted`, so either mode can be simulated offline.
        let mut out = String::new();
        let mut out_hinted = String::new();
        for ((s, t, hints), (_, _, matches, _)) in recall_jobs.iter().zip(&recall_hits) {
            let sample = all[*s];
            let target = &targets[*t];
            let expected = target.functions[&sample.name];
            let found: Vec<Value> = matches
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "true": m.address == expected,
                        "score": m.score,
                        "similarity": m.similarity,
                        "logp": target.scan_source(false).1.key_frequencies(&m.matched),
                        "carriers": target.scan_source(false).1.key_carriers(&m.matched),
                        "matched": m.matched,
                        "address": m.address,
                        "rival": m.rival,
                        "waived": m.waived,
                    })
                })
                .collect();
            let line = serde_json::json!({
                "sample": sample.name,
                "arch": sample.arch,
                "source": sample.source_file,
                "opt": sample.opt,
                "verdict": sample.verdict,
                "features": feature_labels(&sample.signature),
                "neighbours": sample.signature.neighbours,
                "target": format!("{}/{}/{}", target.arch, target.opt, target.source_file),
                "matches": found,
            });
            let sink = if *hints { &mut out_hinted } else { &mut out };
            sink.push_str(&line.to_string());
            sink.push('\n');
        }
        for (suffix, text) in [(".recall", out), (".recall-hinted", out_hinted)] {
            let mut recall_path = path.as_os_str().to_owned();
            recall_path.push(suffix);
            std::fs::write(&recall_path, text).map_err(|error| format!("{error}"))?;
        }
    }
    let mut cells: BTreeMap<CellKey, (usize, usize, usize)> = BTreeMap::new();
    let mut answers: BTreeMap<&str, IdentifiedCell> = BTreeMap::new();
    let mut libraries: BTreeMap<(String, &str, &str), (usize, usize)> = BTreeMap::new();
    for ((s, t, hints), hit) in recall_jobs.iter().zip(&recall_hits) {
        let sample = all[*s];
        let target = &targets[*t];
        let arch = if sample.arch == target.arch {
            sample.arch.clone()
        } else {
            format!("{}->{}", sample.arch, target.arch)
        };
        let discovery = if *hints { HINTED } else { HINT_FREE };
        if let Some(row) = g1_row(&arch, &sample.opt, &target.opt) {
            let cell = libraries
                .entry((sample.source_file.clone(), discovery, row))
                .or_default();
            cell.0 += usize::from(hit.1);
            cell.1 += 1;
        }
        let cell = cells
            .entry((
                arch,
                sample.opt.clone(),
                target.opt.clone(),
                discovery.to_string(),
            ))
            .or_default();
        cell.2 += 1;
        if hit.0 {
            cell.0 += 1;
        }
        if hit.1 {
            cell.1 += 1;
        }
        let answer = identified_cell(&mut answers, discovery);
        if hit.3 {
            answer.answers += 1;
            if hit.1 {
                answer.correct += 1;
            }
        }
    }
    let recall = cells
        .into_iter()
        .map(
            |((arch, source_opt, target_opt, discovery), (hits, top_hits, attempts))| RecallCell {
                arch,
                source_opt,
                target_opt,
                discovery,
                hits,
                top_hits,
                attempts,
            },
        )
        .collect();

    phases.done("recall");
    // -- false positives ----------------------------------------------------
    // Corpus FP: other source files of the same arch (any arch for merged).
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
    // Scan every signature once per target set; the strong cells are the
    // strong subset of the same counts.
    let hinted_fp =
        !options.skip_false_positives && options.discovery.as_deref() != Some(HINT_FREE);
    let hint_free_fp =
        !options.skip_false_positives && options.discovery.as_deref() != Some(HINTED);
    let (corpus_hits, negative_hits) = if hinted_fp {
        let corpus_hits = false_positive_hits(&all, corpus_targets, true);
        let negative_hits = false_positive_hits(&all, negative_targets, true);
        if let Some(path) = &options.fp_report {
            let mut hinted_path = path.as_os_str().to_owned();
            hinted_path.push(".hinted");
            let both: Vec<_> = corpus_hits.iter().chain(&negative_hits).cloned().collect();
            write_fp_report(Path::new(&hinted_path), &all, &both)?;
        }
        let cell = identified_cell(&mut answers, HINTED);
        for hits in [&corpus_hits, &negative_hits] {
            cell.unrelated_scans += hits.len();
            cell.unrelated_answers += hits
                .iter()
                .filter(|(_, _, matches)| identified_answer(matches))
                .count();
        }
        (corpus_hits, negative_hits)
    } else {
        // Not measured: the hinted cells report zero targets and fail a
        // baseline comparison rather than pass with an unmeasured rate.
        (Vec::new(), Vec::new())
    };
    // Hint-free scans see every function in a stripped image, so their
    // precision is its own number: any verdict, unrelated sources and the
    // negative corpus together.
    let hint_free_false_positives = if hint_free_fp {
        let hits = false_positive_hits(
            &all,
            |sample| {
                let mut chosen = corpus_targets(sample);
                chosen.extend(negative_targets(sample));
                chosen
            },
            false,
        );
        if let Some(path) = &options.fp_report {
            write_fp_report(path, &all, &hits)?;
        }
        let cell = identified_cell(&mut answers, HINT_FREE);
        for (_, _, matches) in &hits {
            cell.unrelated_scans += 1;
            if identified_answer(matches) {
                cell.unrelated_answers += 1;
            }
        }
        false_positive_cells(&all, &hits, false, None)
    } else {
        Vec::new()
    };
    let is_strong: Vec<bool> = all.iter().map(|s| s.verdict == "strong").collect();
    let false_positives = false_positive_cells(&all, &corpus_hits, true, Some(&is_strong));
    let negative_false_positives =
        false_positive_cells(&all, &negative_hits, true, Some(&is_strong));
    let any_false_positives = false_positive_cells(&all, &corpus_hits, true, None);
    let any_negative_false_positives = false_positive_cells(&all, &negative_hits, true, None);

    phases.done("false positives");
    let (joint, joint_false_positives) = if options.joint {
        measure_joint(&targets, options.joint_report.as_deref())?
    } else {
        (Vec::new(), Vec::new())
    };
    if options.joint {
        phases.done("joint");
    }
    Ok(BenchReport {
        spec_version: SPEC_VERSION.to_string(),
        sample_seed: options.sample_seed,
        hint_free_stripped: targets.iter().all(|t| t.stripped.is_some()),
        hint_free_false_positives,
        signatures: all.len(),
        refused,
        merged_refused,
        verdicts,
        recall,
        false_positives,
        negative_false_positives,
        any_false_positives,
        any_negative_false_positives,
        joint,
        joint_false_positives,
        identified: answers.into_values().collect(),
        library_recall: libraries
            .into_iter()
            .map(
                |((library, discovery, row), (top_hits, attempts))| LibraryRecallCell {
                    library,
                    discovery: discovery.to_string(),
                    row: row.to_string(),
                    top_hits,
                    attempts,
                },
            )
            .collect(),
        cost: Some(phases.finish()),
    })
}

/// The [`IdentifiedCell`] of `discovery`, created empty on first use.
fn identified_cell<'a>(
    cells: &'a mut BTreeMap<&'static str, IdentifiedCell>,
    discovery: &'static str,
) -> &'a mut IdentifiedCell {
    cells.entry(discovery).or_insert_with(|| IdentifiedCell {
        discovery: discovery.to_string(),
        answers: 0,
        correct: 0,
        unrelated_scans: 0,
        unrelated_answers: 0,
    })
}

/// The build whose whole module is signed for `--joint`.
const JOINT_SOURCE: (&str, &str) = ("x64", "clang-O2");

/// Whether the expected function is the single best match.
fn top_is(matches: &[Match], expected: u64) -> bool {
    matches.first().is_some_and(|m| m.address == expected)
        && matches
            .get(1)
            .is_none_or(|next| rank_key(next) < rank_key(&matches[0]))
}

/// Joint resolution over whole modules: every ground-truth function of the
/// `JOINT_SOURCE` build is signed, then scanned hint-free in every other
/// build of the library, alone and resolved together. The same set scanned
/// in the other libraries' `JOINT_SOURCE` builds measures what joint
/// resolution adds to false positives.
fn measure_joint(
    targets: &[Target],
    report: Option<&Path>,
) -> Result<(Vec<JointCell>, Vec<JointFalsePositiveCell>), String> {
    let mut lines: Vec<String> = Vec::new();
    // One line per joint scan. Expected addresses come from the unstripped
    // ground truth and are for offline scoring only; resolution never sees them.
    let mut log = |kind: &str,
                   library: &str,
                   target: &Target,
                   signatures: &[Signature],
                   expected: &[Option<u64>],
                   matches: &[Vec<Match>],
                   resolved: &[Vec<Match>]| {
        if report.is_none() {
            return;
        }
        let (image, image_context) = target.scan_source(false);
        let mut line = crate::joint::report(image, image_context, signatures, matches, false);
        line["kind"] = serde_json::json!(kind);
        line["library"] = serde_json::json!(library);
        line["target"] = serde_json::json!(format!(
            "{}/{}/{}",
            target.arch, target.opt, target.source_file
        ));
        line["names"] = serde_json::json!(signatures.iter().map(|s| &s.name).collect::<Vec<_>>());
        line["expected"] = serde_json::json!(expected);
        line["resolved"] = serde_json::json!(resolved
            .iter()
            .map(|found| found.first().map(|m| m.address))
            .collect::<Vec<_>>());
        lines.push(line.to_string());
    };
    let mut cells = Vec::new();
    let mut false_positives = Vec::new();
    let sources: Vec<&Target> = targets
        .iter()
        .filter(|t| (t.arch.as_str(), t.opt.as_str()) == JOINT_SOURCE)
        .collect();
    for source in &sources {
        let context = source
            .context
            .get_or_init(|| ScanContext::build(&source.source));
        let names: Vec<(&String, &u64)> = source.all_functions.iter().collect();
        let generated = parallel(names.len(), |job| {
            let (name, start) = names[job];
            generate_in(
                &source.source,
                *start,
                Some(name),
                Some(&source.opt),
                Some(compiler(&source.opt)),
                None,
                None,
                Some(context),
            )
            .ok()
            .map(|result| result.signature)
        });
        let signatures: Vec<Signature> = generated.into_iter().flatten().collect();
        let scan_all = |target: &Target| -> Vec<Vec<Match>> {
            parallel(signatures.len(), |job| target.scan(&signatures[job], false))
        };
        for target in targets
            .iter()
            .filter(|t| t.source_file == source.source_file)
            .filter(|t| !std::ptr::eq(*t, *source))
        {
            let mut matches = scan_all(target);
            let expected: Vec<Option<u64>> = signatures
                .iter()
                .map(|s| target.all_functions.get(&s.name).copied())
                .collect();
            let score = |matches: &[Vec<Match>]| {
                matches
                    .iter()
                    .zip(&expected)
                    .filter(|(found, want)| want.is_some_and(|want| top_is(found, want)))
                    .count()
            };
            let independent_top = score(&matches);
            let scanned = report.is_some().then(|| matches.clone());
            let (image, image_context) = target.scan_source(false);
            crate::joint::resolve(image, image_context, &signatures, &mut matches, false);
            if let Some(scanned) = &scanned {
                log(
                    "recall",
                    &source.source_file,
                    target,
                    &signatures,
                    &expected,
                    scanned,
                    &matches,
                );
            }
            cells.push(JointCell {
                library: source.source_file.clone(),
                arch: format!("{}->{}", source.arch, target.arch),
                source_opt: source.opt.clone(),
                target_opt: target.opt.clone(),
                attempts: expected.iter().filter(|want| want.is_some()).count(),
                independent_top,
                joint_top: score(&matches),
            });
        }
        let mut cell = JointFalsePositiveCell {
            library: source.source_file.clone(),
            signatures: 0,
            independent_with_hits: 0,
            joint_with_hits: 0,
        };
        for other in sources
            .iter()
            .filter(|t| t.source_file != source.source_file)
        {
            let mut matches = scan_all(other);
            cell.signatures += signatures.len();
            cell.independent_with_hits += matches.iter().filter(|m| !m.is_empty()).count();
            let scanned = report.is_some().then(|| matches.clone());
            let (image, image_context) = other.scan_source(false);
            crate::joint::resolve(image, image_context, &signatures, &mut matches, false);
            if let Some(scanned) = &scanned {
                log(
                    "fp",
                    &source.source_file,
                    other,
                    &signatures,
                    &vec![None; signatures.len()],
                    scanned,
                    &matches,
                );
            }
            cell.joint_with_hits += matches.iter().filter(|m| !m.is_empty()).count();
        }
        false_positives.push(cell);
    }
    if let Some(path) = report {
        let mut text = lines.join("\n");
        text.push('\n');
        std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok((cells, false_positives))
}

/// Every accepted match per `(sample, target)` pair, for reporting.
fn false_positive_hits<'t, F>(
    samples: &[&Sample],
    targets_for: F,
    hints: bool,
) -> Vec<(usize, &'t Target, Vec<Match>)>
where
    F: Fn(&Sample) -> Vec<&'t Target> + Sync,
{
    let jobs: Vec<(usize, &'t Target)> = samples
        .iter()
        .enumerate()
        .flat_map(|(index, sample)| targets_for(sample).into_iter().map(move |t| (index, t)))
        .collect();
    let matches = parallel(jobs.len(), |job| {
        let (index, target) = jobs[job];
        target.scan(&samples[index].signature, hints)
    });
    jobs.into_iter()
        .zip(matches)
        .map(|((index, target), found)| (index, target, found))
        .collect()
}

/// A signature's features as `!key@weight` (`!` marks required), for reports.
fn feature_labels(signature: &Signature) -> Vec<String> {
    signature
        .features
        .iter()
        .map(|f| {
            format!(
                "{}{}@{:.2}",
                if f.required { "!" } else { "" },
                f.key(),
                f.weight
            )
        })
        .collect()
}

/// One JSON line per false-positive hit. The hit is labelled from the
/// unstripped ground truth, which the scan itself never saw.
fn write_fp_report(
    path: &Path,
    samples: &[&Sample],
    hits: &[(usize, &Target, Vec<Match>)],
) -> Result<(), String> {
    let mut out = String::new();
    for (index, target, matches) in hits {
        let sample = samples[*index];
        for found in matches {
            let label = target
                .functions
                .iter()
                .find(|(_, start)| **start == found.address)
                .map(|(name, _)| name.clone());
            let features = feature_labels(&sample.signature);
            let line = serde_json::json!({
                "sample": sample.name,
                "arch": sample.arch,
                "source": sample.source_file,
                "opt": sample.opt,
                "verdict": sample.verdict,
                "confidence": sample.signature.confidence,
                "min_distinct": sample.signature.min_distinct,
                "threshold": sample.signature.match_threshold,
                "features": features,
                "anchors": sample.signature.anchors,
                "target": format!("{}/{}/{}", target.arch, target.opt, target.source_file),
                "address": found.address,
                "size": found.end.saturating_sub(found.address),
                "score": found.score,
                "similarity": found.similarity,
                "logp": target.scan_source(false).1.key_frequencies(&found.matched),
                "carriers": target.scan_source(false).1.key_carriers(&found.matched),
                "matched": found.matched,
                "rival": found.rival,
                "waived": found.waived,
                "label": label,
                "neighbours": sample.signature.neighbours,
            });
            out.push_str(&line.to_string());
            out.push('\n');
        }
    }
    std::fs::write(path, out).map_err(|error| format!("{}: {error}", path.display()))
}

/// One cell per sample arch from the accepted matches of every
/// `(sample, target)` scan; `only` keeps a subset of the samples.
fn false_positive_cells(
    samples: &[&Sample],
    hits: &[(usize, &Target, Vec<Match>)],
    hints: bool,
    only: Option<&[bool]>,
) -> Vec<FalsePositiveCell> {
    let mut counts = vec![0usize; samples.len()];
    // Images per arch, by identity: a negative image may share its
    // `(arch, opt, stem)` with a corpus image.
    let mut scanned: BTreeMap<&str, BTreeMap<*const Target, u64>> = BTreeMap::new();
    for (index, target, matches) in hits {
        if only.is_some_and(|keep| !keep[*index]) {
            continue;
        }
        counts[*index] += matches.len();
        scanned
            .entry(samples[*index].arch.as_str())
            .or_default()
            .insert(*target as *const Target, target.scanned_bytes(hints));
    }
    let mut cells: BTreeMap<String, FalsePositiveCell> = BTreeMap::new();
    for (index, (sample, count)) in samples.iter().zip(&counts).enumerate() {
        if only.is_some_and(|keep| !keep[index]) {
            continue;
        }
        let cell = cells
            .entry(sample.arch.clone())
            .or_insert_with(|| FalsePositiveCell {
                arch: sample.arch.clone(),
                signatures: 0,
                signatures_with_hits: 0,
                hits: 0,
                targets: 0,
                target_bytes: 0,
            });
        cell.signatures += 1;
        cell.hits += count;
        if *count > 0 {
            cell.signatures_with_hits += 1;
        }
    }
    for cell in cells.values_mut() {
        if let Some(images) = scanned.get(cell.arch.as_str()) {
            cell.targets = images.len();
            cell.target_bytes = images.values().sum();
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
            Some(current) => {
                if current.rate() + tolerance < cell.rate() {
                    failures.push(format!(
                        "recall {:?}: {:.3} < baseline {:.3} - {tolerance:.2}",
                        cell.key(),
                        current.rate(),
                        cell.rate()
                    ));
                }
                if current.top_rate() + tolerance < cell.top_rate() {
                    failures.push(format!(
                        "top-1 recall {:?}: {:.3} < baseline {:.3} - {tolerance:.2}",
                        cell.key(),
                        current.top_rate(),
                        cell.top_rate()
                    ));
                }
            }
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
        (
            "hint-free false positives",
            &baseline.hint_free_false_positives,
            &current.hint_free_false_positives,
        ),
    ] {
        for cell in base {
            let Some(current) = now.iter().find(|c| c.arch == cell.arch) else {
                failures.push(format!("missing {label} cell {}", cell.arch));
                continue;
            };
            if current.targets == 0 {
                failures.push(format!(
                    "{label} {}: scanned 0 targets; an empty cell cannot pass",
                    cell.arch
                ));
                continue;
            }
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
    // Joint cells are gated only when both runs measured them (`--joint`).
    if !current.joint.is_empty() {
        // One cell per source library and target build. The n-th baseline
        // cell with a key is compared with the n-th current one: the key
        // alone repeats once per library, and matching the first hit compared
        // every library's baseline against the first library's result.
        let mut seen: BTreeMap<(String, &String, &String, &String), usize> = BTreeMap::new();
        for cell in &baseline.joint {
            let key = (&cell.arch, &cell.source_opt, &cell.target_opt);
            let library = |c: &JointCell| {
                if cell.library.is_empty() {
                    String::new()
                } else {
                    c.library.clone()
                }
            };
            let occurrence = seen
                .entry((library(cell), key.0, key.1, key.2))
                .or_insert(0);
            let found = current
                .joint
                .iter()
                .filter(|c| (&c.arch, &c.source_opt, &c.target_opt) == key)
                .filter(|c| library(c) == library(cell))
                .nth(*occurrence);
            *occurrence += 1;
            let Some(now) = found else {
                failures.push(format!("missing joint cell {key:?}"));
                continue;
            };
            let (before, after) = (
                ratio(cell.joint_top, cell.attempts),
                ratio(now.joint_top, now.attempts),
            );
            if after < before - tolerance {
                failures.push(format!(
                    "joint top-1 {} {key:?}: {after:.3} < baseline {before:.3} - {tolerance:.2}",
                    now.library
                ));
            }
        }
        for cell in &baseline.joint_false_positives {
            let Some(now) = current
                .joint_false_positives
                .iter()
                .find(|c| c.library == cell.library)
            else {
                failures.push(format!("missing joint FP cell {}", cell.library));
                continue;
            };
            let (before, after) = (
                ratio(cell.joint_with_hits, cell.signatures),
                ratio(now.joint_with_hits, now.signatures),
            );
            if after > before + tolerance {
                failures.push(format!(
                    "joint FP {}: {after:.3} > baseline {before:.3} + {tolerance:.2}",
                    cell.library
                ));
            }
        }
    }
    // Baselines from before identified cells existed have none: not compared.
    for cell in &baseline.identified {
        let Some(now) = current
            .identified
            .iter()
            .find(|c| c.discovery == cell.discovery)
        else {
            failures.push(format!("missing identified cell {}", cell.discovery));
            continue;
        };
        // Precision counts unrelated answers only when the FP scans ran, so a
        // `--no-fp` run is compared only with another `--no-fp` run.
        let same_scans = (cell.unrelated_scans > 0) == (now.unrelated_scans > 0);
        if same_scans && now.precision() + tolerance < cell.precision() {
            failures.push(format!(
                "identified precision {}: {:.3} < baseline {:.3} - {tolerance:.2}",
                cell.discovery,
                now.precision(),
                cell.precision()
            ));
        }
        if cell.unrelated_scans > 0
            && now.unrelated_scans > 0
            && now.abstention() + tolerance < cell.abstention()
        {
            failures.push(format!(
                "abstention {}: {:.3} < baseline {:.3} - {tolerance:.2}",
                cell.discovery,
                now.abstention(),
                cell.abstention()
            ));
        }
    }
    // Library cells: only where both runs have enough attempts for the
    // tolerance to mean something (see `MIN_LIBRARY_ATTEMPTS`).
    for cell in baseline
        .library_recall
        .iter()
        .filter(|c| c.attempts >= MIN_LIBRARY_ATTEMPTS)
    {
        let key = (&cell.library, &cell.discovery, &cell.row);
        let Some(now) = current
            .library_recall
            .iter()
            .find(|c| (&c.library, &c.discovery, &c.row) == key)
        else {
            failures.push(format!("missing library recall cell {key:?}"));
            continue;
        };
        if now.attempts >= MIN_LIBRARY_ATTEMPTS && now.top_rate() + tolerance < cell.top_rate() {
            failures.push(format!(
                "library top-1 recall {key:?}: {:.3} < baseline {:.3} - {tolerance:.2}",
                now.top_rate(),
                cell.top_rate()
            ));
        }
    }
    failures
}

/// PLAN.md §2 (G1, G3) v1.0 goals, evaluated on a report. Informational: the gate
/// is [`compare`]; this says how far the tool is from "done".
/// Each goal is `(name, successes, n, goal, met)`; `met` compares the point
/// rate, like the gate.
pub fn targets(report: &BenchReport) -> Vec<(String, usize, usize, f64, bool)> {
    let mut out = Vec::new();
    let mut rate = |name: &str, filter: &dyn Fn(&RecallCell) -> bool, goal: f64| {
        let (hits, top, attempts) = report
            .recall
            .iter()
            .filter(|c| filter(c))
            .fold((0, 0, 0), |(h, t, a), c| {
                (h + c.hits, t + c.top_hits, a + c.attempts)
            });
        let value = ratio(hits, attempts);
        out.push((
            format!("{name} (found)"),
            hits,
            attempts,
            goal,
            value >= goal,
        ));
        let value = ratio(top, attempts);
        out.push((
            format!("{name} (top-1)"),
            top,
            attempts,
            goal,
            value >= goal,
        ));
    };
    // Groups: same arch (comparison quality), cross arch from one sample (the
    // goal), merged (two samples), and merged held out (an architecture
    // neither sample came from: the honest cross-arch number for merging).
    let same_arch = |c: &RecallCell| !c.arch.contains("->");
    let cross_arch = |c: &RecallCell| c.arch.contains("->") && !c.arch.starts_with(MERGED);
    let merged = |c: &RecallCell| c.arch.starts_with(MERGED);
    let held_out = |c: &RecallCell| {
        c.arch.starts_with(MERGED)
            && !MERGE_ARCHES
                .iter()
                .any(|arch| c.arch == format!("{MERGED}->{arch}"))
    };
    // (same build, other compiler, other level) goals per group.
    let groups: [(&str, CellFilter<'_>, [f64; 3]); 4] = [
        ("same arch", &same_arch, [0.95, 0.55, 0.45]),
        ("cross arch, one sample", &cross_arch, [0.60, 0.45, 0.35]),
        ("merged", &merged, [0.80, 0.55, 0.45]),
        ("merged, held-out arch", &held_out, [0.70, 0.50, 0.40]),
    ];
    for discovery in [HINTED, HINT_FREE] {
        for (group, filter, [same_goal, compiler_goal, level_goal]) in &groups {
            rate(
                &format!("{group}, same opt, {discovery}"),
                &|c| c.discovery == discovery && filter(c) && c.source_opt == c.target_opt,
                *same_goal,
            );
            // Present only on corpora built by several compilers.
            if report.recall.iter().any(other_compiler) {
                rate(
                    &format!("{group}, other compiler same level, {discovery}"),
                    &|c| c.discovery == discovery && filter(c) && other_compiler(c),
                    *compiler_goal,
                );
            }
            rate(
                &format!("{group}, cross opt, {discovery}"),
                &|c| {
                    c.discovery == discovery
                        && filter(c)
                        && level(&c.source_opt) != level(&c.target_opt)
                },
                *level_goal,
            );
        }
    }
    // False-positive ceilings (G3). The any-verdict hinted rates have no
    // v1.0 goal of their own; they are shown against the hint-free ceiling.
    for (label, cells, ceiling) in [
        ("strong FP rate (corpus)", &report.false_positives, 0.01),
        (
            "strong FP rate (negative)",
            &report.negative_false_positives,
            0.0,
        ),
        (
            "any-verdict FP rate (corpus)",
            &report.any_false_positives,
            0.05,
        ),
        (
            "any-verdict FP rate (negative)",
            &report.any_negative_false_positives,
            0.0,
        ),
        (
            "hint-free FP rate (any verdict)",
            &report.hint_free_false_positives,
            0.05,
        ),
    ] {
        let (with, total) = cells.iter().fold((0, 0), |(w, t), c| {
            (w + c.signatures_with_hits, t + c.signatures)
        });
        let value = ratio(with, total);
        out.push((label.to_string(), with, total, ceiling, value <= ceiling));
    }
    for cell in &report.identified {
        let value = cell.precision();
        out.push((
            format!("identified precision, {}", cell.discovery),
            cell.correct,
            cell.answers + cell.unrelated_answers,
            0.98,
            value >= 0.98,
        ));
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
    if let Some(seed) = report.sample_seed {
        let _ = writeln!(text, "sample seed: {seed}");
    }
    for (arch, counts) in &report.verdicts {
        let line: Vec<String> = counts.iter().map(|(v, n)| format!("{v}={n}")).collect();
        let _ = writeln!(text, "  {arch}: {}", line.join(" "));
    }
    for discovery in [HINTED, HINT_FREE] {
        let note = match (discovery, report.hint_free_stripped) {
            (HINT_FREE, true) => " on strip --strip-all targets",
            (HINT_FREE, false) => " (WARNING: targets not stripped; .symtab names leak)",
            _ => "",
        };
        let _ = writeln!(text, "\nrecall ({discovery}{note})");
        let (mut same, mut cross) = ((0, 0), (0, 0));
        for cell in report.recall.iter().filter(|c| c.discovery == discovery) {
            let same_build = cell.source_opt == cell.target_opt;
            let _ = writeln!(
                text,
                "  {} {}->{}: {}  top-1 {}{}",
                cell.arch,
                cell.source_opt,
                cell.target_opt,
                rate_text(cell.hits, cell.attempts),
                rate_text(cell.top_hits, cell.attempts),
                if same_build { "  (same build)" } else { "" }
            );
            let bucket = if same_build { &mut same } else { &mut cross };
            bucket.0 += cell.hits;
            bucket.1 += cell.attempts;
        }
        let _ = writeln!(
            text,
            "  total same build: {}\n  total cross build: {}",
            rate_text(same.0, same.1),
            rate_text(cross.0, cross.1)
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
        (
            "false positives (hint-free, any verdict, unrelated + negative)",
            &report.hint_free_false_positives,
        ),
    ] {
        let _ = writeln!(text, "\n{label}");
        for cell in cells {
            let _ = writeln!(
                text,
                // KiB, not MiB: toy-corpus images are a few KiB each.
                "  {}: {}, total hits {}, {} targets ({} KiB)",
                cell.arch,
                rate_text(cell.signatures_with_hits, cell.signatures),
                cell.hits,
                cell.targets,
                cell.target_bytes.div_ceil(1024)
            );
        }
    }
    if !report.identified.is_empty() {
        let _ = writeln!(
            text,
            "\nidentified top-1 answers (precision: correct / all identified; \
             abstention: images without the function)"
        );
    }
    for cell in &report.identified {
        let _ = writeln!(
            text,
            "  {}: precision {} ({} wrong where the function is, {} where it is not); \
             abstention {}",
            cell.discovery,
            rate_text(cell.correct, cell.answers + cell.unrelated_answers),
            cell.answers - cell.correct,
            cell.unrelated_answers,
            rate_text(
                cell.unrelated_scans - cell.unrelated_answers,
                cell.unrelated_scans
            )
        );
    }
    for discovery in [HINTED, HINT_FREE] {
        let cells: Vec<&LibraryRecallCell> = report
            .library_recall
            .iter()
            .filter(|c| c.discovery == discovery)
            .collect();
        if cells.is_empty() {
            continue;
        }
        let _ = writeln!(
            text,
            "\ntop-1 recall per library ({discovery}, G1 rows; gated at >= {MIN_LIBRARY_ATTEMPTS} attempts)"
        );
        for cell in cells {
            let _ = writeln!(
                text,
                "  {} / {}: {}",
                cell.library,
                cell.row,
                rate_text(cell.top_hits, cell.attempts)
            );
        }
    }
    let _ = writeln!(text, "\nv1.0 goals (PLAN.md §2)");
    for (name, successes, n, goal, met) in targets(report) {
        let _ = writeln!(
            text,
            "  [{}] {name}: {} (target {}{goal:.2})",
            if met { "met" } else { "   " },
            rate_text(successes, n),
            if name.contains("FP rate") { "<=" } else { ">=" }
        );
    }
    if !report.joint.is_empty() {
        let _ = writeln!(
            text,
            "\njoint resolution (whole {} {} module, hint-free, top-1: alone -> joint)",
            JOINT_SOURCE.0, JOINT_SOURCE.1
        );
        let mut groups: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
        for cell in &report.joint {
            let same_arch = cell
                .arch
                .split_once("->")
                .is_some_and(|(from, to)| from == to);
            let level = |opt: &str| opt.split('-').nth(1).unwrap_or(opt).to_string();
            let group = match (
                same_arch,
                cell.source_opt == cell.target_opt,
                level(&cell.source_opt) == level(&cell.target_opt),
            ) {
                (true, _, true) => "same arch, other compiler same level",
                (true, _, false) => "same arch, cross opt",
                (false, true, _) => "cross arch, same build",
                (false, false, true) => "cross arch, other compiler same level",
                (false, false, false) => "cross arch, cross opt",
            };
            let entry = groups.entry(group).or_default();
            entry.0 += cell.attempts;
            entry.1 += cell.independent_top;
            entry.2 += cell.joint_top;
        }
        for (group, (attempts, alone, joint)) in groups {
            let _ = writeln!(
                text,
                "  {group}: {} -> {}",
                rate_text(alone, attempts),
                rate_text(joint, attempts)
            );
        }
        for cell in &report.joint_false_positives {
            let _ = writeln!(
                text,
                "  {} signatures hitting other libraries: {} -> {}",
                cell.library,
                rate_text(cell.independent_with_hits, cell.signatures),
                rate_text(cell.joint_with_hits, cell.signatures)
            );
        }
    }
    if let Some(cost) = &report.cost {
        let memory = |bytes: Option<u64>| {
            bytes.map_or("n/a".to_string(), |bytes| {
                format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
            })
        };
        let _ = writeln!(
            text,
            "\ncost (G5, informational, not gated; {} threads): total {:.1} s, peak memory {}",
            cost.threads,
            cost.total_millis as f64 / 1000.0,
            memory(cost.peak_memory_bytes)
        );
        for phase in &cost.phases {
            let _ = writeln!(
                text,
                "  {}: {:.1} s, peak so far {}",
                phase.phase,
                phase.millis as f64 / 1000.0,
                memory(phase.peak_memory_bytes)
            );
        }
    }
    text
}

/// Per-phase wall time and peak memory, also printed on stderr with
/// `SIGTOOL_BENCH_PROGRESS` set.
struct Phases {
    clock: std::time::Instant,
    last: std::time::Duration,
    phases: Vec<PhaseCost>,
}

impl Phases {
    fn start() -> Phases {
        Phases {
            clock: std::time::Instant::now(),
            last: std::time::Duration::ZERO,
            phases: Vec::new(),
        }
    }

    fn done(&mut self, phase: &str) {
        let now = self.clock.elapsed();
        if std::env::var_os("SIGTOOL_BENCH_PROGRESS").is_some() {
            eprintln!("bench: {phase} done at {now:.1?}");
        }
        self.phases.push(PhaseCost {
            phase: phase.to_string(),
            millis: millis(now - self.last),
            peak_memory_bytes: crate::memory::peak_memory_bytes(),
        });
        self.last = now;
    }

    fn finish(self) -> Cost {
        Cost {
            threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            phases: self.phases,
            total_millis: millis(self.clock.elapsed()),
            peak_memory_bytes: crate::memory::peak_memory_bytes(),
        }
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Default corpus location relative to the repository root.
pub fn default_corpus(repo_root: &Path) -> PathBuf {
    repo_root.join("corpus").join("build")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed toy baseline with the M8 keys removed, as a baseline
    /// saved before M8 loads.
    fn old_baseline() -> BenchReport {
        let mut baseline: BenchReport =
            serde_json::from_str(include_str!("../../tests/baseline/native-bench.json"))
                .expect("baseline loads");
        baseline.identified.clear();
        baseline.library_recall.clear();
        baseline.cost = None;
        // A run compared against it scanned targets in every FP cell.
        for cell in fp_cells(&mut baseline) {
            cell.targets = 1;
        }
        baseline
    }

    fn fp_cells(report: &mut BenchReport) -> impl Iterator<Item = &mut FalsePositiveCell> {
        [
            &mut report.false_positives,
            &mut report.negative_false_positives,
            &mut report.any_false_positives,
            &mut report.any_negative_false_positives,
            &mut report.hint_free_false_positives,
        ]
        .into_iter()
        .flatten()
    }

    #[test]
    fn baselines_without_target_counts_load() {
        let mut baseline: BenchReport =
            serde_json::from_str(include_str!("../../tests/baseline/native-real-bench.json"))
                .expect("baseline loads");
        assert!(fp_cells(&mut baseline).all(|cell| cell.targets == 0));
    }

    #[test]
    fn empty_false_positive_cells_fail() {
        let baseline = old_baseline();
        let mut current = baseline.clone();
        // A zero rate from a cell that scanned nothing is not a measurement.
        current.negative_false_positives[0].targets = 0;
        let failures = compare(&baseline, &current, DEFAULT_TOLERANCE);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("scanned 0 targets"), "{failures:?}");
    }

    fn answers(discovery: &str, correct: usize, unrelated_answers: usize) -> IdentifiedCell {
        IdentifiedCell {
            discovery: discovery.to_string(),
            answers: 100,
            correct,
            unrelated_scans: 100,
            unrelated_answers,
        }
    }

    fn joint(library: &str, joint_top: usize) -> JointCell {
        JointCell {
            library: library.to_string(),
            arch: "x64->arm64".to_string(),
            source_opt: "clang-O2".to_string(),
            target_opt: "gcc-O2".to_string(),
            attempts: 100,
            independent_top: 0,
            joint_top,
        }
    }

    #[test]
    fn joint_cells_repeating_a_key_compare_per_library() {
        let mut baseline = old_baseline();
        baseline.joint = vec![joint("lua", 20), joint("zlib", 80)];
        let mut current = baseline.clone();
        assert!(compare(&baseline, &current, DEFAULT_TOLERANCE).is_empty());
        // A baseline saved before `library` was recorded matches by order.
        let mut unlabelled = baseline.clone();
        unlabelled.joint = vec![joint("", 20), joint("", 80)];
        assert!(compare(&unlabelled, &current, DEFAULT_TOLERANCE).is_empty());
        current.joint[1].joint_top = 60;
        assert_eq!(compare(&baseline, &current, DEFAULT_TOLERANCE).len(), 1);
        assert_eq!(compare(&unlabelled, &current, DEFAULT_TOLERANCE).len(), 1);
    }

    #[test]
    fn missing_identified_cells_are_not_compared() {
        let baseline = old_baseline();
        assert!(baseline.identified.is_empty());
        let mut current = baseline.clone();
        current.identified = vec![answers(HINT_FREE, 10, 90)];
        assert!(compare(&baseline, &current, DEFAULT_TOLERANCE).is_empty());
    }

    #[test]
    fn identified_precision_and_abstention_are_gated() {
        let mut baseline = old_baseline();
        baseline.identified = vec![answers(HINT_FREE, 100, 0)];
        let mut current = baseline.clone();
        current.identified = vec![answers(HINT_FREE, 90, 20)];
        let failures = compare(&baseline, &current, DEFAULT_TOLERANCE);
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].starts_with("identified precision hint-free"));
        assert!(failures[1].starts_with("abstention hint-free"));
    }

    fn library(row: &str, top_hits: usize, attempts: usize) -> LibraryRecallCell {
        LibraryRecallCell {
            library: "zlib".to_string(),
            discovery: HINT_FREE.to_string(),
            row: row.to_string(),
            top_hits,
            attempts,
        }
    }

    #[test]
    fn library_cells_are_gated_only_when_large_enough() {
        let mut baseline = old_baseline();
        assert!(baseline.library_recall.is_empty());
        let mut current = baseline.clone();
        current.library_recall = vec![library("small", 0, 19)];
        assert!(compare(&baseline, &current, DEFAULT_TOLERANCE).is_empty());

        baseline.library_recall = vec![library("small", 19, 19), library("large", 20, 20)];
        current.library_recall = vec![library("small", 0, 19), library("large", 19, 20)];
        assert!(compare(&baseline, &current, DEFAULT_TOLERANCE).is_empty());
        current.library_recall[1].top_hits = 18;
        let failures = compare(&baseline, &current, DEFAULT_TOLERANCE);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].starts_with("library top-1 recall"));
    }

    #[test]
    fn wilson_intervals_match_hand_computed_values() {
        // Worked by hand from Wilson (1927): at 0/n the upper bound is
        // z^2 / (n + z^2), which a normal-approximation interval would give as 0.
        let close = |(low, high): (f64, f64), want: (f64, f64)| {
            (low - want.0).abs() < 5e-4 && (high - want.1).abs() < 5e-4
        };
        assert!(close(wilson(0, 10), (0.0, 0.2775)));
        assert!(close(wilson(5, 10), (0.2366, 0.7634)));
        assert!(close(wilson(10, 10), (0.7225, 1.0)));
        assert_eq!(wilson(0, 0), (0.0, 1.0));
        assert_eq!(rate_text(5, 10), "5/10 = 0.500 [0.237, 0.763]");
    }

    #[test]
    fn sample_seed_changes_only_the_ranking() {
        let functions: BTreeMap<String, u64> = (0..64u64)
            .map(|index| (format!("function_{index}"), index))
            .collect();
        let unseeded = limit_functions(functions.clone(), 8, None);
        // No seed: the name-only CRC ranking every saved baseline used.
        let mut by_name: Vec<&String> = functions.keys().collect();
        by_name.sort_by_key(|name| (crc32fast::hash(name.as_bytes()), *name));
        let expected: BTreeSet<&String> = by_name.into_iter().take(8).collect();
        assert_eq!(unseeded.keys().collect::<BTreeSet<_>>(), expected);
        let seeded = limit_functions(functions.clone(), 8, Some(7));
        assert_eq!(seeded.len(), 8);
        assert_ne!(seeded, unseeded);
        assert_eq!(seeded, limit_functions(functions.clone(), 8, Some(7)));
        assert_ne!(seeded, limit_functions(functions, 8, Some(8)));
    }

    #[test]
    fn compiler_comes_from_the_build_directory() {
        assert_eq!(compiler("gcc-O2"), "gcc");
        assert_eq!(compiler("clang-Os"), "clang");
        assert_eq!(compiler("O0"), "clang");
    }

    #[test]
    fn g1_rows_follow_the_plan() {
        assert_eq!(
            g1_row("x64", "clang-O2", "clang-O2"),
            Some("same arch, same build")
        );
        assert_eq!(
            g1_row("x64->arm64", "clang-O2", "gcc-O2"),
            Some("other arch, other compiler")
        );
        assert_eq!(
            g1_row("merged->arm32", "O2", "O2"),
            Some("merged x64+arm64, held-out arch, same level")
        );
        assert_eq!(g1_row("merged->x64", "O2", "O2"), None);
    }

    #[test]
    fn cost_is_never_compared() {
        let cost = |millis: u64, bytes: u64| Cost {
            threads: 8,
            phases: vec![PhaseCost {
                phase: "load".to_string(),
                millis,
                peak_memory_bytes: Some(bytes),
            }],
            total_millis: millis,
            peak_memory_bytes: Some(bytes),
        };
        let mut baseline = old_baseline();
        assert!(baseline.cost.is_none());
        baseline.cost = Some(cost(1, 1));
        let mut current = baseline.clone();
        current.cost = Some(cost(1_000_000, 1 << 40));
        assert!(compare(&baseline, &current, DEFAULT_TOLERANCE).is_empty());
    }
}
