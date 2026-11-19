//! Command-line front-end for the native scanner.
//!
//! The CLI is thin by contract (AGENTS.md rule 2): it opens a [`FileSource`]
//! (`--file`) or a read-only [`ProcessSource`] (`--pid`, Windows only),
//! calls [`sigtool_native::generate::generate`], the reference matcher, or the
//! scanner, and formats results. No feature, scoring, matching, or serialisation
//! logic lives here.
//!
//! ```text
//! sigtool-native gen --file image.elf --addr 0x1000
//! sigtool-native gen --file image.elf --module image.elf --rva 0x1000
//! sigtool-native gen --pid 4242 --module target --rva 0x1a2b0
//! sigtool-native locate --signature fn.yaml --pid 4242
//! sigtool-native locate --signature fn.yaml --file other.so --json matches.json
//! sigtool-native scan --file image.elf --signature fn.yaml --signature other.yaml
//! sigtool-native scan --file image.elf --db signatures.db
//! sigtool-native merge --sample a.elf:0x1000 --sample b.elf:0x2c40 --name fn
//! sigtool-native db build --signature fn.yaml --output signatures.db
//! sigtool-native db build --file image.elf --functions names.json --output signatures.db
//! ```
//!
//! The signature YAML goes to stdout (or `--output`) so it can be piped; the
//! quality report goes to stderr.
//!
//! Exit codes:
//!
//! * `0` success
//! * `1` locate/scan found no accepted match
//! * `2` usage or input error (missing file, bad address, unmapped address, ...)
//! * `3` unsupported target architecture or mode
//! * `4` self-test failed, so no signature was emitted (AGENTS.md rule 7)

use std::collections::{BTreeMap, BTreeSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde_json::Value;

use sigtool_native::coverage::Coverage;
use sigtool_native::db::{DbView, MappedDb, SignatureDb};
use sigtool_native::elf::FileSource;
use sigtool_native::errors::{DecodeError, SourceFormatError};
use sigtool_native::generate::{generate_in, GenerateError, GenerationResult};
use sigtool_native::matcher::{
    evidence, hinted_floors, scan, scan_in, Match, ScanContext, DEFAULT_MAX_RECOVERIES,
};
use sigtool_native::merge::{merge_in, MergeSample};
use sigtool_native::proc_win::{ProcessError, ProcessSource};
use sigtool_native::scanner::{ScanHit, SignatureScanner};
use sigtool_native::sigfile::Signature;
use sigtool_native::source::{ByteSource, Module};

const EXIT_OK: u8 = 0;
const EXIT_NOT_FOUND: u8 = 1;
const EXIT_ERROR: u8 = 2;
const EXIT_UNSUPPORTED: u8 = 3;
const EXIT_SELF_TEST: u8 = 4;

#[derive(Parser)]
#[command(
    name = "sigtool-native",
    about = "Native scanner for sigtool feature signatures",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signature for one function
    Gen(GenArgs),
    /// Find a signature's function in an image
    Locate(LocateArgs),
    /// Match one or more signatures (or a DB) against an image
    Scan(ScanArgs),
    /// Merge samples of one function into one signature
    Merge(MergeArgs),
    /// Build and inspect signature databases
    Db(DbArgs),
    /// Measure corpus recall and false positives; gate against a baseline
    Bench(BenchArgs),
}

#[derive(Args)]
struct GenArgs {
    /// ELF or PE image
    #[arg(
        long,
        value_name = "IMAGE",
        required_unless_present = "pid",
        conflicts_with = "pid"
    )]
    file: Option<PathBuf>,
    /// Live Windows process to read (read-only)
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
    /// Absolute address, e.g. 0x1000
    #[arg(long, value_name = "ADDR", conflicts_with = "rva")]
    addr: Option<String>,
    /// Module-relative address
    #[arg(long, value_name = "RVA", conflicts_with = "addr")]
    rva: Option<String>,
    /// Module name for --rva (optional when the image has one module)
    #[arg(long, value_name = "NAME")]
    module: Option<String>,
    /// Signature name (default: symbol or module+rva)
    #[arg(long)]
    name: Option<String>,
    /// Provenance only: optimization level, e.g. O2
    #[arg(long)]
    opt: Option<String>,
    /// Provenance only: compiler or tool name
    #[arg(long)]
    tool: Option<String>,
    /// Write signature YAML here instead of stdout
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Write the quality report as JSON
    #[arg(long = "json-report", value_name = "FILE")]
    json_report: Option<PathBuf>,
}

#[derive(Args)]
struct LocateArgs {
    /// Signature YAML file
    #[arg(long, value_name = "FILE")]
    signature: PathBuf,
    /// ELF or PE image to scan
    #[arg(
        long,
        value_name = "IMAGE",
        required_unless_present = "pid",
        conflicts_with = "pid"
    )]
    file: Option<PathBuf>,
    /// Live Windows process to scan (read-only)
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
    /// Write the match list as JSON
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// Do not prompt for confirmation of the best match
    #[arg(long)]
    yes: bool,
    /// Discovery mode: `hinted` uses the image's symbols and function bounds;
    /// `hint-free` uses only what survives stripping (unwind tables, dynamic
    /// symbols, relocations, code); `auto` picks hint-free for image files
    /// without `.symtab` function symbols (stripped ELF, PE)
    #[arg(long, default_value = "auto", value_parser = ["auto", "hinted", "hint-free"])]
    discovery: String,
}

#[derive(Args)]
struct ScanArgs {
    /// ELF or PE image to scan
    #[arg(
        long,
        value_name = "IMAGE",
        required_unless_present = "pid",
        conflicts_with = "pid"
    )]
    file: Option<PathBuf>,
    /// Live Windows process to scan (read-only)
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
    /// Signature YAML file (repeatable)
    #[arg(long, value_name = "FILE")]
    signature: Vec<PathBuf>,
    /// Signature database built by `db build`
    #[arg(long, value_name = "DB", conflicts_with = "signature")]
    db: Option<PathBuf>,
    /// Write the hit list as JSON
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// Discovery mode: `hinted` uses the image's symbols and function bounds;
    /// `hint-free` uses only what survives stripping (unwind tables, dynamic
    /// symbols, relocations, code); `auto` picks hint-free for image files
    /// without `.symtab` function symbols (stripped ELF, PE)
    #[arg(long, default_value = "auto", value_parser = ["auto", "hinted", "hint-free"])]
    discovery: String,
}

#[derive(Args)]
struct MergeArgs {
    /// One sample: FILE:ADDR (absolute) or FILE:+RVA (from the image base); repeatable, at least two
    #[arg(long = "sample", value_name = "FILE:ADDR", required = true)]
    sample: Vec<String>,
    /// Signature name (default: the first sample's symbol)
    #[arg(long)]
    name: Option<String>,
    /// Write signature YAML here instead of stdout
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Write the quality report as JSON
    #[arg(long = "json-report", value_name = "FILE")]
    json_report: Option<PathBuf>,
}

#[derive(Args)]
struct DbArgs {
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Subcommand)]
enum DbCommand {
    /// Build a deterministic binary DB from signature YAML files
    Build(DbBuildArgs),
}

#[derive(Args)]
struct DbBuildArgs {
    /// Signature YAML file (repeatable)
    #[arg(long, value_name = "FILE", required_unless_present = "functions")]
    signature: Vec<PathBuf>,
    /// ELF or PE image whose --functions are signed into the DB
    #[arg(long, value_name = "IMAGE", requires = "functions")]
    file: Option<PathBuf>,
    /// JSON list of functions to sign in --file, each as `gen --rva` would:
    /// `[{"rva": "0x1130", "name": "top"}, ...]` (`name` optional)
    #[arg(long, value_name = "FILE", requires = "file")]
    functions: Option<PathBuf>,
    /// Provenance only, for --functions: compiler or tool name
    #[arg(long, requires = "functions")]
    tool: Option<String>,
    /// Write what happened to each of --functions as JSON
    #[arg(long, value_name = "FILE", requires = "functions")]
    report: Option<PathBuf>,
    /// Output database path
    #[arg(long, value_name = "DB")]
    output: PathBuf,
}

#[derive(Args)]
struct BenchArgs {
    /// Corpus directory holding ground_truth.json
    #[arg(long, value_name = "DIR", default_value = "../corpus/build")]
    corpus: PathBuf,
    /// Limit to one architecture (repeatable): x64, arm64, arm32, thumb
    #[arg(long)]
    arch: Vec<String>,
    /// Fail when recall drops or false positives rise beyond --tolerance
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Write the metrics as a new baseline (review the diff)
    #[arg(long = "save-baseline", value_name = "FILE")]
    save_baseline: Option<PathBuf>,
    /// Keep at most N ground-truth functions per binary (0 = all)
    #[arg(long = "max-functions", default_value_t = 0)]
    max_functions: usize,
    /// With --max-functions, pick functions by CRC-32 of this seed and the
    /// name instead of the name alone (a fresh sample for milestone exits)
    #[arg(long = "sample-seed", value_name = "N")]
    sample_seed: Option<u64>,
    /// Only one discovery mode: hinted or hint-free
    #[arg(long, value_parser = ["hinted", "hint-free"])]
    discovery: Option<String>,
    /// Skip the false-positive scans (recall-only iteration)
    #[arg(long = "no-fp")]
    no_fp: bool,
    /// Write each hint-free false-positive hit as a JSON line to this file;
    /// hinted hits go to `<file>.hinted`, recall scans to `<file>.recall` and
    /// `<file>.recall-hinted`
    #[arg(long = "fp-report")]
    fp_report: Option<PathBuf>,
    /// Also measure joint resolution of whole-module signature sets (slow)
    #[arg(long)]
    joint: bool,
    /// With --joint, write what joint resolution saw per joint scan as JSON
    /// lines to this file (offline simulation of assignment rules)
    #[arg(long = "joint-report", requires = "joint")]
    joint_report: Option<PathBuf>,
    /// Allowed recall drop / false-positive increase
    #[arg(long, default_value_t = sigtool_native::bench::DEFAULT_TOLERANCE)]
    tolerance: f64,
}

/// A front-end input problem with the exit code it maps to.
#[derive(Debug)]
struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn input(message: impl Into<String>) -> CliError {
        CliError {
            code: EXIT_ERROR,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> CliError {
        CliError {
            code: EXIT_UNSUPPORTED,
            message: message.into(),
        }
    }

    fn self_test(message: impl Into<String>) -> CliError {
        CliError {
            code: EXIT_SELF_TEST,
            message: message.into(),
        }
    }
}

/// `--version` names the spec version too: a front-end shipped beside the
/// binary (the IDA plugin) checks it to warn about a stale or mismatched copy.
fn version_line() -> String {
    format!(
        "{} (spec {})",
        env!("CARGO_PKG_VERSION"),
        sigtool_native::spec::SPEC_VERSION
    )
}

fn main() -> ExitCode {
    // The version string is built at runtime, so clap gets it here rather
    // than from the derive attribute.
    let version: &'static str = Box::leak(version_line().into_boxed_str());
    let matches = Cli::command().version(version).get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let result = match cli.command {
        Command::Gen(args) => run_gen(args),
        Command::Locate(args) => run_locate(args),
        Command::Scan(args) => run_scan(args),
        Command::Merge(args) => run_merge(args),
        Command::Db(args) => run_db(args),
        Command::Bench(args) => run_bench(args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("sigtool-native: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}

// -- gen ---------------------------------------------------------------------

fn run_gen(args: GenArgs) -> Result<u8, CliError> {
    let target = load_target(args.file.as_deref(), args.pid)?;
    let source = target.as_ref();
    let addr = resolve_address(
        source,
        args.addr.as_deref(),
        args.rva.as_deref(),
        args.module.as_deref(),
    )?;
    // The image's call graph gives the signature its neighbour keys. A live
    // process is not indexed: the code index would decode every loaded DLL,
    // so `gen --pid` runs no budgeted pass and always reports `[]`.
    let context = args.file.is_some().then(|| ScanContext::build(source));
    let result = generate_in(
        source,
        addr,
        args.name.as_deref(),
        args.opt.as_deref(),
        args.tool.as_deref(),
        None,
        None,
        context.as_ref(),
    )
    .map_err(classify_generate_error)?;
    let mut coverage = Coverage::new();
    if let Some(context) = &context {
        coverage.add_context(context);
    }
    let arch = source.arch().as_str().to_string();
    let label = source
        .label_for_address(result.matched.address)
        .unwrap_or_else(|| format!("0x{:x}", result.matched.address));
    write_outputs(
        &result,
        &arch,
        &label,
        args.output.as_deref(),
        args.json_report.as_deref(),
        &coverage,
    )?;
    Ok(EXIT_OK)
}

fn classify_generate_error(error: GenerateError) -> CliError {
    match error {
        GenerateError::SelfTest(error) => CliError::self_test(format!(
            "self-test failed, refusing to emit a signature: {error}"
        )),
        GenerateError::Decode(DecodeError(message)) => {
            if message.contains("not supported") || message.contains("only x86-64") {
                CliError::unsupported(format!("unsupported target: {message}"))
            } else {
                CliError::input(message)
            }
        }
        GenerateError::Signature(error) => CliError::input(error.to_string()),
    }
}

fn write_outputs(
    result: &GenerationResult,
    arch: &str,
    label: &str,
    output: Option<&Path>,
    json_report: Option<&Path>,
    coverage: &Coverage,
) -> Result<(), CliError> {
    let text = result
        .to_yaml()
        .map_err(|error| CliError::input(error.to_string()))?;
    let destination = match output {
        None => {
            print!("{text}");
            "stdout".to_string()
        }
        Some(path) => {
            std::fs::write(path, text.as_bytes()).map_err(|error| {
                CliError::input(format!("cannot write {}: {error}", path.display()))
            })?;
            path.display().to_string()
        }
    };

    eprintln!("{}", report_text(result, &destination, arch, label));
    warn_coverage(coverage);

    if let Some(path) = json_report {
        let mut document = report_document(result, arch, label);
        document.insert("truncated".to_string(), coverage_value(coverage));
        write_json(path, &document)?;
    }
    Ok(())
}

fn report_text(result: &GenerationResult, destination: &str, arch: &str, label: &str) -> String {
    let signature = &result.signature;
    let report = &result.report;
    let mut lines = vec![
        format!(
            "signature {}  ({})",
            signature.name,
            signature.signature_id().unwrap_or_default()
        ),
        format!(
            "arch {arch}  verdict {}  confidence {}",
            report.verdict, signature.confidence
        ),
        format!(
            "features {} (required {}, optional {})  anchors {}  evidence {:.3}",
            signature.features.len(),
            report.required_features,
            report.optional_features,
            report.anchor_count,
            report.evidence
        ),
        format!(
            "self-test {}  score {:.3}  matched {}",
            label,
            result.matched.score,
            result.matched.matched.len()
        ),
        format!("yaml {destination}"),
    ];
    if !report.notes.is_empty() {
        lines.push("notes:".to_string());
        lines.extend(report.notes.iter().map(|note| format!("  - {note}")));
    }
    lines.join("\n")
}

fn report_document(result: &GenerationResult, arch: &str, label: &str) -> BTreeMap<String, Value> {
    let signature = &result.signature;
    let report = &result.report;
    let mut self_test = BTreeMap::new();
    self_test.insert("at".to_string(), Value::String(label.to_string()));
    self_test.insert("score".to_string(), json_number(result.matched.score));
    self_test.insert(
        "matched".to_string(),
        Value::Number(result.matched.matched.len().into()),
    );

    let mut document: BTreeMap<String, Value> = BTreeMap::new();
    document.insert(
        "signature_id".to_string(),
        Value::String(signature.signature_id().unwrap_or_default()),
    );
    document.insert("name".to_string(), Value::String(signature.name.clone()));
    document.insert("arch".to_string(), Value::String(arch.to_string()));
    document.insert("verdict".to_string(), Value::String(report.verdict.clone()));
    document.insert(
        "confidence".to_string(),
        Value::String(signature.confidence.clone()),
    );
    document.insert(
        "features".to_string(),
        Value::Number(signature.features.len().into()),
    );
    document.insert(
        "required_features".to_string(),
        Value::Number(report.required_features.into()),
    );
    document.insert(
        "optional_features".to_string(),
        Value::Number(report.optional_features.into()),
    );
    document.insert(
        "anchors".to_string(),
        Value::Number(report.anchor_count.into()),
    );
    document.insert("evidence".to_string(), json_number(round6(report.evidence)));
    document.insert(
        "self_test".to_string(),
        Value::Object(self_test.into_iter().collect()),
    );
    document.insert(
        "notes".to_string(),
        Value::Array(report.notes.iter().cloned().map(Value::String).collect()),
    );
    document
}

// -- merge -------------------------------------------------------------------

fn run_merge(args: MergeArgs) -> Result<u8, CliError> {
    if args.sample.len() < 2 {
        return Err(CliError::input(
            "merging needs at least two --sample arguments",
        ));
    }
    let mut sources: Vec<FileSource> = Vec::new();
    let mut addresses: Vec<u64> = Vec::new();
    for text in &args.sample {
        // Split on the last colon so Windows drive paths keep working.
        let Some((path, addr_text)) = text.rsplit_once(':') else {
            return Err(CliError::input(format!(
                "--sample expects FILE:ADDR, got {text:?}"
            )));
        };
        let source = load_file(Path::new(path))?;
        // `FILE:+RVA` is relative to the image base, the form a disassembler
        // with a rebased database can always supply.
        let addr = match addr_text.strip_prefix('+') {
            Some(rva_text) => {
                let rva = parse_address(rva_text, "--sample")?;
                let Some(module) = source.modules().first() else {
                    return Err(CliError::input(format!("{path} has no module")));
                };
                module.image_base.wrapping_add(rva)
            }
            None => parse_address(addr_text, "--sample")?,
        };
        if !source.is_mapped(addr, 1) {
            return Err(CliError::input(format!(
                "address 0x{addr:x} is not mapped in {path}"
            )));
        }
        sources.push(source);
        addresses.push(addr);
    }
    let samples: Vec<MergeSample<'_>> = sources
        .iter()
        .zip(addresses.iter())
        .map(|(source, addr)| MergeSample {
            source,
            addr: *addr,
            opt: None,
            tool: None,
        })
        .collect();
    // The Python front-end reports a merge refusal as an input error (exit 2):
    // the samples cannot be combined into one honest signature.
    let contexts: Vec<ScanContext> = sources.iter().map(ScanContext::build).collect();
    let context_refs: Vec<Option<&ScanContext>> = contexts.iter().map(Some).collect();
    let result = merge_in(&samples, &context_refs, args.name.as_deref(), None)
        .map_err(|error| CliError::input(format!("refusing to merge: {error}")))?;

    let arches: BTreeSet<&str> = sources
        .iter()
        .map(|source| source.arch().as_str())
        .collect();
    let arch = arches.into_iter().collect::<Vec<&str>>().join("+");
    let label = format!("{} samples", samples.len());
    let mut coverage = Coverage::new();
    for context in &contexts {
        coverage.add_context(context);
    }
    write_outputs(
        &result,
        &arch,
        &label,
        args.output.as_deref(),
        args.json_report.as_deref(),
        &coverage,
    )?;
    Ok(EXIT_OK)
}

// -- locate ------------------------------------------------------------------

fn run_locate(args: LocateArgs) -> Result<u8, CliError> {
    let signature = load_signature(&args.signature)?;
    let target = load_target(args.file.as_deref(), args.pid)?;
    let source = target.as_ref();
    let hints = use_hints(source, &args.discovery);
    eprintln!(
        "sigtool-native: {} discovery",
        if hints { "hinted" } else { "hint-free" }
    );
    // A file is scanned the way the bench measures it, with the image's
    // indexes and every trust floor, in both modes. A live process builds
    // no whole-process index (hundreds of modules); its hinted scan starts
    // from anchor hits and gets the same hinted floors.
    let mut coverage = Coverage::new();
    let matches = if hints && args.pid.is_some() {
        let found = scan(source, &signature, None, 256, true, None);
        hinted_floors(source, &signature, found)
    } else {
        let context = ScanContext::build(source);
        coverage.add_context(&context);
        coverage.add_source(source, hints);
        scan_in(source, &signature, &context, hints)
    };
    warn_coverage(&coverage);

    if let Some(path) = &args.json {
        let mut document = match_document(source, &signature, &matches);
        document.insert("truncated".to_string(), coverage_value(&coverage));
        write_json(path, &document)?;
    }

    if matches.is_empty() {
        eprintln!(
            "sigtool-native: no match for signature {:?} in the target",
            signature.name
        );
        return Ok(EXIT_NOT_FOUND);
    }
    println!(
        "signature {}  ({})  threshold {}",
        signature.name,
        signature.signature_id().unwrap_or_default(),
        signature.match_threshold
    );
    for (index, matched) in matches.iter().enumerate() {
        let where_ = source
            .label_for_address(matched.address)
            .unwrap_or_else(|| "unlabelled".to_string());
        println!(
            "  {}. 0x{:x} score {:.3} {} {}",
            index + 1,
            matched.address,
            matched.score,
            evidence(&matches, index).label(),
            where_
        );
    }
    if !args.yes && std::io::stdin().is_terminal() {
        let label = source
            .label_for_address(matches[0].address)
            .unwrap_or_else(|| format!("0x{:x}", matches[0].address));
        print!(
            "accept match at 0x{:x} ({label})? [y/N] ",
            matches[0].address
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("confirmed 0x{:x}", matches[0].address);
        }
    }
    Ok(EXIT_OK)
}

fn match_document(
    source: &dyn ByteSource,
    signature: &Signature,
    matches: &[Match],
) -> BTreeMap<String, Value> {
    let mut document: BTreeMap<String, Value> = BTreeMap::new();
    document.insert(
        "signature".to_string(),
        Value::String(signature.name.clone()),
    );
    let entries = matches
        .iter()
        .enumerate()
        .map(|(index, matched)| {
            let mut entry: BTreeMap<String, Value> = BTreeMap::new();
            entry.insert(
                "address".to_string(),
                Value::String(format!("0x{:x}", matched.address)),
            );
            entry.insert(
                "end".to_string(),
                Value::String(format!("0x{:x}", matched.end)),
            );
            // Front-ends that load the image at another base (a rebased IDB, a
            // live process) map a match back through module and rva.
            if let Some(module) = source.module_for(matched.address) {
                entry.insert("module".to_string(), Value::String(module.name.clone()));
                entry.insert(
                    "rva".to_string(),
                    Value::String(format!("0x{:x}", module.rva(matched.address))),
                );
            }
            entry.insert("score".to_string(), json_number(matched.score));
            entry.insert(
                "evidence".to_string(),
                Value::String(evidence(matches, index).label().to_string()),
            );
            entry.insert(
                "label".to_string(),
                source
                    .label_for_address(matched.address)
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            entry.insert(
                "matched".to_string(),
                Value::Array(matched.matched.iter().cloned().map(Value::String).collect()),
            );
            Value::Object(entry.into_iter().collect())
        })
        .collect();
    document.insert("matches".to_string(), Value::Array(entries));
    document
}

// -- scan --------------------------------------------------------------------

fn run_scan(args: ScanArgs) -> Result<u8, CliError> {
    let target = load_target(args.file.as_deref(), args.pid)?;
    let source = target.as_ref();
    let signatures = if let Some(db_path) = &args.db {
        load_db_signatures(db_path)?
    } else {
        if args.signature.is_empty() {
            return Err(CliError::input("one of --signature or --db is required"));
        }
        args.signature
            .iter()
            .map(|path| load_signature(path))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut coverage = Coverage::new();
    let hints = use_hints(source, &args.discovery);
    let hits = if hints && args.file.is_some() {
        // Files get the bench's path (see `run_locate`); only a live process
        // uses the incremental scanner.
        indexed_hits(source, &signatures, &mut coverage, true)?
    } else if hints {
        let mut scanner = SignatureScanner::new(source, signatures, None, None)
            .map_err(|error| CliError::input(error.to_string()))?;
        let report = scanner.scan_pass();
        // The scanner's own reference index is not passed to its matcher,
        // so only the recovery budget can drop its matches.
        coverage.add_scan_report(&report, DEFAULT_MAX_RECOVERIES);
        report.hits
    } else {
        indexed_hits(source, &signatures, &mut coverage, false)?
    };
    warn_coverage(&coverage);

    if let Some(path) = &args.json {
        let mut document = scan_document(source, &hits);
        document.insert("truncated".to_string(), coverage_value(&coverage));
        write_json(path, &document)?;
    }
    for hit in &hits {
        let where_ = source
            .label_for_address(hit.address)
            .unwrap_or_else(|| hit.region.clone());
        println!(
            "{}  0x{:x} score {:.3} {} {}",
            hit.name,
            hit.address,
            hit.score,
            hit.evidence.label(),
            where_
        );
    }
    if hits.is_empty() {
        eprintln!("sigtool-native: no accepted matches in the target");
        return Ok(EXIT_NOT_FOUND);
    }
    Ok(EXIT_OK)
}

/// Whether a scan uses the image's symbol hints. `auto` drops them for a
/// stripped image: its dynamic symbols name only exports, and on the stripped
/// real corpus hinted discovery found about half as many functions as
/// hint-free (cross-arch top-1 0.158 vs 0.293).
fn use_hints(source: &dyn ByteSource, discovery: &str) -> bool {
    match discovery {
        "hinted" => true,
        "hint-free" => false,
        _ => !source.symbols_stripped(),
    }
}

/// Every signature against one shared hint-free context, best match first
/// per signature, in signature order. Signatures from one module are then
/// resolved jointly through their call-graph links.
fn indexed_hits(
    source: &dyn ByteSource,
    signatures: &[Signature],
    coverage: &mut Coverage,
    hints: bool,
) -> Result<Vec<ScanHit>, CliError> {
    let context = ScanContext::build(source);
    coverage.add_context(&context);
    coverage.add_source(source, hints);
    // Signatures share only the context's caches, so they scan in parallel;
    // results keep signature order.
    if signatures.len() > 1 {
        context.prepare_frequencies(source, hints);
    }
    let mut all: Vec<Vec<Match>> = sigtool_native::parallel::map(signatures.len(), |index| {
        scan_in(source, &signatures[index], &context, hints)
    });
    // Joint resolution is measured hint-free only (`bench --joint`).
    if !hints {
        sigtool_native::joint::resolve(source, &context, signatures, &mut all, false);
    }
    let mut hits = Vec::new();
    for (signature, matches) in signatures.iter().zip(all) {
        let signature_id = signature
            .signature_id()
            .map_err(|error| CliError::input(error.to_string()))?;
        for (index, matched) in matches.iter().enumerate() {
            hits.push(ScanHit {
                signature_id: signature_id.clone(),
                name: signature.name.clone(),
                address: matched.address,
                end: matched.end,
                score: matched.score,
                region: source
                    .region_for(matched.address)
                    .map(|region| region.name.clone())
                    .unwrap_or_default(),
                first_seen: 0,
                evidence: evidence(&matches, index),
            });
        }
    }
    Ok(hits)
}

fn scan_document(source: &dyn ByteSource, hits: &[ScanHit]) -> BTreeMap<String, Value> {
    let mut document: BTreeMap<String, Value> = BTreeMap::new();
    let entries = hits
        .iter()
        .map(|hit| {
            let mut entry: BTreeMap<String, Value> = BTreeMap::new();
            entry.insert(
                "signature_id".to_string(),
                Value::String(hit.signature_id.clone()),
            );
            entry.insert("name".to_string(), Value::String(hit.name.clone()));
            entry.insert(
                "address".to_string(),
                Value::String(format!("0x{:x}", hit.address)),
            );
            entry.insert("end".to_string(), Value::String(format!("0x{:x}", hit.end)));
            // As in `locate --json`: front-ends with a rebased view of the
            // image (an IDB, a live process) map a hit back through the rva.
            if let Some(module) = source.module_for(hit.address) {
                entry.insert("module".to_string(), Value::String(module.name.clone()));
                entry.insert(
                    "rva".to_string(),
                    Value::String(format!("0x{:x}", module.rva(hit.address))),
                );
            }
            entry.insert("score".to_string(), json_number(hit.score));
            entry.insert(
                "evidence".to_string(),
                Value::String(hit.evidence.label().to_string()),
            );
            entry.insert("region".to_string(), Value::String(hit.region.clone()));
            entry.insert(
                "label".to_string(),
                source
                    .label_for_address(hit.address)
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            entry.insert(
                "first_seen".to_string(),
                Value::Number(hit.first_seen.into()),
            );
            Value::Object(entry.into_iter().collect())
        })
        .collect();
    document.insert("hits".to_string(), Value::Array(entries));
    document
}

// -- db ----------------------------------------------------------------------

fn run_db(args: DbArgs) -> Result<u8, CliError> {
    match args.command {
        DbCommand::Build(build) => run_db_build(build),
    }
}

fn run_db_build(args: DbBuildArgs) -> Result<u8, CliError> {
    let mut db = SignatureDb::new();
    for path in &args.signature {
        let text = std::fs::read_to_string(path)
            .map_err(|error| CliError::input(format!("cannot read {}: {error}", path.display())))?;
        db.push_yaml(&text)
            .map_err(|error| CliError::input(format!("{}: {error}", path.display())))?;
    }
    if let (Some(image), Some(functions)) = (&args.file, &args.functions) {
        let signed = sign_functions(
            image,
            functions,
            args.tool.as_deref(),
            args.report.as_deref(),
        )?;
        for signature in &signed {
            db.push(signature)
                .map_err(|error| CliError::input(error.to_string()))?;
        }
    }
    let bytes = db.encode();
    std::fs::write(&args.output, &bytes).map_err(|error| {
        CliError::input(format!("cannot write {}: {error}", args.output.display()))
    })?;
    eprintln!(
        "wrote {} signatures to {} ({} bytes, spec {})",
        db.len(),
        args.output.display(),
        bytes.len(),
        sigtool_native::spec::SPEC_VERSION
    );
    Ok(EXIT_OK)
}

/// One entry of a `db build --functions` list.
struct FunctionEntry {
    rva: String,
    name: Option<String>,
}

fn load_function_list(path: &Path) -> Result<Vec<FunctionEntry>, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::input(format!("cannot read {}: {error}", path.display())))?;
    let document: Value = serde_json::from_str(&text)
        .map_err(|error| CliError::input(format!("{}: {error}", path.display())))?;
    let Some(items) = document.as_array() else {
        return Err(CliError::input(format!(
            "{}: expected a JSON array of {{\"rva\": ..., \"name\": ...}}",
            path.display()
        )));
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let rva = match item.get("rva") {
                Some(Value::String(text)) => text.clone(),
                Some(Value::Number(number)) if number.is_u64() => {
                    format!("0x{:x}", number.as_u64().unwrap_or_default())
                }
                _ => {
                    return Err(CliError::input(format!(
                        "{}: entry {index} needs an \"rva\" string or integer",
                        path.display()
                    )))
                }
            };
            parse_address(&rva, "rva")?;
            let name = match item.get("name") {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
                Some(_) => {
                    return Err(CliError::input(format!(
                        "{}: entry {index} has a \"name\" that is not a non-empty string",
                        path.display()
                    )))
                }
            };
            Ok(FunctionEntry { rva, name })
        })
        .collect()
}

/// Sign every function of a `--functions` list in one image, as `gen --file
/// IMAGE --rva RVA --name NAME` would, sharing one scan context instead of
/// one process and one image index per function. A function that cannot be
/// signed (self-test refusal, unmapped RVA, undecodable code) is reported and
/// skipped; the build fails only when nothing was signed.
fn sign_functions(
    image: &Path,
    functions: &Path,
    tool: Option<&str>,
    report: Option<&Path>,
) -> Result<Vec<Signature>, CliError> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let entries = load_function_list(functions)?;
    let source = load_file(image)?;
    let context = ScanContext::build(&source);
    // Signing self-tests hinted, so only the context's indexes apply.
    let mut coverage = Coverage::new();
    coverage.add_context(&context);
    let total = entries.len();
    let done = AtomicUsize::new(0);
    // Functions share only the context's caches, so they sign in parallel;
    // results keep list order, so the report and the DB are deterministic.
    let results: Vec<Result<GenerationResult, CliError>> =
        sigtool_native::parallel::map(total, |index| {
            let entry = &entries[index];
            let result = resolve_address(&source, None, Some(&entry.rva), None).and_then(|addr| {
                generate_in(
                    &source,
                    addr,
                    entry.name.as_deref(),
                    None,
                    tool,
                    None,
                    None,
                    Some(&context),
                )
                .map_err(classify_generate_error)
            });
            // Front-ends read these lines to show progress and allow cancel.
            eprintln!(
                "progress {}/{total}",
                done.fetch_add(1, Ordering::Relaxed) + 1
            );
            result
        });

    let mut signed = Vec::new();
    let mut rows = Vec::new();
    for (entry, result) in entries.iter().zip(results) {
        let mut row: BTreeMap<String, Value> = BTreeMap::new();
        row.insert("rva".to_string(), Value::String(entry.rva.clone()));
        row.insert(
            "name".to_string(),
            entry.name.clone().map(Value::String).unwrap_or(Value::Null),
        );
        match result {
            Ok(result) => {
                row.insert("status".to_string(), Value::String("signed".to_string()));
                row.insert(
                    "signature_id".to_string(),
                    Value::String(result.signature.signature_id().unwrap_or_default()),
                );
                row.insert(
                    "verdict".to_string(),
                    Value::String(result.report.verdict.clone()),
                );
                row.insert(
                    "confidence".to_string(),
                    Value::String(result.signature.confidence.clone()),
                );
                signed.push(result.signature);
            }
            Err(error) => {
                let status = match error.code {
                    EXIT_SELF_TEST => "refused",
                    EXIT_UNSUPPORTED => "unsupported",
                    _ => "error",
                };
                eprintln!(
                    "skipped {} {}: {}",
                    entry.rva,
                    entry.name.as_deref().unwrap_or("-"),
                    error.message
                );
                row.insert("status".to_string(), Value::String(status.to_string()));
                row.insert("error".to_string(), Value::String(error.message));
            }
        }
        rows.push(Value::Object(row.into_iter().collect()));
    }
    let failed = total - signed.len();
    if let Some(path) = report {
        let mut document: BTreeMap<String, Value> = BTreeMap::new();
        document.insert("signed".to_string(), Value::Number(signed.len().into()));
        document.insert("failed".to_string(), Value::Number(failed.into()));
        document.insert("functions".to_string(), Value::Array(rows));
        document.insert("truncated".to_string(), coverage_value(&coverage));
        write_json(path, &document)?;
    }
    warn_coverage(&coverage);
    eprintln!(
        "signed {} of {total} functions ({failed} skipped)",
        signed.len()
    );
    if signed.is_empty() && total > 0 {
        return Err(CliError::input(
            "no function in --functions could be signed",
        ));
    }
    Ok(signed)
}

fn load_db_signatures(path: &Path) -> Result<Vec<Signature>, CliError> {
    let mapped = MappedDb::open(path).map_err(|error| CliError::input(error.to_string()))?;
    let view: DbView<'_> = mapped
        .view()
        .map_err(|error| CliError::input(error.to_string()))?;
    view.signatures()
        .map_err(|error| CliError::input(error.to_string()))
}

// -- shared ------------------------------------------------------------------

fn load_file(path: &Path) -> Result<FileSource, CliError> {
    if !path.is_file() {
        return Err(CliError::input(format!(
            "no such image file: {}",
            path.display()
        )));
    }
    FileSource::from_path(path).map_err(classify_source_error)
}

/// Open the `--file` image or the `--pid` process (clap enforces exactly one).
fn load_target(file: Option<&Path>, pid: Option<u32>) -> Result<Box<dyn ByteSource>, CliError> {
    match (file, pid) {
        (Some(path), _) => Ok(Box::new(load_file(path)?)),
        (None, Some(pid)) => ProcessSource::open(pid)
            .map(|source| Box::new(source) as Box<dyn ByteSource>)
            .map_err(|error| match error {
                ProcessError::Unsupported(message) => {
                    CliError::unsupported(format!("unsupported target: {message}"))
                }
                ProcessError::Os(message) => CliError::input(message),
            }),
        (None, None) => Err(CliError::input("one of --file or --pid is required")),
    }
}

fn load_signature(path: &Path) -> Result<Signature, CliError> {
    if !path.is_file() {
        return Err(CliError::input(format!(
            "no such signature file: {}",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::input(format!("cannot read {}: {error}", path.display())))?;
    Signature::from_yaml(&text)
        .map_err(|error| CliError::input(format!("{}: {error}", path.display())))
}

fn classify_source_error(error: SourceFormatError) -> CliError {
    let message = error.to_string();
    if message.contains("not supported") || message.contains("unsupported") {
        CliError::unsupported(format!("unsupported target: {message}"))
    } else {
        CliError::input(message)
    }
}

fn resolve_address(
    source: &dyn ByteSource,
    addr: Option<&str>,
    rva: Option<&str>,
    module_name: Option<&str>,
) -> Result<u64, CliError> {
    if let Some(addr) = addr {
        if module_name.is_some() {
            return Err(CliError::input("--module applies to --rva, not --addr"));
        }
        let addr = parse_address(addr, "--addr")?;
        if !source.is_mapped(addr, 1) {
            return Err(CliError::input(format!(
                "address 0x{addr:x} is not mapped in the image"
            )));
        }
        return Ok(addr);
    }

    let Some(rva) = rva else {
        return Err(CliError::input("one of --addr or --rva is required"));
    };
    let module = find_module(source, module_name)?;
    let rva = parse_address(rva, "--rva")?;
    let addr = module.image_base.wrapping_add(rva);
    if !module.contains(addr, 1) {
        return Err(CliError::input(format!(
            "rva 0x{rva:x} is outside module {:?} (size 0x{:x})",
            module.name, module.size
        )));
    }
    if !source.is_mapped(addr, 1) {
        return Err(CliError::input(format!(
            "module+rva {}+0x{rva:x} is not mapped",
            module.name
        )));
    }
    Ok(addr)
}

fn find_module<'a>(source: &'a dyn ByteSource, name: Option<&str>) -> Result<&'a Module, CliError> {
    let modules = source.modules();
    if modules.is_empty() {
        return Err(CliError::input("the image has no modules"));
    }
    let Some(name) = name else {
        if modules.len() == 1 {
            return Ok(&modules[0]);
        }
        let names: Vec<&str> = modules.iter().map(|module| module.name.as_str()).collect();
        return Err(CliError::input(format!(
            "--module is required; the image has several modules: {}",
            names.join(", ")
        )));
    };
    if let Some(module) = modules.iter().find(|module| module.name == name) {
        return Ok(module);
    }
    let folded: Vec<&Module> = modules
        .iter()
        .filter(|module| module.name.to_lowercase() == name.to_lowercase())
        .collect();
    if folded.len() == 1 {
        return Ok(folded[0]);
    }
    // Modules are named by stem, so `--module kernel32.dll` names `kernel32`.
    if let Some(stem) = Path::new(name).file_stem().and_then(|stem| stem.to_str()) {
        let stemmed: Vec<&Module> = modules
            .iter()
            .filter(|module| module.name.eq_ignore_ascii_case(stem))
            .collect();
        if stemmed.len() == 1 {
            return Ok(stemmed[0]);
        }
    }
    let names: Vec<&str> = modules.iter().map(|module| module.name.as_str()).collect();
    Err(CliError::input(format!(
        "unknown module {name:?}; the image has: {}",
        names.join(", ")
    )))
}

fn parse_address(text: &str, option: &str) -> Result<u64, CliError> {
    let text = text.trim();
    let parsed = if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16)
    } else if let Some(rest) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        u64::from_str_radix(rest, 8)
    } else if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        u64::from_str_radix(rest, 2)
    } else {
        text.parse::<u64>()
    };
    parsed.map_err(|_| {
        CliError::input(format!(
            "{option} expects a decimal or 0x-prefixed address, got {text:?}"
        ))
    })
}

/// One stderr line per scan budget that ran out (`coverage`).
fn warn_coverage(coverage: &Coverage) {
    for line in coverage.warnings() {
        eprintln!("sigtool-native: {line}");
    }
}

/// The `truncated` JSON field: one object per exhausted budget, in budget
/// order, each `{"budget", "count", "limit"}` (`count` is null when the pass
/// keeps none). An empty array means every budgeted pass the command ran
/// completed; commands that build no image index (hinted `locate`,
/// `gen --pid`) always write `[]`, and the per-signature candidate cap, which
/// ranks candidates and drops the least likely by design, is never reported
/// (`Coverage`).
fn coverage_value(coverage: &Coverage) -> Value {
    Value::Array(
        coverage
            .exhausted()
            .iter()
            .map(|entry| {
                let mut object: BTreeMap<String, Value> = BTreeMap::new();
                object.insert(
                    "budget".to_string(),
                    Value::String(entry.budget.key().to_string()),
                );
                object.insert(
                    "count".to_string(),
                    entry
                        .count
                        .map_or(Value::Null, |count| Value::Number(count.into())),
                );
                object.insert("limit".to_string(), Value::Number(entry.limit.into()));
                Value::Object(object.into_iter().collect())
            })
            .collect(),
    )
}

fn write_json(path: &Path, document: &BTreeMap<String, Value>) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(document)
        .map_err(|error| CliError::input(format!("cannot encode JSON: {error}")))?;
    std::fs::write(path, format!("{text}\n"))
        .map_err(|error| CliError::input(format!("cannot write {}: {error}", path.display())))
}

fn json_number(value: f64) -> Value {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn round6(value: f64) -> f64 {
    format!("{value:.6}").parse::<f64>().unwrap_or(value)
}

fn run_bench(args: BenchArgs) -> Result<u8, CliError> {
    use sigtool_native::bench;
    let options = bench::BenchOptions {
        arches: args.arch.clone(),
        max_functions: args.max_functions,
        sample_seed: args.sample_seed,
        discovery: args.discovery.clone(),
        skip_false_positives: args.no_fp,
        fp_report: args.fp_report.clone(),
        joint: args.joint,
        joint_report: args.joint_report.clone(),
    };
    let report = bench::run_with(&args.corpus, &options).map_err(CliError::input)?;
    print!("{}", bench::render(&report));
    let write = |path: &Path, report: &bench::BenchReport| -> Result<(), CliError> {
        let text =
            serde_json::to_string_pretty(report).map_err(|e| CliError::input(e.to_string()))?;
        std::fs::write(
            path,
            text + "
",
        )
        .map_err(|e| CliError::input(format!("{}: {e}", path.display())))
    };
    if let Some(path) = &args.save_baseline {
        write(path, &report)?;
        println!(
            "
wrote baseline {}",
            path.display()
        );
    }
    let mut failed = report.refused > 0;
    if let Some(path) = &args.baseline {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::input(format!("{}: {e}", path.display())))?;
        let baseline: bench::BenchReport = serde_json::from_str(&text)
            .map_err(|e| CliError::input(format!("{}: {e}", path.display())))?;
        let failures = bench::compare(&baseline, &report, args.tolerance);
        if failures.is_empty() {
            println!(
                "
baseline comparison: OK within {:.2} ({})",
                args.tolerance,
                path.display()
            );
        } else {
            println!(
                "
baseline comparison: FAILED ({})",
                path.display()
            );
            for failure in &failures {
                println!("  {failure}");
            }
            failed = true;
        }
    }
    Ok(if failed { EXIT_NOT_FOUND } else { EXIT_OK })
}
