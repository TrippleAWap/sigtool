//! Command-line front-end for the native scanner.
//!
//! The CLI is thin by contract (AGENTS.md rule 2): it opens a [`FileSource`],
//! calls [`sigtool_native::generate::generate`], the reference matcher, or the
//! scanner, and formats results. No feature, scoring, matching, or serialisation
//! logic lives here.
//!
//! ```text
//! sigtool-native gen --file image.elf --addr 0x1000
//! sigtool-native gen --file image.elf --module image.elf --rva 0x1000
//! sigtool-native locate --signature fn.yaml --file other.so --json matches.json
//! sigtool-native scan --file image.elf --signature fn.yaml --signature other.yaml
//! sigtool-native scan --file image.elf --db signatures.db
//! sigtool-native merge --sample a.elf:0x1000 --sample b.elf:0x2c40 --name fn
//! sigtool-native db build --signature fn.yaml --output signatures.db
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

use clap::{Args, Parser, Subcommand};
use serde_json::Value;

use sigtool_native::arch::Arch;
use sigtool_native::db::{DbView, MappedDb, SignatureDb};
use sigtool_native::elf::FileSource;
use sigtool_native::errors::{DecodeError, SourceFormatError};
use sigtool_native::generate::{generate, GenerateError, GenerationResult};
use sigtool_native::matcher::{scan, Match};
use sigtool_native::merge::{merge, MergeSample};
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
    version,
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
}

#[derive(Args)]
struct GenArgs {
    /// ELF or PE image
    #[arg(long, value_name = "IMAGE")]
    file: PathBuf,
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
    #[arg(long, value_name = "IMAGE")]
    file: PathBuf,
    /// Write the match list as JSON
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
    /// Do not prompt for confirmation of the best match
    #[arg(long)]
    yes: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// ELF or PE image to scan
    #[arg(long, value_name = "IMAGE")]
    file: PathBuf,
    /// Signature YAML file (repeatable)
    #[arg(long, value_name = "FILE")]
    signature: Vec<PathBuf>,
    /// Signature database built by `db build`
    #[arg(long, value_name = "DB", conflicts_with = "signature")]
    db: Option<PathBuf>,
    /// Write the hit list as JSON
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,
}

#[derive(Args)]
struct MergeArgs {
    /// One sample: image path and function address (repeatable, at least two)
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
    #[arg(long, value_name = "FILE", required = true)]
    signature: Vec<PathBuf>,
    /// Output database path
    #[arg(long, value_name = "DB")]
    output: PathBuf,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Gen(args) => run_gen(args),
        Command::Locate(args) => run_locate(args),
        Command::Scan(args) => run_scan(args),
        Command::Merge(args) => run_merge(args),
        Command::Db(args) => run_db(args),
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
    let source = load_file(&args.file)?;
    ensure_supported(&source)?;
    let addr = resolve_address(
        &source,
        args.addr.as_deref(),
        args.rva.as_deref(),
        args.module.as_deref(),
    )?;
    let result = generate(
        &source,
        addr,
        args.name.as_deref(),
        args.opt.as_deref(),
        args.tool.as_deref(),
        None,
        None,
    )
    .map_err(classify_generate_error)?;
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

    if let Some(path) = json_report {
        let document = report_document(result, arch, label);
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
        ensure_supported(&source)?;
        let addr = parse_address(addr_text, "--sample")?;
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
    let result = merge(&samples, args.name.as_deref(), None)
        .map_err(|error| CliError::input(format!("refusing to merge: {error}")))?;

    let arches: BTreeSet<&str> = sources
        .iter()
        .map(|source| source.arch().as_str())
        .collect();
    let arch = arches.into_iter().collect::<Vec<&str>>().join("+");
    let label = format!("{} samples", samples.len());
    write_outputs(
        &result,
        &arch,
        &label,
        args.output.as_deref(),
        args.json_report.as_deref(),
    )?;
    Ok(EXIT_OK)
}

// -- locate ------------------------------------------------------------------

fn run_locate(args: LocateArgs) -> Result<u8, CliError> {
    let signature = load_signature(&args.signature)?;
    let source = load_file(&args.file)?;
    ensure_supported(&source)?;
    let matches = scan(&source, &signature, None, 256, true, None);

    if let Some(path) = &args.json {
        let document = match_document(&source, &signature, &matches);
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
            "  {}. 0x{:x} score {:.3} {}",
            index + 1,
            matched.address,
            matched.score,
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
    source: &FileSource,
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
        .map(|matched| {
            let mut entry: BTreeMap<String, Value> = BTreeMap::new();
            entry.insert(
                "address".to_string(),
                Value::String(format!("0x{:x}", matched.address)),
            );
            entry.insert(
                "end".to_string(),
                Value::String(format!("0x{:x}", matched.end)),
            );
            entry.insert("score".to_string(), json_number(matched.score));
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
    let source = load_file(&args.file)?;
    ensure_supported(&source)?;
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

    let mut scanner = SignatureScanner::new(&source, signatures, None, None)
        .map_err(|error| CliError::input(error.to_string()))?;
    let report = scanner.scan_pass();

    if let Some(path) = &args.json {
        write_json(path, &scan_document(&source, &report.hits))?;
    }
    for hit in &report.hits {
        let where_ = source
            .label_for_address(hit.address)
            .unwrap_or_else(|| hit.region.clone());
        println!(
            "{}  0x{:x} score {:.3} {}",
            hit.name, hit.address, hit.score, where_
        );
    }
    if report.hits.is_empty() {
        eprintln!("sigtool-native: no accepted matches in the target");
        return Ok(EXIT_NOT_FOUND);
    }
    Ok(EXIT_OK)
}

fn scan_document(source: &FileSource, hits: &[ScanHit]) -> BTreeMap<String, Value> {
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
            entry.insert("score".to_string(), json_number(hit.score));
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

fn ensure_supported(source: &FileSource) -> Result<(), CliError> {
    if !matches!(source.arch(), Arch::X64 | Arch::Arm64) {
        return Err(CliError::unsupported(format!(
            "the native port currently decodes x64 and arm64 only, not {}",
            source.arch()
        )));
    }
    Ok(())
}

fn resolve_address(
    source: &FileSource,
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
    let addr = module.base.wrapping_add(rva);
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

fn find_module<'a>(source: &'a FileSource, name: Option<&str>) -> Result<&'a Module, CliError> {
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
