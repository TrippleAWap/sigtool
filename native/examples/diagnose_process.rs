//! Process-path miss diagnosis (`bench --process-like`): each bench sample
//! (the same `--max-functions` choice as `bench`) is scanned in the stripped
//! copy of every same-arch build of its library the way `scan --pid` scans
//! a live process (no symbol starts, only the unwind table's own entries,
//! hint-free per module: `scanner::scan_modules`), then the way a forced
//! `scan --pid --discovery hinted` does (unwind bounds as hints, the
//! incremental scanner), then as a stripped file (`scan_in` hint-free on the
//! stripped copy), and what each found is printed. Ground truth only picks
//! addresses and labels.
//!
//! Usage: `diagnose_process CORPUS MAX_FUNCTIONS ARCH...`: a summary per
//! arch on stderr, and one JSON object per pair the process path did not
//! answer correctly on stdout.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use serde_json::{json, Value};
use sigtool_native::coverage::Coverage;
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{identified_answer, scan_in, Match, ReferenceIndex, ScanContext};
use sigtool_native::scanner::{scan_modules, SignatureScanner};
use sigtool_native::source::{ByteSource, ProcessView};

struct Image {
    path: String,
    arch: String,
    library: String,
    source: FileSource,
    stripped: FileSource,
    functions: BTreeMap<String, u64>,
    names: BTreeMap<u64, String>,
    context: ScanContext,
    stripped_context: ScanContext,
    process_contexts: Vec<OnceLock<ScanContext>>,
    table: Vec<(u64, u64)>,
}

fn limit(functions: &BTreeMap<String, u64>, max: usize) -> Vec<(String, u64)> {
    let mut ranked: Vec<(u32, String, u64)> = functions
        .iter()
        .map(|(name, start)| (crc32fast::hash(name.as_bytes()), name.clone(), *start))
        .collect();
    ranked.sort();
    if max > 0 {
        ranked.truncate(max);
    }
    ranked.into_iter().map(|(_, n, s)| (n, s)).collect()
}

/// The unwind-table entries a process source would have (bench's
/// `Image::process_view`): synthesized starts dropped.
fn table(source: &FileSource) -> Vec<(u64, u64)> {
    let synthesized: BTreeSet<u64> = source.synthesized_starts().iter().copied().collect();
    source
        .unwind_entries()
        .iter()
        .filter(|(start, _)| !synthesized.contains(start))
        .copied()
        .collect()
}

fn load(corpus: &Path, entry: &Value) -> Option<Image> {
    let path = entry["path"].as_str()?;
    let mut parts = path.split('/');
    let arch = parts.next()?.to_string();
    let library = parts.nth(1)?.split('.').next()?.to_string();
    let source = FileSource::from_path(corpus.join(path)).ok()?;
    let stripped = FileSource::from_path(corpus.join(entry["stripped"].as_str()?)).ok()?;
    let functions: BTreeMap<String, u64> = entry["functions"]
        .as_array()?
        .iter()
        .filter_map(|f| Some((f["name"].as_str()?.to_string(), f["start"].as_u64()?)))
        .collect();
    let names = functions
        .iter()
        .map(|(name, start)| (*start, name.clone()))
        .collect();
    let context = ScanContext::build(&source);
    let stripped_context = ScanContext::build(&stripped);
    let table = table(&stripped);
    let process_contexts = stripped.modules().iter().map(|_| OnceLock::new()).collect();
    Some(Image {
        path: path.to_string(),
        arch,
        library,
        source,
        stripped,
        functions,
        names,
        context,
        stripped_context,
        process_contexts,
        table,
    })
}

fn top(matches: &[Match]) -> Option<u64> {
    matches.first().map(|found| found.address)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let corpus = Path::new(&args[1]);
    let max: usize = args[2].parse().expect("MAX_FUNCTIONS");
    let arches: BTreeSet<&str> = args[3..].iter().map(String::as_str).collect();
    let truth: Value = serde_json::from_str(
        &std::fs::read_to_string(corpus.join("ground_truth.json")).expect("ground truth"),
    )
    .expect("json");
    let images: Vec<Image> = truth["binaries"]
        .as_array()
        .expect("binaries")
        .iter()
        .filter(|entry| {
            entry["path"]
                .as_str()
                .and_then(|path| path.split('/').next())
                .is_some_and(|arch| arches.contains(arch))
        })
        .filter_map(|entry| load(corpus, entry))
        .collect();
    // Per arch: pairs, process top-1, process identified answers, of those
    // correct, forced-hinted process top-1, stripped file hint-free top-1.
    let mut summary: BTreeMap<String, [usize; 6]> = BTreeMap::new();
    for image in &images {
        for (name, start) in limit(&image.functions, max) {
            let Ok(result) = generate_in(
                &image.source,
                start,
                None,
                None,
                None,
                None,
                None,
                Some(&image.context),
            ) else {
                continue;
            };
            let signature = result.signature;
            for target in images
                .iter()
                .filter(|t| t.arch == image.arch && t.library == image.library)
            {
                let Some(&expected) = target.functions.get(&name) else {
                    continue;
                };
                let view = ProcessView::new(&target.stripped, target.table.clone());
                let process = scan_modules(
                    &view,
                    std::slice::from_ref(&signature),
                    None,
                    Some(&target.process_contexts),
                    &mut Coverage::new(),
                )
                .pop()
                .unwrap_or_default();
                let mut scanner = SignatureScanner::new(
                    &view,
                    vec![signature.clone()],
                    None,
                    Some(ReferenceIndex::default()),
                )
                .expect("scanner");
                scanner.scan_pass();
                let forced_hinted = scanner.matches(0).to_vec();
                let file = scan_in(
                    &target.stripped,
                    &signature,
                    &target.stripped_context,
                    false,
                );
                let found = top(&process) == Some(expected);
                let answered = identified_answer(&process);
                let row = summary.entry(image.arch.clone()).or_default();
                row[0] += 1;
                row[1] += usize::from(found);
                row[2] += usize::from(answered);
                row[3] += usize::from(answered && found);
                row[4] += usize::from(top(&forced_hinted) == Some(expected));
                row[5] += usize::from(top(&file) == Some(expected));
                if found && answered {
                    continue;
                }
                let label = |matches: &[Match]| {
                    top(matches).map(|address| {
                        json!({
                            "name": target.names.get(&address),
                            "similarity": matches[0].similarity,
                            "matched": matches[0].matched,
                            "identified": identified_answer(matches),
                        })
                    })
                };
                println!(
                    "{}",
                    json!({
                        "signed": image.path,
                        "target": target.path,
                        "sample": name,
                        "anchors": signature.anchors,
                        "unwind_entry": view.unwind_function(expected).is_some(),
                        "process": label(&process),
                        "forced_hinted": label(&forced_hinted),
                        "file_hint_free": label(&file),
                    })
                );
            }
        }
    }
    for (arch, row) in summary {
        eprintln!(
            "{arch}: pairs {} process top-1 {} identified {} (correct {}); \
             forced-hinted process top-1 {}; stripped file hint-free top-1 {}",
            row[0], row[1], row[2], row[3], row[4], row[5]
        );
    }
}
