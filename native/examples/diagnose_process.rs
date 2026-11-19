//! Process-path miss diagnosis (`bench --process-like`): each bench sample
//! (the same `--max-functions` choice as `bench`) is scanned in the stripped
//! copy of every same-arch build of its library the way `scan --pid` scans
//! a live process (no symbol starts, unwind bounds as hints, the
//! incremental scanner), then through `matcher::scan` on the same view with
//! a reference index, then on the unstripped target through the file hinted
//! path, and what each found is printed. Ground truth only picks addresses
//! and labels.
//!
//! Usage: `diagnose_process CORPUS MAX_FUNCTIONS ARCH...`: a summary per
//! arch on stderr, and one JSON object per pair the process path did not
//! answer correctly on stdout.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{
    hinted_floors, identified_answer, scan, scan_in, Match, ReferenceIndex, ScanContext,
    MAX_CANDIDATE_STARTS,
};
use sigtool_native::scanner::SignatureScanner;
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
    index: ReferenceIndex,
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
/// `Target::process_view`): synthesized starts dropped.
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
    let table = table(&stripped);
    let mut index = ReferenceIndex::default();
    for region in stripped.regions().iter().filter(|region| region.executable) {
        index.index_region(&stripped, region);
    }
    Some(Image {
        path: path.to_string(),
        arch,
        library,
        source,
        stripped,
        functions,
        names,
        context,
        index,
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
    // correct, top-1 with a reference index, file hinted top-1.
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
                let mut scanner = SignatureScanner::new(
                    &view,
                    vec![signature.clone()],
                    None,
                    Some(ReferenceIndex::default()),
                )
                .expect("scanner");
                scanner.scan_pass();
                let process = scanner.matches(0).to_vec();
                let indexed = hinted_floors(
                    &view,
                    &signature,
                    scan(
                        &view,
                        &signature,
                        None,
                        MAX_CANDIDATE_STARTS,
                        true,
                        Some(&target.index),
                    ),
                );
                let hinted = scan_in(&target.source, &signature, &target.context, true);
                let found = top(&process) == Some(expected);
                let answered = identified_answer(&process);
                let row = summary.entry(image.arch.clone()).or_default();
                row[0] += 1;
                row[1] += usize::from(found);
                row[2] += usize::from(answered);
                row[3] += usize::from(answered && found);
                row[4] += usize::from(top(&indexed) == Some(expected));
                row[5] += usize::from(top(&hinted) == Some(expected));
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
                        "hint": view.hint_function(expected).is_some(),
                        "process": label(&process),
                        "indexed": label(&indexed),
                        "hinted": label(&hinted),
                    })
                );
            }
        }
    }
    for (arch, row) in summary {
        eprintln!(
            "{arch}: pairs {} process top-1 {} identified {} (correct {}); \
             with a reference index top-1 {}; file hinted top-1 {}",
            row[0], row[1], row[2], row[3], row[4], row[5]
        );
    }
}
