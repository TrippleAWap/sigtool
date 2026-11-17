//! Cross-ISA false positives: the bench measures false positives against
//! unrelated libraries of the signature's own arch only, so a matcher rule
//! that applies across instruction sets needs its own check. For every bench
//! sample (the same `--max-functions` choice as `bench`), scan the stripped
//! copies of the *other* libraries, same build, in every other ISA family,
//! hint-free, and count signatures with any accepted match and identified
//! answers.
//!
//! Usage: `cross_fp CORPUS MAX_FUNCTIONS [HITS.jsonl]` (one summary line per arch pair,
//! then the totals).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{identified_answer, scan_in, ScanContext};

struct Image {
    arch: String,
    opt: String,
    lib: String,
    source: FileSource,
    stripped: FileSource,
    chosen: Vec<u64>,
}

fn family(arch: &str) -> &str {
    if arch == "thumb" {
        "arm32"
    } else {
        arch
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = Path::new(&args[0]);
    let max: usize = args[1].parse().expect("max functions");
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    let mut images = Vec::new();
    for entry in truth["binaries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let parts: Vec<&str> = path.split('/').collect();
        let Some(stripped) = entry["stripped"].as_str() else {
            continue;
        };
        let mut ranked: Vec<(u32, u64)> = entry["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    crc32fast::hash(f["name"].as_str().unwrap().as_bytes()),
                    f["start"].as_u64().unwrap(),
                )
            })
            .collect();
        ranked.sort();
        if max > 0 {
            ranked.truncate(max);
        }
        images.push(Image {
            arch: parts[0].to_string(),
            opt: parts[1].to_string(),
            lib: Path::new(parts[2])
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            source: FileSource::from_path(corpus.join(path)).unwrap(),
            stripped: FileSource::from_path(corpus.join(stripped)).unwrap(),
            chosen: ranked.into_iter().map(|(_, start)| start).collect(),
        });
    }
    let contexts: Vec<(ScanContext, ScanContext)> =
        sigtool_native::parallel::map(images.len(), |i| {
            (
                ScanContext::build(&images[i].source),
                ScanContext::build(&images[i].stripped),
            )
        });
    let samples: Vec<(usize, u64)> = images
        .iter()
        .enumerate()
        .flat_map(|(i, image)| image.chosen.iter().map(move |start| (i, *start)))
        .collect();
    let signatures = sigtool_native::parallel::map(samples.len(), |job| {
        let (i, start) = samples[job];
        generate_in(
            &images[i].source,
            start,
            None,
            None,
            None,
            None,
            None,
            Some(&contexts[i].0),
        )
        .ok()
        .map(|result| result.signature)
    });
    let mut jobs: Vec<(usize, usize)> = Vec::new();
    for (job, (i, _)) in samples.iter().enumerate() {
        if signatures[job].is_none() {
            continue;
        }
        for (j, target) in images.iter().enumerate() {
            let image = &images[*i];
            if target.lib != image.lib
                && target.opt == image.opt
                && family(&target.arch) != family(&image.arch)
            {
                jobs.push((job, j));
            }
        }
    }
    let results = sigtool_native::parallel::map(jobs.len(), |k| {
        let (job, j) = jobs[k];
        let signature = signatures[job].as_ref().unwrap();
        let matches = scan_in(&images[j].stripped, signature, &contexts[j].1, false);
        let dump = (!matches.is_empty()).then(|| {
            serde_json::json!({
                "pair": [images[samples[job].0].arch, images[j].arch],
                "lib": [images[samples[job].0].lib, images[j].lib],
                "opt": images[j].opt,
                "job": job,
                "sig": signature.features.iter().map(|f| serde_json::json!([f.key(), f.weight, f.required])).collect::<Vec<_>>(),
                "matches": matches.iter().map(|m| serde_json::json!({"matched": m.matched, "similarity": m.similarity, "score": m.score})).collect::<Vec<_>>(),
            })
            .to_string()
        });
        (matches.len(), identified_answer(&matches), dump)
    });
    // Optional third argument: a path for one JSON line per scan
    // with hits, for offline simulation of stricter gates.
    if let Some(path) = args.get(2) {
        let lines: Vec<&str> = results
            .iter()
            .filter_map(|(_, _, d)| d.as_deref())
            .collect();
        std::fs::write(path, lines.join("\n")).unwrap();
    }
    let results: Vec<(usize, bool)> = results.into_iter().map(|(n, i, _)| (n, i)).collect();
    // (signature, target arch) -> any hit, hits, identified answers.
    let mut per_signature: BTreeMap<(usize, String), (bool, usize, usize)> = BTreeMap::new();
    let mut scans: BTreeMap<String, usize> = BTreeMap::new();
    for ((job, j), (hits, identified)) in jobs.iter().zip(results) {
        let (i, _) = samples[*job];
        let pair = format!("{}->{}", images[i].arch, images[*j].arch);
        *scans.entry(pair.clone()).or_insert(0) += 1;
        let entry = per_signature.entry((*job, pair)).or_insert((false, 0, 0));
        entry.0 |= hits > 0;
        entry.1 += hits;
        entry.2 += usize::from(identified);
    }
    let mut pairs: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    for ((_, pair), (any, hits, identified)) in &per_signature {
        let entry = pairs.entry(pair.clone()).or_insert((0, 0, 0, 0));
        entry.0 += 1;
        entry.1 += usize::from(*any);
        entry.2 += hits;
        entry.3 += identified;
    }
    let mut total = (0, 0, 0, 0, 0);
    for (pair, (signatures, any, hits, identified)) in &pairs {
        let scanned = scans[pair];
        println!(
            "{pair}: signatures with a hit {any}/{signatures} = {:.3}, hits {hits}, identified {identified}/{scanned} scans",
            *any as f64 / *signatures as f64
        );
        total.0 += signatures;
        total.1 += any;
        total.2 += hits;
        total.3 += identified;
        total.4 += scanned;
    }
    println!(
        "total: signatures with a hit {}/{} = {:.3}, hits {}, identified {}/{} scans",
        total.1,
        total.0,
        total.1 as f64 / total.0.max(1) as f64,
        total.2,
        total.3,
        total.4
    );
}
