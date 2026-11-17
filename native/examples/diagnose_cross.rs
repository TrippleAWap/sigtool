//! Cross-build miss diagnosis: for every bench sample (the same
//! `--max-functions` choice as `bench`), compare the signature with the
//! features the extractor produces at the true function of every other build
//! of the same library, on the stripped copy and without hints, as hint-free
//! discovery would see it. Ground truth only picks addresses.
//!
//! Usage: `diagnose_cross CORPUS MAX_FUNCTIONS ARCH...` (one JSON object per
//! pair on stdout). Offline analysis lives outside the crate.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::features::{const_words, extract, string_at, FeatureKind};
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{
    accepts_on, compare_keys, cross_isa, explain_candidates, similarity, ScanContext,
};
use sigtool_native::normalize::Kind;
use sigtool_native::recover::recover;
use sigtool_native::recover::RecoveredFunction;
use sigtool_native::score::score_features;
use sigtool_native::source::ByteSource;

struct Image {
    arch: String,
    opt: String,
    lib: String,
    source: FileSource,
    stripped: FileSource,
    functions: BTreeMap<String, u64>,
    chosen: Vec<(String, u64)>,
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

/// Evidence of the direct callees: `(instruction count, identifying keys)`.
fn callee_evidence<S: ByteSource + ?Sized>(
    source: &S,
    context: &ScanContext,
    start: u64,
    hints: bool,
) -> Vec<Value> {
    context
        .callees_of(source, start, hints)
        .into_iter()
        .filter_map(|callee| {
            let recovered = recover(source, callee, None, hints).ok()?;
            let keys: Vec<String> = extract(source, &recovered)
                .into_iter()
                .filter(|f| {
                    matches!(
                        f.kind,
                        FeatureKind::Str | FeatureKind::Const | FeatureKind::Callee
                    )
                })
                .map(|f| f.key())
                .collect();
            Some(json!({"n": recovered.instruction_count(), "keys": keys}))
        })
        .collect()
}

/// Constants the pointer test dropped, as `const:` keys, tagged with what the
/// value points at: `s` a string, `x` executable code, `d` other data.
fn dropped_constants<S: ByteSource + ?Sized>(
    source: &S,
    recovered: &RecoveredFunction,
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for insn in recovered.blocks.iter().flat_map(|b| b.insns.iter()) {
        if insn.kind == Kind::Ignored {
            continue;
        }
        for value in &insn.consts {
            if *value == 0 || source.module_for(*value).is_none() {
                continue;
            }
            let tag = if string_at(source, *value).is_some() {
                "s"
            } else if source.is_executable(*value) {
                "x"
            } else {
                "d"
            };
            for word in const_words(*value) {
                out.insert(format!("{tag}|const:0x{word:x}"));
            }
        }
    }
    out.into_iter().collect()
}

/// Unbucketed shape: op-class counts and CFG sizes, for simulating other
/// bucketings and class mappings offline.
fn raw_shape(recovered: &RecoveredFunction) -> Value {
    let mut ops: BTreeMap<&'static str, usize> = BTreeMap::new();
    for insn in recovered.blocks.iter().flat_map(|b| b.insns.iter()) {
        if insn.kind != Kind::Ignored {
            *ops.entry(insn.op.as_str()).or_insert(0) += 1;
        }
    }
    json!({
        "ops": ops,
        "blocks": recovered.block_count(),
        "edges": recovered.edge_count(),
        "loops": recovered.loop_count(),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = Path::new(&args[0]);
    let max: usize = args[1].parse().expect("max functions");
    let arches: HashSet<&str> = args[2..].iter().map(String::as_str).collect();
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    let mut images = Vec::new();
    for entry in truth["binaries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let parts: Vec<&str> = path.split('/').collect();
        if !arches.contains(parts[0]) {
            continue;
        }
        let Some(stripped) = entry["stripped"].as_str() else {
            continue;
        };
        let functions: BTreeMap<String, u64> = entry["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["name"].as_str().unwrap().to_string(),
                    f["start"].as_u64().unwrap(),
                )
            })
            .collect();
        let chosen = limit(&functions, max);
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
            functions,
            chosen,
        });
    }
    let contexts: Vec<(ScanContext, ScanContext)> =
        sigtool_native::parallel::map(images.len(), |i| {
            (
                ScanContext::build(&images[i].source),
                ScanContext::build(&images[i].stripped),
            )
        });
    let jobs: Vec<(usize, String, u64)> = images
        .iter()
        .enumerate()
        .flat_map(|(i, image)| image.chosen.iter().map(move |(n, s)| (i, n.clone(), *s)))
        .collect();
    let lines = sigtool_native::parallel::map(jobs.len(), |job| {
        let (i, name, start) = &jobs[job];
        let image = &images[*i];
        let mut out = Vec::new();
        let Ok(result) = generate_in(
            &image.source,
            *start,
            None,
            None,
            None,
            None,
            None,
            Some(&contexts[*i].0),
        ) else {
            return out;
        };
        let signature = result.signature;
        let source_callees = callee_evidence(&image.source, &contexts[*i].0, *start, true);
        let source_recovered = recover(&image.source, *start, None, true).ok();
        let source_dropped = source_recovered
            .as_ref()
            .map(|r| dropped_constants(&image.source, r))
            .unwrap_or_default();
        let source_shape = source_recovered.as_ref().map(raw_shape);
        let features: Vec<Value> = signature
            .features
            .iter()
            .map(|f| json!([f.key(), f.weight, f.required]))
            .collect();
        for (j, target) in images.iter().enumerate() {
            if j == *i || target.lib != image.lib {
                continue;
            }
            let Some(true_start) = target.functions.get(name) else {
                continue;
            };
            let context = &contexts[j].1;
            let Ok(recovered) = recover(&target.stripped, *true_start, None, false) else {
                out.push(json!({"name": name, "src": [image.arch, image.opt], "dst": [target.arch, target.opt], "lib": image.lib, "recovered": false}).to_string());
                continue;
            };
            let target_features = extract(&target.stripped, &recovered);
            let candidate_keys: HashSet<String> = target_features.iter().map(|f| f.key()).collect();
            let weighted: Vec<(String, f64)> = score_features(&target_features, None)
                .into_iter()
                .map(|item| (item.key(), item.weight))
                .collect();
            let score = compare_keys(&signature, &candidate_keys);
            let accepted = accepts_on(
                &signature,
                &score,
                cross_isa(&signature, target.stripped.arch()),
            );
            let in_candidates = explain_candidates(&target.stripped, &signature, context, false)
                .contains(true_start);
            let neighbours: HashSet<&str> =
                signature.neighbours.iter().map(String::as_str).collect();
            let target_neighbours = context.neighbour_keys(&target.stripped, *true_start, false);
            let shared: Vec<&String> = target_neighbours
                .iter()
                .filter(|key| neighbours.contains(key.as_str()))
                .collect();
            let mut keys: Vec<&String> = candidate_keys.iter().collect();
            keys.sort();
            out.push(
                json!({
                    "name": name,
                    "lib": image.lib,
                    "src": [image.arch, image.opt],
                    "dst": [target.arch, target.opt],
                    "recovered": true,
                    "start_ok": recovered.start() == *true_start,
                    "threshold": signature.match_threshold,
                    "min_distinct": signature.min_distinct,
                    "anchors": signature.anchors,
                    "score": score.score,
                    "matched_required": score.matched_required,
                    "accepted": accepted,
                    "similarity": similarity(&signature, &weighted),
                    "in_candidates": in_candidates,
                    "sig": features,
                    "sig_neighbours": signature.neighbours,
                    "shared_neighbours": shared,
                    "dst_keys": keys,
                    "src_callees": source_callees,
                    "dst_callees": callee_evidence(&target.stripped, context, *true_start, false),
                    "src_dropped": source_dropped,
                    "dst_dropped": dropped_constants(&target.stripped, &recovered),
                    "dst_neighbours": target_neighbours,
                    "src_shape": source_shape,
                    "dst_shape": raw_shape(&recovered),
                })
                .to_string(),
            );
        }
        out
    });
    for line in lines.into_iter().flatten() {
        println!("{line}");
    }
}
