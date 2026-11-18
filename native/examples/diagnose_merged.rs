//! Merged-signature miss diagnosis: builds the bench's x64+arm64 merged
//! signatures (same `--max-functions` choice), scans every held-out
//! architecture build (arm32, thumb) of the same library at the same level
//! hint-free on the stripped copy, and reports, per scan, the rank of the
//! true function, the true function's score and similarity, and the first
//! match. With `FP=1` it also scans the stripped builds of the other
//! libraries and counts signatures with any accepted match. Ground truth only
//! picks addresses.
//!
//! Usage: `diagnose_merged CORPUS MAX_FUNCTIONS` (one JSON object per line on
//! stdout). Offline analysis lives outside the crate.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::features::extract;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{
    accepts, compare_keys, explain_candidates, identified_answer, rank_key, scan_in, similarity,
    ScanContext,
};
use sigtool_native::merge::{merge_in, MergeSample};
use sigtool_native::recover::recover;
use sigtool_native::score::score_features;
use sigtool_native::sigfile::Signature;

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

fn level(opt: &str) -> &str {
    opt.split('-').nth(1).unwrap_or(opt)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = Path::new(&args[0]);
    let max: usize = args[1].parse().expect("max functions");
    let fp = std::env::var("FP").is_ok_and(|v| v == "1");
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    let mut images = Vec::new();
    for entry in truth["binaries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let parts: Vec<&str> = path.split('/').collect();
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
    let find = |arch: &str, lib: &str, opt: &str| {
        images
            .iter()
            .position(|i| i.arch == arch && i.lib == lib && i.opt == opt)
    };
    let contexts: Vec<(ScanContext, ScanContext)> =
        sigtool_native::parallel::map(images.len(), |i| {
            (
                ScanContext::build(&images[i].source),
                ScanContext::build(&images[i].stripped),
            )
        });
    let mut jobs: Vec<(usize, usize, String)> = Vec::new();
    for (a, image) in images.iter().enumerate().filter(|(_, i)| i.arch == "x64") {
        let Some(b) = find("arm64", &image.lib, &image.opt) else {
            continue;
        };
        for (name, _) in &image.chosen {
            if images[b].functions.contains_key(name) {
                jobs.push((a, b, name.clone()));
            }
        }
    }
    jobs.sort_by(|l, r| {
        (&images[l.0].lib, &images[l.0].opt, &l.2).cmp(&(&images[r.0].lib, &images[r.0].opt, &r.2))
    });
    let lines = sigtool_native::parallel::map(jobs.len(), |job| {
        let (a, b, name) = &jobs[job];
        let (first, second) = (&images[*a], &images[*b]);
        let samples = [
            MergeSample {
                source: &first.source,
                addr: first.functions[name],
                opt: Some(&first.opt),
                tool: Some("clang"),
            },
            MergeSample {
                source: &second.source,
                addr: second.functions[name],
                opt: Some(&second.opt),
                tool: Some("clang"),
            },
        ];
        let own: Vec<Option<Signature>> = [(first, *a), (second, *b)]
            .iter()
            .map(|(image, index)| {
                generate_in(
                    &image.source,
                    image.functions[name],
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(&contexts[*index].0),
                )
                .ok()
                .map(|r| r.signature)
            })
            .collect();
        let Ok(merged) = merge_in(
            &samples,
            &[Some(&contexts[*a].0), Some(&contexts[*b].0)],
            Some(name),
            None,
        ) else {
            return vec![
                json!({"name": name, "lib": first.lib, "opt": first.opt, "refused": true})
                    .to_string(),
            ];
        };
        let mut signature = merged.signature;
        let presence = |key: &str, index: usize| {
            own[index]
                .as_ref()
                .is_some_and(|s| s.features.iter().any(|f| f.key() == key))
        };
        // VARIANT=widen: a shape bucket only one sample has also accepts its
        // neighbouring bucket values, at minimal weight (shape gate only).
        if std::env::var("VARIANT").is_ok_and(|v| v == "widen") {
            let existing: HashSet<String> = signature.features.iter().map(|f| f.key()).collect();
            let mut extra = Vec::new();
            for f in &signature.features {
                if !matches!(
                    f.kind,
                    sigtool_native::features::FeatureKind::Cfg
                        | sigtool_native::features::FeatureKind::Ops
                ) || (presence(&f.key(), 0) && presence(&f.key(), 1))
                {
                    continue;
                }
                let Some((head, bucket)) = f.value.rsplit_once(':') else {
                    continue;
                };
                let Ok(bucket) = bucket.parse::<i64>() else {
                    continue;
                };
                for next in [bucket - 1, bucket + 1] {
                    if next < 0 {
                        continue;
                    }
                    let mut added = f.clone();
                    added.value = format!("{head}:{next}");
                    added.weight = 0.001;
                    added.required = false;
                    if !existing.contains(&added.key())
                        && !extra
                            .iter()
                            .any(|e: &sigtool_native::sigfile::SignatureFeature| {
                                e.key() == added.key()
                            })
                    {
                        extra.push(added);
                    }
                }
            }
            signature.features.extend(extra);
            signature
                .features
                .sort_by(|l, r| (l.kind, l.value.as_str()).cmp(&(r.kind, r.value.as_str())));
            signature.validate().expect("widened signature");
        }
        let features: Vec<Value> = signature
            .features
            .iter()
            .map(|f| {
                let key = f.key();
                json!([
                    key,
                    f.weight,
                    f.required,
                    presence(&key, 0),
                    presence(&key, 1)
                ])
            })
            .collect();
        let mut out = Vec::new();
        for (t, target) in images.iter().enumerate() {
            if target.lib != first.lib
                || !(target.arch == "arm32" || target.arch == "thumb")
                || level(&target.opt) != level(&first.opt)
            {
                continue;
            }
            let Some(true_start) = target.functions.get(name).copied() else {
                continue;
            };
            let context = &contexts[t].1;
            let matches = scan_in(&target.stripped, &signature, context, false);
            let rank = matches.iter().position(|m| m.address == true_start);
            let top = matches.first().is_some_and(|m| m.address == true_start)
                && matches
                    .get(1)
                    .is_none_or(|next| rank_key(next) < rank_key(&matches[0]));
            let truth = recover(&target.stripped, true_start, None, false)
                .ok()
                .map(|recovered| {
                    let target_features = extract(&target.stripped, &recovered);
                    let keys: HashSet<String> = target_features.iter().map(|f| f.key()).collect();
                    let weighted: Vec<(String, f64)> = score_features(&target_features, None)
                        .into_iter()
                        .map(|item| (item.key(), item.weight))
                        .collect();
                    let score = compare_keys(&signature, &keys);
                    let mut sorted: Vec<(String, f64)> = weighted.clone();
                    sorted.sort_by(|l, r| l.0.cmp(&r.0));
                    json!({
                        "start_ok": recovered.start() == true_start,
                        "score": score.score,
                        "matched_required": score.matched_required,
                        "accepted": accepts(&signature, &score),
                        "similarity": similarity(&signature, &weighted),
                        "matched": score.matched,
                        "keys": sorted,
                        "neighbours": context.neighbour_keys(&target.stripped, true_start, false),
                    })
                });
            let in_candidates = explain_candidates(&target.stripped, &signature, context, false)
                .contains(&true_start);
            let shown: Vec<Value> = matches
                .iter()
                .take(3)
                .map(|m| {
                    json!({"true": m.address == true_start, "similarity": m.similarity,
                           "score": m.score, "matched": m.matched})
                })
                .collect();
            out.push(
                json!({
                    "name": name, "lib": first.lib, "opt": first.opt,
                    "target": [target.arch, target.opt],
                    "threshold": signature.match_threshold,
                    "min_distinct": signature.min_distinct,
                    "anchors": signature.anchors,
                    "sig": features,
                    "sig_neighbours": signature.neighbours,
                    "top": top, "rank": rank, "found": matches.len(),
                    "answer": identified_answer(&matches),
                    "in_candidates": in_candidates,
                    "truth": truth,
                    "matches": shown,
                })
                .to_string(),
            );
        }
        if fp {
            let mut hits = 0usize;
            let mut answers = 0usize;
            for (t, target) in images.iter().enumerate() {
                if target.lib == first.lib {
                    continue;
                }
                let matches = scan_in(&target.stripped, &signature, &contexts[t].1, false);
                hits += matches.len();
                answers += usize::from(identified_answer(&matches));
            }
            out.push(
                json!({"fp": true, "name": name, "lib": first.lib, "opt": first.opt,
                       "hits": hits, "answers": answers})
                .to_string(),
            );
        }
        out
    });
    for line in lines.into_iter().flatten() {
        println!("{line}");
    }
}
