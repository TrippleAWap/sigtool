//! In-module constants: how many `const` records each image's functions carry
//! whose value falls inside the module's address range, and how those values
//! are used. Runs over every ground-truth function of the stripped copies,
//! without hints (as hint-free discovery sees them).
//!
//! Usage: `in_module_consts CORPUS` (one JSON line per arch on stdout).

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::features::{extract_own, string_at, FeatureKind};
use sigtool_native::normalize::Kind;
use sigtool_native::recover::recover;
use sigtool_native::source::ByteSource;

#[derive(Default)]
struct Counts {
    functions: u64,
    with_in_range: u64,
    consts: u64,
    in_range: u64,
    raw_in_range: u64,
    relocated: u64,
    string: u64,
    code: u64,
    region_start: u64,
    values: BTreeMap<String, u64>,
}

fn main() {
    let corpus = std::env::args()
        .nth(1)
        .expect("usage: in_module_consts CORPUS");
    let corpus = Path::new(&corpus);
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    let mut per_arch: BTreeMap<String, Counts> = BTreeMap::new();
    for entry in truth["binaries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let arch = path.split('/').next().unwrap().to_string();
        let Some(stripped) = entry["stripped"].as_str() else {
            continue;
        };
        let source = FileSource::from_path(corpus.join(stripped)).unwrap();
        let module = &source.modules()[0];
        let (base, end) = (module.base, module.end());
        let starts: Vec<u64> = entry["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["start"].as_u64().unwrap())
            .collect();
        let results = sigtool_native::parallel::map(starts.len(), |index| {
            let mut counts = Counts::default();
            let Ok(recovered) = recover(&source, starts[index], None, false) else {
                return counts;
            };
            counts.functions = 1;
            for insn in recovered.blocks.iter().flat_map(|b| b.insns.iter()) {
                if insn.kind == Kind::Ignored {
                    continue;
                }
                for value in &insn.consts {
                    if *value == 0 || source.module_for(*value).is_none() {
                        continue;
                    }
                    counts.raw_in_range += 1;
                    if module.relocated(insn.addr, insn.size) == Some(true) {
                        counts.relocated += 1;
                    } else if string_at(&source, *value).is_some() {
                        counts.string += 1;
                    } else if source.is_executable(*value) {
                        counts.code += 1;
                    }
                    if source.regions().iter().any(|r| r.start == *value) {
                        counts.region_start += 1;
                    }
                }
            }
            let mut any = false;
            for feature in extract_own(&source, &recovered) {
                if feature.kind != FeatureKind::Const {
                    continue;
                }
                counts.consts += 1;
                let value =
                    u64::from_str_radix(feature.value.trim_start_matches("0x"), 16).unwrap_or(0);
                if value != 0 && base <= value && value < end {
                    counts.in_range += 1;
                    *counts.values.entry(feature.value.clone()).or_default() += 1;
                    any = true;
                }
            }
            counts.with_in_range = u64::from(any);
            counts
        });
        let total = per_arch.entry(arch).or_default();
        for c in results {
            total.functions += c.functions;
            total.with_in_range += c.with_in_range;
            total.consts += c.consts;
            total.in_range += c.in_range;
            total.raw_in_range += c.raw_in_range;
            total.relocated += c.relocated;
            total.string += c.string;
            total.code += c.code;
            total.region_start += c.region_start;
            for (value, count) in c.values {
                *total.values.entry(value).or_default() += count;
            }
        }
    }
    for (arch, c) in per_arch {
        let mut top: Vec<(u64, String)> = c.values.iter().map(|(v, n)| (*n, v.clone())).collect();
        top.sort_by(|a, b| b.cmp(a));
        top.truncate(25);
        println!(
            "{}",
            json!({
                "arch": arch,
                "functions": c.functions,
                "functions_with_in_range_const": c.with_in_range,
                "const_records": c.consts,
                "in_range_const_records": c.in_range,
                "decoded_in_range_values": c.raw_in_range,
                "relocated_site": c.relocated,
                "points_at_string": c.string,
                "points_at_code": c.code,
                "region_start": c.region_start,
                "top_in_range": top,
            })
        );
    }
}
