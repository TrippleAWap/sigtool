//! Hint-free recovery coverage per corpus image: how much of each ground-truth
//! function's body the bounded recovery reaches on the stripped copy, and
//! whether a block ended in an indirect jump (a switch table the walk could
//! not follow). Ground truth only supplies starts and sizes.
//!
//! Usage: `recovery_coverage CORPUS [ARCH...]`, one summary line per image.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;
use sigtool_native::elf::FileSource;
use sigtool_native::normalize::Kind;
use sigtool_native::recover::recover;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = Path::new(&args[0]);
    let arches: HashSet<&str> = args[1..].iter().map(String::as_str).collect();
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    for entry in truth["binaries"].as_array().unwrap() {
        let path = entry["path"].as_str().unwrap();
        let arch = path.split('/').next().unwrap();
        if !arches.is_empty() && !arches.contains(arch) {
            continue;
        }
        let Some(stripped) = entry["stripped"].as_str() else {
            continue;
        };
        let image = FileSource::from_path(corpus.join(stripped)).unwrap();
        let functions: Vec<(u64, u64)> = entry["functions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| Some((f["start"].as_u64()?, f["size"].as_u64()?)))
            .filter(|(_, size)| *size > 0)
            .collect();
        let results = sigtool_native::parallel::map(functions.len(), |index| {
            let (start, size) = functions[index];
            let Ok(found) = recover(&image, start, None, false) else {
                return (0.0, false, false);
            };
            let covered: u64 = found
                .blocks
                .iter()
                .flat_map(|block| block.insns.iter())
                .map(|insn| insn.size as u64)
                .sum();
            let indirect = found.blocks.iter().any(|block| {
                block.insns.last().is_some_and(|insn| {
                    insn.kind == Kind::Jump && insn.target.is_none() && insn.callee.is_none()
                })
            });
            (
                (covered as f64 / size as f64).min(1.0),
                indirect,
                found.degraded,
            )
        });
        let n = results.len().max(1) as f64;
        let low = results.iter().filter(|r| r.0 < 0.9).count();
        let indirect = results.iter().filter(|r| r.1).count();
        let low_indirect = results.iter().filter(|r| r.0 < 0.9 && r.1).count();
        let mean: f64 = results.iter().map(|r| r.0).sum::<f64>() / n;
        println!(
            "{path:32} n={:5} mean_cov={mean:.3} cov<0.9={:.3} indirect={:.3} cov<0.9&indirect={:.3}",
            results.len(),
            low as f64 / n,
            indirect as f64 / n,
            low_indirect as f64 / n
        );
    }
}
