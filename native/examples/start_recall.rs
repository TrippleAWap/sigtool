//! Function-start recall and precision on stripped images (G4).
//!
//! ```text
//! cargo run --release --example start_recall -- CORPUS [--arch A] [--misses]
//! ```
//!
//! `CORPUS` is a real-corpus build directory (`ARCH/BUILD/LIB.so` beside
//! `stripped/ARCH/BUILD/LIB.so`). The function list a hint-free scan sees
//! (`unwind_entries` of the stripped copy) is compared with the `.symtab`
//! FUNC symbols of the unstripped copy, which serve only as labels. A
//! symbol counts when it lies in scanned code (not the PLT). `--misses`
//! prints every missed start and every false start with the nearest symbol,
//! so misses can be sorted by cause.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sigtool_native::elf::FileSource;
use sigtool_native::source::ByteSource;

fn scanned(source: &FileSource, address: u64) -> bool {
    source.regions().iter().any(|region| {
        region.executable
            && !region.name.starts_with(".plt")
            && region.name != ".iplt"
            && region.start <= address
            && address < region.end()
    })
}

fn category(name: &str) -> &'static str {
    if name.contains(".cold") {
        "cold"
    } else if name.contains(".part.") {
        "part"
    } else if name.contains(".isra.") || name.contains(".constprop.") {
        "clone"
    } else if name.contains("Thunk_") || name.contains("_veneer") {
        "thunk"
    } else if name.starts_with("__aeabi")
        || name.starts_with("__gnu_")
        || ["__udiv", "__div", "__umod", "__mod", "__clz", "__ctz"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        || name.ends_with("df3")
        || name.ends_with("sf3")
        || name.ends_with("di3")
        || name.ends_with("sidf")
        || name.ends_with("disf")
        || name.ends_with("didf")
    {
        "libgcc"
    } else if matches!(
        name,
        "_init"
            | "_fini"
            | "_start"
            | "frame_dummy"
            | "register_tm_clones"
            | "deregister_tm_clones"
            | "__do_global_dtors_aux"
            | "call_weak_fn"
    ) {
        "crt"
    } else {
        "other"
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let corpus = Path::new(&args[0]);
    let mut arches: Vec<String> = Vec::new();
    let mut misses = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--arch" => {
                arches.push(args[index + 1].clone());
                index += 1;
            }
            "--misses" => misses = true,
            other => panic!("unknown argument {other}"),
        }
        index += 1;
    }
    if arches.is_empty() {
        arches = ["x64", "arm64", "arm32", "thumb"]
            .map(String::from)
            .to_vec();
    }
    for arch in &arches {
        let mut builds: Vec<_> = std::fs::read_dir(corpus.join(arch))
            .expect("arch dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        builds.sort();
        let mut arch_truth = 0usize;
        let mut arch_hit = 0usize;
        let mut arch_found = 0usize;
        let mut arch_false = 0usize;
        let mut arch_categories: BTreeMap<&str, usize> = BTreeMap::new();
        for build in &builds {
            let mut libraries: Vec<_> = std::fs::read_dir(corpus.join(arch).join(build))
                .expect("build dir")
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().to_string())
                .collect();
            libraries.sort();
            let (mut truth_n, mut hit_n, mut found_n, mut false_n) = (0, 0, 0, 0);
            for library in &libraries {
                let full = FileSource::from_path(corpus.join(arch).join(build).join(library))
                    .expect("unstripped image");
                let stripped = FileSource::from_path(
                    corpus.join("stripped").join(arch).join(build).join(library),
                )
                .expect("stripped image");
                let names: BTreeMap<u64, String> = full.modules()[0]
                    .functions
                    .iter()
                    .filter(|(address, _)| scanned(&full, **address))
                    .map(|(address, name)| (*address, name.clone()))
                    .collect();
                let truth: BTreeSet<u64> = names.keys().copied().collect();
                let found: BTreeSet<u64> = stripped
                    .unwind_entries()
                    .iter()
                    .map(|(start, _)| *start)
                    .filter(|start| scanned(&stripped, *start))
                    .collect();
                let hit = truth.intersection(&found).count();
                truth_n += truth.len();
                hit_n += hit;
                found_n += found.len();
                false_n += found.len() - hit;
                for address in truth.difference(&found) {
                    let name = &names[address];
                    *arch_categories.entry(category(name)).or_default() += 1;
                    if misses {
                        println!("MISS {arch}/{build}/{library} {address:#x} {name}");
                    }
                }
                if misses {
                    for address in found.difference(&truth) {
                        let near = names
                            .range(..=*address)
                            .next_back()
                            .map(|(start, name)| format!("{name}+{:#x}", address - start))
                            .unwrap_or_default();
                        println!("FALSE {arch}/{build}/{library} {address:#x} {near}");
                    }
                }
            }
            println!(
                "{arch:6} {build:8} recall {:.4} ({hit_n}/{truth_n}) precision {:.4} ({false_n} false)",
                hit_n as f64 / truth_n.max(1) as f64,
                (found_n - false_n) as f64 / found_n.max(1) as f64,
            );
            arch_truth += truth_n;
            arch_hit += hit_n;
            arch_found += found_n;
            arch_false += false_n;
        }
        println!(
            "{arch:6} ALL      recall {:.4} ({arch_hit}/{arch_truth}) precision {:.4} ({arch_false} false) misses {:?}",
            arch_hit as f64 / arch_truth.max(1) as f64,
            (arch_found - arch_false) as f64 / arch_found.max(1) as f64,
            arch_categories,
        );
    }
}
