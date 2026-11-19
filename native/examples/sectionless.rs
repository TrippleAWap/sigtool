//! Section-less ELF agreement (G4): what `llvm-objcopy --strip-sections`
//! leaves of each stripped real-corpus image, read as hint-free discovery
//! reads it, against the `--strip-all` copy it came from.
//!
//! ```text
//! cargo run --release --example sectionless -- CORPUS SCRATCH [MAX_FUNCTIONS]
//! ```
//!
//! For every `stripped` image in `CORPUS/ground_truth.json`, writes the
//! section-less copy to `SCRATCH` (`llvm-objcopy` from `PATH`), then prints
//! one JSON line per image: function starts (unwind entries, synthesized
//! starts), whether the module tables (exports, imports, relocations) agree,
//! and, for the first `MAX_FUNCTIONS` ground-truth functions by name (default
//! 4), whether a signature from the unstripped image gets the same first
//! hint-free match (address, score, identified) in both copies, and how
//! often that match is identified at the signed start in each. A last line
//! sums them.

use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{identified_answer, scan_in, ScanContext};
use sigtool_native::source::ByteSource;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(corpus), Some(scratch)) = (args.first(), args.get(1)) else {
        panic!("usage: sectionless CORPUS SCRATCH [MAX_FUNCTIONS]");
    };
    let limit: usize = args.get(2).map_or(4, |text| text.parse().expect("count"));
    let (corpus, scratch) = (Path::new(corpus), Path::new(scratch));
    let truth: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("ground_truth.json")).unwrap()).unwrap();
    // images, tables agree, starts agree, signed, same first match, and
    // identified at the right start: with sections, without
    let mut totals = [0u64; 7];
    for entry in truth["binaries"].as_array().unwrap() {
        let Some(stripped) = entry["stripped"].as_str() else {
            continue;
        };
        let output = scratch.join(stripped);
        std::fs::create_dir_all(output.parent().unwrap()).unwrap();
        let status = Command::new("llvm-objcopy")
            .arg("--strip-sections")
            .arg(corpus.join(stripped))
            .arg(&output)
            .status()
            .expect("run llvm-objcopy");
        assert!(status.success(), "llvm-objcopy {stripped}");
        let original = FileSource::from_path(corpus.join(stripped)).unwrap();
        let sectionless = match FileSource::from_path(&output) {
            Ok(source) => source,
            Err(error) => {
                println!("{}", json!({"image": stripped, "error": error.to_string()}));
                totals[0] += 1;
                continue;
            }
        };
        let (want, got) = (&original.modules()[0], &sectionless.modules()[0]);
        let tables = want.exports == got.exports
            && want.imports == got.imports
            && want.relocations == got.relocations;
        let starts = original.unwind_entries() == sectionless.unwind_entries();

        let image = FileSource::from_path(corpus.join(entry["path"].as_str().unwrap())).unwrap();
        let mut functions: Vec<(&str, u64)> = entry["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| (f["name"].as_str().unwrap(), f["start"].as_u64().unwrap()))
            .collect();
        functions.sort();
        functions.truncate(limit);
        let contexts = [
            ScanContext::build(&original),
            ScanContext::build(&sectionless),
        ];
        let (mut signed, mut same) = (0u64, 0u64);
        let mut right = [0u64; 2];
        for (_, start) in &functions {
            let Ok(result) = generate_in(&image, *start, None, None, None, None, None, None) else {
                continue;
            };
            signed += 1;
            let first = |source: &FileSource, context: &ScanContext| {
                let found = scan_in(source, &result.signature, context, false);
                found
                    .first()
                    .map(|m| (m.address, m.score.to_bits(), identified_answer(&found)))
            };
            let answers = [
                first(&original, &contexts[0]),
                first(&sectionless, &contexts[1]),
            ];
            if answers[0] == answers[1] {
                same += 1;
            }
            for (count, answer) in right.iter_mut().zip(&answers) {
                *count += u64::from(answer.is_some_and(|(at, _, named)| at == *start && named));
            }
        }
        println!(
            "{}",
            json!({
                "image": stripped,
                "unwind": [original.unwind_entries().len(), sectionless.unwind_entries().len()],
                "synthesized": [original.synthesized_starts().len(), sectionless.synthesized_starts().len()],
                "base": [want.base, got.base],
                "tables_agree": tables,
                "starts_agree": starts,
                "signed": signed,
                "same_first_match": same,
                "identified_right": right,
            })
        );
        for (total, value) in totals.iter_mut().zip([
            1,
            u64::from(tables),
            u64::from(starts),
            signed,
            same,
            right[0],
            right[1],
        ]) {
            *total += value;
        }
    }
    println!(
        "{}",
        json!({
            "images": totals[0],
            "tables_agree": totals[1],
            "starts_agree": totals[2],
            "signed": totals[3],
            "same_first_match": totals[4],
            "identified_right": [totals[5], totals[6]],
        })
    );
}
