//! Golden-vector baseline: the native extractor currently reproduces the
//! Python reference feature records byte for byte. The port's bar is to be at
//! least as good as the reference, so equality here is the baseline rather than
//! the goal: an intentional native improvement updates these expectations
//! explicitly, with its measurement recorded in `PLAN.md`.
//!
//! The vectors' bytes come from real clang + lld output
//! (`tests/vectors/generate.py`). After an intentional feature change, run
//! `SIGTOOL_BLESS=1 cargo test --test golden` to rewrite the expected records
//! from the native extractor, then review the diff. x86-64 is the reference architecture; AArch64, ARM32, and Thumb
//! are ported second, and every vector is compared with no skips.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sigtool_native::arch::Arch;
use sigtool_native::features::extract;
use sigtool_native::recover::recover;
use sigtool_native::source::{MemorySource, Module, Region};

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("tests")
        .join("vectors")
}

fn source_from_vector(vector: &Value) -> MemorySource {
    source_from_vector_at(vector, 0)
}

/// The vector's image loaded `delta` bytes above its link address, as a
/// loader would: every section moves and every relocated word that holds an
/// in-image address is adjusted. Only a vector with `relocations` (a shared
/// object) may be moved.
fn source_from_vector_at(vector: &Value, delta: u64) -> MemorySource {
    let arch_text = vector["arch"].as_str().expect("arch");
    let arch_text = arch_text
        .replace("-pac", "")
        .replace("-cet", "")
        .replace("-pic", "");
    let arch = Arch::parse(&arch_text).expect("known arch");
    let relocations: Option<Vec<u64>> = vector.get("relocations").map(|slots| {
        slots
            .as_array()
            .expect("relocations")
            .iter()
            .map(|slot| slot.as_u64().expect("relocation slot"))
            .collect()
    });
    assert!(
        delta == 0 || relocations.is_some(),
        "only a relocatable vector can be moved"
    );

    let mut regions = Vec::new();
    for section in vector["sections"].as_array().expect("sections") {
        let name = section["name"].as_str().expect("section name").to_string();
        let start = section["addr"].as_u64().expect("section addr");
        let bytes = section["bytes"].as_str().expect("section bytes");
        let data = hex_decode(bytes);
        let executable = section["executable"].as_bool().unwrap_or(false);
        regions.push(Region::new(name, start, data, executable, false));
    }
    let base = regions.iter().map(|region| region.start).min().unwrap();
    let end = regions.iter().map(|region| region.end()).max().unwrap();
    if delta != 0 {
        let width = arch.pointer_size();
        for slot in relocations.iter().flatten() {
            let Some(region) = regions
                .iter_mut()
                .find(|region| region.contains(*slot, width))
            else {
                continue;
            };
            let offset = (*slot - region.start) as usize;
            let mut word = [0u8; 8];
            word[..width].copy_from_slice(&region.data[offset..offset + width]);
            let value = u64::from_le_bytes(word);
            if value != 0 && base <= value && value < end {
                let moved = (value + delta).to_le_bytes();
                region.data[offset..offset + width].copy_from_slice(&moved[..width]);
            }
        }
        for region in &mut regions {
            region.start += delta;
        }
    }

    let mut functions = HashMap::new();
    let mut exports = Vec::new();
    let mut hints = Vec::new();
    for (name, info) in vector["functions"].as_object().expect("functions") {
        let entry = info["entry"].as_u64().expect("entry") + delta;
        let function_end = info
            .get("end")
            .and_then(Value::as_u64)
            .map_or(entry, |end| end + delta);
        functions.insert(entry, name.clone());
        exports.push((name.clone(), entry));
        hints.push((entry, function_end));
    }

    let module = Module {
        name: "fixture".to_string(),
        base: base + delta,
        image_base: base + delta,
        size: end - base,
        path: None,
        exports,
        functions,
        imports: HashMap::new(),
        relocations: relocations.map(|slots| slots.into_iter().map(|slot| slot + delta).collect()),
    };
    MemorySource::new(arch, regions, vec![module], hints, Vec::new())
}

fn hex_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let high = (bytes[index] as char).to_digit(16).expect("hex");
        let low = (bytes[index + 1] as char).to_digit(16).expect("hex");
        out.push(((high << 4) | low) as u8);
        index += 2;
    }
    out
}

/// Rewrite every function's expected records from the native extractor.
fn bless_vector(vector: &mut Value) {
    let source = source_from_vector(vector);
    let functions = vector["functions"].as_object_mut().expect("functions");
    for (name, info) in functions.iter_mut() {
        let entry = info["entry"].as_u64().expect("entry");
        let recovered =
            recover(&source, entry, None, true).unwrap_or_else(|error| panic!("{name}: {error}"));
        let features: Vec<Value> = extract(&source, &recovered)
            .iter()
            .map(|feature| {
                // Inherited callee evidence (SPEC.md §1.4) is marked; own
                // records keep their two-field form.
                let mut record =
                    serde_json::json!({"kind": feature.kind.as_str(), "value": feature.value});
                if feature.inherited {
                    record["inherited"] = true.into();
                }
                record
            })
            .collect();
        info["features"] = Value::Array(features);
        info["blocks"] = recovered.block_count().into();
        info["edges"] = recovered.edge_count().into();
        info["loops"] = recovered.loop_count().into();
        info["degraded"] = recovered.degraded.into();
    }
}

#[test]
fn golden_vectors_match_reference_features() {
    let mut checked = 0usize;
    let mut files: Vec<PathBuf> = std::fs::read_dir(vector_dir())
        .expect("vector directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();

    let bless = std::env::var_os("SIGTOOL_BLESS").is_some();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("vector file");
        let mut vector: Value = serde_json::from_str(&text).expect("vector json");
        if bless {
            bless_vector(&mut vector);
            // One-space indent, sorted keys: the format the vectors were written in.
            let mut buffer = Vec::new();
            let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
            let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
            serde::Serialize::serialize(&vector, &mut serializer).expect("vector json");
            let mut out = String::from_utf8(buffer).expect("utf-8");
            out.push('\n');
            // A CRLF checkout of an unchanged vector is not a change.
            if out != text.replace("\r\n", "\n") {
                std::fs::write(&path, out).expect("write vector");
                eprintln!("blessed {}", path.display());
            }
        }
        let source = source_from_vector(&vector);
        let functions = vector["functions"].as_object().expect("functions");
        for (name, info) in functions {
            let entry = info["entry"].as_u64().expect("entry");
            let recovered = recover(&source, entry, None, true)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            let features = extract(&source, &recovered);
            let actual: Vec<(String, String, bool)> = features
                .iter()
                .map(|feature| {
                    (
                        feature.kind.as_str().to_string(),
                        feature.value.clone(),
                        feature.inherited,
                    )
                })
                .collect();
            let expected: Vec<(String, String, bool)> = info["features"]
                .as_array()
                .expect("features")
                .iter()
                .map(|item| {
                    (
                        item["kind"].as_str().expect("kind").to_string(),
                        item["value"].as_str().expect("value").to_string(),
                        item["inherited"].as_bool().unwrap_or(false),
                    )
                })
                .collect();
            assert_eq!(actual, expected, "{name} in {}", path.display());
            assert_eq!(
                recovered.block_count(),
                info["blocks"].as_u64().unwrap() as usize,
                "{name} blocks"
            );
            assert_eq!(
                recovered.edge_count(),
                info["edges"].as_u64().unwrap() as usize,
                "{name} edges"
            );
            assert_eq!(
                recovered.loop_count(),
                info["loops"].as_u64().unwrap() as usize,
                "{name} loops"
            );
            assert_eq!(
                recovered.degraded,
                info["degraded"].as_bool().unwrap_or(false),
                "{name} degraded"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no golden functions were checked");
}

/// Rule 4: the same shared object loaded at two bases yields identical
/// features. A shared object links at 0, so its constants also look like
/// in-image addresses there and not at a high base; only how a value is used
/// (a relocated word, a PC-relative address) may decide what it is.
#[test]
fn relocatable_vectors_give_identical_features_at_two_bases() {
    let mut checked = 0usize;
    for entry in std::fs::read_dir(vector_dir()).expect("vector directory") {
        let path = entry.expect("vector entry").path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let vector: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file"))
                .expect("vector json");
        if vector.get("relocations").is_none() {
            continue;
        }
        let delta = 0x4000_0000;
        let low = source_from_vector(&vector);
        let high = source_from_vector_at(&vector, delta);
        for (name, info) in vector["functions"].as_object().expect("functions") {
            let entry = info["entry"].as_u64().expect("entry");
            let at_low =
                recover(&low, entry, None, true).unwrap_or_else(|error| panic!("{name}: {error}"));
            let at_high = recover(&high, entry + delta, None, true)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                extract(&low, &at_low),
                extract(&high, &at_high),
                "{name} in {}",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no relocatable vector was checked");
}
