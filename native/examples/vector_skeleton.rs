//! Golden-vector skeleton: the sections and named function bounds of one
//! fixture ELF, as JSON on stdout. `tests/vectors/generate.py` wraps it with
//! the build metadata, and `SIGTOOL_BLESS=1 cargo test --test golden` fills in
//! the feature records from the extractor.
//!
//! Usage: `vector_skeleton IMAGE NAME...`. The image is loaded as
//! `fixture.elf` so `module+rva` callee labels stay independent of the path.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use sigtool_native::elf::FileSource;
use sigtool_native::source::ByteSource;
use sigtool_native::spec::SPEC_VERSION;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: vector_skeleton IMAGE NAME...");
    let wanted: Vec<String> = args.collect();
    let data = std::fs::read(&path).expect("read image");
    let image = FileSource::from_bytes(&data, "fixture.elf").expect("parse image");

    let sections: Vec<Value> = image
        .regions()
        .iter()
        .filter(|region| !region.data.is_empty())
        .map(|region| {
            json!({
                "name": region.name,
                "addr": region.start,
                "executable": region.executable,
                "bytes": hex(&region.data),
            })
        })
        .collect();

    let module = &image.modules()[0];
    let mut by_name: Vec<(&String, u64)> = module
        .functions
        .iter()
        .map(|(address, name)| (name, *address))
        .collect();
    by_name.sort();
    let mut functions: BTreeMap<String, Value> = BTreeMap::new();
    for (name, address) in by_name {
        if !wanted.contains(name) || functions.contains_key(name) {
            continue;
        }
        let (_, end) = image
            .hint_function(address)
            .expect("fixture symbols carry sizes");
        functions.insert(
            name.clone(),
            json!({"entry": address, "end": end, "features": []}),
        );
    }

    let skeleton = json!({
        "spec_version": SPEC_VERSION,
        "sections": sections,
        "functions": functions,
    });
    println!("{skeleton}");
}
