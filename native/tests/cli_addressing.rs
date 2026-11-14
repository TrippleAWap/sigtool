//! Front-end addressing contract: an RVA is relative to the image base (the
//! lowest `PT_LOAD` address), so `--rva`, `FILE:+RVA` merge samples, and the
//! `rva` that `locate --json` reports agree with readelf and disassemblers.
//! The IDA plugin relies on this to work on rebased databases.

use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("corpus")
        .join("build");
    root.join("ground_truth.json").exists().then_some(root)
}

fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(args)
        .output()
        .expect("run sigtool-native");
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8")
}

/// The lowest PT_LOAD address and a function's (name, start) from `.symtab`,
/// read here without the crate so the test checks it against the ELF itself.
fn load_base_and_function(path: &Path) -> (u64, u64) {
    let data = std::fs::read(path).expect("read image");
    let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    assert_eq!(data[4], 2, "fixture is ELF64");
    let (phoff, phentsize, phnum) = (u64_at(0x20) as usize, u16_at(0x36), u16_at(0x38));
    let base = (0..phnum)
        .map(|i| phoff + i * phentsize)
        .filter(|o| u32_at(*o) == 1)
        .map(|o| u64_at(o + 0x10))
        .min()
        .expect("PT_LOAD");
    let (shoff, shentsize, shnum) = (u64_at(0x28) as usize, u16_at(0x3A), u16_at(0x3C));
    let section = |i: usize| shoff + i * shentsize;
    let symtab = (0..shnum)
        .map(section)
        .find(|o| u32_at(o + 4) == 2)
        .expect(".symtab");
    let strtab = section(u32_at(symtab + 0x28) as usize);
    let (sym_off, sym_size) = (
        u64_at(symtab + 0x18) as usize,
        u64_at(symtab + 0x20) as usize,
    );
    let str_off = u64_at(strtab + 0x18) as usize;
    for entry in (sym_off..sym_off + sym_size).step_by(24) {
        let name_at = str_off + u32_at(entry) as usize;
        let end = data[name_at..].iter().position(|b| *b == 0).unwrap();
        if &data[name_at..name_at + end] == b"accumulate" {
            return (base, u64_at(entry + 8));
        }
    }
    panic!("accumulate not in {}", path.display());
}

#[test]
fn rva_addressing_matches_the_image_base() {
    let Some(corpus) = corpus() else {
        eprintln!("skip: corpus/build is absent (python corpus/build.py)");
        return;
    };
    let x64 = corpus.join("x64").join("O2").join("loops.elf");
    let arm64 = corpus.join("arm64").join("O2").join("loops.elf");
    let (x64_base, x64_start) = load_base_and_function(&x64);
    let (arm_base, arm_start) = load_base_and_function(&arm64);
    let x64_rva = format!("0x{:x}", x64_start - x64_base);
    let arm_rva = format!("0x{:x}", arm_start - arm_base);
    let (x64_path, arm_path) = (x64.to_str().unwrap(), arm64.to_str().unwrap());

    let by_rva = run(&["gen", "--file", x64_path, "--rva", &x64_rva]);
    let by_addr = run(&[
        "gen",
        "--file",
        x64_path,
        "--addr",
        &format!("0x{x64_start:x}"),
    ]);
    assert_eq!(by_rva, by_addr);
    assert!(by_rva.contains(&format!("rva: '{x64_rva}'")), "{by_rva}");

    let absolute = run(&[
        "merge",
        "--sample",
        &format!("{x64_path}:0x{x64_start:x}"),
        "--sample",
        &format!("{arm_path}:0x{arm_start:x}"),
    ]);
    let relative = run(&[
        "merge",
        "--sample",
        &format!("{x64_path}:+{x64_rva}"),
        "--sample",
        &format!("{arm_path}:+{arm_rva}"),
    ]);
    assert_eq!(absolute, relative);

    let dir = std::env::temp_dir().join(format!("sigtool-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let signature = dir.join("merged.yaml");
    let matches = dir.join("matches.json");
    std::fs::write(&signature, &relative).unwrap();
    run(&[
        "locate",
        "--signature",
        signature.to_str().unwrap(),
        "--file",
        arm_path,
        "--json",
        matches.to_str().unwrap(),
        "--yes",
    ]);
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&matches).unwrap()).unwrap();
    std::fs::remove_file(&signature).ok();
    std::fs::remove_file(&matches).ok();
    std::fs::remove_dir(&dir).ok();
    let best = &document["matches"][0];
    assert_eq!(best["rva"], serde_json::Value::String(arm_rva));
    assert_eq!(best["module"], "loops");
}
