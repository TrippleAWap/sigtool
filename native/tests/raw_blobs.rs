//! Raw code blobs (`--raw FILE --arch A --base ADDR`): the `.text` of a
//! clang-built AArch64 and Thumb executable, cut out with `llvm-objcopy -O
//! binary` and mapped at its own address, must still give up functions
//! signed from the ELF it came from. The blob has no symbols, relocations,
//! unwind tables, or data: starts are synthesized from the code alone and
//! discovery is hint-free.

use std::path::{Path, PathBuf};
use std::process::Command;

use sigtool_native::arch::Arch;
use sigtool_native::elf::FileSource;
use sigtool_native::generate::generate_in;
use sigtool_native::matcher::{rank_key, scan_in, ScanContext};
use sigtool_native::source::ByteSource;

mod common;

/// Functions with their own constants and branches (no strings or globals:
/// the blob holds code only), all called from `_start` so that each is a
/// direct call target.
const FUNCTIONS: u32 = 40;

fn source() -> String {
    let mut code = String::new();
    for n in 0..FUNCTIONS {
        code.push_str(&format!(
            "__attribute__((noinline)) unsigned f{n}(unsigned x, unsigned y) {{\n\
             \x20   unsigned a = x * 0x{:x}u;\n\
             \x20   if (a > y)\n\
             \x20       a ^= 0x{:x}u;\n\
             \x20   return a + (y >> {});\n\
             }}\n",
            0x9e37_0000u32 + n * 0x101,
            0x5bd1_0000u32 + n * 0x11,
            n % 7 + 1
        ));
    }
    code.push_str("void _start(void) {\n    volatile unsigned sink = 1;\n");
    for n in 0..FUNCTIONS {
        code.push_str(&format!("    sink = f{n}(sink, {n}u);\n"));
    }
    code.push_str("    for (;;) {}\n}\n");
    code
}

fn run(command: &mut Command, what: &str) -> std::process::Output {
    let output = command.output().unwrap_or_else(|_| panic!("run {what}"));
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A static, non-PIC executable for `target` and its `.text` as a raw blob.
fn build(dir: &Path, name: &str, target: &str, extra: &[&str]) -> (PathBuf, PathBuf) {
    let source = dir.join(format!("{name}.c"));
    std::fs::write(&source, self::source()).unwrap();
    let image = dir.join(format!("{name}.elf"));
    run(
        Command::new("clang")
            .arg(format!("--target={target}"))
            .args([
                "-O1",
                "-ffreestanding",
                "-nostdlib",
                "-fno-pic",
                "-no-pie",
                "-static",
                "-fuse-ld=lld",
            ])
            .args(extra)
            .arg(&source)
            .arg("-o")
            .arg(&image),
        "clang",
    );
    let blob = dir.join(format!("{name}.bin"));
    run(
        Command::new("llvm-objcopy")
            .args(["-O", "binary", "--only-section=.text"])
            .arg(&image)
            .arg(&blob),
        "llvm-objcopy",
    );
    (image, blob)
}

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(args)
        .output()
        .expect("run sigtool-native")
}

/// Functions signed from the ELF that the blob's hint-free scan puts first,
/// strictly, at the same address; and how many were tried.
fn agreement(elf: &FileSource, blob: &FileSource) -> (usize, usize) {
    let elf_context = ScanContext::build(elf);
    let blob_context = ScanContext::build(blob);
    let mask = if elf.arch().is_arm() { !1u64 } else { !0u64 };
    let module = &elf.modules()[0];
    let mut wanted: Vec<(String, u64)> = (0..FUNCTIONS)
        .filter_map(|n| {
            let name = format!("f{n}");
            let address = module
                .functions
                .iter()
                .find(|(_, symbol)| **symbol == name)
                .map(|(address, _)| address & mask)?;
            Some((name, address))
        })
        .collect();
    wanted.sort();
    assert_eq!(wanted.len(), FUNCTIONS as usize, "every fN has a symbol");
    let mut found = 0;
    for (name, address) in &wanted {
        let signature = generate_in(
            elf,
            *address,
            Some(name),
            None,
            None,
            None,
            None,
            Some(&elf_context),
        )
        .unwrap_or_else(|error| panic!("sign {name}: {error}"))
        .signature;
        let matches = scan_in(blob, &signature, &blob_context, false);
        let first = matches.first().map(|m| m.address) == Some(*address);
        let tied = matches
            .get(1)
            .is_some_and(|next| rank_key(next) == rank_key(&matches[0]));
        if first && !tied {
            found += 1;
        }
    }
    (found, wanted.len())
}

/// Minimum agreement out of [`FUNCTIONS`]: what each blob measured when raw
/// input landed (LLVM 22.1.5), so a regression in start synthesis or the
/// module-range rule shows. x86-64 has no code-only start sweep; its starts
/// are the call targets reachable from the blob's first byte.
const MIN_AGREEMENT: [(&str, usize); 3] = [("arm64", 40), ("thumb", 40), ("x64", 40)];

#[test]
fn functions_signed_in_an_elf_are_found_in_its_raw_text() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-objcopy"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-raw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, target, extra, arch) in [
        ("arm64", "aarch64-linux-gnu", &[][..], Arch::Arm64),
        (
            "thumb",
            "armv7-linux-gnueabihf",
            &["-mthumb"][..],
            Arch::Thumb,
        ),
        ("x64", "x86_64-linux-gnu", &[][..], Arch::X64),
    ] {
        let (image, blob_path) = build(&dir, name, target, extra);
        let elf = FileSource::from_path(&image).expect("elf");
        let text = elf
            .regions()
            .iter()
            .find(|region| region.name == ".text")
            .expect(".text")
            .start;
        let bytes = std::fs::read(&blob_path).unwrap();
        let blob = FileSource::from_raw(&bytes, "blob.bin", arch, text).expect("raw");
        assert!(blob.symbols_stripped(), "a raw blob names no function");
        assert!(blob.modules()[0].relocations.is_none());
        let (found, tried) = agreement(&elf, &blob);
        eprintln!(
            "{name}: {found}/{tried} signed in the ELF found first in the raw .text \
             ({} synthesized starts)",
            blob.unwind_entries().len()
        );
        let floor = MIN_AGREEMENT
            .iter()
            .find(|(arch, _)| *arch == name)
            .map(|(_, floor)| *floor)
            .unwrap();
        assert!(found >= floor, "{name}: {found}/{tried} < {floor}");

        // The same through the CLI: sign from the ELF by symbol address,
        // locate in the blob, and read the answer from the JSON.
        let module = &elf.modules()[0];
        let address = module
            .functions
            .iter()
            .find(|(_, symbol)| symbol.as_str() == "f7")
            .map(|(address, _)| address & !1)
            .expect("f7");
        let signature = dir.join(format!("{name}-f7.yaml"));
        let json = dir.join(format!("{name}-f7.json"));
        let output = cli(&[
            "gen",
            "--file",
            image.to_str().unwrap(),
            "--addr",
            &format!("0x{address:x}"),
            "--output",
            signature.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "gen: {output:?}");
        let base = format!("0x{text:x}");
        let raw_args = [
            "--raw",
            blob_path.to_str().unwrap(),
            "--arch",
            arch.as_str(),
            "--base",
            &base,
        ];
        let mut args = vec![
            "locate",
            "--signature",
            signature.to_str().unwrap(),
            "--json",
            json.to_str().unwrap(),
            "--yes",
        ];
        args.extend(raw_args);
        let output = cli(&args);
        assert!(output.status.success(), "locate --raw: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("hint-free discovery"));
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        assert_eq!(
            document["matches"][0]["address"],
            format!("0x{address:x}"),
            "{name}: {document}"
        );
        assert_eq!(
            document["matches"][0]["rva"],
            format!("0x{:x}", address - text)
        );

        // A blob has no symbols to hint with: asking for hints is refused.
        args.extend(["--discovery", "hinted"]);
        assert_eq!(cli(&args).status.code(), Some(2), "{name}: hinted --raw");
    }
    // --raw needs its architecture and base.
    let output = cli(&[
        "locate",
        "--signature",
        "unused.yaml",
        "--raw",
        "unused.bin",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
