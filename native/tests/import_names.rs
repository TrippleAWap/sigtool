//! The same source calling an imported function gives the same callee key
//! in an ELF shared object (`*!name`: ELF never records the providing
//! library) and in a PE DLL, whose import names its DLL (SPEC.md §2.1).

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const SOURCE: &str = r#"
int external_helper(int);
int wrap(int x) { return external_helper(x * 7) + 3; }
"#;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sigtool-imports-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("wrap.c"), SOURCE).unwrap();
    // The import library a real DLL links against, as the PE tier makes it.
    std::fs::write(
        dir.join("ucrtbase.def"),
        "LIBRARY ucrtbase\nEXPORTS\n  external_helper\n",
    )
    .unwrap();
    dir
}

fn tool(program: &str, args: &[&str], dir: &Path) {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(status.success(), "{program} {args:?} failed");
}

/// The callee keys of `gen`'s signature for the export `wrap` of `image`.
fn callees(image: &Path, rva: &str) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(["gen", "--file", image.to_str().unwrap(), "--rva", rva])
        .output()
        .expect("run sigtool-native");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    yaml.lines()
        .collect::<Vec<_>>()
        .windows(2)
        .filter(|pair| pair[0].trim_start() == "- kind: callee")
        .map(|pair| {
            let value = pair[1].trim().trim_start_matches("value: ");
            value.trim_matches('\'').to_string()
        })
        .collect()
}

fn export_rva(listing: &str, name: &str) -> String {
    // `llvm-nm` on the shared object: "ADDRESS T name", base 0.
    listing
        .lines()
        .find(|line| line.ends_with(&format!(" {name}")))
        .and_then(|line| line.split_whitespace().next())
        .map(|text| format!("0x{}", text.trim_start_matches('0')))
        .expect("symbol in listing")
}

#[test]
fn elf_and_pe_imports_give_the_same_callee_key() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-readobj"]) {
        return;
    }
    let dir = scratch();
    tool(
        "clang",
        &[
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            "wrap.c",
            "-o",
            "libwrap.so",
        ],
        &dir,
    );
    tool(
        "clang",
        &[
            "--target=x86_64-pc-windows-msvc",
            "-O2",
            "-c",
            "wrap.c",
            "-o",
            "wrap.obj",
        ],
        &dir,
    );
    tool(
        "ld.lld",
        &[
            "-flavor",
            "link",
            "/lib",
            "/machine:x64",
            "/def:ucrtbase.def",
            "/out:ucrtbase.lib",
        ],
        &dir,
    );
    tool(
        "ld.lld",
        &[
            "-flavor",
            "link",
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/export:wrap",
            "/out:wrap.dll",
            "wrap.obj",
            "ucrtbase.lib",
        ],
        &dir,
    );

    let nm = Command::new("llvm-nm")
        .arg(dir.join("libwrap.so"))
        .output()
        .expect("run llvm-nm");
    let elf_rva = export_rva(&String::from_utf8(nm.stdout).unwrap(), "wrap");
    let exports = Command::new("llvm-readobj")
        .args(["--coff-exports"])
        .arg(dir.join("wrap.dll"))
        .output()
        .expect("run llvm-readobj");
    let exports = String::from_utf8(exports.stdout).unwrap();
    let pe_rva = exports
        .lines()
        .find_map(|line| line.trim().strip_prefix("RVA: "))
        .expect("export RVA")
        .to_string();

    let elf = callees(&dir.join("libwrap.so"), &elf_rva);
    let pe = callees(&dir.join("wrap.dll"), &pe_rva);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        elf.contains(&"*!external_helper".to_string()),
        "ELF: {elf:?}"
    );
    assert_eq!(elf, pe, "ELF {elf:?} vs PE {pe:?}");
}
