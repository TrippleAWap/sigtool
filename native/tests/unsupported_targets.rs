//! Images the tool cannot decode correctly are refused with exit code 3 and
//! a message naming the reason, built here with clang and lld so the headers
//! are what a real toolchain writes.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const SOURCE: &str = "int scramble(int x) { return (x ^ 0x55) * 0x9e3779b1; }\n";

fn scratch(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sigtool-unsupported-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("small.c"), SOURCE).unwrap();
    dir
}

fn run_tool(program: &str, args: &[&str], dir: &Path) {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(status.success(), "{program} {args:?} failed");
}

/// Run `gen` on `image` and return (exit code, stderr).
fn gen(image: &Path) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .arg("gen")
        .arg("--file")
        .arg(image)
        .args(["--rva", "0x1000"])
        .output()
        .expect("run sigtool-native");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn big_endian_elf_is_refused_by_name() {
    if !common::have_tools(&["clang", "ld.lld"]) {
        return;
    }
    let dir = scratch("armeb");
    run_tool(
        "clang",
        &[
            "--target=armebv7-linux-gnueabihf",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            "small.c",
            "-o",
            "libsmall.so",
        ],
        &dir,
    );
    let (code, stderr) = gen(&dir.join("libsmall.so"));
    assert_eq!(code, Some(3), "{stderr}");
    // Before the byte-order check, e_machine was read little-endian and the
    // error named machine 0x2800 instead of the byte order.
    assert!(stderr.contains("big-endian"), "{stderr}");
}

#[test]
fn windows_armnt_dll_is_refused() {
    if !common::have_tools(&["clang", "lld-link"]) {
        return;
    }
    let dir = scratch("armnt");
    run_tool(
        "clang",
        &[
            "--target=thumbv7-pc-windows-msvc",
            "-O2",
            "-c",
            "small.c",
            "-o",
            "small.obj",
        ],
        &dir,
    );
    run_tool(
        "lld-link",
        &[
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/export:scramble",
            "/out:small.dll",
            "small.obj",
        ],
        &dir,
    );
    let (code, stderr) = gen(&dir.join("small.dll"));
    assert_eq!(code, Some(3), "{stderr}");
    assert!(stderr.contains("ARMNT"), "{stderr}");
}
