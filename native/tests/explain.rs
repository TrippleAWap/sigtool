//! `locate --explain` and `--expect RVA` on clang + lld output: the
//! explanation of the best match agrees with the match list, and one of a
//! function the signature does not describe names the gate that rejected
//! it, in both discovery modes.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

mod common;

/// Functions with their own constants, enough of them for the frequency
/// gates of hint-free scans to apply.
fn source() -> String {
    let mut code = String::new();
    for n in 0..40u32 {
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
    code
}

fn tool(program: &str, args: &[&str], dir: &Path) {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(status.success(), "{program} {args:?} failed");
}

fn symbol(image: &Path, name: &str) -> u64 {
    let output = Command::new("llvm-nm")
        .arg(image)
        .output()
        .expect("run llvm-nm");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .find(|line| line.ends_with(&format!(" {name}")))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .unwrap_or_else(|| panic!("{name} in llvm-nm output"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(args)
        .output()
        .expect("run sigtool-native")
}

fn explain(document: &Value) -> &Value {
    let explain = &document["explain"];
    assert!(explain.is_object(), "no explain object: {document}");
    explain
}

/// The gate list ends at `decided` when a gate failed, and every gate before
/// it passed.
fn check_gates(explain: &Value) {
    let gates = explain["gates"].as_array().expect("gates");
    assert!(!gates.is_empty());
    let decided = explain["decided"].as_str().expect("decided");
    let failed: Vec<&Value> = gates
        .iter()
        .filter(|gate| gate["passed"] == false)
        .collect();
    match decided {
        "accepted" | "ranked-out" => assert!(failed.is_empty(), "{explain}"),
        gate => assert_eq!(failed[0]["gate"], gate, "{explain}"),
    }
}

#[test]
fn explain_reports_the_deciding_gate() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-explain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lib.c"), source()).unwrap();
    tool(
        "clang",
        &[
            "--target=x86_64-linux-gnu",
            "-O1",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            "lib.c",
            "-o",
            "lib.so",
        ],
        &dir,
    );
    tool(
        "llvm-strip",
        &["--strip-all", "lib.so", "-o", "stripped.so"],
        &dir,
    );
    let image = dir.join("lib.so");
    let stripped = dir.join("stripped.so");
    let signed = symbol(&image, "f7");
    let other = symbol(&image, "f8");
    let signature = dir.join("f7.yaml");
    let output = run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--addr",
        &format!("0x{signed:x}"),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "gen: {output:?}");

    for (target, discovery) in [(&image, "hinted"), (&stripped, "hint-free")] {
        let json = dir.join(format!("{discovery}.json"));
        let base = [
            "locate",
            "--signature",
            signature.to_str().unwrap(),
            "--file",
            target.to_str().unwrap(),
            "--discovery",
            discovery,
            "--yes",
            "--explain",
            "--json",
            json.to_str().unwrap(),
        ];
        // The best match: accepted, first, and the same address as the list.
        let output = run(&base);
        assert!(output.status.success(), "{discovery}: {output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("explain 0x"), "{text}");
        assert!(text.contains("gate score: pass"), "{text}");
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        let best = explain(&document);
        assert_eq!(best["address"], document["matches"][0]["address"]);
        assert_eq!(best["address"], format!("0x{signed:x}"), "{discovery}");
        assert_eq!(best["decided"], "accepted", "{best}");
        assert_eq!(best["rank"], 1);
        assert_eq!(best["evidence"], document["matches"][0]["evidence"]);
        assert!(!best["matched"].as_array().unwrap().is_empty());
        check_gates(best);

        // Another function: not this signature's, so a gate rejects it.
        let mut expect = base.to_vec();
        let rva = format!("0x{other:x}");
        expect.extend(["--expect", &rva]);
        let output = run(&expect);
        assert!(output.status.success(), "{discovery} --expect: {output:?}");
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        let rejected = explain(&document);
        assert_eq!(rejected["address"], format!("0x{other:x}"));
        assert!(rejected["rank"].is_null(), "{rejected}");
        assert_ne!(rejected["decided"], "accepted");
        assert!(!rejected["missed"].as_array().unwrap().is_empty());
        check_gates(rejected);

        // Deterministic: the same explanation twice.
        let again = run(&expect);
        assert_eq!(again.stdout, output.stdout, "{discovery}: explain differs");
    }

    // --expect needs --explain, and --explain needs a file.
    let output = run(&[
        "locate",
        "--signature",
        signature.to_str().unwrap(),
        "--file",
        image.to_str().unwrap(),
        "--expect",
        "0x10",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let output = run(&[
        "locate",
        "--signature",
        signature.to_str().unwrap(),
        "--pid",
        "1",
        "--explain",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
