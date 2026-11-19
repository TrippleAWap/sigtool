//! A function signed in a shared object is found in a stripped executable
//! linking the same code (SPEC.md §8, "Targets that name no function"). The
//! shared object calls its exported helpers by name, so their names are the
//! signature's identifying evidence; the executable exports nothing, so
//! there the same calls have no name and must not be demanded. The
//! multiplier keeps one identifying key the executable can show; without
//! one the signature abstains there by design.

use std::path::Path;
use std::process::Command;

mod common;

const SOURCE: &str = r#"
__attribute__((noinline)) int helper_a(int x) { return x * 3 + 1; }
__attribute__((noinline)) int helper_b(int x) { return x ^ (x >> 3); }
int combine(int x, int y) {
    int t = helper_a(x) + helper_b(y * 0x9e3779b1);
    if (t > 10)
        t = helper_a(t);
    return t - helper_b(x);
}
"#;

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

#[test]
fn shared_object_signature_finds_its_function_in_a_stripped_pie() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-exe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lib.c"), SOURCE).unwrap();
    std::fs::write(
        dir.join("main.c"),
        "int combine(int, int);\nint main(void) { return combine(1, 2); }\n",
    )
    .unwrap();
    let common_flags = [
        "--target=x86_64-linux-gnu",
        "-O1",
        "-nostdlib",
        "-fuse-ld=lld",
    ];
    let mut shared = common_flags.to_vec();
    shared.extend(["-fPIC", "-shared", "lib.c", "-o", "lib.so"]);
    tool("clang", &shared, &dir);
    let mut pie = common_flags.to_vec();
    pie.extend([
        "-fPIE",
        "-pie",
        "-Wl,-e,main",
        "lib.c",
        "main.c",
        "-o",
        "app",
    ]);
    tool("clang", &pie, &dir);
    tool(
        "llvm-strip",
        &["--strip-all", "app", "-o", "app.stripped"],
        &dir,
    );

    let address = symbol(&dir.join("lib.so"), "combine");
    let expected = symbol(&dir.join("app"), "combine");
    let signature = dir.join("combine.yaml");
    let generated = run(&[
        "gen",
        "--file",
        dir.join("lib.so").to_str().unwrap(),
        "--addr",
        &format!("0x{address:x}"),
        "--output",
        signature.to_str().unwrap(),
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let yaml = std::fs::read_to_string(&signature).unwrap();
    assert!(yaml.contains("helper_a"), "fixture lost its callee: {yaml}");

    let json = dir.join("matches.json");
    let located = run(&[
        "locate",
        "--signature",
        signature.to_str().unwrap(),
        "--file",
        dir.join("app.stripped").to_str().unwrap(),
        "--discovery",
        "hint-free",
        "--json",
        json.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&located.stderr).into_owned();
    assert!(located.status.success(), "locate found nothing: {stderr}");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        document["matches"][0]["address"].as_str().unwrap_or(""),
        format!("0x{expected:x}"),
        "{document}"
    );
}
