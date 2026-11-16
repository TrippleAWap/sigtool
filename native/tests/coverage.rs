//! Coverage cases built on the fly from real compiler output (M9): code
//! shapes the corpus builds do not produce, so each case compiles a small
//! source with clang + ld.lld and checks the CLI's answer. Skips when the
//! tools are absent.

use std::path::{Path, PathBuf};
use std::process::Command;

fn has(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
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

/// A scratch directory unique to this test and process.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sigtool-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `clang --target=TARGET -O2 -fPIC -shared EXTRA source -o image`.
fn build(target: &str, extra: &[&str], source: &Path, image: &Path) {
    let built = Command::new("clang")
        .arg(format!("--target={target}"))
        .args(["-O2", "-fPIC", "-shared", "-nostdlib", "-fuse-ld=lld"])
        .args(extra)
        .arg(source)
        .arg("-o")
        .arg(image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed for {}", image.display());
}

fn symbol(image: &Path, name: &str) -> u64 {
    let symbols = Command::new("llvm-nm")
        .arg(image)
        .output()
        .expect("run llvm-nm");
    String::from_utf8(symbols.stdout)
        .expect("utf-8")
        .lines()
        .find(|line| line.ends_with(&format!(" {name}")))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .unwrap_or_else(|| panic!("{name} in llvm-nm output"))
}

fn callees(yaml: &str) -> Vec<String> {
    let lines: Vec<&str> = yaml.lines().collect();
    lines
        .windows(2)
        .filter(|pair| pair[0].trim_start() == "- kind: callee")
        .map(|pair| pair[1].trim().trim_start_matches("value: ").to_string())
        .collect()
}

/// AArch64 `-fno-plt` calls load the callee from its GOT slot (`adrp x8,
/// :got:f; ldr x8, [x8, :got_lo12:f]; blr x8`) instead of calling a PLT
/// stub. Both forms must name the import, or a signature generated from one
/// build cannot find the function in the other.
#[test]
fn arm64_no_plt_calls_name_their_import() {
    if !has("clang") || !has("ld.lld") || !has("llvm-nm") {
        eprintln!("skip: clang, ld.lld, and llvm-nm are needed");
        return;
    }
    let dir = scratch("noplt");
    let source = dir.join("calls.c");
    std::fs::write(
        &source,
        "extern int ext_compute(int value);\n\
         extern void ext_log(const char *message);\n\
         extern int ext_tail(int value);\n\
         int caller(int value) {\n\
         \x20   ext_log(\"caller: computing\");\n\
         \x20   return ext_compute(value * 3) + 7;\n\
         }\n\
         int tail(int value) { return ext_tail(value + 1); }\n",
    )
    .unwrap();
    let mut seen = Vec::new();
    for (variant, extra) in [("plt", &[][..]), ("noplt", &["-fno-plt"][..])] {
        let image = dir.join(format!("lib{variant}.so"));
        build("aarch64-linux-gnu", extra, &source, &image);
        let image_path = image.to_str().unwrap();
        let mut found = Vec::new();
        for function in ["caller", "tail"] {
            let address = format!("0x{:x}", symbol(&image, function));
            let yaml = run(&["gen", "--file", image_path, "--addr", &address]);
            found.push((function, callees(&yaml)));
        }
        std::fs::remove_file(&image).ok();
        seen.push((variant, found));
    }
    std::fs::remove_file(&source).ok();
    std::fs::remove_dir(&dir).ok();
    for (variant, found) in &seen {
        let caller = &found[0].1;
        assert!(
            caller.contains(&"'*!ext_compute'".to_string())
                && caller.contains(&"'*!ext_log'".to_string()),
            "{variant} caller: {caller:?}"
        );
        assert!(
            found[1].1.contains(&"'*!ext_tail'".to_string()),
            "{variant} tail: {:?}",
            found[1].1
        );
    }
}
