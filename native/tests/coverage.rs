//! Coverage cases built on the fly from real compiler output (M9): code
//! shapes the corpus builds do not produce, so each case compiles a small
//! source with clang + ld.lld and checks the CLI's answer. Skips when the
//! tools are absent.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

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

/// Function addresses from an lld-link `/map` file.
fn map_symbols(map: &Path) -> Vec<(String, u64)> {
    std::fs::read_to_string(map)
        .expect("map file")
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || !fields[0].starts_with("0001:") {
                return None;
            }
            let address = u64::from_str_radix(fields[2], 16).ok()?;
            Some((fields[1].to_string(), address))
        })
        .collect()
}

/// Windows x64 gives `.pdata` entries only to functions with a frame, so
/// leaf functions are absent from the table hint-free discovery reads; an
/// image without `.pdata` has no table at all. Both must still list the
/// leaf functions, found as direct call targets.
#[test]
fn pe_leaf_functions_and_images_without_pdata_have_starts() {
    // `ld.lld -flavor link` is lld-link without needing the alias installed.
    if !common::have_tools(&["clang", "ld.lld"]) {
        return;
    }
    // x86-64 and AArch64: Windows on both lets a leaf go without `.pdata`.
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        pe_leaf_starts(target);
    }
}

fn pe_leaf_starts(target: &str) {
    let dir = scratch(&format!("pe-leaf-{target}"));
    let source = dir.join("leaf.c");
    // Enough leaves that a table-less image clears the 32-start floor
    // (`elf::MIN_SYNTHESIZED_STARTS`); each is called from a framed export.
    const LEAVES: usize = 40;
    let mut code = String::from(
        "__declspec(noinline) static unsigned leaf_hash(const unsigned char *p, unsigned n) {\n\
         \x20   unsigned h = 0x811c9dc5u;\n\
         \x20   for (unsigned i = 0; i < n; i++) h = (h ^ p[i]) * 0x01000193u;\n\
         \x20   return h;\n\
         }\n\
         __declspec(noinline) static unsigned leaf_clamp(unsigned v, unsigned lo, unsigned hi) {\n\
         \x20   return v < lo ? lo : (v > hi ? hi : v);\n\
         }\n",
    );
    for index in 0..LEAVES {
        code.push_str(&format!(
            "__declspec(noinline) static unsigned leaf_{index}(unsigned x) \
             {{ return (x ^ {}u) * {}u; }}\n",
            0x9e37_79b9u32.wrapping_mul(index as u32 + 1),
            0x85eb_ca6bu32.wrapping_add(2 * index as u32)
        ));
    }
    code.push_str(
        "__declspec(dllexport) unsigned api_digest(const unsigned char *p, unsigned n) {\n\
         \x20   volatile unsigned buffer[64];\n\
         \x20   unsigned h = leaf_hash(p, n);\n",
    );
    for index in 0..LEAVES {
        code.push_str(&format!(
            "    buffer[{index}] = leaf_{index}(h + buffer[{index}]);\n"
        ));
    }
    code.push_str("    return leaf_clamp(buffer[n & 31], 3, 0x7fff);\n}\n");
    std::fs::write(&source, code).unwrap();
    let object = dir.join("leaf.obj");
    let image = dir.join("leaf.dll");
    let map = dir.join("leaf.map");
    let compiled = Command::new("clang")
        .arg(format!("--target={target}"))
        .args(["-O2", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("run clang");
    assert!(compiled.success());
    let linked = common::command("ld.lld")
        .args(["-flavor", "link", "/dll", "/noentry", "/nodefaultlib"])
        .arg(format!("/out:{}", image.display()))
        .arg(format!("/map:{}", map.display()))
        .arg(&object)
        .status()
        .expect("run ld.lld -flavor link");
    assert!(linked.success());
    let symbols = map_symbols(&map);
    let address = |name: &str| {
        symbols
            .iter()
            .find(|(symbol, _)| symbol == name)
            .map(|(_, address)| *address)
            .unwrap_or_else(|| panic!("{name} in the map"))
    };
    let data = std::fs::read(&image).unwrap();
    // The same image with its exception directory (data directory 3)
    // cleared: what a table-less image looks like to the loader.
    let mut bare = data.clone();
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let directory = pe + 24 + 112 + 3 * 8;
    bare[directory..directory + 8].fill(0);
    std::fs::remove_file(&source).ok();
    std::fs::remove_file(&object).ok();
    std::fs::remove_file(&image).ok();
    std::fs::remove_file(&map).ok();
    std::fs::remove_dir(&dir).ok();

    for (label, bytes) in [("with .pdata", &data), ("without .pdata", &bare)] {
        let loaded =
            sigtool_native::elf::FileSource::from_bytes(bytes, "leaf.dll").expect("PE image");
        let starts: Vec<u64> = sigtool_native::source::ByteSource::unwind_entries(&loaded)
            .iter()
            .map(|(start, _)| *start)
            .collect();
        let mut names = vec!["api_digest".to_string(), "leaf_hash".into()];
        // `leaf_clamp` is reached only by api_digest's tail `jmp`, which is
        // a tail call only when the caller's extent is known (`.pdata`);
        // without one, a forward `jmp` may be a branch inside the function.
        if label == "with .pdata" {
            names.push("leaf_clamp".into());
        }
        names.extend((0..LEAVES).map(|index| format!("leaf_{index}")));
        for name in &names {
            assert!(
                starts.contains(&address(name)),
                "{target} {label}: {name} at {:#x} not in {starts:x?}",
                address(name)
            );
        }
        // Every start is a function: nothing lands inside one.
        let truth: Vec<u64> = symbols.iter().map(|(_, address)| *address).collect();
        let stray: Vec<&u64> = starts
            .iter()
            .filter(|start| !truth.contains(start))
            .collect();
        assert!(
            stray.is_empty(),
            "{target} {label}: false starts {stray:x?}"
        );
    }
}

/// AArch64 `-fno-plt` calls load the callee from its GOT slot (`adrp x8,
/// :got:f; ldr x8, [x8, :got_lo12:f]; blr x8`) instead of calling a PLT
/// stub. Both forms must name the import, or a signature generated from one
/// build cannot find the function in the other.
#[test]
fn arm64_no_plt_calls_name_their_import() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm"]) {
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
