//! Front-end addressing contract: an RVA is relative to the image base (the
//! lowest `PT_LOAD` address), so `--rva`, `FILE:+RVA` merge samples, and the
//! `rva` that `locate --json` reports agree with readelf and disassemblers.
//! The IDA plugin relies on this to work on rebased databases.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

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
    // The toy image has symbols, so `auto` above ran hinted, which builds no
    // index and always writes `[]`. Hint-free builds the scan context and
    // reads the image's start lists, which is the path coverage checks.
    // Only the report is checked here, so "found nothing" (exit 1) is fine.
    let hint_free = dir.join("matches-hint-free.json");
    let output = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args([
            "locate",
            "--signature",
            signature.to_str().unwrap(),
            "--file",
            arm_path,
            "--discovery",
            "hint-free",
            "--json",
            hint_free.to_str().unwrap(),
            "--yes",
        ])
        .output()
        .expect("run sigtool-native");
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "hint-free locate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hint_free_document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&hint_free).unwrap()).unwrap();
    std::fs::remove_file(&hint_free).ok();
    std::fs::remove_file(&signature).ok();
    std::fs::remove_file(&matches).ok();
    std::fs::remove_dir(&dir).ok();
    let best = &document["matches"][0];
    assert_eq!(best["rva"], serde_json::Value::String(arm_rva));
    assert_eq!(best["module"], "loops");
    // A toy image exhausts no scan budget, in either discovery mode.
    assert_eq!(document["truncated"], serde_json::json!([]), "{document}");
    assert_eq!(
        hint_free_document["truncated"],
        serde_json::json!([]),
        "{hint_free_document}"
    );
}

/// A shared object's image base is 0, below its first section. The image base
/// may only shift RVAs: if it widened the module range, every constant below
/// the first section (loop bounds, masks, small sizes) would be dropped as a
/// pointer by rule 4. Built on the fly because the toy corpus is all static
/// executables, whose first section sits on the image base.
#[test]
fn shared_object_keeps_small_constants_and_reports_symbol_rvas() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-so-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("small.c");
    let image = dir.join("libsmall.so");
    std::fs::write(
        &source,
        "unsigned scramble(unsigned x) { return ((x ^ 0x55u) * 0x9e3779b1u) & 0xffu; }\n",
    )
    .unwrap();
    let built = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
        ])
        .args(["-fuse-ld=lld", "-fno-asynchronous-unwind-tables"])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed to build the shared object");

    let symbols = Command::new("llvm-nm")
        .arg(&image)
        .output()
        .expect("run llvm-nm");
    let symbols = String::from_utf8(symbols.stdout).expect("utf-8");
    let address = symbols
        .lines()
        .find(|line| line.ends_with(" scramble"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .expect("scramble in llvm-nm output");

    let yaml = run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--addr",
        &format!("0x{address:x}"),
    ]);
    std::fs::remove_file(&source).ok();
    std::fs::remove_file(&image).ok();
    std::fs::remove_dir(&dir).ok();
    // The image base is 0, so the RVA is the symbol address itself.
    assert!(yaml.contains(&format!("rva: '0x{address:x}'")), "{yaml}");
    let constants: Vec<&str> = yaml
        .lines()
        .skip_while(|line| !line.starts_with("features:"))
        .collect::<Vec<_>>()
        .windows(2)
        .filter(|pair| pair[0].trim_start() == "- kind: const")
        .map(|pair| pair[1].trim())
        .collect();
    assert!(
        constants.iter().any(|value| value.contains("0x55")),
        "{yaml}"
    );
}

/// `locate` on a stripped image: `auto` discovery must fall back to
/// hint-free scanning, because the few dynamic symbols left do not name the
/// function, and hinted discovery has nothing else to start from.
#[test]
fn locate_finds_a_local_function_in_a_stripped_image() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-strip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("local.c");
    let image = dir.join("liblocal.so");
    let stripped = dir.join("liblocal.stripped.so");
    std::fs::write(
        &source,
        "__attribute__((noinline)) static unsigned mix(unsigned x, unsigned y) {\n\
         \x20   unsigned h = x * 0x85ebca6bu;\n\
         \x20   for (unsigned i = 0; i < y; i++) h = (h ^ (h >> 13)) * 0xc2b2ae35u + i;\n\
         \x20   return h ^ 0x27d4eb2fu;\n\
         }\n\
         unsigned exported(unsigned x) { return mix(x, 7) + mix(x + 1, 3); }\n",
    )
    .unwrap();
    let built = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed to build the shared object");
    let strip = Command::new("llvm-strip")
        .arg("--strip-all")
        .arg(&image)
        .arg("-o")
        .arg(&stripped)
        .status()
        .expect("run llvm-strip");
    assert!(strip.success(), "llvm-strip failed");
    let symbols = Command::new("llvm-nm")
        .arg(&image)
        .output()
        .expect("run llvm-nm");
    let symbols = String::from_utf8(symbols.stdout).expect("utf-8");
    let address = symbols
        .lines()
        .find(|line| line.ends_with(" mix"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .expect("mix in llvm-nm output");

    let signature = dir.join("mix.yaml");
    run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--addr",
        &format!("0x{address:x}"),
        "--output",
        signature.to_str().unwrap(),
    ]);
    let json = dir.join("matches.json");
    let locate = |image: &Path| {
        let output = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
            .args(["locate", "--signature", signature.to_str().unwrap()])
            .args(["--file", image.to_str().unwrap()])
            .args(["--json", json.to_str().unwrap(), "--yes"])
            .output()
            .expect("run sigtool-native");
        assert!(output.status.success(), "locate {}", image.display());
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let unstripped_mode = locate(&image);
    let stripped_mode = locate(&stripped);
    assert!(
        unstripped_mode.contains("hinted discovery"),
        "{unstripped_mode}"
    );
    assert!(
        stripped_mode.contains("hint-free discovery"),
        "{stripped_mode}"
    );
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    for path in [&source, &image, &stripped, &signature, &json] {
        std::fs::remove_file(path).ok();
    }
    std::fs::remove_dir(&dir).ok();
    let best = document["matches"][0]["address"].as_str().unwrap_or("");
    assert_eq!(best, format!("0x{address:x}"), "{document}");
    // Its multiplier constants identify it; shape alone would not.
    assert_eq!(
        document["matches"][0]["evidence"], "identified",
        "{document}"
    );
}

/// A helper too small to identify itself (a few shape features, no data) is
/// found in a stripped image through its caller's string: the signature
/// carries the caller's evidence as a neighbour key, and `locate` reports it
/// as a `near:` match. Forty exported lookalikes give the image the function
/// count the hint-free gates need.
#[test]
fn locate_finds_a_shape_only_helper_through_its_caller() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-near-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("near.c");
    let image = dir.join("libnear.so");
    let stripped = dir.join("libnear.stripped.so");
    let mut code = String::from(
        "__attribute__((noinline)) static int helper(int x) { return x + 1; }\n\
         const char *describe(int x) {\n\
         \x20   return helper(x) > 3 ? \"neighbour evidence banner\" : \"short\";\n\
         }\n",
    );
    for n in 0..40 {
        code.push_str(&format!(
            "int filler{n}(int x) {{ return x * {} + {n}; }}\n",
            n + 3
        ));
    }
    std::fs::write(&source, code).unwrap();
    let built = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed to build the shared object");
    let strip = Command::new("llvm-strip")
        .arg("--strip-all")
        .arg(&image)
        .arg("-o")
        .arg(&stripped)
        .status()
        .expect("run llvm-strip");
    assert!(strip.success(), "llvm-strip failed");
    let symbols = Command::new("llvm-nm")
        .arg(&image)
        .output()
        .expect("run llvm-nm");
    let symbols = String::from_utf8(symbols.stdout).expect("utf-8");
    let address = symbols
        .lines()
        .find(|line| line.ends_with(" helper"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .expect("helper in llvm-nm output");

    let signature = dir.join("helper.yaml");
    run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--addr",
        &format!("0x{address:x}"),
        "--output",
        signature.to_str().unwrap(),
    ]);
    let yaml = std::fs::read_to_string(&signature).unwrap();
    let json = dir.join("matches.json");
    // Not `run`: a miss exits 1, and the failure message below says more.
    let locate = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(["locate", "--signature", signature.to_str().unwrap()])
        .args(["--file", stripped.to_str().unwrap()])
        .args(["--json", json.to_str().unwrap(), "--yes"])
        .output()
        .expect("run sigtool-native");
    let document: serde_json::Value = std::fs::read_to_string(&json)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    for path in [&source, &image, &stripped, &signature, &json] {
        std::fs::remove_file(path).ok();
    }
    std::fs::remove_dir(&dir).ok();
    let context = format!(
        "signature:\n{yaml}\nlocate stderr:\n{}\nmatches:\n{document}",
        String::from_utf8_lossy(&locate.stderr)
    );
    assert!(
        yaml.contains("- in:str:neighbour evidence banner"),
        "{context}"
    );
    let best = &document["matches"][0];
    assert_eq!(best["address"], format!("0x{address:x}"), "{context}");
    assert_eq!(best["evidence"], "identified", "{context}");
    let matched = best["matched"].as_array().cloned().unwrap_or_default();
    assert!(
        matched
            .iter()
            .any(|key| key == "near:in:str:neighbour evidence banner"),
        "{context}"
    );
}

/// Builds `code` as a stripped x86-64 shared object with clang -O2, signs
/// `names` on the unstripped copy, scans them together on the stripped one,
/// and returns `wanted`'s expected address, the scan's JSON document, and
/// its stderr. `None` when the LLVM tools are missing.
fn scan_jointly(
    tag: &str,
    code: &str,
    names: &[&str],
    wanted: &str,
) -> Option<(String, serde_json::Value, String)> {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return None;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("chain.c");
    let image = dir.join("libchain.so");
    let stripped = dir.join("libchain.stripped.so");
    std::fs::write(&source, code).unwrap();
    let built = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed to build the shared object");
    let strip = Command::new("llvm-strip")
        .arg("--strip-all")
        .arg(&image)
        .arg("-o")
        .arg(&stripped)
        .status()
        .expect("run llvm-strip");
    assert!(strip.success(), "llvm-strip failed");
    let symbols = Command::new("llvm-nm")
        .arg(&image)
        .output()
        .expect("run llvm-nm");
    let symbols = String::from_utf8(symbols.stdout).expect("utf-8");
    let address_of = |name: &str| {
        symbols
            .lines()
            .find(|line| line.ends_with(&format!(" {name}")))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|text| u64::from_str_radix(text, 16).ok())
            .unwrap_or_else(|| panic!("{name} in llvm-nm output"))
    };
    let mut signatures = Vec::new();
    for name in names {
        let path = dir.join(format!("{name}.yaml"));
        run(&[
            "gen",
            "--file",
            image.to_str().unwrap(),
            "--addr",
            &format!("0x{:x}", address_of(name)),
            "--output",
            path.to_str().unwrap(),
        ]);
        signatures.push(path);
    }
    let json = dir.join("hits.json");
    let mut scan = Command::new(env!("CARGO_BIN_EXE_sigtool-native"));
    scan.args(["scan", "--file", stripped.to_str().unwrap()])
        .args(["--json", json.to_str().unwrap()]);
    for path in &signatures {
        scan.arg("--signature").arg(path);
    }
    let output = scan.output().expect("run sigtool-native");
    let document: serde_json::Value = std::fs::read_to_string(&json)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let expected = format!("0x{:x}", address_of(wanted));
    for path in signatures.iter().chain([&source, &image, &stripped, &json]) {
        std::fs::remove_file(path).ok();
    }
    std::fs::remove_dir(&dir).ok();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Some((expected, document, stderr))
}

/// The best hit of signature `name` in a scan document.
fn best_hit<'a>(document: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    document["hits"]
        .as_array()
        .and_then(|hits| hits.iter().find(|hit| hit["name"] == name))
}

/// The three-call chain both joint tests start from: `top` holds the only
/// string, `bottom` is out of reach of neighbour keys (two hops).
const CHAIN: &str = "__attribute__((noinline)) static int bottom(int x) { return x ^ 5; }\n\
     __attribute__((noinline)) static int lower(int x) { return bottom(x) - 7; }\n\
     __attribute__((noinline)) static int middle(int x) { return lower(x) * 3; }\n\
     const char *top(int x) {\n\
     \x20   return middle(x) > 9 ? \"joint resolution banner\" : \"no\";\n\
     }\n";

/// Joint resolution: `bottom` is three calls below the only function with a
/// string and has forty exported lookalikes. Scanned alone it is at best a
/// `shape-only` candidate; scanned with the signatures of its callers, `top`
/// pins `middle`, `middle` pins `lower`, and `lower` pins `bottom` through
/// the stripped call graph, which makes the match `identified`.
#[test]
fn scan_resolves_a_call_chain_jointly() {
    let mut code = String::from(CHAIN);
    for n in 0..40 {
        code.push_str(&format!(
            "int filler{n}(int x) {{ return x ^ {}; }}\n",
            n + 6
        ));
    }
    let Some((expected, document, stderr)) = scan_jointly(
        "joint",
        &code,
        &["top", "middle", "lower", "bottom"],
        "bottom",
    ) else {
        return;
    };
    let best = best_hit(&document, "bottom");
    assert_eq!(
        best.map(|hit| hit["address"].clone()),
        Some(serde_json::Value::String(expected)),
        "stderr: {stderr}\nhits: {document}"
    );
    assert_eq!(best.unwrap()["evidence"], "identified", "{document}");
}

/// Joint resolution follows tail calls in both directions: `wrapper` reaches
/// `middle` only through a tail call (`jmp`), which the code index's call
/// sites do not hold, and has forty lookalikes that tail-call helpers of
/// their own. Its `out:` link to `middle`, which the chain pins, must earn
/// the link bonus at the function that tail-calls `middle`'s placement, or
/// `wrapper` stays tied with its lookalikes.
#[test]
fn scan_resolves_a_tail_caller_jointly() {
    let mut code = String::from(CHAIN);
    code.push_str("int wrapper(int x) { return middle(x + 11); }\n");
    for n in 0..40 {
        code.push_str(&format!(
            "__attribute__((noinline)) static int sink{n}(int x) {{ return (x ^ {}) * 3; }}\n\
             int filler{n}(int x) {{ return sink{n}(x + 11); }}\n",
            n + 6
        ));
    }
    let Some((expected, document, stderr)) = scan_jointly(
        "joint-tail",
        &code,
        &["top", "middle", "lower", "bottom", "wrapper"],
        "wrapper",
    ) else {
        return;
    };
    let best = best_hit(&document, "wrapper");
    assert_eq!(
        best.map(|hit| hit["address"].clone()),
        Some(serde_json::Value::String(expected)),
        "stderr: {stderr}\nhits: {document}"
    );
    assert_eq!(best.unwrap()["evidence"], "identified", "{document}");
}

/// The lowest PT_LOAD address of an ELF64 image (its image base).
fn load_base(path: &Path) -> u64 {
    let data = std::fs::read(path).expect("read image");
    let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let u64_at = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let (phoff, phentsize, phnum) = (u64_at(0x20) as usize, u16_at(0x36), u16_at(0x38));
    (0..phnum)
        .map(|i| phoff + i * phentsize)
        .filter(|o| u32_at(*o) == 1)
        .map(|o| u64_at(o + 0x10))
        .min()
        .expect("PT_LOAD")
}

/// The IDA workflow "sign a whole IDB, apply the names to another": `db build
/// --functions` signs a name list by RVA in one run, each signature identical
/// to the one `gen --rva --name` makes, skipping what cannot be signed; a
/// `scan --db` of the stripped copy then reports each hit's rva, and joint
/// resolution identifies the shape-only `bottom` through its callers.
#[test]
fn db_build_signs_a_function_list_and_scan_reports_rvas() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-batch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("chain.c");
    let image = dir.join("libchain.so");
    let stripped = dir.join("libchain.stripped.so");
    let mut code = String::from(
        "__attribute__((noinline)) static int bottom(int x) { return x ^ 5; }\n\
         __attribute__((noinline)) static int lower(int x) { return bottom(x) - 7; }\n\
         __attribute__((noinline)) static int middle(int x) { return lower(x) * 3; }\n\
         const char *top(int x) {\n\
         \x20   return middle(x) > 9 ? \"joint resolution banner\" : \"no\";\n\
         }\n",
    );
    for n in 0..40 {
        code.push_str(&format!(
            "int filler{n}(int x) {{ return x ^ {}; }}\n",
            n + 6
        ));
    }
    std::fs::write(&source, code).unwrap();
    let built = Command::new("clang")
        .args([
            "--target=x86_64-linux-gnu",
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .status()
        .expect("run clang");
    assert!(built.success(), "clang failed to build the shared object");
    let strip = Command::new("llvm-strip")
        .arg("--strip-all")
        .arg(&image)
        .arg("-o")
        .arg(&stripped)
        .status()
        .expect("run llvm-strip");
    assert!(strip.success(), "llvm-strip failed");
    let symbols = Command::new("llvm-nm")
        .arg(&image)
        .output()
        .expect("run llvm-nm");
    let symbols = String::from_utf8(symbols.stdout).expect("utf-8");
    let base = load_base(&image);
    let rva_of = |name: &str| {
        symbols
            .lines()
            .find(|line| line.ends_with(&format!(" {name}")))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|text| u64::from_str_radix(text, 16).ok())
            .map(|addr| addr - base)
            .unwrap_or_else(|| panic!("{name} in llvm-nm output"))
    };

    // An IDB name list: renamed functions, plus one RVA outside the image.
    let mut list: Vec<serde_json::Value> = ["top", "middle", "lower", "bottom"]
        .iter()
        .map(|name| serde_json::json!({"rva": format!("0x{:x}", rva_of(name)), "name": name}))
        .collect();
    list.push(serde_json::json!({"rva": "0x7fffffff", "name": "outside"}));
    let functions = dir.join("functions.json");
    std::fs::write(&functions, serde_json::to_string(&list).unwrap()).unwrap();
    let db = dir.join("chain.db");
    let db_again = dir.join("chain.again.db");
    let report = dir.join("report.json");
    for output in [&db, &db_again] {
        run(&[
            "db",
            "build",
            "--file",
            image.to_str().unwrap(),
            "--functions",
            functions.to_str().unwrap(),
            "--tool",
            "IDA",
            "--report",
            report.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ]);
    }
    let gen_report = dir.join("bottom.json");
    run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--rva",
        &format!("0x{:x}", rva_of("bottom")),
        "--name",
        "bottom",
        "--tool",
        "IDA",
        "--output",
        dir.join("bottom.yaml").to_str().unwrap(),
        "--json-report",
        gen_report.to_str().unwrap(),
    ]);
    let json = dir.join("hits.json");
    let scan = Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(["scan", "--file", stripped.to_str().unwrap()])
        .args(["--db", db.to_str().unwrap()])
        .args(["--discovery", "hint-free"])
        .args(["--json", json.to_str().unwrap()])
        .output()
        .expect("run sigtool-native");
    let read_json = |path: &Path| -> serde_json::Value {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    };
    let report = read_json(&report);
    let gen_report = read_json(&gen_report);
    let hits = read_json(&json);
    let same_db = std::fs::read(&db).ok() == std::fs::read(&db_again).ok();
    let bottom_rva = format!("0x{:x}", rva_of("bottom"));
    std::fs::remove_dir_all(&dir).ok();

    assert!(same_db, "db build --functions is not deterministic");
    assert_eq!(report["signed"], 4, "{report}");
    assert_eq!(report["failed"], 1, "{report}");
    // Small images exhaust no scan budget, and every report says so.
    assert_eq!(report["truncated"], serde_json::json!([]), "{report}");
    assert_eq!(
        gen_report["truncated"],
        serde_json::json!([]),
        "{gen_report}"
    );
    assert_eq!(hits["truncated"], serde_json::json!([]), "{hits}");
    let rows = report["functions"].as_array().expect("functions");
    assert_eq!(rows[4]["status"], "error", "{report}");
    assert_eq!(
        rows[3]["signature_id"], gen_report["signature_id"],
        "a batch signature differs from gen's: {report}\n{gen_report}"
    );
    let best = hits["hits"]
        .as_array()
        .and_then(|hits| hits.iter().find(|hit| hit["name"] == "bottom"));
    assert_eq!(
        best.map(|hit| hit["rva"].clone()),
        Some(serde_json::Value::String(bottom_rva)),
        "stderr: {}\nhits: {hits}",
        String::from_utf8_lossy(&scan.stderr)
    );
    assert_eq!(best.unwrap()["evidence"], "identified", "{hits}");
}

#[test]
fn version_names_the_spec_version() {
    // The IDA plugin parses this line to warn about a mismatched binary.
    let text = run(&["--version"]);
    assert_eq!(
        text.trim(),
        format!(
            "sigtool-native {} (spec {})",
            env!("CARGO_PKG_VERSION"),
            sigtool_native::spec::SPEC_VERSION
        )
    );
}
