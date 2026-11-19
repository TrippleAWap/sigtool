//! Workflow commands around scanning: batch `scan --path`, the input identity
//! that reports record, `db info` / `db list`, and the spec-mismatch refusal
//! that names its fix. Every input is built here with clang and lld.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use sigtool_native::identity::{hex, sha256};

mod common;

fn sigtool(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sigtool-native"));
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run sigtool-native")
}

fn run(args: &[&str]) -> String {
    let output = sigtool(args, &[]);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read JSON")).expect("parse JSON")
}

/// As in `common`: std appends `.exe` on Windows only to a name with no
/// extension, so `ld.lld` is named in full there.
fn tool(program: &str, args: &[&str]) -> String {
    let suffix = std::env::consts::EXE_SUFFIX;
    let executable = if program.ends_with(suffix) {
        program.to_string()
    } else {
        format!("{program}{suffix}")
    };
    let output = Command::new(executable)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8")
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sigtool-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A call chain under a string-bearing caller, plus filler so the image is
/// not "small" to the matcher; the same source as the `db build` CLI test.
fn chain_source() -> String {
    let mut code = String::from(
        "__attribute__((noinline)) static int bottom(int x) { return x ^ 5; }\n\
         __attribute__((noinline)) static int lower(int x) { return bottom(x) - 7; }\n\
         __attribute__((noinline)) static int middle(int x) { return lower(x) * 3; }\n\
         const char *top(int x) {\n\
         \x20   return middle(x) > 9 ? \"batch workflow banner\" : \"no\";\n\
         }\n",
    );
    for n in 0..40 {
        code.push_str(&format!(
            "int filler{n}(int x) {{ return x ^ {}; }}\n",
            n + 6
        ));
    }
    code
}

/// `clang -shared` for `target`, with a GNU build-id note.
fn build_shared(dir: &Path, target: &str, name: &str) -> PathBuf {
    let source = dir.join(format!("{name}.c"));
    std::fs::write(&source, chain_source()).unwrap();
    let image = dir.join(format!("{name}.so"));
    tool(
        "clang",
        &[
            &format!("--target={target}"),
            "-O2",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            "-Wl,--build-id=sha1",
            source.to_str().unwrap(),
            "-o",
            image.to_str().unwrap(),
        ],
    );
    std::fs::remove_file(&source).ok();
    image
}

/// The lowest PT_LOAD address, read without the crate.
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

fn symbol_rva(image: &Path, name: &str) -> String {
    let symbols = tool("llvm-nm", &[image.to_str().unwrap()]);
    let addr = symbols
        .lines()
        .find(|line| line.ends_with(&format!(" {name}")))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .unwrap_or_else(|| panic!("{name} in llvm-nm output"));
    format!("0x{:x}", addr - load_base(image))
}

/// The `db build --functions` list for the chain in `image`.
fn function_list(dir: &Path, image: &Path) -> PathBuf {
    let list: Vec<Value> = ["top", "middle", "lower", "bottom"]
        .iter()
        .map(|name| serde_json::json!({"rva": symbol_rva(image, name), "name": name}))
        .collect();
    let path = dir.join("functions.json");
    std::fs::write(&path, serde_json::to_string(&list).unwrap()).unwrap();
    path
}

fn build_db(image: &Path, functions: &Path, output: &Path, report: Option<&Path>) {
    let mut args = vec![
        "db",
        "build",
        "--file",
        image.to_str().unwrap(),
        "--functions",
        functions.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    if let Some(report) = report {
        args.extend(["--report", report.to_str().unwrap()]);
    }
    run(&args);
}

/// `llvm-readelf -n`'s "Build ID: <hex>".
fn readelf_build_id(image: &Path) -> String {
    tool("llvm-readelf", &["-n", image.to_str().unwrap()])
        .lines()
        .find_map(|line| line.trim().strip_prefix("Build ID: "))
        .map(str::to_string)
        .expect("build id in llvm-readelf -n")
}

fn expected_identity(image: &Path) -> (String, u64) {
    let data = std::fs::read(image).unwrap();
    (hex(&sha256(&data)), data.len() as u64)
}

/// `gen`, `merge`, and `db build` reports name the exact input: its SHA-256,
/// size, and GNU build-id, as `llvm-readelf` reads the note. The signature
/// YAML and the DB bytes are the same with or without a report.
#[test]
fn reports_record_input_identity_and_leave_outputs_unchanged() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-readelf"]) {
        return;
    }
    let dir = scratch("identity");
    let x64 = build_shared(&dir, "x86_64-linux-gnu", "libx64");
    let arm64 = build_shared(&dir, "aarch64-linux-gnu", "libarm64");
    let (x64_sha, x64_size) = expected_identity(&x64);
    let x64_build_id = readelf_build_id(&x64);
    let x64_rva = symbol_rva(&x64, "top");
    let arm_rva = symbol_rva(&arm64, "top");

    let report = dir.join("gen.json");
    let plain = run(&["gen", "--file", x64.to_str().unwrap(), "--rva", &x64_rva]);
    let reported = run(&[
        "gen",
        "--file",
        x64.to_str().unwrap(),
        "--rva",
        &x64_rva,
        "--json-report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(plain, reported, "a report changed the signature YAML");
    let input = &read_json(&report)["input"];
    assert_eq!(input["sha256"], x64_sha, "{input}");
    assert_eq!(input["size"], x64_size, "{input}");
    assert_eq!(input["build_id"], x64_build_id, "{input}");
    assert!(input.get("pdb_guid").is_none(), "{input}");

    let merge_report = dir.join("merge.json");
    run(&[
        "merge",
        "--sample",
        &format!("{}:+{x64_rva}", x64.to_str().unwrap()),
        "--sample",
        &format!("{}:+{arm_rva}", arm64.to_str().unwrap()),
        "--json-report",
        merge_report.to_str().unwrap(),
    ]);
    let inputs = read_json(&merge_report)["inputs"].clone();
    let (arm_sha, _) = expected_identity(&arm64);
    assert_eq!(inputs[0]["sha256"], x64_sha, "{inputs}");
    assert_eq!(inputs[1]["sha256"], arm_sha, "{inputs}");
    assert_eq!(inputs[1]["build_id"], readelf_build_id(&arm64), "{inputs}");

    let functions = function_list(&dir, &x64);
    let (db, db_reported, db_report) = (
        dir.join("plain.db"),
        dir.join("reported.db"),
        dir.join("db.json"),
    );
    build_db(&x64, &functions, &db, None);
    build_db(&x64, &functions, &db_reported, Some(&db_report));
    let same_db = std::fs::read(&db).unwrap() == std::fs::read(&db_reported).unwrap();
    let document = read_json(&db_report);
    let (list_sha, list_size) = expected_identity(&functions);
    std::fs::remove_dir_all(&dir).ok();

    assert!(same_db, "a report changed the DB bytes");
    assert_eq!(document["input"]["sha256"], x64_sha, "{document}");
    assert_eq!(document["input"]["build_id"], x64_build_id, "{document}");
    assert_eq!(document["functions_list"]["sha256"], list_sha, "{document}");
    assert_eq!(document["functions_list"]["size"], list_size, "{document}");
}

/// A PE DLL linked with `/debug` carries a CodeView RSDS record; the report
/// names its GUID and age as `llvm-readobj --coff-debug-directory` prints
/// them. lld is invoked as `ld.lld -flavor link` so no `lld-link` alias is
/// needed.
#[test]
fn db_build_report_names_the_pe_pdb_guid() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-readobj"]) {
        return;
    }
    let dir = scratch("pe-identity");
    let source = dir.join("pe.c");
    let object = dir.join("pe.obj");
    let image = dir.join("pe.dll");
    std::fs::write(&source, chain_source()).unwrap();
    tool(
        "clang",
        &[
            "--target=x86_64-pc-windows-msvc",
            "-O2",
            "-c",
            source.to_str().unwrap(),
            "-o",
            object.to_str().unwrap(),
        ],
    );
    tool(
        "ld.lld",
        &[
            "-flavor",
            "link",
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/debug",
            "/export:top",
            &format!("/pdb:{}", dir.join("pe.pdb").display()),
            &format!("/out:{}", image.display()),
            object.to_str().unwrap(),
        ],
    );
    let exports = tool("llvm-readobj", &["--coff-exports", image.to_str().unwrap()]);
    let rva = exports
        .lines()
        .find_map(|line| line.trim().strip_prefix("RVA: "))
        .expect("export RVA")
        .to_string();
    let debug = tool(
        "llvm-readobj",
        &["--coff-debug-directory", image.to_str().unwrap()],
    );
    let guid = debug
        .lines()
        .find_map(|line| line.trim().strip_prefix("PDBGUID: "))
        .map(|text| text.trim_matches(|c| c == '{' || c == '}').to_string())
        .expect("PDBGUID");
    let age: u64 = debug
        .lines()
        .find_map(|line| line.trim().strip_prefix("PDBAge: "))
        .and_then(|text| text.trim().parse().ok())
        .expect("PDBAge");
    let functions = dir.join("functions.json");
    std::fs::write(
        &functions,
        format!(r#"[{{"rva": "{rva}", "name": "top"}}]"#),
    )
    .unwrap();
    let report = dir.join("report.json");
    build_db(&image, &functions, &dir.join("pe.db"), Some(&report));
    let document = read_json(&report);
    let (sha, size) = expected_identity(&image);
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(document["signed"], 1, "{document}");
    let input = &document["input"];
    assert_eq!(input["sha256"], sha, "{input}");
    assert_eq!(input["size"], size, "{input}");
    assert_eq!(input["pdb_guid"], guid, "{input}");
    assert_eq!(input["pdb_age"], age, "{input}");
    assert!(input.get("build_id").is_none(), "{input}");
}

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read JSONL")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON line"))
        .collect()
}

/// `scan --path` scans every regular file once with one DB: sorted relative
/// paths, a status for files that are not images or do not parse, hits in the
/// `scan --json` shape, and byte-identical output across runs and thread
/// counts. Its own output file inside the tree is not scanned.
#[test]
fn batch_scan_writes_one_sorted_line_per_file() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = scratch("batch-scan");
    let build = dir.join("build");
    let tree = dir.join("tree");
    std::fs::create_dir_all(&build).unwrap();
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    let image = build_shared(&build, "x86_64-linux-gnu", "libchain");
    let functions = function_list(&build, &image);
    let db = build.join("chain.db");
    build_db(&image, &functions, &db, None);

    std::fs::copy(&image, tree.join("libchain.so")).unwrap();
    tool(
        "llvm-strip",
        &[
            "--strip-all",
            image.to_str().unwrap(),
            "-o",
            tree.join("sub").join("stripped.so").to_str().unwrap(),
        ],
    );
    std::fs::write(tree.join("notes.txt"), "not an image\n").unwrap();
    let data = std::fs::read(&image).unwrap();
    std::fs::write(tree.join("truncated.so"), &data[..96]).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(tree.join("libchain.so"), tree.join("link.so")).unwrap();

    let out = tree.join("out.jsonl");
    let batch = |output: &Path, recursive: bool, envs: &[(&str, &str)]| {
        let mut args = vec![
            "scan",
            "--path",
            tree.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--jsonl",
            output.to_str().unwrap(),
        ];
        if recursive {
            args.push("--recursive");
        }
        let result = sigtool(&args, envs);
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    batch(&out, true, &[]);
    let first = std::fs::read(&out).unwrap();
    // The second run sees the first run's output in the tree and skips it.
    batch(&out, true, &[]);
    let second = std::fs::read(&out).unwrap();
    batch(&out, true, &[("SIGTOOL_THREADS", "1")]);
    let single = std::fs::read(&out).unwrap();
    let rows = lines(&out);
    let flat = dir.join("flat.jsonl");
    batch(&flat, false, &[]);
    let flat_rows = lines(&flat);

    let json = dir.join("single.json");
    run(&[
        "scan",
        "--file",
        tree.join("sub").join("stripped.so").to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--json",
        json.to_str().unwrap(),
    ]);
    let single_scan = read_json(&json);
    let (image_sha, image_size) = expected_identity(&image);
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(first, second, "batch output differs between runs");
    assert_eq!(first, single, "batch output differs with SIGTOOL_THREADS=1");
    let paths: Vec<&str> = rows
        .iter()
        .map(|row| row["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "libchain.so",
            "notes.txt",
            "sub/stripped.so",
            "truncated.so"
        ]
    );
    let flat_paths: Vec<&str> = flat_rows
        .iter()
        .map(|row| row["path"].as_str().unwrap())
        .collect();
    // Writing elsewhere, the flat run scans the earlier runs' output too.
    assert_eq!(
        flat_paths,
        ["libchain.so", "notes.txt", "out.jsonl", "truncated.so"]
    );
    assert_eq!(flat_rows[2]["status"], "unsupported", "{}", flat_rows[2]);

    let (full, notes, stripped, truncated) = (&rows[0], &rows[1], &rows[2], &rows[3]);
    assert_eq!(full["status"], "ok", "{full}");
    assert_eq!(full["arch"], "x64", "{full}");
    assert_eq!(full["discovery"], "hinted", "{full}");
    assert_eq!(full["sha256"], image_sha, "{full}");
    assert_eq!(full["size"], image_size, "{full}");
    assert_eq!(full["error"], Value::Null, "{full}");
    assert_eq!(full["truncated"], serde_json::json!([]), "{full}");
    assert!(
        full["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["name"] == "top"),
        "{full}"
    );

    assert_eq!(notes["status"], "unsupported", "{notes}");
    assert_eq!(notes["arch"], Value::Null, "{notes}");
    assert_eq!(notes["hits"], serde_json::json!([]), "{notes}");
    assert!(notes["sha256"].is_string(), "{notes}");

    // Auto discovery runs hint-free on the stripped copy, as `scan --file`
    // does, and the hits are the ones `scan --json` writes.
    assert_eq!(stripped["status"], "ok", "{stripped}");
    assert_eq!(stripped["discovery"], "hint-free", "{stripped}");
    assert_eq!(stripped["hits"], single_scan["hits"], "{stripped}");
    assert!(
        stripped["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["name"] == "top"),
        "{stripped}"
    );

    assert!(
        matches!(truncated["status"].as_str(), Some("error" | "unsupported")),
        "{truncated}"
    );
    assert!(truncated["error"].is_string(), "{truncated}");
}

/// A copy of `db` whose header names another spec version of the same
/// length; the record checksum does not cover the header.
fn stale_copy(db: &Path, output: &Path) {
    let mut bytes = std::fs::read(db).unwrap();
    let spec_len = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;
    let spec_at = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
    let last = spec_at + spec_len - 1;
    bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
    std::fs::write(output, &bytes).unwrap();
}

fn assert_names_db_rebuild(what: &str, output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{what}: {stderr}");
    assert!(stderr.contains("spec version"), "{what}: {stderr}");
    assert!(
        stderr.contains("db build --file IMAGE --functions F.json"),
        "{what}: {stderr}"
    );
}

/// A DB or signature from another spec version is refused (exit 2, as
/// before) with the command that rebuilds it.
#[test]
fn spec_mismatch_names_the_rebuild() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm"]) {
        return;
    }
    let dir = scratch("spec-mismatch");
    let image = build_shared(&dir, "x86_64-linux-gnu", "libchain");
    let functions = function_list(&dir, &image);
    let db = dir.join("chain.db");
    build_db(&image, &functions, &db, None);
    let stale_db = dir.join("stale.db");
    stale_copy(&db, &stale_db);
    let stale_scan = sigtool(
        &[
            "scan",
            "--file",
            image.to_str().unwrap(),
            "--db",
            stale_db.to_str().unwrap(),
        ],
        &[],
    );

    let yaml = run(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--rva",
        &symbol_rva(&image, "top"),
    ]);
    let spec = sigtool_native::spec::SPEC_VERSION;
    let current = format!("spec_version: '{spec}'");
    assert!(yaml.contains(&current), "{yaml}");
    let stale_yaml = dir.join("stale.yaml");
    std::fs::write(
        &stale_yaml,
        yaml.replace(&current, &format!("spec_version: '{spec}0'")),
    )
    .unwrap();
    let stale_locate = sigtool(
        &[
            "locate",
            "--signature",
            stale_yaml.to_str().unwrap(),
            "--file",
            image.to_str().unwrap(),
            "--yes",
        ],
        &[],
    );
    std::fs::remove_dir_all(&dir).ok();

    assert_names_db_rebuild("scan --db", &stale_scan);
    let stderr = String::from_utf8_lossy(&stale_locate.stderr);
    assert_eq!(stale_locate.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("spec version"), "{stderr}");
    assert!(stderr.contains("regenerate it"), "{stderr}");
}

/// `db info` and `db list` summarize and list a DB, sorted by name, and
/// refuse a stale one the way `scan --db` does.
#[test]
fn db_info_and_list_describe_a_db() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm"]) {
        return;
    }
    let dir = scratch("db-info");
    let image = build_shared(&dir, "x86_64-linux-gnu", "libchain");
    let functions = function_list(&dir, &image);
    let db = dir.join("chain.db");
    build_db(&image, &functions, &db, None);
    let db_path = db.to_str().unwrap();
    let before = std::fs::read(&db).unwrap();

    let info: Value = serde_json::from_str(&run(&["db", "info", db_path, "--json"])).unwrap();
    let info_text = run(&["db", "info", db_path]);
    let list: Value = serde_json::from_str(&run(&["db", "list", db_path, "--json"])).unwrap();
    let list_text = run(&["db", "list", db_path]);
    let stale_db = dir.join("stale.db");
    stale_copy(&db, &stale_db);
    let stale_info = sigtool(&["db", "info", stale_db.to_str().unwrap()], &[]);
    let stale_list = sigtool(&["db", "list", stale_db.to_str().unwrap()], &[]);
    let after = std::fs::read(&db).unwrap();
    std::fs::remove_dir_all(&dir).ok();

    assert_eq!(before, after, "db info or list changed the DB");
    let spec = sigtool_native::spec::SPEC_VERSION;
    assert_eq!(info["spec_version"], spec, "{info}");
    assert_eq!(info["signatures"], 4, "{info}");
    assert_eq!(info["arches"], serde_json::json!({"x64": 4}), "{info}");
    let confidence_total: u64 = info["confidence"]
        .as_object()
        .unwrap()
        .values()
        .map(|count| count.as_u64().unwrap())
        .sum();
    assert_eq!(confidence_total, 4, "{info}");
    assert!(
        info_text.starts_with(&format!("spec {spec}\nsignatures 4\n")),
        "{info_text}"
    );
    assert!(info_text.contains("arch x64 4\n"), "{info_text}");

    let rows = list["signatures"].as_array().unwrap();
    let names: Vec<&str> = rows
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["bottom", "lower", "middle", "top"], "{list}");
    for row in rows {
        assert_eq!(row["arches"], serde_json::json!(["x64"]), "{row}");
        assert!(row["signature_id"].is_string(), "{row}");
        assert!(row["confidence"].is_string(), "{row}");
    }
    let text_rows: Vec<Vec<&str>> = list_text
        .lines()
        .map(|line| line.split("  ").collect())
        .collect();
    assert_eq!(text_rows.len(), 4, "{list_text}");
    for (fields, row) in text_rows.iter().zip(rows) {
        assert_eq!(fields[0], row["name"], "{list_text}");
        assert_eq!(fields[1], row["signature_id"], "{list_text}");
        assert_eq!(fields[2], "x64", "{list_text}");
        assert_eq!(fields[3], row["confidence"], "{list_text}");
    }
    assert_names_db_rebuild("db info", &stale_info);
    assert_names_db_rebuild("db list", &stale_list);
}
