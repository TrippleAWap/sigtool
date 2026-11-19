//! ELF inputs that a loader accepts but our parser once read differently or
//! refused: packed relative relocations (`-z pack-relative-relocs`,
//! `SHT_RELR`) and images without section headers (`llvm-objcopy
//! --strip-sections`). Each test builds twins from one source with clang and
//! lld and requires them to give the same features and the same hint-free
//! matches.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sigtool_native::elf::FileSource;
use sigtool_native::source::ByteSource;

mod common;

/// Pointer tables (strings and functions), a writable pointer, and constants,
/// so the relocation set decides which words are addresses. The fillers give
/// the image the function count hint-free discovery needs.
fn relocation_heavy_source() -> String {
    let mut code = String::from(
        "static const char *const names[] = {\"alpha state\", \"beta state\",\n\
         \x20   \"gamma state\", \"delta state\"};\n\
         __attribute__((noinline)) static const char *state_name(unsigned i) {\n\
         \x20   return names[i & 3];\n\
         }\n\
         __attribute__((noinline)) static int add3(int x) { return x + 3; }\n\
         __attribute__((noinline)) static int mul5(int x) { return x * 5; }\n\
         __attribute__((noinline)) static int xor7(int x) { return x ^ 0x7777; }\n\
         static int (*const ops[])(int) = {add3, mul5, xor7};\n\
         __attribute__((noinline)) static int apply(unsigned i, int x) {\n\
         \x20   return ops[i % 3](x) * (int)0x9e3779b1u;\n\
         }\n\
         static const unsigned table[] = {0x12345678u, 0x9abcdef0u, 0x0badf00du, 0xdeadbeefu};\n\
         __attribute__((noinline)) static unsigned lookup(unsigned i) {\n\
         \x20   return table[i & 3] ^ 0x5bd1e995u;\n\
         }\n\
         static const char *mode = \"initial mode banner\";\n\
         __attribute__((noinline)) static const char *swap_mode(const char *next) {\n\
         \x20   const char *old = mode;\n\
         \x20   mode = next;\n\
         \x20   return old;\n\
         }\n\
         const char *describe(unsigned i, int x) {\n\
         \x20   return apply(i, x) > 7 ? state_name(lookup(i)) : swap_mode(\"next mode\");\n\
         }\n",
    );
    for n in 0..40 {
        code.push_str(&format!(
            "unsigned filler{n}(unsigned x) {{ return lookup(x + {n}) * {}u + (unsigned)apply(x, {n}); }}\n",
            2 * n + 3
        ));
    }
    code
}

/// The functions each test compares: the table users and two fillers.
const FUNCTIONS: [&str; 6] = [
    "state_name",
    "apply",
    "lookup",
    "swap_mode",
    "filler3",
    "filler17",
];

fn run(command: &mut Command, what: &str) -> Vec<u8> {
    let output = command.output().unwrap_or_else(|_| panic!("run {what}"));
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// `source` built as a PIC shared object for `target`, with `extra` flags.
fn build(dir: &Path, name: &str, target: &str, extra: &[&str], source: &Path) -> PathBuf {
    let image = dir.join(name);
    run(
        Command::new("clang")
            .arg(format!("--target={target}"))
            .args(["-O2", "-fPIC", "-shared", "-nostdlib", "-fuse-ld=lld"])
            .args(extra)
            .arg(source)
            .arg("-o")
            .arg(&image),
        "clang",
    );
    image
}

fn strip_all(image: &Path) -> PathBuf {
    let stripped = image.with_extension("stripped.so");
    run(
        Command::new("llvm-strip")
            .arg("--strip-all")
            .arg(image)
            .arg("-o")
            .arg(&stripped),
        "llvm-strip",
    );
    stripped
}

/// `.symtab` function addresses, Thumb bit cleared.
fn symbols(image: &Path) -> HashMap<String, u64> {
    let text = run(Command::new("llvm-nm").arg(image), "llvm-nm");
    String::from_utf8(text)
        .expect("utf-8")
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let address = u64::from_str_radix(parts.next()?, 16).ok()?;
            let kind = parts.next()?;
            let name = parts.next()?;
            matches!(kind, "t" | "T").then(|| (name.to_string(), address & !1))
        })
        .collect()
}

fn sigtool(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
        .args(args)
        .output()
        .expect("run sigtool-native")
}

/// `gen` for `address`, without the parts that name a place in one image
/// (provenance and call-graph links hold its RVAs).
fn signature(image: &Path, address: u64, output: &Path) -> serde_norway::Value {
    let result = sigtool(&[
        "gen",
        "--file",
        image.to_str().unwrap(),
        "--addr",
        &format!("0x{address:x}"),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "gen {}: {}",
        image.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    let mut document: serde_norway::Value =
        serde_norway::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
    let mapping = document.as_mapping_mut().expect("signature mapping");
    mapping.remove("provenance");
    mapping.remove("links");
    document
}

/// Each hint-free match of `signature` in `image`, by function name (or
/// `?` for an unnamed address), with what makes it that match.
fn locate(signature: &Path, image: &Path, names: &HashMap<u64, String>) -> Vec<String> {
    let json = signature.with_extension("json");
    let output = sigtool(&[
        "locate",
        "--signature",
        signature.to_str().unwrap(),
        "--file",
        image.to_str().unwrap(),
        "--discovery",
        "hint-free",
        "--json",
        json.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        matches!(output.status.code(), Some(0 | 1)),
        "locate {}: {}",
        image.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let hex = |value: &serde_json::Value| {
        u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    document["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| {
            let (start, end) = (hex(&hit["address"]), hex(&hit["end"]));
            format!(
                "{} +0x{:x} score {} {} {}",
                names.get(&start).map_or("?", String::as_str),
                end - start,
                hit["score"],
                hit["evidence"],
                hit["matched"]
            )
        })
        .collect()
}

fn by_address(symbols: &HashMap<String, u64>) -> HashMap<u64, String> {
    symbols
        .iter()
        .map(|(name, address)| (*address, name.clone()))
        .collect()
}

/// The four targets, with the flags that pick Thumb.
const TARGETS: [(&str, &str, &[&str]); 4] = [
    ("x64", "x86_64-linux-gnu", &[]),
    ("arm64", "aarch64-linux-gnu", &[]),
    ("arm32", "armv7-linux-gnueabihf", &[]),
    ("thumb", "armv7-linux-gnueabihf", &["-mthumb"]),
];

/// Builds the relocation-heavy source plain and with `packing` (linker
/// flags), checks that `llvm-readelf -S` of the packed image names `marker`,
/// and requires the twins to give the same relocated-word count, signatures,
/// and hint-free matches. The packed image's section-less copy, whose tables
/// come from `PT_DYNAMIC`, must read like its `--strip-all` copy.
fn assert_packed_twin(packing: &str, marker: &str) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("tables.c");
    std::fs::write(&source, relocation_heavy_source()).unwrap();
    for (arch, target, mode) in TARGETS {
        let plain = build(dir.path(), &format!("{arch}.so"), target, mode, &source);
        let flags: Vec<&str> = mode.iter().copied().chain([packing]).collect();
        let packed = build(
            dir.path(),
            &format!("{arch}-packed.so"),
            target,
            &flags,
            &source,
        );
        let sections = run(
            Command::new("llvm-readelf").arg("-S").arg(&packed),
            "llvm-readelf",
        );
        assert!(
            String::from_utf8_lossy(&sections).contains(marker),
            "{arch}: no {marker} section, so the test would not test {packing}"
        );

        // Layouts differ (the packed table is smaller), so only the count of
        // relocated words can be compared directly.
        let count = |image: &Path| {
            let source = FileSource::from_path(image).expect("parse image");
            source.modules()[0]
                .relocations
                .as_ref()
                .map(Vec::len)
                .unwrap_or(0)
        };
        assert!(count(&plain) > 0, "{arch}: no relocations in the twin");
        assert_eq!(count(&plain), count(&packed), "{arch}: relocated words");

        let (plain_symbols, packed_symbols) = (symbols(&plain), symbols(&packed));
        let (plain_stripped, packed_stripped) = (strip_all(&plain), strip_all(&packed));
        let sectionless = packed.with_extension("sectionless.so");
        run(
            Command::new("llvm-objcopy")
                .arg("--strip-sections")
                .arg(&packed)
                .arg(&sectionless),
            "llvm-objcopy",
        );
        assert_eq!(
            loader_view(&packed_stripped).0,
            loader_view(&sectionless).0,
            "{arch}: section-less packed image"
        );
        for function in FUNCTIONS {
            let label = format!("{arch} {function}");
            let plain_yaml = dir.path().join(format!("{arch}-{function}.yaml"));
            let packed_yaml = dir.path().join(format!("{arch}-{function}-packed.yaml"));
            assert_eq!(
                signature(&plain, plain_symbols[function], &plain_yaml),
                signature(&packed, packed_symbols[function], &packed_yaml),
                "{label}: signatures"
            );
            assert_eq!(
                locate(&plain_yaml, &plain_stripped, &by_address(&plain_symbols)),
                locate(&packed_yaml, &packed_stripped, &by_address(&packed_symbols)),
                "{label}: hint-free matches"
            );
        }
    }
}

const PACKED_TOOLS: [&str; 6] = [
    "clang",
    "ld.lld",
    "llvm-nm",
    "llvm-strip",
    "llvm-readelf",
    "llvm-objcopy",
];

/// lld's packed relative relocations move every aligned relative relocation
/// out of `.rela.dyn` into `.relr.dyn`. Those words are still addresses
/// (SPEC.md §2.2) and still seed start synthesis, so the packed image must
/// match its unpacked twin.
#[test]
fn packed_relative_relocations_match_their_unpacked_twin() {
    if common::have_tools(&PACKED_TOOLS) {
        assert_packed_twin("-Wl,-z,pack-relative-relocs", ".relr.dyn");
    }
}

/// What a hint-free scan reads from an image's tables, which must not depend
/// on whether the section headers survive, and the module's lowest address.
///
/// That base is the one thing allowed to move: without sections it is the
/// end of the program headers, with them the first section, which can sit a
/// few bytes of alignment padding higher. No code or data lives there.
fn loader_view(image: &Path) -> (String, u64) {
    let source = FileSource::from_path(image)
        .unwrap_or_else(|error| panic!("{}: {error:?}", image.display()));
    let module = &source.modules()[0];
    let mut imports: Vec<_> = module.imports.iter().collect();
    imports.sort();
    let mut functions: Vec<_> = module.functions.iter().collect();
    functions.sort();
    let thumb: Vec<bool> = source
        .unwind_entries()
        .iter()
        .map(|(start, _)| source.is_thumb(*start))
        .collect();
    let view = format!(
        "image base 0x{:x} end 0x{:x}\nexports {:?}\nfunctions {functions:?}\n\
         imports {imports:?}\nrelocations {:?}\nunwind {:x?}\nsynthesized {:x?}\nthumb {thumb:?}",
        module.image_base,
        module.end(),
        module.exports,
        module.relocations,
        source.unwind_entries(),
        source.synthesized_starts(),
    );
    (view, module.base)
}

/// `llvm-objcopy --strip-sections` keeps only what the loader reads: program
/// headers, `PT_DYNAMIC`, and the unwind tables behind `PT_GNU_EH_FRAME` and
/// `PT_ARM_EXIDX`, all of which also survive `strip --strip-all`. So the
/// section-less copy must give the same tables and the same hint-free
/// matches as the `--strip-all` copy, for toy-corpus executables (static,
/// no unwind tables: starts come from code) and for shared objects.
#[test]
fn section_less_images_match_their_strip_all_twin() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip", "llvm-objcopy"]) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("corpus")
        .join("src");
    let shared = dir.path().join("tables.c");
    std::fs::write(&shared, relocation_heavy_source()).unwrap();
    // As `corpus/build.py` links the toy corpus, without debug info.
    let toy: &[&str] = &[
        "-nostdlib",
        "-static",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-Wl,-e,_start",
    ];
    let builds: [(&str, &[&str], &[&str]); 3] = [
        (
            "loops",
            toy,
            &[
                "accumulate",
                "collatz_length",
                "mix64",
                "counter_state",
                "table_walk",
            ],
        ),
        (
            "parser",
            toy,
            &[
                "parse_record",
                "record_error",
                "record_score",
                "record_copy",
            ],
        ),
        ("tables", &[], &FUNCTIONS),
    ];
    let (mut found, mut compared) = (0, 0);
    for (arch, target, mode) in TARGETS {
        for (name, flags, functions) in builds {
            let mut extra: Vec<&str> = flags.to_vec();
            extra.extend(mode);
            let image = if name == "tables" {
                build(
                    dir.path(),
                    &format!("{arch}-{name}.so"),
                    target,
                    &extra,
                    &shared,
                )
            } else {
                // Not `build`: the toy corpus is linked static, not shared.
                let image = dir.path().join(format!("{arch}-{name}.so"));
                run(
                    Command::new("clang")
                        .arg(format!("--target={target}"))
                        .args(["-O2", "-fuse-ld=lld"])
                        .args(&extra)
                        .arg(corpus.join(format!("{name}.c")))
                        .arg("-o")
                        .arg(&image),
                    "clang",
                );
                image
            };
            let stripped = strip_all(&image);
            let sectionless = image.with_extension("sectionless.so");
            run(
                Command::new("llvm-objcopy")
                    .arg("--strip-sections")
                    .arg(&image)
                    .arg(&sectionless),
                "llvm-objcopy",
            );
            let label = format!("{arch} {name}");
            let ((want, base), (got, headers_end)) =
                (loader_view(&stripped), loader_view(&sectionless));
            assert_eq!(want, got, "{label}: loader view");
            assert!(
                headers_end <= base && base - headers_end < 0x40,
                "{label}: base 0x{base:x} with sections, 0x{headers_end:x} without"
            );
            if name == "tables" {
                assert!(
                    !FileSource::from_path(&sectionless)
                        .unwrap()
                        .unwind_entries()
                        .is_empty(),
                    "{label}: no unwind entries, so the test would not test them"
                );
            }
            let symbols = symbols(&image);
            let names = by_address(&symbols);
            for function in functions {
                let yaml = dir.path().join(format!("{arch}-{name}-{function}.yaml"));
                signature(&image, symbols[*function], &yaml);
                let want = locate(&yaml, &stripped, &names);
                found += usize::from(
                    want.first()
                        .is_some_and(|hit| hit.starts_with(&format!("{function} "))),
                );
                compared += 1;
                assert_eq!(
                    want,
                    locate(&yaml, &sectionless, &names),
                    "{label} {function}: hint-free matches"
                );
            }
        }
    }
    // Equal empty answers would pass too: most functions must be found (59 of
    // 60 with LLVM 22.1.5).
    assert!(
        4 * found >= 3 * compared,
        "only {found} of {compared} functions found in the --strip-all copies"
    );
}
