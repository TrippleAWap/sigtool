//! Synthesized function starts on stripped real-corpus images (G4, M9).
//!
//! Each case loads a stripped copy, as hint-free discovery does, and labels
//! its function list with the `.symtab` of the unstripped copy (labels only;
//! the stripped image never sees them). The real corpus is generated, not
//! committed: the tests read `SIGTOOL_REAL_CORPUS`, else `corpus/build-real`,
//! and skip when the image is absent. `examples/start_recall.rs` gives the
//! same measurement over the whole corpus.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sigtool_native::elf::FileSource;
use sigtool_native::source::ByteSource;

fn corpus() -> PathBuf {
    std::env::var_os("SIGTOOL_REAL_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("repo root")
                .join("corpus")
                .join("build-real")
        })
}

struct Starts {
    /// `.symtab` FUNC symbols in scanned code (not the PLT), by address.
    names: BTreeMap<u64, String>,
    /// The stripped copy's function list.
    found: BTreeSet<u64>,
}

impl Starts {
    fn misses(&self) -> Vec<&str> {
        self.names
            .iter()
            .filter(|(address, _)| !self.found.contains(address))
            .map(|(_, name)| name.as_str())
            .collect()
    }

    /// Starts that are no symbol, as `name+offset` of the symbol before them.
    fn false_starts(&self) -> Vec<String> {
        self.found
            .iter()
            .filter(|address| !self.names.contains_key(address))
            .map(|address| match self.names.range(..*address).next_back() {
                Some((start, name)) => format!("{name}+{:#x}", address - start),
                None => format!("{address:#x}"),
            })
            .collect()
    }
}

fn scanned(source: &FileSource, address: u64) -> bool {
    source.regions().iter().any(|region| {
        region.executable
            && !region.name.starts_with(".plt")
            && region.start <= address
            && address < region.end()
    })
}

fn load(arch: &str, build: &str, library: &str) -> Option<Starts> {
    let root = corpus();
    let full_path = root.join(arch).join(build).join(library);
    let stripped_path = root.join("stripped").join(arch).join(build).join(library);
    if !full_path.is_file() || !stripped_path.is_file() {
        eprintln!("skip: {} is absent", stripped_path.display());
        return None;
    }
    let full = FileSource::from_path(&full_path).expect("unstripped image");
    let stripped = FileSource::from_path(&stripped_path).expect("stripped image");
    let names = full.modules()[0]
        .functions
        .iter()
        .filter(|(address, _)| scanned(&full, **address))
        .map(|(address, name)| (*address, name.clone()))
        .collect();
    let found = stripped
        .unwind_entries()
        .iter()
        .map(|(start, _)| *start)
        .filter(|start| scanned(&stripped, *start))
        .collect();
    Some(Starts { names, found })
}

#[test]
fn thumb_calls_through_lld_thunks_name_their_callee() {
    // cJSON_DetachItemFromArray tail-calls cJSON_DetachItemViaPointer
    // through `__ThumbV7PILongThunk_cJSON_DetachItemViaPointer` (movw/movt/
    // add ip, pc/bx ip) and its PLT entry. Stripped or not, the callee must
    // be the import, not the thunk's address or its `.symtab` name.
    let root = corpus();
    let full = root.join("thumb/clang-Os/cjson.so");
    if !full.is_file() {
        eprintln!("skip: {} is absent", full.display());
        return;
    }
    // The address comes from the unstripped copy's labels.
    let address = FileSource::from_path(&full).expect("image").modules()[0]
        .functions
        .iter()
        .find(|(_, name)| name.as_str() == "cJSON_DetachItemFromArray")
        .map(|(address, _)| *address)
        .expect("cJSON_DetachItemFromArray");
    for image in [root.join("stripped/thumb/clang-Os/cjson.so"), full] {
        if !image.is_file() {
            eprintln!("skip: {} is absent", image.display());
            return;
        }
        let source = FileSource::from_path(&image).expect("image");
        let result =
            sigtool_native::generate::generate(&source, address, None, None, None, None, None)
                .expect("generate");
        let yaml = result.to_yaml().expect("yaml");
        assert!(
            yaml.contains("callee:cJSON_DetachItemViaPointer"),
            "{}: {yaml}",
            image.display()
        );
        assert!(!yaml.contains("Thunk"), "{}", image.display());
    }
}

#[test]
fn source_twins_are_candidates_not_answers() {
    // `cJSONUtils_GeneratePatches` and `..CaseSensitive` differ in one
    // boolean argument. gcc's arm32 copy materialises its `false` from a
    // comparison (`moveq r6, #1`), so the signature requires `0x1` and, in a
    // stripped arm64 gcc build, matches the twin that passes `true`; the
    // true function, holding the same keys, is the rival.
    let root = corpus();
    let full = root.join("arm32/gcc-O2/cjson.so");
    let image = root.join("stripped/arm64/gcc-O2/cjson.so");
    if !full.is_file() || !image.is_file() {
        eprintln!("skip: {} is absent", image.display());
        return;
    }
    let signed = FileSource::from_path(&full).expect("image");
    let address = signed.modules()[0]
        .functions
        .iter()
        .find(|(_, name)| name.as_str() == "cJSONUtils_GeneratePatches")
        .map(|(address, _)| *address)
        .expect("cJSONUtils_GeneratePatches");
    let signature =
        sigtool_native::generate::generate(&signed, address, None, None, None, None, None)
            .expect("generate")
            .signature;
    let source = FileSource::from_path(&image).expect("image");
    let context = sigtool_native::matcher::ScanContext::build(&source);
    let matches = sigtool_native::matcher::scan_in(&source, &signature, &context, false);
    let first = matches.first().expect("a match");
    assert!(first.rival.is_some(), "{first:?}");
    assert_ne!(
        sigtool_native::matcher::evidence(&matches, 0),
        sigtool_native::matcher::Evidence::Identified,
        "{first:?}"
    );
}

#[test]
fn gcc_pic_strings_after_text_resolve() {
    // GNU ld puts arm32 `.rodata` after `.text` in one segment, so gcc's
    // `ldr r0, =.LC0-(.LPIC0+8); .LPIC0: add r0, pc, r0` pools a small
    // positive offset that also passes for an in-module address. It must
    // still reach the `add` and resolve to the string (both modes).
    let root = corpus();
    for arch in ["arm32", "thumb"] {
        for build in ["gcc-O0", "gcc-O2", "gcc-Os"] {
            let full = root.join(arch).join(build).join("lz4.so");
            let image = root.join("stripped").join(arch).join(build).join("lz4.so");
            if !full.is_file() || !image.is_file() {
                eprintln!("skip: {} is absent", image.display());
                continue;
            }
            // The address comes from the unstripped copy's labels.
            let address = FileSource::from_path(&full).expect("image").modules()[0]
                .functions
                .iter()
                .find(|(_, name)| name.as_str() == "LZ4_versionString")
                .map(|(address, _)| *address)
                .expect("LZ4_versionString");
            let source = FileSource::from_path(&image).expect("image");
            let recovered =
                sigtool_native::recover::recover(&source, address, None, false).expect("recover");
            let keys: Vec<String> = sigtool_native::features::extract(&source, &recovered)
                .iter()
                .map(|feature| feature.key())
                .collect();
            assert!(
                keys.iter().any(|key| key == "str:1.10.0"),
                "{arch}/{build}: {keys:?}"
            );
            assert!(
                !keys.iter().any(|key| key.starts_with("const:")),
                "{arch}/{build}: the pooled offset leaked as a constant: {keys:?}"
            );
        }
    }
}

#[test]
fn lld_thumb_thunks_are_function_starts() {
    // lld places `__ThumbV7PILongThunk_*` back to back at the end of
    // `.text`; they open with `movw ip` (no prologue) and are reached only
    // by `b.w`, so before the stub rule none of them was a start.
    for build in ["clang-O2", "clang-Os"] {
        let Some(starts) = load("thumb", build, "lua.so") else {
            return;
        };
        let thunks: Vec<&str> = starts
            .misses()
            .into_iter()
            .filter(|name| name.contains("Thunk_"))
            .collect();
        assert!(thunks.is_empty(), "thumb/{build}: {thunks:?}");
        assert!(starts.names.values().any(|name| name.contains("Thunk_")));
    }
}

#[test]
fn functions_after_a_noreturn_call_and_its_pool_are_starts() {
    // gcc: luaV_objlen ends `bl luaG_typeerror` (noreturn, local), its
    // literal pool follows, then `luaV_idiv` opens with `push`; luaV_idiv is
    // reached only by a `b.w` tail call, and no terminator precedes it.
    for arch in ["thumb", "arm32"] {
        let Some(starts) = load(arch, "gcc-O2", "lua.so") else {
            return;
        };
        assert!(
            !starts.misses().contains(&"luaV_idiv"),
            "{arch}: luaV_idiv missed"
        );
    }
}

#[test]
fn pic_function_addresses_are_function_starts() {
    // Leaf callbacks referenced only by address, formed as
    // `ldr rX, =sym-(.LPIC+pc); .LPIC: add rX, pc` (gcc, both modes).
    for (arch, names) in [
        ("thumb", ["sqlite3NoopDestructor", "renameTableExprCb"]),
        ("arm32", ["sqlite3NoopDestructor", "renameTableExprCb"]),
    ] {
        let Some(starts) = load(arch, "gcc-O2", "sqlite.so") else {
            return;
        };
        let misses = starts.misses();
        for name in names {
            assert!(!misses.contains(&name), "{arch}: {name} missed");
        }
    }
}

#[test]
fn thumb_computed_goto_labels_are_not_function_starts() {
    // lua's `luaV_execute` dispatches through a table of `&&label`
    // addresses with `R_ARM_RELATIVE` relocations, like a function-pointer
    // table, but the labels are even in Thumb code. Before the mode check,
    // all 83 labels became starts and cut `luaV_execute` into pieces.
    labels_stay_inside_luav_execute("thumb");
}

#[test]
fn arm_computed_goto_tables_are_not_function_starts() {
    // In ARM code the labels are even like functions, so the mode check
    // cannot tell them apart; `starts::label_tables` does, because all 83
    // targets fall between the same two known starts.
    labels_stay_inside_luav_execute("arm32");
}

fn labels_stay_inside_luav_execute(arch: &str) {
    for build in ["gcc-O0", "gcc-O2", "clang-O2"] {
        let Some(starts) = load(arch, build, "lua.so") else {
            return;
        };
        let inside: Vec<String> = starts
            .false_starts()
            .into_iter()
            .filter(|start| start.starts_with("luaV_execute+"))
            .collect();
        assert!(inside.is_empty(), "{arch}/{build}: {inside:?}");
        assert!(!starts.misses().contains(&"luaV_execute"));
    }
}
