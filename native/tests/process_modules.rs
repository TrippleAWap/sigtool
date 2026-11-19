//! The live-process scan path on clang + lld output, without a live process:
//! stripped shared objects linked at different bases are mapped into one
//! source the way `ProcessSource` maps loaded modules (every module's
//! regions in one address space, unwind-table entries only, no symbol
//! starts), and scanned through `scanner::scan_modules`, the path
//! `scan --pid` and `locate --pid` take. Each signature must be found in the
//! module it was signed from, at the right `module+rva`, with the verdict a
//! scan of that module alone gives; a second copy of the same module makes
//! the answer a rival, not an identification.

use std::path::{Path, PathBuf};
use std::process::Command;

use sigtool_native::arch::Arch;
use sigtool_native::coverage::Coverage;
use sigtool_native::elf::FileSource;
use sigtool_native::errors::ReadError;
use sigtool_native::generate::generate;
use sigtool_native::matcher::{evidence, Evidence, Match};
use sigtool_native::scanner::scan_modules;
use sigtool_native::sigfile::Signature;
use sigtool_native::source::{read_regions, ByteSource, Module, ModuleView, Region};

mod common;

/// Functions with their own constants, enough of them for the frequency
/// gates of hint-free scans to apply. `seed` keeps two libraries' constants
/// apart.
fn library(prefix: &str, seed: u32) -> String {
    let mut code = String::new();
    for n in 0..40u32 {
        code.push_str(&format!(
            "__attribute__((noinline)) unsigned {prefix}{n}(unsigned x, unsigned y) {{\n\
             \x20   unsigned a = x * 0x{:x}u;\n\
             \x20   if (a > y)\n\
             \x20       a ^= 0x{:x}u;\n\
             \x20   return a + (y >> {});\n\
             }}\n",
            seed + n * 0x101,
            (seed ^ 0x5bd1_0000) + n * 0x11,
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

/// Build `name.so` from `code` linked at `base`, and its stripped copy
/// `stripped/name.so` (same file name, so the same module name); return
/// both paths.
fn build(dir: &Path, name: &str, code: &str, base: u64) -> (PathBuf, PathBuf) {
    let c_file = format!("{name}.c");
    std::fs::write(dir.join(&c_file), code).unwrap();
    std::fs::create_dir_all(dir.join("stripped")).unwrap();
    let image = format!("{name}.so");
    let stripped = format!("stripped/{name}.so");
    tool(
        "clang",
        &[
            "--target=x86_64-linux-gnu",
            "-O1",
            "-fPIC",
            "-shared",
            "-nostdlib",
            "-fuse-ld=lld",
            &format!("-Wl,--image-base=0x{base:x}"),
            &c_file,
            "-o",
            &image,
        ],
        dir,
    );
    tool("llvm-strip", &["--strip-all", &image, "-o", &stripped], dir);
    (dir.join(image), dir.join(stripped))
}

/// Loaded modules in one address space, as `ProcessSource` exposes them:
/// sorted regions and modules, the unwind tables' own entries (a process
/// source synthesizes no starts), no symbol starts, `.pdata`-style bounds
/// as hints.
struct Process {
    regions: Vec<Region>,
    modules: Vec<Module>,
    unwind: Vec<(u64, u64)>,
}

impl Process {
    fn new(files: &[&FileSource]) -> Process {
        let mut regions: Vec<Region> = Vec::new();
        let mut modules: Vec<Module> = Vec::new();
        let mut unwind: Vec<(u64, u64)> = Vec::new();
        for file in files {
            regions.extend(file.regions().iter().cloned());
            modules.extend(file.modules().iter().cloned());
            let synthesized = file.synthesized_starts();
            unwind.extend(
                file.unwind_entries()
                    .iter()
                    .filter(|(start, _)| synthesized.binary_search(start).is_err()),
            );
        }
        regions.sort_by_key(|region| region.start);
        modules.sort_by_key(|module| module.base);
        unwind.sort_unstable();
        Process {
            regions,
            modules,
            unwind,
        }
    }
}

impl ByteSource for Process {
    fn arch(&self) -> Arch {
        Arch::X64
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        read_regions(&self.regions, addr, size)
    }

    fn regions(&self) -> &[Region] {
        &self.regions
    }

    fn modules(&self) -> &[Module] {
        &self.modules
    }

    fn symbols_stripped(&self) -> bool {
        true
    }

    fn unwind_entries(&self) -> &[(u64, u64)] {
        &self.unwind
    }

    fn hint_function(&self, addr: u64) -> Option<(u64, u64)> {
        self.unwind_function(addr).filter(|(_, end)| *end != 0)
    }
}

fn sign(image: &Path, name: &str) -> Signature {
    let source = FileSource::from_path(image).expect("load image");
    generate(
        &source,
        symbol(image, name),
        Some(name),
        None,
        None,
        None,
        None,
    )
    .expect("generate")
    .signature
}

fn scan(process: &Process, signatures: &[Signature], only: Option<u64>) -> Vec<Vec<Match>> {
    scan_modules(process, signatures, only, None, &mut Coverage::new())
}

#[test]
fn a_process_is_scanned_one_module_at_a_time() {
    if !common::have_tools(&["clang", "ld.lld", "llvm-nm", "llvm-strip"]) {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sigtool-process-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let base_a = 0x1000_0000u64;
    let base_b = 0x2000_0000u64;
    let base_copy = 0x3000_0000u64;
    let (image_a, stripped_a) = build(&dir, "liba", &library("f", 0x9e37_0000), base_a);
    let (image_b, stripped_b) = build(&dir, "libb", &library("g", 0x7f4a_0000), base_b);
    let (_, stripped_copy) = build(&dir, "libcopy", &library("f", 0x9e37_0000), base_copy);
    let signatures = [sign(&image_a, "f7"), sign(&image_b, "g11")];
    let expected = [
        ("liba", symbol(&image_a, "f7") - base_a),
        ("libb", symbol(&image_b, "g11") - base_b),
    ];

    let a = FileSource::from_path(&stripped_a).expect("load liba");
    let b = FileSource::from_path(&stripped_b).expect("load libb");
    let copy = FileSource::from_path(&stripped_copy).expect("load libcopy");
    let process = Process::new(&[&a, &b]);
    assert_eq!(process.modules().len(), 2);

    // The view shows one module as a stripped image of its own.
    let module_a = &process.modules()[0];
    let view = ModuleView::new(&process, module_a);
    assert!(view.symbols_stripped());
    assert!(view.function_starts().is_empty());
    assert_eq!(view.modules().len(), 1);
    assert!(!view.regions().is_empty());
    assert!(view
        .regions()
        .iter()
        .all(|region| module_a.contains(region.start, 1)));
    assert!(!view.unwind_entries().is_empty());
    assert!(view
        .unwind_entries()
        .iter()
        .all(|(start, _)| module_a.contains(*start, 1)));
    assert!(view.read(base_b, 4).is_err(), "reads stop at the module");
    assert!(!view.is_mapped(base_b, 1));
    assert!(view.read_partial(base_b, 16).is_empty());

    let found = scan(&process, &signatures, None);
    for (index, (module, rva)) in expected.iter().enumerate() {
        let matches = &found[index];
        let first = matches
            .first()
            .unwrap_or_else(|| panic!("{} found", signatures[index].name));
        let owner = process.module_for(first.address).expect("in a module");
        assert_eq!(owner.name, *module, "{}", signatures[index].name);
        assert_eq!(owner.rva(first.address), *rva, "{}", signatures[index].name);
        assert_eq!(evidence(matches, 0), Evidence::Identified, "{matches:?}");
    }

    // Another module changes nothing a module's own scan decides.
    let alone = scan(&Process::new(&[&a]), &signatures[..1], None);
    let in_a: Vec<&Match> = found[0]
        .iter()
        .filter(|matched| module_a.contains(matched.address, 1))
        .collect();
    assert_eq!(in_a, alone[0].iter().collect::<Vec<_>>());

    // `--module` keeps one module's matches.
    let module_b = &process.modules()[1];
    assert_eq!(module_b.name, "libb");
    let only_b = scan(&process, &signatures, Some(module_b.base));
    assert!(only_b[0]
        .iter()
        .all(|matched| module_b.contains(matched.address, 1)));
    assert_eq!(only_b[1], found[1]);

    // The same code loaded twice: both copies match, neither is identified.
    let twice = Process::new(&[&a, &copy]);
    let matches = &scan(&twice, &signatures[..1], None)[0];
    let tops: Vec<u64> = matches
        .iter()
        .filter(|matched| {
            twice
                .module_for(matched.address)
                .unwrap()
                .rva(matched.address)
                == expected[0].1
        })
        .map(|matched| matched.address)
        .collect();
    assert_eq!(tops.len(), 2, "{matches:?}");
    assert_ne!(evidence(matches, 0), Evidence::Identified, "{matches:?}");

    // Deterministic: the same scan twice gives the same lists.
    assert_eq!(scan(&process, &signatures, None), found);
    let _ = std::fs::remove_dir_all(&dir);
}
