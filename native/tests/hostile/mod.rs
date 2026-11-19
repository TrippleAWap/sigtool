//! Entry points that hostile bytes are fed through, shared by the
//! deterministic robustness test (`tests/hostile_inputs.rs`) and the
//! cargo-fuzz targets (`fuzz/fuzz_targets/*.rs`, which include this file by
//! path), so both exercise exactly the same calls. Each driver only checks
//! that the library returns: any `Err` is an acceptable answer to bad input,
//! a panic, abort, or hang is not (AGENTS.md rule 8).

// Each fuzz target uses one driver; the others are dead code there.
#![allow(dead_code)]

use std::collections::HashMap;

use sigtool_native::arch::Arch;
use sigtool_native::arm_mode::ModeMap;
use sigtool_native::db::{DbView, SignatureDb};
use sigtool_native::elf::FileSource;
use sigtool_native::features;
use sigtool_native::recover::{recover, RecoveryLimits};
use sigtool_native::sigfile::Signature;
use sigtool_native::source::{ByteSource, MemorySource, Module, Region};
use sigtool_native::starts;
use sigtool_native::unwind;

/// Functions recovered and extracted per image: enough to reach the
/// decoders through every start source without making a case slow.
pub const MAX_IMAGE_FUNCTIONS: usize = 8;

/// Records parsed per database.
pub const MAX_DB_RECORDS: usize = 64;

/// Code bytes kept by [`code`]: the recovery budget is 64 KiB of function.
pub const MAX_CODE_BYTES: usize = 1 << 16;

/// The architecture [`code`] decodes its input as, from the first byte.
pub fn code_arch(selector: u8) -> Arch {
    match selector & 3 {
        0 => Arch::X64,
        1 => Arch::Arm64,
        2 => Arch::Arm32,
        _ => Arch::Thumb,
    }
}

/// The selector byte [`code`] maps to `arch` (with no other option bits).
pub fn code_selector(arch: Arch) -> u8 {
    match arch {
        Arch::X64 => 0,
        Arch::Arm64 => 1,
        Arch::Arm32 => 2,
        Arch::Thumb => 3,
    }
}

/// An ELF or PE image file, parsed the way `--file` opens it
/// (`FileSource::from_bytes`), then a bounded recovery and feature extraction
/// from each source of function starts the image offers.
pub fn image(data: &[u8]) {
    let Ok(source) = FileSource::from_bytes(data, "hostile.bin") else {
        return;
    };
    exercise(&source);
}

/// Bytes [`raw`] reads before the blob: an architecture selector (as for
/// [`code`]) and the little-endian base address.
pub const RAW_HEADER: usize = 9;

/// A raw blob, opened the way `--raw FILE --arch A --base ADDR` opens it
/// (`FileSource::from_raw`): byte 0 selects the architecture as for
/// [`code`], bytes 1-8 are the base, the rest is the blob. Then the
/// whole-image indexes a hint-free scan builds, and the same recovery as
/// [`image`].
pub fn raw(data: &[u8]) {
    if data.len() < RAW_HEADER {
        return;
    }
    let arch = code_arch(data[0]);
    let base = u64::from_le_bytes(data[1..RAW_HEADER].try_into().expect("8 bytes"));
    let blob = &data[RAW_HEADER..data.len().min(RAW_HEADER + MAX_CODE_BYTES)];
    let Ok(source) = FileSource::from_raw(blob, "hostile.bin", arch, base) else {
        return;
    };
    let _ = sigtool_native::matcher::ScanContext::build(&source);
    exercise(&source);
}

/// Bounded recovery and feature extraction from each source of function
/// starts `source` offers.
fn exercise(source: &FileSource) {
    let mut addresses: Vec<u64> = Vec::new();
    addresses.extend(
        source
            .unwind_entries()
            .iter()
            .take(MAX_IMAGE_FUNCTIONS)
            .map(|(start, _)| *start),
    );
    addresses.extend(
        source
            .synthesized_starts()
            .iter()
            .take(MAX_IMAGE_FUNCTIONS)
            .copied(),
    );
    addresses.extend(
        source
            .function_starts()
            .into_iter()
            .take(MAX_IMAGE_FUNCTIONS),
    );
    addresses.extend(
        source
            .regions()
            .iter()
            .filter(|region| region.executable)
            .take(MAX_IMAGE_FUNCTIONS)
            .map(|region| region.start),
    );
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(MAX_IMAGE_FUNCTIONS);
    for address in addresses {
        for hints in [true, false] {
            if let Ok(function) = recover(source, address, None, hints) {
                let _ = features::extract(source, &function);
            }
        }
    }
    let _ = source.symbols_stripped();
    if let Some(region) = source.regions().first() {
        let _ = source.label_for_address(region.start);
        let _ = source.read_partial(region.start, 64);
    }
}

/// A signature YAML document (`--signature`), then its canonical forms.
pub fn signature_yaml(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(signature) = Signature::from_yaml(text) else {
        return;
    };
    let _ = signature.signature_id();
    if let Ok(canonical) = signature.to_yaml() {
        let _ = Signature::from_yaml(&canonical);
    }
    let mut db = SignatureDb::new();
    if db.push(&signature).is_ok() {
        database(&db.encode());
    }
}

/// A signature database (`--db`), every record read back.
pub fn database(data: &[u8]) {
    let Ok(view) = DbView::parse(data) else {
        return;
    };
    let _ = view.spec_version();
    for index in 0..view.len().min(MAX_DB_RECORDS) {
        let _ = view.name(index);
        if let Ok(id) = view.signature_id(index) {
            let _ = view.find(id);
        }
        let _ = view.signature(index);
    }
    let _ = view.find("");
    let _ = view.find("ffffffffffffffffffffffffffffffff");
    let _ = view.signature(view.len());
}

/// Raw code bytes. The first byte selects the architecture (bits 0-1), a
/// Thumb mode map for ARM32 and the Thumb flag start synthesis sees (bit 2),
/// front-end bounds over the whole buffer (bit 3), and which unwind table
/// the copy of the bytes in a data region pretends to be (bits 4-5). The rest
/// is decoded, recovered, and featurized at a few addresses, under the
/// default and tight budgets, and swept for synthesized function starts.
pub fn code(data: &[u8]) {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let arch = code_arch(selector);
    let bytes = &bytes[..bytes.len().min(MAX_CODE_BYTES)];
    let length = bytes.len() as u64;
    let base = 0x40_0000u64;
    let data_base = base + 2 * MAX_CODE_BYTES as u64;
    let table_name = match (selector >> 4) & 3 {
        0 => ".rodata",
        1 => ".eh_frame",
        2 => ".ARM.exidx",
        _ => ".pdata",
    };
    let regions = vec![
        Region::new(".text", base, bytes.to_vec(), true, false),
        Region::new(table_name, data_base, bytes.to_vec(), false, false),
    ];
    let thumb = selector & 4 != 0;
    let thumb_ranges = if arch == Arch::Arm32 && thumb {
        vec![(base, base + length / 2)]
    } else {
        Vec::new()
    };
    let hints = if selector & 8 != 0 && length > 0 {
        vec![(base, base + length)]
    } else {
        Vec::new()
    };
    let module = Module {
        name: "hostile".to_string(),
        base,
        image_base: base,
        size: data_base + length - base,
        path: None,
        exports: Vec::new(),
        functions: HashMap::new(),
        imports: HashMap::new(),
        relocations: None,
    };
    let source = MemorySource::new(arch, regions.clone(), vec![module], hints, thumb_ranges);

    let tight = RecoveryLimits {
        max_function_bytes: 256,
        max_block_bytes: 64,
        max_instructions: 32,
        max_blocks: 8,
    };
    let align = match arch {
        Arch::X64 => 1,
        Arch::Thumb => 2,
        Arch::Arm64 | Arch::Arm32 => 4,
    };
    let mut addresses = vec![base, base + align, base + 4 * align];
    addresses.push(base + (length / 2) / align * align);
    addresses.dedup();
    for address in addresses {
        for limits in [None, Some(tight)] {
            for hinted in [false, true] {
                if let Ok(function) = recover(&source, address, limits, hinted) {
                    let _ = features::extract(&source, &function);
                }
            }
        }
    }

    let pointers: Vec<u64> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .take(256)
        .map(|word| u64::from(u32::from_le_bytes(*word)))
        .collect();
    let is_thumb = move |_: u64| thumb;
    let found = starts::evidence(arch, &regions, &pointers, &is_thumb);
    let synthesized = starts::synthesize(&found);
    let table = unwind::elf_entries(&regions, arch.pointer_size());
    let _ = starts::merge(&table, &synthesized, true);
    let _ = starts::merge(&table, &synthesized, false);
    let _ = unwind::pdata(bytes, base, arch == Arch::Arm64);
    if arch == Arch::X64 {
        let _ = starts::x64_call_targets(&regions, &table, &[base]);
    }
    if arch.is_arm() {
        let map = ModeMap::build(&regions, &pointers);
        let _ = map.is_thumb(base);
    }
}
