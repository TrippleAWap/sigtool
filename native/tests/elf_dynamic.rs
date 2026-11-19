//! Dynamic tables from `PT_DYNAMIC`: an ELF image whose
//! section table names only its allocated sections, all as plain
//! `SHT_PROGBITS`, as the IDA plugin writes when it rebuilds an image from an
//! IDB, must give the same module (exports, function symbols, imports,
//! relocations), regions, and unwind entries as the stripped file it came
//! from. The real corpus is generated, not committed, so the test skips when
//! `corpus/build-real` is absent.

use std::path::{Path, PathBuf};

use sigtool_native::elf::FileSource;
use sigtool_native::source::ByteSource;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// `data` with its section table replaced by one listing only the allocated
/// sections, each `SHT_PROGBITS` (or `SHT_NOBITS`), plus `.shstrtab`.
fn allocated_sections_only(data: &[u8]) -> Vec<u8> {
    let wide = data[4] == 2;
    let (shoff, entsize, count, names_index) = if wide {
        (
            u64_at(data, 0x28) as usize,
            u16_at(data, 0x3A) as usize,
            u16_at(data, 0x3C) as usize,
            u16_at(data, 0x3E) as usize,
        )
    } else {
        (
            u32_at(data, 0x20) as usize,
            u16_at(data, 0x2E) as usize,
            u16_at(data, 0x30) as usize,
            u16_at(data, 0x32) as usize,
        )
    };
    // (name offset, kind, flags, addr, offset, size)
    let row = |index: usize| -> (u32, u32, u64, u64, u64, u64) {
        let at = shoff + index * entsize;
        if wide {
            (
                u32_at(data, at),
                u32_at(data, at + 4),
                u64_at(data, at + 8),
                u64_at(data, at + 16),
                u64_at(data, at + 24),
                u64_at(data, at + 32),
            )
        } else {
            (
                u32_at(data, at),
                u32_at(data, at + 4),
                u64::from(u32_at(data, at + 8)),
                u64::from(u32_at(data, at + 12)),
                u64::from(u32_at(data, at + 16)),
                u64::from(u32_at(data, at + 20)),
            )
        }
    };
    let names = row(names_index);
    let names = &data[names.4 as usize..(names.4 + names.5) as usize];
    let name = |offset: u32| -> &[u8] {
        let start = offset as usize;
        let end = start + names[start..].iter().position(|b| *b == 0).unwrap();
        &names[start..end]
    };

    let mut strings = vec![0u8];
    let mut rows: Vec<(u32, u32, u64, u64, u64, u64)> = vec![(0, 0, 0, 0, 0, 0)];
    for index in 0..count {
        let (name_off, kind, flags, addr, offset, size) = row(index);
        if flags & 0x2 == 0 || size == 0 {
            continue;
        }
        let at = strings.len() as u32;
        strings.extend_from_slice(name(name_off));
        strings.push(0);
        let kind = if kind == 8 { 8 } else { 1 };
        rows.push((at, kind, flags, addr, offset, size));
    }
    let table_name = strings.len() as u32;
    strings.extend_from_slice(b".shstrtab\0");
    let mut out = data.to_vec();
    let strings_at = out.len() as u64;
    rows.push((table_name, 3, 0, 0, strings_at, strings.len() as u64));
    out.extend_from_slice(&strings);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    let table_at = out.len();
    for (name_off, kind, flags, addr, offset, size) in &rows {
        out.extend_from_slice(&name_off.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        if wide {
            for value in [*flags, *addr, *offset, *size] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            out.extend_from_slice(&[0; 8]); // link, info
            out.extend_from_slice(&1u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
        } else {
            for value in [*flags, *addr, *offset, *size] {
                out.extend_from_slice(&(value as u32).to_le_bytes());
            }
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    let rows_count = rows.len() as u16;
    if wide {
        out[0x28..0x30].copy_from_slice(&(table_at as u64).to_le_bytes());
        out[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        out[0x3C..0x3E].copy_from_slice(&rows_count.to_le_bytes());
        out[0x3E..0x40].copy_from_slice(&(rows_count - 1).to_le_bytes());
    } else {
        out[0x20..0x24].copy_from_slice(&(table_at as u32).to_le_bytes());
        out[0x2E..0x30].copy_from_slice(&40u16.to_le_bytes());
        out[0x30..0x32].copy_from_slice(&rows_count.to_le_bytes());
        out[0x32..0x34].copy_from_slice(&(rows_count - 1).to_le_bytes());
    }
    out
}

#[test]
fn dynamic_tables_stand_in_for_a_section_table_without_them() {
    let corpus = repo_root()
        .join("corpus")
        .join("build-real")
        .join("stripped");
    let mut checked = 0;
    for arch in ["x64", "arm64", "arm32", "thumb"] {
        for build in ["clang-O2", "gcc-O2"] {
            for library in ["zlib", "lz4", "cjson"] {
                let path = corpus.join(arch).join(build).join(format!("{library}.so"));
                let Ok(data) = std::fs::read(&path) else {
                    continue;
                };
                let name = format!("{library}.so");
                let original = FileSource::from_bytes(&data, &name).expect("stripped image");
                let rebuilt = FileSource::from_bytes(&allocated_sections_only(&data), &name)
                    .expect("rebuilt image");
                let label = path.display();
                let (want, got) = (&original.modules()[0], &rebuilt.modules()[0]);
                assert!(!want.exports.is_empty(), "{label}: no exports to compare");
                assert_eq!(want.exports, got.exports, "{label}: exports");
                assert_eq!(want.functions, got.functions, "{label}: function symbols");
                assert_eq!(want.imports, got.imports, "{label}: imports");
                assert_eq!(want.relocations, got.relocations, "{label}: relocations");
                assert_eq!(
                    (want.base, want.image_base, want.size),
                    (got.base, got.image_base, got.size),
                    "{label}: module extent"
                );
                assert_eq!(original.regions(), rebuilt.regions(), "{label}: regions");
                assert_eq!(
                    original.unwind_entries(),
                    rebuilt.unwind_entries(),
                    "{label}: unwind entries"
                );
                checked += 1;
            }
        }
    }
    if checked == 0 {
        eprintln!(
            "skipping: {} has no stripped real-corpus images (run python corpus/real.py)",
            corpus.display()
        );
    }
}
