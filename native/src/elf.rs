//! Image-file byte source for ELF and PE containers.
//!
//! Relocatable ELF objects (`ET_REL`) have no virtual addresses, so their
//! sections are placed at `ELF_PLACE_BASE + file offset`. The placement is
//! injective and keeps intra-object references resolvable without linking.
//!
//! The parser mirrors `sources/file.py`; divergence would change feature
//! records, so it is kept deliberately close to the Python code.

use std::collections::HashMap;
use std::path::Path;

use crate::arch::{detect, Arch};
use crate::arm_mode::ModeMap;
use crate::errors::{ReadError, SourceFormatError};
use crate::source::{read_regions, ByteSource, Module, Region};
use crate::starts;

pub const ELF_PLACE_BASE: u64 = 0x1000_0000;

const ELF_SHT_SYMTAB: u32 = 2;
const ELF_SHT_RELA: u32 = 4;
const ELF_SHT_NOBITS: u32 = 8;
const ELF_SHT_REL: u32 = 9;
const ELF_SHT_DYNSYM: u32 = 11;
const ELF_SHF_WRITE: u64 = 0x1;
const ELF_SHF_ALLOC: u64 = 0x2;
const ELF_SHF_EXECINSTR: u64 = 0x4;
const ELF_STT_FUNC: u8 = 2;
const ELF_ET_REL: u16 = 1;
const R_ARM_RELATIVE: u64 = 23;
/// Fewest synthesized starts that stand in for a missing unwind table; the
/// same floor as `matcher::MIN_FREQUENCY_FUNCTIONS`.
const MIN_SYNTHESIZED_STARTS: usize = crate::matcher::MIN_FREQUENCY_FUNCTIONS;
const R_X86_64_RELATIVE: u64 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;

const PE_SECTION_HEADER_SIZE: usize = 40;

#[derive(Debug, Clone)]
struct Section {
    name_off: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

pub struct FileSource {
    arch: Arch,
    regions: Vec<Region>,
    module: Module,
    bounds: Vec<(u64, u64)>,
    bounds_starts: Vec<u64>,
    thumb_starts: Vec<u64>,
    /// ARM32 images without `.symtab`: mode from surviving pointers and code.
    mode_map: Option<ModeMap>,
    /// Unwind-table entries merged with synthesized starts, sorted.
    unwind: Vec<(u64, u64)>,
    synthesized: Vec<u64>,
}

impl FileSource {
    pub fn from_path(path: impl AsRef<Path>) -> Result<FileSource, SourceFormatError> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|error| {
            SourceFormatError(format!("cannot read {}: {error}", path.display()))
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("image")
            .to_string();
        FileSource::from_bytes(&data, &name)
    }

    pub fn from_bytes(data: &[u8], name: &str) -> Result<FileSource, SourceFormatError> {
        let arch = detect(data).map_err(SourceFormatError)?;
        if data.starts_with(b"\x7fELF") {
            Self::from_elf(data, name, arch)
        } else if data.starts_with(b"MZ") {
            Self::from_pe(data, name, arch)
        } else {
            Err(SourceFormatError(
                "FileSource supports ELF and PE images only".into(),
            ))
        }
    }

    fn from_elf(data: &[u8], name: &str, arch: Arch) -> Result<FileSource, SourceFormatError> {
        let parsed = parse_elf(data, name, arch)?;
        Ok(FileSource::build(arch, parsed))
    }

    fn from_pe(data: &[u8], name: &str, arch: Arch) -> Result<FileSource, SourceFormatError> {
        let parsed = parse_pe(data, name, arch)?;
        Ok(FileSource::build(arch, parsed))
    }

    fn build(arch: Arch, parsed: ParsedImage) -> FileSource {
        let mut regions = parsed.regions;
        regions.sort_by_key(|region| region.start);
        let mut bounds = parsed.bounds;
        bounds.sort();
        let bounds_starts = bounds.iter().map(|(start, _)| *start).collect();
        let mut thumb_starts = parsed.thumb_starts;
        thumb_starts.sort_unstable();
        thumb_starts.dedup();
        let unwind = crate::unwind::finish(parsed.unwind, &regions);
        let mode_map = parsed
            .code_pointers
            .map(|pointers| ModeMap::build(&regions, &pointers));
        let mut source = FileSource {
            arch,
            regions,
            module: parsed.module,
            bounds,
            bounds_starts,
            thumb_starts,
            mode_map,
            unwind,
            synthesized: Vec::new(),
        };
        if let Some(pointers) = parsed.start_pointers {
            // Decoding needs the finished mode map, so this runs last.
            let found = starts::evidence(arch, &source.regions, &pointers, &|a| source.is_thumb(a));
            let mut synthesized = starts::synthesize(&found);
            // With no table, a few synthesized starts (a section start, a
            // couple of call targets) are not a function list: hint-free
            // discovery would compare only those instead of sweeping, and the
            // chance gate cannot judge matches over so few functions.
            if source.unwind.is_empty() && synthesized.len() < MIN_SYNTHESIZED_STARTS {
                synthesized.clear();
            }
            let merged = starts::merge(&source.unwind, &synthesized, parsed.unwind_exact_ends);
            let table: std::collections::HashSet<u64> =
                source.unwind.iter().map(|(start, _)| *start).collect();
            source.synthesized = merged
                .iter()
                .map(|(start, _)| *start)
                .filter(|start| !table.contains(start))
                .collect();
            source.unwind = merged;
        }
        source
    }

    /// Entries in [`ByteSource::unwind_entries`] that no unwind table gave,
    /// synthesized from code evidence (`starts`), sorted.
    pub fn synthesized_starts(&self) -> &[u64] {
        &self.synthesized
    }
}

impl ByteSource for FileSource {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        read_regions(&self.regions, addr, size)
    }

    fn regions(&self) -> &[Region] {
        &self.regions
    }

    fn modules(&self) -> &[Module] {
        std::slice::from_ref(&self.module)
    }

    fn function_starts(&self) -> Vec<u64> {
        self.bounds.iter().map(|(start, _)| *start).collect()
    }

    fn unwind_entries(&self) -> &[(u64, u64)] {
        &self.unwind
    }

    fn hint_function(&self, addr: u64) -> Option<(u64, u64)> {
        if self.bounds.is_empty() {
            return None;
        }
        let index = self
            .bounds_starts
            .partition_point(|start| *start <= addr)
            .checked_sub(1)?;
        let (start, end) = self.bounds[index];
        if start <= addr && addr < end {
            Some((start, end))
        } else {
            None
        }
    }

    fn is_thumb(&self, addr: u64) -> bool {
        if self.arch == Arch::Thumb {
            return true;
        }
        if let Some(map) = &self.mode_map {
            return map.is_thumb(addr);
        }
        if self.thumb_starts.is_empty() {
            return false;
        }
        let Some(index) = self
            .bounds_starts
            .partition_point(|start| *start <= addr)
            .checked_sub(1)
        else {
            return false;
        };
        let start = self.bounds[index].0;
        self.thumb_starts.binary_search(&start).is_ok()
    }
}

/// Lowest `PT_LOAD` virtual address, if the image has program headers.
fn elf_load_base(data: &[u8], is64: bool) -> Option<u64> {
    let (phoff, phentsize, phnum) = if is64 {
        (
            u64_at(data, 0x20).ok()?,
            u16_at(data, 0x36).ok()?,
            u16_at(data, 0x38).ok()?,
        )
    } else {
        (
            u64::from(u32_at(data, 0x1C).ok()?),
            u16_at(data, 0x2A).ok()?,
            u16_at(data, 0x2C).ok()?,
        )
    };
    let minimum = if is64 { 0x38 } else { 0x20 };
    if phoff == 0 || (phentsize as usize) < minimum {
        return None;
    }
    let mut base: Option<u64> = None;
    for index in 0..phnum as usize {
        let offset = usize::try_from(phoff)
            .ok()?
            .checked_add(index * phentsize as usize)?;
        let Ok(kind) = u32_at(data, offset) else {
            break;
        };
        if kind != 1 {
            continue;
        }
        let vaddr = if is64 {
            u64_at(data, offset + 0x10).ok()?
        } else {
            u64::from(u32_at(data, offset + 0x08).ok()?)
        };
        base = Some(base.map_or(vaddr, |current| current.min(vaddr)));
    }
    base
}

struct ParsedImage {
    regions: Vec<Region>,
    module: Module,
    bounds: Vec<(u64, u64)>,
    thumb_starts: Vec<u64>,
    /// Set for a linked ARM32 image without `.symtab` function symbols: every
    /// surviving pointer to code whose low bit still encodes the mode.
    code_pointers: Option<Vec<u64>>,
    unwind: Vec<(u64, u64)>,
    /// Whether table entries carry exact lengths (see `starts::merge`).
    unwind_exact_ends: bool,
    /// Linked ELF images: code pointers that survive stripping, the evidence
    /// for synthesized function starts. `None` disables synthesis.
    start_pointers: Option<Vec<u64>>,
}

// -- little-endian readers ----------------------------------------------------

fn u16_at(data: &[u8], offset: usize) -> Result<u16, SourceFormatError> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| SourceFormatError("truncated image".into()))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, SourceFormatError> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| SourceFormatError("truncated image".into()))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64, SourceFormatError> {
    data.get(offset..offset + 8)
        .map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })
        .ok_or_else(|| SourceFormatError("truncated image".into()))
}

fn cstr(blob: &[u8], offset: usize) -> String {
    if offset >= blob.len() {
        return String::new();
    }
    let end = blob[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| offset + index)
        .unwrap_or(blob.len());
    String::from_utf8_lossy(&blob[offset..end]).into_owned()
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn module_stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("image")
        .to_string()
}

// -- ELF ----------------------------------------------------------------------

fn parse_elf(data: &[u8], name: &str, arch: Arch) -> Result<ParsedImage, SourceFormatError> {
    if data.len() < 0x34 {
        return Err(SourceFormatError("truncated ELF header".into()));
    }
    let elf_class = data[4];
    if data[5] != 1 {
        return Err(SourceFormatError(
            "big-endian ELF images are not supported yet".into(),
        ));
    }
    if elf_class != 1 && elf_class != 2 {
        return Err(SourceFormatError("invalid ELF class".into()));
    }
    let is64 = elf_class == 2;
    let e_type = u16_at(data, 16)?;

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx, sh_struct_size) = if is64 {
        (
            u64_at(data, 0x28)?,
            u16_at(data, 0x3A)?,
            u16_at(data, 0x3C)?,
            u16_at(data, 0x3E)?,
            64usize,
        )
    } else {
        (
            u32_at(data, 0x20)? as u64,
            u16_at(data, 0x2E)?,
            u16_at(data, 0x30)?,
            u16_at(data, 0x32)?,
            40usize,
        )
    };
    if e_shoff == 0 || e_shnum == 0 || (e_shentsize as usize) < sh_struct_size {
        return Err(SourceFormatError(
            "ELF image has no usable section table".into(),
        ));
    }

    // The image base is the lowest PT_LOAD address, so `module+rva` agrees
    // with readelf and disassemblers (the ELF header page is part of the
    // image even though no section covers it). Relocatable objects have no
    // program headers and fall back to the lowest placed section.
    let load_base = elf_load_base(data, is64);

    let mut sections: Vec<Section> = Vec::with_capacity(e_shnum as usize);
    for index in 0..e_shnum as usize {
        let offset = e_shoff as usize + index * e_shentsize as usize;
        if offset + sh_struct_size > data.len() {
            return Err(SourceFormatError("truncated ELF section table".into()));
        }
        if is64 {
            sections.push(Section {
                name_off: u32_at(data, offset)?,
                kind: u32_at(data, offset + 4)?,
                flags: u64_at(data, offset + 8)?,
                addr: u64_at(data, offset + 16)?,
                offset: u64_at(data, offset + 24)?,
                size: u64_at(data, offset + 32)?,
                link: u32_at(data, offset + 40)?,
                info: u32_at(data, offset + 44)?,
                entsize: u64_at(data, offset + 56)?,
            });
        } else {
            sections.push(Section {
                name_off: u32_at(data, offset)?,
                kind: u32_at(data, offset + 4)?,
                flags: u32_at(data, offset + 8)? as u64,
                addr: u32_at(data, offset + 12)? as u64,
                offset: u32_at(data, offset + 16)? as u64,
                size: u32_at(data, offset + 20)? as u64,
                link: u32_at(data, offset + 24)?,
                info: u32_at(data, offset + 28)?,
                entsize: u32_at(data, offset + 36)? as u64,
            });
        }
    }

    if e_shstrndx as usize >= sections.len() {
        return Err(SourceFormatError(
            "invalid ELF section-name table index".into(),
        ));
    }
    let name_table = section_bytes(data, &sections[e_shstrndx as usize])?;
    let names: Vec<String> = sections
        .iter()
        .map(|section| cstr(&name_table, section.name_off as usize))
        .collect();

    let mut places: HashMap<usize, u64> = HashMap::new();
    let mut regions: Vec<Region> = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        if section.flags & ELF_SHF_ALLOC == 0 || section.size == 0 {
            continue;
        }
        let start = if e_type == ELF_ET_REL {
            ELF_PLACE_BASE + section.offset
        } else {
            if section.addr == 0 {
                continue;
            }
            section.addr
        };
        places.insert(index, start);
        regions.push(Region::new(
            if names[index].is_empty() {
                format!("section{index}")
            } else {
                names[index].clone()
            },
            start,
            section_bytes(data, section)?,
            section.flags & ELF_SHF_EXECINSTR != 0,
            section.flags & ELF_SHF_WRITE != 0,
        ));
    }
    if regions.is_empty() {
        return Err(SourceFormatError(
            "ELF image has no allocatable sections".into(),
        ));
    }

    let sym_struct_size = if is64 { 24usize } else { 16usize };
    let mut symbols: Vec<(String, u64, u8, u16, u64, bool)> = Vec::new();
    let mut tables: HashMap<usize, (Vec<u8>, Vec<u8>)> = HashMap::new();
    let mut symtab_functions = false;
    // Pointers to code that survive `strip --strip-all`: exported function
    // values (Thumb bit kept) and relative relocation targets. Evidence for
    // synthesized function starts; `.symtab` is a hint and is not used.
    let mut start_pointers: Vec<u64> = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        if section.kind != ELF_SHT_SYMTAB && section.kind != ELF_SHT_DYNSYM {
            continue;
        }
        if section.link as usize >= sections.len() {
            continue;
        }
        let raw = section_bytes(data, section)?;
        let strings = section_bytes(data, &sections[section.link as usize])?;
        tables.insert(index, (raw.clone(), strings.clone()));
        let entry_size = if section.entsize != 0 {
            section.entsize as usize
        } else {
            sym_struct_size
        };
        if entry_size < sym_struct_size {
            continue;
        }
        for symbol_index in 0..raw.len() / entry_size {
            let offset = symbol_index * entry_size;
            if offset + sym_struct_size > raw.len() {
                break;
            }
            let (st_name, st_info, st_shndx, st_value, st_size) = if is64 {
                (
                    u32_at(&raw, offset)?,
                    raw[offset + 4],
                    u16::from_le_bytes([raw[offset + 6], raw[offset + 7]]),
                    u64_at(&raw, offset + 8)?,
                    u64_at(&raw, offset + 16)?,
                )
            } else {
                (
                    u32_at(&raw, offset)?,
                    raw[offset + 12],
                    u16::from_le_bytes([raw[offset + 14], raw[offset + 15]]),
                    u32_at(&raw, offset + 4)? as u64,
                    u32_at(&raw, offset + 8)? as u64,
                )
            };
            let symbol_name = cstr(&strings, st_name as usize);
            if section.kind == ELF_SHT_SYMTAB && st_info & 0xF == ELF_STT_FUNC && st_shndx != 0 {
                symtab_functions = true;
            }
            if section.kind == ELF_SHT_DYNSYM
                && st_info & 0xF == ELF_STT_FUNC
                && st_shndx != 0
                && start_pointers.len() < crate::unwind::MAX_UNWIND_ENTRIES
            {
                start_pointers.push(st_value);
            }
            if st_shndx != 0 && !symbol_name.is_empty() {
                symbols.push((
                    symbol_name,
                    st_value,
                    st_info,
                    st_shndx,
                    st_size,
                    section.kind == ELF_SHT_DYNSYM,
                ));
            }
        }
    }

    let mut imports: HashMap<u64, String> = HashMap::new();
    let mut relative_slots: Vec<u64> = Vec::new();
    for section in &sections {
        if section.kind != ELF_SHT_RELA && section.kind != ELF_SHT_REL {
            continue;
        }
        // `Elf32_Rel` is 8 bytes (ARM32 uses REL, not RELA); the addend that
        // RELA adds is never read here.
        let rel_struct_size = match (is64, section.kind == ELF_SHT_RELA) {
            (true, true) => 24usize,
            (true, false) => 16,
            (false, true) => 12,
            (false, false) => 8,
        };
        let entry_size = if section.entsize != 0 {
            section.entsize as usize
        } else {
            rel_struct_size
        };
        if entry_size < rel_struct_size {
            continue;
        }
        let raw = section_bytes(data, section)?;
        for rel_index in 0..raw.len() / entry_size {
            let offset = rel_index * entry_size;
            if offset + rel_struct_size > raw.len() {
                break;
            }
            let (r_offset, r_info) = if is64 {
                (u64_at(&raw, offset)?, u64_at(&raw, offset + 8)?)
            } else {
                (
                    u32_at(&raw, offset)? as u64,
                    u32_at(&raw, offset + 4)? as u64,
                )
            };
            if arch == Arch::Arm32
                && !is64
                && e_type != ELF_ET_REL
                && r_info & 0xff == R_ARM_RELATIVE
            {
                relative_slots.push(r_offset);
                continue;
            }
            let relative = match arch {
                Arch::X64 => R_X86_64_RELATIVE,
                Arch::Arm64 => R_AARCH64_RELATIVE,
                _ => u64::MAX,
            };
            if is64
                && e_type != ELF_ET_REL
                && section.kind == ELF_SHT_RELA
                && r_info & 0xffff_ffff == relative
            {
                if start_pointers.len() < 2 * crate::unwind::MAX_UNWIND_ENTRIES {
                    start_pointers.push(u64_at(&raw, offset + 16)?);
                }
                continue;
            }
            let symbol_index = if is64 { r_info >> 32 } else { r_info >> 8 };
            let Some(target) = symbol_name(&tables, section.link as usize, symbol_index, is64)
            else {
                continue;
            };
            if target.is_empty() {
                continue;
            }
            let slot = if e_type == ELF_ET_REL {
                let Some(base) = places.get(&(section.info as usize)) else {
                    continue;
                };
                base + r_offset
            } else {
                r_offset
            };
            imports.entry(slot).or_insert(target);
        }
    }

    let mut functions: HashMap<u64, String> = HashMap::new();
    let mut exports: Vec<(String, u64)> = Vec::new();
    let mut export_seen: HashMap<String, ()> = HashMap::new();
    let mut bounds: Vec<(u64, u64)> = Vec::new();
    let mut thumb_starts: Vec<u64> = Vec::new();
    let mut code_pointers: Vec<u64> = Vec::new();
    // Exports are the names a stripped copy keeps: `.dynsym` when the image
    // has one (`strip` removes `.symtab`), else the global `.symtab` symbols
    // of an object file.
    let has_dynsym = symbols.iter().any(|symbol| symbol.5);
    for (symbol_name, value, info, shndx, size, dynamic) in symbols {
        let Some(base) = places.get(&(shndx as usize)) else {
            continue;
        };
        let mut address = if e_type == ELF_ET_REL {
            base + value
        } else {
            value
        };
        let mut thumb = false;
        if arch == Arch::Arm32 && address & 1 != 0 {
            address &= !1;
            thumb = true;
        }
        if info & 0xF == ELF_STT_FUNC {
            code_pointers.push(address | u64::from(thumb));
            functions
                .entry(address)
                .or_insert_with(|| symbol_name.clone());
            if size > 0 {
                bounds.push((address, address + size));
                if thumb {
                    thumb_starts.push(address);
                }
            }
        }
        let binding = info >> 4;
        if (binding == 1 || binding == 2)
            && (dynamic || !has_dynsym)
            && export_seen.insert(symbol_name.clone(), ()).is_none()
        {
            exports.push((symbol_name, address));
        }
    }

    let section_start = regions.iter().map(|region| region.start).min().unwrap_or(0);
    let module_start = match load_base {
        Some(base) if e_type != ELF_ET_REL => base.min(section_start),
        _ => section_start,
    };
    let module_end = regions.iter().map(|region| region.end()).max().unwrap_or(0);
    let module = Module {
        name: module_stem(name),
        base: module_start,
        size: module_end - module_start,
        path: Some(name.to_string()),
        exports,
        functions,
        imports,
    };
    let unwind = crate::unwind::elf_entries(&regions, if is64 { 8 } else { 4 });
    // `.ARM.exidx` ends are only the next entry's start; `.eh_frame` lengths
    // are exact.
    let unwind_exact_ends = !regions.iter().any(|region| region.name == ".ARM.exidx");
    if arch == Arch::Arm32 && e_type != ELF_ET_REL {
        start_pointers.extend(
            relative_slots
                .iter()
                .take(crate::unwind::MAX_UNWIND_ENTRIES)
                .filter_map(|slot| read_regions(&regions, *slot, 4).ok())
                .map(|word| u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))),
        );
    }
    let start_pointers = (e_type != ELF_ET_REL).then_some(start_pointers);
    // Stripping removes `.symtab` (local functions and mapping symbols), so
    // the ELF symbol bit no longer covers most code. Dynamic symbols and
    // `R_ARM_RELATIVE` function pointers keep the bit; see `arm_mode`.
    let code_pointers =
        (arch == Arch::Arm32 && e_type != ELF_ET_REL && !symtab_functions).then(|| {
            code_pointers.extend(
                relative_slots
                    .iter()
                    .take(crate::arm_mode::MAX_MODE_MARKS)
                    .filter_map(|slot| read_regions(&regions, *slot, 4).ok())
                    .map(|word| {
                        u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
                    }),
            );
            code_pointers
        });
    Ok(ParsedImage {
        regions,
        module,
        bounds,
        thumb_starts,
        code_pointers,
        unwind,
        unwind_exact_ends,
        start_pointers,
    })
}

fn section_bytes(data: &[u8], section: &Section) -> Result<Vec<u8>, SourceFormatError> {
    if section.kind == ELF_SHT_NOBITS {
        return Ok(vec![0; section.size as usize]);
    }
    let start = section.offset as usize;
    let end = start
        .checked_add(section.size as usize)
        .ok_or_else(|| SourceFormatError("ELF section exceeds file size".into()))?;
    if end > data.len() {
        return Err(SourceFormatError("ELF section exceeds file size".into()));
    }
    Ok(data[start..end].to_vec())
}

fn symbol_name(
    tables: &HashMap<usize, (Vec<u8>, Vec<u8>)>,
    table_index: usize,
    symbol_index: u64,
    is64: bool,
) -> Option<String> {
    let (raw, strings) = tables.get(&table_index)?;
    let entry_size = if is64 { 24usize } else { 16usize };
    let offset = (symbol_index as usize).checked_mul(entry_size)?;
    if offset + 4 > raw.len() {
        return None;
    }
    let st_name = u32::from_le_bytes([
        raw[offset],
        raw[offset + 1],
        raw[offset + 2],
        raw[offset + 3],
    ]);
    Some(cstr(strings, st_name as usize))
}

// -- PE -----------------------------------------------------------------------

fn parse_pe(data: &[u8], name: &str, arch: Arch) -> Result<ParsedImage, SourceFormatError> {
    if data.len() < 0x40 {
        return Err(SourceFormatError("truncated DOS header".into()));
    }
    let lfanew = u32_at(data, 0x3C)? as usize;
    if lfanew + 24 > data.len() || &data[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err(SourceFormatError("PE signature missing".into()));
    }
    let coff = lfanew + 4;
    let number_of_sections = u16_at(data, coff + 2)?;
    let size_of_optional = u16_at(data, coff + 16)? as usize;
    let optional = coff + 20;
    if optional + size_of_optional > data.len() || size_of_optional < 96 {
        return Err(SourceFormatError("truncated PE optional header".into()));
    }
    let magic = u16_at(data, optional)?;
    let (image_base, count_offset, dirs_offset, thunk_size) = match magic {
        0x20B => (
            u64_at(data, optional + 24)?,
            optional + 108,
            optional + 112,
            8usize,
        ),
        0x10B => (
            u32_at(data, optional + 28)? as u64,
            optional + 92,
            optional + 96,
            4usize,
        ),
        other => {
            return Err(SourceFormatError(format!(
                "unknown PE optional header magic 0x{other:x}"
            )))
        }
    };
    let number_of_dirs = u32_at(data, count_offset)?;

    let headers_end = optional + size_of_optional;
    let mut sections: Vec<(u64, u64, usize)> = Vec::new(); // (rva, span, raw_ptr)
    let mut regions: Vec<Region> = Vec::new();
    for index in 0..number_of_sections as usize {
        let offset = headers_end + index * PE_SECTION_HEADER_SIZE;
        if offset + PE_SECTION_HEADER_SIZE > data.len() {
            return Err(SourceFormatError("truncated PE section table".into()));
        }
        let section_name = {
            let raw = &data[offset..offset + 8];
            let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
            let decoded = latin1(&raw[..end]);
            if decoded.is_empty() {
                format!("s{index}")
            } else {
                decoded
            }
        };
        let virtual_size = u32_at(data, offset + 8)? as u64;
        let virtual_address = u32_at(data, offset + 12)? as u64;
        let raw_size = u32_at(data, offset + 16)? as u64;
        let raw_ptr = u32_at(data, offset + 20)? as usize;
        let span = virtual_size.max(raw_size);
        if span == 0 {
            continue;
        }
        let mut payload = {
            let take = (raw_size.min(span)) as usize;
            let end = raw_ptr.saturating_add(take).min(data.len());
            let start = raw_ptr.min(data.len());
            data[start..end].to_vec()
        };
        if (payload.len() as u64) < span {
            payload.resize(span as usize, 0);
        }
        let characteristics = u32_at(data, offset + 36)?;
        sections.push((virtual_address, span, raw_ptr));
        regions.push(Region::new(
            section_name,
            image_base + virtual_address,
            payload,
            characteristics & 0x2000_0000 != 0,
            characteristics & 0x8000_0000 != 0,
        ));
    }
    if regions.is_empty() {
        return Err(SourceFormatError("PE image has no sections".into()));
    }

    let rva_to_offset = |rva: u64| -> Option<usize> {
        sections
            .iter()
            .find_map(|(virtual_address, span, raw_ptr)| {
                if *virtual_address <= rva && rva < virtual_address + span {
                    Some(raw_ptr + (rva - virtual_address) as usize)
                } else {
                    None
                }
            })
    };

    let mut exports: Vec<(String, u64)> = Vec::new();
    let mut export_seen: HashMap<String, ()> = HashMap::new();
    let mut functions: HashMap<u64, String> = HashMap::new();
    let mut imports: HashMap<u64, String> = HashMap::new();

    if number_of_dirs > 0 {
        let export_rva = u32_at(data, dirs_offset)? as u64;
        let export_size = u32_at(data, dirs_offset + 4)?;
        if export_rva != 0 && export_size != 0 {
            parse_pe_exports(
                data,
                &rva_to_offset,
                image_base,
                export_rva,
                &mut exports,
                &mut export_seen,
                &mut functions,
            );
        }
    }
    if number_of_dirs > 1 {
        let import_rva = u32_at(data, dirs_offset + 8)? as u64;
        let import_size = u32_at(data, dirs_offset + 12)?;
        if import_rva != 0 && import_size != 0 {
            parse_pe_imports(
                data,
                &rva_to_offset,
                image_base,
                import_rva,
                thunk_size,
                &mut imports,
            );
        }
    }

    // Exception directory (index 3): RUNTIME_FUNCTION entries.
    let mut unwind = Vec::new();
    if number_of_dirs > 3 {
        let pdata_rva = u32_at(data, dirs_offset + 24)? as u64;
        let pdata_size = u32_at(data, dirs_offset + 28)? as usize;
        if pdata_rva != 0 && pdata_size != 0 {
            if let Some(offset) = rva_to_offset(pdata_rva) {
                let end = offset.saturating_add(pdata_size).min(data.len());
                unwind = crate::unwind::pdata(
                    &data[offset.min(end)..end],
                    image_base,
                    arch == Arch::Arm64,
                );
            }
        }
    }

    // A PE RVA is relative to ImageBase, which the headers occupy.
    let section_start = regions.iter().map(|region| region.start).min().unwrap_or(0);
    let module_start = image_base.min(section_start);
    let module_end = regions.iter().map(|region| region.end()).max().unwrap_or(0);
    let module = Module {
        name: module_stem(name),
        base: module_start,
        size: module_end - module_start,
        path: Some(name.to_string()),
        exports,
        functions,
        imports,
    };
    // PE exports carry no size, so there are no symbol bounds to hint recovery.
    Ok(ParsedImage {
        regions,
        module,
        bounds: Vec::new(),
        thumb_starts: Vec::new(),
        code_pointers: None,
        unwind,
        // `.pdata` lengths are exact; PE start synthesis is not measured yet.
        unwind_exact_ends: true,
        start_pointers: None,
    })
}

fn parse_pe_exports(
    data: &[u8],
    rva_to_offset: &impl Fn(u64) -> Option<usize>,
    image_base: u64,
    export_rva: u64,
    exports: &mut Vec<(String, u64)>,
    export_seen: &mut HashMap<String, ()>,
    functions: &mut HashMap<u64, String>,
) {
    let Some(base_offset) = rva_to_offset(export_rva) else {
        return;
    };
    if base_offset + 40 > data.len() {
        return;
    }
    let number_of_functions = match u32_at(data, base_offset + 20) {
        Ok(value) => value,
        Err(_) => return,
    };
    let number_of_names = match u32_at(data, base_offset + 24) {
        Ok(value) => value,
        Err(_) => return,
    };
    let address_of_functions = match u32_at(data, base_offset + 28) {
        Ok(value) => value as u64,
        Err(_) => return,
    };
    let address_of_names = match u32_at(data, base_offset + 32) {
        Ok(value) => value as u64,
        Err(_) => return,
    };
    let address_of_ordinals = match u32_at(data, base_offset + 36) {
        Ok(value) => value as u64,
        Err(_) => return,
    };
    let (Some(functions_offset), Some(names_offset), Some(ordinals_offset)) = (
        rva_to_offset(address_of_functions),
        rva_to_offset(address_of_names),
        rva_to_offset(address_of_ordinals),
    ) else {
        return;
    };
    for index in 0..(number_of_names.min(number_of_functions).min(65536) as usize) {
        let name_entry = names_offset + index * 4;
        let ordinal_entry = ordinals_offset + index * 2;
        if name_entry + 4 > data.len() || ordinal_entry + 2 > data.len() {
            break;
        }
        let name_rva = match u32_at(data, name_entry) {
            Ok(value) => value as u64,
            Err(_) => break,
        };
        let ordinal = match u16_at(data, ordinal_entry) {
            Ok(value) => value,
            Err(_) => break,
        };
        let Some(name_offset) = rva_to_offset(name_rva) else {
            continue;
        };
        if ordinal as u32 >= number_of_functions {
            continue;
        }
        let function_entry = functions_offset + ordinal as usize * 4;
        if function_entry + 4 > data.len() {
            continue;
        }
        let symbol = cstr(data, name_offset);
        if symbol.is_empty() {
            continue;
        }
        let function_rva = match u32_at(data, function_entry) {
            Ok(value) => value as u64,
            Err(_) => continue,
        };
        let address = image_base + function_rva;
        if export_seen.insert(symbol.clone(), ()).is_none() {
            exports.push((symbol.clone(), address));
        }
        functions.entry(address).or_insert(symbol);
    }
}

fn parse_pe_imports(
    data: &[u8],
    rva_to_offset: &impl Fn(u64) -> Option<usize>,
    image_base: u64,
    import_rva: u64,
    thunk_size: usize,
    imports: &mut HashMap<u64, String>,
) {
    let Some(descriptor_offset) = rva_to_offset(import_rva) else {
        return;
    };
    for index in 0..4096 {
        let offset = descriptor_offset + index * 20;
        if offset + 20 > data.len() {
            return;
        }
        let original_thunk = match u32_at(data, offset) {
            Ok(value) => value as u64,
            Err(_) => return,
        };
        let name_rva = match u32_at(data, offset + 12) {
            Ok(value) => value as u64,
            Err(_) => return,
        };
        let first_thunk = match u32_at(data, offset + 16) {
            Ok(value) => value as u64,
            Err(_) => return,
        };
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            return;
        }
        let Some(name_offset) = rva_to_offset(name_rva) else {
            continue;
        };
        let dll = module_stem(&cstr(data, name_offset));
        let Some(thunk_offset) = rva_to_offset(if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        }) else {
            continue;
        };
        for slot in 0..4096 {
            let entry = thunk_offset + slot * thunk_size;
            if entry + thunk_size > data.len() {
                break;
            }
            let (value, ordinal_flag) = if thunk_size == 8 {
                (
                    match u64_at(data, entry) {
                        Ok(value) => value,
                        Err(_) => break,
                    },
                    1u64 << 63,
                )
            } else {
                (
                    match u32_at(data, entry) {
                        Ok(value) => value as u64,
                        Err(_) => break,
                    },
                    1u64 << 31,
                )
            };
            if value == 0 {
                break;
            }
            let symbol = if value & ordinal_flag != 0 {
                format!("#{}", value & 0xFFFF)
            } else {
                let Some(hint_offset) = rva_to_offset(value & 0x7FFF_FFFF) else {
                    break;
                };
                cstr(data, hint_offset + 2)
            };
            let address = image_base + first_thunk + (slot * thunk_size) as u64;
            imports
                .entry(address)
                .or_insert_with(|| format!("{dll}!{symbol}"));
        }
    }
}
