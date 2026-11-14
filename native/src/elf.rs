//! Image-file byte source for ELF and PE containers.
//!
//! Relocatable ELF objects (`ET_REL`) have no virtual addresses, so their
//! sections are placed at `ELF_PLACE_BASE + file offset`. The placement is
//! injective and keeps intra-object references resolvable without linking.
//!
//! The parser mirrors `sources/file.py`; divergence would change feature
//! records, so it is kept deliberately close to the Python code.

use std::borrow::Cow;
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

pub(crate) fn module_stem(name: &str) -> String {
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
//
// The directory walkers address the image by RVA through `PeImage`, so one
// parser serves a file on disk (`PeFile`, RVAs mapped through the section
// table) and an image mapped in a live process (`proc_win`, RVAs read from the
// target). Every loop is bounded: both layouts are untrusted input.

/// RVA-addressed, read-only view of one PE image.
pub(crate) trait PeImage {
    /// Exactly `len` bytes at `rva`, or `None` when any of them is unbacked.
    fn bytes(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>>;
    /// Up to `len` bytes at `rva`, cut at the end of the backed range.
    fn span(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>>;
    /// Whether `rva` is backed at all.
    fn contains(&self, rva: u64) -> bool;
    /// The NUL-terminated string at `rva` (empty when unbacked).
    fn cstr(&self, rva: u64) -> String;

    fn u16(&self, rva: u64) -> Option<u16> {
        self.bytes(rva, 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&self, rva: u64) -> Option<u32> {
        self.bytes(rva, 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&self, rva: u64) -> Option<u64> {
        self.bytes(rva, 8).map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })
    }
}

/// One section header, as the loader sees it.
#[derive(Debug, Clone)]
pub(crate) struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub raw_ptr: usize,
    pub characteristics: u32,
}

impl PeSection {
    /// Mapped extent: the larger of the virtual and raw sizes.
    pub fn span(&self) -> u64 {
        self.virtual_size.max(self.raw_size)
    }
}

/// The parts of the PE headers the directory walkers need.
#[derive(Debug, Clone)]
pub(crate) struct PeHeaders {
    pub machine: u16,
    pub image_base: u64,
    pub thunk_size: usize,
    /// Data directories 0 (export), 1 (import), 3 (exception) when present.
    pub export: Option<(u32, u32)>,
    pub import: Option<(u32, u32)>,
    pub exception: Option<(u32, u32)>,
    /// Sections with a non-zero span, in header order.
    pub sections: Vec<PeSection>,
}

/// Parse the DOS, COFF, optional, and section headers at the start of `data`.
pub(crate) fn parse_pe_headers(data: &[u8]) -> Result<PeHeaders, SourceFormatError> {
    if data.len() < 0x40 {
        return Err(SourceFormatError("truncated DOS header".into()));
    }
    let lfanew = u32_at(data, 0x3C)? as usize;
    if lfanew + 24 > data.len() || &data[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err(SourceFormatError("PE signature missing".into()));
    }
    let coff = lfanew + 4;
    let machine = u16_at(data, coff)?;
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
    let mut sections = Vec::new();
    for index in 0..number_of_sections as usize {
        let offset = headers_end + index * PE_SECTION_HEADER_SIZE;
        if offset + PE_SECTION_HEADER_SIZE > data.len() {
            return Err(SourceFormatError("truncated PE section table".into()));
        }
        let name = {
            let raw = &data[offset..offset + 8];
            let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
            let decoded = latin1(&raw[..end]);
            if decoded.is_empty() {
                format!("s{index}")
            } else {
                decoded
            }
        };
        let section = PeSection {
            name,
            virtual_size: u32_at(data, offset + 8)? as u64,
            virtual_address: u32_at(data, offset + 12)? as u64,
            raw_size: u32_at(data, offset + 16)? as u64,
            raw_ptr: u32_at(data, offset + 20)? as usize,
            characteristics: u32_at(data, offset + 36)?,
        };
        if section.span() != 0 {
            sections.push(section);
        }
    }

    let directory = |index: usize| -> Result<Option<(u32, u32)>, SourceFormatError> {
        if number_of_dirs as usize <= index {
            return Ok(None);
        }
        let offset = dirs_offset + index * 8;
        Ok(Some((u32_at(data, offset)?, u32_at(data, offset + 4)?)))
    };
    Ok(PeHeaders {
        machine,
        image_base,
        thunk_size,
        export: directory(0)?,
        import: directory(1)?,
        exception: directory(3)?,
        sections,
    })
}

/// A PE file on disk: RVAs resolve through the section table to file offsets.
struct PeFile<'a> {
    data: &'a [u8],
    sections: &'a [PeSection],
}

impl PeFile<'_> {
    fn offset(&self, rva: u64) -> Option<usize> {
        self.sections.iter().find_map(|section| {
            let start = section.virtual_address;
            (start <= rva && rva < start + section.span())
                .then(|| section.raw_ptr + (rva - start) as usize)
        })
    }
}

impl PeImage for PeFile<'_> {
    fn bytes(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        let offset = self.offset(rva)?;
        self.data
            .get(offset..offset.checked_add(len)?)
            .map(Cow::Borrowed)
    }

    fn span(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        let offset = self.offset(rva)?;
        let end = offset.saturating_add(len).min(self.data.len());
        Some(Cow::Borrowed(&self.data[offset.min(end)..end]))
    }

    fn contains(&self, rva: u64) -> bool {
        self.offset(rva).is_some()
    }

    fn cstr(&self, rva: u64) -> String {
        self.offset(rva)
            .map(|offset| cstr(self.data, offset))
            .unwrap_or_default()
    }
}

/// Names and unwind entries from the export, import, and exception directories.
#[derive(Debug, Default)]
pub(crate) struct PeMetadata {
    pub exports: Vec<(String, u64)>,
    pub functions: HashMap<u64, String>,
    pub imports: HashMap<u64, String>,
    pub unwind: Vec<(u64, u64)>,
}

/// Walk the directories of `image`, loaded at `image_base`.
///
/// `strict` (mapped images) additionally drops forwarder exports, whose RVA
/// points at a string inside the export directory rather than at code, and
/// exports outside the image. `.pdata` reads stop at `max_pdata_bytes`.
pub(crate) fn pe_metadata(
    image: &impl PeImage,
    headers: &PeHeaders,
    image_base: u64,
    arm64: bool,
    strict: bool,
    max_pdata_bytes: usize,
) -> PeMetadata {
    let mut metadata = PeMetadata::default();
    if let Some((export_rva, export_size)) = headers.export {
        if export_rva != 0 && export_size != 0 {
            parse_pe_exports(
                image,
                image_base,
                u64::from(export_rva),
                u64::from(export_size),
                strict,
                &mut metadata,
            );
        }
    }
    if let Some((import_rva, import_size)) = headers.import {
        if import_rva != 0 && import_size != 0 {
            parse_pe_imports(
                image,
                image_base,
                u64::from(import_rva),
                headers.thunk_size,
                &mut metadata.imports,
            );
        }
    }
    // Exception directory (index 3): RUNTIME_FUNCTION entries.
    if let Some((pdata_rva, pdata_size)) = headers.exception {
        if pdata_rva != 0 && pdata_size != 0 {
            let size = (pdata_size as usize).min(max_pdata_bytes);
            if let Some(bytes) = image.span(u64::from(pdata_rva), size) {
                metadata.unwind = crate::unwind::pdata(&bytes, image_base, arm64);
            }
        }
    }
    metadata
}

fn parse_pe(data: &[u8], name: &str, arch: Arch) -> Result<ParsedImage, SourceFormatError> {
    let headers = parse_pe_headers(data)?;
    let image_base = headers.image_base;
    let mut regions: Vec<Region> = Vec::new();
    for section in &headers.sections {
        let span = section.span();
        let mut payload = {
            let take = (section.raw_size.min(span)) as usize;
            let end = section.raw_ptr.saturating_add(take).min(data.len());
            let start = section.raw_ptr.min(data.len());
            data[start..end].to_vec()
        };
        if (payload.len() as u64) < span {
            payload.resize(span as usize, 0);
        }
        regions.push(Region::new(
            section.name.clone(),
            image_base + section.virtual_address,
            payload,
            section.characteristics & 0x2000_0000 != 0,
            section.characteristics & 0x8000_0000 != 0,
        ));
    }
    if regions.is_empty() {
        return Err(SourceFormatError("PE image has no sections".into()));
    }

    let image = PeFile {
        data,
        sections: &headers.sections,
    };
    let metadata = pe_metadata(
        &image,
        &headers,
        image_base,
        arch == Arch::Arm64,
        false,
        usize::MAX,
    );

    // A PE RVA is relative to ImageBase, which the headers occupy.
    let section_start = regions.iter().map(|region| region.start).min().unwrap_or(0);
    let module_start = image_base.min(section_start);
    let module_end = regions.iter().map(|region| region.end()).max().unwrap_or(0);
    let module = Module {
        name: module_stem(name),
        base: module_start,
        size: module_end - module_start,
        path: Some(name.to_string()),
        exports: metadata.exports,
        functions: metadata.functions,
        imports: metadata.imports,
    };
    // PE exports carry no size, so there are no symbol bounds to hint recovery.
    Ok(ParsedImage {
        regions,
        module,
        bounds: Vec::new(),
        thumb_starts: Vec::new(),
        code_pointers: None,
        unwind: metadata.unwind,
        // `.pdata` lengths are exact; PE start synthesis is not measured yet.
        unwind_exact_ends: true,
        start_pointers: None,
    })
}

fn parse_pe_exports(
    image: &impl PeImage,
    image_base: u64,
    export_rva: u64,
    export_size: u64,
    strict: bool,
    metadata: &mut PeMetadata,
) {
    let Some(directory) = image.bytes(export_rva, 40) else {
        return;
    };
    let field = |offset: usize| {
        u32::from_le_bytes([
            directory[offset],
            directory[offset + 1],
            directory[offset + 2],
            directory[offset + 3],
        ])
    };
    let number_of_functions = field(20);
    let number_of_names = field(24);
    let address_of_functions = u64::from(field(28));
    let address_of_names = u64::from(field(32));
    let address_of_ordinals = u64::from(field(36));
    if !(image.contains(address_of_functions)
        && image.contains(address_of_names)
        && image.contains(address_of_ordinals))
    {
        return;
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for index in 0..u64::from(number_of_names.min(number_of_functions).min(65536)) {
        let (Some(name_rva), Some(ordinal)) = (
            image.u32(address_of_names + index * 4),
            image.u16(address_of_ordinals + index * 2),
        ) else {
            break;
        };
        let name_rva = u64::from(name_rva);
        if !image.contains(name_rva) {
            continue;
        }
        if u32::from(ordinal) >= number_of_functions {
            continue;
        }
        let Some(function_rva) = image.u32(address_of_functions + u64::from(ordinal) * 4) else {
            continue;
        };
        let function_rva = u64::from(function_rva);
        let symbol = image.cstr(name_rva);
        if symbol.is_empty() {
            continue;
        }
        if strict
            && (function_rva == 0
                || (export_rva..export_rva + export_size).contains(&function_rva)
                || !image.contains(function_rva))
        {
            continue;
        }
        let address = image_base + function_rva;
        if seen.insert(symbol.clone()) {
            metadata.exports.push((symbol.clone(), address));
        }
        metadata.functions.entry(address).or_insert(symbol);
    }
}

fn parse_pe_imports(
    image: &impl PeImage,
    image_base: u64,
    import_rva: u64,
    thunk_size: usize,
    imports: &mut HashMap<u64, String>,
) {
    if !image.contains(import_rva) {
        return;
    }
    let thunk = thunk_size as u64;
    let ordinal_flag = if thunk_size == 8 {
        1u64 << 63
    } else {
        1u64 << 31
    };
    for index in 0..4096u64 {
        let Some(descriptor) = image.bytes(import_rva + index * 20, 20) else {
            return;
        };
        let field = |offset: usize| {
            u64::from(u32::from_le_bytes([
                descriptor[offset],
                descriptor[offset + 1],
                descriptor[offset + 2],
                descriptor[offset + 3],
            ]))
        };
        let original_thunk = field(0);
        let name_rva = field(12);
        let first_thunk = field(16);
        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            return;
        }
        if !image.contains(name_rva) {
            continue;
        }
        let dll = module_stem(&image.cstr(name_rva));
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        if !image.contains(thunk_rva) {
            continue;
        }
        for slot in 0..4096u64 {
            let entry = thunk_rva + slot * thunk;
            let value = if thunk_size == 8 {
                image.u64(entry)
            } else {
                image.u32(entry).map(u64::from)
            };
            let Some(value) = value else {
                break;
            };
            if value == 0 {
                break;
            }
            let symbol = if value & ordinal_flag != 0 {
                format!("#{}", value & 0xFFFF)
            } else {
                let hint_rva = value & 0x7FFF_FFFF;
                if !image.contains(hint_rva) {
                    break;
                }
                image.cstr(hint_rva + 2)
            };
            let address = image_base + first_thunk + slot * thunk;
            imports
                .entry(address)
                .or_insert_with(|| format!("{dll}!{symbol}"));
        }
    }
}
