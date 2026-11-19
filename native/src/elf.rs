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

/// Symbol tables by section index: the raw entries and their string table,
/// borrowed from the file where the section is file-backed.
type SymbolTables<'a> = HashMap<usize, (Cow<'a, [u8]>, Cow<'a, [u8]>)>;

pub const ELF_PLACE_BASE: u64 = 0x1000_0000;

const ELF_SHT_SYMTAB: u32 = 2;
const ELF_SHT_STRTAB: u32 = 3;
const ELF_SHT_RELA: u32 = 4;
const ELF_SHT_NOBITS: u32 = 8;
const ELF_SHT_REL: u32 = 9;
const ELF_SHT_DYNSYM: u32 = 11;
const ELF_SHT_RELR: u32 = 19;
const ELF_SHT_ANDROID_REL: u32 = 0x6000_0001;
const ELF_SHT_ANDROID_RELA: u32 = 0x6000_0002;
const ELF_SHF_WRITE: u64 = 0x1;
const ELF_SHF_ALLOC: u64 = 0x2;
const ELF_SHF_EXECINSTR: u64 = 0x4;
const ELF_STT_FUNC: u8 = 2;
const ELF_STT_TLS: u8 = 6;
const ELF_PT_LOAD: u32 = 1;
const ELF_PT_DYNAMIC: u32 = 2;
/// Most `.dynamic` entries read; a real image has a few dozen.
const MAX_DYNAMIC_ENTRIES: usize = 4096;
const ELF_ET_REL: u16 = 1;
const ELF_ET_DYN: u16 = 3;
const R_ARM_RELATIVE: u64 = 23;
/// Fewest synthesized starts that stand in for a missing unwind table; the
/// same floor as `matcher::MIN_FREQUENCY_FUNCTIONS`.
const MIN_SYNTHESIZED_STARTS: usize = crate::matcher::MIN_FREQUENCY_FUNCTIONS;
const R_X86_64_RELATIVE: u64 = 8;
const R_AARCH64_RELATIVE: u64 = 1027;

const PE_SECTION_HEADER_SIZE: usize = 40;

/// Largest raw blob [`FileSource::from_raw`] maps. The blob is copied into
/// one region and swept for starts, so an unbounded file would be an
/// unbounded allocation; firmware images and single-region dumps are far
/// smaller, and the start sweep stops at `starts::MAX_START_SWEEP_BYTES`
/// (128 MiB) anyway.
pub const MAX_RAW_BYTES: usize = 1 << 30;

/// Zero fill (ELF `SHT_NOBITS`, PE virtual size past the raw data) one image
/// file may materialize: a floor that covers the `.bss` of any real program,
/// plus a multiple of the file length so large images get more. Header sizes
/// are attacker-chosen (`u64` per ELF section, 4 GiB per PE section), so
/// without a total a small file could ask for terabytes.
const ZERO_FILL_FLOOR: u64 = 1 << 30;
const ZERO_FILL_PER_FILE_BYTE: u64 = 16;
/// File-backed region bytes, as a multiple of the file length. Real sections
/// do not overlap in the file, so their copies sum to at most the file; the
/// headroom tolerates odd layouts while thousands of sections that all cover
/// the whole file cannot multiply it.
const FILE_COPIES_PER_FILE_BYTE: u64 = 2;
/// Bytes of ELF section, symbol, and relocation names one parse may copy. A
/// name runs to the next NUL, so N symbols naming one long unterminated
/// string would cost N times the table; real names sum to about their string
/// tables (relocations repeat names, still well under the multiple).
const ELF_NAMES_FLOOR: usize = 64 << 20;
const ELF_NAMES_PER_FILE_BYTE: usize = 32;
/// PE export and import names, in total (the walkers also serve live
/// processes, so the bound cannot come from a file length).
const MAX_PE_NAME_BYTES: usize = 128 << 20;
/// Longest name read from a PE file. MSVC truncates decorated names at 4096
/// characters; a longer run is not a name.
const MAX_PE_FILE_NAME: usize = 0x1_0000;
/// Import thunk slots visited across all descriptors; real images import a
/// few thousand functions.
const MAX_PE_IMPORT_SLOTS: usize = 1 << 18;

/// Bytes the image parsers may still materialize into regions.
///
/// A capped total keeps every region byte-identical for valid images. The
/// alternative, regions with a virtual zero tail, would change what every
/// `Region::data` reader sees (anchor search, page hashes, start sweeps).
///
/// Zero fill past the cap is dropped, not refused: a program with a multi-GB
/// static array (Fortran, HPC codes) is valid, and its code is still worth
/// scanning. The parsers keep the module bounds from the header sizes, so
/// only reads inside the dropped tail differ (they find no region).
struct RegionBudget {
    file_bytes: u64,
    zero_bytes: u64,
}

impl RegionBudget {
    fn new(file_len: usize) -> RegionBudget {
        let file_len = file_len as u64;
        RegionBudget {
            file_bytes: file_len.saturating_mul(FILE_COPIES_PER_FILE_BYTE),
            zero_bytes: ZERO_FILL_FLOOR
                .saturating_add(file_len.saturating_mul(ZERO_FILL_PER_FILE_BYTE)),
        }
    }

    /// `bytes` copied out of the file, zero-filled up to `length`, or short
    /// of it once the zero-fill budget runs out.
    fn padded(&mut self, bytes: &[u8], length: u64) -> Result<Vec<u8>, SourceFormatError> {
        let copied = bytes.len() as u64;
        if copied > self.file_bytes {
            return Err(SourceFormatError(
                "image sections copy more bytes than the file can back".into(),
            ));
        }
        let zeros = length.saturating_sub(copied).min(self.zero_bytes);
        let total = usize::try_from(copied + zeros)
            .map_err(|_| SourceFormatError("section does not fit in memory".into()))?;
        self.file_bytes -= copied;
        self.zero_bytes -= zeros;
        if zeros == 0 {
            return Ok(bytes.to_vec());
        }
        // Zeroed allocation first, so untouched fill pages can stay lazily
        // committed instead of being written.
        let mut out = vec![0u8; total];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(out)
    }
}

/// Bytes of names a parser may still copy out of the image.
struct NameBudget {
    left: usize,
}

impl NameBudget {
    fn new(limit: usize) -> NameBudget {
        NameBudget { left: limit }
    }

    /// Charge `length` bytes; `false` (and spent) once that would overspend.
    fn charge(&mut self, length: usize) -> bool {
        if length > self.left {
            self.left = 0;
            return false;
        }
        self.left -= length;
        true
    }

    /// [`cstr`], charged; `None` once the budget is spent. The scan stops one
    /// byte past what is left, so scanning is bounded too.
    fn cstr(&mut self, blob: &[u8], offset: usize) -> Option<String> {
        let rest = blob.get(offset..).unwrap_or(&[]);
        let window = &rest[..rest.len().min(self.left.saturating_add(1))];
        let length = window
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(window.len());
        if !self.charge(length) {
            return None;
        }
        Some(String::from_utf8_lossy(&rest[..length]).into_owned())
    }
}

fn elf_names_exhausted() -> SourceFormatError {
    SourceFormatError("ELF names exceed the bytes the file can account for".into())
}

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
    local_symbols: bool,
    thumb_starts: Vec<u64>,
    /// ARM32 images without `.symtab`: mode from surviving pointers and code.
    mode_map: Option<ModeMap>,
    /// Unwind-table entries merged with synthesized starts, sorted.
    unwind: Vec<(u64, u64)>,
    synthesized: Vec<u64>,
    /// Start synthesis ran out of its sweep budget (`starts`).
    start_sweep_truncated: bool,
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

    /// A raw code blob (`--raw`): a firmware image or a dump of one code
    /// region, mapped as one executable region at `base`. It has no
    /// container, so nothing names a function, gives bounds, or says which
    /// words are relocated: discovery is hint-free, every in-range value is
    /// an address (the module-range test of SPEC.md §2.2 for images without
    /// a relocation table), and function starts are synthesized from the
    /// code alone (`starts`), as for a stripped image without unwind tables.
    /// ARM32 mode comes from the code (`arm_mode`); x86-64 has no code-only
    /// start sweep, so its starts are the direct call targets reachable from
    /// `base`.
    pub fn from_raw(
        data: &[u8],
        name: &str,
        arch: Arch,
        base: u64,
    ) -> Result<FileSource, SourceFormatError> {
        if data.is_empty() {
            return Err(SourceFormatError("raw blob is empty".into()));
        }
        if data.len() > MAX_RAW_BYTES {
            return Err(SourceFormatError(format!(
                "raw blob of {} bytes exceeds the {MAX_RAW_BYTES}-byte limit",
                data.len()
            )));
        }
        // The region's end must be representable: addresses past it are
        // compared against it everywhere.
        // ARM32 and Thumb address 32 bits, so their code ends at 4 GiB. An
        // ELF32 image cannot place a region higher; a raw base could, and
        // the ARM start sweep's realigning steps would wrap past 2^64 there.
        let limit = if arch.is_arm() { 1u64 << 32 } else { u64::MAX };
        if base
            .checked_add(data.len() as u64)
            .is_none_or(|end| end > limit)
        {
            return Err(SourceFormatError(format!(
                "raw blob of {} bytes does not fit at base 0x{base:x} in the {arch} address space",
                data.len()
            )));
        }
        let region = Region::new("raw", base, data.to_vec(), true, false);
        let module = Module {
            name: name.to_string(),
            base,
            image_base: base,
            size: data.len() as u64,
            path: None,
            relocations: None,
            ..Module::default()
        };
        let parsed = ParsedImage {
            regions: vec![region],
            module,
            bounds: Vec::new(),
            local_symbols: false,
            thumb_starts: Vec::new(),
            code_pointers: (arch == Arch::Arm32).then(Vec::new),
            unwind: Vec::new(),
            unwind_exact_ends: false,
            start_pointers: (arch != Arch::X64).then(Vec::new),
            pointer_slots: Vec::new(),
            pe_roots: (arch == Arch::X64).then(|| vec![base]),
        };
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
            local_symbols: parsed.local_symbols,
            thumb_starts,
            mode_map,
            unwind,
            synthesized: Vec::new(),
            start_sweep_truncated: false,
        };
        let mut synthesized: Option<Vec<u64>> = None;
        if let Some(roots) = &parsed.pe_roots {
            let mut roots = roots.clone();
            // With no table, the exports are starts themselves.
            roots.sort_unstable();
            let (mut found, truncated) = if arch == Arch::Arm64 {
                starts::arm64_call_targets_checked(&source.regions, &source.unwind, &roots)
            } else {
                starts::x64_call_targets_checked(&source.regions, &source.unwind, &roots)
            };
            source.start_sweep_truncated |= truncated;
            found.extend(&roots);
            synthesized = Some(found);
        }
        if let Some(pointers) = parsed.start_pointers {
            // Decoding needs the finished mode map, so this runs last.
            let mut found =
                starts::evidence(arch, &source.regions, &pointers, &|a| source.is_thumb(a));
            source.start_sweep_truncated |= found.sweep_truncated;
            if !parsed.pointer_slots.is_empty() {
                // Starts known without relocated pointers: every other rule,
                // the unwind table, and exported function values.
                let mut others = found.clone();
                let relocated: std::collections::HashSet<u64> =
                    parsed.pointer_slots.iter().map(|(_, p)| p & !1).collect();
                others
                    .pointers
                    .retain(|pointer| !relocated.contains(pointer));
                let mut known = starts::synthesize(&others);
                known.extend(source.unwind.iter().map(|(start, _)| *start));
                let labels = starts::label_tables(&parsed.pointer_slots, 4, &known);
                found
                    .pointers
                    .retain(|pointer| labels.binary_search(pointer).is_err());
            }
            synthesized = Some(starts::synthesize(&found));
        }
        if let Some(mut synthesized) = synthesized {
            synthesized.sort_unstable();
            synthesized.dedup();
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

    fn symbols_stripped(&self) -> bool {
        !self.local_symbols
    }

    fn unwind_entries(&self) -> &[(u64, u64)] {
        &self.unwind
    }

    fn start_sweep_truncated(&self) -> bool {
        self.start_sweep_truncated
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
    /// `.symtab` names functions, so symbol hints cover local code too.
    local_symbols: bool,
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
    /// `(slot, pointer)` for relocated pointers (ARM32 only).
    pointer_slots: Vec<(u64, u64)>,
    /// x86-64 PE: exported code addresses, roots of the call-target sweep
    /// that finds leaf functions `.pdata` omits. `None` disables it.
    pe_roots: Option<Vec<u64>>,
}

// -- little-endian readers ----------------------------------------------------

fn u16_at(data: &[u8], offset: usize) -> Result<u16, SourceFormatError> {
    data.get(offset..offset.saturating_add(2))
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| SourceFormatError("truncated image".into()))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, SourceFormatError> {
    data.get(offset..offset.saturating_add(4))
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or_else(|| SourceFormatError("truncated image".into()))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64, SourceFormatError> {
    data.get(offset..offset.saturating_add(8))
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
    parse_elf_budgeted(data, name, arch, RegionBudget::new(data.len()))
}

/// [`parse_elf`] with an explicit region budget, so tests can reach the cap
/// without allocating a gigabyte.
fn parse_elf_budgeted(
    data: &[u8],
    name: &str,
    arch: Arch,
    mut budget: RegionBudget,
) -> Result<ParsedImage, SourceFormatError> {
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
    // `llvm-objcopy --strip-sections` (and firmware or malware that drops
    // the table) leaves only what the loader reads: program headers. A
    // relocatable object has no segments, so it still needs its sections.
    let sectionless = e_shnum == 0 && e_type != ELF_ET_REL;
    if !sectionless && (e_shoff == 0 || e_shnum == 0 || (e_shentsize as usize) < sh_struct_size) {
        return Err(SourceFormatError(
            "ELF image has no usable section table".into(),
        ));
    }

    // The image base is the lowest PT_LOAD address, so `module+rva` agrees
    // with readelf and disassemblers (the ELF header page is part of the
    // image even though no section covers it). Relocatable objects have no
    // program headers and fall back to the lowest placed section.
    let load_base = elf_load_base(data, is64);

    let mut name_budget = NameBudget::new(
        ELF_NAMES_FLOOR.saturating_add(data.len().saturating_mul(ELF_NAMES_PER_FILE_BYTE)),
    );
    let (mut sections, mut names, segment_tables) = if sectionless {
        let segments = segment_sections(data, is64)?;
        (segments.sections, segments.names, Some(segments.tables))
    } else {
        let sections = section_table(data, is64, e_shoff, e_shnum, e_shentsize, sh_struct_size)?;
        if e_shstrndx as usize >= sections.len() {
            return Err(SourceFormatError(
                "invalid ELF section-name table index".into(),
            ));
        }
        let name_table = section_bytes(data, &sections[e_shstrndx as usize], &mut budget)?;
        let names: Vec<String> = sections
            .iter()
            .map(|section| {
                name_budget
                    .cstr(&name_table, section.name_off as usize)
                    .ok_or_else(elf_names_exhausted)
            })
            .collect::<Result<_, _>>()?;
        (sections, names, None)
    };
    // A section table that does not describe the dynamic symbols (an image
    // rebuilt from an IDA database, whose segments name only some sections)
    // still has the loader's view of them: take the tables from the dynamic
    // segment, as the loader does. Their symbols' section indices then refer
    // to the original table, so symbols are placed by address instead.
    let dynamic_tables = e_type != ELF_ET_REL
        && !sections
            .iter()
            .any(|section| section.kind == ELF_SHT_DYNSYM);
    let dynamic_tables = dynamic_tables && {
        let found = dynamic_sections(data, is64, sections.len());
        let any = !found.is_empty();
        for (section, name) in found {
            sections.push(section);
            names.push(name.to_string());
        }
        any
    };

    let mut places: HashMap<usize, u64> = HashMap::new();
    let mut regions: Vec<Region> = Vec::new();
    // Header-claimed end of the sections, which a zero fill cut short by the
    // region budget does not reach.
    let mut claimed_end = 0u64;
    for (index, section) in sections.iter().enumerate() {
        if section.flags & ELF_SHF_ALLOC == 0 || section.size == 0 {
            continue;
        }
        let start = if e_type == ELF_ET_REL {
            ELF_PLACE_BASE.saturating_add(section.offset)
        } else {
            if section.addr == 0 {
                continue;
            }
            section.addr
        };
        // Every later address computation (region ends, unwind cursors, start
        // sweeps) assumes a section's span fits in the address space; checking
        // once here keeps a hostile header from wrapping any of them.
        if start.checked_add(section.size).is_none() {
            return Err(SourceFormatError(
                "ELF section extends past the end of the address space".into(),
            ));
        }
        places.insert(index, start);
        claimed_end = claimed_end.max(start.saturating_add(section.size));
        let bytes = match section_bytes(data, section, &mut budget)? {
            Cow::Borrowed(bytes) => budget.padded(bytes, bytes.len() as u64)?,
            Cow::Owned(zeros) => zeros,
        };
        if bytes.is_empty() {
            continue; // zero fill past the budget; the bounds still cover it
        }
        regions.push(Region::new(
            if names[index].is_empty() {
                format!("section{index}")
            } else {
                names[index].clone()
            },
            start,
            bytes,
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
    let mut tables: SymbolTables<'_> = HashMap::new();
    // Real symbol tables are disjoint in the file; many headers that all
    // point at one table must not multiply the work (2x headroom).
    let mut symbol_entries_left = data.len() / 8;
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
        let raw = section_bytes(data, section, &mut budget)?;
        let strings = section_bytes(data, &sections[section.link as usize], &mut budget)?;
        tables.insert(index, (raw, strings));
        let (raw, strings) = &tables[&index];
        let raw: &[u8] = raw;
        let strings: &[u8] = strings;
        let entry_size = if section.entsize != 0 {
            section.entsize as usize
        } else {
            sym_struct_size
        };
        if entry_size < sym_struct_size {
            continue;
        }
        let count = raw.len() / entry_size;
        if count > symbol_entries_left {
            return Err(SourceFormatError(
                "ELF symbol tables hold more entries than the file".into(),
            ));
        }
        symbol_entries_left -= count;
        for symbol_index in 0..count {
            let offset = symbol_index * entry_size;
            if offset + sym_struct_size > raw.len() {
                break;
            }
            let (st_name, st_info, st_shndx, st_value, st_size) = if is64 {
                (
                    u32_at(raw, offset)?,
                    raw[offset + 4],
                    u16::from_le_bytes([raw[offset + 6], raw[offset + 7]]),
                    u64_at(raw, offset + 8)?,
                    u64_at(raw, offset + 16)?,
                )
            } else {
                (
                    u32_at(raw, offset)?,
                    raw[offset + 12],
                    u16::from_le_bytes([raw[offset + 14], raw[offset + 15]]),
                    u32_at(raw, offset + 4)? as u64,
                    u32_at(raw, offset + 8)? as u64,
                )
            };
            let symbol_name = name_budget
                .cstr(strings, st_name as usize)
                .ok_or_else(elf_names_exhausted)?;
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
    // Every word the loader writes in a shared object or PIE: the only places
    // such an image can hold an absolute address (SPEC.md §2.2).
    let mut relocations: Vec<u64> = Vec::new();
    // As for symbols: relocation tables are disjoint in a real file (2x
    // headroom over the smallest entry).
    let mut relocation_entries_left = data.len() / 4;
    let pointer_size = if is64 { 8 } else { 4 };
    // A packed relative relocation's addend is the word at its place, so
    // every place is file-backed: no more of them than the file has words.
    let mut packed_slots_left = data.len() / pointer_size;
    for section in &sections {
        if section.kind == ELF_SHT_RELR && e_type != ELF_ET_REL {
            // `-z pack-relative-relocs` moves the relative relocations out of
            // RELA/REL into this table. They must land in the same sets as
            // their unpacked twins, or packing would change which words are
            // addresses (SPEC.md §2.2) and which pointers seed start synthesis.
            let raw = section_bytes(data, section, &mut budget)?;
            for slot in relr_slots(&raw, pointer_size, &mut packed_slots_left)? {
                if e_type == ELF_ET_DYN {
                    relocations.push(slot);
                }
                if arch == Arch::Arm32 && !is64 {
                    relative_slots.push(slot);
                } else if is64 && start_pointers.len() < 2 * crate::unwind::MAX_UNWIND_ENTRIES {
                    // The unpacked twin's RELA addend, which RELR keeps in place.
                    if let Ok(word) = read_regions(&regions, slot, 8) {
                        start_pointers.push(u64::from_le_bytes(
                            word[..8].try_into().expect("8-byte read"),
                        ));
                    }
                }
            }
            continue;
        }
        // Android's packed tables (`--pack-dyn-relocs=android`) hold the same
        // entries as their unpacked twins, so they are decoded into that form.
        let (kind, packed) = match section.kind {
            ELF_SHT_ANDROID_RELA => (ELF_SHT_RELA, true),
            ELF_SHT_ANDROID_REL => (ELF_SHT_REL, true),
            kind => (kind, false),
        };
        if kind != ELF_SHT_RELA && kind != ELF_SHT_REL {
            continue;
        }
        // `Elf32_Rel` is 8 bytes (ARM32 uses REL, not RELA); the addend that
        // RELA adds is never read here.
        let rel_struct_size = match (is64, kind == ELF_SHT_RELA) {
            (true, true) => 24usize,
            (true, false) => 16,
            (false, true) => 12,
            (false, false) => 8,
        };
        let entry_size = if section.entsize != 0 && !packed {
            section.entsize as usize
        } else {
            rel_struct_size
        };
        if entry_size < rel_struct_size {
            continue;
        }
        let raw = section_bytes(data, section, &mut budget)?;
        let raw: Cow<'_, [u8]> = if packed {
            Cow::Owned(android_relocations(
                &raw,
                is64,
                kind == ELF_SHT_RELA,
                relocation_entries_left,
            )?)
        } else {
            raw
        };
        let count = raw.len() / entry_size;
        if count > relocation_entries_left {
            return Err(SourceFormatError(
                "ELF relocation tables hold more entries than the file".into(),
            ));
        }
        relocation_entries_left -= count;
        for rel_index in 0..count {
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
            if e_type == ELF_ET_DYN {
                relocations.push(r_offset);
            }
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
                && kind == ELF_SHT_RELA
                && r_info & 0xffff_ffff == relative
            {
                if start_pointers.len() < 2 * crate::unwind::MAX_UNWIND_ENTRIES {
                    start_pointers.push(u64_at(&raw, offset + 16)?);
                }
                continue;
            }
            let symbol_index = if is64 { r_info >> 32 } else { r_info >> 8 };
            // A spent budget only stops naming relocation targets: a large C++
            // image repeats long mangled names once per call site, and losing
            // some import names is better than refusing the whole image.
            let Some(target) = symbol_name(
                &tables,
                section.link as usize,
                symbol_index,
                is64,
                &mut name_budget,
            ) else {
                continue;
            };
            if target.is_empty() {
                continue;
            }
            let slot = if e_type == ELF_ET_REL {
                let Some(base) = places.get(&(section.info as usize)) else {
                    continue;
                };
                base.wrapping_add(r_offset)
            } else {
                r_offset
            };
            imports.entry(slot).or_insert(target);
        }
    }

    if segment_tables.is_some() && arch != Arch::X64 {
        if let Some(plt) = plt_range(arch, &regions, &imports) {
            carve_plt(&mut regions, plt);
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
        let placed = if dynamic_tables {
            // Reserved indices (`SHN_ABS`, `SHN_COMMON`) and TLS offsets are
            // not addresses; every other defined symbol lies in a section.
            (shndx < 0xff00
                && info & 0xF != ELF_STT_TLS
                && regions.iter().any(|region| region.contains(value & !1, 0)))
            .then_some(0)
        } else {
            places.get(&(shndx as usize)).copied()
        };
        let Some(base) = placed else {
            continue;
        };
        let mut address = if e_type == ELF_ET_REL {
            base.wrapping_add(value)
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
                bounds.push((address, address.saturating_add(size)));
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
    let image_start = match load_base {
        Some(base) if e_type != ELF_ET_REL => base.min(section_start),
        _ => section_start,
    };
    let module_end = regions
        .iter()
        .map(|region| region.end())
        .max()
        .unwrap_or(0)
        .max(claimed_end);
    relocations.sort_unstable();
    relocations.dedup();
    let module = Module {
        name: module_stem(name),
        base: section_start,
        image_base: image_start,
        size: module_end - section_start,
        path: Some(name.to_string()),
        exports,
        functions,
        imports,
        relocations: (e_type == ELF_ET_DYN).then_some(relocations),
    };
    let unwind = match &segment_tables {
        Some(tables) => {
            let views = tables.unwind_views(&regions);
            crate::unwind::elf_table_entries(&views, &regions, pointer_size)
        }
        None => crate::unwind::elf_entries(&regions, pointer_size),
    };
    // `.ARM.exidx` ends are only the next entry's start; `.eh_frame` lengths
    // are exact.
    let unwind_exact_ends = match &segment_tables {
        Some(tables) => tables.arm_exidx.is_none(),
        None => !regions.iter().any(|region| region.name == ".ARM.exidx"),
    };
    // `(slot, pointer)` per relocated pointer, so tables can be told apart
    // (`starts::label_tables`). Only ARM needs it: `.eh_frame` extents
    // already drop starts inside x64/arm64 functions.
    let mut pointer_slots: Vec<(u64, u64)> = Vec::new();
    if arch == Arch::Arm32 && e_type != ELF_ET_REL {
        pointer_slots = relative_slots
            .iter()
            .take(crate::unwind::MAX_UNWIND_ENTRIES)
            .filter_map(|slot| {
                let word = read_regions(&regions, *slot, 4).ok()?;
                let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
                Some((*slot, u64::from(value)))
            })
            .collect();
        start_pointers.extend(pointer_slots.iter().map(|(_, value)| *value));
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
        local_symbols: symtab_functions,
        thumb_starts,
        code_pointers,
        unwind,
        unwind_exact_ends,
        start_pointers,
        pointer_slots,
        pe_roots: None,
    })
}

/// What an image without section headers keeps of its unwind tables: the
/// `PT_GNU_EH_FRAME` and `PT_ARM_EXIDX` ranges, as `(vaddr, memsz)`.
struct SegmentTables {
    eh_frame_hdr: Option<(u64, u64)>,
    arm_exidx: Option<(u64, u64)>,
}

impl SegmentTables {
    /// `.eh_frame` and `.ARM.exidx` as named copies of the loaded bytes, for
    /// the unwind parsers, which find tables by section name.
    fn unwind_views(&self, regions: &[Region]) -> Vec<Region> {
        let mut views = Vec::new();
        if let Some(hdr) = self
            .eh_frame_hdr
            .and_then(|(addr, size)| region_view(regions, ".eh_frame_hdr", addr, size))
        {
            if let Some(frames) = crate::unwind::eh_frame_extent(&hdr, regions)
                .and_then(|(start, end)| region_view(regions, ".eh_frame", start, end - start))
            {
                views.push(frames);
            }
        }
        if let Some(exidx) = self
            .arm_exidx
            .and_then(|(addr, size)| region_view(regions, ".ARM.exidx", addr, size))
        {
            views.push(exidx);
        }
        views
    }
}

/// `[addr, addr + size)` cut to the one region holding `addr`, as a region
/// named `name`: a table the loader finds through a segment never spans two.
fn region_view(regions: &[Region], name: &str, addr: u64, size: u64) -> Option<Region> {
    let region = regions
        .iter()
        .find(|region| region.start <= addr && addr < region.end())?;
    let begin = (addr - region.start) as usize;
    let end = (addr.saturating_add(size).min(region.end()) - region.start) as usize;
    Some(Region::new(
        name,
        addr,
        region.data[begin..end].to_vec(),
        false,
        false,
    ))
}

/// The PLT of a section-less ARM32 or AArch64 image, `[start, end)`.
///
/// Start synthesis leaves `.plt` out by name: its stubs are linker-made, and
/// a call into one names an import, not a function. Without sections the
/// PLT shares the code segment, and on the real corpus every stub became a
/// synthesized start. The stubs are the `stubs` matches that jump through an
/// import slot; the header before them opens with `stp x16, x30, [sp,
/// #-16]!` (AArch64) or `str lr, [sp, #-4]!` (ARM), in lld and GNU ld alike.
fn plt_range(arch: Arch, regions: &[Region], imports: &HashMap<u64, String>) -> Option<(u64, u64)> {
    const ARM64_HEADER: u32 = 0xa9bf_7bf0;
    const ARM64_BTI_C: u32 = 0xd503_245f;
    const ARM_HEADER: u32 = 0xe52d_e004;
    /// Longest PLT header (lld's AArch64 and ARM headers, 32 bytes).
    const MAX_HEADER: u64 = 32;
    let arm64 = arch == Arch::Arm64;
    let mut entries: Vec<u64> = Vec::new();
    for region in regions.iter().filter(|region| region.executable) {
        for (index, chunk) in region.data.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_le_bytes(*chunk);
            // Cheap first-word filters before the full match: `adrp x16` or
            // `bti`, and `add ip, pc` or Thumb's `bx pc; nop`.
            let candidate = if arm64 {
                word & 0x9f00_001f == 0x9000_0010 || word & 0xffff_ff3f == 0xd503_241f
            } else {
                word & 0xffff_f000 == 0xe28f_c000 || word == 0x46c0_4778
            };
            if !candidate || entries.len() >= imports.len() {
                continue;
            }
            let offset = index * 4;
            let address = region.start + offset as u64;
            let bytes =
                &region.data[offset..region.data.len().min(offset + crate::stubs::MAX_STUB_BYTES)];
            let exit = if arm64 {
                crate::stubs::arm64_stub(address, bytes)
            } else {
                crate::stubs::arm32_stub(address, bytes)
            };
            if let Some(crate::stubs::StubExit::Slot(slot)) = exit {
                if imports.contains_key(&slot) {
                    entries.push(address);
                }
            }
        }
    }
    let first = *entries.iter().min()?;
    let last = *entries.iter().max()?;
    let mut stride = 16;
    entries.sort_unstable();
    if let Some(gap) = entries.windows(2).map(|pair| pair[1] - pair[0]).min() {
        stride = gap.clamp(4, 32);
    }
    let region = regions
        .iter()
        .find(|region| region.start <= first && first < region.end())?;
    let word_at = |address: u64| {
        let offset = address.checked_sub(region.start)? as usize;
        let bytes = region.data.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    };
    let mut start = first;
    for back in (4..=MAX_HEADER).step_by(4) {
        let Some(address) = first.checked_sub(back) else {
            break;
        };
        if word_at(address) == Some(if arm64 { ARM64_HEADER } else { ARM_HEADER }) {
            start = address;
            if arm64 && address >= 4 && word_at(address - 4) == Some(ARM64_BTI_C) {
                start = address - 4;
            }
            break;
        }
    }
    Some((start, last.saturating_add(stride).min(region.end())))
}

/// Split the executable region holding `[start, end)` so that range becomes
/// its own region named `.plt`, as the section table would have shown it.
fn carve_plt(regions: &mut Vec<Region>, (start, end): (u64, u64)) {
    let Some(index) = regions.iter().position(|region| {
        region.executable && region.start <= start && start < end && end <= region.end()
    }) else {
        return;
    };
    let mut region = regions.remove(index);
    let mut plt = region.data.split_off((start - region.start) as usize);
    let tail = plt.split_off((end - start) as usize);
    let writable = region.writable;
    if !tail.is_empty() {
        regions.push(Region::new(
            format!("{}.tail", region.name),
            end,
            tail,
            true,
            writable,
        ));
    }
    regions.push(Region::new(".plt", start, plt, true, writable));
    if !region.data.is_empty() {
        regions.push(region);
    }
    regions.sort_by_key(|region| region.start);
}

/// Sections standing in for a missing section table: one per `PT_LOAD` file
/// part and one per zero-filled tail, as the loader maps them.
struct Segments {
    sections: Vec<Section>,
    names: Vec<String>,
    tables: SegmentTables,
}

fn segment_sections(data: &[u8], is64: bool) -> Result<Segments, SourceFormatError> {
    const ELF_PT_GNU_EH_FRAME: u32 = 0x6474_e550;
    const ELF_PT_ARM_EXIDX: u32 = 0x7000_0001;
    const ELF_PF_X: u32 = 1;
    const ELF_PF_W: u32 = 2;
    const ELF_SHT_PROGBITS: u32 = 1;
    let (phoff, phentsize, phnum, header_size, entry_size) = if is64 {
        (
            u64_at(data, 0x20)?,
            u16_at(data, 0x36)?,
            u16_at(data, 0x38)?,
            0x40u64,
            0x38usize,
        )
    } else {
        (
            u64::from(u32_at(data, 0x1C)?),
            u16_at(data, 0x2A)?,
            u16_at(data, 0x2C)?,
            0x34,
            0x20,
        )
    };
    if phoff == 0 || phnum == 0 || (phentsize as usize) < entry_size {
        return Err(SourceFormatError(
            "ELF image has neither a section table nor program headers".into(),
        ));
    }
    // No code or data lives in the file's own headers, and leaving them out
    // starts the first region where the first section would have. The
    // program headers count only when they follow the ELF header, as every
    // linker writes them; a table elsewhere in the file would otherwise hide
    // everything before it.
    let headers_end = if phoff <= header_size {
        phoff
            .saturating_add(u64::from(phnum) * u64::from(phentsize))
            .max(header_size)
    } else {
        header_size
    };
    let mut segments = Segments {
        sections: Vec::new(),
        names: Vec::new(),
        tables: SegmentTables {
            eh_frame_hdr: None,
            arm_exidx: None,
        },
    };
    let section = |kind: u32, flags: u64, addr: u64, offset: u64, size: u64| Section {
        name_off: 0,
        kind,
        flags,
        addr,
        offset,
        size,
        link: 0,
        info: 0,
        entsize: 0,
    };
    for index in 0..phnum as usize {
        let at = usize::try_from(phoff)
            .ok()
            .and_then(|phoff| phoff.checked_add(index * phentsize as usize))
            .filter(|at| at.saturating_add(entry_size) <= data.len())
            .ok_or_else(|| SourceFormatError("truncated ELF program headers".into()))?;
        let (kind, flags, offset, vaddr, filesz, memsz) = if is64 {
            (
                u32_at(data, at)?,
                u32_at(data, at + 4)?,
                u64_at(data, at + 8)?,
                u64_at(data, at + 16)?,
                u64_at(data, at + 32)?,
                u64_at(data, at + 40)?,
            )
        } else {
            (
                u32_at(data, at)?,
                u32_at(data, at + 24)?,
                u64::from(u32_at(data, at + 4)?),
                u64::from(u32_at(data, at + 8)?),
                u64::from(u32_at(data, at + 16)?),
                u64::from(u32_at(data, at + 20)?),
            )
        };
        match kind {
            ELF_PT_LOAD => {}
            ELF_PT_GNU_EH_FRAME => {
                segments.tables.eh_frame_hdr = Some((vaddr, memsz));
                continue;
            }
            ELF_PT_ARM_EXIDX => {
                segments.tables.arm_exidx = Some((vaddr, memsz));
                continue;
            }
            _ => continue,
        }
        let mut section_flags = ELF_SHF_ALLOC;
        if flags & ELF_PF_X != 0 {
            section_flags |= ELF_SHF_EXECINSTR;
        }
        if flags & ELF_PF_W != 0 {
            section_flags |= ELF_SHF_WRITE;
        }
        let file_part = filesz.min(memsz);
        let skip = headers_end.saturating_sub(offset).min(file_part);
        if file_part > skip {
            segments.sections.push(section(
                ELF_SHT_PROGBITS,
                section_flags,
                vaddr.saturating_add(skip),
                offset.saturating_add(skip),
                file_part - skip,
            ));
            segments.names.push(format!("load{index}"));
        }
        if memsz > file_part {
            segments.sections.push(section(
                ELF_SHT_NOBITS,
                section_flags,
                vaddr.saturating_add(file_part),
                0,
                memsz - file_part,
            ));
            segments.names.push(format!("load{index}.bss"));
        }
    }
    Ok(segments)
}

/// The section header table, every entry inside the file.
fn section_table(
    data: &[u8],
    is64: bool,
    e_shoff: u64,
    e_shnum: u16,
    e_shentsize: u16,
    sh_struct_size: usize,
) -> Result<Vec<Section>, SourceFormatError> {
    let mut sections: Vec<Section> = Vec::with_capacity(e_shnum as usize);
    for index in 0..e_shnum as usize {
        let offset = (e_shoff as usize).saturating_add(index * e_shentsize as usize);
        if offset.saturating_add(sh_struct_size) > data.len() {
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
    Ok(sections)
}

/// Android's packed relocations (`APS2`, as bionic reads them) re-encoded as
/// plain `Elf*_Rela` (`rela`) or `Elf*_Rel` entries.
///
/// The stream is SLEB128 values: the count and first offset, then groups
/// whose flags say which of offset delta, info, and addend delta the group
/// shares and which each entry carries. More than `limit` entries is a
/// malformed table; a truncated stream keeps the entries before the cut.
fn android_relocations(
    raw: &[u8],
    is64: bool,
    rela: bool,
    limit: usize,
) -> Result<Vec<u8>, SourceFormatError> {
    const GROUPED_BY_INFO: i64 = 1;
    const GROUPED_BY_OFFSET_DELTA: i64 = 2;
    const GROUPED_BY_ADDEND: i64 = 4;
    const GROUP_HAS_ADDEND: i64 = 8;
    let Some(stream) = raw.strip_prefix(b"APS2") else {
        return Ok(Vec::new());
    };
    let mut cursor = 0usize;
    let mut next = || -> Option<i64> {
        let mut value = 0i64;
        for shift in (0..64).step_by(7) {
            let byte = *stream.get(cursor)?;
            cursor += 1;
            value |= i64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if shift + 7 < 64 && byte & 0x40 != 0 {
                    value |= -1i64 << (shift + 7);
                }
                return Some(value);
            }
        }
        None
    };
    let mut out = Vec::new();
    let (Some(count), Some(mut offset)) = (next(), next()) else {
        return Ok(out);
    };
    let count = usize::try_from(count).unwrap_or(0);
    if count > limit {
        return Err(SourceFormatError(
            "ELF packed relocations hold more entries than the file".into(),
        ));
    }
    let mut emit = |offset: i64, info: i64, addend: i64| {
        for value in [offset, info, addend].iter().take(if rela { 3 } else { 2 }) {
            if is64 {
                out.extend_from_slice(&value.to_le_bytes());
            } else {
                out.extend_from_slice(&(*value as u32).to_le_bytes());
            }
        }
    };
    let (mut info, mut addend, mut done) = (0i64, 0i64, 0usize);
    'groups: while done < count {
        let (Some(size), Some(flags)) = (next(), next()) else {
            break;
        };
        let delta = if flags & GROUPED_BY_OFFSET_DELTA != 0 {
            match next() {
                Some(delta) => delta,
                None => break,
            }
        } else {
            0
        };
        if flags & GROUPED_BY_INFO != 0 {
            let Some(value) = next() else { break };
            info = value;
        }
        let has_addend = rela && flags & GROUP_HAS_ADDEND != 0;
        if has_addend && flags & GROUPED_BY_ADDEND != 0 {
            let Some(value) = next() else { break };
            addend = addend.wrapping_add(value);
        } else if !has_addend {
            addend = 0;
        }
        // A group never holds more than the entries still to come; a zero or
        // negative size consumes its header and nothing else.
        let size = usize::try_from(size).unwrap_or(0).min(count - done);
        for _ in 0..size {
            let step = if flags & GROUPED_BY_OFFSET_DELTA != 0 {
                delta
            } else {
                let Some(step) = next() else { break 'groups };
                step
            };
            offset = offset.wrapping_add(step);
            if flags & GROUPED_BY_INFO == 0 {
                let Some(value) = next() else { break 'groups };
                info = value;
            }
            if has_addend && flags & GROUPED_BY_ADDEND == 0 {
                let Some(value) = next() else { break 'groups };
                addend = addend.wrapping_add(value);
            }
            emit(offset, info, addend);
            done += 1;
        }
    }
    Ok(out)
}

/// The places an `SHT_RELR` table relocates (gABI packed relative
/// relocations): an even word is a place, and each odd word after it is a
/// bitmap of the `8 * word - 1` words that follow the last place covered.
///
/// `left` caps the places over all tables, since a bitmap expands one word
/// into up to 63; running out is a malformed image, not a short read.
fn relr_slots(raw: &[u8], word: usize, left: &mut usize) -> Result<Vec<u64>, SourceFormatError> {
    let bits = (word * 8 - 1) as u64;
    let mut slots = Vec::new();
    let mut push = |slot: u64, slots: &mut Vec<u64>| {
        if *left == 0 {
            return Err(SourceFormatError(
                "ELF RELR tables relocate more words than the file holds".into(),
            ));
        }
        *left -= 1;
        slots.push(slot);
        Ok(())
    };
    // Where the next bitmap starts; `None` before the first place, so a
    // leading bitmap (malformed) relocates nothing.
    let mut next: Option<u64> = None;
    for entry in raw.chunks_exact(word) {
        let entry = if word == 8 {
            u64::from_le_bytes(entry.try_into().expect("8-byte chunk"))
        } else {
            u64::from(u32::from_le_bytes(entry.try_into().expect("4-byte chunk")))
        };
        if entry & 1 == 0 {
            push(entry, &mut slots)?;
            next = entry.checked_add(word as u64);
            continue;
        }
        let Some(base) = next else {
            continue;
        };
        for bit in 0..bits {
            if (entry >> (bit + 1)) & 1 != 0 {
                if let Some(slot) = base.checked_add(bit * word as u64) {
                    push(slot, &mut slots)?;
                }
            }
        }
        next = base.checked_add(bits * word as u64);
    }
    Ok(slots)
}

/// The dynamic symbol, string, and relocation tables the `PT_DYNAMIC` segment
/// points at, as unallocated sections appended after `first_index` existing
/// ones (their `link` fields index the result's position in that list).
///
/// Every value is target data (AGENTS.md rule 8): addresses map to file
/// offsets only inside a `PT_LOAD` segment's file bytes, counts are bounded
/// by the file, and a table that does not fit is dropped.
fn dynamic_sections(data: &[u8], is64: bool, first_index: usize) -> Vec<(Section, &'static str)> {
    const DT_NULL: u64 = 0;
    const DT_PLTRELSZ: u64 = 2;
    const DT_STRTAB: u64 = 5;
    const DT_SYMTAB: u64 = 6;
    const DT_RELA: u64 = 7;
    const DT_RELASZ: u64 = 8;
    const DT_STRSZ: u64 = 10;
    const DT_REL: u64 = 17;
    const DT_RELSZ: u64 = 18;
    const DT_PLTREL: u64 = 20;
    const DT_JMPREL: u64 = 23;
    const DT_RELRSZ: u64 = 35;
    const DT_RELR: u64 = 36;
    const DT_ANDROID_REL: u64 = 0x6000_000f;
    const DT_ANDROID_RELSZ: u64 = 0x6000_0010;
    const DT_ANDROID_RELA: u64 = 0x6000_0011;
    const DT_ANDROID_RELASZ: u64 = 0x6000_0012;

    let word = |offset: usize| -> Option<u64> {
        if is64 {
            u64_at(data, offset).ok()
        } else {
            u32_at(data, offset).ok().map(u64::from)
        }
    };
    let (phoff, phentsize, phnum) = if is64 {
        (word(0x20), u16_at(data, 0x36).ok(), u16_at(data, 0x38).ok())
    } else {
        (word(0x1C), u16_at(data, 0x2A).ok(), u16_at(data, 0x2C).ok())
    };
    let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, phentsize, phnum) else {
        return Vec::new();
    };
    // (vaddr, offset, filesz) of each PT_LOAD, and the PT_DYNAMIC file range.
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    for index in 0..phnum as usize {
        let Some(at) = (phoff as usize).checked_add(index * phentsize as usize) else {
            break;
        };
        let Ok(kind) = u32_at(data, at) else {
            break;
        };
        let fields = if is64 {
            (
                word(at.saturating_add(8)),
                word(at.saturating_add(16)),
                word(at.saturating_add(32)),
            )
        } else {
            (
                word(at.saturating_add(4)),
                word(at.saturating_add(8)),
                word(at.saturating_add(16)),
            )
        };
        let (Some(offset), Some(vaddr), Some(filesz)) = fields else {
            break;
        };
        match kind {
            ELF_PT_LOAD => loads.push((vaddr, offset, filesz)),
            ELF_PT_DYNAMIC => dynamic = Some((offset, filesz)),
            _ => {}
        }
    }
    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Vec::new();
    };
    let to_offset = |addr: u64, size: u64| -> Option<u64> {
        let (vaddr, offset, filesz) = loads
            .iter()
            .find(|(vaddr, _, filesz)| *vaddr <= addr && addr < vaddr.saturating_add(*filesz))?;
        let start = offset.checked_add(addr - vaddr)?;
        let end = start.checked_add(size)?;
        (end <= offset.saturating_add(*filesz) && end <= data.len() as u64).then_some(start)
    };

    let entry_size = if is64 { 16 } else { 8 };
    let mut tags: HashMap<u64, u64> = HashMap::new();
    for index in 0..(dynamic_size as usize / entry_size).min(MAX_DYNAMIC_ENTRIES) {
        let at = (dynamic_offset as usize).saturating_add(index * entry_size);
        let (Some(tag), Some(value)) = (word(at), word(at.saturating_add(entry_size / 2))) else {
            break;
        };
        if tag == DT_NULL {
            break;
        }
        tags.entry(tag).or_insert(value);
    }

    let sym_size: u64 = if is64 { 24 } else { 16 };
    let (Some(&symtab), Some(&strtab)) = (tags.get(&DT_SYMTAB), tags.get(&DT_STRTAB)) else {
        return Vec::new();
    };
    let Some(strsz) = tags.get(&DT_STRSZ).copied() else {
        return Vec::new();
    };
    let Some(strtab_offset) = to_offset(strtab, strsz) else {
        return Vec::new();
    };
    let count = symbol_count(data, &tags, symtab, strtab, sym_size, is64, &to_offset);
    let Some(count) = count.filter(|count| *count > 0) else {
        return Vec::new();
    };
    let Some(symtab_offset) = to_offset(symtab, count * sym_size) else {
        return Vec::new();
    };

    let unallocated =
        |kind: u32, addr: u64, offset: u64, size: u64, link: u32, entsize: u64| Section {
            name_off: 0,
            kind,
            flags: 0,
            addr,
            offset,
            size,
            link,
            info: 0,
            entsize,
        };
    let strtab_index = first_index as u32;
    let symtab_index = strtab_index + 1;
    let mut sections = vec![
        (
            unallocated(ELF_SHT_STRTAB, strtab, strtab_offset, strsz, 0, 0),
            ".dynstr",
        ),
        (
            unallocated(
                ELF_SHT_DYNSYM,
                symtab,
                symtab_offset,
                count * sym_size,
                strtab_index,
                sym_size,
            ),
            ".dynsym",
        ),
    ];
    let rela_size: u64 = if is64 { 24 } else { 12 };
    let rel_size: u64 = if is64 { 16 } else { 8 };
    let relr_size: u64 = if is64 { 8 } else { 4 };
    let pltrel_kind = match tags.get(&DT_PLTREL) {
        Some(&DT_REL) => ELF_SHT_REL,
        _ => ELF_SHT_RELA,
    };
    let tables = [
        (DT_RELA, DT_RELASZ, ELF_SHT_RELA, ".rela.dyn"),
        (DT_REL, DT_RELSZ, ELF_SHT_REL, ".rel.dyn"),
        (DT_JMPREL, DT_PLTRELSZ, pltrel_kind, ".rela.plt"),
        (DT_RELR, DT_RELRSZ, ELF_SHT_RELR, ".relr.dyn"),
        (
            DT_ANDROID_RELA,
            DT_ANDROID_RELASZ,
            ELF_SHT_ANDROID_RELA,
            ".rela.dyn",
        ),
        (
            DT_ANDROID_REL,
            DT_ANDROID_RELSZ,
            ELF_SHT_ANDROID_REL,
            ".rel.dyn",
        ),
    ];
    for (address_tag, size_tag, kind, name) in tables {
        let (Some(&addr), Some(&size)) = (tags.get(&address_tag), tags.get(&size_tag)) else {
            continue;
        };
        let Some(offset) = to_offset(addr, size) else {
            continue;
        };
        let entsize = match kind {
            ELF_SHT_RELA => rela_size,
            ELF_SHT_REL => rel_size,
            _ => relr_size,
        };
        let name = if kind == ELF_SHT_REL && name == ".rela.plt" {
            ".rel.plt"
        } else {
            name
        };
        sections.push((
            unallocated(kind, addr, offset, size, symtab_index, entsize),
            name,
        ));
    }
    sections
}

/// How many entries `DT_SYMTAB` holds: `DT_HASH`'s chain count, else the end
/// of `DT_GNU_HASH`'s last chain, else the gap up to `DT_STRTAB` (which
/// linkers place right after it).
fn symbol_count(
    data: &[u8],
    tags: &HashMap<u64, u64>,
    symtab: u64,
    strtab: u64,
    sym_size: u64,
    is64: bool,
    to_offset: &dyn Fn(u64, u64) -> Option<u64>,
) -> Option<u64> {
    const DT_HASH: u64 = 4;
    const DT_GNU_HASH: u64 = 0x6fff_fef5;
    // A symbol table cannot hold more entries than the file has bytes for.
    let limit = data.len() as u64 / sym_size;
    if let Some(&hash) = tags.get(&DT_HASH) {
        let offset = to_offset(hash, 8)? as usize;
        return Some(u64::from(u32_at(data, offset + 4).ok()?).min(limit));
    }
    if let Some(&hash) = tags.get(&DT_GNU_HASH) {
        let offset = to_offset(hash, 16)? as usize;
        let buckets = u64::from(u32_at(data, offset).ok()?);
        let first = u64::from(u32_at(data, offset + 4).ok()?);
        let bloom = u64::from(u32_at(data, offset + 8).ok()?);
        let bloom_word = if is64 { 8 } else { 4 };
        let buckets_at = (offset as u64)
            .checked_add(16)?
            .checked_add(bloom.checked_mul(bloom_word)?)?;
        if buckets > limit || buckets_at.saturating_add(buckets * 4) > data.len() as u64 {
            return None;
        }
        let mut last = 0u64;
        for index in 0..buckets {
            let value = u64::from(u32_at(data, (buckets_at + index * 4) as usize).ok()?);
            last = last.max(value);
        }
        if last < first {
            return Some(first.min(limit));
        }
        // Walk the last bucket's chain to its end marker (low bit set).
        let chains_at = buckets_at + buckets * 4;
        let mut index = last;
        while index < limit {
            let at = chains_at.checked_add((index - first).checked_mul(4)?)?;
            let value = u32_at(data, at as usize).ok()?;
            if value & 1 != 0 {
                return Some(index + 1);
            }
            index += 1;
        }
        return None;
    }
    (strtab > symtab).then(|| ((strtab - symtab) / sym_size).min(limit))
}

/// A section's bytes: borrowed from the file, or for `SHT_NOBITS` zeros
/// charged to `budget` (the size is a header field, not file data).
fn section_bytes<'a>(
    data: &'a [u8],
    section: &Section,
    budget: &mut RegionBudget,
) -> Result<Cow<'a, [u8]>, SourceFormatError> {
    if section.kind == ELF_SHT_NOBITS {
        return Ok(Cow::Owned(budget.padded(&[], section.size)?));
    }
    let start = section.offset as usize;
    let end = start
        .checked_add(section.size as usize)
        .ok_or_else(|| SourceFormatError("ELF section exceeds file size".into()))?;
    if end > data.len() {
        return Err(SourceFormatError("ELF section exceeds file size".into()));
    }
    Ok(Cow::Borrowed(&data[start..end]))
}

fn symbol_name(
    tables: &SymbolTables<'_>,
    table_index: usize,
    symbol_index: u64,
    is64: bool,
    names: &mut NameBudget,
) -> Option<String> {
    let (raw, strings) = tables.get(&table_index)?;
    let entry_size = if is64 { 24usize } else { 16usize };
    let bytes = (symbol_index as usize)
        .checked_mul(entry_size)
        .and_then(|offset| raw.get(offset..offset.checked_add(4)?))?;
    let st_name = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    names.cstr(strings, st_name as usize)
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
            .map(|offset| {
                let end = offset.saturating_add(MAX_PE_FILE_NAME).min(self.data.len());
                cstr(&self.data[offset.min(end)..end], 0)
            })
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
    let mut names = NameBudget::new(MAX_PE_NAME_BYTES);
    if let Some((export_rva, export_size)) = headers.export {
        if export_rva != 0 && export_size != 0 {
            parse_pe_exports(
                image,
                image_base,
                u64::from(export_rva),
                u64::from(export_size),
                strict,
                &mut metadata,
                &mut names,
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
                &mut names,
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
    parse_pe_budgeted(data, name, arch, RegionBudget::new(data.len()))
}

/// [`parse_pe`] with an explicit region budget, so tests can reach the cap
/// without allocating a gigabyte.
fn parse_pe_budgeted(
    data: &[u8],
    name: &str,
    arch: Arch,
    mut budget: RegionBudget,
) -> Result<ParsedImage, SourceFormatError> {
    let headers = parse_pe_headers(data)?;
    let image_base = headers.image_base;
    // RVAs are 32-bit, so every address in the image lies below
    // `image_base + 4 GiB`; refusing a base that leaves no room for that keeps
    // section, unwind, export, and import addresses from wrapping.
    if image_base.checked_add(1 << 32).is_none() {
        return Err(SourceFormatError(
            "PE image base leaves no room for the image".into(),
        ));
    }
    let mut regions: Vec<Region> = Vec::new();
    // Header-claimed end of the sections, which a zero fill cut short by the
    // region budget does not reach.
    let mut claimed_end = 0u64;
    for section in &headers.sections {
        let span = section.span();
        let take = (section.raw_size.min(span)) as usize;
        let end = section.raw_ptr.saturating_add(take).min(data.len());
        let start = section.raw_ptr.min(data.len());
        let payload = budget.padded(&data[start..end], span)?;
        claimed_end = claimed_end.max(
            image_base
                .wrapping_add(section.virtual_address)
                .saturating_add(span),
        );
        if payload.is_empty() {
            continue; // zero fill past the budget; the bounds still cover it
        }
        regions.push(Region::new(
            section.name.clone(),
            image_base.wrapping_add(section.virtual_address),
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
    let image_start = image_base.min(section_start);
    let module_end = regions
        .iter()
        .map(|region| region.end())
        .max()
        .unwrap_or(0)
        .max(claimed_end);
    let module = Module {
        name: module_stem(name),
        base: section_start,
        image_base: image_start,
        size: module_end - section_start,
        path: Some(name.to_string()),
        exports: metadata.exports,
        functions: metadata.functions,
        imports: metadata.imports,
        relocations: None,
    };
    // Exports that point into code root the leaf-function sweep
    // (`starts::x64_call_targets`, `starts::arm64_call_targets_checked`);
    // forwarders and data exports do not.
    let pe_roots = matches!(arch, Arch::X64 | Arch::Arm64).then(|| {
        module
            .exports
            .iter()
            .map(|(_, address)| *address)
            .filter(|address| {
                regions.iter().any(|region| {
                    region.executable && region.start <= *address && *address < region.end()
                })
            })
            .collect()
    });
    // PE exports carry no size, so there are no symbol bounds to hint recovery.
    Ok(ParsedImage {
        regions,
        module,
        bounds: Vec::new(),
        local_symbols: false,
        thumb_starts: Vec::new(),
        code_pointers: None,
        unwind: metadata.unwind,
        // `.pdata` lengths are exact.
        unwind_exact_ends: true,
        start_pointers: None,
        pointer_slots: Vec::new(),
        pe_roots,
    })
}

fn parse_pe_exports(
    image: &impl PeImage,
    image_base: u64,
    export_rva: u64,
    export_size: u64,
    strict: bool,
    metadata: &mut PeMetadata,
    names: &mut NameBudget,
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
        if !names.charge(symbol.len()) {
            return;
        }
        if strict
            && (function_rva == 0
                || (export_rva..export_rva + export_size).contains(&function_rva)
                || !image.contains(function_rva))
        {
            continue;
        }
        let address = image_base.wrapping_add(function_rva);
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
    names: &mut NameBudget,
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
    // Descriptors can share one thunk array, so the per-descriptor bound
    // alone would allow 4096 x 4096 slots.
    let mut slots_left = MAX_PE_IMPORT_SLOTS;
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
        if !names.charge(dll.len()) {
            return;
        }
        let thunk_rva = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };
        if !image.contains(thunk_rva) {
            continue;
        }
        for slot in 0..4096u64 {
            if slots_left == 0 {
                return;
            }
            slots_left -= 1;
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
            if !names.charge(dll.len() + 1 + symbol.len()) {
                return;
            }
            let address = image_base
                .wrapping_add(first_thunk)
                .wrapping_add(slot.wrapping_mul(thunk));
            imports
                .entry(address)
                .or_insert_with(|| format!("{dll}!{symbol}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHT_PROGBITS: u32 = 1;
    const SHT_STRTAB: u32 = 3;

    struct ElfSection {
        name: &'static str,
        kind: u32,
        flags: u64,
        addr: u64,
        offset: u64,
        size: u64,
    }

    fn section_header(name: u32, section: &ElfSection) -> [u8; 64] {
        let mut entry = [0u8; 64];
        entry[0..4].copy_from_slice(&name.to_le_bytes());
        entry[4..8].copy_from_slice(&section.kind.to_le_bytes());
        entry[8..16].copy_from_slice(&section.flags.to_le_bytes());
        entry[16..24].copy_from_slice(&section.addr.to_le_bytes());
        entry[24..32].copy_from_slice(&section.offset.to_le_bytes());
        entry[32..40].copy_from_slice(&section.size.to_le_bytes());
        entry
    }

    /// A little-endian x86-64 `ET_EXEC` with `body` at file offset 0x40 and
    /// `sections`, plus a null section and a trailing `.shstrtab`.
    fn elf64(body: &[u8], sections: &[ElfSection]) -> Vec<u8> {
        let mut image = vec![0u8; 0x40];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&2u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        image.extend_from_slice(body);
        let mut strings = vec![0u8];
        let mut name_offsets = Vec::new();
        for section in sections {
            name_offsets.push(strings.len() as u32);
            strings.extend_from_slice(section.name.as_bytes());
            strings.push(0);
        }
        let shstrtab_name = strings.len() as u32;
        strings.extend_from_slice(b".shstrtab\0");
        let strings_offset = image.len() as u64;
        image.extend_from_slice(&strings);
        while !image.len().is_multiple_of(8) {
            image.push(0);
        }
        let shoff = image.len() as u64;
        let null = ElfSection {
            name: "",
            kind: 0,
            flags: 0,
            addr: 0,
            offset: 0,
            size: 0,
        };
        image.extend_from_slice(&section_header(0, &null));
        for (section, name) in sections.iter().zip(&name_offsets) {
            image.extend_from_slice(&section_header(*name, section));
        }
        let shstrtab = ElfSection {
            name: ".shstrtab",
            kind: SHT_STRTAB,
            flags: 0,
            addr: 0,
            offset: strings_offset,
            size: strings.len() as u64,
        };
        image.extend_from_slice(&section_header(shstrtab_name, &shstrtab));
        let count = (sections.len() + 2) as u16;
        image[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        image[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());
        image[0x3C..0x3E].copy_from_slice(&count.to_le_bytes());
        image[0x3E..0x40].copy_from_slice(&(count - 1).to_le_bytes());
        image
    }

    fn text() -> ElfSection {
        ElfSection {
            name: ".text",
            kind: SHT_PROGBITS,
            flags: ELF_SHF_ALLOC | ELF_SHF_EXECINSTR,
            addr: 0x40_1000,
            offset: 0x40,
            size: 0x10,
        }
    }

    fn bss(size: u64) -> ElfSection {
        ElfSection {
            name: ".bss",
            kind: ELF_SHT_NOBITS,
            flags: ELF_SHF_ALLOC | ELF_SHF_WRITE,
            addr: 0x40_2000,
            offset: 0x50,
            size,
        }
    }

    #[test]
    fn nobits_section_is_zero_filled() {
        let image = elf64(&[0xC3; 0x10], &[text(), bss(0x1_0000)]);
        let parsed = parse_elf(&image, "bss", Arch::X64).expect("valid ELF");
        let bss = parsed
            .regions
            .iter()
            .find(|region| region.name == ".bss")
            .expect(".bss region");
        assert_eq!(bss.data.len(), 0x1_0000);
        assert!(bss.data.iter().all(|byte| *byte == 0));
        assert_eq!(parsed.module.size, 0x40_2000 + 0x1_0000 - 0x40_1000);
    }

    /// A budget small enough that tests reach the zero-fill cap cheaply.
    fn small_budget() -> RegionBudget {
        RegionBudget {
            file_bytes: 1 << 20,
            zero_bytes: 0x2_0000,
        }
    }

    #[test]
    fn huge_nobits_section_is_cut_to_the_budget() {
        for size in [u64::MAX / 2, 1 << 40, 0x2_0000 + 1] {
            let image = elf64(&[0xC3; 0x10], &[text(), bss(size)]);
            let parsed = parse_elf_budgeted(&image, "bss", Arch::X64, small_budget())
                .unwrap_or_else(|error| panic!("size 0x{size:x}: {}", error.0));
            let bss = parsed
                .regions
                .iter()
                .find(|region| region.name == ".bss")
                .expect(".bss region");
            assert_eq!(bss.data.len(), 0x2_0000, "size 0x{size:x}");
            // The bounds still come from the header, as without the cap.
            assert_eq!(
                parsed.module.size,
                0x40_2000u64.saturating_add(size) - 0x40_1000,
                "size 0x{size:x}"
            );
        }
        // A section whose end would pass the top of the address space is
        // refused before any budgeting: later address arithmetic relies on it.
        let image = elf64(&[0xC3; 0x10], &[text(), bss(u64::MAX)]);
        let Err(error) = parse_elf_budgeted(&image, "bss", Arch::X64, small_budget()) else {
            panic!("a section past the address space must be refused");
        };
        assert!(error.0.contains("address space"), "{}", error.0);
        // Within the budget nothing is cut.
        let image = elf64(&[0xC3; 0x10], &[text(), bss(0x2_0000)]);
        let parsed = parse_elf_budgeted(&image, "bss", Arch::X64, small_budget()).unwrap();
        assert_eq!(parsed.regions[1].data.len(), 0x2_0000);
    }

    #[test]
    fn real_budget_scales_with_the_file() {
        let budget = RegionBudget::new(100 << 20);
        assert_eq!(budget.zero_bytes, ZERO_FILL_FLOOR + (1600 << 20));
        assert_eq!(budget.file_bytes, 200 << 20);
    }

    #[test]
    fn overlapping_sections_cannot_multiply_the_file() {
        let sections: Vec<ElfSection> = (0..8u64)
            .map(|index| ElfSection {
                name: ".data",
                kind: SHT_PROGBITS,
                flags: ELF_SHF_ALLOC,
                addr: 0x50_0000 + index * 0x1_0000,
                offset: 0x40,
                size: 0x1000,
            })
            .collect();
        let image = elf64(&[0x55; 0x1000], &sections);
        assert!(parse_elf(&image, "overlap", Arch::X64).is_err());
        // One copy of the same bytes is fine.
        let image = elf64(&[0x55; 0x1000], &sections[..1]);
        let parsed = parse_elf(&image, "overlap", Arch::X64).expect("valid ELF");
        assert_eq!(parsed.regions[0].data, vec![0x55; 0x1000]);
    }

    #[test]
    fn repeated_symbol_tables_are_refused() {
        // Sixteen `.symtab` headers over the same zeroed table.
        let mut sections = vec![text()];
        sections.extend((0..16).map(|_| ElfSection {
            name: ".symtab",
            kind: ELF_SHT_SYMTAB,
            flags: 0,
            addr: 0,
            offset: 0x40,
            size: 0x1800,
        }));
        let image = elf64(&[0; 0x1800], &sections);
        let error = parse_elf(&image, "symtab", Arch::X64)
            .err()
            .expect("refused");
        assert!(error.0.contains("symbol tables"), "{}", error.0);
    }

    struct PeSectionSpec {
        name: &'static str,
        virtual_size: u32,
        virtual_address: u32,
        raw: Vec<u8>,
        characteristics: u32,
    }

    /// An x86-64 PE32+ with no data directories and `sections`, whose raw
    /// data follows the headers in order.
    fn pe64(sections: &[PeSectionSpec]) -> Vec<u8> {
        let optional = 0x58usize;
        let headers_end = optional + 240;
        let mut image = vec![0u8; headers_end + sections.len() * PE_SECTION_HEADER_SIZE];
        image[..2].copy_from_slice(b"MZ");
        image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        image[0x40..0x44].copy_from_slice(b"PE\0\0");
        image[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x46..0x48].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        image[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        image[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        while !image.len().is_multiple_of(0x200) {
            image.push(0);
        }
        for (index, section) in sections.iter().enumerate() {
            let raw_ptr = image.len() as u32;
            image.extend_from_slice(&section.raw);
            let header = headers_end + index * PE_SECTION_HEADER_SIZE;
            let name = section.name.as_bytes();
            image[header..header + name.len()].copy_from_slice(name);
            image[header + 8..header + 12].copy_from_slice(&section.virtual_size.to_le_bytes());
            image[header + 12..header + 16].copy_from_slice(&section.virtual_address.to_le_bytes());
            image[header + 16..header + 20]
                .copy_from_slice(&(section.raw.len() as u32).to_le_bytes());
            image[header + 20..header + 24].copy_from_slice(&raw_ptr.to_le_bytes());
            image[header + 36..header + 40].copy_from_slice(&section.characteristics.to_le_bytes());
        }
        image
    }

    #[test]
    fn pe_virtual_size_is_zero_filled() {
        let image = pe64(&[
            PeSectionSpec {
                name: ".text",
                virtual_size: 0x20,
                virtual_address: 0x1000,
                raw: vec![0xC3; 0x10],
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".bss",
                virtual_size: 0x1_0000,
                virtual_address: 0x2000,
                raw: Vec::new(),
                characteristics: 0xC000_0080,
            },
        ]);
        let parsed = parse_pe(&image, "bss.exe", Arch::X64).expect("valid PE");
        let text = &parsed.regions[0];
        assert_eq!(text.start, 0x1_4000_1000);
        assert_eq!(text.data.len(), 0x20);
        assert_eq!(&text.data[..0x10], &[0xC3; 0x10]);
        assert!(text.data[0x10..].iter().all(|byte| *byte == 0));
        assert_eq!(parsed.regions[1].data.len(), 0x1_0000);
        assert_eq!(parsed.module.size, 0x2000 + 0x1_0000 - 0x1000);
    }

    #[test]
    fn huge_pe_virtual_sizes_are_cut_to_the_budget() {
        let mut sections: Vec<PeSectionSpec> = (0..96u32)
            .map(|index| PeSectionSpec {
                name: ".bss",
                virtual_size: u32::MAX,
                virtual_address: 0x1000 + index * 0x1000,
                raw: Vec::new(),
                characteristics: 0xC000_0080,
            })
            .collect();
        // Raw data is charged to the file budget, so a section after the zero
        // fill ran out keeps its bytes.
        sections.push(PeSectionSpec {
            name: ".text",
            virtual_size: 0x20,
            virtual_address: 0x10_0000,
            raw: vec![0xC3; 0x10],
            characteristics: 0x6000_0020,
        });
        let image = pe64(&sections);
        let parsed = parse_pe_budgeted(&image, "huge.exe", Arch::X64, small_budget())
            .expect("cut, not refused");
        // The first section takes the whole zero fill; the rest get none and
        // are left out, except for `.text`'s file bytes.
        assert_eq!(parsed.regions.len(), 2);
        assert_eq!(parsed.regions[0].data.len(), 0x2_0000);
        assert_eq!(parsed.regions[1].name, ".text");
        assert_eq!(parsed.regions[1].data, vec![0xC3; 0x10]);
        let last_end = 0x1_4000_0000u64 + 0x1000 + 95 * 0x1000 + u64::from(u32::MAX);
        assert_eq!(parsed.module.size, last_end - 0x1_4000_1000);
    }

    #[test]
    fn region_budget_counts_across_sections() {
        let mut budget = RegionBudget {
            file_bytes: 4,
            zero_bytes: 8,
        };
        assert_eq!(budget.padded(&[1, 2], 6).unwrap(), vec![1, 2, 0, 0, 0, 0]);
        // Zero fill past the budget is cut, then none is left.
        assert_eq!(budget.padded(&[], 5).unwrap(), vec![0; 4]);
        assert_eq!(budget.padded(&[], 4).unwrap(), Vec::<u8>::new());
        assert!(budget.padded(&[1, 2, 3], 3).is_err());
        assert_eq!(budget.padded(&[7, 8], 2).unwrap(), vec![7, 8]);
        assert_eq!(budget.padded(&[], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn relr_bitmaps_expand_after_their_place_and_are_capped() {
        let words: Vec<u8> = [0x1000u64, 0b1011, 0x2000, 1 | (1 << 63)]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let mut left = 16;
        // 0x1000, then bits 0 and 2 of the next 63 words; 0x2000, then the
        // last of its 63 words.
        assert_eq!(
            relr_slots(&words, 8, &mut left).unwrap(),
            vec![0x1000, 0x1008, 0x1018, 0x2000, 0x2008 + 8 * 62]
        );
        assert_eq!(left, 11);
        assert!(relr_slots(&words, 8, &mut 4).is_err());
        // A bitmap before any place relocates nothing.
        let leading: Vec<u8> = [3u32, 0x40].iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(relr_slots(&leading, 4, &mut 8).unwrap(), vec![0x40]);
    }

    #[test]
    fn packed_relocation_streams_never_panic_and_stay_bounded() {
        let mut state = 0x9e37_79b9u32;
        for size in [0usize, 3, 4, 5, 9, 64, 4096] {
            for prefix in [&b""[..], b"APS2"] {
                let mut data = prefix.to_vec();
                data.extend((0..size).map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                }));
                for (is64, rela) in [(true, true), (true, false), (false, true), (false, false)] {
                    let entry = match (is64, rela) {
                        (true, true) => 24,
                        (true, false) => 16,
                        (false, true) => 12,
                        (false, false) => 8,
                    };
                    if let Ok(out) = android_relocations(&data, is64, rela, 1000) {
                        assert!(out.len() <= 1000 * entry);
                        assert_eq!(out.len() % entry, 0);
                    }
                }
                let _ = relr_slots(&data, 8, &mut 100_000);
                let _ = relr_slots(&data, 4, &mut 100_000);
            }
        }
        // A huge count is refused, and a group of size 0 consumes its header.
        assert!(android_relocations(b"APS2\xff\xff\x03\x00", true, true, 10).is_err());
        let zero_groups = [b"APS2".to_vec(), vec![2, 0x10], [0u8, 0].repeat(64)].concat();
        assert_eq!(
            android_relocations(&zero_groups, true, true, 10).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn name_budget_matches_cstr_until_spent() {
        let blob = b"abc\0tail";
        for offset in 0..blob.len() + 2 {
            assert_eq!(
                NameBudget::new(64).cstr(blob, offset),
                Some(cstr(blob, offset))
            );
        }
        let mut names = NameBudget::new(5);
        assert_eq!(names.cstr(blob, 0).as_deref(), Some("abc"));
        assert_eq!(names.cstr(blob, 4), None);
        // Spent stays spent: only empty names remain free.
        assert_eq!(names.cstr(blob, 0), None);
        assert_eq!(names.cstr(blob, 3).as_deref(), Some(""));
    }
}
