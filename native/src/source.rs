//! The `ByteSource` contract.
//!
//! Everything in the core reaches target bytes through this interface, so the
//! same extractor runs against a live process, an image file, or IDA without
//! knowing which. Sources own all OS- and tool-specific access.

use std::collections::HashMap;

use crate::arch::Arch;
use crate::errors::ReadError;
use crate::spec::MAX_READ_BYTES;

/// A contiguous mapped range with bytes attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub name: String,
    pub start: u64,
    pub data: Vec<u8>,
    pub executable: bool,
    pub writable: bool,
}

impl Region {
    pub fn new(
        name: impl Into<String>,
        start: u64,
        data: Vec<u8>,
        executable: bool,
        writable: bool,
    ) -> Region {
        Region {
            name: name.into(),
            start,
            data,
            executable,
            writable,
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn end(&self) -> u64 {
        self.start + self.data.len() as u64
    }

    pub fn contains(&self, addr: u64, length: usize) -> bool {
        if length == 0 {
            return self.start <= addr && addr < self.end();
        }
        self.start <= addr
            && addr
                .checked_add(length as u64)
                .is_some_and(|end| end <= self.end())
    }

    pub fn read(&self, addr: u64, size: usize) -> Result<&[u8], ReadError> {
        if !self.contains(addr, size) {
            return Err(ReadError(format!(
                "read of {size} bytes at 0x{addr:x} is outside {}",
                self.name
            )));
        }
        let begin = (addr - self.start) as usize;
        Ok(&self.data[begin..begin + size])
    }
}

/// A loaded image and the names that can be resolved inside it.
#[derive(Debug, Clone, Default)]
pub struct Module {
    pub name: String,
    /// Lowest mapped address; with `size`, the range rule 4 treats as
    /// addresses when `relocations` is `None` (SPEC.md §2.2).
    pub base: u64,
    /// What `rva` is relative to: the lowest `PT_LOAD` address or PE
    /// `ImageBase`. It can sit below `base` (a shared object's base is 0),
    /// so it must never widen the pointer range.
    pub image_base: u64,
    pub size: u64,
    pub path: Option<String>,
    /// `name -> address` for exported/dynamic symbols, in insertion order.
    pub exports: Vec<(String, u64)>,
    /// `address -> name` for defined function symbols.
    pub functions: HashMap<u64, String>,
    /// `address -> "module!symbol"` for import thunks and IAT/GOT slots.
    pub imports: HashMap<u64, String>,
    /// Sorted addresses of every word a load-time relocation writes, for an
    /// image that can be loaded anywhere (an ELF shared object or PIE).
    /// `None` for an image whose relocations were not read (ELF `ET_EXEC`,
    /// relocatable objects, PE, memory fixtures): there every in-range value
    /// is taken as an address.
    pub relocations: Option<Vec<u64>>,
}

impl Module {
    pub fn end(&self) -> u64 {
        self.base + self.size
    }

    pub fn contains(&self, addr: u64, length: usize) -> bool {
        if length == 0 {
            return self.base <= addr && addr < self.end();
        }
        self.base <= addr
            && addr
                .checked_add(length as u64)
                .is_some_and(|end| end <= self.end())
    }

    /// `Some(true)` when a relocation writes inside `[addr, addr + length)`,
    /// `None` when the image's relocations are unknown (see `relocations`).
    pub fn relocated(&self, addr: u64, length: usize) -> Option<bool> {
        let slots = self.relocations.as_ref()?;
        let first = slots.partition_point(|slot| *slot < addr);
        Some(
            slots
                .get(first)
                .is_some_and(|slot| *slot < addr.saturating_add(length as u64)),
        )
    }

    pub fn rva(&self, addr: u64) -> u64 {
        addr.wrapping_sub(self.image_base)
    }

    /// Return the symbol name defined exactly at `addr`, if any.
    pub fn name_at(&self, addr: u64) -> Option<&str> {
        if let Some(name) = self.imports.get(&addr) {
            return Some(name);
        }
        if let Some(name) = self.functions.get(&addr) {
            return Some(name);
        }
        self.exports
            .iter()
            .find(|(_, value)| *value == addr)
            .map(|(name, _)| name.as_str())
    }
}

/// Read-only view of the bytes and metadata of one target image.
///
/// `Sync` so one image's whole-image indexes and many signatures can be
/// worked on from several threads at once.
pub trait ByteSource: Sync {
    fn arch(&self) -> Arch;

    /// Read `size` bytes at `addr` or return a [`ReadError`].
    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError>;

    fn regions(&self) -> &[Region];

    fn modules(&self) -> &[Module];

    /// Optional known function bounds `(start, end)` from the front-end.
    fn hint_function(&self, _addr: u64) -> Option<(u64, u64)> {
        None
    }

    /// Optional known function entry points.
    fn function_starts(&self) -> Vec<u64> {
        Vec::new()
    }

    /// An image file whose symbols name only exports (`strip --strip-all`,
    /// or a PE file): symbol hints miss every local function, so front-ends
    /// default to hint-free discovery. Live processes answer `false`: their
    /// `.pdata` bounds already serve as hints.
    fn symbols_stripped(&self) -> bool {
        false
    }

    /// ARM32 family: whether `addr` decodes as Thumb (default: ARM mode).
    /// Function entries from the image's unwind tables (`.eh_frame`,
    /// `.ARM.exidx`, `.pdata`), sorted by start. These survive stripping and
    /// are not symbol hints, so hint-free discovery may use them.
    fn unwind_entries(&self) -> &[(u64, u64)] {
        &[]
    }

    /// The unwind entry whose function contains `addr`: the greatest start at
    /// or before it, when the entry's end (if known) is past `addr`.
    fn unwind_function(&self, addr: u64) -> Option<(u64, u64)> {
        let entries = self.unwind_entries();
        let index = entries
            .partition_point(|(start, _)| *start <= addr)
            .checked_sub(1)?;
        let (start, end) = entries[index];
        (end == 0 || addr < end).then_some((start, end))
    }

    fn is_thumb(&self, _addr: u64) -> bool {
        self.arch() == Arch::Thumb
    }

    fn try_read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        self.read(addr, size).ok()
    }

    /// Read up to `size` contiguous bytes, stopping at an unmapped edge.
    fn read_partial(&self, addr: u64, size: usize) -> Vec<u8> {
        let mut remaining = size.min(MAX_READ_BYTES);
        let mut cursor = addr;
        let mut out = Vec::new();
        while remaining > 0 {
            let Some(region) = self.region_for(cursor) else {
                break;
            };
            let take = remaining.min((region.end() - cursor) as usize);
            match region.read(cursor, take) {
                Ok(bytes) => out.extend_from_slice(bytes),
                Err(_) => break,
            }
            cursor += take as u64;
            remaining -= take;
        }
        out
    }

    fn region_for(&self, addr: u64) -> Option<&Region> {
        self.regions()
            .iter()
            .find(|region| region.contains(addr, 1))
    }

    fn module_for(&self, addr: u64) -> Option<&Module> {
        self.modules()
            .iter()
            .find(|module| module.contains(addr, 1))
    }

    fn is_mapped(&self, addr: u64, size: usize) -> bool {
        if size == 0 {
            return self.region_for(addr).is_some();
        }
        self.regions()
            .iter()
            .any(|region| region.contains(addr, size))
    }

    fn is_executable(&self, addr: u64) -> bool {
        self.region_for(addr)
            .is_some_and(|region| region.executable)
    }

    /// Resolve a symbol defined at `addr` across all modules.
    fn name_for_address(&self, addr: u64) -> Option<String> {
        for module in self.modules() {
            if module.contains(addr, 1) {
                if let Some(name) = module.name_at(addr) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// Symbol name, else `module+rva`; `None` if the address is unmapped.
    ///
    /// Unmapped addresses return `None` rather than the raw address so that
    /// ASLR does not leak into signatures.
    fn label_for_address(&self, addr: u64) -> Option<String> {
        if let Some(name) = self.name_for_address(addr) {
            return Some(name);
        }
        let module = self.module_for(addr)?;
        Some(format!("{}+0x{:x}", module.name, module.rva(addr)))
    }
}

/// A `ByteSource` over explicit regions, used by tests and live sources.
#[derive(Debug, Clone)]
pub struct MemorySource {
    arch: Arch,
    regions: Vec<Region>,
    modules: Vec<Module>,
    hints: Vec<(u64, u64)>,
    thumb_ranges: Vec<(u64, u64)>,
}

impl MemorySource {
    pub fn new(
        arch: Arch,
        mut regions: Vec<Region>,
        mut modules: Vec<Module>,
        mut hints: Vec<(u64, u64)>,
        mut thumb_ranges: Vec<(u64, u64)>,
    ) -> MemorySource {
        regions.sort_by_key(|region| region.start);
        modules.sort_by_key(|module| module.base);
        hints.sort();
        thumb_ranges.sort();
        MemorySource {
            arch,
            regions,
            modules,
            hints,
            thumb_ranges,
        }
    }

    pub fn simple(arch: Arch, regions: Vec<Region>) -> MemorySource {
        MemorySource::new(arch, regions, Vec::new(), Vec::new(), Vec::new())
    }
}

impl ByteSource for MemorySource {
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
        &self.modules
    }

    fn function_starts(&self) -> Vec<u64> {
        let mut starts: Vec<u64> = self.hints.iter().map(|(start, _)| *start).collect();
        for module in &self.modules {
            starts.extend(module.functions.keys().copied());
            starts.extend(module.exports.iter().map(|(_, value)| *value));
        }
        starts.sort_unstable();
        starts.dedup();
        starts
    }

    fn hint_function(&self, addr: u64) -> Option<(u64, u64)> {
        if self.hints.is_empty() {
            return None;
        }
        // bisect_right(starts, addr) - 1: the last hint whose start <= addr.
        let index = self
            .hints
            .partition_point(|(start, _)| *start <= addr)
            .checked_sub(1)?;
        let (start, end) = self.hints[index];
        if start <= addr && addr < end {
            Some((start, end))
        } else {
            None
        }
    }

    fn is_thumb(&self, addr: u64) -> bool {
        if !self.thumb_ranges.is_empty() {
            return self
                .thumb_ranges
                .iter()
                .any(|(low, high)| *low <= addr && addr < *high);
        }
        self.arch == Arch::Thumb
    }
}

/// Read across a sorted region list; used by [`MemorySource`] and test sources.
pub fn read_regions(regions: &[Region], addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
    if size > MAX_READ_BYTES {
        return Err(ReadError(format!("refusing read of {size} bytes")));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(size);
    let mut cursor = addr;
    let mut remaining = size;
    for region in regions {
        if remaining == 0 {
            break;
        }
        if !region.contains(cursor, 1) {
            continue;
        }
        let take = remaining.min((region.end() - cursor) as usize);
        out.extend_from_slice(region.read(cursor, take)?);
        cursor += take as u64;
        remaining -= take;
    }
    if remaining != 0 {
        return Err(ReadError(format!(
            "read of {size} bytes at 0x{addr:x} crosses unmapped memory"
        )));
    }
    Ok(out)
}
