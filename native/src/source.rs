//! The `ByteSource` contract.
//!
//! Everything in the core reaches target bytes through this interface, so the
//! same extractor runs against a live process, an image file, or IDA without
//! knowing which. Sources own all OS- and tool-specific access.

use std::borrow::Cow;
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
        // Saturating: a hostile header can place a region at the top of the
        // address space, and the end is only ever compared against.
        self.start.saturating_add(self.data.len() as u64)
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

    /// An image whose symbols name only exports (`strip --strip-all`, a PE
    /// file, a live process): symbol hints miss every local function, so
    /// front-ends default to hint-free discovery.
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

    /// Whether start synthesis (`starts`) stopped at its sweep budget, so
    /// [`ByteSource::unwind_entries`] may miss functions it would have found.
    /// Reported to the user only; no matcher rule reads it.
    fn start_sweep_truncated(&self) -> bool {
        false
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

/// An image file seen the way [`crate::proc_win::ProcessSource`] sees a
/// loaded module, so the bench can measure the live-process scan path on
/// files with ground truth (`bench --process-like`). A process names no
/// symbol starts, only unwind-table bounds (which a forced `--discovery
/// hinted` scan takes for symbol bounds), so it answers `symbols_stripped()`
/// as the process does; exports, imports, and relocations stay as the
/// module gives them. Scans see it one module at a time ([`ModuleView`]).
pub struct ProcessView<'a, S: ByteSource + ?Sized> {
    inner: &'a S,
    unwind: Vec<(u64, u64)>,
}

impl<'a, S: ByteSource + ?Sized> ProcessView<'a, S> {
    /// View `inner` with `unwind` as its only function table: what the
    /// image's own tables list, without starts a file source synthesized
    /// from code, because a process source reads `.pdata` and synthesizes
    /// nothing.
    pub fn new(inner: &'a S, mut unwind: Vec<(u64, u64)>) -> ProcessView<'a, S> {
        unwind.sort_unstable();
        unwind.dedup_by_key(|(start, _)| *start);
        ProcessView { inner, unwind }
    }
}

impl<S: ByteSource + ?Sized> ByteSource for ProcessView<'_, S> {
    fn arch(&self) -> Arch {
        self.inner.arch()
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        self.inner.read(addr, size)
    }

    fn regions(&self) -> &[Region] {
        self.inner.regions()
    }

    fn modules(&self) -> &[Module] {
        self.inner.modules()
    }

    fn symbols_stripped(&self) -> bool {
        true
    }

    fn unwind_entries(&self) -> &[(u64, u64)] {
        &self.unwind
    }

    /// As `ProcessSource::hint_function`: an entry without a known end gives
    /// no hint.
    fn hint_function(&self, addr: u64) -> Option<(u64, u64)> {
        self.unwind_function(addr).filter(|(_, end)| *end != 0)
    }

    fn is_thumb(&self, addr: u64) -> bool {
        self.inner.is_thumb(addr)
    }
}

/// One module of a source, seen as a stripped image of its own: only the
/// regions that start inside the module, only its [`Module`], only its
/// unwind entries, no symbol starts or bounds, and reads confined to the
/// module's span.
///
/// A live process maps many modules into one address space, while every
/// whole-image rule assumes one image: feature frequencies and the trust
/// gates count one image's functions, a rival is another function of the
/// same image, and joint resolution maps one module's call graph
/// (`matcher::scan_in`, `joint::resolve`). Scanning each module through its
/// own view gives a process the hint-free path a stripped file of the same
/// module gets (`scanner::scan_modules`). The view also hides everything
/// hint-free discovery may not read (AGENTS.md rule 10): what is left is the
/// module's code and data, its unwind table, its exports and imports, and
/// its relocations, as the inner source gives them.
pub struct ModuleView<'a, S: ByteSource + ?Sized> {
    inner: &'a S,
    module: &'a Module,
    regions: Cow<'a, [Region]>,
    unwind: &'a [(u64, u64)],
}

impl<'a, S: ByteSource + ?Sized> ModuleView<'a, S> {
    pub fn new(inner: &'a S, module: &'a Module) -> ModuleView<'a, S> {
        let all = inner.regions();
        let inside = |region: &Region| module.contains(region.start, 1);
        // Sources keep regions sorted by start, so one module's regions are
        // one run of the list and are borrowed; any other order is copied
        // and sorted, as `regions` users expect.
        let regions = match all.iter().position(inside) {
            None => Cow::Borrowed(&all[..0]),
            Some(first) => {
                let count = all[first..].iter().take_while(|r| inside(r)).count();
                if all[first + count..].iter().any(inside) {
                    let mut owned: Vec<Region> =
                        all.iter().filter(|r| inside(r)).cloned().collect();
                    owned.sort_by_key(|region| region.start);
                    Cow::Owned(owned)
                } else {
                    Cow::Borrowed(&all[first..first + count])
                }
            }
        };
        // `unwind_entries` is sorted by start (its contract).
        let entries = inner.unwind_entries();
        let end = module.base.saturating_add(module.size);
        let low = entries.partition_point(|(start, _)| *start < module.base);
        let high = entries.partition_point(|(start, _)| *start < end).max(low);
        ModuleView {
            inner,
            module,
            regions,
            unwind: &entries[low..high],
        }
    }

    pub fn module(&self) -> &'a Module {
        self.module
    }
}

impl<S: ByteSource + ?Sized> ByteSource for ModuleView<'_, S> {
    fn arch(&self) -> Arch {
        self.inner.arch()
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        if size > 0 && !self.module.contains(addr, size) {
            return Err(ReadError(format!(
                "read of {size} bytes at 0x{addr:x} is outside module {}",
                self.module.name
            )));
        }
        self.inner.read(addr, size)
    }

    fn regions(&self) -> &[Region] {
        &self.regions
    }

    fn modules(&self) -> &[Module] {
        std::slice::from_ref(self.module)
    }

    fn symbols_stripped(&self) -> bool {
        true
    }

    fn unwind_entries(&self) -> &[(u64, u64)] {
        self.unwind
    }

    fn start_sweep_truncated(&self) -> bool {
        self.inner.start_sweep_truncated()
    }

    fn is_thumb(&self, addr: u64) -> bool {
        self.inner.is_thumb(addr)
    }

    fn read_partial(&self, addr: u64, size: usize) -> Vec<u8> {
        if !self.module.contains(addr, 1) {
            return Vec::new();
        }
        let room = self.module.base.saturating_add(self.module.size) - addr;
        let size = size.min(usize::try_from(room).unwrap_or(usize::MAX));
        self.inner.read_partial(addr, size)
    }

    fn is_mapped(&self, addr: u64, size: usize) -> bool {
        self.module.contains(addr, size) && self.inner.is_mapped(addr, size)
    }

    fn is_executable(&self, addr: u64) -> bool {
        self.module.contains(addr, 1) && self.inner.is_executable(addr)
    }
}
