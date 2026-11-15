//! Read-only live-process byte source for Windows x64 and ARM64 targets.
//!
//! Mirrors `sources/proc_win.py`. The source never writes to, suspends, or
//! injects into the target: it opens the process with
//! `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ` ([`OPEN_ACCESS`]) and
//! uses `ReadProcessMemory` for every byte it returns (AGENTS.md rule 9).
//!
//! [`ByteSource::regions`] deliberately exposes only readable, non-writable
//! module image pages. Those are where anchors live, and materialising them
//! lets the matcher and scanner run unchanged; heap, stack, and writable data
//! stay readable through [`ByteSource::read`] but are not anchor-scanned. Every
//! materialised region is capped, so a hostile or enormous image cannot make
//! generation read unbounded memory (rule 8). Module metadata (exports,
//! imports, `.pdata`) is parsed from the mapped image by the same PE walkers
//! that [`crate::elf::FileSource`] uses.
//!
//! 32-bit (WOW64) processes are detected and rejected, never decoded as x64.
//! On hosts other than 64-bit Windows the module compiles to a stub whose
//! [`ProcessSource::open`] returns [`ProcessError::Unsupported`].

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use crate::arch::Arch;
use crate::elf::{module_stem, parse_pe_headers, pe_metadata, PeImage};
use crate::errors::ReadError;
use crate::source::{ByteSource, Module, Region};
use crate::spec::MAX_READ_BYTES;
use crate::unwind::MAX_UNWIND_ENTRIES;

// Access rights from winnt.h.
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

/// The only rights the source requests: query and read, nothing else.
pub const OPEN_ACCESS: u32 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

/// Rights that could modify, suspend, or inject into a target. None of them
/// may ever be requested or granted to the source's handle.
pub const MUTATING_ACCESS: u32 = PROCESS_TERMINATE
    | PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_WRITE
    | PROCESS_DUP_HANDLE
    | PROCESS_CREATE_PROCESS
    | PROCESS_SET_QUOTA
    | PROCESS_SET_INFORMATION
    | PROCESS_SUSPEND_RESUME
    | PROCESS_SET_LIMITED_INFORMATION
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

const MEM_COMMIT: u32 = 0x1000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;

pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01C2;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

const MAX_REGIONS: usize = 65536;
#[cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]
const MAX_MODULES: usize = 4096;
const MAX_PE_HEADER_BYTES: u64 = 0x1000;
const MAX_PE_NAME: u64 = 512;
const MAX_ANCHOR_REGION_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ANCHOR_BYTES: u64 = 128 * 1024 * 1024;
/// Header and directory pages cached per module while parsing metadata.
const MAX_CACHED_PAGES: usize = 4096;
const MAX_PDATA_BYTES: usize = MAX_UNWIND_ENTRIES * 12;
const PAGE: u64 = 0x1000;

/// Why a process could not be opened as a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessError {
    /// The target or host architecture is not supported (32-bit, WOW64, ...).
    Unsupported(String),
    /// The OS refused or the process could not be enumerated.
    Os(String),
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessError::Unsupported(message) | ProcessError::Os(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Map a PE machine type to a supported [`Arch`].
///
/// 32-bit machines are rejected explicitly, so a WOW64 target is never decoded
/// as x64 (AGENTS.md rule 9).
pub fn arch_for_machine(machine: u16) -> Result<Arch, ProcessError> {
    match machine {
        IMAGE_FILE_MACHINE_AMD64 => Ok(Arch::X64),
        IMAGE_FILE_MACHINE_ARM64 => Ok(Arch::Arm64),
        IMAGE_FILE_MACHINE_I386
        | IMAGE_FILE_MACHINE_ARM
        | IMAGE_FILE_MACHINE_THUMB
        | IMAGE_FILE_MACHINE_ARMNT => Err(ProcessError::Unsupported(format!(
            "32-bit process machine 0x{machine:x} is not supported; WOW64 and 32-bit \
             targets are rejected (AGENTS.md rule 9)"
        ))),
        other => Err(ProcessError::Unsupported(format!(
            "unsupported process machine 0x{other:x}"
        ))),
    }
}

/// One `VirtualQueryEx` result.
#[cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
struct RawRange {
    base: u64,
    size: u64,
    state: u32,
    protect: u32,
}

/// One module from `EnumProcessModulesEx`.
#[cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]
#[derive(Debug, Clone)]
struct RawModule {
    base: u64,
    size: u64,
    path: String,
}

/// A committed, readable range of the target's address space.
#[derive(Debug, Clone, Copy)]
struct MemoryRange {
    start: u64,
    size: u64,
    executable: bool,
    writable: bool,
}

impl MemoryRange {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }
}

/// Read-only view of one live Windows process.
pub struct ProcessSource {
    pid: u32,
    process: os::Process,
    arch: Arch,
    modules: Vec<Module>,
    ranges: Vec<MemoryRange>,
    regions: Vec<Region>,
    unwind: Vec<(u64, u64)>,
}

impl ProcessSource {
    /// Open `pid` read-only and enumerate its architecture, modules, and
    /// readable memory.
    pub fn open(pid: u32) -> Result<ProcessSource, ProcessError> {
        if pid == 0 {
            return Err(ProcessError::Os("invalid process id 0".into()));
        }
        let process = os::Process::open(pid)?;
        // WOW64 is decided before anything else is read from the target.
        let native_machine = reject_wow64(&process)?;
        let listed = process.modules()?;
        let Some(main) = listed.first() else {
            return Err(ProcessError::Os(format!(
                "process {pid} has no enumerable modules"
            )));
        };
        // The main image's machine decides: under ARM64 emulation an x64
        // process reports the native ARM64 machine, but its code is x64.
        let machine = read_headers(&process, main.base, main.size)
            .map(|headers| headers.machine)
            .or(native_machine)
            .ok_or_else(|| {
                ProcessError::Os(format!("cannot read the main image header of {pid}"))
            })?;
        let arch = arch_for_machine(machine)?;

        let mut modules = Vec::new();
        let mut sections: HashMap<u64, Vec<(String, u64, u64)>> = HashMap::new();
        let mut unwind = Vec::new();
        for raw in &listed {
            let (module, module_sections, module_unwind) = build_module(&process, raw);
            sections.insert(module.base, module_sections);
            unwind.extend(module_unwind);
            modules.push(module);
        }
        let main_base = main.base;
        modules.sort_by_key(|module| module.base);

        let ranges = enumerate_ranges(&process);
        let regions = anchor_regions(&process, &ranges, &modules, &sections, main_base);
        let unwind = crate::unwind::finish(unwind, &regions);
        Ok(ProcessSource {
            pid,
            process,
            arch,
            modules,
            ranges,
            regions,
            unwind,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The access mask the OS actually granted to the source's handle, or
    /// `None` when it cannot be queried.
    pub fn granted_access(&self) -> Option<u32> {
        self.process.granted_access()
    }

    fn range_at(&self, addr: u64) -> Option<&MemoryRange> {
        let index = self
            .ranges
            .partition_point(|range| range.start <= addr)
            .checked_sub(1)?;
        let range = &self.ranges[index];
        (addr < range.end()).then_some(range)
    }
}

impl ByteSource for ProcessSource {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, ReadError> {
        if size > MAX_READ_BYTES {
            return Err(ReadError(format!("refusing read of {size} bytes")));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        self.process
            .read_exact(addr, size)
            .ok_or_else(|| ReadError(format!("read of {size} bytes at 0x{addr:x} failed")))
    }

    fn regions(&self) -> &[Region] {
        &self.regions
    }

    fn modules(&self) -> &[Module] {
        &self.modules
    }

    // No `function_starts`: like `FileSource` for PE images, exports name
    // functions but are not offered as hinted starts. The Python source
    // returned every export of every loaded DLL; tens of thousands of starts
    // outrank the backward sweeps from anchor hits in the hinted candidate cap,
    // so a function in an image without exports (the usual main executable)
    // was never reached. `.pdata` entries serve hint-free discovery instead.

    fn unwind_entries(&self) -> &[(u64, u64)] {
        &self.unwind
    }

    /// `.pdata` bounds stand in for symbol bounds. A live process has no
    /// symbols, and without bounds a hinted scan can only reach a function
    /// by backward sweeps from anchor hits, which a common constant spread
    /// over every loaded DLL exhausts before the target's own code. x64
    /// `RUNTIME_FUNCTION` ends are exact; an entry without a known end (ARM64
    /// `.xdata` form) gives no hint. The Python source had no hints at all.
    fn hint_function(&self, addr: u64) -> Option<(u64, u64)> {
        self.unwind_function(addr).filter(|(_, end)| *end != 0)
    }

    /// Bounded contiguous read that stops at an unreadable boundary.
    fn read_partial(&self, addr: u64, size: usize) -> Vec<u8> {
        let mut remaining = size.min(MAX_READ_BYTES);
        let mut cursor = addr;
        let mut out = Vec::new();
        while remaining > 0 {
            let Some(range) = self.range_at(cursor) else {
                break;
            };
            let take = remaining.min((range.end() - cursor) as usize);
            let Some(chunk) = self.process.read_exact(cursor, take) else {
                break;
            };
            out.extend_from_slice(&chunk);
            cursor += take as u64;
            remaining -= take;
        }
        out
    }

    fn is_mapped(&self, addr: u64, size: usize) -> bool {
        let Some(range) = self.range_at(addr) else {
            return false;
        };
        size == 0
            || addr
                .checked_add(size as u64)
                .is_some_and(|end| end <= range.end())
    }

    fn is_executable(&self, addr: u64) -> bool {
        self.range_at(addr).is_some_and(|range| range.executable)
    }
}

// -- enumeration ----------------------------------------------------------------

/// Reject WOW64 targets; return the native machine when the OS reports it.
fn reject_wow64(process: &os::Process) -> Result<Option<u16>, ProcessError> {
    if let Some((process_machine, native_machine)) = process.wow64_machines() {
        if process_machine != IMAGE_FILE_MACHINE_UNKNOWN {
            return Err(match arch_for_machine(process_machine) {
                Err(error) => error,
                Ok(_) => ProcessError::Unsupported(format!(
                    "WOW64 process machine 0x{process_machine:x} is not supported"
                )),
            });
        }
        return Ok(Some(native_machine));
    }
    // Before Windows 10 1709 there is no IsWow64Process2; IsWow64Process only
    // has to catch a 32-bit guest on this 64-bit host.
    if process.is_wow64() == Some(true) {
        return Err(ProcessError::Unsupported(
            "32-bit (WOW64) processes are not supported (AGENTS.md rule 9)".into(),
        ));
    }
    Ok(None)
}

fn read_headers(process: &os::Process, base: u64, size: u64) -> Option<crate::elf::PeHeaders> {
    let header = process.read_exact(base, size.min(MAX_PE_HEADER_BYTES) as usize)?;
    parse_pe_headers(&header).ok()
}

type ModuleParts = (Module, Vec<(String, u64, u64)>, Vec<(u64, u64)>);

fn build_module(process: &os::Process, raw: &RawModule) -> ModuleParts {
    let file_name = raw
        .path
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty());
    // The stem, as `FileSource` names modules, so `--module` and provenance
    // agree between `--file` and `--pid` for the same image.
    let name = file_name
        .map(module_stem)
        .unwrap_or_else(|| format!("module_{:x}", raw.base));
    let mut module = Module {
        name,
        base: raw.base,
        image_base: raw.base,
        size: raw.size,
        path: (!raw.path.is_empty()).then(|| raw.path.clone()),
        ..Module::default()
    };
    let Some(headers) = read_headers(process, raw.base, raw.size) else {
        return (module, Vec::new(), Vec::new());
    };
    let image = MappedPe::new(process, raw.base, raw.size);
    let metadata = pe_metadata(
        &image,
        &headers,
        raw.base,
        headers.machine == IMAGE_FILE_MACHINE_ARM64,
        true,
        MAX_PDATA_BYTES,
    );
    module.exports = metadata.exports;
    module.functions = metadata.functions;
    module.imports = metadata.imports;
    let sections = headers
        .sections
        .iter()
        .map(|section| {
            (
                section.name.clone(),
                section.virtual_address,
                section.span(),
            )
        })
        .collect();
    (module, sections, metadata.unwind)
}

fn enumerate_ranges(process: &os::Process) -> Vec<MemoryRange> {
    let mut ranges = Vec::new();
    let mut address = 0u64;
    for _ in 0..MAX_REGIONS {
        let Some(info) = process.query(address) else {
            break;
        };
        if info.size == 0 {
            break;
        }
        let base_protect = info.protect & 0xFF;
        let readable = matches!(
            base_protect,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        );
        if info.state == MEM_COMMIT && info.protect & PAGE_GUARD == 0 && readable {
            ranges.push(MemoryRange {
                start: info.base,
                size: info.size,
                executable: matches!(
                    base_protect,
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
                ),
                writable: matches!(
                    base_protect,
                    PAGE_READWRITE
                        | PAGE_WRITECOPY
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_EXECUTE_WRITECOPY
                ),
            });
        }
        let Some(following) = info.base.checked_add(info.size) else {
            break;
        };
        if following <= address {
            break;
        }
        address = following;
    }
    ranges.sort_by_key(|range| range.start);
    ranges
}

/// Materialise readable, non-writable module pages within the byte budget.
///
/// The main image is materialised first so a process with many large DLLs
/// cannot spend the budget before the target's own code.
fn anchor_regions(
    process: &os::Process,
    ranges: &[MemoryRange],
    modules: &[Module],
    sections: &HashMap<u64, Vec<(String, u64, u64)>>,
    main_base: u64,
) -> Vec<Region> {
    let module_at = |addr: u64| modules.iter().find(|module| module.contains(addr, 1));
    let mut candidates: Vec<(&MemoryRange, &Module)> = ranges
        .iter()
        .filter(|range| !range.writable)
        .filter_map(|range| module_at(range.start).map(|module| (range, module)))
        .collect();
    candidates.sort_by_key(|(range, module)| (module.base != main_base, range.start));

    let mut regions = Vec::new();
    let mut budget = MAX_ANCHOR_BYTES;
    for (range, module) in candidates {
        if range.size > MAX_ANCHOR_REGION_BYTES || range.size > budget {
            continue;
        }
        let data = read_filled(process, range.start, range.size as usize);
        budget -= data.len() as u64;
        let rva = range.start - module.base;
        let name = sections
            .get(&module.base)
            .and_then(|list| {
                list.iter()
                    .find(|(_, start, span)| *start <= rva && rva < start + span)
                    .map(|(name, _, _)| name.clone())
            })
            .unwrap_or_else(|| format!("{}+0x{rva:x}", module.name));
        regions.push(Region::new(
            name,
            range.start,
            data,
            range.executable,
            range.writable,
        ));
    }
    regions.sort_by_key(|region| region.start);
    regions
}

/// Read a module range, zero-filling pages the target will not share.
fn read_filled(process: &os::Process, addr: u64, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        let take = MAX_READ_BYTES.min(size - offset);
        match process.read_exact(addr + offset as u64, take) {
            Some(chunk) => data[offset..offset + take].copy_from_slice(&chunk),
            None => {
                // Retry page by page so one unreadable page does not blank
                // the whole chunk.
                let mut page = 0usize;
                while page < take {
                    let step = (PAGE as usize).min(take - page);
                    if let Some(chunk) = process.read_exact(addr + (offset + page) as u64, step) {
                        data[offset + page..offset + page + step].copy_from_slice(&chunk);
                    }
                    page += step;
                }
            }
        }
        offset += take;
    }
    data
}

// -- the mapped image as a PeImage ------------------------------------------------

/// A PE image mapped in the target: RVAs are offsets from the module base.
/// Small reads go through a bounded page cache, since the directory walkers
/// read a few bytes at a time.
struct MappedPe<'a> {
    process: &'a os::Process,
    base: u64,
    size: u64,
    pages: RefCell<HashMap<u64, Option<Box<[u8]>>>>,
}

impl<'a> MappedPe<'a> {
    fn new(process: &'a os::Process, base: u64, size: u64) -> MappedPe<'a> {
        MappedPe {
            process,
            base,
            size,
            pages: RefCell::new(HashMap::new()),
        }
    }

    /// Copy `rva..end` page by page; `None` on any unreadable page.
    fn copy(&self, rva: u64, end: u64, out: &mut Vec<u8>) -> Option<()> {
        let mut cursor = rva;
        while cursor < end {
            let page = cursor / PAGE;
            let offset = (cursor % PAGE) as usize;
            let take = ((PAGE - cursor % PAGE).min(end - cursor)) as usize;
            let mut pages = self.pages.borrow_mut();
            if !pages.contains_key(&page) {
                let bytes = self
                    .process
                    .read_exact(self.base + page * PAGE, PAGE as usize)
                    .map(Vec::into_boxed_slice);
                if pages.len() >= MAX_CACHED_PAGES {
                    let bytes = bytes?;
                    out.extend_from_slice(&bytes[offset..offset + take]);
                    cursor += take as u64;
                    continue;
                }
                pages.insert(page, bytes);
            }
            let bytes = pages.get(&page)?.as_ref()?;
            out.extend_from_slice(&bytes[offset..offset + take]);
            cursor += take as u64;
        }
        Some(())
    }
}

impl PeImage for MappedPe<'_> {
    fn bytes(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        if len > MAX_READ_BYTES {
            return None;
        }
        let end = rva.checked_add(len as u64)?;
        if end > self.size {
            return None;
        }
        let mut out = Vec::with_capacity(len);
        self.copy(rva, end, &mut out)?;
        Some(Cow::Owned(out))
    }

    fn span(&self, rva: u64, len: usize) -> Option<Cow<'_, [u8]>> {
        if rva >= self.size {
            return None;
        }
        let end = rva.saturating_add(len as u64).min(self.size);
        let mut out = Vec::new();
        let mut cursor = rva;
        while cursor < end {
            let take = (MAX_READ_BYTES as u64).min(end - cursor) as usize;
            let Some(chunk) = self.process.read_exact(self.base + cursor, take) else {
                break;
            };
            out.extend_from_slice(&chunk);
            cursor += take as u64;
        }
        Some(Cow::Owned(out))
    }

    fn contains(&self, rva: u64) -> bool {
        rva < self.size
    }

    fn cstr(&self, rva: u64) -> String {
        if rva >= self.size {
            return String::new();
        }
        let end = rva.saturating_add(MAX_PE_NAME).min(self.size);
        let mut out = Vec::new();
        let mut cursor = rva;
        // Page by page, so a name near the end of a readable page still reads.
        while cursor < end {
            let stop = ((cursor / PAGE + 1) * PAGE).min(end);
            let before = out.len();
            if self.copy(cursor, stop, &mut out).is_none() {
                break;
            }
            if let Some(nul) = out[before..].iter().position(|byte| *byte == 0) {
                out.truncate(before + nul);
                return String::from_utf8_lossy(&out).into_owned();
            }
            cursor = stop;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

// -- OS layer -----------------------------------------------------------------

#[cfg(all(windows, target_pointer_width = "64"))]
mod os {
    use std::ffi::c_void;

    use super::{ProcessError, RawModule, RawRange, MAX_MODULES, OPEN_ACCESS};

    type Handle = *mut c_void;

    const LIST_MODULES_ALL: u32 = 0x03;
    const OBJECT_BASIC_INFORMATION_CLASS: u32 = 0;

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        partition_id: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    #[repr(C)]
    struct ModuleInfo {
        base_of_dll: *mut c_void,
        size_of_image: u32,
        entry_point: *mut c_void,
    }

    /// `PUBLIC_OBJECT_BASIC_INFORMATION`: 56 bytes; only the access mask is read.
    #[repr(C)]
    struct ObjectBasicInformation {
        attributes: u32,
        granted_access: u32,
        rest: [u32; 12],
    }

    type IsWow64Process2Fn = unsafe extern "system" fn(Handle, *mut u16, *mut u16) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn ReadProcessMemory(
            process: Handle,
            base: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn VirtualQueryEx(
            process: Handle,
            address: *const c_void,
            info: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
        fn GetLastError() -> u32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn IsWow64Process(process: Handle, wow64: *mut i32) -> i32;
        fn K32EnumProcessModulesEx(
            process: Handle,
            modules: *mut *mut c_void,
            bytes: u32,
            needed: *mut u32,
            filter: u32,
        ) -> i32;
        fn K32GetModuleInformation(
            process: Handle,
            module: *mut c_void,
            info: *mut ModuleInfo,
            bytes: u32,
        ) -> i32;
        fn K32GetModuleFileNameExW(
            process: Handle,
            module: *mut c_void,
            name: *mut u16,
            size: u32,
        ) -> u32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryObject(
            handle: Handle,
            class: u32,
            info: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    fn last_error(what: &str) -> ProcessError {
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        ProcessError::Os(format!("{what} failed (Windows error {code})"))
    }

    /// An open, read-only process handle; closed on drop.
    pub struct Process {
        handle: Handle,
    }

    // SAFETY: a process handle is a kernel object reference that Windows
    // lets any thread use; this type only issues query and read calls on it
    // and keeps no other state.
    unsafe impl Send for Process {}
    unsafe impl Sync for Process {}

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenProcess and is closed once.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    impl Process {
        pub fn open(pid: u32) -> Result<Process, ProcessError> {
            // SAFETY: plain FFI call; a null result is handled below.
            let handle = unsafe { OpenProcess(OPEN_ACCESS, 0, pid) };
            if handle.is_null() {
                return Err(last_error(&format!("OpenProcess({pid})")));
            }
            Ok(Process { handle })
        }

        pub fn read_exact(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            if len == 0 {
                return Some(Vec::new());
            }
            let mut buffer = vec![0u8; len];
            let mut read = 0usize;
            // SAFETY: `buffer` holds `len` writable bytes; the target address
            // is only read by the OS on the source's behalf.
            let ok = unsafe {
                ReadProcessMemory(
                    self.handle,
                    addr as usize as *const c_void,
                    buffer.as_mut_ptr().cast(),
                    len,
                    &mut read,
                )
            };
            (ok != 0 && read == len).then_some(buffer)
        }

        pub fn query(&self, addr: u64) -> Option<RawRange> {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid.
            let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is a correctly sized out-parameter.
            let written = unsafe {
                VirtualQueryEx(
                    self.handle,
                    addr as usize as *const c_void,
                    &mut info,
                    std::mem::size_of::<MemoryBasicInformation>(),
                )
            };
            (written != 0).then_some(RawRange {
                base: info.base_address as u64,
                size: info.region_size as u64,
                state: info.state,
                protect: info.protect,
            })
        }

        /// `(process machine, native machine)` from `IsWow64Process2`, when
        /// the host has it. The process machine is 0 for a native process.
        pub fn wow64_machines(&self) -> Option<(u16, u16)> {
            let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
            // SAFETY: both strings are NUL-terminated; kernel32 is always loaded.
            let function = unsafe {
                let module = GetModuleHandleW(kernel32.as_ptr());
                if module.is_null() {
                    return None;
                }
                GetProcAddress(module, c"IsWow64Process2".as_ptr().cast())
            };
            if function.is_null() {
                return None;
            }
            // SAFETY: the exported symbol has this documented signature.
            let function =
                unsafe { std::mem::transmute::<*mut c_void, IsWow64Process2Fn>(function) };
            let mut process_machine = 0u16;
            let mut native_machine = 0u16;
            // SAFETY: both out-parameters are valid u16s.
            let ok = unsafe { function(self.handle, &mut process_machine, &mut native_machine) };
            (ok != 0).then_some((process_machine, native_machine))
        }

        pub fn is_wow64(&self) -> Option<bool> {
            let mut wow64 = 0i32;
            // SAFETY: `wow64` is a valid out-parameter.
            let ok = unsafe { IsWow64Process(self.handle, &mut wow64) };
            (ok != 0).then_some(wow64 != 0)
        }

        /// Loaded modules, the main image first, at most `MAX_MODULES`.
        pub fn modules(&self) -> Result<Vec<RawModule>, ProcessError> {
            let pointer = std::mem::size_of::<*mut c_void>();
            let mut capacity = 1024usize;
            let mut handles: Vec<*mut c_void> = Vec::new();
            for _ in 0..8 {
                let mut array: Vec<*mut c_void> = vec![std::ptr::null_mut(); capacity];
                let mut needed = 0u32;
                // SAFETY: `array` holds `capacity` pointer slots.
                let ok = unsafe {
                    K32EnumProcessModulesEx(
                        self.handle,
                        array.as_mut_ptr(),
                        (capacity * pointer) as u32,
                        &mut needed,
                        LIST_MODULES_ALL,
                    )
                };
                if ok == 0 {
                    return Err(last_error("EnumProcessModulesEx"));
                }
                let listed = needed as usize / pointer;
                let count = listed.min(capacity).min(MAX_MODULES);
                handles = array[..count]
                    .iter()
                    .copied()
                    .filter(|handle| !handle.is_null())
                    .collect();
                if listed <= capacity || count >= MAX_MODULES {
                    break;
                }
                capacity = (listed + 16).min(MAX_MODULES);
            }

            let mut modules = Vec::new();
            for handle in handles {
                // SAFETY: an all-zero MODULEINFO is valid.
                let mut info: ModuleInfo = unsafe { std::mem::zeroed() };
                // SAFETY: `info` is a correctly sized out-parameter.
                let ok = unsafe {
                    K32GetModuleInformation(
                        self.handle,
                        handle,
                        &mut info,
                        std::mem::size_of::<ModuleInfo>() as u32,
                    )
                };
                let base = info.base_of_dll as u64;
                let size = u64::from(info.size_of_image);
                if ok == 0 || base == 0 || size == 0 {
                    continue;
                }
                let mut name = vec![0u16; 1024];
                // SAFETY: `name` holds 1024 UTF-16 units.
                let copied = unsafe {
                    K32GetModuleFileNameExW(self.handle, handle, name.as_mut_ptr(), 1024)
                } as usize;
                let path = String::from_utf16_lossy(&name[..copied.min(name.len())]);
                modules.push(RawModule { base, size, path });
            }
            Ok(modules)
        }

        pub fn granted_access(&self) -> Option<u32> {
            // SAFETY: an all-zero information block is valid.
            let mut info: ObjectBasicInformation = unsafe { std::mem::zeroed() };
            let mut returned = 0u32;
            // SAFETY: `info` is a correctly sized out-parameter.
            let status = unsafe {
                NtQueryObject(
                    self.handle,
                    OBJECT_BASIC_INFORMATION_CLASS,
                    (&mut info as *mut ObjectBasicInformation).cast(),
                    std::mem::size_of::<ObjectBasicInformation>() as u32,
                    &mut returned,
                )
            };
            (status >= 0).then_some(info.granted_access)
        }
    }
}

#[cfg(not(all(windows, target_pointer_width = "64")))]
mod os {
    use super::{ProcessError, RawModule, RawRange};

    /// Stub: live-process access exists only on 64-bit Windows hosts.
    pub struct Process {
        _private: (),
    }

    impl Process {
        pub fn open(_pid: u32) -> Result<Process, ProcessError> {
            Err(ProcessError::Unsupported(
                "live-process sources are not supported on this host; \
                 they need 64-bit Windows"
                    .into(),
            ))
        }

        pub fn read_exact(&self, _addr: u64, _len: usize) -> Option<Vec<u8>> {
            None
        }

        pub fn query(&self, _addr: u64) -> Option<RawRange> {
            None
        }

        pub fn wow64_machines(&self) -> Option<(u16, u16)> {
            None
        }

        pub fn is_wow64(&self) -> Option<bool> {
            None
        }

        pub fn modules(&self) -> Result<Vec<RawModule>, ProcessError> {
            Ok(Vec::new())
        }

        pub fn granted_access(&self) -> Option<u32> {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_for_machine_rejects_32_bit_and_unknown_machines() {
        assert_eq!(arch_for_machine(IMAGE_FILE_MACHINE_AMD64), Ok(Arch::X64));
        assert_eq!(arch_for_machine(IMAGE_FILE_MACHINE_ARM64), Ok(Arch::Arm64));
        for machine in [IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARMNT] {
            let error = arch_for_machine(machine).unwrap_err();
            assert!(matches!(error, ProcessError::Unsupported(_)));
            assert!(error.to_string().contains("32-bit"), "{error}");
        }
        let error = arch_for_machine(0x1234).unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }

    #[test]
    fn open_access_requests_no_mutating_rights() {
        assert_eq!(OPEN_ACCESS & MUTATING_ACCESS, 0);
        assert_eq!(OPEN_ACCESS, 0x1010);
    }

    #[test]
    fn rejects_pid_zero() {
        assert!(ProcessSource::open(0).is_err());
    }
}
