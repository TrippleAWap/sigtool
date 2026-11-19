//! Deterministic hostile-input robustness (AGENTS.md rule 8, PLAN.md G6).
//!
//! Minimal but well-formed ELF64 (x86-64, AArch64), ELF32 ARM, and PE32+
//! (x86-64, ARM64) images, a signature document, and a signature database
//! are built here, then every recorded header field is set to edge values
//! (0, small, the file length, `u32::MAX`, `u64::MAX`, ...) one at a time,
//! fields and bytes are corrupted at random from a fixed seed, and the inputs
//! are truncated. Each case goes through the same drivers as the cargo-fuzz
//! targets (`tests/hostile/mod.rs`) and must return without panicking; any
//! error is an acceptable answer. Executable sections of the golden vectors
//! (real clang + lld output) seed the raw-code driver.
//!
//! The start-synthesis, unwind, and ARM mode-map unit tests already feed
//! random bytes to those modules directly; this test reaches them through the
//! image parser and covers the parsers and recovery on top.
//!
//! `SIGTOOL_FUZZ_SEEDS=DIR` makes `write_fuzz_seeds` write the unmutated
//! inputs to `DIR/<target>/` as starting corpora for the fuzz targets (CI).

mod hostile;

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use sigtool_native::arch::Arch;
use sigtool_native::db::{DbView, SignatureDb};
use sigtool_native::elf::FileSource;
use sigtool_native::features::{self, FeatureKind};
use sigtool_native::recover::recover;
use sigtool_native::sigfile::{SampleProvenance, Signature, SignatureFeature};
use sigtool_native::source::ByteSource;

// -- deterministic randomness --------------------------------------------------

/// xorshift64: fixed seeds, so every run sees the same cases.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| self.next_u64() as u8).collect()
    }
}

// -- case runner ---------------------------------------------------------------

/// Runs cases and collects the labels of those that panicked, so one bad
/// field does not hide the others.
struct Cases {
    count: usize,
    failures: Vec<String>,
}

impl Cases {
    fn new() -> Cases {
        Cases {
            count: 0,
            failures: Vec::new(),
        }
    }

    fn run(&mut self, label: &dyn Fn() -> String, driver: fn(&[u8]), data: &[u8]) {
        self.count += 1;
        if catch_unwind(AssertUnwindSafe(|| driver(data))).is_err() {
            self.failures.push(label());
        }
    }

    fn finish(self, what: &str) {
        assert!(self.count > 0, "{what}: no cases ran");
        assert!(
            self.failures.is_empty(),
            "{what}: {} of {} hostile inputs panicked:\n  {}",
            self.failures.len(),
            self.count,
            self.failures
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }
}

/// Allocation-field values above this are announced before the case runs.
const ALLOC_ANNOUNCE: u64 = 0x10_0000;

/// Names a case outside the harness's output capture. An allocation-size
/// case that the library does not bound aborts the process instead of
/// panicking, which loses captured output; this line survives it.
fn announce(label: &str) {
    let _ = writeln!(std::io::stderr(), "hostile_inputs: allocation case {label}");
}

// -- image builders --------------------------------------------------------------

/// A header or table field the mutators target.
#[derive(Debug, Clone)]
struct Field {
    name: String,
    offset: usize,
    width: usize,
    /// The library allocates (or zero-fills) this many bytes from the field
    /// (ELF `SHT_NOBITS` size; PE `VirtualSize` and `SizeOfRawData`, since a
    /// section payload is sized to the larger of the two).
    alloc: bool,
}

#[derive(Default)]
struct Builder {
    bytes: Vec<u8>,
    fields: Vec<Field>,
}

impl Builder {
    fn align(&mut self, alignment: usize) {
        while !self.bytes.len().is_multiple_of(alignment) {
            self.bytes.push(0);
        }
    }

    fn write(&mut self, offset: usize, width: usize, value: u64) {
        if self.bytes.len() < offset + width {
            self.bytes.resize(offset + width, 0);
        }
        self.bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    /// Write `value` and record the field for mutation.
    fn set(&mut self, name: impl Into<String>, offset: usize, width: usize, value: u64) {
        self.write(offset, width, value);
        self.fields.push(Field {
            name: name.into(),
            offset,
            width,
            alloc: false,
        });
    }

    fn raw(&mut self, offset: usize, data: &[u8]) {
        if self.bytes.len() < offset + data.len() {
            self.bytes.resize(offset + data.len(), 0);
        }
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }
}

struct Image {
    name: String,
    bytes: Vec<u8>,
    fields: Vec<Field>,
    /// `fn_a`'s address in the parsed image, for the builder sanity check.
    fn_a: u64,
    /// ELF: `(name, addr, size)` per section, for [`sectionless`].
    layout: Vec<(&'static str, u64, u64)>,
}

/// Two functions per architecture: `fn_a` (frame, a 0x12345678 constant,
/// a call to `fn_b`; x86-64 also loads a string) at 0, `fn_b` at 32, and a
/// padding tail to 48 bytes. Returns the bytes and `fn_a`'s length.
fn code_bytes(arch: Arch) -> (Vec<u8>, u64) {
    match arch {
        Arch::X64 => {
            let mut code = vec![
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp, rsp
                0x48, 0x8d, 0x3d, 0, 0, 0, 0, // lea rdi, [rip+disp32] (patched)
                0xb8, 0x78, 0x56, 0x34, 0x12, // mov eax, 0x12345678
                0xe8, 0x0b, 0, 0, 0,    // call fn_b
                0x5d, // pop rbp
                0xc3, // ret
            ];
            code.resize(32, 0xcc);
            code.extend([0x31, 0xc0, 0xc3]); // fn_b: xor eax, eax; ret
            code.resize(48, 0xcc);
            (code, 23)
        }
        Arch::Arm64 => {
            let words: [u32; 12] = [
                0xa9bf_7bfd, // stp x29, x30, [sp, #-16]!
                0x9100_03fd, // mov x29, sp
                0x528a_cf00, // movz w0, #0x5678
                0x72a2_4680, // movk w0, #0x1234, lsl #16
                0x9400_0004, // bl fn_b
                0xa8c1_7bfd, // ldp x29, x30, [sp], #16
                0xd65f_03c0, // ret
                0xd503_201f, // nop
                0x5280_0000, // fn_b: mov w0, #0
                0xd65f_03c0, // ret
                0xd503_201f, // nop
                0xd503_201f, // nop
            ];
            (
                words.iter().flat_map(|word| word.to_le_bytes()).collect(),
                28,
            )
        }
        Arch::Arm32 | Arch::Thumb => {
            let words: [u32; 12] = [
                0xe92d_4800, // push {r11, lr}
                0xe305_0678, // movw r0, #0x5678
                0xe341_0234, // movt r0, #0x1234
                0xeb00_0003, // bl fn_b
                0xe8bd_8800, // pop {r11, pc}
                0xe320_f000, // nop
                0xe320_f000, // nop
                0xe320_f000, // nop
                0xe3a0_0000, // fn_b: mov r0, #0
                0xe12f_ff1e, // bx lr
                0xe320_f000, // nop
                0xe320_f000, // nop
            ];
            (
                words.iter().flat_map(|word| word.to_le_bytes()).collect(),
                20,
            )
        }
    }
}

const ELF_VBASE: u64 = 0x1_0000;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

/// How the builder stores the dynamic relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packing {
    None,
    Relr,
    Android,
}

struct ElfSection {
    name: &'static str,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

/// A linked shared object (`ET_DYN`) shaped like lld output after
/// `strip --strip-all`: `.text`, `.rodata`, an unwind table, `.data` with one
/// relocated function pointer, `.dynsym`/`.dynstr`, the relative relocation,
/// `.bss`, and `.shstrtab`. With [`Packing::Relr`], `.data` holds a second
/// pointer and both are relocated by `.relr.dyn` (`-z pack-relative-relocs`):
/// one place entry and one bitmap entry. With [`Packing::Android`], the one
/// relocation is an `APS2` stream (`--pack-dyn-relocs=android`).
fn elf_image(arch: Arch, packing: Packing) -> Image {
    let relr = packing == Packing::Relr;
    let is64 = arch != Arch::Arm32;
    let (ehsize, phentsize, shentsize) = if is64 { (64, 56, 64) } else { (52, 32, 40) };
    let pointer = if is64 { 8 } else { 4 };
    let machine: u64 = match arch {
        Arch::X64 => 0x3e,
        Arch::Arm64 => 0xb7,
        _ => 0x28,
    };
    let mut b = Builder::default();
    b.bytes.resize(ehsize + phentsize, 0);
    let mut sections: Vec<ElfSection> = vec![ElfSection {
        name: "",
        kind: 0,
        flags: 0,
        addr: 0,
        offset: 0,
        size: 0,
        link: 0,
        info: 0,
        entsize: 0,
    }];
    let place = |b: &mut Builder, data: &[u8]| -> u64 {
        b.align(16);
        let offset = b.bytes.len();
        b.bytes.extend_from_slice(data);
        offset as u64
    };

    let (code, fn_a_size) = code_bytes(arch);
    let text_offset = place(&mut b, &code);
    let text_addr = ELF_VBASE + text_offset;
    let fn_a = text_addr;
    let fn_b = text_addr + 32;
    sections.push(ElfSection {
        name: ".text",
        kind: 1,
        flags: SHF_ALLOC | SHF_EXECINSTR,
        addr: text_addr,
        offset: text_offset,
        size: code.len() as u64,
        link: 0,
        info: 0,
        entsize: 0,
    });

    let literal = b"hostile input literal\0";
    let rodata_offset = place(&mut b, literal);
    let rodata_addr = ELF_VBASE + rodata_offset;
    sections.push(ElfSection {
        name: ".rodata",
        kind: 1,
        flags: SHF_ALLOC,
        addr: rodata_addr,
        offset: rodata_offset,
        size: literal.len() as u64,
        link: 0,
        info: 0,
        entsize: 0,
    });
    if arch == Arch::X64 {
        // lea rdi, [rip+disp32] ends at code offset 11.
        let disp = rodata_addr.wrapping_sub(text_addr + 11) as u32;
        b.write(text_offset as usize + 7, 4, u64::from(disp));
    }

    // Unwind table: `.eh_frame` (one CIE, one FDE per function) for the
    // 64-bit targets, `.ARM.exidx` (EXIDX_CANTUNWIND entries) for ARM32.
    b.align(16);
    let unwind_offset = b.bytes.len();
    let unwind_addr = ELF_VBASE + unwind_offset as u64;
    if is64 {
        let at = unwind_offset;
        b.set("eh_frame.cie.length", at, 4, 16);
        b.write(at + 4, 4, 0); // CIE id
        b.raw(at + 8, &[1, b'z', b'R', 0, 1, 0x78]);
        let return_register = if arch == Arch::X64 { 16 } else { 30 };
        b.raw(at + 14, &[return_register, 1, 0x1b, 0, 0, 0]);
        for (index, (start, size)) in [(fn_a, fn_a_size), (fn_b, 3)].iter().enumerate() {
            let fde = at + 20 + index * 20;
            let fde_addr = ELF_VBASE + fde as u64;
            b.set(format!("eh_frame.fde{index}.length"), fde, 4, 16);
            b.set(
                format!("eh_frame.fde{index}.cie_pointer"),
                fde + 4,
                4,
                (fde + 4 - at) as u64,
            );
            b.set(
                format!("eh_frame.fde{index}.pc_begin"),
                fde + 8,
                4,
                u64::from(start.wrapping_sub(fde_addr + 8) as u32),
            );
            b.set(format!("eh_frame.fde{index}.pc_range"), fde + 12, 4, *size);
            b.write(fde + 16, 4, 0); // augmentation length, padding
        }
        b.write(at + 60, 4, 0); // terminator
    } else {
        for (index, start) in [fn_a, fn_b].iter().enumerate() {
            let entry = unwind_offset + index * 8;
            let place_addr = ELF_VBASE + entry as u64;
            let prel31 = (start.wrapping_sub(place_addr) as u32) & 0x7fff_ffff;
            b.set(format!("exidx{index}.offset"), entry, 4, u64::from(prel31));
            b.set(format!("exidx{index}.handler"), entry + 4, 4, 1);
        }
    }
    let unwind_size = (b.bytes.len() - unwind_offset) as u64;
    sections.push(ElfSection {
        name: if is64 { ".eh_frame" } else { ".ARM.exidx" },
        kind: if is64 { 1 } else { 0x7000_0001 },
        flags: SHF_ALLOC,
        addr: unwind_addr,
        offset: unwind_offset as u64,
        size: unwind_size,
        link: 1,
        info: 0,
        entsize: 0,
    });

    // `.data`: one function pointer (two with `relr`), written by a relative
    // relocation.
    b.align(16);
    let data_offset = b.bytes.len();
    let slot = ELF_VBASE + data_offset as u64;
    b.set("data.pointer", data_offset, pointer, fn_a);
    if relr {
        b.set("data.pointer2", data_offset + pointer, pointer, fn_b);
    }
    sections.push(ElfSection {
        name: ".data",
        kind: 1,
        flags: SHF_ALLOC | SHF_WRITE,
        addr: slot,
        offset: data_offset as u64,
        size: (pointer * if relr { 2 } else { 1 }) as u64,
        link: 0,
        info: 0,
        entsize: 0,
    });

    // `.dynsym` (index 5) and `.dynstr` (index 6).
    let dynstr = b"\0fn_a\0fn_b\0";
    let sym_size = if is64 { 24 } else { 16 };
    b.align(16);
    let dynsym_offset = b.bytes.len();
    b.bytes.resize(dynsym_offset + 3 * sym_size, 0);
    for (index, (name, value, size)) in [(1u64, fn_a, fn_a_size), (6, fn_b, 3)].iter().enumerate() {
        let at = dynsym_offset + (index + 1) * sym_size;
        let label = format!("dynsym{}", index + 1);
        b.set(format!("{label}.name"), at, 4, *name);
        if is64 {
            b.set(format!("{label}.info"), at + 4, 1, 0x12);
            b.set(format!("{label}.shndx"), at + 6, 2, 1);
            b.set(format!("{label}.value"), at + 8, 8, *value);
            b.set(format!("{label}.size"), at + 16, 8, *size);
        } else {
            b.set(format!("{label}.value"), at + 4, 4, *value);
            b.set(format!("{label}.size"), at + 8, 4, *size);
            b.set(format!("{label}.info"), at + 12, 1, 0x12);
            b.set(format!("{label}.shndx"), at + 14, 2, 1);
        }
    }
    sections.push(ElfSection {
        name: ".dynsym",
        kind: 11,
        flags: SHF_ALLOC,
        addr: ELF_VBASE + dynsym_offset as u64,
        offset: dynsym_offset as u64,
        size: (3 * sym_size) as u64,
        link: 6,
        info: 1,
        entsize: sym_size as u64,
    });
    let dynstr_offset = place(&mut b, dynstr);
    sections.push(ElfSection {
        name: ".dynstr",
        kind: 3,
        flags: SHF_ALLOC,
        addr: ELF_VBASE + dynstr_offset,
        offset: dynstr_offset,
        size: dynstr.len() as u64,
        link: 0,
        info: 0,
        entsize: 0,
    });

    // `.rela.dyn` (RELA, 64-bit) or `.rel.dyn` (REL, ARM32): `*RELATIVE`;
    // with `relr`, `.relr.dyn`: the slot, then a bitmap naming the next word.
    b.align(16);
    let rel_offset = b.bytes.len();
    let rel_size = if relr {
        b.set("relr.place", rel_offset, pointer, slot);
        b.set("relr.bitmap", rel_offset + pointer, pointer, 0b11);
        2 * pointer as u64
    } else if packing == Packing::Android {
        // Count, first offset, then one group sharing offset delta, info,
        // and (RELA) addend: flags 1 | 2 (| 4 | 8). Each value is a 5-byte
        // SLEB128 so the fields have fixed places.
        let relative = match arch {
            Arch::X64 => 8,
            Arch::Arm64 => 1027,
            _ => 23,
        };
        let mut values = vec![
            ("aps2.count", 1),
            ("aps2.offset", 0),
            ("aps2.group_size", 1),
            ("aps2.group_flags", if is64 { 15 } else { 3 }),
            ("aps2.offset_delta", slot),
            ("aps2.info", relative),
        ];
        if is64 {
            values.push(("aps2.addend", fn_a));
        }
        b.raw(rel_offset, b"APS2");
        for (index, (name, value)) in values.iter().enumerate() {
            let at = rel_offset + 4 + 5 * index;
            let mut encoded = 0u64;
            for byte in 0..5 {
                let septet = (value >> (7 * byte)) & 0x7f;
                let more = if byte < 4 { 0x80 } else { 0 };
                encoded |= (septet | more) << (8 * byte);
            }
            b.set(*name, at, 5, encoded);
        }
        (4 + 5 * values.len()) as u64
    } else if is64 {
        let relative = if arch == Arch::X64 { 8 } else { 1027 };
        b.set("rela.offset", rel_offset, 8, slot);
        b.set("rela.info", rel_offset + 8, 8, relative);
        b.set("rela.addend", rel_offset + 16, 8, fn_a);
        24
    } else {
        b.set("rel.offset", rel_offset, 4, slot);
        b.set("rel.info", rel_offset + 4, 4, 23);
        8
    };
    sections.push(ElfSection {
        name: match (packing, is64) {
            (Packing::Relr, _) => ".relr.dyn",
            (Packing::Android, true) => ".android.rela.dyn",
            (Packing::Android, false) => ".android.rel.dyn",
            (Packing::None, true) => ".rela.dyn",
            (Packing::None, false) => ".rel.dyn",
        },
        kind: match (packing, is64) {
            (Packing::Relr, _) => 19,
            (Packing::Android, true) => 0x6000_0002,
            (Packing::Android, false) => 0x6000_0001,
            (Packing::None, true) => 4,
            (Packing::None, false) => 9,
        },
        flags: SHF_ALLOC,
        addr: ELF_VBASE + rel_offset as u64,
        offset: rel_offset as u64,
        size: rel_size,
        link: if relr { 0 } else { 5 },
        info: 0,
        entsize: if relr { pointer as u64 } else { rel_size },
    });

    // `.bss`: no file bytes.
    b.align(16);
    let bss_offset = b.bytes.len() as u64;
    sections.push(ElfSection {
        name: ".bss",
        kind: 8,
        flags: SHF_ALLOC | SHF_WRITE,
        addr: ELF_VBASE + bss_offset,
        offset: bss_offset,
        size: 0x40,
        link: 0,
        info: 0,
        entsize: 0,
    });

    // `.shstrtab`, last.
    let mut names: Vec<u8> = vec![0];
    let mut name_offsets: Vec<u64> = Vec::new();
    for section in &sections {
        if section.name.is_empty() {
            name_offsets.push(0);
            continue;
        }
        name_offsets.push(names.len() as u64);
        names.extend_from_slice(section.name.as_bytes());
        names.push(0);
    }
    name_offsets.push(names.len() as u64);
    names.extend_from_slice(b".shstrtab\0");
    let shstrtab_offset = place(&mut b, &names);
    sections.push(ElfSection {
        name: ".shstrtab",
        kind: 3,
        flags: 0,
        addr: 0,
        offset: shstrtab_offset,
        size: names.len() as u64,
        link: 0,
        info: 0,
        entsize: 0,
    });

    // Section headers.
    b.align(8);
    let shoff = b.bytes.len();
    let load_size = bss_offset;
    for (index, section) in sections.iter().enumerate() {
        let at = shoff + index * shentsize;
        let label = if section.name.is_empty() {
            format!("section{index}")
        } else {
            format!("section{index}({})", section.name)
        };
        let fields: [(&str, usize, usize, usize, usize, u64); 9] = [
            ("name", 0, 4, 0, 4, name_offsets[index]),
            ("type", 4, 4, 4, 4, u64::from(section.kind)),
            ("flags", 8, 8, 8, 4, section.flags),
            ("addr", 16, 8, 12, 4, section.addr),
            ("offset", 24, 8, 16, 4, section.offset),
            ("size", 32, 8, 20, 4, section.size),
            ("link", 40, 4, 24, 4, u64::from(section.link)),
            ("info", 44, 4, 28, 4, u64::from(section.info)),
            ("entsize", 56, 8, 36, 4, section.entsize),
        ];
        for (field, offset64, width64, offset32, width32, value) in fields {
            let (offset, width) = if is64 {
                (offset64, width64)
            } else {
                (offset32, width32)
            };
            b.set(format!("{label}.{field}"), at + offset, width, value);
            if field == "size" && section.kind == 8 {
                b.fields.last_mut().expect("field").alloc = true;
            }
        }
        // sh_addralign
        if is64 {
            b.write(at + 48, 8, 16);
        } else {
            b.write(at + 32, 4, 16);
        }
    }
    let file_len = b.bytes.len() as u64;

    // ELF header.
    b.raw(0, b"\x7fELF");
    b.set("ident.class", 4, 1, if is64 { 2 } else { 1 });
    b.set("ident.data", 5, 1, 1);
    b.write(6, 1, 1); // EI_VERSION
    b.set("e_type", 16, 2, 3);
    b.set("e_machine", 18, 2, machine);
    b.write(20, 4, 1);
    let shnum = sections.len() as u64;
    let shstrndx = shnum - 1;
    if is64 {
        b.set("e_entry", 24, 8, fn_a);
        b.set("e_phoff", 32, 8, ehsize as u64);
        b.set("e_shoff", 40, 8, shoff as u64);
        b.write(52, 2, ehsize as u64);
        b.set("e_phentsize", 54, 2, phentsize as u64);
        b.set("e_phnum", 56, 2, 1);
        b.set("e_shentsize", 58, 2, shentsize as u64);
        b.set("e_shnum", 60, 2, shnum);
        b.set("e_shstrndx", 62, 2, shstrndx);
        let ph = ehsize;
        b.set("p_type", ph, 4, 1);
        b.write(ph + 4, 4, 5); // PF_R | PF_X
        b.set("p_offset", ph + 8, 8, 0);
        b.set("p_vaddr", ph + 16, 8, ELF_VBASE);
        b.write(ph + 24, 8, ELF_VBASE);
        b.set("p_filesz", ph + 32, 8, load_size);
        b.set("p_memsz", ph + 40, 8, load_size + 0x40);
        b.write(ph + 48, 8, 0x1000);
    } else {
        b.set("e_entry", 24, 4, fn_a);
        b.set("e_phoff", 28, 4, ehsize as u64);
        b.set("e_shoff", 32, 4, shoff as u64);
        b.write(36, 4, 0x0500_0000); // EF_ARM_EABI_VER5
        b.write(40, 2, ehsize as u64);
        b.set("e_phentsize", 42, 2, phentsize as u64);
        b.set("e_phnum", 44, 2, 1);
        b.set("e_shentsize", 46, 2, shentsize as u64);
        b.set("e_shnum", 48, 2, shnum);
        b.set("e_shstrndx", 50, 2, shstrndx);
        let ph = ehsize;
        b.set("p_type", ph, 4, 1);
        b.set("p_offset", ph + 4, 4, 0);
        b.set("p_vaddr", ph + 8, 4, ELF_VBASE);
        b.write(ph + 12, 4, ELF_VBASE);
        b.set("p_filesz", ph + 16, 4, load_size);
        b.set("p_memsz", ph + 20, 4, load_size + 0x40);
        b.write(ph + 24, 4, 5);
        b.write(ph + 28, 4, 0x1000);
    }
    assert_eq!(
        b.bytes.len() as u64,
        file_len,
        "headers fit before the data"
    );
    let name = match arch {
        Arch::X64 => "elf64-x64",
        Arch::Arm64 => "elf64-arm64",
        _ => "elf32-arm",
    };
    Image {
        name: match packing {
            Packing::None => name.to_string(),
            Packing::Relr => format!("{name}-relr"),
            Packing::Android => format!("{name}-aps2"),
        },
        bytes: b.bytes,
        fields: b.fields,
        fn_a,
        layout: sections
            .iter()
            .map(|section| (section.name, section.addr, section.size))
            .collect(),
    }
}

/// `image` as `llvm-objcopy --strip-sections` leaves an image: no section
/// table, only program headers, here appended with what the loader reads in
/// their place: `PT_LOAD` over the whole file, `PT_DYNAMIC` (hash, symbol,
/// string, and relocation tables), and `PT_GNU_EH_FRAME` with an
/// `.eh_frame_hdr` (64-bit) or `PT_ARM_EXIDX` (ARM32).
fn sectionless(image: Image, arch: Arch) -> Image {
    let is64 = arch != Arch::Arm32;
    let word = if is64 { 8 } else { 4 };
    let find = |name: &str| {
        image
            .layout
            .iter()
            .find(|(section, _, _)| *section == name)
            .map(|(_, addr, size)| (*addr, *size))
    };
    let mut b = Builder {
        bytes: image.bytes.clone(),
        // The section table and the old program header are dead bytes now.
        fields: image
            .fields
            .iter()
            .filter(|field| {
                !["section", "e_sh", "e_ph", "p_"]
                    .iter()
                    .any(|prefix| field.name.starts_with(prefix))
            })
            .cloned()
            .collect(),
    };
    let address = |offset: usize| ELF_VBASE + offset as u64;
    let mut segments: Vec<(u32, u64, u64)> = Vec::new(); // (type, offset, size)

    if is64 {
        // `.eh_frame_hdr`: pcrel sdata4 frame pointer, udata4 count, and a
        // datarel sdata4 search table, as lld and GNU ld write it.
        b.align(16);
        let at = b.bytes.len();
        let hdr = address(at);
        let (frames, _) = find(".eh_frame").expect(".eh_frame");
        b.raw(at, &[1, 0x1b, 0x03, 0x3b]);
        b.set(
            "eh_frame_hdr.frame_pointer",
            at + 4,
            4,
            u64::from(frames.wrapping_sub(hdr + 4) as u32),
        );
        b.set("eh_frame_hdr.count", at + 8, 4, 2);
        for (index, start) in [image.fn_a, image.fn_a + 32].iter().enumerate() {
            let fde = frames + 20 + 20 * index as u64;
            let row = at + 12 + 8 * index;
            let relative = |value: u64| u64::from(value.wrapping_sub(hdr) as u32);
            b.set(
                format!("eh_frame_hdr.row{index}.start"),
                row,
                4,
                relative(*start),
            );
            b.set(
                format!("eh_frame_hdr.row{index}.fde"),
                row + 4,
                4,
                relative(fde),
            );
        }
        segments.push((0x6474_e550, at as u64, 28));
    } else {
        let (exidx, size) = find(".ARM.exidx").expect(".ARM.exidx");
        segments.push((0x7000_0001, exidx - ELF_VBASE, size));
    }

    // `DT_HASH`: one bucket, and the chain count that sizes `.dynsym`.
    b.align(8);
    let hash = b.bytes.len();
    b.write(hash, 4, 1);
    b.set("hash.nchain", hash + 4, 4, 3);
    b.bytes.resize(hash + 24, 0);

    let (dynsym, _) = find(".dynsym").expect(".dynsym");
    let (dynstr, dynstr_size) = find(".dynstr").expect(".dynstr");
    let mut tags: Vec<(&str, u64, u64)> = vec![
        ("hash", 4, address(hash)),
        ("strtab", 5, dynstr),
        ("symtab", 6, dynsym),
        ("strsz", 10, dynstr_size),
    ];
    for (name, address_tag, size_tag) in [
        (".rela.dyn", 7, 8),
        (".rel.dyn", 17, 18),
        (".relr.dyn", 36, 35),
        (".android.rela.dyn", 0x6000_0011, 0x6000_0012),
        (".android.rel.dyn", 0x6000_000f, 0x6000_0010),
    ] {
        if let Some((addr, size)) = find(name) {
            tags.push(("relocations", address_tag, addr));
            tags.push(("relocations_size", size_tag, size));
        }
    }
    b.align(8);
    let dynamic = b.bytes.len();
    for (index, (name, tag, value)) in tags.iter().enumerate() {
        let at = dynamic + 2 * word * index;
        b.write(at, word, *tag);
        b.set(format!("dynamic.{name}"), at + word, word, *value);
    }
    let dynamic_size = 2 * word * (tags.len() + 1);
    b.bytes.resize(dynamic + dynamic_size, 0); // DT_NULL
    segments.push((2, dynamic as u64, dynamic_size as u64));

    // Program headers last: the file before them is one RWX `PT_LOAD`.
    b.align(8);
    let phoff = b.bytes.len();
    segments.insert(0, (1, 0, phoff as u64));
    let phentsize = if is64 { 56 } else { 32 };
    for (index, (kind, offset, size)) in segments.iter().enumerate() {
        let at = phoff + index * phentsize;
        let label = format!("ph{index}");
        let memsz = if *kind == 1 { size + 0x40 } else { *size };
        // (field, offset64, offset32, value); widths are the class's word,
        // except type and flags, which are always 4 bytes.
        let rows: [(&str, usize, usize, u64); 6] = [
            ("type", 0, 0, u64::from(*kind)),
            ("flags", 4, 24, 7),
            ("offset", 8, 4, *offset),
            ("vaddr", 16, 8, ELF_VBASE + offset),
            ("filesz", 32, 16, *size),
            ("memsz", 40, 20, memsz),
        ];
        for (field, offset64, offset32, value) in rows {
            let width = if matches!(field, "type" | "flags") {
                4
            } else {
                word
            };
            let offset = if is64 { offset64 } else { offset32 };
            b.set(format!("{label}.{field}"), at + offset, width, value);
            if field == "memsz" {
                b.fields.last_mut().expect("field").alloc = true;
            }
        }
        // p_paddr
        b.write(at + if is64 { 24 } else { 12 }, word, ELF_VBASE + offset);
    }
    b.bytes.resize(phoff + segments.len() * phentsize, 0);
    let (phoff_at, phnum_at, shoff_at, shnum_at) = if is64 {
        (32, 56, 40, 60)
    } else {
        (28, 44, 32, 48)
    };
    b.set("e_phoff", phoff_at, word, phoff as u64);
    b.set("e_phnum", phnum_at, 2, segments.len() as u64);
    b.write(shoff_at, word, 0);
    b.write(shnum_at, 2, 0);
    b.write(shnum_at + 2, 2, 0); // e_shstrndx
    Image {
        name: format!("{}-sectionless", image.name),
        bytes: b.bytes,
        fields: b.fields,
        fn_a: image.fn_a,
        layout: Vec::new(),
    }
}

const PE_IMAGE_BASE: u64 = 0x1_4000_0000;
const PE_TEXT_RVA: u64 = 0x1000;
const PE_RDATA_RVA: u64 = 0x2000;
const PE_PDATA_RVA: u64 = 0x3000;

/// A PE32+ DLL: `.text` with two functions (x86-64 also an import thunk),
/// `.rdata` with an export directory naming both and an import directory
/// with one import, and `.pdata`.
fn pe_image(arch: Arch) -> Image {
    let mut b = Builder::default();
    b.bytes.resize(0xa00, 0);
    b.raw(0, b"MZ");
    b.set("e_lfanew", 0x3c, 4, 0x40);
    b.raw(0x40, b"PE\0\0");
    let coff = 0x44;
    let machine = if arch == Arch::X64 { 0x8664 } else { 0xaa64 };
    b.set("coff.machine", coff, 2, machine);
    b.set("coff.sections", coff + 2, 2, 3);
    b.set("coff.optional_size", coff + 16, 2, 240);
    b.write(coff + 18, 2, 0x2022);
    let optional = coff + 20;
    b.set("optional.magic", optional, 2, 0x20b);
    b.write(optional + 16, 4, PE_TEXT_RVA); // AddressOfEntryPoint
    b.write(optional + 20, 4, PE_TEXT_RVA); // BaseOfCode
    b.set("optional.image_base", optional + 24, 8, PE_IMAGE_BASE);
    b.write(optional + 32, 4, 0x1000);
    b.write(optional + 36, 4, 0x200);
    b.write(optional + 56, 4, 0x4000); // SizeOfImage
    b.write(optional + 60, 4, 0x400); // SizeOfHeaders
    b.write(optional + 68, 2, 3); // console
    b.set("optional.dirs", optional + 108, 4, 16);
    let dirs = optional + 112;
    let pdata_size = if arch == Arch::X64 { 24 } else { 16 };
    for (index, name, rva, size) in [
        (0, "export", PE_RDATA_RVA, 0x90),
        (1, "import", PE_RDATA_RVA + 0x100, 0x28),
        (3, "exception", PE_PDATA_RVA, pdata_size),
    ] {
        b.set(format!("dir.{name}.rva"), dirs + index * 8, 4, rva);
        b.set(format!("dir.{name}.size"), dirs + index * 8 + 4, 4, size);
    }
    let table = optional + 240;
    for (index, (name, rva, raw, characteristics)) in [
        (".text", PE_TEXT_RVA, 0x400u64, 0x6000_0020u64),
        (".rdata", PE_RDATA_RVA, 0x600, 0x4000_0040),
        (".pdata", PE_PDATA_RVA, 0x800, 0x4000_0040),
    ]
    .iter()
    .enumerate()
    {
        let at = table + index * 40;
        b.raw(at, name.as_bytes());
        let label = format!("section{index}({name})");
        b.set(format!("{label}.virtual_size"), at + 8, 4, 0x200);
        b.fields.last_mut().expect("field").alloc = true;
        b.set(format!("{label}.virtual_address"), at + 12, 4, *rva);
        b.set(format!("{label}.raw_size"), at + 16, 4, 0x200);
        b.fields.last_mut().expect("field").alloc = true;
        b.set(format!("{label}.raw_pointer"), at + 20, 4, *raw);
        b.set(
            format!("{label}.characteristics"),
            at + 36,
            4,
            *characteristics,
        );
    }

    // `.text`.
    let (mut code, fn_a_size) = code_bytes(arch);
    let text = 0x400;
    let rdata = 0x600usize;
    let fn_b_name = PE_RDATA_RVA + 0x78;
    if arch == Arch::X64 {
        // lea rdi, [rip+disp32] points at the "fn_b" export name; a
        // `jmp [rip+disp32]` thunk at 48 loads the import's IAT slot.
        let disp = fn_b_name.wrapping_sub(PE_TEXT_RVA + 11) as u32;
        code[7..11].copy_from_slice(&disp.to_le_bytes());
        let iat = PE_RDATA_RVA + 0x160;
        let jump = iat.wrapping_sub(PE_TEXT_RVA + 48 + 6) as u32;
        code.extend([0xff, 0x25]);
        code.extend(jump.to_le_bytes());
    }
    b.raw(text, &code);

    // `.rdata`: export directory.
    b.set("export.name", rdata + 12, 4, PE_RDATA_RVA + 0x80);
    b.write(rdata + 16, 4, 1); // ordinal base
    b.set("export.functions", rdata + 20, 4, 2);
    b.set("export.names", rdata + 24, 4, 2);
    b.set(
        "export.address_of_functions",
        rdata + 28,
        4,
        PE_RDATA_RVA + 0x40,
    );
    b.set(
        "export.address_of_names",
        rdata + 32,
        4,
        PE_RDATA_RVA + 0x50,
    );
    b.set(
        "export.address_of_ordinals",
        rdata + 36,
        4,
        PE_RDATA_RVA + 0x60,
    );
    b.set("export.function0", rdata + 0x40, 4, PE_TEXT_RVA);
    b.set("export.function1", rdata + 0x44, 4, PE_TEXT_RVA + 32);
    b.set("export.name0", rdata + 0x50, 4, PE_RDATA_RVA + 0x70);
    b.set("export.name1", rdata + 0x54, 4, fn_b_name);
    b.set("export.ordinal0", rdata + 0x60, 2, 0);
    b.set("export.ordinal1", rdata + 0x62, 2, 1);
    b.raw(rdata + 0x70, b"fn_a\0");
    b.raw(rdata + 0x78, b"fn_b\0");
    b.raw(rdata + 0x80, b"hostile.dll\0");
    // Import directory: one descriptor, then the null terminator.
    let import = rdata + 0x100;
    b.set("import.original_thunk", import, 4, PE_RDATA_RVA + 0x140);
    b.set("import.name", import + 12, 4, PE_RDATA_RVA + 0x130);
    b.set("import.first_thunk", import + 16, 4, PE_RDATA_RVA + 0x160);
    b.raw(rdata + 0x130, b"kernel32.dll\0");
    b.set("import.ilt0", rdata + 0x140, 8, PE_RDATA_RVA + 0x180);
    b.set("import.iat0", rdata + 0x160, 8, PE_RDATA_RVA + 0x180);
    b.raw(rdata + 0x182, b"ExitProcess\0");

    // `.pdata`.
    let pdata = 0x800;
    if arch == Arch::X64 {
        for (index, (start, size)) in [(PE_TEXT_RVA, fn_a_size), (PE_TEXT_RVA + 32, 3)]
            .iter()
            .enumerate()
        {
            let at = pdata + index * 12;
            b.set(format!("pdata{index}.begin"), at, 4, *start);
            b.set(format!("pdata{index}.end"), at + 4, 4, start + size);
            b.write(at + 8, 4, PE_PDATA_RVA + 0x100);
        }
    } else {
        for (index, (start, size)) in [(PE_TEXT_RVA, fn_a_size), (PE_TEXT_RVA + 32, 8)]
            .iter()
            .enumerate()
        {
            let at = pdata + index * 8;
            b.set(format!("pdata{index}.begin"), at, 4, *start);
            // Packed unwind data: flag 1, function length in words.
            b.set(
                format!("pdata{index}.packed"),
                at + 4,
                4,
                1 | ((size / 4) << 2),
            );
        }
    }
    Image {
        name: if arch == Arch::X64 {
            "pe32p-x64"
        } else {
            "pe32p-arm64"
        }
        .to_string(),
        bytes: b.bytes,
        fields: b.fields,
        fn_a: PE_IMAGE_BASE + PE_TEXT_RVA,
        layout: Vec::new(),
    }
}

fn images() -> Vec<Image> {
    let mut images = Vec::new();
    for arch in [Arch::X64, Arch::Arm64, Arch::Arm32] {
        images.push(elf_image(arch, Packing::None));
        images.push(elf_image(arch, Packing::Relr));
        images.push(elf_image(arch, Packing::Android));
        images.push(sectionless(elf_image(arch, Packing::None), arch));
    }
    images.push(sectionless(
        elf_image(Arch::Arm64, Packing::Relr),
        Arch::Arm64,
    ));
    images.push(sectionless(
        elf_image(Arch::Arm32, Packing::Android),
        Arch::Arm32,
    ));
    images.push(pe_image(Arch::X64));
    images.push(pe_image(Arch::Arm64));
    images
}

// -- mutation ------------------------------------------------------------------

/// Edge values for a field, truncated to its width and deduplicated.
fn edge_values(width: usize, file_len: usize) -> Vec<u64> {
    let mask = if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width)) - 1
    };
    let mut values: Vec<u64> = [
        0,
        1,
        0x10,
        0x7f,
        0xffff,
        0x7fff_ffff,
        u64::from(u32::MAX),
        file_len as u64,
        file_len as u64 + 1,
        1 << 40,
        u64::MAX,
    ]
    .iter()
    .map(|value| value & mask)
    .collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn write_field(bytes: &mut [u8], field: &Field, value: u64) {
    bytes[field.offset..field.offset + field.width]
        .copy_from_slice(&value.to_le_bytes()[..field.width]);
}

/// Truncations at `steps` evenly spaced lengths plus the ends.
fn truncations(length: usize, steps: usize) -> Vec<usize> {
    let mut lengths: Vec<usize> = (0..=steps).map(|step| length * step / steps).collect();
    lengths.extend([1, 2, 3, 4, length.saturating_sub(1)]);
    lengths.retain(|cut| *cut <= length);
    lengths.sort_unstable();
    lengths.dedup();
    lengths
}

/// The unmutated images, signature, and database must parse and reach the
/// code paths the mutation tests aim at. Without this a builder mistake
/// would make every mutated case fail at the first check and still pass.
#[test]
fn unmutated_inputs_parse_and_recover() {
    for image in images() {
        let name = image.name.as_str();
        let source = FileSource::from_bytes(&image.bytes, "hostile.bin")
            .unwrap_or_else(|error| panic!("{name}: builder image rejected: {error:?}"));
        assert!(
            source
                .unwind_entries()
                .iter()
                .any(|(start, _)| *start == image.fn_a)
                || source.function_starts().contains(&image.fn_a),
            "{name}: fn_a at 0x{:x} is not an unwind entry or function start",
            image.fn_a
        );
        let function = recover(&source, image.fn_a, None, false)
            .unwrap_or_else(|error| panic!("{name}: fn_a does not recover: {error:?}"));
        let features = features::extract(&source, &function);
        assert!(
            features
                .iter()
                .any(|feature| feature.kind == FeatureKind::Const && feature.value == "0x12345678"),
            "{name}: fn_a lacks the const 0x12345678 record: {features:?}"
        );
        if name == "elf64-x64" {
            assert!(
                features
                    .iter()
                    .any(|feature| feature.kind == FeatureKind::Str
                        && feature.value == "hostile input literal"),
                "{name}: fn_a lacks the string record: {features:?}"
            );
        }
    }
    let db = sample_db();
    let view = DbView::parse(&db).expect("sample database parses");
    assert_eq!(view.len(), 2, "sample database record count");
    Signature::from_yaml(&sample_yaml()).expect("sample signature parses");
}

#[test]
fn image_header_fields_at_edge_values_never_panic() {
    let mut cases = Cases::new();
    for image in images() {
        cases.run(
            &|| format!("{} unmutated", image.name),
            hostile::image,
            &image.bytes,
        );
        for field in &image.fields {
            for value in edge_values(field.width, image.bytes.len()) {
                let mut bytes = image.bytes.clone();
                write_field(&mut bytes, field, value);
                let label = || format!("{} {}=0x{value:x}", image.name, field.name);
                if field.alloc && value > ALLOC_ANNOUNCE {
                    announce(&label());
                }
                cases.run(&label, hostile::image, &bytes);
            }
        }
    }
    cases.finish("image header fields");
}

#[test]
fn randomly_corrupted_and_truncated_images_never_panic() {
    let mut rng = Rng(0x5167_7001_d00d_f00d);
    let mut cases = Cases::new();
    for image in images() {
        for cut in truncations(image.bytes.len(), 48) {
            cases.run(
                &|| format!("{} truncated to {cut}", image.name),
                hostile::image,
                &image.bytes[..cut],
            );
        }
        for round in 0..256 {
            let mut bytes = image.bytes.clone();
            let mut large_alloc = false;
            // A few fields to edge or random values, then a few random bytes.
            for _ in 0..1 + rng.below(4) {
                let field = &image.fields[rng.below(image.fields.len())];
                let values = edge_values(field.width, bytes.len());
                let value = if rng.below(2) == 0 {
                    values[rng.below(values.len())]
                } else {
                    rng.next_u64()
                };
                write_field(&mut bytes, field, value);
                let mask = if field.width >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (8 * field.width)) - 1
                };
                large_alloc |= field.alloc && value & mask > ALLOC_ANNOUNCE;
            }
            for _ in 0..rng.below(8) {
                let at = rng.below(bytes.len());
                bytes[at] = rng.next_u64() as u8;
            }
            let label = || format!("{} random round {round}", image.name);
            if large_alloc {
                announce(&label());
            }
            cases.run(&label, hostile::image, &bytes);
        }
    }
    // Container magic in front of noise, and noise alone.
    for round in 0..64 {
        let length = rng.below(2048);
        let mut bytes = rng.bytes(length);
        match round % 3 {
            0 if length >= 4 => bytes[..4].copy_from_slice(b"\x7fELF"),
            1 if length >= 2 => bytes[..2].copy_from_slice(b"MZ"),
            _ => {}
        }
        cases.run(&|| format!("noise round {round}"), hostile::image, &bytes);
    }
    cases.finish("corrupted images");
}

// -- signatures and databases ------------------------------------------------------

fn sample_signature(name: &str, literal: &str, rva: u64) -> Signature {
    Signature::new(
        name,
        vec![
            SignatureFeature {
                kind: FeatureKind::Str,
                value: literal.to_string(),
                weight: 1.2,
                required: true,
            },
            SignatureFeature {
                kind: FeatureKind::Const,
                value: "0x12345678".to_string(),
                weight: 0.8,
                required: true,
            },
            SignatureFeature {
                kind: FeatureKind::Cfg,
                value: "blocks:1".to_string(),
                weight: 0.25,
                required: false,
            },
        ],
        vec![format!("str:{literal}")],
        0.85,
        2,
        "single-arch",
        vec![SampleProvenance {
            arch: "x64".to_string(),
            module: "hostile".to_string(),
            rva,
            opt: Some("O2".to_string()),
            tool: Some("test".to_string()),
        }],
    )
    .expect("valid signature")
}

fn sample_yaml() -> String {
    sample_signature("fn_a", "hostile input literal", 0x1000)
        .to_yaml()
        .expect("yaml")
}

fn sample_db() -> Vec<u8> {
    let mut db = SignatureDb::new();
    db.push(&sample_signature("fn_a", "hostile input literal", 0x1000))
        .expect("push");
    db.push(&sample_signature("fn_b", "another literal", 0x1020))
        .expect("push");
    db.encode()
}

/// Bytes that change YAML structure, for byte-level corruption.
const YAML_SYNTAX: &[u8] = b":-[]{}&*!|>'\"#%@`\n ,?";

#[test]
fn hostile_signature_documents_never_panic() {
    let base = sample_yaml();
    let mut cases = Cases::new();
    cases.run(
        &|| "unmutated".to_string(),
        hostile::signature_yaml,
        base.as_bytes(),
    );
    for cut in truncations(base.len(), 64) {
        cases.run(
            &|| format!("truncated to {cut}"),
            hostile::signature_yaml,
            &base.as_bytes()[..cut],
        );
    }
    // Every scalar replaced by hostile scalars, one at a time.
    let hostile_scalars = [
        "",
        "~",
        "-1",
        "0",
        ".nan",
        ".inf",
        "-.inf",
        "1e309",
        "18446744073709551616",
        "0xffffffffffffffffffff",
        "'0x'",
        "'out:0x'",
        "[]",
        "{}",
        "*undefined",
        "!!binary AAAA",
    ];
    let lines: Vec<&str> = base.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let Some(colon) = line.find(": ") else {
            continue;
        };
        for scalar in hostile_scalars {
            let mut mutated: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
            mutated[index] = format!("{}: {scalar}", &line[..colon]);
            let text = mutated.join("\n");
            cases.run(
                &|| format!("line {index} value {scalar:?}"),
                hostile::signature_yaml,
                text.as_bytes(),
            );
        }
        let mut without: Vec<&str> = lines.clone();
        without.remove(index);
        let text = without.join("\n");
        cases.run(
            &|| format!("line {index} removed"),
            hostile::signature_yaml,
            text.as_bytes(),
        );
    }
    // Structural attacks: deep nesting, alias expansion, huge collections.
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
    for level in 1..10 {
        let previous = (b'a' + level - 1) as char;
        let current = (b'a' + level) as char;
        bomb.push_str(&format!(
            "{current}: &{current} [*{previous}, *{previous}, *{previous}, *{previous}, \
             *{previous}, *{previous}, *{previous}, *{previous}, *{previous}]\n"
        ));
    }
    let many_features = {
        let block: String = (0..2000)
            .map(|index| format!("- kind: const\n  value: '0x{index:x}'\n  weight: 1\n"))
            .collect();
        base.replace("features:\n", &format!("features:\n{block}"))
    };
    for (label, text) in [
        ("deep nesting", deep),
        ("alias bomb", bomb),
        ("many features", many_features),
        ("document stream", format!("{base}---\n{base}")),
    ] {
        cases.run(
            &|| label.to_string(),
            hostile::signature_yaml,
            text.as_bytes(),
        );
    }
    let mut rng = Rng(0x7a11_5eed_0bad_cafe);
    for round in 0..512 {
        let mut bytes = base.clone().into_bytes();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(bytes.len());
            bytes[at] = match rng.below(4) {
                0 => YAML_SYNTAX[rng.below(YAML_SYNTAX.len())],
                1 => b'0' + rng.below(10) as u8,
                _ => rng.next_u64() as u8,
            };
        }
        cases.run(
            &|| format!("random round {round}"),
            hostile::signature_yaml,
            &bytes,
        );
    }
    cases.finish("signature documents");
}

/// DB header and record-table fields, as (name, offset, width).
fn db_fields(bytes: &[u8]) -> Vec<Field> {
    let field = |name: String, offset: usize, width: usize| Field {
        name,
        offset,
        width,
        alloc: false,
    };
    let mut fields: Vec<Field> = [
        ("format_version", 8, 2),
        ("header_size", 10, 2),
        ("flags", 12, 4),
        ("spec_len", 16, 2),
        ("record_size", 18, 2),
        ("count", 20, 4),
        ("spec_offset", 24, 8),
        ("records_offset", 32, 8),
        ("blob_offset", 40, 8),
        ("blob_len", 48, 8),
        ("table_crc", 56, 4),
    ]
    .iter()
    .map(|(name, offset, width)| field(name.to_string(), *offset, *width))
    .collect();
    let count = u32::from_le_bytes(bytes[20..24].try_into().expect("count")) as usize;
    let records = u64::from_le_bytes(bytes[32..40].try_into().expect("records")) as usize;
    for index in 0..count {
        let at = records + index * 40;
        for (name, offset, width) in [
            ("id_offset", 0, 8),
            ("id_len", 8, 4),
            ("name_len", 12, 4),
            ("name_offset", 16, 8),
            ("payload_offset", 24, 8),
            ("payload_len", 32, 4),
            ("payload_crc", 36, 4),
        ] {
            fields.push(field(format!("record{index}.{name}"), at + offset, width));
        }
    }
    fields
}

/// Recompute the table CRC (and each payload CRC, from the original table)
/// so a mutation reaches the checks behind them.
fn fix_db_checksums(bytes: &mut [u8], original: &[u8]) {
    let count = u32::from_le_bytes(original[20..24].try_into().expect("count")) as usize;
    let records = u64::from_le_bytes(original[32..40].try_into().expect("records")) as usize;
    for index in 0..count {
        let at = records + index * 40;
        let offset =
            u64::from_le_bytes(original[at + 24..at + 32].try_into().expect("offset")) as usize;
        let length =
            u32::from_le_bytes(original[at + 32..at + 36].try_into().expect("len")) as usize;
        let crc = crc32fast::hash(&bytes[offset..offset + length]);
        bytes[at + 36..at + 40].copy_from_slice(&crc.to_le_bytes());
    }
    let table = crc32fast::hash(&bytes[records..records + count * 40]);
    bytes[56..60].copy_from_slice(&table.to_le_bytes());
}

#[test]
fn hostile_signature_databases_never_panic() {
    let base = sample_db();
    let fields = db_fields(&base);
    let mut cases = Cases::new();
    cases.run(&|| "unmutated".to_string(), hostile::database, &base);
    for cut in truncations(base.len(), 64) {
        cases.run(
            &|| format!("truncated to {cut}"),
            hostile::database,
            &base[..cut],
        );
    }
    for field in &fields {
        for value in edge_values(field.width, base.len()) {
            for fix in [false, true] {
                let mut bytes = base.clone();
                write_field(&mut bytes, field, value);
                if fix && !field.name.ends_with("crc") {
                    fix_db_checksums(&mut bytes, &base);
                }
                cases.run(
                    &|| format!("{}=0x{value:x} fixed-crc={fix}", field.name),
                    hostile::database,
                    &bytes,
                );
            }
        }
    }
    let mut rng = Rng(0xdb0d_b0db_0db0_db0d);
    for round in 0..512 {
        let mut bytes = base.clone();
        for _ in 0..1 + rng.below(6) {
            let at = rng.below(bytes.len());
            bytes[at] = rng.next_u64() as u8;
        }
        // Half the rounds keep the checksums valid, so payload corruption
        // reaches the YAML parser and the id check.
        if round % 2 == 0 {
            let header_intact = bytes[..64] == base[..64];
            if header_intact {
                fix_db_checksums(&mut bytes, &base);
            }
        }
        cases.run(
            &|| format!("random round {round}"),
            hostile::database,
            &bytes,
        );
    }
    cases.finish("signature databases");
}

// -- raw code --------------------------------------------------------------------

fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join("tests")
        .join("vectors")
}

fn hex_decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| (byte as char).to_digit(16).expect("hex") as u8;
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

/// `(label, selector + bytes)` for every executable section of every golden
/// vector: real compiler output for each architecture.
fn vector_code() -> Vec<(String, Vec<u8>)> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(vector_dir())
        .expect("vector dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path).expect("vector");
        let vector: serde_json::Value = serde_json::from_str(&text).expect("vector json");
        let arch_text = vector["arch"]
            .as_str()
            .expect("arch")
            .replace("-pac", "")
            .replace("-cet", "")
            .replace("-pic", "");
        let arch = Arch::parse(&arch_text).expect("known arch");
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("stem")
            .to_string();
        for section in vector["sections"].as_array().expect("sections") {
            if !section["executable"].as_bool().unwrap_or(false) {
                continue;
            }
            let name = section["name"].as_str().unwrap_or("code").trim_matches('.');
            let mut input = vec![hostile::code_selector(arch)];
            input.extend(hex_decode(section["bytes"].as_str().expect("bytes")));
            out.push((format!("{stem}-{name}"), input));
        }
    }
    out
}

#[test]
fn raw_code_never_panics() {
    let vectors = vector_code();
    assert!(!vectors.is_empty(), "golden vectors have code sections");
    let mut rng = Rng(0xc0de_c0de_1234_5678);
    let mut cases = Cases::new();
    for (label, input) in &vectors {
        // Every option combination over real code.
        for options in 0..16u8 {
            let mut bytes = input.clone();
            bytes[0] = (bytes[0] & 3) | (options << 2);
            cases.run(
                &|| format!("{label} options {options}"),
                hostile::code,
                &bytes,
            );
        }
        // Decoded as every other architecture, then corrupted.
        for selector in 0..4u8 {
            let mut bytes = input.clone();
            bytes[0] = selector;
            cases.run(
                &|| format!("{label} as selector {selector}"),
                hostile::code,
                &bytes,
            );
        }
        for round in 0..8 {
            if input.len() < 2 {
                break;
            }
            let mut bytes = input.clone();
            for _ in 0..1 + rng.below(16) {
                let at = 1 + rng.below(bytes.len() - 1);
                bytes[at] = rng.next_u64() as u8;
            }
            let cut = 1 + rng.below(bytes.len());
            cases.run(
                &|| format!("{label} random round {round}"),
                hostile::code,
                &bytes[..cut],
            );
        }
    }
    for selector in 0..64u8 {
        for length in [0usize, 1, 2, 3, 4, 7, 16, 64, 255, 4096] {
            let mut bytes = vec![selector];
            bytes.extend(rng.bytes(length));
            cases.run(
                &|| format!("noise selector {selector} length {length}"),
                hostile::code,
                &bytes,
            );
        }
    }
    cases.finish("raw code");
}

// -- fuzz seeds ------------------------------------------------------------------

/// With `SIGTOOL_FUZZ_SEEDS=DIR`, write the unmutated inputs above as
/// starting corpora: `DIR/image`, `DIR/signature`, `DIR/db`, `DIR/code`.
#[test]
fn write_fuzz_seeds() {
    let Some(dir) = std::env::var_os("SIGTOOL_FUZZ_SEEDS") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let write = |target: &str, name: &str, bytes: &[u8]| {
        let folder = dir.join(target);
        std::fs::create_dir_all(&folder).expect("seed dir");
        std::fs::write(folder.join(name), bytes).expect("seed");
    };
    for image in images() {
        write("image", &format!("{}.bin", image.name), &image.bytes);
    }
    write("signature", "sample.yaml", sample_yaml().as_bytes());
    write("db", "sample.db", &sample_db());
    for (label, input) in vector_code() {
        write("code", &format!("{label}.bin"), &input);
    }
}
