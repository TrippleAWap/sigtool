//! Image identity for reports: SHA-256 of the file, plus the build identifier
//! the toolchain embedded (ELF `NT_GNU_BUILD_ID`, PE CodeView `RSDS` GUID and
//! age).
//!
//! Reports carry these so a signature set or a scan result can be tied back
//! to the exact input it came from, and a debug-symbol server can find the
//! matching symbols. None of it reaches a signature or a DB: those stay free
//! of paths and per-file data (AGENTS.md rule 3).
//!
//! The headers are read here from raw bytes rather than through `elf.rs`, so
//! identity works on any file a batch meets, including ones `FileSource`
//! refuses. Every read is bounded by the file and by fixed entry caps
//! (AGENTS.md rule 8). SHA-256 is implemented in-tree because the crate's
//! dependency list is fixed (AGENTS.md conventions).

/// What container a file claims to be, by magic alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Elf,
    Pe,
    Other,
}

/// `FileSource` dispatches on the same two magics, so a file sniffed as
/// [`Container::Other`] is one it would refuse.
pub fn container(data: &[u8]) -> Container {
    if data.starts_with(b"\x7fELF") {
        Container::Elf
    } else if data.starts_with(b"MZ") {
        Container::Pe
    } else {
        Container::Other
    }
}

/// A PE image's PDB identity, as a symbol server keys it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbId {
    /// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, upper case, the form
    /// `llvm-readobj --coff-debug-directory` and debuggers print.
    pub guid: String,
    pub age: u32,
}

/// Identity of one input file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentity {
    pub sha256: [u8; 32],
    pub size: u64,
    /// Lower-case hex of the ELF GNU build-id note, when present.
    pub build_id: Option<String>,
    /// The PE CodeView record, when present.
    pub pdb: Option<PdbId>,
}

impl ImageIdentity {
    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }
}

pub fn identify(data: &[u8]) -> ImageIdentity {
    let (build_id, pdb) = match container(data) {
        Container::Elf => (elf_build_id(data), None),
        Container::Pe => (None, pe_pdb_id(data)),
        Container::Other => (None, None),
    };
    ImageIdentity {
        sha256: sha256(data),
        size: data.len() as u64,
        build_id,
        pdb,
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

// -- SHA-256 (FIPS 180-4) ----------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Incremental SHA-256, for inputs that arrive in pieces.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: H0,
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                return;
            }
            let block = self.buffer;
            compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8);
        let mut tail = [0u8; 72];
        tail[0] = 0x80;
        // Pad to 56 mod 64, then the 64-bit big-endian bit length.
        let pad = if self.buffered < 56 {
            56 - self.buffered
        } else {
            120 - self.buffered
        };
        tail[pad..pad + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&tail[..pad + 8]);
        debug_assert_eq!(self.buffered, 0);
        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (index, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[index] = u32::from_be_bytes(*chunk);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

// -- bounded raw reads -------------------------------------------------------

fn bytes_at(data: &[u8], offset: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    data.get(start..start.checked_add(len)?)
}

fn u16_at(data: &[u8], offset: u64, big: bool) -> Option<u16> {
    let raw: [u8; 2] = bytes_at(data, offset, 2)?.try_into().ok()?;
    Some(if big {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    })
}

fn u32_at(data: &[u8], offset: u64, big: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes_at(data, offset, 4)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}

fn u64_at(data: &[u8], offset: u64, big: bool) -> Option<u64> {
    let raw: [u8; 8] = bytes_at(data, offset, 8)?.try_into().ok()?;
    Some(if big {
        u64::from_be_bytes(raw)
    } else {
        u64::from_le_bytes(raw)
    })
}

// -- ELF build-id ------------------------------------------------------------

const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;
/// Notes examined per file. Linkers emit a handful (build-id, ABI tag, GNU
/// property, package metadata); the cap only stops a hostile note table.
const MAX_NOTES: usize = 256;
/// Longest build-id kept. `--build-id` writes 8 (fast), 16 (md5, uuid) or 20
/// (sha1) bytes, and `0x<hex>` ids are rarely longer; the cap bounds what a
/// hostile note can put in a report.
const MAX_BUILD_ID: usize = 64;

/// The GNU build-id from the first `PT_NOTE` segment that carries one. Program
/// headers, not sections, because `strip --strip-all` keeps segments and a
/// section-less image has no section table at all.
pub fn elf_build_id(data: &[u8]) -> Option<String> {
    if container(data) != Container::Elf {
        return None;
    }
    let wide = match data.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big = match data.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let (phoff, phentsize, phnum) = if wide {
        (
            u64_at(data, 0x20, big)?,
            u16_at(data, 0x36, big)?,
            u16_at(data, 0x38, big)?,
        )
    } else {
        (
            u64::from(u32_at(data, 0x1c, big)?),
            u16_at(data, 0x2a, big)?,
            u16_at(data, 0x2c, big)?,
        )
    };
    let needed = if wide { 0x38 } else { 0x20 };
    if usize::from(phentsize) < needed {
        return None;
    }
    let mut notes = 0usize;
    for index in 0..u64::from(phnum) {
        let header = phoff.checked_add(index.checked_mul(u64::from(phentsize))?)?;
        if header.checked_add(u64::from(phentsize))? > data.len() as u64 {
            return None;
        }
        if u32_at(data, header, big)? != PT_NOTE {
            continue;
        }
        let (offset, size, align) = if wide {
            (
                u64_at(data, header + 8, big)?,
                u64_at(data, header + 0x20, big)?,
                u64_at(data, header + 0x30, big)?,
            )
        } else {
            (
                u64::from(u32_at(data, header + 4, big)?),
                u64::from(u32_at(data, header + 0x10, big)?),
                u64::from(u32_at(data, header + 0x1c, big)?),
            )
        };
        // gABI notes pad to 4 bytes; the GNU property notes of 64-bit images
        // sit in an 8-aligned PT_NOTE and pad to 8.
        let pad = if align == 8 { 8 } else { 4 };
        let end = offset.saturating_add(size).min(data.len() as u64);
        let mut at = offset;
        while at.saturating_add(12) <= end && notes < MAX_NOTES {
            notes += 1;
            let namesz = u64::from(u32_at(data, at, big)?);
            let descsz = u64::from(u32_at(data, at + 4, big)?);
            let kind = u32_at(data, at + 8, big)?;
            let name_at = at + 12;
            let desc_at = name_at.checked_add(round_up(namesz, pad)?)?;
            let next = desc_at.checked_add(round_up(descsz, pad)?)?;
            if desc_at.checked_add(descsz)? > end {
                break;
            }
            if kind == NT_GNU_BUILD_ID
                && namesz == 4
                && bytes_at(data, name_at, 4)? == b"GNU\0"
                && descsz > 0
                && descsz as usize <= MAX_BUILD_ID
            {
                return Some(hex(bytes_at(data, desc_at, descsz as usize)?));
            }
            at = next;
        }
    }
    None
}

fn round_up(value: u64, to: u64) -> Option<u64> {
    Some(value.checked_add(to - 1)? / to * to)
}

// -- PE CodeView ---------------------------------------------------------------

const IMAGE_DIRECTORY_ENTRY_DEBUG: u64 = 6;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const DEBUG_DIRECTORY_SIZE: u64 = 28;
/// Debug directory entries examined. Linkers write one to four (CodeView,
/// POGO, repro, extended DLL characteristics); the cap stops a hostile size.
const MAX_DEBUG_ENTRIES: u64 = 64;

/// The CodeView `RSDS` record a PDB-producing link (`/DEBUG`) writes, found
/// through the debug data directory.
pub fn pe_pdb_id(data: &[u8]) -> Option<PdbId> {
    if container(data) != Container::Pe {
        return None;
    }
    let nt = u64::from(u32_at(data, 0x3c, false)?);
    if bytes_at(data, nt, 4)? != b"PE\0\0" {
        return None;
    }
    let coff = nt + 4;
    let sections = u64::from(u16_at(data, coff + 2, false)?);
    let optional_size = u64::from(u16_at(data, coff + 16, false)?);
    let optional = coff + 20;
    let (count_at, directories) = match u16_at(data, optional, false)? {
        0x10b => (92, 96),
        0x20b => (108, 112),
        _ => return None,
    };
    let directory_count = u64::from(u32_at(data, optional + count_at, false)?);
    let entry = directories + IMAGE_DIRECTORY_ENTRY_DEBUG * 8;
    if directory_count <= IMAGE_DIRECTORY_ENTRY_DEBUG || entry + 8 > optional_size {
        return None;
    }
    let debug_rva = u64::from(u32_at(data, optional + entry, false)?);
    let debug_size = u64::from(u32_at(data, optional + entry + 4, false)?);
    if debug_rva == 0 || debug_size == 0 {
        return None;
    }
    let table = optional + optional_size;
    let rva_to_offset = |rva: u64| -> Option<u64> {
        for index in 0..sections {
            let header = table + index * 40;
            let virtual_size = u64::from(u32_at(data, header + 8, false)?);
            let virtual_address = u64::from(u32_at(data, header + 12, false)?);
            let raw_size = u64::from(u32_at(data, header + 16, false)?);
            let raw_offset = u64::from(u32_at(data, header + 20, false)?);
            let span = virtual_size.max(raw_size);
            if rva >= virtual_address && rva - virtual_address < span {
                let delta = rva - virtual_address;
                return (delta < raw_size).then_some(raw_offset + delta);
            }
        }
        None
    };
    let directory = rva_to_offset(debug_rva)?;
    for index in 0..(debug_size / DEBUG_DIRECTORY_SIZE).min(MAX_DEBUG_ENTRIES) {
        let at = directory + index * DEBUG_DIRECTORY_SIZE;
        if u32_at(data, at + 12, false)? != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let size = u32_at(data, at + 16, false)?;
        let pointer = u64::from(u32_at(data, at + 24, false)?);
        if size < 24 || bytes_at(data, pointer, 4)? != b"RSDS" {
            continue;
        }
        let guid = bytes_at(data, pointer + 4, 16)?;
        let age = u32_at(data, pointer + 20, false)?;
        return Some(PdbId {
            guid: format_guid(guid),
            age,
        });
    }
    None
}

/// The first three GUID fields are stored little-endian, the last eight
/// bytes in order, which is why the printed form is not the byte hex.
fn format_guid(raw: &[u8]) -> String {
    let data1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let data2 = u16::from_le_bytes([raw[4], raw[5]]);
    let data3 = u16::from_le_bytes([raw[6], raw[7]]);
    format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{}-{}",
        hex(&raw[8..10]).to_uppercase(),
        hex(&raw[10..16]).to_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 example messages (NIST CSRC "SHA256.pdf" and the long
    // message from the SHA test vectors).
    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_sha256_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|n| (n * 7 + 3) as u8).collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 119, 128, 999, 1000] {
            let mut hasher = Sha256::new();
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finish(), sha256(&data), "split {split}");
        }
    }

    #[test]
    fn truncated_headers_yield_no_identity() {
        // Every prefix of a header-shaped buffer must parse to nothing, not
        // panic (rule 8).
        let mut elf = [0u8; 128];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[0x20] = 0x40;
        elf[0x36] = 0x38;
        elf[0x38] = 0xff;
        elf[0x39] = 0xff;
        let mut pe = [0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        pe[0x46] = 0xff;
        pe[0x54] = 0xf0;
        pe[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes());
        for len in 0..=elf.len() {
            assert_eq!(elf_build_id(&elf[..len]), None);
        }
        for len in 0..=pe.len() {
            assert_eq!(pe_pdb_id(&pe[..len]), None);
        }
    }
}
