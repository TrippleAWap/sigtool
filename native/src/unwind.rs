//! Function entries from unwind metadata: `.eh_frame`, `.ARM.exidx`, `.pdata`.
//!
//! Stripping removes `.symtab`, but not the tables the runtime needs to unwind
//! the stack: x86-64 and AArch64 ELF keep `.eh_frame` (one FDE per function,
//! with its start and length), ARM EABI keeps `.ARM.exidx` (one entry per
//! function start), and PE keeps `.pdata` (`RUNTIME_FUNCTION`). These are
//! exact entries recovered from the image itself, not symbol hints, so
//! hint-free discovery may use them.
//!
//! The bytes are target data and therefore untrusted (AGENTS.md rule 8):
//! every read is bounds-checked, every length is validated against the
//! section, and the number of entries is capped.

use crate::source::Region;

/// Upper bound on entries taken from one table (a hostile length field must
/// not make parsing unbounded).
pub const MAX_UNWIND_ENTRIES: usize = 1 << 20;

/// One function described by unwind data: `[start, end)`, `end == 0` when the
/// table gives only the start.
pub type UnwindEntry = (u64, u64);

/// Parse every ELF unwind table present in `regions` (by section name).
///
/// Entries are sorted by start, deduplicated, and restricted to starts inside
/// an executable region.
pub fn elf_entries(regions: &[Region], pointer_size: usize) -> Vec<UnwindEntry> {
    elf_table_entries(regions, regions, pointer_size)
}

/// [`elf_entries`] over `tables` (named as sections), keeping the starts that
/// lie in `regions`' code: an image without section headers has its tables
/// only as views into a loaded segment.
pub fn elf_table_entries(
    tables: &[Region],
    regions: &[Region],
    pointer_size: usize,
) -> Vec<UnwindEntry> {
    let mut entries = Vec::new();
    for region in tables {
        match region.name.as_str() {
            ".eh_frame" => entries.extend(eh_frame(region, pointer_size)),
            ".ARM.exidx" => entries.extend(arm_exidx(region)),
            _ => {}
        }
    }
    finish(entries, regions)
}

/// Sort, deduplicate, and drop entries that do not start in executable code.
pub fn finish(mut entries: Vec<UnwindEntry>, regions: &[Region]) -> Vec<UnwindEntry> {
    entries.retain(|(start, _)| {
        regions
            .iter()
            .any(|region| region.executable && region.start <= *start && *start < region.end())
    });
    entries.sort_unstable();
    // Keep the widest description of each start.
    entries.dedup_by(|later, earlier| {
        if later.0 == earlier.0 {
            earlier.1 = earlier.1.max(later.1);
            true
        } else {
            false
        }
    });
    entries.truncate(MAX_UNWIND_ENTRIES);
    entries
}

// -- .ARM.exidx -----------------------------------------------------------------

/// Each 8-byte entry starts with a prel31 offset to the function. Entries are
/// sorted and contiguous, so an entry's function ends where the next begins;
/// the last entry's end is unknown.
fn arm_exidx(region: &Region) -> Vec<UnwindEntry> {
    let mut starts = Vec::new();
    for (index, chunk) in region.data.as_chunks::<8>().0.iter().enumerate() {
        if index >= MAX_UNWIND_ENTRIES {
            break;
        }
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if word & 0x8000_0000 != 0 {
            continue;
        }
        let offset = ((word << 1) as i32 >> 1) as i64;
        let place = region.start + (index * 8) as u64;
        // The Thumb bit, if a toolchain sets it, is not part of the address.
        starts.push((place as i64).wrapping_add(offset) as u64 & !1);
    }
    starts.sort_unstable();
    starts.dedup();
    let mut entries = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        entries.push((*start, starts.get(index + 1).copied().unwrap_or(0)));
    }
    entries
}

// -- .eh_frame ------------------------------------------------------------------

const DW_EH_PE_OMIT: u8 = 0xff;
/// Longest CIE augmentation string read. GCC and clang emit at most a few
/// letters (`zPLRSB`); an FDE can name any offset as its CIE, so an unbounded
/// scan per out-of-order CIE would make one table quadratic.
const MAX_AUGMENTATION: usize = 32;

/// Bounded little-endian cursor over one region.
struct Cursor<'a> {
    data: &'a [u8],
    base: u64,
    pos: usize,
}

impl Cursor<'_> {
    fn address(&self) -> u64 {
        self.base + self.pos as u64
    }
    fn take(&mut self, size: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(size)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            value |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    value |= -1i64 << shift;
                }
                return Some(value);
            }
            if shift >= 64 {
                return None;
            }
        }
    }
    /// A NUL-terminated string of at most `max` bytes.
    fn cstr(&mut self, max: usize) -> Option<&[u8]> {
        let rest = self.data.get(self.pos..)?;
        let window = &rest[..rest.len().min(max.saturating_add(1))];
        let length = window.iter().position(|byte| *byte == 0)?;
        let text = &rest[..length];
        self.pos += length + 1;
        Some(text)
    }

    /// A pointer in DWARF EH encoding. `pcrel` is the only base used for code
    /// addresses by GCC and clang; `datarel` and the others need a base the
    /// FDE does not carry and are rejected.
    fn encoded(&mut self, encoding: u8, pointer_size: usize) -> Option<u64> {
        if encoding == DW_EH_PE_OMIT {
            return None;
        }
        let place = self.address();
        let value: i64 = match encoding & 0x0f {
            0x00 => match pointer_size {
                8 => self.u64()? as i64,
                _ => self.u32()? as i64,
            },
            0x01 => self.uleb()? as i64,
            0x02 => self.u16()? as i64,
            0x03 => self.u32()? as i64,
            0x04 => self.u64()? as i64,
            0x09 => self.sleb()?,
            0x0a => self.u16()? as i16 as i64,
            0x0b => self.u32()? as i32 as i64,
            0x0c => self.u64()? as i64,
            _ => return None,
        };
        match encoding & 0x70 {
            0x00 => Some(value as u64),
            0x10 => Some((place as i64).wrapping_add(value) as u64),
            _ => None,
        }
    }
}

/// CIE fields an FDE needs: its pointer encoding.
struct Cie {
    fde_encoding: u8,
}

fn parse_cie(cursor: &mut Cursor<'_>, pointer_size: usize) -> Option<Cie> {
    let version = cursor.u8()?;
    let augmentation = cursor.cstr(MAX_AUGMENTATION)?.to_vec();
    if augmentation.windows(2).any(|pair| pair == b"eh") {
        cursor.take(pointer_size)?;
    }
    cursor.uleb()?; // code alignment
    cursor.sleb()?; // data alignment
    if version == 1 {
        cursor.u8()?;
    } else {
        cursor.uleb()?;
    }
    let mut fde_encoding = 0u8; // absptr
    if augmentation.first() == Some(&b'z') {
        cursor.uleb()?;
        for flag in &augmentation[1..] {
            match flag {
                b'R' => fde_encoding = cursor.u8()?,
                b'L' => {
                    cursor.u8()?;
                }
                b'P' => {
                    let encoding = cursor.u8()?;
                    // The personality pointer's value is irrelevant; it only
                    // has to be consumed with the right width.
                    cursor.encoded(encoding & 0x0f, pointer_size);
                }
                b'S' | b'B' | b'G' => {}
                _ => return None,
            }
        }
    }
    Some(Cie { fde_encoding })
}

fn eh_frame(region: &Region, pointer_size: usize) -> Vec<UnwindEntry> {
    let mut entries = Vec::new();
    let mut cies: std::collections::HashMap<usize, Option<Cie>> = std::collections::HashMap::new();
    let mut cursor = Cursor {
        data: &region.data,
        base: region.start,
        pos: 0,
    };
    while entries.len() < MAX_UNWIND_ENTRIES {
        let entry_start = cursor.pos;
        let Some(length) = cursor.u32() else { break };
        if length == 0 {
            break; // terminator
        }
        let (length, header) = if length == 0xffff_ffff {
            let Some(length) = cursor.u64() else { break };
            (length, 12usize)
        } else {
            (u64::from(length), 4usize)
        };
        let Some(end) = entry_start
            .checked_add(header)
            .and_then(|start| start.checked_add(usize::try_from(length).ok()?))
            .filter(|end| *end <= region.data.len())
        else {
            break;
        };
        let id_pos = cursor.pos;
        let Some(id) = cursor.u32() else { break };
        if id == 0 {
            let mut cie_cursor = Cursor {
                data: &region.data[..end],
                base: region.start,
                pos: cursor.pos,
            };
            cies.insert(entry_start, parse_cie(&mut cie_cursor, pointer_size));
        } else if let Some(cie_start) = id_pos.checked_sub(id as usize) {
            let cie = match cies.get(&cie_start) {
                Some(cie) => cie.as_ref().map(|cie| cie.fde_encoding),
                None => {
                    // CIEs normally precede their FDEs; parse one out of order
                    // once and remember it.
                    let mut cie_cursor = Cursor {
                        data: &region.data,
                        base: region.start,
                        pos: cie_start + 8,
                    };
                    let parsed = parse_cie(&mut cie_cursor, pointer_size);
                    let encoding = parsed.as_ref().map(|cie| cie.fde_encoding);
                    cies.insert(cie_start, parsed);
                    encoding
                }
            };
            if let Some(encoding) = cie {
                let mut fde = Cursor {
                    data: &region.data[..end],
                    base: region.start,
                    pos: cursor.pos,
                };
                if let Some(start) = fde.encoded(encoding, pointer_size) {
                    // pc_range uses the same width, never a base.
                    let range = fde.encoded(encoding & 0x0f, pointer_size).unwrap_or(0);
                    if start != 0 {
                        let end_address = if range > 0 && range < 0x100_0000 {
                            start.wrapping_add(range)
                        } else {
                            0
                        };
                        entries.push((start, end_address));
                    }
                }
            }
        }
        cursor.pos = end;
    }
    entries
}

/// `.eh_frame`'s address range, found from `.eh_frame_hdr` (`hdr`, the bytes
/// `PT_GNU_EH_FRAME` maps) and the `region` holding the frame data, for an
/// image without section headers (`llvm-objcopy --strip-sections`): the
/// loader keeps only segments, and the header is how unwinders find frames.
///
/// The end is the furthest FDE the binary-search table lists, so the parse
/// stops where the frames do even without a terminator (lld writes none for
/// `-nostdlib` links). Without a usable table it is the region's end.
pub fn eh_frame_extent(hdr: &Region, regions: &[Region]) -> Option<(u64, u64)> {
    const DW_EH_PE_DATAREL_SDATA4: u8 = 0x3b;
    let mut cursor = Cursor {
        data: &hdr.data,
        base: hdr.start,
        pos: 0,
    };
    if cursor.u8()? != 1 {
        return None;
    }
    let pointer_encoding = cursor.u8()?;
    let count_encoding = cursor.u8()?;
    let table_encoding = cursor.u8()?;
    // The header's own pointers are 4-byte encodings in every toolchain;
    // `absptr` would need the class, which only these two forms avoid.
    let start = cursor.encoded(pointer_encoding, 4)?;
    let region = regions
        .iter()
        .find(|region| region.start <= start && start < region.end())?;
    let region_end = region.end();
    let Some(count) = cursor.encoded(count_encoding, 4) else {
        return Some((start, region_end));
    };
    if table_encoding != DW_EH_PE_DATAREL_SDATA4 {
        return Some((start, region_end));
    }
    let mut end = start;
    let rows = usize::try_from(count).unwrap_or(usize::MAX);
    for _ in 0..rows.min(MAX_UNWIND_ENTRIES) {
        let (Some(_), Some(fde)) = (cursor.u32(), cursor.u32()) else {
            break;
        };
        let fde = hdr.start.wrapping_add(fde as i32 as i64 as u64);
        if fde < start || fde >= region_end {
            continue;
        }
        let at = (fde - region.start) as usize;
        let Some(length) = region.data.get(at..at + 4) else {
            continue;
        };
        let length = u32::from_le_bytes([length[0], length[1], length[2], length[3]]);
        let extent = if length == 0xffff_ffff {
            let Some(long) = region.data.get(at + 4..at + 12) else {
                continue;
            };
            u64::from_le_bytes(long.try_into().expect("8 bytes")).saturating_add(12)
        } else {
            u64::from(length) + 4
        };
        end = end.max(fde.saturating_add(extent).min(region_end));
    }
    Some((start, end))
}

// -- PE .pdata ------------------------------------------------------------------

/// `RUNTIME_FUNCTION` entries. x64 entries are 12 bytes (begin, end, unwind
/// RVAs); ARM64 entries are 8 bytes (begin RVA, packed or .xdata RVA), with
/// the function length in the packed form only.
pub fn pdata(data: &[u8], image_base: u64, arm64: bool) -> Vec<UnwindEntry> {
    pdata_with(data, image_base, arm64, &|_| None)
}

/// [`pdata`], reading an AArch64 entry's `.xdata` record through `xdata`
/// (an RVA to its first word). A packed entry carries its length in the
/// `.pdata` word itself; an unpacked one points at `.xdata`, whose first
/// word holds the length in words (bits 0-17). Without it the entry has no
/// end, so a tail `b` out of the function looks like a branch inside it and
/// its target is never offered as a start (`starts::arm64_call_targets_checked`).
pub fn pdata_with(
    data: &[u8],
    image_base: u64,
    arm64: bool,
    xdata: &dyn Fn(u64) -> Option<u32>,
) -> Vec<UnwindEntry> {
    let mut entries = Vec::new();
    if arm64 {
        for chunk in data.as_chunks::<8>().0.iter().take(MAX_UNWIND_ENTRIES) {
            let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let unwind = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            if begin == 0 {
                continue;
            }
            let start = image_base + u64::from(begin);
            let end = if unwind & 0b11 != 0 {
                start + u64::from((unwind >> 2) & 0x7ff) * 4
            } else {
                xdata(u64::from(unwind))
                    .map(|header| u64::from(header & 0x3_ffff) * 4)
                    .filter(|length| *length > 0)
                    .map_or(0, |length| start + length)
            };
            entries.push((start, end));
        }
    } else {
        for chunk in data.as_chunks::<12>().0.iter().take(MAX_UNWIND_ENTRIES) {
            let begin = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            if begin == 0 || end <= begin {
                continue;
            }
            entries.push((image_base + u64::from(begin), image_base + u64::from(end)));
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str, start: u64, data: Vec<u8>, executable: bool) -> Region {
        Region::new(name.to_string(), start, data, executable, false)
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut state = 0x1234_5678u32;
        for size in [0usize, 1, 7, 8, 13, 64, 4096] {
            let data: Vec<u8> = (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
            let regions = vec![
                region(".text", 0x1000, vec![0; 0x1000], true),
                region(".eh_frame", 0x3000, data.clone(), false),
                region(".ARM.exidx", 0x5000, data.clone(), false),
            ];
            let _ = elf_entries(&regions, 8);
            let _ = elf_entries(&regions, 4);
            for header in [data.clone(), [&[1u8, 0x1b, 0x03, 0x3b][..], &data].concat()] {
                let hdr = region(".eh_frame_hdr", 0x2ff0, header, false);
                if let Some((start, end)) = eh_frame_extent(&hdr, &regions) {
                    assert!(start <= end);
                }
            }
            let _ = pdata(&data, 0x1_4000_0000, false);
            let _ = pdata(&data, 0x1_4000_0000, true);
        }
    }

    #[test]
    fn exidx_prel31_resolves_backwards() {
        // Entry at 0x5000 pointing 0x4000 back -> 0x1000.
        let offset = (-0x4000i32 as u32) & 0x7fff_ffff;
        let mut data = offset.to_le_bytes().to_vec();
        data.extend_from_slice(&1u32.to_le_bytes()); // EXIDX_CANTUNWIND
        let regions = vec![
            region(".text", 0x1000, vec![0; 0x100], true),
            region(".ARM.exidx", 0x5000, data, false),
        ];
        assert_eq!(elf_entries(&regions, 4), vec![(0x1000, 0)]);
    }

    /// One CIE with `augmentation` (`R` encoding pcrel sdata4) and one FDE
    /// for `[0x1000, 0x1040)`, for a table placed at 0x3000.
    fn eh_frame_with(augmentation: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0, 1];
        body.extend_from_slice(augmentation);
        body.extend_from_slice(&[0, 1, 0x78, 16, 1, 0x1b]);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut table = (body.len() as u32).to_le_bytes().to_vec();
        table.extend_from_slice(&body);
        let fde_start = table.len();
        let place = 0x3000 + fde_start as i64 + 8;
        let mut fde = ((fde_start + 4) as u32).to_le_bytes().to_vec();
        fde.extend_from_slice(&((0x1000 - place) as i32).to_le_bytes());
        fde.extend_from_slice(&0x40i32.to_le_bytes());
        fde.extend_from_slice(&[0, 0, 0, 0]);
        table.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        table.extend_from_slice(&fde);
        table.extend_from_slice(&[0, 0, 0, 0]);
        table
    }

    #[test]
    fn cie_augmentation_scan_is_bounded() {
        let entries = |augmentation: &[u8]| {
            let regions = vec![
                region(".text", 0x1000, vec![0; 0x100], true),
                region(".eh_frame", 0x3000, eh_frame_with(augmentation), false),
            ];
            elf_entries(&regions, 8)
        };
        assert_eq!(entries(&b"zR"[..]), vec![(0x1000, 0x1040)]);
        // 'S' (signal frame) reads no augmentation data, so "zRSS..." parses
        // at any length unless the length cap rejects it: one byte at the cap
        // still parses, one past it does not.
        let mut at_cap = b"zR".to_vec();
        at_cap.resize(MAX_AUGMENTATION, b'S');
        assert_eq!(entries(at_cap.as_slice()), vec![(0x1000, 0x1040)]);
        let mut over_cap = at_cap.clone();
        over_cap.push(b'S');
        assert_eq!(entries(over_cap.as_slice()), Vec::new());
    }
}
