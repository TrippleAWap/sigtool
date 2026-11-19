//! Binary signature database with a memory-map friendly layout.
//!
//! The DB is a deterministic serialisation of a set of [`Signature`] documents.
//! It is built once (offline, or by `sigtool-native db build`) and then mapped
//! read-only by the scanner. Nothing is written to the target process, and the
//! file itself is immutable after `encode` (AGENTS.md rules 3 and 9).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! header (64 bytes)
//! spec version string (padded to 8)
//! record table (record_count * 40 bytes)
//! blob: id, name, canonical YAML payload per record, each padded to 8
//! ```
//!
//! The record table is sorted by signature id so a mapped DB can be searched
//! with a binary search without allocating. Every record points into the blob
//! with absolute offsets, so opening the file validates structure once and
//! slicing is zero-copy. Payloads carry a CRC-32 that is verified on access;
//! the table itself carries one verified at open time.
//!
//! The spec version is part of the header: a DB written for another feature
//! spec is refused instead of being interpreted with the wrong semantics
//! (AGENTS.md rule 5).

use std::collections::BTreeMap;
use std::path::Path;

use memmap2::Mmap;

use crate::errors::{DbError, SignatureError};
use crate::sigfile::Signature;
use crate::spec::SPEC_VERSION;

pub const DB_MAGIC: [u8; 8] = *b"SIGTDB\x00\x01";
pub const DB_FORMAT_VERSION: u16 = 1;
pub const DB_HEADER_SIZE: usize = 64;
pub const DB_RECORD_SIZE: usize = 40;
pub const DB_ALIGN: usize = 8;

/// One stored signature: identity, display name, and canonical YAML bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbRecord {
    pub signature_id: String,
    pub name: String,
    pub payload: Vec<u8>,
    pub crc32: u32,
}

/// An in-memory set of signatures, ready to be encoded.
#[derive(Debug, Clone, Default)]
pub struct SignatureDb {
    records: BTreeMap<String, DbRecord>,
}

impl SignatureDb {
    pub fn new() -> SignatureDb {
        SignatureDb::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Add one signature, replacing an identical identity.
    ///
    /// Re-adding the same canonical document is a no-op, which lets a build
    /// combine overlapping inputs deterministically. Two different documents
    /// cannot share an id (the id is the canonical digest), so there is no
    /// ambiguity to resolve.
    pub fn push(&mut self, signature: &Signature) -> Result<(), SignatureError> {
        let signature_id = signature.signature_id()?;
        let payload = signature.to_yaml()?.into_bytes();
        let crc32 = crc32fast::hash(&payload);
        self.records.insert(
            signature_id.clone(),
            DbRecord {
                signature_id,
                name: signature.name.clone(),
                payload,
                crc32,
            },
        );
        Ok(())
    }

    /// Add a signature from its YAML text, storing the canonical form.
    pub fn push_yaml(&mut self, text: &str) -> Result<(), SignatureError> {
        self.push(&Signature::from_yaml(text)?)
    }

    pub fn records(&self) -> impl Iterator<Item = &DbRecord> {
        self.records.values()
    }

    /// Serialise the DB. Identical inputs always produce identical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let records: Vec<&DbRecord> = self.records.values().collect();
        let spec = SPEC_VERSION.as_bytes();

        let spec_offset = DB_HEADER_SIZE;
        let records_offset = align8(spec_offset + spec.len());
        let blob_offset = records_offset + records.len() * DB_RECORD_SIZE;

        let mut blob: Vec<u8> = Vec::new();
        let mut table: Vec<u8> = Vec::with_capacity(records.len() * DB_RECORD_SIZE);
        for record in &records {
            let id_offset = blob_offset + blob.len();
            blob.extend_from_slice(record.signature_id.as_bytes());
            pad8(&mut blob);

            let name_offset = blob_offset + blob.len();
            blob.extend_from_slice(record.name.as_bytes());
            pad8(&mut blob);

            let payload_offset = blob_offset + blob.len();
            blob.extend_from_slice(&record.payload);
            pad8(&mut blob);

            table.extend_from_slice(&(id_offset as u64).to_le_bytes());
            table.extend_from_slice(&(record.signature_id.len() as u32).to_le_bytes());
            table.extend_from_slice(&(record.name.len() as u32).to_le_bytes());
            table.extend_from_slice(&(name_offset as u64).to_le_bytes());
            table.extend_from_slice(&(payload_offset as u64).to_le_bytes());
            table.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
            table.extend_from_slice(&record.crc32.to_le_bytes());
        }
        let table_crc = crc32fast::hash(&table);

        let mut out: Vec<u8> = Vec::with_capacity(blob_offset + blob.len());
        out.extend_from_slice(&DB_MAGIC);
        out.extend_from_slice(&DB_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(DB_HEADER_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&(spec.len() as u16).to_le_bytes());
        out.extend_from_slice(&(DB_RECORD_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        out.extend_from_slice(&(spec_offset as u64).to_le_bytes());
        out.extend_from_slice(&(records_offset as u64).to_le_bytes());
        out.extend_from_slice(&(blob_offset as u64).to_le_bytes());
        out.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        out.extend_from_slice(&table_crc.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        debug_assert_eq!(out.len(), DB_HEADER_SIZE);

        out.extend_from_slice(spec);
        pad8(&mut out);
        debug_assert_eq!(out.len(), records_offset);
        out.extend_from_slice(&table);
        out.extend_from_slice(&blob);
        out
    }
}

/// A validated, zero-copy view over encoded DB bytes.
#[derive(Debug, Clone, Copy)]
pub struct DbView<'a> {
    data: &'a [u8],
    count: usize,
    records_offset: usize,
    blob_offset: usize,
    blob_len: usize,
    spec_version: &'a str,
}

impl<'a> DbView<'a> {
    /// Validate the header, table, and record bounds.
    ///
    /// Payload CRCs are checked lazily by [`DbView::payload`] so opening a large
    /// DB stays cheap; the table CRC covers the offsets themselves.
    pub fn parse(data: &'a [u8]) -> Result<DbView<'a>, SignatureError> {
        if data.len() < DB_HEADER_SIZE {
            return Err(db_error(format!(
                "database is {} bytes, shorter than the {DB_HEADER_SIZE}-byte header",
                data.len()
            )));
        }
        if data[0..8] != DB_MAGIC {
            return Err(db_error("not a sigtool database (bad magic)"));
        }
        let format_version = read_u16(data, 8)?;
        if format_version != DB_FORMAT_VERSION {
            return Err(db_error(format!(
                "unsupported database format version {format_version}"
            )));
        }
        let header_size = read_u16(data, 10)? as usize;
        if header_size != DB_HEADER_SIZE {
            return Err(db_error(format!(
                "unsupported database header size {header_size}"
            )));
        }
        let flags = read_u32(data, 12)?;
        if flags != 0 {
            return Err(db_error(format!("unsupported database flags 0x{flags:x}")));
        }
        let spec_len = read_u16(data, 16)? as usize;
        let record_size = read_u16(data, 18)? as usize;
        if record_size != DB_RECORD_SIZE {
            return Err(db_error(format!(
                "unsupported database record size {record_size}"
            )));
        }
        let count = read_u32(data, 20)? as usize;
        let spec_offset = read_u64(data, 24)? as usize;
        let records_offset = read_u64(data, 32)? as usize;
        let blob_offset = read_u64(data, 40)? as usize;
        let blob_len = read_u64(data, 48)? as usize;
        let table_crc = read_u32(data, 56)?;

        if spec_offset != DB_HEADER_SIZE {
            return Err(db_error(format!(
                "spec version offset {spec_offset} is not {DB_HEADER_SIZE}"
            )));
        }
        let spec_end = spec_offset
            .checked_add(spec_len)
            .ok_or_else(|| db_error("spec version length overflows"))?;
        if spec_end > data.len() {
            return Err(db_error("spec version extends past end of file"));
        }
        let spec_version = std::str::from_utf8(&data[spec_offset..spec_end])
            .map_err(|_| db_error("spec version is not UTF-8"))?;
        if spec_version != SPEC_VERSION {
            // Features mean different things across spec versions, so the
            // DB cannot be converted, only rebuilt; the message says how.
            return Err(db_error(format!(
                "database spec version {spec_version:?} is not {SPEC_VERSION:?}; \
                 rebuild it with this sigtool-native: `db build --file IMAGE --functions F.json \
                 --output DB` re-signs the functions from their image, or `db build --signature` \
                 takes regenerated signatures"
            )));
        }

        let table_len = count
            .checked_mul(DB_RECORD_SIZE)
            .ok_or_else(|| db_error("record table length overflows"))?;
        let table_end = records_offset
            .checked_add(table_len)
            .ok_or_else(|| db_error("record table extends past end of file"))?;
        let blob_end = blob_offset
            .checked_add(blob_len)
            .ok_or_else(|| db_error("blob extends past end of file"))?;
        if table_end > data.len() || blob_end > data.len() {
            return Err(db_error("record table or blob extends past end of file"));
        }
        if table_end > blob_offset {
            return Err(db_error("record table overlaps the blob"));
        }
        if crc32fast::hash(&data[records_offset..table_end]) != table_crc {
            return Err(db_error("record table checksum mismatch"));
        }

        let view = DbView {
            data,
            count,
            records_offset,
            blob_offset,
            blob_len,
            spec_version,
        };
        view.validate_records()?;
        Ok(view)
    }

    fn validate_records(&self) -> Result<(), SignatureError> {
        let mut previous: Option<&str> = None;
        for index in 0..self.count {
            let id = self.signature_id(index)?;
            if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(db_error(format!(
                    "record {index} has an invalid signature id {id:?}"
                )));
            }
            if let Some(previous) = previous {
                if previous >= id {
                    return Err(db_error(format!(
                        "record ids are not strictly sorted at index {index}"
                    )));
                }
            }
            previous = Some(id);
            let name = self.name(index)?;
            if name.is_empty() {
                return Err(db_error(format!("record {index} has an empty name")));
            }
            // Payload bounds are checked here; the CRC is checked on access.
            self.payload_bounds(index)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn spec_version(&self) -> &'a str {
        self.spec_version
    }

    /// Signature id for one record, borrowed from the mapped blob.
    pub fn signature_id(&self, index: usize) -> Result<&'a str, SignatureError> {
        let (offset, len) = self.field(index, 0, 8)?;
        std::str::from_utf8(self.slice(offset, len)?)
            .map_err(|_| db_error(format!("record {index} id is not UTF-8")))
    }

    /// Display name for one record, borrowed from the mapped blob.
    pub fn name(&self, index: usize) -> Result<&'a str, SignatureError> {
        let name_len = read_u32(self.record(index)?, 12)? as usize;
        let name_offset = read_u64(self.record(index)?, 16)? as usize;
        std::str::from_utf8(self.slice(name_offset, name_len)?)
            .map_err(|_| db_error(format!("record {index} name is not UTF-8")))
    }

    /// Canonical YAML payload for one record, after verifying its checksum.
    pub fn payload(&self, index: usize) -> Result<&'a [u8], SignatureError> {
        let (offset, len) = self.payload_bounds(index)?;
        let expected = read_u32(self.record(index)?, 36)?;
        let payload = self.slice(offset, len)?;
        let actual = crc32fast::hash(payload);
        if actual != expected {
            return Err(db_error(format!(
                "record {index} payload checksum mismatch (stored {expected:08x}, actual {actual:08x})"
            )));
        }
        Ok(payload)
    }

    /// Parse one record back into a [`Signature`].
    ///
    /// The stored id is re-derived from the payload, so a DB that was edited by
    /// hand cannot silently change what a signature means.
    pub fn signature(&self, index: usize) -> Result<Signature, SignatureError> {
        let payload = self.payload(index)?;
        let text = std::str::from_utf8(payload)
            .map_err(|_| db_error(format!("record {index} payload is not UTF-8")))?;
        let signature = Signature::from_yaml(text)?;
        if signature.signature_id()? != self.signature_id(index)? {
            return Err(db_error(format!(
                "record {index} payload does not match its signature id"
            )));
        }
        Ok(signature)
    }

    /// Binary search by signature id; `None` when absent.
    pub fn find(&self, signature_id: &str) -> Result<Option<usize>, SignatureError> {
        let mut low = 0usize;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            match self.signature_id(middle)?.cmp(signature_id) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }

    /// Parse every record, in stored (id) order.
    pub fn signatures(&self) -> Result<Vec<Signature>, SignatureError> {
        (0..self.count).map(|index| self.signature(index)).collect()
    }

    // -- internals ---------------------------------------------------------

    fn record(&self, index: usize) -> Result<&'a [u8], SignatureError> {
        if index >= self.count {
            return Err(db_error(format!(
                "record index {index} is out of range (count {})",
                self.count
            )));
        }
        let start = self.records_offset + index * DB_RECORD_SIZE;
        Ok(&self.data[start..start + DB_RECORD_SIZE])
    }

    fn payload_bounds(&self, index: usize) -> Result<(usize, usize), SignatureError> {
        let record = self.record(index)?;
        let offset = read_u64(record, 24)? as usize;
        let len = read_u32(record, 32)? as usize;
        self.slice(offset, len)?;
        Ok((offset, len))
    }

    /// `(offset, len)` for the id field (record bytes 0 and 8).
    fn field(
        &self,
        index: usize,
        offset_at: usize,
        len_at: usize,
    ) -> Result<(usize, usize), SignatureError> {
        let record = self.record(index)?;
        let offset = read_u64(record, offset_at)? as usize;
        let len = read_u32(record, len_at)? as usize;
        self.slice(offset, len)?;
        Ok((offset, len))
    }

    fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8], SignatureError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| db_error("record field length overflows"))?;
        let blob_end = self.blob_offset + self.blob_len;
        if offset < self.blob_offset || end > blob_end || end > self.data.len() {
            return Err(db_error(format!(
                "record field 0x{offset:x}..0x{end:x} is outside the blob"
            )));
        }
        Ok(&self.data[offset..end])
    }
}

/// A memory-mapped DB file. The view borrows the mapping, so the map lives as
/// long as the reader needs it without copying the blob.
pub struct MappedDb {
    mmap: Mmap,
}

impl MappedDb {
    pub fn open(path: &Path) -> Result<MappedDb, DbError> {
        let file = std::fs::File::open(path)
            .map_err(|error| DbError(format!("cannot open {}: {error}", path.display())))?;
        // SAFETY: the DB is documented as immutable; mapping is read-only and
        // the scanner never writes through it.
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|error| DbError(format!("cannot map {}: {error}", path.display())))?;
        Ok(MappedDb { mmap })
    }

    pub fn view(&self) -> Result<DbView<'_>, SignatureError> {
        DbView::parse(&self.mmap)
    }
}

fn align8(value: usize) -> usize {
    value.div_ceil(DB_ALIGN) * DB_ALIGN
}

fn pad8(buffer: &mut Vec<u8>) {
    let padded = align8(buffer.len());
    buffer.resize(padded, 0);
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, SignatureError> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| db_error("truncated header"))?
        .try_into()
        .expect("slice length");
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, SignatureError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| db_error("truncated field"))?
        .try_into()
        .expect("slice length");
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, SignatureError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| db_error("truncated field"))?
        .try_into()
        .expect("slice length");
    Ok(u64::from_le_bytes(bytes))
}

fn db_error(message: impl Into<String>) -> SignatureError {
    SignatureError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::FeatureKind;
    use crate::sigfile::{SampleProvenance, SignatureFeature};

    fn signature(name: &str, value: &str, rva: u64) -> Signature {
        Signature::new(
            name,
            vec![
                SignatureFeature {
                    kind: FeatureKind::Str,
                    value: value.to_string(),
                    weight: 1.2,
                    required: true,
                },
                SignatureFeature {
                    kind: FeatureKind::Cfg,
                    value: "blocks:1".to_string(),
                    weight: 0.25,
                    required: false,
                },
            ],
            vec![format!("str:{value}")],
            0.85,
            1,
            "single-arch",
            vec![SampleProvenance {
                arch: "x64".to_string(),
                module: "fixture".to_string(),
                rva,
                opt: Some("O2".to_string()),
                tool: Some("test".to_string()),
            }],
        )
        .expect("valid signature")
    }

    fn sample_db() -> SignatureDb {
        let mut db = SignatureDb::new();
        db.push(&signature("first", "alpha literal", 0x1000))
            .unwrap();
        db.push(&signature("second", "beta literal", 0x2000))
            .unwrap();
        db
    }

    #[test]
    fn round_trips_signatures_and_lookup() {
        let db = sample_db();
        let bytes = db.encode();
        let view = DbView::parse(&bytes).expect("parse");

        assert_eq!(view.len(), 2);
        assert_eq!(view.spec_version(), SPEC_VERSION);
        let parsed = view.signatures().expect("signatures");
        assert_eq!(parsed.len(), 2);
        let names: std::collections::HashSet<&str> = parsed
            .iter()
            .map(|signature| signature.name.as_str())
            .collect();
        assert_eq!(names, ["first", "second"].into_iter().collect());
        for signature in &parsed {
            let id = signature.signature_id().unwrap();
            let index = view.find(&id).expect("find").expect("present");
            assert_eq!(view.signature_id(index).unwrap(), id);
            assert_eq!(view.name(index).unwrap(), signature.name);
            assert_eq!(&view.signature(index).unwrap(), signature);
        }
        assert_eq!(view.find("00000000000000000000000000000000").unwrap(), None);
    }

    #[test]
    fn encoding_is_deterministic_and_order_independent() {
        let forward = sample_db().encode();
        let mut reverse = SignatureDb::new();
        reverse
            .push(&signature("second", "beta literal", 0x2000))
            .unwrap();
        reverse
            .push(&signature("first", "alpha literal", 0x1000))
            .unwrap();
        assert_eq!(forward, reverse.encode());
        assert_eq!(forward, sample_db().encode());
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let bytes = sample_db().encode();
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(DbView::parse(&bad_magic).is_err());
        assert!(DbView::parse(&bytes[..DB_HEADER_SIZE - 1]).is_err());
        assert!(DbView::parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn rejects_a_foreign_spec_version() {
        let mut bytes = sample_db().encode();
        // The spec string sits immediately after the fixed header.
        assert_eq!(bytes[DB_HEADER_SIZE], SPEC_VERSION.as_bytes()[0]);
        bytes[DB_HEADER_SIZE] = b'0';
        let error = DbView::parse(&bytes).expect_err("spec mismatch");
        assert!(error.to_string().contains("spec version"), "{error}");
    }

    #[test]
    fn detects_table_and_payload_corruption() {
        let bytes = sample_db().encode();
        let records_offset = read_u64(&bytes, 32).unwrap() as usize;

        let mut bad_table = bytes.clone();
        bad_table[records_offset] ^= 0xFF;
        assert!(DbView::parse(&bad_table).is_err());

        let mut bad_payload = bytes.clone();
        let payload_offset = read_u64(&bad_payload, records_offset + 24).unwrap() as usize;
        bad_payload[payload_offset] ^= 0xFF;
        let view = DbView::parse(&bad_payload).expect("structure still valid");
        assert!(view.signatures().is_err());
    }

    #[test]
    fn empty_database_round_trips() {
        let bytes = SignatureDb::new().encode();
        let view = DbView::parse(&bytes).expect("parse");
        assert!(view.is_empty());
        assert_eq!(view.len(), 0);
        assert!(view.signatures().unwrap().is_empty());
    }
}
