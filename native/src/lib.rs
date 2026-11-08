//! Native implementation of the sigtool feature signature spec.
//!
//! The crate mirrors the Python reference implementation in `core/`: one
//! extractor for generation and scanning, bounded recovery over untrusted
//! bytes, and deterministic output. x86-64 is the reference architecture and
//! the first port; AArch64 is ported next, ARM32/Thumb are follow-ups.

pub mod arch;
mod arm64;
pub mod db;
pub mod elf;
pub mod errors;
pub mod features;
pub mod generate;
pub mod matcher;
pub mod merge;
pub mod normalize;
pub mod recover;
pub mod scanner;
pub mod score;
pub mod sigfile;
pub mod source;
pub mod spec;
pub mod validate;
