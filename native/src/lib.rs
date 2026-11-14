//! Native implementation of the sigtool feature signature spec.
//!
//! The crate mirrors the Python reference implementation in `core/`: one
//! extractor for generation and scanning, bounded recovery over untrusted
//! bytes, and deterministic output. x86-64 is the reference architecture and
//! the first port; AArch64, ARM32, and Thumb are ported as well. x64 decodes
//! through `iced-x86`, AArch64 through `yaxpeax-arm`, and ARM32/Thumb through
//! Capstone (the reference's decoder, needed for VFP/NEON and the ARMv7 media
//! group).

pub mod arch;
mod arm32;
mod arm64;
pub mod bench;
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
pub mod unwind;
pub mod validate;
