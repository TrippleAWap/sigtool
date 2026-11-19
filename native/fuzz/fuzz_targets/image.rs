//! ELF and PE image files as `--file` opens them, then bounded recovery and
//! feature extraction (`hostile::image`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/hostile/mod.rs"]
mod hostile;

fuzz_target!(|data: &[u8]| hostile::image(data));
