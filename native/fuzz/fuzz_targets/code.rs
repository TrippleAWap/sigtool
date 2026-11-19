//! Raw code bytes, architecture from the first byte: decode, recovery,
//! feature extraction, and start synthesis (`hostile::code`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/hostile/mod.rs"]
mod hostile;

fuzz_target!(|data: &[u8]| hostile::code(data));
