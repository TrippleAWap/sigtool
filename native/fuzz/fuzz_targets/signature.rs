//! Signature YAML documents (`hostile::signature_yaml`).
#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/hostile/mod.rs"]
mod hostile;

fuzz_target!(|data: &[u8]| hostile::signature_yaml(data));
