//! Tool checks shared by the tests that build their inputs with LLVM.

use std::ffi::OsString;
use std::process::Command;

/// The program name to run `name` by. On Windows, std appends `.exe` only to
/// a name with no extension, so `ld.lld` is searched for as a file literally
/// named `ld.lld` and never found; the executable is named in full there.
fn program(name: &str) -> OsString {
    let suffix = std::env::consts::EXE_SUFFIX;
    if name.ends_with(suffix) {
        name.into()
    } else {
        format!("{name}{suffix}").into()
    }
}

/// Whether every tool in `tools` runs; a missing tool skips the calling test.
pub fn have_tools(tools: &[&str]) -> bool {
    let missing: Vec<&str> = tools
        .iter()
        .copied()
        .filter(|tool| {
            !Command::new(program(tool))
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        })
        .collect();
    if missing.is_empty() {
        return true;
    }
    eprintln!("skip: {} not found", missing.join(", "));
    false
}
