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

/// A command running `name`, found on Windows too (see `program`).
#[allow(dead_code)] // not every test binary that includes this module runs a tool by name
pub fn command(name: &str) -> Command {
    Command::new(program(name))
}

/// Whether every tool in `tools` runs. A missing tool skips the calling
/// test, except under `SIGTOOL_REQUIRE_TOOLS` (set in CI, where LLVM is
/// installed), where a skip would pass a test that never ran.
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
    assert!(
        std::env::var_os("SIGTOOL_REQUIRE_TOOLS").is_none(),
        "SIGTOOL_REQUIRE_TOOLS is set but {} did not run",
        missing.join(", ")
    );
    eprintln!("skip: {} not found", missing.join(", "));
    false
}
