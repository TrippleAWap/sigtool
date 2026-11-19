//! Live Windows process source: read-only access, architecture checks, module
//! enumeration, and `gen --pid` / `locate --pid` / `scan --pid` end to end.
//!
//! The target is this test binary re-run as a helper (`helper_process`, gated
//! on an environment variable): it reports the address of `known_function`
//! and waits on stdin. Nothing is hardcoded; the PID and address come from the
//! child, and every spawned process is killed when its guard drops.
#![cfg(all(windows, target_pointer_width = "64"))]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sigtool_native::arch::Arch;
use sigtool_native::proc_win::{ProcessError, ProcessSource, MUTATING_ACCESS, OPEN_ACCESS};
use sigtool_native::source::ByteSource;
use sigtool_native::spec::MAX_READ_BYTES;

const HELPER_ENV: &str = "SIGTOOL_LIVE_PROC_HELPER";
const ADDR_PREFIX: &str = "SIGTOOL_HELPER_ADDR=";

/// A function with distinctive strings and constants, so its signature is
/// strong enough to be re-found by `locate` and `scan`.
#[inline(never)]
pub fn known_function(seed: u64) -> u64 {
    let banner = std::hint::black_box("sigtool live-process known function banner");
    let mut acc = seed ^ 0x5bd1_e995_7f4a_7c15;
    for (index, byte) in banner.bytes().enumerate() {
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(byte) ^ index as u64;
        if acc & 0xff == 0x42 {
            acc = acc.rotate_left(13) ^ 0x2545_f491_4f6c_dd1d;
        }
    }
    if acc % 7 == 3 {
        acc = acc.wrapping_add(std::hint::black_box(0x9e37_79b9));
    }
    acc
}

/// Helper mode: report `known_function` and block until stdin closes.
#[test]
fn helper_process() {
    if std::env::var_os(HELPER_ENV).is_none() {
        return;
    }
    let function: fn(u64) -> u64 = known_function;
    std::hint::black_box(function(std::hint::black_box(1)));
    println!("{ADDR_PREFIX}0x{:x}", function as usize);
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
}

/// A spawned process, killed and reaped on drop.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_helper() -> (Guard, u64) {
    let exe = std::env::current_exe().expect("current test executable");
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "helper_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");
    let stdout = child.stdout.take().expect("helper stdout");
    let guard = Guard(child);
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    // Bounded: libtest prints a few header lines before the helper's own.
    for _ in 0..64 {
        line.clear();
        if reader.read_line(&mut line).expect("read helper stdout") == 0 {
            break;
        }
        // libtest may print `test helper_process ... ` on the same line.
        if let Some((_, text)) = line.trim().split_once(ADDR_PREFIX) {
            let addr = u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("hex addr");
            return (guard, addr);
        }
    }
    panic!("helper did not report its function address");
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sigtool-native"))
}

fn run(command: &mut Command) -> (i32, String, String) {
    let output = command.output().expect("run sigtool-native");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn exe_stem() -> String {
    let exe = std::env::current_exe().expect("current test executable");
    Path::new(&exe)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("exe stem")
        .to_string()
}

#[test]
fn requests_and_holds_no_mutating_access() {
    assert_eq!(OPEN_ACCESS & MUTATING_ACCESS, 0);
    let (_guard, _) = spawn_helper();
    let pid = _guard.0.id();
    let source = ProcessSource::open(pid).expect("open helper");
    let granted = source.granted_access().expect("query granted access");
    assert_eq!(granted & MUTATING_ACCESS, 0, "granted 0x{granted:x}");
}

#[test]
fn enumerates_modules_exports_imports_and_unwind() {
    let source = ProcessSource::open(std::process::id()).expect("open self");
    if cfg!(target_arch = "x86_64") {
        assert_eq!(source.arch(), Arch::X64);
    }
    let modules = source.modules();
    assert!(!modules.is_empty());
    assert!(modules.iter().any(|module| !module.exports.is_empty()));
    assert!(modules.iter().any(|module| !module.imports.is_empty()));
    let stem = exe_stem();
    assert!(
        modules.iter().any(|module| module.name == stem),
        "the test executable {stem} is listed"
    );
    for module in modules {
        assert!(module.base > 0 && module.size > 0);
        assert_eq!(source.read(module.base, 2).expect("read header"), b"MZ");
        assert!(module
            .exports
            .iter()
            .all(|(_, addr)| module.contains(*addr, 1)));
        assert!(module.imports.keys().all(|slot| module.contains(*slot, 1)));
    }

    assert!(!source.unwind_entries().is_empty());
    assert!(!source.regions().is_empty());
    assert!(source.regions().iter().all(|region| !region.writable));

    let own = known_function as fn(u64) -> u64 as usize as u64;
    assert!(source.is_executable(own));
    assert!(source.unwind_function(own).is_some());
    assert!(source.read(own, MAX_READ_BYTES + 1).is_err());
    assert!(source.read(0, 4).is_err());
    assert!(source.read_partial(own, 64).len() == 64);
}

#[test]
fn gen_locate_and_scan_by_pid() {
    let (guard, addr) = spawn_helper();
    let pid = guard.0.id().to_string();
    let scratch = tempfile::tempdir().expect("tempdir");
    let signature = scratch.path().join("known.yaml");

    let (code, _, stderr) = run(cli()
        .args([
            "gen",
            "--pid",
            &pid,
            "--addr",
            &format!("0x{addr:x}"),
            "--name",
            "known_function",
            "--output",
        ])
        .arg(&signature));
    assert_eq!(code, 0, "gen --pid failed: {stderr}");
    assert!(stderr.contains("self-test"), "{stderr}");
    let by_addr = std::fs::read_to_string(&signature).expect("signature yaml");

    // module+rva addressing yields the same document.
    let source = ProcessSource::open(guard.0.id()).expect("open helper");
    let module = source
        .module_for(addr)
        .expect("known_function lies in a module");
    assert_eq!(module.name, exe_stem());
    let rva = module.rva(addr);
    let by_rva_path: PathBuf = scratch.path().join("known-rva.yaml");
    let (code, _, stderr) = run(cli()
        .args([
            "gen",
            "--pid",
            &pid,
            "--module",
            &module.name,
            "--rva",
            &format!("0x{rva:x}"),
            "--name",
            "known_function",
            "--output",
        ])
        .arg(&by_rva_path));
    assert_eq!(code, 0, "gen --pid --module --rva failed: {stderr}");
    assert_eq!(
        std::fs::read_to_string(&by_rva_path).expect("rva yaml"),
        by_addr
    );

    let wanted = format!("0x{addr:x} ");
    let (code, stdout, stderr) = run(cli()
        .args(["locate", "--pid", &pid, "--yes", "--signature"])
        .arg(&signature));
    assert_eq!(code, 0, "locate --pid failed: {stderr}");
    assert!(
        stderr.contains("hint-free discovery"),
        "a process is scanned hint-free by default: {stderr}"
    );
    let best = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("1."))
        .unwrap_or_default();
    assert!(
        best.contains(&wanted),
        "best match is the function: {stdout}"
    );

    let (code, stdout, stderr) = run(cli()
        .args(["scan", "--pid", &pid, "--signature"])
        .arg(&signature));
    assert_eq!(code, 0, "scan --pid failed: {stderr}");
    assert!(
        stdout.contains(&wanted),
        "scan hit at the function: {stdout}"
    );

    // `--module` scans the helper's own image only, and still finds it.
    let (code, stdout, stderr) = run(cli()
        .args([
            "scan",
            "--pid",
            &pid,
            "--module",
            &module.name,
            "--signature",
        ])
        .arg(&signature));
    assert_eq!(code, 0, "scan --pid --module failed: {stderr}");
    assert!(
        stdout.contains(&wanted),
        "scan --module hit at the function: {stdout}"
    );

    // Read-only: the target is still running, not suspended or killed.
    let mut guard = guard;
    assert!(guard.0.try_wait().expect("poll helper").is_none());
}

#[test]
fn rejects_wow64_targets() {
    let Some(root) = std::env::var_os("SystemRoot") else {
        eprintln!("skipped: SystemRoot is not set");
        return;
    };
    let cmd = Path::new(&root).join("SysWOW64").join("cmd.exe");
    if !cmd.is_file() {
        eprintln!("skipped: no 32-bit cmd.exe on this host");
        return;
    }
    let child = Command::new(&cmd)
        .args(["/d", "/q", "/k"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn 32-bit cmd.exe");
    let guard = Guard(child);
    let pid = guard.0.id();

    match ProcessSource::open(pid) {
        Err(ProcessError::Unsupported(message)) => {
            assert!(message.contains("32-bit"), "{message}")
        }
        Err(other) => panic!("expected an unsupported-arch error, got {other}"),
        Ok(_) => panic!("a WOW64 process was opened as a 64-bit source"),
    }
    let (code, _, stderr) = run(cli().args(["gen", "--pid", &pid.to_string(), "--addr", "0x1000"]));
    assert_eq!(code, 3, "{stderr}");
}

#[test]
fn file_and_pid_are_exclusive() {
    let (code, _, _) = run(cli().args(["gen", "--addr", "0x1000"]));
    assert_eq!(code, 2);
    let (code, _, _) = run(cli().args(["gen", "--pid", "1", "--file", "x", "--addr", "0x1"]));
    assert_eq!(code, 2);
}
