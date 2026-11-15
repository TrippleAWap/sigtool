//! Peak resident memory of the current process, for the bench's cost report
//! (PLAN.md G5). OS-specific code stays behind `cfg` (AGENTS.md rule 1) and
//! every other platform reports `None` instead of a guess.

/// Peak resident set of this process in bytes so far, when the OS reports it:
/// `PeakWorkingSetSize` on Windows, `VmHWM` on Linux.
pub fn peak_memory_bytes() -> Option<u64> {
    imp::peak_memory_bytes()
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    /// `PROCESS_MEMORY_COUNTERS` from psapi.h.
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    // K32GetProcessMemoryInfo is the kernel32 export of psapi's
    // GetProcessMemoryInfo (Windows 7+), so no psapi import library is needed.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    pub fn peak_memory_bytes() -> Option<u64> {
        let size = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        let mut counters = ProcessMemoryCounters {
            cb: size,
            ..ProcessMemoryCounters::default()
        };
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
        // closing, and `counters` is a live, correctly sized out-parameter.
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, size) };
        (ok != 0).then_some(counters.peak_working_set_size as u64)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub fn peak_memory_bytes() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
        let kib: u64 = line
            .trim_start_matches("VmHWM:")
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        kib.checked_mul(1024)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    pub fn peak_memory_bytes() -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(windows, target_os = "linux"))]
    fn peak_memory_is_reported_and_nonzero() {
        let peak = super::peak_memory_bytes().expect("peak memory on this OS");
        assert!(peak > 0);
    }
}
