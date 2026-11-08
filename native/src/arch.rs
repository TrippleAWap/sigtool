//! Architecture identifiers and container format detection.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Arch {
    X64,
    Arm64,
    Arm32,
    Thumb,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Arm64 => "arm64",
            Arch::Arm32 => "arm32",
            Arch::Thumb => "thumb",
        }
    }

    pub fn parse(value: &str) -> Option<Arch> {
        match value {
            "x64" => Some(Arch::X64),
            "arm64" => Some(Arch::Arm64),
            "arm32" => Some(Arch::Arm32),
            "thumb" => Some(Arch::Thumb),
            _ => None,
        }
    }

    pub fn pointer_size(self) -> usize {
        match self {
            Arch::X64 | Arch::Arm64 => 8,
            Arch::Arm32 | Arch::Thumb => 4,
        }
    }

    pub fn is_arm(self) -> bool {
        matches!(self, Arch::Arm32 | Arch::Thumb)
    }

    pub fn insn_align(self) -> u64 {
        match self {
            Arch::X64 => 1,
            Arch::Arm64 | Arch::Arm32 | Arch::Thumb => 4,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const ELF_MACHINE_X86_64: u16 = 0x3E;
pub const ELF_MACHINE_ARM: u16 = 0x28;
pub const ELF_MACHINE_AARCH64: u16 = 0xB7;
pub const ELF_MACHINE_I386: u16 = 0x03;

pub const PE_MACHINE_AMD64: u16 = 0x8664;
pub const PE_MACHINE_ARM64: u16 = 0xAA64;
pub const PE_MACHINE_ARMNT: u16 = 0x01C4;
pub const PE_MACHINE_ARM: u16 = 0x01C0;
pub const PE_MACHINE_THUMB: u16 = 0x01C2;
pub const PE_MACHINE_I386: u16 = 0x014C;

/// Detect the architecture of an ELF or PE image from its header.
///
/// 32-bit x86 is rejected by design rather than decoded as x64.
pub fn detect(data: &[u8]) -> Result<Arch, String> {
    if data.starts_with(b"\x7fELF") {
        if data.len() < 20 {
            return Err("truncated ELF header".into());
        }
        let machine = u16::from_le_bytes([data[18], data[19]]);
        return match machine {
            ELF_MACHINE_X86_64 => Ok(Arch::X64),
            ELF_MACHINE_AARCH64 => Ok(Arch::Arm64),
            ELF_MACHINE_ARM => Ok(Arch::Arm32),
            ELF_MACHINE_I386 => Err("32-bit x86 images are not supported".into()),
            other => Err(format!("unsupported ELF machine 0x{other:x}")),
        };
    }
    if data.starts_with(b"MZ") {
        if data.len() < 0x40 {
            return Err("truncated DOS header".into());
        }
        let lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if lfanew + 24 > data.len() || &data[lfanew..lfanew + 4] != b"PE\0\0" {
            return Err("PE signature missing".into());
        }
        let machine = u16::from_le_bytes([data[lfanew + 4], data[lfanew + 5]]);
        return match machine {
            PE_MACHINE_AMD64 => Ok(Arch::X64),
            PE_MACHINE_ARM64 => Ok(Arch::Arm64),
            PE_MACHINE_ARM | PE_MACHINE_ARMNT => Ok(Arch::Arm32),
            PE_MACHINE_THUMB => Ok(Arch::Thumb),
            PE_MACHINE_I386 => Err("32-bit x86 images are not supported".into()),
            other => Err(format!("unsupported PE machine 0x{other:x}")),
        };
    }
    Err("only ELF and PE images are supported".into())
}
