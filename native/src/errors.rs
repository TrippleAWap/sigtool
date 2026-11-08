//! Errors raised by the native core.
//!
//! Front-ends translate these into exit codes and UI messages; the core never
//! prints.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError(pub String);

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFormatError(pub String);

impl fmt::Display for SourceFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceFormatError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureError(pub String);

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestError(pub String);

impl fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SelfTestError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError(pub String);

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbError {}
