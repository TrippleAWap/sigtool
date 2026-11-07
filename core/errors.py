"""Exception hierarchy for sigtool.

Front-ends translate these into exit codes and UI strings; ``core`` never prints.
"""

from __future__ import annotations


class SigToolError(Exception):
    """Base class for every error raised by sigtool."""


class UnsupportedArchError(SigToolError):
    """The architecture (or a mode of it) is not supported for feature extraction."""


class SourceFormatError(SigToolError):
    """An image file could not be parsed as a supported container."""


class ReadError(SigToolError):
    """A read of target memory failed: unmapped, truncated, or oversized."""


class ProcessError(SigToolError):
    """A live process could not be opened, inspected, or read from."""


class DecodeError(SigToolError):
    """Instruction decoding failed in a way recovery cannot work around."""


class SignatureError(SigToolError):
    """A signature is malformed, has an unknown spec version, or fails validation."""


class SelfTestError(SigToolError):
    """A signature did not match the function it was generated from."""
