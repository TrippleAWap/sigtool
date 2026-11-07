"""Live Windows process source: architecture, modules, reads, and generation.

The target is a child process that allocates one executable page, writes a tiny
x64 function, reports its address, and sleeps. Nothing is hardcoded: the PID and
address come from the child (AGENTS.md testing rules). The injected page also
stands in for the packed/injected-region case in PLAN.md section 7.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from collections.abc import Iterator

import pytest

from core.arch import Arch
from core.errors import ReadError, UnsupportedArchError
from core.generate import generate
from core.sigfile import Signature
from core.spec import MAX_READ_BYTES
from sources.proc_win import WindowsProcessSource, arch_for_machine

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows live-process source")

CHILD = r"""
import ctypes
import time

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
address = kernel32.VirtualAlloc(None, 4096, 0x3000, 0x40)
code = bytes.fromhex("b878563412c3")  # mov eax, 0x12345678; ret
ctypes.memmove(address, code, len(code))
print(hex(address), flush=True)
time.sleep(60)
"""


@pytest.fixture
def injected() -> Iterator[tuple[int, int]]:
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        pytest.skip("injected function bytes are x64")
    process = subprocess.Popen(
        [sys.executable, "-c", CHILD],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    line = process.stdout.readline().strip()
    if not line:
        process.kill()
        pytest.fail("child process did not report its injected address")
    try:
        yield process.pid, int(line, 16)
    finally:
        process.kill()
        process.wait(timeout=10)


def test_arch_for_machine_rejects_32_bit_and_unknown_machines() -> None:
    assert arch_for_machine(0x8664) is Arch.X64
    assert arch_for_machine(0xAA64) is Arch.ARM64
    with pytest.raises(UnsupportedArchError, match="32-bit"):
        arch_for_machine(0x014C)
    with pytest.raises(UnsupportedArchError, match="32-bit"):
        arch_for_machine(0x01C4)
    with pytest.raises(UnsupportedArchError, match="unsupported"):
        arch_for_machine(0x1234)


def test_reads_injected_executable_memory(injected: tuple[int, int]) -> None:
    pid, address = injected
    with WindowsProcessSource.open(pid) as source:
        assert source.arch is Arch.X64
        assert source.is_mapped(address)
        assert source.is_executable(address)
        assert source.read(address, 6) == bytes.fromhex("b878563412c3")
        assert source.read_partial(address, 64).startswith(bytes.fromhex("b878"))

        with pytest.raises(ReadError, match="refusing read"):
            source.read(address, MAX_READ_BYTES + 1)
        with pytest.raises(ReadError):
            source.read(0, 4)


def test_enumerates_modules_exports_and_imports() -> None:
    with WindowsProcessSource.open(os.getpid()) as source:
        modules = source.modules()
        assert modules
        assert any(module.exports for module in modules)
        assert any(module.imports for module in modules)

        for module in modules:
            assert module.base > 0
            assert module.size > 0
            assert all(module.contains(address) for address in module.exports.values())
            assert all(module.contains(slot) for slot in module.imports)

        first = modules[0]
        assert source.read(first.base, 2) == b"MZ"
        assert source.function_starts()


def test_generates_and_self_tests_an_injected_function(injected: tuple[int, int]) -> None:
    pid, address = injected
    with WindowsProcessSource.open(pid) as source:
        result = generate(source, address, name="injected")

        assert result.match.address == address
        assert result.match.score == 1.0
        assert result.signature.name == "injected"
        assert result.report.verdict in {"small", "weak", "strong"}

        again = generate(source, address, name="injected")
        assert again.signature.to_yaml() == result.signature.to_yaml()


def test_cli_pid_mode_emits_yaml(
    injected: tuple[int, int], capsys: pytest.CaptureFixture[str]
) -> None:
    import cli

    pid, address = injected
    code = cli.main(["gen", "--pid", str(pid), "--addr", hex(address), "--name", "injected"])
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert Signature.from_yaml(captured.out).name == "injected"
    assert "self-test" in captured.err


def test_closed_source_refuses_reads(injected: tuple[int, int]) -> None:
    pid, address = injected
    source = WindowsProcessSource.open(pid)
    source.close()
    with pytest.raises(ReadError, match="closed"):
        source.read(address, 1)
