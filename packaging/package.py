"""Assemble the release archives for one platform.

Writes two archives into ``--out``:

* ``sigtool-ida-plugin-<version>-<platform>.zip``: an IDA plugin archive in the
  HCLI / Plugin Manager format (https://hcli.docs.hex-rays.com/reference/plugin-packaging-and-format).
  It holds one ``sigtool/`` directory with ``ida-plugin.json``, ``ida_plugin.py``
  (the entry point), the ``sigtool-native`` binary beside it (where the plugin's
  ``_native()`` looks for it), and ``README.md`` / ``LICENSE*`` when present.
* ``sigtool-native-<version>-<platform>.tar.gz`` (``.zip`` on Windows): the
  standalone CLI.

The plugin is IDAPython but ships a native executable, so each archive is thin:
its manifest lists exactly the one platform whose binary it carries, which is
what HCLI uses to pick the right archive. The repository copy of the manifest
leaves ``platforms`` out and this script fills it in.

Archives are deterministic (fixed timestamps and modes, sorted entries), and the
binary's executable bit is recorded as a Unix mode so HCLI restores it on Linux
and macOS even when the archive is built on Windows.

Usage::

    python packaging/package.py --platform windows-x86_64 \\
        --binary native/target/release/sigtool-native.exe --out dist [--expect-version 0.1.0]
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import stat
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "packaging" / "ida-plugin.json"
ENTRY = ROOT / "ida_plugin.py"
CARGO_TOML = ROOT / "native" / "Cargo.toml"
DOCS = ("README.md",)
PLUGIN_DIR = "sigtool"

# 1980-01-01, the earliest time a zip entry can record.
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
ZIP_CREATE_SYSTEM_UNIX = 3
MODE_FILE = stat.S_IFREG | 0o644
MODE_EXEC = stat.S_IFREG | 0o755

# HCLI platform names (the schema's plugin.platforms enum) and the machine the
# binary must be built for, so a wrong cross-build target fails here and not on
# a user's machine.
PLATFORMS = {
    "linux-x86_64": ("elf", 62),
    "linux-aarch64": ("elf", 183),
    "windows-x86_64": ("pe", 0x8664),
    "windows-aarch64": ("pe", 0xAA64),
    "macos-x86_64": ("macho", 0x01000007),
    "macos-aarch64": ("macho", 0x0100000C),
}

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
CARGO_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


class PackageError(Exception):
    pass


def binary_machine(data: bytes) -> tuple[str, int] | None:
    """Return (format, machine) for an ELF, PE, or thin Mach-O executable."""
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        endian = "<" if data[5] == 1 else ">"
        return "elf", struct.unpack_from(endian + "H", data, 18)[0]
    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] == b"PE\0\0" and len(data) >= pe + 6:
            return "pe", struct.unpack_from("<H", data, pe + 4)[0]
    if data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 8:
        return "macho", struct.unpack_from("<I", data, 4)[0]
    return None


def check_binary(platform: str, data: bytes) -> None:
    expected = PLATFORMS[platform]
    found = binary_machine(data)
    if found != expected:
        raise PackageError(
            f"binary is {found or 'not a known executable'}, {platform} needs {expected}"
        )


def read_versions() -> tuple[dict, str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    # tomllib is 3.11+; the [package] version is the first top-level version key.
    found = CARGO_VERSION.search(CARGO_TOML.read_text(encoding="utf-8"))
    if found is None:
        raise PackageError("no version in native/Cargo.toml")
    cargo = found.group(1)
    version = manifest["plugin"]["version"]
    if version != cargo:
        raise PackageError(
            f"{MANIFEST.name} version {version} != native/Cargo.toml version {cargo}"
        )
    if not SEMVER.match(version):
        raise PackageError(f"version {version!r} is not x.y.z")
    return manifest, version


def zip_entry(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_EPOCH)
    info.create_system = ZIP_CREATE_SYSTEM_UNIX
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def write_zip(path: Path, entries: list[tuple[str, bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, mode in sorted(entries):
            archive.writestr(zip_entry(name, mode), data, compresslevel=9)


def write_tar_gz(path: Path, entries: list[tuple[str, bytes, int]]) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = stat.S_IMODE(mode)
            info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    # filename="" and mtime=0 keep the gzip header free of the build path and time.
    with open(path, "wb") as raw, gzip.GzipFile("", "wb", 9, raw, mtime=0) as gz:
        gz.write(buf.getvalue())


def extras() -> list[tuple[str, bytes, int]]:
    files = [ROOT / name for name in DOCS] + sorted(ROOT.glob("LICENSE*"))
    return [(p.name, p.read_bytes(), MODE_FILE) for p in files if p.is_file()]


def package(platform: str, binary: Path, out: Path, expect_version: str | None) -> list[Path]:
    manifest, version = read_versions()
    if expect_version is not None and expect_version != version:
        raise PackageError(f"expected version {expect_version}, repository says {version}")

    data = binary.read_bytes()
    check_binary(platform, data)
    exe = "sigtool-native.exe" if platform.startswith("windows-") else "sigtool-native"

    manifest["plugin"]["platforms"] = [platform]
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    docs = extras()

    out.mkdir(parents=True, exist_ok=True)
    plugin_zip = out / f"sigtool-ida-plugin-{version}-{platform}.zip"
    write_zip(
        plugin_zip,
        [
            (f"{PLUGIN_DIR}/ida-plugin.json", manifest_bytes, MODE_FILE),
            (f"{PLUGIN_DIR}/ida_plugin.py", ENTRY.read_bytes(), MODE_FILE),
            (f"{PLUGIN_DIR}/{exe}", data, MODE_EXEC),
        ]
        + [(f"{PLUGIN_DIR}/{name}", body, mode) for name, body, mode in docs],
    )

    cli_dir = f"sigtool-native-{version}-{platform}"
    cli_entries = [(f"{cli_dir}/{exe}", data, MODE_EXEC)] + [
        (f"{cli_dir}/{name}", body, mode) for name, body, mode in docs
    ]
    if platform.startswith("windows-"):
        cli_archive = out / f"{cli_dir}.zip"
        write_zip(cli_archive, cli_entries)
    else:
        cli_archive = out / f"{cli_dir}.tar.gz"
        write_tar_gz(cli_archive, cli_entries)
    return [plugin_zip, cli_archive]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument("--binary", required=True, type=Path, help="built sigtool-native")
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    parser.add_argument(
        "--expect-version", help="fail unless the repository version equals this (the tag)"
    )
    args = parser.parse_args(argv)
    try:
        written = package(args.platform, args.binary, args.out, args.expect_version)
    except (PackageError, OSError, KeyError, ValueError) as err:
        print(f"package.py: {err}", file=sys.stderr)
        return 2
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
