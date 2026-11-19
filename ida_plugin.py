"""IDA plugin front-end for sigtool: UI glue over the native ``sigtool-native`` CLI.

The plugin never extracts features itself (AGENTS.md rule 2). It hands the
IDB's input file and a module-relative address to ``sigtool-native`` and shows
what comes back, so a signature made here is byte-identical to one made with
``sigtool-native gen --file IMAGE --rva RVA``. Addresses cross the boundary as
RVAs (``ea - imagebase``), which keeps rebased databases correct.

Install (IDA 8.4+ / 9.x, Python 3.10+, no extra packages):

    cargo build --release --manifest-path native/Cargo.toml
    # copy this file into %IDAUSR%/plugins and native/target/release/sigtool-native
    # next to it (or on PATH, or set SIGTOOL_NATIVE to its full path)

The binary is looked up as ``SIGTOOL_NATIVE``, then next to this file (where a
packaged release puts it), then PATH. On first use the plugin runs
``sigtool-native --version`` and warns when it writes another signature spec
than this plugin expects.

The IDB is all the plugin needs. The CLI reads an image file, so the plugin
hands it one of two things:

* the input file itself, when it is on disk: the path IDA recorded, else a
  file of the same name beside the IDB (an IDB copied to another machine or
  folder), each accepted only when its SHA-256 equals the one IDA stored when
  the IDB was made. A file found somewhere new is recorded in the IDB. An
  unstripped ELF file also supplies its ``.symtab`` names, which the IDB
  route does not.
* otherwise, the image rebuilt from the IDB: every byte IDA loaded, with
  patches reverted, back at its file offset, plus the headers IDA did not
  load. ELF gets a section table made from the segments (the CLI reads the
  dynamic symbols and relocations from the dynamic segment); PE gets its NT
  headers from IDA's copy (``peutils_t``) and a section table made from the
  segments. Signatures from a rebuilt image are byte-identical to ones from
  the stripped file (ELF) or the file itself (PE).

A file dialog asks for the input file only when neither works (an IDB of
another format).

Ctrl-Alt-G (or Edit > Plugins > sigtool) opens the action menu, laid out
like IDA-Fusion's: one radio row per action, the signatures DB that sign-all
writes and apply-names reads, and "Configure settings", whose checkboxes are
kept in IDA's registry. The menu remembers the last action and DB. By
default nothing asks for a file: a new signature is copied to the clipboard
and saved as ``sigtool/<function>.yaml`` beside the IDB, DBs go to the same
folder, locate takes the signature on the clipboard, and the best match is
jumped to. The actions are also in a ``sigtool`` menu (Edit > Plugins when
IDA cannot add one) and on the right-click menus of the disassembly,
pseudocode, and Functions views, where they act on the selected rows.

* ``sigtool: generate signature``: sign the function under the cursor (copy
  and save it as the settings say). With several functions selected in the
  Functions view, sign them into one DB instead.
* ``sigtool: merge with another build``: sign the function together with the
  same function in other image files (at an address or RVA) into one
  multi-arch signature.
* ``sigtool: locate signature in this IDB``: scan the input file with the
  signature on the clipboard (else a saved one), list the matches, and jump to
  the best one.
* ``sigtool: sign all named functions to a DB``: sign every function with a
  meaningful name (not ``sub_*`` or another IDA dummy name, not a thunk, an
  extern, or a stub under five bytes) into one signatures DB, in a single
  ``sigtool-native db build --file IMAGE --functions LIST`` run with progress
  and cancel. Functions the CLI cannot sign are listed and skipped.
* ``sigtool: apply names from a DB``: scan the input file with a signatures DB
  (``scan --db --discovery hint-free``, which resolves signatures from one
  module jointly through their call graph) and propose renames for functions
  whose match is ``identified``. The proposals open in a chooser with every
  row selected except those that would replace a user name (both settings);
  the selected rows are renamed. A name already used elsewhere in the IDB,
  two signatures claiming one address, or one name claiming two addresses is
  skipped.

File dialogs that remain start beside the IDB, or at the file last used.

Together the last two are the "sign a whole IDB, apply the resolved names to
another" workflow: sign the analysed IDB, then apply the DB in the other one.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import queue
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_nalt
import ida_name
import ida_registry
import ida_segment
import idautils

PLUGIN_COMMENT = "Architecture-independent function signatures"
PLUGIN_HELP = "Generate, merge, and locate sigtool signatures without leaving IDA"

GEN_ACTION = "sigtool:generate"
GEN_LABEL = "sigtool: generate signature"
MERGE_ACTION = "sigtool:merge"
MERGE_LABEL = "sigtool: merge with another build"
LOCATE_ACTION = "sigtool:locate"
LOCATE_LABEL = "sigtool: locate signature in this IDB"
SIGN_ALL_ACTION = "sigtool:sign_all"
SIGN_ALL_LABEL = "sigtool: sign all named functions to a DB"
APPLY_ACTION = "sigtool:apply_names"
APPLY_LABEL = "sigtool: apply names from a DB"
OPEN_ACTION = "sigtool:open"
OPEN_LABEL = "sigtool: open menu"
# One hotkey opens the action menu, as IDA-Fusion does with Ctrl-Alt-S
# (which it keeps); the actions themselves stay on the right-click menus.
OPEN_HOTKEY = "Ctrl-Alt-G"
MENU_NAME = "sigtool:menu"
# IDA registry subkey for the settings and the remembered menu state.
REGISTRY_KEY = "sigtool"

# Settings, one bit each in the order the settings form lists them.
SET_COPY_TO_CLIPBOARD = 1 << 0
SET_SAVE_BESIDE_IDB = 1 << 1
SET_SHOW_REPORT = 1 << 2
SET_LOCATE_CLIPBOARD = 1 << 3
SET_AUTO_JUMP = 1 << 4
SET_LIST_MATCHES = 1 << 5
SET_CONFIRM_RENAMES = 1 << 6
SET_PRESELECT_USER_NAMES = 1 << 7
SETTINGS = (
    (SET_COPY_TO_CLIPBOARD, "Copy created signatures to the clipboard"),
    (SET_SAVE_BESIDE_IDB, "Save signatures and DBs in a sigtool folder beside the IDB (no dialog)"),
    (SET_SHOW_REPORT, "Show the quality report in a dialog after signing"),
    (SET_LOCATE_CLIPBOARD, "Locate the signature on the clipboard when there is one"),
    (SET_AUTO_JUMP, "Auto jump to the best match"),
    (SET_LIST_MATCHES, "List every match in a window"),
    (SET_CONFIRM_RENAMES, "Confirm renames in a list before applying them"),
    (SET_PRESELECT_USER_NAMES, "Also replace user names when applying (preselected)"),
)
DEFAULT_SETTINGS = (
    SET_COPY_TO_CLIPBOARD
    | SET_SAVE_BESIDE_IDB
    | SET_LOCATE_CLIPBOARD
    | SET_AUTO_JUMP
    | SET_LIST_MATCHES
    | SET_CONFIRM_RENAMES
)
# Generation decodes one function; locating sweeps the image. Both are bounded
# so a pathological input cannot hang the IDA UI thread forever. Whole-IDB
# runs have no fixed bound; they show a wait box with a cancel button instead.
TIMEOUT_SECONDS = 300
# The signature spec this plugin was released with (native/src/spec.rs
# SPEC_VERSION; a unit test keeps them equal). A CLI writing another spec
# still runs, but its signatures and DBs will not load in a matching build.
EXPECTED_SPEC_VERSION = "7"

# Stubs this small (`ret`, `xor eax, eax; ret`, one AArch64 instruction) carry
# no evidence a signature could match on; a five-byte x64 body still can,
# through joint resolution of its callers.
MIN_FUNCTION_BYTES = 5
# Names IDA made up rather than names anyone resolved; signing them would
# spread guesses to other IDBs. Dummy names are `<kind>_<hex address>`,
# optionally decorated (`_sub_401000`, `sub_401000_0`); `j_` names a jump to
# another function and `unknown_libname_` an unnamed FLIRT hit.
AUTO_NAME_PREFIXES = ("j_", "unknown_libname_", "__imp_")
_DUMMY_NAME = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:sub|nullsub|loc|locret|unk|def|off|byte|word|dword|qword)"
    r"_[0-9A-Fa-f]+(?:_\d+)?$"
)
# Only an `identified` match is a trusted answer (spec: untied first match on
# naming evidence); `candidate` and `shape-only` are never applied as names.
ACCEPTED_EVIDENCE = frozenset({"identified"})


class SigtoolError(Exception):
    """A failed ``sigtool-native`` run, with its stderr as the message."""


class SigtoolCancelled(Exception):
    """The user pressed cancel in the wait box."""


# -- pure helpers (no IDA calls; unit-tested outside IDA) --------------------


def is_meaningful_name(name: str | None) -> bool:
    """Whether ``name`` is a resolved name rather than one IDA made up."""
    if not name:
        return False
    if name.startswith(AUTO_NAME_PREFIXES):
        return False
    return _DUMMY_NAME.search(name) is None


def parse_progress(line: str) -> tuple[int, int] | None:
    """``progress DONE/TOTAL`` lines that ``db build --functions`` and
    ``scan --progress`` print."""
    match = re.fullmatch(r"progress (\d+)/(\d+)", line.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def parse_phase(line: str) -> str | None:
    """``phase NAME`` lines that ``scan --progress`` prints as a phase starts."""
    match = re.fullmatch(r"phase ([A-Za-z0-9_-]+)", line.strip())
    return None if match is None else match.group(1)


class WaitStatus:
    """What the wait box shows for one CLI run, fed the run's stderr lines.

    Progress and phase lines update the status and are kept out of the
    collected stderr, so a failure's message is the CLI's error, not a
    thousand progress lines in front of it.
    """

    def __init__(self, message: str) -> None:
        self.message = message
        self.progress: tuple[int, int] | None = None
        self.phase: str | None = None
        self.collected: list[str] = []

    def feed(self, line: str) -> None:
        progress = parse_progress(line)
        if progress is not None:
            self.progress = progress
            return
        phase = parse_phase(line)
        if phase is not None:
            self.phase = phase
            return
        self.collected.append(line)

    def text(self, elapsed: float) -> str:
        parts = []
        if self.phase:
            parts.append(self.phase)
        if self.progress is not None:
            parts.append(f"{self.progress[0]} / {self.progress[1]}")
        parts.append(f"{int(elapsed)} s")
        return f"{self.message}\n{', '.join(parts)}"

    def stderr(self) -> str:
        return "".join(self.collected)

    def error(self, returncode: int) -> str:
        return self.stderr().strip() or f"exit code {returncode}"


def summarize_build(report: dict) -> str:
    """A short text summary of a ``db build --report`` document."""
    rows = report.get("functions", [])
    lines = [f"signed {report.get('signed', 0)} of {len(rows)} functions"]
    skipped = [row for row in rows if row.get("status") != "signed"]
    if skipped:
        lines.append(f"skipped {len(skipped)}:")
        for row in skipped[:20]:
            lines.append(
                f"  {row.get('rva')} {row.get('name') or '-'}: "
                f"{row.get('status')} ({row.get('error', '')})"
            )
        if len(skipped) > 20:
            lines.append(f"  ... and {len(skipped) - 20} more (see the Output window)")
    return "\n".join(lines)


@dataclass(frozen=True)
class Proposal:
    """One rename: the function at ``rva`` becomes ``name``."""

    rva: int
    name: str
    score: float
    evidence: str
    current: str
    signature_id: str = ""
    # The function already carries a user name this rename would replace.
    replaces_user_name: bool = False


def choose_renames(
    hits: Iterable[dict],
    current_name: Callable[[int], str],
    user_named: Callable[[int], bool],
    name_owner: Callable[[str], int | None],
    overwrite_user: bool = False,
) -> tuple[list[Proposal], list[tuple[str, str]]]:
    """Renames to propose from ``scan --json`` hits, and what was skipped why.

    ``hits`` are best first per signature, so a signature's first hit is its
    answer. ``current_name`` and ``user_named`` describe the IDB at an RVA;
    ``name_owner`` gives the RVA already carrying a name, or ``None``.
    """
    skipped: list[tuple[str, str]] = []
    best: dict[str, dict] = {}
    for hit in hits:
        key = str(hit.get("signature_id") or hit.get("name"))
        best.setdefault(key, hit)

    claims: dict[int, list[dict]] = {}
    for hit in best.values():
        name = str(hit.get("name") or "")
        if hit.get("evidence") not in ACCEPTED_EVIDENCE:
            skipped.append((name, f"best match is {hit.get('evidence')}"))
            continue
        if not name or hit.get("rva") is None:
            skipped.append((name, "hit has no name or rva"))
            continue
        claims.setdefault(int(str(hit["rva"]), 16), []).append(hit)

    # One name per address and one address per name, or the answer is unsure.
    by_name: dict[str, set[int]] = {}
    for rva, group in claims.items():
        for hit in group:
            by_name.setdefault(str(hit["name"]), set()).add(rva)

    proposals: list[Proposal] = []
    for rva in sorted(claims):
        group = claims[rva]
        names = sorted({str(hit["name"]) for hit in group})
        if len(names) > 1:
            for name in names:
                skipped.append((name, f"{len(names)} signatures claim +{rva:#x}"))
            continue
        name = names[0]
        if len(by_name[name]) > 1:
            skipped.append((name, f"matched {len(by_name[name])} addresses"))
            continue
        hit = max(group, key=lambda item: float(item.get("score") or 0.0))
        current = current_name(rva)
        if current == name:
            skipped.append((name, "already named"))
            continue
        replaces_user_name = user_named(rva)
        if replaces_user_name and not overwrite_user:
            skipped.append((name, f"+{rva:#x} already has user name {current!r}"))
            continue
        owner = name_owner(name)
        if owner is not None and owner != rva:
            skipped.append((name, f"name already used at +{owner:#x}"))
            continue
        proposals.append(
            Proposal(
                rva=rva,
                name=name,
                score=float(hit.get("score") or 0.0),
                evidence=str(hit.get("evidence")),
                current=current,
                signature_id=str(hit.get("signature_id") or ""),
                replaces_user_name=replaces_user_name,
            )
        )
    return proposals, sorted(skipped)


def default_selection(proposals: list[Proposal], include_user_names: bool = False) -> list[int]:
    """Rows the rename chooser starts with selected: all but user-name replacements.

    Replacing an analyst's name is shown, so it is one click away, but never
    applied by just confirming the dialog, unless the setting says so.
    """
    return [
        index
        for index, item in enumerate(proposals)
        if include_user_names or not item.replaces_user_name
    ]


def is_signature_text(text: str | None) -> bool:
    """Whether ``text`` (say, the clipboard) is a sigtool signature document."""
    if not text:
        return False
    return bool(
        re.search(r"^spec_version:", text, re.MULTILINE)
        and re.search(r"^features:", text, re.MULTILINE)
    )


def safe_file_name(name: str) -> str:
    """``name`` usable as a file name (mangled names hold characters file systems refuse)."""
    return re.sub(r'[<>:"/\\|?*\s]+', "_", name).strip("._") or "signature"


def output_path(idb_path: str, name: str, suffix: str) -> str:
    """Where an output named ``name`` goes without asking: ``sigtool/`` beside the IDB."""
    folder = os.path.join(os.path.dirname(idb_path) or os.getcwd(), "sigtool")
    return os.path.join(folder, safe_file_name(name) + suffix)


def _basename(path: str) -> str:
    # An IDB made on Windows and opened elsewhere (or the reverse) records a
    # path in the other OS's separators, which os.path would not split.
    return re.split(r"[\\/]", path)[-1] if path else ""


def input_file_candidates(recorded: str, idb_path: str, root_name: str) -> list[str]:
    """Where an IDB's input file may be, most likely first.

    ``recorded`` is the path IDA stored when the IDB was made; it goes stale
    when the IDB moves to another folder or machine, and the binary usually
    moves with it. So the candidates continue with files beside the IDB named
    like the recorded file, like IDA's root file name, and like the IDB itself
    without its ``.i64``/``.idb`` extension (``libz.so.i64`` -> ``libz.so``).
    """
    folder = os.path.dirname(idb_path) if idb_path else ""
    stem, extension = os.path.splitext(_basename(idb_path))
    names = [_basename(recorded), root_name]
    if extension.lower() in (".i64", ".idb"):
        names.append(stem)
    candidates = [recorded] if recorded else []
    if folder:
        for name in names:
            path = os.path.join(folder, name) if name else ""
            if path and path not in candidates:
                candidates.append(path)
    return candidates


def known_digest(digest: bytes | None) -> bytes | None:
    """The stored SHA-256, or ``None`` when IDA stored none (empty or zeros)."""
    if not digest or not any(digest):
        return None
    return bytes(digest)


def file_matches(path: str, sha256: bytes | None, size: int | None) -> bool:
    """Whether ``path`` is the file an IDB with this stored hash and size was made from.

    Without a stored hash a matching size is accepted; without either, any
    existing file is.
    """
    try:
        if not os.path.isfile(path):
            return False
        if size and os.path.getsize(path) != size:
            return False
        if sha256 is None:
            return True
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        return digest.digest() == sha256
    except OSError:
        return False


@dataclass(frozen=True)
class Segment:
    """One IDB segment: where it maps, where its bytes sit in the input file
    (``None`` for zero-fill such as ``.bss``), and its permissions."""

    name: str
    start: int
    end: int
    file_offset: int | None
    executable: bool
    writable: bool


_SHT_PROGBITS, _SHT_STRTAB, _SHT_NOBITS = 1, 3, 8
_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 0x1, 0x2, 0x4


def rebuild_elf(image: bytes, segments: Iterable[Segment]) -> bytes | None:
    """An ELF image from an IDB: ``image`` holds the input file's bytes at their
    file offsets (zero where the IDB has none), and a section table describing
    ``segments`` is appended. ``None`` if ``image`` is not a little-endian ELF.

    What an IDB lacks is what ``strip --strip-all`` removes (``.symtab``, the
    section table), plus how IDA merged unnamed sections into ``LOAD``
    segments; ``sigtool-native`` reads the dynamic symbols and relocations
    from the dynamic segment when the section table does not describe them.
    """
    if len(image) < 0x40 or image[:4] != b"\x7fELF" or image[5] != 1:
        return None
    is64 = image[4] == 2
    if not is64 and image[4] != 1:
        return None
    entry = struct.Struct("<IIQQQQIIQQ" if is64 else "<IIIIIIIIII")
    names = bytearray(b"\0")
    rows = [entry.pack(*([0] * 10))]

    def name_offset(name: str) -> int:
        offset = len(names)
        names.extend(name.encode("utf-8", "replace") + b"\0")
        return offset

    for segment in sorted(segments, key=lambda item: item.start):
        if segment.end <= segment.start:
            continue
        flags = _SHF_ALLOC
        flags |= _SHF_EXECINSTR if segment.executable else 0
        flags |= _SHF_WRITE if segment.writable else 0
        kind = _SHT_NOBITS if segment.file_offset is None else _SHT_PROGBITS
        offset = segment.file_offset or 0
        size = segment.end - segment.start
        if kind == _SHT_PROGBITS and offset + size > len(image):
            return None
        rows.append(
            entry.pack(
                name_offset(segment.name), kind, flags, segment.start, offset, size, 0, 0, 1, 0
            )
        )
    table_name = name_offset(".shstrtab")
    names_offset = len(image)
    rows.append(entry.pack(table_name, _SHT_STRTAB, 0, 0, names_offset, len(names), 0, 0, 1, 0))
    table_offset = (names_offset + len(names) + 7) & ~7
    out = bytearray(image)
    out += names
    out += bytes(table_offset - len(out))
    for row in rows:
        out += row
    if is64:
        struct.pack_into("<Q", out, 0x28, table_offset)
        struct.pack_into("<HHH", out, 0x3A, entry.size, len(rows), len(rows) - 1)
    else:
        struct.pack_into("<I", out, 0x20, table_offset)
        struct.pack_into("<HHH", out, 0x2E, entry.size, len(rows), len(rows) - 1)
    return bytes(out)


# IDA keeps the PE headers it parsed (`peutils_t().header()`) in its own
# `peheader_t`: the PE32 layout of signature, COFF header, and optional header,
# with a PE32+ image base widened in place, then 16 data directories.
_IDA_PE_HEADER_SIZE = 248
_PE64_MACHINES = (0x8664, 0xAA64)


def rebuild_pe(
    image: bytes, segments: Iterable[Segment], header: bytes, image_base: int
) -> bytes | None:
    """A PE image from an IDB: ``image`` holds the section bytes at their file
    offsets; IDA does not load the headers, so a DOS header pointing past the
    image, NT headers made from ``header`` (IDA's copy), and a section table
    describing ``segments`` are written. ``None`` if ``header`` is not one.
    """
    if len(header) < _IDA_PE_HEADER_SIZE or header[:4] != b"PE\0\0":
        return None
    machine, _count, timestamp = struct.unpack_from("<HHI", header, 4)
    characteristics = struct.unpack_from("<H", header, 22)[0]
    entry = struct.unpack_from("<I", header, 40)[0]
    section_align, file_align = struct.unpack_from("<II", header, 56)
    subsystem, dll_characteristics = struct.unpack_from("<HH", header, 92)
    directories = [struct.unpack_from("<II", header, 120 + 8 * index) for index in range(16)]
    is64 = machine in _PE64_MACHINES

    sections = []
    for segment in sorted(segments, key=lambda item: item.start):
        size = segment.end - segment.start
        if size <= 0 or segment.start < image_base:
            continue
        raw_ptr = segment.file_offset or 0
        raw_size = min(size, max(0, len(image) - raw_ptr)) if segment.file_offset is not None else 0
        flags = 0x4000_0000  # IMAGE_SCN_MEM_READ
        if segment.executable:
            flags |= 0x2000_0000 | 0x20  # MEM_EXECUTE, CNT_CODE
        if segment.writable:
            flags |= 0x8000_0000
        name = segment.name.encode("ascii", "replace")[:8].ljust(8, b"\0")
        sections.append(
            struct.pack(
                "<8sIIIIIIHHI",
                name,
                size,
                segment.start - image_base,
                raw_size,
                raw_ptr,
                0,
                0,
                0,
                0,
                flags,
            )
        )
    if not sections:
        return None
    size_of_image = max(segment.end for segment in segments) - image_base

    optional = bytearray(240 if is64 else 224)
    struct.pack_into("<H", optional, 0, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", optional, 16, entry)
    if is64:
        struct.pack_into("<Q", optional, 24, image_base)
    else:
        struct.pack_into("<I", optional, 28, image_base)
    struct.pack_into("<II", optional, 32, section_align or 0x1000, file_align or 0x200)
    struct.pack_into("<I", optional, 56, size_of_image)
    struct.pack_into("<HH", optional, 68, subsystem, dll_characteristics)
    count_at, directories_at = (108, 112) if is64 else (92, 96)
    struct.pack_into("<I", optional, count_at, 16)
    for index, (rva, size) in enumerate(directories):
        struct.pack_into("<II", optional, directories_at + 8 * index, rva, size)
    coff = struct.pack(
        "<HHIIIHH", machine, len(sections), timestamp, 0, 0, len(optional), characteristics
    )

    out = bytearray(image)
    # The original headers sit below the first section, where IDA kept no
    # bytes; the rebuilt ones go after the image so no section byte moves.
    lfanew = (len(out) + 7) & ~7
    out += bytes(lfanew - len(out))
    out += b"PE\0\0" + coff + optional + b"".join(sections)
    if len(out) < 0x40:
        out += bytes(0x40 - len(out))
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, lfanew)
    return bytes(out)


def rename_blocker(
    rva: int,
    function_start: int | None,
    is_code: bool,
    add_function: Callable[[], int | None],
) -> str | None:
    """Why the function at ``rva`` must not be renamed, or ``None`` to rename it.

    ``function_start`` is the RVA of the IDB function containing ``rva`` (or
    ``None``); ``add_function`` asks IDA to create one at ``rva`` and returns
    its start RVA, or ``None`` when IDA refuses. A match is applied only to a
    function starting exactly there, or to code IDA agrees to make one at:
    a rename at data or mid-function would invent a function IDA never saw.
    """
    if function_start == rva:
        return None
    if function_start is not None:
        return f"+{rva:#x} is inside the function at +{function_start:#x}"
    if not is_code:
        return f"no function at +{rva:#x} (not code in this IDB)"
    if add_function() != rva:
        return f"no function at +{rva:#x} (IDA could not create one there)"
    return None


def provenance_comment(existing: str, proposal: Proposal, source: str) -> str:
    """``existing`` function comment plus a line recording where a rename came from.

    The line names the signature, score, and evidence so a later reader can
    tell a sigtool rename from an analyst's; applying the same DB twice does
    not repeat it.
    """
    line = (
        f"sigtool: {proposal.name} from {source} "
        f"(signature {proposal.signature_id or '?'}, score {proposal.score:.3f}, "
        f"{proposal.evidence})"
    )
    if line in existing.splitlines():
        return existing
    return f"{existing.rstrip()}\n{line}" if existing.strip() else line


@dataclass(frozen=True)
class Row:
    """One chooser row: the address a double-click jumps to, and its cells."""

    ea: int
    cells: tuple[str, ...]


def match_rows(matches: Iterable[dict], base: int) -> list[Row]:
    """Chooser rows for ``locate --json`` matches, best first.

    A match maps back through its ``rva`` (the IDB may be rebased); one
    without a module has no ``rva`` and cannot be placed, so it is dropped.
    """
    rows = []
    for match in matches:
        rva = match.get("rva")
        if rva is None:
            continue
        ea = base + int(str(rva), 16)
        rows.append(
            Row(
                ea=ea,
                cells=(
                    f"{ea:#x}",
                    f"{float(match.get('score') or 0.0):.3f}",
                    str(match.get("evidence") or ""),
                    str(match.get("label") or ""),
                    str(len(match.get("matched") or [])),
                ),
            )
        )
    return rows


# -- CLI glue -----------------------------------------------------------------


def find_native(
    environ: dict[str, str] | os._Environ,
    plugin_dir: Path,
    which: Callable[[str], str | None],
    windows: bool,
) -> str:
    """Where ``sigtool-native`` is: ``SIGTOOL_NATIVE``, beside the plugin, PATH.

    A packaged release ships the binary next to this file, and that copy is
    the one built with this plugin; a stale copy on PATH must not win over it.
    """
    configured = environ.get("SIGTOOL_NATIVE")
    if configured:
        return configured
    sibling = plugin_dir / ("sigtool-native.exe" if windows else "sigtool-native")
    if sibling.is_file():
        return str(sibling)
    found = which("sigtool-native")
    if found:
        return found
    raise SigtoolError(
        "sigtool-native not found: put it next to ida_plugin.py, on PATH, "
        "or set SIGTOOL_NATIVE to its full path"
    )


def version_problem(text: str, expected_spec: str = EXPECTED_SPEC_VERSION) -> str | None:
    """Why ``sigtool-native --version`` output does not fit this plugin, or ``None``."""
    match = re.search(r"\(spec ([^)\s]+)\)", text)
    if match is None:
        return (
            f"{text.strip() or 'sigtool-native'} does not report a spec version "
            f"(older than this plugin, which expects spec {expected_spec})"
        )
    if match.group(1) != expected_spec:
        return (
            f"{text.strip()} writes spec {match.group(1)}; this plugin expects spec {expected_spec}"
        )
    return None


_native_checked: str | None = None


def _native() -> str:
    """The CLI path, checking its version the first time each path is used."""
    global _native_checked
    path = find_native(os.environ, Path(__file__).resolve().parent, shutil.which, os.name == "nt")
    if path != _native_checked:
        _native_checked = path
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            problem = version_problem(result.stdout)
        except (OSError, subprocess.TimeoutExpired) as error:
            _native_checked = None
            raise SigtoolError(f"cannot run {path}: {error}") from error
        ida_kernwin.msg(f"sigtool: using {path} ({result.stdout.strip()})\n")
        if problem is not None:
            ida_kernwin.msg(f"sigtool: warning: {problem}\n")
            ida_kernwin.warning(f"sigtool: {problem}\n\nBinary: {path}")
    return path


def _run_cancellable(args: list[str], message: str, ok_codes: tuple[int, ...] = (0,)) -> str:
    """Run the CLI behind a wait box; cancel kills it. Returns its stderr.

    stderr is read on a thread so the UI thread can poll the cancel button
    while a long function or a whole-image scan prints nothing.
    """
    process = subprocess.Popen(
        [_native(), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        # A console child of the IDA GUI would otherwise open a window.
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        assert process.stderr is not None
        for line in process.stderr:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    status = WaitStatus(message)
    started = time.monotonic()
    shown = ""
    shown_at = 0.0
    ida_kernwin.show_wait_box(message)
    try:
        while True:
            try:
                line = lines.get(timeout=0.1)
            except queue.Empty:
                line = ""
            if line is None:
                break
            if line:
                status.feed(line)
            now = time.monotonic()
            # db build prints a line per function: redrawing the wait box for
            # each would cost more than the work it reports, so redraw at
            # most ten times a second, and only when the text changed.
            if now - shown_at >= 0.1:
                text = status.text(now - started)
                if text != shown:
                    ida_kernwin.replace_wait_box(text)
                    shown = text
                shown_at = now
            if ida_kernwin.user_cancelled():
                process.kill()
                process.wait()
                raise SigtoolCancelled
        returncode = process.wait()
    finally:
        ida_kernwin.hide_wait_box()
    if returncode not in ok_codes:
        raise SigtoolError(status.error(returncode))
    return status.stderr()


# CLI flags newer than some installed binaries, by (path, subcommand, flag).
_flag_support: dict[tuple[str, str, str], bool] = {}


def _supports(subcommand: str, flag: str) -> bool:
    """Whether the CLI's ``SUBCOMMAND --help`` lists ``flag`` (an older binary
    rejects an unknown flag as a usage error, so newer ones are offered only
    when present)."""
    path = _native()
    key = (path, subcommand, flag)
    if key not in _flag_support:
        try:
            result = subprocess.run(
                [path, *subcommand.split(), "--help"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            listed = re.search(rf"(?<![\w-]){re.escape(flag)}\b", result.stdout)
            _flag_support[key] = listed is not None
        except (OSError, subprocess.TimeoutExpired):
            _flag_support[key] = False
    return _flag_support[key]


# Files confirmed as this session's input file, keyed by what would change if
# the file did: hashing a large binary on every action would be noticeable.
_verified_inputs: dict[tuple[str, int, int], bool] = {}


def _idb_path() -> str:
    return str(ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "")


def _is_input_file(path: str, sha256: bytes | None, size: int | None) -> bool:
    try:
        stat = os.stat(path)
    except OSError:
        return False
    key = (os.path.abspath(path), stat.st_mtime_ns, stat.st_size)
    if key not in _verified_inputs:
        _verified_inputs[key] = file_matches(path, sha256, size)
    return _verified_inputs[key]


def _input_file() -> str:
    """The IDB's input file on disk, found without asking whenever possible."""
    recorded = str(ida_nalt.get_input_file_path() or "")
    root = str(ida_nalt.get_root_filename() or "") or _basename(recorded)
    sha256 = known_digest(ida_nalt.retrieve_input_file_sha256())
    size = int(ida_nalt.retrieve_input_file_size() or 0) or None
    for path in input_file_candidates(recorded, _idb_path(), root):
        if _is_input_file(path, sha256, size):
            if path != recorded:
                _remember_input_file(path, recorded)
            return path

    # No copy on disk: rebuild the image from the IDB itself.
    rebuilt = _image_from_idb(root)
    if rebuilt is not None:
        return rebuilt

    # Last resort, for a format the IDB cannot be rebuilt into yet (PE): the
    # binary is not where IDA recorded it nor beside the IDB.
    where = f"not at {recorded}" if recorded else "no path recorded"
    path = ida_kernwin.ask_file(
        False, root or "*", f"Where is {root or 'the input file'}? ({where}, not beside the IDB)"
    )
    if not path:
        raise SigtoolCancelled
    path = str(path)
    if not _is_input_file(path, sha256, size):
        answer = ida_kernwin.ask_yn(
            0,
            f"HIDECANCEL\n{_basename(path)} is not the file this IDB was made from "
            "(its SHA-256 differs), so addresses may not line up.\n\nUse it anyway?",
        )
        if answer != 1:
            raise SigtoolCancelled
        key = os.path.abspath(path)
        stat = os.stat(path)
        _verified_inputs[(key, stat.st_mtime_ns, stat.st_size)] = True
    _remember_input_file(path, recorded)
    return path


# Images rebuilt from IDBs this session, by IDB path; the files live in one
# temporary directory removed when the plugin unloads.
_rebuilt_images: dict[str, str] = {}
_rebuilt_dir: str | None = None


def _idb_segments() -> list[Segment]:
    segments = []
    for start in idautils.Segments():
        segment = ida_segment.getseg(start)
        if segment is None:
            continue
        offset = int(ida_loader.get_fileregion_offset(int(segment.start_ea)))
        # An ELF IDB's `extern` segment holds import names IDA made up, with
        # no bytes in the file; a PE's `.idata` is also typed extern but is
        # file-backed, and holds the import address table.
        if segment.type == ida_segment.SEG_XTRN and offset < 0:
            continue
        segments.append(
            Segment(
                name=str(ida_segment.get_segm_name(segment) or ""),
                start=int(segment.start_ea),
                end=int(segment.end_ea),
                file_offset=offset if offset >= 0 else None,
                executable=bool(segment.perm & ida_segment.SEGPERM_EXEC),
                writable=bool(segment.perm & ida_segment.SEGPERM_WRITE),
            )
        )
    return segments


def _ida_pe_header() -> bytes:
    """IDA's copy of a PE IDB's headers (empty for any other format)."""
    try:
        header = idautils.peutils_t().header()
    # IDA raises its own types for a non-PE IDB.
    except Exception:
        return b""
    return bytes(header or b"")


def _image_from_idb(root: str) -> str | None:
    """The input file rebuilt from the IDB's original bytes, or ``None``."""
    global _rebuilt_dir
    key = _idb_path() or root
    if key in _rebuilt_images and os.path.isfile(_rebuilt_images[key]):
        return _rebuilt_images[key]
    size = int(ida_nalt.retrieve_input_file_size() or 0)
    segments = _idb_segments()
    if size <= 0 or not segments:
        return None
    image = bytearray(size)
    # Page by page: a segment's bytes are contiguous in the file only as far
    # as IDA's file-region map says, so each page is placed by its own offset.
    page = 0x1000
    for segment in segments:
        if segment.file_offset is None:
            continue
        ea = segment.start
        while ea < segment.end:
            take = min(page - (ea % page), segment.end - ea)
            offset = int(ida_loader.get_fileregion_offset(ea))
            data = ida_bytes.get_bytes(ea, take) if offset >= 0 else None
            if data and offset + len(data) <= size:
                image[offset : offset + len(data)] = data
            ea += take

        # A patched byte goes back to its original value: a signature must
        # describe the shipped code, and the same file signed outside IDA.
        def restore(_ea, fpos, original, _patched):
            if 0 <= fpos < size:
                image[fpos] = original & 0xFF
            return 0

        ida_bytes.visit_patched_bytes(segment.start, segment.end, restore)
    rebuilt = rebuild_elf(bytes(image), segments)
    if rebuilt is None:
        rebuilt = rebuild_pe(
            bytes(image), segments, _ida_pe_header(), int(ida_nalt.get_imagebase())
        )
    if rebuilt is None:
        return None
    if _rebuilt_dir is None:
        _rebuilt_dir = tempfile.mkdtemp(prefix="sigtool-idb-")
    # The file name is the module name signatures record; keep the input's.
    folder = Path(_rebuilt_dir) / str(len(_rebuilt_images))
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (_safe_file_name(root) if root else "image")
    path.write_bytes(rebuilt)
    _rebuilt_images[key] = str(path)
    ida_kernwin.msg(f"sigtool: input file not on disk; read the image from the IDB ({path})\n")
    return str(path)


def _remember_input_file(path: str, recorded: str) -> None:
    # Recording the path in the IDB (what IDA itself does when the debugger
    # asks for a moved input) means the next action, and the next session,
    # find it first.
    ida_nalt.set_root_filename(path)
    ida_kernwin.msg(f"sigtool: input file is {path} (IDB recorded {recorded or 'none'})\n")


# The file last chosen in each kind of dialog, so repeating an action does not
# mean browsing to the same file again.
_last_paths: dict[str, str] = {}


def _dialog_default(kind: str, name: str) -> str:
    """A file dialog's starting point: the last file of ``kind``, else ``name`` beside the IDB."""
    last = _last_paths.get(kind)
    if last:
        return last if not name or "*" in name else os.path.join(os.path.dirname(last), name)
    folder = os.path.dirname(_idb_path())
    return os.path.join(folder, name) if folder else name


def _ask_path(kind: str, saving: bool, name: str, prompt: str) -> str | None:
    # ask_file takes (for_saving, mask or default file name, prompt); there is
    # no separate default-name argument.
    path = ida_kernwin.ask_file(saving, _dialog_default(kind, name), prompt)
    if not path:
        return None
    _last_paths[kind] = str(path)
    return str(path)


def _rva(ea: int) -> int:
    return ea - int(ida_nalt.get_imagebase())


def _function_start(ea: int) -> int:
    function = ida_funcs.get_func(ea)
    return int(function.start_ea) if function is not None else ea


def _target_functions(ctx) -> list[int]:
    """The functions an action applies to: the Functions view's selected rows,
    else the function under the cursor (or the cursor itself outside one).

    In the Functions view the cursor is the last disassembly position, not the
    row the user right-clicked, so its selection must be read from ``ctx``.
    """
    if ctx is not None and getattr(ctx, "widget_type", None) == ida_kernwin.BWN_FUNCS:
        starts = []
        for index in getattr(ctx, "chooser_selection", None) or []:
            function = ida_funcs.getn_func(index)
            if function is not None:
                starts.append(int(function.start_ea))
        if starts:
            return starts
    return [_function_start(int(ida_kernwin.get_screen_ea()))]


def _function_label(ea: int) -> str:
    name = ida_funcs.get_func_name(ea) or ""
    return (
        name
        if is_meaningful_name(name)
        else f"{Path(ida_nalt.get_root_filename() or 'image').name}+{_rva(ea):#x}"
    )


_safe_file_name = safe_file_name


def _settings() -> int:
    try:
        return int(ida_registry.reg_read_int("settings", DEFAULT_SETTINGS, REGISTRY_KEY))
    except Exception:  # an IDA without a registry (tests) keeps the defaults
        return DEFAULT_SETTINGS


def _save_settings(value: int) -> None:
    ida_registry.reg_write_int("settings", int(value), REGISTRY_KEY)


def _setting(flag: int) -> bool:
    return bool(_settings() & flag)


def _remembered(name: str, default: str = "") -> str:
    try:
        return str(ida_registry.reg_read_string(name, REGISTRY_KEY, default) or default)
    except Exception:
        return default


def _remember(name: str, value: str) -> None:
    with contextlib.suppress(Exception):
        ida_registry.reg_write_string(name, value, REGISTRY_KEY)


def _qt_clipboard():
    # IDA 9.2 ships PySide6 (Qt 6); older releases PyQt5. Without a GUI
    # (idat), IDA 9.2's PyQt5 shim raises NotImplementedError, not ImportError.
    for module in ("PySide6.QtWidgets", "PyQt5.QtWidgets"):
        try:
            widgets = __import__(module, fromlist=["QApplication"])
        except Exception:
            continue
        app = widgets.QApplication.instance()
        return app.clipboard() if app is not None else None
    return None


def _clipboard_text() -> str:
    clipboard = _qt_clipboard()
    return str(clipboard.text() or "") if clipboard is not None else ""


def _set_clipboard(text: str) -> bool:
    clipboard = _qt_clipboard()
    if clipboard is None:
        return False
    clipboard.setText(text)
    return True


def _deliver_signature(text: str, report: str, label: str, suffix: str) -> None:
    """Hand a new signature over as the settings say: clipboard, a file beside
    the IDB, or a save dialog when neither is on; the report goes to the
    Output window, and to a dialog only if asked for."""
    done = []
    if _setting(SET_COPY_TO_CLIPBOARD) and _set_clipboard(text):
        done.append("copied to the clipboard")
    path = None
    if _setting(SET_SAVE_BESIDE_IDB):
        path = output_path(_idb_path(), label, suffix)
    elif not done:
        path = _ask_path("yaml", True, f"{safe_file_name(label)}{suffix}", f"Save {label} as")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
        _last_paths["yaml"] = path
        done.append(f"saved to {path}")
    ida_kernwin.msg(f"sigtool: {label}:\n{report}\n")
    ida_kernwin.msg(f"sigtool: signature of {label} {' and '.join(done) or 'discarded'}\n")
    if _setting(SET_SHOW_REPORT):
        ida_kernwin.info(f"{report}\n\n{label}: {', '.join(done) or 'not saved'}")


def _ask_sample() -> str | None:
    """One more merge sample as ``FILE:ADDR`` or ``FILE:+RVA``."""
    path = _ask_path("sample", False, "*", "Other build of this function (image file)")
    if not path:
        return None
    where = ida_kernwin.ask_str(
        "+0x", 0, f"Address (0x...) or RVA from the image base (+0x...) in {_basename(path)}"
    )
    if not where or where.strip() in ("+0x", "0x"):
        return None
    return f"{path}:{where.strip()}"


def _has_user_name(ea: int) -> bool:
    """A name someone (or a loader symbol table) gave ``ea``, not a dummy one."""
    return bool(ida_bytes.has_user_name(ida_bytes.get_flags(ea))) and is_meaningful_name(
        ida_name.get_ea_name(ea)
    )


def _add_function(ea: int, base: int) -> int | None:
    """Create a function at ``ea``; the RVA it starts at, or ``None``."""
    if not ida_funcs.add_func(ea):
        return None
    function = ida_funcs.get_func(ea)
    return None if function is None else int(function.start_ea) - base


def _unsignable(ea: int) -> str | None:
    """Why the function at ``ea`` is not worth signing, or ``None``."""
    function = ida_funcs.get_func(ea)
    if function is None or int(function.start_ea) != ea:
        return "not a function start"
    # A thunk or a PLT stub resolves to the import it jumps to; signing it
    # names the jump, not a function.
    if function.flags & ida_funcs.FUNC_THUNK:
        return "a thunk"
    if function.size() < MIN_FUNCTION_BYTES:
        return f"under {MIN_FUNCTION_BYTES} bytes"
    segment = ida_segment.getseg(ea)
    if segment is not None and segment.type == ida_segment.SEG_XTRN:
        return "an extern"
    if not _has_user_name(ea):
        return "no meaningful name (a DB entry is applied as a name)"
    return None


def _function_entries(starts: Iterable[int]) -> tuple[list[dict[str, str]], list[str]]:
    """A ``db build --functions`` list for ``starts``, and why the rest were left out."""
    base = int(ida_nalt.get_imagebase())
    entries, skipped = [], []
    for ea in starts:
        reason = _unsignable(ea)
        if reason is None:
            entries.append({"rva": f"{ea - base:#x}", "name": ida_funcs.get_func_name(ea)})
        else:
            skipped.append(f"{ea:#x} {ida_funcs.get_func_name(ea) or ''}: {reason}")
    return entries, skipped


def _named_functions() -> list[dict[str, str]]:
    """The IDB's functions worth signing, as a ``db build --functions`` list."""
    return _function_entries(idautils.Functions())[0]


def _db_path(name: str, what: str, given: str | None = None) -> str | None:
    """Where a new DB goes: ``given`` (the menu's DB field), beside the IDB when
    that setting is on, else a save dialog."""
    if given:
        return given
    if _setting(SET_SAVE_BESIDE_IDB):
        return output_path(_idb_path(), name, ".db")
    return _ask_path(
        "db", True, f"{safe_file_name(name)}.db", f"Save the signatures DB for {what} as"
    )


def _sign_to_db(
    image: str, functions: list[dict[str, str]], what: str, name: str, db: str | None = None
) -> None:
    """Sign ``functions`` into a DB, and report what was signed."""
    path = _db_path(name, what, db)
    if not path:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        listing = Path(temp) / "functions.json"
        listing.write_text(json.dumps(functions), encoding="utf-8")
        report_path = Path(temp) / "report.json"
        stderr = _run_cancellable(
            [
                "db",
                "build",
                "--file",
                image,
                "--functions",
                str(listing),
                "--tool",
                "IDA",
                "--report",
                str(report_path),
                "--output",
                path,
            ],
            f"sigtool: signing {what}",
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    for line in stderr.splitlines():
        if line.startswith("skipped "):
            ida_kernwin.msg(f"sigtool: {line}\n")
    _last_paths["db"] = path
    _remember("db", path)
    summary = summarize_build(report)
    ida_kernwin.msg(f"sigtool: {summary.splitlines()[0]}; wrote {path}\n")
    ida_kernwin.info(f"{summary}\n\nDB: {path}")


class _Handler(ida_kernwin.action_handler_t):
    """Shared error reporting for the actions."""

    def activate(self, ctx) -> int:
        try:
            self.run(ctx)
        except SigtoolCancelled:
            ida_kernwin.msg("sigtool: cancelled\n")
        except (SigtoolError, subprocess.TimeoutExpired, OSError) as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def run(self, ctx=None) -> None:
        raise NotImplementedError


def _generate(image: str, ea: int, output: Path) -> str:
    """Sign the function at ``ea`` into ``output``; the quality report."""
    rva = _rva(ea)
    # Signing builds the image's call graph first, which takes a while on a
    # large image: run it behind the cancellable wait box.
    return _run_cancellable(
        ["gen", "--file", image, "--rva", hex(rva), "--tool", "IDA", "--output", str(output)],
        f"sigtool: signing {_function_label(ea)}",
    ).strip()


def _image_stem() -> str:
    return Path(ida_nalt.get_root_filename() or Path(_idb_path()).stem or "image").name


class GenerateHandler(_Handler):
    """Sign the function under the cursor, or the Functions view's selection to a DB."""

    def __init__(self, db: str | None = None) -> None:
        super().__init__()
        self.db = db

    def run(self, ctx=None) -> None:
        starts = _target_functions(ctx)
        image = _input_file()
        if len(starts) > 1:
            functions, skipped = _function_entries(starts)
            for line in skipped:
                ida_kernwin.msg(f"sigtool: not signing {line}\n")
            if not functions:
                raise SigtoolError(
                    f"none of the {len(starts)} selected functions can be signed "
                    "(see the Output window)"
                )
            what = f"{len(functions)} selected functions"
            _sign_to_db(image, functions, what, f"{_image_stem()}.selection", self.db)
            return
        ea = starts[0]
        label = _function_label(ea)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "signature.yaml"
            report = _generate(image, ea, output)
            text = output.read_text(encoding="utf-8")
        _deliver_signature(text, report, label, ".yaml")


class MergeHandler(_Handler):
    """Sign the function together with other builds of it into one signature."""

    def run(self, ctx=None) -> None:
        ea = _target_functions(ctx)[0]
        image = _input_file()
        label = _function_label(ea)
        samples = [f"{image}:+{_rva(ea):#x}"]
        while True:
            sample = _ask_sample()
            if sample is None:
                break
            samples.append(sample)
            if ida_kernwin.ask_yn(0, "HIDECANCEL\nAdd another build?") != 1:
                break
        if len(samples) < 2:
            return
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "merged.yaml"
            arguments = ["merge", "--name", label, "--output", str(output)]
            for sample in samples:
                arguments += ["--sample", sample]
            report = _run_cancellable(
                arguments, f"sigtool: merging {len(samples)} builds of {label}"
            ).strip()
            text = output.read_text(encoding="utf-8")
        _deliver_signature(text, report, label, ".merged.yaml")


class LocateHandler(_Handler):
    """Scan this IDB with a signature (the clipboard's, else a file) and jump to it."""

    def run(self, ctx=None) -> None:
        with tempfile.TemporaryDirectory() as temp:
            signature = None
            clipboard = _clipboard_text() if _setting(SET_LOCATE_CLIPBOARD) else ""
            if is_signature_text(clipboard):
                signature = str(Path(temp) / "clipboard.yaml")
                Path(signature).write_text(clipboard, encoding="utf-8")
                source = "the clipboard"
            else:
                signature = _ask_path("yaml", False, "*.yaml", "Signature to locate in this IDB")
                if not signature:
                    return
                source = Path(signature).name
            image = _input_file()
            output = Path(temp) / "matches.json"
            # Exit 1 is "no accepted match"; the JSON is written either way.
            _run_cancellable(
                [
                    "locate",
                    "--signature",
                    signature,
                    "--file",
                    image,
                    "--json",
                    str(output),
                    "--yes",
                ],
                f"sigtool: locating the signature from {source}",
                ok_codes=(0, 1),
            )
            result = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
        name = str(result.get("signature") or Path(signature).stem)
        rows = match_rows(result.get("matches", []), int(ida_nalt.get_imagebase()))
        if not rows:
            ida_kernwin.msg(f"sigtool: no match for {name} (from {source}) in this IDB\n")
            ida_kernwin.warning(f"sigtool: no match for {name!r} in this IDB")
            return
        ida_kernwin.msg(f"sigtool: {name} (from {source}): {len(rows)} match(es)\n")
        for row in rows:
            ida_kernwin.msg(f"sigtool:   {' '.join(row.cells)}\n")
        if _setting(SET_LIST_MATCHES):
            show_results(
                f"sigtool: matches for {name}",
                [
                    ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                    ["Score", 8],
                    ["Evidence", 10],
                    ["Label", 32],
                    ["Matched", 8],
                ],
                rows,
            )
        if _setting(SET_AUTO_JUMP):
            ida_kernwin.jumpto(rows[0].ea)


class SignAllHandler(_Handler):
    """Sign every meaningfully named function into one signatures DB."""

    def __init__(self, db: str | None = None) -> None:
        super().__init__()
        self.db = db

    def run(self, ctx=None) -> None:
        functions = _named_functions()
        if not functions:
            ida_kernwin.warning("sigtool: no named functions to sign (only sub_* and stubs)")
            return
        what = f"{len(functions)} named functions"
        _sign_to_db(_input_file(), functions, what, _image_stem(), self.db)


class ResultChooser(ida_kernwin.Choose):
    """A non-modal list of addresses; Enter or a double-click jumps to the row."""

    def __init__(self, title: str, columns: list[list], rows: list[Row]) -> None:
        super().__init__(title, columns)
        self.rows = rows

    def OnGetSize(self) -> int:
        return len(self.rows)

    def OnGetLine(self, n: int) -> list[str]:
        return list(self.rows[n].cells)

    def OnGetEA(self, n: int) -> int:
        return self.rows[n].ea

    def OnSelectLine(self, n):
        index = n[0] if isinstance(n, list) else n
        if 0 <= index < len(self.rows):
            ida_kernwin.jumpto(self.rows[index].ea)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnClose(self) -> None:
        # A replaced chooser may report its close after the new one opened.
        if _OPEN_CHOOSERS.get(self.title) is self:
            del _OPEN_CHOOSERS[self.title]


# A non-modal chooser lives on after its action returns; holding it here keeps
# Python from collecting it while the window is open.
_OPEN_CHOOSERS: dict[str, ResultChooser] = {}


def show_results(title: str, columns: list[list], rows: list[Row]) -> None:
    """Open ``rows`` in a non-modal chooser, replacing one with the same title.

    IDA reactivates an open chooser of the same title instead of showing new
    rows, so the old one is closed first.
    """
    previous = _OPEN_CHOOSERS.pop(title, None)
    if previous is not None:
        previous.Close()
    chooser = ResultChooser(title, columns, rows)
    _OPEN_CHOOSERS[title] = chooser
    chooser.Show()


class RenameChooser(ida_kernwin.Choose):
    """The proposed renames, selected per [`default_selection`]; the rows still
    selected are applied."""

    def __init__(self, proposals: list[Proposal], base: int) -> None:
        super().__init__(
            "sigtool: proposed renames (select the rows to apply)",
            [
                ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Current name", 24],
                ["New name", 32],
                ["Score", 8],
                ["Evidence", 10],
            ],
            flags=ida_kernwin.Choose.CH_MULTI,
            deflt=default_selection(proposals, _setting(SET_PRESELECT_USER_NAMES)),
        )
        self.items = [
            [
                f"{base + item.rva:#x}",
                f"{item.current} (user name)" if item.replaces_user_name else item.current,
                item.name,
                f"{item.score:.3f}",
                item.evidence,
            ]
            for item in proposals
        ]
        self.selection: list[int] = []

    def OnGetSize(self) -> int:
        return len(self.items)

    def OnGetLine(self, n: int) -> list[str]:
        return self.items[n]

    def OnSelectLine(self, n):
        # A modal multi-select chooser hands the confirmed rows to this
        # callback; Show() itself returns one index (or < 0 on cancel).
        self.selection = _chosen(n)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def ask(self) -> list[int]:
        """Show the chooser modally: the confirmed rows, or none on cancel."""
        if self.Show(modal=True) < 0:
            return []
        return self.selection


def _chosen(selection) -> list[int]:
    """Normalize a chooser selection (one index or a list of them)."""
    if selection is None:
        return []
    if isinstance(selection, int):
        return [selection] if selection >= 0 else []
    return [int(index) for index in selection if int(index) >= 0]


class ApplyNamesHandler(_Handler):
    """Rename this IDB's functions from a signatures DB's identified matches."""

    def __init__(self, db: str | None = None) -> None:
        super().__init__()
        self.db = db

    def run(self, ctx=None) -> None:
        db = self.db
        if not db or not os.path.isfile(db):
            db = _ask_path("db", False, "*.db", "Signatures DB to apply names from")
        if not db:
            return
        _last_paths["db"] = db
        _remember("db", db)
        image = _input_file()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "hits.json"
            # Exit 1 is "no accepted match", not a failure. Hint-free discovery
            # is the mode that resolves a module's signatures jointly.
            arguments = [
                "scan",
                "--file",
                image,
                "--db",
                db,
                "--discovery",
                "hint-free",
                "--json",
                str(output),
            ]
            # The slowest action: show which phase it is in and how many
            # signatures are done, when the CLI can say.
            if _supports("scan", "--progress"):
                arguments.append("--progress")
            _run_cancellable(
                arguments,
                "sigtool: scanning this IDB with the DB",
                ok_codes=(0, 1),
            )
            hits = (
                json.loads(output.read_text(encoding="utf-8")).get("hits", [])
                if output.exists()
                else []
            )
        base = int(ida_nalt.get_imagebase())

        def name_owner(name: str) -> int | None:
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
            return None if ea == ida_idaapi.BADADDR else int(ea) - base

        proposals, skipped = choose_renames(
            hits,
            current_name=lambda rva: ida_name.get_ea_name(base + rva),
            user_named=lambda rva: _has_user_name(base + rva),
            name_owner=name_owner,
            # Listed but not preselected (see `default_selection`).
            overwrite_user=True,
        )
        for name, reason in skipped:
            ida_kernwin.msg(f"sigtool: not renaming {name}: {reason}\n")
        if not proposals:
            ida_kernwin.warning(
                f"sigtool: no renames to propose ({len(hits)} hits, {len(skipped)} skipped; "
                "see the Output window)"
            )
            return
        if _setting(SET_CONFIRM_RENAMES):
            chosen = RenameChooser(proposals, base).ask()
        else:
            chosen = default_selection(proposals, _setting(SET_PRESELECT_USER_NAMES))
        source = Path(db).name
        rows = []
        for index in chosen:
            item = proposals[index]
            ea = base + item.rva
            function = ida_funcs.get_func(ea)
            problem = rename_blocker(
                item.rva,
                None if function is None else int(function.start_ea) - base,
                bool(ida_bytes.is_code(ida_bytes.get_flags(ea))),
                lambda ea=ea: _add_function(ea, base),
            )
            if problem is not None:
                ida_kernwin.msg(f"sigtool: not renaming {item.name}: {problem}\n")
                continue
            # SN_NOCHECK replaces characters IDA does not allow in names (a
            # name from another toolchain's mangling) instead of failing.
            if not ida_name.set_name(ea, item.name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                ida_kernwin.msg(f"sigtool: IDA refused to rename {ea:#x} to {item.name}\n")
                continue
            function = ida_funcs.get_func(ea)
            if function is not None:
                # A regular, not repeatable, comment: it stays on the function
                # instead of repeating at every call site.
                existing = ida_funcs.get_func_cmt(function, False) or ""
                ida_funcs.set_func_cmt(function, provenance_comment(existing, item, source), False)
            rows.append(
                Row(
                    ea=ea,
                    cells=(
                        f"{ea:#x}",
                        item.current,
                        item.name,
                        f"{item.score:.3f}",
                        item.evidence,
                        item.signature_id,
                    ),
                )
            )
        ida_kernwin.msg(f"sigtool: renamed {len(rows)} of {len(proposals)} proposed functions\n")
        ida_kernwin.refresh_idaview_anyway()
        if rows:
            show_results(
                f"sigtool: renamed from {source}",
                [
                    ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                    ["Old name", 24],
                    ["New name", 32],
                    ["Score", 8],
                    ["Evidence", 10],
                    ["Signature", 20],
                ],
                rows,
            )


class MenuForm(ida_kernwin.Form):
    """The action menu (IDA-Fusion style): one radio row per action, and the
    signatures DB that sign-all writes and apply-names reads."""

    # (control name, label, hint); the radio index is the position here.
    CHOICES = (
        (
            "rGen",
            "Generate a signature for this function",
            "The selected rows in the Functions view sign into the DB below",
        ),
        (
            "rMerge",
            "Merge this function with another build of it",
            "Other image files at an address or RVA",
        ),
        (
            "rLocate",
            "Locate a signature in this IDB",
            "The signature on the clipboard, else a file",
        ),
        (
            "rSignAll",
            "Sign all named functions into the DB",
            "Every function with a meaningful name",
        ),
        ("rApply", "Apply names from the DB", "Rename identified matches of the DB's signatures"),
        ("rSettings", "Configure settings", ""),
    )

    def __init__(self) -> None:
        rows = []
        for index, (name, label, hint) in enumerate(self.CHOICES):
            closing = "{cAction}>" if index == len(self.CHOICES) - 1 else ""
            rows.append(f"<#{hint}#{label}:{{{name}}}>{closing}")
        form = "\n".join(
            [
                "BUTTON YES* Run",
                "BUTTON CANCEL Cancel",
                f"sigtool (signature spec {EXPECTED_SPEC_VERSION})",
                "",
                *rows,
                "",
                "<#Written by sign-all and generate-on-selection, read by apply-names#"
                "Signatures DB:{iDb}>",
                "",
            ]
        )
        super().__init__(
            form,
            {
                "cAction": ida_kernwin.Form.RadGroupControl(
                    tuple(name for name, *_ in self.CHOICES)
                ),
                "iDb": ida_kernwin.Form.FileInput(open=True),
            },
        )


class SettingsForm(ida_kernwin.Form):
    """Checkboxes for [`SETTINGS`], one bit each in order."""

    def __init__(self) -> None:
        names = [f"s{index}" for index in range(len(SETTINGS))]
        rows = []
        for index, (name, (_flag, label)) in enumerate(zip(names, SETTINGS, strict=True)):
            closing = "{cSettings}>" if index == len(SETTINGS) - 1 else ""
            rows.append(f"<{label}:{{{name}}}>{closing}")
        form = "\n".join(["sigtool settings", "", *rows, ""])
        super().__init__(form, {"cSettings": ida_kernwin.Form.ChkGroupControl(tuple(names))})


def show_menu(choice: int, db: str) -> tuple[int, str] | None:
    """Show the menu with ``choice`` and ``db`` filled in; what was chosen, or None."""
    form = MenuForm()
    form.Compile()
    form.cAction.value = choice
    form.iDb.value = db
    try:
        if form.Execute() != 1:
            return None
        return int(form.cAction.value), str(form.iDb.value or "").strip()
    finally:
        form.Free()


def show_settings() -> None:
    form = SettingsForm()
    form.Compile()
    form.cSettings.value = _settings()
    try:
        if form.Execute() == 1:
            _save_settings(int(form.cSettings.value))
    finally:
        form.Free()


class MenuHandler(_Handler):
    """Open the action menu; Configure settings returns to it, as in IDA-Fusion."""

    def run(self, ctx=None) -> None:
        choice = int(_remembered("choice", "0") or 0)
        db = _remembered("db", "")
        if not db:
            db = output_path(_idb_path(), _image_stem(), ".db")
        while True:
            picked = show_menu(choice, db)
            if picked is None:
                return
            choice, db = picked
            _remember("choice", str(choice))
            if db:
                _remember("db", db)
            name = MenuForm.CHOICES[choice][0]
            if name != "rSettings":
                break
            show_settings()
        handlers = {
            "rGen": lambda: GenerateHandler(db),
            "rMerge": MergeHandler,
            "rLocate": LocateHandler,
            "rSignAll": lambda: SignAllHandler(db),
            "rApply": lambda: ApplyNamesHandler(db),
        }
        # The menu acts on the cursor, as the hotkey's context is no view.
        handlers[name]().run(None)


ACTIONS = (
    (GEN_ACTION, GEN_LABEL, GenerateHandler, ""),
    (MERGE_ACTION, MERGE_LABEL, MergeHandler, ""),
    (LOCATE_ACTION, LOCATE_LABEL, LocateHandler, ""),
    (SIGN_ALL_ACTION, SIGN_ALL_LABEL, SignAllHandler, ""),
    (APPLY_ACTION, APPLY_LABEL, ApplyNamesHandler, ""),
)


class PopupHooks(ida_kernwin.UI_Hooks):
    """Attach the actions to the disassembly and Functions right-click menus."""

    def populating_widget_popup(self, form, popup, *_args) -> None:
        if ida_kernwin.get_widget_type(form) not in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_FUNCS,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            return
        for action, *_rest in ACTIONS:
            ida_kernwin.attach_action_to_popup(form, popup, action, "sigtool/")


class SigtoolPlugin(ida_idaapi.plugin_t):
    """Register the actions once per IDA session."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = "sigtool"
    wanted_hotkey = ""
    _hooks: PopupHooks | None = None
    _menu = False

    def init(self):
        # A top-level menu before Help; IDA versions or layouts without one
        # keep the actions under Edit > Plugins. The path names the submenu
        # (trailing slash); a path ending in an item name means "next to that
        # item".
        create_menu = getattr(ida_kernwin, "create_menu", None)
        self._menu = bool(create_menu and create_menu(MENU_NAME, "sigtool", "Help"))
        menu_path = "sigtool/" if self._menu else "Edit/Plugins/"
        everything = ((OPEN_ACTION, OPEN_LABEL, MenuHandler, OPEN_HOTKEY), *ACTIONS)
        for action, label, handler, hotkey in everything:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action, label, handler(), hotkey or None)
            )
            ida_kernwin.attach_action_to_menu(menu_path, action, ida_kernwin.SETMENU_APP)
        self._hooks = PopupHooks()
        self._hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _arg):
        # Edit > Plugins > sigtool: the same menu as the hotkey.
        MenuHandler().activate(None)

    def term(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        ida_kernwin.unregister_action(OPEN_ACTION)
        for action, *_rest in ACTIONS:
            ida_kernwin.unregister_action(action)
        if self._menu:
            ida_kernwin.delete_menu(MENU_NAME)
            self._menu = False
        if _rebuilt_dir is not None:
            shutil.rmtree(_rebuilt_dir, ignore_errors=True)
            _rebuilt_images.clear()


def PLUGIN_ENTRY():
    return SigtoolPlugin()
