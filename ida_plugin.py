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

The CLI reads the IDB's input file, because an IDB holds only the loaded
segments and the matcher also needs the parts IDA drops (relocations, unwind
tables, dynamic symbols). The plugin finds that file itself: the path IDA
recorded, else a file of the same name beside the IDB (an IDB copied to
another machine or folder), each accepted only when its SHA-256 equals the
one IDA stored when the IDB was made. A file found somewhere new is recorded
in the IDB, so the plugin asks for it at most once, and only when no
candidate matches.

Actions land in a ``sigtool`` menu (Edit > Plugins when IDA cannot add one)
and on the right-click menus of the disassembly, pseudocode, and Functions
views. In the Functions view they act on the selected rows.

* ``sigtool: generate signature``: sign the function under the cursor and
  save the YAML (default: the function's name, beside the IDB). With several
  functions selected in the Functions view, sign them into one DB instead.
* ``sigtool: merge with another build``: sign the function together with the
  same function in other image files (at an address or RVA) into one
  multi-arch signature.
* ``sigtool: locate signature in this IDB``: scan the input file with a saved
  signature, list the matches, and jump to the best one.
* ``sigtool: sign all named functions to a DB``: sign every function with a
  meaningful name (not ``sub_*`` or another IDA dummy name, not a thunk, an
  extern, or a stub under five bytes) into one signatures DB, in a single
  ``sigtool-native db build --file IMAGE --functions LIST`` run with progress
  and cancel. Functions the CLI cannot sign are listed and skipped.
* ``sigtool: apply names from a DB``: scan the input file with a signatures DB
  (``scan --db --discovery hint-free``, which resolves signatures from one
  module jointly through their call graph) and propose renames for functions
  whose match is ``identified``. The proposals open in a chooser with every
  row selected except those that would replace a user name; the selected rows
  are renamed. A name already used elsewhere in the IDB, two signatures
  claiming one address, or one name claiming two addresses is skipped.

File dialogs start beside the IDB, or at the file last used for that action.

Together the last two are the "sign a whole IDB, apply the resolved names to
another" workflow: sign the analysed IDB, then apply the DB in the other one.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
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
MENU_NAME = "sigtool:menu"
# Generation decodes one function; locating sweeps the image. Both are bounded
# so a pathological input cannot hang the IDA UI thread forever. Whole-IDB
# runs have no fixed bound; they show a wait box with a cancel button instead.
TIMEOUT_SECONDS = 300
# The signature spec this plugin was released with (native/src/spec.rs
# SPEC_VERSION; a unit test keeps them equal). A CLI writing another spec
# still runs, but its signatures and DBs will not load in a matching build.
EXPECTED_SPEC_VERSION = "5"

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
    """``progress DONE/TOTAL`` lines that ``db build --functions`` prints."""
    match = re.fullmatch(r"progress (\d+)/(\d+)", line.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


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


def default_selection(proposals: list[Proposal]) -> list[int]:
    """Rows the rename chooser starts with selected: all but user-name replacements.

    Replacing an analyst's name is shown, so it is one click away, but never
    applied by just confirming the dialog.
    """
    return [index for index, item in enumerate(proposals) if not item.replaces_user_name]


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
    collected: list[str] = []
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
                collected.append(line)
                progress = parse_progress(line)
                if progress is not None:
                    ida_kernwin.replace_wait_box(f"{message}\n{progress[0]} / {progress[1]}")
            if ida_kernwin.user_cancelled():
                process.kill()
                process.wait()
                raise SigtoolCancelled
        returncode = process.wait()
    finally:
        ida_kernwin.hide_wait_box()
    stderr = "".join(collected)
    if returncode not in ok_codes:
        raise SigtoolError(stderr.strip() or f"exit code {returncode}")
    return stderr


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

    # Last resort: the binary is not where IDA recorded it nor beside the IDB.
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


def _safe_file_name(name: str) -> str:
    # Mangled C++ and Objective-C names hold characters file systems refuse.
    return re.sub(r'[<>:"/\\|?*\s]+', "_", name).strip("._") or "signature"


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


def _sign_to_db(image: str, functions: list[dict[str, str]], what: str) -> None:
    """Sign ``functions`` into a DB the user names, and report what was signed."""
    stem = Path(ida_nalt.get_root_filename() or Path(image).name).name
    path = _ask_path("db", True, f"{stem}.db", f"Save the signatures DB for {what} as")
    if not path:
        return
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
    ida_kernwin.msg(f"sigtool: wrote {path}\n")
    ida_kernwin.info(f"{summarize_build(report)}\n\nDB: {path}")


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


class GenerateHandler(_Handler):
    """Sign the function under the cursor, or the Functions view's selection to a DB."""

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
            _sign_to_db(image, functions, f"{len(functions)} selected functions")
            return
        ea = starts[0]
        label = _function_label(ea)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "signature.yaml"
            report = _generate(image, ea, output)
            text = output.read_text(encoding="utf-8")
        ida_kernwin.msg(f"sigtool: {label}:\n{report}\n")
        path = _ask_path(
            "yaml", True, f"{_safe_file_name(label)}.yaml", f"Save the signature of {label} as"
        )
        if not path:
            return
        Path(path).write_text(text, encoding="utf-8")
        ida_kernwin.msg(f"sigtool: wrote {path}\n")
        ida_kernwin.info(f"{report}\n\nSaved {path}")


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
        ida_kernwin.msg(f"sigtool: {label} (merged):\n{report}\n")
        path = _ask_path(
            "yaml",
            True,
            f"{_safe_file_name(label)}.merged.yaml",
            f"Save the merged signature of {label} as",
        )
        if not path:
            return
        Path(path).write_text(text, encoding="utf-8")
        ida_kernwin.msg(f"sigtool: wrote merged signature {path}\n")
        ida_kernwin.info(f"{report}\n\nSaved {path}")


class LocateHandler(_Handler):
    """Scan this IDB's input file with a saved signature and list the matches."""

    def run(self, ctx=None) -> None:
        signature = _ask_path("yaml", False, "*.yaml", "Signature to locate in this IDB")
        if not signature:
            return
        image = _input_file()
        with tempfile.TemporaryDirectory() as temp:
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
                f"sigtool: locating {Path(signature).name} in this IDB",
                ok_codes=(0, 1),
            )
            result = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
        name = str(result.get("signature") or Path(signature).stem)
        rows = match_rows(result.get("matches", []), int(ida_nalt.get_imagebase()))
        if not rows:
            ida_kernwin.warning(f"sigtool: no match for {name!r} in this IDB")
            return
        for row in rows:
            ida_kernwin.msg(f"sigtool: {name}: {' '.join(row.cells)}\n")
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
        ida_kernwin.jumpto(rows[0].ea)


class SignAllHandler(_Handler):
    """Sign every meaningfully named function into one signatures DB."""

    def run(self, ctx=None) -> None:
        functions = _named_functions()
        if not functions:
            ida_kernwin.warning("sigtool: no named functions to sign (only sub_* and stubs)")
            return
        _sign_to_db(_input_file(), functions, f"{len(functions)} named functions")


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
            deflt=default_selection(proposals),
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

    def run(self, ctx=None) -> None:
        db = _ask_path("db", False, "*.db", "Signatures DB to apply names from")
        if not db:
            return
        image = _input_file()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "hits.json"
            # Exit 1 is "no accepted match", not a failure. Hint-free discovery
            # is the mode that resolves a module's signatures jointly.
            _run_cancellable(
                [
                    "scan",
                    "--file",
                    image,
                    "--db",
                    db,
                    "--discovery",
                    "hint-free",
                    "--json",
                    str(output),
                ],
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
        chosen = RenameChooser(proposals, base).ask()
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


ACTIONS = (
    (GEN_ACTION, GEN_LABEL, GenerateHandler, "Ctrl-Shift-G"),
    (MERGE_ACTION, MERGE_LABEL, MergeHandler, ""),
    (LOCATE_ACTION, LOCATE_LABEL, LocateHandler, "Ctrl-Shift-L"),
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
        for action, label, handler, hotkey in ACTIONS:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action, label, handler(), hotkey or None)
            )
            ida_kernwin.attach_action_to_menu(menu_path, action, ida_kernwin.SETMENU_APP)
        self._hooks = PopupHooks()
        self._hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _arg):
        # Edit > Plugins > sigtool (or its hotkey): pick an action from a list.
        index = ActionPicker().Show(modal=True)
        if isinstance(index, int) and 0 <= index < len(ACTIONS):
            ida_kernwin.process_ui_action(ACTIONS[index][0])

    def term(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        for action, *_rest in ACTIONS:
            ida_kernwin.unregister_action(action)
        if self._menu:
            ida_kernwin.delete_menu(MENU_NAME)
            self._menu = False


class ActionPicker(ida_kernwin.Choose):
    """The actions in a modal list; the chosen row's index is what Show returns."""

    def __init__(self) -> None:
        super().__init__(
            "sigtool", [["Action", 40], ["Hotkey", 12]], flags=ida_kernwin.Choose.CH_MODAL
        )

    def OnGetSize(self) -> int:
        return len(ACTIONS)

    def OnGetLine(self, n: int) -> list[str]:
        _action, label, _handler, hotkey = ACTIONS[n]
        return [label.removeprefix("sigtool: "), hotkey]


def PLUGIN_ENTRY():
    return SigtoolPlugin()
