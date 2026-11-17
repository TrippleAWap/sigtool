"""IDA plugin front-end for sigtool: UI glue over the native ``sigtool-native`` CLI.

The plugin never extracts features itself (AGENTS.md rule 2). It hands the
IDB's input file and a module-relative address to ``sigtool-native`` and shows
what comes back, so a signature made here is byte-identical to one made with
``sigtool-native gen --file IMAGE --rva RVA``. Addresses cross the boundary as
RVAs (``ea - imagebase``), which keeps rebased databases correct.

Install (IDA 8.4+ / 9.x, Python 3.10+, no extra packages):

    cargo build --release --manifest-path native/Cargo.toml
    # put native/target/release/sigtool-native on PATH, or set SIGTOOL_NATIVE
    # to its full path, then copy this file into %IDAUSR%/plugins

Actions land under Edit > Plugins and on the right-click menus of the
disassembly and Functions views:

* ``sigtool: generate here``: sign the function under the cursor, show the
  quality report, save the YAML, and optionally merge further samples (other
  image files at an address or RVA) into a multi-arch signature.
* ``sigtool: locate in this IDB``: scan the input file with a saved signature
  and jump to the best match.
* ``sigtool: sign all named functions to a DB``: sign every function with a
  meaningful name (not ``sub_*`` or another IDA dummy name, not a thunk, an
  extern, or a stub under five bytes) into one signatures DB, in a single
  ``sigtool-native db build --file IMAGE --functions LIST`` run with progress
  and cancel. Functions the CLI cannot sign are listed and skipped.
* ``sigtool: apply names from a DB``: scan the input file with a signatures DB
  (``scan --db --discovery hint-free``, which resolves signatures from one
  module jointly through their call graph) and propose renames for functions
  whose match is ``identified``. Functions that already carry a user name are
  left alone unless you opt in; a name already used elsewhere in the IDB, two
  signatures claiming one address, or one name claiming two addresses is
  skipped. The proposals open in a chooser; the selected rows are renamed.

Together the last two are the "sign a whole IDB, apply the resolved names to
another" workflow: sign the analysed IDB, then apply the DB in the other one.
"""

from __future__ import annotations

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
import ida_nalt
import ida_name
import ida_segment
import idautils

PLUGIN_COMMENT = "Architecture-independent function signatures"
PLUGIN_HELP = "Generate, merge, and locate sigtool signatures without leaving IDA"

GEN_ACTION = "sigtool:generate"
GEN_LABEL = "sigtool: generate signature here"
LOCATE_ACTION = "sigtool:locate"
LOCATE_LABEL = "sigtool: locate signature in this IDB"
SIGN_ALL_ACTION = "sigtool:sign_all"
SIGN_ALL_LABEL = "sigtool: sign all named functions to a DB"
APPLY_ACTION = "sigtool:apply_names"
APPLY_LABEL = "sigtool: apply names from a DB"
# Generation decodes one function; locating sweeps the image. Both are bounded
# so a pathological input cannot hang the IDA UI thread forever. Whole-IDB
# runs have no fixed bound; they show a wait box with a cancel button instead.
TIMEOUT_SECONDS = 300

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
        if user_named(rva) and not overwrite_user:
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
            )
        )
    return proposals, sorted(skipped)


# -- CLI glue -----------------------------------------------------------------


def _native() -> str:
    configured = os.environ.get("SIGTOOL_NATIVE")
    if configured:
        return configured
    found = shutil.which("sigtool-native")
    if found:
        return found
    sibling = Path(__file__).with_name(
        "sigtool-native.exe" if os.name == "nt" else "sigtool-native"
    )
    if sibling.exists():
        return str(sibling)
    raise SigtoolError("sigtool-native not found: put it on PATH or set SIGTOOL_NATIVE")


def _run(*args: str) -> str:
    result = subprocess.run(
        [_native(), *args], capture_output=True, text=True, timeout=TIMEOUT_SECONDS
    )
    if result.returncode != 0:
        raise SigtoolError(result.stderr.strip() or f"exit code {result.returncode}")
    return result.stderr


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


def _input_file() -> str:
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.exists(path):
        path = ida_kernwin.ask_file(False, "*", "Input file of this IDB (not found on disk)")
    if not path:
        raise SigtoolError("the IDB's input file is needed to read the function bytes")
    return str(path)


def _rva(ea: int) -> int:
    return ea - int(ida_nalt.get_imagebase())


def _function_start(ea: int) -> int:
    function = ida_funcs.get_func(ea)
    return int(function.start_ea) if function is not None else ea


def _save_yaml(text: str, suggested: str) -> str | None:
    path = ida_kernwin.ask_file(True, "*.yaml", "Save signature as", suggested)
    if not path:
        return None
    Path(path).write_text(text, encoding="utf-8")
    return str(path)


def _ask_sample() -> str | None:
    """One more merge sample as ``FILE:ADDR`` or ``FILE:+RVA``."""
    path = ida_kernwin.ask_file(False, "*.elf;*.so;*.dll;*.exe;*.sys;*", "Sample image file")
    if not path:
        return None
    where = ida_kernwin.ask_str("+0x1000", 0, "Sample address (0x...) or RVA (+0x...)")
    if not where:
        return None
    return f"{path}:{where.strip()}"


def _has_user_name(ea: int) -> bool:
    """A name someone (or a loader symbol table) gave ``ea``, not a dummy one."""
    return bool(ida_bytes.has_user_name(ida_bytes.get_flags(ea))) and is_meaningful_name(
        ida_name.get_ea_name(ea)
    )


def _named_functions() -> list[dict[str, str]]:
    """The IDB's functions worth signing, as a ``db build --functions`` list."""
    base = int(ida_nalt.get_imagebase())
    entries = []
    for ea in idautils.Functions():
        function = ida_funcs.get_func(ea)
        if function is None or int(function.start_ea) != ea:
            continue
        # A thunk or a PLT stub resolves to the import it jumps to; signing it
        # names the jump, not a function.
        if function.flags & ida_funcs.FUNC_THUNK or function.size() < MIN_FUNCTION_BYTES:
            continue
        segment = ida_segment.getseg(ea)
        if segment is not None and segment.type == ida_segment.SEG_XTRN:
            continue
        if not _has_user_name(ea):
            continue
        entries.append({"rva": f"{ea - base:#x}", "name": ida_funcs.get_func_name(ea)})
    return entries


class _Handler(ida_kernwin.action_handler_t):
    """Shared error reporting for the actions."""

    def activate(self, ctx) -> int:
        try:
            self.run()
        except SigtoolCancelled:
            ida_kernwin.msg("sigtool: cancelled\n")
        except (SigtoolError, subprocess.TimeoutExpired, OSError) as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def run(self) -> None:
        raise NotImplementedError


class GenerateHandler(_Handler):
    """Sign the function under the cursor, then optionally merge more samples."""

    def run(self) -> None:
        image = _input_file()
        rva = _rva(_function_start(int(ida_kernwin.get_screen_ea())))
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "signature.yaml"
            report = _run(
                "gen", "--file", image, "--rva", hex(rva), "--tool", "IDA", "--output", str(output)
            )
            text = output.read_text(encoding="utf-8")
        ida_kernwin.info(report.strip())
        name = Path(image).stem + f"+{rva:#x}"
        path = _save_yaml(text, f"{name}.yaml")
        if path:
            ida_kernwin.msg(f"sigtool: wrote {path}\n")

        if ida_kernwin.ask_yn(False, "Merge another sample into this signature?") != 1:
            return
        samples = [f"{image}:+{rva:#x}"]
        while True:
            sample = _ask_sample()
            if sample is None:
                break
            samples.append(sample)
            if ida_kernwin.ask_yn(False, "Add another sample?") != 1:
                break
        if len(samples) < 2:
            ida_kernwin.warning("sigtool: merging needs a second sample")
            return
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "merged.yaml"
            arguments = ["merge", "--output", str(output)]
            for sample in samples:
                arguments += ["--sample", sample]
            report = _run(*arguments)
            text = output.read_text(encoding="utf-8")
        ida_kernwin.info(report.strip())
        merged_path = _save_yaml(text, f"{name}.merged.yaml")
        if merged_path:
            ida_kernwin.msg(f"sigtool: wrote merged signature {merged_path}\n")


class LocateHandler(_Handler):
    """Scan this IDB's input file with a saved signature and jump to the best match."""

    def run(self) -> None:
        signature = ida_kernwin.ask_file(False, "*.yaml;*.yml", "Signature file")
        if not signature:
            return
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "matches.json"
            _run(
                "locate",
                "--signature",
                signature,
                "--file",
                _input_file(),
                "--json",
                str(output),
                "--yes",
            )
            result = json.loads(output.read_text(encoding="utf-8"))
        matches = result.get("matches", [])
        if not matches:
            ida_kernwin.warning(f"sigtool: no match for {result.get('signature')!r} in this IDB")
            return
        base = int(ida_nalt.get_imagebase())
        lines = [f"{result.get('signature')}: {len(matches)} match(es)"]
        for index, match in enumerate(matches, start=1):
            ea = base + int(match["rva"], 16)
            label = match.get("label") or "unlabelled"
            evidence = match.get("evidence", "")
            lines.append(f"{index}. {ea:#x} score {match['score']:.3f} {evidence} {label}")
        ida_kernwin.info("\n".join(lines))
        ida_kernwin.jumpto(base + int(matches[0]["rva"], 16))


class SignAllHandler(_Handler):
    """Sign every meaningfully named function into one signatures DB."""

    def run(self) -> None:
        image = _input_file()
        functions = _named_functions()
        if not functions:
            ida_kernwin.warning("sigtool: no named functions to sign (only sub_* and stubs)")
            return
        if (
            ida_kernwin.ask_yn(True, f"Sign {len(functions)} named functions into a signatures DB?")
            != 1
        ):
            return
        path = ida_kernwin.ask_file(True, "*.db", "Save signatures DB as", f"{Path(image).stem}.db")
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
                f"sigtool: signing {len(functions)} functions",
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
        for line in stderr.splitlines():
            if line.startswith("skipped "):
                ida_kernwin.msg(f"sigtool: {line}\n")
        ida_kernwin.msg(f"sigtool: wrote {path}\n")
        ida_kernwin.info(f"{summarize_build(report)}\n\nDB: {path}")


class RenameChooser(ida_kernwin.Choose):
    """The proposed renames; the selected rows are applied."""

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
            flags=ida_kernwin.Choose.CH_MULTI | ida_kernwin.Choose.CH_MODAL,
            deflt=list(range(len(proposals))),
        )
        self.items = [
            [
                f"{base + item.rva:#x}",
                item.current,
                item.name,
                f"{item.score:.3f}",
                item.evidence,
            ]
            for item in proposals
        ]

    def OnGetSize(self) -> int:
        return len(self.items)

    def OnGetLine(self, n: int) -> list[str]:
        return self.items[n]


def _chosen(selection) -> list[int]:
    """Normalize what a modal multi-select chooser returns across IDA versions."""
    if selection is None:
        return []
    if isinstance(selection, int):
        return [selection] if selection >= 0 else []
    return [int(index) for index in selection if int(index) >= 0]


class ApplyNamesHandler(_Handler):
    """Rename this IDB's functions from a signatures DB's identified matches."""

    def run(self) -> None:
        image = _input_file()
        db = ida_kernwin.ask_file(False, "*.db", "Signatures DB")
        if not db:
            return
        overwrite = (
            ida_kernwin.ask_yn(False, "Also rename functions that already have a user name?") == 1
        )
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
            overwrite_user=overwrite,
        )
        for name, reason in skipped:
            ida_kernwin.msg(f"sigtool: not renaming {name}: {reason}\n")
        if not proposals:
            ida_kernwin.warning(
                f"sigtool: no renames to propose ({len(hits)} hits, {len(skipped)} skipped; "
                "see the Output window)"
            )
            return
        chosen = _chosen(RenameChooser(proposals, base).show())
        renamed = 0
        for index in chosen:
            item = proposals[index]
            ea = base + item.rva
            if ida_funcs.get_func(ea) is None:
                ida_funcs.add_func(ea)
            # SN_NOCHECK replaces characters IDA does not allow in names (a
            # name from another toolchain's mangling) instead of failing.
            if ida_name.set_name(ea, item.name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                renamed += 1
            else:
                ida_kernwin.msg(f"sigtool: IDA refused to rename {ea:#x} to {item.name}\n")
        ida_kernwin.msg(f"sigtool: renamed {renamed} of {len(proposals)} proposed functions\n")
        ida_kernwin.refresh_idaview_anyway()


ACTIONS = (
    (GEN_ACTION, GEN_LABEL, GenerateHandler, "Ctrl-Shift-G"),
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

    def init(self):
        for action, label, handler, hotkey in ACTIONS:
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(action, label, handler(), hotkey or None)
            )
            ida_kernwin.attach_action_to_menu(
                f"Edit/Plugins/{label}", action, ida_kernwin.SETMENU_APP
            )
        self._hooks = PopupHooks()
        self._hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _arg):
        lines = [
            f"  {label} ({hotkey})" if hotkey else f"  {label}"
            for _action, label, _handler, hotkey in ACTIONS
        ]
        ida_kernwin.info("sigtool actions:\n" + "\n".join(lines))

    def term(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        for action, *_rest in ACTIONS:
            ida_kernwin.unregister_action(action)


def PLUGIN_ENTRY():
    return SigtoolPlugin()
