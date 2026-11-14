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
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt

PLUGIN_COMMENT = "Architecture-independent function signatures"
PLUGIN_HELP = "Generate, merge, and locate sigtool signatures without leaving IDA"

GEN_ACTION = "sigtool:generate"
GEN_LABEL = "sigtool: generate signature here"
LOCATE_ACTION = "sigtool:locate"
LOCATE_LABEL = "sigtool: locate signature in this IDB"
# Generation decodes one function; locating sweeps the image. Both are bounded
# so a pathological input cannot hang the IDA UI thread forever.
TIMEOUT_SECONDS = 300


class SigtoolError(Exception):
    """A failed ``sigtool-native`` run, with its stderr as the message."""


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


class GenerateHandler(ida_kernwin.action_handler_t):
    """Sign the function under the cursor, then optionally merge more samples."""

    def activate(self, ctx) -> int:
        try:
            self._generate()
        except (SigtoolError, subprocess.TimeoutExpired) as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _generate(self) -> None:
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


class LocateHandler(ida_kernwin.action_handler_t):
    """Scan this IDB's input file with a saved signature and jump to the best match."""

    def activate(self, ctx) -> int:
        try:
            self._locate()
        except (SigtoolError, subprocess.TimeoutExpired) as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _locate(self) -> None:
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


class PopupHooks(ida_kernwin.UI_Hooks):
    """Attach the actions to the disassembly and Functions right-click menus."""

    def populating_widget_popup(self, form, popup, *_args) -> None:
        if ida_kernwin.get_widget_type(form) not in (
            ida_kernwin.BWN_DISASM,
            ida_kernwin.BWN_FUNCS,
            ida_kernwin.BWN_PSEUDOCODE,
        ):
            return
        for action in (GEN_ACTION, LOCATE_ACTION):
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
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(GEN_ACTION, GEN_LABEL, GenerateHandler(), "Ctrl-Shift-G")
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(LOCATE_ACTION, LOCATE_LABEL, LocateHandler(), "Ctrl-Shift-L")
        )
        for label, action in ((GEN_LABEL, GEN_ACTION), (LOCATE_LABEL, LOCATE_ACTION)):
            ida_kernwin.attach_action_to_menu(
                f"Edit/Plugins/{label}", action, ida_kernwin.SETMENU_APP
            )
        self._hooks = PopupHooks()
        self._hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _arg):
        ida_kernwin.info(
            f"sigtool actions:\n  {GEN_LABEL} (Ctrl-Shift-G)\n  {LOCATE_LABEL} (Ctrl-Shift-L)"
        )

    def term(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        for action in (GEN_ACTION, LOCATE_ACTION):
            ida_kernwin.unregister_action(action)


def PLUGIN_ENTRY():
    return SigtoolPlugin()
