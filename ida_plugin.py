"""IDA plugin front-end (UI glue only; AGENTS.md rule 2).

Everything that touches bytes, features, matching, or serialisation lives in
``core/`` and ``sources/``; this file resolves the current IDB into an
:class:`sources.ida.IdaSource`, calls :func:`core.generate.generate` /
:func:`core.merge.merge` / :func:`core.match.scan`, and formats dialogs.

Install (IDA 8.4+ / 9.x, Python 3.10+):

    pip install -e <sigtool checkout>   # into IDA's Python environment
    # then copy this file into the IDA user plugins directory (%IDAUSR%/plugins)
    # or point IDA's PYTHONPATH at the checkout

Actions land under Edit > Plugins and on the right-click menus of the
disassembly and Functions views:

* ``sigtool: generate here`` — sign the function under the cursor, show the
  quality report (including any recovery/IDA bounds disagreement), save the
  YAML, and optionally merge another sample (an IDB, an image file, or a live
  Windows PID) into a multi-arch signature.
* ``sigtool: locate in this IDB`` — scan the current database with a saved
  signature and jump to the best match.
"""

from __future__ import annotations

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines

from core.errors import SelfTestError, SigToolError, UnsupportedArchError
from core.generate import GenerationResult, generate
from core.match import scan
from core.merge import MergeSample, merge
from core.sigfile import Signature
from sources.file import FileSource
from sources.ida import IdaSource

PLUGIN_COMMENT = "Architecture-independent function signatures"
PLUGIN_HELP = "Generate, merge, and locate sigtool signatures without leaving IDA"
PLUGIN_WANTED_HOTKEY = ""

GEN_ACTION = "sigtool:generate"
GEN_LABEL = "sigtool: generate signature here"
LOCATE_ACTION = "sigtool:locate"
LOCATE_LABEL = "sigtool: locate signature in this IDB"
POPUP_PATHS = ("Disassembly", "Functions")


def _source() -> IdaSource:
    return IdaSource.from_ida()


def _current_address() -> int:
    return int(ida_kernwin.get_screen_ea())


def _function_bounds(addr: int) -> tuple[int, int] | None:
    function = ida_funcs.get_func(addr)
    if function is None:
        return None
    return (int(function.start_ea), int(function.end_ea))


def _report_text(source: IdaSource, result: GenerationResult, addr: int) -> str:
    """The dialog body: quality report plus the bounds-disagreement note."""
    signature = result.signature
    report = result.report
    lines = [
        f"signature {signature.name}  ({signature.signature_id})",
        f"arch {source.arch.value}  verdict {report.verdict}  confidence {signature.confidence}",
        f"features {len(signature.features)} (required {report.required_features}, "
        f"optional {report.optional_features})  anchors {report.anchor_count}",
        f"self-test 0x{result.match.address:x} score {result.match.score:.3f}",
    ]
    disagreement = source.bounds_disagreement(addr, result.match.address, result.match.end)
    if disagreement is not None:
        lines.append(f"note: {disagreement}")
    lines.extend(f"note: {note}" for note in report.notes)
    return "\n".join(lines)


def _save_yaml(text: str, suggested: str) -> str | None:
    path = ida_kernwin.ask_file(True, "*.yaml", "Save signature as", suggested)
    if not path:
        return None
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return str(path)


def _sample_from_file() -> MergeSample | None:
    path = ida_kernwin.ask_file(False, "*.elf;*.dll;*.exe;*.so;*.sys", "Sample image file")
    if not path:
        return None
    addr_text = ida_kernwin.ask_str("0x1000", 0, "Sample address (hex)")
    if not addr_text:
        return None
    addr = int(addr_text, 16)
    return MergeSample(FileSource.from_path(path), addr)


def _sample_from_process() -> MergeSample | None:
    pid_text = ida_kernwin.ask_str("0", 0, "Live process id (Windows, read-only)")
    if not pid_text:
        return None
    from sources.proc_win import WindowsProcessSource

    source = WindowsProcessSource.open(int(pid_text))
    addr_text = ida_kernwin.ask_str("0x1000", 0, "Sample address (hex)")
    if not addr_text:
        source.close()
        return None
    return MergeSample(source, int(addr_text, 16))


class GenerateHandler(ida_kernwin.action_handler_t):
    """Sign the function under the cursor, then optionally merge more samples."""

    samples: list[MergeSample]

    def activate(self, ctx) -> int:
        try:
            self._run()
        except UnsupportedArchError as error:
            ida_kernwin.warning(f"sigtool: unsupported target: {error}")
        except SelfTestError as error:
            ida_kernwin.warning(f"sigtool: refused to emit a signature: {error}")
        except SigToolError as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _run(self) -> None:
        source = _source()
        addr = _current_address()
        result = generate(source, addr)
        ida_kernwin.info(_report_text(source, result, addr))
        path = _save_yaml(result.to_yaml(), f"{result.signature.name}.yaml")
        if path:
            ida_kernwin.msg(f"sigtool: wrote {path}\n")

        if ida_kernwin.ask_yn(False, "Merge another sample into this signature?") != 1:
            return
        samples = [self._sample_for_current(source, result)]
        while True:
            mode = ida_kernwin.ask_yn(False, "Add the sample from an image file? (No: live PID)")
            sample = _sample_from_file() if mode == 1 else _sample_from_process()
            if sample is None:
                break
            samples.append(sample)
            if ida_kernwin.ask_yn(False, "Add another sample?") != 1:
                break
        if len(samples) < 2:
            ida_kernwin.warning("sigtool: merging needs a second sample")
            return
        merged = merge(samples, name=result.signature.name)
        merged_path = _save_yaml(merged.to_yaml(), f"{merged.signature.name}.merged.yaml")
        if merged_path:
            ida_kernwin.msg(f"sigtool: wrote merged signature {merged_path}\n")

    @staticmethod
    def _sample_for_current(source: IdaSource, result: GenerationResult) -> MergeSample:
        opt = ida_kernwin.ask_str("", 0, "Provenance opt level (e.g. O2, empty for none)")
        return MergeSample(source, result.match.address, opt=opt or None, tool="IDA")


class LocateHandler(ida_kernwin.action_handler_t):
    """Scan this IDB with a saved signature and jump to the best match."""

    def activate(self, ctx) -> int:
        try:
            self._run()
        except UnsupportedArchError as error:
            ida_kernwin.warning(f"sigtool: unsupported target: {error}")
        except SigToolError as error:
            ida_kernwin.warning(f"sigtool: {error}")
        return 1

    def update(self, _ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _run(self) -> None:
        signature_path = ida_kernwin.ask_file(False, "*.yaml;*.yml", "Signature file")
        if not signature_path:
            return
        with open(signature_path, encoding="utf-8") as handle:
            signature = Signature.from_yaml(handle.read())
        source = _source()
        matches = scan(source, signature)
        if not matches:
            ida_kernwin.warning(f"sigtool: no match for {signature.name!r} in this IDB")
            return
        lines = [f"{signature.name}: {len(matches)} match(es)"]
        for index, match in enumerate(matches, start=1):
            label = source.label_for_address(match.address) or "unlabelled"
            lines.append(f"{index}. 0x{match.address:x} score {match.score:.3f} {label}")
        ida_kernwin.info("\n".join(lines))
        ida_kernwin.jumpto(matches[0].address)


class PopupHooks(ida_kernwin.UI_Hooks):
    """Attach the actions to the disassembly and Functions right-click menus."""

    def populating_widget_popup(self, form, popup, *_args) -> None:
        widget_type = ida_kernwin.get_widget_type(form)
        if widget_type not in (
            ida_idaapi.BWN_DISASM,
            ida_idaapi.BWN_FUNCS,
            ida_idaapi.BWN_PSEUDOCODE,
        ):
            return
        for action in (GEN_ACTION, LOCATE_ACTION):
            ida_kernwin.attach_action_to_popup(
                form, popup, action, "sigtool/", ida_kernwin.SETMENU_APP
            )


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
        ida_kernwin.attach_action_to_menu(
            f"Edit/Plugins/{GEN_LABEL}", GEN_ACTION, ida_kernwin.SETMENU_APP
        )
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/" + LOCATE_LABEL, LOCATE_ACTION, ida_kernwin.SETMENU_APP
        )
        self._hooks = PopupHooks()
        self._hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _arg):
        ida_kernwin.info(
            "sigtool actions:\n"
            f"  {GEN_LABEL} ({ida_lines.tag_remove('Ctrl-Shift-G')})\n"
            f"  {LOCATE_LABEL} ({ida_lines.tag_remove('Ctrl-Shift-L')})"
        )

    def term(self):
        if self._hooks is not None:
            self._hooks.unhook()
            self._hooks = None
        for action in (GEN_ACTION, LOCATE_ACTION):
            ida_kernwin.unregister_action(action)


def PLUGIN_ENTRY():
    return SigtoolPlugin()
