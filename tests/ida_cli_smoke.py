"""End-to-end check of ida_plugin.py's actions against the real CLI, outside IDA.

IDA's modules are replaced by in-process fakes that model one IDB (the
functions and names from a corpus ``ground_truth.json``), answer the dialogs
from a script, and record what the plugin shows. The plugin's own code runs
unchanged: it builds the ``sigtool-native`` command lines, runs them behind
the wait box, parses their JSON, and decides the renames. This checks the
plugin-to-CLI contract; it does not exercise IDA's UI or its API (that needs
a licensed IDA, see AGENTS.md).

    python tests/ida_cli_smoke.py --corpus corpus/build-real
    python tests/ida_cli_smoke.py --corpus corpus/build-real --arch arm64 \\
        --library lz4 --sign clang-O2 --apply gcc-Os

Steps: sign one function (generate, then merge it with another arch's build), locate
it, sign every ground-truth function of the ``--sign`` build into a DB, and
apply the DB to the stripped ``--apply`` build. Exit 0 when every step's
assertion holds; the renames' precision against ground truth is printed.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import tempfile
import types
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BADADDR = 0xFFFFFFFFFFFFFFFF


class FakeIdb:
    """One IDB: function starts and sizes, names, comments, and the UI log."""

    def __init__(self, image: Path, functions: dict[int, tuple[str | None, int]]) -> None:
        self.image = image
        self.functions = functions
        self.code = executable_ranges(image)
        self.names = {ea: name for ea, (name, _size) in functions.items() if name}
        self.comments: dict[int, str] = {}
        self.answers: deque = deque()
        self.screen_ea = 0
        self.jumps: list[int] = []
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.choosers: list = []

    def answer(self, *values) -> None:
        self.answers.extend(values)

    def next_answer(self, prompt: str):
        if not self.answers:
            raise AssertionError(f"unexpected dialog: {prompt}")
        return self.answers.popleft()


def install_fakes(idb: FakeIdb) -> None:
    """Register fake ``ida_*`` modules that read and write ``idb``."""

    def module(name: str) -> types.ModuleType:
        fake = types.ModuleType(name)
        sys.modules[name] = fake
        return fake

    idaapi = module("ida_idaapi")
    idaapi.BADADDR = BADADDR
    idaapi.PLUGIN_KEEP = 2
    idaapi.plugin_t = type("plugin_t", (), {})

    kernwin = module("ida_kernwin")
    kernwin.AST_ENABLE_ALWAYS = 1
    kernwin.SETMENU_APP = 1
    kernwin.BWN_DISASM = kernwin.BWN_FUNCS = kernwin.BWN_PSEUDOCODE = 0
    kernwin.action_handler_t = type("action_handler_t", (), {})
    kernwin.UI_Hooks = type("UI_Hooks", (), {})
    kernwin.msg = lambda text: sys.stdout.write(f"  [ida] {text}")
    kernwin.info = lambda text: idb.infos.append(text)
    kernwin.warning = lambda text: idb.warnings.append(text)
    kernwin.ask_file = lambda _save, _mask, prompt: idb.next_answer(prompt)
    kernwin.ask_yn = lambda _default, prompt: idb.next_answer(prompt)
    kernwin.ask_str = lambda _default, _hist, prompt: idb.next_answer(prompt)
    kernwin.show_wait_box = kernwin.replace_wait_box = lambda _text: None
    kernwin.hide_wait_box = lambda: None
    kernwin.user_cancelled = lambda: False
    kernwin.get_screen_ea = lambda: idb.screen_ea
    kernwin.jumpto = lambda ea: idb.jumps.append(ea) or True
    kernwin.refresh_idaview_anyway = lambda: None

    class Choose:
        CH_MULTI = 1
        CH_MODAL = 2
        CHCOL_HEX = 0x40000
        NOTHING_CHANGED = 0

        def __init__(self, title, cols, flags=0, deflt=None, **_rest):
            self.title, self.cols, self.flags, self.deflt = title, cols, flags, deflt

        def Show(self, modal=False):
            idb.choosers.append(self)
            if modal:
                # The user confirms the default selection (every row).
                self.OnSelectLine(self.deflt)
            return 0

        def Close(self):
            self.OnClose()

        def OnClose(self):
            pass

    kernwin.Choose = Choose

    nalt = module("ida_nalt")
    nalt.get_input_file_path = lambda: str(idb.image)
    nalt.get_imagebase = lambda: 0

    class Func:
        def __init__(self, ea: int, size: int) -> None:
            self.start_ea, self.end_ea, self.flags = ea, ea + size, 0

        def size(self) -> int:
            return self.end_ea - self.start_ea

    def get_func(ea: int):
        for start, (_name, size) in idb.functions.items():
            if start <= ea < start + max(size, 1):
                return Func(start, size)
        return None

    funcs = module("ida_funcs")
    funcs.FUNC_THUNK = 0x80
    funcs.get_func = get_func
    funcs.get_func_name = lambda ea: idb.names.get(ea, f"sub_{ea:X}")
    # The fake IDB already holds every function IDA's analysis would find
    # (ground truth); code outside them is a chunk or tail of one of them, so
    # IDA refuses to start a new function there.
    funcs.add_func = lambda _ea: False
    funcs.get_func_cmt = lambda func, _repeatable: idb.comments.get(func.start_ea, "")
    funcs.set_func_cmt = lambda func, text, _repeatable: (
        idb.comments.__setitem__(func.start_ea, text) or True
    )

    name = module("ida_name")
    name.SN_NOWARN, name.SN_NOCHECK = 1, 2
    name.get_ea_name = lambda ea, *_flags: idb.names.get(ea, f"sub_{ea:X}")

    def get_name_ea(_from, text):
        return next((ea for ea, owned in idb.names.items() if owned == text), BADADDR)

    def set_name(ea, text, _flags):
        idb.names[ea] = text
        return True

    name.get_name_ea = get_name_ea
    name.set_name = set_name

    bytes_ = module("ida_bytes")
    bytes_.get_flags = lambda ea: ea
    bytes_.has_user_name = lambda ea: ea in idb.names
    bytes_.is_code = lambda ea: any(low <= ea < high for low, high in idb.code)

    segment = module("ida_segment")
    segment.SEG_XTRN = 1
    segment.getseg = lambda _ea: None

    idautils = module("idautils")
    idautils.Functions = lambda: sorted(idb.functions)


def ground_truth(corpus: Path, relative: str) -> dict[int, tuple[str, int]]:
    document = json.loads((corpus / "ground_truth.json").read_text(encoding="utf-8"))
    for binary in document["binaries"]:
        if binary["path"] == relative:
            return {f["start"]: (f["name"], f["size"]) for f in binary["functions"]}
    raise SystemExit(f"{relative} is not in {corpus / 'ground_truth.json'}")


def executable_ranges(path: Path) -> list[tuple[int, int]]:
    """``[low, high)`` of a little-endian ELF's executable ``PT_LOAD`` segments."""
    data = path.read_bytes()
    wide = data[4] == 2
    if wide:
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    else:
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    ranges = []
    for index in range(phnum):
        at = phoff + index * phentsize
        if wide:
            kind, flags, _offset, vaddr, _paddr, _filesz, memsz = struct.unpack_from(
                "<IIQQQQQ", data, at
            )
        else:
            kind, _offset, vaddr, _paddr, _filesz, memsz, flags = struct.unpack_from(
                "<IIIIIII", data, at
            )
        if kind == 1 and flags & 1:  # PT_LOAD, PF_X
            ranges.append((vaddr, vaddr + memsz))
    return ranges


def dynamic_functions(path: Path) -> dict[int, str]:
    """Defined function symbols of a little-endian ELF's ``.dynsym``.

    A stripped image keeps these, and IDA names its functions from them, so
    the fake IDB of the stripped build carries them as user names too.
    """
    data = path.read_bytes()
    wide = data[4] == 2
    shoff, shentsize, shnum = (
        (struct.unpack_from("<Q", data, 0x28)[0], *struct.unpack_from("<HH", data, 0x3A))
        if wide
        else (struct.unpack_from("<I", data, 0x20)[0], *struct.unpack_from("<HH", data, 0x2E))
    )
    sections = []
    for index in range(shnum):
        at = shoff + index * shentsize
        if wide:
            _name, kind, _flags, _addr, offset, size, link = struct.unpack_from(
                "<IIQQQQI", data, at
            )
        else:
            _name, kind, _flags, _addr, offset, size, link = struct.unpack_from(
                "<IIIIIII", data, at
            )
        sections.append((kind, offset, size, link))
    names: dict[int, str] = {}
    for kind, offset, size, link in sections:
        if kind != 11:  # SHT_DYNSYM
            continue
        strings = sections[link]
        step = 24 if wide else 16
        for at in range(offset + step, offset + size, step):
            if wide:
                name, info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", data, at)
            else:
                name, value, _size, info, _other, shndx = struct.unpack_from("<IIIBBH", data, at)
            if info & 0xF != 2 or shndx == 0:  # STT_FUNC, defined
                continue
            start = strings[1] + name
            text = data[start : data.index(b"\0", start)].decode()
            # Thumb symbols carry the mode in bit 0.
            names.setdefault(value & ~1, text)
    return names


def check(condition: bool, message: str) -> None:
    print(("ok   " if condition else "FAIL ") + message)
    if not condition:
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--corpus", type=Path, default=ROOT / "corpus" / "build-real")
    parser.add_argument("--native", type=Path, help="sigtool-native (default: native/target)")
    parser.add_argument("--arch", default="x64")
    parser.add_argument("--library", default="zlib")
    parser.add_argument("--sign", default="clang-O2", help="build signed (unstripped)")
    parser.add_argument("--apply", default="gcc-O2", help="build renamed (stripped copy)")
    parser.add_argument(
        "--merge-arch", default="arm64", help="arch of the second merge sample (same build)"
    )
    parser.add_argument("--function", default=None, help="function to generate and locate")
    # A floor that catches a broken plugin-to-CLI contract (a wrong base or
    # RVA parse renames almost nothing right), not the matcher's precision
    # target: that is measured by the real-corpus bench.
    parser.add_argument("--min-precision", type=float, default=0.8)
    args = parser.parse_args()

    native = args.native or ROOT / "native" / "target" / "release" / (
        "sigtool-native.exe" if os.name == "nt" else "sigtool-native"
    )
    os.environ["SIGTOOL_NATIVE"] = str(native)
    sign_rel = f"{args.arch}/{args.sign}/{args.library}.so"
    apply_rel = f"{args.arch}/{args.apply}/{args.library}.so"
    sign_truth = ground_truth(args.corpus, sign_rel)
    apply_truth = ground_truth(args.corpus, apply_rel)
    merge_rel = f"{args.merge_arch}/{args.sign}/{args.library}.so"
    merge_by_name = {name: ea for ea, (name, _size) in ground_truth(args.corpus, merge_rel).items()}
    sign_image = args.corpus / sign_rel
    apply_image = args.corpus / "stripped" / apply_rel

    idb = FakeIdb(sign_image, dict(sign_truth))
    install_fakes(idb)
    sys.path.insert(0, str(ROOT))
    import ida_plugin as plugin

    by_name = {name: ea for ea, (name, _size) in sign_truth.items()}
    apply_by_name = {name: ea for ea, (name, _size) in apply_truth.items()}
    # The largest function both builds have: plenty of evidence to sign.
    target = args.function or max(
        (name for name in by_name if name in apply_by_name and name in merge_by_name),
        key=lambda name: sign_truth[by_name[name]][1],
    )
    print(f"native {native}\nsign   {sign_image}\napply  {apply_image}\nfunction {target}")

    with tempfile.TemporaryDirectory() as temp_name:
        temp = Path(temp_name)
        yaml = temp / f"{target}.yaml"
        merged = temp / f"{target}.merged.yaml"
        idb.screen_ea = by_name[target] + 1
        idb.answer(
            str(yaml),  # save the signature
            1,  # merge another sample
            str(args.corpus / merge_rel),  # sample image
            f"+{merge_by_name[target]:#x}",  # sample RVA
            0,  # no further sample
            str(merged),  # save the merged signature
        )
        plugin.GenerateHandler().run()
        check(yaml.exists() and "spec_version:" in yaml.read_text(), f"generate wrote {yaml.name}")
        check(merged.exists(), "merge wrote the two-sample signature")
        check(not idb.answers and len(idb.infos) == 2, "generate showed two reports")

        idb.answer(str(yaml))
        plugin.LocateHandler().run()
        rows = idb.choosers[-1].rows if idb.choosers else []
        check(
            bool(rows) and rows[0].ea == by_name[target] and idb.jumps[-1] == by_name[target],
            f"locate lists {target} first and jumps to it ({len(rows)} rows)",
        )

        db = temp / "signatures.db"
        idb.answer(1, str(db))
        plugin.SignAllHandler().run()
        summary = idb.infos[-1]
        check(db.exists() and "signed " in summary, summary.splitlines()[0])

        # The other build, stripped: only its exported functions are named.
        exports = dynamic_functions(apply_image)
        apply_idb_functions = {
            ea: (exports.get(ea), size) for ea, (_name, size) in apply_truth.items()
        }
        idb.__init__(apply_image, apply_idb_functions)
        idb.answer(str(db), 0)
        plugin.ApplyNamesHandler().run()
        renamed = {ea: name for ea, name in idb.names.items() if ea not in exports}
        right = sum(1 for ea, name in renamed.items() if apply_truth.get(ea, ("",))[0] == name)
        precision = right / len(renamed) if renamed else 0.0
        print(
            f"     renamed {len(renamed)} of {len(apply_truth)} functions, {right} right "
            f"(precision {precision:.3f})"
        )
        for ea, name in sorted(renamed.items()):
            if apply_truth.get(ea, ("",))[0] != name:
                truth = apply_truth.get(ea, (None,))[0]
                print(f"     wrong: {ea:#x} named {name}, ground truth {truth}")
        check(len(renamed) > 0, "apply renamed functions")
        check(precision >= args.min_precision, f"rename precision >= {args.min_precision}")
        check(
            all("sigtool:" in idb.comments.get(ea, "") for ea in renamed),
            "every rename carries a provenance comment",
        )
        check(
            idb.choosers[-1].title.startswith("sigtool: renamed"),
            "renames are listed in a results chooser",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
