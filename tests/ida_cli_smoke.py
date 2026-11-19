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
import hashlib
import json
import os
import shutil
import struct
import subprocess
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
        # Where IDA recorded the input file and where the IDB lives; a moved
        # IDB records a path that no longer exists.
        self.recorded = str(image)
        self.idb_path = str(image) + ".i64"
        self.sha256 = hashlib.sha256(image.read_bytes()).digest()
        self.size = image.stat().st_size
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
        self.registry: dict = {}
        self.clipboard = ""
        self.wait_texts: list[str] = []

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
    kernwin.BWN_DISASM, kernwin.BWN_FUNCS, kernwin.BWN_PSEUDOCODE = 27, 3, 46
    kernwin.action_handler_t = type("action_handler_t", (), {})
    kernwin.UI_Hooks = type("UI_Hooks", (), {})
    kernwin.msg = lambda text: sys.stdout.write(f"  [ida] {text}")
    kernwin.info = lambda text: idb.infos.append(text)
    kernwin.warning = lambda text: idb.warnings.append(text)
    kernwin.ask_file = lambda _save, _mask, prompt: idb.next_answer(prompt)
    kernwin.ask_yn = lambda _default, prompt: idb.next_answer(prompt)
    kernwin.ask_str = lambda _default, _hist, prompt: idb.next_answer(prompt)
    kernwin.show_wait_box = lambda _text: None
    kernwin.replace_wait_box = lambda text: idb.wait_texts.append(text)
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
    kernwin.Form = type("Form", (), {})

    registry = module("ida_registry")
    registry.reg_read_int = lambda name, default, _key=None: idb.registry.get(name, default)
    registry.reg_write_int = lambda name, value, _key=None: idb.registry.__setitem__(name, value)
    registry.reg_read_string = lambda name, _key=None, default=None: idb.registry.get(name, default)
    registry.reg_write_string = lambda name, value, _key=None: idb.registry.__setitem__(name, value)

    nalt = module("ida_nalt")
    nalt.get_input_file_path = lambda: idb.recorded
    nalt.get_root_filename = lambda: Path(idb.image).name
    nalt.retrieve_input_file_sha256 = lambda: idb.sha256
    nalt.retrieve_input_file_size = lambda: idb.size
    nalt.set_root_filename = lambda path: setattr(idb, "recorded", path)
    nalt.get_imagebase = lambda: 0

    loader = module("ida_loader")
    loader.PATH_TYPE_IDB = 1
    loader.get_path = lambda _kind: idb.idb_path

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
    funcs.getn_func = lambda n: get_func(sorted(idb.functions)[n])
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

    # Segments as IDA's ELF loader makes them: one per allocated section, at
    # its file offset (none for `.bss`), with the file's bytes. The image's
    # path stands in for the IDB's contents, so it is read even when the
    # "input file" has moved away.
    sections = elf_sections(idb.image)

    class Seg:
        def __init__(self, row) -> None:
            self.name, self.start_ea, self.end_ea, self.offset, self.perm = row
            self.type = 0

    def segment_at(ea: int):
        return next((Seg(row) for row in sections if row[1] <= ea < row[2]), None)

    def file_offset(ea: int) -> int:
        seg = segment_at(ea)
        return -1 if seg is None or seg.offset is None else seg.offset + ea - seg.start_ea

    content = idb.image.read_bytes()
    segment = module("ida_segment")
    segment.SEG_XTRN = 1
    segment.SEGPERM_EXEC, segment.SEGPERM_WRITE = 1, 2
    segment.getseg = segment_at
    segment.get_segm_name = lambda seg: seg.name
    loader.get_fileregion_offset = file_offset

    def get_bytes(ea: int, size: int):
        offset = file_offset(ea)
        return None if offset < 0 else content[offset : offset + size]

    bytes_.get_bytes = get_bytes
    bytes_.visit_patched_bytes = lambda _start, _end, _callback: 0

    idautils = module("idautils")
    idautils.Functions = lambda: sorted(idb.functions)
    idautils.Segments = lambda: [row[1] for row in sections]

    def no_pe_header():
        raise RuntimeError("not a PE database")

    idautils.peutils_t = lambda: types.SimpleNamespace(header=no_pe_header)


def ground_truth(corpus: Path, relative: str) -> dict[int, tuple[str, int]]:
    document = json.loads((corpus / "ground_truth.json").read_text(encoding="utf-8"))
    for binary in document["binaries"]:
        if binary["path"] == relative:
            return {f["start"]: (f["name"], f["size"]) for f in binary["functions"]}
    raise SystemExit(f"{relative} is not in {corpus / 'ground_truth.json'}")


def elf_sections(path: Path) -> list[tuple[str, int, int, int | None, int]]:
    """``(name, start, end, file offset or None, perm)`` per allocated section
    of a little-endian 64- or 32-bit ELF image, by address."""
    data = path.read_bytes()
    wide = data[4] == 2
    if wide:
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        entsize, count, names_index = struct.unpack_from("<HHH", data, 0x3A)
        layout = "<IIQQQQ"
    else:
        shoff = struct.unpack_from("<I", data, 0x20)[0]
        entsize, count, names_index = struct.unpack_from("<HHH", data, 0x2E)
        layout = "<IIIIII"
    rows = [struct.unpack_from(layout, data, shoff + index * entsize) for index in range(count)]
    names_row = rows[names_index]
    names = data[names_row[4] : names_row[4] + names_row[5]]
    out = []
    for name_off, kind, flags, addr, offset, size in rows:
        if not flags & 0x2 or not size or not addr:
            continue
        name = names[name_off : names.index(b"\0", name_off)].decode()
        perm = (1 if flags & 0x4 else 0) | (2 if flags & 0x1 else 0) | 4
        out.append((name, addr, addr + size, None if kind == 8 else offset, perm))
    # IDA covers the rest of each PT_LOAD's file bytes (the ELF header and
    # program headers among them) with segments named `LOAD`.
    if wide:
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    else:
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    for index in range(phnum):
        at = phoff + index * phentsize
        if wide:
            kind, flags, offset, vaddr, _paddr, filesz = struct.unpack_from("<IIQQQQ", data, at)
        else:
            kind, offset, vaddr, _paddr, filesz, _memsz, flags = struct.unpack_from(
                "<IIIIIII", data, at
            )
        if kind != 1 or not filesz:
            continue
        perm = (1 if flags & 0x1 else 0) | (2 if flags & 0x2 else 0) | 4
        cursor, end = vaddr, vaddr + filesz
        for _name, start, stop, _offset, _perm in sorted(out, key=lambda row: row[1]):
            if stop <= cursor or start >= end:
                continue
            if start > cursor:
                out.append(("LOAD", cursor, start, offset + cursor - vaddr, perm))
            cursor = max(cursor, stop)
        if cursor < end:
            out.append(("LOAD", cursor, end, offset + cursor - vaddr, perm))
    return sorted(out, key=lambda row: row[1])


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

    plugin._clipboard_text = lambda: idb.clipboard
    # Every CLI document the plugin reads budgets from, to check it does.
    budget_reads: list[dict] = []
    describe_truncation = plugin.describe_truncation
    plugin.describe_truncation = lambda doc: budget_reads.append(doc) or describe_truncation(doc)
    plugin._set_clipboard = lambda text: setattr(idb, "clipboard", text) or True

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
        # Outputs land in `sigtool/` beside the IDB; keep that out of the corpus.
        idb.idb_path = str(temp / f"{sign_image.name}.i64")
        outputs = temp / "sigtool"
        yaml = outputs / f"{target}.yaml"
        merged = outputs / f"{target}.merged.yaml"
        idb.screen_ea = by_name[target] + 1
        plugin.GenerateHandler().run()
        check(
            yaml.exists() and "spec_version:" in yaml.read_text(),
            f"generate saved sigtool/{yaml.name} without a dialog",
        )
        check(
            not idb.infos and idb.clipboard == yaml.read_text(encoding="utf-8"),
            "generate copied the signature to the clipboard and showed no dialog",
        )

        idb.answer(
            str(args.corpus / merge_rel),  # other build
            f"+{merge_by_name[target]:#x}",  # its RVA
            0,  # no further build
        )
        plugin.MergeHandler().run()
        check(
            merged.exists() and merged.read_text().count("- arch:") == 2,
            "merge saved the two-sample signature",
        )

        # The clipboard holds the merged signature now; locate takes it.
        plugin.LocateHandler().run()
        rows = idb.choosers[-1].rows if idb.choosers else []
        check(
            not idb.answers
            and bool(rows)
            and rows[0].ea == by_name[target]
            and idb.jumps[-1] == by_name[target],
            f"locate takes the clipboard, lists {target} first, and jumps ({len(rows)} rows)",
        )
        idb.clipboard = "not a signature"
        idb.answer(str(yaml))
        plugin.LocateHandler().run()
        check(not idb.answers, "without one on the clipboard, locate asks for a file")
        check(
            len(budget_reads) == 2 and all("truncated" in doc for doc in budget_reads),
            "locate reads the exhausted budgets from both JSON documents",
        )

        db = outputs / f"{sign_image.name}.db"
        plugin.SignAllHandler().run()
        summary = idb.infos[-1]
        check(db.exists() and "signed " in summary, summary.splitlines()[0])
        check(
            any(text.endswith(" s") for text in idb.wait_texts)
            and all(text.endswith(" s") for text in idb.wait_texts),
            f"the wait box shows progress and the elapsed time ({idb.wait_texts[-1:]})",
        )

        # The Functions view's selection, not the cursor: three named rows
        # (indices into the sorted function list) sign into one DB.
        starts = sorted(idb.functions)
        picked = [i for i, ea in enumerate(starts) if idb.names.get(ea)][:3]
        selection = types.SimpleNamespace(
            widget_type=sys.modules["ida_kernwin"].BWN_FUNCS, chooser_selection=picked
        )
        selected_db = temp / "selected.db"
        plugin.GenerateHandler(str(selected_db)).run(selection)
        check(
            selected_db.exists() and idb.infos[-1].startswith("signed 3 of 3"),
            "generate on a Functions-view selection signs those rows into the menu's DB",
        )

        # A moved IDB: the recorded path is gone, the binary sits beside the
        # IDB. It is found by hash without a dialog and recorded in the IDB.
        moved = temp / "moved"
        moved.mkdir()
        copy = moved / sign_image.name
        shutil.copyfile(sign_image, copy)
        idb.recorded = str(temp / "gone" / sign_image.name)
        idb.idb_path = str(moved / f"{sign_image.name}.i64")
        relocated = moved / "sigtool" / f"{target}.yaml"
        plugin.GenerateHandler().run()
        check(
            relocated.exists() and not idb.answers and idb.recorded == str(copy),
            "a moved IDB finds its input file beside it without asking",
        )
        # A same-named file with other bytes is not taken for it.
        changed = bytearray(copy.read_bytes())
        changed[-1] ^= 0xFF
        copy.write_bytes(bytes(changed))
        idb.recorded = str(temp / "gone" / sign_image.name)
        plugin._verified_inputs.clear()
        relocated.unlink()
        # With no matching file anywhere, the image is rebuilt from the IDB,
        # without a dialog, and signs like the stripped copy of the binary.
        plugin.GenerateHandler().run()
        reference = temp / "stripped.yaml"
        stripped_copy = args.corpus / "stripped" / sign_rel
        subprocess.run(
            [
                str(native),
                "gen",
                "--file",
                str(stripped_copy),
                "--rva",
                hex(by_name[target]),
                "--tool",
                "IDA",
                "--output",
                str(reference),
            ],
            check=True,
            capture_output=True,
        )
        check(
            not idb.answers
            and idb.recorded != str(copy)
            and relocated.exists()
            and relocated.read_bytes() == reference.read_bytes(),
            "without the binary, the IDB alone signs like the stripped file (no dialog)",
        )

        # The other build, stripped: only its exported functions are named.
        exports = dynamic_functions(apply_image)
        apply_idb_functions = {
            ea: (exports.get(ea), size) for ea, (_name, size) in apply_truth.items()
        }
        idb.__init__(apply_image, apply_idb_functions)
        idb.idb_path = str(temp / f"{apply_image.name}.i64")
        # The menu hands apply-names the DB sign-all wrote: no dialog.
        progress_seen: list[tuple[int, int]] = []

        class RecordingStatus(plugin.WaitStatus):
            def feed(self, line: str) -> None:
                super().feed(line)
                if self.progress is not None:
                    progress_seen.append(self.progress)

        plugin.WaitStatus = RecordingStatus
        plugin.ApplyNamesHandler(str(db)).run()
        check(not idb.answers, "apply-names takes the menu's DB without a dialog")
        check("truncated" in budget_reads[-1], "apply-names reads the scan's exhausted budgets")
        if plugin._supports("scan", "--progress"):
            check(bool(progress_seen), f"apply-names saw scan progress ({progress_seen[-1:]})")
        else:
            print("skip this CLI has no scan --progress (older than the plugin)")
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
