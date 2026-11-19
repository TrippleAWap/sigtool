"""Tests for the IDA-free parts of ida_plugin.py: name filtering, CLI output
parsing, and choosing renames. IDA's modules are stubbed, so this runs with a
plain Python: ``python -m unittest tests/test_ida_plugin.py``."""

from __future__ import annotations

import ast
import importlib
import re
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


def _load_plugin():
    for name in (
        "ida_bytes",
        "ida_funcs",
        "ida_idaapi",
        "ida_kernwin",
        "ida_loader",
        "ida_nalt",
        "ida_name",
        "ida_registry",
        "ida_segment",
        "idautils",
    ):
        sys.modules.setdefault(name, types.ModuleType(name))
    kernwin = sys.modules["ida_kernwin"]
    for base in ("action_handler_t", "Choose", "Form", "UI_Hooks"):
        if not hasattr(kernwin, base):
            setattr(kernwin, base, type(base, (), {}))
    idaapi = sys.modules["ida_idaapi"]
    if not hasattr(idaapi, "plugin_t"):
        idaapi.plugin_t = type("plugin_t", (), {})
        idaapi.PLUGIN_KEEP = 2
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    try:
        return importlib.import_module("ida_plugin")
    finally:
        sys.path.pop(0)


plugin = _load_plugin()


def hit(name, rva, evidence="identified", score=0.9, signature_id=None):
    return {
        "signature_id": signature_id or f"id-{name}",
        "name": name,
        "rva": f"{rva:#x}",
        "evidence": evidence,
        "score": score,
    }


def choose(hits, names=None, user=(), overwrite=False):
    names = names or {}
    owners = {name: rva for rva, name in names.items()}
    return plugin.choose_renames(
        hits,
        current_name=lambda rva: names.get(rva, f"sub_{rva:X}"),
        user_named=lambda rva: rva in user,
        name_owner=owners.get,
        overwrite_user=overwrite,
    )


class NameTests(unittest.TestCase):
    def test_auto_names_are_not_meaningful(self):
        for name in ("", None, "sub_401000", "nullsub_3", "j_sub_401000", "unknown_libname_12"):
            self.assertFalse(plugin.is_meaningful_name(name), name)
        for name in ("_sub_401000", "?sub_1F00_1"):
            self.assertFalse(plugin.is_meaningful_name(name), name)

    def test_resolved_names_are_meaningful(self):
        for name in ("inflate", "_ZN3foo3barEv", "lua_pushnumber", "submit", "sub_total"):
            self.assertTrue(plugin.is_meaningful_name(name), name)

    def test_only_resolved_names_are_passed_to_the_cli(self):
        self.assertEqual(plugin.name_arguments("decrypt_config"), ["--name", "decrypt_config"])
        for name in (None, "", "sub_1234", "j_sub_10", "unknown_libname_3"):
            self.assertEqual(plugin.name_arguments(name), [], name)

    def test_progress_lines(self):
        self.assertEqual(plugin.parse_progress("progress 3/40\n"), (3, 40))
        self.assertIsNone(plugin.parse_progress("skipped 0x10 f: no"))

    def test_build_summary_lists_skipped(self):
        text = plugin.summarize_build(
            {
                "signed": 1,
                "functions": [
                    {"rva": "0x10", "name": "a", "status": "signed"},
                    {"rva": "0x20", "name": "b", "status": "refused", "error": "self-test"},
                ],
            }
        )
        self.assertIn("signed 1 of 2", text)
        self.assertIn("0x20 b: refused (self-test)", text)


class ChooseRenamesTests(unittest.TestCase):
    def test_first_identified_hit_per_signature_is_proposed(self):
        proposals, skipped = choose(
            [hit("inflate", 0x200, score=0.8), hit("inflate", 0x300, "candidate")]
        )
        self.assertEqual([(p.rva, p.name) for p in proposals], [(0x200, "inflate")])
        self.assertEqual(proposals[0].current, "sub_200")
        self.assertEqual(skipped, [])

    def test_untrusted_evidence_is_skipped(self):
        proposals, skipped = choose([hit("a", 0x10, "candidate"), hit("b", 0x20, "shape-only")])
        self.assertEqual(proposals, [])
        self.assertEqual([name for name, _ in skipped], ["a", "b"])

    def test_user_names_kept_unless_opted_in(self):
        hits = [hit("inflate", 0x200)]
        proposals, skipped = choose(hits, names={0x200: "my_inflate"}, user={0x200})
        self.assertEqual(proposals, [])
        self.assertIn("user name", skipped[0][1])
        proposals, _ = choose(hits, names={0x200: "my_inflate"}, user={0x200}, overwrite=True)
        self.assertEqual([p.name for p in proposals], ["inflate"])
        self.assertTrue(proposals[0].replaces_user_name)

    def test_user_name_replacements_are_listed_but_not_preselected(self):
        proposals, _ = choose(
            [hit("inflate", 0x200), hit("deflate", 0x300)],
            names={0x200: "my_inflate"},
            user={0x200},
            overwrite=True,
        )
        self.assertEqual([p.name for p in proposals], ["inflate", "deflate"])
        self.assertEqual(plugin.default_selection(proposals), [1])

    def test_already_named_and_name_in_use_are_skipped(self):
        proposals, skipped = choose(
            [hit("inflate", 0x200), hit("deflate", 0x300)],
            names={0x200: "inflate", 0x500: "deflate"},
        )
        self.assertEqual(proposals, [])
        self.assertEqual(
            skipped, [("deflate", "name already used at +0x500"), ("inflate", "already named")]
        )

    def test_conflicting_claims_are_skipped(self):
        proposals, skipped = choose(
            [
                hit("a", 0x10),
                hit("b", 0x10),
                hit("c", 0x20, signature_id="c1"),
                hit("c", 0x30, signature_id="c2"),
                hit("d", 0x40, signature_id="d1", score=0.5),
                hit("d", 0x40, signature_id="d2", score=0.7),
            ]
        )
        self.assertEqual([(p.rva, p.name, p.score) for p in proposals], [(0x40, "d", 0.7)])
        self.assertEqual(sorted(name for name, _ in skipped), ["a", "b", "c", "c"])

    def test_chooser_selection_is_normalized(self):
        self.assertEqual(plugin._chosen(None), [])
        self.assertEqual(plugin._chosen(-1), [])
        self.assertEqual(plugin._chosen(2), [2])
        self.assertEqual(plugin._chosen([0, 3]), [0, 3])


class RenameBlockerTests(unittest.TestCase):
    def blocker(self, start, is_code=True, created=None):
        calls = []

        def add():
            calls.append(True)
            return created

        return plugin.rename_blocker(0x200, start, is_code, add), calls

    def test_existing_function_start_is_renamed_without_creating(self):
        self.assertEqual(self.blocker(0x200), (None, []))

    def test_mid_function_is_skipped(self):
        reason, calls = self.blocker(0x180)
        self.assertEqual(reason, "+0x200 is inside the function at +0x180")
        self.assertEqual(calls, [])

    def test_data_is_skipped_without_creating(self):
        reason, calls = self.blocker(None, is_code=False, created=0x200)
        self.assertIn("no function at +0x200", reason)
        self.assertEqual(calls, [])

    def test_code_needs_a_function_created_at_the_address(self):
        self.assertEqual(self.blocker(None, created=0x200), (None, [True]))
        for created in (None, 0x1F0):
            reason, _ = self.blocker(None, created=created)
            self.assertIn("could not create", reason)


class CursorTests(unittest.TestCase):
    """Which address a single-function generate or merge signs."""

    def start(self, ea, function=None, code=False, answer=1, created=None):
        asked, added = [], []

        def add_func(at):
            added.append(at)
            return created is not None

        def get_func(at):
            if function is not None:
                return types.SimpleNamespace(start_ea=function)
            if added and created is not None:
                return types.SimpleNamespace(start_ea=created)
            return None

        with (
            mock.patch.object(plugin.ida_funcs, "get_func", get_func, create=True),
            mock.patch.object(plugin.ida_funcs, "add_func", add_func, create=True),
            mock.patch.object(plugin.ida_bytes, "get_flags", lambda at: at, create=True),
            mock.patch.object(plugin.ida_bytes, "is_code", lambda _flags: code, create=True),
            mock.patch.object(
                plugin.ida_kernwin,
                "ask_yn",
                lambda _default, text: asked.append(text) or answer,
                create=True,
            ),
            mock.patch.object(plugin.ida_kernwin, "msg", lambda _text: None, create=True),
        ):
            return plugin._signable_start(ea), asked, added

    def test_a_cursor_in_a_function_signs_its_start(self):
        self.assertEqual(self.start(0x1234, function=0x1200), (0x1200, [], []))

    def test_a_cursor_on_data_is_refused(self):
        with self.assertRaises(plugin.SigtoolError) as caught:
            self.start(0x5000)
        self.assertIn("0x5000 is not code", str(caught.exception))

    def test_code_outside_a_function_asks_before_creating_one(self):
        start, asked, added = self.start(0x3000, code=True, created=0x3000)
        self.assertEqual((start, added), (0x3000, [0x3000]))
        self.assertIn("outside any function", asked[0])
        with self.assertRaises(plugin.SigtoolCancelled):
            self.start(0x3000, code=True, answer=0)
        # IDA refusing to make a function still signs the code, as confirmed.
        self.assertEqual(self.start(0x3000, code=True)[0], 0x3000)


class QtBindingTests(unittest.TestCase):
    def test_order_follows_the_ida_version_and_what_is_loaded(self):
        pyside, pyqt = "PySide6.QtWidgets", "PyQt5.QtWidgets"
        self.assertEqual(plugin.qt_binding_order("9.2"), [pyside, pyqt])
        self.assertEqual(plugin.qt_binding_order("10.0"), [pyside, pyqt])
        self.assertEqual(plugin.qt_binding_order("9.1"), [pyqt, pyside])
        self.assertEqual(plugin.qt_binding_order("8.4"), [pyqt, pyside])
        self.assertEqual(plugin.qt_binding_order(""), [pyside, pyqt])
        self.assertEqual(plugin.qt_binding_order("9.2", {pyqt}), [pyqt, pyside])

    def test_a_binding_without_an_application_is_passed_over(self):
        def widgets(app):
            module = types.ModuleType("QtWidgets")
            module.QApplication = types.SimpleNamespace(instance=lambda: app)
            return module

        app = types.SimpleNamespace(clipboard=lambda: "pyqt5 clipboard")
        stubs = {"PySide6.QtWidgets": widgets(None), "PyQt5.QtWidgets": widgets(app)}
        with (
            mock.patch.dict(sys.modules, stubs),
            mock.patch.object(plugin.ida_kernwin, "get_kernel_version", lambda: "9.2", create=True),
        ):
            self.assertEqual(plugin._qt_clipboard(), "pyqt5 clipboard")


class ProvenanceTests(unittest.TestCase):
    def proposal(self):
        return plugin.Proposal(0x200, "inflate", 0.91234, "identified", "sub_200", "abc123")

    def test_comment_is_appended_once(self):
        first = plugin.provenance_comment("", self.proposal(), "zlib.db")
        self.assertEqual(
            first, "sigtool: inflate from zlib.db (signature abc123, score 0.912, identified)"
        )
        self.assertEqual(plugin.provenance_comment(first, self.proposal(), "zlib.db"), first)
        kept = plugin.provenance_comment("analyst note\n", self.proposal(), "zlib.db")
        self.assertEqual(kept, f"analyst note\n{first}")

    def test_proposals_carry_the_signature_id(self):
        proposals, _ = choose([hit("inflate", 0x200, signature_id="sig-1")])
        self.assertEqual(proposals[0].signature_id, "sig-1")


class MatchRowTests(unittest.TestCase):
    def test_rows_map_rvas_through_the_idb_base(self):
        rows = plugin.match_rows(
            [
                {
                    "address": "0x1200",
                    "rva": "0x200",
                    "score": 0.91234,
                    "evidence": "identified",
                    "label": "inflate",
                    "matched": ["str:a", "const:b"],
                },
                {"address": "0x9000", "score": 0.5, "evidence": "candidate", "label": None},
            ],
            base=0x140000000,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ea, 0x140000200)
        self.assertEqual(rows[0].cells, ("0x140000200", "0.912", "identified", "inflate", "2"))


class InputFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def test_candidates_continue_beside_the_idb(self):
        idb = str(self.dir / "libz.so.i64")
        self.assertEqual(
            plugin.input_file_candidates(r"C:\work\build\libz.so", idb, "libz.so"),
            [r"C:\work\build\libz.so", str(self.dir / "libz.so")],
        )
        self.assertEqual(
            plugin.input_file_candidates("/old/a.out", str(self.dir / "renamed.i64"), "a.out"),
            ["/old/a.out", str(self.dir / "a.out"), str(self.dir / "renamed")],
        )
        self.assertEqual(plugin.input_file_candidates("", "", ""), [])

    def test_only_the_file_with_the_stored_hash_matches(self):
        import hashlib

        good = self.dir / "good.bin"
        good.write_bytes(b"ELF" + bytes(60))
        bad = self.dir / "bad.bin"
        bad.write_bytes(b"ELF" + bytes(59) + b"")
        digest = hashlib.sha256(good.read_bytes()).digest()
        self.assertTrue(plugin.file_matches(str(good), digest, 64))
        self.assertFalse(plugin.file_matches(str(bad), digest, 64))
        self.assertFalse(plugin.file_matches(str(good), None, 65))
        self.assertTrue(plugin.file_matches(str(bad), None, None))
        self.assertFalse(plugin.file_matches(str(self.dir / "missing"), None, None))

    def test_zero_digest_means_none_stored(self):
        self.assertIsNone(plugin.known_digest(b""))
        self.assertIsNone(plugin.known_digest(bytes(32)))
        self.assertEqual(plugin.known_digest(b"" * 32), b"" * 32)


class RebuildTests(unittest.TestCase):
    def segments(self):
        return [
            plugin.Segment(".text", 0x1000, 0x1100, 0x1000, True, False),
            plugin.Segment(".data", 0x2000, 0x2040, 0x1100, False, True),
            plugin.Segment(".bss", 0x2040, 0x2080, None, False, True),
        ]

    def test_elf_gets_a_section_table_of_the_segments(self):
        image = bytearray(0x1140)
        image[:6] = b"ELF"
        out = plugin.rebuild_elf(bytes(image), self.segments())
        self.assertEqual(out[: len(image)][0x40:], bytes(image)[0x40:])
        shoff = struct.unpack_from("<Q", out, 0x28)[0]
        entsize, count, names_index = struct.unpack_from("<HHH", out, 0x3A)
        self.assertEqual((entsize, count, names_index), (64, 5, 4))
        rows = [struct.unpack_from("<IIQQQQIIQQ", out, shoff + 64 * i) for i in range(count)]
        names = rows[names_index]
        strings = out[names[4] : names[4] + names[5]]

        def name(row):
            return strings[row[0] : strings.index(b"\0", row[0])].decode()

        self.assertEqual([name(row) for row in rows[1:]], [".text", ".data", ".bss", ".shstrtab"])
        text, data, bss = rows[1:4]
        self.assertEqual(
            (text[1], text[2], text[3], text[4], text[5]), (1, 0x6, 0x1000, 0x1000, 0x100)
        )
        self.assertEqual((data[2], data[4]), (0x3, 0x1100))
        self.assertEqual(bss[1], 8)

    def elf_with_loads(self):
        # Two PT_LOADs as lld lays out a shared object: text from offset 0 at
        # address 0, data one page up in memory.
        image = bytearray(0x1140)
        image[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<QHH", image, 0x20, 0x40, 56, 0)
        struct.pack_into("<HH", image, 0x36, 56, 2)
        struct.pack_into("<IIQQQQQQ", image, 0x40, 1, 5, 0, 0, 0, 0x1100, 0x1100, 0x1000)
        struct.pack_into("<IIQQQQQQ", image, 0x78, 1, 6, 0x1100, 0x2000, 0x2000, 0x40, 0x80, 0x1000)
        return bytes(image)

    def section_addresses(self, out):
        shoff = struct.unpack_from("<Q", out, 0x28)[0]
        count = struct.unpack_from("<H", out, 0x3C)[0]
        return [struct.unpack_from("<IIQQ", out, shoff + 64 * i)[3] for i in range(1, count - 1)]

    def test_rebased_elf_is_rebuilt_at_the_file_addresses(self):
        image = self.elf_with_loads()
        delta = 0x10000000
        shifted = [
            plugin.Segment(
                s.name, s.start + delta, s.end + delta, s.file_offset, s.executable, s.writable
            )
            for s in self.segments()
        ]
        plain = plugin.rebuild_elf(image, self.segments())
        self.assertEqual(self.section_addresses(plain), [0x1000, 0x2000, 0x2040])
        self.assertEqual(plugin.rebuild_elf(image, shifted), plain)

    def test_elf_segments_that_disagree_on_the_rebase_are_refused(self):
        segments = self.segments()
        segments[1] = plugin.Segment(".data", 0x3000, 0x3040, 0x1100, False, True)
        self.assertIsNone(plugin.rebuild_elf(self.elf_with_loads(), segments))

    def test_elf_rejects_other_formats_and_segments_past_the_file(self):
        self.assertIsNone(plugin.rebuild_elf(b"MZ" + bytes(0x100), self.segments()))
        elf = b"ELF" + bytes(0x100)
        self.assertIsNone(plugin.rebuild_elf(elf, self.segments()))

    def test_pe_headers_are_appended_and_sections_keep_their_offsets(self):
        header = bytearray(248)
        header[:4] = b"PE\0\0"
        struct.pack_into("<HH", header, 4, 0x8664, 3)
        struct.pack_into("<I", header, 40, 0x1010)
        struct.pack_into("<II", header, 120 + 8, 0x1080, 0x28)  # import directory
        base = 0x180000000
        segments = [
            plugin.Segment(".text", base + 0x1000, base + 0x1100, 0x1000, True, False),
            plugin.Segment(".data", base + 0x2000, base + 0x2040, 0x1100, False, True),
        ]
        image = bytes(0x1140)
        out = plugin.rebuild_pe(image, segments, bytes(header), base)
        self.assertEqual(out[:2], b"MZ")
        lfanew = struct.unpack_from("<I", out, 0x3C)[0]
        self.assertGreaterEqual(lfanew, len(image))
        self.assertEqual(out[lfanew : lfanew + 4], b"PE\0\0")
        machine, count = struct.unpack_from("<HH", out, lfanew + 4)
        optional_size = struct.unpack_from("<H", out, lfanew + 20)[0]
        self.assertEqual((machine, count, optional_size), (0x8664, 2, 240))
        optional = lfanew + 24
        self.assertEqual(struct.unpack_from("<H", out, optional)[0], 0x20B)
        self.assertEqual(struct.unpack_from("<Q", out, optional + 24)[0], base)
        self.assertEqual(struct.unpack_from("<II", out, optional + 112 + 8), (0x1080, 0x28))
        table = optional + optional_size
        name, vsize, rva, raw_size, raw_ptr = struct.unpack_from("<8sIIII", out, table)
        self.assertEqual(
            (name.rstrip(b"\0"), vsize, rva, raw_size, raw_ptr),
            (b".text", 0x100, 0x1000, 0x100, 0x1000),
        )
        self.assertIsNone(plugin.rebuild_pe(image, segments, b"", base))

    def test_pe_raw_size_stops_at_the_next_section(self):
        # `.data`'s virtual size runs past its raw data, into `.rdata`'s bytes.
        header = bytearray(248)
        header[:4] = b"PE\0\0"
        struct.pack_into("<HH", header, 4, 0x8664, 3)
        base = 0x180000000
        segments = [
            plugin.Segment(".text", base + 0x1000, base + 0x1100, 0x400, True, False),
            plugin.Segment(".data", base + 0x2000, base + 0x2800, 0x600, False, True),
            plugin.Segment(".rdata", base + 0x3000, base + 0x3100, 0x800, False, False),
            plugin.Segment(".bss", base + 0x4000, base + 0x4100, None, False, True),
        ]
        image = bytes(0x880)
        self.assertEqual(plugin.file_extents(segments, len(image)), [0x100, 0x200, 0x80, 0])
        out = plugin.rebuild_pe(image, segments, bytes(header), base)
        lfanew = struct.unpack_from("<I", out, 0x3C)[0]
        table = lfanew + 24 + 240
        rows = [struct.unpack_from("<8sIIII", out, table + 40 * i) for i in range(4)]
        self.assertEqual(
            [(vsize, raw_size, raw_ptr) for _name, vsize, _rva, raw_size, raw_ptr in rows],
            [(0x100, 0x100, 0x400), (0x800, 0x200, 0x600), (0x100, 0x80, 0x800), (0x100, 0, 0)],
        )


class MenuHelperTests(unittest.TestCase):
    def test_clipboard_signature_detection(self):
        document = "spec_version: '5'\nname: inflate\nfeatures:\n- kind: str\n"
        self.assertTrue(plugin.is_signature_text(document))
        for text in ("", None, "48 8B ?? ?? 89", "name: inflate\nfeatures:\n"):
            self.assertFalse(plugin.is_signature_text(text), text)

    def test_outputs_go_to_a_sigtool_folder_beside_the_idb(self):
        idb = str(Path("work") / "libz.so.i64")
        self.assertEqual(
            plugin.output_path(idb, "deflate<int>::run", ".yaml"),
            str(Path("work") / "sigtool" / "deflate_int_run.yaml"),
        )

    def test_long_names_are_cut_and_keep_a_hash(self):
        idb = str(Path("work") / "libz.so.i64")
        first = plugin.output_path(idb, "_ZN" + "a" * 300 + "Ev", ".merged.yaml")
        second = plugin.output_path(idb, "_ZN" + "a" * 300 + "Ei", ".merged.yaml")
        stem = Path(first).name[: -len(".merged.yaml")]
        self.assertLessEqual(len(stem), plugin.MAX_FILE_STEM + 9)
        self.assertTrue(stem.startswith("ZNaaaa"))
        self.assertRegex(stem, r"_[0-9a-f]{8}$")
        self.assertNotEqual(first, second)
        short = "inflate" + "x" * (plugin.MAX_FILE_STEM - 7)
        self.assertEqual(plugin.safe_file_name(short), short)

    def test_a_failed_save_keeps_the_report_and_says_so(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        # A file where the sigtool folder would go makes the save fail.
        (Path(temp.name) / "sigtool").write_text("")
        log, asked = [], []
        settings = plugin.SET_SAVE_BESIDE_IDB | plugin.SET_SHOW_REPORT
        kernwin = plugin.ida_kernwin
        with (
            mock.patch.object(plugin, "_settings", lambda: settings),
            mock.patch.object(plugin, "_idb_path", lambda: str(Path(temp.name) / "a.i64")),
            mock.patch.object(plugin, "_ask_path", lambda *args: asked.append(args)),
            mock.patch.object(kernwin, "msg", log.append, create=True),
            mock.patch.object(kernwin, "info", log.append, create=True),
        ):
            plugin._deliver_signature("spec_version: '7'\n", "REPORT", "inflate", ".yaml")
        self.assertIn("REPORT", log[0])
        self.assertEqual(len(asked), 1)
        self.assertIn("not saved to", log[-2])
        self.assertIn("REPORT", log[-1])
        self.assertIn("not saved to", log[-1])

    def test_settings_are_distinct_bits_in_form_order(self):
        flags = [flag for flag, _label in plugin.SETTINGS]
        self.assertEqual(flags, [1 << index for index in range(len(flags))])
        self.assertTrue(plugin.DEFAULT_SETTINGS & plugin.SET_COPY_TO_CLIPBOARD)
        self.assertFalse(plugin.DEFAULT_SETTINGS & plugin.SET_PRESELECT_USER_NAMES)

    def test_user_name_replacements_preselected_only_when_asked(self):
        proposals, _ = choose(
            [hit("inflate", 0x200), hit("deflate", 0x300)],
            names={0x200: "my_inflate"},
            user={0x200},
            overwrite=True,
        )
        self.assertEqual(plugin.default_selection(proposals), [1])
        self.assertEqual(plugin.default_selection(proposals, True), [0, 1])


class NativeDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def find(self, environ=None, on_path=None, windows=True):
        return plugin.find_native(environ or {}, self.dir, lambda _name: on_path, windows)

    def test_override_wins(self):
        (self.dir / "sigtool-native.exe").write_bytes(b"")
        self.assertEqual(self.find({"SIGTOOL_NATIVE": "C:/x.exe"}, "C:/path.exe"), "C:/x.exe")

    def test_bundled_copy_beats_path(self):
        (self.dir / "sigtool-native.exe").write_bytes(b"")
        self.assertEqual(self.find(on_path="C:/stale.exe"), str(self.dir / "sigtool-native.exe"))
        self.assertEqual(self.find(on_path="/usr/bin/x", windows=False), "/usr/bin/x")

    def test_path_then_error(self):
        self.assertEqual(self.find(on_path="C:/path.exe"), "C:/path.exe")
        with self.assertRaises(plugin.SigtoolError):
            self.find()

    def test_version_problem(self):
        expected = plugin.EXPECTED_SPEC_VERSION
        self.assertIsNone(plugin.version_problem(f"sigtool-native 0.1.0 (spec {expected})\n"))
        self.assertIn("expects spec", plugin.version_problem("sigtool-native 0.1.0 (spec 99)"))
        self.assertIn("does not report", plugin.version_problem("sigtool-native 0.1.0"))

    def test_plugin_parses_and_calls_like_python_3_8(self):
        # IDA 8.4 can embed Python 3.8: no newer syntax, and no `strict=`
        # (zip, 3.10), which parses everywhere but fails when called.
        source = Path(plugin.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source, feature_version=(3, 8))
        strict = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and any(k.arg == "strict" for k in node.keywords)
        ]
        self.assertEqual(strict, [])

    def test_expected_spec_matches_the_crate(self):
        spec = (Path(__file__).resolve().parent.parent / "native" / "src" / "spec.rs").read_text()
        match = re.search(r'pub const SPEC_VERSION: &str = "([^"]+)";', spec)
        self.assertIsNotNone(match)
        self.assertEqual(plugin.EXPECTED_SPEC_VERSION, match.group(1))


if __name__ == "__main__":
    unittest.main()
