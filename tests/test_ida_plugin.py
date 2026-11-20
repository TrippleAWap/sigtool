"""Tests for the IDA-free parts of ida_plugin.py: name filtering, CLI output
parsing, and choosing renames. IDA's modules are stubbed, so this runs with a
plain Python: ``python -m unittest tests/test_ida_plugin.py``."""

from __future__ import annotations

import ast
import importlib
import json
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


def choose(hits, names=None, user=(), overwrite=False, review=()):
    names = names or {}
    owners = {name: rva for rva, name in names.items()}
    return plugin.choose_renames(
        hits,
        current_name=lambda rva: names.get(rva, f"sub_{rva:X}"),
        user_named=lambda rva: rva in user,
        name_owner=owners.get,
        overwrite_user=overwrite,
        review=review,
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
        self.assertIsNone(plugin.parse_progress("phase match"))

    def test_phase_lines(self):
        self.assertEqual(plugin.parse_phase("phase joint\n"), "joint")
        self.assertIsNone(plugin.parse_phase("progress 1/2"))
        self.assertIsNone(plugin.parse_phase("phase of the moon"))

    def test_wait_status_shows_phase_progress_and_elapsed(self):
        status = plugin.WaitStatus("sigtool: scanning")
        self.assertEqual(status.text(0.4), "sigtool: scanning\n0 s")
        status.feed("phase context\n")
        status.feed("phase match\n")
        status.feed("progress 7/40\n")
        self.assertEqual(status.text(12.7), "sigtool: scanning\nmatch, 7 / 40, 12 s")

    def test_wait_status_keeps_progress_and_skips_out_of_the_error(self):
        # A failed sign-all prints one `skipped` line per function before its
        # error; the warning shows the error, the Output window the rest.
        status = plugin.WaitStatus("sigtool: signing")
        for line in ("progress 1/3\n", "phase match\n", "skipped 0x10 f: no\n", "error: bad\n"):
            status.feed(line)
        self.assertEqual(status.stderr(), "skipped 0x10 f: no\nerror: bad\n")
        self.assertEqual(status.error(2), "error: bad")
        self.assertEqual(plugin.WaitStatus("x").error(3), "exit code 3")

    def test_menu_remembers_the_action_by_name(self):
        names = [row[0] for row in plugin.MenuForm.CHOICES]
        self.assertEqual(plugin.menu_index("rApply"), names.index("rApply"))
        # An index stored by an older version, or garbage, selects the first row.
        for stale in ("5", "", "rGone"):
            self.assertEqual(plugin.menu_index(stale), 0)

    def test_own_db_is_named_after_the_idb_not_the_input(self):
        folder = Path("work")
        x64_idb, arm_idb = str(folder / "libz-x64.i64"), str(folder / "libz-arm64.i64")
        x64 = plugin.own_db_paths(x64_idb, plugin.own_stem(x64_idb, "libz.so.1"))
        arm = plugin.own_db_paths(arm_idb, plugin.own_stem(arm_idb, "libz.so.1"))
        self.assertEqual(x64[0], str(folder / "sigtool" / "libz-x64.db"))
        self.assertNotEqual(x64, arm)
        self.assertEqual(plugin.own_stem("", "libz.so.1"), "libz.so.1")
        self.assertEqual(plugin.own_stem("C:\\w\\libz.so.i64", "x"), "libz.so")

    def test_windows_device_names_are_not_file_names(self):
        for name in ("nul", "CON", "com1", "aux.so", "Lpt9"):
            self.assertTrue(plugin.safe_file_name(name).startswith("_"), name)
        for name in ("console", "nullify", "com0", "auxiliary"):
            self.assertEqual(plugin.safe_file_name(name), name)

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
        self.assertNotIn("incomplete", text)

    def test_build_summary_counts_verdict_and_confidence(self):
        def signed(verdict, confidence):
            row = {"rva": "0x10", "status": "signed"}
            return {**row, "verdict": verdict, "confidence": confidence}

        text = plugin.summarize_build(
            {
                "signed": 3,
                "functions": [
                    signed("weak", "single-arch"),
                    signed("good", "single-arch"),
                    signed("weak", "low"),
                    {"rva": "0x20", "status": "refused", "verdict": "ignored"},
                ],
            }
        )
        lines = text.splitlines()
        self.assertEqual(lines[0], "signed 3 of 4 functions")
        self.assertEqual(lines[1], "verdicts: good 1, weak 2")
        self.assertEqual(lines[2], "confidence: low 1, single-arch 2")

    def test_report_quality(self):
        report = (
            "signature inflate  (abc)\narch x64  verdict weak  confidence single-arch\n"
            "features 9 (required 1, optional 8)"
        )
        self.assertEqual(plugin.report_quality(report), "weak, single-arch")
        self.assertIsNone(plugin.report_quality("no report"))

    def test_truncation_is_described(self):
        self.assertIsNone(plugin.describe_truncation({}))
        self.assertIsNone(plugin.describe_truncation({"truncated": []}))
        document = {
            "truncated": [
                {"budget": "reference_index", "count": 4000000, "limit": 4000000},
                {"budget": "joint_pairs", "count": 70000000, "limit": 67108864},
            ]
        }
        self.assertTrue(plugin.truncation_skips_code(document))
        # The joint cap leaves no code unscanned: only joint resolution.
        joint = {"truncated": [document["truncated"][1]]}
        self.assertFalse(plugin.truncation_skips_code(joint))
        self.assertEqual(
            plugin.describe_truncation(joint),
            "joint resolution skipped a module (70000000 pairs, limit 67108864), "
            "so matches there were judged alone",
        )
        self.assertEqual(
            plugin.describe_truncation(document),
            "incomplete: budgets ran out: reference index (limit 4000000); "
            "joint resolution skipped a module (70000000 pairs, limit 67108864), "
            "so matches there were judged alone",
        )
        summary = plugin.summarize_build({"signed": 0, "functions": [], **document})
        self.assertEqual(summary.splitlines()[0], "signed 0 of 0 functions")
        self.assertIn("incomplete: budgets ran out: reference index", summary)


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

    def test_unsure_matches_follow_for_review_and_are_never_preselected(self):
        hits = [
            hit("inflate", 0x200),
            {**hit("deflate", 0x300, "candidate"), "answer_withheld": "tie", "matched": 3},
            hit("crc32", 0x400, "shape-only"),
        ]
        proposals, skipped = choose(hits, user={0x300}, overwrite=True)
        self.assertEqual([p.name for p in proposals], ["inflate"])
        proposals, skipped = choose(hits, review=("candidate",), overwrite=True)
        self.assertEqual([(p.name, p.evidence) for p in proposals][1:], [("deflate", "candidate")])
        self.assertEqual((proposals[1].withheld, proposals[1].matched), ("tie", 3))
        self.assertEqual(skipped, [("crc32", "best match is shape-only at +0x400")])
        proposals, _ = choose(hits, review=("candidate", "shape-only"))
        self.assertEqual([p.name for p in proposals], ["inflate", "deflate", "crc32"])
        self.assertEqual(plugin.default_selection(proposals), [0])
        self.assertEqual(plugin.default_selection(proposals, True), [0])

    def test_unsure_matches_never_contradict_identified_ones(self):
        hits = [
            hit("inflate", 0x200),
            hit("deflate", 0x200, "candidate"),  # the address is taken
            hit("inflate", 0x500, "candidate", signature_id="inflate-2"),  # the name is
            hit("crc32", 0x600, "candidate"),
            hit("crc32", 0x700, "candidate", signature_id="crc32-2"),  # two addresses
        ]
        proposals, skipped = choose(hits, review=("candidate",))
        self.assertEqual([(p.rva, p.name) for p in proposals], [(0x200, "inflate")])
        reasons = dict(skipped)
        self.assertIn("an identified match claims", reasons["deflate"])
        self.assertIn("an identified match is at +0x200", reasons["inflate"])
        self.assertEqual(reasons["crc32"], "matched 2 addresses")

    def test_identified_proposals_do_not_depend_on_review(self):
        hits = [hit("a", 0x10), hit("b", 0x20), hit("c", 0x10, "candidate")]
        plain, _ = choose(hits)
        reviewed, _ = choose(hits, review=("candidate", "shape-only"))
        self.assertEqual([p for p in reviewed if p.trusted], plain)

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
            first,
            "sigtool: inflate (was sub_200) from zlib.db "
            "(signature abc123, score 0.912, identified)",
        )
        self.assertEqual(plugin.provenance_comment(first, self.proposal(), "zlib.db"), first)
        kept = plugin.provenance_comment("analyst note\n", self.proposal(), "zlib.db")
        self.assertEqual(kept, f"analyst note\n{first}")

    def test_last_provenance_line_is_parsed(self):
        self.assertIsNone(plugin.parse_provenance(""))
        self.assertIsNone(plugin.parse_provenance("analyst: sigtool: x from y"))
        old_format = "sigtool: inflate from zlib.db (signature a, score 1.000, identified)"
        self.assertEqual(plugin.parse_provenance(old_format), ("inflate", None))
        twice = (
            "note\nsigtool: inflate (was sub_200) from a.db (signature a)\n"
            "sigtool: inflate2 (was inflate) from b.db (signature b)"
        )
        self.assertEqual(plugin.parse_provenance(twice), ("inflate2", "inflate"))

    def test_sigtool_owned_only_while_the_name_is_unchanged(self):
        comment = "sigtool: op<int> (was sub_200) from a.db (signature a)"
        self.assertTrue(plugin.sigtool_owned("op<int>", comment))
        # IDA stored the name with characters replaced (SN_NOCHECK).
        validate = lambda name: re.sub(r"[<>]", "_", name)  # noqa: E731
        self.assertTrue(plugin.sigtool_owned("op_int_", comment, validate))
        self.assertFalse(plugin.sigtool_owned("my_op", comment, validate))
        self.assertFalse(plugin.sigtool_owned("op<int>", "analyst note"))

    def test_revert_plan(self):
        functions = [
            (0x200, "inflate", "note\nsigtool: inflate (was sub_200) from a.db (s)"),
            (0x300, "my_name", "sigtool: deflate (was sub_300) from a.db (s)"),  # renamed since
            (0x400, "crc", "sigtool: crc from a.db (s)"),  # no old name recorded
            (
                0x500,
                "adler2",
                "sigtool: adler (was sub_500) from a.db (s)\n"
                "sigtool: adler2 (was adler) from b.db (s)",
            ),
            (0x600, "plain", "just a comment"),
            (0x700, "zlib_inflate", "sigtool: zlib_inflate (was my_inflate) from a.db (s)"),
        ]
        reverts, skipped = plugin.revert_plan(functions)
        self.assertEqual(
            [(r.rva, r.current, r.old, r.comment) for r in reverts],
            [
                (0x200, "inflate", "", "note"),
                (0x500, "adler2", "adler", "sigtool: adler (was sub_500) from a.db (s)"),
                (0x700, "zlib_inflate", "my_inflate", ""),
            ],
        )
        self.assertEqual([name for name, _ in skipped], ["crc", "deflate"])
        self.assertIn("renamed since", dict(skipped)["deflate"])

    def test_revert_keeps_name_and_comment_when_the_old_name_is_taken(self):
        # X was `foo`, sigtool named it `baz`; a later apply gave `foo` to Y.
        # Reverting X must not clear it to a dummy name and drop the only
        # record of `foo`.
        names = {0x1200: "baz", 0x1300: "foo"}
        comments = {0x1200: "sigtool: baz (was foo) from a.db (s)"}

        def set_name(ea, name, _flags=0):
            if name and name in names.values() and names.get(ea) != name:
                return False
            names[ea] = name
            return True

        function = types.SimpleNamespace(start_ea=0x1200)
        written = []
        with (
            mock.patch.object(plugin.ida_name, "get_ea_name", names.get, create=True),
            mock.patch.object(plugin.ida_name, "set_name", set_name, create=True),
            mock.patch.object(plugin.ida_name, "SN_NOWARN", 1, create=True),
            mock.patch.object(plugin.ida_name, "SN_NOCHECK", 2, create=True),
            mock.patch.object(plugin.ida_funcs, "get_func", lambda _ea: function, create=True),
            mock.patch.object(
                plugin.ida_funcs,
                "get_func_cmt",
                lambda f, _r: comments.get(f.start_ea),
                create=True,
            ),
            mock.patch.object(
                plugin.ida_funcs,
                "set_func_cmt",
                lambda f, text, _r: written.append((f.start_ea, text)),
                create=True,
            ),
            mock.patch.object(plugin, "_validated_name", lambda name: name),
        ):
            self.assertIsNone(plugin._revert_function(0x1200, 0x1000))
            self.assertEqual(names[0x1200], "baz")
            self.assertEqual(written, [])
            # Once `foo` is free, the second pass restores it.
            names[0x1300] = "sub_1300"
            done = plugin._revert_function(0x1200, 0x1000)
        self.assertEqual((done.old, names[0x1200]), ("foo", "foo"))
        self.assertEqual(written, [(0x1200, "")])

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

    def test_label_is_the_idb_name_when_meaningful(self):
        matches = [
            {"rva": "0x200", "evidence": "identified", "label": "inflate"},
            {"rva": "0x300", "evidence": "candidate", "label": None},
            {"rva": "0x400", "evidence": "candidate", "label": "deflate"},
        ]
        names = {0x1200: "my_inflate", 0x1300: "sub_1300", 0x1400: "sub_1400"}
        rows = plugin.match_rows(matches, 0x1000, names.get)
        self.assertEqual([row.cells[3] for row in rows], ["my_inflate", "sub_1300", "deflate"])

    def test_jump_only_to_an_identified_best_match(self):
        def rows(*evidence):
            return [plugin.Row(0x10 * i, ("", "", e, "", "")) for i, e in enumerate(evidence)]

        self.assertEqual(plugin.locate_actions([], True, True), (False, False))
        self.assertEqual(plugin.locate_actions(rows("identified"), True, False), (True, False))
        self.assertEqual(plugin.locate_actions(rows("identified"), False, True), (False, True))
        # A guess is never jumped to, and is listed even with listing off.
        for evidence in ("candidate", "shape-only"):
            self.assertEqual(
                plugin.locate_actions(rows(evidence, "identified"), True, False), (False, True)
            )


# `locate --explain --expect 0x15bb0 --discovery hint-free --json` of zlib's
# `inflate` signature (x64 clang-O2) on the same image: inflateUndermine fails
# the score gate. Captured from sigtool-native 0.1.1 (spec 7).
EXPLAIN = json.loads(
    """{"address": "0x15bb0", "answer_floor": null, "answer_withheld": null, "candidate": true,
    "carriers": null, "chance": null, "cross_isa": false, "decided": "score", "end": "0x15bf4",
    "evidence": null, "gates": [{"gate": "candidate", "needed": null, "passed": true,
    "value": null}, {"gate": "score", "needed": 0.75, "passed": false, "value": 0.650246}],
    "inherited": [], "label": "inflateUndermine", "matched": ["cfg:loops:1", "const:0x0",
    "const:0x1f", "const:0xffffc0cc", "const:0xfffffffe", "ops:ret:2"], "matched_required": 4,
    "matches": 1, "min_distinct": 3, "missed": [{"key": "cfg:blocks:8", "required": false},
    {"key": "cfg:edges:9", "required": false}, {"key": "const:0x1e", "required": true},
    {"key": "const:0x3f3f", "required": true}, {"key": "const:0x3f40", "required": true},
    {"key": "ops:arith:5", "required": false}, {"key": "ops:branch:2", "required": false},
    {"key": "ops:cmp:7", "required": false}, {"key": "ops:cond:7", "required": false},
    {"key": "ops:load:6", "required": false}, {"key": "ops:move:7", "required": false},
    {"key": "ops:stack:10", "required": false}], "module": "zlib", "neighbours": {"missed":
    ["in2:const:0x40000000", "in:str:1.3.1", "in:str:unexpected end of file"], "shared": []},
    "optional_callees": [], "rank": null, "required": 7, "rival": null, "rva": "0x15bb0",
    "score": 0.650246, "similarity": 0.309496, "start": "0x15bb0", "threshold": 0.75}"""
)


class ExplainTests(unittest.TestCase):
    def test_captured_explanation(self):
        text = plugin.format_explanation(EXPLAIN, "inflate", "0x15bb0 (sub_15BB0)")
        lines = text.splitlines()
        self.assertEqual(lines[0], "inflate at 0x15bb0 (sub_15BB0): decided by the score gate")
        self.assertEqual(lines[1], "not among the 1 matches")
        self.assertEqual(
            lines[2],
            "score 0.650 (threshold 0.75), similarity 0.309, required 4/7 (min distinct 3)",
        )
        self.assertIn("  candidate          pass", lines)
        self.assertIn("  score              FAIL 0.65 vs 0.75", lines)
        self.assertIn("missed, required (3): const:0x1e const:0x3f3f const:0x3f40", lines)
        self.assertIn(
            "matched (6): cfg:loops:1 const:0x0 const:0x1f const:0xffffc0cc "
            "const:0xfffffffe ops:ret:2",
            lines,
        )
        self.assertNotIn("not identified", text)
        self.assertNotIn("inherited", text)

    def test_withheld_answer_and_rank(self):
        explain = {
            **EXPLAIN,
            "decided": "answer",
            "rank": 1,
            "matches": 2,
            "evidence": "candidate",
            "answer_withheld": "rival",
            "answer_floor": 0.85,
            "rival": 0.8123,
            "inherited": ["inl:str:x"],
        }
        text = plugin.format_explanation(explain, "inflate", "0x15bb0")
        self.assertIn("rank 1 of 2 matches, candidate", text)
        self.assertTrue(text.startswith("inflate at 0x15bb0: decided by the answer gate"))
        accepted = plugin.format_explanation({**EXPLAIN, "decided": "accepted"}, "f", "0x1")
        self.assertTrue(accepted.startswith("f at 0x1: accepted\n"))
        self.assertIn("not identified: rival (answer floor 0.85, rival 0.812)", text)
        self.assertIn("inherited from callees (1): inl:str:x", text)

    def test_missing_explanation(self):
        self.assertIn("nothing to explain", plugin.format_explanation(None, "inflate", "0x10"))


class DbContentsTests(unittest.TestCase):
    def test_db_summary(self):
        info = {
            "spec_version": "7",
            "signatures": 3,
            "confidence": {"single-arch": 2, "low": 1},
            "arches": {"x64": 3, "arm64": 1},
        }
        self.assertEqual(
            plugin.describe_db(info),
            "3 signatures, spec 7; confidence: low 1, single-arch 2; arch: arm64 1, x64 3",
        )
        self.assertEqual(
            plugin.describe_db({"spec_version": "7", "signatures": 0}), "0 signatures, spec 7"
        )

    def test_db_rows(self):
        listing = {
            "signatures": [
                {
                    "name": "deflate",
                    "signature_id": "ab",
                    "arches": ["arm64", "x64"],
                    "confidence": "multi-arch",
                },
                {"name": "inflate", "signature_id": "cd", "arches": [], "confidence": "low"},
            ]
        }
        rows = plugin.db_rows(listing)
        self.assertEqual([row.ea for row in rows], [None, None])
        self.assertEqual(rows[0].cells, ("deflate", "ab", "arm64+x64", "multi-arch"))
        self.assertEqual(rows[1].cells, ("inflate", "cd", "", "low"))
        self.assertEqual(plugin.db_rows({}), [])


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

    def test_elf_segment_with_a_zero_fill_tail_ends_its_file_data_at_p_filesz(self):
        # A section-less image's data LOAD holds 0x40 file bytes and 0x80 in
        # memory, and is last in the file; IDA maps it as one 0x80 segment.
        image = self.elf_with_loads()
        segments = [
            plugin.Segment("LOAD", 0x0, 0x1100, 0x0, True, False),
            plugin.Segment("LOAD", 0x2000, 0x2080, 0x1100, False, True),
        ]
        out = plugin.rebuild_elf(image, segments)
        self.assertIsNotNone(out)
        shoff = struct.unpack_from("<Q", out, 0x28)[0]
        count = struct.unpack_from("<H", out, 0x3C)[0]
        rows = [struct.unpack_from("<IIQQQQ", out, shoff + 64 * i) for i in range(1, count - 1)]
        self.assertEqual(
            [(kind, address, offset, size) for _name, kind, _flags, address, offset, size in rows],
            [(1, 0x0, 0x0, 0x1100), (1, 0x2000, 0x1100, 0x40), (8, 0x2040, 0x1140, 0x40)],
        )

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

    def test_signing_goes_to_this_idbs_own_db_unless_another_is_typed(self):
        idb = str(Path("b") / "libb.so.i64")
        own, selection = plugin.own_db_paths(idb, "libb.so")
        self.assertEqual(own, str(Path("b") / "sigtool" / "libb.so.db"))
        self.assertEqual(selection, str(Path("b") / "sigtool" / "libb.so.selection.db"))
        other = str(Path("a") / "sigtool" / "liba.so.db")
        # The field still shows the DB applied last (another IDB's): not it.
        self.assertEqual(plugin.signing_db_path(other, other, idb, "libb.so", False), own)
        self.assertEqual(plugin.signing_db_path(other, other, idb, "libb.so", True), selection)
        # This IDB's own DB shown by default: a selection still gets its own.
        self.assertEqual(plugin.signing_db_path(own, own, idb, "libb.so", True), selection)
        self.assertEqual(plugin.signing_db_path("", other, idb, "libb.so", False), own)
        typed = str(Path("c") / "new.db")
        self.assertEqual(plugin.signing_db_path(f" {typed} ", other, idb, "libb.so", False), typed)

    def test_replacing_another_idbs_db_asks_first(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        idb = str(Path(temp.name) / "b" / "libb.so.i64")
        own = Path(plugin.own_db_paths(idb, "libb.so")[0])
        own.parent.mkdir(parents=True)
        own.write_bytes(b"own")
        other = Path(temp.name) / "liba.so.db"
        other.write_bytes(b"other")
        asked = []
        kernwin = plugin.ida_kernwin
        with (
            mock.patch.object(plugin, "_idb_path", lambda: idb),
            mock.patch.object(plugin, "_image_stem", lambda: "libb.so"),
            mock.patch.object(plugin, "_db_signature_count", lambda _path: 120),
            mock.patch.object(
                kernwin, "ask_yn", lambda _d, text: asked.append(text) or 0, create=True
            ),
        ):
            plugin._confirm_replace(str(own), "12 named functions")
            plugin._confirm_replace(str(Path(temp.name) / "new.db"), "12 named functions")
            self.assertEqual(asked, [])
            with self.assertRaises(plugin.SigtoolCancelled):
                plugin._confirm_replace(str(other), "12 named functions")
        self.assertIn("holds 120 signatures", asked[0])
        self.assertIn(str(other), asked[0])

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
        # Methods that parse on 3.8 but exist only from 3.9 or later.
        newer = {"removeprefix", "removesuffix", "is_relative_to", "bit_count", "lcm"}
        used = [
            (node.lineno, node.attr)
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in newer
        ]
        self.assertEqual(used, [])

    def test_expected_spec_matches_the_crate(self):
        spec = (Path(__file__).resolve().parent.parent / "native" / "src" / "spec.rs").read_text()
        match = re.search(r'pub const SPEC_VERSION: &str = "([^"]+)";', spec)
        self.assertIsNotNone(match)
        self.assertEqual(plugin.EXPECTED_SPEC_VERSION, match.group(1))


if __name__ == "__main__":
    unittest.main()
