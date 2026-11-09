"""M7.6b (ADR-0008 decision 6): the window's look. The theme table, the
level -> colour mapping, the Treeview columns and their sort keys, the
detail pane, the Rules table's overlay state, the header's rules item, the
first-run text and the doctrine, the footer, the tray tip; then one small
Tk test (skipped without tkinter or a display) that builds every screen at
900x600 and checks that nothing asks for more."""
from __future__ import annotations

import ast
import datetime
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, host, overlay, tray  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_app import FakeSession, TkSession, tk_or_skip, until  # noqa: E402
from test_app_host import CATALOG, FakeHostWatch, TkHost, inv, probe  # noqa: E402

LEVELS = ("clean", "alarm", "incomplete", "note", "hole", "suppressed")
HEX = re.compile(r"#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3}){0,3}")
TK_NAMES = {"black", "white", "red", "green", "blue", "yellow", "orange", "gray", "grey", "purple", "brown", "pink",
            "cyan", "magenta", "navy", "maroon", "olive", "teal", "silver", "gold", "darkred", "darkgreen",
            "darkblue", "darkorange", "darkgray", "darkgrey", "lightgray", "lightgrey", "lightblue", "firebrick",
            "forestgreen", "systembuttonface", "systemwindow", "systemwindowtext", "systembuttontext",
            "systemhighlight", "systemhighlighttext", "amber"}
WAIT = 30


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


# --- E1: one theme table; the exit-code scheme; a word beside every colour ------------------------------------

def test_e1_the_theme_has_both_modes_with_the_same_keys_and_every_level():
    light, dark = app.THEME["light"], app.THEME["dark"]
    assert set(light) == set(dark) and set(light["levels"]) == set(dark["levels"]) == set(LEVELS)
    assert set(light["band_bg"]) == set(dark["band_bg"]) == {"clean", "alarm", "incomplete", "note"}
    for mode in (light, dark):
        flat = [v for k, v in mode.items() if isinstance(v, str)] + list(mode["levels"].values()) + list(
            mode["band_bg"].values())
        assert all(HEX.fullmatch(c) for c in flat), flat
    assert set(app.LEVEL_WORDS) == set(LEVELS) and all(app.LEVEL_WORDS.values())
    fonts = app.THEME["fonts"]
    assert fonts["ui"] and fonts["mono"] and all(isinstance(f, str) for f in fonts["ui"] + fonts["mono"])
    assert app.THEME["min_size"] == (900, 600)
    assert app.DOCTRINE == "Rules decide; a model may only raise suspicion."


def test_e1_level_colour_follows_the_exit_codes_holes_amber_suppressed_red_notes_grey():
    for mode in ("light", "dark"):
        lv = app.THEME[mode]["levels"]
        assert [app.level_colour(c, mode) for c in (0, 1, 3)] == [lv["clean"], lv["alarm"], lv["incomplete"]]
        assert app.level_colour(2, mode) == lv["alarm"]          # any other code: alarm, as code_level
        assert app.level_colour("hole", mode) == lv["incomplete"]          # holes amber
        assert app.level_colour("suppressed", mode) == lv["alarm"]         # ADR-0008 A-2: red
        assert app.level_colour("note", mode) not in (lv["clean"], lv["alarm"], lv["incomplete"])   # grey
        assert app.level_colour("no such level", mode) == lv["incomplete"]
        assert app.band_colours(1, mode) == (lv["alarm"], app.THEME[mode]["band_bg"]["alarm"])
    assert [app.level_of(c) for c in (0, 1, 3, 2)] == [app.code_level(c) for c in (0, 1, 3, 2)]
    assert app.level_colour(0, "no such mode") == app.THEME["light"]["levels"]["clean"]
    assert [app.level_word(c) for c in (0, 1, 3, "note")] == ["clean", "alarm", "incomplete", "note"]


def _colour_literals(path):
    """(line, text) of every string constant outside THEME that is a colour."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "THEME" for t in node.targets):
            skip |= {id(n) for n in ast.walk(node)}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            text = node.value.strip()
            if HEX.fullmatch(text) or text.lower() in TK_NAMES:
                out.append((node.lineno, text))
    return out


def test_e6_the_theme_table_is_the_only_place_a_colour_lives():
    """AST: no colour literal (#rrggbb, or a Tk colour name) outside THEME."""
    assert _colour_literals(ROOT / "raqib" / "app.py") == []
    assert _colour_literals(ROOT / "raqib" / "tray.py") == []
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert "LEVEL_COLORS" not in src and src.count("THEME = {") == 1


def test_e1_dark_or_light_from_the_os_where_it_can_be_read_else_light():
    assert app.os_mode("win32", read=lambda: 0) == "dark"
    assert app.os_mode("win32", read=lambda: 1) == "light"

    def broken():
        raise OSError("no such key")
    assert app.os_mode("win32", read=broken) == "light"
    assert app.os_mode("linux") == "light" and app.os_mode("darwin") == "light"
    # the registry is read, never written: winreg only in _apps_use_light_theme, KEY_READ, no Set/Create/Delete
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_apps_use_light_theme")
    names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    assert {"OpenKey", "QueryValueEx", "KEY_READ", "HKEY_CURRENT_USER"} <= names
    assert not {x for x in names if x.startswith(("Set", "Create", "Delete", "Save", "Load", "Flush"))}
    winreg_users = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                    for n in ast.walk(f) if isinstance(n, ast.Import) and any(a.name == "winreg" for a in n.names)}
    assert winreg_users == {"_apps_use_light_theme"}


def test_e1_named_system_fonts_with_fallbacks():
    assert app.pick_font(("Segoe UI", "DejaVu Sans"), ["dejavu sans", "Courier"]) == "dejavu sans"
    assert app.pick_font(("Segoe UI",), ["Segoe UI"]) == "Segoe UI"
    assert app.pick_font(("Nothing",), ["Courier"]) is None   # Tk's own default font stays


# --- E2: the host table ---------------------------------------------------------------------------------------

def test_e2_the_tree_table_has_the_eight_columns_in_order():
    assert [c[1] for c in app.TREE_COLUMNS] == ["image", "pid", "kind", "source", "findings", "rhythm / suspicion",
                                                "first seen", "endpoints"]
    names = [n for n, _ in app.HOST_COLUMNS]
    for cid, heading, width, index, kind in app.TREE_COLUMNS:   # each maps to its host_rows cell
        assert names[index] == {"kind": "named"}.get(heading, heading)
        assert width > 0 and kind in ("text", "number", "severity")
    assert sum(c[2] for c in app.TREE_COLUMNS) <= 860 and sum(c[2] for c in app.RULES_COLUMNS) <= 860
    row = ("img", "7", "named (new)", "2026-11-09T00:00:00Z", "3", "os", "high 1", "-", "1.2.3.4:443")
    assert app.tree_values(row) == ("img", "7", "named (new)", "os", "high 1", "-", "2026-11-09T00:00:00Z",
                                    "1.2.3.4:443")


def test_e2_sort_keys_numbers_severities_text_and_dash_last():
    k = app.sort_key
    assert sorted(["10", "9", "x", "100"], key=lambda c: k("number", c)) == ["9", "10", "100", "x"]
    cells = ["none", "medium 2", "high 1, low 4", "high 2", "low 1", "-", "history 3"]
    assert sorted(cells, key=lambda c: k("severity", c)) == ["high 2", "high 1, low 4", "medium 2", "low 1",
                                                             "history 3", "none", "-"]
    assert sorted(["high", "low", "medium"], key=lambda c: k("severity", c)) == ["high", "medium", "low"]
    assert sorted(["b", "-", "A", "a10", "a9"], key=lambda c: k("text", c)) == ["A", "a9", "a10", "b", "-"]
    rows = [("z", "10"), ("a", "9"), ("m", "100")]
    cols = (("image", "image", 1, 0, "text"), ("pid", "pid", 1, 1, "number"))
    assert [r[0] for r in app.sort_rows(rows, cols, "pid")] == ["a", "z", "m"]
    assert [r[0] for r in app.sort_rows(rows, cols, "pid", reverse=True)] == ["m", "z", "a"]
    assert [r[0] for r in app.sort_rows(rows, cols, "image")] == ["a", "m", "z"]


def test_e2_row_levels_say_it_in_words_too():
    base = ["img", "1", "named", "-", "0", "-", "none", "-", "-"]
    assert app.row_level(base) is None
    assert app.row_level(base[:2] + ["unknown (new)"] + base[3:]) == "alarm"
    assert app.row_level(base[:6] + ["medium 1"] + base[7:]) == "alarm"
    assert app.row_level(base[:2] + ["named (history, gone)"] + base[3:]) == "note"
    assert app.row_level(base[:2] + ["unknown"] + base[3:]) is None      # "unknown" is not "new"


def _host_state():
    st = FakeHostWatch().state(0)
    key = [4242, "scribe", "2026-11-09T00:00:00Z"]
    other = [7, "claude", None]
    word = host.tree_word(tuple(key))
    tree = {"key": key, "pid": 4242, "image": "scribe", "exe": "/usr/local/bin/scribe", "started": key[2],
            "class": "candidate", "named": False, "benign": False, "acts": 2, "knocked": True,
            "endpoints": ["1.2.3.4:443"], "cites": [{"src": "proc", "line": 12, "text": "scribe --session secret"}]}
    st["host"] = dict(st["host"], now=2, new=1, trees=[tree, dict(tree, key=other, pid=7, image="claude",
                                                                  named=True, knocked=False, cites=[])],
                      findings=[{"rule_id": "NEW-AGENT-UNKNOWN", "severity": "medium", "round": 1, "tree": word,
                                 "tree_key": key, "summary": "a new tree", "notice": "sent", "run": "r1",
                                 "cited_seq": [3]},
                                {"rule_id": "NEW-AGENT", "severity": "high", "round": 1, "tree": "7:claude:-",
                                 "tree_key": other, "summary": "claude", "notice": "sent", "run": "r1",
                                 "cited_seq": [4]}],
                      suspicions=[{"suspicion": 0.9, "round": 2, "tree": word, "reasons": ["odd"], "notice": "sent",
                                   "backend": "fake", "model": "m", "trace": "t", "cited_seq": [5]}],
                      dark_notes=[{"text": "round 3: a note of scribe", "live_tree": word},
                                  {"text": "round 3: a note of another", "live_tree": "9:x:-"}])
    return st


def test_e2_the_detail_pane_shows_the_selected_trees_findings_notes_source_cites():
    v = app.host_watch_view(_host_state())
    assert len(v["details"]) == len(v["rows"]) == 2
    text = app.tree_detail_text(v["rows"][0], v["details"][0])
    assert text.startswith("scribe pid 4242: unknown (new)")
    assert "NEW-AGENT-UNKNOWN [medium]" in text and "SUSPECT [suspicion 0.90]" in text
    assert "NEW-AGENT [high]" not in text
    assert "round 3: a note of scribe" in text and "a note of another" not in text
    assert "cites: proc:12" in text and "acts 2" in text and "source: " in text and "class candidate" in text
    assert "--session" not in text and "/usr/local/bin" not in text    # never a command line or an exe path
    other = app.tree_detail_text(v["rows"][1], v["details"][1])
    assert "NEW-AGENT [high]" in other and "FINDINGS: 1" in other and "cites: -" in other
    assert "FINDINGS: 0" in app.tree_detail_text(("x", "1"))            # a row without its detail still says


def test_e2_the_look_has_details_too_and_look_json_is_unchanged(home):
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0, home=str(home)).start()
    assert until(p.done, WAIT)
    v = p.view()
    assert len(v["details"]) == len(v["rows"]) == 2
    import json
    written = json.loads(Path(app.look_path(str(home))).read_text(encoding="ascii"))
    assert "details" not in written and written["rows"] == [list(r) for r in v["rows"]]
    # the text under the table: no table there any more (the Treeview has the rows), the rest as host_body
    body = app.host_text_body(v)
    assert app.host_table(v["rows"])[0] not in body and body == app.host_body(dict(v, rows=[])).lstrip("\n")
    assert "HOLES (A3): 14" in body


def test_e2_the_empty_state_and_nothing_read_keep_not_a_clearance():
    i = dict(inv("linux"), candidates=[], act_roots=[], footprints=[], agent_dark=[], result="clean")
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    body = app.host_text_body(p.view())
    assert body.startswith("no agent seen (") and "Not a clearance." in body
    p, _ = probe(lambda: dict(i, records=0))
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "NOTHING READ" and "Not a clearance." in app.host_text_body(v)


# --- E3: the Rules table, the header ---------------------------------------------------------------------------

def test_e3_the_rules_table_says_the_overlay_state_per_row(home):
    overlay.set_status("NET-TOOL", "off", str(home))
    overlay.set_threshold("HOST-RHYTHM", "suspect_every", "20", str(home))
    rows = dict((v[0], (v, level)) for v, level in app.rules_rows(overlay.listing(overlay.load(str(home)))))
    assert [c[0] for c in app.RULES_COLUMNS] == ["id", "kind", "class", "severity", "budget", "status", "overlay",
                                                 "origin", "thresholds"]
    assert rows["NET-TOOL"][0][5:7] == ("off", "off by the overlay") and rows["NET-TOOL"][1] == "incomplete"
    assert rows["HOST-RHYTHM"][0][6] == "thresholds set" and "suspect_every=20*" in rows["HOST-RHYTHM"][0][8]
    assert rows["SECRET-OUTPUT"][0][5:7] == ("on", "-") and rows["SECRET-OUTPUT"][1] is None
    yaml_off = app.rules_rows([{"id": "X", "status": "off", "off_by": "yaml", "thresholds": []}])
    assert yaml_off[0][0][6] == "off in its YAML" and yaml_off[0][0][8] == "-"


def test_e3_the_header_rules_item_is_red_while_suppressed():
    suppressed = {"rules_overlay": {"not_judged": {"NET-TOOL": {"fired": 2}}}}
    assert app.header_rules("1 rule off: NET-TOOL", [suppressed, None]) == (
        "1 rule off: NET-TOOL; 2 finding(s) suppressed by the overlay", "suppressed")
    assert app.header_rules("1 rule off: NET-TOOL", [{}]) == ("1 rule off: NET-TOOL", "incomplete")
    assert app.header_rules("no rule off") == ("no rule off", None)
    assert app.level_colour("suppressed") == app.level_colour(1)


def test_e3_the_rules_text_under_the_table_has_no_table(home):
    p = app.RulesPanel(home=str(home))
    assert p.notes_text().startswith(app.RULES_INTRO) and "rules: no rule off" in p.notes_text()
    assert overlay.table_text(p.rows).splitlines()[0] not in p.notes_text()
    assert overlay.table_text(p.rows).splitlines()[0] in p.text()        # text() as before (raqib rules, tests)


def test_e1_text_tags_colour_findings_holes_notes_with_their_words():
    tags = dict(app.text_tags("FINDINGS: 2\n  high (1)\n    X\n\nNOTES (not alarms): 1\n  - n\n\nHOLES (A3): 1\n"
                              "  - h\nhole: tray\nRESULT: CLEAN (exit 0)\n"))
    assert tags["FINDINGS: 2"] == tags["    X"] == "alarm" and tags["  - n"] == "note"
    assert tags["  - h"] == tags["hole: tray"] == "hole" and tags["RESULT: CLEAN (exit 0)"] is None
    assert dict(app.text_tags("FINDINGS: 0\nHOLES (A3): 0\n")) == {"FINDINGS: 0": None, "HOLES (A3): 0": None}


# --- E4: the first run and the doctrine ---------------------------------------------------------------------

def test_e4_the_first_run_text_appears_and_then_does_not(home):
    lines = app.first_run_lines(str(home))
    assert len(lines) == 3 and lines == list(app.FIRST_RUN)
    assert "what Raqib sees" in lines[0] and "never touches an agent" in lines[1]
    assert "\"No agent seen\" is never a clearance" in lines[2]
    assert app.look_path(str(home)) == os.path.join(str(home), ".raqib", "host", "look.json")
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0, home=str(home)).start()   # the first look writes it
    assert until(p.done, WAIT)
    p.view()
    assert app.first_run_lines(str(home)) == []
    assert app.first_run_lines(None, exists=lambda path: False) == list(app.FIRST_RUN)


def test_e5_the_footer_counts_the_looks_holes_and_keeps_the_windows_own():
    lines = app.foot_lines(["tray: x"], ["page: y"], ["a", "b", "c"])
    assert lines == ["hole: tray: x", "hole: round at open: the first look has 3 hole(s), each listed under HOLES on"
                     " the Host screen and written to the log", "note: page: y"]
    assert app.foot_lines([], [], []) == []


# --- E5: the tray tip ---------------------------------------------------------------------------------------

def test_e5_the_tray_tip_while_watching_and_idle(tmp_path):
    assert tray.tip_text(3, 1, 4) == "Raqib: 3 trees, 1 new, 4 findings" and tray.IDLE_TIP == "Raqib: idle"
    assert tray.Tray(lambda a: None, platform="linux").tip == "Raqib: idle"
    c = app.Controller(None, make_session=FakeSession, make_host=lambda: FakeSession("host"))
    assert c.tip == "Raqib: idle" and c.host_tip(5, 2, 1) == "Raqib: idle"
    c.start(str(tmp_path))                        # a project watch alone: no trees, its findings
    assert c.host_tip(5, 2, 1) == "Raqib: 0 trees, 0 new, 1 findings"
    c.start_host()
    assert c.host_tip(5, 2, 3) == "Raqib: 5 trees, 2 new, 3 findings"
    c.stop("x")
    assert c.host_tip(5, 2, 3) == "Raqib: idle"
    assert len(tray.tip_text(10 ** 6, 10 ** 6, 10 ** 6)) <= 127


# --- E6: the A4 guards still hold ---------------------------------------------------------------------------

def test_e6_no_new_writes_in_app_py():
    """The only writes of app.py stay where they were: the look (HostProbe._write,
    ~/.raqib/host/look.json) and app.log (AppLog); the theme reads only."""
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    writers = set()
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)] + [tree]:
        for fn in (n for n in ast.walk(cls) if isinstance(n, ast.FunctionDef)):
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                    if name in ("open", "makedirs", "write_json", "replace", "rename", "remove", "unlink", "mkstemp",
                                "copy", "copyfile", "SetValueEx", "CreateKey"):
                        writers.add(fn.name)
    assert writers == {"_write", "__init__"}, writers
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert src.count("open(path, \"w\"") == 1 and "hostmod.write_json(self.path(), record)" in src


def test_e6_files_are_ascii():
    for name in ("raqib/app.py", "raqib/tray.py", "tests/test_app_look.py"):
        (ROOT / name).read_bytes().decode("ascii")


def test_e6_readme_the_windows_three_lines_refreshed():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## The window\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in section.split("\n") if line.strip()]
    assert len(lines) == 5
    assert "Host | Project | Rules | Log" in lines[2] and "Rules decide; a model may only raise suspicion." in lines[3]
    assert "Raqib: N trees, K new, F findings" in " ".join(lines)


# --- the Tk window at 900x600 -------------------------------------------------------------------------------

def _fits(root, width=900, height=600):
    root.update_idletasks()
    return root.winfo_reqwidth() <= width and root.winfo_reqheight() <= height, (root.winfo_reqwidth(),
                                                                                    root.winfo_reqheight())


def test_tk_every_screen_fits_900x600_with_its_widgets(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        from tkinter import ttk
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)           # no home: look.json is not written
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("hooks", (False, "not installed"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        root.geometry("900x600")
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        window.tick()
        # E4: the first-run lines (no look.json under this home) and the doctrine
        assert window.first_run_shown and window.first_run_label.cget("text") == "\n".join(app.FIRST_RUN)
        assert window.doctrine.cget("text") == app.DOCTRINE
        # E2: the Treeview with the eight columns, sortable; the detail pane follows the selection
        assert isinstance(window.host_tree, ttk.Treeview)
        assert list(window.host_tree.cget("columns")) == [col[0] for col in app.TREE_COLUMNS]
        kids = window.host_tree.get_children()
        assert len(kids) == 2 and window.band.cget("text") == "HOST: 2 TREE(S)"
        assert window.band_level.cget("text") == "[alarm]"
        window.sort_by("host", "pid")
        pids = [window.host_tree.item(i, "values")[1] for i in window.host_tree.get_children()]
        assert pids == sorted(pids, key=int) and window.host_tree.heading("pid", "text") == "pid ^"
        window.sort_by("host", "pid")
        assert [window.host_tree.item(i, "values")[1] for i in window.host_tree.get_children()] == pids[::-1]
        window.host_tree.selection_set(window.host_tree.get_children()[0])
        window._show_tree_detail()
        assert window.host_detail.get("1.0", "end").startswith(window.host_tree.item(
            window.host_tree.get_children()[0], "values")[0])
        fits = []
        fits.append(("host", _fits(root)))
        window.toggle_screen_log()                                     # the header's Log on the host screen
        assert window.log_tab.cget("text") == "Hide log"
        fits.append(("host with its log", _fits(root)))
        window.toggle_screen_log()
        window.show_first()
        window.tick()
        assert str(window.doctor_text.cget("font")) == "TkFixedFont"
        fits.append(("project", _fits(root)))
        window.start()
        window.tick()
        window.toggle_log()
        assert str(window.log_text.cget("font")) == "TkFixedFont"     # E3: the log monospace
        fits.append(("watching with its log", _fits(root)))
        window.toggle_log()
        window.show_rules()
        window.tick()
        assert isinstance(window.rules_tree, ttk.Treeview) and len(window.rules_tree.get_children()) >= 10
        assert list(window.rules_tree.cget("columns"))[6] == "overlay"
        fits.append(("rules", _fits(root)))
        assert all(ok for _, (ok, _) in fits), fits
        # E4: the look is written (here, by hand, as the look does): the first-run lines go
        os.makedirs(os.path.dirname(app.look_path(str(home))), exist_ok=True)
        Path(app.look_path(str(home))).write_text("{}", encoding="ascii")
        window.tick()
        assert not window.first_run_shown and not window.first_run_label.winfo_manager()
        assert window.running_note.cget("text").startswith("running: ")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
