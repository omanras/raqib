"""M8.1 the look (HANDOFF E1-E7, ADR-0009 decisions 1-3): the window a
person likes to open. The helpers run without a display: THEME's tokens and
its text / ground pairs, the verdict's sentences, the round strip, doctor's
rows, the Rules rows, the scale function, the two Windows calls (with fakes)
and the pictures the window draws. The Tk tests (skipped without tkinter or
a display) toggle a switch, step a threshold, open each disclosure, walk the
keyboard, and build the window at scale 1.5 and with a title bar that fails."""
from __future__ import annotations

import ast
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, host, overlay  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_app import TkSession, tk_or_skip, until  # noqa: E402
from test_app_host import CATALOG, FakeHostWatch, TkHost, inv  # noqa: E402


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    overlay._MEASURED.clear()   # a threshold measured here is not kept for another file's tests
    yield path
    overlay._MEASURED.clear()


def contrast_ratio(a, b):
    """The WCAG 2 contrast ratio of two #rrggbb colours (the test's own; M8.1 REDO A-9: not a window helper)."""
    def lum(colour):
        c = colour.lstrip("#")
        rgb = [int(c[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
        lin = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def theme_pairs(mode):
    """Every (name, text, ground) THEME["pairs"] names in mode, a level on "pill" read on its own level's pill."""
    p = app.THEME[mode]
    out = []
    for text, ground in app.THEME["pairs"]:
        if text in ("levels", "rail_levels"):
            for level, colour in p[text].items():
                out.append(("%s.%s on %s" % (text, level, ground), colour,
                            p["pill"][level] if ground == "pill" else p[ground]))
        else:
            out.append(("%s on %s" % (text, ground), p[text], p[ground]))
    return out


# --- E1: THEME's tokens, its pairs, its fonts -------------------------------------------------------------

def test_e1_theme_holds_adr_0009s_tokens_for_light_and_dark():
    light, dark = app.THEME["light"], app.THEME["dark"]
    assert (light["ground"], dark["ground"]) == ("#F4F6FA", "#111620")
    assert (light["card"], dark["card"]) == ("#FFFFFF", "#1A2130")
    assert (light["ink"], dark["ink"]) == ("#18212F", "#E7EBF3")
    assert (light["muted"], dark["muted"]) == ("#566179", "#9AA6BA")
    assert light["rail"] == dark["rail"] == "#141C2B"
    assert (light["accent"], dark["accent"]) == ("#2B59D9", "#7AA2FF")
    # blue is the only accent: green, red and amber stay the levels' (exit 0, 1, 3)
    for mode in (light, dark):
        assert mode["accent"] not in mode["levels"].values()


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_e1_every_text_ground_pair_theme_pairs_is_at_least_4_5_to_1(mode):
    pairs = theme_pairs(mode)
    assert len(pairs) > 40 and any(name.startswith("levels.alarm on pill") for name, _, _ in pairs)
    low = [(name, round(contrast_ratio(fg, bg), 2)) for name, fg, bg in pairs
           if contrast_ratio(fg, bg) < 4.5]
    assert low == []
    names = {name for name, _, _ in pairs}
    for level in app.LEVEL_WORDS:   # every level on every ground it is drawn on, with its word
        for ground in ("ground", "card", "select", "pill"):
            assert "levels.%s on %s" % (level, ground) in names
        assert "rail_levels.%s on rail" % level in names


def test_e1_fonts_are_adr_0009s_families_by_pick_font_four_sizes():
    fonts = app.THEME["fonts"]
    assert fonts["ui"] == ("Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", "Inter", "Noto Sans",
                           "DejaVu Sans")
    assert fonts["mono"] == ("Cascadia Mono", "Consolas", "DejaVu Sans Mono")
    assert [fonts[k] for k in ("verdict", "title", "body", "meta")] == [15, 11, 10, 9]
    assert app.pick_font(fonts["ui"], ["DejaVu Sans", "Inter"]) == "Inter"
    assert app.pick_font(fonts["ui"], ["segoe ui", "Inter"]) == "segoe ui"
    assert app.pick_font(fonts["mono"], ["Courier"]) is None


# --- E2: the verdict header's words ---------------------------------------------------------------------

def test_e2_the_verdict_is_one_sentence_in_sentence_case():
    s = app.verdict_sentence
    assert s("HOST: 2 TREE(S)") == "2 trees on this host" and s("HOST: 1 TREE(S)") == "1 tree on this host"
    assert s("WATCHING HOST") == "Watching this host"
    assert s("WATCHING HOST (stopping)") == "Watching this host (stopping)"
    assert s("NO AGENT SEEN") == "No agent seen on this host" and s("NOTHING READ") == "Nothing was read"
    assert s("DOCTOR: 1 MISSING, 0 UNSURE") == "Checks: 1 missing, 0 unsure" and s("DOCTOR: all OK") == "Checks: all OK"
    assert s("SILENT for 70 s") == "Silent for 70 s" and s("CRASHED or stuck (31 s)") == "Crashed or stuck (31 s)"
    assert s("RULES: REFUSED") == "The change was refused" and s("FINISHED") == "The project watch finished"
    for word in list(app.SENTENCES) + ["CAPTURE FAILED", "SILENT for 5 s"]:
        out = s(word)
        assert out[0].isupper() or out[0].isdigit()
        assert out != out.upper(), out   # no all-capital words


def test_e2_not_a_clearance_beside_every_green_state_and_the_suppressed_count():
    n = app.verdict_note
    assert n("clean", result=True) == "Not a clearance."
    assert n("clean", 2, result=True) == "2 findings suppressed by the overlay. Not a clearance."
    assert n("clean", result=True, detail="x. Not a clearance.") == ""   # the detail says it already
    assert n("clean") == "" and n("alarm", 2, result=True) == "" and n(0, result=True) == "Not a clearance."
    assert app.watch_words(False) == "Not watching" and app.watch_words(True) == "Watching the host"
    assert app.watch_words(True, "/work/demo/") == "Watching the host and project demo"
    assert app.watch_words(False, "/work/demo") == "Watching project demo"


def test_redo_a13a_a_finding_is_an_item_pill_rule_sentence_where_and_never_none():
    entries = [{"rule_id": "DESTRUCT-CMD", "severity": "medium", "cited_seq": [5], "state": "settled",
                "history": False, "session_id": "s1", "summary": "rm at seq 5", "notice": None},
               {"rule_id": "SECRET-OUTPUT", "severity": "high", "cited_seq": [2, 3], "state": "pending",
                "history": False, "session_id": "s1", "summary": "a key", "notice": "sent"},
               {"rule_id": "NET-TOOL", "severity": "low", "cited_seq": [1], "state": "settled", "history": True,
                "session_id": "s0", "summary": "curl", "notice": None}]
    items = app.finding_items(entries)
    assert [(i[0], i[1], i[2]) for i in items] == [("high", "incomplete", "SECRET-OUTPUT"),
                                                   ("medium", "alarm", "DESTRUCT-CMD"), ("low", "note", "NET-TOOL")]
    assert items[1][3] == "Rm at seq 5" and items[1][4] == "session s1 \u00b7 seq 5 \u00b7 settled"
    assert "knocked: sent" in items[0][4] and all("None" not in i[4] for i in items)   # no "[None]"
    st = FakeHostWatch().state(0)
    st["host"] = dict(st["host"], findings=[{"rule_id": "NEW-AGENT", "severity": "high", "round": 2,
                                             "tree": "2100:claude:-", "summary": "claude", "notice": "sent",
                                             "run": "r1", "cited_seq": [12]}],
                      suspicions=[{"suspicion": 0.9, "round": 3, "tree": "7:x:-", "reasons": ["odd"], "notice": None,
                                   "backend": "fake", "model": "m", "trace": "t", "cited_seq": [5]}],
                      dark_notes=[{"text": "round 3: a note"}])
    items = app.host_finding_items(st)
    assert [(i[0], i[1], i[2]) for i in items] == [("high", "alarm", "NEW-AGENT"), ("suspicion", "note", "SUSPECT"),
                                                   ("note", "note", "NOTE")]
    assert items[0][4] == "round 2 \u00b7 claude pid 2100 \u00b7 knocked: sent \u00b7 cites run r1 seq 12"
    assert "knocked" not in items[1][4]                                   # absent: not printed
    look = {"lines": ["no agent seen (3 records, 1 holes). Not a clearance.", "AGENT-DARK codex footprint x: no tree"]}
    assert app.host_finding_items(None, look) == [("footprint", "alarm", "AGENT-DARK", "No tree", "codex footprint x")]


# --- E3: the round strip ----------------------------------------------------------------------------------

def _strip_state(rounds=40, **kw):
    st = FakeHostWatch().state(0)
    tail = [{"round": n, "late": False, "error": None, "nothing_read": False, "findings": [], "incomplete": []}
            for n in range(1, rounds + 1)]
    st["host"] = dict(st["host"], rounds=rounds, rounds_tail=tail, findings=[], reader=None)
    st["holes"] = []
    for key, value in kw.items():
        st["host"][key] = value
    return st


def test_e3_the_strip_cells_and_their_sentence():
    st = _strip_state(40)
    tail = st["host"]["rounds_tail"]
    for n in (5, 17):
        tail[n - 1]["findings"] = ["NEW-AGENT x"]
    st["host"]["findings"] = [{"round": 30, "rule_id": "HOST-RHYTHM"}]   # a finding the state lists by its round
    del tail[33 - 1]                                                     # round 33: no line, not read (held)
    cells = app.strip_cells(st, 40)
    assert len(cells) == 40 and [c[0] for c in cells] == list(range(1, 41))   # oldest left, newest right
    assert [c[0] for c in cells if c[1] == "finding"] == [5, 17, 30]
    assert [c for c in cells if c[1] == "unread"] == [(33, "unread", "not read")]   # drawn, never skipped (A3)
    assert app.strip_text(cells) == "40 rounds: 36 clean, 3 with findings, 1 not read"
    # as many as fit, the newest at the right
    assert [c[0] for c in app.strip_cells(st, 10)] == list(range(31, 41))
    assert app.strip_text(app.strip_cells(st, 10), 40) == (
        "The last 10 of 40 rounds: 9 clean, 0 with findings, 1 not read")


def test_e3_late_failed_partly_read_in_progress_and_before_the_watch():
    st = _strip_state(6)
    tail = st["host"]["rounds_tail"]
    tail[1]["late"] = True
    tail[2]["error"] = "OSError: denied"
    tail[3]["nothing_read"] = True
    tail[4]["incomplete"] = ["source proc-net not read"]
    cells = app.strip_cells(st, 10)
    assert [c[1] for c in cells] == ["before"] * 4 + ["clean", "unread", "unread", "unread", "unread", "clean"]
    assert [c[2] for c in cells[4:]] == ["", "late", "not read", "not read", "partly read", ""]
    assert app.strip_text(cells) == "6 rounds: 2 clean, 0 with findings, 2 not read, 1 partly read, 1 late"
    # round 7's reader is out: not drawn until it is back; once late, it is drawn amber
    st["host"]["rounds"], st["host"]["reader"] = 7, {"round": 7, "late": False}
    assert app.strip_cells(st, 10)[-1][0] == 6
    st["host"]["reader"] = {"round": 7, "late": True}
    assert app.strip_cells(st, 10)[-1] == (7, "unread", "late")
    # a round named by a reader hole is partly read even when its line looks clean
    st = _strip_state(3)
    st["holes"] = [{"kind": "lines-unread", "round": 2, "detail": "x"}]
    assert app.strip_cells(st, 3)[1] == (2, "unread", "partly read")
    # no host watch: a few quiet places, no rounds
    idle = app.strip_cells(None, 50)
    assert len(idle) == app.STRIP_IDLE and {c[1] for c in idle} == {"before"}
    assert app.strip_text(idle) == "No rounds yet" and app.strip_cells(None, 0) == []


def test_e3_rounds_older_than_the_kept_lines_are_not_drawn():
    n = host.ROUNDS_KEPT + 20
    st = _strip_state(n)
    st["host"]["rounds_tail"] = st["host"]["rounds_tail"][-host.ROUNDS_KEPT:]
    cells = app.strip_cells(st, 200)
    assert cells[0][0] == 21 and len(cells) == host.ROUNDS_KEPT and "before" not in {c[1] for c in cells}
    assert app.strip_text(cells, n).startswith("The last %d of %d rounds" % (host.ROUNDS_KEPT, n))


def test_e3_the_strip_is_drawn_on_a_canvas_in_the_window():
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    body = src.split("    def _draw_strip(self):", 1)[1].split("\n    def ", 1)[0]
    assert "strip_cells(" in body and "strip_text(" in body and "create_rectangle(" in body


# --- E4: doctor's rows, the holes, the pills ----------------------------------------------------------------

def test_e4_doctors_checks_are_rows_pill_name_sentence():
    lines = app.doctor_lines([("python", (True, "3.12 at /usr/bin/python3")), ("claude", (False, "not on PATH")),
                              ("trace", ("UNSURE", "not checked"))], ["moved"])
    assert app.check_rows(lines) == [("OK", "clean", "python", "3.12 at /usr/bin/python3"),
                                     ("missing", "alarm", "claude", "Not on PATH"),
                                     ("unsure", "incomplete", "trace", "Not checked"),
                                     ("note", "note", "", "Moved")]
    assert app.checks_state(lines) == ("Checks: 1 missing", "alarm")


def test_e4_could_not_see_lists_every_hole_never_dropped():
    holes = ["h%d" % i for i in range(40)]
    lines = app.seen_lines(holes, ["page: x"], ["round at open: a"])
    assert len(lines) == 42 and lines[-1] == "note: page: x" and app.seen_title(lines) == "Could not see (41), 1 note"


# --- E5: the Rules rows ---------------------------------------------------------------------------------------

def test_e5_rule_rows_switch_title_pills_steppers_and_the_filter(home):
    overlay.set_threshold("HOST-RHYTHM", "k", "4", str(home))
    panel = app.RulesPanel(home=str(home))
    items = {i["id"]: i for i in app.rule_items(panel.rows, panel.titles)}
    rhythm = items["HOST-RHYTHM"]
    assert rhythm["on"] and rhythm["pills"] == ["anchor", "high", "package"] and rhythm["title"]   # M7.18: high
    k = next(t for t in rhythm["steppers"] if t["name"] == "k")
    assert k["value"] == 4 and k["low"] <= 4 <= k["high"] and "YAML 3" in k["words"] and "measured" in k["words"]
    assert items["HOST-UNWATCHED"]["fixed"] and "fixed" in items["HOST-UNWATCHED"]["fixed"][0]
    assert app.rule_matches(rhythm, "rhythm") and app.rule_matches(rhythm, "ANCHOR thresholds")
    assert not app.rule_matches(rhythm, "signature") and app.rule_matches(rhythm, "")
    assert app.stepper_words({"low": 1, "high": 9, "value": 3, "yaml": 3}) == "1..9"


# --- E6: the scale, the two Windows calls ---------------------------------------------------------------------

@pytest.mark.parametrize("scale, rail, size", [(1.0, 184, (900, 600)), (1.25, 230, (1125, 750)),
                                               (1.5, 276, (1350, 900))])
def test_e6_every_pixel_size_through_one_scale_function(scale, rail, size):
    assert app.scaled(app.THEME["px"]["rail"], scale) == rail
    assert app.scaled(app.THEME["min_size"], scale) == size
    assert app.scaled(0, scale) == 0 and app.scaled(1, scale) >= 1
    assert app.screen_scale(96 * scale) == scale


def test_e6_the_scale_of_a_display():
    assert [app.screen_scale(d) for d in (96, 100.04, 120, 144, 192, 72, None)] == [1.0, 1.0, 1.25, 1.5, 2.0, 1.0, 1.0]


class FakeWin:
    def __init__(self, dpi=0, dwm=(0,), boom=None):
        self.dpi, self.dwm, self.boom, self.calls = dpi, list(dwm), boom, []

    def SetProcessDpiAwareness(self, value):
        self.calls.append(("dpi", value))
        if self.boom:
            raise self.boom
        return self.dpi

    def DwmSetWindowAttribute(self, hwnd, attribute, on):
        self.calls.append(("dwm", hwnd, attribute, on))
        if self.boom:
            raise self.boom
        return self.dwm.pop(0) if self.dwm else 0


def test_e6_dpi_awareness_is_declared_on_windows_only_and_a_failure_is_a_line():
    fake = FakeWin()
    assert app.declare_dpi_awareness("linux", fake) is None and fake.calls == []      # Linux never calls it
    assert app.declare_dpi_awareness("win32", fake) is None and fake.calls == [("dpi", 1)]
    assert app.declare_dpi_awareness("win32", FakeWin(dpi=app.E_ACCESSDENIED)) is None   # declared already
    assert app.declare_dpi_awareness("win32", FakeWin(dpi=-2147024809)) == (
        "DPI awareness was not declared: SetProcessDpiAwareness returned 0x80070057")
    assert app.declare_dpi_awareness("win32", FakeWin(boom=OSError("no shcore"))) == (
        "DPI awareness was not declared: OSError: no shcore")


def test_e6_the_title_bar_follows_dark_mode_on_windows_only():
    fake = FakeWin()
    assert app.dark_title_bar(77, "dark", "linux", fake) is None and fake.calls == []
    assert app.dark_title_bar(77, "light", "win32", fake) is None and fake.calls == []   # light: as it is
    assert app.dark_title_bar(77, "dark", "win32", fake) is None and fake.calls == [("dwm", 77, 20, True)]
    fake = FakeWin(dwm=(-2147024809, 0))                                                    # Windows 10 before 20H1
    assert app.dark_title_bar(77, "dark", "win32", fake) is None and [c[2] for c in fake.calls] == [20, 19]
    assert app.dark_title_bar(77, "dark", "win32", FakeWin(dwm=(1, 2))) == (
        "the title bar was not made dark: DwmSetWindowAttribute returned 0x00000001, 0x00000002")
    assert app.dark_title_bar(77, "dark", "win32", FakeWin(boom=OSError("no dwmapi"))).endswith("OSError: no dwmapi")


def test_e6_a_dpi_failure_is_a_line_in_the_log_and_the_window_opens_as_before(monkeypatch):
    monkeypatch.setattr(app, "declare_dpi_awareness", lambda platform=None, api=None: "DPI awareness was not"
                        " declared: OSError: x")
    monkeypatch.setattr(app, "display_problem", lambda environ, platform=None: None)
    opened = []

    class Root:
        def mainloop(self):
            opened.append("mainloop")

    class FakeTk:
        def Tk(self):
            return Root()

    class FakeWindow:
        def __init__(self, tk, root, controller, project, **kw):
            self.closed = True
            opened.append("window")
    monkeypatch.setattr(app, "Window", FakeWindow)
    out = io.StringIO()
    assert app.run(None, app.Options(None, None, 60, environ={}, no_notify=True), out=out, tk=FakeTk()) == 0
    assert opened == ["window", "mainloop"]
    assert "raqib app: DPI awareness was not declared: OSError: x\n" in out.getvalue()


def test_e6_the_ast_guard_admits_only_the_two_windows_calls():
    """A4: ctypes is imported in app.py inside _win_api only, and the only
    Win32 functions it names are SetProcessDpiAwareness and
    DwmSetWindowAttribute, reached through windll.shcore and windll.dwmapi."""
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="ascii"))
    users = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
             for n in ast.walk(f) if isinstance(n, ast.Import) and any(a.name == "ctypes" for a in n.names)}
    assert users == {"_win_api"}
    assert not any(isinstance(n, ast.ImportFrom) and (n.module or "").startswith("ctypes") for n in ast.walk(tree))
    fn = next(f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_win_api")
    chains = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute) and isinstance(n.value.value,
                                                                                              ast.Attribute):
            chains.add("%s.%s" % (n.value.attr, n.attr))
    assert chains == {"shcore.SetProcessDpiAwareness", "dwmapi.DwmSetWindowAttribute"}
    windll = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute)
              and n.value.attr == "windll"}
    assert windll == {"shcore", "dwmapi"}
    # every other module-level use goes through the two guarded functions; Linux never reaches _win_api
    callers = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
               for n in ast.walk(f) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_win_api"}
    assert callers == {"declare_dpi_awareness", "dark_title_bar"}
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    assert 'if (platform or sys.platform) != "win32":' in src.split("def declare_dpi_awareness", 1)[1][:800]
    assert 'if (platform or sys.platform) != "win32" or mode != "dark":' in src.split("def dark_title_bar", 1)[1][:800]
    title = src.split("    def _title_bar(self, api):", 1)[1].split("\n    def ", 1)[0]
    assert 'if sys.platform != "win32" and api is None:' in title
    run = src.split("\ndef run(", 1)[1].split("\ndef ", 1)[0]
    assert run.index("declare_dpi_awareness()") < run.index("root = tk.Tk()")   # before Tk starts


# --- the pictures the window draws ------------------------------------------------------------------------------

def test_e4_the_drawn_shapes_are_pure_and_their_edges_are_blends_of_two_theme_colours():
    rows = app.box(24, 24, 10, "#FFFFFF", "#F4F6FA", "#E1E6EE")
    assert len(rows) == 24 and all(len(r) == 24 for r in rows)
    assert rows[0][0] == "#f4f6fa" and rows[12][12] == "#ffffff" and rows[12][0] == "#e1e6ee"
    on = app.switch_shape(34, 18, True, "#2B59D9", "#FFFFFF", "#FFFFFF")
    off = app.switch_shape(34, 18, False, "#8F99AB", "#FFFFFF", "#FFFFFF")
    assert on[9][26] == "#ffffff" and on[9][8] != "#ffffff" and off[9][8] == "#ffffff" and off[9][26] != "#ffffff"
    ring = app.switch_shape(34, 18, True, "#2B59D9", "#FFFFFF", "#FFFFFF", ring="#2B59D9", margin=4)
    assert len(ring) == 26 and ring[13][0] != "#ffffff"             # the focus ring, drawn around it
    right, down = app.chevron(12, "right", "#18212F", "#F4F6FA"), app.chevron(12, "down", "#18212F", "#F4F6FA")
    assert right != down and len(right) == 12
    assert app.image_data([["#000000", "#ffffff"]]) == "{#000000 #ffffff}"


# --- the Tk window: only with tkinter and a display ------------------------------------------------------------

def _window(tkinter, root, home, tmp_path, **kw):
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)
    c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                       make_host=lambda: TkHost(), tee=kw.pop("tee", None))
    doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
    window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                        home=str(home), **kw)
    assert until(lambda: doctor.result() is not None and p.done(), 10)
    window.tick()
    return window, c


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_tk_e5_toggle_a_switch_step_a_threshold_filter_and_reset(home, tmp_path, monkeypatch, mode):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: mode)
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.withdraw()
        window.rules_tab.invoke()
        window.tick()
        assert window.screen == "rules" and window.rules_add_button.winfo_manager() == "pack"
        switch = window.rule_widgets[("NET-TOOL", "switch")]
        assert str(switch.cget("style")) == "Switch.TCheckbutton" and window.rule_vars["NET-TOOL"].get()
        switch.invoke()                                     # Space does what invoke does
        window.tick()
        assert not window.rule_vars["NET-TOOL"].get() and window.rules_note.cget("text") == "1 rule off"
        assert window.detail.cget("text").startswith("NET-TOOL off in ")   # the change, said in the verdict
        assert app.RulesPanel(home=str(home)).header() == "1 rule off: NET-TOOL"
        plus = window.rule_widgets[("HOST-RHYTHM", "k")]
        plus.invoke()                                       # k 3 -> 4: measured, then kept
        window.tick()
        rhythm = next(i for i, _ in window.rule_rows if i["id"] == "HOST-RHYTHM")
        assert next(t for t in rhythm["steppers"] if t["name"] == "k")["value"] == 4
        assert window.verdict_word == "RULES" and window.detail.cget("text").startswith("Threshold ok (measured)")
        window.rule_filter.set("rhythm")                    # the filter box keeps the matching rows
        window.tick()
        shown = [i["id"] for i, f in window.rule_rows if f.winfo_manager()]
        assert shown == ["HOST-RHYTHM"] and "1 shown" in window.rules_count.cget("text")
        window.rule_filter.set("")
        window.rule_widgets[("HOST-RHYTHM", "reset")].invoke()
        window.tick()
        assert window.rule_vars["HOST-RHYTHM"].get() and ("HOST-RHYTHM", "reset") not in window.rule_widgets
        window.overlay.invoke()                             # what the overlay applies, one click away
        assert window.overlay.panel.winfo_manager() and "1 rule off: NET-TOOL" in window.rules_text.get("1.0", "end")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_tk_e4_disclosures_closed_by_default_one_open_at_a_time_and_the_keyboard(home, tmp_path, monkeypatch, mode):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: mode)
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        for _ in range(5):
            root.update()
        visible = [d for d in window.disclosures if d.toggle.winfo_manager()]
        assert [d.name for d in visible] == ["seen", "checks", "options"]
        assert not any(d.is_open() for d in window.disclosures)       # closed until clicked
        for d in visible:
            d.invoke()                                                # Space does what invoke does
            assert d.is_open() and d.panel.winfo_manager()
            assert [x.name for x in window.disclosures if x.is_open()] == [d.name]   # one at a time
        window.options.invoke()
        assert not any(d.is_open() for d in window.disclosures)
        # Enter acts as Space does, on every button and every switch or disclosure
        for cls in ("TButton", "TCheckbutton"):
            assert root.bind_class(cls, "<Return>")
        # Tab reaches the rail, the primary action, each disclosure, the switch in the options
        window.options.invoke()
        root.update()
        seen, widget = [], root.focus_get() or root
        widget = window.host_tab
        for _ in range(60):
            seen.append(widget)
            widget = widget.tk_focusNext()
            if widget is None or widget is window.host_tab:
                break
        for want in (window.host_tab, window.project_tab, window.rules_tab, window.log_tab, window.host_button,
                     window.seen.toggle, window.checks.toggle, window.options.toggle, window.attach_box,
                     window.host_tree):   # REDO A-12: the table is in the walk, and draws its focus
            assert want in seen, want
        assert {"Table.box"} <= set(map(str, root.tk.call("ttk::style", "element", "names")))
        # focus is drawn: the focus pictures of the switch, the disclosure and the buttons exist
        p = app.THEME[mode]
        keys = set(window.images)
        assert ("turn", "right", p["accent"]) in keys and ("switch", True, p["accent"], None) in keys
        assert any(k[0] == "button" and k[1] == "Primary.TButton" and k[3] == p["accent"] for k in keys)
        assert any(k[0] == "button" and k[1] == "Rail.TButton" and k[3] == p["rail_accent"] for k in keys)
        names = root.tk.call("ttk::style", "element", "names")
        assert {"Switch.indicator", "Disclosure.indicator", "Primary.TButton.box", "Field.box"} <= set(map(str, names))
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_e6_the_window_at_scale_1_5_and_a_title_bar_that_fails_is_a_log_line(home, tmp_path, monkeypatch):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: "dark")
    window = None
    tee = io.StringIO()
    try:
        fake = FakeWin(dwm=(1, 1))
        window, c = _window(tkinter, root, home, tmp_path, scale=1.5, win_api=fake, tee=tee)
        root.withdraw()
        assert int(window.rail.cget("width")) == 276 and root.minsize() == (1350, 900)
        assert window.px(10) == 15 and int(window.strip.cget("height")) == 18   # px(cell + 2), REDO A-10
        assert [call[2] for call in fake.calls] == [20, 19] and isinstance(fake.calls[0][1], int)
        assert window.title_note.startswith("the title bar was not made dark")
        assert "raqib app: the title bar was not made dark: DwmSetWindowAttribute returned" in tee.getvalue()
        assert window.screen == "host" and window.verdict.cget("text") == "2 trees on this host"   # opens as before
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_e6_light_mode_does_not_touch_the_title_bar(home, tmp_path, monkeypatch):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: "light")
    window = None
    try:
        fake = FakeWin()
        window, c = _window(tkinter, root, home, tmp_path, win_api=fake)
        root.withdraw()
        assert fake.calls == [] and window.title_note is None
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_e7_files_are_ascii():
    for name in ("raqib/app.py", "tests/test_app_design.py"):
        (ROOT / name).read_bytes().decode("ascii")
    assert os.path.basename(__file__) == "test_app_design.py"
