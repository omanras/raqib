"""M8.1 REDO (ADR-0009 Amendment A, A-1..A-16): one test or more per ruling
(A-15). The helpers run without a display; the Tk tests (named test_tk_*)
are skipped without tkinter or a display, and tests/conftest.py ends what
each of them started (A-16)."""
from __future__ import annotations

import ast
import io
import re
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, host, notify, overlay, watch  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_app import TkSession, tk_or_skip, until  # noqa: E402
from test_app_host import CATALOG, RULES, FakeHostWatch, TkHost, inv  # noqa: E402
from test_watch import make_watch, rec, secret_call  # noqa: E402

WAIT = 30
# The event sequences Tk documents on Windows, macOS and X11 alike (bind(n), event(n), keysyms(n)): a keysym
# here is one every Tk knows; <<PrevWindow>> and <<TreeviewSelect>> are Tk's own virtual events.
PORTABLE = {"<Return>", "<KP_Enter>", "<Tab>", "<MouseWheel>", "<Button-4>", "<Button-5>", "<Configure>",
            "<FocusIn>", "<<PrevWindow>>", "<<TreeviewSelect>>"}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    overlay._MEASURED.clear()
    yield path
    overlay._MEASURED.clear()


# --- A-1: the window opens on Windows: every sequence it binds is in one table of portable ones ----------------

def _sequences(tree):
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and re.fullmatch(r"<<?[A-Za-z][\w-]*>>?", n.value)}


def test_redo_a1_every_sequence_the_window_binds_is_in_keys_and_portable():
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="ascii"))
    keys = {seq for seqs in app.KEYS.values() for seq in seqs}
    assert _sequences(tree) == keys, _sequences(tree) ^ keys   # no sequence outside the one table
    assert keys <= PORTABLE, keys - PORTABLE
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    for x11 in ("ISO_Left_Tab", "-type", "-zoomed", "XF86", "Super_", "cursor="):
        assert x11 not in src, x11
    # every bind / bind_all / bind_class takes its sequence from KEYS, never a literal
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in ("bind", "bind_all", "bind_class"):
            args = node.args[1:] if node.func.attr == "bind_class" else node.args
            assert args and not (isinstance(args[0], ast.Constant)), ast.dump(node)[:120]


def test_tk_redo_a1_every_sequence_of_keys_binds_on_this_tk():
    """On windows-latest this is the proof (Tk 8.6 refused ISO_Left_Tab there)."""
    tkinter, root = tk_or_skip()
    try:
        widget = tkinter.Text(root)
        for seqs in app.KEYS.values():
            for seq in seqs:
                widget.bind(seq, lambda e: None)
                root.bind_class("TButton", seq, lambda e: None)
                root.bind_all(seq, lambda e: None)
        assert root.tk.call("event", "info", "<<PrevWindow>>")   # Tk defines Shift-Tab for this platform
    finally:
        root.destroy()


# --- A-2: a running watch's verdict is the level of the code it would end with now ------------------------------

def _host_watch(home, feed):
    return host.HostWatch(feed, CATALOG, RULES, notify.Notifier(host.HOST, enabled=False, reason="t", host=True),
                          out=io.StringIO(), err=io.StringIO(), clock=_Clock(), wall=lambda: 1793700000.0,
                          home=str(home), platform="test", every=1.0)


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _empty():
    return dict(inv("linux"), candidates=[], act_roots=[], footprints=[], agent_dark=[], result="clean")


HOST_SCENARIOS = {
    "trees there at the start (clean)": [lambda: inv("linux"), lambda: inv("linux")],
    "a new agent (alarm)": [lambda: inv("benign/windows-desktop"), lambda: inv("windows")],
    "no agent seen (none-seen)": [_empty, _empty],
    "a round that read nothing (incomplete)": [_empty, lambda: dict(_empty(), records=0)],
    "a source not read (incomplete)": [lambda: dict(inv("linux"), incomplete=["source proc-net not read: x"])],
    "a reader that fails (incomplete)": ["fail", lambda: inv("linux")],
}


@pytest.mark.parametrize("name", sorted(HOST_SCENARIOS))
def test_redo_a2_host_code_now_is_the_code_the_host_watch_ends_with(home, name):
    feed = list(HOST_SCENARIOS[name])

    def reader():
        step = feed.pop(0) if len(feed) > 1 else feed[0]
        if step == "fail":
            raise OSError("denied")
        return step()
    w = _host_watch(home, reader)
    for _ in range(len(HOST_SCENARIOS[name])):
        w.tick(wait=WAIT)
        w.clock.t += 1.0
    now = host.code_now(w)
    _, code = w.finish()
    assert now == code, (name, now, code)
    assert {0, 1, 3} >= {code}


def _project_lines(kind):
    if kind == "a medium finding (alarm)":
        return [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1, input_meta={"command_head": "rm"}),
                rec(2, "post", 2, input_meta={"command_head": "rm"})]
    if kind == "a secret in an output (alarm)":
        return [rec(1, "session_start", 0, tool="-")] + secret_call(2, 1)
    if kind == "a quiet session (clean or notes)":
        return [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1), rec(2, "post", 2)]
    return []


@pytest.mark.parametrize("kind", ["a medium finding (alarm)", "a secret in an output (alarm)",
                                  "a quiet session (clean or notes)", "nothing read yet"])
def test_redo_a2_watch_code_now_is_the_code_the_project_watch_ends_with(tmp_path, kind):
    w, path, clock = make_watch(tmp_path)
    lines = _project_lines(kind)
    if lines:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for _ in range(3):
        w.step()
        clock.t += 1.0
    now = watch.code_now(w)
    w.finish()
    assert now == w.final_exit, (kind, now, w.final_exit)


@pytest.mark.parametrize("fixture", sorted(p.name for p in (ROOT / "tests" / "fixtures").glob("*.log")))
def test_redo_a2_watch_code_now_on_every_fixture_trace(tmp_path, fixture):
    w, path, clock = make_watch(tmp_path)
    path.write_bytes((ROOT / "tests" / "fixtures" / fixture).read_bytes())
    for _ in range(3):
        w.step()
        clock.t += 1.0
    now = watch.code_now(w)
    w.finish()
    assert now == w.final_exit, (fixture, now, w.final_exit)


def test_redo_a2_a_held_state_gives_no_code_and_the_level_rule():
    class Held:
        lock = threading.Lock()
    Held.lock.acquire()
    try:
        assert host.code_now(Held(), wait=0.01) is None and watch.code_now(Held(), wait=0.01) is None
    finally:
        Held.lock.release()
    assert [app.live_level(c, "WATCHING HOST", "clean") for c in (0, 1, 3)] == ["clean", "alarm", "incomplete"]
    assert app.live_level(None, "WATCHING", "clean") == "clean"          # not known yet: the view's
    assert app.live_level(0, "CRASHED or stuck (31 s)", "clean") == "alarm"
    assert app.so_far("Watching this host", 3) == "Watching this host: 3 findings so far"
    assert app.so_far("Watching the project", 0, 1) == "Watching the project: no finding so far, 1 suspicion"
    st = FakeHostWatch().state(0)
    st["host"] = dict(st["host"], findings=[{}, {}], source_findings=[{"history": False}, {"history": True}],
                      suspicions=[{}])
    assert app.host_counts(st) == (3, 1)


class CodeHost(TkHost):
    def __init__(self, code):
        super().__init__()
        self.running = type("R", (), {"watcher": type("W", (), {"lock": threading.Lock(), "code": code})()})()


@pytest.mark.parametrize("code, level", [(1, "alarm"), (3, "incomplete"), (0, "clean")])
def test_tk_redo_a2_a8_the_verdict_and_the_rail_say_the_code_the_watch_would_end_with(home, tmp_path, monkeypatch,
                                                                                       code, level):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(host, "code_now", lambda watcher, wait=0.2: watcher.code)
    window = None
    try:
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: CodeHost(code))
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        window.host_toggle()
        window.tick()
        assert window.pill.cget("text") == level and window.verdict.cget("text") == (
            "Watching this host: no finding so far")
        assert ("Not a clearance." in window.note.cget("text") + window.detail.cget("text")) == (level == "clean")
        window.show_rules()                 # A-8: the rail says it on every screen
        window.tick()
        rows = window.shown["rail_watches"]
        assert rows == [("Host", level, "no finding")]
        assert window.host_page_button.winfo_manager() == "pack"   # Open page on every screen
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-3: an overlay's hole is counted where every hole is --------------------------------------------------------

def test_redo_a3_the_overlays_holes(home):
    assert app.overlay_holes(None) == [] and app.overlay_holes({"file": "read", "refused": []}) == []
    info = {"file": "malformed", "path": "/h/.raqib/rules.yaml", "hole": "line 1: not a mapping",
            "refused": ["X: no such rule"], "user_refused": ["MINE: no fixtures"]}
    assert app.overlay_holes(info, "the rules could not be loaded: boom") == [
        "rules: the rules could not be loaded: boom",
        "rules overlay /h/.raqib/rules.yaml is not applied: line 1: not a mapping",
        "rules overlay: an entry refused at load: X: no such rule", "rules: a user rule refused at load: MINE: no fixtures"]
    (home / ".raqib").mkdir()
    (home / ".raqib" / "rules.yaml").write_text("rules: [not: an: overlay\n", encoding="ascii")
    panel = app.RulesPanel(home=str(home))
    holes = app.overlay_holes(panel.info, panel.error)
    assert len(holes) == 1 and holes[0].startswith("rules overlay ") and "is not applied" in holes[0]
    assert app.rail_rules(panel.info, panel.error) == ("No rule off; rules: 1 refused", "incomplete")


def test_tk_redo_a3_a_malformed_overlay_is_in_could_not_see_on_every_screen(home, tmp_path):
    tkinter, root = tk_or_skip()
    (home / ".raqib").mkdir()
    (home / ".raqib" / "rules.yaml").write_text("rules: [not: an: overlay\n", encoding="ascii")
    window = None
    try:
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0, home=str(home))
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession)
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        for show in (window.show_host, window.show_first, window.show_log, window.show_rules):
            show()
            window.tick()
            assert "is not applied" in window.seen_text.get("1.0", "end"), window.screen
        assert window.verdict_word == "RULES" and window.pill.cget("text") == "incomplete"
        assert "1 overlay line not applied" in window.detail.cget("text")
        assert window.rules_note.cget("text") == "No rule off; rules: 1 refused"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-4: the strip skips nothing ---------------------------------------------------------------------------------

def test_redo_a4_the_round_whose_reader_was_out_at_the_end_is_drawn_and_counted(home):
    gate = threading.Event()
    feed = [inv("linux")]

    def reader():
        if feed:
            return feed.pop(0)
        gate.wait(WAIT)
        return inv("linux")
    w = _host_watch(home, reader)
    try:
        w.tick(wait=WAIT)                    # round 1 read
        w.clock.t += 1.0
        w.tick()                             # round 2 starts, its reader stays out
        st = w.state(w.clock.t)
        assert app.strip_progress(st) == 2 and [c[0] for c in app.strip_cells(st, 5) if c[0]] == [1]
        assert app.strip_text(app.strip_cells(st, 5), app.strip_total(st), app.strip_progress(st)).endswith(
            "; round 2 in progress")
        w.finish()                           # the end: round 2's reader is out, a hole
        st = w.state(w.clock.t)
        cells = app.strip_cells(st, 5)
        assert cells[-1] == (2, "unread", "not read") and app.strip_progress(st) is None
        assert app.strip_total(st) == 2
        assert app.strip_text(cells, app.strip_total(st)) == "2 rounds: 1 clean, 0 with findings, 1 not read"
    finally:
        gate.set()
        if w.worker is not None:
            w.worker.thread.join(WAIT)


def test_redo_a4_m_counts_the_rounds_drawn_and_a_suspicion_is_said():
    st = FakeHostWatch().state(0)
    tail = [{"round": n, "late": False, "error": None, "findings": [], "incomplete": []} for n in range(1, 6)]
    st["host"] = dict(st["host"], rounds=6, rounds_tail=tail, reader={"round": 6, "late": False},
                      suspicions=[{"round": 4}, {"round": 5}])
    cells = app.strip_cells(st, 3)
    assert app.strip_total(st) == 5 and app.strip_progress(st) == 6 and [c[0] for c in cells] == [3, 4, 5]
    assert app.strip_text(cells, app.strip_total(st), app.strip_progress(st), app.strip_suspected(st)) == (
        "The last 3 of 5 rounds: 3 clean, 0 with findings, 0 not read, 2 with a suspicion; round 6 in progress")


# --- A-5..A-8 in the window ---------------------------------------------------------------------------------------

def _window(tkinter, root, home, tmp_path, **kw):
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)
    c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                       make_host=lambda: TkHost())
    lines = kw.pop("lines", [("python", (True, "3"))])
    doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, lines, []))
    window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                        home=str(home), **kw)
    assert until(lambda: doctor.result() is not None and p.done(), 10)
    window.tick()
    return window, c


def test_tk_redo_a5_a_failed_tick_takes_no_line_out_of_could_not_see(home, tmp_path, monkeypatch):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.withdraw()
        before = window.seen_text.get("1.0", "end").rstrip("\n").split("\n")
        assert len(before) == 14

        def broken():
            raise KeyError("x")
        monkeypatch.setattr(window, "_tick", broken)
        window.tick()
        window.tick()
        after = window.seen_text.get("1.0", "end").rstrip("\n").split("\n")
        assert after[:14] == before and "hole: the window failed to update: KeyError: 'x'" in after
        assert window.seen.title() == "Could not see (15)"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo_a6_a_refused_switch_goes_back_and_says_why_beside_its_row(home, tmp_path, monkeypatch):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.withdraw()
        window.show_rules()
        window.tick()

        def refuse(*a, **k):
            raise overlay.OverlayError("NET-TOOL cannot be switched here (a test's refusal)")
        monkeypatch.setattr(overlay, "set_status", refuse)
        window.rule_widgets[("NET-TOOL", "switch")].invoke()
        assert window.rule_vars["NET-TOOL"].get()                    # the rule's real state, at once
        assert window.rule_said == ("NET-TOOL", "REFUSED: NET-TOOL cannot be switched here (a test's refusal)")
        frame = dict((i["id"], f) for i, f in window.rule_rows)["NET-TOOL"]
        texts = [str(w.cget("text")) for w in frame.winfo_children() if w.winfo_class() == "TLabel"]
        assert "REFUSED: NET-TOOL cannot be switched here (a test's refusal)" in texts
        assert window.verdict_word == "RULES: REFUSED"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo_a12_a_typed_threshold_is_set_on_enter_and_one_doctor_level(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path, lines=[("trace", ("UNSURE", "not checked"))])
        root.deiconify()
        root.geometry("900x600")
        root.update()
        assert window.checks.title() == "Checks: 1 unsure"
        window.show_first()
        window.tick()
        assert window.pill.cget("text") == "incomplete"            # one doctor result, one level on both screens
        window.show_rules()
        window.tick()
        root.update()
        field = window.rule_widgets[("HOST-RHYTHM", "k=")]
        field.delete(0, "end")
        field.insert(0, "5")
        field.focus_force()
        root.update()
        field.event_generate("<Return>")
        root.update()
        k = next(t for t in next(i for i, _ in window.rule_rows if i["id"] == "HOST-RHYTHM")["steppers"]
                 if t["name"] == "k")
        assert k["value"] == 5 and window.detail.cget("text").startswith("Threshold ok (measured)")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-10: the fit is measured on what is drawn, the rail included ---------------------------------------------

def _rail_need(window):
    need = 0
    for child in window.rail.winfo_children():
        if child.winfo_manager() == "pack":
            pady = child.pack_info().get("pady", 0)
            pady = [int(x) for x in (pady if isinstance(pady, (tuple, list)) else str(pady).split())]
            need += child.winfo_reqheight() + (2 * pady[0] if len(pady) == 1 else sum(pady))
    return need


def _fit(root, window):
    root.update_idletasks()
    return (root.winfo_reqwidth(), root.winfo_reqheight(), _rail_need(window))


@pytest.mark.parametrize("mode", ["light", "dark"])
def test_tk_redo_a10_every_screen_and_each_disclosure_fits_900x600_rail_included(home, tmp_path, monkeypatch, mode):
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: mode)
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path, lines=[("hooks", (False, "not installed"))])
        root.withdraw()
        root.geometry("900x600")
        seen = {}
        for name, go in (("host", window.show_host), ("project", window.show_first), ("rules", window.show_rules),
                         ("log", window.show_log), ("host watching", lambda: (window.show_host(),
                                                                              window.host_toggle())),
                         ("watching", lambda: (window.show_first(), window.start()))):
            go()
            for _ in range(2):
                window.tick()
            seen[name] = _fit(root, window)
            for d in window.disclosures:
                if d.toggle.winfo_manager():
                    d.invoke()
                    window.tick()
                    seen["%s, %s open" % (name, d.name)] = _fit(root, window)
                    d.invoke()
        bad = {k: v for k, v in seen.items() if v[0] > 900 or v[1] > 600 or v[2] > 600}
        assert bad == {}, bad
        assert len(seen) >= 6 + 7    # every screen, and each disclosure open on each screen that has it
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-11: the trees table ----------------------------------------------------------------------------------------

def test_redo_a11_cells_cut_with_an_ellipsis_state_words_kept_first_seen_as_a_time():
    measure = len   # one pixel per character
    assert app.fit_cell("environment-manager", 8, measure) == "environ" + app.ELLIPSIS
    assert app.fit_cell("unknown (new)", 10, measure) == "unk" + app.ELLIPSIS + " (new)"
    assert app.fit_cell("named, benign image (history, quiet)", 20, measure).endswith(app.ELLIPSIS + " (history, quiet)")
    assert app.fit_cell("os", 8, measure) == "os"
    assert app.first_seen_text("2026-11-10T09:12:04Z", "2026-11-10") == "09:12:04"
    assert app.first_seen_text("2026-11-09T23:59:59Z", "2026-11-10") == "2026-11-09 23:59"
    assert app.first_seen_text("-", "2026-11-10") == "-"
    assert app.column_widths(100, [10, 10, 10], [50, 40, 10], (1, 0, 2)) == [50, 40, 10]
    assert app.column_widths(60, [10, 10, 10], [50, 40, 10], (1, 0, 2)) == [10, 40, 10]   # the first in order first
    assert app.column_widths(20, [10, 10], [50, 50]) == [10, 10]


def test_tk_redo_a11_at_900x600_no_heading_and_no_state_word_is_cut(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        for _ in range(4):
            root.update()
            window.tick()
        tree = window.host_tree
        assert tree.get_children()
        for cid, heading, _, _, _ in app.TREE_COLUMNS:
            assert int(tree.column(cid, "width")) >= window.font_meta_bold.measure(heading) + window.px(16), cid
        total = sum(int(tree.column(c[0], "width")) for c in app.TREE_COLUMNS)
        assert total >= tree.winfo_width() - window.px(40)        # the columns take the card's whole width
        for iid in tree.get_children():
            values = tree.item(iid, "values")
            assert values[2] in ("named", "unknown", "benign") or values[2].endswith(")")   # kind whole or flags kept
            assert len(str(values[6])) in (8, 16)                                  # a time, or a date and minute
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-12: the guard, the pairs ---------------------------------------------------------------------------------------

def test_redo_a12_the_guard_refuses_every_other_form_of_ctypes_and_the_calls_declare_their_types():
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="ascii"))
    win = next(f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_win_api")
    inside = {id(n) for n in ast.walk(win)}
    for n in ast.walk(tree):
        if id(n) in inside:
            continue
        if isinstance(n, (ast.Attribute, ast.Name)):
            name = n.attr if isinstance(n, ast.Attribute) else n.id
            assert name not in ("windll", "oledll", "WinDLL", "OleDLL", "CDLL", "PyDLL", "LibraryLoader", "cdll",
                                "__import__"), name
        if isinstance(n, ast.Constant) and n.value in ("ctypes", "_ctypes"):
            raise AssertionError("ctypes named outside _win_api")
    sets = {(t.value.id, t.attr) for n in ast.walk(win) if isinstance(n, ast.Assign) for t in
            (n.targets[0].elts if isinstance(n.targets[0], ast.Tuple) else n.targets)
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)}
    assert sets == {("fn", "argtypes"), ("fn", "restype")}
    assert (ROOT / "raqib" / "app.py").read_text(encoding="ascii").count("fn.restype") == 2


def test_redo_a12_theme_pairs_hold_what_the_styles_draw():
    pairs = set(app.THEME["pairs"])
    assert {("muted", "line"), ("accent", "hover"), ("accent", "chip"), ("muted", "field")} <= pairs


# --- A-13: badges, panels, quiet ----------------------------------------------------------------------------------

def test_redo_a13d_a_quiet_tree_is_said_quiet_never_gone():
    assert app.tree_kind({"named": False, "quiet": True, "quiet_round": 7, "present": False}) == "unknown (quiet)"
    assert app.tree_kind({"named": True, "present": False}) == "named (gone)"
    st = FakeHostWatch().state(0)
    st["host"] = dict(st["host"], trees=[{"key": [9, "x", None], "pid": 9, "image": "x", "named": True,
                                          "quiet": True, "quiet_round": 4, "present": False}])
    (row,) = app.host_watch_view(st)["rows"]
    assert row[2] == "named (quiet)" and app.row_level(row) == "note"


def test_tk_redo_a13_badges_quiet_when_clean_panels_as_tall_as_the_screen_gives(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        lines = [("python", (True, "3"))] * 6 + [("trace", ("UNSURE", "not checked")), ("host", (True, "ok"))]
        window, c = _window(tkinter, root, home, tmp_path, lines=lines)
        root.deiconify()
        root.geometry("1100x720")
        root.update()
        window.host_toggle()
        for _ in range(3):
            window.tick()
            root.update()
        badges = [w for w in window.host_badges.winfo_children() if hasattr(w, "level")]
        clean = [w for w in badges if w.level == "clean"]
        assert clean and all(w.winfo_class() == "Label" and w.cget("text") not in app.LEVEL_WORDS for w in clean)
        assert all(str(w.cget("foreground")) == window.palette["muted"] for w in clean)
        assert all(w.winfo_class() == "TFrame" for w in badges if w.level != "clean")
        window.seen.invoke()
        root.update()
        assert int(window.seen_text.cget("height")) > 2               # not two lines: what the screen can give
        window.checks.invoke()
        root.update()
        named = window.checks_rows.named_line
        assert named == "7.0" and window.checks_rows.bbox(named) is not None   # the line its title names, in view
        root.geometry("900x600")
        root.update()
        root.update_idletasks()
        assert root.winfo_reqheight() <= 600
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- A-16: a Tk test ends what it started -------------------------------------------------------------------------

def test_tk_redo_a16_after_its_teardown_no_thread_of_the_window_is_alive(home, tmp_path):
    tkinter, root = tk_or_skip()
    import conftest
    before = set(threading.enumerate())
    gate = threading.Event()
    window = None
    try:
        p = app.HostProbe(lambda: (gate.wait(WAIT), inv("linux"))[1], CATALOG, 20.0)
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        assert [t for t in threading.enumerate() if t not in before]   # the look's reader is out
    finally:
        gate.set()
        if window is not None:
            window.destroy()
        else:
            root.destroy()
    assert conftest.end_tk_test(before) == []
    assert not [t for t in threading.enumerate() if t not in before and t.is_alive()]
