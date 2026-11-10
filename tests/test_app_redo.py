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

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

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
def test_redo_b4_the_host_state_says_the_code_the_host_watch_ends_with(home, name):
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
    now = w.state(w.clock.t)["code_so_far"]   # REDO B-4: written by the watch, in its state
    _, code = w.finish()
    assert now == code, (name, now, code)


@pytest.mark.parametrize("name", host_fixtures.HOSTDATA_NAMES + ["linux", "windows"])
def test_redo_b4_on_every_host_fixture(home, name):
    w = _host_watch(home, lambda: host_fixtures.inventory(name.split(":")[0], CATALOG))
    w.tick(wait=WAIT)
    w.clock.t += 1.0
    w.tick(wait=WAIT)
    now = w.state(w.clock.t)["code_so_far"]
    _, code = w.finish()
    assert now == code, (name, now, code)


def test_redo_b4_with_sources_attached(home):
    """A host watch with an os source followed on its trees (test_host_sources' FakeFollow): the field is its
    code there too."""
    import test_host_sources as ths
    w, clock = ths.make_host(home, ["windows", "windows"], sysmon=ths.SYSMON, os_follow=ths.FakeFollow())
    ths.rounds(w, clock, 2)
    assert w.sources
    now = w.state(clock())["code_so_far"]
    _, code = w.finish()
    assert now == code and isinstance(now, int)


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
def test_redo_b4_the_project_state_says_the_code_the_project_watch_ends_with(tmp_path, kind):
    w, path, clock = make_watch(tmp_path)
    lines = _project_lines(kind)
    if lines:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for _ in range(3):
        w.step()
        clock.t += 1.0
    with w.lock:
        now = w.state(clock())["code_so_far"]
    w.finish()
    assert now == w.final_exit, (kind, now, w.final_exit)


@pytest.mark.parametrize("fixture", sorted(p.name for p in (ROOT / "tests" / "fixtures").glob("*.log")))
def test_redo_b4_on_every_fixture_trace(tmp_path, fixture):
    w, path, clock = make_watch(tmp_path)
    path.write_bytes((ROOT / "tests" / "fixtures" / fixture).read_bytes())
    for _ in range(3):
        w.step()
        clock.t += 1.0
    with w.lock:
        now = w.state(clock())["code_so_far"]
    w.finish()
    assert now == w.final_exit, (fixture, now, w.final_exit)


def test_redo_b2_b5_the_level_rule_and_its_words():
    assert [app.live_level(c, "WATCHING HOST") for c in (0, 1, 3)] == ["clean", "alarm", "incomplete"]
    assert app.live_level(None, "WATCHING") == "incomplete"            # B-2: not known is never clean
    assert app.live_level(0, "CRASHED or stuck (31 s)") == "alarm"
    assert app.live_level(1, "WATCHING", lines=0) == "incomplete"      # B-5: the window's one softening
    assert app.live_level(1, "SILENT for 70 s", lines=0) == "alarm"
    assert app.live_cause(None, 0) == "not judged yet" and app.live_cause(1, 0, lines=0) == "no line read yet"
    assert app.live_cause(1, 0, 0, 2) == "2 holes" and app.live_cause(1, 2) == "" and app.live_cause(1, 0, 1) == ""
    assert app.so_far("Watching this host", 3) == "Watching this host: 3 findings so far"
    assert app.so_far("Watching the project", 0, 0, "1 hole") == "Watching the project: no finding so far; 1 hole"
    assert app.so_far("Watching the project", 0, 1) == "Watching the project: no finding so far, 1 suspicion"
    st = FakeHostWatch().state(0)
    st["host"] = dict(st["host"], findings=[{}, {}], source_findings=[{"history": False}, {"history": True}],
                      suspicions=[{}])
    assert app.host_counts(st) == (3, 1)
    assert [i[2] for i in app.host_finding_items(dict(st, host=dict(st["host"], findings=[], suspicions=[],
            source_findings=[{"rule_id": "NET-TOOL", "severity": "medium", "summary": "curl", "trace": "t.jsonl",
                              "cited_seq": [4], "tree": "7:x:-", "history": False}])))] == ["NET-TOOL"]


class CodeHost(TkHost):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def state(self):
        return dict(super().state(), code_so_far=self.code)


@pytest.mark.parametrize("code, level", [(1, "alarm"), (3, "incomplete"), (0, "clean")])
def test_tk_redo_a2_a8_the_verdict_and_the_rail_say_the_code_the_watch_would_end_with(home, tmp_path, monkeypatch,
                                                                                       code, level):
    tkinter, root = tk_or_skip()
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
            "Watching this host: no finding so far" + ("; an alarm of the watch (its report says)" if code == 1
                                                       else ""))   # B-5: the words say why
        assert ("Not a clearance." in window.note.cget("text") + window.detail.cget("text")) == (level == "clean")
        window.show_rules()                 # A-8: the rail says it on every screen
        window.tick()
        rows = window.shown["rail_watches"]
        assert rows == [("Host", level, "no finding" + ("; an alarm of the watch (its report says)" if code == 1
                                                       else ""))]
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


def _biggest(root, n=5):
    """REDO B-1: the widgets that ask for the most width and height (class, Tk path, first words of their text)."""
    out = []

    def walk(w):
        for c in w.winfo_children():
            if c.winfo_manager():
                try:
                    text = str(c.cget("text"))[:40]
                except Exception:
                    text = ""
                out.append((c.winfo_reqwidth(), c.winfo_reqheight(), c.winfo_class(), str(c), text))
                walk(c)
    walk(root)
    wide = sorted(out, key=lambda x: -x[0])[:n]
    tall = sorted(out, key=lambda x: -x[1])[:n]
    return "widest: %s; tallest: %s" % (wide, tall)


def _fit(root, window):
    root.update()   # the wraps follow the widths they were given (Configure events), as in a running window
    root.update_idletasks()
    at = (root.winfo_reqwidth(), root.winfo_reqheight(), _rail_need(window))
    root.geometry("")           # REDO B-1: the window's natural size, as a withdrawn root on Windows takes it
    for _ in range(2):
        root.update_idletasks()
        window.tick()
    natural = (root.winfo_reqwidth(), root.winfo_reqheight())
    root.geometry("900x600")
    for _ in range(2):
        root.update_idletasks()
        window.tick()
    bad = max(at[0], natural[0]) > 900 or max(at[1], natural[1]) > 600 or at[2] > 600
    return at + natural + ((_biggest(root),) if bad else ())


@pytest.mark.parametrize("font", ["the theme's", "DejaVu Sans"])
@pytest.mark.parametrize("mode", ["light", "dark"])
def test_tk_redo_a10_every_screen_and_each_disclosure_fits_900x600_rail_included(home, tmp_path, monkeypatch, mode,
                                                                                 font):
    """REDO A-10, B-1, B-8: every screen, the finished ones too, in both modes, each disclosure open on each
    screen that has it, at 900x600 and at the window's natural size, the rail included; once more with a font
    wider than Inter (DejaVu Sans) forced through pick_font. On a failure the message names the five widgets
    that ask for the most width and height."""
    tkinter, root = tk_or_skip()
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: mode)
    if font != "the theme's":
        fonts = dict(app.THEME["fonts"], ui=(font,), display=(font,), mono=("DejaVu Sans Mono",))
        monkeypatch.setitem(app.THEME, "fonts", fonts)
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path, lines=[("hooks", (False, "not installed")),
                                                                  ("trace", ("UNSURE", "not checked"))])
        root.withdraw()
        root.geometry("900x600")
        seen = {}

        def finish_project():
            window.show_project()
            c.stop_project("test")
        for name, go in (("host", window.show_host), ("project", window.show_first), ("rules", window.show_rules),
                         ("log", window.show_log), ("host watching", lambda: (window.show_host(),
                                                                              window.host_toggle())),
                         ("host finished", window.host_toggle),
                         ("watching", lambda: (window.show_first(), window.start())),
                         ("project finished", finish_project)):
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
        bad = {k: v for k, v in seen.items() if len(v) > 5}
        assert bad == {}, bad
        assert len(seen) == 8 + 3 + 1 + 2 + 1 + 3 + 3 + 1 + 1   # every screen; each of its disclosures open
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
    # REDO B-7: the needs first (in their order), then the wants: a severity is given its width before an image
    assert app.column_widths(60, [10, 10, 10], [50, 40, 10], (0, 1, 2), ([10, 25, 10],), (1, 0, 2)) == [25, 25, 10]
    assert app.column_widths(40, [10, 10, 10], [50, 40, 10], (0, 1, 2), ([10, 25, 10], [10, 40, 10])) == [10, 20, 10]


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
        window.tick()                                                 # the window's next tick follows the size
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


# === REDO 2 (ADR-0009 Amendment B, B-1..B-10): the tests for the behaviour each ruling adds (B-10) ===============

def _win(tkinter, root, home, tmp_path, make_host=None, make_session=None, reader=None, lines=None):
    """A window over fakes: the look's reader, the host watch, the project watch, the doctor's lines."""
    p = app.HostProbe(reader or (lambda: inv("linux")), CATALOG, 20.0, home=str(home))
    c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=make_session or TkSession,
                       make_host=make_host or (lambda: TkHost()))
    doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, lines or [("python", (True, "3"))], []))
    window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                        home=str(home))
    root.withdraw()
    assert until(lambda: doctor.result() is not None and p.done(), 10)
    window.tick()
    return window, c


def _said(window):
    return window.pill.cget("text"), window.verdict.cget("text"), "%s %s" % (window.note.cget("text"),
                                                                            window.detail.cget("text"))


class StateSession(TkSession):
    """A project watch whose state the test sets (st); its final report clean, exit 0, when stopped."""

    def __init__(self, project):
        super().__init__(project)
        self.st = dict(TkSession.state(self), findings=[])

    def state(self):
        return dict(self.st)

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase, self.final_text = "finished", "Raqib watch\nRESULT: CLEAN (exit 0)\n"

    def snapshot(self):
        return dict(super().snapshot(), final_exit=0 if self.final_text else None)


class StateHost(TkHost):
    """A host watch whose state the test gives (a real HostWatch's, B-6, B-7)."""

    def __init__(self, st):
        super().__init__()
        self.st = st

    def state(self):
        return dict(self.st)


def test_tk_redo2_b2_b5_the_project_path_with_a_known_code_and_without_one(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path, make_session=StateSession)
        window.start()
        s = c.session
        s.st["code_so_far"] = None                       # the first ask: no code known yet
        window.tick()
        assert _said(window)[:2] == ("incomplete", "Watching the project: no finding so far; not judged yet")
        assert window.shown["rail_watches"] == [("Project", "incomplete", "no finding; not judged yet")]
        s.st["code_so_far"] = 0                          # a known code: the watch's own rule says clean
        window.tick()
        pill, sentence_, beside = _said(window)
        assert (pill, sentence_) == ("clean", "Watching the project: no finding so far") and "Not a clearance." in beside
        s.st["code_so_far"] = None                       # not known now: the last known code, never a guess
        window.tick()
        assert _said(window)[:2] == ("clean", "Watching the project: no finding so far")
        s.st.update(code_so_far=1, holes=[{"kind": "gap", "detail": "no line for 70 s", "at": "T"}])
        window.tick()                                    # code 1 with no finding: the sentence names the hole
        pill, sentence_, beside = _said(window)
        assert (pill, sentence_) == ("alarm", "Watching the project: no finding so far; 1 hole")
        assert "Not a clearance." not in beside
        s.st.update(code_so_far=1, lines=0, holes=[])    # B-5: the window's one softening
        window.tick()
        assert _said(window)[:2] == ("incomplete", "Watching the project: no finding so far; no line read yet")
        s.st.update(code_so_far=1, lines=2, findings=TkSession("x").state()["findings"])
        window.tick()
        assert _said(window)[:2] == ("alarm", "Watching the project: 1 finding so far")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_b3_an_overlay_hole_decides_the_rules_verdict_after_a_change(home, tmp_path):
    (home / ".raqib").mkdir()
    (home / ".raqib" / "rules.yaml").write_text("rules:\n  NO-SUCH-RULE:\n    status: \"off\"\n", encoding="ascii")
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path)
        window.show_rules()
        window.tick()
        assert window.pill.cget("text") == "incomplete" and "1 overlay line not applied" in window.detail.cget("text")
        window.rule_widgets[("NET-TOOL", "switch")].invoke()   # a change that succeeds
        assert window.rules_panel.level == "clean" and window.rules_panel.message   # its word is said...
        assert window.pill.cget("text") == "incomplete"                          # ...the hole decides the level
        assert "1 overlay line not applied" in window.detail.cget("text")
        assert window.verdict_word == "RULES"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def _source_state(home):
    """A real host watch's state with one source finding and no tree finding (the review's F5 case)."""
    import test_host_sources as ths
    w, clock = ths.make_host(home, ["benign/linux-desktop", "linux-agent"])
    ths.rounds(w, clock, 2)
    st = w.state(clock())
    w.finish()
    assert app.host_counts(st) == (1, 0) and not st["host"].get("findings") and st["code_so_far"] == 1
    return st


def test_tk_redo2_b6_one_count_and_a_source_finding_is_an_item_with_its_cite(home, tmp_path):
    st = _source_state(home)
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path, make_host=lambda: StateHost(st))
        window.host_toggle()
        window.tick()
        assert window.verdict.cget("text") == "Watching this host: 1 finding so far"
        assert window.shown["rail_watches"] == [("Host", "alarm", "1 finding")]
        assert window.findings_title.cget("text") == "Findings (1)"
        assert c.tip.endswith(", 1 findings")                          # the tray's count, the same list
        text = window.host_text.get("1.0", "end")
        cite = st["host"]["source_findings"][0]
        assert "NET-TOOL" in text and "source %s" % cite["trace"] in text and "seq 1" in text
        assert window.counts["host"] == app.host_counts(st)
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_redo2_b6_one_function_counts_a_project_watch_for_every_place():
    st = TkSession("x").state()
    assert app.project_count(st) == 1 and app.project_count(dict(st, findings=[{}, "x", None])) == 1
    assert app.project_count(None) == 0 and app.project_count({}) == 0


def test_tk_redo2_b7_with_each_disclosure_open_the_table_keeps_the_card_width_and_its_words(home, tmp_path):
    st = _source_state(home)
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path, make_host=lambda: StateHost(st),
                         lines=[("hooks", (False, "not installed")), ("trace", ("UNSURE", "not checked"))])
        root.deiconify()
        root.geometry("900x600")
        window.host_toggle()
        heads = [x[0] for x in app.TREE_COLUMNS]
        opened = []
        for d in [None] + [d for d in window.disclosures if d.toggle.winfo_manager()]:
            if d is not None:
                d.invoke()
                opened.append(d.name)
            for _ in range(3):
                root.update()
                window.tick()
            tree = window.host_tree
            total = sum(int(tree.column(x, "width")) for x in heads)
            assert tree.winfo_width() - window.px(14) <= total <= tree.winfo_width(), (d and d.name, total,
                                                                                       tree.winfo_width())
            assert tree.get_children()
            for iid in tree.get_children():
                shown, row = tree.item(iid, "values"), window.payload["host"][iid][0]
                full = app.tree_values(row)
                kind, findings = heads.index("kind"), heads.index("findings")
                assert str(shown[findings]) == str(full[findings]), (shown, full)   # a severity word, whole
                flags = str(full[kind]).partition(" (")[2]
                assert str(shown[kind]).endswith(" (" + flags) if flags else str(shown[kind]) == str(full[kind])
                assert app.ELLIPSIS not in str(shown[heads.index("pid")])
            if d is not None:
                d.invoke()
        assert opened == ["seen", "checks", "options"]
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_b7_a_panel_grows_with_its_lines_and_is_scrolled_only_when_it_opens(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        lines = [("python", (True, "3"))] * 7 + [("trace", ("UNSURE", "not checked"))]
        window, c = _win(tkinter, root, home, tmp_path, reader=lambda: dict(inv("linux"), holes=["one"]),
                         lines=lines)
        root.deiconify()
        root.geometry("1100x720")
        root.update()
        window.seen.invoke()
        root.update()
        window.tick()
        before = int(window.seen_text.cget("height"))
        for n in range(4):
            c.hole("a hole that arrives later, number %d" % n)
        window.tick()
        root.update()
        assert int(window.seen_text.cget("height")) == before + 4      # the panel grew with the lines
        window.checks.invoke()                                          # opens: scrolled to its named line once
        root.update()
        text = window.checks_rows
        assert text.named_line == "8.0" and text.bbox("8.0") is not None
        text.yview_moveto(0)                                            # the person scrolls back to the top
        root.update()
        root.geometry("1000x700")                                       # a resize, then ticks
        for _ in range(3):
            root.update()
            window.tick()
        assert text.yview()[0] == 0.0                                   # left where the person put it
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_b7_a_finished_host_watchs_holes_are_in_could_not_see(home, tmp_path):
    hole = {"kind": "reader-out", "detail": "round 2's reader was out at the end", "at": "2026-11-11T10:00:00Z"}
    st = dict(FakeHostWatch().state(0), holes=[hole], code_so_far=3)
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path, make_host=lambda: StateHost(st))
        window.host_toggle()
        window.tick()
        window.host_toggle()                       # stopped: the final report is shown
        window.tick()
        assert c.host_view().get("final")
        lines = window.shown["seen_lines"]
        assert "hole: " + app.hole_line(hole) in lines
        assert window.seen.title() == app.seen_title(lines) and lines.count("hole: " + app.hole_line(hole)) == 1
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo_c3_every_green_state_of_both_screens(home, tmp_path):
    """REDO C-3, B-8 (the test test_app_look's docstring cites): each green state of the host screen and of
    the project screen says "Not a clearance." beside its pill."""
    from test_app_host import empty_inv
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path, reader=empty_inv, make_session=StateSession,
                         make_host=lambda: CodeHost(0))
        said = {}
        window.show_host()
        window.tick()
        said["the look at open"] = _said(window)
        window.host_toggle()
        window.tick()
        said["the host watch, clean so far"] = _said(window)
        window.host_toggle()
        window.tick()
        said["the host watch, finished exit 0"] = _said(window)
        window.show_first()
        window.start()
        c.session.st["code_so_far"] = 0
        window.tick()
        said["the project watch, clean so far"] = _said(window)
        c.stop_project("test")
        window.tick()
        said["the project watch, finished exit 0"] = _said(window)
        for name, (pill, _, beside) in said.items():
            assert pill == "clean" and "Not a clearance." in beside, (name, pill, beside)
        assert len(said) == 5
        assert "suppressed" not in said["the project watch, clean so far"][2]
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


@pytest.mark.parametrize("typed, word", [("abc", "must be a whole number"), ("", "must be a whole number"),
                                         ("101", "outside its bounds"), ("0", "outside its bounds")])
def test_tk_redo2_b8_a_typed_value_refused_goes_back_and_says_why_beside_its_row(home, tmp_path, typed, word):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path)
        window.show_rules()
        window.tick()
        field = window.rule_widgets[("HOST-RHYTHM", "k=")]
        was = field.get()
        field.delete(0, "end")
        field.insert(0, typed)
        window.rules_threshold("HOST-RHYTHM", "k", field.get().strip(), "k=")   # what Enter calls (KEYS act)
        assert window.verdict_word == "RULES: REFUSED" and word in window.rule_said[1], window.rule_said
        assert window.rule_widgets[("HOST-RHYTHM", "k=")].get() == was           # the rule's real value, back
        frame = dict((i["id"], f) for i, f in window.rule_rows)["HOST-RHYTHM"]
        texts = [str(w.cget("text")) for w in frame.winfo_children() if w.winfo_class() == "TLabel"]
        assert window.rule_said[1] in texts
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_redo2_b8_a_refused_step_goes_back_and_says_why_beside_its_row(home, tmp_path, monkeypatch):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _win(tkinter, root, home, tmp_path)
        window.show_rules()
        window.tick()
        was = window.rule_widgets[("HOST-RHYTHM", "k=")].get()

        def refuse(*a, **k):
            raise overlay.OverlayError("HOST-RHYTHM k refused: its fixture fails at this value (a test's refusal)")
        monkeypatch.setattr(overlay, "set_threshold", refuse)
        window.rule_widgets[("HOST-RHYTHM", "k")].invoke()                       # the plus step
        assert window.verdict_word == "RULES: REFUSED"
        assert window.rule_said == ("HOST-RHYTHM", "REFUSED: threshold refused: HOST-RHYTHM k refused: its fixture"
                                                   " fails at this value (a test's refusal)")   # RulesPanel's words
        assert window.rule_widgets[("HOST-RHYTHM", "k=")].get() == was
        frame = dict((i["id"], f) for i, f in window.rule_rows)["HOST-RHYTHM"]
        assert window.rule_said[1] in [str(w.cget("text")) for w in frame.winfo_children()
                                       if w.winfo_class() == "TLabel"]
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


# --- B-9: the ctypes guard; a refused user rule said as refused, not off ------------------------------------------

ALLOWED_CTYPES = {"windll", "c_int", "c_long", "c_void_p", "c_uint", "byref", "sizeof"}
ALLOWED_CALLS = {("shcore", "SetProcessDpiAwareness"), ("dwmapi", "DwmSetWindowAttribute")}


def _ctypes_refusals(tree):
    """Every form of ctypes outside the two declared calls: an import of it outside _win_api, getattr on it,
    pythonapi, a ctypes attribute or a windll call not in the lists."""
    win = [f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_win_api"]
    inside = {id(n) for f in win for n in ast.walk(f)}
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import) and any(a.name.split(".")[0] in ("ctypes", "_ctypes") for a in n.names) or (
                isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in ("ctypes", "_ctypes")):
            if id(n) not in inside or isinstance(n, ast.ImportFrom):
                out.append("import of ctypes at line %d" % n.lineno)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "__import__") \
                and n.args and isinstance(n.args[0], (ast.Name, ast.Attribute, ast.Constant)):
            first = n.args[0]
            name = first.id if isinstance(first, ast.Name) else getattr(first, "attr", getattr(first, "value", ""))
            if name in ("ctypes", "_ctypes", "windll") or n.func.id == "__import__":
                out.append("getattr on ctypes at line %d" % n.lineno)
        if isinstance(n, ast.Attribute) and n.attr == "pythonapi" or isinstance(n, ast.Name) and n.id == "pythonapi":
            out.append("pythonapi at line %d" % n.lineno)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "ctypes" \
                and n.attr not in ALLOWED_CTYPES:
            out.append("ctypes.%s at line %d" % (n.attr, n.lineno))
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Attribute) and isinstance(n.value.value,
                                                                                              ast.Attribute) \
                and n.value.value.attr == "windll" and (n.value.attr, n.attr) not in ALLOWED_CALLS:
            out.append("windll.%s.%s at line %d" % (n.value.attr, n.attr, n.lineno))
    return out


def test_redo2_b9_the_guard_refuses_getattr_on_ctypes_and_pythonapi_and_app_has_neither():
    assert _ctypes_refusals(ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="ascii"))) == []
    for bad in ("import ctypes\nx = getattr(ctypes, 'windll')\n",
                "def _win_api():\n    import ctypes\n    return getattr(ctypes, 'windll')\n",
                "def _win_api():\n    import ctypes\n    return ctypes.pythonapi\n",
                "def _win_api():\n    import ctypes\n    return ctypes.CDLL('x')\n",
                "def _win_api():\n    import ctypes\n    return ctypes.windll.kernel32.TerminateProcess\n",
                "from ctypes import windll\n", "m = __import__('ctypes')\n", "import ctypes.util\n"):
        assert _ctypes_refusals(ast.parse(bad)), bad


def test_redo2_b9_a_refused_user_rule_is_said_refused_in_the_rail_not_also_off():
    info = {"file": "read", "off": [{"rule_id": "MINE", "refused": "no fixtures beside it"}], "refused": [],
            "user_refused": ["MINE: no fixtures beside it"]}
    assert app.rail_rules(info) == ("No rule off; rules: 1 refused", "incomplete")
    both = dict(info, off=info["off"] + [{"rule_id": "NET-TOOL", "since": "T"}])
    assert app.rail_rules(both) == ("1 rule off; rules: 1 refused", "incomplete")
