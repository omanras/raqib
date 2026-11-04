"""M7.3 the window starts from the host (HANDOFF.md E1-E5, ADR-0007 decision 5).

No live host is read here: the round at open and the host watch get a
reader that returns inventories of the discover fixtures (or fails, or never
comes back), and every notifier is off or has a fake runner. The Tk tests
run only where tkinter imports and a display is there (Windows CI); they
withdraw the root, drive tick() by hand and destroy it in finally.
"""
import ast
import datetime
import io
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, discover, host, notify, tray, ui  # noqa: E402
from raqib.rules import engine  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner  # noqa: E402
from test_app import FakeTray, FakeWin32, FakeSession, TkSession, tk_or_skip, until  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
QUESTIONS = ROOT / "docs" / "review" / "2026-11-04-M7.3-questions.md"
WAIT = 30


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


def inv(name):
    return host_fixtures.inventory(name, CATALOG)


def empty_inv():
    """A round that read records and found no tree."""
    i = inv("linux")
    return dict(i, candidates=[], act_roots=[], footprints=[], agent_dark=[], result="clean")


def options(home, reader, every=0.2, **kw):
    return app.Options(None, RULES, 60, no_notify=kw.pop("no_notify", True), environ={}, home=str(home),
                       every=every, catalog=CATALOG, host_reader=reader, host_port=0, **kw)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def probe(reader, deadline=20.0):
    clock = Clock()
    p = app.HostProbe(reader, CATALOG, deadline, clock=clock, wall=lambda: 1793700000.0).start()
    return p, clock


# --- E1: the host screen's state -> text, with fake rounds ------------------------------------------

def test_e1_reading_then_trees_never_a_command_line():
    gate = threading.Event()

    def reader():
        gate.wait(WAIT)
        return inv("linux")
    p, clock = probe(reader)
    v = p.view()
    assert v["word"] == "READING HOST" and v["detail"].startswith("reading the host...") and v["rows"] == []
    gate.set()
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "HOST: 2 TREE(S)" and v["trees"] == 2 and v["holes"] == []
    body = app.host_body(v)
    head = body.splitlines()[0]
    for col in ("image", "pid", "named", "first seen", "acts", "endpoints"):
        assert col in head
    assert "environment-manager" in body and "anthropic 160.79.104.0/23" in body
    # E1: never a command line, a cited record's text or an executable path
    assert "argv" not in body and "--session" not in body and "/usr/local/bin" not in body
    assert "named" in body and "2026-" in body


def test_e1_empty_round_says_no_agent_seen_with_records_and_holes_not_a_clearance():
    i = empty_inv()
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    expected = "no agent seen (%d records, %d holes). Not a clearance." % (i["records"], len(i["holes"]))
    assert v["word"] == "NO AGENT SEEN" and v["lines"] == [expected] and expected in app.host_body(v)
    assert app.empty_line(30, 4) == "no agent seen (30 records, 4 holes). Not a clearance."


def test_e1_a_round_that_read_nothing_is_nothing_read_never_no_agent_seen():
    i = dict(empty_inv(), records=0)
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "NOTHING READ" and v["level"] == "alarm"
    assert "no agent seen" not in app.host_body(v) and "Not a clearance." in v["detail"]


def test_e1_a_late_reader_is_the_hole_in_the_band_and_a_failed_one_too():
    gate = threading.Event()
    p, clock = probe(lambda: (gate.wait(WAIT), inv("linux"))[1], deadline=20.0)
    clock.t += 21
    v = p.view()
    assert v["word"] == "READER LATE" and v["level"] == "alarm" and "deadline 20 s" in v["detail"]
    assert v["holes"] == ["reader-late: the round at open was not back within 20 s (2 x T)"]
    gate.set()
    assert until(p.done, WAIT)
    assert p.view()["word"] == "HOST: 2 TREE(S)"       # it came: the trees, shown

    def boom():
        raise OSError("denied")
    p, _ = probe(boom)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "HOST READER FAILED" and v["holes"] == ["reader-failed: the round at open: OSError: denied"]


def test_e1_kinds_named_unknown_benign_and_what_the_watch_knows():
    assert app.tree_kind({"named": True}) == "named"
    assert app.tree_kind({"named": False}) == "unknown"
    assert app.tree_kind({"named": True, "benign": True}) == "benign"
    assert app.tree_kind({"named": False, "history": True, "class": "act-root"}) == "unknown (act-root, history)"
    assert app.tree_kind({"named": False, "knocked": "sent", "present": False}) == "unknown (new, gone)"


def test_e1_checks_fold_and_open_when_any_missing():
    assert app.checks_state(None) == ("Checks: running...", False)
    ok = [("OK", "clean", "x"), ("UNSURE", "incomplete", "y")]
    assert app.checks_state(ok) == ("Checks: 1 UNSURE", False)
    assert app.checks_state(ok[:1]) == ("Checks: all OK", False)
    assert app.checks_state(ok + [("MISSING", "alarm", "z")]) == ("Checks: 1 MISSING", True)


def test_e1_the_controller_starts_the_round_at_open_and_a_probe_that_cannot_start_is_a_hole(home):
    c = app.Controller(options(home, lambda: inv("linux")))
    c.start_probe()
    assert until(c.probe.done, WAIT) and c.host_view()["word"] == "HOST: 2 TREE(S)"
    assert c.probe.deadline == host.DEADLINE_FACTOR * 0.2

    def broken():
        raise RuntimeError("no catalog")
    c = app.Controller(options(home, None))
    c.start_probe(make=broken)
    v = c.host_view()
    assert v["word"] == "HOST NOT READ" and "RuntimeError: no catalog" in v["detail"]
    assert c.holes == ["the host could not be read at open: RuntimeError: no catalog"]


# --- E2: the host watch in the window ------------------------------------------------------------------

def fed(names):
    feed = iter([inv(n) for n in names])
    last = [None]

    def reader():
        try:
            last[0] = next(feed)
        except StopIteration:
            pass
        return last[0]
    return reader


def test_e2_watch_this_host_runs_the_same_hostwatch_knocks_and_stop_shows_the_report(home, monkeypatch):
    runner = FakeRunner()
    real = notify.Notifier

    def fake_notifier(*a, **kw):
        kw.update(runner=runner, platform="linux", isfile=lambda p: True, environ={})
        return real(*a, **kw)
    monkeypatch.setattr(notify, "Notifier", fake_notifier)
    o = options(home, fed(["benign/windows-desktop", "windows"]), no_notify=False)
    c = app.Controller(o)
    assert c.start_host() is None and c.host_watching()
    assert c.start_host() == "the host is being watched: stop it first"
    assert until(lambda: c.host.running is not None and (c.host.state() or {}).get("host", {}).get("new", 0) >= 3,
                 WAIT)
    v = c.host_view()
    assert v["word"] == "WATCHING HOST" and v["new"] == 3
    assert any(f.startswith("NEW-AGENT [high]") for f in v["findings"])
    assert any(f.startswith("NEW-AGENT-UNKNOWN [medium]") for f in v["findings"])
    assert any("unknown (new)" in row[2] for row in v["rows"])
    assert c.host_tip(v["trees"], v["new"]) == "Raqib: %d trees, 3 new" % v["trees"]
    # the knocks: HostWatch's own Notifier, each tree under its own rate-limit id (C-5)
    texts = [x["text"] for x in runner.calls]
    assert "Raqib: NEW-AGENT\nhost, claude pid 2100 (named)\n" in texts
    assert "Raqib: NEW-AGENT-UNKNOWN\nhost, scribe pid 7000 (unknown)\n" in texts
    c.stop_host("Stop in the window")
    assert until(lambda: not c.host.alive(), WAIT)
    v = c.host_view()
    assert v["word"] == "HOST WATCH FINISHED" and v["level"] == "alarm"
    assert v["final"].startswith("Raqib watch --host") and "RESULT: ALARM (exit 1" in app.host_body(v)
    assert c.exit_code() == 1 and c.host_tip(1, 1) == "Raqib"     # not watched: the plain tip
    assert "raqib watch --host: stopped (Stop in the window)" in c.host.log.text()


def test_e2_a_second_host_watch_on_this_home_is_a_hole_line_never_a_crash(home):
    clock = Clock()
    other = host.HostWatch(lambda: inv("linux"), CATALOG, RULES, notify.Notifier(host.HOST, enabled=False,
                                                                                   reason="t", host=True),
                           out=io.StringIO(), err=io.StringIO(), clock=clock, wall=time.time, home=str(home),
                           platform="test")
    other.tick(wait=WAIT)                     # a fresh heartbeat: this home is watched
    c = app.Controller(options(home, lambda: inv("linux")))
    c.start_probe()
    assert c.start_host() is None
    assert until(lambda: c.host.snapshot()["phase"] == "failed", WAIT)
    v = c.host_view()
    assert v["word"] == "HOST NOT WATCHED" and v["level"] == "alarm"
    assert any("one host watch per home" in h for h in v["holes"])
    assert "one host watch per home" in app.host_body(v)
    assert not c.host_watching() and c.exit_code() == 1


class FakeHostWatch:
    """What host.loop/conclude/close read of a HostWatch: no reader, no file."""

    def __init__(self):
        self.lock = threading.Lock()
        self.port = {"warning": None}
        self.url = "http://127.0.0.1:1/"
        self.refresh = 5
        self.stopping = False
        self.ticks = 0
        self.ended = None

    def clock(self):
        return time.monotonic()

    def tick(self):
        self.ticks += 1

    def done_rounds(self):
        return False

    def settled(self):
        return True

    def finish(self, status, error=None):
        self.ended = status
        return "Raqib watch --host: fake\nRESULT: CLEAN (exit 0)\n", 0

    def unregister(self):
        return None

    def state(self, now):
        return {"mode": "host", "status": "watching", "heartbeat": host.iso(datetime.datetime.now(
            datetime.timezone.utc)), "heartbeat_age_seconds": 0.0, "stale_after_seconds": 30,
            "notifications": {"backend": "off", "reason": "t", "counts": {}}, "holes": [],
            "host": {"now": 0, "new": 0, "trees": [], "last_round": {"round": 1, "records": 30, "holes": 2,
                                                                      "at": "T"}}}


class FakeServer:
    def __init__(self):
        self.down = False

    def shutdown(self):
        self.down = True

    def server_close(self):
        pass


def test_e2_the_worker_starts_and_stops_with_a_fake_hostwatch(home):
    fake, server = FakeHostWatch(), FakeServer()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="t", host=True)
    calls = []

    def starter(catalog, rules, **kw):
        calls.append(kw)
        return host.Running(fake, server, notifier, None, True, {}, kw["out"], kw["err"])
    s = app.HostSession(options(home, lambda: inv("linux"), every=7), starter=starter).start()
    assert until(lambda: fake.ticks > 0, WAIT) and s.snapshot()["phase"] == "watching"
    assert calls[0]["every"] == 7 and calls[0]["no_open"] is True and calls[0]["port"] == 0
    assert calls[0]["home"] == str(home) and calls[0]["reader"] is not None
    v = app.host_watch_view(s.state())
    assert v["word"] == "WATCHING HOST" and v["lines"] == ["no agent seen (30 records, 2 holes). Not a clearance."]
    s.stop("Stop in the window")
    s.thread.join(WAIT)
    snap = s.snapshot()
    assert snap["phase"] == "finished" and snap["final_exit"] == 0 and fake.ended == "finished" and server.down


def test_e2_the_band_words_come_from_hosts_band():
    base = FakeHostWatch().state(0)
    assert app.host_watch_view(base)["word"] == "WATCHING HOST"
    late = dict(base, host=dict(base["host"], reader={"late": True, "round": 2, "seconds": 25}))
    assert app.host_watch_view(late)["word"] == "READER LATE"
    failed = dict(base, host=dict(base["host"], last_round={"round": 2, "at": "T", "error": "OSError: denied"}))
    assert app.host_watch_view(failed)["word"] == "HOST READER FAILED"
    nothing = dict(base, host=dict(base["host"], last_round={"round": 2, "at": "T", "records": 0,
                                                             "nothing_read": True}))
    v = app.host_watch_view(nothing)
    assert v["word"] == "NOTHING READ" and v["level"] == "alarm" and v["lines"] == []
    assert [text for _, text in v["badges"]][:2] == ["trees now: 0", "new this session: 0"]


def test_e2_close_hides_while_any_watch_runs_with_a_tray_else_stops_both(home, tmp_path):
    c = app.Controller(None, tray=FakeTray(), make_session=FakeSession, make_host=lambda: FakeSession("host"))
    c.start_tray()
    assert c.start_host() is None and c.watching() and not c.project_watching()
    assert c.close_request() == "hide"
    c = app.Controller(None, tray=None, make_session=FakeSession, make_host=lambda: FakeSession("host"))
    c.start_host()
    c.start(str(tmp_path))
    assert c.close_request() == "stop" and c.host.stopped == ["window closed"] and c.session.stopped == [
        "window closed"]
    assert c.close_request() == "quit"


# --- E3: project mode beside the host; the tooltip -------------------------------------------------------

def test_e3_host_and_project_watches_run_together_and_stop_each_on_its_own(tmp_path):
    c = app.Controller(None, make_session=FakeSession, make_host=lambda: FakeSession("host"))
    assert c.start_host() is None and c.start(str(tmp_path)) is None
    assert c.host_watching() and c.project_watching()
    c.stop_project("Stop in the window")
    assert c.session.stopped == ["Stop in the window"] and c.host.stopped == [] and c.host_watching()
    c.stop("Stop in the tray menu")             # the tray's Stop ends every watch
    assert c.host.stopped == ["Stop in the tray menu"]
    c.shutdown()
    assert c.host.stopped[-1] == "the window was closed"


def test_e3_the_exit_code_is_an_alarm_first_then_any_other_code():
    class S(FakeSession):
        def __init__(self, code):
            super().__init__("p")
            self.code = code

        def snapshot(self):
            return {"phase": "finished", "final_exit": self.code}
    c = app.Controller(None)
    c.session, c.host = S(0), S(3)
    assert c.exit_code() == 3
    c.session = S(1)
    assert c.exit_code() == 1
    c.session = None
    c.host = S(0)
    assert c.exit_code() == 0


def test_e3_the_tooltip_text_and_the_tray_changes_its_own_icon_only():
    assert tray.tip_text(4, 1) == "Raqib: 4 trees, 1 new" and tray.tip_text(None, None) == "Raqib: 0 trees, 0 new"
    api = FakeWin32()
    tips = []
    real = api.Shell_NotifyIconW

    def notify_icon(what, data):
        if what == tray.NIM_MODIFY:
            tips.append(data.szTip)
            return len(tips) == 1          # the second NIM_MODIFY fails: a hole
        return real(what, data)
    api.Shell_NotifyIconW = notify_icon
    t = tray.Tray(lambda a: None, platform="win32", api=api)
    assert t.start() is None
    try:
        t.set_tip("Raqib: 4 trees, 1 new")
        assert until(lambda: tips == ["Raqib: 4 trees, 1 new"], 10)
        assert api.posted == [tray.WM_RAQIB_TIP] and t.tip == "Raqib: 4 trees, 1 new" and t.holes == []
        t.set_tip("Raqib: 5 trees, 1 new")
        assert until(lambda: len(t.holes) == 1, 10)
        assert t.holes[0].startswith("the tray's tooltip could not be changed (Shell_NotifyIconW NIM_MODIFY failed")
        assert t.running                      # a failed tooltip does not end the tray
    finally:
        t.stop()
    assert api.posted == [tray.WM_RAQIB_TIP, tray.WM_RAQIB_TIP, tray.WM_RAQIB_STOP]
    off = tray.Tray(lambda a: None, platform="linux")
    off.set_tip("Raqib: 1 trees, 0 new")          # no thread: kept, nothing posted, never raised
    assert off.tip == "Raqib: 1 trees, 0 new" and off.holes == []


def test_e3_the_controller_sets_the_tip_only_while_the_host_is_watched_and_once_per_change():
    class TipTray(FakeTray):
        def __init__(self):
            super().__init__()
            self.tips = []

        def set_tip(self, text):
            self.tips.append(text)
    t = TipTray()
    c = app.Controller(None, tray=t, make_host=lambda: FakeSession("host"))
    assert c.host_tip(2, 0) == "Raqib" and t.tips == []
    c.start_host()
    c.host_tip(2, 0)
    c.host_tip(2, 0)
    c.host_tip(3, 1)
    assert t.tips == ["Raqib: 2 trees, 0 new", "Raqib: 3 trees, 1 new"]
    c.host.stop("x")
    c.host_tip(3, 1)
    assert t.tips[-1] == "Raqib"


def test_e3_raqib_app_every_and_its_usage_error(monkeypatch, capsys, tmp_path):
    seen = {}

    def fake_run(project, opts, out=None):
        seen["project"], seen["every"] = project, opts.every
        return 0
    monkeypatch.setattr(app, "run", fake_run)
    assert cli.main(["app", str(tmp_path), "--every", "3"], out=io.StringIO()) == 0
    assert seen == {"project": str(tmp_path), "every": 3.0}
    assert cli.main(["app"], out=io.StringIO()) == 0 and seen["every"] == host.EVERY_DEFAULT
    assert cli.main(["app", "--every", "0"], out=io.StringIO()) == 2
    assert "--every must be a number of seconds from 0.1 to 86400" in capsys.readouterr().err


# --- E4: nothing signalled, attached to or written outside ~/.raqib ---------------------------------------

def test_e4_the_host_round_and_watch_write_only_under_raqib(home, tmp_path):
    before = {p for p in tmp_path.rglob("*")}
    c = app.Controller(options(home, fed(["linux", "linux"])))
    c.start_probe()
    c.start_host()
    assert until(lambda: (c.host.state() or {}).get("host", {}).get("applied", 0) >= 1, WAIT)
    c.shutdown()
    new = {p for p in tmp_path.rglob("*")} - before
    assert new and all(str(p).startswith(str(home / ".raqib")) for p in new), sorted(map(str, new))


def test_e4_app_imports_host_and_still_starts_no_program_and_signals_nothing():
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "raqib":
            imported |= {a.name for a in node.names}
        if isinstance(node, ast.Call):
            f = node.func
            called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            assert called not in ("kill", "send_signal", "terminate", "Popen", "system", "attach"), called
    assert "host" in imported
    src = (ROOT / "raqib" / "tray.py").read_text(encoding="utf-8")
    assert "PostMessageW" not in src and "SendMessageW" not in src


def test_e5_files_are_ascii():
    for name in ("raqib/app.py", "raqib/tray.py", "raqib/cli.py", "tests/test_app_host.py"):
        (ROOT / name).read_bytes().decode("ascii")


# --- E5: README, questions --------------------------------------------------------------------------------

def test_e5_readme_says_the_window_opens_on_the_host():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## The window\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in section.split("\n") if line.strip()]
    assert len(lines) == 5 and "opens on the host" in lines[0] and "Watch this host" in lines[0]
    assert "Watch a project" in lines[1] and "--every" in lines[1]


def test_e5_the_questions_file_has_the_gate_numbers_and_the_tests():
    text = QUESTIONS.read_text(encoding="utf-8")
    for q in ("Q-1", "Q-2", "Q-3", "Q-4", "Q-5"):
        assert q in text
    assert "2568 passed, 16 skipped" in text and "test_app_host.py" in text


# --- the Tk host screen: only with tkinter and a display ----------------------------------------------------

def test_tk_host_screen_round_at_open_checks_and_watch_this_host(tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)   # started by the window (E1)
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("hooks", (False, "not installed"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p)
        root.withdraw()
        assert window.screen == "host"
        assert p.worker is not None             # the round at open started with the window
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        window.tick()
        assert window.band.cget("text") == "HOST: 2 TREE(S)"
        assert "environment-manager" in window.host_text.get("1.0", "end")
        assert window.checks_button.cget("text") == "Checks: 1 MISSING" and window.checks_open   # MISSING: open
        window.host_toggle()                       # Watch this host
        window.tick()
        assert window.band.cget("text") == "WATCHING HOST"
        assert window.host_button.cget("text") == "Stop host watch"
        window.host_toggle()                       # Stop: the final report
        window.tick()
        assert window.band.cget("text") == "HOST WATCH FINISHED"
        assert window.host_text.get("1.0", "end").startswith("Raqib watch --host")
        window.show_first()                        # Watch a project: M6.4's screen
        window.tick()
        assert window.screen == "first" and window.band.cget("text") == "DOCTOR: 1 MISSING, 0 UNSURE"
        window.on_close()
        assert window.closed
    finally:
        if window is None or not window.closed:
            root.destroy()


class TkHost(TkSession):
    """A host watch as the window reads it."""

    def __init__(self):
        super().__init__("host")

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase, self.final_text = "finished", "Raqib watch --host\nRESULT: CLEAN (exit 0)\n"

    def snapshot(self):
        return dict(super().snapshot(), final_exit=0 if self.final_text else None)

    def state(self):
        return FakeHostWatch().state(0)
