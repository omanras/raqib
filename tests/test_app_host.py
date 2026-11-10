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
    # F-1: the inventory's holes are listed with their count; F-7: trees seen = exit 1, red
    i = inv("linux")
    assert v["word"] == "HOST: 2 TREE(S)" and v["trees"] == 2 and v["level"] == "alarm" and v["code"] == 1
    assert v["holes"] == ["inventory: %s" % h for h in i["holes"]] and len(v["holes"]) == len(i["holes"]) == 14
    # M8.1 REDO A-9: the rows as the window's table draws them, and the selected tree's detail
    heads = [c[1] for c in app.TREE_COLUMNS]
    for col in ("image", "pid", "kind", "first seen", "endpoints"):
        assert col in heads
    table = "\n".join(" ".join(str(c) for c in app.tree_values(r)) for r in v["rows"])
    # REDO B-8: the whole screen as the window draws it - the table, the selected tree's detail, the card's
    # lines, the findings' items, the verdict's detail and every line of "could not see" - as host_body was
    body = "\n".join([table, "".join(app.tree_detail_text(r, d) for r, d in zip(v["rows"], v["details"])),
                      app.empty_trees_text(v), v["detail"]] + [" ".join(map(str, it)) for it in
                                                               app.host_finding_items(None, v)]
                     + app.seen_lines(v["holes"], v.get("notes") or []))
    assert "environment-manager" in body and "anthropic 160.79.104.0/23" in body
    assert "hole: inventory: %s" % i["holes"][0] in body and len(v["holes"]) == 14   # the holes are read
    # E1: never a command line, a cited record's text or an executable path
    detail = "".join(app.tree_detail_text(r, d) for r, d in zip(v["rows"], v["details"]))
    # REDO C-7: the table and the selected tree's detail (a hole may name argv[0] as a word of the doctrine)
    assert "argv" not in table + detail and "--session" not in body and "/usr/local/bin" not in body
    assert "named" in body and "2026-" in body


def test_e1_empty_round_says_no_agent_seen_with_records_and_holes_not_a_clearance():
    i = empty_inv()
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    expected = "no agent seen (%d records, %d holes). Not a clearance." % (i["records"], len(i["holes"]))
    assert v["word"] == "NO AGENT SEEN" and v["lines"] == [expected]
    assert app.empty_trees_text(v) == app.sentence(expected)   # REDO B-8: the trees' card says it (M8.1)
    assert app.empty_line(30, 4) == "no agent seen (30 records, 4 holes). Not a clearance."


def test_e1_a_round_that_read_nothing_is_nothing_read_never_no_agent_seen():
    i = dict(empty_inv(), records=0)
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "NOTHING READ" and v["level"] == "incomplete" and v["code"] == 3   # F-7: amber
    assert not any("no agent seen" in x for x in v["lines"]) and "Not a clearance." in v["detail"]


def test_e1_a_late_reader_is_the_hole_in_the_band_and_a_failed_one_too():
    gate = threading.Event()
    p, clock = probe(lambda: (gate.wait(WAIT), inv("linux"))[1], deadline=20.0)
    clock.t += 21
    v = p.view()
    assert v["word"] == "READER LATE" and v["level"] == "incomplete" and "deadline 20 s" in v["detail"]
    assert v["holes"] == ["reader-late: the round at open was not back within 20 s (2 x T)"]
    gate.set()
    assert until(p.done, WAIT)
    v = p.view()                                      # it came: the trees, shown; F-3: the late hole stays
    assert v["word"] == "HOST: 2 TREE(S)" and v["holes"][0].startswith("reader-late: the round at open came back")

    def boom():
        raise OSError("denied")
    p, _ = probe(boom)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "HOST READER FAILED" and v["holes"] == ["reader-failed: the round at open: OSError: denied"]


def test_e1_kinds_named_unknown_benign_and_what_the_watch_knows():
    assert app.tree_kind({"named": True}) == "named"
    assert app.tree_kind({"named": False}) == "unknown"
    assert app.tree_kind({"named": True, "benign": True}) == "named, benign image"    # F-5
    assert app.tree_kind({"named": False, "benign": True}) == "benign"
    assert app.tree_kind({"named": False, "history": True, "class": "act-root"}) == "unknown (act-root, history)"
    assert app.tree_kind({"named": False, "knocked": "sent", "present": False}) == "unknown (new, gone)"


def test_e1_checks_fold_closed_until_clicked_and_say_what_is_missing():
    """M8.1 REDO A-7 (ADR-0009 Amendment A, superseding M7.3 E1's "open when
    MISSING"): the checks fold under a disclosure closed until clicked; its
    title says what is missing in the alarm colour; each MISSING check is a
    line of "could not see"."""
    assert app.checks_state(None) == ("Checks: running...", None)
    ok = [("OK", "clean", "x"), ("UNSURE", "incomplete", "y")]
    assert app.checks_state(ok) == ("Checks: 1 unsure", "incomplete")
    assert app.checks_state(ok[:1]) == ("Checks: all OK", None)
    assert app.checks_state(ok + [("MISSING", "alarm", "z")]) == ("Checks: 1 missing", "alarm")
    lines = app.doctor_lines([("hooks", (False, "not installed")), ("python", (True, "3"))])
    assert app.missing_checks(lines) == ["check missing: hooks: Not installed"]


def test_e1_the_controller_starts_the_round_at_open_and_a_probe_that_cannot_start_is_a_hole(home):
    c = app.Controller(options(home, lambda: inv("linux")))
    c.start_probe()
    assert until(c.probe.done, WAIT) and c.host_view()["word"] == "HOST: 2 TREE(S)"
    assert json.loads((home / ".raqib" / "host" / "look.json").read_text(encoding="ascii"))["stage"] == "done"
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
    assert c.start_host() == "a watch is running: the host watch; stop it first"
    assert until(lambda: c.host.running is not None and (c.host.state() or {}).get("host", {}).get("new", 0) >= 3,
                 WAIT)
    v = c.host_view()
    assert v["word"] == "WATCHING HOST" and v["new"] == 3
    assert any(f.startswith("NEW-AGENT [high]") for f in v["findings"])
    assert any(f.startswith("NEW-AGENT-UNKNOWN [medium]") for f in v["findings"])
    assert any("unknown (new)" in row[2] for row in v["rows"])
    # M7.6b E5: the tip says the findings too (reworded, docs/review/2026-11-09-M7.6b-questions.md)
    assert c.host_tip(v["trees"], v["new"], len(v["findings"])) == "Raqib: %d trees, 3 new, %d findings" % (
        v["trees"], len(v["findings"]))
    # the knocks: HostWatch's own Notifier, each tree under its own rate-limit id (C-5)
    texts = [x["text"] for x in runner.calls]
    assert "Raqib: NEW-AGENT claude\nhost, claude pid 2100 (named)\n" in texts
    assert "Raqib: NEW-AGENT-UNKNOWN scribe\nhost, scribe pid 7000 (unknown)\n" in texts
    c.stop_host("Stop in the window")
    assert until(lambda: not c.host.alive(), WAIT)
    v = c.host_view()
    assert v["word"] == "HOST WATCH FINISHED" and v["level"] == "alarm"
    assert v["final"].startswith("Raqib watch --host") and "RESULT: ALARM (exit 1" in v["final"]
    assert c.exit_code() == 1 and c.host_tip(1, 1) == "Raqib: idle"     # not watched: idle (M7.6b E5)
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
    assert any("one host watch per home" in x for x in app.seen_lines(v["holes"], []))   # in "could not see"
    assert not c.host_watching() and c.exit_code() == 2          # F-8: a refusal, not a finding


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
                                                                      "at": "T"}},
            "code_so_far": 0}   # M8.1 REDO B-4: the watch writes the code of what it read so far


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
    assert tray.tip_text(4, 1, 2) == "Raqib: 4 trees, 1 new, 2 findings"   # M7.6b E5 (reworded)
    assert tray.tip_text(None, None) == "Raqib: 0 trees, 0 new, 0 findings" and tray.IDLE_TIP == "Raqib: idle"
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
    assert c.host_tip(2, 0) == "Raqib: idle" and t.tips == []   # M7.6b E5 (reworded)
    c.start_host()
    c.host_tip(2, 0)
    c.host_tip(2, 0)
    c.host_tip(3, 1)
    assert t.tips == ["Raqib: 2 trees, 0 new, 0 findings", "Raqib: 3 trees, 1 new, 0 findings"]
    c.host.stop("x")
    c.host_tip(3, 1)
    assert t.tips[-1] == "Raqib: idle"
    # M7.6b REDO C-4: the trees tip is the host watch's only; a project watch alone names the project
    p = app.Controller(None, make_session=FakeSession)
    p.start(str(ROOT))
    assert p.host_tip(3, 1, 0, 0, 2) == "Raqib: project %s, 2 findings" % ROOT.name


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
    assert "opens on the host" in lines[0] and "Watch this host" in lines[0]
    flat = " ".join(section.split())
    assert "Project" in flat and "--every" in flat


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
        assert window.verdict.cget("text") == "2 trees on this host" and window.verdict_word == "HOST: 2 TREE(S)"
        # M7.6b E2: the trees are rows of the Treeview now, not lines of the text
        assert any("environment-manager" in window.host_tree.item(i, "values")
                   for i in window.host_tree.get_children())
        # M8.1: the checks fold under a disclosure closed until clicked; its title in the alarm colour
        assert window.checks.title() == "Checks: 1 missing" and not window.checks.is_open()
        assert str(window.checks.toggle.cget("style")) == "alarm.Disclosure.TCheckbutton"
        window.host_toggle()                       # Watch this host
        window.tick()
        assert window.verdict.cget("text") == "Watching this host: no finding so far"   # REDO A-2
        assert window.host_button.cget("text") == "Stop host watch"
        window.host_toggle()                       # Stop: the final report
        window.tick()
        assert window.verdict.cget("text") == "The host watch finished"
        assert window.host_text.get("1.0", "end").startswith("Raqib watch --host")
        window.show_first()                        # Watch a project: M6.4's screen
        window.tick()
        assert window.screen == "first" and window.verdict.cget("text") == "Checks: 1 missing, 0 unsure"
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


# --- REDO (ADR-0007 Amendment F): one test per behaviour (F-13) ---------------------------------------------

def test_redo_f1_an_incomplete_look_is_amber_trees_or_not_never_discovers_result_word():
    """The reviewer's probe: the linux fixture with a source not read reads incomplete, not clean."""
    i = dict(inv("linux"), incomplete=["source proc-net not read: denied"])
    assert i["result"] == "alarm"                     # discover's word: never what the look's level reads
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["level"] == "incomplete" and v["code"] == 3 and "partly blind" in v["detail"]
    assert v["holes"][0] == "unread source: source proc-net not read: denied"
    lines = app.seen_lines(v["holes"], [])   # M8.1: "could not see (N)" holds every hole
    assert app.seen_title(lines) == "Could not see (%d)" % len(v["holes"])
    assert "hole: unread source: source proc-net not read: denied" in lines
    # a parse problem and a partly read source listed in the inventory's sources make it amber too
    j = dict(empty_inv(), problems=[{"src": "proc", "line": 3, "reason": "not JSON"}])
    k = dict(empty_inv(), sources=[dict(empty_inv()["sources"][0], error="cut short", text_read=True)])
    for x in (j, k):
        p, _ = probe(lambda x=x: x)
        assert until(p.done, WAIT)
        assert p.view()["code"] == 3 and p.view()["word"] == "NO AGENT SEEN, PARTLY BLIND"


def test_redo_f1_the_looks_agent_dark_footprints_are_their_own_lines():
    i = inv("windows")
    assert len(i["agent_dark"]) == 2
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    dark = [x for x in v["lines"] if x.startswith("AGENT-DARK ")]
    assert len(dark) == 2 and v["dark"] == 2 and "2 AGENT-DARK footprint(s)" in v["detail"]
    assert any("codex footprint" in x and "footprints:4" in x for x in dark)
    items = app.host_finding_items(None, v)   # M8.1 REDO A-13(a): the look's footprints as items, red
    assert len(items) == 2 and all(i[1] == "alarm" and i[2] == "AGENT-DARK" for i in items)


def test_redo_f2_the_refusal_names_the_running_watch_and_project_leads_to_its_screen(tmp_path):
    c = app.Controller(None, make_session=FakeSession, make_host=lambda: FakeSession("host"))
    assert c.project_screen() == "first" and app.watch_words(c.host_watching()) == "Not watching"
    c.start(str(tmp_path))
    c.start_host()
    assert c.project_screen() == "watching"
    assert app.watch_words(c.host_watching(), c.session.project) == "Watching the host and project %s" % (
        tmp_path.name)
    assert c.start(str(tmp_path)) == "a watch is running: the project watch of %s; stop it first" % tmp_path
    assert c.start_host() == "a watch is running: the host watch; stop it first"


def test_redo_f3_the_looks_holes_stand_in_the_footer_and_the_log_until_round_one(home):
    gate = threading.Event()
    out = io.StringIO()
    c = app.Controller(options(home, lambda: inv("linux")), tee=out)
    c.start_probe(make=lambda: app.HostProbe(lambda: (gate.wait(WAIT), inv("linux"))[1], CATALOG, 0.0))
    time.sleep(0.05)
    holes = c.look_holes()
    assert holes == ["round at open: reader-late: the round at open was not back within 0 s (2 x T)"]
    c.look_holes()
    assert out.getvalue().count("reader-late") == 1          # in the log once
    gate.set()
    assert until(c.probe.done, WAIT)
    assert c.look_holes()[0].startswith("round at open: reader-late: the round at open came back")   # stays
    c.start_host()
    assert until(c.host_first_round, WAIT)
    assert c.look_holes() == []                              # round 1 replaced them
    c.shutdown()


def test_redo_f3_round_one_waits_for_the_looks_reader_never_two_readers(home):
    gate = threading.Event()
    out = []
    lock = threading.Lock()
    active = [0]

    def reader():
        with lock:
            active[0] += 1
            out.append(active[0])
        try:
            if len(out) == 1:
                gate.wait(WAIT)
            return inv("linux")
        finally:
            with lock:
                active[0] -= 1
    c = app.Controller(options(home, reader))
    c.start_probe()
    assert c.look_thread() is not None
    c.start_host()
    time.sleep(0.5)
    assert len(out) == 1                                    # round 1's reader has not started
    assert "round 1 waits for the reader of the round at open" in c.host.log.text()
    gate.set()
    assert until(c.host_first_round, WAIT)
    assert max(out) == 1                                    # never two readers at once
    c.shutdown()


def test_redo_f4_a_host_finding_line_cites_run_and_seq():
    line = app.host_finding_line({"rule_id": "NEW-AGENT", "severity": "high", "round": 2, "tree": "2100:claude:-",
                                  "summary": "s", "notice": "sent", "run": "20261104T1200-7", "cited_seq": [12]})
    assert line.endswith("cites run 20261104T1200-7 seq 12")


def test_redo_f6_the_host_watch_has_a_log_pane():
    """M8.1: the Log screen shows the host watch's lines or the project watch's (F-6, A-5)."""
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    assert "def show_log" in src and "self.log_text" in src
    body = src.split("def _tick_log", 1)[1].split("\n    def ", 1)[0]
    assert 'log_view(log.text())' in body and 'self.c.host if self.log_source == "host"' in body


def test_redo_f7_colours_follow_c10_codes_and_green_says_not_a_clearance(home):
    i = empty_inv()
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "NO AGENT SEEN" and v["level"] == "clean" and v["code"] == 0
    assert "Not a clearance." in v["detail"] and "Not a clearance." in v["lines"][0]
    assert [app.code_level(x) for x in (0, 1, 3, 2)] == ["clean", "alarm", "incomplete", "alarm"]
    w = app.host_watch_view(FakeHostWatch().state(0))
    assert w["level"] == "clean" and w["detail"].endswith("Not a clearance.")

    class Done(FakeSession):
        def __init__(self, code):
            super().__init__("host")
            self.code = code

        def snapshot(self):
            return {"phase": "finished", "final_exit": self.code, "final_text": "r\n", "holes": []}
    for code, level in ((0, "clean"), (1, "alarm"), (3, "incomplete")):
        c = app.Controller(None)
        c.host = Done(code)
        v = c.host_view()
        assert v["level"] == level and ("Not a clearance." in v["detail"]) == (code == 0)


def test_redo_f8_every_watchs_final_report_is_appended_once_and_kept_after_a_new_start(tmp_path):
    out = io.StringIO()

    class Done(FakeSession):
        n = 0

        def __init__(self, project):
            super().__init__(project)
            Done.n += 1
            self.text = "report %d\n" % Done.n
            self.phase = "finished"

        def snapshot(self):
            return {"phase": self.phase, "final_exit": 1 if self.text == "report 1\n" else 0, "final_text": self.text}
    c = app.Controller(None, tee=out, make_session=Done, make_host=lambda: Done("host"))
    c.start(str(tmp_path))
    c.report_finished()
    c.start(str(tmp_path))                     # the first is replaced: its report and its exit are kept
    c.start_host()
    c.report_finished()
    c.report_finished()
    assert out.getvalue() == "\nreport 1\n\nreport 2\n\nreport 3\n"
    assert c.exit_code() == 1 and len(c.all_sessions()) == 3


def test_redo_f9_a_tree_beside_a_partly_read_source_is_never_clean(tmp_path):
    """The reviewer's probe on HostWatch.result."""
    clock = Clock()
    feed = iter([dict(inv("linux"), incomplete=["source proc-net partly read: cut short"])])
    w = host.HostWatch(lambda: next(feed), CATALOG, RULES, notify.Notifier(host.HOST, enabled=False, reason="t",
                                                                           host=True),
                       out=io.StringIO(), err=io.StringIO(), clock=clock, wall=lambda: 1793700000.0,
                       home=str(tmp_path / "h"), platform="test")
    w.tick(wait=WAIT)
    text, code = w.finish()
    assert code == 3 and "RESULT: INCOMPLETE" in text
    assert "1 round(s) with a source not read or partly read (round 1): source proc-net partly read" in text
    assert host.unread_sources({"sources": [{"name": "proc", "error": "denied", "text_read": False}]}) == [
        "source proc not read: denied"]
    assert host.unread_sources(inv("linux")) == []


def test_redo_f10_the_look_is_written_to_look_json_with_its_holes_and_timing(home):
    gate = threading.Event()
    clock = Clock()
    p = app.HostProbe(lambda: (gate.wait(WAIT), inv("linux"))[1], CATALOG, 20.0, clock=clock,
                      wall=lambda: 1793700000.0, home=str(home)).start()
    path = home / ".raqib" / "host" / "look.json"
    p.view()
    assert not path.exists()                    # reading: nothing to say yet
    clock.t += 21
    p.view()
    late = json.loads(path.read_text(encoding="ascii"))
    assert late["stage"] == "late" and late["reader_out_seconds"] == 21.0 and late["word"] == "READER LATE"
    gate.set()
    assert until(p.done, WAIT)
    p.view()
    done = json.loads(path.read_text(encoding="ascii"))
    assert done["stage"] == "done" and done["word"] == "HOST: 2 TREE(S)" and done["code"] == 3
    assert isinstance(done["reader_seconds"], float) and done["deadline_seconds"] == 20.0
    assert done["holes"][0].startswith("reader-late") and len(done["rows"]) == 2
    assert "not a round of the host watch" in done["note"]
    assert not (home / ".raqib" / "host" / "rounds.jsonl").exists()   # not round 1


def test_redo_f11_open_page_on_the_host_screen_never_under_ci(home):
    c = app.Controller(app.Options(None, None, 60, environ={}))
    assert c.open_page("host") == "no page yet: the watch has not started"

    class Up(FakeSession):
        def state(self):
            return {"url": "http://127.0.0.1:9/"}
    c.host = Up("host")
    opened = []
    c.opener = lambda url, environ=None: opened.append(url)
    assert c.open_page("host") is None and opened == ["http://127.0.0.1:9/"]
    c.options = app.Options(None, None, 60, environ={"CI": "1"})
    assert c.open_page("host") == "CI is set: the page is not opened" and opened == ["http://127.0.0.1:9/"]
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    assert 'text="Open page", command=self.open_host_page' in src


def test_tk_redo_f2_both_watches_running_switch_back_and_forth_every_control_present(tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p)
        root.withdraw()
        window.host_toggle()                       # the host watch runs
        window.show_project()
        assert window.screen == "first"
        window.start()                             # the project watch runs
        window.tick()
        assert window.screen == "watching" and c.host_watching() and c.project_watching()
        for _ in range(2):
            window.host_tab.invoke()
            window.tick()
            assert window.screen == "host" and window.verdict.cget("text") == "Watching this host: no finding so far"
            assert window.host_button.cget("text") == "Stop host watch"
            window.project_tab.invoke()
            window.tick()
            assert window.screen == "watching" and window.verdict.cget("text").startswith("Watching the project: ")
            assert window.stop_button.winfo_manager() == "pack"
        # M8.1 E2: the rail says what is watched, in words
        assert window.running_note.cget("text") == "Watching the host and project %s" % tmp_path.name
        window.show_first()
        window.start()                             # refused: names the running watch, goes to its screen
        assert window.screen == "watching" and "the project watch of" in window.detail.cget("text")
        window.host_tab.invoke()
        window.show_log()                          # F-6: from the host screen, the host watch's lines
        c.host.log.write("raqib watch --host: round 1\n")
        window.tick()
        assert window.log_source == "host" and "round 1" in window.log_text.get("1.0", "end")
        c.stop("test")
        window.tick()
        window.on_close()
        assert window.closed
    finally:
        if window is None or not window.closed:
            root.destroy()
