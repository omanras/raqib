"""M6.4 the window (HANDOFF.md, ADR-0006): raqib app, raqib/tray.py, the
first-finding knock. The logic runs with fakes everywhere; the Tk tests run
only where tkinter imports and a display is there (Windows CI), and keep the
root withdrawn and destroyed. No test shows a real notification: the watches
here run with --no-notify, or the Notifier gets a fake runner."""
import ast
import datetime
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, cli, notify, tray, ui, watch  # noqa: E402
from raqib.rules import engine  # noqa: E402

WINDOWS = os.name == "nt"
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
START = datetime.datetime(2026, 11, 3, 12, 0, 0, tzinfo=datetime.timezone.utc)
WAIT_SECONDS = 30


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


def ts(seconds):
    return (START + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rec(seq, phase, at, session="s-app", tool="Bash", **extra):
    line = {"ts": ts(at), "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "/work/demo"}
    if phase in ("pre", "post"):
        line.update(input_sha256="0" * 64, input_meta=extra.pop("input_meta", {"command_head": "ls"}))
    if phase == "post":
        line.update(output_sha256="1" * 64, ok=True,
                    output_meta=extra.pop("output_meta", {"scan": "full", "secret_kinds": []}))
    line.update(extra)
    return json.dumps(line)


def destruct_call(seq, at):
    """rm: DESTRUCT-CMD, severity medium (a first finding that is not high)."""
    return [rec(seq, "pre", at, input_meta={"command_head": "rm"}), rec(seq, "post", at + 1,
                                                                       input_meta={"command_head": "rm"})]


def secret_call(seq, at):
    return [rec(seq, "pre", at, input_meta={"command_head": "cat"}),
            rec(seq, "post", at + 1, input_meta={"command_head": "cat"},
                output_meta={"scan": "full", "secret_kinds": ["aws_access_key_id"]})]


def append(path, lines):
    with open(path, "ab") as f:
        f.write(("\n".join(lines) + "\n").encode("utf-8"))


def until(predicate, seconds=WAIT_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, env, timeout, wait=True):
        self.calls.append(Path(argv[-1]).read_text(encoding="ascii"))
        return 0, None


def options(**kw):
    rules, gap, evaluator = cli._watch_setup()
    kw.setdefault("no_notify", True)
    kw.setdefault("port", 0)
    return app.Options(evaluator, rules, gap, **kw)


# --- E5: no tkinter, no display ----------------------------------------------------------

def test_e5_without_tkinter_raqib_app_exits_2_naming_python3_tk(monkeypatch, capsys, tmp_path):
    monkeypatch.setitem(sys.modules, "tkinter", None)    # import tkinter raises ImportError, as in this sandbox
    out = io.StringIO()
    assert cli.main(["app", str(tmp_path)], out=out) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "python3-tk" in err and err.startswith("raqib: tkinter cannot be imported")
    assert out.getvalue() == ""
    assert cli.main(["app", "--help"], out=io.StringIO()) == 0


def test_e5_without_a_display_on_x11_raqib_app_exits_2(monkeypatch, capsys):
    class FakeTk:
        def Tk(self):
            raise AssertionError("a window was asked for without a display")
    monkeypatch.setattr(app, "display_problem", lambda environ, platform=None: app.NO_DISPLAY % "linux")
    with pytest.raises(app.AppError) as exc:
        app.run(None, options(environ={}), tk=FakeTk())
    assert "DISPLAY is not set" in str(exc.value) and "`raqib watch` works without a window" in str(exc.value)


def test_e5_display_problem_by_platform():
    assert app.display_problem({}, "win32") is None and app.display_problem({}, "darwin") is None
    assert app.display_problem({"DISPLAY": ":0"}, "linux") is None
    assert app.display_problem({}, "linux").startswith("DISPLAY is not set")


def test_e5_a_tk_that_cannot_open_is_exit_2_not_a_traceback(monkeypatch, capsys, tmp_path):
    class Broken:
        def Tk(self):
            raise RuntimeError("couldn't connect to display")
    monkeypatch.setattr(app, "probe_tk", lambda importer=None: (Broken(), None))
    monkeypatch.setattr(app, "display_problem", lambda environ, platform=None: None)
    assert cli.main(["app", str(tmp_path)], out=io.StringIO()) == 2
    assert "no window could be opened (RuntimeError: couldn't connect to display)" in capsys.readouterr().err


def test_e5_app_and_tray_import_tkinter_lazily_and_nothing_deprecated():
    """tkinter is imported only inside functions (this sandbox has none);
    no tkinter.tix, no module removed by 3.13 (PEP 594)."""
    removed = {"tix", "aifc", "audioop", "cgi", "cgitb", "chunk", "crypt", "imghdr", "mailcap", "msilib", "nis",
               "nntplib", "ossaudiodev", "pipes", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib", "asynchat",
               "asyncore", "distutils", "imp", "smtpd"}
    for name in ("app.py", "tray.py"):
        tree = ast.parse((ROOT / "raqib" / name).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                assert not any(m.split(".")[0] in ("tkinter", "ctypes") for m in mods), (name, mods)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                assert not any(set(m.split(".")) & removed for m in mods), (name, mods)


def test_e5_app_and_tray_signal_nothing_and_start_no_program():
    """A4: the window and the tray start no program, open no socket, signal
    no process; tray.py alone uses ctypes (Win32)."""
    banned = ("kill", "killpg", "send_signal", "terminate", "system", "popen", "Popen", "startfile", "run",
              "urlopen", "create_connection", "open_new", "open_new_tab", "call", "check_call", "check_output")
    for name in ("app.py", "tray.py"):
        tree = ast.parse((ROOT / "raqib" / name).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Call):
                f = node.func
                called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                if called == "run" and name == "app.py":
                    continue   # app.run itself, and doctor's checks: no subprocess here (checked below)
                assert called not in banned, (name, called)
        assert not imported & {"subprocess", "socket", "ssl", "urllib", "signal", "asyncio", "webbrowser", "http",
                               "anthropic", "shutil"}, (name, imported)
        assert ("ctypes" in imported) == (name == "tray.py"), name
        assert imported - {"raqib", "__future__"} <= set(sys.stdlib_module_names)


def test_e5_new_files_are_ascii():
    for name in ("raqib/app.py", "raqib/tray.py", "tests/test_app.py"):
        (ROOT / name).read_bytes().decode("ascii")


# --- E3: the first-finding knock ---------------------------------------------------------

def entry(rule, severity, seqs, state="settled", history=False):
    return {"rule_id": rule, "severity": severity, "cited_seq": seqs, "state": state, "history": history,
            "session_id": "s", "summary": "agent text /etc/passwd $(rm -rf)", "notice": None}


def test_e3_the_first_live_settled_finding_knocks_once_any_severity_own_limit_id():
    runner = FakeRunner()
    n = notify.Notifier("/work/demo", runner=runner, environ={}, platform="linux", isfile=lambda p: True,
                        stderr=io.StringIO())
    knock = notify.FirstFinding(n)
    assert knock.check([], 10.0) is None
    assert knock.check([entry("SILENCE-OPEN", "high", [1], state="pending")], 10.0) is None   # can be taken back
    assert knock.check([entry("DESTRUCT-CMD", "medium", [2], history=True)], 10.0) is None     # history (B-3)
    done = knock.check([entry("DESTRUCT-CMD", "medium", [2], history=True), entry("DESTRUCT-CMD", "low", [3, 4])],
                       11.0)
    assert done["status"] == "sent" and done["where"] == "DESTRUCT-CMD low seq 3,4"
    assert runner.calls == ["Raqib: FIRST-FINDING\nproject demo, DESTRUCT-CMD low seq 3,4\n"]
    assert knock.check([entry("SECRET-OUTPUT", "high", [5])], 12.0) is None                     # once per watch
    assert len(runner.calls) == 1
    # Its own rate-limit id: a rule's knock in the same second is not folded into it, nor it into the rule's.
    assert notify.FIRST_LIMIT not in ("DESTRUCT-CMD", "SECRET-OUTPUT") and n.last == {notify.FIRST_LIMIT: 11.0}
    assert n.notify("DESTRUCT-CMD", "seq 3", 11.5) == "sent"


def test_e3_the_knock_text_is_the_a4_alphabet_bounded_and_never_agent_content():
    runner = FakeRunner()
    n = notify.Notifier("/work/demo", runner=runner, environ={}, platform="linux", isfile=lambda p: True,
                        stderr=io.StringIO())
    knock = notify.FirstFinding(n)
    knock.check([entry("RULE-$(x)`y`" + "A" * 200, "high;rm", list(range(1, 50)))], 1.0)
    (text,) = runner.calls
    title, body, _ = text.split("\n")
    assert len(title) <= notify.TEXT_MAX and len(body) <= notify.TEXT_MAX
    assert not notify.UNSAFE.search(title) and not notify.UNSAFE.search(body)
    assert "passwd" not in text and "rm -rf" not in text   # the summary is never in it


# --- E2: the same watch in a worker thread -----------------------------------------------

def project_files(proj):
    return sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*") if p.is_file())


def test_e2_start_runs_the_same_watch_in_a_worker_and_stop_ends_it_like_ctrl_c(tmp_path, home):
    proj = tmp_path / "proj"
    proj.mkdir()
    session = app.Session(str(proj), options()).start()
    assert until(lambda: session.snapshot()["phase"] == "watching" and session.state() is not None)
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    state = session.state()
    assert state["trace"] == str(trace_path) and state["url"].startswith("http://127.0.0.1:")
    assert state["status"] == "watching" and state["registry"]["row"] == "registered"
    append(trace_path, [rec(1, "session_start", 0, tool="-")] + destruct_call(2, 1))
    assert until(lambda: any(f["rule_id"] == "DESTRUCT-CMD" for f in (session.state() or {}).get("findings", [])))
    # E3: the first finding (medium) knocked through the watch's notifier (off here: --no-notify).
    assert until(lambda: session.snapshot()["knock"] is not None)
    assert session.snapshot()["knock"]["where"] == "DESTRUCT-CMD medium seq 2"
    assert session.snapshot()["knock"]["status"] == "off"
    view = app.watch_view(session.state())
    groups = dict(view["findings"])
    assert view["word"] == "WATCHING" and list(groups) == [g for g in ("high", "medium") if g in groups]
    assert any(line.startswith("DESTRUCT-CMD settled session s-app seq 2") for line in groups["medium"]), groups
    session.stop("Stop in the window")
    assert until(lambda: session.snapshot()["phase"] == "finished")
    snap = session.snapshot()
    assert snap["final_text"].startswith("Raqib watch\n") and "RESULT: ALARM (exit 1)" in snap["final_text"]
    assert snap["final_exit"] == 1
    log = session.log.text()
    assert "raqib watch: stopped (Stop in the window)" in log and "page not opened (--no-open)" in log
    assert "Stop stops the watch" in log and "first finding of this watch knocked: DESTRUCT-CMD medium" in log
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    assert st["status"] == "finished" and st["finished"]
    rows = json.loads((home / ".raqib" / "watches.json").read_text(encoding="ascii"))["watches"]
    assert [r["status"] for r in rows] == ["finished"]
    assert project_files(proj) == [".claude/settings.json"]   # A4: nothing else written into the project
    session.thread.join(10)
    assert not session.alive()


def test_e2_the_page_server_is_down_after_stop(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    session = app.Session(str(proj), options()).start()
    assert until(lambda: session.state() is not None)
    server = session.running.server
    session.stop("test")
    assert until(lambda: session.snapshot()["phase"] == "finished")
    session.thread.join(10)
    assert server.socket.fileno() == -1   # server_close() ran


def test_e2_a_watch_that_cannot_start_is_shown_and_a_crashed_worker_is_a_hole(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    session = app.Session(str(proj), options(log=str(proj / "t.jsonl"))).start()   # --log inside: refused
    assert until(lambda: session.snapshot()["phase"] == "failed")
    snap = session.snapshot()
    assert "the watch did not start: --log" in snap["error"] and "inside the project" in snap["error"]

    def boom(*a, **k):
        raise RuntimeError("the worker broke")
    session = app.Session(str(proj), options(), starter=boom).start()
    assert until(lambda: session.snapshot()["phase"] == "failed")
    snap = session.snapshot()
    assert snap["holes"] == ["the watch worker crashed: RuntimeError: the worker broke"]
    assert "Traceback" in session.log.text()


def test_e2_a_state_held_too_long_shows_the_last_one_and_says_so(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    session = app.Session(str(proj), options()).start()
    try:
        assert until(lambda: session.state() is not None)
        last = session.state()
        lock = session.running.watcher.lock
        with lock:
            assert session.state() is last
            assert session.read_note.startswith("the watch held its state for more than")
        assert session.state() is not last and session.read_note is None
    finally:
        session.stop("test")
        session.thread.join(WAIT_SECONDS)


# --- the views ------------------------------------------------------------------------------

def test_e1_watch_view_band_findings_by_severity_holes_and_url():
    state = {"status": "watching", "lines": 4, "url": "http://127.0.0.1:8765/", "epoch": 0,
             "notifications": {"backend": "off", "reason": "--no-notify", "counts": {}},
             "findings": [entry("DESTRUCT-CMD", "medium", [3]), entry("SECRET-OUTPUT", "high", [2]),
                          entry("X", "weird", [9])],
             "holes": [{"kind": "trace-truncated", "detail": "shrank", "at": "T", "count": 2, "last": "T2"}],
             "silence": [{"epoch": 0, "since": "S", "after": "after line 4", "closed": None}],
             "quiet_seconds": 70, "gap_seconds": 60, "capture": {}}
    view = app.watch_view(state, extra_holes=["tray: it failed"])
    assert view["word"] == "SILENT for 70 s" and view["level"] == "alarm" and view["url"] == state["url"]
    assert [g for g, _ in view["findings"]] == ["high", "medium", "other"]
    assert view["holes"] == ["trace-truncated: shrank at T (2 times, last at T2)",
                             "silence-window: no line since S (after line 4): open", "tray: it failed"]
    assert ("incomplete", "notifications: off (--no-notify)") in view["badges"]
    text = app.body_text(view)
    assert text.startswith("FINDINGS: 3\n  high (1)\n    SECRET-OUTPUT settled session s seq 2")
    assert "HOLES (A3): 3\n  - trace-truncated" in text


def test_e1_doctor_lines_carry_the_verdict_and_level():
    lines = app.doctor_lines([("python", (True, "3.12")), ("claude", (False, "not on PATH")),
                              ("trace", ("UNSURE", "not checked"))], ["moved"])
    assert lines == [("OK", "clean", "OK      python   3.12"), ("MISSING", "alarm", "MISSING claude   not on PATH"),
                     ("UNSURE", "incomplete", "UNSURE  trace    not checked"),
                     ("", "incomplete", " " * 17 + "note: moved")]


def test_e1_doctor_job_runs_doctor_in_a_thread_and_a_failure_is_shown():
    job = app.DoctorJob("/p", checks=lambda p: (p, [("python", (True, "ok"))], [])).start()
    assert until(lambda: job.result() is not None)
    assert job.result() == ("/p", [("OK", "clean", "OK      python   ok")], "raqib doctor: all OK")

    def broken(p):
        raise OSError("no")
    job = app.DoctorJob("/p", checks=broken).start()
    assert until(lambda: job.result() is not None)
    assert job.result()[1][0][2] == "doctor failed: OSError: no"


def test_e1_log_buffer_keeps_the_lines_bounded_and_survives_a_dead_terminal():
    class Dead:
        def write(self, text):
            raise OSError("closed")

        def flush(self):
            raise OSError("closed")
    log = app.LogBuffer(tee=Dead(), limit=10)
    log.write("12345")
    log.write("67890")
    log.write("abc")
    log.flush()
    assert log.text() == "[5 earlier characters dropped]\n67890abc" and log.tee_error == "OSError: closed"


# --- the controller: close, Stop, tray actions -----------------------------------------------

class FakeSession:
    def __init__(self, project):
        self.project = project
        self.phase = "watching"
        self.stopped = []
        self.thread = None

    def start(self):
        return self

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase = "finished"

    def snapshot(self):
        return {"phase": self.phase, "final_exit": 1 if self.phase == "finished" else None}


class FakeTray:
    def __init__(self, result=None, running=True, platform="win32"):
        self.result, self.running, self.platform = result, running, platform
        self.holes, self.stopped = [], 0

    def start(self):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def stop(self):
        self.stopped += 1


def controller(tray=None):
    return app.Controller(None, tray=tray, make_session=FakeSession)


def test_e4_close_while_watching_hides_to_the_tray_and_without_one_stops(tmp_path):
    c = controller(FakeTray())
    assert c.start_tray() is None and c.tray_up()
    assert c.close_request() == "quit"                       # nothing watched: close quits
    assert c.start(str(tmp_path)) is None and c.watching()
    assert c.start(str(tmp_path)) == "a watch is running: stop it first"
    assert c.close_request() == "hide" and c.session.stopped == []
    c = controller(None)
    c.tray = None
    c.start(str(tmp_path))
    assert c.close_request() == "stop" and c.session.stopped == ["window closed"]   # like Ctrl-C
    assert c.close_request() == "quit" and c.exit_code() == 1
    assert c.start(str(tmp_path / "nope")) == "not a directory: %s" % (tmp_path / "nope")


def test_e4_tray_actions_are_queued_and_done_on_the_window_side(tmp_path):
    c = controller(FakeTray())
    c.start_tray()
    c.start(str(tmp_path))
    for action in ("show", "stop"):
        c.actions.put(action)        # what the tray thread does: put only
    assert c.drain() == ["show", "stop"] and c.session.stopped == ["Stop in the tray menu"]
    assert not c.can_exit()
    c.actions.put("quit")
    assert c.drain() == ["quit"] and c.can_exit()


def test_e4_a_tray_failure_is_a_hole_and_no_tray_on_linux_is_a_note():
    c = controller(FakeTray(result="Shell_NotifyIconW(NIM_ADD) failed (error 5)"))
    assert c.start_tray().startswith("Shell_NotifyIconW") and c.tray is None and not c.tray_up()
    assert c.holes == ["tray: Shell_NotifyIconW(NIM_ADD) failed (error 5)"] and c.notes == []
    c = controller(FakeTray(result=RuntimeError("ctypes broke")))
    c.start_tray()
    assert c.holes == ["tray: the tray failed to start: RuntimeError: ctypes broke"]
    c = controller(tray.Tray(lambda a: None, platform="linux"))
    c.start_tray()
    assert c.holes == [] and c.notes == ["tray: " + tray.unsupported("linux")]


def test_e4_shutdown_stops_the_watch_and_the_tray(tmp_path):
    t = FakeTray()
    c = controller(t)
    c.start_tray()
    c.start(str(tmp_path))
    c.shutdown()
    assert c.session.stopped == ["the window was closed"] and t.stopped == 1


# --- E4: the tray's pure parts ------------------------------------------------------------------

def test_e4_menu_ids_and_mouse_messages():
    assert [label for _, label in tray.MENU] == ["Show", "Stop", "Quit"]
    assert [tray.menu_action(i) for i, _ in tray.MENU] == ["show", "stop", "quit"]
    assert tray.menu_action(0) is None                      # the menu was dismissed
    assert tray.mouse_action(tray.WM_LBUTTONUP) == "show" and tray.mouse_action(tray.WM_RBUTTONUP) == "menu"
    assert tray.mouse_action(tray.WM_CONTEXTMENU) == "menu" and tray.mouse_action(0x0200) is None
    got = []
    assert tray.dispatch(tray.WM_TRAY, tray.WM_RBUTTONUP, got.append) and got == ["menu"]
    assert tray.dispatch(tray.WM_TRAY, 0x10000 | tray.WM_LBUTTONUP, got.append) and got == ["menu", "show"]
    assert tray.dispatch(tray.WM_TRAY, 0x0200, got.append) and got == ["menu", "show"]   # mouse move: nothing
    assert not tray.dispatch(tray.WM_CLOSE, 0, got.append)


@pytest.mark.parametrize("size", [16, 20, 24, 32])
def test_e4_the_icon_is_drawn_in_code(size):
    and_bits, xor_bits = tray.icon_masks(size)
    row = (size + 15) // 16 * 2
    assert len(and_bits) == len(xor_bits) == row * size

    def bit(mask, x, y):
        return bool(mask[y * row + x // 8] & (0x80 >> (x % 8)))
    c = size // 2
    assert bit(and_bits, 0, 0) and not bit(xor_bits, 0, 0)               # a corner: transparent
    assert not bit(and_bits, c, c) and not bit(xor_bits, c, c)           # the pupil: black
    assert not bit(and_bits, c, c - size // 4) and bit(xor_bits, c, c - size // 4)   # the iris: white
    assert tray.icon_size(None) == 16 and tray.icon_size(200) == 64 and tray.icon_size(20) == 20


def test_e4_no_tray_off_windows_is_said_never_raised():
    t = tray.Tray(lambda a: None, platform="linux")
    assert t.start() == "no tray on this platform (linux): the window stays open; closing it stops the watch"
    t.stop()
    assert t.holes == [] and not t.running and tray.unsupported("win32") is None


def test_e4_a_tray_that_fails_to_set_up_returns_why_and_never_raises():
    class BrokenApi:
        def GetModuleHandleW(self, name):
            raise OSError("no user32 here")
    t = tray.Tray(lambda a: None, platform="win32", api=BrokenApi())
    assert t.start() == "the tray could not be set up: OSError: no user32 here"
    t.stop()
    assert not t.running


def test_e4_an_exception_in_the_wndproc_is_a_hole_not_a_crash():
    class Api:
        def DefWindowProcW(self, *a):
            return 0
    t = tray.Tray(lambda a: None, platform="win32", api=Api())

    def boom():
        raise OSError("CreatePopupMenu failed")
    t._menu = boom
    assert t._wndproc(1, tray.WM_TRAY, 0, tray.WM_RBUTTONUP) == 0
    assert t.holes == ["the tray failed on message 0x8001: OSError: CreatePopupMenu failed"]
    chosen = []
    t.on_action = chosen.append
    t._menu = lambda: tray.ID_STOP
    t._wndproc(1, tray.WM_TRAY, 0, tray.WM_RBUTTONUP)
    t._wndproc(1, tray.WM_TRAY, 0, tray.WM_LBUTTONUP)
    assert chosen == ["stop", "show"]


@pytest.mark.skipif(not WINDOWS, reason="the real Win32 tray")
def test_e4_real_tray_starts_and_stops_or_says_why():
    t = tray.Tray(lambda a: None)
    why = t.start()
    try:
        assert why is None or isinstance(why, str)
        if why is None:
            assert t.running and t.hwnd
    finally:
        t.stop()
    assert not t.running and (t.thread is None or not t.thread.is_alive())


# --- E6: the README ------------------------------------------------------------------------------

def test_e6_readme_the_window_in_three_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## The window\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in section.split("\n") if line.strip()]
    assert len(lines) == 3 and "raqib app" in lines[0] and "python3-tk" in " ".join(lines)


# --- the Tk window: only with tkinter and a display ------------------------------------------------

def tk_or_skip():
    try:
        import tkinter
    except ImportError:
        pytest.skip("no tkinter in this Python")
    if not WINDOWS and sys.platform != "darwin" and not os.environ.get("DISPLAY"):
        pytest.skip("no display (DISPLAY is not set)")
    try:
        root = tkinter.Tk()
    except tkinter.TclError as exc:
        pytest.skip("Tk cannot open a window here: %s" % exc)
    root.withdraw()
    return tkinter, root


class TkSession(FakeSession):
    """A watch as the window reads it: a state, a log, a final report."""

    def __init__(self, project):
        super().__init__(project)
        self.log = app.LogBuffer()
        self.read_note = None
        self.final_text = None

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase, self.final_text = "finished", "Raqib watch\nthe final report\n"

    def snapshot(self):
        return {"phase": self.phase, "error": None, "final_text": self.final_text,
                "final_exit": 1 if self.final_text else None, "holes": [], "knock": None}

    def state(self):
        return {"status": "watching", "lines": 2, "url": "http://127.0.0.1:1/", "capture": {},
                "notifications": {"backend": "off", "reason": "--no-notify", "counts": {}},
                "findings": [entry("SECRET-OUTPUT", "high", [2])], "holes": [], "silence": []}


def pump(root, cycles=5):
    for _ in range(cycles):
        root.update()
        time.sleep(0.02)


def test_tk_window_first_screen_watching_screen_stop_and_close(tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        c = app.Controller(None, tray=None, make_session=TkSession)
        doctor = app.DoctorJob(str(tmp_path), checks=lambda p: (p, [("python", (True, "3.12"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda p: doctor)
        root.withdraw()
        assert until(lambda: doctor.result() is not None, 10)
        window.tick()
        assert window.screen == "first" and window.band.cget("text") == "DOCTOR: all OK"
        assert "OK      python   3.12" in window.doctor_text.get("1.0", "end")
        window.start()
        window.tick()
        assert window.screen == "watching" and window.band.cget("text") == "WATCHING"
        assert window.url.get() == "http://127.0.0.1:1/"
        assert "SECRET-OUTPUT settled" in window.body.get("1.0", "end")
        window.on_close()                    # no tray: the watch stops like Ctrl-C, the report stays
        window.tick()
        assert c.session.stopped == ["window closed"] and window.band.cget("text") == "FINISHED"
        assert window.body.get("1.0", "end").startswith("Raqib watch\nthe final report")
        assert "note: tray" not in window.foot.cget("text")
        window.on_close()                    # closing again quits
        assert window.closed
    finally:
        if window is None or not window.closed:
            root.destroy()


def test_tk_window_hides_to_the_tray_and_shows_on_a_tray_action(tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        t = FakeTray()
        c = app.Controller(None, tray=t, make_session=TkSession)
        c.start_tray()
        doctor = app.DoctorJob(str(tmp_path), checks=lambda p: (p, [], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda p: doctor)
        root.deiconify()
        pump(root)
        window.start()
        window.on_close()
        pump(root)
        assert root.state() == "withdrawn" and c.session.stopped == []
        c.actions.put("show")
        window.tick()
        pump(root)
        assert root.state() != "withdrawn"
        t.holes.append("the tray icon could not be added again after Explorer restarted")
        window.tick()
        assert "hole: tray: the tray icon could not be added again" in window.foot.cget("text")
        c.actions.put("quit")
        window.tick()
        assert window.closed and c.session.stopped == ["Quit in the tray menu", "the window was closed"]
        assert t.stopped == 1
    finally:
        if window is None or not window.closed:
            root.destroy()
