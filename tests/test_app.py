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
    no process; ctypes is tray.py's (Win32) and app.py's two calls only (M8.1 E6)."""
    banned = ("kill", "killpg", "send_signal", "terminate", "system", "popen", "Popen", "startfile", "run",
              "urlopen", "create_connection", "open_new", "open_new_tab", "call", "check_call", "check_output",
              # A-11: no message to another window, no process ended
              "PostMessageW", "SendMessageW", "TerminateProcess")
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
            elif isinstance(node, (ast.Attribute, ast.Name)):   # A-11: not even named (getattr, a field)
                named = node.attr if isinstance(node, ast.Attribute) else node.id
                assert named not in ("PostMessageW", "SendMessageW", "TerminateProcess", "kill", "killpg"), (
                    name, named)
        assert not imported & {"subprocess", "socket", "ssl", "urllib", "signal", "asyncio", "webbrowser", "http",
                               "anthropic", "shutil"}, (name, imported)
        # M8.1 E6: app.py imports ctypes too, inside _win_api only, for its two calls (the DPI awareness and the
        # title bar): tests/test_app_design.py::test_e6_the_ast_guard_admits_only_the_two_windows_calls
        assert ("ctypes" in imported) == (name in ("tray.py", "app.py")), name
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
    assert "Stop stops the watch" in log and "] first finding knocked: DESTRUCT-CMD medium seq 2 (off)" in log
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
    session = app.Session(str(proj), options(log=str(proj / "t.jsonl"), log_project=str(proj))).start()   # inside
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
            held = session.state()
            assert held["lines"] == last["lines"] and held["heartbeat"] == last["heartbeat"]   # the last one, aged
            assert session.read_note.startswith("the watch held its state for more than")
            assert "the state shown was read " in session.read_note
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
    # M8.1 REDO A-9, A-13(a): what the window draws - each finding an item, the gravest first; the holes counted
    items = app.finding_items(state["findings"])
    assert [(i[0], i[2]) for i in items] == [("high", "SECRET-OUTPUT"), ("medium", "DESTRUCT-CMD"), ("weird", "X")]
    assert items[0][4] == "session s \u00b7 seq 2 \u00b7 settled" and "None" not in " ".join(i[4] for i in items)
    assert app.seen_title(app.seen_lines(view["holes"], [])) == "Could not see (3)"


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
    # M7.3 F-2: the refusal names the running watch
    assert c.start(str(tmp_path)) == "a watch is running: the project watch of %s; stop it first" % tmp_path
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
    """A-7: passes only when the icon came up; otherwise it skips with the
    tray's own reason, which -rsxXp shows in the CI log."""
    t = tray.Tray(lambda a: None)
    why = t.start()
    try:
        if why is not None:
            pytest.skip("the tray did not come up: %s" % why)
        assert t.running and t.hwnd and t._added
    finally:
        t.stop()
    assert not t.running and (t.thread is None or not t.thread.is_alive())
    assert t.holes == [], t.holes


# --- E6: the README ------------------------------------------------------------------------------

def test_e6_readme_the_window_section_names_the_command_the_gui_script_and_python3_tk():
    """M6.4's facts in the window's section (M8.1: rewritten for what a person sees)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## The window\n", 1)[1].split("\n## ", 1)[0]
    flat = " ".join(section.split())
    assert "`raqib app [PROJECT]`" in flat and "`raqib-app`" in flat and "python3-tk" in flat


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
        self.knock = None

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase, self.final_text = "finished", "Raqib watch\nthe final report\n"

    def snapshot(self):
        return {"phase": self.phase, "error": None, "final_text": self.final_text,
                "final_exit": 1 if self.final_text else None, "holes": [], "knock": self.knock}

    def state(self):
        return {"status": "watching", "lines": 2, "url": "http://127.0.0.1:1/", "capture": {},
                "notifications": {"backend": "off", "reason": "--no-notify", "counts": {}},
                "findings": [entry("SECRET-OUTPUT", "high", [2])], "holes": [], "silence": [],
                "code_so_far": 1}   # M8.1 REDO B-4: the watch writes the code of what it read so far


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
        assert window.screen == "host"           # M7.3: the window opens on the host
        window.show_first()                      # "Watch a project": M6.4's first screen, unchanged
        window.tick()
        # M8.1: the verdict says it in a sentence; doctor's checks are rows (pill, name, sentence)
        assert window.screen == "first" and window.verdict.cget("text") == "Checks: all OK"
        assert window.verdict_word == "DOCTOR: all OK" and window.pill.cget("text") == "clean"
        assert "python\t3.12" in window.doctor_rows.get("1.0", "end")
        window.start()
        window.tick()
        assert window.screen == "watching" and window.verdict.cget("text") == "Watching the project: 1 finding so far"
        assert window.url.get() == "http://127.0.0.1:1/"
        assert "\tSECRET-OUTPUT  Agent text" in window.body.get("1.0", "end")   # REDO A-13(a): an item
        # A-5: the first-finding line, and the Log screen at any time (bounded)
        assert window.knock_label.cget("text") == "First finding: none yet (it knocks once, whatever its severity)"
        c.session.knock = {"rule_id": "SECRET-OUTPUT", "severity": "high", "status": "by the rule"}
        c.session.log.write("raqib watch: a line of the watch\n")
        window.tick()
        assert window.knock_label.cget("text") == "First finding: SECRET-OUTPUT high (by the rule)"
        window.show_log()                    # from the project's screen: the project watch's log
        window.tick()
        assert window.screen == "log" and window.log_source == "project"
        assert "a line of the watch" in window.log_text.get("1.0", "end")
        window.show_project()
        # A-13: Open page through the controller's opener. The environ is given without CI, because this
        # test runs where CI is set (windows-latest); the refusal under CI is test_a13's.
        c.options = app.Options(None, None, 60, environ={})
        c.opener = lambda url, environ=None: "no opener here"
        window.open_page()
        window.tick()
        assert "note: page: the page was not opened (no opener here)" in window.seen_text.get("1.0", "end")
        # A-4: a callback exception is a hole in "could not see (N)"
        root.report_callback_exception(ValueError, ValueError("boom"), None)
        window.tick()
        assert "hole: a window callback failed: ValueError: boom" in window.seen_text.get("1.0", "end")
        window.on_close()                    # no tray: the watch stops like Ctrl-C, the report stays
        window.tick()
        assert c.session.stopped == ["window closed"] and window.verdict.cget("text") == "The project watch finished"
        assert window.body.get("1.0", "end").startswith("Raqib watch\nthe final report")
        assert "note: tray" not in window.seen_text.get("1.0", "end")
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
        assert "hole: tray: the tray icon could not be added again" in window.seen_text.get("1.0", "end")
        c.actions.put("quit")
        window.tick()
        assert window.closed and c.session.stopped == ["Quit in the tray menu", "the window was closed"]
        assert t.stopped == 1
    finally:
        if window is None or not window.closed:
            root.destroy()


# --- REDO (ADR-0006 Amendment A) ---------------------------------------------------------------
# A-15 (D-8): every change of the REDO has its test here; the questions file names them.

class _Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeWin32:
    """The Win32 calls of tray.Tray, in Python: a message queue per thread
    (GetMessageW blocks on it), windows that call the WndProc, and a
    notification area whose NIM_ADD answers can be scripted."""

    WM_QUIT = 0x0012

    def __init__(self, adds=None):
        import queue as q
        self.q = q.Queue()
        self.adds = list(adds or [])      # scripted NIM_ADD answers, then True
        self.icons = set()                # (hwnd, uID) in the notification area
        self.calls = []
        self.windows = {}
        self.posted = []                  # PostThreadMessageW
        self.ctypes = _Obj(sizeof=lambda t: 0, byref=lambda o: o)
        self.WNDCLASSEXW = lambda: _Obj()
        self.NOTIFYICONDATAW = lambda: _Obj()
        self.MSG = lambda: _Obj(hWnd=None, message=0, wParam=0, lParam=0)
        self.POINT = lambda: _Obj(x=0, y=0)
        self.WNDPROC = lambda f: f
        self.TID = 4242
        self.TASKBAR = 0xC123

    def last_error(self):
        return 5

    def GetModuleHandleW(self, name):
        return 1

    def GetCurrentThreadId(self):
        return self.TID

    def RegisterClassExW(self, wc):
        self.wndproc = wc.lpfnWndProc
        return 1

    def UnregisterClassW(self, *a):
        self.calls.append("UnregisterClassW")
        return 1

    def RegisterWindowMessageW(self, name):
        assert name == "TaskbarCreated"
        return self.TASKBAR

    def CreateWindowExW(self, ex, cls, title, style, x, y, w, h, parent, menu, inst, param):
        self.created = {"style": style, "parent": parent}
        self.windows[77] = True
        return 77

    def DestroyWindow(self, hwnd):
        self.calls.append("DestroyWindow")
        if self.windows.pop(hwnd, None):
            self.wndproc(hwnd, tray.WM_DESTROY, 0, 0)
        return 1

    def DefWindowProcW(self, *a):
        return 0

    def GetSystemMetrics(self, i):
        return 16

    def CreateIcon(self, *a):
        return 55

    def DestroyIcon(self, icon):
        self.calls.append("DestroyIcon")
        return 1

    def Shell_NotifyIconW(self, what, data):
        key = (data.hWnd, data.uID)
        if what == tray.NIM_ADD:
            ok = self.adds.pop(0) if self.adds else True
            if ok:
                self.icons.add(key)
            self.calls.append("NIM_ADD %s" % ok)
            return ok
        if what == tray.NIM_DELETE:
            self.calls.append("NIM_DELETE")
            ok = key in self.icons
            self.icons.discard(key)
            return ok
        return True

    def GetMessageW(self, msg, hwnd, a, b):
        m = self.q.get(timeout=10)
        msg.hWnd, msg.message, msg.wParam, msg.lParam = m
        return 0 if msg.message == self.WM_QUIT else 1

    def TranslateMessage(self, msg):
        return 0

    def DispatchMessageW(self, msg):
        return self.wndproc(msg.hWnd, msg.message, msg.wParam, msg.lParam)

    def PostQuitMessage(self, code):
        self.q.put((None, self.WM_QUIT, 0, 0))

    def PostThreadMessageW(self, tid, msg, w, l):
        assert tid == self.TID
        self.posted.append(msg)
        self.q.put((None, msg, w, l))
        return 1

    def send(self, msg, w=0, l=0):
        """A message to the tray's window, as Windows would deliver it."""
        self.q.put((77, msg, w, l))


def up_tray(api, actions=None):
    t = tray.Tray((actions if actions is not None else []).append, platform="win32", api=api)
    assert t.start() is None and t.running
    return t


def test_a1_the_tray_window_is_top_level_not_message_only():
    api = FakeWin32()
    t = up_tray(api)
    try:
        assert api.created["parent"] is None and api.created["parent"] != tray.HWND_MESSAGE
        assert api.created["style"] == tray.WS_OVERLAPPED
        assert api.icons == {(77, 1)}
    finally:
        t.stop()
    assert not t.running and not t.thread.is_alive() and t.holes == [] and t.ended is None
    assert api.icons == set() and api.posted == [tray.WM_RAQIB_STOP]
    assert api.calls[-4:] == ["NIM_DELETE", "DestroyWindow", "DestroyIcon", "UnregisterClassW"]


def test_a1_taskbar_created_re_adds_the_icon():
    api = FakeWin32()
    t = up_tray(api)
    try:
        api.icons.clear()                   # Explorer restarted: the notification area is empty
        api.send(api.TASKBAR)
        assert until(lambda: api.icons == {(77, 1)}, 10)
        assert t.running and t.holes == [] and api.calls.count("NIM_ADD True") == 2
    finally:
        t.stop()


def test_a1_a_failed_re_add_is_a_hole_and_close_then_stops_the_watch(tmp_path):
    api = FakeWin32(adds=[True, False])
    t = up_tray(api)
    try:
        c = controller(t)
        c.start(str(tmp_path))
        assert c.close_request() == "hide" and c.session.stopped == []   # the tray is up: hide
        api.icons.clear()
        api.send(api.TASKBAR)
        assert until(lambda: not t.running, 10)
        assert t.holes == ["the tray icon could not be added again after Explorer restarted (Shell_NotifyIconW"
                           " NIM_ADD failed): no tray; closing the window stops the watch"]
        assert not c.tray_up() and c.tray_holes() == ["tray: " + t.holes[0]]
        assert c.close_request() == "stop" and c.session.stopped == ["window closed"]   # A-1: stop, not hide
    finally:
        t.stop()


def test_a6_a7_wm_close_from_outside_stop_ends_the_tray_with_a_hole():
    """A-7's fake-API test of _up / _pump / WM_CLOSE / _down, and A-6's hole."""
    api = FakeWin32()
    t = up_tray(api)
    api.send(tray.WM_CLOSE)               # another same-user process (P6, P18)
    t.thread.join(10)
    assert not t.thread.is_alive() and not t.running
    assert t.ended == "WM_CLOSE from outside stop()" and t.holes == ["tray ended: WM_CLOSE from outside stop()"]
    assert api.icons == set() and "NIM_DELETE" in api.calls and "UnregisterClassW" in api.calls
    c = controller(t)
    assert not c.tray_up() and c.tray_holes() == ["tray: tray ended: WM_CLOSE from outside stop()"]
    t.stop()                               # after the end: nothing posted, no new hole
    assert api.posted == [] and t.holes == ["tray ended: WM_CLOSE from outside stop()"]


def test_a6_wm_destroy_not_from_stop_and_a_failing_pump_are_holes():
    api = FakeWin32()
    t = up_tray(api)
    api.send(tray.WM_DESTROY)
    t.thread.join(10)
    assert t.holes == ["tray ended: WM_DESTROY not from stop()"]
    api = FakeWin32()
    t = up_tray(api)
    api.GetMessageW = lambda *a: -1
    api.send(0)                            # wakes nothing: the next GetMessageW fails
    t.thread.join(10)
    assert t.holes == ["tray ended: its message loop failed: OSError: GetMessageW failed (error 5)"]


def test_a6_a_stop_is_not_a_hole_and_menu_actions_reach_the_queue():
    api = FakeWin32()
    got = []
    t = up_tray(api, got)
    t._menu = lambda: tray.ID_QUIT
    api.send(tray.WM_TRAY, 0, tray.WM_RBUTTONUP)
    api.send(tray.WM_TRAY, 0, tray.WM_LBUTTONUP)
    assert until(lambda: got == ["quit", "show"], 10)
    t.stop()
    assert t.holes == [] and t.ended is None


def test_a6_a_tray_that_comes_up_after_its_start_timed_out_removes_its_icon_and_ends(monkeypatch):
    import threading
    gate = threading.Event()
    api = FakeWin32()
    real = api.GetModuleHandleW

    def slow(name):
        gate.wait(10)
        return real(name)
    api.GetModuleHandleW = slow
    monkeypatch.setattr(tray, "START_SECONDS", 0.05)
    t = tray.Tray(lambda a: None, platform="win32", api=api)
    assert t.start() == "the tray did not come up within 0.05 s" and t.cancelled and not t.running
    gate.set()
    t.thread.join(10)
    assert not t.thread.is_alive() and not t.running
    assert "NIM_ADD True" in api.calls and "NIM_DELETE" in api.calls and api.icons == set()
    assert "UnregisterClassW" in api.calls and t.holes == []


def test_a6_the_controller_keeps_a_timed_out_tray_so_its_holes_show_and_shutdown_stops_it(monkeypatch):
    class Late(FakeTray):
        def start(self):
            self.cancelled = True
            return "the tray did not come up within 5 s"
    t = Late(running=False)
    c = controller(t)
    assert c.start_tray() == "the tray did not come up within 5 s"
    assert c.tray is t and not c.tray_up() and c.holes == ["tray: the tray did not come up within 5 s"]
    t.holes.append("tray ended: x")
    assert c.tray_holes() == ["tray: tray ended: x"]
    c.shutdown()
    assert t.stopped == 1


@pytest.mark.skipif(not WINDOWS, reason="the Win32 structures (win64 sizes)")
def test_a7_win64_structure_sizes():
    import ctypes
    api = tray._Api()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip("32-bit Python: the win64 sizes do not apply")
    assert ctypes.sizeof(api.WNDCLASSEXW) == 80
    assert ctypes.sizeof(api.NOTIFYICONDATAW) == 976


def test_a7_the_install_job_checks_the_gui_launcher_and_entry_points():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    job = gate.split("\n  install:", 1)[1]
    assert "raqib-app.exe" in job and "bin/raqib-app" in job
    assert "entry_points.txt" in job and "[gui_scripts]" in job and "raqib-app = raqib.app:gui_main" in job


def test_a7_the_real_tray_test_skips_with_the_reason():
    src = (ROOT / "tests" / "test_app.py").read_text(encoding="utf-8")
    body = src.split("def test_e4_real_tray_starts_and_stops_or_says_why", 1)[1].split("\ndef ", 1)[0]
    assert "pytest.skip(" in body and "assert why is None or" not in body


def test_a11_the_tray_posts_only_to_its_own_thread():
    src = (ROOT / "raqib" / "tray.py").read_text(encoding="utf-8")
    assert "PostMessageW" not in src and "SendMessageW" not in src and "PostThreadMessageW" in src


def test_a11_the_docstring_says_what_runs():
    doc = " ".join(app.__doc__.split())
    assert "It starts no program" not in doc
    assert "The programs that run are those of `raqib doctor` - `claude --version`" in doc
    assert "and nothing else here" in doc


# --- A-2: the heartbeat's age at every tick ------------------------------------------------------

def beat_state(age, beat="2026-11-03T12:00:00.000Z"):
    return {"status": "watching", "lines": 1, "capture": {}, "heartbeat": beat, "heartbeat_age_seconds": age,
            "stale_after_seconds": 30, "updated": beat, "notifications": {"backend": "off", "counts": {}}}


def test_a2_the_age_is_recomputed_from_the_wall_clock_and_a_stale_watch_reads_crashed_or_stuck():
    beat = START.timestamp()
    st = beat_state(0.4)
    assert app.aged(st, beat + 1.0)["heartbeat_age_seconds"] == 1.0
    assert app.watch_view(app.aged(st, beat + 10))["word"] == "WATCHING"
    view = app.watch_view(app.aged(st, beat + 31))
    assert view["word"] == "CRASHED or stuck (31 s)" and view["level"] == "alarm"
    assert "no heartbeat for 31 s" in view["detail"]
    assert app.aged(st, beat - 5)["heartbeat_age_seconds"] == 0.4   # never younger than when read
    assert app.aged(None, beat) is None and app.aged({"x": 1}, beat) == {"x": 1}
    done = dict(beat_state(99), finished="T")
    assert app.stale_age(done) == (None, 30)                        # a finished watch is not stuck


def test_a2_a_watch_stuck_under_its_lock_turns_crashed_or_stuck_at_a_later_tick(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    wall = [time.time()]
    session = app.Session(str(proj), options(), wall=lambda: wall[0]).start()
    try:
        assert until(lambda: session.state() is not None)
        assert app.watch_view(session.state())["word"] == "WATCHING"
        with session.running.watcher.lock:             # the worker is stuck holding it
            wall[0] += 45                               # the wall clock moves on; the cached state does not
            view = app.watch_view(session.state())
            assert view["word"].startswith("CRASHED or stuck (") and view["level"] == "alarm"
            assert int(view["word"].split("(")[1].split(" ")[0]) >= 44
    finally:
        session.stop("test")
        session.thread.join(WAIT_SECONDS)


# --- A-3: Quit waits, the window comes back, nothing is killed ------------------------------------------

class StuckSession(FakeSession):
    """A worker that does not end when asked."""

    def __init__(self, project):
        super().__init__(project)
        import threading
        self.release = threading.Event()
        self.thread = threading.Thread(target=self.release.wait, args=(30,), daemon=True)
        self.thread.start()

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase = "stopping"

    def alive(self):
        return self.thread.is_alive()

    def snapshot(self):
        return {"phase": self.phase, "final_exit": None, "holes": [], "knock": None, "final_text": None,
                "error": None}


def test_a3_quit_waits_join_seconds_then_the_window_comes_back_with_a_hole(tmp_path):
    clock = [100.0]
    c = app.Controller(None, tray=FakeTray(), make_session=StuckSession, clock=lambda: clock[0])
    c.start_tray()
    c.start(str(tmp_path))
    c.actions.put("quit")
    c.drain()
    assert c.quitting and not c.can_exit() and not c.quit_overdue()
    clock[0] += app.JOIN_SECONDS - 1
    assert not c.quit_overdue()
    clock[0] += 2
    assert c.quit_overdue() and not c.quitting and not c.can_exit()
    assert c.holes == ["the watch did not end in 30 s after Quit: the window stays; Quit again, or see the log"]
    assert not c.quit_overdue() and c.session.thread.is_alive()   # once; and nothing was killed
    c.session.release.set()
    c.session.thread.join(5)
    c.quit("again")
    c.session.phase = "finished"
    assert c.can_exit()


def test_a3_the_process_waits_for_an_unconcluded_watch_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "JOIN_SECONDS", 0.05)
    c = app.Controller(None, tray=None, make_session=StuckSession)
    c.start(str(tmp_path))
    c.session.log = app.LogBuffer()
    err = io.StringIO()
    assert c.finish_wait(err=err, rounds=2) is False                   # bounded here; run() has no bound
    assert err.getvalue().count("still waiting for its final report (nothing is killed)") == 2
    assert "did not end in 0.05 s" in c.session.log.text()
    c.session.release.set()
    assert c.finish_wait(err=err) is True


def test_a3_can_exit_needs_the_worker_ended_not_only_the_phase(tmp_path):
    c = app.Controller(None, tray=None, make_session=StuckSession)
    c.start(str(tmp_path))
    c.quit("q")
    c.session.phase = "finished"         # the report is there, but the worker still runs (close() pending)
    assert not c.can_exit()
    c.session.release.set()
    c.session.thread.join(5)
    assert c.can_exit()


# --- A-4: the gui-script's log, the message box, Tk callback errors ---------------------------------

def test_a4_gui_main_writes_app_log_and_a_failure_before_tk_is_one_message_box(monkeypatch, home):
    monkeypatch.setitem(sys.modules, "tkinter", None)
    shown = []
    (home / ".raqib").mkdir()
    (home / ".raqib" / "app.log").write_text("an old run\n", encoding="utf-8")
    code = app.gui_main([str(home)], home=str(home), platform="win32",
                        box=lambda text, title: shown.append((title, text)))
    assert code == 2 and len(shown) == 1
    title, text = shown[0]
    assert title == "Raqib: the window did not open"
    assert text.startswith("raqib: tkinter cannot be imported") and "python3-tk" in text
    assert "~" not in text and str(home / ".raqib" / "app.log") in text
    log = (home / ".raqib" / "app.log").read_text(encoding="utf-8")
    assert "an old run" not in log and "raqib: tkinter cannot be imported" in log   # truncated at start


def test_a4_elsewhere_the_sentence_goes_to_stderr_and_a_failed_box_falls_back(monkeypatch, home):
    monkeypatch.setitem(sys.modules, "tkinter", None)
    err = io.StringIO()
    assert app.gui_main([str(home)], home=str(home), platform="linux", stream=err) == 2
    assert err.getvalue().startswith("raqib: tkinter cannot be imported") and err.getvalue().count("python3-tk")
    err = io.StringIO()
    app.gui_main([str(home)], home=str(home), platform="win32", box=lambda t, ti: "no user32", stream=err)
    assert "(the message box could not be shown: no user32)" in err.getvalue()
    assert tray.message_box("x", platform="linux") == "no message box on this platform"

    class Box:
        def __init__(self):
            self.calls = []

        def MessageBoxW(self, *a):
            self.calls.append(a)
            return 1
    box = Box()
    assert tray.message_box("the text", "Raqib", platform="win32", api=box) is None
    assert box.calls == [(None, "the text", "Raqib", tray.MB_OK | tray.MB_ICONERROR)]


def test_a4_a_startup_exception_is_shown_too(monkeypatch, home):
    def boom(argv, out=None):
        raise RuntimeError("Tk exploded")
    monkeypatch.setattr(cli, "main", boom)
    shown = []
    assert app.gui_main([], home=str(home), platform="win32", box=lambda t, ti: shown.append(t)) == 2
    assert shown and "the window failed before it opened: RuntimeError: Tk exploded" in shown[0]
    assert "Traceback" in (home / ".raqib" / "app.log").read_text(encoding="utf-8")


def test_a4_a_good_run_shows_no_box_and_restores_the_streams(monkeypatch, home):
    def ok(argv, out=None):
        out.write("the final report\n")
        sys.stderr.write("a warning\n")
        return 1
    monkeypatch.setattr(cli, "main", ok)
    before = sys.stdout, sys.stderr
    shown = []
    assert app.gui_main([], home=str(home), platform="win32", box=lambda t, ti: shown.append(t)) == 1
    assert shown == [] and (sys.stdout, sys.stderr) == before
    assert (home / ".raqib" / "app.log").read_text(encoding="utf-8") == "the final report\na warning\n"


def test_a4_app_log_is_bounded_and_never_raises(tmp_path):
    log = app.AppLog(str(tmp_path / "d" / "app.log"), limit=20)
    log.write("0123456789")
    log.write("0123456789")
    log.write("more and more")
    log.write("and more")
    log.close()
    text = (tmp_path / "d" / "app.log").read_text(encoding="utf-8")
    assert text.startswith("01234567890123456789\n[raqib app: app.log reached 20 bytes; the rest is not written]")
    assert "more" not in text
    bad = app.AppLog(str(tmp_path / "d" / "app.log" / "x"))   # its directory is a file
    assert bad.error and bad.write("x") == 1
    tail = app.Tail(limit=5)
    tail.write("abcdefgh")
    assert tail.text == "defgh"


def test_a4_a_tk_callback_exception_is_a_hole_and_a_log_line(tmp_path):
    tee = io.StringIO()
    c = app.Controller(None, tray=None, make_session=FakeSession, tee=tee)
    try:
        raise ValueError("a button broke")
    except ValueError:
        c.callback_error(*sys.exc_info())
    assert c.holes == ["a window callback failed: ValueError: a button broke"]
    assert "raqib app: a window callback failed: ValueError: a button broke" in tee.getvalue()
    assert "Traceback" in tee.getvalue()
    c.callback_error(ValueError, ValueError("a button broke"), None)
    assert len(c.holes) == 1                                   # deduplicated (A-8)


def test_a4_the_window_hooks_report_callback_exception():
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert "root.report_callback_exception = controller.callback_error" in src
    assert "StringIO" not in src                              # P21: no unbounded buffer


# --- A-5 and A-12: the first finding knocks once; the screen and watch.json say how ------------------

def notifier_for(runner):
    return notify.Notifier("/work/demo", runner=runner, environ={}, platform="linux", isfile=lambda p: True,
                           stderr=io.StringIO())


def test_a5_a_high_first_finding_knocks_once_by_the_rule():
    runner = FakeRunner()
    knock = notify.FirstFinding(notifier_for(runner))
    high = dict(entry("SECRET-OUTPUT", "high", [2]), notice="sent")
    done = knock.check([high], 5.0)
    assert done["status"] == notify.BY_THE_RULE == "by the rule" and done["rule_notice"] == "sent"
    assert runner.calls == []                                   # FIRST-FINDING is not sent after the rule's knock
    for notice in ("terminal", "failed", "folded", "folded: sent as 2 more"):
        k = notify.FirstFinding(notifier_for(runner))
        assert k.check([dict(high, notice=notice)], 5.0)["status"] == "by the rule"
    for notice in ("off", None, "not notified: severity high"):   # the rule did not knock: FIRST-FINDING does
        k = notify.FirstFinding(notifier_for(runner))
        assert k.check([dict(high, notice=notice)], 5.0)["status"] == "sent"
    assert len(runner.calls) == 3


def test_a5_the_watching_screen_line_and_the_bounded_log_view():
    assert app.first_line(None) == "first finding: none yet (it knocks once, whatever its severity)"
    assert app.first_line({"rule_id": "DESTRUCT-CMD", "severity": "medium", "status": "sent"}) == \
        "first finding: DESTRUCT-CMD medium (sent)"
    assert app.first_line({"rule_id": "SECRET-OUTPUT", "severity": "high", "status": "by the rule"}) == \
        "first finding: SECRET-OUTPUT high (by the rule)"
    assert app.log_view("abc", limit=10) == "abc"
    assert app.log_view("0123456789abc", limit=3) == "[10 earlier characters not shown here]\nabc"


def watch_cli(monkeypatch, argv, actions):
    servers = []
    real = ui.make_server

    def make(page, port, **kw):
        server = real(page, port, **kw)
        servers.append(server)
        return server
    monkeypatch.setattr(ui, "make_server", make)
    queue = list(actions)

    def fake_sleep(seconds):
        if not queue:
            raise KeyboardInterrupt
        queue.pop(0)()
    monkeypatch.setattr(watch, "_sleep", fake_sleep)
    out = io.StringIO()
    return cli.main([str(a) for a in argv], out=out), out.getvalue()


def test_a12_a_terminal_watch_knocks_first_finding_once_and_watch_json_carries_it(tmp_path, home, monkeypatch):
    runner = FakeRunner()
    real = notify.Notifier

    def fake_notifier(*a, **kw):
        kw.update(runner=runner, platform="linux", isfile=lambda p: True)
        kw["environ"] = {}
        return real(*a, **kw)
    monkeypatch.setattr(notify, "Notifier", fake_notifier)
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    work = [lambda: append(trace_path, [rec(1, "session_start", 0, tool="-")] + destruct_call(2, 1)),
            lambda: append(trace_path, destruct_call(3, 3)), lambda: None]
    code, out = watch_cli(monkeypatch, ["watch", proj, "--no-open", "--port", "0"], work)
    assert code == 1
    titles = [c.split("\n")[0] for c in runner.calls]
    assert titles == ["Raqib: FIRST-FINDING"]                  # medium: only the first-finding knock, once
    assert runner.calls[0] == "Raqib: FIRST-FINDING\nproject proj, DESTRUCT-CMD medium seq 2\n"
    assert out.count("] first finding knocked: DESTRUCT-CMD medium seq 2 (sent)") == 1
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    fk = st["first_knock"]
    assert {k: fk[k] for k in ("rule_id", "severity", "where", "status")} == {
        "rule_id": "DESTRUCT-CMD", "severity": "medium", "where": "DESTRUCT-CMD medium seq 2", "status": "sent"}
    assert fk["at"].startswith("20")


def test_a12_a_high_first_finding_in_a_terminal_watch_knocks_once_by_the_rule(tmp_path, home, monkeypatch):
    """The blocked-calls fixture: its first live settled finding is high and
    its rule knocks; FIRST-FINDING is not sent after it (A-5, A-12)."""
    runner = FakeRunner()
    real = notify.Notifier

    def fake_notifier(*a, **kw):
        kw.update(runner=runner, platform="linux", isfile=lambda p: True)
        kw["environ"] = {}
        return real(*a, **kw)
    monkeypatch.setattr(notify, "Notifier", fake_notifier)
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    blocked = (ROOT / "tests" / "fixtures" / "blocked-calls-claude-code-2.1.301.log").read_bytes()

    def agent():
        with open(trace_path, "ab") as f:
            f.write(blocked)
    code, out = watch_cli(monkeypatch, ["watch", proj, "--no-open", "--port", "0"], [agent, lambda: None])
    titles = [c.split("\n")[0] for c in runner.calls]
    assert "Raqib: FIRST-FINDING" not in titles and titles and titles[0] == "Raqib: SILENCE-HALF"
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    assert st["first_knock"]["status"] == "by the rule" and st["first_knock"]["rule_id"] == "SILENCE-HALF"
    assert st["first_knock"]["rule_notice"] == "sent"
    assert out.count("] first finding knocked: SILENCE-HALF high seq 2 (by the rule)") == 1


def test_a12_watch_json_first_knock_is_null_until_it_knocks(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    code, out = watch_cli(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"], [lambda: None])
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    assert "first_knock" in st and st["first_knock"] is None and "first finding knocked" not in out


def test_a12_a_failing_knock_is_a_hole_not_the_end_of_a_terminal_watch(tmp_path, home, monkeypatch):
    def broken(running):
        raise RuntimeError("knock broke")
    monkeypatch.setattr(watch, "first_step", broken)
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    code, out = watch_cli(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"],
                          [lambda: None, lambda: None])
    assert "CRASHED" not in out
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    holes = [h for h in st["holes"] if h["kind"] == "first-knock"]
    assert [h["detail"] for h in holes] == ["the first-finding knock failed: RuntimeError: knock broke"]


# --- A-8: the final report survives close(); holes are kept ----------------------------------------

def test_a8_a_close_that_raises_keeps_the_final_report_and_its_exit(tmp_path, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()

    def bad_close(running):
        running.server.shutdown()
        running.server.server_close()
        raise OSError("the notifier's temp files could not be removed")
    monkeypatch.setattr(watch, "close", bad_close)
    session = app.Session(str(proj), options()).start()
    assert until(lambda: session.state() is not None)
    session.stop("test")
    session.thread.join(WAIT_SECONDS)
    snap = session.snapshot()
    assert snap["phase"] == "finished" and snap["final_text"].startswith("Raqib watch\n")
    assert snap["final_exit"] in (0, 1) and snap["error"] is None
    assert snap["holes"] == ["the watch did not close cleanly (page server or notifier): OSError: the notifier's"
                             " temp files could not be removed"]


def test_a8_log_buffer_errors_are_holes_kept_and_deduplicated():
    class Dead:
        def write(self, text):
            raise OSError("closed")

        def flush(self):
            raise OSError("gone")
    log = app.LogBuffer(tee=Dead())
    log.write("a")
    log.write("b")
    assert log.holes == ["the log's copy to the terminal or app.log failed, and stopped: OSError: closed"]

    class Flaky:
        def write(self, text):
            pass

        def flush(self):
            raise OSError("gone")
    log = app.LogBuffer(tee=Flaky())
    log.flush()
    log.flush()
    assert log.holes == ["the log's copy to the terminal or app.log could not be flushed: OSError: gone"]
    s = app.Session("/nowhere", options(), log=log)
    assert s.snapshot()["holes"] == log.holes


def test_a8_window_holes_are_kept_once_and_never_overwritten():
    c = controller(None)
    c.hole("the window failed to update: KeyError: 'x'")
    c.hole("tray: something")
    c.hole("the window failed to update: KeyError: 'x'")
    assert c.holes == ["the window failed to update: KeyError: 'x'", "tray: something"]
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    tick = src.split("    def tick(self):", 1)[1].split("\n    def ", 1)[0]
    assert 'self.c.hole("the window failed to update' in tick


# --- A-10: --log is the command line's project only ----------------------------------------------

def test_a10_log_applies_only_to_the_project_on_the_command_line(tmp_path):
    first, other = tmp_path / "first", tmp_path / "other"
    o = options(log=str(tmp_path / "t.jsonl"), log_project=str(first))
    assert o.log_for(str(first)) == str(tmp_path / "t.jsonl")
    assert o.log_for(str(first) + os.sep) == str(tmp_path / "t.jsonl")
    assert o.log_for(str(other)) is None
    assert options().log_for(str(first)) is None
    seen = []

    def starter(project, log, *a, **kw):
        seen.append((project, log))
        raise watch.WatchError("stop here")
    for proj in (first, other):
        proj.mkdir()
        s = app.Session(str(proj), o, starter=starter).start()
        s.thread.join(10)
    assert seen == [(str(first), str(tmp_path / "t.jsonl")), (str(other), None)]


def test_a10_cli_app_passes_the_command_line_project(monkeypatch, tmp_path):
    got = {}

    def fake_run(project, options, out=None):
        got["o"] = options
        return 0
    monkeypatch.setattr(app, "run", fake_run)
    assert cli.main(["app", str(tmp_path), "--log", str(tmp_path / "x.jsonl")], out=io.StringIO()) == 0
    assert got["o"].log_project == os.path.abspath(str(tmp_path)) and got["o"].log == str(tmp_path / "x.jsonl")


# --- A-13: the Open page button ------------------------------------------------------------------

class UrlSession(FakeSession):
    def state(self):
        return {"url": "http://127.0.0.1:9/"}


def test_a13_open_page_uses_watch_open_page_and_never_under_ci(tmp_path):
    opened = []

    def opener(url, environ=None):
        opened.append(url)
        return None
    c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=UrlSession, opener=opener)
    assert c.open_page() == "no page yet: the watch has not started" and opened == []
    c.start(str(tmp_path))
    assert c.open_page() is None and opened == ["http://127.0.0.1:9/"]
    c = app.Controller(app.Options(None, None, 60, environ={"CI": "true"}), tray=None, make_session=UrlSession,
                       opener=opener)
    c.start(str(tmp_path))
    assert c.open_page() == "CI is set: the page is not opened" and opened == ["http://127.0.0.1:9/"]
    c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=UrlSession,
                       opener=lambda url, environ=None: "no /usr/bin/xdg-open or /bin/xdg-open")
    c.start(str(tmp_path))
    assert c.open_page() == ("the page was not opened (no /usr/bin/xdg-open or /bin/xdg-open); open"
                             " http://127.0.0.1:9/ by hand")
    assert app.Controller(None).opener is watch.open_page


def test_tk_a3_an_overdue_quit_brings_the_window_back(tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    clock = [0.0]
    try:
        c = app.Controller(None, tray=FakeTray(), make_session=StuckSession, clock=lambda: clock[0])
        c.start_tray()
        doctor = app.DoctorJob(str(tmp_path), checks=lambda p: (p, [], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda p: doctor)
        window.start()
        window.on_close()
        assert root.state() == "withdrawn"
        c.actions.put("quit")
        window.tick()
        assert not window.closed
        clock[0] += app.JOIN_SECONDS + 1
        window.tick()
        pump(root)
        assert not window.closed and root.state() != "withdrawn"
        assert "hole: the watch did not end in 30 s after Quit" in window.seen_text.get("1.0", "end")
        c.session.release.set()
        c.session.thread.join(5)
    finally:
        if window is None or not window.closed:
            root.destroy()
