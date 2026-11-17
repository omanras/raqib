"""The window's Link screen (HANDOFF.md M10.4b REDO; ADR-0011 Amendments R-2 to R-4, S, T, U): the rows of
raqib/link.py formatted - a rail line that carries the worst word on every screen, and a screen of text - by a
window that starts nothing and judges nothing itself. The pure functions run with no Tk; the Tk tests only where
tkinter imports and a display is there (as tests/test_app.py's). No sleeps: clocks are injected."""
import ast
import datetime
import json
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, cli, link  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (autouse: fails a raqib- thread left behind)

NOW = 1_800_000_000.0
NAMES = ["behind", "broken", "failing", "ok", "silent"]
WAIT = 30.0   # the most a test waits for a thread it released (join, never a sleep)


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def iso(seconds):
    d = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (d.microsecond // 1000)


def a_state(name, written=NOW - 1, **change):
    s = {"schema": "raqib-forward/1", "name": name, "pid": 4242, "written": iso(written),
         "destination": {"scheme": "https", "host": "192.0.2.10", "port": 8088, "path": "/collect"},
         "shape": "raqib", "delivery": "acknowledged", "plain": False, "file": "/home/u/.raqib/host/events.jsonl",
         "cursor": {"offset": 0, "line_sha256": None}, "from": {"start": "start", "offset": 0}, "beat": 60,
         "sent": 7, "skipped": 0, "refused": {"count": 2, "ids": ["r1:2", "r1:3"]}, "restarts": 0,
         "last_id": "r1:9", "last_ok": iso(written), "behind": 0, "failing": None,
         "head": {"length": 0, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
         "in_question": {"count": 0, "since": None}}
    s.update(change)
    return s


def put(home, name, data):
    d = Path(link.forward_dir(str(home)))
    d.mkdir(parents=True, exist_ok=True)
    (d / (name + ".json")).write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode("ascii"))


def each_word(home, only=None):
    states = {"ok": a_state("ok"),
              "failing": a_state("failing", failing={"since": iso(NOW - 30), "tries": 3, "error": "connect",
                                                     "status": None}),
              "behind": a_state("behind", behind=100, last_ok=None, last_id=None),
              "silent": a_state("silent", written=NOW - 500), "broken": b"{not json"}
    for name in only or states:
        put(home, name, states[name])
    return link.read(home=str(home), now=NOW)


def printable(view):
    lines = [t for t, _ in view["text"]] + [view["word"], view["detail"]]
    lines += [x for item in view["items"] for x in [item["name"], item["word"]] + item["lines"]]
    return all(x.isprintable() for x in lines)


# --- E2 (T-1, T-3, T-5, S-1, S-2, U-2): link_view, with no Tk -----------------------------------------------------

def test_e2_each_forwarder_is_one_item_levelled_by_level_of_of_its_code_and_ok_is_a_note(home):
    rows = each_word(home)
    view = app.link_view(rows)
    got = [(i["name"], i["word"], i["level"]) for i in view["items"]]
    assert got == [("behind", "BEHIND", "alarm"), ("broken", "UNREADABLE", "incomplete"),
                   ("failing", "FAILING", "alarm"), ("ok", "OK", "note"), ("silent", "SILENT", "incomplete")]
    for item, row in zip(view["items"], rows):   # the row's own lines, apart as the row gives them (T-2)
        assert (item["facts"], item["why"], item["lines"]) == (row["facts"], row["why"], row["lines"])
        assert item["level"] == ("note" if row["code"] == 0 else app.level_of(row["code"]))
    # the verdict: link.worst's code (3 over 1 over 0) by level_of; the words of the worst code, counted (U-3)
    assert view["level"] == app.level_of(link.worst(rows)) == "incomplete"
    assert app.verdict_sentence(view["word"]) == "Link: 5 forwarders, 1 unreadable, 1 silent"
    heads = [(t, tag) for t, tag in view["text"] if tag == "head"]
    assert [t.split("  ")[:2] for t, _ in heads] == [[n, w] for n, w, _ in got]
    assert "ok  OK  (state written 1 s ago)" in [t for t, _ in heads]
    why = [(t.strip(), tag) for t, tag in view["text"] if t.strip() in rows[2]["why"]]
    assert why == [(rows[2]["why"][0], "alarm")]   # a why line carries its forwarder's level
    one = app.link_view(link.read(str(home), NOW, "ok"))
    assert one["level"] == "note" and app.verdict_sentence(one["word"]) == "Link: 1 forwarder, 1 OK"
    for rows_of in (["ok"], ["failing"], ["silent"]):   # T-1: never clean, whatever the link says
        assert app.link_view(link.read(str(home), NOW, rows_of[0]))["level"] != "clean"


def test_e2_no_row_and_no_problem_is_no_forwarder_at_note_with_the_command_as_text(home):
    for rows in (link.read(str(home), NOW), link.Rows()):   # no folder at all: no row, no problem (T-5)
        view = app.link_view(rows)
        assert (view["word"], view["level"], view["items"]) == ("NO FORWARDER", "note", [])
        assert view["detail"] == "no forwarder: nothing leaves this host by Raqib"
        assert app.verdict_sentence(view["word"]) == "No forwarder: nothing leaves this host by Raqib"
        assert ("  " + app.LINK_START, None) in view["text"]
        assert app.rail_link(rows) == ("Link: none", "note")
    args = cli._parser().parse_args(app.LINK_START.split()[1:])   # the command said is one the parser takes
    assert (args.command, args.to, args.name) == ("forward", "URL", "NAME")


def test_e2_rows_problem_or_rest_are_incomplete_and_said(home, monkeypatch):
    rows = link.Rows()
    rows.problem = "the folder /x/forward cannot be listed (PermissionError)"
    view = app.link_view(rows)
    assert (view["word"], view["level"]) == ("LINK NOT READ", "incomplete") and "cannot be listed" in view["detail"]
    assert app.rail_link(rows) == ("Link: not read", "incomplete")
    rows = each_word(home, ["ok"])
    rows.rest = 3   # S-1: states counted and not read are not calm
    view = app.link_view(rows)
    assert view["level"] == "incomplete" and "3 more state(s) were counted and not read" in view["detail"]
    assert any(t.startswith("3 more state(s)") and tag == "incomplete" for t, tag in view["text"])
    assert app.rail_link(rows) == ("Link: 1 forwarder, 1 OK; 3 not read", "incomplete")
    monkeypatch.setattr(link, "_names", lambda folder: (_ for _ in ()).throw(PermissionError("no")))
    rows = link.read(str(home), NOW)   # S-2: a folder there that cannot be listed
    assert rows.problem and app.link_view(rows)["level"] == "incomplete"


def test_e2_u2_a_read_late_by_more_than_10_s_is_incomplete_said_with_its_age_but_an_alarm_stays_an_alarm(home):
    each_word(home)
    ok = link.read(str(home), NOW, "ok")
    for rows, calm in ((ok, "note"), (link.Rows(), "note"), (link.read(str(home), NOW, "silent"), "incomplete")):
        assert app.link_view(rows, 9.5)["level"] == calm and app.link_view(rows)["level"] == calm
        late = app.link_view(rows, 12.5)
        assert late["level"] == "incomplete" and "has returned for 12 s" in late["detail"]
        assert app.rail_link(rows, 12.5)[1] == "incomplete" and "not read for 12 s" in app.rail_link(rows, 12.5)[0]
    for name in ("failing", "behind"):   # U-2: a known failure is not turned amber by a late read
        rows = link.read(str(home), NOW, name)
        late = app.link_view(rows, 12.5)
        assert late["level"] == "alarm" and "has returned for 12 s" in late["detail"]
        assert late["items"][0]["word"] == name.upper() and app.rail_link(rows, 12.5)[1] == "alarm"
    first = app.link_view(None)
    assert (first["word"], first["level"]) == ("READING LINK", "incomplete")
    late = app.link_view(None, 10.5)
    assert (late["word"], late["level"]) == ("LINK NOT READ", "incomplete") and "for 10 s" in late["detail"]
    assert app.rail_link(None) == ("Link: not read", "incomplete")
    assert app.rail_link(None, 10.5) == ("Link: not read for 10 s", "incomplete")


def test_e2_t3_every_text_of_a_state_passes_one_function_that_removes_control_characters_and_bounds_a_line(home):
    assert app.link_line("a\x1b[31mred\x1b[0m\nb\rc\x00\u202e") == "a?[31mred?[0m?b?c??"
    long = app.link_line("x" * 10000)
    assert len(long) == app.LINK_LINE_MAX and long.endswith("[%d characters not shown]" % (10000 - 300))
    assert app.link_line("x" * app.LINK_LINE_MAX) == "x" * app.LINK_LINE_MAX
    # a state whose texts are a stranger's: an escape in its file, a newline in its last id, a line of 10000
    put(home, "odd", a_state("odd", file="/tmp/\x1b]0;owned\x07\x1b[2J" + "f" * 10000, last_id="r1:9\nOK fake"))
    rows = link.read(str(home), NOW)
    assert rows[0]["word"] == "OK" and any("\x1b" in x for x in rows[0]["lines"])   # the row holds them as written
    view = app.link_view(rows)
    assert printable(view)
    assert all(len(t) <= app.LINK_LINE_MAX + 2 for t, _ in view["text"])   # 2: the indent of a forwarder's line
    assert all(len(x) <= app.LINK_LINE_MAX for x in view["items"][0]["lines"])
    assert not any(t.startswith("OK fake") for t, _ in view["text"])   # a newline in a value makes no line
    fake = [{"name": "n\x1b[1m", "word": "OK\n", "code": 0, "facts": ["a\x07"], "why": ["b" * 10000], "age": None}]
    assert printable(app.link_view(fake)) and "\n" not in app.rail_link(fake)[0]


# --- E3 (R-3, U-3): the rail's one bounded line ----------------------------------------------------------------

def test_e3_rail_link_counts_the_forwarders_and_each_word_at_the_worst_code(home):
    rows = each_word(home)
    assert app.rail_link(rows) == ("Link: 5 forwarders, 1 unreadable, 1 silent", "incomplete")
    failing = link.Rows(r for r in rows if r["code"] == 1)
    assert app.rail_link(failing) == ("Link: 2 forwarders, 1 behind, 1 failing", "alarm")
    ok = link.Rows(r for r in rows if r["code"] == 0)
    assert app.rail_link(ok) == ("Link: 1 forwarder, 1 OK", "note")
    assert app.rail_link(link.Rows()) == ("Link: none", "note") and app.rail_link(None)[0] == "Link: not read"
    many = [{"name": "n%d" % i, "word": "W" * 500 + "\n", "code": 3} for i in range(64)]
    text, level = app.rail_link(many, 99999.0)
    assert len(text) <= app.LINK_RAIL_MAX and text.isprintable() and level == "incomplete"


# --- E5 (T-4, R-4, U-4): the worker -------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def joined(job):
    job.thread.join(WAIT)
    assert not job.thread.is_alive()


def test_e5_at_most_one_read_a_second_on_a_worker_thread_named_as_the_windows_and_a_daemon(home):
    calls, clock = [], Clock()
    job = app.LinkJob(reader=lambda: calls.append(threading.current_thread()) or link.Rows(), clock=clock)
    assert job.rows is None and job.age() is None
    assert job.poll() and job.thread.name == "raqib-app-link" and job.thread.daemon
    joined(job)
    assert calls == [job.thread] and calls[0] is not threading.current_thread() and job.rows == []
    for t in (0.25, 0.5, 0.99):
        clock.t = t
        assert not job.poll()
    clock.t = 1.0
    assert job.poll()
    joined(job)
    clock.t = 1.5
    assert not job.poll() and len(calls) == job.reads == 2


def test_e5_a_reader_that_blocks_is_never_read_twice_and_after_10_s_the_view_says_for_how_long(home):
    gate, clock, calls = threading.Event(), Clock(), []
    good = each_word(home, ["failing"])

    def blocks():
        calls.append(1)
        if len(calls) > 1:
            gate.wait(WAIT)
        return good
    job = app.LinkJob(reader=blocks, clock=clock)
    try:
        assert job.poll()
        joined(job)
        clock.t = 2.0
        assert job.poll()   # the second read blocks
        for t in (3.0, 5.0, 11.0, 20.0):
            clock.t = t
            assert not job.poll() and len(calls) == 2   # never two reads at once
        clock.t = 11.5
        assert 9.0 < job.age() < 10.0 and app.link_view(job.rows, job.age())["level"] == "alarm"
        clock.t = 12.5
        view = app.link_view(job.rows, job.age())
        assert "has returned for 10 s" in view["detail"] and view["level"] == "alarm"   # U-2: FAILING stays
        job.rows = link.Rows()
        assert app.link_view(job.rows, job.age())["level"] == "incomplete"
        assert app.rail_link(job.rows, job.age()) == ("Link: none; not read for 10 s", "incomplete")
    finally:
        gate.set()
        joined(job)
    assert job.age() is None and job.rows is good


def test_e5_a_reader_that_raises_is_a_read_said_incomplete_never_the_windows_failure(home):
    def raises():
        raise OSError("the disk")
    job = app.LinkJob(reader=raises, clock=Clock())
    assert job.poll()
    joined(job)
    view = app.link_view(job.rows, job.age())
    assert (view["word"], view["level"]) == ("LINK NOT READ", "incomplete") and "OSError" in view["detail"]
    job = app.LinkJob(reader=lambda: None, clock=Clock())   # a reader that gives no rows
    assert job.poll()
    joined(job)
    assert job.rows.problem and app.rail_link(job.rows) == ("Link: not read", "incomplete")


class FakeJob:
    def __init__(self, busy=True, rows=None):
        self.closed, self.polls, self.rows, self._busy = [], 0, rows, busy

    def poll(self, now=None):
        self.polls += 1

    def busy(self):
        return self._busy

    def age(self, now=None):
        return 50.0 if self._busy else None

    def close(self, seconds=None):
        self.closed.append(seconds)
        return not self._busy


class FakeSession:
    def __init__(self, project):
        self.project, self.phase, self.stopped, self.thread = project, "watching", [], None

    def start(self):
        return self

    def stop(self, reason):
        self.stopped.append(reason)
        self.phase = "finished"

    def snapshot(self):
        return {"phase": self.phase, "final_exit": 1 if self.phase == "finished" else None,
                "final_text": "RESULT: ALARM (exit 1)\n" if self.phase == "finished" else None, "holes": [],
                "knock": {"rule_id": "SECRET-OUTPUT", "severity": "high", "status": "by the rule"}}


def test_e5_u4_the_end_waits_for_a_read_in_flight_at_most_2_s_and_it_is_no_part_of_the_watch_did_not_end(home):
    c = app.Controller(None, make_session=FakeSession)
    job = FakeJob(busy=True)
    assert c.start_link(job) is job and job.polls == 1
    assert c.link_now() == (None, 50.0) and job.polls == 2
    assert not c.worker_alive()
    c.quit("the test")
    assert c.can_exit() and not c.quit_overdue()   # a read in flight never holds Quit
    assert c.shutdown() is True and job.closed == [app.LINK_WAIT] and app.LINK_WAIT == 2.0
    gate = threading.Event()
    real = app.LinkJob(reader=lambda: gate.wait(WAIT) and link.Rows(), clock=Clock())
    assert real.poll()
    gate.set()
    assert real.close() and not real.poll()   # closed: no read starts after the end


# --- E6 (R-2, J-1): no result of a watch changes with the link ------------------------------------------------------

def test_e6_the_exit_code_report_knock_and_a_watchs_view_are_equal_with_a_failing_a_silent_and_no_forwarder(home):
    state = {"status": "watching", "lines": 2, "url": "http://127.0.0.1:1/", "capture": {},
             "notifications": {"backend": "off", "reason": "--no-notify", "counts": {}},
             "findings": [{"rule_id": "SECRET-OUTPUT", "severity": "high", "cited_seq": [2], "state": "settled",
                           "history": False, "session_id": "s", "summary": "x", "notice": None}],
             "holes": [], "silence": [], "code_so_far": 1}
    seen = []
    kinds = {"failing": each_word(home / "f", ["failing"]), "silent": each_word(home / "s", ["silent"]),
             "none": link.Rows(), "not read": None}
    for kind, rows in kinds.items():
        c = app.Controller(None, make_session=FakeSession)
        job = app.LinkJob(reader=lambda rows=rows: rows if rows is not None else link.Rows(), clock=Clock())
        c.start_link(job)
        joined(job)
        before = (c.exit_code(), app.watch_view(state), app.host_watch_view(state))
        assert c.start(str(home)) is None
        c.stop("the test")
        seen.append((before, c.exit_code(), c.session.snapshot(), app.watch_view(state), app.host_watch_view(state),
                     app.rail_state("WATCHING", 1, 1)))
        c.shutdown()
    assert all(s == seen[0] for s in seen) and seen[0][1] == 1 and seen[0][0][0] == 0


# --- E7: app imports raqib.link and never raqib.forward -------------------------------------------------------------

def test_e7_app_imports_raqib_link_and_never_raqib_forward_by_any_spelling():
    src = (ROOT / "raqib" / "app.py").read_text(encoding="ascii")
    tree = ast.parse(src)
    names = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            base = ("." * n.level) + (n.module or "")
            names += [base] + ["%s.%s" % (base, a.name) for a in n.names]
        elif isinstance(n, ast.Call) and ast.unparse(n.func).split(".")[-1] in ("import_module", "__import__"):
            assert "forward" not in ast.unparse(n), ast.unparse(n)
    assert "raqib.link" in names
    assert not [x for x in names if "forward" in x.split(".")], names
    assert "raqib.forward" not in src and "import forward" not in src


# --- E8: the Tk window (only with tkinter and a display) -----------------------------------------------------------

def tk_or_skip():
    try:
        import tkinter
    except ImportError:
        pytest.skip("no tkinter in this Python")
    if os.name != "nt" and sys.platform != "darwin" and not os.environ.get("DISPLAY"):
        pytest.skip("no display (DISPLAY is not set)")
    try:
        root = tkinter.Tk()
    except tkinter.TclError as exc:
        pytest.skip("Tk cannot open a window here: %s" % exc)
    root.withdraw()
    return tkinter, root


def a_window(tkinter, root, home, reader, tmp_path):
    c = app.Controller(None, tray=None, make_session=FakeSession)
    doctor = app.DoctorJob(str(tmp_path), checks=lambda p: (p, [("python", (True, "3.12"))], []))
    job = app.LinkJob(reader=reader)
    window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda p: doctor, link_job=job)
    root.withdraw()
    joined(job)
    return window, job


def widgets(w):
    out = []
    for child in w.winfo_children():
        out += [child] + widgets(child)
    return out


def test_tk_e8_the_rails_link_item_opens_the_screen_filled_from_rows_of_each_word(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        rows = each_word(home)
        window, job = a_window(tkinter, root, home, lambda: rows, tmp_path)
        window.tick()
        assert window.screen == "host"
        text, level = app.rail_link(rows)
        assert window.link_note.cget("text") == text == "Link: 5 forwarders, 1 unreadable, 1 silent"   # every screen
        assert str(window.link_note.cget("foreground")) == window.palette["rail_levels"][level]
        window.link_tab.invoke()
        window.tick()
        assert window.screen == "link" and str(window.link_tab.cget("style")) == "Current.Rail.TButton"
        view = app.link_view(rows)
        assert window.verdict.cget("text") == app.verdict_sentence(view["word"])
        assert window.pill.cget("text") == app.level_word(view["level"]) == "incomplete"
        shown = window.link_text.get("1.0", "end")
        for row in rows:
            assert "%s  %s" % (row["name"], row["word"]) in shown
            assert all(line in shown for line in row["lines"])
        assert str(window.link_text.cget("state")) == "disabled"   # read-only text, selectable
        kinds = {x.winfo_class() for x in widgets(window.linkf)}
        assert kinds <= {"TFrame", "TLabel", "Text", "TScrollbar"}, kinds   # no button, field, or switch
        for screen in (window.show_rules, window.show_log, window.show_host):
            screen()
            window.tick()
            assert window.link_note.cget("text") == text
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_e8_no_forwarder_is_said_as_a_note_and_the_window_leaves_no_thread_at_destroy(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, job = a_window(tkinter, root, home, lambda: link.read(str(home)), tmp_path)
        window.show_link()
        assert window.verdict.cget("text") == "No forwarder: nothing leaves this host by Raqib"
        assert window.pill.cget("text") == "note" and app.LINK_START in window.link_text.get("1.0", "end")
        assert window.link_note.cget("text") in ("", "Link: none")
        window.tick()
        assert window.link_note.cget("text") == "Link: none"
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
    assert not [t for t in threading.enumerate() if t.name == "raqib-app-link" and t.is_alive()]
