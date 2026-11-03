"""M6.1 raqib watch + OS notifications: exit criteria E1-E5 (HANDOFF.md, ADR-0005).

No test shows a real notification: every Notifier here gets a fake runner,
or CI / --no-notify switches it off, or (POSIX) a fake notify-send program
in tmp_path stands in for the real one.
"""
import ast
import datetime
import io
import json
import os
import random
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, notify, report, ui, watch  # noqa: E402
from raqib.rules import engine, trace  # noqa: E402

WINDOWS = os.name == "nt"
FIXTURES = ROOT / "tests" / "fixtures"
CATALOG = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG)
BLOCKED = FIXTURES / "blocked-calls-claude-code-2.1.301.log"
REAL_TRACES = [FIXTURES / "quickstart-d7841d1-claude-code-2.1.301.log",
               BLOCKED,
               FIXTURES / "file-tools-d7841d1-claude-code-2.1.301.log"]
START = datetime.datetime(2026, 11, 2, 12, 0, 0, tzinfo=datetime.timezone.utc)
PROJECT = "/work/demo-proj"


# --- helpers ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Every test gets its own HOME, so ~/.raqib (traces, tmp) is in tmp_path."""
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.delenv("RAQIB_GAP_SECONDS", raising=False)
    return path


class FakeRunner:
    """Stands in for notify.run_program: records the argv, the env and the
    text of the file the command names last, and returns `result` (or the
    next of `results`, one per call)."""

    def __init__(self, result=(0, None), results=None):
        self.calls = []
        self.result = result
        self.results = list(results or [])

    def __call__(self, argv, env, timeout, wait=True):
        text = Path(argv[-1]).read_text(encoding="ascii")
        self.calls.append({"argv": list(argv), "env": dict(env), "text": text, "timeout": timeout})
        return self.results.pop(0) if self.results else self.result

    def titles(self):
        return [c["text"].split("\n")[0] for c in self.calls]


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_notifier(runner=None, **kw):
    kw.setdefault("environ", {})
    kw.setdefault("platform", "linux")
    kw.setdefault("isfile", lambda p: True)
    kw.setdefault("stderr", io.StringIO())
    return notify.Notifier(PROJECT, runner=runner or FakeRunner(), **kw)


def evaluator(gap, counter=None):
    def evaluate(records):
        if counter is not None:
            counter.append(len(records))
        return cli.run_rules(records, RULES, {}, gap)
    return evaluate


def make_watch(tmp_path, gap=60, runner=None, clock=None, notifier=None, counter=None):
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    clock = clock or Clock()
    notifier = notifier or make_notifier(runner)
    return watch.Watch(PROJECT, str(path), evaluator(gap, counter), RULES, gap, notifier, out=io.StringIO(),
                       err=io.StringIO(), clock=clock, started=START), path, clock


def ts(seconds):
    return (START + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rec(seq, phase, at, session="s-watch", tool="Bash", **extra):
    line = {"ts": ts(at), "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "/work/demo-proj"}
    if phase in ("pre", "post"):
        line.update(input_sha256="0" * 64, input_meta=extra.pop("input_meta", {"command_head": "ls"}))
    if phase == "post":
        line.update(output_sha256="1" * 64, ok=True,
                    output_meta=extra.pop("output_meta", {"scan": "full", "secret_kinds": []}))
    line.update(extra)
    return json.dumps(line)


def secret_call(seq, at, session="s-watch", **extra):
    """A Bash call whose output matched a secret pattern: SECRET-OUTPUT (high)."""
    return [rec(seq, "pre", at, session, input_meta={"command_head": "cat"}, **extra),
            rec(seq, "post", at + 1, session, input_meta={"command_head": "cat"},
                output_meta={"scan": "full", "secret_kinds": ["aws_access_key_id"]}, **extra)]


def append(path, data):
    with open(path, "ab") as f:
        f.write(data if isinstance(data, bytes) else ("\n".join(data) + "\n").encode("utf-8"))


def fetch(url):
    """GET from 127.0.0.1 with no proxy (an http_proxy in the environment is not used)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def state_of(w):
    return json.loads(Path(w.state_path).read_text(encoding="ascii"))


# --- E4: the tail on a growing file -------------------------------------------------

def test_e4_tail_reads_what_was_appended_and_holds_a_partial_line(tmp_path):
    path = tmp_path / "trace"
    tail = watch.Tail(str(path))
    assert tail.poll() == ([], [])            # not there yet, never read: silence, not a hole
    append(path, b"one\ntw")
    assert tail.poll() == ([b"one"], [])
    append(path, b"o\n")
    assert tail.poll() == ([b"two"], [])
    assert tail.poll() == ([], [])
    append(path, b"three\r\n\nfour\nfi")
    assert tail.poll() == ([b"three\r", b"", b"four"], [])
    assert tail.rest() == [b"fi"] and tail.rest() == []


def test_e4_tail_truncation_rewrite_replacement_and_removal_are_holes(tmp_path):
    path = tmp_path / "trace"
    tail = watch.Tail(str(path))
    path.write_bytes(b"alpha\nbeta\n")
    assert tail.poll() == ([b"alpha", b"beta"], [])
    path.write_bytes(b"x\n")                                   # shorter: truncated
    lines, holes = tail.poll()
    assert lines == [b"x"] and [(k, r) for k, _, r in holes] == [("trace-truncated", True)]
    assert "shrank from 11 to 2 bytes" in holes[0][1]
    path.write_bytes(b"y\nlonger than before\n")              # same file, new start: rewritten
    lines, holes = tail.poll()
    assert lines == [b"y", b"longer than before"] and [k for k, _, _ in holes] == ["trace-rewritten"]
    other = tmp_path / "other"
    other.write_bytes(b"z" * 40 + b"\n")
    os.replace(other, path)                                   # another file at the path: replaced
    lines, holes = tail.poll()
    assert lines == [b"z" * 40] and [k for k, _, _ in holes] == ["trace-replaced"]
    append(path, b"torn")
    tail.poll()
    os.remove(path)                                           # removed: missing, once
    lines, holes = tail.poll()
    assert lines == [] and [(k, r) for k, _, r in holes] == [("trace-missing", True)]
    assert "4 bytes after the last newline never became a line" in holes[0][1]
    assert tail.poll() == ([], [])
    path.write_bytes(b"again\n")                              # back: read from its start, no hole
    assert tail.poll() == ([b"again"], [])


def test_e4_tail_an_unreadable_trace_is_one_hole_until_it_changes(tmp_path):
    path = tmp_path / "trace"
    path.mkdir()                                              # a directory cannot be read as a trace
    tail = watch.Tail(str(path))
    _, holes = tail.poll()
    assert [(k, r) for k, _, r in holes] == [("trace-unreadable", False)]
    assert tail.poll() == ([], [])


# --- E4: incremental == batch on the final file --------------------------------------

def synthetic():
    rows = [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1)]
    data = ("\n".join(rows) + "\r\n").encode()                 # a CRLF line
    data += b"\n   \n"                                         # blank lines
    data += b"RAQIB-SILENCE: capture failed event=PostToolUse log=x: Deadline\n"
    data += b"\xff\xfe not UTF-8\n" + b"{not json\n" + b'{"session_id": "s", "seq": "1"}\n'
    data += ("\n".join([rec(2, "post", 2), *secret_call(3, 3),
                        rec(4, "pre", 5, input_meta={"path": "/x/RAQIB-SILENCE:no-marker"}, tool="Read"),
                        rec(4, "post", 5, tool="Read", input_meta={"path": "/x/RAQIB-SILENCE:no-marker"}),
                        rec(5, "pre", 200, input_meta={"command_head": "rm"})]) + "\n").encode()
    data += rec(6, "stop", 201, tool="-").encode()              # no final newline
    return data


@pytest.mark.parametrize("source", REAL_TRACES + ["synthetic"], ids=lambda s: getattr(s, "name", s))
def test_e4_incremental_equals_batch_on_the_final_file(tmp_path, source):
    data = synthetic() if source == "synthetic" else source.read_bytes()
    counter = []
    w, path, clock = make_watch(tmp_path, counter=counter)
    rng = random.Random(61)
    cut = 0
    while cut < len(data):
        size = rng.randint(1, 97)
        append(path, data[cut:cut + size])
        cut += size
        clock.t += 0.5
        w.step()
    calls = len(counter)
    w.step()
    w.step()
    assert len(counter) == calls                               # nothing new: the rules are not re-run
    final = w.finish()
    numbered, problems = trace.read_numbered(str(path))
    assert w.numbered == numbered and w.problems == problems
    found, notes = cli.run_rules([r for _, r in numbered], RULES, {}, 60)
    assert w.found == found and w.notes == notes
    assert {k for k, e in w.inventory.items() if e["present"]} == {w.key(f) for f in found}
    assert final == report.build(str(path), numbered, problems, found, notes, report.rule_table(RULES),
                                 watch.SOURCE, extra_alarms=w.alarms())
    if source == "synthetic":
        assert [h["detail"] for h in w.holes] == [
            "line 5 of the trace is a RAQIB-SILENCE line: an event was not captured"]
        assert {e["rule_id"] for e in w.inventory.values() if e["state"] == "settled"} >= {
            "SECRET-OUTPUT", "SILENCE-GAP", "DESTRUCT-CMD"}


def test_e4_a_finding_is_reported_once_and_a_grown_aggregate_is_a_new_finding(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, secret_call(1, 0))
    w.step()
    for seq in range(2, 6):                                    # more lines: the old finding is not new
        append(path, [rec(seq, "pre", seq), rec(seq, "post", seq, cwd="/work/dir%d" % seq)])
        clock.t += 1
        w.step()
    assert runner.titles().count("Raqib: SECRET-OUTPUT") == 1
    # D-2: a settled aggregate is never handed over; each growth (a new cwd) is a new finding.
    moved = [e for e in w.inventory.values() if e["rule_id"] == "SCOPE-CWD-MOVED"]
    assert [len(e["cited_seq"]) for e in moved] == [2, 3, 4, 5] and [e["present"] for e in moved] == [
        False, False, False, True]
    assert all(e["state"] == "settled" and "grown" not in e for e in moved)
    assert w.out.getvalue().count("FINDING [medium] SCOPE-CWD-MOVED") == 4     # each printed once
    assert "SCOPE-CWD-MOVED" not in " ".join(runner.titles())                # medium: shown, not knocked


def test_e4_pending_findings_are_not_notified_and_vanish_when_taken_back(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1)])
    w.step()
    states = {e["rule_id"]: e["state"] for e in w.inventory.values()}
    assert states == {"SILENCE-OPEN": "pending", "SILENCE-HALF": "pending"} and runner.calls == []
    append(path, [rec(2, "post", 2), rec(3, "stop", 3, tool="-")])
    clock.t += 1
    w.step()
    assert w.inventory == {} and runner.calls == []            # the call finished, the session stopped
    append(path, [rec(4, "post", 4)])                          # a post with no pre: settled, notified
    clock.t += 1
    w.step()
    # ... and the session's last line is no longer its stop: open again, pending.
    assert {e["rule_id"]: e["state"] for e in w.inventory.values()} == {
        "SILENCE-HALF": "settled", "SILENCE-OPEN": "pending"}
    assert runner.titles() == ["Raqib: SILENCE-HALF"]


# --- E2: live silence ---------------------------------------------------------------

def test_e2_no_line_for_the_gap_opens_a_window_and_the_next_line_closes_it(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "stop", 0, tool="-")])
    w.step()
    clock.t = 1005.0
    w.step()
    assert w.windows == []                                     # exactly the limit is not more than it
    clock.t = 1005.5
    w.step()
    assert runner.calls[-1]["text"] == "Raqib: SILENCE-LIVE open\nproject demo-proj, after line 2, seq 2\n"
    st = state_of(w)
    assert st["status"] == "silent" and st["silence"][0]["opened"] == "2026-11-02T12:00:05.500Z"
    assert st["silence"][0]["since"] == "2026-11-02T12:00:00.000Z" and st["silence"][0]["closed"] is None
    # M6.2 I-3: one state word and a detail line.
    assert w.band()[0] == ("alarm", "SILENT for 5 s")
    assert w.status_word() == ("SILENT for 5 s", "alarm", "no line since 2026-11-02T12:00:00.000Z (after line 2,"
                                                          " seq 2; limit 5 s)")
    clock.t = 1009.0
    w.step()
    assert len(w.windows) == 1 and runner.titles().count("Raqib: SILENCE-LIVE open") == 1
    append(path, [rec(3, "session_start", 12, session="s-two", tool="-")])
    clock.t = 1012.0
    w.step()
    closed = [c["text"] for c in runner.calls if c["text"].startswith("Raqib: SILENCE-LIVE closed")]
    assert closed == ["Raqib: SILENCE-LIVE closed\nproject demo-proj, line 3, seq 3\n"]
    st = state_of(w)
    assert st["status"] == "watching"
    assert {k: st["silence"][0][k] for k in ("closed", "seconds", "closed_by_line", "closed_by_seq",
                                              "notice_open", "notice_closed")} == {
        "closed": "2026-11-02T12:00:12.000Z", "seconds": 12.0, "closed_by_line": 3, "closed_by_seq": 3,
        "notice_open": "sent", "notice_closed": "sent"}
    assert any(a["kind"] == "silence-window" and "(12.0s; limit 5s)" in a["detail"] for a in w.alarms())


def test_e2_lines_closer_than_the_gap_open_no_window(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    for seq in range(1, 8):
        append(path, [rec(seq, "pre" if seq % 2 else "post", seq)])
        clock.t += 4.9
        w.step()
    assert w.windows == [] and "SILENCE-LIVE" not in " ".join(runner.titles())


def test_e2_a_watch_with_no_trace_yet_opens_a_window_from_its_start(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    w.step()
    clock.t += 6
    w.step()
    assert runner.calls[-1]["text"] == "Raqib: SILENCE-LIVE open\nproject demo-proj, no line since watch start\n"
    final = w.finish()
    assert [a["kind"] for a in final["alarms"]] == ["empty-trace", "silence-window"]
    assert "still open at exit" in final["alarms"][1]["detail"]


def test_e2_a_raqib_silence_line_is_a_capture_failure_and_is_notified(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"),
                  "RAQIB-SILENCE: capture failed event=PreToolUse log=x: Deadline",
                  rec(2, "pre", 1, tool="Read", input_meta={"path": "/tmp/RAQIB-SILENCE: in a path"})])
    w.step()
    assert [(h["kind"], h["detail"]) for h in w.holes] == [
        ("capture-failed", "line 2 of the trace is a RAQIB-SILENCE line: an event was not captured")]
    assert runner.titles() == ["Raqib: RAQIB-SILENCE"]
    assert runner.calls[0]["text"] == "Raqib: RAQIB-SILENCE\nproject demo-proj, line 2\n"
    assert state_of(w)["holes"][0]["kind"] == "capture-failed"


def test_e2_a_truncated_trace_is_a_hole_and_a_new_epoch_that_keeps_the_old_findings(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, secret_call(1, 0))
    w.step()
    path.write_text(rec(1, "session_start", 9, session="s-new", tool="-") + "\n", encoding="utf-8")
    clock.t += 1
    w.step()
    assert runner.titles() == ["Raqib: SECRET-OUTPUT", "Raqib: TRACE-HOLE"]
    assert runner.calls[1]["text"] == "Raqib: TRACE-HOLE\nproject demo-proj, after line 2\n"
    assert w.epoch == 1 and w.numbered == trace.read_numbered(str(path))[0]
    kinds = [a["kind"] for a in w.alarms()]
    assert kinds == ["trace-truncated", "finding-before-hole"]
    assert "SECRET-OUTPUT [high] session s-watch seq 1" in w.alarms()[1]["detail"]
    final = w.finish()
    assert final["result"] == "alarm" and [f["rule_id"] for f in final["findings"]] == ["SILENCE-OPEN"]


# --- E3: notification backends, with a fake runner (the text is a file, not a string) -------

def test_e3_windows_toast_through_powershell_with_the_text_in_a_file():
    runner = FakeRunner()
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    n = notify.Notifier("C:/Users/someone/demo-proj", platform="win32", runner=runner, isfile=lambda p: p == ps,
                        isdir=lambda p: p == "C:\\Windows",
                        environ={"SystemRoot": "C:\\Windows", "TEMP": "C:\\T", "PATH": "C:\\agent\\bin",
                                 "PSModulePath": "C:\\agent\\modules"}, stderr=io.StringIO())
    assert (n.backend, n.program) == ("windows-toast", ps)
    assert n.notify("SECRET-OUTPUT", "seq 4", 0) == "sent"
    (call,) = runner.calls
    argv = call["argv"]
    assert argv[:6] == [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
    assert len(argv) == 8 and argv[6].endswith("toast.ps1") and os.path.isabs(argv[7])
    assert call["text"] == "Raqib: SECRET-OUTPUT\nproject demo-proj, seq 4\n"
    assert not any("SECRET" in a or "seq 4" in a or "demo-proj" in a for a in argv)
    assert call["env"] == {"SystemRoot": "C:\\Windows", "TEMP": "C:\\T"}
    script = Path(argv[6]).read_text(encoding="ascii")
    for needle in ("[System.IO.File]::ReadAllLines($args[0])",
                   "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
                   " ContentType = WindowsRuntime]",
                   "CreateTextNode($lines[0])", "CreateTextNode($lines[1])",
                   "CreateToastNotifier($app).Show($toast)", "$app = '%s'" % notify.POWERSHELL_APP_ID):
        assert needle in script
    assert not Path(argv[7]).exists()                          # the text file is gone once it was read
    n.close()
    assert not Path(argv[6]).exists()


def test_e3_linux_notify_send_by_absolute_path_with_the_text_in_a_file():
    runner = FakeRunner()
    n = make_notifier(runner, isfile=lambda p: p in ("/bin/notify-send", "/bin/sh"),
                      environ={"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "DISPLAY": ":0",
                               "PATH": "/home/agent/bin", "LD_PRELOAD": "/home/agent/x.so"})
    assert (n.backend, n.program) == ("notify-send", "/bin/notify-send")
    assert n.notify("SILENCE-GAP", "seq 2,3", 0) == "sent"
    (call,) = runner.calls
    assert call["argv"][:4] == ["/bin/sh", "-c", notify.NOTIFY_SEND_SH, "/bin/notify-send"]
    assert len(call["argv"]) == 5 and os.path.isabs(call["argv"][4])
    assert call["text"] == "Raqib: SILENCE-GAP\nproject demo-proj, seq 2,3\n"
    assert not any("SILENCE" in a or "demo-proj" in a for a in call["argv"])
    assert call["env"] == {"LC_ALL": "C", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                           "DISPLAY": ":0"}


def test_e3_darwin_osascript_reads_the_text_file_inside_the_script():
    runner = FakeRunner()
    n = make_notifier(runner, platform="darwin", environ={"HOME": "/Users/x", "PATH": "/agent"})
    assert (n.backend, n.program) == ("osascript", "/usr/bin/osascript")
    assert n.notify("RAQIB-SILENCE", "line 7", 0) == "sent"
    (call,) = runner.calls
    argv = call["argv"]
    assert argv[0] == "/usr/bin/osascript" and len(argv) == 3 and argv[1].endswith("notify.applescript")
    assert call["text"] == "Raqib: RAQIB-SILENCE\nproject demo-proj, line 7\n"
    assert not any("RAQIB-SILENCE" in a or "line 7" in a for a in argv)
    script = Path(argv[1]).read_text(encoding="ascii")
    assert "read (POSIX file (item 1 of argv))" in script and "display notification (item 2 of p)" in script
    assert call["env"] == {"LC_ALL": "C", "HOME": "/Users/x"}
    n.close()


@pytest.mark.skipif(WINDOWS or not os.path.isfile("/bin/sh"), reason="needs /bin/sh")
def test_e3_the_notify_send_script_hands_the_two_lines_to_the_program(tmp_path, monkeypatch):
    seen = tmp_path / "argv.txt"
    fake = tmp_path / "notify-send"
    fake.write_text("#!/bin/sh\nfor a in \"$@\"; do printf '%%s\\n' \"$a\"; done > '%s'\n" % seen)
    fake.chmod(0o755)
    monkeypatch.setattr(notify, "NOTIFY_SEND_PATHS", (str(fake),))
    n = notify.Notifier(PROJECT, environ={}, platform="linux", stderr=io.StringIO())
    assert n.backend == "notify-send" and n.notify("SILENCE-LIVE open", "after line 3, seq 2", 0) == "sent"
    assert seen.read_text().splitlines() == ["--app-name=Raqib", "--urgency=critical", "--",
                                             "Raqib: SILENCE-LIVE open", "project demo-proj, after line 3, seq 2"]
    n.close()


def test_e3_no_notifier_program_rings_the_bell_and_writes_stderr():
    runner, err = FakeRunner(), io.StringIO()
    n = make_notifier(runner, isfile=lambda p: False, stderr=err)
    assert n.backend == "terminal" and n.notify("SILENCE-GAP", "seq 2,3", 0) == "terminal"
    assert runner.calls == [] and n.holes == []
    assert err.getvalue() == "\araqib watch: NOTICE Raqib: SILENCE-GAP - project demo-proj, seq 2,3\n"
    assert n.band() == ("incomplete", "notifications: terminal bell and stderr only"
                                      " (no /usr/bin/notify-send or /bin/notify-send)")
    win = make_notifier(runner, platform="win32", environ={"SystemRoot": "C:\\Windows"}, isdir=lambda p: True,
                        isfile=lambda p: False)
    assert win.backend == "terminal" and win.reason.startswith("no C:\\Windows\\System32\\") and win.holes == []


def test_e3_a_delivery_that_fails_is_a_hole_and_falls_back_to_the_bell(tmp_path):
    runner = FakeRunner(result=(1, "/bin/sh exited 1: cannot open display"))
    err = io.StringIO()
    n = make_notifier(runner, stderr=err)
    w, path, clock = make_watch(tmp_path, notifier=n)
    append(path, secret_call(1, 0))
    w.step()
    clock.t += 61
    append(path, secret_call(2, 61))
    w.step()
    assert [e["notice"] for e in w.inventory.values()] == ["failed", "failed"]
    assert err.getvalue().count("\araqib watch: NOTICE Raqib: SECRET-OUTPUT") == 2
    (hole,) = state_of(w)["holes"]
    assert hole["kind"] == "notify-failed" and hole["count"] == 2
    assert hole["detail"] == "notify-send: /bin/sh exited 1: cannot open display"
    page = w.page()
    # M6.2 E2: the band says on or off.
    assert 'class="band"' in page and "notifications: on, 2 not delivered by notify-send" in page
    assert re.search(r'<span class="badge alarm">notifications: on, 2 not delivered', page)
    assert any(a["kind"] == "notify-failed" and "(2 times, last at" in a["detail"] for a in w.finish()["alarms"])


def test_e3_off_under_ci_and_with_no_notify():
    runner = FakeRunner()
    ci = make_notifier(runner, environ={"CI": "true"})
    assert ci.backend == "off" and ci.notify("SECRET-OUTPUT", "seq 1", 0) == "off" and ci.tick(999) == []
    assert ci.band() == ("incomplete", "notifications: off (CI is set: no notification is shown in CI)")
    off = make_notifier(runner, enabled=False, reason="--no-notify")
    assert off.notify("SILENCE-LIVE open", "x", 0) == "off" and off.band()[1] == "notifications: off (--no-notify)"
    assert runner.calls == [] and ci.state()["counts"]["off"] == 1


def test_e3_notification_text_is_rule_project_and_seq_never_agent_content(tmp_path):
    runner = FakeRunner()
    n = notify.Notifier("/work/demo;$(touch x)`id`\n", environ={}, platform="linux", runner=runner,
                        isfile=lambda p: True, stderr=io.StringIO())
    w, path, clock = make_watch(tmp_path, gap=5, notifier=n)
    hostile = "s-\x1b[2J\nRESULT: CLEAN <b>"
    append(path, [rec(1, "session_start", 0, session=hostile, tool="-",
                      cwd="/home/agent/$(curl evil)/`rm -rf ~`")] +
           secret_call(2, 1, session=hostile, cwd="/etc/passwd; rm -rf ~"))
    append(path, b"RAQIB-SILENCE: capture failed log=/home/agent/$(evil): boom\n")
    w.step()
    clock.t += 10
    w.step()
    assert len(runner.calls) == 4
    for call in runner.calls:
        assert re.fullmatch(r"Raqib: [A-Z][A-Z-]*( open| closed)?\nproject [A-Za-z0-9 ._,:+()-]+\n", call["text"])
        for bad in ("passwd", "rm", "curl", "evil", "RESULT", "<", "$", "`", "\x1b", hostile):
            assert bad not in call["text"].split("\n", 1)[1].replace("project demo", "")
    assert sorted(c["text"] for c in runner.calls) == [
        "Raqib: RAQIB-SILENCE\nproject demo__(touch x)_id__, line 4\n",
        "Raqib: SECRET-OUTPUT\nproject demo__(touch x)_id__, seq 2\n",
        "Raqib: SILENCE-LIVE open\nproject demo__(touch x)_id__, after line 4\n",
        "Raqib: SILENCE-OPEN\nproject demo__(touch x)_id__, seq 2\n"]      # settled by the window (B-1)


def test_e3_run_program_refuses_a_bare_name_and_never_signals(tmp_path):
    assert notify.run_program(["notify-send", "x"], {})[1].startswith("['notify-send'] is not an absolute path")
    assert notify.run_program([sys.executable, "-c", "pass"], {"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
                              if WINDOWS else {}) == (0, None)
    code, error = notify.run_program([sys.executable, "-c", "import sys; sys.stderr.write('no bus'); sys.exit(3)"],
                                     {"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")} if WINDOWS else {})
    assert code == 3 and error.endswith("exited 3: no bus")
    code, error = notify.run_program([sys.executable, "-c", "import time; time.sleep(3)"],
                                     {"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")} if WINDOWS else {},
                                     timeout=0.2)
    assert code is None and error.endswith("did not exit within 0.2 s; it was left running, not signalled (A4)")
    code, error = notify.run_program([str(tmp_path / "missing")], {})
    assert code is None and error.startswith("%s could not be started: " % (tmp_path / "missing"))


# --- E4: the rate limit ------------------------------------------------------------------

def test_e4_one_notification_per_rule_per_minute_the_rest_folded_into_a_count():
    runner = FakeRunner()
    n = make_notifier(runner)
    assert n.notify("SECRET-OUTPUT", "seq 1", 0) == "sent"
    assert [n.notify("SECRET-OUTPUT", "seq %d" % s, 10 + s) for s in (2, 3, 4)] == ["folded"] * 3
    assert n.notify("SILENCE-GAP", "seq 5,6", 20) == "sent"   # another rule is not held back
    assert n.state()["folded_waiting"] == {"SECRET-OUTPUT": 3}
    assert n.tick(59.9) == []
    assert n.tick(60) == [("SECRET-OUTPUT", 3, "sent")]
    assert runner.calls[-1]["text"] == "Raqib: SECRET-OUTPUT\nproject demo-proj, 3 more (first seq 2, last seq 4)\n"
    assert n.notify("SECRET-OUTPUT", "seq 9", 100) == "folded"
    assert n.notify("SECRET-OUTPUT", "seq 10", 120) == "sent"  # a fresh one carries the waiting count
    assert runner.calls[-1]["text"] == "Raqib: SECRET-OUTPUT\nproject demo-proj, seq 10, and 1 more (seq 9)\n"
    assert n.tick(1000) == [] and len(runner.calls) == 4
    assert n.state()["counts"] == {"sent": 4, "terminal": 0, "failed": 0, "folded": 4, "off": 0}


def test_e4_watch_folds_a_burst_and_sends_the_count_after_the_minute(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    for seq in range(1, 6):
        append(path, secret_call(seq, seq * 2))
        clock.t += 1
        w.step()
    assert runner.titles() == ["Raqib: SECRET-OUTPUT"]
    assert [e["notice"] for e in w.inventory.values()] == ["sent"] + ["folded"] * 4
    clock.t += 60
    w.step()
    assert runner.calls[-1]["text"] == "Raqib: SECRET-OUTPUT\nproject demo-proj, 4 more (first seq 2, last seq 5)\n"
    assert "SECRET-OUTPUT: 4 more, folded into one notification (sent)" in w.out.getvalue()
    # D-4: what became of each folded knock is written back to its finding.
    assert [e["notice"] for e in w.inventory.values()] == ["sent"] + ["folded: sent as 4 more"] * 4
    assert [f["notice"] for f in state_of(w)["findings"]] == ["sent"] + ["folded: sent as 4 more"] * 4


# --- E1: the command -------------------------------------------------------------------

@pytest.fixture
def home(_home):
    return _home


def run_watch(monkeypatch, argv, actions=()):
    """`raqib watch` with a fake poll wait: each wait runs the next action
    with the page server; when none is left, Ctrl-C."""
    servers = []
    real = ui.make_server

    def make(page, port, **kw):   # M6.2: routes (GET /discover) and refresh pass through
        server = real(page, port, **kw)
        servers.append(server)
        return server
    monkeypatch.setattr(ui, "make_server", make)
    queue = list(actions)

    def fake_sleep(seconds):
        assert seconds == watch.POLL_SECONDS
        if not queue:
            raise KeyboardInterrupt
        queue.pop(0)(servers[0])
    monkeypatch.setattr(watch, "_sleep", fake_sleep)
    out = io.StringIO()
    code = cli.main([str(a) for a in argv], out=out)
    return code, out.getvalue()


def project_files(proj):
    return sorted(p.relative_to(proj).as_posix() for p in proj.rglob("*") if p.is_file())


def test_e1_watch_installs_tails_serves_and_prints_the_final_report(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    pages = []

    def agent_works(server):
        append(trace_path, [rec(1, "session_start", 0, tool="-")] + secret_call(2, 1) +
               [rec(3, "pre", 3, input_meta={"command_head": "rm"}), rec(3, "post", 4), rec(4, "stop", 5, tool="-")])

    def look(server):
        status, page = fetch("http://127.0.0.1:%d/" % server.server_address[1])
        assert status == 200
        pages.append(page)

    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"],
                          [agent_works, look])
    assert code == 1
    assert "install-hooks: " in out and out.count(" added\n") == 6
    assert "  trace: %s (watch default, outside the project)" % trace_path in out
    assert "FINDING [high] SECRET-OUTPUT session s-watch seq 2: Bash output at seq 2 matched" in out
    assert "(off)" in out and "FINDING [medium] DESTRUCT-CMD session s-watch seq 3" in out
    assert "(not notified: severity medium)" in out
    assert "raqib watch: page http://127.0.0.1:" in out and "page not opened (--no-open)" in out
    assert out.index("Raqib watch\n") < out.index("Raqib report\n") < out.index("RESULT: ALARM (exit 1)")
    assert "notifications: off (--no-notify)" in pages[0] and "SECRET-OUTPUT" in pages[0]
    assert "Content-Security-Policy" in pages[0] and "<script" not in pages[0]
    assert project_files(proj) == [".claude/settings.json"]   # nothing else written into the project
    installer = watch.load_installer()
    assert installer.installed_traces(str(proj)) == [str(trace_path)]
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    assert st["status"] == "finished" and st["records"] == 6 and st["url"].startswith("http://127.0.0.1:")
    assert {(e["rule_id"], e["notice"]) for e in st["findings"]} >= {
        ("SECRET-OUTPUT", "off"), ("DESTRUCT-CMD", "not notified: severity medium")}
    assert st["notifications"]["backend"] == "off" and st["notifications"]["reason"] == "--no-notify"
    # Again: the install is idempotent and keeps the trace.
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    assert code == 1 and out.count(" unchanged\n") == 6 and "(file not rewritten)" in out
    assert "  trace: %s (kept from the existing install)" % trace_path in out
    # B-3: the first run's lines are history now: shown, counted, not knocked.
    assert "] 2 prior findings in the trace, not knocked (lines 1-6 were there at the start" in out
    assert "FINDING [" not in out and "PRIOR FINDINGS (history, in the trace at the start, not knocked): 2" in out
    assert project_files(proj) == [".claude/settings.json"]


def test_e1_a_log_inside_the_project_is_refused(tmp_path, home, monkeypatch, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    code, _ = run_watch(monkeypatch, ["watch", proj, "--log", proj / "t.jsonl", "--no-open", "--no-notify"])
    assert code == 2 and "is inside the project" in capsys.readouterr().err
    assert project_files(proj) == []
    code, _ = run_watch(monkeypatch, ["watch", tmp_path / "nowhere", "--no-open", "--no-notify"])
    assert code == 2 and "not a directory" in capsys.readouterr().err


def test_e1_an_earlier_trace_inside_the_project_is_moved_out(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    installer = watch.load_installer()
    result = installer.install_project(str(proj), out=io.StringIO())
    old = proj / "raqib.log.jsonl"
    assert result["trace"] == str(old) and result["trace_source"] == "default"
    old.write_text(rec(1, "session_start", 0, tool="-") + "\n", encoding="utf-8")
    before = old.read_bytes()
    log = tmp_path / "elsewhere" / "trace.jsonl"
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    trace_path = watch.default_trace(os.path.normpath(str(proj)), str(home))
    assert "raqib watch: note: the trace an earlier install chose, %s, is inside the project;" % old in out
    assert installer.installed_traces(str(proj)) == [trace_path] and old.read_bytes() == before
    assert out.count(" updated\n") == 6 and "  replaced: " in out
    code, out = run_watch(monkeypatch, ["watch", proj, "--log", log, "--no-open", "--no-notify", "--port", "0"])
    assert installer.installed_traces(str(proj)) == [str(log)] and "  trace: %s (--log)" % log in out
    assert project_files(proj) == [".claude/settings.json", "raqib.log.jsonl"]


def test_e1_disabled_hooks_are_a_capture_failure(tmp_path, home, monkeypatch, capsys):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text('{"disableAllHooks": true}\n', encoding="utf-8")
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    assert code == 1 and "RAQIB-SILENCE: the installer reports disableAllHooks" in out
    assert "RAQIB-SILENCE: disableAllHooks is true in " in capsys.readouterr().err
    assert "  - capture-failed: the installer reports disableAllHooks: the hooks will not run at " in out


def test_e1_the_page_is_opened_once_and_not_under_ci(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    opened = []
    monkeypatch.setattr(watch, "open_page", lambda url, environ=None: opened.append(url))
    monkeypatch.delenv("CI", raising=False)
    noop = [lambda server: None] * 3
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-notify", "--port", "0"], noop)
    assert len(opened) == 1 and "raqib watch: page %s " % opened[0] in out
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(notify, "run_program", lambda *a, **k: pytest.fail("a program ran under CI"))
    code, out = run_watch(monkeypatch, ["watch", proj, "--port", "0"], noop)
    assert len(opened) == 1 and "page not opened (CI is set)" in out
    assert "raqib watch: notifications: off (CI is set: no notification is shown in CI)" in out


def test_b7_a_busy_port_gives_another_port_and_a_warning(tmp_path, home, monkeypatch):
    asked = []
    real = ui.make_server

    def busy(page, port, **kw):
        asked.append(port)
        if port in (watch.DEFAULT_PORT, 4242):
            raise OSError(98, "Address already in use")
        return real(page, port, **kw)
    monkeypatch.setattr(ui, "make_server", busy)
    server, port = watch._serve(lambda: "", None)
    server.server_close()
    assert asked == [watch.DEFAULT_PORT, 0] and port["requested"] == watch.DEFAULT_PORT
    assert port["warning"] == ("port %d on 127.0.0.1 is not available (Address already in use); the page is on"
                               " port %d instead" % (watch.DEFAULT_PORT, port["used"]))
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr(watch, "_sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))
    out = io.StringIO()
    code = cli.main(["watch", str(proj), "--no-open", "--no-notify", "--port", "4242"], out=out)
    text = out.getvalue()
    assert code == 1 and "raqib watch: WARNING: port 4242 on 127.0.0.1 is not available" in text
    assert "WARNING: port 4242" in text.split("Raqib watch\n", 1)[1]           # and in the final report
    trace_path = watch.default_trace(os.path.normpath(str(proj)), str(home))
    st = json.loads(Path(trace_path + ".watch.json").read_text(encoding="ascii"))
    assert st["port"]["requested"] == 4242 and st["port"]["used"] != 4242 and "4242" in st["port"]["warning"]


def test_e1_open_page_runs_the_opener_by_absolute_path_without_waiting():
    calls = []

    def runner(argv, env, timeout, wait=True):
        calls.append((argv, env, wait))
        return None, None
    url = "http://127.0.0.1:8765/"
    environ = {"DISPLAY": ":0", "PATH": "/home/agent/bin", "BROWSER": "/home/agent/fake", "HOME": "/home/u"}
    assert watch.open_page(url, environ, "linux", lambda p: p == "/bin/xdg-open", runner) is None
    assert calls[-1] == (["/bin/xdg-open", url], {"PATH": watch.OPENER_PATH, "DISPLAY": ":0", "HOME": "/home/u"},
                         False)
    assert watch.open_page(url, {"SystemRoot": "C:\\Windows"}, "win32", lambda p: True, runner,
                           isdir=lambda p: True) is None
    assert calls[-1][0] == ["C:\\Windows\\explorer.exe", url]
    assert watch.open_page(url, {}, "darwin", lambda p: True, runner) is None
    assert calls[-1][0] == ["/usr/bin/open", url]
    assert watch.open_page(url, environ, "linux", lambda p: False, runner) == "no /usr/bin/xdg-open or /bin/xdg-open"
    assert len(calls) == 3


def test_e1_watch_and_notify_signal_nothing_and_run_programs_by_absolute_path_only():
    banned = ("kill", "killpg", "send_signal", "terminate", "ptrace", "system", "popen", "startfile", "which",
              "execv", "execve", "execvp", "execvpe", "execl", "execlp", "spawnv", "spawnvp", "posix_spawn",
              "posix_spawnp", "urlopen", "create_connection", "open_new", "open_new_tab")
    runs, trees = [], {}
    for name in ("watch.py", "notify.py"):
        tree = trees[name] = ast.parse((ROOT / "raqib" / name).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Call):
                f = node.func
                called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                assert called not in banned, (name, called)
                assert not any(k.arg == "shell" for k in node.keywords)
                if isinstance(f, ast.Attribute) and getattr(f.value, "id", None) == "subprocess":
                    runs.append((name, f.attr, node))
        assert not imported & {"socket", "ssl", "urllib", "signal", "ctypes", "asyncio", "webbrowser", "shutil",
                               "anthropic", "http"}, name
        assert imported - {"raqib", "__future__"} <= set(sys.stdlib_module_names)
    # One program start in both files: Popen in notify.run_program, behind the absolute-path check.
    assert [(n, a) for n, a, _ in runs] == [("notify.py", "Popen")]
    (fn,) = [n for n in ast.walk(trees["notify.py"]) if isinstance(n, ast.FunctionDef) and n.name == "run_program"]
    assert runs[0][2] in list(ast.walk(fn)) and "os.path.isabs(argv[0])" in ast.unparse(fn)
    assert "kill" not in ast.unparse(fn) and "terminate" not in ast.unparse(fn)
    for path in notify.NOTIFY_SEND_PATHS + (notify.SH, notify.OSASCRIPT, watch.MAC_OPENER) + watch.OPENERS:
        assert path.startswith("/")


# --- the installer API (tools/install_hooks.py, API only) --------------------------------

def test_installer_api_prints_what_the_command_prints(tmp_path, home):
    proj = tmp_path / "proj"
    proj.mkdir()
    installer = watch.load_installer()
    assert installer.installed_traces(str(proj)) == []
    out = io.StringIO()
    log = tmp_path / "out" / "t.jsonl"
    result = installer.install_project(str(proj), log=str(log), log_source="--log", out=out)
    assert result["code"] == 0 and result["trace"] == str(log) and result["changed"] is True
    assert [s for _, s in result["events"]] == ["added"] * 6
    assert out.getvalue().startswith("install-hooks: %s\n" % (proj / ".claude" / "settings.json"))
    assert "  trace: %s (--log)\n" % log in out.getvalue()
    assert installer.installed_traces(str(proj)) == [str(log)]
    with pytest.raises(installer.Exit) as exc:
        installer.installed_traces(str(tmp_path / "missing"))
    assert exc.value.code == 2


# --- ui: the band hook -------------------------------------------------------------------

def test_ui_band_is_escaped_and_the_a6_byte_for_byte_rule_is_retired(tmp_path):
    """M6.2 I-9: A-6's "the page without a band is unchanged byte for byte"
    is retired by a dated note: one builder, so the band-less page changes
    too (findings by severity). The band hook itself still adds only the band."""
    adr = (ROOT / "docs" / "specs" / "ADR-0005-one-command-watch.md").read_text(encoding="utf-8")
    assert "(Note 2026-11-03, M6.2, ruling I-9: the byte-for-byte rule is retired." in adr
    numbered, problems = trace.read_numbered(str(REAL_TRACES[0]))
    found, notes = cli.run_rules([r for _, r in numbered], RULES, {}, 60)
    rep = report.build("t", numbered, problems, found, notes, report.rule_table(RULES), "rules")
    plain = ui.render(rep, numbered, problems, 60)
    b_numbered, b_problems = trace.read_numbered(str(BLOCKED))                   # the band-less page changed:
    b_found, b_notes = cli.run_rules([r for _, r in b_numbered], RULES, {}, 60)
    blocked = ui.render(report.build("b", b_numbered, b_problems, b_found, b_notes, report.rule_table(RULES), "rules"),
                        b_numbered, b_problems, 60)
    assert "<h3>high (" in blocked and 'class="band"' not in blocked
    assert ui.render(rep, numbered, problems, 60, band=None) == plain == ui.render(rep, numbered, problems, 60, [])
    assert 'class="band"' not in plain
    page = ui.render(rep, numbered, problems, 60, band=[("alarm", "<script>x</script>\n"), ("odd", "ok")])
    assert '<p class="band"><span class="badge alarm">&lt;script&gt;x&lt;/script&gt;?</span>' in page
    assert '<span class="badge incomplete">ok</span></p>' in page and "<script" not in page
    assert page.replace(page[page.index('<p class="band">'):page.index("</p>", page.index('<p class="band">')) + 5],
                        "") == plain


# --- E5: the README ------------------------------------------------------------------------

def test_e5_readme_watch_a_project_in_three_lines():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## Watch a project\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in section.split("\n") if line.strip()]
    assert len(lines) == 3 and "raqib watch" in lines[0] and "--no-notify" in lines[1]
    assert "final report" in lines[2]
    # B-8 and B-3
    assert "by default under `~/.raqib/traces/`" in lines[0] and "`HANDOFF.md`" in lines[0]
    assert lines[1].startswith("High findings knock once settled")
    assert "already in the trace when watch starts are history" in lines[1]


# --- REDO: ADR-0005 Amendment B ----------------------------------------------------------

def blocked_lines():
    return BLOCKED.read_bytes().split(b"\n")   # 7 lines, then "" after the last newline


def test_b1_pending_halves_settle_on_a_later_stop_and_both_knock(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    lines = blocked_lines()
    append(path, b"\n".join(lines[:5]) + b"\n")                  # start, pre 2, pre 3, pre and post 4
    w.step()
    states = sorted((e["rule_id"], e["cited_seq"], e["state"]) for e in w.inventory.values())
    assert states == [("SILENCE-HALF", [2], "pending"), ("SILENCE-HALF", [3], "pending"),
                      ("SILENCE-OPEN", [4], "pending")] and runner.calls == []
    append(path, b"\n".join(lines[5:]))                          # stop, session_end
    clock.t += 1
    w.step()
    halves = [e for e in w.inventory.values() if e["rule_id"] == "SILENCE-HALF"]
    assert [(e["cited_seq"], e["state"], e["settled_by"], e["notice"]) for e in halves] == [
        ([2], "settled", "a later stop or session_end of its session", "sent"),
        ([3], "settled", "a later stop or session_end of its session", "folded")]
    assert "SILENCE-OPEN" not in {e["rule_id"] for e in w.inventory.values()}   # the stop took it back
    clock.t += 60
    w.step()                                                      # the folded half goes out after the minute
    assert [c["text"] for c in runner.calls] == [
        "Raqib: SILENCE-HALF\nproject demo-proj, seq 2\n",
        "Raqib: SILENCE-HALF\nproject demo-proj, 1 more (seq 3)\n"]
    assert [e["notice"] for e in halves] == ["sent", "folded: sent as 1 more"]      # D-4
    assert "settled by a later stop or session_end of its session" in w.out.getvalue()


def test_b1_pending_findings_settle_when_the_live_silence_window_opens(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, b"\n".join(blocked_lines()[:5]) + b"\n")       # the session never stops
    w.step()
    clock.t += 6
    w.step()
    assert runner.titles() == ["Raqib: SILENCE-LIVE open", "Raqib: SILENCE-HALF", "Raqib: SILENCE-OPEN"]
    settled = [(e["rule_id"], e["cited_seq"], e["notice"], e["settled_by"]) for e in w.inventory.values()]
    assert settled == [("SILENCE-HALF", [2], "sent", "the live silence window"),
                       ("SILENCE-HALF", [3], "folded", "the live silence window"),
                       ("SILENCE-OPEN", [4], "sent", "the live silence window")]
    append(path, [rec(9, "pre", 20, session="b3744113-5956-4e40-915a-91c245a2ece7")])
    clock.t += 1
    w.step()                                                      # SILENCE-OPEN grew: the same finding, not a new knock
    assert runner.titles().count("Raqib: SILENCE-OPEN") == 1


def test_b2_two_silence_order_shapes_on_the_same_seqs_are_two_findings(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    # The third line takes no new seq ("seq went back", cites [max seq, seq]) and is
    # earlier than the line before it ("time went back", cites [previous seq, seq]): [1, 1] both.
    append(path, [rec(1, "pre", 10), rec(1, "post", 11), rec(1, "pre", 5)])
    w.step()
    orders = [e for e in w.inventory.values() if e["rule_id"] == "SILENCE-ORDER"]
    assert [e["cited_seq"] for e in orders] == [[1, 1], [1, 1]]
    assert sorted("seq went back" in e["summary"] for e in orders) == [False, True]
    assert sorted("time went back" in e["summary"] for e in orders) == [False, True]
    assert [e["notice"] for e in orders] == ["sent", "folded"] and orders[0]["key"] != orders[1]["key"]
    assert len([f for f in state_of(w)["findings"] if f["rule_id"] == "SILENCE-ORDER"]) == 2
    assert w.out.getvalue().count("FINDING [high] SILENCE-ORDER") == 2


def test_b3_lines_in_the_trace_at_start_are_history_and_never_knock(tmp_path):
    runner = FakeRunner()
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    past = [*secret_call(1, 0, session="s-old"), "RAQIB-SILENCE: capture failed long ago", "{torn",
            rec(1, "pre", 1, session="s-live", input_meta={"command_head": "cat"})]
    path.write_bytes(BLOCKED.read_bytes() + ("\n".join(past) + "\n").encode())
    w, _, clock = make_watch(tmp_path, runner=runner)
    w.step()
    assert runner.calls == []
    prior = [e for e in w.inventory.values() if e["history"]]
    assert sorted((e["rule_id"], e["cited_seq"]) for e in prior) == [
        ("SECRET-OUTPUT", [1]), ("SILENCE-HALF", [1]), ("SILENCE-HALF", [2]), ("SILENCE-HALF", [3])]
    assert all(e["notice"] in (watch.HISTORY_NOTICE, None) for e in prior)
    out = w.out.getvalue()
    assert out.count("4 prior findings in the trace, not knocked (lines 1-12 were there at the start") == 1
    assert "FINDING" not in out and "TRACE-HOLE" not in out and "RAQIB-SILENCE at" not in out
    assert [(h["kind"], h["history"]) for h in w.holes] == [("capture-failed", True)]
    assert [p["notice"] for p in state_of(w)["trace_problems"]] == [watch.HISTORY_NOTICE] * 2
    page = w.page()
    assert "SECRET-OUTPUT" in page and "s-old" in page                           # shown, not hidden
    append(path, [rec(1, "post", 30, session="s-live", input_meta={"command_head": "cat"},
                      output_meta={"scan": "full", "secret_kinds": ["github_token"]})])
    clock.t += 1
    w.step()                                                      # its post is new: the finding is not history
    assert runner.titles() == ["Raqib: SECRET-OUTPUT"] and "FINDING [high] SECRET-OUTPUT session s-live" in \
        w.out.getvalue()
    final = w.finish()
    assert {f["session_id"] for f in final["findings"] if f["rule_id"] == "SECRET-OUTPUT"} == {"s-old", "s-live"}


def test_b4_live_parse_problems_knock_as_trace_hole_once_a_minute(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, b"{not json\n" + b"\xff\xfe\n" + b'{"session_id": "s", "seq": "1"}\n')
    w.step()
    assert [c["text"] for c in runner.calls] == ["Raqib: TRACE-HOLE\nproject demo-proj, line 1\n"]
    assert [(p["line"], p["notice"]) for p in state_of(w)["trace_problems"]] == [
        (1, "sent"), (2, "folded"), (2, "folded"), (3, "folded")]
    assert "TRACE-HOLE line 2: invalid UTF-8; not JSON (folded)" in w.out.getvalue()
    clock.t += 60
    w.step()
    assert runner.calls[-1]["text"] == "Raqib: TRACE-HOLE\nproject demo-proj, 2 more (first line 2, last line 3)\n"
    assert [(p["line"], p["notice"], p["knocked_as"]) for p in state_of(w)["trace_problems"]] == [
        (1, "sent", "TRACE-HOLE"), (2, "folded: sent as 2 more", "TRACE-HOLE"),
        (2, "folded: sent as 2 more", "TRACE-HOLE"), (3, "folded: sent as 2 more", "TRACE-HOLE")]


def test_b4_the_heartbeat_is_written_on_every_poll_and_a_stale_one_reads_as_crashed(tmp_path):
    w, path, clock = make_watch(tmp_path)
    w.step()
    first = state_of(w)
    clock.t += 0.5
    w.step()                                                      # nothing new, written anyway
    second = state_of(w)
    assert (first["heartbeat"], second["heartbeat"]) == ("2026-11-02T12:00:00.000Z", "2026-11-02T12:00:00.500Z")
    assert second["stale_after_seconds"] == watch.STALE_SECONDS and w.band()[0][0] == "clean"
    clock.t += watch.STALE_SECONDS + 1
    # M6.2 I-3: the C-4 texts are the detail line of the state word.
    assert w.status_word() == ("CAPTURE FAILED", "alarm",
                               "CRASHED or stuck: no heartbeat for 31 s (last at 2026-11-02T12:00:00.500Z)")
    assert "CRASHED or stuck: no heartbeat for 31 s" in w.page()
    w.finish(status="crashed", error="RuntimeError: x")
    assert w.status_word() == ("FINISHED", "alarm", "CRASHED: RuntimeError: x") and state_of(w)["status"] == "crashed"


def test_b4_a_page_that_cannot_get_the_state_says_the_watch_is_not_responding(tmp_path, monkeypatch):
    monkeypatch.setattr(watch, "PAGE_LOCK_SECONDS", 0.05)
    w, path, clock = make_watch(tmp_path)
    server = ui.make_server(w.page, 0)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with w.lock:                                              # the watch loop holds its state
            status, page = fetch("http://127.0.0.1:%d/" % server.server_address[1])
        assert status == 500 and "raqib watch is not responding" in page and "ALARM" in page
        assert fetch("http://127.0.0.1:%d/" % server.server_address[1])[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_b4_an_exception_ends_in_finish_crashed_and_the_final_report(tmp_path, home, monkeypatch, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))

    def work(server):
        append(trace_path, secret_call(1, 0))

    def boom(server):
        raise RuntimeError("boom in the loop")
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"], [work, boom])
    assert code == 1 and "raqib watch: CRASHED: RuntimeError: boom in the loop" in out
    assert "watch-crashed: the watch ended on an exception: RuntimeError: boom in the loop" in out
    assert out.index("Raqib watch\n") < out.index("RESULT: ALARM (exit 1)")
    assert "SECRET-OUTPUT" in out.split("Raqib report\n", 1)[1]
    st = json.loads(Path(str(trace_path) + ".watch.json").read_text(encoding="ascii"))
    assert (st["status"], st["error"]) == ("crashed", "RuntimeError: boom in the loop") and st["finished"]
    assert "Traceback" in capsys.readouterr().err


def test_b5_scripts_are_checked_by_sha256_before_every_use_and_rewritten(home):
    for name, text in notify.SCRIPTS.items():
        assert notify.SCRIPT_SHA256[name] == __import__("hashlib").sha256(text.encode("ascii")).hexdigest()
    used = []

    def runner(argv, env, timeout, wait=True):
        used.append(Path(argv[1]).read_text(encoding="ascii"))
        return 0, None
    n = make_notifier(runner, platform="darwin")
    assert n.notify("EVENT-A", "seq 1", 0) == "sent"
    script = Path(n.tmpdir) / "notify.applescript"
    assert Path(n.tmpdir).parent == home / ".raqib" / "tmp"       # never the cwd, never the system temp
    script.write_text('display dialog "a same-user process swapped me"\n')
    assert n.notify("EVENT-B", "seq 2", 1) == "sent"
    script.unlink()
    assert n.notify("EVENT-C", "seq 3", 2) == "sent"
    assert used == [notify.OSA_SCRIPT] * 3                        # what ran is always the in-code script
    assert [h["kind"] for h in n.holes] == ["script-changed", "script-changed"]
    assert "not its in-code %s" % notify.SCRIPT_SHA256["notify.applescript"] in n.holes[0]["detail"]
    assert "was gone" in n.holes[1]["detail"]


def test_b5_no_temp_directory_but_under_raqib_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    n = make_notifier(FakeRunner(), tmp_root="relative/tmp")
    assert n.notify("EVENT-A", "seq 1", 0) == "failed"
    assert n.holes[0]["detail"] == ("notify-send: cannot prepare the notification files: the temp directory"
                                    " 'relative/tmp' is not an absolute path (is HOME set?)")
    assert not (tmp_path / "relative").exists()


def test_b5_systemroot_must_be_an_existing_directory_named_windows():
    cases = [({"SystemRoot": "C:\\Users\\agent\\fake"}, lambda p: True),
             ({"SystemRoot": "C:\\Windows"}, lambda p: False), ({}, lambda p: True)]
    for environ, isdir in cases:
        runner = FakeRunner()
        n = make_notifier(runner, platform="win32", environ=environ, isdir=isdir)
        assert n.backend == "off" and [h["kind"] for h in n.holes] == ["notify-off"]
        assert n.notify("SECRET-OUTPUT", "seq 1", 0) == "off" and runner.calls == []
        assert n.band() == ("incomplete", "notifications: off (%s)" % n.reason)
    ok = make_notifier(FakeRunner(), platform="win32", environ={"SystemRoot": "C:\\WINDOWS\\"}, isdir=lambda p: True)
    assert ok.backend == "windows-toast" and ok.holes == []


def test_b6_the_project_handoff_scope_is_the_context_and_a_clean_watch_ends_clean(tmp_path, home, monkeypatch):
    # M5.1b C-1: runs on Windows too; a project cwd there is a judged negative
    # for SCOPE-CWD-ROOT and its HANDOFF root a valid context root (E2).
    proj = tmp_path / "proj"
    proj.mkdir()
    handoff = proj / "HANDOFF.md"
    handoff.write_text("# HANDOFF\n\nScope:\n  src/, tests/\n\nExit criteria: none\n", encoding="utf-8")
    trace_path = Path(watch.default_trace(os.path.normpath(str(proj)), str(home)))
    cwd = str(proj)
    rows = [rec(1, "session_start", 0, tool="-", cwd=cwd),
            rec(2, "pre", 1, tool="Read", cwd=cwd, input_meta={"path": cwd + "/src/a.py"}),
            rec(2, "post", 2, tool="Read", cwd=cwd, input_meta={"path": cwd + "/src/a.py"}),
            rec(3, "stop", 3, tool="-", cwd=cwd), rec(4, "session_end", 4, tool="-", cwd=cwd)]
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"],
                          [lambda server: append(trace_path, rows)])
    assert "raqib watch: scope: %s Scope: src/, tests/ (root %s), as report --handoff" % (handoff, proj) in out
    assert "RULES THAT DID NOT RUN: 0" in out and "RESULT: CLEAN (exit 0)" in out and code == 0
    assert cli.main(["report", str(trace_path), "--handoff", str(handoff)], out=io.StringIO()) == 0
    # Without the HANDOFF.md the same watch is incomplete: DRIFT-FILES needs a scope.
    handoff.unlink()
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    assert code == 3 and "raqib watch: scope: no HANDOFF.md in the project" in out
    assert "DRIFT-FILES not-evaluated: needs context: scope" in out


# --- REDO 2: ADR-0005 Amendment D (each change with a test for what it adds, D-8) --------------

def test_d1_after_a_reset_every_line_is_live_the_window_closes_and_raqib_silence_knocks(tmp_path):
    runner = FakeRunner()
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    # 6 lines of history; not the 7th, a session_end, after which no window opens (M6.2 I-2)
    path.write_bytes(b"\n".join(blocked_lines()[:6]) + b"\n")
    w, _, clock = make_watch(tmp_path, gap=5, runner=runner)
    w.step()
    assert w.history_line == 6 and runner.calls == []
    clock.t += 6
    w.step()                                                      # a live window opens
    assert runner.titles() == ["Raqib: SILENCE-LIVE open"]
    path.write_bytes((rec(1, "session_start", 20, session="s-new", tool="-") +
                      "\nRAQIB-SILENCE: capture failed\n{torn\n").encode())   # truncated: new content
    clock.t += 1
    w.step()
    assert runner.titles() == ["Raqib: SILENCE-LIVE open", "Raqib: TRACE-HOLE", "Raqib: SILENCE-LIVE closed",
                               "Raqib: RAQIB-SILENCE", "Raqib: TRACE-HOLE"]
    assert runner.calls[2]["text"] == "Raqib: SILENCE-LIVE closed\nproject demo-proj, line 1, seq 1\n"
    assert runner.calls[3]["text"] == "Raqib: RAQIB-SILENCE\nproject demo-proj, line 2\n"
    assert (w.windows[0]["closed_by_line"], w.windows[0]["notice_closed"]) == (1, "sent")
    st = state_of(w)
    assert (st["epoch"], st["history"]["bytes"], st["history"]["lines"]) == (1, 0, 0)
    assert [(p["line"], p["history"], p["knocked_as"], p["notice"]) for p in st["trace_problems"]] == [
        (2, False, "RAQIB-SILENCE", "sent"), (3, False, "TRACE-HOLE", "sent")]
    assert [(h["kind"], h["history"], h["notice"]) for h in st["holes"]] == [
        ("trace-truncated", False, "sent"), ("capture-failed", False, "sent")]


def test_d2_a_second_silence_open_after_a_stop_is_a_new_finding_printed_and_knocked(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, gap=5, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1)])   # a long call starts
    w.step()
    clock.t += 6
    w.step()                                                      # longer than the gap: OPEN settles, knocks
    append(path, [rec(2, "post", 7), rec(3, "stop", 8, tool="-")])
    clock.t += 1
    w.step()                                                      # the stop takes it back
    append(path, [rec(4, "pre", 70)])                             # the next turn, over a minute later
    clock.t += 64
    w.step()
    opens = [e for e in w.inventory.values() if e["rule_id"] == "SILENCE-OPEN"]
    assert [(e["cited_seq"], e["state"], e["present"], e["notice"]) for e in opens] == [
        ([2], "settled", False, "sent"), ([4], "pending", True, None)]   # not adopted (D-2)
    clock.t += 6
    w.step()                                                      # its own window
    assert (opens[1]["state"], opens[1]["notice"], opens[1]["settled_by"]) == (
        "settled", "sent", "the live silence window")
    assert w.out.getvalue().count("FINDING [high] SILENCE-OPEN") == 2
    assert [c["text"] for c in runner.calls if c["text"].startswith("Raqib: SILENCE-OPEN")] == [
        "Raqib: SILENCE-OPEN\nproject demo-proj, seq 2\n", "Raqib: SILENCE-OPEN\nproject demo-proj, seq 4\n"]


def test_d3_open_page_checks_systemroot_as_notify_does():
    calls = []

    def runner(argv, env, timeout, wait=True):
        calls.append(argv)
        return None, None
    url = "http://127.0.0.1:8765/"
    assert watch.open_page(url, {"SystemRoot": "C:\\Users\\agent\\Windows2"}, "win32", lambda p: True, runner,
                           isdir=lambda p: True).startswith("SystemRoot 'C:\\\\Users\\\\agent\\\\Windows2' is not")
    assert watch.open_page(url, {"SystemRoot": "C:\\Windows"}, "win32", lambda p: True, runner,
                           isdir=lambda p: False).endswith("is not an existing directory named Windows, so no"
                                                           " program under it is trusted")
    assert watch.open_page(url, {}, "win32", lambda p: True, runner) == (
        "SystemRoot is not set, so no program under it can be placed")
    assert calls == []
    assert watch.open_page(url, {"SystemRoot": "C:\\Windows"}, "win32", lambda p: True, runner,
                           isdir=lambda p: True) is None
    assert calls == [["C:\\Windows\\explorer.exe", url]]


def test_d4_a_fold_is_written_back_with_its_outcome_and_names_first_and_last_seq(tmp_path):
    runner = FakeRunner(results=[(0, None), (1, "/bin/sh exited 1: no bus")])
    w, path, clock = make_watch(tmp_path, runner=runner)
    for seq in (1, 2, 3):
        append(path, secret_call(seq, seq * 2))
        clock.t += 1
        w.step()
    assert [e["notice"] for e in w.inventory.values()] == ["sent", "folded", "folded"]
    clock.t += 60
    w.step()                                                      # the fold goes out, and fails
    assert runner.calls[-1]["text"] == "Raqib: SECRET-OUTPUT\nproject demo-proj, 2 more (first seq 2, last seq 3)\n"
    assert [e["notice"] for e in w.inventory.values()] == ["sent", "folded: failed as 2 more",
                                                           "folded: failed as 2 more"]
    assert [f["notice"] for f in state_of(w)["findings"]][1:] == ["folded: failed as 2 more"] * 2
    assert notify.fold_text(1, "seq 7", "seq 7") == "1 more (seq 7)"


def test_d5_a_call_hung_at_start_knocks_when_a_live_stop_settles_it(tmp_path):
    runner = FakeRunner()
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("\n".join([rec(1, "session_start", 0, tool="-"), rec(2, "pre", 1)]) + "\n", encoding="utf-8")
    w, _, clock = make_watch(tmp_path, runner=runner)
    w.step()
    (half,) = [e for e in w.inventory.values() if e["rule_id"] == "SILENCE-HALF"]
    assert (half["state"], half["history"]) == ("pending", True) and runner.calls == []
    append(path, [rec(3, "stop", 5, tool="-")])                   # the live stop settles the old call
    clock.t += 1
    w.step()
    assert (half["state"], half["history"], half["notice"], half["settled_by"]) == (
        "settled", False, "sent", "a later stop or session_end of its session")
    assert runner.titles() == ["Raqib: SILENCE-HALF"]
    assert "FINDING [high] SILENCE-HALF session s-watch seq 2" in w.out.getvalue()


def test_d6_a_live_raqib_silence_line_is_labelled_live_and_a_history_one_history(tmp_path):
    runner = FakeRunner()
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("RAQIB-SILENCE: from before the start\n", encoding="utf-8")
    w, _, clock = make_watch(tmp_path, runner=runner)
    w.step()
    append(path, [rec(1, "session_start", 1, tool="-"), "RAQIB-SILENCE: capture failed now"])
    clock.t += 1
    w.step()
    assert runner.titles() == ["Raqib: RAQIB-SILENCE"]
    assert [(p["line"], p["history"], p["knocked_as"], p["notice"]) for p in state_of(w)["trace_problems"]] == [
        (1, True, None, watch.HISTORY_NOTICE), (3, False, "RAQIB-SILENCE", "sent")]
    assert [(h["history"], h["notice"]) for h in state_of(w)["holes"]] == [(True, watch.HISTORY_NOTICE),
                                                                          (False, "sent")]


def test_d6_tail_holes_and_parse_problems_have_separate_rate_limit_ids(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-"), rec(2, "stop", 1, tool="-")])
    w.step()
    path.write_text(rec(1, "session_start", 2, tool="-") + "\n", encoding="utf-8")   # a tail hole
    clock.t += 1
    w.step()
    append(path, b"{torn\n")                                     # a parse problem 1 s later
    clock.t += 1
    w.step()
    append(path, b"{torn again\n")                               # and another: this one folds
    clock.t += 1
    w.step()
    assert [c["text"] for c in runner.calls] == ["Raqib: TRACE-HOLE\nproject demo-proj, after line 2\n",
                                                 "Raqib: TRACE-HOLE\nproject demo-proj, line 2\n"]
    assert state_of(w)["notifications"]["folded_waiting"] == {watch.PARSE_LIMIT: 1}


@pytest.mark.parametrize("broken", ["_write_state", "report", "summary_text"])
def test_d7_finish_always_gives_a_final_report_or_a_one_line_reason(tmp_path, monkeypatch, broken):
    w, path, clock = make_watch(tmp_path)
    append(path, secret_call(1, 0))
    w.step()

    def boom(*a, **k):
        raise RuntimeError("broken %s" % broken)
    monkeypatch.setattr(w, broken, boom)
    w.finish()
    text = w.final_text
    if broken == "_write_state":
        assert "Raqib watch\n" in text and text.rstrip().endswith("RESULT: ALARM (exit 1)") and w.final_exit == 1
        assert "cannot write" in w.state_error and "broken _write_state" in w.state_error
    elif broken == "report":
        assert "raqib watch: no final report: it could not be built (RuntimeError: broken report)\n" in text
        assert w.final_exit == 1
    else:
        assert text.startswith("raqib watch: no watch summary: it could not be built (RuntimeError: broken"
                               " summary_text)\n") and "RESULT: ALARM (exit 1)" in text


def test_d7_a_finish_that_raises_still_ends_in_one_line(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()

    def boom(self, *a, **k):
        raise RuntimeError("finish broke")
    monkeypatch.setattr(watch.Watch, "finish", boom)
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    assert code == 1 and out.endswith("\nraqib watch: no final report: RuntimeError: finish broke\n")


def test_d7_the_scope_note_goes_through_safe(tmp_path, home, monkeypatch):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "HANDOFF.md").write_text("Scope:\n  \x1b[2Jsrc/\x07, tests/\n", encoding="utf-8")
    code, out = run_watch(monkeypatch, ["watch", proj, "--no-open", "--no-notify", "--port", "0"])
    line = [l for l in out.splitlines() if l.startswith("raqib watch: scope: ")][0]
    assert "\x1b" not in out and "\x07" not in out and "Scope: ?[2Jsrc/?, tests/" in line


# --- M4.1 E3 (ADR-0002): the findings watch keeps carry their kind ----------------

def test_m41_e3_watch_findings_carry_their_rule_kind(tmp_path):
    from raqib.rules import silence
    kinds = dict({r.id: r.kind for r in RULES}, **silence.RULE_KINDS)
    w, path, clock = make_watch(tmp_path)
    append(path, secret_call(1, 0) + [rec(2, "pre", 2, cwd="/work/other"), rec(2, "post", 3, cwd="/work/other"),
                                      rec(3, "post", 4)])
    w.step()
    entries = state_of(w)["findings"]
    assert {e["rule_id"] for e in entries} >= {"SECRET-OUTPUT", "SCOPE-CWD-MOVED", "SILENCE-HALF"}
    assert all(e["kind"] == kinds[e["rule_id"]] for e in entries), entries
    assert {e["kind"] for e in entries} == {"signature", "demand", "anchor"}
    assert [e["kind"] for e in w.inventory.values()] == [e["kind"] for e in entries]


def test_m41_b3_a_finding_without_kind_is_a_notice_in_watch_and_an_alarm_in_its_report(tmp_path):
    """K5 (A3): watch says it once; the report it builds raises no-kind."""
    def evaluate(records):
        found, notes = cli.run_rules(records, RULES, {}, 60)
        return [{k: v for k, v in f.items() if k != "kind"} if f["rule_id"] == "SECRET-OUTPUT" else f
                for f in found], notes
    path = tmp_path / "traces" / "raqib.log.jsonl"
    path.parent.mkdir(parents=True)
    clock = Clock()
    w = watch.Watch(PROJECT, str(path), evaluate, RULES, 60, make_notifier(), out=io.StringIO(),
                    err=io.StringIO(), clock=clock, started=START)
    append(path, secret_call(1, 0))
    w.step()
    append(path, [rec(2, "pre", 2), rec(2, "post", 3)])
    clock.t += 1
    w.step()
    notices = [x for x in w.out.getvalue().splitlines() if "NOTICE no-kind" in x]
    assert len(notices) == 1, w.out.getvalue()
    assert notices[0].endswith("NOTICE no-kind: SECRET-OUTPUT session s-watch seq 1 has no kind (ADR-0002); the"
                               " report raises a no-kind alarm")
    (entry,) = [e for e in state_of(w)["findings"] if e["rule_id"] == "SECRET-OUTPUT"]
    assert entry["kind"] is None
    rep = w.report()[0]
    assert [a["kind"] for a in rep["alarms"]] == ["no-kind"] and "SECRET-OUTPUT" in rep["alarms"][0]["detail"]
    assert all(f["rule_id"] != "SECRET-OUTPUT" for f in rep["findings"])


# --- M4.2 REDO-2 E-3: SILENCE-EMPTY in watch (one knock, on the end line) ------

def test_m42_redo2_e3_silence_empty_knocks_once_on_the_end_line_and_not_on_a_later_start(tmp_path):
    runner = FakeRunner()
    w, path, clock = make_watch(tmp_path, runner=runner)
    append(path, [rec(1, "session_start", 0, tool="-")])
    w.step()
    assert runner.calls == [] and {e["rule_id"]: e["state"] for e in w.inventory.values()} == {
        "SILENCE-OPEN": "pending"}
    append(path, [rec(2, "session_end", 1, tool="-")])           # the end line: settled at once (D-7)
    clock.t += 1
    w.step()
    assert runner.titles() == ["Raqib: SILENCE-EMPTY"]
    (empty,) = [e for e in w.inventory.values() if e["rule_id"] == "SILENCE-EMPTY"]
    assert (empty["cited_seq"], empty["state"], empty["settled_by"], empty["severity"]) == (
        [1, 2], "settled", "its lines", "high")
    append(path, [rec(3, "session_start", 2, tool="-")])         # the same session id starts again
    clock.t += 1
    w.step()
    assert runner.titles() == ["Raqib: SILENCE-EMPTY"]            # no second knock (E-3: same cited_seq)
    assert empty["present"] and empty["cited_seq"] == [1, 2]
    assert {e["rule_id"]: e["state"] for e in w.inventory.values()} == {
        "SILENCE-EMPTY": "settled", "SILENCE-OPEN": "pending"}
    assert w.out.getvalue().count("FINDING [high] SILENCE-EMPTY") == 1
