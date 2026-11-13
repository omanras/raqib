"""ADR-0011 Amendments J to N: `raqib forward`, the forwarder over HTTP. Every collector here is the rig's stand-in
(tools/rig/collector.py) on loopback, on a port it bound itself, stopped and joined by the fixture; a collector
that is down holds its port bound and listens on nothing, and a test that needs a port it never connects to takes
one of those. Every clock and wait the forwarder has is injected where a test needs time to pass; where a test
waits for another thread or process, it waits for the collector's or the state's own facts, never for a time to
pass. A bound on real time is the proof of a mechanism, at least five times the mechanism's own. No thread of the
forwarder outlives its test (a fixture fails the test that leaves one, and only that test), and no forwarder's
run is on a test's own thread (N-7: every run is on a thread of its own, bounded, stopped at its bound). The
tokens are made-up strings."""
import ast
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from raqib import cli, event, forward

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("rig_collector", ROOT / "tools" / "rig" / "collector.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

TOKEN = "made-up-test-token-not-a-secret-0123"
WRONG = "made-up-wrong-token-not-a-secret-4567"
FACTS = {"run": "r1", "mode": "host", "platform": "linux", "version": "0.1.0", "host": "host.example", "beat": 20.0}
PATH = "/services/collector/event"


def lines(count, start=1, text="note", size=0):
    """Whole lines of raqib-event/1 notes, n from `start`, each with its newline (bytes)."""
    out = []
    for n in range(start, start + count):
        e = event.note({"text": "%s %d%s" % (text, n, "x" * size)}, FACTS, "2026-11-03T07:50:%02d.250Z" % (n % 60), n,
                       "note:%d" % n)
        out.append((event.line(e) + "\n").encode("ascii"))
    return out


def write(path, rows, mode="wb"):
    with open(str(path), mode) as f:
        f.write(b"".join(rows))
    return str(path)


def secret(path, value=TOKEN):
    path = str(path)
    if os.path.exists(path):
        os.chmod(path, 0o600)
        os.remove(path)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    return path


class Clock:
    """The forwarder's clock and wait: no wall clock passes; each wait is recorded and moves the clock."""

    def __init__(self, t=1_800_000_000.0):
        self.t, self.waits, self.then = t, [], None

    def __call__(self):
        return self.t

    def wait(self, seconds):
        self.waits.append(seconds)
        self.t += seconds
        return bool(self.then and self.then(self))


THREADS = "raqib-forward"
LEFT_S = 60.0    # an abandoned send's own socket calls are bounded (30 s at most): the margin is twice that
RUN_S = 120.0    # N-7: a forwarder's run on its own thread is failed and stopped past this
REAL_RUN = forward.Forwarder.run


def left_behind(before, budget=LEFT_S, clock=time.monotonic):
    """N-7: the forwarder's threads alive now that were not alive at the test's start, each joined within one
    budget for them all; the names of those still alive. A thread an earlier test left is in `before`: it was
    that test's failure, and it is neither waited for nor counted again here."""
    new = [t for t in threading.enumerate() if t.name.startswith(THREADS) and t not in before]
    end = clock() + budget
    for t in new:
        t.join(max(0.0, end - clock()))
    return [t.name for t in new if t.is_alive()]


def bounded_run(self, once=False, bound=None):
    """N-7: Forwarder.run as every test here calls it - directly, or through cli.main - on a thread of its own
    (named raqib-forward-run, a daemon), joined within RUN_S; past it, the run is stopped and the test fails.
    A run already on such a thread (run_thread) is the run itself."""
    if threading.current_thread().name.startswith(THREADS + "-run"):
        return REAL_RUN(self, once)
    box = {}

    def body():
        try:
            box["code"] = REAL_RUN(self, once)
        except BaseException as exc:   # handed to the test's thread
            box["error"] = exc
    t = run_thread(body)
    t.join(RUN_S if bound is None else bound)
    if t.is_alive():
        self.stop()
        t.join(30)
        pytest.fail("the forwarder's run did not end within %g s: stopped" % (RUN_S if bound is None else bound))
    if "error" in box:
        raise box["error"]
    return box["code"]


@pytest.fixture(autouse=True)
def no_forwarder_thread_left_behind(monkeypatch):
    """L-4, M-9, N-7: every thread of the forwarder - a send's (an abandoned one included), and a run (each on a
    thread of its own, named raqib-forward-run, a daemon) - has ended when the test ends: the test that leaves
    one alive fails here, and no later test waits for it or fails for it."""
    before = {t for t in threading.enumerate() if t.name.startswith(THREADS)}
    monkeypatch.setattr(forward.Forwarder, "run", bounded_run)
    yield
    assert not left_behind(before)


def run_thread(target):
    """M-9: a run a test must stop, on a daemon thread the fixture above looks for."""
    t = threading.Thread(target=target, name="raqib-forward-run", daemon=True)
    t.start()
    return t


@pytest.fixture
def collectors():
    started = []

    def make(**kw):
        c = collector.Collector(**kw)
        c.start()
        started.append(c)
        return c
    yield make
    for c in started:
        c.stop()


def fwd(tmp_path, path, port, clock=None, scheme="http", **kw):
    kw.setdefault("name", "t")
    clock = clock or Clock()
    kw.setdefault("mono", clock)
    f = forward.Forwarder(kw.pop("name"), path, "%s://127.0.0.1:%d%s" % (scheme, port, PATH), home=str(tmp_path / "home"),
                          out=io.StringIO(), clock=clock, wait=clock.wait, **kw)
    return f


def state(tmp_path, name="t"):
    with open(forward.state_path(name, str(tmp_path / "home")), "rb") as f:
        return json.loads(f.read().decode("ascii"))


class Mute:
    """A listener the test bound: it takes each connection and says `say` (then closes it), or says nothing and
    holds it until the end (a handshake that never ends)."""

    def __init__(self, say=None):
        self.say, self.conns, self.quit = say, [], threading.Event()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, name="raqib-test-mute", daemon=True)
        self.thread.start()

    def serve(self):
        while not self.quit.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            if self.say is not None:
                try:
                    conn.sendall(self.say)
                except OSError:
                    pass
                conn.close()
            else:
                self.conns.append(conn)

    def stop(self):
        self.quit.set()
        self.thread.join()
        self.sock.close()
        for conn in self.conns:
            conn.close()


@pytest.fixture
def mutes():
    made = []

    def make(say=None):
        m = Mute(say)
        made.append(m)
        return m
    yield make
    for m in made:
        m.stop()


def read_state(home, name):
    try:
        with open(forward.state_path(name, home), "rb") as f:
            return json.loads(f.read().decode("ascii"))
    except (OSError, ValueError):
        return None


def order_held(rows, requests):
    """L-1 (MUST NOT TOUCH the order): no taken line is sent before an earlier line that is neither taken nor in
    question; no line is taken twice. The lines taken and the lines refused alone, by index."""
    at = {r: i for i, r in enumerate(rows)}
    taken, question = set(), set()
    for req in requests:
        sent = [at[x + b"\n"] for x in req["body"].split(b"\n")[:-1]]
        if req["status"] == 200:
            assert all(j in taken or j in question for j in range(sent[0])), (sent[0], sorted(taken | question))
            assert not taken & set(sent)
            taken |= set(sent)
        elif len(sent) == 1:
            question.add(sent[0])
    return taken, question


def cursor_held(rows, requests, snaps):
    """M-2, N-7: at every cursor seen - (n, offset): read when n requests had been answered - each line before it
    was taken (in a request answered 200), or refused alone twice with a request answered 200 that holds a LATER
    line between the two, or is not an event (never sent)."""
    at = {r: i for i, r in enumerate(rows)}
    sent = [[at[x + b"\n"] for x in req["body"].split(b"\n")[:-1]] for req in requests]
    end = 0
    for i, row in enumerate(rows):
        end += len(row)
        for n, offset in snaps:
            if end > offset:
                continue
            done = list(zip(sent[:n], [r["status"] for r in requests[:n]]))
            if forward.classify(row) is None or any(st == 200 and i in idx for idx, st in done):
                continue
            no = [k for k, (idx, st) in enumerate(done) if idx == [i] and st not in (200, None)]
            later = [k for k in range(no[0] + 1, no[-1]) if done[k][1] == 200 and max(done[k][0]) > i] if no else []
            assert len(no) >= 2 and later, (i, n, offset)   # N-7: the take of a LATER line between


# --- E1 (J-1, J-2) ---------------------------------------------------------------------------------------------

def imports(path):
    out = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out |= {node.module} | {node.module + "." + a.name for a in node.names}
    return out


def test_e1_the_capture_path_imports_nothing_of_the_forwarder_and_the_forwarder_only_the_standard_library():
    """J-1: host.py, eventlog.py, event.py and raqib/hooks/ reach nothing of raqib.forward, by any chain of raqib's
    own imports (a function's import included); the forwarder imports the standard library and raqib only."""
    def module_file(name):
        p = ROOT.joinpath(*name.split("."))
        return p / "__init__.py" if p.is_dir() else p.with_suffix(".py")
    start = ["raqib.host", "raqib.eventlog", "raqib.event"] + [
        "raqib.hooks." + p.stem for p in (ROOT / "raqib" / "hooks").glob("*.py") if p.stem != "__init__"]
    seen, todo = set(), list(start)
    while todo:   # every chain but the command line's dispatch (raqib.cli, reached by the window's functions)
        name = todo.pop()
        if name in seen or name == "raqib.cli" or not module_file(name).is_file():
            continue
        seen.add(name)
        todo += [m for m in imports(module_file(name)) if m.startswith("raqib")]
    assert "raqib.host" in seen and "raqib.hooks.proxy" in seen and "raqib.forward" not in seen
    for name in seen:
        assert "forward" not in {m.rsplit(".", 1)[-1] for m in imports(module_file(name))}, name
    code = ("import sys, raqib.host, raqib.eventlog, raqib.event, raqib.hooks.capture, raqib.hooks.proxy,"
            " raqib.hooks.os_sysmon; print(sorted(m for m in sys.modules if m.startswith('raqib.forward')))")
    got = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert got.returncode == 0 and got.stdout.decode("ascii").strip() == "[]", got.stderr
    tops = {m.split(".")[0] for m in imports(ROOT / "raqib" / "forward.py")}
    assert tops - set(sys.stdlib_module_names) == {"raqib"}, tops
    assert "urllib.request" not in imports(ROOT / "raqib" / "forward.py")   # urllib would read the proxies


def test_e1_a_redirect_is_a_failed_send_and_is_not_followed(tmp_path, collectors):
    c = collectors(token_file=secret(tmp_path / "c.tok"), redirect=True)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, shape="hec", token_file=secret(tmp_path / "t"))
    assert f.step() == "failed" and f.offset == 0
    assert f.failing["error"] == "redirect" and f.failing["status"] == 302
    assert len(c.requests) == 1 and c.events == []   # its Location was never asked


def test_e1_a_proxy_named_in_the_environment_is_not_used(tmp_path, collectors, monkeypatch):
    dead = "http://127.0.0.1:%d" % collectors(down=True).port   # bound by the test, nothing listening
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(key, dead)
    for key in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(key, raising=False)
    c = collectors(token_file=secret(tmp_path / "c.tok"), shape="raqib")
    rows = lines(3)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, token_file=secret(tmp_path / "t"))
    assert f.step() == "moved" and f.failing is None
    assert c.events == [r.decode("ascii")[:-1] for r in rows]


# --- E2 (J-3, J-5, J-11, J-12) ---------------------------------------------------------------------------------

def test_e2_every_whole_line_arrives_in_order_at_most_100_lines_to_a_request(tmp_path, collectors):
    c = collectors(shape="raqib")
    rows = lines(250)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.run(once=True) == 0
    assert [r["body"].count(b"\n") for r in c.requests] == [100, 100, 50]
    assert b"".join(r["body"] for r in c.requests) == b"".join(rows)
    assert f.offset == len(b"".join(rows)) and state(tmp_path)["sent"] == 250


def test_e2_at_most_512_kib_to_a_request(tmp_path, collectors):
    c = collectors(shape="raqib")
    rows = lines(60, size=20000)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.run(once=True) == 0
    assert len(c.requests) >= 3 and all(len(r["body"]) <= 512 * 1024 for r in c.requests)
    assert b"".join(r["body"] for r in c.requests) == b"".join(rows)


def test_e2_a_batch_answered_503_is_sent_again_whole_and_nothing_after_it_before_it(tmp_path, collectors):
    c = collectors(shape="raqib", fail=1, fail_status=503)
    rows = lines(25)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, batch=10)
    assert f.step() == "failed" and f.offset == 0 and f.failing["error"] == "server" and f.failing["status"] == 503
    assert f.step() == "moved" and f.offset == len(b"".join(rows[:10])) and f.failing is None
    assert c.requests[0]["body"] == c.requests[1]["body"] == b"".join(rows[:10])
    assert f.run(once=True) == 0 and c.events == [r.decode("ascii")[:-1] for r in rows]


def test_e2_a_line_not_json_or_not_an_event_is_skipped_counted_never_sent(tmp_path, collectors):
    c = collectors(shape="raqib")
    good = lines(4)
    rows = good[:2] + [b"{\"torn\n", b'{"schema":"raqib-event/1","kind":"note"}\n'] + good[2:]
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.run(once=True) == 0
    assert c.events == [r.decode("ascii")[:-1] for r in good]
    assert not any(b"torn" in r["body"] or b'"kind":"note"}' in r["body"] for r in c.requests)
    assert state(tmp_path)["skipped"] == 2 and state(tmp_path)["sent"] == 4


def test_e2_a_last_line_with_no_newline_waits_and_is_sent_when_its_newline_comes(tmp_path, collectors):
    c = collectors(shape="raqib")
    rows = lines(2)
    path = write(tmp_path / "e.jsonl", [rows[0], rows[1][:-1]])
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "moved" and f.step() == "idle" and len(c.events) == 1
    assert state(tmp_path)["behind"] == 0
    write(path, [b"\n"], mode="ab")
    assert f.step() == "moved" and c.events == [r.decode("ascii")[:-1] for r in rows]


def test_e2_a_file_shorter_than_the_cursor_or_whose_last_line_changed_is_read_again_and_counted(tmp_path, collectors):
    c = collectors(shape="raqib")
    path = write(tmp_path / "e.jsonl", lines(5))
    f = fwd(tmp_path, path, c.port)
    assert f.run(once=True) == 0 and f.restarts == 0
    write(path, lines(2, start=10))                       # shorter than the cursor
    assert f.step() == "moved" and f.restarts == 1 and len(c.events) == 7
    write(path, lines(2, start=10) + lines(1, start=12))  # one more line, then the last one passed changes
    assert f.step() == "moved" and f.restarts == 1 and len(c.events) == 8
    write(path, lines(2, start=10) + lines(1, start=12, text="eton"))
    assert len(b"".join(lines(1, start=12, text="eton"))) == len(b"".join(lines(1, start=12)))
    assert f.step() == "moved" and f.restarts == 2 and state(tmp_path)["restarts"] == 2
    assert "read again from its start, restart 2" in f.out.getvalue()


def test_e2_from_end_starts_at_the_files_end_and_the_state_says_from_which_offset(tmp_path, collectors):
    c = collectors(shape="raqib")
    rows = lines(5)
    path = write(tmp_path / "e.jsonl", rows + [b'{"half'])
    f = fwd(tmp_path, path, c.port, start="end")
    assert f.run(once=True) == 0 and c.requests == []
    s = state(tmp_path)
    assert s["from"] == {"start": "end", "offset": len(b"".join(rows))} == {"start": "end", "offset": s["cursor"]["offset"]}
    write(path, [b'"}\n'] + lines(2, start=6), mode="ab")
    again = fwd(tmp_path, path, c.port, start="end")
    assert again.run(once=True) == 0 and len(c.events) == 2 and state(tmp_path)["skipped"] == 1
    assert state(tmp_path)["from"]["offset"] == len(b"".join(rows))


# --- E3 (J-4) --------------------------------------------------------------------------------------------------

def test_e3_a_batch_answered_400_is_sent_line_by_line_and_the_refused_line_is_counted_kept_and_passed(tmp_path,
                                                                                                       collectors):
    c = collectors(shape="raqib", refuse={"r1:3"})
    rows = lines(6)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.run(once=True) == 1   # not all taken
    assert c.events == [r.decode("ascii")[:-1] for i, r in enumerate(rows) if i != 2]
    assert [r["status"] for r in c.requests] == [400, 200, 200, 400, 200, 400, 200, 200]   # M-2: 3 asked again
    s = state(tmp_path)
    assert s["refused"] == {"count": 1, "ids": ["r1:3"]} and s["cursor"]["offset"] == len(b"".join(rows))
    assert s["sent"] == 5 and s["failing"] is None


def test_e3_the_latest_50_refused_ids_are_kept(tmp_path, collectors):
    refuse = ["r1:%d" % n for n in range(1, 61)]
    c = collectors(shape="raqib", refuse=set(refuse))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(65)), c.port)
    assert f.run(once=True) == 1
    s = state(tmp_path)
    assert s["refused"]["count"] == 60 and s["refused"]["ids"] == refuse[10:] and len(c.events) == 5


def test_e3_401_and_403_move_nothing_and_a_token_file_corrected_between_two_tries_is_read_again(tmp_path, collectors):
    c = collectors(token_file=secret(tmp_path / "c.tok"))
    tok = secret(tmp_path / "t", WRONG)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, shape="hec", token_file=tok)
    assert f.step() == "failed" and f.offset == 0 and (f.failing["error"], f.failing["status"]) == ("token", 403)
    assert state(tmp_path)["failing"]["error"] == "token"
    secret(tok, TOKEN)
    assert f.step() == "moved" and len(c.events) == 3 and f.failing is None
    c401 = collectors(token_file=secret(tmp_path / "c.tok"), fail=1, fail_status=401)
    g = fwd(tmp_path, write(tmp_path / "e2.jsonl", lines(3)), c401.port, name="u", shape="hec", token_file=tok)
    assert g.step() == "failed" and g.offset == 0 and (g.failing["error"], g.failing["status"]) == ("token", 401)


@pytest.mark.parametrize("kind,how,word", [
    ("408", {"fail": 1, "fail_status": 408}, "busy"), ("429", {"fail": 1, "fail_status": 429}, "busy"),
    ("500", {"fail": 1, "fail_status": 500}, "server"), ("503", {"fail": 1, "fail_status": 503}, "server"),
    ("no answer", {"fail": 1, "fail_status": None}, "no-answer"), ("late", {"late": 2.0}, "late"),
    ("down", None, "connect")])
def test_e3_408_429_5xx_no_answer_a_late_answer_and_no_collector_are_failed_sends(tmp_path, collectors, kind, how,
                                                                                    word):
    port = collectors(shape="raqib", **(how or {"down": True})).port
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), port, answer_s=0.3)
    assert f.step() == "failed" and f.offset == 0 and f.sent == 0 and f.failing["error"] == word
    assert state(tmp_path)["failing"]["tries"] == 1 and state(tmp_path)["cursor"]["offset"] == 0


# --- E4 (J-6) --------------------------------------------------------------------------------------------------

def test_e4_shape_raqib_the_body_is_the_lines_as_the_file_holds_them_byte_for_byte(tmp_path, collectors):
    c = collectors(shape="raqib", token_file=secret(tmp_path / "c.tok"))
    rows = lines(7)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, token_file=secret(tmp_path / "t"))
    assert f.run(once=True) == 0
    (req,) = c.requests
    assert req["body"] == b"".join(rows) and req["headers"]["Content-Type"] == "application/x-ndjson"


def test_e4_shape_hec_one_envelope_per_line_the_event_unchanged_and_the_splunk_header(tmp_path, collectors):
    c = collectors(token_file=secret(tmp_path / "c.tok"))
    rows = lines(3)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, shape="hec", token_file=secret(tmp_path / "t"))
    assert f.run(once=True) == 0
    (req,) = c.requests
    assert req["headers"]["Authorization"] == "Splunk " + TOKEN
    envelopes = req["body"].decode("ascii").splitlines()
    assert len(envelopes) == 3
    for raw, env in zip(rows, envelopes):
        obj = json.loads(env)
        assert sorted(obj) == ["event", "host", "source", "sourcetype", "time"]
        assert obj["event"] == json.loads(raw) and raw[:-1].decode("ascii") in env   # the event's bytes, unchanged
        assert (obj["host"], obj["source"], obj["sourcetype"]) == ("host.example", "raqib", "raqib:event")
        assert env.startswith('{"time":%s.250,' % forward.calendar.timegm((2026, 11, 3, 7, 50, obj["event"]["n"] % 60)))


def test_e4_a_200_whose_bodys_code_is_not_0_is_not_taken(tmp_path, collectors):
    c = collectors(token_file=secret(tmp_path / "c.tok"), code=7)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, shape="hec", token_file=secret(tmp_path / "t"))
    assert f.step() == "failed" and f.offset == 0 and (f.failing["error"], f.failing["status"]) == ("answer", 200)


# --- E5 (J-7, J-8) ---------------------------------------------------------------------------------------------

def test_e5_the_token_is_in_no_output_state_error_or_argument_list(tmp_path, collectors, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    good = collectors(token_file=secret(tmp_path / "c.tok"))
    busy = collectors(token_file=secret(tmp_path / "c2.tok"), fail=100)
    path = write(tmp_path / "e.jsonl", lines(4))
    tok, wrong = secret(tmp_path / "t"), secret(tmp_path / "w", WRONG)
    said, codes = [], []
    for name, port, token in (("ok", good.port, tok), ("wrong", good.port, wrong), ("busy", busy.port, tok)):
        out = io.StringIO()
        argv = ["forward", path, "--to", "http://127.0.0.1:%d%s" % (port, PATH), "--name", name, "--shape", "hec",
                "--token-file", token, "--once"]
        codes.append(cli.main(argv, out=out))
        said += [out.getvalue(), " ".join(argv)]
        out = io.StringIO()
        codes.append(cli.main(["forward", "--status", name], out=out))
        said.append(out.getvalue())
    assert codes == [0, 0, 1, 1, 1, 1]
    said += list(capsys.readouterr())
    said += [p.read_text(encoding="ascii") for p in (tmp_path / "home" / ".raqib" / "forward").glob("*.json")]
    assert len(said) == 14 and "failing: token" in said[3] and "failing: server" in said[6]
    for secret_text in (TOKEN, WRONG):
        assert not [s for s in said if secret_text in s]
    options = [o for a in cli._parser()._subparsers._group_actions[0].choices["forward"]._actions
               for o in a.option_strings]
    assert [o for o in options if "token" in o] == ["--token-file"]


@pytest.mark.skipif(sys.platform == "win32", reason="J-7: on Windows a token file's mode is not checked (the guide"
                                                    " says so)")
def test_e5_off_windows_a_token_file_others_can_read_is_exit_2(tmp_path, capsys, collectors):
    tok = secret(tmp_path / "t")
    os.chmod(tok, 0o644)
    port = collectors(down=True).port
    argv = ["forward", write(tmp_path / "e.jsonl", lines(1)), "--to", "http://127.0.0.1:%d%s" % (port, PATH), "--name", "m",
            "--token-file", tok, "--once"]
    assert cli.main(argv, out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert "others can read it (mode 644)" in err and TOKEN not in err
    os.chmod(tok, 0o640)
    with pytest.raises(forward.UsageError, match="others can read it"):
        forward.read_token(tok, platform="linux")
    os.chmod(tok, 0o600)
    assert forward.read_token(tok, platform="linux") == TOKEN


def certificates(tmp_path):
    """A test authority and a certificate for 127.0.0.1 it signed, made with openssl; skipped with the reason
    where the machine has none."""
    tool = shutil.which("openssl")
    if not tool:
        pytest.skip("openssl is not on this machine: the certificate cannot be made here")
    d = tmp_path / "pki"
    d.mkdir()
    (d / "ext.cnf").write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,"
                               "keyEncipherment\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n"
                               "subjectKeyIdentifier=hash\n", encoding="ascii")
    steps = [["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2",
              "-subj", "/CN=raqib test authority", "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
              "keyUsage=critical,keyCertSign,cRLSign"],
             ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=127.0.0.1"],
             ["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "2", "-out",
              "srv.pem", "-days", "2", "-extfile", "ext.cnf"]]
    for step in steps:
        p = subprocess.run([tool] + step, cwd=str(d), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode:
            pytest.skip("openssl could not make the certificate here: %s" % p.stderr.decode("ascii", "replace")[:200])
    return str(d / "ca.pem"), str(d / "srv.pem"), str(d / "srv.key")


def test_e5_https_is_verified_by_the_systems_authorities_or_ca_and_nothing_turns_it_off(tmp_path, collectors,
                                                                                         monkeypatch):
    """J-8, and L-5 (REDO E5): with SSLKEYLOGFILE set, a verified send writes no key log."""
    ca, cert, key = certificates(tmp_path)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.delenv(name, raising=False)
    keys = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keys))
    monkeypatch.setenv("PYTHONHTTPSVERIFY", "0")
    monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)   # what that env does
    c = collectors(shape="raqib", cert=cert, key=key)
    path = write(tmp_path / "e.jsonl", lines(2))
    f = fwd(tmp_path, path, c.port, scheme="https")
    assert f.step() == "failed" and f.failing["error"] == "tls" and c.events == []   # the system's: refused
    g = fwd(tmp_path, path, c.port, scheme="https", name="ca", ca=ca)
    assert g.step() == "moved" and len(c.events) == 2 and not g.plain               # --ca: taken
    assert not keys.exists()                                                         # L-5: no TLS secret written
    options = [o for a in cli._parser()._subparsers._group_actions[0].choices["forward"]._actions
               for o in a.option_strings]
    assert not [o for o in options if any(w in o for w in ("verify", "insecure", "unsafe", "no-", "ssl", "tls"))]


def test_e5_plain_http_only_to_loopback_unless_plain_and_then_every_status_says_plain(tmp_path, capsys):
    with pytest.raises(forward.UsageError, match="loopback"):
        forward.destination("http://192.0.2.10/services/collector/event")
    with pytest.raises(forward.UsageError, match="user information"):
        forward.destination("https://user:pw@collector.example/x")
    dest, target = forward.destination("http://192.0.2.10:8088/services/collector/event?channel=c1", plain=True)
    assert dest == {"scheme": "http", "host": "192.0.2.10", "port": 8088, "path": "/services/collector/event"}
    assert target.endswith("?channel=c1")
    f = forward.Forwarder("p", write(tmp_path / "e.jsonl", lines(1)), "http://192.0.2.10:8088/x", plain=True,
                          home=str(tmp_path / "home"), out=io.StringIO(), clock=Clock())
    f.write_state()
    assert state(tmp_path, "p")["plain"] is True and "channel" not in json.dumps(state(tmp_path, "p"))
    out = io.StringIO()
    forward.status("p", home=str(tmp_path / "home"), out=out, clock=Clock())
    assert "plain: not encrypted" in out.getvalue()


def test_redo_e4_a_collector_that_trickles_its_answer_is_late_within_the_bound(tmp_path, collectors):
    """L-4: the whole answer within the bound from the request's last byte, not each read: one byte every 0.2 s
    never lets a read wait 0.6 s, and the send is still late at 0.6 s."""
    assert (forward.CONNECT_S, forward.ANSWER_S) == (10.0, 30.0)
    c = collectors(shape="raqib", trickle=0.2)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), c.port, answer_s=0.6)
    began = time.monotonic()
    assert f.step() == "failed" and (f.failing["error"], f.offset, f.sent) == ("late", 0, 0)
    assert time.monotonic() - began < 10   # the trickle alone would take some 20 s
    assert state(tmp_path)["failing"]["error"] == "late"


def test_redo_e4_a_handshake_that_never_ends_is_late_within_the_connect_bound(tmp_path, mutes):
    m = mutes()   # takes the connection and says nothing: the TLS handshake never ends
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), m.port, scheme="https", connect_s=0.5)
    began = time.monotonic()
    assert f.step() == "failed" and (f.failing["error"], f.offset) == ("late", 0)
    assert time.monotonic() - began < 10   # the connect bound (0.5 s here), never the answer's 30 s
    assert m.conns   # it was connected: the bound held the handshake, not the connect


def test_redo_e4_stop_during_a_send_ends_the_forwarder_within_a_few_seconds_with_the_state_written(tmp_path,
                                                                                                  collectors):
    """M-9: the mechanism is a slice (0.25 s), the abandon's join (0.5 s) and a state written; the bound is ten
    seconds, and without Stop the send would last its 30 s bound (the collector holds it 120 s)."""
    stopped_at = []
    f = None

    def stop(n, headers, body):
        stopped_at.append(time.monotonic())
        f.stop()   # Stop while the collector holds the request
    c = collectors(shape="raqib", late=120.0, on_request=stop)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port)
    written = []
    real = f.write_state
    f.write_state = lambda: (written.append(f.stopped()), real())[1]
    code = f.run()
    took = time.monotonic() - stopped_at[0]
    assert took < 10.0, took
    assert code == 1 and written[-1] is True and state(tmp_path)["cursor"]["offset"] == 0 and c.events == []
    assert not os.path.exists(f.lock_file)


def test_redo_e4_stop_between_the_lines_of_a_refused_batch_sends_no_more(tmp_path, collectors):
    c = collectors(shape="raqib", refuse={"r1:1"})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(5)), c.port)
    real, calls, stopped_at = f.send, [], []

    def send(batch):
        r = real(batch)
        calls.append(len(batch))
        if len(calls) == 2:
            stopped_at.append(time.monotonic())
            f.stop()   # after the first line alone was answered
        return r
    f.send = send
    written = []
    real_write = f.write_state
    f.write_state = lambda: (written.append(f.stopped()), real_write())[1]
    assert f.run() == 1 and len(c.requests) == 2 and calls == [5, 1]   # no line sent after Stop: the count says it
    assert f.offset == 0 and f.refused == 0 and written[-1] is True
    s = state(tmp_path)
    assert s["cursor"]["offset"] == 0 and s["refused"]["count"] == 0 and c.events == []


def test_redo_e4_stop_in_a_wait_of_ten_minutes_ends_it_within_a_few_seconds_by_stop_and_by_a_signals_flag(
        tmp_path, collectors):
    """M-9: the run on a daemon thread, ended in a finally; its own fact (the forwarder entered its wait), never a
    time; the bound (ten seconds) is forty slices, and without Stop the wait lasts ten minutes."""
    rows = lines(2)
    for how in ("stop", "stop_by_signal"):
        c = collectors(shape="raqib")
        f = forward.Forwarder("w" + str(len(how)), write(tmp_path / ("%s.jsonl" % how), rows),
                              "http://127.0.0.1:%d/" % c.port, home=str(tmp_path / "home"), out=io.StringIO(),
                              poll_s=600.0)   # the default wait and clocks: a wait of ten minutes
        entered, real = threading.Event(), f.wait
        f.wait = lambda seconds: (entered.set() if f.sent == 2 and seconds > 1 else None, real(seconds))[1]
        t = run_thread(f.run)
        try:
            assert entered.wait(60), how   # both lines taken, and the forwarder in its wait
            began = time.monotonic()
            getattr(f, how)()
            t.join(10)
            assert not t.is_alive() and time.monotonic() - began < 10.0, how
            assert "stopped: sent 2" in f.out.getvalue()
        finally:
            f.stop()
            t.join(10)


def test_redo_e4_the_waits_run_on_a_clock_that_does_not_step(tmp_path, collectors):
    """L-4: a wall clock set back an hour - during a wait, at a beat - delays nothing; only the state's times
    are the wall's."""
    mono = Clock(5000.0)
    wall = {"back": 0.0}

    def clock():   # the wall moves with the waits, and is set back an hour once
        return 1_800_000_000.0 + (mono.t - 5000.0) - wall["back"]

    def wait(seconds):   # the wall is set back an hour while the forwarder waits, once
        if mono.t > 5007.5 and not wall["back"]:
            wall["back"] = 3600.0
        return mono.wait(seconds)
    c = collectors(shape="raqib")
    f = forward.Forwarder("t", write(tmp_path / "e.jsonl", lines(2)), "http://127.0.0.1:%d/" % c.port,
                          home=str(tmp_path / "home"), out=io.StringIO(), clock=clock, mono=mono, wait=wait,
                          beat=5, poll_s=2.0)
    assert f.mono is mono and f.clock is clock
    seen, beats = [], []
    real = f.write_state

    def write_state():
        seen.append(clock())
        beats.append(mono.t)
        real()
    f.write_state = write_state
    mono.then = lambda m: m.t > 5030
    assert f.run() == 0 and wall["back"] == 3600.0
    assert mono.waits and max(mono.waits) <= 5   # no wait grew by the hour
    assert max(b - a for a, b in zip(beats, beats[1:])) <= 5 and beats[-1] > 5030   # once a beat, across the step
    assert max(seen) - min(seen) > 3000   # the state's own times did step: the wall's


# --- E6 (J-9, J-10, J-13) --------------------------------------------------------------------------------------

def test_e6_the_state_is_written_whole_beside_then_renamed_after_every_batch_and_failure(tmp_path, collectors,
                                                                                         monkeypatch):
    renames, real = [], os.replace
    monkeypatch.setattr(forward.os, "replace", lambda a, b: (renames.append((a, b)), real(a, b))[1])
    c = collectors(shape="raqib", fail=1, token_file=secret(tmp_path / "c.tok"))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(250)), c.port, token_file=secret(tmp_path / "t"))
    assert f.run(once=True) == 1 and len(renames) == 3          # the start, the failure, the end of --once
    assert state(tmp_path)["failing"]["error"] == "server"
    assert f.run(once=True) == 0 and len(renames) == 3 + 5      # the start, three batches, the end
    for temp, final in renames:
        assert os.path.dirname(temp) == os.path.dirname(final) and temp != final and not os.path.exists(temp)
    s = state(tmp_path)
    assert sorted(s) == sorted(forward.KEYS) and s["schema"] == "raqib-forward/1" and s["delivery"] == "acknowledged"
    assert sorted(s["failing"] or {"since": 0, "tries": 0, "error": 0, "status": 0}) == ["error", "since", "status",
                                                                                         "tries"]
    text = (tmp_path / "home" / ".raqib" / "forward" / "t.json").read_text(encoding="ascii")
    assert TOKEN not in text and "Server is busy" not in text and "Success" not in text
    assert "Server is busy" not in f.out.getvalue()


def test_e6_the_state_is_written_at_least_once_a_beat_while_nothing_happens(tmp_path, collectors, monkeypatch):
    times = []
    clock = Clock()
    clock.then = lambda c: c.t > clock_start + 60
    clock_start = clock.t
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(1)), c.port, clock=clock, beat=5, poll_s=1.5)
    real = f.write_state
    monkeypatch.setattr(f, "write_state", lambda: (times.append(clock.t), real())[1])
    assert f.run() == 0
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert times[-1] > clock_start + 60 and len(times) >= 12 and max(gaps) <= 5


def write_state(home, name, now, **change):
    s = {"schema": "raqib-forward/1", "name": name, "pid": 4242, "written": forward.iso(now),
         "destination": {"scheme": "https", "host": "collector.example", "port": 8088, "path": "/x"}, "shape": "hec",
         "delivery": "acknowledged", "plain": False, "file": "/f", "cursor": {"offset": 9, "line_sha256": "a" * 64},
         "from": {"start": "start", "offset": 0}, "beat": 10.0, "sent": 1, "skipped": 0,
         "refused": {"count": 0, "ids": []}, "restarts": 0, "last_id": "r1:1", "last_ok": forward.iso(now),
         "behind": 0, "failing": None}
    s.update(change)
    os.makedirs(forward.forward_dir(home), exist_ok=True)
    with open(forward.state_path(name, home), "w", encoding="ascii") as f:
        json.dump(s, f)


def test_e6_status_exits_0_taken_1_failing_or_behind_3_unreadable_or_older_than_two_beats(tmp_path):
    """J-9, and L-2 (REDO E2): `refusing` is failing; a state written in the future is 3; the lines refused
    are said on every status."""
    home, now = str(tmp_path / "home"), 1_800_000_000.0
    clock = Clock(now)

    def code(name=None, at=now):
        out = io.StringIO()
        return forward.status(name, home=home, out=out, clock=Clock(at)), out.getvalue()
    assert code()[0] == 3                                                # nothing has written a state: silent
    write_state(home, "ok", now, refused={"count": 7, "ids": ["r1:4"]})
    assert code("ok")[0] == 0 and code("ok", now + 20)[0] == 0
    assert code("ok", now + 20.5)[0] == 3 and "more than two beats" in code("ok", now + 21)[1]
    write_state(home, "fail", now, failing={"since": forward.iso(now), "tries": 3, "error": "server", "status": 503})
    assert code("fail") == (1, code("fail")[1]) and "failing since" in code("fail")[1]
    write_state(home, "refusing", now, failing={"since": forward.iso(now), "tries": 1, "error": "refusing",
                                                "status": 404}, last_ok=None, last_id=None, behind=900)
    assert code("refusing")[0] == 1 and "refusing" in code("refusing")[1] and "status 404" in code("refusing")[1]
    write_state(home, "behind", now, behind=500, last_ok=forward.iso(now - 11))
    assert code("behind")[0] == 1 and "wait longer than a beat" in code("behind")[1]
    write_state(home, "fresh", now, behind=500, last_ok=forward.iso(now - 5))
    assert code("fresh")[0] == 0
    write_state(home, "future", now + 0.5)
    assert code("future")[0] == 3 and "in the future" in code("future")[1]
    for name, at in (("ok", now), ("fail", now), ("refusing", now), ("behind", now), ("ok", now + 30),
                     ("future", now)):
        head = code(name, at)[1].splitlines()[0]
        assert head.endswith("; refused %d" % (7 if name == "ok" else 0)), head   # said on every status
    with open(forward.state_path("bad", home), "wb") as f:
        f.write(b"{not json")
    assert code("bad")[0] == 3 and code("none")[0] == 3
    write_state(home, "keys", now, cursor=None)
    assert code("keys")[0] == 3
    assert code()[0] == 3 and clock.t == now   # every state at once: the worst


def test_redo_e2_forward_md_and_the_guide_say_the_status_rule_in_the_codes_words():
    rule = " ".join(forward.STATUS_RULE.split())
    spec_text = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    guide = [r for r in (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").splitlines()
             if r.startswith("| `raqib forward --status")]
    assert rule in spec_text and len(guide) == 1 and rule in guide[0]
    assert "`refusing`" in rule and "in the future" in rule and "no whole line has waited longer than a beat" in rule


def test_e6_the_waits_are_1_2_4_up_to_60_and_it_does_not_give_up(tmp_path, collectors):
    clock = Clock()
    clock.then = lambda c: len(c.waits) >= 10
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), collectors(down=True).port, clock=clock, beat=1000)
    f.post = lambda body, token: forward.Result("failed", "connect")   # no collector, and no time to wait for it
    assert f.run() == 1
    assert clock.waits == [1, 2, 4, 8, 16, 32, 60, 60, 60, 60] and f.failing["tries"] == 10
    assert state(tmp_path)["failing"]["error"] == "connect"


def test_e6_once_exits_0_all_taken_1_not_all_2_usage_and_a_syslog_usage_error_says_so(tmp_path, collectors, capsys,
                                                                                     monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    ok, down = collectors(shape="raqib"), collectors(shape="raqib", fail=10)
    nobody = "http://127.0.0.1:%d/" % collectors(down=True).port
    path = write(tmp_path / "e.jsonl", lines(3))

    def run(*argv):
        return cli.main(["forward", path] + list(argv), out=io.StringIO())
    assert run("--to", "http://127.0.0.1:%d/" % ok.port, "--name", "a", "--once") == 0
    assert run("--to", "http://127.0.0.1:%d/" % down.port, "--name", "b", "--once") == 1
    capsys.readouterr()
    token = secret(tmp_path / "token.txt")   # M10.3b: syslog is built; what it refuses is said (J-6, J-7, J-8)
    for argv in (("--to", "syslog+udp://127.0.0.1:514", "--name", "c", "--token-file", token, "--once"),
                 ("--to", "syslog+tcp://192.0.2.10:514", "--name", "c", "--once"),
                 ("--to", nobody, "--name", "Bad_Name", "--once"),
                 ("--to", nobody, "--once"), ("--name", "c", "--once"),
                 ("--to", nobody, "--name", "c", "--batch", "101", "--once"),
                 ("--to", "ftp://127.0.0.1/", "--name", "c", "--once")):
        assert run(*argv) == 2, argv
    err = capsys.readouterr().err
    assert "syslog carries no token" in err and "plain syslog (udp, tcp) is taken only to a loopback address" in err
    assert "[a-z0-9-]{1,32}" in err and TOKEN not in err


def test_e6_stop_writes_the_state(tmp_path, collectors):
    clock = Clock()
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, clock=clock)
    clock.then = lambda _: (f.stop(), True)[1]   # Stop, while it waits for more lines
    written = []
    real = f.write_state
    f.write_state = lambda: (written.append(f.stopped()), real())[1]
    assert f.run() == 0 and written[-1] is True and f.stopped()
    assert state(tmp_path)["sent"] == 3 and not os.path.exists(f.lock_file)
    assert "stopped: sent 3" in f.out.getvalue()


def test_e6_a_second_forwarder_of_one_name_is_refused_while_the_first_ones_pid_lives(tmp_path, collectors):
    got = threading.Event()
    c = collectors(shape="raqib", on_request=lambda n, h, b: got.set())
    path = write(tmp_path / "e.jsonl", lines(2))
    lock = Path(forward.forward_dir(str(tmp_path / "home"))) / "t.pid"
    lock.parent.mkdir(parents=True)
    lock.write_text("4242\n", encoding="ascii")
    f = fwd(tmp_path, path, c.port, alive=lambda pid: pid == 4242)
    with pytest.raises(forward.UsageError, match=r"a forwarder named t runs \(pid 4242\)"):
        f.run(once=True)
    assert c.requests == [] and lock.read_text(encoding="ascii") == "4242\n"
    g = fwd(tmp_path, path, c.port, alive=lambda pid: False)   # its pid is gone: the name is free again
    assert g.run(once=True) == 0 and not lock.exists()
    got.clear()
    # a real one: a forwarder running as a process of its own (it has sent: the collector says so), and a
    # second of its name here
    home = str(tmp_path / "real")
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    first = subprocess.Popen([sys.executable, "-m", "raqib", "forward", path, "--to", "http://127.0.0.1:%d/" % c.port,
                              "--name", "real"], cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    try:
        assert got.wait(60) and first.poll() is None
        second = forward.Forwarder("real", path, "http://127.0.0.1:%d/" % c.port, home=home, out=io.StringIO())
        with pytest.raises(forward.UsageError, match="a second one of one name is refused"):
            second.run(once=True)
    finally:
        first.kill()
        first.communicate(timeout=30)


# --- E8, E9 ----------------------------------------------------------------------------------------------------

def test_e8_the_spec_the_guide_and_the_threat_model_say_the_forwarder():
    spec_text = (ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8")
    for key in forward.KEYS + ("offset", "line_sha256", "count", "ids", "since", "tries", "error", "status"):
        assert "`%s`" % key in spec_text, key
    flat = " ".join(spec_text.split())
    for said in ("`acknowledged`", "`--shape raqib`", "`--shape hec`", "Authorization: Splunk <token>",
                 "no heartbeat of a host for more than two beats", "application/x-ndjson",
                 "SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR", "in question", "own clock of arrival"):
        assert said in flat, said
    assert "The cursor moves only past lines the collector took" not in flat   # REDO E9: not so
    for word in forward.ERRORS:
        assert "`%s`" % word in spec_text, word
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    rows = [r for r in guide.splitlines() if r.startswith("| `raqib forward")]
    assert len(rows) == 3 and "no heartbeat of a host for more than two beats" in " ".join(rows)
    assert "on Windows it is not checked" in " ".join(rows)
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "### The forwarder (`raqib forward`" in threat
    for said in ("**the token.**", "**the wire.**", "**what the collector learns.**", "**the watched account.**"):
        assert said in threat.lower(), said
    section = threat[threat.index("### The forwarder (`raqib forward`"):threat.index("## 6. Attacks on the watcher")]
    for said in ("SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR", "process list", "forged offset", "pid file",
                 "own clock of arrival"):
        assert said in section, said
    import re
    assert not re.search(r"\bM\d+\.\d+", section)   # no milestone token


def test_e9_the_forwarders_files_are_ascii_and_name_only_loopback_and_documentation_addresses():
    import re
    for path in (ROOT / "raqib" / "forward.py", ROOT / "tools" / "rig" / "collector.py",
                 ROOT / "tools" / "rig" / "forward_run.py", Path(__file__), ROOT / "tests" / "test_forward_rig.py"):
        text = path.read_bytes().decode("ascii")
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            assert ip.startswith(("127.", "192.0.2.", "198.51.100.", "203.0.113.")), (path.name, ip)


# --- REDO E1 (L-1): a refusal is the line's only where the collector shows it takes lines --------------------

def test_redo_e1_a_line_refused_alone_is_counted_and_passed_only_after_a_later_line_is_taken(tmp_path, collectors):
    rows = lines(3)
    f = None
    seen = []
    c = collectors(shape="raqib", refuse={"r1:2"},
                   on_request=lambda n, h, b: seen.append((n, b.count(b"\n"), f.refused, f.offset)))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.step() == "moved"
    a, b = len(rows[0]), len(rows[0] + rows[1])
    assert [r["status"] for r in c.requests] == [400, 200, 400, 200, 400]   # the batch, a, b alone, c, b again
    assert seen == [(0, 3, 0, 0), (1, 1, 0, 0), (2, 1, 0, a), (3, 1, 0, a), (4, 1, 0, a)]   # b asked twice unpassed
    assert c.events == [rows[0].decode("ascii")[:-1], rows[2].decode("ascii")[:-1]]
    assert (f.refused, f.refused_ids, f.offset, f.failing) == (1, ["r1:2"], b + len(rows[2]), None)
    assert f.out.getvalue().index("refused alone twice (status 400), a later line taken between") > 0
    order_held(rows, c.requests)
    cursor_held(rows, c.requests, [(n, off) for n, _, _, off in seen] + [(len(c.requests), f.offset)])


@pytest.mark.parametrize("how,status", [({"fail": 1000, "fail_status": 404}, 404), ({"refuse": {"*"}}, 400)])
def test_redo_e1_a_collector_that_refuses_every_line_moves_nothing_and_is_failing_refusing(tmp_path, collectors, how,
                                                                                           status):
    rows = lines(5)
    c = collectors(shape="raqib", **how)
    path = write(tmp_path / "e.jsonl", rows)
    f = fwd(tmp_path, path, c.port)
    offsets = []
    real = f.write_state
    f.write_state = lambda: (offsets.append(f.offset), real())[1]
    assert f.run(once=True) == 1   # --once: lines in question are not all taken
    assert set(offsets) == {0} and len(offsets) >= 3 and c.events == []
    s = state(tmp_path)
    assert s["cursor"] == {"offset": 0, "line_sha256": None} and s["refused"] == {"count": 0, "ids": []}
    assert (s["failing"]["error"], s["failing"]["status"]) == ("refusing", status) and s["sent"] == 0
    out = io.StringIO()
    assert forward.status("t", home=str(tmp_path / "home"), out=out, clock=Clock()) == 1 and "refusing" in out.getvalue()
    assert "5 line(s) in question from offset 0" in f.out.getvalue()
    c.fail, c.refuse = 0, set()   # the collector put right: every line arrives once, in order
    again = fwd(tmp_path, path, c.port)
    assert again.run(once=True) == 0 and c.events == [r.decode("ascii")[:-1] for r in rows]
    assert state(tmp_path)["refused"]["count"] == 0 and state(tmp_path)["failing"] is None


def test_redo_e1_a_refused_last_line_is_passed_once_a_line_appended_after_it_is_taken_across_a_restart(tmp_path,
                                                                                                      collectors):
    rows = lines(4)
    c = collectors(shape="raqib", refuse={"r1:3"})
    path = write(tmp_path / "e.jsonl", rows[:3])
    f = fwd(tmp_path, path, c.port)
    assert f.run(once=True) == 1
    s = state(tmp_path)
    assert s["cursor"]["offset"] == len(rows[0] + rows[1]) and s["refused"]["count"] == 0
    assert s["failing"]["error"] == "refusing"
    write(path, rows[3:], mode="ab")
    again = fwd(tmp_path, path, c.port)   # a restart: the state's cursor is before the line in question
    assert again.run(once=True) == 1      # K-2: a refused line makes --once 1
    s = state(tmp_path)
    assert s["refused"] == {"count": 1, "ids": ["r1:3"]} and s["cursor"]["offset"] == len(b"".join(rows))
    assert s["failing"] is None and c.events == [rows[i].decode("ascii")[:-1] for i in (0, 1, 3)]
    out = io.StringIO()
    assert forward.status("t", home=str(tmp_path / "home"), out=out, clock=Clock()) == 0


def test_redo_e1_a_batch_of_100_with_several_refused_keeps_the_order_and_counts_each_once(tmp_path, collectors):
    rows = lines(250)
    refused = [3, 50, 51, 99, 100, 150]
    c = collectors(shape="raqib", refuse={"r1:%d" % n for n in refused})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.run(once=True) == 1
    taken, question = order_held(rows, c.requests)
    assert question == {n - 1 for n in refused} and taken == set(range(250)) - question
    assert c.events == [r.decode("ascii")[:-1] for i, r in enumerate(rows) if i + 1 not in refused]
    s = state(tmp_path)
    assert s["refused"] == {"count": 6, "ids": ["r1:%d" % n for n in refused]} and s["sent"] == 244
    assert s["cursor"]["offset"] == len(b"".join(rows)) and s["failing"] is None


def test_redo_e1_the_lines_after_those_in_question_are_read_from_the_file_as_they_are_needed(tmp_path, collectors):
    rows = lines(4, size=200 * 1024)   # two lines fill a request: the third is past what one read holds
    c = collectors(shape="raqib", refuse={"r1:1", "r1:2"})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.step() == "moved" and f.failing is None
    assert [r["body"].count(b"\n") for r in c.requests] == [2, 1, 1, 2, 1, 1]   # M-2: each asked again
    assert (f.refused, f.refused_ids, f.offset) == (2, ["r1:1", "r1:2"], len(b"".join(rows)))
    order_held(rows, c.requests)


def test_redo_e1_the_lines_in_question_of_one_try_are_bounded(tmp_path, collectors):
    c = collectors(shape="raqib", refuse={"r1:%d" % n for n in range(1, 5)})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(6)), c.port)
    f.alone_max = 3
    assert f.step() == "failed" and f.failing["error"] == "refusing" and f.offset == 0
    assert [r["body"].count(b"\n") for r in c.requests] == [6, 1, 1, 1]


# --- REDO E3 (L-3): every failure writes the state; nothing ends the run without it ---------------------------

@pytest.mark.parametrize("how", ["emptied", "readable by others"])
def test_redo_e3_a_token_file_that_fails_its_checks_while_running_is_a_failed_try(tmp_path, collectors, how):
    if how == "readable by others" and sys.platform == "win32":
        pytest.skip("J-7: on Windows a token file's mode is not checked")
    c = collectors(token_file=secret(tmp_path / "c.tok"))
    tok = secret(tmp_path / "t")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, shape="hec", token_file=tok)
    if how == "emptied":
        open(tok, "wb").close()
    else:
        os.chmod(tok, 0o644)
    assert f.step() == "failed" and (f.failing["error"], f.offset) == ("token-file", 0) and c.requests == []
    assert state(tmp_path)["failing"]["error"] == "token-file"
    secret(tok)
    assert f.step() == "moved" and len(c.events) == 3 and f.failing is None


def test_redo_e3_an_unforeseen_error_ends_the_run_with_the_state_written_and_no_traceback(tmp_path, collectors,
                                                                                          capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    c = collectors(token_file=secret(tmp_path / "c.tok"))

    def boom(self, body, token):
        raise RuntimeError("boom " + token)
    monkeypatch.setattr(forward.Forwarder, "post", boom)
    out = io.StringIO()
    argv = ["forward", write(tmp_path / "e.jsonl", lines(3)), "--to", "http://127.0.0.1:%d%s" % (c.port, PATH),
            "--name", "u", "--shape", "hec", "--token-file", secret(tmp_path / "t"), "--once"]
    assert cli.main(argv, out=out) == 1
    said = out.getvalue() + "".join(capsys.readouterr())
    s = read_state(str(tmp_path / "home"), "u")
    assert s["failing"]["error"] == "unforeseen" and s["cursor"]["offset"] == 0
    assert "ended by an error it did not foresee (RuntimeError)" in said
    assert "Traceback" not in said and "boom" not in said and TOKEN not in said and TOKEN not in json.dumps(s)
    assert not os.path.exists(os.path.join(forward.forward_dir(str(tmp_path / "home")), "u.pid"))
# --- REDO E5 (L-5, L-6) ------------------------------------------------------------------------------------------

def test_redo_e5_sslkeylogfile_is_not_honoured_and_verification_is_as_the_default_context(tmp_path, monkeypatch,
                                                                                          collectors):
    keys = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keys))
    f = forward.Forwarder("k", write(tmp_path / "e.jsonl", lines(1)), "https://127.0.0.1:%d/x" % collectors(
                              down=True).port,
                          home=str(tmp_path / "home"), out=io.StringIO())
    assert not keys.exists() and getattr(f.context, "keylog_filename", None) is None
    monkeypatch.delenv("SSLKEYLOGFILE")
    ref = ssl.create_default_context()
    for attr in ("verify_mode", "check_hostname", "verify_flags", "options", "minimum_version", "maximum_version",
                 "protocol"):
        assert getattr(f.context, attr) == getattr(ref, attr), attr
    assert f.context.verify_mode == ssl.CERT_REQUIRED and f.context.check_hostname is True


def test_redo_e5_the_usage_errors_of_l6_are_exit_2_with_their_reason_before_any_send(tmp_path, collectors, capsys,
                                                                                     monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    c = collectors(shape="raqib")
    path = write(tmp_path / "e.jsonl", lines(3))
    url = "http://127.0.0.1:%d/" % c.port

    def run(*argv):
        code = cli.main(["forward", path] + list(argv), out=io.StringIO())
        return code, capsys.readouterr().err
    for argv, reason in (((url + "caf\u00e9",), "printable ASCII"), ((url + "a b",), "no space"),
                         (("http://bad_name.example/",), "no valid name"), (("https://-x.example/",), "no valid name"),
                         (("https://ex\u00e4mple.example/",), "xn--"),
                         ((url, "--beat", "inf"), "--beat: a finite number"), ((url, "--beat", "nan"), "finite"),
                         ((url, "--beat", "0.5"), "at least 1"), (("http://127.0.0.1:0/",), "port 0"),
                         ((url + "a\tb",), "control character"), ((url + "a\nb",), "control character")):
        code, err = run("--to", argv[0], "--name", "u", "--once", *argv[1:])   # --once: a guard missed ends
        assert code == 2 and reason in err, (argv, err)
    damaged = ('{"schema": "raqib-other/1"}', '{"schema": "raqib-forward/1", "cursor": {"offset": "x"}}', "",
               '{"schema": "raqib-forward/1", "cursor": {"offset": 9, "line_sha256": null}, "sent": 1}')
    for text in damaged:
        state_file = Path(forward.state_path("d", str(home)))
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(text, encoding="ascii")
        for more in ((), ("--from", "end")):   # never taken for a first run, from the end or the start
            code, err = run("--to", url, "--name", "d", "--once", *more)
            assert code == 2 and "is damaged" in err and "never taken for a first run" in err, (text, err)
            assert state_file.read_text(encoding="ascii") == text   # left as it was
    assert c.requests == []


def test_redo_e5_the_state_is_flushed_to_the_disk_before_it_is_renamed(tmp_path, monkeypatch, collectors):
    did = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(forward.os, "fsync", lambda fd: (did.append(("fsync", os.fstat(fd).st_size)),
                                                         real_fsync(fd))[1])
    monkeypatch.setattr(forward.os, "replace", lambda a, b: (did.append(("replace", os.path.getsize(a))),
                                                             real_replace(a, b))[1])
    f = forward.Forwarder("f", write(tmp_path / "e.jsonl", lines(1)), "http://127.0.0.1:%d/" % collectors(
                          down=True).port, home=str(tmp_path / "h"), out=io.StringIO(), clock=Clock())
    f.write_state()
    assert [d[0] for d in did] == ["fsync", "replace"] and did[0][1] == did[1][1] > 0


# --- REDO E6 (L-7, L-8) ------------------------------------------------------------------------------------------

def test_redo_e6_the_pid_file_appears_whole_a_second_start_between_its_steps_never_sees_it_empty(tmp_path,
                                                                                                 collectors):
    """L-7, M-9: what each start read of the pid file, asserted: the start that published first read nothing;
    the one whose publication came second read the other's pid whole (never an empty file, never None); a
    start after both reads the holder's pid."""
    path = write(tmp_path / "e.jsonl", lines(1))
    port = collectors(down=True).port
    first = fwd(tmp_path, path, port, pid=4242, alive=lambda pid: True)
    second = fwd(tmp_path, path, port, pid=4243, alive=lambda pid: True)
    third = fwd(tmp_path, path, port, pid=4245, alive=lambda pid: True)
    read = {4242: [], 4243: [], 4245: []}

    def reader(g):
        real = g.holder
        g.holder = lambda: (lambda v: (read[g.pid].append(v), v)[1])(real())
    for g in (first, second, third):
        reader(g)
    calls = []

    def between():   # the second start comes after the first wrote its pid and before its pid file appears
        calls.append(1)
        if len(calls) == 1:
            assert not os.path.exists(first.lock_file)
            second.lock()
    first.between = between
    with pytest.raises(forward.UsageError, match=r"a forwarder named t runs \(pid 4243\)"):
        first.lock()
    assert second.locked and not first.locked
    assert read[4242] == [4243] and read[4243] == []   # the second to publish read the first's pid, whole
    with pytest.raises(forward.UsageError, match=r"\(pid 4243\)"):
        third.lock()
    assert read[4245] == [4243]
    assert Path(first.lock_file).read_text(encoding="ascii") == "4243\n"
    assert [p.name for p in Path(first.lock_file).parent.iterdir() if p.name.endswith(".tmp")] == []
    second.unlock()
    Path(first.lock_file).write_text("", encoding="ascii")   # empty: a life that cannot be told
    fourth = fwd(tmp_path, path, port, pid=4244, alive=lambda pid: False)
    with pytest.raises(forward.UsageError, match="is empty or cannot be read"):
        fourth.lock()
    assert Path(first.lock_file).read_text(encoding="ascii") == ""   # refused, never taken


class Counted:
    """A file opened for the forwarder whose reads are counted (L-8: what is read into memory)."""

    def __init__(self, path, reads):
        self.f, self.reads = open(path, "rb"), reads

    def read(self, n=-1):
        data = self.f.read(n)
        self.reads.append(len(data))
        return data

    def __getattr__(self, name):
        return getattr(self.f, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.f.close()


def test_redo_e6_a_tail_of_more_than_512_kib_with_no_newline_is_failing_file_and_its_read_bounded(tmp_path,
                                                                                                 collectors):
    c = collectors(shape="raqib")
    rows = lines(2)
    long_line = lines(1, start=3, size=700 * 1024)[0]
    after = lines(1, start=4)[0]
    path = write(tmp_path / "e.jsonl", rows + [long_line[:-1]])
    reads = []
    f = fwd(tmp_path, path, c.port, opener=lambda p: Counted(p, reads))
    assert f.step() == "moved" and len(c.events) == 2
    del reads[:]
    assert f.step() == "failed" and f.failing["error"] == "file" and state(tmp_path)["failing"]["error"] == "file"
    assert reads and max(reads) <= forward.MAX_BYTES + 1   # never more than 512 KiB and a byte held at once
    first = sum(reads)
    del reads[:]
    assert f.step() == "failed" and sum(reads) < first / 2   # the next look reads what it had not looked through
    assert f.run(once=True) == 1   # --once: not all taken
    write(path, [b"\n", after], mode="ab")   # its newline comes
    del reads[:]
    start = len(b"".join(rows))
    assert f.step() == "moved" and f.failing is None and f.refused == 1 and f.refused_ids == ["offset %d" % start]
    assert max(reads) <= forward.MAX_BYTES + 1   # M-3: the line, longer than that, was never read whole
    assert c.events[-1] == after.decode("ascii")[:-1] and len(c.events) == 3 and f.step() == "idle"
# --- REDO E8 (L-11) ----------------------------------------------------------------------------------------------

def test_redo_e8_stop_by_the_systems_signal_on_a_real_process_writes_the_state(tmp_path, collectors):
    """SIGTERM off Windows; CTRL_BREAK_EVENT to a process group of its own on Windows. The state is removed once
    the lines are taken (its beat is 60 s): the state found after the exit is the one Stop wrote."""
    got = threading.Event()
    c = collectors(shape="raqib", on_request=lambda n, h, b: got.set())
    home = str(tmp_path / "home")
    path = write(tmp_path / "e.jsonl", lines(3))
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    win = sys.platform == "win32"
    kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if win else {}
    proc = subprocess.Popen([sys.executable, "-m", "raqib", "forward", path, "--to", "http://127.0.0.1:%d/" % c.port,
                             "--name", "sig"], cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, **kw)
    try:
        assert got.wait(60)
        pause = threading.Event()
        for _ in range(1200):   # its own fact: the state says the three lines were taken
            if (read_state(home, "sig") or {}).get("sent") == 3:
                break
            pause.wait(0.05)
        os.remove(forward.state_path("sig", home))
        proc.send_signal(signal.CTRL_BREAK_EVENT if win else signal.SIGTERM)
        output = proc.communicate(timeout=60)[0].decode("utf-8", "replace")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=30)
    s = read_state(home, "sig")
    assert proc.returncode == 0 and "stopped: sent 3" in output, output
    assert s["sent"] == 3 and s["failing"] is None and s["cursor"]["offset"] == os.path.getsize(path)
    assert not os.path.exists(os.path.join(forward.forward_dir(home), "sig.pid"))


def test_redo_e8_the_token_is_in_no_output_of_the_paths_that_could_print_it(tmp_path, collectors, mutes, capsys,
                                                                            monkeypatch):
    """L-11: a token file that fails its checks while running, a failed handshake, 401, 403, an unforeseen
    error; every output, error, state and status, for both tokens."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    path = write(tmp_path / "e.jsonl", lines(2))
    tok, wrong = secret(tmp_path / "t"), secret(tmp_path / "w", WRONG)
    c = collectors(token_file=secret(tmp_path / "c.tok"))
    spoil = collectors(token_file=secret(tmp_path / "c2.tok"),
                       on_request=lambda n, h, b: secret(tok, "") if n == 0 else None)   # emptied while it runs
    garbage = mutes(b"HTTP/1.1 400 Bad\r\nContent-Length: 0\r\n\r\n")                     # no TLS at all
    raqib = collectors(shape="raqib", token_file=secret(tmp_path / "c3.tok"))              # 401: no token given
    said, codes = [], {}

    def run(name, url, *more):
        out = io.StringIO()
        codes[name] = cli.main(["forward", path, "--to", url, "--name", name, "--once"] + list(more), out=out)
        said.append(out.getvalue())
        out = io.StringIO()
        cli.main(["forward", "--status", name], out=out)
        said.append(out.getvalue())
    hec = "http://127.0.0.1:%d" + PATH
    run("spoil", hec % spoil.port, "--shape", "hec", "--token-file", tok, "--batch", "1")
    secret(tok)
    run("hand", "https://127.0.0.1:%d/" % garbage.port, "--token-file", tok)
    run("t401", "http://127.0.0.1:%d/" % raqib.port)
    run("t403", hec % c.port, "--shape", "hec", "--token-file", wrong)
    real = forward.Forwarder.post
    monkeypatch.setattr(forward.Forwarder, "post", lambda self, body, token: (_ for _ in ()).throw(
        RuntimeError("an-exception-text " + str(token))))
    run("boom", hec % c.port, "--shape", "hec", "--token-file", tok)
    monkeypatch.setattr(forward.Forwarder, "post", real)
    said += list(capsys.readouterr())
    states = {p.stem: json.loads(p.read_text(encoding="ascii")) for p in (home / ".raqib" / "forward").glob("*.json")}
    said += [json.dumps(s) for s in states.values()]
    assert codes == {"spoil": 1, "hand": 1, "t401": 1, "t403": 1, "boom": 1}
    assert {n: s["failing"]["error"] for n, s in states.items()} == {"spoil": "token-file", "hand": "tls",
                                                                     "t401": "token", "t403": "token",
                                                                     "boom": "unforeseen"}
    assert states["t401"]["failing"]["status"] == 401 and states["t403"]["failing"]["status"] == 403
    for text in (TOKEN, WRONG, "Traceback", "an-exception-text"):
        assert not [s for s in said if text in s], text



# --- REDO 2 E1 (M-1): a refusal by kind does not stop the line after it -------------------------------------

def tries(f, c, count, after=None):
    """Run `count` tries; for each, its word and its requests (`after(k, word)` is called as each ends)."""
    out = []
    for k in range(count):
        before = len(c.requests)
        word = f.step()
        out.append((word, c.requests[before:]))
        if after is not None:
            after(k, word)
    return out


def alone_index(rows, req):
    body = req["body"]
    return rows.index(body) if body.count(b"\n") == 1 else None


def test_redo2_e1_250_lines_of_a_refused_kind_do_not_stop_the_line_after_them_and_are_settled(tmp_path, collectors):
    """M-1: 250 lines of a kind the collector refuses, then one of another kind: the other line arrives within
    three tries; a try sends at most 100 lines alone; no line asked alone in this run is asked again, but the
    first in question, once a try; the lines in question are a reach and a count. Then M-2 settles the 250."""
    rows = lines(250, text="heartbeat") + lines(1, start=251, text="finding")
    snaps = []
    f = None
    c = collectors(shape="raqib", refuse={"r1:%d" % n for n in range(1, 251)},
                   on_request=lambda n, h, b: snaps.append((n, f.offset)))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    asked, arrived = {}, None

    def first(k, word):
        if k == 0:   # what the run holds of the lines in question: a reach and a count, not the lines
            assert word == "failed" and f.failing["error"] == "refusing" and f.offset == 0
            assert (f.question, f.reach) == (100, len(b"".join(rows[:100])))
            held = [v for v in vars(f).values() if isinstance(v, (list, tuple, set, dict)) and len(v) > 50]
            assert held == [], held
    for k, (word, reqs) in enumerate(tries(f, c, 3, first)):
        assert len(reqs) <= 101, (k, len(reqs))
        statuses = [r["status"] for r in reqs]
        took = statuses.index(200) if 200 in statuses else len(reqs)
        before = [alone_index(rows, r) for r in reqs[:took + 1] if alone_index(rows, r) is not None]
        settling = [alone_index(rows, r) for r in reqs[took + 1:]]
        assert len(before) + len(settling) <= 100, k   # at most 100 sends of a line alone in a try
        for i in before:   # asked again before the other line arrived: only the first in question, once a try
            if i in asked:
                assert i == 0 and before.count(0) == 1, (k, i)
            asked[i] = asked.get(i, 0) + 1
        if took < len(reqs):
            arrived = k
            assert rows[250].decode("ascii")[:-1] in c.events and before[-1] == 250
            assert settling == list(range(len(settling)))   # then each line in question, alone once more, in order
    assert arrived is not None and arrived <= 2   # within three tries
    assert f.refused == len(settling) and f.offset == len(b"".join(rows[:len(settling)]))
    for _ in range(10):   # then the 250 are settled: each asked alone once more, refused, counted and passed
        if f.offset == len(b"".join(rows)):
            break
        f.step()
    assert f.offset == len(b"".join(rows)) and f.refused == 250 and f.failing is None and f.sent == 1
    assert c.events == [rows[250].decode("ascii")[:-1]]
    snaps.append((len(c.requests), f.offset))
    cursor_held(rows, c.requests, snaps)


def test_redo2_e1_a_collector_that_refuses_everything_then_put_right_takes_every_line(tmp_path, collectors):
    """M-1: a collector that refuses everything: `refusing`, the cursor unmoved, at most 101 requests a try. Put
    right, the first line in question is taken at once, and so is every line after it: none counted refused."""
    rows = lines(250)
    snaps = []
    f = None
    c = collectors(shape="raqib", refuse={"*"}, on_request=lambda n, h, b: snaps.append((n, f.offset)))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    for word, reqs in tries(f, c, 4):
        assert word == "failed" and f.failing["error"] == "refusing" and f.offset == 0 and len(reqs) <= 101
    assert f.question == 250 and c.events == [] and state(tmp_path)["cursor"]["offset"] == 0
    c.refuse = set()   # put right
    before = len(c.requests)
    for _ in range(5):
        if f.step() == "idle":
            break
    assert c.events == [r.decode("ascii")[:-1] for r in rows] and f.refused == 0 and f.failing is None
    assert [r["body"] for r in c.requests[before:]] == rows   # each line alone, in the file's order
    snaps.append((len(c.requests), f.offset))
    cursor_held(rows, c.requests, snaps)


# --- REDO 2 E2 (M-2): refused only when asked twice with a take between ----------------------------------------

def test_redo2_e2_a_line_refused_once_then_taken_when_asked_again_is_taken_not_counted(tmp_path, collectors):
    rows = lines(3)
    snaps = []
    f = None

    def on_request(n, headers, body):
        snaps.append((n, f.offset))
        if n == 3:   # the node that refused b is gone (a balancer's): b is taken when asked again
            c.refuse.clear()
    c = collectors(shape="raqib", refuse={"r1:2"}, on_request=on_request)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.step() == "moved"
    assert [r["status"] for r in c.requests] == [400, 200, 400, 200, 200]   # the batch, a, b, c, b again
    assert c.events == [rows[i].decode("ascii")[:-1] for i in (0, 2, 1)]   # b arrived after c (M-2, said)
    assert (f.refused, f.sent, f.offset, f.failing) == (0, 3, len(b"".join(rows)), None)
    snaps.append((len(c.requests), f.offset))
    cursor_held(rows, c.requests, snaps)


# --- REDO 2 E3 (M-3): a line too long is never read whole ------------------------------------------------------

def test_redo2_e3_a_line_of_2_mib_is_passed_counted_and_named_by_its_offset_never_read_whole(tmp_path, collectors):
    c = collectors(shape="raqib")
    rows = lines(2)
    huge = lines(1, start=3, size=2 * 1024 * 1024)[0]
    after = lines(2, start=4)
    path = write(tmp_path / "e.jsonl", rows + [huge] + after)
    reads = []
    f = fwd(tmp_path, path, c.port, opener=lambda p: Counted(p, reads))
    assert f.run(once=True) == 1   # K-2: a line refused makes --once 1
    assert len(huge) > 2 * 1024 * 1024 and max(reads) <= forward.MAX_BYTES + 1   # never more than a piece at once
    assert f.refused == 1 and f.refused_ids == ["offset %d" % len(b"".join(rows))]
    assert "offset %d (its id not read) refused locally" % len(b"".join(rows)) in f.out.getvalue()
    assert c.events == [r.decode("ascii")[:-1] for r in rows + after]
    s = state(tmp_path)
    assert s["cursor"]["offset"] == os.path.getsize(path) and s["refused"]["count"] == 1
    del reads[:]
    again = fwd(tmp_path, path, c.port, opener=lambda p: Counted(p, reads))   # a restart over a cursor after it
    assert again.run(once=True) == 0 and max(reads) <= forward.MAX_BYTES + 1 and again.restarts == 0


# --- REDO 2 E4 (M-4): the state every beat and Stop, whatever it is doing; the halved batch ---------------------

def test_redo2_e4_during_a_send_of_three_beats_the_state_is_written_once_a_beat_and_stop_ends_it(tmp_path,
                                                                                              collectors):
    mono, marks, writes = Clock(5000.0), {}, []
    f = None

    def nap(ev, seconds):   # the forwarder's wait for its send: the clock of its beat moves with each slice
        mono.t += seconds
        ev.wait(0.005)
        if "sent" in marks and "stop" not in marks and mono.t >= marks["sent"] + 3 * f.beat:
            marks["stop"] = mono.t
            f.stop()
    c = collectors(shape="raqib", hold=0, on_request=lambda n, h, b: marks.setdefault("sent", mono.t))
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, mono=mono, nap=nap, beat=1)
    real = f.write_state
    f.write_state = lambda: (writes.append(mono.t), real())[1]
    assert f.step() == "stopped" and f.offset == 0 and f.sent == 0
    during = [t for t in writes if marks["sent"] <= t <= marks["stop"]]
    assert len(during) >= 3, (writes, marks)
    assert max(b - a for a, b in zip(writes, writes[1:])) <= f.beat + forward.SLICE_S
    assert mono.t - marks["stop"] <= forward.SLICE_S   # Stop was looked at within a slice of the send's wait


def test_redo2_e4_during_a_try_of_100_slow_refusals_the_state_once_a_beat_and_stop_ends_it(tmp_path, collectors):
    mono, writes = Clock(5000.0), []
    f = None

    def on_request(n, headers, body):   # each answer takes half a second of the forwarder's clock
        mono.t += 0.5
        if n == 60:
            f.stop()
    c = collectors(shape="raqib", refuse={"*"}, on_request=on_request)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(150)), c.port, mono=mono, beat=5)
    real = f.write_state
    f.write_state = lambda: (writes.append(mono.t), real())[1]
    assert f.step() == "stopped" and f.offset == 0
    assert c.arrived == 61   # Stop came during the 61st request: no request after it
    assert len(writes) >= 5 and max(b - a for a, b in zip(writes, writes[1:])) <= f.beat + 0.5, writes


def test_redo2_e4_during_a_walk_over_50000_lines_that_are_not_events_the_state_once_a_beat_and_stop(tmp_path,
                                                                                                  collectors):
    t, stopped_at, writes = [5000.0], [], []
    f = None

    def mono():   # the forwarder's clock: a thousandth of a second at each look; Stop at 30 s of it
        t[0] += 0.001
        if f is not None and t[0] >= 5030.0 and not stopped_at:
            stopped_at.append(t[0])
            f.stop()
        return t[0]
    rows = [b"not an event %d\n" % i for i in range(50000)]
    path = write(tmp_path / "e.jsonl", rows)
    f = fwd(tmp_path, path, collectors(down=True).port, mono=mono, beat=5)
    real = f.write_state
    f.write_state = lambda: (writes.append(t[0]), real())[1]
    assert f.step() == "stopped"
    assert len(writes) >= 5 and max(b - a for a, b in zip(writes, writes[1:])) <= f.beat + 0.01, writes
    assert t[0] - stopped_at[0] <= 2.0   # M-4: Stop looked at within the bound
    assert 0 < f.skipped < 50000 and f.offset == len(b"".join(rows[:f.skipped]))   # the walk ended where it was


def test_redo3_e1_a_late_send_halves_the_next_batch_down_to_one_and_a_taken_one_doubles_it_up_to_batch(tmp_path,
                                                                                                       collectors):
    """N-1: late in its request or in its answer, halved (100, 50, 25, 12, 6, 3, 1, and one stays one); taken,
    doubled (1, 2, 4 ... 64, then 100, no more than --batch). No batch is sent again at the size it was late at
    (but one line)."""
    sizes, firsts, script = [], [], ["answer"] * 4 + ["send"] * 4 + ["taken"] * 8 + ["send", "taken"]

    def post(body, token):
        sizes.append(body.count(b"\n"))
        firsts.append(json.loads(body.split(b"\n")[0])["n"])
        how = script.pop(0)
        return forward.Result("taken", status=200) if how == "taken" else forward.Result("failed", "late", phase=how)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(400)), collectors(down=True).port)
    f.post = post
    words = [f.step() for _ in range(18)]
    assert words == ["failed"] * 8 + ["moved"] * 8 + ["failed", "moved"]
    assert sizes == [100, 50, 25, 12, 6, 3, 1, 1, 1, 2, 4, 8, 16, 32, 64, 100, 100, 50]
    for k, word in enumerate(words[:-1]):
        if word == "failed":   # the same first line next, at a smaller size (one line stays one)
            assert firsts[k + 1] == firsts[k] and (sizes[k + 1] < sizes[k] or sizes[k] == 1), k
    assert f.size == 100 and f.offset == len(b"".join(lines(277)))


def test_redo2_e4_a_send_whose_request_is_not_sent_within_the_bound_is_late_while_being_sent(tmp_path, collectors,
                                                                                           monkeypatch):
    gate = threading.Event()

    def request(self, *args, **kw):   # the link takes the request and never finishes sending it
        gate.wait(60)
        raise OSError("the test's link")
    monkeypatch.setattr(forward.http.client.HTTPConnection, "request", request)
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(10)), c.port, answer_s=0.3)
    try:
        assert f.step() == "failed" and f.failing["error"] == "late" and f.size == 5 and f.offset == 0
    finally:
        gate.set()


# --- REDO 2 E5 (M-5): abandoned sends are bounded; no socket closed under its thread ----------------------------

def test_redo2_e5_after_four_abandoned_sends_no_fifth_starts_and_the_state_says_stuck(tmp_path, collectors):
    gate, calls = threading.Event(), []

    def lookup(*args):   # a name that never resolves, until the test lets it
        calls.append(args)
        gate.wait(60)
        return socket.getaddrinfo(*args)
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(3)), c.port, connect_s=0.2, lookup=lookup)
    try:
        for _ in range(4):
            assert f.step() == "failed" and f.failing["error"] == "connect"
        assert len(calls) == 4 and len(f.adrift) == 4
        assert f.step() == "failed" and f.failing["error"] == "stuck" and len(calls) == 4   # no fifth started
        assert state(tmp_path)["failing"]["error"] == "stuck" and "four sends abandoned" in forward.ERRORS["stuck"]
        gate.set()
        for job in list(f.adrift):   # their own fact: each abandoned send ends once its name resolves
            job.thread.join(30)
        assert f.step() == "moved" and len(calls) == 5 and len(c.events) == 3 and f.failing is None
    finally:
        gate.set()


def test_redo2_e5_an_abandoned_sends_sockets_are_shut_down_never_closed_by_another_thread():
    """M-5, read in the code: abandon() (the forwarder's thread) only shuts the sockets down; the close calls of
    Send are in the send's own thread - run() at its end, hold() of a socket it just made, exchange()."""
    tree = ast.parse(inspect.getsource(forward.Send))
    methods = {n.name: n for n in tree.body[0].body if isinstance(n, ast.FunctionDef)}
    calls = {name: {c.func.attr for c in ast.walk(m) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
             for name, m in methods.items()}
    assert "shutdown" in calls["abandon"] and not calls["abandon"] & {"close", "detach"}
    assert [name for name, attrs in calls.items() if attrs & {"close", "detach"}] == ["hold", "run", "exchange"]
    assert "detach" not in set().union(*calls.values())


# --- REDO 2 E6 (M-6, M-7, M-8) ---------------------------------------------------------------------------------

def test_redo2_e6_an_oserror_of_the_directory_or_the_pid_file_at_the_start_is_exit_2_with_no_traceback(
        tmp_path, collectors, capsys, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    c = collectors(shape="raqib")
    argv = ["forward", write(tmp_path / "e.jsonl", lines(1)), "--to", "http://127.0.0.1:%d/" % c.port, "--name", "o",
            "--once"]
    folder = Path(forward.forward_dir(str(home)))
    folder.parent.mkdir(parents=True)
    folder.write_text("a file where the directory goes", encoding="ascii")
    assert cli.main(argv, out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert "the name o cannot be taken" in err and "Traceback" not in err, err
    folder.unlink()

    def refused(*args):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(forward.os, "rename" if os.name == "nt" else "link", refused)
    assert cli.main(argv, out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert "the name o cannot be taken" in err and "Permission denied" in err and "Traceback" not in err, err
    assert c.requests == []


def test_redo2_e6_status_reads_a_state_the_forwarder_does_not_write_as_unreadable(tmp_path):
    home, now = str(tmp_path / "home"), 1_800_000_000.0
    for name, change in (("beat0", {"beat": 0}), ("beatno", {"beat": False}), ("list", {"failing": ["server"]}),
                         ("word", {"failing": {"since": forward.iso(now), "tries": 1, "error": "x", "status": None}}),
                         ("nohash", {"cursor": {"offset": 9, "line_sha256": None}})):
        write_state(home, name, now, **change)
        out = io.StringIO()
        assert forward.status(name, home=home, out=out, clock=Clock(now)) == 3, name
        assert "UNREADABLE" in out.getvalue() and "not what a forwarder writes" in out.getvalue(), name
    write_state(home, "fine", now)
    assert forward.status("fine", home=home, out=io.StringIO(), clock=Clock(now)) == 0


def test_redo2_e6_a_restarted_forwarder_says_the_refusing_its_state_held_until_its_first_answer(tmp_path,
                                                                                               collectors):
    home = str(tmp_path / "home")
    c = collectors(shape="raqib", refuse={"*"})
    path = write(tmp_path / "e.jsonl", lines(3))
    assert fwd(tmp_path, path, c.port).run(once=True) == 1 and state(tmp_path)["failing"]["error"] == "refusing"
    seen = []
    c.on_request = lambda n, h, b: seen.append((read_state(home, "t") or {}).get("failing"))
    c.refuse = set()   # put right; the restart says refusing until its first try has an answer
    again = fwd(tmp_path, path, c.port)
    assert again.run(once=True) == 0
    assert seen[0]["error"] == "refusing" and seen[0]["tries"] >= 1
    assert state(tmp_path)["failing"] is None and len(c.events) == 3


def test_redo2_e6_the_file_replaced_during_a_try_ends_the_try_and_the_next_pass_counts_a_restart(tmp_path,
                                                                                                collectors):
    rows, other = lines(4), lines(4, start=10, text="other")
    path = write(tmp_path / "e.jsonl", rows)

    def on_request(n, headers, body):
        if n == 3:   # line 3 alone, while line 2 is in question: the file is replaced by another
            os.replace(write(tmp_path / "new.jsonl", other), path)
    c = collectors(shape="raqib", refuse={"r1:2"}, on_request=on_request)
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "again" and f.restarts == 0 and f.offset == len(rows[0]) and f.refused == 0
    assert f.run(once=True) == 0 and f.restarts == 1
    assert c.events == [rows[i].decode("ascii")[:-1] for i in (0, 2)] + [r.decode("ascii")[:-1] for r in other]


# --- REDO 2 E8 (M-10) ------------------------------------------------------------------------------------------

def test_redo2_e8_forward_md_lists_the_codes_failing_words_and_says_what_m_rules():
    spec_text = (ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8")
    table = spec_text[spec_text.index("| word | the failure |"):]
    table = table[:table.index("\n\n")]
    words = [row.split("|")[1].strip().strip("`") for row in table.splitlines()[2:]]
    assert words == list(forward.ERRORS)
    flat = " ".join(spec_text.split())
    for said in ("`stuck`", "half as many lines", "order at the collector", "asked alone once more",
                 "a reach and a count", "within 30 s of its start", "four", "no send of this name was ever taken",
                 "offset N"):
        assert said in flat, said
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = threat[threat.index("### The forwarder (`raqib forward`"):threat.index("## 6. Attacks on the watcher")]
    for said in ("`stuck`", "order at the collector", "no traceback"):
        assert said in section, said


# --- REDO 3 E1 (N-1): a slow collector is not sent the same batch for ever --------------------------------------

def test_redo3_e1_a_collector_late_for_100_lines_and_in_time_for_50_is_sent_50_then_100_again(tmp_path, collectors):
    """N-1 with the real send: the bound injected (0.3 s); the collector answers a request of more than 50 lines
    only at its own stop, and one of 50 at once. The next try after a late 100 sends 50, taken; a taken send
    doubles (100), a late one halves (50): never the same 100 again."""
    rows, arrived = lines(300), []
    c = None

    def on_request(n, headers, body):
        arrived.append((json.loads(body.split(b"\n")[0])["n"], body.count(b"\n")))
        if body.count(b"\n") > 50:
            c.quit.wait(60)   # its answer comes after the bound; this handler ends at the collector's stop
    c = collectors(shape="raqib", on_request=on_request)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, answer_s=0.3)
    words = [f.step() for _ in range(4)]
    assert words == ["failed", "moved", "failed", "moved"] and f.failing is None
    assert arrived == [(1, 100), (1, 50), (51, 100), (51, 50)]   # (the first line's n, how many)
    assert f.offset == len(b"".join(rows[:100])) and f.sent == 100 and f.size == 100
    assert "was late (no whole answer): the next batch is 50" in f.out.getvalue()


# --- REDO 3 E2 (N-2): a try that moved is not a failed try --------------------------------------------------------

def test_redo3_e2_once_over_r1_to_r101_with_r100_refused_sends_r101_and_no_wait_follows_a_try_that_moved(
        tmp_path, collectors):
    """The packet's finding 4: a try at the cap with a line in question has moved (99 lines taken); the next try
    follows with no wait, and --once goes on: r101 arrives, r100 is refused twice around its take and counted,
    and --once is 1 for that line alone. `refusing` is in every state written while a line is in question."""
    rows = lines(101)
    clock = Clock()
    c = collectors(shape="raqib", refuse={"r1:100"})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, clock=clock)
    written = []
    real = f.write_state
    f.write_state = lambda: (real(), written.append(state(tmp_path)))[0]
    assert f.run(once=True) == 1
    assert clock.waits == []   # no wait at all: each try moved, but the last, which ended --once
    assert c.events == [r.decode("ascii")[:-1] for r in rows[:99] + rows[100:]]
    s = state(tmp_path)
    assert s["refused"] == {"count": 1, "ids": ["r1:100"]} and s["failing"] is None and s["sent"] == 100
    assert s["in_question"] == {"count": 0, "since": None} and s["cursor"]["offset"] == len(b"".join(rows))
    said = [w for w in written if w["in_question"]["count"]]
    first = next(k for k, w in enumerate(said) if w["failing"])
    assert len(said) - first >= 2   # the end of the first try, and the take of r101 (the proof)
    assert all(w["failing"]["error"] == "refusing" for w in said[first:]), said[first:]


def test_redo3_e2_a_try_that_moved_nothing_waits_1_2_4_and_one_that_moved_waits_nothing(tmp_path, collectors):
    rows = lines(101)
    clock = Clock()
    c = collectors(shape="raqib", refuse={"*"})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port, clock=clock)
    at_wait = []
    clock.then = lambda clk: (at_wait.append(len(c.requests)), len(clk.waits) >= 3)[1]
    assert f.run() == 1 and f.failing["error"] == "refusing"
    # try 1: the batch and 100 alone (the reach carried); try 2: r1 again and r101 (carried); then nothing moves
    assert clock.waits == [1, 2, 4] and at_wait == [104, 105, 106]


# --- REDO 3 E3 (N-3): the same file from its first byte; the run's memory held to it -----------------------------

def test_redo3_e3_a_file_replaced_at_cursor_0_after_a_long_tail_counts_a_restart_and_loses_no_line(tmp_path,
                                                                                                    collectors):
    """The first build's case: the cursor at 0, a tail of 700 KiB with no newline looked through; the file is
    replaced by another, shorter than what was looked through. The head says it: a restart, every line sent."""
    c = collectors(shape="raqib")
    path = write(tmp_path / "e.jsonl", [b"x" * (700 * 1024)])
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "failed" and f.failing["error"] == "file" and f.scanned == (0, 700 * 1024)
    assert state(tmp_path)["head"] == {"length": 4096, "sha256": forward._sha(b"x" * 4096)}
    rows = lines(3)
    os.replace(write(tmp_path / "new.jsonl", rows), path)
    assert f.step() == "moved" and f.restarts == 1 and f.refused == 0
    assert c.events == [r.decode("ascii")[:-1] for r in rows]
    whole = b"".join(rows)
    assert state(tmp_path)["head"] == {"length": len(whole), "sha256": forward._sha(whole)}
    write(path, lines(30, start=4), mode="ab")   # the cursor passes 4096: the head is hashed again, longer
    assert f.step() == "moved" and f.step() == "idle" and f.restarts == 0 + 1 and f.head["length"] == 4096
    assert f.head["sha256"] == forward._sha(Path(path).read_bytes()[:4096])


def test_redo3_e3_a_tail_mark_past_the_end_of_a_file_with_the_same_head_is_given_up(tmp_path, collectors):
    """N-3: the same first 4096 bytes and the same line at the cursor, but the file is shorter than its tail
    was looked through: the mark is given up (no restart), and the new lines are read and sent."""
    c = collectors(shape="raqib")
    head = lines(20)
    assert len(b"".join(head)) > 4096
    path = write(tmp_path / "e.jsonl", head + [b"x" * (700 * 1024)])
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "moved" and f.step() == "failed" and f.scanned[0] == f.offset == len(b"".join(head))
    os.replace(write(tmp_path / "new.jsonl", head + lines(3, start=21)), path)
    assert f.step() == "moved" and f.restarts == 0 and f.refused == 0 and f.failing is None
    assert c.events == [r.decode("ascii")[:-1] for r in head + lines(3, start=21)]
    assert "shorter than its tail was looked through" in f.out.getvalue()


@pytest.mark.parametrize("how", ["cut", "replaced", "proof"])
def test_redo3_e3_after_the_cursor_changed_while_lines_are_in_question_the_memory_goes_back_to_the_cursor(
        tmp_path, collectors, how):
    """N-3: the file cut to the cursor, or replaced by one with the same lines up to the cursor, while lines are
    in question (and, "proof", while a take after them waits to be settled): the reach, the count and the proof
    go back to the cursor, and no line of the new part is counted refused after one refusal of its own."""
    rows = lines(4)
    c = collectors(shape="raqib", refuse={"r1:2", "r1:3", "r1:4"} if how != "proof" else {"r1:2"})
    if how == "proof":   # b alone, asked again after c's take, fails: the proof is held to the next try
        c.on_request = lambda n, h, b: setattr(c, "fail", 1) if n == 3 else None
    path = write(tmp_path / "e.jsonl", rows if how != "proof" else rows[:3])
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "failed" and f.offset == len(rows[0]) and f.question >= 1
    assert (f.proof is not None) == (how == "proof") and f.reach > f.offset
    new = lines(4, start=10)
    if how == "cut":
        with open(path, "r+b") as fh:
            fh.truncate(len(rows[0]))
        assert f.step() == "idle"   # nothing after the cursor: what was asked after it is given up
        write(path, new, mode="ab")
    else:
        os.replace(write(tmp_path / "new.jsonl", rows[:1] + new), path)
    assert f.reach > f.offset or how == "cut"
    c.refuse, c.on_request, c.fail = {"r1:10", "r1:11"}, None, 0
    begun = len(c.requests)
    for _ in range(4):
        f.step()
    assert "is asked again from the cursor" in f.out.getvalue() and f.restarts == 0
    assert f.offset == len(rows[0] + b"".join(new)) and f.refused == 2 and f.refused_ids == ["r1:10", "r1:11"]
    assert c.events[-2:] == [new[2].decode("ascii")[:-1], new[3].decode("ascii")[:-1]]
    tail = rows[:1] + new
    cursor_held(tail, [{"body": rows[0], "status": 200}] + c.requests[begun:],
                [(1 + len(c.requests) - begun, f.offset)])


def test_redo3_e3_a_file_that_only_grew_gives_nothing_up(tmp_path, collectors):
    rows = lines(4)
    c = collectors(shape="raqib", refuse={"r1:2", "r1:3"})
    path = write(tmp_path / "e.jsonl", rows[:3])
    f = fwd(tmp_path, path, c.port)
    assert f.step() == "failed" and f.question == 2 and len(c.requests) == 4
    write(path, rows[3:], mode="ab")
    assert f.step() == "moved" and f.refused == 2 and f.offset == len(b"".join(rows))
    assert [alone_index(rows, r) for r in c.requests[4:]] == [1, 3, 1, 2]   # no extra request: b, d, b, c
    assert "asked again from the cursor" not in f.out.getvalue()


# --- REDO 3 E4 (N-4): the name is lost only to another live forwarder ---------------------------------------------

def test_redo3_e4_the_pid_file_removed_is_written_again_unreadable_once_goes_on_another_live_pid_ends_with_1(
        tmp_path, collectors):
    clock = Clock()
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), c.port, clock=clock, beat=5, poll_s=1.0,
            alive=lambda pid: pid == 4321)
    lock, seen = Path(f.lock_file), {}
    real_holder = f.holder

    def unreadable_once():
        f.holder = real_holder
        return False

    def then(clk):
        n = len(clk.waits)
        if n == 3:
            lock.unlink()   # removed while it runs
        elif n == 12:
            seen["again"] = lock.read_text(encoding="ascii")
            f.holder = unreadable_once   # the next state write cannot read it, once
        elif n == 25:
            seen["state"] = Path(f.state_file).read_text(encoding="ascii")
            lock.write_text("4321\n", encoding="ascii")   # another forwarder, alive, took the name
        return n > 60   # a guard only: the forwarder must end long before
    clock.then = then
    assert f.run() == 1
    out = f.out.getvalue()
    assert seen["again"] == "%d\n" % f.pid and out.count("was gone: it is written again") == 1
    assert out.count("cannot be read at this state write") == 1
    assert 25 <= len(clock.waits) <= 25 + 6 and out.count("holds pid 4321, a process that lives") == 1
    assert Path(f.state_file).read_text(encoding="ascii") == seen["state"]   # the other's to write now
    assert lock.read_text(encoding="ascii") == "4321\n"


# --- REDO 3 E5 (N-5): lines in question are lines that wait; `sent` when the cursor passes -----------------------

def test_redo3_e5_in_question_is_in_the_state_and_the_status_is_1_while_it_waits_settling_included(tmp_path,
                                                                                                   collectors):
    home = str(tmp_path / "home")
    clock = Clock()
    rows = lines(4)
    c = collectors(shape="raqib", refuse={"r1:2", "r1:3"})
    path = write(tmp_path / "e.jsonl", rows[:3])
    f = fwd(tmp_path, path, c.port, clock=clock, beat=10)
    assert f.step() == "failed"
    s = state(tmp_path)
    assert s["in_question"] == {"count": 2, "since": forward.iso(clock.t)}
    clock.t += 25   # more than a beat: the lines in question have waited
    settling = []
    c.on_request = lambda n, h, b: settling.append(read_state(home, "t")) if n >= 6 else None
    write(path, rows[3:], mode="ab")
    assert f.step() == "moved"
    mid = settling[0]   # written when d was taken, before b and c were asked again
    assert mid["in_question"]["count"] == 2 and mid["in_question"]["since"] == s["in_question"]["since"]
    assert forward.judge(mid, forward.seconds_of(mid["written"]))[:2] == (1, "FAILING")
    calm = dict(mid, failing=None)   # N-5 alone: a line in question longer than a beat waits
    assert forward.judge(calm, forward.seconds_of(mid["written"]))[:2] == (1, "BEHIND")
    end = state(tmp_path)
    assert end["in_question"] == {"count": 0, "since": None}
    assert forward.judge(end, forward.seconds_of(end["written"]))[:2] == (0, "OK")   # settled


def test_redo3_e5_status_judges_in_question_by_its_since_and_reads_a_state_without_it(tmp_path):
    home, now = str(tmp_path / "home"), 1_800_000_000.0
    for name, change, want in (("long", {"in_question": {"count": 2, "since": forward.iso(now - 11)}}, 1),
                               ("short", {"in_question": {"count": 2, "since": forward.iso(now - 5)}}, 0),
                               ("none", {"in_question": {"count": 0, "since": None}}, 0),
                               ("older", {}, 0),
                               ("bad", {"in_question": {"count": -1, "since": None}}, 3),
                               ("head", {"head": {"length": 4097, "sha256": "a" * 64}}, 3)):
        write_state(home, name, now, **change)
        out = io.StringIO()
        assert forward.status(name, home=home, out=out, clock=Clock(now)) == want, (name, out.getvalue())
        if name == "long":
            assert "2 line(s) in question since" in out.getvalue() and "BEHIND" in out.getvalue()


def test_redo3_e5_sent_is_not_counted_twice_for_a_proof_across_a_restart(tmp_path, collectors):
    """The packet's finding 1: [a, b], a refused. 400, 400, 200 (b: the proof), Stop while a is asked again;
    the restart: 400, 400, 200 (b again), 400 (a counted). `sent` is 1: b, once, when the cursor passed it."""
    rows = lines(2)
    f = None

    def on_request(n, headers, body):
        if n == 3:
            f.stop()   # while a is asked again, after b's take
    c = collectors(shape="raqib", refuse={"r1:1"}, on_request=on_request)
    path = write(tmp_path / "e.jsonl", rows)
    f = fwd(tmp_path, path, c.port)
    assert f.run(once=True) == 1
    assert state(tmp_path)["sent"] == 0 and state(tmp_path)["cursor"]["offset"] == 0
    again = fwd(tmp_path, path, c.port)
    assert again.run(once=True) == 1   # a refused: --once is 1
    assert [r["status"] for r in c.requests] == [400, 400, 200, 400, 400, 400, 200, 400]
    s = state(tmp_path)
    assert s["sent"] == 1 and s["refused"] == {"count": 1, "ids": ["r1:1"]}
    assert s["cursor"]["offset"] == len(b"".join(rows))


# --- REDO 3 E6 (N-6): no state of any shape is a traceback ---------------------------------------------------------

def test_redo3_e6_a_failing_error_that_is_a_list_or_json_nested_100000_deep_is_3_and_a_start_2(tmp_path, collectors,
                                                                                                capsys, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    c = collectors(shape="raqib")
    path = write(tmp_path / "e.jsonl", lines(1))
    now = time.time()
    write_state(str(home), "list", now, failing={"since": forward.iso(now), "tries": 1, "error": ["server"],
                                                 "status": None})
    write_state(str(home), "dict", now, failing={"since": forward.iso(now), "tries": 1, "error": {"a": 1},
                                                 "status": None})
    Path(forward.state_path("deep", str(home))).write_text(
        '{"schema": "raqib-forward/1", "x": ' + "[" * 100000 + "]" * 100000 + "}", encoding="ascii")
    for name in ("list", "dict", "deep"):
        out = io.StringIO()
        assert cli.main(["forward", "--status", name], out=out) == 3, name
        assert "UNREADABLE" in out.getvalue(), name
        argv = ["forward", path, "--to", "http://127.0.0.1:%d/" % c.port, "--name", name, "--once"]
        out = io.StringIO()
        assert cli.main(argv, out=out) == 2, name
        said = out.getvalue() + "".join(capsys.readouterr())
        assert "is damaged" in said and "Traceback" not in said, (name, said)
    out = io.StringIO()
    assert cli.main(["forward", "--status"], out=out) == 3 and "Traceback" not in out.getvalue()
    assert c.requests == []


# --- REDO 3 E7 (N-7): the fixture, no run on a test's thread, the take of a LATER line ---------------------------

def test_redo3_e7_a_thread_left_behind_fails_the_test_that_left_it_and_no_later_test_waits_for_it():
    gate, joins = threading.Event(), []

    class StandIn(threading.Thread):
        def join(self, timeout=None):
            joins.append(timeout)
            threading.Thread.join(self, min(timeout or 0.0, 0.01))
    before = {t for t in threading.enumerate() if t.name.startswith(THREADS)}
    t = StandIn(target=gate.wait, args=(60,), name="raqib-forward-standin", daemon=True)
    t.start()
    try:
        assert left_behind(before, budget=0.05) == ["raqib-forward-standin"]   # the test that left it fails
        # (the Table, 2026-11-13, CI run on 8bc1a8b, both windows jobs: (clock + 0.05) - clock is 0.05000000000001137
        # where the clock did not move between the two reads; the budget is held to a rounding's width)
        assert len(joins) == 1 and joins[0] <= 0.05 + 1e-9
        later = {x for x in threading.enumerate() if x.name.startswith(THREADS)}   # a later test's start
        assert t in later and left_behind(later) == [] and len(joins) == 1   # not waited for, not counted
    finally:
        gate.set()
        threading.Thread.join(t, 30)
    assert not t.is_alive()


def test_redo3_e7_no_run_is_on_a_tests_own_thread_and_a_run_that_never_ends_is_stopped_and_failed(
        tmp_path, collectors, monkeypatch, capsys):
    assert forward.Forwarder.run is bounded_run   # f.run() and cli.main alike
    where = []
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(1)), collectors(down=True).port)
    f.loop = lambda once: (where.append(threading.current_thread().name), f._stop.wait(600))
    with pytest.raises(pytest.fail.Exception, match="did not end within"):
        bounded_run(f, bound=0.2)
    assert where == ["raqib-forward-run"] and f.stopped()
    monkeypatch.setattr(forward.Forwarder, "loop", lambda self, once: where.append(threading.current_thread().name))
    monkeypatch.setenv("HOME", str(tmp_path / "home2"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home2"))
    cli.main(["forward", str(tmp_path / "e.jsonl"), "--to", "http://127.0.0.1:%d/" % collectors(down=True).port,
              "--name", "cli", "--once"], out=io.StringIO())
    assert where == ["raqib-forward-run", "raqib-forward-run"]


def test_redo3_e7_the_first_line_in_question_taken_on_its_re_ask_is_no_proof_for_the_next_refused(tmp_path,
                                                                                                    collectors):
    rows = lines(3)
    c = collectors(shape="raqib", refuse={"*"})
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", rows), c.port)
    assert f.step() == "failed" and f.question == 3
    c.refuse = {"r1:2", "r1:3"}   # a is taken now; b still refused
    begun = len(c.requests)
    assert f.step() == "failed" and f.failing["error"] == "refusing"
    assert [(alone_index(rows, r), r["status"]) for r in c.requests[begun:]] == [(0, 200), (1, 400)]
    assert f.offset == len(rows[0]) and f.refused == 0 and f.question == 2   # nothing passed on a's take
    cursor_held(rows, c.requests, [(len(c.requests), f.offset)])


def test_redo3_e7_the_cursor_helper_fails_a_trace_whose_only_take_between_two_refusals_is_an_earlier_line():
    a, b, d = lines(3)
    ok = [{"body": a + b + d, "status": 400}, {"body": a, "status": 200}, {"body": b, "status": 400},
          {"body": d, "status": 200}, {"body": b, "status": 400}]
    cursor_held([a, b, d], ok, [(5, len(a + b + d))])   # b: refused twice, d (later) taken between
    made_up = [{"body": a + b, "status": 400}, {"body": a, "status": 400}, {"body": b, "status": 400},
               {"body": a, "status": 200}, {"body": b, "status": 400}]
    with pytest.raises(AssertionError):
        cursor_held([a, b], made_up, [(5, len(a + b))])   # b passed: the only take between is a's, earlier


# --- REDO 3 E8 (N-8): the state every beat and Stop inside one long line --------------------------------------------

@pytest.mark.parametrize("phase", ["end", "hash", "start"])
def test_redo3_e8_a_line_of_64_mib_the_state_each_beat_and_stop_in_its_end_its_hash_and_its_start(
        tmp_path, collectors, monkeypatch, phase):
    """A sparse file: one event, then a line of 64 MiB (zeros, then its newline). The forwarder's clock moves a
    hundredth of a second at each look; Stop comes 5 s of it into the walk named: looking for the line's end,
    hashing it, or looking back for its start (the cursor's line, after it is passed)."""
    big = 64 * 1024 * 1024
    a = lines(1)[0]
    path = tmp_path / "e.jsonl"
    with open(str(path), "wb") as fh:
        fh.write(a)
        fh.seek(len(a) + big - 1)
        fh.write(b"\n")
    t, marks, writes, stop_at, reads = [5000.0], {}, [], [], []
    f = None

    def mono():
        t[0] += 0.01
        if f is not None and phase in marks and not stop_at and t[0] >= marks[phase] + 5:
            stop_at.append(t[0])
            f.stop()
        return t[0]
    real_scan, real_sha, real_back = forward.Forwarder.scan_newline, forward.sha_range, forward._rfind_newline

    def scan(self, fh, offset, start):
        marks.setdefault("end", t[0])
        return real_scan(self, fh, offset, start)

    def sha(fh, start, end, look=None):
        if end - start > forward.MAX_BYTES:
            marks.setdefault("hash", t[0])
        return real_sha(fh, start, end, look)

    def back(fh, before, floor=0, look=None):
        if before - floor > forward.MAX_BYTES:
            marks.setdefault("start", t[0])
        return real_back(fh, before, floor, look)
    monkeypatch.setattr(forward.Forwarder, "scan_newline", scan)
    monkeypatch.setattr(forward, "sha_range", sha)
    monkeypatch.setattr(forward, "_rfind_newline", back)
    f = fwd(tmp_path, str(path), collectors(shape="raqib").port, mono=mono, beat=1,
            opener=lambda p: Counted(p, reads))
    assert f.step() == "moved" and f.sent == 1   # the event; the long line is the next try's
    real = f.write_state
    f.write_state = lambda: (writes.append(t[0]), real())[1]
    del reads[:]
    assert f.step() == "stopped" and stop_at, marks
    during = [w for w in writes if w >= marks[phase]]
    assert len(during) >= 4 and max(b - a for a, b in zip(writes, writes[1:])) <= f.beat + 0.05, writes
    assert t[0] - stop_at[0] <= 2.0   # Stop seen within the bound, in the walk named
    assert max(reads) <= forward.MAX_BYTES + 1
    assert sum(reads) < {"end": big, "hash": 2 * big, "start": 3 * big}[phase]   # the walk ended where it was
    assert f.offset == (len(a) + big if phase == "start" else len(a))


def test_redo3_e8_behind_never_walks_a_long_tail(tmp_path, collectors):
    """N-8: a tail of 64 MiB with no newline at the file's end: `behind` looks back at most BEHIND_LOOK, then
    reads once forward from what the run knows; it counts the whole line before the tail, and a state write
    never walks the tail (nor does it with Stop come)."""
    big = 64 * 1024 * 1024
    a = lines(1)[0]
    path = tmp_path / "e.jsonl"
    with open(str(path), "wb") as fh:
        fh.write(a)
        fh.truncate(len(a) + big)   # sparse: zeros, no newline
    reads = []
    f = fwd(tmp_path, str(path), collectors(down=True).port, opener=lambda p: Counted(p, reads))
    assert f.behind() == len(a)
    assert sum(reads) <= forward.BEHIND_LOOK + forward.MAX_BYTES + 1 and len(reads) <= 17
    del reads[:]
    f.stop()
    f.write_state()
    assert state(tmp_path)["behind"] == len(a) and sum(reads) <= forward.BEHIND_LOOK + forward.MAX_BYTES + 1


# --- REDO 3 E9 (N-9): the documents ------------------------------------------------------------------------------

def table(text, head):
    part = text[text.index(head):]
    part = part[:part.index("\n\n")]
    return [[cell.strip() for cell in row.strip("|").split("|")] for row in part.splitlines()[2:]]


def test_redo3_e9_forward_md_s_table_of_what_status_says_in_each_state_is_judges_own(tmp_path):
    """Each row of FORWARD.md's table names a state of the machine (its first cell's word in backticks) and what
    `--status` says of it (the exit and the word): built here as the forwarder writes it, and judged."""
    spec_text = (ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8")
    rows = table(spec_text, "| the forwarder's state | exit | word |")
    now = 1_800_000_000.0
    fail = lambda word, status=None: {"since": forward.iso(now - 30), "tries": 2, "error": word, "status": status}
    cases = {"nothing waits": {}, "growing": {"behind": 900, "last_ok": forward.iso(now - 5)},
             "behind": {"behind": 900, "last_ok": forward.iso(now - 11)},
             "never taken": {"behind": 900, "last_ok": None, "last_id": None},
             "refusing": {"failing": fail("refusing", 404), "in_question": {"count": 3, "since": forward.iso(now - 30)}},
             "settling": {"failing": fail("refusing", 404), "in_question": {"count": 1, "since": forward.iso(now - 30)},
                          "last_ok": forward.iso(now)},
             "in question": {"in_question": {"count": 1, "since": forward.iso(now - 11)}},
             "failed send": {"failing": fail("late")}, "stuck": {"failing": fail("stuck")},
             "silent": {"written": forward.iso(now - 21)}, "future": {"written": forward.iso(now + 1)},
             "damaged": {"failing": fail(["late"])}}
    seen = []
    home = str(tmp_path / "home")
    for cells in rows:
        key = cells[0].split("`")[1]
        seen.append(key)
        want = (int(cells[1]), cells[2].strip("`"))
        if key == "no state":
            out = io.StringIO()
            got = forward.status("none", home=home, out=out, clock=Clock(now)), out.getvalue().split(": ")[1].split()[0]
        else:
            write_state(home, "s", now, **cases[key])
            with open(forward.state_path("s", home), "rb") as fh:
                got = forward.judge(json.loads(fh.read().decode("ascii")), now)[:2]
        assert got == want, (key, got, want)
    assert sorted(seen) == sorted(list(cases) + ["no state"])


def test_redo3_e9_forward_md_and_the_threat_model_say_what_n_rules():
    flat = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    for said in ("at most 201 requests", "sent again smaller", "doubles it", "no wait", "`in_question`", "`head`",
                 "4096", "given up", "written again", "exit 1", "A writer of the events file", "A writer of the state",
                 "A writer of the pid file", "`sent` counts a line when the cursor passes it"):
        assert said in flat, said
    assert "A batch that failed is sent again whole" not in flat and "at most 101 requests" not in flat
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = threat[threat.index("### The forwarder (`raqib forward`"):threat.index("## 6. Attacks on the watcher")]
    for said in ("two sends a line", "removed", "first 4096 bytes", "a process that lives", "nested",
                 "the latest 50"):
        assert said in section, said
    import re
    assert not re.search(r"\bM\d+\.\d+", section)


# --- M10.3b (ADR-0011 J-6, J-14): the forwarder over syslog ----------------------------------------------------
# Every syslog collector here is the rig's stand-in (tools/rig/syslog_collector.py) on loopback, on ports it bound
# itself, stopped and joined by the fixture (it drains what was sent before its Stop), or a TLS listener the test
# bound on port 0. No verdict waits for a time to pass: the collector's own counts and the states say it.

sspec = importlib.util.spec_from_file_location("rig_syslog_collector", ROOT / "tools" / "rig" / "syslog_collector.py")
syslog_collector = importlib.util.module_from_spec(sspec)
sspec.loader.exec_module(syslog_collector)
RFC5424 = re.compile(rb"<(\d{1,3})>1 (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z) ([\x21-\x7e]{1,255})"
                     rb" ([\x21-\x7e]{1,48}) ([\x21-\x7e]{1,128}) ([\x21-\x7e]{1,32}) (-) (.*)\Z", re.S)


@pytest.fixture
def syslogs():
    started = []

    def make(**kw):
        c = syslog_collector.SyslogCollector(**kw)
        c.start()
        started.append(c)
        return c
    yield make
    for c in started:
        c.stop()


def sfwd(tmp_path, path, url, clock=None, **kw):
    kw.setdefault("name", "s")
    clock = clock or Clock()
    kw.setdefault("mono", clock)
    return forward.Forwarder(kw.pop("name"), path, url, home=str(tmp_path / "home"), out=io.StringIO(), clock=clock,
                             wait=clock.wait, **kw)


def tcp_url(c, scheme="syslog+tcp"):
    return "%s://127.0.0.1:%d" % (scheme, c.tcp_port)


def udp_url(c):
    return "syslog+udp://127.0.0.1:%d" % c.udp_port


def drained(c):
    """The stand-in's facts once it has taken all that was sent (its Stop drains, then joins)."""
    c.stop()
    return c


def sorted_line(row):
    return json.dumps(json.loads(row.decode("ascii")), sort_keys=True, separators=(",", ":"))


def severities():
    """One event line of each severity the event contract has: high, medium, low (findings), hole, info (a
    blind spot, a note)."""
    t, out = "2026-11-03T07:51:21.000Z", []
    for i, sev in enumerate(("high", "medium", "low"), 1):
        out.append(event.finding({"rule_id": "R-%d" % i, "severity": sev, "summary": "s", "class": "HOST",
                                  "kind": "anchor", "run": "r1", "round": 1}, FACTS, t, i, "finding:%d" % i,
                                 rule={"attack": ["T1059"]}))
    out.append(event.hole({"kind": "reader-failed", "detail": "d", "round": 2}, FACTS, t, 4, "hole:1"))
    out.append(event.hole({"kind": "seen", "detail": "d", "class": "blind spot", "rounds": [1]}, FACTS, t, 5,
                          "blind:1"))
    out.append(event.note({"text": "a note"}, FACTS, t, 6, "note:1"))
    return [(event.line(e) + "\n").encode("ascii") for e in out]


def test_m103b_e1_a_built_line_is_rfc_5424_with_each_severity_the_facility_and_the_line_as_its_msg(tmp_path,
                                                                                                   syslogs):
    """E1 (J-6): <PRI>1 TIMESTAMP HOSTNAME raqib - MSGID - MSG; PRI = facility * 8 + severity (13 unless
    --facility N; high 2, medium 4, low 5, a hole 4, none and info 6); the event's time, watch.host, kind; the
    line as written as the MSG. Built, and as a collector got it over tcp."""
    rows = severities()
    want = {"high": 2, "medium": 4, "low": 5, "hole": 4, "info": 6}
    seen = set()
    for raw in rows:
        obj = forward.classify(raw)
        assert obj is not None
        m = RFC5424.match(forward.syslog_message(raw, obj))
        assert m, raw
        pri, stamp, host, app, procid, msgid, sd, msg = m.groups()
        assert int(pri) == 13 * 8 + want[obj["severity"]] and int(pri) // 8 == 13
        assert stamp.decode() == obj["time"] and host.decode() == obj["watch"]["host"] == "host.example"
        assert (app, procid, msgid.decode(), sd) == (b"raqib", b"-", obj["kind"], b"-")
        assert msg == raw[:-1] and b"\n" not in msg   # the line as written, without its newline
        assert int(RFC5424.match(forward.syslog_message(raw, obj, 4)).group(1)) == 4 * 8 + want[obj["severity"]]
        seen.add(obj["severity"])
    assert seen == set(want)
    assert forward.severity_of({"severity": "none"}) == 6 and forward.severity_of({"severity": "info"}) == 6
    assert forward.severity_of({"severity": "no-such"}) == 4 and forward.severity_of({}) == 4
    odd = dict(forward.classify(rows[-1]), watch=dict(FACTS, host="a host with spaces"), kind="k" * 33, time="x")
    assert forward.syslog_head(odd) == b"<110>1 - - raqib - - - "   # "-" where RFC 5424 does not take the value
    c = syslogs(facility=4)
    path = write(tmp_path / "e.jsonl", rows)
    f = sfwd(tmp_path, path, tcp_url(c), facility=4)
    assert f.step() == "moved" and f.offset == os.path.getsize(path)
    drained(c)
    assert c.events["tcp"] == [sorted_line(r) for r in rows] and c.problems == [] and c.framings == {"octet"}
    for bad in ("24", "-1", "x", "1.5", "\u0661"):
        with pytest.raises(forward.UsageError, match="--facility: a syslog facility"):
            sfwd(tmp_path, path, tcp_url(c), facility=bad)
    assert sfwd(tmp_path, path, tcp_url(c), facility="0").facility == 0
    assert sfwd(tmp_path, path, tcp_url(c)).facility == forward.FACILITY == 13


def test_m103b_e2_the_three_forms_their_ports_and_plain_udp_and_tcp_only_to_loopback_unless_plain(tmp_path):
    """E2 (J-6, J-8): syslog+udp://, syslog+tcp://, syslog+tls://host[:port]; no path, query or fragment; plain
    udp and tcp only to a loopback address unless --plain, and then the state and the status say plain."""
    d = forward.destination
    assert d("syslog+udp://127.0.0.1") == ({"scheme": "syslog+udp", "host": "127.0.0.1", "port": 514, "path": ""},
                                          None)
    assert d("syslog+tcp://127.0.0.1:1514")[0]["port"] == 1514 and d("syslog+tcp://[::1]:1514")[0]["port"] == 1514
    assert d("SYSLOG+TLS://collector.example")[0] == {"scheme": "syslog+tls", "host": "collector.example",
                                                      "port": 6514, "path": ""}
    for url in ("syslog+udp://127.0.0.1:514/x", "syslog+tcp://127.0.0.1:514?a=b", "syslog+tls://collector.example#f",
                "syslog+tcp://127.0.0.1:514?"):
        with pytest.raises(forward.UsageError, match="host\\[:port\\] only"):
            d(url)
    for url in ("syslog+udp://192.0.2.10", "syslog+tcp://collector.example:514"):
        with pytest.raises(forward.UsageError, match="plain syslog \\(udp, tcp\\) is taken only to a loopback"):
            d(url)
        assert d(url, plain=True)[0]["host"] in ("192.0.2.10", "collector.example")
    assert d("syslog+tls://192.0.2.10:6514")[0]["port"] == 6514   # verified: no --plain needed
    with pytest.raises(forward.UsageError, match="user information"):
        d("syslog+tls://user@collector.example")
    with pytest.raises(forward.UsageError, match="port 0"):
        d("syslog+udp://127.0.0.1:0")
    path = write(tmp_path / "e.jsonl", lines(1))
    for url, plain in (("syslog+udp://192.0.2.10:514", True), ("syslog+tcp://192.0.2.10:514", True),
                       ("syslog+tls://192.0.2.10:6514", False)):
        name = url.split(":")[0].split("+")[1]
        f = sfwd(tmp_path, path, url, name=name, plain=True)
        assert f.plain is plain and f.target is None
        f.write_state()
        out = io.StringIO()
        assert forward.status(name, home=str(tmp_path / "home"), out=out, clock=Clock()) in (0, 1)
        assert ("plain: not encrypted" in out.getvalue()) is plain and url.split("//")[0] in out.getvalue()


def test_m103b_e2_over_tcp_octet_counting_and_framing_newline_over_udp_one_datagram_a_message(tmp_path, syslogs,
                                                                                            capsys, monkeypatch):
    """E2 (J-6, RFC 6587): over tcp "<length> <message>", or with --framing newline the message and a newline;
    over udp the message is the datagram. The framing the stand-in found is the one asked; its length is the one
    computed without building it."""
    raw = lines(1)[0]
    obj = forward.classify(raw)
    msg = forward.syslog_message(raw, obj)
    assert forward.syslog_frame(msg, "syslog+tcp") == b"%d " % len(msg) + msg
    assert forward.syslog_frame(msg, "syslog+tls", "newline") == msg + b"\n"
    assert forward.syslog_frame(msg, "syslog+udp") == msg
    for scheme in forward.SYSLOG:
        for framing in forward.FRAMINGS:
            assert forward.syslog_len(raw, obj, scheme, 13, framing) == len(
                forward.syslog_frame(msg, scheme, framing))
    rows = lines(30)
    path = write(tmp_path / "e.jsonl", rows)
    for framing in ("octet", "newline"):
        c = syslogs(framing=framing)   # the stand-in reads only this framing: another is a problem
        f = sfwd(tmp_path, path, tcp_url(c), name=framing, framing=None if framing == "octet" else framing)
        assert f.step() == "moved"
        drained(c)
        assert c.events["tcp"] == [sorted_line(r) for r in rows] and c.problems == [] and c.framings == {framing}
    c = syslogs()
    f = sfwd(tmp_path, path, udp_url(c), name="udp")
    assert f.step() == "moved"
    drained(c)
    assert c.events["udp"] == [sorted_line(r) for r in rows] and c.framings == {"datagram"} and c.messages == 30
    with pytest.raises(forward.UsageError, match="a datagram is one message, never framed"):
        sfwd(tmp_path, path, udp_url(c), name="u2", framing="newline")
    with pytest.raises(forward.UsageError, match="--framing: octet"):
        sfwd(tmp_path, path, tcp_url(c), name="t2", framing="lines")
    with pytest.raises(forward.UsageError, match="--facility and --framing are syslog's"):
        sfwd(tmp_path, path, "http://127.0.0.1:9/x", name="h2", framing="newline")
    with pytest.raises(forward.UsageError, match="--facility and --framing are syslog's"):
        sfwd(tmp_path, path, "http://127.0.0.1:9/x", name="h3", facility=13)
    monkeypatch.setenv("HOME", str(tmp_path / "cli"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "cli"))
    c = syslogs()
    assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "cli", "--framing", "newline", "--facility", "4",
                     "--once"], out=io.StringIO()) == 0
    assert cli.main(["forward", path, "--to", udp_url(c), "--name", "cli2", "--framing", "octet", "--once"],
                    out=io.StringIO()) == 2
    drained(c)
    assert c.framings == {"newline"} and len(c.events["tcp"]) == 30 and c.problems == ["tcp: PRI of r1:%d not as J-6"
                                                                                       " rules" % n for n in
                                                                                       range(1, 31)]
    assert "a datagram is one message" in capsys.readouterr().err


class TlsListener:
    """A syslog collector over TLS the test bound on port 0 (the test's own certificate), TLS 1.3: it reads each
    connection to the forwarder's close, keeps the bytes, then ends in order (P-2: its own close, unwrap, then
    the socket closed) - so what it holds is kept before the forwarder can say `written`. `require` (a CA file):
    it asks a client certificate, and a client with none is refused after the handshake by an alert (TLS 1.3's
    certificate_required, P-2 finding 5). It keeps how many handshakes failed."""

    def __init__(self, cert, key, require=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(cert, key)
        if require:
            self.ctx.verify_mode = ssl.CERT_REQUIRED
            self.ctx.load_verify_locations(require)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.data, self.failed, self.quit = [], 0, threading.Event()
        self.thread = threading.Thread(target=self.serve, name="raqib-test-tls", daemon=True)
        self.thread.start()

    def serve(self):
        while True:   # Stop drains: it ends only at an accept with nothing waiting after Stop
            try:
                conn, _ = self.sock.accept()
            except OSError:
                if self.quit.is_set():
                    break
                continue
            conn.settimeout(10)
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
            except (OSError, ssl.SSLError):
                self.failed += 1
                conn.close()
                continue
            got, whole = b"", False
            try:
                while True:
                    block = tls.recv(65536)
                    if not block:
                        whole = True
                        break
                    got += block
            except (OSError, ssl.SSLError):
                pass
            self.data.append(got)   # kept before its close: the forwarder's `written` waits for that close
            try:
                if whole:
                    tls.unwrap()
            except (OSError, ssl.SSLError):
                pass
            finally:
                tls.close()

    def stop(self):
        self.quit.set()
        self.thread.join()
        self.sock.close()


def test_m103b_e2_tls_is_verified_as_https_is_and_ca_adds_an_authority(tmp_path, monkeypatch):
    """E2 (J-8, L-5): syslog over tls is verified by the same context as https - the certificate and the host
    name, by the system's authorities or by --ca; nothing turns it off; no key log is written."""
    ca, cert, key = certificates(tmp_path)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.delenv(name, raising=False)
    keys = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keys))
    t = TlsListener(cert, key)
    try:
        rows = lines(3)
        path = write(tmp_path / "e.jsonl", rows)
        url = "syslog+tls://127.0.0.1:%d" % t.port
        f = sfwd(tmp_path, path, url)
        assert f.context.verify_mode == ssl.CERT_REQUIRED and f.context.check_hostname and not f.plain
        assert f.step() == "failed" and f.failing["error"] == "tls" and f.offset == 0   # the system's: refused
        g = sfwd(tmp_path, path, url, name="ca", ca=ca)
        assert g.step() == "moved" and g.offset == os.path.getsize(path) and g.delivery == "written"
        frames = b"".join(t.data)   # P-2, E2: read when the forwarder returned, before the listener's Stop
    finally:
        t.stop()
    msgs = []
    while frames:
        n, _, rest = frames.partition(b" ")
        msgs.append(rest[:int(n)])
        frames = rest[int(n):]
    assert [m.split(b" - ", 2)[-1] + b"\n" for m in msgs] == rows and t.failed >= 1
    assert not keys.exists()


def test_m103b_e2_a_message_over_65000_bytes_over_udp_is_refused_locally_counted_named_passed_never_cut(tmp_path,
                                                                                                      syslogs):
    """E2 (J-6): over udp a message longer than a datagram may be is never sent and never cut: counted refused,
    named by its id, passed; the line after it is sent. Over tcp the same line is sent whole."""
    small, big, after = lines(1, 1), lines(1, 2, size=forward.DATAGRAM_MAX), lines(1, 3)
    rows = small + big + after
    obj = forward.classify(big[0])
    assert forward.syslog_len(big[0], obj, "syslog+udp") > forward.DATAGRAM_MAX > len(small[0])
    assert len(big[0]) < forward.MAX_BYTES
    path = write(tmp_path / "e.jsonl", rows)
    c = syslogs()
    f = sfwd(tmp_path, path, udp_url(c))
    for _ in range(4):
        if f.step() == "idle":
            break
    drained(c)
    assert c.events["udp"] == [sorted_line(small[0]), sorted_line(after[0])] and c.messages == 2
    assert f.refused == 1 and f.refused_ids == ["r1:2"] and f.offset == os.path.getsize(path) and f.sent == 2
    assert "longer than one datagram may be (over 65000 bytes" in f.out.getvalue()
    c = syslogs()
    g = sfwd(tmp_path, path, tcp_url(c), name="tcp")
    assert g.step() == "moved" and g.refused == 0
    drained(c)
    assert c.events["tcp"] == [sorted_line(r) for r in rows] and c.problems == []   # whole, never cut


def test_m103b_e3_written_over_tcp_and_tls_sent_over_udp_and_every_line_arrives_in_order(tmp_path, syslogs):
    """E3 (J-3): the same cursor machine; a batch passed when the transport took it, and the state's delivery
    says what took means: written (tcp, tls), sent (udp). 250 lines, three batches each, in the file's order."""
    assert forward.DELIVERY_OF == {"http": "acknowledged", "https": "acknowledged", "syslog+udp": "sent",
                                   "syslog+tcp": "written", "syslog+tls": "written"}
    rows = lines(250)
    path = write(tmp_path / "e.jsonl", rows)
    for transport, word in (("tcp", "written"), ("udp", "sent")):
        c = syslogs()
        f = sfwd(tmp_path, path, tcp_url(c) if transport == "tcp" else udp_url(c), name=transport)
        assert [f.step() for _ in range(4)] == ["moved", "moved", "moved", "idle"]
        f.write_state()
        s = state(tmp_path, transport)
        assert s["delivery"] == word and s["sent"] == 250 and s["behind"] == 0 and s["failing"] is None
        assert s["destination"]["path"] == "" and forward.state_problem(s) is None
        drained(c)
        assert c.events[transport] == [sorted_line(r) for r in rows] and c.problems == []
        assert c.connections == (3 if transport == "tcp" else 0)   # one connection a batch
        out = io.StringIO()
        assert forward.status(transport, home=str(tmp_path / "home"), out=out, clock=Clock()) == 0
        assert "delivery %s" % word in out.getvalue()
    bad = dict(s, delivery="acknowledged")
    assert "syslog destination" in forward.state_problem(bad)   # a delivery the forwarder never writes for udp


def test_m103b_e3_a_collector_down_is_a_failed_send_nothing_moves_and_every_line_arrives_when_it_is_up(tmp_path,
                                                                                                     syslogs):
    """E3 (J-3, J-10): over tcp nothing listening is `connect`: nothing moves, and when it comes up every line
    arrives, in order, once."""
    rows = lines(7)
    path = write(tmp_path / "e.jsonl", rows)
    c = syslogs(down=True)   # its tcp port bound by it, nothing listening
    f = sfwd(tmp_path, path, tcp_url(c))
    assert f.step() == "failed" and f.failing["error"] == "connect" and f.offset == 0 and state(tmp_path, "s")["failing"]
    c.up()
    assert f.step() == "moved" and f.failing is None and f.offset == os.path.getsize(path)
    drained(c)
    assert c.events["tcp"] == [sorted_line(r) for r in rows]


KILL_CHILD = r"""
import os, socket, sys
sys.path.insert(0, sys.argv[5])
from raqib import forward
how, path, url, home = sys.argv[1:5]
calls = []
def lookup(*a):
    calls.append(1)
    if how == "before" and len(calls) == 2:   # between batch 1 (taken, its state written) and batch 2
        os._exit(9)
    return socket.getaddrinfo(*a)
f = forward.Forwarder("k", path, url, home=home, batch=5, lookup=lookup)
real = f.write_state
def write_state():
    if how == "after" and f.takes == 2:   # batch 2's bytes written, the state not yet
        os._exit(9)
    real()
f.write_state = write_state
f.run(once=True)
os._exit(0)
"""


@pytest.mark.parametrize("how", ["before", "after"])
def test_m103b_e3_a_forwarder_killed_between_two_batches_and_started_again_leaves_no_gap_over_tcp(tmp_path, syslogs,
                                                                                                how):
    """E3 (J-3, J-14's X21 over syslog): a real process killed (os._exit: no finally, no state written) between
    two batches - before the second's connection, or after its bytes were written and before its state - and
    started again: every line arrives; no line taken before the kill comes again, but the batch whose state was
    never written (at least once)."""
    rows = lines(17)
    path = write(tmp_path / "e.jsonl", rows)
    home = str(tmp_path / "home")
    c = syslogs()
    p = subprocess.run([sys.executable, "-c", KILL_CHILD, how, path, tcp_url(c), home, str(ROOT)], cwd=str(ROOT),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    assert p.returncode == 9, p.stdout
    killed = read_state(home, "k")
    assert killed["cursor"]["offset"] == sum(len(r) for r in rows[:5]) and killed["delivery"] == "written"
    g = forward.Forwarder("k", path, tcp_url(c), home=home, batch=5, out=io.StringIO())
    assert g.run(once=True) == 0 and "resumed at offset %d" % killed["cursor"]["offset"] in g.out.getvalue()
    drained(c)
    want = [sorted_line(r) for r in rows]
    # P-4: what each connection carried (the stand-in keeps each one's messages apart, in accept order: the
    # forwarder opens the next connection only after the last one ended in order), not the order two threads
    # recorded them in
    batches = [want[0:5], want[5:10]] + ([want[5:10]] if how == "after" else []) + [want[10:15], want[15:17]]
    assert c.sessions == batches and sorted(c.events["tcp"]) == sorted(sum(batches, []))
    assert read_state(home, "k")["sent"] == 17 and read_state(home, "k")["behind"] == 0


def test_m103b_e4_a_token_file_with_a_syslog_destination_is_a_usage_error_and_no_secret_is_anywhere(tmp_path,
                                                                                                  syslogs, capsys,
                                                                                                  monkeypatch):
    """E4 (J-7): syslog carries no Authorization: --token-file with a syslog destination is a usage error that
    says so, before the file is read (a file others can read is refused for that reason, not for its mode); no
    secret is in any output, state or error; --shape hec is HTTP's."""
    token = secret(tmp_path / "token.txt")
    if sys.platform != "win32":
        os.chmod(token, 0o644)   # were it read, its mode would be the reason
    path = write(tmp_path / "e.jsonl", lines(3))
    c = syslogs()
    for url in (tcp_url(c), udp_url(c), tcp_url(c, "syslog+tls")):
        with pytest.raises(forward.UsageError, match="syslog carries no token") as exc:
            sfwd(tmp_path, path, url, token_file=token)
        assert TOKEN not in str(exc.value) and "mode" not in str(exc.value)
        with pytest.raises(forward.UsageError, match="--shape hec is HTTP's"):
            sfwd(tmp_path, path, url, shape="hec")
    monkeypatch.setenv("HOME", str(tmp_path / "cli"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "cli"))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "k", "--token-file", token, "--once"]) == 2
    assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "k", "--once"]) == 0
    out, err = capsys.readouterr()
    assert "syslog carries no token (no Authorization header" in err
    drained(c)
    texts = [out, err, json.dumps(read_state(str(tmp_path / "cli"), "k"))] + c.events["tcp"]
    assert not [t for t in texts if TOKEN in t or "Authorization:" in t or "Bearer" in t]


def test_m103b_e6_forward_md_the_guide_and_the_threat_model_say_syslog():
    """E6: the three forms, the framing, the severity map, what took means per transport; the threat model says
    syslog is cleartext over udp and tcp unless tls, and what a collector learns (no milestone token)."""
    flat = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    for said in ("`syslog+udp://`", "`syslog+tcp://`", "`syslog+tls://`", "RFC 5424", "RFC 6587", "`--framing newline`",
                 "`--facility N`", "high 2, medium 4, low 5, a hole 4, none and info 6", "`written`", "`sent`",
                 "65000 bytes", "no Authorization", "`write`"):
        assert said in flat, said
    assert "until then a `syslog+udp://`" not in flat and "(the next task)" not in flat
    guide = " ".join(r for r in (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").splitlines()
                     if r.startswith("| `raqib forward"))
    for said in ("`syslog+udp://`", "`syslog+tcp://`", "`syslog+tls://`", "--framing newline", "octet count",
                 "high 2, medium 4, low 5, a hole 4, none and info 6", "`written`", "`sent`", "`acknowledged`"):
        assert said in guide, said
    assert "not built yet" not in guide
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = threat[threat.index("### The forwarder (`raqib forward`"):threat.index("## 6. Attacks on the watcher")]
    for said in ("syslog", "clear text over udp and tcp", "syslog+tls", "no token", "any host on the path",
                 "forged"):
        assert said in section, said
    assert not re.search(r"\bM\d+\.\d+", section)


def test_m103b_e7_the_syslog_stand_in_is_ascii_and_names_only_loopback_and_documentation_addresses():
    for p in (ROOT / "tools" / "rig" / "syslog_collector.py",):
        text = p.read_bytes().decode("ascii")
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            assert ip.startswith(("127.", "192.0.2.", "198.51.100.", "203.0.113.")), (p.name, ip)
        assert "import requests" not in text and "from raqib" not in text and "import raqib" not in text


# --- M10.3b REDO (ADR-0011 Amendment P): no event ends it; `written` is an orderly end; the failures tested ------
# Every listener here is the test's own on loopback, port 0, or the rig's stand-in. No test sleeps: a bound that
# must pass is injected small (answer_s), and every wait is on an event a listener sets or on the forwarder's own.

def odd_rows():
    """P-1: whole event lines the contract takes whose fields RFC 5424 does not take in its header: a year in
    other digits than ASCII and a fullwidth digit (written as JSON escapes, so the line is ASCII), a host of 300
    characters, a host with a space."""
    out = []
    for raw, change in zip(lines(4), (lambda o: o.update(time="\u0662\u0660\u0662\u0666-11-03T07:51:21.000Z"),
                                      lambda o: o.update(time="\uff12026-11-03T07:51:21.000Z"),
                                      lambda o: o["watch"].update(host="h" * 300),
                                      lambda o: o["watch"].update(host="a host"))):
        o = json.loads(raw.decode("ascii"))
        change(o)
        out.append((json.dumps(o, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii"))
    return out


class Raising(dict):
    """A made-up event no JSON line yields: every look into it raises."""

    def get(self, *a):
        raise RuntimeError("no look")


def test_m103b_redo_e1_a_field_rfc_5424_does_not_take_is_a_dash_the_line_whole_and_no_event_ends_it(tmp_path,
                                                                                                   syslogs):
    """E1 (P-1): each odd line passes the contract and is sent with `-` in that field and the whole line as its
    MSG, over tcp and udp, by a run that ends 0; made-up odd events, fed through the real send, are sent too;
    building a message raises for none."""
    rows = odd_rows()
    for raw, head in zip(rows, (b"<110>1 - host.example raqib - note - ", b"<110>1 - host.example raqib - note - ",
                                b"<110>1 2026-11-03T07:50:03.250Z - raqib - note - ",
                                b"<110>1 2026-11-03T07:50:04.250Z - raqib - note - ")):
        obj = forward.classify(raw)
        assert obj is not None and raw.isascii()   # the contract takes it: the forwarder must bear it
        assert forward.syslog_message(raw, obj) == head + raw[:-1]
        for scheme in forward.SYSLOG:
            assert forward.syslog_len(raw, obj, scheme) == len(forward.syslog_frame(
                forward.syslog_message(raw, obj), scheme))
    assert forward.STAMP.match("2026-11-03T07:51:21.000Z") and not forward.STAMP.match(
        "\u0662\u0660\u0662\u0666-11-03T07:51:21.000Z")
    path = write(tmp_path / "e.jsonl", rows + lines(1, 5))
    for transport in ("tcp", "udp"):
        c = syslogs()
        f = sfwd(tmp_path, path, tcp_url(c) if transport == "tcp" else udp_url(c), name=transport)
        assert f.run(once=True) == 0 and f.offset == os.path.getsize(path) and f.skipped == 0
        drained(c)
        assert c.events[transport] == [sorted_line(r) for r in rows + lines(1, 5)] and c.problems == []
    base = forward.classify(lines(1)[0])
    made = [dict(base, kind="k" * 40), dict(base, time=5), dict(base, watch="w"), dict(base, severity=["high"]),
            dict(base, kind=None, time=None), dict(base, time="2026-11-03T07:51:21.000Z\n")]
    for obj in made + [Raising(base), None, [], "x"]:
        head = forward.syslog_head(obj)
        assert head.startswith(b"<") and head.endswith(b" - ") and head.isascii()
        assert forward.syslog_len(b"{}\n", obj, "syslog+tcp") == len(forward.syslog_frame(
            forward.syslog_message(b"{}\n", obj), "syslog+tcp"))
    assert forward.syslog_head(made[0]) == b"<110>1 2026-11-03T07:50:01.250Z host.example raqib - - - "
    assert forward.syslog_head(Raising(base)) == b"<108>1 - - raqib - - - "
    c = syslogs()
    g = sfwd(tmp_path, path, tcp_url(c), name="made")
    raws = [(json.dumps(o, separators=(",", ":")) + "\n").encode("ascii") for o in made]
    at, sent = 0, []
    for raw, obj in zip(raws, made):
        sent.append(forward.Line(at, at + len(raw), raw, obj))
        at += len(raw)
    assert g.send(sent).kind == "taken"   # the real send, on its thread, to the stand-in
    drained(c)
    assert c.events["tcp"] == [sorted_line(r) for r in raws] and c.problems == []


class Scripted:
    """A tcp collector the test bound on loopback, port 0, that takes each connection as told, in turn: `ok` reads
    to the forwarder's end, keeps the bytes, then ends its side and closes; `hold` reads to the end and keeps the
    bytes, then holds the connection open until the test's Stop; `close` closes at once without reading; `reset`
    reads to the end, keeps the bytes, then resets (SO_LINGER 0); `half` reads `cut` bytes, keeps them, then
    resets in the middle of the batch; `never` never reads (its receive buffer small) until the test's Stop."""
    RCVBUF = 4096

    def __init__(self, *hows, cut=8192):
        self.hows, self.cut, self.got, self.closed = list(hows), cut, [], threading.Event()
        self.quit, self.threads = threading.Event(), []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.RCVBUF)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, name="raqib-test-scripted", daemon=True)
        self.thread.start()

    def url(self):
        return "syslog+tcp://127.0.0.1:%d" % self.port

    def serve(self):
        while not self.quit.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            how = self.hows.pop(0) if self.hows else "ok"
            t = threading.Thread(target=self.take, args=(conn, how), name="raqib-test-scripted-conn", daemon=True)
            self.threads.append(t)
            t.start()

    @staticmethod
    def reset(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("HH" if sys.platform == "win32" else "ii",
                                                                         1, 0))
        conn.close()

    def take(self, conn, how):
        conn.settimeout(RUN_S)
        if how == "close":
            conn.close()
            self.closed.set()
            return
        if how == "never":
            self.quit.wait(RUN_S)
            self.reset(conn)
            return
        got = b""
        try:
            while how != "half" or len(got) < self.cut:
                block = conn.recv(65536)
                if not block:
                    break
                got += block
        except OSError:
            pass
        self.got.append(got)
        if how in ("reset", "half"):
            self.reset(conn)
            return
        if how == "hold":
            self.quit.wait(RUN_S)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        conn.close()

    def stop(self):
        self.quit.set()
        self.thread.join(RUN_S)
        for t in self.threads:
            t.join(RUN_S)
        self.sock.close()


def octets(data):
    """The messages of one connection's octet-counted frames, each the line as written (its newline put back)."""
    out = []
    while data:
        n, _, rest = data.partition(b" ")
        out.append(rest[:int(n)].split(b" - ", 2)[-1] + b"\n")
        data = rest[int(n):]
    return out


class Net:
    """forward's view of the socket module, with one class changed (the module itself untouched): `gate`, an
    Event a connect waits for after it connected; `sndbuf`, a send buffer this small (a write that blocks)."""

    def __init__(self, gate=None, sndbuf=None):
        net = self

        class Sock(socket.socket):
            def __init__(self, *a, **k):
                socket.socket.__init__(self, *a, **k)
                if net.sndbuf:
                    self.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, net.sndbuf)

            def connect(self, addr):
                socket.socket.connect(self, addr)
                if net.gate is not None:
                    assert net.gate.wait(RUN_S)

        self.socket, self.gate, self.sndbuf = Sock, gate, sndbuf

    def __getattr__(self, name):
        return getattr(socket, name)


@pytest.mark.parametrize("how", ["hold", "close", "reset"])
def test_m103b_redo_e2_over_tcp_a_batch_is_taken_only_after_the_collectors_orderly_end(tmp_path, monkeypatch, how):
    """E2 (P-2): the forwarder half-closes and reads to the collector's end within the bound. A collector that
    read everything then holds the connection open past the bound (late); one that accepts and closes at once
    without reading (its close before the forwarder writes: the gate); one that resets after reading: each a
    failed send, nothing passes - each would pass were the batch taken at the write. Sent again to a collector
    that ends in order, every line arrives once."""
    rows = lines(9)
    path = write(tmp_path / "e.jsonl", rows)
    s = Scripted(how, "ok")
    if how == "close":
        monkeypatch.setattr(forward, "socket", Net(gate=s.closed))
    try:
        f = sfwd(tmp_path, path, s.url(), answer_s=0.5)
        assert f.step() == "failed" and f.offset == 0 and f.sent == 0
        assert f.failing["error"] == ("late" if how == "hold" else "write"), f.failing
        assert state(tmp_path, "s")["failing"]["error"] == f.failing["error"]
        if how != "close":
            assert octets(s.got[0]) == rows   # the collector had all of it: only its end was not in order
        monkeypatch.setattr(forward, "socket", socket)
        first = len(s.got)
        for _ in range(6):   # `late` halved the batch: it doubles again as sends are taken
            if f.step() == "idle":
                break
        assert f.offset == os.path.getsize(path) and f.failing is None and f.sent == len(rows)
        # read when the forwarder returned: the collector kept each batch before its end
        assert sum((octets(g) for g in s.got[first:]), []) == rows
    finally:
        s.stop()
    if how == "hold":
        assert "no orderly end of the connection" in f.out.getvalue()
        out = io.StringIO()
        f.fail(forward.Result("failed", "late", phase="answer"))
        f.write_state()
        assert forward.status("s", home=str(tmp_path / "home"), out=out, clock=f.clock) == 1
        assert "not ended in order" in out.getvalue() and "answer" not in out.getvalue().split("failing since")[1]


def test_m103b_redo_e2_over_tls_an_alert_after_the_handshake_is_a_failed_send_and_nothing_passes(tmp_path,
                                                                                                monkeypatch):
    """E2 (P-2, finding 5): a TLS 1.3 collector that asks a client certificate refuses the forwarder (which
    presents none) after the handshake, by an alert: a failed send, nothing passes, the batch is sent again."""
    ca, cert, key = certificates(tmp_path)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        monkeypatch.delenv(name, raising=False)
    rows = lines(3)
    path = write(tmp_path / "e.jsonl", rows)
    t = TlsListener(cert, key, require=ca)
    try:
        f = sfwd(tmp_path, path, "syslog+tls://127.0.0.1:%d" % t.port, ca=ca)
        assert f.step() == "failed" and f.offset == 0 and f.sent == 0
        assert f.failing["error"] in ("tls", "write") and f.failing["tries"] == 1
        assert f.step() == "failed" and f.offset == 0 and f.failing["tries"] == 2
    finally:
        t.stop()
    assert t.failed == 2 and t.data == []


def test_m103b_redo_e3_syslog_tcp_needs_its_port_and_the_state_keeps_facility_and_framing(tmp_path, syslogs,
                                                                                          capsys, monkeypatch):
    """E3 (P-3): syslog+tcp:// with no port is exit 2 with the reason; udp 514 and tls 6514 stay. A syslog
    destination's state holds facility and framing (null over udp); a start with another of either is exit 2;
    an older syslog state without them is read, and this start's are kept from then on."""
    d = forward.destination
    for url in ("syslog+tcp://127.0.0.1", "syslog+tcp://[::1]", "syslog+tcp://collector.example"):
        with pytest.raises(forward.UsageError, match="write the collector's port .*514 over tcp is another"):
            d(url, plain=True)
    assert d("syslog+udp://127.0.0.1")[0]["port"] == 514 and d("syslog+tls://collector.example")[0]["port"] == 6514
    rows = lines(4)
    path = write(tmp_path / "e.jsonl", rows)
    monkeypatch.setenv("HOME", str(tmp_path / "cli"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "cli"))
    capsys.readouterr()
    assert cli.main(["forward", path, "--to", "syslog+tcp://127.0.0.1", "--name", "p", "--once"]) == 2
    assert "write the collector's port" in capsys.readouterr().err
    c = syslogs()
    home = str(tmp_path / "cli")
    assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "k", "--framing", "newline", "--facility", "4",
                     "--once"], out=io.StringIO()) == 0
    s = read_state(home, "k")
    assert (s["facility"], s["framing"]) == (4, "newline") and forward.state_problem(s) is None
    for more in ((), ("--facility", "4"), ("--framing", "newline"), ("--facility", "5", "--framing", "newline")):
        capsys.readouterr()
        assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "k", "--once"] + list(more)) == 2, more
        assert "another facility or framing is another name" in capsys.readouterr().err
    assert cli.main(["forward", path, "--to", tcp_url(c), "--name", "k", "--once", "--facility", "4", "--framing",
                     "newline"], out=io.StringIO()) == 0
    for url, name, want in ((udp_url(c), "u", (13, None)), ("syslog+tls://127.0.0.1:%d" % c.tcp_port, "t",
                                                            (13, "octet"))):
        f = sfwd(tmp_path, path, url, name=name)
        f.write_state()
        s = state(tmp_path, name)
        assert (s["facility"], s["framing"]) == want and forward.state_problem(s) is None
        out = io.StringIO()
        forward.status(name, home=str(tmp_path / "home"), out=out, clock=f.clock)
        assert "facility 13, framing %s" % (want[1] or "none") in out.getvalue()
    older = {k: v for k, v in s.items() if k not in forward.SYSLOG_KEYS}   # a state from before the two were kept
    assert forward.state_problem(older) is None
    with open(forward.state_path("t", str(tmp_path / "home")), "w", encoding="ascii") as fh:
        json.dump(older, fh)
    g = sfwd(tmp_path, path, "syslog+tls://127.0.0.1:%d" % c.tcp_port, name="t", facility=9)
    assert "the state held no facility or framing" in g.resume() and "facility 9, framing octet" in g.resume()
    g.write_state()
    assert state(tmp_path, "t")["facility"] == 9
    for bad in (dict(s, facility=24), dict(s, facility=True), dict(s, framing="lines"), dict(s, framing=None),
                {k: v for k, v in s.items() if k != "framing"}):
        assert forward.state_problem(bad), bad
    u = state(tmp_path, "u")
    assert forward.state_problem(dict(u, framing="octet")) and forward.state_problem(dict(u, facility=-1))
    write_state(str(tmp_path / "h"), "h", 1_800_000_000.0)
    h = read_state(str(tmp_path / "h"), "h")
    assert forward.state_problem(h) is None and "facility" not in h and forward.state_problem(dict(h, facility=13))
    drained(c)


def test_m103b_redo_e4_an_error_in_the_middle_of_a_batch_passes_nothing_and_all_of_it_arrives_again(tmp_path,
                                                                                                    monkeypatch):
    """E4 (P-4): the collector reads part of the batch, then resets: nothing passes; sent again, all of it
    arrives (what the first connection carried arrives twice: at least once)."""
    rows = lines(60, size=1000)
    path = write(tmp_path / "e.jsonl", rows)
    s = Scripted("half", "ok", cut=8192)
    monkeypatch.setattr(forward, "socket", Net(sndbuf=4096))   # the batch is still being written at the reset
    try:
        f = sfwd(tmp_path, path, s.url())
        assert f.step() == "failed" and f.offset == 0 and f.failing["error"] == "write" and f.sent == 0
        assert 0 < len(s.got[0]) < sum(len(r) for r in rows)   # the reset came in the middle
        assert f.step() == "moved" and f.offset == os.path.getsize(path) and f.sent == 60
        assert octets(s.got[1]) == rows
    finally:
        s.stop()


def test_m103b_redo_e4_a_collector_that_never_reads_is_late_within_the_bound_and_the_next_batch_halved(tmp_path,
                                                                                                       monkeypatch):
    """E4 (P-4, L-4, M-4): a collector that never reads: the write blocks, `late` within the injected bound,
    nothing passes, and the next batch is half of this one."""
    rows = lines(40, size=4000)
    path = write(tmp_path / "e.jsonl", rows)
    s = Scripted("never", "never")
    monkeypatch.setattr(forward, "socket", Net(sndbuf=4096))
    try:
        f = sfwd(tmp_path, path, s.url(), answer_s=0.5, batch=40)
        assert f.step() == "failed" and f.offset == 0 and f.failing["error"] == "late" and f.size == 20
        assert "a send of 40 line(s) was late (its bytes not written): the next batch is 20" in f.out.getvalue()
    finally:
        s.stop()


def test_m103b_redo_e4_stop_during_a_blocked_write_ends_the_send_by_its_mechanism_long_before_the_bound(
        tmp_path, monkeypatch):
    """E4 (P-4, L-4, M-5): Stop while the write is blocked (a collector that never reads, the bound far): the
    send is abandoned, its socket shut down, which ends the blocked write - its thread ends (nothing adrift),
    nothing passes, and the try ends long before the bound."""
    rows = lines(40, size=4000)
    path = write(tmp_path / "e.jsonl", rows)
    s = Scripted("never")
    monkeypatch.setattr(forward, "socket", Net(sndbuf=4096))
    seen = []

    def nap(ev, seconds):
        job = f._send
        if job is not None and job.phase == "send" and not seen:
            seen.append(job)   # the write is in progress and cannot end: nothing reads
            f.stop()
        ev.wait(seconds)

    bound = 4 * RUN_S
    try:
        f = sfwd(tmp_path, path, s.url(), answer_s=bound, nap=nap)
        began = time.monotonic()
        assert f.step() == "stopped" and f.offset == 0 and f.sent == 0
        took = time.monotonic() - began
        assert seen and seen[0].ended() and f.adrift == [] and seen[0].result is not None
        assert seen[0].result.kind == "failed"   # its write ended by the shutdown, never taken
        assert took < bound / 4
    finally:
        s.stop()


def test_m103b_redo_e5_forward_md_and_the_threat_model_say_what_each_syslog_word_cannot_promise():
    """E5 (P-5): over udp to a collector that is down every line is `sent` and the status OK; `written` is an
    orderly end, not a stored event; a collector may cut a message at its limit; a bare CR may split a line
    under --framing newline; no advice of client certificates; tcp needs its port; the status words of a
    syslog send speak of no answer (no milestone token in the threat model)."""
    flat = " ".join((ROOT / "docs" / "specs" / "FORWARD.md").read_text(encoding="utf-8").split())
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    section = threat[threat.index("### The forwarder (`raqib forward`"):threat.index("## 6. Attacks on the watcher")]
    for text in (flat, section):
        for said in ("over udp to a collector that is down every line is `sent` and the status is OK - only the"
                     " collector's own search for silence tells", "`written` is an orderly end, not a stored event",
                     "may be cut by a collector at its own limit", "with `--framing newline` a line that holds a"
                     " bare CR may be split by a collector that breaks on it", "ends its side", "collector's end"):
            assert said.lower() in text.lower(), said
        assert "client certificates" not in text
    assert "`syslog+tcp://HOST:PORT` (its port written" in flat and "no default" in flat
    assert "the connection not ended in order, within the bound" in flat and "(no answer)" not in flat
    assert not re.search(r"\bM\d+\.\d+", section)
    late = forward.SYSLOG_ERRORS["late"]
    assert "answer" not in late and late in flat and "answer" not in forward.SYSLOG_ERRORS["write"]
