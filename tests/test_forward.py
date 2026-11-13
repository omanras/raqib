"""ADR-0011 Amendments J, K, L and M: `raqib forward`, the forwarder over HTTP. Every collector here is the rig's
stand-in (tools/rig/collector.py) on loopback, on a port it bound itself, stopped and joined by the fixture; a
collector that is down holds its port bound and listens on nothing, and a test that needs a port it never
connects to takes one of those. Every clock and wait the forwarder has is injected where a test needs time to
pass; where a test waits for another thread or process, it waits for the collector's or the state's own facts,
never for a time to pass. A bound on real time is the proof of a mechanism, at least five times the mechanism's
own. No thread of the forwarder outlives its test (a fixture fails the test that leaves one). The tokens are
made-up strings."""
import ast
import importlib.util
import inspect
import io
import json
import os
import shutil
import signal
import socket
import ssl
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


@pytest.fixture(autouse=True)
def no_forwarder_thread_left_behind():
    """L-4, M-9: every thread of the forwarder - a send's (an abandoned one included), and a run a test started on
    a thread of its own (named raqib-forward-run, a daemon, ended in a finally) - has ended when the test ends:
    a test that leaves one alive fails here. An abandoned send's own socket calls are bounded (30 s at most): the
    margin is twice that, and a thread that has ended is joined at once."""
    yield
    left = [t for t in threading.enumerate() if t.name.startswith("raqib-forward")]
    for t in left:
        t.join(60)
    assert not [t.name for t in left if t.is_alive()]


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
    """M-2: at every cursor seen - (n, offset): read when n requests had been answered - each line before it was
    taken (in a request answered 200), or refused alone twice with a request answered 200 between the two, or is
    not an event (never sent)."""
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
            assert len(no) >= 2 and any(done[k][1] == 200 for k in range(no[0] + 1, no[-1])), (i, n, offset)


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


def test_e6_once_exits_0_all_taken_1_not_all_2_usage_and_syslog_is_a_usage_error_that_says_so(tmp_path, collectors,
                                                                                              capsys, monkeypatch):
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
    for argv in (("--to", "syslog+udp://127.0.0.1:514", "--name", "c", "--once"),
                 ("--to", "syslog+tls://127.0.0.1:6514", "--name", "c", "--once"),
                 ("--to", nobody, "--name", "Bad_Name", "--once"),
                 ("--to", nobody, "--once"), ("--name", "c", "--once"),
                 ("--to", nobody, "--name", "c", "--batch", "101", "--once"),
                 ("--to", "ftp://127.0.0.1/", "--name", "c", "--once")):
        assert run(*argv) == 2, argv
    err = capsys.readouterr().err
    assert err.count("a syslog destination is not built yet") == 2 and "[a-z0-9-]{1,32}" in err


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


def test_redo2_e4_a_request_late_while_being_sent_halves_the_next_batch_down_to_one(tmp_path, collectors):
    sizes, script = [], ["send"] * 8 + ["taken", "answer", "taken"]

    def post(body, token):
        sizes.append(body.count(b"\n"))
        how = script.pop(0)
        return forward.Result("taken", status=200) if how == "taken" else forward.Result("failed", "late", phase=how)
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(300)), collectors(down=True).port)
    f.post = post
    for _ in range(8):
        assert f.step() == "failed" and f.failing["error"] == "late"
    assert f.step() == "moved" and f.step() == "failed" and f.step() == "moved"
    assert sizes == [100, 50, 25, 12, 6, 3, 1, 1, 1, 100, 100]   # late in the answer: the size stays


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


def test_redo2_e6_a_forwarder_whose_pid_file_another_took_stops_at_its_next_state_write(tmp_path, collectors):
    clock = Clock()
    c = collectors(shape="raqib")
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), c.port, clock=clock, beat=5, poll_s=1.0)
    before = {}

    def then(clk):
        if len(clk.waits) == 3:   # another forwarder of the name took the pid file
            before["state"] = Path(f.state_file).read_text(encoding="ascii")
            Path(f.lock_file).write_text("999999\n", encoding="ascii")
        return len(clk.waits) > 50   # a guard only: the forwarder must have stopped long before
    clock.then = then
    with pytest.raises(forward.UsageError, match="no longer holds this forwarder's pid"):
        f.run()
    assert 3 < len(clock.waits) <= 3 + 5   # at its next state write, within a beat of waits
    assert Path(f.state_file).read_text(encoding="ascii") == before["state"]   # the other's to write now
    assert Path(f.lock_file).read_text(encoding="ascii") == "999999\n"
    assert "another forwarder took the name t" in f.out.getvalue()


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
