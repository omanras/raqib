"""M5.2 and its REDO (ADR-0003 Amendment A, rulings A-1..A-13): the proxy
capture source, common.py (E1), the source field (E3) and the source per
finding (E4). The upstream is a local fake that speaks raw HTTP, so the bytes
on both sides of the proxy can be compared."""
import gzip
import importlib.util
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, report, ui  # noqa: E402
from raqib.hooks import capture, common, proxy  # noqa: E402
from raqib.rules import silence, trace  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
PROXY = FIXTURES / "proxy"
GOLDEN = FIXTURES / "golden" / "hook-lines-721bb55.log"
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
CWD = "/work/example"
SECRETS = ("fixture-not-a-key-openai", "fixture-not-a-key-anthropic")


# --- a raw HTTP upstream ---------------------------------------------------------------

class FakeUpstream:
    """One request per connection, as the proxy makes them. Each connection
    takes the next script: bytes are sent, an Event is waited for, "close"
    ends the connection at once, "hold" never answers."""

    def __init__(self, scripts=(), raw=False):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.scripts = list(scripts)
        self.raw = raw
        self.requests = []
        self.accepts = 0
        self.done = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(20)
        try:
            if self.raw:
                self.requests.append(conn.recv(4096))
                return
            data = b""
            while b"\r\n\r\n" not in data:
                piece = conn.recv(65536)
                if not piece:
                    return
                data += piece
            head, body = data.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            headers = [tuple(x.split(": ", 1)) for x in lines[1:]]
            names = {k.lower(): v for k, v in headers}
            if names.get("transfer-encoding", "").lower() == "chunked":
                while not body.endswith(b"0\r\n\r\n"):
                    body += conn.recv(65536)
            else:
                n = int(names.get("content-length", "0"))
                while len(body) < n:
                    body += conn.recv(65536)
            self.requests.append({"line": lines[0], "headers": headers, "body": body})
            script = self.scripts.pop(0) if self.scripts else [json_response({"ok": True})]
            for item in script:
                if isinstance(item, bytes):
                    conn.sendall(item)
                elif isinstance(item, threading.Event):
                    item.wait(20)
                elif item == "hold":
                    time.sleep(30)
                elif item == "close":
                    break
        except OSError:
            pass
        finally:
            conn.close()
            self.done.set()

    def close(self):
        self.sock.close()


def json_response(obj, status=200, headers=(("Content-Type", "application/json"),), raw_body=None):
    body = raw_body if raw_body is not None else json.dumps(obj).encode()
    head = "HTTP/1.1 %d %s\r\n" % (status, {200: "OK", 500: "Internal Server Error"}.get(status, "X"))
    head += "".join("%s: %s\r\n" % h for h in headers) + "Content-Length: %d\r\n\r\n" % len(body)
    return head.encode() + body


def chunked_head(headers):
    return ("HTTP/1.1 200 OK\r\n" + "".join("%s: %s\r\n" % h for h in headers)
            + "Transfer-Encoding: chunked\r\n\r\n").encode()


def chunk(text):
    data = text.encode() if isinstance(text, str) else text
    return b"%x\r\n%s\r\n" % (len(data), data)


def script_of(response):
    """A FakeUpstream script for a recorded response of a session fixture."""
    headers = [tuple(h) for h in response["headers"]]
    if response.get("chunked"):
        return [chunked_head(headers)] + [chunk(c) for c in response["chunks"]] + [b"0\r\n\r\n"]
    return [json_response(response["json"], response["status"], headers)]


# --- the agent side --------------------------------------------------------------------

def raw_request(method, path, headers, body=b""):
    head = "%s %s HTTP/1.1\r\n" % (method, path) + "".join("%s: %s\r\n" % tuple(h) for h in headers)
    if body and not any(h[0].lower() in ("content-length", "transfer-encoding") for h in headers):
        head += "Content-Length: %d\r\n" % len(body)
    return head.encode("latin-1") + b"\r\n" + body


def send(port, data, timeout=20):
    """Send raw bytes to the proxy and read until it closes the connection."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        out = b""
        while True:
            piece = s.recv(65536)
            if not piece:
                return out
            out += piece


def call(px, method, path, headers=(), body=b""):
    """One request as an agent sends it: Host 127.0.0.1:PORT, then the
    headers, then Connection: close; the raw answer."""
    hs = [["Host", "127.0.0.1:%d" % px.port]] + [list(h) for h in headers] + [["Connection", "close"]]
    return send(px.port, raw_request(method, path, hs, body))


def post(px, path, obj, headers=()):
    return parse_response(call(px, "POST", path, headers, json.dumps(obj).encode()))


def parse_response(raw):
    head, body = raw.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    headers = [tuple(x.split(": ", 1)) for x in lines[1:]]
    if any(k.lower() == "transfer-encoding" and v.lower() == "chunked" for k, v in headers):
        decoded, rest = b"", body
        while True:
            size_line, rest = rest.split(b"\r\n", 1)
            size = int(size_line, 16)
            if size == 0:
                break
            decoded, rest = decoded + rest[:size], rest[size + 2:]
        body = decoded
    return int(lines[0].split()[1]), headers, body


class Clock:
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return "2026-11-03T10:%02d:%02d.000Z" % divmod(self.n, 60)


class Mono:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Running:
    """The proxy in this process, on a free port, in front of an upstream."""

    def __init__(self, tmp_path, upstream_url, log=None, err=None, cwd=CWD):
        self.log = Path(log or tmp_path / "trace.jsonl")
        self.err = err or io.StringIO()
        self.mono = Mono()
        self.recorder = proxy.Recorder(str(self.log), cwd=cwd, clock=Clock(), err=self.err, monotonic=self.mono)
        target = proxy.parse_upstream(upstream_url, allow_plain=upstream_url.startswith("http:"))
        self.server = proxy.make_server(("127.0.0.1", 0), target, self.recorder)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def records(self):
        return [json.loads(x) for x in self.lines() if x.startswith("{")]

    def tools(self):
        return [r for r in self.records() if r["phase"] in ("pre", "post")]

    def markers(self):
        return [x for x in self.lines() if x.startswith("RAQIB-SILENCE:")]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def running(tmp_path):
    made = []

    def start(scripts=(), raw=False, **kw):
        up = FakeUpstream(scripts, raw=raw)
        px = Running(tmp_path, kw.pop("upstream", None) or up.url(), **kw)
        made.append((up, px))
        return up, px
    yield start
    for up, px in made:
        px.stop()
        up.close()


def request_of(exchange, port):
    req = exchange["request"]
    body = json.dumps(req["json"], separators=(",", ":")).encode()
    return raw_request(req["method"], req["path"], [["Host", "127.0.0.1:%d" % port]] + req["headers"]
                       + [["Connection", "close"]], body), body


def replay(tmp_path, name, start):
    """Replay a recorded session through the proxy and stop it (session_end);
    (session, upstream, proxy, answers)."""
    session = json.loads((PROXY / ("%s-session.json" % name)).read_text(encoding="utf-8"))
    up, px = start([script_of(x["response"]) for x in session["exchanges"]])
    answers = []
    for exchange in session["exchanges"]:
        data, _ = request_of(exchange, px.port)
        answers.append(parse_response(send(px.port, data)))
    px.recorder.shutdown()
    return session, up, px, answers


def run_report(path, *extra):
    out = io.StringIO()
    code = cli.main(["report", str(path)] + list(extra), out=out)
    return code, out.getvalue()


def key_of(model, first):
    return common.canonical_sha256([model, first])


def anthropic_turn(first, *more, model="m"):
    return {"model": model, "messages": [first] + list(more)}


def tool_use(use_id, name="Bash", tool_input=None):
    return {"type": "tool_use", "id": use_id, "name": name, "input": tool_input or {"command": "ls"}}


def tool_result(use_id, content="ok", **extra):
    return dict({"type": "tool_result", "tool_use_id": use_id, "content": content}, **extra)


def answer_with(*blocks, stop="tool_use"):
    return json_response({"type": "message", "content": list(blocks), "stop_reason": stop})


FIRST = {"role": "user", "content": "do the task"}


# --- E1: one module of shared helpers ----------------------------------------------------

def test_e1_capture_and_proxy_share_common():
    assert capture.common is common and proxy.common is common and proxy.capture is capture
    for name in common.__all__:
        assert getattr(capture, name) is getattr(common, name), name
    for name in ("canonical_sha256", "input_meta", "command_head", "command_programs", "redact", "output_meta"):
        assert name in common.__all__
    source = (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    for name in ("def canonical_sha256", "def input_meta", "def command_head", "def redact", "SECRET_PATTERNS ="):
        assert name not in source


def test_e1_the_hook_loads_common_next_to_it_under_isolated_mode(tmp_path):
    # A planted common.py in the cwd is never imported: -I, and the loader reads the file next to capture.py.
    (tmp_path / "common.py").write_text("raise SystemExit('planted')\n", encoding="utf-8")
    log = tmp_path / "trace.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    proc = subprocess.run([sys.executable, "-I", str(CAPTURE), str(log)], cwd=tmp_path, env=env, timeout=30,
                          input=(FIXTURES / "pretooluse-bash.json").read_bytes(), capture_output=True)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")
    (rec,) = [json.loads(x) for x in log.read_text().splitlines()]
    assert rec["source"] == "hook" and rec["input_meta"] == {"command_head": "ls", "command_programs": ["ls"]}


@pytest.mark.parametrize("broken", ["missing", "raises"])
def test_a7_a_hook_without_common_writes_its_silence_line_into_the_trace_too(tmp_path, broken):
    lone = tmp_path / "hooks"
    lone.mkdir()
    shutil.copy(CAPTURE, lone / "capture.py")
    if broken == "raises":
        (lone / "common.py").write_text("raise ImportError('broken on purpose')\n", encoding="utf-8")
    log = tmp_path / "trace.jsonl"
    log.write_bytes(b'{"torn line')   # a torn last line does not swallow the silence line
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    proc = subprocess.run([sys.executable, "-I", str(lone / "capture.py"), str(log)], timeout=30, env=env,
                          input=(FIXTURES / "pretooluse-bash.json").read_bytes(), capture_output=True)
    assert (proc.returncode, proc.stdout) == (0, b"")
    (line,) = proc.stderr.decode().splitlines()
    assert line.startswith("RAQIB-SILENCE: capture failed event=PreToolUse log=%s: CaptureError: cannot load"
                           " common.py: " % log)
    assert log.read_text().splitlines() == ['{"torn line', line]
    records, problems = trace.read(log)
    assert {"line": 2, "reason": trace.SILENCE_REASON} in problems
    # Loaded by path under another name (as the tests load it), the error is raised, not hidden.
    spec = importlib.util.spec_from_file_location("raqib_capture_alone", lone / "capture.py")
    with pytest.raises((OSError, ImportError)):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))


# --- E3 / A-10: the source field and the golden hook line ----------------------------------

def test_a10_hook_lines_equal_the_golden_lines_of_721bb55_plus_source_last(tmp_path):
    """tests/fixtures/golden/hook-lines-721bb55.log was written by the
    capture.py of 721bb55 (before M5.2) for these payloads, in this order.
    Today's line for the same event is that line, with its own ts, and
    ,"source":"hook" before the closing brace."""
    golden = GOLDEN.read_text(encoding="utf-8").splitlines()
    log = tmp_path / "trace.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    names = ("sessionstart.json", "pretooluse-bash.json", "posttooluse-bash.json", "pretooluse-write.json",
             "pretooluse-webfetch.json", "posttoolusefailure-bash.json", "stop.json", "sessionend.json")
    for name in names:
        proc = subprocess.run([sys.executable, "-I", str(CAPTURE), str(log)], env=env, timeout=30,
                              input=(FIXTURES / name).read_bytes(), capture_output=True)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")
    new = log.read_text(encoding="utf-8").splitlines()
    assert len(new) == len(golden) == len(names)
    for old, line in zip(golden, new):
        assert '"source"' not in old
        old_ts, new_ts = json.loads(old)["ts"], json.loads(line)["ts"]
        assert line.replace('"ts":"%s"' % new_ts, '"ts":"%s"' % old_ts, 1) == old[:-1] + ',"source":"hook"}'


def test_e3_old_traces_load_unchanged_and_read_as_hook():
    for path in sorted(FIXTURES.glob("*.log")) + [FIXTURES / "field" / "2026-11-02.log", GOLDEN]:
        text = path.read_text(encoding="utf-8")
        records, problems = trace.read(path)
        assert '"source"' not in text, path
        assert records == [json.loads(x) for x in text.splitlines() if x.strip()][:len(records)]
        assert all("source" not in r and trace.source_of(r) == "hook" for r in records)
        assert not any("source" in p["reason"] for p in problems)


def test_e3_unknown_sources_are_reported_and_strict_lines_accept_the_three():
    base = {"ts": "2026-11-03T10:00:00.000Z", "seq": 1, "session_id": "s", "phase": "stop", "tool": "-", "cwd": "/w"}
    text = "\n".join(json.dumps(dict(base, seq=n, source=s)) for n, s in enumerate(("hook", "proxy", "os", "x", 5), 1))
    records, problems = trace.parse(text)
    assert len(records) == 5
    assert problems == [{"line": 4, "reason": "unknown source 'x'"}, {"line": 5, "reason": "unknown source 5"}]
    assert [trace.source_of(r) for r in records] == ["hook", "proxy", "os", "x", "5"]
    assert trace.SOURCES == ("hook", "proxy", "os") and trace.DEFAULT_SOURCE == "hook"
    for value in trace.SOURCES:
        assert trace.strict_problem(dict(base, source=value)) is None
    assert trace.strict_problem(base) is None
    assert trace.strict_problem(dict(base, source="hooks")) == "unknown source 'hooks'"
    history = dict(base, phase="history", source="proxy", results=2, tool_use_ids=["a", "b"],
                   output_sha256s=["0" * 64, "1" * 64], tool_hashed=True)
    assert trace.strict_problem(history) is None and trace.parse(json.dumps(history))[1] == []


def test_a13_trace_names_a_raqib_silence_line_and_the_report_says_so(tmp_path):
    path = tmp_path / "t.log"
    path.write_text('{"ts":"2026-11-03T10:00:00.000Z","seq":1,"session_id":"s","phase":"stop","tool":"-","cwd":"/w"}\n'
                    "RAQIB-SILENCE: proxy upstream failed before an answer: X session=- POST /v1/messages\n"
                    "  RAQIB-SILENCE: capture failed event=- log=x: E\n{not json\n", encoding="utf-8")
    assert trace.read(path)[1] == [{"line": 2, "reason": trace.SILENCE_REASON},
                                   {"line": 3, "reason": trace.SILENCE_REASON}, {"line": 4, "reason": "not JSON"}]
    assert trace.SILENCE_REASON == "a RAQIB-SILENCE line: something was not captured (A3)"
    code, text = run_report(path)
    assert code == 1 and "  - trace-problem: line 2: a RAQIB-SILENCE line: something was not captured (A3)" in text
    assert "  - trace-problem: line 4: not JSON" in text


# --- E2: options ---------------------------------------------------------------------------

@pytest.mark.parametrize("listen", ["0.0.0.0:8787", "localhost:8787", "127.0.0.1", "127.0.0.1:x", "127.0.0.1:70000",
                                    "[::1]:8787", ":8787"])
def test_e2_listen_is_127_0_0_1_only(listen):
    with pytest.raises(proxy.UsageError):
        proxy.parse_listen(listen)
    assert proxy.parse_listen("127.0.0.1:0") == ("127.0.0.1", 0)


@pytest.mark.parametrize("url, allow", [
    ("http://api.example.com", False), ("http://127.0.0.1:9", False), ("http://api.example.com", True),
    ("http://10.0.0.1:80", True), ("http://localhost:9", True), ("ftp://api.example.com", False),
    ("https://user:pw@api.example.com", False), ("https://api.example.com/v1?key=x", False),
    ("https://api.example.com/#x", False), ("https://", False), ("api.example.com", False),
])
def test_e2_upstream_is_https_and_plain_only_to_loopback_with_the_flag(url, allow):
    with pytest.raises(proxy.UsageError):
        proxy.parse_upstream(url, allow)


def test_e2_upstream_forms_tls_verification_on_and_127_8():
    up = proxy.parse_upstream("https://api.example.com/v1/")
    assert (up.scheme, up.host, up.port, up.prefix, up.netloc) == ("https", "api.example.com", 443, "/v1",
                                                                    "api.example.com")
    assert up.target("/chat/completions?x=1") == "/v1/chat/completions?x=1"
    assert proxy.parse_upstream("https://api.example.com:8443").netloc == "api.example.com:8443"
    # A-8: the whole loopback range with the flag, as the docs say: 127.0.0.0/8 and ::1.
    for url in ("http://127.0.0.1:9", "http://127.0.0.2:9", "http://127.255.255.254:9", "http://[::1]:9"):
        assert proxy.parse_upstream(url, True).scheme == "http"
    ctx = proxy.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    conn = up.connection()
    assert isinstance(conn, proxy.http.client.HTTPSConnection) and conn._context.verify_mode == ssl.CERT_REQUIRED
    source = (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    for banned in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "verify=False",
                   "HTTPS_PROXY", "set_tunnel"):
        assert banned not in source.split('"""', 2)[2], banned   # the docstring names HTTPS_PROXY as not used


def test_e2_cli_refuses_bad_options_with_exit_2(tmp_path, capsys):
    log = str(tmp_path / "t.jsonl")
    assert cli.main(["proxy", "--listen", "0.0.0.0:0", "--upstream", "https://api.example.com", "--log", log]) == 2
    assert cli.main(["proxy", "--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:9", "--log", log]) == 2
    assert cli.main(["proxy", "--listen", "127.0.0.1:0", "--upstream", "https://api.example.com",
                     "--log", str(tmp_path / "no" / "dir" / "t.jsonl")]) == 2
    assert cli.main(["proxy", "--listen", "127.0.0.1:0", "--upstream", "https://api.example.com", "--log", log,
                     "--cwd", "relative/dir"]) == 2
    err = capsys.readouterr().err
    assert "127.0.0.1 only" in err and "--allow-plain-upstream" in err and "cannot write the trace" in err
    assert "--cwd must be an absolute directory" in err
    assert cli.main(["proxy", "--upstream", "https://api.example.com", "--log", log]) == 2   # --listen required


# --- E3/E4: the recorded sessions, now with conversation sessions (A-3) -------------------------

@pytest.mark.parametrize("name", ["openai", "anthropic"])
def test_e3_the_recorded_session_gives_the_fixture_trace(tmp_path, running, name):
    session, up, px, answers = replay(tmp_path, name, running)
    assert px.log.read_text(encoding="utf-8") == (PROXY / ("%s-session.trace.log" % name)).read_text(encoding="utf-8")
    recs = px.records()
    first = session["exchanges"][0]["request"]["json"]
    key = key_of(first["model"], first["messages"][0])
    assert all(r["session_id"] == key and r["source"] == "proxy" and r["cwd"] == CWD for r in recs)
    assert [(r["phase"], r["seq"]) for r in recs] == [("session_start", 1), ("pre", 2), ("pre", 3), ("post", 2),
                                                       ("post", 3), ("stop", 4), ("session_end", 5)]
    pres, posts = recs[1:3], recs[3:5]
    for pre, done in zip(pres, posts):
        assert (pre["tool_use_id"], pre["input_sha256"]) == (done["tool_use_id"], done["input_sha256"])
    assert not silence.findings(recs)
    text = px.log.read_text(encoding="utf-8")
    for fragment in ("203.0.113.7", "notes.txt", "Upload the notes", "coding agent", "total 0", "No such file",
                     "build directory", "-rf", "-la") + SECRETS:
        assert fragment not in text, fragment
    assert not px.markers() and px.err.getvalue() == ""
    for exchange, got, (status, headers, body) in zip(session["exchanges"], up.requests, answers):
        _, sent = request_of(exchange, px.port)
        assert got["body"] == sent
        response = exchange["response"]
        want = "".join(response["chunks"]).encode() if response.get("chunked") else \
            json.dumps(response["json"]).encode()
        assert (status, body) == (response["status"], want)


def test_e4_each_fixture_has_its_positive_and_its_negative():
    want = {"openai": ("NET-TOOL", "call_fx_1", "call_fx_2"), "anthropic": ("DESTRUCT-CMD", "toolu_fx_1", "toolu_fx_2")}
    for name, (rule, positive, negative) in want.items():
        path = PROXY / ("%s-session.trace.log" % name)
        code, text = run_report(path)
        rep = json.loads(run_report(path, "--json")[1])
        records = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
        seq_of = {r["tool_use_id"]: r["seq"] for r in records if r["phase"] == "pre"}
        (finding,) = rep["findings"]
        assert code == 1 and (finding["rule_id"], finding["cited_seq"], finding["source"]) == (rule, [seq_of[positive]],
                                                                                              "proxy")
        assert seq_of[negative] not in finding["cited_seq"]
        assert rep["sources"] == {"proxy": 7} and "sources: proxy 7" in text.splitlines()
        assert "      source: proxy" in text.splitlines() and not rep["alarms"]


def test_e4_mixed_sources_in_one_trace():
    """A hook trace of v0.1 (no source field) followed by a proxy session;
    each finding names the source of its own lines."""
    mixed = PROXY / "mixed-sources.trace.log"
    hook_log = FIXTURES / "blocked-calls-claude-code-2.1.301.log"
    parts = hook_log.read_text(encoding="utf-8") + (PROXY / "anthropic-session.trace.log").read_text(encoding="utf-8")
    assert mixed.read_text(encoding="utf-8") == parts
    code, text = run_report(mixed)
    rep = json.loads(run_report(mixed, "--json")[1])
    by_source = {}
    for f in rep["findings"]:
        by_source.setdefault(f["source"], set()).add(f["rule_id"])
    assert code == 1 and by_source == {"hook": {"SILENCE-HALF"}, "proxy": {"DESTRUCT-CMD"}}
    hook_records = len(trace.read(hook_log)[0])
    assert rep["sources"] == {"hook": hook_records, "proxy": 7}
    assert "sources: hook %d, proxy 7" % hook_records in text.splitlines()
    lines = text.splitlines()
    for f in rep["findings"]:
        head = "  [%s] %s (%s, %s) session %s seq %s" % (f["severity"], f["rule_id"], f["class"], f["kind"],
                                                         f["session_id"], ",".join(map(str, f["cited_seq"])))
        assert lines[lines.index(head) + 1] == "      source: %s" % f["source"]
    page = ui.render(rep, trace.read_numbered(mixed)[0], [])
    assert "<th>session</th><th>source</th><th>seq</th>" in page
    assert page.count("<td>hook</td>") == hook_records and page.count("<td>proxy</td>") == 7
    for name in ("hook", "proxy"):
        assert page.count(", source %s</span>" % name) == sum(f["source"] == name for f in rep["findings"]) > 0


def test_e4_a_finding_with_no_line_in_the_trace_names_no_source():
    assert report._source({}, "s", [1]) == "-"
    index = {("s", 1): [(1, {"source": "proxy"})], ("s", 2): [(2, {})]}
    assert report._source(index, "s", [1, 2]) == "hook+proxy"


# --- A-3: conversations ------------------------------------------------------------------------

def test_a3_the_key_is_model_and_first_message_and_each_conversation_is_a_session(running):
    one, two = {"role": "user", "content": "task one"}, {"role": "user", "content": "task two"}
    assert proxy.conversation_key({"model": "m", "messages": [one, FIRST]}) == key_of("m", one)
    assert proxy.conversation_key({"model": "m"}) == key_of("m", None) != key_of("n", None)
    # Two conversations through one proxy, both with a call numbered "Bash:0" (ids repeat across conversations).
    up, px = running([[answer_with(tool_use("Bash:0", tool_input={"command": "rm a"}))],
                      [answer_with(tool_use("Bash:0", tool_input={"command": "ls b"}))],
                      [answer_with({"type": "text", "text": "done"}, stop="end_turn")],
                      [answer_with({"type": "text", "text": "done"}, stop="end_turn")]])
    post(px, "/v1/messages", anthropic_turn(one))
    post(px, "/v1/messages", anthropic_turn(two))
    a_use = {"role": "assistant", "content": [tool_use("Bash:0", tool_input={"command": "rm a"})]}
    b_use = {"role": "assistant", "content": [tool_use("Bash:0", tool_input={"command": "ls b"})]}
    post(px, "/v1/messages", anthropic_turn(two, b_use, {"role": "user", "content": [tool_result("Bash:0", "B")]}))
    post(px, "/v1/messages", anthropic_turn(one, a_use, {"role": "user", "content": [tool_result("Bash:0", "A")]}))
    px.recorder.shutdown()
    recs = px.records()
    ka, kb = key_of("m", one), key_of("m", two)
    assert [(r["session_id"] == ka, r["phase"], r["seq"]) for r in recs] == [
        (True, "session_start", 1), (True, "pre", 2), (False, "session_start", 1), (False, "pre", 2),
        (False, "post", 2), (False, "stop", 3), (True, "post", 2), (True, "stop", 3),
        (True, "session_end", 4), (False, "session_end", 4)]
    by = {(r["session_id"], r["phase"]): r for r in recs}
    assert by[(ka, "post")]["input_meta"]["command_head"] == "rm" and by[(kb, "post")]["input_meta"]["command_head"] == "ls"
    assert not silence.findings(recs)


def test_a3_numbered_ids_repeat_within_one_conversation_and_pair_in_order(running):
    """Kimi-style ids ("Bash:0" every turn): the i-th result with an id is the
    i-th time that id was answered, so a re-sent first result never closes the
    second call."""
    up, px = running([[answer_with(tool_use("Bash:0", tool_input={"command": "ls"}))],
                      [answer_with(tool_use("Bash:0", tool_input={"command": "rm x"}))],
                      [answer_with({"type": "text", "text": "ok"}, stop="end_turn")]])
    use1 = {"role": "assistant", "content": [tool_use("Bash:0", tool_input={"command": "ls"})]}
    use2 = {"role": "assistant", "content": [tool_use("Bash:0", tool_input={"command": "rm x"})]}
    res1 = {"role": "user", "content": [tool_result("Bash:0", "first")]}
    res2 = {"role": "user", "content": [tool_result("Bash:0", "second")]}
    post(px, "/v1/messages", anthropic_turn(FIRST))
    post(px, "/v1/messages", anthropic_turn(FIRST, use1, res1))
    post(px, "/v1/messages", anthropic_turn(FIRST, use1, res1, use2, res2))
    tools = px.tools()
    assert [(r["phase"], r["seq"], r["input_meta"]["command_head"]) for r in tools] == [
        ("pre", 2, "ls"), ("post", 2, "ls"), ("pre", 3, "rm"), ("post", 3, "rm")]
    assert tools[1]["output_sha256"] == common.canonical_sha256("first")
    assert tools[3]["output_sha256"] == common.canonical_sha256("second")
    assert not px.markers() and not [f for f in silence.findings(px.records()) if f["rule_id"] == "SILENCE-HALF"]


def test_a3_a_result_with_no_call_in_its_key_is_a_half_and_never_crosses_keys(running):
    one, two = {"role": "user", "content": "one"}, {"role": "user", "content": "two"}
    up, px = running([[answer_with(tool_use("call_1"))], [answer_with()], [answer_with()]])
    post(px, "/v1/messages", anthropic_turn(one))   # call_1 is open in conversation one
    post(px, "/v1/messages", anthropic_turn(two))   # conversation two, first sight, no result
    # Conversation two answers "call_1", which it never asked for: a half in its key; one's pre stays open.
    post(px, "/v1/messages", anthropic_turn(two, {"role": "user", "content": [tool_result("call_1")]}))
    recs = px.records()
    half = [r for r in recs if r["phase"] == "post"]
    assert [(r["session_id"], r["seq"], r["tool"]) for r in half] == [(key_of("m", two), 2, "?")]
    halves = {(f["session_id"], tuple(f["cited_seq"])) for f in silence.findings(recs) if f["rule_id"] == "SILENCE-HALF"}
    assert halves == {(key_of("m", one), (2,)), (key_of("m", two), (2,))}


def test_a3_stop_only_on_a_turn_end_with_no_tool_call_and_a_closed_session_reopens(running):
    up, px = running([[json_response({"choices": [{"index": 0, "finish_reason": "length", "message": {}}]})],
                      [json_response({"choices": [{"index": 0, "finish_reason": "stop", "message": {}}]})],
                      [json_response({"choices": [{"index": 0, "finish_reason": "stop", "message": {}}]})]])
    first = {"role": "system", "content": "s"}
    post(px, "/v1/chat/completions", {"model": "m", "messages": [first]})
    post(px, "/v1/chat/completions", {"model": "m", "messages": [first]})
    px.recorder.shutdown()
    post(px, "/v1/chat/completions", {"model": "m", "messages": [first]})
    assert [r["phase"] for r in px.records()] == ["session_start", "stop", "session_end", "session_start", "stop"]


def test_a3_cwd_option_and_default(tmp_path, running):
    up, px = running([[answer_with(tool_use("t1"))]], cwd="/elsewhere/project")
    post(px, "/v1/messages", anthropic_turn(FIRST))
    assert {r["cwd"] for r in px.records()} == {"/elsewhere/project"}
    rec = proxy.Recorder(str(tmp_path / "other.jsonl"))
    assert rec._cwd() == os.getcwd()


# --- A-4, A-5: results that predate the proxy, results re-sent with another hash ----------------

def test_a4_results_in_a_conversations_first_request_are_one_history_line(running, tmp_path):
    up, px = running([[answer_with({"type": "text", "text": "ok"}, stop="end_turn")],
                      [answer_with({"type": "text", "text": "ok"}, stop="end_turn")]])
    old = [{"role": "assistant", "content": [tool_use("toolu_old1"), tool_use("toolu_old2")]},
           {"role": "user", "content": [tool_result("toolu_old1", "a"), tool_result("toolu_old2", "b")]},
           {"role": "assistant", "content": [tool_use("example_call")]},
           {"role": "user", "content": [tool_result("example_call", "few-shot")]}]
    post(px, "/v1/messages", anthropic_turn(FIRST, *old))
    post(px, "/v1/messages", anthropic_turn(FIRST, *old))     # the same history again: nothing new
    recs = px.records()
    assert [r["phase"] for r in recs] == ["session_start", "history", "stop", "stop"]
    hist = recs[1]
    assert (hist["results"], hist["tool_use_ids"], hist["tool"]) == (3, ["toolu_old1", "toolu_old2", "example_call"], "-")
    assert hist["output_sha256s"] == [common.canonical_sha256(x) for x in ("a", "b", "few-shot")]
    assert not silence.findings(recs) and not px.markers()
    # A restarted proxy reads the history line back: the same results are still not new.
    up2, px2 = running([[answer_with({"type": "text", "text": "ok"}, stop="end_turn")]], log=px.log)
    post(px2, "/v1/messages", anthropic_turn(FIRST, *old))
    assert [r["phase"] for r in px2.records()][4:] == ["stop"] and not px2.markers()
    # Shutdown ends every open key, those read from the trace as well (A-3).
    other = tmp_path / "other.jsonl"
    other.write_text(px.log.read_text(encoding="utf-8"), encoding="utf-8")
    fresh = proxy.Recorder(str(other), cwd=CWD, clock=Clock())
    fresh.shutdown()
    assert [json.loads(x)["phase"] for x in other.read_text().splitlines()][-1] == "session_end"


def test_a5_a_result_re_sent_with_another_hash_is_one_silence_line(running):
    up, px = running([[answer_with(tool_use("toolu_x"))], [answer_with()], [answer_with()], [answer_with()]])
    use = {"role": "assistant", "content": [tool_use("toolu_x")]}
    post(px, "/v1/messages", anthropic_turn(FIRST))
    post(px, "/v1/messages", anthropic_turn(FIRST, use, {"role": "user", "content": [tool_result("toolu_x", "real")]}))
    for _ in range(2):
        post(px, "/v1/messages", anthropic_turn(FIRST, use, {"role": "user", "content": [tool_result("toolu_x", "forged")]}))
    (post_line,) = [r for r in px.records() if r["phase"] == "post"]
    assert post_line["output_sha256"] == common.canonical_sha256("real")   # the first post stays
    (marker,) = px.markers()
    assert "result for toolu_x re-sent with a different hash" in marker and "the first post stays" in marker
    assert "session=%s" % key_of("m", FIRST) in marker
    assert trace.parse(marker)[1] == [{"line": 1, "reason": trace.SILENCE_REASON}]   # a trace problem: an alarm


def test_e3_a_restarted_proxy_closes_the_calls_of_the_run_before(tmp_path, running):
    first = {"role": "system", "content": "s"}
    answer = {"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"tool_calls": [
        {"id": "call_r", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"ls\"}"}}]}}]}
    up, one = running([[json_response(answer)]])
    post(one, "/v1/chat/completions", {"model": "m", "messages": [first]})
    one.stop()
    one.recorder.shutdown()
    up2, two = running([[json_response({"choices": [{"index": 0, "finish_reason": "stop", "message": {}}]})]],
                       log=one.log)
    msgs = [first, {"role": "assistant", "tool_calls": answer["choices"][0]["message"]["tool_calls"]},
            {"role": "tool", "tool_call_id": "call_r", "content": "x"}]
    post(two, "/v1/chat/completions", {"model": "m", "messages": msgs})
    assert [(r["phase"], r["seq"]) for r in two.records()] == [
        ("session_start", 1), ("pre", 2), ("session_end", 3), ("session_start", 4), ("post", 2), ("stop", 5)]
    assert not [f for f in silence.findings(two.records()) if f["rule_id"] == "SILENCE-HALF"]


def test_a9_the_trace_is_read_once_at_start(tmp_path, running, monkeypatch):
    up, px = running([[answer_with(tool_use("toolu_m"))], [answer_with()]])
    reads = []
    real_open = open

    def watching_open(path, mode="r", *a, **k):
        if str(path) == str(px.log) and "r" in mode and "+" not in mode:
            reads.append(mode)
        return real_open(path, mode, *a, **k)
    monkeypatch.setattr("builtins.open", watching_open)
    post(px, "/v1/messages", anthropic_turn(FIRST))
    post(px, "/v1/messages", anthropic_turn(FIRST, {"role": "assistant", "content": [tool_use("toolu_m")]},
                                            {"role": "user", "content": [tool_result("toolu_m")]}))
    assert reads == [] and [r["phase"] for r in px.tools()] == ["pre", "post"]
    # Lines another process appends are not read back: the index is the proxy's own.
    with real_open(px.log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-11-03T11:00:00.000Z", "seq": 99, "session_id": key_of("m", FIRST),
                            "phase": "pre", "tool": "Bash", "tool_use_id": "toolu_z", "input_sha256": "0" * 64,
                            "input_meta": {}, "cwd": CWD, "source": "proxy"}) + "\n")
    assert "toolu_z" not in px.recorder.convs[key_of("m", FIRST)].pres


def test_e3_a_hook_pre_with_the_same_id_is_not_the_proxys(running, tmp_path):
    log = tmp_path / "trace.jsonl"
    log.write_text(json.dumps({"ts": "2026-11-03T09:00:00.000Z", "seq": 1, "session_id": "claude-1", "phase": "pre",
                               "tool": "Bash", "tool_use_id": "toolu_h", "input_sha256": "0" * 64, "input_meta": {},
                               "cwd": CWD}) + "\n", encoding="utf-8")
    up, px = running([[answer_with()], [answer_with()]], log=log)
    post(px, "/v1/messages", anthropic_turn(FIRST))
    post(px, "/v1/messages", anthropic_turn(FIRST, {"role": "user", "content": [tool_result("toolu_h")]}))
    hook, start, done = px.records()
    assert "source" not in hook and (done["phase"], done["seq"], done["session_id"]) == ("post", 2, key_of("m", FIRST))


def test_e3_tool_results_are_scanned_for_secret_names_only(running):
    token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    up, px = running([[json_response({"choices": []})], [json_response({"choices": []})]])
    first = {"role": "system", "content": "s"}
    post(px, "/v1/chat/completions", {"model": "m", "messages": [first]})
    post(px, "/v1/chat/completions", {"model": "m", "messages": [first, {"role": "tool", "tool_call_id": "call_k",
                                                                        "content": "token=" + token}]})
    (done,) = px.tools()
    assert done["output_meta"] == {"scan": "full", "secret_kinds": ["github_token"]}
    assert token not in px.log.read_text() and token[-12:] not in px.log.read_text()


# --- A-2: bounded tool names and ids -------------------------------------------------------------

def test_a2_tool_and_tool_use_id_are_bounded_or_hashed(running, tmp_path):
    assert proxy.bounded("Bash", 64) == ("Bash", False) and proxy.bounded(None, 64) == (None, False)
    assert proxy.bounded("", 64) == (None, False) and proxy.bounded("x" * 64, 64) == ("x" * 64, False)
    for bad in ("x" * 65, "na\u00efve", "a\nb", "a\x7fb", 7, ["Bash"], {"n": 1}):
        text, hashed = proxy.bounded(bad, 64)
        assert hashed and text == "sha256:" + common.canonical_sha256(bad)[:16]
    long_id, odd_name = "id-" + "9" * 200, "Bash\u202e\n" + "x" * 100
    up, px = running([[answer_with(tool_use(long_id, name=odd_name)), ], [answer_with()]])
    post(px, "/v1/messages", anthropic_turn(FIRST))
    post(px, "/v1/messages", anthropic_turn(FIRST, {"role": "assistant", "content": [tool_use(long_id, name=odd_name)]},
                                            {"role": "user", "content": [tool_result(long_id)]}))
    pre, done = px.tools()
    for rec in (pre, done):
        assert rec["tool_hashed"] is True and rec["seq"] == 2
        assert rec["tool"] == "sha256:" + common.canonical_sha256(odd_name)[:16]
        assert rec["tool_use_id"] == "sha256:" + common.canonical_sha256(long_id)[:16]
        assert list(rec).index("tool_hashed") == list(rec).index("tool_use_id") + 1
    assert all(ord(c) < 128 for c in px.log.read_text(encoding="utf-8")) and "9" * 50 not in px.log.read_text()
    up2, px2 = running([[answer_with(tool_use("toolu_plain"))]], log=tmp_path / "plain.jsonl")
    post(px2, "/v1/messages", anthropic_turn(FIRST))
    assert "tool_hashed" not in px2.tools()[0]


# --- E2: relaying ------------------------------------------------------------------------------

def test_e2_headers_are_relayed_except_host_and_hop_by_hop(running):
    up, px = running([[json_response({"id": "x"}, headers=(("Content-Type", "application/json"), ("X-Up", "1"),
                                                           ("Connection", "close"), ("Keep-Alive", "timeout=5"),
                                                           ("x-request-id", "r-1")))]])
    headers = [["Host", "127.0.0.1:%d" % px.port], ["Authorization", "Bearer " + SECRETS[0]], ["X-Hop", "1"],
               ["Connection", "close, X-Hop"], ["Keep-Alive", "timeout=5"], ["Proxy-Authorization", "Basic x"],
               ["TE", "trailers"], ["Accept-Encoding", "identity"], ["X-Agent", "a b"],
               ["Content-Type", "application/json"]]
    body = b'{"model":"m","messages":[]}'
    status, got, answer = parse_response(send(px.port, raw_request("POST", "/v1/chat/completions?x=1", headers, body)))
    (req,) = up.requests
    assert req["line"] == "POST /v1/chat/completions?x=1 HTTP/1.1"
    assert req["headers"] == [("Host", "127.0.0.1:%d" % up.port), ("Authorization", "Bearer " + SECRETS[0]),
                              ("Accept-Encoding", "identity"), ("X-Agent", "a b"), ("Content-Type", "application/json"),
                              ("Content-Length", str(len(body)))]
    assert req["body"] == body
    assert (status, answer) == (200, b'{"id": "x"}')
    assert got == [("Content-Type", "application/json"), ("X-Up", "1"), ("x-request-id", "r-1"),
                   ("Content-Length", "11")]
    assert not px.markers()


def test_e2_an_upstream_path_prefix_and_other_methods_pass_unrecorded(tmp_path):
    up = FakeUpstream([[json_response({"data": []})], [json_response({"deleted": True})],
                       [json_response({}, status=200)]])
    px = Running(tmp_path, up.url() + "/base")
    try:
        status, _, body = parse_response(call(px, "GET", "/v1/models"))
        assert (status, body) == (200, b'{"data": []}')
        call(px, "DELETE", "/v1/files/f-1")
        call(px, "OPTIONS", "/v1/x")
        assert [r["line"] for r in up.requests] == ["GET /base/v1/models HTTP/1.1", "DELETE /base/v1/files/f-1 HTTP/1.1",
                                                    "OPTIONS /base/v1/x HTTP/1.1"]
        assert px.lines() == []
    finally:
        px.stop()
        up.close()


def test_e2_streaming_passes_each_piece_as_it_arrives_and_the_pre_is_written_first(running):
    first_read = threading.Event()
    events = ['data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_s","type":"function",'
              '"function":{"name":"Bash","arguments":"{\\"command\\": \\"ls\\"}"}}]},"finish_reason":null}]}\n\n',
              'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n', "data: [DONE]\n\n"]
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]), chunk(events[0]), first_read,
                       chunk(events[1]), chunk(events[2]), b"0\r\n\r\n"]])
    body = b'{"model":"m","stream":true,"messages":[{"role":"system","content":"s"}]}'
    with socket.create_connection(("127.0.0.1", px.port), timeout=20) as s:
        s.sendall(raw_request("POST", "/v1/chat/completions", [["Host", "127.0.0.1:%d" % px.port],
                                                               ["Connection", "close"]], body))
        got = b""
        while events[0].encode() not in got:
            got += s.recv(65536)
        assert b"finish_reason\":\"tool_calls" not in got and px.tools() == []
        first_read.set()
        while b"[DONE]" not in got:
            piece = s.recv(65536)
            if b"finish_reason\":\"tool_calls" in piece:
                assert [r["phase"] for r in px.tools()] == ["pre"]   # written before the piece passed
            got += piece
        while not got.endswith(b"0\r\n\r\n"):
            got += s.recv(65536)
    status, _, answer = parse_response(got)
    assert (status, answer) == (200, "".join(events).encode())
    (pre,) = px.tools()
    assert (pre["tool"], pre["tool_use_id"], pre["input_meta"]) == ("Bash", "call_s", {"command_head": "ls",
                                                                                        "command_programs": ["ls"]})
    assert not px.markers()


# --- A-6: who may send ----------------------------------------------------------------------------

@pytest.mark.parametrize("hosts, origin", [([], None), (["localhost:{port}"], None), (["127.0.0.1"], None),
                                           (["127.0.0.1:1"], None), (["127.0.0.1:{port}", "127.0.0.1:{port}"], None),
                                           (["127.0.0.1:{port}"], "http://evil.example"),
                                           (["127.0.0.1:{port}"], "null")])
def test_a6_a_wrong_host_or_any_origin_is_403_and_never_relayed(running, hosts, origin):
    up, px = running()
    headers = [["Host", h.format(port=px.port)] for h in hosts] + ([["Origin", origin]] if origin else [])
    body = json.dumps(anthropic_turn(FIRST, {"role": "user", "content": [tool_result("toolu_f")]})).encode()
    status, _, text = parse_response(send(px.port, raw_request("POST", "/v1/messages", headers + [["Connection", "close"]],
                                                               body)))
    assert status == 403 and up.requests == [] and px.records() == []
    (marker,) = px.markers()
    assert marker.startswith("RAQIB-SILENCE: proxy did not relay a request: ")
    assert ("Origin header" in marker) == bool(origin)
    assert "evil" not in marker   # the header values are not written


def test_a6_refused_lines_fold_to_one_per_60_s_with_a_count(running):
    up, px = running()
    bad = raw_request("GET", "/v1/models", [["Host", "localhost"], ["Connection", "close"]])
    for _ in range(5):
        assert parse_response(send(px.port, bad))[0] == 403
    assert len(px.markers()) == 1
    px.mono.now += proxy.FOLD_SECONDS
    send(px.port, bad)
    assert len(px.markers()) == 2 and "; 4 more refused requests in the 60 s before were not written one by one" \
        in px.markers()[1]
    send(px.port, bad)
    send(px.port, bad)
    px.recorder.shutdown()   # the count not yet written is written at the end
    assert len(px.markers()) == 3 and "did not relay 2 more refused requests" in px.markers()[2]


# --- A-8: refused and odd exchanges ---------------------------------------------------------------

def test_a8_upgrade_trace_connect_and_other_methods_are_refused(running):
    up, px = running()
    host = ["Host", "127.0.0.1:%d" % px.port]
    for data, status, why in (
            (raw_request("GET", "/ws", [host, ["Upgrade", "websocket"], ["Connection", "Upgrade"]]), 501, "Upgrade"),
            (raw_request("TRACE", "/", [host, ["Connection", "close"]]), 405, "method TRACE"),
            (raw_request("FROB", "/x", [host, ["Connection", "close"]]), 405, "method FROB"),
            (b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % px.port, 405, "method CONNECT"),
            (raw_request("GET", "http://api.example.com/v1/models", [host, ["Connection", "close"]]), 400, "not a path"),
            (raw_request("POST", "/v1/messages", [host, ["Transfer-Encoding", "gzip, chunked"]]), 501, "chunked"),
            (raw_request("POST", "/v1/messages", [host, ["Content-Length", "x"]]), 400, "Content-Length")):
        px.mono.now += proxy.FOLD_SECONDS   # one line each, not folded
        assert parse_response(send(px.port, data))[0] == status, why
        assert why in px.markers()[-1], (why, px.markers()[-1])
    assert len(px.markers()) == 7 and up.requests == []


def test_a8_http_1_0_agents_get_no_stale_framing(running):
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n")
    up, px = running([[head, chunk('{"a":'), chunk("1}"), b"0\r\n\r\n"], [head, chunk('{"b":2}'), b"0\r\n\r\n"]])
    old = send(px.port, b"GET /v1/models HTTP/1.0\r\nHost: 127.0.0.1:%d\r\n\r\n" % px.port)
    head_text, body = old.split(b"\r\n\r\n", 1)
    assert body == b'{"a":1}' and b"Content-Length" not in head_text and b"Transfer-Encoding" not in head_text
    assert b"Connection: close" in head_text
    status, headers, body = parse_response(call(px, "GET", "/v1/models"))
    assert body == b'{"b":2}' and not any(k.lower() == "content-length" for k, _ in headers)
    assert ("Transfer-Encoding", "chunked") in headers


def test_a8_a_head_answer_keeps_its_headers_and_the_connection(running):
    up, px = running([[b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"],
                      [json_response({"after": 1})]])
    with socket.create_connection(("127.0.0.1", px.port), timeout=20) as s:
        s.sendall(raw_request("HEAD", "/v1/x", [["Host", "127.0.0.1:%d" % px.port]]))
        got = b""
        while b"\r\n\r\n" not in got:
            got += s.recv(65536)
        assert b"Transfer-Encoding: chunked" in got and b"Connection: close" not in got
        s.sendall(raw_request("GET", "/v1/y", [["Host", "127.0.0.1:%d" % px.port], ["Connection", "close"]]))
        while True:   # the same connection serves the next request
            piece = s.recv(65536)
            if not piece:
                break
            got += piece
    assert got.endswith(b'{"after": 1}') and [r["line"] for r in up.requests] == ["HEAD /v1/x HTTP/1.1",
                                                                                "GET /v1/y HTTP/1.1"]


def test_a8_an_interim_1xx_is_not_relayed_and_is_one_line(running):
    up, px = running([[b"HTTP/1.1 103 Early Hints\r\nLink: </x>; rel=preload\r\n\r\n",
                       json_response({"choices": [{"index": 0, "finish_reason": "stop", "message": {}}]})],
                      [b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"]])
    status, headers, body = post(px, "/v1/chat/completions", {"model": "m", "messages": [{"role": "system"}]})
    assert status == 200 and json.loads(body)["choices"][0]["finish_reason"] == "stop"
    assert not any(k == "Link" for k, _ in headers)
    (marker,) = px.markers()
    assert "upstream sent an interim 103 answer; not relayed" in marker
    assert [r["phase"] for r in px.records()] == ["session_start", "stop"]
    status, _, _ = parse_response(call(px, "GET", "/v1/models"))
    assert status == 502 and "interim 101" in px.markers()[1] and "upstream failed before an answer" in px.markers()[2]


def test_a8_an_sse_error_event_an_unended_stream_and_an_agent_that_leaves(running):
    error = ('event: error\ndata: {"type":"error","error":{"type":"overloaded_error"}}\n\n')
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]), chunk(error), b"0\r\n\r\n"],
                      [chunked_head([("Content-Type", "text/event-stream")]),
                       chunk('data: {"type":"message_start","message":{}}\n\n'), b"0\r\n\r\n"]])
    post(px, "/v1/messages", anthropic_turn(FIRST))
    assert "the answer carried an error event" in px.markers()[0]
    assert "ended without its end event" in px.markers()[1]
    post(px, "/v1/messages", anthropic_turn(FIRST))
    assert len(px.markers()) == 3 and "ended without its end event" in px.markers()[2]
    # An agent that leaves mid-stream.
    hold = threading.Event()
    up.scripts.append([chunked_head([("Content-Type", "text/event-stream")]), chunk("data: {}\n\n"), hold]
                      + [chunk("data: {}\n\n" * 6000)] * 40 + [b"0\r\n\r\n"])
    s = socket.create_connection(("127.0.0.1", px.port), timeout=20)
    s.sendall(raw_request("POST", "/v1/messages", [["Host", "127.0.0.1:%d" % px.port]],
                          json.dumps(anthropic_turn(FIRST)).encode()))
    s.recv(100)
    s.close()
    hold.set()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any("the agent left during the answer" in m for m in px.markers()):
        time.sleep(0.05)
    assert any("the agent left during the answer" in m for m in px.markers())


def test_a8_a_stream_whose_end_event_came_writes_no_line(running):
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]),
                       chunk('data: {"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}\n\n'),
                       chunk('data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'), b"0\r\n\r\n"]])
    post(px, "/v1/chat/completions", {"model": "m", "messages": [{"role": "system"}], "stream": True})
    assert not px.markers() and [r["phase"] for r in px.records()] == ["session_start", "stop"]


# --- A-1: recording never breaks relaying -------------------------------------------------------------

def test_a1_a_request_too_deep_for_json_is_relayed_with_one_record_failed_line(running):
    up, px = running([[json_response({"ok": True})]])
    body = b'{"model":"m","messages":' + b"[" * 200000 + b"]" * 200000 + b"}"
    status, _, answer = parse_response(call(px, "POST", "/v1/messages", (), body))
    assert (status, answer) == (200, b'{"ok": true}') and up.requests[0]["body"] == body
    (marker,) = px.markers()
    assert "record failed: RecursionError (reading the request); the bytes are relayed" in marker


def test_a1_an_answer_too_deep_for_json_is_relayed_whole(running):
    deep = b'{"content":' + b"[" * 200000 + b"]" * 200000 + b"}"
    up, px = running([[json_response(None, raw_body=deep)]])
    status, _, answer = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert (status, answer) == (200, deep)
    assert any("record failed: RecursionError (reading the answer)" in m for m in px.markers())


@pytest.mark.parametrize("api, event", [
    ("anthropic", 'data: {"type":"content_block_start","index":[1],"content_block":{"type":"tool_use","id":"t",'
                  '"name":"Bash","input":{}}}\n\n'),
    ("openai", 'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":[0],"id":"c","function":{"name":"f",'
               '"arguments":"{}"}}]}}]}\n\n'),
])
def test_a1_a_list_valued_index_stops_recording_not_the_stream(running, api, event):
    rest = "data: [DONE]\n\n" if api == "openai" else 'data: {"type":"message_stop"}\n\n'
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]), chunk(event), chunk(rest), b"0\r\n\r\n"]])
    path = "/v1/chat/completions" if api == "openai" else "/v1/messages"
    status, _, answer = post(px, path, {"model": "m", "messages": [{"role": "user", "content": "x"}], "stream": True})
    assert (status, answer) == (200, (event + rest).encode())
    (marker,) = px.markers()
    assert "record failed: TypeError (reading the answer)" in marker and px.tools() == []


def test_a1_memory_shaped_failures_in_recording_are_lines_and_the_bytes_pass(running, monkeypatch):
    stream = [chunked_head([("Content-Type", "text/event-stream")]), chunk('data: {"type":"message_stop"}\n\n'),
              b"0\r\n\r\n"]
    up, px = running([[json_response({"x": 1})], list(stream)])

    def oom(*a, **k):
        raise MemoryError()
    monkeypatch.setattr(proxy.Recorder, "request", oom)
    status, _, answer = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert (status, answer) == (200, b'{"x": 1}')
    assert "record failed: MemoryError (reading the request)" in px.markers()[0]
    monkeypatch.undo()
    monkeypatch.setattr(proxy.StreamCalls, "feed", oom)
    status, _, answer = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert (status, answer) == (200, b'data: {"type":"message_stop"}\n\n')
    assert "record failed: MemoryError (reading the answer)" in px.markers()[1] and len(px.markers()) == 2


def test_a1_a_request_body_over_the_cap_is_streamed_whole_and_unrecorded(running, monkeypatch):
    monkeypatch.setattr(proxy, "PARSE_MAX", 1000)
    up, px = running([[json_response({"a": 1})], [json_response({"b": 2})]])
    big = json.dumps(anthropic_turn(FIRST, {"role": "user", "content": [tool_result("toolu_big", "x" * 5000)]})).encode()
    status, _, answer = parse_response(call(px, "POST", "/v1/messages", (), big))
    assert (status, answer) == (200, b'{"a": 1}') and up.requests[0]["body"] == big
    chunks = b"".join(chunk(big[i:i + 700]) for i in range(0, len(big), 700)) + b"0\r\n\r\n"
    status, _, answer = parse_response(call(px, "POST", "/v1/messages", [["Transfer-Encoding", "chunked"]], chunks))
    assert (status, answer) == (200, b'{"b": 2}') and up.requests[1]["body"] == chunks
    assert len(px.markers()) == 2 and all("over the 1000 bytes the proxy reads; relayed unrecorded" in m
                                          for m in px.markers())
    assert px.records() == []


def test_a1_a_chunk_size_line_is_bounded_and_a_big_chunk_is_read_in_pieces(running):
    up, px = running([[json_response({"ok": 1})]])
    huge = b"1" + b"0" * 16 + b"\r\nx\r\n0\r\n\r\n"   # 17 hex digits
    status, _, _ = parse_response(call(px, "POST", "/v1/messages", [["Transfer-Encoding", "chunked"]], huge))
    assert status == 400 and up.requests == [] and "body cannot be read (bad chunk size line)" in px.markers()[0]
    body = json.dumps(anthropic_turn(FIRST, {"role": "user", "content": [tool_result("t", "y" * 300000)]})).encode()
    one_chunk = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    status, _, _ = parse_response(call(px, "POST", "/v1/messages", [["Transfer-Encoding", "chunked"]], one_chunk))
    assert status == 200 and up.requests[0]["body"] == one_chunk
    assert [r["phase"] for r in px.records()] == ["session_start", "history"]


# --- E2 / A3: failures ----------------------------------------------------------------------------

def test_e2_an_upstream_that_refuses_is_502_and_one_silence_line(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens there
    px = Running(tmp_path, "http://127.0.0.1:%d" % port)
    try:
        status, headers, body = parse_response(call(px, "POST", "/v1/chat/completions?api_key=" + SECRETS[0],
                                                    [["Authorization", "Bearer " + SECRETS[0]]],
                                                    b'{"model":"m","messages":[]}'))
        assert status == 502 and b"did not answer" in body and ("Connection", "close") in headers
        (marker,) = px.markers()
        assert marker.startswith("RAQIB-SILENCE: proxy upstream failed before an answer: ConnectionRefusedError")
        assert marker.endswith(" session=%s POST /v1/chat/completions" % key_of("m", None))
        for secret in SECRETS:
            assert secret not in px.log.read_text() and secret not in px.err.getvalue()
    finally:
        px.stop()


def test_e2_no_retry_an_upstream_that_closes_is_asked_once(running):
    up, px = running([["close"]])
    status, _, _ = post(px, "/v1/messages", anthropic_turn(FIRST))
    up.done.wait(5)
    assert status == 502 and up.accepts == 1 and len(up.requests) == 1
    assert "upstream failed before an answer" in px.markers()[0]


def test_a13_an_upstream_5xx_is_silence_and_a_4xx_is_not(running):
    up, px = running([[json_response({"error": {"type": "overloaded_error"}}, status=500)],
                      [json_response({"error": "bad key"}, status=401)],
                      [json_response({"error": "slow down"}, status=429)]])
    status, _, body = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert (status, body) == (500, b'{"error": {"type": "overloaded_error"}}')
    (marker,) = px.markers()
    assert "upstream answered 500; relayed unchanged" in marker
    assert post(px, "/v1/messages", anthropic_turn(FIRST))[0] == 401
    assert post(px, "/v1/messages", anthropic_turn(FIRST))[0] == 429
    assert len(px.markers()) == 1


def test_e2_an_upstream_cut_mid_answer_is_one_silence_line(running):
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]), chunk("data: {}\n\n"), b"5\r\nab", "close"]])
    raw = call(px, "POST", "/v1/messages", (), json.dumps(anthropic_turn(FIRST)).encode())
    assert raw.startswith(b"HTTP/1.1 200 ") and not raw.endswith(b"0\r\n\r\n")
    (marker,) = px.markers()
    assert "upstream failed during the answer (status 200 already sent)" in marker


def test_e2_an_upstream_timeout_is_504(running, monkeypatch):
    monkeypatch.setattr(proxy, "UPSTREAM_TIMEOUT", 0.5)
    up, px = running([["hold"]])
    status, _, _ = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert status == 504 and "timed out" in px.markers()[0]


def test_e2_https_is_never_spoken_as_plain_http(tmp_path):
    up = FakeUpstream(raw=True)
    px = Running(tmp_path, "https://127.0.0.1:%d" % up.port)
    try:
        status, _, _ = post(px, "/v1/messages", anthropic_turn(FIRST))
        assert status == 502 and up.requests and up.requests[0][:1] == b"\x16"
        assert b"POST" not in up.requests[0] and b"messages" not in up.requests[0]
        assert "upstream failed before an answer" in px.markers()[0]
    finally:
        px.stop()
        up.close()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl to make a self-signed certificate")
def test_e2_an_untrusted_certificate_is_refused(tmp_path):
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    proc = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out",
                           str(cert), "-days", "1", "-subj", "/CN=127.0.0.1"], capture_output=True, timeout=60)
    if proc.returncode != 0:
        pytest.skip("openssl could not make a certificate: %r" % proc.stderr[-200:])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    seen = []

    def serve():
        conn, _ = sock.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                seen.append(tls.recv(4096))
        except (ssl.SSLError, OSError) as exc:
            seen.append(type(exc).__name__)
    threading.Thread(target=serve, daemon=True).start()
    px = Running(tmp_path, "https://127.0.0.1:%d" % sock.getsockname()[1])
    try:
        status, _, _ = post(px, "/v1/messages", anthropic_turn(FIRST))
        (marker,) = px.markers()
        assert status == 502 and "SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED (self" in marker
        assert not any(isinstance(x, bytes) and x for x in seen)
    finally:
        px.stop()
        sock.close()


# --- reading bodies -----------------------------------------------------------------------------

def test_e2_a_gzip_answer_is_relayed_compressed_and_read(running):
    answer = {"content": [{"type": "tool_use", "id": "toolu_z", "name": "WebFetch",
                           "input": {"url": "https://example.org/a"}}]}
    packed = gzip.compress(json.dumps(answer).encode())
    up, px = running([[json_response(None, headers=(("Content-Type", "application/json"), ("Content-Encoding", "gzip")),
                                     raw_body=packed)]])
    status, _, body = post(px, "/v1/messages", anthropic_turn(FIRST), [["Accept-Encoding", "gzip"]])
    assert (status, body) == (200, packed)
    (pre,) = px.tools()
    assert (pre["tool"], pre["input_meta"]) == ("WebFetch", {"url_host": "example.org"})


def test_e2_the_decoder_reads_gzip_and_both_deflates_and_is_bounded():
    text = b'{"a": 1}' * 100
    raw = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    for encoding, packed in (("gzip", gzip.compress(text)), ("x-gzip", gzip.compress(text)),
                             ("deflate", zlib.compress(text)), ("deflate", raw.compress(text) + raw.flush()),
                             ("identity", text), ("", text), (None, text)):
        assert proxy.decode_body(packed, encoding) == text, encoding
    with pytest.raises(proxy.Unreadable, match="larger than the 100 bytes"):
        proxy.Decoder("gzip", limit=100).feed(gzip.compress(text))
    with pytest.raises(proxy.Unreadable, match="larger than the 100 bytes"):
        proxy.Decoder(None, limit=100).feed(text)
    for encoding in ("br", "zstd", "gzip, br", "compress"):
        with pytest.raises(proxy.Unreadable, match="cannot be read"):
            proxy.Decoder(encoding)
    with pytest.raises(proxy.Unreadable, match="does not decode"):
        proxy.decode_body(b"not gzip at all", "gzip")


def test_e2_a_chunked_request_is_relayed_as_it_came_and_read(running):
    up, px = running([[json_response({"choices": []})]])
    first = {"role": "system", "content": "s"}
    body = json.dumps({"model": "m", "messages": [first, {"role": "tool", "tool_call_id": "call_c", "content": "x"}]})
    chunks = chunk(body[:10]) + chunk(body[10:]) + b"0\r\n\r\n"
    call(px, "POST", "/v1/chat/completions", [["Transfer-Encoding", "chunked"]], chunks)
    (req,) = up.requests
    assert req["body"] == chunks and ("Transfer-Encoding", "chunked") in req["headers"]
    assert [(r["phase"], r.get("tool_use_ids")) for r in px.records()] == [("session_start", None),
                                                                         ("history", ["call_c"])]


@pytest.mark.parametrize("headers, raw_body, why", [
    ((("Content-Type", "application/json"), ("Content-Encoding", "br")), b"\x00\x01", "Content-Encoding br cannot be read"),
    ((("Content-Type", "application/json"),), b"{not json", "the body is not JSON"),
    ((("Content-Type", "text/plain"),), b"hello", "Content-Type text/plain is neither JSON nor an event stream"),
])
def test_e2_an_answer_that_cannot_be_read_is_relayed_and_is_silence(running, headers, raw_body, why):
    up, px = running([[json_response(None, headers=headers, raw_body=raw_body)]])
    status, _, body = post(px, "/v1/messages", anthropic_turn(FIRST))
    assert (status, body) == (200, raw_body)
    (marker,) = px.markers()
    assert "did not read an answer (%s): its tool calls are not recorded" % why in marker


def test_e2_a_request_that_cannot_be_read_is_relayed_and_is_silence(running):
    up, px = running([[json_response({})], [json_response({})]])
    call(px, "POST", "/v1/messages", (), b"{not json")
    call(px, "POST", "/v1/messages", (), b"[1, 2]")
    assert [r["body"] for r in up.requests] == [b"{not json", b"[1, 2]"]
    assert "did not read a request (the body is not JSON)" in px.markers()[0]
    assert "did not read a request (not a JSON object)" in px.markers()[1]


def test_e2_model_requests_on_paths_it_cannot_read_are_silence_once_per_path(running):
    up, px = running([[json_response({})]] * 4)
    for path in ("/v1/responses", "/v1/responses", "/v1beta/models/m:generateContent"):
        call(px, "POST", path, (), json.dumps({"model": "m", "tools": [], "input": "x"}).encode())
    call(px, "POST", "/v1/embeddings", (), json.dumps({"model": "m", "input": "x"}).encode())
    markers = px.markers()
    assert len(markers) == 2 and markers[0].endswith("POST /v1/responses")
    assert markers[1].endswith("POST /v1beta/models/m:generateContent")


def test_e2_count_tokens_is_relayed_and_never_recorded(running):
    up, px = running()
    post(px, "/v1/messages/count_tokens", anthropic_turn(FIRST, {"role": "user", "content": [tool_result("t")]}))
    assert len(up.requests) == 1 and px.lines() == []


def test_e3_stream_parsers_finish_cut_streams_and_skip_server_tools():
    s = proxy.StreamCalls(proxy.ANTHROPIC)
    calls = s.feed(b'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
                   b'"content_block":{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{}}}\n\n'
                   b'data: {"type":"content_block_stop","index":0}\r\n\r\n'
                   b'data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1",'
                   b'"name":"Bash","input":{}}}\n\ndata: {"type":"content_block_delta","index":1,"delta":'
                   b'{"type":"input_json_delta","partial_json":"{\\"command\\":\\"rm a\\"}"}}\n\n')
    assert calls == []
    (one,) = s.finish()
    assert (one.id, one.name, one.input, s.complete) == ("t1", "Bash", {"command": "rm a"}, False)
    o = proxy.StreamCalls(proxy.OPENAI)
    o.feed(b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f",'
           b'"arguments":"{\\"a\\""}}]}}]}\n\n')
    o.feed(b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f",'
           b'"arguments":":1}"}}]}}]}\n\n')   # a provider that repeats the id and the name
    (one,) = o.feed(b"data: [DONE]\n\n")
    assert (one.id, one.name, one.input, o.complete) == ("c1", "f", {"a": 1}, True)
    assert proxy.tool_input_of("not json") == "not json" and proxy.tool_input_of("") == ""


def test_e2_never_logs_a_request_line_and_errors_by_class():
    source = (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    assert "def log_message(self, format, *args):\n        pass" in source
    assert proxy.describe_error(ValueError("Invalid header value b'Bearer %s'" % SECRETS[0])) == "ValueError"
    assert proxy.describe_error(ConnectionRefusedError(111, "Connection refused")) == \
        "ConnectionRefusedError: [Errno 111] Connection refused"


# --- E2: the command ----------------------------------------------------------------------------

def test_e2_the_cli_proxy_end_to_end(tmp_path):
    answer = {"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"tool_calls": [
        {"id": "call_cli", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"curl x\"}"}}]}}]}
    up = FakeUpstream([[json_response(answer)]])
    log = tmp_path / "trace.jsonl"
    proc = subprocess.Popen([sys.executable, "-m", "raqib", "proxy", "--listen", "127.0.0.1:0", "--upstream", up.url(),
                             "--allow-plain-upstream", "--log", str(log)], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        banner = proc.stdout.readline().decode()
        assert banner.startswith("raqib: proxy http://127.0.0.1:") and "-> %s (trace %s, one session per conversation" % (
            up.url(), log) in banner
        port = int(banner.split("http://127.0.0.1:", 1)[1].split("/", 1)[0])
        status, _, body = parse_response(send(port, raw_request(
            "POST", "/v1/chat/completions", [["Host", "127.0.0.1:%d" % port], ["Connection", "close"],
                                             ["Authorization", "Bearer " + SECRETS[0]]],
            b'{"model":"m","messages":[{"role":"system","content":"s"}]}')))
        assert (status, json.loads(body)) == (200, answer)
        start, pre = [json.loads(x) for x in log.read_text().splitlines()]
        assert (start["phase"], pre["source"], pre["tool_use_id"]) == ("session_start", "proxy", "call_cli")
        assert pre["session_id"] == key_of("m", {"role": "system", "content": "s"})
        assert os.path.normcase(pre["cwd"]) == os.path.normcase(os.path.realpath(ROOT))   # the proxy's own cwd
        assert SECRETS[0] not in log.read_text()
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=30)
        up.close()
    assert SECRETS[0].encode() not in out + err


def test_a3_run_writes_session_end_for_the_open_conversations_when_it_stops(tmp_path, monkeypatch):
    up = FakeUpstream([[answer_with(tool_use("t1"))]])
    log = tmp_path / "trace.jsonl"
    started = threading.Event()
    servers = []
    real = proxy.make_server

    def make(*a):
        server = real(*a)
        servers.append(server)
        started.set()
        return server
    monkeypatch.setattr(proxy, "make_server", make)
    out = io.StringIO()
    worker = threading.Thread(target=proxy.run, args=("127.0.0.1:0", up.url(), str(log), True, out),
                              kwargs={"cwd": "/w/p", "err": io.StringIO()}, daemon=True)
    worker.start()
    assert started.wait(10)
    port = servers[0].server_address[1]
    send(port, raw_request("POST", "/v1/messages", [["Host", "127.0.0.1:%d" % port], ["Connection", "close"]],
                           json.dumps(anthropic_turn(FIRST)).encode()))
    servers[0].shutdown()
    worker.join(10)
    assert [r["phase"] for r in (json.loads(x) for x in log.read_text().splitlines())] == [
        "session_start", "pre", "session_end"]
    up.close()


# --- E5 and the Amendment A docs -----------------------------------------------------------------

def test_e5_readme_watch_another_agent_and_adr_0003_accepted():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = " ".join(readme.split("\n## Watch another agent\n", 1)[1].split("\n## ", 1)[0].split())
    assert "raqib proxy --listen 127.0.0.1:8787 --upstream https://api.moonshot.ai --log" in section
    assert "OpenAI-compatible chat/completions API" in section and "Anthropic messages API" in section
    assert ("**Kimi Code CLI:** in `~/.kimi-code/config.toml`, set the provider's `base_url`" in section
            and "`http://127.0.0.1:8787/v1`" in section and "was not run here" in section)
    assert "see the agent's docs for its base-URL setting" in section
    for phrase in ("one session per conversation", "`--cwd DIR`", "`raqib ui TRACE --serve`",
                   "`--allow-plain-upstream`", "127.0.0.0/8", "set the base URL back when the proxy stops",
                   "a fresh port for each run", "only `127.0.0.1:PORT`", "Connection: close",
                   "the Content-Type and Content-Encoding of an answer it cannot read",
                   "written before M5.2 carry no `source`", "SCOPE-PATH", "`history`"):
        assert phrase in section, phrase
    for name in ("openai-session.json", "anthropic-session.json", "openai-session.trace.log",
                 "anthropic-session.trace.log", "mixed-sources.trace.log"):
        assert (PROXY / name).is_file(), name
    adr = (ROOT / "docs" / "specs" / "ADR-0003-capture-sources.md").read_text(encoding="utf-8")
    assert adr.splitlines()[2] == "Status: accepted (M5.2, 2026-11-03). Proposed by the Table, 2026-11-02."
    assert adr.index("## Builder note (2026-11-03, M5.2;") < adr.index("## Amendment A (the Table, 2026-11-03)")
    for name in ("openai-session.json", "anthropic-session.json"):
        text = (PROXY / name).read_text(encoding="utf-8")
        assert '"upstream": "https://api.example.com"' in text and "sk-" not in text
        assert common.scan_output([json.loads(text)])[0] == []


def test_a6_a12_threat_model_names_the_proxy_holes():
    flat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    for phrase in ("a forged `post` sent first suppresses the real one", "Origin header",
                   "the API key travels in the clear to whatever process holds the port",
                   "`SSL_CERT_FILE` and `SSL_CERT_DIR`", "`HTTPS_PROXY` is not used",
                   "Content-Type and Content-Encoding", "the conversation key"):
        assert phrase in flat, phrase
