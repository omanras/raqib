"""M5.2: the proxy capture source (ADR-0003), common.py (E1), the source field
(E3) and the source per finding (E4). The upstream is a local fake that speaks
raw HTTP, so the bytes on both sides of the proxy can be compared."""
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
from raqib.rules import engine, silence, trace  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
PROXY = FIXTURES / "proxy"
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
CATALOG = ROOT / "raqib" / "rules" / "catalog"
SESSION = "proxy-fixture"
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
        return "2026-11-03T10:00:%02d.000Z" % self.n


class Running:
    """The proxy in this process, on a free port, in front of an upstream."""

    def __init__(self, tmp_path, upstream_url, session=SESSION, log=None, err=None):
        self.log = Path(log or tmp_path / "trace.jsonl")
        self.err = err or io.StringIO()
        self.recorder = proxy.Recorder(str(self.log), session, cwd=CWD, clock=Clock(), err=self.err)
        target = proxy.parse_upstream(upstream_url, allow_plain=upstream_url.startswith("http:"))
        self.server = proxy.make_server(("127.0.0.1", 0), target, self.recorder)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def records(self):
        return [json.loads(x) for x in self.lines() if x.startswith("{")]

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


def request_of(exchange):
    req = exchange["request"]
    body = json.dumps(req["json"], separators=(",", ":")).encode()
    return raw_request(req["method"], req["path"], req["headers"] + [["Host", "127.0.0.1"], ["Connection", "close"]],
                       body), body


def replay(tmp_path, name, start):
    """Replay a recorded session through the proxy; (upstream, proxy, responses)."""
    session = json.loads((PROXY / ("%s-session.json" % name)).read_text(encoding="utf-8"))
    up, px = start([script_of(x["response"]) for x in session["exchanges"]])
    answers = []
    for exchange in session["exchanges"]:
        data, _ = request_of(exchange)
        answers.append(parse_response(send(px.port, data)))
    return session, up, px, answers


def run_report(path, *extra):
    out = io.StringIO()
    code = cli.main(["report", str(path)] + list(extra), out=out)
    return code, out.getvalue()


# --- E1: one module of shared helpers ----------------------------------------------------

def test_e1_capture_and_proxy_share_common():
    assert capture.common is common and proxy.common is common and proxy.capture is capture
    for name in common.__all__:
        assert getattr(capture, name) is getattr(common, name), name
    for name in ("canonical_sha256", "input_meta", "command_head", "command_programs", "redact", "output_meta"):
        assert name in common.__all__
    # The proxy names no helper of its own for what common does.
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


def test_e1_a_hook_without_common_is_one_silence_line_and_exit_0(tmp_path):
    lone = tmp_path / "hooks"
    lone.mkdir()
    shutil.copy(CAPTURE, lone / "capture.py")
    log = tmp_path / "trace.jsonl"
    proc = subprocess.run([sys.executable, "-I", str(lone / "capture.py"), str(log)], timeout=30,
                          input=(FIXTURES / "pretooluse-bash.json").read_bytes(), capture_output=True)
    assert (proc.returncode, proc.stdout) == (0, b"")
    (line,) = proc.stderr.decode().splitlines()
    assert line.startswith("RAQIB-SILENCE: capture failed event=- log=-: cannot load common.py: ")
    assert not log.exists()
    # Loaded by path under another name (as the tests load it), the error is raised, not hidden.
    spec = importlib.util.spec_from_file_location("raqib_capture_alone", lone / "capture.py")
    with pytest.raises(OSError):
        spec.loader.exec_module(importlib.util.module_from_spec(spec))


# --- E3: the source field ----------------------------------------------------------------

def test_e3_a_hook_line_is_the_old_line_with_source_hook_last(tmp_path):
    log = tmp_path / "trace.jsonl"
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    for name in ("sessionstart.json", "pretooluse-bash.json", "posttooluse-bash.json", "stop.json"):
        proc = subprocess.run([sys.executable, str(CAPTURE), str(log)], env=env, timeout=30,
                              input=(FIXTURES / name).read_bytes(), capture_output=True)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")
    for line in log.read_text().splitlines():
        rec = json.loads(line)
        assert list(rec)[-1] == "source" and rec["source"] == "hook"
        old = dict(rec)
        del old["source"]
        # The line an older raqib wrote for the same event is a byte prefix of this one.
        assert line == json.dumps(old, separators=(",", ":"))[:-1] + ',"source":"hook"}'


def test_e3_old_traces_load_unchanged_and_read_as_hook():
    for path in sorted(FIXTURES.glob("*.log")) + [FIXTURES / "field" / "2026-11-02.log"]:
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


def test_e2_upstream_forms_and_tls_verification_on():
    up = proxy.parse_upstream("https://api.example.com/v1/")
    assert (up.scheme, up.host, up.port, up.prefix, up.netloc) == ("https", "api.example.com", 443, "/v1",
                                                                    "api.example.com")
    assert up.target("/chat/completions?x=1") == "/v1/chat/completions?x=1"
    assert proxy.parse_upstream("https://api.example.com:8443").netloc == "api.example.com:8443"
    assert proxy.parse_upstream("http://127.0.0.1:9", True).url == "http://127.0.0.1:9"
    assert proxy.parse_upstream("http://[::1]:9", True).netloc == "[::1]:9"
    ctx = proxy.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    conn = up.connection()
    assert isinstance(conn, proxy.http.client.HTTPSConnection) and conn._context.verify_mode == ssl.CERT_REQUIRED
    source = (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    for banned in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "verify=False"):
        assert banned not in source


def test_e2_cli_refuses_bad_options_with_exit_2(tmp_path, capsys):
    log = str(tmp_path / "t.jsonl")
    assert cli.main(["proxy", "--listen", "0.0.0.0:0", "--upstream", "https://api.example.com", "--log", log]) == 2
    assert cli.main(["proxy", "--listen", "127.0.0.1:0", "--upstream", "http://127.0.0.1:9", "--log", log]) == 2
    assert cli.main(["proxy", "--listen", "127.0.0.1:0", "--upstream", "https://api.example.com",
                     "--log", str(tmp_path / "no" / "dir" / "t.jsonl")]) == 2
    err = capsys.readouterr().err
    assert "127.0.0.1 only" in err and "--allow-plain-upstream" in err and "cannot write the trace" in err
    assert cli.main(["proxy", "--upstream", "https://api.example.com", "--log", log]) == 2   # --listen required


# --- E2/E3/E4: the recorded sessions ------------------------------------------------------------

@pytest.mark.parametrize("name", ["openai", "anthropic"])
def test_e3_the_recorded_session_gives_the_fixture_trace(tmp_path, running, name):
    session, up, px, answers = replay(tmp_path, name, running)
    assert px.log.read_text(encoding="utf-8") == (PROXY / ("%s-session.trace.log" % name)).read_text(encoding="utf-8")
    recs = px.records()
    assert [(r["phase"], r["seq"]) for r in recs] == [("pre", 1), ("pre", 2), ("post", 1), ("post", 2)]
    assert all(r["source"] == "proxy" and r["session_id"] == SESSION and r["cwd"] == CWD for r in recs)
    assert recs[0]["tool_use_id"] == recs[2]["tool_use_id"] and recs[1]["tool_use_id"] == recs[3]["tool_use_id"]
    assert recs[0]["input_sha256"] == recs[2]["input_sha256"] and recs[1]["input_sha256"] == recs[3]["input_sha256"]
    # Hashes and the extract only: no prompt, argument, output or key text.
    text = px.log.read_text(encoding="utf-8")
    for fragment in ("203.0.113.7", "notes.txt", "Upload the notes", "coding agent", "total 0", "No such file",
                     "build directory", "-rf", "-la") + SECRETS:
        assert fragment not in text, fragment
    assert not px.markers() and px.err.getvalue() == ""
    # Bytes unchanged both ways.
    for exchange, got, (status, headers, body) in zip(session["exchanges"], up.requests, answers):
        _, sent = request_of(exchange)
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
        assert rep["sources"] == {"proxy": 4} and "sources: proxy 4" in text.splitlines()
        assert "      source: proxy" in text.splitlines()
        assert not rep["alarms"]


def test_e4_mixed_sources_in_one_trace(tmp_path):
    """The mixed fixture is a hook trace of v0.1 (no source field) followed by
    a proxy session; each finding names the source of its own lines."""
    mixed = PROXY / "mixed-sources.trace.log"
    parts = (FIXTURES / "blocked-calls-claude-code-2.1.301.log").read_text(encoding="utf-8") + \
        (PROXY / "anthropic-session.trace.log").read_text(encoding="utf-8")
    assert mixed.read_text(encoding="utf-8") == parts
    code, text = run_report(mixed)
    rep = json.loads(run_report(mixed, "--json")[1])
    by_source = {}
    for f in rep["findings"]:
        by_source.setdefault(f["source"], set()).add(f["rule_id"])
    assert code == 1 and by_source == {"hook": {"SILENCE-HALF"}, "proxy": {"DESTRUCT-CMD"}}
    hook_records = len(trace.read(FIXTURES / "blocked-calls-claude-code-2.1.301.log")[0])
    assert rep["sources"] == {"hook": hook_records, "proxy": 4}
    assert "sources: hook %d, proxy 4" % hook_records in text.splitlines()
    lines = text.splitlines()
    for f in rep["findings"]:
        head = "  [%s] %s (%s, %s) session %s seq %s" % (f["severity"], f["rule_id"], f["class"], f["kind"],
                                                         f["session_id"], ",".join(map(str, f["cited_seq"])))
        assert lines[lines.index(head) + 1] == "      source: %s" % f["source"]
    # The page: a source column on every timeline row, the source on every finding card.
    page = ui.render(rep, trace.read_numbered(mixed)[0], [])
    assert "<th>session</th><th>source</th><th>seq</th>" in page
    assert page.count("<td>hook</td>") == hook_records and page.count("<td>proxy</td>") == 4
    for name in ("hook", "proxy"):
        assert page.count(", source %s</span>" % name) == sum(f["source"] == name for f in rep["findings"]) > 0


def test_e4_a_finding_with_no_line_in_the_trace_names_no_source():
    index = {}
    assert report._source(index, "s", [1]) == "-"
    index = {("s", 1): [(1, {"source": "proxy"})], ("s", 2): [(2, {})]}
    assert report._source(index, "s", [1, 2]) == "hook+proxy"


# --- E2: relaying ------------------------------------------------------------------------------

def test_e2_headers_are_relayed_except_host_and_hop_by_hop(running):
    up, px = running([[json_response({"id": "x"}, headers=(("Content-Type", "application/json"), ("X-Up", "1"),
                                                           ("Connection", "close"), ("Keep-Alive", "timeout=5"),
                                                           ("x-request-id", "r-1")))]])
    headers = [["Host", "127.0.0.1:%d" % px.port], ["Authorization", "Bearer " + SECRETS[0]], ["X-Hop", "1"],
               ["Connection", "close, X-Hop"], ["Keep-Alive", "timeout=5"], ["Proxy-Authorization", "Basic x"],
               ["TE", "trailers"], ["Upgrade", "h2c"], ["Accept-Encoding", "identity"], ["X-Agent", "a b"],
               ["Content-Type", "application/json"]]
    body = b'{"model":"m","messages":[]}'
    status, got, answer = parse_response(send(px.port, raw_request("POST", "/v1/chat/completions?x=1", headers, body)))
    (req,) = up.requests
    assert req["line"] == "POST /v1/chat/completions?x=1 HTTP/1.1"
    assert req["headers"] == [("Host", "127.0.0.1:%d" % up.port), ("Authorization", "Bearer " + SECRETS[0]),
                              ("Accept-Encoding", "identity"), ("X-Agent", "a b"), ("Content-Type", "application/json"),
                              ("Content-Length", str(len(body)))]
    assert req["body"] == body
    # The answer: the upstream's headers in order, minus hop-by-hop; nothing added (no Server, no Date).
    assert (status, answer) == (200, b'{"id": "x"}')
    assert got == [("Content-Type", "application/json"), ("X-Up", "1"), ("x-request-id", "r-1"),
                   ("Content-Length", "11")]
    assert not px.markers() and px.records() == []


def test_e2_an_upstream_path_prefix_and_other_methods_pass_unrecorded(running, tmp_path):
    up = FakeUpstream([[json_response({"data": []})], [json_response({"deleted": True})]])
    px = Running(tmp_path, up.url() + "/base")
    try:
        status, _, body = parse_response(send(px.port, raw_request("GET", "/v1/models", [["Connection", "close"]])))
        assert (status, body) == (200, b'{"data": []}')
        send(px.port, raw_request("DELETE", "/v1/files/f-1", [["Connection", "close"]]))
        assert [r["line"] for r in up.requests] == ["GET /base/v1/models HTTP/1.1", "DELETE /base/v1/files/f-1 HTTP/1.1"]
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
    body = b'{"model":"m","stream":true,"messages":[]}'
    with socket.create_connection(("127.0.0.1", px.port), timeout=20) as s:
        s.sendall(raw_request("POST", "/v1/chat/completions", [["Connection", "close"]], body))
        got = b""
        while events[0].encode() not in got:
            got += s.recv(65536)
        # The first event is here while the upstream still holds the second: nothing was buffered.
        assert b"finish_reason\":\"tool_calls" not in got and px.records() == []
        first_read.set()
        while b"[DONE]" not in got:
            piece = s.recv(65536)
            if b"tool_calls\"}" in piece or b"finish_reason\":\"tool_calls" in piece:
                # The piece that completes the call is passed on only after its pre is in the trace.
                assert [r["phase"] for r in px.records()] == ["pre"]
            got += piece
        while not got.endswith(b"0\r\n\r\n"):
            got += s.recv(65536)
    status, _, answer = parse_response(got)
    assert (status, answer) == (200, "".join(events).encode())
    (pre,) = px.records()
    assert (pre["tool"], pre["tool_use_id"], pre["input_meta"]) == ("Bash", "call_s", {"command_head": "ls",
                                                                                        "command_programs": ["ls"]})


def test_e3_a_result_posted_once_and_an_unmatched_result_is_a_half(running):
    def turn(messages):
        return raw_request("POST", "/v1/messages", [["Connection", "close"]],
                           json.dumps({"model": "m", "messages": messages}).encode())
    answer = {"type": "message", "content": [{"type": "tool_use", "id": "toolu_a", "name": "Read",
                                              "input": {"file_path": "/work/example/a.txt"}}], "stop_reason": "tool_use"}
    up, px = running([[json_response(answer)], [json_response({"type": "message", "content": []})],
                      [json_response({"type": "message", "content": []})]])
    history = [{"role": "user", "content": "read a"},
               {"role": "assistant", "content": answer["content"]},
               {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_a", "content": "A"}]}]
    send(px.port, turn(history[:1]))
    send(px.port, turn(history))
    # The next turn repeats the result (posted already) and holds one whose call the proxy never saw.
    send(px.port, turn(history + [{"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_b", "name": "Bash",
                                                                     "input": {"command": "rm x"}}]},
                                  {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_b",
                                                                "content": "done"},
                                                               {"type": "tool_result", "tool_use_id": "toolu_c",
                                                                "content": "?"}]}]))
    recs = px.records()
    assert [(r["phase"], r["seq"], r.get("tool_use_id"), r["tool"]) for r in recs] == [
        ("pre", 1, "toolu_a", "Read"), ("post", 1, "toolu_a", "Read"), ("post", 2, "toolu_b", "Bash"),
        ("post", 3, "toolu_c", "?")]
    assert recs[1]["input_meta"] == {"path": "/work/example/a.txt"} and recs[1]["ok"] is True
    assert recs[2]["input_meta"] == {"command_head": "rm", "command_programs": ["rm"]}
    assert recs[3]["input_meta"] == {} and recs[3]["input_sha256"] == common.canonical_sha256(None)
    halves = [f for f in silence.findings(recs) if f["rule_id"] == "SILENCE-HALF"]
    assert [f["cited_seq"] for f in halves] == [[2], [3]] and all("a pre is missing" in f["summary"] for f in halves)


def test_e3_a_restarted_proxy_closes_the_calls_of_the_run_before(tmp_path, running):
    answer = {"choices": [{"index": 0, "message": {"tool_calls": [
        {"id": "call_r", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"ls\"}"}}]}}]}
    up, first = running([[json_response(answer)]], session="proxy-run-1")
    send(first.port, raw_request("POST", "/v1/chat/completions", [["Connection", "close"]], b'{"messages":[]}'))
    first.stop()
    up2, second = running([[json_response({"choices": []})]], session="proxy-run-2", log=first.log)
    msgs = [{"role": "assistant", "tool_calls": answer["choices"][0]["message"]["tool_calls"]},
            {"role": "tool", "tool_call_id": "call_r", "content": "x"}]
    send(second.port, raw_request("POST", "/v1/chat/completions", [["Connection", "close"]],
                                  json.dumps({"messages": msgs}).encode()))
    recs = second.records()
    assert [(r["session_id"], r["phase"], r["seq"]) for r in recs] == [("proxy-run-1", "pre", 1),
                                                                         ("proxy-run-1", "post", 1)]
    assert not silence.findings(recs)


def test_e3_a_hook_pre_with_the_same_id_is_not_the_proxys(running, tmp_path):
    log = tmp_path / "trace.jsonl"
    log.write_text(json.dumps({"ts": "2026-11-03T09:00:00.000Z", "seq": 1, "session_id": "claude-1", "phase": "pre",
                               "tool": "Bash", "tool_use_id": "toolu_h", "input_sha256": "0" * 64, "input_meta": {},
                               "cwd": CWD}) + "\n", encoding="utf-8")
    up, px = running([[json_response({"content": []})]], log=log)
    msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_h", "content": "x"}]}]
    send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]], json.dumps({"messages": msgs}).encode()))
    hook, post = px.records()
    assert "source" not in hook and (post["session_id"], post["seq"], post["source"]) == (SESSION, 1, "proxy")


def test_e3_tool_results_are_scanned_for_secret_names_only(running):
    token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    up, px = running([[json_response({"choices": []})]])
    msgs = [{"role": "tool", "tool_call_id": "call_k", "content": "token=" + token}]
    send(px.port, raw_request("POST", "/v1/chat/completions", [["Connection", "close"]],
                              json.dumps({"messages": msgs}).encode()))
    (post,) = px.records()
    assert post["output_meta"] == {"scan": "full", "secret_kinds": ["github_token"]}
    assert token not in px.log.read_text() and token[-12:] not in px.log.read_text()


# --- E2 / A3: failures -------------------------------------------------------------------------

def test_e2_an_upstream_that_refuses_is_502_and_one_silence_line(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens there
    px = Running(tmp_path, "http://127.0.0.1:%d" % port)
    try:
        status, headers, body = parse_response(send(px.port, raw_request(
            "POST", "/v1/chat/completions?api_key=" + SECRETS[0], [["Authorization", "Bearer " + SECRETS[0]]],
            b'{"messages":[]}')))
        assert status == 502 and b"did not answer" in body and ("Connection", "close") in headers
        (marker,) = px.markers()
        assert marker.startswith("RAQIB-SILENCE: proxy upstream failed before an answer: ConnectionRefusedError")
        assert marker.endswith(" session=%s POST /v1/chat/completions" % SESSION)
        assert px.err.getvalue() == marker + "\n" and px.records() == []
        for secret in SECRETS:
            assert secret not in px.log.read_text() and secret not in px.err.getvalue()
    finally:
        px.stop()


def test_e2_no_retry_an_upstream_that_closes_is_asked_once(running):
    up, px = running([["close"]])
    status, _, _ = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                            b'{"messages":[]}')))
    up.done.wait(5)
    assert status == 502 and up.accepts == 1 and len(up.requests) == 1
    (marker,) = px.markers()
    assert "upstream failed before an answer" in marker   # RemoteDisconnected (or a reset, on Windows)


def test_e2_an_upstream_5xx_is_relayed_unchanged_with_one_silence_line(running):
    up, px = running([[json_response({"error": {"type": "overloaded_error"}}, status=500)]])
    status, headers, body = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                                     b'{"messages":[]}')))
    assert (status, body) == (500, b'{"error": {"type": "overloaded_error"}}')
    (marker,) = px.markers()
    assert "upstream answered 500; relayed unchanged" in marker and px.records() == []


def test_e2_an_upstream_4xx_is_relayed_and_is_not_silence(running):
    up, px = running([[json_response({"error": "bad key"}, status=401)]])
    status, _, body = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                               b'{"messages":[]}')))
    assert (status, body) == (401, b'{"error": "bad key"}') and px.lines() == []


def test_e2_an_upstream_cut_mid_answer_is_one_silence_line(running):
    up, px = running([[chunked_head([("Content-Type", "text/event-stream")]), chunk("data: {}\n\n"), b"5\r\nab", "close"]])
    raw = send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]], b'{"messages":[]}'))
    assert raw.startswith(b"HTTP/1.1 200 ") and not raw.endswith(b"0\r\n\r\n")
    (marker,) = px.markers()
    assert "upstream failed during the answer (status 200 already sent)" in marker


def test_e2_an_upstream_timeout_is_504(running, monkeypatch):
    monkeypatch.setattr(proxy, "UPSTREAM_TIMEOUT", 0.5)
    up, px = running([["hold"]])
    status, _, _ = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                            b'{"messages":[]}')))
    assert status == 504 and "timed out" in px.markers()[0]


def test_e2_https_is_never_spoken_as_plain_http(running, tmp_path):
    """An https upstream that answers in plain HTTP fails the TLS handshake:
    502 and one line; the upstream saw a TLS ClientHello, never the request."""
    up = FakeUpstream(raw=True)
    px = Running(tmp_path, "https://127.0.0.1:%d" % up.port)
    try:
        status, _, _ = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                                b'{"messages":[]}')))
        assert status == 502 and up.requests and up.requests[0][:1] == b"\x16"
        assert b"POST" not in up.requests[0] and b"messages" not in up.requests[0]
        (marker,) = px.markers()
        assert "upstream failed before an answer" in marker
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
        status, _, _ = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                                b'{"messages":[]}')))
        (marker,) = px.markers()
        assert status == 502 and "SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED (self" in marker
        assert not any(isinstance(x, bytes) and x for x in seen)   # no request bytes ever reached it
    finally:
        px.stop()
        sock.close()


def test_e2_requests_that_are_not_relayed_are_silence(running):
    up, px = running()
    for data, status in ((b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n", 405),
                         (raw_request("GET", "http://api.example.com/v1/models", [["Connection", "close"]]), 400),
                         (raw_request("POST", "/v1/messages", [["Transfer-Encoding", "gzip, chunked"]], b""), 501)):
        assert parse_response(send(px.port, data))[0] == status
    assert len(px.markers()) == 3 and all("did not relay a request" in m for m in px.markers())
    assert up.requests == []


# --- reading bodies -----------------------------------------------------------------------------

def test_e2_a_gzip_answer_is_relayed_compressed_and_read(running):
    answer = {"content": [{"type": "tool_use", "id": "toolu_z", "name": "WebFetch", "input": {"url": "https://example.org/a"}}]}
    packed = gzip.compress(json.dumps(answer).encode())
    up, px = running([[json_response(None, headers=(("Content-Type", "application/json"), ("Content-Encoding", "gzip")),
                                     raw_body=packed)]])
    status, _, body = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"],
                                                                                        ["Accept-Encoding", "gzip"]],
                                                               b'{"messages":[]}')))
    assert (status, body) == (200, packed)
    (pre,) = px.records()
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
    up, px = running()
    body = json.dumps({"messages": [{"role": "tool", "tool_call_id": "call_c", "content": "x"}]}).encode()
    chunks = chunk(body[:10]) + chunk(body[10:]) + b"0\r\n\r\n"
    send(px.port, raw_request("POST", "/v1/chat/completions", [["Transfer-Encoding", "chunked"], ["Connection", "close"]],
                              chunks))
    (req,) = up.requests
    assert req["body"] == chunks and ("Transfer-Encoding", "chunked") in req["headers"]
    (post,) = px.records()
    assert post["tool_use_id"] == "call_c"


@pytest.mark.parametrize("headers, raw_body, why", [
    ((("Content-Type", "application/json"), ("Content-Encoding", "br")), b"\x00\x01", "Content-Encoding br cannot be read"),
    ((("Content-Type", "application/json"),), b"{not json", "the body is not JSON"),
    ((("Content-Type", "text/plain"),), b"hello", "Content-Type text/plain is neither JSON nor an event stream"),
])
def test_e2_an_answer_that_cannot_be_read_is_relayed_and_is_silence(running, headers, raw_body, why):
    up, px = running([[json_response(None, headers=headers, raw_body=raw_body)]])
    status, _, body = parse_response(send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]],
                                                               b'{"messages":[]}')))
    assert (status, body) == (200, raw_body)
    (marker,) = px.markers()
    assert "did not read an answer (%s): its tool calls are not recorded" % why in marker


def test_e2_a_request_that_cannot_be_read_is_relayed_and_is_silence(running):
    up, px = running()
    send(px.port, raw_request("POST", "/v1/messages", [["Connection", "close"]], b"{not json"))
    assert up.requests[0]["body"] == b"{not json"
    (marker,) = px.markers()
    assert "did not read a request (the body is not JSON): its tool results are not recorded" in marker


def test_e2_model_requests_on_paths_it_cannot_read_are_silence_once_per_path(running):
    up, px = running([[json_response({})]] * 4)
    for path in ("/v1/responses", "/v1/responses", "/v1beta/models/m:generateContent"):
        send(px.port, raw_request("POST", path, [["Connection", "close"]],
                                  json.dumps({"model": "m", "tools": [], "input": "x"}).encode()))
    send(px.port, raw_request("POST", "/v1/embeddings", [["Connection", "close"]],
                              json.dumps({"model": "m", "input": "x"}).encode()))
    markers = px.markers()
    assert len(markers) == 2 and markers[0].endswith("POST /v1/responses")
    assert markers[1].endswith("POST /v1beta/models/m:generateContent")


def test_e2_count_tokens_is_relayed_and_never_recorded(running):
    up, px = running()
    msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_n", "content": "x"}]}]
    send(px.port, raw_request("POST", "/v1/messages/count_tokens", [["Connection", "close"]],
                              json.dumps({"model": "m", "messages": msgs}).encode()))
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
    (call,) = s.finish()   # the stream ended before content_block_stop
    assert (call.id, call.name, call.input) == ("t1", "Bash", {"command": "rm a"})
    o = proxy.StreamCalls(proxy.OPENAI)
    o.feed(b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f",'
           b'"arguments":"{\\"a\\""}}]}}]}\n\n')
    o.feed(b'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f",'
           b'"arguments":":1}"}}]}}]}\n\n')   # a provider that repeats the id and the name
    (call,) = o.feed(b"data: [DONE]\n\n")
    assert (call.id, call.name, call.input) == ("c1", "f", {"a": 1})
    assert proxy.tool_input_of("not json") == "not json" and proxy.tool_input_of("") == ""


def test_e2_never_logs_a_request_line_or_a_header_value():
    source = (ROOT / "raqib" / "hooks" / "proxy.py").read_text(encoding="utf-8")
    assert "def log_message(self, format, *args):\n        pass" in source
    # An exception's own message can quote a header value: only its class (and the OS's words) are written.
    assert proxy.describe_error(ValueError("Invalid header value b'Bearer %s'" % SECRETS[0])) == "ValueError"
    assert proxy.describe_error(ConnectionRefusedError(111, "Connection refused")) == \
        "ConnectionRefusedError: [Errno 111] Connection refused"


# --- E2: the command ----------------------------------------------------------------------------

def test_e2_the_cli_proxy_end_to_end(tmp_path):
    answer = {"choices": [{"index": 0, "message": {"tool_calls": [
        {"id": "call_cli", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\":\"curl x\"}"}}]}}]}
    up = FakeUpstream([[json_response(answer)]])
    log = tmp_path / "trace.jsonl"
    proc = subprocess.Popen([sys.executable, "-m", "raqib", "proxy", "--listen", "127.0.0.1:0", "--upstream", up.url(),
                             "--allow-plain-upstream", "--log", str(log)], cwd=ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        banner = proc.stdout.readline().decode()
        assert banner.startswith("raqib: proxy http://127.0.0.1:") and "-> %s (trace %s, session proxy-" % (
            up.url(), log) in banner
        port = int(banner.split("http://127.0.0.1:", 1)[1].split("/", 1)[0])
        status, _, body = parse_response(send(port, raw_request("POST", "/v1/chat/completions",
                                                                [["Connection", "close"],
                                                                 ["Authorization", "Bearer " + SECRETS[0]]],
                                                                b'{"messages":[]}')))
        assert (status, json.loads(body)) == (200, answer)
        (pre,) = [json.loads(x) for x in log.read_text().splitlines()]
        assert (pre["source"], pre["tool_use_id"]) == ("proxy", "call_cli")
        assert os.path.normcase(pre["cwd"]) == os.path.normcase(os.path.realpath(ROOT))   # the proxy's own cwd
        assert pre["session_id"].startswith("proxy-") and SECRETS[0] not in log.read_text()
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=30)
        up.close()
    assert SECRETS[0].encode() not in out + err


# --- E5: the docs -------------------------------------------------------------------------------

def test_e5_readme_watch_another_agent_and_adr_0003_accepted():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = " ".join(readme.split("\n## Watch another agent\n", 1)[1].split("\n## ", 1)[0].split())
    assert "raqib proxy --listen 127.0.0.1:8787 --upstream https://api.moonshot.ai --log" in section
    assert "OpenAI-compatible chat/completions API" in section and "Anthropic messages API" in section
    assert ("**Kimi Code CLI:** in `~/.kimi-code/config.toml`, set the provider's `base_url`" in section
            and "`http://127.0.0.1:8787/v1`" in section and "was not run here" in section)
    assert "see the agent's docs for its base-URL setting" in section
    assert "tests/fixtures/proxy/" in section and "SILENCE-HALF" in section and "RAQIB-SILENCE:" in section
    for name in ("openai-session.json", "anthropic-session.json", "openai-session.trace.log",
                 "anthropic-session.trace.log", "mixed-sources.trace.log"):
        assert (PROXY / name).is_file(), name
    adr = (ROOT / "docs" / "specs" / "ADR-0003-capture-sources.md").read_text(encoding="utf-8")
    assert adr.splitlines()[2] == "Status: accepted (M5.2, 2026-11-03). Proposed by the Table, 2026-11-02."
    assert "## Builder note (2026-11-03, M5.2; the decision above stays as written)" in adr
    # Synthetic only: documentation hosts, no key-like text in the recorded sessions.
    for name in ("openai-session.json", "anthropic-session.json"):
        text = (PROXY / name).read_text(encoding="utf-8")
        assert '"upstream": "https://api.example.com"' in text and "sk-" not in text
        assert common.scan_output([json.loads(text)])[0] == []
