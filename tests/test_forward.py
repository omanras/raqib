"""M10.3 (ADR-0011 Amendment J): `raqib forward`, the forwarder over HTTP. Every collector here is the rig's
stand-in (tools/rig/collector.py) on loopback, on an ephemeral port, stopped and joined by the fixture; every
clock and wait the forwarder has is injected where a test needs time to pass. The token is a made-up string."""
import ast
import importlib.util
import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
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
    f = forward.Forwarder(kw.pop("name"), path, "%s://127.0.0.1:%d%s" % (scheme, port, PATH), home=str(tmp_path / "home"),
                          out=io.StringIO(), clock=clock, wait=clock.wait, **kw)
    return f


def state(tmp_path, name="t"):
    with open(forward.state_path(name, str(tmp_path / "home")), "rb") as f:
        return json.loads(f.read().decode("ascii"))


def dead_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
    dead = "http://127.0.0.1:%d" % dead_port()
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
    assert [r["status"] for r in c.requests] == [400, 200, 200, 400, 200, 200, 200]
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
    port = collectors(shape="raqib", **how).port if how is not None else dead_port()
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
    # the process's own argument list: a forwarder running as a process of its own
    proc = subprocess.Popen([sys.executable, "-m", "raqib", "forward", path, "--to", "http://127.0.0.1:%d%s" % (
        busy.port, PATH), "--name", "proc", "--shape", "hec", "--token-file", tok, "--beat", "1"], cwd=str(ROOT),
        env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        written, ticks = threading.Event(), 0
        while not (tmp_path / "home" / ".raqib" / "forward" / "proc.json").exists() and ticks < 600:
            ticks += 1
            written.wait(0.05)   # the process is up: it has written its first state
        listed = Path("/proc/%d/cmdline" % proc.pid)
        args = listed.read_bytes().decode("utf-8", "replace") if listed.exists() else " ".join(proc.args)
    finally:
        proc.terminate()
        output = proc.communicate(timeout=30)[0].decode("utf-8", "replace")
    assert "--token-file" in args and TOKEN not in args and TOKEN not in output
    options = [o for a in cli._parser()._subparsers._group_actions[0].choices["forward"]._actions
               for o in a.option_strings]
    assert [o for o in options if "token" in o] == ["--token-file"]


@pytest.mark.skipif(sys.platform == "win32", reason="J-7: on Windows a token file's mode is not checked (the guide"
                                                    " says so)")
def test_e5_off_windows_a_token_file_others_can_read_is_exit_2(tmp_path, capsys):
    tok = secret(tmp_path / "t")
    os.chmod(tok, 0o644)
    argv = ["forward", write(tmp_path / "e.jsonl", lines(1)), "--to", "http://127.0.0.1:9%s" % PATH, "--name", "m",
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
    ca, cert, key = certificates(tmp_path)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PYTHONHTTPSVERIFY", "0")
    monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)   # what that env does
    c = collectors(shape="raqib", cert=cert, key=key)
    path = write(tmp_path / "e.jsonl", lines(2))
    f = fwd(tmp_path, path, c.port, scheme="https")
    assert f.step() == "failed" and f.failing["error"] == "tls" and c.events == []   # the system's: refused
    g = fwd(tmp_path, path, c.port, scheme="https", name="ca", ca=ca)
    assert g.step() == "moved" and len(c.events) == 2 and not g.plain               # --ca: taken
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


def test_e5_connect_within_10_s_and_an_answer_within_30_s(tmp_path, collectors, monkeypatch):
    assert (forward.CONNECT_S, forward.ANSWER_S) == (10.0, 30.0)
    seen = []

    class Spy(forward.http.client.HTTPConnection):
        def request(self, *a, **kw):
            seen.append((self.timeout, self.sock.gettimeout()))
            return super().request(*a, **kw)
    monkeypatch.setattr(forward.http.client, "HTTPConnection", Spy)
    c = collectors(shape="raqib")
    f = forward.Forwarder("s", write(tmp_path / "e.jsonl", lines(1)), "http://127.0.0.1:%d/" % c.port,
                          home=str(tmp_path / "home"), out=io.StringIO())
    assert f.step() == "moved" and seen == [(10.0, 30.0)]


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
         "delivery": "acknowledged", "plain": False, "file": "/f", "cursor": {"offset": 9, "line_sha256": None},
         "from": {"start": "start", "offset": 0}, "beat": 10.0, "sent": 1, "skipped": 0,
         "refused": {"count": 0, "ids": []}, "restarts": 0, "last_id": "r1:1", "last_ok": forward.iso(now),
         "behind": 0, "failing": None}
    s.update(change)
    os.makedirs(forward.forward_dir(home), exist_ok=True)
    with open(forward.state_path(name, home), "w", encoding="ascii") as f:
        json.dump(s, f)


def test_e6_status_exits_0_taken_1_failing_or_behind_3_unreadable_or_older_than_two_beats(tmp_path):
    home, now = str(tmp_path / "home"), 1_800_000_000.0
    clock = Clock(now)

    def code(name=None, at=now):
        out = io.StringIO()
        return forward.status(name, home=home, out=out, clock=Clock(at)), out.getvalue()
    assert code()[0] == 3                                                # nothing has written a state: silent
    write_state(home, "ok", now)
    assert code("ok")[0] == 0 and code("ok", now + 20)[0] == 0
    assert code("ok", now + 20.5)[0] == 3 and "more than two beats" in code("ok", now + 21)[1]
    write_state(home, "fail", now, failing={"since": forward.iso(now), "tries": 3, "error": "server", "status": 503})
    assert code("fail") == (1, code("fail")[1]) and "failing since" in code("fail")[1]
    write_state(home, "behind", now, behind=500, last_ok=forward.iso(now - 11))
    assert code("behind")[0] == 1 and "wait longer than a beat" in code("behind")[1]
    write_state(home, "fresh", now, behind=500, last_ok=forward.iso(now - 5))
    assert code("fresh")[0] == 0
    with open(forward.state_path("bad", home), "wb") as f:
        f.write(b"{not json")
    assert code("bad")[0] == 3 and code("none")[0] == 3
    write_state(home, "keys", now, cursor=None)
    assert code("keys")[0] == 3
    assert code()[0] == 3 and clock.t == now   # every state at once: the worst


def test_e6_the_waits_are_1_2_4_up_to_60_and_it_does_not_give_up(tmp_path):
    clock = Clock()
    clock.then = lambda c: len(c.waits) >= 10
    f = fwd(tmp_path, write(tmp_path / "e.jsonl", lines(2)), dead_port(), clock=clock, beat=1000)
    assert f.run() == 1
    assert clock.waits == [1, 2, 4, 8, 16, 32, 60, 60, 60, 60] and f.failing["tries"] == 10
    assert state(tmp_path)["failing"]["error"] == "connect"


def test_e6_once_exits_0_all_taken_1_not_all_2_usage_and_syslog_is_a_usage_error_that_says_so(tmp_path, collectors,
                                                                                              capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    ok, down = collectors(shape="raqib"), collectors(shape="raqib", fail=10)
    path = write(tmp_path / "e.jsonl", lines(3))

    def run(*argv):
        return cli.main(["forward", path] + list(argv), out=io.StringIO())
    assert run("--to", "http://127.0.0.1:%d/" % ok.port, "--name", "a", "--once") == 0
    assert run("--to", "http://127.0.0.1:%d/" % down.port, "--name", "b", "--once") == 1
    capsys.readouterr()
    for argv in (("--to", "syslog+udp://127.0.0.1:514", "--name", "c", "--once"),
                 ("--to", "syslog+tls://127.0.0.1:6514", "--name", "c", "--once"),
                 ("--to", "http://127.0.0.1:1/", "--name", "Bad_Name", "--once"),
                 ("--to", "http://127.0.0.1:1/", "--once"), ("--name", "c", "--once"),
                 ("--to", "http://127.0.0.1:1/", "--name", "c", "--batch", "101", "--once"),
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
    c = collectors(shape="raqib", late=0.2)
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
    # a real one: a forwarder running as a process of its own, and a second of its name here
    home = str(tmp_path / "real")
    env = dict(os.environ, HOME=home, USERPROFILE=home)
    first = subprocess.Popen([sys.executable, "-m", "raqib", "forward", path, "--to", "http://127.0.0.1:%d/" % c.port,
                              "--name", "real"], cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    try:
        taken = threading.Event()
        for _ in range(600):
            if os.path.exists(os.path.join(forward.forward_dir(home), "real.pid")) or first.poll() is not None:
                break
            taken.wait(0.05)
        assert first.poll() is None
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
                 "no heartbeat of a host for more than two beats", "application/x-ndjson"):
        assert said in flat, said
    for word in forward.ERRORS:
        assert "`%s`" % word in spec_text, word
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    rows = [r for r in guide.splitlines() if r.startswith("| `raqib forward")]
    assert len(rows) == 3 and "no heartbeat of a host for more than two beats" in " ".join(rows)
    assert "on Windows it is not checked" in " ".join(rows)
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "### The forwarder (`raqib forward`" in threat
    for said in ("**the token.**", "**the wire.**", "**what the collector learns.**"):
        assert said in threat.lower(), said


def test_e9_the_forwarders_files_are_ascii_and_name_only_loopback_and_documentation_addresses():
    import re
    for path in (ROOT / "raqib" / "forward.py", ROOT / "tools" / "rig" / "collector.py",
                 ROOT / "tools" / "rig" / "forward_run.py", Path(__file__), ROOT / "tests" / "test_forward_rig.py"):
        text = path.read_bytes().decode("ascii")
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
            assert ip.startswith(("127.", "192.0.2.", "198.51.100.", "203.0.113.")), (path.name, ip)
