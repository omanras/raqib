"""Capture hook: M0.1 exit criteria E1-E3, M0.1b E1-E3 (ADR-0001 section 3, A-1, A-2),
M5.1 E2 (a lock on every platform) and E3 (this file imports on Windows)."""
import base64
import datetime
import errno
import hashlib
import importlib.util
import io
import json
import os
import random
import re
import signal
import string
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

try:
    import fcntl
except ImportError:  # Windows (M5.1 E3)
    fcntl = None

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
NO_ALARM = pytest.mark.skipif(not hasattr(signal, "SIGALRM"),
                              reason="tests the SIGALRM deadline; without SIGALRM the timer "
                                     "deadline runs (test_m51_e2_timer_*)")
FIXTURES = Path(__file__).resolve().parent / "fixtures"

E1_FIELDS = {"ts", "session_id", "phase", "tool", "input_sha256", "cwd", "seq"}


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def run(payload, log=None, cwd=None):
    """Pipe payload (dict or raw str) into capture.py, as Claude Code would."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    if log is not None:
        env["RAQIB_LOG"] = str(log)
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run([sys.executable, str(CAPTURE)], input=data.encode(),
                          capture_output=True, env=env, cwd=cwd, timeout=30)


def lines(log):
    return [json.loads(x) for x in Path(log).read_text().splitlines()]


def sha256_canonical(value):
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def assert_captured(proc):
    assert proc.returncode == 0
    assert proc.stdout == b""
    assert proc.stderr == b""


def assert_silence(proc):
    assert proc.returncode == 0
    assert proc.stdout == b""
    err = proc.stderr.decode().splitlines()
    assert len(err) == 1
    assert err[0].startswith("RAQIB-SILENCE:")


# --- E1: a PreToolUse appends one line with the required fields -----------

def test_e1_pre_appends_one_line_with_required_fields(tmp_path):
    log = tmp_path / "trace.jsonl"
    pre = fixture("pretooluse-bash.json")
    assert_captured(run(pre, log))

    (rec,) = lines(log)
    assert E1_FIELDS <= set(rec)
    assert rec["session_id"] == "fixture-session-0001"
    assert rec["phase"] == "pre"
    assert rec["tool"] == "Bash"
    assert rec["cwd"] == "/work/example"
    assert rec["seq"] == 1
    assert rec["input_sha256"] == sha256_canonical(pre["tool_input"])
    ts = datetime.datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
    assert ts.utcoffset() == datetime.timedelta(0)
    assert "output_sha256" not in rec and "ok" not in rec


def test_e1_raw_input_is_not_stored(tmp_path):
    log = tmp_path / "trace.jsonl"
    assert_captured(run(fixture("pretooluse-bash.json"), log))
    text = log.read_text()
    assert "ls -la /etc" not in text
    assert "list etc" not in text


def test_e1_appends_and_seq_increases(tmp_path):
    log = tmp_path / "trace.jsonl"
    for _ in range(3):
        assert_captured(run(fixture("pretooluse-bash.json"), log))
    assert [r["seq"] for r in lines(log)] == [1, 2, 3]


def test_e1_seq_is_per_session(tmp_path):
    log = tmp_path / "trace.jsonl"
    a = fixture("pretooluse-bash.json")
    b = dict(a, session_id="fixture-session-0002")
    for payload in (a, b, a, b):
        assert_captured(run(payload, log))
    assert [(r["session_id"][-1], r["seq"]) for r in lines(log)] == [
        ("1", 1), ("2", 1), ("1", 2), ("2", 2)]


def test_e1_default_log_is_cwd_raqib_log_jsonl(tmp_path):
    assert_captured(run(fixture("pretooluse-bash.json"), log=None, cwd=tmp_path))
    assert len(lines(tmp_path / "raqib.log.jsonl")) == 1


def test_e1_concurrent_pres_get_distinct_seq(tmp_path):
    log = tmp_path / "trace.jsonl"
    # A long session history widens the read-then-append window, so a missing
    # lock shows up as duplicate seq.
    seeded = 20000
    with log.open("w") as f:
        for seq in range(1, seeded + 1):
            f.write(json.dumps({"seq": seq, "session_id": "fixture-session-0001",
                                "phase": "post", "tool": "Bash"}) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    env["RAQIB_LOG"] = str(log)
    procs = []
    for i in range(16):
        pre = fixture("pretooluse-bash.json")
        pre["tool_input"]["command"] = "echo %d" % i
        stdin = tmp_path / ("pre-%d.json" % i)
        stdin.write_text(json.dumps(pre))
        # stdin from a file, not a pipe, so every process runs at once.
        with stdin.open("rb") as f:
            procs.append(subprocess.Popen([sys.executable, str(CAPTURE)], stdin=f,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          env=env))
    for p in procs:
        out, err = p.communicate(timeout=60)
        assert (p.returncode, out, err) == (0, b"", b"")
    new = [r["seq"] for r in lines(log)[seeded:]]
    assert sorted(new) == list(range(seeded + 1, seeded + 17))


def test_input_meta_is_small_extract(tmp_path):
    log = tmp_path / "trace.jsonl"
    assert_captured(run(fixture("pretooluse-write.json"), log))
    assert_captured(run(fixture("pretooluse-webfetch.json"), log))
    write, fetch = lines(log)
    assert write["input_meta"] == {"path": "/work/example/notes.txt"}
    assert fetch["input_meta"] == {"url_host": "example.org"}
    assert "hello" not in log.read_text()


# --- E2: PostToolUse shares seq with its PreToolUse ------------------------

def test_e2_post_shares_seq_and_adds_output_and_ok(tmp_path):
    log = tmp_path / "trace.jsonl"
    post = fixture("posttooluse-bash.json")
    assert_captured(run(fixture("pretooluse-bash.json"), log))
    assert_captured(run(post, log))

    pre_rec, post_rec = lines(log)
    assert post_rec["phase"] == "post"
    assert post_rec["seq"] == pre_rec["seq"]
    assert E1_FIELDS <= set(post_rec)
    assert post_rec["input_sha256"] == pre_rec["input_sha256"]
    assert post_rec["output_sha256"] == sha256_canonical(post["tool_response"])
    assert post_rec["ok"] is True
    assert "total 0" not in log.read_text()


def test_e2_post_ok_false_on_failure(tmp_path):
    log = tmp_path / "trace.jsonl"
    assert_captured(run(fixture("pretooluse-bash.json"), log))
    assert_captured(run(fixture("posttooluse-bash-interrupted.json"), log))
    pre_rec, post_rec = lines(log)
    assert post_rec["seq"] == pre_rec["seq"]
    assert post_rec["ok"] is False


def test_e2_repeated_call_pairs_with_open_pre(tmp_path):
    log = tmp_path / "trace.jsonl"
    pre, post = fixture("pretooluse-bash.json"), fixture("posttooluse-bash.json")
    for payload in (pre, post, pre, post):
        assert_captured(run(payload, log))
    assert [(r["phase"], r["seq"]) for r in lines(log)] == [
        ("pre", 1), ("post", 1), ("pre", 2), ("post", 2)]


def test_e2_interleaved_posts_pair_by_input(tmp_path):
    log = tmp_path / "trace.jsonl"
    bash_pre, bash_post = fixture("pretooluse-bash.json"), fixture("posttooluse-bash.json")
    write_pre = fixture("pretooluse-write.json")
    write_post = dict(write_pre, hook_event_name="PostToolUse",
                      tool_response={"filePath": "/work/example/notes.txt", "success": True})
    for payload in (bash_pre, write_pre, write_post, bash_post):
        assert_captured(run(payload, log))
    assert [(r["tool"], r["phase"], r["seq"]) for r in lines(log)] == [
        ("Bash", "pre", 1), ("Write", "pre", 2), ("Write", "post", 2), ("Bash", "post", 1)]


def test_e2_post_without_pre_gets_fresh_seq(tmp_path):
    log = tmp_path / "trace.jsonl"
    assert_captured(run(fixture("pretooluse-write.json"), log))
    assert_captured(run(fixture("posttooluse-bash.json"), log))
    assert [(r["phase"], r["seq"]) for r in lines(log)] == [("pre", 1), ("post", 2)]


# --- E3: unwritable log -> exit 0 and one RAQIB-SILENCE line ---------------

def test_e3_missing_directory_is_silence(tmp_path):
    log = tmp_path / "no-such-dir" / "trace.jsonl"
    assert_silence(run(fixture("pretooluse-bash.json"), log))
    assert not log.exists()


def test_e3_log_is_a_directory_is_silence(tmp_path):
    assert_silence(run(fixture("posttooluse-bash.json"), tmp_path))


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="POSIX root ignores file permissions")
def test_e3_read_only_log_is_silence(tmp_path):
    log = tmp_path / "trace.jsonl"
    log.write_text("")
    log.chmod(0o444)  # on Windows: the read-only attribute
    try:
        assert_silence(run(fixture("pretooluse-bash.json"), log))
        assert log.read_text() == ""
    finally:
        log.chmod(0o644)


def test_e3_writable_log_is_not_silence(tmp_path):
    assert_captured(run(fixture("pretooluse-bash.json"), tmp_path / "trace.jsonl"))


@pytest.mark.parametrize("payload", [
    "",
    "not json",
    "[]",
    json.dumps({"hook_event_name": "UserPromptSubmit", "session_id": "s"}),
    json.dumps({"hook_event_name": "SessionStart"}),
    json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}),
    json.dumps({"hook_event_name": "PreToolUse", "session_id": "s"}),
])
def test_uncapturable_input_is_silence_and_writes_nothing(tmp_path, payload):
    log = tmp_path / "trace.jsonl"
    assert_silence(run(payload, log))
    assert not log.exists()


def test_torn_last_line_does_not_swallow_next(tmp_path):
    log = tmp_path / "trace.jsonl"
    log.write_text('{"ts":"2026-01-01T00:00:00Z","seq":7,"session_id":"fixture-session')
    assert_captured(run(fixture("pretooluse-bash.json"), log))
    torn, rec = log.read_text().splitlines()
    assert json.loads(rec)["seq"] == 1


# --- M0.1b E1/E3: tool_use_id is carried and is the pairing key (A-2) ------

def run_all(payloads, log):
    for payload in payloads:
        assert_captured(run(payload, log))
    return lines(log)


def pairs(recs):
    return [(r["phase"], r["seq"], r.get("tool_use_id")) for r in recs]


def test_m01b_e1_pre_and_post_carry_tool_use_id(tmp_path):
    events = fixture("pairing-identical-in-flight.json")
    recs = run_all(events, tmp_path / "trace.jsonl")
    assert [r["tool_use_id"] for r in recs] == [e["tool_use_id"] for e in events]
    assert all(isinstance(r["tool_use_id"], str) for r in recs)


@pytest.mark.parametrize("value", ["<missing>", None, "", 7, ["toolu_x"]])
def test_m01b_e1_no_tool_use_id_unless_non_empty_string(tmp_path, value):
    pre = fixture("pretooluse-bash.json")
    if value != "<missing>":
        pre["tool_use_id"] = value
    (rec,) = run_all([pre], tmp_path / "trace.jsonl")
    assert "tool_use_id" not in rec


def test_m01b_e3_identical_commands_in_flight_pair_by_tool_use_id(tmp_path):
    # Same input twice: pairing by input alone would cross the two posts.
    recs = run_all(fixture("pairing-identical-in-flight.json"), tmp_path / "trace.jsonl")
    assert pairs(recs) == [
        ("pre", 1, "toolu_fixture_0001"), ("pre", 2, "toolu_fixture_0002"),
        ("post", 2, "toolu_fixture_0002"), ("post", 1, "toolu_fixture_0001")]
    assert [r.get("ok") for r in recs] == [None, None, True, False]


def test_m01b_e3_updated_input_rewrite_still_pairs(tmp_path):
    # A PreToolUse updatedInput rewrite: the post of 0003 carries the rewritten
    # input, which hashes like the still-open pre 0004. The id must win.
    events = fixture("pairing-updated-input.json")
    recs = run_all(events, tmp_path / "trace.jsonl")
    assert pairs(recs) == [
        ("pre", 1, "toolu_fixture_0003"), ("pre", 2, "toolu_fixture_0004"),
        ("post", 1, "toolu_fixture_0003"), ("post", 2, "toolu_fixture_0004")]
    pre, _, post, _ = recs
    assert pre["input_sha256"] == sha256_canonical(events[0]["tool_input"])
    assert post["input_sha256"] == sha256_canonical(events[2]["tool_input"])
    assert pre["input_sha256"] != post["input_sha256"]
    assert (pre["input_meta"], post["input_meta"]) == (
        {"command_head": "pytest"}, {"command_head": "timeout"})


def test_m01b_e3_unknown_tool_use_id_falls_back_and_is_logged(tmp_path):
    # Negative: the post's id matches no pre. The only open pre has the same
    # input but another id, so the fallback must not take it either.
    log = tmp_path / "trace.jsonl"
    recs = run_all(fixture("pairing-unknown-id.json"), log)
    assert pairs(recs) == [
        ("pre", 1, "toolu_fixture_0005"), ("post", 2, "toolu_fixture_unknown"),
        ("post", 1, "toolu_fixture_0005")]
    assert E1_FIELDS <= set(recs[1]) and recs[1]["ok"] is True


def test_m01b_e1_post_with_id_falls_back_to_pre_without_id(tmp_path):
    post = dict(fixture("posttooluse-bash.json"), tool_use_id="toolu_fixture_unknown")
    recs = run_all([fixture("pretooluse-bash.json"), post], tmp_path / "trace.jsonl")
    assert pairs(recs) == [("pre", 1, None), ("post", 1, "toolu_fixture_unknown")]


def test_m01b_e1_post_without_id_falls_back_to_pre_with_id(tmp_path):
    pre = dict(fixture("pretooluse-bash.json"), tool_use_id="toolu_fixture_0006")
    recs = run_all([pre, fixture("posttooluse-bash.json")], tmp_path / "trace.jsonl")
    assert pairs(recs) == [("pre", 1, "toolu_fixture_0006"), ("post", 1, None)]


# --- M0.1b E2: input_meta.command_head for Bash (A-1) ----------------------

@pytest.mark.parametrize("tool_input,head", [
    ({"command": "ls -la /etc"}, "ls"),
    ({"command": "FOO=1 /usr/bin/git x"}, "git"),
    ({"command": "  A=1\tB_2=x ./bin/run.sh --flag"}, "run.sh"),
    ({"command": "cd /tmp\nrm -rf build"}, "cd"),
    ({"command": "9X=1 ls"}, None),
    ({"command": "/usr/local/bin/ --help"}, "bin"),
    ({"command": "/opt/" + "x" * 100 + " -v"}, None),
    ({"command": "y" * 65}, None),
    ({"command": "y" * 64}, "y" * 64),
    ({"command": ""}, None),
    ({"command": " \n\t "}, None),
    ({"command": "FOO=1 BAR=2"}, None),
    ({"command": ["ls"]}, None),
    ({"description": "no command"}, None),
], ids=lambda v: v if isinstance(v, str) and len(v) < 20 else None)
def test_m01b_e2_command_head(tmp_path, tool_input, head):
    pre = dict(fixture("pretooluse-bash.json"), tool_input=tool_input)
    (rec,) = run_all([pre], tmp_path / "trace.jsonl")
    if head is None:
        assert "command_head" not in rec["input_meta"]
    else:
        assert rec["input_meta"]["command_head"] == head
        assert len(rec["input_meta"]["command_head"]) <= 64


def test_m01b_e2_command_head_on_bash_post_and_only_for_bash(tmp_path):
    other = dict(fixture("pretooluse-bash.json"), tool_name="mcp__shell__run")
    recs = run_all([fixture("pretooluse-bash.json"), fixture("posttooluse-bash.json"),
                    other, fixture("pretooluse-write.json")], tmp_path / "trace.jsonl")
    assert [r["input_meta"].get("command_head") for r in recs] == ["ls", "ls", None, None]


# --- M0.3 E4: session events (A-3) and PostToolUseFailure error_class (A-4) -

SESSION_FIELDS = {"ts", "seq", "session_id", "phase", "tool", "cwd"}


@pytest.mark.parametrize("name, phase", [
    ("sessionstart.json", "session_start"),
    ("stop.json", "stop"),
    ("sessionend.json", "session_end"),
])
def test_m03_session_event_line(tmp_path, name, phase):
    log = tmp_path / "trace.jsonl"
    assert_captured(run(fixture(name), log))
    (rec,) = lines(log)
    assert set(rec) == SESSION_FIELDS
    assert (rec["phase"], rec["tool"], rec["seq"]) == (phase, "-", 1)
    assert (rec["session_id"], rec["cwd"]) == ("fixture-session-0001", "/work/example")


def test_m03_session_events_take_the_next_seq(tmp_path):
    recs = run_all([fixture("sessionstart.json"), fixture("pretooluse-bash.json"),
                    fixture("posttooluse-bash.json"), fixture("stop.json"),
                    fixture("sessionend.json")], tmp_path / "trace.jsonl")
    assert [(r["phase"], r["seq"]) for r in recs] == [
        ("session_start", 1), ("pre", 2), ("post", 2), ("stop", 3), ("session_end", 4)]


def test_m03_session_event_does_not_close_an_open_pre(tmp_path):
    recs = run_all([fixture("pretooluse-bash.json"), fixture("stop.json"),
                    fixture("posttooluse-bash.json")], tmp_path / "trace.jsonl")
    assert [(r["phase"], r["seq"]) for r in recs] == [("pre", 1), ("stop", 2), ("post", 1)]


def test_m03_failure_is_a_post_with_ok_false_and_error_class(tmp_path):
    failure = fixture("posttoolusefailure-bash.json")
    recs = run_all([fixture("pretooluse-bash-id-f.json"), failure], tmp_path / "trace.jsonl")
    pre_rec, post_rec = recs
    assert (post_rec["phase"], post_rec["seq"], post_rec["ok"]) == ("post", pre_rec["seq"], False)
    assert post_rec["error_class"] == "failure"
    assert post_rec["output_sha256"] == sha256_canonical(failure["error"])
    assert "exit code" not in (tmp_path / "trace.jsonl").read_text()


def test_m03_error_class_only_on_failure_lines(tmp_path):
    recs = run_all([fixture("pretooluse-bash.json"), fixture("posttooluse-bash-interrupted.json")],
                   tmp_path / "trace.jsonl")
    assert recs[1]["ok"] is False
    assert all("error_class" not in r for r in recs)


@pytest.mark.parametrize("error, expected", [
    ("TimeoutError: took too long", "TimeoutError"),
    ("Error: boom", "Error"),
    ("  InputValidationError: bad input", "InputValidationError"),
    ("pkg.mod.CustomException: z", "pkg.mod.CustomException"),
    ("X" * 100 + "Error: y", "failure"),
    ("X" * 59 + "Error: y", "X" * 59 + "Error"),
    ("TimeoutErrorX: y", "failure"),
    ("Errors happened", "failure"),
    ("Command failed with exit code 1", "failure"),
    ("", "failure"),
    (None, "failure"),
    ("<missing>", "failure"),
    (7, "failure"),
    ({"type": "ToolError", "message": "secret text"}, "ToolError"),
    ({"type": "not an identifier"}, "failure"),
    ({"name": "alice"}, "failure"),
    ({"name": "DbError", "type": "alice"}, "DbError"),
    (["TimeoutError"], "failure"),
])
def test_m03_error_class(tmp_path, error, expected):
    failure = fixture("posttoolusefailure-bash.json")
    if error == "<missing>":
        del failure["error"]
    else:
        failure["error"] = error
    log = tmp_path / "trace.jsonl"
    assert_captured(run(failure, log))
    (rec,) = lines(log)
    assert rec["error_class"] == expected
    assert "secret text" not in log.read_text()


# --- M1.2 E2: output_meta.secret_kinds (names only, never the text) ---------
# Fake secrets are assembled at run time so that no secret-like string is in
# the tree for the gate's secret scan to find. They are random-looking (a
# fixed seed), because uniform fakes such as "Z7Z7..." read as placeholders.

def rnd(n, alphabet, seed):
    r = random.Random(seed)
    return "".join(r.choice(alphabet) for _ in range(n))


UP, LOW, DIG = string.ascii_uppercase, string.ascii_lowercase, string.digits
ALNUM = UP + LOW + DIG
B64URL = ALNUM + "-_"


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


FAKE = {
    "auth_header": "Authori" + "zation: Bearer " + rnd(32, ALNUM, 1),
    "aws_access_key_id": "AK" + "IA" + rnd(16, UP + DIG, 2),
    "aws_secret_access_key": "aws_secret_" + "access_key = " + rnd(40, ALNUM + "/+", 3),
    "github_token": "gh" + "p_" + rnd(36, ALNUM, 4),
    "gitlab_token": "glp" + "at-" + rnd(20, ALNUM, 5),
    "google_api_key": "AI" + "za" + rnd(35, ALNUM + "_-", 6),
    "huggingface_token": "h" + "f_" + rnd(34, ALNUM, 7),
    "jwt": b64url({"alg": "HS256"}) + "." + b64url({"sub": "u-42", "iat": 1760000000}) + "."
           + rnd(43, B64URL, 8),
    "npm_token": "np" + "m_" + rnd(36, ALNUM, 9),
    "private_key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + rnd(70, ALNUM + "+/", 10) + "\n",
    "pypi_token": "pyp" + "i-AgEIcHlwaS5vcmc" + rnd(60, B64URL, 11),
    "sk_api_key": "sk-" + "ant-" + rnd(40, ALNUM, 12),
    "slack_token": "xo" + "xb-" + rnd(24, ALNUM, 13),
    "slack_webhook": "https://hooks.slack" + ".com/services/T" + rnd(9, UP + DIG, 14) + "/B"
                     + rnd(9, UP + DIG, 15) + "/" + rnd(24, ALNUM, 16),
    "stripe_key": "sk" + "_live_" + rnd(24, ALNUM, 17),
    "url_credentials": "postgres://app:" + rnd(16, ALNUM, 18) + "@db.internal:5432/app",
}


def load_capture():
    spec = importlib.util.spec_from_file_location("raqib_capture_under_test", CAPTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def post_with(response, tmp_path):
    post = fixture("posttooluse-bash.json")
    post["tool_response"] = response
    log = tmp_path / "trace.jsonl"
    assert_captured(run(post, log))
    (rec,) = lines(log)
    return rec, log.read_text()


def full(*kinds, placeholders=()):
    meta = {"scan": "full", "secret_kinds": sorted(kinds)}
    if placeholders:
        meta["placeholder_kinds"] = sorted(placeholders)
    return meta


def test_m12_every_pattern_has_a_fake():
    assert sorted(FAKE) == sorted(name for name, _ in load_capture().SECRET_PATTERNS)


@pytest.mark.parametrize("kind", sorted(FAKE))
def test_m12_secret_in_output_is_recorded_by_name_only(tmp_path, kind):
    secret = FAKE[kind]
    rec, text = post_with({"stdout": "config:\n" + secret + "\n", "stderr": ""}, tmp_path)
    assert rec["output_meta"] == full(kind)
    tail = secret.strip()[-12:]
    assert secret not in text and tail not in text


def test_m12_kinds_are_sorted_and_found_in_keys_and_nesting(tmp_path):
    response = {FAKE["slack_token"]: [{"deep": ["x", FAKE["aws_access_key_id"]]}]}
    rec, _ = post_with(response, tmp_path)
    assert rec["output_meta"] == full("aws_access_key_id", "slack_token")


NEAR_MISSES = {
    "aws-15-chars": "AK" + "IA" + rnd(15, UP + DIG, 20) + " ",
    "aws-17-chars": "AK" + "IA" + rnd(17, UP + DIG, 21),
    "sk-short": "sk-" + "short",
    "public-key": "-----BEGIN " + "PUBLIC KEY-----\n" + rnd(70, ALNUM, 22),
    "pem-header-alone": 'if line == "-----BEGIN ' + 'RSA PRIVATE KEY-----":\n    return True',
    "url-without-password": "https://user@example.org:8443/path",
    "plain-text": "no secrets here",
}


@pytest.mark.parametrize("name", sorted(NEAR_MISSES))
def test_m12_near_misses_are_not_secrets(tmp_path, name):
    rec, _ = post_with({"stdout": NEAR_MISSES[name]}, tmp_path)
    assert rec["output_meta"] == full()


PLACEHOLDERS = {
    "aws-docs-example": ("aws_access_key_id", "AK" + "IAIOSFODNN7" + "EXAMPLE"),
    "aws-xxxx": ("aws_access_key_id", "AK" + "IA" + "X" * 16),
    "aws-uniform": ("aws_access_key_id", "AK" + "IA" + "A1" * 8),
    "auth-uniform": ("auth_header", "Authori" + "zation: Bearer " + "a1" * 10),
    "env-example-sk": ("sk_api_key", "OPENAI_API_KEY=sk-" + "your-openai-api-key-here"),
    "env-example-slack": ("slack_token", "SLACK_TOKEN=xo" + "xb-your-token"),
    "kebab-case-sk": ("sk_api_key", "sk-" + "learn-intelex-extension-config"),
    "jwt-io-sample": ("jwt", b64url({"alg": "HS256", "typ": "JWT"}) + "."
                      + b64url({"sub": "1234567890", "name": "John Doe", "iat": 1516239022})
                      + "." + rnd(43, B64URL, 23)),
    "url-user-pass": ("url_credentials", "postgres://user:" + "password@localhost/db"),
    "auth-docs": ("auth_header", "Authori" + "zation: Bearer your-api-token-goes-here"),
}


@pytest.mark.parametrize("name", sorted(PLACEHOLDERS))
def test_m12_placeholders_are_named_but_not_counted(tmp_path, name):
    kind, text = PLACEHOLDERS[name]
    rec, _ = post_with({"stdout": text}, tmp_path)
    assert rec["output_meta"] == full(placeholders=[kind])


def test_m12_a_real_key_next_to_a_placeholder_still_counts(tmp_path):
    text = PLACEHOLDERS["aws-docs-example"][1] + "\n" + FAKE["aws_access_key_id"]
    rec, _ = post_with({"stdout": text}, tmp_path)
    assert rec["output_meta"] == full("aws_access_key_id")


def test_m12_secret_in_a_failure_message(tmp_path):
    failure = fixture("posttoolusefailure-bash.json")
    failure["error"] = "curl: (22) 401 for token " + FAKE["github_token"]
    log = tmp_path / "trace.jsonl"
    assert_captured(run(failure, log))
    (rec,) = lines(log)
    assert rec["output_meta"] == full("github_token")
    assert FAKE["github_token"] not in log.read_text()


def test_m12_error_is_scanned_even_next_to_a_tool_response(tmp_path):
    failure = fixture("posttoolusefailure-bash.json")
    failure["tool_response"] = None
    failure["error"] = "denied: " + FAKE["npm_token"]
    log = tmp_path / "trace.jsonl"
    assert_captured(run(failure, log))
    (rec,) = lines(log)
    assert rec["output_meta"] == full("npm_token")
    assert rec["output_sha256"] == sha256_canonical(None)


def test_m12_nothing_to_scan_is_not_clean(tmp_path):
    post = fixture("posttooluse-bash.json")
    del post["tool_response"]
    log = tmp_path / "trace.jsonl"
    assert_captured(run(post, log))
    (rec,) = lines(log)
    assert rec["output_meta"] == {"scan": "none"}


def test_m12_large_output_is_scanned_partly_and_never_reads_clean(tmp_path):
    cap = load_capture().SCAN_MAX_CHARS
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    rec, _ = post_with({"stdout": "a" * cap + "\n" + FAKE["github_token"]}, tmp_path / "a")
    assert rec["output_meta"] == {"scan": "partial"}
    rec, _ = post_with({"stdout": FAKE["github_token"] + "\n" + "a" * cap}, tmp_path / "b")
    assert rec["output_meta"] == {"scan": "partial", "secret_kinds": ["github_token"]}


def test_m12_scan_budget_counts_every_string():
    capture = load_capture()
    assert capture.scan_output([["x"] * 10], limit=15) == ([], [], False)
    assert capture.scan_output([["x"] * 10], limit=20) == ([], [], True)


def test_m12_only_post_lines_carry_output_meta(tmp_path):
    pre = fixture("pretooluse-bash.json")
    pre["tool_input"]["command"] = "echo " + FAKE["aws_access_key_id"]
    recs = run_all([fixture("sessionstart.json"), pre, fixture("posttooluse-bash.json")],
                   tmp_path / "trace.jsonl")
    assert ["output_meta" in r for r in recs] == [False, False, True]
    assert recs[2]["output_meta"] == full()


def test_m12_all_kinds_at_once_are_sorted(tmp_path):
    rec, text = post_with({"stdout": " \n".join(FAKE[k] for k in reversed(sorted(FAKE)))}, tmp_path)
    assert rec["output_meta"] == full(*FAKE)
    assert not any(v in text for v in FAKE.values())


ADVERSARIAL = {
    "jwt-starts": "-eyJ" * 60000,
    "jwt-two-segments": ("eyJ" + "a1" * 8 + ".") * 20000,
    "url-schemes": "a://" + "b" * 100 + ":" * 100000,
    "pem-headers": ("-----BEGIN " + "RSA PRIVATE KEY-----\n" + "X-Y: " + "z" * 190 + "\n") * 1000,
    "auth-headers": "Authorization: Bearer " * 20000,
    "word-chars": "A" * 250000,
    "pem-name-colon-runs": "-----BEGIN " + "PRIVATE KEY-----\n" + "a: " * 20000,
    "pem-many-header-lines": "-----BEGIN " + "PRIVATE KEY-----\n" + ("a: " * 60 + "\n") * 300,
    "pem-escaped-lines": "-----BEGIN " + "PRIVATE KEY-----\\n" + "a: \\n" * 20000,
    "url-colons": "postgres://" + ("a:" * 120 + " ") * 400,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_m12_scan_time_is_linear(name):
    capture = load_capture()
    start = time.monotonic()
    capture.scan_output([ADVERSARIAL[name]])
    assert time.monotonic() - start < 2.0


# --- M1.2 REDO: command_head never carries a secret (F1) --------------------

TOKEN = rnd(40, ALNUM, 30)


@pytest.mark.parametrize("command, head", [
    ('AUTH="Bearer ' + TOKEN + '" gh api user', "gh"),
    ("AUTH='Bearer " + TOKEN + "' X=1 curl -s x", "curl"),
    ('AUTH="Bearer ' + TOKEN + ' gh api user', None),
    ('"rm" -rf build', "rm"),
    ("\\rm -rf build", "rm"),
    ("ls;rm -rf build", None),
    ("$(which rm) -rf build", None),
    ("(rm -rf build)", None),
    ("[ -f x ] && rm x", "["),
    (FAKE["github_token"] + " --help", None),
    (FAKE["aws_access_key_id"] + " x", None),
    (TOKEN[:20] + " x", None),
    ("A=" + "x" * 70000 + " rm -rf /", None),
    ("A=" + "x" * ((1 << 16) - 5) + " rmdir x", None),
    ("ls " + "x" * 70000, "ls"),
], ids=["quoted-assignment", "single-quoted", "unbalanced", "quoted-name", "backslash",
        "glued-operator", "substitution", "subshell", "test-bracket", "token-first",
        "aws-key-first", "mixed-case-word", "huge-assignment", "head-cut-at-limit",
        "huge-argument"])
def test_redo_command_head_is_never_a_fragment_of_a_value(tmp_path, command, head):
    pre = dict(fixture("pretooluse-bash.json"), tool_input={"command": command})
    log = tmp_path / "trace.jsonl"
    assert_captured(run(pre, log))
    (rec,) = lines(log)
    assert rec["input_meta"].get("command_head") == head
    assert TOKEN not in log.read_text() and TOKEN[:12] not in log.read_text()


# --- M1.2 REDO: bounded work under the lock (F9, B4) ------------------------

def test_redo_scan_runs_before_the_lock(tmp_path, monkeypatch):
    capture = load_capture()
    order = []
    real_meta, real_lock = capture.output_meta, capture.lock
    monkeypatch.setattr(capture, "output_meta", lambda p: order.append("scan") or real_meta(p))
    monkeypatch.setattr(capture, "lock", lambda f: order.append("lock") or real_lock(f))
    capture.append(str(tmp_path / "trace.jsonl"), fixture("posttooluse-bash.json"))
    assert order == ["scan", "lock"]


def test_redo_lock_wait_is_capped(tmp_path):
    capture = load_capture()
    log = tmp_path / "trace.jsonl"
    log.write_text("")
    # M5.1: the holder takes the lock as capture does, flock or msvcrt.
    with open(log, "a+") as holder, open(log, "a+") as waiter:
        capture.lock(holder)
        start = time.monotonic()
        with pytest.raises(capture.CaptureError, match="lock"):
            capture.lock(waiter, wait=0.3)
        assert 0.3 <= time.monotonic() - start < 2.0
        capture.unlock(holder)


@pytest.mark.skipif(fcntl is None, reason="POSIX flock")
def test_redo_lock_wait_is_capped_against_a_plain_flock(tmp_path):
    capture = load_capture()
    log = tmp_path / "trace.jsonl"
    log.write_text("")
    with open(log) as holder, open(log) as waiter:
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
        with pytest.raises(capture.CaptureError, match="lock"):
            capture.lock(waiter, wait=0.3)


@NO_ALARM
def test_redo_deadline_ends_capture_with_silence(tmp_path, monkeypatch, capsys):
    capture = load_capture()
    monkeypatch.setattr(capture, "DEADLINE_SECONDS", 1)
    monkeypatch.setattr(capture, "append", lambda log, payload: time.sleep(5))
    monkeypatch.setenv("RAQIB_LOG", str(tmp_path / "trace.jsonl"))
    data = json.dumps(fixture("pretooluse-bash.json")).encode()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    start = time.monotonic()
    assert capture.main() == 0
    assert time.monotonic() - start < 3
    out = capsys.readouterr()
    assert out.out == ""
    (line,) = out.err.splitlines()
    assert line.startswith("RAQIB-SILENCE:") and "Deadline" in line
    assert signal.alarm(0) == 0


def test_redo_deadline_is_below_the_installed_timeout():
    install = (ROOT / "raqib" / "install.py").read_text(encoding="utf-8")  # M6.3: the installer's home
    timeout = int(re.search(r"^TIMEOUT = (\d+)", install, re.M).group(1))
    capture = load_capture()
    assert capture.LOCK_WAIT_SECONDS < capture.DEADLINE_SECONDS < timeout


# --- M1.1+M1.2 REDO 2 (docs/review/2026-10-16-M1.1-M1.2-REDO.md) ------------

def pem(kind="PRIVATE KEY", headers="", sep="\n", seed=40):
    return ("-----BEGIN " + kind + "-----" + sep + headers + rnd(64, ALNUM + "+/", seed) + sep)


@pytest.mark.parametrize("text", [
    pem("RSA PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D4E5F\n\n"),
    pem("PGP PRIVATE KEY BLOCK", "Version: GnuPG v2\n\n"),
    pem(sep="\\n"),
    pem("EC PRIVATE KEY", "Proc-Type: 4,ENCRYPTED\\nDEK-Info: AES-128-CBC,0A1B2C3D\\n\\n", sep="\\n"),
], ids=["encrypted-pem", "pgp-block", "escaped-newlines", "escaped-encrypted"])
def test_redo2_private_keys_with_headers_or_escaped_lines(text):
    assert load_capture().scan_output([text])[0] == ["private_key"]


@pytest.mark.parametrize("text, found, placeholders", [
    ("postgres://testuser:" + rnd(16, ALNUM, 41) + "@db/x", ["url_credentials"], []),
    ("mysql://root:" + "to" + "or@localhost/x", ["url_credentials"], []),
    ("redis://app:" + "your-password-here@cache:6379", [], ["url_credentials"]),
    ("key = sk-" + rnd(32, "0123456789abcdef", 42), ["sk_api_key"], []),
    ("key = sk-" + rnd(30, UP + LOW, 43), [], ["sk_api_key"]),
    ("id AK" + "IA" + "BCDEF" * 3 + "B", ["aws_access_key_id"], []),
    ("id AK" + "IA" + "BCDE" * 4, [], ["aws_access_key_id"]),
    (b64url({"alg": "HS256"}) + "." + b64url({"sub": "1234567890", "name": "Jane Roe"}) + "."
     + rnd(43, B64URL, 44), ["jwt"], []),
], ids=["user-name-with-marker", "short-password", "password-placeholder", "lowercase-hex-sk",
        "letters-only-sk", "eight-distinct", "seven-distinct", "jwt-sub-without-sample-name"])
def test_redo2_placeholder_checks_look_at_the_secret_only(text, found, placeholders):
    assert load_capture().scan_output([text])[:2] == (found, placeholders)


HEX23 = rnd(23, "0123456789abcdef", 46)


@pytest.mark.parametrize("command, head", [
    ("'' rm -rf x", None),
    (rnd(32, "0123456789abcdef", 45) + " x", None),
    (HEX23 + " x", HEX23),
    ("Ab1" * 5 + "Z x", None),
    ("Ab1" * 5 + " x", "Ab1" * 5),
], ids=["empty-quoted-word", "hex-token-32", "hex-23-kept", "mixed-16", "mixed-15-kept"])
def test_redo2_command_head_edges(command, head):
    assert load_capture().command_head(command) == head


def test_redo2_a_secret_in_a_path_is_redacted(tmp_path):
    token = FAKE["github_token"]
    pre = dict(fixture("pretooluse-bash.json"), tool_name="Read",
               tool_input={"file_path": "/tmp/" + token + "/notes.txt"})
    log = tmp_path / "trace.jsonl"
    assert_captured(run(pre, log))
    (rec,) = lines(log)
    assert rec["input_meta"]["path"] == "/tmp/[redacted:github_token]/notes.txt"
    assert token not in log.read_text()
    placeholder = "/srv/AK" + "IAIOSFODNN7" + "EXAMPLE/x"
    assert load_capture().input_meta("Read", {"file_path": placeholder}) == {"path": placeholder}


def test_redo2_null_output_is_nothing_to_scan(tmp_path):
    rec, _ = post_with(None, tmp_path)
    assert rec["output_meta"] == {"scan": "none"}


def test_redo2_capped_scan_covers_the_start_in_document_order():
    capture = load_capture()
    head = {"first": FAKE["npm_token"], "second": "a" * 100}
    assert capture.scan_output([head], limit=60)[0] == ["npm_token"]
    assert list(capture.strings_in({"a": ["b", "c"], "d": "e"})) == ["a", "b", "c", "d", "e"]


def test_redo2_hashing_also_runs_before_the_lock(tmp_path, monkeypatch):
    capture = load_capture()
    order = []
    real_hash, real_lock = capture.canonical_sha256, capture.lock
    monkeypatch.setattr(capture, "canonical_sha256", lambda v: order.append("hash") or real_hash(v))
    monkeypatch.setattr(capture, "lock", lambda f: order.append("lock") or real_lock(f))
    capture.append(str(tmp_path / "trace.jsonl"), fixture("posttooluse-bash.json"))
    assert order == ["hash", "hash", "lock"]


@NO_ALARM
def test_redo2_the_deadline_is_cancelled_before_the_write(tmp_path, monkeypatch):
    capture = load_capture()
    calls = []
    monkeypatch.setattr(capture.signal, "alarm", lambda n: calls.append(n) or 0)
    log = tmp_path / "trace.jsonl"
    capture.append(str(log), fixture("pretooluse-bash.json"))
    assert calls == [0] and len(lines(log)) == 1


# --- M5.1 E2: every platform appends under a lock ---------------------------

WORKER = r"""
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("raqib_capture_worker", sys.argv[1])
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
log, go, payload_file, name, count = sys.argv[2:7]
with open(payload_file, encoding="utf-8") as f:
    payload = json.load(f)
deadline = time.monotonic() + 60
while not os.path.exists(go):
    if time.monotonic() > deadline:
        sys.exit("no start signal")
    time.sleep(0.001)
for i in range(int(count)):
    payload["tool_input"] = {"command": "echo %s %d" % (name, i)}
    capture.append(log, payload)
"""


def test_m51_e2_processes_appending_at_once_never_share_a_seq(tmp_path):
    """Real processes, released together, each append pres to one session.
    Every pre takes max(seq) + 1 under the lock, so the new seqs are exactly
    the next ones, with no duplicate. Runs as is on POSIX and Windows."""
    log = tmp_path / "trace.jsonl"
    seeded, workers, each = 2000, 4, 25
    with log.open("w", encoding="utf-8", newline="\n") as f:
        for seq in range(1, seeded + 1):
            f.write(json.dumps({"seq": seq, "session_id": "fixture-session-0001",
                                "phase": "post", "tool": "Bash"}) + "\n")
    payload = tmp_path / "pre.json"
    payload.write_text(json.dumps(fixture("pretooluse-bash.json")), encoding="utf-8")
    go = tmp_path / "go"
    procs = [subprocess.Popen([sys.executable, "-I", "-c", WORKER, str(CAPTURE), str(log), str(go),
                               str(payload), "w%d" % n, str(each)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for n in range(workers)]
    go.write_text("")
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert (p.returncode, out, err) == (0, b"", b"")
    new = [r["seq"] for r in lines(log)[seeded:]]
    assert len(new) == workers * each
    assert sorted(new) == list(range(seeded + 1, seeded + workers * each + 1))


class FakeMsvcrt:
    """msvcrt.locking as Windows has it: the region starts at the file position."""
    LK_UNLCK, LK_NBLCK = 0, 2

    def __init__(self, busy=0, error=errno.EACCES):
        self.calls, self.busy, self.error = [], busy, error

    def locking(self, fd, mode, nbytes):
        self.calls.append((mode, os.lseek(fd, 0, os.SEEK_CUR), nbytes))
        if mode == self.LK_NBLCK and self.busy:
            self.busy -= 1
            raise OSError(self.error, "locked")


def windows_lock(monkeypatch, fake):
    capture = load_capture()
    monkeypatch.setattr(capture, "fcntl", None)
    monkeypatch.setattr(capture, "msvcrt", fake)
    return capture


def test_m51_e2_without_fcntl_msvcrt_locks_one_byte_beyond_eof(tmp_path, monkeypatch):
    fake = FakeMsvcrt(busy=2)
    capture = windows_lock(monkeypatch, fake)
    log = tmp_path / "trace.jsonl"
    for _ in range(2):
        capture.append(str(log), fixture("pretooluse-bash.json"))
    assert [r["seq"] for r in lines(log)] == [1, 2]
    lock, unlock = (fake.LK_NBLCK, capture.LOCK_OFFSET, 1), (fake.LK_UNLCK, capture.LOCK_OFFSET, 1)
    # Two busy tries, then the lock; one unlock per append; never a data byte.
    assert fake.calls == [lock, lock, lock, unlock, lock, unlock]
    assert capture.LOCK_OFFSET > 1 << 32 and log.stat().st_size < capture.LOCK_OFFSET


def test_m51_e2_msvcrt_wait_is_capped(tmp_path, monkeypatch):
    capture = windows_lock(monkeypatch, FakeMsvcrt(busy=10 ** 6))
    log = tmp_path / "trace.jsonl"
    with open(log, "a+") as f:
        start = time.monotonic()
        with pytest.raises(capture.CaptureError, match="not acquired"):
            capture.lock(f, wait=0.2)
        assert 0.2 <= time.monotonic() - start < 2.0


def test_m51_e2_an_msvcrt_error_that_is_not_contention_is_not_retried(tmp_path, monkeypatch):
    fake = FakeMsvcrt(busy=1, error=errno.EBADF)
    capture = windows_lock(monkeypatch, fake)
    with open(tmp_path / "trace.jsonl", "a+") as f:
        with pytest.raises(OSError):
            capture.lock(f, wait=5)
    assert len(fake.calls) == 1


def capture_main(capture, monkeypatch, payload, argv=()):
    data = json.dumps(payload).encode()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    return capture.main(argv)


def test_m51_e2_no_lock_at_all_is_silence_not_an_unlocked_append(tmp_path, monkeypatch, capsys):
    capture = windows_lock(monkeypatch, None)
    log = tmp_path / "trace.jsonl"
    monkeypatch.setenv("RAQIB_LOG", str(log))
    assert capture_main(capture, monkeypatch, fixture("pretooluse-bash.json")) == 0
    out = capsys.readouterr()
    (line,) = out.err.splitlines()
    assert out.out == "" and line.startswith("RAQIB-SILENCE:") and "no inter-process lock" in line
    assert log.read_text() == ""


def test_m51_the_log_argument_wins_over_raqib_log(tmp_path, monkeypatch, capsys):
    capture = load_capture()
    log, decoy = tmp_path / "trace.jsonl", tmp_path / "decoy.jsonl"
    monkeypatch.setenv("RAQIB_LOG", str(decoy))
    assert capture_main(capture, monkeypatch, fixture("stop.json"), [str(log)]) == 0
    assert capsys.readouterr().err == ""
    assert len(lines(log)) == 1 and not decoy.exists()


def test_m51_more_than_one_argument_is_silence(tmp_path, monkeypatch, capsys):
    capture = load_capture()
    log = tmp_path / "trace.jsonl"
    assert capture_main(capture, monkeypatch, fixture("stop.json"), [str(log), "extra"]) == 0
    (line,) = capsys.readouterr().err.splitlines()
    assert line.startswith("RAQIB-SILENCE:") and "at most one argument" in line
    assert not log.exists()


# --- M5.1 E2 (ruling Amendment 2, Q-3): the deadline without SIGALRM ---------

TIMER_SCRIPT = r"""
import importlib.util, sys, threading, time, types
spec = importlib.util.spec_from_file_location("raqib_capture_timer", sys.argv[1])
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
capture.signal = types.SimpleNamespace()  # as on Windows: no SIGALRM
capture.DEADLINE_SECONDS = 1
if sys.argv[2] == "slow":
    capture.append = lambda log, payload: time.sleep(5)
if sys.argv[2] == "fail":
    def boom(log, payload):
        raise capture.CaptureError("boom")
    capture.append = boom
    real_silence = capture.silence
    def slow_silence(*args):
        real_silence(*args)
        if threading.current_thread() is threading.main_thread():
            time.sleep(2)  # a deadline still armed would fire in here: a second line
    capture.silence = slow_silence
code = capture.main([sys.argv[3]])
time.sleep(2)  # a timer still running would end the process in here
sys.stdout.write("returned %d" % code)
"""


def run_timer_script(tmp_path, mode):
    log = tmp_path / "trace.jsonl"
    start = time.monotonic()
    proc = subprocess.run([sys.executable, "-I", "-c", TIMER_SCRIPT, str(CAPTURE), mode, str(log)],
                          input=json.dumps(fixture("pretooluse-bash.json")).encode(),
                          capture_output=True, timeout=60)
    return proc, log, time.monotonic() - start


def test_m51_e2_timer_deadline_ends_a_slow_capture_with_silence_and_exit_0(tmp_path):
    proc, log, elapsed = run_timer_script(tmp_path, "slow")
    assert (proc.returncode, proc.stdout) == (0, b"")
    (line,) = proc.stderr.decode().splitlines()
    assert line == ("RAQIB-SILENCE: capture failed event=PreToolUse log=%s: Deadline: capture did not"
                    " finish within 1s" % log)
    assert elapsed < 4


def test_m51_e2_timer_deadline_is_cancelled_when_capture_finishes(tmp_path):
    proc, log, _ = run_timer_script(tmp_path, "normal")
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"returned 0", b"")
    assert [r["phase"] for r in lines(log)] == ["pre"]


def test_m51_e2_timer_deadline_is_cancelled_before_the_write(tmp_path, monkeypatch):
    capture = load_capture()
    monkeypatch.setattr(capture, "signal", types.SimpleNamespace())
    log = tmp_path / "trace.jsonl"
    seen = []
    monkeypatch.setattr(capture, "_timer_deadline",
                        types.SimpleNamespace(cancel=lambda: seen.append(log.read_text())))
    capture.append(str(log), fixture("pretooluse-bash.json"))
    assert seen == [""] and len(lines(log)) == 1


def test_m51_e2_a_failed_capture_cancels_the_deadline_first_so_one_line_only(tmp_path):
    """Review F12: the except path cancels the deadline before its
    RAQIB-SILENCE line, so the timer cannot add a second one."""
    proc, log, _ = run_timer_script(tmp_path, "fail")
    assert (proc.returncode, proc.stdout) == (0, b"returned 0")
    (line,) = proc.stderr.decode().splitlines()
    assert line == "RAQIB-SILENCE: capture failed event=PreToolUse log=%s: CaptureError: boom" % log
