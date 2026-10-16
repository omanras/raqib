"""Capture hook: M0.1 exit criteria E1-E3, M0.1b E1-E3 (ADR-0001 section 3, A-1, A-2)."""
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
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


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root ignores file permissions")
def test_e3_read_only_log_is_silence(tmp_path):
    log = tmp_path / "trace.jsonl"
    log.write_text("")
    log.chmod(0o444)
    assert_silence(run(fixture("pretooluse-bash.json"), log))
    assert log.read_text() == ""


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
    ({"command": "9X=1 ls"}, "9X=1"),
    ({"command": "/usr/local/bin/ --help"}, "bin"),
    ({"command": "/opt/" + "x" * 100 + " -v"}, "x" * 64),
    ({"command": "y" * 65}, "y" * 64),
    ({"command": ""}, None),
    ({"command": " \n\t "}, None),
    ({"command": "FOO=1 BAR=2"}, None),
    ({"command": ["ls"]}, None),
    ({"description": "no command"}, None),
])
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
# the tree for the gate's secret scan to find.

FAKE = {
    "aws_access_key_id": "AKIA" + "Z7" * 8,
    "github_token": "gh" + "p_" + "A1" * 18,
    "google_api_key": "AI" + "za" + "B2" * 17 + "C",
    "jwt": "ey" + "J" + "a" * 10 + ".ey" + "J" + "b" * 10 + "." + "c" * 10,
    "private_key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "sk_api_key": "sk-" + "ant-" + "k9" * 12,
    "slack_token": "xo" + "xb-" + "1234567890ab",
}


def post_with(response, tmp_path):
    post = fixture("posttooluse-bash.json")
    post["tool_response"] = response
    log = tmp_path / "trace.jsonl"
    assert_captured(run(post, log))
    (rec,) = lines(log)
    return rec, log.read_text()


@pytest.mark.parametrize("kind", sorted(FAKE))
def test_m12_secret_in_output_is_recorded_by_name_only(tmp_path, kind):
    secret = FAKE[kind]
    rec, text = post_with({"stdout": "config:\n" + secret + "\n", "stderr": ""}, tmp_path)
    assert rec["output_meta"] == {"secret_kinds": [kind]}
    assert secret not in text and secret[4:14] not in text


def test_m12_kinds_are_sorted_and_found_in_keys_and_nesting(tmp_path):
    response = {FAKE["slack_token"]: [{"deep": ["x", FAKE["aws_access_key_id"]]}]}
    rec, _ = post_with(response, tmp_path)
    assert rec["output_meta"] == {"secret_kinds": ["aws_access_key_id", "slack_token"]}


@pytest.mark.parametrize("text", [
    "AKIA" + "Z7" * 7 + "Z",
    "x" + "AKIA" + "Z7" * 8,
    "AKIA" + "Z7" * 8 + "Q",
    "sk-" + "short",
    "-----BEGIN " + "PUBLIC KEY-----",
    "no secrets here",
])
def test_m12_near_misses_are_not_secrets(tmp_path, text):
    rec, _ = post_with({"stdout": text}, tmp_path)
    assert rec["output_meta"] == {}


def test_m12_secret_in_a_failure_message(tmp_path):
    failure = fixture("posttoolusefailure-bash.json")
    failure["error"] = "curl: (22) 401 for token " + FAKE["github_token"]
    log = tmp_path / "trace.jsonl"
    assert_captured(run(failure, log))
    (rec,) = lines(log)
    assert rec["output_meta"] == {"secret_kinds": ["github_token"]}
    assert FAKE["github_token"] not in log.read_text()


def test_m12_only_post_lines_carry_output_meta(tmp_path):
    pre = fixture("pretooluse-bash.json")
    pre["tool_input"]["command"] = "echo " + FAKE["aws_access_key_id"]
    recs = run_all([fixture("sessionstart.json"), pre, fixture("posttooluse-bash.json")],
                   tmp_path / "trace.jsonl")
    assert ["output_meta" in r for r in recs] == [False, False, True]
    assert recs[2]["output_meta"] == {}


def test_m12_all_kinds_at_once_are_sorted(tmp_path):
    rec, text = post_with({"stdout": " ".join(FAKE[k] for k in reversed(sorted(FAKE)))}, tmp_path)
    assert rec["output_meta"] == {"secret_kinds": sorted(FAKE)}
    assert not any(v in text for v in FAKE.values())
