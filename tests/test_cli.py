"""Tests for mizan.cli through ``mizan.cli.main(argv)`` -- no subprocess
(HANDOFF M1.1 E3-E5, ADR-0001 sections 8-9)."""

import io
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import cli  # noqa: E402

SIDECARS = ROOT / "tests" / "fixtures" / "sidecars"
EVENTS = ROOT / "tests" / "fixtures" / "events"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def rule(name):
    return str(SIDECARS / (name + ".yml"))


# --- test command ----------------------------------------------------------------------------

def test_test_pass():
    code, out, err = run("test", rule("pass"))
    assert code == 0 and err == ""
    lines = out.splitlines()
    assert lines[0] == "pass 11111111-1111-4111-8111-111111111111 Pass fixture rule"
    assert lines[1] == "  %s:1 matched" % (SIDECARS / "pass.positive.jsonl")
    assert all(line.startswith("  ") for line in lines[1:])
    assert len(lines) == 1 + 3 + 4


def test_test_fail():
    code, out, err = run("test", rule("fail"))
    assert code == 1
    lines = out.splitlines()
    assert lines[0].startswith("fail 22222222-2222-4222-8222-222222222222 ")
    assert lines[1].endswith("fail.positive.jsonl:4 did not match (must match)")
    assert lines[2].endswith("fail.negative.jsonl:5 matched (must not match)")


def test_test_unknown():
    code, out, _ = run("test", rule("unknown_modifier"))
    assert code == 1
    assert out.startswith("unknown 33333333-3333-4333-8333-333333333333 ")
    assert "base64offset" in out
    code, out, _ = run("test", rule("malformed"))
    assert code == 1
    assert out.startswith("unknown ")
    assert "malformed.positive.jsonl:2 malformed JSON" in out


def test_test_missing_sidecar():
    code, out, _ = run("test", rule("missing_positive"))
    assert code == 1
    assert out.startswith("fail ")
    assert "missing_positive.positive.jsonl missing" in out


def test_test_invalid_rule():
    code, out, _ = run("test", rule("invalid"))
    assert code == 1
    lines = out.splitlines()
    assert lines[0] == "invalid - %s" % rule("invalid")
    assert lines[1].endswith("invalid.yml id: missing")
    assert lines[2].endswith("invalid.yml level: missing")


def test_test_json():
    code, out, err = run("test", rule("fail"), "--json")
    assert code == 1 and err == ""
    document = json.loads(out)
    assert document["version"] == 1
    assert document["command"] == "test"
    assert document["green"] is False
    assert len(document["rules"]) == 1
    result = document["rules"][0]
    assert result["status"] == "fail"
    assert result["id"] == "22222222-2222-4222-8222-222222222222"
    assert result["citations"][0]["line"] == 4
    assert result["fixtures"]["positive"]["wrong"] == [4]
    code, out, _ = run("test", "--json", rule("pass"))
    assert code == 0 and json.loads(out)["green"] is True


def test_test_unreadable_path_is_exit_3():
    code, out, err = run("test", str(SIDECARS / "does_not_exist.yml"))
    assert code == 3 and out == ""
    assert "does_not_exist.yml" in err and "not a file" in err
    code, out, err = run("test", str(SIDECARS))
    assert code == 3 and "not a file" in err


# --- match command -------------------------------------------------------------------------------

def test_match_prints_matching_lines_and_unknown_separately():
    code, out, err = run("match", rule("pass"), str(EVENTS / "sample.jsonl"))
    assert code == 1 and err == ""  # one line could not be judged
    lines = out.splitlines()
    assert lines[0].startswith("unknown 11111111-1111-4111-8111-111111111111 ")
    sample = str(EVENTS / "sample.jsonl")
    assert lines[1] == "  %s:1 match" % sample
    assert lines[2] == "  %s:4 match" % sample
    assert lines[3].startswith("  %s:5 unknown: malformed JSON" % sample)
    assert lines[4] == "  %s:7 match" % sample
    assert lines[5] == "  events=5 matched=3 unknown=1 blank=1"


def test_match_clean_file_is_exit_0():
    code, out, _ = run("match", rule("pass"), str(EVENTS / "clean.jsonl"))
    assert code == 0
    lines = out.splitlines()
    assert lines[0].startswith("ok 11111111-1111-4111-8111-111111111111 ")
    assert lines[1].endswith("clean.jsonl:1 match")
    assert lines[2].endswith("clean.jsonl:3 match")
    assert lines[3] == "  events=3 matched=2 unknown=0"
    code, out, _ = run("match", rule("pass"), str(EVENTS / "none.jsonl"))
    assert code == 0 and "matched=0" in out


def test_match_json():
    code, out, _ = run("match", rule("pass"), str(EVENTS / "sample.jsonl"), "--json")
    assert code == 1
    document = json.loads(out)
    assert document["command"] == "match"
    result = document["rules"][0]
    assert result["status"] == "unknown"
    assert result["matched"] == [1, 4, 7]
    assert [u["line"] for u in result["unknown"]] == [5]
    assert result["events"] == 5
    assert document["green"] is False


def test_match_with_unknown_and_invalid_rules():
    code, out, _ = run("match", rule("unknown_modifier"), str(EVENTS / "clean.jsonl"))
    assert code == 1 and out.startswith("unknown ")
    code, out, _ = run("match", rule("invalid"), str(EVENTS / "clean.jsonl"))
    assert code == 1 and out.startswith("invalid ")


def test_match_unreadable_paths_are_exit_3():
    code, out, err = run("match", rule("pass"), str(EVENTS / "nope.jsonl"))
    assert code == 3 and out == "" and "nope.jsonl" in err
    code, out, err = run("match", str(SIDECARS / "nope.yml"), str(EVENTS / "clean.jsonl"))
    assert code == 3 and out == "" and "nope.yml" in err


# --- usage -------------------------------------------------------------------------------------------

def test_usage_errors_are_exit_2():
    code, out, err = run()
    assert code == 2 and out == "" and "usage:" in err
    code, out, err = run("bogus")
    assert code == 2 and "invalid choice" in err
    code, out, err = run("test")
    assert code == 2 and "required" in err
    code, out, err = run("match", rule("pass"))
    assert code == 2
    code, out, err = run("test", rule("pass"), "--nope")
    assert code == 2 and "unrecognized" in err


def test_help_is_exit_0():
    code, out, err = run("--help")
    assert code == 0
    assert "test" in (out + err) and "match" in (out + err)


def test_main_defaults_to_sys_argv_and_streams(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mizan", "test", rule("pass")])
    assert cli.main() == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("pass ")


def test_dunder_main_module():
    import importlib
    import mizan.__main__ as entry
    importlib.reload(entry)
    assert entry._main(["test", rule("pass")]) == 0
    assert entry._main([]) == 2
