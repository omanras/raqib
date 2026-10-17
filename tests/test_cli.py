"""Tests for mizan.cli through ``mizan.cli.main(argv)`` -- no subprocess
(HANDOFF M1.1 E3-E5, ADR-0001 sections 8-9)."""

import io
import json
import os
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


# --- corpus command (M1.2) ------------------------------------------------------------------------

RULESET = str(ROOT / "tests" / "fixtures" / "ruleset")
CORPUS_OK = str(ROOT / "tests" / "fixtures" / "corpus_ok")
CORPUS_BAD = str(ROOT / "tests" / "fixtures" / "corpus_bad")


def test_corpus_command_text():
    code, out, err = run("corpus", RULESET, "--corpus", CORPUS_OK)
    assert code == 1 and err == ""
    heads = [line for line in out.splitlines() if not line.startswith("  ")]
    assert heads == [
        "invalid - fp/10k=- budget=- events=0",
        "unknown a1a1a1a1-0000-4000-8000-000000000008 fp/10k=0 budget=1 events=50",
        "over_budget a1a1a1a1-0000-4000-8000-000000000002 fp/10k=200 budget=100 events=50",
        "no_corpus a1a1a1a1-0000-4000-8000-000000000003 fp/10k=- budget=1 events=0",
        "no_corpus a1a1a1a1-0000-4000-8000-000000000005 fp/10k=- budget=1500 events=0",
        "pass a1a1a1a1-0000-4000-8000-000000000001 fp/10k=200 budget=250 events=50",
        "pass a1a1a1a1-0000-4000-8000-000000000004 fp/10k=1000 budget=1500 events=40",
        "pass a1a1a1a1-0000-4000-8000-000000000007 fp/10k=200 budget=250 events=50",
        "pass a1a1a1a1-0000-4000-8000-000000000006 fp/10k=0 budget=0 events=50",
    ]
    assert "  %s:22 match" % (ROOT / "tests" / "fixtures" / "corpus_ok" / "windows-process_creation.jsonl") in out


def test_corpus_command_json():
    code, out, _ = run("corpus", RULESET, "--corpus", CORPUS_OK, "--json")
    assert code == 1
    document = json.loads(out)
    assert document["command"] == "corpus" and document["green"] is False
    by_id = {r["id"]: r for r in document["rules"]}
    r1 = by_id["a1a1a1a1-0000-4000-8000-000000000001"]
    assert r1["status"] == "pass" and r1["corpus"]["fp_per_10k"] == 200.0
    assert r1["corpus"]["files"][0]["matches"] == [22]
    assert by_id["a1a1a1a1-0000-4000-8000-000000000002"]["status"] == "over_budget"


def test_corpus_command_broken_corpus_is_exit_3():
    code, out, err = run("corpus", RULESET, "--corpus", CORPUS_BAD)
    assert code == 3
    assert "no_header.jsonl" in err and "malformed_line.jsonl:4" in err
    assert out.startswith("invalid ")
    assert "unknown a1a1a1a1-0000-4000-8000-000000000001" in out


def test_corpus_command_missing_dirs():
    code, out, err = run("corpus", str(ROOT / "nope"), "--corpus", CORPUS_OK)
    assert code == 3 and out == "" and "missing" in err
    code, out, err = run("corpus", RULESET, "--corpus", str(ROOT / "nope"))
    assert code == 3 and "corpus directory missing" in err
    assert "no_corpus" in out


# --- check command (M1.2) ---------------------------------------------------------------------------

def test_check_command_red_rules_first():
    code, out, err = run("check", RULESET, "--corpus", CORPUS_OK)
    assert code == 1 and err == ""
    heads = [line.split(" ")[0] for line in out.splitlines() if not line.startswith("  ")]
    assert heads == ["invalid", "unknown", "fail", "over_budget", "no_corpus", "no_corpus", "pass", "pass", "pass"]
    lines = out.splitlines()
    assert lines[0] == "invalid - %s" % os.path.join(RULESET, "invalid.yml")
    assert any(line.endswith("r7_fixture_fail.positive.jsonl:3 did not match (must match)") for line in lines)
    assert any(line.endswith("windows-process_creation.jsonl:22 match") for line in lines)
    assert "  fp/10k=200 budget=250 events=50 corpus=windows-process_creation.jsonl" in lines


def test_check_command_json_shape():
    code, out, _ = run("check", RULESET, "--corpus", CORPUS_OK, "--json")
    assert code == 1
    document = json.loads(out)
    assert set(document) == {"version", "command", "rules_dir", "corpus", "rules", "green"}
    assert document["version"] == 1 and document["green"] is False
    statuses = [r["status"] for r in document["rules"]]
    assert statuses == ["invalid", "unknown", "fail", "over_budget", "no_corpus", "no_corpus", "pass", "pass", "pass"]
    r6 = [r for r in document["rules"] if (r["id"] or "").endswith("006")][0]
    assert r6["fixtures"]["positive"]["events"] == 2
    assert r6["corpus"]["fp_per_10k"] == 0.0


def test_check_green_set(tmp_path):
    import shutil
    rules = tmp_path / "rules"
    rules.mkdir()
    for name in ("r1_within_budget", "r4_named_corpus"):
        for suffix in (".yml", ".positive.jsonl", ".negative.jsonl"):
            shutil.copy(os.path.join(RULESET, name + suffix), str(rules / (name + suffix)))
    code, out, err = run("check", str(rules), "--corpus", CORPUS_OK)
    assert code == 0 and err == "", out
    assert all(line.startswith("pass ") or line.startswith("  ") for line in out.splitlines())
    code, out, _ = run("check", str(rules), "--corpus", CORPUS_OK, "--json")
    assert code == 0 and json.loads(out)["green"] is True


def test_check_defaults_to_rules_and_corpus_of_cwd(tmp_path, monkeypatch):
    import shutil
    (tmp_path / "rules").mkdir()
    shutil.copytree(CORPUS_OK, str(tmp_path / "corpus"))
    for suffix in (".yml", ".positive.jsonl", ".negative.jsonl"):
        shutil.copy(os.path.join(RULESET, "r1_within_budget" + suffix), str(tmp_path / "rules" / ("r" + suffix)))
    monkeypatch.chdir(str(tmp_path))
    code, out, err = run("check")
    assert code == 0, err
    assert out.startswith("pass a1a1a1a1-0000-4000-8000-000000000001 ")
    assert "rules/r.positive.jsonl:1 matched" in out


def test_check_empty_rules_dir_is_red(tmp_path):
    code, out, err = run("check", str(tmp_path), "--corpus", CORPUS_OK)
    assert code == 1 and out == "" and "no *.yml rule" in err
    code, out, _ = run("check", str(tmp_path), "--corpus", CORPUS_OK, "--json")
    assert code == 1 and json.loads(out) == {"version": 1, "command": "check", "rules_dir": str(tmp_path),
                                             "corpus": CORPUS_OK, "rules": [], "green": False}


def test_check_broken_corpus_is_exit_3():
    code, out, err = run("check", RULESET, "--corpus", CORPUS_BAD)
    assert code == 3 and "empty.jsonl" in err
    assert "unknown a1a1a1a1-0000-4000-8000-000000000001" in out


def test_check_missing_rules_dir_is_exit_3():
    code, out, err = run("check", str(ROOT / "nope"))
    assert code == 3 and out == "" and "missing" in err
