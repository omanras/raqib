"""M1.3 findings format + report CLI (HANDOFF.md E1-E4)."""
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, report  # noqa: E402
from raqib.rules import engine  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
QUICKSTART = FIXTURES / "quickstart-claude-code-2.1.301.log"
BLOCKED = FIXTURES / "blocked-calls-claude-code-2.1.301.log"


def raqib(*argv, env=None):
    out = io.StringIO()
    old = dict(os.environ)
    try:
        os.environ.pop("RAQIB_GAP_SECONDS", None)
        os.environ.update(env or {})
        code = cli.main([str(a) for a in argv], out=out)
    finally:
        os.environ.clear()
        os.environ.update(old)
    return code, out.getvalue()


def write_trace(path, lines):
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))
    return path


def fixture_lines(rel):
    data = json.loads((FIXTURES / rel).read_text())
    return (data["lines"], data.get("context", {})) if isinstance(data, dict) else (data, {})


def current_trace(tmp_path):
    """A benign session in the shape current capture writes (output_meta on posts)."""
    lines, _ = fixture_lines("rules/benign/dev-session.json")
    return write_trace(tmp_path / "current.jsonl", lines)


def findings_of(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines()]


# --- E1: rules TRACE -o FILE -----------------------------------------------

def test_e1_rules_writes_one_valid_finding_per_line(tmp_path):
    out = tmp_path / "findings.jsonl"
    code, text = raqib("rules", BLOCKED, "-o", out)
    assert code == 1
    assert "2 findings -> " in text
    found = findings_of(out)
    assert [(f["rule_id"], f["class"], f["cited_seq"]) for f in found] == [
        ("SILENCE-HALF", "SILENCE", [2]), ("SILENCE-HALF", "SILENCE", [3])]
    for f in found:
        assert engine.check_finding(f) is f
        assert set(f) == {"ts", "rule_id", "class", "severity", "session_id", "cited_seq", "summary"}
    sidecar = json.loads((tmp_path / "findings.jsonl.notes.json").read_text())
    assert [(n["rule_id"], n["status"]) for n in sidecar["notes"]] == [
        ("DRIFT-FILES", "not-evaluated"), ("SECRET-OUTPUT", "partial")]
    assert [r["id"] for r in sidecar["rules"]][:4] == [
        "SILENCE-GAP", "SILENCE-OPEN", "SILENCE-HALF", "SILENCE-ORDER"]


def test_e1_rules_to_stdout(tmp_path):
    code, text = raqib("rules", current_trace(tmp_path), "--scope", ".")
    assert (code, text) == (0, "")


def drift_trace(tmp_path):
    lines, ctx = fixture_lines("rules/DRIFT-FILES/positive-three-files.json")
    return write_trace(tmp_path / "trace.jsonl", lines), ctx["scope"]


def test_e1_scope_from_option_and_from_handoff(tmp_path):
    trace, scope = drift_trace(tmp_path)
    args = [a for s in scope for a in ("--scope", s)]
    code, text = raqib("rules", trace, *args)
    assert code == 1 and [f["rule_id"] for f in map(json.loads, text.splitlines())] == ["DRIFT-FILES"]
    handoff = tmp_path / "HANDOFF.md"
    handoff.write_text("# HANDOFF\n\nScope:\n  %s\n  %s\n\nExit criteria:\n- x\n" % (scope[0], ", ".join(scope[1:])))
    assert raqib("rules", trace, "--handoff", handoff, "--root", "/work/example")[1] == text
    assert raqib("rules", trace, *args, "--root", "/work/example")[1] == text
    anchored = [json.loads(x) for x in raqib("rules", trace, "--handoff", handoff)[1].splitlines()]
    assert anchored[0]["summary"].startswith("5 distinct files")  # paths resolved under tmp_path
    code, text = raqib("rules", trace)
    assert (code, text) == (3, "")


def gap_trace(tmp_path):
    lines = json.loads((FIXTURES / "silence" / "gap-negative.json").read_text())
    return write_trace(tmp_path / "gap.jsonl", lines)


def test_e1_gap_seconds_from_environment_and_option(tmp_path):
    trace = gap_trace(tmp_path)
    assert raqib("rules", trace)[0] == 3
    code, text = raqib("rules", trace, env={"RAQIB_GAP_SECONDS": "10"})
    assert code == 1 and json.loads(text)["rule_id"] == "SILENCE-GAP"
    assert raqib("rules", trace, "--gap-seconds", "100", env={"RAQIB_GAP_SECONDS": "10"})[0] == 3
    assert raqib("rules", trace, env={"RAQIB_GAP_SECONDS": "nan"})[0] == 2
    assert raqib("rules", trace, "--gap-seconds", "0")[0] == 2


# --- E2: report cites the lines --------------------------------------------

def test_e2_report_cites_file_lines_of_every_cited_seq(tmp_path):
    lines, _ = fixture_lines("rules/SCOPE-PATH/positive-etc-and-dotdot.json")
    trace = write_trace(tmp_path / "trace.jsonl", lines)
    code, text = raqib("report", trace, "--scope", ".")
    assert code == 1
    assert "[medium] SCOPE-PATH (SCOPE) session fixture-rules-scope-2 seq 1" in text
    assert "      seq 1: line 1  pre Edit seq 1  2026-10-16T13:00:01.000Z  " \
           'input_meta={"path": "/etc/hosts"}' in text
    assert "      seq 1: line 2  post Edit seq 1" in text
    assert "      seq 2: line 3  pre Write seq 2" in text
    assert "RESULT: ALARM (exit 1)" in text


def test_e2_findings_file_round_trip_matches_direct_report(tmp_path):
    out = tmp_path / "f.jsonl"
    raqib("rules", BLOCKED, "-o", out)
    direct = json.loads(raqib("report", BLOCKED, "--json")[1])
    via_file = json.loads(raqib("report", BLOCKED, "--findings", out, "--json")[1])
    for key in ("findings", "alarms", "notes", "result", "exit"):
        assert via_file[key] == direct[key], key


def test_e2_bad_citations_are_alarms(tmp_path):
    out = tmp_path / "f.jsonl"
    good = {"ts": "t", "rule_id": "X-Y", "class": "NET", "severity": "low",
            "session_id": "nobody", "cited_seq": [9], "summary": "s"}
    out.write_text("\n".join([json.dumps(good), json.dumps(dict(good, cited_seq=[])), "not json"]) + "\n")
    (tmp_path / "f.jsonl.notes.json").write_text(json.dumps({"notes": []}))
    code, rep = raqib("report", QUICKSTART, "--findings", out, "--json")
    rep = json.loads(rep)
    assert code == 1
    assert [a["kind"] for a in rep["alarms"]] == ["missing-citation", "rejected-finding", "rejected-finding"]
    assert rep["findings"][0]["cites"] == [{"seq": 9, "lines": []}]
    assert "NO LINE IN TRACE" in raqib("report", QUICKSTART, "--findings", out)[1]


def test_e2_findings_file_without_notes_is_incomplete(tmp_path):
    out = tmp_path / "empty.jsonl"
    out.write_text("")
    code, text = raqib("report", QUICKSTART, "--findings", out)
    assert code == 3
    assert "* unknown: no rule notes next to the findings file" in text


# --- E3: rules, alarms, unrun rules, exit codes ----------------------------

def test_e3_rule_table_lists_every_rule_with_budget(tmp_path):
    rep = json.loads(raqib("report", QUICKSTART, "--json")[1])
    table = {r["id"]: r for r in rep["rules"]}
    assert set(table) == {"SILENCE-GAP", "SILENCE-OPEN", "SILENCE-HALF", "SILENCE-ORDER",
                          "DESTRUCT-CMD", "DRIFT-FILES", "NET-TOOL", "SCOPE-CWD-MOVED",
                          "SCOPE-CWD-ROOT", "SCOPE-PATH", "SECRET-OUTPUT"}
    assert table["SECRET-OUTPUT"]["fp_budget"] == 0.05 and table["SILENCE-GAP"]["fp_budget"] is None
    text = raqib("report", QUICKSTART)[1]
    assert "  NET-TOOL        NET       medium  0.25      active" in text


def test_e3_clean_incomplete_and_alarm(tmp_path):
    current = current_trace(tmp_path)
    code, text = raqib("report", current, "--scope", ".")
    assert code == 0 and "RESULT: CLEAN (exit 0)" in text
    code, text = raqib("report", current)
    assert code == 3 and "RESULT: INCOMPLETE (exit 3)" in text
    assert "DRIFT-FILES not-evaluated: needs context: scope" in text


def test_e3_trace_from_before_secret_scanning_is_incomplete(tmp_path):
    """The real quickstart trace predates output_meta (M1.2): its posts cannot be
    judged for secrets, so the report is incomplete, never clean (A3)."""
    code, text = raqib("report", QUICKSTART, "--scope", ".")
    assert code == 3
    assert "SECRET-OUTPUT partial: could not judge 1 line(s)" in text


def test_e3_empty_trace_is_an_alarm(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    code, rep = raqib("report", empty, "--scope", ".", "--json")
    assert code == 1
    assert json.loads(rep)["alarms"][0]["kind"] == "empty-trace"


def test_e3_corrupt_lines_are_alarms_with_line_numbers(tmp_path):
    good = QUICKSTART.read_text().splitlines()
    trace = tmp_path / "t.jsonl"
    trace.write_text("\n".join(good[:2] + ["{torn", '{"seq": 1}'] + good[2:]) + "\n")
    code, text = raqib("report", trace, "--scope", ".")
    assert code == 1
    assert "  - trace-problem: line 3: not JSON" in text
    assert "  - trace-problem: line 4: no session_id" in text


def test_e3_disabled_rule_is_listed_but_not_incomplete(tmp_path):
    catalog = tmp_path / "catalog"
    shutil.copytree(ROOT / "raqib" / "rules" / "catalog", catalog)
    path = catalog / "NET-TOOL.yaml"
    path.write_text(path.read_text().replace("severity: medium\n", "severity: medium\nstatus: disabled\n"))
    code, text = raqib("report", current_trace(tmp_path), "--scope", ".", "--catalog", catalog)
    assert code == 0
    assert "NET-TOOL disabled: status: disabled in" in text


@pytest.mark.parametrize("argv", [
    [],
    ["bogus"],
    ["report"],
    ["report", "/nonexistent/trace.jsonl"],
    ["rules", str(QUICKSTART), "--handoff", "/nonexistent/HANDOFF.md"],
    ["rules", str(QUICKSTART), "-o", "/nonexistent/dir/f.jsonl"],
])
def test_e3_usage_errors_exit_2(argv):
    assert raqib(*argv)[0] == 2


def test_e3_broken_catalog_exits_2(tmp_path):
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    (catalog / "NET-X.yaml").write_text("id: NET-X\n")
    assert raqib("report", QUICKSTART, "--catalog", catalog)[0] == 2


# --- E4: check-rules --------------------------------------------------------

def test_e4_check_rules_prints_measured_rate_against_budget():
    code, text = raqib("check-rules")
    assert code == 0
    rows = {line.split()[0]: line.split() for line in text.splitlines()[1:]}
    assert set(rows) == {"DESTRUCT-CMD", "DRIFT-FILES", "NET-TOOL", "SCOPE-CWD-MOVED", "SCOPE-CWD-ROOT",
                         "SCOPE-PATH", "SECRET-OUTPUT"}
    assert "3 measured, 7 unmeasured" in " ".join(rows["DRIFT-FILES"])
    assert rows["NET-TOOL"][1:4] == ["ok", "0.111", "0.25"]
    data = json.loads(raqib("check-rules", "--json")[1])
    assert {r["verdict"] for r in data} == {"ok"}


def test_e4_check_rules_fails_an_over_budget_rule(tmp_path):
    catalog = tmp_path / "catalog"
    shutil.copytree(ROOT / "raqib" / "rules" / "catalog", catalog)
    path = catalog / "NET-TOOL.yaml"
    path.write_text(path.read_text().replace("fp_budget: 0.25", "fp_budget: 0.1"))
    code, text = raqib("check-rules", "--catalog", catalog)
    assert code == 1
    assert [line.split()[1] for line in text.splitlines() if line.startswith("NET-TOOL ")] == ["over-budget"]


def test_python_dash_m_entry_point(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "raqib", "report", str(current_trace(tmp_path)), "--scope", "."],
                          cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("Raqib report\n")


def test_report_build_is_pure_and_bounded():
    rec = {"seq": 1, "session_id": "s", "phase": "pre", "tool": "Bash", "ts": "t",
           "input_meta": {"path": "x" * 500 + "\x1b"}}
    text = report.describe(rec)
    assert len(text) == report.LINE_TEXT_MAX and text.endswith("...") and "\x1b" not in text
