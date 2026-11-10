"""M1.3 findings format + report CLI (HANDOFF.md E1-E4)."""
import io
import hashlib
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
        assert set(f) == {"ts", "rule_id", "class", "kind", "severity", "session_id", "cited_seq", "summary"}
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
    # M5.1b E6: no Windows marker. The engine accepts a Windows root (E2), and
    # --root is made absolute as the host does (ruling C-3).
    trace, scope = drift_trace(tmp_path)
    args = [a for s in scope for a in ("--scope", s)]
    code, text = raqib("rules", trace, *args)
    assert code == 1 and [f["rule_id"] for f in map(json.loads, text.splitlines())] == ["DRIFT-FILES"]
    assert json.loads(text)["summary"].startswith("3 distinct files")   # scope anchored on each line's cwd
    handoff = tmp_path / "HANDOFF.md"
    handoff.write_text("# HANDOFF\n\nScope:\n  %s\n  %s\n\nExit criteria:\n- x\n" % (scope[0], ", ".join(scope[1:])))
    rooted = raqib("rules", trace, "--handoff", handoff, "--root", "/work/example")[1]
    assert raqib("rules", trace, *args, "--root", "/work/example")[1] == rooted
    if os.name == "nt":
        # C-3: on Windows /work/example is <drive>:\work\example, a Windows root that
        # holds none of the trace's POSIX paths, so all five files are outside it.
        assert json.loads(rooted)["summary"].startswith("5 distinct files")
    else:
        assert rooted == text
    anchored = [json.loads(x) for x in raqib("rules", trace, "--handoff", handoff)[1].splitlines()]
    assert anchored[0]["summary"].startswith("5 distinct files")  # paths resolved under tmp_path (Windows too)
    code, text = raqib("rules", trace)
    assert (code, text) == (3, "")


@pytest.mark.parametrize("root", ["/work/example", "rel/dir", r"C:\proj", "/"])
def test_m51b_c3_root_is_made_absolute_as_the_host_does_and_help_says_so(root, capsys):
    """Ruling C-3: --root keeps os.path.abspath's meaning on the host (on
    Windows /x is \\x on the current drive); the help text records it."""
    import argparse
    ctx = cli._context(argparse.Namespace(scope=["src"], root=root, handoff=None))
    assert ctx == {"scope": ["src"], "root": os.path.abspath(root)}
    assert cli.ROOT_HELP == ("directory the scope paths are relative to (default: each line's cwd); made absolute"
                             " as this host does (os.path.abspath): on Windows /x means \\x on the current drive,"
                             " e.g. C:\\x")
    assert cli.main(["rules", "--help"], out=io.StringIO()) == 0
    assert "made absolute as this host does (os.path.abspath)" in " ".join(capsys.readouterr().out.split())


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
    assert "[medium] SCOPE-PATH (SCOPE, signature) session fixture-rules-scope-2 seq 1" in text
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
    good = {"ts": "t", "rule_id": "X-Y", "class": "NET", "kind": "signature", "severity": "low",
            "session_id": "nobody", "cited_seq": [9], "summary": "s"}
    out.write_text("\n".join([json.dumps(good), json.dumps(dict(good, cited_seq=[])), "not json"]) + "\n")
    sha = hashlib.sha256(QUICKSTART.read_bytes()).hexdigest()
    (tmp_path / "f.jsonl.notes.json").write_text(json.dumps({"notes": [], "trace_sha256": sha}))
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
    assert set(table) == {"SILENCE-GAP", "SILENCE-OPEN", "SILENCE-HALF", "SILENCE-ORDER", "SILENCE-EMPTY",
                          "CROSS-SOURCE", "DESTRUCT-CMD", "DRIFT-FILES", "NET-TOOL", "SCOPE-CWD-MOVED",
                          "SCOPE-CWD-ROOT", "SCOPE-PATH", "SECRET-OUTPUT", "LANDED-NO-GATE", "EDIT-NO-TEST",
                          "HEAD-UNMOVED", "INDEX-UNTOUCHED",   # M4.3 J-1: the two tree anchors
                          "NEW-AGENT", "NEW-AGENT-UNKNOWN", "AGENT-DARK-LIVE",   # M7.2: the host anchors
                         "HOST-UNWATCHED", "HOST-RHYTHM"}                  # M7.2b (ADR-0007 H-3); M7.4 (judge host lines only)
    assert table["SECRET-OUTPUT"]["fp_budget"] == 0.05 and table["SILENCE-GAP"]["fp_budget"] is None
    assert table["CROSS-SOURCE"]["fp_budget"] == 0.1 and table["CROSS-SOURCE"]["class"] == "CROSS"   # M5.3 C-8
    for rid in ("HEAD-UNMOVED", "INDEX-UNTOUCHED"):
        assert {k: table[rid][k] for k in ("class", "kind", "severity", "fp_budget", "status")} == {
            "class": "DRIFT", "kind": "anchor", "severity": "medium", "fp_budget": 0.1, "status": "active"}, rid
    assert [r["id"] for r in rep["rules"]][5:8] == ["CROSS-SOURCE", "HEAD-UNMOVED", "INDEX-UNTOUCHED"]
    text = raqib("report", QUICKSTART)[1]
    assert "  NET-TOOL        NET       signature medium  0.25      active" in text
    assert "  CROSS-SOURCE    CROSS     anchor    high    0.1       active" in text
    assert "  HEAD-UNMOVED    DRIFT     anchor    medium  0.1       active" in text
    assert "  INDEX-UNTOUCHED DRIFT     anchor    medium  0.1       active" in text


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
                         "SCOPE-PATH", "SECRET-OUTPUT", "CROSS-SOURCE",   # M5.3 D-11: the code rule too
                         "LANDED-NO-GATE", "EDIT-NO-TEST",                # M4.2b: the two demands
                         "HEAD-UNMOVED", "INDEX-UNTOUCHED",               # M4.3 J-1: the two tree anchors
                         "NEW-AGENT", "NEW-AGENT-UNKNOWN", "AGENT-DARK-LIVE",   # M7.2: the host anchors
                         "HOST-UNWATCHED", "HOST-RHYTHM"}                  # M7.2b (ADR-0007 H-3); M7.4
    assert rows["CROSS-SOURCE"][1:4] == ["ok", "0.000", "0.1"]
    # M4.3: the tree anchors are measured on their own negatives only; no benign
    # file carries git keys, so none is judged (J-3).
    assert rows["HEAD-UNMOVED"][1:4] == ["ok", "0.000", "0.1"] and "2 measured, 8 unmeasured" in " ".join(
        rows["HEAD-UNMOVED"])
    assert rows["INDEX-UNTOUCHED"][1:4] == ["ok", "0.000", "0.1"] and "3 measured, 8 unmeasured" in " ".join(
        rows["INDEX-UNTOUCHED"])
    assert "4 measured, 7 unmeasured" in " ".join(rows["DRIFT-FILES"])   # M5.1b: + the Windows negative
    # M4.2 REDO-2 E-1: the field trace is not benign (tests/fixtures/field/), so
    # NET-TOOL is 1 of 11 (docs-lookup; negative-programs.json is the 10th, M7.2b's host-source
    # negative-host-child.json the 11th) and SCOPE-PATH 0 of 10 (M5.1b: + the Windows negative).
    # M7.8: NET-TOOL's os-line negative is measured too (1 of 12)
    assert rows["NET-TOOL"][1:4] == ["ok", "0.083", "0.25"] and "12 measured" in " ".join(rows["NET-TOOL"])
    assert rows["SCOPE-PATH"][1:4] == ["ok", "0.000", "0.1"] and "10 measured" in " ".join(rows["SCOPE-PATH"])
    data = json.loads(raqib("check-rules", "--json")[1])
    assert {r["verdict"] for r in data} == {"ok"}


def test_e4_check_rules_fails_an_over_budget_rule(tmp_path):
    catalog = tmp_path / "catalog"
    shutil.copytree(ROOT / "raqib" / "rules" / "catalog", catalog)
    path = catalog / "NET-TOOL.yaml"
    path.write_text(path.read_text().replace("fp_budget: 0.25", "fp_budget: 0.05"))   # measured 0.1
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
    assert len(text) == report.LINE_TEXT_MAX and "..." in text and "\x1b" not in text
    assert text.endswith('\\u001b"}')  # the end of a long path stays visible


# --- REDO 3 (docs/review/2026-10-16-M1.3-M2.1-review.md, part 1) -----------

NEW_QUICKSTART = FIXTURES / "quickstart-d7841d1-claude-code-2.1.301.log"


def test_redo3_findings_made_for_another_trace_are_an_alarm(tmp_path):
    out = tmp_path / "f.jsonl"
    assert raqib("rules", NEW_QUICKSTART, "--scope", ".", "-o", out)[0] == 0
    assert raqib("report", NEW_QUICKSTART, "--findings", out)[0] == 0
    other = tmp_path / "other.log"
    other.write_bytes(BLOCKED.read_bytes())
    code, text = raqib("report", other, "--findings", out, "--json")
    rep = json.loads(text)
    assert code == 1 and [a["kind"] for a in rep["alarms"]] == ["findings-for-another-trace"]
    grown = tmp_path / "grown.log"
    grown.write_bytes(NEW_QUICKSTART.read_bytes())
    sidecar = json.loads((tmp_path / "f.jsonl.notes.json").read_text())
    assert sidecar["trace_sha256"] == hashlib.sha256(grown.read_bytes()).hexdigest()
    with open(grown, "ab") as f:
        f.write(NEW_QUICKSTART.read_bytes().splitlines(keepends=True)[-1])
    assert raqib("report", grown, "--findings", out)[0] == 1


@pytest.mark.parametrize("notes", ['{"notes": "x"}', '{"notes": [{}]}', '{"notes": [{"rule_id": 1}]}', "[]"])
def test_redo3_a_bad_notes_file_is_a_usage_error(tmp_path, notes):
    out = tmp_path / "f.jsonl"
    out.write_text("")
    (tmp_path / "f.jsonl.notes.json").write_text(notes)
    assert raqib("report", NEW_QUICKSTART, "--findings", out)[0] == 2


def test_redo3_the_text_report_prints_no_control_characters(tmp_path):
    sha = hashlib.sha256(QUICKSTART.read_bytes()).hexdigest()
    forged = {"ts": "t", "rule_id": "X-Y", "class": "NET", "severity": "low",
              "session_id": "s\nRESULT: CLEAN (exit 0)\x1b[2J", "cited_seq": [2],
              "summary": "x\rRESULT: CLEAN"}
    out = tmp_path / "f.jsonl"
    out.write_text(json.dumps(forged) + "\n")
    (tmp_path / "f.jsonl.notes.json").write_text(json.dumps({"notes": [], "trace_sha256": sha}))
    code, text = raqib("report", QUICKSTART, "--findings", out)
    assert code == 1
    assert [l for l in text.splitlines() if l.startswith("RESULT:")] == ["RESULT: ALARM (exit 1)"]
    assert all(c == "\n" or c.isprintable() for c in text)


def test_redo3_cited_lines_show_cwd():
    rec = {"seq": 1, "session_id": "s", "phase": "pre", "tool": "Bash", "ts": "t", "cwd": "/home/u"}
    assert 'cwd="/home/u"' in report.describe(rec)


def suspicion_files(tmp_path, lines, run):
    out = tmp_path / "s.jsonl"
    out.write_text("".join(json.dumps(x) + "\n" for x in lines))
    if run is not None:
        (tmp_path / "s.jsonl.run.json").write_text(json.dumps(run) if not isinstance(run, str) else run)
    return out


RAISED = {"kind": "suspicion", "session_id": "57f643ec-4568-4c20-9897-8649acf2d998", "window": [1, 4],
          "suspicion": 0.8, "reasons": ["odd"], "cited_seq": [2], "backend": "fake", "model": "canned"}
RUN = {"windows": 1, "raised": 1, "errors": 0, "below_threshold": 0, "backend": "fake", "model": "canned",
       "threshold": 0.5}


def test_redo3_a_raised_suspicion_alone_makes_an_alarm(tmp_path):
    out = suspicion_files(tmp_path, [RAISED], RUN)
    code, text = raqib("report", NEW_QUICKSTART, "--scope", ".", "--suspicion", out, "--json")
    rep = json.loads(text)
    assert (code, rep["result"], rep["alarms"], rep["findings"]) == (1, "alarm", [], [])


@pytest.mark.parametrize("lines, run, fragment", [
    ([], None, "no run record"),
    ([RAISED], dict(RUN, raised=0, below_threshold=1), "lines were added or removed"),
    ([], dict(RUN, raised=0, errors=1, below_threshold=0), "lines were added or removed"),
    ([RAISED], dict(RUN, windows=3), "do not add up"),
    ([RAISED], {"windows": "1"}, "malformed"),
    ([RAISED], "[]", "malformed"),
], ids=["missing", "raised-removed", "error-removed", "bad-sum", "bad-types", "not-an-object"])
def test_redo3_the_run_record_must_account_for_the_file(tmp_path, lines, run, fragment):
    out = suspicion_files(tmp_path, lines, run)
    code, text = raqib("report", NEW_QUICKSTART, "--scope", ".", "--suspicion", out, "--json")
    rep = json.loads(text)
    assert code == 1 and fragment in " ".join(a["detail"] for a in rep["alarms"] if a["kind"] == "suspicion-run")
    assert raqib("report", NEW_QUICKSTART, "--scope", ".", "--suspicion", out)[0] == 1


def test_redo3_a_suspicion_citing_outside_its_window_is_rejected():
    assert "outside its window" in report.suspicion_problem(dict(RAISED, cited_seq=[9]))
    assert report.suspicion_problem(RAISED) is None


# --- M4.1 E3 (ADR-0002): every finding carries its rule's kind ----------------

def kind_of(rule_id):
    from raqib.rules import silence
    kinds = {r.id: r.kind for r in engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")}
    return dict(kinds, **silence.RULE_KINDS)[rule_id]


def test_m41_e3_report_json_rules_and_findings_file_carry_the_kind(tmp_path):
    lines = fixture_lines("rules/SCOPE-PATH/positive-etc-and-dotdot.json")[0] + \
        fixture_lines("rules/SCOPE-CWD-MOVED/positive-cd-out.json")[0]
    mixed = write_trace(tmp_path / "trace.jsonl", lines)
    seen = {}
    for trace in (mixed, BLOCKED):
        code, text = raqib("report", trace, "--scope", ".", "--json")
        rep = json.loads(text)
        assert code == 1 and rep["findings"]
        for f in rep["findings"]:
            assert f["kind"] == kind_of(f["rule_id"]), f
            seen.setdefault(f["kind"], set()).add(f["rule_id"])
        out = tmp_path / ("%s.jsonl" % trace.name)
        raqib("rules", trace, "--scope", ".", "-o", out)
        assert [(f["rule_id"], f["kind"]) for f in findings_of(out)] == [
            (f["rule_id"], f["kind"]) for f in rep["findings"]]
        via_file = json.loads(raqib("report", trace, "--findings", out, "--json")[1])
        assert [f["kind"] for f in via_file["findings"]] == [f["kind"] for f in rep["findings"]]
    assert set(seen) == set(engine.KINDS)          # each kind was shown at least once
    assert "SCOPE-PATH" in seen["signature"] and "SCOPE-CWD-MOVED" in seen["anchor"]
    assert "SILENCE-HALF" in seen["demand"]


def test_m41_e3_a_findings_file_with_an_unknown_kind_is_a_rejected_finding(tmp_path):
    sha = hashlib.sha256(QUICKSTART.read_bytes()).hexdigest()
    forged = {"ts": "t", "rule_id": "X-Y", "class": "NET", "kind": "acquitted", "severity": "low",
              "session_id": "s", "cited_seq": [2], "summary": "x"}
    out = tmp_path / "f.jsonl"
    out.write_text(json.dumps(forged) + "\n")
    (tmp_path / "f.jsonl.notes.json").write_text(json.dumps({"notes": [], "trace_sha256": sha}))
    rep = json.loads(raqib("report", QUICKSTART, "--findings", out, "--json")[1])
    assert rep["findings"] == [] and [a["kind"] for a in rep["alarms"]] == ["rejected-finding"]
    assert "unknown kind" in rep["alarms"][0]["detail"]



# --- M4.1 REDO (ADR-0002 Amendment B) -----------------------------------------------

def mixed_trace(tmp_path):
    lines = fixture_lines("rules/SCOPE-PATH/positive-etc-and-dotdot.json")[0] + \
        fixture_lines("rules/SCOPE-CWD-MOVED/positive-cd-out.json")[0]
    return write_trace(tmp_path / "mixed.jsonl", lines)


def test_m41_b1_the_text_report_prints_the_kind_on_every_finding_line(tmp_path):
    """K2: the text path, not only --json."""
    seen = set()
    for trace in (mixed_trace(tmp_path), BLOCKED):
        rep = json.loads(raqib("report", trace, "--scope", ".", "--json")[1])
        code, text = raqib("report", trace, "--scope", ".")
        assert code == 1 and rep["findings"]
        for f in rep["findings"]:
            head = "  [%s] %s (%s, %s) session %s seq %s" % (
                f["severity"], f["rule_id"], f["class"], f["kind"], f["session_id"],
                ",".join(str(s) for s in f["cited_seq"]))
            assert head in text.splitlines(), head
            seen.add(f["kind"])
    assert seen == set(engine.KINDS)


def test_m41_b1_the_text_rules_table_has_a_kind_column():
    rep = json.loads(raqib("report", QUICKSTART, "--json")[1])
    text = raqib("report", QUICKSTART)[1].splitlines()
    assert "  id              class     kind      sev     fp_budget status" in text
    assert {r["id"]: r["kind"] for r in rep["rules"]} == dict(
        {r.id: r.kind for r in engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")},
        **{rid: "demand" for rid, _ in report.SILENCE_RULES}, **{rid: "anchor" for rid, _ in report.CROSS_RULES},
        **{rid: "anchor" for rid, _ in report.TREE_RULES})   # M4.3 J-1
    for r in rep["rules"]:
        budget = "-" if r["fp_budget"] is None else "%g" % r["fp_budget"]
        row = "  %-15s %-9s %-9s %-7s %-9s %s" % (r["id"], r["class"], r["kind"], r["severity"], budget, r["status"])
        assert row in text, row
    assert "  SILENCE-GAP     SILENCE   demand    high    -         active" in text
    assert "  SCOPE-CWD-ROOT  SCOPE     anchor    medium  0.1       active" in text


def test_m41_b3_a_finding_without_kind_is_a_no_kind_alarm(tmp_path):
    """K5 (A3): a finding file line with no kind is not passed over."""
    from raqib.rules import trace
    numbered = trace.read_numbered(str(QUICKSTART))[0]
    session, seq = numbered[0][1]["session_id"], numbered[0][1]["seq"]
    finding = {"ts": None, "rule_id": "NET-TOOL", "class": "NET", "severity": "medium",
               "session_id": session, "cited_seq": [seq], "summary": "an older findings file"}
    rep = report.build(str(QUICKSTART), numbered, [], [finding], [], [], "file")
    assert [a["kind"] for a in rep["alarms"]] == ["no-kind"] and rep["findings"] == []
    detail = rep["alarms"][0]["detail"]
    assert detail.startswith("finding has no kind (ADR-0002") and "NET-TOOL" in detail
    assert (rep["result"], rep["exit"]) == ("alarm", 1)
    with_kind = report.build(str(QUICKSTART), numbered, [], [dict(finding, kind="signature")], [], [], "file")
    assert with_kind["alarms"] == [] and len(with_kind["findings"]) == 1
    out = tmp_path / "f.jsonl"
    out.write_text(json.dumps(finding) + "\n")
    sha = hashlib.sha256(QUICKSTART.read_bytes()).hexdigest()
    (tmp_path / "f.jsonl.notes.json").write_text(json.dumps({"notes": [], "trace_sha256": sha}))
    code, text = raqib("report", QUICKSTART, "--findings", out)
    assert code == 1 and "  - no-kind: finding has no kind (ADR-0002" in text and "FINDINGS: 0" in text


# --- M4.2 E5: SILENCE-EMPTY in the report; the field trace of 2026-11-02 ------

FIELD = FIXTURES / "field" / "2026-11-02.log"   # E-1: outside the benign glob


def test_m42_e5_report_ids_and_the_rules_table_row():
    assert [rid for rid, _ in report.SILENCE_RULES][-1] == "SILENCE-EMPTY"
    (row,) = [r for r in report.rule_table([]) if r["id"] == "SILENCE-EMPTY"]
    assert row == {"id": "SILENCE-EMPTY", "class": "SILENCE", "kind": "demand", "severity": "high",
                   "fp_budget": None, "status": "active", "title": row["title"]}
    text = raqib("report", QUICKSTART)[1]
    assert "  SILENCE-EMPTY   SILENCE   demand    high    -         active" in text.splitlines()


def test_m42_e5_raqib_report_on_the_field_trace_shows_its_five_findings():
    """Ruling D-4: SILENCE-GAP s3, SCOPE-PATH s5, NET-TOOL s6, SILENCE-EMPTY
    s1 and s2. s7 (python3 -c 'import urllib.request') is the recorded
    NET-TOOL miss: no rule fires on it, as the field note recorded."""
    code, text = raqib("report", FIELD, "--json")
    rep = json.loads(text)
    assert (code, rep["result"], rep["alarms"], rep["notes"]) == (1, "alarm", [], [
        {"rule_id": "DRIFT-FILES", "status": "not-evaluated", "detail": "needs context: scope"}])
    assert (rep["records"], len(rep["sessions"])) == (26, 7)
    assert [(f["rule_id"], f["kind"], f["severity"], f["session_id"][-2:], f["cited_seq"]) for f in rep["findings"]] == [
        ("SILENCE-EMPTY", "demand", "high", "s1", [1, 2]),
        ("SILENCE-EMPTY", "demand", "high", "s2", [1, 2]),
        ("SILENCE-GAP", "demand", "high", "s3", [1, 2]),
        ("SCOPE-PATH", "signature", "medium", "s5", [2]),
        ("NET-TOOL", "signature", "medium", "s6", [2])]
    assert not any(f["session_id"].endswith(("s4", "s7")) for f in rep["findings"])
    code, text = raqib("report", FIELD)
    assert code == 1 and "FINDINGS: 5" in text and "RESULT: ALARM (exit 1)" in text
    assert "  [high] SILENCE-EMPTY (SILENCE, demand) session field-2026-11-02-s1 seq 1,2" in text.splitlines()
    assert "  [high] SILENCE-EMPTY (SILENCE, demand) session field-2026-11-02-s2 seq 1,2" in text.splitlines()
