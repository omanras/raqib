"""Tests for mizan.fixtures and mizan.report (HANDOFF M1.1, ADR-0001 sections 4, 6, 8)."""

import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mizan import fixtures, loader, report  # noqa: E402
from mizan.fixtures import iter_jsonl, judge, match_file, sidecar_paths  # noqa: E402
from mizan.report import Citation, Result  # noqa: E402

SIDECARS = ROOT / "tests" / "fixtures" / "sidecars"
EVENTS = ROOT / "tests" / "fixtures" / "events"


def rule(name):
    loaded = loader.load(str(SIDECARS / (name + ".yml")))
    return loaded


def cited(result, file_suffix=None, line=None):
    """Citations filtered by file suffix and line."""
    out = []
    for c in result.citations:
        if file_suffix is not None and not c.file.endswith(file_suffix):
            continue
        if line is not None and c.line != line:
            continue
        out.append(c)
    return out


# --- sidecar discovery -------------------------------------------------------------------

def test_sidecar_paths():
    assert sidecar_paths("rules/foo.yml") == ("rules/foo.positive.jsonl", "rules/foo.negative.jsonl")
    assert sidecar_paths("foo.yaml") == ("foo.positive.jsonl", "foo.negative.jsonl")
    assert sidecar_paths(os.path.join("a", "b.sigma.yml")) == (
        os.path.join("a", "b.sigma.positive.jsonl"), os.path.join("a", "b.sigma.negative.jsonl"))


# --- JSON Lines reading (A7) --------------------------------------------------------------

def test_iter_jsonl_reports_every_line(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"a": 1}\n\n   \n{"a": 2}\r\n[1]\n{"a": NaN}\n{"a": 1, "a": 2}\nnot json\n')
    lines = list(iter_jsonl(str(path)))
    assert [l.number for l in lines] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert lines[0].event == {"a": 1} and lines[0].ok
    assert lines[1].event is None and lines[1].ok  # blank
    assert lines[2].event is None and lines[2].ok  # whitespace only
    assert lines[3].event == {"a": 2}  # CRLF tolerated
    assert "not a JSON object" in lines[4].error
    assert "NaN" in lines[5].error
    assert "duplicate key" in lines[6].error
    assert lines[7].error.startswith("malformed JSON")


def test_iter_jsonl_missing_and_directory(tmp_path):
    lines = list(iter_jsonl(str(tmp_path / "nope.jsonl")))
    assert len(lines) == 1 and lines[0].number is None and lines[0].error == "missing"
    lines = list(iter_jsonl(str(tmp_path)))
    assert lines[0].number is None and lines[0].error == "not a file"


def test_iter_jsonl_not_utf8(tmp_path):
    path = tmp_path / "e.jsonl"
    path.write_bytes(b'{"a": 1}\n{"a": "\xff"}\n')
    lines = list(iter_jsonl(str(path)))
    assert lines[0].ok and "UTF-8" in lines[1].error


def test_line_limit_is_enforced_and_cited(tmp_path):
    path = tmp_path / "e.jsonl"
    long_value = "x" * (fixtures.MAX_LINE_BYTES + 10)
    path.write_text('{"a": 1}\n{"a": "%s"}\n{"a": 3}\n' % long_value)
    lines = list(iter_jsonl(str(path)))
    assert lines[0].ok
    assert lines[1].number == 2 and "line longer than %d bytes" % fixtures.MAX_LINE_BYTES in lines[1].error
    assert lines[2].event == {"a": 3}  # the run continues after the bad line


def test_file_limit_is_enforced_and_cited(tmp_path, monkeypatch):
    path = tmp_path / "e.jsonl"
    path.write_text('{"a": 1}\n' * 100)
    monkeypatch.setattr(fixtures, "MAX_FILE_BYTES", 100)
    lines = list(iter_jsonl(str(path)))
    assert len(lines) == 1 and lines[0].number is None
    assert "file larger than 100 bytes" in lines[0].error


def test_limits_match_the_adr():
    assert fixtures.MAX_LINE_BYTES == 1024 * 1024
    assert fixtures.MAX_FILE_BYTES == 256 * 1024 * 1024


def test_parse_event_rejects_non_objects_and_constants():
    assert fixtures.parse_event('{"a": [1, {"b": null}]}') == ({"a": [1, {"b": None}]}, None)
    assert fixtures.parse_event("[1]")[1].startswith("event is not a JSON object")
    assert fixtures.parse_event("42")[1].startswith("event is not a JSON object")
    assert "Infinity" in fixtures.parse_event('{"a": Infinity}')[1]
    assert "malformed JSON" in fixtures.parse_event("{")[1]
    assert "column" in fixtures.parse_event('{"a": }')[1]
    assert "line 1" not in fixtures.parse_event('{"a": }')[1]


# --- E1: judge -----------------------------------------------------------------------------

def test_judge_pass_cites_every_line_it_rests_on():
    result = judge(rule("pass"))
    assert result.status == "pass" and result.green
    assert result.id == "11111111-1111-4111-8111-111111111111"
    assert result.title == "Pass fixture rule"
    positive = cited(result, "pass.positive.jsonl")
    negative = cited(result, "pass.negative.jsonl")
    assert [c.line for c in positive] == [1, 2, 3]
    assert all(c.reason == "matched" for c in positive)
    assert [c.line for c in negative] == [1, 2, 3, 4]
    assert all(c.reason == "did not match" for c in negative)
    assert result.details["fixtures"]["positive"]["events"] == 3
    assert result.details["fixtures"]["negative"]["events"] == 4


def test_judge_fail_cites_wrong_lines_only():
    result = judge(rule("fail"))
    assert result.status == "fail" and not result.green
    assert [(c.file.rsplit(".", 2)[-2], c.line, c.reason) for c in result.citations] == [
        ("positive", 4, "did not match (must match)"),
        ("negative", 5, "matched (must not match)"),
    ]
    assert result.details["fixtures"]["positive"]["wrong"] == [4]
    assert result.details["fixtures"]["negative"]["wrong"] == [5]


def test_judge_unknown_modifier_is_unknown_naming_it():
    result = judge(rule("unknown_modifier"))
    assert result.status == "unknown"
    assert len(result.citations) == 1
    citation = result.citations[0]
    assert citation.file.endswith("unknown_modifier.yml") and citation.line is None
    assert "base64offset" in citation.reason and "selection" in citation.reason
    # the fixtures were still read and counted
    assert result.details["fixtures"]["positive"]["events"] == 3


def test_judge_unknown_condition():
    result = judge(rule("unknown_condition"))
    assert result.status == "unknown"
    assert "aggregation" in result.citations[0].reason


def test_judge_malformed_line_is_unknown_citing_it():
    result = judge(rule("malformed"))
    assert result.status == "unknown"
    bad = [(c.file.rsplit(".", 2)[-2], c.line) for c in result.citations]
    assert bad == [("positive", 2), ("negative", 3), ("negative", 4)]
    assert "malformed JSON" in result.citations[0].reason
    assert "NaN" in result.citations[1].reason
    assert "duplicate key" in result.citations[2].reason
    assert result.details["fixtures"]["positive"]["unknown"] == [2]
    assert result.details["fixtures"]["positive"]["events"] == 2  # the good lines were judged


def test_judge_non_object_line_is_unknown():
    result = judge(rule("not_object"))
    assert result.status == "unknown"
    assert [c.line for c in result.citations] == [2, 3]
    assert all("not a JSON object" in c.reason for c in result.citations)


def test_judge_missing_sidecar_is_fail_naming_the_file():
    result = judge(rule("missing_positive"))
    assert result.status == "fail"
    assert len(result.citations) == 1
    assert result.citations[0].file.endswith("missing_positive.positive.jsonl")
    assert result.citations[0].line is None
    assert "missing" in result.citations[0].reason and "A2" in result.citations[0].reason
    result = judge(rule("missing_negative"))
    assert result.status == "fail"
    assert result.citations[0].file.endswith("missing_negative.negative.jsonl")


def test_judge_empty_sidecar_is_fail():
    result = judge(rule("empty_negative"))
    assert result.status == "fail"
    assert result.citations[0].file.endswith("empty_negative.negative.jsonl")
    assert "no event" in result.citations[0].reason


def test_judge_blank_lines_are_counted_not_silent():
    result = judge(rule("blank_lines"))
    assert result.status == "pass"
    assert [c.line for c in cited(result, "positive.jsonl")] == [1, 3]
    assert [c.line for c in cited(result, "negative.jsonl")] == [2, 3]
    assert result.details["fixtures"]["positive"]["blank_lines"] == 2
    assert result.details["fixtures"]["negative"]["blank_lines"] == 2
    assert any("blank line" in note for note in result.details["notes"])


def test_judge_invalid_rule():
    problems = rule("invalid")
    assert isinstance(problems, loader.Problems)
    result = judge(problems)
    assert result.status == "invalid" and result.id is None
    assert [p["field"] for p in result.problems] == ["id", "level"]
    assert result.citations == []


def test_judge_precedence_unknown_over_fail(tmp_path):
    # a missing positive sidecar (fail) and a malformed negative line (unknown)
    src = (SIDECARS / "pass.yml").read_text()
    (tmp_path / "r.yml").write_text(src)
    (tmp_path / "r.negative.jsonl").write_text('{"Image": "x"}\n{bad\n')
    result = judge(loader.load(str(tmp_path / "r.yml")))
    assert result.status == "unknown"
    reasons = [c.reason for c in result.citations]
    assert any("malformed" in r for r in reasons)
    assert any("missing" in r for r in reasons)


def test_judge_unreadable_sidecar_is_unknown(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    src = (SIDECARS / "pass.yml").read_text()
    (tmp_path / "r.yml").write_text(src)
    (tmp_path / "r.positive.jsonl").write_text('{"Image": "a\\\\cmd.exe", "CommandLine": "whoami"}\n')
    neg = tmp_path / "r.negative.jsonl"
    neg.write_text('{"Image": "x"}\n')
    neg.chmod(0)
    try:
        result = judge(loader.load(str(tmp_path / "r.yml")))
    finally:
        neg.chmod(0o600)
    assert result.status == "unknown"
    assert any("cannot be read" in c.reason for c in result.citations)


def test_judge_never_raises_on_odd_input():
    assert judge(None).status == "invalid"
    assert judge("rules/x.yml").status == "invalid"


# --- match_file --------------------------------------------------------------------------------

def test_match_file_lists_matches_and_unknowns_separately():
    result = match_file(rule("pass"), str(EVENTS / "sample.jsonl"))
    assert result.status == "unknown"  # line 5 is malformed
    assert result.details["matched"] == [1, 4, 7]
    assert [u["line"] for u in result.details["unknown"]] == [5]
    assert result.details["events"] == 5
    assert result.details["blank_lines"] == 1
    assert [(c.line, c.reason.split(":")[0]) for c in result.citations] == [
        (1, "match"), (4, "match"), (5, "unknown"), (7, "match")]


def test_match_file_ok_when_every_line_is_judged():
    result = match_file(rule("pass"), str(EVENTS / "clean.jsonl"))
    assert result.status == "ok"
    assert result.details["matched"] == [1, 3]
    assert result.details["unknown"] == []
    result = match_file(rule("pass"), str(EVENTS / "none.jsonl"))
    assert result.status == "ok" and result.details["matched"] == []


def test_match_file_with_unknown_rule_and_invalid_rule():
    result = match_file(rule("unknown_modifier"), str(EVENTS / "clean.jsonl"))
    assert result.status == "unknown"
    assert result.details["matched"] == [] and result.details["events"] == 3
    result = match_file(rule("invalid"), str(EVENTS / "clean.jsonl"))
    assert result.status == "invalid"


def test_match_file_missing_events_file():
    result = match_file(rule("pass"), str(EVENTS / "nope.jsonl"))
    assert result.status == "unknown"
    assert result.details["file_error"] == "missing"


# --- report ------------------------------------------------------------------------------------

def test_result_text_and_json():
    result = Result("fail", "rules/x.yml", id="abc", title="Title")
    result.cite("rules/x.positive.jsonl", 2, "did not match (must match)")
    result.cite("rules/x.negative.jsonl", None, "missing")
    text = result.text()
    assert text.splitlines() == [
        "fail abc Title",
        "  rules/x.positive.jsonl:2 did not match (must match)",
        "  rules/x.negative.jsonl missing",
    ]
    document = json.loads(report.render_json([result], command="test"))
    assert document["version"] == 1 and document["command"] == "test"
    assert document["green"] is False
    assert document["rules"][0]["citations"][0] == {
        "file": "rules/x.positive.jsonl", "line": 2, "reason": "did not match (must match)"}
    assert document["rules"][0]["citations"][1]["line"] is None


def test_invalid_result_text_lists_problems():
    result = Result("invalid", "rules/x.yml", problems=[{"field": "id", "reason": "missing"}])
    assert result.text().splitlines() == ["invalid - rules/x.yml", "  rules/x.yml id: missing"]


def test_sort_results_red_first_and_green():
    results = [Result("pass", "a"), Result("fail", "b"), Result("unknown", "c"),
               Result("invalid", "d"), Result("no_corpus", "e"), Result("over_budget", "f"),
               Result("pass", "g")]
    ordered = [r.path for r in report.sort_results(results)]
    assert ordered == ["d", "c", "b", "f", "e", "a", "g"]
    assert report.is_green([Result("pass", "a")]) is True
    assert report.is_green([Result("pass", "a"), Result("fail", "b")]) is False
    assert report.is_green([]) is False  # nothing is green by default (A4)
    assert report.exit_code([Result("pass", "a")]) == 0
    assert report.exit_code([Result("unknown", "a")]) == 1


def test_citation_text():
    assert Citation("f", 3, "why").text() == "f:3 why"
    assert Citation("f", None, "why").text() == "f why"
    assert Citation("f", 3, "").text() == "f:3"
