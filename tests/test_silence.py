"""M0.2 silence rules: exit criteria E1-E4 (HANDOFF.md), constitution A3."""
import builtins
import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib.rules import silence, trace  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "silence"
S1 = "fixture-silence-0001"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def rules_and_seqs(found):
    return [(f["rule_id"], f["session_id"], f["cited_seq"]) for f in found]


# --- fixture matrix: every rule has a positive and a negative --------------

MATRIX = [
    ("gap-positive.json", [("SILENCE-GAP", S1, [1, 2])]),
    ("gap-interleaved-positive.json", [("SILENCE-GAP", S1, [1, 2])]),
    ("gap-negative.json", []),
    ("open-positive.json", [("SILENCE-OPEN", S1, [2])]),
    ("open-negative.json", []),
    ("half-positive.json", [("SILENCE-HALF", S1, [2])]),
    ("half-orphan-positive.json", [("SILENCE-HALF", S1, [2])]),
    ("half-negative.json", []),
]


@pytest.mark.parametrize("name, expected", MATRIX)
def test_fixture_matrix(name, expected):
    assert rules_and_seqs(silence.findings(load(name))) == expected


def test_e4_each_rule_has_positive_and_negative_fixture():
    for rule in ("gap", "open", "half"):
        names = {n for n, _ in MATRIX if n.startswith(rule + "-")}
        assert any(n.endswith("-positive.json") for n in names), rule
        assert any(n.endswith("-negative.json") for n in names), rule
    assert sorted(p.name for p in FIXTURES.glob("*.json")) == sorted(n for n, _ in MATRIX)


# --- E1 SILENCE-GAP ---------------------------------------------------------

def test_e1_gap_finding_shape():
    lines = load("gap-positive.json")
    (f,) = silence.findings(lines)
    assert f == {
        "ts": lines[2]["ts"],
        "rule_id": "SILENCE-GAP",
        "severity": "high",
        "session_id": S1,
        "cited_seq": [1, 2],
        "summary": f["summary"],
    }
    assert "89.0s" in f["summary"] and "limit 60s" in f["summary"]


def test_e1_gap_equal_to_limit_is_not_a_gap():
    lines = load("gap-negative.json")  # largest gap: exactly 29 s
    assert silence.findings(lines, gap_seconds=29) == []
    assert rules_and_seqs(silence.findings(lines, gap_seconds=28.999)) == [
        ("SILENCE-GAP", S1, [1, 2])]


def test_e1_gap_seconds_parameter():
    found = silence.findings(load("gap-negative.json"), gap_seconds=10)
    assert rules_and_seqs(found) == [("SILENCE-GAP", S1, [1, 2])]


def test_e1_gap_ignores_lines_without_a_timestamp():
    lines = load("gap-positive.json")
    lines[2]["ts"] = "not a time"
    lines[3]["ts"] = None
    assert silence.findings(lines) == []


@pytest.mark.parametrize("environ, expected", [
    ({}, 60),
    ({"RAQIB_GAP_SECONDS": ""}, 60),
    ({"RAQIB_GAP_SECONDS": "5"}, 5.0),
    ({"RAQIB_GAP_SECONDS": "0.5"}, 0.5),
])
def test_e1_gap_seconds_from_environment(environ, expected):
    assert silence.gap_seconds_from(environ) == expected


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "nan", "inf"])
def test_e1_bad_gap_seconds_is_an_error_not_a_default(raw):
    with pytest.raises(ValueError):
        silence.gap_seconds_from({"RAQIB_GAP_SECONDS": raw})


# --- E2 SILENCE-OPEN --------------------------------------------------------

def test_e2_open_cites_last_seq():
    lines = load("open-positive.json")
    (f,) = silence.findings(lines)
    assert (f["rule_id"], f["cited_seq"], f["ts"]) == ("SILENCE-OPEN", [2], lines[-1]["ts"])


def test_e2_session_end_also_closes():
    lines = load("open-negative.json")
    lines[-1]["phase"] = "session_end"
    assert silence.findings(lines) == []


def test_e2_stop_before_start_does_not_close():
    lines = load("open-negative.json")
    stop = lines.pop()
    lines.insert(0, dict(stop, seq=0))
    assert rules_and_seqs(silence.findings(lines)) == [("SILENCE-OPEN", S1, [2])]


def test_e2_no_session_start_no_open():
    assert silence.findings(load("open-positive.json")[1:]) == []


# --- E3 SILENCE-HALF --------------------------------------------------------

def test_e3_half_summaries_name_the_missing_half():
    (pre_only,) = silence.findings(load("half-positive.json"))
    (post_only,) = silence.findings(load("half-orphan-positive.json"))
    assert "has no post" in pre_only["summary"]
    assert "has no pre" in post_only["summary"]


def test_e3_half_per_session():
    lines = load("half-negative.json")
    other = [dict(r, session_id="fixture-silence-0002") for r in lines[:1]]
    found = silence.findings(lines + other)
    assert rules_and_seqs(found) == [("SILENCE-HALF", "fixture-silence-0002", [1])]


# --- E4 pure function -------------------------------------------------------

def test_e4_pure_no_io_no_env_no_mutation(monkeypatch):
    lines = load("gap-negative.json") + load("half-positive.json")
    before = copy.deepcopy(lines)

    def no_io(*a, **k):
        raise AssertionError("findings() must not do I/O")

    monkeypatch.setattr(builtins, "open", no_io)
    monkeypatch.setenv("RAQIB_GAP_SECONDS", "1")
    first = silence.findings(lines)
    assert first == silence.findings(lines)
    assert lines == before
    assert not any(f["rule_id"] == "SILENCE-GAP" for f in first)


def test_e4_every_finding_cites_seq():
    for name, _ in MATRIX:
        for f in silence.findings(load(name)):
            assert f["cited_seq"] and all(isinstance(s, int) for s in f["cited_seq"])


def test_e4_malformed_records_are_ignored_not_fatal():
    lines = load("gap-negative.json") + [{}, {"seq": "x", "session_id": S1}, [], None]
    assert silence.findings(lines) == []


def test_findings_order_is_session_then_seq():
    a = load("half-positive.json")
    b = [dict(r, session_id="fixture-silence-0002") for r in load("open-positive.json")]
    found = silence.findings(b[:1] + a + b[1:])
    assert rules_and_seqs(found) == [
        ("SILENCE-OPEN", "fixture-silence-0002", [2]), ("SILENCE-HALF", S1, [2])]


# --- trace.parse: corrupt lines are surfaced, not skipped silently ---------

def test_trace_parse_reports_bad_lines():
    good = json.dumps(load("gap-negative.json")[0])
    text = "\n".join([good, "", "not json", "[1]", '{"seq": 1}', good + " "]) + "\n"
    records, bad = trace.parse(text)
    assert len(records) == 2
    assert bad == [3, 4, 5]


def test_trace_read_round_trip(tmp_path):
    lines = load("half-positive.json")
    path = tmp_path / "trace.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))
    records, bad = trace.read(path)
    assert (records, bad) == (lines, [])
    assert rules_and_seqs(silence.findings(records)) == [("SILENCE-HALF", S1, [2])]
