"""M0.2 silence rules: exit criteria E1-E4 (HANDOFF.md), constitution A3,
plus the M0.2 REDO from docs/review/2026-10-16-M0.2.md."""
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
S2 = "fixture-silence-0002"


def load(name):
    return json.loads((FIXTURES / name).read_text())


def rules_and_seqs(found):
    return [(f["rule_id"], f["session_id"], f["cited_seq"]) for f in found]


def other_session(recs):
    return [dict(r, session_id=S2) for r in recs]


# --- fixture matrix: every rule has a positive and a negative --------------

MATRIX = [
    ("gap-positive.json", [("SILENCE-GAP", S1, [1, 2])]),
    ("gap-interleaved-positive.json", [("SILENCE-GAP", S1, [1, 2])]),
    ("gap-negative.json", []),
    ("open-positive.json", [("SILENCE-OPEN", S1, [2])]),
    ("open-after-stop-positive.json", [("SILENCE-OPEN", S1, [4])]),
    ("open-negative.json", []),
    ("half-positive.json", [("SILENCE-HALF", S1, [2])]),
    ("half-orphan-positive.json", [("SILENCE-HALF", S1, [2])]),
    ("half-duplicate-positive.json", [("SILENCE-HALF", S1, [2]), ("SILENCE-ORDER", S1, [2, 2])]),
    ("half-negative.json", []),
    ("order-seq-positive.json", [("SILENCE-ORDER", S1, [2, 1])]),
    ("order-ts-positive.json", [("SILENCE-ORDER", S1, [1, 2])]),
    ("order-negative.json", []),
]
RULES = ("gap", "open", "half", "order")


@pytest.mark.parametrize("name, expected", MATRIX)
def test_fixture_matrix(name, expected):
    found = silence.findings(load(name))
    assert sorted(rules_and_seqs(found)) == sorted(expected)


def test_e4_each_rule_has_positive_and_negative_fixture():
    for rule in RULES:
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
        "kind": "demand",
        "severity": "high",
        "session_id": S1,
        "cited_seq": [1, 2],
        "summary": f["summary"],
    }
    assert f["summary"] == (
        "no capture for 89.000s from 2026-10-16T12:00:01.000Z (post seq 1) "
        "to 2026-10-16T12:01:30.000Z (pre seq 2); limit 60s")


def test_e1_gap_equal_to_limit_is_not_a_gap():
    lines = load("gap-negative.json")  # largest gap: exactly 29 s
    assert silence.findings(lines, gap_seconds=29) == []
    assert rules_and_seqs(silence.findings(lines, gap_seconds=28.999)) == [
        ("SILENCE-GAP", S1, [1, 2])]


def test_e1_gap_inside_one_tool_call_cites_that_seq_twice():
    lines = load("gap-negative.json")
    found = silence.findings(lines[:2], gap_seconds=0.5)
    assert rules_and_seqs(found) == [("SILENCE-GAP", S1, [1, 1])]
    assert "(pre seq 1) to" in found[0]["summary"] and "(post seq 1)" in found[0]["summary"]


def test_e1_gap_skips_lines_without_a_timestamp_and_parse_reports_them():
    lines = load("gap-positive.json")
    lines[2]["ts"] = "not a time"
    lines[3]["ts"] = None
    assert silence.findings(lines) == []
    _, problems = trace.parse("\n".join(json.dumps(r) for r in lines))
    assert problems == [{"line": 3, "reason": "missing or bad ts"},
                        {"line": 4, "reason": "missing or bad ts"}]


@pytest.mark.parametrize("environ, expected", [
    ({}, 60),
    ({"RAQIB_GAP_SECONDS": ""}, 60),
    ({"RAQIB_GAP_SECONDS": "5"}, 5.0),
    ({"RAQIB_GAP_SECONDS": "0.5"}, 0.5),
])
def test_e1_gap_seconds_from_environment(environ, expected):
    assert silence.gap_seconds_from(environ) == expected


def test_e1_environment_value_drives_findings():
    lines = load("gap-negative.json")
    gap = silence.gap_seconds_from({"RAQIB_GAP_SECONDS": "10"})
    assert rules_and_seqs(silence.findings(lines, gap)) == [("SILENCE-GAP", S1, [1, 2])]


@pytest.mark.parametrize("raw", ["abc", "0", "-1", "nan", "inf", "1e12", "604801"])
def test_e1_bad_gap_seconds_from_env_is_an_error_not_a_default(raw):
    with pytest.raises(ValueError):
        silence.gap_seconds_from({"RAQIB_GAP_SECONDS": raw})


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), 1e12, 604800.5, None, "60", True])
def test_e1_bad_gap_seconds_argument_is_an_error(value):
    with pytest.raises(ValueError):
        silence.findings(load("gap-positive.json"), gap_seconds=value)


# --- E2 SILENCE-OPEN --------------------------------------------------------

def test_e2_open_cites_last_line():
    lines = load("open-positive.json")
    (f,) = silence.findings(lines)
    assert (f["rule_id"], f["cited_seq"], f["ts"]) == ("SILENCE-OPEN", [2], lines[-1]["ts"])


def test_e2_session_end_also_closes():
    lines = load("open-negative.json")
    lines[-1]["phase"] = "session_end"
    assert silence.findings(lines) == []


def test_e2_activity_after_the_last_stop_reopens():
    lines = load("open-after-stop-positive.json")
    (f,) = silence.findings(lines)
    assert "post seq 4" in f["summary"]
    assert silence.findings(lines[:4]) == []


def test_e2_resumed_session_without_stop_is_open():
    lines = load("open-negative.json")
    resume = dict(lines[0], seq=4, ts="2026-10-16T12:00:05.000Z")
    found = silence.findings(lines + [resume])
    assert rules_and_seqs(found) == [("SILENCE-OPEN", S1, [4])]


def test_e2_no_session_start_no_open():
    assert silence.findings(load("open-positive.json")[1:]) == []


def test_e2_open_ts_falls_back_to_last_valid_ts():
    lines = load("open-positive.json")
    lines[-1]["ts"] = None
    (f,) = [f for f in silence.findings(lines) if f["rule_id"] == "SILENCE-OPEN"]
    assert f["ts"] == lines[-2]["ts"]


# --- E3 SILENCE-HALF --------------------------------------------------------

def test_e3_half_summaries_name_the_missing_half():
    (pre_only,) = silence.findings(load("half-positive.json"))
    (post_only,) = silence.findings(load("half-orphan-positive.json"))
    assert pre_only["summary"].endswith("1 pre and 0 post line(s): a post is missing")
    assert post_only["summary"].endswith("0 pre and 1 post line(s): a pre is missing")


def test_e3_half_counts_lines_so_a_duplicate_seq_cannot_hide_it():
    combined = load("gap-negative.json") + load("half-positive.json")
    assert ("SILENCE-HALF", S1, [2]) in rules_and_seqs(silence.findings(combined))


def test_e3_half_per_session():
    lines = load("half-negative.json")
    found = silence.findings(lines + other_session(lines[:1]))
    assert rules_and_seqs(found) == [("SILENCE-HALF", S2, [1])]


# --- REDO: SILENCE-ORDER ----------------------------------------------------

def test_order_seq_regression_summary():
    (f,) = silence.findings(load("order-seq-positive.json"))
    assert f["summary"] == (
        "pre seq 1 comes after pre seq 2: seq went back (trace truncated, rotated or merged?)")


def test_order_time_regression_summary():
    (f,) = silence.findings(load("order-ts-positive.json"))
    assert "6.000s earlier than post seq 1" in f["summary"]


def test_order_posts_may_reuse_old_seqs():
    assert silence.findings(load("order-negative.json")) == []


# --- E4 pure function -------------------------------------------------------

def test_e4_pure_no_io_no_env_no_mutation(monkeypatch):
    lines = load("gap-positive.json") + other_session(load("half-positive.json"))
    before = copy.deepcopy(lines)

    def no_io(*a, **k):
        raise AssertionError("findings() must not do I/O")

    monkeypatch.setattr(builtins, "open", no_io)
    monkeypatch.setenv("RAQIB_GAP_SECONDS", "1000")
    first = silence.findings(lines)
    assert rules_and_seqs(first) == [("SILENCE-GAP", S1, [1, 2]), ("SILENCE-HALF", S2, [2])]
    assert first == silence.findings(lines)
    assert lines == before
    first[0]["cited_seq"].append(99)
    assert silence.findings(lines)[0]["cited_seq"] == [1, 2]


def test_e4_every_finding_cites_seq():
    for name, _ in MATRIX:
        for f in silence.findings(load(name)):
            assert f["cited_seq"] and all(type(s) is int for s in f["cited_seq"])
            assert f["ts"]


def test_e4_uncitable_records_are_skipped_not_fatal():
    lines = load("gap-negative.json") + [{}, {"seq": "x", "session_id": S1},
                                         {"seq": True, "session_id": S1}, [], None]
    assert silence.findings(lines) == []


def test_findings_order_is_session_then_seq():
    a = load("half-positive.json")
    b = other_session(load("open-positive.json"))
    found = silence.findings(b[:1] + a + b[1:])
    assert rules_and_seqs(found) == [("SILENCE-OPEN", S2, [2]), ("SILENCE-HALF", S1, [2])]


def test_two_findings_in_one_session_are_sorted_by_seq():
    lines = load("open-positive.json") + [
        dict(load("half-positive.json")[2], seq=3, ts="2026-10-16T12:05:00.000Z")]
    found = silence.findings(lines)
    assert [(f["rule_id"], f["cited_seq"]) for f in found] == [
        ("SILENCE-GAP", [2, 3]), ("SILENCE-HALF", [3]), ("SILENCE-OPEN", [3])]


# --- trace.parse / trace.read: corruption is surfaced, never skipped -------

def test_trace_parse_reports_problems():
    good = json.dumps(load("gap-negative.json")[0])
    bad_phase = json.dumps(dict(load("gap-negative.json")[1], phase="prr"))
    text = "\n".join([good, "", "not json", "[1]", '{"seq": 1}',
                      '{"seq": true, "session_id": "s"}', bad_phase, good + " \r"]) + "\n"
    records, problems = trace.parse(text)
    assert len(records) == 3
    assert problems == [
        {"line": 3, "reason": "not JSON"},
        {"line": 4, "reason": "not a JSON object"},
        {"line": 5, "reason": "no session_id"},
        {"line": 6, "reason": "no int seq"},
        {"line": 7, "reason": "unknown phase 'prr'"},
    ]


def test_trace_parse_counts_only_newlines():
    rec = load("gap-negative.json")[0]
    text = json.dumps(dict(rec, cwd="/a\u2028b")).replace("\\u2028", "\u2028") + "\n" + "oops\n"
    records, problems = trace.parse(text)
    assert len(records) == 1 and problems == [{"line": 2, "reason": "not JSON"}]


def test_trace_read_reports_invalid_utf8(tmp_path):
    rec = load("gap-negative.json")[0]
    raw = json.dumps(dict(rec, cwd="X")).encode().replace(b'"X"', b'"\xff"')
    path = tmp_path / "trace.jsonl"
    path.write_bytes(raw + b"\n")
    records, problems = trace.read(path)
    assert len(records) == 1
    assert problems == [{"line": 1, "reason": "invalid UTF-8"}]


def test_trace_read_round_trip(tmp_path):
    lines = load("half-positive.json")
    path = tmp_path / "trace.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in lines))
    records, problems = trace.read(path)
    assert (records, problems) == (lines, [])
    assert rules_and_seqs(silence.findings(records)) == [("SILENCE-HALF", S1, [2])]


# --- M1.1 REDO: every finding has a ts (S14) and the gap limit is capped (S15)

def test_gap_limit_of_seven_days_is_allowed():
    assert silence.gap_seconds_from({"RAQIB_GAP_SECONDS": "604800"}) == 604800.0
    assert silence.findings(load("gap-positive.json"), gap_seconds=604800) == []


def test_half_and_order_fall_back_to_the_last_valid_ts():
    half = load("half-positive.json")
    half[2]["ts"] = None
    (f,) = silence.findings(half)
    assert (f["rule_id"], f["ts"]) == ("SILENCE-HALF", half[1]["ts"])
    order = load("order-seq-positive.json")
    order[4]["ts"] = "garbage"
    found = [f for f in silence.findings(order) if f["rule_id"] == "SILENCE-ORDER"]
    assert [f["ts"] for f in found] == [order[3]["ts"]]


# --- M4.1 E3 (ADR-0002): the silence rules are demands -------------------------

def test_m41_e3_each_silence_rule_declares_kind_demand():
    assert silence.RULE_KINDS == {"SILENCE-GAP": "demand", "SILENCE-OPEN": "demand",
                                  "SILENCE-HALF": "demand", "SILENCE-ORDER": "demand"}
    from raqib import report
    assert [rule_id for rule_id, _ in report.SILENCE_RULES] == list(silence.RULE_KINDS)


def test_m41_e3_every_silence_finding_carries_kind_demand():
    seen = set()
    for name, _ in MATRIX:
        for f in silence.findings(load(name)):
            assert f["kind"] == silence.RULE_KINDS[f["rule_id"]] == "demand", (name, f)
            seen.add(f["rule_id"])
    assert seen == set(silence.RULE_KINDS)      # each of the four rules was seen firing


def test_m41_e3_a_silence_rule_without_a_kind_cannot_emit(monkeypatch):
    monkeypatch.delitem(silence.RULE_KINDS, "SILENCE-GAP")
    with pytest.raises(KeyError):
        silence.findings(load("gap-positive.json"))
    assert silence.findings(load("gap-negative.json")) == []
