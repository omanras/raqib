"""M1.1 rule schema, YAML-subset loader, engine and fixture runner (HANDOFF.md E1-E4)."""
import builtins
import copy
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib.rules import engine, fixtures, yamlite  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
RULE_FIXTURES = ROOT / "tests" / "fixtures" / "rules"
# Synthetic sessions plus every real Claude Code trace (the CLI uses the same set).
BENIGN = fixtures.benign_corpus(RULE_FIXTURES / "benign") + sorted(
    str(p) for p in (ROOT / "tests" / "fixtures").glob("*.log"))

try:
    import yaml
except ImportError:  # the cross-check is optional; raqib itself is stdlib-only
    yaml = None


# --- E1: YAML subset ---------------------------------------------------------

DOCS = [
    "a: 1\nb: -2.5\nc: ~\nd:\ne: true\nf: 'x # not a comment'  # a comment\n"
    "g: \"\\u0041\\/\\t\"\nh: [1, [2, 3], {k: v}]\ni: {}\nj: []\nk: .5\nl: +7\nm: False\n",
    "- a\n- - b\n  - c\n- k: v\n  l: w\n-\n  m: n\n",
    "a:\n- 1\n- x: [a, 'b']\n  y:\n  - z\nb: ''\nc: \"it's\"\nd: it's fine\n",
    "---\n# leading comment\nkey/with.dots-and_under: \"v\"\n'quoted key': 1\n",
    "a: {b: {c: [1, {d: null}]}, e: \"x, y\"}\nf: [\"a]b\", 'c}d']\n",
    "a: http://example.org/x?y=1#frag\nb: -rf\nc: 3.0\nd: x:y\n",
    # Y1: a quote inside a plain value does not hide a comment
    'summary: a - "b # c"\nregex: =["\'] # note\nk: it\'s # c\nm: b - c\n',
    "- a: 'x # y'\n  b: \"z\"\n- [a, 'b # c']\n- {k: a#b}\n",
]


def test_redo2_y1_quotes_inside_plain_values_without_pyyaml():
    assert yamlite.loads(DOCS[6]) == {"summary": 'a - "b', "regex": "=[\"']", "k": "it's", "m": "b - c"}
    assert yamlite.loads(DOCS[7]) == [{"a": "x # y", "b": "z"}, ["a", "b # c"], {"k": "a#b"}]


@pytest.mark.parametrize("text", DOCS + [p.read_text() for p in sorted(CATALOG.glob("*.yaml"))])
def test_e1_subset_agrees_with_pyyaml(text):
    if yaml is None:
        pytest.skip("PyYAML not installed")
    assert yamlite.loads(text) == yaml.safe_load(text)


def test_e1_values():
    assert yamlite.loads(DOCS[0]) == {
        "a": 1, "b": -2.5, "c": None, "d": None, "e": True, "f": "x # not a comment",
        "g": "A/\t", "h": [1, [2, 3], {"k": "v"}], "i": {}, "j": [], "k": 0.5, "l": 7, "m": False}
    assert yamlite.loads("") is None
    assert yamlite.loads("# only a comment\n") is None


ERRORS = [
    ("a: yes", 1, "ambiguous plain scalar 'yes'"),
    ("a: Off", 1, "ambiguous"),
    ("a: 017", 1, "ambiguous"),
    ("a: 0x1F", 1, "ambiguous"),
    ("a: 1_000", 1, "ambiguous"),
    ("a: 1e3", 1, "ambiguous"),
    ("a: 1:30", 1, "ambiguous"),
    ("a: .inf", 1, "ambiguous"),
    ("a: -.5", 1, "ambiguous"),
    ("a: 2026-10-16", 1, "ambiguous"),
    ("a: 1\n\tb: 2", 2, "tab in indentation"),
    ("a:\tb", 1, "tab outside a quoted scalar"),
    ("a: &x 1", 1, "unsupported YAML feature or indicator '&'"),
    ("a: *x", 1, "unsupported YAML feature or indicator '*'"),
    ("a: !!str 1", 1, "unsupported YAML feature or indicator '!'"),
    ("a: |\n  t", 1, "unsupported YAML feature or indicator '|'"),
    ("a: >\n  t", 1, "unsupported YAML feature or indicator '>'"),
    ("a: ]x", 1, "indicator ']'"),
    ("a: ,x", 1, "indicator ','"),
    ("on: 1", 1, "ambiguous plain scalar 'on'"),
    ("1: x", 1, "key '1' is not a string in YAML"),
    ("null: 2", 1, "key 'null' is not a string in YAML"),
    ("a: {1: x}", 1, "key '1' is not a string in YAML"),
    ("a: 1.5_0", 1, "ambiguous"),
    ("a: 1._", 1, "ambiguous"),
    ("a: [a,#b]", 1, "must be quoted"),
    ("a: {regex: colou?r}", 1, "must be quoted"),
    ("--- foo", 1, "document markers"),
    ("a: b" + chr(11) + "c", 1, "U+000B"),
    ("a: v" + chr(0xA0), 1, "U+00A0"),
    ("a: x" + chr(0x1B) + "[31m", 1, "U+001B"),
    ("a: " + chr(0x202E) + "x", 1, "U+202E"),
    ('a: "' + chr(92) + 'x1b[31m"', 1, "control or invisible"),
    ('a: "' + chr(92) + 'u202e"', 1, "control or invisible"),
    ('a: "x' + chr(92) + 'ny"', 1, "escape \\n is a control character"),
    ('a: "' + chr(92) + 'r"', 1, "escape \\r is a control character"),
    ('a: "' + chr(92) + 'b"', 1, "escape \\b is a control character"),
    ('a: "' + chr(92) + 'ud800"', 1, "control or invisible"),
    ("a: x" + chr(0x200C) + "y", 1, "U+200C"),
    ("a: x" + chr(0x061C) + "y", 1, "U+061C"),
    ("a: x" + chr(0x2060) + "y", 1, "U+2060"),
    ("a: - x", 1, "block sequence entry"),
    ("a: -", 1, "block sequence entry"),
    ("%YAML 1.2\n---\na: 1", 1, "unsupported"),
    ("a: 1\nb: 2\na: 3", 3, "duplicate key 'a'"),
    ("a: {b: 1, b: 2}", 1, "duplicate key 'b'"),
    ("a: b: c", 1, "':' inside a plain value"),
    ("a: [1,\n  2]", 1, "multi-line flow"),
    ("a: 'x\n  y'", 1, "multi-line scalars"),
    ("a: \"\\q\"", 1, "unsupported escape"),
    ("a: 1\n---\nb: 2", 2, "document markers"),
    ("a: 1\n...", 2, "document markers"),
    ("a:\n  - x\n  y: 1", 3, "bad indentation"),
    ("a: 1\n   b: 2", 2, "bad indentation"),
    ("  a: 1", 1, "must start at column 0"),
    ("key with space: 1", 1, "unsupported key"),
    ("a: [a: b]", 1, "expected ',' or ']'"),
    ("a: {b:c}", 1, "expected ': '"),
    ("a: [1, , 2]", 1, "empty value"),
    ("a: [1, 2,]", 1, "empty value"),
    ("a: \"x\" y", 1, "unexpected text after a quoted scalar"),
    ("a: [1] 2", 1, "unexpected text after a flow collection"),
    ("? a\n: 1", 1, "unsupported"),
    ("a\nb", 2, "unexpected content"),
]


@pytest.mark.parametrize("text, line, fragment", ERRORS)
def test_e1_outside_the_subset_is_an_error_with_a_line(text, line, fragment):
    with pytest.raises(yamlite.YamlError) as info:
        yamlite.loads(text)
    assert info.value.line == line
    assert fragment in str(info.value)
    assert str(info.value).startswith("line %d: " % line)


def test_e1_rule_file_error_names_file_and_line(tmp_path):
    path = tmp_path / "NET-X.yaml"
    path.write_text("id: NET-X\ntitle: t\nclass: NET\nseverity: yes\n")
    with pytest.raises(engine.RuleError) as info:
        engine.load_rule(path)
    assert str(info.value) == "%s: line 4: ambiguous plain scalar 'yes'; quote it" % path


# --- E2: rule schema -----------------------------------------------------------

def rule_doc(**changes):
    doc = {
        "id": "NET-TEST",
        "title": "Test rule",
        "class": "NET",
        "kind": "signature",
        "evasion": ["any program but Bash"],
        "severity": "medium",
        "fp_budget": 0.1,
        "match": {"field": "tool", "eq": "Bash"},
        "fixtures": {"positive": ["tests/fixtures/x.json"], "negative": ["tests/fixtures/y.json"]},
    }
    for key, value in changes.items():
        if value is DELETE:
            del doc[key]
        else:
            doc[key] = value
    return doc


DELETE = object()


@pytest.mark.parametrize("field", engine.REQUIRED)
def test_e2_missing_field_is_named(field):
    with pytest.raises(engine.RuleError, match=r"^src: %s: missing$" % field):
        engine.compile_rule(rule_doc(**{field: DELETE}), "src")


@pytest.mark.parametrize("change, field", [
    ({"severty": "low"}, "severty: unknown field"),
    ({"id": "net-tool"}, "id: must look like"),
    ({"id": "NETTOOL"}, "id: must look like"),
    ({"title": ""}, "title: must be a non-empty string"),
    ({"class": "NETWORK"}, "class: must be one of"),
    ({"severity": "critical"}, "severity: must be one of"),
    ({"fp_budget": 1.5}, "fp_budget: must be a number with 0 <= fp_budget < 1"),
    ({"fp_budget": 1}, "fp_budget"),
    ({"title": "Bad {tool}"}, "title: must not contain { or }"),
    ({"class": "SILENCE", "severity": "medium"}, "class SILENCE must be high"),
    ({"fp_budget": -0.1}, "fp_budget"),
    ({"fp_budget": True}, "fp_budget"),
    ({"fp_budget": "0.1"}, "fp_budget"),
    ({"status": "off"}, "status: must be one of"),
    ({"fixtures": {"positive": ["a"]}}, "fixtures: must have exactly positive and negative"),
    ({"fixtures": {"positive": [], "negative": ["a"]}}, "fixtures.positive: must be a non-empty list"),
    ({"fixtures": {"positive": ["a"], "negative": ["/etc/x"]}}, "fixtures.negative: '/etc/x' must be a relative"),
    ({"fixtures": {"positive": ["../x"], "negative": ["a"]}}, "fixtures.positive: '../x' must be a relative"),
    ({"aggregate": {"distinct": "input_meta.path"}}, "aggregate: must have distinct and over"),
    ({"aggregate": {"distinct": "a", "over": 1, "x": 1}}, "aggregate: must have distinct and over"),
    ({"aggregate": {"distinct": "a", "over": 1, "as": "text"}}, "aggregate.as: must be path"),
    ({"aggregate": {"distinct": "a", "over": 1, "cite": "some"}}, "aggregate.cite: must be all or first"),
    ({"aggregate": {"distinct": "Bad.Field", "over": 1}}, "aggregate.distinct"),
    ({"aggregate": {"distinct": "a", "over": -1}}, "aggregate.over"),
    ({"summary": "{Bad Name}"}, "summary: bad placeholder {Bad Name}"),
    ({"match": "tool == Bash"}, "match: a match node must be a mapping"),
    ({"match": {"all": []}}, "match.all: must be a non-empty list"),
    ({"match": {"all": [{"field": "tool"}]}}, "match.all[0]: a predicate needs field and exactly one of"),
    ({"match": {"field": "tool", "eq": "a", "ne": "b"}}, "a predicate needs field and exactly one"),
    ({"match": {"field": "tool", "like": "a"}}, "a predicate needs field and exactly one"),
    ({"match": {"field": "Tool", "eq": "a"}}, "match.field: must be a dotted path"),
    ({"match": {"field": "tool", "eq": ["a"]}}, "match.eq: must be a scalar"),
    ({"match": {"field": "tool", "in": []}}, "match.in: must be a non-empty list of scalars"),
    ({"match": {"field": "tool", "exists": "yes"}}, "match.exists: must be true or false"),
    ({"match": {"field": "tool", "nonempty": False}}, "match.nonempty: must be true"),
    ({"match": {"field": "tool", "regex": "("}}, "match.regex: bad regex"),
    ({"match": {"field": "tool", "prefix": ""}}, "match.prefix: must be a non-empty string"),
    ({"match": {"field": "input_meta.path", "outside": "/etc"}}, "match.outside: must name another field"),
    ({"match": {"field": "input_meta.path", "outside_any": "Scope"}}, "match.outside_any: must name a context key"),
    ({"match": {"any": [{"not": {"weird": 1}}]}}, "match.any[0].not: unknown match node"),
])
def test_e2_invalid_rule_names_the_field(change, field):
    with pytest.raises(engine.RuleError) as info:
        engine.compile_rule(rule_doc(**change), "src")
    assert str(info.value).startswith("src: ")
    assert field in str(info.value)


def test_e2_file_name_must_equal_id(tmp_path):
    path = tmp_path / "NET-OTHER.yaml"
    path.write_text((CATALOG / "NET-TOOL.yaml").read_text())
    with pytest.raises(engine.RuleError, match="must equal the file name 'NET-OTHER'"):
        engine.load_rule(path)


def test_e2_rule_file_must_be_a_mapping(tmp_path):
    path = tmp_path / "NET-X.yaml"
    path.write_text("- a\n")
    with pytest.raises(engine.RuleError, match="must hold a mapping"):
        engine.load_rule(path)


# --- E3: engine ----------------------------------------------------------------

def line(seq=1, phase="pre", tool="Bash", session="s1", cwd="/work/p", **meta):
    rec = {"ts": "2026-10-16T13:00:%02d.000Z" % seq, "seq": seq, "session_id": session,
           "phase": phase, "tool": tool, "input_meta": meta, "cwd": cwd}
    return rec


def rule_for(match, **changes):
    return engine.compile_rule(rule_doc(match=match, **changes), "test")


def matches(match, rec, context=None):
    return bool(engine.run_rule(rule_for(match), [rec], context or {}))


@pytest.mark.parametrize("match, rec, expected", [
    ({"field": "tool", "eq": "Bash"}, line(), True),
    ({"field": "tool", "eq": "Read"}, line(), False),
    ({"field": "input_meta.n", "eq": 1}, line(n=1.0), True),
    ({"field": "input_meta.n", "eq": 1}, line(n=True), False),
    ({"field": "input_meta.n", "eq": True}, line(n=1), False),
    ({"field": "input_meta.n", "eq": "1"}, line(n=1), False),
    ({"field": "input_meta.n", "eq": None}, line(n=None), True),
    ({"field": "input_meta.n", "eq": None}, line(), False),
    ({"field": "tool", "ne": "Read"}, line(), True),
    ({"field": "input_meta.x", "ne": "a"}, line(), False),
    ({"field": "tool", "in": ["Read", "Bash"]}, line(), True),
    ({"field": "input_meta.x", "in": ["a"]}, line(), False),
    ({"field": "tool", "not_in": ["Read"]}, line(), True),
    ({"field": "input_meta.x", "not_in": ["a"]}, line(), False),
    ({"field": "input_meta.x", "exists": True}, line(x="a"), True),
    ({"field": "input_meta.x", "exists": True}, line(x=None), False),
    ({"field": "input_meta.x", "exists": False}, line(), True),
    ({"field": "input_meta.x", "nonempty": True}, line(x=["a"]), True),
    ({"field": "input_meta.x", "nonempty": True}, line(x=[]), False),
    ({"field": "input_meta.x", "nonempty": True}, line(x=0), False),
    ({"field": "input_meta.command_head", "regex": "^rm$"}, line(command_head="rm"), True),
    ({"field": "input_meta.command_head", "regex": "^rm$"}, line(command_head="rmate"), False),
    ({"field": "input_meta.command_head", "regex": "rm"}, line(command_head=5), False),
    ({"field": "input_meta.path", "prefix": "/etc/"}, line(path="/etc/hosts"), True),
    ({"field": "input_meta.path", "glob": "*.pem"}, line(path="/x/key.pem"), True),
    ({"field": "input_meta.path", "glob": "*.PEM"}, line(path="/x/key.pem"), False),
    ({"not": {"field": "input_meta.x", "eq": "a"}}, line(), False),
    ({"not": {"field": "input_meta.x", "eq": "a"}}, line(x="b"), True),
    ({"field": "input_meta.x", "nonempty": True}, line(x={"k": 1}), True),
    ({"field": "input_meta.x", "nonempty": True}, line(x={}), False),
    ({"all": [{"field": "tool", "eq": "Bash"}, {"field": "phase", "eq": "pre"}]}, line(), True),
    ({"all": [{"field": "tool", "eq": "Bash"}, {"field": "phase", "eq": "post"}]}, line(), False),
    ({"any": [{"field": "tool", "eq": "Read"}, {"field": "phase", "eq": "pre"}]}, line(), True),
    ({"field": "input_meta", "exists": True}, line(), True),
    ({"field": "input_meta.path.deeper", "exists": True}, line(path="/x"), False),
])
def test_e3_predicates(match, rec, expected):
    assert matches(match, rec) is expected


OUTSIDE = {"field": "input_meta.path", "outside": "cwd"}


@pytest.mark.parametrize("path, cwd, expected", [
    ("/work/p/src/a.py", "/work/p", False),
    ("src/a.py", "/work/p", False),
    ("/work/p", "/work/p", False),
    ("/work/p/", "/work/p/", False),
    ("/work/p/src/../b", "/work/p", False),
    ("/work/p-secrets/a", "/work/p", True),
    ("/work/p/../q/a", "/work/p", True),
    ("../q/a", "/work/p", True),
    ("/etc/hosts", "/work/p", True),
    ("~/.ssh/id_rsa", "/work/p", True),
    ("/anything", "/", False),
    ("src/a.py", "relative/cwd", False),
    ("src/a.py", None, False),
    ("", "/work/p", False),
    ("//work/p/a", "/work/p", False),
    ("//etc/x", "/work/p", True),
])
def test_e3_outside(path, cwd, expected):
    assert matches(OUTSIDE, line(path=path, cwd=cwd)) is expected


SCOPE_RULE = {"all": [{"field": "phase", "eq": "pre"},
                      {"field": "input_meta.path", "outside_any": "scope"}]}


def test_e3_outside_any_uses_context_and_notes_when_missing():
    rule = rule_for(SCOPE_RULE)
    assert rule.context_keys == {"scope"}
    recs = [line(1, path="/work/p/src/a.py"), line(2, path="/work/p/docs/b.md"), line(3, path="tools/c.sh")]
    found, notes = engine.evaluate([rule], recs, {"scope": ["src", "/work/p/tools"]})
    assert [f["cited_seq"] for f in found] == [[2]] and notes == []
    found, notes = engine.evaluate([rule], recs)
    assert found == []
    assert notes == [{"rule_id": "NET-TEST", "status": "not-evaluated", "detail": "needs context: scope"}]
    found, notes = engine.evaluate([rule], recs, {"scope": "src"})
    assert found == []
    assert notes == [{"rule_id": "NET-TEST", "status": "not-evaluated",
                      "detail": "context scope must be a non-empty list of paths"}]


def test_e3_finding_shape_and_dedupe_per_seq():
    rule = rule_for({"field": "tool", "eq": "Bash"}, summary="{tool} {input_meta.command_head} seq {seq}")
    recs = [line(1, command_head="rm"), line(1, phase="post", command_head="rm")]
    found, notes = engine.evaluate([rule], recs)
    assert notes == []
    assert found == [{
        "ts": "2026-10-16T13:00:01.000Z", "rule_id": "NET-TEST", "class": "NET", "kind": "signature",
        "severity": "medium", "session_id": "s1", "cited_seq": [1], "summary": "Bash rm seq 1"}]


def test_e3_summary_rendering():
    rule = rule_for({"field": "tool", "eq": "Bash"},
                    summary="{input_meta.missing}|{input_meta.n}|{input_meta.weird}|{input_meta.long}")
    rec = line(1, n=[1, "a"], weird="a\nb\x1bc", long="x" * 100)
    (f,) = engine.run_rule(rule, [rec])
    assert f["summary"] == '-|[1, "a"]|a?b?c|' + "x" * 38 + "..." + "x" * 39
    assert engine.run_rule(rule_for({"field": "tool", "eq": "Bash"}), [rec])[0]["summary"] == "Test rule"


def test_e3_aggregate_counts_distinct_values_per_session():
    rule = rule_for({"field": "phase", "eq": "pre"},
                    aggregate={"distinct": "input_meta.path", "over": 2},
                    summary="{count} paths, last seq {seq}")
    recs = [line(1, path="a"), line(2, path="b"), line(3, path="a"), line(4, path=None),
            line(5, path="c"), line(5, phase="post", path="c"),
            line(1, session="s2", path="a"), line(2, session="s2", path="b")]
    found, _ = engine.evaluate([rule], recs)
    assert [(f["session_id"], f["cited_seq"], f["summary"]) for f in found] == [
        ("s1", [1, 2, 3, 5], "3 paths, last seq 5")]


def test_e3_disabled_rule_is_noted_not_run():
    rule = rule_for({"field": "tool", "eq": "Bash"}, status="disabled")
    found, notes = engine.evaluate([rule], [line()])
    assert found == []
    assert notes[0]["status"] == "disabled" and notes[0]["rule_id"] == "NET-TEST"
    assert engine.run_rule(rule, [line()])


def test_e3_findings_order_session_then_seq_then_rule():
    a = rule_for({"field": "tool", "eq": "Bash"}, id="AAA-ONE")
    b = rule_for({"field": "tool", "eq": "Bash"}, id="BBB-ONE")
    recs = [line(2, session="s2"), line(3), line(1), line(1, session="s2")]
    found, _ = engine.evaluate([b, a], recs)
    assert [(f["session_id"], f["cited_seq"][0], f["rule_id"]) for f in found] == [
        ("s2", 1, "AAA-ONE"), ("s2", 1, "BBB-ONE"), ("s2", 2, "AAA-ONE"), ("s2", 2, "BBB-ONE"),
        ("s1", 1, "AAA-ONE"), ("s1", 1, "BBB-ONE"), ("s1", 3, "AAA-ONE"), ("s1", 3, "BBB-ONE")]


@pytest.mark.parametrize("cited", [None, [], [True], ["1"], [1.0], "1"])
def test_e3_finding_without_cited_seq_is_rejected(cited):
    finding = {"ts": "t", "rule_id": "X-Y", "severity": "low", "session_id": "s",
               "summary": "x", "cited_seq": cited}
    with pytest.raises(engine.FindingError, match="A5"):
        engine.check_finding(finding)


def test_e3_finding_needs_rule_id_and_summary():
    good = {"ts": "t", "rule_id": "X-Y", "kind": "demand", "severity": "low", "session_id": "s",
            "summary": "x", "cited_seq": [1]}
    assert engine.check_finding(good) is good
    for key in ("rule_id", "severity", "session_id", "summary"):
        with pytest.raises(engine.FindingError):
            engine.check_finding(dict(good, **{key: ""}))


def test_e3_pure_no_io_no_mutation(monkeypatch):
    rules = engine.load_catalog(CATALOG)
    lines, _, _ = fixtures.load_fixture(RULE_FIXTURES / "SCOPE-PATH" / "positive-etc-and-dotdot.json")
    before = copy.deepcopy(lines)

    def no_io(*a, **k):
        raise AssertionError("evaluate() must not do I/O")

    monkeypatch.setattr(builtins, "open", no_io)
    found, notes = engine.evaluate(rules, lines)
    assert [f["rule_id"] for f in found] == ["SCOPE-PATH", "SCOPE-PATH"]
    assert notes == [{"rule_id": "DRIFT-FILES", "status": "not-evaluated",
                      "detail": "needs context: scope"}]
    assert lines == before
    assert engine.evaluate(rules, lines) == (found, notes)


def test_e3_engine_skips_uncitable_records_and_says_so():
    rule = rule_for({"field": "tool", "eq": "Bash"})
    bad = [{"tool": "Bash"}, {"seq": True, "session_id": "s", "tool": "Bash"}]
    assert engine.run_rule(rule, bad) == []
    found, notes = engine.evaluate([rule], bad + [line()])
    assert len(found) == 1
    assert notes == [{"rule_id": "*", "status": "skipped-lines",
                      "detail": "2 line(s) without session_id or int seq were not evaluated"}]


def test_a1_rules_never_reach_a_model_or_the_network():
    for path in (ROOT / "raqib" / "rules").glob("*.py"):
        text = path.read_text()
        for banned in ("urllib.request", "http.client", "socket", "subprocess", "raqib.suspect"):
            assert banned not in text, (path.name, banned)


# --- E4: fixture runner and the shipped catalog ---------------------------------

def test_m12_e1_rule_set_v1_ships():
    rules = engine.load_catalog(CATALOG)
    assert [(r.id, r.cls) for r in rules] == [
        ("DESTRUCT-CMD", "DESTRUCT"), ("DRIFT-FILES", "DRIFT"), ("NET-TOOL", "NET"),
        ("SCOPE-CWD-MOVED", "SCOPE"), ("SCOPE-CWD-ROOT", "SCOPE"),
        ("SCOPE-PATH", "SCOPE"), ("SECRET-OUTPUT", "SECRET")]


@pytest.mark.parametrize("report", fixtures.check_catalog(engine.load_catalog(CATALOG), ROOT, BENIGN),
                         ids=lambda r: r["rule_id"])
def test_e4_catalog_rule_passes_its_fixtures(report):
    assert report["positives"] and all(p["fired"] for p in report["positives"]), report
    assert len(report["negatives"]) >= 1 + len(BENIGN)
    assert report["verdict"] in ("ok", "disabled"), report
    assert report["measured"] >= 1
    assert report["fp_rate"] <= report["fp_budget"] or report["status"] == "disabled"


def test_e4_own_negatives_never_fire():
    for rule in engine.load_catalog(CATALOG):
        for path in rule.fixtures["negative"]:
            assert not fixtures.fires(rule, ROOT / path), (rule.id, path)


def test_e4_every_rule_fixture_file_is_referenced():
    referenced = {p for r in engine.load_catalog(CATALOG)
                  for kind in ("positive", "negative") for p in r.fixtures[kind]}
    on_disk = {p.relative_to(ROOT).as_posix() for p in RULE_FIXTURES.glob("*/*")
               if p.parent.name != "benign"}
    assert on_disk == referenced
    for p in referenced:
        name = Path(p).name
        assert Path(p).parts[3] in name or re.match(r"(positive|negative)-", name), p


def test_e4_runner_flags_over_budget_and_missed_positives(tmp_path):
    fires_on_all = rule_doc(match={"field": "seq", "exists": True}, fp_budget=0.5,
                            fixtures={"positive": ["p.json"], "negative": ["n1.json", "n2.json"]})
    for name in ("p.json", "n1.json", "n2.json"):
        (tmp_path / name).write_text(json.dumps([line()]))
    report = fixtures.check_rule(engine.compile_rule(fires_on_all), tmp_path)
    assert (report["verdict"], report["fp_rate"]) == ("over-budget", 1.0)
    report = fixtures.check_rule(engine.compile_rule(dict(fires_on_all, status="disabled")), tmp_path)
    assert report["verdict"] == "disabled"
    never = dict(fires_on_all, match={"field": "tool", "eq": "Nope"})
    report = fixtures.check_rule(engine.compile_rule(never), tmp_path)
    assert (report["verdict"], report["fp_rate"]) == ("positive-missed", 0.0)


def test_e4_fixture_formats(tmp_path):
    (tmp_path / "list.json").write_text(json.dumps([line()]))
    (tmp_path / "ctx.json").write_text(json.dumps({"context": {"scope": ["src"]}, "lines": [line()],
                                                   "expect_seq": [1]}))
    (tmp_path / "t.log").write_text(json.dumps(line()) + "\n")
    bad = {
        "extra.json": {"lines": [], "other": 1},
        "noseq.json": [dict(line(), seq="1")],
        "nots.json": [dict(line(), ts="yesterday")],
        "phase.json": [dict(line(), phase="pree")],
        "expect.json": {"lines": [line()], "expect_seq": []},
    }
    for name, data in bad.items():
        (tmp_path / name).write_text(json.dumps(data))
    (tmp_path / "corrupt.log").write_text("nope\n")
    assert fixtures.load_fixture(tmp_path / "list.json") == ([line()], {}, None)
    assert fixtures.load_fixture(tmp_path / "ctx.json") == ([line()], {"scope": ["src"]}, [1])
    assert fixtures.load_fixture(tmp_path / "t.log") == ([line()], {}, None)
    for name in list(bad) + ["corrupt.log", "missing.json"]:
        with pytest.raises(fixtures.FixtureError):
            fixtures.load_fixture(tmp_path / name)


# --- M1.2: SECRET-OUTPUT and DRIFT-FILES ------------------------------------

def catalog_rule(rule_id):
    (rule,) = [r for r in engine.load_catalog(CATALOG) if r.id == rule_id]
    return rule


def test_m12_e4_benign_corpus_has_a_scoped_session():
    contexts = [fixtures.load_fixture(p)[1] for p in BENIGN]
    assert any("scope" in c for c in contexts)


def edit(seq, path, session="s1", tool="Edit", ok=True):
    """A completed edit: DRIFT-FILES counts post lines with ok."""
    return dict(line(seq, phase="post", tool=tool, session=session, cwd="/work/p", path=path), ok=ok)


SCOPE = {"scope": ["src", "docs/review", "HANDOFF.md"]}


def drift(recs, context=SCOPE):
    return engine.evaluate([catalog_rule("DRIFT-FILES")], recs, context)


def test_m12_e3_drift_fires_on_the_third_distinct_file():
    recs = [edit(1, "/work/p/README.md"), edit(2, "/work/p/src/a.py"), edit(3, "setup.cfg"),
            edit(4, "/work/p/README.md"), edit(5, "/work/p/tools/x.sh", tool="Write")]
    assert drift(recs[:4]) == ([], [])
    found, notes = drift(recs)
    assert notes == [] and [f["cited_seq"] for f in found] == [[1, 3, 4, 5]]
    assert found[0]["summary"].startswith("3 distinct files edited outside the declared scope")


def test_m12_e3_drift_counts_only_edits_per_session():
    reads = [line(i, tool="Read", path="/work/p/x%d" % i) for i in range(1, 6)]
    split = [edit(1, "/a"), edit(2, "/b"), edit(1, "/c", session="s2"), edit(2, "/d", session="s2")]
    assert drift(reads) == ([], [])
    assert drift(split) == ([], [])


def test_m12_e3_drift_without_scope_is_not_evaluated():
    recs = [edit(i, "/x/%d" % i) for i in range(1, 5)]
    found, notes = drift(recs, context={})
    assert found == []
    assert notes == [{"rule_id": "DRIFT-FILES", "status": "not-evaluated", "detail": "needs context: scope"}]


def test_m12_e3_drift_scope_entries_are_paths_not_prefixes():
    recs = [edit(1, "/work/p/src2/a.py"), edit(2, "/work/p/srcfile.py"), edit(3, "/work/p/HANDOFF.md.bak")]
    found, _ = drift(recs)
    assert [f["cited_seq"] for f in found] == [[1, 2, 3]]


def test_m12_secret_output_fires_on_named_kinds_in_posts_only():
    rule = catalog_rule("SECRET-OUTPUT")
    post = line(1, phase="post")
    post["output_meta"] = {"secret_kinds": ["aws_access_key_id"]}
    pre = dict(post, phase="pre")
    empty = dict(post, output_meta={"secret_kinds": []})
    (f,) = engine.run_rule(rule, [post])
    assert (f["severity"], f["class"]) == ("high", "SECRET")
    assert f["summary"] == 'Bash output at seq 1 matched ["aws_access_key_id"]'
    assert engine.run_rule(rule, [pre, empty, line(2, phase="post")]) == []


def test_m12_secret_output_end_to_end_from_capture(tmp_path):
    import os
    import subprocess
    capture = ROOT / "raqib" / "hooks" / "capture.py"
    log = tmp_path / "trace.jsonl"
    hook = json.loads((ROOT / "tests" / "fixtures" / "posttooluse-bash.json").read_text())
    secret = "AKIA" + "Q3W8R5T1Y6U2P9Z4"  # assembled: no secret-like literal in the tree
    hook["tool_response"] = {"stdout": "aws_access_key_id = " + secret, "stderr": ""}
    env = dict(os.environ, RAQIB_LOG=str(log))
    subprocess.run([sys.executable, str(capture)], input=json.dumps(hook).encode(),
                   env=env, check=True, timeout=30)
    from raqib.rules import trace
    recs, problems = trace.read(log)
    assert problems == [] and secret not in log.read_text()
    found, _ = engine.evaluate(engine.load_catalog(CATALOG), recs)
    assert [(f["rule_id"], f["cited_seq"]) for f in found] == [("SECRET-OUTPUT", [1])]


# --- M1.1 REDO (docs/review/2026-10-16-M1.1.md) ------------------------------

def test_redo_three_valued_logic_and_partial_notes():
    unknown = rule_for({"not": {"field": "input_meta.x", "eq": "a"}})
    found, notes = engine.evaluate([unknown], [line(1), line(2, x="a"), line(3, x="b")])
    assert [f["cited_seq"] for f in found] == [[3]]
    assert notes[0]["status"] == "partial" and "could not judge 1 line(s) (session:seq s1:1)" in notes[0]["detail"]
    definite = rule_for({"all": [{"field": "phase", "eq": "post"}, {"field": "input_meta.x", "eq": "a"}]})
    assert engine.evaluate([definite], [line(1)]) == ([], [])
    either = rule_for({"any": [{"field": "tool", "eq": "Bash"}, {"field": "input_meta.x", "eq": "a"}]})
    assert len(engine.evaluate([either], [line(1)])[0]) == 1
    guarded = rule_for({"all": [{"field": "input_meta.path", "exists": True}, OUTSIDE]})
    assert engine.evaluate([guarded], [line(1)]) == ([], [])


def test_redo_unplaceable_paths_are_unknown_not_clean():
    found, notes = engine.evaluate([rule_for(OUTSIDE)], [line(1, path="a", cwd="relative")])
    assert found == [] and notes[0]["status"] == "partial"


def test_redo_scope_root_anchors_relative_entries():
    rule = rule_for(SCOPE_RULE)
    recs = [line(1, path="/work/p/src/a.py", cwd="/work/p/sub")]
    assert len(engine.evaluate([rule], recs, {"scope": ["src"]})[0]) == 1
    assert engine.evaluate([rule], recs, {"scope": ["src"], "root": "/work/p"}) == ([], [])
    found, notes = engine.evaluate([rule], recs, {"scope": ["src"], "root": "work/p"})
    assert len(found) == 1 and notes[0]["status"] == "bad-context"


@pytest.mark.parametrize("bad", ["src", [], [""], [None], None])
def test_redo_unusable_scope_is_not_evaluated(bad):
    found, notes = engine.evaluate([rule_for(SCOPE_RULE)], [line(1, path="/x")], {"scope": bad})
    assert found == [] and notes[0]["status"] == "not-evaluated"


def test_redo_catalog_must_exist_be_nonempty_and_use_yaml(tmp_path):
    with pytest.raises(engine.RuleError, match="not found"):
        engine.load_catalog(tmp_path / "nope")
    with pytest.raises(engine.RuleError, match="catalog is empty"):
        engine.load_catalog(tmp_path)
    shutil_copy = (CATALOG / "NET-TOOL.yaml").read_text()
    (tmp_path / "NET-TOOL.yml").write_text(shutil_copy)
    with pytest.raises(engine.RuleError, match="must end in .yaml: NET-TOOL.yml"):
        engine.load_catalog(tmp_path)


def test_redo_check_finding_checks_class_and_ts():
    good = {"ts": None, "rule_id": "X-Y", "class": "NET", "kind": "signature", "severity": "low",
            "session_id": "s", "summary": "x", "cited_seq": [1]}
    assert engine.check_finding(good) is good
    for bad in (dict(good, **{"class": "NETWORK"}), dict(good, ts=5)):
        with pytest.raises(engine.FindingError):
            engine.check_finding(bad)
    no_ts = dict(good)
    del no_ts["ts"]
    with pytest.raises(engine.FindingError):
        engine.check_finding(no_ts)


def test_redo_finding_ts_falls_back_to_last_valid_ts():
    rule = rule_for({"field": "input_meta.x", "eq": "a"})
    first = line(1)
    second = dict(line(2, x="a"), ts="not a time")
    (f,) = engine.run_rule(rule, [first, second])
    assert f["ts"] == first["ts"]


def test_redo_aggregate_paths_cite_first_and_unknown_values():
    rule = rule_for({"field": "phase", "eq": "pre"},
                    aggregate={"distinct": "input_meta.path", "over": 1, "as": "path", "cite": "first"})
    recs = [line(1, path="README.md"), line(2, path="./README.md"), line(3, path="/work/p/x/../README.md"),
            line(4, path="b.md"), line(5, path="b.md"), line(6)]
    found, notes = engine.evaluate([rule], recs)
    assert [f["cited_seq"] for f in found] == [[1, 4]]
    assert notes[0]["status"] == "partial" and "s1:6" in notes[0]["detail"]


def test_redo_runner_unmeasured_equal_budget_and_expected_seq(tmp_path):
    for name, data in {
        "p.json": {"lines": [line(1), line(2, x="hit")], "expect_seq": [2]},
        "p-miss.json": {"lines": [line(1, x="hit"), line(2)], "expect_seq": [1, 2]},
        "n1.json": [line(1, x="hit")],
        "n2.json": [line(1, x="miss")],
        "n3.json": [line(1)],
        "ctx.json": {"context": {"scope": ["src"]}, "lines": [line(1, path="/x")]},
    }.items():
        (tmp_path / name).write_text(json.dumps(data))
    hit = {"field": "input_meta.x", "eq": "hit"}
    doc = rule_doc(match=hit, fp_budget=0.5,
                   fixtures={"positive": ["p.json"], "negative": ["n1.json", "n2.json", "n3.json"]})
    report = fixtures.check_rule(engine.compile_rule(doc), tmp_path)
    assert (report["verdict"], report["fp_rate"], report["measured"], report["unmeasured"]) == ("ok", 0.5, 2, 1)
    doc_miss = dict(doc, fixtures={"positive": ["p-miss.json"], "negative": ["n2.json"]})
    report = fixtures.check_rule(engine.compile_rule(doc_miss), tmp_path)
    assert report["verdict"] == "positive-missed" and report["positives"][0]["missing_seq"] == [2]
    scoped = rule_doc(match=SCOPE_RULE, fixtures={"positive": ["ctx.json"], "negative": ["n2.json"]})
    report = fixtures.check_rule(engine.compile_rule(scoped), tmp_path)
    assert (report["verdict"], report["measured"], report["unmeasured"]) == ("unmeasured", 0, 1)


@pytest.mark.parametrize("rule_id, fixture, expected", [
    ("SCOPE-CWD-ROOT", "positive-root-and-home.json",
     [("fixture-rules-cwdroot-%d" % i, [1]) for i in (1, 2, 5, 6, 7, 8, 9, 10) + tuple(range(13, 21))]),
    ("SCOPE-CWD-MOVED", "positive-cd-out.json", [("fixture-rules-cwdmoved-1", [1, 3])]),
])
def test_redo_cwd_rules(rule_id, fixture, expected):
    lines, _, _ = fixtures.load_fixture(RULE_FIXTURES / rule_id / fixture)
    found, _ = engine.evaluate([catalog_rule(rule_id)], lines)
    assert [(f["session_id"], f["cited_seq"]) for f in found] == expected


def test_redo_drift_counts_completed_edits_by_placed_path():
    lines, ctx, _ = fixtures.load_fixture(RULE_FIXTURES / "DRIFT-FILES" / "negative-two-files.json")
    assert drift(lines, ctx) == ([], [])


# --- M1.1+M1.2 REDO 2 (docs/review/2026-10-16-M1.1-M1.2-REDO.md) ------------

def judged(match, rec, context=None):
    """(fired, unknown) of one rule on one line."""
    found, unknown = engine.judge(rule_for(match), [rec], context or {})
    return bool(found), bool(unknown)


@pytest.mark.parametrize("op", ["regex", "prefix", "glob"])
@pytest.mark.parametrize("value", [None, 7, ["a"]])
def test_redo2_string_tests_on_non_strings_are_unknown(op, value):
    rec = dict(line(1), input_meta={"x": value})
    pred = {"field": "input_meta.x", op: "a"}
    assert judged(pred, rec) == (False, True)
    assert judged({"not": pred}, rec) == (False, True)


def test_redo2_an_unplaceable_root_with_an_absolute_path_is_unknown():
    rec = line(1, tool="Edit", path="/work/p/src/a.py")
    pred = {"field": "input_meta.path", "outside_any": "scope"}
    assert judged(pred, rec, {"scope": ["src", ""]}) == (False, True)
    assert judged(pred, rec, {"scope": ["src", "lib"], "root": "relative/root"}) == (False, True)
    assert judged(pred, rec, {"scope": ["src"]}) == (False, False)
    other = dict(line(1), cwd="relative/cwd", input_meta={"path": "/etc/x", "root": "/work/p"})
    assert judged({"field": "input_meta.path", "outside": "input_meta.root"}, other) == (True, False)
    assert judged({"field": "input_meta.path", "outside": "input_meta.nothere"}, other) == (False, True)


def test_redo2_a_negative_that_fires_counts_even_with_unjudged_lines(tmp_path):
    rule = rule_for({"field": "input_meta.x", "eq": "bad"})
    lines = [dict(line(1), input_meta={"x": "bad"}), line(2)]
    path = tmp_path / "neg.json"
    path.write_text(json.dumps(lines))
    assert fixtures.outcome(rule, path) == (True, {1}, True)


@pytest.mark.parametrize("change, fragment", [
    (lambda r: r.update(tol="Bash"), "unknown field"),
    (lambda r: r.pop("tool"), "no tool"),
    (lambda r: r.pop("cwd"), "no cwd"),
    (lambda r: r.pop("input_meta"), "input_meta"),
    (lambda r: r.update(phase="post"), "ok"),
    (lambda r: r.update(output_meta=[]), "output_meta"),
], ids=["misspelled-key", "no-tool", "no-cwd", "no-input-meta", "post-without-ok", "bad-output-meta"])
def test_redo2_fixture_lines_must_have_the_capture_shape(tmp_path, change, fragment):
    rec = line(1)
    change(rec)
    path = tmp_path / "f.json"
    path.write_text(json.dumps([rec]))
    with pytest.raises(fixtures.FixtureError, match=fragment):
        fixtures.load_fixture(path)


def test_redo2_committed_rule_fixtures_are_what_the_generator_writes(tmp_path, monkeypatch):
    import runpy
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(RULE_FIXTURES / "generate.py"))
    made = sorted(p.relative_to(tmp_path) for p in (tmp_path / "tests").rglob("*.json"))
    assert made, "the generator wrote nothing"
    for rel in made:
        assert (tmp_path / rel).read_bytes() == (ROOT / rel).read_bytes(), rel
    committed = sorted(p.relative_to(ROOT) for p in RULE_FIXTURES.rglob("*.json"))
    assert made == committed


def test_redo2_scope_cwd_moved_summary_matches_its_citations():
    lines, _, _ = fixtures.load_fixture(RULE_FIXTURES / "SCOPE-CWD-MOVED" / "positive-cd-out.json")
    (f,) = engine.evaluate([catalog_rule("SCOPE-CWD-MOVED")], lines)[0]
    assert f["summary"] == "session ran in 2 working directories; each is cited where it first appears"
    assert f["cited_seq"] == [1, 3]


# --- M4.1 (ADR-0002): rule kinds ---------------------------------------------

from raqib.rules import silence  # noqa: E402

ADR = ROOT / "docs" / "specs" / "ADR-0002-rule-kinds.md"


def kind_doc(kind, **changes):
    """A rule of one kind: a signature keeps rule_doc's evasion list, a demand
    or an anchor has none."""
    doc = rule_doc(kind=kind, **changes)
    if kind != "signature" and "evasion" not in changes:
        del doc["evasion"]
    return doc


@pytest.mark.parametrize("kind", ["signature", "demand", "anchor"])
def test_m41_e1_the_three_valid_kinds_load_and_reach_their_findings(kind):
    rule = engine.compile_rule(kind_doc(kind), "src")
    assert rule.kind == kind
    assert rule.evasion == (("any program but Bash",) if kind == "signature" else ())
    (f,) = engine.run_rule(rule, [line()])
    assert f["kind"] == kind and engine.check_finding(f) is f


ONE_OF = "must be one of signature|demand|anchor, not "
NOT_A_LIST = "must be a non-empty list of one-line strings, not "
NOT_A_LINE = "must be a non-empty one-line string of printable characters, not "


@pytest.mark.parametrize("change, message", [
    # 1. no kind
    ({"kind": DELETE}, "kind: missing; every rule declares one of signature|demand|anchor (ADR-0002)"),
    # 2. a kind that is not one of the three
    ({"kind": "heuristic"}, "kind: " + ONE_OF + "'heuristic'"),
    ({"kind": "Signature"}, "kind: " + ONE_OF + "'Signature'"),
    ({"kind": None}, "kind: " + ONE_OF + "None"),
    ({"kind": ["signature"]}, "kind: " + ONE_OF + "['signature']"),
    # 3. a signature without evasion, or with evasion of another shape
    ({"evasion": DELETE}, "evasion: missing; a signature must list its known evasions, one line each"
                          " (ADR-0002: a signature with no listed evasion is invalid)"),
    ({"evasion": []}, "evasion: " + NOT_A_LIST + "[]"),
    ({"evasion": None}, "evasion: " + NOT_A_LIST + "None"),
    ({"evasion": "python urllib"}, "evasion: " + NOT_A_LIST + "'python urllib'"),
    ({"evasion": ["bash -c", ""]}, "evasion[1]: " + NOT_A_LINE + "''"),
    ({"evasion": ["   "]}, "evasion[0]: " + NOT_A_LINE + "'   '"),
    ({"evasion": ["two\nlines"]}, "evasion[0]: " + NOT_A_LINE + "'two\\nlines'"),
    ({"evasion": ["a\tb"]}, "evasion[0]: " + NOT_A_LINE + "'a\\tb'"),
    ({"evasion": [7]}, "evasion[0]: " + NOT_A_LINE + "7"),
    ({"evasion": [["nested"]]}, "evasion[0]: " + NOT_A_LINE + "['nested']"),
    # 4. evasion on a demand or an anchor
    ({"kind": "demand"}, "evasion: only a signature lists evasions; kind demand must not have one (ADR-0002)"),
    ({"kind": "anchor", "evasion": []},
     "evasion: only a signature lists evasions; kind anchor must not have one (ADR-0002)"),
    ({"kind": "anchor", "evasion": None},
     "evasion: only a signature lists evasions; kind anchor must not have one (ADR-0002)"),
], ids=["no-kind", "unknown-kind", "kind-case", "kind-null", "kind-list",
        "signature-no-evasion", "evasion-empty", "evasion-null", "evasion-string", "evasion-empty-line",
        "evasion-blank-line", "evasion-two-lines", "evasion-tab", "evasion-not-a-string", "evasion-nested",
        "demand-with-evasion", "anchor-with-empty-evasion", "anchor-with-null-evasion"])
def test_m41_e1_any_other_shape_is_an_error_naming_the_rule_and_field(change, message):
    with pytest.raises(engine.RuleError) as info:
        engine.compile_rule(rule_doc(**change), "src")
    assert str(info.value) == "src: rule NET-TEST: " + message


def test_m41_e1_a_rule_file_without_kind_names_file_rule_and_field(tmp_path):
    path = tmp_path / "NET-TOOL.yaml"
    text = (CATALOG / "NET-TOOL.yaml").read_text()
    path.write_text("".join(x for x in text.splitlines(True) if not x.startswith("kind:")))
    with pytest.raises(engine.RuleError) as info:
        engine.load_rule(path)
    assert str(info.value).startswith("%s: rule NET-TOOL: kind: missing" % path)
    (tmp_path / "catalog").mkdir()
    (tmp_path / "catalog" / "NET-TOOL.yaml").write_text(path.read_text())
    with pytest.raises(engine.RuleError, match="rule NET-TOOL: kind: missing"):
        engine.load_catalog(tmp_path / "catalog")


def test_m41_e1_a_bad_id_is_reported_before_the_kind():
    with pytest.raises(engine.RuleError) as info:
        engine.compile_rule(rule_doc(id="net-test", kind=DELETE), "src")
    assert str(info.value).startswith("src: id: must look like")


def adr_table():
    """(rows, section) of ADR-0002's classification table: rows maps a rule id
    to (kind, the items of its evasion column split on ';', [] for '-')."""
    text = ADR.read_text(encoding="utf-8")
    section = text.split("\n## Classification", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for row in section.splitlines():
        if not row.startswith("|"):
            continue
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if cells[0] == "rule" or set(cells[0]) <= set("-"):
            continue
        rule_id, kind, evasion = cells
        rows[rule_id] = (kind, [] if evasion == "-" else [e.strip() for e in evasion.split(";")])
    return rows, section


def test_m41_e2_every_rule_carries_the_kind_and_evasion_of_the_adr_table():
    table, section = adr_table()
    rules = {r.id: r for r in engine.load_catalog(CATALOG)}
    assert len(table) == 11 and set(table) == set(rules) | set(silence.RULE_KINDS)
    for rule_id, (kind, items) in table.items():
        if rule_id in silence.RULE_KINDS:
            assert (silence.RULE_KINDS[rule_id], items) == (kind, []), rule_id
            continue
        rule = rules[rule_id]
        assert rule.kind == kind, rule_id
        (CATALOG / (rule_id + ".yaml")).read_bytes().decode("ascii")   # ASCII-safe
        if kind == "signature":
            # The table's evasions are the minimum: each starts one line of the list.
            assert items and all(any(e.startswith(item) for e in rule.evasion) for item in items), rule_id
            assert len(set(rule.evasion)) == len(rule.evasion), rule_id
        else:
            assert rule.evasion == () and "evasion" not in rule.doc, rule_id
            for item in items:  # an anchor's hole is written in its description
                assert item.startswith("hole: ") and "Bash are not seen" in rule.doc["description"], rule_id
    counts = [sum(1 for k, _ in table.values() if k == kind) for kind in engine.KINDS]
    assert "Ratio today: %d : %d : %d." % tuple(counts) in section
    tree = [r.kind for r in rules.values()] + list(silence.RULE_KINDS.values())
    assert counts == [tree.count(kind) for kind in engine.KINDS] == [4, 4, 3]


def test_m41_e3_every_catalog_finding_carries_its_rule_kind():
    for rule in engine.load_catalog(CATALOG):
        for rel in rule.fixtures["positive"]:
            lines, ctx, _ = fixtures.load_fixture(ROOT / rel)
            found = engine.run_rule(rule, lines, ctx)
            assert found and all(f["kind"] == rule.kind for f in found), (rule.id, rel)


def test_m41_e3_check_finding_rejects_an_unknown_kind():
    good = {"ts": None, "rule_id": "X-Y", "class": "NET", "severity": "low", "session_id": "s",
            "summary": "x", "cited_seq": [1]}
    for kind in engine.KINDS:
        finding = dict(good, kind=kind)
        assert engine.check_finding(finding) is finding
    for bad in ("heuristic", "", None, ["signature"], 1):
        with pytest.raises(engine.FindingError, match="unknown kind"):
            engine.check_finding(dict(good, kind=bad))
    # B-3 (K5), inverted: a finding without a kind is rejected as NoKindError,
    # which the report raises as a no-kind alarm (A3).
    with pytest.raises(engine.NoKindError, match="finding has no kind"):
        engine.check_finding(good)
    assert issubclass(engine.NoKindError, engine.FindingError)
    # Any other fault is reported first: NoKindError means sound but for its kind.
    with pytest.raises(engine.FindingError) as info:
        engine.check_finding(dict(good, cited_seq=[]))
    assert type(info.value) is engine.FindingError


# --- M4.1 REDO (ADR-0002 Amendment B): B-4 evasion lines, B-5 known holes -----

def load_capture():
    import importlib.util
    spec = importlib.util.spec_from_file_location("raqib_capture_for_rules", ROOT / "raqib" / "hooks" / "capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evasion_line(rule_id, start):
    (found,) = [e for e in catalog_rule(rule_id).evasion if e.startswith(start)]
    return found


def test_m41_b4_secret_output_placeholder_marker_evasion_is_real():
    """K6: a real key with a placeholder marker glued into the match lands in
    placeholder_kinds, which SECRET-OUTPUT does not read."""
    capture = load_capture()
    line_text = evasion_line("SECRET-OUTPUT", "glue a placeholder marker into the match")
    assert "placeholder_kinds" in line_text and "which no rule reads" in line_text
    key = "s" + "k-" + "Q7w3Rt9Yp2Lm5Nb8Vc4X"          # assembled: no secret-like literal in the tree
    assert capture.scan_output([{"stdout": key}]) == (["sk_api_key"], [], True)
    for glued in (key + "_test", key + "-example", key + "test"):
        assert capture.scan_output([{"stdout": glued}]) == ([], ["sk_api_key"], True), glued
    rule = catalog_rule("SECRET-OUTPUT")
    post = dict(line(1, phase="post"), output_meta={"scan": "full", "secret_kinds": [],
                                                    "placeholder_kinds": ["sk_api_key"]})
    assert engine.judge(rule, [post]) == ([], [])
    assert all("placeholder_kinds" not in json.dumps(r.doc["match"]) for r in engine.load_catalog(CATALOG))


def test_m41_b4_secret_output_scan_budget_line_is_exact():
    """K9: the budget is SCAN_MAX_CHARS over all strings of tool_response and
    error, keys included, each costing its length plus 1, in document order."""
    capture = load_capture()
    assert capture.SCAN_MAX_CHARS == 1048576
    assert ("1048576 characters over all strings of tool_response and error (keys too, each its length + 1,"
            " in order)") in evasion_line("SECRET-OUTPUT", "put it past capture's scan budget")
    key = "s" + "k-" + "Q7w3Rt9Yp2Lm5Nb8Vc4XzK6Hj"   # 25 after sk-: still a key when cut by one
    # Strings in document order: key "a" (1 + 1), the filler (n + 1), key "b" (1 + 1), then the secret.
    def meta(n):
        return capture.output_meta({"tool_response": {"a": "x" * n, "b": key}})
    exact = capture.SCAN_MAX_CHARS - 2 - 1 - 2 - len(key)
    assert meta(exact) == {"scan": "full", "secret_kinds": ["sk_api_key"]}               # fits exactly
    assert meta(exact + 1) == {"scan": "partial", "secret_kinds": ["sk_api_key"]}        # cut by one character
    past = meta(capture.SCAN_MAX_CHARS - 3)                                              # nothing left for it
    assert past == {"scan": "partial"}
    found, unknown = engine.judge(catalog_rule("SECRET-OUTPUT"), [dict(line(1, phase="post"), output_meta=past)])
    assert (found, unknown) == ([], [("s1", 1)])       # only a partial note, never a finding


def test_m41_b4_scope_path_pattern_only_location_is_not_judged():
    """K7: Glob or Grep with the location only in pattern or glob gives no
    input_meta.path, so SCOPE-PATH does not apply (not even unknown)."""
    capture = load_capture()
    assert "Glob or Grep with the location only in pattern or glob" in evasion_line("SCOPE-PATH", "Glob or Grep")
    for tool, tool_input in (("Glob", {"pattern": "/etc/*"}), ("Grep", {"pattern": "key", "glob": "/etc/**"})):
        meta = capture.input_meta(tool, tool_input)
        assert meta == {}, (tool, meta)
        rec = dict(line(1, tool=tool), input_meta=meta)
        assert engine.judge(catalog_rule("SCOPE-PATH"), [rec]) == ([], [])
    aimed = dict(line(1, tool="Glob"), input_meta=capture.input_meta("Glob", {"pattern": "*", "path": "/etc"}))
    assert len(engine.run_rule(catalog_rule("SCOPE-PATH"), [aimed])) == 1


def test_m41_b4_amendment_a_counts_the_lines_added_beyond_the_table():
    note = ADR.read_text(encoding="utf-8").split("Note (2026-11-03, M4.1 REDO, B-4", 1)[1].split("\n- A-3", 1)[0]
    added = dict((rule_id, int(n)) for rule_id, n in re.findall(r"([A-Z]+-[A-Z]+) \+(\d+)", " ".join(note.split())))
    table, _ = adr_table()
    signatures = {r.id: r for r in engine.load_catalog(CATALOG) if r.kind == "signature"}
    assert added == {rule_id: len(rule.evasion) - len(table[rule_id][1]) for rule_id, rule in signatures.items()}
    assert '"programs not on the list" is a NET-TOOL line only' in " ".join(note.split())
    assert not any("programs not on the list" in e or e.startswith("a program not on the list")
                   for e in catalog_rule("DESTRUCT-CMD").evasion)
    assert any(e.startswith("a network program not on the list") for e in catalog_rule("NET-TOOL").evasion)


def test_m41_b5_k16_holes_are_written_in_the_anchor_descriptions():
    drift = catalog_rule("DRIFT-FILES").doc["description"]
    assert ("Known hole: the scope is read from HANDOFF.md in the working tree, which the agent can edit,"
            " not from a commit.") in drift
    root = catalog_rule("SCOPE-CWD-ROOT").doc["description"]
    assert "Known holes: the list omits other broad directories such as /etc, /usr and /var" in root
    assert "a nested session, one the agent starts itself, chooses its own cwd" in root
    rule = catalog_rule("SCOPE-CWD-ROOT")
    for cwd in ("/etc", "/usr", "/var"):     # the hole, as the match block has it
        assert engine.run_rule(rule, [line(1, cwd=cwd)]) == [], cwd
