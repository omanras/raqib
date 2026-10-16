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
BENIGN = fixtures.benign_corpus(RULE_FIXTURES / "benign") + [
    str(ROOT / "tests" / "fixtures" / "quickstart-claude-code-2.1.301.log"),
    str(ROOT / "tests" / "fixtures" / "blocked-calls-claude-code-2.1.301.log"),
]

try:
    import yaml
except ImportError:  # the cross-check is optional; raqib itself is stdlib-only
    yaml = None


# --- E1: YAML subset ---------------------------------------------------------

DOCS = [
    "a: 1\nb: -2.5\nc: ~\nd:\ne: true\nf: 'x # not a comment'  # a comment\n"
    "g: \"\\u0041\\n\\t\"\nh: [1, [2, 3], {k: v}]\ni: {}\nj: []\nk: .5\nl: +7\nm: False\n",
    "- a\n- - b\n  - c\n- k: v\n  l: w\n-\n  m: n\n",
    "a:\n- 1\n- x: [a, 'b']\n  y:\n  - z\nb: ''\nc: \"it's\"\nd: it's fine\n",
    "---\n# leading comment\nkey/with.dots-and_under: \"v\"\n'quoted key': 1\n",
    "a: {b: {c: [1, {d: null}]}, e: \"x, y\"}\nf: [\"a]b\", 'c}d']\n",
    "a: http://example.org/x?y=1#frag\nb: -rf\nc: 3.0\nd: x:y\n",
]


@pytest.mark.parametrize("text", DOCS + [p.read_text() for p in sorted(CATALOG.glob("*.yaml"))])
def test_e1_subset_agrees_with_pyyaml(text):
    if yaml is None:
        pytest.skip("PyYAML not installed")
    assert yamlite.loads(text) == yaml.safe_load(text)


def test_e1_values():
    assert yamlite.loads(DOCS[0]) == {
        "a": 1, "b": -2.5, "c": None, "d": None, "e": True, "f": "x # not a comment",
        "g": "A\n\t", "h": [1, [2, 3], {"k": "v"}], "i": {}, "j": [], "k": 0.5, "l": 7, "m": False}
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
    ("a: &x 1", 1, "unsupported YAML feature starting with '&'"),
    ("a: *x", 1, "unsupported YAML feature starting with '*'"),
    ("a: !!str 1", 1, "unsupported YAML feature starting with '!'"),
    ("a: |\n  t", 1, "unsupported YAML feature starting with '|'"),
    ("a: >\n  t", 1, "unsupported YAML feature starting with '>'"),
    ("%YAML 1.2\n---\na: 1", 1, "unsupported"),
    ("a: 1\nb: 2\na: 3", 3, "duplicate key 'a'"),
    ("a: {b: 1, b: 2}", 1, "duplicate key 'b'"),
    ("a: b: c", 1, "':' inside a plain value"),
    ("a: [1,\n  2]", 1, "multi-line flow"),
    ("a: 'x\n  y'", 1, "multi-line scalars"),
    ("a: \"\\q\"", 1, "unsupported escape"),
    ("a: 1\n---\nb: 2", 2, "multiple documents"),
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
    ({"fp_budget": 1.5}, "fp_budget: must be a number from 0 to 1"),
    ({"fp_budget": -0.1}, "fp_budget"),
    ({"fp_budget": True}, "fp_budget"),
    ({"fp_budget": "0.1"}, "fp_budget"),
    ({"status": "off"}, "status: must be one of"),
    ({"fixtures": {"positive": ["a"]}}, "fixtures: must have exactly positive and negative"),
    ({"fixtures": {"positive": [], "negative": ["a"]}}, "fixtures.positive: must be a non-empty list"),
    ({"fixtures": {"positive": ["a"], "negative": ["/etc/x"]}}, "fixtures.negative: '/etc/x' must be a relative"),
    ({"fixtures": {"positive": ["../x"], "negative": ["a"]}}, "fixtures.positive: '../x' must be a relative"),
    ({"aggregate": {"distinct": "input_meta.path"}}, "aggregate: must have exactly distinct and over"),
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
    ({"not": {"field": "input_meta.x", "eq": "a"}}, line(), True),
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
    found, _ = engine.evaluate([rule], recs, {"scope": "src"})
    assert found == []


def test_e3_finding_shape_and_dedupe_per_seq():
    rule = rule_for({"field": "tool", "eq": "Bash"}, summary="{tool} {input_meta.command_head} seq {seq}")
    recs = [line(1, command_head="rm"), line(1, phase="post", command_head="rm")]
    found, notes = engine.evaluate([rule], recs)
    assert notes == []
    assert found == [{
        "ts": "2026-10-16T13:00:01.000Z", "rule_id": "NET-TEST", "class": "NET",
        "severity": "medium", "session_id": "s1", "cited_seq": [1], "summary": "Bash rm seq 1"}]


def test_e3_summary_rendering():
    rule = rule_for({"field": "tool", "eq": "Bash"},
                    summary="{input_meta.missing}|{input_meta.n}|{input_meta.weird}|{input_meta.long}")
    rec = line(1, n=[1, "a"], weird="a\nb\x1bc", long="x" * 100)
    (f,) = engine.run_rule(rule, [rec])
    assert f["summary"] == '-|[1, "a"]|a?b?c|' + "x" * 77 + "..."
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
    good = {"ts": "t", "rule_id": "X-Y", "severity": "low", "session_id": "s",
            "summary": "x", "cited_seq": [1]}
    assert engine.check_finding(good) is good
    for key in ("rule_id", "severity", "session_id", "summary"):
        with pytest.raises(engine.FindingError):
            engine.check_finding(dict(good, **{key: ""}))


def test_e3_pure_no_io_no_mutation(monkeypatch):
    rules = engine.load_catalog(CATALOG)
    lines, _ = fixtures.load_fixture(RULE_FIXTURES / "SCOPE-PATH" / "positive-etc-and-dotdot.json")
    before = copy.deepcopy(lines)

    def no_io(*a, **k):
        raise AssertionError("evaluate() must not do I/O")

    monkeypatch.setattr(builtins, "open", no_io)
    found, notes = engine.evaluate(rules, lines)
    assert [f["rule_id"] for f in found] == ["SCOPE-PATH", "SCOPE-PATH"] and notes == []
    assert lines == before
    assert engine.evaluate(rules, lines) == (found, notes)


def test_e3_engine_skips_uncitable_records():
    rule = rule_for({"field": "tool", "eq": "Bash"})
    assert engine.run_rule(rule, [{"tool": "Bash"}, {"seq": True, "session_id": "s", "tool": "Bash"}]) == []


def test_a1_rules_never_reach_a_model_or_the_network():
    for path in (ROOT / "raqib" / "rules").glob("*.py"):
        text = path.read_text()
        for banned in ("urllib.request", "http.client", "socket", "subprocess", "raqib.suspect"):
            assert banned not in text, (path.name, banned)


# --- E4: fixture runner and the shipped catalog ---------------------------------

def test_e4_three_rules_ship():
    rules = engine.load_catalog(CATALOG)
    assert [r.id for r in rules] == ["DESTRUCT-CMD", "NET-TOOL", "SCOPE-PATH"]


@pytest.mark.parametrize("report", fixtures.check_catalog(engine.load_catalog(CATALOG), ROOT, BENIGN),
                         ids=lambda r: r["rule_id"])
def test_e4_catalog_rule_passes_its_fixtures(report):
    assert report["positives"] and all(p["fired"] for p in report["positives"]), report
    assert len(report["negatives"]) >= 1 + len(BENIGN)
    assert report["verdict"] in ("ok", "disabled"), report
    assert report["fp_rate"] <= report["fp_budget"] or report["status"] == "disabled"


def test_e4_own_negatives_never_fire():
    for rule in engine.load_catalog(CATALOG):
        for path in rule.fixtures["negative"]:
            assert not fixtures.fires(rule, ROOT / path), (rule.id, path)


def test_e4_every_rule_fixture_file_is_referenced():
    referenced = {p for r in engine.load_catalog(CATALOG)
                  for kind in ("positive", "negative") for p in r.fixtures[kind]}
    on_disk = {str(p.relative_to(ROOT)) for p in RULE_FIXTURES.glob("*/*")
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
    (tmp_path / "ctx.json").write_text(json.dumps({"context": {"scope": ["src"]}, "lines": [line()]}))
    (tmp_path / "bad.json").write_text(json.dumps({"lines": []}))
    (tmp_path / "t.log").write_text(json.dumps(line()) + "\n")
    (tmp_path / "corrupt.log").write_text("nope\n")
    assert fixtures.load_fixture(tmp_path / "list.json") == ([line()], {})
    assert fixtures.load_fixture(tmp_path / "ctx.json") == ([line()], {"scope": ["src"]})
    assert fixtures.load_fixture(tmp_path / "t.log") == ([line()], {})
    for name in ("bad.json", "corrupt.log", "missing.json"):
        with pytest.raises(fixtures.FixtureError):
            fixtures.load_fixture(tmp_path / name)
