"""M4.2b (ADR-0002 Amendments D and G; docs/review/2026-11-03-M4.2b-ruling.md):
E1 the `require:` construct, `under_any` and `holes:`; E2 command_scripts,
commit_prefix and the command_head fix (E-12) in common.py; E3 LANDED-NO-GATE;
E4 EDIT-NO-TEST; E5 the counts and the docs. Every behaviour has a test (D-8)."""
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, eval as evaluation  # noqa: E402
from raqib.hooks import capture, common  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
CAPTURE = ROOT / "raqib" / "hooks" / "capture.py"
README = (ROOT / "README.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
EVIDENCE = ["pytest", "python", "python3", "gate.sh", "gate.py"]


def catalog_rule(rule_id):
    (rule,) = [r for r in engine.load_catalog(CATALOG) if r.id == rule_id]
    return rule


def doc(**changes):
    base = {"id": "DRIFT-TEST", "title": "Test demand", "class": "DRIFT", "kind": "demand", "severity": "medium",
            "fp_budget": 0.1, "match": {"field": "tool", "eq": "Edit"},
            "fixtures": {"positive": ["tests/x.json"], "negative": ["tests/y.json"]}}
    base.update(changes)
    return {k: v for k, v in base.items() if v is not None}


def rec(seq, phase="post", tool="Bash", session="s1", cwd="/work/p", ok=True, **meta):
    line = {"ts": "2026-11-03T10:00:%02d.000Z" % seq, "seq": seq, "session_id": session, "phase": phase,
            "tool": tool, "cwd": cwd}
    if phase in ("pre", "post"):
        line["input_meta"] = meta
    if phase == "post" and ok is not None:
        line["ok"] = ok
    return line


def call(seq, tool="Bash", session="s1", ok=True, post=True, **meta):
    """A pre line and (unless post is False) its post line."""
    out = [rec(seq, "pre", tool, session, **meta)]
    if post:
        out.append(rec(seq, "post", tool, session, ok=ok, **meta))
    return out


def event(seq, phase, session="s1"):
    return rec(seq, phase, "-", session)


BEFORE = engine.compile_rule(doc(
    match={"all": [{"field": "phase", "eq": "post"}, {"field": "tool", "eq": "Bash"},
                   {"field": "ok", "eq": True}, {"field": "input_meta.mark", "exists": True},
                   {"field": "input_meta.mark", "eq": "T"}]},
    require={"before": {"all": [{"field": "phase", "eq": "post"}, {"field": "ok", "eq": True},
                                {"field": "input_meta.evidence", "exists": True},
                                {"field": "input_meta.evidence", "eq": True}]}},
    summary="trigger at seq {seq}"), "before")
AFTER = engine.compile_rule(doc(
    match={"all": [{"field": "phase", "eq": "post"}, {"field": "ok", "eq": True},
                   {"field": "tool", "eq": "Edit"}]},
    require={"after": {"all": [{"field": "phase", "eq": "post"}, {"field": "tool", "eq": "Bash"},
                               {"field": "ok", "eq": True}, {"field": "input_meta.evidence", "exists": True},
                               {"field": "input_meta.evidence", "eq": True}]},
             "until": {"field": "phase", "in": ["stop", "session_end"]}},
    summary="{count} trigger(s) before the {phase} at seq {seq}"), "after")


def cited(rule, lines, context=None):
    found, unknown = engine.judge(rule, lines, context)
    return [(f["session_id"], f["cited_seq"]) for f in found], unknown


# --- E1: schema ---------------------------------------------------------------------------

@pytest.mark.parametrize("changes, message", [
    ({"kind": "signature", "evasion": ["x"], "require": {"before": {"field": "seq", "exists": True}}},
     "require: only a demand requires evidence on another line (ADR-0002 Amendment D); kind signature"),
    ({"kind": "anchor", "require": {"before": {"field": "seq", "exists": True}}},
     "require: only a demand requires evidence on another line (ADR-0002 Amendment D); kind anchor"),
    ({"require": {"before": {"field": "seq", "exists": True}}, "aggregate": {"distinct": "seq", "over": 1}},
     "require: never together with aggregate"),
    ({"require": {}}, "require: must be {before: <node>} or {after: <node>, until: <node>}"),
    ({"require": {"after": {"field": "seq", "exists": True}}}, "require: must be {before"),
    ({"require": {"until": {"field": "seq", "exists": True}}}, "require: must be {before"),
    ({"require": {"before": {"field": "seq", "exists": True}, "after": {"field": "seq", "exists": True}}},
     "require: must be {before"),
    ({"require": [{"before": {}}]}, "require: must be {before"),
    ({"require": {"before": {"field": "seq"}}}, "require.before: a predicate needs field and exactly one"),
    ({"require": {"after": {"field": "seq", "exists": True}, "until": {"all": []}}},
     "require.until.all: must be a non-empty list"),
], ids=["on-signature", "on-anchor", "with-aggregate", "empty", "after-alone", "until-alone", "both-shapes",
        "a-list", "bad-before-node", "bad-until-node"])
def test_e1_require_is_demand_only_never_with_aggregate_and_of_two_shapes(changes, message):
    with pytest.raises(engine.RuleError) as info:
        engine.compile_rule(doc(**changes), "src")
    assert message in str(info.value), str(info.value)


def test_e1_both_require_shapes_load_and_compile():
    assert set(BEFORE.require) == {"before"} and set(AFTER.require) == {"after", "until"}
    assert engine.compile_rule(doc(), "src").require is None
    assert "require" in engine.OPTIONAL and engine.REQUIRE_SHAPES == ({"before"}, {"after", "until"})


@pytest.mark.parametrize("kind", ["demand", "anchor"])
def test_e1_holes_are_allowed_on_demands_and_anchors(kind):
    rule = engine.compile_rule(doc(kind=kind, holes=["one hole", "another hole"]), "src")
    assert rule.holes == ("one hole", "another hole") and rule.evasion == ()
    assert engine.compile_rule(doc(kind=kind), "src").holes == ()


@pytest.mark.parametrize("changes, message", [
    ({"kind": "signature", "evasion": ["x"], "holes": ["y"]},
     "holes: only a demand or an anchor lists holes; a signature lists them as evasion"),
    ({"holes": []}, "holes: must be a non-empty list of one-line strings, not []"),
    ({"holes": "a hole"}, "holes: must be a non-empty list of one-line strings"),
    ({"holes": None}, None),
    ({"holes": ["two\nlines"]}, "holes[0]: must be a non-empty one-line string"),
    ({"holes": ["ok", 7]}, "holes[1]: must be a non-empty one-line string"),
    ({"holes": ["  "]}, "holes[0]: must be a non-empty one-line string"),
], ids=["on-signature", "empty", "a-string", "null-is-absent", "two-lines", "not-a-string", "blank"])
def test_e1_holes_have_the_shape_of_evasion(changes, message):
    if message is None:   # doc() drops a None value: no holes key at all
        assert engine.compile_rule(doc(**changes), "src").holes == ()
        return
    with pytest.raises(engine.RuleError) as info:
        engine.compile_rule(doc(**changes), "src")
    assert str(info.value).startswith("src: rule DRIFT-TEST: " + message.split(":")[0]), str(info.value)
    assert message in str(info.value)


def test_e1_a_holes_key_set_to_null_is_an_error():
    with pytest.raises(engine.RuleError, match="holes: must be a non-empty list"):
        engine.compile_rule(dict(doc(), holes=None), "src")


# --- E1: under_any ------------------------------------------------------------------------

UNDER = engine.compile_rule(doc(match={"field": "input_meta.path", "under_any": ["raqib", "tests"]}), "under")


@pytest.mark.parametrize("path, cwd, context, expected", [
    ("/work/p/raqib/a.py", "/work/p", {}, True),
    ("/work/p/tests", "/work/p", {}, True),                       # the directory itself
    ("raqib/rules/engine.py", "/work/p", {}, True),               # relative: joined to the cwd
    ("/work/p/src/a.py", "/work/p", {}, False),
    ("/work/p/raqib-notes/a.md", "/work/p", {}, False),           # a sibling with the same prefix
    ("/work/p/raqib/../src/a.py", "/work/p", {}, False),          # normalised lexically
    ("/elsewhere/raqib/a.py", "/work/p", {}, False),
    ("/work/root/tests/a.py", "/work/p", {"root": "/work/root"}, True),   # entries placed at context root
    ("/work/p/tests/a.py", "/work/p", {"root": "/work/root"}, False),
    ("C:\\proj\\Tests\\a.py", "c:/PROJ", {}, True),               # Windows paths, as everywhere (M5.1b)
    ("raqib/a.py", "relative/cwd", {}, None),                     # cannot be placed: unknown
    ("/work/p/raqib/a.py", None, {}, None),                       # no cwd to place the entries
])
def test_e1_under_any_places_its_entries_like_outside_any(path, cwd, context, expected):
    line = rec(1, "pre", "Edit", cwd=cwd, path=path)
    if cwd is None:
        del line["cwd"]
    assert UNDER.match(line, context) is expected


def test_e1_under_any_takes_a_literal_list_of_paths():
    for arg in ([], "raqib", ["raqib", ""], [1], None):
        with pytest.raises(engine.RuleError, match="match.under_any: must be a non-empty list of paths"):
            engine.compile_rule(doc(match={"field": "input_meta.path", "under_any": arg}), "src")
    assert "under_any" in engine.OPS and UNDER.context_keys == set()
    assert UNDER.match(rec(1, "pre", "Edit"), {}) is None   # no path: unknown, as outside_any


# --- E1: require before ---------------------------------------------------------------------

def test_e1_before_fires_on_a_trigger_with_no_evidence_on_or_before_it():
    lines = [event(1, "session_start")] + call(2, mark="T")
    assert cited(BEFORE, lines) == ([("s1", [2])], [])
    (f,) = engine.judge(BEFORE, lines)[0]
    assert f["ts"] == "2026-11-03T10:00:02.000Z" and f["summary"] == "trigger at seq 2" and f["kind"] == "demand"


@pytest.mark.parametrize("lines", [
    call(1, evidence=True) + call(2, mark="T"),                           # earlier
    call(1, mark="T", evidence=True),                                     # the same line
    call(1, evidence=True) + call(2) + call(3, mark="T"),                 # earlier, with lines between
], ids=["earlier", "same-line", "earlier-with-lines-between"])
def test_e1_before_evidence_on_or_before_the_trigger_satisfies_it(lines):
    assert cited(BEFORE, lines) == ([], [])


def test_e1_before_later_or_other_session_or_failed_evidence_does_not_count():
    lines = (call(1, evidence=True, session="other") + call(1, mark="T") + call(2, evidence=True)
             + call(3, evidence=True, ok=False, session="s2") + call(4, mark="T", session="s2"))
    assert cited(BEFORE, lines) == ([("s1", [1]), ("s2", [4])], [])


def test_e1_before_unknown_evidence_makes_the_trigger_unknown_never_a_finding():
    unknown_ev = rec(1, "post", ok=None, evidence=True)   # a post with no ok: `ok eq true` cannot be judged
    lines = [rec(1, "pre", evidence=True), unknown_ev] + call(2, mark="T")
    assert cited(BEFORE, lines) == ([], [("s1", 2)])
    found, notes = engine.evaluate([BEFORE], lines)
    assert found == [] and [n["status"] for n in notes] == ["partial"]
    assert notes[0]["detail"] == "could not judge 1 line(s) (session:seq s1:2 (evidence unknown))"   # H-3
    # Evidence that is true anywhere before wins over evidence that is unknown.
    assert cited(BEFORE, call(1, evidence=True) + [rec(2, "pre", evidence=True), rec(2, "post", ok=None, evidence=True)]
                 + call(3, mark="T")) == ([], [])


def test_e1_before_a_trigger_that_cannot_be_judged_is_unknown():
    lines = [rec(1, "pre", mark="T"), rec(1, "post", ok=None, mark="T")]
    assert cited(BEFORE, lines) == ([], [("s1", 1)])


def test_e1_g7_a_pre_with_no_post_stands_for_its_missing_post():
    """A trigger whose post never came is unknown (SILENCE-HALF's fact); a pre
    whose post came later is judged as a pre only."""
    assert cited(BEFORE, call(1, mark="T", post=False)) == ([], [("s1", 1)])
    assert cited(BEFORE, call(1, evidence=True, post=False) + call(2, mark="T")) == ([], [("s1", 2)])
    assert cited(BEFORE, call(1, mark="T")) == ([("s1", [1])], [])
    # The ghost is phase post with no ok; a node it cannot match keeps the line false.
    ghosts = engine._ghosts(call(1, post=False) + call(2) + [event(3, "stop")])
    assert ghosts[0] == {k: v for k, v in dict(call(1)[0], phase="post").items()}
    assert ghosts[1:] == [None, None, None]


# --- E1: require after / until --------------------------------------------------------------

def test_e1_after_fires_at_the_deadline_citing_the_triggers_and_the_deadline():
    lines = [event(1, "session_start")] + call(2, "Edit") + call(3, "Edit") + [event(4, "stop")]
    assert cited(AFTER, lines) == ([("s1", [2, 3, 4])], [])
    (f,) = engine.judge(AFTER, lines)[0]
    assert f["ts"] == "2026-11-03T10:00:04.000Z" and f["summary"] == "2 trigger(s) before the stop at seq 4"


def test_e1_after_evidence_between_trigger_and_deadline_discharges_it():
    assert cited(AFTER, call(1, "Edit") + call(2, evidence=True) + [event(3, "stop")]) == ([], [])
    # Evidence before the trigger, or a failed run, is no evidence.
    lines = call(1, evidence=True) + call(2, "Edit") + call(3, evidence=True, ok=False) + [event(4, "session_end")]
    assert cited(AFTER, lines) == ([("s1", [2, 4])], [])


def test_e1_after_each_trigger_is_judged_at_its_first_deadline_only():
    lines = (call(1, "Edit") + [event(2, "stop")] + call(3, evidence=True) + [event(4, "stop")]
             + call(5, "Edit") + call(6, evidence=True) + call(7, "Edit") + [event(8, "session_end")])
    assert cited(AFTER, lines) == ([("s1", [1, 2]), ("s1", [7, 8])], [])


def test_e1_after_a_deadline_that_never_comes_is_unknown():
    lines = call(1, "Edit") + call(2, "Edit")
    assert cited(AFTER, lines) == ([], [("s1", 1), ("s1", 2)])
    assert cited(AFTER, call(1, "Edit") + [event(1, "stop", session="other")]) == ([], [("s1", 1)])


def test_e1_after_unknown_evidence_covers_only_the_triggers_before_it():
    lines = call(1, "Edit") + [rec(2, "pre", evidence=True), rec(2, "post", ok=None, evidence=True)] + call(3, "Edit") + [event(4, "stop")]
    assert cited(AFTER, lines) == ([("s1", [3, 4])], [("s1", 1)])
    # Later true evidence discharges them all.
    lines = call(1, "Edit") + [rec(2, "pre", evidence=True), rec(2, "post", ok=None, evidence=True)] + call(3, evidence=True) + [event(4, "stop")]
    assert cited(AFTER, lines) == ([], [])


def test_e1_after_an_unknown_deadline_makes_the_triggers_before_it_unknown():
    rule = engine.compile_rule(doc(match=AFTER.doc["match"], require={
        "after": AFTER.doc["require"]["after"], "until": {"field": "input_meta.close", "eq": True}}), "u")
    lines = call(1, "Edit") + [event(2, "stop")]          # a stop line has no input_meta: unknown
    assert cited(rule, lines) == ([], [("s1", 1)])


def test_e1_after_an_edit_whose_post_never_came_is_unknown():
    assert cited(AFTER, call(1, "Edit", post=False) + [event(2, "stop")]) == ([], [("s1", 1)])


def test_e1_require_rules_and_plain_rules_side_by_side():
    plain = engine.compile_rule(doc(match={"field": "tool", "eq": "Edit"}, kind="anchor"), "plain")
    lines = call(1, "Edit") + [event(2, "stop")]
    found, notes = engine.evaluate([plain, AFTER], lines)
    assert [(f["rule_id"], f["cited_seq"]) for f in found] == [("DRIFT-TEST", [1]), ("DRIFT-TEST", [1, 2])]
    assert notes == []


# --- E2: command_scripts (G-2, G-9) ------------------------------------------------------------

SCRIPTS = [
    ("bash tools/gate.sh", ["gate.sh"]),
    ("sh tools/x.sh", ["x.sh"]),
    ("python -I tools/gate.py", ["gate.py"]),
    ("python3 tools/gate.py --rule-kinds-child", ["gate.py"]),
    ("python -W ignore -X dev tools/gate.py", ["gate.py"]),
    ("python3 -Wignore -Xdev x.py", ["x.py"]),
    ("python3 -IB x.py", ["x.py"]),
    ("python3 --check-hash-based-pycs never x.py", ["x.py"]),
    ("python3 -- x.py", ["x.py"]),
    ("bash -e -o pipefail x.sh", ["x.sh"]),
    ("bash +O extglob x.sh", ["x.sh"]),
    ("bash --rcfile rc.sh x.sh", ["x.sh"]),
    ("bash --norc x.sh", ["x.sh"]),
    ("bash - x.sh", ["x.sh"]),
    ("bash -- x.sh", ["x.sh"]),
    # G-2: -c and -m (python), -c and -s (bash, sh) mean no script; the .py/.sh word is data.
    ("python3 -c 'pass' gate.py", []),
    ("python3 -Ic 'pass' gate.py", []),
    ("python3 -m pytest tests/test_report.py", []),
    ("python3 -m pyflakes raqib/hooks/common.py", []),
    ("python3 - x.py", []),
    ("bash -c 'true' gate.sh", []),
    ("bash -lc 'true' gate.sh", []),
    ("sh -c 'exit 0' tools/gate.sh", []),
    ("bash -s gate.sh", []),
    # The operand is the first non-option word: a later .py/.sh word is its argument.
    ("python3 tool x.py", []),
    ("bash script gate.sh", []),
    ("python3 x.txt", []),
    ("python3 $S x.py", []),
    ("python3 \"$S\".py", []),
    # Only python, python3, bash and sh; wrappers and other names are not read.
    ("python3.12 x.py", []),
    ("zsh x.sh", []),
    ("./tools/gate.sh", []),
    # Every simple command the reader reads, each name once.
    ("cd x && python3 tools/gate.py 2>&1 | tail -5", ["gate.py"]),
    ("bash -c 'python3 tools/gate.py'", ["gate.py"]),
    ("echo $(bash tools/v.sh)", ["v.sh"]),
    ("bash a.sh; python3 b.py; bash a.sh", ["a.sh", "b.py"]),
    ("time python3 x.py", ["x.py"]),
    # H-1: split on / and \ (an unquoted backslash is kept for the name), the Windows names,
    # timeout/nohup/env one level, . and source.
    ("python -I tools\\gate.py", ["gate.py"]),
    ("python3 'tools\\gate.py'", ["gate.py"]),
    ("python3 \"tools\\gate.py\"", ["gate.py"]),
    ("bash C:\\proj\\tools\\gate.sh", ["gate.sh"]),
    ("py -I tools\\gate.py", ["gate.py"]),
    ("py -3.12 tools/gate.py", ["gate.py"]),
    ("py.exe -3 tools\\gate.py", ["gate.py"]),
    ("python.exe tools/gate.py", ["gate.py"]),
    ("timeout 900 tools/gate.sh", ["gate.sh"]),
    ("timeout 900 ./tools\\gate.sh", ["gate.sh"]),
    ("timeout -k 5 -s KILL 900 python3 tools/gate.py", ["gate.py"]),
    ("timeout --preserve-status --signal=TERM 9 bash x.sh", ["x.sh"]),
    ("timeout 9 x.txt", []),
    ("timeout $T x.sh", []),
    ("nohup tools/gate.sh", ["gate.sh"]),
    ("nohup -- bash x.sh", ["x.sh"]),
    ("env python3 x.py", ["x.py"]),
    ("env x.py", ["x.py"]),
    ("env A=1 python3 x.py", []),                 # env with an assignment: not read (H-1)
    ("env -i python3 x.py", []),                  # env with an option: not read
    ("timeout 5 nohup x.sh", []),                 # one level only
    ("timeout 9 env python3 x.py", []),
    (". ./env.sh", ["env.sh"]),
    (". -- tools/a.sh", ["a.sh"]),
    ("source tools/x.sh && pytest", ["x.sh"]),
    ("source venv/bin/activate", []),              # a sourced file is a script when it ends .sh
    ("sudo python3 x.py", []),                     # other wrappers stay unread (D-9)
    # Basename only, under the name rules of a program.
    ("python3 /opt/deep/path/x.py", ["x.py"]),
    ("python3 ./-x.py", []),
    ("python3 caf\u00e9.py", []),
]


@pytest.mark.parametrize("command, expected", SCRIPTS, ids=[c for c, _ in SCRIPTS])
def test_e2_command_scripts_is_the_script_operand_only(command, expected):
    assert common.command_scripts(command) == expected
    meta = common.input_meta("Bash", {"command": command})
    assert meta.get("command_scripts", []) == expected and (("command_scripts" in meta) == bool(expected))   # G-9


def test_e2_command_scripts_absent_when_the_command_is_unread_and_capped():
    assert common.command_scripts("for f in *; do bash $f; done") is None
    many = "; ".join("python3 s%d.py" % i for i in range(common.SCRIPTS_MAX))
    assert common.command_scripts(many) == ["s%d.py" % i for i in range(common.SCRIPTS_MAX)]
    over = many + "; python3 s%d.py" % common.SCRIPTS_MAX
    assert common.read_command(over) is None and common.command_programs(over) is None
    assert common.input_meta("Bash", {"command": over}) == {"command_head": "python3", "command_unread": True}


# --- E2: commit_prefix (G-3, G-4) ---------------------------------------------------------------

HEREDOC = "git commit -m \"$(cat <<'EOF'\nlanded: M4.2b x\n\nCo-Authored-By: a <b@c>\nEOF\n)\""
COMMITS = [
    # The forms read (G-4).
    ("git commit -m 'landed: M4.2b x'", "landed:"),
    ("git commit -m landed:", "landed:"),
    ("git commit -mlanded:", "landed:"),
    ("git commit '-mlanded: x'", "landed:"),
    ("git commit --message='landed: x'", "landed:"),
    ("git commit --message 'landed: x'", "landed:"),
    ("git commit -am 'landed: x'", "landed:"),
    ("git commit -avm 'landed: x'", "landed:"),
    ("git commit -amlanded:", "landed:"),
    ("git -C /work/raqib commit -m 'landed: x'", "landed:"),
    ("git -c user.name=x --no-pager --git-dir=/x/.git commit -m 'landed: x'", "landed:"),
    ("git --work-tree /x commit -m 'landed: x'", "landed:"),
    ("/usr/bin/git commit -m 'landed: x'", "landed:"),
    ("git commit -t tmpl --author 'A <a@b>' --no-edit -m 'landed: x'", "landed:"),
    ("git commit -m 'landed: x' -m 'body'", "landed:"),
    # H-4: the first NON-EMPTY -m; --no-message is not read (a listed hole).
    ("git commit -m '' -m 'landed: x'", "landed:"),
    ("git commit -m '   ' --message='landed: x'", "landed:"),
    ("git commit -m \"$(cat <<'EOF'\n\nEOF\n)\" -m 'landed: x'", "landed:"),
    ("git commit -m 'wip' -m 'landed: x'", None),
    ("git commit -m \"$X\" -m 'landed: x'", None),
    ("git commit -m ''", None),
    ("git commit -m wip --no-message -m 'landed: x'", None),
    ("git commit -m 'landed: x' --no-message -m wip", "landed:"),
    ("git commit -m '  landed: x'", "landed:"),
    ("git commit -m 'landed: x' -- $FILES", "landed:"),
    ("git commit -m \"landed: $(date)\"", "landed:"),
    ("tools/gate.sh && git commit -m 'landed: x'", "landed:"),
    ("git log -1 && git commit -m 'landed: x'", "landed:"),
    ("git add -A && git commit -m 'wip: x'", "wip:"),
    # Here-documents with a quoted delimiter, read statically (G-4).
    (HEREDOC, "landed:"),
    ("git commit -m \"$(cat <<\"EOF\"\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit -m \"$(cat <<\\EOF\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit -m \"$(cat <<-'EOF'\n\t\n\tlanded: x\n\tEOF\n)\"", "landed:"),
    ("git commit -m \"$(cat <<'EOF'\n\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit -m\"$(cat <<'EOF'\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit -am\"$(cat <<'EOF'\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit --message=\"$(cat <<'EOF'\nlanded: x\nEOF\n)\"", "landed:"),
    ("git commit --message=\"landed: $X\"", "landed:"),
    ("git commit \"$A\"-m 'landed: x'", None),
    # Not read: absent (G-4, listed in the rule's holes).
    ("git commit --amend -m 'landed: x'", None),
    ("git commit -m 'landed: x' --amend", None),
    ("git commit -F msg.txt", None),
    ("git commit --file=msg.txt", None),
    ("git commit -C HEAD", None),
    ("git commit -c HEAD", None),
    ("git commit --reuse-message=HEAD", None),
    ("git commit -m \"$(cat <<EOF\nlanded: x\nEOF\n)\"", None),          # an unquoted delimiter
    ("git commit -m \"$(cat <<'EOF' | tr a b\nlanded: x\nEOF\n)\"", None),
    ("git commit -m \"$(cat <<'EOF'\nlanded: x\nEOF\n) more\"", None),
    ("git commit -m \"$MSG\"", None),
    ("git commit -m \"$X landed: x\"", None),
    ("git commit -m landed:*", None),
    ("git commit $OPTS -m 'landed: x'", None),
    ("git commit -m", None),
    ("git commit", None),
    ("git commit -m wip --allow-empty && git commit -m 'landed: x'", None),   # the first commit only
    ("git merge -m 'landed: x' topic", None),
    ("git commit-tree -m 'landed: x' HEAD^{tree}", None),
    ("sudo git commit -m 'landed: x'", None),
    ("git $SUB -m 'landed: x'", None),
    ("for f in a; do git commit -m 'landed: x'; done", None),                # the command is not read
    # G-3: only a lower-case word ending in ":" of at most 16 characters.
    ("git commit -m 'STOP: M4.2b x'", None),
    ("git commit -m 'Landed: x'", None),
    ("git commit -m 'landed:x'", None),
    ("git commit -m 'landed x'", None),
    ("git commit -m 'abcdefghijklmno:'", "abcdefghijklmno:"),
    ("git commit -m 'abcdefghijklmnop:'", None),
    ("git commit -m 'l4nded: x'", None),
    ("git commit -m 'sk-ant-abcdefghijklmnopqrstuvwxyz: x'", None),
]


@pytest.mark.parametrize("command, expected", COMMITS, ids=[c[:60] for c, _ in COMMITS])
def test_e2_commit_prefix_forms(command, expected):
    assert common.commit_prefix(command) == expected
    meta = common.input_meta("Bash", {"command": command})
    assert meta.get("commit_prefix") == expected and (("commit_prefix" in meta) == (expected is not None))


def test_e2_commit_prefix_constants_are_the_rulings():
    assert common.COMMIT_PREFIX.pattern == r"[a-z]+:\Z" and common.COMMIT_PREFIX_MAX == 16   # G-3
    assert common.PYTHONS == ("python", "python3", "python.exe", "py", "py.exe")               # G-2, H-1
    assert common.C_SHELLS == ("bash", "sh") and common.SCRIPT_WRAPPERS == ("timeout", "nohup", "env")
    assert set(common.COMMIT_NOT_READ) == {"--amend", "--file", "--reuse-message", "--reedit-message"}


# --- E2: command_head's leading redirection (E-12) ------------------------------------------------

@pytest.mark.parametrize("command, head", [
    ("2>/dev/null rm x", "rm"),
    ("2> /dev/null rm x", "rm"),
    (">out echo hi", "echo"),
    ("&>log curl x", "curl"),
    ("&>> log curl x", "curl"),
    (">| f rm x", "rm"),
    ("<> f cat", "cat"),
    ("<&3 cat", "cat"),
    ("2>&1 ls", "ls"),
    ("<<< 'x' cat", "cat"),
    ("A=1 2>/dev/null B=2 rm", "rm"),
    ('>"a file" rm x', "rm"),
    (">$LOG rm x", "rm"),
    (">", None),
    ("2>", None),
    (">$(rm x) ls", None),
    (">a;b ls", None),
    (">`x` ls", None),
    ("2 >x ls", "2"),          # 2 apart from > is the program
    ("ls 2>/dev/null", "ls"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_e2_e12_command_head_skips_leading_redirections(command, head):
    assert common.command_head(command) == head


# --- E2: input_meta, capture's re-export, the hook end to end ---------------------------------------

def test_e2_new_keys_only_when_there_is_one_so_old_shapes_are_byte_for_byte():
    assert common.input_meta("Bash", {"command": "ls -la /etc"}) == {"command_head": "ls", "command_programs": ["ls"]}
    assert common.input_meta("Bash", {"command": "bash -c 'rm x'"}) == {
        "command_head": "bash", "command_programs": ["bash", "rm"]}
    assert list(common.input_meta("Bash", {"command": HEREDOC + " && bash tools/gate.sh"})) == [
        "command_head", "command_programs", "command_scripts", "commit_prefix"]
    for tool in ("Read", "Write", "mcp__shell__run"):
        meta = common.input_meta(tool, {"command": "bash tools/gate.sh && git commit -m 'landed: x'"})
        assert "command_scripts" not in meta and "commit_prefix" not in meta


def test_e2_capture_re_exports_the_new_names_and_the_proxy_shares_them():
    for name in ("read_command", "command_scripts", "commit_prefix", "COMMIT_PREFIX", "SCRIPTS_MAX",
                 "HEREDOC_MESSAGE", "HEAD_TARGET_STOP"):
        assert name in common.__all__ and getattr(capture, name) is getattr(common, name), name
    from raqib.hooks import proxy
    assert proxy.common is common and capture.input_meta is common.input_meta


def test_e2_the_reader_stays_pure_and_the_new_code_is_inside_the_checked_body():
    source = (ROOT / "raqib" / "hooks" / "common.py").read_text(encoding="utf-8")
    body = source.split("def command_programs(", 1)[1].split("\ndef input_meta(", 1)[0]
    for name in ("def read_command(", "class _Operand:", "class _Wrapped:", "class _Commit:",
                 "def _heredoc_message("):
        assert name in body, name
    for banned in ("subprocess", "os.system", "os.popen", "exec(", "eval(", "shlex.split", "open("):
        assert banned not in body, banned


def run_hook(payloads, log, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RAQIB_")}
    for payload in payloads:
        proc = subprocess.run([sys.executable, "-I", str(CAPTURE), str(log)], input=json.dumps(payload).encode(),
                              capture_output=True, env=env, cwd=cwd, timeout=30)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b""), proc
    return [json.loads(x) for x in Path(log).read_text(encoding="utf-8").splitlines()]


def payload(event, cwd, session="close-shape", **extra):
    return dict({"session_id": session, "transcript_path": "/tmp/t.jsonl", "cwd": str(cwd),
                 "hook_event_name": event}, **extra)


def tool(event, cwd, name, tool_input, use_id, **extra):
    return payload(event, cwd, tool_name=name, tool_input=tool_input, tool_use_id=use_id, **extra)


def test_e2_the_hook_writes_the_new_keys_and_no_other_argument_text(tmp_path):
    secret = "/srv/private-%s" % "q7w8e9r0"
    command = ("cd %s && python3 -I %s/tools/gate.py --flag && git commit -m \"$(cat <<'EOF'\nlanded: M9 %s\n"
               "\nbody words here\nEOF\n)\"" % (secret, secret, "subject-words"))
    recs = run_hook([tool("PreToolUse", tmp_path, "Bash", {"command": command}, "toolu_1")], tmp_path / "t.jsonl",
                    tmp_path)
    assert recs[0]["input_meta"] == {"command_head": "cd", "command_programs": ["cd", "python3", "git", "cat"],
                                     "command_scripts": ["gate.py"], "commit_prefix": "landed:"}
    text = (tmp_path / "t.jsonl").read_text(encoding="utf-8")
    for fragment in (secret, "q7w8e9r0", "--flag", "subject-words", "body words", "M9", "tools/"):
        assert fragment not in text, fragment
    assert text.count('"commit_prefix":"landed:"}') == 1   # the new key ends input_meta, nothing after it


# --- E3 / E4: the two rules -------------------------------------------------------------------------

def test_e3_e4_the_rules_declare_kind_severity_holes_and_require():
    landed, edit = catalog_rule("LANDED-NO-GATE"), catalog_rule("EDIT-NO-TEST")
    assert (landed.kind, landed.severity, landed.cls) == ("demand", "high", "DRIFT")
    assert (edit.kind, edit.severity, edit.cls) == ("demand", "medium", "DRIFT")
    assert set(landed.require) == {"before"} and set(edit.require) == {"after", "until"}
    assert landed.evasion == () == edit.evasion and len(landed.holes) == 12 and len(edit.holes) == 11
    flat = " ".join(landed.holes)
    for hole in ("a stale gate", "||", "| tail -5", "run_in_background", "basenames", "--amend", "post line never"):
        assert hole in flat, hole   # G-5
    assert landed.fp_budget == 0.05 and edit.fp_budget == 0.1
    assert edit.doc["match"]["all"][2] == {"field": "tool", "in": ["Edit", "Write", "MultiEdit", "NotebookEdit"]}
    assert edit.doc["match"]["all"][4] == {"field": "input_meta.path", "under_any": ["raqib", "tests"]}   # G-10
    assert edit.doc["require"]["until"] == {"field": "phase", "in": ["stop", "session_end"]}
    for rule, names in ((landed, ["gate.sh", "gate.py"]), (edit, EVIDENCE)):
        (branches,) = [p["any"] for p in rule.doc["require"]["before" if rule is landed else "after"]["all"]
                       if "any" in p]
        fields = [[q["field"] for q in b["all"]] for b in branches]
        assert fields == [["input_meta.command_programs"] * 2, ["input_meta.command_scripts"] * 2,
                          ["input_meta.command_programs", "input_meta.command_head"]]   # G-8 fallback last
        assert all(b["all"][-1].get("has_any", b["all"][-1].get("in")) == names for b in branches)


def fixture_findings(rule_id, name):
    lines, ctx, expect = fixtures.load_fixture(ROOT / "tests" / "fixtures" / "rules" / rule_id / name)
    found, unknown = engine.judge(catalog_rule(rule_id), lines, ctx)
    return [(f["session_id"], f["cited_seq"]) for f in found], unknown, expect


def test_e3_landed_no_gate_fixtures_both_ways():
    found, unknown, expect = fixture_findings("LANDED-NO-GATE", "positive-landings.json")
    assert found == [("fixture-rules-landed-1", [3]), ("fixture-rules-landed-2", [3]),
                     ("fixture-rules-landed-3", [3]), ("fixture-rules-landed-5", [2])] and unknown == []
    assert expect == [2, 3]
    # negatives: the && same line, a stale gate, python -I tools/gate.py, a piped gate (a hole), a
    # line before M4.2 (G-8), and commits that are no landing (wip:, failed, STOP:, --amend, merge);
    # the Windows forms (H-1, H-8): python -I tools\gate.py, timeout 900 tools/gate.sh,
    # py -I tools\gate.py and python.exe ... && git commit on one line, under cwd C:\proj.
    assert fixture_findings("LANDED-NO-GATE", "negative-gated.json")[:2] == ([], [])
    assert fixture_findings("LANDED-NO-GATE", "negative-windows.json")[:2] == ([], [])
    lines, _, _ = fixtures.load_fixture(ROOT / "tests" / "fixtures" / "rules" / "LANDED-NO-GATE" / "negative-windows.json")
    assert all(r["cwd"] == "C:\\proj" for r in lines)
    assert [r["input_meta"].get("command_scripts") for r in lines if r["phase"] == "pre"] == [
        ["gate.py"], None, ["gate.sh"], None, ["gate.py"], None, ["gate.py"]]


def test_e3_landed_no_gate_cases():
    rule = catalog_rule("LANDED-NO-GATE")
    meta = lambda c: common.input_meta("Bash", {"command": c})   # noqa: E731
    commit = meta(HEREDOC)
    gate_and_commit = meta("tools/gate.sh && git commit -m 'landed: x'")
    assert gate_and_commit["command_programs"] == ["gate.sh", "git"] and gate_and_commit["commit_prefix"] == "landed:"
    assert cited(rule, call(1, **gate_and_commit)) == ([], [])                       # && on the same line
    assert cited(rule, call(1, **meta("tools/gate.sh")) + call(2, "Edit", path="/work/p/raqib/a.py")
                 + call(3, **commit)) == ([], [])                                    # a stale gate (G-5)
    assert cited(rule, call(1, **meta("python3 -c 'pass' gate.py")) + call(2, **commit)) == ([("s1", [2])], [])
    assert cited(rule, call(1, **meta("tools/gate.sh"), ok=False) + call(2, **commit)) == ([("s1", [2])], [])
    assert cited(rule, call(1, **commit, ok=False)) == ([], [])                      # a failed commit
    assert cited(rule, call(1, **commit, post=False)) == ([], [("s1", 1)])           # G-7: no post line
    assert cited(rule, call(1, command_head="gate.sh") + call(2, **commit)) == ([], [])   # G-8 head fallback
    assert cited(rule, call(1, command_head="gate.py", command_programs=["ls"]) + call(2, **commit)) == (
        [("s1", [2])], [])                                                           # programs win over the head
    assert cited(rule, call(1, command_unread=True) + call(2, **commit)) == ([], [("s1", 2)])   # no head: unknown
    assert cited(rule, call(1, **meta("bash tools/gate.sh")) + call(2, **commit)) == ([], [])  # scripts (G-2)
    assert cited(rule, call(1, **meta("git commit -m 'STOP: x'"))) == ([], [])


def test_e4_edit_no_test_fixtures_both_ways():
    found, unknown, _ = fixture_findings("EDIT-NO-TEST", "positive-untested.json")
    assert found == [("fixture-rules-edit-1", [2, 3, 4]), ("fixture-rules-edit-2", [4, 5]),
                     ("fixture-rules-edit-3", [2, 3]), ("fixture-rules-edit-4", [2, 3, 4]),
                     ("fixture-rules-edit-5", [2, 5])] and unknown == []
    assert fixture_findings("EDIT-NO-TEST", "negative-tested.json")[:2] == ([], [])


def test_e4_edit_no_test_cases():
    rule = catalog_rule("EDIT-NO-TEST")
    meta = lambda c: common.input_meta("Bash", {"command": c})   # noqa: E731
    edit = dict(path="/work/p/tests/test_a.py")
    for command in ("pytest -q", "python3 -m pytest", "bash tools/gate.sh", "python -I tools/gate.py",
                    "cd /work/p && tools/gate.sh", "python3 -c 'print(1)'"):
        assert cited(rule, call(1, "Edit", **edit) + call(2, **meta(command)) + [event(3, "stop")]) == ([], []), command
    for command in ("make test", "tox", "uv run pytest", "python3.12 -m pytest", "env pytest"):
        assert cited(rule, call(1, "Edit", **edit) + call(2, **meta(command)) + [event(3, "stop")]) == (
            [("s1", [1, 3])], []), command
    assert cited(rule, call(1, "Edit", **edit) + call(2, command_head="pytest") + [event(3, "stop")]) == ([], [])
    assert cited(rule, call(1, "Edit", **edit)) == ([], [("s1", 1)])                # no deadline (G-10)
    assert cited(rule, call(1, "Edit", **edit, post=False) + [event(2, "stop")]) == ([], [("s1", 1)])
    assert cited(rule, call(1, "Edit", path="tests/a.py", **{}) + [event(2, "stop")], {"root": "/work/p"}) == (
        [("s1", [1, 2])], [])                                                        # placed at context root
    assert cited(rule, call(1, "Edit", path="/work/p/tests/a.py") + [event(2, "stop")], {"root": "/work/q"}) == (
        [], [])
    for name in ("Write", "MultiEdit", "NotebookEdit"):
        assert cited(rule, call(1, name, **edit) + [event(2, "session_end")]) == ([("s1", [1, 2])], []), name
    assert cited(rule, call(1, "Read", **edit) + call(2, "Bash", **meta("sed -i s/a/b/ tests/a.py"))
                 + [event(3, "stop")]) == ([], [])


def test_e4_b11_refactor_flips_and_b06_stays_clean():
    """G-11: b11-refactor (edits, one under tests/, then stop) is flagged by
    EDIT-NO-TEST alone; b06-new-test's pytest line has command_head only and
    is evidence by G-8."""
    events = {e["id"]: e for e in evaluation.load_events(ROOT / "tests" / "fixtures" / "eval" / "events.json")}
    rules = engine.load_catalog(CATALOG)
    found, notes = evaluation.rule_findings(events["b11-refactor"], rules)
    assert [(f["rule_id"], f["cited_seq"]) for f in found] == [("EDIT-NO-TEST", [5, 6])] and notes == []
    found, notes = evaluation.rule_findings(events["b06-new-test"], rules)
    assert found == [] and notes == []
    (row,) = evaluation.evaluate(list(events.values()), rules)["rows"]
    assert (row["fn"], row["fp"], row["errors"]) == (9, 9, 0)


def test_e3_e4_no_benign_trace_has_a_finding_or_an_unknown_line():
    benign = fixtures.benign_corpus(ROOT / "tests" / "fixtures" / "rules" / "benign") + sorted(
        str(p) for p in (ROOT / "tests" / "fixtures").glob("*.log"))
    for rule_id in ("LANDED-NO-GATE", "EDIT-NO-TEST"):
        for path in benign:
            lines, ctx, _ = fixtures.load_fixture(path)
            assert engine.judge(catalog_rule(rule_id), lines, ctx) == ([], []), (rule_id, path)


# --- the project's own close shape, through the hook and `raqib report` ------------------------------

def close_shape(cwd, gate="tools/gate.sh"):
    edit_input = {"file_path": str(cwd / "raqib" / "x.py"), "old_string": "a", "new_string": "b"}
    calls = [("Edit", edit_input, {"filePath": "x"}),
             ("Bash", {"command": gate or "git status"}, {"stdout": "GREEN"}),
             ("Bash", {"command": "git add -A && " + HEREDOC.replace("x\n", "M4.2b require + two demands\n", 1)},
              {"stdout": "1 file changed"})]
    out = [payload("SessionStart", cwd, source="startup")]
    for i, (name, tool_input, response) in enumerate(calls, 1):
        out.append(tool("PreToolUse", cwd, name, tool_input, "toolu_%d" % i))
        out.append(tool("PostToolUse", cwd, name, tool_input, "toolu_%d" % i, tool_response=response))
    return out + [payload("Stop", cwd, stop_hook_active=False), payload("SessionEnd", cwd, reason="exit")]


def report_json(trace, *extra):
    out = io.StringIO()
    code = cli.main(["report", str(trace), "--json"] + list(extra), out=out)
    return code, json.loads(out.getvalue())


def test_e3_e4_the_close_shape_of_this_project_fires_neither_demand(tmp_path):
    """edit -> tools/gate.sh -> landed: commit (Claude Code's here-document
    form), through the real hook: neither demand fires or is partial; without
    the gate, both fire."""
    (tmp_path / "proj" / "raqib").mkdir(parents=True)
    cwd = tmp_path / "proj"
    demands = ("LANDED-NO-GATE", "EDIT-NO-TEST")
    for i, gate in enumerate(("tools/gate.sh", "tools/gate.sh 2>&1 | tail -3", "python -I tools/gate.py")):
        recs = run_hook(close_shape(cwd, gate), tmp_path / ("close-%d.jsonl" % i), cwd)
        assert recs[5]["input_meta"]["commit_prefix"] == "landed:", recs[5]
        code, rep = report_json(tmp_path / ("close-%d.jsonl" % i), "--scope", ".")
        assert [f["rule_id"] for f in rep["findings"] if f["rule_id"] in demands] == [], gate
        assert [n for n in rep["notes"] if n["rule_id"] in demands] == [], gate
        assert code == 0 and rep["result"] == "clean", rep
    recs = run_hook(close_shape(cwd, gate=None), tmp_path / "ungated.jsonl", cwd)
    code, rep = report_json(tmp_path / "ungated.jsonl", "--scope", ".")
    assert sorted((f["rule_id"], f["cited_seq"]) for f in rep["findings"]) == [
        ("EDIT-NO-TEST", [2, 5]), ("LANDED-NO-GATE", [4])] and code == 1


# --- E5: counts and docs ------------------------------------------------------------------------------

def test_e5_readme_rows_capture_bullet_and_cannot_see():
    flat = " ".join(README.split())
    assert "Fifteen rules turn the trace into findings" in flat and "and 9 YAML rules" in flat
    assert "| LANDED-NO-GATE | a `landed:` commit with no ok run of `gate.sh` or `gate.py`" in README
    assert "| EDIT-NO-TEST | an edit under `raqib/` or `tests/` with no ok run of pytest" in README
    assert "never its arguments" not in README
    assert ("Of a command's arguments only two things are kept: the file name of the script python or bash runs"
            " (`command_scripts`), and the first word of a `git commit` message") in flat
    assert ("a gate or test run that failed behind a pipe (`| tail`), an `||` or the background: LANDED-NO-GATE and"
            " EDIT-NO-TEST read only the Bash call's own ok") in flat
    assert "flag 9 of 25 benign ones" in flat and "8 until M4.2b, whose EDIT-NO-TEST flags b11-refactor" in flat


def test_e5_threat_model_lists_the_new_extract_and_the_holes():
    flat = " ".join(THREAT.split())
    stored = flat.split("**Stored in clear:**", 1)[1].split("**Stored as sha256:**", 1)[0]
    assert "`command_scripts`, the basename of its script operand" in stored and "(`commit_prefix`)" in stored
    assert "nothing else of a command line is kept" in stored
    demands = flat.split("**The two demands of a landing read names and ok only", 1)[1].split("### ", 1)[0]
    # H-8: section 5 names every listed hole, as the rule states it.
    for rule_id in ("LANDED-NO-GATE", "EDIT-NO-TEST"):
        block = demands.split("- %s:" % rule_id, 1)[1]
        for hole in catalog_rule(rule_id).holes:
            assert " ".join(hole.split()) in block, (rule_id, hole)
    assert "the rules flag 9 of 25 benign events" in flat and "flag 6 of 25" not in flat


def test_e5_the_baseline_record_has_the_dated_note_with_the_measured_numbers():
    text = (ROOT / "docs" / "review" / "2026-10-16-M2.2-baseline.md").read_text(encoding="utf-8")
    note = text.split("## Note (2026-11-03, M4.2b, ruling G-11", 1)[1]
    assert "FN 9, FP 9" in note and "b11-refactor" in note
    assert "1    rules                                           9    9      0  9/25      16/20      0/5" in note
    assert "FP 8" in text.split("## Note (2026-11-03", 1)[0]   # the record above stays as written


def test_e5_gate_yml_derives_the_catalog_count():
    gate = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert "never a literal" in gate and not re.search(r"len\(catalog\) == \d", gate)
    assert len(list(CATALOG.glob("*.yaml"))) == 9


# --- M4.2b REDO (ADR-0002 Amendment H) ------------------------------------------------------------

def test_h1_the_windows_landing_is_clean_and_measured():
    """H-1: the README's Windows gate (python -I tools\\gate.py), py, python.exe
    and timeout 900 tools/gate.sh before a landing: no finding, nothing
    unknown, and the file counts as a measured negative."""
    rule = catalog_rule("LANDED-NO-GATE")
    assert "tests/fixtures/rules/LANDED-NO-GATE/negative-windows.json" in rule.fixtures["negative"]
    report = fixtures.check_rule(rule, ROOT, ())
    windows = [dict(n, path=Path(n["path"]).as_posix()) for n in report["negatives"]
               if n["path"].endswith("negative-windows.json")]   # relpath: \ on Windows
    assert windows == [{"path": "tests/fixtures/rules/LANDED-NO-GATE/negative-windows.json", "fired": False,
                        "measured": True}]
    assert "python -I tools\\gate.py" in README   # the form the fixture holds
    meta = common.input_meta("Bash", {"command": "python -I tools\\gate.py"})
    assert meta == {"command_head": "python", "command_programs": ["python"], "command_scripts": ["gate.py"]}


def test_h1_wrappers_pass_through_for_scripts_only():
    for command in ("timeout 900 tools/gate.sh", "nohup tools/gate.sh", "env tools/gate.sh"):
        read = common.read_command(command)
        assert read[0] == [command.split()[0]] and read[1] == ["gate.sh"], command   # programs: the wrapper only
    assert common.SOURCES == (".", "source") and common.TIMEOUT_VALUE_OPTIONS == ("-s", "-k", "--signal",
                                                                                   "--kill-after")


def test_h2_true_evidence_wins_over_unknown_evidence():
    unknown_line = [rec(9, "pre", evidence=True), rec(9, "post", ok=None, evidence=True)]
    unk = lambda seq: [dict(r, seq=seq) for r in unknown_line]   # noqa: E731
    # before: unknown, then true, then the trigger; true, then unknown, then the trigger.
    assert cited(BEFORE, unk(1) + call(2, evidence=True) + call(3, mark="T")) == ([], [])
    assert cited(BEFORE, call(1, evidence=True) + unk(2) + call(3, mark="T")) == ([], [])
    # unknown only when no evidence line is true and one is unknown
    assert cited(BEFORE, unk(1) + call(2) + call(3, mark="T")) == ([], [("s1", 3)])
    assert cited(BEFORE, call(1) + call(2, mark="T")) == ([("s1", [2])], [])
    # after/until: the same between the trigger and its deadline.
    assert cited(AFTER, call(1, "Edit") + unk(2) + call(3, evidence=True) + [event(4, "stop")]) == ([], [])
    assert cited(AFTER, call(1, "Edit") + call(2, evidence=True) + unk(3) + [event(4, "stop")]) == ([], [])
    assert cited(AFTER, call(1, "Edit") + unk(2) + [event(3, "stop")]) == ([], [("s1", 1)])


def test_h2_one_unread_bash_line_does_not_downgrade_a_gated_session():
    rule = catalog_rule("LANDED-NO-GATE")
    meta = lambda c: common.input_meta("Bash", {"command": c})   # noqa: E731
    unread = meta("$X --run")
    assert unread == {"command_unread": True}
    commit = meta("git commit -m 'landed: x'")
    lines = call(1, **unread) + call(2, **meta("tools/gate.sh")) + call(3, **unread) + call(4, **commit)
    assert cited(rule, lines) == ([], [])
    assert cited(rule, call(1, **unread) + call(2, **commit)) == ([], [("s1", 2)])
    assert any("cannot read at all" in h and "H-2" in h for h in rule.holes)
    assert any("cannot read at all" in h and "H-2" in h for h in catalog_rule("EDIT-NO-TEST").holes)


def test_h3_an_unknown_trigger_with_true_evidence_is_not_partial():
    unknown_trigger = [rec(2, "pre", mark="T"), rec(2, "post", ok=None, mark="T")]
    assert cited(BEFORE, call(1, evidence=True) + unknown_trigger) == ([], [])
    assert cited(BEFORE, call(1, evidence=True) + call(2, mark="T", post=False)) == ([], [])
    assert cited(BEFORE, unknown_trigger) == ([], [("s1", 2)])
    # after/until: an unknown trigger discharged by later true evidence is not partial either.
    unknown_edit = [rec(1, "pre", "Edit"), rec(1, "post", "Edit", ok=None)]
    assert cited(AFTER, unknown_edit + call(2, evidence=True) + [event(3, "stop")]) == ([], [])
    assert cited(AFTER, unknown_edit + [event(2, "stop")]) == ([], [("s1", 1)])


@pytest.mark.parametrize("rule, lines, cause", [
    (BEFORE, [rec(1, "pre", mark="T"), rec(1, "post", ok=None, mark="T")], "the trigger cannot be judged"),
    (BEFORE, call(1, mark="T", post=False), "no post line"),
    (BEFORE, [rec(1, "pre", evidence=True), rec(1, "post", ok=None, evidence=True)] + call(2, mark="T"),
     "evidence unknown"),
    (AFTER, call(1, "Edit"), "no deadline came"),
    (AFTER, call(1, "Edit", post=False) + [event(2, "stop")], "no post line"),
    (AFTER, call(1, "Edit") + [rec(2, "pre", evidence=True), rec(2, "post", ok=None, evidence=True),
                               event(3, "stop")], "evidence unknown"),
], ids=["trigger", "no-post-before", "evidence", "no-deadline", "no-post-after", "evidence-after"])
def test_h3_the_partial_note_names_the_cause_per_seq(rule, lines, cause):
    (_, unknown) = engine.judge(rule, lines)
    (u,) = unknown
    assert u.cause == cause and tuple(u) == ("s1", u[1])
    found, notes = engine.evaluate([rule], lines)
    assert found == [] and notes == [{"rule_id": "DRIFT-TEST", "status": "partial",
                                      "detail": "could not judge 1 line(s) (session:seq s1:%d (%s))" % (u[1], cause)}]


def test_h3_a_deadline_that_cannot_be_judged_and_more_than_five_causes():
    rule = engine.compile_rule(doc(match=AFTER.doc["match"], require={
        "after": AFTER.doc["require"]["after"], "until": {"field": "input_meta.close", "eq": True}}), "u")
    assert [u.cause for u in engine.judge(rule, call(1, "Edit") + [event(2, "stop")])[1]] == ["deadline unknown"]
    lines = [r for i in range(1, 8) for r in call(i, "Edit")]
    (note,) = engine.evaluate([AFTER], lines)[1]
    assert note["detail"].startswith("could not judge 7 line(s) (session:seq s1:1 (no deadline came), ")
    assert note["detail"].endswith("s1:5 (no deadline came) ...)")
    plain = engine.compile_rule(doc(kind="anchor", match={"field": "input_meta.path", "prefix": "/"}), "p")
    (note,) = engine.evaluate([plain], [rec(1, "pre", "Edit")])[1]
    assert note["detail"] == ("could not judge 1 line(s) (session:seq s1:1): a field it reads is missing or a path"
                              " cannot be placed")   # other rules: unchanged


def test_h4_the_first_non_empty_message_and_the_no_message_hole():
    assert common.commit_prefix("git commit -m '' -m 'landed: x'") == "landed:"
    assert common.commit_prefix("git commit -m wip --no-message -m 'landed: x'") is None
    hole = [h for h in catalog_rule("LANDED-NO-GATE").holes if h.startswith("--no-message")]
    assert hole and "first non-empty -m" in hole[0]


def test_h5_the_listed_holes_and_the_line_ok_wording():
    landed, edit = catalog_rule("LANDED-NO-GATE"), catalog_rule("EDIT-NO-TEST")
    flat = " ".join(landed.holes)
    for phrase in ("a gate run after the commit on the same line counts", "the trigger is the line's ok, not the"
                   " commit's", "git $OPT commit", "CRLF line ends", "git.exe", "bash -n tools/gate.sh",
                   "python -V tools/gate.py", "--rule-kinds-child"):
        assert phrase in flat, phrase
    assert "with no context root, raqib/ and tests/ are placed against each line's cwd" in " ".join(edit.holes)
    assert "bash -n tools/gate.sh" in " ".join(edit.holes)
    description = " ".join(landed.doc["description"].split())
    assert "with that line's ok" in description and "the commit's post line" not in description
    # each listed behaviour, as built
    meta = lambda c: common.input_meta("Bash", {"command": c})   # noqa: E731
    assert cited(landed, call(1, **meta("git commit -m 'landed: x' && tools/gate.sh"))) == ([], [])
    assert cited(landed, call(1, **meta("git commit -m 'landed: x' && false"), ok=False)) == ([], [])
    for command in ("git $OPT commit -m 'landed: x'", "git.exe commit -m 'landed: x'",
                    "git commit -m \"$(cat <<'EOF'\r\nlanded: x\r\nEOF\r\n)\""):
        assert "commit_prefix" not in meta(command), command
    for command in ("bash -n tools/gate.sh", "python -V tools/gate.py", "python -I tools/gate.py --rule-kinds-child"):
        assert cited(landed, call(1, **meta(command)) + call(2, **meta("git commit -m 'landed: x'"))) == ([], [])
    assert cited(edit, call(1, "Edit", path="/work/p/raqib/a.py", cwd="/tmp") + [event(2, "stop")]) == ([], [])


def test_h6_require_null_is_an_error_and_holes_are_unique():
    with pytest.raises(engine.RuleError, match="require: must be {before: <node>} or {after: <node>, until: <node>}"):
        engine.compile_rule(dict(doc(), require=None), "src")
    for rule in engine.load_catalog(CATALOG):
        assert len(set(rule.holes)) == len(rule.holes), rule.id


def test_h7_both_demands_are_class_drift():
    assert {catalog_rule(r).cls for r in ("LANDED-NO-GATE", "EDIT-NO-TEST")} == {"DRIFT"}


def test_h8_the_record_counts_its_tables():
    record = " ".join((ROOT / "docs" / "review" / "2026-11-03-M4.2b.md").read_text(encoding="utf-8").split())
    assert "SCRIPTS (%d rows)" % len(SCRIPTS) in record and "COMMITS (%d rows)" % len(COMMITS) in record


def test_h9_the_field_item_is_recorded_in_the_night_status():
    status = (ROOT / "docs" / "review" / "2026-11-03-night-status.md").read_text(encoding="utf-8")
    assert "ruling H-9" in status and "PostToolUseFailure" in status


def nested(levels, inner):
    return "echo " + "$(echo " * (levels - 1) + "$(" + inner + ")" + ")" * (levels - 1)


@pytest.mark.parametrize("command, expected", [
    # $'...' (ANSI-C quoting) is not literal: nothing is read from it.
    ("git commit -m $'landed: x'", (["git"], [], None)),
    ("python3 $'tools/gate.py'", (["python3"], [], None)),
    ("git commit -m $'' -m 'landed: x'", (["git"], [], None)),
    # CRLF: a CR stays in the word (bash reads it so), so x.sh\r is no .sh operand and the
    # here-document's end line does not match; a word before a CR is still read.
    ("bash x.sh\r\n", (["bash"], [], None)),
    ("git commit -m 'landed: x'\r\n", (["git"], [], "landed:")),
    ("git commit -m \"$(cat <<'EOF'\r\nlanded: x\r\nEOF\r\n)\"", (["git", "cat"], [], None)),
    # 8-deep $(...) is read, 9-deep is not (PROGRAMS_DEPTH_MAX).
    (nested(8, "git commit -m 'landed: x'"), (["echo", "git"], [], "landed:")),
    (nested(8, "bash tools/gate.sh"), (["echo", "bash"], ["gate.sh"], None)),
    (nested(9, "git commit -m 'landed: x'"), None),
], ids=["ansi-c-message", "ansi-c-operand", "ansi-c-empty-first", "crlf-operand", "crlf-after-message",
        "crlf-heredoc", "8-deep-commit", "8-deep-script", "9-deep"])
def test_h10_hostile_inputs(command, expected):
    assert common.read_command(command) == expected


def test_h10_a_64_kib_command_is_read_and_one_more_character_is_not():
    head = "bash tools/gate.sh && git commit -m 'landed: x' && echo "
    edge = head + "x" * (common.COMMAND_SCAN_MAX - len(head))
    assert len(edge) == common.COMMAND_SCAN_MAX == 65536
    assert common.read_command(edge) == (["bash", "git", "echo"], ["gate.sh"], "landed:")
    assert common.read_command(edge + "x") is None
    assert common.input_meta("Bash", {"command": edge + "x"}) == {"command_head": "bash", "command_unread": True}
