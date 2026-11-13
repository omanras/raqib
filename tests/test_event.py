"""M10.1 (ADR-0011 Amendment B): the event, raqib-event/1, and the rules' ATT&CK ids.

Every entry fed to raqib/event.py here is made by a fixture HostWatch (B-7),
never written by hand: run A is tests/test_field_run.py's field run (findings
of a footprint and of a tree, a dark note), run B tests/test_acts_judged.py's
os source of net-windows (a finding, source findings, knocks, trees), run C
tests/test_host.py's reader that fails once (a hole). The fixtures' home is
a temporary directory; docs/specs/EVENT.md writes it as ~.
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import __version__, cli, event, host, overlay, report  # noqa: E402
from raqib.rules import cross, engine, silence, tree  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)
import test_acts_judged as aj  # noqa: E402
import test_field_run as fr  # noqa: E402
import test_host as th  # noqa: E402
import test_overlay as tov  # noqa: E402

CATALOG_DIR = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG_DIR)
TABLE = {r["id"]: r for r in report.rule_table(RULES)}
HOST = "host.example"
DOC = ROOT / "docs" / "specs" / "EVENT.md"
NOTE = "a rule about the agent's own work or the watch's own sight, not a technique"
B5 = {"NEW-AGENT": ["T1059"], "NEW-AGENT-UNKNOWN": ["T1059"], "HOST-RHYTHM": ["T1059", "T1071"],
      "NET-TOOL": ["T1105", "T1048"], "DESTRUCT-CMD": ["T1485"], "SECRET-OUTPUT": ["T1552"], "SCOPE-PATH": ["T1005"],
      "SILENCE-GAP": ["T1562"], "SILENCE-OPEN": ["T1562"], "SILENCE-HALF": ["T1562"], "SILENCE-ORDER": ["T1562"],
      "SILENCE-EMPTY": ["T1562"], "CROSS-SOURCE": ["T1562"],
      "AGENT-DARK-LIVE": [], "HOST-UNWATCHED": [], "SCOPE-CWD-ROOT": [], "SCOPE-CWD-MOVED": [], "DRIFT-FILES": [],
      "EDIT-NO-TEST": [], "LANDED-NO-GATE": [], "HEAD-UNMOVED": [], "INDEX-UNTOUCHED": []}


# --- the fixture runs (B-7) -------------------------------------------------------------------------------------

def run_a(tmp):
    """The field run: AGENT-DARK-LIVE on a footprint, NEW-AGENT on a tree, a dark note (M7.5 E1)."""
    w, clock = fr.make_host(tmp, fr.FIELD, runner=fr.FakeRunner(), run="field-run")
    fr.run_rounds(w, clock, len(fr.FIELD))
    w.finish()
    return w


def run_b(tmp):
    """The os source of net-windows on powershell pid 5888 (tests/test_acts_judged.py E3): NEW-AGENT-UNKNOWN,
    three NET-TOOL source findings, knocks. (watch, state at its last round, state after its end)."""
    follow = aj.CountingFollow(aj.after_start(aj.os_lines("net-windows.sysmon.xml", 4700)))
    w = aj.watch_rounds(tmp, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow)
    beat = json.loads(json.dumps(w.state(w.clock())))
    w.finish()
    return w, beat, json.loads(json.dumps(w.state(w.clock())))


def run_c(tmp):
    """A reader that fails in round 2 (tests/test_host.py E3): a reader-failed hole."""
    seq = iter([th.inv("windows"), None, th.inv("windows")])

    def reader():
        got = next(seq)
        if got is None:
            raise OSError("snapshot failed")
        return got
    clock = th.Clock()
    notifier = th.make_notifier(th.FakeRunner())
    notifier.host = True
    w = host.HostWatch(reader, th.CATALOG, th.RULES, notifier, every=10, out=None, err=__import__("io").StringIO(),
                       clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0, home=str(tmp / "home"),
                       platform="test", run="hole-run")
    th.run_rounds(w, clock, 3)
    w.finish()
    return w


def facts(state):
    return event.facts(state, host=HOST)


def ledger_of(w, state, end=False):
    return event.ledger(state, facts(state), state["updated"], rules=TABLE, knocks=w.knock_rows(), end=end,
                        exit=0 if end else None)


def examples(tmp):
    """{label: event} of the document's examples: the first event of each kind of the named run's ledger."""
    (tmp / "a").mkdir()
    (tmp / "b").mkdir()
    (tmp / "c").mkdir()
    wa = run_a(tmp / "a")
    wb, beat, end = run_b(tmp / "b")
    wc = run_c(tmp / "c")
    la = ledger_of(wa, json.loads(json.dumps(wa.state(wa.clock()))), end=True)
    lb = ledger_of(wb, beat)
    lb_end = ledger_of(wb, end, end=True)
    lc = ledger_of(wc, json.loads(json.dumps(wc.state(wc.clock()))), end=True)

    def first(events, kind, **want):
        return next(e for e in events if e["kind"] == kind and all(e.get(k) == v for k, v in want.items()))
    out = {"finding": first(lb, "finding"), "source-finding": first(lb, "source-finding"),
           "note": next(e for e in la if e["kind"] == "note" and "agent" in e.get("subject", {})),
           "tree": first(lb, "tree"), "hole": first(lc, "hole"), "knock": first(lb, "knock"),
           "heartbeat": first(lb, "heartbeat"), "watch start": first(lb, "watch", state="start"),
           "watch end": first(lb_end, "watch", state="end")}
    return out, {"a": (wa, la), "b": (wb, lb, lb_end), "c": (wc, lc)}


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("event")
    ex, runs = examples(tmp)
    return tmp, ex, runs


def strings(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(*[strings(v) for v in value.values()]) if value else set()
    if isinstance(value, (list, tuple)):
        return set().union(*[strings(v) for v in value]) if value else set()
    return set()


def home_free(text, tmp):
    return text.replace(str(tmp), "~")


# --- E1: one module, pure ---------------------------------------------------------------------------------------

def test_e1_the_module_reads_no_clock_file_network_or_environment():
    text = (ROOT / "raqib" / "event.py").read_text(encoding="ascii")
    imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", text, re.M)
    assert sorted(set(imports)) == ["json", "raqib", "re"], imports
    for word in ("import time", "datetime", "socket", "os.environ", "getenv", "open(", "urllib", "random",
                 "import host", "import watch", "uuid"):
        assert word not in text, word


def test_e1_one_function_per_kind_and_check_and_line():
    for name in ("finding", "source_finding", "note", "tree", "hole", "knock", "heartbeat", "watch_start",
                 "watch_end", "check", "line", "facts", "ledger"):
        assert callable(getattr(event, name)), name
    assert event.KINDS == ("finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch")
    assert event.tree_word((5888, "powershell", None)) == host.tree_word((5888, "powershell", None))


# --- E2: the keys of B-2, per kind, on the watch's own entries ------------------------------------------------

def test_e2_every_kind_is_built_from_a_fixture_run_and_has_no_problem(built):
    _, ex, runs = built
    kinds = {e["kind"] for e in ex.values()}
    assert kinds == set(event.KINDS)
    for label, ev in ex.items():
        assert event.check(ev) == [], (label, event.check(ev))
    for events in [runs["a"][1], runs["b"][1], runs["b"][2], runs["c"][1]]:
        for ev in events:
            assert event.check(ev) == [], (ev, event.check(ev))
            keys = list(ev)
            assert keys == [k for k in event.KEYS if k in ev]   # B-2's order of meaning
            for part, names in event.PARTS.items():
                if part in ev:
                    assert list(ev[part]) == [k for k in names if k in ev[part]], (part, ev[part])
            assert ev["watch"]["host"] == HOST and ev["watch"]["version"] == __version__


def test_e2_the_shape_of_each_kind(built):
    _, ex, _ = built
    f = ex["finding"]
    assert f["severity"] == TABLE["NEW-AGENT-UNKNOWN"]["severity"] and f["rule"] == {"id": "NEW-AGENT-UNKNOWN", "class": "HOST", "kind": "anchor",
                                                     "fp_budget": TABLE["NEW-AGENT-UNKNOWN"]["fp_budget"],
                                                     "attack": ["T1059"]}
    assert set(f["subject"]) == {"tree", "pid", "image", "named"} and f["subject"]["pid"] == 5888
    assert set(f["evidence"]) == {"run", "round", "seqs", "cites"} and f["knocked"] == {"status": "off"}
    s = ex["source-finding"]
    assert s["state"] == "settled" and s["rule"]["attack"] == ["T1105", "T1048"]
    assert set(s["evidence"]) == {"run", "source", "trace", "seqs", "lines"} and "round" not in s["evidence"]
    assert set(s["subject"]) == {"tree", "pid", "image"}
    n = ex["note"]
    assert n["severity"] == "info" and set(n["subject"]) <= {"tree", "agent", "path"} and n["evidence"]["seqs"]
    assert ex["hole"]["severity"] == "hole" and ex["hole"]["summary"].startswith("reader-failed: ")
    assert set(ex["knock"]["knocked"]) == {"status", "event"}
    assert ex["heartbeat"]["result"] == {"word": "WATCHING"} and set(ex["heartbeat"]["counts"]) == set(
        event.PARTS["counts"])
    assert ex["watch end"]["result"] == {"word": "FINISHED", "exit": 0}
    assert set(ex["watch start"]) == set(event.BASE) | {"state"}


def test_e2_a_key_the_entry_does_not_hold_is_absent_never_null(built):
    _, ex, runs = built
    for events in [runs["a"][1], runs["b"][1], runs["c"][1]]:
        for ev in events:
            assert "null" not in event.line(ev).replace('"null', ""), ev
    wb = runs["b"][0]
    footprint = [e for e in runs["a"][0].findings if e.get("path")]
    assert footprint
    ev = event.finding(footprint[0], facts(runs["a"][0].state(runs["a"][0].clock())), "2026-11-03T10:00:00.000Z",
                       1, TABLE.get(footprint[0]["rule_id"]))
    assert "pid" not in ev["subject"] and "tree" not in ev["subject"] and ev["subject"]["path"] == fr.KIMI_FP
    plain = event.note(wb.notes[0], facts(wb.state(wb.clock())), "2026-11-03T10:00:00.000Z", 1)
    assert set(plain) == set(event.BASE) | {"summary"}


def test_e2_nothing_new_is_said_every_string_is_the_entry_s_the_rule_s_or_the_watch_s(built):
    _, _, runs = built
    fixed = {event.SCHEMA, "info", "hole", "start", "end"} | set(event.KINDS) | set(event.SOURCE_STATES)
    for w, state, events in [(runs["a"][0], None, runs["a"][1]), (runs["b"][0], None, runs["b"][1]),
                             (runs["c"][0], None, runs["c"][1])]:
        st = json.loads(json.dumps(w.state(w.clock())))
        h = st["host"]
        dark = {d["text"]: d for d in h["dark_notes"]}
        entries = ([("tree", r) for r in h["trees"]] + [("finding", e) for e in h["findings"]]
                   + [("source-finding", e) for e in h["source_findings"]] + [("hole", e) for e in st["holes"]]
                   + [("note", dark.get(t, t)) for t in h["notes"]] + [("knock", k) for k in w.knock_rows()])
        assert entries
        for kind, entry in entries:
            build = {"tree": event.tree, "hole": event.hole, "note": event.note, "knock": event.knock}.get(kind)
            f = facts(st)
            if build:
                ev = build(entry, f, "2026-11-03T10:00:00.000Z", 7)
            else:
                ev = getattr(event, kind.replace("-", "_"))(entry, f, "2026-11-03T10:00:00.000Z", 7,
                                                            TABLE.get(entry.get("rule_id")))
            known = strings(json.loads(json.dumps(entry))) | strings(TABLE.get(
                entry.get("rule_id") if isinstance(entry, dict) else None) or {}) | strings(f) | fixed
            if kind == "tree":
                known.add(host.tree_word(tuple(entry["key"])))
            if kind == "hole":
                known.add("%s: %s" % (entry["kind"], entry["detail"]))   # the report's HOLES line, kind: detail
            said = strings({k: v for k, v in ev.items() if k not in ("id", "time")})
            assert said <= known, (kind, said - known)


# --- E3: the same in, the same out ------------------------------------------------------------------------------

def test_e3_the_same_entries_give_the_same_lines_and_ids_rise(built, tmp_path):
    tmp, ex, runs = built
    wb, lb, _ = runs["b"]
    for events in [runs["a"][1], lb, runs["c"][1]]:
        lines = [event.line(e) for e in events]
        assert all(ln.isascii() and "\n" not in ln for ln in lines)
        assert lines == [json.dumps(json.loads(ln), sort_keys=True, separators=(",", ":")) for ln in lines]
        ns = [e["n"] for e in events]
        assert ns == list(range(1, len(events) + 1))
        ids = [e["id"] for e in events]
        assert len(set(ids)) == len(ids) and ids == ["%s:%d" % (events[0]["watch"]["run"], k) for k in ns]
    # run twice: the same ledger, and the same fixture run in another home, give the same lines byte for byte
    _, beat, _ = run_b(tmp_path)
    again = ledger_of(wb, beat)
    assert [home_free(event.line(e), tmp_path) for e in again] == [home_free(event.line(e), tmp / "b")
                                                                  for e in lb]
    assert [event.line(e) for e in ledger_of(wb, json.loads(json.dumps(beat)))] == [event.line(e) for e in again]


def test_e3_non_ascii_is_escaped():
    ev = event.note("round 1: caf\u00e9", {"run": "r"}, "2026-11-03T10:00:00.000Z", 1)
    assert event.check(ev) == [] and "\\u00e9" in event.line(ev) and event.line(ev).isascii()


@pytest.mark.parametrize("change, word", [
    (lambda e: e.pop("watch"), "watch: missing"), (lambda e: e.update(n=0), "n:"), (lambda e: e.update(id="x:9"), "id:"),
    (lambda e: e.update(time="2026-11-03 10:00:00"), "time:"), (lambda e: e.update(severity="high"), "severity:"),
    (lambda e: e.update(kind="other"), "kind:"), (lambda e: e.update(extra=1), "extra:"),
    (lambda e: e.update(summary=None), "null"), (lambda e: e.update(schema="raqib-event/0"), "schema:"),
])
def test_e3_check_names_each_problem(change, word):
    ev = event.note("round 1: a note", {"run": "r", "mode": "host"}, "2026-11-03T10:00:00.000Z", 1)
    assert event.check(ev) == []
    change(ev)
    assert any(word in p for p in event.check(ev)), event.check(ev)


# --- E4: the ATT&CK ids are declared (B-5) ----------------------------------------------------------------------

def test_e4_every_rule_declares_b5_s_table_exactly():
    assert {rid: r["attack"] for rid, r in TABLE.items()} == B5
    for r in RULES:
        assert "attack" in r.doc and list(r.attack) == B5[r.id]
        assert (r.attack_note == NOTE) if not r.attack else ("attack_note" not in r.doc), r.id
    assert silence.ATTACK == {rid: ("T1562",) for rid in silence.RULE_KINDS} and cross.ATTACK == {
        "CROSS-SOURCE": ("T1562",)}
    assert tree.ATTACK == {rid: () for rid in tree.RULES} and set(tree.ATTACK_NOTE.values()) == {NOTE}


@pytest.mark.parametrize("attack, note, word", [
    ("[T105]", None, "not a technique id"), ("[T1059.01]", None, "not a technique id"), ("T1059", None, "a list"),
    ("[]", None, "needs attack_note"), (None, "why", "declare attack: []"), ("[]", '""', "non-empty"),
    ("[T1059, T1059]", None, "twice"),
])
def test_e4_the_engine_validates_attack_when_present(tmp_path, attack, note, word):
    text = (CATALOG_DIR / "NET-TOOL.yaml").read_text(encoding="ascii").replace("attack: [T1105, T1048]\n", "")
    add = ("attack: %s\n" % attack if attack else "") + ("attack_note: %s\n" % note if note else "")
    (tmp_path / "NET-TOOL.yaml").write_text(text.replace("severity: medium\n", add + "severity: medium\n", 1),
                                            encoding="ascii")
    with pytest.raises(engine.RuleError, match=re.escape(word)):
        engine.load_rule(tmp_path / "NET-TOOL.yaml")


def test_e4_a_sub_technique_loads(tmp_path):
    text = (CATALOG_DIR / "NET-TOOL.yaml").read_text(encoding="ascii")
    (tmp_path / "NET-TOOL.yaml").write_text(text.replace("[T1105, T1048]", "[T1105, T1059.004]"), encoding="ascii")
    assert engine.load_rule(tmp_path / "NET-TOOL.yaml").attack == ("T1105", "T1059.004")


def test_e4_check_rules_refuses_a_catalog_rule_with_neither(tmp_path, capsys):
    d = tmp_path / "catalog"
    d.mkdir()
    for p in CATALOG_DIR.glob("*.yaml"):
        text = p.read_text(encoding="ascii")
        if p.stem == "SCOPE-PATH":
            text = text.replace("attack: [T1005]\n", "")
        (d / p.name).write_text(text, encoding="ascii")
    assert "attack" not in engine.load_rule(d / "SCOPE-PATH.yaml").doc   # the engine still loads it
    assert cli.main(["check-rules", "--catalog", str(d)]) == 2
    err = capsys.readouterr().err
    assert "SCOPE-PATH" in err and "attack" in err and "NET-TOOL" not in err


def test_e4_a_user_rule_without_attack_loads_as_before(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    src = tov.user_rule(tmp_path / "mine")   # a person's rule as tests/test_overlay.py writes it: no attack
    assert "attack" not in src.read_text(encoding="ascii")
    overlay.add_rule(str(src), str(home))
    rules = engine.load_catalog(CATALOG_DIR, overlay=overlay.overlay_path(str(home)),
                                user_rules=overlay.user_dir(str(home)))
    (user,) = [r for r in rules if r.id == "USER-SHRED"]
    assert user.attack == () and user.attack_note is None and "attack" not in user.doc
    assert {r["id"]: r["attack"] for r in report.rule_table(rules)}["USER-SHRED"] == []


# --- E5: the contract is a document (B-6) -----------------------------------------------------------------------

def doc_keys(text):
    table = text[text.index("## Keys"):text.index("## Required keys")]
    return set(re.findall(r"^\| `([a-z_.]+)` \|", table, re.M))


def test_e5_the_document_names_every_key_the_module_can_emit_and_no_other():
    text = DOC.read_text(encoding="utf-8")
    emitted = set(event.KEYS) | {"%s.%s" % (p, k) for p, ks in event.PARTS.items() for k in ks}
    assert doc_keys(text) == emitted
    for row in re.findall(r"^\| `[a-z_.]+` \|.*$", text[text.index("## Keys"):text.index("## Required keys")], re.M):
        assert row.count("|") == 6, row   # key | meaning | kinds | OCSF | ECS
    req = text[text.index("## Required keys"):text.index("## Examples")]
    for kind in event.KINDS:
        (row,) = re.findall(r"^\| %s \| (.*) \|$" % re.escape(kind), req, re.M)
        assert sorted(re.findall(r"`([a-z_]+)`", row)) == sorted(event.BASE + event.REQUIRED[kind]), kind


def test_e5_each_example_line_is_what_the_module_builds_from_its_named_run(built):
    tmp, ex, _ = built
    text = DOC.read_text(encoding="utf-8")
    found = dict(re.findall(r"^### example: (.+?)\n(?:.*\n)*?```json\n(.+?)\n```", text, re.M))
    assert set(found) == set(ex)
    for label, ev in ex.items():
        line = event.line(ev)
        for sub in ("a", "b", "c"):
            line = home_free(line, tmp / sub)
        assert found[label] == line, label


def test_e6_no_real_host_user_or_address_in_the_document():
    text = DOC.read_text(encoding="utf-8")
    for addr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert addr.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), addr
    hosts = set(re.findall(r'"host":"([^"]*)"', text))
    assert hosts <= {HOST}, hosts
