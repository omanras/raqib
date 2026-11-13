"""M10.1 REDO (ADR-0011 Amendment B, as Amendment C rules it): the event, raqib-event/1, and the rules' ATT&CK ids.

Every entry fed to raqib/event.py here is made by a fixture HostWatch (B-7,
C-12), never written by hand; a broken event for check() is a built event
with one value changed. The runs (each in its own temporary home):
  A  tests/test_field_run.py's field run: a footprint finding, a NEW-AGENT tree finding, a dark note
  B  tests/test_acts_judged.py's os source of net-windows: NEW-AGENT-UNKNOWN, settled source findings, knocks,
     a blind spot; a snapshot after each round (a tree and a finding arrive in round 2)
  C  tests/test_host.py's reader that fails once: a hole that knocked
  D  tests/test_acts_judged.py's person and agent under explorer: a benign tree, history, judged on another tree,
     noted
  N  run B with a decision that raises (tests/test_acts_judged.py's redo3 case): not settled
  P  tests/test_host_sources.py's hooks source silent at stop: pending at exit
  R  tests/test_rhythm.py's cycle with a notifier that fails: HOST-RHYTHM, a notifier's hole, a tree there at the start
  F  tests/test_host.py's fold (redo c5): a knock whose fold was decided
A path is the machine's; a comparison across homes or platforms is of the
event with each path under the run's home written ~/ and posix (pathless).
"""
import copy
import json
import re
import sys
from pathlib import Path, PurePath

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
import test_host_sources as hs  # noqa: E402
import test_overlay as tov  # noqa: E402
import test_rhythm as tr  # noqa: E402
import test_watch as tw  # noqa: E402

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
# C-4 and C-5, held here as the ruling's words (not read from the module)
C4_STATES = ["judged on another tree", "history", "noted", "pending at exit", "not settled", "settled"]
C5_WORDS = {0: "CLEAN", 1: "ALARM", 3: "INCOMPLETE"}
# C-11: the named pairs, as the ruling gives them; every other key maps to the namespace
C11 = {
    "kind": ({"class_uid", "category_uid"}, {"event.action"}),
    "rev": ({"activity_id", "type_uid"}, {"raqib.rev"}),
    "time": ({"time", "time_dt"}, {"@timestamp"}),
    "severity": ({"severity_id"}, {"event.severity"}),
    "alarm": ({"is_alert"}, {"event.kind"}),
    "id": ({"finding_info.uid"}, {"event.id"}),
    "about": ({"metadata.correlation_uid"}, {"raqib.about"}),
    "summary": ({"message", "finding_info.desc"}, {"message"}),
    "rule.id": ({"finding_info.analytic.uid", "finding_info.title"}, {"rule.id"}),
    "rule.class": ({"unmapped.raqib.rule.class"}, {"rule.category"}),
    "rule.attack": ({"finding_info.attacks[].technique.uid"}, {"threat.technique.id"}),
    "subject.pid": ({"evidences[].process.pid"}, {"process.pid"}),
    "subject.image": ({"evidences[].process.name"}, {"process.name"}),
    "watch.host": ({"device.hostname"}, {"host.name"}),
    "watch.version": ({"metadata.product.version", "metadata.product.name"}, {"observer.version", "observer.product"}),
    "knocked.status": ({"status_detail"}, {"raqib.knocked.status"}),
}
C11_SENTENCES = [
    "finding, source-finding and hole are OCSF Detection Finding (`class_uid` 2004, `category_uid` 2;"
    " `activity_id` 1 Create at rev 1, 2 Update after; `type_uid` 200400 + `activity_id`); every other kind is"
    " OCSF Base Event (`class_uid` 0).",
    "`time` -> `time` as epoch milliseconds and `time_dt` as given; ECS `@timestamp`.",
    "`severity` -> `severity_id` high 4, medium 3, low 2, info 1, hole 3; ECS `event.severity` the same number.",
    "`alarm` -> `is_alert`; ECS `event.kind` \"alert\" when true, else \"event\".",
    "`watch.version` -> `metadata.product.version` (`metadata.product.name` is \"Raqib\"); ECS `observer.version`"
    " (`observer.product` \"Raqib\").",
    "The whole line -> OCSF `raw_data`; ECS `event.original`.",
]


# --- the fixture runs (B-7, C-12) ------------------------------------------------------------------------------

def facts(state):
    return event.facts(state, host=HOST)


def take(w, end=False, exit=None):
    """One moment of a watch: its state and its knock rows read together, and the snapshot of them."""
    st = json.loads(json.dumps(w.state(w.clock())))
    knocks = json.loads(json.dumps(w.knock_rows()))
    return {"state": st, "knocks": knocks,
            "events": event.snapshot(st, facts(st), st["updated"], knocks, TABLE, end=end, exit=exit)}


def ended(w, home, **more):
    text, code = w.finish()
    return dict(take(w, end=True, exit=code), w=w, home=home, report=text, code=code, **more)


def run_a(tmp):
    w, clock = fr.make_host(tmp, fr.FIELD, runner=fr.FakeRunner(), run="field-run")
    fr.run_rounds(w, clock, len(fr.FIELD))
    return ended(w, tmp / "home")


def run_b(tmp, decide=None):
    moments = []
    follow = aj.CountingFollow(aj.after_start(aj.os_lines("net-windows.sysmon.xml", 4700)))
    w = aj.watch_rounds(tmp, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow,
                        between=lambda w, k: moments.append(take(w)))
    return ended(w, tmp, moments=moments)


def run_c(tmp):
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
    return ended(w, tmp / "home")


def run_d(tmp):
    text = aj.person_and_agent_export()
    follow = aj.CountingFollow(by_root={5100: aj.after_start(aj.built(text, 5100)),
                                        6100: aj.after_start(aj.built(text, 6100))})
    w = aj.watch_rounds(tmp, ["benign-person/before", "benign-person/agent", "benign-person/agent"], follow=follow)
    return ended(w, tmp)


def run_p(tmp):
    project = tmp / "proj"
    project.mkdir()
    names = [hs.moved("linux", project, pid=95)] * 3
    w, clock = hs.make_host(tmp, [copy.deepcopy(n) for n in names], runner=tw.FakeRunner(), attach_hooks=True,
                            run="pending-run")
    hs.rounds(w, clock, 1)
    src = w.sources[next(k for k in w.sources if k[0] == 95)]
    hs.write_hooks(src, [hs.hook_line(project, 1, "session_start")])
    w.tick()
    return ended(w, tmp)


def run_r(tmp):
    w, clock = tr.make_host(tmp, tr.scenario("cycle", 4), runner=tw.FakeRunner(result=(1, "boom")), run="rhythm-run")
    tr.rounds(w, clock, 4)
    return ended(w, tmp)


def run_f(tmp):
    four = json.loads(json.dumps(th.inv("windows")))
    four["candidates"] = [c for c in four["candidates"] if c["image"] != "msedge"]
    w, clock = th.make_host(tmp, [th.inv("benign/linux-desktop:before"), four, four], runner=th.FakeRunner())
    th.run_rounds(w, clock, 2)
    w.notifier.notify("NEW-AGENT", "claude pid 2100 (named)", clock.t, token=(w.findings[0], "notice"),
                      limit_id="NEW-AGENT pid 2100")
    clock.t += 61
    w.tick()
    return ended(w, tmp / "home")


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    out = {}
    with pytest.MonkeyPatch.context() as mp:
        home = tmp_path_factory.mktemp("event-home")
        mp.setenv("HOME", str(home))
        mp.setenv("USERPROFILE", str(home))
        for name, fn in (("A", run_a), ("B", run_b), ("C", run_c), ("D", run_d), ("P", run_p), ("R", run_r),
                         ("F", run_f)):
            out[name] = fn(tmp_path_factory.mktemp("event-" + name.lower()))
        mp.setattr(host.HostWatch, "_decide", lambda self, now, act: (_ for _ in ()).throw(
            RuntimeError("cannot decide (test)")))
        out["N"] = run_b(tmp_path_factory.mktemp("event-n"))
    return out


def all_events(runs):
    for name, r in runs.items():
        for m in [r] + r.get("moments", []):
            for ev in m["events"]:
                yield name, r, m, ev


def strings(value):
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(set(), *[strings(v) for v in value.values()])
    if isinstance(value, (list, tuple)):
        return set().union(set(), *[strings(v) for v in value])
    return set()


def leaves(value, where=""):
    """(dotted key, string) of every string the event says."""
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from leaves(v, "%s.%s" % (where, k) if where else k)
    elif isinstance(value, list):
        for v in value:
            yield from leaves(v, where + "[]")


def pathless(ev, home):
    """C-12: the event with each path under the run's home (evidence.trace, evidence.record) written ~/ and posix,
    and a trace directory named by a temporary project's hash written proj-HASH; in any other string (a note
    that names a trace) the home is written ~: values no home enters. Done on the values, never on the line
    (a line escapes a Windows path's backslashes)."""
    def free(v):
        if isinstance(v, str):
            return v.replace(str(home), "~")
        if isinstance(v, dict):
            return {k: free(x) for k, x in v.items()}
        return [free(x) for x in v] if isinstance(v, list) else v
    ev = copy.deepcopy(ev)
    for key in ("trace", "record"):
        v = (ev.get("evidence") or {}).get(key)
        if isinstance(v, str):
            rel = PurePath(v).relative_to(PurePath(str(home)))
            ev["evidence"][key] = re.sub(r"proj-[0-9a-f]{12}", "proj-HASH", "~/" + rel.as_posix())
    ev = free(ev)
    assert str(home) not in event.line(ev) and str(home) not in json.dumps(ev), ev   # no other string holds it
    return ev


def by_about(events):
    return {e["about"]: e for e in events if e["about"] != "watch"}


# --- E1 (C-1): one module, pure; an event's identity --------------------------------------------------------

def test_e1_the_module_reads_no_clock_file_network_or_environment():
    text = (ROOT / "raqib" / "event.py").read_text(encoding="ascii")
    imports = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", text, re.M)
    assert sorted(set(imports)) == ["datetime", "json", "raqib", "re"], imports
    for word in ("import time", ".now(", "utcnow", "today(", "socket", "os.environ", "getenv", "open(", "urllib",
                 "random", "import host", "import watch", "uuid", "import os"):
        assert word not in text, word


def test_e1_one_function_per_kind_snapshot_check_and_line():
    for name in ("finding", "source_finding", "note", "tree", "hole", "knock", "heartbeat", "watch_start",
                 "watch_end", "check", "line", "facts", "snapshot"):
        assert callable(getattr(event, name)), name
    assert not hasattr(event, "ledger")
    assert event.KINDS == ("finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch")


def test_e1_a_snapshot_names_each_entry_by_its_ledger_and_place_n_from_1_rev_1(runs):
    for name, r in runs.items():
        for m in [r] + r.get("moments", []):
            st, h, evs = m["state"], m["state"]["host"], m["events"]
            want = (["watch"] + ["tree:%s" % host.tree_word(tuple(t["key"])) for t in h["trees"]]
                    + ["finding:%d" % i for i in range(1, len(h["findings"]) + 1)]
                    + ["source-finding:%d" % i for i in range(1, len(h["source_findings"]) + 1)]
                    + ["hole:%d" % i for i in range(1, len(st["holes"]) + 1)]
                    + ["blind:%d" % i for i in range(1, len(h["blind"]) + 1)]
                    + ["note:%d" % i for i in range(1, len(h["notes"]) + 1)]
                    + ["knock:%d" % i for i in range(1, len(m["knocks"]) + 1)] + ["watch"])
            assert [e["about"] for e in evs] == want, name
            assert [e["n"] for e in evs] == list(range(1, len(want) + 1)) and {e["rev"] for e in evs} == {1}
            assert [e["id"] for e in evs] == ["%s:%d" % (st["run"], k) for k in range(1, len(want) + 1)]


def test_e1_two_moments_of_one_watch_give_the_same_about_to_the_same_entry_though_its_n_moved(runs):
    first, second = runs["B"]["moments"][:2]
    h1, h2 = first["state"]["host"], second["state"]["host"]
    assert (len(h1["trees"]), len(h1["findings"])) == (0, 0) and (len(h2["trees"]), len(h2["findings"])) == (1, 1)
    one, two = by_about(first["events"]), by_about(second["events"])
    assert one and set(one) < set(two)
    moved = 0
    for about, e in one.items():
        f = two[about]
        assert (f["kind"], f.get("summary"), f.get("subject"), f.get("hole")) == (
            e["kind"], e.get("summary"), e.get("subject"), e.get("hole")), about
        moved += f["n"] != e["n"]
    assert moved == len(one)   # every entry of the first moment sits after the tree and the finding that arrived
    new = set(two) - set(one)
    assert {"tree:%s" % aj.SHELL, "finding:1"} <= new


def test_e1_snapshot_must_be_given_the_knock_rows_and_the_rule_table(runs):
    st = runs["B"]["state"]
    with pytest.raises(ValueError, match="knocks"):
        event.snapshot(st, facts(st), st["updated"], None, TABLE)
    with pytest.raises(ValueError, match="rules"):
        event.snapshot(st, facts(st), st["updated"], runs["B"]["knocks"], None)


# --- E2 (C-2): the keys, in C-2's order; a key the entry does not hold is absent --------------------------

C2 = ["schema", "id", "n", "time", "kind", "about", "rev", "severity", "alarm", "summary", "rule", "subject",
      "evidence", "hole", "knocked", "state", "result", "counts", "watch"]
C2_PARTS = {"rule": ["id", "class", "kind", "fp_budget", "attack"],
            "subject": ["tree", "pid", "image", "started", "named", "agent", "path", "benign", "history", "by"],
            "evidence": ["run", "round", "rounds", "record", "source", "trace", "seqs", "lines", "cites"],
            "hole": ["kind", "class", "count", "last"], "knocked": ["status", "event", "title", "limit_id", "called"],
            "result": ["word", "exit"],
            "counts": ["rounds", "findings", "source_findings", "holes", "blind", "notes", "trees", "knocks"],
            "watch": ["run", "mode", "platform", "version", "host"]}


def test_e2_every_event_of_every_run_has_no_problem_and_c2_s_order(runs):
    assert list(event.KEYS) == C2 and {k: list(v) for k, v in event.PARTS.items()} == C2_PARTS
    kinds = set()
    for name, _, _, ev in all_events(runs):
        assert event.check(ev) == [], (name, ev, event.check(ev))
        assert list(ev) == [k for k in C2 if k in ev], ev
        for part, names in C2_PARTS.items():
            if part in ev:
                assert list(ev[part]) == [k for k in names if k in ev[part]], (part, ev[part])
        assert ev["watch"]["host"] == HOST and ev["watch"]["version"] == __version__
        assert "null" not in event.line(ev).replace('"null', ""), ev   # absent, never null
        kinds.add(ev["kind"])
    assert kinds == set(event.KINDS)


def test_e2_a_footprint_finding_holds_no_tree_and_a_plain_note_only_its_text(runs):
    a = runs["A"]
    (fp,) = [e for e in a["events"] if e["kind"] == "finding" and "path" in e.get("subject", {})]
    assert fp["rule"]["id"] == "AGENT-DARK-LIVE" and fp["subject"]["path"] == fr.KIMI_FP
    assert "pid" not in fp["subject"] and "tree" not in fp["subject"] and fp["rule"]["attack"] == []
    plain = [e for e in runs["B"]["events"] if e["kind"] == "note"]
    assert plain and all(set(e) == set(event.BASE) | {"summary"} for e in plain)


# --- E3 (C-3): a cite is never its text; nothing new is said ---------------------------------------------------

def cite_texts(value):
    """Every cite text and sample row the watch holds in an entry (anywhere under a "cites" or "sample" key)."""
    out = set()
    if isinstance(value, dict):
        for k, v in value.items():
            if k in ("cites", "talk_cites") and isinstance(v, list):
                out |= {c["text"] for c in v if isinstance(c, dict) and isinstance(c.get("text"), str) and c["text"]}
            if k == "sample" and isinstance(v, str) and v:
                out.add(v)
            out |= cite_texts(v)
    elif isinstance(value, list):
        for v in value:
            out |= cite_texts(v)
    return out


def cites_of(value):
    if isinstance(value, dict):
        return [c for k, v in value.items() for c in (v if k == "cites" and isinstance(v, list) else cites_of(v))]
    return [c for v in value for c in cites_of(v)] if isinstance(value, list) else []


def test_e3_no_event_holds_a_cite_s_text_or_a_sample_row(runs):
    everything = set()
    for name, r in runs.items():
        st = r["state"]
        held = cite_texts(st["host"]["trees"]) | cite_texts(st["host"]["findings"]) | cite_texts(
            st["host"]["dark_notes"]) | cite_texts(st["host"]["source_findings"])
        everything.update(held)
        for m in [r] + r.get("moments", []):
            for ev in m["events"]:
                said = strings(ev)
                for c in (ev.get("evidence") or {}).get("cites", []):
                    assert set(c) <= {"src", "line", "round", "seq"} and "text" not in c, c
                for text in held:
                    if text in r["report"]:   # a value the report prints itself (a footprint's path) may be said
                        continue
                    assert not any(text in s for s in said), (name, text, ev)
    assert len(everything) > 10   # the runs' entries hold cite texts and sample rows to look for


def test_e3_a_rhythm_finding_says_its_cycle_rounds_and_each_cite_s_round_and_seq(runs):
    r = runs["R"]
    (entry,) = [f for f in r["w"].findings if f["rule_id"] == "HOST-RHYTHM"]
    (ev,) = [e for e in r["events"] if e["kind"] == "finding" and e["rule"]["id"] == "HOST-RHYTHM"]
    assert ev["evidence"]["rounds"] == entry["cycle_rounds"] == [2, 3, 4]
    assert ev["evidence"]["cites"] == [{k: c[k] for k in ("src", "line", "round", "seq")} for c in entry["cites"]]
    assert ev["evidence"]["record"] == r["state"]["trace"] == r["w"].rounds_path


def test_e3_the_record_of_a_finding_a_tree_and_a_dark_note_is_the_state_s_trace(runs):
    seen = set()
    for name, r, m, ev in all_events(runs):
        ev_ = ev.get("evidence") or {}
        if ev["kind"] in ("finding", "tree") or (ev["kind"] == "note" and "seqs" in ev_):
            assert ev_["record"] == m["state"]["trace"], ev
            seen.add(ev["kind"])
        else:
            assert "record" not in ev_, ev
        if ev["kind"] == "source-finding":
            entry = m["state"]["host"]["source_findings"][int(ev["about"].split(":")[1]) - 1]
            assert ev_["trace"] == entry["trace"] and ev["summary"] == entry["summary"]
    assert seen == {"finding", "tree", "note"}


def test_e3_nothing_new_is_said_every_string_is_the_report_s_the_rule_s_or_the_watch_s(runs):
    closed = (set(event.KINDS) | set(C4_STATES) | set(C5_WORDS.values()) | {event.SCHEMA, "info", "hole",
              "blind spot", "start", "end"} | set(event.SEVERITIES))
    unsaid = set()
    for name, r, m, ev in all_events(runs):
        rule = TABLE.get((ev.get("rule") or {}).get("id")) or {}
        own = {ev["id"], ev["time"], ev["about"], m["state"]["band"]} | strings(facts(m["state"]))
        trees = m["state"]["host"]["trees"]
        words = {host.tree_word(tuple(t["key"])) for t in trees}   # the watch's tree word (C-1's about)
        # C-7, C-3: a tree's start is the third part of its key; a cite's src is the entry's own pointer (A5)
        ruled = {("subject.started", t["key"][2]) for t in trees} | {
            ("evidence.cites[].src", c["src"]) for c in cites_of(m["state"]["host"])}
        for where, s in leaves(ev):
            if not (s in closed or s in own or s in strings(rule) or s in words or (where, s) in ruled
                    or s in r["report"]):
                unsaid.add((name, ev["kind"], where, s[:80]))
    assert sorted(unsaid) == [], "\n".join(map(repr, sorted(unsaid)))


def test_e3_non_ascii_in_a_built_event_is_escaped(runs):
    ev = copy.deepcopy(next(e for e in runs["B"]["events"] if e["kind"] == "note"))
    ev["summary"] = ev["summary"] + " caf\u00e9"
    assert event.check(ev) == [] and "caf\\u00e9" in event.line(ev) and event.line(ev).isascii()


# --- E4 (C-4): a source finding's state is the report's word; alarm is the report's ALARMS ------------------

def report_word(entry):
    """The word the report prints for a source finding (host.py HostWatch._word), as C-4 names it."""
    word = host.HostWatch._word(entry)
    return {host.BENIGN_COUNT: "noted", entry["severity"]: "settled"}.get(word, word)


def test_e4_each_of_the_six_states_is_the_report_s_word_for_the_same_entry(runs):
    assert list(event.SOURCE_STATES) == ["judged on another tree", "history", "pending at exit", "noted",
                                         "not settled", "settled"]   # host.py _word's order of precedence
    reached = set()
    for name, r in runs.items():
        evs = [e for e in r["events"] if e["kind"] == "source-finding"]
        assert len(evs) == len(r["w"].source_findings), name
        for ev, entry in zip(evs, r["w"].source_findings):
            assert ev["summary"] == entry["summary"] and ev["state"] == report_word(entry), (name, ev)
            reached.add(ev["state"])
    assert reached == set(C4_STATES)


def test_e4_alarm_is_what_the_report_counts_under_alarms_or_incomplete(runs):
    for name, r in runs.items():
        w, text = r["w"], r["report"]
        alarms = text[text.index("\nALARMS: "):].split("\n")[1]
        live = w.source_alarms()
        for ev in r["events"]:
            if ev["kind"] == "finding":
                assert ev["alarm"] is True and ev["rule"]["id"] in alarms, (name, ev["about"])
            elif ev["kind"] == "source-finding":
                entry = w.source_findings[int(ev["about"].split(":")[1]) - 1]
                assert ev["alarm"] is any(entry is x for x in live), (name, ev["about"])
                if ev["alarm"]:
                    assert "%s on pid %s" % (entry["rule_id"], entry["pid"]) in alarms
            elif ev["kind"] == "hole":
                assert ev["alarm"] is (ev["hole"]["class"] == "hole")
                assert (ev["severity"], ev["hole"]["class"]) in (("hole", "hole"), ("info", "blind spot"))
            else:
                assert "alarm" not in ev
    assert any(e["alarm"] is False for e in runs["D"]["events"] if e["kind"] == "source-finding")


# --- E5 (C-5 to C-8): the watch's word, holes and blind spots, trees, knocks ----------------------------------

def test_e5_the_heartbeat_says_the_band_and_the_code_so_far_and_the_end_the_exit(runs):
    for name, r in runs.items():
        for m in r.get("moments", []):
            (hb,) = [e for e in m["events"] if e["kind"] == "heartbeat"]
            code = m["state"]["code_so_far"]
            assert hb["state"] == m["state"]["band"] and hb["result"] == {"word": C5_WORDS[code], "exit": code}
        (end,) = [e for e in r["events"] if e["kind"] == "watch" and e["state"] == "end"]
        word, code = re.search(r"^RESULT: (\w+) \(exit (\d+)", r["report"], re.M).groups()
        assert end["result"] == {"word": C5_WORDS[r["code"]], "exit": r["code"]} and int(code) == r["code"]
        assert word == end["result"]["word"] or word not in C5_WORDS.values(), (name, word)
    b = runs["B"]
    assert b["code"] == 1 and b["moments"][-1]["state"]["band"] == "WATCHING"   # never "FINISHED, exit 0" again


def test_e5_holes_blind_spots_and_the_counts(runs):
    (c,) = [e for e in runs["C"]["events"] if e["about"].startswith("hole:")]
    assert c["hole"] == {"kind": "reader-failed", "class": "hole"} and c["knocked"] == {"status": "sent"}
    assert c["severity"] == "hole" and c["evidence"] == {"round": 2}
    (nf,) = [e for e in runs["R"]["events"] if e["about"].startswith("hole:")]
    entry = runs["R"]["w"].notifier.holes[0]
    assert nf["hole"] == {"kind": "notify-failed", "class": "hole", "count": entry["count"], "last": entry["last"]}
    blind = [e for _, _, _, e in all_events(runs) if e["about"].startswith("blind:")]
    assert blind and all(e["hole"]["class"] == "blind spot" and e["severity"] == "info" for e in blind)
    for name, r, m, ev in all_events(runs):
        if "counts" in ev:
            st = m["state"]
            assert ev["counts"]["blind"] == len(st["host"]["blind"]) and ev["counts"]["holes"] == len(st["holes"])
            assert ev["counts"]["knocks"] == len(m["knocks"]), name


def test_e5_a_tree_s_subject_and_time_and_named_is_a_boolean_on_every_kind(runs):
    trees = [(r, e) for _, r, m, e in all_events(runs) if e["kind"] == "tree"]
    for r, ev in trees:
        row = next(t for t in r["w"].trees.values() if "tree:" + host.tree_word(tuple(t["key"])) == ev["about"])
        assert ev["time"] == row["first_seen"] and ev["subject"]["pid"] == row["pid"]
        assert ev["subject"].get("started") == row["key"][2] and ev["subject"]["benign"] is row["benign"]
        assert ev["subject"]["history"] is row["history"]
    assert any(e["subject"]["benign"] for _, e in trees) and any(e["subject"]["history"] for _, e in trees)
    for _, _, _, ev in all_events(runs):
        if "named" in ev.get("subject", {}):
            assert isinstance(ev["subject"]["named"], bool), ev
    (f,) = [e for e in runs["B"]["events"] if e["kind"] == "finding"]
    assert f["subject"]["named"] is False   # the report's "unknown"


def test_e5_a_knock_says_its_title_limit_id_and_what_the_notifier_said_at_the_call(runs):
    for name, r in runs.items():
        evs = [e for e in r["events"] if e["kind"] == "knock"]
        assert len(evs) == len(r["knocks"]), name
        for ev, row in zip(evs, r["knocks"]):
            assert ev["knocked"] == {"status": row["status"], "event": row["event"], "title": row["title"],
                                     "limit_id": row["limit_id"], "called": row["called"]}
    folded = [e for e in runs["F"]["events"] if e["kind"] == "knock" and e["knocked"]["status"].startswith("folded")]
    assert folded and folded[0]["knocked"]["called"] == "sent"
    assert any(e["knocked"]["status"] == "failed" for e in runs["R"]["events"] if e["kind"] == "knock")


# --- E6 (C-10): check, on a built event with one value changed ----------------------------------------------

def pick(runs, run, kind, **want):
    r = runs[run]
    evs = r["events"] + [e for m in r.get("moments", []) for e in m["events"]]
    return copy.deepcopy(next(e for e in evs if e["kind"] == kind and all(e.get(k) == v for k, v in want.items())))


def setin(path, value):
    def change(ev):
        *parts, last = path.split(".")
        obj = ev
        for p in parts:
            obj = obj[p]
        if value is KeyError:
            obj.pop(last)
        else:
            obj[last] = value
    return change


CHANGES = [
    ("finding", "rule.attack", KeyError), ("finding", "rule.attack", ["T105"]), ("finding", "rule.attack", "T1059"),
    ("finding", "alarm", KeyError), ("finding", "alarm", False), ("finding", "alarm", "true"),
    ("finding", "about", KeyError), ("finding", "about", "hole:1"), ("finding", "about", "finding:0"),
    ("finding", "rev", KeyError), ("finding", "rev", 0), ("finding", "rev", "1"),
    ("finding", "time", "2026-13-45T25:61:61.000Z"), ("finding", "time", "2026-11-03 10:00:00"),
    ("finding", "subject.named", "unknown"), ("finding", "subject.pid", "5888"),
    ("finding", "evidence.seqs", ["1"]), ("finding", "evidence.round", True), ("finding", "severity", "hole"),
    ("finding", "kind", "other"), ("finding", "extra", 1), ("finding", "summary", None), ("finding", "summary", ""),
    ("finding", "schema", "raqib-event/0"), ("finding", "n", 0), ("finding", "id", "x:9"),
    ("finding", "watch", KeyError),
    ("finding", "rule.fp_budget", "0.4"), ("finding", "watch.host", ""),
    ("source-finding", "state", "pending"), ("source-finding", "state", KeyError), ("source-finding", "alarm", False),
    ("source-finding", "evidence.lines", "8"),
    ("hole", "hole.class", "other"), ("hole", "hole.kind", KeyError), ("hole", "severity", "info"),
    ("hole", "alarm", False), ("hole", "about", "blind:1"),
    ("watch", "result.exit", KeyError), ("watch", "result.word", "FINISHED"), ("watch", "counts.blind", KeyError),
    ("heartbeat", "counts.knocks", -1), ("heartbeat", "result.word", "SILENT"), ("heartbeat", "state", 1),
    ("knock", "knocked.status", KeyError), ("knock", "knocked.title", 3), ("tree", "subject.benign", "yes"),
    ("tree", "subject.tree", KeyError), ("tree", "about", "watch"),
]


@pytest.mark.parametrize("kind, path, value", CHANGES, ids=["%s-%s-%r" % c for c in CHANGES])
def test_e6_check_names_the_key_of_a_built_event_with_one_value_changed(runs, kind, path, value):
    run = "C" if kind == "hole" else "B"
    ev = pick(runs, run, kind, state="end") if kind == "watch" else pick(runs, run, kind)
    assert event.check(ev) == []
    setin(path, value)(ev)
    assert any(p.startswith(path + ":") for p in event.check(ev)), event.check(ev)


def test_e6_a_builder_raises_value_error_naming_the_key_rather_than_build_a_half_event(runs):
    b = runs["B"]
    st, f = b["state"], facts(b["state"])
    entry = b["w"].findings[0]
    with pytest.raises(ValueError, match=r"rule\.attack: missing"):
        event.finding(entry, f, "2026-11-03T10:00:00.000Z", 3, "finding:1")   # no rule row: no attack
    hole = dict(runs["C"]["state"]["holes"][0])
    hole.pop("kind")
    with pytest.raises(ValueError, match=r"hole\.kind: missing"):
        event.hole(hole, facts(runs["C"]["state"]), "2026-11-03T10:00:00.000Z", 5, "hole:1")
    with pytest.raises(ValueError, match=r"result\.exit: missing"):
        event.watch_end(st, f, "2026-11-03T10:00:00.000Z", 9, None)
    with pytest.raises(ValueError, match=r"time: must be instant"):
        event.watch_start(st, f, "2026-02-30T10:00:00.000Z")


# --- E7 (C-11, B-6): the contract is a document -----------------------------------------------------------------

def section(text, head, nxt):
    return text[text.index(head):text.index(nxt)]


def key_rows(text):
    table = section(text, "## Keys", "## Mapping")
    return {m[0]: [c.strip() for c in m[1].split("|")] for m in re.findall(r"^\| `([a-z_.]+)` \|(.*)\|$", table, re.M)}


def test_e7_the_document_names_every_key_its_type_and_its_closed_values(runs):
    rows = key_rows(DOC.read_text(encoding="utf-8"))
    assert set(rows) == set(C2) | {"%s.%s" % (p, k) for p, ks in C2_PARTS.items() for k in ks}
    closed = {"kind": list(event.KINDS), "severity": list(event.SEVERITIES) + ["hole", "info"],
              "state": C4_STATES + ["start", "end"], "hole.class": ["hole", "blind spot"],
              "result.word": list(C5_WORDS.values()), "alarm": ["true", "false"]}
    for key, cells in rows.items():
        assert len(cells) == 5, (key, cells)   # key | type | values | kinds | OCSF | ECS
        assert cells[0] == "`%s`" % event.TYPES[key], key
        if key in closed:
            vals = [a or b for a, b in re.findall(r'"([^"]+)"|\b(true|false)\b', cells[1])]
            assert sorted(vals) == sorted(closed[key]), key


def test_e7_the_mapping_is_c11_s_and_no_other(runs):
    text = DOC.read_text(encoding="utf-8")
    rows = key_rows(text)
    for key, cells in rows.items():
        ocsf, ecs = (set(re.findall(r"`([^`]+)`", c)) for c in cells[3:5])
        want = C11.get(key, ({"unmapped.raqib.%s" % key}, {"raqib.%s" % key}))
        assert (ocsf, ecs) == want, key
    mapping = " ".join(section(text, "## Mapping", "## Required keys").split())
    for sentence in C11_SENTENCES:
        assert sentence in mapping, sentence


def test_e7_the_required_keys_of_each_kind(runs):
    req = section(DOC.read_text(encoding="utf-8"), "## Required keys", "## Examples")
    for kind in list(event.KINDS) + ["watch end"]:
        (row,) = re.findall(r"^\| %s \| (.*) \|$" % re.escape(kind), req, re.M)
        want = event.BASE + (event.REQUIRED["watch"] + event.REQUIRED_END if kind == "watch end"
                             else event.REQUIRED[kind])
        assert sorted(re.findall(r"`([a-z_.]+)`", row)) == sorted(want), kind
    assert set(event.REQUIRED["finding"]) >= {"rule.attack", "alarm"} and "about" in event.BASE


def examples(runs):
    """{label: (event, run's home)}: the document's examples, one per kind and per source-finding state."""
    def first(run, test):
        r = runs[run]
        return next(e for e in r["events"] if test(e)), r["home"]
    out = {"finding": first("B", lambda e: e["kind"] == "finding"),
           "finding: HOST-RHYTHM": first("R", lambda e: e["kind"] == "finding"),
           "note": first("A", lambda e: e["kind"] == "note" and "subject" in e),
           "tree": first("B", lambda e: e["kind"] == "tree"),
           "hole": first("C", lambda e: e["kind"] == "hole" and e["about"].startswith("hole:")),
           "hole: blind spot": first("B", lambda e: e["about"] == "blind:1"),
           "knock": first("B", lambda e: e["kind"] == "knock"),
           "heartbeat": (next(e for e in runs["B"]["moments"][-1]["events"] if e["kind"] == "heartbeat"),
                         runs["B"]["home"]),
           "watch start": first("B", lambda e: e["kind"] == "watch" and e["state"] == "start"),
           "watch end": first("B", lambda e: e["kind"] == "watch" and e["state"] == "end")}
    for state, run in (("settled", "B"), ("history", "D"), ("judged on another tree", "D"), ("noted", "D"),
                       ("pending at exit", "P"), ("not settled", "N")):
        out["source-finding: %s" % state] = first(run, lambda e, s=state: e["kind"] == "source-finding"
                                                  and e["state"] == s)
    return out


RUN_D = ("source-finding: history", "source-finding: judged on another tree", "source-finding: noted")


def test_e7_each_example_is_what_the_module_builds_from_its_named_run(runs):
    text = DOC.read_text(encoding="utf-8")
    found = dict(re.findall(r"^### example: (.+?)\n(?:.*\n)*?```json\n(.+?)\n```", text, re.M))
    ex = examples(runs)
    assert set(found) == set(ex)
    for label, (ev, home) in ex.items():
        doc, built_ = json.loads(found[label]), pathless(ev, home)
        assert event.check(doc) == []
        if label in RUN_D:   # two os follows: which source finding the watch lists first varies from run to run
            assert doc["about"].startswith("source-finding:") and doc["id"] == "%s:%d" % (doc["watch"]["run"], doc["n"])
            doc, built_ = ({k: v for k, v in e.items() if k not in ("id", "n", "about")} for e in (doc, built_))
            assert doc == built_, label
        else:
            assert found[label] == event.line(built_), label


def test_e7_the_document_says_paths_ids_and_what_snapshot_is_not():
    text = " ".join(DOC.read_text(encoding="utf-8").split()).lower()
    for words in ("a path is the machine's", "unique within a host", "is not how a running watch says events",
                  "a catalog rule's file says why", "may declare none"):
        assert words in text, words


def test_e7_no_real_host_user_or_address_in_the_document():
    text = DOC.read_text(encoding="utf-8")
    for addr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        assert addr.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), addr
    assert set(re.findall(r'"host":"([^"]*)"', text)) <= {HOST}
    assert set(re.findall(r"Users\\\\+([A-Za-z0-9_.-]+)", text)) <= {"user"}


# --- E8 (C-12): the same entries, the same lines, on every platform ----------------------------------------------

def test_e8_the_same_entries_give_the_same_lines_and_another_home_the_same_values(runs, tmp_path):
    b = runs["B"]
    again = event.snapshot(json.loads(json.dumps(b["state"])), facts(b["state"]), b["state"]["updated"],
                           json.loads(json.dumps(b["knocks"])), TABLE, end=True, exit=b["code"])
    assert [event.line(e) for e in again] == [event.line(e) for e in b["events"]]   # byte for byte
    for e in b["events"]:
        ln = event.line(e)
        assert ln.isascii() and "\n" not in ln and ln.startswith('{"about":') and json.loads(ln) == e
    other = run_b(tmp_path)   # the same fixture run in another home: the same values where no path enters
    assert [pathless(e, tmp_path) for e in other["events"]] == [pathless(e, b["home"]) for e in b["events"]]


# --- E4 of M10.1: the ATT&CK ids are declared (B-5), unchanged ---------------------------------------------------

def test_b5_every_rule_declares_b5_s_table_exactly():
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
def test_b5_the_engine_validates_attack_when_present(tmp_path, attack, note, word):
    text = (CATALOG_DIR / "NET-TOOL.yaml").read_text(encoding="ascii").replace("attack: [T1105, T1048]\n", "")
    add = ("attack: %s\n" % attack if attack else "") + ("attack_note: %s\n" % note if note else "")
    (tmp_path / "NET-TOOL.yaml").write_text(text.replace("severity: medium\n", add + "severity: medium\n", 1),
                                            encoding="ascii")
    with pytest.raises(engine.RuleError, match=re.escape(word)):
        engine.load_rule(tmp_path / "NET-TOOL.yaml")


def test_b5_a_sub_technique_loads(tmp_path):
    text = (CATALOG_DIR / "NET-TOOL.yaml").read_text(encoding="ascii")
    (tmp_path / "NET-TOOL.yaml").write_text(text.replace("[T1105, T1048]", "[T1105, T1059.004]"), encoding="ascii")
    assert engine.load_rule(tmp_path / "NET-TOOL.yaml").attack == ("T1105", "T1059.004")


def test_b5_check_rules_refuses_a_catalog_rule_with_neither(tmp_path, capsys):
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


def test_b5_a_user_rule_without_attack_loads_as_before(tmp_path):
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
