"""ADR-0007 Amendments AP, AQ and AR: the rhythm of a tree that is not in the round.

A beat is judged in the round that reads it (AP-1): a tree quiet at the
sample, or kept by a round that could not read the connections, or gone
(AR-2), whose source gained a beat gets its HostTree line by the code that
writes a candidate's (AP-2, AQ-2), from its sources' beats only (AQ-3); its
ring has an entry for every round from its first line on (AR-1), and its
line says what its round read (AR-3). Every run here is synthetic
(raqib/rules/fixturegen.py), on a fake clock.
"""
import copy
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, discover, host, notify, ui  # noqa: E402
from raqib.rules import engine, fixturegen  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (V-5: every HostWatch ended, no thread leaked)

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
RHYTHM = next(r for r in RULES if r.id == "HOST-RHYTHM")
PID = fixturegen.RHYTHM_PID
CYCLES = {2: [(2, "oscycle")], 3: [(3, "oscycle")], 4: [(4, "oscycle")]}   # k=3 cycles between samples
TREE_RULES = {"NEW-AGENT": False, "NEW-AGENT-UNKNOWN": False, "HOST-UNWATCHED": False, "HOST-RHYTHM": True}
LINE_ONLY = {"line_seq", "rhythm", "rhythm_rounds"}   # what a line of a tree not in the round may change on it


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def quiet(n, **kw):
    """Rounds 1..n: the tree a candidate in round 1, quiet after it (its root in the process sample)."""
    return [fixturegen.quiet_inventory(k, **kw) for k in range(1, n + 1)]


def run(home, invs, os_at):
    """The HostWatch fed invs (one per round) with a fake os follow; os_at {round: [(k, scenario)]}: the lines
    fixturegen.os_lines makes for round k, appended to the tree's os source file before that round (as
    host.fixture_rounds does). (watch, round records, report text)."""
    feed = iter(invs)
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    watch = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=fixturegen.EVERY, out=None,
                           err=io.StringIO(), clock=clock, wall=lambda: fixturegen.WALL0 + clock.t, home=str(home),
                           platform="fixture", run="test-run", sysmon=lambda: (True, "test: a synthetic os source"),
                           os_follow=host.FixtureFollow())
    seen, seq = [], 0
    for n in range(1, len(invs) + 1):
        for k, scenario in os_at.get(n, ()):
            (key,) = [x for x in watch.trees if x[0] == PID]
            src = watch.sources[key]
            src.first_pass.wait(5)
            lines, seq = fixturegen.os_lines(k, scenario, seq)
            with open(src.path, "a", encoding="ascii", newline="\n") as f:
                f.write("".join(json.dumps(x, separators=(",", ":")) + "\n" for x in lines))
        before = watch.round_lines[-1] if watch.round_lines else None
        watch.tick(wait=30)
        if watch.round_lines and watch.round_lines[-1] is not before:
            seen.append(watch.round_lines[-1])
        clock.t += watch.every
    text, _ = watch.finish()
    return watch, seen, text


def cand(n):
    """Rounds 1..n: the same tree a candidate at every sample (a line in every round)."""
    return [fixturegen.synthetic_inventory("rhythm-os:oscycle:%d" % k) for k in range(1, n + 1)]


def gone_from(invs, g):
    """The same rounds, the tree's root not in the process sample from round g on: gone, not quiet."""
    out = copy.deepcopy(invs)
    for inv in out[g - 1:]:
        inv["processes"] = []
    return out


def arriving(n):
    """Rounds 1..n: no tree in round 1; the tree arrives in round 2 as an act-root (it acts, it is not seen
    talking: not history, never a candidate); quiet after it (its root in the sample)."""
    first = fixturegen.quiet_inventory(1)
    first["candidates"], first["processes"] = [], []
    return [first, fixturegen.rhythm_inventory("notalk", 2, sampled=True)] + [
        fixturegen.quiet_inventory(k) for k in range(3, n + 1)]


def by_value(f):
    """A HOST-RHYTHM finding's rounds and cites, without the seqs (a round with no line has none)."""
    return (f["round"], f["cycle_rounds"], [(b["talk_round"], b["round"]) for b in f["beats"]],
            [(c["round"], c["src"], c["line"], c["text"]) for c in f["cites"]])


def tree_lines(record):
    return [l for l in record["lines"] if l["tool"] == "HostTree"]


def key_of(watch):
    (key,) = [k for k in watch.trees if k[0] == PID]
    return key


def beats_line(text):
    return next(x for x in text.splitlines() if x.startswith("RHYTHM BEATS:"))


def retype(invs, image, exe):
    """The same rounds, the tree another program (its image and path)."""
    out = copy.deepcopy(invs)
    for inv in out:
        for t in inv["candidates"] + inv["processes"]:
            t["image"] = image
            if "exe" in t:
                t["exe"] = exe
    return out


# --- E1 (AP-2): the FOR case, through rounds and the report ---------------------------------------------------------

def test_e1_a_quiet_trees_cycles_between_samples_fire_once_in_the_round_that_reads_the_third(home):
    watch, rounds, text = run(home, quiet(5), CYCLES)
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 1, 1]   # round 2: quiet, no beat yet: no line
    for r in rounds[2:]:
        (line,) = tree_lines(r)
        meta = line["input_meta"]
        assert meta["class"] == host.QUIET and meta["was"] == host.QUIET and meta["tree"] not in r["trees"]
        assert (meta["rhythm"]["k"], meta["rhythm"]["w"], meta["rhythm"]["r"]) == (3, 30, 10)   # the same K, W, R
    assert [tree_lines(r)[0]["input_meta"]["rhythm"]["cycles"] for r in rounds[2:]] == [1, 2, 3]
    (f,) = [f for f in watch.findings if f["rule_id"] == "HOST-RHYTHM"]   # once
    assert f["round"] == 5 and f["cited_seq"] == [tree_lines(rounds[4])[0]["seq"]] and f["cycle_rounds"] == [2, 3, 4]
    assert len(f["beats"]) == 3 and all(b["talk_cites"] and b["acts"] and b["acts"][0]["cites"] for b in f["beats"])
    assert any("os net seq" in c["text"] for c in f["cites"]) and any("os process seq" in c["text"] for c in f["cites"])
    assert [x["rule_id"] for x in watch.findings] == ["HOST-RHYTHM"]
    tree = watch.trees[key_of(watch)]
    assert tree["rhythm"] == f["notice"] and tree["rhythm_rounds"] == [5]
    # AR-5: it knocks as a candidate's does, by value: the same rounds with the tree a candidate at every sample
    cwatch, _, ctext = run(home / "candidate", cand(5), CYCLES)
    (cf,) = [x for x in cwatch.findings if x["rule_id"] == "HOST-RHYTHM"]
    assert sorted(cf) == sorted(f) and cf["notice"] == f["notice"] and by_value(cf) == by_value(f)
    assert (cf["round"], cf["cycle_rounds"], cf["destination"]) == (5, [2, 3, 4], f["destination"])
    # AR-1: round 2 had no line of the quiet tree: its cites name the round, no seq; the candidate's have one
    assert {c["round"] for c in f["cites"] if "seq" not in c} == {2} and all("seq" in c for c in cf["cites"])
    assert "HOST-RHYTHM in round(s) 5" in text and "HOST-RHYTHM in round(s) 5" in ctext
    # RHYTHM BEATS: none of its beats waits for the final poll, "in no round"
    assert beats_line(text).startswith("RHYTHM BEATS: beats after the last round: 0 (") and "relay-bot" not in beats_line(text)
    assert beats_line(text) == beats_line(ctext)


def test_e1_ar1_a_tree_quiet_for_r_minus_1_rounds_then_k_cycles_fires_as_a_candidate_every_round_does(home):
    # the review's case: a candidate in round 1, no beat in rounds 2..11, one cycle in each of intervals 11, 12, 13
    late = {11: [(11, "oscycle")], 12: [(12, "oscycle")], 13: [(13, "oscycle")]}
    watch, rounds, text = run(home, quiet(14), late)
    cwatch, crounds, ctext = run(home / "candidate", cand(14), late)
    assert [len(tree_lines(r)) for r in rounds] == [1] + [0] * 10 + [1, 1, 1]
    assert [tree_lines(r)[0]["input_meta"]["rhythm"]["cycles"] for r in rounds[11:]] == [1, 2, 3]
    (f,) = [x for x in watch.findings if x["rule_id"] == "HOST-RHYTHM"]
    (cf,) = [x for x in cwatch.findings if x["rule_id"] == "HOST-RHYTHM"]
    assert f["round"] == cf["round"] == 14 and f["cycle_rounds"] == cf["cycle_rounds"] == [11, 12, 13]
    assert by_value(f) == by_value(cf)
    # each cycle cites the round of its beats: round 11 had no line of the quiet tree (no seq), 12 and 13 had
    assert [(b["talk_round"], b["round"], b["seq"]) for b in f["beats"]] == [
        (11, 11, None), (12, 12, tree_lines(rounds[11])[0]["seq"]), (13, 13, tree_lines(rounds[12])[0]["seq"])]
    c11 = next(c for c in f["cites"] if c["round"] == 11)
    assert "seq" not in c11 and "round 11 %s:%s" % (c11["src"], c11["line"]) in text
    assert "HOST-RHYTHM in round(s) 14" in text and "HOST-RHYTHM in round(s) 14" in ctext
    assert beats_line(text).startswith("RHYTHM BEATS: beats after the last round: 0 (") and beats_line(text) == beats_line(
        ctext)
    # the ring: R entries, one per round, the empty ones with their round's own interval and no seq
    ring = watch.rings[key_of(watch)]
    assert [e["round"] for e in ring] == list(range(5, 15))
    assert [e["seq"] for e in ring] == [None] * 7 + [tree_lines(r)[0]["seq"] for r in rounds[11:]]
    assert all(e["from"] == watch.rings[key_of(watch)][i - 1]["at"] for i, e in enumerate(ring) if i)


def test_e1_ar1_must_not_touch_a_tree_with_a_line_in_every_round_has_the_ring_it_had(home):
    watch, rounds, _ = run(home, cand(14), {11: [(11, "oscycle")], 12: [(12, "oscycle")], 13: [(13, "oscycle")]})
    ring = watch.rings[key_of(watch)]
    # no entry is added: each entry is a round's line (its seq), the last R of them
    assert [(e["round"], e["seq"]) for e in ring] == [
        (r["round"], tree_lines(r)[0]["seq"]) for r in rounds[4:]] and None not in [e["seq"] for e in ring]
    for r in rounds:   # and a candidate's line carries no key of a line of a tree not in the round
        (line,) = tree_lines(r)
        assert not {"read_talks", "read_acts", "read_cites"} & set(line["input_meta"]["rhythm"])


# --- E2 (AP-2): what it must not touch -------------------------------------------------------------------------------

def test_e2_a_quiet_line_is_no_arrival_and_changes_no_trees_history_candidate_before_or_first_round(home):
    watch, rounds, _ = run(home, quiet(5), CYCLES)
    still, srounds, _ = run(home / "still", quiet(5), {})
    assert not [f for f in watch.findings if f["rule_id"] in ("NEW-AGENT", "NEW-AGENT-UNKNOWN")]
    for r in rounds:
        assert r["new"] == [] and r["back"] == []
    a, b = watch.trees[key_of(watch)], still.trees[key_of(still)]
    def here(v, root):   # the two runs' homes differ (the source file's path): the rest is compared as it is
        return v.replace(str(root), "HOME") if isinstance(v, str) else v
    assert {k for k in set(a) | set(b) if here(a.get(k), home) != here(b.get(k), home / "still")} <= LINE_ONLY
    assert (a["history"], a["candidate_round"], a["first_round"], a["rounds_seen"], a["last_round"]) == (
        b["history"], b["candidate_round"], b["first_round"], b["rounds_seen"], b["last_round"]) == (True, 1, 1, 1, 1)
    assert a["quiet"] is True and a["present"] is False and key_of(watch) in watch.quiet
    assert watch.prev_class == still.prev_class
    for r in rounds[2:]:
        meta = tree_lines(r)[0]["input_meta"]
        assert meta["candidate_before"] is True and meta["history"] is True   # there at the start: history, kept


def test_e2_what_each_rule_that_reads_a_host_tree_line_gives_on_a_quiet_or_kept_line():
    readers = {r.id for r in RULES
               if "HostTree" in (ROOT / "raqib" / "rules" / "catalog" / ("%s.yaml" % r.id)).read_text(encoding="utf-8")}
    assert readers == set(TREE_RULES)
    doc = json.loads((ROOT / "tests" / "fixtures" / "rules" / "HOST-RHYTHM" / "positive-quiet-three-cycles.json")
                     .read_text(encoding="ascii"))
    (line,) = doc["lines"]
    # AR-5 (S-3): an arrival's other fields (not history, never a candidate; HOST-UNWATCHED's two rounds): on a
    # candidate's line each arrival rule fires, so on a line of a tree not in the round only its class stops it
    arrival = {"history": False, "candidate_before": False}
    changes = (({}, "NEW-AGENT-UNKNOWN"), ({"named": True, "named_word": "named"}, "NEW-AGENT"),
               ({"source": "none", "none_rounds": 2}, "HOST-UNWATCHED"))
    for change, rid in changes:
        got = copy.deepcopy(line)
        got["input_meta"].update(arrival, **change)
        got["input_meta"]["class"] = "candidate"
        assert engine.judge(next(r for r in RULES if r.id == rid), [got], {})[0], rid
    for cls in (host.QUIET, host.KEPT, host.GONE):
        for change, _ in changes:
            got = copy.deepcopy(line)
            got["input_meta"].update(arrival, **change)
            got["input_meta"]["class"] = cls
            for rule in RULES:
                if rule.id in TREE_RULES:
                    fires = bool(engine.judge(rule, [got], {})[0])
                    assert fires == (TREE_RULES[rule.id] and not change.get("named")), (rule.id, cls, change)
    for rid in ("NEW-AGENT", "NEW-AGENT-UNKNOWN", "HOST-UNWATCHED"):   # the arrival rules read the candidate only
        text = (ROOT / "raqib" / "rules" / "catalog" / ("%s.yaml" % rid)).read_text(encoding="utf-8")
        assert "{field: input_meta.class, eq: candidate}" in text


def test_e2_a_quiet_tree_with_no_new_beat_has_no_line(home):
    _, rounds, text = run(home, quiet(5), {})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 0, 0, 0] and all(r["quiet"] for r in rounds[1:])


def test_e2_ar2_a_gone_tree_whose_source_gained_a_beat_gets_its_line_class_gone(home):
    watch, rounds, text = run(home, gone_from(quiet(5), 3), {2: [(2, "oscycle")], 3: [(3, "oscycle")]})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 1, 0]   # round 5: no new beat, no line
    word = tree_lines(rounds[0])[0]["input_meta"]["tree"]
    assert rounds[2]["gone"] == [word] and rounds[3]["gone"] == []   # gone in round 3, said once
    for r, cycles in zip(rounds[2:4], (1, 2)):
        meta = tree_lines(r)[0]["input_meta"]
        assert meta["class"] == host.GONE and meta["tree"] not in r["trees"] and meta["rhythm"]["cycles"] == cycles
    assert watch.findings == [] and beats_line(text).startswith("RHYTHM BEATS: beats after the last round: 0 (")


def test_e2_ar2_a_tree_that_makes_k_cycles_in_its_last_intervals_and_exits_fires_on_its_gone_line(home):
    watch, rounds, text = run(home, gone_from(quiet(5), 4), CYCLES)
    assert [tree_lines(r)[0]["input_meta"]["class"] for r in rounds[2:]] == [host.QUIET, host.GONE, host.GONE]
    (f,) = watch.findings
    assert (f["rule_id"], f["round"], f["cycle_rounds"]) == ("HOST-RHYTHM", 5, [2, 3, 4])
    assert f["cited_seq"] == [tree_lines(rounds[4])[0]["seq"]] and "HOST-RHYTHM in round(s) 5" in text
    # the same beats on a tree that stays quiet: the same finding by value
    qwatch, _, _ = run(home / "quiet", quiet(5), CYCLES)
    (qf,) = qwatch.findings
    assert by_value(qf) == by_value(f) and qf["notice"] == f["notice"]


def test_e2_ar2_a_gone_tree_with_no_new_beat_has_no_line(home):
    _, rounds, text = run(home, gone_from(quiet(5), 3), {})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 0, 0, 0] and rounds[2]["gone"]


def test_e2_e5_an_arriving_tree_quiet_or_gone_with_beats_makes_no_arrival_finding_through_rounds(home):
    # AR-5 (S-3): the real risk case: an act-root that arrived during the watch (not history, never a candidate)
    late = {3: [(3, "oscycle")], 4: [(4, "oscycle")], 5: [(5, "oscycle")]}
    for name, invs, cls in (("quiet", arriving(6), host.QUIET), ("gone", gone_from(arriving(6), 4), host.GONE)):
        watch, rounds, text = run(home / name, invs, late)
        assert rounds[1]["new"] == [] and all(r["new"] == [] and r["back"] == [] for r in rounds)
        metas = [tree_lines(r)[0]["input_meta"] for r in rounds[4:]]
        assert [m["class"] for m in metas] == [cls, cls] and metas[-1]["rhythm"]["fires"] is True
        assert all(m["history"] is False and m["candidate_before"] is False and m["named"] is False for m in metas)
        assert [(f["rule_id"], f["round"]) for f in watch.findings] == [("HOST-RHYTHM", 6)], name
        assert "HOST-RHYTHM in round(s) 6" in text
        assert not [x for x in ("NEW-AGENT in round", "NEW-AGENT-UNKNOWN in round", "HOST-UNWATCHED in round")
                    if x in text], name


def test_e3_ar3_a_line_of_a_tree_not_in_the_round_says_what_its_round_read(home):
    watch, rounds, _ = run(home, quiet(5), CYCLES)
    first = tree_lines(rounds[0])[0]["input_meta"]   # the candidate's line: the sample's acts, endpoints, cites
    assert first["acts"] == 1 and first["endpoints"] == ["192.0.2.10:443"] and first["cites"]
    assert not {"read_talks", "read_acts", "read_cites"} & set(first["rhythm"])
    for r in rounds[2:]:
        meta = tree_lines(r)[0]["input_meta"]
        assert (meta["acts"], meta["endpoints"], meta["cites"]) == (0, [], [])   # nothing of an earlier sample
        assert set(meta) == set(first) and set(meta["rhythm"]) == set(first["rhythm"]) | {
            "read_talks", "read_acts", "read_cites"}
        rh = meta["rhythm"]
        assert (rh["read_talks"], rh["read_acts"], rh["talks"], rh["acts"]) == (1, 1, [], 0)   # in the round before's entry (its interval)
        assert [c["text"].split(" seq ")[0] for c in rh["read_cites"]] == ["os net", "os process"]
        assert all(c["src"].endswith(".jsonl") and isinstance(c["line"], int) for c in rh["read_cites"])


def test_e5_ar5_a_gone_trees_waiting_beats_are_in_the_report_where_no_round_read_them(home):
    # gone in round 3; the cycle of interval 2 is read by round 3 (a gone line); interval 5's waits for the final poll
    watch, rounds, text = run(home, gone_from(quiet(5), 3), {2: [(2, "oscycle")], 5: [(5, "oscycle")]})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 0, 0]
    word = tree_lines(rounds[0])[0]["input_meta"]["tree"]
    assert watch.late_beats == {word: 2}
    assert beats_line(text).startswith("RHYTHM BEATS: beats after the last round: 2 (") and (
        "; %s: 2;" % word) in beats_line(text)


def test_e2_a_named_quiet_trees_rhythm_does_not_fire(home):
    watch, rounds, _ = run(home, retype(quiet(5), "claude", "C:\\Users\\user\\AppData\\Local\\claude\\claude.exe"),
                           CYCLES)
    meta = tree_lines(rounds[4])[0]["input_meta"]
    assert meta["class"] == host.QUIET and meta["named"] is True and meta["rhythm"]["cycles"] == 3
    assert watch.findings == []   # not HOST-RHYTHM's (named: NEW-AGENT's), and a quiet line is no arrival


def test_e2_a_benign_quiet_trees_rhythm_is_judged_as_a_benign_candidates(home):
    exe = "C:\\Windows\\explorer.exe"
    watch, rounds, _ = run(home, retype(quiet(5), "explorer", exe), CYCLES)
    cand = [fixturegen.synthetic_inventory("rhythm-os:oscycle:%d" % k) for k in range(1, 6)]
    for inv in cand:
        inv["processes"] = [{"pid": PID, "image": "explorer", "started": inv["candidates"][0]["started"]}]
    cwatch, crounds, _ = run(home / "candidate", retype(cand, "explorer", exe), CYCLES)
    meta, cmeta = tree_lines(rounds[4])[0]["input_meta"], tree_lines(crounds[4])[0]["input_meta"]
    assert meta["benign"] is True and cmeta["benign"] is True and meta["class"] == host.QUIET
    got = [(f["rule_id"], f["round"], f["severity"], f["notice"]) for f in watch.findings]
    assert got == [(f["rule_id"], f["round"], f["severity"], f["notice"]) for f in cwatch.findings]
    assert [g[0] for g in got] == ["HOST-RHYTHM"]   # its rhythm is judged


# --- E6 (AQ-1 to AQ-4) ----------------------------------------------------------------------------------------------

def test_e6_the_fixtures_made_before_aq_carry_no_process_sample():
    scenarios, _ = fixturegen.plan(RHYTHM)
    new = {"HOST-RHYTHM/positive-quiet-three-cycles.json", "HOST-RHYTHM/negative-quiet-no-cycle.json",
           "HOST-RHYTHM/negative-quiet-few-beats.json", "HOST-RHYTHM/positive-gone-three-cycles.json",
           "HOST-RHYTHM/negative-gone-few-beats.json"}
    assert new <= set(scenarios)
    for name, (names, _) in scenarios.items():
        for n in names:
            inv = fixturegen.synthetic_inventory(n)
            if inv is not None:
                assert ("processes" in inv) == (name in new), (name, n)   # the shipped ones are made as they were


def test_e6_a_kept_tree_with_a_new_beat_gets_its_line_as_a_quiet_one_does(home):
    invs = quiet(5)
    for inv in invs[1:]:
        inv["incomplete"] = ["no connection source read (test: the TCP table)"]
    watch, rounds, _ = run(home, invs, CYCLES)
    qwatch, qrounds, _ = run(home / "quiet", quiet(5), CYCLES)
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 1, 1]
    for r, q in zip(rounds[2:], qrounds[2:]):
        meta, qmeta = tree_lines(r)[0]["input_meta"], tree_lines(q)[0]["input_meta"]
        assert meta["class"] == host.KEPT and r["not_judged"] == [meta["tree"]]
        assert meta["rhythm"] == qmeta["rhythm"]
    assert [(f["rule_id"], f["round"]) for f in watch.findings] == [("HOST-RHYTHM", 5)]
    assert [(f["rule_id"], f["round"]) for f in qwatch.findings] == [("HOST-RHYTHM", 5)]


def test_e6_a_line_for_a_tree_not_in_the_round_leaves_its_connections_and_children_as_the_sample_knows_them(home):
    def invs():   # in round 1 and again in round 5 (the same connection, no bytes read, the same child); quiet between
        out = quiet(4)
        out.append(fixturegen.rhythm_inventory("between", 5, bytes_moved=False, sampled=True))
        return out
    watch, rounds, _ = run(home, invs(), {2: [(2, "oscycle")], 3: [(3, "oscycle")]})
    still, srounds, _ = run(home / "still", invs(), {})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 1, 1] and [len(tree_lines(r)) for r in srounds] == [
        1, 0, 0, 0, 1]
    key = key_of(watch)
    assert watch.conn_state[key] == still.conn_state[key_of(still)] and watch.conn_state[key]["open"]
    assert watch.kids[key] == still.kids[key_of(still)] and watch.kids[key]
    for r in (rounds[4], srounds[4]):   # back in a round: nothing is new that was old
        meta = tree_lines(r)[0]["input_meta"]
        assert meta["class"] == "candidate" and meta["rhythm"]["talks"] == [] and meta["rhythm"]["acts"] == 0


def test_e1_ar1_two_cycles_of_two_intervals_read_in_one_round_count_twice(home):
    # AQ-4's merge, undone by AR-1: a source hands two intervals' cycles to one round with no line between; the ring
    # has an empty entry for rounds 2..4 with their own intervals, so each beat goes to its own round
    watch, rounds, _ = run(home, quiet(5), {4: [(2, "oscycle"), (3, "oscycle")]})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 0, 0, 1]
    rhythm = tree_lines(rounds[4])[0]["input_meta"]["rhythm"]
    assert rhythm["cycles"] == 2 and rhythm["rounds"] == [2, 3] and rhythm["read_acts"] == 2
    ring = watch.rings[key_of(watch)]
    assert [(e["round"], len(e["acts"]), e["seq"] is None) for e in ring] == [
        (1, 0, False), (2, 1, True), (3, 1, True), (4, 0, True), (5, 0, False)]


# --- ADR-0007 Amendment AS (the Table's, after the REDO's review) -----------------------------------------------

AS_CYCLES = {2: [(2, "oscycle")], 7: [(7, "oscycle")], 8: [(8, "oscycle")]}   # one cycle, a gap, two more


def test_as4_a_gap_and_a_return_cycles_on_both_sides_of_rounds_with_no_line_count_as_a_candidates_do(home):
    # a candidate in round 1, quiet with one cycle (interval 2, read in round 3), no beat and no line in rounds
    # 4..6, a candidate again from round 7 with two more cycles: the ring has every round, so the three cycles are
    # in the last R rounds and the finding is, by value, that of the tree a candidate in every round
    watch, rounds, text = run(home, quiet(6) + cand(9)[6:], AS_CYCLES)
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 1, 0, 0, 0, 1, 1, 1]
    metas = [tree_lines(r)[0]["input_meta"] for r in rounds if tree_lines(r)]
    assert [(m["round"], m["class"], m["was"]) for m in metas] == [
        (1, "candidate", "absent"), (3, host.QUIET, host.QUIET), (7, "candidate", host.QUIET),
        (8, "candidate", "candidate"), (9, "candidate", "candidate")]
    assert [m["rhythm"]["rounds"] for m in metas] == [[], [2], [2], [2, 7], [2, 7, 8]]
    assert [(e["round"], e["seq"] is None) for e in watch.rings[key_of(watch)]] == [
        (1, False), (2, True), (3, False), (4, True), (5, True), (6, True), (7, False), (8, False), (9, False)]
    (f,) = watch.findings
    assert (f["rule_id"], f["round"], f["cycle_rounds"]) == ("HOST-RHYTHM", 9, [2, 7, 8])
    cwatch, _, ctext = run(home / "candidate", cand(9), AS_CYCLES)
    (cf,) = cwatch.findings
    assert by_value(f) == by_value(cf)
    assert beats_line(text) == beats_line(ctext) and beats_line(text).startswith(
        "RHYTHM BEATS: beats after the last round: 0 (")


def test_as3_a_beat_of_a_round_with_no_line_is_said_by_its_round_alone_in_the_window_and_the_page(home):
    watch, rounds, text = run(home, quiet(6) + cand(9)[6:], AS_CYCLES)
    (f,) = watch.findings
    assert [(b["talk_round"], b["talk_seq"], b["round"], b["seq"]) for b in f["beats"]][0] == (2, None, 2, None)
    line = app.host_finding_line(f)
    assert "; talk round 2, act round 2; talk round 7 seq " in line and "None" not in line and "null" not in line
    assert app.beat_text({"talk_round": 4, "talk_seq": 11, "round": 5, "seq": 12}) == (
        "talk round 4 seq 11, act round 5 seq 12")
    assert app.beat_text({"talk_round": 4, "talk_seq": None, "round": 5, "seq": 12}) == "talk round 4, act round 5 seq 12"
    said = ui._cites_text(f["cites"])
    assert "round 2 " in said and "seq null" not in said and "seq None" not in said and " seq " in said
    assert ui._cites_text([{"round": 4, "seq": None, "src": "a.jsonl", "line": 2},
                           {"round": 5, "seq": 9, "src": "a.jsonl", "line": 3}, {"src": "b", "line": 1}]) == (
        "round 4 a.jsonl:2 round 5 seq 9 a.jsonl:3 b:1")
    state = json.loads(json.dumps(watch.state(fixturegen.WALL0)))
    page = ui.host_page(state)
    assert "seq null" not in page and "seq None" not in page


# --- M7.18 (ADR-0007 Amendment AT, AT-1): HOST-RHYTHM is high, on a line of a tree not in the round too -------------

def test_m718_a_quiet_or_gone_trees_finding_is_high_as_a_candidates_and_a_named_one_is_still_not_judged(home):
    cwatch, _, ctext = run(home / "candidate", cand(5), CYCLES)
    (cf,) = cwatch.findings
    for name, invs in (("quiet", quiet(5)), ("gone", gone_from(quiet(5), 4))):
        watch, rounds, text = run(home / name, invs, CYCLES)
        (f,) = watch.findings
        assert (f["rule_id"], f["round"], f["severity"]) == ("HOST-RHYTHM", 5, "high"), name
        assert (cf["severity"], cf["notice"]) == (f["severity"], f["notice"]) and by_value(cf) == by_value(f), name
        assert app.host_finding_line(f).startswith("HOST-RHYTHM [high] round 5: "), name
        view = app.host_watch_view(json.loads(json.dumps(watch.state(fixturegen.WALL0))))
        assert [x.split(":", 1)[0] for x in view["findings"]] == ["HOST-RHYTHM [high] round 5"], name
        said = [x for x in text.splitlines() if x.startswith("  [") and " HOST-RHYTHM " in x]
        assert [x.split(" (", 1)[0] for x in said] == ["  [high] HOST-RHYTHM round 5"], name
    assert [x.split(" (", 1)[0] for x in ctext.splitlines() if x.startswith("  [high] HOST-RHYTHM ")] == [
        "  [high] HOST-RHYTHM round 5"]
    # a named quiet tree with the same rhythm: still not HOST-RHYTHM's
    named, nrounds, _ = run(home / "named", retype(quiet(5), "claude",
                                                   "C:\\Users\\user\\AppData\\Local\\claude\\claude.exe"), CYCLES)
    assert tree_lines(nrounds[4])[0]["input_meta"]["named"] is True and named.findings == []
