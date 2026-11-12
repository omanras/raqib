"""ADR-0007 Amendments AP and AQ: the rhythm of a tree that is not in the round.

A beat is judged in the round that reads it (AP-1): a tree quiet at the
sample, or kept by a round that could not read the connections, whose
source gained a beat gets its HostTree line by the code that writes a
candidate's (AP-2, AQ-2), from its sources' beats only (AQ-3). Every run
here is synthetic (raqib/rules/fixturegen.py), on a fake clock.
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

from raqib import discover, host, notify  # noqa: E402
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
    assert f["round"] == 5 and f["cited_seq"] == [tree_lines(rounds[4])[0]["seq"]] and f["cycle_rounds"] == [1, 3, 4]
    assert len(f["beats"]) == 3 and all(b["talk_cites"] and b["acts"] and b["acts"][0]["cites"] for b in f["beats"])
    assert any("os net seq" in c["text"] for c in f["cites"]) and any("os process seq" in c["text"] for c in f["cites"])
    assert [x["rule_id"] for x in watch.findings] == ["HOST-RHYTHM"]
    tree = watch.trees[key_of(watch)]
    assert tree["rhythm"] == f["notice"] and tree["rhythm_rounds"] == [5]
    # it knocks as a candidate's does: the same rounds with the tree a candidate at every sample
    cand_invs = [fixturegen.synthetic_inventory("rhythm-os:oscycle:%d" % k) for k in range(1, 6)]
    cwatch, _, ctext = run(home / "candidate", cand_invs, CYCLES)
    (cf,) = [x for x in cwatch.findings if x["rule_id"] == "HOST-RHYTHM"]
    assert sorted(cf) == sorted(f) and cf["notice"] == f["notice"] and cf["round"] == 5
    assert "HOST-RHYTHM in round(s) 5" in text and "HOST-RHYTHM in round(s) 5" in ctext
    # RHYTHM BEATS: none of its beats waits for the final poll, "in no round"
    assert beats_line(text).startswith("RHYTHM BEATS: beats after the last round: 0 (") and "relay-bot" not in beats_line(text)
    assert beats_line(text) == beats_line(ctext)


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
    for cls in (host.QUIET, host.KEPT):
        for change in ({}, {"named": True, "named_word": "named"}, {"source": "none", "none_rounds": 9},
                       {"candidate_before": False}):
            got = copy.deepcopy(line)
            got["input_meta"].update(change, **{"class": cls})
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


def test_e2_a_gone_tree_has_no_line(home):
    invs = quiet(5)
    for inv in invs[2:]:
        inv["processes"] = []   # its root not in the sample from round 3: gone, not quiet
    watch, rounds, _ = run(home, invs, {2: [(2, "oscycle")], 3: [(3, "oscycle")]})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 0, 0, 0] and rounds[2]["gone"]
    assert watch.findings == []


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
           "HOST-RHYTHM/negative-quiet-few-beats.json"}
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


def test_e6_the_rings_gap_two_cycles_of_two_intervals_read_in_one_round_count_once(home):
    # AQ-4 (said, not fixed): a source that hands two intervals' cycles to one round with no line between: the ring
    # has no entry for rounds 2..4, both beats go to round 1's entry, and two cycles count as one
    watch, rounds, _ = run(home, quiet(5), {4: [(2, "oscycle"), (3, "oscycle")]})
    assert [len(tree_lines(r)) for r in rounds] == [1, 0, 0, 0, 1]
    rhythm = tree_lines(rounds[4])[0]["input_meta"]["rhythm"]
    assert rhythm["cycles"] == 1 and rhythm["rounds"] == [1]
    ring = watch.rings[key_of(watch)]
    assert [e["round"] for e in ring] == [1, 5] and len(ring[0]["acts"]) == 2 and ring[1]["acts"] == []
