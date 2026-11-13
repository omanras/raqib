"""ADR-0007 Amendment AY: a process under a tree the watch holds is that tree's.

The field case (AX-4): an agent whose connection to its model is closed at
every sample after its first is quiet; the inventory's anchor ("every
process goes to its nearest talking ancestor") gives its commands to the
runner's worker above it, which talks all the time. AY-1: such a child is
the held tree's (one function, before any line of the round); AY-2: it is
in that tree's own host record, judged there, and an act beat of its ring;
the tree stays quiet. Amendment AZ: the held root itself stays its parent's
act (AZ-1); nothing is given to a tree whose host record cannot be written
(AZ-2); a child is judged as one tree's child once (AZ-3); its line names the
tree the inventory had it under (AZ-4). Every run here is synthetic (fixturegen.held_inventory),
on a fake clock.
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
WORKER, AGENT = fixturegen.HELD_ANCESTOR_PID, fixturegen.HELD_PID
K = host.RHYTHM_K
N = K + 3          # rounds: on main's code the worker's cycles reach K by round K + 1
NET = 3            # the round whose new child is curl


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


def run(home, invs, between=None, os_source=True):
    """The HostWatch fed invs (one per round) with a fake os follow (os_source False: none, each tree's source
    the host's record): (watch, round records). between(watch, k) runs after round k."""
    feed = iter(invs)
    clock = host.FixtureClock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    sysmon = (True, "test: a synthetic os source") if os_source else (False, "test: no os source")
    watch = host.HostWatch(lambda: next(feed), CATALOG, RULES, notifier, every=fixturegen.EVERY, out=None,
                           err=io.StringIO(), clock=clock, wall=lambda: fixturegen.WALL0 + clock.t, home=str(home),
                           platform="fixture", run="test-run", sysmon=lambda: sysmon,
                           os_follow=host.FixtureFollow())
    seen = []
    for k, _ in enumerate(invs, 1):
        before = watch.round_lines[-1] if watch.round_lines else None
        watch.tick(wait=30)
        if watch.round_lines and watch.round_lines[-1] is not before:
            seen.append(watch.round_lines[-1])
        if between:
            between(watch, k)
        clock.t += watch.every
    watch.finish()
    return watch, seen


def field(n=N, **kw):
    return [fixturegen.held_inventory(k, net_round=NET, **kw) for k in range(1, n + 1)]


def key_of(watch, pid):
    (key,) = [k for k in watch.trees if k[0] == pid]
    return key


def tree_lines(seen, pid=None):
    return [l["input_meta"] for r in seen for l in r["lines"]
            if l["tool"] == "HostTree" and (pid is None or l["input_meta"]["pid"] == pid)]


def record(watch, pid):
    """The lines of the host's own record of one tree (its host_path)."""
    src = watch.sources[key_of(watch, pid)]
    path = Path(src.host_path) if src.host_path else None
    return [json.loads(x) for x in path.read_text(encoding="ascii").splitlines()] if path and path.exists() else []


def programs(watch, pid):
    return [p for l in record(watch, pid) if l["tool"] == "HostChild" for p in l["input_meta"]["command_programs"]]


def child_pids(watch, pid):
    return [c["pid"] for l in record(watch, pid) if l["tool"] == "HostChild" for c in l["input_meta"]["children"]]


def news(watch):
    """The arrivals said: (rule, pid), one per finding."""
    return sorted((f["rule_id"], f.get("pid")) for f in watch.findings if f["rule_id"] in host.NEW_RULES)


def found(watch, rule_id, pid):
    return [f for f in watch.findings + watch.source_findings if f["rule_id"] == rule_id and f.get("pid") == pid]


def shape(watch, seen):
    """What a run gives, without paths: its tree lines, its findings, the host records' children."""
    lines = [(m["round"], m["pid"], m["class"], m["acts"], m["rhythm"]["acts"], m["rhythm"]["cycles"])
             for m in tree_lines(seen)]
    findings = sorted((f["rule_id"], f.get("pid"), f.get("round")) for f in watch.findings + watch.source_findings)
    kids = {k[0]: child_pids(watch, k[0]) for k in sorted(watch.sources, key=str)}
    return lines, findings, kids


@pytest.fixture
def main_code(monkeypatch):
    """The watch as main has it: the inventory's anchor alone decides whose a child is."""
    monkeypatch.setattr(host.HostWatch, "_give_held", lambda self, inv, *a: inv)


def test_e3_the_field_case_no_rhythm_on_the_ancestor_the_children_are_the_quiet_trees(home, monkeypatch):
    calls, real = [], host.HostWatch._give_held
    monkeypatch.setattr(host.HostWatch, "_give_held", lambda self, inv, now, n: calls.append(n) or real(
        self, inv, now, n))
    watch, seen = run(home, field())
    assert calls == list(range(1, N + 1))   # one call per round
    assert not found(watch, "HOST-RHYTHM", WORKER)   # AX-4: main's code fires it here (the twin below)
    assert child_pids(watch, AGENT) == [AGENT + k for k in range(1, N + 1)]   # round 1's as a candidate, then held
    assert "curl" in programs(watch, AGENT) and "curl" not in programs(watch, WORKER)
    assert [f["rule_id"] for f in found(watch, "NET-TOOL", AGENT)] == ["NET-TOOL"]
    assert not found(watch, "NET-TOOL", WORKER)
    agent = tree_lines(seen, AGENT)
    assert [(m["round"], m["class"], m["acts"], m["rhythm"]["acts"]) for m in agent] == [(1, "candidate", 1, 0)] + [
        (n, host.QUIET, 1, 1) for n in range(2, N + 1)]   # AY-2: still quiet; each given child an act beat
    # AY-3: only round 1's talk (to its model) and round 2's act make a cycle; the later acts with no talk none
    assert [m["rhythm"]["cycles"] for m in agent] == [0] + [1] * (N - 1) and not any(m["rhythm"]["fires"] for m in agent)
    assert key_of(watch, AGENT) in watch.quiet
    assert news(watch) == []   # both trees are history here; the arrival is AZ-6's test below
    # AZ-4: the line of a given child names the candidate the inventory had it under; no other line has the key
    under = [l["input_meta"].get("inventory_tree") for l in record(watch, AGENT) if l["tool"] == "HostChild"]
    assert under == [None] + [host.tree_word(key_of(watch, WORKER))] * (N - 1)
    assert not [l for l in record(watch, WORKER) if "inventory_tree" in l["input_meta"]]


def test_e3_on_mains_code_the_same_rounds_fire_rhythm_on_the_ancestor(home, main_code):
    watch, seen = run(home, field())
    assert found(watch, "HOST-RHYTHM", WORKER)   # the false finding AX-4 reports
    assert child_pids(watch, AGENT) == [AGENT + 1] and "curl" in programs(watch, WORKER)


def test_az1_the_held_root_stays_its_parents_act_so_the_ancestor_stays_a_candidate(home):
    watch, seen = run(home, field())
    worker = tree_lines(seen, WORKER)
    assert [(m["round"], m["class"], m["acts"]) for m in worker] == [(n, "candidate", 1) for n in range(1, N + 1)]
    assert child_pids(watch, WORKER) == [AGENT]   # the agent's root, once; nothing under it
    assert key_of(watch, WORKER) in watch.present


def test_e1_one_function_inv_itself_when_nothing_is_taken_and_never_changed(home):
    watch, _ = run(home, field(2))
    inv = fixturegen.held_inventory(3, net_round=NET)
    before = copy.deepcopy(inv)
    got = watch._give_held(inv, 0.0, 3)
    assert inv == before and got is not inv
    assert [[a["pid"] for a in c["acts"]] for c in got["candidates"]] == [[AGENT]]   # AZ-1: the root stays
    assert [a["pid"] for a in watch.given[key_of(watch, AGENT)]] == [AGENT + 3]
    other = fixturegen.held_inventory(3, net_round=NET, talks_from=99)   # the agent a candidate: nothing taken
    assert watch._give_held(other, 0.0, 3) is other and watch.given == {}


def test_az1_a_new_talking_ancestor_above_a_held_tree_arrives_and_the_held_tree_does_not_again(home):
    # the trees are not history (both start at the watch's start); the worker first talks in round 2
    watch, seen = run(home, field(fresh=True, worker_from=2))
    assert not watch.trees[key_of(watch, AGENT)]["history"] and not watch.trees[key_of(watch, WORKER)]["history"]
    assert news(watch) == sorted([("NEW-AGENT-UNKNOWN", AGENT), ("NEW-AGENT-UNKNOWN", WORKER)])   # once each
    worker = tree_lines(seen, WORKER)
    assert [(m["round"], m["class"], m["acts"]) for m in worker] == [(n, "candidate", 1) for n in range(2, N + 1)]
    assert child_pids(watch, WORKER) == [AGENT]   # one act, the held root; none of the children under it
    assert child_pids(watch, AGENT) == [AGENT + k for k in range(1, N + 1)]
    assert not found(watch, "NET-TOOL", WORKER) and found(watch, "NET-TOOL", AGENT)


def test_az6_destruct_cmd_is_judged_on_the_held_tree(home):
    watch, _ = run(home, field(destruct_round=NET + 1))
    assert [f["rule_id"] for f in found(watch, "DESTRUCT-CMD", AGENT)] == ["DESTRUCT-CMD"]
    assert not found(watch, "DESTRUCT-CMD", WORKER) and "rm" not in programs(watch, WORKER)


def test_az6_two_held_roots_on_one_path_the_nearest_has_the_child(home):
    sub = fixturegen.HELD_SUB_PID
    watch, _ = run(home, field(sub=True))
    assert child_pids(watch, sub) == [sub + 10 + k for k in range(1, N + 1)]
    assert child_pids(watch, AGENT) == [AGENT + 1, sub] + [AGENT + k for k in range(2, N + 1)]   # sub: not new
    assert child_pids(watch, WORKER) == [AGENT]
    assert not found(watch, "HOST-RHYTHM", WORKER)


def test_az6_a_held_tree_that_is_a_candidate_again_its_given_children_are_not_new(home):
    again = NET + 2
    watch, seen = run(home, field(keep=True, talks_again=again))   # every child lives to the last round
    assert child_pids(watch, AGENT) == [AGENT + k for k in range(1, N + 1)]   # each once
    assert [f["rule_id"] for f in found(watch, "NET-TOOL", AGENT)] == ["NET-TOOL"]
    agent = tree_lines(seen, AGENT)
    assert [(m["round"], m["class"]) for m in agent] == [(1, "candidate")] + [
        (n, host.QUIET) for n in range(2, again)] + [(n, "candidate") for n in range(again, N + 1)]
    assert [m["rhythm"]["acts"] for m in agent] == [0] + [1] * (N - 1)   # only the round's new child is a beat
    assert child_pids(watch, WORKER) == [AGENT] and not found(watch, "NET-TOOL", WORKER)


@pytest.mark.parametrize("case", ["none", "ended"])
def test_az2_no_child_is_given_to_a_tree_whose_host_record_cannot_be_written(home, case):
    def between(watch, k):
        if k != 1:
            return
        key = key_of(watch, AGENT)
        if case == "none":   # no host record: nothing could be attached
            watch.sources[key] = host.TreeSource("none", "none (test: nothing could be attached)")
            watch.sources[key].error = "test: nothing could be attached"
        else:                # its host source ended with a hole
            watch.sources[key].error = "test: the source ended"
    watch, seen = run(home, field(), between=between, os_source=False)
    assert [p for p in child_pids(watch, WORKER) if p > AGENT] == [AGENT + k for k in range(2, N + 1)]   # as main
    assert found(watch, "NET-TOOL", WORKER) and not found(watch, "NET-TOOL", AGENT)
    assert [m["round"] for m in tree_lines(seen, AGENT)] == [1] and watch.given == {}
    (note,) = [h for h in watch.holes if h["kind"] == "held-not-given"]   # once for the tree
    assert note["round"] == 2 and host.tree_word(key_of(watch, AGENT)) in note["detail"]


def test_az3_a_child_once_given_is_not_new_on_the_ancestor_when_its_tree_is_gone(home):
    invs = field(NET)   # the curl of round NET is given to the agent
    given = copy.deepcopy(invs[-1]["candidates"][0]["acts"][1])
    assert given["image"] == "curl" and given["via"] == [AGENT]
    inv = fixturegen.held_inventory(NET + 1, net_round=NET, sampled_agent=False)   # the agent's root has ended
    stranger = dict(copy.deepcopy(given), pid=5399, image="bash", started=inv["candidates"][0]["acts"][1]["started"])
    orphan = dict(given, via=[])   # the system gave the still-living child a new parent: the worker
    inv["candidates"][0]["acts"] = [orphan, stranger]
    worker_row = inv["processes"][0]
    inv["processes"] = [worker_row] + [dict(worker_row, pid=a["pid"], ppid=WORKER, image=a["image"],
                                            started=a["started"]) for a in (orphan, stranger)]
    watch, seen = run(home, invs + [inv])
    assert AGENT + NET in child_pids(watch, AGENT)
    assert AGENT + NET not in child_pids(watch, WORKER) and 5399 in child_pids(watch, WORKER)   # a new one is new
    assert not found(watch, "NET-TOOL", WORKER) and found(watch, "NET-TOOL", AGENT)
    last = [m for m in tree_lines(seen, WORKER) if m["round"] == NET + 1]
    assert [m["rhythm"]["acts"] for m in last] == [1]   # the stranger's beat only


def test_e4_a_child_with_no_held_root_on_its_path_stays_its_ancestors(home):
    watch, seen = run(home, field(side=True))
    assert [5300 + k for k in range(1, N + 1)] == [p for p in child_pids(watch, WORKER) if p >= 5300]
    assert not [p for p in child_pids(watch, AGENT) if p >= 5300]
    assert child_pids(watch, AGENT) == [AGENT + k for k in range(1, N + 1)]
    assert [m["round"] for m in tree_lines(seen, WORKER)] == list(range(1, N + 1))   # still a candidate


@pytest.mark.parametrize("case", ["gone", "nested", "kept"])
def test_e4_not_touched_the_same_as_mains_code(home, monkeypatch, case):
    if case == "gone":     # the agent's root not in the sample from round 2: its orphans go as they do
        invs = field(sampled_agent=False)
    elif case == "nested":   # the agent a candidate in every round, nested in the worker
        invs = field(talks_from=N + 1)
    else:                  # rounds whose connections were not read: no tree seen talking, the agent kept
        invs = field()
        for inv in invs[1:]:
            inv.update(candidates=[], incomplete=["no connection source read (test: the TCP table)"])
            inv.pop("conn_bytes")
    (home / "on").mkdir()
    (home / "off").mkdir()
    on = shape(*run(home / "on", copy.deepcopy(invs)))
    monkeypatch.setattr(host.HostWatch, "_give_held", lambda self, inv, *a: inv)
    off = shape(*run(home / "off", copy.deepcopy(invs)))
    assert on == off
    lines, _, kids = on
    if case == "kept":   # no candidate to take from: the agent's children are in no record after round 1
        assert kids[AGENT] == [AGENT + 1] and not [l for l in lines if l[0] > 1]
    elif case == "gone":   # the orphans are the worker's, as on main's code
        assert [p for p in kids[WORKER] if p > AGENT] == [AGENT + k for k in range(2, N + 1)]
    else:   # nested: each child is the agent's as a candidate's, the worker has the agent only
        assert kids[AGENT] == [AGENT + k for k in range(1, N + 1)] and kids[WORKER] == [AGENT]


def test_e1_a_kept_tree_is_given_its_children_in_a_round_whose_connections_were_partly_read(home):
    invs = field()
    for inv in invs[1:]:   # a talker is still seen (the worker), but the round's connection record is not whole
        inv["incomplete"] = ["no connection source read (test: one of two TCP tables)"]
    watch, seen = run(home, invs)
    assert child_pids(watch, AGENT) == [AGENT + k for k in range(1, N + 1)]
    assert [(m["round"], m["class"], m["acts"]) for m in tree_lines(seen, AGENT)][1:] == [
        (n, host.KEPT, 1) for n in range(2, N + 1)]
    assert not found(watch, "HOST-RHYTHM", WORKER) and found(watch, "NET-TOOL", AGENT)
