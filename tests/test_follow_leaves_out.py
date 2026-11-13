"""M7.24 (ADR-0007 Amendment BB): an os follow does not hold what is under another tree's root.
BB-1: a tree's os follow is told at every pass (leave_out, a callable) the roots of the other trees the watch holds
with an os follow of their own under its root; it does not write an event of a process at or under such a root, and
it writes the root's own event 1 as before. With no callable, or one that returns nothing, it writes what it wrote.
BB-2: only while the root is told; the tree still knows the left-out members, so their later events are held again,
and an event written before the root was told stays. BB-3: the follow says once per root, in its own file, that it
leaves that subtree out and from which record (the session_start of that block: "left_out"); the host watch's feed
reads it without a finding, a hole or a "could not judge" note. E2, E5: the watch's side, through rounds.
SYNTHETIC: host `host`, user `user`, RFC 5737 addresses only. No test here reads the Table's review folder.
"""
import functools
import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import created, guid_of, talked  # noqa: E402
from test_host_follow_returns import START, FollowChannel, at  # noqa: E402
from test_event_logged_time import FIXTURES_BUILT, every_fixture_build  # noqa: E402
from test_one_destination import RULES  # noqa: E402

WORKER = "C:\\actions-runner\\bin\\Runner.Worker.exe"
AGENT = "C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\kimi.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
W, A, C1, C2, X, D, E = 4000, 4100, 4200, 4210, 4300, 4400, 4500
G = {p: guid_of(p) for p in (W, A, C1, C2, X, D, E)}
NESTED = (A, G[A])

PASSES = [
    [talked(10, at("07:54:00"), W, WORKER, G[W]),                                    # the worker talks
     created(11, at("07:54:01"), A, AGENT, G[A], W, WORKER, G[W], "kimi"),           # it starts the agent
     created(12, at("07:54:02"), C1, CMD, G[C1], A, AGENT, G[A], "cmd /c one")],     # before the agent is known
    [created(20, at("07:54:10"), C2, CMD, G[C2], A, AGENT, G[A], "cmd /c two"),      # the agent's: left out
     talked(21, at("07:54:11"), A, AGENT, G[A], port=50210),                         # the agent's own talk: left out
     talked(22, at("07:54:12"), E, CMD, G[E], port=50220),                           # no event 1 (c)
     created(23, at("07:54:13"), X, CMD, G[X], W, WORKER, G[W], "cmd /c worker")],   # the worker's own child
    [created(30, at("07:54:20"), D, CMD, G[D], C1, CMD, G[C1], "cmd /c three"),      # no longer told: held again
     talked(31, at("07:54:21"), C2, CMD, G[C2], port=50230),                         # a member left out earlier
     talked(32, at("07:54:22"), E, CMD, G[E], port=50221)],                          # still no event 1 (c)
]


def follow(tmp_path, told=None, passes=PASSES, name="w.jsonl"):
    """The real os_sysmon.follow of the worker's tree over the stand-in channel, one pass per element of passes;
    told(k) the roots leave_out returns at pass k (None: no callable at all). (the file's records, the calls)."""
    log, stop, calls = tmp_path / name, threading.Event(), []

    def on_pass(n, top):
        if n >= len(passes):
            stop.set()

    def leave_out():
        calls.append(len(calls) + 1)
        return told(len(calls))
    kw = {} if told is None else {"leave_out": leave_out}
    os_sysmon.follow("%d:%s" % (W, G[W]), str(log), stop, every=0.0, nt=True, since=START, on_pass=on_pass,
                     reader=FollowChannel(passes), out=open(tmp_path / "out.txt", "w"),
                     err=open(tmp_path / "err.txt", "w"), **kw)
    return [json.loads(x) for x in log.read_text().splitlines()], calls


def acts(recs):
    return [(r["tool"], r["input_meta"].get("time_record") or r["ts"][11:19]) for r in recs if r["phase"] == "pre"]


def seen(recs):
    """(tool, ts) of the pre lines: which events the file holds."""
    return [(r["tool"], r["ts"][11:19]) for r in recs if r["phase"] == "pre"]


# --- E1 (BB-1) ---------------------------------------------------------------------------------------------------------

def test_e1_bb1_a_follow_with_no_callable_or_one_that_returns_nothing_writes_byte_for_byte(tmp_path, monkeypatch):
    main, _ = follow(tmp_path, None, name="main.jsonl")
    empty, calls = follow(tmp_path, lambda k: [], name="empty.jsonl")
    assert (tmp_path / "main.jsonl").read_bytes() == (tmp_path / "empty.jsonl").read_bytes() and calls == [1, 2, 3]
    assert len(seen(main)) == 8   # every event of the tree (E's has no event 1: none of it, as on main)
    # every Sysmon fixture under tests/fixtures, built with an empty leave_out: what main's build gives, to the byte
    monkeypatch.setattr(os_sysmon, "build", functools.partial(os_sysmon.build, leave_out=[]))
    assert every_fixture_build() == FIXTURES_BUILT


def test_e1_bb1_the_subtree_under_a_told_root_is_not_written_and_the_roots_event_1_is(tmp_path):
    recs, _ = follow(tmp_path, lambda k: [NESTED])
    assert seen(recs) == [("net", "07:54:00"), ("process", "07:54:01"), ("process", "07:54:13")]   # told from pass 1
    procs = [r["input_meta"]["image"] for r in recs if r["phase"] == "pre" and r["tool"] == "process"]
    assert procs == ["kimi", "cmd"]   # the agent's event 1 (the worker started it), the worker's own child
    # a root given by its pid alone is the same root (the members' pids are kept)
    alone, _ = follow(tmp_path, lambda k: [A], name="alone.jsonl")
    assert seen(alone) == seen(recs)
    # MUST NOT TOUCH: the follow's own root is never left out, and a root that is not a pid is no root
    own, _ = follow(tmp_path, lambda k: [(W, G[W]), "x", (-1, None)], name="own.jsonl")
    main, _ = follow(tmp_path, None, name="main.jsonl")
    assert (tmp_path / "own.jsonl").read_bytes() == (tmp_path / "main.jsonl").read_bytes()


# --- E3 (BB-2): the seams ----------------------------------------------------------------------------------------------

def told_at(*ks):
    return lambda k: [NESTED] if k in ks else []


def test_e3a_bb2_what_was_written_before_the_root_was_told_stays_later_events_are_left_out(tmp_path):
    recs, _ = follow(tmp_path, told_at(2, 3))
    assert ("process", "07:54:02") in seen(recs)          # C1, written in pass 1: stays
    assert ("process", "07:54:10") not in seen(recs)      # C2, pass 2: left out
    assert ("process", "07:54:20") not in seen(recs)      # D, under C1 (written before): its later events left out
    assert ("net", "07:54:21") not in seen(recs)
    assert ("process", "07:54:13") in seen(recs)          # the worker's own child: written


def test_e3b_bb2_after_the_root_is_no_longer_told_the_subtree_is_held_again_none_lost(tmp_path):
    recs, _ = follow(tmp_path, told_at(2))
    main, _ = follow(tmp_path, None, name="main.jsonl")
    left = [("process", "07:54:10"), ("net", "07:54:11")]   # pass 2's events of the agent's tree: left out
    assert seen(recs) == [s for s in seen(main) if s not in left]
    # pass 3: D (a child of C1) and C2's talk (C2's event 1 was left out): both the tree's again, at their depth
    by = {(r["tool"], r["ts"][11:19]): r for r in recs if r["phase"] == "pre"}
    assert by[("process", "07:54:20")]["input_meta"]["depth"] == 3 and ("net", "07:54:21") in by
    mains = {(r["tool"], r["ts"][11:19]): r["input_meta"] for r in main if r["phase"] == "pre"}
    assert all(mains[k] == by[k]["input_meta"] for k in [("process", "07:54:20"), ("net", "07:54:21")])


def test_e3c_bb2_a_child_of_a_left_out_process_whose_creation_is_missing_is_treated_as_today(tmp_path):
    for k, told in enumerate([told_at(2, 3), told_at(2), told_at(3)]):
        recs, _ = follow(tmp_path, told, name="c%d.jsonl" % k)
        assert not [s for s in seen(recs) if s[1] in ("07:54:12", "07:54:22")]   # E: in no pass, as on main
    main, _ = follow(tmp_path, None, name="main.jsonl")
    assert not [s for s in seen(main) if s[1] in ("07:54:12", "07:54:22")]


# --- E4 (BB-3) ---------------------------------------------------------------------------------------------------------

def test_e4_bb3_one_line_says_which_root_and_from_which_record_once(tmp_path):
    recs, _ = follow(tmp_path, told_at(2, 3))
    said = [r for r in recs if "left_out" in r]
    assert len(said) == 1 and said[0]["phase"] == "session_start" and said[0]["source"] == "os"
    assert said[0]["left_out"] == [{"root_pid": A, "root_guid": G[A], "from_record": 20}]
    # a pass that only leaves out says it in a block of its own (no event): the record it begins from
    only = [[talked(40, at("07:54:30"), A, AGENT, G[A], port=50240)]]
    recs2, _ = follow(tmp_path, lambda k: [NESTED] if k == 2 else [], passes=PASSES[:1] + only, name="only.jsonl")
    tail = recs2[-2:]
    assert [r["phase"] for r in tail] == ["session_start", "session_end"]
    assert tail[0]["left_out"] == [{"root_pid": A, "root_guid": G[A], "from_record": 40}]
    starts = [r["seq"] for r in recs2 if r["phase"] != "post"]
    assert starts == sorted(set(starts))   # the block takes the next seqs (SILENCE-ORDER and -HALF have nothing)


def test_e4_bb3_the_watchs_feed_reads_the_line_without_a_finding_a_hole_or_a_could_not_judge_note(tmp_path):
    recs, _ = follow(tmp_path, told_at(2, 3))
    bare = tmp_path / "bare.jsonl"   # the same lines without the key
    bare.write_text("".join(json.dumps({k: v for k, v in r.items() if k != "left_out"}, separators=(",", ":")) + "\n"
                            for r in recs))
    judged = []
    for path in (tmp_path / "w.jsonl", bare):
        feed = host.Feed(str(path), host.source_rules(RULES))
        holes, changed = feed.poll()
        found, notes, _ = feed.judge()
        judged.append((holes, feed.problems, [f["rule_id"] for f in found],
                       [n for n in notes if "could not judge" in str(n.get("detail", ""))]))
    assert judged[0] == judged[1] and judged[0][:2] == ([], [])
    assert not [f for f in judged[0][2] if f.startswith("SILENCE")]


# --- E2 (BB-1) and E5: the watch's side, through rounds -----------------------------------------------------------------

import datetime  # noqa: E402

import pytest  # noqa: E402

from raqib.rules import fixturegen  # noqa: E402
from test_round_channel import channel_xml, event  # noqa: E402
from test_one_destination import run  # noqa: E402

ANC, AG, N = fixturegen.HELD_ANCESTOR_PID, fixturegen.HELD_PID, 6
BASH = "C:\\Program Files\\Git\\usr\\bin\\bash.exe"


def t_at(seconds):
    return datetime.datetime.fromtimestamp(fixturegen.WALL0 + seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]


def channel(k):
    """The Sysmon channel up to round k (SYNTHETIC, held_inventory's case): the agent started by the ancestor before
    the watch; from round 2 the ancestor talks to its server and the agent starts a command that talks to its model
    (pid 5200 + k), all in round k's interval."""
    out = [created(1, t_at(-3600), AG, AGENT, guid_of(AG), ANC, WORKER, guid_of(ANC), "agent")]
    for m in range(2, k + 1):
        T, c = (m - 1) * fixturegen.EVERY, AG + m
        out += [talked(10 * m, t_at(T - 6), ANC, WORKER, guid_of(ANC), port=50000 + m, dest="203.0.113.20"),
                created(10 * m + 1, t_at(T - 5), c, BASH, guid_of(c), AG, AGENT, guid_of(AG), "bash -c step"),
                talked(10 * m + 2, t_at(T - 4), c, BASH, guid_of(c), port=51000 + m, dest="203.0.113.30")]
    return out


class Built:
    """A fake os follow for each tree: at each pass the test lets go, it writes what os_sysmon.follow's pass writes
    (os_sysmon.build of the channel so far for its root, its tree carried, after the highest record read), leaving
    out the roots leave_out() returns at that pass (roots_of)."""

    def __init__(self):
        self.follows = {}

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None,
                 helpers=None, since=None, tree=None, leave_out=None):
        pid = int(str(root).split(":")[0])
        self.follows[pid] = {"log": log, "leave_out": leave_out, "tree": {}, "top": None, "said": set(),
                             "told": [], "stop": stop}
        if on_pass:
            on_pass(1, None)
        stop.wait()
        return 1

    def passes(self, k):
        text = channel_xml(*channel(k))
        for pid, f in sorted(self.follows.items()):
            if f["stop"].is_set():
                continue
            roots = None if f["leave_out"] is None else os_sysmon.roots_of(f["leave_out"](), pid, None)
            f["told"].append((k, roots))
            info = {}
            lines, _ = os_sysmon.build(text, pid, start_seq=os_sysmon.last_seq(f["log"], os_sysmon.session_id(pid)),
                                       after_record=f["top"], info=info, tree=f["tree"], server_hash=True,
                                       leave_out=roots, out_said=f["said"])
            if info.get("last_record") is not None:
                f["top"] = max(f["top"] or 0, info["last_record"])
            if lines:
                os_sysmon.append(f["log"], lines)


def field_run(home, invs):
    follow, nested = Built(), []

    def step(k):
        def at_round(watch):
            nested.append((k, dict(watch.os_nested)))
            follow.passes(k)
        return at_round
    watch, _ = run(home, invs, {}, follow=follow, pids=(), at_round={k: step(k) for k in range(2, len(invs) + 1)})
    return watch, follow, nested


def key_of(watch, pid):
    (key,) = [k for k in watch.trees if k[0] == pid]
    return key


def test_e2_bb1_the_ancestors_follow_is_given_the_nested_root_from_its_attach_to_the_end_of_its_follow(tmp_path):
    invs = [fixturegen.held_inventory(k, talks_from=99) for k in range(1, 4)] + \
        [fixturegen.held_inventory(k, talks_from=99, sampled_agent=False) for k in range(4, 6)]
    watch, follow, nested = field_run(tmp_path, invs)
    anc, ag = key_of(watch, ANC), key_of(watch, AG)
    assert watch.sources[anc].kind == "os" and watch.sources[ag].kind == "os"
    told = {k: snap.get(anc, ()) for k, snap in nested}   # the snapshot after round k - 1
    assert [k for k in sorted(told) if told[k]] == [2, 3, 4] and told[2] == ((AG, None),)
    assert told[5] == () and watch.sources[ag].ended   # the round its follow ended (the tree gone): no longer
    assert [roots for k, roots in follow.follows[ANC]["told"]] == [[(AG, None)]] * 3 + [[]]   # read at every pass
    assert all(not snap.get(ag) for _, snap in nested)   # the ancestor is not under the agent


def shape(watch, follow):
    anc = key_of(watch, ANC)
    path = watch.sources[anc].path
    recs = [json.loads(x) for x in Path(path).read_text().splitlines()]
    base = Path(path).name
    ring = watch.rings.get(anc, [])
    os_acts = sum(1 for e in ring for a in e["acts"] if any(c.get("src") == base for c in a.get("cites", [])))
    model = os_sysmon.dest_sha256("203.0.113.30", 443, "tcp")   # the server the agent's commands talk to
    at_line = dict(enumerate([None] + recs))
    agent_talks = sum(1 for e in ring for cites in e["talks"].values() for c in cites if c.get("src") == base
                      and (at_line.get(c.get("line")) or {}).get("input_meta", {}).get("dest_sha256") == model)
    return {"anc_procs": sum(1 for r in recs if r["phase"] == "pre" and r["tool"] == "process"),
            "anc_nets": sum(1 for r in recs if r["phase"] == "pre" and r["tool"] == "net"),
            "left_out": [r["left_out"] for r in recs if "left_out" in r],
            "os_acts": os_acts, "agent_talks": agent_talks,
            "rhythm": [f for f in watch.findings if f.get("rule_id") == "HOST-RHYTHM" and f.get("pid") == ANC],
            "agent_found": any(f.get("rule_id") == "HOST-RHYTHM" and f.get("pid") == AG for f in watch.findings),
            "elsewhere": [f for f in watch.source_findings if f.get("judged_on") is not None]}


@pytest.mark.parametrize("main", [False, True])
def test_e5_through_rounds_the_nested_trees_commands_are_in_its_own_file_only(tmp_path, monkeypatch, main):
    if main:   # the twin: the callable returns nothing (what main's code gives)
        monkeypatch.setattr(host.HostWatch, "_nested_roots", lambda self, inv: {})
    watch, follow, _ = field_run(tmp_path, [fixturegen.held_inventory(k) for k in range(1, N + 1)])
    got = shape(watch, follow)
    ag = [json.loads(x) for x in Path(watch.sources[key_of(watch, AG)].path).read_text().splitlines()]
    assert sum(1 for r in ag if r["phase"] == "pre" and r["tool"] == "process") == N   # its event 1, its commands
    if not main:
        assert got["anc_procs"] == 1 and got["anc_nets"] == N - 1   # the agent's event 1; its own talks
        assert got["left_out"] == [[{"root_pid": AG, "root_guid": None, "from_record": 21}]]
        assert got["os_acts"] == 0 and got["agent_talks"] == 0 and got["rhythm"] == [] and got["elsewhere"] == []
        assert got["agent_found"]   # BB-4's "the agent is still found": by its own file
    else:   # main: the agent's commands in the ancestor's file too, its acts and talks in the ancestor's rhythm
        assert got["anc_procs"] == N and got["anc_nets"] == 2 * (N - 1) and got["left_out"] == []
        assert got["os_acts"] > 0 and got["agent_talks"] > 0   # the beats (in the ring's last R rounds)
        assert got["rhythm"] and got["rhythm"][0]["severity"] == "high" and got["agent_found"]   # AX-4's false one
