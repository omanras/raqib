"""The host rules' fixture generator (M7.6c, ADR-0008 Amendment B, Q-15).

The fixtures of HOST-RHYTHM and AGENT-DARK-LIVE are host lines of rounds fed
to raqib/host.py's HostWatch with a fake clock: the LAST round's host lines,
with the earlier rounds as their history (tests/fixtures/host/make.py has
made them so since M7.2 / M7.4 / M7.5). Their thresholds are eq values of the
rules' YAMLs that host.py reads and writes on every line (k, w, r of
HOST-RHYTHM; streak and live_window of AGENT-DARK-LIVE), so a fixture made at
one value says nothing of another: a changed threshold can be measured only
on fixtures made AT it. This module makes them, in memory, at any values:

    generate(rule) -> {"positive": [(path, doc)], "negative": [(path, doc)],
                       "arrivals": [path], "values": {...},
                       "runs": {path: [the host lines of each round]},
                       "last_round_only": [path]}

where rule is the (overlaid) compiled rule: its own eq values are the values
generated at (engine.declared_thresholds: the fields host.py reads). path is the fixture's path as the YAML lists it; doc is what the
shipped file holds ({"lines", "expect_seq"?}); dumps(doc) is its text. At the
YAMLs' declared values generate() gives exactly the shipped files (a test
regenerates and diffs them byte for byte), and make.py, now a thin writer,
writes them through the same functions. A shipped file holds the LAST
round's lines only; runs holds every round's, because a host rule fires once
per streak: a run that fires before its last round (k=1: a single cycle, in
round 2) is seen only there. overlay.measure judges the runs.

What is SYNTHETIC here (pure functions of the thresholds; nothing read):
- rhythm_inventory: round k of a fake tree in discover's inventory shape
  (pid 4400, "relay-bot", RFC 5737 remotes), scenarios "cycle" (a new child
  every round, one destination), "change" (a new destination every round),
  "between" (the same child every round) and "notalk" (an act-root). A child
  new in round c started HOST_GAP seconds after round c-1 (its talk beat),
  min(HOST_GAP, w): inside W whatever W the person sets.
- os_lines: the lines os_sysmon writes for Sysmon events before round k (M7.8:
  a process line carries its image name, input_meta.image, as os_sysmon's): a
  connection (event 3) OS_GAP s, min(OS_GAP, w), before the round's act; in
  "oscycle" a child (event 1, depth 1) 5 s before the round; in "osact" a
  child min(HOST_GAP, w) s after the round before (the host talks); a
  connection line carries dest_sha256 as the host watch's os follow writes
  it (ADR-0007 AU-1, AW-2: the follow asks for it); in "osnamed" Sysmon
  names its host (OS_NAME) before an even round only.
- the scenarios, parametric in k (rounds 1..k+1 for k cycles, 1..k for k-1,
  k+2 for the others and the os ones, the os rounds 2..k+1 or 2..k) and in the
  streak s (s dark rounds, s-1, s then a linked round).
What is NOT generated here: the inventories of the discover exports (the
discover fixtures "windows", kimi's, the benign desktops'; M7.6c REDO E-4:
SYNTHETIC exports, their run.json says so). The ones the generated rules need
are shipped as package data (HOSTDATA, inventories.json: discover.run's
inventory of each, the catalog path written relative), so an installed raqib
(no tests/) measures the same; make.py writes that file from the exports and
a test holds it to them. The synthetic desktops' arrivals ([benign/X:before,
benign/X], ADR-0007 C-1b): their rounds are fixed, their lines are made at
the values (they carry k, w, r and the streak as every host line does), and
a threshold under which one fires is refused ("would fire on a synthetic
desktop", overlay.measure); they are never counted among a rule's measured
negatives (E-5: they cannot fire it).
M7.6c REDO: E-2 the edge pairs (EDGES, STRICTER; w_scenarios, r_scenarios,
window_scenarios); E-6 the conditions a failure means (CONDITIONS) and the
range the measurement accepts (effective); E-8 the rounds are made by a
builder the caller hands generate() (raqib/host.py's fixture_builder): this
package imports neither raqib.host nor the suspect layer.

Nothing is written outside a temporary home that is removed after each run
(HostWatch keeps its record under its home). The cache of a measurement's
result (E-7) is raqib/overlay.py's, not this module's.
"""
from __future__ import annotations

import copy
import datetime
import json
import os
import re
import tempfile

from raqib.rules import engine

HERE = os.path.dirname(os.path.abspath(__file__))
HOSTDATA = os.path.join(HERE, "hostdata", "inventories.json")
FIXTURE_DIR = "tests/fixtures/rules/"   # the prefix of a fixture path as the YAMLs list it

WALL0 = 1793700000.0      # the wall clock of a fixture run at t = 0 (host.fixture_rounds)
EVERY = 10                # a fixture run's round period T
RHYTHM_PID = 4400
SYSTEM_DRIVE = "c"        # make.py's host_record gives the Windows exports' rounds this drive (D-3)
OS_DEST = {"hostname": None, "ip": "192.0.2.20", "port": "443", "protocol": "tcp"}   # RFC 5737
OS_NAME = "model.example"   # ADR-0007 AU-1: the host name Sysmon gives on some events of one server (RFC 2606)
HOST_GAP = 5              # s from a talk beat of the host (a round's time) to the child it is followed by
OS_GAP = 3                # s from an os talk (Sysmon event 3) to the act of its round
BEFORE = ":before"
GENERATED = ("HOST-RHYTHM", "AGENT-DARK-LIVE")   # the rules whose fixtures this module makes at any values
# A negative whose point is its last round (the round that clears what fired before it): judged there only.
# negative-dark-then-linked fires in round S (S dark rounds, as positive-never-live) and its last round links
# the footprint again; every other generated fixture is judged on every round of its run.
LAST_ROUND_ONLY = ("AGENT-DARK-LIVE/negative-dark-then-linked.json",)
ARRIVAL = "NEW-AGENT/negative-arrival-%s.json"


class GenerateError(ValueError):
    """The fixtures cannot be made at these values (the reason)."""


def _iso_at(seconds):
    return datetime.datetime.fromtimestamp(WALL0 + seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def _gap(limit, w):
    """A gap of `limit` seconds, never more than W (w None: the limit)."""
    return limit if w is None else min(limit, w)


# --- the synthetic rounds (M7.4, M7.5 E2) ------------------------------------------------------------

def rhythm_inventory(scenario, k, pid=RHYTHM_PID, image="relay-bot", every=EVERY, remote=None, children=None,
                     bytes_moved=True, act_after=HOST_GAP, sampled=False):
    """Round k (1-based) of a fake scenario, in discover's inventory shape
    (SYNTHETIC). Round k is read at t = (k-1) * every; a child new in round
    c started act_after s after round c-1. bytes_moved: the connection's
    byte counts (a fake ss) grow each round (K-5: a talk beat each round);
    False: no bytes are read (the round carries none). sampled (ADR-0007
    AQ-1): the round carries a process sample (`processes`) holding the
    tree's root, so a round the tree is not in finds it quiet, not gone;
    False (every fixture made before AQ): no sample, as they were made."""
    at = (k - 1) * every
    if children is None:
        if scenario in ("cycle", "change", "notalk"):
            children = list(range(1, k + 1))
        else:   # "between": one child, always the same
            children = [1]
    cites = [{"src": "win-process", "line": 2, "text": "fake process row of pid %d (make.py)" % pid}]
    acts = [{"how": "process", "pid": pid + c, "image": "bash" if c % 2 else "python", "listed": True,
             "path": None, "via": [], "reader_ancestor": False,
             "started": _iso_at((c - 2) * every + act_after if c > 1 else -60),
             "cites": [{"src": "win-process", "line": 2 + c, "text": "fake child row %d (make.py)" % (pid + c)}]}
            for c in children]
    if remote is None:
        remote = "192.0.2.%d:443" % (10 + k) if scenario == "change" else "192.0.2.10:443"
    tree = {"pid": pid, "image": image, "exe": "C:\\Users\\user\\AppData\\Local\\%s\\%s.exe" % (image, image),
            "exe_from": "record", "started": _iso_at(-3600), "cwd": None, "cites": cites, "acts": acts,
            "id": "C1"}
    talk = [{"remote": remote, "state": "ESTABLISHED", "basis": "ports", "lines": 1, "names": [], "endpoint": [],
             "cites": [{"src": "win-tcp", "line": 2, "text": "fake connection of pid %d to %s (make.py)" % (pid, remote)}]}]
    inv = {"records": 20, "holes": [], "incomplete": [], "alarms": [], "problems": [], "result": "alarm",
           "sources": [], "footprints": [], "agent_dark": [], "system_drive": SYSTEM_DRIVE, "live": False,
           "candidates": [], "act_roots": [],
           "window": {"start": _iso_at(at), "end": _iso_at(at), "snapshots": 0, "samples_read": [k]}}
    if scenario == "notalk":
        inv["act_roots"].append(dict(tree, talks=[]))
    else:
        inv["candidates"].append(dict(tree, talks=talk))
        if bytes_moved:
            inv["conn_bytes"] = {"from": "fake ss -tinp (make.py)", "hole": None, "by": {
                "%d %s" % (pid, remote): {"bytes_sent": 1000 * k, "bytes_received": 5000 * k, "sockets": 1}}}
    if sampled:
        inv["processes"] = [{"pid": pid, "image": image, "started": tree["started"], "cites": cites}]
    return inv


def quiet_inventory(k, pid=RHYTHM_PID, image="relay-bot"):
    """ADR-0007 AP-2, AQ-1 (SYNTHETIC): round k of a tree seen at the
    sample in round 1 and quiet after it: from round 2 the round's process
    sample holds its root, and no candidate and no act-root (the sample
    does not see it talk); its os source reads what os_lines writes."""
    inv = rhythm_inventory("between", k, pid=pid, image=image, bytes_moved=False, sampled=True)
    if k > 1:
        inv["candidates"] = []
    return inv


def gone_inventory(k, gone, pid=RHYTHM_PID, image="relay-bot"):
    """ADR-0007 AR-2 (SYNTHETIC): round k of the tree quiet_inventory
    makes, its root not in the round's process sample from round `gone`
    on: gone, not quiet; its os source still reads what os_lines writes."""
    inv = quiet_inventory(k, pid=pid, image=image)
    if k >= gone:
        inv["processes"] = []
    return inv


HELD_ANCESTOR_PID = 5100   # ADR-0007 AX-4, AY: the runner's worker, which talks to its server every round
HELD_PID = 5200            # the agent under it: a candidate in round 1, quiet after it
HELD_SUB_PID = 5250        # ADR-0007 AZ-6: a second held tree under the agent (sub=True)


def held_inventory(k, net_round=None, every=EVERY, talks_from=2, sampled_agent=True, side=False, fresh=False,
                   worker_from=1, talks_again=None, keep=False, sub=False, destruct_round=None):
    """ADR-0007 AX-4, AY-1 (SYNTHETIC): round k of the field case, in
    discover's inventory shape. An unknown ancestor (pid 5100,
    "runner-worker") talks to one server every round, its bytes moving (a
    talk beat each round); an unknown tree under it (pid 5200, "node")
    talks to its model in round 1 only (a candidate there, quiet after it
    while its root is in the sample). Each round a new child of the agent
    starts HOST_GAP s after the round before (pid 5200 + k; "bash", "curl"
    in round net_round). As discover's anchor has it (B-6), from round 2 the
    agent and its child are acts of the ancestor (the child via [5200]).
    talks_from: the agent talks in every round below it (a large value: a
    candidate nested in a candidate in every round). sampled_agent False:
    from round 2 the agent's root is not in the sample (gone). side: the
    ancestor also has a child of its own each round (pid 5300 + k), no held
    root on its path. ADR-0007 AZ-6: fresh, both trees start at the watch's
    start (not history); worker_from, the ancestor talks from that round
    on (before it, it is no candidate); talks_again, the agent talks again
    from that round on (a candidate again); keep, each child stays alive
    (in the sample and among the acts) to the last round; sub, a second
    talker under the agent (pid 5250, a candidate in round 1 and quiet
    after it), whose own child (pid 5260 + k) is new each round;
    destruct_round, the round whose new child is rm."""
    at, worker, agent = (k - 1) * every, HELD_ANCESTOR_PID, HELD_PID
    w_start, a_start = (_iso_at(0), _iso_at(0)) if fresh else (_iso_at(-7200), _iso_at(-3600))
    w_remote, a_remote = "192.0.2.20:443", "192.0.2.30:443"

    def proc(pid, ppid, image, started):
        return {"pid": pid, "ppid": ppid, "image": image, "started": started,
                "cites": [{"src": "proc", "line": 2, "text": "fake process row of pid %d (fixturegen)" % pid}]}

    def act(pid, image, started, via):
        return {"how": "process", "pid": pid, "image": image, "listed": image in ("bash", "curl"), "path": None,
                "via": list(via), "reader_ancestor": False, "started": started,
                "cites": [{"src": "proc", "line": 2, "text": "fake child row of pid %d (fixturegen)" % pid}]}

    def talk(pid, remote):
        return [{"remote": remote, "state": "ESTABLISHED", "basis": "ports", "lines": 1, "names": [],
                 "endpoint": [], "cites": [{"src": "proc-net", "line": 2, "text": "fake connection of pid %d to %s"
                                            " (fixturegen)" % (pid, remote)}]}]

    talking = k < talks_from or (talks_again is not None and k >= talks_again)

    def image_of(j):
        return "curl" if j == net_round else "rm" if j == destruct_round else "bash"

    def start_of(j):
        return _iso_at((j - 2) * every + HOST_GAP if j > 1 else (0 if fresh else -60))

    child_pid = agent + k
    child_start = start_of(k)
    kids = [act(agent + j, image_of(j), start_of(j), [] if talking else [agent])
            for j in (range(1, k + 1) if keep else (k,))]
    child = kids[-1]
    sub_start = start_of(1)
    sub_kid = act(HELD_SUB_PID + 10 + k, "bash", child_start, [] if k == 1 else [agent, HELD_SUB_PID])
    tree = {"exe_from": "record", "cwd": None, "talks": []}
    w_acts = [act(agent, "node", a_start, [])] + ([] if talking else kids)
    if sub and k > 1:
        w_acts += [act(HELD_SUB_PID, "python3", sub_start, [agent]), sub_kid]
    if side:
        w_acts.append(act(5300 + k, "python", child_start, []))
    cands = [dict(tree, pid=worker, image="runner-worker", exe="/opt/runner/bin/runner-worker", started=w_start,
                  cites=proc(worker, 1, "runner-worker", w_start)["cites"], acts=w_acts, id="C1",
                  talks=talk(worker, w_remote))] if k >= worker_from else []
    by = {"%d %s" % (worker, w_remote): {"bytes_sent": 1000 * k, "bytes_received": 5000 * k, "sockets": 1}
          } if k >= worker_from else {}
    if talking:
        a_acts = kids + ([act(HELD_SUB_PID, "python3", sub_start, [])] if sub and k == 1 else [])
        cands.append(dict(tree, pid=agent, image="node", exe="/usr/bin/node", started=a_start,
                          cites=proc(agent, worker, "node", a_start)["cites"], acts=a_acts, id="C2",
                          talks=talk(agent, a_remote)))
        by["%d %s" % (agent, a_remote)] = {"bytes_sent": 300 * k, "bytes_received": 900 * k, "sockets": 1}
    if sub and k == 1:
        cands.append(dict(tree, pid=HELD_SUB_PID, image="python3", exe="/usr/bin/python3", started=sub_start,
                          cites=proc(HELD_SUB_PID, agent, "python3", sub_start)["cites"], acts=[sub_kid], id="C3",
                          talks=talk(HELD_SUB_PID, "192.0.2.40:443")))
        by["%d 192.0.2.40:443" % HELD_SUB_PID] = {"bytes_sent": 100, "bytes_received": 400, "sockets": 1}
    processes = [proc(worker, 1, "runner-worker", w_start)]
    if sampled_agent or k == 1:
        processes += [proc(agent, worker, "node", a_start)] + [proc(c["pid"], agent, c["image"], c["started"])
                                                               for c in kids]
        if sub:
            processes += [proc(HELD_SUB_PID, agent, "python3", sub_start),
                          proc(sub_kid["pid"], HELD_SUB_PID, "bash", child_start)]
    if side:
        processes.append(proc(5300 + k, worker, "python", child_start))
    return {"records": 20, "holes": [], "incomplete": [], "alarms": [], "problems": [], "result": "alarm",
            "sources": [], "footprints": [], "agent_dark": [], "system_drive": SYSTEM_DRIVE, "live": False,
            "candidates": cands, "act_roots": [], "processes": processes,
            "conn_bytes": {"from": "fake ss -tinp (fixturegen)", "hole": None, "by": by},
            "window": {"start": _iso_at(at), "end": _iso_at(at), "snapshots": 0, "samples_read": [k]}}


def os_lines(k, scenario, seq, sid="os-%d" % RHYTHM_PID, w=None):
    """M7.5 E2 (SYNTHETIC): the lines os_sysmon writes (its _lines shape:
    a pre and a post per event, tool net / process, source os, the hash of
    the destination or the command line) for the os events before round k:
    a connection to OS_DEST min(OS_GAP, w) s before the round's act (5 s
    before the round) and, in "oscycle", that child (depth 1); in "osact"
    only a child, min(HOST_GAP, w) s after the round before (the host's own
    connection talks there). (lines, last seq)."""
    from raqib.hooks import common, os_sysmon
    at = (k - 1) * EVERY
    # ADR-0007 AU-1: "osnamed" is "oscycle" whose connection Sysmon names (OS_NAME) before an even round only: one
    # server, two input_sha256, one dest_sha256 (AW-2: written as the host watch's follow, which asks for it)
    dest = dict(OS_DEST, hostname=OS_NAME) if scenario == "osnamed" and k % 2 == 0 else OS_DEST
    events = [] if scenario == "osact" else [(at - 5 - _gap(OS_GAP, w), "net",
                                               common.canonical_sha256({"destination": dest}),
                                               {"dest_port": 443, "dest_private": False,
                                                "dest_sha256": os_sysmon.dest_sha256(dest["ip"], dest["port"],
                                                                                     dest["protocol"])})]
    if scenario == "osnamed":
        scenario = "oscycle"
    if scenario in ("oscycle", "osact"):
        when = at - 5 if scenario == "oscycle" else at - EVERY + _gap(HOST_GAP, w)
        events.append((when, "process", common.canonical_sha256({"command_line": "fake child %d (make.py)" % k}),
                       {"command_head": "bash", "command_programs": ["bash"], "image": "bash", "depth": 1}))   # M7.8
    out = []
    for when, tool, digest, meta in events:
        seq += 1
        base = {"ts": _iso_at(when), "seq": seq, "session_id": sid, "tool": tool, "input_sha256": digest,
                "input_meta": dict(meta), "source": "os"}
        out.append(dict(base, phase="pre"))
        out.append(dict(base, phase="post", output_meta={}, ok=True))
    return out, seq


def synthetic_inventory(name, w=None):
    """The inventory of a synthetic round name ("rhythm:<scenario>:<k>",
    "rhythm-os:<scenario>:<k>"), or None for any other name."""
    if name.startswith("rhythm-os:"):
        _, scenario, k = name.split(":")
        if scenario == "ostalk":   # the host's new child each round, 5 s before it; the talks are os
            return rhythm_inventory("cycle", int(k), bytes_moved=False)
        if scenario == "osact":    # N-3: the host's connection talks each round (its bytes move); the acts are os
            return rhythm_inventory("between", int(k), bytes_moved=True)
        return rhythm_inventory("between", int(k), bytes_moved=False)
    if name.startswith("rhythm-quiet:"):   # AP-2: candidate in round 1, quiet after; the os lines name the scenario
        return quiet_inventory(int(name.split(":")[2]))
    if name.startswith("rhythm-gone:"):   # AR-2: the same, its root gone from the sample from round <gone> on
        _, _, k, gone = name.split(":")
        return gone_inventory(int(k), int(gone))
    if name.startswith("rhythm:"):
        _, scenario, k = name.split(":")
        return rhythm_inventory(scenario, int(k), act_after=_gap(HOST_GAP, w))
    if name.startswith("rhythm-gap:"):   # E-2, W's edge: round i of k cycles, each act `gap` s after its talk
        _, gap, period, i = name.split(":")
        return rhythm_inventory("cycle", int(i), every=int(period), act_after=int(gap))
    if name.startswith("rhythm-ring:"):   # E-2, R's edge: round i of n; cycles in round 2 and the last k-1 rounds
        _, n, k, i = (int(x) if x.isdigit() else x for x in name.split(":"))
        children = [1] + ([2] if i >= 2 else []) + [j for j in range(max(3, n - k + 2), i + 1)]
        return rhythm_inventory("cycle", i, children=children, act_after=_gap(HOST_GAP, w))
    return None


# --- the scenarios, parametric in the thresholds ---------------------------------------------------------

def rhythm_scenarios(k):
    """M7.4: HOST-RHYTHM's host-source fixtures at K (file -> round names)."""
    return {
        "HOST-RHYTHM/positive-three-cycles.json": ["rhythm:cycle:%d" % i for i in range(1, k + 2)],
        "HOST-RHYTHM/negative-two-cycles.json": ["rhythm:cycle:%d" % i for i in range(1, k + 1)],
        "HOST-RHYTHM/negative-changing-destination.json": ["rhythm:change:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-acts-between-rounds.json": ["rhythm:between:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-no-talk.json": ["rhythm:notalk:%d" % i for i in range(1, k + 3)],
    }


def os_scenarios(k):
    """M7.5 E2 / REDO N-3: HOST-RHYTHM's os-source fixtures at K."""
    return {
        "HOST-RHYTHM/positive-os-three-cycles.json": ["rhythm-os:oscycle:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-os-two-cycles.json": ["rhythm-os:oscycle:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/positive-os-talks-host-acts.json": ["rhythm-os:ostalk:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/positive-host-talks-os-acts.json": ["rhythm-os:osact:%d" % i for i in range(1, k + 3)],
        # ADR-0007 AP-3, AQ-1: a tree seen at the sample in round 1 and quiet after it, its cycles all between samples
        # (os lines before rounds 2..k+1: k cycles, the k-th read in round k+2), talks with no act (no cycle), and
        # the rig's shape: a few beats of a long-lived tree (k-1 cycles; the last round still reads one)
        "HOST-RHYTHM/positive-quiet-three-cycles.json": ["rhythm-quiet:oscycle:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-quiet-no-cycle.json": ["rhythm-quiet:ostalk:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-quiet-few-beats.json": ["rhythm-quiet:oscycle:%d" % i for i in range(1, k + 2)],
        # ADR-0007 AR-2: the same tree gone from the sample in round k+1, its last cycles read after it is gone (os
        # lines before rounds 2..k+1: k cycles, the k-th read in round k+2 on a gone line); and k-1 of them
        "HOST-RHYTHM/positive-gone-three-cycles.json": ["rhythm-gone:oscycle:%d:%d" % (i, k + 1)
                                                        for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-gone-few-beats.json": ["rhythm-gone:oscycle:%d:%d" % (i, k + 1) for i in range(1, k + 3)],
        # ADR-0007 AU-4: AU-1's pair, one server Sysmon names on some events and not on others (k cycles; k-1)
        "HOST-RHYTHM/positive-os-named-some.json": ["rhythm-os:osnamed:%d" % i for i in range(1, k + 3)],
        "HOST-RHYTHM/negative-os-named-some.json": ["rhythm-os:osnamed:%d" % i for i in range(1, k + 3)],
    }


def os_rounds(k):
    """The rounds before which os_lines are appended, per os fixture, at K."""
    return {
        "HOST-RHYTHM/positive-os-three-cycles.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-os-two-cycles.json": tuple(range(2, k + 1)),
        "HOST-RHYTHM/positive-os-talks-host-acts.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/positive-host-talks-os-acts.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/positive-quiet-three-cycles.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-quiet-no-cycle.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-quiet-few-beats.json": tuple(range(2, k + 1)),
        "HOST-RHYTHM/positive-gone-three-cycles.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-gone-few-beats.json": tuple(range(3, k + 2)),
        "HOST-RHYTHM/positive-os-named-some.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-os-named-some.json": tuple(range(2, k + 1)),
    }


def dark_scenarios(streak):
    """M7.2 / M7.5 E1: AGENT-DARK-LIVE's fixtures at the streak S (the
    synthetic exports as rounds: "windows" holds a footprint no tree links to; kimi-gone
    is kimi with its tree left out; kimi/one-sample links it again)."""
    return {
        "AGENT-DARK-LIVE/positive-dark-three-rounds.json": ["windows"] * streak,
        "AGENT-DARK-LIVE/negative-dark-two-rounds.json": ["windows"] * (streak - 1),
        "AGENT-DARK-LIVE/negative-dark-then-linked.json": ["kimi-gone"] * streak + ["kimi/one-sample"],
        "AGENT-DARK-LIVE/positive-never-live.json": ["kimi-gone"] * streak,
    }


def arrival_scenarios(benign):
    """C-1b: a synthetic desktop whose trees arrive after round 1, for each
    benign export name ("benign/linux-desktop", ...): fixed rounds."""
    return {ARRIVAL % name.split("/")[1]: [name + BEFORE, name] for name in benign}


# --- running the rounds ----------------------------------------------------------------------------------

def source_lines(watch):
    """Every line of every per-tree source file of a watch, in pid order."""
    out = []
    # I-8: <run>-<pid>-<started tag>.jsonl; the run "fixture-run" has dashes of its own
    names = sorted(os.listdir(watch.sources_dir), key=lambda n: int(n[len(watch.run) + 1:].split("-", 1)[0]))
    for name in names:
        with open(os.path.join(watch.sources_dir, name), encoding="ascii") as f:
            out += [json.loads(line) for line in f if line.strip()]
    return out


def fixture_doc(rule, lines, positive):
    """A fixture's content: its lines and, for a positive, the seqs its own
    rule cites on them (expect_seq), as make.py has always written it."""
    doc = {"lines": lines}
    if positive:
        found, _ = engine.judge(rule, lines, {})
        doc["expect_seq"] = sorted({s for f in found for s in f["cited_seq"]})
    return doc


def dumps(doc):
    """A fixture's text, byte for byte as the shipped files hold it."""
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def run_lines(builder, names, rules, inventory, **opts):
    """The host lines of every round of a run of these rounds (oldest
    first), made by builder (raqib/host.py's fixture_builder: a HostWatch
    with a fake clock; E-8, this package never imports it) in a temporary
    home that is removed after it."""
    if not names:
        raise GenerateError("a scenario with no round")
    with tempfile.TemporaryDirectory(prefix="raqib-fixturegen-", ignore_cleanup_errors=True) as home:
        seen = []
        builder(names, rules, home, inventory=inventory, seen=seen, **opts)
        if len(seen) != len(names):
            raise GenerateError("%d rounds fed, %d recorded" % (len(names), len(seen)))
        return [r["lines"] for r in seen]


# --- machine-independent paths (M7.6c follow-up) ----------------------------------------------------------------
# Every path written into shipped or generated data is relative to the repository root, so a regeneration is
# the same on every machine and no local path (a user name) ships in the package. portable() is how make.py
# writes HOSTDATA; machine_path_problem() is what the replay refuses (packaged()) and what the tests assert.
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))   # the checkout (or site-packages) holding raqib/
# The home names the exports were redacted to (tests/fixtures/discover headers): the only ones data may carry.
PLACEHOLDER_HOMES = ("user", "field")
HOME_PATH = re.compile(r"(?:/home/|/Users/|[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/))([A-Za-z0-9._-]+)")


def _roots(root):
    out = []
    for r in (os.path.abspath(root), os.path.realpath(root)):
        r = r.rstrip("\\/")
        if r and r not in out:
            out.append(r)
    return out


def portable(obj, root=REPO_ROOT):
    """obj (JSON-like) with every path under the absolute root written
    relative to it, with / between its parts: "<root>/tests/fixtures/x.txt
    (note)" -> "tests/fixtures/x.txt (note)". Keys and values alike."""
    if isinstance(obj, dict):
        return {portable(k, root): portable(v, root) for k, v in obj.items()}
    if isinstance(obj, list):
        return [portable(v, root) for v in obj]
    if not isinstance(obj, str):
        return obj
    for r in _roots(root):
        obj = re.sub(re.escape(r) + r"[\\/]([^\s\"()]*)", lambda m: m.group(1).replace("\\", "/"), obj)
    return obj


def machine_path_problem(text, root=REPO_ROOT):
    """Why text is not machine-independent (the absolute root of this
    checkout, or a home directory other than the redaction placeholders),
    or None."""
    for r in _roots(root):
        for form in (r, r.replace("\\", "\\\\"), r.replace("\\", "/")):
            if form in text:
                return "the absolute path %s of this machine" % form
    for m in HOME_PATH.finditer(text):
        if m.group(1) not in PLACEHOLDER_HOMES:
            return "a local home path %s" % m.group(0)
    return None


# --- the packaged inventories (the synthetic exports' rounds) ---------------------------------------------------

_PACKAGED = {}


def packaged():
    """{name: inventory} of HOSTDATA (read once per process; never written here)."""
    if not _PACKAGED:
        try:
            with open(HOSTDATA, encoding="ascii") as f:
                text = f.read()
            data = json.loads(text)
        except (OSError, ValueError) as exc:
            raise GenerateError("the packaged inventories cannot be read (%s): %s" % (HOSTDATA, exc))
        why = machine_path_problem(text)
        if why:   # M7.6c follow-up: data that would not regenerate the same on another machine is not replayed
            raise GenerateError("%s holds %s (make.py writes every path relative)" % (HOSTDATA, why))
        if not (isinstance(data, dict) and isinstance(data.get("inventories"), dict)):
            raise GenerateError("%s holds no inventories" % HOSTDATA)
        _PACKAGED.update(data["inventories"])
    return _PACKAGED


def packaged_inventory(name):
    inv = packaged().get(name)
    if inv is None:
        raise GenerateError("no packaged inventory %r (%s)" % (name, HOSTDATA))
    return json.loads(json.dumps(inv))   # a copy: a round never changes the next run's input


def benign_names():
    """The synthetic desktops whose arrivals are shipped (C-1b), sorted."""
    return sorted(n for n in packaged() if n.startswith("benign/") and not n.endswith(BEFORE))


# --- generate -----------------------------------------------------------------------------------------------

RHYTHM, DARK = "HOST-RHYTHM", "AGENT-DARK-LIVE"
FIELDS = {RHYTHM: ("k", "w", "r"), DARK: ("streak", "live_window")}
# M7.6c REDO E-2 (ADR-0008 Amendment E): "measured" means sensitive. For each field a person may set, the edge
# pair: a positive that stops firing just past the value (at v+1) and a negative that starts firing just short
# of it (at v-1), both generated at v and run under the neighbouring value. A field without one is FIXED.
EDGES = {
    RHYTHM: {"k": ("HOST-RHYTHM/positive-three-cycles.json", "HOST-RHYTHM/negative-two-cycles.json"),
             "w": ("HOST-RHYTHM/positive-w-edge.json", "HOST-RHYTHM/negative-w-edge.json"),
             "r": ("HOST-RHYTHM/positive-r-edge.json", "HOST-RHYTHM/negative-r-edge.json")},
    DARK: {"streak": ("AGENT-DARK-LIVE/positive-dark-three-rounds.json",
                      "AGENT-DARK-LIVE/negative-dark-two-rounds.json"),
           "live_window": ("AGENT-DARK-LIVE/positive-window-edge.json",
                           "AGENT-DARK-LIVE/negative-window-edge.json")},
}
# The stricter neighbour of each field: +1 where a larger value asks more of a run (k cycles, a longer streak, a
# longer live window before a knock), -1 where a smaller one does (a shorter W, fewer rounds R). The edge positive
# stops firing at v + STRICTER; the edge negative starts firing at v - STRICTER.
STRICTER = {"k": 1, "w": -1, "r": -1, "streak": 1, "live_window": 1}
# E-6: what a fixture's failure means, said with its name in a refusal.
CONDITIONS = {
    "HOST-RHYTHM/negative-changing-destination.json":
        "k must be >= 2: at k=1 one talk-then-act to each of many destinations is k cycles",
    "HOST-RHYTHM/negative-r-edge.json":
        "k must be >= 2: at k=1 the one cycle that left the last r rounds fired when it was made",
    "HOST-RHYTHM/positive-host-talks-os-acts.json": "r must be >= k+2: an os act is read one round late",
    "HOST-RHYTHM/positive-os-three-cycles.json": "r must be >= k+2: an os act is read one round late",
    "HOST-RHYTHM/positive-quiet-three-cycles.json": "r must be >= k+2: an os act is read one round late",
    "HOST-RHYTHM/positive-gone-three-cycles.json": "r must be >= k+2: an os act is read one round late",
    "HOST-RHYTHM/positive-os-named-some.json": "r must be >= k+2: an os act is read one round late",
    "HOST-RHYTHM/positive-os-talks-host-acts.json": "r must be >= k+1: the first talk must stay in the last r rounds",
    "HOST-RHYTHM/positive-three-cycles.json": "r must be >= k+1: the first talk must stay in the last r rounds",
}


def edge_fields(rule_id):
    """The fields of a rule the generator has an edge pair for (E-2)."""
    return tuple(EDGES.get(rule_id, {}))


def effective(rule_id, field, values, low, high):
    """E-6: (lo, hi), the range of field the measurement accepts given the
    other values (its conditions above), inside the declared bounds."""
    lo, hi = low, high
    if rule_id == RHYTHM and field == "k":
        lo, hi = max(lo, 2), min(hi, values["r"] - 2)
    elif rule_id == RHYTHM and field == "r":
        lo = max(lo, values["k"] + 2)
    elif rule_id == DARK and field == "streak":
        hi = min(hi, values["live_window"])
    elif rule_id == DARK and field == "live_window":
        lo = max(lo, values["streak"])
    return lo, hi


def values_of(rule):
    """The thresholds a rule generates at: its own eq values (pure: the
    match's declared thresholds, the fields host.py reads)."""
    if rule.id not in FIELDS:
        raise GenerateError("no generator for %s (generated: %s)" % (rule.id, ", ".join(GENERATED)))
    declared = engine.declared_thresholds(rule.doc)
    missing = [f for f in FIELDS[rule.id] if f not in declared]
    if missing:
        raise GenerateError("%s does not declare %s" % (rule.id, ", ".join(missing)))
    return {f: declared[f]["value"] for f in FIELDS[rule.id]}


def with_values(rule, values):
    """The rule with these eq values (compiled by the engine: a value out
    of its YAML's bounds or breaking a relation is a RuleError)."""
    doc = copy.deepcopy(rule.doc)
    declared = engine.declared_thresholds(doc)
    for p in engine.eq_predicates(doc.get("match")):
        name = p["field"].rsplit(".", 1)[-1]
        if name in values and name in declared and declared[name]["field"] == p["field"]:
            p["eq"] = values[name]
    return engine.compile_rule(doc, rule.source)


def window_scenarios(streak, window):
    """E-2: the live window's edge pair: a footprint whose tree is live in
    round 2, then dark. Its window closes window rounds after it; the fresh
    streak that starts then knocks at its streak-th round: after
    window + streak - 1 dark rounds (the positive's last round), not after
    one fewer (the negative)."""
    head = ["kimi-gone", "kimi/two-samples"]
    return {
        "AGENT-DARK-LIVE/positive-window-edge.json": head + ["kimi-gone"] * (window + streak - 1),
        "AGENT-DARK-LIVE/negative-window-edge.json": head + ["kimi-gone"] * (window + streak - 2),
    }


def w_scenarios(k, w):
    """E-2: W's edge pair: k host cycles whose act starts exactly W s
    after its talk (the positive) or W+1 s (the negative: no cycle at W,
    k cycles at W+1). The rounds are W+6 s apart (never under 10), so the
    act stays inside the round after its talk."""
    period = max(EVERY, w + 6)
    return {
        "HOST-RHYTHM/positive-w-edge.json": (["rhythm-gap:%d:%d:%d" % (w, period, i) for i in range(1, k + 2)],
                                             {"every": period}),
        "HOST-RHYTHM/negative-w-edge.json": (["rhythm-gap:%d:%d:%d" % (w + 1, period, i) for i in range(1, k + 2)],
                                             {"every": period}),
    }


def r_scenarios(k, r):
    """E-2: R's edge pair: a run of n rounds whose first cycle (talk in
    round 1, act in round 2) is the oldest of the last R rounds when n = R
    (the positive: k cycles; at R-1 it falls out) and just out of them
    when n = R+1 (the negative: k-1 cycles; at R+1 it is in). The other
    k-1 cycles are the run's last rounds."""
    return {
        "HOST-RHYTHM/positive-r-edge.json": ["rhythm-ring:%d:%d:%d" % (r, k, i) for i in range(1, r + 1)],
        "HOST-RHYTHM/negative-r-edge.json": ["rhythm-ring:%d:%d:%d" % (r + 1, k, i) for i in range(1, r + 2)],
    }


def plan(rule, shape=None):
    """({fixture name (RULE/file.json): (round names, opts)}, values): the
    rule's scenarios made at shape (default: its own values), its arrivals
    included."""
    values = dict(shape or values_of(rule))
    out = {}
    if rule.id == RHYTHM:
        k, w, r = values["k"], values["w"], values["r"]
        rounds = os_rounds(k)
        for name, names in rhythm_scenarios(k).items():
            out[name] = (names, {})
        for name, names in os_scenarios(k).items():
            out[name] = (names, {"os_rounds": rounds[name]})
        out.update(w_scenarios(k, w))
        if r < k + 1:
            raise GenerateError("r=%d: the r edge pair needs r >= k+1 (k=%d)" % (r, k))
        for name, names in r_scenarios(k, r).items():
            out[name] = (names, {})
    else:
        if values["streak"] < 2:
            raise GenerateError("streak %d: its negative (streak - 1 dark rounds) has no round" % values["streak"])
        for name, names in dark_scenarios(values["streak"]).items():
            out[name] = (names, {})
        for name, names in window_scenarios(values["streak"], values["live_window"]).items():
            out[name] = (names, {})
    for name, names in arrival_scenarios(benign_names()).items():
        out[name] = (names, {})
    return out, values


def generate(rule, builder, rules=None, shape=None, only=None):
    """The rule's fixtures made in memory (see the module docstring): the
    scenarios planned at shape (default: the rule's own values), run with
    THIS rule (its values are what HostWatch reads). builder: the round
    builder (raqib/host.py's fixture_builder()); rules: the catalog the watch
    is given (default: the package's), with this rule in place of its
    namesake; only: the fixture paths to make (default: all of the rule's,
    and the synthetic desktops). GenerateError when a fixture of the rule
    has no generator or a round cannot be made."""
    scenarios, values = plan(rule, shape)
    if rules is None:
        rules = engine.load_catalog(os.path.join(HERE, "catalog"))
    rules = [rule if r.id == rule.id else r for r in rules]
    arrivals = sorted(FIXTURE_DIR + name for name in arrival_scenarios(benign_names()))
    out = {"positive": [], "negative": [], "arrivals": arrivals, "values": dict(values_of(rule)), "shape": values,
           "runs": {}, "last_round_only": sorted(FIXTURE_DIR + n for n in LAST_ROUND_ONLY if n in scenarios)}
    w = values_of(rule).get("w")
    for kind in ("positive", "negative"):
        paths = list(rule.fixtures[kind])
        if kind == "negative":   # E4: the synthetic desktops are run for every generated rule
            paths += [p for p in arrivals if p not in paths]
        for path in paths:
            if only is not None and path not in only:
                continue
            name = path[len(FIXTURE_DIR):] if path.startswith(FIXTURE_DIR) else None
            if name not in scenarios:
                raise GenerateError("%s: no generator for fixture %s" % (rule.id, path))
            names, opts = scenarios[name]
            rounds = run_lines(builder, names, rules, lambda n: synthetic_inventory(n, w) or packaged_inventory(n),
                               w=w, **opts)
            out["runs"][path] = rounds
            out[kind].append((path, fixture_doc(rule, rounds[-1], kind == "positive")))
    return out
