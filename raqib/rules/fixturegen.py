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
generated at (host.rhythm_params / host.rule_eq read them, as the watch
does). path is the fixture's path as the YAML lists it; doc is what the
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
- os_lines: the lines os_sysmon writes for Sysmon events before round k: a
  connection (event 3) OS_GAP s, min(OS_GAP, w), before the round's act; in
  "oscycle" a child (event 1, depth 1) 5 s before the round; in "osact" a
  child min(HOST_GAP, w) s after the round before (the host talks).
- the scenarios, parametric in k (rounds 1..k+1 for k cycles, 1..k for k-1,
  k+2 for the others and the os ones, the os rounds 2..k+1 or 2..k) and in the
  streak s (s dark rounds, s-1, s then a linked round).
What is NOT generated: the inventories of real exports (the discover fixtures
"windows", kimi's, the benign desktops'). The ones the generated rules need
are shipped as package data (HOSTDATA, inventories.json: discover.run's
inventory of each, the catalog path written relative), so an installed raqib
(no tests/) measures the same; make.py writes that file from the exports and
a test holds it to them. The benign arrivals ([benign/X:before, benign/X],
ADR-0007 C-1b) are real exports: their rounds are fixed, their lines are
made at the values (they carry k, w, r and the streak as every host line
does), and a threshold under which one fires is refused ("would fire on a
benign desktop", overlay.measure).

Nothing is written outside a temporary home that is removed after each run
(HostWatch keeps its record under its home); nothing is cached on disk.
"""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOSTDATA = os.path.join(HERE, "hostdata", "inventories.json")
FIXTURE_DIR = "tests/fixtures/rules/"   # the prefix of a fixture path as the YAMLs list it

WALL0 = 1793700000.0      # the wall clock of rounds_of at t = 0
EVERY = 10                # rounds_of's T
RHYTHM_PID = 4400
SYSTEM_DRIVE = "c"        # make.py's host_record gives the Windows exports' rounds this drive (D-3)
OS_DEST = {"hostname": None, "ip": "192.0.2.20", "port": "443", "protocol": "tcp"}   # RFC 5737
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
                     bytes_moved=True, act_after=HOST_GAP):
    """Round k (1-based) of a fake scenario, in discover's inventory shape
    (SYNTHETIC). Round k is read at t = (k-1) * every; a child new in round
    c started act_after s after round c-1. bytes_moved: the connection's
    byte counts (a fake ss) grow each round (K-5: a talk beat each round);
    False: no bytes are read (the round carries none)."""
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
    return inv


def os_lines(k, scenario, seq, sid="os-%d" % RHYTHM_PID, w=None):
    """M7.5 E2 (SYNTHETIC): the lines os_sysmon writes (its _lines shape:
    a pre and a post per event, tool net / process, source os, the hash of
    the destination or the command line) for the os events before round k:
    a connection to OS_DEST min(OS_GAP, w) s before the round's act (5 s
    before the round) and, in "oscycle", that child (depth 1); in "osact"
    only a child, min(HOST_GAP, w) s after the round before (the host's own
    connection talks there). (lines, last seq)."""
    from raqib.hooks import common
    at = (k - 1) * EVERY
    events = [] if scenario == "osact" else [(at - 5 - _gap(OS_GAP, w), "net",
                                               common.canonical_sha256({"destination": OS_DEST}),
                                               {"dest_port": 443, "dest_private": False})]
    if scenario in ("oscycle", "osact"):
        when = at - 5 if scenario == "oscycle" else at - EVERY + _gap(HOST_GAP, w)
        events.append((when, "process", common.canonical_sha256({"command_line": "fake child %d (make.py)" % k}),
                       {"command_head": "bash", "command_programs": ["bash"], "depth": 1}))
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
    if name.startswith("rhythm:"):
        _, scenario, k = name.split(":")
        return rhythm_inventory(scenario, int(k), act_after=_gap(HOST_GAP, w))
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
    }


def os_rounds(k):
    """The rounds before which os_lines are appended, per os fixture, at K."""
    return {
        "HOST-RHYTHM/positive-os-three-cycles.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/negative-os-two-cycles.json": tuple(range(2, k + 1)),
        "HOST-RHYTHM/positive-os-talks-host-acts.json": tuple(range(2, k + 2)),
        "HOST-RHYTHM/positive-host-talks-os-acts.json": tuple(range(2, k + 2)),
    }


def dark_scenarios(streak):
    """M7.2 / M7.5 E1: AGENT-DARK-LIVE's fixtures at the streak S (real
    exports as rounds: "windows" holds a footprint no tree links to; kimi-gone
    is kimi with its tree left out; kimi/one-sample links it again)."""
    return {
        "AGENT-DARK-LIVE/positive-dark-three-rounds.json": ["windows"] * streak,
        "AGENT-DARK-LIVE/negative-dark-two-rounds.json": ["windows"] * (streak - 1),
        "AGENT-DARK-LIVE/negative-dark-then-linked.json": ["kimi-gone"] * streak + ["kimi/one-sample"],
        "AGENT-DARK-LIVE/positive-never-live.json": ["kimi-gone"] * streak,
    }


def arrival_scenarios(benign):
    """C-1b: a benign desktop whose trees arrive after round 1, for each
    benign export name ("benign/linux-desktop", ...): fixed rounds."""
    return {ARRIVAL % name.split("/")[1]: [name + BEFORE, name] for name in benign}


# --- running the rounds ----------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class Follow:
    """M7.5 E2: a fake os follow: one pass that writes nothing, then waits
    for the Stop; the os lines are appended by rounds_of, between rounds."""

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None,
                 helpers=None):
        if on_pass:
            on_pass(1, None)
        stop.wait(60)
        return 1


def rounds_of(names, catalog, rules, home, sources=True, os_rounds=None, inventory=None, w=None, seen=None):
    """The HostWatch fed these rounds in order (finished). inventory(name):
    the inventory of a round name (default: synthetic, else HOSTDATA).
    sources False: a file stands where the sources directory would be, so
    no source can be attached (HOST-UNWATCHED's fixtures). The Sysmon check
    says no (platform "fixture"): every tree gets the host source.
    os_rounds (M7.5 E2): the Sysmon check says yes, every tree gets a fake
    os follow, and before each of these rounds os_lines() are appended to
    the rhythm tree's per-tree file. w: the W the synthetic gaps stay in.
    seen: a list each round's record is appended to as it is made
    (HostWatch keeps only its last ROUNDS_KEPT)."""
    from raqib import host, notify   # here: host imports overlay, which imports this module
    resolve = inventory or (lambda n: synthetic_inventory(n, w) or packaged_inventory(n))
    invs = [resolve(n) for n in names]
    if not sources:
        os.makedirs(os.path.join(home, ".raqib", "host"), exist_ok=True)
        with open(os.path.join(home, ".raqib", "host", host.SOURCES_DIR), "w") as f:
            f.write("not a directory: make.py (NO_SOURCES)\n")
    feed = iter(invs)
    clock = Clock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    os_kw = {} if os_rounds is None else {"os_follow": Follow()}
    watch = host.HostWatch(lambda: next(feed), catalog, rules, notifier, every=10, out=None, err=io.StringIO(),
                           clock=clock, wall=lambda: WALL0 + clock.t, home=home, platform="fixture",
                           run="fixture-run",   # C-2: a fixed run id, so the fixtures are what make.py makes
                           sysmon=(lambda: (False, "fixture: no Sysmon")) if os_rounds is None
                           else (lambda: (True, "fixture: a synthetic os source (make.py)")), **os_kw)
    seq = 0
    for k, name in enumerate(names, start=1):
        if os_rounds is not None and k in os_rounds:
            (key,) = [x for x in watch.trees if x[0] == RHYTHM_PID]
            src = watch.sources[key]
            src.first_pass.wait(5)
            lines, seq = os_lines(k, name.split(":")[1], seq, w=w)
            with open(src.path, "a", encoding="ascii", newline="\n") as f:
                f.write("".join(json.dumps(x, separators=(",", ":"), ensure_ascii=True) + "\n" for x in lines))
        before = watch.round_lines[-1] if watch.round_lines else None
        watch.tick(wait=30)
        if seen is not None and watch.round_lines and watch.round_lines[-1] is not before:
            seen.append(watch.round_lines[-1])
        clock.t += 10
    watch.finish()
    return watch


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
    from raqib.rules import engine
    doc = {"lines": lines}
    if positive:
        found, _ = engine.judge(rule, lines, {})
        doc["expect_seq"] = sorted({s for f in found for s in f["cited_seq"]})
    return doc


def dumps(doc):
    """A fixture's text, byte for byte as the shipped files hold it."""
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def run_lines(names, catalog, rules, sources=True, os_rounds=None, inventory=None, w=None):
    """The host lines of every round of a run of these rounds (oldest
    first), in a temporary home that is removed after it."""
    if not names:
        raise GenerateError("a scenario with no round")
    with tempfile.TemporaryDirectory(prefix="raqib-fixturegen-", ignore_cleanup_errors=True) as home:
        seen = []
        rounds_of(names, catalog, rules, home, sources=sources, os_rounds=os_rounds, inventory=inventory, w=w,
                  seen=seen)
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


# --- the packaged inventories (the real exports' rounds) -------------------------------------------------------

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
    """The benign desktops whose arrivals are shipped (C-1b), sorted."""
    return sorted(n for n in packaged() if n.startswith("benign/") and not n.endswith(BEFORE))


# --- generate -----------------------------------------------------------------------------------------------

def values_of(rule):
    """The thresholds a rule generates at: its own eq values, read as host.py reads them."""
    from raqib import host
    if rule.id == host.RHYTHM:
        params = host.rhythm_params(rule)
        if params is None:
            raise GenerateError("%s does not declare k, w and r" % rule.id)
        return dict(zip(("k", "w", "r"), params))
    if rule.id == host.DARK_LIVE:
        streak, window = host.rule_eq(rule, host.STREAK_FIELD), host.rule_eq(rule, host.LIVE_WINDOW_FIELD)
        if streak is None or window is None:
            raise GenerateError("%s does not declare its streak and live_window" % rule.id)
        return {"streak": streak, "live_window": window}
    raise GenerateError("no generator for %s (generated: %s)" % (rule.id, ", ".join(GENERATED)))


def plan(rule):
    """{fixture name (RULE/file.json): (round names, {sources, os_rounds})}
    of a generated rule at its own values, its arrivals included."""
    values = values_of(rule)
    out = {}
    if "k" in values:
        k = values["k"]
        rounds = os_rounds(k)
        for name, names in rhythm_scenarios(k).items():
            out[name] = (names, {})
        for name, names in os_scenarios(k).items():
            out[name] = (names, {"os_rounds": rounds[name]})
    else:
        if values["streak"] < 2:
            raise GenerateError("streak %d: its negative (streak - 1 dark rounds) has no round" % values["streak"])
        for name, names in dark_scenarios(values["streak"]).items():
            out[name] = (names, {})
    for name, names in arrival_scenarios(benign_names()).items():
        out[name] = (names, {})
    return out, values


def generate(rule, rules=None, catalog=None):
    """The rule's fixtures made at its own thresholds, in memory (see the
    module docstring). rules: the catalog the watch is given (default: the
    package's), with this rule in place of its namesake; catalog: discover's
    endpoints (default: the package's). GenerateError when a fixture of the
    rule has no generator or a round cannot be made."""
    from raqib import discover
    from raqib.rules import engine
    scenarios, values = plan(rule)
    if rules is None:
        rules = engine.load_catalog(os.path.join(HERE, "catalog"))
    rules = [rule if r.id == rule.id else r for r in rules]
    if catalog is None:
        catalog = discover.load_catalog(discover.CATALOG)
    arrivals = sorted(FIXTURE_DIR + name for name in arrival_scenarios(benign_names()))
    out = {"positive": [], "negative": [], "arrivals": arrivals, "values": values, "runs": {},
           "last_round_only": sorted(FIXTURE_DIR + n for n in LAST_ROUND_ONLY if n in scenarios)}
    for kind in ("positive", "negative"):
        paths = list(rule.fixtures[kind])
        if kind == "negative":   # E4: the benign arrivals are measured for every generated rule
            paths += [p for p in arrivals if p not in paths]
        for path in paths:
            name = path[len(FIXTURE_DIR):] if path.startswith(FIXTURE_DIR) else None
            if name not in scenarios:
                raise GenerateError("%s: no generator for fixture %s" % (rule.id, path))
            names, opts = scenarios[name]
            rounds = run_lines(names, catalog, rules, w=values.get("w"), **opts)
            out["runs"][path] = rounds
            out[kind].append((path, fixture_doc(rule, rounds[-1], kind == "positive")))
    return out
