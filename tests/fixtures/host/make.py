"""Make the rule fixtures of NEW-AGENT and AGENT-DARK-LIVE (M7.2), under
tests/fixtures/rules/<RULE>/ as every catalog rule's, from the
discover fixtures: each is a sequence of rounds, each round the inventory
`raqib discover --from DIR` gives for one discover fixture directory, run
through raqib/host.py's HostWatch with a fake clock. The fixture holds the
host lines of the LAST round only (the round judged); the earlier rounds
are its history, written into each line by HostWatch (history,
candidate_before, streak). A test (tests/test_host.py) runs this again and
holds the files to it.

    python3 tests/fixtures/host/make.py

The inventories are of the SYNTHETIC and REAL-redacted discover fixtures
under tests/fixtures/discover (see their headers); "kimi-gone" is
kimi/one-sample with the rows of kimi.exe's tree (pid 10728 and below)
left out of its process file: the agent exited, its footprint stays.
"NAME:before" (M7.2 REDO, ADR-0007 Amendment C, C-1b) is NAME with the
process rows of every candidate tree and act-root tree of NAME's own
inventory left out of each process file: the host before those trees
started. ["benign/X:before", "benign/X"] is a benign desktop whose trees
arrive after round 1, the negatives C-1b asks for, made for every benign
discover fixture with process records (BENIGN).

M7.2b (ADR-0007 decision 3, Amendment H): HOST-UNWATCHED's fixtures are
host lines too, of a watch whose sources directory cannot be written (a
file stands where ~/.raqib/host/sources should be: NO_SOURCES), so no
tree has a source. SOURCE_SCENARIOS are the fixtures of NET-TOOL and
DESTRUCT-CMD over lines of the host source: every line of every per-tree
file under ~/.raqib/host/sources/ after the rounds, in pid order (the trees'
HostChild, HostConnection and HostGone lines). "NAME:rm" is NAME with every
"curl" of its process file written "rm" (SYNTHETIC, made here: no discover
fixture holds a destructive child).

M7.4 (ADR-0007 decision 4): RHYTHM's fixtures are host lines of fake rounds
(SYNTHETIC, made here, "rhythm:" names): rhythm_inventory() builds an
inventory in discover's shape for round k of a scenario - one unknown tree
(pid 4400, image "relay-bot" under a user directory, started at a fixed
ISO UTC time as raqib/hostwin.py records it) that talks to a remote of the
RFC 5737 documentation ranges and has children, each child started 5 s
before the round (inside W after the round before). Scenarios: "cycle" (a
new child every round, one destination), "change" (a new child and a new
destination every round), "between" (the same one child every round: the
children that start and end between rounds are never seen) and "notalk"
(children, no connection: an act-root). The fixture holds the LAST round's
host lines, as the others.
M7.4 REDO K-5: a talk beat is a connection new in the round or one whose
bytes moved; so each round of a scenario with a connection carries the byte
counts a fake `ss -tinp` would give (conn_bytes, growing each round:
bytes_moved), and a connection kept up with no bytes read is one talk only
(bytes_moved False; tests/test_rhythm.py).
"""
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
from raqib import discover, host, notify  # noqa: E402
from raqib.rules import engine  # noqa: E402

DISCOVER = os.path.join(ROOT, "tests", "fixtures", "discover")
KIMI_TREE = ("10728", "7768", "10476", "5796", "8496", "8500")
PROCESS_KINDS = ("proc", "win-process")   # the process files a "before" variant thins
BEFORE = ":before"


def benign_dirs():
    """C-1b: every benign discover fixture with process records."""
    root = os.path.join(DISCOVER, "benign")
    return sorted("benign/" + n for n in os.listdir(root)
                  if any(f.split(".")[0].rsplit("-", 1)[0] in PROCESS_KINDS or f.split(".")[0] in PROCESS_KINDS
                         for f in os.listdir(os.path.join(root, n))))


BENIGN = benign_dirs()
# The benign arrivals are negatives of every host rule (C-1b); they live under NEW-AGENT/.
ARRIVALS = {"NEW-AGENT/negative-arrival-%s.json" % name.split("/")[1]: [name + BEFORE, name] for name in BENIGN}

# file (under tests/fixtures/rules/) -> the discover fixtures read as rounds, in order
SCENARIOS = {
    "NEW-AGENT-UNKNOWN/positive-new-unknown.json": ["benign/windows-desktop", "windows"],
    "NEW-AGENT/positive-new-named-windows.json": ["benign/windows-desktop", "windows"],
    "NEW-AGENT/positive-new-named.json": ["benign/linux-desktop", "linux"],
    "NEW-AGENT/positive-act-root-becomes-candidate.json": ["kimi/one-sample", "kimi/two-samples"],
    "NEW-AGENT/negative-history-only.json": ["linux", "linux"],
    "NEW-AGENT/negative-gone-and-back.json": ["benign/windows-desktop", "windows", "benign/windows-desktop",
                                              "windows"],
    "NEW-AGENT/negative-act-root-only.json": ["benign/linux-desktop", "linux-agent"],
    "AGENT-DARK-LIVE/positive-dark-three-rounds.json": ["windows", "windows", "windows"],
    "AGENT-DARK-LIVE/negative-dark-two-rounds.json": ["windows", "windows"],
    "AGENT-DARK-LIVE/negative-dark-then-linked.json": ["kimi-gone", "kimi-gone", "kimi-gone", "kimi/one-sample"],
}
SCENARIOS.update(ARRIVALS)
NO_SOURCES = {
    "HOST-UNWATCHED/positive-no-source-two-rounds.json": ["linux", "linux"],
    "HOST-UNWATCHED/negative-one-round.json": ["linux"],
}
SCENARIOS.update(NO_SOURCES)
SCENARIOS["HOST-UNWATCHED/negative-host-source.json"] = ["linux", "linux"]
RHYTHM_SCENARIOS = {   # M7.4: fake rounds, "rhythm:<scenario>:<round>"
    "HOST-RHYTHM/positive-three-cycles.json": ["rhythm:cycle:%d" % k for k in range(1, 5)],
    "HOST-RHYTHM/negative-two-cycles.json": ["rhythm:cycle:%d" % k for k in range(1, 4)],
    "HOST-RHYTHM/negative-changing-destination.json": ["rhythm:change:%d" % k for k in range(1, 6)],
    "HOST-RHYTHM/negative-acts-between-rounds.json": ["rhythm:between:%d" % k for k in range(1, 6)],
    "HOST-RHYTHM/negative-no-talk.json": ["rhythm:notalk:%d" % k for k in range(1, 6)],
}
SCENARIOS.update(RHYTHM_SCENARIOS)
WALL0 = 1793700000.0      # the wall clock of rounds_of at t = 0
EVERY = 10                # rounds_of's T
RHYTHM_PID = 4400


def _iso_at(seconds):
    import datetime
    return datetime.datetime.fromtimestamp(WALL0 + seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")


def rhythm_inventory(scenario, k, pid=RHYTHM_PID, image="relay-bot", every=EVERY, remote=None, children=None,
                     bytes_moved=True):
    """Round k (1-based) of a fake scenario, in discover's inventory shape
    (SYNTHETIC). Round k is read at t = (k-1) * every; a child new in round
    k started 5 s before it. bytes_moved: the connection's byte counts (a
    fake ss) grow each round (K-5: a talk beat each round); False: no bytes
    are read (the round carries none)."""
    at = (k - 1) * every
    if children is None:
        if scenario in ("cycle", "change", "notalk"):
            children = list(range(1, k + 1))
        else:   # "between": one child, always the same
            children = [1]
    cites = [{"src": "win-process", "line": 2, "text": "fake process row of pid %d (make.py)" % pid}]
    acts = [{"how": "process", "pid": pid + c, "image": "bash" if c % 2 else "python", "listed": True,
             "path": None, "via": [], "reader_ancestor": False,
             "started": _iso_at((c - 1) * every - 5 if c > 1 else -60),
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
RM = ":rm"
SOURCE_SCENARIOS = {
    "NET-TOOL/positive-host-child.json": ["benign/linux-desktop", "linux-agent"],
    "NET-TOOL/negative-host-child.json": ["benign/windows-desktop", "windows", "linux-agent" + RM],
    "DESTRUCT-CMD/positive-host-child.json": ["benign/linux-desktop", "linux-agent" + RM],
    "DESTRUCT-CMD/negative-host-child.json": ["kimi/one-sample", "kimi/two-samples", "kimi-gone", "linux-agent"],
}
OUT = os.path.join(ROOT, "tests", "fixtures", "rules")


def inventory(name, catalog):
    if name.startswith("rhythm:"):
        _, scenario, k = name.split(":")
        return rhythm_inventory(scenario, int(k))
    if name.endswith(RM):
        base = name[:-len(RM)]
        texts, holes = discover.read_dir(os.path.join(DISCOVER, *base.split("/")))
        for key in sorted(texts):
            if key.rsplit("-", 1)[0] in PROCESS_KINDS or key in PROCESS_KINDS:
                label, text, error = texts[key]
                texts[key] = (label + " (curl written rm: make.py, SYNTHETIC)", text.replace("curl", "rm"), error)
        return discover.run(texts, catalog, holes=holes, run=host_record(os.path.join(DISCOVER, *base.split("/"))))
    if name.endswith(BEFORE):
        base = name[:-len(BEFORE)]
        full = inventory(base, catalog)
        pids = {str(p) for c in full["candidates"] for p in c.get("tree") or [c["pid"]]}
        pids |= {str(a["pid"]) for a in full.get("act_roots") or []}
        pids |= {str(x["pid"]) for a in full.get("act_roots") or [] for x in a.get("acts") or [] if "pid" in x}
        texts, holes = discover.read_dir(os.path.join(DISCOVER, *base.split("/")))
        inodes = set()
        for key in sorted(texts):   # the process rows first: their socket inodes go with them
            if key.rsplit("-", 1)[0] in PROCESS_KINDS or key in PROCESS_KINDS:
                label, text, error = texts[key]
                kept = []
                for line in text.splitlines(True):
                    if _pid_of(line) in pids:
                        inodes |= {str(i) for i in (json.loads(line).get("sockets") or [])} if line.startswith("{") else set()
                    else:
                        kept.append(line)
                texts[key] = (label + " (the arriving trees left out: make.py)", "".join(kept), error)
        for key in sorted(texts):   # then their connections: Windows by owner, Linux by socket inode
            kind = key.rsplit("-", 1)[0] if key[-1:].isdigit() else key
            if kind not in ("win-tcp", "proc-net"):
                continue
            label, text, error = texts[key]
            texts[key] = (label + " (the arriving trees' connections left out: make.py)", "".join(
                line for line in text.splitlines(True)
                if not (kind == "win-tcp" and _owner_of(line) in pids)
                and not (kind == "proc-net" and _inode_of(line) in inodes)), error)
        return discover.run(texts, catalog, holes=holes, run=host_record(os.path.join(DISCOVER, *base.split("/"))))
    if name == "kimi-gone":
        texts, holes = discover.read_dir(os.path.join(DISCOVER, "kimi", "one-sample"))
        label, text, error = texts["win-process-1"]
        kept = [line for line in text.splitlines(True)
                if not any(line.startswith('"%s",' % pid) for pid in KIMI_TREE)]
        texts["win-process-1"] = (label + " (kimi.exe's tree left out: make.py)", "".join(kept), error)
    else:
        texts, holes = discover.read_dir(os.path.join(DISCOVER, *name.split("/")))
    where = os.path.join(DISCOVER, "kimi", "one-sample") if name == "kimi-gone" else os.path.join(DISCOVER, *name.split("/"))
    return discover.run(texts, catalog, holes=holes, run=host_record(where))


SYSTEM_DRIVE = "c"


def host_record(directory):
    """D-3: the run record a host round carries. A Windows round of
    `raqib watch --host` is read live by raqib/hostwin.py, which records
    SystemRoot's drive; the Windows discover fixtures are the README loop's
    exports (with a run.json that holds none, or none at all), so their rounds are given drive
    "c" (SYSTEM_DRIVE), as hostwin would record it on such a host. A Linux
    fixture has no run record."""
    record = discover.run_record(directory)
    if any(n.startswith("win-process") for n in os.listdir(directory)):
        record = dict(record or {}, system_drive=SYSTEM_DRIVE)
    return record


def _pid_of(line):
    """The pid of a process line: a proc.txt JSON line, or a Win32_Process CSV row."""
    if line.startswith("{"):
        try:
            return str(json.loads(line).get("pid"))
        except ValueError:
            return None
    if line.startswith('"'):
        return line[1:].split('"', 1)[0]
    return None


def _owner_of(line):
    """OwningProcess of a Get-NetTCPConnection CSV row (its 6th column)."""
    cells = line.strip().split('","')
    return cells[5].strip('"') if line.startswith('"') and len(cells) >= 6 else None


def _inode_of(line):
    """The inode of a /proc/net/tcp row (its 10th field)."""
    parts = line.split()
    return parts[9] if len(parts) > 9 and parts[0].endswith(":") and parts[0][:-1].isdigit() else None


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def rounds_of(names, catalog, rules, home, sources=True):
    """The round records of a HostWatch fed these inventories in order.
    sources False: a file stands where the sources directory would be, so
    no source can be attached (HOST-UNWATCHED's fixtures). The Sysmon check
    says no (platform "fixture"): every tree gets the host source."""
    invs = [inventory(n, catalog) for n in names]
    if not sources:
        os.makedirs(os.path.join(home, ".raqib", "host"), exist_ok=True)
        with open(os.path.join(home, ".raqib", "host", host.SOURCES_DIR), "w") as f:
            f.write("not a directory: make.py (NO_SOURCES)\n")
    feed = iter(invs)
    clock = Clock()
    notifier = notify.Notifier(host.HOST, enabled=False, reason="fixture", host=True)
    watch = host.HostWatch(lambda: next(feed), catalog, rules, notifier, every=10, out=None, err=io.StringIO(),
                           clock=clock, wall=lambda: 1793700000.0 + clock.t, home=home, platform="fixture",
                           run="fixture-run",   # C-2: a fixed run id, so the fixtures are what make.py makes
                           sysmon=lambda: (False, "fixture: no Sysmon"))
    for _ in names:
        watch.tick(wait=30)
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


def build():
    catalog = discover.load_catalog(discover.CATALOG)
    rules = engine.load_catalog(os.path.join(ROOT, "raqib", "rules", "catalog"))
    out = {}
    with tempfile.TemporaryDirectory() as home:
        for name, names in list(SCENARIOS.items()) + list(SOURCE_SCENARIOS.items()):
            watch = rounds_of(names, catalog, rules, os.path.join(home, name.replace("/", "-")),
                              sources=name not in NO_SOURCES)
            lines = source_lines(watch) if name in SOURCE_SCENARIOS else watch.round_lines[-1]["lines"]
            rule_id, base = name.split("/")
            doc = {"lines": lines}
            if base.startswith("positive-"):   # what this fixture's own rule must cite
                found, _ = engine.evaluate([r for r in rules if r.id == rule_id], lines)
                doc["expect_seq"] = sorted({s for f in found for s in f["cited_seq"]})
            out[name] = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    return out


def main():
    for name, text in build().items():
        path = os.path.join(OUT, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write(text)


if __name__ == "__main__":
    main()
