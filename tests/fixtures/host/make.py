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

M7.5 (ADR-0007 Amendment M, the first field run):
E1 - AGENT-DARK-LIVE's fixtures after a live tree (REDO N-2: the two
negatives are under tests/fixtures/host/notes/, not the rule's): "kimi-gone" then
"kimi/two-samples" (kimi a candidate: the footprint links to it, so it was
live in this watch) then "kimi-gone" three times is a negative (dark after a
live tree: a note, input_meta.was_live true); the same with kimi live again
and gone again is the second negative; "kimi-gone" three times (never live)
is the positive. Every HostFootprint line now carries was_live, so every
fixture that holds one was made again (the field is new on the line).
E2 - HOST-RHYTHM over an os source ("rhythm-os:" names, SYNTHETIC): the tree
of rhythm_inventory gets the os source (a fake Sysmon check and a fake
follow that writes nothing), and before round k (OS_ROUNDS) make.py appends
to the tree's per-tree file the lines os_sysmon would write for a Sysmon
event 3 (net, the same destination each time) at 8 s and, in "oscycle",
an event 1 (process, depth 1) at 5 s before round k's time. The tree's
inventory keeps one child seen from round 1 on and a connection with no
bytes read, so the host gives one talk (round 1) and no act: the cycles are
the os source's. "ostalk" keeps the host's new child each round ("cycle")
and takes only the talks from os: the talks are os, the acts host.
M7.5 REDO N-3: "osact" is the field run's shape (Amendment M: kimi's acts
came from the os source, its talk from the host's TCP table): the host's
connection talks each round (bytes read and moving, K-5) and the acts are
os event 1 lines, 5 s before each round from round 2 on.
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, ROOT)
from raqib import discover, host  # noqa: E402
from raqib.rules import engine, fixturegen  # noqa: E402
from raqib.rules.fixturegen import (BEFORE, EVERY, OS_DEST, RHYTHM_PID, SYSTEM_DRIVE, WALL0,  # noqa: E402,F401
                                    _iso_at, os_lines, rhythm_inventory, source_lines)
from raqib.host import FixtureClock as Clock, FixtureFollow as _Follow  # noqa: E402,F401

DISCOVER = os.path.join(ROOT, "tests", "fixtures", "discover")
CATALOG_DIR = os.path.join(ROOT, "raqib", "rules", "catalog")
KIMI_TREE = ("10728", "7768", "10476", "5796", "8496", "8500")
PROCESS_KINDS = ("proc", "win-process")   # the process files a "before" variant thins


def benign_dirs():
    """C-1b: every benign discover fixture with process records."""
    root = os.path.join(DISCOVER, "benign")
    return sorted("benign/" + n for n in os.listdir(root)
                  if any(f.split(".")[0].rsplit("-", 1)[0] in PROCESS_KINDS or f.split(".")[0] in PROCESS_KINDS
                         for f in os.listdir(os.path.join(root, n))))


def declared():
    """The thresholds the YAMLs declare (k, w, r; streak, live_window): the shipped fixtures are made at them."""
    rules = {r.id: r for r in engine.load_catalog(CATALOG_DIR)}
    out = {}
    for rid in fixturegen.GENERATED:
        out.update(fixturegen.values_of(rules[rid]))
    return out


DECLARED = declared()
BENIGN = benign_dirs()
# The benign arrivals are negatives of every host rule (C-1b); they live under NEW-AGENT/.
ARRIVALS = fixturegen.arrival_scenarios(BENIGN)

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
}
SCENARIOS.update(fixturegen.dark_scenarios(DECLARED["streak"]))   # M7.2, M7.5 E1 (made at the declared streak)
SCENARIOS.update(ARRIVALS)
NO_SOURCES = {
    "HOST-UNWATCHED/positive-no-source-two-rounds.json": ["linux", "linux"],
    "HOST-UNWATCHED/negative-one-round.json": ["linux"],
}
SCENARIOS.update(NO_SOURCES)
SCENARIOS["HOST-UNWATCHED/negative-host-source.json"] = ["linux", "linux"]
# M7.9 REDO 4 (ADR-0007 AB-5): a round of the quiet host whose channel read holds an unknown program that starts,
# talks and acts between two rounds: its line is listed by the channel, and NEW-AGENT-UNKNOWN does not fire on it
SCENARIOS["NEW-AGENT-UNKNOWN/negative-by-the-channel.json"] = ["channel/quiet", "channel/quiet+agentx"]
RHYTHM_SCENARIOS = fixturegen.rhythm_scenarios(DECLARED["k"])   # M7.4: fake rounds, "rhythm:<scenario>:<round>"
SCENARIOS.update(RHYTHM_SCENARIOS)
# M7.5 E1, REDO N-2: a footprint whose tree was live in this watch, then dark: host.py's NOTE, which
# AGENT-DARK-LIVE's match cannot see (was_live true), so they are not its measured negatives (as K-9): they
# live under tests/fixtures/host/notes/ (NOTES_OUT), made by build_notes(), held by tests/test_field_run.py.
NOTE_SCENARIOS = {
    "negative-live-then-gone.json": ["kimi-gone", "kimi/two-samples"] + ["kimi-gone"] * 3,
    "negative-linked-again.json": ["kimi-gone", "kimi/two-samples", "kimi-gone", "kimi-gone",
                                   "kimi/two-samples"] + ["kimi-gone"] * 3,
}
OS_SCENARIOS = fixturegen.os_scenarios(DECLARED["k"])   # M7.5 E2: "rhythm-os:<scenario>:<round>"
OS_ROUNDS = fixturegen.os_rounds(DECLARED["k"])         # the rounds os lines are appended before
SCENARIOS.update(OS_SCENARIOS)
# M7.6c REDO E-2: the edge pairs of w, r and live_window, at the declared values (opts: the rounds' period)
EDGE_SCENARIOS = {}
SCENARIO_OPTS = {}
for _name, _v in fixturegen.w_scenarios(DECLARED["k"], DECLARED["w"]).items():
    EDGE_SCENARIOS[_name], SCENARIO_OPTS[_name] = _v
EDGE_SCENARIOS.update(fixturegen.r_scenarios(DECLARED["k"], DECLARED["r"]))
EDGE_SCENARIOS.update(fixturegen.window_scenarios(DECLARED["streak"], DECLARED["live_window"]))
SCENARIOS.update(EDGE_SCENARIOS)
RM = ":rm"
SOURCE_SCENARIOS = {
    "NET-TOOL/positive-host-child.json": ["benign/linux-desktop", "linux-agent"],
    "NET-TOOL/negative-host-child.json": ["benign/windows-desktop", "windows", "linux-agent" + RM],
    "DESTRUCT-CMD/positive-host-child.json": ["benign/linux-desktop", "linux-agent" + RM],
    "DESTRUCT-CMD/negative-host-child.json": ["kimi/one-sample", "kimi/two-samples", "kimi-gone", "linux-agent"],
}
OUT = os.path.join(ROOT, "tests", "fixtures", "rules")
# M7.6c: the exports' inventories fixturegen needs (AGENT-DARK-LIVE's rounds and the benign arrivals)
HOSTDATA_NAMES = sorted({n for v in fixturegen.dark_scenarios(DECLARED["streak"]).values() for n in v}
                        | {n for v in fixturegen.window_scenarios(DECLARED["streak"], 2).values() for n in v}
                        | {n for v in ARRIVALS.values() for n in v})


def inventory(name, catalog, w=None):
    """The inventory of a round name: a synthetic one (fixturegen), else
    discover.run over the discover export it names (with the variants
    below)."""
    if name.startswith("channel/"):   # M7.9 REDO 4 (AB-5): the quiet host, and its channel read (SYNTHETIC)
        quiet = os.path.join(HERE, "quiet", "quiet")
        texts, holes = discover.read_dir(quiet)
        read = name.endswith("+agentx")
        if read:
            with open(os.path.join(HERE, "channel", "agentx.sysmon.xml"), encoding="ascii") as f:
                texts["sysmon"] = ("tests/fixtures/host/channel/agentx.sysmon.xml (SYNTHETIC)", f.read(), None)
        return discover.run(texts, catalog, holes=holes, run=host_record(quiet), processes=True, channel=read)
    synthetic = fixturegen.synthetic_inventory(name, w)
    if synthetic is not None:
        return synthetic
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


def rounds_of(names, catalog, rules, home, sources=True, os_rounds=None, **opts):
    """host.fixture_rounds (the builder fixturegen is handed) over the discover exports (inventory())."""
    return host.fixture_rounds(names, catalog, rules, home, lambda n: inventory(n, catalog), sources=sources,
                               os_rounds=os_rounds, w=DECLARED["w"], **opts)


def build():
    catalog = discover.load_catalog(discover.CATALOG)
    rules = engine.load_catalog(CATALOG_DIR)
    out = {}
    with tempfile.TemporaryDirectory() as home:
        for name, names in list(SCENARIOS.items()) + list(SOURCE_SCENARIOS.items()):
            watch = rounds_of(names, catalog, rules, os.path.join(home, name.replace("/", "-")),
                              sources=name not in NO_SOURCES, os_rounds=OS_ROUNDS.get(name),
                              **SCENARIO_OPTS.get(name, {}))
            lines = source_lines(watch) if name in SOURCE_SCENARIOS else watch.round_lines[-1]["lines"]
            rule_id, base = name.split("/")
            # positive-: what this fixture's own rule must cite
            doc = fixturegen.fixture_doc(next(r for r in rules if r.id == rule_id), lines,
                                         base.startswith("positive-"))
            out[name] = fixturegen.dumps(doc)
    return out


NOTES_OUT = os.path.join(HERE, "notes")


def build_notes():
    """N-2: the last round's lines of each NOTE_SCENARIOS run (host.py's note, not a rule's fixture)."""
    catalog = discover.load_catalog(discover.CATALOG)
    rules = engine.load_catalog(CATALOG_DIR)
    out = {}
    with tempfile.TemporaryDirectory() as home:
        for name, names in NOTE_SCENARIOS.items():
            watch = rounds_of(names, catalog, rules, os.path.join(home, name))
            out[name] = json.dumps({"lines": watch.round_lines[-1]["lines"], "dark_notes": [
                d["round"] for d in watch.dark_notes]}, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    return out


def build_hostdata():
    """M7.6c: the text of raqib/rules/hostdata/inventories.json: the
    inventory discover.run gives for each export round of HOSTDATA_NAMES
    with every path written relative to the repository root
    (fixturegen.portable: the catalog's, each source file's label), so the
    file is the same on every machine; compact, sorted keys, ASCII."""
    catalog = discover.load_catalog(discover.CATALOG)
    invs = {name: fixturegen.portable(inventory(name, catalog), ROOT) for name in HOSTDATA_NAMES}
    doc = {"about": "M7.6c (ADR-0008 Amendment B): discover.run's inventory of each discover export round"
                    " raqib/rules/fixturegen.py replays at a changed threshold; written by"
                    " tests/fixtures/host/make.py from tests/fixtures/discover (real, redacted, and SYNTHETIC"
                    " exports: see their headers); do not edit by hand",
           "inventories": invs}
    return json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"


def main():
    os.makedirs(NOTES_OUT, exist_ok=True)
    for name, text in build_notes().items():
        with open(os.path.join(NOTES_OUT, name), "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    for name, text in build().items():
        path = os.path.join(OUT, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    os.makedirs(os.path.dirname(fixturegen.HOSTDATA), exist_ok=True)
    with open(fixturegen.HOSTDATA, "w", encoding="ascii", newline="\n") as f:
        f.write(build_hostdata())


if __name__ == "__main__":
    main()
