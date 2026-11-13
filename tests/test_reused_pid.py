"""M7.26 (ADR-0007 Amendments BE and BF): a reused pid is not a parent.

Every record here is SYNTHETIC (made in memory, as tests/fixtures/discover/synthetic.py makes a Windows sample, with
the live reader's ISO UTC CreationDate): user `user`, host `host`, RFC 5737 documentation addresses only. Nothing
was captured from a machine.
"""
import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "discover"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))

from raqib import discover, host, hostwin  # noqa: E402
from raqib.rules import engine  # noqa: E402
import synthetic  # noqa: E402
import make as host_fixtures  # noqa: E402
from test_watch import FakeRunner, make_notifier  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
AT = "2026-11-13T10:00:30.000Z"
W = "C:\\Windows\\System32\\"
AGENTX = "C:\\Users\\user\\AppData\\Local\\Programs\\agentx\\agentx.exe"
PYTHON = "C:\\Users\\user\\raqib\\Scripts\\python.exe"
BROKEN = "parent link(s) broken by their starts (ADR-0007 BE-1)"
UNREAD = "parent link(s) kept with a start unread"


def row(pid, ppid, name, path, start, argv=None):
    """A Win32_Process row as the live reader writes it; start "HH:MM:SS.fff" on 2026-11-13 (UTC), "" unread, or a
    text taken as it is (an export's local CreationDate)."""
    when = start if not start or "/" in start else "2026-11-13T%sZ" % start
    return (pid, ppid, name, path, name if argv is None else argv, when)


def field_rows(reader="10:00:00.000", chain=("07:40:09.000", "07:40:10.000", "09:30:00.000", "09:31:00.000")):
    """BE-4, the field's shape: the reader's pid (732) is the parent pid of an old chain (wininit and services,
    started hours before the reader) under which a talker (agentx) with a child (cmd) lives; the reader's own child
    (wevtutil) starts after it. `chain`: the starts of wininit, services, agentx and cmd."""
    return [row(0, 0, "System Idle Process", None, "07:40:02.000", ""), row(4, 0, "System", None, "07:40:02.000", ""),
            row(700, 732, "wininit.exe", W + "wininit.exe", chain[0]),
            row(760, 700, "services.exe", W + "services.exe", chain[1]),
            row(2400, 760, "agentx.exe", AGENTX, chain[2]),
            row(2410, 2400, "cmd.exe", W + "cmd.exe", chain[3]),
            row(3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", "07:41:00.000"),
            row(5100, 3000, "powershell.exe", W + "WindowsPowerShell\\v1.0\\powershell.exe", "09:59:00.000"),
            row(732, 5100, "python.exe", PYTHON, reader),
            row(7400, 732, "wevtutil.exe", W + "wevtutil.exe", "10:00:20.000")]


TALK = [("192.0.2.10", 50500, "203.0.113.40", 443, "Established", 2400, "2026-11-13T09:30:05.000Z")]


def texts(rows, self_="732", talk=TALK):
    """{source: (path, text, error)} of one sample of the live reader (SNAPSHOT_LINE first), or of an export
    (self_ None: no snapshot line)."""
    head = [hostwin.SNAPSHOT_LINE % (AT, self_, 1)] if self_ else []
    procs = "\n".join(head + [synthetic.csv_line(synthetic.WIN_PROCESS)] + [synthetic.csv_line(r) for r in rows])
    tcp = "\n".join([synthetic.csv_line(synthetic.WIN_TCP)] + [synthetic.csv_line(t) for t in talk])
    return {"win-process-1": ("tests/test_reused_pid.py win-process-1 (SYNTHETIC)", procs + "\n", None),
            "win-tcp-1": ("tests/test_reused_pid.py win-tcp-1 (SYNTHETIC)", tcp + "\n", None)}


def build(rows, self_="732", talk=TALK):
    return discover.run(texts(rows, self_, talk), CATALOG, live=True, processes=True)


def trees(inv):
    return [(c["pid"], c["tree"]) for c in inv["candidates"]]


def acted(inv):
    return {a["pid"] for c in inv["candidates"] for a in c["acts"]} | {
        a["pid"] for t in inv["act_roots"] for a in t["acts"]} | {q for c in inv["candidates"] for q in c["tree"]}


def link_holes(inv):
    return [h for h in inv["holes"] if BROKEN in h or UNREAD in h]


# --- E1 (BE-1): ancestors() and _descendants() do not cross a link whose parent started after the child -------

def proc(pid, ppid, started=None, created=None):
    """A process of a round: `started` its sampled start (None: not read), `created` its channel event 1 UtcTime."""
    recs = []
    if started is not None:
        recs.append({"kind": "proc", "src": "win-process-1", "started": started})
    if created is not None:
        recs.append({"kind": "proc", "src": "sysmon", "created": True, "ts": discover._ts(created)})
    return {"pid": pid, "ppid": ppid, "recs": recs}


def dated(procs, channel=False):
    return discover._date_links({p["pid"]: p for p in procs}, channel)


def chain(c_start, b_start, channel=False, b_created=None, c_created=None):
    """A(100) -> B(200) -> C(300) -> D(400): B's start against C's decides the middle link."""
    return dated([proc(100, 1, "2026-11-13T08:00:00.000Z"), proc(200, 100, b_start, b_created),
                  proc(300, 200, c_start, c_created), proc(400, 300, "2026-11-13T09:00:00.000Z")], channel)


def test_e1_one_source_any_later_start_breaks_the_link_and_the_chain_ends_there():
    procs = chain("2026-11-13T08:30:00.000Z", "2026-11-13T08:30:00.001Z")   # B 1 ms after C: B's pid was reused
    assert procs[300]["link"] == "broken"
    assert list(discover.ancestors(procs, 400)) == [300]          # nothing above the broken link is an ancestor
    assert list(discover.ancestors(procs, 300)) == []
    assert discover._descendants(procs, 100) == {200} and discover._descendants(procs, 200) == set()
    kept = chain("2026-11-13T08:30:00.000Z", "2026-11-13T08:30:00.000Z")   # the same start: not after it
    assert kept[300]["link"] == "kept"
    assert list(discover.ancestors(kept, 400)) == [300, 200, 100, 1]
    assert discover._descendants(kept, 100) == {200, 300, 400}
    # the channel's two event 1 times are one source too: any later start breaks
    both = chain(None, None, True, b_created="2026-11-13T08:30:00.500Z", c_created="2026-11-13T08:30:00.400Z")
    assert both[300]["link"] == "broken" and list(discover.ancestors(both, 400)) == [300]


def test_e1_two_sources_break_only_above_guid_same_seconds():
    near = "2026-11-13T08:30:01.500Z"   # the parent's channel start 1.5 s after the child's sampled start
    far = "2026-11-13T08:30:02.500Z"    # 2.5 s after
    assert discover.GUID_SAME_SECONDS == 2.0
    procs = chain("2026-11-13T08:30:00.000Z", None, True, b_created=near)
    assert procs[300]["link"] == "kept" and list(discover.ancestors(procs, 400)) == [300, 200, 100, 1]
    procs = chain("2026-11-13T08:30:00.000Z", None, True, b_created=far)
    assert procs[300]["link"] == "broken" and list(discover.ancestors(procs, 400)) == [300]
    assert discover._descendants(procs, 100) == {200}
    procs = chain(None, "2026-11-13T08:30:02.500Z", True, c_created="2026-11-13T08:30:00.000Z")   # the other way
    assert procs[300]["link"] == "broken"
    # BF-5: a round that does not read the channel dates no link by it
    procs = chain("2026-11-13T08:30:00.000Z", None, False, b_created=far)
    assert procs[300]["link"] == "unread" and list(discover.ancestors(procs, 400)) == [300, 200, 100, 1]
    # the same 1.5 s from one source breaks (the slack is for two sources only)
    assert chain("2026-11-13T08:30:00.000Z", near)[300]["link"] == "broken"


def test_e1_a_start_unread_on_either_side_keeps_the_link():
    for c_start, b_start in ((None, "2026-11-13T08:30:05.000Z"), ("2026-11-13T08:30:00.000Z", None),
                             ("2026-11-13T08:30:00.000Z", "11/13/2026 9:30:05 AM"),   # an export's local text
                             ("11/13/2026 8:30:00 AM", "2026-11-13T08:30:05.000Z")):
        procs = chain(c_start, b_start)
        assert procs[300]["link"] == "unread", (c_start, b_start)
        assert list(discover.ancestors(procs, 400)) == [300, 200, 100, 1]
        assert discover._descendants(procs, 100) == {200, 300, 400}
        proven = {200} if procs[200]["link"] == "kept" else set()   # B's own link proven only where B's start read
        assert discover._descendants(procs, 100, proven=True) == proven   # BE-2: proven links only


def test_e1_bf4_the_linux_key_is_read_as_its_ticks():
    procs = chain("boot+500", "boot+600")
    assert procs[300]["link"] == "broken" and list(discover.ancestors(procs, 400)) == [300]
    procs = chain("boot+500", "boot+400")
    assert procs[300]["link"] == "kept" and list(discover.ancestors(procs, 400)) == [300, 200, 100, 1]
    assert chain("boot+500", "2026-11-13T08:30:05.000Z")[300]["link"] == "unread"   # two kinds: not compared


# --- E2 (BE-4): the field's shape ----------------------------------------------------------------------------

def test_e2_the_reader_given_an_old_chains_parent_pid_still_sees_the_talker():
    inv = build(field_rows())
    assert inv["self"] == [732] and inv["result"] == "alarm" and inv["exit"] == 1
    assert trees(inv) == [(2400, [2400, 2410])]                    # the talker with its child: a candidate
    assert [a["pid"] for a in inv["candidates"][0]["acts"]] == [2410]
    assert 7400 not in acted(inv)                                  # the reader's own child: nobody's act, no tree
    assert link_holes(inv) == ["1 " + BROKEN + ": the process that holds the parent pid started after the child, so"
                               " the pid was taken again; the child has no parent in this round (its acts go to no"
                               " ancestor through it): pid 700 under parent pid 732 (the reader's own pid)"]
    assert discover.ALWAYS_HOLES[2] in inv["holes"]


def test_e2_negative_a_reader_that_started_first_holds_the_chain_as_its_own():
    inv = build(field_rows(chain=("10:00:01.000", "10:00:02.000", "10:00:03.000", "10:00:04.000")))   # the chain started after the reader: its own
    assert trees(inv) == [] and inv["result"] == "none-seen" and link_holes(inv) == []


# --- E3: the reused pid is a launcher's; the reader's launcher walk; a stale link that is not the reader's ------

def launcher_rows():
    """The reader 7320 (python) under its launcher 732 (raqib.exe, A-7), whose pid is the old chain's parent pid."""
    rows = [r for r in field_rows() if r[0] not in (732, 7400)]
    return rows + [row(732, 5100, "raqib.exe", "C:\\Users\\user\\raqib\\Scripts\\raqib.exe", "09:59:30.000"),
                   row(7320, 732, "python.exe", PYTHON, "10:00:00.000"),
                   row(7400, 7320, "wevtutil.exe", W + "wevtutil.exe", "10:00:20.000")]


def test_e3_the_reused_pid_of_a_launcher_is_no_parent_either():
    inv = build(launcher_rows(), self_="7320,732")
    assert inv["self"] == [732, 7320] and trees(inv) == [(2400, [2400, 2410])] and 7400 not in acted(inv)
    assert [h.rsplit(": ", 1)[1] for h in link_holes(inv)] == ["pid 700 under parent pid 732 (the reader's own pid)"]


def test_e3_bf7_the_readers_launcher_walk_names_only_proven_launchers():
    procs = [(5100, 3000, "powershell.exe"), (732, 5100, "raqib.exe"), (7320, 732, "python.exe"),
             (7330, 7320, "python.exe")]
    read = {5100: "2026-11-13T09:59:00.000000Z", 732: "2026-11-13T09:59:30.000000Z",
            7320: "2026-11-13T10:00:00.000000Z", 7330: "2026-11-13T10:00:01.000000Z"}
    assert hostwin.self_tree(procs, 7330, read) == [7330, 7320, 732]               # every link proven
    younger = {**read, 7320: "2026-11-13T10:00:02.000000Z"}                  # 7320 started after 7330
    assert hostwin.self_tree(procs, 7330, younger) == [7330]                       # the chain ends: nothing above
    middle = {**read, 732: "2026-11-13T10:00:00.500000Z"}                    # a younger raqib.exe mid-chain
    assert hostwin.self_tree(procs, 7330, middle) == [7330, 7320]
    for unread in ({**read, 732: ""}, {k: v for k, v in read.items() if k != 732}):   # the launcher's start
        assert hostwin.self_tree(procs, 7330, unread) == [7330, 7320]
    assert hostwin.self_tree(procs, 7330, {**read, 7320: ""}) == [7330]       # its child's start not read
    assert hostwin.self_tree(procs, 7330, {**read, 7330: ""}) == [7330]       # the reader's own not read


def stranger_rows(cmd_start):
    """A stranger (node, a talker) holds pid 4000, which an older cmd.exe names as its parent pid."""
    rows = [r for r in field_rows() if r[0] not in (700, 760, 2400, 2410)]
    return rows + [row(4000, 3000, "node.exe", "C:\\Program Files\\nodejs\\node.exe", "10:00:00.000"),
                   row(4100, 4000, "cmd.exe", W + "cmd.exe", cmd_start)]


def test_e3_a_child_whose_parent_pid_a_younger_stranger_holds_is_not_the_strangers_act():
    talk = [("192.0.2.10", 50510, "203.0.113.41", 443, "Established", 4000, "2026-11-13T10:00:01.000Z")]
    inv = build(stranger_rows("08:00:00.000"), talk=talk)
    assert trees(inv) == [] and 4100 not in acted(inv)
    assert [h.rsplit(": ", 1)[1] for h in link_holes(inv)] == ["pid 4100 under parent pid 4000"]
    inv = build(stranger_rows("10:00:05.000"), talk=talk)            # negative: its real child is its act
    assert trees(inv) == [(4000, [4000, 4100])] and link_holes(inv) == []


# --- E4 (BE-2): the reader's own tree is proven, never assumed ---------------------------------------------------

def under_reader(reader, agentx):
    """The talker agentx (2400, with its child cmd) directly under the reader's pid (732)."""
    rows = [r for r in field_rows(reader=reader) if r[0] not in (700, 760, 2400, 2410)]
    return rows + [row(2400, 732, "agentx.exe", AGENTX, agentx), row(2410, 2400, "cmd.exe", W + "cmd.exe",
                                                                     "10:00:11.000")]


def test_e4_a_process_under_the_reader_with_a_start_unread_is_judged_as_any_other():
    for reader, agentx in (("10:00:00.000", ""), ("", "10:00:10.000")):
        inv = build(under_reader(reader, agentx))
        assert trees(inv) == [(2400, [2400, 2410])], (reader, agentx)   # not the reader's: a candidate
        (said,) = [h for h in link_holes(inv) if UNREAD in h]
        assert "not taken for the reader's (BE-2), judged as any other process: pid 2400 under parent pid 732 (the"\
            " reader's own pid)" in said, said


def test_e4_negative_the_readers_real_children_stay_out_of_every_tree():
    inv = build(under_reader("10:00:00.000", "10:00:10.000"))       # both starts read, agentx after the reader
    assert trees(inv) == [] and 2400 not in acted(inv) and 7400 not in acted(inv) and link_holes(inv) == []


# --- E5 (BE-3, BF-2, BF-3, BF-6): the inventory's holes ---------------------------------------------------------

def test_e5_the_links_broken_sorted_at_most_20_the_count_whole():
    rows = [r for r in field_rows() if r[0] not in (2400, 2410)]
    rows += [row(900, 760, "notepad.exe", W + "notepad.exe", "10:00:10.000")]
    rows += [row(1000 + k, 900, "conhost.exe", W + "conhost.exe", "08:00:00.000") for k in range(24, -1, -1)]
    inv = build(rows)
    (said,) = [h for h in link_holes(inv) if BROKEN in h]
    assert said.startswith("26 " + BROKEN)                          # 25 under notepad, wininit under the reader
    shown = said.split("(its acts go to no ancestor through it): ", 1)[1]
    assert shown == ", ".join(["pid 700 under parent pid 732 (the reader's own pid)"] +
                              ["pid %d under parent pid 900" % (1000 + k) for k in range(19)]) + " and 6 more"
    assert [h for h in link_holes(inv) if UNREAD in h] == []        # every start read: nothing unread to count


def test_e5_bf3_the_links_unread_are_counted_only_where_the_reader_dates():
    rows = [r if r[0] != 3000 else row(3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", "") for r in
            field_rows(chain=("10:00:01.000", "10:00:02.000", "10:00:03.000", "10:00:04.000"))]
    inv = build(rows)                                                # a live round: explorer's start unread
    assert link_holes(inv) == ["1 " + UNREAD + ", the child's or its parent's (ADR-0007 BE-3): a pid taken again"
                               " cannot be told there, so the child is taken for a child of the pid's present"
                               " holder and \"reparented acts\" above does not hold for it"]
    local = [r[:5] + ("11/13/2026 %d:00:00 AM" % (7 + i % 3),) for i, r in enumerate(field_rows())]
    export = build(local, self_=None)                                # an export: local texts date no link
    assert link_holes(export) == [] and discover.ALWAYS_HOLES[2] in export["holes"]
    # on any round, a process that hangs under the reader's own pid by a link not dated is named
    inv = build(local, self_="732")
    assert link_holes(inv) == ["%d %s, the child's or its parent's (ADR-0007 BE-3): a pid taken again cannot be told"
                               " there, so the child is taken for a child of the pid's present holder and"
                               " \"reparented acts\" above does not hold for it; not taken for the reader's (BE-2),"
                               " judged as any other process: pid 700 under parent pid 732 (the reader's own pid),"
                               " pid 7400 under parent pid 732 (the reader's own pid)" % (8, UNREAD)]


def test_e5_bf2_the_always_hole_keeps_its_words():
    assert discover.ALWAYS_HOLES[2] == (
        "reparented acts: a child started with setsid, nohup or a double fork, or whose parent exited"
        " (reparented to init; on Windows a dead parent's pid can be reused), is not attributed")


# --- E6 (BE-1's MUST NOT TOUCH): no existing fixture holds a reused pid; Linux breaks nothing --------------------

def fixture_dirs():
    out = []
    for base in ("discover", "host"):
        for d, _, files in os.walk(str(ROOT / "tests" / "fixtures" / base)):
            if any(f.startswith(("win-process", "proc")) for f in files):
                out.append(d)
    return sorted(out)


def test_e6_no_existing_fixture_breaks_a_link_or_says_a_new_hole_but_quiet_unread():
    seen = []
    for d in fixture_dirs():
        texts_, holes = discover.read_dir(d)
        inv = discover.run(texts_, CATALOG, holes=holes, processes=True, run=host_fixtures.host_record(d))
        name = os.path.relpath(d, str(ROOT / "tests" / "fixtures")).replace(os.sep, "/")
        assert not any(BROKEN in h for h in inv["holes"]), name
        if link_holes(inv):
            seen.append((name, [h.split(",", 1)[0] for h in link_holes(inv)]))
    assert len(fixture_dirs()) >= 18 and any("linux" in d for d in fixture_dirs())
    assert seen == [("host/quiet/quiet-unread", ["2 " + UNREAD])]   # BF-3: a live round with starts unread


# --- E7: through the host watch -----------------------------------------------------------------------------------

def test_e7_the_host_watch_over_the_field_shape_lists_the_talkers_tree_not_none_seen(tmp_path):
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    clock = {"t": 1000.0}
    w = host.HostWatch(lambda: build(field_rows()), CATALOG, RULES, notifier, every=10, rounds_max=None,
                       out=io.StringIO(), err=io.StringIO(), clock=lambda: clock["t"],
                       wall=lambda: 1794564000.0 + clock["t"] - 1000.0, home=str(tmp_path / "home"), platform="test")
    for _ in range(2):
        w.tick(wait=30)
        clock["t"] += w.every
    text, code = w.finish()
    keys = [k for k in w.trees if k[0] == 2400]
    assert len(keys) == 1 and w.trees[keys[0]]["class"] == "candidate"
    assert not [k for k in w.trees if k[0] in (7400, 700, 760)]
    assert "NONE-SEEN" not in text and code == 0                     # round 1's trees are the host's history
    assert "CLEAN: 1 tree(s) listed, none new: agentx pid 2400" in text and "RESULT: CLEAN (exit 0" in text


# --- E1 (BE-1, FOR the act roots): an act-root's shell is a parent only by a date --------------------------

def act_root_rows(shell):
    """agentx under the user's AppData, started from a listed shell (powershell), runs cmd which runs ping; it never
    talks. `shell`: the start of the process that holds the shell's pid."""
    return [row(760, 700, "services.exe", W + "services.exe", "07:40:10.000"),
            row(3000, 2990, "explorer.exe", "C:\\Windows\\explorer.exe", "07:41:00.000"),
            row(5100, 3000, "powershell.exe", W + "WindowsPowerShell\\v1.0\\powershell.exe", shell),
            row(2400, 5100, "agentx.exe", AGENTX, "09:30:00.000"),
            row(2410, 2400, "cmd.exe", W + "cmd.exe", "09:31:00.000"),
            row(2420, 2410, "PING.EXE", W + "PING.EXE", "09:31:01.000")]


def test_e1_an_act_root_whose_shells_pid_a_younger_process_holds_is_not_one():
    listen = [("0.0.0.0", 135, "0.0.0.0", 0, "Listen", 760, "2026-11-13T07:40:10.000Z")]
    inv = build(act_root_rows("09:29:00.000"), self_=None, talk=listen)
    assert [t["pid"] for t in inv["act_roots"]] == [2400]           # FOR: the shell started first, its child
    inv = build(act_root_rows("10:00:00.000"), self_=None, talk=listen)   # the shell's pid taken again after
    assert inv["act_roots"] == [] and [h.rsplit(": ", 1)[1] for h in link_holes(inv)] == [
        "pid 2400 under parent pid 5100"]
