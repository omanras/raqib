"""M7.24 REDO (ADR-0007 Amendments BB and BC): a mark, not an omission.
BC-1: an os follow writes every event of its tree as it does with no root told, in the same order; each line of an
event of a process at or under the root of another tree it is told carries input_meta.under_root (that root's pid);
the root's own event 1 does not. BC-2: told and matched by ProcessGuid only (a pid-only entry is no root; an event
with no ProcessGuid is not marked; a process that once had the root's pid is not under it); the follow's own parents
by ProcessGuid say "under" (one map); the watch tells a root only while the other tree's os follow lives, read when
the follow asks. BC-3: a marked line gives its tree no beat. BC-4: no key on a session_start, no block without an
event; a marked line is in capture's shape. BC-5: said in HOST-RHYTHM's holes and THREAT_MODEL.
Each test names the behaviour it holds and fails without it. SYNTHETIC: host `host`, user `user`, RFC 5737
addresses only. No test here reads the Table's review folder.
"""
import datetime
import inspect
import io
import json
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import discover, host, notify  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import fixturegen, trace  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import channel_xml, created, event, guid_of, talked  # noqa: E402
from test_host_follow_returns import START, FollowChannel, at  # noqa: E402
from test_event_logged_time import FIXTURES_BUILT, every_fixture_build  # noqa: E402
from test_one_destination import CATALOG, RULES  # noqa: E402

WORKER = "C:\\actions-runner\\bin\\Runner.Worker.exe"
AGENT = "C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\kimi.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
CURL = "C:\\Windows\\System32\\curl.exe"
W, A, C1, C2, X, D, E = 4000, 4100, 4200, 4210, 4300, 4400, 4500
G = {p: guid_of(p) for p in (W, A, C1, C2, X, D, E)}
NESTED = (A, G[A])


def no_guid(rec, utc, pid, image):
    """A Sysmon event 3 of pid whose ProcessGuid is empty (an event the tree places by its pid alone)."""
    return event(3, rec, utc, pid, image, "", Protocol="tcp", Initiated="true", SourceIp="192.0.2.10",
                 SourcePort="50999", DestinationIp="203.0.113.41", DestinationHostname="-", DestinationPort="443")


PASSES = [
    [talked(10, at("07:54:00"), W, WORKER, G[W]),                                    # the worker talks
     created(11, at("07:54:01"), A, AGENT, G[A], W, WORKER, G[W], "kimi"),           # it starts the agent
     created(12, at("07:54:02"), C1, CMD, G[C1], A, AGENT, G[A], "cmd /c one"),      # the agent's child
     talked(13, at("07:54:03"), A, AGENT, G[A], port=50213)],                        # the agent's own talk
    [created(20, at("07:54:10"), C2, CMD, G[C2], A, AGENT, G[A], "cmd /c two"),
     talked(21, at("07:54:11"), A, AGENT, G[A], port=50210),
     talked(22, at("07:54:12"), E, CMD, G[E], port=50220),                           # no event 1: in no file
     created(23, at("07:54:13"), X, CMD, G[X], W, WORKER, G[W], "cmd /c worker"),    # the worker's own child
     talked(24, at("07:54:14"), C1, CMD, G[C1], port=50224),
     no_guid(25, at("07:54:15"), C1, CMD)],                                          # under the agent, no guid
    [created(30, at("07:54:20"), D, CURL, G[D], C1, CMD, G[C1], "curl -s https://198.51.100.20/x"),
     talked(31, at("07:54:21"), C2, CMD, G[C2], port=50230),
     talked(32, at("07:54:22"), X, CMD, G[X], port=50232)],
]
# the records (EventRecordID) of the events at or under the agent's root, but for its own event 1 and the one with
# no ProcessGuid: what a follow told the agent's root marks
UNDER_A = {12, 13, 20, 21, 24, 30, 31}


def follow(tmp_path, told=None, passes=PASSES, name="w.jsonl", tree=None, cwd=None):
    """The real os_sysmon.follow of the worker's tree over the stand-in channel, one pass per element of passes;
    told(k) the roots mark_under returns at pass k (None: no callable at all). (the file's records, the calls)."""
    log, stop, calls = tmp_path / name, threading.Event(), []

    def on_pass(n, top):
        if n >= len(passes):
            stop.set()

    def mark_under():
        calls.append(len(calls) + 1)
        return told(len(calls))
    kw = {} if told is None else {"mark_under": mark_under}
    if tree is not None:
        kw["tree"] = tree
    os_sysmon.follow("%d:%s" % (W, G[W]), str(log), stop, every=0.0, nt=True, since=START, on_pass=on_pass,
                     reader=FollowChannel(passes), out=open(tmp_path / "out.txt", "w"),
                     err=open(tmp_path / "err.txt", "w"), cwd=cwd, **kw)
    return [json.loads(x) for x in log.read_text().splitlines()], calls


def bare(recs):
    """The records with input_meta.under_root taken out (nothing else changed)."""
    out = []
    for r in recs:
        r = json.loads(json.dumps(r))
        if isinstance(r.get("input_meta"), dict):
            r["input_meta"].pop("under_root", None)
        out.append(r)
    return out


def marked(recs):
    """{(phase, EventRecordID or ts): under_root} of the marked lines."""
    return {(r["phase"], r["input_meta"].get("time_record") or rec_of(r)): r["input_meta"]["under_root"]
            for r in recs if isinstance(r.get("input_meta"), dict) and "under_root" in r["input_meta"]}


RECORD_AT = {}   # ts -> EventRecordID of PASSES (each event has its own second)
for _pass in PASSES:
    for _x in _pass:
        RECORD_AT[_x.split("UtcTime'>")[1][:19].replace(" ", "T")] = int(_x.split("<EventRecordID>")[1].split("<")[0])


def rec_of(r):
    return RECORD_AT.get(r["ts"][:19])


def records_marked(recs, phase="pre"):
    return sorted(rec_of(r) for r in recs if r["phase"] == phase and "under_root" in r.get("input_meta", {}))


def told_at(*ks, roots=(NESTED,)):
    return lambda k: list(roots) if k in ks else []


# --- E1 (BC-1): the same lines, in the same order, but for the mark ------------------------------------------------

def test_e1_bc1_a_told_root_marks_its_subtree_and_the_follow_writes_every_line_it_writes_untold(tmp_path):
    main, _ = follow(tmp_path, None, name="main.jsonl")
    recs, calls = follow(tmp_path, told_at(1, 2, 3))
    assert calls == [1, 2, 3]   # asked at every pass
    assert bare(recs) == main and len(recs) == len(main)   # no line left out, none added, the same order
    assert records_marked(recs) == records_marked(recs, "post") == sorted(UNDER_A)   # its pre and its post
    assert set(marked(recs).values()) == {A}   # the root's pid
    assert not [r for r in recs if r["phase"] not in ("pre", "post") and set(r) != set(main[0])]   # no new key
    # the root's own event 1 (its parent started it) and the worker's own events are not marked
    unmarked = {rec_of(r) for r in recs if r["phase"] == "pre" and "under_root" not in r["input_meta"]}
    assert unmarked == {10, 11, 23, 25, 32}
    # with a root told the lines that are not under it are byte for byte main's
    keep = [json.dumps(r, separators=(",", ":")) for r in recs if "under_root" not in r.get("input_meta", {})]
    assert set(keep) <= set((tmp_path / "main.jsonl").read_text().splitlines())


def test_bd2_a_told_root_that_is_no_member_of_the_follows_tree_marks_nothing(tmp_path):
    """ADR-0007 BD-2: the watch tells every other tree's root; what is under this follow's root is the follow's own
    reading. A root the channel never showed under it, and a root above it, mark nothing: the bytes are main's."""
    main, _ = follow(tmp_path, None, name="main.jsonl")
    stranger = (64999, "{11111111-2222-3333-4444-555555555555}")
    recs, calls = follow(tmp_path, told_at(1, 2, 3, roots=(stranger,)), name="stranger.jsonl")
    assert calls == [1, 2, 3] and not marked(recs)
    assert (tmp_path / "main.jsonl").read_bytes() == (tmp_path / "stranger.jsonl").read_bytes()
    both, _ = follow(tmp_path, told_at(1, 2, 3, roots=(stranger, NESTED)), name="both.jsonl")
    assert records_marked(both) == sorted(UNDER_A) and set(marked(both).values()) == {A}


def test_bd3_the_fixtures_process_sample_holds_what_the_real_sample_holds():
    """ADR-0007 BD-3: discover's sample of a round is {pid, image, started} for each process. The first build asked
    the sample for a parent, which only the fixture gave, and told nothing on a real host."""
    real = discover._last_sample([{"kind": "proc", "src": "win-process-1", "line": 2, "pid": 7, "image": "x",
                                   "started": None}], {})
    assert real and set(real[0]) == {"pid", "image", "started"}
    for k in (1, 3):
        for p in fixturegen.held_inventory(k, sub=True, side=True)["processes"]:
            assert set(p) - {"cites"} == set(real[0]), p   # cites: the fixture's own


def test_e1_bc1_with_no_root_told_the_bytes_are_mains(tmp_path, monkeypatch):
    main, _ = follow(tmp_path, None, name="main.jsonl")
    empty, calls = follow(tmp_path, lambda k: [], name="empty.jsonl")
    assert (tmp_path / "main.jsonl").read_bytes() == (tmp_path / "empty.jsonl").read_bytes() and calls == [1, 2, 3]
    # every Sysmon fixture under tests/fixtures, built with an empty mark_under: what main's build gives, to the byte
    real = os_sysmon.build
    monkeypatch.setattr(os_sysmon, "build", lambda *a, **kw: real(*a, mark_under=[], **kw))
    assert every_fixture_build() == FIXTURES_BUILT


def test_e1_bc1_every_fixture_with_every_other_process_told_is_mains_but_for_the_marks(monkeypatch):
    """No event is left out in any case and no block is added: each fixture's build for each pid, with every other
    (pid, ProcessGuid) of the fixture told, is main's to the byte once the marks are taken out."""
    real, count = os_sysmon.build, []

    def told_all(text, pid, **kw):
        roots = sorted({(int(e["data"]["ProcessId"]), e["data"]["ProcessGuid"])
                        for e in os_sysmon.discover.sysmon_events(text, "sysmon", [], os_sysmon.READ)
                        if (e["data"].get("ProcessId") or "").strip().isdigit() and e["data"].get("ProcessGuid")})
        lines, silences = real(text, pid, mark_under=os_sysmon.roots_of(roots, pid, None), **kw)
        out = []
        for line in lines:
            rec = json.loads(line)
            if "under_root" in rec.get("input_meta", {}):
                count.append(rec["input_meta"]["under_root"])
                del rec["input_meta"]["under_root"]
            out.append(json.dumps(rec, separators=(",", ":"), ensure_ascii=True))
        return out, silences
    monkeypatch.setattr(os_sysmon, "build", told_all)
    assert every_fixture_build() == FIXTURES_BUILT
    assert len(count) > 50   # the fixtures' nested processes were marked (this is no empty comparison)


def test_e1_the_arguments_name_says_what_it_does():
    for fn in (os_sysmon.build, os_sysmon.follow):
        params = inspect.signature(fn).parameters
        assert "mark_under" in params and not {"leave_out", "out_said"} & set(params)
    assert "notes" not in inspect.signature(os_sysmon._lines).parameters


# --- E2 (BC-2): by ProcessGuid only -------------------------------------------------------------------------------

def test_e2_bc2_a_pid_only_entry_is_no_root_and_the_follows_own_root_is_never_one(tmp_path):
    main, _ = follow(tmp_path, None, name="main.jsonl")
    for k, roots in enumerate([[A], [(A, None)], [(A, "")], [(A, " ")], ["x"], [(W, G[W])], [(-1, G[A])],
                               [(True, G[A])], [(str(A), G[A])], [(A, G[A], 1)]]):
        follow(tmp_path, lambda n: roots, name="p%d.jsonl" % k)
        assert (tmp_path / ("p%d.jsonl" % k)).read_bytes() == (tmp_path / "main.jsonl").read_bytes(), roots
    assert os_sysmon.roots_of([A, (A, None), (A, G[A]), (A + 1, G[A].upper()), (W, G[W])], W, G[W]) == [(A, G[A])]


def test_e2_bc2_an_event_with_no_processguid_is_not_marked(tmp_path):
    recs, _ = follow(tmp_path, told_at(1, 2, 3))
    by = {rec_of(r): r for r in recs if r["phase"] == "pre"}
    assert by[25]["tool"] == "net" and "under_root" not in by[25]["input_meta"]   # C1's, placed by its pid: written
    assert by[24]["input_meta"]["under_root"] == A   # C1's event just before, with its ProcessGuid: marked


def test_e2_bc2_a_process_that_once_had_the_roots_pid_and_its_children_are_not_marked(tmp_path):
    """The packet's F1 case: P (pid 4100) left a long-lived child Q and ended; pid 4100 is then the agent's."""
    P, Q, C = (A, guid_of(0x4100F)), (4600, guid_of(4600)), (4700, guid_of(4700))
    passes = [
        [created(10, at("07:54:00"), P[0], CMD, P[1], W, WORKER, G[W], "cmd /c p"),
         created(11, at("07:54:01"), Q[0], CMD, Q[1], P[0], CMD, P[1], "cmd /c q"),
         talked(12, at("07:54:02"), P[0], CMD, P[1], port=50112)],
        [created(20, at("07:54:10"), A, AGENT, G[A], W, WORKER, G[W], "kimi"),        # the pid is now the agent's
         created(21, at("07:54:11"), C[0], CMD, C[1], A, AGENT, G[A], "cmd /c c"),
         talked(22, at("07:54:12"), Q[0], CMD, Q[1], port=50122),                    # P's child, still alive
         created(23, at("07:54:13"), 4800, CMD, guid_of(4800), Q[0], CMD, Q[1], "cmd /c qq"),
         talked(24, at("07:54:14"), A, AGENT, G[A], port=50124)]]
    for _pass in passes:
        for _x in _pass:
            RECORD_AT[_x.split("UtcTime'>")[1][:19].replace(" ", "T")] = int(
                _x.split("<EventRecordID>")[1].split("<")[0])
    recs, _ = follow(tmp_path, told_at(1, 2), passes=passes)
    main, _ = follow(tmp_path, None, passes=passes, name="main.jsonl")
    assert bare(recs) == main and len([r for r in main if r["phase"] == "pre"]) == 8
    assert records_marked(recs) == [21, 24]   # the agent's child and its own talk; not P, not Q, not Q's child
    assert set(marked(recs).values()) == {A}


def test_e2_bc2_one_parents_map_keyed_by_processguid(tmp_path):
    tree = {}
    follow(tmp_path, told_at(1, 2, 3), tree=tree)
    key = os_sysmon._gkey
    assert tree["parents"] == {key(G[A]): key(G[W]), key(G[C1]): key(G[A]), key(G[C2]): key(G[A]),
                               key(G[X]): key(G[W]), key(G[D]): key(G[C1])}
    assert not {"parent_of", "pid_of", "ident_of_pid"} & set(tree)   # the pid maps are gone
    plain = {}
    follow(tmp_path, None, tree=plain, name="plain.jsonl")
    assert "parents" not in plain   # a follow that is never asked keeps no map
    for name in ("pid_of", "ident_of_pid", "_ident"):
        assert not hasattr(os_sysmon, name)


# --- E4 (BC-2, BC-5): a process born under the root before it was told; a root no longer told ----------------------

@pytest.mark.parametrize("ks,under", [
    ((2, 3), {20, 21, 24, 30, 31}),   # told from pass 2: C1 (born in pass 1, unmarked then) is marked from then on
    ((1, 2), {12, 13, 20, 21, 24}),   # told to pass 2: pass 3's events (D under C1, C2's talk) are unmarked
    ((2,), {20, 21, 24}),             # both changes
])
def test_e4_the_marks_follow_the_telling_and_nothing_is_written_twice_or_lost(tmp_path, ks, under):
    main, _ = follow(tmp_path, None, name="main.jsonl")
    recs, _ = follow(tmp_path, told_at(*ks))
    assert bare(recs) == main   # the same lines as with no root told, but for the mark
    assert records_marked(recs) == records_marked(recs, "post") == sorted(under)
    by = {rec_of(r): r["input_meta"] for r in recs if r["phase"] == "pre"}
    assert by[30]["depth"] == 3 and 25 in by and 24 in by   # C1's later events and D are the tree's, D at its depth


# --- E6 (BC-4): capture's shape; the feed reads a marked line as it reads the line unmarked -------------------------

def test_e6_bc4_a_marked_line_is_in_captures_shape_and_the_feed_reads_it_with_nothing_of_its_own(tmp_path):
    recs, _ = follow(tmp_path, told_at(1, 2, 3), cwd="C:\\Users\\user")
    marks = [r for r in recs if "under_root" in r.get("input_meta", {})]
    assert len(marks) == 2 * len(UNDER_A)
    assert [trace.strict_problem(r) for r in recs] == [None] * len(recs)
    plain = tmp_path / "plain.jsonl"   # the same lines without the mark
    plain.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in bare(recs)))
    judged = []
    for path in (tmp_path / "w.jsonl", plain):
        feed = host.Feed(str(path), host.source_rules(RULES))
        holes, changed = feed.poll()
        found, notes, _ = feed.judge()
        judged.append((holes, feed.problems, sorted((f["rule_id"], json.dumps(f, sort_keys=True)) for f in found),
                       [n for n in notes if "could not judge" in str(n.get("detail", ""))]))
    # the same findings and the same "could not judge" notes (CROSS-SOURCE's, of a file read alone) as the lines
    # unmarked: the mark adds none; no hole, no problem
    assert judged[0] == judged[1] and judged[0][:2] == ([], [])
    assert "NET-TOOL" in [r for r, _ in judged[0][2]]   # D's curl (the one curl), a marked line: still judged
    assert not [f for f in judged[0][2] if f[0].startswith("SILENCE")]


# --- the watch's side, through rounds: E2, E3 (BC-2), E5 (BC-3) -------------------------------------------------------

ANC, AG, N, NET = fixturegen.HELD_ANCESTOR_PID, fixturegen.HELD_PID, 6, 4
BASH = "C:\\Program Files\\Git\\usr\\bin\\bash.exe"


def t_at(seconds):
    return datetime.datetime.fromtimestamp(fixturegen.WALL0 + seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]


def channel(k):
    """The Sysmon channel up to round k (SYNTHETIC, held_inventory's case): the agent started by the ancestor before
    the watch; from round 2 the ancestor talks to its server and the agent starts a command that talks to its model
    (pid 5200 + m; in round NET it is curl), all in round m's interval; the agent talks to its model too."""
    out = [created(1, t_at(-3600), AG, AGENT, guid_of(AG), ANC, WORKER, guid_of(ANC), "agent")]
    for m in range(2, k + 1):
        T, c = (m - 1) * fixturegen.EVERY, AG + m
        image, cmd = (CURL, "curl -s https://198.51.100.20/x") if m == NET else (BASH, "bash -c step")
        out += [talked(10 * m, t_at(T - 7), AG, AGENT, guid_of(AG), port=52000 + m, dest="203.0.113.30"),
                talked(10 * m + 1, t_at(T - 6), ANC, WORKER, guid_of(ANC), port=50000 + m, dest="203.0.113.20"),
                created(10 * m + 2, t_at(T - 5), c, image, guid_of(c), AG, AGENT, guid_of(AG), cmd),
                talked(10 * m + 3, t_at(T - 4), c, image, guid_of(c), port=51000 + m, dest="203.0.113.30")]
    return out


class Built:
    """A stand-in os follow for each tree: at each pass the test lets go, it writes what os_sysmon.follow's pass
    writes (os_sysmon.build of the channel so far for its root, its tree carried, after the highest record read,
    marking under the roots its mark_under() returns at that pass: roots_of). end(pid, how) ends a follow in its
    own thread: "raise" (an error), "return" (it returns)."""

    def __init__(self):
        self.follows = {}

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None,
                 helpers=None, since=None, tree=None, mark_under=None):
        pid, _, guid = str(root).partition(":")
        f = self.follows[int(pid)] = {"log": log, "mark_under": mark_under, "tree": {}, "top": None, "told": [],
                                      "asked": [], "stop": stop, "guid": guid or None, "end": threading.Event(),
                                      "how": None}
        if on_pass:
            on_pass(1, None)
        while not (stop.is_set() or f["end"].is_set()):
            f["end"].wait(0.01)
        if f["how"] == "raise":
            raise RuntimeError("test: the follow failed")
        return 1

    def end(self, watch, pid, how):
        f = self.follows[pid]
        f["how"] = how
        f["end"].set()
        (key,) = [k for k in watch.trees if k[0] == pid]
        watch.sources[key].thread.join(5)
        assert not watch.sources[key].thread.is_alive()

    def passes(self, k):
        text = channel_xml(*channel(k))
        for pid, f in sorted(self.follows.items()):
            if f["stop"].is_set() or f["end"].is_set():
                continue
            asked = None if f["mark_under"] is None else list(f["mark_under"]())
            roots = None if asked is None else os_sysmon.roots_of(asked, pid, f["guid"])
            f["asked"].append((k, asked))   # what the watch told, before the follow's own reading (roots_of)
            f["told"].append((k, roots))
            info = {}
            lines, _ = os_sysmon.build(text, pid, guid=f["guid"], after_record=f["top"], info=info, tree=f["tree"],
                                       start_seq=os_sysmon.last_seq(f["log"], os_sysmon.session_id(pid)),
                                       server_hash=True, mark_under=roots)
            if info.get("last_record") is not None:
                f["top"] = max(f["top"] or 0, info["last_record"])
            if lines:
                os_sysmon.append(f["log"], lines)


def with_guid(inv, guid=True):
    """held_inventory's round with the agent's ProcessGuid on its candidate (the watch then holds it: told)."""
    for c in inv["candidates"]:
        if c["pid"] == AG and guid:
            c["guid"] = guid_of(AG)
    return inv


def field_run(home, invs, at_round=None):
    """The HostWatch fed invs (an Exception: that round's reader fails) with a Built follow for each tree; before
    each round k >= 2 the follows make their pass k (at_round[k](watch, follow) first, where given)."""
    follow, feed, clock = Built(), iter(invs), host.FixtureClock()

    def reader():
        inv = next(feed)
        if isinstance(inv, Exception):
            raise inv
        return inv
    notifier = notify.Notifier(host.HOST, enabled=False, reason="test", host=True)
    watch = host.HostWatch(reader, CATALOG, RULES, notifier, every=fixturegen.EVERY, out=None, err=io.StringIO(),
                           clock=clock, wall=lambda: fixturegen.WALL0 + clock.t, home=str(home), platform="fixture",
                           run="test-run", sysmon=lambda: (True, "test: a synthetic os source"), os_follow=follow)
    try:
        for n in range(1, len(invs) + 1):
            if n >= 2:
                if at_round and n in at_round:
                    at_round[n](watch, follow)
                follow.passes(n)
            watch.tick(wait=30)
            clock.t += watch.every
    finally:
        watch.finish()
    return watch, follow


def key_of(watch, pid):
    (key,) = [k for k in watch.trees if k[0] == pid]
    return key


def told_of(follow, pid=ANC, what="told"):
    return {k: roots for k, roots in follow.follows[pid][what]}


TOLD = [(AG, guid_of(AG))]


def test_e2_bc2_through_rounds_a_root_is_told_with_its_processguid_and_never_without_one(tmp_path):
    invs = [fixturegen.held_inventory(k, talks_from=99) for k in range(1, 5)]
    watch, follow = field_run(tmp_path / "g", [with_guid(i) for i in json.loads(json.dumps(invs))])
    assert watch.sources[key_of(watch, ANC)].kind == "os" and watch.sources[key_of(watch, AG)].kind == "os"
    assert told_of(follow) == told_of(follow, what="asked") == {k: TOLD for k in range(2, 5)}   # at every pass
    assert told_of(follow, AG) == {k: [] for k in range(2, 5)}   # the watch holds no ProcessGuid of the ancestor
    watch, follow = field_run(tmp_path / "n", invs)   # the watch does not hold the agent's ProcessGuid
    assert not watch.trees[key_of(watch, AG)].get("guid")
    assert told_of(follow, what="asked") == {k: [] for k in range(2, 5)}   # not told (F1): the watch tells nothing


@pytest.mark.parametrize("how", ["raise", "return", "stop"])
def test_e3_bc2_a_follow_that_ended_is_not_told_at_the_asking_that_follows_its_root_still_sampled(tmp_path, how):
    def end(watch, follow):
        if how == "stop":
            watch.sources[key_of(watch, AG)].stop.set()   # stopped (its thread may still be in a pass)
        else:
            follow.end(watch, AG, how)
        before[0] = [r for r in watch.os_nested if r[0] == key_of(watch, AG)]
    before = [None]
    invs = [with_guid(fixturegen.held_inventory(k, talks_from=99)) for k in range(1, 6)]
    watch, follow = field_run(tmp_path, invs, at_round={4: end})
    assert before[0] and before[0][0][1:] == TOLD[0]   # the round's snapshot still holds it: its root is sampled
    told = told_of(follow, what="asked")
    assert told[2] == told[3] == TOLD and told[4] == []   # read at the asking: no longer told
    # the next round attaches the tree again where it can (a follow that returned or was stopped: a new follow,
    # alive, so its root is told again); one that raised has a host source from then on, and is not
    assert told[5] == ([] if how == "raise" else TOLD)
    assert (watch.sources[key_of(watch, AG)].kind == "os") is (how != "raise")


def test_e3_bc2_a_round_that_failed_does_not_keep_a_dead_follow_told(tmp_path):
    def end(watch, follow):
        snap[0] = watch.os_nested   # no round was applied since round 2: the snapshot is round 2's
        follow.end(watch, AG, "raise")
    snap = [None]
    invs = [with_guid(fixturegen.held_inventory(k, talks_from=99)) for k in range(1, 3)] + [
        RuntimeError("test: the reader failed"), RuntimeError("test: the reader failed")] + [
        with_guid(fixturegen.held_inventory(k, talks_from=99)) for k in range(5, 7)]
    watch, follow = field_run(tmp_path, invs, at_round={4: end})
    assert sum(1 for h in watch.holes if h.get("kind") == "reader-failed") == 2
    assert [r[1:] for r in snap[0] if r[0] == key_of(watch, AG)] == [TOLD[0]]   # the stale snapshot still names it
    asked = told_of(follow, what="asked")
    assert asked[2] == asked[3] == TOLD   # alive through the failed round 3: still told
    assert asked[4] == asked[5] == []   # dead after the failed rounds, no round applied: not told at the asking


def shape(watch, pid):
    """What tree pid's ring and findings read of its own os file, and which of its lines are marked."""
    key = key_of(watch, pid)
    path = watch.sources[key].path
    recs = [json.loads(x) for x in Path(path).read_text().splitlines()]
    base, at_line = Path(path).name, dict(enumerate([None] + recs))
    ring = watch.rings.get(key, [])
    act_lines = [c["line"] for e in ring for a in e["acts"] for c in a.get("cites", []) if c.get("src") == base]
    talk_lines = [c["line"] for e in ring for cites in e["talks"].values() for c in cites if c.get("src") == base]
    return {"recs": recs,
            "marked": [ln for ln, r in at_line.items() if r and "under_root" in r.get("input_meta", {})],
            "acts": act_lines, "talks": talk_lines,
            "dests": sorted({d for e in ring for d in e["talks"] if str(d).startswith("os:")}),
            "rhythm": [f for f in watch.findings if f.get("rule_id") == "HOST-RHYTHM" and f.get("pid") == pid]}


def dest(ip):
    return "os:%s" % os_sysmon.dest_sha256(ip, 443, "tcp")[:12]


def test_e5_bc3_through_rounds_marked_lines_give_the_ancestor_no_beat_and_the_nested_tree_its_own(tmp_path):
    runs = {}
    for told in (True, False):   # False: the watch holds no ProcessGuid of the agent: no root told (main's result)
        invs = [with_guid(fixturegen.held_inventory(k), told) for k in range(1, N + 1)]
        watch, follow = field_run(tmp_path / str(told), invs)
        runs[told] = (watch, follow, shape(watch, ANC), shape(watch, AG))
    (watch, follow, anc, ag), (watch0, follow0, anc0, ag0) = runs[True], runs[False]
    assert told_of(follow) == {k: TOLD for k in range(2, N + 1)}
    assert told_of(follow0, what="asked") == {k: [] for k in range(2, N + 1)}
    # the ancestor's file holds the same lines in both, the agent's subtree marked when told (BC-1)
    assert bare(anc["recs"]) == anc0["recs"] and anc0["marked"] == []
    assert len(anc["marked"]) == 2 * 3 * (N - 1)   # each round: the agent's talk, its command, the command's talk
    # BC-3: the ancestor's ring gains no act, no talk and no destination from a marked line, and makes no rhythm
    assert anc["acts"] == [] and not set(anc["talks"]) & set(anc["marked"]) and anc["talks"]
    assert anc["dests"] == [dest("203.0.113.20")]   # its own server only
    assert anc["rhythm"] == []
    # with no root told the ancestor counts its child's commands, as on main: AX-4's false HOST-RHYTHM at high
    assert anc0["acts"] and dest("203.0.113.30") in anc0["dests"]
    assert anc0["rhythm"] and anc0["rhythm"][0]["severity"] == "high"
    # the nested tree makes its own, from its own (unmarked) file, in both
    for a in (ag, ag0):
        assert a["marked"] == [] and a["acts"] and a["rhythm"]
    # a NET-TOOL command among the marked lines is still found, once, as on main (the twin "judged on another tree")
    for w in (watch, watch0):
        nets = [f for f in w.source_findings if f.get("rule_id") == "NET-TOOL"]
        assert len(nets) == 2 and len([f for f in nets if f.get("judged_on") is None]) == 1, nets
    standing = [(f.get("tree"), f.get("judged_on")) for w in (watch, watch0) for f in w.source_findings
                if f.get("rule_id") == "NET-TOOL"]
    assert standing[:2] == standing[2:]   # the same copy stands as on main


# --- E7 (BC-5): said, and no more --------------------------------------------------------------------------------

def test_e7_bc5_the_rules_holes_and_the_threat_model_say_the_mark_and_its_cost():
    rhythm = next(r for r in RULES if r.id == "HOST-RHYTHM")
    said = [h for h in rhythm.holes if "under_root" in h]
    assert len(said) == 1 and "BC-5" in said[0]
    for words in ("no beat to either tree", "no ProcessGuid", "born under the root before"):
        assert words in said[0], words
    assert "under_root" in rhythm.doc["description"]
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "under_root" in text and "no beat to either tree" in " ".join(text.split())
    for gone in ("leaves out the events under the root", "says once from which record", "left_out"):
        assert gone not in " ".join(h for h in rhythm.holes) and gone not in rhythm.doc["description"]
        assert gone not in " ".join(text.split())
