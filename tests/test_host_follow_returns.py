"""M7.14 (ADR-0007 Amendment AI): a tree's follow that returns, as the person meets it.
On a machine whose Sysmon channel holds weeks, every pass of a tree's os follow
asked wevtutil for the whole channel and was ended at its 10 s: the tree was
judged by nothing. AI-1: a follow's pass under raqib watch --host asks a bounded
question, as a round's read does (the first pass the events since the watch's
start, each later pass the records after the highest read, the round's cap; a
cut is a hole); `raqib os-sysmon` run by a person reads what it read. REDO
(Amendment AJ): AI-2's counting of passes is withdrawn; a tree whose source is
os has the host's own record from its attach (AJ-1), a finding is the source of
the line it cites (AJ-3), one act told twice is one entry of the listing (AJ-2),
and the follow keeps its tree, its GUIDs and the round's restarts (AJ-4). REDO 2 (Amendment AK): the host's
record of an os tree is the host source's own road (its own file and feed, the host's rules, its history rule), and
the property is tested as written: with Sysmon and without, the same host-line findings, knocks and words. AI-3: the
guide and THREAT_MODEL say the proxy has what an agent without hooks reads with
its own code. The stand-in wevtutil here is a Python class (never a process)
that honours the query and records its arguments. SYNTHETIC: host `host`, user
`user`, RFC 5737 addresses only. No test here reads a file under docs/review.
"""
import datetime
import io
import json
import re
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import discover, host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import G_KIMI, G_SHELL, EXPLORER, WALL0, channel_xml, created, guid_of, talked  # noqa: E402
from test_host_third_field_run import (CURL, KIMI, KIMI_WORD, TIMED_OUT, Channel, FakeWevtutil, judged,  # noqa: E402
                                       kimi_then_curl, report, sample, section, watch)

START = datetime.datetime(2026, 11, 10, 7, 53, 30, tzinfo=datetime.timezone.utc)   # WALL0 + 240: the watch's start
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
FIRST = ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
         " TimeCreated[@SystemTime>='2026-11-10T07:53:30.000Z']]]", "/c:2000", "/f:xml")
AFTER_603 = ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and EventRecordID>603]]", "/c:2000",
             "/f:xml")
AFTER_605 = ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and EventRecordID>605]]", "/c:2000",
             "/f:xml")
WHOLE = ("qe", CHANNEL, "/f:xml")
CMD = "C:\\Windows\\System32\\cmd.exe"
G_CURL, G_CURL2, G_CMD = guid_of(9300), guid_of(9310), guid_of(9400)
UTC = datetime.timezone.utc


def at(clock):
    return "2026-11-10 %s.000" % clock


KIMI_BORN = created(100, at("07:51:00"), 9176, KIMI, G_KIMI, 5888, EXPLORER, G_SHELL, "kimi")   # before the watch
CURL_BORN = created(602, at("07:54:20"), 9300, CURL, G_CURL, 9176, KIMI, G_KIMI, "curl -s https://198.51.100.20/x")
CURL_TALK = talked(603, at("07:54:21"), 9300, CURL, G_CURL, port=50310, dest="198.51.100.20")
CURL2_BORN = created(604, at("07:56:20"), 9310, CURL, G_CURL2, 9176, KIMI, G_KIMI, "curl -s https://198.51.100.21/y")
CURL2_TALK = talked(605, at("07:56:21"), 9310, CURL, G_CURL2, port=50320, dest="198.51.100.21")
CURL3_BORN = created(606, at("07:58:20"), 9320, CURL, guid_of(9320), 9176, KIMI, G_KIMI, "curl -s https://192.0.2.30/z")
CURL3_TALK = talked(607, at("07:58:21"), 9320, CURL, guid_of(9320), port=50340, dest="192.0.2.30")
AFTER_607 = ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and EventRecordID>607]]", "/c:2000",
             "/f:xml")


class FollowChannel:
    """A stand-in wevtutil for a follow's passes (reader(args, timeout)): the channel's records grow pass by pass
    (passes[k - 1] appended before the k-th call); it HONOURS the query as wevtutil does (the event ids asked,
    EventRecordID>N or TimeCreated at or after the start, oldest first, /c:cap) and records every argument list. A
    call in `fail` does not return in time (the follow's own words)."""

    def __init__(self, passes, fail=()):
        self.passes = [list(p) for p in passes]
        self.fail = set(fail)
        self.args = []
        self.log = []

    def __call__(self, args, timeout):
        self.args.append(tuple(args))
        n = len(self.args)
        if n <= len(self.passes) and self.passes[n - 1]:
            self.log += os_sysmon._chunks(channel_xml(*self.passes[n - 1]))[1]
        if n in self.fail:
            return None, TIMED_OUT
        if len(args) == 3:   # the whole channel, as a person's os-sysmon asks it
            return channel_xml(*[c for c, _, _ in self.log]), None
        query, cap = args[2][3:], int(args[3][3:])
        ids = {int(i) for i in re.findall(r"EventID=([0-9]+)", query)}
        rid = re.search(r"EventRecordID>([0-9]+)", query)
        since = re.search(r"SystemTime>='([^']+)'", query)
        keep = [c for c, r, t in self.log if int(re.search(r"<EventID>([0-9]+)<", c).group(1)) in ids and (
            (rid and r > int(rid.group(1))) or (since and t >= discover._ts(since.group(1))))]
        return channel_xml(*keep[:cap]), None


def follow_through(channel, passes, **kw):
    """The real os_sysmon.follow of kimi's tree (pid 9176) over the stand-in, `passes` passes, no wait between them:
    (the trace's lines, the RAQIB-SILENCE lines, [(pass, top)], [(pass, read, why)])."""
    log, root = kw.pop("log"), kw.pop("root", "9176")
    stop, tops, reads = threading.Event(), [], []

    def on_pass(n, top):
        tops.append((n, top))
        if n >= passes:
            stop.set()
    os_sysmon.follow(root, str(log), stop, every=0.0, out=io.StringIO(), err=io.StringIO(), nt=True,
                     on_pass=on_pass, on_read=lambda n, read, why: reads.append((n, read, why)), reader=channel, **kw)
    text = log.read_text(encoding="ascii").splitlines() if log.exists() else []
    return ([json.loads(x) for x in text if x.startswith("{")], [x for x in text if os_sysmon.MARKER in x], tops,
            reads)


def acts(lines):
    return [(x["ts"], x["tool"]) for x in lines if x["phase"] == "pre"]


# --- E1 (AI-1): a follow's pass asks a bounded question --------------------------------------------------------------

def test_e1_ai1_three_passes_ask_since_the_start_then_after_the_highest_read_and_read_every_event_once(tmp_path):
    other = talked(601, at("07:54:00"), 5888, EXPLORER, G_SHELL, port=50300)   # not the tree: read, never a line
    cmd = created(606, at("07:56:30"), 9400, CMD, G_CMD, 9176, KIMI, G_KIMI, "cmd /c dir")
    cmd_talk = talked(607, at("07:57:00"), 9400, CMD, G_CMD, port=50330)       # its event 1 was the second pass's
    late_talk = talked(608, at("07:57:01"), 9300, CURL, G_CURL, port=50311)    # its event 1 was the first pass's
    channel = FollowChannel([[KIMI_BORN, other, CURL_BORN, CURL_TALK], [CURL2_BORN, CURL2_TALK, cmd],
                             [cmd_talk, late_talk]])
    lines, silent, tops, reads = follow_through(channel, 3, since=START, log=tmp_path / "os.jsonl")
    # the arguments, byte for byte: only the start and an integer record number go into the query
    assert channel.args == [FIRST, AFTER_603, ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                                               " EventRecordID>606]]", "/c:2000", "/f:xml")]
    assert tops == [(1, 603), (2, 606), (3, 608)]
    assert reads == [(1, True, None), (2, True, None), (3, True, None)]
    # every event of the tree once, none lost (the cmd's talk in pass 3, its event 1 in pass 2), none read twice;
    # the tree's past before the watch's start (kimi's event 1) is not read (AI-1, said)
    assert acts(lines) == [("2026-11-10T07:54:20.000Z", "process"), ("2026-11-10T07:54:21.000Z", "net"),
                           ("2026-11-10T07:56:20.000Z", "process"), ("2026-11-10T07:56:21.000Z", "net"),
                           ("2026-11-10T07:56:30.000Z", "process"), ("2026-11-10T07:57:00.000Z", "net"),
                           ("2026-11-10T07:57:01.000Z", "net")]
    assert silent == []   # a pass's window without an event 11 is not a silence of the configuration


def test_e1_ai1_a_cut_is_a_hole_the_next_pass_reads_on_and_a_pass_that_did_not_read_asks_again(tmp_path):
    channel = FollowChannel([[], [CURL_BORN, CURL_TALK, CURL2_BORN], []], fail={1})
    lines, silent, tops, reads = follow_through(channel, 4, since=START, cap=2, log=tmp_path / "os.jsonl")
    first = FIRST[:3] + ("/c:2", "/f:xml")
    assert channel.args == [first, first, ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                                           " EventRecordID>603]]", "/c:2", "/f:xml"),
                            ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                             " EventRecordID>604]]", "/c:2", "/f:xml")]
    assert reads == [(1, False, TIMED_OUT), (2, True, None), (3, True, None), (4, True, None)]
    assert tops == [(1, None), (2, 603), (3, 604), (4, 604)]
    assert silent == [os_sysmon.silence_line(9176, TIMED_OUT), os_sysmon.silence_line(
        9176, "the follow's pass read 2 events, the cap (/c:2): the records after record 603 are read by its next pass")]
    assert acts(lines) == [("2026-11-10T07:54:20.000Z", "process"), ("2026-11-10T07:54:21.000Z", "net"),
                           ("2026-11-10T07:56:20.000Z", "process")]


class Runner:
    """subprocess.run for a person's os-sysmon (read_live): records the argv, returns the whole channel."""

    def __init__(self, text):
        self.text, self.argv = text, []

    def __call__(self, argv, **kw):
        self.argv.append(list(argv))
        return type("Done", (), {"returncode": 0, "stdout": self.text.encode("ascii"), "stderr": b""})()


def test_e1_ai1_not_touched_raqib_os_sysmon_by_a_person_reads_the_whole_channel_or_its_file(tmp_path):
    text = channel_xml(KIMI_BORN, CURL_BORN, CURL_TALK)
    runner = Runner(text)
    out = io.StringIO()
    os_sysmon.run("9176", str(tmp_path / "live.jsonl"), out=out, err=io.StringIO(), nt=True,
                  live=lambda: os_sysmon.read_live(runner=runner))
    assert runner.argv == [["C:\\Windows\\System32\\wevtutil.exe", "qe", "Microsoft-Windows-Sysmon/Operational",
                            "/f:xml"]]
    live = (tmp_path / "live.jsonl").read_text(encoding="ascii")
    # the tree's past is read (kimi's own event 1, weeks or minutes before), as it was
    assert acts([json.loads(x) for x in live.splitlines() if x.startswith("{")]) == [
        ("2026-11-10T07:51:00.000Z", "process"), ("2026-11-10T07:54:20.000Z", "process"),
        ("2026-11-10T07:54:21.000Z", "net")]
    assert "from the live channel" in out.getvalue()
    export = tmp_path / "export.xml"
    export.write_text(text, encoding="ascii")
    os_sysmon.run("9176", str(tmp_path / "from.jsonl"), from_path=str(export), out=io.StringIO(), err=io.StringIO())
    assert (tmp_path / "from.jsonl").read_text(encoding="ascii") == live
    # a follow given no bound (no start, no record) asks the whole channel, as before
    channel = FollowChannel([[KIMI_BORN, CURL_BORN]])
    lines, _, _, _ = follow_through(channel, 1, log=tmp_path / "unbounded.jsonl")
    assert channel.args == [WHOLE] and len(acts(lines)) == 2


# --- E1 (AJ-1, AK-1): an os tree has the host's own record by the host source's road; E2 (AK-2); E3 (AK-3);
# --- E4 (AK-4); E5 (AK-5, AK-6); E7 (AK-8): the property, as written -------------------------------------------

class Follow:
    """A tree's os follow for raqib watch --host: the real os_sysmon.follow (bounded: the watch gives it its start),
    its wevtutil FollowChannel: its first `unread` passes do not return in time; the next waits until a round
    releases it (go) and reads `then`; later passes wait for the Stop. The host's on_pass is given the first passes
    with the `unread`-th, so the round after the attach meets them (deterministic, no clock)."""

    def __init__(self, unread=2, then=(), go=False):
        self.unread = unread
        self.go, self.done = threading.Event(), threading.Event()
        if go:
            self.go.set()
        self.channel = FollowChannel([[]] * unread + [list(then)], fail=set(range(1, unread + 1)))
        self.kw = []

    def __call__(self, root, log, stop, **kw):
        self.kw.append(sorted(kw))
        on_pass, unread, held = kw.pop("on_pass"), self.unread, []

        def passed(n, top):
            if n < unread:
                held.append((n, top))
                return
            for h in held:
                on_pass(*h)
            del held[:]
            on_pass(n, top)
            if n > unread:
                self.done.set()

        def reader(args, timeout):
            n = len(self.channel.args) + 1
            while n > unread and not stop.is_set() and not (n == unread + 1 and self.go.is_set()):
                stop.wait(0.01)
            return self.channel(args, timeout)
        kw["every"] = 0.0
        return os_sysmon.follow(root, log, stop, on_pass=passed, reader=reader, nt=True, **kw)


class Rounds(Channel):
    """The rounds' channel: every round read (an empty kept read, or `xml[n]` in round n); at round `release` the
    follow's waiting pass is let go first and the round waits for it."""

    def __init__(self, follow=None, release=None, xml=None):
        super().__init__(denied=set())
        self.follow, self.release, self.xml = follow, release, dict(xml or {})

    def __call__(self, timeout, helpers=None, popen=None, environ=None, args=()):
        if self.release is not None and len(self.args) + 1 == self.release:
            self.follow.go.set()
            assert self.follow.done.wait(5)
        got = super().__call__(timeout, helpers, popen, environ, args)
        return (channel_xml(*self.xml[len(self.args)]), None) if len(self.args) in self.xml else got


KIMI_T = (9176, 5888, KIMI, "kimi", "2026-11-10T07:51:00.000")
CURL_T = (9300, 9176, CURL, "curl -s https://198.51.100.20/x", "2026-11-10T07:54:20.000")
CURL2_T = (9310, 9176, CURL, "curl -s https://198.51.100.21/y", "2026-11-10T07:56:20.000")
CURL3_T = (9320, 9176, CURL, "curl -s https://192.0.2.30/z", "2026-11-10T07:58:20.000")
TALKS = [(50300, "203.0.113.50", 9176, "2026-11-10T07:51:01.000"), (50310, "198.51.100.20", 9300,
         "2026-11-10T07:54:21.000"), (50320, "198.51.100.21", 9310, "2026-11-10T07:56:21.000"),
         (50340, "192.0.2.30", 9320, "2026-11-10T07:58:21.000")]


def rounds(tmp_path, n=3):
    """kimi (round 1); its child curl talks (round 2: its tree is attached, os); a second child curl talks (round 3:
    the round after the follow's two passes); a third (round 4) (SYNTHETIC)."""
    return [sample(tmp_path, "r%d" % (i + 1), [KIMI_T, CURL_T, CURL2_T, CURL3_T][:i + 1], TALKS[:i + 1])
            for i in range(n)]


def at_start(tmp_path):
    """kimi and its curl both in round 1 (a tree there at the start with a child in round 1), then curl2, curl3."""
    return [sample(tmp_path, "s%d" % (i + 1), [KIMI_T, CURL_T, CURL2_T, CURL3_T][:i + 2], TALKS[:i + 2])
            for i in range(3)]


def host_file_lines(w):
    (src,) = w.sources.values()
    path = Path(src.host_path)
    return [json.loads(x) for x in path.read_text(encoding="ascii").splitlines() if x.startswith("{")] \
        if path.exists() else []


def source_line(w):
    lines = report(w)
    tree = next(i for i, x in enumerate(lines) if "pid 9176 kimi" in x)
    return lines[tree + 1]


class Script:
    """A tree's os follow for raqib watch --host: the real os_sysmon.follow over a FollowChannel (its passes, its
    failing calls; every call from `fail_from` on does not return in time). A pass after the scripted ones waits a
    little on the Stop first, so the follow does not spin (no clock is asserted). Records each attach and the tree
    it was handed (`raises`: the follow raises at once, in the round of its attach)."""

    def __init__(self, passes=(), fail=(), fail_from=None, raises=False):
        self.channel = FollowChannel(passes, fail)
        self.fail_from, self.kw, self.trees, self.raises = fail_from, [], [], raises

    def __call__(self, root, log, stop, **kw):
        self.kw.append(sorted(kw))
        self.trees.append(kw.get("tree"))
        if self.raises:
            raise os_sysmon.UsageError("the stand-in follow ends at once (SYNTHETIC)")

        def reader(args, timeout):
            n = len(self.channel.args) + 1
            if n > len(self.channel.passes):
                stop.wait(0.01)
            if self.fail_from is not None and n >= self.fail_from:
                self.channel.args.append(tuple(args))
                return None, TIMED_OUT
            return self.channel(args, timeout)
        kw["every"] = 0.0
        return os_sysmon.follow(root, log, stop, reader=reader, nt=True, **kw)


KW = ["after_record", "err", "every", "helpers", "on_pass", "out", "restart", "since", "tree"]


def settled_follows(monkeypatch, truncate=None):
    """Before each round's host lines, every os follow has finished its first pass or ended (deterministic: no
    clock); in round `truncate` the tree's file of the host's own record is emptied first (a file that restarts),
    in the watch with Sysmon and in the one without alike."""
    real = host.HostWatch._host_lines

    def _host_lines(self, now, n, *rest):
        for src in list(self.sources.values()):
            while src.thread is not None and src.thread.is_alive() and not src.first_pass.is_set():
                src.first_pass.wait(0.01)
            if n == truncate and src.host_path and Path(src.host_path).exists():
                Path(src.host_path).write_bytes(b"")
        return real(self, now, n, *rest)
    monkeypatch.setattr(host.HostWatch, "_host_lines", _host_lines)


def host_said(w, said):
    """What the person meets of the host-line findings of a watch: each (rule, tree, the children or remote of the
    lines it cites, their seqs, history, notice); the KNOCKS rows of the source findings; and the terminal lines of
    the host-line findings."""
    found = []
    for f in w.source_findings:
        if f["source"] != host.HOST_SOURCE:
            continue
        src = w.sources.get(tuple(f["tree_key"]))
        feed = next((d for d in (src.feeds if src is not None else ()) if d.path == f["trace"]
                     and d.epoch == f["fkey"][1]), None)
        recs = dict(feed.numbered) if feed is not None else {}
        what = tuple(sorted("%s" % c.get("pid") for ln in f["lines"]
                            for c in ((recs.get(ln) or {}).get("input_meta") or {}).get("children") or ())
                     or sorted("%s" % ((recs.get(ln) or {}).get("input_meta") or {}).get("remote") for ln in f["lines"]))
        found.append((f["rule_id"], f["tree"], what, tuple(f["cited_seq"]), f["history"], f["notice"]))
    rows = [x for x in section(report(w), "KNOCKS:", "NOTIFICATIONS:")[1:]
            if "FIRST-FINDING" in x or " via " in x]
    terminal = [x.split("SOURCE FINDING", 1)[1] for x in said.splitlines()
                if "SOURCE FINDING" in x and " (host): " in x]
    return sorted(found), rows, terminal


def property_holds(w, said, without, said_without):
    got, want = host_said(w, said), host_said(without, said_without)
    assert got == want, (got, want)
    return got


def against_without(tmp_path, monkeypatch, name, samples, follow, without_samples, channel=None, truncate=None):
    settled_follows(monkeypatch, truncate)
    w, said, _ = watch(tmp_path / name, monkeypatch, samples, channel=channel or Rounds(follow), follow=follow,
                       wall0=WALL0 + 240)
    without, said_without, _ = watch(tmp_path / (name + "-without"), monkeypatch, without_samples, sysmon=False,
                                     wall0=WALL0 + 240)
    return w, said, without, property_holds(w, said, without, said_without)


def cited_sources(w, f):
    lines = Path(f["trace"]).read_text(encoding="ascii").splitlines()
    return {json.loads(lines[ln - 1])["source"] for ln in f["lines"]}


def test_e1_ak1_an_os_tree_has_two_files_the_host_record_by_the_host_sources_road(tmp_path, monkeypatch):
    follow = Script(fail_from=1)
    w, said, without, (found, rows, terminal) = against_without(tmp_path, monkeypatch, "never", rounds(tmp_path, 4),
                                                                follow, rounds(tmp_path / "w", 4))
    (key,) = w.trees
    src = w.sources[key]
    assert src.kind == "os" and src.also_host and src.writes_host() and follow.kw == [KW]
    # two files: the os follow's own (the untagged per-tree file) and the host's own record's (tagged "host"),
    # each with its own feed: the catalog on the os lines, the host's rules on the host lines
    assert src.path == w._source_path(key) and src.host_path == w._source_path(key, "host") != src.path
    assert [(d.path, d.rules) for d in src.feeds] == [(src.path, w.src_rules), (src.host_path, w.host_rules)]
    assert not hasattr(src, "host_from")
    assert [c["pid"] for x in host_file_lines(w) if x["tool"] == "HostChild" for c in x["input_meta"]["children"]] \
        == [9300, 9310, 9320]
    assert ("NET-TOOL", KIMI_WORD, ("9300",), (1,), False) == found[0][:5] and len(found) == 3 and rows and terminal
    assert source_line(w).startswith("      source: os (os: Sysmon, rooted at pid 9176")
    for gone in ("its os follow read nothing", "the host's own record stopped"):   # AI-2's texts, withdrawn
        assert gone not in said and gone not in w.final_text
    assert not hasattr(host, "FOLLOW_UNREAD") and not hasattr(host, "FOLLOW_READ")
    assert not hasattr(src, "follow_passes") and not hasattr(src, "unread_follow")
    assert not hasattr(host.HostWatch, "_follow_unread")


def test_e7_ak8_a_tree_there_at_the_start_with_a_child_in_round_1(tmp_path, monkeypatch):
    follow = Script(fail_from=1)
    w, _, without, (found, _, _) = against_without(tmp_path, monkeypatch, "start", at_start(tmp_path), follow,
                                                   at_start(tmp_path / "w"))
    (key,) = w.trees
    assert w.trees[key]["first_round"] == w.history_round == 1 and w.sources[key].kind == "os"
    # round 1's HostChild line (curl) is history, as on a machine without Sysmon (the round-1 rule); later ones live
    assert [(x[2], x[4]) for x in found] == [(("9300",), True), (("9310",), False), (("9320",), False)]
    assert found[0][5] == "history: not knocked"
    # not touched (AK-1): the os feed's own history is as before M7.14 (unknown until the first pass, a tree there
    # at the start): the host lines do not set it
    assert w.sources[key].feeds[0].history_bytes == 0 or w.sources[key].passes >= 1


def test_e7_ak8_the_trees_host_file_restarted(tmp_path, monkeypatch):
    follow = Script(fail_from=1)
    w, said, _, (found, rows, _) = against_without(tmp_path, monkeypatch, "restart", rounds(tmp_path, 4), follow,
                                                   rounds(tmp_path / "w", 4), truncate=4)
    # the line written after the restart (curl3, round 4) is live, as on a machine without Sysmon (R-1)
    assert [x[4] for x in found if x[2] == ("9320",)] == [False]
    assert "source-hole" in [h["kind"] for h in w.holes]


def test_e2_e7_ak2_a_follow_that_ends_in_the_round_of_its_attach_stops_no_host_line(tmp_path, monkeypatch):
    follow = Script(raises=True)
    w, said, _, (found, rows, terminal) = against_without(tmp_path, monkeypatch, "ends", rounds(tmp_path, 4),
                                                          follow, rounds(tmp_path / "w", 4))
    assert follow.kw and "UsageError: the stand-in follow ends at once" in w.final_text   # it ended, said
    # its round's HostChild line (curl, round 2) is written and judged, and knocks as without Sysmon
    assert [x[2] for x in found] == [("9300",), ("9310",), ("9320",)] and found[0][5] != "history: not knocked"
    assert any("FIRST-FINDING" in x for x in rows) and len(terminal) == 3


BRIEF_G, BRIEF_CURL_G = guid_of(9500), guid_of(9510)
BRIEF = [created(700, at("07:55:00"), 9500, KIMI, BRIEF_G, 5888, EXPLORER, G_SHELL, "kimi"),
         talked(701, at("07:55:01"), 9500, KIMI, BRIEF_G, port=50400, dest="203.0.113.60"),
         created(702, at("07:55:02"), 9510, CURL, BRIEF_CURL_G, 9500, KIMI, BRIEF_G, "curl -s https://198.51.100.30/w"),
         talked(703, at("07:55:03"), 9510, CURL, BRIEF_CURL_G, port=50410, dest="198.51.100.30")]


def test_e3_e7_ak3_a_tree_known_only_from_the_channel_has_no_host_line_through_the_rounds(tmp_path, monkeypatch):
    follow = Script(fail_from=1)
    w, _, _, (found, _, _) = against_without(tmp_path, monkeypatch, "brief", rounds(tmp_path, 3), follow,
                                             rounds(tmp_path / "w", 3), channel=Rounds(xml={2: BRIEF}))
    brief = [k for k in w.trees if k[0] == 9500]
    assert brief and not w.trees[brief[0]].get("sampled", True)   # the channel's tree, never sampled
    src = w.sources[brief[0]]
    assert src.host_path and (not Path(src.host_path).exists() or Path(src.host_path).read_bytes() == b"")
    assert not [f for f in w.source_findings if f["source"] == "host" and tuple(f["tree_key"]) == brief[0]]
    assert all(x[1] == KIMI_WORD for x in found)


CMD_BORN = created(610, at("07:54:30"), 9400, CMD, G_CMD, 9176, KIMI, G_KIMI, "cmd /c dir")


def test_e5_e7_ak5_a_follow_attached_again_knows_the_earlier_ones_child_through_the_watch(tmp_path, monkeypatch):
    r, rw = rounds(tmp_path, 4), rounds(tmp_path / "w", 4)
    follow = Script(passes=[[CMD_BORN]])   # the first follow finds kimi's cmd (no sample holds it)
    w, _, _, (found, _, _) = against_without(tmp_path, monkeypatch, "again", [r[0], r[1], "quiet/quiet", r[3]],
                                             follow, [rw[0], rw[1], "quiet/quiet", rw[3]])
    assert len(follow.kw) == 2
    first, second = follow.trees
    # AK-5: the second follow is handed the tree the first published after its last finished pass: it knows the cmd
    assert second is not first and second.get("found") and second["by_guid"][os_sysmon._gkey(G_CMD)] == 1
    # S-1: each child once (curl2 and curl3 are new in round 4, after the quiet round: one HostChild line)
    assert [x[2] for x in found if x[0] == "NET-TOOL"] == [("9300",), ("9310", "9320")]
    assert [x["tool"] for x in host_file_lines(w)].count("HostGone") == 1


def test_e5_e7_ak6_a_restart_through_the_rounds_its_holes_words_and_a_follow_attached_after_it(tmp_path,
                                                                                            monkeypatch):
    explorer = [talked(500, at("07:53:40"), 5888, EXPLORER, G_SHELL, port=50299)]
    again = [talked(5, at("07:54:10"), 5888, EXPLORER, G_SHELL, port=50298)]   # record 5: the numbers restarted
    r, rw = rounds(tmp_path, 3), rounds(tmp_path / "w", 3)
    follow = Script(fail_from=1)
    # the restart in round 2, before kimi's tree is attached (round 3)
    w, said, _, (found, _, _) = against_without(tmp_path, monkeypatch, "before", [r[0], r[0], r[1], r[2]], follow,
                                                [rw[0], rw[0], rw[1], rw[2]],
                                                channel=Rounds(xml={1: explorer, 2: again}))
    (restart,) = [h for h in w.holes if h["kind"] == "channel-restart"]
    assert restart["round"] == 2 and "its record numbers restarted (record 5 at or below the bound 500" in restart[
        "detail"] and host.FOLLOW_RESTART.split(" %s")[0] not in restart["detail"]   # no follow ran yet
    (key,) = [k for k in w.trees if k[0] == 9176]
    # AK-6: a follow attached after the restart says in its source text that it reads from the restart's time
    assert ("(it reads the channel from the restart's time %s, not from the watch's start)"
            % host.iso(w.follow_restart.get()[1])) in w.sources[key].text
    assert [x[2] for x in found] == [("9300",), ("9310",)]
    # the restart in round 3, kimi's follow running (attached in round 2): the hole says its bound restarts too
    follow = Script(fail_from=1)
    w, said, _, _ = against_without(tmp_path, monkeypatch, "running", rounds(tmp_path / "x", 3), follow,
                                    rounds(tmp_path / "xw", 3), channel=Rounds(xml={1: explorer, 3: again}))
    (restart,) = [h for h in w.holes if h["kind"] == "channel-restart"]
    assert restart["round"] == 3 and restart["detail"].split("; query ")[0].endswith(
        host.FOLLOW_RESTART % (host.iso(w.follow_restart.get()[1]), 1))
    (key,) = [k for k in w.trees if k[0] == 9176]
    assert "(it reads the channel from the restart's time" not in w.sources[key].text   # attached before it


def test_e1_ak1_not_touched_no_round_read_the_channel_the_trees_are_host_and_no_follow_is_attached(tmp_path,
                                                                                                 monkeypatch):
    follow = Script()
    w, said, _ = watch(tmp_path / "denied", monkeypatch, rounds(tmp_path, 3), follow=follow, wall0=WALL0 + 240)
    without, said_without, _ = watch(tmp_path / "without", monkeypatch, rounds(tmp_path / "w", 3), sysmon=False,
                                     wall0=WALL0 + 240)
    assert follow.kw == [] and [s.kind for s in w.sources.values()] == ["host"]   # AF-1: the host's record alone
    property_holds(w, said, without, said_without)
    assert "Sysmon is registered, but no round up to round" in source_line(w)


def test_e1_aj1_not_touched_host_rhythm_counts_an_act_two_sources_saw_once(tmp_path, monkeypatch):
    samples, xml = kimi_then_curl(tmp_path)
    # round 1 not back in time (host), then os with the host's record beside it: the second curl is in round 2's
    # sample and in the os follow's lines, one act
    every, _, _ = watch(tmp_path / "late", monkeypatch, samples, channel=FakeWevtutil(xml, fail={1}),
                        wall0=WALL0 + 240)
    (src,) = every.sources.values()
    assert src.kind == "os" and src.also_host
    assert every.act_twins == 1 and "; 1 act(s) seen by a second source, counted once" in every.final_text


def test_e4_e6_ak4_ak7_a_curl_both_sources_saw_is_one_listing_entry_and_says_and_knocks_as_without_sysmon(
        tmp_path, monkeypatch):
    follow = Follow(unread=0, then=[CURL_BORN, CURL_TALK], go=True)
    w, said, without, (found, rows, terminal) = against_without(tmp_path, monkeypatch, "both", rounds(tmp_path, 3),
                                                                follow, rounds(tmp_path / "w", 3))
    nets = [f for f in w.source_findings if f["rule_id"] == "NET-TOOL" and f["tree"] == KIMI_WORD]
    # curl (round 2's sample, and the follow's event 1) and curl2 (round 3's sample only): the record keeps all three
    assert sorted(f["source"] for f in nets) == ["host", "host", "os"]
    assert all(cited_sources(w, f) == {f["source"]} for f in nets)   # AJ-3: two files, each its own lines
    lines = report(w)
    head = next(x for x in lines if x.startswith("SOURCE FINDINGS: "))
    assert head.startswith("SOURCE FINDINGS: %d (" % (len(w.source_findings) - 1))
    listed = [x for x in lines if "] NET-TOOL on kimi pid 9176 via " in x]
    assert len(listed) == 2 and all(" via host: " in x for x in listed)
    os_entry = next(f for f in nets if f["source"] == "os")
    both = [x for x in listed if "; and via os, %s, counted once: cites %s lines " % (host.TAKEN_SAME,
                                                                                       os_entry["trace"]) in x]
    assert len(both) == 1 and "program curl" in both[0]
    assert host.TAKEN_SAME == "taken for the same act (one image, starts within 1 s)"
    assert "the same act (counted once)" not in w.final_text
    # AK-4: the knocks and the terminal lines name the cited line's source: those of the watch without Sysmon
    assert any(" via host" in x or "FIRST-FINDING" in x for x in rows) and terminal
    assert judged(w)[2] == judged(without)[2]


def test_e6_ak7_not_touched_two_curls_of_two_images_or_times_stay_two(tmp_path, monkeypatch):
    late = created(602, at("07:54:25"), 9300, CURL, G_CURL, 9176, KIMI, G_KIMI, "curl -s https://198.51.100.20/x")
    follow = Follow(unread=0, then=[late, CURL_TALK], go=True)   # started 5 s from the sample's: not one child
    w, _, _ = watch(tmp_path / "apart", monkeypatch, rounds(tmp_path, 3), channel=Rounds(follow), follow=follow,
                    wall0=WALL0 + 240)
    listed = [x for x in report(w) if "] NET-TOOL on kimi pid 9176 via " in x]
    assert sorted(x.split(" via ")[1].split(":")[0] for x in listed) == ["host", "host", "os"]
    assert not any(host.TAKEN_SAME in x for x in listed)


def test_e1_ak1_told_twice_joins_nothing_across_a_restarted_file():
    feed = type("F", (), {"path": "h", "epoch": 1, "numbered": [(1, {"tool": "HostChild"})]})()
    src = type("S", (), {"feeds": [feed]})()
    f = {"trace": "h", "fkey": ["h", 0], "lines": [1], "tree_key": ["k"], "source": "host", "src_kind": "os",
         "rule_id": "NET-TOOL", "history": False}
    o = dict(f, source="os", trace="h")
    assert host.told_twice([f, o], {("k",): src}) == {}   # the entries' epoch is not the feed's: no record read


# --- E4 (AJ-4): the os source itself, through the real follow ------------------------------------------------------

def test_e4_aj4_r1_a_follow_attached_again_knows_the_tree_the_earlier_follow_found(tmp_path):
    tree = {}
    lines, _, tops, _ = follow_through(FollowChannel([[CURL_BORN]]), 1, since=START, tree=tree,
                                       log=tmp_path / "one.jsonl")
    assert tops == [(1, 602)] and acts(lines) == [("2026-11-10T07:54:20.000Z", "process")]
    assert tree["found"] and tree["by_guid"][os_sysmon._gkey(G_CURL)] == 1
    again = FollowChannel([[CURL_BORN, CURL_TALK]])
    lines, _, _, _ = follow_through(again, 1, since=START, after_record=602, tree=dict(tree),
                                    log=tmp_path / "two.jsonl")
    assert again.args == [("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                           " EventRecordID>602]]", "/c:2000", "/f:xml")]
    assert acts(lines) == [("2026-11-10T07:54:21.000Z", "net")]   # the child's event 3 after the attach: its act
    bare, _, _, _ = follow_through(FollowChannel([[CURL_BORN, CURL_TALK]]), 1, since=START, after_record=602,
                                   log=tmp_path / "bare.jsonl")
    assert acts(bare) == []   # without the earlier tree it is no one's (as before AJ-4)


def test_e4_aj4_r2_a_guid_given_in_another_case_and_without_braces_joins(tmp_path):
    given = G_KIMI.strip("{}").upper()
    tree = {}
    lines, silent, _, _ = follow_through(FollowChannel([[CURL_BORN, CURL_TALK]]), 1, since=START, tree=tree,
                                         root="9176:" + given, log=tmp_path / "upper.jsonl")
    assert acts(lines) == [("2026-11-10T07:54:20.000Z", "process"), ("2026-11-10T07:54:21.000Z", "net")]
    assert tree["root_guid"] == G_KIMI.strip("{}").lower() and silent == []
    other, _, _, _ = follow_through(FollowChannel([[CURL_BORN, CURL_TALK]]), 1, since=START,
                                    root="9176:" + G_SHELL, log=tmp_path / "other.jsonl")
    assert acts(other) == []   # not touched: another process's GUID is not kimi's


class Cleared(FollowChannel):
    """The channel cleared (wevtutil cl) before the second call: its records restart at 1."""

    def __call__(self, args, timeout):
        if len(self.args) == 1:
            self.log = []
        return super().__call__(args, timeout)


def test_e4_aj4_r3_when_the_rounds_read_restarts_the_follows_bound_restarts_and_reads_on(tmp_path):
    cleared = [created(1, at("07:56:20"), 9310, CURL, G_CURL2, 9176, KIMI, G_KIMI, "curl -s https://198.51.100.21/y"),
               talked(2, at("07:56:21"), 9310, CURL, G_CURL2, port=50320, dest="198.51.100.21")]
    restart_at = datetime.datetime(2026, 11, 10, 7, 56, 0, tzinfo=UTC)
    channel = Cleared([[CURL_BORN, CURL_TALK], cleared, []])
    lines, _, tops, _ = follow_through(channel, 3, since=START, log=tmp_path / "restart.jsonl",
                                       restart=lambda: (1, restart_at) if channel.args else None)
    assert channel.args == [FIRST, ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                                    " TimeCreated[@SystemTime>='2026-11-10T07:56:00.000Z']]]", "/c:2000", "/f:xml"),
                            ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                             " EventRecordID>2]]", "/c:2000", "/f:xml")]
    assert tops == [(1, 603), (2, 2), (3, 2)]
    assert acts(lines) == [("2026-11-10T07:54:20.000Z", "process"), ("2026-11-10T07:54:21.000Z", "net"),
                           ("2026-11-10T07:56:20.000Z", "process"), ("2026-11-10T07:56:21.000Z", "net")]
    still = Cleared([[CURL_BORN, CURL_TALK], cleared, []])   # without the round's restart: nothing above 603
    lines, _, _, _ = follow_through(still, 3, since=START, log=tmp_path / "still.jsonl")
    assert len(acts(lines)) == 2
    shared = host.FollowRestart()
    assert shared.get() is None
    shared.restart(restart_at)
    assert shared.get() == (1, restart_at)
    assert host.FOLLOW_RESTART % ("2026-11-10T07:56:00.000Z", 1) == (
        "; the trees' os follows read from 2026-11-10T07:56:00.000Z too (1 follow(s))")


# --- E3 (AI-1, said) and E4 (AI-3): the guide and THREAT_MODEL ----------------------------------------------------

AI3 = ("in no source of the host watch; the proxy source records the tool call where the agent is pointed at it; the"
       " host watch does not read the proxy's trace")


def words(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


@pytest.mark.parametrize("path", ["docs/GUIDE.md", "docs/THREAT_MODEL.md"])
def test_e3_ai1_the_guide_and_threat_model_say_what_a_bounded_follow_no_longer_reads(path):
    text = words(path)
    for said in ("each pass of a tree's os follow asks the channel a bounded question, as a round's read does",
                 "the first pass those since the watch's start",
                 "then the records after the highest it has read in the whole channel",
                 "under the host watch a tree whose source is os also has the host's own record, from its attach",
                 "a follow attached again is given the tree the earlier follow published at the end of its last finished pass",
                 "a follow attached after a restart says in its source text that it reads from the restart's time",
                 "taken for the same act (one image, starts within 1 s)",
                 "every follow's bound restarts",
                 "the follow no longer reads the tree's past before the watch's start",
                 "a child that started before the watch is not known to",
                 "counts it once" if path.endswith("GUIDE.md") else "counted once"):
        assert said in text.lower(), (path, said)
    assert "two passes and none that read" not in text   # AI-2's counting, withdrawn (AJ-1)


@pytest.mark.parametrize("path", ["docs/GUIDE.md", "docs/THREAT_MODEL.md"])
def test_e4_ai3_the_guide_and_threat_model_say_the_proxy_has_it_and_the_host_watch_does_not_read_it(path):
    text = words(path)
    assert ("reads with its own code (a file it opens, a directory it lists) is " + AI3) in text, path
    assert "a directory it lists) is in no source:" not in text, path   # the false words, gone
    # not touched: a file's deletion is in no source at all, as it was
    assert "a file's deletion is in no source at all" in text.replace("A file's", "a file's"), path


def test_e4_ai3_not_touched_the_readme():
    assert "proxy's trace" not in words("README.md")


# --- E5 -----------------------------------------------------------------------------------------------------------

def test_e5_the_code_and_tests_are_ascii_and_no_test_here_reads_docs_review():
    for p in ("raqib/hooks/os_sysmon.py", "raqib/host.py", "tests/test_host_follow_returns.py",
              "tests/test_readme_top.py"):
        (ROOT / p).read_bytes().decode("ascii")
    code = Path(__file__).read_text(encoding="ascii").split('"""', 2)[2].split("def test_e5_")[0]
    assert "docs" + "/review" not in code
