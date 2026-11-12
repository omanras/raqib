"""M7.14 (ADR-0007 Amendment AI): a tree's follow that returns, as the person meets it.
On a machine whose Sysmon channel holds weeks, every pass of a tree's os follow
asked wevtutil for the whole channel and was ended at its 10 s: the tree was
judged by nothing. AI-1: a follow's pass under raqib watch --host asks a bounded
question, as a round's read does (the first pass the events since the watch's
start, each later pass the records after the highest read, the round's cap; a
cut is a hole); `raqib os-sysmon` run by a person reads what it read. AI-2: a
tree whose follow has had two passes and none that read is judged by the host's
own record too, from the next round it is in, until a pass reads. AI-3: the
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
from test_host_third_field_run import (CURL, KIMI, KIMI_WORD, TIMED_OUT, Channel, judged, report, sample,  # noqa: E402
                                       watch)

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
UNREAD_2 = ("its os follow read nothing in 2 passes (not back in time): judged by the host's own record too from round"
            " 3, as on a machine without Sysmon, until a pass reads the channel")
READ_4 = "a pass of its os follow read the channel by round 4: the host's own record stopped; its lines before stay judged"


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
    log = kw.pop("log")
    stop, tops, reads = threading.Event(), [], []

    def on_pass(n, top):
        tops.append((n, top))
        if n >= passes:
            stop.set()
    os_sysmon.follow("9176", str(log), stop, every=0.0, out=io.StringIO(), err=io.StringIO(), nt=True,
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


# --- E2 (AI-2): a tree whose follow read nothing in two passes gets the host's own record too -------------------

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
    """The rounds' channel: every round read (an empty kept read); at round `release` the follow's waiting pass is
    let go first and the round waits for it."""

    def __init__(self, follow, release=None):
        super().__init__(denied=set())
        self.follow, self.release = follow, release

    def __call__(self, timeout, helpers=None, popen=None, environ=None, args=()):
        if self.release is not None and len(self.args) + 1 == self.release:
            self.follow.go.set()
            assert self.follow.done.wait(5)
        return super().__call__(timeout, helpers, popen, environ, args)


def rounds(tmp_path, n=3):
    """kimi (round 1); its child curl talks (round 2: its tree is attached, os); a second child curl talks (round 3:
    the round after the follow's two passes); a third (round 4) (SYNTHETIC)."""
    kimi = (9176, 5888, KIMI, "kimi", "2026-11-10T07:51:00.000")
    curl = (9300, 9176, CURL, "curl -s https://198.51.100.20/x", "2026-11-10T07:54:20.000")
    curl2 = (9310, 9176, CURL, "curl -s https://198.51.100.21/y", "2026-11-10T07:56:20.000")
    talk = (50300, "203.0.113.50", 9176, "2026-11-10T07:51:01.000")
    curl3 = (9320, 9176, CURL, "curl -s https://192.0.2.30/z", "2026-11-10T07:58:20.000")
    talks = [talk, (50310, "198.51.100.20", 9300, "2026-11-10T07:54:21.000"),
             (50320, "198.51.100.21", 9310, "2026-11-10T07:56:21.000"), (50340, "192.0.2.30", 9320,
                                                                        "2026-11-10T07:58:21.000")]
    return [sample(tmp_path, "r%d" % (i + 1), [kimi, curl, curl2, curl3][:i + 1], talks[:i + 1]) for i in range(n)]


def file_lines(w):
    (src,) = w.sources.values()
    return [json.loads(x) for x in Path(src.path).read_text(encoding="ascii").splitlines() if x.startswith("{")]


def host_children(lines):
    """The child pids the host's own record wrote (HostChild lines)."""
    return sorted({c["pid"] for x in lines if x["source"] == "host" and x.get("tool") == "HostChild"
                   for c in x["input_meta"]["children"]})


def source_line(w):
    lines = report(w)
    tree = next(i for i, x in enumerate(lines) if "pid 9176 kimi" in x)
    return lines[tree + 1]


def test_e2_ai2_a_follow_that_never_reads_gets_the_host_record_from_round_2_and_its_child_curl_is_judged(
        tmp_path, monkeypatch):
    follow = Follow(unread=2)
    w, said, _ = watch(tmp_path / "unread", monkeypatch, rounds(tmp_path), channel=Rounds(follow),
                       follow=follow, wall0=WALL0 + 240)
    (key,) = w.trees
    src = w.sources[key]
    assert src.kind == "os" and src.also_host and src.unread_follow == 3
    assert follow.kw == [["after_record", "err", "every", "helpers", "on_pass", "on_read", "out", "since"]]
    assert follow.channel.args[:2] == [FIRST, FIRST]   # the bounded question, asked again after a pass not read
    (line,) = [x for x in said.splitlines() if "] round 3: kimi pid 9176: os: Sysmon, rooted at pid 9176" in x]
    assert line.endswith("(%s)" % UNREAD_2)
    assert source_line(w).startswith("      source: os (os: Sysmon, rooted at pid 9176") and UNREAD_2 in source_line(w)
    # round 3's sample: the child curl is judged (NET-TOOL) by the host's record, as on a machine without Sysmon
    assert ("NET-TOOL", KIMI_WORD, 9176, "host", False) in judged(w)[1]
    without, _, _ = watch(tmp_path / "without", monkeypatch, rounds(tmp_path / "w"), sysmon=False,
                          wall0=WALL0 + 240)
    assert set(judged(without)[1]) <= set(judged(w)[1])   # never judged by less than the watch without Sysmon
    assert host_children(file_lines(w)) == host_children(file_lines(without))


def test_e2_ai2_when_a_pass_reads_the_host_lines_stop_and_the_os_source_judges(tmp_path, monkeypatch):
    follow = Follow(unread=2, then=[CURL_BORN, CURL_TALK, CURL2_BORN, CURL2_TALK, CURL3_BORN, CURL3_TALK])
    w, said, _ = watch(tmp_path / "reads", monkeypatch, rounds(tmp_path, 4), channel=Rounds(follow, release=4),
                       follow=follow, wall0=WALL0 + 240)
    (key,) = w.trees
    src = w.sources[key]
    assert src.kind == "os" and not src.also_host and src.unread_follow is None
    assert follow.channel.args == [FIRST, FIRST, FIRST, AFTER_607][:len(follow.channel.args)]
    assert UNREAD_2 in said
    assert [x for x in said.splitlines() if "] round 4: kimi pid 9176: os" in x][-1].endswith("(%s)" % READ_4)
    assert "(%s));" % READ_4 in source_line(w) and UNREAD_2 not in source_line(w)
    lines = file_lines(w)
    host = [x for x in lines if x["source"] == "host"]
    assert host_children(lines) == [9300, 9310]                         # round 4's child: no host line
    assert "2026-11-10T07:58:21.000Z" in [x["ts"] for x in lines if x["source"] == "os"]   # the os source has it
    found = judged(w)[1]
    assert ("NET-TOOL", KIMI_WORD, 9176, "host", False) in found and ("NET-TOOL", KIMI_WORD, 9176, "os", False) in found


def test_e2_ai2_not_touched_a_tree_whose_follow_reads_or_missed_one_pass_has_no_host_line(tmp_path, monkeypatch):
    for name, follow in (("reads", Follow(unread=0, then=[CURL_BORN, CURL_TALK], go=True)), ("one", Follow(unread=1))):
        w, said, _ = watch(tmp_path / name, monkeypatch, rounds(tmp_path / name), channel=Rounds(follow),
                           follow=follow, wall0=WALL0 + 240)
        (key,) = w.trees
        src = w.sources[key]
        assert src.kind == "os" and not src.also_host and src.unread_follow is None, name
        assert [x for x in file_lines(w) if x["source"] == "host"] == [], name
        assert "its os follow read nothing" not in said and "its os follow read nothing" not in w.final_text, name
        assert source_line(w).startswith("      source: os (os: Sysmon, rooted at pid 9176"), name


# --- E3 (AI-1, said) and E4 (AI-3): the guide and THREAT_MODEL ----------------------------------------------------

AI3 = ("in no source of the host watch; the proxy source records the tool call where the agent is pointed at it; the"
       " host watch does not read the proxy's trace")


def words(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


@pytest.mark.parametrize("path", ["docs/GUIDE.md", "docs/THREAT_MODEL.md"])
def test_e3_ai1_the_guide_and_threat_model_say_what_a_bounded_follow_no_longer_reads(path):
    text = words(path)
    for said in ("each pass of a tree's os follow asks the channel a bounded question, as a round's read does",
                 "the events since the watch's start",
                 "then the records after the highest it has read",
                 "a tree whose follow has had two passes and none that read is judged by the host's own record too",
                 "the follow no longer reads the tree's past before the watch's start",
                 "a child that started before the watch is not known to"):
        assert said in text.lower(), (path, said)


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
