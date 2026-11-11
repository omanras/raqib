"""M7.13 (ADR-0007 Amendment AF): the third field run, as the person meets it.

docs/review/2026-11-11-third-field-run.md, F1 to F4: on a machine where
Sysmon is registered and the watch is not elevated, every round's read of the
channel failed (wevtutil exit 5, access denied); every tree had the os source,
which could read nothing (F1); the report said "the rounds read its channel"
under "0 read(s) kept" (F2); nothing knocked for it (F3); 216 of the report's
lines were the same hole (F4). Each test here runs a HostWatch round by round
through tests/test_round_channel.py's channel_watch (the live reader the window
builds, its samples and its channel faked) and reads what the person reads: the
findings, the knocks, the terminal lines and the printed report. The failed
read is the real os_sysmon.read_live_bounded, its wevtutil a stand-in process
that exits 5 with "Access is denied.". SYNTHETIC: host `host`, user `user`,
RFC 5737 addresses only; no address, host or user name of the field run.

The REDO (ADR-0007 Amendment AG): a tree given the host's record only because
no round had read the channel is attached again as os after a kept read
(AG-1); the cause of a failed read is a word the code decides (AG-2); the one
terminal line says what is not seen and how the trees are judged (AG-3); the
CHANNEL, SYSMON and AB-3 words are true (AG-4); one folded line per episode
(AG-5). No test here reads a file under docs/review (AG-10).
"""
import io
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import host  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
from test_round_channel import (HOSTFIX, EXPLORER, FakeWevtutil, channel_watch, channel_xml, created,  # noqa: E402
                                guid_of, shell_events, talked, WALL0)

REAL_BOUNDED = os_sysmon.read_live_bounded
DENIED = ("wevtutil exited 5 (Access is denied.): the Sysmon channel was not read (no Sysmon, no channel, or no"
          " rights to read it)")
TIMED_OUT = "wevtutil did not return in 10 s (fake): the Sysmon channel was not read"
KIMI = "C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\kimi.exe"
KIMI_WORD = "9176:kimi:2026-11-10T07:51:00.000Z"
AGENT = "C:\\Users\\user\\AppData\\Local\\Programs\\agent\\agent.exe"
SYSMON_TODAY = "SYSMON: the live reader's check: present, the rounds read its channel"   # before M7.13, every round
CURL = "C:\\Windows\\System32\\curl.exe"
ADVICE = "an elevated terminal (Run as administrator) reads it"   # AG-2: said only for a denial
UNTIL = ("until a round reads it, what lives between two rounds is not seen and the trees are judged by the host's"
         " own record; a round that reads attaches them again as os (Sysmon)")   # AG-3


class DeniedProc:
    """The wevtutil a terminal that is not elevated starts (SYNTHETIC): it exits 5, "Access is denied."."""
    pid = 4711
    returncode = 5

    def __init__(self, argv, **kw):
        self.argv = argv

    def communicate(self, timeout=None):
        return b"", b"Access is denied.\r\n"


class Channel:
    """os_sysmon.read_live_bounded for the rounds' channel: the real function with the denied wevtutil in the
    rounds of `denied`, a read that does not return in the rounds of `late`, and an empty kept read in every other
    round. Every call is counted."""

    def __init__(self, denied=None, late=(), proc=DeniedProc):
        self.denied = denied   # None: every round
        self.late = set(late)
        self.proc = proc       # the stand-in wevtutil of the failed rounds
        self.args = []

    def __call__(self, timeout, helpers=None, popen=None, environ=None, args=()):
        self.args.append(tuple(args))
        n = len(self.args)
        if n in self.late:
            return None, TIMED_OUT
        if self.denied is None or n in self.denied:
            return REAL_BOUNDED(timeout, helpers, popen=self.proc, environ={"SystemRoot": "C:\\Windows"}, args=args)
        return "", None


class Follows:
    """An os follow that records each attach and waits on its stop (none is expected where the channel is unread)."""

    def __init__(self):
        self.roots = []

    def __call__(self, root, log, stop, **kw):
        self.roots.append(root)
        if kw.get("on_pass"):
            kw["on_pass"](1, None)
        stop.wait()
        return 1


def sample(tmp_path, name, processes=(), connections=(), drive=True):
    """tests/fixtures/host/quiet/quiet with these process and connection rows added (SYNTHETIC)."""
    d = tmp_path / name
    shutil.copytree(str(HOSTFIX / "quiet" / "quiet"), str(d))
    with open(d / "win-process-1.csv", "a", encoding="ascii", newline="\n") as f:
        for pid, ppid, exe, cmd, start in processes:
            f.write('"%d","%d","%s","%s","%s","%sZ"\n' % (pid, ppid, exe.rsplit("\\", 1)[1], exe, cmd, start))
    with open(d / "win-tcp-1.csv", "a", encoding="ascii", newline="\n") as f:
        for port, remote, pid, start in connections:
            f.write('"192.0.2.10","%d","%s","443","Established","%d","%sZ"\n' % (port, remote, pid, start))
    if not drive:   # D-3: a run record without the system drive (a benign check that cannot be made: a hole a round)
        run = json.loads((d / "run.json").read_text(encoding="ascii"))
        run.pop("system_drive", None)
        (d / "run.json").write_text(json.dumps(run), encoding="ascii")
    return d


def kimi_curl(tmp_path):
    """Run 3's case: kimi (named by the catalog) talks and runs curl, which talks (about 20 s)."""
    return sample(tmp_path, "kimi-curl",
                  [(9176, 5888, KIMI, "kimi", "2026-11-10T07:51:00.000"),
                   (9300, 9176, "C:\\Windows\\System32\\curl.exe", "curl -s https://198.51.100.20/x",
                    "2026-11-10T07:51:20.000")],
                  [(50300, "203.0.113.50", 9176, "2026-11-10T07:51:01.000"),
                   (50310, "198.51.100.20", 9300, "2026-11-10T07:51:21.000")])


def watch(tmp_path, monkeypatch, samples, channel=None, sysmon=True, follow=None, **kw):
    """channel_watch over these samples: the reader finds Sysmon (sysmon) and reads the channel through `channel`
    (default: denied in every round), or finds no Sysmon. (watch, terminal text, round records)."""
    out = io.StringIO()
    if sysmon:
        kw["wevtutil"] = channel if channel is not None else Channel()
    w, _, rounds = channel_watch(tmp_path, monkeypatch, list(samples), [""] * len(samples), sysmon=sysmon,
                                 out=out, follow=follow, **kw)
    return w, out.getvalue(), rounds


def report(w):
    return w.final_text.splitlines()


def section(lines, head, until):
    start = next(i for i, x in enumerate(lines) if x.startswith(head))
    end = next(i for i, x in enumerate(lines) if i > start and x.startswith(until))
    return lines[start:end]


def channel_knocks(w):
    return [k for k in w.knocks if k["limit_id"] == host.CHANNEL_KNOCK_ID]


def judged(w):
    """What the watch judged, as AF-1's property compares it: the findings (rule, round, tree), the source
    findings (rule, tree, pid, source, a note or not) and the knocks (round, event, rate-limit id, title)."""
    return ([(f["rule_id"], f["round"], f.get("tree")) for f in w.findings],
            [(f["rule_id"], f.get("tree"), f["pid"], f["source"], bool(f.get("benign_note")))
             for f in w.source_findings],
            [(k["round"], k["event"], k["limit_id"], k["title"]) for k in w.knocks
             if k["limit_id"] != host.CHANNEL_KNOCK_ID])


# --- E1 (AF-1, F1): a watch that cannot read the channel judges its trees by the host's own record -------------

def test_e1_a_watch_whose_reads_are_denied_judges_as_a_machine_without_sysmon(tmp_path, monkeypatch):
    k = kimi_curl(tmp_path)
    follow = Follows()
    denied, said, rounds = watch(tmp_path / "denied", monkeypatch, ["quiet/quiet", k, k], follow=follow)
    bare, _, _ = watch(tmp_path / "bare", monkeypatch, ["quiet/quiet", k, k], sysmon=False)
    # the property: on the same rounds, every finding and every knock of the machine with no Sysmon
    assert judged(denied) == judged(bare)
    findings, sources, knocks = judged(denied)
    assert findings == [(host.NEW_AGENT, 2, KIMI_WORD)]                     # run 3: NEW-AGENT (high) ...
    assert sources == [("NET-TOOL", KIMI_WORD, 9176, "host", False)]        # ... and NET-TOOL (medium) on kimi
    assert [x[1] for x in knocks] == [host.NEW_AGENT, "FIRST-FINDING"]
    assert follow.roots == []                                               # no os source was attached
    (key,) = denied.trees
    src = denied.sources[key]
    assert src.kind == host.HOST_SOURCE and denied.trees[key]["source"] == host.HOST_SOURCE
    # AG-3: the tree's own text names the cause in its few words, never the advice nor the full reason again
    assert src.text.endswith("(Sysmon is registered, but no round up to round 2 read its channel (denied): judged by"
                             " the host's own record, as on a machine without Sysmon, until a round reads it)")
    assert "Access is denied." not in src.text and "elevated" not in src.text
    # AG-1, not touched: a watch that never reads keeps AF-1 (host in every round it is in)
    assert [x["input_meta"]["source"] for r in rounds for x in r["lines"] if x["tool"] == host.TREE_TOOL] == [
        "host", "host"]
    (line,) = [x for x in rounds[1]["lines"] if x["tool"] == host.TREE_TOOL]
    assert line["input_meta"]["source"] == host.HOST_SOURCE                 # the HostTree line says it too
    tree = next(i for i, x in enumerate(report(denied)) if "pid 9176 kimi" in x)
    assert report(denied)[tree + 1].startswith("      source: host (host: the host's own record of the tree: ")
    assert "Sysmon is registered, but no round up to round 2 read its channel" in report(denied)[tree + 1]
    assert "round 2: kimi pid 9176: host: the host's own record of the tree" in said
    assert denied.final_exit == bare.final_exit == 1


def test_e1_not_touched_a_first_round_that_reads_the_channel_gives_its_trees_os_sources(tmp_path, monkeypatch):
    follow = Follows()
    w, _, rounds = watch(tmp_path, monkeypatch, ["quiet/talking", "quiet/talking"], channel=Channel(denied=()),
                         follow=follow)
    (key,) = w.trees
    assert w.sources[key].kind == "os" and follow.roots == [5888]          # in round 1, as before M7.13
    (line,) = [x for x in rounds[0]["lines"] if x["tool"] == host.TREE_TOOL]
    assert line["input_meta"]["source"] == "os" and "Sysmon is registered" not in w.sources[key].text
    assert channel_knocks(w) == []
    # said, not fixed (THREAT_MODEL): a read that fails after rounds that read leaves the os sources in place, and
    # a tree new in that round gets one too
    k = kimi_curl(tmp_path)
    follow2 = Follows()
    w2, _, _ = watch(tmp_path / "after", monkeypatch, ["quiet/quiet", k, k], channel=Channel(denied={2, 3}),
                     follow=follow2)
    assert [s.kind for s in w2.sources.values()] == ["os"] and follow2.roots == [9176]


def test_e1_not_touched_the_machine_without_sysmon_prints_todays_lines(tmp_path, monkeypatch):
    k = kimi_curl(tmp_path)
    w, said, rounds = watch(tmp_path, monkeypatch, ["quiet/quiet", k, k], sysmon=False)
    (key,) = w.trees
    assert w.sources[key].text == "host: the host's own record of the tree: %s" % w._source_path(key)
    (line,) = [x for x in rounds[1]["lines"] if x["tool"] == host.TREE_TOOL]
    assert line["input_meta"]["source_word"] == "host: the host's own record of the tree"
    assert "Sysmon channel" not in said and "elevated" not in said
    lines = report(w)
    assert "SYSMON: the live reader's check: fixture: Sysmon" in lines      # the reader's own words, as before
    assert not [x for x in lines if "elevated" in x or "AF-1" in x or "AF-4" in x]
    assert channel_knocks(w) == [] and not [h for h in w.holes if h["kind"].startswith("channel")]


# --- E2 (AF-2, F3): the first failed read knocks once and says one line -------------------------------------------

def test_e2_216_denied_rounds_are_one_knock_one_terminal_line_and_216_holes(tmp_path, monkeypatch):
    w, said, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 216)
    (knock,) = channel_knocks(w)
    assert knock["round"] == 1 and knock["event"] == host.HOLE_EVENT == "HOST-HOLE"
    assert knock["limit_id"] == "HOST-HOLE channel-unread" != knock["event"]   # its own rate-limit id
    assert knock["body"] == ("host, denied: round 1: the Sysmon channel is not read, an elevated terminal (Run as"
                             " administrator) reads it")             # AG-2: the cause first, no reason, uncut
    lines = [x for x in said.splitlines() if "Sysmon channel" in x]
    assert len(lines) == 1 and lines[0].endswith(
        "HOST-HOLE round 1: the Sysmon channel is not read (denied: %s): %s; %s (off)" % (DENIED, UNTIL, ADVICE))
    ledger = section(report(w), "KNOCKS:", "NOTIFICATIONS:")
    assert ledger[0] == "KNOCKS: 1 (each: round, event, title / body, rate-limit id: status)"
    assert ledger[1] == ('  round 1 at 2026-11-10T07:49:30.000Z: HOST-HOLE, "Raqib: HOST-HOLE" / "host, denied:'
                         ' round 1: the Sysmon channel is not read, an elevated terminal (Run as administrator) reads'
                         ' it", id HOST-HOLE channel-unread: off')
    holes = [h for h in w.holes if h["kind"] == host.CHANNEL_UNREAD]
    assert [h["round"] for h in holes] == list(range(1, 217))                # each round's hole is still recorded
    assert [h["notice"] for h in holes] == ["off"] + [None] * 215            # the knock rides on round 1's
    assert w.final_exit == 3


def test_e2_a_failure_after_kept_reads_knocks_once_for_its_episode(tmp_path, monkeypatch):
    w, said, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 9, channel=Channel(denied={3, 4, 5, 7, 8}))
    knocks = channel_knocks(w)
    assert [k["round"] for k in knocks] == [3, 7]                           # one knock per episode
    assert knocks[0]["body"] == "host, denied: round 3: the Sysmon channel read failed after 2 read(s) kept"
    assert knocks[1]["body"] == "host, denied: round 7: the Sysmon channel read failed after 3 read(s) kept"
    lines = [x for x in said.splitlines() if "Sysmon channel" in x]
    assert len(lines) == 2 and all("the os sources stay in place" in x and "elevated" not in x for x in lines)
    assert lines[0].endswith("HOST-HOLE round 3: the Sysmon channel's read failed after 2 read(s) kept (denied: %s):"
                             " the os sources stay in place, and what they cannot read is not seen (a hole) (off)"
                             % DENIED)
    assert [h["round"] for h in w.holes if h["kind"] == host.CHANNEL_UNREAD] == [3, 4, 5, 7, 8]


def test_e2_not_touched_no_sysmon_is_a_note_never_this_knock(tmp_path, monkeypatch):
    w, said, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, sysmon=False)
    assert channel_knocks(w) == [] and [k for k in w.knocks if k["event"] == host.HOLE_EVENT] == []
    assert any(n.startswith(host.BETWEEN_HOLE % "") and "no Sysmon channel is read" in n for n in w.notes)
    assert "Sysmon channel is not read" not in said


# --- E3 (AF-3, F2): the SYSMON line says what the rounds did -------------------------------------------------------

def test_e3_every_round_read_is_todays_line_byte_for_byte(tmp_path, monkeypatch):
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 3, channel=Channel(denied=()))
    assert SYSMON_TODAY in report(w) and host.SYSMON_ALL == SYSMON_TODAY[len("SYSMON: "):]
    # AG-4, not touched: the CHANNEL line of a watch whose every round read, byte for byte as before
    assert ("CHANNEL (the rounds read the Sysmon channel since the previous round): 3 read(s) kept, 0 failed, 0 at the"
            " cap of 2000; 0 event(s); kinds read: none; 0 brief tree(s) (seen in the channel only); no event 1"
            " read so far: a tree that starts and ends between two rounds may be unseen; no event 3 read so far: talk"
            " between rounds may be unseen (Sysmon without -n logs none); no event 22 read so far: a name asked"
            " between two rounds may be unseen") in report(w)


def test_e3_none_read_says_the_rounds_the_first_reason_and_how_the_trees_were_judged(tmp_path, monkeypatch):
    k = kimi_curl(tmp_path)
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet", k, k])
    lines = report(w)
    assert ("SYSMON: the live reader's check: present, but none of the 3 read(s) of its channel the rounds asked was"
            " kept (the first reason, round 1: %s): every tree was judged by the host's own record (AF-1)" % DENIED) \
        in lines                                                            # AG-4: N is the reads asked, said so
    # AG-4, AG-10: the CHANNEL line is headed by the fact; never "the rounds read", never "record None"
    assert ("CHANNEL (no round kept a read of the Sysmon channel): 0 read(s) kept, 3 failed: nothing the channel holds"
            " since the watch's start was read") in lines
    assert not [x for x in lines if "the rounds read" in x or "record None" in x]   # never beside 0 reads kept (F2)


def test_e3_some_read_says_k_of_n_and_the_first_failed_read(tmp_path, monkeypatch):
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, channel=Channel(denied={3}))
    lines = report(w)
    assert ("SYSMON: the live reader's check: present; 3 of the 4 read(s) of its channel the rounds asked were kept"
            " (the first failed read, round 3: %s)" % DENIED) in lines
    assert not [x for x in lines if "the rounds read its channel" in x]


# --- E4 (AF-4, F4): the same hole of many rounds is one line -------------------------------------------------------

def test_e4_216_rounds_of_the_same_hole_are_one_line_and_the_count_stays(tmp_path, monkeypatch):
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 216)
    holes = section(report(w), "HOLES (A3):", "BLIND SPOTS")
    assert holes[0] == "HOLES (A3): 216"                                    # the count: the holes, as before
    assert holes[1] == ("  (216 hole(s) in 1 line(s): the holes of a round's channel read whose words differ only by"
                        " the round and its time are one line, AF-4)")
    assert len(holes) == 3
    line = holes[2]
    assert line.startswith("  - channel-unread: rounds 1-216 (216 holes in this line: their words differ only by the"
                           " round and its time): the Sysmon channel was not read this round (%s): the round keeps its"
                           " sample; the next round reads the records after the start; query " % DENIED)
    assert line.count("Access is denied.") == 1 and "round 2" not in line   # the words once
    assert "; first at 2026-11-10T07:49:30.000Z, last at 2026-11-10T14:59:30.000Z; round 1 knocked (off)" in line
    # AG-5 (Q-D confirmed): inside one episode a start that moves is a time, and the line says it moved
    assert ("; the query's start (the watch's start as each round computed it) moved from 2026-11-10T07:49:29.999Z to"
            " 2026-11-10T07:49:30.000Z; first at") in line
    from raqib import app   # the window reads the count as a number and marks the lines under it as holes
    tags = dict(app.text_tags("\n".join(holes)))
    assert tags[holes[0]] == tags[holes[1]] == tags[holes[2]] == "hole"


def unfolded(self, holes):
    """The HOLES lines before M7.13: one line per hole."""
    return ["  - %s: %s at %s%s" % (h["kind"], h["detail"], h["at"], " (%s)" % h["notice"] if h.get("notice") else "")
            for h in holes]


def test_e4_not_touched_other_kinds_two_reasons_the_record_the_state_and_the_result(tmp_path, monkeypatch):
    # explorer talks and has a child; its run record has no system drive: a benign-no-drive hole every round,
    # the same words but its round, another kind; rounds 3 and 4 fail for another reason
    nodrive = sample(tmp_path, "nodrive", connections=[(50300, "198.51.100.42", 5100, "2026-11-10T07:44:00.000")],
                     drive=False)
    w, _, rounds = watch(tmp_path / "w", monkeypatch, [nodrive] * 6, channel=Channel(late={3, 4}))
    holes = section(report(w), "HOLES (A3):", "BLIND SPOTS")
    assert holes[0] == "HOLES (A3): %d" % len(w.holes) == "HOLES (A3): 12"
    assert holes[1] == "  (12 hole(s) in 8 line(s): the holes of a round's channel read whose words differ only by" \
                       " the round and its time are one line, AF-4)"
    unread = [x for x in holes if x.startswith("  - channel-unread:")]
    assert [x.split(" (", 1)[0] for x in unread] == ["  - channel-unread: rounds 1-2, 5-6",
                                                     "  - channel-unread: rounds 3-4"]   # two reasons: two lines
    assert "Access is denied." in unread[0] and "did not return in 10 s" in unread[1]
    other = [x for x in holes if x.startswith("  - benign-no-drive: round ")]
    assert len(other) == 6                                                  # another kind: a line each, as before
    # only the text's HOLES lines changed: the rest of the report, RESULT and the exit code are the same unfolded
    text, code = w.summary()
    monkeypatch.setattr(host.HostWatch, "hole_lines", unfolded)
    before, code_before = w.summary()
    holes_before = section(before.splitlines(), "HOLES (A3):", "BLIND SPOTS")
    assert len(holes_before) == 13 and holes_before[0] == holes[0]
    assert [x for x in text.splitlines() if x not in holes] == [x for x in before.splitlines() if x not in holes_before]
    assert code == code_before == w.final_exit == 3 and "RESULT: INCOMPLETE (exit 3" in text
    state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
    assert len(state["holes"]) == 12 and [h["round"] for h in state["holes"] if h["kind"] == host.CHANNEL_UNREAD] \
        == [1, 2, 3, 4, 5, 6]                                               # the state keeps every hole
    recorded = [json.loads(x) for x in Path(w.rounds_path).read_text(encoding="ascii").splitlines()]
    assert [len(r["channel"]["holes"]) for r in recorded] == [1] * 6        # rounds.jsonl: each round its own


# --- E5 (AF-5, Q-2): today's behaviour, stated; not ruled -------------------------------------------------------------

def test_e5_today_an_unnamed_program_under_a_benign_tree_that_leaves_its_talk_to_a_child_curl_is_a_note(
        tmp_path, monkeypatch):
    """Q-2 of the field note: agent.exe (no name the catalog knows) under explorer (benign), never talking itself;
    its child curl talks. Today, on run 3's machine (no Sysmon): no tree of its own, its child's NET-TOOL a note on
    the benign tree, no knock, exit 0. Changed by nothing here: returned in docs/review/2026-11-11-M7.13-questions.md."""
    talks = [(50300, "198.51.100.42", 5100, "2026-11-10T07:44:00.000")]   # explorer talks from the start
    procs = [(6100, 5100, AGENT, "agent", "2026-11-10T07:51:00.000"),
             (6120, 6100, "C:\\Windows\\System32\\curl.exe", "curl -s https://198.51.100.43/x", "2026-11-10T07:51:20.000")]
    before = sample(tmp_path, "explorer", connections=talks)
    child = sample(tmp_path, "child-talks", procs, talks + [(50320, "198.51.100.43", 6120, "2026-11-10T07:51:21.000")])
    w, said, _ = watch(tmp_path / "w", monkeypatch, [before, child, child], sysmon=False)
    assert [k[0] for k in w.trees] == [5100]                                # agent.exe is no tree of its own
    (note,) = w.source_findings
    assert note["rule_id"] == "NET-TOOL" and note["pid"] == 5100 and note["benign_note"]
    assert w.findings == [] and w.knocks == [] and w.source_alarms() == []
    lines = report(w)
    assert "ON BENIGN TREES (noted, not knocked): 1" in lines
    assert any(x.startswith("  [medium] NET-TOOL on explorer pid 5100 via host: ") and '"agent", "curl"' in x
               for x in lines)
    assert w.final_exit == 0 and lines[-1].startswith("RESULT: CLEAN (exit 0")
    # the other side, today too: the same program that talks itself is its own tree, and knocks
    own = sample(tmp_path, "agent-talks", procs, talks + [(50320, "198.51.100.43", 6120, "2026-11-10T07:51:21.000"),
                                                          (50330, "203.0.113.44", 6100, "2026-11-10T07:51:01.000")])
    w2, _, _ = watch(tmp_path / "w2", monkeypatch, [before, own, own], sysmon=False)
    assert [(f["rule_id"], f["pid"]) for f in w2.findings] == [(host.NEW_UNKNOWN, 6100)]
    assert [(f["rule_id"], f["pid"], bool(f.get("benign_note"))) for f in w2.source_findings] == [
        ("NET-TOOL", 6100, False)]
    assert w2.final_exit == 1


# --- E6 (AF-6): said in THREAT_MODEL (the guide's paragraph and the README's clause: returned, Q-A) ---------------

def words(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split()).lower()


@pytest.mark.parametrize("path", ["docs/THREAT_MODEL.md", "docs/GUIDE.md"])
def test_e6_threat_model_and_the_guide_say_it(path):
    text = words(path)
    for said in ("the watch never checks elevation",                               # AG-6 (W-8)
                 "a read that fails after rounds that read leaves the os sources in place",
                 "what an agent without hooks reads with its own code (a file it opens, a directory it lists) is in"
                 " no source",
                 "the watched read the watcher's record"):
        assert said.lower() in text, (path, said)
    assert "a watch that is not elevated is denied every read" not in text     # W-8: a claim about Windows, gone


def test_e6_ag6_the_threat_model_bullet_is_true():
    text = words("docs/THREAT_MODEL.md")
    for said in ("who may read the channel is windows' and sysmon's configuration (administrators on a default"
                 " install)",
                 "except a claude code tree with hooks attached and a tree with no source",
                 "a file's deletion is in no source at all (sysmon's events 23 and 26 are never asked for)",
                 "a creation only where event 11 is read"):
        assert said in text, said
    assert "a file it creates or deletes where" not in text                    # W-10


# --- E7: no new kind, every rule's budget as it was -------------------------------------------------------------

def test_e7_no_new_kind_of_hole_and_the_code_is_ascii():
    src = (ROOT / "raqib" / "host.py").read_text(encoding="ascii")
    assert host.CHANNEL_UNREAD in host.CHANNEL_KINDS and '"channel-unread"' in src
    assert Path(__file__).read_text(encoding="ascii")


# --- The REDO (ADR-0007 Amendment AG) ------------------------------------------------------------------------------

def kimi_then_curl(tmp_path):
    """Run 3's kimi there at the start (07:51:00; the watch starts at 07:53:30), talking, its curl too; between
    rounds 1 and 2 it runs a second curl (07:54:20), which talks. The samples of round 1 and of rounds 2 on, and the
    channel's records each round adds (SYNTHETIC)."""
    k = kimi_curl(tmp_path)
    later = sample(tmp_path, "kimi-curl-later",
                   [(9176, 5888, KIMI, "kimi", "2026-11-10T07:51:00.000"),
                    (9300, 9176, CURL, "curl -s https://198.51.100.20/x", "2026-11-10T07:51:20.000"),
                    (9310, 9176, CURL, "curl -s https://198.51.100.21/y", "2026-11-10T07:54:20.000")],
                   [(50300, "203.0.113.50", 9176, "2026-11-10T07:51:01.000"),
                    (50310, "198.51.100.20", 9300, "2026-11-10T07:51:21.000"),
                    (50311, "198.51.100.21", 9310, "2026-11-10T07:54:21.000")])
    g = guid_of(9176)
    xml = [created(600, "2026-11-10 07:51:00.000", 9176, KIMI, g, 3000, EXPLORER, guid_of(3000), "kimi")
           + talked(601, "2026-11-10 07:51:01.000", 9176, KIMI, g, port=50300, dest="203.0.113.50")
           + created(602, "2026-11-10 07:51:20.000", 9300, CURL, guid_of(9300), 9176, KIMI, g,
                     "curl -s https://198.51.100.20/x")
           + talked(603, "2026-11-10 07:51:21.000", 9300, CURL, guid_of(9300), port=50310, dest="198.51.100.20"),
           created(604, "2026-11-10 07:54:20.000", 9310, CURL, guid_of(9310), 9176, KIMI, g,
                   "curl -s https://198.51.100.21/y")
           + talked(605, "2026-11-10 07:54:21.000", 9310, CURL, guid_of(9310), port=50311, dest="198.51.100.21")]
    return [k, later, later], xml


def sources_by_round(rounds):
    return [[x["input_meta"]["source"] for x in r["lines"] if x["tool"] == host.TREE_TOOL] for r in rounds]


def test_e1_ag1_a_tree_host_because_round_1_was_not_back_in_time_is_attached_again_as_os_in_round_2(
        tmp_path, monkeypatch):
    samples, xml = kimi_then_curl(tmp_path)
    late, said, rounds_late = watch(tmp_path / "late", monkeypatch, samples, channel=FakeWevtutil(xml, fail={1}),
                                    wall0=WALL0 + 240)
    every, _, rounds_every = watch(tmp_path / "every", monkeypatch, samples, channel=FakeWevtutil(xml),
                                   wall0=WALL0 + 240)
    # the property: from the round after the first kept read, the tree is sourced as in the watch whose every round
    # read (round 2 reads before its trees are attached: the first round it is in after a kept read is round 2)
    assert sources_by_round(rounds_late) == [["host"], ["os"], ["os"]] and sources_by_round(rounds_every) == [["os"]] * 3
    (key,) = late.trees
    src = late.sources[key]
    assert src.kind == "os" and late.trees[key]["source_round"] == 2
    assert src.text.endswith("(attached again as os: round 2 read the Sysmon channel; the lines of the host's own"
                             " record before it stay judged)")
    (line,) = [x for x in said.splitlines() if "round 2: kimi pid 9176: os: Sysmon, rooted at pid 9176" in x]
    assert "stay judged)" in line and "(attached again after a hole)" not in line
    tree = next(i for i, x in enumerate(report(late)) if "pid 9176 kimi" in x)
    assert report(late)[tree + 1].startswith("      source: os (os: Sysmon, rooted at pid 9176")
    # the lines its host record wrote in round 1 stay in its file, before the os lines, and were judged
    lines = [json.loads(x) for x in Path(src.path).read_text(encoding="ascii").splitlines() if x.startswith("{")]
    assert lines[0]["source"] == "host" and any(x["source"] == "os" for x in lines)
    found = judged(late)[1]
    assert found[0] == ("NET-TOOL", KIMI_WORD, 9176, "host", False)       # round 1's host line: judged, and stays
    assert ("NET-TOOL", KIMI_WORD, 9176, "os", False) in found              # the os lines judged from round 2
    # an act both sources saw is one act (the registry, as for any second source): the second curl, in round 2's
    # sample and in the os follow's lines
    assert late.act_twins == 1 and "; 1 act(s) seen by a second source, counted once" in late.final_text


def test_e1_ag1_not_touched_a_host_source_for_another_reason_stays(tmp_path, monkeypatch):
    def broken(root, log, stop, **kw):   # an os follow that fails: its source ends with a hole, host next
        broken.calls += 1
        raise OSError("fake: the follow could not start")
    broken.calls = 0
    k = kimi_curl(tmp_path)
    w, _, rounds = watch(tmp_path / "w", monkeypatch, [k, k, k, k], channel=Channel(denied=()), follow=broken)
    assert sources_by_round(rounds) == [["os"], ["host"], ["host"], ["host"]] and broken.calls == 1
    (src,) = w.sources.values()
    assert "the os source ended with a hole" in src.text and "attached again as os" not in src.text
    # no Sysmon on the machine: host in every round, as before
    _, _, bare = watch(tmp_path / "bare", monkeypatch, [k, k, k], sysmon=False)
    assert sources_by_round(bare) == [["host"]] * 3


class LongDeniedProc(DeniedProc):
    """wevtutil's denial as a terminal that is not elevated prints it (real-shaped, longer than the test's)."""

    def communicate(self, timeout=None):
        return b"", b"Failed to read events. Access is denied.\r\n"


class NoProc:
    def __init__(self, argv, **kw):
        raise FileNotFoundError(2, "No such file or directory (fake)")


class OtherProc(DeniedProc):
    """Exit 15, its stderr naming an exit 5 and a denial: the cause is decided from the code's words, not these."""
    returncode = 15

    def communicate(self, timeout=None):
        return b"", b"Access is denied. wevtutil exited 5 (\r\n"


@pytest.mark.parametrize("channel,cause,head", [
    (Channel(proc=LongDeniedProc), "denied", "wevtutil exited 5 (Failed to read events. Access is denied.): "),
    (Channel(late={1}, denied=()), "not back in time", "wevtutil did not return in 10 s (fake): "),
    (Channel(proc=NoProc), "could not be run", "wevtutil could not be run ("),
    (Channel(proc=OtherProc), "other failure", "wevtutil exited 15 (Access is denied. wevtutil exited 5 (): "),
], ids=["denied", "late", "unrun", "other"])
def test_e2_ag2_the_cause_is_a_word_the_code_decides_and_only_a_denial_names_the_elevated_terminal(
        tmp_path, monkeypatch, channel, cause, head):
    channel.args = []
    w, said, rounds = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 2, channel=channel)
    error = rounds[0]["channel"]["error"]
    assert error.startswith(head) and host.channel_cause(error) == cause
    (knock,) = channel_knocks(w)
    advice = ", " + ADVICE if cause == "denied" else ""
    assert knock["body"] == "host, %s: round 1: the Sysmon channel is not read%s" % (cause, advice)
    assert len(knock["body"]) <= 120                                         # the notifier's cut keeps all of it
    (line,) = [x for x in said.splitlines() if error in x]                  # the full reason: one terminal line
    assert ("the Sysmon channel is not read (%s: %s): %s" % (cause, error, UNTIL)) in line
    assert line.endswith("; %s (off)" % ADVICE if cause == "denied" else "(Sysmon) (off)")
    assert ("elevated" in said) == (cause == "denied")
    # not touched: the hole's own words
    hole = next(h for h in w.holes if h["kind"] == host.CHANNEL_UNREAD)
    assert hole["detail"].startswith("round 1: the Sysmon channel was not read this round (%s): the round keeps its"
                                     " sample; the next round reads the records after the start; query " % error)


def test_e3_ag3_one_terminal_line_with_the_reason_and_the_advice_however_many_trees(tmp_path, monkeypatch):
    two = sample(tmp_path, "two-trees", [(9176, 5888, KIMI, "kimi", "2026-11-10T07:51:00.000"),
                                         (9300, 9176, CURL, "curl -s https://198.51.100.20/x", "2026-11-10T07:51:20.000"),
                                         (6100, 5100, AGENT, "agent", "2026-11-10T07:51:00.000"),
                                         (6120, 6100, CURL, "curl -s https://198.51.100.43/x", "2026-11-10T07:51:20.000")],
                 [(50300, "203.0.113.50", 9176, "2026-11-10T07:51:01.000"),
                  (50310, "198.51.100.20", 9300, "2026-11-10T07:51:21.000"),
                  (50330, "203.0.113.44", 6100, "2026-11-10T07:51:01.000"),
                  (50320, "198.51.100.43", 6120, "2026-11-10T07:51:21.000")])
    w, said, _ = watch(tmp_path / "w", monkeypatch, [two] * 3, wall0=WALL0 + 240)
    assert len(w.trees) == 2
    reason = [x for x in said.splitlines() if "Access is denied." in x]
    assert len(reason) == 1 and [x for x in said.splitlines() if "elevated" in x] == reason
    assert ("%s; %s (off)" % (UNTIL, ADVICE)) in reason[0]
    attach = [x for x in said.splitlines() if " pid " in x and "host: the host's own record of the tree" in x]
    assert len(attach) == 2 and all(x.endswith(
        "(Sysmon is registered, but no round up to round 1 read its channel (denied): judged by the host's own"
        " record, as on a machine without Sysmon, until a round reads it)") for x in attach)
    for key, entry in w.trees.items():   # the report's source text too: the cause only
        assert "(denied)" in entry["source_text"] and "Access is denied." not in entry["source_text"]
        assert "elevated" not in entry["source_text"]


def test_e4_ag4_the_ab3_note_says_the_sources_the_trees_now_get(tmp_path, monkeypatch):
    k = kimi_curl(tmp_path)
    w, _, _ = watch(tmp_path / "w", monkeypatch, ["quiet/quiet", k, k], own=False)
    (note,) = [x for x in w.notes if "finds Sysmon, though" in x]
    assert note == ("round 1: the live reader's own check at round 1 finds Sysmon, though the watch's own check at its"
                    " start did not (fixture: the watch's own check), and its read of the channel failed (denied: %s):"
                    " the trees get the host's own record until a round reads the channel, then os (Sysmon); the"
                    " between-rounds hole of the first lines stands until then" % DENIED)
    assert [s.kind for s in w.sources.values()] == ["host"]
    # not touched: the round reads, the note's words as before
    w2, _, _ = watch(tmp_path / "w2", monkeypatch, ["quiet/quiet", k, k], channel=Channel(denied=()), own=False,
                     follow=Follows())
    (note2,) = [x for x in w2.notes if "finds Sysmon, though" in x]
    assert note2 == ("round 1: the live reader's own check at round 1 finds Sysmon, though the watch's own check at its"
                     " start did not (fixture: the watch's own check): the sources are now os (Sysmon) for every tree,"
                     " and each round reads the channel: the between-rounds hole of the first lines is narrowed where"
                     " Sysmon is read")


def test_e5_ag5_holes_before_the_first_kept_read_and_after_a_restart_are_two_lines(tmp_path, monkeypatch):
    cleared = created(5, "2026-11-10 07:55:00.000", 9500, "C:\\Windows\\System32\\cmd.exe", guid_of(9500), 3000,
                      EXPLORER, guid_of(3000), "cmd")   # record 5: the numbers restarted (wevtutil cl)

    def read(timeout, helpers=None, popen=None, environ=None, args=()):
        read.args.append(tuple(args))
        n = len(read.args)
        if n in (1, 2, 5, 6):
            return REAL_BOUNDED(timeout, helpers, popen=DeniedProc, environ={"SystemRoot": "C:\\Windows"}, args=args)
        return channel_xml(shell_events(rec=500) if n == 3 else cleared if n == 4 else ""), None
    read.args = []
    w, said, rounds = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 6, channel=read, follow=host.FixtureFollow())
    assert "channel-restart" in [h["kind"] for h in w.holes]
    holes = section(report(w), "HOLES (A3):", "BLIND SPOTS")
    unread = [x for x in holes if x.startswith("  - channel-unread:")]
    assert [x.split(" (", 1)[0] for x in unread] == ["  - channel-unread: rounds 1-2",
                                                     "  - channel-unread: rounds 5-6"]   # two episodes: two lines
    assert ("; the query's start (the watch's start as each round computed it) moved from 2026-11-10T07:49:29.999Z to"
            " 2026-11-10T07:49:30.000Z") in unread[0]
    assert "moved from" not in unread[1] and "2026-11-10T07:57:30" in unread[1]   # the restart's start, said once
    assert [k["round"] for k in channel_knocks(w)] == [1, 5]
    print("\n".join(holes))
    # AG-4: the CHANNEL line never says "record None" (the last round failed after a restart)
    assert not [x for x in report(w) if "record None" in x]


def test_e7_ag10_no_test_here_reads_a_file_under_docs_review():
    code = Path(__file__).read_text(encoding="ascii").split("def test_e7_ag10")[0]
    assert '"review"' not in code and "QUESTIONS" not in code   # E5 no longer reads the questions file
