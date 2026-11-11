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
from test_round_channel import HOSTFIX, FakeWevtutil, channel_watch  # noqa: E402

QUESTIONS = ROOT / "docs" / "review" / "2026-11-11-M7.13-questions.md"
REAL_BOUNDED = os_sysmon.read_live_bounded
DENIED = ("wevtutil exited 5 (Access is denied.): the Sysmon channel was not read (no Sysmon, no channel, or no"
          " rights to read it)")
TIMED_OUT = "wevtutil did not return in 10 s (fake): the Sysmon channel was not read"
KIMI = "C:\\Users\\user\\AppData\\Local\\Programs\\kimi\\kimi.exe"
KIMI_WORD = "9176:kimi:2026-11-10T07:51:00.000Z"
AGENT = "C:\\Users\\user\\AppData\\Local\\Programs\\agent\\agent.exe"
SYSMON_TODAY = "SYSMON: the live reader's check: present, the rounds read its channel"   # before M7.13, every round


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

    def __init__(self, denied=None, late=()):
        self.denied = denied   # None: every round
        self.late = set(late)
        self.args = []

    def __call__(self, timeout, helpers=None, popen=None, environ=None, args=()):
        self.args.append(tuple(args))
        n = len(self.args)
        if n in self.late:
            return None, TIMED_OUT
        if self.denied is None or n in self.denied:
            return REAL_BOUNDED(timeout, helpers, popen=DeniedProc, environ={"SystemRoot": "C:\\Windows"}, args=args)
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


def watch(tmp_path, monkeypatch, samples, channel=None, sysmon=True, follow=None):
    """channel_watch over these samples: the reader finds Sysmon (sysmon) and reads the channel through `channel`
    (default: denied in every round), or finds no Sysmon. (watch, terminal text, round records)."""
    out = io.StringIO()
    kw = {"wevtutil": channel if channel is not None else Channel()} if sysmon else {}
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
    assert src.text.endswith("(Sysmon is registered, but no round up to round 2 read its channel (%s): judged by the"
                             " host's own record, as on a machine without Sysmon; %s)" % (DENIED, host.ELEVATED))
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
    assert knock["body"].startswith("host, round 1: Sysmon channel not read, an elevated terminal reads it (wevtutil"
                                     " exited 5 (Access is denied.)")
    lines = [x for x in said.splitlines() if "Sysmon channel" in x]
    assert len(lines) == 1 and lines[0].endswith(
        "HOST-HOLE round 1: the Sysmon channel is not read (%s): every tree is judged by the host's own record until a"
        " round reads it; an elevated terminal (Run as administrator) reads it (off)" % DENIED)
    ledger = section(report(w), "KNOCKS:", "NOTIFICATIONS:")
    assert ledger[0] == "KNOCKS: 1 (each: round, event, title / body, rate-limit id: status)"
    assert ledger[1].startswith('  round 1 at 2026-11-10T07:49:30.000Z: HOST-HOLE, "Raqib: HOST-HOLE" / "host, round'
                                ' 1: Sysmon channel not read, an elevated terminal reads it (wevtutil exited 5')
    assert ledger[1].endswith(", id HOST-HOLE channel-unread: off")
    holes = [h for h in w.holes if h["kind"] == host.CHANNEL_UNREAD]
    assert [h["round"] for h in holes] == list(range(1, 217))                # each round's hole is still recorded
    assert [h["notice"] for h in holes] == ["off"] + [None] * 215            # the knock rides on round 1's
    assert w.final_exit == 3


def test_e2_a_failure_after_kept_reads_knocks_once_for_its_episode(tmp_path, monkeypatch):
    w, said, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 9, channel=Channel(denied={3, 4, 5, 7, 8}))
    knocks = channel_knocks(w)
    assert [k["round"] for k in knocks] == [3, 7]                           # one knock per episode
    assert knocks[0]["body"].startswith("host, round 3: Sysmon channel read failed after 2 read(s) kept (wevtutil"
                                        " exited 5 (Access is denied.)")
    assert knocks[1]["body"].startswith("host, round 7: Sysmon channel read failed after 3 read(s) kept (wevtutil"
                                        " exited 5 (Access is denied.)")
    lines = [x for x in said.splitlines() if "Sysmon channel" in x]
    assert len(lines) == 2 and all("the os sources stay in place" in x and "elevated" not in x for x in lines)
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


def test_e3_none_read_says_the_rounds_the_first_reason_and_how_the_trees_were_judged(tmp_path, monkeypatch):
    k = kimi_curl(tmp_path)
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet", k, k])
    lines = report(w)
    assert ("SYSMON: the live reader's check: present, but its channel was not read in any of 3 round(s) (the first"
            " reason, round 1: %s): every tree was judged by the host's own record (AF-1)" % DENIED) in lines
    assert any(x.startswith("CHANNEL (") and ": 0 read(s) kept, 3 failed" in x for x in lines)
    assert not [x for x in lines if "the rounds read its channel" in x]     # never beside 0 reads kept (F2)


def test_e3_some_read_says_k_of_n_and_the_first_failed_read(tmp_path, monkeypatch):
    w, _, _ = watch(tmp_path, monkeypatch, ["quiet/quiet"] * 4, channel=Channel(denied={3}))
    lines = report(w)
    assert ("SYSMON: the live reader's check: present; its channel was read in 3 of 4 round(s) (the first failed"
            " read, round 3: %s)" % DENIED) in lines
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
    text = QUESTIONS.read_text(encoding="utf-8")
    assert "Q-2" in text and test_e5_today_an_unnamed_program_under_a_benign_tree_that_leaves_its_talk_to_a_child_curl_is_a_note.__name__ in text


# --- E6 (AF-6): said in THREAT_MODEL (the guide's paragraph and the README's clause: returned, Q-A) ---------------

def words(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split()).lower()


@pytest.mark.parametrize("path", ["docs/THREAT_MODEL.md"])
def test_e6_threat_model_says_it(path):
    text = words(path)
    for said in ("the Sysmon channel needs an elevated terminal",
                 "a read that fails after rounds that read leaves the os sources in place",
                 "what an agent without hooks reads with its own code (a file it opens, a directory it lists) is in"
                 " no source",
                 "the watched read the watcher's record"):
        assert said.lower() in text, (path, said)


# --- E7: no new kind, every rule's budget as it was -------------------------------------------------------------

def test_e7_no_new_kind_of_hole_and_the_code_is_ascii():
    src = (ROOT / "raqib" / "host.py").read_text(encoding="ascii")
    assert host.CHANNEL_UNREAD in host.CHANNEL_KINDS and '"channel-unread"' in src
    assert Path(__file__).read_text(encoding="ascii")
