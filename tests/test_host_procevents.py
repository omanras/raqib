"""M14.1b and its REDO (ADR-0007 Amendments BU-2 to BU-5, BW-1 to BW-8): the watch asks the helper once a round and
says, in one section of its report, what was heard between two asks. Nothing is judged from it.

Every test here gives the live reader a stand-in Helper (live_reader(helper=)), or the watch an inventory that
carries inv["procevents"]; the real helper is tests/test_procevents_helper.py's."""
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host, own, procevents  # noqa: E402
from raqib.rules import engine  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

from test_procevents_helper import READY, FakeProc  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

sys.path.insert(0, str(ROOT / "tools" / "rig"))
import check  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
MARK = "ZQ-PATH-MARK"
EVIL = "/tmp/\x1b[31m%s\r\n\x07(deleted) \x00x" % MARK   # a program path with control characters (BU-4)


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


E, F = "2026-11-20T00:00:01.500000Z", "2026-11-20T00:00:02.500000Z"   # M14.1c REDO (BZ-4): an end is a readable time


def rec(pid, began="2026-11-20T00:00:01.000000Z", ended=None, exe="/usr/bin/true", **kw):
    return dict({"pid": pid, "ppid": 1, "exe": exe, "earlier": [], "started_ticks": 9, "began": began,
                 "ended": ended, "code": 0 if ended else None, "signal": None, "unread": {}}, **kw)


def counts(missed=0, lost=0, events=0, ended=None, beyond=0):
    return {"missed": {"exe": missed, "stat": 0}, "ended": ended, "refused": None, "beyond": beyond,
            "lost": {"count": lost, "events": events, "why": "ENOBUFS %d time(s)" % lost if lost else None}}


def answer(processes=(), more=False, ask=1, **kw):
    return {"processes": list(processes), "ends": [], "older": [], "more": more, "counts": counts(**kw), "ask": ask,
            "v": 1}


class StandIn:
    """A stand-in Helper: start() gives `why`; each ask() gives the next of `script` (an answer dict, or a reason
    of procevents: LATE, ENDED, NOT_A_LINE, REFUSED)."""

    def __init__(self, script=(), why=None, log=None, refused=None):
        self.script, self.why, self.log = list(script), why, log if log is not None else []
        self.refused = refused
        self.stops = 0

    def start(self):
        self.log.append("start")
        return self.why

    def ask(self, timeout):
        self.log.append(("ask", timeout))
        step = self.script.pop(0) if self.script else answer()
        return (None, step) if isinstance(step, str) else (step, None)

    def stop(self, within=None):
        self.stops += 1
        self.log.append("stop" if within is None else ("stop", within))
        return []


def factory(*helpers):
    made, queue = [], list(helpers)

    def make():
        made.append(queue.pop(0) if queue else StandIn())
        return made[-1]
    make.made = made
    return make


def fake_round(monkeypatch, log):
    """discover's live collection of the Linux fixture, its bytes and start times faked; each call logged."""
    def collect_live(catalog, **kw):
        log.append("sample")
        texts, holes = discover.read_dir(str(ROOT / "tests" / "fixtures" / "discover" / "linux"))
        return texts, holes, 1
    monkeypatch.setattr(discover, "collect_live", collect_live)
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", None))
    monkeypatch.setattr(discover, "proc_start_times", lambda pids: ({}, None))


def rounds(reader, n):
    return [reader()["procevents"] for _ in range(n)]


def fake_client(drains=True, script=()):
    """A factory of real clients (procevents.Helper) over fake processes that say READY, then `script`."""
    procs = []

    def make():
        def popen(argv, **kw):
            procs.append(FakeProc(argv, drains=drains, **kw))
            procs[-1].say(READY)
            for line in script:
                procs[-1].say(line)
            return procs[-1]
        return procevents.Helper(popen=popen)
    make.procs = procs
    return make


# --- E3: the live reader starts one helper, asks it after each sample ------------------------------------------
def test_e3_one_helper_started_at_the_first_round_before_its_sample_and_asked_after_each_sample(monkeypatch):
    log = []
    fake_round(monkeypatch, log)
    make = factory(StandIn([answer([rec(1, ended=E), rec(2), rec(3, began=None)], missed=1, beyond=4),
                            answer([rec(1, ended=E), rec(4, ended=F)], missed=3, more=True, beyond=4)], log=log))
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    one, two, three = rounds(reader, 3)
    assert len(make.made) == 1
    assert log == ["start", "sample", ("ask", 2.0), "sample", ("ask", 2.0), "sample", ("ask", 2.0)]
    assert one == {"began": 2, "inside": 1, "unread_exe": 1, "beyond": 4, "lost": {"count": 0, "events": 0,
                   "why": None}, "refused": None, "hole": None, "more": False, "restarts": 0, "asked": True,
                   "answered": True, "own": 0}   # M14.1c REDO (BZ-7): the watch's own left out of the round
    assert (two["began"], two["inside"], two["unread_exe"], two["more"]) == (1, 1, 2, True)   # pid 1 given again
    assert (three["began"], three["unread_exe"], three["hole"], three["beyond"]) == (0, 0, None, 0)


def test_e3_a_late_answer_and_a_line_that_is_not_the_helpers_are_holes_of_their_own_and_the_next_round_asks(
        monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([procevents.LATE, procevents.NOT_A_LINE, answer([rec(5)])]))
    late, bad, good = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 3)
    assert late["hole"] == "late: the helper's answer did not come within 2 s" and late["began"] == 0
    assert late["asked"] and not late["answered"]
    assert bad["hole"] == "not a line: the helper's answer was not its line"
    assert good["hole"] is None and good["began"] == 1 and len(make.made) == 1


def test_e1_bw1_a_late_answer_is_taken_by_the_round_that_reads_it_and_counted_once(monkeypatch):
    fake_round(monkeypatch, [])
    make = fake_client()
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    first = reader()["procevents"]
    assert first["hole"] == host.PE_LATE % 2.0 and make.procs[0].asked == [b"read 1\n"]
    make.procs[0].say(answer([rec(1, ended=E), rec(2)], ask=1))
    second = reader()["procevents"]
    assert (second["began"], second["inside"], second["answered"]) == (2, 1, True)
    make.procs[0].say(answer([rec(1, ended=E), rec(2, ended=F)], ask=2))
    third = reader()["procevents"]
    assert third["began"] == 0 and make.procs[0].asked == [b"read 1\n", b"read 2\n"]


def test_e1_bw1_three_rounds_late_running_end_the_helper_and_start_it_again_once(monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([procevents.LATE] * 3), StandIn([procevents.LATE] * 3))
    got = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 7)
    assert [g["hole"].split(":")[0] for g in got] == ["late", "late", "ended", "late", "late", "ended for good",
                                                      "ended for good"]
    assert got[2]["hole"] == host.PE_ENDED % (host.PE_LATE_RUN_WHY % (3, 2.0)) and got[2]["restarts"] == 1
    assert len(make.made) == 2 and [h.stops for h in make.made] == [1, 1] and host.PE_LATE_RUN == 3


def test_e1_bw1_an_input_that_never_drains_costs_each_round_its_time_10000_rounds_and_close_returns():
    make = fake_client(drains=False)
    events = host.ProcEvents(make, timeout=0.01)
    events.begin()
    t0, took, got = time.monotonic(), [], []
    for _ in range(10000):
        r0 = time.monotonic()
        got.append(events.round())
        took.append(time.monotonic() - r0)
    assert time.monotonic() - t0 < 30
    # the second review, M1: the rounds that END a helper (the third late one, twice) are not held for its sake:
    # the helper is ended at once and each wait is the ask's own time (0.01 s here), never the Stop's two seconds
    assert max(took) < 0.5, sorted(took)[-3:]
    assert all(getattr(p, "killed", False) and not p.terminated for p in make.procs)
    assert all(len(p.asked) <= 1 for p in make.procs) and len(make.procs) == 2
    assert got[-1]["hole"].startswith("ended for good")
    assert events.close() == []


def test_e3_a_refusal_is_final_said_in_the_readers_words_and_the_helper_is_stopped(monkeypatch):
    fake_round(monkeypatch, [])
    words = procevents.PREFIX + "the ask to listen was not answered within 2 s"
    helper = StandIn([procevents.REFUSED], refused=words)
    make = factory(helper)
    one, two = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 2)
    assert one["refused"] == words and one["hole"] == "refused: " + words and two == one and not one["asked"]
    assert helper.stops == 1 and helper.log.count(("ask", 2.0)) == 1 and len(make.made) == 1


def test_e2_a_helper_that_ended_is_started_again_once_its_loss_kept_and_a_second_end_is_final(monkeypatch):
    fake_round(monkeypatch, [])
    first = StandIn([answer([rec(7)], lost=2, events=5, beyond=1), procevents.ENDED])
    second = StandIn([answer([rec(8)]), procevents.ENDED])
    make = factory(first, second)
    got = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 5)
    assert got[1]["hole"] == ("ended: the helper of the process events ended (its output ended); it is started"
                              " again, once") and first.stops == 1 and got[1]["restarts"] == 1
    assert got[2]["hole"] is None and got[2]["began"] == 1
    assert got[2]["lost"] == {"count": 2, "events": 5, "why": "helper 1: ENOBUFS 2 time(s)"} and got[2]["beyond"] == 1
    assert got[3]["hole"].startswith("ended for good: the helper of the process events ended again (its output ended)")
    assert got[4]["hole"] == got[3]["hole"] and got[3]["asked"] and not got[4]["asked"]   # nothing asked after it
    assert len(make.made) == 2 and second.stops == 1 and got[4]["lost"]["count"] == 2


def test_e3_a_reader_that_ended_inside_the_helper_is_an_end_too_and_its_numbers_count(monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([answer([rec(1)], ended="the receive failed (EBADF)")]))
    (one,) = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 1)
    assert one["began"] == 1 and one["answered"] and one["hole"].startswith(
        "ended: the helper of the process events ended (its reader ended: the receive failed (EBADF))")
    assert len(make.made) == 2


@pytest.mark.parametrize("bad", [
    answer([rec("7")]), answer([rec(None)]), answer([rec(True)]), answer([rec(0)]), answer([rec(5, began=7)]),
    answer(["not a record"]), dict(answer(), counts=dict(counts(), missed=[])), dict(answer(), counts=dict(
        counts(), missed={"exe": "1"})), dict(answer(), counts=dict(counts(), lost={"count": 1.5, "events": 0})),
    dict(answer(), counts=dict(counts(), beyond=-1)), dict(answer(), counts=dict(counts(), beyond=None)),
    dict(answer(), counts=dict(counts(), ended=7)), dict(answer(), processes={}), dict(answer(), more="no"),
    dict(answer(), counts=[]), dict(answer(), ends=[{"pid": "x"}])])
def test_e8_a_line_the_watch_cannot_count_is_not_a_line_a_hole_of_its_round_never_an_exception(monkeypatch, bad):
    fake_round(monkeypatch, [])
    make = factory(StandIn([bad, answer([rec(3)])]))
    one, two = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 2)
    assert one["hole"] == host.PE_NOT_A_LINE and one["asked"] and not one["answered"] and one["began"] == 0
    assert two["hole"] is None and two["began"] == 1


def test_e3_a_watch_whose_helper_cannot_start_runs_as_before_with_one_hole_more(monkeypatch):
    fake_round(monkeypatch, [])
    plain = host.live_reader(CATALOG, 0.0, "linux", helper=factory(StandIn(why="no helper here (a fake)")))()
    hole = plain.pop("procevents")
    assert hole["hole"] == "not started: the helper of the process events could not be started (no helper here (a" \
                           " fake))"

    def boom():
        raise OSError("no fork")
    assert host.live_reader(CATALOG, 0.0, "linux", helper=boom)()["procevents"]["hole"].startswith("not started")
    monkeypatch.setattr(host.sys, "platform", "win32")   # the real helper is never made off Linux: as before
    before = host.live_reader(CATALOG, 0.0, "linux")()
    assert "procevents" not in before and json.dumps(before, sort_keys=True) == json.dumps(plain, sort_keys=True)


def test_e3_on_windows_no_helper_is_started_and_the_key_is_absent(monkeypatch):
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: ({}, [], 1))
    make = factory()
    inv = host.live_reader(CATALOG, 0.0, "win32", sysmon=lambda: (False, "test: no Sysmon"), helper=make)()
    assert "procevents" not in inv and make.made == []


def test_e3_e4_the_helper_is_stopped_by_a_look_and_by_its_watch_and_asks_within_a_quarter_of_its_interval(
        monkeypatch):
    fake_round(monkeypatch, [])
    helper = StandIn()
    look = host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))
    look()
    assert look.close("the look ended") == [] and helper.stops == 1 and helper.log[1] == ("ask", 2.0)
    for every, timeout in ((0.1, 0.025), (4.0, 1.0), (10.0, 2.0), (600.0, 2.0)):
        owner = host.HelperOwner(every)
        host.PROCEVENTS_OWNER.owner = owner
        try:
            helper = StandIn()
            host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))()
        finally:
            host.PROCEVENTS_OWNER.owner = None
        assert helper.log[1] == ("ask", timeout) and owner.close() == [] and helper.stops == 1
    late = factory(StandIn())   # a reader whose watch stopped already starts no helper at all
    host.PROCEVENTS_OWNER.owner = owner
    try:
        got = host.live_reader(CATALOG, 0.0, "linux", helper=late)()["procevents"]
    finally:
        host.PROCEVENTS_OWNER.owner = None
    assert late.made == [] and got["hole"] == host.PE_NOT_STARTED % "the watch stopped (Stop)"


def test_e4_at_every_0_1_a_helper_that_never_answers_adds_at_most_25_ms_and_makes_no_round_late(tmp_path,
                                                                                               monkeypatch):
    fake_round(monkeypatch, [])
    make = fake_client()
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    w = host.HostWatch(host.live_reader(CATALOG, 0.0, "linux", helper=make), CATALOG, RULES, notifier, every=0.1,
                       out=io.StringIO(), err=io.StringIO(), home=str(tmp_path / "home"), platform="linux")
    asks = []
    real = procevents.Helper.ask

    def timed(self, timeout=procevents.ASK_SECONDS):
        t0 = time.monotonic()
        try:
            return real(self, timeout)
        finally:
            asks.append((timeout, time.monotonic() - t0))
    monkeypatch.setattr(procevents.Helper, "ask", timed)
    ticks = []
    for _ in range(8):
        t0 = time.monotonic()
        w.tick(wait=5)
        ticks.append(time.monotonic() - t0)
        time.sleep(0.1)
    w.finish()
    # the second review, M1 and its must-fix 4: tick(wait=5) waits for the round, so the watch's own lateness
    # check cannot see a slow one: each round is timed here. The rounds that end the helper (the third late one)
    # are among them; with the Stop's two seconds inside a round this was over a second
    # The first round carries the machine's own first costs (measured on GitHub's Windows machines: 0.656 s once
    # and 1.047 s once, 0.03 to 0.05 s in every round after it) and is not the round the fault was in: the rounds
    # after it, the ones that end the helper among them, are each held under half a second
    assert max(ticks[1:]) < 0.5, ticks
    assert asks and all(t == 0.025 and took < 0.025 + 0.25 for t, took in asks), asks
    assert not [r for r in w.round_lines if r.get("late") or r.get("error")]
    assert not [h for h in w.holes if h["kind"] in host.READER_HOLES]


# --- E2, E3, E4, E6: the watch -------------------------------------------------------------------------------------
class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def watch(tmp_path, reader, platform="linux", every=10):
    clock = Clock()
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    w = host.HostWatch(reader, CATALOG, RULES, notifier, every=every, out=io.StringIO(), err=io.StringIO(),
                       clock=clock, wall=lambda: 1793700000.0 + clock.t - 1000.0, home=str(tmp_path / "home"),
                       platform=platform)
    return w, clock


def run(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every
    return w.finish()


def feed(names, events=None):
    """A reader of these inventories; events: one inv["procevents"] per round (None: no key)."""
    invs = [host_fixtures.inventory(n, CATALOG) for n in names]
    queue = list(zip(invs, events or [None] * len(invs)))

    def read():
        inv, pe = queue.pop(0)
        return inv if pe is None else dict(inv, procevents=pe)
    return read


def pe(began=0, inside=0, unread_exe=0, hole=None, lost=0, refused=None, beyond=0, more=False, restarts=0,
       asked=None, answered=None):
    asked = (hole is None or not hole.startswith(("refused", "not started"))) if asked is None else asked
    return {"began": began, "inside": inside, "unread_exe": unread_exe, "refused": refused, "hole": hole,
            "lost": {"count": lost, "events": 3 * lost, "why": "ENOBUFS %d time(s)" % lost if lost else None},
            "beyond": beyond, "more": more, "restarts": restarts, "asked": asked,
            "answered": (asked and hole is None) if answered is None else answered}


def files(home):
    return {p.relative_to(home).as_posix(): p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(Path(home).rglob("*")) if p.is_file()}


def judged(w, code, home):
    lines = {k: [json.loads(x) for x in v.splitlines() if x.strip()] for k, v in files(home).items()
             if "/sources/" in "/" + k}
    return (code, w.result(), [(f["rule_id"], f.get("pid"), f.get("detail")) for f in w.findings],
            [(f["rule_id"], f.get("pid")) for f in w.source_findings], lines)


@pytest.mark.parametrize("names", [["linux", "linux"], ["benign/windows-desktop", "windows"]])
@pytest.mark.parametrize("events,gaps", [([pe(5, 3), pe(2, 2, 1)], 0), ([pe(hole=host.PE_LATE % 2.0), pe(lost=1)], 1),
                                         ([pe(hole="refused: " + procevents.PREFIX + "x", refused="x")] * 2, 0),
                                         ([pe(1, beyond=3, more=True), pe(hole=host.PE_ENDED % "x", restarts=1)],
                                          3)])   # M14.1c REDO (BZ-6): a rest held back is a hole of the result too
def test_e9_no_finding_no_source_line_no_result_and_no_exit_code_changes_with_the_helper(tmp_path, names, events,
                                                                                         gaps):
    w0, c0 = watch(tmp_path / "without", feed(names))
    _, code0 = run(w0, c0, 2)
    w1, c1 = watch(tmp_path / "with", feed(names, events))
    _, code1 = run(w1, c1, 2)
    before, after = judged(w0, code0, tmp_path / "without" / "home"), judged(w1, code1, tmp_path / "with" / "home")
    assert before[2:] == after[2:]   # no finding and no source line changes with the helper
    # M14.1c (ADR-0007 BY-5) changes the result and the exit code exactly there: after an answered ask, a loss, a
    # bound passed or an end of the helper is a hole of the result of its own kind (a late first round is not)
    added = [h for h in w1.holes if h["kind"] == host.PE_HOLE_KIND]
    assert len(added) == gaps and [h["kind"] for h in w0.holes] == [h["kind"] for h in w1.holes if h not in added]
    alarm = before[1][0] == "alarm"   # a finding stays the result (exit 1); else the hole makes it incomplete (exit 3)
    assert before[:2] == after[:2] if not gaps else (after[0], after[1][0]) == ((1, "alarm") if alarm else (
        3, "incomplete"))
    assert not gaps or "%d hole(s) of the watch" % gaps in "; ".join(after[1][1])


def section(text):
    lines = text.splitlines()
    at = lines.index(next(x for x in lines if x.startswith(host.PE_SECTION)))
    out = [lines[at]]
    for x in lines[at + 1:]:
        if not x.startswith("  "):
            break
        out.append(x)
    return lines, at, out


def test_e4_e6_the_section_follows_the_channel_lines_place_and_says_what_was_heard_between_two_asks(tmp_path):
    w, clock = watch(tmp_path, feed(["linux", "linux", "linux"], [pe(5, 3, 1), pe(4, 4), pe(0)]))
    text, code = run(w, clock, 3)
    lines, at, got = section(text)
    assert got == ["PROCESS EVENTS (Linux): the kernel's process events, read by a helper process of the watch's own;"
                   " " + host.PE_JUDGED,   # M14.1c (E6): what is judged from them and what is not
                   "  rounds asked: 3, answered: 3",
                   "  processes that began: 9; of them began and ended between two asks: 7",
                   "  programs not read: 1 (reads at an exec that failed)",
                   "  given to the rounds: 0; joined to a tree as its child: 0; of them with no program read (no"
                   " line): 0",
                   "  past the reader's bounds: 0",
                   "  lost: none"]
    assert lines[at - 1].startswith("  round 3") and lines[at + len(got)].startswith("TREES SEEN:")
    flat_ = " ".join(text.split())
    assert host.BETWEEN_HEARD in flat_ and host.BETWEEN_LINUX not in flat_   # healthy for the whole watch
    assert "BLIND SPOT" not in w.out.getvalue() and not [b for b in w.blind if b["kind"].startswith("process")]


def test_e4_a_round_before_the_helper_was_ready_is_no_ask_and_no_hole(tmp_path):
    starting = pe(asked=False, answered=False)
    w, clock = watch(tmp_path, feed(["linux"] * 3, [starting, pe(2), pe(1)]))
    text, _ = run(w, clock, 3)
    assert "  rounds asked: 2, answered: 2; before the helper was ready: 1" in text
    assert host.BETWEEN_HEARD in " ".join(text.split())


def test_e4_without_a_helper_the_section_is_absent_and_the_old_words_stand(tmp_path):
    w, clock = watch(tmp_path, feed(["linux", "linux"]))
    text, _ = run(w, clock, 2)
    assert "PROCESS EVENTS" not in text and host.BETWEEN_HOLE % host.BETWEEN_LINUX in " ".join(text.split())
    w, clock = watch(tmp_path / "win", feed(["windows"], [pe(1)]), platform="win32")
    assert host.BETWEEN_HEARD not in run(w, clock, 1)[0]


@pytest.mark.parametrize("events,reason", [
    ([pe(2), pe(hole=host.PE_LATE % 2.0), pe(1)], "1 of 3 ask(s) not answered in their round"),
    ([pe(2), pe(hole=host.PE_NOT_A_LINE), pe(1)], "round 2: not a line"),
    ([pe(2), pe(1, lost=2), pe(1, lost=2)], "the reader lost events: ENOBUFS 2 time(s)"),
    ([pe(2), pe(1, beyond=7), pe(1, beyond=7)], "the reader passed its bounds: 7 event(s) or record(s) beyond them"),
    ([pe(2), pe(1), pe(1, more=True)], "the last answer left more for a next one"),
    ([pe(2), pe(1, hole=host.PE_ENDED % "its output ended", restarts=1, answered=True), pe(1, restarts=1)],
     "the helper was started again 1 time(s): nothing was heard between an end and the next start"),
    ([pe(hole="refused: why", refused="why")] * 3, "round 1: refused: why"),
    ([pe(hole=host.PE_ENDED % "its output ended", restarts=1), pe(1, restarts=1),
      pe(hole=host.PE_FINAL % "its output ended", restarts=1)], "round 3: ended for good")])
def test_e3_where_the_reader_was_not_healthy_the_old_words_stand_with_the_reason_beside(tmp_path, events, reason):
    w, clock = watch(tmp_path, feed(["linux"] * 3, events))
    text, _ = run(w, clock, 3)
    flat_ = " ".join(text.split())
    if any(e["answered"] for e in events):   # M14.1c REDO (BZ-2): after an answered ask, what was heard and judged
        note = next(x for x in w.notes if x.startswith(host.BETWEEN_HEARD))
        assert note.startswith(host.BETWEEN_HEARD + "; the reader was not whole for the whole watch: ")
        assert reason in note and host.BETWEEN_LINUX not in flat_
        return
    note = next(x for x in w.notes if x.startswith(host.BETWEEN_HOLE % host.BETWEEN_LINUX))
    assert note.startswith(host.BETWEEN_HOLE % host.BETWEEN_LINUX + "; the process events are not counted for the"
                           " whole watch: ") and reason in note and host.BETWEEN_HEARD not in flat_


def test_e2_a_restart_adds_its_own_line_and_a_loss_before_it_is_never_said_as_none(tmp_path, monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([answer([rec(1)], lost=1, events=4), procevents.ENDED]), StandIn([answer([rec(2)])] * 3))
    w, clock = watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=make))
    text, _ = run(w, clock, 4)
    _, _, got = section(text)
    assert "  lost: helper 1: ENOBUFS 1 time(s)" in got and "  lost: none" not in got
    assert ("  started again, round 2: ended: the helper of the process events ended (its output ended); it is started"
            " again, once; nothing was heard between the end of the helper before and this start") in got
    report = text.replace("TREES SEEN:", "TREES SEEN:", 1)
    ((_, state, words),) = check.read_watch_events(report, "WORKLOAD 1 start curl\n", "linux")
    assert state == check.MISSED and "started again" in words and "lost" in words


def test_e6_each_hole_is_a_blind_spot_of_its_own_kind_said_once_while_it_lasts_and_at_most_10_lines(tmp_path):
    late, bad = pe(hole=host.PE_LATE % 2.0), pe(hole=host.PE_NOT_A_LINE)
    w, clock = watch(tmp_path, feed(["linux"] * 6, [late, late, pe(1), late, bad, pe(1)]))
    text, code = run(w, clock, 6)
    said = [x for x in w.out.getvalue().splitlines() if "BLIND SPOT" in x or "HOLE round" in x]
    assert len(said) == 3 and "round 1: the process events: late" in said[0] and "round 4" in said[1]
    # M14.1c (ADR-0007 BY-5): before the first answered ask a blind spot as before; after it a hole of the result
    kinds = {b["kind"]: b["rounds"] for b in w.blind if b["kind"].startswith("process events")}
    assert kinds == {"process events late": [1, 2]} and "BLIND SPOT" in said[0] and "HOLE round 5" in said[2]
    assert [h["round"] for h in w.holes if h["kind"] == host.PE_HOLE_KIND] == [4, 5]
    assert all(b["class"] == host.BLIND for b in w.blind) and code == 3
    assert "  hole, round 1: late: the helper's answer did not come within 2 s" in text
    assert "  hole, round 4: late" in text and "  rounds asked: 6, answered: 2" in text
    many = [late if n % 2 else pe(1) for n in range(30)]
    w, clock = watch(tmp_path / "many", feed(["linux"] * 30, many))
    text, _ = run(w, clock, 30)
    said = [x for x in w.out.getvalue().splitlines() if "HOLE round" in x]
    assert host.PE_EPISODES_MAX == 10 and len(said) == 11 and "more than 10 episodes" in said[-1]
    _, _, got = section(text)
    assert len([x for x in got if x.startswith("  hole, ")]) == 10 and "  and 5 more episode(s) of the helper, not" \
                                                                         " printed" in got


def test_e4_bu4_a_programs_path_through_the_real_client_reaches_no_output_no_event_and_no_file(tmp_path,
                                                                                             monkeypatch):
    fake_round(monkeypatch, [])
    evil = [rec(11, exe=EVIL, ended=E, unread={"exe": EVIL}, earlier=[{"exe": EVIL, "unread": {}}]),
            rec(12, exe=None, unread={"exe": "ENOENT " + EVIL})]
    make = fake_client(script=[answer(evil, missed=1, ask=n) for n in (1, 2, 3)])
    w, clock = watch(tmp_path, host.live_reader(CATALOG, 0.0, "linux", helper=make))
    text, code = run(w, clock, 3)
    assert make.procs[0].closed                               # the watch's stop stopped its reader's helper
    assert "processes that began: 2" in text                  # read through Helper._parse, and counted
    home = tmp_path / "home"
    every = [text, w.out.getvalue(), w.err.getvalue()] + list(files(home).values())
    assert len(every) > 4 and not [x for x in every if MARK in x]


# --- E8: the helper is the watch's own -----------------------------------------------------------------------------
def test_e8_the_helper_goes_into_the_watchs_record_by_the_image_a_sample_reads(monkeypatch):
    import subprocess
    record = own.Record()
    monkeypatch.setattr(own, "RECORD", record)
    made = []
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: made.append(FakeProc(argv, **kw)) or made[-1])
    helper = host.procevents_helper()
    assert helper.start() is None and made[0].kw["cwd"] == "/"
    real = os.path.basename(os.path.realpath(sys.executable)).lower()
    assert {pid: image for pid, (_, image) in record.kept().items()} == {4242: real}
    helper.stop()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a /proc sample")
def test_e8_a_real_rounds_sample_holds_the_helper_as_the_watchs_own(monkeypatch):
    made = []

    def make():
        made.append(host.procevents_helper())
        return made[-1]
    monkeypatch.setattr(discover, "read_conn_bytes", lambda paths: ({}, "fake ss", None))
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    try:
        inv = reader()
        if inv["procevents"].get("refused"):
            pytest.skip("the kernel refused here")
        pid = made[0].proc.pid
        sampled = [p.get("pid") for p in inv.get("processes") or ()]
        trees = [t.get("pid") for g in ("candidates", "act_roots") for t in inv.get(g) or ()]
        assert pid in sampled and pid in own.RECORD.kept() and pid not in trees, (pid, trees)
        # BH-3: a process under the reader's pid that is not in the record is said "did not start" (a hole)
        assert not [h for h in inv.get("holes") or () if "did not start" in str(h)]
    finally:
        reader.close("the test ended")


# --- E6: the documents ---------------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e6_the_documents_say_what_the_helper_reads_loads_and_bounds_and_what_is_judged_from_it():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in (
            "`python -m raqib.procevents --serve` starts a Reader, then says `{\"ready\": null, \"v\": 1}`",
            "Every line it writes carries `\"v\": 1`, the protocol's version.",
            "packed until the line would pass 1 MiB (LINE_MAX, its newline included) and at most 2000 entries in all"
            " (SERVE_MAX)",
            "it stops the Reader and exits 0",
            "its Reader reads the kernel's socket and, at each exec, that process's /proc/PID/exe and /proc/PID/stat."
            " It opens no other file, writes only its standard output and starts no program.",
            "So it loads Raqib from where the watch loaded it and from nowhere else, and needs nothing of the user's"
            " environment or site folder.",   # M14.1c (BY-6): always -I
            "At most one ask is unanswered: while one is, `ask` writes nothing and waits for that answer",
            "`ask` says `starting` for 5 s after the start (STARTING_SECONDS), then `late`",
            "waits at most 2 s and at most a quarter of the watch's interval",
            "they began and ended between two asks",
            "summed over every helper the watch had",
            "under the watch the reader runs in a process of its own, never as a thread of the watch",
            "158 to 202 programs of 200 not read"):
        assert sentence in spec, sentence
    for gone in ("reads nothing but its input", "never waits past its timeout"):
        assert gone not in spec, gone
    guide = flat("docs/GUIDE.md")
    for sentence in ("PROCESS EVENTS (Linux):", "a process that began between two samples under a tree that talks at a"
                     " sample is that tree's child",   # M14.1c (BY-2): no longer "Nothing is judged from it yet"
                     "No program's name or path is shown",
                     "began and ended between two asks", "at most 10 such episodes are printed, then how many more",
                     "nothing was heard between its end and the new start"):
        assert sentence in guide, sentence
    threat = flat("docs/THREAT_MODEL.md")
    for sentence in ("a second process of Raqib's", "it ends when its input ends",
                     "A program's path, text a process chose, reaches a tree's programs only through the gate a"
                     " sampled child's name goes through",   # M14.1c (BY-4); its REDO (BZ-11): "programs", not "line"
                     "it opens no other file, writes only its output and starts no program",
                     "so it loads Raqib from where the watch did and from nowhere else",
                     "costs the watch a hole, never its round or its Stop",
                     "shows the helper's program with \" (deleted)\" after it"):   # M14.1c (BY-6)
        assert sentence in threat, sentence
    assert "opens no file and starts no program" not in threat
    service = flat("docs/specs/SERVICE.md")
    assert "the unit's watch starts the helper of the process events" in service
    assert "No run of the rig reads the unit's own watch yet" in service
    assert "the rig's service run says whether the unit's watch heard" not in service
    source = (ROOT / "raqib" / "procevents.py").read_text(encoding="utf-8")
    assert "reads nothing but its input" not in source and "never waits past its timeout" not in source
    assert host.PE_EPISODES_MAX == 10


def test_e7_ascii_outside_docs():
    for path in ("raqib/host.py", "raqib/procevents.py", "tests/test_host_procevents.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path


# --- M17.2b E4 (ADR-0007 CI-3): the entry's put-back that failed, said once by the watch as a hole of its own ------
LIBRARY_WORDS = "what the watch starts searches the packed program's folder first for its libraries"


@pytest.mark.parametrize("platform,kind", [("win32", "windows"), ("linux", "linux")])
def test_ci3_a_failed_put_back_is_said_once_as_a_hole_of_the_watchs_own_never_fatal(platform, kind, tmp_path,
                                                                                    monkeypatch):
    monkeypatch.setattr(own, "LIBRARY_FOLDER", "SetDllDirectoryW(NULL) returned 0")
    w, clock = watch(tmp_path, feed([kind] * 3), platform=platform)
    text, code = run(w, clock, 3)
    holes = [h for h in w.holes if h["kind"] == "own-library-folder"]
    assert len(holes) == 1 and holes[0]["detail"] == own.library_folder_hole() and holes[0]["round"] is None
    assert holes[0]["detail"].startswith(LIBRARY_WORDS) and "SetDllDirectoryW(NULL) returned 0" in holes[0]["detail"]
    assert " ".join(text.split()).count(LIBRARY_WORDS) == 1 and code is not None   # the watch ran its rounds


@pytest.mark.parametrize("result", [None, True])
def test_ci3_not_called_or_put_back_the_watch_says_nothing_of_it(result, tmp_path, monkeypatch):
    monkeypatch.setattr(own, "LIBRARY_FOLDER", None)
    w0, clock0 = watch(tmp_path / "before", feed(["windows"] * 2), platform="win32")
    text0, code0 = run(w0, clock0, 2)
    monkeypatch.setattr(own, "LIBRARY_FOLDER", result)
    w, clock = watch(tmp_path / "now", feed(["windows"] * 2), platform="win32")
    text, code = run(w, clock, 2)
    assert LIBRARY_WORDS not in text and [h["kind"] for h in w.holes] == [h["kind"] for h in w0.holes]
    assert code == code0
