"""M14.1b E3, E4, E6 (ADR-0007 Amendment BU-2 to BU-5): the watch asks the helper once a round and says, in one
section of its report, what was heard between two samples. Nothing is judged from it.

Every test here gives the live reader a stand-in Helper (live_reader(helper=)), or the watch an inventory that
carries inv["procevents"]; the real helper is tests/test_procevents_helper.py's."""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover, host, procevents  # noqa: E402
from raqib.rules import engine  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_watch import FakeRunner, make_notifier  # noqa: E402

sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))
import make as host_fixtures  # noqa: E402

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


def rec(pid, began="2026-11-20T00:00:01.000000Z", ended=None, exe="/usr/bin/true", **kw):
    return dict({"pid": pid, "ppid": 1, "exe": exe, "earlier": [], "started_ticks": 9, "began": began,
                 "ended": ended, "code": 0 if ended else None, "signal": None, "unread": {}}, **kw)


def counts(missed=0, lost=0, events=0, ended=None):
    return {"missed": {"exe": missed, "stat": 0}, "ended": ended, "refused": None,
            "lost": {"count": lost, "events": events, "why": "ENOBUFS %d time(s)" % lost if lost else None}}


def answer(processes=(), more=False, **kw):
    return {"processes": list(processes), "ends": [], "older": [], "more": more, "counts": counts(**kw), "ask": 1}


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

    def stop(self):
        self.stops += 1
        self.log.append("stop")
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


# --- E3: the live reader starts one helper, asks it after each sample ------------------------------------------
def test_e3_one_helper_started_at_the_first_round_before_its_sample_and_asked_after_each_sample(monkeypatch):
    log = []
    fake_round(monkeypatch, log)
    make = factory(StandIn([answer([rec(1, ended="E"), rec(2), rec(3, began=None)], missed=1),
                            answer([rec(1, ended="E"), rec(4, ended="F")], missed=3, more=True)], log=log))
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=make)
    one, two, three = rounds(reader, 3)
    assert len(make.made) == 1
    assert log == ["start", "sample", ("ask", 2.0), "sample", ("ask", 2.0), "sample", ("ask", 2.0)]
    assert one == {"began": 2, "inside": 1, "unread_exe": 1, "lost": {"count": 0, "events": 0, "why": None},
                   "refused": None, "hole": None, "more": False}
    assert (two["began"], two["inside"], two["unread_exe"], two["more"]) == (1, 1, 2, True)   # pid 1 given again
    assert (three["began"], three["unread_exe"], three["hole"]) == (0, 0, None)
    assert procevents.ASK_SECONDS == 2.0


def test_e3_a_late_answer_and_a_line_that_is_not_the_helpers_are_holes_of_their_own_and_the_next_round_asks(
        monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([procevents.LATE, procevents.NOT_A_LINE, answer([rec(5)])]))
    late, bad, good = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 3)
    assert late["hole"] == "late: the helper's answer did not come within 2 s" and late["began"] == 0
    assert bad["hole"] == "not a line: the helper's answer was not its line"
    assert good["hole"] is None and good["began"] == 1 and len(make.made) == 1


def test_e3_a_refusal_is_final_said_in_the_readers_words_and_the_helper_is_stopped(monkeypatch):
    fake_round(monkeypatch, [])
    words = procevents.PREFIX + "the ask to listen was not answered within 2 s"
    helper = StandIn([procevents.REFUSED], refused=words)
    make = factory(helper)
    one, two = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 2)
    assert one["refused"] == words and one["hole"] == "refused: " + words and two == one
    assert helper.stops == 1 and helper.log.count(("ask", 2.0)) == 1 and len(make.made) == 1


def test_e3_a_helper_that_ended_is_started_again_once_and_a_second_end_is_final(monkeypatch):
    fake_round(monkeypatch, [])
    first, second = StandIn([procevents.ENDED]), StandIn([answer([rec(8)]), procevents.ENDED])
    make = factory(first, second)
    got = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 4)
    assert got[0]["hole"] == "ended: the helper of the process events ended (its output ended); it is started again," \
                             " once" and first.stops == 1
    assert got[1]["hole"] is None and got[1]["began"] == 1
    assert got[2]["hole"].startswith("ended for good: the helper of the process events ended again (its output ended)")
    assert got[3] == got[2] and len(make.made) == 2 and second.stops == 1


def test_e3_a_reader_that_ended_inside_the_helper_is_an_end_too(monkeypatch):
    fake_round(monkeypatch, [])
    make = factory(StandIn([answer([rec(1)], ended="the receive failed (EBADF)")]))
    (one,) = rounds(host.live_reader(CATALOG, 0.0, "linux", helper=make), 1)
    assert one["began"] == 1 and one["hole"].startswith("ended: the helper of the process events ended (its reader"
                                                        " ended: the receive failed (EBADF))")
    assert len(make.made) == 2


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


def test_e3_the_helper_is_stopped_by_close_of_a_single_look_and_by_its_watch(monkeypatch):
    fake_round(monkeypatch, [])
    helper = StandIn()
    look = host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))
    look()
    assert look.close("the look ended") == [] and helper.stops == 1
    owner = host.HelperOwner()
    host.PROCEVENTS_OWNER.owner = owner
    try:
        helper = StandIn()
        host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))()
    finally:
        host.PROCEVENTS_OWNER.owner = None
    assert owner.close() == [] and helper.stops == 1
    late = factory(StandIn())   # a reader whose watch stopped already starts no helper at all
    host.PROCEVENTS_OWNER.owner = owner
    try:
        got = host.live_reader(CATALOG, 0.0, "linux", helper=late)()["procevents"]
    finally:
        host.PROCEVENTS_OWNER.owner = None
    assert late.made == [] and got["hole"] == host.PE_NOT_STARTED % "the watch stopped (Stop)"


# --- E3, E4: the watch ---------------------------------------------------------------------------------------------
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


def pe(began=0, inside=0, unread_exe=0, hole=None, lost=0, refused=None):
    return {"began": began, "inside": inside, "unread_exe": unread_exe, "refused": refused, "hole": hole,
            "lost": {"count": lost, "events": 3 * lost, "why": "ENOBUFS %d time(s)" % lost if lost else None},
            "more": False}


def files(home):
    return {p.relative_to(home).as_posix(): p.read_text(encoding="utf-8", errors="replace")
            for p in sorted(Path(home).rglob("*")) if p.is_file()}


def judged(w, code, home):
    lines = {k: [json.loads(x) for x in v.splitlines() if x.strip()] for k, v in files(home).items()
             if "/sources/" in "/" + k}
    return (code, w.result(), [(f["rule_id"], f.get("pid"), f.get("detail")) for f in w.findings],
            [(f["rule_id"], f.get("pid")) for f in w.source_findings], lines)


@pytest.mark.parametrize("names", [["linux", "linux"], ["benign/windows-desktop", "windows"]])
@pytest.mark.parametrize("events", [[pe(5, 3), pe(2, 2, 1)], [pe(hole=host.PE_LATE % 2.0), pe(lost=1)],
                                    [pe(hole="refused: " + procevents.PREFIX + "x", refused="x")] * 2])
def test_e3_no_finding_no_source_line_no_result_and_no_exit_code_changes_with_the_helper(tmp_path, names, events):
    w0, c0 = watch(tmp_path / "without", feed(names))
    _, code0 = run(w0, c0, 2)
    w1, c1 = watch(tmp_path / "with", feed(names, events))
    _, code1 = run(w1, c1, 2)
    assert judged(w0, code0, tmp_path / "without" / "home") == judged(w1, code1, tmp_path / "with" / "home")
    assert [h["kind"] for h in w0.holes] == [h["kind"] for h in w1.holes]


def test_e4_the_section_follows_the_channel_lines_place_and_says_what_was_heard(tmp_path):
    w, clock = watch(tmp_path, feed(["linux", "linux", "linux"], [pe(5, 3, 1), pe(4, 4), pe(0)]))
    text, code = run(w, clock, 3)
    lines = text.splitlines()
    at = lines.index(next(x for x in lines if x.startswith(host.PE_SECTION)))
    assert lines[at] == ("PROCESS EVENTS (Linux): the kernel's process events, read by a helper process of the watch's"
                         " own; not judged yet: no rule reads them, no line of a tree's source is written from them")
    assert lines[at + 1:at + 5] == ["  rounds asked: 3, answered: 3",
                                    "  processes that began: 9; of them began and ended between two samples: 7",
                                    "  programs not read: 1", "  lost: none"]
    assert lines[at - 1].startswith("  round 3") and lines[at + 5].startswith("TREES SEEN:")
    flat = " ".join(text.split())
    assert host.BETWEEN_HEARD in flat and host.BETWEEN_LINUX not in flat   # healthy for the whole watch
    assert "BLIND SPOT" not in w.out.getvalue() and not [b for b in w.blind if b["kind"].startswith("process")]


def test_e4_without_a_helper_the_section_is_absent_and_the_old_words_stand(tmp_path):
    w, clock = watch(tmp_path, feed(["linux", "linux"]))
    text, _ = run(w, clock, 2)
    assert "PROCESS EVENTS" not in text and host.BETWEEN_HOLE % host.BETWEEN_LINUX in " ".join(text.split())
    w, clock = watch(tmp_path / "win", feed(["windows"], [pe(1)]), platform="win32")
    assert host.BETWEEN_HEARD not in run(w, clock, 1)[0]


@pytest.mark.parametrize("events,reason", [
    ([pe(2), pe(hole=host.PE_LATE % 2.0), pe(1)], "round 2: late: the helper's answer did not come within 2 s"),
    ([pe(2), pe(1, lost=2), pe(1, lost=2)], "the reader lost events: ENOBUFS 2 time(s)"),
    ([pe(hole="refused: why", refused="why")] * 3, "round 1: refused: why"),
    ([pe(hole=host.PE_ENDED % "its output ended"), pe(1), pe(hole=host.PE_FINAL % "its output ended")],
     "round 1: ended: the helper of the process events ended (its output ended); it is started again, once; round 3:"
     " ended for good")])
def test_e4_where_the_reader_was_not_healthy_the_old_words_stand_with_the_reason_beside(tmp_path, events, reason):
    w, clock = watch(tmp_path, feed(["linux"] * 3, events))
    text, _ = run(w, clock, 3)
    flat = " ".join(text.split())
    note = next(x for x in w.notes if x.startswith(host.BETWEEN_HOLE % host.BETWEEN_LINUX))
    assert note.startswith(host.BETWEEN_HOLE % host.BETWEEN_LINUX + "; the process events are not counted for the"
                           " whole watch: ") and reason in note and host.BETWEEN_HEARD not in flat
    assert reason.split(";")[0] in flat


def test_e4_each_hole_is_a_blind_spot_of_its_own_kind_said_once_while_it_lasts(tmp_path):
    late = pe(hole=host.PE_LATE % 2.0)
    bad = pe(hole=host.PE_NOT_A_LINE)
    w, clock = watch(tmp_path, feed(["linux"] * 6, [late, late, pe(1), late, bad, pe(1)]))
    text, code = run(w, clock, 6)
    said = [x for x in w.out.getvalue().splitlines() if "BLIND SPOT" in x]
    assert len(said) == 3 and "round 1: the process events: late" in said[0] and "round 4" in said[1]
    kinds = {b["kind"]: b["rounds"] for b in w.blind if b["kind"].startswith("process events")}
    assert kinds == {"process events late": [1, 2, 4], "process events not a line": [5]}
    assert all(b["class"] == host.BLIND for b in w.blind) and code == 0
    assert "  hole, round 1: late: the helper's answer did not come within 2 s" in text
    assert "  hole, round 4: late" in text and "  rounds asked: 6, answered: 2" in text


def test_e4_bu4_a_programs_path_reaches_no_output_no_event_and_no_file(tmp_path, monkeypatch):
    fake_round(monkeypatch, [])
    evil = [rec(11, exe=EVIL, ended="E", unread={"exe": EVIL}, earlier=[{"exe": EVIL, "unread": {}}]),
            rec(12, exe=None, unread={"exe": "ENOENT " + EVIL})]
    helper = StandIn([answer(evil, missed=1)] * 3)
    reader = host.live_reader(CATALOG, 0.0, "linux", helper=factory(helper))
    w, clock = watch(tmp_path, reader)
    text, code = run(w, clock, 3)
    assert helper.stops == 1                                  # the watch's stop stopped its reader's helper
    assert "processes that began: 2" in text                  # it was read, and counted
    home = tmp_path / "home"
    every = [text, w.out.getvalue(), w.err.getvalue()] + list(files(home).values())
    assert len(every) > 4 and not [x for x in every if MARK in x]


# --- E6: the documents ---------------------------------------------------------------------------------------------
def flat(path):
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def test_e6_the_documents_say_the_helper_its_bounds_and_that_nothing_is_judged_from_it():
    spec = flat("docs/specs/PROC-EVENTS.md")
    for sentence in (
            "`python -m raqib.procevents --serve` starts a Reader, then says `{\"ready\": null}`",
            "at most 2000 entries in all (SERVE_MAX)",
            "it stops the Reader and exits 0",
            "answers carry the ask's number, so a late answer is never taken by the next ask",
            "It reads nothing but its input, writes nothing but its output and starts no program.",
            "under the watch the reader runs in a process of its own, never as a thread of the watch",
            "158 to 202 programs of 200 not read"):
        assert sentence in spec, sentence
    guide = flat("docs/GUIDE.md")
    for sentence in ("PROCESS EVENTS (Linux):", "Nothing is judged from it yet",
                     "No program's name or path is shown"):
        assert sentence in guide, sentence
    threat = flat("docs/THREAT_MODEL.md")
    for sentence in ("a second process of Raqib's", "it ends when its input ends",
                     "A program's path, text a process chose, reaches no output"):
        assert sentence in threat, sentence
    assert "the unit's watch starts the helper of the process events" in flat("docs/specs/SERVICE.md")


def test_e7_ascii_outside_docs():
    for path in ("raqib/host.py", "raqib/procevents.py", "tests/test_host_procevents.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path
