"""M7.21b (ADR-0007 Amendment BO): a live Windows watch takes each connection's bytes from the kernel's tracing
(raqib/etwnet.py) through the door Linux's counts use (conn_bytes). Every reader here is a fake made by the watch's
factory: no test touches the real system, the real atexit registry or a real session."""
import copy
import io
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))

from raqib import discover, etwnet, host, hostwin, watch  # noqa: E402
from raqib.rules import engine  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401
from test_watch import FakeRunner, make_notifier  # noqa: E402
import make as host_fixtures  # noqa: E402
import test_etwnet as te  # noqa: E402
import test_hostwin as th  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
NO_SYSMON = lambda: (False, "test: no Sysmon channel")   # noqa: E731
PID, REMOTE = 4400, "192.0.2.10:443"
LEFT = "raqib-net-999999"


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    monkeypatch.setattr(host, "tracing_live_pids", lambda: ({os.getpid()}, None))   # never the real snapshot
    return path


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def counts(conns=(), events=None, lost=(0, 0, 0), beyond=0, ended=None, since="2026-11-13T10:00:00.000000Z"):
    """counts() as etwnet.Reader gives it; conns: [(pid, raddr, rport, sent, received)]."""
    c = {(p, "192.0.2.99", 50000 + i, ra, rp): {"sent": s, "received": r, "last": since}
         for i, (p, ra, rp, s, r) in enumerate(conns)}
    return {"session": "raqib-net-%d" % os.getpid(), "since": since, "connections": c,
            "events": len(c) if events is None else events, "unread": 0, "unread_why": {}, "other": 0,
            "other_ids": {}, "beyond": beyond, "lost": {"events": lost[0], "buffers": lost[1], "notices": lost[2],
                                                        "why": None},
            "ended": ended, "refused": None, "said": []}


class FakeTracing:
    """etwnet.Reader's face: start, counts (one scripted value a round), stop. Its _api is test_etwnet's fake
    system, holding a killed watch's session, for the leftovers the watch stops first."""

    def __init__(self, log, script=(), refuse=None):
        self.log, self.script, self.refuse = log, list(script), refuse
        self._api = te.FakeEtw(others=te.OTHERS + (LEFT,))
        self.log.append(("made", os.getpid()))

    def start(self):
        self.log.append(("start", sorted(n for n in self._api.sessions if n.startswith("raqib-net-"))))
        return self.refuse

    def counts(self):
        self.log.append("counts")
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]

    def stop(self):
        self.log.append("stop")
        return []


def win_rounds(n, **kw):
    out = []
    for k in range(1, n + 1):
        inv = copy.deepcopy(host_fixtures.rhythm_inventory("cycle", k, **kw))
        inv.pop("conn_bytes", None)
        inv["live"] = True
        out.append(inv)
    return out


def live(invs):
    """A stand-in for live_reader on Windows: it says on the thread that it read a live Windows round."""
    feed = iter(invs)

    def read():
        host.LIVE_ROUND.win32 = True
        return next(feed)
    return read


def make(home, invs, script=(), refuse=None, platform="win32", reader=None):
    log = []
    clock = Clock()
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    w = host.HostWatch(reader or live(invs), CATALOG, RULES, notifier, every=10, out=io.StringIO(), err=io.StringIO(),
                       clock=clock, wall=lambda: host_fixtures.WALL0 + clock.t, home=str(home), platform=platform,
                       sysmon=NO_SYSMON, tracing=lambda: FakeTracing(log, script, refuse))
    return w, clock, log


def run(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def conns_of(w):
    (key,) = list(w.trees)
    import json
    lines = [json.loads(x) for x in Path(w._source_path(key)).read_text(encoding="ascii").splitlines()]
    return [(l["input_meta"]["round"], l["input_meta"]["change"]) for l in lines if l["tool"] == "HostConnection"]


def bytes_blind(w):
    return [b for b in w.blind if b["kind"] == "bytes"]


# --- E1 (BO-1): the same door as Linux ------------------------------------------------------------------------

def test_e1_sums_a_pid_and_a_remote_spelled_as_discover_spells_a_talk():
    got = etwnet.sums({(7, "192.0.2.10", 1, "198.51.100.7", 443): {"sent": 5, "received": 6, "last": ""},
                       (7, "192.0.2.10", 2, "198.51.100.7", 443): {"sent": 1, "received": 2, "last": ""},
                       (7, "2001:db8::10", 3, "2001:db8::7", 443): {"sent": 3, "received": 4, "last": ""}})
    assert got == {(7, "198.51.100.7:443"): {"sent": 6, "received": 8, "sockets": 2},
                   (7, "2001:db8::7:443"): {"sent": 3, "received": 4, "sockets": 1}}


def test_e1_remote_is_named_as_the_tcp_tables_talks_name_it_v4_and_v6():
    api = th.Samples(th.KIMI1, 1)
    api.tcp.append((5, "2001:db8::10", 50433, "2001:db8::7", 443, 6636))
    texts, holes, _ = hostwin.collect(api, 1, 10, th.SELF, [].append, now=lambda: th.AT, clock=lambda: 0.0)
    inv = discover.run(texts, CATALOG, holes=holes, live=True, processes=True)
    talks = {"%s %s" % (t["pid"], x["remote"]) for t in inv["candidates"] for x in t["talks"]}
    assert {"6636 198.51.100.23:443", "6636 2001:db8::7:443"} <= talks
    c = counts([(6636, "198.51.100.23", 443, 10, 20), (6636, "2001:db8::7", 443, 30, 40)])
    cb = host.tracing_bytes({}, c, inv)
    assert set(cb) == {"from", "hole", "by"} and cb["hole"] is None and set(cb["by"]) == talks
    assert cb["by"]["6636 198.51.100.23:443"] == {"bytes_sent": 10, "bytes_received": 20, "sockets": 1}
    assert cb["by"]["6636 2001:db8::7:443"] == {"bytes_sent": 30, "bytes_received": 40, "sockets": 1}


def test_e1_a_kept_connection_whose_counts_moved_is_a_talk_of_change_bytes(home):
    script = [counts([(PID, "192.0.2.10", 443, 100 * k, 500 * k)]) for k in (1, 2, 3)]
    w, clock, log = make(home, win_rounds(3), script)
    run(w, clock, 3)
    cb = w.last_inventory["conn_bytes"]
    assert set(cb) == {"from", "hole", "by"} and cb["hole"] is None and "raqib-net-" in cb["from"]
    assert cb["by"]["%d %s" % (PID, REMOTE)] == {"bytes_sent": 300, "bytes_received": 1500, "sockets": 1}
    assert conns_of(w) == [(1, "new"), (2, "bytes"), (3, "bytes")] and bytes_blind(w) == []


# --- E2 (BO-2): one reader a watch, stopped on every way out ----------------------------------------------------

def test_e2_leftovers_first_then_one_start_and_the_normal_end_stops_it(home):
    w, clock, log = make(home, win_rounds(3), [counts()])
    run(w, clock, 3)
    assert log[:2] == [("made", os.getpid()), ("start", [])] and log.count(("made", os.getpid())) == 1
    w.finish()
    w.tracing_stop()
    assert log.count("stop") == 1 and log[-1] == "stop"


@pytest.mark.parametrize("way", ["stop", "crash", "interrupt"])
def test_e2_every_way_out_of_a_watch_stops_the_reader(home, monkeypatch, way):
    log, started = [], threading.Event()

    class Started(FakeTracing):
        def start(self):
            got = FakeTracing.start(self)
            started.set()
            return got

    monkeypatch.setattr(host, "_sleep", lambda s: None)
    running = host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, port=0, out=io.StringIO(),
                         err=io.StringIO(), environ={}, home=str(home), reader=live(win_rounds(3) * 50),
                         platform="win32", sysmon=NO_SYSMON, tracing=lambda: Started(log, [counts()]))
    stop = None
    if way == "stop":
        stop = watch.Stop()
        stop.set("the window's Stop")
    elif way == "crash":
        monkeypatch.setattr(running.watcher, "_bytes_note", lambda *a: 1 / 0)
    else:
        real, ticks = running.watcher.tick, []

        def tick(*a, **k):
            ticks.append(1)
            if len(ticks) > 1:
                assert started.wait(60)   # the interrupt comes once the first round's reader was started
                raise KeyboardInterrupt
            return real(*a, **k)
        monkeypatch.setattr(running.watcher, "tick", tick)
    try:
        crash = host.loop(running, stop)
        host.conclude(running, crash)
    finally:
        host.close(running)
    assert ("crash" == way) == (crash is not None)
    assert ("start", []) in log and log.count("stop") == 1


def test_e2_no_reader_on_linux_for_exports_or_for_a_look(home, monkeypatch):
    w, clock, log = make(home, win_rounds(2), [counts()], platform="linux")
    run(w, clock, 2)
    w2, clock2, log2 = make(home / "x", [dict(i, live=False) for i in win_rounds(2)], [counts()],
                            reader=lambda: dict(win_rounds(1)[0], live=False))
    run(w2, clock2, 2)
    assert log == [] and log2 == []
    (b,) = bytes_blind(w2)
    assert b["detail"] == "%s; %s%s" % (host.WIN_BYTES_HOLE, host.TRACING_NOT_LIVE, host.BLIND_TAIL)
    made = []
    monkeypatch.setattr(host, "tracing_reader", lambda: made.append(1))
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: ({}, [], None))
    inv = host.live_reader(CATALOG, platform="win32", sysmon=NO_SYSMON)()   # a single look, outside any watch
    assert made == [] and "conn_bytes" not in inv


def test_e2_the_default_factory_is_etwnets_reader_under_the_own_pid_and_never_windows_off_windows(home, monkeypatch):
    r = host.tracing_reader()
    assert isinstance(r, etwnet.Reader) and r.pid == os.getpid() and r.counts()["since"] is None
    asked = []
    monkeypatch.setattr(etwnet, "leftovers", lambda *a, **k: asked.append(1) or [])
    monkeypatch.setattr(sys, "platform", "linux")
    running = host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, port=0, out=io.StringIO(),
                         err=io.StringIO(), environ={}, home=str(home), reader=live(win_rounds(2)),
                         platform="win32", sysmon=NO_SYSMON)
    try:
        running.watcher.tick(wait=30)
    finally:
        host.close(running)
    (b,) = bytes_blind(running.watcher)
    assert b["detail"] == "%s; %s%s" % (host.WIN_BYTES_HOLE, host.TRACING_OFF % "linux", host.BLIND_TAIL)
    assert asked == []


# --- E3 (BO-3): a refused start is today's blind spot with the reason -------------------------------------------

def test_e3_a_refused_start_is_the_blind_spot_as_today_with_the_reason_once_and_the_result_unchanged(home):
    why = "the bytes are not read: no rights: a tracing session needs an administrator (StartTraceW returned 5)"
    w, clock, log = make(home, win_rounds(3), [counts()], refuse=why)
    run(w, clock, 3)
    (b,) = bytes_blind(w)
    assert b["detail"] == "%s; %s%s" % (host.WIN_BYTES_HOLE, why, host.BLIND_TAIL) and b["rounds"] == [1, 2, 3]
    assert log.count("counts") == 0 and sum(why in n for n in w.notes) == 0
    today, clock2, _ = make(home / "t", [], reader=lambda: dict(win_rounds(1)[0], live=False))
    today.reader = iter([dict(i, live=False) for i in win_rounds(3)]).__next__
    run(today, clock2, 3)
    assert w.result()[0] == today.result()[0] and w.finish()[1] == today.finish()[1]
    assert conns_of(w) == conns_of(today) == [(1, "new")]


# --- E4 (BO-4): a loss is not a quiet turn ---------------------------------------------------------------------

CAUSES = {"events": dict(lost=(2, 0, 0)), "buffers": dict(lost=(0, 1, 0)), "notices": dict(lost=(0, 0, 3)),
          "beyond": dict(beyond=4), "ended": dict(ended="consumer ended before the stop (ProcessTrace returned 0)")}
WORDS = {"events": "2 event(s) lost", "buffers": "1 real-time buffer(s) lost", "notices": "3 lost-event notice(s)",
         "beyond": "4 event(s) of connections beyond", "ended": "consumer ended before the stop"}


@pytest.mark.parametrize("cause", sorted(CAUSES))
def test_e4_a_round_after_a_loss_has_a_hole_no_counts_and_no_bytes_talk(home, cause):
    c = [(PID, "192.0.2.10", 443)]
    script = [counts([c[0] + (100, 500)]), counts([c[0] + (200, 900)], **CAUSES[cause]),
              counts([c[0] + (300, 1300)], **CAUSES[cause]), counts([c[0] + (400, 1700)], **CAUSES[cause])]
    w, clock, log = make(home, win_rounds(4), script)
    run(w, clock, 2)
    cb = w.last_inventory["conn_bytes"]
    assert cb["by"] is None and WORDS[cause] in cb["hole"]
    (b,) = bytes_blind(w)
    assert b["detail"].startswith("bytes: ") and WORDS[cause] in b["detail"] and b["rounds"] == [2]
    run(w, clock, 2)
    if cause == "ended":   # said once; the rounds after it are not read
        assert bytes_blind(w)[0]["rounds"] == [2, 3, 4] and conns_of(w) == [(1, "new")]
    else:   # round 3 compares with nothing older than it; round 4 with round 3
        assert bytes_blind(w)[0]["rounds"] == [2] and conns_of(w) == [(1, "new"), (4, "bytes")]


def test_e4_without_a_loss_round_three_would_have_been_a_bytes_talk(home):
    c = (PID, "192.0.2.10", 443)
    script = [counts([c + (100 * k, 400 * k)]) for k in (1, 2, 3, 4)]
    w, clock, log = make(home, win_rounds(4), script)
    run(w, clock, 4)
    assert conns_of(w) == [(1, "new"), (2, "bytes"), (3, "bytes"), (4, "bytes")]


# --- E5 (BO-5): a session that hears nothing -------------------------------------------------------------------

def test_e5_no_event_since_the_start_while_the_tables_connections_moved_is_the_readers_hole(home):
    invs = win_rounds(3)
    for inv in invs[1:]:
        inv["candidates"][0]["talks"].append(dict(inv["candidates"][0]["talks"][0],
                                                  remote="198.51.100.%d:443" % (9 + invs.index(inv))))
    w, clock, log = make(home, invs, [counts(events=0)])
    run(w, clock, 2)
    assert bytes_blind(w) == []   # BP-4: not in the session's first two rounds (what the kernel says comes late)
    run(w, clock, 1)
    cb = w.last_inventory["conn_bytes"]
    assert cb["by"] is None and "heard no event at all since its start" in cb["hole"] and "1 new, 1 closed" in cb["hole"]
    assert bytes_blind(w)[0]["rounds"] == [3] and cb["causes"] == ["deaf"]


def test_bp1_byte_events_the_reader_could_not_read_make_the_round_a_hole_not_a_zero(home):
    c = (PID, "192.0.2.10", 443)
    script = [counts([c + (100, 500)]), dict(counts([c + (100, 500)]), unread=2), dict(counts([c + (100, 500)]), unread=2)]
    w, clock, log = make(home, win_rounds(3), script)
    run(w, clock, 2)
    cb = w.last_inventory["conn_bytes"]
    assert cb["by"] is None and "2 tcp byte event(s) the reader could not read since the round before" in cb["hole"]
    run(w, clock, 1)   # no more of them: the round is read again
    assert w.last_inventory["conn_bytes"]["hole"] is None and bytes_blind(w)[0]["rounds"] == [2]


def test_bp3_each_kind_of_cause_is_said_once_though_the_blind_spot_keeps_its_first_words(home):
    c = (PID, "192.0.2.10", 443)
    script = [counts([c + (1, 1)]), counts([c + (2, 2)], lost=(3, 0, 0)), counts([c + (3, 3)], lost=(3, 0, 0), beyond=4),
              counts([c + (4, 4)], lost=(9, 0, 0), beyond=4), counts([c + (5, 5)], lost=(9, 0, 0), beyond=4)]
    w, clock, log = make(home, win_rounds(5), script)
    run(w, clock, 5)
    (b,) = bytes_blind(w)
    assert b["rounds"] == [2, 3, 4] and "event(s) lost by the session" in b["detail"] and "beyond" not in b["detail"]
    said = [n for n in w.notes if n.startswith("the tracing, round ")]
    assert len(said) == 2 and said[0].startswith("the tracing, round 2: ") and "lost by the session" in said[0]
    assert said[1].startswith("the tracing, round 3: ") and "beyond the reader's cap" in said[1]


def test_bp5_a_reader_that_raises_at_its_start_is_a_refusal_with_its_reason_never_a_failed_round(home):
    class Raising(FakeTracing):
        def start(self):
            raise OSError("no such thing")
    log = []
    w, clock, _ = make(home, win_rounds(2))
    w.tracing_factory = lambda: Raising(log)
    run(w, clock, 2)
    (b,) = bytes_blind(w)
    assert b["detail"].startswith(host.WIN_BYTES_HOLE + "; ") and "failed while starting (OSError: no such thing)" in \
        b["detail"] and b["rounds"] == [1, 2]
    assert not [h for h in w.holes if "reader" in str(h.get("kind", ""))]


def test_bp2_an_ipv4_remote_said_in_ipv6s_form_is_summed_under_its_ipv4_spelling():
    got = etwnet.sums({(7, "2001:db8::10", 1, "::ffff:198.51.100.7", 443): {"sent": 5, "received": 6, "last": ""},
                       (7, "192.0.2.10", 2, "198.51.100.7", 443): {"sent": 1, "received": 2, "last": ""},
                       (7, "2001:db8::10", 3, "2001:db8::7", 443): {"sent": 9, "received": 9, "last": ""}})
    assert got == {(7, "198.51.100.7:443"): {"sent": 6, "received": 8, "sockets": 2},
                   (7, "2001:db8::7:443"): {"sent": 9, "received": 9, "sockets": 1}}


def test_e5_a_quiet_machine_with_no_connection_change_says_nothing(home):
    w, clock, log = make(home, win_rounds(3), [counts(events=0)])
    run(w, clock, 3)
    assert bytes_blind(w) == [] and w.last_inventory["conn_bytes"]["hole"] is None
    assert w.last_inventory["conn_bytes"]["by"] == {"%d %s" % (PID, REMOTE): {"bytes_sent": 0, "bytes_received": 0,
                                                                              "sockets": 0}}


# --- E6 (BO-7): the leftovers are notes ------------------------------------------------------------------------

def test_e6_leftovers_stopped_are_a_note_by_name_and_a_problem_is_a_note_never_a_failure(home, monkeypatch):
    w, clock, log = make(home, win_rounds(2), [counts()])
    run(w, clock, 2)
    assert (host.TRACING_LEFTOVER % LEFT) in w.notes and log[1] == ("start", [])
    code = w.finish()[1]
    monkeypatch.setattr(host, "tracing_live_pids", lambda: (None, "the live pids were not read (fake)"))
    w2, clock2, _ = make(home / "y", win_rounds(2), [counts()])
    run(w2, clock2, 2)
    said = [n for n in w2.notes if n.startswith("the tracing's leftovers (not a failure): ")]
    assert said and not any(LEFT in n for n in w2.notes if n.startswith("the tracing: a session"))
    assert w2.finish()[1] == code and not any("leftover" in h["detail"] for h in w2.holes)


# --- E7 (BO-6): what the counts are, said ----------------------------------------------------------------------

@pytest.mark.parametrize("doc", ["THREAT_MODEL.md", "GUIDE.md"])
def test_e7_the_documents_say_what_the_windows_counts_are(doc):
    text = " ".join((ROOT / "docs" / doc).read_text(encoding="utf-8").split())
    for words in ("an administrator", "one tracing session named for the watch", "a killed watch leaves it until the"
                  " next start", "sums since the watch began", "UDP carries no counts"):
        assert words in text, (doc, words)
    assert "M7.21" not in (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
