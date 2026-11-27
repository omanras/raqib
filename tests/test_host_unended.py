"""M12.4b (ADR-0013 Amendment H, AH-1): a host watch that starts over a state another watch left unfinished says so
once, at its start, as a hole of its own run; host.holder() is the one reading of whether another watch holds a
home, the watch's own refusal (D-6) and the Windows service's wait (AH-2) both rest on it.

Every watch here is given its own clocks (the monotonic one and the wall one); every state is a made-up file under
the test's temp folder. No process is ended, stopped or signalled: "ended without its end" is a watch whose
finish() was never called."""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "host"))

from raqib import discover, host  # noqa: E402
from raqib.rules import engine  # noqa: E402

from test_watch import FakeRunner, make_notifier  # noqa: E402

import make as host_fixtures  # noqa: E402

CATALOG = discover.load_catalog(discover.CATALOG)
RULES = engine.load_catalog(ROOT / "raqib" / "rules" / "catalog")
BASE = 1793700000.0          # the wall clock of the first watch at its start
BEAT = "2026-11-03T12:00:00.000Z"
BEAT_AT = 1793707200.0       # BEAT in seconds of the wall clock
WORDS = "ended without its end"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    path = tmp_path / "user"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def watch(tmp_path, wall0=BASE, platform="linux"):
    """A host watch of this home with its own clocks: the wall clock reads wall0 at its start."""
    clock = Clock()
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    names = iter(["linux"] * 10)
    w = host.HostWatch(lambda: host_fixtures.inventory(next(names), CATALOG), CATALOG, RULES, notifier, every=10,
                       out=io.StringIO(), err=io.StringIO(), clock=clock, wall=lambda: wall0 + clock.t - 1000.0,
                       home=str(tmp_path / "home"), platform=platform)
    return w, clock


def rounds(w, clock, n):
    for _ in range(n):
        w.tick(wait=30)
        clock.t += w.every


def unended(w):
    return [h for h in w.holes if h["kind"] == host.UNENDED]


def events(w):
    return [json.loads(x) for x in Path(w.events_path).read_text(encoding="ascii").splitlines() if x.strip()]


def state_file(tmp_path, **fields):
    path = tmp_path / "home" / ".raqib" / "host" / "rounds.jsonl.watch.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {"raqib_watch": 1, "mode": "host", "run": "20261103T120000Z-4242", "pid": 4242, "heartbeat": BEAT,
             "stale_after_seconds": 30, "finished": None}
    state.update(fields)
    path.write_text(json.dumps(state), encoding="ascii")
    return path


# --- E1: one reading of whether another watch holds a home ---------------------------------------------------------

def test_e1_holder_nothing_held_no_state_a_finished_state_a_state_of_no_host_watch_and_one_that_cannot_be_read(
        tmp_path):
    got = host.holder(home=str(tmp_path / "home"), wall=lambda: BEAT_AT)
    assert got["held"] == host.HELD_NONE and got["why"] == "no state" and got["run"] is None
    assert got["path"] == str(tmp_path / "home" / ".raqib" / "host" / "rounds.jsonl.watch.json")
    path = state_file(tmp_path, finished="2026-11-03T12:00:01.000Z")
    got = host.holder(path=str(path), wall=lambda: BEAT_AT + 1)
    assert got["held"] == host.HELD_NONE and got["why"] == "the state is finished" and got["run"] == "20261103T120000Z-4242"
    for other in ({"mode": "project"}, {"mode": None}):
        state_file(tmp_path, **other)
        assert host.holder(home=str(tmp_path / "home"), wall=lambda: BEAT_AT)["why"] == "the state is no host watch's"
    path.write_text("[1, 2]", encoding="ascii")
    assert host.holder(path=str(path), wall=lambda: BEAT_AT)["held"] == host.HELD_NONE
    path.write_text('{"mode": "host", "heartbeat": ', encoding="ascii")   # torn
    got = host.holder(path=str(path), wall=lambda: BEAT_AT)
    assert got["held"] == host.HELD_NONE and got["why"].startswith("the state cannot be read")


def test_e1_holder_fresh_stale_and_unparsed_with_what_it_read(tmp_path):
    path = str(state_file(tmp_path))
    got = host.holder(path=path, wall=lambda: BEAT_AT + 3.5)
    assert got["held"] == host.HELD_FRESH and (got["run"], got["pid"], got["heartbeat"]) == (
        "20261103T120000Z-4242", 4242, BEAT)
    assert got["beat"] == BEAT_AT and got["age"] == 3.5 and got["stale"] == 30
    assert host.holder(path=path, wall=lambda: BEAT_AT + 30)["held"] == host.HELD_FRESH    # at its staleness: fresh
    got = host.holder(path=path, wall=lambda: BEAT_AT + 30.5)
    assert got["held"] == host.HELD_STALE and got["age"] == 30.5 and got["pid"] == 4242
    state_file(tmp_path, stale_after_seconds=5)                       # the state's own staleness
    assert host.holder(path=path, wall=lambda: BEAT_AT + 6)["held"] == host.HELD_STALE
    for odd in (True, "30", None):                                    # no number: STALE_SECONDS
        state_file(tmp_path, stale_after_seconds=odd)
        got = host.holder(path=path, wall=lambda: BEAT_AT + 6)
        assert got["held"] == host.HELD_FRESH and got["stale"] == host.STALE_SECONDS == 30
    for beat in ("not a time", None, 12):
        state_file(tmp_path, heartbeat=beat)
        got = host.holder(path=path, wall=lambda: BEAT_AT)
        assert got["held"] == host.HELD_UNPARSED and got["heartbeat"] == beat and got["age"] is None


def test_e1_the_watch_refuses_exactly_where_holder_says_fresh_or_unparsed(tmp_path):
    state_file(tmp_path)
    with pytest.raises(host.HostError) as got:
        watch(tmp_path, wall0=BEAT_AT + 3)
    assert str(got.value).startswith("another raqib watch --host is watching this home (run 20261103T120000Z-4242,"
                                     " pid 4242, heartbeat 3 s ago): one host watch per home; stop it first (")
    state_file(tmp_path, heartbeat="garbled")
    with pytest.raises(host.HostError, match="holds a heartbeat that cannot be parsed \\(garbled\\) and is not"):
        watch(tmp_path, wall0=BEAT_AT + 3600)


# --- E2: the hole of a watch started over an unfinished, stale state ----------------------------------------------

def test_e2_a_watch_over_a_state_left_unfinished_says_one_hole_of_its_own_with_the_run_pid_beat_and_seconds(tmp_path):
    w1, c1 = watch(tmp_path)
    rounds(w1, c1, 2)                               # its last heartbeat: BASE + 10 (the second round's tick)
    first = w1.run
    beat = json.loads(Path(w1.state_path).read_text(encoding="ascii"))["heartbeat"]
    assert unended(w1) == []                        # no state before it: none
    w2, c2 = watch(tmp_path, wall0=BASE + 10 + 125.75)   # w1 ended without its end; 125.75 s later, this start
    (hole,) = unended(w2)
    assert hole["detail"] == (
        "the host watch before this one, run %s (pid %s), ended without its end: its state %s was left unfinished,"
        " its last heartbeat %s; nothing was watched from this home for 125 s, from that heartbeat to this start (a"
        " watch ended from outside, a crash or a power loss)" % (first, w1.state(c1())["pid"], w2.state_path, beat))
    assert hole["at"] == w2.at(w2.t0) and hole["round"] is None and hole["notice"] is None   # at the start, no knock
    rounds(w2, c2, 2)
    text, code = w2.finish()
    assert code == 3 and len(unended(w2)) == 1      # a hole of the result, said once
    result, reasons = w2.result()
    assert result == "incomplete" and "1 hole(s) of the watch" in reasons
    assert "%s: %s" % (host.UNENDED, hole["detail"]) in " ".join(text.split())
    said = [e for e in events(w2) if e["kind"] == "hole" and e["hole"]["kind"] == host.UNENDED]
    assert len(said) == 1 and said[0]["watch"]["run"] == w2.run and said[0]["hole"]["class"] == "hole"
    assert said[0]["summary"] == "%s: %s" % (host.UNENDED, hole["detail"]) and first in said[0]["summary"]
    assert said[0]["alarm"] is True and said[0]["severity"] == "hole" and said[0]["about"].startswith("hole:")
    w3, c3 = watch(tmp_path, wall0=BASE + 1000)     # after a clean end: none
    assert unended(w3) == []
    rounds(w3, c3, 1)
    assert w3.finish()[1] == 0
    assert [e["watch"]["run"] for e in events(w3) if e["kind"] == "hole" and e["hole"]["kind"] == host.UNENDED] == [
        w2.run]                                     # the one of w2 alone, never one of w3


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_e2_the_hole_on_every_system_and_none_without_a_state_or_over_a_finished_one(tmp_path, platform):
    w, _ = watch(tmp_path, platform=platform)
    assert unended(w) == []
    state_file(tmp_path, finished="2026-11-03T12:00:01.000Z")
    w, _ = watch(tmp_path, wall0=BEAT_AT + 3600, platform=platform)
    assert unended(w) == []
    state_file(tmp_path, stale_after_seconds=5)
    w, _ = watch(tmp_path, wall0=BEAT_AT + 6.9, platform=platform)
    (hole,) = unended(w)
    assert "run 20261103T120000Z-4242 (pid 4242)" in hole["detail"] and "heartbeat %s;" % BEAT in hole["detail"]
    assert "for 6 s, from that heartbeat to this start" in hole["detail"]


def test_e2_none_where_this_run_is_refused_and_the_state_is_left_as_it_was(tmp_path):
    path = state_file(tmp_path)
    before = path.read_bytes()
    for wall0, beat in ((BEAT_AT + 30, BEAT), (BEAT_AT + 3600, "garbled")):
        state_file(tmp_path, heartbeat=beat)
        before = path.read_bytes()
        with pytest.raises(host.HostError):
            watch(tmp_path, wall0=wall0)
        assert path.read_bytes() == before
        assert not (tmp_path / "home" / ".raqib" / "host" / "events.jsonl").exists()


def test_e2_ascii():
    for path in ("raqib/host.py", "tests/test_host_unended.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path
