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
OLD_BEAT = "2020-01-01T00:00:00.000Z"   # a heartbeat stale by any real clock this test runs under


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


def watch(tmp_path, wall0=BASE, platform="linux", run=None):
    """A host watch of this home with its own clocks: the wall clock reads wall0 at its start (run: its id)."""
    clock = Clock()
    notifier = make_notifier(FakeRunner())
    notifier.host = True
    names = iter(["linux"] * 10)
    w = host.HostWatch(lambda: host_fixtures.inventory(next(names), CATALOG), CATALOG, RULES, notifier, every=10,
                       out=io.StringIO(), err=io.StringIO(), clock=clock, wall=lambda: wall0 + clock.t - 1000.0,
                       home=str(tmp_path / "home"), platform=platform, run=run)
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


def said_unended(w):
    return [e for e in events(w) if e["kind"] == "hole" and e["hole"]["kind"] == host.UNENDED]


def chain_whole(lines):
    """Every line of one run's chain holds the digest of the run's line before it (the first: FIRST)."""
    from raqib import event
    head = {}
    for raw in lines:
        e = json.loads(raw)
        run = e["watch"]["run"]
        assert e[event.PREV] == head.get(run, event.FIRST), raw
        head[run] = event.digest(raw.encode("ascii"))


def hole_words(run, pid, path, beat, when, gap):
    return ("the host watch before this one, run %s (pid %s), left its state %s unfinished with its heartbeat stale:"
            " its last heartbeat %s, %s; a watch that ended without its end (ended from outside, a crash or a power"
            " loss) or one that stopped writing its state: %s" % (run, pid, path, beat, when, gap))


# --- holder(): one reading of whether another watch holds a home (AH-1, AI-2, finding 2) ---------------------------

def test_holder_nothing_held_no_state_a_finished_state_and_a_state_of_no_host_watch(tmp_path):
    got = host.holder(home=str(tmp_path / "home"), wall=lambda: BEAT_AT)
    assert got["held"] == host.HELD_NONE and got["why"] == "no state" and got["run"] is None and got["error"] is None
    assert got["path"] == str(tmp_path / "home" / ".raqib" / "host" / "rounds.jsonl.watch.json")
    path = state_file(tmp_path, finished="2026-11-03T12:00:01.000Z")
    got = host.holder(path=str(path), wall=lambda: BEAT_AT + 1)
    assert got["held"] == host.HELD_NONE and got["why"] == "the state is finished" and got["run"] == "20261103T120000Z-4242"
    for other in ({"mode": "project"}, {"mode": None}):
        state_file(tmp_path, **other)
        assert host.holder(home=str(tmp_path / "home"), wall=lambda: BEAT_AT)["why"] == "the state is no host watch's"


@pytest.mark.parametrize("data, error", [
    (b"", "JSONDecodeError: Expecting value"),                               # empty
    (b"\x00" * 64, "JSONDecodeError: Expecting value"),                      # filled with zeros
    (b'{"mode": "host", "heartbeat": ', "JSONDecodeError: Expecting value"),   # torn
    (b'{"mode": "h\xc3\xb4st"}', "UnicodeDecodeError: "),        # not ASCII
    (b"[1, 2]", "it holds a JSON list, not an object"),                      # a JSON that is no object
    (b"null", "it holds a JSON NoneType, not an object"),
    (b"42", "it holds a JSON int, not an object"),
])
def test_ai2_holder_tells_a_state_that_cannot_be_read_apart_from_no_state(tmp_path, data, error):
    path = state_file(tmp_path)
    path.write_bytes(data)
    got = host.holder(path=str(path), wall=lambda: BEAT_AT)
    assert got["held"] == host.HELD_UNREADABLE != host.HELD_NONE and got["error"].startswith(error), got
    assert got["why"] == "the state cannot be read (%s)" % got["error"] and len(got["error"]) <= 120
    assert got["run"] is None and got["age"] is None and got["error"].isascii()


def test_ai2_holder_an_open_refused_and_a_folder_where_the_state_is_are_unreadable(tmp_path, monkeypatch):
    path = state_file(tmp_path)

    def refused(*a, **kw):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(host, "open", refused, raising=False)
    got = host.holder(path=str(path), wall=lambda: BEAT_AT)
    assert got["held"] == host.HELD_UNREADABLE and got["error"] == "PermissionError: Permission denied"
    monkeypatch.undo()
    folder = tmp_path / "folder"
    folder.mkdir()
    assert host.holder(path=str(folder), wall=lambda: BEAT_AT)["held"] == host.HELD_UNREADABLE


def test_finding2_holder_raises_what_its_docstring_says_a_state_nested_past_the_parsers_limit(tmp_path):
    path = state_file(tmp_path)
    path.write_text("[" * 200000, encoding="ascii")
    with pytest.raises(RecursionError):
        host.holder(path=str(path), wall=lambda: BEAT_AT)
    assert "RecursionError" in host.holder.__doc__ and "MemoryError" in host.holder.__doc__


def test_holder_fresh_stale_and_unparsed_with_what_it_read(tmp_path):
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


def test_finding29_holder_takes_the_states_number_as_read_zero_negative_huge_nan_infinity_and_a_beat_ahead(
        tmp_path):
    path = state_file(tmp_path)
    for stale, age, held in ((0, 6, host.HELD_STALE), (0, 0, host.HELD_FRESH), (-5, 6, host.HELD_STALE),
                             (-5, -3, host.HELD_STALE), (10 ** 400, 6, host.HELD_FRESH),
                             (float("inf"), 10 ** 6, host.HELD_FRESH), (30, -100, host.HELD_FRESH)):
        state_file(tmp_path, stale_after_seconds=stale)
        got = host.holder(path=str(path), wall=lambda: BEAT_AT + age)
        assert (got["held"], got["age"], got["stale"]) == (held, age, stale), (stale, age)
    path.write_text(json.dumps({"mode": "host", "run": "r", "pid": 1, "heartbeat": BEAT, "finished": None,
                                "stale_after_seconds": float("nan")}), encoding="ascii")   # JSON's NaN
    got = host.holder(path=str(path), wall=lambda: BEAT_AT + 1)
    assert got["held"] == host.HELD_STALE and got["stale"] != got["stale"]


def test_the_watch_refuses_exactly_where_holder_says_fresh_or_unparsed_and_in_todays_words(tmp_path):
    state_file(tmp_path)
    with pytest.raises(host.HostError) as got:
        watch(tmp_path, wall0=BEAT_AT + 3)
    assert str(got.value).startswith("another raqib watch --host is watching this home (run 20261103T120000Z-4242,"
                                     " pid 4242, heartbeat 3 s ago): one host watch per home; stop it first (")
    state_file(tmp_path, heartbeat="garbled")
    with pytest.raises(host.HostError, match="holds a heartbeat that cannot be parsed \\(garbled\\) and is not"):
        watch(tmp_path, wall0=BEAT_AT + 3600)
    state_file(tmp_path, heartbeat="x" * 100)                          # the heartbeat cut as before: 40
    with pytest.raises(host.HostError, match="cannot be parsed \\(%s\\) and" % ("x" * 40)):
        watch(tmp_path, wall0=BEAT_AT + 3600)
    state_file(tmp_path).write_text("[1, 2]", encoding="ascii")        # unreadable: never refused (AI-2)
    w, _ = watch(tmp_path, wall0=BEAT_AT + 3)
    assert [h["kind"] for h in w.holes if h["kind"].startswith("watch-")] == [host.UNREADABLE_BEFORE]


# --- AI-1: the hole is in the events before this watch's state replaces the one that named the run before ---------

class Ended(BaseException):
    """The watch ended right after its state was first written (a stand-in: nothing is signalled)."""


@pytest.mark.parametrize("given", ["stale", "unreadable"])
def test_ai1_a_start_ended_right_after_its_state_is_written_has_the_hole_in_its_events_once_in_its_chain(
        tmp_path, monkeypatch, given):
    home = tmp_path / "home"
    path = state_file(tmp_path, heartbeat=OLD_BEAT)
    if given == "unreadable":
        path.write_bytes(b"")
    kind = host.UNENDED if given == "stale" else host.UNREADABLE_BEFORE
    seen = {}
    real = host.write_json

    def first_state_then_end(where, value):
        real(where, value)
        if where == str(path):
            events_path = home / ".raqib" / "host" / "events.jsonl"
            seen["events"] = events_path.read_text(encoding="ascii") if events_path.exists() else ""
            seen["state"] = value
            raise Ended()
    monkeypatch.setattr(host, "write_json", first_state_then_end)
    out = io.StringIO()
    with pytest.raises(Ended):
        host.start(CATALOG, RULES, every=10, no_open=True, no_notify=True, no_page=True, out=out, err=io.StringIO(),
                   environ={}, home=str(home), reader=lambda: host_fixtures.inventory("linux", CATALOG),
                   platform="linux")
    assert seen["state"]["finished"] is None and not (home / ".raqib" / "host" / "rounds.jsonl").exists()   # no round
    run = seen["state"]["run"]
    assert json.loads(path.read_text(encoding="ascii"))["run"] == run    # the state that named the run before: gone
    lines = [x for x in seen["events"].splitlines() if x.strip()]
    assert lines == [x for x in (home / ".raqib" / "host" / "events.jsonl").read_text(
        encoding="ascii").splitlines() if x.strip()]
    got = [json.loads(x) for x in lines]
    assert [e["kind"] for e in got][0] == "watch" and got[0]["state"] == "start"
    holes = [e for e in got if e["kind"] == "hole" and e["hole"]["kind"] == kind]
    assert len(holes) == 1 and holes[0]["watch"]["run"] == run and holes[0]["alarm"] is True
    if given == "stale":
        assert "run 20261103T120000Z-4242 (pid 4242)" in holes[0]["summary"]
    chain_whole(lines)
    started = out.getvalue()                                            # AI-3: said with the start's holes
    (line,) = [x for x in started.splitlines() if x.startswith("raqib watch --host: hole: %s: " % kind)]
    assert line == "raqib watch --host: hole: %s: %s" % (kind, holes[0]["summary"].split(": ", 1)[1])


def test_ai1_a_full_run_after_it_still_holds_the_hole_once_and_a_start_with_no_such_state_writes_nothing_early(
        tmp_path):
    w0, _ = watch(tmp_path)
    assert not Path(w0.events_path).exists()                            # no state before: nothing early
    w0.finish()
    state_file(tmp_path)
    w, c = watch(tmp_path, wall0=BEAT_AT + 40)
    early = [e for e in events(w) if e["watch"]["run"] == w.run]
    assert [e["kind"] for e in early] == ["watch", "hole"] and len(said_unended(w)) == 1   # before any round
    rounds(w, c, 3)
    text, code = w.finish()
    assert code == 3 and len(said_unended(w)) == 1 and len(unended(w)) == 1
    chain_whole([x for x in Path(w.events_path).read_text(encoding="ascii").splitlines() if x.strip()])
    mine = [e for e in events(w) if e["watch"]["run"] == w.run]
    assert [e["state"] for e in mine if e["kind"] == "watch"].count("start") == 1 and mine[0]["state"] == "start"


# --- AH-1, AI-3: the hole's words say what was read ----------------------------------------------------------------

def test_ah1_a_watch_over_a_state_left_unfinished_says_one_hole_of_its_own_with_the_run_pid_beat_and_seconds(tmp_path):
    w1, c1 = watch(tmp_path)
    rounds(w1, c1, 2)                               # its last heartbeat: BASE + 10 (the second round's tick)
    first = w1.run
    beat = json.loads(Path(w1.state_path).read_text(encoding="ascii"))["heartbeat"]
    assert unended(w1) == []                        # no state before it: none
    w2, c2 = watch(tmp_path, wall0=BASE + 10 + 125.75)   # w1 ended without its end; 125.75 s later, this start
    (hole,) = unended(w2)
    assert hole["detail"] == hole_words(first, w1.state(c1())["pid"], w2.state_path, beat, "125 s before this start",
                                        "for those 125 s no watch of this home is known to have watched")
    assert WORDS in hole["detail"] and "one that stopped writing its state" in hole["detail"]
    assert hole["at"] == w2.at(w2.t0) and hole["round"] is None and hole["notice"] is None   # at the start, no knock
    rounds(w2, c2, 2)
    text, code = w2.finish()
    assert code == 3 and len(unended(w2)) == 1      # a hole of the result, said once
    result, reasons = w2.result()
    assert result == "incomplete" and "1 hole(s) of the watch" in reasons
    assert "%s: %s" % (host.UNENDED, hole["detail"]) in " ".join(text.split())   # in the final report
    said = said_unended(w2)
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
def test_ah1_the_hole_on_every_system_and_none_without_a_state_or_over_a_finished_one(tmp_path, platform):
    w, _ = watch(tmp_path, platform=platform)
    assert unended(w) == []
    state_file(tmp_path, finished="2026-11-03T12:00:01.000Z")
    w, _ = watch(tmp_path, wall0=BEAT_AT + 3600, platform=platform)
    assert unended(w) == []
    state_file(tmp_path, stale_after_seconds=5)
    w, _ = watch(tmp_path, wall0=BEAT_AT + 6.9, platform=platform)
    (hole,) = unended(w)
    assert "run 20261103T120000Z-4242 (pid 4242)" in hole["detail"] and "heartbeat %s, 6 s before" % BEAT in hole[
        "detail"]
    assert "for those 6 s no watch of this home is known to have watched" in hole["detail"]


def test_ai3_the_run_pid_and_heartbeat_are_cut_to_one_bound(tmp_path):
    assert host.HELD_SAID_MAX == 40
    state_file(tmp_path, run="r" * 10000, pid="9" * 10000, stale_after_seconds=5)
    w, _ = watch(tmp_path, wall0=BEAT_AT + 7)
    (hole,) = unended(w)
    assert "run %s... (pid %s...)" % ("r" * 40, "9" * 40) in hole["detail"] and len(hole["detail"]) < 600
    assert "r" * 41 not in hole["detail"] and "9" * 41 not in hole["detail"]
    held = {"held": host.HELD_STALE, "run": "r\x1b[2J", "pid": 7, "heartbeat": "b" * 50, "age": 31.0}
    kind, words = host.before_hole(held, "S")
    assert kind == host.UNENDED and "run r?[2J (pid 7)" in words and "heartbeat %s...," % ("b" * 40) in words


def test_ai3_a_heartbeat_ahead_of_the_clock_is_said_ahead_by_its_seconds_never_as_0_s(tmp_path):
    state_file(tmp_path, stale_after_seconds=-5)                       # the state's own staleness negative
    w, _ = watch(tmp_path, wall0=BEAT_AT - 3)                          # its heartbeat 3 s ahead of this clock
    (hole,) = unended(w)
    assert hole["detail"] == hole_words("20261103T120000Z-4242", 4242, w.state_path, BEAT,
                                        "3 s ahead of this start's clock",
                                        "how long no watch of this home watched is not known")
    for age, when in ((-0.25, "0.25 s ahead"), (-1e-06, "1e-06 s ahead"), (0.75, "0 s before this start")):
        words = host.before_hole({"held": host.HELD_STALE, "run": "r", "pid": 1, "heartbeat": BEAT, "age": age},
                                 "S")[1]
        assert when in words and ("0 s ahead" not in words), words
    assert host.before_hole({"held": host.HELD_NONE}, "S") is None
    assert host.before_hole({"held": host.HELD_FRESH}, "S") is None


def test_ai2_a_watch_over_a_state_it_cannot_read_starts_and_says_one_hole_of_its_own_kind_absent_says_nothing(
        tmp_path):
    w, _ = watch(tmp_path)
    assert [h for h in w.holes if h["kind"] == host.UNREADABLE_BEFORE] == []   # absent: no gap, nothing said
    w.finish()
    state_file(tmp_path).write_bytes(b'{"mode": "host", "hea')                  # torn
    w, c = watch(tmp_path, wall0=BASE + 100)
    (hole,) = [h for h in w.holes if h["kind"] == host.UNREADABLE_BEFORE]
    assert hole["detail"] == (
        "the state %s is there and cannot be read as a state (JSONDecodeError: Unterminated string starting at: line"
        " 1 column 18 (char 17)): whether the host watch before this one ended without its end, and how long no"
        " watch of this home watched, is not known; this watch takes the home" % w.state_path)
    assert unended(w) == [] and hole["round"] is None and hole["notice"] is None
    rounds(w, c, 1)
    text, code = w.finish()
    assert code == 3 and "%s: %s" % (host.UNREADABLE_BEFORE, hole["detail"]) in " ".join(text.split())
    assert len([e for e in events(w) if e["kind"] == "hole" and e["hole"]["kind"] == host.UNREADABLE_BEFORE]) == 1


def test_ascii():
    for path in ("raqib/host.py", "tests/test_host_unended.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path
