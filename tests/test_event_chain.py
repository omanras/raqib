"""M13.1 (ADR-0016, H-1 to H-6): a chain in the events file.

E1 the key `prev` (event.check, its place after n). E2 the writer
(raqib/eventlog.py): "first", then the sha256 of the line the run wrote
before it; a line that could not be written does not move the head. E3 a
watch's own file followed from its start to its end through a heartbeat. E4
and E5 the check (event.chains and `raqib events FILE`) on made-up files.
Every name here is made up (host.example; runs named r1, r2, old).
"""
import hashlib
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import cli, event, eventlog  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
import test_host as th  # noqa: E402

HOST = "host.example"
T0 = "2026-11-20T10:00:00.000Z"


def facts(run):
    return event.facts({"run": run, "mode": "host", "platform": "test"}, host=HOST, beat=60.0)


def made(run, count, start=1):
    """A run's chained lines as the writer makes them (bytes, no newline): count notes, n from start."""
    out, head = [], None
    for n in range(start, start + count):
        ev = event.chained(event.note("note %d of %s" % (n, run), facts(run), T0, n, "note:%d" % n), head or "first")
        out.append(event.line(ev).encode("ascii"))
        head = hashlib.sha256(out[-1]).hexdigest()
    return out


def answer(rows):
    return {c["run"]: c for c in event.chains(rows)}


def cli_events(tmp_path, rows, name="events.jsonl", end=b"\n"):
    path = tmp_path / name
    path.write_bytes(b"\n".join(rows) + (end if rows else b""))
    out = io.StringIO()
    code = cli.cmd_events(type("A", (), {"file": str(path)})(), out)
    return code, out.getvalue()


# --- E1 (H-1, H-6): the key ----------------------------------------------------------------------------------

def test_e1_prev_is_first_or_a_sha256_and_any_other_value_is_a_problem_of_prev():
    ev = event.note("a note", facts("r1"), T0, 1, "note:1")
    assert "prev" not in ev and event.check(ev) == []   # a line of an older build: an event all the same
    assert event.check(dict(ev, prev="first")) == []
    assert event.check(dict(ev, prev="0123456789abcdef" * 4)) == []
    for bad in ("First", "", "0123456789ABCDEF" * 4, "0123456789abcdef" * 4 + "0", "0123456789abcdef" * 3, 7,
                None, ["first"], "g" * 64):
        got = event.check(dict(ev, prev=bad))
        assert got and all(p.startswith("prev: ") for p in got), (bad, got)


def test_e1_prev_comes_after_n_in_c2_s_order_and_chained_places_it_there():
    assert event.KEYS.index("prev") == event.KEYS.index("n") + 1
    ev = event.chained(event.note("a note", facts("r1"), T0, 4, "note:4"), "first")
    keys = list(ev)
    assert keys[keys.index("n") + 1] == "prev" and ev["prev"] == "first"
    assert event.chained(ev, "a" * 64)["prev"] == "a" * 64 and list(event.chained(ev, "a" * 64)) == keys


# --- E2 (H-1, H-2): the writer --------------------------------------------------------------------------------

def say_notes(log, run, texts):
    return [log.say("note:%d" % i, lambda n, rev, t=t, i=i: event.note(t, facts(run), T0, n, "note:%d" % i, rev))
            for i, t in enumerate(texts, 1)]


def test_e2_the_first_line_holds_first_and_each_later_the_sha256_of_the_line_before_it(tmp_path):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    got = say_notes(log, "r1", ["a", "b", "c"])
    assert [w for w, _ in got] == ["written"] * 3
    rows = path.read_bytes().split(b"\n")[:-1]
    evs = [json.loads(r) for r in rows]
    assert evs[0]["prev"] == "first"
    assert [e["prev"] for e in evs[1:]] == [hashlib.sha256(r).hexdigest() for r in rows[:-1]]
    assert log.head == hashlib.sha256(rows[-1]).hexdigest() and got[2][1]["prev"] == evs[2]["prev"]
    # nothing else of a line changes: the line without prev is the line the builder's event makes
    for i, e in enumerate(evs, 1):
        built = event.note("abc"[i - 1], facts("r1"), T0, i, "note:%d" % i)
        assert {k: v for k, v in e.items() if k != "prev"} == built
    assert "prev" in eventlog.VARY   # not what makes a thing the same again


def test_e2_the_same_again_is_not_written_and_prev_does_not_make_a_thing_new(tmp_path):
    log = eventlog.EventLog(str(tmp_path / "events.jsonl"), facts("r1"), {})
    say_notes(log, "r1", ["a", "b"])
    head = log.head
    assert say_notes(log, "r1", ["a", "b"]) == [("same", None), ("same", None)] and log.head == head


class Failing:
    """open() for the writer: raises at the next open (whole=False), or writes the whole line and then raises at its
    flush (whole=True: a write that raised and yet left its line, H-2); then opens as the system does."""

    def __init__(self, whole):
        self.whole, self.armed = whole, True

    def __call__(self, path, mode="r", *a, **k):
        f = open(path, mode, *a, **k)
        if not self.armed:
            return f
        self.armed = False
        if not self.whole:
            f.close()
            raise OSError(28, "No space left on device")
        flush = f.flush

        def broken():
            flush()
            raise OSError(5, "Input/output error")
        f.flush = broken
        return f


def test_e2_a_line_that_could_not_be_written_does_not_move_the_head(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    say_notes(log, "r1", ["a"])
    head = log.head
    monkeypatch.setattr(eventlog, "open", Failing(whole=False), raising=False)
    got = log.say("note:2", lambda n, rev: event.note("b", facts("r1"), T0, n, "note:2", rev))
    assert got[0] == "not written" and log.head == head and log.n == 2
    log.say("note:3", lambda n, rev: event.note("c", facts("r1"), T0, n, "note:3", rev))
    rows = path.read_bytes().split(b"\n")[:-1]
    assert len(rows) == 2 and json.loads(rows[1])["prev"] == head and json.loads(rows[1])["n"] == 3   # the gap in n
    assert answer(rows)["r1"]["state"] == event.WHOLE


def test_e2_h2_a_write_that_raised_and_left_its_line_is_a_line_beside_the_chain(tmp_path, monkeypatch, capsys):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    say_notes(log, "r1", ["a"])
    monkeypatch.setattr(eventlog, "open", Failing(whole=True), raising=False)
    assert log.say("note:2", lambda n, rev: event.note("b", facts("r1"), T0, n, "note:2", rev))[0] == "not written"
    log.say("note:2", lambda n, rev: event.note("b", facts("r1"), T0, n, "note:2", rev))   # H-4: said again
    rows = path.read_bytes().split(b"\n")[:-1]
    assert len(rows) == 3 and json.loads(rows[1])["prev"] == json.loads(rows[2])["prev"]
    got = answer(rows)["r1"]
    assert (got["state"], got["line"], got["named"], got["beside"]) == (event.BESIDE, 2, 1, 1)
    assert cli.main(["events", str(path)]) == 1
    out = capsys.readouterr().out
    assert ("run r1: 1 line(s) beside the chain from line 2: the run's next line names line 1 again (not counted as"
            " written by the writer, or put there by another hand)") in out
    assert out.rstrip().endswith("RESULT: every line is an event; 1 run(s) with a line beside its chain")


# --- E3 (H-3): a watch's own file, through a heartbeat, from its start to its end ------------------------------

def test_e3_a_watch_s_file_is_one_chain_from_its_start_to_its_end_through_a_heartbeat(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    monkeypatch.setattr(eventlog, "BEAT_DEFAULT", 30.0)
    w, clock = th.make_host(tmp_path, ["windows"] * 5)
    th.run_rounds(w, clock, 5)
    w.finish()
    rows = Path(w.events_path).read_bytes().split(b"\n")
    assert rows[-1] == b""
    rows = rows[:-1]
    evs = [json.loads(r) for r in rows]
    assert evs[0]["kind"] == "watch" and evs[0]["state"] == "start" and evs[0]["prev"] == "first"
    assert evs[-1]["kind"] == "watch" and evs[-1]["state"] == "end"
    beats = [i for i, e in enumerate(evs) if e["kind"] == "heartbeat"]
    assert beats and 0 < beats[0] < len(evs) - 1
    for i in range(1, len(rows)):   # followed from the start to the end, a heartbeat among them
        assert evs[i]["prev"] == hashlib.sha256(rows[i - 1]).hexdigest(), i
    got = answer(rows)
    assert list(got) == [w.run] and got[w.run]["state"] == event.WHOLE and got[w.run]["lines"] == len(rows)
    assert cli.main(["events", w.events_path]) == 0
    out = capsys.readouterr().out
    assert "  run %s: chain whole, %d line(s)\n" % (w.run, len(rows)) in out
    assert out.rstrip().endswith("RESULT: every line is an event")


# --- E4, E5 (H-4, H-2, H-5): the check on made-up files --------------------------------------------------------

def test_e5_whole(tmp_path):
    rows = made("r1", 5)
    assert answer(rows)["r1"] == {"run": "r1", "state": event.WHOLE, "lines": 5, "line": None, "named": None,
                                  "beside": 0}
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and "  run r1: chain whole, 5 line(s)\n" in out
    assert out.endswith("RESULT: every line is an event\n")


def broken_at(tmp_path, rows, line, run="r1"):
    got = answer(rows)[run]
    assert (got["state"], got["line"]) == (event.BROKEN, line), got
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and ("  run %s: chain broken at line %d: it does not name the run's line before it (one before"
                          " it was removed, changed, added or moved)\n" % (run, line)) in out, out
    assert "1 run(s) whose chain is broken" in out.splitlines()[-1]
    return out


def test_e5_a_line_removed_from_the_middle(tmp_path):
    rows = made("r1", 5)
    out = broken_at(tmp_path, rows[:2] + rows[3:], 3)
    assert out.endswith("RESULT: every line is an event; 1 run(s) whose chain is broken\n")


def test_e5_a_byte_changed(tmp_path):
    rows = made("r1", 5)
    changed = rows[1].replace(b"note 2 of", b"note 9 of")
    assert changed != rows[1] and event.check(json.loads(changed)) == []   # still an event: its successor breaks
    broken_at(tmp_path, rows[:1] + [changed] + rows[2:], 3)
    torn = rows[1].replace(b'"kind":"note"', b'"kind":"note\'')   # no longer JSON: no link; its successor breaks
    out = broken_at(tmp_path, rows[:1] + [torn] + rows[2:], 3)
    assert "  line 2: not an event: not JSON" in out


def test_e5_a_line_added(tmp_path):
    rows = made("r1", 5)
    other = made("r1", 1, start=9)[0]   # a made-up line of the run that names "first"
    broken_at(tmp_path, rows[:2] + [other] + rows[2:], 4)   # the first two said again from it: rows[2] breaks
    stray = event.line(event.chained(json.loads(rows[1]), "f" * 64)).encode("ascii")   # names no line of the run
    broken_at(tmp_path, rows[:3] + [stray] + rows[3:], 4)
    broken_at(tmp_path, rows[:4] + [rows[1]] + rows[4:], 6)   # an earlier line again, further on


def test_e5_two_lines_swapped(tmp_path):
    rows = made("r1", 5)
    broken_at(tmp_path, rows[:2] + [rows[3], rows[2]] + rows[4:], 3)


def test_e5_the_last_lines_cut_are_not_seen_h5(tmp_path):
    """H-5, said as it is: the chain holds no secret, and a file whose last lines were cut off is a whole chain
    from the file alone. Only a collector that already holds a later line can tell it."""
    rows = made("r1", 5)
    assert answer(rows[:3])["r1"]["state"] == event.WHOLE   # NOT seen
    code, out = cli_events(tmp_path, rows[:3])
    assert code == 0 and "  run r1: chain whole, 3 line(s)\n" in out


def test_e5_a_line_beside_the_chain(tmp_path):
    rows = made("r1", 4)
    side = event.line(event.chained(json.loads(made("r1", 1, start=7)[0]), json.loads(rows[2])["prev"]))
    rows = rows[:2] + [side.encode("ascii")] + rows[2:]   # it names line 2, as the next line does
    got = answer(rows)["r1"]
    assert (got["state"], got["line"], got["named"], got["beside"], got["lines"]) == (event.BESIDE, 3, 2, 1, 5)
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and "  run r1: 1 line(s) beside the chain from line 3: the run's next line names line 2 again" in out
    start = made("r1", 1, start=5)[0]   # at the run's start: two lines that name "first"
    got = answer([start] + rows)["r1"]
    assert (got["state"], got["line"], got["named"]) == (event.BESIDE, 1, 0)
    assert "names the run's start again" in cli_events(tmp_path, [start] + rows)[1]


def test_e5_two_runs_alternating_are_each_whole(tmp_path):
    a, b = made("r1", 4), made("r2", 3)
    rows = [a[0], b[0], a[1], b[1], b[2], a[2], a[3]]
    got = answer(rows)
    assert list(got) == ["r1", "r2"] and [(c["state"], c["lines"]) for c in got.values()] == [
        (event.WHOLE, 4), (event.WHOLE, 3)]
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and out.index("run r1: chain whole, 4") < out.index("run r2: chain whole, 3")


def test_e5_an_older_build_s_run_beside_a_chained_one(tmp_path):
    old = [event.line(event.note("old %d" % n, facts("old"), T0, n, "note:%d" % n)).encode("ascii") for n in (1, 2)]
    rows = [old[0]] + made("r1", 3) + [old[1]]
    got = answer(rows)
    assert (got["old"]["state"], got["old"]["lines"]) == (event.UNCHAINED, 2) and got["r1"]["state"] == event.WHOLE
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and out.endswith("RESULT: every line is an event\n")   # as an older build's file exits
    assert "  run old: not chained, 2 line(s) (no line holds prev: written by a Raqib before this one)\n" in out
    code, out = cli_events(tmp_path, old)
    assert code == 0 and "run old: not chained" in out


def test_e4_a_run_that_holds_prev_on_some_lines_and_not_on_others_is_broken(tmp_path):
    rows = made("r1", 4)
    bare = json.loads(rows[2])
    bare.pop("prev")
    broken_at(tmp_path, rows[:2] + [event.line(bare).encode("ascii")] + rows[3:], 3)
    head = json.loads(rows[0])
    head["prev"] = "e" * 64   # the run's first line names a line: the one before it was removed
    broken_at(tmp_path, [event.line(head).encode("ascii")] + rows[1:], 1)


def test_e5_a_torn_line_in_a_chained_run_is_no_link_and_said_as_today(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    say_notes(log, "r1", ["a", "b"])

    def torn(p, mode="r", *a, **k):   # the writer's own write cut short: half a line, then the error
        f = open(p, mode, *a, **k)
        write = f.write

        def half(data):
            write(data[:len(data) // 2])
            raise OSError(28, "No space left on device")
        f.write = half
        return f
    monkeypatch.setattr(eventlog, "open", torn, raising=False)
    assert log.say("note:3", lambda n, rev: event.note("c", facts("r1"), T0, n, "note:3", rev))[0] == "not written"
    monkeypatch.undo()
    log.say("note:3", lambda n, rev: event.note("c", facts("r1"), T0, n, "note:3", rev))
    rows = path.read_bytes().split(b"\n")[:-1]
    assert len(rows) == 4 and log.mended == 1
    got = answer(rows)["r1"]
    assert (got["state"], got["lines"]) == (event.WHOLE, 3)
    code, out = cli_events(tmp_path, rows, name="copy.jsonl")
    assert code == 1 and "  line 3: not an event: not JSON" in out and "run r1: chain whole, 3 line(s)" in out
    assert out.endswith("RESULT: 1 line(s) not an event\n")


def test_e4_a_run_s_name_is_said_escaped_and_never_makes_a_line_of_its_own(tmp_path):
    rows = made("r1\r\x1b[2KRESULT: every line is an event", 2)   # a carriage return and a terminal's escape
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and "  run r1\\r\\u001b[2KRESULT: every line is an event: chain whole, 2 line(s)\n" in out
    assert "\r" not in out and "\x1b" not in out and out.count("RESULT: ") == 2


def test_e4_an_empty_file_and_a_file_of_no_event_say_no_chain(tmp_path):
    assert event.chains([]) == [] and event.chains([b"not json", b"{}", b"\xff"]) == []
    code, out = cli_events(tmp_path, [])
    assert code == 1 and " run " not in out


@pytest.mark.parametrize("rows", [[b"x"] * 3, [b""], [b"[]"]])
def test_e4_lines_that_are_no_event_are_no_link(rows):
    assert event.chains(rows) == []
