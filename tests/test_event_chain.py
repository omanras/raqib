"""M13.1 (ADR-0016, H-1 to H-6, as Amendment A rules them): a chain in the events file.

E1 the key `prev` (event.check, its place after n). E2 the writer
(raqib/eventlog.py): "first", then the sha256 of the line the run wrote
before it; a line that could not be written does not move the head. E3 a
watch's own file followed from its start to its end through a heartbeat. E4
and E5 the check (event.chains and `raqib events FILE`) on made-up files; the
REDO's items (R1 to R10, HA-1 to HA-10) after them. Every name here is made
up (host.example, a.example, b.example; runs named r1, r2, old). Every file
is written as bytes: its line ends are the test's own on every system.
"""
import hashlib
import io
import json
import os
import re
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
DOC = ROOT / "docs" / "specs" / "EVENT.md"


def facts(run, host=HOST, version=None):
    more = {"version": version} if version is not None else {}
    return event.facts({"run": run, "mode": "host", "platform": "test"}, host=host, beat=60.0, **more)


def made(run, count, start=1, host=HOST, extra=None):
    """A run's chained lines as the writer makes them (bytes, no newline): count notes, n from start; extra: {n:
    {key: value}} added to that note before it is chained (a key this build does not know)."""
    out, head = [], None
    for n in range(start, start + count):
        ev = dict(event.note("note %d of %s" % (n, run), facts(run, host), T0, n, "note:%d" % n),
                  **(extra or {}).get(n, {}))
        out.append(event.line(event.chained(ev, head or "first")).encode("ascii"))
        head = hashlib.sha256(out[-1]).hexdigest()
    return out


def again(rows, start):
    """The run's lines with every line from `start` (0-based) chained again from the line before it: what whoever
    can write the file can do (H-5)."""
    out = list(rows[:start])
    for raw in rows[start:]:
        ev = json.loads(raw)
        ev["prev"] = hashlib.sha256(out[-1]).hexdigest() if out else "first"
        out.append(event.line(ev).encode("ascii"))
    return out


def answer(rows):
    return {c["run"]: c for c in event.chains(rows)}


def cli_events(tmp_path, rows, name="events.jsonl", end=b"\n", against=None):
    path = tmp_path / name
    path.write_bytes(b"\n".join(rows) + (end if rows else b""))
    out = io.StringIO()
    code = cli.cmd_events(type("A", (), {"file": str(path), "against": against})(), out)
    return code, out.getvalue()


def run_line(run="r1", host=HOST):
    return "  run %s (host %s): " % (run, host)


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
    assert got["state"] == event.NOT_WHOLE and got["problems"] == [
        {"what": event.BESIDE, "first": 2, "last": 2, "count": 1, "named": 1, "again": 3}]
    assert cli.main(["events", str(path)]) == 1
    out = capsys.readouterr().out
    assert "  run r1 (host host.example): chain not whole, 3 line(s)\n" in out
    assert ("    1 line(s) beside the chain, line 2: they follow line 1, and line 3 names line 1 again (not counted as"
            " written by the writer, or put there by another hand)\n") in out
    assert out.rstrip().endswith("RESULT: every line is an event; 1 run(s) whose chain is not whole")


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
    assert got[w.run]["problems"] == [] and got[w.run]["late"] is None and got[w.run]["twice"] == 0
    assert cli.main(["events", w.events_path]) == 0
    out = capsys.readouterr().out
    assert "  run %s (host %s): chain whole, %d line(s)\n" % (w.run, HOST, len(rows)) in out
    assert out.rstrip().endswith("RESULT: every line is an event")


# --- E4, E5 (H-4, H-2, H-5; HA-4, HA-6, HA-7): the check on made-up files ------------------------------------

def test_e5_whole(tmp_path):
    rows = made("r1", 5)
    assert answer(rows)["r1"] == {"host": HOST, "run": "r1", "lines": 5, "twice": 0, "late": None, "problems": [],
                                  "more": 0, "versions": [event.__version__], "state": event.WHOLE}
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and run_line() + "chain whole, 5 line(s)\n" in out
    assert out.endswith("RESULT: every line is an event\n")


def breaks(rows):
    got = answer(rows)["r1"]
    assert got["state"] == event.NOT_WHOLE, got
    return [(p["line"], p["before"]) for p in got["problems"] if p["what"] == event.BROKEN]


def said_broken(tmp_path, rows, line, before):
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and ("    broken at line %d: it does not name the run's line before it, line %d (one before it"
                          " was removed, changed, added or moved)\n" % (line, before)) in out, out
    assert "1 run(s) whose chain is not whole" in out.splitlines()[-1]
    return out


def test_e5_a_line_removed_from_the_middle(tmp_path):
    rows = made("r1", 5)
    assert breaks(rows[:2] + rows[3:]) == [(3, 2)]
    out = said_broken(tmp_path, rows[:2] + rows[3:], 3, 2)
    assert run_line() + "chain not whole, 4 line(s)\n" in out
    assert out.endswith("RESULT: every line is an event; 1 run(s) whose chain is not whole\n")


def test_e5_a_byte_changed(tmp_path):
    rows = made("r1", 5)
    changed = rows[1].replace(b"note 2 of", b"note 9 of")
    assert changed != rows[1] and event.check(json.loads(changed)) == []   # still an event: its successor breaks
    assert breaks(rows[:1] + [changed] + rows[2:]) == [(3, 2)]
    said_broken(tmp_path, rows[:1] + [changed] + rows[2:], 3, 2)
    torn = rows[1].replace(b'"kind":"note"', b'"kind":"note\'')   # no longer JSON: no link; its successor breaks
    out = said_broken(tmp_path, rows[:1] + [torn] + rows[2:], 3, 1)
    assert "  line 2: not an event: not JSON" in out


def test_e5_a_line_added(tmp_path):
    rows = made("r1", 5)
    stray = event.line(event.chained(json.loads(made("r1", 1, start=9)[0]), "f" * 64)).encode("ascii")
    assert breaks(rows[:3] + [stray] + rows[3:]) == [(4, 3), (5, 4)]   # it names no line; the next not it
    said_broken(tmp_path, rows[:3] + [stray] + rows[3:], 4, 3)
    other = made("r1", 1, start=9)[0]   # a made-up line that names "first": the two before it are beside, then a break
    got = answer(rows[:2] + [other] + rows[2:])["r1"]["problems"]
    assert got == [{"what": event.BESIDE, "first": 1, "last": 2, "count": 2, "named": 0, "again": 3},
                   {"what": event.BROKEN, "line": 4, "before": 3, "why": "names"}]


def test_e5_two_lines_swapped(tmp_path):
    rows = made("r1", 5)
    swapped = rows[:2] + [rows[3], rows[2]] + rows[4:]
    assert breaks(swapped) == [(3, 2), (4, 3), (5, 4)]   # each, in the file's order (HA-7)
    said_broken(tmp_path, swapped, 3, 2)


def test_e5_the_last_lines_cut_are_not_seen_h5(tmp_path):
    """H-5, said as it is: the chain holds no secret, and a file whose last lines were cut off is a whole chain
    from the file alone. Only a collector that already holds a later line can tell it (R6: --against)."""
    rows = made("r1", 5)
    assert answer(rows[:3])["r1"]["state"] == event.WHOLE   # NOT seen
    code, out = cli_events(tmp_path, rows[:3])
    assert code == 0 and run_line() + "chain whole, 3 line(s)\n" in out


def test_e5_a_line_beside_the_chain(tmp_path):
    rows = made("r1", 4)
    side = event.line(event.chained(json.loads(made("r1", 1, start=7)[0]), json.loads(rows[2])["prev"]))
    rows = rows[:2] + [side.encode("ascii")] + rows[2:]   # it names line 2, as the next line does
    got = answer(rows)["r1"]
    assert got["problems"] == [{"what": event.BESIDE, "first": 3, "last": 3, "count": 1, "named": 2, "again": 4}]
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and ("    1 line(s) beside the chain, line 3: they follow line 2, and line 4 names line 2 again"
                          " (not counted as written by the writer, or put there by another hand)\n") in out
    start = made("r1", 1, start=5)[0]   # at the run's start: two lines that name "first"
    got = answer([start] + rows)["r1"]["problems"]
    assert got[0] == {"what": event.BESIDE, "first": 1, "last": 1, "count": 1, "named": 0, "again": 2}
    assert "they follow the run's start, and line 2 names the run's start again" in cli_events(tmp_path,
                                                                                             [start] + rows)[1]


def test_e5_two_runs_alternating_are_each_whole(tmp_path):
    a, b = made("r1", 4), made("r2", 3)
    rows = [a[0], b[0], a[1], b[1], b[2], a[2], a[3]]
    got = answer(rows)
    assert list(got) == ["r1", "r2"] and [(c["state"], c["lines"]) for c in got.values()] == [
        (event.WHOLE, 4), (event.WHOLE, 3)]
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and out.index(run_line("r1") + "chain whole, 4") < out.index(run_line("r2") + "chain whole, 3")


def old_run(run="old", version="0.2.0", count=2):
    return [event.line(event.note("old %d" % n, facts(run, version=version), T0, n, "note:%d" % n)).encode("ascii")
            for n in range(1, count + 1)]


def test_e5_an_older_build_s_run_beside_a_chained_one(tmp_path):
    old = old_run()
    rows = [old[0]] + made("r1", 3) + [old[1]]
    got = answer(rows)
    assert (got["old"]["state"], got["old"]["lines"]) == (event.UNCHAINED, 2) and got["r1"]["state"] == event.WHOLE
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and out.endswith("RESULT: every line is an event\n")   # as an older build's file exits
    assert run_line("old") + ("not chained, 2 line(s) (no line holds prev: written by a Raqib before this one,"
                              " version 0.2.0)\n") in out
    code, out = cli_events(tmp_path, old)
    assert code == 0 and run_line("old") + "not chained" in out


def test_e4_a_run_that_holds_prev_on_some_lines_and_not_on_others_is_broken(tmp_path):
    rows = made("r1", 4)
    bare = json.loads(rows[2])
    bare.pop("prev")
    rows = rows[:2] + [event.line(bare).encode("ascii")] + rows[3:]
    got = answer(rows)["r1"]["problems"]
    assert got[0] == {"what": event.BROKEN, "line": 3, "before": 2, "why": "none"}
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and "    broken at line 3: it holds no prev, in a run whose other lines hold it\n" in out


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
    assert code == 1 and "  line 3: not an event: not JSON" in out and run_line() + "chain whole, 3 line(s)" in out
    assert out.endswith("RESULT: 1 line(s) not an event\n")


def test_e4_a_run_s_name_is_said_escaped_and_never_makes_a_line_of_its_own(tmp_path):
    rows = made("r1\r\x1b[2KRESULT: every line is an event", 2)   # a carriage return and a terminal's escape
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and "  run r1\\r\\u001b[2KRESULT: every line is an event (host host.example): chain whole" in out
    assert "\r" not in out and "\x1b" not in out and out.count("RESULT: ") == 2


def test_e4_an_empty_file_and_a_file_of_no_event_say_no_chain(tmp_path):
    assert event.chains([]) == [] and event.chains([b"not json", b"{}", b"\xff"]) == []
    code, out = cli_events(tmp_path, [])
    assert code == 1 and " run " not in out


@pytest.mark.parametrize("rows", [[b"x"] * 3, [b""], [b"[]"], [b'{"watch":{"host":"h"}}']])
def test_e4_lines_that_name_no_host_and_run_are_no_link(rows):
    assert event.chains(rows) == []


# --- R1 (HA-1): a link is told by its shape ------------------------------------------------------------------

def test_r1_a_line_with_a_key_this_build_does_not_know_is_a_link_and_its_own_problem_is_named(tmp_path):
    rows = made("r1", 5, extra={3: {"later": 1}})
    assert event.check(json.loads(rows[2])) and event.check(json.loads(rows[3])) == []
    assert answer(rows)["r1"]["state"] == event.WHOLE   # the line after it is not said broken for it
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and "  line 3: later: not a key of a note event\n" in out
    assert run_line() + "chain whole, 5 line(s)\n" in out and "broken" not in out
    assert out.endswith("RESULT: 1 line(s) not an event\n")
    wrong = made("r1", 3)
    wrong[1] = wrong[1].replace(b'"prev":"', b'"prev":"X')   # a prev not of its shape: no link, a break
    assert answer(wrong)["r1"]["problems"][0] == {"what": event.BROKEN, "line": 2, "before": 1, "why": "prev"}


def test_r1_the_reader_s_section_says_a_torn_write_is_a_line_that_is_not_whole_json():
    text = " ".join(DOC.read_text(encoding="utf-8").split())
    reader = text[text.index("## For a reader of the file"):text.index("## Keys")]
    assert "a torn write is a line that is not whole json" in reader.lower()
    assert "a line that is not json (or not an event, `event.check`), in the middle of the file" not in reader


# --- R2 (HA-2): a chain taken out is said -----------------------------------------------------------------------

def test_r2_chain_since_is_one_constant():
    assert event.CHAIN_SINCE == (0, 4, 0)
    assert event.version_of("0.4.0") == (0, 4, 0) and event.version_of("0.10.2") == (0, 10, 2)
    for text in ("dev", "0.4", "0.4.0rc1", "v0.4.0", "", None, 4):
        assert event.version_of(text) is None, text


@pytest.mark.parametrize("versions,state,code,words", [
    (("0.2.0", "0.3.9"), event.UNCHAINED, 0, "not chained, 2 line(s) (no line holds prev: written by a Raqib before"
                                             " this one, version 0.2.0, 0.3.9)"),
    (("0.4.0", "0.4.0"), event.TAKEN, 1, "no line holds prev, yet its version 0.4.0 writes the chain (from 0.4.0):"
                                         " the chain was taken out, 2 line(s)"),
    (("0.3.0", "0.5.1"), event.TAKEN, 1, "no line holds prev, yet its version 0.5.1 writes the chain"),
    (("dev", "dev"), event.UNCHAINED, 0, "not chained, 2 line(s) (no line holds prev: its version is not read: dev)"),
    (("dev", "0.4.2"), event.TAKEN, 1, "no line holds prev, yet its version 0.4.2 writes the chain"),
])
def test_r2_a_run_with_no_prev_is_judged_by_the_versions_it_reads(tmp_path, versions, state, code, words):
    rows = [old_run(version=v, count=2)[i] for i, v in enumerate(versions)]
    assert answer(rows)["old"]["state"] == state
    got, out = cli_events(tmp_path, rows)
    assert got == code and run_line("old") + words in out, out
    if code:
        assert out.endswith("RESULT: every line is an event; 1 run(s) whose chain is not whole\n")


# --- R3 (HA-3): a run is its host's -----------------------------------------------------------------------------

def test_r3_two_hosts_runs_under_one_run_word_are_each_whole(tmp_path):
    a, b = made("r1", 3, host="a.example"), made("r1", 3, host="b.example")
    rows = [a[0], b[0], a[1], b[1], a[2], b[2]]
    got = event.chains(rows)
    assert [(c["host"], c["run"], c["state"], c["lines"]) for c in got] == [
        ("a.example", "r1", event.WHOLE, 3), ("b.example", "r1", event.WHOLE, 3)]
    code, out = cli_events(tmp_path, rows)
    assert code == 0 and run_line("r1", "a.example") + "chain whole, 3" in out
    assert run_line("r1", "b.example") + "chain whole, 3" in out


# --- R4 (HA-6): lines that are not the whole run ------------------------------------------------------------------

def test_r4_an_export_that_starts_mid_run_began_before_the_file_and_is_no_break(tmp_path):
    rows = made("r1", 6)[2:]
    got = answer(rows)["r1"]
    assert (got["state"], got["late"], got["problems"]) == (event.NOT_WHOLE, 1, [])
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and ("    begins before this file: its first line here, line 1, names a line that is not here (an"
                          " export that starts late, or a file whose beginning was cut)\n") in out
    assert "broken" not in out


def test_r4_a_line_sent_twice_is_counted_no_break_and_not_beside(tmp_path):
    rows = made("r1", 5)
    rows = rows[:3] + [rows[1]] + rows[3:] + [rows[4]]
    got = answer(rows)["r1"]
    assert (got["state"], got["lines"], got["twice"], got["problems"]) == (event.WHOLE, 5, 2, [])
    code, out = cli_events(tmp_path, rows)
    assert run_line() + "chain whole, 5 line(s), 2 said twice\n" in out
    assert "broken" not in out and "beside" not in out
    assert code == 1 and "said twice in the file (line 2)" in out   # the id said twice: a problem of the line, as today


# --- R5 (HA-7): every problem of a run, in the file's order, to a bound -------------------------------------------

def test_r5_a_break_after_a_line_beside_both_said(tmp_path):
    rows = made("r1", 6)
    side = event.line(event.chained(json.loads(made("r1", 1, start=9)[0]), json.loads(rows[2])["prev"]))
    rows = rows[:2] + [side.encode("ascii")] + rows[2:4] + rows[5:]   # a line beside at 3; line 5 of the run removed
    got = answer(rows)["r1"]["problems"]
    assert got == [{"what": event.BESIDE, "first": 3, "last": 3, "count": 1, "named": 2, "again": 4},
                   {"what": event.BROKEN, "line": 6, "before": 5, "why": "names"}]
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and out.index("line(s) beside the chain, line 3") < out.index("    broken at line 6:")


def test_r5_twelve_breaks_ten_said_and_the_bound_said(tmp_path):
    rows = made("r1", 25)[::2]   # every other line removed: twelve breaks
    got = answer(rows)["r1"]
    assert [p["line"] for p in got["problems"]] == list(range(2, 12)) and got["more"] == 2
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and out.count("    broken at line ") == 10
    assert "    the bound of 10 a run reached: 2 more not listed\n" in out


# --- R6 (HA-5): the collector's lines beside the file -------------------------------------------------------------

def other(tmp_path, rows, name="held.jsonl"):
    path = tmp_path / name
    path.write_bytes(b"".join(r + b"\n" for r in rows))
    return str(path)


def test_r6_equal_files_and_without_against_nothing_changes(tmp_path):
    rows = made("r1", 4)
    code, out = cli_events(tmp_path, rows, against=other(tmp_path, rows))
    assert code == 0 and "4 line(s), 4 in the file byte for byte, 0 not in it, 0 with other bytes, 0 not read" in out
    assert out.endswith("RESULT: every line is an event\n")
    code, plain = cli_events(tmp_path, rows)
    assert code == 0 and " against " not in plain


def test_r6_a_line_changed_in_the_file_after_the_collector_took_it_is_seen_only_side_by_side(tmp_path):
    rows = made("r1", 5)
    held = other(tmp_path, rows)
    changed = again(rows[:2] + [rows[2].replace(b"note 3 of", b"note 7 of")] + rows[3:], 2)   # the tail chained again
    assert answer(changed)["r1"]["state"] == event.WHOLE and answer(rows)["r1"]["state"] == event.WHOLE
    code, out = cli_events(tmp_path, changed, against=held)
    assert code == 1 and "5 line(s), 2 in the file byte for byte, 0 not in it, 3 with other bytes" in out
    assert "    line 3 of %s (id r1:3, host host.example): the file's line 3 holds other bytes\n" % held in out
    assert out.endswith("RESULT: every line is an event; 3 line(s) of the collector's with other bytes\n")


def test_r6_a_line_the_collector_holds_that_the_file_lacks_is_said(tmp_path):
    rows = made("r1", 5)
    code, out = cli_events(tmp_path, rows[:3], against=other(tmp_path, rows))   # the file's end cut (H-5): seen here
    assert code == 1 and "5 line(s), 3 in the file byte for byte, 2 not in it" in out
    assert "(id r1:4, host host.example): not in the file\n" in out
    assert "; 2 line(s) of the collector's not in the file" in out.splitlines()[-1]


def test_r6_a_collector_behind_is_not_a_problem_and_other_unreadable_is_2(tmp_path, capsys):
    rows = made("r1", 5)
    code, out = cli_events(tmp_path, rows, against=other(tmp_path, rows[:3] + [b"not a line of raqib"]))
    assert code == 0 and "4 line(s), 3 in the file byte for byte, 0 not in it, 0 with other bytes, 1 not read" in out
    assert "; 2 line(s) of the file it does not hold (a collector behind: not a problem)" in out
    path = tmp_path / "events.jsonl"
    assert cli.main(["events", str(path), "--against", str(tmp_path / "missing.jsonl")]) == 2
    assert "cannot read" in capsys.readouterr().err
    crlf = other(tmp_path, [r + b"\r" for r in rows], name="crlf.jsonl")   # a copy whose line ends are Windows'
    assert cli.main(["events", str(path), "--against", crlf]) == 0


def test_r6_the_lines_said_are_bounded(tmp_path):
    rows = made("r1", 14)
    code, out = cli_events(tmp_path, rows[:1], against=other(tmp_path, rows))
    assert code == 1 and out.count("): not in the file\n") == 10 and "    the bound of 10 reached: 3 more not listed" in out


# --- R7 (HA-4, H-5): the limits, said in tests ------------------------------------------------------------------

def test_r7_a_tail_written_again_with_new_hashes_is_not_seen_from_the_file_alone(tmp_path):
    """H-5: whoever can write the file can write a tail again from any line and compute the hashes again: the
    check then says whole. It holds no secret; only the collector's lines beside it (--against) show it."""
    rows = made("r1", 5)
    forged = again(rows[:2] + [b.replace(b" of r1", b" OF r1") for b in rows[2:]], 2)
    assert forged != rows and answer(forged)["r1"]["state"] == event.WHOLE   # NOT seen
    assert cli_events(tmp_path, forged)[0] == 0


def test_r7_the_run_s_last_line_changed_or_named_by_a_line_added_after_it_is_not_seen(tmp_path):
    """HA-4: no line names a run's last line: changed, or followed by a line added after the run ended that names
    it, it is not seen from the file alone."""
    rows = made("r1", 4)
    last = rows[:3] + [rows[3].replace(b"note 4 of", b"note 8 of")]
    assert answer(last)["r1"]["state"] == event.WHOLE   # NOT seen
    added = event.line(event.chained(json.loads(made("r1", 1, start=5)[0]), hashlib.sha256(rows[3]).hexdigest()))
    assert answer(rows + [added.encode("ascii")])["r1"]["state"] == event.WHOLE   # NOT seen


def test_r7_the_words_say_the_last_line_s_limit_and_the_base_keys_leave_prev_out():
    flat = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "(`schema` to `severity` but `prev`" in flat
    for path in (DOC, ROOT / "docs" / "GUIDE.md", ROOT / "docs" / "THREAT_MODEL.md"):   # each bullet, row or entry
        blocks = re.split(r"\n(?:\s*- |\||\n)", path.read_text(encoding="utf-8").replace("\r\n", "\n"))
        said = [b for b in blocks if "changed, added" in " ".join(b.split())]
        assert said, path.name
        for block in said:
            assert "last line" in " ".join(block.split()), (path.name, block[:200])
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    assert "--against" in threat


# --- R8 (HA-8): the spec's made-up chained run ---------------------------------------------------------------------

def test_r8_the_spec_s_made_up_run_is_two_events_chained_as_the_document_writes_them():
    text = DOC.read_text(encoding="utf-8").replace("\r\n", "\n")
    m = re.search(r"^### a chained run, made up\n(?:(?!#|```).*\n)*?```jsonl\n(.+)\n(.+)\n```", text, re.M)
    assert m and "### example:" not in m.group(0)
    one, two = m.group(1), m.group(2)
    for line in (one, two):
        assert event.check(json.loads(line)) == []
    assert json.loads(one)["prev"] == "first"
    assert json.loads(two)["prev"] == hashlib.sha256(one.encode("ascii")).hexdigest()
    assert [c["state"] for c in event.chains([one.encode("ascii"), two.encode("ascii")])] == [event.WHOLE]


# --- R9 (HA-9): a line that cannot be read does not end the reader -----------------------------------------------------

def test_r9_a_line_nested_deeper_than_can_be_read_is_not_an_event_and_no_link(tmp_path):
    deep = b"[" * 100000 + b"]" * 100000
    rows = made("r1", 3)
    rows = rows[:1] + [deep] + rows[1:]
    assert [c["state"] for c in event.chains(rows)] == [event.WHOLE]
    code, out = cli_events(tmp_path, rows)
    assert code == 1 and "  line 2: not an event: not JSON (nested deeper than can be read)\n" in out
    assert run_line() + "chain whole, 3 line(s)" in out
    assert event.against(rows, [deep])["unread"] == 1


# --- R10 (HA-10): the writer's first write fails; the file is replaced under a running watch ------------------------

def test_r10_a_run_whose_first_write_fails_says_first_on_its_first_written_line(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    monkeypatch.setattr(eventlog, "open", Failing(whole=False), raising=False)
    assert log.say("note:1", lambda n, rev: event.note("a", facts("r1"), T0, n, "note:1", rev))[0] == "not written"
    assert log.head is None
    say_notes(log, "r1", ["a", "b"])
    rows = path.read_bytes().split(b"\n")[:-1]
    assert [json.loads(r)["n"] for r in rows] == [2, 3] and json.loads(rows[0])["prev"] == "first"
    assert answer(rows)["r1"]["state"] == event.WHOLE


def test_r10_a_file_replaced_under_a_running_watch_is_said(tmp_path):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), facts("r1"), {})
    say_notes(log, "r1", ["a", "b"])
    (tmp_path / "other.jsonl").write_bytes(b"".join(r + b"\n" for r in old_run()))
    os.replace(str(tmp_path / "other.jsonl"), str(path))   # another file where the watch's was
    log.say("note:3", lambda n, rev: event.note("c", facts("r1"), T0, n, "note:3", rev))
    rows = path.read_bytes().split(b"\n")[:-1]
    assert len(rows) == 3 and answer(rows)["r1"]["late"] == 3   # its line names a line that is not there
    code, out = cli_events(tmp_path, rows, name="copy.jsonl")
    assert code == 1 and "    begins before this file: its first line here, line 3," in out
