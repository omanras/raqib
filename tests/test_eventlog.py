"""M10.2 (ADR-0011 Amendment F, F-1 to F-9): the watch writes its events.

E1 the writer alone (raqib/eventlog.py), without a watch. E2 to E6 through
fixture watches made as tests/test_event.py makes them (its runs B, C, R, H,
L, F, A, P), each in its own temporary home, the host's name the system gives
replaced by host.example (no real name is read into any line here). The
events file is read back and held against the report, the state and
event.snapshot of the same watch.
"""
import copy
import io
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import cli, event, eventlog, host, report  # noqa: E402
from hostthreads import raqib_threads_end  # noqa: E402,F401  (every HostWatch ended, no thread leaked)
import test_event as te  # noqa: E402
import test_host as th  # noqa: E402

HOST = te.HOST   # host.example
FACTS = event.facts({"run": "unit-run", "mode": "host", "platform": "test"}, host=HOST)
T0 = "2026-11-03T10:00:00.000Z"
T1 = "2026-11-03T10:00:10.000Z"


def lines_of(path):
    return [json.loads(ln) for ln in Path(path).read_text(encoding="ascii").splitlines()]


def note_builder(text, time=T0):
    return lambda n, rev: event.note(text, FACTS, time, n, "note:1", rev)


# --- E1 (F-1): the writer -----------------------------------------------------------------------------------

def test_e1_new_same_again_changed_and_two_things(tmp_path):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), FACTS, {})
    assert log.say("note:1", note_builder("first words"))[0] == "written"
    assert log.say("note:1", note_builder("first words", T1))[0] == "same"   # the same again: nothing (a new time)
    assert len(lines_of(path)) == 1
    assert log.say("note:1", note_builder("other words"))[0] == "written"   # changed: rev 2
    assert log.say("hole:1", lambda n, rev: event.hole({"kind": "reader-failed", "detail": "round 2: failed"},
                                                       FACTS, T1, n, "hole:1", rev))[0] == "written"
    got = lines_of(path)
    assert [(e["about"], e["rev"], e["n"]) for e in got] == [("note:1", 1, 1), ("note:1", 2, 2), ("hole:1", 1, 3)]
    assert [e["summary"] for e in got[:2]] == ["first words", "other words"]
    assert all(event.check(e) == [] for e in got)
    assert (log.written, log.heartbeats, log.not_built, log.not_written) == (3, 0, 0, 0)
    raw = path.read_text(encoding="ascii")
    assert raw.endswith("\n") and raw.splitlines()[0] == event.line(got[0])   # one line each, event.line


def test_e1_an_id_is_never_written_twice_in_a_run(tmp_path):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), FACTS, {}, beat=10)
    log.start(T0, 0.0)
    for k in range(6):
        log.say("note:%d" % (k % 3 + 1), lambda n, rev, k=k: event.note("words %d" % (k // 2), FACTS, T0, n,
                                                                        "note:%d" % (k % 3 + 1), rev))
        if log.due(k * 5.0):
            log.heartbeat({"band": "WATCHING", "code_so_far": 0, "host": {"rounds": k}}, T1, k * 5.0)
    log.end({"host": {"rounds": 6}}, T1, 0)
    got = lines_of(path)
    ids = [e["id"] for e in got]
    assert len(ids) == len(set(ids)) and [e["n"] for e in got] == list(range(1, len(got) + 1))
    assert [e["rev"] for e in got if e["about"] == "watch"] == list(range(1, 1 + sum(
        e["about"] == "watch" for e in got)))


def test_e1_a_builder_that_raises_is_one_problem_per_thing_and_writes_nothing(tmp_path):
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), FACTS, {})

    def broken(n, rev):
        return event.hole({"kind": "x", "detail": "y"}, dict(FACTS, run=""), T0, n, "hole:1", rev)
    what, detail = log.say("hole:1", broken)
    assert what == "not built" and detail.startswith("hole:1: ") and "watch.run" in detail
    assert log.say("hole:1", broken) == ("not built", None)   # said once
    assert log.not_built == 1 and log.n == 0 and not path.exists()


def test_e1_a_file_that_cannot_be_written_is_said_once_and_counted(tmp_path):
    (tmp_path / "events.jsonl").mkdir()
    log = eventlog.EventLog(str(tmp_path / "events.jsonl"), FACTS, {})
    first = log.say("note:1", note_builder("a"))
    again = log.say("note:2", lambda n, rev: event.note("b", FACTS, T0, n, "note:2", rev))
    assert first[0] == "not written" and "cannot append to" in first[1] and again == ("not written", None)
    assert (log.not_written, log.written, log.n) == (2, 0, 2)   # the numbers are used: a collector sees the gap


def test_e6_the_host_s_name_is_given_or_the_system_s_or_unnamed():
    assert eventlog.host_name("host.example") == ("host.example", "given")
    assert eventlog.host_name(None, system=lambda: "host.example") == ("host.example", "system")
    assert eventlog.host_name(None, system=lambda: "") == (eventlog.UNNAMED, "none")

    def fails():
        raise OSError("no name")
    assert eventlog.host_name(" ", system=fails) == ("unnamed", "none")
    src = (ROOT / "raqib" / "eventlog.py").read_text(encoding="ascii")
    for call in ("getfqdn", "gethostbyname", "getaddrinfo", "urllib", "http", "connect("):   # rule 5: no network
        assert call not in src, call


# --- the fixture watches ------------------------------------------------------------------------------------

def unbuildable_table(rules, real=report.rule_table):
    return [r for r in real(rules) if r["id"] != "NEW-AGENT-UNKNOWN"]


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    out = {}
    with pytest.MonkeyPatch.context() as mp:
        home = tmp_path_factory.mktemp("eventlog-home")
        mp.setenv("HOME", str(home))
        mp.setenv("USERPROFILE", str(home))
        mp.setattr(eventlog._platform, "node", lambda: HOST)   # never the machine's own name in a test
        for name, fn in (("B", te.run_b), ("C", te.run_c), ("R", te.run_r), ("H", te.run_h), ("L", te.run_l),
                         ("F", te.run_f), ("A", te.run_a), ("P", te.run_p), ("D", te.run_d)):
            out[name] = fn(tmp_path_factory.mktemp("eventlog-" + name.lower()))
        # E2: run B whose decisions fail until the finish: its source findings are said not settled, then settled
        late = {"fail": True}
        decide, finish = host.HostWatch._decide, host.HostWatch.finish

        def failing(self, now, act):
            if late["fail"]:
                raise RuntimeError("cannot decide yet (test)")
            return decide(self, now, act)
        mp.setattr(host.HostWatch, "_decide", failing)
        mp.setattr(host.HostWatch, "finish", lambda self, *a, **k: (late.update(fail=False), finish(self, *a, **k))[1])
        out["N-late"] = te.run_b(tmp_path_factory.mktemp("eventlog-n-late"))
        mp.setattr(host.HostWatch, "_decide", decide)
        mp.setattr(host.HostWatch, "finish", finish)
        mp.setattr(eventlog, "BEAT_DEFAULT", 1e6)   # E3: no beat within the watch
        out["B-nobeat"] = te.run_b(tmp_path_factory.mktemp("eventlog-b-nobeat"))
        out["L-nobeat"] = te.run_l(tmp_path_factory.mktemp("eventlog-l-nobeat"))
        mp.setattr(eventlog, "BEAT_DEFAULT", 10.0)   # E3: a beat every round
        out["B-beat"] = te.run_b(tmp_path_factory.mktemp("eventlog-b-beat"))
        mp.setattr(report, "rule_table", unbuildable_table)   # E4: one finding the builder refuses
        out["B-unbuilt"] = te.run_b(tmp_path_factory.mktemp("eventlog-b-unbuilt"))
        mp.setattr(report, "rule_table", unbuildable_table.__defaults__[0])
        tmp = tmp_path_factory.mktemp("eventlog-b-dir")
        (tmp / ".raqib" / "host" / "events.jsonl").mkdir(parents=True)   # E4: a file that cannot be written
        out["B-dir"] = te.run_b(tmp)
    for r in out.values():
        r["file"] = r["w"].events_path
        r["lines"] = lines_of(r["file"]) if Path(r["file"]).is_file() else None
    return out


MAIN = ("B", "C", "R", "H", "L", "F", "A", "P", "D", "N-late")


def last_by_about(events):
    out = {}
    for e in events:
        out[e["about"]] = e
    return out


def without(e, keys=eventlog.VARY):
    return {k: v for k, v in e.items() if k not in keys}


# --- E2 (F-2): the pass ----------------------------------------------------------------------------------------

def test_e2_every_line_is_an_event_the_first_the_start_the_last_the_end_with_the_report_s_result(runs):
    for name in MAIN:
        r = runs[name]
        got = r["lines"]
        assert got and all(event.check(e) == [] for e in got), name
        assert (got[0]["kind"], got[0]["state"], got[0]["rev"], got[0]["n"]) == ("watch", "start", 1, 1), name
        end = got[-1]
        assert (end["kind"], end["state"]) == ("watch", "end"), name
        word = re.search(r"^RESULT: ([A-Z-]+) \(exit (\d+):", r["report"], re.M)
        assert end["result"]["exit"] == r["code"] == int(word.group(2)), name
        assert end["result"]["word"] == event.WORDS[r["code"]], name
        if word.group(1) in ("ALARM", "INCOMPLETE", "CLEAN"):
            assert end["result"]["word"] == word.group(1), name
        assert [e["n"] for e in got] == list(range(1, len(got) + 1)) and len({e["id"] for e in got}) == len(got)
        assert sum(e["kind"] == "watch" for e in got) == 2, name   # one start, one end


def test_e2_each_finding_and_source_finding_of_the_report_has_its_event(runs):
    seen = set()
    for name in MAIN:
        r = runs[name]
        last = last_by_about(r["lines"])
        for i, f in enumerate(r["w"].findings, 1):
            assert last["finding:%d" % i]["rule"]["id"] == f["rule_id"] and f["summary"] in r["report"], name
            seen.add("finding")
        for i, f in enumerate(r["w"].source_findings, 1):
            ev = last["source-finding:%d" % i]
            assert ev["rule"]["id"] == f["rule_id"] and ev["state"] == event.source_state(f), name
            seen.add("source-finding")
        trees = {"tree:%s" % host.tree_word(k) for k in r["w"].trees}
        assert trees <= set(last), name
    assert seen == {"finding", "source-finding"}


def test_e2_a_source_finding_said_before_it_settled_is_said_again_when_settled(runs):
    again = []
    for name in MAIN:
        by = {}
        for e in runs[name]["lines"]:
            if e["kind"] == "source-finding":
                by.setdefault(e["about"], []).append(e)
        for about, evs in by.items():
            assert [e["rev"] for e in evs] == list(range(1, len(evs) + 1)), (name, about)
            if evs[0]["state"] != "settled" and evs[-1]["state"] == "settled":
                again.append((name, about, evs[0]["state"], len(evs)))
    assert again, "no source finding said before it settled"
    assert all(k >= 2 for _, _, _, k in again)


def test_e2_a_notifier_s_hole_made_before_a_watch_s_hole_keeps_its_name(runs):
    got = runs["H"]["lines"]
    holes = [e for e in got if e["kind"] == "hole"]
    order = [e["about"] for e in holes if e["rev"] == 1]
    assert order.index("notifier-hole:1") < order.index("hole:1")   # the notifier's hole was made first
    assert all("count" in e["hole"] for e in holes if e["about"].startswith("notifier-hole:"))
    assert all("count" not in e["hole"] for e in holes if e["about"].startswith("hole:"))
    assert {e["hole"]["kind"] for e in holes if e["about"] == "hole:1"} == {"reader-failed"}
    assert len(runs["H"]["w"].notifier.holes) == len({e["about"] for e in holes
                                                       if e["about"].startswith("notifier-hole:")})


def test_e2_the_file_read_back_is_the_snapshot_of_the_final_state(runs):
    for name in MAIN:
        r = runs[name]
        mine, snap = last_by_about(r["lines"]), last_by_about(r["events"])
        assert set(mine) == set(snap), (name, set(mine) ^ set(snap))
        for about in snap:
            assert without(mine[about]) == without(snap[about]), (name, about)


def test_e2_a_dark_note_the_lost_words_note_and_a_rhythm_finding_reach_the_file(runs):
    assert any(e["kind"] == "note" and "subject" in e for e in runs["A"]["lines"])   # a dark note, its footprint
    assert any(e["about"] == event.LOST for e in runs["L"]["lines"])
    assert any(e.get("rule", {}).get("id") == "HOST-RHYTHM" for e in runs["R"]["lines"])
    assert any(e["about"].startswith("blind:") for e in runs["B"]["lines"])


# --- E3 (F-3): the beat --------------------------------------------------------------------------------------

def test_e3_watch_is_rev_1_at_the_start_and_one_more_for_each_beat_and_the_end(runs):
    for name in MAIN + ("B-beat",):
        w = [e for e in runs[name]["lines"] if e["about"] == "watch"]
        assert [e["rev"] for e in w] == list(range(1, len(w) + 1)), name
        assert [e["kind"] for e in w] == ["watch"] + ["heartbeat"] * (len(w) - 2) + ["watch"], name
    assert sum(e["kind"] == "heartbeat" for e in runs["B-beat"]["lines"]) >= 2


def steady(tmp_path, monkeypatch, beat, rounds):
    """A watch of identical rounds on the fake clock (a round every 10 s), its file's line count after each tick."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    monkeypatch.setattr(eventlog, "BEAT_DEFAULT", float(beat))
    w, clock = th.make_host(tmp_path, ["windows"] * rounds)
    counts = []
    for _ in range(rounds):
        th.run_rounds(w, clock, 1)
        counts.append(len(lines_of(w.events_path)))
    w.finish()
    return w, counts, lines_of(w.events_path)


def test_e3_a_heartbeat_at_each_beat_and_none_between_and_a_quiet_round_writes_nothing(tmp_path, monkeypatch):
    w, counts, got = steady(tmp_path, monkeypatch, 30, 10)
    beats = [e for e in got if e["kind"] == "heartbeat"]
    assert len(beats) == 3   # ticks at 0, 10, ..., 90 s: beats at 30, 60 and 90 s
    stamps = [event.datetime.datetime.strptime(e["time"][:-1], "%Y-%m-%dT%H:%M:%S.%f") for e in beats]
    assert [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])] == [30.0, 30.0]
    added = [b - a for a, b in zip(counts, counts[1:])]   # what rounds 2..10 wrote
    for k, extra in enumerate(added, 2):
        if k <= 3:   # rounds 1 to 3 change: the trees, then the footprints dark for 3 rounds (AGENT-DARK-LIVE)
            continue
        if k in (4, 7, 10):   # a due beat: the heartbeat, and only a re-saying of what waits for a beat before it
            assert extra >= 1
        else:
            assert extra == 0, (k, extra)
    at_beats = [e for e in got if e["kind"] != "heartbeat" and e["rev"] > 1 and e["about"] != "watch"]
    assert all(e["kind"] == "tree" or e["about"].startswith("blind:") or e["about"] == event.LOST
               for e in at_beats)


def test_e3_a_blind_spot_s_count_and_the_lost_words_are_said_again_only_with_a_beat(runs):
    for name, about in (("B-nobeat", "blind:1"), ("L-nobeat", event.LOST)):
        evs = [e for e in runs[name]["lines"] if e["about"] == about]
        assert 1 <= len(evs) <= 2, (name, len(evs))   # rev 1 when new, and at most once more: at the end
        assert not any(e["kind"] == "heartbeat" for e in runs[name]["lines"])
    lost = [m["lost"] for m in runs["L-nobeat"]["moments"] if m["lost"]]
    assert len(set(lost)) > 2   # the words changed in more rounds than the file says them
    blind = [len(m["state"]["host"]["blind"][0]["rounds"]) for m in runs["B-nobeat"]["moments"]
             if m["state"]["host"]["blind"]]
    assert len(set(blind)) >= 2
    beat = [e for e in runs["B-beat"]["lines"] if e["about"] == "blind:1"]
    assert len(beat) >= len([e for e in runs["B-nobeat"]["lines"] if e["about"] == "blind:1"])


def test_e3_beat_is_never_shorter_than_a_round_less_is_a_usage_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cli.main(["watch", "--host", "--every", "10", "--beat", "5"]) == 2
    assert "--beat must be a number of seconds from the round's interval" in capsys.readouterr().err
    assert cli.main(["watch", "--beat", "60"]) == 2
    assert cli.main(["watch", "--event-host", "host.example"]) == 2
    w, _ = th.make_host(tmp_path, ["windows"], every=90)
    assert w.events.beat == 90.0   # the default, 60 s, is never shorter than the round
    w.finish()


# --- E4 (F-4): what cannot be said is said ----------------------------------------------------------------------

def test_e4_a_builder_that_raises_is_one_hole_naming_the_thing_and_the_key_and_the_pass_goes_on(runs):
    r = runs["B-unbuilt"]
    holes = [h for h in r["w"].holes if h["kind"] == "event-not-built"]
    assert len(holes) == 1 and holes[0]["detail"].startswith("finding:1: ") and "rule.attack" in holes[0]["detail"]
    abouts = {e["about"] for e in r["lines"]}
    assert "finding:1" not in abouts and any(a.startswith("source-finding:") for a in abouts)
    assert any(e["kind"] == "hole" and e["hole"]["kind"] == "event-not-built" for e in r["lines"])
    assert r["lines"][-1]["state"] == "end" and r["state"]["events"]["not_built"] == 1
    assert "not built 1" in r["report"]


def test_e4_a_file_that_cannot_be_written_is_one_hole_counted_in_the_report_and_the_state(runs):
    r = runs["B-dir"]
    assert r["lines"] is None and Path(r["file"]).is_dir()
    holes = [h for h in r["w"].holes if h["kind"] == "events-unwritable"]
    assert len(holes) == 1 and "cannot append to" in holes[0]["detail"]
    ev = r["state"]["events"]
    assert ev["written"] == 0 and ev["not_written"] > 0
    assert re.search(r"^EVENTS: written 0 \(heartbeats 0, .*\), not built 0, not written %d; " % ev["not_written"],
                     r["report"], re.M)
    assert re.search(r"^RESULT: ", r["report"], re.M) and r["code"] in (1, 3)


def test_e4_a_cite_left_out_is_counted_and_no_event_holds_an_empty_list(runs):
    st = runs["B"]["state"]
    f = copy.deepcopy(st["host"]["findings"][0])
    assert len(f["cites"]) >= 2
    rule = te.TABLE[f["rule_id"]]
    del f["cites"][0]["src"]
    one = event.finding(f, te.facts(st), T0, 1, "finding:1", rule=rule)
    assert one["evidence"]["cites_left_out"] == 1 and len(one["evidence"]["cites"]) == len(f["cites"]) - 1
    for c in f["cites"]:
        c.pop("line", None)
    every = event.finding(f, te.facts(st), T0, 1, "finding:1", rule=rule)
    assert "cites" not in every["evidence"] and every["evidence"]["cites_left_out"] == len(f["cites"])
    built = copy.deepcopy(one)
    built["evidence"]["cites"] = []
    assert any(p.startswith("evidence.cites: ") for p in event.check(built))
    for name in MAIN:
        assert not any(e.get("evidence", {}).get("cites") == [] for e in runs[name]["lines"])


# --- E5 (F-5, F-6): the knock's thing, the tree's road, the host's name ---------------------------------------

def test_e5_every_knock_names_the_thing_it_knocked_for(runs):
    count = 0
    for name in MAIN:
        r = runs[name]
        abouts = {e["about"] for e in r["lines"] if e["kind"] != "knock"}
        for e in r["lines"]:
            if e["kind"] == "knock":
                assert e["knocked"].get("for") in abouts, (name, e["about"], e["knocked"].get("for"))
                count += 1
    assert count >= 3
    built = copy.deepcopy(next(e for e in runs["B"]["lines"] if e["kind"] == "finding"))
    built["knocked"]["for"] = "finding:1"
    assert any(p.startswith("knocked.for: ") for p in event.check(built))   # on a knock event only


def test_e5_a_tree_says_how_it_became_a_candidate_from_its_row(runs):
    said = 0
    for name in MAIN:
        rows = {"tree:%s" % host.tree_word(k): t for k, t in runs[name]["w"].trees.items()}
        for e in last_by_about(runs[name]["lines"]).values():
            if e["kind"] == "tree":
                row = rows[e["about"]]
                assert e["subject"].get("by") == row.get("candidate_by"), (name, e["about"])
                said += "by" in e["subject"]
    assert said >= 2


def test_e5_the_host_is_read_once_or_given_and_unnamed_is_said_at_the_start(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(eventlog._platform, "node", lambda: "")
    monkeypatch.setattr(eventlog._platform, "node", lambda: "")
    w, clock = th.make_host(tmp_path, ["windows", "windows"])
    lines = host.event_lines(w)
    assert lines[0].startswith("events %s (raqib-event/1" % w.events_path) and "a heartbeat every 60 s" in lines[0]
    assert lines[1] == ("events: the system gives no host name: the events say \"unnamed\" (--event-host NAME"
                        " names it)")
    th.run_rounds(w, clock, 2)
    w.finish()
    assert {e["watch"]["host"] for e in lines_of(w.events_path)} == {"unnamed"}
    calls = []
    monkeypatch.setattr(eventlog._platform, "node", lambda: calls.append(1) or "host.example")
    w2 = host.HostWatch(lambda: th.inv("windows"), th.CATALOG, th.RULES, th.make_notifier(th.FakeRunner()),
                        out=io.StringIO(), err=io.StringIO(), clock=th.Clock(), home=str(tmp_path / "two"),
                        platform="test", event_host="host.example")
    assert calls == [] and w2.event_host == "host.example" and host.event_lines(w2)[1] == (
        "events: host host.example (--event-host)")
    w2.finish()
    assert {e["watch"]["host"] for e in lines_of(w2.events_path)} == {"host.example"}


# --- E6 (F-7, F-8): what the person is told; raqib events FILE ----------------------------------------------

def test_e6_the_report_s_events_line_and_the_state_carry_the_same_numbers_as_the_file(runs):
    for name in MAIN:
        r = runs[name]
        ev = r["state"]["events"]
        m = re.search(r"^EVENTS: written (\d+) \(heartbeats (\d+), one every (\S+) s\), not built (\d+), not"
                      r" written (\d+); file (.+) \(raqib-event/1, appended; host (\S+); nothing is sent\)$",
                      r["report"], re.M)
        assert m, name
        assert (int(m.group(1)), int(m.group(2)), int(m.group(4)), int(m.group(5))) == (
            ev["written"], ev["heartbeats"], ev["not_built"], ev["not_written"]), name
        assert ev["written"] == len(r["lines"]) and ev["heartbeats"] == sum(e["kind"] == "heartbeat"
                                                                            for e in r["lines"])
        assert m.group(6) == r["file"] and m.group(7) == HOST and float(m.group(3)) == ev["beat_seconds"]
        assert r["report"].index("\nKNOCKS: ") < r["report"].index("\nEVENTS: ")


def test_e6_raqib_events_checks_a_good_file(runs, capsys):
    assert cli.main(["events", runs["B"]["file"]]) == 0
    out = capsys.readouterr().out
    got = runs["B"]["lines"]
    assert "%d line(s), %d event(s)" % (len(got), len(got)) in out and out.rstrip().endswith(
        "RESULT: every line is an event")
    for kind in {e["kind"] for e in got}:
        assert "  %s: %d\n" % (kind, sum(e["kind"] == kind for e in got)) in out


def test_e6_raqib_events_names_the_bad_line_and_a_missing_file_is_2(runs, tmp_path, capsys):
    got = copy.deepcopy(runs["B"]["lines"])
    got[2]["severity"] = "bogus"   # a built event with one value changed
    bad = tmp_path / "bad.jsonl"
    bad.write_text("".join(event.line(e) + "\n" for e in got), encoding="ascii")
    assert cli.main(["events", str(bad)]) == 1
    out = capsys.readouterr().out
    assert "line 3: severity: " in out and "RESULT: 1 line(s) not an event" in out
    assert cli.main(["events", str(tmp_path / "missing.jsonl")]) == 2
    assert "cannot read" in capsys.readouterr().err
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="ascii")
    assert cli.main(["events", str(empty)]) == 1   # silence is a finding


def test_e6_the_first_lines_name_the_file_and_the_beat(runs):
    w = runs["B"]["w"]
    first = host.event_lines(w)
    assert first[0] == ("events %s (raqib-event/1, one line appended for each thing new or changed; a heartbeat"
                        " every 60 s; nothing is sent)" % w.events_path)
    assert first[1] == "events: host host.example (the system's name)"


def test_e7_the_rig_s_check_reads_a_fixture_watch_s_report_and_events_as_met(runs):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rig_check", ROOT / "tools" / "rig" / "check.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    for name in MAIN:
        r = runs[name]
        text = Path(r["file"]).read_text(encoding="ascii")
        got = {i.split(" ", 1)[0]: s for i, s, _ in check.read(r["report"], "", (), r["code"], "test", False, text)}
        assert [got[k] for k in ("X16", "X17", "X18")] == [check.MET] * 3, (name, got)
    bad = check.read(runs["B"]["report"], "", (), runs["B"]["code"], "test", False, "")
    assert [s for i, s, _ in bad if i.startswith("X16")] == [check.MISSED]


def test_ascii():
    for name in ("raqib/eventlog.py", "raqib/event.py", "raqib/host.py", "raqib/cli.py", "tests/test_eventlog.py",
                 "tools/rig/check.py"):
        (ROOT / name).read_bytes().decode("ascii")
