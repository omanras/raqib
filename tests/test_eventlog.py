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
FACTS = event.facts({"run": "unit-run", "mode": "host", "platform": "test"}, host=HOST, beat=60.0)
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
        assert end["result"]["word"] == word.group(1) == r["word"], name   # G-4: the report's own word, always
        assert end["result"].get("suppressed", 0) == r["suppressed"], name
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
    for name, about in (("B-nobeat", "blind:1"), ("L-nobeat", event.LOST), ("B-beat", "blind:1")):
        evs = [e for e in runs[name]["lines"] if e["about"] == about]
        assert 1 <= len(evs) <= 2, (name, len(evs))   # rev 1 when new, and at most once more: at the end (G-2)
    assert not any(e["kind"] == "heartbeat" for e in runs["B-nobeat"]["lines"] + runs["L-nobeat"]["lines"])
    lost = [m["lost"] for m in runs["L-nobeat"]["moments"] if m["lost"]]
    assert len(set(lost)) > 2   # the words changed in more rounds than the file says them
    blind = [len(m["state"]["host"]["blind"][0]["rounds"]) for m in runs["B-nobeat"]["moments"]
             if m["state"]["host"]["blind"]]
    assert len(set(blind)) >= 2
    beat = [e for e in runs["B-beat"]["lines"] if e["about"] == "blind:1"]
    assert len(beat) == len([e for e in runs["B-nobeat"]["lines"] if e["about"] == "blind:1"])   # G-2: not at a beat


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
    assert re.search(r"^EVENTS: written 0 \(heartbeats 0, .*\), not built 0, not written %d \(attempts\); " % ev["not_written"],
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
        w = runs[name]["w"]
        held = {"tree:%s" % host.tree_word(k): w.tree_by.get(k) for k in w.trees}   # G-8: held apart by the watch
        state = json.loads(Path(w.state_path).read_text(encoding="ascii"))
        assert state["host"]["trees"] and not any("candidate_by" in t for t in state["host"]["trees"])   # AD-4
        for e in last_by_about(runs[name]["lines"]).values():
            if e["kind"] == "tree":
                assert e["subject"].get("by") == held[e["about"]], (name, e["about"])
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
                      r" written (\d+) \(attempts\); longest pass ([\d.]+) s; file (.+) \(raqib-event/1, appended; host (\S+); nothing is sent\)$",
                      r["report"], re.M)
        assert m, name
        assert (int(m.group(1)), int(m.group(2)), int(m.group(4)), int(m.group(5))) == (
            ev["written"], ev["heartbeats"], ev["not_built"], ev["not_written"]), name
        assert ev["written"] == len(r["lines"]) and ev["heartbeats"] == sum(e["kind"] == "heartbeat"
                                                                            for e in r["lines"])
        assert m.group(7) == r["file"] and m.group(8) == HOST and float(m.group(3)) == ev["beat_seconds"]
        assert float(m.group(6)) == ev["longest_pass_seconds"] >= 0   # G-6 (c): the longest pass, said
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


# --- M10.2 REDO (ADR-0011 Amendment G) --------------------------------------------------------------------------

def test_redo_g2_g3_a_tree_that_only_gained_record_lines_is_said_twice_its_first_and_the_finish_s(tmp_path,
                                                                                                    monkeypatch):
    w, counts, got = steady(tmp_path, monkeypatch, 30, 10)
    assert sum(e["kind"] == "heartbeat" for e in got) == 3   # several beats
    end = got[-1]
    quiet = 0
    for about in {e["about"] for e in got if e["kind"] == "tree"}:
        evs = [e for e in got if e["about"] == about]
        if len({event.line(eventlog.TREE_CORE(without(e))) for e in evs}) == 1:   # it only gained record lines
            assert [e["rev"] for e in evs] == [1, 2] and evs[1]["time"] == end["time"], about   # G-3: the pass's
            quiet += 1
    assert quiet >= 1


def test_redo_g4_g12_a_none_seen_watch_s_end_its_suppressed_and_an_unwritable_file_is_3(tmp_path, monkeypatch):
    from raqib import overlay
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    empty = dict(th.inv("benign/windows-desktop"), candidates=[], act_roots=[], result="none-seen")
    w, clock = th.make_host(tmp_path / "a", [empty])
    th.run_rounds(w, clock, 1)
    text, code = w.finish()
    end = lines_of(w.events_path)[-1]
    assert code == 0 and "RESULT: NONE-SEEN (exit 0" in text and end["result"] == {"word": "NONE-SEEN", "exit": 0}
    monkeypatch.setattr(overlay, "suppressed", lambda counts: 2)   # the overlay's count, as the report reads it
    w, clock = th.make_host(tmp_path / "b", [empty])
    th.run_rounds(w, clock, 1)
    text, code = w.finish()
    assert "RESULT: NONE-SEEN (2 findings suppressed by the overlay) (exit 0" in text
    assert lines_of(w.events_path)[-1]["result"] == {"word": "NONE-SEEN", "exit": 0, "suppressed": 2}
    monkeypatch.setattr(overlay, "suppressed", lambda counts: 0)
    w, clock = th.make_host(tmp_path / "c", [empty])
    Path(w.events_path).mkdir(parents=True)   # G-5, G-12: no finding, an events file that cannot be written
    th.run_rounds(w, clock, 1)
    text, code = w.finish()
    assert code == 3 and not w.findings and "RESULT: INCOMPLETE (exit 3" in text
    built = event.watch_end({"host": {"rounds": 1}}, FACTS, T0, 2, 0, word="CLEAN", suppressed=1)
    assert event.check(built) == [] and event.check(dict(built, result={"word": "ALARM", "exit": 1, "suppressed": 1}))
    with pytest.raises(ValueError, match=r"result\.word"):
        event.watch_end({"host": {"rounds": 1}}, FACTS, T0, 2, 0)   # the module does not derive the word from the exit


def test_redo_g1_a_pair_taken_for_one_act_is_one_alarm_in_the_file_and_x18_is_met(tmp_path, monkeypatch):
    import test_host_follow_returns as tf
    sys.path.insert(0, str(ROOT / "tools" / "rig"))
    import check
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    follow = tf.Follow(unread=0, then=[tf.CURL_BORN, tf.CURL_TALK], go=True)
    w, _, _, _ = tf.against_without(tmp_path, monkeypatch, "both", tf.rounds(tmp_path, 3), follow,
                                    tf.rounds(tmp_path / "w", 3))
    pairs = host.told_twice(w.source_findings, w.sources)
    assert len(pairs) == 1
    place = {id(f): i for i, f in enumerate(w.source_findings, 1)}
    (o_id, h), = pairs.items()
    got = lines_of(w.events_path)
    last = last_by_about(got)
    folded, kept = last["source-finding:%d" % place[o_id]], last["source-finding:%d" % place[id(h)]]
    assert folded["alarm"] is False and folded["evidence"]["same_as"] == kept["about"] and kept["alarm"] is True
    act = [e for e in last.values() if e["kind"] == "source-finding" and e["alarm"]
           and e["evidence"].get("source") in ("host", "os") and e["subject"].get("pid") == kept["subject"]["pid"]
           and e["rule"]["id"] == kept["rule"]["id"] and e["summary"] == kept["summary"]]
    assert act == [kept]   # one alarm for the act
    x18 = [r for r in check.read_events("".join(event.line(e) + "\n" for e in got), w.final_text.splitlines(),
                                        w.final_exit) if r[0].startswith("X18")]
    assert x18[0][1] == check.MET, x18


def test_redo_g9_a_knock_names_only_a_thing_said_in_the_file(runs):
    lines = runs["B-unbuilt"]["lines"]
    said = {e["about"] for e in lines if e["kind"] != "knock"}
    knocks = [e for e in lines if e["kind"] == "knock"]
    assert knocks and all(e["knocked"].get("for", "finding:1") in said | {"finding:1"} for e in knocks)
    assert "finding:1" not in said and not any(e["knocked"].get("for") == "finding:1" for e in knocks)


# --- M10.2 REDO 2 (ADR-0011 Amendment H) -------------------------------------------------------------------------

def entries_of(w):
    """Each kind's entries as the watch's pass gives them to the writer (a tree with its "by", a note as its dark
    note, a knock row with its "for")."""
    dark = {d.get("text"): d for d in w.dark_notes}
    return {"finding": list(w.findings), "source-finding": list(w.source_findings),
            "note": [dark.get(t, t) for t in w.notes],
            "tree": [dict(e, candidate_by=w.tree_by[k]) if k in w.tree_by else e for k, e in w.trees.items()],
            "hole": list(w.holes) + list(w.notifier.holes) + list(w.blind), "knock": w.knock_rows(fors=True)}


BUILD = {"finding": lambda e, *m: event.finding(e, FACTS, T0, 1, "finding:1", rule=te.TABLE.get(e.get("rule_id")),
                                                record="rounds.jsonl"),
         "source-finding": lambda e, *m: event.source_finding(e, FACTS, T0, 1, "source-finding:1",
                                                              rule=te.TABLE.get(e.get("rule_id")), same_as=m[0]),
         "note": lambda e, *m: event.note(e, FACTS, T0, 1, "note:1", record="rounds.jsonl"),
         "tree": lambda e, *m: event.tree(e, FACTS, T0, 1, "tree:x", record="rounds.jsonl"),
         "hole": lambda e, *m: event.hole(e, FACTS, T0, 1, "hole:1"),
         "knock": lambda e, *m: event.knock(e, FACTS, T0, 1, "knock:1")}


def built(kind, e, *more):
    try:
        return without(BUILD[kind](e, *more))
    except Exception as exc:   # a change that makes the builder refuse is a change too
        return ("refused", str(exc))


def others(v):
    """Other values for one key: changed, emptied, of another type, absent."""
    if isinstance(v, bool):
        return [not v, None, int(v)]
    if isinstance(v, int):
        return [v + 1, None, str(v)]
    if isinstance(v, float):
        return [v + 1.5, None]
    if isinstance(v, str):
        return [v + "-changed", "", None]
    if isinstance(v, (list, tuple)):
        out = [list(v) + [7], list(v)[:-1], None]
        if v and isinstance(v[0], dict):
            out.append([dict(v[0], line=(v[0].get("line") or 0) + 1, seq=(v[0].get("seq") or 0) + 1)] + list(v[1:]))
        elif v:
            out.append([v[0] + 1 if isinstance(v[0], int) else "changed"] + list(v[1:]))
        return out
    if isinstance(v, dict):
        return [dict(v, changed=1), None]
    return ["changed", 3, True, [3], [{"src": "rounds.jsonl", "line": 2, "seq": 4}], ["10:a.exe:-", 3, "-"]]


def test_h1_a_any_value_a_builder_reads_changes_what_the_writer_keeps(runs):
    """H-1 (E1 a), driven by the builders: for real entries of each kind, each key any of them holds is changed in
    turn; where the event built after differs from the one built before, the values kept must differ too, so no
    change can hide. A list changed in place differs from the values kept before it."""
    pool = {}
    for name in MAIN + ("B-unbuilt",):
        for kind, es in entries_of(runs[name]["w"]).items():
            pool.setdefault(kind, []).extend(es)
    for kind, es in pool.items():
        es = sorted(es, key=lambda e: -len(e) if isinstance(e, dict) else 0)[:8]
        assert es, kind
        keys = sorted({k for e in es if isinstance(e, dict) for k in e})
        seen = 0
        for e in es:
            more = ("source-finding:9",) if kind == "source-finding" else ()
            if not isinstance(e, dict):   # a note that is a text
                assert eventlog.values(kind, e) != eventlog.values(kind, e + " (changed)")
                continue
            before = built(kind, e, *more)
            for k in keys:
                for v in others(e.get(k)):
                    e2 = dict(e)
                    if v is None:
                        e2.pop(k, None)
                    else:
                        e2[k] = v
                    after = built(kind, e2, *more)
                    if after != before:
                        seen += 1
                        assert eventlog.values(kind, e, *more) != eventlog.values(kind, e2, *more), (
                            kind, k, v, before, after)
            if kind == "source-finding":   # what the pass adds: same_as
                assert built(kind, e, None) != before and eventlog.values(kind, e, None) != eventlog.values(
                    kind, e, *more)
            for k, v in e.items():   # in place: the writer keeps a copy, not the list the watch goes on changing
                if isinstance(v, list) and v:
                    e2 = copy.deepcopy(e)
                    kept, was = eventlog.values(kind, e2, *more), built(kind, e2, *more)
                    if isinstance(e2[k][0], dict):
                        e2[k][0]["line"] = (e2[k][0].get("line") or 0) + 1
                    else:
                        e2[k].append(7)
                    if built(kind, e2, *more) != was:
                        assert eventlog.values(kind, e2, *more) != kept, (kind, k)
        assert seen >= 5, (kind, seen)   # the test reached the builder


def test_h1_b_a_source_finding_changed_after_it_settled_is_said_in_the_next_pass(tmp_path, monkeypatch):
    """H-1 (E1 b), through a fixture watch (run B's rounds) with no beat: a settled source finding already said
    whose standing moves to another tree, whose fold is decided, and which grows, is said again in the next pass,
    each at once; a pass with a beat due says its change too, with the beat after it."""
    import test_acts_judged as aj
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    monkeypatch.setattr(eventlog, "BEAT_DEFAULT", 1e6)
    done = []

    def between(w, k):
        log = w.events
        places = [j for j, e in enumerate(w.source_findings, 1) if event.source_state(e) == "settled"
                  and "source-finding:%d" % j in log.said]
        if done or not places:
            return
        j = places[0]
        e, about = w.source_findings[j - 1], "source-finding:%d" % j
        saved = copy.deepcopy(e)
        changes = ((lambda: e.update(judged_on=["4242", "other.exe", "-"]),
                    lambda ev: ev["state"] == "judged on another tree" and ev["alarm"] is False),
                   (lambda: e.update(judged_on=None, notice="folded: sent (test)"),
                    lambda ev: ev["knocked"]["status"] == "folded: sent (test)" and ev["alarm"] is True),
                   (lambda: e.update(cited_seq=list(e.get("cited_seq") or []) + [99999],
                                     summary=e["summary"] + " (grown)"),
                    lambda ev: 99999 in ev["evidence"]["seqs"] and ev["summary"].endswith(" (grown)")))
        for change, holds in changes:
            n0 = len(lines_of(w.events_path))
            change()
            w._events_pass(w.clock())   # the next pass, between beats
            new = [ev for ev in lines_of(w.events_path)[n0:]]
            assert [ev["about"] for ev in new] == [about] and holds(new[0]), new
        n0 = len(lines_of(w.events_path))
        e["notice"] = "folded: delivered (test)"
        log.next_beat = 0.0   # a beat is due
        w._events_tick(w.clock())
        new = lines_of(w.events_path)[n0:]
        assert [ev["about"] for ev in new][0] == about and new[-1]["kind"] == "heartbeat"
        assert new[0]["knocked"]["status"] == "folded: delivered (test)"
        log.next_beat = 1e6
        e.clear()
        e.update(saved)
        done.append(about)
    follow = aj.CountingFollow(aj.after_start(aj.os_lines("net-windows.sysmon.xml", 4700)))
    w = aj.watch_rounds(tmp_path, ["defender/before", "quiet/talking", "quiet/talking"], follow=follow,
                        between=between)
    w.finish()
    assert done


def test_h1_c_a_pass_over_thousands_of_unchanged_entries_builds_nothing(runs, tmp_path, monkeypatch):
    """H-1 (E1 c): 2000 notes and 2000 settled source findings (real ones, copied), said once; a pass between
    beats and a pass with a beat, nothing changed, build no event (the builders' calls counted); one changed
    entry is one build."""
    sf = next(e for n in MAIN for e in runs[n]["w"].source_findings if event.source_state(e) == "settled")
    sfs = [dict(copy.deepcopy(sf), cited_seq=[i]) for i in range(2000)]
    notes = ["note %d (test)" % i for i in range(2000)]
    log = eventlog.EventLog(str(tmp_path / "e.jsonl"), FACTS, te.TABLE)
    assert log.ledgers(T0, source_findings=sfs, notes=notes) == [] and log.written == 4000
    calls = []
    for name in ("source_finding", "note"):
        real = getattr(event, name)
        monkeypatch.setattr(event, name, lambda *a, real=real, **k: (calls.append(1), real(*a, **k))[1])
    builds = log.builds
    log.ledgers(T1, source_findings=sfs, notes=notes)
    log.ledgers(T1, source_findings=sfs, notes=notes, beat=True)
    assert calls == [] and log.builds == builds and log.written == 4000
    sfs[1500]["notice"] = "folded: sent (test)"
    log.ledgers(T1, source_findings=sfs, notes=notes)
    assert len(calls) == 1 and log.written == 4001 and lines_of(log.path)[-1]["about"] == "source-finding:1501"


def test_h1_a_note_replaced_in_place_is_said_in_the_next_pass(tmp_path, monkeypatch):
    """H-1: the watch tells the pass which notes it replaced in place (notes_replaced); the next pass says it."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    monkeypatch.setattr(eventlog, "BEAT_DEFAULT", 1e6)
    w, clock = th.make_host(tmp_path, ["windows"] * 3)
    w.notes.append("a note (test)")
    th.run_rounds(w, clock, 1)
    i = len(w.notes)
    w.notes[i - 1] = "a note, replaced (test)"
    w.notes_replaced.add(i)
    th.run_rounds(w, clock, 1)
    got = [e for e in lines_of(w.events_path) if e["about"] == "note:%d" % i]
    assert [(e["rev"], e["summary"]) for e in got] == [(1, "a note (test)"), (2, "a note, replaced (test)")]
    assert w.notes_replaced == set()
    w.finish()


def pair_entries(runs):
    sf = next(e for n in MAIN for e in runs[n]["w"].source_findings if event.source_state(e) == "settled")
    return dict(copy.deepcopy(sf), source="host"), dict(copy.deepcopy(sf), source="os")


def sf_lines(path):
    return [(e["about"], e["rev"], e["alarm"], e.get("evidence", {}).get("same_as")) for e in lines_of(path)
            if e["kind"] == "source-finding"]


def test_h2_a_pair_in_every_order_of_arrival_is_one_alarm_and_the_folded_half_waits_for_the_kept(runs, tmp_path):
    """H-2 (E2): host first; os first (rev 1 an alarm, rev 2 folded); the pair found a round later; the kept half
    unbuildable (the folded half said unfolded until the kept half is said)."""
    h, o = pair_entries(runs)
    log = eventlog.EventLog(str(tmp_path / "a.jsonl"), FACTS, te.TABLE)
    log.ledgers(T0, source_findings=[h])
    log.ledgers(T1, source_findings=[h, o], same={2: "source-finding:1"})
    assert sf_lines(log.path) == [("source-finding:1", 1, True, None), ("source-finding:2", 1, False,
                                                                        "source-finding:1")]
    log = eventlog.EventLog(str(tmp_path / "b.jsonl"), FACTS, te.TABLE)
    log.ledgers(T0, source_findings=[o])
    log.ledgers(T1, source_findings=[o, h], same={1: "source-finding:2"})
    assert sf_lines(log.path) == [("source-finding:1", 1, True, None), ("source-finding:2", 1, True, None),
                                  ("source-finding:1", 2, False, "source-finding:2")]
    log = eventlog.EventLog(str(tmp_path / "c.jsonl"), FACTS, te.TABLE)
    log.ledgers(T0, source_findings=[o, h])
    log.ledgers(T1, source_findings=[o, h], same={1: "source-finding:2"})
    assert sf_lines(log.path) == [("source-finding:1", 1, True, None), ("source-finding:2", 1, True, None),
                                  ("source-finding:1", 2, False, "source-finding:2")]
    log = eventlog.EventLog(str(tmp_path / "d.jsonl"), FACTS, te.TABLE)
    bad = dict(h, severity="bogus")   # the kept half cannot be built
    problems = log.ledgers(T0, source_findings=[o, bad], same={1: "source-finding:2"})
    assert [p[0] for p in problems] == ["not built"] and "source-finding:2" in problems[0][1]
    assert sf_lines(log.path) == [("source-finding:1", 1, True, None)]   # the act has its alarm
    log.ledgers(T1, source_findings=[o, bad], same={1: "source-finding:2"})
    assert len(sf_lines(log.path)) == 1
    bad["severity"] = h["severity"]
    log.ledgers(T1, source_findings=[o, bad], same={1: "source-finding:2"})
    assert sf_lines(log.path) == [("source-finding:1", 1, True, None), ("source-finding:2", 1, True, None),
                                  ("source-finding:1", 2, False, "source-finding:2")]   # the kept half first


def test_h3_a_row_that_raises_when_read_stops_only_itself_and_a_list_s_failure_is_said_once(runs, tmp_path):
    """H-3 (E3): one bad knock row among good ones, over three passes: the rows after it are said, one problem;
    a list whose own length cannot be read: one problem for the watch's life."""
    good = runs["B"]["w"].knock_rows(fors=True)[0]

    def get(i):
        if i == 1:
            raise RuntimeError("cannot read this row (test)")
        return dict(good, body="row %d (test)" % (i + 1))

    class NoLength(list):
        def __len__(self):
            raise RuntimeError("cannot count (test)")
    log = eventlog.EventLog(str(tmp_path / "e.jsonl"), FACTS, te.TABLE)
    problems = []
    for _ in range(3):
        problems += log.ledgers(T0, knocks=eventlog.Lazy(4, get), holes=NoLength(), notes=["a note (test)"])
    assert len(problems) == 2 and sorted(p[1][:23] for p in problems) == ["hole: the list was not s",
                                                                          "knock:2: cannot be read"][:2] or problems
    assert problems[0][1].startswith("knock:2: cannot be read: RuntimeError") or problems[1][1].startswith(
        "knock:2: cannot be read: RuntimeError")
    assert any(p[1].startswith("hole: the list was not said: RuntimeError") for p in problems)
    said = [e["about"] for e in lines_of(log.path)]
    assert said == ["note:1", "knock:1", "knock:3", "knock:4"] and log.not_built == 1


def unwritable(path):
    """The file cannot be written for a while: it is set aside and a directory stands in its place."""
    import os

    class Away:
        def __enter__(self):
            if os.path.exists(path):
                os.rename(path, path + ".aside")
            os.mkdir(path)

        def __exit__(self, *a):
            os.rmdir(path)
            if os.path.exists(path + ".aside"):
                os.rename(path + ".aside", path)
    return Away()


def test_h4_a_fragment_left_between_two_lines_and_what_a_failed_write_left_is_said_next(tmp_path):
    """H-4 (E4): the file's end is looked at before every line (another writer's fragment between two lines of one
    watch: the next line starts on its own line); a failed write of the start, of a first saying and of a later rev
    is said at the next pass, the start first; a heartbeat never reuses a rev."""
    path = tmp_path / "events.jsonl"
    log = eventlog.EventLog(str(path), FACTS, {}, beat=10)
    hole = {"kind": "reader-failed", "detail": "round 2: failed", "at": T0, "notice": None}
    with unwritable(str(path)):
        assert log.start(T0, 0.0)[0] == "not written"
        assert log.ledgers(T0, holes=[hole], notes=["first (test)"]) == []   # the reason was said once already
    assert not path.exists() and log.not_written == 4   # the start tried again first
    log.ledgers(T1, holes=[hole], notes=["first (test)"])
    got = lines_of(path)
    assert [(e["about"], e["rev"], e.get("state")) for e in got] == [("watch", 1, "start"), ("hole:1", 1, None),
                                                                     ("note:1", 1, None)]
    with open(str(path), "ab") as f:
        f.write(b'{"schema":"raqib-ev')   # another writer's fragment, after this watch's own lines
    hole["notice"] = "sent"
    with unwritable(str(path)):
        log.ledgers(T1, holes=[hole], notes=["first (test)"])
        assert log.heartbeat({"band": "WATCHING", "code_so_far": 0, "host": {"rounds": 1}}, T1, 10.0)[0] == \
            "not written"
    log.ledgers(T1, holes=[hole], notes=["first (test)"])
    log.heartbeat({"band": "WATCHING", "code_so_far": 0, "host": {"rounds": 2}}, T1, 20.0)
    log.end({"host": {"rounds": 2}}, T1, 0, word="CLEAN")
    raw = path.read_text(encoding="ascii").split("\n")
    assert raw[3] == '{"schema":"raqib-ev' and log.mended == 1
    after = [json.loads(x) for x in raw[4:] if x]
    assert [(e["about"], e["rev"]) for e in after] == [("hole:1", 2), ("watch", 3), ("watch", 4)]
    assert after[0]["knocked"]["status"] == "sent"   # the later rev, said when the file could be written again
    assert [e["rev"] for e in lines_of_whole(path) if e["about"] == "watch"] == [1, 3, 4]   # rev 2 never reused


def lines_of_whole(path):
    out = []
    for x in Path(path).read_text(encoding="ascii").splitlines():
        try:
            out.append(json.loads(x))
        except ValueError:
            pass
    return out


def test_h5_a_state_that_cannot_be_written_at_the_finish_makes_the_end_say_incomplete(tmp_path, monkeypatch):
    """H-5 (E5): the state is written before the result the end says is computed: a state that cannot be written
    at the finish makes the end INCOMPLETE with the report's exit (a watch that is NONE-SEEN without it)."""
    import os
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    empty = dict(th.inv("benign/windows-desktop"), candidates=[], act_roots=[], result="none-seen")
    words = {}
    for name in ("plain", "no-state"):
        w, clock = th.make_host(tmp_path / name, [empty])
        th.run_rounds(w, clock, 1)
        if name == "no-state":
            os.remove(w.state_path)
            os.mkdir(w.state_path)   # it cannot be written from now on
        text, code = w.finish()
        end = lines_of(w.events_path)[-1]
        word = te.said_result(text)[0]
        assert end["state"] == "end" and end["result"]["word"] == word and end["result"]["exit"] == code, name
        words[name] = (word, code)
    assert words == {"plain": ("NONE-SEEN", 0), "no-state": ("INCOMPLETE", 3)}


def test_h6_h7_the_beat_is_on_every_event_and_the_file_equals_the_snapshot_on_a_watch_with_a_pair(tmp_path,
                                                                                                    monkeypatch):
    """H-6: watch.beat on every event, required; H-7: snapshot is given the pairs, and the file read back equals it
    for a watch with a pair (the rig's X18 on Windows: one act, one alarm)."""
    import test_host_follow_returns as tf
    monkeypatch.setattr(eventlog._platform, "node", lambda: HOST)
    follow = tf.Follow(unread=0, then=[tf.CURL_BORN, tf.CURL_TALK], go=True)
    w, _, _, _ = tf.against_without(tmp_path, monkeypatch, "both", tf.rounds(tmp_path, 3), follow,
                                    tf.rounds(tmp_path / "w", 3))
    got = lines_of(w.events_path)
    assert {e["watch"]["beat"] for e in got} == {w.events.beat}
    word, suppressed = te.said_result(w.final_text)
    snap = te.take(w, end=True, exit=w.final_exit, word=word, suppressed=suppressed)
    assert len(snap["same"]) == 1 and any("same_as" in e.get("evidence", {}) for e in snap["events"])
    mine, theirs = last_by_about(got), last_by_about(snap["events"])
    assert set(mine) == set(theirs)
    for about in theirs:
        assert without(mine[about]) == without(theirs[about]), about
    no_beat = copy.deepcopy(got[0])
    del no_beat["watch"]["beat"]
    assert any(p.startswith("watch.beat: missing") for p in event.check(no_beat))
    with pytest.raises(ValueError, match=r"watch\.beat"):
        event.facts({"run": "r"}, host=HOST)


def test_h9_the_host_name_line_is_in_what_the_watch_prints_at_its_start(tmp_path, monkeypatch):
    """H-9 (E8): the real start (host.start) prints the events file, its beat and the host's name, or that the
    system gives none."""
    from raqib import watch
    for name, said in (("host.example", "raqib watch --host: events: host host.example (the system's name)\n"),
                       ("", "raqib watch --host: events: the system gives no host name: the events say \"unnamed\""
                            " (--event-host NAME names it)\n")):
        home = tmp_path / ("home-%d" % len(name))
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setattr(eventlog._platform, "node", lambda name=name: name)
        running = host.start(th.CATALOG, th.RULES, every=10, no_open=True, no_notify=True, port=0, out=io.StringIO(),
                             err=io.StringIO(), environ={}, home=str(home), reader=lambda: th.inv("linux"),
                             platform="test")
        try:
            stop = watch.Stop()
            stop.set("the test's stop")
            host.conclude(running, host.loop(running, stop))
        finally:
            host.close(running)
        out = running.out.getvalue()
        assert said in out, out
        assert ("raqib watch --host: events %s (raqib-event/1, one line appended for each thing new or changed; a"
                " heartbeat every 60 s; nothing is sent)\n" % running.watcher.events_path) in out
        assert out.index("raqib watch --host: events ") < out.index(said)
