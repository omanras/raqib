"""ADR-0012: the rig's reader (tools/rig/check.py), offline. A made-up report in the shape `raqib watch --host`
prints (documentation addresses, synthetic names) is read as all MET; each expectation is then broken in turn, by
the words of the field run that taught it, and must be the one that is MISSED."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("rig_check", ROOT / "tools" / "rig" / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

WORKLOAD = "WORKLOAD 07:50:35 pid 9828\nWORKLOAD 07:50:35 talking\nWORKLOAD 07:51:15 done\n"
REPORT = """raqib watch --host: the host, not a name (ADR-0007)
[07:51:21Z] round 16: 295 records read, 14 holes; 1 tree(s) now
raqib watch --host: 16 round(s) done (--rounds)

Raqib watch --host (ADR-0007): the host, not a name
host: win32; a round every 5 s; window 0 s; rounds 16 of 16
ROUNDS: 16 started, 16 with an inventory, 0 late, 0 failed
  round 1: 249 records read, 13 holes
CHANNEL (the rounds read the Sysmon channel since the previous round): 16 read(s) kept, 0 failed, 0 at the cap of 2000; 540 event(s); kinds read: event 1, event 3, event 11, event 22; 0 brief tree(s) (seen in the channel only)
TREES SEEN: 1 (0 now, 0 quiet)
  [candidate] pid 9828 python (unknown): gone; first round 4; last round 7; 5 act(s); endpoints 203.0.113.7:443
      source: os (os: Sysmon, rooted at pid 9828: C:\\Users\\user\\.raqib\\host\\sources\\run-9828-aa.jsonl); findings medium 4
FINDINGS: 1
  [medium] NEW-AGENT-UNKNOWN round 4 (window a .. b; Windows sample(s) 1): unknown agent tree python pid 9828 (round 4, was absent); off
SUSPICION (A2: a model may raise suspicion, never acquit): off (no --suspect)
RHYTHM BEATS: beats after the last round: 0 (source beats read by the final poll, in no round: not judged by HOST-RHYTHM); 0 act(s) seen by a second source, counted once
SOURCE FINDINGS: 2 (2 live, of them 0 pending at exit; 0 history; 0 judged on another tree; 0 on benign trees, noted)
  [medium] NET-TOOL on python pid 9828 via host: HostChild may reach the network at seq 1 (host -, program curl, programs ["curl"]); off
  [medium] NET-TOOL on python pid 9828 via host: HostChild may reach the network at seq 3 (host -, program curl, programs ["curl"]); off
SYSMON: the live reader's check: present, the rounds read its channel
NOTES: 3
  - HOST-RHYTHM (M7.4) sees only what the rounds see
  - tree 9828:python:t, C:\\x\\run-9828-aa.jsonl: rule SCOPE-CWD-ROOT partial: could not judge 13 line(s) (session:seq os-9828:6)
  - tree 9828:python:t, C:\\x\\run-9828-aa.jsonl: rule SCOPE-CWD-MOVED partial: could not judge 26 line(s) (session:seq os-9828:6)
HOLES (A3): 0
BLIND SPOTS (K-8, holes of the class blind spot, counted apart; they do not change the result): 1
  - bytes: Windows: no byte counts; 16 round(s)
KNOCKS: 0 (each: round, event, title / body, rate-limit id: status)

ALARMS: 1 finding(s): NEW-AGENT-UNKNOWN; 2 source finding(s) listed (4 findings: a pair taken for the same act is listed once): NET-TOOL on pid 9828
INCOMPLETE: none
CLEAN: none
RESULT: ALARM (exit 1: a finding)
"""
SOURCES = [("run-9828-aa.jsonl", '{"input_meta":{"image":"powershell"}}\n{"input_meta":{"path":"C:\\\\t\\\\raqib-rig-file.txt"}}\n')]


def states(report=REPORT, workload=WORKLOAD, sources=SOURCES, code=1, platform="win32", sysmon=True):
    return {ident.split(" ", 1)[0]: state for ident, state, _ in check.read(report, workload, sources, code, platform, sysmon)}


def test_the_made_up_report_is_all_met_but_the_clipboard_which_is_open():
    got = states()
    assert got.pop("X15") == check.OPEN                                   # no rule for the clipboard yet: recorded
    assert [got.pop(k) for k in ("X16", "X17", "X18")] == [check.SKIP] * 3   # M10.2: no events file given here
    assert set(got.values()) == {check.MET} and sorted(got, key=lambda x: int(x[1:])) == ["X%d" % i for i in range(1, 15)]
    assert got["X12"] == check.MET   # ADR-0007 AR-4: with Sysmon X12 is judged (MET here), n/a only without it


BROKEN = [
    ("X1", lambda r: r.replace("RESULT: ALARM (exit 1: a finding)", "RESULT: ALARM (exit 3: a finding)")),
    ("X2", lambda r: r.replace("HOLES (A3): 0", "HOLES (A3): 1\n  - source-helper: tree 9828: wevtutil pid 7 terminated: did"
                               " not return in 10 s at t")),
    ("X3", lambda r: r.replace("16 read(s) kept, 0 failed", "0 read(s) kept, 16 failed")),
    ("X4", lambda r: r.replace("kinds read: event 1, event 3, event 11, event 22", "kinds read: event 1")),
    ("X6", lambda r: r.replace("unknown agent tree python pid 9828", "unknown agent tree python pid 77")),
    ("X7", lambda r: r.replace("NET-TOOL on python pid 9828 via host", "NET-TOOL on python pid 77 via host")),
    ("X8", lambda r: r.replace("2 source finding(s) listed (4 findings: a pair taken for the same act is listed once)",
                               "4 source finding(s)")),
    ("X9", lambda r: r.replace("rule SCOPE-CWD-MOVED partial: could not judge 26", "rule SCOPE-CWD-ROOT partial: could"
                               " not judge 26")),
    ("X10", lambda r: r.replace("findings medium 4", "findings none; 3 os event(s) before the watch's start: history"
                                " (never knocked)")),
    ("X11", lambda r: r.replace("HOLES (A3): 0", "HOLES (A3): 1\n  - lines-unread: round 2: 1 line(s) could not be read")),
]


@pytest.mark.parametrize("ident,breaker", BROKEN, ids=[b[0] for b in BROKEN])
def test_each_expectation_is_the_one_missed_when_its_field_finding_comes_back(ident, breaker):
    broken = breaker(REPORT)
    assert broken != REPORT
    got = states(report=broken)
    assert got[ident] == check.MISSED
    others = {k for k, v in got.items() if v == check.MISSED} - {ident}
    assert others <= {"X3", "X5", "X11"} if ident in ("X2", "X3") else not others, others


def test_x5_the_sysmon_line_beside_no_read_kept_is_the_third_field_runs_lie():
    lie = REPORT.replace("16 read(s) kept, 0 failed", "0 read(s) kept, 16 failed")
    assert states(report=lie)["X5"] == check.MISSED
    true = lie.replace("present, the rounds read its channel", "present, but none of the 16 read(s) was kept")
    assert states(report=true)["X5"] == check.MET


def test_x12_beats_left_for_the_final_poll_are_missed_and_x13_x14_read_the_sources():
    # ADR-0007 AP-4: X12 is an expectation that can be MISSED (no longer OPEN); none left is MET
    assert states(report=REPORT.replace("beats after the last round: 0", "beats after the last round: 9"))["X12"] == check.MISSED
    assert states()["X12"] == check.MET
    said = [w for i, s, w in check.read(REPORT.replace("beats after the last round: 0", "beats after the last round: 9"),
                                        WORKLOAD, platform="win32", sysmon=True) if i.startswith("X12")]
    assert said and "Amendment AP" in said[0] and "9 beat(s)" in said[0]
    got = states(sources=[("run-9828-aa.jsonl", "{}")])
    assert got["X13"] == got["X14"] == check.MISSED


def test_no_report_at_all_is_one_missed_line_and_linux_skips_what_needs_sysmon():
    assert [(i.split(" ", 1)[0], s) for i, s, _ in check.read("raqib watch --host: started\n", WORKLOAD)] == [("X1", check.MISSED)]
    got = states(platform="linux", sysmon=False, sources=[])
    assert got["X3"] == got["X4"] == got["X5"] == got["X11"] == check.SKIP and "X13" not in got and got["X7"] == check.MET
    # ADR-0007 AR-4: no Sysmon, no tree with a source with beats: a 0 measured nothing there, so n/a
    assert states(platform="linux", sysmon=False, sources=[])["X12"] == check.SKIP
    assert states(platform="win32", sysmon=False)["X12"] == check.SKIP
    (said,) = [w for i, s, w in check.read(REPORT, WORKLOAD, platform="linux", sysmon=False) if i.startswith("X12")]
    assert "no Sysmon: no tree had a source with beats here" in said and "AR-4" in said and "AS-2" in said
    # AS-2: a count that is not 0 is a measure wherever it is read (a beat did wait): MISSED, never n/a; and a
    # report whose RHYTHM BEATS line is not there is MISSED too
    report = REPORT.replace("beats after the last round: 0", "beats after the last round: 9")
    assert report != REPORT
    for kw in ({"platform": "linux", "sysmon": False, "sources": []}, {"platform": "win32", "sysmon": False}):
        assert states(report=report, **kw)["X12"] == check.MISSED
        (said,) = [w for i, s, w in check.read(report, WORKLOAD, **kw) if i.startswith("X12")]
        assert said.startswith("9 beat(s) read by the final poll, in no round")


def test_main_prints_the_table_exits_0_and_1_only_when_strict_and_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "bad.out").write_text(BROKEN[6][1](REPORT), encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    base = ["--workload", str(tmp_path / "l.out"), "--exit-code", "1", "--platform", "win32", "--sysmon"]
    assert check.main(["--report", str(tmp_path / "w.out"), "--strict", "--summary", str(tmp_path / "s.md")] + base) == 0
    assert "RIG: 12 met, 0 missed, 0 open" in capsys.readouterr().out and "RIG:" in (tmp_path / "s.md").read_text()
    assert check.main(["--report", str(tmp_path / "bad.out")] + base) == 0          # it reports; it does not fail
    assert "::warning title=rig MISSED::X8" in capsys.readouterr().out
    assert check.main(["--report", str(tmp_path / "bad.out"), "--strict"] + base) == 1


def test_the_rigs_files_are_ascii_and_the_stand_in_is_no_part_of_raqib():
    for name in ("check.py", "workload.py", "sysmon-all.xml"):
        (ROOT / "tools" / "rig" / name).read_bytes().decode("ascii")
    Path(__file__).read_bytes().decode("ascii")
    assert not [p for p in (ROOT / "raqib").rglob("*.py") if "tools.rig" in p.read_text(encoding="utf-8")]


# --- X16-X18 (ADR-0011 F-9, M10.2): the watch's events file ----------------------------------------------------

def made_up_events(code=1, beats=0):
    """Events in raqib-event/1 for the made-up report: a start, one finding, two source findings, the end."""
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import event
    facts = {"run": "rig-run", "mode": "host", "platform": "win32", "version": "0.1.0", "host": "host.example"}
    t = "2026-11-03T07:51:21.000Z"
    rule = {"attack": ["T1059"]}
    out = [event.watch_start({}, facts, "2026-11-03T07:50:00.000Z")]
    out.append(event.finding({"rule_id": "NEW-AGENT-UNKNOWN", "severity": "medium", "summary": "unknown agent tree",
                              "class": "HOST", "kind": "anchor", "run": "rig-run", "round": 4},
                             facts, t, len(out) + 1, "finding:1", rule=rule))
    for i in (1, 2):
        out.append(event.source_finding({"rule_id": "NET-TOOL", "severity": "medium", "summary": "may reach the network",
                                         "pid": 9828, "image": "python", "settled": True, "run": "rig-run",
                                         "source": "host"}, facts, t, len(out) + 1,
                                        "source-finding:%d" % i, rule=rule))
    for k in range(beats):
        out.append(event.heartbeat({"band": "WATCHING", "code_so_far": 1, "host": {"rounds": k}}, facts, t,
                                   len(out) + 1, rev=k + 2))
    out.append(event.watch_end({"host": {"rounds": 16}}, facts, t, len(out) + 1, code, rev=beats + 2,
                               word={0: "CLEAN", 1: "ALARM", 3: "INCOMPLETE"}[code]))
    return "".join(event.line(e) + "\n" for e in out)


def x(report=REPORT, events=None, code=1):
    return {i.split(" ", 1)[0]: (s, w) for i, s, w in check.read(report, WORKLOAD, SOURCES, code, "win32", True, events)
            if i.split(" ", 1)[0] in ("X16", "X17", "X18")}


def test_x16_x18_are_met_by_the_events_of_the_report_and_n_a_without_a_file():
    assert {k: s for k, (s, _) in x(events=made_up_events()).items()} == {"X16": check.MET, "X17": check.MET,
                                                                           "X18": check.MET}
    assert {k: s for k, (s, _) in x().items()} == {"X16": check.SKIP, "X17": check.SKIP, "X18": check.SKIP}


def test_x16_x18_each_missed_when_its_part_is_broken():
    good = made_up_events()
    lines = good.splitlines()
    assert x(events="")["X16"][0] == check.MISSED                                          # no events at all
    assert x(events=good.replace('"severity":"medium"', '"severity":"bogus"', 1))["X16"][0] == check.MISSED
    assert x(events="\n".join(lines[:-1]) + "\n")["X17"][0] == check.MISSED                # no end
    assert x(events=made_up_events(code=0))["X17"][0] == check.MISSED                     # not the report's exit
    assert x(events="\n".join(lines[:2] + lines[3:]) + "\n")["X18"][0] == check.MISSED    # a source finding unsaid
    long = REPORT.replace("KNOCKS: 0 (each", "EVENTS: written 5 (heartbeats 0, one every 20 s), not built 0, not"
                          " written 0; file f (raqib-event/1, appended; host host.example; nothing is sent)\nKNOCKS: 0"
                          " (each")
    assert x(report=long, events=good)["X17"][0] == check.MISSED                           # 81 s, beat 20 s, none
    assert x(report=long, events=made_up_events(beats=3))["X17"][0] == check.MET


def test_main_reads_the_events_file_and_a_missing_one_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "e.jsonl").write_text(made_up_events(), encoding="ascii")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
            "--platform", "win32", "--sysmon"]
    assert check.main(base + ["--events", str(tmp_path / "e.jsonl"), "--strict"]) == 0
    assert "RIG: 15 met, 0 missed, 0 open" in capsys.readouterr().out
    assert check.main(base + ["--events", str(tmp_path / "none.jsonl"), "--strict"]) == 1
    assert "::warning title=rig MISSED::X16" in capsys.readouterr().out


def test_x18_compares_things_of_the_report_s_run_a_pair_said_as_one_act():
    import json
    good = made_up_events()
    lines = good.splitlines()
    one = json.loads(lines[2])
    twin = dict(one, about="source-finding:3", n=9, id="rig-run:9", alarm=False,
                evidence=dict(one["evidence"], source="os", same_as="source-finding:1"))
    paired = "\n".join(lines[:-1] + [json.dumps(twin, sort_keys=True), lines[-1]]) + "\n"
    report = REPORT.replace("FINDINGS: 1\n", "FINDINGS: 1\n", 1)
    ran = report.replace("\nFINDINGS: 1", "\nrun: rig-run (seqs 1..9 of the record)\nFINDINGS: 1", 1)
    assert x(report=ran, events=paired)["X18"][0] == check.MET                                    # a pair: one act
    gone = "\n".join(lines[:2] + lines[3:-1] + [json.dumps(twin, sort_keys=True), lines[-1]]) + "\n"
    assert x(report=ran, events=gone)["X18"][0] == check.MISSED   # a pair and one event missing: not hidden
    other = dict(json.loads(lines[1]), id="other-run:2", watch=dict(one["watch"], run="other-run"))
    two_runs = json.dumps(other, sort_keys=True) + "\n" + paired
    assert x(report=ran, events=two_runs)["X18"][0] == check.MET      # another run's events are not this report's
    assert x(report=report, events=two_runs)["X18"][0] == check.MISSED   # without the run line: every event counts
