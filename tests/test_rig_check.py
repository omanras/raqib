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
REPORT = """raqib watch --host: the host, not a name (ADR-0007); raqib 9.8.7
[07:51:21Z] round 16: 295 records read, 14 holes; 1 tree(s) now
raqib watch --host: 16 round(s) done (--rounds)

Raqib watch --host (ADR-0007): the host, not a name; raqib 9.8.7
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
    assert [got.pop(k) for k in ("X32", "X33", "X34")] == [check.SKIP] * 3   # ADR-0014: this stand-in did none of them
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
    facts = {"run": "rig-run", "mode": "host", "platform": "win32", "version": "0.1.0", "host": "host.example",
             "beat": 20.0}   # ADR-0011 H-6: the beat on every event
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


# --- X32 to X34 (ADR-0014): what the stand-in did to the host ---------------------------------------------------
ACTS = ("WORKLOAD 07:50:50 startup file written\nWORKLOAD 07:50:53 port 22 of this machine's own address reached\n"
        "WORKLOAD 07:50:54 autostart value set\n")
BEHAVED = REPORT.replace(
    "SOURCE FINDINGS: 2 (2 live", "SOURCE FINDINGS: 5 (5 live").replace(
    "SYSMON: the live reader's check",
    "  [high] PERSIST-AUTOSTART on python pid 9828 via os: file writes a file in a Startup folder at seq 17 (C:\\x); off\n"
    "  [high] NET-ADMIN-PORT on python pid 9828 via os: net reaches port 22 of a private address at seq 25; off\n"
    "  [high] PERSIST-RUN-KEY on python pid 9828 via os: registry sets an autostart value at seq 21; off\n"
    "SYSMON: the live reader's check").replace("2 source finding(s) listed (4 findings", "5 source finding(s) listed (7 findings")


def behaviour(report=BEHAVED, workload=WORKLOAD + ACTS, platform="win32", sysmon=True):
    return {i.split(" ", 1)[0]: (s, w) for i, s, w in check.read(report, workload, SOURCES, 1, platform, sysmon)
            if i.split(" ", 1)[0] in ("X32", "X33", "X34")}


def test_x32_to_x34_each_act_the_stand_in_says_it_did_is_a_finding_of_its_tree():
    got = behaviour()
    assert {k: s for k, (s, _) in got.items()} == {"X32": check.MET, "X33": check.MET, "X34": check.MET}
    assert "PERSIST-AUTOSTART on python pid 9828" in got["X32"][1]


@pytest.mark.parametrize("ident,rule,absent", [("X32", "PERSIST-AUTOSTART", check.MISSED),
                                               ("X33", "NET-ADMIN-PORT", check.MISSED),
                                               ("X34", "PERSIST-RUN-KEY", check.MISSED)])   # AC-8: landed
def test_x32_to_x34_an_act_with_no_finding_is_missed(ident, rule, absent):
    gone = "\n".join(line for line in BEHAVED.splitlines() if "] %s on " % rule not in line) + "\n"
    got = behaviour(report=gone)
    assert got[ident][0] == absent and "0 %s line(s)" % rule in got[ident][1]
    assert all(got[k][0] == check.MET for k in got if k != ident)          # the other two are not touched
    other = behaviour(report=BEHAVED.replace("%s on python pid 9828" % rule, "%s on python pid 77" % rule))
    assert other[ident][0] == absent                                       # another tree's finding is not this one's


def test_x32_to_x34_are_not_judged_without_an_os_source_or_where_the_act_was_not_done():
    assert {s for s, _ in behaviour(platform="linux", sysmon=False).values()} == {check.SKIP}
    assert {s for s, _ in behaviour(sysmon=False).values()} == {check.SKIP}
    undone = WORKLOAD + ACTS.replace("startup file written", "startup file not written").replace(
        "address reached", "address not reached").replace("value set", "value not set")
    got = behaviour(workload=undone)
    assert {s for s, _ in got.values()} == {check.SKIP} and "did not do it" in got["X33"][1]


# --- X35 (ADR-0007 BU-5, BW-7): the watch's own count of the process events -------------------------------------
LINUX_WORKLOAD = ("WORKLOAD 07:50:35 pid 9828\nWORKLOAD 07:50:35 talking\nWORKLOAD 07:50:43 start curl\n"
                  "WORKLOAD 07:50:55 start curl\nWORKLOAD 07:50:56 end curl rc=0\nWORKLOAD 07:51:15 done\n")
EVENTS_SECTION = ("PROCESS EVENTS (Linux): the kernel's process events, read by a helper process of the watch's own;"
                  " not judged yet: no rule reads them, no line of a tree's source is written from them\n"
                  "  rounds asked: 16, answered: 16\n"
                  "  processes that began: 41; of them began and ended between two asks: 37\n"
                  "  programs not read: 0 (reads at an exec that failed)\n"
                  "  past the reader's bounds: 0\n"
                  "  lost: none\n")
RESTART = ("  started again, round 4: ended: the helper of the process events ended (its output ended); it is started"
           " again, once; nothing was heard between the end of the helper before and this start\n")


def x35(section=EVENTS_SECTION, workload=LINUX_WORKLOAD, platform="linux"):
    report = REPORT.replace("TREES SEEN:", section + "TREES SEEN:", 1)
    ((ident, state, words),) = check.read_watch_events(report, workload, platform)
    assert ident.startswith("X35 ")
    return state, words


def test_x35_met_only_where_every_ask_was_answered_no_restart_nothing_lost_and_the_children_began_a_floor():
    state, words = x35()
    assert state == check.MET and words.startswith("16 of 16 round(s) answered; at least the stand-in's 2 child(ren)"
                                                   " began (41 process(es) of the machine: a floor")
    assert x35(section=EVENTS_SECTION.replace("began: 41", "began: 2"))[0] == check.MET
    assert x35(section=EVENTS_SECTION.replace("answered: 16", "answered: 16; before the helper was ready: 2"))[0] \
        == check.MET


@pytest.mark.parametrize("change,said", [
    (lambda t: "", "holds no PROCESS EVENTS"),
    (lambda t: t.replace("answered: 16", "answered: 15") + "  hole, round 3: late: the helper's answer did not come"
     " within 2 s\n", "15 of 16 round(s) asked were answered"),
    (lambda t: t.replace("asked: 16, answered: 16", "asked: 0, answered: 0"), "0 of 0 round(s)"),
    (lambda t: t + RESTART, "the helper was started again: started again, round 4"),
    (lambda t: t + "  and started again 2 more time(s), not printed\n", "the helper was started again"),
    (lambda t: t.replace("lost: none", "lost: helper 1: ENOBUFS 1 time(s)"), "lost: helper 1: ENOBUFS 1 time(s)"),
    (lambda t: t.replace("lost: none", "lost: not known (no answer)"), "lost: not known (no answer)"),
    (lambda t: t.replace("began: 41", "began: 1"), "1 process(es) began, fewer than the 2"),
    (lambda t: t + "  refused: the process events are not read: no answer to the ask within 2 s\n",
     "refused (not for want of a right)")])
def test_x35_missed_on_linux_for_each_way_the_section_says_the_helper_was_not_whole(change, said):
    state, words = x35(section=change(EVENTS_SECTION))
    assert state == check.MISSED and said in words, words


def test_x35_missed_where_the_stand_in_said_it_started_no_child():
    state, words = x35(workload="WORKLOAD 07:50:35 pid 9828\nWORKLOAD 07:51:15 done\n")
    assert state == check.MISSED and "the stand-in said it started no child" in words


def test_x35_n_a_off_linux_and_where_the_refusal_names_a_right_this_user_lacks():
    assert x35(platform="win32")[0] == check.SKIP and x35(section="", platform="win32")[0] == check.SKIP
    refused = EVENTS_SECTION + "  refused: the process events are not read: the bind was refused (EPERM)\n"
    assert x35(section=refused)[0] == check.SKIP
    assert check.read_watch_events(None, None, "linux")[0][1] == check.MISSED   # never raises


def test_x35_is_a_row_of_main_and_off_linux_it_counts_for_nothing(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT.replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1), encoding="utf-8")
    (tmp_path / "l.out").write_text(LINUX_WORKLOAD, encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1"]
    check.main(base + ["--platform", "win32", "--sysmon"])
    out = capsys.readouterr().out
    assert "n/a     X35 " in out and "RIG: 12 met, 0 missed, 0 open" in out
    check.main(base + ["--platform", "linux"])
    assert "MET     X35 " in capsys.readouterr().out


# --- X38 (ADR-0016 H-4, M13.1): raqib events over the watch's events file says this watch's run is whole --------

RAN = REPORT.replace("\nFINDINGS: 1", "\nrun: rig-run (seqs 1..9 of the record)\nFINDINGS: 1", 1)
WHOLE = ("raqib events: events.jsonl: 9 line(s), 9 event(s)\n  watch: 3\n"
         "  run rig-run (host rig.example): chain whole, 9 line(s)\nRESULT: every line is an event\n")
NOT_WHOLE = "chain not whole, 9 line(s)\n    "


def x38(answer, report=RAN):
    ((ident, state, words),) = check.read_chain(answer, report)
    assert ident.startswith("X38 ")
    return state, words


def test_x38_met_where_this_watch_s_run_is_whole_and_no_line_names_a_break():
    assert x38(WHOLE) == (check.MET, "run rig-run: chain whole, 9 line(s)")
    older = WHOLE.replace("RESULT:", "  run old-run (host rig.example): not chained, 4 line(s) (no line holds prev:"
                                     " written by a Raqib before this one, version 0.2.0)\nRESULT:")
    assert x38(older)[0] == check.MET   # an older build's run beside it is no break
    state, words = x38(WHOLE.replace("9 line(s)", "9 line(s), 2 said twice"))   # HB-6: no break, and not MET
    assert state == check.MISSED and "2 line(s) said twice in the watch's own file" in words
    # the Table (seen on the rig's Windows machine: the kept answer ends its lines as Windows does, and X38 was MISSED)
    assert x38(WHOLE.replace("\n", "\r\n"), RAN.replace("\n", "\r\n")) == (
        check.MET, "run rig-run: chain whole, 9 line(s)")


@pytest.mark.parametrize("answer,said", [
    (WHOLE.replace("chain whole, 9 line(s)", NOT_WHOLE + "broken at line 4: it does not name the run's line before"
                   " it, line 3 (one before it was removed, changed, added or moved)"), "broken at line 4"),
    (WHOLE.replace("chain whole, 9 line(s)", NOT_WHOLE + "1 line(s) beside the chain, line 5: they follow line 4, and"
                   " line 6 names line 4 again (not counted as written by the writer, or put there by another hand)"),
     "beside the chain"),
    (WHOLE.replace("chain whole, 9 line(s)", NOT_WHOLE + "begins before this file: its first line here, line 1, names a"
                   " line that is not here"), "begins before this file"),
    (WHOLE.replace("RESULT:", "  run other (host rig.example): chain not whole, 2 line(s)\n    broken at line 2: it does"
                   " not name the run's line before it, line 1\nRESULT:"), "run other (host rig.example): chain not"),
    (WHOLE.replace("chain whole, 9 line(s)", "no line holds prev, yet its version 0.4.0 writes the chain (from 0.4.0):"
                   " the chain was taken out, 9 line(s)"), "the chain was taken out"),
    (WHOLE.replace("run rig-run (", "run other-run ("), "no line says its chain whole"),
    ("", "said nothing"),
])
def test_x38_missed_for_a_break_a_line_beside_another_run_s_whole_chain_or_silence(answer, said):
    state, words = x38(answer)
    assert state == check.MISSED and said in words, words


def test_x38_missed_where_the_report_names_no_run_and_n_a_where_the_rig_ran_no_check():
    assert x38(WHOLE, REPORT)[0] == check.MISSED and "names no run" in x38(WHOLE, REPORT)[1]
    assert x38(None)[0] == check.SKIP


def test_x38_is_a_row_of_main_given_or_missing(tmp_path, capsys):
    (tmp_path / "w.out").write_text(RAN, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "c.out").write_text(WHOLE, encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--exit-code", "1",
            "--platform", "win32", "--sysmon"]
    check.main(base + ["--events-check", str(tmp_path / "c.out")])
    assert "MET     X38 " in capsys.readouterr().out
    check.main(base + ["--events-check", str(tmp_path / "missing.out")])   # given and missing: silence
    assert "MISSED  X38 " in capsys.readouterr().out
    check.main(base)
    assert "n/a     X38 " in capsys.readouterr().out


def test_x38_the_rig_runs_raqib_events_after_the_watch_on_both_systems_and_keeps_its_answer():
    text = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="utf-8")
    win, linux = text.split("\n  linux:")
    for job, run, reader in ((win, "raqib events $HOME\\.raqib\\host\\events.jsonl > ", "tools\\rig\\check.py"),
                             (linux, 'raqib events "$HOME/.raqib/host/events.jsonl" > ', "tools/rig/check.py")):
        assert job.count(run) == 1 and job.index("workload.py") < job.index(run) < job.index(reader)
        assert job.count("--events-check ") == 1 and job.count("events-check.out") >= 3   # written, read, kept
    # HA-10: what raqib events wrote to its error stream is printed and kept (on Linux it is in the answer: 2>&1)
    assert "Get-Content $env:RUNNER_TEMP\\events-check.err" in win and "events-check.err rig-out" in win
    assert '"$RUNNER_TEMP/events-check.out" 2>&1' in linux
