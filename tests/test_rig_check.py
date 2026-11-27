"""ADR-0012: the rig's reader (tools/rig/check.py), offline. A made-up report in the shape `raqib watch --host`
prints (documentation addresses, synthetic names) is read as all MET; each expectation is then broken in turn, by
the words of the field run that taught it, and must be the one that is MISSED."""
import importlib.util
import json
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
                  " judged: a process that began between two samples under a tree that talks at a sample is that"
                  " tree's child, by its program's name, from the reader (the helper's lines are its word, not checked"
                  " by the watch); not judged: a tree that lives whole between two samples, a child's own"
                  " connections, a program not read\n"
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
    (lambda t: t.replace("bounds: 0", "bounds: 3"), "past the reader's bounds: 3"),   # M14.1c (BX-5)
    (lambda t: t.replace("  past the reader's bounds: 0\n", ""), "past the reader's bounds: not said"),
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


# --- X36 (ADR-0007 BY-7, M14.1c): the stand-in's wget, a child that lives under a second ---------------------------
WGET_WORKLOAD = LINUX_WORKLOAD.replace("WORKLOAD 07:51:15 done\n", "WORKLOAD 07:50:57 start wget\n"
                                       "WORKLOAD 07:50:57 end wget rc=0\nWORKLOAD 07:51:15 done\n")
WGET_LINE = ("  [medium] NET-TOOL on python pid 9828 via host: HostChild may reach the network at seq 5 (host -, program"
             " wget, programs [\"wget\"]); off\n")


def child_line(pid=9828, programs=("wget",), seen=("events",), seq=5):
    """A HostChild line of the stand-in's tree's source file: its programs and, in their order, where each was seen
    (ADR-0007 CA-2: command_sources; None: a line of a round with no reader's text, which carries none)."""
    meta = {"command_programs": list(programs), "pid": pid, "children": [{"pid": 9900, "image": programs[0]}],
            "cites": [{"src": "procevents", "line": 3, "text_sha256": "0" * 64}]}
    if seen is not None:
        meta["command_sources"] = list(seen)
    return json.dumps({"seq": seq, "tool": "HostChild", "source": "host", "input_meta": meta}) + "\n"


READER_SOURCES = [("20261120T075035.000Z-1-9828-ab.jsonl", "not json\n" + child_line(programs=("curl",), seen=None,
                                                                                         seq=1) + child_line())]


def x36(report=None, workload=WGET_WORKLOAD, platform="linux", section=EVENTS_SECTION, sources=READER_SOURCES):
    report = REPORT.replace("TREES SEEN:", section + "TREES SEEN:", 1) if report is None else report
    ((ident, state, words),) = check.read_short_tool(report, workload, platform, sources)
    assert ident.startswith("X36 ")
    return state, words


def with_wget(report=REPORT):
    at = report.index("  [medium] NET-TOOL on python pid 9828")
    return report[:at] + WGET_LINE + report[at:]


def test_x36_met_only_where_the_wgets_own_entry_says_the_process_events_alone():
    report = with_wget().replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1)
    state, words = x36(report=report)
    assert state == check.MET and words.startswith("1 NET-TOOL line(s) on pid 9828 name wget (its rc=0), and its"
                                                   " HostChild line says the process events alone saw it")
    together = [("t.jsonl", child_line(programs=("curl", "wget"), seen=("both", "events")))]   # CA-3: its own entry
    assert x36(report=report, sources=together)[0] == check.MET


def test_x36_n_a_where_the_wget_lived_to_a_sample_and_missed_where_the_sample_alone_or_nothing_says_it():
    report = with_wget().replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1)
    state, words = x36(report=report, sources=[("t.jsonl", child_line(seen=("both",)))])
    assert state == check.SKIP and words.startswith("it lived to a sample: the reader and the sample both held it")
    mixed = [("t.jsonl", child_line(programs=("curl", "wget"), seen=("events", "both")))]   # curl's entry is not it
    assert x36(report=report, sources=mixed)[0] == check.SKIP
    state, words = x36(report=report, sources=[("t.jsonl", child_line(seen=("sample",)))])
    assert state == check.MISSED and "the sample alone saw the wget on pid 9828" in words
    for sources in ((), [("t.jsonl", child_line(pid=77))], [("t.jsonl", child_line(programs=("curl",)))],
                    [("t.jsonl", child_line(seen=None))], [("t.jsonl", child_line(seen=("events", "x")))]):
        state, words = x36(report=report, sources=sources)
        assert state == check.MISSED and "whose word it is cannot be told" in words, sources


def test_x36_missed_where_the_stand_in_ran_wget_and_no_line_of_its_tree_names_it():
    state, words = x36()   # its curl's lines are there, none names wget
    assert state == check.MISSED and "ran wget (rc=0) and no NET-TOOL line on pid 9828 names it" in words
    other = with_wget().replace("NET-TOOL on python pid 9828 via host: HostChild may reach the network at seq 5",
                                "NET-TOOL on python pid 77 via host: HostChild may reach the network at seq 5")
    assert x36(report=other.replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1))[0] == check.MISSED
    assert check.read_short_tool(None, WGET_WORKLOAD, "linux")[0][1] == check.MISSED   # never raises


def test_x36_n_a_off_linux_without_wget_where_the_stand_in_did_not_run_it_or_the_helper_was_refused():
    assert x36(platform="win32")[0] == check.SKIP
    assert x36(workload=LINUX_WORKLOAD.replace("WORKLOAD 07:51:15 done", "WORKLOAD 07:50:57 wget not installed\n"
                                               "WORKLOAD 07:51:15 done"))[0] == check.SKIP
    assert x36(workload=LINUX_WORKLOAD)[0] == check.SKIP
    refused = EVENTS_SECTION + "  refused: the process events are not read: no answer to the ask within 2 s\n"
    state, words = x36(section=refused)
    assert state == check.SKIP and "refused" in words


def test_x36_is_a_row_of_main(tmp_path, capsys):
    (tmp_path / "w.out").write_text(with_wget().replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1),
                                    encoding="utf-8")
    (tmp_path / "l.out").write_text(WGET_WORKLOAD, encoding="utf-8")
    (tmp_path / "sources").mkdir()
    (tmp_path / "sources" / READER_SOURCES[0][0]).write_text(READER_SOURCES[0][1], encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "linux"]
    check.main(base + ["--sources", str(tmp_path / "sources")])
    assert "MET     X36 " in capsys.readouterr().out
    check.main(base)   # no sources: whose word it is cannot be told
    assert "MISSED  X36 " in capsys.readouterr().out


# --- X37 (ADR-0014 AG-4): the autostart places read by Raqib itself beside the stand-in -------------------------
def autostart_facts(**over):
    changes = []
    for place, name in check.AUTOSTART_ACTS:
        changes += [{"round": 4, "change": "added", "place": place, "scope": "user", "view32": False, "name": name,
                     "program": None}, {"round": 30, "change": "removed", "place": place, "scope": "user",
                                        "view32": False, "name": name, "program": None}]
    held = {"made": True, "error": None, "removed": True, "reads": [   # ADR-0014 AI-10: the file held across one read
        {"round": 2, "held": True, "listed": True, "content": "not read", "changes": ["added"]},
        {"round": 3, "held": False, "listed": True, "content": "read", "changes": ["read"]},
        {"round": 4, "held": False, "listed": False, "content": None, "changes": ["removed"]}]}
    facts = {"platform": "win32", "reads": 40, "seconds_max": 0.09, "changes": changes, "unread": [], "error": None,
             "held": held, "workload": ["WORKLOAD 07:50:50 startup file written",
                                        "WORKLOAD 07:51:30 undone: the startup file"]}
    facts.update(over)
    return facts


def x37(facts):
    rows = check.read_autostart(facts)
    assert len(rows) == 1 and rows[0][0].startswith("X37 ")
    return rows[0][1], rows[0][2]


def test_x37_met_where_each_act_is_added_and_later_removed():
    state, words = x37(autostart_facts())
    assert state == check.MET and "service added in read 4, removed in read 30" in words and "40 read(s)" in words


@pytest.mark.parametrize("drop,why", [(("added", "service"), "service RaqibRigService: no added change"),
                                      (("removed", "run"), "run RaqibRigValue: added in read 4, no removed change"),
                                      (("added", "startup"), "startup raqib-rig-startup.cmd: no added change")])
def test_x37_missed_where_an_act_is_not_added_then_removed(drop, why):
    facts = autostart_facts()
    facts["changes"] = [c for c in facts["changes"] if (c["change"], c["place"]) != drop]
    facts["unread"] = [{"round": 7, "places": {"task": "refused"}}]
    state, words = x37(facts)
    assert state == check.MISSED and why in words and "read 7: task" in words


def test_x37_missed_where_the_removal_came_first_or_the_run_was_silent():
    facts = autostart_facts()
    for c in facts["changes"]:
        c["round"] = {"added": 30, "removed": 4}[c["change"]]
    assert x37(facts)[0] == check.MISSED
    assert x37(None)[0] == check.MISSED and x37({"platform": "win32", "changes": 3})[0] == check.MISSED
    assert x37(autostart_facts(error="OSError: x"))[0] == check.MISSED
    assert x37(autostart_facts(not_run="why"))[0] == check.MISSED


def test_x37_says_when_the_run_ended_the_stand_in_and_its_acts_were_not_undone():
    """ADR-0014 AH-4: a stand-in the run had to end did not undo its acts; X37's row says so, MISSED."""
    facts = autostart_facts(ended_by_run=True)
    facts["changes"] = [c for c in facts["changes"] if c["change"] == "added"]
    state, words = x37(facts)
    assert state == check.MISSED and "the run ended the stand-in before its end: its acts were not undone" in words
    state, words = x37(autostart_facts(error="OSError (5)", ended_by_run=True))
    assert state == check.MISSED and "its acts were not undone" in words
    assert "not undone" not in x37(autostart_facts(error="OSError (5)"))[1]


def test_x37_n_a_off_windows_and_a_row_of_main_only_where_given(tmp_path, capsys):
    import json
    assert x37({"platform": "linux", "not_run": "not Windows (linux)"})[0] == check.SKIP
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text("WORKLOAD 07:50:35 pid 9828\n", encoding="utf-8")
    (tmp_path / "a.json").write_text(json.dumps(autostart_facts()), encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]
    check.main(base)
    assert "X37 " not in capsys.readouterr().out
    check.main(base + ["--autostart", str(tmp_path / "a.json")])
    assert "MET     X37 " in capsys.readouterr().out
    check.main(base + ["--autostart", str(tmp_path / "none.json")])
    assert "MISSED  X37 " in capsys.readouterr().out


# --- X37 (ADR-0014 AI-10): the stand-in's delete, the held file, every other change by its kind ------------------
def test_x37_missed_where_the_stand_ins_delete_of_its_startup_file_failed():
    facts = autostart_facts(workload=["WORKLOAD 07:51:30 the startup file's delete failed (PermissionError)"])
    state, words = x37(facts)
    assert state == check.MISSED and "its Startup file failed beside the reads (PermissionError)" in words


@pytest.mark.parametrize("held,why", [
    ({"made": False, "error": "PermissionError (5)", "reads": []}, "the held file was not made (PermissionError (5))"),
    ({"made": True, "reads": [{"round": 2, "listed": False, "changes": []}]}, "the held file was listed by no read"),
    ({"made": True, "reads": [{"round": 2, "listed": True, "content": "not read", "changes": []},
                              {"round": 3, "listed": True, "content": "read", "changes": ["added"]}]},
     "not said as added by the first read that listed it (read 2: no change)")])
def test_x37_missed_where_the_held_file_was_not_said_as_added_by_the_first_read_that_listed_it(held, why):
    state, words = x37(autostart_facts(held=held))
    assert state == check.MISSED and why in words


def test_x37_names_every_other_change_by_its_kind_and_place():
    facts = autostart_facts()
    facts["changes"] += [{"round": 9, "change": "rescheduled", "place": "task", "name": "\\Vendor\\Task"},
                         {"round": 12, "change": "changed", "place": "task", "name": "\\Vendor\\Other"},
                         {"round": 2, "change": "added", "place": "startup", "name": "raqib-rig-held.cmd"}]
    state, words = x37(facts)
    assert state == check.MET and "other changes: changed task 1, rescheduled task 1" in words
    assert ("the held file added in read 2 while held, its content not read, read after it was let go, and removed"
            " after") in words
    assert "other changes: none" in x37(autostart_facts())[1]


# --- X37 (ADR-0014 AJ-7): the held read, the held file removed, a place read in part ----------------------------
@pytest.mark.parametrize("first,removed,why", [
    ({"round": 3, "held": False, "listed": True, "content": "read", "changes": ["added"]}, True,
     "the read that first listed the held file was not the one made while it was held"),
    ({"round": 2, "held": True, "listed": True, "content": "read", "changes": ["added"]}, True,
     "(read 2: held True, content read)"),
    ({"round": 2, "held": True, "listed": True, "content": "not read", "changes": ["added"]}, False,
     "the held file was not removed after")])
def test_x37_missed_unless_the_held_read_listed_it_unread_and_it_was_removed(first, removed, why):
    later = {"round": 3, "held": False, "listed": True, "content": "read", "changes": ["read"]}   # AK-7: read after
    held = {"made": True, "error": None, "removed": removed, "reads": [first, later]}
    state, words = x37(autostart_facts(held=held))
    assert state == check.MISSED and why in words


def test_x37_says_a_place_read_in_part_as_read_in_part_not_as_unread():
    facts = autostart_facts(unread=[{"round": 5, "places": {"task": "refused"}},
                                    {"round": 6, "places": {"task": "in part: 26 key(s) refused"}}],
                            partly=[{"round": 7, "places": {"task": "in part: 26 key(s) refused"}}])
    state, words = x37(facts)
    assert state == check.MET and "unread: read 5: task; read in part: read 6: task; read 7: task" in words



def test_x37_missed_where_no_later_read_after_the_let_go_read_the_held_files_content():
    """ADR-0014 AK-7: a run whose opener never read a Startup file is not MET on the held file."""
    held = {"made": True, "error": None, "removed": True, "reads": [
        {"round": 2, "held": True, "listed": True, "content": "not read", "changes": ["added"]},
        {"round": 3, "held": False, "listed": True, "content": "not read", "changes": []},
        {"round": 4, "held": False, "listed": False, "content": None, "changes": ["removed"]}]}
    state, words = x37(autostart_facts(held=held))
    assert state == check.MISSED and "no later read, after the held file was let go, read its content" in words


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


# --- X43 to X46 (ADR-0007 CC-7, CE-3, CE-5): programs a child runs later, the name nc, an outliving bash, sudo ------
LATER_WORKLOAD = LINUX_WORKLOAD.replace("WORKLOAD 07:51:15 done\n", "WORKLOAD 07:51:00 start bash\n"
                                        "WORKLOAD 07:51:00 bash-exec pid 9911\nWORKLOAD 07:51:08 end bash rc=0\n"
                                        "WORKLOAD 07:51:08 start nc\nWORKLOAD 07:51:09 end nc rc=0\n"
                                        "WORKLOAD 07:51:09 start sh\nWORKLOAD 07:51:09 outliving pid 9922 (sh rc=0)\n"
                                        "WORKLOAD 07:51:19 outliving waited\nWORKLOAD 07:51:20 start sudo\n"
                                        "WORKLOAD 07:51:20 sudo-fetch pid 9930\nWORKLOAD 07:51:21 end sudo rc=0\n"
                                        "WORKLOAD 07:51:22 done\n")


def later_line(seq, children, programs, seen=None, unread=None):
    """A HostChild line of the stand-in's tree: its children [(pid, image)] and programs, where each was seen."""
    meta = {"command_programs": list(programs), "command_sources": list(seen or ["events"] * len(programs)),
            "pid": 9828, "children": [{"pid": p, "image": i} for p, i in children], "cites": []}
    if unread:
        meta["files_unread"] = list(unread)
    return json.dumps({"seq": seq, "tool": "HostChild", "source": "host", "input_meta": meta}) + "\n"


LATER_SOURCES = [("t.jsonl", later_line(6, [(9911, "bash")], ["bash"]) + later_line(8, [(9911, "wget")], ["wget"])
                  + later_line(9, [(9915, "nc.openbsd")], ["nc.openbsd", "nc"])
                  + later_line(10, [(9922, "bash")], ["bash"]) + later_line(12, [(9922, "wget")], ["wget"])
                  + later_line(14, [(9930, "sudo"), (9931, "wget")], ["sudo", "wget"], unread=["sudo", "wget"]))]


def later_report(*seqs):
    report = REPORT
    at = report.index("  [medium] NET-TOOL on python pid 9828")
    lines = "".join("  [medium] NET-TOOL on python pid 9828 via host: HostChild may reach the network at seq %d (host -,"
                    " program %s, programs [\"%s\"]); off\n" % (seq, x, x) for seq, x in seqs)
    return (report[:at] + lines + report[at:]).replace("TREES SEEN:", EVENTS_SECTION + "TREES SEEN:", 1)


ALL_CITED = later_report((8, "wget"), (9, "nc"), (12, "wget"), (14, "wget"))


def later(report=ALL_CITED, workload=LATER_WORKLOAD, platform="linux", sources=LATER_SOURCES):
    rows = check.read_later_programs(report, workload, platform, sources)
    assert [r[0][:4] for r in rows] == ["X43 ", "X44 ", "X45 ", "X46 "]
    return {r[0][:3]: (r[1], r[2]) for r in rows}


def test_x43_to_x46_met_where_each_childs_own_entry_names_it_and_a_finding_cites_that_line():
    got = later()
    assert {k: v[0] for k, v in got.items()} == {"X43": check.MET, "X44": check.MET, "X45": check.MET,
                                                 "X46": check.MET}
    assert "own entry for pid 9911 names wget (seq 8)" in got["X43"][1]
    assert "own entry for pid 9922 names wget (seq 12)" in got["X45"][1] and "seen by: events" in got["X44"][1]


def test_x45_is_missed_where_its_pid_shares_a_line_with_another_childs_fetch():
    """CE-5: the outliving bash's first line shares a round with X43's wget: the line names wget and holds pid 9922,
    but 9922's own entry is bash: not MET."""
    shared = [("t.jsonl", later_line(8, [(9911, "wget"), (9922, "bash")], ["wget", "bash"]))]
    got = later(report=later_report((8, "wget")), sources=shared)
    assert got["X43"][0] == check.MET and got["X45"][0] == check.MISSED
    assert later(report=later_report((9, "wget")), sources=shared)["X43"][0] == check.MISSED   # cites another line


def test_x44_says_where_nc_was_seen_and_is_not_met_by_a_samples_name_alone():
    sample_only = [("t.jsonl", later_line(9, [(9915, "nc")], ["nc"], seen=["sample"]))]
    state, words = later(sources=sample_only)["X44"]
    assert state == check.MISSED and "seen by: sample" in words
    both = [("t.jsonl", later_line(9, [(9915, "nc.openbsd")], ["nc.openbsd", "nc"], seen=["both", "both"]))]
    assert later(sources=both)["X44"][0] == check.MET   # its file by another name: CC-2's own word


def test_x46_needs_the_events_alone_and_the_file_said_not_read():
    for meta in (later_line(14, [(9931, "wget")], ["wget"], unread=None),
                 later_line(14, [(9931, "wget")], ["wget"], seen=["both"], unread=["wget"])):
        assert later(sources=[("t.jsonl", meta)])["X46"][0] == check.MISSED


def test_x43_to_x46_missed_where_the_line_or_the_citing_finding_is_not_there():
    only_bash = [("t.jsonl", later_line(6, [(9911, "bash")], ["bash"]) + later_line(10, [(9922, "bash")], ["bash"]))]
    assert {v[0] for v in later(sources=only_bash).values()} == {check.MISSED}
    assert {v[0] for v in later(report=later_report((1, "curl"))).values()} == {check.MISSED}
    assert "no sources given" in later(sources=())["X43"][1]
    assert {v[0] for v in later(report=None, workload=None).values()} == {check.SKIP}   # never raises: not said run


def test_x43_to_x46_n_a_off_linux_without_the_tool_where_not_run_or_the_helper_was_refused():
    assert {v[0] for v in later(platform="win32").values()} == {check.SKIP}
    refused = ALL_CITED.replace("  lost: none\n", "  lost: none\n  refused: the process events are not read: no"
                                " answer\n")
    assert {v[0] for v in later(report=refused).values()} == {check.SKIP}
    missing = LATER_WORKLOAD.replace("start nc\n", "nc not installed\n").replace(
        "bash-exec pid 9911", "bash-exec not run: wget or bash not installed").replace(
        "outliving pid 9922 (sh rc=0)", "outliving not run: wget, bash or sh not installed").replace(
        "sudo-fetch pid 9930", "sudo-fetch not run: sudo -n is not allowed here")
    assert {v[0] for v in later(workload=missing).values()} == {check.SKIP}
    assert {v[0] for v in later(workload=LINUX_WORKLOAD).values()} == {check.SKIP}   # an older stand-in


# --- X47 (ADR-0007 CG-3, M17.2a): a Raqib packed with its own runtime keeps its process events -------------------
PACKED = """raqib watch --host: sources: the host's own record of every tree (the watch's own check at its start)
Raqib watch --host (ADR-0007): the host, not a name; raqib 9.8.7
ROUNDS: 4 started, 4 with an inventory, 0 late, 0 failed
PROCESS EVENTS (Linux): the kernel's process events, read by a helper process of the watch's own; judged: a process
  rounds asked: 4, answered: 4
  processes that began: 48; of them began and ended between two asks: 47
  programs not read: 0 (reads at an exec that failed)
  given to the rounds: 48; joined to a tree as its child: 48; of them with no program read (no line): 2
  past the reader's bounds: 0
  lost: none
TREES SEEN: 2 (2 now, 0 quiet)
  [candidate] pid 4105 agent-example (named: image agent-example is the catalog's agent-example): now; first round 1 (history, not knocked); last round 4; 2 act(s)
      source: host (host: the host's own record of the tree: /home/user/.raqib/host/sources/a.jsonl); findings none
  [candidate] [brief] pid 4111 raqib-notes (unknown): now; first round 1 (history, not knocked); last round 4; 1 act(s)
      source: host (host: the host's own record of the tree: /home/user/.raqib/host/sources/b.jsonl); findings none
FINDINGS: 0
RESULT: CLEAN (exit 0: trees listed, nothing new)
"""
FIELD_ENDED = (  # the field's words (Amendment CG, GitHub's Linux machine) and this task's own run before its change
    "  rounds asked: 2, answered: 0",
    "  started again, round 1: ended: the helper of the process events ended (its output ended); it is started again,"
    " once; nothing was heard between the end of the helper before and this start\n"
    "  hole, round 1: ended: the helper of the process events ended (its output ended); it is started again, once\n"
    "  hole, round 2: ended for good: the helper of the process events ended again (its output ended): the process"
    " events are not read for the rest of the watch")


def x47(report, platform="linux"):
    ((ident, state, words),) = check.read_packed(report, platform)
    assert ident.startswith("X47 ") and ident == check.PACKED_EVENTS_NAME
    return state, words


def test_x47_met_where_every_ask_of_at_least_3_was_answered_no_helper_ended_and_no_tree_is_the_packed_program():
    state, words = x47(PACKED)
    assert state == check.MET, words
    assert "rounds asked: 4, answered: 4" in words and "2 tree line(s) read" in words
    assert "processes heard to begin: 48" in words
    # CH-2 (the review's S5): a packed helper that answers and hears nothing is not MET
    for said, why in (("processes that began: 0;", "processes that began: 0 (the job starts six"),
                      ("processes that began: 2;", "processes that began: 2 (the job starts six")):
        state, words = x47(PACKED.replace("processes that began: 48;", said))
        assert state == check.MISSED and why in words, words
    state, words = x47(PACKED.replace("  processes that began: 48; of them began and ended between two asks: 47\n", ""))
    assert state == check.MISSED and "no count of the processes that began" in words
    assert x47(PACKED.replace("processes that began: 48;", "processes that began: 3;"))[0] == check.MET
    assert x47(PACKED.replace("asked: 4, answered: 4", "asked: 3, answered: 3"))[0] == check.MET
    assert x47(PACKED.replace("\n", "\r\n"))[0] == check.MET   # a report of Windows' line ends is read the same


@pytest.mark.parametrize("change, said", [
    (lambda r: r.replace("  rounds asked: 4, answered: 4\n", FIELD_ENDED[0] + "\n" + FIELD_ENDED[1] + "\n").replace(
        "  lost: none", "  lost: not known (no answer)"), "rounds asked: 2, answered: 0 (at least 3"),
    (lambda r: r.replace("  rounds asked: 4, answered: 4\n", FIELD_ENDED[0] + "\n" + FIELD_ENDED[1] + "\n"),
     "3 line(s) say the helper ended or was started again"),
    (lambda r: r.replace("asked: 4, answered: 4", "asked: 4, answered: 3"), "rounds asked: 4, answered: 3"),
    (lambda r: r.replace("asked: 4, answered: 4", "asked: 2, answered: 2"), "rounds asked: 2, answered: 2 (at least"),
    (lambda r: r.replace("asked: 4, answered: 4", "asked: 0, answered: 0"), "rounds asked: 0, answered: 0"),
    (lambda r: r.replace("  rounds asked: 4, answered: 4\n", ""), "no count of the rounds asked and answered"),
    (lambda r: r.replace("  lost: none\n", "  lost: none\n  hole, round 2: ended: the helper of the process events ended"
                         " (its output ended); it is started again, once\n"), "1 line(s) say the helper ended"),
    (lambda r: r.replace("  lost: none\n", "  lost: none\n  started again, round 3: late 3 rounds running (0.75 s each):"
                         " ended by the watch; nothing was heard between the end of the helper before and this start\n"),
     "1 line(s) say the helper ended or was started again: started again, round 3"),
    (lambda r: r.replace("FINDINGS: 0", "FINDINGS: 0\n[19:15:31Z] BLIND SPOT round 1: the process events: ended: the"
                         " helper of the process events ended (its output ended)"), "1 line(s) say the helper ended"),
    (lambda r: r.replace("  lost: none\n", "  lost: none\n  refused: the process events are not read: the socket was"
                         " refused (EPERM: a fake)\n"), "the helper's reader was refused: the process events are not"),
    (lambda r: r.replace("pid 4105 agent-example (named: image agent-example is the catalog's agent-example)",
                         "pid 4120 raqib (unknown)"), "a tree of the report is the packed program itself (raqib): pid 4120"),
    (lambda r: r.replace("[brief] pid 4111 raqib-notes", "[brief] pid 4111 raqib"), "(raqib): pid 4111"),
    (lambda r: r.replace("pid 4111 raqib-notes", "pid 4111 RAQIB"), "(raqib): pid 4111"),
    (lambda r: r.split("TREES SEEN")[0], "the report holds no TREES SEEN section"),
    (lambda r: r.replace("PROCESS EVENTS (Linux):", "PROCESSES (Linux):"), "holds no PROCESS EVENTS (Linux): section"),
    (lambda r: "", "the packed watch's report is empty (silence is a finding)"),
    (lambda r: "\n  \n", "the packed watch's report is empty"),
])
def test_x47_missed_for_each_way_the_packed_watch_lost_its_process_events(change, said):
    state, words = x47(change(PACKED))
    assert state == check.MISSED and said in words, words


def test_x47_n_a_off_linux_and_where_no_report_was_given():
    for platform in ("win32", "darwin", None):
        state, words = x47(PACKED, platform)
        assert state == check.SKIP and words.startswith("not run: not Linux")
    assert x47(None) == (check.SKIP, "no packed watch's report was given (--packed)")
    assert x47("", "win32")[0] == check.SKIP


def test_x47_main_reads_packed_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(PACKED, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "linux"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X47 " in x and not x.startswith("::")]
        return line.split()[0]
    assert row(["--packed", str(tmp_path / "w.out")]) == check.MET
    assert row(["--packed", str(tmp_path / "none.out")]) == check.MISSED   # given and missing: its silence
    assert row([]) == check.SKIP


def test_x47_the_packer_is_pinned_one_folder_no_window_toolkit_and_no_dependency_of_raqib():
    pack = (ROOT / "tools" / "rig" / "pack.sh").read_text(encoding="utf-8")
    assert pack.isascii() and "PINNED=6.11.1" in pack and "NAME=%s " % check.PACKED_NAME in pack
    for flag in ("--onedir", "--collect-all raqib", "--exclude-module tkinter", "--noconfirm"):
        assert flag in pack
    assert "--onefile" not in pack and "pip install" not in pack   # the job installs the packer, not the tool
    assert "pyinstaller" not in (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    rig = (ROOT / ".github" / "workflows" / "rig.yml").read_text(encoding="utf-8")
    linux = rig[rig.index("\n  linux:"):rig.index("\n  siem:")]
    assert "pyinstaller==6.11.1" in linux and "tools/rig/pack.sh" in linux
    assert "watch --host --rounds 4 --every 3 --no-open --no-page" in linux
    assert '2> "$RUNNER_TEMP/packed.err" &' in linux and "do /bin/true; sleep 1; done" in linux   # CH-2
    assert 'cp -r "$RUNNER_TEMP/packed-home/.raqib/host" rig-out/packed-host' in linux           # the review's S3
    assert '--packed "$RUNNER_TEMP/packed.out"' in linux
    windows = rig[rig.index("\n  windows:"):rig.index("\n  linux:")]
    assert "--packed" not in windows   # X47's packed watch is Linux's
    # K-8 (X49): the Windows job packs too, with the same pinned packer and pack.sh's arguments, for the check only
    assert windows.lower().count("pyinstaller") == 1 and "pyinstaller==6.11.1" in windows
    asked = (ROOT / "tools" / "rig" / "service_check.ps1").read_text(encoding="utf-8")
    assert asked.isascii() and "pip install" not in asked and "--onefile" not in asked
    for flag in ("--onedir", "--name %s " % check.PACKED_NAME, "--collect-all raqib", "--exclude-module tkinter",
                 "--noconfirm"):
        assert flag in asked
    assert "service check" in asked and "tools\\rig\\service_check.ps1" in windows
    assert "--service-check $env:RUNNER_TEMP\\service-check\\service-check.txt" in windows
    # M-6 (X50): the plain interpreter's question needs no packer; it asks each interpreter with -I
    plain = (ROOT / "tools" / "rig" / "service_check_plain.ps1").read_text(encoding="utf-8")
    assert plain.isascii() and "pip install" not in plain and "PyInstaller" not in plain
    assert "-I -m raqib service check" in plain and "tools\\rig\\service_check_plain.ps1" in windows
    assert ("--service-check-plain $env:RUNNER_TEMP\\service-check-plain\\service-check-plain.txt" in windows)
    # P-3 (X51): the same packed copy asked through a letter given to its folder; the letter taken back
    drive = (ROOT / "tools" / "rig" / "service_check_drive.ps1").read_text(encoding="utf-8")
    assert drive.isascii() and "pip install" not in drive and "PyInstaller" not in drive
    assert 'subst "${letter}:" $system' in drive and 'subst "${letter}:" /D' in drive and "service check" in drive
    assert "tools\\rig\\service_check_drive.ps1 -Packed $env:RUNNER_TEMP\\service-check\\pack\\dist\\raqib" in windows
    assert ("--service-check-drive $env:RUNNER_TEMP\\service-check-drive\\service-check-drive.txt" in windows)
    # T-3 (X48, X52): the job's services are made from a copy of its Python under Program Files, one folder deeper,
    # with -I; one more is made from the job's own Python, which the runner's own check refuses
    again = (ROOT / "tools" / "rig" / "service_again.ps1").read_text(encoding="utf-8")
    refused = (ROOT / "tools" / "rig" / "service_refused.ps1").read_text(encoding="utf-8")
    for script in (again, refused):
        assert script.isascii() and "pip install" not in script and "taskkill" not in script.replace(
            "taskkill /f /pid $killed", "")   # X48 ends the one process it made, and nothing else does
        assert "-I -m raqib service run" in script and "Join-Path $env:ProgramFiles" in script
        assert "Remove-Item -Recurse -Force $holder" in script or "$place, $holder" in script
    assert '$py = Join-Path $holder "Py\\python.exe"' in again and "(Get-Command python).Source) (Join-Path" in again
    assert all("%s: " % key in refused for key in check.REFUSED_KEYS)
    assert "its own code, checked at this start" in refused and check.RUNNER_SAID.endswith(
        "its own code, checked at this start")
    assert "tools\\rig\\service_refused.ps1 -Out $env:RUNNER_TEMP\\service-refused" in windows
    assert "--service-refused $env:RUNNER_TEMP\\service-refused\\service-refused.txt" in windows


# --- X48 (ADR-0013 AH-3, M12.4b): a service of Windows ended from outside runs again, and its next watch says so ---
RUN_A, RUN_B = "20261127T080000.000Z-4242", "20261127T080041.000Z-5150"
RUNFILE = "killed-pid: 4242\nagain-pid: 5150\nagain-seconds: 41.3\nstate: Running\n"


def ev(run, kind, **kw):
    return json.dumps(dict({"kind": kind, "watch": {"mode": "host", "run": run, "platform": "win32"}}, **kw))


UNENDED_SUMMARY = ("watch-unended: the host watch before this one, run %s (pid 4242), left its state"
                   " C:\\ProgramData\\Raqib\\.raqib\\host\\rounds.jsonl.watch.json unfinished with its heartbeat"
                   " stale: its last heartbeat 2026-11-27T08:00:09.500Z, 31 s before this start; a watch that ended"
                   " without its end (ended from outside, a crash or a power loss) or one that stopped writing its"
                   " state: for those 31 s no watch of this home is known to have watched" % RUN_A)
EVENTS_PAIR = "\n".join([
    ev(RUN_A, "watch", state="start"), ev(RUN_A, "heartbeat"),
    ev(RUN_B, "watch", state="start"),
    ev(RUN_B, "hole", about="hole:1", hole={"class": "hole", "kind": "watch-unended"}, summary=UNENDED_SUMMARY),
    ev(RUN_B, "heartbeat"), ev(RUN_B, "watch", state="end")]) + "\n"


def x48(runfile=RUNFILE, events=EVENTS_PAIR):
    ((ident, state, words),) = check.read_service_again(runfile, events)
    assert ident.startswith("X48 ") and ident == check.SERVICE_AGAIN_NAME
    return state, words


def test_x48_met_where_the_service_ran_again_and_the_later_run_says_the_earlier_one_that_has_no_end():
    state, words = x48()
    assert state == check.MET, words
    assert "pid 5150, not 4242, Running 41.3 s" in words and "run %s says the hole watch-unended naming run %s" % (
        RUN_B, RUN_A) in words
    assert x48(RUNFILE.replace("\n", "\r\n"), EVENTS_PAIR.replace("\n", "\r\n"))[0] == check.MET
    assert x48(RUNFILE.replace("41.3", "90"))[0] == check.MET
    assert check.AGAIN_SECONDS_MAX == 90 and check.UNENDED_KIND == "watch-unended"


def test_x48_met_on_the_events_two_real_watches_write(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    import test_host_unended as unended
    from raqib import host
    assert host.UNENDED == check.UNENDED_KIND
    w1, c1 = unended.watch(tmp_path)
    unended.rounds(w1, c1, 2)                          # ended without its end: never finished
    pid = w1.state(c1())["pid"]
    w2, c2 = unended.watch(tmp_path, wall0=unended.BASE + 41, run="20261103T100041.000Z-%d" % (pid + 1))
    unended.rounds(w2, c2, 1)
    w2.finish()
    assert UNENDED_SUMMARY.split(": ", 1)[1] == host.before_hole(
        {"held": host.HELD_STALE, "run": RUN_A, "pid": 4242, "heartbeat": "2026-11-27T08:00:09.500Z", "age": 31.4},
        "C:\\ProgramData\\Raqib\\.raqib\\host\\rounds.jsonl.watch.json")[1]   # the fixture's words: the engine's
    events = (tmp_path / "home" / ".raqib" / "host" / "events.jsonl").read_text(encoding="ascii")
    state, words = x48("killed-pid: %d\nagain-pid: %d\nagain-seconds: 41\nstate: Running\n" % (pid, pid + 1), events)
    assert state == check.MET and "naming run %s" % w1.run in words, words


@pytest.mark.parametrize("runfile, events, said", [
    (RUNFILE.replace("state: Running", "state: Stopped"), EVENTS_PAIR, "the service's state is Stopped, not Running"),
    (RUNFILE.replace("state: Running\n", ""), EVENTS_PAIR, "the service's state is not said, not Running"),
    (RUNFILE.replace("again-pid: 5150", "again-pid: 4242"), EVENTS_PAIR,
     "again-pid 4242 is killed-pid: the service did not run again with another pid"),
    (RUNFILE.replace("again-pid: 5150", "again-pid: none"), EVENTS_PAIR, "no again-pid that is a number (none)"),
    (RUNFILE.replace("killed-pid: 4242\n", ""), EVENTS_PAIR, "no killed-pid that is a number (not said)"),
    (RUNFILE.replace("41.3", "91"), EVENTS_PAIR, "again-seconds 91 is over 90"),
    (RUNFILE.replace("41.3", "soon"), EVENTS_PAIR, "no again-seconds that is a number (soon)"),
    ("", EVENTS_PAIR, "the run's file is empty (silence is a finding)"),
    (None, EVENTS_PAIR, "the run's file is not given"),
    (RUNFILE, "", "the place's events are empty (silence is a finding)"),
    (RUNFILE, None, "the place's events are not given"),
    (RUNFILE, "\n".join(l for l in EVENTS_PAIR.splitlines() if RUN_A not in l.split('"summary"')[0]),
     "the events hold 1 run(s) of a host watch, not two"),
    (RUNFILE, EVENTS_PAIR.replace('"watch-unended"', '"rounds-corrupt"'), "no run's events hold the hole watch-unended"),
    (RUNFILE, EVENTS_PAIR + ev(RUN_A, "watch", state="end") + "\n",
     "the hole of run %s names run %s, which has an end" % (RUN_B, RUN_A)),
    (RUNFILE, EVENTS_PAIR.replace("run %s (pid" % RUN_A, "run 20261127T070000.000Z-1 (pid"),
     "names run 20261127T070000.000Z-1, which is not an earlier run of the events"),
    (RUNFILE, EVENTS_PAIR.replace("the host watch before this one, run", "a watch before"),
     "the hole of run %s names no run" % RUN_B),
    (RUNFILE, EVENTS_PAIR.replace('"mode": "host"', '"mode": "project"'), "the events hold 0 run(s) of a host watch"),
])
def test_x48_missed_for_each_thing_not_found(runfile, events, said):
    state, words = x48(runfile, events)
    assert state == check.MISSED and said in words, words


def test_x48_n_a_where_neither_file_was_given():
    assert x48(None, None) == (check.SKIP, "no service run was given (--service-run, --service-events)")


def test_x48_main_reads_both_files_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "run.txt").write_text(RUNFILE, encoding="utf-16")     # a redirect of Windows PowerShell 5
    (tmp_path / "events.jsonl").write_text(EVENTS_PAIR, encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X48 " in x and not x.startswith("::")]
        return line.split()[0]
    both = ["--service-run", str(tmp_path / "run.txt"), "--service-events", str(tmp_path / "events.jsonl")]
    assert row(both) == check.MET
    assert row(["--service-run", str(tmp_path / "none.txt"), "--service-events", str(tmp_path / "events.jsonl")]) == \
        check.MISSED
    assert row(["--service-run", str(tmp_path / "run.txt")]) == check.MISSED   # the events not given: MISSED
    assert row([]) == check.SKIP


# --- M12.4b REDO (ADR-0013 AI-5): X48 rests on the end the job made -------------------------------------------------
RUN_C = "20261127T080300.000Z-6060"
OLD_X, OLD_Y = "20261127T070000.000Z-1111", "20261127T070040.000Z-2222"


def unended_summary(run, pid):
    return UNENDED_SUMMARY.replace("run %s (pid 4242)" % RUN_A, "run %s (pid %s)" % (run, pid))


def test_x48_met_only_where_the_holes_pid_is_killed_pid_and_the_later_run_is_again_pids():
    assert x48(RUNFILE.replace("killed-pid: 4242", "killed-pid: 4343")) == (check.MISSED, (
        "missing: the hole of run %s names pid 4242, not killed-pid 4343" % RUN_B))
    state, words = x48(RUNFILE.replace("again-pid: 5150", "again-pid: 5151"))
    assert state == check.MISSED and "run %s is not the one again-pid 5151 wrote" % RUN_B in words
    assert x48(RUNFILE.replace("again-pid: 5150", "again-pid: 150"))[0] == check.MISSED   # "-150" is not "-5150"
    match = check.UNENDED_RUN.search(UNENDED_SUMMARY)
    assert match.groups() == (RUN_A, "4242")


def test_x48_three_runs_the_pair_of_this_kill_is_found_and_an_older_pair_meets_nothing():
    third = "\n".join([ev(RUN_C, "watch", state="start"), ev(RUN_C, "watch", state="end")]) + "\n"
    state, words = x48(RUNFILE, EVENTS_PAIR + third)       # after a Stop and one more start: no second hole
    assert state == check.MET and "run %s says the hole watch-unended naming run %s" % (RUN_B, RUN_A) in words
    older = "\n".join([ev(OLD_X, "watch", state="start"), ev(OLD_Y, "watch", state="start"),
                       ev(OLD_Y, "hole", about="hole:1", hole={"class": "hole", "kind": "watch-unended"},
                          summary=unended_summary(OLD_X, 1111)), ev(OLD_Y, "watch", state="end")]) + "\n"
    assert x48(RUNFILE, older + EVENTS_PAIR)[0] == check.MET
    state, words = x48(RUNFILE, older + third)              # only a pair this kill did not make: MISSED
    assert state == check.MISSED and "names pid 1111, not killed-pid 4242" in words, words


def test_x48_a_torn_last_line_and_a_byte_order_mark_are_read_past():
    assert x48(RUNFILE, EVENTS_PAIR + '{"kind": "heartbeat", "watch": {"mode": "ho')[0] == check.MET
    assert x48(RUNFILE, EVENTS_PAIR.rstrip("\n")[:-7])[0] == check.MET   # the end's line itself torn
    assert x48("\ufeff" + RUNFILE)[0] == check.MET
    assert x48(RUNFILE, "\ufeff" + EVENTS_PAIR)[0] == check.MET
    assert x48("\ufeff")[1] == "missing: the run's file is empty (silence is a finding)"


def test_x48_a_negative_again_seconds_and_an_again_pid_of_0_are_missed():
    assert x48(RUNFILE.replace("41.3", "-2")) == (check.MISSED, "missing: again-seconds -2 is before the end from"
                                                                " outside")
    assert x48(RUNFILE.replace("again-pid: 5150", "again-pid: 0"))[1].startswith("missing: again-pid 0 is no process's")


def test_x48_main_reads_a_utf8_runfile_with_its_byte_order_mark(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "run.txt").write_bytes(b"\xef\xbb\xbf" + RUNFILE.replace("\n", "\r\n").encode("ascii"))
    (tmp_path / "events.jsonl").write_text(EVENTS_PAIR, encoding="utf-8")
    check.main(["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32",
                "--service-run", str(tmp_path / "run.txt"), "--service-events", str(tmp_path / "events.jsonl")])
    (line,) = [x for x in capsys.readouterr().out.splitlines() if "X48 " in x and not x.startswith("::")]
    assert line.split()[0] == check.MET


# --- X49 (ADR-0013 K-8, M12.4c1): `raqib service check` takes the copy in Program Files, refuses the job's own -----
def checked_line():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    return ("raqib service check: the code a service would run is the system's alone: %s"
            % wincode.checked_words({"folders": 41, "files": 1180, "above": 2},
                                    [("C:", "\\Device\\HarddiskVolume3")]))


REFUSED_LINE = ("raqib service check: NOT the system's alone: D:\\, as a folder above it (K-3): owned by NS, not the"
                " system (SY), the administrators (BA) or the system's installer")


def checkfile(**kw):
    keys = {"system-exit": "0", "system-words": checked_line(), "open-exit": "1", "open-words": REFUSED_LINE}
    keys.update(kw)
    return "".join("%s: %s\n" % (k, v) for k, v in keys.items() if v is not None)


def x49(text):
    ((ident, state, words),) = check.read_service_check(text)
    assert ident.startswith("X49 ") and ident == check.SERVICE_CHECK_NAME
    return state, words


def test_x49_met_where_program_files_was_taken_by_count_and_the_jobs_copy_refused_with_a_path_and_a_role():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    assert check.CHECK_ROLES == (wincode.ROLE_CODE, wincode.ROLE_ABOVE)   # the words are the check's own
    state, words = x49(checkfile())
    assert state == check.MET, words
    assert "(exit 0; 1223 names checked: 41 folders, 1180 files, 2 folders above)" in words and REFUSED_LINE in words
    assert x49(checkfile().replace("\n", "\r\n"))[0] == check.MET
    assert x49("\ufeff" + checkfile())[0] == check.MET
    code_role = REFUSED_LINE.replace("as a folder above it (K-3)", "as the code itself (K-2)")
    assert x49(checkfile(**{"open-words": code_role}))[0] == check.MET


@pytest.mark.parametrize("kw, said", [
    ({"system-exit": "1"}, "the copy in Program Files: exit 1, not 0"),
    ({"system-exit": "two"}, "the copy in Program Files: exit two, not 0"),
    ({"system-words": "raqib service check: the code a service would run is the system's alone"},
     "its words hold no counts' sentence"),
    ({"open-exit": "0"}, "the copy in the job's folder: exit 0, not 1"),
    ({"open-exit": "2"}, "the copy in the job's folder: exit 2, not 1"),
    ({"open-words": "raqib service check: NOT the system's alone: somewhere, as a folder above it (K-3): no"},
     "its words name no path of a drive"),
    ({"open-words": "raqib service check: NOT the system's alone: D:\\, owned by NS"}, "its words name no role"),
    ({"system-exit": None}, "no system-exit"), ({"system-words": None}, "no system-words"),
    ({"open-exit": None}, "no open-exit"), ({"open-words": None}, "no open-words"),
])
def test_x49_missed_for_each_thing_not_found(kw, said):
    state, words = x49(checkfile(**kw))
    assert state == check.MISSED and said in words, words


def test_x49_missed_where_the_counts_do_not_add_up_or_the_file_is_empty():
    state, words = x49(checkfile(**{"system-words": checked_line().replace("checked 1223 names", "checked 9 names")}))
    assert state == check.MISSED and "its counts do not add up (9 names, 41 + 1180 + 2)" in words
    for text in ("", "\ufeff\n", "  \n"):
        assert x49(text) == (check.MISSED, "missing: the check's file is empty or was not written (silence is a"
                                           " finding)")


def test_x49_n_a_where_none_was_given():
    assert x49(None) == (check.SKIP, "no service check was given (--service-check)")


def test_x49_main_reads_the_file_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "check.txt").write_text(checkfile(), encoding="utf-16")   # a redirect of Windows PowerShell 5
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X49 " in x and not x.startswith("::")]
        return line.split()[0]
    assert row(["--service-check", str(tmp_path / "check.txt")]) == check.MET
    assert row(["--service-check", str(tmp_path / "none.txt")]) == check.MISSED
    assert row([]) == check.SKIP


# --- X50 (ADR-0013 M-6, M12.4c1b): `raqib service check` takes a Python copied under Program Files, refuses the job's
def plain_line():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    return ("raqib service check: the code a service would run is the system's alone: %s"
            % wincode.plain_words({"folders": 120, "files": 2400, "above": 2, "entries": 5, "missing": 1, "pth": 0,
                                   "pth_lines": 0, "alone": 2, "beneath": 0, "own": 3, "own_there": 0, "base": 0,
                                   "exec": 0}, [("C:", "\\Device\\HarddiskVolume3"),
                                                ("D:", "\\Device\\HarddiskVolume1")]))


PLAIN_REFUSED = ("raqib service check: NOT the system's alone: C:\\hostedtoolcache\\windows\\Python, as a folder"
                 " above it (K-3): the entry (A;ID;0x1301bf;;;AU) gives AU, a name outside the system's, 0x10, 0x100,"
                 " 0x10000: not allowed")


def test_x50_the_refusal_held_is_the_checks_own_words_for_that_entry():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    words = wincode.as_above(0x10, "O:BAD:(A;ID;0x1301bf;;;AU)")   # the bits the check says for that entry above
    assert words.startswith(PLAIN_REFUSED.split("Python, ", 1)[1]) and "0x10, 0x100, 0x10000:" in words


def plainfile(**kw):
    keys = {"system-exit": "0", "system-words": plain_line(), "open-exit": "1", "open-words": PLAIN_REFUSED}
    keys.update(kw)
    return "".join("%s: %s\n" % (k, v) for k, v in keys.items() if v is not None)


def x50(text):
    ((ident, state, words),) = check.read_service_check_plain(text)
    assert ident.startswith("X50 ") and ident == check.SERVICE_CHECK_PLAIN_NAME
    return state, words


def test_x50_met_where_the_copy_was_taken_by_count_and_the_jobs_python_refused_with_a_path_and_a_role():
    state, words = x50(plainfile())
    assert state == check.MET, words
    assert "(exit 0; 2522 names checked: 120 folders, 2400 files, 2 folders above)" in words
    assert "the job's own Python was refused (exit 1): " + PLAIN_REFUSED in words
    assert x50(plainfile().replace("\n", "\r\n"))[0] == check.MET and x50("\ufeff" + plainfile())[0] == check.MET
    code_role = PLAIN_REFUSED.replace("as a folder above it (K-3)", "as the code itself (K-2)")
    assert x50(plainfile(**{"open-words": code_role}))[0] == check.MET


def test_x50_and_x49_are_one_reading_each_its_own_sentence():
    assert x50(checkfile())[0] == check.MISSED and "its words hold no counts' sentence" in x50(checkfile())[1]
    assert x49(plainfile())[0] == check.MISSED and "its words hold no counts' sentence" in x49(plainfile())[1]
    assert check.read_service_check.__code__.co_names.count("read_check") == 1
    assert check.read_service_check_plain.__code__.co_names.count("read_check") == 1


@pytest.mark.parametrize("kw, said", [
    ({"system-exit": "1"}, "the copy in Program Files: exit 1, not 0"),
    ({"system-exit": "two"}, "the copy in Program Files: exit two, not 0"),
    ({"system-words": "raqib service check: the code a service would run is the system's alone"},
     "its words hold no counts' sentence"),
    ({"open-exit": "0"}, "the job's own Python: exit 0, not 1"),
    ({"open-exit": "2"}, "the job's own Python: exit 2, not 1"),
    ({"open-words": "raqib service check: NOT the system's alone: somewhere, as a folder above it (K-3): no"},
     "its words name no path of a drive"),
    ({"open-words": "raqib service check: NOT the system's alone: D:\\, owned by NS"}, "its words name no role"),
    ({"system-exit": None}, "no system-exit"), ({"system-words": None}, "no system-words"),
    ({"open-exit": None}, "no open-exit"), ({"open-words": None}, "no open-words"),
])
def test_x50_missed_for_each_thing_not_found(kw, said):
    state, words = x50(plainfile(**kw))
    assert state == check.MISSED and said in words, words


def test_x50_missed_where_the_counts_do_not_add_up_or_the_file_is_empty():
    state, words = x50(plainfile(**{"system-words": plain_line().replace("checked 2522 names", "checked 9 names")}))
    assert state == check.MISSED and "its counts do not add up (9 names, 120 + 2400 + 2)" in words
    for text in ("", "\ufeff\n", "  \n"):
        assert x50(text) == (check.MISSED, "missing: the check's file is empty or was not written (silence is a"
                                           " finding)")


def test_x50_n_a_where_none_was_given():
    assert x50(None) == (check.SKIP, "no service check was given (--service-check-plain)")


def test_x50_main_reads_the_file_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "plain.txt").write_text(plainfile(), encoding="utf-16")   # a redirect of Windows PowerShell 5
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X50 " in x and not x.startswith("::")]
        return line.split()[0]
    assert row(["--service-check-plain", str(tmp_path / "plain.txt")]) == check.MET
    assert row(["--service-check-plain", str(tmp_path / "none.txt")]) == check.MISSED
    assert row([]) == check.SKIP


# --- X51 (ADR-0013 P-3, M12.4c2a): the check asked through a letter given to the packed copy's folder refuses it ----
def letter_line():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    root, words = wincode.drive_refused("R:", (3, "\\??\\C:\\Program Files\\RaqibRig"))   # a stand-in letter
    return "raqib service check: NOT the system's alone: %s, %s" % (root, words)     # and folder: the check's words


def refused_line(letter, got):
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    root, words = wincode.drive_refused(letter, got)
    return "raqib service check: NOT the system's alone: %s, %s" % (root, words)


def letterfile(**kw):
    keys = {"letter-exit": "1", "letter-words": letter_line()}
    keys.update(kw)
    return "".join("%s: %s\n" % (k, v) for k, v in keys.items() if v is not None)


def x51(text):
    ((ident, state, words),) = check.read_service_check_drive(text)
    assert ident.startswith("X51 ") and ident == check.SERVICE_CHECK_DRIVE_NAME
    return state, words


def test_x51_met_where_the_letter_was_refused_naming_a_kind_and_a_device_not_a_disks():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode
    assert (check.DISK_DEVICE.pattern, check.DISK_DEVICE.flags) == (wincode.DISK_DEVICE.pattern,
                                                                    wincode.DISK_DEVICE.flags)   # Q-1's one form
    state, words = x51(letterfile())
    assert state == check.MET, words
    assert words.startswith('the check through the letter was refused (exit 1), naming kind 3 (fixed) and the device'
                            ' \\??\\C:\\Program Files\\RaqibRig: raqib service check: NOT the system\'s alone: R:\\')
    assert x51(letterfile().replace("\n", "\r\n"))[0] == check.MET and x51("\ufeff" + letterfile())[0] == check.MET
    assert "first met by" not in words and "share" not in words   # Q-2
    other = refused_line("S:", (2, "\\??\\C:\\x"))   # invented: another kind, not a disk's
    state, words = x51(letterfile(**{"letter-words": other}))
    assert state == check.MET and "naming kind 2 (removable)" in words
    for name in ("\\Device\\HarddiskVolume3\\Users\\someone\\Rig", "\\Device\\HarddiskVolume3\\",
                 "\\Device\\HarddiskVolume", "\\device\\harddiskvolume3"):   # invented: names not of Q-1's form
        state, words = x51(letterfile(**{"letter-words": refused_line("S:", (3, name))}))
        assert state == check.MET and "naming kind 3 (fixed) and the device %s:" % name in words, words


@pytest.mark.parametrize("got", [(1, "\\Device\\HarddiskVolume3"), (2, "\\Device\\HarddiskVolume12")])
def test_x51_missed_where_the_name_said_is_a_disks_volume(got):   # invented: a disk's name, refused by its kind
    state, words = x51(letterfile(**{"letter-words": refused_line("S:", got)}))
    assert state == check.MISSED and "the device's name it names, %s, is of a disk's volume's form" % got[1] in words


@pytest.mark.parametrize("kw, said", [
    ({"letter-exit": "0"}, "the check through the letter: exit 0, not 1"),
    ({"letter-exit": "2"}, "the check through the letter: exit 2, not 1"),
    ({"letter-exit": "one"}, "the check through the letter: exit one, not 1"),
    ({"letter-words": "raqib service check: NOT the system's alone: R:\\, the drive R:: names its device"
                      " \"\\??\\C:\\x\","}, "its words name no kind of the drive"),
    ({"letter-words": "raqib service check: NOT the system's alone: R:\\, the system says kind 3 (fixed)"},
     "its words name no device's name"),
    ({"letter-words": "raqib service check: NOT the system's alone: R:\\, the system says kind 1 (no root) and names"
                      " its device \"\\Device\\HarddiskVolume3\": not the fixed kind"},
     "the device's name it names, \\Device\\HarddiskVolume3, is of a disk's volume's form, \\Device\\HarddiskVolumeN"
     " (the letter was a disk's)"),
    ({"letter-words": "raqib service check: NOT the system's alone: C:\\Program Files, as a folder above it (K-3)"},
     "its words name no kind of the drive"),
    ({"letter-exit": None}, "no letter-exit"), ({"letter-words": None}, "no letter-words"),
])
def test_x51_missed_for_each_thing_not_found(kw, said):
    state, words = x51(letterfile(**kw))
    assert state == check.MISSED and said in words, words


def test_x51_missed_where_the_file_is_empty_and_n_a_where_none_was_given():
    for text in ("", "\ufeff\n", "  \n"):
        assert x51(text) == (check.MISSED, "missing: the check's file is empty or was not written (silence is a"
                                           " finding)")
    assert x51(None) == (check.SKIP, "no service check through a letter was given (--service-check-drive)")


def test_x51_main_reads_the_file_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "letter.txt").write_text(letterfile(), encoding="utf-16")   # a redirect of Windows PowerShell 5
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X51 " in x and not x.startswith("::")]
        return line.split()[0]
    assert row(["--service-check-drive", str(tmp_path / "letter.txt")]) == check.MET
    assert row(["--service-check-drive", str(tmp_path / "none.txt")]) == check.MISSED
    assert row([]) == check.SKIP


def test_x49_and_x50_still_read_the_pass_with_its_drives():
    assert "C: \"\\Device\\HarddiskVolume3\"" in checked_line() and check.CHECK_COUNTS.search(checked_line())
    assert "D: \"\\Device\\HarddiskVolume1\"" in plain_line() and check.CHECK_PLAIN_COUNTS.search(plain_line())


# --- X52 (ADR-0013 T-1, T-3, M12.4c2b1): the service asks the check of its own code at every start -----------------
def service_lines():
    """The runner's two lines of the check, as raqib/winservice.py writes them: a refusal of a folder a user may
    write (the placeholder `user`) and the plain road's pass."""
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import wincode, winservice
    head = "raqib service run: its own code, checked at this start by this process (ADR-0013 T-1), in 0.31 s: "
    bad = ("C:\\Users\\user\\rig\\python", wincode.as_code(0x10, "O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)"))
    told = "; no watch is begun; the system is told %s" % winservice.told(winservice.EXIT_NOT_ALONE)
    return head + winservice.REFUSED_SAID % bad + told, head + winservice.PASS_SAID % plain_line().split(": ", 2)[2]


def refusedfile(**kw):
    refused, taken = service_lines()
    keys = {"refused-exit": "1066", "refused-own": "536870927", "refused-text": refused, "taken-state": "Running",
            "taken-text": taken}
    keys.update(kw)
    return "".join("%s: %s\n" % (k, v) for k, v in keys.items() if v is not None)


def x52(text):
    ((ident, state, words),) = check.read_service_refused(text)
    assert ident.startswith("X52 ") and ident == check.SERVICE_REFUSED_NAME
    return state, words


def test_x52_met_where_the_users_tree_did_not_run_with_15_and_the_copy_under_program_files_ran():
    import sys
    sys.path.insert(0, str(ROOT))
    from raqib import winservice
    assert check.REFUSED_OWN == winservice.EXIT_NOT_ALONE == 0x2000000F and check.REFUSED_WIN32 == 1066
    assert winservice.SERVICE_SPECIFIC == check.REFUSED_WIN32 and check.REFUSED_SAID in winservice.REFUSED_SAID
    assert check.TAKEN_SAID in winservice.PASS_SAID
    assert check.RUNNER_SAID == "raqib service run: " + winservice.CHECK_HEAD.split(" by this process")[0]
    state, words = x52(refusedfile())
    assert state == check.MET, words
    assert words.startswith("the service from the job's own Python did not run (exit 1066, its own number"
                            " 0x2000000F): raqib service run: its own code, checked at this start")
    for own in ("0x2000000F", "0x2000000f", "536870927", "536870927 (0x2000000f)"):
        assert x52(refusedfile(**{"refused-own": own}))[0] == check.MET, own
    assert x52(refusedfile().replace("\n", "\r\n"))[0] == check.MET and x52("\ufeff" + refusedfile())[0] == check.MET


@pytest.mark.parametrize("kw, said", [
    ({"refused-exit": "0"}, "the service from the job's own Python: exit 0, not 1066"),
    ({"refused-exit": "1077"}, "exit 1077, not 1066"),
    ({"refused-own": "0"}, "its own number 0, not 15 (0x2000000F or 536870927)"),
    ({"refused-own": "15"}, "its own number 15, not 15"),
    ({"refused-own": "0x2000000E"}, "its own number 0x2000000E, not 15"),
    ({"refused-own": "fifteen"}, "its own number fifteen, not 15"),
    ({"refused-text": "raqib service run: the watch returned with 0"}, "does not say NOT the system's alone"),
    ({"refused-text": "raqib service check: NOT the system's alone: no path here"}, "names no path of a drive"),
    ({"taken-state": "Stopped"}, "its state is Stopped, not Running"),
    ({"taken-state": ""}, "its state is not said, not Running"),
    ({"taken-text": "raqib service check: the code a service would run is the system's alone"},
     "holds no pass's sentence with its counts"),
    ({"taken-text": "raqib service check: NOT the system's alone: C:\\x, y"}, "holds no pass's sentence"),
    # the command's own output, which says the same sentences, is not the service's text file (U-3)
    ({"refused-text": "raqib service check: NOT the system's alone: C:\\Users\\user\\rig, owned by a user"},
     "the service from the job's own Python: its text file's line is not the runner's own"),
    ({"taken-text": plain_line()},
     "the service from the copy under Program Files: its text file's line is not the runner's own"),
    ({"refused-exit": None}, "no refused-exit"), ({"refused-own": None}, "no refused-own"),
    ({"refused-text": None}, "no refused-text"), ({"taken-state": None}, "no taken-state"),
    ({"taken-text": None}, "no taken-text"),
])
def test_x52_missed_for_each_thing_not_found(kw, said):
    state, words = x52(refusedfile(**kw))
    assert state == check.MISSED and said in words, words


def test_x52_missed_where_the_file_is_empty_and_n_a_where_none_was_given():
    for text in ("", "\ufeff\n", "  \n"):
        assert x52(text) == (check.MISSED, "missing: the services' file is empty or was not written (silence is a"
                                           " finding)")
    assert x52(None) == (check.SKIP, "no services made from two trees were given (--service-refused)")
    assert x52(object())[0] == check.MISSED   # never raises


def test_x52_main_reads_the_file_and_a_given_file_that_is_missing_is_missed(tmp_path, capsys):
    (tmp_path / "w.out").write_text(REPORT, encoding="utf-8")
    (tmp_path / "l.out").write_text(WORKLOAD, encoding="utf-8")
    (tmp_path / "refused.txt").write_text(refusedfile(), encoding="utf-16")   # a redirect of Windows PowerShell 5
    (tmp_path / "bom.txt").write_text("\ufeff" + refusedfile(), encoding="utf-8")
    base = ["--report", str(tmp_path / "w.out"), "--workload", str(tmp_path / "l.out"), "--platform", "win32"]

    def row(argv):
        check.main(base + argv)
        (line,) = [x for x in capsys.readouterr().out.splitlines() if "X52 " in x and not x.startswith("::")]
        return line.split()[0]
    assert row(["--service-refused", str(tmp_path / "refused.txt")]) == check.MET
    assert row(["--service-refused", str(tmp_path / "bom.txt")]) == check.MET
    assert row(["--service-refused", str(tmp_path / "none.txt")]) == check.MISSED
    assert row([]) == check.SKIP
