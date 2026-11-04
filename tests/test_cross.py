"""M5.3 E3, E4 (ADR-0003 Amendment C, rulings C-1 to C-5, C-8, C-9): the
CROSS-SOURCE code rule (raqib/rules/cross.py), its four fixtures, the
SILENCE-GAP/ORDER exemption for os sessions, the SECRET-OUTPUT and NET-TOOL
guards, and the rule in report, cli, README and THREAT_MODEL."""
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, report  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402
from raqib.rules import cross, engine, silence, trace  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
CROSS_DIR = FIXTURES / "cross"
CATALOG = ROOT / "raqib" / "rules" / "catalog"
README = (ROOT / "README.md").read_text(encoding="utf-8")
THREAT = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
EXPECTED = {"asked-not-done": [("s-hook", [2])], "done-not-asked": [("os-4100", [7])],
            "matched": [], "rg-helper": []}


def read(name):
    recs, problems = trace.read(CROSS_DIR / ("%s.log" % name))
    assert problems == []
    return recs


def ts(sec):
    import datetime
    at = datetime.datetime(2026, 11, 3, 9, 0, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=sec)
    return at.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hook(seq, phase, at, tool="Bash", programs=None, head=None, source="hook", session="s-hook", unread=False):
    rec = {"ts": ts(at), "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "C:\\w"}
    if phase in ("pre", "post"):
        meta = {}
        if programs is not None:
            meta["command_programs"] = programs
        if head is not None:
            meta["command_head"] = head
        if unread:
            meta["command_unread"] = True
        rec.update(input_sha256="0" * 64, input_meta=meta)
    if phase == "post":
        rec.update(ok=True, output_meta={"scan": "full", "secret_kinds": []})
    if source is not None:
        rec["source"] = source
    return rec


def osl(seq, at, program=None, depth=2, tool="process", phase="pre", meta=None, parent=None, session="os-4100"):
    rec = {"ts": ts(at), "seq": seq, "session_id": session, "phase": phase, "tool": tool, "cwd": "C:\\w",
           "source": "os"}
    if phase in ("pre", "post"):
        if meta is None:
            meta = {"command_head": program, "command_programs": [program]} if program else {"command_unread": True}
            if depth is not None:
                meta["depth"] = depth
            if parent is not None:
                meta["parent_seq"] = parent
        rec.update(input_sha256="0" * 64, input_meta=meta)
    return rec


def span(first, last):
    """An os session from first to last (seconds) and an agent session as wide."""
    return [osl(1, first, phase="session_start", tool="-"), osl(99, last, phase="session_end", tool="-"),
            hook(1, "session_start", first, tool="-"), hook(99, "session_end", last, tool="-")]


def cited(found):
    return [(f["session_id"], f["cited_seq"]) for f in found]


# --- C-8: the four fixtures --------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_c8_each_fixture_gives_its_verdict_and_is_fully_judged(name):
    found, notes = cross.findings(read(name))
    assert cited(found) == EXPECTED[name] and notes == []
    for f in found:
        engine.check_finding(f)
        assert (f["class"], f["kind"], f["severity"], f["rule_id"]) == ("CROSS", "anchor", "high", "CROSS-SOURCE")


def test_c8_fixtures_are_declared_and_the_negatives_measure_within_budget():
    assert cross.FIXTURES == {"positive": ["tests/fixtures/cross/asked-not-done.log",
                                           "tests/fixtures/cross/done-not-asked.log"],
                              "negative": ["tests/fixtures/cross/matched.log", "tests/fixtures/cross/rg-helper.log"]}
    fired = []
    for rel in cross.FIXTURES["negative"]:
        found, notes = cross.findings(trace.read(ROOT / rel)[0])
        assert notes == [], rel   # measured: every line judged
        fired.append(bool(found))
    assert sum(fired) / len(fired) <= cross.FP_BUDGET == 0.1
    assert all(cross.findings(trace.read(ROOT / rel)[0])[0] for rel in cross.FIXTURES["positive"])


def test_c8_the_os_halves_are_os_sysmon_output_of_their_exports(tmp_path):
    for name in EXPECTED:
        lines = (CROSS_DIR / ("%s.log" % name)).read_text().splitlines()
        os_half = [x for x in lines if '"source":"os"' in x]
        log = tmp_path / ("%s.jsonl" % name)
        assert cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from",
                         str(CROSS_DIR / ("%s.sysmon.xml" % name)), "--cwd", "C:\\work\\proj"], out=io.StringIO()) == 0
        assert log.read_text().splitlines() == os_half, name
        assert lines == [x for x in lines if '"source":"hook"' in x] + os_half


def test_c4_the_rg_helper_fired_in_the_prototype_and_is_the_agents_own_here():
    recs = read("rg-helper")
    (rg,) = [r for r in recs if r.get("input_meta", {}).get("command_head") == "rg.exe" and r["phase"] == "pre"]
    assert rg["input_meta"]["depth"] == 1
    as_deep = [dict(r, input_meta=dict(r["input_meta"], depth=2)) if r is rg else r for r in recs]
    assert cited(cross.findings(as_deep)[0]) == [("os-4100", [rg["seq"]])]


# --- C-2: only with os lines -----------------------------------------------------------------

@pytest.mark.parametrize("path", sorted(str(p) for p in FIXTURES.glob("*.log")) + sorted(
    str(p) for p in (FIXTURES / "rules" / "benign").glob("*.json")))
def test_c2_a_trace_without_os_lines_gets_nothing_and_no_note(path):
    from raqib.rules import fixtures
    lines = fixtures.load_fixture(path)[0]
    assert cross.findings(lines) == ([], [])


def test_c2_a_clean_hook_trace_stays_clean():
    out = io.StringIO()
    assert cli.main(["report", str(FIXTURES / "quickstart-d7841d1-claude-code-2.1.301.log"), "--scope", "."],
                    out=out) == 0
    assert "RESULT: CLEAN (exit 0)" in out.getvalue() and "CROSS-SOURCE    CROSS     anchor" in out.getvalue()


# --- C-3: reading B, the two directions ----------------------------------------------------

def test_c3_asked_not_done_and_its_window():
    base = span(0, 60) + [hook(2, "pre", 5, programs=["ls"], head="ls")]
    assert cited(cross.findings(base)[0]) == [("s-hook", [2])]
    for at, fires in ((5, False), (15, False), (15.001, True), (4.999, True)):
        found, notes = cross.findings(base + [osl(2, at, "ls.exe")])
        assert (("s-hook", [2]) in cited(found)) is fires and notes == [], at
    # a shell image matches whatever the programs are; another program does not
    assert cross.findings(base + [osl(2, 6, "bash.exe", depth=1)])[0] == []
    assert cross.findings(base + [osl(2, 6, "powershell.exe", depth=1)])[0] == []
    # findings are ordered by the session's first line: the os session comes first here
    assert cited(cross.findings(base + [osl(2, 6, "curl.exe")])[0]) == [("os-4100", [2]), ("s-hook", [2])]


def test_c3_done_not_asked_and_its_window():
    base = span(0, 60) + [osl(2, 20, "curl.exe")]
    assert cited(cross.findings(base)[0]) == [("os-4100", [2])]
    for at, fires in ((20, False), (10, False), (9.999, True), (20.001, True)):
        found, _ = cross.findings(base + [hook(2, "pre", at, programs=["curl"], head="curl")])
        assert ("os-4100", [2]) in cited(found) if fires else ("os-4100", [2]) not in cited(found), at
    # the head counts as a program too (a line written before command_programs)
    assert ("os-4100", [2]) not in cited(cross.findings(base + [hook(2, "pre", 15, head="curl")])[0])


def test_d8_a_pre_outside_the_os_sessions_is_history_an_os_process_outside_the_agent_is_partial():
    recs = [osl(1, 10, phase="session_start", tool="-"), osl(2, 12, "ls.exe", depth=2),
            osl(9, 20, phase="session_end", tool="-"),
            hook(1, "session_start", 13, tool="-"), hook(2, "pre", 30, programs=["ls"], head="ls"),
            hook(9, "session_end", 40, tool="-")]
    found, notes = cross.findings(recs)
    assert found == []
    (note,) = notes
    assert note["rule_id"] == "CROSS-SOURCE" and note["status"] == "partial"
    assert "could not judge 1 line(s) (session:seq os-4100:2)" in note["detail"]   # s-hook:2 is history


def test_c3_an_os_only_trace_is_partial_on_every_process_below_the_agents_children():
    lines, _ = os_sysmon.build((FIXTURES / "os" / "sysmon-synthetic.xml").read_text(), 4100, cwd="C:\\w")
    found, notes = cross.findings([json.loads(x) for x in lines])
    assert found == [] and [n["status"] for n in notes] == ["partial"]
    assert "could not judge 3 line(s) (session:seq os-4100:6, os-4100:7, os-4100:11)" in notes[0]["detail"]


def test_c3_unknown_programs_or_depth():
    unread = span(0, 60) + [hook(2, "pre", 5, unread=True)]
    assert cited(cross.findings(unread)[0]) == [("s-hook", [2])]          # nothing at all started
    assert cross.findings(unread + [osl(2, 6, "bash.exe", depth=1)]) == ([], [])   # a shell started
    found, notes = cross.findings(unread + [osl(2, 6, "ls.exe", depth=1)])
    assert found == [] and notes[0]["status"] == "partial"                 # could be the asked one
    found, notes = cross.findings(span(0, 60) + [hook(2, "pre", 5, programs=["ls"], head="ls"), osl(2, 6)])
    assert found == [] and "s-hook:2" in notes[0]["detail"] and "os-4100:2" in notes[0]["detail"]
    found, notes = cross.findings(span(0, 60) + [osl(2, 6, "ls.exe", depth=None)])
    assert found == [] and "os-4100:2" in notes[0]["detail"]
    found, notes = cross.findings(span(0, 60) + [osl(2, 9, "ls.exe"), hook(2, "pre", 5, unread=True)])
    assert ("os-4100", [2]) not in cited(found) and "os-4100:2" in notes[0]["detail"]


# --- C-4: shell tools, folding, the agent's own children -------------------------------------

@pytest.mark.parametrize("tool, shell", [
    ("Bash", True), ("bash", True), ("shell", True), ("local_shell", True), ("RunShellCommand", True),
    ("execute_command", True), ("run_command", True), ("cmd", True), ("Cmd.Run", True),
    ("command", True), ("run_terminal_command", True), ("CommandPalette", True),   # D-10: "cmd" and "command"
    ("Read", False), ("Grep", False), ("WebFetch", False), ("Task", False), ("sha256:0123456789abcdef", False),
    (None, False),
])
def test_c4_shell_tool_names(tool, shell):
    assert cross.is_shell_tool(tool) is shell


@pytest.mark.parametrize("name, folded", [
    ("LS.EXE", "ls"), ("Script.CMD", "script"), ("run.bat", "run"), ("git", "git"), ("tool.com", "tool.com"),
    (".exe", ".exe"), ("", None), (None, None),
])
def test_c4_folding(name, folded):
    assert cross.fold(name) == folded


def test_c4_folding_matches_both_sides():
    recs = span(0, 60) + [hook(2, "pre", 5, tool="run_command", programs=["Python.exe"], head="Python.exe"),
                          osl(2, 6, "python.EXE")]
    assert cross.findings(recs) == ([], [])


@pytest.mark.parametrize("depth, verdict", [(0, "none"), (1, "none"), (2, "finding"), (5, "partial")])
def test_c4_the_root_and_its_direct_children_are_not_judged(depth, verdict):
    # depth 5 with no parent line: its ancestors below the shell cannot be judged (D-9)
    found, notes = cross.findings(span(0, 60) + [osl(2, 30, "curl.exe", depth=depth)])
    assert ("finding" if found else "partial" if notes else "none") == verdict


def test_c4_proxy_pres_ask_too_and_a_line_without_source_is_the_hook():
    for source in ("proxy", None):
        recs = span(0, 60) + [hook(2, "pre", 25, programs=["curl"], head="curl", source=source),
                              osl(2, 30, "curl.exe")]
        assert cross.findings(recs) == ([], []), source
    # a non-shell tool never asks, whatever its input_meta says
    recs = span(0, 60) + [hook(2, "pre", 25, tool="Read", programs=["curl"]), osl(2, 30, "curl.exe")]
    assert cited(cross.findings(recs)[0]) == [("os-4100", [2])]


# --- C-7: no event 3 is an INCOMPLETE note ------------------------------------------------

def test_c7_missing_events_is_a_source_incomplete_note_and_the_report_is_incomplete(tmp_path):
    recs = read("matched")
    recs[[i for i, r in enumerate(recs) if r["session_id"] == "os-4100"][0]]["missing_events"] = [3]
    found, notes = cross.findings(recs)
    assert found == [] and [(n["rule_id"], n["status"]) for n in notes] == [("*", "source-incomplete")]
    assert ("os session os-4100 (seq 1): the Sysmon export held no event 3, so the os source is incomplete;"
            " Sysmon logs network connections (event 3) only when installed with -n") == notes[0]["detail"]
    path = tmp_path / "t.log"
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    out = io.StringIO()
    assert cli.main(["report", str(path), "--scope", "."], out=out) == 3
    text = out.getvalue()
    assert "ALARMS (A3, A5): 0" in text and "* source-incomplete: os session os-4100" in text


# --- E3/E4 wiring: run_rules, report, rules ------------------------------------------------

def test_e3_report_on_the_positive_fixtures_is_an_alarm_with_the_cited_line_and_source():
    for name, (session, seqs) in (("asked-not-done", ("s-hook", [2])), ("done-not-asked", ("os-4100", [7]))):
        out = io.StringIO()
        assert cli.main(["report", str(CROSS_DIR / ("%s.log" % name)), "--scope", "."], out=out) == 1
        text = out.getvalue()
        assert "[high] CROSS-SOURCE (CROSS, anchor) session %s seq %d" % (session, seqs[0]) in text, text
        assert "FINDINGS: 1" in text and "RULES THAT DID NOT RUN: 0" in text
        assert ("source: hook" if session == "s-hook" else "source: os") in text
    for name in ("matched", "rg-helper"):
        out = io.StringIO()
        assert cli.main(["report", str(CROSS_DIR / ("%s.log" % name)), "--scope", "."], out=out) == 0, name
        assert "RESULT: CLEAN (exit 0)" in out.getvalue()


def test_e3_rules_writes_the_finding_and_report_reads_it_back(tmp_path):
    out = tmp_path / "f.jsonl"
    path = str(CROSS_DIR / "done-not-asked.log")
    assert cli.main(["rules", path, "--scope", ".", "-o", str(out)], out=io.StringIO()) == 1
    (finding,) = [json.loads(x) for x in out.read_text().splitlines()]
    assert finding["rule_id"] == "CROSS-SOURCE" and finding["class"] == "CROSS"
    text = io.StringIO()
    assert cli.main(["report", path, "--scope", ".", "--findings", str(out)], out=text) == 1
    assert "rejected-finding" not in text.getvalue() and "CROSS-SOURCE (CROSS, anchor)" in text.getvalue()


def test_c1_report_lists_the_rule_beside_the_silence_rules():
    assert report.CROSS_RULES == ((cross.RULE_ID, cross.TITLE),)
    table = report.rule_table(engine.load_catalog(CATALOG))
    ids = [r["id"] for r in table]
    assert ids[:6] == [rid for rid, _ in report.SILENCE_RULES] + ["CROSS-SOURCE"]
    row = table[5]
    assert row == {"id": "CROSS-SOURCE", "class": "CROSS", "kind": "anchor", "severity": "high", "fp_budget": 0.1,
                   "status": "active", "title": cross.TITLE}
    assert "CROSS" in engine.CLASSES and cross.RULE_KINDS == {"CROSS-SOURCE": "anchor"}
    assert (cross.WINDOW_SECONDS, cross.SEVERITY, cross.CLASS) == (10, "high", "CROSS")


# --- C-5: GAP and ORDER skip os-only sessions; the two guards ---------------------------

def test_c5_silence_gap_and_order_skip_a_session_of_os_lines_only():
    recs = [osl(1, 0, phase="session_start", tool="-"), osl(2, 30, "ls.exe"), osl(2, 30, "ls.exe", phase="post"),
            osl(3, 5, "ls.exe"), osl(3, 5, "ls.exe", phase="post")]
    recs[1]["ts"] = recs[2]["ts"] = "2026-11-03T09:05:00.000Z"   # 5 minutes on: a gap
    found = silence.findings(recs, 60)
    assert [f["rule_id"] for f in found] == ["SILENCE-OPEN"]     # OPEN still judges an os session
    mixed = recs + [dict(recs[-1], source="hook", phase="session_end", tool="-", seq=4)]
    del mixed[-1]["input_meta"], mixed[-1]["input_sha256"]
    assert {f["rule_id"] for f in silence.findings(mixed, 60)} >= {"SILENCE-GAP", "SILENCE-ORDER"}
    half = [osl(1, 0, phase="session_start", tool="-"), osl(2, 1, "ls.exe"), osl(3, 2, phase="session_end", tool="-")]
    assert [f["rule_id"] for f in silence.findings(half, 60)] == ["SILENCE-HALF"]
    assert "SILENCE-GAP or SILENCE-ORDER" in silence.__doc__ and "an\nidle os source is not judged" in silence.__doc__


def guarded(rule_id, rec):
    rule = [r for r in engine.load_catalog(CATALOG) if r.id == rule_id][0]
    return engine.judge(rule, [rec])


def test_c5_secret_output_does_not_judge_os_lines():
    post = osl(2, 1, "ls.exe", phase="post")
    post.update(ok=True, output_meta={})
    assert guarded("SECRET-OUTPUT", post) == ([], [])                      # judged, not partial
    forged = dict(post, output_meta={"secret_kinds": ["aws_access_key_id"]})
    assert guarded("SECRET-OUTPUT", forged) == ([], [])
    for source in ("hook", None):
        line = hook(2, "post", 1, source=source)
        line["output_meta"] = {"scan": "full", "secret_kinds": ["aws_access_key_id"]}
        assert len(guarded("SECRET-OUTPUT", line)[0]) == 1, source       # a line before M5.2 still fires
    rule = [r for r in engine.load_catalog(CATALOG) if r.id == "SECRET-OUTPUT"][0]
    assert "Note (2026-11-03, M5.3, ADR-0003 Amendment C, C-5)" in rule.doc["description"]


def test_c5_net_tool_does_not_judge_os_lines():
    net = osl(2, 1, tool="net", meta={"dest_port": 443, "dest_private": False, "url_host": "api.example.com"})
    assert guarded("NET-TOOL", net) == ([], [])
    curl = osl(2, 1, "curl")
    curl["tool"] = "Bash"
    assert guarded("NET-TOOL", curl) == ([], [])
    for source in ("hook", "proxy", None):
        line = hook(2, "pre", 1, programs=["curl"], head="curl", source=source)
        assert len(guarded("NET-TOOL", line)[0]) == 1, source
    rule = [r for r in engine.load_catalog(CATALOG) if r.id == "NET-TOOL"][0]
    assert "Note (2026-11-03, M5.3, ADR-0003 Amendment C, C-5)" in rule.doc["description"]
    assert "for a later rule" in rule.doc["description"]


def test_c5_an_os_trace_reports_no_partial_from_the_guarded_signatures():
    lines, _ = os_sysmon.build((FIXTURES / "os" / "sysmon-synthetic.xml").read_text(), 4100, cwd="C:\\w")
    recs = [json.loads(x) for x in lines]
    found, notes = cli.run_rules(recs, engine.load_catalog(CATALOG), {"scope": ["."], "root": "C:\\w"}, 60)
    assert found == []
    assert [(n["rule_id"], n["status"]) for n in notes] == [("CROSS-SOURCE", "partial")]


# --- C-9 and E4: docs ------------------------------------------------------------------------

def test_c9_readme_names_the_rule_the_shell_tools_the_window_and_sysmon_n():
    flat = " ".join(README.split())
    for phrase in ("Twenty-one rules turn the trace into findings",   # M4.2b: was Thirteen; M4.3: Seventeen; M7.2: Nineteen; REDO: Twenty; M7.2b: Twenty-one
                   "| CROSS-SOURCE | only in a trace with `os` lines:",
                   "`raqib os-sysmon --root PID[:GUID] --log TRACE [--from FILE.xml] [--cwd DIR]`",
                   "a `pre` of `Bash` or of any tool whose name, in lower case, holds `bash`, `shell`,"
                   " `execute_command`, `run_command`, `cmd` or `command`",
                   "in lower case without `.exe`, `.cmd` or `.bat`",
                   "(bash, sh, zsh, dash, ksh, fish, cmd, powershell, pwsh)",
                   "in the 10 s after it", "named its program in the 10 s before it",
                   "Sysmon logs network connections only when installed with `-n`",
                   "an export with no event 3 makes the report INCOMPLETE (exit 3), not an alarm",
                   "A trace with no os line is not judged and gets no note",
                   "an agent that runs its acts that way is a known hole",
                   "reruns are not deduplicated", "`C:\\Windows\\System32\\wevtutil.exe`"):
        assert phrase in flat, phrase
    assert ", ".join(cross.SHELL_IMAGES) in flat and "`, `".join(cross.SHELL_TOOL_WORDS[:4]) in flat


def test_c9_threat_model_says_what_os_records_still_miss():
    section = THREAT.split("\n### The os source (Sysmon; ADR-0003 Amendment C)\n", 1)[1].split("\n## ", 1)[0]
    flat = " ".join(section.split())
    for phrase in ("The only record the agent does not write.", "in-process actions:", "memory-only tools:",
                   "Sysmon configuration gaps:", "without `-n` there is no event 3",
                   "an export given with `--from` is trusted as Sysmon's",
                   "An agent that runs its acts as direct children rather than through a shell is a known hole",
                   "an idle os source is not judged", "False-positive sources of CROSS-SOURCE:"):
        assert phrase in flat, phrase
    assert THREAT.index("## 5. What Raqib cannot see") < THREAT.index("### The os source") < THREAT.index(
        "## 6. Attacks on the watcher itself")


# --- REDO-2 (ADR-0003 Amendment D, rulings D-7 to D-11, D-13) ----------------------------

def synthetic():
    import importlib.util
    spec = importlib.util.spec_from_file_location("os_synthetic", FIXTURES / "os" / "synthetic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_d7_an_os_only_trace_of_the_agents_own_processes_has_nothing_to_judge(tmp_path):
    x = synthetic()
    export = x.Export()
    x.agent_start(export)
    export.proc("09.000", 4300, x.RG, "rg --files", 4100, x.AGENT, x.AGENT)
    export.net("10.000", 4100, x.AGENT, "203.0.113.7", 443)
    export.file("11.000", 4100, x.AGENT, "C:\\work\\proj\\a.txt")
    lines, _ = os_sysmon.build(export.text(), 4100, cwd="C:\\w")
    recs = [json.loads(line) for line in lines]
    found, notes = cross.findings(recs)
    assert found == [] and notes == [{"rule_id": "CROSS-SOURCE", "status": "nothing-to-judge",
                                      "detail": "nothing to judge (every os process is the agent's own): the trace"
                                                " holds no hook or proxy line and no os process below the agent's"
                                                " direct children"}]
    path = tmp_path / "t.log"
    path.write_text("".join(line + "\n" for line in lines))
    out = io.StringIO()
    assert cli.main(["report", str(path), "--scope", "."], out=out) == 3
    assert "CROSS-SOURCE nothing-to-judge: nothing to judge (every os process is the agent's own)" in out.getvalue()
    # with a hook session beside it there is no such note
    assert cross.findings(recs + [hook(1, "session_start", 1, tool="-"), hook(2, "session_end", 2, tool="-")]) == ([], [])


def test_d7_both_directions_of_c2_are_in_readme_and_threat_model():
    flat = " ".join(README.split())
    assert "A trace with no os line is not judged and gets no note; a trace with os lines and no hook or proxy line" \
           " is INCOMPLETE, by a partial note or, when every os process is the agent's own, \"nothing to judge\"" in flat
    threat = " ".join(THREAT.split())
    assert "C-2, both directions: a trace with no os line (Linux, macOS, or os-sysmon not run) gets no finding and" \
           " no note" in threat
    assert "a trace with os lines and no hook or proxy line is INCOMPLETE, by a partial note or, when every os" \
           " process is the agent's own, \"nothing to judge\"" in threat


def test_d8_the_os_span_is_per_session_and_history_outside_gets_no_note():
    recs = [osl(1, 0, phase="session_start", tool="-"), osl(9, 20, phase="session_end", tool="-"),
            osl(1, 100, phase="session_start", tool="-", session="os-4200"),
            osl(9, 120, phase="session_end", tool="-", session="os-4200"),
            hook(1, "session_start", 0, tool="-"), hook(9, "session_end", 130, tool="-"),
            hook(2, "pre", 50, programs=["ls"], head="ls"),     # between the two os sessions: history
            hook(3, "pre", 125, programs=["ls"], head="ls"),    # after both: history
            hook(4, "pre", 105, programs=["ls"], head="ls")]    # inside os-4200, nothing done: a finding
    found, notes = cross.findings(recs)
    assert cited(found) == [("s-hook", [4])] and notes == []


def test_d8_an_os_process_inside_the_union_of_agent_sessions_is_judged():
    recs = [osl(1, 0, phase="session_start", tool="-"), osl(9, 100, phase="session_end", tool="-"),
            hook(1, "session_start", 0, tool="-", session="s-a"), hook(2, "session_end", 30, tool="-", session="s-a"),
            hook(1, "session_start", 60, tool="-", session="s-b"), hook(2, "session_end", 90, tool="-", session="s-b"),
            osl(2, 20, "curl.exe"), osl(3, 45, "curl.exe"), osl(4, 70, "curl.exe")]
    found, notes = cross.findings(recs)
    assert cited(found) == [("os-4100", [2]), ("os-4100", [4])]
    assert notes[0]["status"] == "partial" and "could not judge 1 line(s) (session:seq os-4100:3)" in notes[0]["detail"]


def test_d8_a_long_lived_project_trace_stays_clean_after_one_os_sysmon_run(tmp_path):
    """Hook sessions over three hours; one os-sysmon export in the middle,
    matched by its shell call: CLEAN, not INCOMPLETE."""
    rows = []
    for name, base in (("s-morning", 0), ("s-noon", 3600), ("s-evening", 3 * 3600)):
        rows += [hook(1, "session_start", base, tool="-", session=name),
                 hook(2, "pre", base + 5, programs=["ls"], head="ls", session=name),
                 hook(2, "post", base + 5.5, programs=["ls"], head="ls", session=name),
                 hook(3, "stop", base + 6, tool="-", session=name), hook(4, "session_end", base + 30, tool="-",
                                                                         session=name)]
    rows += [osl(1, 3600, phase="session_start", tool="-"),
             osl(2, 3605.2, "bash.exe", depth=1), osl(2, 3605.2, "bash.exe", depth=1, phase="post"),
             osl(3, 3605.3, "ls.exe", depth=2, parent=2), osl(3, 3605.3, "ls.exe", depth=2, parent=2, phase="post"),
             osl(4, 3610, phase="session_end", tool="-")]
    for r in rows:
        if r["phase"] == "post" and r.get("source") == "os":
            r.update(ok=True, output_meta={})
    assert cross.findings(rows) == ([], [])
    path = tmp_path / "long.log"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    out = io.StringIO()
    assert cli.main(["report", str(path), "--scope", "."], out=out) == 0, out.getvalue()
    assert "RESULT: CLEAN (exit 0)" in out.getvalue() and "sources: hook 15, os 6" in out.getvalue()


def chain(*procs):
    """os process lines (seq, at, program, depth, parent seq) under a shell at seq 2."""
    return [osl(seq, at, program, depth=depth, parent=parent) for seq, at, program, depth, parent in procs]


def test_d9_the_descendants_of_an_asked_process_are_asked():
    base = span(0, 100) + [hook(2, "pre", 5, programs=["npm"], head="npm"),
                           hook(3, "pre", 50, programs=["git"], head="git")]
    recs = base + chain((2, 5.2, "bash.exe", 1, None), (3, 5.3, "npm.cmd", 2, 2), (4, 35, "node.exe", 3, 3),
                        (5, 36, "esbuild.exe", 4, 4),
                        (6, 50.2, "bash.exe", 1, None), (7, 50.3, "git.exe", 2, 6), (8, 80, "sh.exe", 3, 7))
    assert cross.findings(recs) == ([], [])
    # a parent that was not asked asks for nothing: both it and its child are findings
    recs = span(0, 100) + [hook(2, "pre", 5, programs=["npm"], head="npm")] + chain(
        (2, 5.2, "bash.exe", 1, None), (3, 5.3, "python.exe", 2, 2), (4, 6, "curl.exe", 3, 3))
    assert cited(cross.findings(recs)[0]) == [("os-4100", [3]), ("os-4100", [4])]


def test_d9_a_forked_bash_below_the_shell_is_asked_and_so_is_what_it_runs():
    base = span(0, 100) + [hook(2, "pre", 5, programs=["ls", "grep"], head="ls")]
    recs = base + chain((2, 5.2, "bash.exe", 1, None), (3, 5.25, "bash.exe", 2, 2), (4, 5.3, "ls.exe", 3, 3),
                        (5, 5.26, "bash.exe", 2, 2), (6, 5.31, "grep.exe", 3, 5))
    assert cross.findings(recs) == ([], [])
    # the same fork with no shell call in the 10 s before it is not asked (the MSYS hole has a window)
    late = base + chain((2, 5.2, "bash.exe", 1, None), (3, 40, "bash.exe", 2, 2), (4, 40.1, "curl.exe", 3, 3))
    assert cited(cross.findings(late)[0]) == [("os-4100", [3]), ("os-4100", [4])]


def test_d9_a_parent_that_cannot_be_judged_leaves_its_child_partial():
    recs = span(0, 100) + [hook(2, "pre", 5, programs=["npm"], head="npm")] + chain(
        (2, 5.2, "bash.exe", 1, None), (3, 30, "node.exe", 3, 77))   # parent seq 77 is not in the trace
    found, notes = cross.findings(recs)
    assert found == [] and "os-4100:3 (its parent could not be judged)" in notes[0]["detail"]


def test_d9_the_matched_fixture_holds_a_forked_bash_pipeline():
    recs = read("matched")
    procs = [r for r in recs if r.get("source") == "os" and r["phase"] == "pre" and r["tool"] == "process"]
    shape = [(r["input_meta"]["command_head"], r["input_meta"]["depth"]) for r in procs]
    assert shape == [("agent.exe", 0), ("bash.exe", 1), ("bash.exe", 2), ("bash.exe", 2), ("ls.exe", 3),
                     ("grep.exe", 3)]
    assert cross.findings(recs) == ([], [])


def test_d10_an_unread_pre_in_the_window_makes_the_process_partial_and_is_named():
    found, notes = cross.findings(span(0, 60) + [osl(2, 9, "ls.exe"), hook(2, "pre", 5, unread=True)])
    assert ("os-4100", [2]) not in cited(found)
    assert "os-4100:2 (unread pre s-hook:2)" in notes[0]["detail"]
    # a pre with unknown programs and no process at all stays a finding
    assert cited(cross.findings(span(0, 60) + [hook(2, "pre", 5, unread=True)])[0]) == [("s-hook", [2])]


def test_d10_the_holes_are_named():
    flat = " ".join(README.split())
    assert "Matching is by name only, so a renamed program passes as the name it carries" in flat
    assert "a tool that only has a shell word in its name and starts no process is a false-positive source" in flat
    threat = " ".join(THREAT.split())
    for phrase in ("a renamed binary (curl copied to `ls.exe`) passes as the program it is named for",
                   "Programs that start children of their own include npm, npx, yarn, pip, python, node, git",
                   "the real shape of an MSYS fork under Sysmon is checked only by the field test",
                   "leaves the processes in its window partial, and the note names that call",
                   "a tool that only has a shell word (bash, shell, cmd, command) in its name and starts no process"
                   " gives \"asked, not done\""):
        assert phrase in threat, phrase
    assert "command" in cross.SHELL_TOOL_WORDS and cross.is_shell_tool("RunCommand")


def test_d11_check_rules_lists_cross_source_with_its_rate_and_status():
    out = io.StringIO()
    assert cli.main(["check-rules"], out=out) == 0
    (row,) = [line for line in out.getvalue().splitlines() if line.startswith("CROSS-SOURCE ")]
    assert row.split()[1:4] == ["ok", "0.000", "0.1"] and "2 positive;" in row and "2 measured," in row
    data = json.loads(cli_json("check-rules", "--json"))
    (entry,) = [r for r in data if r["rule_id"] == "CROSS-SOURCE"]
    assert entry["status"] == cross.STATUS == "active" and entry["verdict"] == "ok"
    assert [p["fired"] for p in entry["positives"]] == [True, True]
    # OS-native relative paths, as fixtures.check_rule writes them for the catalog rules
    measured = [n["path"].replace(os.sep, "/") for n in entry["negatives"] if n["measured"]]
    assert measured == ["tests/fixtures/cross/matched.log", "tests/fixtures/cross/rg-helper.log"]


def cli_json(*argv):
    out = io.StringIO()
    cli.main(list(argv), out=out)
    return out.getvalue()


def test_d11_a_disabled_cross_rule_writes_only_a_disabled_note(monkeypatch):
    from raqib.rules import fixtures
    monkeypatch.setattr(cross, "STATUS", "disabled")
    assert cross.findings(read("done-not-asked")) == ([], [
        {"rule_id": "CROSS-SOURCE", "status": "disabled", "detail": "STATUS = disabled in raqib/rules/cross.py (A6)"}])
    assert cross.findings(trace.read(FIXTURES / "quickstart-d7841d1-claude-code-2.1.301.log")[0]) == ([], [])
    report_ = cross.check(fixtures.load_fixture, ROOT)
    assert report_["verdict"] == "positive-missed"   # a disabled rule fires on nothing
    table = {r["id"]: r for r in report.rule_table(engine.load_catalog(CATALOG))}
    assert table["CROSS-SOURCE"]["status"] == "disabled"


def test_d11_the_guards_are_measured_on_one_os_line():
    from raqib.rules import fixtures
    rules = {r.id: r for r in engine.load_catalog(CATALOG)}
    for rule_id, rel in (("NET-TOOL", "tests/fixtures/rules/NET-TOOL/negative-local.json"),
                         ("SECRET-OUTPUT", "tests/fixtures/rules/SECRET-OUTPUT/negative-clean-output.json")):
        lines = fixtures.load_fixture(ROOT / rel)[0]
        assert sum(1 for r in lines if r.get("source") == "os") == 1, rel
        assert fixtures.outcome(rules[rule_id], ROOT / rel) == (False, set(), True), rel   # measured, clean
    # Without the guard, SECRET-OUTPUT could not judge the os post: its negative would be unmeasured.
    doc = json.loads(json.dumps(rules["SECRET-OUTPUT"].doc))
    doc["match"]["all"] = [n for n in doc["match"]["all"] if "any" not in n]
    bare = engine.compile_rule(doc)
    lines = fixtures.load_fixture(ROOT / "tests/fixtures/rules/SECRET-OUTPUT/negative-clean-output.json")[0]
    assert engine.judge(bare, lines)[1] == [("os-4100", 1)]


def test_d11_a_yaml_rule_may_not_declare_class_cross():
    doc = dict(engine.load_rule(CATALOG / "DRIFT-FILES.yaml").doc, **{"class": "CROSS"})
    with pytest.raises(engine.RuleError, match="class: CROSS is the class of the code rule raqib/rules/cross.py"):
        engine.compile_rule(doc)


def test_d13_threat_model_names_the_agent_writable_trace_a_stopped_sysmon_and_events_4_16():
    threat = " ".join(THREAT.split())
    for phrase in ("once appended, os lines sit in the same trace as the hook's, a file the agent's user can write",
                   "an agent with administrator rights can stop Sysmon, unload its driver or clear its log before"
                   " os-sysmon reads it",
                   "Sysmon's own state and configuration events (4 and 16) are not read",
                   "it names the event ids an export does not hold (per export)"):
        assert phrase in threat, phrase
