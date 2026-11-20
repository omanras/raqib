"""M15.2 (ADR-0014 Amendment B, AB-1 to AB-4): Sysmon's event 13 of an autostart value is an os line of tool
`registry`, read beside the events 1, 11 and 3 (never in READ), by a second bounded question of a follow's pass
under the watch; PERSIST-RUN-KEY judges it.

Every export here is SYNTHETIC (synthetic.py's Export: host `host`, user `user`; a made-up SID, made-up value names
and harmless value text only); the lines are os-sysmon's own (os_sysmon.build, os_sysmon.follow). The stand-in
wevtutil is a Python class (never a process) that honours the query and records its arguments."""
import datetime
import importlib.util
import io
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, host, ruleform  # noqa: E402
from raqib.hooks import common, os_sysmon  # noqa: E402
from raqib.rules import engine, fixtures  # noqa: E402

CATALOG = ROOT / "raqib" / "rules" / "catalog"
RULES = engine.load_catalog(CATALOG)
FX = ROOT / "tests" / "fixtures" / "rules" / "PERSIST-RUN-KEY"
_spec = importlib.util.spec_from_file_location("os_synthetic_m152", ROOT / "tests" / "fixtures" / "os" / "synthetic.py")
SYN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SYN)

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
USER = "HKU\\" + SID + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
USER32 = "HKU\\" + SID + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\"
MACHINE = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
MACHINE32 = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\"
REG = "C:\\Windows\\System32\\reg.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
TEXT = "cmd /c echo test"
KEY = "AK" + "IA" + "Z7Q2M4N8P3R5T6W9"   # a made-up key shape, never a real one: common.redact's aws pattern
META = {"autostart", "hive", "view32", "value_name", "nested", "program", "image", "parent_image", "depth"}
START = datetime.datetime(2026, 11, 3, 9, 0, 0, tzinfo=datetime.timezone.utc)   # synthetic.py's DAY
CHANNEL = os_sysmon.CHANNEL


def rule(rule_id="PERSIST-RUN-KEY"):
    return next(r for r in RULES if r.id == rule_id)


def reg(x, at, pid, image, target, details=TEXT, utc=None, drop=()):
    """One Sysmon event 13 (SetValue) in the measured shape (its Data names), into Export x."""
    data = [("RuleName", "-"), ("EventType", "SetValue"), ("UtcTime", utc or SYN.DAY + at),
            ("ProcessGuid", SYN.pguid_of(pid)), ("ProcessId", pid), ("Image", image), ("TargetObject", target),
            ("Details", details), ("User", "host\\user")]
    x.event(13, at, [(k, v) for k, v in data if k not in drop])


def export(acts, root=4950, first=79001, start_root=True):
    """A SYNTHETIC Export: the root agent (its event 1 when start_root), then acts: ("proc", at, pid, image, ppid,
    pimage), ("file", at, pid, image, path), ("net", at, pid, image, ip, port) or ("reg", at, pid, image, target
    [, details[, utc[, drop]]])."""
    x = SYN.Export(first_record=first)
    if start_root:
        x.proc("00.100", root, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    for act in acts:
        if act[0] == "proc":
            _, at, pid, image, ppid, pimage = act
            x.proc(at, pid, image, '"%s"' % image, ppid, pimage, '"%s"' % pimage)
        elif act[0] == "file":
            x.file(*act[1:])
        elif act[0] == "net":
            x.net(*act[1:])
        else:
            reg(x, *act[1:])
    return x


def built(text, root=4950, **kw):
    lines, silences = os_sysmon.build(text, root, cwd="C:\\work\\proj", **kw)
    return [json.loads(line) for line in lines], silences


def regs(recs):
    return [r["input_meta"] for r in recs if r["tool"] == "registry" and r["phase"] == "pre"]


# --- E1 (AB-2): the line --------------------------------------------------------------------------------------------

SHAPES = [   # the four measured shapes, the two they imply, and the user's 32-bit view the pattern also holds
    (USER + "Run\\RaqibTestA", ("run", "user", False, "RaqibTestA")),
    (USER + "RunOnce\\RaqibTestB", ("runonce", "user", False, "RaqibTestB")),
    (MACHINE + "Run\\RaqibTestC", ("run", "machine", False, "RaqibTestC")),
    (MACHINE32 + "Run\\RaqibTestD", ("run", "machine", True, "RaqibTestD")),
    (MACHINE + "RunOnce\\RaqibTestE", ("runonce", "machine", False, "RaqibTestE")),
    (MACHINE32 + "RunOnce\\RaqibTestF", ("runonce", "machine", True, "RaqibTestF")),
    (USER32 + "Run\\RaqibTestG", ("run", "user", True, "RaqibTestG"))]


@pytest.mark.parametrize("target, want", SHAPES)
def test_e1_the_four_measured_shapes_and_the_two_implied_in_any_case(target, want):
    assert os_sysmon.autostart_value(target) == want
    for other in (target.lower(), target.upper()):
        got = os_sysmon.autostart_value(other)
        assert got[:3] == want[:3] and got[3].lower() == want[3].lower()
    pattern = os_sysmon.AUTOSTART_VALUE.pattern
    assert pattern.startswith("(?is)\\A") and pattern.endswith("\\Z")


def test_e1_each_shape_is_a_line_with_its_facts():
    recs, silences = built(export([("reg", "01.%03d" % i, 4950, SYN.AGENT, t) for i, (t, _) in enumerate(SHAPES)]
                                  ).text())
    assert [(m["autostart"], m["hive"], m["view32"], m["value_name"]) for m in regs(recs)] == [w for _, w in SHAPES]
    assert silences == [os_sysmon.SILENT_IF_MISSING[11]]   # the export holds no file event: said, as before
    for r in recs:
        if r["tool"] == "registry":
            assert set(r["input_meta"]) == META and r["source"] == "os" and r["session_id"] == "os-4950"
    assert [r["tool"] for r in recs if r["phase"] == "post"] == ["process"] + ["registry"] * len(SHAPES)


NOT_AUTOSTART = [
    USER + "RunNotification\\StartupTNotiRaqibTest",   # measured: Windows' own sihost.exe sets these
    USER + "RunOnceEx\\RaqibTest", MACHINE + "RunServices\\RaqibTest", MACHINE + "RunServicesOnce\\RaqibTest",
    USER + "Run", MACHINE + "RunOnce",                  # the key itself, no value
    USER + "Run\\", MACHINE + "Run\\RaqibTest\\",       # a trailing backslash
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\RaqibTask\\Id",
    "HKU\\.DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RaqibTest",
    "HKU\\" + SID + "_Classes\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\RaqibTest",
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Run\\RaqibTest",
    "X" + USER + "Run\\RaqibTest", "", None]


@pytest.mark.parametrize("target", NOT_AUTOSTART)
def test_e1_not_an_autostart_value_is_no_line_and_changes_no_other_line(target):
    assert os_sysmon.autostart_value(target) is None
    acts = [("proc", "01.000", 4960, REG, 4950, SYN.AGENT), ("file", "01.500", 4960, REG, "C:\\work\\proj\\a.txt")]
    without = export(acts)
    with_it = export(acts[:1] + [("reg", "01.200", 4960, REG, target or "-")] + acts[1:])
    got, said = built(with_it.text())
    assert regs(got) == [] and said == []
    want, _ = built(without.text())
    assert got == want and [r["tool"] for r in got if r["phase"] == "pre"] == ["process", "process", "file"]
    assert [r["ts"] for r in got if r["tool"] == "file"] == ["2026-11-03T09:00:01.500Z"] * 2   # every line, its time


# AC-3: anything below the key is a line; what follows it is the value's name, `nested` where it holds a backslash
@pytest.mark.parametrize("target, name, nested", [
    (USER + "Run\\RaqibRig\\Slash", "RaqibRig\\Slash", True),          # measured: Sysmon's target for such a name
    (USER + "Run\\Sub\\RaqibTest", "Sub\\RaqibTest", True),             # a value of a key under Run: the same
    (MACHINE32 + "RunOnce\\A\\B\\C", "A\\B\\C", True), (USER + "Run\\\\Lead", "\\Lead", True),
    (USER + "Run\\Plain", "Plain", False)])
def test_e3_anything_below_the_key_is_a_line_and_a_backslash_in_its_name_is_nested(target, name, nested):
    assert os_sysmon.autostart_value(target)[3] == name
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, target)]).text())
    (meta,) = regs(recs)
    assert (meta["value_name"], meta["nested"]) == (name, nested) and set(meta) == META
    (f,), notes = engine.evaluate([rule()], recs, {})
    assert notes == [] and f["severity"] == "high"
    assert ('a backslash in the name: %s (where true, the event cannot tell a value whose name holds one from a value'
            ' of a key under the Run or RunOnce key)' % ("true" if nested else "false")) in f["summary"]


def test_e1_an_event_with_no_target_object_is_not_a_line_and_is_said_as_the_other_unread_events():
    x = export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\RaqibTestA", TEXT, None, ("TargetObject",)),
                ("reg", "01.100", 4950, SYN.AGENT, "", TEXT),
                ("reg", "01.200", 4950, SYN.AGENT, USER + "Run\\RaqibTestB", TEXT, None, ("ProcessId",))])
    recs, said = built(x.text())
    assert regs(recs) == []
    assert [s for s in said if "(Sysmon 13) has no TargetObject: it is not recorded" in s] == [
        "the event at line 3 (Sysmon 13) has no TargetObject: it is not recorded",
        "the event at line 4 (Sysmon 13) has no TargetObject: it is not recorded"]
    assert "the event at line 5 (Sysmon 13) has no ProcessId or UtcTime: it is not recorded" in said


@pytest.mark.parametrize("details, program", [
    ("cmd /c echo benign-persistence-test", "cmd"), (TEXT, "cmd"),
    ('"C:\\Program Files\\Example\\tool.exe" --start', "tool.exe"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe"), ("%SystemRoot%\\system32\\example.exe /x", "example.exe"),
    ("C:/Tools/run.bat", "run.bat"), ("   cmd   ", "cmd"),
    ("", None), (None, None), ("   ", None), ("Binary Data", None), ("DWORD (0x00000003)", None),
    ("QWORD (0x00000000-0x00000001)", None), ("{8d1c0a51-0000-6732-0000-00000000a1b2}", None),
    ('"C:\\unclosed\\tool.exe', None), ('""', None), ("C:\\x\\" + "a" * 70 + ".exe", None),
    ("C:\\x\\" + KEY + ".exe", None), ("C:\\x\\", "x")])   # trailing separators do not count (basename)
def test_e1_details_of_each_kind_give_the_program_or_null(details, program):
    assert os_sysmon.registry_program(details) == program
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\RaqibTestA", details or "")]).text())
    assert [m["program"] for m in regs(recs)] == [program]


def test_e1_a_long_value_name_is_bounded_and_one_that_looks_like_a_key_is_redacted():
    long_name, key_name = "R" * 2000, "Raqib" + KEY
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\" + long_name),
                            ("reg", "01.100", 4950, SYN.AGENT, MACHINE + "RunOnce\\" + key_name)]).text())
    first, second = regs(recs)
    assert len(first["value_name"]) == os_sysmon.VALUE_NAME_MAX == 80 and first["value_name"].endswith("...")
    assert second["value_name"] == "Raqib[redacted:aws_access_key_id]"
    flat = "\n".join(json.dumps(r) for r in recs)
    assert KEY not in flat and long_name not in flat


@pytest.mark.parametrize("length, shown", [(80, "R" * 80), (81, "R" * 77 + "...")])
def test_e4_a_name_of_80_characters_is_kept_and_one_of_81_ends_with_dots(length, shown):
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\" + "R" * length)]).text())
    assert [m["value_name"] for m in regs(recs)] == [shown]


def test_e4_a_double_quote_is_an_apostrophe_and_a_name_that_imitates_the_sentence_stays_inside_its_quotes():
    name = 'Raqib" of the machine hive at seq 1; it would run calc; started by "explorer'
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\" + name),
                            ("reg", "01.100", 4950, SYN.AGENT, USER + "RunOnce\\Raqib\"Quote")]).text())
    first, second = regs(recs)
    assert first["value_name"] == name.replace('"', "'") and second["value_name"] == "Raqib'Quote"
    found, _ = engine.evaluate([rule()], recs, {})
    summary = found[0]["summary"]
    assert summary.count('"') == 2 and summary.split('"')[1] == first["value_name"]
    assert summary.startswith("agent (started by explorer) sets the run value \"Raqib' of the machine hive at seq 1;")
    assert summary.split('"')[2].startswith(" of the user hive at seq ")   # the sentence's own words, after the quotes


def test_e1_the_target_and_details_are_in_the_hash_only():
    target = USER + "Run\\RaqibTestA"
    details = "cmd /c echo benign-persistence-test"
    recs, _ = built(export([("reg", "01.000", 4950, SYN.AGENT, target, details)]).text())
    lines = [r for r in recs if r["tool"] == "registry"]
    assert [r["phase"] for r in lines] == ["pre", "post"] and lines[0]["input_meta"] == lines[1]["input_meta"]
    assert all(r["input_sha256"] == common.canonical_sha256({"target": target, "details": details}) for r in lines)
    flat = json.dumps(lines)
    for text in ("benign-persistence-test", "echo", "CurrentVersion", SID, "SOFTWARE"):
        assert text not in flat, text
    assert lines[1]["ok"] is True and lines[1]["output_meta"] == {}


def test_e1_image_parent_image_depth_and_the_time_keys():
    x = export([("proc", "01.000", 4960, CMD, 4950, SYN.AGENT), ("proc", "01.100", 4970, REG, 4960, CMD),
                ("reg", "01.050", 4950, SYN.AGENT, USER + "Run\\RaqibTestA"),          # between the two starts
                ("reg", "01.200", 4970, REG, USER + "RunOnce\\RaqibTestB"),
                ("reg", "01.300", 4970, REG, MACHINE + "Run\\RaqibTestC", TEXT, "2026-11-03 09:02:01.300")])
    recs, _ = built(x.text())
    pre = [r for r in recs if r["phase"] == "pre"]
    assert [(r["tool"], r["input_meta"].get("image")) for r in pre] == [
        ("process", "agent"), ("process", "cmd"), ("registry", "agent"), ("process", "reg"), ("registry", "reg"),
        ("registry", "reg")]   # in the order of time, among the process lines
    assert [(m["image"], m["parent_image"], m["depth"]) for m in regs(recs)] == [
        ("agent", "explorer", 0), ("reg", "cmd", 2), ("reg", "cmd", 2)]
    late = regs(recs)[2]   # its UtcTime 120 s after the time it was logged: timed from the log, as the others
    assert late["time_from"] == "logged" and abs(late["time_skew_s"]) == 120.0 and late["time_record"] == 79006
    assert "time_from" not in regs(recs)[0]
    # the root's start is not in the export: its value is still the tree's (its pid named by a net line), no parent
    y = export([("net", "01.000", 4950, SYN.AGENT, "192.0.2.20", 443), ("reg", "01.100", 4950, SYN.AGENT,
                                                                        USER + "Run\\RaqibTestA")], start_root=False)
    assert [(m["image"], m["parent_image"], m["depth"]) for m in regs(built(y.text())[0])] == [("agent", None, 0)]
    # a value set by a process outside the tree is not the tree's
    z = export([("proc", "01.000", 7000, PWSH, 900, SYN.EXPLORER), ("reg", "01.100", 7000, PWSH,
                                                                    USER + "Run\\RaqibTestA")])
    assert regs(built(z.text())[0]) == []


# --- E3: what must not change ---------------------------------------------------------------------------------------

def test_e3_read_missing_events_and_the_rounds_read_are_about_1_11_and_3():
    assert os_sysmon.READ == (1, 11, 3) and set(os_sysmon.SILENT_IF_MISSING) == {1, 11}
    assert discover.SYSMON_READ == os_sysmon.ROUND_IDS == (1, 3, 11, 22)
    assert os_sysmon.TOOLS == {1: "process", 11: "file", 3: "net", 13: "registry"}
    recs, said = built(export([("reg", "01.000", 4950, SYN.AGENT, USER + "Run\\RaqibTestA")]).text())
    assert recs[0]["missing_events"] == [3, 11] and len(regs(recs)) == 1
    assert said == [os_sysmon.SILENT_IF_MISSING[11]]


# --- E1, E2 of the REDO (ADR-0014 AC-1, AC-2): the read, the question for event 13 FIRST -----------------------------

HEAD = "<!-- SYNTHETIC Sysmon export (not captured): written by tests/test_registry_lines.py -->\n"
TIMED_OUT = "wevtutil did not return in 10 s (SYNTHETIC)"


class Wevtutil:
    """A stand-in wevtutil for a follow's passes (reader(args, timeout)): it HONOURS the query as wevtutil does
    (the event ids asked, EventRecordID>N or TimeCreated at or after the start, oldest first, /c:cap) over `log`,
    the channel's records as they stand, and records every argument list. The channel GROWS BETWEEN ANY TWO CALLS:
    grow[n] is appended before the n-th call is answered (so between the two questions of one pass too); a call
    whose number is in `fail` does not return in time."""

    def __init__(self, chunks, grow=None, fail=()):
        self.log, self.grow, self.fail, self.args = list(chunks), dict(grow or {}), set(fail), []

    def __call__(self, args, timeout):
        self.args.append(tuple(args))
        self.log += self.grow.pop(len(self.args), [])
        if len(self.args) in self.fail:
            return None, TIMED_OUT
        if len(args) == 3:
            return HEAD + "".join(c for c, _, _ in self.log), None
        query, cap = args[2][3:], int(args[3][3:])
        ids = {int(i) for i in re.findall(r"EventID=([0-9]+)", query)}
        rid, since = re.search(r"EventRecordID>([0-9]+)", query), re.search(r"SystemTime>='([^']+)'", query)
        keep = [c for c, r, t in self.log if int(re.search(r"<EventID>([0-9]+)<", c).group(1)) in ids and (
            (rid and r > int(rid.group(1))) or (since and t >= discover._ts(since.group(1))))]
        return HEAD + "".join(keep[:cap]), None


def chunks(x):
    return os_sysmon._chunks(x.text())[1]


def first_q(bound, cap=2000):
    return os_sysmon.round_args(os_sysmon.round_query(*bound, ids=os_sysmon.READ), cap)


def reg_q(bound, cap=500):
    return os_sysmon.round_args(os_sysmon.round_query(*bound, ids=(13,)), cap)


def follow(channel, passes, tmp_path, name="os.jsonl", **kw):
    """The real os_sysmon.follow of the tree under pid 4950 over the stand-in, bounded (since START), `passes`
    passes with no wait: (lines, RAQIB-SILENCE lines, [(pass, top, the tree's registry_top at its end)])."""
    stop, tops = threading.Event(), []
    tree = kw.setdefault("tree", {})

    def on_pass(n, top):
        tops.append((n, top, tree.get("registry_top")))
        if n >= passes:
            stop.set()
    kw.setdefault("since", START)
    kw.setdefault("registry", True)
    log = tmp_path / name
    os_sysmon.follow(kw.pop("root", "4950"), str(log), stop, every=0.0, out=io.StringIO(), err=io.StringIO(),
                     nt=True, on_pass=on_pass, reader=channel, **kw)
    text = log.read_text(encoding="ascii").splitlines() if log.exists() else []
    return [json.loads(x) for x in text if x.startswith("{")], [x for x in text if os_sysmon.MARKER in x], tops


def names(lines):
    return [m["value_name"] for m in regs(lines)]


def grown():
    """The channel of the three-pass test, in the order Sysmon logged it (record numbers count up):
    now:            79001 the root's start, 79002 reg.exe's start, 79003 its value A, 79004 an outsider's value;
    before call 2:  79005 cmd's start, 79006 its value B   (between the two questions of pass 1);
    before call 3:  79007 powershell's start, 79008 its value C   (after both questions of pass 1);
    before call 5:  79009 cmd's machine value D, 79010 a connection."""
    x = export([("proc", "01.000", 4970, REG, 4950, SYN.AGENT), ("reg", "01.100", 4970, REG, USER + "Run\\RaqibTestA"),
                ("reg", "01.200", 7000, PWSH, USER + "Run\\RaqibOther"),
                ("proc", "01.300", 4980, CMD, 4950, SYN.AGENT), ("reg", "01.400", 4980, CMD, USER + "Run\\RaqibTestB"),
                ("proc", "02.000", 4990, PWSH, 4950, SYN.AGENT),
                ("reg", "02.100", 4990, PWSH, USER + "RunOnce\\RaqibTestC"),
                ("reg", "03.000", 4980, CMD, MACHINE + "Run\\RaqibTestD"),
                ("net", "03.100", 4970, REG, "192.0.2.20", 443)])
    c = chunks(x)
    assert [r for _, r, _ in c] == list(range(79001, 79011))
    return c[:4], {2: c[4:6], 3: c[6:8], 5: c[8:]}


def test_e1_registry_first_and_a_value_set_between_the_two_questions_is_a_line_of_the_next_pass_once(tmp_path):
    now, grow = grown()
    channel = Wevtutil(now, grow)
    lines, silent, tops = follow(channel, 3, tmp_path)
    assert channel.args == [reg_q((None, START)), first_q((None, START)),
                            reg_q((79004, None)), first_q((79005, None)),
                            reg_q((79008, None)), first_q((79007, None))]
    assert channel.args[0] == ("qe", CHANNEL, "/q:*[System[(EventID=13) and TimeCreated[@SystemTime>="
                                              "'2026-11-03T09:00:00.000Z']]]", "/c:500", "/f:xml")
    assert channel.args[1] == ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                                              " TimeCreated[@SystemTime>='2026-11-03T09:00:00.000Z']]]", "/c:2000",
                               "/f:xml")   # the first question, to the byte
    # B: cmd started and set its value after the registry's answer and before the other's: a line of pass 2, once;
    # C: powershell started after both questions of pass 1: a line of pass 2; D: of pass 3; the outsider's: never
    assert names(lines) == ["RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]
    assert [(m["image"], m["parent_image"], m["depth"]) for m in regs(lines)] == [
        ("reg", "agent", 1), ("cmd", "agent", 1), ("powershell", "agent", 1), ("cmd", "agent", 1)]
    # the main bound is the other answer's, never moved by an event 13; the registry's ran ahead of it after pass 2
    # (79008 beside 79007: the measured order of bounds) and nothing was lost
    assert tops == [(1, 79005, 79004), (2, 79007, 79008), (3, 79010, 79009)]
    assert silent == []
    pre = [r for r in lines if r["phase"] == "pre"]
    assert [r["tool"] for r in pre] == ["process", "process", "registry", "process",   # pass 1, in time's order
                                        "registry", "process", "registry",             # pass 2
                                        "registry", "net"]                             # pass 3


def test_e1_a_cut_of_the_other_answer_holds_the_value_above_it_for_the_next_pass(tmp_path):
    x = export([("proc", "01.000", 4970, REG, 4950, SYN.AGENT), ("proc", "01.100", 4980, CMD, 4950, SYN.AGENT),
                ("reg", "01.200", 4980, CMD, USER + "Run\\RaqibTestB")])
    channel = Wevtutil(chunks(x))   # 79001 root, 79002 reg.exe, 79003 cmd (past the cut of 2), 79004 cmd's value
    lines, silent, tops = follow(channel, 2, tmp_path, cap=2)
    assert channel.args == [reg_q((None, START)), first_q((None, START), 2),
                            reg_q((None, START)), first_q((79002, None), 2)]   # the value was held: asked again
    assert tops == [(1, 79002, None), (2, 79003, 79004)]
    assert names(lines) == ["RaqibTestB"] and regs(lines)[0]["image"] == "cmd"
    assert [r["tool"] for r in lines if r["phase"] == "pre"] == ["process", "process", "process", "registry"]
    assert silent == [os_sysmon.silence_line(4950, os_sysmon.FOLLOW_CUT % (2, 2, 79002))]


def test_e1_a_members_value_above_a_cut_is_held_and_is_a_line_once(tmp_path):
    # the second review, K11: the value's process is a member already (its start is below the cut); only its record
    # is above the cut. Without the hold at the cut it would be a line in this pass and again in the next
    x = export([("proc", "01.000", 4970, REG, 4950, SYN.AGENT), ("proc", "01.100", 4980, CMD, 4950, SYN.AGENT),
                ("reg", "01.200", 4970, REG, USER + "Run\\RaqibTestA")])
    channel = Wevtutil(chunks(x))   # 79001 root, 79002 reg.exe (the cut of 2), 79003 cmd, 79004 reg.exe's value
    lines, silent, tops = follow(channel, 2, tmp_path, cap=2)
    assert tops == [(1, 79002, None), (2, 79003, 79004)]
    assert names(lines) == ["RaqibTestA"]                                        # once
    assert [r["tool"] for r in lines if r["phase"] == "pre"] == ["process", "process", "process", "registry"]


def test_e1_a_failed_other_read_takes_no_value_and_the_registrys_bound_does_not_move(tmp_path):
    now, grow = grown()
    channel = Wevtutil(now, grow, fail={2})   # pass 1's other question does not return
    lines, silent, tops = follow(channel, 3, tmp_path)
    assert tops[0] == (1, None, None) and channel.args[2] == reg_q((None, START))
    assert silent == [os_sysmon.silence_line(4950, TIMED_OUT)]
    assert names(lines) == ["RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]   # each once, none lost


def test_e1_a_failed_registry_read_is_said_once_and_takes_nothing_from_the_pass(tmp_path):
    now, grow = grown()
    channel = Wevtutil(now, grow, fail={1, 3})   # the registry's question of passes 1 and 2
    lines, silent, tops = follow(channel, 3, tmp_path)
    why = os_sysmon.REGISTRY_FAILED % TIMED_OUT
    assert silent == [os_sysmon.silence_line(4950, why)]   # said once, as its own silence
    assert [r["tool"] for r in lines if r["phase"] == "pre"][:3] == ["process", "process", "process"]
    assert [t[:2] for t in tops] == [(1, 79005), (2, 79007), (3, 79010)] and tops[1][2] is None
    assert channel.args[4] == reg_q((None, START))   # its bound did not move: pass 3 reads every value, once
    assert sorted(names(lines)) == ["RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]


def test_e1_a_registry_read_at_its_cap_is_said_and_the_next_pass_reads_on(tmp_path, monkeypatch):
    assert os_sysmon.REGISTRY_CAP == 500
    monkeypatch.setattr(os_sysmon, "REGISTRY_CAP", 1)
    now, grow = grown()
    channel = Wevtutil(now, grow)
    lines, silent, _ = follow(channel, 4, tmp_path)
    assert channel.args[0] == reg_q((None, START), 1) and channel.args[2] == reg_q((79003, None), 1)
    cut = os_sysmon.REGISTRY_CUT % (1, 1, 79003)
    assert cut == ("the follow's read of event 13 (a registry value set) read 1 events, its cap (/c:1): the"
                   " records after record 79003 are read by its next pass")
    assert silent.count(os_sysmon.silence_line(4950, cut)) == 1
    assert names(lines) == ["RaqibTestA", "RaqibTestB", "RaqibTestC"]   # one record a pass, none lost


def test_e2_a_root_not_found_yet_does_not_move_the_registrys_bound(tmp_path):
    x = SYN.Export(first_record=79001)
    reg(x, "01.000", 4950, SYN.AGENT, USER + "Run\\RaqibTestR")   # the root's value, before any other event of it
    x.net("01.100", 4950, SYN.AGENT, "192.0.2.20", 443)
    c = chunks(x)
    channel = Wevtutil(c[:1], {3: c[1:]})   # the root's connection comes before pass 2
    lines, _, tops = follow(channel, 2, tmp_path)   # the root by its pid alone
    assert tops == [(1, None, None), (2, 79002, 79001)]   # pass 1 found no root: the bound did not move
    assert channel.args[2] == reg_q((None, START))
    assert names(lines) == ["RaqibTestR"] and regs(lines)[0]["depth"] == 0


def test_e1_a_restart_resets_the_registrys_bound_as_the_others(tmp_path):
    now, grow = grown()
    channel, tree = Wevtutil(now, grow), {}
    at = datetime.datetime(2026, 11, 3, 9, 0, 2, tzinfo=datetime.timezone.utc)
    follow(channel, 2, tmp_path, tree=tree, restart=lambda: (1, at) if len(channel.args) >= 2 else None)
    assert channel.args[2:] == [reg_q((None, at)), first_q((None, at))]
    assert tree["restart"] == (1, at)


def test_e1_a_follow_attached_again_with_the_kept_tree_reads_none_twice(tmp_path):
    now, grow = grown()
    channel, tree = Wevtutil(now, {2: grow[2]}), {}
    one, _, tops = follow(channel, 1, tmp_path, name="one.jsonl", tree=tree)
    assert names(one) == ["RaqibTestA"] and tree["registry_top"] == 79004
    again = Wevtutil(channel.log + grow[3])
    two, _, _ = follow(again, 1, tmp_path, name="two.jsonl", tree=host.tree_copy(tree), after_record=tops[-1][1])
    assert again.args == [reg_q((79004, None)), first_q((79005, None))]
    assert names(two) == ["RaqibTestB", "RaqibTestC"]   # the earlier follow's never again
    assert [(m["image"], m["parent_image"]) for m in regs(two)] == [("cmd", "agent"), ("powershell", "agent")]


def test_e1_a_follow_without_registry_asks_one_question_and_writes_no_registry_line(tmp_path):
    now, grow = grown()
    channel = Wevtutil(now, grow)
    lines, _, _ = follow(channel, 2, tmp_path, registry=False)
    assert channel.args == [first_q((None, START)), first_q((79002, None))] and regs(lines) == []


def test_e1_a_follow_given_no_bound_and_run_on_an_export_read_event_13_from_the_same_text(tmp_path):
    now, grow = grown()
    text = HEAD + "".join(c for c, _, _ in now + grow[2] + grow[3] + grow[5])
    stop = threading.Event()
    stop.set()
    os_sysmon.follow("4950", str(tmp_path / "whole.jsonl"), stop, live=lambda: (text, None), out=io.StringIO(),
                     err=io.StringIO(), nt=True, registry=True)
    whole = [json.loads(x) for x in (tmp_path / "whole.jsonl").read_text(encoding="ascii").splitlines()
             if x.startswith("{")]
    export_file = tmp_path / "export.xml"
    export_file.write_text(text, encoding="ascii")
    os_sysmon.run("4950", str(tmp_path / "run.jsonl"), from_path=str(export_file), out=io.StringIO(),
                  err=io.StringIO())
    ran = [json.loads(x) for x in (tmp_path / "run.jsonl").read_text(encoding="ascii").splitlines()
           if x.startswith("{")]
    assert names(whole) == names(ran) == ["RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]
    assert [r for r in whole if r["phase"] != "session_start"] == [r for r in ran if r["phase"] != "session_start"]


def test_e7_the_registry_reads_problem_lines_and_an_event_with_no_target_object_are_said_as_its_own():
    x = SYN.Export(first_record=79001)
    reg(x, "01.000", 4950, SYN.AGENT, USER + "Run\\RaqibTestA", TEXT, None, ("TargetObject",))
    reg(x, "01.100", 4950, SYN.AGENT, USER + "Run\\RaqibTestB")
    second = x.text() + "<Event xmlns='%s'><System><EventID>13</EventID>\n" % SYN.NS   # cut short: no </Event>
    first = export([]).text()
    recs, said = built(first, tree={}, info={}, registry=second)
    assert names(recs) == ["RaqibTestB"]
    assert "the event at line 2 of the read of event 13 (Sysmon 13) has no TargetObject: it is not recorded" in said
    assert ("the read of event 13: its line 4 cannot be read (an <Event> without </Event>): that event is not"
            " recorded") in said


# --- E4 (AB-1): the rule ----------------------------------------------------------------------------------------------

NOTE_ITEMS = ("another autostart place of the registry", "a value or a key renamed into place",
              "a Sysmon that logs no value set there")


def test_e4_the_rule_as_amendment_b_rules_it():
    r = rule()
    assert (r.cls, r.kind, r.severity, r.attack, r.fp_budget) == ("PERSIST", "signature", "high", ("T1547.001",), 0.05)
    assert r.doc["match"]["all"] == [{"field": "phase", "eq": "pre"}, {"field": "source", "exists": True},
                                     {"field": "source", "eq": "os"}, {"field": "tool", "eq": "registry"},
                                     {"field": "input_meta.autostart", "in": ["run", "runonce"]}]
    assert tuple(e.split(":", 1)[0] for e in r.evasion[:3]) == NOTE_ITEMS
    for start in ("a hive written offline or loaded from a file", "a value changed by a program of the system on the"
                  " tree's behalf", "Linux has no os source", "an export or a follow that reached its cap"):
        assert any(e.startswith(start) for e in r.evasion), start
    assert not [e for e in r.evasion if e.startswith("a value whose name holds a backslash")]   # AC-3: no way round
    assert "(not measured for the registry" in next(e for e in r.evasion if e.startswith("a value changed by"))
    assert "registry is not read" not in " ".join(rule("PERSIST-AUTOSTART").evasion)   # AC-6
    assert "PERSIST-RUN-KEY's: Sysmon event 13" in rule("PERSIST-AUTOSTART").evasion[0]
    third = r.evasion[2]
    assert "Raqib cannot tell that from nothing done" in third and "not said yet" in third
    for word in ("{input_meta.hive}", "{input_meta.autostart}", "{input_meta.value_name}", "{input_meta.program}",
                 "{input_meta.image}"):
        assert word in r.doc["summary"], word
    # PERSIST-AUTOSTART is as it was (MUST NOT TOUCH)
    assert [m for m in ("registry",) if m in json.dumps(rule("PERSIST-AUTOSTART").doc["match"])] == []


def judged(name):
    lines, ctx, expect = fixtures.load_fixture(FX / name)
    return lines, expect, engine.evaluate([rule()], lines, ctx)


def test_e4_the_fixtures_six_shapes_and_a_null_program_fire_and_the_negatives_do_not():
    lines, expect, (found, notes) = judged("positive-run-values.json")
    metas = regs(lines)
    assert {(m["autostart"], m["hive"], m["view32"]) for m in metas} == {
        ("run", "user", False), ("runonce", "user", False), ("run", "machine", False), ("run", "machine", True),
        ("runonce", "machine", False), ("runonce", "machine", True)}
    assert any(m["program"] is None for m in metas) and {"reg", "powershell", "agent"} == {m["image"] for m in metas}
    assert sorted(s for f in found for s in f["cited_seq"]) == expect and len(found) == len(metas) == 7
    assert notes == [] and all(f["severity"] == "high" for f in found)
    assert found[0]["summary"] == ('reg (started by cmd) sets the run value "RaqibTestA" of the user hive at seq 5; it'
                                   " would run cmd; a backslash in the name: false (where true, the event cannot tell"
                                   " a value whose name holds one from a value of a key under the Run or RunOnce key)")
    assert all(m["nested"] is False for m in metas)
    lines, expect, (found, notes) = judged("positive-nested.json")   # AC-3: both read as nested, both fire
    assert [(m["value_name"], m["nested"]) for m in regs(lines)] == [("RaqibTestH\\Part", True),
                                                                     ("RaqibTest\\Deeper\\Part", True)]
    assert sorted(s for f in found for s in f["cited_seq"]) == expect and len(found) == 2 and notes == []
    assert all("a backslash in the name: true (where true, the event cannot tell" in f["summary"] for f in found)
    lines, _, (found, notes) = judged("negative-not-a-run-value.json")
    assert found == [] and notes == []
    pre = [r for r in lines if r["phase"] == "pre"]
    assert any(r["tool"] == "registry" and r["input_meta"]["autostart"] is None for r in pre)
    assert any(r["tool"] == "file" and "\\CurrentVersion\\Run\\" in r["input_meta"]["path"] for r in pre)
    assert any(r["tool"] == "process" and r["input_meta"]["image"] == "reg" for r in pre)
    lines, _, (found, notes) = judged("negative-autostart-absent.json")
    assert found == [] and [(n["rule_id"], n["status"]) for n in notes] == [("PERSIST-RUN-KEY", "partial")]
    assert all("autostart" not in m for m in regs(lines))


# --- E5 (AB-4): the watch ---------------------------------------------------------------------------------------------

def test_e5_the_watch_knows_registry_and_judge_source_gives_one_high_source_finding():
    assert host.LOGGED_EVENT == {"process": 1, "file": 11, "net": 3, "registry": 13}
    assert "registry" in ruleform.SOURCE_TOOLS and ruleform.check_tool("registry")[0] is None
    x = export([("proc", "01.000", 4960, CMD, 4950, SYN.AGENT), ("proc", "01.100", 4970, REG, 4960, CMD),
                ("reg", "01.200", 4970, REG, USER + "Run\\RaqibTestA"),
                ("reg", "01.300", 4970, REG, USER + "RunNotification\\StartupTNotiRaqib", "DWORD (0x00000001)")])
    recs, _ = built(x.text())
    line = next(r for r in recs if r["tool"] == "registry" and r["phase"] == "pre")
    assert host.act_key(line) == (line["ts"], "registry", line["input_sha256"], "reg", "cmd")
    assert host.act_key(dict(line, source="hooks")) is None
    found, notes = host.judge_source(host.source_rules(RULES), recs)
    (f,) = [f for f in found if f["rule_id"] == "PERSIST-RUN-KEY"]
    assert f["severity"] == "high" and f["kind"] == "signature" and f["session_id"] == "os-4950"
    assert f["cited_seq"] == [line["seq"]] and not [n for n in notes if n["rule_id"] == "PERSIST-RUN-KEY"]
    tool = next(f for f in found if f["rule_id"] == "NET-TOOL" or f["rule_id"] == "PERSIST-RUN-KEY")
    assert set(f) == set(tool)
    flat = json.dumps(found)
    assert "echo" not in flat and "CurrentVersion" not in flat and SID not in flat   # E7: no value text, no target
    assert "PERSIST-RUN-KEY" in {r.id for r in host.source_rules(RULES)}
    assert "PERSIST-RUN-KEY" not in {r.id for r in host.source_rules(RULES, host_lines=True)}


CLAUSE = "; this follow does not read the registry (Sysmon event 13): no value the tree sets is a line here"


class NamesRegistry:
    """A tree's os follow for raqib watch --host whose signature names `registry` (as os_sysmon.follow's does): it
    records what it is given, finishes one pass that writes nothing, then waits for its Stop."""

    def __init__(self):
        self.given = []

    def __call__(self, root, log, stop, every=None, out=None, err=None, on_pass=None, after_record=None, helpers=None,
                 since=None, tree=None, restart=None, server_hash=False, mark_under=None, registry=False):
        self.given.append({"registry": registry, "server_hash": server_hash, "bounded": since is not None})
        on_pass(1, None)
        stop.wait()
        return 1


class TakesAnyWord:
    """One whose signature does not name `registry` (it takes any keyword, as the tests' stand-ins of the real
    follow do): it is called as before."""

    def __init__(self):
        self.given = []

    def __call__(self, root, log, stop, **kw):
        self.given.append(sorted(kw))
        kw["on_pass"](1, None)
        stop.wait()
        return 1


def watched(tmp_path, monkeypatch, follow):
    sys.path.insert(0, str(ROOT / "tests"))
    from test_host_follow_returns import Rounds, rounds   # noqa: E402  (kimi and its curls, SYNTHETIC)
    from test_host_third_field_run import watch           # noqa: E402
    from test_round_channel import WALL0                  # noqa: E402
    w, _, _ = watch(tmp_path, monkeypatch, rounds(tmp_path, 3), channel=Rounds(), follow=follow, wall0=WALL0 + 240)
    (key,) = [k for k in w.trees if k[0] == 9176]
    assert w.sources[key].kind == "os"
    return w.sources[key]


def test_e5_the_watch_gives_registry_to_a_follow_that_names_it(tmp_path, monkeypatch):
    follow = NamesRegistry()
    src = watched(tmp_path, monkeypatch, follow)
    assert follow.given == [{"registry": True, "server_hash": True, "bounded": True}]
    assert CLAUSE not in src.text and "registry" in __import__("inspect").signature(os_sysmon.follow).parameters


def test_e5_a_follow_that_does_not_name_it_is_called_as_before_and_its_source_says_so(tmp_path, monkeypatch):
    follow = TakesAnyWord()
    src = watched(tmp_path, monkeypatch, follow)
    assert follow.given == [["after_record", "err", "every", "helpers", "mark_under", "on_pass", "out", "restart",
                             "server_hash", "since", "tree"]]   # no `registry`: as before
    assert src.text.startswith("os: Sysmon, rooted at pid 9176") and src.text.endswith(CLAUSE)


def test_e5_a_registry_line_is_paired_with_no_hostchild_line():
    ts = "2026-11-03T09:00:01.200Z"
    reg_line = {"source": "os", "tool": "registry", "ts": ts, "input_meta": {"image": "reg"}}
    child = {"tool": "HostChild", "input_meta": {"children": [{"pid": 4970, "image": "reg", "started": ts}]}}
    feed = type("F", (), {"path": "t", "epoch": 1, "numbered": [(1, reg_line), (2, child)]})()
    src = type("S", (), {"feeds": [feed]})()
    o = {"trace": "t", "fkey": ["t", 1], "lines": [1], "tree_key": ["k"], "source": "os", "src_kind": "os",
         "rule_id": "PERSIST-RUN-KEY", "history": False}
    h = dict(o, source=host.HOST_SOURCE, lines=[2])
    assert host.told_twice([o, h], {("k",): src}) == {}
    feed.numbered = [(1, dict(reg_line, tool="process")), (2, child)]   # the same shape as a process line: paired
    assert host.told_twice([o, h], {("k",): src}) == {id(o): h}


def test_e5_check_rules_lists_the_rule_ok_within_its_budget():
    report = next(r for r in fixtures.check_catalog(RULES, ROOT, cli.benign_default(ROOT))
                  if r["rule_id"] == "PERSIST-RUN-KEY")
    assert (report["verdict"], report["fp_rate"], report["measured"], report["unmeasured"]) == ("ok", 0.0, 1, 9)
    out = subprocess.run([sys.executable, "-m", "raqib", "check-rules"], cwd=str(ROOT), capture_output=True,
                         text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    rows = {line.split()[0]: line for line in out.stdout.splitlines()[1:]}
    assert re.match(r"PERSIST-RUN-KEY +ok +0\.000 +0\.05 +2 positive; .* 1 measured, 9 unmeasured",
                    rows["PERSIST-RUN-KEY"])


# --- E6: the guide and the threat model; E7: ASCII --------------------------------------------------------------------

def test_e6_the_guide_and_the_threat_model_hold_the_sentences_that_matter():
    guide = " ".join((ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").split())
    assert "Twenty-five rules turn the trace into findings" in guide and "and 19 more: 17 YAML rules" in guide
    assert "| PERSIST-RUN-KEY | a value set under a Run or RunOnce key of the registry" in guide
    assert "read from Sysmon's registry line (event 13) of a watched tree, whatever program of the tree set it" in guide
    assert ("It needs Windows with Sysmon logging a value set under these keys: where the configuration logs none,"
            " there is nothing to read. Linux has no os source for it: nothing there is judged by it |") in guide
    assert len(list(CATALOG.glob("*.yaml"))) == 17
    # AC-6: what os-sysmon reads and writes, said where it is said
    assert ("Sysmon events 1 (process create), 11 (file create), 3 (network connect) and 13 (a value set below the"
            " registry's Run or RunOnce key, ADR-0014) of the tree under the root") in guide
    assert '`source: "os"`, tool `process`, `file`, `net` or `registry`.' in guide
    assert "Hashes of the command line, the path, the destination or the registry's target and value text" in guide
    assert "before it, the follow asks one of its own for event 13" in guide
    assert "A value under the registry's Run or RunOnce key is PERSIST-RUN-KEY's" in guide
    assert "An autostart value of the registry, a scheduled task" not in guide
    assert ("file, net (dest_port) or registry (a value set under the registry's Run or RunOnce key; depth)"
            in host.SUSPECT_PROMPT)
    helped = " ".join((ROOT / "raqib" / "cli.py").read_text(encoding="ascii").split())   # the os-sysmon help
    assert ("1 (process create), 11 (file create), 3 (network connect) and 13 (a value set under the registry's"
            in helped)
    doc = " ".join(os_sysmon.__doc__.split())
    assert "11 (file create), 3 (network connect) and 13 (a value set below the registry's Run or RunOnce key" in doc
    assert "tool `process`, `file`, `net` or `registry`" in doc
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    part = text.split("### The registry's autostart values (PERSIST-RUN-KEY; ADR-0014 Amendment B)", 1)[1]
    flat = " ".join(part.split("### ", 1)[0].split())
    for sentence in ("Measured: the values were in four shapes of `TargetObject`",
                     "the only events 13 of the 91 seconds measured.",
                     "Windows' own sihost.exe set values under `...\\CurrentVersion\\RunNotification\\`",
                     "the match is on the whole key, so they are not this rule's.",
                     "never a command.",
                     "The target and the value's text are in the line's hash only, never in a finding.",
                     "nothing is then there to read, and Raqib cannot tell that from nothing done.",
                     "A configuration that logs every key was not measured",
                     "Linux has no os source: the rule judges nothing there.",
                     "a net line whose `Initiated` was not read is not judged and nothing says so;",
                     "asks its question for event 13 first (at most 500 events a pass), and then the first question,",
                     "no event 13 above its last record is taken and the registry's bound stops there,",
                     "while the tree's root is not found yet, the bound does not move either.",
                     "the line says `nested`, the rule fires for both, and its sentence says that it cannot tell.",
                     "(not measured for the registry; the measured case is the Schedule service's own TaskCache key).",
                     "An event 13 named by its pid alone (no ProcessGuid)",
                     "a later problem at a line number said before is not said again. Not measured.",
                     "and so two acts. Not shown reachable.",
                     "SYSTEM's own hive as `HKU\\S-1-5-18` or as `HKU\\.DEFAULT` (the second is not read): not"
                     " measured.",
                     "a Sysmon channel that gives no file event, and now none of event 13, is not said."):
        assert sentence in flat, sentence
    assert not re.search(r"\bM\d+\.\d+", flat)   # no milestone token


def test_e7_the_new_and_changed_code_is_ascii():
    for path in [CATALOG / "PERSIST-RUN-KEY.yaml", Path(__file__), ROOT / "raqib" / "hooks" / "os_sysmon.py",
                 ROOT / "raqib" / "host.py", ROOT / "raqib" / "ruleform.py",
                 ROOT / "tests" / "fixtures" / "rules" / "generate.py"] + sorted(FX.glob("*.json")):
        path.read_bytes().decode("ascii")
