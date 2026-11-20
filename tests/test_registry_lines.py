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
META = {"autostart", "hive", "view32", "value_name", "program", "image", "parent_image", "depth"}
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
    assert os_sysmon.AUTOSTART_VALUE.pattern.startswith("(?i)\\A") and os_sysmon.AUTOSTART_VALUE.pattern.endswith("\\Z")


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
    USER + "Run\\Sub\\RaqibTest",                       # a value of a key under Run
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
    assert [dict(r, ts=None) for r in got if r["tool"] != "file"] == [dict(r, ts=None) for r in want
                                                                       if r["tool"] != "file"]


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
    assert len(first["value_name"]) == os_sysmon.TEXT_MAX == 300 and first["value_name"].endswith("...")
    assert second["value_name"] == "Raqib[redacted:aws_access_key_id]"
    flat = "\n".join(json.dumps(r) for r in recs)
    assert KEY not in flat and long_name not in flat


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


# --- E2 (AB-3): the read ----------------------------------------------------------------------------------------------

HEAD = "<!-- SYNTHETIC Sysmon export (not captured): written by tests/test_registry_lines.py -->\n"


class Wevtutil:
    """A stand-in wevtutil for a follow's passes (reader(args, timeout)): it HONOURS the query as wevtutil does
    (the event ids asked, EventRecordID>N or TimeCreated at or after the start, oldest first, /c:cap) over `log`,
    the channel's records as they stand, and records every argument list; a call whose number is in `fail` does not
    return in time."""

    def __init__(self, chunks, fail=()):
        self.log, self.fail, self.args = list(chunks), set(fail), []

    def __call__(self, args, timeout):
        self.args.append(tuple(args))
        if len(self.args) in self.fail:
            return None, "wevtutil did not return in 10 s (SYNTHETIC)"
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


def second_q(bound, cap=500):
    return os_sysmon.round_args(os_sysmon.round_query(*bound, ids=(13,)), cap)


def follow(channel, later, passes, tmp_path, name="os.jsonl", **kw):
    """The real os_sysmon.follow of the tree under pid 4950 over the stand-in, bounded (since START), `passes`
    passes with no wait; after pass n the channel gains later[n-1]. (lines, RAQIB-SILENCE lines, [(pass, top)])."""
    stop, tops, later = threading.Event(), [], list(later)

    def on_pass(n, top):
        tops.append((n, top))
        if later:
            channel.log += later.pop(0)
        if n >= passes:
            stop.set()
    kw.setdefault("since", START)
    kw.setdefault("registry", True)
    log = tmp_path / name
    os_sysmon.follow(kw.pop("root", "4950"), str(log), stop, every=0.0, out=io.StringIO(), err=io.StringIO(),
                     nt=True, on_pass=on_pass, reader=channel, **kw)
    text = log.read_text(encoding="ascii").splitlines() if log.exists() else []
    return [json.loads(x) for x in text if x.startswith("{")], [x for x in text if os_sysmon.MARKER in x], tops


def three_passes():
    """79001 kimi-like root start, 79002 reg.exe's start, 79003 its Run value, 79004 a value of a process outside
    the tree | 79005 cmd's start, 79006 its value, 79007 reg.exe's RunOnce value | 79008 cmd's machine value (its
    start was the second pass's), 79009 a connection."""
    x = export([("proc", "01.000", 4970, REG, 4950, SYN.AGENT), ("reg", "01.100", 4970, REG, USER + "Run\\RaqibTestA"),
                ("reg", "01.200", 7000, PWSH, USER + "Run\\RaqibOther"),
                ("proc", "02.000", 4980, CMD, 4950, SYN.AGENT), ("reg", "02.100", 4980, CMD, USER + "Run\\RaqibTestB"),
                ("reg", "02.200", 4970, REG, USER + "RunOnce\\RaqibTestC"),
                ("reg", "03.000", 4980, CMD, MACHINE + "Run\\RaqibTestD"),
                ("net", "03.100", 4970, REG, "192.0.2.20", 443)])
    c = chunks(x)
    assert [r for _, r, _ in c] == list(range(79001, 79010))
    return c[:4], [c[4:7], c[7:]]


def test_e2_three_passes_ask_the_two_questions_each_in_order_and_read_every_event_13_once(tmp_path):
    now, later = three_passes()
    channel, tree = Wevtutil(now), {}
    lines, silent, tops = follow(channel, later, 3, tmp_path, tree=tree)
    assert channel.args == [first_q((None, START)), second_q((None, START)),
                            first_q((79002, None)), second_q((79004, None)),
                            first_q((79005, None)), second_q((79007, None))]
    assert channel.args[1] == ("qe", CHANNEL, "/q:*[System[(EventID=13) and TimeCreated[@SystemTime>="
                                              "'2026-11-03T09:00:00.000Z']]]", "/c:500", "/f:xml")
    assert channel.args[0] == ("qe", CHANNEL, "/q:*[System[(EventID=1 or EventID=11 or EventID=3) and"
                                              " TimeCreated[@SystemTime>='2026-11-03T09:00:00.000Z']]]", "/c:2000",
                               "/f:xml")   # the first question, to the byte
    assert tops == [(1, 79002), (2, 79005), (3, 79009)]   # on_pass's bound is the first read's
    assert tree["registry_top"] == 79008 and os_sysmon.REGISTRY_CAP == 500
    got = [(m["value_name"], m["image"], m["parent_image"], m["depth"]) for m in regs(lines)]
    assert got == [("RaqibTestA", "reg", "agent", 1), ("RaqibTestB", "cmd", "agent", 1),
                   ("RaqibTestC", "reg", "agent", 1), ("RaqibTestD", "cmd", "agent", 1)]   # each once, none other
    pre = [(r["seq"], r["tool"]) for r in lines if r["phase"] == "pre"]
    assert [t for _, t in pre] == ["process", "process", "registry", "process", "registry", "registry", "registry",
                                   "net"]   # each pass's lines in the order of time
    assert silent == []


def test_e2_a_follow_without_the_second_read_asks_one_question_and_writes_no_registry_line(tmp_path):
    now, later = three_passes()
    channel = Wevtutil(now)
    lines, _, tops = follow(channel, later, 2, tmp_path, registry=False)
    assert channel.args == [first_q((None, START)), first_q((79002, None))] and regs(lines) == []
    assert "registry" in __import__("inspect").signature(os_sysmon.follow).parameters


def test_e2_a_second_read_at_its_cap_is_said_once_and_the_next_pass_reads_on(tmp_path, monkeypatch):
    monkeypatch.setattr(os_sysmon, "REGISTRY_CAP", 1)
    now, later = three_passes()
    channel = Wevtutil(now)
    lines, silent, _ = follow(channel, later, 3, tmp_path)
    assert channel.args[1] == second_q((None, START), 1) and channel.args[3] == second_q((79003, None), 1)
    cut = os_sysmon.REGISTRY_CUT % (1, 1, 79003)
    assert cut == ("the follow's second read (event 13, a registry value set) read 1 events, its cap (/c:1): the"
                   " records after record 79003 are read by its next pass")
    assert silent.count(os_sysmon.silence_line(4950, cut)) == 1
    assert [m["value_name"] for m in regs(lines)] == ["RaqibTestA", "RaqibTestB"]   # one a pass, read on


def test_e2_a_failed_second_read_beside_a_good_first_is_said_once_and_takes_nothing_from_the_pass(tmp_path):
    now, later = three_passes()
    channel = Wevtutil(now, fail={2, 4})   # the second question of passes 1 and 2
    lines, silent, tops = follow(channel, later, 3, tmp_path)
    why = os_sysmon.REGISTRY_FAILED % "wevtutil did not return in 10 s (SYNTHETIC)"
    assert silent == [os_sysmon.silence_line(4950, why)]   # said once, as its own silence
    assert [r["tool"] for r in lines if r["phase"] == "pre"][:3] == ["process", "process", "process"]
    assert tops == [(1, 79002), (2, 79005), (3, 79009)]
    # its bound did not move: the third pass asks since the start and reads every value of the tree, once
    assert channel.args[5] == second_q((None, START))
    assert sorted(m["value_name"] for m in regs(lines)) == ["RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]


def test_e2_a_restart_resets_the_second_reads_bound_as_the_firsts(tmp_path):
    now, later = three_passes()
    channel, tree = Wevtutil(now), {}
    at = datetime.datetime(2026, 11, 3, 9, 0, 2, tzinfo=datetime.timezone.utc)
    follow(channel, later, 2, tmp_path, tree=tree, restart=lambda: (1, at) if len(channel.args) >= 2 else None)
    assert channel.args[2:] == [first_q((None, at)), second_q((None, at))]
    assert tree["restart"] == (1, at) and tree["registry_top"] == 79007


def test_e2_a_follow_attached_again_with_the_kept_tree_reads_none_twice(tmp_path):
    now, later = three_passes()
    channel, tree = Wevtutil(now), {}
    one, _, tops = follow(channel, [], 1, tmp_path, name="one.jsonl", tree=tree)
    assert [m["value_name"] for m in regs(one)] == ["RaqibTestA"] and tree["registry_top"] == 79004
    again = Wevtutil(now + later[0])
    two, _, _ = follow(again, [], 1, tmp_path, name="two.jsonl", tree=host.tree_copy(tree), after_record=tops[-1][1])
    assert again.args == [first_q((79002, None)), second_q((79004, None))]
    assert [m["value_name"] for m in regs(two)] == ["RaqibTestB", "RaqibTestC"]   # the earlier follow's never again
    # a start read by the earlier follow gives the names (reg.exe's, 79002, is not read again)
    assert [(m["image"], m["parent_image"]) for m in regs(two)] == [("cmd", "agent"), ("reg", "agent")]


def test_e2_a_follow_given_no_bound_and_run_on_an_export_read_event_13_from_the_same_text(tmp_path):
    now, later = three_passes()
    text = HEAD + "".join(c for c, _, _ in now + later[0] + later[1])
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
    assert [m["value_name"] for m in regs(whole)] == [m["value_name"] for m in regs(ran)] == [
        "RaqibTestA", "RaqibTestB", "RaqibTestC", "RaqibTestD"]
    assert [r for r in whole if r["phase"] != "session_start"] == [r for r in ran if r["phase"] != "session_start"]


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
    assert found[0]["summary"] == ("reg sets a run value of the user hive at seq 5 (RaqibTestA: it would run cmd;"
                                   " started by cmd)")
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
    assert re.match(r"PERSIST-RUN-KEY +ok +0\.000 +0\.05 +1 positive; .* 1 measured, 9 unmeasured",
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
                     "a Sysmon channel that gives no file event, and now none of event 13, is not said."):
        assert sentence in flat, sentence
    assert not re.search(r"\bM\d+\.\d+", flat)   # no milestone token


def test_e7_the_new_and_changed_code_is_ascii():
    for path in [CATALOG / "PERSIST-RUN-KEY.yaml", Path(__file__), ROOT / "raqib" / "hooks" / "os_sysmon.py",
                 ROOT / "raqib" / "host.py", ROOT / "raqib" / "ruleform.py",
                 ROOT / "tests" / "fixtures" / "rules" / "generate.py"] + sorted(FX.glob("*.json")):
        path.read_bytes().decode("ascii")
