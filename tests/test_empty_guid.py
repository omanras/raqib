"""ADR-0007 Amendment BV (the Table, 2026-11-20): an empty ProcessGuid is no ProcessGuid.

Seen in the field (the probe branch, GitHub's Windows machine): Sysmon stopped holding a parent that still ran,
and wrote the starts of its later children with ParentProcessGuid all zeros, ParentImage "-" and
ParentCommandLine "-", the ParentProcessId still right. The zeros were taken for a ProcessGuid of their own: the
children joined no tree, a follow wrote nothing for them and moved on, and the round took the tree for quiet.
Every export here is SYNTHETIC (synthetic.py's Export: host `host`, user `user`)."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import discover  # noqa: E402
from raqib.hooks import os_sysmon  # noqa: E402

_spec = importlib.util.spec_from_file_location("os_synthetic_bv", ROOT / "tests" / "fixtures" / "os" / "synthetic.py")
SYN = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SYN)

ZERO = "{00000000-0000-0000-0000-000000000000}"
REG = "C:\\Windows\\System32\\reg.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
ROOT_PID = 4950


def export(forgotten=True, first=81001, start_root=True, more=()):
    """The agent (4950), a child whose parent Sysmon holds (5001), then a child (5002) whose start names its
    parent as Sysmon wrote it once it no longer held the agent, a file that child made, and a grandchild (5003)."""
    x = SYN.Export(first_record=first)
    if start_root:
        x.proc("00.100", ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
        x.proc("01.000", 5001, CMD, '"%s"' % CMD, ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT)
    if forgotten:
        x.proc("02.000", 5002, REG, '"%s"' % REG, ROOT_PID, "-", "-", pguid=ZERO)
    else:
        x.proc("02.000", 5002, REG, '"%s"' % REG, ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT)
    x.file("02.100", 5002, REG, "C:\\Users\\user\\AppData\\Local\\Temp\\made-by-5002.txt")
    x.proc("02.200", 5003, CMD, '"%s"' % CMD, 5002, REG, '"%s"' % REG)
    for act in more:
        act(x)
    return x.text()


def pres(lines):
    return [d for d in map(json.loads, lines) if d.get("phase") == "pre"]


def test_bv1_a_child_whose_start_names_its_parent_by_an_empty_guid_is_the_trees_by_its_parents_pid():
    lines, silences = os_sysmon.build(export(), ROOT_PID)
    got = [(d["tool"], d["input_meta"].get("image"), d["input_meta"].get("depth")) for d in pres(lines)]
    assert ("process", "reg", 1) in got and ("process", "cmd", 2) in got       # the child and its own child
    assert [d["input_meta"]["path"] for d in pres(lines) if d["tool"] == "file"]  # and what the child did
    child = next(d for d in pres(lines) if d["input_meta"].get("image") == "reg")
    assert child["input_meta"]["parent_image"] is None                          # BV-2: "-" is not a program's name
    assert silences.count(os_sysmon.EMPTY_GUID) == 1 and "joined by the pid" in os_sysmon.EMPTY_GUID


def test_bv1_the_lines_are_the_ones_a_held_parent_gives_but_for_the_parents_name():
    forgotten, _ = os_sysmon.build(export(), ROOT_PID)
    held, said = os_sysmon.build(export(forgotten=False), ROOT_PID)
    assert os_sysmon.EMPTY_GUID not in said                                     # nothing empty: nothing said
    a, b = pres(forgotten), pres(held)
    assert len(a) == len(b) == 5
    for x, y in zip(a, b):
        mx, my = dict(x["input_meta"]), dict(y["input_meta"])
        if mx.get("image") == "reg" and x["tool"] == "process":
            assert (mx.pop("parent_image"), my.pop("parent_image")) == (None, "agent")
        assert (x["tool"], x["ts"], mx) == (y["tool"], y["ts"], my)


def test_bv1_in_a_later_pass_of_a_follow_the_child_joins_the_tree_the_earlier_pass_found():
    tree = {}
    first = SYN.Export(first_record=81001)
    first.proc("00.100", ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    lines, _ = os_sysmon.build(first.text(), ROOT_PID, guid=SYN.pguid_of(ROOT_PID), tree=tree, info={})
    assert len(pres(lines)) == 1
    later, silences = os_sysmon.build(export(first=81050, start_root=False), ROOT_PID, guid=SYN.pguid_of(ROOT_PID),
                                      tree=tree, after_record=81001, info={}, start_seq=len(lines))
    assert [d["input_meta"].get("image") for d in pres(later) if d["tool"] == "process"] == ["reg", "cmd"]
    assert os_sysmon.EMPTY_GUID in silences


def test_bv1_an_event_whose_own_guid_is_empty_is_its_pids():
    def more(x):
        x.file("03.000", 5001, CMD, "C:\\Users\\user\\AppData\\Local\\Temp\\by-an-unheld-process.txt", guid=ZERO)
    lines, silences = os_sysmon.build(export(forgotten=False, more=[more]), ROOT_PID)
    assert any(d["tool"] == "file" and d["input_meta"]["path"].endswith("by-an-unheld-process.txt") for d in pres(lines))
    assert os_sysmon.EMPTY_GUID in silences


def test_bv1_a_parent_pid_that_is_not_the_trees_is_still_not_the_trees():
    x = SYN.Export(first_record=81001)
    x.proc("00.100", ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.proc("02.000", 6002, REG, '"%s"' % REG, 7777, "-", "-", pguid=ZERO)      # another parent's child
    lines, _ = os_sysmon.build(x.text(), ROOT_PID)
    assert [d["input_meta"].get("image") for d in pres(lines)] == ["agent"]


def test_bv1_the_words_empty_and_given():
    assert os_sysmon.empty_guid(ZERO) and os_sysmon.empty_guid(ZERO.strip("{}")) and discover.empty_guid(ZERO)
    for given in (SYN.pguid_of(5001), "", None, "{00000000-0000-0000-0000-000000000001}", "-", "0", "{}", "--"):
        assert not os_sysmon.empty_guid(given) and not discover.empty_guid(given)
    assert os_sysmon._event_guid(ZERO) is None and os_sysmon._event_guid(SYN.pguid_of(5001)) == SYN.pguid_of(5001)
    assert discover._guid_text(ZERO) is None and discover._guid_text(SYN.pguid_of(5001)) == SYN.pguid_of(5001)


def test_bv1_the_round_keys_the_start_by_its_parents_pid_and_says_how_many():
    records, problems = discover.parse_sysmon(export(), keyed=True)
    assert problems == []
    start = next(r for r in records if r["kind"] == "proc" and r.get("created") and r["pid"] == 5002)
    assert start["ppid"] == ROOT_PID and start["pguid"] is None and start["guid_empty"] is True
    named = [r for r in records if r["kind"] == "proc" and r.get("derived") and r["pid"] == ROOT_PID]
    assert named and all(r.get("guid") != ZERO for r in named)
    assert {r["image"] for r in named} == {"agent", None}            # BV-2: "-" is no image of the agent's pid
    assert not any(r.get("guid") == ZERO or r.get("pguid") == ZERO for r in records)
    _, holes = discover._guid_instances(records)
    said = [h for h in holes if "empty ProcessGuid" in h]
    assert len(said) == 1 and said[0].startswith("1 event(s) of this round's channel")
    assert not any(ZERO in h for h in holes)                         # no process "of its own" made of the zeros
    _, quiet = discover._guid_instances(discover.parse_sysmon(export(forgotten=False), keyed=True)[0])
    assert not any("empty ProcessGuid" in h for h in quiet)


def test_bv1_an_event_of_another_kind_with_an_empty_guid_is_counted_by_the_round_too():
    def more(x):
        x.file("03.000", 5001, CMD, "C:\\Users\\user\\AppData\\Local\\Temp\\by-an-unheld-process.txt", guid=ZERO)
    records, _ = discover.parse_sysmon(export(forgotten=False, more=[more]), keyed=True)
    assert sum(1 for r in records if r.get("guid_empty")) == 1 and not any(r.get("guid") == ZERO for r in records)
    _, holes = discover._guid_instances(records)
    assert [h for h in holes if "empty ProcessGuid" in h][0].startswith("1 event(s) of this round's channel")


def test_bv2_an_image_of_a_dash_is_unread_never_a_programs_name():
    assert os_sysmon.program_name("-") is None and os_sysmon.program_name(" - ") is None
    assert os_sysmon.program_name("C:\\Windows\\System32\\reg.exe") == "reg.exe"
    x = SYN.Export(first_record=81001)
    x.proc("00.100", ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT, 900, SYN.EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.proc("02.000", 5002, "-", "-", ROOT_PID, SYN.AGENT, '"%s"' % SYN.AGENT)      # Sysmon holds no image of it
    lines, _ = os_sysmon.build(x.text(), ROOT_PID)
    child = [d for d in pres(lines) if d["tool"] == "process"][1]["input_meta"]
    assert child.get("command_unread") is True and "command_head" not in child and child["image"] is None
    assert discover._held("-") is None and discover._held(" - ") is None and discover._held("x") == "x"
