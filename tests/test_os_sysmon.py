"""M5.3 E1, E2 (ADR-0003 Amendment C, rulings C-5, C-6, C-7): the os capture
source from Sysmon (raqib/hooks/os_sysmon.py, `raqib os-sysmon`), the
synthetic export it is tested on, and the shared Sysmon reader in
raqib/discover.py, whose own output is pinned unchanged."""
import hashlib
import importlib.util
import io
import json
import re
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover  # noqa: E402
from raqib.hooks import common, os_sysmon  # noqa: E402
from raqib.rules import trace  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
E2 = FIXTURES / "os" / "sysmon-synthetic.xml"
DISCOVER_XML = FIXTURES / "discover" / "windows" / "sysmon.xml"
CWD = "C:\\work\\proj"


def synthetic():
    spec = importlib.util.spec_from_file_location("os_synthetic", FIXTURES / "os" / "synthetic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def e2_text():
    return discover.decode(E2.read_bytes())


def records(lines):
    return [json.loads(line) for line in lines]


def pres(lines):
    return [r for r in records(lines) if r["phase"] == "pre"]


# --- E2: the synthetic export -------------------------------------------------------

def test_e2_the_fixtures_are_what_the_generator_writes():
    """The export and the four CROSS-SOURCE fixtures are exactly synthetic.py's output (C-8)."""
    for rel, data in synthetic().files().items():
        assert (ROOT / rel).read_bytes() == data, rel


def test_e2_host_user_and_documentation_addresses_only():
    text = e2_text()
    assert "<Computer>host</Computer>" in text and "host\\user" in text
    import ipaddress
    import re
    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    found = re.findall(r"<Data Name='(?:Source|Destination)Ip'>([^<]+)</Data>", text)
    found += re.findall(r"::ffff:([0-9.]+)", text) + re.findall(r"https://([0-9.]+)/", text)
    assert found and all(any(ipaddress.ip_address(ip) in n for n in docs) for ip in found), found
    assert "FIELD-PC" not in text and "\\field" not in text   # not M5.0's host and user


def test_e2_discover_parse_sysmon_reads_the_synthetic_export():
    recs, problems = discover.parse_sysmon(e2_text())
    assert problems == []
    kinds = {}
    for r in recs:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    # 9 process creates (each also names its parent: 18), and the Image of the 3 connects (2 TCP, 1 UDP
    # with no conn record), the query and the 2 file creates (6); event 5 and the other provider are skipped.
    assert kinds == {"proc": 24, "conn": 2, "dns": 1, "file": 2}
    creates = [r for r in recs if r["kind"] == "proc" and not r.get("derived")]
    assert [r["pid"] for r in creates] == [4100, 4200, 4210, 4211, 4300, 5100, 4210, 4500, 4400]
    assert {r["pid"] for r in recs if r["kind"] == "conn"} == {4100, 4400}


def test_e2_c6_sysmon_events_keeps_command_line_guids_record_ids_and_udp():
    problems = []
    events = list(discover.sysmon_events(e2_text(), "sysmon", problems))
    assert problems == []
    assert [e["event"] for e in events] == [1, 3, 3, 22, 1, 1, 1, 1, 1, 11, 5, 1, 11, 1, 1, 3]
    # 70014 is the other provider's event, skipped.
    assert [e["record_id"] for e in events] == list(range(70001, 70014)) + [70015, 70016, 70017]
    bash = [e for e in events if e["event"] == 1 and e["data"]["ProcessId"] == "4200"][0]["data"]
    assert bash["CommandLine"] == '"C:\\Program Files\\Git\\usr\\bin\\bash.exe" -c -l "ls -la | grep src"'
    assert bash["ProcessGuid"].startswith("{8d1c0a51-") and bash["ParentProcessGuid"].startswith("{8d1c0a51-")
    udp = [e for e in events if e["event"] == 3 and e["data"]["Protocol"] == "udp"]
    assert len(udp) == 1 and udp[0]["data"]["DestinationIp"] == "203.0.113.9"
    only = list(discover.sysmon_events(e2_text(), ids=(11,)))
    assert [e["event"] for e in only] == [11, 11]


# Pinned before discover.py gained sysmon_events (C-6: discover's own output is unchanged).
PINNED = {
    "tests/fixtures/discover/windows/sysmon.xml": ("dff02ffa9f2b63fd9a7c2f4fe76b6c96e737dcc4b60974cff1ee393a00655ea7",
                                                   31),
    "tests/fixtures/os/sysmon-synthetic.xml": ("c0e06b93266794828ae92160827285cb0b1694aab4f3ed2dd651bcc9fdc39c50", 29),
}


@pytest.mark.parametrize("rel", sorted(PINNED))
@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_c6_parse_sysmon_output_is_pinned_unchanged(rel, eol):
    text = discover.decode((ROOT / rel).read_bytes()).replace("\n", eol)
    out = discover.parse_sysmon(text)
    blob = json.dumps(list(out), sort_keys=True, default=discover.iso)
    assert (hashlib.sha256(blob.encode()).hexdigest(), len(out[0])) == PINNED[rel] and out[1] == []


def test_c6_problems_keep_their_order_with_the_shared_reader():
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    no_pid = ("<Event xmlns='%s'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>11</EventID></System>"
              "<EventData><Data Name='UtcTime'>2026-11-03 09:00:00.000</Data></EventData></Event>\n" % ns)
    broken = "<Event xmlns='%s'><System><EventID>1</System></Event>\n" % ns
    _, problems = discover.parse_sysmon(broken + no_pid + broken)
    assert [(p["line"], p["reason"].split(":")[0]) for p in problems] == [
        (1, "XML"), (2, "Sysmon event 11 without a ProcessId"), (3, "XML")]


# --- E1: what is written --------------------------------------------------------------

def built(text=None, **kw):
    lines, silences = os_sysmon.build(e2_text() if text is None else text, 4100, **kw)
    return lines, silences


def test_e1_the_tree_under_the_root_and_nothing_else():
    lines, silences = built(cwd=CWD)
    assert silences == []
    rows = pres(lines)
    got = [(r["tool"], r["input_meta"].get("command_head"), r["input_meta"].get("depth")) for r in rows]
    assert got == [("process", "agent.exe", 0), ("net", None, None), ("net", None, None),
                   ("process", "bash.exe", 1), ("process", "ls.exe", 2), ("process", "grep.exe", 2),
                   ("process", "rg.exe", 1), ("file", None, None), ("process", "bash.exe", 1),
                   ("process", "curl.exe", 2), ("net", None, None)]
    flat = "\n".join(lines)
    # outside the tree: notepad (another parent), the service that reused pid 4210 and its file,
    # the other provider's event; the DNS query (event 22) is not read.
    for absent in ("notepad", "svchost", "svc.log", "Temp"):
        assert absent not in flat, absent


def test_e1_every_event_is_a_pre_and_a_post_with_one_seq_source_os():
    lines, _ = built(cwd=CWD)
    recs = records(lines)
    assert recs[0]["phase"] == "session_start" and recs[-1]["phase"] == "session_end"
    assert all(r["source"] == "os" and r["session_id"] == "os-4100" and r["cwd"] == CWD for r in recs)
    body = recs[1:-1]
    for pre, post in zip(body[0::2], body[1::2]):
        assert (pre["phase"], post["phase"]) == ("pre", "post")
        assert pre["seq"] == post["seq"] and pre["ts"] == post["ts"] and pre["tool"] == post["tool"]
        assert post["ok"] is True and post["output_meta"] == {} and "ok" not in pre
        assert post["input_sha256"] == pre["input_sha256"] and post["input_meta"] == pre["input_meta"]
    assert [r["seq"] for r in recs] == [1] + [s for s in range(2, 13) for _ in (0, 1)] + [13]
    assert recs[0]["ts"] == "2026-11-03T09:00:00.100Z" and recs[-1]["ts"] == "2026-11-03T09:00:40.200Z"
    for r in recs:   # in capture's shape, ASCII
        assert trace.strict_problem(r) is None, r
    assert all(line.isascii() for line in lines)


def test_e1_hashes_of_command_line_path_and_destination_never_the_text():
    lines, _ = built(cwd=CWD)
    rows = {(r["tool"], r["ts"]): r for r in pres(lines)}
    bash = rows[("process", "2026-11-03T09:00:05.200Z")]
    command = '"C:\\Program Files\\Git\\usr\\bin\\bash.exe" -c -l "ls -la | grep src"'
    assert bash["input_sha256"] == common.canonical_sha256({"command_line": command})
    assert bash["input_meta"] == {"command_head": "bash.exe", "command_programs": ["bash.exe"], "image": "bash",
                                  "parent_image": "agent", "depth": 1, "parent_seq": 2}   # D-9; M7.8: image, parent
    note = rows[("file", "2026-11-03T09:00:12.500Z")]
    assert note["input_sha256"] == common.canonical_sha256({"path": "C:\\work\\proj\\notes.txt"})
    assert note["input_meta"] == {"path": "C:\\work\\proj\\notes.txt"}
    api = rows[("net", "2026-11-03T09:00:01.000Z")]
    assert api["input_sha256"] == common.canonical_sha256(
        {"destination": {"hostname": "api.example.com", "ip": "203.0.113.7", "port": "443", "protocol": "tcp"}})
    assert api["input_meta"] == {"dest_port": 443, "dest_private": False}
    udp = rows[("net", "2026-11-03T09:00:01.500Z")]
    assert udp["input_sha256"] == common.canonical_sha256(
        {"destination": {"hostname": "-", "ip": "203.0.113.9", "port": "443", "protocol": "udp"}})
    flat = "\n".join(lines)
    for text in ("-la", "grep src", "--files", "https://", "198.51.100.20", "203.0.113", "api.example.com",
                 "host\\\\user", "Program Files", "AppData", "ParentCommandLine"):
        assert text not in flat, text


def test_e1_a_path_is_redacted_as_the_hook_redacts_it():
    key = "AKIA" + "Q7XW3MZT5KPL2VYR"
    text = e2_text().replace("C:\\work\\proj\\notes.txt", "C:\\work\\proj\\%s.txt" % key)
    lines, _ = built(text, cwd=CWD)
    (note,) = [r for r in pres(lines) if r["tool"] == "file"]
    assert note["input_meta"] == {"path": common.redact("C:\\work\\proj\\%s.txt" % key)}
    assert key not in "\n".join(lines)


@pytest.mark.parametrize("image, meta", [
    ("C:\\Program Files\\Git\\usr\\bin\\bash.exe", {"command_head": "bash.exe", "command_programs": ["bash.exe"],
                                                "image": "bash"}),
    ("C:/tools/Git/usr/bin/LS.EXE", {"command_head": "LS.EXE", "command_programs": ["LS.EXE"], "image": "ls"}),
    ("C:\\Windows\\System32\\format.com", {"command_head": "format.com", "command_programs": ["format.com"],
                                         "image": "format"}),
    ("C:\\Program Files\\App\\Code Helper.exe", {"command_unread": True, "image": None}),
    ("C:\\x\\" + "a1B2c3D4e5F6g7H8i9", {"command_unread": True, "image": None}),   # looks like a key
    ("", {"command_unread": True, "image": None}),
])
def test_e1_program_names_only_through_common(image, meta):
    assert os_sysmon.program_name(image) == meta.get("command_head")
    text = e2_text().replace("<Data Name='Image'>C:\\Program Files\\Git\\usr\\bin\\ls.exe</Data>",
                             "<Data Name='Image'>%s</Data>" % image, 1)
    lines, _ = built(text, cwd=CWD)
    ls = [r for r in pres(lines) if r["ts"] == "2026-11-03T09:00:05.300Z"][0]
    assert ls["input_meta"] == dict(meta, parent_image="bash", depth=2, parent_seq=5)   # M7.8 REDO R-7: the parent


@pytest.mark.parametrize("ip, private", [
    ("10.0.0.5", True), ("172.20.1.1", True), ("192.168.1.20", True), ("127.0.0.1", True), ("169.254.1.1", True),
    ("100.64.0.1", True), ("::1", True), ("fd00::1", True), ("fe80::1%12", True), ("::ffff:10.0.0.1", True),
    ("203.0.113.7", False), ("198.51.100.20", False), ("2001:db8::1", False), ("8.8.8.8", False),
    ("", None), ("x", None),
])
def test_c5_dest_private(ip, private):
    assert os_sysmon.dest_private(ip) is private


def without_root_start():
    return "\n".join(line for line in e2_text().splitlines() if "<Data Name='ProcessId'>4100</Data>"
                     not in line or "<EventID>1<" not in line)


def test_d4_cwd_is_the_option_else_the_roots_directory_else_no_cwd_at_all():
    assert {r["cwd"] for r in records(built(cwd="D:\\elsewhere")[0])} == {"D:\\elsewhere"}
    assert {r["cwd"] for r in records(built()[0])} == {"C:\\work\\proj\\"}   # the root's CurrentDirectory
    lines, _ = os_sysmon.build(without_root_start(), 4100)
    assert lines and not any("cwd" in r for r in records(lines))
    assert os.getcwd() not in "\n".join(lines) and "os.getcwd" not in (ROOT / "raqib" / "hooks" / "os_sysmon.py"
                                                                         ).read_text(encoding="utf-8")


def test_e1_order_is_utctime_then_record_id_whatever_the_export_order():
    lines, _ = built(cwd=CWD)
    text = e2_text()
    head, *events = text.splitlines()
    newest_first = "\n".join([head] + events[::-1]) + "\n"
    assert built(newest_first, cwd=CWD)[0] == lines
    assert built(text.replace("\n", "\r\n"), cwd=CWD)[0] == lines
    utf16 = b"\xff\xfe" + text.encode("utf-16-le")
    assert built(os_sysmon.decode(utf16), cwd=CWD)[0] == lines
    assert built(os_sysmon.decode(text.encode("utf-16-le")), cwd=CWD)[0] == lines   # no BOM
    # Two events at one UtcTime: EventRecordID decides, not the export's order.
    same = text.replace("2026-11-03 09:00:05.310", "2026-11-03 09:00:05.300")
    swapped = "\n".join([head] + events[::-1]) + "\n"
    order = [r["input_meta"].get("command_head") for r in pres(built(same, cwd=CWD)[0])]
    assert order[4:6] == ["ls.exe", "grep.exe"]
    order = [r["input_meta"].get("command_head") for r in pres(built(swapped.replace(
        "2026-11-03 09:00:05.310", "2026-11-03 09:00:05.300"), cwd=CWD)[0])]
    assert order[4:6] == ["ls.exe", "grep.exe"]


def test_c6_a_reused_pid_does_not_join_the_tree_and_a_root_reuse_is_followed():
    lines, _ = built(cwd=CWD)
    assert "svchost" not in "\n".join(lines)
    # Without ProcessGuids the pid decides: the reused pid left the tree at its new event 1.
    bare = "\n".join(line for line in e2_text().splitlines())
    import re
    bare = re.sub(r"<Data Name='(?:Parent)?ProcessGuid'>[^<]*</Data>", "", bare)
    flat = "\n".join(built(bare, cwd=CWD)[0])
    assert "svchost" not in flat and "C:\\\\Windows\\\\Temp" not in flat
    assert [r["input_meta"].get("command_head") for r in pres(built(bare, cwd=CWD)[0])
            if r["tool"] == "process"] == ["agent.exe", "bash.exe", "ls.exe", "grep.exe", "rg.exe", "bash.exe",
                                            "curl.exe"]


def test_c6_the_parent_guid_decides_when_the_reused_pids_new_process_has_no_event_1():
    """ls (pid 4210) exits; a process outside the tree takes pid 4210 with no
    event 1 in the export, and starts a child: its ParentProcessId is in the
    tree, its ParentProcessGuid is not, so it stays out."""
    x = synthetic()
    export = x.Export()
    x.agent_start(export)
    x.shell(export, "05.200", 4200, "ls")
    x.child(export, "05.300", 4210, x.LS, "ls", 4200, "ls")
    export.net("06.000", 4100, x.AGENT, "203.0.113.7", 443)
    export.file("07.000", 4100, x.AGENT, "C:\\work\\proj\\a.txt")
    export.proc("30.000", 6000, x.NOTEPAD, "notepad.exe", 4210, x.SVCHOST, "svchost.exe",
                pguid=x.pguid_of(4210, 1))
    lines, silences = os_sysmon.build(export.text(), 4100, cwd=CWD)
    assert silences == [] and "notepad" not in "\n".join(lines)
    # the same child with the tree's ls as its parent guid joins, at depth 3
    export.proc("31.000", 6001, x.NOTEPAD, "notepad.exe", 4210, x.LS, "ls")
    lines, _ = os_sysmon.build(export.text(), 4100, cwd=CWD)
    (joined,) = [r for r in pres(lines) if r["input_meta"].get("command_head") == "notepad.exe"]
    assert joined["ts"] == "2026-11-03T09:00:31.000Z" and joined["input_meta"]["depth"] == 3


def test_c5_seq_goes_on_from_the_trace_and_reruns_are_not_deduplicated(tmp_path):
    log = tmp_path / "trace.jsonl"
    out = io.StringIO()
    assert cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from", str(E2), "--cwd", CWD], out=out) == 0
    first = log.read_text().splitlines()
    assert cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from", str(E2), "--cwd", CWD],
                    out=io.StringIO()) == 0
    both = log.read_text().splitlines()
    assert both[:len(first)] == first and len(both) == 2 * len(first)
    again = records(both[len(first):])
    assert [r["seq"] for r in again] == [r["seq"] + 13 for r in records(first)]
    assert [r["input_sha256"] for r in again if r["phase"] == "pre"] == [
        r["input_sha256"] for r in records(first) if r["phase"] == "pre"]
    assert "raqib os-sysmon: 11 events of the tree under pid 4100" in out.getvalue()


def test_c5_cli_output_is_build_output(tmp_path):
    log = tmp_path / "t.jsonl"
    assert cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from", str(E2), "--cwd", CWD],
                    out=io.StringIO()) == 0
    assert log.read_text() == "".join(line + "\n" for line in built(cwd=CWD)[0])


# --- C-7: silence -----------------------------------------------------------------------

def run(tmp_path, text, root=4100, **kw):
    src = tmp_path / "in.xml"
    src.write_text(text, encoding="utf-8")
    log = tmp_path / "trace.jsonl"
    out, err = io.StringIO(), io.StringIO()
    code = os_sysmon.run(root, str(log), from_path=str(src), out=out, err=err, **kw)
    return code, log.read_text().splitlines() if log.exists() else [], err.getvalue()


def test_c7_root_not_found_is_one_silence_line_and_no_session(tmp_path):
    code, lines, err = run(tmp_path, e2_text(), root=9999)
    assert code == 1 and len(lines) == 1
    assert lines[0].startswith("RAQIB-SILENCE: os-sysmon root=9999 root pid 9999 is in no event 1, 3 or 11")
    assert err.splitlines() == lines
    recs, problems = trace.read(tmp_path / "trace.jsonl")
    assert recs == [] and problems == [{"line": 1, "reason": trace.SILENCE_REASON}]


@pytest.mark.parametrize("drop, line", [
    ("<EventID>1<", "the export holds no event 1 (process create)"),
    ("<EventID>11<", "the export holds no event 11 (file create)"),
])
def test_c7_no_event_1_or_11_is_a_silence_line(tmp_path, drop, line):
    text = "\n".join(x for x in e2_text().splitlines() if drop not in x or "Microsoft-Windows-Other" in x)
    code, lines, _ = run(tmp_path, text)
    assert code == 1 and any(x.startswith("RAQIB-SILENCE: os-sysmon root=4100 " + line) for x in lines)
    starts = [json.loads(x) for x in lines if x.startswith("{") and '"session_start"' in x]
    assert starts and starts[0]["missing_events"] == [int(drop.strip("<EventID>").strip("<"))]


def test_c7_no_event_3_is_no_silence_line_but_missing_events(tmp_path):
    text = "\n".join(x for x in e2_text().splitlines() if "<EventID>3<" not in x)
    code, lines, err = run(tmp_path, text)
    assert code == 0 and err == "" and not any(x.startswith("RAQIB-SILENCE") for x in lines)
    start = json.loads(lines[0])
    assert start["phase"] == "session_start" and start["missing_events"] == [3]
    assert trace.strict_problem(start) is None
    assert "missing_events" not in json.loads(built(cwd=CWD)[0][0])   # a complete export: no field


def test_c7_an_unreadable_event_and_one_without_processid_are_silence_lines(tmp_path):
    text = e2_text()
    head, *events = text.splitlines()
    broken = events[4].replace("</System>", "", 1)
    no_pid = events[5].replace("<Data Name='ProcessId'>4210</Data>", "")
    code, lines, _ = run(tmp_path, "\n".join([head] + events[:4] + [broken, no_pid] + events[6:]))
    silence = [x for x in lines if x.startswith("RAQIB-SILENCE")]
    assert code == 1 and len(silence) == 2
    assert "the event at line 7 (Sysmon 1) has no ProcessId or UtcTime: it is not recorded" in silence[0]
    assert "the export's line 6 cannot be read (XML: " in silence[1]
    assert all(x.isascii() and "\n" not in x for x in silence)


def test_c7_posix_without_from_is_exit_2_and_wevtutil_is_never_run(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a) or None)
    with pytest.raises(os_sysmon.UsageError, match="live Sysmon channel on Windows only"):
        os_sysmon.run(4100, str(tmp_path / "t.jsonl"), nt=False)
    if os.name != "nt":
        err = io.StringIO()
        sys_err, sys.stderr = sys.stderr, err
        try:
            assert cli.main(["os-sysmon", "--root", "4100", "--log", str(tmp_path / "t.jsonl")], out=io.StringIO()) == 2
        finally:
            sys.stderr = sys_err
        assert "--from FILE.xml" in err.getvalue()
    assert calls == [] and not (tmp_path / "t.jsonl").exists()


def test_c7_usage_errors_are_exit_2(tmp_path):
    for argv in (["os-sysmon", "--root", "x", "--log", "t"], ["os-sysmon", "--log", "t", "--from", str(E2)],
                 ["os-sysmon", "--root", "4100", "--log", str(tmp_path / "t.jsonl"), "--from", str(tmp_path / "no.xml")],
                 ["os-sysmon", "--root", "-1", "--log", str(tmp_path / "t.jsonl"), "--from", str(E2)]):
        assert cli.main(argv, out=io.StringIO()) == 2, argv
    assert cli.main(["os-sysmon", "--root", "4100", "--log", str(tmp_path), "--from", str(E2)],
                    out=io.StringIO()) == 2   # a directory is not a trace


class FakeRun:
    def __init__(self, result=None, raises=None):
        self.result, self.raises, self.calls = result, raises, []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.raises:
            raise self.raises
        return self.result


def test_c7_live_read_is_wevtutil_by_absolute_path_minimal_environment():
    ok = FakeRun(subprocess.CompletedProcess([], 0, E2.read_bytes(), b""))
    text, failed = os_sysmon.read_live(ok, environ={"SystemRoot": "C:\\WINDOWS", "PATH": "C:\\evil", "X": "y"})
    assert failed is None and text == e2_text()
    ((argv, kw),) = ok.calls
    assert argv == ["C:\\Windows\\System32\\wevtutil.exe", "qe", "Microsoft-Windows-Sysmon/Operational", "/f:xml"]
    assert kw == {"capture_output": True, "env": {"SystemRoot": "C:\\WINDOWS"}, "timeout": os_sysmon.LIVE_TIMEOUT}
    assert os_sysmon.read_live(FakeRun(subprocess.CompletedProcess([], 0, b"", b"")), environ={})[1] is None
    fake = FakeRun(subprocess.CompletedProcess([], 0, b"", b""))
    os_sysmon.read_live(fake, environ={})
    assert fake.calls[0][1]["env"] == {"SystemRoot": "C:\\Windows"}


@pytest.mark.parametrize("fake, why", [
    (FakeRun(subprocess.CompletedProcess([], 15007, b"", b"The specified channel could not be found.\r\n")),
     "wevtutil exited 15007 (The specified channel could not be found.): the Sysmon channel was not read"),
    (FakeRun(raises=FileNotFoundError(2, "No such file or directory")),
     "wevtutil could not be run (No such file or directory): the Sysmon channel was not read"),
    (FakeRun(raises=subprocess.TimeoutExpired("wevtutil", 600)),
     "wevtutil did not finish in 600 s: the Sysmon channel was not read"),
], ids=["exit", "missing", "timeout"])
def test_c7_a_failed_wevtutil_is_one_silence_line(tmp_path, fake, why):
    log = tmp_path / "t.jsonl"
    err = io.StringIO()
    code = os_sysmon.run(4100, str(log), out=io.StringIO(), err=err, nt=True,
                         live=lambda: os_sysmon.read_live(fake, environ={}))
    (line,) = log.read_text().splitlines()
    assert code == 1 and line.startswith("RAQIB-SILENCE: os-sysmon root=4100 " + why) and err.getvalue() == line + "\n"


def test_c7_live_on_windows_writes_the_session(tmp_path):
    fake = FakeRun(subprocess.CompletedProcess([], 0, E2.read_bytes(), b""))
    log = tmp_path / "t.jsonl"
    code = os_sysmon.run(4100, str(log), cwd=CWD, out=io.StringIO(), err=io.StringIO(), nt=True,
                         live=lambda: os_sysmon.read_live(fake, environ={}))
    assert code == 0 and log.read_text() == "".join(line + "\n" for line in built(cwd=CWD)[0])


def test_e1_the_module_runs_nothing_but_wevtutil_and_opens_no_socket():
    import ast
    tree = ast.parse((ROOT / "raqib" / "hooks" / "os_sysmon.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    # M7.9 REDO 4 (ADR-0007 AB-9): threading for a lock and a thread-local owner (no process, no socket)
    assert names == {"__future__", "ipaddress", "json", "os", "re", "subprocess", "sys", "threading", "raqib",
                     "raqib.hooks", "raqib.rules"}
    assert (ROOT / "raqib" / "hooks" / "os_sysmon.py").read_bytes().isascii()
    assert (ROOT / "raqib" / "rules" / "cross.py").read_bytes().isascii()


# --- REDO-2 (ADR-0003 Amendment D, rulings D-4, D-5, D-6, D-12, D-13) ------------------

def test_d4_an_export_read_elsewhere_with_no_cwd_makes_the_scope_cwd_rules_partial(tmp_path):
    src = tmp_path / "no-root-start.xml"
    src.write_text(without_root_start(), encoding="utf-8")
    log = tmp_path / "t.jsonl"
    assert cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from", str(src)], out=io.StringIO()) == 0
    recs, problems = trace.read(log)
    assert problems == [] and recs and not any("cwd" in r for r in recs)
    out = io.StringIO()
    # M7.8 (ADR-0007 P-1): NET-TOOL judges curl.exe's os line by its image and fires (exit 1); the SCOPE-CWD
    # rules still could not judge the lines with no cwd (partial)
    assert cli.main(["report", str(log), "--scope", "."], out=out) == 1
    text = out.getvalue()
    assert "FINDINGS: 1" in text and "NET-TOOL (NET, signature) session os-4100" in text
    assert "ALARMS (A3, A5): 0" in text   # M7.8 REDO R-8 (P8): a finding, and still no silence alarm
    assert "SCOPE-CWD-MOVED partial" in text and "SCOPE-CWD-ROOT partial" in text


@pytest.mark.parametrize("cwd, ok", [
    ("C:\\work\\proj", True), ("\\\\srv\\share\\proj", True), ("/work/proj", True),
    ("work", False), ("C:work", False), ("~/proj", False), ("", False),
])
def test_d12_cwd_is_validated_as_the_proxy_does(tmp_path, cwd, ok):
    log = tmp_path / "t.jsonl"
    code = cli.main(["os-sysmon", "--root", "4100", "--log", str(log), "--from", str(E2), "--cwd", cwd],
                    out=io.StringIO())
    assert code == (0 if ok else 2) and log.exists() is ok
    if not ok:
        with pytest.raises(os_sysmon.UsageError, match="--cwd must be an absolute directory"):
            os_sysmon.check_cwd(cwd)


def two_holders():
    """pid 4100 held first by an agent that ran curl and ended, then by the current one."""
    x = synthetic()
    export = x.Export()
    export.proc("00.100", 4100, x.AGENT, '"%s"' % x.AGENT, 900, x.EXPLORER, "explorer.exe", guid=x.pguid_of(4100, 0))
    export.proc("01.000", 4150, x.CURL, "curl -s https://198.51.100.20/x", 4100, x.AGENT, x.AGENT,
                pguid=x.pguid_of(4100, 0))
    export.end("02.000", 4100, x.AGENT)
    export.proc("10.000", 4100, x.AGENT, '"%s"' % x.AGENT, 900, x.EXPLORER, "explorer.exe", guid=x.pguid_of(4100, 1),
                cwd="C:\\work\\later\\")
    export.proc("11.000", 4160, x.BASH, '"%s" -c -l "ls"' % x.BASH, 4100, x.AGENT, x.AGENT, pguid=x.pguid_of(4100, 1))
    export.net("12.000", 4100, x.AGENT, "203.0.113.7", 443, guid=x.pguid_of(4100, 1))
    export.file("13.000", 4100, x.AGENT, "C:\\work\\later\\a.txt", guid=x.pguid_of(4100, 1))
    return x, export.text()


def heads(lines):
    return [r["input_meta"].get("command_head") for r in pres(lines) if r["tool"] == "process"]


def test_d5_the_latest_holder_is_the_root_and_earlier_holders_are_one_silence_line(tmp_path):
    x, text = two_holders()
    lines, silences = os_sysmon.build(text, 4100)
    assert heads(lines) == ["agent.exe", "bash.exe"] and "curl" not in "\n".join(lines)
    assert silences == ["pid 4100 had 1 earlier holder(s) in the export; the latest is the root (ProcessGuid %s);"
                        " give --root 4100:GUID for another" % x.pguid_of(4100, 1)]
    assert {r["cwd"] for r in records(lines)} == {"C:\\work\\later\\"}   # the latest holder's directory
    src = tmp_path / "two.xml"
    src.write_text(text, encoding="utf-8")
    err = io.StringIO()
    code = os_sysmon.run("4100", str(tmp_path / "t.jsonl"), from_path=str(src), out=io.StringIO(), err=err)
    assert code == 1 and err.getvalue().startswith("RAQIB-SILENCE: os-sysmon root=4100 pid 4100 had 1 earlier")


@pytest.mark.parametrize("spelling", ["{8d1c0a51-0000-6732-0000-000000001004}", "8D1C0A51-0000-6732-0000-000000001004"])
def test_d5_root_pid_guid_picks_the_holder(tmp_path, spelling):
    x, text = two_holders()
    assert x.pguid_of(4100, 0) == "{8d1c0a51-0000-6732-0000-000000001004}"
    lines, silences = os_sysmon.build(text, 4100, guid=spelling)
    assert silences == [] and heads(lines) == ["agent.exe", "curl.exe"]
    assert "bash" not in "\n".join(lines) and not [r for r in pres(lines) if r["tool"] in ("net", "file")]
    src = tmp_path / "two.xml"
    src.write_text(text, encoding="utf-8")
    log = tmp_path / "t.jsonl"
    assert cli.main(["os-sysmon", "--root", "4100:" + spelling, "--log", str(log), "--from", str(src)],
                    out=io.StringIO()) == 0
    assert [json.loads(x)["session_id"] for x in log.read_text().splitlines()][0] == "os-4100"


def test_d5_an_unknown_guid_is_root_not_found():
    _, text = two_holders()
    lines, silences = os_sysmon.build(text, 4100, guid="{00000000-0000-0000-0000-000000000000}")
    assert lines == [] and silences == ["root pid 4100 with ProcessGuid {00000000-0000-0000-0000-000000000000} is in no"
                                        " event 1, 3 or 11 of the export: nothing of its tree is recorded"]


@pytest.mark.parametrize("value", ["x", "4100:", "4100:not-a-guid", "-1", "4100:{8d1c0a51-0000-6732-0000-0000}",
                                   "4100:{8d1c0a51-0000-6732-0000-000000001004}x", " 4100"])
def test_d5_a_bad_root_is_a_usage_error(tmp_path, value):
    with pytest.raises(os_sysmon.UsageError, match="--root must be"):
        os_sysmon.parse_root(value)
    assert cli.main(["os-sysmon", "--root", value, "--log", str(tmp_path / "t"), "--from", str(E2)],
                    out=io.StringIO()) == 2


def test_d5_readme_says_the_latest_holder_is_the_root():
    readme = " ".join((ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").split())   # M9.2: docs/GUIDE.md
    assert "The root is the LATEST process that held the pid in the export" in readme
    assert "`--root PID:GUID` (its Sysmon ProcessGuid) picks another" in readme
    assert "the ProcessGuid keeps a reused pid out" in readme


def test_d6_silence_goes_to_stderr_before_the_append(tmp_path):
    err = io.StringIO()
    with pytest.raises(os_sysmon.UsageError, match="cannot write the trace"):
        os_sysmon.run(9999, str(tmp_path / "missing-dir" / "t.jsonl"), from_path=str(E2), out=io.StringIO(), err=err)
    assert err.getvalue().startswith("RAQIB-SILENCE: os-sysmon root=9999 root pid 9999 is in no event 1, 3 or 11")


def test_d12_a_torn_last_line_gets_its_newline_before_the_append(tmp_path):
    log = tmp_path / "t.jsonl"
    log.write_bytes(b'{"torn":')
    assert os_sysmon.run(4100, str(log), from_path=str(E2), cwd=CWD, out=io.StringIO(), err=io.StringIO()) == 0
    assert log.read_text() == '{"torn":\n' + "".join(line + "\n" for line in built(cwd=CWD)[0])


def test_d12_a_root_named_only_as_a_parent_is_found():
    x = synthetic()
    export = x.Export()
    x.shell(export, "05.200", 4200, "ls")
    x.child(export, "05.300", 4210, x.LS, "ls", 4200, "ls")
    export.net("06.000", 4200, x.BASH, "203.0.113.7", 443)
    export.file("07.000", 4200, x.BASH, "C:\\work\\proj\\a.txt")
    lines, silences = os_sysmon.build(export.text(), 4100)
    assert silences == []
    procs = [r for r in pres(lines) if r["tool"] == "process"]
    assert [(r["input_meta"]["command_head"], r["input_meta"]["depth"], r["input_meta"].get("parent_seq"))
            for r in procs] == [("bash.exe", 1, None), ("ls.exe", 2, procs[0]["seq"])]
    assert not any("cwd" in r for r in records(lines))   # no event 1 of the root: no cwd (D-4)


def test_d12_an_event_with_a_pid_and_no_utctime_is_a_silence_line():
    # M7.16 REDO (ADR-0007 AN-1): with no time read at all (no UtcTime, and an export with no TimeCreated) as before
    text = re.sub(r"<TimeCreated[^>]*/>", "", e2_text().replace(
        "<Data Name='UtcTime'>2026-11-03 09:00:12.500</Data>", "", 1))
    lines, silences = built(text, cwd=CWD)
    assert silences == ["the event at line 11 (Sysmon 11) has no ProcessId or UtcTime: it is not recorded"]
    assert not [r for r in pres(lines) if r["tool"] == "file"]


def test_d12_an1_an_event_with_no_utctime_and_a_logged_time_is_a_line_timed_from_the_log():
    text = e2_text().replace("<Data Name='UtcTime'>2026-11-03 09:00:12.500</Data>", "", 1)
    lines, silences = built(text, cwd=CWD)
    assert silences == ["Sysmon's event 11 carries a UtcTime that is not read: it is timed from the time it was"
                        " logged (time_from \"logged\", no skew)"]
    (f,) = [r for r in pres(lines) if r["tool"] == "file"]
    assert f["input_meta"]["time_from"] == "logged" and "time_skew_s" not in f["input_meta"]
    assert "time_record" not in f["input_meta"]


def test_d9_process_lines_link_their_parent_line():
    lines, _ = built(cwd=CWD)
    procs = {r["seq"]: r for r in pres(lines) if r["tool"] == "process"}
    for seq, r in procs.items():
        meta = r["input_meta"]
        if meta["depth"] == 0:
            assert "parent_seq" not in meta
        else:
            parent = procs[meta["parent_seq"]]
            assert parent["input_meta"]["depth"] == meta["depth"] - 1 and parent["seq"] < seq


def test_d13_no_claim_about_a_default_configuration():
    text = (FIXTURES / "os" / "synthetic.py").read_text(encoding="utf-8")
    assert "default configuration" not in text and "Raqib names the event ids an export does not hold" in " ".join(
        text.split())
    readme = " ".join((ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8").split())   # M9.2: docs/GUIDE.md
    assert "Raqib names the event ids your configuration does not log" in readme
    assert ("For Claude Code on Windows the root is `claude.exe`'s pid, from `raqib discover` or Task Manager"
            in readme)


def test_d13_adr_0004_says_the_root_comes_from_the_commander():
    adr = (ROOT / "docs" / "specs" / "ADR-0004-agent-discovery.md").read_text(encoding="utf-8")
    old = "os source rooted at its PID. M5.3 takes `--root` from `discover` instead\nof from the commander.\n"
    assert old in adr   # the sentence stays as written; the note under it corrects it
    note = adr.split(old, 1)[1].split("\n\n", 1)[0].strip()
    assert note.startswith("Note (2026-11-03, M5.3, ruling D-13 of ADR-0003 Amendment D;")
    assert "the root comes from the commander" in " ".join(note.split())
