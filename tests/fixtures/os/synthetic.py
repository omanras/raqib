"""M5.3 E2 and C-8: the SYNTHETIC Sysmon exports (not captured from a machine)
for the os source and the CROSS-SOURCE fixtures, and the hook halves of
those fixtures.

Shape: what `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml` writes,
one event per line (LF here: .gitattributes keeps every file LF; the
readers take CRLF too, tested in memory), with the Data fields Sysmon 15
renders for events 1, 3, 5, 11 and 22 (SHA1 image hashes). No claim is made
about any configuration's defaults (ruling D-13): Raqib names the event ids
an export does not hold. Host `host`, user `user`; every IP is a
documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). The
real export under the commander's configuration is the field test, not
this file.

`python tests/fixtures/os/synthetic.py` (from the checkout) rewrites:
- tests/fixtures/os/sysmon-synthetic.xml: one agent tree (root pid 4100)
  plus processes outside it, a reused pid, a UDP connection, a DNS query,
  an event of another provider;
- tests/fixtures/cross/<name>.sysmon.xml and <name>.log for the four
  CROSS-SOURCE fixtures: the hook lines below, then os-sysmon's lines for
  the export (`os_sysmon.build`, as `raqib os-sysmon --from` writes them).
- M7.8 (ADR-0007 Amendment P, P-1): the os-line fixtures of NET-TOOL and
  DESTRUCT-CMD, tests/fixtures/rules/<RULE>/{positive,negative}-os-process.json,
  os-sysmon's lines (`os_sysmon.build`) of these exports:
  - tests/fixtures/os/net-windows.sysmon.xml (root 4700): Windows network
    programs below an agent (cmd.exe -> bitsadmin.exe; plink.exe);
  - tests/fixtures/os/destruct-windows.sysmon.xml (root 4600): destructive
    programs below an agent (Git's bash.exe -> rm.exe; cmd.exe ->
    vssadmin.exe);
  - tests/fixtures/os/benign-windows-desktop.sysmon.xml and
    kimi-two-samples.sysmon.xml: the discover exports
    tests/fixtures/discover/benign/windows-desktop and kimi/two-samples
    (themselves SYNTHETIC) READ AS OS LINES: every Win32_Process row with an
    ExecutablePath, once per (pid, CreationDate), becomes the event 1 Sysmon
    would have logged at its creation (pid, parent pid, image, command line;
    no ProcessGuid, so the pid alone decides; times made up, 0.1 s apart).
    The roots: explorer 5100 of the desktop (the whole desktop, code 6050's
    subtree in it, once), kimi 10728.
  - tests/fixtures/os/git-ssh-windows.sysmon.xml (root 4800, M7.8 REDO R-7):
    git.exe -> Git's ssh.exe, git over SSH (NET-TOOL's negative);
  - tests/fixtures/os/nested-windows.sysmon.xml (roots 6100 and 6200, REDO
    R-3): outer.exe -> inner.exe -> cmd.exe -> curl.exe, two nested trees.
  The positives cite the lines of the listed programs (expect_seq, computed
  here from the image names, not from the rule); each rule's negative holds
  the desktop, Kimi's tree and the other rule's positive tree.
tests/test_os_sysmon.py and tests/test_cross.py check that the files are
exactly what this script writes.
"""
import csv
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
AGENT = "C:\\Users\\user\\AppData\\Local\\Programs\\agent\\agent.exe"
BASH = "C:\\Program Files\\Git\\usr\\bin\\bash.exe"
LS = "C:\\Program Files\\Git\\usr\\bin\\ls.exe"
GREP = "C:\\Program Files\\Git\\usr\\bin\\grep.exe"
CURL = "C:\\Windows\\System32\\curl.exe"
RG = "C:\\Users\\user\\AppData\\Local\\Programs\\agent\\resources\\rg.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
NOTEPAD = "C:\\Windows\\System32\\notepad.exe"
SVCHOST = "C:\\Windows\\System32\\svchost.exe"
SERVICES = "C:\\Windows\\System32\\services.exe"
PROJECT = "C:\\work\\proj\\"
ROOT_PID = 4100
DAY = "2026-11-03 09:00:"


class Export:
    """Events in the order Sysmon wrote them; EventRecordID counts up."""

    def __init__(self, first_record=70001):
        self.lines = []
        self.record = first_record

    def event(self, eid, at, data, provider="Microsoft-Windows-Sysmon"):
        utc = DAY + at
        system = utc.replace(" ", "T") + "0000Z"
        body = "".join("<Data Name='%s'>%s</Data>" % (k, _xml(v)) for k, v in data)
        self.lines.append(
            "<Event xmlns='%s'><System><Provider Name='%s' Guid='%s'/><EventID>%d</EventID><Version>5</Version>"
            "<Level>4</Level><Task>%d</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
            "<TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID><Correlation/>"
            "<Execution ProcessID='2210' ThreadID='3304'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "<Computer>host</Computer><Security UserID='S-1-5-18'/></System><EventData>%s</EventData></Event>"
            % (NS, provider, GUID, eid, eid, system, self.record, body))
        self.record += 1

    def proc(self, at, pid, image, cmd, ppid, pimage, pcmd, cwd=PROJECT, guid=None, pguid=None):
        self.event(1, at, [
            ("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessGuid", guid or pguid_of(pid)), ("ProcessId", pid),
            ("Image", image), ("FileVersion", "-"), ("Description", "-"), ("Product", "-"), ("Company", "-"),
            ("OriginalFileName", "-"), ("CommandLine", cmd), ("CurrentDirectory", cwd), ("User", "host\\user"),
            ("LogonGuid", "{8d1c0a51-0000-6732-0000-00000000a1b2}"), ("LogonId", "0xa1b2"),
            ("TerminalSessionId", 1), ("IntegrityLevel", "Medium"), ("Hashes", "SHA1=" + "0" * 40),
            ("ParentProcessGuid", pguid or pguid_of(ppid)), ("ParentProcessId", ppid), ("ParentImage", pimage),
            ("ParentCommandLine", pcmd), ("ParentUser", "host\\user")])

    def net(self, at, pid, image, dip, dport, host="-", sport=50001, protocol="tcp", guid=None):
        self.event(3, at, [
            ("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessGuid", guid or pguid_of(pid)), ("ProcessId", pid),
            ("Image", image), ("User", "host\\user"), ("Protocol", protocol), ("Initiated", "true"),
            ("SourceIsIpv6", "false"), ("SourceIp", "192.0.2.10"), ("SourceHostname", "host"),
            ("SourcePort", sport), ("SourcePortName", "-"), ("DestinationIsIpv6", "false"),
            ("DestinationIp", dip), ("DestinationHostname", host), ("DestinationPort", dport),
            ("DestinationPortName", "https" if dport == 443 else "-")])

    def file(self, at, pid, image, path, guid=None):
        self.event(11, at, [
            ("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessGuid", guid or pguid_of(pid)), ("ProcessId", pid),
            ("Image", image), ("TargetFilename", path), ("CreationUtcTime", DAY + at), ("User", "host\\user")])

    def end(self, at, pid, image):
        self.event(5, at, [("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessGuid", pguid_of(pid)),
                           ("ProcessId", pid), ("Image", image), ("User", "host\\user")])

    def query(self, at, pid, image, name, results):
        self.event(22, at, [("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessGuid", pguid_of(pid)),
                            ("ProcessId", pid), ("QueryName", name), ("QueryStatus", "0"),
                            ("QueryResults", results), ("Image", image), ("User", "host\\user")])

    def text(self):
        head = ("<!-- SYNTHETIC Sysmon export (not captured): host `host`, user `user`, documentation IPs;"
                " written by tests/fixtures/os/synthetic.py -->")
        return "\n".join([head] + self.lines) + "\n"


def pguid_of(pid, era=0):
    return "{8d1c0a51-0000-6732-%04x-%012x}" % (era, pid)


def _xml(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def agent_start(x, at="00.100"):
    x.proc(at, ROOT_PID, AGENT, '"%s"' % AGENT, 900, EXPLORER, "C:\\Windows\\Explorer.EXE")


def shell(x, at, pid, command):
    x.proc(at, pid, BASH, '"%s" -c -l "%s"' % (BASH, command), ROOT_PID, AGENT, '"%s"' % AGENT)


def child(x, at, pid, image, cmd, ppid, command):
    x.proc(at, pid, image, cmd, ppid, BASH, '"%s" -c -l "%s"' % (BASH, command))


def synthetic():
    """E2: one tree under 4100, and what must stay outside it."""
    x = Export()
    agent_start(x)
    x.net("01.000", ROOT_PID, AGENT, "203.0.113.7", 443, "api.example.com")
    x.net("01.500", ROOT_PID, AGENT, "203.0.113.9", 443, sport=50003, protocol="udp")
    x.query("01.900", ROOT_PID, AGENT, "api.example.com", "::ffff:203.0.113.7;")
    shell(x, "05.200", 4200, "ls -la | grep src")
    child(x, "05.300", 4210, LS, "ls -la", 4200, "ls -la | grep src")
    child(x, "05.310", 4211, GREP, "grep src", 4200, "ls -la | grep src")
    x.proc("09.000", 4300, RG, '"%s" --files C:\\work\\proj' % RG, ROOT_PID, AGENT, '"%s"' % AGENT)
    x.proc("10.000", 5100, NOTEPAD, "notepad.exe", 900, EXPLORER, "C:\\Windows\\Explorer.EXE",
           cwd="C:\\Users\\user\\")
    x.file("12.500", ROOT_PID, AGENT, "C:\\work\\proj\\notes.txt")
    x.end("20.000", 4210, LS)
    # pid 4210 is reused by a service: a new ProcessGuid, a parent outside the tree.
    x.proc("30.000", 4210, SVCHOST, "C:\\Windows\\system32\\svchost.exe -k netsvcs", 700, SERVICES,
           "C:\\Windows\\system32\\services.exe", cwd="C:\\Windows\\system32\\", guid=pguid_of(4210, 1),
           pguid=pguid_of(700, 1))
    x.file("31.000", 4210, SVCHOST, "C:\\Windows\\Temp\\svc.log", guid=pguid_of(4210, 1))
    x.event(1, "32.000", [("UtcTime", DAY + "32.000"), ("ProcessId", 4100)], provider="Microsoft-Windows-Other")
    shell(x, "39.950", 4500, "curl -s https://198.51.100.20/x")
    child(x, "40.000", 4400, CURL, "curl -s https://198.51.100.20/x", 4500, "curl -s https://198.51.100.20/x")
    x.net("40.200", 4400, CURL, "198.51.100.20", 443, sport=50002)
    return x.text()


def hook_line(seq, phase, at, tool="-", command=None, session="s-hook"):
    """A hook line in capture's shape (hashes of zeros; input_meta from common)."""
    from raqib.hooks import common
    rec = {"ts": "2026-11-03T09:00:%sZ" % at, "seq": seq, "session_id": session, "phase": phase, "tool": tool}
    if phase in ("pre", "post"):
        rec["tool_use_id"] = "toolu_%02d" % seq
        rec["input_sha256"] = "0" * 64
        tool_input = {"command": command} if tool == "Bash" else {"pattern": "x", "path": "C:\\work\\proj"}
        rec["input_meta"] = common.input_meta(tool, tool_input)
    if phase == "post":
        rec.update(output_sha256="0" * 64, output_meta={"scan": "full", "secret_kinds": []}, ok=True)
    rec.update(cwd="C:\\work\\proj", source="hook")
    return json.dumps(rec, separators=(",", ":"), ensure_ascii=True)


def call(seq, at, end, tool, command=None):
    return [hook_line(seq, "pre", at, tool, command), hook_line(seq, "post", end, tool, command)]


def cross_fixtures():
    """C-8: name -> (export text, hook lines). The os half is os-sysmon's."""
    out = {}
    # asked-not-done (positive): Bash `ls` at :05; the tree starts nothing in
    # [:05, :15], though Sysmon records it until :58.
    x = Export()
    agent_start(x)
    x.net("01.000", ROOT_PID, AGENT, "203.0.113.7", 443, "api.example.com")
    x.file("58.000", ROOT_PID, AGENT, "C:\\work\\proj\\notes.txt")
    out["asked-not-done"] = (x.text(), [hook_line(1, "session_start", "01.000")]
                             + call(2, "05.000", "05.500", "Bash", "ls")
                             + [hook_line(3, "stop", "06.000"), hook_line(4, "session_end", "20.000")])
    # done-not-asked (positive): `ls` is asked and done; a second shell the
    # agent started with no pre runs curl at :40.
    x = Export()
    agent_start(x)
    shell(x, "05.200", 4200, "ls")
    child(x, "05.300", 4210, LS, "ls", 4200, "ls")
    x.file("12.500", ROOT_PID, AGENT, "C:\\work\\proj\\notes.txt")
    shell(x, "39.950", 4500, "curl -s https://198.51.100.20/x")
    child(x, "40.000", 4400, CURL, "curl -s https://198.51.100.20/x", 4500, "curl -s https://198.51.100.20/x")
    x.net("40.200", 4400, CURL, "198.51.100.20", 443, sport=50002)
    out["done-not-asked"] = (x.text(), [hook_line(1, "session_start", "01.000")]
                             + call(2, "05.000", "05.600", "Bash", "ls")
                             + [hook_line(3, "stop", "50.000"), hook_line(4, "session_end", "58.000")])
    # matched (negative): `ls -la | grep src` asked; bash, ls and grep done,
    # each side of the pipeline under a bash the shell forked (MSYS, D-9).
    x = Export()
    agent_start(x)
    x.net("01.000", ROOT_PID, AGENT, "203.0.113.7", 443, "api.example.com")
    shell(x, "05.200", 4200, "ls -la | grep src")
    child(x, "05.250", 4205, BASH, '"%s" -c -l "ls -la | grep src"' % BASH, 4200, "ls -la | grep src")
    child(x, "05.260", 4206, BASH, '"%s" -c -l "ls -la | grep src"' % BASH, 4200, "ls -la | grep src")
    x.proc("05.300", 4210, LS, "ls -la", 4205, BASH, '"%s" -c -l "ls -la | grep src"' % BASH)
    x.proc("05.310", 4211, GREP, "grep src", 4206, BASH, '"%s" -c -l "ls -la | grep src"' % BASH)
    x.file("12.500", ROOT_PID, AGENT, "C:\\work\\proj\\notes.txt")
    out["matched"] = (x.text(), [hook_line(1, "session_start", "01.000")]
                      + call(2, "05.000", "05.600", "Bash", "ls -la | grep src")
                      + [hook_line(3, "stop", "06.000"), hook_line(4, "session_end", "30.000")])
    # rg-helper (negative, C-4): the agent's own rg for Grep, a direct child of
    # the root, is the agent's and not judged; the prototype flagged it.
    x = Export()
    agent_start(x)
    x.net("01.000", ROOT_PID, AGENT, "203.0.113.7", 443, "api.example.com")
    shell(x, "05.200", 4200, "ls")
    child(x, "05.300", 4210, LS, "ls", 4200, "ls")
    x.file("12.500", ROOT_PID, AGENT, "C:\\work\\proj\\notes.txt")
    x.proc("09.000", 4300, RG, '"%s" --files C:\\work\\proj' % RG, ROOT_PID, AGENT, '"%s"' % AGENT)
    out["rg-helper"] = (x.text(), [hook_line(1, "session_start", "01.000")]
                        + call(2, "05.000", "05.600", "Bash", "ls")
                        + call(3, "08.900", "09.300", "Grep")
                        + [hook_line(4, "stop", "10.000"), hook_line(5, "session_end", "30.000")])
    return out


def cross_log(export, hook):
    """The fixture trace: the hook lines, then os-sysmon's lines for export."""
    from raqib.hooks import os_sysmon
    lines, silence = os_sysmon.build(export, ROOT_PID, cwd="C:\\work\\proj")
    assert not silence, silence
    return "".join(line + "\n" for line in hook + lines)


# --- M7.8 (ADR-0007 P-1): the os-line fixtures of NET-TOOL and DESTRUCT-CMD -------------------------------
CMD = "C:\\Windows\\System32\\cmd.exe"
RM = "C:\\Program Files\\Git\\usr\\bin\\rm.exe"
VSSADMIN = "C:\\Windows\\System32\\vssadmin.exe"
BITSADMIN = "C:\\Windows\\System32\\bitsadmin.exe"
PLINK = "C:\\Program Files\\PuTTY\\plink.exe"
SSH = "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
GIT = "C:\\Program Files\\Git\\cmd\\git.exe"
GIT_SSH = "C:\\Program Files\\Git\\usr\\bin\\ssh.exe"
OUTER = "C:\\Users\\user\\AppData\\Local\\Programs\\outer\\outer.exe"
INNER = "C:\\Users\\user\\AppData\\Local\\Programs\\inner\\inner.exe"
NET_PROGRAMS = ("curl", "bitsadmin", "plink", "ssh")   # what the NET-TOOL positive must cite
DESTRUCT_PROGRAMS = ("rm", "vssadmin")             # what the DESTRUCT-CMD positive must cite
OS_CWD = "C:\\work\\proj"
DESKTOP_CWD = "C:\\Users\\user"


def destruct_windows():
    """Root 4600: Git's bash runs rm; cmd runs vssadmin (SYNTHETIC)."""
    x = Export(first_record=71001)
    x.proc("00.100", 4600, AGENT, '"%s"' % AGENT, 900, EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.net("01.000", 4600, AGENT, "203.0.113.7", 443, "api.example.com")
    x.proc("05.200", 4610, BASH, '"%s" -c -l "rm -rf build"' % BASH, 4600, AGENT, '"%s"' % AGENT)
    x.proc("05.300", 4620, RM, "rm -rf build", 4610, BASH, '"%s" -c -l "rm -rf build"' % BASH)
    x.proc("07.000", 4630, CMD, 'cmd.exe /c "vssadmin delete shadows /all /quiet"', 4600, AGENT, '"%s"' % AGENT)
    x.proc("07.100", 4640, VSSADMIN, "vssadmin delete shadows /all /quiet", 4630, CMD,
           'cmd.exe /c "vssadmin delete shadows /all /quiet"')
    x.file("08.000", 4600, AGENT, "C:\\work\\proj\\notes.txt")
    return x.text()


def net_windows():
    """Root 4700: cmd runs bitsadmin; the agent runs plink (SYNTHETIC)."""
    x = Export(first_record=72001)
    x.proc("00.100", 4700, AGENT, '"%s"' % AGENT, 900, EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.net("01.000", 4700, AGENT, "203.0.113.7", 443, "api.example.com")
    x.proc("05.200", 4710, CMD, 'cmd.exe /c "bitsadmin /transfer j https://198.51.100.20/x C:\\work\\x"', 4700,
           AGENT, '"%s"' % AGENT)
    x.proc("05.300", 4720, BITSADMIN, "bitsadmin /transfer j https://198.51.100.20/x C:\\work\\x", 4710, CMD,
           'cmd.exe /c "bitsadmin /transfer j https://198.51.100.20/x C:\\work\\x"')
    x.proc("09.000", 4730, PLINK, '"%s" user@198.51.100.21' % PLINK, 4700, AGENT, '"%s"' % AGENT)
    x.file("10.000", 4700, AGENT, "C:\\work\\proj\\notes.txt")
    # M7.8 REDO R-7: ssh under cmd is NET-TOOL's (git-ssh-windows holds ssh under git, which is not)
    x.proc("11.000", 4740, CMD, 'cmd.exe /c "ssh user@198.51.100.22"', 4700, AGENT, '"%s"' % AGENT)
    x.proc("11.100", 4750, SSH, "ssh user@198.51.100.22", 4740, CMD, 'cmd.exe /c "ssh user@198.51.100.22"')
    return x.text()


def git_ssh_windows():
    """Root 4800 (M7.8 REDO R-7): git over SSH - git.exe starts Git's ssh.exe for a fetch; git is left out of
    NET-TOOL on every source, so its ssh is too (SYNTHETIC)."""
    x = Export(first_record=75001)
    x.proc("00.100", 4800, AGENT, '"%s"' % AGENT, 900, EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.net("01.000", 4800, AGENT, "203.0.113.7", 443, "api.example.com")
    x.proc("05.200", 4810, GIT, '"%s" fetch origin' % GIT, 4800, AGENT, '"%s"' % AGENT)
    x.proc("05.300", 4820, GIT_SSH, "ssh git@198.51.100.23 \"git-upload-pack 'proj.git'\"", 4810, GIT,
           '"%s" fetch origin' % GIT)
    return x.text()


def nested_windows():
    """Roots 6100 and 6200 (M7.8 REDO R-3): two nested trees, outer.exe -> inner.exe -> cmd.exe -> curl.exe;
    each tree's os source reads the curl, at depth 3 under the outer root and 2 under the inner (SYNTHETIC)."""
    x = Export(first_record=76001)
    x.proc("00.100", 6100, OUTER, '"%s"' % OUTER, 900, EXPLORER, "C:\\Windows\\Explorer.EXE")
    x.proc("00.500", 6200, INNER, '"%s"' % INNER, 6100, OUTER, '"%s"' % OUTER)
    x.proc("05.200", 6210, CMD, 'cmd.exe /c "curl -s https://198.51.100.24/x"', 6200, INNER, '"%s"' % INNER)
    x.proc("05.300", 6220, CURL, "curl -s https://198.51.100.24/x", 6210, CMD,
           'cmd.exe /c "curl -s https://198.51.100.24/x"')
    return x.text()


def win_process_rows(directory):
    """Every Win32_Process row of a discover export directory's win-process
    files (sample order), once per (ProcessId, CreationDate)."""
    rows, seen = [], set()
    names = sorted(n for n in os.listdir(directory) if n.startswith("win-process"))
    for name in names:
        with open(os.path.join(directory, name), encoding="utf-8") as f:
            text = "".join(line for line in f if not line.startswith("#"))
        for row in csv.DictReader(io.StringIO(text)):
            mark = (row["ProcessId"], row["CreationDate"])
            if mark not in seen:
                seen.add(mark)
                rows.append(row)
    return rows


def as_os_lines_export(directory, first_record):
    """A discover export READ AS OS LINES: each process row with an image
    path is the event 1 Sysmon would have logged at its creation (no
    ProcessGuid: the pid decides; times 0.1 s apart, made up)."""
    rows = win_process_rows(directory)
    image = {r["ProcessId"]: r["ExecutablePath"] for r in rows if r["ExecutablePath"]}
    command = {r["ProcessId"]: r["CommandLine"] for r in rows}
    x = Export(first_record=first_record)
    for i, r in enumerate(rr for rr in rows if rr["ExecutablePath"]):
        at = "%02d.%03d" % ((i // 10) % 60, (i % 10) * 100)
        x.event(1, at, [
            ("RuleName", "-"), ("UtcTime", DAY + at), ("ProcessId", r["ProcessId"]), ("Image", r["ExecutablePath"]),
            ("CommandLine", r["CommandLine"] or "-"), ("CurrentDirectory", DESKTOP_CWD + "\\"),
            ("User", "host\\user"), ("ParentProcessId", r["ParentProcessId"]),
            ("ParentImage", image.get(r["ParentProcessId"], "-")),
            ("ParentCommandLine", command.get(r["ParentProcessId"]) or "-")])
    return x.text()


def os_fixture_exports():
    """name -> (export text, the roots read, cwd)."""
    discover = os.path.join(ROOT, "tests", "fixtures", "discover")
    return {
        "sysmon-synthetic": (synthetic(), (ROOT_PID,), OS_CWD),
        "net-windows": (net_windows(), (4700,), OS_CWD),
        "destruct-windows": (destruct_windows(), (4600,), OS_CWD),
        # REDO (P6 note): the whole desktop once, under explorer; code 6050's subtree is in it
        "benign-windows-desktop": (as_os_lines_export(os.path.join(discover, "benign", "windows-desktop"), 73001),
                                   (5100,), DESKTOP_CWD),
        "git-ssh-windows": (git_ssh_windows(), (4800,), OS_CWD),
        "nested-windows": (nested_windows(), (6100, 6200), OS_CWD),
        "kimi-two-samples": (as_os_lines_export(os.path.join(discover, "kimi", "two-samples"), 74001), (10728,),
                             DESKTOP_CWD),
    }


OS_RULE_FIXTURES = {   # rule fixture -> the exports whose os lines it holds, and what a positive must cite
    "NET-TOOL/positive-os-process.json": (("sysmon-synthetic", "net-windows"), NET_PROGRAMS),
    "NET-TOOL/negative-os-process.json": (("benign-windows-desktop", "kimi-two-samples", "destruct-windows",
                                           "git-ssh-windows"), None),
    "DESTRUCT-CMD/positive-os-process.json": (("destruct-windows",), DESTRUCT_PROGRAMS),
    "DESTRUCT-CMD/negative-os-process.json": (("benign-windows-desktop", "kimi-two-samples", "sysmon-synthetic",
                                               "net-windows", "git-ssh-windows"), None),
}


def os_rule_fixture(names, cite, exports):
    """The fixture's text: os-sysmon's lines of each export's roots; a
    positive's expect_seq is the seq of every process line whose image is
    one of `cite` (read from the lines, not from the rule)."""
    from raqib.hooks import os_sysmon
    lines = []
    for name in names:
        text, roots, cwd = exports[name]
        for root in roots:
            got, _ = os_sysmon.build(text, root, cwd=cwd)
            lines += [json.loads(line) for line in got]
    doc = {"lines": lines}
    if cite:
        doc["expect_seq"] = sorted({r["seq"] for r in lines if r["phase"] == "pre" and r["tool"] == "process"
                                    and r["input_meta"].get("image") in cite})
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def files():
    """Relative path -> bytes, everything this script writes."""
    out = {"tests/fixtures/os/sysmon-synthetic.xml": synthetic().encode("ascii")}
    for name, (export, hook) in cross_fixtures().items():
        out["tests/fixtures/cross/%s.sysmon.xml" % name] = export.encode("ascii")
        out["tests/fixtures/cross/%s.log" % name] = cross_log(export, hook).encode("ascii")
    exports = os_fixture_exports()   # M7.8
    for name, (text, _, _) in exports.items():
        if name != "sysmon-synthetic":
            out["tests/fixtures/os/%s.sysmon.xml" % name] = text.encode("ascii")
    for rel, (names, cite) in OS_RULE_FIXTURES.items():
        out["tests/fixtures/rules/%s" % rel] = os_rule_fixture(names, cite, exports).encode("ascii")
    return out


if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    for rel, data in files().items():
        path = os.path.join(ROOT, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        print(rel)
