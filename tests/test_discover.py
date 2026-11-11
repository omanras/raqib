"""M5.0 agent discovery (HANDOFF.md E1-E6, ADR-0004 with Amendment B).
Parsers are tested on one fixture file each: tests/fixtures/discover/linux/
was captured in the builder's container by capture.py there (REAL,
identifiers redacted); tests/fixtures/discover/windows/ is SYNTHETIC but
shaped like the PowerShell and wevtutil output. The small texts built in
this file are test-made."""
import ast
import io
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "discover"
LINUX, WINDOWS = FIX / "linux", FIX / "windows"
CATALOG = discover.load_catalog()
README = (ROOT / "README.md").read_text(encoding="utf-8")
from readme_text import GUIDE  # noqa: E402  (M9.2: docs/GUIDE.md holds what README.md no longer does)
AT = "2026-11-02T10:00:00.000Z"
NET_HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def text_of(path):
    return discover.decode(Path(path).read_bytes())


def lines_of(path):
    return [x[:-1] if x.endswith("\r") else x for x in text_of(path).split("\n")]


def parsed(kind, path):
    return discover.PARSERS[kind](text_of(path), kind)


def from_dir(directory, window=None, catalog=CATALOG):
    texts, holes = discover.read_dir(str(directory))
    return discover.run(texts, catalog, window=window, holes=holes)


def inv_of(catalog=CATALOG, errors=None, **texts):
    errors = errors or {}
    return discover.run({k.replace("_", "-"): ("<%s>" % k, v, errors.get(k)) for k, v in texts.items()}, catalog)


def proc(pid, ppid, argv, env=None, cwd="/w", at=AT, sockets=None, exe=None, unread=None):
    obj = {"pid": pid, "ppid": ppid, "name": argv[0].rsplit("/", 1)[-1][:15], "argv": argv,
           "cwd": cwd, "env_keys": env, "sockets": sockets, "at": at}
    if exe is not None or unread is not None:
        obj.update(exe=exe, unread=unread or [])
    return json.dumps(obj)


def procs(*lines, self_pid=None, **counts):
    return "\n".join([json.dumps(dict({"snapshot": AT, "self": self_pid}, **counts))] + list(lines)) + "\n"


def ss(*rows, listen=()):
    out = ["# at %s (ss -tnp)" % AT, "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"]
    out += ['LISTEN 0 128 %s 0.0.0.0:* users:(("%s",pid=%d,fd=3))' % row for row in listen]
    out += ['ESTAB 0 0 %s %s users:(("%s",pid=%d,fd=9))' % row for row in rows]
    return "\n".join(out) + "\n"


def net_row(n, local, remote, state, inode):
    return "  %2d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000" % (
        n, local, remote, state, inode)


def raqib(*argv):
    out = io.StringIO()
    code = cli.main([str(a) for a in argv], out=out)
    return code, out.getvalue()


def can_symlink(tmp_path):
    try:
        os.symlink("socket:[1]", str(tmp_path / "probe"))
        return True
    except (OSError, NotImplementedError):
        return False


def fake_proc(root, rows, net=None, sockets=None):
    """A /proc tree: rows of (pid, ppid, name, argv bytes); net: /proc/net/tcp
    text; sockets: {pid: [inode]} as fd links."""
    for pid, ppid, name, argv in rows:
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "status").write_text("Name:\t%s\nPPid:\t%d\n" % (name, ppid))
        (d / "cmdline").write_bytes(argv)
        (d / "fd").mkdir()
        for i, inode in enumerate((sockets or {}).get(pid, [])):
            os.symlink("socket:[%d]" % inode, str(d / "fd" / str(3 + i)))
    if net is not None:
        (root / "net").mkdir(parents=True)
        (root / "net" / "tcp").write_text(net)


# --- E1: parsers, text in -> records out ---------------------------------------

def test_e1_fixtures_say_real_or_synthetic():
    assert "REAL, identifiers redacted" in lines_of(LINUX / "proc.txt")[0]
    for name in ("proc-net.txt", "ss.txt", "footprints.txt"):
        assert "REAL (not synthetic)" in lines_of(LINUX / name)[0], name
    for name in ("win-process.csv", "win-tcp.csv", "win-dns.csv", "sysmon.xml", "footprints.txt"):
        assert "SYNTHETIC (not captured from a machine)" in lines_of(WINDOWS / name)[0], name
    assert {p.name for p in LINUX.iterdir() if p.name != "__pycache__"} == {
        "proc.txt", "proc-net.txt", "ss.txt", "footprints.txt", "capture.py"}
    assert {p.name for p in WINDOWS.iterdir()} == {"win-process.csv", "win-tcp.csv", "win-dns.csv",
                                                    "sysmon.xml", "footprints.txt"}


def test_e1_proc_fixture_real_container_snapshot():
    records, problems = parsed("proc", LINUX / "proc.txt")
    assert problems == []
    (snap,) = [r for r in records if r["kind"] == "snapshot"]
    assert (snap["self"], discover.iso(snap["ts"]), snap["kernel_parent"]) == (7652, "2026-11-02T15:38:29.201Z", 2)
    assert snap["counts"] == {"gone_while_read": 0, "unreadable": 0, "kernel_threads": 56}
    by_pid = {r["pid"]: r for r in records if r["kind"] == "proc"}
    assert sorted(by_pid) == [1, 66, 67, 87, 95, 7647, 7649, 7650, 7652]
    claude = by_pid[95]
    assert (claude["ppid"], claude["image"], claude["exe"], claude["cwd"], claude["line"]) == (
        87, "claude", "/opt/claude-code/bin/claude", "/home/user", 8)   # M7.6d: the sandbox home redacted
    assert 87504 in claude["sockets"] and by_pid[87]["sockets"][:2] == [797, 805]
    # D-3: pid 1's fd links could not be read: unknown (null), never []
    assert (by_pid[1]["sockets"], by_pid[1]["unread"]) == (None, ["cwd", "environ", "fd"])
    assert by_pid[87]["image"] == "environment-manager"  # argv[0], not the 15-char status Name
    assert (by_pid[7650]["image"], by_pid[7650]["ppid"]) == ("git", 7647)
    for r in by_pid.values():
        assert r["env_keys"] is None or all(discover.ENV_NAME.match(k) for k in r["env_keys"])
    for obj in (json.loads(x) for x in lines_of(LINUX / "proc.txt") if x.startswith("{")):
        assert all("=" not in k for k in obj.get("env_keys") or [])   # names, never NAME=value


def test_b9_real_proc_fixture_is_redacted_and_its_capture_script_is_in_the_tree():
    text = text_of(LINUX / "proc.txt")
    assert set(re.findall(r"cse_[A-Za-z0-9]+", text)) == {"cse_REDACTED"}
    assert not re.search(r"/tmp/claude-", text)
    assert not re.search(r"(?:cse|session)_[A-Za-z0-9]{12,}", text.replace("cse_REDACTED", ""))
    assert '"--session", "cse_REDACTED"' in text
    assert not re.search(r"snapshot-bash-[0-9]", text) and "shell-snapshots/snapshot-REDACTED.sh" in text   # D-6
    claude = [json.loads(x) for x in text.splitlines() if '"pid": 95,' in x][0]
    assert "ANTHROPIC_BASE_URL" in claude["env_keys"]                  # names stay (B-9)
    script = (LINUX / "capture.py").read_text(encoding="utf-8")
    assert "def redact" in script and "snapshot_proc" in script and "read_proc_net" in script
    assert "SHELL_SNAPSHOT" in script and "read and dropped" in script


def test_e1_proc_file_readers_on_real_shapes():
    status = "Name:\tclaude\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t95\nNgid:\t0\nPid:\t95\nPPid:\t87\n"
    assert discover.status_fields(status)["PPid"] == "87"
    assert discover.cmdline_args(b"/opt/claude-code/bin/claude\0--preload\0/x.sock\0") == [
        "/opt/claude-code/bin/claude", "--preload", "/x.sock"]
    assert discover.cmdline_args(b"") == []
    names = discover.environ_keys(b"HOME=/root\0ANTHROPIC_API_KEY=value-never-kept\0PATH=/usr/bin\0=x\0")
    assert names == ["ANTHROPIC_API_KEY", "HOME", "PATH"]
    assert "value-never-kept" not in json.dumps(names)


def _proc_tree(tmp_path, kthreadd="kthreadd"):
    root = tmp_path / "proc"
    for pid, ppid, name, argv, env in ((42, 1, "agent", b"/usr/bin/agent\0--x\0",
                                        b"OPENAI_API_KEY=value-never-kept\0HOME=/h\0"),
                                       (7, 2, "kworker", b"", b""), (2, 0, kthreadd, b"", b"")):
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "status").write_text("Name:\t%s\nPPid:\t%d\n" % (name, ppid))
        (d / "cmdline").write_bytes(argv)
        (d / "environ").write_bytes(env)
    (root / "43").mkdir()                     # ended while read: no status
    (root / "44" / "status").mkdir(parents=True)   # status cannot be read
    (root / "self").mkdir()                   # not a pid
    return root


def test_e1_snapshot_proc_reads_a_proc_tree_and_drops_env_values(tmp_path):
    root = _proc_tree(tmp_path)
    linked = can_symlink(tmp_path)
    if linked:
        os.symlink(str(tmp_path), str(root / "42" / "cwd"))
        (root / "42" / "fd").mkdir()
        os.symlink("socket:[777]", str(root / "42" / "fd" / "3"))
        os.symlink("/dev/null", str(root / "42" / "fd" / "4"))
    text = discover.snapshot_proc(str(root), AT, 99)
    assert "value-never-kept" not in text and text.isascii()
    meta = json.loads(text.splitlines()[0])
    assert (meta["self"], meta["processes"], meta["kernel_threads"], meta["kernel_parent"],
            meta["gone_while_read"], meta["unreadable"]) == (99, 1, 2, 2, 1, 1)
    records, problems = discover.parse_proc(text)
    (p,) = [r for r in records if r["kind"] == "proc"]
    assert problems == [] and p["pid"] == 42 and p["argv"] == ["/usr/bin/agent", "--x"]
    assert p["env_keys"] == ["HOME", "OPENAI_API_KEY"]
    if linked and sys.platform != "win32":
        assert (p["cwd"], p["sockets"]) == (str(tmp_path), [777])
    else:
        assert p["sockets"] is None or p["sockets"] == [777]


def test_b3_pid_2_is_dropped_only_when_it_is_kthreadd(tmp_path):
    text = discover.snapshot_proc(str(_proc_tree(tmp_path, kthreadd="init")), AT, 99)
    meta = json.loads(text.splitlines()[0])
    assert (meta["kernel_parent"], meta["kernel_threads"], meta["processes"]) == (None, 0, 3)


def test_e1_proc_bad_lines_are_problems():
    records, problems = discover.parse_proc('# c\n{"pid": "x"}\nnot json\n[1]\n{"pid": 1, "sockets": ["a"]}\n')
    assert records == [] and [p["line"] for p in problems] == [2, 3, 4, 5]


def test_b1_proc_net_fixture_real_container_sockets():
    records, problems = parsed("proc-net", LINUX / "proc-net.txt")
    assert problems == []
    conns = [r for r in records if r["kind"] == "conn"]
    holes = [r for r in records if r["kind"] == "hole"]
    assert len(conns) == 16
    assert [(h["line"], h["note"].endswith("no IPv6 table")) for h in holes] == [(20, True)]
    assert sorted({r["state"] for r in conns}) == ["ESTABLISHED", "LISTEN"]
    first = conns[0]
    assert (first["laddr"], first["lport"], first["state"], first["inode"], first["line"]) == (
        "127.0.0.1", 44061, "LISTEN", 1214, 4)
    est = [r for r in conns if r["state"] == "ESTABLISHED"]
    assert len(est) == 13 and {(r["laddr"], r["raddr"], r["rport"]) for r in est} == {
        ("192.0.2.2", "160.79.104.10", 443)}
    assert {(r["direction"], r["basis"], r["pid"]) for r in est} == {("out", "listen", None)}
    assert all(discover.iso(r["ts"]) == "2026-11-02T15:38:29.201Z" for r in conns)


def test_b1_proc_net_ipv6_mapped_and_bad_rows():
    text = "\n".join([
        "# at %s (/proc/net/tcp6)" % AT, NET_HEAD,
        net_row(0, "00000000000000000000000001000000:2CAA", "00000000000000000000000000000000:0000", "0A", 5),
        net_row(1, "0000000000000000FFFF00000500000A:9C40", "0000000000000000FFFF00000A684FA0:01BB", "01", 6),
        net_row(2, "0500000A:9C41", "0A684FA0:01BB", "99", 7),
        "   3: garbage", ""])
    records, problems = discover.parse_proc_net(text)
    assert [(r["laddr"], r["lport"], r["raddr"], r["state"]) for r in records] == [
        ("::1", 11434, "::", "LISTEN"), ("10.0.0.5", 40000, "160.79.104.10", "ESTABLISHED")]
    assert [p["line"] for p in problems] == [5, 6]


def test_e1_ss_fixture_real_container_sockets():
    records, problems = parsed("ss", LINUX / "ss.txt")
    assert problems == [] and len(records) == 13
    assert {r["pid"] for r in records} == {87, 95}
    assert {(r["state"], r["raddr"], r["rport"], r["direction"], r["basis"]) for r in records} == {
        ("ESTABLISHED", "160.79.104.10", 443, "out", "ports")}
    assert all(discover.iso(r["ts"]) == "2026-11-02T15:38:29.201Z" for r in records)
    assert records[0]["line"] == 4 and records[0]["comm"] == "environment-man"


def test_e1_ss_listen_ipv6_netid_and_bad_rows():
    text = "\n".join([
        "State  Recv-Q Send-Q Local Address:Port   Peer Address:PortProcess",
        'LISTEN 0      512        127.0.0.1:44061       0.0.0.0:*    users:(("claude",pid=95,fd=12))',
        "LISTEN 0      128          0.0.0.0:2024        0.0.0.0:*",
        'ESTAB  0      0          127.0.0.1:44061     127.0.0.1:50000 users:(("claude",pid=95,fd=30))',
        'ESTAB  0      0      [::ffff:10.0.0.5]:50001 [2607:6bb0::1]:443 users:(("a",pid=5,fd=3),("b",pid=6,fd=3))',
        "ESTAB  0      0      nonsense",
        "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
        "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*",
        'tcp ESTAB 0 0 [fe80::1%eth0]:40000 [fe80::2%eth0]:22 users:(("ssh",pid=8,fd=3))', ""])
    records, problems = discover.parse_ss(text)
    assert [p["line"] for p in problems] == [6]
    est = [r for r in records if r["state"] == "ESTABLISHED"]
    assert [(r["pid"], r["laddr"], r["raddr"], r["direction"], r["basis"]) for r in est] == [
        (95, "127.0.0.1", "127.0.0.1", "in", "listen"),
        (5, "10.0.0.5", "2607:6bb0::1", "out", "listen"), (6, "10.0.0.5", "2607:6bb0::1", "out", "listen"),
        (8, "fe80::1", "fe80::2", "out", "listen")]


def test_e1_win_process_fixture():
    records, problems = parsed("win-process", WINDOWS / "win-process.csv")
    assert problems == [] and len(records) == 16
    by_pid = {r["pid"]: r for r in records}
    assert (by_pid[2100]["image"], by_pid[2100]["ppid"], by_pid[2100]["line"]) == ("claude", 1000, 8)
    assert by_pid[2240]["argv"] == ["C:\\Program Files\\Git\\usr\\bin\\bash.exe", "-c", "-l", "git status --short"]
    assert by_pid[4]["exe"] is None and by_pid[4]["argv"] == []
    assert by_pid[6020]["image"] == "node" and by_pid[3410]["image"] == "cmd"


def test_e1_win_tcp_fixture():
    records, problems = parsed("win-tcp", WINDOWS / "win-tcp.csv")
    assert problems == [] and len(records) == 12
    assert {r["state"] for r in records} == {"LISTEN", "ESTABLISHED", "TIME-WAIT", "BOUND"}
    by = {(r["pid"], r["lport"]): r for r in records if r["state"] == "ESTABLISHED"}
    assert (by[(5000, 11434)]["direction"], by[(3300, 50150)]["direction"]) == ("in", "out")
    assert {r["basis"] for r in by.values()} == {"listen"}
    assert records[2]["laddr"] == "127.0.0.1" and records[1]["laddr"] == "::"


def test_e1_win_dns_fixture():
    records, problems = parsed("win-dns", WINDOWS / "win-dns.csv")
    assert problems == [] and len(records) == 5   # the two CNAME rows carry no IP
    by_ip = {r["ips"][0]: r["names"] for r in records}
    assert by_ip["104.18.33.45"] == ["api.openai.com", "api.openai.com.cdn.cloudflare.net"]
    assert by_ip["160.79.104.10"] == ["api.anthropic.com"]


def test_e1_sysmon_fixture():
    records, problems = parsed("sysmon", WINDOWS / "sysmon.xml")
    assert problems == []
    kinds = {}
    for r in records:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    # 4 process creates (each also names its parent), 5 tcp connects and 1 udp, 2 queries,
    # 4 file creates; every other event also yields its Image as a process (8 + 12 = 20).
    assert kinds == {"proc": 20, "conn": 5, "dns": 2, "file": 4}
    conn = {(r["pid"], r["rport"]): r for r in records if r["kind"] == "conn"}
    assert conn[(5000, 50150)]["direction"] == "in" and conn[(5000, 50150)]["lport"] == 11434
    assert conn[(3300, 443)]["direction"] == "out" and conn[(3300, 443)]["basis"] == "initiated"
    dns = [r for r in records if r["kind"] == "dns" and r["pid"] == 3300][0]
    assert dns["ips"] == ["104.18.33.45", "172.66.0.243"] and dns["names"] == ["api.openai.com"]
    create = [r for r in records if r["kind"] == "proc" and r["pid"] == 3420 and not r.get("derived")][0]
    assert (create["ppid"], create["image"], create["line"]) == (3410, "python", 8)
    assert discover.iso(create["ts"]) == "2026-11-01T05:14:10.520Z"


def test_e1_sysmon_multi_line_events_bad_events_and_other_providers():
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    good = ("<Event xmlns='%s'>\n <System>\n  <Provider Name='Microsoft-Windows-Sysmon'/>\n  <EventID>11</EventID>\n"
            " </System>\n <EventData>\n  <Data Name='UtcTime'>2026-11-01 05:00:00.000</Data>\n"
            "  <Data Name='ProcessId'>9</Data>\n  <Data Name='TargetFilename'>C:\\w\\a.txt</Data>\n"
            " </EventData>\n</Event>\n" % ns)
    other = "<Event xmlns='%s'><System><Provider Name='Other'/><EventID>1</EventID></System></Event>\n" % ns
    doctype = "<Event><!DOCTYPE x [<!ENTITY a 'b'>]><System/></Event>\n"
    broken = "<Event xmlns='%s'><System><EventID>1</System></Event>\n" % ns
    cut = "<Event xmlns='%s'><System>\n" % ns
    records, problems = discover.parse_sysmon("<Events>\n" + good + other + doctype + broken + cut + "</Events>\n")
    assert [(r["kind"], r["line"]) for r in records] == [("proc", 2), ("file", 2)]
    assert [p["line"] for p in problems] == [14, 15, 16]   # DOCTYPE, malformed, no </Event>


def test_e1_csv_utf16_bom_numeric_codes_and_missing_columns():
    data = text_of(WINDOWS / "win-tcp.csv").encode("utf-16-le")
    assert discover.parse_win_tcp(discover.decode(b"\xff\xfe" + data))[0] == parsed("win-tcp", WINDOWS / "win-tcp.csv")[0]
    text = '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess"\n' \
           '"10.0.0.5","50000","1.2.3.4","443","5","77"\n"x","y"\n'
    records, problems = discover.parse_win_tcp(text)
    assert [(r["state"], r["direction"]) for r in records] == [("ESTABLISHED", "out")]
    assert [p["line"] for p in problems] == [3]
    dns = '"Entry","Name","Type","Data"\n"a.example","a.example","1","10.0.0.9"\n"b","b","28","not-an-ip"\n'
    records, problems = discover.parse_win_dns(dns)
    assert records[0]["ips"] == ["10.0.0.9"] and [p["line"] for p in problems] == [3]
    _, problems = discover.parse_win_process('"Name","Id"\n"x","1"\n')
    assert "no column ProcessId, ParentProcessId" in problems[0]["reason"]
    _, problems = discover.parse_win_process("")
    assert "no CSV header" in problems[0]["reason"]


# --- E2: endpoints.yaml ----------------------------------------------------------

def test_e2_catalog_is_a_signature_with_evasion():
    assert CATALOG["kind"] == "signature" and len(CATALOG["evasion"]) >= 3
    hosts = {h["match"] for h in CATALOG["hosts"]}
    assert {"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"} <= hosts
    assert {p["port"] for p in CATALOG["ports"]} >= {11434, 1234}
    assert {f["match"] for f in CATALOG["footprints"]} >= {".claude", ".kimi", ".codex", ".gemini", ".cursor",
                                                          ".aider*"}
    assert CATALOG["env"] == ["*_API_KEY"]
    # ADR-0004: the first field test ran with no prior knowledge of Kimi's endpoints (B-10, field note
    # 2026-11-02). M5.0b lists them for E2's recent talk; a blind run uses a --catalog copy without them.
    assert {h["match"] for h in CATALOG["hosts"] if h["vendor"] == "moonshot"} == {
        "api.moonshot.ai", "api.moonshot.cn", "api.kimi.com"}
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    assert "B-10" in text and "--catalog copy without them" in " ".join(text.split())


def test_b4_b6_b7_catalog_evasions_acts_and_proxy_capable():
    evasion = " ".join(CATALOG["evasion"]).lower()
    for word in ("quic", "udp", "unix-socket", "reparenting", "sibling"):
        assert word in evasion, word
    assert {"sh", "bash", "cmd", "powershell", "python*", "node", "git"} <= set(CATALOG["acts"])
    acts_evasion = " ".join(CATALOG["acts_evasion"]).lower()
    assert "rename-by-copy" in acts_evasion and "custom shell" in acts_evasion and "not listed" in acts_evasion
    assert CATALOG["proxy_capable"] == ["codex", "aider"] and CATALOG["hook_images"] == ["claude"]
    assert CATALOG["hook_not_paths"] == ["AnthropicClaude", "Claude.app", "claude-desktop"]
    assert CATALOG["hook_evasion"] and CATALOG["proxy_evasion"]                              # D-5


@pytest.mark.parametrize("change, error", [
    ((r"kind: signature", "kind: anchor"), "kind: must be signature"),
    ((r"\nevasion:\n(  - .*\n)+", "\nevasion: []\n"), "evasion: a signature must list"),
    ((r"\nevasion:\n(  - .*\n)+", "\n"), "evasion: missing"),
    ((r"env:\n", "extra: 1\nenv:\n"), "extra: unknown field"),
    ((r"cidr: 160\.79\.104\.0/23", "cidr: 160.79.104.0/33"), "networks[0].cidr"),
    ((r"match: \.claude,", "match: '*/.claude',"), "footprints[0].match"),
    ((r"port: 11434", "port: 70000"), "ports[0].port"),
    ((r"match: api\.anthropic\.com,", "match: API.anthropic.com,"), "hosts[0].match"),
    ((r"  evasion:\n(    - .*\n)+", ""), "acts.evasion: the act names are a signature"),
    ((r"acts:\n  names: .*\n", "acts:\n  names: []\n"), "acts.names"),
    ((r"\nhandoff:\n", "\nhand_off:\n"), "handoff: missing"),
    ((r"    evasion:\n(      - .*\n)+(?=  # proxy)", ""), "handoff.hook: must hold"),
    ((r"    evasion:\n(      - .*\n)+(?=  # proxy)", "    evasion: []\n"), "handoff.hook.evasion"),
    ((r"    proxy_capable: .*\n    evasion:\n(      - .*\n)+", "    proxy_capable: [codex]\n    evasion: []\n"),
     "handoff.proxy.evasion"),
    ((r"proxy_capable: \[codex", "proxy_capable: [Codex"), "must be lower-case"),
])
def test_e2_catalog_rejects_what_it_cannot_read(tmp_path, change, error):
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    changed = re.sub(change[0], lambda m: change[1], text, count=1)
    assert changed != text
    path = tmp_path / "endpoints.yaml"
    path.write_text(changed, encoding="utf-8")
    with pytest.raises(discover.CatalogError) as exc:
        discover.load_catalog(str(path))
    assert error in str(exc.value)


def test_e2_catalog_subset_agrees_with_pyyaml():
    yaml = pytest.importorskip("yaml")
    from raqib.rules import yamlite
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    assert yamlite.loads(text) == yaml.safe_load(text)


# --- E3: the tree anchor ("talks + has a child", B-6) ------------------------------

def test_e3_linux_fixture_finds_claude_code_by_its_tree():
    inv = from_dir(LINUX)
    by = {c["pid"]: c for c in inv["candidates"]}
    assert sorted(by) == [87, 95]
    outer, claude = by[87], by[95]
    assert [(a["pid"], a["listed"]) for a in outer["acts"]] == [(95, False)]   # its child claude, unlisted
    assert (claude["inside"], claude["image"]) == (outer["id"], "claude")
    acts = {a["pid"]: a for a in claude["acts"]}
    assert sorted(acts) == [7647, 7649, 7650]     # bash, sleep and git below it; the reader 7652 is not
    assert (acts[7647]["listed"], acts[7649]["listed"], acts[7650]["listed"]) == (True, False, True)
    assert acts[7647]["reader_ancestor"] and acts[7650]["via"] == [7647]
    assert [t["pid"] for t in claude["talking_ancestors"]] == [87]
    (t,) = claude["talks"]
    assert (t["remote"], t["lines"], t["endpoint"][0]["vendor"]) == ("160.79.104.10:443", 6, "anthropic")
    assert {c["src"] for c in t["cites"]} == {"proc-net"}
    assert "ss" not in {s["name"] for s in inv["sources"]}        # R10: ss.txt beside proc-net.txt is ignored
    assert any("ss.txt ignored" in h for h in inv["holes"])
    assert inv["complete"] and inv["incomplete"] == []


def test_e3_windows_fixture_candidates_and_non_candidates():
    inv = from_dir(WINDOWS)
    by = {c["pid"]: c for c in inv["candidates"]}
    assert sorted(by) == [2100, 3300, 4100, 7000]   # claude.exe, nimbus.exe, msedge.exe, scribe.exe
    assert sorted((a["how"], a["pid"]) for a in by[3300]["acts"]) == [
        ("file-write", 3300), ("process", 3410), ("process", 3420)]
    assert [a["path"] for a in by[7000]["acts"]] == ["C:\\work\\notes\\draft.md"]
    assert by[7000]["talks"][0]["endpoint"] == []  # a private endpoint: the anchor alone finds it
    assert [(a["pid"], a["listed"]) for a in by[4100]["acts"]] == [(4120, False)]   # a browser renderer
    assert by[4100]["listed_acts"] == 0 and by[3300]["listed_acts"] == 2
    # ollama (inbound only) and node/gemini (talks, no child) are not candidates
    assert not {5000, 6020} & set(by)


def test_e3_the_anchor_reads_no_catalog():
    empty = dict(CATALOG, hosts=[], networks=[], ports=[], footprints=[], env=[], acts=[], proxy_capable=[],
                 hook_images=[], hook_not_paths=[])
    for directory in (LINUX, WINDOWS):
        full, bare = from_dir(directory), from_dir(directory, catalog=empty)
        assert [c["pid"] for c in bare["candidates"]] == [c["pid"] for c in full["candidates"]]
        assert all(t["endpoint"] == [] for c in bare["candidates"] for t in c["talks"])
        assert all(not a["listed"] for c in bare["candidates"] for a in c["acts"])


def test_b6_a_renamed_shell_still_counts_and_names_only_label():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/kodo"]), proc(11, 10, ["/tmp/x/notashell", "-c", "rm -rf ."]),
                            proc(20, 1, ["/usr/bin/tmux"]), proc(21, 20, ["/bin/bash"])),
                 ss=ss(("10.0.0.5:40000", "203.0.113.1:443", "kodo", 10)))
    (c,) = inv["candidates"]
    assert (c["pid"], c["acts"][0]["pid"], c["acts"][0]["listed"], c["listed_acts"]) == (10, 11, False, 0)


def test_e3_talks_without_a_child_is_not_a_candidate():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/browser"]), proc(20, 1, ["/usr/bin/tmux"]),
                            proc(21, 20, ["/bin/bash"])),
                 ss=ss(("10.0.0.5:40000", "160.79.104.10:443", "browser", 10)))
    assert inv["candidates"] == [] and inv["result"] == "none-seen" and inv["exit"] == 0
    assert [t["pid"] for t in inv["endpoint_talkers"]] == [10]


def test_e3_inbound_connections_are_not_talking():
    inv = inv_of(proc=procs(proc(30, 1, ["/usr/sbin/sshd"]), proc(31, 30, ["-bash"])),
                 ss=ss(("10.0.0.5:22", "203.0.113.9:51000", "sshd", 30), listen=(("0.0.0.0:22", "sshd", 30),)))
    assert inv["candidates"] == []


def test_e3_nested_talkers_each_get_their_own_acts():
    inv = inv_of(proc=procs(proc(40, 1, ["/opt/host/hostd"]), proc(41, 40, ["/usr/bin/node", "/x/agent.js"]),
                            proc(42, 41, ["/bin/sh", "-c", "ls"]), proc(43, 40, ["/usr/bin/python3", "tool.py"])),
                 ss=ss(("10.0.0.5:40000", "203.0.113.1:443", "hostd", 40),
                       ("10.0.0.5:40001", "203.0.113.2:443", "node", 41)))
    by = {c["pid"]: c for c in inv["candidates"]}
    assert sorted((a["pid"] for a in by[40]["acts"])) == [41, 43]   # node and python3: acts of hostd
    assert [a["pid"] for a in by[41]["acts"]] == [42]              # sh: act of node, its nearest talker
    assert (by[41]["inside"], by[41]["talking_ancestors"][0]["pid"]) == (by[40]["id"], 40)


def test_e3_file_writes_count_outside_config_space_only():
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"

    def ev(eid, data):
        body = "".join("<Data Name='%s'>%s</Data>" % kv for kv in data)
        return ("<Event xmlns='%s'><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>%d</EventID>"
                "</System><EventData>%s</EventData></Event>" % (ns, eid, body))
    image = ("Image", "C:\\Apps\\quill\\quill.exe")
    talk = ev(3, [("UtcTime", "2026-11-01 05:00:00.000"), ("ProcessId", "50"), image, ("Protocol", "tcp"),
                  ("Initiated", "true"), ("SourceIp", "10.0.0.5"), ("SourcePort", "50000"),
                  ("DestinationIp", "203.0.113.7"), ("DestinationPort", "443")])

    def wrote(path):
        return ev(11, [("UtcTime", "2026-11-01 05:00:01.000"), ("ProcessId", "50"), image, ("TargetFilename", path)])
    config = ["C:\\Users\\u\\.quill\\state.json", "C:\\Users\\u\\AppData\\Roaming\\quill\\x.db",
              "C:\\Apps\\quill\\cache\\y", "C:\\Users\\u\\AppData\\Local\\Temp\\z.tmp", "/home/u/.config/q/c.json"]
    inv = inv_of(sysmon="\n".join([talk] + [wrote(p) for p in config]) + "\n")
    assert inv["candidates"] == []
    assert any("config space" in h and ".git/hooks" in h for h in inv["holes"])     # D8, said
    inv = inv_of(sysmon="\n".join([talk, wrote("C:\\work\\repo\\main.go")]) + "\n")
    assert [(c["pid"], c["acts"][0]["path"]) for c in inv["candidates"]] == [(50, "C:\\work\\repo\\main.go")]


# --- E4: footprints and AGENT-DARK --------------------------------------------------

def test_e4_agent_dark_positive_windows():
    inv = from_dir(WINDOWS)
    dark = {d["agent"]: d for d in inv["agent_dark"]}
    assert sorted(dark) == ["codex", "gemini"]
    assert dark["codex"]["quiet"] == [] and dark["codex"]["cites"][0]["line"] == 4
    assert [(q["pid"], q["talks"]) for q in dark["gemini"]["quiet"]] == [(6020, True)]
    linked = {f["path"]: f["candidate"] for f in inv["footprints"]}
    claude = [c["id"] for c in inv["candidates"] if c["pid"] == 2100][0]
    assert linked["C:\\Users\\field\\.claude"] == claude and linked["C:\\Users\\field\\.claude.json"] == claude
    assert "C:\\Users\\field\\.nimbus" not in linked   # not in the catalog: the anchor found nimbus anyway


def test_e4_agent_dark_negative_linux():
    inv = from_dir(LINUX)
    claude = [c["id"] for c in inv["candidates"] if c["pid"] == 95][0]
    assert inv["agent_dark"] == []
    assert [(f["path"], f["candidate"]) for f in inv["footprints"]] == [
        ("/root/.claude", claude), ("/root/.claude.json", claude), ("/home/user/.claude", claude)]


def test_e4_footprint_unjudged_without_trees():
    inv = inv_of(footprints="/home/u/.codex\n")
    assert inv["agent_dark"] == [] and "cannot be judged" in inv["footprints"][0]["unjudged"]
    assert inv["result"] == "incomplete" and inv["exit"] == 3


def test_e4_env_footprints_are_names_never_values():
    inv = inv_of(proc=procs(proc(60, 1, ["/usr/bin/python3", "/opt/a/run.py"], env=["OPENAI_API_KEY", "PATH"]),
                            proc(61, 60, ["/bin/bash"]), proc(70, 1, ["/usr/bin/top"], env=["MISTRAL_API_KEY"])),
                 ss=ss(("10.0.0.5:40000", "203.0.113.1:443", "python3", 60)))
    (c,) = inv["candidates"]
    assert [e["name"] for e in c["env_footprints"]] == ["OPENAI_API_KEY"]
    assert [(e["pid"], e["names"], e["candidate"]) for e in inv["env_footprints"]] == [
        (60, ["OPENAI_API_KEY"], "C1"), (70, ["MISTRAL_API_KEY"], None)]


def test_e4_scan_footprints_lists_names_only(tmp_path):
    home = tmp_path / "home"
    for d in (".claude", ".kimi", "projects", ".config"):
        (home / d).mkdir(parents=True)
    (home / ".aider.conf.yml").write_text("x")
    nested = home / "AppData" / "Roaming" / "Claude"
    nested.mkdir(parents=True)
    (nested / "claude_desktop_config.json").write_text("{}")
    text = discover.scan_footprints([str(home), str(tmp_path / "missing")], CATALOG)
    paths = [x for x in text.splitlines() if not x.startswith(("#", "!"))]
    assert sorted(os.path.relpath(p, str(home)).replace("\\", "/") for p in paths) == [
        ".aider.conf.yml", ".claude", ".kimi", "AppData/Roaming/Claude/claude_desktop_config.json"]
    assert any(x.startswith("!hole home ") and "not readable" in x for x in text.splitlines())


@pytest.mark.skipif(sys.platform == "win32", reason="Windows file names cannot hold a newline")
def test_e4_scan_footprints_skips_names_that_could_forge_a_line(tmp_path):
    (tmp_path / ".aider\n/etc/forged").mkdir(parents=True)
    text = discover.scan_footprints([str(tmp_path)], CATALOG)
    assert "/etc/forged" not in text and "!hole home" in text and "control characters not listed" in text


# --- B-3: every read failure is a hole -----------------------------------------------

def test_b3_footprint_and_proc_meta_failures_reach_the_holes():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/x"]), gone_while_read=2, unreadable=1, kernel_threads=5,
                            kernel_parent=2),
                 ss=ss(listen=(("0.0.0.0:22", "sshd", 10),)),
                 footprints="# c\n!hole home /home/eve not readable: Permission denied\n/home/u/.codex\n")
    holes = " | ".join(inv["holes"])
    assert "footprints:2 home /home/eve not readable" in holes
    assert "proc:1 snapshot %s: 2 process(es) ended while read" % AT in holes
    assert "5 kernel thread(s) under kthreadd (pid 2)" in holes and "1 process(es) whose status" in holes
    assert any("could not be read" in x for x in inv["incomplete"])


# --- B-4: the anchor's blind spots are said on every run --------------------------------

@pytest.mark.parametrize("inv", [inv_of(proc=procs(), ss=ss()), from_dir(LINUX), from_dir(WINDOWS)],
                         ids=["empty", "linux", "windows"])
def test_b4_every_run_names_liveness_siblings_reparenting_tcp_and_namespaces(inv):
    holes = " ".join(inv["holes"])
    for phrase in ("liveness:", "sibling talkers:", "reparented acts:", "TCP only:", "QUIC", "unix-socket",
                   "network namespaces", "hidepid"):
        assert phrase in holes, phrase
    text = discover.render_text(inv)
    assert "liveness:" in text and "hidepid" in text


# --- E5: output, citations, silence ---------------------------------------------------

def _all_cites(node):
    if isinstance(node, dict):
        if "cites" in node:
            yield node["cites"]
        for v in node.values():
            yield from _all_cites(v)
    elif isinstance(node, list):
        for v in node:
            yield from _all_cites(v)


@pytest.mark.parametrize("directory", [LINUX, WINDOWS], ids=["linux", "windows"])
def test_e5_every_claim_cites_lines_that_exist(directory):
    inv = from_dir(directory)
    files = {s["name"]: lines_of(s["path"]) for s in inv["sources"]}
    groups = list(_all_cites(inv))
    assert groups and all(groups), "a claim without a citation is not a claim (A5)"
    for group in groups:
        for c in group:
            raw = files[c["src"]][c["line"] - 1]
            if c["src"] == "sysmon":
                pid = re.match(r"Sysmon \d+ \S+ \S+ pid (\d+)", c["text"]).group(1)
                assert raw.startswith("<Event") and c["text"].startswith("Sysmon ")
                assert "<Data Name='ProcessId'>%s</Data>" % pid in raw or "ParentProcessId'>%s<" % pid in raw
            else:
                assert c["text"] == discover.bounded(raw)
    for c in inv["candidates"]:
        assert c["cites"] and c["source"]["cites"] and all(t["cites"] for t in c["talks"])
        assert all(a["cites"] for a in c["acts"])


def test_d5_handoff_criteria_come_from_the_catalog():
    linux = {c["pid"]: c["source"]["suggested"] for c in from_dir(LINUX)["candidates"]}
    assert linux == {87: "os", 95: "hook"}                       # /opt/claude-code/bin/claude
    windows = {c["pid"]: c["source"]["suggested"] for c in from_dir(WINDOWS)["candidates"]}
    assert windows == {2100: "hook", 3300: "os", 4100: "os", 7000: "os"}   # claude.exe (Q-R2, D-5)

    def suggested(argv, env=None, catalog=CATALOG):
        inv = inv_of(catalog=catalog, proc=procs(proc(80, 1, argv, env=env), proc(81, 80, ["/bin/sh"])),
                     ss=ss(("10.0.0.5:40000", "203.0.113.1:443", "x", 80)))
        return inv["candidates"][0]["source"]
    assert suggested(["/usr/local/bin/kodo"], env=["OPENAI_BASE_URL"])["suggested"] == "os"   # A-5 rejected
    assert suggested(["/usr/local/bin/codex"])["suggested"] == "proxy"
    assert suggested(["node", "/usr/lib/node_modules/@openai/codex/bin/codex.js"])["suggested"] == "proxy"
    assert suggested(["/home/u/.local/bin/claude"])["suggested"] == "hook"
    assert suggested(["/home/u/.local/bin/claude", "-p", "hello"])["suggested"] == "hook"
    # the image is node, not claude: os (recorded in handoff.hook.evasion)
    assert suggested(["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"])["suggested"] == "os"
    for desktop in (["C:\\Users\\u\\AppData\\Local\\AnthropicClaude\\app-1.0\\claude.exe"],
                    ["/Applications/Claude.app/Contents/MacOS/Claude"], ["/opt/claude-desktop/claude"]):
        source = suggested(desktop)
        assert source["suggested"] == "os" and "Claude Desktop" in source["why"], desktop
    assert suggested(["python3", "/home/claude/agent.py"])["suggested"] == "os"   # a directory is not a name
    other = dict(CATALOG, hook_images=["kodo"], proxy_capable=[])
    assert suggested(["/usr/local/bin/kodo"], catalog=other)["suggested"] == "hook"   # the catalog decides


def test_e5_no_agent_seen_only_when_complete():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/sbin/sshd"])), ss=ss(listen=(("0.0.0.0:22", "sshd", 10),)))
    text = discover.render_text(inv)
    assert inv["result"] == "none-seen" and inv["exit"] == 0 and inv["complete"]
    assert "NO AGENT SEEN in window 2026-11-02T10:00:00.000Z .. 2026-11-02T10:00:00.000Z; 3 records read" in text
    assert "(proc 2, ss 1); the read was complete. Not a clearance." in text
    assert "INCOMPLETE: none - every process and connection source was read" in text
    assert text.endswith("RESULT: NONE-SEEN (exit 0)\n")


@pytest.mark.parametrize("texts, errors, reason", [
    ({"proc": procs(proc(10, 1, ["/x"])), "ss": "State Recv-Q\n"}, {}, "source ss holds no conn record"),
    ({"proc": procs(), "ss": ss(listen=(("0.0.0.0:22", "sshd", 10),))}, {}, "source proc holds no proc record"),
    ({"proc": procs(proc(10, 1, ["/x"])), "ss": ss(listen=(("0.0.0.0:22", "x", 10),))},
     {"ss": "1 of 3 sample(s) failed: boom"}, "source ss partly read: 1 of 3"),
    ({"proc": None, "ss": ss(listen=(("0.0.0.0:22", "x", 10),))}, {"proc": "cannot list /proc"},
     "source proc not read"),
    ({"proc": procs(proc(10, 1, ["/x"])),
      "proc_net": "\n".join([NET_HEAD, net_row(0, "0500000A:9C40", "0A684FA0:01BB", "01", 4242)]) + "\n"},
     {}, "1 talking line(s) without an owner"),
    ({"proc": procs(proc(10, 1, ["/x"])),
      "ss": "State R S L P Process\nESTAB 0 0 10.0.0.5:40000 203.0.113.1:443\n"}, {}, "without an owner"),
    ({"proc": procs(proc(10, 1, ["/x"])), "ss": ss(("10.0.0.5:40000", "203.0.113.1:443", "gone", 99))},
     {}, "1 talking pid(s) with no process record"),
    ({"proc": procs(proc(10, 1, ["/x"]), unreadable=2), "ss": ss(listen=(("0.0.0.0:22", "x", 10),))},
     {}, "2 process(es) could not be read"),
], ids=["conn-source-empty", "proc-source-empty", "partial-window", "proc-failed", "proc-net-unowned",
        "ss-unowned", "orphan-talker", "proc-unreadable"])
def test_b2_any_gap_in_process_or_connection_sources_is_incomplete(texts, errors, reason):
    inv = inv_of(errors=errors, **texts)
    assert inv["result"] == "incomplete" and inv["exit"] == 3 and not inv["complete"], inv["incomplete"]
    assert any(reason in x for x in inv["incomplete"]), inv["incomplete"]
    assert "INCOMPLETE: " + "; ".join(inv["incomplete"]) in discover.render_text(inv)


def test_b1_proc_net_owners_come_from_fd_sockets():
    net = "\n".join(["# at %s (/proc/net/tcp)" % AT, NET_HEAD,
                     net_row(0, "0500000A:9C40", "0A684FA0:01BB", "01", 4242),
                     net_row(1, "0500000A:9C41", "0A684FA0:01BB", "06", 0)]) + "\n"
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/agent"], sockets=[4242]), proc(11, 10, ["/bin/sh"])), proc_net=net)
    (c,) = inv["candidates"]
    assert (c["pid"], c["talks"][0]["remote"], c["talks"][0]["cites"][0]["src"]) == (10, "160.79.104.10:443", "proc-net")
    assert inv["complete"] and inv["connections_from"] == ["<proc_net>"]


def test_e5_nothing_read_is_an_alarm():
    inv = inv_of(proc="", ss="")
    text = discover.render_text(inv)
    assert inv["result"] == "alarm" and "nothing read" in inv["alarms"][0]
    assert "window: - .. - (no observation time in the records read" in text and "records read: 0" in text


def test_e5_unreadable_lines_and_missing_sources_are_said():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/x"])) + "garbage\n")
    assert inv["result"] == "alarm" and "could not be read" in " ".join(inv["alarms"])
    assert "no connection source read" in " ".join(inv["incomplete"])
    texts = discover.read_inputs({"ss": str(LINUX / "no-such-file.txt"), "proc": str(LINUX / "proc.txt")})
    inv = discover.run(texts, CATALOG)
    assert inv["result"] == "incomplete" and any("source ss not read" in x for x in inv["incomplete"])


def test_e5_text_output_holds_no_control_characters():
    inv = inv_of(proc=procs(proc(10, 1, ["/usr/bin/a\nRESULT: NONE-SEEN\x1b[2J"]), proc(11, 10, ["/bin/sh"])),
                 ss=ss(("10.0.0.5:40000", "203.0.113.1:443", "a", 10)))
    text = discover.render_text(inv)
    assert inv["candidates"] and all(c.isprintable() for line in text.splitlines() for c in line)
    assert [x for x in text.splitlines() if x.startswith("RESULT:")] == ["RESULT: ALARM (exit 1)"]


def test_e5_cli_text_and_json(tmp_path):
    code, text = raqib("discover", "--from", WINDOWS)
    assert code == 1 and "CANDIDATES (anchor: talks + has a child or writes): 4" in text
    assert "AGENT-DARK (footprint, no active tree; A3): 2" in text and "CITED LINES (A5):" in text
    assert "RESULT: ALARM (exit 1)" in text and "[unlisted]" in text
    code, out = raqib("discover", "--read", "proc=%s" % (LINUX / "proc.txt"),
                      "--read", "proc-net=%s" % (LINUX / "proc-net.txt"), "--json")
    inv = json.loads(out)
    assert code == 1 and [c["pid"] for c in inv["candidates"]] == [87, 95] and out.isascii()
    assert inv["connections_from"] == [str(LINUX / "proc-net.txt")]
    code, out = raqib("discover", "--from", LINUX, "-o", tmp_path / "inv.txt")
    assert code == 1 and "-> " in out and "connections read from:" in (tmp_path / "inv.txt").read_text()


@pytest.mark.parametrize("argv", [
    ["--read", "bogus=x"], ["--read", "proc"], ["--from", "no-such-dir"], ["--window", "-1"],
    ["--window", "nan"], ["--from", str(LINUX), "--save", "x"], ["--from", str(LINUX), "--home", "x"],
    ["--from", str(LINUX), "--read", "proc=x"], ["--catalog", "no-such.yaml"],
])
def test_e5_cli_usage_errors(argv):
    assert raqib("discover", *argv)[0] == 2


def test_e5_cli_from_an_empty_directory_is_a_usage_error(tmp_path):
    code, _ = raqib("discover", "--from", tmp_path)
    assert code == 2


def test_e5_window_filter_on_timed_records():
    inv = from_dir(WINDOWS, window=30)
    assert inv["window"]["filter_seconds"] == 30
    assert any("left out" in h for h in inv["holes"])
    assert 3300 in [c["pid"] for c in inv["candidates"]]     # its Win32_Process/TCP rows carry no time


# --- E6: offline, read-only, stdlib-only; B-1: no PATH lookup --------------------------

def test_e6_discover_opens_no_socket_touches_no_process_and_runs_nothing_by_bare_name():
    tree = ast.parse((ROOT / "raqib" / "discover.py").read_text(encoding="utf-8"))
    imported, runs = set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            assert name not in ("kill", "killpg", "send_signal", "terminate", "ptrace", "Popen", "system",
                                "popen", "urlopen", "create_connection", "which", "execv", "execve", "execvp",
                                "execvpe", "execl", "execlp", "execle", "execlpe", "spawnv", "spawnvp", "spawnl",
                                "spawnlp", "posix_spawn", "posix_spawnp", "startfile"), name
            assert not any(k.arg == "shell" for k in node.keywords)
            if isinstance(f, ast.Attribute) and getattr(f.value, "id", None) == "subprocess":
                runs.append(node)
                first = node.args[0] if node.args else None
                literal = first.elts[0] if isinstance(first, (ast.List, ast.Tuple)) and first.elts else None
                assert not (isinstance(literal, ast.Constant) and "/" not in str(literal.value)), "bare program"
    assert not imported & {"socket", "ssl", "http", "urllib", "ctypes", "signal", "asyncio", "anthropic", "shutil"}
    assert imported - {"raqib", "__future__"} <= set(sys.stdlib_module_names)
    # one subprocess call in all of discover.py, inside run_ss, behind an absolute-path check
    (run_ss,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run_ss"]
    assert len(runs) == 1 and runs[0] in list(ast.walk(run_ss))
    assert "os.path.isabs(path)" in ast.unparse(run_ss)
    # R5: the argv is `[path] + list(args)`: its program is the checked `path`, never a literal
    argv = runs[0].args[0]
    assert isinstance(argv, ast.BinOp) and isinstance(argv.left, ast.List)
    assert [ast.unparse(e) for e in argv.left.elts] == ["path"]
    assert all(p.startswith("/") and p.endswith("/ss") for p in discover.SS_PATHS)


def test_b1_run_ss_refuses_a_bare_name_and_uses_a_minimal_env(monkeypatch):
    seen = []

    def fake_run(argv, **kw):
        seen.append((argv, kw["env"]))
        return subprocess.CompletedProcess(argv, 0, "State\n", "")
    monkeypatch.setattr(discover.subprocess, "run", fake_run)
    text, error = discover.run_ss("ss", at=AT)
    assert text is None and "not an absolute path" in error and seen == []
    path = os.path.abspath(os.sep + os.path.join("usr", "sbin", "ss"))
    text, error = discover.run_ss(path, at=AT)
    assert error is None and text.startswith("# at %s (%s -tanp)" % (AT, path))
    (argv, env), = seen
    assert argv == [path, "-tanp"] and set(env) <= {"LC_ALL", "SYSTEMROOT"} and "PATH" not in env


def test_e6_run_ss_reports_a_missing_program():
    text, error = discover.run_ss(os.path.abspath(os.sep + os.path.join("no-such-dir", "raqib-ss")), at=AT)
    assert text is None and "not found" in error


def test_e6_live_elsewhere_lists_homes_and_says_what_it_cannot_read(tmp_path):
    (tmp_path / ".codex").mkdir()
    # M7.1: Windows now reads live (tests/test_hostwin.py); "elsewhere" is any other system.
    texts, holes, _ = discover.collect_live(CATALOG, platform="darwin", homes=[str(tmp_path)])
    assert set(texts) == {"footprints"} and "no live process or connection reader on darwin" in holes[0]
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    text = discover.render_text(inv)
    assert inv["result"] == "incomplete" and inv["agent_dark"] == []    # unjudged, not dark
    assert "window: - .. -" in text and "records read: 1" in text


def _fake_ss_script(pid):
    return ("print('State Recv-Q Send-Q Local Address:Port Peer Address:Port Process');"
            "print('ESTAB 0 0 10.0.0.5:40000 160.79.104.10:443 users:((\"agent\",pid=%d,fd=3))')" % pid)


def _clock():
    now = [1793620000.0]
    return (lambda: now[0]), (lambda s: now.__setitem__(0, now[0] + s))


def test_b1_live_reads_proc_net_first_and_never_runs_ss(tmp_path, monkeypatch):
    if not can_symlink(tmp_path):
        pytest.skip("fd links need symlinks")
    root = tmp_path / "proc"
    net = "\n".join([NET_HEAD, net_row(0, "0500000A:9C40", "0A684FA0:01BB", "01", 4242)]) + "\n"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0"), (51, 50, "bash", b"/bin/bash\0")], net,
              sockets={50: [4242]})
    monkeypatch.setattr(discover.subprocess, "run", lambda *a, **k: pytest.fail("ss must not run"))
    texts, holes, _ = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root))
    assert "ss" not in texts and "proc-net" in texts and texts["proc-net"][2] is None
    assert any("tcp6 not present" in x for x in texts["proc-net"][1].splitlines())
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert [c["pid"] for c in inv["candidates"]] == [50] and inv["complete"]
    assert inv["connections_from"] == ["live %s, %s" % (os.path.join(str(root), "net", "tcp"),
                                                         os.path.join(str(root), "net", "tcp6"))]
    assert "connections read from: live %s" % os.path.join(str(root), "net", "tcp") in discover.render_text(inv)


def test_e6_live_sampling_with_the_ss_fallback(tmp_path):
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0"), (51, 50, "bash", b"/bin/bash\0-c\0make\0")])
    clock, sleep = _clock()
    texts, holes, _ = discover.collect_live(CATALOG, window=2, homes=[], platform="linux", proc_root=str(root),
                                         ss_paths=(sys.executable,), ss_args=("-c", _fake_ss_script(50)),
                                         clock=clock, sleep=sleep)
    assert texts["proc"][1].count('"snapshot"') == 3 and texts["ss"][1].count("# at ") == 3
    assert texts["ss"][0] == "live fallback: %s -c %s" % (sys.executable, _fake_ss_script(50))
    assert texts["proc-net"][1] is None and texts["proc-net"][2].startswith("3 of 3 sample(s) failed: cannot read")
    assert holes == ["ss fallback used for 3 of 3 sample(s): %s" % sys.executable]
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    (c,) = inv["candidates"]
    assert (c["pid"], c["talks"][0]["lines"], inv["window"]["seconds"], inv["window"]["snapshots"]) == (50, 3, 2.0, 3)
    assert c["seen"]["first"] != c["seen"]["last"]
    # D-2: /proc/net/tcp failed, so the run is incomplete even though ss stood in
    assert not inv["complete"] and any("source proc-net not read" in x for x in inv["incomplete"])


def test_d17_live_with_no_connection_reader_at_all_is_incomplete(tmp_path):
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0")])
    missing = os.path.join(str(tmp_path), "nowhere", "ss")
    texts, holes, _ = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root), ss_paths=(missing,))
    assert texts["ss"][1] is None and "no ss at %s" % missing in texts["ss"][2]
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    text = discover.render_text(inv)
    assert inv["result"] == "incomplete" and inv["exit"] == 3
    assert "no connection source read" in text and "NOT READ: 1 of 1 sample(s) failed: no ss at" in text


def test_d17_a_source_that_fails_in_part_of_the_window_makes_the_run_incomplete(tmp_path):
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0")])
    clock, advance = _clock()

    def sleep(s):                      # /proc vanishes after the first sample
        advance(s)
        shutil.rmtree(str(root), ignore_errors=True)
    texts, holes, _ = discover.collect_live(CATALOG, window=2, homes=[], platform="linux", proc_root=str(root),
                                         ss_paths=(sys.executable,), ss_args=("-c", _fake_ss_script(50)),
                                         clock=clock, sleep=sleep)
    assert texts["proc"][1] is not None and texts["proc"][2].startswith("2 of 3 sample(s) failed")
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["exit"] == 3 and any("source proc partly read: 2 of 3" in x for x in inv["incomplete"])
    assert "PARTLY READ: 2 of 3 sample(s) failed" in discover.render_text(inv)


def test_e6_save_then_from_gives_the_same_inventory(tmp_path):
    texts = discover.read_inputs(discover.inputs_in(str(LINUX)))
    written = discover.save(texts, str(tmp_path / "saved"))
    assert len(written) == 5 and written[-1].endswith("run.json")
    again = from_dir(tmp_path / "saved")
    first = discover.run(texts, CATALOG)
    for key in ("candidates", "footprints", "agent_dark", "window", "records", "result", "incomplete"):
        assert again[key] == first[key], key


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the live reader is Linux-only in M5.0")
def test_e6_live_linux_smoke(tmp_path):
    texts, holes, _ = discover.collect_live(CATALOG, homes=[str(tmp_path)])
    records, problems = discover.parse_proc(texts["proc"][1])
    assert problems == [] and any(r["kind"] == "snapshot" and r["self"] == os.getpid() for r in records)
    assert any(r["kind"] == "proc" and r["pid"] == os.getpid() for r in records)
    if os.path.exists("/proc/net/tcp"):
        assert texts["proc-net"][1] is not None and "ss" not in texts
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["result"] in ("alarm", "incomplete", "none-seen") and "window:" in discover.render_text(inv)
    assert all(a["pid"] != os.getpid() for c in inv["candidates"] for a in c["acts"])


# --- REDO 2 (Amendment D) ------------------------------------------------------------

def _sysmon_events(*ids):
    """The Windows fixture's Sysmon lines whose EventID is in ids."""
    keep = [x for x in lines_of(WINDOWS / "sysmon.xml")
            if any("<EventID>%d</EventID>" % i in x for i in ids)]
    return "\n".join(keep) + "\n"


@pytest.mark.parametrize("ids, missing", [((3, 22), "event 1"), ((1, 22), "event 3")],
                         ids=["no-event-1", "no-event-3"])
def test_d1_sysmon_is_a_complete_source_only_with_event_1_and_event_3(ids, missing):
    inv = inv_of(sysmon=_sysmon_events(*ids))
    assert (inv["result"], inv["exit"], inv["candidates"]) == ("incomplete", 3, []) and not inv["complete"]
    assert "source sysmon holds no %s" % missing in inv["incomplete"]
    holes = " ".join(inv["holes"])
    assert "holds no %s" % missing in holes
    if missing == "event 3":
        assert "Sysmon without -n logs no event 3" in holes
    assert inv["agent_dark"] == []          # trees cannot be judged without both


def test_d1_sysmon_with_events_1_and_3_is_complete():
    inv = inv_of(sysmon=_sysmon_events(1, 3))
    assert not any("sysmon" in x for x in inv["incomplete"])


def test_d2_only_a_missing_tcp6_is_a_hole(tmp_path, monkeypatch):
    import errno
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0")],
              net="\n".join([NET_HEAD, net_row(0, "0500000A:9C40", "0A684FA0:01BB", "0A", 9)]) + "\n")
    text, error = discover.read_proc_net(str(root), AT)
    assert error is None and "!hole %s not present" % os.path.join(str(root), "net", "tcp6") in text
    (root / "net" / "tcp6").write_text(NET_HEAD + "\n")
    real = discover._read_bytes

    def denied(path):
        if path.endswith("tcp6"):
            raise PermissionError(errno.EACCES, "Permission denied", path)
        return real(path)
    monkeypatch.setattr(discover, "_read_bytes", denied)
    text, error = discover.read_proc_net(str(root), AT)
    assert text is not None and "!hole" not in text and "tcp6: Permission denied" in error
    texts, holes, _ = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root),
                                         ss_paths=(os.path.join(str(tmp_path), "no", "ss"),))
    assert "ss" not in texts                                   # tcp was read: no fallback
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["exit"] == 3 and any("source proc-net partly read: 1 of 1 sample(s) failed" in x
                                    for x in inv["incomplete"])


def test_d3_an_unreadable_fd_link_makes_sockets_unknown_and_is_a_hole(tmp_path, monkeypatch):
    root = tmp_path / "proc"
    fake_proc(root, [(60, 1, "agent", b"/usr/local/bin/agent\0"), (61, 1, "other", b"/usr/bin/other\0")])
    (root / "60" / "fd" / "3").write_text("")                 # an fd entry whose link cannot be read
    real = os.readlink

    def readlink(path):
        if os.path.basename(os.path.dirname(path)) == "fd":
            raise PermissionError(13, "Permission denied", path)
        return real(path)
    monkeypatch.setattr(discover.os, "readlink", readlink)
    (root / "61" / "fd").rmdir()                              # an fd directory that cannot be listed
    text = discover.snapshot_proc(str(root), AT, None)
    by = {o["pid"]: o for o in map(json.loads, text.splitlines()[1:])}
    assert (by[60]["sockets"], by[61]["sockets"]) == (None, None)
    assert "fd" in by[60]["unread"] and "fd" in by[61]["unread"] and "cwd" in by[60]["unread"]
    inv = inv_of(proc=text, ss=ss(listen=(("0.0.0.0:22", "x", 60),)))
    holes = " ".join(inv["holes"])
    assert "2 process(es) with open sockets (/proc/PID/fd links) unknown, recorded as null:" \
           " pid 60 (proc:2), pid 61 (proc:3)" in holes
    assert "with working directory (cwd link) not read: pid 60 (proc:2)" in holes


def test_d4_save_and_replay_of_a_partial_live_run_stays_incomplete(tmp_path):
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0"), (51, 50, "bash", b"/bin/bash\0")])
    clock, advance = _clock()

    def sleep(s):
        advance(s)
        shutil.rmtree(str(root), ignore_errors=True)
    texts, holes, _ = discover.collect_live(CATALOG, window=1, homes=[], platform="linux", proc_root=str(root),
                                         ss_paths=(sys.executable,), ss_args=("-c", _fake_ss_script(50)),
                                         clock=clock, sleep=sleep)
    live = discover.run(texts, CATALOG, holes=holes, live=True)
    assert live["exit"] == 1 and not live["complete"]           # a candidate, and incomplete
    saved = tmp_path / "saved"
    discover.save(texts, str(saved), holes)
    run = json.loads((saved / "run.json").read_text())
    assert run["sources"]["proc"]["error"].startswith("1 of 2 sample(s) failed")
    assert run["connections_from"] == ["live fallback: %s -c %s" % (sys.executable, _fake_ss_script(50))]
    assert run["sources"]["proc-net"]["file"] is None and run["holes"] == holes
    replay = from_dir(saved)
    assert replay["incomplete"] == live["incomplete"] and not replay["complete"]
    assert [c["pid"] for c in replay["candidates"]] == [50]
    assert any("saved from live fallback: %s" % sys.executable in x for x in replay["connections_from"])
    assert "saved run: ss fallback used for 2 of 2 sample(s): %s" % sys.executable in replay["holes"]
    code, _ = raqib("discover", "--from", saved)
    assert code == 1
    (saved / "run.json").write_text("{not json")
    assert raqib("discover", "--from", saved)[0] == 2


def test_d4_cli_save_writes_run_json(tmp_path, monkeypatch):
    texts = {"proc": ("live /proc", procs(proc(10, 1, ["/x"])), "1 of 2 sample(s) failed: boom"),
             "footprints": ("live: homes", "# none\n", None)}
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: (texts, ["a live hole"], 2))
    code, _ = raqib("discover", "--save", tmp_path / "s")
    run = json.loads((tmp_path / "s" / "run.json").read_text())
    assert code == 3 and run["holes"] == ["a live hole"] and run["sources"]["proc"]["error"].startswith("1 of 2")


def test_d8_r7_unowned_lines_name_inode_0_states_and_the_opening_race():
    net = "\n".join([NET_HEAD, net_row(0, "0500000A:9C40", "0A684FA0:01BB", "04", 0),
                      net_row(1, "0500000A:9C41", "0A684FA0:01BB", "01", 4242)]) + "\n"
    inv = inv_of(proc=procs(proc(10, 1, ["/x"], sockets=[])), proc_net=net)
    (hole,) = [h for h in inv["holes"] if "without an owning process" in h]
    assert "opened between the fd snapshot and the tcp read" in hole
    assert "1 with inode 0, which the kernel keeps after the owner closed it (FIN-WAIT-1)" in hole
    assert inv["exit"] == 3


# --- README (B-4, B-5, B-8, D12) ------------------------------------------------------

def test_readme_states_the_rulings():
    section = GUIDE.split("## Find the agents on a host (discover)")[1].split("\n## ")[0]
    flat = " ".join(section.split())
    assert "/rd:true" in section                                             # B-5
    for phrase in ("IDE terminals", "package managers", "CI runners", "loopback"):   # B-8
        assert phrase in flat, phrase
    # M5.0b E4: the B-8 "no fp_budget" line is replaced by the first measured numbers
    assert "no fp_budget" not in flat and "declares no fp_budget in M5.0" not in flat
    report = discover.check(CATALOG, str(ROOT))
    act, anchor = report["classes"]
    assert ("candidates fire on %d of %d, and the anchor still declares no budget; act-root declares fp_budget %g"
            " and fires on %d of %d" % (anchor["fired"], anchor["measured"], CATALOG["act_root"]["fp_budget"],
                                        act["fired"], act["measured"])) in flat
    assert "raqib discover --check" in flat and "set from field runs, not guessed" in flat
    for phrase in ("liveness", "sibling", "reparent", "TCP only", "QUIC", "unix-socket", "namespace", "hidepid"):
        assert phrase in flat, phrase                                        # B-4
    assert "/proc/net/tcp" in flat and "absolute path" in flat               # B-1
    assert "AppData\\Roaming\\Claude" in section                              # D12
    assert ".git/hooks" in flat                                              # D8


# --- M5.0b (HANDOFF E1-E5; ADR-0004 Amendments F, G) -------------------------------------

KIMI1, KIMI2 = FIX / "kimi" / "one-sample", FIX / "kimi" / "two-samples"
BENIGN_LINUX, BENIGN_WINDOWS = FIX / "benign" / "linux-desktop", FIX / "benign" / "windows-desktop"
AGENT = FIX / "linux-agent"
M50B = (KIMI1, KIMI2, BENIGN_LINUX, BENIGN_WINDOWS, AGENT)
DOC_NETS = [discover.ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                         "127.0.0.0/8", "0.0.0.0/32", "::/128")]
DOC_NETS += [n["net"] for n in CATALOG["networks"]]      # the catalog's own endpoint networks


def copy_fixture(src, tmp_path, name="fx"):
    dst = tmp_path / name
    shutil.copytree(str(src), str(dst))
    return dst


DATE = "11/3/2026 9:00:00 AM"


def win_row(row):
    """A Win32_Process CSV row of (pid, ppid, name, path[, command line[, CreationDate]]); "" leaves a field blank."""
    pid, ppid, name, path = row[:4]
    cmdline, date = (list(row[4:]) + ["", DATE])[:2] if len(row) > 4 else ("", DATE)
    return ",".join('"%s"' % str(v).replace('"', '""') if v else "" for v in (pid, ppid, name, path, cmdline, date)) + "\n"


def win_texts(*samples, dns=None):
    """{name: (path, text, None)} for Windows samples given as (k, process rows, tcp rows)."""
    texts = {}
    for k, procs_rows, tcp_rows in samples:
        texts["win-process-%d" % k] = ("<p%d>" % k, '"ProcessId","ParentProcessId","Name","ExecutablePath",'
                                       '"CommandLine","CreationDate"\n' + "".join(win_row(r) for r in procs_rows),
                                       None)
        texts["win-tcp-%d" % k] = ("<t%d>" % k, '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State",'
                                   '"OwningProcess"\n' + "".join('"%s","%s","%s","%s","%s","%s"\n' % r for r in tcp_rows),
                                   None)
    if dns:
        texts["win-dns"] = ("<d>", '"Entry","Name","Type","Data"\n' + "".join('"%s","%s","1","%s"\n' % r for r in dns),
                            None)
    return texts


LISTEN_ROW = ("0.0.0.0", "135", "0.0.0.0", "0", "Listen", "4")
SYS = ("4", "0", "System", "")


# E1: the Windows window

def test_m50b_e1_numbered_samples_are_read_and_merged_like_the_linux_window():
    inv = from_dir(KIMI2)
    assert [s["name"] for s in inv["sources"]] == ["win-process-1", "win-process-2", "win-tcp-1", "win-tcp-2",
                                                   "win-dns-1", "win-dns-2", "footprints"]
    assert (inv["window"]["samples"], inv["window"]["samples_read"], inv["complete"]) == ([1, 2], [1, 2], True)
    # one tree from both samples: kimi's process from sample 1 and 2, its talk from sample 2 only
    (kimi,) = [c for c in inv["candidates"] if c["image"] == "kimi"]
    assert [c["src"] + ":%d" % c["line"] for c in kimi["cites"]] == ["win-process-1:12", "win-process-2:12"]
    assert [c["src"] for c in kimi["talks"][0]["cites"]][0] == "win-tcp-2"
    assert any(h.startswith("window merge: the records of 2 sample(s)") for h in inv["holes"])
    assert "Windows samples: 2 of 2 read, merged" in discover.render_text(inv)
    assert inv["connections_from"] == [str(KIMI2 / "win-tcp-1.csv"), str(KIMI2 / "win-tcp-2.csv")]


def test_m50b_e1_one_sample_still_works_numbered_or_not():
    one = from_dir(KIMI1)
    assert (one["window"]["samples"], one["complete"]) == ([1], True)
    assert not any(h.startswith("window merge") for h in one["holes"])
    old = from_dir(WINDOWS)                         # the M5.0 single files
    assert (old["window"]["samples"], old["complete"]) == ([], True)
    assert [c["pid"] for c in old["candidates"]] == [2100, 3300, 4100, 7000]


def test_m50b_e1_sample_1_is_the_same_file_in_both_kimi_fixtures():
    for name in ("win-process-1.csv", "win-tcp-1.csv", "win-dns-1.csv", "footprints.txt"):
        assert (KIMI1 / name).read_bytes() == (KIMI2 / name).read_bytes(), name
    assert json.loads((KIMI1 / "run.json").read_text())["samples"] == 1
    assert json.loads((KIMI2 / "run.json").read_text())["samples"] == 2


@pytest.mark.parametrize("drop, samples, missing", [
    (["win-tcp-2.csv"], None, ["win-tcp-2"]),                                    # run.json declares 2
    (["win-process-2.csv", "win-tcp-2.csv", "win-dns-2.csv"], None, ["win-process-2", "win-tcp-2"]),
    ([], 3, ["win-process-3", "win-tcp-3"]),                                     # the loop stopped after 2
], ids=["one-file", "a-whole-sample", "loop-cut-short"])
def test_m50b_e1_a_sample_that_cannot_be_read_is_a_hole_and_incomplete(tmp_path, drop, samples, missing):
    d = copy_fixture(KIMI2, tmp_path)
    for name in drop:
        (d / name).unlink()
    if samples:
        run = json.loads((d / "run.json").read_text())
        (d / "run.json").write_text(json.dumps(dict(run, samples=samples)))
    inv = from_dir(d)
    assert not inv["complete"] and inv["exit"] == 1     # still an alarm (C1 explorer), never a clean exit
    for name in missing:
        k = int(name.rsplit("-", 1)[1])
        assert any(x.startswith("source %s not read: sample %d of %d: %s.csv missing" % (name, k, samples or 2, name))
                   for x in inv["incomplete"]), inv["incomplete"]
        assert any(h.startswith("sample %d: source %s not read" % (k, name)) for h in inv["holes"])
    if "win-dns-2.csv" not in drop and missing == ["win-tcp-2"]:
        assert not any("win-dns-2.csv missing" in h for h in inv["holes"])
    if samples:
        assert any("win-dns-3.csv missing" in h for h in inv["holes"])
    assert "NOT READ: sample" in discover.render_text(inv)


def test_m50b_e1_without_run_json_the_highest_sample_found_is_the_count(tmp_path):
    d = copy_fixture(KIMI2, tmp_path)
    (d / "run.json").unlink()
    (d / "win-process-1.csv").unlink()
    inv = from_dir(d)
    assert any("source win-process-1 not read: sample 1 of 2: win-process-1.csv missing (no run.json" in x
               for x in inv["incomplete"])
    assert any(h.startswith("no run.json beside the numbered samples: the sample count is taken as the highest found"
                            " (2)") for h in inv["holes"])


def test_m50b_e1_an_empty_sample_file_is_unread_lines_and_incomplete(tmp_path):
    d = copy_fixture(KIMI2, tmp_path)
    (d / "win-tcp-2.csv").write_text("")
    inv = from_dir(d)
    assert inv["exit"] == 1 and "source win-tcp-2 holds no conn record" in inv["incomplete"]
    assert any(p["src"] == "win-tcp-2" and "no CSV header" in p["reason"] for p in inv["problems"])


def test_m50b_e1_unnumbered_files_beside_samples_are_merged_and_said(tmp_path):
    d = copy_fixture(KIMI1, tmp_path)
    shutil.copy(str(WINDOWS / "win-process.csv"), str(d / "win-process.csv"))
    inv = from_dir(d)
    assert "win-process" in [s["name"] for s in inv["sources"]]
    assert any(h == "win-process.csv read beside numbered samples of the same kind: merged as one more sample"
               for h in inv["holes"])
    assert any(h.startswith("window merge: the records of 2 sample(s)") for h in inv["holes"])


@pytest.mark.parametrize("run, error", [
    ({"raqib": "discover-run", "version": 1, "samples": 0}, "samples must be a whole number"),
    ({"raqib": "discover-run", "version": 1, "samples": True}, "samples must be a whole number"),
    ({"raqib": "discover-run", "version": 1, "samples": "6"}, "samples must be a whole number"),
    ({"raqib": "discover-run", "version": 1}, "the README loop's"),
    ({"raqib": "other", "samples": 2}, "the README loop's"),
    ([1, 2], "not a JSON object"),
], ids=["zero", "bool", "string", "no-samples", "not-ours", "not-an-object"])
def test_m50b_e1_a_run_json_that_cannot_be_read_is_a_usage_error(tmp_path, run, error):
    d = copy_fixture(KIMI1, tmp_path)
    (d / "run.json").write_text(json.dumps(run))
    with pytest.raises(ValueError, match=error):
        discover.read_dir(str(d))
    assert raqib("discover", "--from", d)[0] == 2


def test_m50b_e1_the_readme_loop_run_json_shape_is_read(tmp_path):
    """PowerShell 5.1's ConvertTo-Json of an [ordered] table: four-space indent, two spaces after the colon,
    CRLF; Out-File -Encoding ascii, so no BOM."""
    d = copy_fixture(KIMI1, tmp_path)
    (d / "run.json").write_bytes(b'{\r\n    "raqib":  "discover-run",\r\n    "version":  1,\r\n    "export":  "windows",'
                                 b'\r\n    "samples":  1,\r\n    "seconds_apart":  10\r\n}\r\n')
    texts, holes = discover.read_dir(str(d))
    assert sorted(texts) == ["footprints", "win-dns-1", "win-process-1", "win-tcp-1"] and holes == []


def test_m50b_e1_save_records_the_sample_count_and_replays(tmp_path):
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"/usr/local/bin/agent\0"), (51, 50, "bash", b"/bin/bash\0")])
    clock, sleep = _clock()
    texts, holes, samples = discover.collect_live(CATALOG, window=2, homes=[], platform="linux", proc_root=str(root),
                                                  ss_paths=(sys.executable,), ss_args=("-c", _fake_ss_script(50)),
                                                  clock=clock, sleep=sleep)
    assert samples == 3
    discover.save(texts, str(tmp_path / "saved"), holes, samples)
    assert json.loads((tmp_path / "saved" / "run.json").read_text())["samples"] == 3
    assert [c["pid"] for c in from_dir(tmp_path / "saved")["candidates"]] == [50]
    assert discover.collect_live(CATALOG, platform="darwin", homes=[])[2] == 0   # M7.1: win32 is live now


def test_m50b_e1_cli_save_writes_the_sample_count(tmp_path, monkeypatch):
    texts = {"proc": ("live /proc", procs(proc(10, 1, ["/x"])), None), "footprints": ("live: homes", "# none\n", None)}
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: (texts, [], 6))
    raqib("discover", "--save", tmp_path / "s")
    assert json.loads((tmp_path / "s" / "run.json").read_text())["samples"] == 6


def test_m50b_e1_readme_windows_export_is_the_loop():
    section = GUIDE.split("## Find the agents on a host (discover)")[1].split("\n## ")[0]
    block, sysmon = [b.split("```", 1)[0] for b in section.split("```powershell\n")[1:3]]
    assert block.startswith("$N = 6; $T = 10\n") and "wevtutil" not in block                  # G-10
    assert sysmon.startswith("wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /rd:true /c:5000 > sysmon.xml")
    assert "If Sysmon is installed, export its newest 5000 events" in section
    assert "Run it from an elevated\nPowerShell when you can" in section                        # G-4
    assert "samples = $N" in block and "Out-File -Encoding ascii run.json" in block
    assert "foreach ($k in 1..$N) {" in block and "if ($k -lt $N) { Start-Sleep -Seconds $T }" in block
    for kind in ("win-process", "win-tcp", "win-dns"):
        assert '"%s-$k.csv"' % kind in block
        assert discover.split_name("%s-6" % kind) == (kind, 6)
    assert "`$N = 1` is one sample" in section


def test_m50b_e1_source_names():
    assert discover.split_name("win-tcp-12") == ("win-tcp", 12) and discover.split_name("proc") == ("proc", None)
    for bad in ("win-tcp-0", "win-tcp-01", "proc-1", "win-tcp-", "sysmon-2", "win-tcp-123456"):
        assert discover.split_name(bad) is None, bad
    assert discover.file_name("win-dns-3") == "win-dns-3.csv" and discover.file_name("proc-net") == "proc-net.txt"
    with pytest.raises(ValueError, match="no such source: bogus"):
        discover.run({"bogus": ("<x>", "", None)}, CATALOG)


# E2: recent talk, owner unknown

def test_m50b_e2_time_wait_owner_0_to_a_catalog_endpoint_is_recent_talk_never_a_candidate():
    inv = from_dir(KIMI1)
    (r,) = inv["recent_talk"]
    assert (r["id"], r["how"], r["remote"], r["owner"], r["lines"]) == ("R1", "time-wait", "203.0.113.40:443", None, 1)
    assert [(m["vendor"], m["name"]) for m in r["endpoint"]] == [("moonshot", "api.moonshot.ai")]
    assert [(c["src"], c["line"]) for c in r["cites"]] == [("win-tcp-1", 7), ("win-dns-1", 3)]
    assert r["summary"].startswith("recent talk, owner unknown: TIME-WAIT to 203.0.113.40:443 x1")
    assert not any(t["remote"].startswith("203.0.113.40") for c in inv["candidates"] for t in c["talks"])
    assert "198.51.100.99" not in json.dumps(inv["recent_talk"])           # a TIME-WAIT to no catalog endpoint
    text = discover.render_text(inv)
    assert "RECENT TALK (owner unknown; never a candidate by itself): 1" in text and "win-tcp-1:7" in text


def test_g3_a_dns_row_alone_is_recent_talk_unless_a_known_owner_talks_to_it_and_ends_incomplete():
    procs_rows = [SYS, ("50", "4", "tool.exe", "C:\\Tools\\tool.exe")]
    talk = ("192.0.2.5", "50000", "198.51.100.7", "443", "Established", "50")
    dns = [("api.openai.com", "api.openai.com", "203.0.113.9"), ("api.mistral.ai", "api.mistral.ai", "198.51.100.7"),
           ("www.example.org", "www.example.org", "198.51.100.8")]
    inv = discover.run(win_texts((1, procs_rows, [LISTEN_ROW, talk]), dns=dns), CATALOG)
    assert [(r["how"], r["names"], r["ips"]) for r in inv["recent_talk"]] == [("dns", ["api.openai.com"],
                                                                               ["203.0.113.9"])]
    assert inv["recent_talk"][0]["cites"] == [{"src": "win-dns", "line": 2, "text": '"api.openai.com","api.openai.com",'
                                                                                    '"1","203.0.113.9"'}]
    # G-3 (B-2): recent talk with no candidate and no act-root: the talker is not seen, so incomplete
    assert (inv["candidates"], inv["act_roots"], inv["result"], inv["exit"]) == ([], [], "incomplete", 3)
    assert ("1 recent-talk line(s) to a model endpoint, owner unknown, and no candidate or act-root: the talker is"
            " not seen") in inv["incomplete"]
    assert "1 recent-talk line(s), owner unknown (below). Not a clearance." in discover.render_text(inv)
    # with an act-root (or a candidate) the run is an alarm, and recent talk adds no incompleteness
    assert from_dir(KIMI1)["incomplete"] == [] and from_dir(AGENT)["incomplete"] == []


def test_m50b_e2_linux_inode_0_time_wait_matches_by_network_and_owned_rows_do_not():
    net = "\n".join([NET_HEAD, net_row(0, "0500000A:9C40", "0A684FA0:01BB", "06", 0),
                     net_row(1, "0500000A:9C41", "0A684FA0:01BB", "06", 4242),
                     net_row(2, "0500000A:9C42", "0A684FA0:01BB", "01", 4243)]) + "\n"
    inv = inv_of(proc=procs(proc(10, 1, ["/x"], sockets=[4242, 4243])), proc_net=net)
    (r,) = inv["recent_talk"]
    assert (r["remote"], r["lines"], r["endpoint"][0]["layer"], r["cites"][0]["line"]) == ("160.79.104.10:443", 1,
                                                                                           "network", 2)


def test_m50b_e2_the_holes_name_recent_talk_every_run():
    for inv in (inv_of(proc=procs(), ss=ss()), from_dir(KIMI1)):
        liveness = [h for h in inv["holes"] if h.startswith("liveness:")][0]
        assert "a connection only while it is open" in liveness and "recent talk, owner unknown" in liveness
        assert "never as a candidate" in liveness and "act-root" in liveness


# E3: the act-root class

def test_m50b_e3_kimi_between_requests_is_an_act_root_with_its_cites():
    inv = from_dir(KIMI1)
    (a,) = inv["act_roots"]
    assert (a["id"], a["pid"], a["image"], a["exe"]) == ("A1", 10728, "kimi", "C:\\Users\\user\\.kimi-code\\bin\\kimi.exe")
    assert (a["user_dir"], a["attributed_to"], a["talking_ancestor"]["pid"], a["inside"]) == (
        "?:/users/*/*", "C1", 6636, None)
    assert [(h["pid"], h["image"], h["commands"]) for h in a["chains"]] == [(7768, "bash", ["ping", "tee"])]
    assert [x["pid"] for x in a["acts"]] == [7768, 10476, 5796, 8500, 8496]
    assert a["cites"][0]["line"] == 12 and all(x["cites"] for x in a["acts"])
    assert a["talk"] == "not seen: pid 10728 owns no talking connection in win-tcp-1"
    assert inv["exit"] == 1 and any(x.startswith("1 act-root(s)") for x in inv["alarms"])
    # explorer is still the candidate the anchor finds, as in the field test
    assert [(c["id"], c["image"]) for c in inv["candidates"]] == [("C1", "explorer")]
    # recent talk to kimi's endpoint does not promote it (no talk evidence in a sample)
    assert inv["recent_talk"] and 10728 not in [c["pid"] for c in inv["candidates"]]
    text = discover.render_text(inv)
    assert "[A1] pid 10728 kimi  C:\\Users\\user\\.kimi-code\\bin\\kimi.exe  (user directory ?:/users/*/*)" in text
    assert "its acts go to C1, the nearest talking ancestor: pid 6636 explorer" in text


def test_m50b_e3_talk_in_a_sample_promotes_it_whatever_the_order(tmp_path):
    two = from_dir(KIMI2)
    assert two["act_roots"] == [] and [c["image"] for c in two["candidates"]] == ["explorer", "kimi"]
    (kimi,) = [c for c in two["candidates"] if c["image"] == "kimi"]
    assert (kimi["inside"], [a["pid"] for a in kimi["acts"]]) == ("C1", [5796, 7768, 8496, 8500, 10476])
    texts, holes = discover.read_dir(str(KIMI2))
    swapped = {"win-tcp-1": texts["win-tcp-2"], "win-tcp-2": texts["win-tcp-1"],
               **{k: v for k, v in texts.items() if not k.startswith("win-tcp")}}
    inv = discover.run(swapped, CATALOG, holes=holes)
    assert inv["act_roots"] == [] and "kimi" in [c["image"] for c in inv["candidates"]]


def test_m50b_e3_footprints_link_to_an_act_root_not_dark():
    one, two = from_dir(KIMI1), from_dir(KIMI2)
    assert [(f["path"], f["candidate"], f["act_root"]) for f in one["footprints"]] == [
        ("C:\\Users\\user\\.kimi", None, "A1")]
    assert [(f["candidate"], f["act_root"]) for f in two["footprints"]] == [("C2", None)]
    assert one["agent_dark"] == [] and two["agent_dark"] == []
    assert "C:\\Users\\user\\.kimi (kimi) -> A1" in discover.render_text(one)


TERM = ("9", "4", "cmd.exe", "C:\\Windows\\System32\\cmd.exe")
ROOT_ROW = ("10", "9", "agent.exe", "C:\\Users\\user\\AppData\\Local\\agent\\agent.exe")
SHELL_ROW = ("11", "10", "cmd.exe", "C:\\Windows\\System32\\cmd.exe")
CMD_ROW = ("12", "11", "git.exe", "C:\\Program Files\\Git\\cmd\\git.exe")
HELPER = ("10", "9", "agent.exe", "C:\\Users\\user\\AppData\\Local\\agent\\agent.exe", "agent.exe --type=utility")


@pytest.mark.parametrize("rows, tcp, roots", [
    ([TERM, ROOT_ROW, SHELL_ROW, CMD_ROW], [], [10]),
    ([TERM, ("10", "9", "agent.exe", "C:\\Program Files\\agent\\agent.exe"), SHELL_ROW, CMD_ROW], [], []),
    ([TERM, ("10", "9", "bash.exe", "C:\\Users\\user\\bin\\bash.exe"), SHELL_ROW, CMD_ROW], [], []),
    ([TERM, ("10", "9", "mintty.exe", "C:\\Users\\user\\AppData\\Local\\Programs\\Git\\usr\\bin\\mintty.exe"),
      SHELL_ROW, CMD_ROW], [], []),
    ([TERM, ROOT_ROW, SHELL_ROW], [], []),
    ([TERM, ROOT_ROW, SHELL_ROW, ("12", "11", "powershell.exe", "C:\\Windows\\powershell.exe")], [], []),
    ([TERM, ROOT_ROW, ("11", "10", "git.exe", "C:\\Program Files\\Git\\cmd\\git.exe"),
      ("12", "11", "x.exe", "C:\\x.exe")], [], []),
    ([TERM, ROOT_ROW, SHELL_ROW, CMD_ROW], [("192.0.2.5", "50000", "203.0.113.9", "443", "Established", "10")], []),
    ([TERM, ROOT_ROW, ("13", "10", "helper.exe", "C:\\h.exe"), SHELL_ROW, CMD_ROW],
     [("192.0.2.5", "50000", "203.0.113.9", "443", "Established", "13")], [10]),
    ([TERM, ("10", "9", "agent.exe", "D:\\Profiles\\user\\AppData\\Roaming\\a\\agent.exe"), SHELL_ROW, CMD_ROW],
     [], [10]),
    # G-1a: the root's own parent is a listed shell or launcher
    ([("9", "4", "explorer.exe", "C:\\Windows\\explorer.exe"), ROOT_ROW, SHELL_ROW, CMD_ROW], [], []),
    ([("9", "4", "mintty.exe", "C:\\Program Files\\Git\\usr\\bin\\mintty.exe"), ROOT_ROW, SHELL_ROW, CMD_ROW],
     [], [10]),
    ([ROOT_ROW, SHELL_ROW, CMD_ROW], [], []),                                       # parent not in the records
    # G-1b: --type= is neither a root nor a hop
    ([TERM, HELPER, SHELL_ROW, CMD_ROW], [], []),
    ([TERM, ROOT_ROW, SHELL_ROW, ("12", "11", "x.exe", "C:\\x.exe", "x.exe --type=renderer"),
      ("13", "12", "git.exe", "C:\\Program Files\\Git\\cmd\\git.exe")], [], []),
    # G-1c: the first hop is a shell, and the command is not under the root's own directory
    ([TERM, ROOT_ROW, SHELL_ROW, ("12", "11", "tool.exe", "C:\\Users\\user\\AppData\\Local\\agent\\bin\\tool.exe")],
     [], []),
    ([TERM, ROOT_ROW, SHELL_ROW, ("12", "11", "tool.exe", "C:\\Users\\user\\AppData\\Local\\agent\\bin\\tool.exe"),
      ("13", "11", "git.exe", "C:\\Program Files\\Git\\cmd\\git.exe")], [], [10]),
    ([TERM, ROOT_ROW, ("11", "10", "helper.exe", "C:\\Users\\user\\AppData\\Local\\agent\\helper.exe"),
      ("12", "11", "cmd.exe", "C:\\Windows\\System32\\cmd.exe"), ("13", "12", "git.exe", "C:\\git.exe")], [], []),
], ids=["positive", "program-files", "shell-looking-name", "terminal-host", "idle-shell", "shell-under-shell-only",
        "no-shell-in-chain", "root-talks", "talks-through-a-child", "appdata-elsewhere", "g1a-gui-parent",
        "g1a-launcher-parent", "g1a-no-parent", "g1b-helper-root", "g1b-helper-hop", "g1c-own-tool-only",
        "g1c-own-tool-and-a-command", "g1c-non-shell-hop"])
def test_m50b_e3_each_act_root_criterion(rows, tcp, roots):
    inv = discover.run(win_texts((1, [SYS] + rows, [LISTEN_ROW] + tcp)), CATALOG)
    assert [a["pid"] for a in inv["act_roots"]] == roots
    if tcp and not roots:
        assert [c["pid"] for c in inv["candidates"]] == [10]   # a root that talks is a candidate instead
    for a in inv["act_roots"]:
        assert a["launched_by"]["pid"] == 9 and a["launched_by"]["cites"]


def test_g2_linux_places_by_the_exe_link_with_argv0_as_the_fallback():
    def run(argv0, exe=None, unread=None, self_pid=None):
        return inv_of(proc=procs(proc(9, 1, ["/bin/bash"]), proc(10, 9, [argv0], exe=exe, unread=unread),
                                 proc(11, 10, ["/bin/bash", "-c", "ls"]), proc(12, 11, ["ls"]), self_pid=self_pid),
                      ss=ss(listen=(("0.0.0.0:22", "sshd", 1),)))
    assert [a["image"] for a in run("/home/u/.local/bin/agent")["act_roots"]] == ["agent"]     # argv[0] fallback
    assert [a["image"] for a in run("/root/.local/bin/agent")["act_roots"]] == ["agent"]
    assert run("agent")["act_roots"] == []                  # through PATH, no exe link: not placed (an evasion line)
    assert [a["exe"] for a in run("agent", exe="/home/u/.local/bin/agent")["act_roots"]] == ["/home/u/.local/bin/agent"]
    assert run("/home/u/.local/bin/agent", exe="/usr/bin/python3.12")["act_roots"] == []      # the link decides
    assert run("/usr/local/bin/agent")["act_roots"] == []
    inv = run("agent", unread=["exe"])
    assert inv["act_roots"] == [] and ("act-root could not place 1 process(es) (exe unreadable): their argv[0], which"
                                       " a process writes itself, is used instead: pid 10 (proc:3)") in inv["holes"]
    # the reader's own tree is never evidence: a shell whose only command is the reader makes no chain
    inv = inv_of(proc=procs(proc(9, 1, ["/bin/bash"]), proc(10, 9, ["/home/u/bin/term"]), proc(11, 10, ["/bin/bash"]),
                            proc(12, 11, ["python3", "-m", "raqib", "discover"]), self_pid=12),
                 ss=ss(listen=(("0.0.0.0:22", "sshd", 1),)))
    assert inv["act_roots"] == []


@pytest.mark.skipif(sys.platform == "win32", reason="the live reader is Linux-only; readlink differs on Windows")
def test_g2_snapshot_proc_writes_the_exe_link_or_null_and_unread(tmp_path):
    if not can_symlink(tmp_path):
        pytest.skip("the exe link needs symlinks")
    root = tmp_path / "proc"
    fake_proc(root, [(50, 1, "agent", b"agent\0"), (51, 50, "bash", b"/bin/bash\0")])
    os.symlink(str(tmp_path / "home" / "agent"), str(root / "50" / "exe"))
    by = {o["pid"]: o for o in map(json.loads, discover.snapshot_proc(str(root), AT, None).splitlines()[1:])}
    assert (by[50]["exe"], "exe" in by[50]["unread"]) == (str(tmp_path / "home" / "agent"), False)
    assert (by[51]["exe"], "exe" in by[51]["unread"]) == (None, True)
    (rec,) = [r for r in discover.parse_proc(discover.snapshot_proc(str(root), AT, None))[0] if r.get("pid") == 51]
    assert rec["exe"] == "/bin/bash"                         # argv[0] when the link could not be read


def test_g2_the_linux_agent_positive_is_placed_by_its_exe():
    inv = from_dir(AGENT)
    (a,) = inv["act_roots"]
    assert (a["image"], a["exe"], a["user_dir"], a["launched_by"]["image"]) == (
        "agent", "/home/user/.local/bin/agent", "/home/*/*", "bash")
    assert [h["commands"] for h in a["chains"]] == [["curl"]] and a["cites"][0]["line"] == 9
    assert json.loads(lines_of(AGENT / "proc.txt")[8])["argv"][0] == "agent"   # run through PATH
    assert [r["endpoint"][0]["vendor"] for r in inv["recent_talk"]] == ["anthropic"]
    assert inv["candidates"] == [] and inv["exit"] == 1 and inv["complete"]


def test_m50b_e3_act_roots_are_not_judged_without_a_connection_record():
    inv = inv_of(proc=procs(proc(10, 1, ["/home/u/bin/agent"]), proc(11, 10, ["/bin/bash"]), proc(12, 11, ["ls"])))
    assert inv["act_roots"] == [] and inv["result"] == "incomplete"
    assert any(h.startswith("act-root not judged: no process source and connection source both hold records")
               for h in inv["holes"])
    assert from_dir(KIMI1)["act_roots"] and not any(h.startswith("act-root not judged") for h in from_dir(KIMI1)["holes"])


def test_g1_the_benign_set_holds_ide_terminals_running_commands_and_measures_0():
    win, lin = from_dir(BENIGN_WINDOWS), from_dir(BENIGN_LINUX)
    assert win["act_roots"] == [] and lin["act_roots"] == []
    texts = {s["name"]: lines_of(s["path"]) for s in win["sources"]}
    rows = {r.split('","')[0].strip('"'): r for r in texts["win-process-1"][2:] if r}
    assert "--type=utility" in rows["6060"] and "ptyHost" in rows["6060"]       # Code.exe ptyHost
    assert rows["6070"].startswith('"6070","6060","powershell.exe"') and rows["6075"].startswith('"6075","6070","node.exe"')
    idea = [json.loads(x) for x in lines_of(BENIGN_LINUX / "proc.txt") if '"pid": 18' in x]
    assert {(o["pid"], o["ppid"], o["name"]) for o in idea} >= {(1800, 1700, "idea"), (1820, 1800, "bash"),
                                                                (1825, 1820, "make"), (1830, 1825, "cc")}
    assert all(o["exe"].startswith(("/home/user/.local/", "/usr/bin/")) for o in idea)


def test_g1_each_narrowing_is_what_keeps_an_ide_terminal_out(tmp_path):
    """Without --type= the VS Code pty host still has a GUI parent (Code.exe), so it is not an act-root; with
    both gone it is one: (a) and (b) each hold the line. The JetBrains IDE is kept out by (a) alone."""
    d = copy_fixture(BENIGN_WINDOWS, tmp_path)

    def edit(old, new):
        for k in (1, 2):
            path = d / ("win-process-%d.csv" % k)
            text = path.read_text(encoding="ascii")
            assert old in text
            path.write_text(text.replace(old, new), encoding="ascii", newline="\n")
    edit("--type=utility --utility-sub-type=node.mojom.NodeService --lang=en-US --service-sandbox-type=none"
         " --vscode-utility-kind=ptyHost", "--vscode-utility-kind=ptyHost")
    assert from_dir(d)["act_roots"] == []
    edit('"6060","6000","Code.exe"', '"6060","5400","Code.exe"')               # its parent now a ... systray
    assert from_dir(d)["act_roots"] == []
    edit('"5400","5100","SecurityHealthSystray.exe"', '"5400","5100","cmd.exe"')   # ... now a shell
    assert [(a["pid"], a["image"]) for a in from_dir(d)["act_roots"]] == [(6060, "code")]
    lin = copy_fixture(BENIGN_LINUX, tmp_path, "lin")
    text = (lin / "proc.txt").read_text(encoding="ascii").replace('"pid": 1800, "ppid": 1700', '"pid": 1800, "ppid": 1530')
    (lin / "proc.txt").write_text(text, encoding="ascii", newline="\n")
    assert [(a["pid"], a["image"]) for a in from_dir(lin)["act_roots"]] == [(1800, "idea")]


def test_m50b_e3_act_root_is_a_signature_with_its_evasions_and_budget():
    spec = CATALOG["act_root"]
    assert (spec["kind"], spec["status"], spec["fp_budget"]) == ("signature", "ok", 0.25)
    evasion = " ".join(spec["evasion"])
    for phrase in ("Program Files", "a shell-looking name", "talking through a child", "argv[0]",
                   "launch from a GUI launcher", "a --type= argument",                       # G-1a, G-1b
                   "a blank image path", "a non-shell hop", "acts inside the shell", "builtins, cmdlets and"
                   " redirections", "wsl, a VM or a container", "trade a masquerade for fewer false positives"):  # G-7
        assert phrase in evasion, phrase
    assert set(spec["shells"]) <= set(CATALOG["acts"]) and "explorer" in spec["not_images"]
    assert set(spec["launchers"]) == {"conhost", "mintty", "kitty", "wezterm", "wezterm-gui", "alacritty",
                                      "gnome-terminal-server", "tmux", "screen"}             # G-1a, the ruling's list
    assert "~/*" not in spec["user_dirs"] and "/root/*" in spec["user_dirs"]                  # G-10
    assert [(p["dir"], p["expect"], p["name"], p["cite"]) for p in spec["positive"]] == [
        ("tests/fixtures/discover/kimi/one-sample", "act_root", "kimi", "win-process-1:12"),
        ("tests/fixtures/discover/kimi/two-samples", "promoted", "kimi", "win-tcp-2:7"),
        ("tests/fixtures/discover/linux-agent", "act_root", "agent", "proc:9")]
    assert spec["negative"] == ["tests/fixtures/discover/benign/linux-desktop",
                                "tests/fixtures/discover/benign/windows-desktop"]


@pytest.mark.parametrize("change, error", [
    ((r"act_root:\n  kind: signature", "act_root:\n  kind: anchor"), "act_root.kind: must be signature"),
    ((r"  fp_budget: 0\.25", "  fp_budget: 1.5"), "act_root.fp_budget"),
    ((r"  fp_budget: 0\.25", "  fp_budget: true"), "act_root.fp_budget"),
    ((r'user_dirs: \["\?:/users', 'user_dirs: ["?:/Users'), "act_root.user_dirs"),
    ((r"  shells: \[.*\]", "  shells: []"), "act_root.shells"),
    ((None, None), "act_root.evasion: a signature must list"),
    ((r"    negative:\n(      - .*\n)+", "    negative: []\n"), "act_root.fixtures: a budget is measured"),
    ((r"dir: tests/fixtures/discover/kimi/one-sample,", "dir: /abs/one-sample,"), "act_root.fixtures.positive[0]"),
    ((r"act_root: kimi, cite", "act_root: Kimi, cite"), "act_root.fixtures.positive[0]"),
    ((r', cite: "win-process-1:12"\}', "}"), "act_root.fixtures.positive[0]"),
    ((r'cite: "win-process-1:12"', 'cite: "win-process-1"'), "act_root.fixtures.positive[0]"),
    ((r'cite: "win-process-1:12"', 'cite: "bogus:12"'), "act_root.fixtures.positive[0]"),
    ((r"  status: ok", "  status: active"), "act_root.status: must be one of ok|disabled"),
    ((r"  launchers: \[.*\]", "  launchers: [Tmux]"), "act_root.launchers"),
    ((r"      - tests/fixtures/discover/benign/linux-desktop", "      - ../outside"), "act_root.fixtures.negative[0]"),
    ((r"\nact_root:\n", "\nact_roots:\n"), "act_root: missing"),
], ids=["kind", "budget-range", "budget-bool", "glob-case", "no-shells", "no-evasion", "no-negative",
        "absolute-dir", "name-case", "no-cite", "cite-no-line", "cite-no-source", "status", "launchers-case",
        "dotdot", "missing"])
def test_m50b_e3_catalog_rejects_a_bad_act_root(tmp_path, change, error):
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    if change[1] is None:   # act_root's own evasion list, emptied, then dropped
        head, tail = text.split("\nact_root:\n", 1)
        changed = head + "\nact_root:\n" + re.sub(r"  evasion:\n(    - .*\n)+", "  evasion: []\n", tail, count=1)
        dropped = head + "\nact_root:\n" + re.sub(r"  evasion:\n(    - .*\n)+", "", tail, count=1)
        (tmp_path / "dropped.yaml").write_text(dropped, encoding="utf-8")
        with pytest.raises(discover.CatalogError, match="act_root: must hold kind"):
            discover.load_catalog(str(tmp_path / "dropped.yaml"))
    else:
        changed = re.sub(change[0], lambda m: change[1], text, count=1)
    assert changed != text
    path = tmp_path / "endpoints.yaml"
    path.write_text(changed, encoding="utf-8")
    with pytest.raises(discover.CatalogError) as exc:
        discover.load_catalog(str(path))
    assert error in str(exc.value)


# E4: --check, the first fp numbers

def test_m50b_e4_check_measures_candidates_and_act_roots_per_fixture():
    code, text = raqib("discover", "--check")
    assert code == 0, text
    report = discover.check(CATALOG, str(ROOT))
    rows = {r["dir"].replace("tests/fixtures/discover/", ""): r for r in report["fixtures"]}
    assert {k: ([c["image"] for c in r["candidates"]], [a["image"] for a in r["act_roots"]], r["verdict"])
            for k, r in rows.items()} == {
        "kimi/one-sample": (["explorer"], ["kimi"], "found: an act-root kimi citing win-process-1:12"),
        "kimi/two-samples": (["explorer", "kimi"], [], "found: kimi a candidate citing win-tcp-2:7, not an act-root"),
        "linux-agent": ([], ["agent"], "found: an act-root agent citing proc:9"),
        "benign/linux-desktop": (["jetbrains-toolbox", "code", "firefox"], [], "measured"),
        "benign/windows-desktop": (["explorer", "code"], [], "measured")}
    act, anchor = report["classes"]
    assert (act["status"], act["verdict"], act["fp_rate"], act["fp_budget"], act["measured"], act["found"]) == (
        "ok", "ok", 0.0, 0.25, 2, 3)
    assert (anchor["verdict"], anchor["fp_rate"], anchor["fp_budget"], anchor["fired"]) == ("no-budget", 1.0, None, 2)
    assert "act-root    signature  ok        ok               0.000    0.25" in text
    assert "candidate   anchor     -         no-budget        1.000    none" in text
    assert text.endswith("RESULT: OK (exit 0)\n")
    code, out = raqib("discover", "--check", "--json")
    assert code == 0 and json.loads(out)["classes"][0]["verdict"] == "ok"


def _check_root(tmp_path, negatives, positives=None, status="ok"):
    """A checkout-shaped root with its own catalog copy naming these fixtures."""
    root = tmp_path / "checkout"
    (root / "tests" / "fixtures").mkdir(parents=True)
    text = Path(discover.CATALOG).read_text(encoding="utf-8").replace("  status: ok\n", "  status: %s\n" % status)
    fixtures = "  fixtures:\n    positive:\n%s    negative:\n%s" % (
        "".join('      - {dir: %s, %s: %s, cite: "%s"}\n' % p
                for p in (positives or [("p", "act_root", "kimi", "win-process-1:12")])),
        "".join("      - %s\n" % n for n in negatives))
    text = text.split("  fixtures:\n    positive:\n", 1)[0] + fixtures
    catalog = tmp_path / "endpoints.yaml"
    catalog.write_text(text, encoding="utf-8")
    shutil.copytree(str(KIMI1), str(root / "p"))
    return root, catalog


def test_m50b_e4_check_fails_over_budget(tmp_path):
    root, catalog = _check_root(tmp_path, ["a", "b", "c"])
    for name, src in (("a", BENIGN_LINUX), ("b", BENIGN_WINDOWS), ("c", KIMI1)):   # c: an act-root on a "negative"
        shutil.copytree(str(src), str(root / name))
    code, text = raqib("discover", "--check", "--fixtures-root", root, "--catalog", catalog)
    assert code == 1 and "act-root    signature  ok        over-budget      0.333    0.25" in text
    assert "measured; act-root FALSE POSITIVE" in text and text.endswith("RESULT: OVER-BUDGET (exit 1)\n")


def test_m50b_e4_check_fails_on_a_missed_positive_and_on_unmeasured_negatives(tmp_path):
    root, catalog = _check_root(tmp_path, ["n"], positives=[("p", "promoted", "kimi", "win-process-1:12")])
    shutil.copytree(str(BENIGN_WINDOWS), str(root / "n"))
    code, text = raqib("discover", "--check", "--fixtures-root", root, "--catalog", catalog)
    assert code == 1 and "MISSED: kimi a candidate citing win-process-1:12, not an act-root" in text
    assert "positive-missed" in text
    root2, catalog2 = _check_root(tmp_path / "2", ["n"])
    shutil.copytree(str(BENIGN_WINDOWS), str(root2 / "n"))
    (root2 / "n" / "win-tcp-2.csv").unlink()
    code, text = raqib("discover", "--check", "--fixtures-root", root2, "--catalog", catalog2)
    assert code == 1 and "UNMEASURED (incomplete)" in text and "act-root    signature  ok        unmeasured" in text


def test_g8_a_positive_needs_the_name_and_the_cited_line(tmp_path):
    root, catalog = _check_root(tmp_path, ["n"], positives=[("p", "act_root", "kimi", "win-process-1:13")])
    shutil.copytree(str(BENIGN_WINDOWS), str(root / "n"))
    code, text = raqib("discover", "--check", "--fixtures-root", root, "--catalog", catalog)
    assert code == 0 and "found: an act-root kimi citing win-process-1:13" in text   # bash 7768, cited in its chain
    root2, catalog2 = _check_root(tmp_path / "2", ["n"], positives=[("p", "act_root", "kimi", "win-process-1:3")])
    shutil.copytree(str(BENIGN_WINDOWS), str(root2 / "n"))
    code, text = raqib("discover", "--check", "--fixtures-root", root2, "--catalog", catalog2)
    assert code == 1 and "MISSED: an act-root kimi citing win-process-1:3" in text   # a line it does not cite
    root3, catalog3 = _check_root(tmp_path / "3", ["n"], positives=[("p", "act_root", "explorer", "win-process-1:9")])
    shutil.copytree(str(BENIGN_WINDOWS), str(root3 / "n"))
    assert raqib("discover", "--check", "--fixtures-root", root3, "--catalog", catalog3)[0] == 1   # cited, wrong name


def test_g8_status_disabled_judges_nothing_and_check_still_measures(tmp_path):
    root, catalog = _check_root(tmp_path, ["n"], status="disabled")
    shutil.copytree(str(BENIGN_WINDOWS), str(root / "n"))
    disabled = discover.load_catalog(str(catalog))
    inv = from_dir(KIMI1, catalog=disabled)
    assert inv["act_roots"] == [] and any(h.startswith("act-root not judged: act_root has status disabled")
                                          for h in inv["holes"])
    code, text = raqib("discover", "--check", "--fixtures-root", root, "--catalog", catalog)
    assert code == 0 and "found: an act-root kimi citing win-process-1:12" in text     # measured whatever its status
    assert "act-root    signature  disabled  disabled" in text and text.endswith("RESULT: DISABLED (exit 0)\n")


@pytest.mark.parametrize("argv", [
    ["--check", "--from", str(KIMI1)], ["--check", "--window", "5"], ["--check", "--read", "proc=x"],
    ["--check", "--home", "x"], ["--fixtures-root", str(ROOT)],
], ids=["from", "window", "read", "home", "root-without-check"])
def test_m50b_e4_check_usage_errors(argv):
    assert raqib("discover", *argv)[0] == 2


def test_m50b_e4_check_without_fixtures_or_with_a_missing_one_is_a_usage_error(tmp_path):
    assert raqib("discover", "--check", "--fixtures-root", tmp_path)[0] == 2
    root, catalog = _check_root(tmp_path, ["gone"])
    assert raqib("discover", "--check", "--fixtures-root", root, "--catalog", catalog)[0] == 2
    code, out = raqib("discover", "--check", "-o", tmp_path / "check.txt")
    assert code == 0 and "-> " in out and "RESULT: OK" in (tmp_path / "check.txt").read_text()


# E5 and the fixture rules (Amendment B, B-9)

def test_m50b_e5_committed_fixtures_are_what_synthetic_py_writes(tmp_path, monkeypatch):
    import runpy
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(FIX / "synthetic.py"), run_name="__main__")
    made = sorted(p.relative_to(tmp_path) for p in (tmp_path / "tests").rglob("*") if p.is_file())
    committed = sorted(p.relative_to(ROOT) for d in M50B for p in d.iterdir())
    assert made == committed and len(made) == 29
    for rel in made:
        assert (tmp_path / rel).read_bytes() == (ROOT / rel).read_bytes(), rel


@pytest.mark.parametrize("directory", M50B, ids=lambda d: d.parent.name + "-" + d.name)
def test_m50b_e5_synthetic_fixtures_carry_the_redaction_note_and_no_real_identifier(directory):
    for path in sorted(directory.iterdir()):
        data = path.read_bytes()
        assert data.isascii(), path
        text = data.decode("ascii")
        first = json.loads(text)["note"] if path.name == "run.json" else text.split("\n", 1)[0]
        assert "SYNTHETIC (not captured from a machine)" in first and "Redaction (ADR-0004 B-9)" in first, path
        assert set(re.findall(r"(?i)\\Users\\([^\\\",]+)", text)) <= {"user", "*"}, path
        assert set(re.findall(r"/home/([^/\" ,:]+)", text)) <= {"user"}, path
        for ip in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text):
            assert any(discover.ipaddress.ip_address(ip) in n for n in DOC_NETS), (path, ip)
    for r in from_dir(directory)["sources"]:
        if r["name"] == "proc-net":
            for c in parsed("proc-net", r["path"].split(" (saved from ")[0])[0]:
                if c["kind"] == "conn":
                    for ip in (c["laddr"], c["raddr"]):
                        assert any(discover.ipaddress.ip_address(ip) in n for n in DOC_NETS), ip


@pytest.mark.parametrize("directory", M50B, ids=lambda d: d.parent.name + "-" + d.name)
def test_m50b_e5_every_claim_cites_lines_that_exist(directory):
    inv = from_dir(directory)
    files = {s["name"]: lines_of(s["path"].split(" (saved from ")[0]) for s in inv["sources"] if s["text_read"]}
    groups = list(_all_cites(inv))
    assert groups and all(groups)
    for group in groups:
        for c in group:
            assert c["text"] == discover.bounded(files[c["src"]][c["line"] - 1]), c
    assert inv["complete"] and inv["problems"] == []


# --- M5.0b REDO: ADR-0004 Amendment G (docs/review/2026-11-03-M5.0b-ruling.md), each with a test -------------

def test_g4_a_blank_image_path_is_a_hole_and_places_nothing():
    rows = [SYS, ("0", "0", "System Idle Process", ""), TERM, ("10", "9", "agent.exe", ""), SHELL_ROW, CMD_ROW,
            ("20", "4", "svchost.exe", "")]
    inv = discover.run(win_texts((1, rows, [LISTEN_ROW])), CATALOG)
    assert inv["act_roots"] == []
    assert ("2 process(es) without image path (export not elevated?): act-root cannot place them: pid 10, 20"
            in inv["holes"])                                       # pids 0 and 4 never have one
    assert not any("without image path" in h for h in from_dir(KIMI1)["holes"])
    section = GUIDE.split("## Find the agents on a host (discover)")[1].split("\n## ")[0]
    assert "elevated" in section and "counted in a hole" in " ".join(section.split())


def test_g5_a_missing_sample_with_no_candidate_is_exit_3_unless_an_alarm(tmp_path):
    texts = win_texts((1, [SYS, ("50", "4", "svc.exe", "C:\\svc.exe")], [LISTEN_ROW]))
    holes = discover.window_gaps(texts, str(tmp_path), declared=2)
    inv = discover.run(texts, CATALOG, holes=holes)
    assert (inv["candidates"], inv["act_roots"], inv["alarms"], inv["result"], inv["exit"]) == ([], [], [], "incomplete", 3)
    assert any(h.startswith("sample 2: source win-process-2 not read") and h.endswith(
        "the run is incomplete (exit 3 unless an alarm)") for h in inv["holes"])
    flat = " ".join(GUIDE.split())   # M9.2: the discover section is in docs/GUIDE.md
    assert "incomplete (exit 3 unless an alarm)" in flat
    adr = " ".join((ROOT / "docs" / "specs" / "ADR-0004-agent-discovery.md").read_text(encoding="utf-8").split())
    assert "Note (2026-11-03, M5.0b REDO, G-5; corrects this item): a missing sample makes the run incomplete (exit 3" \
           " unless an alarm)" in adr


REUSED = '"ProcessId","ParentProcessId","Name","ExecutablePath","CommandLine","CreationDate"\n'


def test_g6_pid_reuse_would_have_created_a_chain(tmp_path):
    """Sample 1: pid 500 is an updater that talks. Sample 2: pid 500 is kimi, started again from cmd, running
    bash -> ping. Merged by pid alone, the updater's talk and kimi's chain would make one candidate."""
    p1 = REUSED + ('"9","4","cmd.exe","C:\\Windows\\System32\\cmd.exe","cmd","11/3/2026 8:00:00 AM"\n'
                   '"500","4","updater.exe","C:\\Users\\user\\AppData\\Local\\u\\updater.exe","u","11/3/2026 9:00:00 AM"\n')
    p2 = REUSED + ('"9","4","cmd.exe","C:\\Windows\\System32\\cmd.exe","cmd","11/3/2026 8:00:00 AM"\n'
                   '"500","9","kimi.exe","C:\\Users\\user\\.kimi-code\\bin\\kimi.exe","kimi","11/3/2026 9:00:20 AM"\n'
                   '"501","500","bash.exe","C:\\Program Files\\Git\\usr\\bin\\bash.exe","bash","11/3/2026 9:00:21 AM"\n'
                   '"502","501","PING.EXE","C:\\Windows\\System32\\PING.EXE","ping","11/3/2026 9:00:21 AM"\n')
    tcp = '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess"\n"0.0.0.0","135","0.0.0.0","0","Listen","9"\n'
    texts = {"win-process-1": ("<p1>", p1, None), "win-process-2": ("<p2>", p2, None),
             "win-tcp-1": ("<t1>", tcp + '"192.0.2.5","50000","198.51.100.7","443","Established","500"\n', None),
             "win-tcp-2": ("<t2>", tcp, None)}
    inv = discover.run(texts, CATALOG)
    assert inv["candidates"] == []                                  # the updater talks but has no child
    assert [(a["pid"], a["image"], [x["src"] for x in a["cites"]]) for a in inv["act_roots"]] == [
        (500, "kimi", ["win-process-2"])]                           # the OS pid shown, the instance cited
    assert ("pid 500 was reused within the window: CreationDate 11/3/2026 9:00:00 AM in win-process-1; CreationDate"
            " 11/3/2026 9:00:20 AM in win-process-2; keyed by pid and CreationDate, 2 processes (G-6)") in inv["holes"]
    def pids(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in discover.PID_FIELDS and isinstance(v, int):
                    yield v
                elif k in discover.PID_LISTS and isinstance(v, list):
                    yield from (x for x in v if isinstance(x, int))
                else:
                    yield from pids(v)
        elif isinstance(node, list):
            for v in node:
                yield from pids(v)
    shown = list(pids(inv))
    assert shown and all(p < discover.REUSE for p in shown)        # no internal key leaks into the inventory
    assert "pid 500 " in discover.render_text(inv) and str(500 + discover.REUSE) not in discover.render_text(inv)


def test_g6_pid_reuse_breaks_a_chain_to_a_parent_that_is_gone():
    """Sample 1: pid 9 is cmd. Sample 2: cmd is gone and pid 9 is a service; kimi, seen only in sample 2, names
    parent 9. Merged by pid alone, kimi's parent would be the cmd of sample 1, and kimi an act-root."""
    p1 = REUSED + '"9","4","cmd.exe","C:\\Windows\\System32\\cmd.exe","cmd","11/3/2026 8:00:00 AM"\n'
    p2 = REUSED + ('"9","4","svc.exe","C:\\Windows\\svc.exe","svc","11/3/2026 9:00:10 AM"\n'
                   '"500","9","kimi.exe","C:\\Users\\user\\.kimi-code\\bin\\kimi.exe","kimi","11/3/2026 8:30:00 AM"\n'
                   '"501","500","bash.exe","C:\\Program Files\\Git\\usr\\bin\\bash.exe","bash","11/3/2026 9:00:21 AM"\n'
                   '"502","501","PING.EXE","C:\\Windows\\System32\\PING.EXE","ping","11/3/2026 9:00:21 AM"\n')
    tcp = '"LocalAddress","LocalPort","RemoteAddress","RemotePort","State","OwningProcess"\n"0.0.0.0","135","0.0.0.0","0","Listen","4"\n'
    texts = {"win-process-1": ("<p1>", p1, None), "win-process-2": ("<p2>", p2, None),
             "win-tcp-1": ("<t1>", tcp, None), "win-tcp-2": ("<t2>", tcp, None)}
    assert discover.run(texts, CATALOG)["act_roots"] == []
    merged = {"win-process": ("<p>", p1 + p2.split("\n", 1)[1].split("\n", 1)[1], None), "win-tcp": ("<t>", tcp, None)}
    # the stale view: pid 9 known only as sample 1's cmd makes kimi an act-root
    assert [a["image"] for a in discover.run(merged, CATALOG)["act_roots"]] == ["kimi"]


def test_g6_a_missing_creation_date_is_a_hole():
    inv = discover.run(win_texts((1, [SYS, ("50", "4", "svc.exe", "C:\\svc.exe", "svc", "")], [LISTEN_ROW])), CATALOG)
    assert ("1 process(es) without CreationDate: a pid reused between samples cannot be told for them, so they are"
            " merged by pid (G-6): pid 50") in inv["holes"]
    assert not any("without CreationDate" in h for h in from_dir(KIMI2)["holes"])


def test_g10_read_files_are_counted_before_the_merged_beside_hole():
    code, text = raqib("discover", "--from", KIMI1, "--read", "win-process=%s" % (WINDOWS / "win-process.csv"), "--json")
    inv = json.loads(text)
    assert "win-process.csv read beside numbered samples of the same kind: merged as one more sample" in inv["holes"]
    assert "win-process" in [s["name"] for s in inv["sources"]]
    assert not any("read beside numbered samples" in h for h in from_dir(KIMI1)["holes"])


def test_g11_moonshot_hosts_are_names_only_from_vendor_docs():
    text = Path(discover.CATALOG).read_text(encoding="utf-8")
    block = text.split("# Moonshot (Kimi, Kimi Code)")[1].split("# Model API networks")[0]
    assert "host names only, no network; from vendor docs" in block and "note:" not in block
    assert not any(n["vendor"] == "moonshot" for n in CATALOG["networks"])


def test_g14_readme_names_the_benign_set_and_records_2_of_2():
    flat = " ".join(GUIDE.split("## Find the agents on a host (discover)")[1].split("\n## ")[0].split())
    for phrase in ("a JetBrains IDE under `~/.local`, each with a terminal running make -> cc",
                   "its terminal running a command (powershell -> node)", "candidates fire on 2 of 2",
                   "the anchor still declares no budget", "act-root declares fp_budget 0.25 and fires on 0 of 2",
                   "a Linux agent under `~/.local/bin`", "and reports its status", "`/proc/PID/exe`",
                   "started from a shell or a terminal host", "Electron/Chromium helper (`--type=`)"):
        assert phrase in flat, phrase
