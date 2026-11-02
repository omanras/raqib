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


def proc(pid, ppid, argv, env=None, cwd="/w", at=AT, sockets=None):
    return json.dumps({"pid": pid, "ppid": ppid, "name": argv[0].rsplit("/", 1)[-1][:15], "argv": argv,
                       "cwd": cwd, "env_keys": env, "sockets": sockets, "at": at})


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
        87, "claude", "/opt/claude-code/bin/claude", "/home/claude", 8)
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
    # ADR-0004: the first field test runs with no prior knowledge of Kimi's endpoints
    assert not any("moonshot" in h or "kimi" in h for h in hosts)


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
        ("/root/.claude", claude), ("/root/.claude.json", claude), ("/home/claude/.claude", claude)]


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
    texts, holes = discover.collect_live(CATALOG, platform="win32", homes=[str(tmp_path)])
    assert set(texts) == {"footprints"} and "no live process or connection reader on win32" in holes[0]
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
    texts, holes = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root))
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
    texts, holes = discover.collect_live(CATALOG, window=2, homes=[], platform="linux", proc_root=str(root),
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
    texts, holes = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root), ss_paths=(missing,))
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
    texts, holes = discover.collect_live(CATALOG, window=2, homes=[], platform="linux", proc_root=str(root),
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
    texts, holes = discover.collect_live(CATALOG, homes=[str(tmp_path)])
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
    texts, holes = discover.collect_live(CATALOG, homes=[], platform="linux", proc_root=str(root),
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
    texts, holes = discover.collect_live(CATALOG, window=1, homes=[], platform="linux", proc_root=str(root),
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
    monkeypatch.setattr(discover, "collect_live", lambda *a, **k: (texts, ["a live hole"]))
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
    section = README.split("## Find the agents on a host (discover)")[1].split("\n## ")[0]
    flat = " ".join(section.split())
    assert "/rd:true" in section                                             # B-5
    for phrase in ("IDE terminals", "package managers", "CI runners", "loopback", "no fp_budget"):   # B-8
        assert phrase in flat, phrase
    for phrase in ("liveness", "sibling", "reparent", "TCP only", "QUIC", "unix-socket", "namespace", "hidepid"):
        assert phrase in flat, phrase                                        # B-4
    assert "/proc/net/tcp" in flat and "absolute path" in flat               # B-1
    assert "AppData\\Roaming\\Claude" in section                              # D12
    assert ".git/hooks" in flat                                              # D8
