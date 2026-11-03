"""M7.1 (HANDOFF E1-E5, ADR-0007 decision 1): Windows live discovery
in-process, raqib/hostwin.py. The Win32 API is a fake here (FakeHost): its
structures are filled in code from the synthetic Kimi fixture's rows
(tests/fixtures/discover/kimi/), so the reader runs on any system; the
real API is read only on Windows (the tests marked so, and the CI step of
the windows install job)."""
import ast
import csv
import ctypes
import datetime
import io
import ipaddress
import json
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import cli, discover, doctor, hostwin  # noqa: E402

FIX = ROOT / "tests" / "fixtures" / "discover"
KIMI1, KIMI2 = FIX / "kimi" / "one-sample", FIX / "kimi" / "two-samples"
CATALOG = discover.load_catalog()
WINDOWS = sys.platform == "win32"
SELF = 99999      # the reader's own pid in the fake runs: no process of the fixtures
AT = "2026-11-03T10:00:00.000Z"
STATE_NUMBERS = {v.upper(): k for k, v in hostwin.TCP_STATES.items()}
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def rows_of(path):
    """The data rows of a fixture CSV, as dicts (its # lines skipped)."""
    lines = [x for x in discover.decode(Path(path).read_bytes()).splitlines() if not x.startswith("#")]
    return list(csv.DictReader(io.StringIO("\n".join(lines) + "\n")))


def filetime_of(text):
    """A FILETIME for a fixture's CreationDate ("11/2/2026 8:01:02 AM", UTC here)."""
    dt = datetime.datetime.strptime(text, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=datetime.timezone.utc)
    return int((dt - EPOCH).total_seconds()) * 10 ** 7


def utf16(text):
    """A NUL-terminated UTF-16 code-unit array, as Windows keeps a PWSTR."""
    units = struct.unpack("<%dH" % (len(text.encode("utf-16-le")) // 2), text.encode("utf-16-le")) + (0,)
    return (ctypes.c_uint16 * len(units))(*units)


def be16(port):
    """A port as the TCP table holds it: network byte order in the low 16 bits."""
    return struct.unpack("<H", struct.pack(">H", port))[0]


class FakeHost:
    """The Win32 calls of hostwin, in Python, over a host described by rows:
    processes [(pid, ppid, name, image path or None, FILETIME)], tcp
    [(state, local ip, local port, remote ip, remote port, pid)], dns
    {cache name: [(record name, "A"|"AAAA", ip)]} or None (dnsapi missing).
    byref is the identity, as in tests/test_app.py's FakeWin32: a call gets
    the very ctypes object the reader passed and fills it."""

    def __init__(self, processes, tcp, dns, denied=(), query_fails=(), snapshot_fails=False, cache_fails=False,
                 grow=0):
        self.processes, self.tcp, self.dns = list(processes), list(tcp), dns
        self.denied, self.query_fails = set(denied), set(query_fails)
        self.snapshot_fails, self.cache_fails, self.grow = snapshot_fails, cache_fails, grow
        self.handles, self.closed, self.access, self.freed, self.lists_freed, self.calls = {}, [], [], [], [], []
        self.keep = []           # what the fake allocated, kept alive while the reader reads it
        self.allocated = []      # addresses DnsFree must see
        self.dns_missing = None if dns is not None else "dnsapi: no such module (fake)"
        if dns is None:
            self.DnsGetCacheDataTable = self.DnsFree = self.DnsQuery_W = self.DnsRecordListFree = None

    byref = staticmethod(lambda obj: obj)

    error = 5     # GetLastError: ERROR_ACCESS_DENIED, or ERROR_NO_MORE_FILES at the end of the snapshot

    def last_error(self):
        return self.error

    # kernel32 -----------------------------------------------------------------------------
    def CreateToolhelp32Snapshot(self, flags, pid):
        self.calls.append(("CreateToolhelp32Snapshot", flags, pid))
        if self.snapshot_fails:
            return hostwin.INVALID_HANDLE_VALUE
        self.handles[700] = {"kind": "snapshot", "next": 0}
        return 700

    def _fill(self, snap, entry):
        state = self.handles[snap]
        if state["next"] >= len(self.processes):
            self.error = hostwin.ERROR_NO_MORE_FILES
            return 0
        assert entry.dwSize == ctypes.sizeof(hostwin.PROCESSENTRY32W)
        pid, ppid, name = self.processes[state["next"]][:3]
        state["next"] += 1
        entry.th32ProcessID, entry.th32ParentProcessID = pid, ppid
        units = utf16(name)
        ctypes.memset(entry.szExeFile, 0, ctypes.sizeof(entry.szExeFile))
        for i, u in enumerate(units):
            entry.szExeFile[i] = u
        return 1

    def Process32FirstW(self, snap, entry):
        self.handles[snap]["next"] = 0
        return self._fill(snap, entry)

    def Process32NextW(self, snap, entry):
        return self._fill(snap, entry)

    def OpenProcess(self, access, inherit, pid):
        self.access.append(access)
        if pid in self.denied:
            return 0
        handle = 1000 + pid
        self.handles[handle] = {"kind": "process", "pid": pid}
        return handle

    def _proc(self, handle):
        pid = self.handles[handle]["pid"]
        return next(p for p in self.processes if p[0] == pid)

    def QueryFullProcessImageNameW(self, handle, flags, buf, size):
        p = self._proc(handle)
        if p[0] in self.query_fails or not p[3]:
            return 0
        units = utf16(p[3])
        assert len(units) <= size.value
        for i, u in enumerate(units):
            buf[i] = u
        size.value = len(units) - 1
        return 1

    def GetProcessTimes(self, handle, created, exited, kernel, user):
        created.value = self._proc(handle)[4]
        return 1

    def CloseHandle(self, handle):
        assert handle in self.handles, handle
        self.closed.append(handle)
        del self.handles[handle]
        return 1

    # iphlpapi -----------------------------------------------------------------------------
    def GetExtendedTcpTable(self, buf, size, order, family, table, reserved):
        assert table == hostwin.TCP_TABLE_OWNER_PID_ALL and reserved == 0
        rows = []
        for state, laddr, lport, raddr, rport, pid in self.tcp:
            v6 = ipaddress.ip_address(laddr).version == 6
            if v6 != (family == hostwin.AF_INET6):
                continue
            if v6:
                r = hostwin.MIB_TCP6ROW_OWNER_PID()
                r.ucLocalAddr[:] = list(ipaddress.IPv6Address(laddr).packed)
                r.ucRemoteAddr[:] = list(ipaddress.IPv6Address(raddr).packed)
            else:
                r = hostwin.MIB_TCPROW_OWNER_PID()
                r.dwLocalAddr = struct.unpack("<I", ipaddress.IPv4Address(laddr).packed)[0]
                r.dwRemoteAddr = struct.unpack("<I", ipaddress.IPv4Address(raddr).packed)[0]
            r.dwLocalPort, r.dwRemotePort = be16(lport), be16(rport)
            r.dwState, r.dwOwningPid = state, pid
            rows.append(bytes(r))
        data = struct.pack("<I", len(rows)) + b"".join(rows)
        if self.grow:
            self.grow -= 1
            size.value = len(data)
            return hostwin.ERROR_INSUFFICIENT_BUFFER
        if size.value < len(data):
            size.value = len(data)
            return hostwin.ERROR_INSUFFICIENT_BUFFER
        ctypes.memmove(buf, data, len(data))
        return hostwin.NO_ERROR

    # dnsapi -------------------------------------------------------------------------------
    def DnsGetCacheDataTable(self, head):
        if self.cache_fails:
            return 0
        prev = None
        for name in reversed(list(self.dns)):
            entry = hostwin.DNS_CACHE_ENTRY()
            text = utf16(name)
            self.keep += [entry, text]
            entry.pszName = ctypes.addressof(text)
            entry.wType = hostwin.DNS_TYPE_A
            if prev is not None:
                entry.pNext = ctypes.pointer(prev)
            self.allocated += [ctypes.addressof(text), ctypes.addressof(entry)]
            prev = entry
        if prev is not None:
            head.contents = prev
        return 1

    def DnsFree(self, address, kind):
        """Frees as Windows would: the memory is no longer the entry, so a
        reader that follows pNext after this reads zeros, not the list."""
        assert kind == hostwin.DNS_FREE_FLAT
        address = address.value if isinstance(address, ctypes.c_void_p) else address
        assert address in self.allocated and address not in self.freed, "freed twice or not ours"
        self.freed.append(address)
        size = next(ctypes.sizeof(o) for o in self.keep if ctypes.addressof(o) == address)
        ctypes.memset(address, 0, size)

    def DnsQuery_W(self, name, rtype, options, extra, head, reserved):
        assert options == hostwin.DNS_QUERY_NO_WIRE_QUERY, "the cache only, never the wire"
        want = {hostwin.DNS_TYPE_A: "A", hostwin.DNS_TYPE_AAAA: "AAAA"}[rtype]
        recs = [r for r in self.dns.get(name, []) if r[1] == want]
        if not recs:
            return 9701    # DNS_INFO_NO_RECORDS
        prev = None
        for rec_name, kind, ip in reversed(recs):
            r = hostwin.DNS_RECORDW()
            text = utf16(rec_name)
            self.keep += [r, text]
            r.pName, r.wType = ctypes.addressof(text), rtype
            packed = ipaddress.ip_address(ip).packed
            r.wDataLength = len(packed)
            for i, b in enumerate(packed):
                r.Data.bytes[i] = b
            if prev is not None:
                r.pNext = ctypes.pointer(prev)
            prev = r
        head.contents = prev
        return 0

    def DnsRecordListFree(self, head, kind):
        assert kind == hostwin.DNS_FREE_RECORD_LIST
        self.lists_freed.append(ctypes.addressof(head.contents))


def host_of(directory, k):
    """A FakeHost holding sample k of a fixture directory's CSV rows."""
    procs = [(int(r["ProcessId"]), int(r["ParentProcessId"]), r["Name"], r["ExecutablePath"] or None,
              filetime_of(r["CreationDate"])) for r in rows_of(directory / ("win-process-%d.csv" % k))]
    tcp = [(STATE_NUMBERS[r["State"].upper()], r["LocalAddress"], int(r["LocalPort"]), r["RemoteAddress"],
            int(r["RemotePort"]), int(r["OwningProcess"])) for r in rows_of(directory / ("win-tcp-%d.csv" % k))]
    dns = {}
    for r in rows_of(directory / ("win-dns-%d.csv" % k)):
        recs = dns.setdefault(r["Entry"], [])
        if r["RecordType"] in ("A", "AAAA"):
            recs.append((r["RecordName"], r["RecordType"], r["Data"]))
    return FakeHost(procs, tcp, dns)


class Samples:
    """A fake API that serves sample 1, 2, ... of a fixture directory, one per snapshot."""

    def __init__(self, directory, n):
        self.hosts = [host_of(directory, k) for k in range(1, n + 1)]
        self.k = 0

    def __getattr__(self, name):
        return getattr(self.hosts[max(self.k - 1, 0)], name)

    def CreateToolhelp32Snapshot(self, *a):
        self.k += 1
        return self.hosts[self.k - 1].CreateToolhelp32Snapshot(*a)


def expected_text(path, kind):
    """The fixture's CSV as the API can give it: CommandLine and CreationTime
    empty (the API gives neither: one hole), CreationDate as the ISO time of
    its FILETIME."""
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\n")
    rows = rows_of(path)
    w.writerow(list(rows[0]))
    for r in rows:
        if kind == "win-process":
            # pid 0 (Idle) is never opened, so it has no creation time live (Q-5)
            r = dict(r, CommandLine="", CreationDate="" if r["ProcessId"] == "0" else
                     hostwin.filetime(filetime_of(r["CreationDate"])))
        if kind == "win-tcp":
            r = dict(r, CreationTime="")
        w.writerow(list(r.values()))
    return out.getvalue()


def comparable(records):
    """Records without where they were read (src, line, text): what they say."""
    out = []
    for r in records:
        if r["kind"] == "snapshot":
            continue
        out.append(json.dumps({k: v for k, v in r.items() if k not in ("src", "line", "text")}, sort_keys=True,
                              default=str))
    return sorted(out)


def live(directory, n, self_pid=SELF, sleeps=None):
    api = Samples(directory, n)
    texts, holes, info = hostwin.collect(api, n, 10, self_pid, (sleeps or []).append, now=lambda: AT)
    return texts, holes, info, api


def strip_cites(node):
    if isinstance(node, dict):
        return {k: strip_cites(v) for k, v in node.items() if k not in ("cites", "summary", "talk")}
    if isinstance(node, list):
        return [strip_cites(v) for v in node]
    return node


# --- E1, E2: a sample is the CSV parsers' records ----------------------------------------------

@pytest.mark.parametrize("directory, n", [(KIMI1, 1), (KIMI2, 2)], ids=["kimi-one-sample", "kimi-two-samples"])
def test_e2_fake_api_from_the_kimi_fixture_yields_the_csv_records(directory, n):
    texts, _, _, _ = live(directory, n)
    assert sorted(texts) == sorted("%s-%d" % (kind, k) for k in range(1, n + 1)
                                   for kind in ("win-process", "win-tcp", "win-dns"))
    for name, (label, text, error) in texts.items():
        kind, k = discover.split_name(name)
        assert error is None and text.isascii() and label.startswith("live: ")
        got, problems = discover.PARSERS[kind](text, name)
        want, _ = discover.PARSERS[kind](expected_text(directory / ("%s.csv" % name), kind), name)
        assert problems == [] and comparable(got) == comparable(want), name
        assert got, name


@pytest.mark.parametrize("directory, n", [(KIMI1, 1), (KIMI2, 2)], ids=["kimi-one-sample", "kimi-two-samples"])
def test_e2_the_live_inventory_is_the_fixture_inventory(directory, n):
    """One path to the inventory: the live texts and the fixture's CSVs give
    the same candidates, act-roots, recent talk and footprints (cites aside:
    they name the live sources' lines)."""
    texts, holes, _, _ = live(directory, n)
    footprints = ("footprints", discover.decode((directory / "footprints.txt").read_bytes()), None)
    got = discover.run(dict(texts, footprints=footprints), CATALOG, holes=holes, live=True)
    want_texts, want_holes = discover.read_dir(str(directory))
    want = discover.run(want_texts, CATALOG, holes=want_holes)
    for key in ("candidates", "act_roots", "recent_talk", "endpoint_talkers", "footprints", "agent_dark",
                "result", "exit", "alarms"):
        assert strip_cites(got[key]) == strip_cites(want[key]), key
    assert got["candidates"] and got["recent_talk"] and got["result"] == "alarm"
    assert [s for s in got["sources"] if s["name"].startswith("win-")] and got["self"] == [SELF]
    assert hostwin.NOT_READ in got["holes"]
    if n == 1:
        assert [a["image"] for a in got["act_roots"]] == ["kimi"]


def test_e2_a_sample_cites_the_api_and_the_reader_in_its_text():
    texts, holes, info, api = live(KIMI1, 1)
    first = texts["win-process-1"][1].splitlines()[0]
    assert first == hostwin.SNAPSHOT_LINE % (AT, SELF, 1) == discover.WIN_SNAPSHOT_LINE % (AT, SELF, 1)
    records, _ = discover.parse_win_process(texts["win-process-1"][1], "win-process-1")
    assert records[0]["kind"] == "snapshot" and records[0]["self"] == SELF and records[0]["line"] == 1
    assert "CreateToolhelp32Snapshot" in texts["win-process-1"][0] and "GetExtendedTcpTable" in texts["win-tcp-1"][0]
    assert "DnsGetCacheDataTable" in texts["win-dns-1"][0]
    assert info == {"apis": [hostwin.API_PROCESSES, hostwin.API_TCP, hostwin.API_DNS], "sample_times": [AT],
                    "seconds_apart": 10}


def test_e2_tcp_ports_are_network_byte_order_and_the_buffer_grows():
    host = FakeHost([], [(5, "192.0.2.10", 50431, "203.0.113.40", 443, 7), (2, "::", 135, "::", 0, 8)], {},
                    grow=2)
    v4, error = hostwin.tcp_table(host, hostwin.AF_INET)
    assert error is None and v4 == [("Established", "192.0.2.10", 50431, "203.0.113.40", 443, 7)]
    assert hostwin.tcp_table(host, hostwin.AF_INET6) == ([("Listen", "::", 135, "::", 0, 8)], None)
    assert hostwin.port(be16(443)) == 443 and hostwin.ipv4(struct.unpack("<I", bytes([192, 0, 2, 10]))[0]) \
        == "192.0.2.10"
    host.grow = hostwin.TCP_TRIES
    rows, error = hostwin.tcp_table(host, hostwin.AF_INET)
    assert rows == [] and "kept growing" in error


def test_e2_samples_are_taken_every_t_seconds_and_merged():
    texts, holes, info, api = live(KIMI2, 2, sleeps=[])
    sleeps = []
    hostwin.collect(Samples(KIMI2, 2), 2, 10, SELF, sleeps.append, now=lambda: AT)
    assert sleeps == [10] and info["sample_times"] == [AT, AT]
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["window"]["samples_read"] == [1, 2]
    assert any(h.startswith("window merge: the records of 2 sample(s)") for h in inv["holes"])


# --- E1 (A4): read-only, least right, handles closed --------------------------------------------

def test_e1_only_query_limited_information_and_every_handle_closed():
    texts, _, _, api = live(KIMI1, 1)
    host = api.hosts[0]
    assert host.access and set(host.access) == {hostwin.PROCESS_QUERY_LIMITED_INFORMATION} == {0x1000}
    assert host.handles == {} and 700 in host.closed       # the snapshot and every process handle
    assert host.calls == [("CreateToolhelp32Snapshot", hostwin.TH32CS_SNAPPROCESS, 0)]


def test_e1_hostwin_writes_signals_and_attaches_nothing():
    tree = ast.parse((ROOT / "raqib" / "hostwin.py").read_text(encoding="utf-8"))
    imported, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
    assert imported - {"__future__"} <= set(sys.stdlib_module_names)
    assert not imported & {"socket", "ssl", "http", "urllib", "subprocess", "signal", "asyncio", "shutil"}
    for forbidden in ("ReadProcessMemory", "WriteProcessMemory", "TerminateProcess", "DebugActiveProcess",
                      "CreateRemoteThread", "VirtualAllocEx", "OpenThread", "SuspendThread", "PROCESS_ALL_ACCESS",
                      "PROCESS_VM_READ", "PROCESS_QUERY_INFORMATION", "NtQueryInformationProcess", "open", "kill"):
        assert forbidden not in names, forbidden
    text = (ROOT / "raqib" / "hostwin.py").read_text(encoding="utf-8")
    assert text.isascii()
    assert text.count("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION") == 2   # the docstring and the one call
    # argtypes and restype on every function the Api binds
    api = ast.unparse(next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Api"))
    bound = [line.split("= fn(")[1].split(",")[1].strip().strip("'\"") for line in api.splitlines() if "= fn(" in line
             and "def fn" not in line]
    assert sorted(bound) == sorted(n for names_ in hostwin.SYMBOLS.values() for n in names_)
    assert "f.restype, f.argtypes = (restype, list(argtypes))" in api


def test_e1_dns_entries_and_names_are_freed_and_the_cache_is_never_queried_on_the_wire():
    texts, _, _, api = live(KIMI1, 1)
    host = api.hosts[0]
    assert host.allocated and sorted(host.freed) == sorted(host.allocated)
    assert len(host.lists_freed) == sum(1 for recs in host.dns.values() for t in ("A", "AAAA")
                                        if any(r[1] == t for r in recs))


# --- E1: the denied path, the empty and missing DNS path ---------------------------------------

def test_e1_denied_image_path_is_empty_and_a_counted_hole():
    host = host_of(KIMI1, 1)
    host.denied, host.query_fails = {6636}, {10728}
    texts, holes, _ = hostwin.collect(host, 1, 10, SELF, lambda s: None, now=lambda: AT)
    rows = {r["ProcessId"]: r for r in rows_of_text(texts["win-process-1"][1])}
    assert rows["6636"]["ExecutablePath"] == "" and rows["10728"]["ExecutablePath"] == ""
    assert rows["6636"]["Name"] == "explorer.exe" and rows["0"]["ExecutablePath"] == ""
    (hole,) = [h for h in holes if "image path was not read" in h]
    assert hole.startswith('2 process(es) whose image path was not read (ExecutablePath "?"') and \
        hole.endswith("pid 6636, 10728")
    assert host.handles == {} and host.closed.count(1000 + 10728) == 1     # opened, denied the query, closed
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert "2 process(es) without image path (export not elevated?): act-root cannot place them: pid 6636, 10728" \
        in inv["holes"]
    assert inv["act_roots"] == []           # kimi cannot be placed under a user directory without its path


def rows_of_text(text):
    return list(csv.DictReader(io.StringIO("\n".join(x for x in text.splitlines() if not x.startswith("#")))))


@pytest.mark.parametrize("how", ["missing", "fails"])
def test_e1_no_dns_is_a_hole_no_names(how):
    host = host_of(KIMI1, 1)
    if how == "missing":
        host = FakeHost(host.processes, host.tcp, None)
    else:
        host.cache_fails = True
    texts, holes, info = hostwin.collect(host, 1, 10, SELF, lambda s: None, now=lambda: AT)
    assert "win-dns-1" not in texts and hostwin.API_DNS not in info["apis"]
    (hole,) = [h for h in holes if h.startswith("no names: the resolver cache was not read (")]
    assert ("dnsapi: no such module (fake)" if how == "missing" else "DnsGetCacheDataTable returned FALSE") in hole
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert hole in inv["holes"] and inv["result"] == "alarm"
    (c,) = [c for c in inv["candidates"] if c["image"] == "kimi"] or [None]
    assert c is None or all(not m.get("name") for t in c["talks"] for m in t["endpoint"])


def test_e1_an_empty_cache_is_read_and_holds_no_record():
    host = host_of(KIMI1, 1)
    host.dns = {}
    texts, holes, info = hostwin.collect(host, 1, 10, SELF, lambda s: None, now=lambda: AT)
    assert texts["win-dns-1"][1].splitlines()[1] == '"' + '","'.join(hostwin.DNS_COLUMNS) + '"'
    assert not any(h.startswith("no names") for h in holes)
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert "source win-dns-1 was read and holds no record" in inv["holes"]


def test_e1_names_without_a_cached_address_are_counted():
    host = host_of(KIMI1, 1)
    host.dns = dict(host.dns, **{"gone.example.com": []})
    _, holes, _ = hostwin.collect(host, 1, 10, SELF, lambda s: None, now=lambda: AT)
    assert "1 cached name lookup(s) gave no A or AAAA record from the cache" in " ".join(holes)


# --- E3: the reader's tree; a failed snapshot ---------------------------------------------------

def test_e3_the_readers_own_tree_is_never_evidence():
    texts, holes, _, _ = live(KIMI1, 1, self_pid=10728)    # as if kimi were the reader
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    tree = {10728, 7768, 10476, 5796, 8496, 8500}
    assert inv["self"] == [10728] and inv["act_roots"] == []
    assert not any(a["pid"] in tree for c in inv["candidates"] for a in c["acts"])


def test_e3_a_failed_snapshot_refuses_the_run_and_later_ones_are_holes():
    host = host_of(KIMI1, 1)
    host.snapshot_fails = True
    with pytest.raises(hostwin.HostError, match="CreateToolhelp32Snapshot"):
        hostwin.collect(host, 2, 0, SELF, lambda s: None)
    with pytest.raises(discover.LiveRefused, match="Windows live discovery: CreateToolhelp32Snapshot"):
        discover.collect_live(CATALOG, platform="win32", homes=[], api=host, win_samples=1, sleep=lambda s: None)
    api = Samples(KIMI2, 2)
    api.hosts[1].snapshot_fails = True
    texts, holes, _ = hostwin.collect(api, 2, 0, SELF, lambda s: None, now=lambda: AT)
    assert texts["win-process-2"][1] is None and "CreateToolhelp32Snapshot" in texts["win-process-2"][2]
    assert texts["win-tcp-2"][1] is not None
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["result"] == "alarm" and any("win-process-2 not read" in x for x in inv["incomplete"])


def test_e3_cli_live_on_windows_refuses_a_failed_snapshot_in_one_line(tmp_path, monkeypatch, capsys):
    host = host_of(KIMI1, 1)
    host.snapshot_fails = True
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: host)
    code = cli.main(["discover", "--home", str(tmp_path), "--samples", "1"], out=io.StringIO())
    err = capsys.readouterr().err
    assert code == 2 and err.count("\n") == 1
    assert err.startswith("raqib: discover refused: Windows live discovery: CreateToolhelp32Snapshot")


# --- E2 (A5, A8): --save then --from --------------------------------------------------------------

def test_e2_save_then_from_gives_the_same_inventory(tmp_path, monkeypatch):
    api = Samples(KIMI2, 2)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: api)
    monkeypatch.setattr(discover.time, "sleep", lambda s: None)
    saved = tmp_path / "run"
    out = io.StringIO()
    code = cli.main(["discover", "--samples", "2", "--every", "0", "--home", str(tmp_path), "--save", str(saved),
                     "--json"], out=out)
    first = json.loads(out.getvalue())
    assert code == first["exit"] == 1
    names = sorted(os.listdir(saved))
    assert names == sorted(["footprints.txt", "run.json"] + ["%s-%d.csv" % (k, n) for n in (1, 2)
                                                           for k in ("win-process", "win-tcp", "win-dns")])
    run = json.loads((saved / "run.json").read_text())
    assert run["samples"] == 2 and run["seconds_apart"] == 0 and run["export"] == "windows-live"
    assert run["apis"] == [hostwin.API_PROCESSES, hostwin.API_TCP, hostwin.API_DNS] and len(run["sample_times"]) == 2
    assert hostwin.NOT_READ in run["holes"]
    assert run["connections_from"][0].startswith("live: iphlpapi GetExtendedTcpTable")
    monkeypatch.setattr(sys, "platform", "linux")
    out = io.StringIO()
    assert cli.main(["discover", "--from", str(saved), "--json"], out=out) == 1
    again = json.loads(out.getvalue())
    for key in ("candidates", "act_roots", "recent_talk", "footprints", "agent_dark", "result", "records", "self"):
        assert strip_cites(again[key]) == strip_cites(first[key]), key
    assert [c["cites"] for c in again["candidates"]] == [c["cites"] for c in first["candidates"]]   # the same lines
    assert ["saved run: %s" % h for h in run["holes"]] == [h for h in again["holes"] if h.startswith("saved run: ")]


def test_e2_cli_options_belong_to_their_platform(tmp_path, monkeypatch, capsys):
    assert cli.main(["discover", "--from", str(KIMI1), "--samples", "2"], out=io.StringIO()) == 2
    assert "apply to a live run" in capsys.readouterr().err
    if not WINDOWS:
        assert cli.main(["discover", "--samples", "2", "--home", str(tmp_path)], out=io.StringIO()) == 2
        assert "--samples and --every apply to a live run on Windows" in capsys.readouterr().err
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: host_of(KIMI1, 1))
    assert cli.main(["discover", "--window", "5", "--home", str(tmp_path)], out=io.StringIO()) == 2
    assert "on Windows use --samples N --every T" in capsys.readouterr().err
    for bad in (["--samples", "0"], ["--every", "-1"]):
        assert cli.main(["discover", "--home", str(tmp_path)] + bad, out=io.StringIO()) == 2
    seen = {}

    def fake_collect(catalog, **kw):
        seen.update(kw)
        return {}, [], 0
    monkeypatch.setattr(discover, "collect_live", fake_collect)
    cli.main(["discover", "--home", str(tmp_path)], out=io.StringIO())
    assert (seen["win_samples"], seen["win_every"]) == (6, 10.0) == (discover.WIN_SAMPLES, discover.WIN_EVERY)


# --- E3: doctor's host line ------------------------------------------------------------------------

@pytest.mark.parametrize("found, verdict, text", [
    ({"kernel32": None, "iphlpapi": None, "dnsapi": None}, True, "raqib discover runs live: kernel32"),
    ({"kernel32": None, "iphlpapi": None, "dnsapi": "cannot be loaded: x"}, True,
     "raqib discover runs live; names: no (kernel32"),
    ({"kernel32": None, "iphlpapi": "no symbol GetExtendedTcpTable", "dnsapi": None}, False,
     "raqib discover cannot run live: kernel32"),
], ids=["all", "no-dnsapi", "no-iphlpapi"])
def test_e3_doctor_host_line_on_windows(found, verdict, text):
    ok, line = doctor.check_host("win32", lambda: found)
    assert ok is verdict and line.startswith(text)
    for dll, name in (("kernel32", "Toolhelp32 processes"), ("iphlpapi", "GetExtendedTcpTable"),
                      ("dnsapi", "DnsGetCacheDataTable")):
        assert ("%s %s %s" % (dll, name, "OK" if found[dll] is None else "MISSING (%s)" % found[dll])) in line


def test_e3_doctor_host_line_elsewhere_and_its_place():
    assert doctor.check_host("linux") == (True, "live discovery reads /proc (raqib discover; Linux)")
    assert doctor.check_host("darwin")[0] is True
    if not WINDOWS:
        assert doctor.check_host("win32")[0] == doctor.UNSURE      # no Win32 API here to resolve
    assert doctor.check_host("win32", lambda: 1 / 0)[0] is False


def test_e3_probe_resolves_names_only():
    class Lib:
        def __init__(self, names):
            self.names = names

        def __getattr__(self, name):
            if name in self.names:
                return lambda *a: pytest.fail("probe called %s" % name)
            raise AttributeError(name)

    def loader(name):
        if name == "dnsapi":
            raise OSError("not here")
        return Lib(hostwin.SYMBOLS[name][:-1] if name == "iphlpapi" else hostwin.SYMBOLS[name])
    found = hostwin.probe(loader)
    assert found == {"kernel32": None, "iphlpapi": "no symbol GetExtendedTcpTable",
                     "dnsapi": "cannot be loaded: not here"}


# --- structures (win64) and the real API (Windows only) -------------------------------------------

def test_structure_layout_independent_of_the_host():
    assert ctypes.sizeof(hostwin.MIB_TCPROW_OWNER_PID) == 24 and ctypes.sizeof(hostwin.MIB_TCP6ROW_OWNER_PID) == 56
    assert hostwin.PROCESSENTRY32W.szExeFile.size == 2 * hostwin.MAX_PATH
    assert hostwin.filetime(filetime_of("11/2/2026 8:01:02 AM")) == "2026-11-02T08:01:02.000000Z"
    assert hostwin.filetime(0) == ""


@pytest.mark.skipif(not (WINDOWS and ctypes.sizeof(ctypes.c_void_p) == 8), reason="win64 structure sizes")
def test_win64_structure_sizes():
    assert ctypes.sizeof(hostwin.PROCESSENTRY32W) == 568
    assert ctypes.sizeof(hostwin.MIB_TCPROW_OWNER_PID) == 24
    assert ctypes.sizeof(hostwin.MIB_TCP6ROW_OWNER_PID) == 56
    assert ctypes.sizeof(hostwin.DNS_CACHE_ENTRY) == 24
    assert hostwin.DNS_RECORDW.Data.offset == 32


@pytest.mark.skipif(not WINDOWS, reason="the real Win32 API")
def test_windows_real_api_one_sample_finds_this_python_and_is_no_candidate():
    api = hostwin.Api()
    assert api.CreateToolhelp32Snapshot.argtypes and api.GetExtendedTcpTable.restype is not None
    assert doctor.check_host("win32")[0] is True
    texts, holes, info = hostwin.collect(api, 1, 0, os.getpid(), lambda s: None)
    rows = rows_of_text(texts["win-process-1"][1])
    me = [r for r in rows if r["ProcessId"] == str(os.getpid())]
    assert me and me[0]["Name"].lower().startswith("python") and me[0]["ExecutablePath"]
    assert os.path.normcase(me[0]["ExecutablePath"]) == os.path.normcase(os.path.realpath(sys.executable)) or \
        me[0]["ExecutablePath"].lower().endswith(".exe")
    assert texts["win-tcp-1"][2] is None
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["self"] == [os.getpid()]
    assert not any(c["pid"] == os.getpid() for c in inv["candidates"])
    assert not any(a["pid"] == os.getpid() for c in inv["candidates"] for a in c["acts"])


# --- E5: README ---------------------------------------------------------------------------------

def test_e5_readme_windows_discover_starts_live_and_keeps_the_loop_as_an_export():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Find the agents on a host (discover)")[1].split("\n## ")[0]
    windows = section[section.index("On Windows, "):]
    assert windows.startswith("On Windows, `raqib discover` reads the live host in-process")
    flat = " ".join(windows.split())
    for phrase in ("`--samples N` samples (default 6) `--every T` seconds apart (default 10)",
                   "PROCESS_QUERY_LIMITED_INFORMATION", "GetExtendedTcpTable", "DnsGetCacheDataTable",
                   "the hole \"no names\"", "refuses the run in one line (exit 2)", "so `--from DIR` repeats the run"):
        assert phrase in flat, phrase
    live, export = windows.split("**Repeat from an export.**")
    assert "```powershell" not in live and export.lstrip().startswith("The PowerShell loop is kept as the fallback")
    assert "$N = 6; $T = 10" in export
    block = section.split("```bash\n")[1].split("```")[0]
    assert block.startswith("raqib discover                      # this host, live:")
    assert "--samples 3 --every 5 --save run1" in block
