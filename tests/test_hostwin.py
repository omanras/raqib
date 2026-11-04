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
STATE_NUMBERS["BOUND"] = None
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
DNS_INFO_NO_RECORDS = 9501       # windns.h (A-13); 9701 is DNS_ERROR_RECORD_DOES_NOT_EXIST


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
        self.null_entries = 0          # A-1: cache entries whose pszName is NULL
        self.negative = set()          # A-2: names answered with a non-zero status AND a record list
        self.tcp_fails = set()         # A-10: the address families whose GetExtendedTcpTable returns an error
        self.tcp_raises = None         # A-6: an exception raised inside the TCP step
        self.reused = {}               # A-8: pid -> the image path another process holds under it
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
        units = utf16(self.reused.get(p[0], p[3]))
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
        if self.tcp_raises is not None:
            raise self.tcp_raises
        if family in self.tcp_fails:
            return 50       # ERROR_NOT_SUPPORTED
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
        for name in reversed(list(self.dns) + [None] * self.null_entries):
            entry = hostwin.DNS_CACHE_ENTRY()
            self.keep.append(entry)
            if name is not None:
                text = utf16(name)
                self.keep.append(text)
                entry.pszName = ctypes.addressof(text)
                self.allocated.append(ctypes.addressof(text))
            entry.wType = hostwin.DNS_TYPE_A
            if prev is not None:
                entry.pNext = ctypes.pointer(prev)
            self.allocated.append(ctypes.addressof(entry))
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
        if name in self.negative:      # a negative answer handed back with a list (its SOA, here an A)
            r = hostwin.DNS_RECORDW()
            text = utf16(name)
            self.keep += [r, text]
            r.pName, r.wType, r.wDataLength = ctypes.addressof(text), hostwin.DNS_TYPE_A, 4
            r.Data.bytes[:4] = [192, 0, 2, 99]
            head.contents = r
            return DNS_INFO_NO_RECORDS
        if not recs:
            return DNS_INFO_NO_RECORDS
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
            int(r["RemotePort"]), int(r["OwningProcess"])) for r in rows_of(directory / ("win-tcp-%d.csv" % k))
           if STATE_NUMBERS[r["State"].upper()] is not None]
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
    texts, holes, info = hostwin.collect(api, n, 10, self_pid, (sleeps if sleeps is not None else []).append,
                                         now=lambda: AT, clock=lambda: 0.0)
    return texts, holes, info, api


def strip_cites(node):
    """Without where a claim was read, and (M7.2) without `started`: the
    reader's own creation-time text, ISO UTC live (GetProcessTimes, ADR-0007
    A-14 Q-4) and the exporter's local CreationDate in a CSV."""
    if isinstance(node, dict):
        return {k: strip_cites(v) for k, v in node.items() if k not in ("cites", "summary", "talk", "started")}
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
                    "seconds_apart": 10, "self": [SELF], "system_drive": None}


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
    hostwin.collect(Samples(KIMI2, 2), 2, 10, SELF, sleeps.append, now=lambda: AT, clock=lambda: 0.0)
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
    # A-7: this python and, under a venv, its redirector python.exe are the reader's tree
    assert info["self"][0] == os.getpid() and inv["self"] == sorted(info["self"])
    mine = set(info["self"])
    assert not any(c["pid"] in mine for c in inv["candidates"])
    assert not any(a["pid"] in mine for c in inv["candidates"] for a in c["acts"])


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


# --- REDO, ADR-0007 Amendment A (rulings A-1..A-13; D-8: every change carries its test) ------------

def holes_of(host, samples=1):
    _, holes, _ = hostwin.collect(host, samples, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    return holes


def test_a1_dns_names_max_reached_is_a_hole_with_how_many_more(monkeypatch):
    monkeypatch.setattr(hostwin, "DNS_NAMES_MAX", 2)
    host = FakeHost([(4, 0, "System", None, 0)], [], {"a%d.example.com" % i: [] for i in range(5)})
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    assert "DNS_NAMES_MAX (2) reached: 3 more cache entr(ies) not read in every sample: their names are not" \
        " joined to an address" in holes
    assert sorted(host.freed) == sorted(host.allocated)          # the entries past the cap are still freed
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert any(h.startswith("DNS_NAMES_MAX (2) reached: 3 more") for h in inv["holes"])


def test_a1_null_names_are_skipped_and_counted():
    host = host_of(KIMI1, 1)
    host.null_entries = 2
    holes = holes_of(host)
    assert "2 cache entr(ies) with a NULL or empty name skipped in every sample" in holes
    assert sorted(host.freed) == sorted(host.allocated)
    assert not any("NULL" in h for h in holes_of(host_of(KIMI1, 1)))      # none: no hole


def test_a1_names_truncated_at_name_max_are_counted(monkeypatch):
    monkeypatch.setattr(hostwin, "NAME_MAX", 12)
    host = FakeHost([(4, 0, "System", None, 0)], [],
                    {"a-very-long-name.example.com": [("a-very-long-name.example.com", "A", "192.0.2.7")],
                     "short.ex": [("short.ex", "A", "192.0.2.8")]})
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    # the long cache name is cut (one count); its cut form is then looked up and finds no record
    (hole,) = [h for h in holes if "truncated at NAME_MAX" in h]
    assert hole.startswith("1 name(s) truncated at NAME_MAX (12 UTF-16 units) in every sample")
    assert hostwin.wstring_cut(ctypes.addressof(utf16("x" * 12)), 12) == ("x" * 12, False)
    assert hostwin.wstring_cut(ctypes.addressof(utf16("x" * 13)), 12) == ("x" * 12, True)
    monkeypatch.undo()
    assert not any("truncated" in h for h in holes_of(host_of(KIMI1, 1)))


def test_a1_processes_max_reached_is_a_hole(monkeypatch):
    monkeypatch.setattr(hostwin, "PROCESSES_MAX", 3)
    host = host_of(KIMI1, 1)
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    assert "PROCESSES_MAX (3) reached in every sample: more processes were not read (not counted: the" \
        " enumeration stops at the cap)" in holes
    assert texts["win-process-1"][2] == "Process32NextW: stopped after 3 processes (PROCESSES_MAX)"
    monkeypatch.undo()
    assert not any("PROCESSES_MAX" in h for h in holes_of(host_of(KIMI1, 1)))


def test_a2_a_record_list_with_a_nonzero_status_is_freed():
    host = FakeHost([], [], {"gone.example.com": []})
    host.negative = {"gone.example.com"}
    assert hostwin.cached_records(host, "gone.example.com", hostwin.DNS_TYPE_A) == []    # not read: status != 0
    assert len(host.lists_freed) == 1                                                    # but freed
    assert hostwin.cached_records(host, "other.example.com", hostwin.DNS_TYPE_A) == []   # NULL list: nothing to free
    assert len(host.lists_freed) == 1


def test_a3_not_read_says_the_consequence_in_one_sentence():
    flat = hostwin.NOT_READ
    assert "argv-based names and the --type helper check (G-1) are not available live" in flat
    assert "a Claude Code run as node shows as \"node\" and its footprint as AGENT-DARK beside it" in flat
    assert "the hand-off falls back to the os source" in flat
    assert flat.isascii() and flat in holes_of(host_of(KIMI1, 1))


def test_a3_the_sentence_is_true_claude_code_as_node_is_node_and_its_footprint_dark():
    """node.exe running ...\\node_modules\\@anthropic-ai\\claude-code\\cli.js: the CSV (with its
    CommandLine) names it claude; live (no CommandLine) it is "node", and ~\\.claude is AGENT-DARK."""
    cli_js = r"C:\Users\user\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js"
    host = FakeHost([(6600, 1, "explorer.exe", r"C:\Windows\explorer.exe", 1),
                     (2100, 6600, "node.exe", r"C:\Program Files\nodejs\node.exe", 2),
                     (2200, 2100, "cmd.exe", r"C:\Windows\System32\cmd.exe", 3)],
                    [(5, "192.0.2.30", 50001, "203.0.113.40", 443, 2100)], {})
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    footprints = ("footprints", "C:\\Users\\user\\.claude\n", None)
    got = discover.run(dict(texts, footprints=footprints), CATALOG, holes=holes, live=True)
    rows = rows_of_text(texts["win-process-1"][1])
    with_argv = dict(texts)
    out = io.StringIO()
    w = csv.writer(out, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writerow(hostwin.PROCESS_COLUMNS)
    for r in rows:
        w.writerow([r[c] if c != "CommandLine" or r["ProcessId"] != "2100" else '"node.exe" "%s"' % cli_js
                    for c in hostwin.PROCESS_COLUMNS])
    with_argv["win-process-1"] = ("export", out.getvalue(), None)
    want = discover.run(dict(with_argv, footprints=footprints), CATALOG, holes=holes)
    assert [d["path"] for d in got["agent_dark"]] == ["C:\\Users\\user\\.claude"]
    assert want["agent_dark"] == []
    assert [c["image"] for c in got["candidates"]] == ["node"]


def windows_fixtures():
    """Every discover fixture with win-* CSVs: (id, directory of numbered samples, sample count, the
    CSV texts as the export gives them)."""
    out = []
    for directory in sorted(FIX.rglob("*")):
        if not directory.is_dir() or not list(directory.glob("win-process*.csv")):
            continue
        out.append(pytest.param(directory, id=directory.relative_to(FIX).as_posix()))
    return out


@pytest.mark.parametrize("directory", windows_fixtures())
def test_a4_every_windows_fixture_live_gives_the_csv_inventory(directory, tmp_path):
    """A-4: the positives and the benign negatives go through the fake API. The live run gives the
    inventory of the same CSVs as the API can give them (no CommandLine, A-3) on every key, and the
    candidates, act-roots, result and exit of the export itself: the act-root budget holds live."""
    numbered = sorted(directory.glob("win-process-*.csv"))
    if numbered:
        source, n = directory, len(numbered)
    else:      # an unnumbered export (win-process.csv): the same as sample 1
        source, n = tmp_path, 1
        for kind in ("win-process", "win-tcp", "win-dns"):
            (tmp_path / ("%s-1.csv" % kind)).write_bytes((directory / ("%s.csv" % kind)).read_bytes())
    texts, holes, _, _ = live(source, n)
    footprints = ("footprints", discover.decode((directory / "footprints.txt").read_bytes()), None)
    got = discover.run(dict(texts, footprints=footprints), CATALOG, holes=holes, live=True)
    as_api = {"%s-%d" % (kind, k): ("csv", expected_text(source / ("%s-%d.csv" % (kind, k)), kind), None)
              for k in range(1, n + 1) for kind in ("win-process", "win-tcp", "win-dns")}
    want_api = discover.run(dict(as_api, footprints=footprints), CATALOG, holes=holes)
    export = {"%s-%d" % (kind, k): ("csv", discover.decode((source / ("%s-%d.csv" % (kind, k))).read_bytes()), None)
              for k in range(1, n + 1) for kind in ("win-process", "win-tcp", "win-dns")}
    want_export = discover.run(dict(export, footprints=footprints), CATALOG, holes=holes)
    for key in ("candidates", "act_roots", "recent_talk", "endpoint_talkers", "footprints", "agent_dark",
                "result", "exit", "alarms"):
        assert strip_cites(got[key]) == strip_cites(want_api[key]), key
    for key in ("candidates", "act_roots", "result", "exit"):
        assert strip_cites(got[key]) == strip_cites(want_export[key]), key
    if "benign" in directory.parts:
        assert got["act_roots"] == [] and strip_cites(got["candidates"]) == strip_cites(want_export["candidates"])


def test_a4_the_fixtures_cover_positives_and_negatives():
    ids = [p.id for p in windows_fixtures()]
    assert ids == ["benign/windows-desktop", "kimi/one-sample", "kimi/two-samples", "windows"]


def replay_check():
    """The A-5 comparison of .github/workflows/gate.yml, as CI runs it."""
    text = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    (line,) = [x.strip() for x in text.splitlines() if x.strip().startswith('python -c "import json; a, b =')]
    return line[len('python -c "'):-1]


def test_a5_ci_replay_equals_live_in_candidates_act_roots_and_holes(tmp_path, monkeypatch):
    import subprocess
    api = Samples(KIMI1, 1)      # one act-root (kimi): the comparison is not of empty lists
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: api)
    monkeypatch.setattr(discover.time, "sleep", lambda s: None)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["discover", "--samples", "1", "--every", "0", "--home", str(tmp_path), "--save", "live-run",
                     "--json", "-o", "live.json"], out=io.StringIO()) == 1
    monkeypatch.setattr(sys, "platform", "linux")
    assert cli.main(["discover", "--from", "live-run", "--json", "-o", "replay.json"], out=io.StringIO()) == 1
    code = replay_check()
    done = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True)
    assert done.returncode == 0 and done.stdout.startswith("replay == live: 1 candidate(s), 1 act-root(s)"), done
    for key, change in (("candidates", lambda v: v[:-1]), ("act_roots", lambda v: []), ("holes", lambda v: v[1:])):
        bad = json.loads((tmp_path / "live.json").read_text())
        bad[key] = change(bad[key])
        (tmp_path / "replay.json").write_text(json.dumps(bad), encoding="ascii")
        done = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True)
        assert done.returncode != 0, key
    workflow = (ROOT / ".github" / "workflows" / "gate.yml").read_text(encoding="utf-8")
    assert workflow.count("runs-on:") == 2 and workflow.count("os: [ubuntu-latest, windows-latest]") == 2


def test_a6_an_exception_inside_the_reader_says_where_and_what(tmp_path, monkeypatch, capsys):
    host = host_of(KIMI1, 1)
    host.tcp_raises = OSError("access violation reading 0x0")
    with pytest.raises(hostwin.ReaderFailed) as got:
        hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    assert str(got.value) == "live reader failed at tcp in sample 1: OSError: access violation reading 0x0"
    assert host.handles == {}          # every handle opened before the failure is closed
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: host)
    assert cli.main(["discover", "--home", str(tmp_path), "--samples", "1"], out=io.StringIO()) == 2
    err = capsys.readouterr().err
    assert err == "raqib: discover refused: live reader failed at tcp in sample 1: OSError: access violation" \
        " reading 0x0\n" and "cannot be loaded" not in err

    def no_api():
        raise OSError("no kernel32 (fake)")
    monkeypatch.setattr(hostwin, "Api", no_api)
    assert cli.main(["discover", "--home", str(tmp_path), "--samples", "1"], out=io.StringIO()) == 2
    assert capsys.readouterr().err == "raqib: discover refused: Windows live discovery: the API cannot be loaded:" \
        " no kernel32 (fake)\n"


def launched_host(reader_started=40):
    """cmd.exe (talks) -> raqib.exe -> python.exe (the venv redirector) -> python.exe (the reader, 503);
    cmd.exe also runs ping.exe, which is not the reader's."""
    return FakeHost([(6600, 1, "explorer.exe", r"C:\Windows\explorer.exe", 10),
                     (500, 6600, "cmd.exe", r"C:\Windows\System32\cmd.exe", 20),
                     (501, 500, "raqib.exe", r"C:\Users\user\venv\Scripts\raqib.exe", 30),
                     (502, 501, "python.exe", r"C:\Users\user\venv\Scripts\python.exe", 35),
                     (503, 502, "python.exe", r"C:\Python312\python.exe", reader_started),
                     (600, 500, "PING.EXE", r"C:\Windows\System32\PING.EXE", 50)],
                    [(5, "192.0.2.30", 50001, "203.0.113.40", 443, 500)], {})


def test_a7_the_readers_launchers_are_its_tree_never_acts(tmp_path, monkeypatch):
    host = launched_host()
    texts, holes, info = hostwin.collect(host, 1, 0, 503, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    assert texts["win-process-1"][1].splitlines()[0] == "# raqib-snapshot at=%s self=503,502,501 sample=1" % AT
    assert info["self"] == [503, 502, 501]
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert inv["self"] == [501, 502, 503]
    acts = [a["pid"] for c in inv["candidates"] for a in c["acts"]]
    assert acts == [600] and not {501, 502, 503} & {a["pid"] for a in inv["act_roots"]}
    # without A-7 (only the reader's pid), raqib.exe would be cmd.exe's act
    texts["win-process-1"] = (texts["win-process-1"][0],
                              texts["win-process-1"][1].replace("self=503,502,501", "self=503"), None)
    old = discover.run(texts, CATALOG, holes=holes, live=True)
    assert 501 in [a["pid"] for c in old["candidates"] for a in c["acts"]]
    # run.json carries self (A-9), and the replay keeps the launchers
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hostwin, "Api", lambda: launched_host())
    monkeypatch.setattr(discover.os, "getpid", lambda: 503)
    saved = tmp_path / "run"
    cli.main(["discover", "--samples", "1", "--home", str(tmp_path), "--save", str(saved)], out=io.StringIO())
    assert json.loads((saved / "run.json").read_text())["self"] == [503, 502, 501]
    monkeypatch.setattr(sys, "platform", "linux")
    out = io.StringIO()
    cli.main(["discover", "--from", str(saved), "--json"], out=out)
    assert json.loads(out.getvalue())["self"] == [501, 502, 503]


def test_a7_the_chain_is_unbroken_and_only_launchers():
    procs = [(1, 0, "services.exe"), (10, 1, "python.exe"), (11, 10, "cmd.exe"), (12, 11, "raqib.exe"),
             (13, 12, "pythonw3.12.exe"), (14, 13, "python.exe")]
    assert hostwin.self_tree(procs, 14) == [14, 13, 12]               # cmd.exe breaks the chain
    assert hostwin.self_tree(procs, 99) == [99]                       # not in the snapshot: itself only
    started = {14: "2026-11-03T10:00:00Z", 13: "2026-11-03T10:00:05Z"}  # a "parent" younger than its child
    assert hostwin.self_tree(procs, 14, started) == [14]
    assert [bool(hostwin.LAUNCHER.match(n)) for n in ("RAQIB.EXE", "python3.12.exe", "pythonw.exe", "py.exe",
                                                      "raqib-app.exe", "node.exe")] == [True, True, True, False,
                                                                                         True, False]
    records, problems = discover.parse_win_process(
        "# raqib-snapshot at=%s self=14,13,12 sample=1\n\"ProcessId\",\"ParentProcessId\",\"Name\"\n" % AT, "w")
    assert problems == [] and records[0]["self"] == 14 and records[0]["launchers"] == [13, 12]


def test_a8_a_pid_reused_in_the_gap_drops_path_and_time_and_is_a_hole():
    host = host_of(KIMI1, 1)
    host.reused = {10728: r"C:\Windows\System32\notepad.exe"}
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    row = next(r for r in rows_of_text(texts["win-process-1"][1]) if r["ProcessId"] == "10728")
    assert (row["Name"], row["ExecutablePath"], row["CreationDate"]) == ("kimi.exe", "", "")
    assert "1 process(es) whose pid was reused in the gap between the snapshot and OpenProcess (the image path's" \
        " name is not the snapshot's): path and creation time dropped: pid 10728" in holes
    assert not any("image path was not read" in h for h in holes)      # reused, not denied
    assert host.handles == {}
    assert hostwin.process_detail(host_of(KIMI1, 1), 10728, "KIMI.EXE")[0].endswith("kimi.exe")   # case: same name


def test_a10_an_ipv6_table_failure_is_a_hole_and_the_ipv4_rows_stand():
    host = host_of(KIMI1, 1)
    host.tcp_fails = {hostwin.AF_INET6}
    texts, holes, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    label, text, error = texts["win-tcp-1"]
    assert error is None and len(rows_of_text(text)) == sum(1 for r in host.tcp if ":" not in r[1])
    assert "IPv6 connections not read in every sample (GetExtendedTcpTable(AF_INET6) returned 50): the IPv4 rows" \
        " stand" in holes
    inv = discover.run(texts, CATALOG, holes=holes, live=True)
    assert not any("win-tcp-1" in x for x in inv["incomplete"])
    host = host_of(KIMI1, 1)
    host.tcp_fails = {hostwin.AF_INET}           # IPv4 is still the source's error: incomplete
    texts, _, _ = hostwin.collect(host, 1, 0, SELF, lambda s: None, now=lambda: AT, clock=lambda: 0.0)
    assert texts["win-tcp-1"][2] == "GetExtendedTcpTable(AF_INET) returned 50"


def test_a11_samples_are_t_seconds_apart_start_to_start():
    ticks = iter([100.0, 103.0, 110.0, 122.5, 122.5])      # sample 1 takes 3 s, sample 2 takes 12.5 s
    sleeps, times = [], iter(["t1", "t2", "t3"])
    _, _, info = hostwin.collect(host_of(KIMI1, 1), 3, 10, SELF, sleeps.append, now=lambda: next(times),
                                 clock=lambda: next(ticks))
    assert sleeps == [7.0, 0.0] and info["sample_times"] == ["t1", "t2", "t3"] and info["seconds_apart"] == 10


def test_a12_doctor_host_on_macos_is_unsure_homes_only():
    assert doctor.check_host("darwin") == (doctor.UNSURE, "homes only; no live reader")


def test_a13_the_negative_answer_constant_is_named_right():
    assert DNS_INFO_NO_RECORDS == 9501
    host = FakeHost([], [], {"x.example.com": []})
    head = ctypes.POINTER(hostwin.DNS_RECORDW)()
    assert host.DnsQuery_W("x.example.com", hostwin.DNS_TYPE_A, hostwin.DNS_QUERY_NO_WIRE_QUERY, None, head,
                           None) == 9501
