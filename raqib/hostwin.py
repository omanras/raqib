"""Windows live discovery in-process (M7.1, ADR-0007 decision 1): the host's
own records of processes, TCP connections and DNS names, read through the
OS API with ctypes from the standard library, read-only.

A sample is three texts in the shapes the README's PowerShell loop writes,
so raqib/discover.py parses them with the parsers it already has and the
inventory has one path (ADR-0004 Amendment F):
- win-process-<k>.csv  Get-CimInstance Win32_Process's columns: ProcessId,
                       ParentProcessId and Name from Toolhelp32
                       (CreateToolhelp32Snapshot TH32CS_SNAPPROCESS,
                       Process32FirstW/NextW); ExecutablePath from
                       QueryFullProcessImageNameW and CreationDate from
                       GetProcessTimes, both on a handle opened with
                       PROCESS_QUERY_LIMITED_INFORMATION and nothing more
                       (empty, "?" in the hole, when it is denied);
                       CommandLine is always empty: reading it would need
                       another process's memory (A4). A first line
                       "# raqib-snapshot at=TIME self=PID sample=K" names
                       the reader's own pid, so its tree is never evidence.
- win-tcp-<k>.csv      Get-NetTCPConnection's columns, from
                       GetExtendedTcpTable (AF_INET and AF_INET6,
                       TCP_TABLE_OWNER_PID_ALL): state, local and remote
                       address and port (ports are in network byte order in
                       the table), owning pid; CreationTime is empty.
- win-dns-<k>.csv      Get-DnsClientCache's columns: the names of the
                       resolver cache (dnsapi DnsGetCacheDataTable, each
                       entry and its name freed with DnsFree), and their A
                       and AAAA records read back from the cache only
                       (DnsQuery_W with DNS_QUERY_NO_WIRE_QUERY: nothing is
                       sent on any network; DnsRecordListFree). When the
                       symbol is missing or the call fails there is no
                       win-dns text and a hole says "no names".

Read-only (A4): no handle beyond PROCESS_QUERY_LIMITED_INFORMATION, no
process memory read, nothing written, signalled or attached to; every
handle is closed in a finally. No socket is opened. Every function has its
argtypes and restype; the structures use fixed-width fields and a
pointer-sized field where Windows has one, so they are 64-bit safe and can
be filled by a fake API on any system (tests/test_hostwin.py). The module
imports on every system; Api() is built on Windows only.
"""
from __future__ import annotations

import csv
import ctypes
import datetime
import io
import ipaddress
import struct

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000   # the only access right ever asked for (A4)
AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
NO_ERROR, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES = 0, 122, 18
DNS_TYPE_A, DNS_TYPE_CNAME, DNS_TYPE_AAAA = 1, 5, 28
DNS_QUERY_NO_WIRE_QUERY = 0x00000010         # the local cache only: never a query on the wire
DNS_FREE_FLAT, DNS_FREE_RECORD_LIST = 0, 1
MAX_PATH = 260
IMAGE_MAX = 32768                             # characters of an image path (long paths)
TCP_BUFFER = 65536
TCP_TRIES = 5
PROCESSES_MAX = 100000
DNS_NAMES_MAX = 20000
NAME_MAX = 1024
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
SYSTEM_PIDS = (0, 4)                          # Idle and System: no image path, never a hole (G-4)

TCP_STATES = {1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived", 5: "Established", 6: "FinWait1",
              7: "FinWait2", 8: "CloseWait", 9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTCB"}
PROCESS_COLUMNS = ("ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate")
TCP_COLUMNS = ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "State", "OwningProcess", "CreationTime")
DNS_COLUMNS = ("Entry", "RecordName", "RecordType", "Status", "Section", "TimeToLive", "DataLength", "Data")
SNAPSHOT_LINE = "# raqib-snapshot at=%s self=%d sample=%d"   # discover.WIN_SNAPSHOT_LINE (a test keeps them equal)

API_PROCESSES = ("kernel32 CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS), Process32FirstW/Process32NextW;"
                 " OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), QueryFullProcessImageNameW, GetProcessTimes,"
                 " CloseHandle")
API_TCP = "iphlpapi GetExtendedTcpTable(AF_INET and AF_INET6, TCP_TABLE_OWNER_PID_ALL)"
API_DNS = ("dnsapi DnsGetCacheDataTable, DnsFree; DnsQuery_W(A, AAAA, DNS_QUERY_NO_WIRE_QUERY),"
           " DnsRecordListFree")
# Every symbol the live reader resolves, per DLL (doctor's `host` line).
SYMBOLS = {"kernel32": ("CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW", "OpenProcess",
                        "QueryFullProcessImageNameW", "GetProcessTimes", "CloseHandle"),
           "iphlpapi": ("GetExtendedTcpTable",),
           "dnsapi": ("DnsGetCacheDataTable", "DnsFree", "DnsQuery_W", "DnsRecordListFree")}
# What the API does not give that the cmdlets' columns hold: said once per run (A3).
NOT_READ = ("Windows live (in-process): no command line, working directory or environment is read (that would"
            " read another process's memory, A4), so CommandLine is empty: argv is empty, an Electron `--type=`"
            " helper (G-1) and a footprint path in argv are not seen, and a process is named by its image only;"
            " TCP CreationTime and the DNS cache's status, section and TTL are not read")

u8, u16, u32, i32, u64 = ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_int32, ctypes.c_uint64


class PROCESSENTRY32W(ctypes.Structure):
    """tlhelp32.h; 568 bytes on win64, 556 on win32."""
    _fields_ = [("dwSize", u32), ("cntUsage", u32), ("th32ProcessID", u32), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", u32), ("cntThreads", u32), ("th32ParentProcessID", u32), ("pcPriClassBase", i32),
                ("dwFlags", u32), ("szExeFile", u16 * MAX_PATH)]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    """tcpmib.h; 24 bytes. Addresses and ports in network byte order."""
    _fields_ = [("dwState", u32), ("dwLocalAddr", u32), ("dwLocalPort", u32), ("dwRemoteAddr", u32),
                ("dwRemotePort", u32), ("dwOwningPid", u32)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    """tcpmib.h; 56 bytes."""
    _fields_ = [("ucLocalAddr", u8 * 16), ("dwLocalScopeId", u32), ("dwLocalPort", u32), ("ucRemoteAddr", u8 * 16),
                ("dwRemoteScopeId", u32), ("dwRemotePort", u32), ("dwState", u32), ("dwOwningPid", u32)]


class DNS_CACHE_ENTRY(ctypes.Structure):
    """The entry DnsGetCacheDataTable lists (undocumented, stable since
    Windows 2000): a linked list of names and the record types cached."""


DNS_CACHE_ENTRY._fields_ = [("pNext", ctypes.POINTER(DNS_CACHE_ENTRY)), ("pszName", ctypes.c_void_p),
                            ("wType", u16), ("wDataLength", u16), ("dwFlags", u32)]


class DNS_DATA(ctypes.Union):
    """The start of DNS_RECORDW's Data union: an A record's IP4_ADDRESS or an
    AAAA record's IP6_ADDRESS (pointer-aligned, as the real union is)."""
    _fields_ = [("pointer", ctypes.c_void_p), ("bytes", u8 * 16)]


class DNS_RECORDW(ctypes.Structure):
    """windns.h, the fields read; records are only read, never allocated here."""


DNS_RECORDW._fields_ = [("pNext", ctypes.POINTER(DNS_RECORDW)), ("pName", ctypes.c_void_p), ("wType", u16),
                        ("wDataLength", u16), ("Flags", u32), ("dwTtl", u32), ("dwReserved", u32),
                        ("Data", DNS_DATA)]


class HostError(Exception):
    """The live run cannot start: the process snapshot failed (E3)."""


class Api:
    """The Win32 functions the live reader calls, with their ctypes
    signatures, each DLL its own WinDLL instance. Windows only. A missing
    dnsapi symbol leaves `dns_missing` set and the DNS functions None."""

    def __init__(self, loader=None):
        loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))
        kernel32, iphlpapi = loader("kernel32"), loader("iphlpapi")
        handle, pointer = ctypes.c_void_p, ctypes.POINTER

        def fn(dll, name, restype, *argtypes):
            f = getattr(dll, name)
            f.restype, f.argtypes = restype, list(argtypes)
            return f
        self.CreateToolhelp32Snapshot = fn(kernel32, "CreateToolhelp32Snapshot", handle, u32, u32)
        self.Process32FirstW = fn(kernel32, "Process32FirstW", ctypes.c_int, handle, pointer(PROCESSENTRY32W))
        self.Process32NextW = fn(kernel32, "Process32NextW", ctypes.c_int, handle, pointer(PROCESSENTRY32W))
        self.OpenProcess = fn(kernel32, "OpenProcess", handle, u32, ctypes.c_int, u32)
        self.QueryFullProcessImageNameW = fn(kernel32, "QueryFullProcessImageNameW", ctypes.c_int, handle, u32,
                                             ctypes.c_void_p, pointer(u32))
        self.GetProcessTimes = fn(kernel32, "GetProcessTimes", ctypes.c_int, handle, pointer(u64), pointer(u64),
                                  pointer(u64), pointer(u64))
        self.CloseHandle = fn(kernel32, "CloseHandle", ctypes.c_int, handle)
        self.GetExtendedTcpTable = fn(iphlpapi, "GetExtendedTcpTable", u32, ctypes.c_void_p, pointer(u32),
                                      ctypes.c_int, u32, ctypes.c_int, u32)
        self.DnsGetCacheDataTable = self.DnsFree = self.DnsQuery_W = self.DnsRecordListFree = None
        self.dns_missing = None
        try:
            dnsapi = loader("dnsapi")
            self.DnsGetCacheDataTable = fn(dnsapi, "DnsGetCacheDataTable", ctypes.c_int,
                                           pointer(pointer(DNS_CACHE_ENTRY)))
            self.DnsFree = fn(dnsapi, "DnsFree", None, ctypes.c_void_p, ctypes.c_int)
            self.DnsQuery_W = fn(dnsapi, "DnsQuery_W", i32, ctypes.c_wchar_p, u16, u32, ctypes.c_void_p,
                                 pointer(pointer(DNS_RECORDW)), ctypes.c_void_p)
            self.DnsRecordListFree = fn(dnsapi, "DnsRecordListFree", None, pointer(DNS_RECORDW), ctypes.c_int)
        except (OSError, AttributeError) as exc:
            self.DnsGetCacheDataTable = self.DnsFree = self.DnsQuery_W = self.DnsRecordListFree = None
            self.dns_missing = "dnsapi: %s" % exc

    byref = staticmethod(ctypes.byref)

    def last_error(self):
        return ctypes.get_last_error()


def probe(loader=None):
    """{dll: None or why it does not resolve} for the DLLs and symbols the
    live reader needs (doctor's `host` line). Resolves names only: no
    function is called, no sample is taken."""
    loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))
    out = {}
    for dll, names in SYMBOLS.items():
        try:
            lib = loader(dll)
            missing = [n for n in names if not hasattr(lib, n)]
            out[dll] = "no symbol %s" % ", ".join(missing) if missing else None
        except (OSError, AttributeError) as exc:
            out[dll] = "cannot be loaded: %s" % exc
    return out


# --- helpers ------------------------------------------------------------------------------

def wchars(array, count=None):
    """Text of a UTF-16 code-unit array (c_uint16 * n), up to its NUL or count."""
    units = list(array[:count] if count is not None else array)
    if 0 in units:
        units = units[:units.index(0)]
    return struct.pack("<%dH" % len(units), *units).decode("utf-16-le", "replace")


def wstring_at(address, limit=NAME_MAX):
    """Text of a NUL-terminated UTF-16 string at an address (two bytes per
    unit on every system, unlike ctypes.wstring_at off Windows)."""
    if not address:
        return ""
    units = []
    for i in range(limit):
        unit = u16.from_address(address + 2 * i).value
        if not unit:
            break
        units.append(unit)
    return struct.pack("<%dH" % len(units), *units).decode("utf-16-le", "replace")


def port(value):
    """A port of the TCP table: the low 16 bits, in network byte order."""
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def ipv4(value):
    """An IPv4 address of the TCP table: a DWORD whose bytes in memory are
    the octets in order (Windows is little-endian)."""
    return str(ipaddress.IPv4Address(struct.pack("<I", value & 0xFFFFFFFF)))


def filetime(value):
    """ISO UTC text of a FILETIME (100 ns since 1601-01-01), or "" for 0."""
    if not value:
        return ""
    start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = start + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _csv(columns, rows, first=None):
    buf = io.StringIO()
    if first:
        buf.write(first + "\n")
    w = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    w.writerow(columns)
    for row in rows:
        w.writerow(["" if v is None else str(v) for v in row])
    return buf.getvalue()


# --- the three readers --------------------------------------------------------------------

def read_processes(api):
    """([(pid, ppid, exe name)], error or None): one Toolhelp32 snapshot.
    HostError when the snapshot or its first entry cannot be read; an
    enumeration that stops early keeps its rows and says why."""
    snap = api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise HostError("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed (error %d)" % api.last_error())
    rows, error = [], None
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not api.Process32FirstW(snap, api.byref(entry)):
            raise HostError("Process32FirstW failed on the snapshot (error %d)" % api.last_error())
        while True:
            rows.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID), wchars(entry.szExeFile)))
            if len(rows) >= PROCESSES_MAX:
                error = "Process32NextW: stopped after %d processes" % PROCESSES_MAX
                break
            if not api.Process32NextW(snap, api.byref(entry)):
                code = api.last_error()
                if code != ERROR_NO_MORE_FILES:
                    error = "Process32NextW failed after %d processes (error %d)" % (len(rows), code)
                break
    finally:
        api.CloseHandle(snap)
    return rows, error


def process_detail(api, pid):
    """(image path or None, creation time text or "") of one process, on a
    handle opened with PROCESS_QUERY_LIMITED_INFORMATION only and closed in
    a finally. None: the handle or the query was denied (a hole)."""
    handle = api.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None, ""
    try:
        buf = (u16 * IMAGE_MAX)()
        size = u32(IMAGE_MAX)
        path = wchars(buf, size.value) if api.QueryFullProcessImageNameW(handle, 0, buf, api.byref(size)) else None
        times = [u64(0) for _ in range(4)]
        started = filetime(times[0].value) if api.GetProcessTimes(handle, *[api.byref(t) for t in times]) else ""
    finally:
        api.CloseHandle(handle)
    return path or None, started


def tcp_table(api, family):
    """(rows, error or None) of GetExtendedTcpTable for one address family:
    rows of (state, local address, local port, remote address, remote port,
    owning pid)."""
    row_type = MIB_TCPROW_OWNER_PID if family == AF_INET else MIB_TCP6ROW_OWNER_PID
    name = "AF_INET" if family == AF_INET else "AF_INET6"
    size = u32(TCP_BUFFER)
    for _ in range(TCP_TRIES):
        buf = ctypes.create_string_buffer(size.value)
        rc = api.GetExtendedTcpTable(buf, api.byref(size), 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        if rc == ERROR_INSUFFICIENT_BUFFER:
            size = u32(max(size.value, len(buf)) + 4096)
            continue
        if rc != NO_ERROR:
            return [], "GetExtendedTcpTable(%s) returned %d" % (name, rc)
        data = buf.raw
        count = struct.unpack_from("<I", data, 0)[0]
        step = ctypes.sizeof(row_type)
        if 4 + count * step > len(data):
            return [], "GetExtendedTcpTable(%s): %d rows do not fit the %d bytes returned" % (name, count, len(data))
        rows = []
        for i in range(count):
            r = row_type.from_buffer_copy(data, 4 + i * step)
            if family == AF_INET:
                laddr, raddr = ipv4(r.dwLocalAddr), ipv4(r.dwRemoteAddr)
            else:
                laddr = str(ipaddress.IPv6Address(bytes(r.ucLocalAddr)))
                raddr = str(ipaddress.IPv6Address(bytes(r.ucRemoteAddr)))
            rows.append((TCP_STATES.get(r.dwState, str(r.dwState)), laddr, port(r.dwLocalPort), raddr,
                         port(r.dwRemotePort), int(r.dwOwningPid)))
        return rows, None
    return [], "GetExtendedTcpTable(%s): the table kept growing after %d tries" % (name, TCP_TRIES)


def _cache_step(api, address, names):
    """Read one cache entry at an address, free its name and the entry
    (DnsFree, DnsFreeFlat: the documented way to free what dnsapi returns),
    and return the next entry's address, read as an integer before the
    entry is freed. names None: free only."""
    entry = DNS_CACHE_ENTRY.from_address(address)
    nxt = ctypes.cast(entry.pNext, ctypes.c_void_p).value or 0
    name_at = entry.pszName or 0
    if names is not None and name_at:
        name = wstring_at(name_at).lower()
        if name and name not in names and len(names) < DNS_NAMES_MAX:
            names.append(name)
    if name_at:
        api.DnsFree(name_at, DNS_FREE_FLAT)
    api.DnsFree(address, DNS_FREE_FLAT)
    return nxt


def cache_names(api):
    """(names in the resolver cache, or None when it was not read; why not).
    Every entry and its name are freed with DnsFree after they are read,
    also when reading one fails."""
    if api.DnsGetCacheDataTable is None:
        return None, api.dns_missing or "dnsapi DnsGetCacheDataTable missing"
    head = ctypes.POINTER(DNS_CACHE_ENTRY)()
    if not api.DnsGetCacheDataTable(api.byref(head)):
        return None, "DnsGetCacheDataTable returned FALSE (error %d)" % api.last_error()
    names, address = [], ctypes.cast(head, ctypes.c_void_p).value or 0
    try:
        while address:
            address = _cache_step(api, address, names)
    finally:
        while address:      # a failure above: free the rest of the list unread
            address = _cache_step(api, address, None)
    return names, None


def cached_records(api, name, rtype):
    """[(record name, "A" or "AAAA", ip)] the cache holds for a name, read
    with DNS_QUERY_NO_WIRE_QUERY (the local cache only); [] when it holds
    none. The list is freed with DnsRecordListFree."""
    head = ctypes.POINTER(DNS_RECORDW)()
    status = api.DnsQuery_W(name, rtype, DNS_QUERY_NO_WIRE_QUERY, None, api.byref(head), None)
    out = []
    if status != 0 or not head:
        return out
    try:
        rec = head
        while rec:
            r = rec.contents
            if r.wType == DNS_TYPE_A and r.wDataLength >= 4:
                out.append((wstring_at(r.pName).lower(), "A", str(ipaddress.IPv4Address(bytes(r.Data.bytes[:4])))))
            elif r.wType == DNS_TYPE_AAAA and r.wDataLength >= 16:
                out.append((wstring_at(r.pName).lower(), "AAAA", str(ipaddress.IPv6Address(bytes(r.Data.bytes)))))
            rec = r.pNext
    finally:
        api.DnsRecordListFree(head, DNS_FREE_RECORD_LIST)
    return out


# --- a sample, and a live run --------------------------------------------------------------

def _label(api_text, k, at):
    return "live: %s; sample %d at %s" % (api_text, k, at)


def process_text(api, k, self_pid, at):
    """(win-process-<k> entry, pids whose image path was not read). The
    first line names the reader's own pid (E3). HostError when the
    snapshot fails."""
    procs, error = read_processes(api)
    rows, denied = [], []
    for pid, ppid, exe_name in procs:
        path, started = (None, "") if pid == 0 else process_detail(api, pid)
        if path is None and pid not in SYSTEM_PIDS:
            denied.append(pid)
        rows.append((pid, ppid, exe_name, path or "", "", started))
    return (_label(API_PROCESSES, k, at), _csv(PROCESS_COLUMNS, rows, SNAPSHOT_LINE % (at, self_pid, k)),
            error), denied


def tcp_text(api, k, at):
    """The win-tcp-<k> entry: both address families in one text."""
    rows, errors = [], []
    for family in (AF_INET, AF_INET6):
        got, error = tcp_table(api, family)
        rows += [(laddr, lport, raddr, rport, state, pid, "") for state, laddr, lport, raddr, rport, pid in got]
        if error:
            errors.append(error)
    return (_label(API_TCP, k, at), _csv(TCP_COLUMNS, rows, "# raqib live sample %d at %s" % (k, at)),
            "; ".join(errors) or None)


def dns_text(api, k, at):
    """(the win-dns-<k> entry or None, why not or None, names with no cached
    A or AAAA record)."""
    names, why = cache_names(api)
    if names is None:
        return None, why, 0
    rows, seen, unanswered = [], set(), 0
    for name in names:
        got = cached_records(api, name, DNS_TYPE_A) + cached_records(api, name, DNS_TYPE_AAAA)
        if not got:
            unanswered += 1
        for rec_name, rtype, ip in got:
            if (name, rec_name, ip) not in seen:
                seen.add((name, rec_name, ip))
                rows.append((name, rec_name, rtype, "", "", "", 4 if rtype == "A" else 16, ip))
    return (_label(API_DNS, k, at), _csv(DNS_COLUMNS, rows, "# raqib live sample %d at %s" % (k, at)), None), None, \
        unanswered


def now_text():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def collect(api, samples, every, self_pid, sleep, now=now_text):
    """A live run: `samples` samples `every` seconds apart, each read as
    win-process-<k>, win-tcp-<k> and (when the cache was read) win-dns-<k>.
    Returns (texts, holes, info); info = {"apis", "sample_times",
    "seconds_apart"} goes into run.json. A snapshot that fails in sample 1
    refuses the run (HostError, E3); in a later sample that sample's process
    source is not read (an error: the run is incomplete, A3) and its TCP and
    DNS kinds are still read."""
    texts, holes, times = {}, [NOT_READ], []
    denied, dns_why, unanswered, dns_read = {}, {}, 0, 0
    for k in range(1, samples + 1):
        at = now()
        times.append(at)
        try:
            texts["win-process-%d" % k], gone = process_text(api, k, self_pid, at)
        except HostError as exc:
            if k == 1:
                raise
            texts["win-process-%d" % k], gone = (_label(API_PROCESSES, k, at), None, str(exc)), []
        for pid in gone:
            denied.setdefault(pid, []).append(k)
        texts["win-tcp-%d" % k] = tcp_text(api, k, at)
        entry, why, missing = dns_text(api, k, at)
        if entry is None:
            dns_why.setdefault(why, []).append(k)
        else:
            texts["win-dns-%d" % k] = entry
            dns_read += 1
        unanswered += missing
        if k < samples:
            sleep(every)
    if denied:
        shown = sorted(denied)
        holes.append("%d process(es) whose image path was not read (ExecutablePath \"?\": OpenProcess with"
                     " PROCESS_QUERY_LIMITED_INFORMATION or QueryFullProcessImageNameW was denied; an elevated"
                     " run reads more): pid %s%s" % (len(shown), ", ".join(map(str, shown[:20])),
                                                     " and %d more" % (len(shown) - 20) if len(shown) > 20 else ""))
    for why, ks in sorted(dns_why.items()):
        holes.append("no names: the resolver cache was not read (%s) in %s: there, connections match the catalog"
                     " by network and loopback port only" % (
                         why, "every sample" if len(ks) == samples else "sample(s) %s" % ", ".join(map(str, ks))))
    if unanswered:
        holes.append("%d cached name lookup(s) gave no A or AAAA record from the cache (expired, negative or another"
                     " type): those names are not joined to an address" % unanswered)
    info = {"apis": [API_PROCESSES, API_TCP] + ([API_DNS] if dns_read else []),
            "sample_times": times, "seconds_apart": every}
    return texts, holes, info
