"""M7.21a (HANDOFF E1-E8, ADR-0007 Amendments BK and BL): the tracing reader alone, raqib/etwnet.py, and the
field tool tools/rig/etw_read.py. The system is a fake here (FakeEtw). It reads what the reader hands it - the
session's properties, the consumer's EVENT_TRACE_LOGFILEW, QueryAllTracesW's buffers - at the offsets 64-bit
Windows lays them out, written here by hand and not taken from the module's structures; and it hands the
reader's callback EVENT_RECORDs built from bytes as the kernel lays them (IPv4 and IPv6), so the module's
layouts are checked against a statement of them made apart. The real system is the Table's field check
(docs/review/2026-11-13-M7.21a-questions.md). Addresses are documentation addresses only."""
import ast
import ctypes
import datetime
import gc
import importlib.util
import io
import ipaddress
import os
import queue
import re
import struct
import sys
import threading
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import etwnet  # noqa: E402

spec = importlib.util.spec_from_file_location("rig_etw_read", ROOT / "tools" / "rig" / "etw_read.py")
etw_read = importlib.util.module_from_spec(spec)
spec.loader.exec_module(etw_read)

WINDOWS = sys.platform == "win32"
WIN64 = ctypes.sizeof(ctypes.c_void_p) == 8
SOURCE = (ROOT / "raqib" / "etwnet.py").read_text(encoding="ascii")
TOOL = (ROOT / "tools" / "rig" / "etw_read.py").read_text(encoding="ascii")
PROVIDER = "7DD42A49-5329-4832-8DFD-43D979153A88"            # as the Table measured it
EVENT_TRACE_GUID = "68FDD900-4A3E-11D1-84F4-0000F80464E3"    # the trace's own header event
CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p)
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SINCE = "2026-11-13T09:59:59.000000Z"
PID = 4242
L4, R4 = ("192.0.2.10", 50123), ("198.51.100.7", 443)
L6, R6 = ("2001:db8::10", 50124), ("2001:db8::7", 443)
OTHERS = ("EventLog-System", "NT Kernel Logger", "DiagLog")
INVALID = 0xFFFFFFFFFFFFFFFF


def stamp(text):
    """The FILETIME (100 ns since 1601) of "2026-11-13T10:00:01.250000Z"."""
    dt = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)
    delta = dt - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10 ** 7 + delta.microseconds * 10


T1, T2 = "2026-11-13T10:00:01.250000Z", "2026-11-13T10:00:02.500000Z"


def kernel_data(event_id, pid, size, local, remote):
    """An event's data as Kernel-Network lays it (the Table's measure): PID u32, size u32, daddr, saddr, dport
    u16, sport u16 (ports in network order), then the others (startime, endtime, seqnum, connid for a send;
    seqnum, connid for a receive). This host's side is saddr:sport."""
    daddr, saddr = ipaddress.ip_address(remote[0]).packed, ipaddress.ip_address(local[0]).packed
    out = struct.pack("<II", pid, size) + daddr + saddr + struct.pack(">HH", remote[1], local[1])
    if event_id in (10, 26):
        return out + struct.pack("<IIIQ", 1000, 1001, 77, 0xFFFF800012340000)
    return out + struct.pack("<IQ", 78, 0xFFFF800012340000)


def record_bytes(provider, event_id, header_pid, when, data_at, length):
    """An EVENT_RECORD of 64-bit Windows, 112 bytes, laid out by hand (evntcons.h, evntprov.h): EVENT_HEADER
    (Size, HeaderType, Flags, EventProperty, ThreadId, ProcessId, TimeStamp at 16, ProviderId at 24,
    EVENT_DESCRIPTOR at 40: Id, Version, Channel, Level, Opcode, Task, Keyword at 48; ProcessorTime at 56,
    ActivityId at 64), ETW_BUFFER_CONTEXT at 80, ExtendedDataCount at 84, UserDataLength at 86, ExtendedData
    at 88, UserData at 96, UserContext at 104."""
    head = struct.pack("<HHHHII", 80, 0, 0x0040, 0, 3131, header_pid) + struct.pack("<q", when)
    head += uuid.UUID(provider).bytes_le + struct.pack("<HBBBBHQ", event_id, 0, 0x10, 4, 0, 0, 0x8000000000000010)
    head += struct.pack("<Q", 0) + bytes(16)
    rest = struct.pack("<BBHHH", 1, 0, 7, 0, length) + struct.pack("<QQQ", 0, data_at, 0)
    out = head + rest
    assert len(head) == 80 and len(out) == 112
    return out


def ev(event_id, local, remote, size, when=T1, pid=PID, header_pid=0, provider=PROVIDER, cut=None):
    data = kernel_data(event_id, pid, size, local, remote)
    return provider, event_id, header_pid, stamp(when), data if cut is None else data[:cut]


def units_at(address):
    out = []
    while True:
        unit = ctypes.c_uint16.from_address(address + 2 * len(out)).value
        if not unit:
            return struct.pack("<%dH" % len(out), *out).decode("utf-16-le")
        out.append(unit)


class Delivery:
    def __init__(self, address):
        self.address, self.done = address, threading.Event()


class FakeEtw:
    """advapi32's tracing calls, in Python. byref is the identity: a call gets the very ctypes object the reader
    passed. Sessions {name: {"handle", "mine"}}; the others are there from the start and are never Raqib's."""

    def __init__(self, others=OTHERS):
        self.sessions = {n: {"handle": 0, "mine": False} for n in others}
        self.next = 0x5000
        self.start_rc = self.enable_rc = self.query_rc = self.listing_rc = 0
        self.open_error = None     # an error number: OpenTraceW fails with it
        self.process_rc = None     # a number: ProcessTrace returns it at once
        self.raises = {}           # function name -> the exception it raises
        self.stop_rc = {}          # session name -> what ControlTraceW(stop) returns
        self.lost = (0, 0)         # (EventsLost, RealTimeBuffersLost) the session says
        self.error = 0
        self.calls, self.started, self.enabled, self.opened, self.closed, self.controls = [], [], [], [], [], []
        self.consumers, self.traces, self.kept = [], {}, []

    byref = staticmethod(lambda obj: obj)

    def last_error(self):
        return self.error

    def callback(self, function):
        return CALLBACK(function)

    def _call(self, name):
        self.calls.append(name)
        if name in self.raises:
            raise self.raises[name]

    def StartTraceW(self, handle, name, buf):
        self._call("StartTraceW")
        raw = bytes(buf)
        at = {"size": 0, "context": 40, "flags": 44, "kb": 48, "mode": 64, "flush": 68, "file_offset": 112,
              "name_offset": 116}
        self.started.append(dict({k: struct.unpack_from("<I", raw, o)[0] for k, o in at.items()},
                                 name=name, length=len(raw)))
        if self.start_rc:
            return self.start_rc
        if name in self.sessions:
            return 183
        self.next += 1
        handle.value = self.next
        self.sessions[name] = {"handle": self.next, "mine": True}
        return 0

    def EnableTraceEx2(self, handle, provider, code, level, any_, all_, timeout, params):
        self._call("EnableTraceEx2")
        self.enabled.append((handle, bytes(provider), code, level, any_, all_, timeout, params))
        return self.enable_rc

    def OpenTraceW(self, logfile):
        self._call("OpenTraceW")
        assert ctypes.sizeof(logfile) == 448
        raw = ctypes.string_at(ctypes.addressof(logfile), 448)
        (file_at, name_at), mode, cb = struct.unpack_from("<QQ", raw, 0), struct.unpack_from("<I", raw, 28)[0], \
            struct.unpack_from("<Q", raw, 424)[0]
        self.opened.append({"name": units_at(name_at), "file": file_at, "mode": mode, "callback": cb})
        if self.open_error is not None:
            self.error = self.open_error
            return INVALID
        self.next += 1
        self.traces[self.next] = {"name": self.opened[-1]["name"], "callback": cb, "inbox": queue.Queue()}
        return self.next

    def ProcessTrace(self, handles, count, start, end):
        self._call("ProcessTrace")
        self.consumers.append(threading.current_thread() is threading.main_thread())
        assert count == 1 and start is None and end is None
        trace = self.traces[handles[0]]
        call = CALLBACK(trace["callback"])
        if self.process_rc is not None:
            return self.process_rc
        while True:
            item = trace["inbox"].get()
            if item is None:
                return 0
            try:
                call(item.address)
            finally:
                item.done.set()

    def CloseTrace(self, trace):
        self._call("CloseTrace")
        self.closed.append(trace)
        self.traces[trace]["inbox"].put(None)
        return 0

    def ControlTraceW(self, handle, name, buf, code):
        self._call("ControlTraceW")
        self.controls.append((handle, name, code))
        found = next((n for n, s in self.sessions.items() if s["handle"] == handle), None) if handle else \
            (name if name in self.sessions else None)
        if found is None:
            return 4201
        if code == etwnet.EVENT_TRACE_CONTROL_QUERY and self.query_rc:
            return self.query_rc
        if code == etwnet.EVENT_TRACE_CONTROL_STOP:
            if self.stop_rc.get(found):
                return self.stop_rc[found]
            del self.sessions[found]
            for trace in self.traces.values():
                if trace["name"] == found:
                    trace["inbox"].put(None)
        assert struct.unpack_from("<I", bytes(buf), 0)[0] == len(buf)
        struct.pack_into("<I", buf, 88, self.lost[0])
        struct.pack_into("<I", buf, 100, self.lost[1])
        return 0

    def QueryAllTracesW(self, array, count, found):
        self._call("QueryAllTracesW")
        names = list(self.sessions)
        found.value = len(names)
        if self.listing_rc:
            return self.listing_rc
        for i, name in enumerate(names[:count]):
            at = array[i]
            size, offset = ctypes.c_uint32.from_address(at).value, ctypes.c_uint32.from_address(at + 116).value
            data = name.encode("utf-16-le") + b"\0\0"
            assert offset >= 120 and offset + len(data) <= size
            ctypes.memmove(at + offset, data, len(data))
        return 234 if len(names) > count else 0

    def deliver(self, *events, null=False):
        """Hand each event to the consumer's callback, on the consumer's thread, and wait until it was taken."""
        inbox = self.traces[max(self.traces)]["inbox"]
        items = []
        for provider, event_id, header_pid, when, data in events:
            data_buf = ctypes.create_string_buffer(data, len(data)) if data else None
            rec = ctypes.create_string_buffer(record_bytes(provider, event_id, header_pid, when, ctypes.addressof(
                data_buf) if data_buf is not None else 0, len(data)), 112)
            self.kept += [data_buf, rec]
            items.append(Delivery(ctypes.addressof(rec)))
        if null:
            items.append(Delivery(0))
        for item in items:
            inbox.put(item)
        assert all(item.done.wait(30) for item in items)


def reader(fake, pid=PID, **kw):
    return etwnet.Reader(pid, fake, now=lambda: SINCE, **kw)


def started(fake, pid=PID):
    r = reader(fake, pid)
    assert r.start() is None
    return r


# --- E1: ctypes and the standard library, importable everywhere, one object for the system's calls -------------

def _imports(text):
    tree = ast.parse(text)
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            out.add(("." * node.level) + (node.module or ""))
    return tree, out


def test_e1_stdlib_only_nothing_of_raqib_no_network_and_nothing_of_windows_at_import():
    tree, mods = _imports(SOURCE)
    tops = {m.split(".")[0] for m in mods}
    assert tops - {"__future__"} <= set(sys.stdlib_module_names) and not any(m.startswith(".") for m in mods)
    assert "raqib" not in tops and not tops & {"socket", "ssl", "http", "urllib", "subprocess", "asyncio",
                                                 "socketserver", "select", "selectors"}
    assert tops == {"__future__", "ctypes", "datetime", "ipaddress", "re", "struct", "threading"}
    # at import (the module's own statements and its classes' bodies), nothing of Windows is touched
    top = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    top += [s for c in tree.body if isinstance(c, ast.ClassDef) for s in c.body if not isinstance(s, ast.FunctionDef)]
    said = " ".join(ast.unparse(n) for n in top if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)))
    for windows in ("WinDLL", "windll", "WINFUNCTYPE", "oledll", "OleDLL", "get_last_error", "FormatError"):
        assert windows not in said, windows
    assert etwnet.Reader and etwnet.Api       # it imported here, on this system


def test_e1_api_binds_every_symbol_through_the_loader_with_argtypes_and_restype():
    class Fn:
        restype = argtypes = "unset"

    class Lib:
        def __init__(self):
            self.made = {}

        def __getattr__(self, name):
            if name.startswith("__"):
                raise AttributeError(name)
            return self.made.setdefault(name, Fn())
    libs = {}
    api = etwnet.Api(lambda name: libs.setdefault(name, Lib()))
    assert set(libs) == set(etwnet.SYMBOLS) == {"advapi32"}
    assert sorted(libs["advapi32"].made) == sorted(etwnet.SYMBOLS["advapi32"])
    for name in etwnet.SYMBOLS["advapi32"]:
        f = getattr(api, name)
        assert f.restype is not None and f.restype != "unset" and isinstance(f.argtypes, list) and f.argtypes, name
    assert api.OpenTraceW.restype is ctypes.c_uint64 and api.StartTraceW.restype is ctypes.c_uint32
    assert len(api.EnableTraceEx2.argtypes) == 8 and len(api.ControlTraceW.argtypes) == 4
    # negative: a loader that cannot load advapi32 builds no Api, and the reader says so and raises nothing
    with pytest.raises(OSError):
        etwnet.Api(lambda name: (_ for _ in ()).throw(OSError("no %s here" % name)))


def test_e1_a_reader_without_its_api_says_so_and_raises_nothing(monkeypatch):
    def no_api():
        raise OSError("advapi32 cannot be loaded (fake)")
    monkeypatch.setattr(etwnet, "Api", no_api)
    r = etwnet.Reader(PID)
    why = r.start()
    assert why == r.refused and "the tracing API cannot be loaded" in why and "advapi32" in why
    assert r.counts()["since"] is None and r.stop() == []


@pytest.mark.skipif(WINDOWS, reason="off Windows: no WinDLL")
def test_e1_off_windows_the_real_api_is_not_there():
    why = etwnet.Reader(PID).start()
    assert why.startswith("the bytes are not read: the tracing API cannot be loaded")


@pytest.mark.skipif(not WINDOWS, reason="the real advapi32: binds only, starts nothing")
def test_e1_windows_the_real_api_binds():
    api = etwnet.Api()
    assert api.StartTraceW.argtypes and api.QueryAllTracesW.restype is ctypes.c_uint32


# --- E2 (BL-1): a session of its own, that provider, those keywords, a consumer on its own thread ---------------

def test_e2_start_names_the_session_enables_the_provider_and_consumes_on_its_own_thread():
    fake = FakeEtw()
    r = started(fake)
    (props,) = fake.started
    assert props["name"] == r.name == "raqib-net-4242" and fake.sessions[r.name]["mine"]
    assert props["size"] == props["length"] and props["flags"] & 0x00020000 and props["mode"] == 0x00000100
    assert props["file_offset"] == 0 and props["name_offset"] == 120      # in memory only: no log file
    assert props["context"] == 1 and props["kb"] == 64 and props["flush"] == 1
    (handle, provider, code, level, any_, all_, timeout, params), = fake.enabled
    assert handle == fake.sessions[r.name]["handle"] and provider == uuid.UUID(PROVIDER).bytes_le
    assert (code, level, any_, all_, timeout, params) == (1, 4, 0x30, 0, 0, None)
    (opened,) = fake.opened
    assert opened["name"] == r.name and opened["file"] == 0 and opened["mode"] == 0x10000100
    assert opened["callback"] == ctypes.cast(r._callback, ctypes.c_void_p).value != 0
    gc.collect()      # the callback is the reader's for its life: the system holds only its address
    fake.deliver(ev(10, L4, R4, 100))
    assert fake.consumers == [False] and r._thread.is_alive()
    assert r.stop() == []
    assert set(fake.sessions) == set(OTHERS)      # no other session was touched


def test_e2_sent_and_received_over_v4_and_v6_this_hosts_side_is_saddr_sport_and_the_pid_is_the_datas():
    fake = FakeEtw()
    r = started(fake)
    fake.deliver(ev(10, L4, R4, 100, header_pid=0), ev(11, L4, R4, 4000, header_pid=777),
                 ev(26, L6, R6, 60), ev(27, L6, R6, 7000, when=T2), ev(10, L4, R4, 23, when=T2))
    got = r.counts()["connections"]
    assert got == {(PID, "192.0.2.10", 50123, "198.51.100.7", 443): {"sent": 123, "received": 4000, "last": T2},
                   (PID, "2001:db8::10", 50124, "2001:db8::7", 443): {"sent": 60, "received": 7000, "last": T2}}
    # negative: the header's pid is never the key; the remote side is never taken for this host's
    assert not [k for k in got if k[0] in (0, 777)] and not [k for k in got if k[1] in ("198.51.100.7", "2001:db8::7")]
    r.stop()


def test_e2_a_connect_or_a_disconnect_adds_no_bytes():
    fake = FakeEtw()
    r = started(fake)
    fake.deliver(ev(12, L4, R4, 0), ev(13, L4, R4, 0), ev(28, L6, R6, 0))
    got = r.counts()
    assert got["connections"] == {} and got["unread"] == 3
    assert got["unread_why"] == {"id 12": 1, "id 13": 1, "id 28": 1}
    r.stop()


# --- E3 (BL-5): counts() a copy, from any thread, with since, unread and lost ------------------------------------

def test_e3_counts_is_a_copy_from_any_thread_with_the_sessions_start():
    fake = FakeEtw()
    r = started(fake)
    fake.deliver(ev(10, L4, R4, 10), ev(11, L4, R4, 20, when=T2))
    there = []
    t = threading.Thread(target=lambda: there.append(r.counts()))
    t.start()
    t.join(30)
    here = r.counts()
    assert there == [here] and here["since"] == SINCE and here["session"] == "raqib-net-4242"
    key = (PID, "192.0.2.10", 50123, "198.51.100.7", 443)
    assert here["connections"][key] == {"sent": 10, "received": 20, "last": T2}
    here["connections"][key]["sent"] = 999999
    here["connections"].clear()
    here["unread_why"]["x"] = 1
    again = r.counts()
    assert again["connections"][key]["sent"] == 10 and again["unread_why"] == {} and again["unread"] == 0
    assert (again["ended"], again["refused"], again["other"]) == (None, None, 0)
    r.stop()


def test_e3_data_shorter_than_the_shape_is_unread_never_guessed():
    fake = FakeEtw()
    r = started(fake)
    fake.deliver(ev(10, L4, R4, 10, cut=19), ev(27, L6, R6, 10, cut=43), ev(11, L4, R4, 10, cut=0),
                 ev(10, L4, R4, 10, provider=EVENT_TRACE_GUID), null=True)
    got = r.counts()
    assert got["connections"] == {} and got["unread"] == 4 and got["other"] == 1
    assert got["unread_why"] == {"id 10 shorter than 20 bytes": 1, "id 27 shorter than 44 bytes": 1,
                                 "id 11 shorter than 20 bytes": 1, "a NULL record": 1}
    # positive: data of exactly the shape (nothing after the ports) is read
    fake.deliver(ev(10, L4, R4, 5, cut=20), ev(26, L6, R6, 6, cut=44))
    assert sorted(v["sent"] for v in r.counts()["connections"].values()) == [5, 6]
    r.stop()


def test_e3_before_a_start_there_is_no_since_and_the_loss_is_not_known():
    got = reader(FakeEtw()).counts()
    assert got["since"] is None and got["connections"] == {}
    assert got["lost"]["events"] is None and got["lost"]["buffers"] is None and "no session" in got["lost"]["why"]


# --- E4 (BL-4): lost is what the session says, asked at each counts() ---------------------------------------------

def test_e4_lost_is_asked_of_the_session_at_each_counts_and_a_loss_is_reported():
    fake = FakeEtw()
    r = started(fake)
    queries = lambda: sum(1 for c in fake.controls if c[2] == etwnet.EVENT_TRACE_CONTROL_QUERY)   # noqa: E731
    assert r.counts()["lost"] == {"events": 0, "buffers": 0, "why": None} and queries() == 1
    fake.lost = (3, 2)
    assert r.counts()["lost"] == {"events": 3, "buffers": 2, "why": None} and queries() == 2
    assert fake.controls[-1] == (fake.sessions[r.name]["handle"], r.name, etwnet.EVENT_TRACE_CONTROL_QUERY)
    fake.lost = (5, 4)
    assert r.stop() == []
    after = r.counts()
    assert after["lost"] == {"events": 5, "buffers": 4, "why": None} and queries() == 2   # the stop's last word


def test_e4_a_query_that_fails_is_a_loss_not_known_never_zero():
    fake = FakeEtw()
    r = started(fake)
    fake.query_rc = 87
    lost = r.counts()["lost"]
    assert lost["events"] is None and lost["buffers"] is None and "returned 87" in lost["why"]
    assert "not known" in lost["why"]
    fake.query_rc = 0
    assert r.counts()["lost"] == {"events": 0, "buffers": 0, "why": None}
    r.stop()


# --- E5 (BL-2): stopped on every way out; a failed start leaves no session; leftovers ----------------------------

def test_e5_stop_ends_the_consumer_and_the_session_and_twice_is_harmless():
    fake = FakeEtw()
    r = started(fake)
    assert r.name in fake.sessions
    assert r.stop() == []
    assert r.name not in fake.sessions and fake.closed == list(fake.traces) and not r._thread.is_alive()
    calls = list(fake.calls)
    assert r.stop() == [] and fake.calls == calls
    assert r.counts()["ended"] is None      # a consumer ended by the stop is no hole


def test_e5_the_context_manager_stops_on_an_exception():
    fake = FakeEtw()
    with pytest.raises(ValueError):
        with reader(fake) as r:
            assert r.refused is None and r.name in fake.sessions
            raise ValueError("a way out")
    assert r.name not in fake.sessions and fake.closed == list(fake.traces)


class NoThread:
    def __init__(self, **kw):
        pass

    def start(self):
        raise RuntimeError("can't start new thread")


@pytest.mark.parametrize("step", ["start refused", "start raises", "enable refused", "enable raises",
                                  "open refused", "open raises", "thread"])
def test_e5_a_start_that_fails_at_any_step_leaves_no_session(step):
    fake = FakeEtw()
    kw = {}
    if step == "start refused":
        fake.start_rc = 5
    elif step == "start raises":
        fake.raises["StartTraceW"] = OSError("fake")
    elif step == "enable refused":
        fake.enable_rc = 5
    elif step == "enable raises":
        fake.raises["EnableTraceEx2"] = ctypes.ArgumentError("fake")
    elif step == "open refused":
        fake.open_error = 5
    elif step == "open raises":
        fake.raises["OpenTraceW"] = OSError("fake")
    else:
        kw["thread"] = NoThread
    r = reader(fake, **kw)
    why = r.start()                                   # raises nothing
    assert why and why == r.refused == r.counts()["refused"] and why.startswith("the bytes are not read")
    assert set(fake.sessions) == set(OTHERS)          # no session of the reader's is left
    assert sorted(fake.closed) == sorted(fake.traces)  # every trace opened is closed
    calls = list(fake.calls)
    assert r.stop() == [] and fake.calls == calls and "ProcessTrace" not in calls
    if step == "thread":
        assert "RuntimeError" in why and fake.closed


def test_e5_a_consumer_that_ends_before_the_stop_is_said():
    fake = FakeEtw()
    fake.process_rc = 1223
    r = started(fake)
    r._thread.join(30)
    got = r.counts()
    assert got["ended"] and "ProcessTrace returned 1223" in got["ended"] and "nothing is counted" in got["ended"]
    r.stop()
    assert r.name not in fake.sessions


LEFT = ("raqib-net-111", "raqib-net-222", "raqib-net-", "raqib-net-12x", "xraqib-net-5", "raqib-net-5-old",
        "RAQIB-NET-6", "raqib-net-7 ", "EventLog-System", "NT Kernel Logger")


def test_e5_leftovers_stops_raqib_sessions_of_no_live_pid_and_never_another():
    fake = FakeEtw(LEFT)
    problems = []
    assert etwnet.leftovers({222, 4242}, fake, problems) == ["raqib-net-111"] and problems == []
    assert list(fake.sessions) == [n for n in LEFT if n != "raqib-net-111"]
    assert [c for c in fake.controls] == [(0, "raqib-net-111", etwnet.EVENT_TRACE_CONTROL_STOP)]
    # negative: with every raqib pid alive, nothing is stopped
    fake = FakeEtw(LEFT)
    assert etwnet.leftovers({111, 222}, fake) == [] and fake.controls == []


def test_e5_leftovers_that_cannot_be_looked_for_or_stopped_are_said():
    fake = FakeEtw(LEFT)
    problems = []
    assert etwnet.leftovers(None, fake, problems) == [] and fake.calls == []
    assert problems == ["leftovers not looked for: the live pids are not known"]
    fake.listing_rc, problems = 5, []
    assert etwnet.leftovers(set(), fake, problems) == [] and "QueryAllTracesW returned 5" in problems[0]
    fake.listing_rc, fake.stop_rc, problems = 0, {"raqib-net-111": 5}, []
    assert etwnet.leftovers({222}, fake, problems) == [] and "raqib-net-111" in fake.sessions
    assert problems == ["raqib-net-111: a leftover not stopped (ControlTraceW(stop) returned 5)"]
    many = FakeEtw(["Other-%d" % i for i in range(70)] + ["raqib-net-9"])
    problems = []
    assert etwnet.leftovers(set(), many, problems) == [] and "71 sessions, 64 listed" in problems[0]
    first = FakeEtw(["raqib-net-9"] + ["Other-%d" % i for i in range(70)])
    assert etwnet.leftovers(set(), first, []) == ["raqib-net-9"]
    fake = FakeEtw(LEFT)
    fake.raises["QueryAllTracesW"] = OSError("fake")
    problems = []
    assert etwnet.leftovers(set(), fake, problems) == [] and problems == ["leftovers: OSError: fake"]


# --- E6 (BL-3): a refusal in the module's words, nothing raised, no elevation, no other source ------------------

@pytest.mark.parametrize("code,words", [(5, "no rights: a tracing session needs an administrator"),
                                        (1450, "the limit of tracing sessions on this system is reached"),
                                        (183, "a session named raqib-net-4242 is already there"),
                                        (87, "the system refused it with error 87")])
def test_e6_a_refused_start_returns_its_reason_and_raises_nothing(code, words):
    fake = FakeEtw()
    fake.start_rc = code
    r = reader(fake)
    why = r.start()
    assert why.startswith("the bytes are not read: " + words) and why.endswith("(StartTraceW returned %d)" % code)
    assert fake.calls == ["StartTraceW"] and set(fake.sessions) == set(OTHERS)


def test_e6_the_name_already_there_and_a_good_start():
    fake = FakeEtw(OTHERS + ("raqib-net-4242",))
    why = reader(fake).start()
    assert "a session named raqib-net-4242 is already there" in why and "StartTraceW returned 183" in why
    assert "raqib-net-4242" in fake.sessions          # not ours to stop: it was there before
    fake = FakeEtw()
    fake.enable_rc = 5
    why = reader(fake).start()
    assert why.startswith("the bytes are not read: no rights") and "(EnableTraceEx2 returned 5)" in why
    fake = FakeEtw()
    fake.open_error = 1450
    why = reader(fake).start()
    assert "the limit of tracing sessions" in why and "(OpenTraceW returned 1450)" in why
    good = FakeEtw()
    r = reader(good)
    assert r.start() is None and r.refused is None            # negative: a start the system allows is no refusal
    r.stop()


def test_e6_another_pointer_size_is_refused_before_any_call(monkeypatch):
    monkeypatch.setattr(etwnet, "POINTER_BYTES", 4)
    fake = FakeEtw()
    why = reader(fake).start()
    assert "64-bit Windows" in why and fake.calls == []


def test_e6_no_other_source_of_counts_and_no_elevation_in_the_source():
    for text in (SOURCE, TOOL):
        for word in ("GetPerTcpConnectionEStats", "SetPerTcpConnectionEStats", "EStats", "iphlpapi",
                     "runas", "ShellExecute", "AdjustTokenPrivileges", "SeDebugPrivilege", "OpenProcessToken"):
            assert word not in text, word
    assert not {m.split(".")[0] for m in _imports(TOOL)[1]} & {"socket", "ssl", "http", "urllib", "subprocess"}


# --- E7: the field tool -------------------------------------------------------------------------------------

def run_tool(fake, wait=None, alive=frozenset({PID}), argv=("5",), platform="win32"):
    out = io.StringIO()
    code = etw_read.main(list(argv), platform=platform, api=fake, alive=alive, wait=wait, out=out, pid=PID)
    return code, out.getvalue().splitlines()


def test_e7_the_tool_stops_leftovers_reads_and_prints_one_line_per_connection():
    fake = FakeEtw(OTHERS + ("raqib-net-111",))
    waited = []

    def wait(seconds):
        waited.append(seconds)
        fake.deliver(ev(10, L4, R4, 100), ev(11, L4, R4, 4000, when=T2), ev(27, L6, R6, 70), ev(12, L4, R4, 0))
    code, lines = run_tool(fake, wait)
    assert code == 0 and waited == [5.0]
    assert lines[0] == "pid=4242 local=192.0.2.10:50123 remote=198.51.100.7:443 sent=100 received=4000 last=%s" % T2
    assert lines[1] == "pid=4242 local=[2001:db8::10]:50124 remote=[2001:db8::7]:443 sent=0 received=70 last=%s" % T1
    assert lines[2] == "said: unread: 1 event(s): id 12"
    assert lines[-1] == "since=%s unread=1 lost=events:0,buffers:0 leftovers=raqib-net-111" % lines[-1].split(
        "since=")[1].split(" ")[0]
    assert set(fake.sessions) == set(OTHERS)           # the leftover and its own session are gone, the rest stay


def test_e7_a_refused_session_is_its_reason_and_exit_3():
    fake = FakeEtw()
    fake.start_rc = 5
    code, lines = run_tool(fake, wait=lambda s: pytest.fail("no wait when refused"))
    assert code == 3 and lines[-1].startswith("refused: the bytes are not read: no rights")
    assert lines[-1].endswith("; leftovers stopped: none")


def test_e7_not_windows_says_so_and_exits_3_and_its_usage_is_2(capsys):
    code, lines = run_tool(FakeEtw(), platform="linux")
    assert code == 3 and lines == ["not Windows (linux): the kernel's tracing is read on Windows only; nothing was"
                                   " read"]
    for argv in ([], ["x"], ["-1"], ["1", "2"]):
        assert run_tool(FakeEtw(), argv=argv)[0] == 2
    assert "usage: python tools/rig/etw_read.py SECONDS" in capsys.readouterr().err


def test_e7_a_loss_not_known_and_live_pids_not_known_are_said():
    fake = FakeEtw(OTHERS + ("raqib-net-111",))
    fake.query_rc = 87
    code, lines = run_tool(fake, wait=lambda s: None, alive=None)
    assert code == 0 and "raqib-net-111" in fake.sessions          # not stopped: the live pids are not known
    assert lines[-1].endswith("lost=unknown leftovers=none")
    assert any(line.startswith("said: lost: ControlTraceW(query) returned 87") for line in lines)
    assert any("live pids" in line for line in lines if line.startswith("said: "))


# --- E8: the structures as 64-bit Windows lays them; ASCII; documentation addresses only ------------------------

@pytest.mark.skipif(not WIN64, reason="64-bit structure sizes")
def test_e8_structure_sizes_and_offsets_of_64_bit_windows():
    sizes = {"GUID": 16, "WNODE_HEADER": 48, "EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_HEADER": 48,
             "EVENT_TRACE": 88, "TIME_ZONE_INFORMATION": 172, "TRACE_LOGFILE_HEADER": 280,
             "EVENT_TRACE_LOGFILEW": 448, "EVENT_DESCRIPTOR": 16, "EVENT_HEADER": 80, "EVENT_RECORD": 112}
    assert {n: ctypes.sizeof(getattr(etwnet, n)) for n in sizes} == sizes
    p, f, h, r = etwnet.EVENT_TRACE_PROPERTIES, etwnet.EVENT_TRACE_LOGFILEW, etwnet.EVENT_HEADER, etwnet.EVENT_RECORD
    assert (p.LogFileMode.offset, p.FlushTimer.offset, p.EventsLost.offset, p.RealTimeBuffersLost.offset,
            p.LoggerThreadId.offset, p.LogFileNameOffset.offset, p.LoggerNameOffset.offset) == (64, 68, 88, 100, 104,
                                                                                               112, 116)
    assert (f.LoggerName.offset, f.ProcessTraceMode.offset, f.CurrentEvent.offset, f.LogfileHeader.offset,
            f.BufferCallback.offset, f.EventRecordCallback.offset, f.Context.offset) == (8, 28, 32, 120, 400, 424, 440)
    assert (h.TimeStamp.offset, h.ProviderId.offset, h.EventDescriptor.offset) == (16, 24, 40)
    assert (r.UserDataLength.offset, r.UserData.offset) == (86, 96)
    assert bytes(etwnet.guid(PROVIDER)) == uuid.UUID(PROVIDER).bytes_le and etwnet.guid_text(
        etwnet.guid(PROVIDER)) == PROVIDER


def test_e8_parse_reads_the_measured_shape_only():
    assert etwnet.parse(10, kernel_data(10, 9, 1500, L4, R4)) == ("sent", 9, 1500, L4, R4)
    assert etwnet.parse(27, kernel_data(27, 9, 1500, L6, R6)) == ("received", 9, 1500, L6, R6)
    assert etwnet.parse(10, kernel_data(10, 9, 1500, L4, R4)[:19]) is None
    assert etwnet.parse(14, kernel_data(10, 9, 1500, L4, R4)) is None
    assert etwnet.filetime(stamp(T1)) == T1 and etwnet.filetime(0) == ""


DOCS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def test_e8_ascii_and_documentation_addresses_only():
    texts = {p: (ROOT / p).read_bytes().decode("ascii") for p in ("raqib/etwnet.py", "tools/rig/etw_read.py",
                                                                   "tests/test_etwnet.py")}
    for path, text in texts.items():
        for quad in re.findall(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])", text):
            assert any(ipaddress.ip_address(quad) in n for n in DOCS), (path, quad)
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and ":" in node.value:
                try:
                    addr = ipaddress.ip_address(node.value)
                except ValueError:
                    continue
                assert any(addr in n for n in DOCS), (path, node.value)
    assert "README" not in texts["raqib/etwnet.py"]
    assert os.path.basename(__file__) == "test_etwnet.py"
