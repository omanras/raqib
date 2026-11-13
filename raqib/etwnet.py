"""Windows: the bytes each TCP connection sent and received, read from the
kernel's own tracing (ETW) by a real-time session of the reader's own
(ADR-0007 Amendments BK and BL; M7.21a: the reader alone, not joined to the
watch yet - that is M7.21b).

The session (BL-1): named raqib-net-<pid> for the reader's pid, real-time
and in memory only (no log file), with one provider enabled:
Microsoft-Windows-Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88} at
level 4 with keywords 0x30 (0x10 IPv4, 0x20 IPv6), consumed by ProcessTrace
on a thread of its own. It listens to what the kernel already says and
switches nothing on for any connection or process (BK-1); it never touches a
session of another name, nor the system's kernel logger.

What is read of an event (BL-5): ids 10 (IPv4) and 26 (IPv6) are bytes sent,
11 and 27 bytes received. The event's data begins PID u32, size u32, daddr,
saddr (4 bytes each over IPv4, 16 each over IPv6), dport u16, sport u16, the
ports in network order; the pid is the data's (the header's is often 0).
saddr:sport is this host's side. An event whose data is shorter than that
shape, or of another id of the provider, is counted as unread, never
guessed. The sums begin at the session's start (`since`): a connection
older than the session has its counts since then only.

Lost events are a hole (BL-4): at each counts() the session is asked what it
lost (events and real-time buffers); the counts of a turn with a loss are
unknown, not smaller.

Ended on every way out (BL-2): stop() stops the session and ends the
consumer, and a second stop() does nothing; the Reader is a context manager;
a start that fails at any step leaves no session. leftovers(alive) stops
the sessions named raqib-net-<n> whose n is no live pid (a watch that was
killed) and names them; a session of any other name is never touched.

No rights, no asking (BL-3): a start the system refuses returns its reason
in this module's own words and raises nothing; no elevation is asked and no
other source of counts is used (BK-1).

Every system call goes through one object, Api(loader) (advapi32's tracing
functions, each with its argtypes and restype), which a test replaces
(tests/test_etwnet.py). The module imports on every system: nothing of
Windows is loaded until Api() is built. ctypes and the standard library
only; no socket, nothing on any network. The structures are laid out with
explicit fixed-width fields for 64-bit Windows; on another pointer size
start() refuses with its reason.
"""
from __future__ import annotations

import ctypes
import datetime
import ipaddress
import re
import struct
import threading

PROVIDER = "7DD42A49-5329-4832-8DFD-43D979153A88"        # Microsoft-Windows-Kernel-Network
PROVIDER_NAME = "Microsoft-Windows-Kernel-Network"
LEVEL = 4                                                 # TRACE_LEVEL_INFORMATION
KEYWORDS = 0x30                                           # 0x10 IPv4, 0x20 IPv6
SESSION_PREFIX = "raqib-net-"
LEFTOVER = re.compile(r"raqib-net-([0-9]+)\Z")            # exactly the reader's name: nothing else is touched
SENT, RECEIVED = "sent", "received"
# event id -> (direction, bytes of one address): the measured shape (BL, the probe branch)
EVENTS = {10: (SENT, 4), 11: (RECEIVED, 4), 26: (SENT, 16), 27: (RECEIVED, 16)}

WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
CLIENT_CONTEXT_QPC = 1                    # Wnode.ClientContext: the timer of the events' stamps
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP = 0, 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF          # 64-bit Windows
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_MORE_DATA = 234
ERROR_NO_SYSTEM_RESOURCES = 1450
ERROR_WMI_INSTANCE_NOT_FOUND = 4201
ERROR_CTX_CLOSE_PENDING = 7007
NAME_ROOM = 1024           # characters kept after the properties for each of the two names
BUFFER_KB = 64             # EVENT_TRACE_PROPERTIES.BufferSize, in KB
FLUSH_SECONDS = 1          # EVENT_TRACE_PROPERTIES.FlushTimer: a real-time buffer is handed on within a second
SESSIONS_MAX = 64          # QueryAllTracesW's array
JOIN_SECONDS = 10          # how long stop() waits for the consumer to end
POINTER_BYTES = ctypes.sizeof(ctypes.c_void_p)

API = ("advapi32 StartTraceW (real-time, no log file), EnableTraceEx2(%s, level %d, keywords 0x%x), OpenTraceW,"
       " ProcessTrace (its own thread), ControlTraceW (query, stop), CloseTrace, QueryAllTracesW"
       % (PROVIDER_NAME, LEVEL, KEYWORDS))
SYMBOLS = {"advapi32": ("StartTraceW", "EnableTraceEx2", "OpenTraceW", "ProcessTrace", "CloseTrace",
                        "ControlTraceW", "QueryAllTracesW")}

u8, u16, u32, i32, u64, i64 = ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint32, ctypes.c_int32, \
    ctypes.c_uint64, ctypes.c_int64


# --- structures (64-bit Windows; unions as their widest member) ----------------------------

class GUID(ctypes.Structure):
    """guiddef.h; 16 bytes."""
    _fields_ = [("Data1", u32), ("Data2", u16), ("Data3", u16), ("Data4", u8 * 8)]


class WNODE_HEADER(ctypes.Structure):
    """wmistr.h; 48 bytes. HistoricalContext is the union with Version and
    Linkage; TimeStamp the union with CountLost and KernelHandle."""
    _fields_ = [("BufferSize", u32), ("ProviderId", u32), ("HistoricalContext", u64), ("TimeStamp", i64),
                ("Guid", GUID), ("ClientContext", u32), ("Flags", u32)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    """evntrace.h; 120 bytes on win64. The session's name (and a log file's,
    never used here) follow it in the same buffer, at the offsets it names.
    AgeLimit is the union with FlushThreshold."""
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", u32), ("MinimumBuffers", u32), ("MaximumBuffers", u32),
                ("MaximumFileSize", u32), ("LogFileMode", u32), ("FlushTimer", u32), ("EnableFlags", u32),
                ("AgeLimit", i32), ("NumberOfBuffers", u32), ("FreeBuffers", u32), ("EventsLost", u32),
                ("BuffersWritten", u32), ("LogBuffersLost", u32), ("RealTimeBuffersLost", u32),
                ("LoggerThreadId", ctypes.c_void_p), ("LogFileNameOffset", u32), ("LoggerNameOffset", u32)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    """evntrace.h; 48 bytes. FieldTypeFlags is the union with HeaderType and
    MarkerFlags; Version the union with Class; ProcessorTime the union with
    KernelTime/UserTime and ClientContext/Flags."""
    _fields_ = [("Size", u16), ("FieldTypeFlags", u16), ("Version", u32), ("ThreadId", u32), ("ProcessId", u32),
                ("TimeStamp", i64), ("Guid", GUID), ("ProcessorTime", u64)]


class EVENT_TRACE(ctypes.Structure):
    """evntrace.h; 88 bytes on win64. ClientContext is the union with
    BufferContext."""
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", u32), ("ParentInstanceId", u32),
                ("ParentGuid", GUID), ("MofData", ctypes.c_void_p), ("MofLength", u32), ("ClientContext", u32)]


class SYSTEMTIME(ctypes.Structure):
    """minwinbase.h; 16 bytes."""
    _fields_ = [("wYear", u16), ("wMonth", u16), ("wDayOfWeek", u16), ("wDay", u16), ("wHour", u16),
                ("wMinute", u16), ("wSecond", u16), ("wMilliseconds", u16)]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    """timezoneapi.h; 172 bytes."""
    _fields_ = [("Bias", i32), ("StandardName", u16 * 32), ("StandardDate", SYSTEMTIME), ("StandardBias", i32),
                ("DaylightName", u16 * 32), ("DaylightDate", SYSTEMTIME), ("DaylightBias", i32)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    """evntrace.h; 280 bytes on win64. LogInstanceGuid is the union with
    StartBuffers, PointerSize, EventsLost and CpuSpeedInMHz."""
    _fields_ = [("BufferSize", u32), ("Version", u32), ("ProviderVersion", u32), ("NumberOfProcessors", u32),
                ("EndTime", i64), ("TimerResolution", u32), ("MaximumFileSize", u32), ("LogFileMode", u32),
                ("BuffersWritten", u32), ("LogInstanceGuid", GUID), ("LoggerName", ctypes.c_void_p),
                ("LogFileName", ctypes.c_void_p), ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", i64),
                ("PerfFreq", i64), ("StartTime", i64), ("ReservedFlags", u32), ("BuffersLost", u32)]


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    """evntrace.h; 448 bytes on win64. ProcessTraceMode is the union with
    LogFileMode; EventRecordCallback the union with EventCallback (a
    function pointer, held as an address)."""
    _fields_ = [("LogFileName", ctypes.c_void_p), ("LoggerName", ctypes.c_void_p), ("CurrentTime", i64),
                ("BuffersRead", u32), ("ProcessTraceMode", u32), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", ctypes.c_void_p), ("BufferSize", u32),
                ("Filled", u32), ("EventsLost", u32), ("EventRecordCallback", ctypes.c_void_p),
                ("IsKernelTrace", u32), ("Context", ctypes.c_void_p)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    """evntprov.h; 16 bytes."""
    _fields_ = [("Id", u16), ("Version", u8), ("Channel", u8), ("Level", u8), ("Opcode", u8), ("Task", u16),
                ("Keyword", u64)]


class EVENT_HEADER(ctypes.Structure):
    """evntcons.h; 80 bytes. ProcessorTime is the union with
    KernelTime/UserTime."""
    _fields_ = [("Size", u16), ("HeaderType", u16), ("Flags", u16), ("EventProperty", u16), ("ThreadId", u32),
                ("ProcessId", u32), ("TimeStamp", i64), ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                ("ProcessorTime", u64), ("ActivityId", GUID)]


class EVENT_RECORD(ctypes.Structure):
    """evntcons.h; 112 bytes on win64. BufferContext (ETW_BUFFER_CONTEXT) is
    laid out as its three fields."""
    _fields_ = [("EventHeader", EVENT_HEADER), ("ProcessorNumber", u8), ("Alignment", u8), ("LoggerId", u16),
                ("ExtendedDataCount", u16), ("UserDataLength", u16), ("ExtendedData", ctypes.c_void_p),
                ("UserData", ctypes.c_void_p), ("UserContext", ctypes.c_void_p)]


class Api:
    """The tracing functions of advapi32 the reader calls, with their ctypes
    signatures. Windows only (ctypes.WinDLL); a test passes a loader or
    replaces the whole object. Each function returns its Win32 error code
    but OpenTraceW, which returns a handle (INVALID_PROCESSTRACE_HANDLE and
    GetLastError on failure)."""

    def __init__(self, loader=None):
        loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))
        advapi32 = loader("advapi32")
        pointer = ctypes.POINTER

        def fn(dll, name, restype, *argtypes):
            f = getattr(dll, name)
            f.restype, f.argtypes = restype, list(argtypes)
            return f
        self.StartTraceW = fn(advapi32, "StartTraceW", u32, pointer(u64), ctypes.c_wchar_p, ctypes.c_void_p)
        self.EnableTraceEx2 = fn(advapi32, "EnableTraceEx2", u32, u64, pointer(GUID), u32, u8, u64, u64, u32,
                                 ctypes.c_void_p)
        self.OpenTraceW = fn(advapi32, "OpenTraceW", u64, pointer(EVENT_TRACE_LOGFILEW))
        self.ProcessTrace = fn(advapi32, "ProcessTrace", u32, pointer(u64), u32, ctypes.c_void_p, ctypes.c_void_p)
        self.CloseTrace = fn(advapi32, "CloseTrace", u32, u64)
        self.ControlTraceW = fn(advapi32, "ControlTraceW", u32, u64, ctypes.c_wchar_p, ctypes.c_void_p, u32)
        self.QueryAllTracesW = fn(advapi32, "QueryAllTracesW", u32, ctypes.c_void_p, u32, pointer(u32))

    byref = staticmethod(ctypes.byref)

    def last_error(self):
        return ctypes.get_last_error()

    def callback(self, function):
        """The EventRecordCallback: VOID WINAPI (PEVENT_RECORD), the record
        handed on as its address. The caller keeps it referenced."""
        return ctypes.WINFUNCTYPE(None, ctypes.c_void_p)(function)


# --- helpers ------------------------------------------------------------------------------

def session_name(pid):
    return "%s%d" % (SESSION_PREFIX, int(pid))


def guid(text):
    """A GUID of its text form, Data1 to Data3 as numbers (little-endian in
    memory), Data4 as its eight bytes in order."""
    raw = bytes.fromhex(text.replace("-", "").strip("{}"))
    g = GUID()
    g.Data1, g.Data2, g.Data3 = int.from_bytes(raw[0:4], "big"), int.from_bytes(raw[4:6], "big"), \
        int.from_bytes(raw[6:8], "big")
    for i, b in enumerate(raw[8:16]):
        g.Data4[i] = b
    return g


def guid_text(g):
    return "%08X-%04X-%04X-%s-%s" % (g.Data1, g.Data2, g.Data3, bytes(g.Data4[0:2]).hex().upper(),
                                      bytes(g.Data4[2:8]).hex().upper())


def utf16(text):
    """A NUL-terminated UTF-16 code-unit array (a PWSTR on Windows)."""
    data = text.encode("utf-16-le")
    units = struct.unpack("<%dH" % (len(data) // 2), data) + (0,)
    return (u16 * len(units))(*units)


def text_at(raw, offset):
    """The NUL-terminated UTF-16 text in bytes `raw` from `offset`."""
    end = offset
    while end + 1 < len(raw) and raw[end:end + 2] != b"\0\0":
        end += 2
    return raw[offset:end].decode("utf-16-le", "replace")


def filetime(value):
    """ISO UTC text of a FILETIME (100 ns since 1601-01-01), or "" for 0 or
    a value out of range."""
    if not value or value < 0:
        return ""
    start = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    try:
        dt = start + datetime.timedelta(microseconds=value // 10)
    except OverflowError:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_text():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def properties(start=False):
    """A buffer holding EVENT_TRACE_PROPERTIES and room for the session's
    name and a log file's name after it. start: the properties of the
    reader's session - real-time, no log file (LogFileNameOffset 0)."""
    head = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    size = head + 2 * NAME_ROOM * 2
    buf = ctypes.create_string_buffer(size)
    p = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    p.Wnode.BufferSize = size
    p.LoggerNameOffset = head
    p.LogFileNameOffset = head + NAME_ROOM * 2
    if start:
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        p.Wnode.ClientContext = CLIENT_CONTEXT_QPC
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        p.BufferSize = BUFFER_KB
        p.FlushTimer = FLUSH_SECONDS
        p.LogFileNameOffset = 0
    return buf


def lost_of(buf):
    p = EVENT_TRACE_PROPERTIES.from_buffer(buf)
    return {"events": int(p.EventsLost), "buffers": int(p.RealTimeBuffersLost), "why": None}


def unknown_lost(why):
    return {"events": None, "buffers": None, "why": why}


def refusal(step, code, name):
    """The reason, in this module's words, a step of the start was refused."""
    if code == ERROR_ACCESS_DENIED:
        text = "no rights: a tracing session needs an administrator, and no elevation is asked"
    elif code == ERROR_NO_SYSTEM_RESOURCES:
        text = "the limit of tracing sessions on this system is reached"
    elif code == ERROR_ALREADY_EXISTS:
        text = "a session named %s is already there" % name
    else:
        text = "the system refused it with error %d" % code
    return "the bytes are not read: %s (%s returned %d)" % (text, step, code)


def _flat(exc):
    return "%s: %s" % (type(exc).__name__, " ".join(str(exc).split()))


def parse(event_id, data):
    """(direction, pid, size, (local addr, local port), (remote addr, remote
    port)) of an event's data of the measured shape, or None: another id, or
    data shorter than the shape (never guessed)."""
    shape = EVENTS.get(event_id)
    if shape is None:
        return None
    direction, width = shape
    if len(data) < 8 + 2 * width + 4:
        return None
    pid, size = struct.unpack_from("<II", data, 0)
    daddr, saddr = data[8:8 + width], data[8 + width:8 + 2 * width]
    dport, sport = struct.unpack_from(">HH", data, 8 + 2 * width)      # network order
    make = ipaddress.IPv4Address if width == 4 else ipaddress.IPv6Address
    return direction, pid, size, (str(make(saddr)), sport), (str(make(daddr)), dport)


def shape_bytes(event_id):
    return 8 + 2 * EVENTS[event_id][1] + 4


# --- the reader ---------------------------------------------------------------------------

class Reader:
    """A real-time session of its own, raqib-net-<pid>, and its consumer.
    start() returns None or the reason it was refused (also kept in
    `refused`) and raises nothing; counts() is a copy, from any thread;
    stop() returns the problems of the stop ([] when clean) and does
    nothing the second time. api: an Api or a test's stand-in (None: Api()
    at start); now: the text of the session's start; thread: the thread
    class of the consumer."""

    def __init__(self, pid, api=None, now=None, thread=None):
        self.pid = int(pid)
        self.name = session_name(self.pid)
        self.refused = None
        self.ended = None            # why the consumer ended before stop (a hole), or None
        self.stop_problems = []
        self._api, self._now, self._thread_class = api, now or now_text, thread or threading.Thread
        self._lock = threading.Lock()
        self._connections, self._unread, self._other = {}, {}, 0
        self._since, self._session, self._trace, self._thread = None, None, None, None
        self._callback = None        # kept for the reader's life: the system holds its address
        self._logfile, self._name_units, self._final_lost = None, None, None
        self._state, self._stopping = "new", False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # start -------------------------------------------------------------------------------
    def start(self):
        if self._state != "new":
            return "this reader was started once already (%s)" % self._state
        try:
            why = self._start()
        except Exception as exc:
            why = "the bytes are not read: the reader failed while starting: %s" % _flat(exc)
        if why:
            undone = self._undo()
            why += "".join("; %s" % u for u in undone)
            self.refused, self._state = why, "refused"
            return why
        self._state = "running"
        return None

    def _start(self):
        if POINTER_BYTES != 8:
            return ("the bytes are not read: the tracing structures are laid out for 64-bit Windows and this"
                    " Python's pointers are %d bytes" % POINTER_BYTES)
        if self._api is None:
            try:
                self._api = Api()
            except (OSError, AttributeError) as exc:
                return "the bytes are not read: the tracing API cannot be loaded (%s)" % _flat(exc)
        api = self._api
        handle = u64(0)
        rc = api.StartTraceW(api.byref(handle), self.name, properties(start=True))
        if rc != ERROR_SUCCESS:
            return refusal("StartTraceW", rc, self.name)
        self._session = handle.value
        provider = guid(PROVIDER)
        rc = api.EnableTraceEx2(self._session, api.byref(provider), EVENT_CONTROL_CODE_ENABLE_PROVIDER, LEVEL,
                                KEYWORDS, 0, 0, None)
        if rc != ERROR_SUCCESS:
            return refusal("EnableTraceEx2", rc, self.name)
        self._since = self._now()
        self._name_units = utf16(self.name)
        self._callback = api.callback(self._on_event)
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = ctypes.addressof(self._name_units)
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = ctypes.cast(self._callback, ctypes.c_void_p).value
        self._logfile = logfile
        trace = api.OpenTraceW(api.byref(logfile))
        if trace is None or trace == INVALID_PROCESSTRACE_HANDLE:
            return refusal("OpenTraceW", api.last_error(), self.name)
        self._trace = trace
        self._thread = self._thread_class(target=self._consume, name=self.name, daemon=True)
        self._thread.start()
        return None

    def _undo(self):
        """After a failed start: close what was opened, stop what was
        started. The problems of the undoing, said with the reason."""
        problems, api = [], self._api
        if self._trace is not None:
            try:
                rc = api.CloseTrace(self._trace)
                if rc not in (ERROR_SUCCESS, ERROR_CTX_CLOSE_PENDING):
                    problems.append("CloseTrace returned %d" % rc)
            except Exception as exc:
                problems.append("CloseTrace failed: %s" % _flat(exc))
            self._trace = None
        if self._session is not None:
            try:
                rc = api.ControlTraceW(self._session, self.name, properties(), EVENT_TRACE_CONTROL_STOP)
                if rc not in (ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND):
                    problems.append("the session %s could not be stopped (ControlTraceW returned %d)"
                                    % (self.name, rc))
            except Exception as exc:
                problems.append("the session %s could not be stopped (%s)" % (self.name, _flat(exc)))
            self._session = None
        return problems

    # the consumer ------------------------------------------------------------------------
    def _consume(self):
        handles = (u64 * 1)(self._trace)
        try:
            text = "ProcessTrace returned %d" % self._api.ProcessTrace(handles, 1, None, None)
        except Exception as exc:
            text = "ProcessTrace failed: %s" % _flat(exc)
        with self._lock:
            if not self._stopping:
                self.ended = "the consumer ended before the stop (%s): from then on nothing is counted" % text

    def _count_unread(self, why):
        with self._lock:
            self._unread[why] = self._unread.get(why, 0) + 1

    def _on_event(self, address):
        """The EventRecordCallback, on the consumer's thread. It raises
        nothing: what it cannot read is counted."""
        try:
            self._take(address)
        except Exception as exc:
            self._count_unread("not read: %s" % type(exc).__name__)

    def _take(self, address):
        if not address:
            self._count_unread("a NULL record")
            return
        record = EVENT_RECORD.from_address(address)
        head = record.EventHeader
        if guid_text(head.ProviderId) != PROVIDER:
            with self._lock:
                self._other += 1        # not the provider's: the trace's own header event among them
            return
        event_id = int(head.EventDescriptor.Id)
        if event_id not in EVENTS:
            self._count_unread("id %d" % event_id)
            return
        length = int(record.UserDataLength)
        data = ctypes.string_at(record.UserData, length) if record.UserData and length else b""
        got = parse(event_id, data)
        if got is None:
            self._count_unread("id %d shorter than %d bytes" % (event_id, shape_bytes(event_id)))
            return
        direction, pid, size, local, remote = got
        when = filetime(head.TimeStamp)
        key = (pid, local[0], local[1], remote[0], remote[1])
        with self._lock:
            entry = self._connections.setdefault(key, {SENT: 0, RECEIVED: 0, "last": ""})
            entry[direction] += size
            entry["last"] = when

    # counts and stop ---------------------------------------------------------------------
    def _ask_lost(self):
        if self._state == "running":
            buf = properties()
            try:
                rc = self._api.ControlTraceW(self._session, self.name, buf, EVENT_TRACE_CONTROL_QUERY)
            except Exception as exc:
                return unknown_lost("ControlTraceW(query) failed (%s): what the session lost is not known"
                                    % _flat(exc))
            if rc != ERROR_SUCCESS:
                return unknown_lost("ControlTraceW(query) returned %d: what the session lost is not known" % rc)
            return lost_of(buf)
        if self._final_lost is not None:
            return dict(self._final_lost)
        return unknown_lost("no session: %s" % (self.refused or "the reader is not started"))

    def counts(self):
        """A copy: {"connections": {(pid, local addr, local port, remote
        addr, remote port): {"sent", "received", "last"}}, "since" (the
        session's start, None without one), "unread" and "unread_why",
        "other" (events of another provider), "lost" ({"events", "buffers",
        "why"}: asked of the session now; None and why where not known),
        "ended", "refused", "session"}."""
        lost = self._ask_lost()
        with self._lock:
            return {"session": self.name, "since": self._since,
                    "connections": {k: dict(v) for k, v in self._connections.items()},
                    "unread": sum(self._unread.values()), "unread_why": dict(self._unread), "other": self._other,
                    "lost": lost, "ended": self.ended, "refused": self.refused}

    def stop(self):
        """Stop the session (its last losses kept), close the consumer's
        trace, wait for the consumer. Raises nothing; the second call does
        nothing."""
        if self._state != "running":
            return []
        self._state = "stopping"
        with self._lock:
            self._stopping = True
        problems, api, buf = [], self._api, properties()
        try:
            rc = api.ControlTraceW(self._session, self.name, buf, EVENT_TRACE_CONTROL_STOP)
            if rc == ERROR_SUCCESS:
                self._final_lost = lost_of(buf)
            else:
                problems.append("ControlTraceW(stop) returned %d: the session %s may still run" % (rc, self.name))
        except Exception as exc:
            problems.append("ControlTraceW(stop) failed (%s): the session %s may still run" % (_flat(exc), self.name))
        try:
            rc = api.CloseTrace(self._trace)
            if rc not in (ERROR_SUCCESS, ERROR_CTX_CLOSE_PENDING):
                problems.append("CloseTrace returned %d" % rc)
        except Exception as exc:
            problems.append("CloseTrace failed (%s)" % _flat(exc))
        if self._thread is not None:
            self._thread.join(JOIN_SECONDS)
            if self._thread.is_alive():
                problems.append("the consumer did not end within %d seconds of the stop" % JOIN_SECONDS)
        if self._final_lost is None:
            self._final_lost = unknown_lost("the session's last losses were not read at its stop")
        self._session = self._trace = None
        self._state = "stopped"
        self.stop_problems = problems
        return problems


# --- leftovers ----------------------------------------------------------------------------

def sessions(api):
    """(the names of the tracing sessions running, why the list is not whole
    or None), by QueryAllTracesW."""
    bufs = [properties() for _ in range(SESSIONS_MAX)]
    array = (ctypes.c_void_p * SESSIONS_MAX)(*[ctypes.addressof(b) for b in bufs])
    found = u32(0)
    rc = api.QueryAllTracesW(array, SESSIONS_MAX, api.byref(found))
    if rc not in (ERROR_SUCCESS, ERROR_MORE_DATA):
        return [], "QueryAllTracesW returned %d: the sessions were not listed, no leftover was looked for" % rc
    names, nameless = [], 0
    for buf in bufs[:min(int(found.value), SESSIONS_MAX)]:
        offset = EVENT_TRACE_PROPERTIES.from_buffer(buf).LoggerNameOffset
        if not offset or offset + 2 > len(buf):
            nameless += 1
            continue
        names.append(text_at(buf.raw, offset))
    why = []
    if rc == ERROR_MORE_DATA:
        why.append("QueryAllTracesW: %d sessions, %d listed: a leftover among the rest is not seen"
                   % (found.value, SESSIONS_MAX))
    if nameless:
        why.append("QueryAllTracesW: %d session(s) listed without a name offset" % nameless)
    return names, "; ".join(why) or None


def leftovers(alive, api=None, problems=None):
    """Stop the sessions named raqib-net-<n> whose n is not in `alive` (the
    live pids; None: not known, and nothing is stopped) and return their
    names. A session of any other name is never touched. What went wrong
    is appended to `problems` (a list); nothing is raised."""
    problems = [] if problems is None else problems
    if alive is None:
        problems.append("leftovers not looked for: the live pids are not known")
        return []
    stopped = []
    try:
        api = api or Api()
        names, why = sessions(api)
        if why:
            problems.append(why)
        for name in names:
            match = LEFTOVER.match(name)
            if not match or int(match.group(1)) in alive:
                continue
            rc = api.ControlTraceW(0, name, properties(), EVENT_TRACE_CONTROL_STOP)
            if rc == ERROR_SUCCESS:
                stopped.append(name)
            elif rc == ERROR_WMI_INSTANCE_NOT_FOUND:
                problems.append("%s: gone before it was stopped" % name)
            else:
                problems.append("%s: a leftover not stopped (ControlTraceW(stop) returned %d)" % (name, rc))
    except Exception as exc:
        problems.append("leftovers: %s" % _flat(exc))
    return stopped
