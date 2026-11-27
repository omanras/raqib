"""`raqib service run` (ADR-0013 Amendment E, AE-1, AE-3, AE-4; Amendment F, AF-1 to AF-4): the host watch as a
service of Windows.

The shape is the one measured on GitHub's Windows machines, x64 and ARM64, plain and packed: the system's control
dispatcher (StartServiceCtrlDispatcherW) in a second thread, the watch in the main thread as it runs from a
console, by Raqib's own entry with the Linux unit's arguments (cli.main(["watch", "--host", "--no-page",
"--no-notify"], out)), and a Stop or a Shutdown from the system turned into the interrupt a person's Ctrl+C is.

The road (Runner.run): the dispatcher is started in a thread of its own. Where it says the process was not
started by the service manager (error 1063), or fails otherwise, or does not answer in CONNECT_WAIT seconds, or
the handler is not registered, that is said on the error stream and no watch starts (exit 2). Else the system's
call of the service's main registers the handler and reports START_PENDING (AF-2). The main thread then makes the
place ready (prepare()) and begins the text file; only then is RUNNING reported and the watch started. A refusal
of either is STOPPED straight from START_PENDING: no RUNNING is ever reported for it.

The place (AF-1): `Raqib` under the folder the environment names ProgramData (refused where that name is absent or
not a whole path of a drive). Nothing here sets an owner or a list on anything that exists. Absent, the place is
made by the one call that gives it the closed list as it is made (CreateDirectoryW with a security descriptor);
"it already exists" from that call (error 183) is the road of a place that is there. Made or found, it is read
through ONE handle on the name itself (CreateFileW with the flag that does not follow a link): its kind, its owner
and its list come from that one handle. It is taken only where that one read says a folder and no reparse point,
its owner the system (SY) or the administrators (BA), and its list CLOSED_AS_MADE; anything else is refused
and left exactly as it is. Only then are HOME and USERPROFILE of the process the place, as the Linux unit's HOME is
its state directory.

The text file (AE-3): TEXT_NAME in the place, begun anew at each start, the one before kept once as TEXT_BEFORE;
at most TEXT_MAX bytes: past its bound nothing more is written to it and its last line (FULL_LINE) says so, once;
a write that fails ends it too, with one last line where that can still be written, and the runner keeps that it
happened (exit EXIT_TEXT_ENDED where the system would be told 0). The record goes on. The standard output and
error streams, where they are None (a service has none), are the text file for the process.

A Stop or a Shutdown (AE-4, AF-4): STOP_PENDING, then the watch's own interrupt (raised only while the watch's
call runs), the watch's end, then STOPPED; nothing is reported after STOPPED. A watch's result 0, 1 or 3 after a
Stop is exit 0 to the system; so is a Stop that came before the watch gave any result, said in one line of the
text file. Each refusal, a watch that ended without being asked, an exception out of the watch and one of the
runner's own is STOPPED with the system's service-specific exit and a number of its own, EXIT_BASE + n (AF-3; the
list: EXIT_WORDS, docs/specs/SERVICE.md).

The watch before (ADR-0013 AH-2, AI-4, M12.4b): after RUNNING and before the watch, the runner asks
raqib/host.py's holder() whether another host watch's state still holds the place (unfinished, its heartbeat
fresh: a watch ended from outside leaves such a state). Where it does, one line of the text file says so, with the
heartbeat's age as read (ahead of the clock where it is), and the runner waits for that heartbeat to go stale - the
state's own staleness less its age, plus one second, never more than HELD_WAIT_MAX whatever numbers the state holds
- asking again every HELD_ASK_EVERY, on the system's waiting clock; then one line says how long the wait lasted and
how it ended (stale, finished, gone, cannot be read, its heartbeat unparsed, still fresh, or a Stop), and it starts
the watch, which says the watch before as a hole of its own (AH-1). A Stop during the wait ends it at once: no watch
is begun, the system is told 0. A state still fresh after the wait is a living watch: the watch's own refusal stands
(20). Not held, stale, one that cannot be read, or a heartbeat that cannot be parsed: no wait and no line (the watch
says the first two as holes and refuses the last itself, D-6).

Every call of the system (the platform, the environment, the dispatcher, the handler's registration, the status,
the interrupt, the place's making and its one read, the text file's beginning, the state of the watch before, the
clock and the wait, and the watch's own entry) goes through one object, System; a test hands its own, so no test
needs Windows, a service manager or ProgramData. ctypes is imported inside System, at its first call of Windows,
never at the module's import. Nothing runs at import. The standard library only; no program is started; no network.
One folder is made, the place; two names are read: the place's, and the state of the watch before inside it (its
host folder's rounds.jsonl.watch.json, through holder(), which writes nothing).
"""
from __future__ import annotations

import io
import ntpath
import os
import re
import signal
import sys
import threading
import time
import traceback
import types

SERVICE_NAME = "RaqibWatch"     # the table's name; a service of its own process may be installed under any name
WATCH_ARGV = ("watch", "--host", "--no-page", "--no-notify")   # the Linux unit's arguments (AE-1)
PLACE_NAME = "Raqib"            # the place: PLACE_NAME under ProgramData (AF-1)
HOME_NAMES = ("HOME", "USERPROFILE")
# The closed list: the system and the administrators, whole, nothing inherited. The system writes it in two forms
# (Amendment F, measured): as read back from a folder MADE with it, and as read back from a list SET on a folder
# that existed. A place is taken only in the first (AG-1): a folder that was closed after it existed was open
# once, and what was put in it then keeps its own owner. MADE_WITH is the text the making call is handed, as the
# measured candidate handed it (it reads back as CLOSED_AS_MADE).
CLOSED_AS_MADE = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
CLOSED_AS_SET = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
MADE_WITH = CLOSED_AS_SET
OWNERS = ("SY", "BA")           # the owners a place may have
TEXT_NAME = "service.txt"
TEXT_BEFORE = "service.before.txt"
TEXT_MAX = 8 * 1024 * 1024      # bytes of the text file, its last line included
FULL_LINE = ("raqib service run: this file reached its bound of %d bytes; nothing more is written to it (the"
             " watch's record goes on)\n" % TEXT_MAX)
LOST_LINE = "raqib service run: a write failed (%s); nothing more is written to this file\n"
CONNECT_WAIT = 25.0             # seconds the dispatcher has to call the service's main or to fail (the candidate's)
END_WAIT = 15.0                 # seconds waited for the dispatcher's return after STOPPED (the candidate's)
START_WAIT_HINT = 5000          # milliseconds told to the system with START_PENDING (the candidate's)
STOP_WAIT_HINT = 30000          # milliseconds told to the system with STOP_PENDING (the candidate's)

# The system's own numbers (winsvc.h, winerror.h, winbase.h, winnt.h, accctrl.h)
SERVICE_WIN32_OWN_PROCESS = 0x10
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
ACCEPT_STOP, ACCEPT_SHUTDOWN = 0x1, 0x4
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
NOT_BY_THE_MANAGER = 1063       # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (measured)
SERVICE_SPECIFIC = 1066         # ERROR_SERVICE_SPECIFIC_ERROR: the exit is the service's own number (measured, AF)
ALREADY_EXISTS = 183            # ERROR_ALREADY_EXISTS: CreateDirectoryW where the name is there (measured, AF)
SE_FILE_OBJECT = 1
OWNER_INFO, DACL_INFO = 0x1, 0x4
SDDL_REVISION_1 = 1
READ_CONTROL, FILE_READ_ATTRIBUTES = 0x20000, 0x80
FILE_SHARE_READ, FILE_SHARE_WRITE = 0x1, 0x2
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000     # a folder may be opened
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000   # the name itself, a link not followed
ATTRIBUTE_FOLDER = 0x10         # FILE_ATTRIBUTE_DIRECTORY
ATTRIBUTE_REPARSE = 0x400       # FILE_ATTRIBUTE_REPARSE_POINT (measured, AF: a junction and a link to a folder)

# The service-specific exits (AE-4, AF-3): EXIT_BASE + n, the range the system leaves to applications
EXIT_BASE = 0x20000000
EXIT_NO_PROGRAMDATA = EXIT_BASE + 10
EXIT_REPARSE = EXIT_BASE + 11
EXIT_NOT_FOLDER = EXIT_BASE + 12
EXIT_OWNER = EXIT_BASE + 13
EXIT_OPEN = EXIT_BASE + 14
EXIT_TEXT = EXIT_BASE + 16
EXIT_UNREAD = EXIT_BASE + 17
EXIT_TEXT_ENDED = EXIT_BASE + 18
EXIT_WATCH_REFUSED = EXIT_BASE + 20
EXIT_WATCH_ENDED = EXIT_BASE + 21
EXIT_WATCH_FAILED = EXIT_BASE + 22
EXIT_RUNNER_FAILED = EXIT_BASE + 23
EXIT_WORDS = {
    EXIT_NO_PROGRAMDATA: "ProgramData is not in the environment, or is not a whole path of a drive",
    EXIT_REPARSE: "the place is a reparse point (a junction or a link)",
    EXIT_NOT_FOLDER: "the place is there and is not a folder",
    EXIT_OWNER: "the place's owner is neither the system (SY) nor the administrators (BA)",
    EXIT_OPEN: "the place's list is not the closed one, whatever it holds",
    EXIT_TEXT: "the text file could not be begun in the place",
    EXIT_UNREAD: "the place could not be made, or could not be read through one handle on its name",
    EXIT_TEXT_ENDED: "a write to the text file failed and ended it (the watch's record went on)",
    EXIT_WATCH_REFUSED: "the watch refused to start (its result 2)",
    EXIT_WATCH_ENDED: "the watch ended without being asked (no Stop or Shutdown came), or with no result of its own",
    EXIT_WATCH_FAILED: "an exception came out of the watch",
    EXIT_RUNNER_FAILED: "an exception of the runner's own (not the watch's)",
}
WATCH_RESULTS = (0, 1, 3)       # clean, an alarm, incomplete: no failure of the service
HELD_FRESH = "fresh"            # raqib/host.py HELD_FRESH: holder()'s word for a state another watch still holds
HELD_WAIT_MAX = 60.0            # AH-2: seconds waited at most for the state of the watch before to go stale
HELD_ASK_EVERY = 1.0            # AH-2: seconds between two asks during that wait


class Refusal(Exception):
    """The place refused: its service-specific number and its words."""

    def __init__(self, number, words):
        super().__init__(words)
        self.number, self.words = number, words


class System:
    """Every call raqib service run makes of the system, here alone (a test hands an object of its own)."""

    def __init__(self):
        self._api = None
        self._kept = []         # the callbacks the system calls later, alive while it may call them

    def platform(self):
        return sys.platform

    def getenv(self, name):
        return os.environ.get(name)

    def setenv(self, name, value):
        os.environ[name] = value

    def _win(self):
        """The system's calls by ctypes, declared at the first call (as measured), never at import."""
        if self._api is not None:
            return self._api
        import ctypes
        from ctypes import wintypes

        class SERVICE_STATUS(ctypes.Structure):
            _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD)]

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                        ("bInheritHandle", wintypes.BOOL)]
        handler_ex = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                        wintypes.LPVOID)
        service_main = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

        class SERVICE_TABLE_ENTRY(ctypes.Structure):
            _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", service_main)]
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv.RegisterServiceCtrlHandlerExW.restype = wintypes.LPVOID
        adv.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_ex, wintypes.LPVOID]
        adv.SetServiceStatus.argtypes = [wintypes.LPVOID, ctypes.POINTER(SERVICE_STATUS)]
        adv.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRY)]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.ULONG)]
        adv.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 5
        k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SECURITY_ATTRIBUTES)]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.LocalFree.argtypes = [wintypes.LPVOID]
        self._api = types.SimpleNamespace(ctypes=ctypes, w=wintypes, adv=adv, k32=k32, status=SERVICE_STATUS,
                                          attributes=SECURITY_ATTRIBUTES, entry=SERVICE_TABLE_ENTRY,
                                          handler=handler_ex, main=service_main)
        return self._api

    # --- the service manager ---
    def dispatch(self, name, main):
        """Hand the system the service's table and wait: 0 once every service of the process stopped, else the
        system's error (NOT_BY_THE_MANAGER where no service manager started this process)."""
        api = self._win()

        def called(argc, argv):
            try:
                main()
            except BaseException:   # nothing may come out into the system's thread
                pass
        proc = api.main(called)
        self._kept.append(proc)
        table = (api.entry * 2)()
        table[0].lpServiceName, table[0].lpServiceProc = name, proc
        if api.adv.StartServiceCtrlDispatcherW(table):
            return 0
        return api.ctypes.get_last_error() or -1

    def register(self, name, handler):
        """Register handler(control) for the service's controls; the handle, or OSError."""
        api = self._win()

        def called(control, kind, data, context):
            try:
                handler(control)
            except BaseException:
                pass
            return 0
        fn = api.handler(called)
        self._kept.append(fn)
        handle = api.adv.RegisterServiceCtrlHandlerExW(name, fn, None)
        if not handle:
            raise OSError(api.ctypes.get_last_error(), "the handler was not registered")
        return handle

    def set_status(self, handle, state, accepted, win32_exit, specific_exit, wait_hint):
        api = self._win()
        s = api.status(SERVICE_WIN32_OWN_PROCESS, state, accepted, win32_exit, specific_exit, 0, wait_hint)
        return bool(api.adv.SetServiceStatus(handle, api.ctypes.byref(s)))

    def raise_interrupt(self):
        signal.raise_signal(signal.SIGINT)   # what a person's Ctrl+C is to the main thread (measured)

    # --- the place: one folder made, one name read ---
    def make_closed(self, path, sddl):
        """Make the folder with the list `sddl` in the one call that makes it: 0 where it was made, else the
        system's error (ALREADY_EXISTS where a thing of that name is there); OSError where the text is not taken."""
        api = self._win()
        ctypes, w = api.ctypes, api.w
        sd, size = w.LPVOID(), w.ULONG()
        if not api.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd),
                                                                            ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "the list's text was not taken")
        try:
            sa = api.attributes(ctypes.sizeof(api.attributes), sd, False)
            if api.k32.CreateDirectoryW(path, ctypes.byref(sa)):
                return 0
            return ctypes.get_last_error() or -1
        finally:
            api.k32.LocalFree(sd)

    def read_place(self, path):
        """(attributes, owner and list) of the name itself, through one handle on it (a link is not followed):
        the attributes as the system gives them, the owner and the list as one text (SDDL, "O:...D:...");
        OSError (the system's error) where the name cannot be opened or read."""
        api = self._win()
        ctypes, w, k32 = api.ctypes, api.w, api.k32
        h = k32.CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
        if h is None or h == w.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "the name was not opened")
        try:
            info = (w.DWORD * 13)()
            if not k32.GetFileInformationByHandle(h, ctypes.byref(info)):
                raise OSError(ctypes.get_last_error(), "its kind was not read")
            sd = w.LPVOID()
            rc = api.adv.GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_INFO | DACL_INFO, None, None, None, None,
                                         ctypes.byref(sd))
            if rc:
                raise OSError(rc, "its owner and list were not read")
            try:
                text, size = w.LPWSTR(), w.ULONG()
                if not api.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        sd, SDDL_REVISION_1, OWNER_INFO | DACL_INFO, ctypes.byref(text), ctypes.byref(size)):
                    raise OSError(ctypes.get_last_error(), "its owner and list were not written as text")
                said = text.value or ""
                k32.LocalFree(ctypes.cast(text, w.LPVOID))
            finally:
                k32.LocalFree(sd)
        finally:
            k32.CloseHandle(h)
        return info[0], said

    def begin_text(self, path, before):
        """The text file begun anew (binary): the one before kept once as `before`; OSError."""
        try:
            os.replace(path, before)
        except FileNotFoundError:
            pass
        return open(path, "xb")

    # --- the watch before (AH-2) ---
    def held(self, place):
        """raqib/host.py's holder() of the place's host folder (the watch's own, HOME being the place), at the
        wall clock: whether another host watch still holds it, and what was read."""
        from raqib import host
        return host.holder(home=place, wall=time.time)

    def clock(self):
        return time.monotonic()

    def pause(self, seconds, stop):
        """Waits `seconds`, or until `stop` (a threading.Event) is set: True where it is set (a Stop: at once)."""
        return stop.wait(seconds)

    # --- the watch ---
    def watch(self, argv, out):
        from raqib import cli   # Raqib's own entry (ADR-0007 CI-3)
        return cli.main(list(argv), out)


def _say(text):
    """One line on the error stream, where there is one; nothing fails where it is None or cannot be written (in
    a service it is None: the line is lost, and the system's state holds the number)."""
    try:
        sys.stderr.write("raqib: %s\n" % text)
        sys.stderr.flush()
    except Exception:
        pass


def _printable(value):
    """A value read from a state, as one short line of printable text."""
    return "".join(c if c.isprintable() else "?" for c in str(value))[:80]


def _seconds(value):
    """AI-4: a number read from a state as a float the wait can use, or None: a boolean, a text, NaN, or an integer
    too large for a float (10**400) is no such number. Infinity is kept (the bound holds it)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        value = float(value)
    except (OverflowError, ValueError):
        return None
    return value if value == value else None


def _number_said(value):
    """A number read from a state as it was read: %g where it is a float the wait can use, else printable, cut."""
    got = _seconds(value)
    return "%g" % got if got is not None else _read_said(value)


def _read_said(value):
    try:
        return _printable(value)[:40]
    except ValueError:   # an integer past str()'s digits
        return "a number too long to say"


def _age_said(value):
    """AI-4: the heartbeat's age as read: so many s ago, or so many s ahead of the clock (never 0 s ago for it)."""
    got = _seconds(value)
    if got is None:
        return "of an age that is no number (%s)" % _read_said(value)
    if got < 0:
        return "%g s ahead of this clock" % -got
    return "%.0f s ago" % got if got < 1e15 else "%g s ago" % got


ENDED_SAID = {"stale": "stale (the watch says the watch before as a hole)",
              "unparsed": "its heartbeat cannot be parsed (the watch refuses it)",
              "unreadable": "the state cannot be read (the watch says so as a hole)"}


def _ended_said(held, why):
    """AI-4: how a wait ended that was no longer held fresh, from holder()'s answer: stale, finished, gone, cannot
    be read; else what holder said (raqib/host.py's words, "no state" and "the state is finished", tied by a test)."""
    if held in ENDED_SAID:
        return ENDED_SAID[held]
    if why == "no state":
        return "gone (the state was removed; the watch before's end is not known)"
    if why == "the state is finished":
        return "finished (the watch before wrote its end)"
    return "no longer held (%s: %s)" % (_printable(held)[:20], _printable(why)[:80])


def _drive_path(text):
    return isinstance(text, str) and bool(re.match(r"[A-Za-z]:[\\/]", text)) and ".." not in re.split(r"[\\/]", text)


def _why(exc):
    number = exc.errno if exc.errno is not None else getattr(exc, "winerror", None)
    return "%s%s" % (exc.strerror or type(exc).__name__, " (error %s)" % number if number is not None else "")


def told(code):
    """What the system is told, in words."""
    return "exit 0" if code == 0 else "the service's own exit %d (0x%08X: %s)" % (code, code, EXIT_WORDS[code])


def owner_and_list(text):
    """("BA", "D:P...") of the system's text "O:BAD:P..."; ("", text) where there is no owner in it."""
    if not text.startswith("O:"):
        return "", text
    owner, mark, rest = text[2:].partition("D:")
    return owner, mark + rest


def prepare(system):
    """AF-1: the place made closed or found, read through one handle on its name and taken only as it reads;
    (place, road, owner, list), the road "made" or "found"; Refusal where it is not taken. Nothing is set on
    anything that exists."""
    root = system.getenv("ProgramData")
    if not _drive_path(root):
        raise Refusal(EXIT_NO_PROGRAMDATA, "ProgramData is %s" % ("absent from the environment" if root is None
                                                                 else "not a whole path of a drive: %r" % root))
    place = ntpath.join(root, PLACE_NAME)
    try:
        got = system.make_closed(place, MADE_WITH)
    except OSError as exc:
        raise Refusal(EXIT_UNREAD, "%s could not be made: %s" % (place, _why(exc)))
    if got not in (0, ALREADY_EXISTS):
        raise Refusal(EXIT_UNREAD, "%s could not be made (error %s)" % (place, got))
    road = "made" if got == 0 else "found"
    try:
        attributes, text = system.read_place(place)
    except OSError as exc:
        raise Refusal(EXIT_UNREAD, "%s (%s) could not be read through one handle on its name: %s"
                      % (place, road, _why(exc)))
    if attributes & ATTRIBUTE_REPARSE:
        raise Refusal(EXIT_REPARSE, "%s is a reparse point (attributes 0x%x); it is left as it is"
                      % (place, attributes))
    if not attributes & ATTRIBUTE_FOLDER:
        raise Refusal(EXIT_NOT_FOLDER, "%s is there and is not a folder (attributes 0x%x); it is left as it is"
                      % (place, attributes))
    owner, dacl = owner_and_list(text)
    if owner not in OWNERS:
        raise Refusal(EXIT_OWNER, "%s is owned by %s, neither the system (SY) nor the administrators (BA); it is"
                                  " left as it is" % (place, owner or "nobody said"))
    if dacl != CLOSED_AS_MADE:
        raise Refusal(EXIT_OPEN, "%s has the list %s, not the closed one as a folder made closed reads (%s); it is"
                                 " left as it is" % (place, dacl, CLOSED_AS_MADE))
    return place, road, owner, dacl


class Text(io.TextIOBase):
    """AE-3: the watch's report and errors, bounded: past `bound` bytes nothing more is written and the last line
    says so, once. A write that fails ends it the same way, with LOST_LINE where that can still be written, and
    `failed` keeps why. Nothing fails because of either."""

    def __init__(self, raw, bound=TEXT_MAX, full=FULL_LINE):
        super().__init__()
        self._raw, self._bound, self._full_line = raw, bound, full.encode("ascii")
        self._size, self._ended, self._ends_line = 0, False, True
        self.failed = None
        self._lock = threading.Lock()

    @property
    def encoding(self):
        return "utf-8"

    @property
    def errors(self):
        return "backslashreplace"

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, text):
        text = str(text)
        data = text.encode("utf-8", "backslashreplace")
        with self._lock:
            if self._ended or not data:
                return len(text)
            try:
                if self._size + len(data) + len(self._full_line) + 1 > self._bound:
                    last = (b"" if self._ends_line else b"\n") + self._full_line
                    self._ended = True
                    self._raw.write(last)
                    self._size += len(last)
                else:
                    self._raw.write(data)
                    self._size += len(data)
                    self._ends_line = data.endswith(b"\n")
                self._raw.flush()
            except (OSError, ValueError) as exc:
                self._lost(exc)
        return len(text)

    def _lost(self, exc):
        self._ended = True
        self.failed = _why(exc) if isinstance(exc, OSError) else "%s: %s" % (type(exc).__name__, exc)
        room = max(0, len(self._full_line) - len(LOST_LINE % ""))
        try:
            self._raw.write((b"" if self._ends_line else b"\n") + (LOST_LINE % self.failed[:room]).encode(
                "ascii", "replace"))
            self._raw.flush()
        except (OSError, ValueError):
            pass

    def flush(self):
        with self._lock:
            try:
                self._raw.flush()
            except (OSError, ValueError):
                pass

    def close(self):
        with self._lock:
            try:
                self._raw.close()
            except (OSError, ValueError):
                pass
        super().close()


def verdict(how, result, asked):
    """AE-4, AF-4: the service-specific exit of how the watch ended (0: nothing for the system to tell)."""
    if how in ("not begun", "interrupted"):
        return 0 if asked else EXIT_WATCH_ENDED
    if how == "returned":
        if result == 2:
            return EXIT_WATCH_REFUSED
        return 0 if asked and result in WATCH_RESULTS else EXIT_WATCH_ENDED
    return EXIT_WATCH_FAILED


class Runner:
    """AE-1, AE-3, AE-4, AF-2, AF-4: the dispatcher in a second thread, the place and the watch in this one."""

    def __init__(self, system):
        self.system = system
        self.handle = None
        self.failed = None          # the dispatcher's error, where it returned before the service's main
        self.why = None             # why the handler was not registered
        self.code = EXIT_RUNNER_FAILED   # the exit STOPPED carries: the runner's own until the road decides it
        self.text = None
        self.early = []             # the runner's lines before its text file is begun
        self.caught = []            # where an interrupt was caught outside the watch's call
        self.outcome = None         # (how, result, trace) of the watch's call, once it is over
        self.decided = False        # self.code is the watch's verdict
        self.finished = False       # the watch's end was said in the text file (AG-2)
        self.watching = False
        self.stopped = False        # STOPPED was reported: nothing is reported after it
        self.lock = threading.Lock()          # the interrupt is raised only while the watch's call runs
        self.status_lock = threading.Lock()
        self.note_lock = threading.Lock()
        self.answered = threading.Event()     # the service's main registered, or the dispatcher returned
        self.done = threading.Event()         # this thread's work is over: STOPPED may be reported
        self.ended = threading.Event()        # the dispatcher returned
        self.stop_asked = threading.Event()

    def _dispatch(self):
        try:
            got = self.system.dispatch(SERVICE_NAME, self._service_main)
            self.failed = got or None
        except Exception as exc:
            self.why = exc
        self.ended.set()
        self.answered.set()

    def _service_main(self):
        try:
            self.handle = self.system.register(SERVICE_NAME, self._control)
        except Exception as exc:
            self.why = exc
            self.answered.set()
            return
        self._status(START_PENDING)
        self.answered.set()
        self.done.wait()
        self._status(STOPPED)

    def _status(self, state):
        accepted = (ACCEPT_STOP | ACCEPT_SHUTDOWN) if state == RUNNING else 0
        hint = {START_PENDING: START_WAIT_HINT, STOP_PENDING: STOP_WAIT_HINT}.get(state, 0)
        with self.status_lock:
            if self.stopped:
                return False
            specific = self.code if state == STOPPED else 0
            self.stopped = state == STOPPED
            try:
                ok = self.system.set_status(self.handle, state, accepted, SERVICE_SPECIFIC if specific else 0,
                                            specific, hint)
            except Exception as exc:
                ok = False
                self._note("the status %d could not be told: %s: %s" % (state, type(exc).__name__, exc))
        if not ok:
            self._note("the system did not take the status %d" % state)
        return ok

    def _control(self, control):
        if control not in (CONTROL_STOP, CONTROL_SHUTDOWN):
            return
        try:
            with self.lock:
                if self.stop_asked.is_set() or self.stopped:
                    return
                self.stop_asked.set()
                self._status(STOP_PENDING)
                if self.watching:
                    self.system.raise_interrupt()
        except Exception as exc:
            self._note("the control %d could not be acted on: %s: %s" % (control, type(exc).__name__, exc))

    def _note(self, words):
        line = "raqib service run: %s\n" % words
        with self.note_lock:
            if self.text is None:
                self.early.append(line)
            else:
                self.text.write(line)

    def _begin(self, raw):
        with self.note_lock:
            self.text = Text(raw)
            for line in self.early:
                self.text.write(line)
            self.early = []

    def run(self):
        threading.Thread(target=self._dispatch, name="raqib-service-dispatcher", daemon=True).start()
        if not self.answered.wait(CONNECT_WAIT):
            _say("raqib service run: the service manager did not answer in %d s; no watch started" % CONNECT_WAIT)
            return 2
        if self.handle is None:
            if self.failed == NOT_BY_THE_MANAGER:
                _say("raqib service run: not started by the service manager (error %d): this command is run by"
                     " Windows as a service; no watch started" % NOT_BY_THE_MANAGER)
            elif self.failed is not None:
                _say("raqib service run: the service manager's dispatcher failed (error %s); no watch started"
                     % self.failed)
            else:
                _say("raqib service run: the service's handler was not registered (%s); no watch started"
                     % (_why(self.why) if isinstance(self.why, OSError) else type(self.why).__name__))
            return 2
        try:        # one interrupt at most is raised; wherever it surfaces after the watch's call, it is caught
            try:
                self._serve()
            except KeyboardInterrupt:   # AG-2: the end is still decided and still said
                self._caught("in the runner, outside the watch's call")
                if self.outcome is not None:
                    self._finish()
                elif self.text is not None and self.stop_asked.is_set():
                    self.code = EXIT_TEXT_ENDED if self.text.failed else 0   # a Stop asked was obeyed
                    self._note("the Stop's interrupt came before the watch's end was kept; the Stop was obeyed; the"
                               " system is told %s" % told(self.code))
            except BaseException as exc:
                self._own(exc)
            finally:
                self._end()
        except KeyboardInterrupt:
            self._caught("as the runner ended")
            self._end()
        return 0 if self.code == 0 else 2

    def _caught(self, where):
        self.caught.append(where)
        self._note("an interrupt came %s; it was caught (a Stop %s)"
                   % (where, "was asked" if self.stop_asked.is_set() else "was not asked"))

    def _own(self, exc):
        self.code = EXIT_RUNNER_FAILED
        trace = traceback.format_exc()
        if self.text is not None:
            self.text.write(trace)
            self._note("the runner ended by %s; the system is told %s" % (type(exc).__name__, told(self.code)))
        else:
            _say("raqib service run: the runner ended by %s: %s; no watch started (the system is told %s)"
                 % (type(exc).__name__, exc, told(self.code)))

    def _end(self):
        if self.text is not None:
            self.text.flush()
        self.done.set()
        self.ended.wait(END_WAIT)

    def _serve(self):
        try:
            place, road, owner, dacl = prepare(self.system)
        except Refusal as exc:
            self.code = exc.number
            _say("raqib service run: %s; no watch started (the system is told %s)" % (exc.words, told(exc.number)))
            return
        try:
            raw = self.system.begin_text(ntpath.join(place, TEXT_NAME), ntpath.join(place, TEXT_BEFORE))
        except OSError as exc:
            self.code = EXIT_TEXT
            _say("raqib service run: the text file was not begun in %s: %s; no watch started (the system is told"
                 " %s)" % (place, _why(exc), told(EXIT_TEXT)))
            return
        self._begin(raw)
        if sys.stdout is None:
            sys.stdout = self.text
        if sys.stderr is None:
            sys.stderr = self.text
        for name in HOME_NAMES:
            self.system.setenv(name, place)
        self._note("the place %s (%s; owner %s, its list %s); HOME and USERPROFILE are the place; the watch:"
                   " raqib %s" % (place, road, owner, dacl, " ".join(WATCH_ARGV)))
        with self.lock:
            if not self.stop_asked.is_set():
                self._status(RUNNING)
        self._wait_for(place)
        self.outcome = self._watch()
        self._finish()

    def _wait_for(self, place):
        """AH-2, AI-4: where the state of another host watch still holds the place, one line (the age as read,
        ahead of the clock where it is), then a wait of the state's own staleness less its age plus one second, at
        most HELD_WAIT_MAX whatever numbers the state holds, asked again every HELD_ASK_EVERY (the last pause the
        part of a second left), measured on the system's waiting clock, until it is no longer held fresh, the wait
        is over, or a Stop comes (at once: the watch is then not begun); then one line: how long it lasted and how
        it ended. An exception out of System.held is the runner's own (23)."""
        if self.stop_asked.is_set():
            return
        held = self.system.held(place)
        if not isinstance(held, dict) or held.get("held") != HELD_FRESH:
            return
        stale, age = _seconds(held.get("stale")), _seconds(held.get("age"))
        rest = None if stale is None or age is None else stale - age
        wait = HELD_WAIT_MAX if rest is None or rest != rest else min(max(rest, 0.0) + 1.0, HELD_WAIT_MAX)
        self._note("another host watch's state still holds the place (run %s, pid %s, heartbeat %s, stale after %s"
                   " s): it was ended without its end, or it still watches; waiting up to %.1f s for it to go stale,"
                   " asked again every %g s, then the watch" % (
                       _printable(held.get("run")), _printable(held.get("pid")), _age_said(held.get("age")),
                       _number_said(held.get("stale")), wait, HELD_ASK_EVERY))
        began = self.system.clock()
        how = "still fresh after the whole wait (a living watch, or a heartbeat ahead of the clock: the watch's own" \
              " refusal stands)"
        while True:
            left = wait - (self.system.clock() - began)
            if not left > 0:
                break
            if self.system.pause(min(HELD_ASK_EVERY, left), self.stop_asked):
                how = "a Stop: no watch is begun"
                break
            held = self.system.held(place)
            got = held.get("held") if isinstance(held, dict) else None
            if got != HELD_FRESH:
                how = _ended_said(got, held.get("why") if isinstance(held, dict) else None)
                break
        lasted = self.system.clock() - began
        self._note("the wait for the state of the watch before lasted %.1f s and ended: %s" % (
            lasted if lasted == lasted else 0.0, how))

    def _finish(self):
        """The end of the watch's call: its exit decided, its trace and the runner's last line written. Once -
        and again, whole, where the Stop's one interrupt surfaced in the middle of it (AG-2: the last line is
        always there)."""
        if self.finished or self.outcome is None:
            return
        how, result, asked, code = self._decide()
        if self.outcome[2]:
            self.text.write(self.outcome[2])
        if how in ("not begun", "interrupted") and asked:
            self._note("the watch was stopped before it gave a report (%s); the Stop was obeyed; the system is told"
                       " %s" % ("it was not begun" if how == "not begun" else "it was interrupted", told(code)))
        else:
            self._note("the watch %s%s; a Stop %s; the system is told %s" % (
                how, " with %r" % (result,) if how == "returned" else "", "was asked" if asked else "was not asked",
                told(code)))
        if self.code == 0 and self.text.failed:
            self.code = EXIT_TEXT_ENDED     # its last note was the write that failed
        self.finished = True

    def _decide(self):
        """The exit of the watch's call as it ended (AE-4, AF-4), kept in self.code at once."""
        how, result, _trace = self.outcome
        asked = self.stop_asked.is_set()
        code = verdict(how, result, asked)
        if code == 0 and self.text.failed:
            code = EXIT_TEXT_ENDED      # the runner keeps that its text file was ended by a failed write
        self.code, self.decided = code, True
        return how, result, asked, code

    def _watch(self):
        """("not begun" | "returned" | "interrupted" | "ended by NAME", result, traceback or "")."""
        how, result = None, None
        try:
            try:
                with self.lock:
                    if self.stop_asked.is_set():
                        return "not begun", None, ""
                    self.watching = True
                how, result = "returned", self.system.watch(WATCH_ARGV, self.text)
            finally:
                with self.lock:
                    self.watching = False
        except KeyboardInterrupt:
            if how == "returned":
                self._caught("after the watch returned")
                return how, result, ""
            return "interrupted", None, ""
        except BaseException as exc:
            return "ended by %s" % type(exc).__name__, None, traceback.format_exc()
        return how, result, ""


def cli_run(args, out, system=None):
    """`raqib service run` from raqib/cli.py (its only importer): exit 0 where the system was told exit 0, 2
    otherwise (said on the error stream where there is one). Off Windows its one line comes first, with --no-start or
    --purge given or not."""
    system = system or System()
    platform = system.platform()
    if platform != "win32":
        _say("raqib service run: Windows only (the system's service manager runs it); this is %s" % platform)
        return 2
    for flag, owner in (("no_start", "install"), ("purge", "remove")):
        if getattr(args, flag, False):
            _say("raqib service: --%s is %s's only" % (flag.replace("_", "-"), owner))
            return 2
    return Runner(system).run()
