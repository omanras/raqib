"""`raqib service run` (ADR-0013 Amendment E, AE-1 to AE-4): the host watch as a service of Windows.

The shape is the one measured on GitHub's Windows machines, x64 and ARM64, plain and packed: the system's control
dispatcher (StartServiceCtrlDispatcherW) in a second thread, the watch in the main thread as it runs from a
console, by Raqib's own entry with the Linux unit's arguments (cli.main(["watch", "--host", "--no-page",
"--no-notify"], out)), and a Stop or a Shutdown from the system turned into the interrupt a person's Ctrl+C is.

The road (Runner.run): the dispatcher is started in a thread of its own. Where it says the process was not
started by the service manager (error 1063), or fails otherwise, or does not answer in CONNECT_WAIT seconds, that
is said on the error stream and no watch starts (exit 2). Else the system's call of the service's main registers
the handler and reports RUNNING. Then the place (AE-2, prepare()): `Raqib` under the folder the environment names
ProgramData (refused where that name is absent or not a whole path of a drive). Refuse rather than repair: absent,
it is made and closed; a link (or any reparse point) is refused, and so is a thing there that is not a folder; an
owner that is neither the system (SY) nor the administrators (BA) is refused; a list that is not CLOSED on a folder
that is not empty is refused (what a stranger left is not adopted); open and empty, it is closed. A folder made or
closed here that is not empty after it was closed is refused. After every road the owner and the list are read
back: the list must be CLOSED and the owner SY or BA, or no watch starts. Only then are HOME and USERPROFILE of the
process the place, as the Linux unit's HOME is its state directory.

The text file (AE-3): TEXT_NAME in the place, begun anew at each start, the one before kept once as TEXT_BEFORE;
at most TEXT_MAX bytes: past its bound nothing more is written to it and its last line (FULL_LINE) says so, once;
the record goes on. A standard stream that is None (a service has none) is replaced by it for the process.

A Stop or a Shutdown (AE-4): STOP_PENDING, then the watch's own interrupt (raised only while the watch runs; a Stop
before it begins means it is not begun), the watch's end with its final report, then STOPPED. A watch's result 0,
1 or 3 after a Stop is exit 0 to the system; each refusal, and a watch that ended without being asked, is STOPPED
with the system's service-specific exit and a number of its own (EXIT_WORDS, docs/specs/SERVICE.md).

Every call of the system (the platform, the environment, the dispatcher, the handler's registration, the status,
the interrupt, a folder's kind, its making, its listing, its owner and list read and its list set, the text file's
beginning, and the watch's own entry) goes through one object, System; a test hands its own, so no test needs
Windows, a service manager or ProgramData. ctypes is imported inside System, at its first call of Windows, never
at the module's import. Nothing runs at import. The standard library only; no program is started; no network.
The access list is set, and the owner read, of one folder only: the place.
"""
from __future__ import annotations

import io
import ntpath
import os
import re
import signal
import stat as statmod
import sys
import threading
import traceback

SERVICE_NAME = "RaqibWatch"     # the table's name; a service of its own process may be installed under any name
WATCH_ARGV = ("watch", "--host", "--no-page", "--no-notify")   # the Linux unit's arguments (AE-1)
PLACE_NAME = "Raqib"            # the place: PLACE_NAME under ProgramData (AE-2)
HOME_NAMES = ("HOME", "USERPROFILE")
CLOSED = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"   # the system and the administrators, whole; nothing inherited
OWNERS = ("SY", "BA")           # the owners a place may have
TEXT_NAME = "service.txt"
TEXT_BEFORE = "service.before.txt"
TEXT_MAX = 8 * 1024 * 1024      # bytes of the text file, its last line included
FULL_LINE = ("raqib service run: this file reached its bound of %d bytes; nothing more is written to it (the"
             " watch's record goes on)\n" % TEXT_MAX)
CONNECT_WAIT = 25.0             # seconds the dispatcher has to call the service's main or to fail (the candidate's)
END_WAIT = 15.0                 # seconds waited for the dispatcher's return after STOPPED (the candidate's)
STOP_WAIT_HINT = 30000          # milliseconds told to the system with STOP_PENDING (the candidate's)

# The system's own numbers (winsvc.h, winerror.h, accctrl.h, winnt.h)
SERVICE_WIN32_OWN_PROCESS = 0x10
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
ACCEPT_STOP, ACCEPT_SHUTDOWN = 0x1, 0x4
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
NOT_BY_THE_MANAGER = 1063       # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (measured)
SERVICE_SPECIFIC = 1066         # ERROR_SERVICE_SPECIFIC_ERROR: the exit is the service's own number (not measured)
SE_FILE_OBJECT = 1
OWNER_INFO, DACL_INFO, PROTECTED_DACL = 0x1, 0x4, 0x80000000
SDDL_REVISION_1 = 1
REPARSE_POINT = 0x400           # FILE_ATTRIBUTE_REPARSE_POINT: a link, a junction, any reparse point

# The service-specific exits (AE-4): one number for each refusal and for a watch that ended without being asked
EXIT_NO_PROGRAMDATA = 10
EXIT_LINK = 11
EXIT_NOT_FOLDER = 12
EXIT_OWNER = 13
EXIT_OPEN = 14
EXIT_NOT_CLOSED = 15
EXIT_TEXT = 16
EXIT_WATCH_REFUSED = 20
EXIT_WATCH_ENDED = 21
EXIT_WATCH_FAILED = 22
EXIT_WORDS = {
    EXIT_NO_PROGRAMDATA: "ProgramData is not in the environment, or is not a whole path of a drive",
    EXIT_LINK: "the place is a link (a reparse point)",
    EXIT_NOT_FOLDER: "the place is there and is not a folder",
    EXIT_OWNER: "the place's owner is neither the system (SY) nor the administrators (BA)",
    EXIT_OPEN: "the place is open (its list is not the closed one) and not empty",
    EXIT_NOT_CLOSED: ("the place could not be read, made or closed, or after it was its list read back is not the"
                      " closed one, or a place made or closed here was not empty after it was closed"),
    EXIT_TEXT: "the text file could not be begun in the place",
    EXIT_WATCH_REFUSED: "the watch refused to start (its result 2)",
    EXIT_WATCH_ENDED: "the watch ended without being asked (no Stop or Shutdown came), or with no result of its own",
    EXIT_WATCH_FAILED: "an exception came out of the watch",
}
WATCH_RESULTS = (0, 1, 3)       # clean, an alarm, incomplete: no failure of the service


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
        adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 5
        adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.ULONG)]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
        adv.GetSecurityDescriptorDacl.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL),
                                                  ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.BOOL)]
        adv.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD] + [wintypes.LPVOID] * 4
        k32.LocalFree.argtypes = [wintypes.LPVOID]
        self._api = (ctypes, wintypes, adv, k32, SERVICE_STATUS, SERVICE_TABLE_ENTRY, handler_ex, service_main)
        return self._api

    # --- the service manager ---
    def dispatch(self, name, main):
        """Hand the system the service's table and wait: 0 once every service of the process stopped, else the
        system's error (NOT_BY_THE_MANAGER where no service manager started this process)."""
        ctypes, _w, adv, _k, _status, entry, _handler, service_main = self._win()

        def called(argc, argv):
            try:
                main()
            except BaseException:   # nothing may come out into the system's thread
                pass
        proc = service_main(called)
        self._kept.append(proc)
        table = (entry * 2)()
        table[0].lpServiceName, table[0].lpServiceProc = name, proc
        if adv.StartServiceCtrlDispatcherW(table):
            return 0
        return ctypes.get_last_error() or -1

    def register(self, name, handler):
        """Register handler(control) for the service's controls; the handle, or OSError."""
        ctypes, _w, adv, _k, _status, _entry, handler_ex, _main = self._win()

        def called(control, kind, data, context):
            try:
                handler(control)
            except BaseException:
                pass
            return 0
        fn = handler_ex(called)
        self._kept.append(fn)
        handle = adv.RegisterServiceCtrlHandlerExW(name, fn, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "the handler was not registered")
        return handle

    def set_status(self, handle, state, accepted, win32_exit, specific_exit, wait_hint):
        ctypes, _w, adv, _k, status, _entry, _handler, _main = self._win()
        s = status(SERVICE_WIN32_OWN_PROCESS, state, accepted, win32_exit, specific_exit, 0, wait_hint)
        return bool(adv.SetServiceStatus(handle, ctypes.byref(s)))

    def raise_interrupt(self):
        signal.raise_signal(signal.SIGINT)   # what a person's Ctrl+C is to the main thread (measured)

    # --- the place: one folder only ---
    def kind(self, path):
        """"absent", "link" (a reparse point of any kind), "folder" or "other"; OSError where it cannot be read."""
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "absent"
        if statmod.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & REPARSE_POINT:
            return "link"
        return "folder" if statmod.S_ISDIR(st.st_mode) else "other"

    def make_folder(self, path):
        os.mkdir(path)

    def listdir(self, path):
        return os.listdir(path)

    def read_security(self, path):
        """(owner, list) of the folder as the system writes them (SDDL): the owner without its "O:", the list
        whole ("D:..."); OSError where either cannot be read."""
        ctypes, wintypes, adv, k32, _s, _e, _h, _m = self._win()
        sd = wintypes.LPVOID()
        rc = adv.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_INFO | DACL_INFO, None, None, None, None,
                                       ctypes.byref(sd))
        if rc:
            raise OSError(rc, "the owner and the list were not read")
        try:
            said = []
            for info in (OWNER_INFO, DACL_INFO):
                text, size = wintypes.LPWSTR(), wintypes.ULONG()
                if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info,
                                                                               ctypes.byref(text),
                                                                               ctypes.byref(size)):
                    raise OSError(ctypes.get_last_error(), "the owner or the list was not written as text")
                said.append(text.value or "")
                k32.LocalFree(ctypes.cast(text, wintypes.LPVOID))
        finally:
            k32.LocalFree(sd)
        owner = said[0][2:] if said[0].startswith("O:") else said[0]
        return owner, said[1]

    def close_folder(self, path, sddl):
        """Give the folder the list `sddl`, protected (nothing inherited), by the system's own calls; OSError."""
        ctypes, wintypes, adv, k32, _s, _e, _h, _m = self._win()
        sd, size = wintypes.LPVOID(), wintypes.ULONG()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd),
                                                                        ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "the list's text was not taken")
        try:
            present, dacl, defaulted = wintypes.BOOL(), wintypes.LPVOID(), wintypes.BOOL()
            if not adv.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl),
                                                 ctypes.byref(defaulted)) or not present.value:
                raise OSError(ctypes.get_last_error(), "the list was not found in its text")
            rc = adv.SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_INFO | PROTECTED_DACL, None, None, dacl, None)
            if rc:
                raise OSError(rc, "the list was not set")
        finally:
            k32.LocalFree(sd)

    def begin_text(self, path, before):
        """The text file begun anew (binary): the one before kept once as `before`; OSError."""
        try:
            os.replace(path, before)
        except FileNotFoundError:
            pass
        return open(path, "xb")

    # --- the watch ---
    def watch(self, argv, out):
        from raqib import cli   # Raqib's own entry (ADR-0007 CI-3)
        return cli.main(list(argv), out)


def _say(text):
    """One line on the error stream, where there is one; nothing fails where it is None or cannot be written."""
    try:
        sys.stderr.write("raqib: %s\n" % text)
        sys.stderr.flush()
    except Exception:
        pass


def _drive_path(text):
    return isinstance(text, str) and bool(re.match(r"[A-Za-z]:[\\/]", text)) and ".." not in re.split(r"[\\/]", text)


def prepare(system):
    """AE-2: the place, closed and owned right, and the road taken ("made", "closed", "taken as it is"); Refusal
    where it cannot be. The list is set, and the owner read, of the place alone."""
    root = system.getenv("ProgramData")
    if not _drive_path(root):
        raise Refusal(EXIT_NO_PROGRAMDATA, "ProgramData is %s" % ("absent from the environment" if root is None
                                                                 else "not a whole path of a drive: %r" % root))
    place = ntpath.join(root, PLACE_NAME)

    def read(what, call, *args):
        try:
            return call(*args)
        except OSError as exc:
            raise Refusal(EXIT_NOT_CLOSED, "%s %s: %s" % (place, what, _why(exc)))

    def kind():
        got = read("could not be read", system.kind, place)
        if got == "link":
            raise Refusal(EXIT_LINK, "%s is a link (a reparse point); it is not followed" % place)
        if got not in ("absent", "folder"):
            raise Refusal(EXIT_NOT_FOLDER, "%s is there and is not a folder" % place)
        return got

    def owned(owner):
        if owner not in OWNERS:
            raise Refusal(EXIT_OWNER, "%s is owned by %s, neither the system (SY) nor the administrators (BA)"
                          % (place, owner))
    if kind() == "absent":
        read("could not be made", system.make_folder, place)
        road = "made"
    else:
        owner, dacl = read("could not be read", system.read_security, place)
        owned(owner)
        if dacl == CLOSED:
            road = "taken as it is"
        elif read("could not be listed", system.listdir, place):
            raise Refusal(EXIT_OPEN, "%s is open (%s) and not empty: what is in it is not adopted" % (place, dacl))
        else:
            road = "closed"
    if road != "taken as it is":
        read("could not be closed", system.close_folder, place, CLOSED)
        if read("could not be listed", system.listdir, place):
            raise Refusal(EXIT_NOT_CLOSED, "%s was not empty after it was closed" % place)
    kind()
    owner, dacl = read("could not be read back", system.read_security, place)
    owned(owner)
    if dacl != CLOSED:
        raise Refusal(EXIT_NOT_CLOSED, "%s read back %s, not %s" % (place, dacl, CLOSED))
    return place, road, owner


def _why(exc):
    number = exc.errno if exc.errno is not None else getattr(exc, "winerror", None)
    return "%s%s" % (exc.strerror or type(exc).__name__, " (error %s)" % number if number is not None else "")


class Text(io.TextIOBase):
    """AE-3: the watch's report and errors, bounded: past `bound` bytes nothing more is written and the last line
    says so, once. A write that fails is dropped; nothing fails because of it."""

    def __init__(self, raw, bound=TEXT_MAX, full=FULL_LINE):
        super().__init__()
        self._raw, self._bound, self._full_line = raw, bound, full.encode("ascii")
        self._size, self._full, self._ends_line = 0, False, True
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
            if self._full or not data:
                return len(text)
            try:
                if self._size + len(data) + len(self._full_line) + 1 > self._bound:
                    last = (b"" if self._ends_line else b"\n") + self._full_line
                    self._raw.write(last)
                    self._size += len(last)
                    self._full = True
                else:
                    self._raw.write(data)
                    self._size += len(data)
                    self._ends_line = data.endswith(b"\n")
                self._raw.flush()
            except (OSError, ValueError):
                self._full = True
        return len(text)

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
    """AE-4: the service-specific exit of how the watch ended (0: nothing for the system to tell)."""
    if how == "not begun":
        return 0
    if how == "interrupted":
        return 0 if asked else EXIT_WATCH_ENDED
    if how == "returned":
        if result == 2:
            return EXIT_WATCH_REFUSED
        return 0 if asked and result in WATCH_RESULTS else EXIT_WATCH_ENDED
    return EXIT_WATCH_FAILED


class Runner:
    """AE-1 to AE-4: the dispatcher in a second thread, the watch in this one."""

    def __init__(self, system):
        self.system = system
        self.handle = None
        self.failed = None          # the dispatcher's error, where it returned before the service's main
        self.why = None             # why the handler was not registered
        self.code = 0               # the service-specific exit, 0 none
        self.text = None
        self.watching = False
        self.lock = threading.Lock()          # the interrupt is raised only while the watch runs
        self.status_lock = threading.Lock()
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
        self._status(RUNNING)
        self.answered.set()
        self.done.wait()
        self._status(STOPPED)

    def _status(self, state):
        accepted = (ACCEPT_STOP | ACCEPT_SHUTDOWN) if state == RUNNING else 0
        specific = self.code if state == STOPPED else 0
        with self.status_lock:
            ok = self.system.set_status(self.handle, state, accepted, SERVICE_SPECIFIC if specific else 0,
                                        specific, STOP_WAIT_HINT if state == STOP_PENDING else 0)
        if not ok:
            self._note("the system did not take the status %d" % state)

    def _control(self, control):
        if control not in (CONTROL_STOP, CONTROL_SHUTDOWN):
            return
        with self.lock:
            if self.stop_asked.is_set():
                return
            self.stop_asked.set()
            self._status(STOP_PENDING)
            if self.watching:
                self.system.raise_interrupt()

    def _note(self, words):
        if self.text is not None:
            self.text.write("raqib service run: %s\n" % words)

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
        code = EXIT_WATCH_FAILED
        try:
            code = self._serve()
        finally:
            self.code = code
            self.done.set()
            self.ended.wait(END_WAIT)
        return 0 if code == 0 else 2

    def _serve(self):
        try:
            place, road, owner = prepare(self.system)
        except Refusal as exc:
            _say("raqib service run: %s; no watch started (exit %d to the system: %s)"
                 % (exc.words, exc.number, EXIT_WORDS[exc.number]))
            return exc.number
        try:
            raw = self.system.begin_text(ntpath.join(place, TEXT_NAME), ntpath.join(place, TEXT_BEFORE))
        except OSError as exc:
            _say("raqib service run: the text file was not begun in %s: %s; no watch started (exit %d to the"
                 " system)" % (place, _why(exc), EXIT_TEXT))
            return EXIT_TEXT
        self.text = Text(raw)
        if sys.stdout is None:
            sys.stdout = self.text
        if sys.stderr is None:
            sys.stderr = self.text
        for name in HOME_NAMES:
            self.system.setenv(name, place)
        self._note("the place %s (%s; owner %s, its list %s); HOME and USERPROFILE are the place; the watch:"
                   " raqib %s" % (place, road, owner, CLOSED, " ".join(WATCH_ARGV)))
        how, result, trace = self._watch()
        if trace:
            self.text.write(trace)
        code = verdict(how, result, self.stop_asked.is_set())
        self._note("the watch %s%s; a Stop %s; the system is told %s" % (
            how, " with %r" % (result,) if how == "returned" else "",
            "was asked" if self.stop_asked.is_set() else "was not asked",
            "exit 0" if code == 0 else "the service's exit %d (%s)" % (code, EXIT_WORDS[code])))
        self.text.flush()
        return code

    def _watch(self):
        """("not begun" | "returned" | "interrupted" | "ended by NAME", result, traceback or "")."""
        try:
            try:
                with self.lock:
                    self.watching = True
                    if self.stop_asked.is_set():
                        return "not begun", None, ""
                return "returned", self.system.watch(WATCH_ARGV, self.text), ""
            finally:
                with self.lock:
                    self.watching = False
        except KeyboardInterrupt:
            return "interrupted", None, ""
        except BaseException as exc:
            return "ended by %s" % type(exc).__name__, None, traceback.format_exc()


def cli_run(args, out, system=None):
    """`raqib service run` from raqib/cli.py (its only importer): exit 0 where the system was told exit 0, 2
    otherwise (said on the error stream where there is one)."""
    system = system or System()
    for flag, owner in (("no_start", "install"), ("purge", "remove")):
        if getattr(args, flag, False):
            _say("raqib service: --%s is %s's only" % (flag.replace("_", "-"), owner))
            return 2
    platform = system.platform()
    if platform != "win32":
        _say("raqib service run: Windows only (the system's service manager runs it); this is %s" % platform)
        return 2
    return Runner(system).run()
