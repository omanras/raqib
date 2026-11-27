"""`raqib service install | remove` on Windows (ADR-0013 Amendment X, X-2 to X-6 and X-8; M12.4c2b2b): Raqib's
service of Windows made and removed by the system's own calls, with the rights measured and no more.

What was measured before this was ruled (Amendment X's first paragraph, the probe 639362e and dc172b1; x64 and ARM64,
the same), each call by an administrator: the service manager opened to connect and to make a service (0x3);
CreateServiceW of a process of its own (0x10), automatic start (2), error control 1, no account named (read back as
LocalSystem), shown as `Raqib watch`, its handle asked with 0x17; ChangeServiceConfig2W on it at level 1 (the mark as
its description), level 2 (started again after 5000, 30000 and 300000 ms, the count forgotten after 3600 s) and level
4 (the failure flag); StartServiceW, the state START_PENDING then RUNNING; a service opened with 0x10024, a Stop,
STOPPED, DeleteService, and the name asked for again answering 1060; a Stop while it waits for its next start
answering 1062. From Amendments T, U and W: a Stop while it starts answers 1052; a name already there answers 1073
to a making, one marked for removal 1072. This module itself was not run on a real machine: the rig reads it as X54
(X-7).

install (X-3), in this order, one line each, and at the first that fails nothing more is made: Windows; the check of
this process's own code by raqib/wincode.py's own functions (not_asked on the plain road, then check), refused in
`raqib service check`'s words; the place, where it is already there, read by winservice.System.read_place and judged
by winservice's own numbers as winservice.prepare judges a place it finds (prepare itself is never called: it makes
the place), and refused where the runner would refuse it at its start; a place not there is the runner's to make, at
its first start, as the system (X-8) - nothing is made or changed there either way; the manager opened to make (error
5: an administrator is needed); no service of the name, asked by the reader (raqib/winmanager.py) - one there is never
touched: Raqib's by its mark is to be removed first, another's is said and left, 1073 and 1072 from the making said
too; the command for this very process by the path the check judged (packed: `"<program>" service run`; plain:
`"<python>" -I -m raqib service run`, winmanager.FORMS), refused where the path holds a quote or a character that is
not printable; the service made; its description (DESCRIPTION, the mark first), its failure actions (X-5) and the
failure flag - where one of the three fails, what was made is removed again (DeleteService) and that is said, or that
it could not be. --no-start ends there. Else StartServiceW and a wait on the state (X-4), asked every ASK_EVERY
seconds through the system object's sleep and clock, until RUNNING or STOPPED or the bound (the runner's START_PENDING
hints, 5 s and 60 s, and MARGIN); then raqib/winmanager.py's status, called, its lines written indented by two, and
one RESULT line of the install. 0 only where it was made and, with a start, status answers ACTIVE; 1 where anything
was refused or failed after Windows and the flags (a service made and not running stays, with status's words for
why); 2 not Windows, or a flag not its own (raised as Refused, said by raqib/cli.py).

remove (X-6): the manager opened to connect (0x1); the service opened with REMOVE_RIGHTS (to ask its state and its
making, to stop it, to remove it): 1060 is `nothing installed`, 0; its description read by the reader, and without
Raqib's mark it is not touched, 1. Else a Stop: 1062 (it does not run) is taken; 1052 (it is starting) waits for it to
leave START_PENDING, within install's bound, and asks again; then a wait for STOPPED (the runner's STOP_WAIT_HINT and
MARGIN); DeleteService (1072, already marked, is taken); the handles closed; the name asked for again by the reader -
1060 is `removed`, 0; still there is marked for removal and not yet gone, 1. Without --purge the record is never
touched; its place is said, and that --purge removes it.

remove --purge (Amendment ZE; M12.4c2b4): the service's remove first, as it is; the record is touched only where that
ended with exit 0 (the service gone, or none installed) - else one line says it is not touched (a service that may
still run may still write), 1. Then the place is judged by place_judged, the one judgement of the runner, the install
and the remove: absent is nothing to remove, 0; refused is said in its own words and the name left exactly as it is,
1; taken alone is removed: bottom up, by System's listed, remove_file and remove_folder, every path handed one inside
the place; a reparse point inside is neither entered nor removed, counted and said, and the place then stays; each
error is counted by the system's number and the first one's path said; 0 only where the place is gone. Measured before
it was ruled (ZE's first paragraph; the probe 91952bf, x64 and ARM64): the place after Raqib's remove read as taken,
3 folders and 11 files, removed bottom up by an administrator's process with no error; a folder of the name made by
an administrator's shell read with ProgramData's inherited list (refused); a link of the name read as a reparse
point, and removing the link removed the link alone. This module's --purge itself was not run on a real machine.

Every call of the system that writes or removes goes through one object, System, whose methods are the system's own
calls and nothing else, each returning (what it did or read, 0), (None, the system's error number) or (None, words);
none raises. Every handle opened is closed on every road, newest first. advapi32 is loaded as raqib/winmanager.py
loads it (by its name, use_last_error, every call's argument and result types declared), at the first call and never
at import; no other library, no program started, no file written, no registry read; the one thing removed beside the
service is the record, with --purge, by os.scandir, os.unlink and os.rmdir. A test hands its own objects (the system,
the reader, the check's and the place's), so no test needs Windows or a service manager. This module is imported in
raqib/cli.py's cmd_service alone. The standard library only; no network.
"""
from __future__ import annotations

import ntpath
import os
import sys
import time
import types

MAKE_RIGHTS = 0x3               # SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE: the install's manager (measured, X)
CONNECT_RIGHTS = 0x1            # SC_MANAGER_CONNECT: remove's manager (measured, V)
MADE_RIGHTS = 0x10017           # the made service's handle: 0x17 measured (to ask its making and its state, to
                                # change its making, to start it), and DELETE (0x10000) to remove it where a setting
                                # fails
REMOVE_RIGHTS = 0x10025         # SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE (X-6)
OWN_PROCESS = 0x10              # SERVICE_WIN32_OWN_PROCESS
AUTO_START = 2                  # SERVICE_AUTO_START, not delayed (X-9)
ERROR_NORMAL = 1                # SERVICE_ERROR_NORMAL
DISPLAY_NAME = "Raqib watch"    # what the system shows it as (measured: its log names it so)
DESCRIPTION = "raqib-service/1 Raqib's watch of this host, a service of Windows (ADR-0013)"   # the mark first (V-2)
CONFIG_DESCRIPTION = 1          # SERVICE_CONFIG_DESCRIPTION
CONFIG_FAILURE_ACTIONS = 2      # SERVICE_CONFIG_FAILURE_ACTIONS
CONFIG_FAILURE_FLAG = 4         # SERVICE_CONFIG_FAILURE_ACTIONS_FLAG
RESTART = 1                     # SC_ACTION_RESTART
RESET_PERIOD = 3600             # seconds without an end that was no Stop, after which the count is forgotten (X-5)
DELAYS = (5000, 30000, 300000)  # milliseconds before each start again (X-5); the last one stands for every later end
CONTROL_STOP = 1                # SERVICE_CONTROL_STOP
STATUS_PROCESS_INFO = 0         # SC_STATUS_PROCESS_INFO
STOPPED, START_PENDING, RUNNING = 1, 2, 4
DENIED = 5                      # ERROR_ACCESS_DENIED
ABSENT = 2                      # ERROR_FILE_NOT_FOUND: the place's own name is not there, its folder above is
STARTING_NOW = 1052             # a Stop while it starts (measured, T, U, W)
NOT_ACTIVE = 1062               # ERROR_SERVICE_NOT_ACTIVE: a Stop of a service that does not run (measured, X)
NOT_THERE = 1060                # ERROR_SERVICE_DOES_NOT_EXIST (measured)
MARKED_FOR_REMOVAL = 1072       # ERROR_SERVICE_MARKED_FOR_DELETE (measured, W)
EXISTS = 1073                   # ERROR_SERVICE_EXISTS (measured, W)
ASK_EVERY = 0.25                # seconds between two asks of the state in a wait (X-4)
MARGIN = 15.0                   # seconds past the runner's own hints before a wait ends
ERROR_WORDS = {DENIED: "access denied: an administrator is needed (a prompt opened as administrator)",
               STARTING_NOW: "the system takes no Stop while it starts", NOT_THERE: "no service of the name",
               NOT_ACTIVE: "it does not run", MARKED_FOR_REMOVAL: "a service of the name is marked for removal and"
               " not yet gone", EXISTS: "a service of the name is there"}
DONE = "installed and started: raqib service status answers ACTIVE"
NO_START = "installed, not started (--no-start)"
NOT_STARTED = "installed, NOT STARTED: the start was refused; it stays"
STARTING = "installed, STILL STARTING after %d s; left as it is"
NOT_ACTIVE_YET = "installed, NOT ACTIVE as raqib service status reads it (%s); it stays"
NOT_KNOWN = "installed and started, its state NOT KNOWN; it stays"
NOTHING = "NOT INSTALLED, nothing made"
UNDONE = "NOT INSTALLED, what was made was removed again"
LEFT = "NOT INSTALLED: a service of the name is left, not as installed"
FAULT = "NOT KNOWN what was made: a fault of its own; raqib service status says what is there"
NOT_CLOSED = "; NOT KNOWN: a handle was not closed"   # Y-4: no RESULT says done where the exit says 1
LEFT_MARKED = ("the service left carries Raqib's mark: raqib service remove removes it")
LEFT_UNMARKED = ("the service left carries no mark, so raqib service remove will not touch it and a second install"
                 " refuses it: remove it with the system's own tools (the services' console, or sc delete)")
REMOVED = "removed"
NONE_INSTALLED = "nothing installed"
NOT_OURS = "nothing touched: a service of the name is not Raqib's"
UNTOUCHED = "NOT REMOVED, nothing touched"
NOT_REMOVED = "NOT REMOVED: %s; left as it is"
NOT_GONE = "marked for removal, not yet gone"
GONE_NOT_KNOWN = "removed by DeleteService, whether it is gone NOT KNOWN"
RECORD = ("  the record stays: the place, Raqib under ProgramData (its events in .raqib\\host\\events.jsonl there),"
          " is not touched; --purge removes it where it reads as the runner makes it (ADR-0013 ZE)\n")
# ZE-3, ZE-4 (M12.4c2b4): --purge, the record's lines and the RESULT's words after the service's own
RECORD_UNTOUCHED = ("  the record (--purge): not touched: the service is not gone, and a service that may still run"
                    " may still write; the place, Raqib under ProgramData, is left as it is (ADR-0013 ZE-3)\n")
RECORD_ABSENT = "  the record (--purge): %s is not there: nothing to remove\n"
RECORD_REFUSED = ("  the record (--purge): %s; not the place as Raqib's service makes it, so it is left exactly as it"
                  " is (ADR-0013 ZE-1)\n")
RECORD_TAKEN = ("  the record (--purge): %s is there, a folder owned by %s with the closed list, as the runner makes"
                " it: removed bottom up, no link followed\n")
RECORD_GONE = "  the record: removed %s and %s inside it, then the place itself: %s is gone\n"
RECORD_LEFT = "  the record: NOT all removed: %s and %s removed; left: %s; the place stays\n"
RECORD_FAULT = "  the record: an answer this command cannot read, or a fault of its own (%s)\n"
SERVICE_GONE = {REMOVED: "the service removed"}   # the RESULT's first words where the record is reached
PURGED = "%s; the record removed"
NO_RECORD = "%s; no record to remove"
RECORD_KEPT = "%s; the record NOT removed: %s"
NOT_PLACE = "not the place as Raqib's service makes it"
PART_LEFT = "part of it is left (said above)"
NOT_TOUCHED = "not touched"
FAULT_PURGE = "%s; the record: NOT KNOWN what of it was removed, a fault of its own"
NOT_ONE_NAME = "a name listed that is not one plain name"


class Refused(Exception):
    """A usage refusal of `raqib service install | remove` on Windows (said by raqib/cli.py, exit 2)."""


class System:
    """Every call `raqib service install` and `remove` make of the system on Windows to write, here alone (a test
    hands an object of its own). Each method returns (what was done or read, 0), (None, the system's error number) or
    (None, words); none raises."""

    def __init__(self):
        self._api = None

    def platform(self):
        return sys.platform

    def _win(self):
        """The system's calls by ctypes, declared at the first call, never at import (as raqib/winmanager.py)."""
        if self._api is not None:
            return self._api
        import ctypes
        from ctypes import wintypes

        class SERVICE_STATUS_PROCESS(ctypes.Structure):
            _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                        ("dwServiceFlags", wintypes.DWORD)]

        class SERVICE_STATUS(ctypes.Structure):
            _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                        ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                        ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                        ("dwWaitHint", wintypes.DWORD)]

        class SERVICE_DESCRIPTIONW(ctypes.Structure):
            _fields_ = [("lpDescription", wintypes.LPWSTR)]

        class SC_ACTION(ctypes.Structure):
            _fields_ = [("Type", ctypes.c_int), ("Delay", wintypes.DWORD)]

        class SERVICE_FAILURE_ACTIONSW(ctypes.Structure):
            _fields_ = [("dwResetPeriod", wintypes.DWORD), ("lpRebootMsg", wintypes.LPWSTR),
                        ("lpCommand", wintypes.LPWSTR), ("cActions", wintypes.DWORD),
                        ("lpsaActions", ctypes.POINTER(SC_ACTION))]

        class SERVICE_FAILURE_ACTIONS_FLAG(ctypes.Structure):
            _fields_ = [("fFailureActionsOnNonCrashFailures", wintypes.BOOL)]
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.OpenSCManagerW.restype = wintypes.HANDLE
        adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        adv.CreateServiceW.restype = wintypes.HANDLE
        adv.CreateServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,
                                       wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR,
                                       wintypes.LPCWSTR, wintypes.LPCWSTR]
        adv.ChangeServiceConfig2W.restype = wintypes.BOOL
        adv.ChangeServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
        adv.StartServiceW.restype = wintypes.BOOL
        adv.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR)]
        adv.QueryServiceStatusEx.restype = wintypes.BOOL
        adv.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
        adv.OpenServiceW.restype = wintypes.HANDLE
        adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        adv.ControlService.restype = wintypes.BOOL
        adv.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]
        adv.DeleteService.restype = wintypes.BOOL
        adv.DeleteService.argtypes = [wintypes.HANDLE]
        adv.CloseServiceHandle.restype = wintypes.BOOL
        adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        self._api = types.SimpleNamespace(ctypes=ctypes, w=wintypes, adv=adv, status=SERVICE_STATUS_PROCESS,
                                          control=SERVICE_STATUS, description=SERVICE_DESCRIPTIONW,
                                          action=SC_ACTION, failure=SERVICE_FAILURE_ACTIONSW,
                                          flag=SERVICE_FAILURE_ACTIONS_FLAG)
        return self._api

    def make_manager(self):
        """OpenSCManagerW of this machine's manager and its active list, with MAKE_RIGHTS: (handle, 0)."""
        try:
            api = self._win()
            handle = api.adv.OpenSCManagerW(None, None, MAKE_RIGHTS)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:   # never raises past the module: said as what failed
            return None, _failed(exc)

    def connect(self):
        """OpenSCManagerW with CONNECT_RIGHTS, for remove: (handle, 0)."""
        try:
            api = self._win()
            handle = api.adv.OpenSCManagerW(None, None, CONNECT_RIGHTS)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def create(self, manager, name, command):
        """CreateServiceW, its thirteen arguments as measured: (the service's handle, with MADE_RIGHTS, 0)."""
        try:
            api = self._win()
            handle = api.adv.CreateServiceW(manager, name, DISPLAY_NAME, MADE_RIGHTS, OWN_PROCESS, AUTO_START,
                                            ERROR_NORMAL, command, None, None, None, None, None)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def describe(self, service, text):
        """ChangeServiceConfig2W at level 1: its description `text`: (True, 0)."""
        try:
            api = self._win()
            given = api.description(text)   # alive, with the text it points at, until the call returns
            done = api.adv.ChangeServiceConfig2W(service, CONFIG_DESCRIPTION, api.ctypes.byref(given))
            return (True, 0) if done else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def failure_actions(self, service):
        """ChangeServiceConfig2W at level 2: started again after each of DELAYS, the count forgotten after
        RESET_PERIOD; no message, no command (X-5): (True, 0)."""
        try:
            api = self._win()
            actions = (api.action * len(DELAYS))(*[api.action(RESTART, delay) for delay in DELAYS])
            given = api.failure(RESET_PERIOD, None, None, len(DELAYS), actions)   # both alive until it returns
            done = api.adv.ChangeServiceConfig2W(service, CONFIG_FAILURE_ACTIONS, api.ctypes.byref(given))
            return (True, 0) if done else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def failure_flag(self, service):
        """ChangeServiceConfig2W at level 4: the failure actions on an exit of the service's own too: (True, 0)."""
        try:
            api = self._win()
            given = api.flag(True)
            done = api.adv.ChangeServiceConfig2W(service, CONFIG_FAILURE_FLAG, api.ctypes.byref(given))
            return (True, 0) if done else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def start(self, service):
        """StartServiceW with no arguments: (True, 0)."""
        try:
            api = self._win()
            done = api.adv.StartServiceW(service, 0, None)
            return (True, 0) if done else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def state(self, service):
        """QueryServiceStatusEx at its one level: ({type, state, exit, own, pid}, 0)."""
        try:
            api = self._win()
            got, needed = api.status(), api.w.DWORD(0)
            if not api.adv.QueryServiceStatusEx(service, STATUS_PROCESS_INFO, api.ctypes.byref(got),
                                                api.ctypes.sizeof(got), api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            return {"type": got.dwServiceType, "state": got.dwCurrentState, "exit": got.dwWin32ExitCode,
                    "own": got.dwServiceSpecificExitCode, "pid": got.dwProcessId}, 0
        except Exception as exc:
            return None, _failed(exc)

    def open_to_remove(self, manager, name):
        """OpenServiceW of `name` with REMOVE_RIGHTS: (handle, 0); a name not there is (None, 1060)."""
        try:
            api = self._win()
            handle = api.adv.OpenServiceW(manager, name, REMOVE_RIGHTS)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def stop(self, service):
        """ControlService with a Stop: ({state}, 0), the state the system answered with."""
        try:
            api = self._win()
            got = api.control()
            if not api.adv.ControlService(service, CONTROL_STOP, api.ctypes.byref(got)):
                return None, _last(api.ctypes.get_last_error())
            return {"state": got.dwCurrentState}, 0
        except Exception as exc:
            return None, _failed(exc)

    def delete(self, service):
        """DeleteService: (True, 0); it is gone once every handle on it is closed."""
        try:
            api = self._win()
            return (True, 0) if api.adv.DeleteService(service) else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def close(self, handle):
        """CloseServiceHandle: (True, 0)."""
        try:
            api = self._win()
            return (True, 0) if api.adv.CloseServiceHandle(handle) else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)

    def sleep(self, seconds):
        """A wait of `seconds` between two asks: (True, 0)."""
        try:
            time.sleep(seconds)
            return True, 0
        except Exception as exc:
            return None, _failed(exc)

    def clock(self):
        """The clock the waits are measured by (monotonic): (seconds, 0)."""
        try:
            return time.monotonic(), 0
        except Exception as exc:
            return None, _failed(exc)

    def listed(self, folder):
        """ZE-2: os.scandir of `folder`: ([(each name, its own attributes)], 0) - the attributes the system lists for
        the name itself, no link followed (stat with follow_symlinks=False); nothing is entered."""
        try:
            with os.scandir(folder) as found:
                return [(one.name, one.stat(follow_symlinks=False).st_file_attributes) for one in found], 0
        except Exception as exc:
            return None, _number(exc)

    def remove_file(self, path):
        """ZE-2: os.unlink of the one name `path`: (True, 0)."""
        try:
            os.unlink(path)
            return True, 0
        except Exception as exc:
            return None, _number(exc)

    def remove_folder(self, path):
        """ZE-2: os.rmdir of the one empty folder `path`: (True, 0)."""
        try:
            os.rmdir(path)
            return True, 0
        except Exception as exc:
            return None, _number(exc)


def _number(exc):
    """The system's number an OSError of Windows carries (winerror), or words where it carries none."""
    number = getattr(exc, "winerror", None)
    return number if isinstance(number, int) and not isinstance(number, bool) and number else _failed(exc)


def _last(number):
    """The system's error number, or words where it gave none (a call that failed and set no number)."""
    return number if number else "it failed and the system gave no error number"


def _failed(exc):
    number = getattr(exc, "winerror", None)
    return "an exception, %s%s" % (type(exc).__name__, " (error %s)" % number if number else "")


def _call(method, *args):
    """One call of an object handed: (what it gave, 0) or (None, its error); one that raises is said."""
    try:
        value, error = method(*args)
    except Exception as exc:
        return None, _failed(exc)
    return (value, 0) if error == 0 and not isinstance(error, bool) else (None, error if error else _last(error))


def _error_said(error):
    from raqib import winmanager
    if isinstance(error, bool) or not isinstance(error, int):
        return winmanager._said(error)
    return "error %d%s" % (error, " (%s)" % ERROR_WORDS[error] if error in ERROR_WORDS else "")


def path_refused(path):
    """X-3: why `path` (the path the check judged) may not be written into the command, or None."""
    if not isinstance(path, str) or not path:
        return "is not a path (%s)" % type(path).__name__
    if '"' in path:
        return "holds a quote, which would end the quoted path in the command"
    if not path.isprintable():
        return "holds a character that is not printable"
    if "%" in path:   # Y-2: read in the system's documents, not measured, and not to be found out by trying
        return ("holds a percent sign, which the system may read in a service's command as the name of a variable"
                " of its environment: the command could then name another path than the one the check judged")
    return None


def command_for(path, packed):
    """X-3: the command for this very process, one of the two forms raqib/winmanager.py reads as Raqib's."""
    from raqib import winmanager
    return '"%s" %s' % (path, winmanager.FORMS[0] if packed else winmanager.FORMS[1])


def start_bound():
    """X-4: seconds a start is waited for: the START_PENDING hints the runner tells (T-2) and MARGIN."""
    from raqib import winservice
    return (winservice.START_WAIT_HINT + winservice.CHECK_WAIT_HINT) / 1000.0 + MARGIN


def stop_bound():
    """X-6: seconds a stop is waited for: the runner's own STOP_WAIT_HINT and MARGIN."""
    from raqib import winservice
    return winservice.STOP_WAIT_HINT / 1000.0 + MARGIN


def place_judged(place):
    """X-8: the place as the runner would find it at its start, read and never made: ("absent", its path), ("taken",
    its path, its owner) or ("refused", winservice's number, words) - each refusal the one winservice.prepare raises
    for a place it finds with the same reading (a test ties them). `place` is winservice.System or a stand-in."""
    from raqib import wincode, winservice as ws
    root = place.getenv("ProgramData")
    if not ws._drive_path(root):
        return "refused", ws.EXIT_NO_PROGRAMDATA, "ProgramData is %s in this process's environment" % (
            "absent" if root is None else "not a whole path of a drive (%s)" % _error_said(str(root)))
    path = ntpath.join(root, ws.PLACE_NAME)
    try:
        attributes, text = place.read_place(path)
    except OSError as exc:
        if exc.errno == ABSENT:   # Y-3: 2 alone; a folder above not there (3) is not the runner's to make
            return "absent", path
        return "refused", ws.EXIT_UNREAD, "%s could not be read through one handle on its name: %s%s" % (
            _error_said(path), ws._why(exc), "; an administrator is needed" if exc.errno == DENIED else "")
    said = _error_said(path)   # W-3: a path from this process's environment is written as printable ASCII
    if attributes & ws.ATTRIBUTE_REPARSE:
        return "refused", ws.EXIT_REPARSE, "%s is a reparse point (attributes 0x%x)" % (said, attributes)
    if not attributes & ws.ATTRIBUTE_FOLDER:
        return "refused", ws.EXIT_NOT_FOLDER, "%s is there and is not a folder (attributes 0x%x)" % (said,
                                                                                                  attributes)
    owner, dacl = ws.owner_and_list(text)
    if owner not in ws.OWNERS:
        return "refused", ws.EXIT_OWNER, "%s is owned by %s, neither the system (SY) nor the administrators (BA)" % (
            said, _error_said(owner or "nobody said"))
    if dacl != ws.CLOSED_AS_MADE:
        return "refused", ws.EXIT_OPEN, ("%s has the list %s, not the closed one as a folder made closed reads (%s)"
                                         % (said, _error_said(dacl), ws.CLOSED_AS_MADE))
    return "taken", path, owner


class _Held:
    """The handles opened, closed newest first on every road; a close that fails is said and counted."""

    def __init__(self, system, out):
        self.system, self.out, self.held, self.failed = system, out, [], False

    def take(self, what, handle):
        self.held.append((what, handle))
        return handle

    def close(self, handle=None):
        for what, got in [h for h in reversed(self.held) if handle is None or h[1] == handle]:
            self.held.remove((what, got))
            _, error = _call(self.system.close, got)
            if error:
                self.out.write("  %s: CloseServiceHandle failed: %s\n" % (what, _error_said(error)))
                self.failed = True


def _wait(system, service, bound, done):
    """X-4: the state asked every ASK_EVERY seconds until done(state) or `bound` seconds by the system's clock: (the
    state read, the seconds waited, None) where done, (the state, seconds, "bound") where not, (None, 0, words)
    where a call failed."""
    first, error = _call(system.clock)
    if error:
        return None, 0, "the clock failed: %s" % _error_said(error)
    while True:
        got, error = _call(system.state, service)
        if error:
            return None, 0, "its state: QueryServiceStatusEx failed: %s" % _error_said(error)
        now, error = _call(system.clock)
        if error:
            return None, 0, "the clock failed: %s" % _error_said(error)
        waited = now - first
        if done(got.get("state")):
            return got, waited, None
        if waited >= bound:
            return got, waited, "bound"
        _, error = _call(system.sleep, ASK_EVERY)
        if error:
            return None, 0, "the wait failed: %s" % _error_said(error)


def _state_said(got):
    from raqib import winmanager
    return winmanager._word(winmanager.STATES, got.get("state"), "a state")


def _status(reader, out):
    """raqib/winmanager.py's status, called: its lines written indented by two; (its exit, its RESULT's words)."""
    import io
    from raqib import winmanager
    said = io.StringIO()
    code = winmanager.status(reader, said)
    lines = said.getvalue().splitlines()
    for line in lines:
        out.write("  %s\n" % line)
    result = [x for x in lines if x.startswith("RESULT: ")]
    return code, result[-1][len("RESULT: "):] if result else "no RESULT line"


def _check(code, out):
    """X-3, X-10: the check of this process's own code, by raqib/wincode.py's own functions as `raqib service check`
    asks it and in its words: (packed, None) where it passed, (None, words) where it refused."""
    from raqib import wincode, winservice
    packed = code.packed()
    if not packed:
        words = wincode.not_asked(code)
        if words:
            out.write("  raqib service check: %s: %s\n" % (wincode._said(code.program()), words))
            out.write("  so the install is asked as the service will run it: \"%s\" -I -m raqib service install\n"
                      % wincode._said(code.program()))
            return None, "refused"
    drives = []
    bad, counts = wincode.check(code, drives)
    if bad is not None:
        out.write("  %s\n" % (winservice.REFUSED_SAID % bad))
        return None, "refused"
    out.write("  %s\n" % (winservice.PASS_SAID % (wincode.plain_words(counts, drives) if "entries" in counts
                                                  else wincode.checked_words(counts, drives))))
    return bool(packed), None


def _install(system, out, start, code, place, reader, held):
    """X-3 in its order; (the exit, the RESULT's words)."""
    from raqib import winmanager, winservice
    name = winservice.SERVICE_NAME
    packed, refused = _check(code, out)
    if refused:
        return 1, NOTHING
    got = place_judged(place)
    if got[0] == "refused":
        out.write("  the place: %s; the runner would refuse it at its start (%s), so no service is made (ADR-0013"
                  " X-8)\n" % (got[2], winservice.told(got[1])))
        return 1, NOTHING
    if got[0] == "absent":
        out.write("  the place: %s is not there: the runner makes it at its first start, as the system, closed"
                  " (ADR-0013 X-8); the install makes nothing there\n" % _error_said(got[1]))
    else:
        out.write("  the place: %s is there, a folder owned by %s with the closed list, as the runner takes it at a"
                  " start; not changed\n" % (_error_said(got[1]), got[2]))
    manager, error = _call(system.make_manager)
    if error:
        out.write("  the service manager: OpenSCManagerW (rights 0x%X, to connect and to make a service) failed: %s;"
                  " nothing made\n" % (MAKE_RIGHTS, _error_said(error)))
        return 1, NOTHING
    held.take("the service manager", manager)
    there, error = _call(reader.open, manager, name)
    if error and error != NOT_THERE:
        out.write("  whether a service named %s is there: OpenServiceW (rights 0x%X, to ask) failed: %s; nothing"
                  " made\n" % (name, winmanager.SERVICE_RIGHTS, _error_said(error)))
        return 1, NOTHING
    if not error:
        held.take("the service %s" % name, there)
        text, error = _call(reader.description, there)
        held.close(there)
        if error:
            out.write("  a service named %s is there; its description: QueryServiceConfig2W (level 1) failed: %s;"
                      " it is not touched\n" % (name, _error_said(error)))
        elif winmanager.marked(text):
            out.write("  a service named %s is there and carries Raqib's mark: it is not changed; remove it first"
                      " (raqib service remove), then install\n" % name)
        else:
            out.write("  a service named %s is there without Raqib's mark: it is not Raqib's and is not touched\n"
                      % name)
        return 1, NOTHING
    out.write("  no service named %s yet (OpenServiceW: error %d)\n" % (name, NOT_THERE))
    program = code.program()
    why = path_refused(program)
    if why:
        out.write("  the command: the path the check judged, %s, %s; nothing made\n" % (_error_said(str(program)),
                                                                                       why))
        return 1, NOTHING
    command = command_for(program, packed)
    out.write("  its command: %s (%s, by the path the check judged)\n" % (
        _error_said(command), winmanager.FORM_WORDS[winmanager.FORMS[0] if packed else winmanager.FORMS[1]]))
    made, error = _call(system.create, manager, name, command)
    if error in (EXISTS, MARKED_FOR_REMOVAL):
        out.write("  CreateServiceW: %s; it is not touched, nothing made\n" % _error_said(error))
        return 1, NOTHING
    if error:
        out.write("  CreateServiceW failed: %s; nothing made\n" % _error_said(error))
        return 1, NOTHING
    held.take("the service %s" % name, made)
    out.write("  made: the service %s, shown as %s, a process of its own (0x%X), automatic start (%d), error control"
              " %d, the system's account (none named)\n" % (name, DISPLAY_NAME, OWN_PROCESS, AUTO_START,
                                                           ERROR_NORMAL))
    for call, given, words in (
            (system.describe, (made, DESCRIPTION), "its description, Raqib's mark first (ChangeServiceConfig2W,"
             " level 1)"),
            (system.failure_actions, (made,), "after an end that was no Stop, started again after %s s, the count"
             " forgotten after %d s (ChangeServiceConfig2W, level 2)" % (
                 ", ".join("%d" % (d // 1000) for d in DELAYS), RESET_PERIOD)),
            (system.failure_flag, (made,), "the same after an exit of the service's own (ChangeServiceConfig2W, level"
             " 4, the failure flag)")):
        _, error = _call(call, *given)
        if error:
            out.write("  %s: failed: %s\n" % (words, _error_said(error)))
            _, error = _call(system.delete, made)
            if error:
                out.write("  what was made could not be removed again: DeleteService failed: %s\n" % _error_said(
                    error))
                out.write("  %s\n" % (LEFT_MARKED if call != system.describe else LEFT_UNMARKED))   # Y-4
                return 1, LEFT
            out.write("  what was made was removed again: DeleteService done on it; it is gone once every handle on"
                      " it is closed (raqib service status says what is there)\n")
            return 1, UNDONE
        out.write("  set: %s\n" % words)
    if not start:
        out.write("  --no-start: not started; it is set to start with the machine (automatic; a start at boot is"
                  " not measured, ADR-0013 X-9), or start it from the services' console\n")
        return 0, NO_START
    _, error = _call(system.start, made)
    if error:
        out.write("  StartServiceW failed: %s\n" % _error_said(error))
        held.close()
        _status(reader, out)
        return 1, NOT_STARTED
    bound = start_bound()
    out.write("  started (StartServiceW); its state asked every %.2f s until it runs or stops, for at most %d s\n" % (
        ASK_EVERY, bound))
    got, waited, how = _wait(system, made, bound, lambda state: state in (RUNNING, STOPPED))
    if got is None:
        out.write("  %s\n" % how)
    else:
        out.write("  after %.2f s: %s\n" % (waited, _state_said(got)))
    held.close()
    code_said, result = _status(reader, out)
    if got is None:
        return 1, NOT_KNOWN
    if how == "bound":
        out.write("  still starting: the runner checks its own code first and may take long (ADR-0013 T-2)\n")
        return 1, STARTING % bound
    if code_said == 0:
        return 0, DONE
    if got.get("state") == STOPPED:
        out.write("  the system starts it again after %d s, %d s, then every %d s (its failure actions); raqib"
                  " service remove removes it\n" % tuple(d // 1000 for d in DELAYS))
    return 1, NOT_ACTIVE_YET % result


def _platform(system, action):
    from raqib import winmanager
    try:
        platform = system.platform()
    except Exception as exc:
        platform = _failed(exc)
    if platform == "win32":
        return None
    return ("raqib service %s: Windows only here (the system's service manager); this is %s; nothing done\n"
            % (action, winmanager._said(platform)))


def install(system, out, start=True, code=None, place=None, reader=None):
    """X-3: the service made, set and (with start) started, said one line a step; the exit (0 made and ACTIVE, or made
    with --no-start; 1 refused or failed; 2 not Windows). code: the check's object (wincode.System); place: the
    runner's reader of the place (winservice.System); reader: raqib/winmanager.py's System - each a stand-in in a
    test."""
    from raqib import wincode, winmanager, winservice
    words = _platform(system, "install")
    if words:
        out.write(words)
        return 2
    out.write("raqib service install\n")
    out.write("  Windows: the service manager's own calls (ADR-0013 X-2)\n")
    held = _Held(system, out)
    try:
        exit_code, result = _install(system, out, start, code or wincode.System(), place or winservice.System(),
                                     reader or winmanager.System(), held)
    except Exception as exc:   # an answer of a shape this command does not read: said, never raised
        out.write("  an answer this command cannot read, or a fault of its own (%s)\n" % type(exc).__name__)
        exit_code, result = 1, FAULT
    held.close()
    if held.failed:
        exit_code, result = 1, result + NOT_CLOSED
    out.write("RESULT: %s\n" % result)
    return exit_code


def _stop(system, out, service):
    """X-6: a Stop, 1062 taken, 1052 waited past once; then a wait for STOPPED: None where it stopped, else the
    RESULT's words."""
    _, error = _call(system.stop, service)
    if error == STARTING_NOW:
        out.write("  a Stop: %s: its start is waited for, at most %d s\n" % (_error_said(error), start_bound()))
        got, waited, how = _wait(system, service, start_bound(), lambda state: state != START_PENDING)
        if got is None:
            out.write("  %s; nothing removed\n" % how)
            return UNTOUCHED
        if how == "bound":
            out.write("  still starting after %.2f s; nothing removed\n" % waited)
            return NOT_REMOVED % "still starting"
        out.write("  after %.2f s: %s; a Stop asked again\n" % (waited, _state_said(got)))
        _, error = _call(system.stop, service)
    if error == NOT_ACTIVE:
        out.write("  a Stop: %s\n" % _error_said(error))
    elif error:
        out.write("  a Stop: ControlService failed: %s; nothing removed\n" % _error_said(error))
        return NOT_REMOVED % "the Stop failed"
    else:
        out.write("  a Stop: sent (ControlService)\n")
    got, waited, how = _wait(system, service, stop_bound(), lambda state: state == STOPPED)
    if got is None:
        out.write("  %s; nothing removed\n" % how)
        return NOT_REMOVED % "its state not known"
    if how == "bound":
        out.write("  not stopped after %.2f s (%s); nothing removed\n" % (waited, _state_said(got)))
        return NOT_REMOVED % "not stopped"
    out.write("  stopped after %.2f s (%s)\n" % (waited, _state_said(got)))
    return None


def _remove(system, out, reader, held):
    """X-6 in its order; (the exit, the RESULT's words)."""
    from raqib import winmanager, winservice
    name = winservice.SERVICE_NAME
    manager, error = _call(system.connect)
    if error:
        out.write("  the service manager: OpenSCManagerW (rights 0x%X, to connect) failed: %s\n" % (
            CONNECT_RIGHTS, _error_said(error)))
        return 1, UNTOUCHED
    held.take("the service manager", manager)
    service, error = _call(system.open_to_remove, manager, name)
    if error == NOT_THERE:
        out.write("  no service named %s (OpenServiceW: error %d): nothing to stop or remove\n" % (name, NOT_THERE))
        return 0, NONE_INSTALLED
    if error:
        out.write("  the service %s: OpenServiceW (rights 0x%X, to ask its state and its making, to stop it and to"
                  " remove it) failed: %s\n" % (name, REMOVE_RIGHTS, _error_said(error)))
        return 1, UNTOUCHED
    held.take("the service %s" % name, service)
    text, error = _call(reader.description, service)
    if error:
        out.write("  its description: QueryServiceConfig2W (level 1) failed: %s; it is not touched\n" % _error_said(
            error))
        return 1, UNTOUCHED
    if not winmanager.marked(text):
        out.write("  a service named %s is there without Raqib's mark: it is not Raqib's and is not touched\n" % name)
        return 1, NOT_OURS
    out.write("  a service named %s is there and carries Raqib's mark\n" % name)
    why = _stop(system, out, service)
    if why:
        return 1, why
    _, error = _call(system.delete, service)
    if error == MARKED_FOR_REMOVAL:
        out.write("  DeleteService: %s: it was marked already\n" % _error_said(error))
    elif error:
        out.write("  DeleteService failed: %s\n" % _error_said(error))
        return 1, NOT_REMOVED % "stopped, DeleteService failed"
    else:
        out.write("  removed (DeleteService)\n")
    held.close()
    again, error = _call(reader.connect)
    if not error:
        held.take("the service manager, asked again", again)
        still, error = _call(reader.open, again, name)
        if not error:
            held.take("the service %s, asked again" % name, still)
        held.close()
    if error == NOT_THERE:
        out.write("  the name asked for again: no service named %s (error %d)\n" % (name, NOT_THERE))
        return 0, REMOVED
    if error:
        out.write("  the name asked for again: failed: %s\n" % _error_said(error))
        return 1, GONE_NOT_KNOWN
    out.write("  the name asked for again: a service named %s is still there; it goes once every handle on it is"
              " closed (the services' console, or a program that holds one)\n" % name)
    return 1, NOT_GONE


def _many(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def _one_name(name):
    """ZE-1: a name a folder's listing gave that names one thing in that folder and nothing outside it."""
    return isinstance(name, str) and name not in ("", ".", "..") and not [c for c in name if c in "\\/:\0"]


def _purge(system, path):
    """ZE-2: what is in the place removed bottom up by the system object's calls, every path handed one inside the
    place; a reparse point neither entered nor removed, and every folder above it then left; each error counted by its
    number, the first one's path kept. (True where the place is gone, the line of the result)."""
    from raqib import winservice
    done, errors, first, links, left = {"folder": 0, "file": 0}, {}, [], [], set()
    above, order, pending = {path: None}, [], [path]

    def failed(error, where):
        errors[error] = errors.get(error, 0) + 1
        if not first:
            first.append(where)
    while pending:   # each folder listed once, its files removed; the folders kept in the order they were entered
        folder = pending.pop()
        order.append(folder)
        names, error = _call(system.listed, folder)
        if error:
            failed(error, folder)
            left.add(folder)
            continue
        for name, attributes in names:
            inner = "%s\\%s" % (folder, name)
            if not _one_name(name):   # never handed to the system: it could name what is not inside the place
                failed(NOT_ONE_NAME, inner)
                left.add(folder)
            elif attributes & winservice.ATTRIBUTE_REPARSE:   # measured: a walk goes through a link into its target
                links.append((inner, attributes))
                left.add(folder)
            elif attributes & winservice.ATTRIBUTE_FOLDER:
                above[inner] = folder
                pending.append(inner)
            else:
                _, error = _call(system.remove_file, inner)
                if error:
                    failed(error, inner)
                    left.add(folder)
                else:
                    done["file"] += 1
    gone = False
    for folder in reversed(order):   # a folder after every folder inside it: bottom up
        if folder not in left:
            _, error = _call(system.remove_folder, folder)
            if not error:
                gone = folder == path
                done["folder"] += folder != path
                continue
            failed(error, folder)
        if above[folder] is not None:
            left.add(above[folder])
    folders, files = _many(done["folder"], "folder"), _many(done["file"], "file")
    if gone:
        return True, RECORD_GONE % (folders, files, _error_said(path))
    what = []
    if links:
        what.append("%s, neither entered nor removed (the first: %s, attributes 0x%x)" % (
            _many(len(links), "reparse point"), _error_said(links[0][0]), links[0][1]))
    if errors:
        counted = ["%s %s" % (_error_said(n), "once" if c == 1 else "%d times" % c) for n, c in errors.items()]
        what.append("%s; the first at %s" % (", ".join(counted), _error_said(first[0])))
    return False, RECORD_LEFT % (folders, files, "; ".join(what) or "NOT KNOWN what")


def _record(system, out, place, service):
    """ZE-1 to ZE-4: the record, the service gone or none installed, judged by place_judged as the runner judges a
    place it finds and removed only where that says taken; (the exit, the RESULT's words)."""
    got = place_judged(place)
    if got[0] == "absent":
        out.write(RECORD_ABSENT % _error_said(got[1]))
        return 0, NO_RECORD % service
    if got[0] != "taken":
        out.write(RECORD_REFUSED % got[2])
        return 1, RECORD_KEPT % (service, NOT_PLACE)
    out.write(RECORD_TAKEN % (_error_said(got[1]), got[2]))
    gone, words = _purge(system, got[1])
    out.write(words)
    return (0, PURGED % service) if gone else (1, RECORD_KEPT % (service, PART_LEFT))


def remove(system, out, reader=None, purge=False, place=None):
    """X-6: Raqib's service stopped and removed, said one line a step; the exit (0 removed or nothing installed; 1
    not Raqib's, refused, failed or not yet gone; 2 not Windows). reader: raqib/winmanager.py's System; place: the
    runner's reader of the place (winservice.System) - each a stand-in in a test. Without purge the record is never
    touched; with it (ZE), after the service's remove ended 0 alone, the record too where place_judged says taken: 0
    gone or not there, 1 refused or left."""
    from raqib import winmanager, winservice
    words = _platform(system, "remove")
    if words:
        out.write(words)
        return 2
    out.write("raqib service remove\n")
    held = _Held(system, out)
    try:
        exit_code, result = _remove(system, out, reader or winmanager.System(), held)
    except Exception as exc:
        out.write("  an answer this command cannot read, or a fault of its own (%s)\n" % type(exc).__name__)
        exit_code, result = 1, "NOT KNOWN what was done: a fault of its own"
    held.close()
    if held.failed:
        exit_code, result = 1, result + NOT_CLOSED
    if not purge:
        out.write(RECORD)
    elif exit_code != 0:   # ZE-3: not Raqib's, refused, failed or not yet gone: nothing of the record touched
        out.write(RECORD_UNTOUCHED)
        result = RECORD_KEPT % (result, NOT_TOUCHED)
    else:
        service = SERVICE_GONE.get(result, result)
        try:
            exit_code, result = _record(system, out, place or winservice.System(), service)
        except Exception as exc:
            out.write(RECORD_FAULT % type(exc).__name__)
            exit_code, result = 1, FAULT_PURGE % service
    out.write("RESULT: %s\n" % result)
    return exit_code


def cli_run(args, out, system=None, **given):
    """`raqib service install | remove` on Windows, from raqib/cli.py (its only importer). Refused: exit 2, said by
    the caller, in the Linux command's words where it has them."""
    if args.action == "install":
        if args.purge:
            raise Refused("raqib service: --purge is remove's only")
        return install(system or System(), out, start=not args.no_start, **given)
    if args.action == "remove":
        if args.no_start:
            raise Refused("raqib service: --no-start is install's only")
        return remove(system or System(), out, purge=args.purge, **given)
    raise Refused("raqib service %s: not asked of raqib/wininstall.py" % args.action)
