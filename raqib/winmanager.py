"""`raqib service status` on Windows (ADR-0013 Amendment V, V-2 to V-4; M12.4c2b2a): Raqib's service of Windows as
the system's service manager holds it, asked by the system's own calls and with no rights.

What was measured before this was ruled (Amendment T's first paragraph and Amendment V's, the probe b1ee4fb; x64 and
ARM64, the same): a caller with no rights may connect to the service manager and open a service to ask its state
and its making, and reads them - the state with the process's id, the system's exit and the service's own; the type,
the start, the account and the command (a first ask with no room answers error 122 and the bytes needed); and its
description, as it was set. A name that is not there answers error 1060; a service never started reads state 1 with
the exit 1077. This command itself was not measured on a real machine: the rig reads it as X53 (V-5).

Raqib's service (V-2) is the one named winservice.SERVICE_NAME (RaqibWatch) whose description begins with MARK, the
mark the Linux unit carries in its first line (raqib/service.py MARK, without its `# `). A service of that name
without the mark is said as not Raqib's; nothing else is read as Raqib's. What status reads and says (V-3), in this
order, one line each: whether the name is there; the mark; the command as the manager holds it, and whether it is one
of the two forms Raqib's install writes (FORMS: a quoted path, then exactly `service run`; a quoted path, then exactly
`-I -m raqib service run`), with the path it names; the type (a process of its own, 0x10); the start, by its number
and word; the account (the system's, LocalSystem); the state by its number and word, with the process's id; and,
where it is not running, the exit the system holds: 1077 as never started, 1066 with the service's own number in the
runner's own words (winservice.told; for 15, where its text file is), 0 as stopped, any other as the system's number.
A text read from the manager (the description, the command, the account) is made printable and cut at SAID_MAX
characters, the cut marked, before it is written. Nothing is said that was not read.

What it reads more (Amendment Z, Z-1; M12.4c2b2c). Measured before it was ruled (Amendment X's first paragraph, the
probe 639362e; x64 and ARM64, the same): a user outside the administrators' group, the manager opened with 0x1 and the
service with 0x5, read back by QueryServiceConfig2W what Raqib's install sets - level 2, 64 bytes: the count forgotten
after 3600 s and three actions of the kind 1 after 5000, 30000 and 300000 ms; level 4, 4 bytes: True; level 3, 4
bytes: False. This reading of them was not asked on a real machine before it was built. With the same handle (0x5) and
by the same two asks as the description: level 2 (the failure actions: each action's kind and delay, read from the
array the structure points at, which must lie inside the bytes read, its count first bounded by ACTIONS_MAX; the
seconds after which the count is forgotten; the two texts kept beside them), level 4 (the failure flag) and level 3
(the delayed start). After the account's line and before the state's, one line each: what the system does after an
end that was no Stop (each action by its kind's word, ACTION_WORDS, any other by its number, with its seconds; "none"
where there is none; the seconds after which the count is forgotten), then the texts kept beside it (the message for
a restart of the machine, the command to run), each on a line of its own and only where it is there, as another
party's text (W-3); the flag; the delayed start. Of a service without the mark these are said and nothing is judged.

The answers (V-4, as on Linux): 0 `RESULT: ACTIVE`, RUNNING and as installed (the mark, the command's form, a process
of its own, the system's account; and, Z-2, the start automatic (AUTO_START) and not delayed, started again after each
of DELAYS, the count forgotten after RESET_PERIOD, the flag set - the numbers raqib/wininstall.py writes, held here
and tied to its own by a test), with the line that says ACTIVE is the service running, not the watch writing its
record. 1 `RESULT: INSTALLED, NOT ACTIVE` (each other state said by its word; a start is said with the reason it
may be long, T-2), with `, NOT AS INSTALLED` where it is not, and `RESULT: ACTIVE, NOT AS INSTALLED` where it runs
and is not as installed; each difference said, one of Z-2 by what was read and what the install writes. 3 `RESULT:
NOT INSTALLED` (error 1060), `RESULT: NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS <its state>` (no mark),
`RESULT: NOT KNOWN` (a call failed - the call and the system's number said; error 5 says the caller may not ask - a
close included). 2 where the platform is not Windows: nothing asked
(raqib/service.py answers on Linux).

Every call of the system goes through one object, System, whose methods are the system's own calls and nothing
else: connect to the manager (OpenSCManagerW, MANAGER_RIGHTS), open the service (OpenServiceW, SERVICE_RIGHTS), its
state (QueryServiceStatusEx, STATUS_PROCESS_INFO), its making (QueryServiceConfigW: a first ask with no room, then
with the bytes it named, those bytes bounded by room()), its description (QueryServiceConfig2W, level 1, the same two
asks), its failure actions, its failure flag and its delayed start (QueryServiceConfig2W, levels 2, 4 and 3, the same
two asks; every value read out of the bytes before the method returns) and close (CloseServiceHandle). Each returns
(what was read, 0), or (None, the system's error number), or (None, words) where what failed is not the system's
number (a bound, an exception); none raises. Every handle opened
is closed on every road, the service's before the manager's. advapi32 is loaded as raqib/winservice.py loads a
library (by its name, use_last_error, every call's argument and result types declared), at the first call and never
at import; no other library, no program started, no file written, no registry read, nothing written to the manager.
A test hands its own object, so no test needs Windows or a service manager. The standard library only; no network.
"""
from __future__ import annotations

import re
import sys
import types

MARK = "raqib-service/1"        # raqib/service.py MARK without its "# " (V-2, a test ties them)
MANAGER_RIGHTS = 0x1            # SC_MANAGER_CONNECT: the least the manager is opened with (measured, V)
SERVICE_RIGHTS = 0x5            # SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS: to ask its making and its state (V)
STATUS_PROCESS_INFO = 0         # SC_STATUS_PROCESS_INFO: QueryServiceStatusEx's one level
CONFIG_DESCRIPTION = 1          # SERVICE_CONFIG_DESCRIPTION: QueryServiceConfig2W's level 1
DENIED = 5                      # ERROR_ACCESS_DENIED (measured: the start, the stop, the removal, the change)
NO_ROOM = 122                   # ERROR_INSUFFICIENT_BUFFER: the first ask with no room (measured, V)
NOT_THERE = 1060                # ERROR_SERVICE_DOES_NOT_EXIST (measured)
NEVER_STARTED = 1077            # ERROR_SERVICE_NEVER_STARTED: state 1 with this exit (measured)
ASK_MAX = 8192                  # bytes the second ask is given at most (QueryServiceConfigW's documented most)
SAID_MAX = 300                  # characters of a text read from the manager said; past it, cut and marked
OWN_PROCESS = 0x10              # SERVICE_WIN32_OWN_PROCESS: a process of its own
SYSTEM_ACCOUNT = "LocalSystem"  # the system's account, as the manager names it (read without regard to case)
RUNNING, START_PENDING, STOPPED = 4, 2, 1
FORMS = ("service run", "-I -m raqib service run")   # what Raqib's install writes after the quoted path (V-3)
FORM_WORDS = {FORMS[0]: "a packed program's", FORMS[1]: "a plain interpreter's"}
COMMAND = re.compile(r'"([^"\x00-\x1f]+)" (service run|-I -m raqib service run)')   # FORMS, matched whole
STATES = {1: "stopped", 2: "starting", 3: "stopping", 4: "running", 5: "continuing", 6: "pausing", 7: "paused"}
STARTS = {0: "at boot (a driver's)", 1: "at the system's start (a driver's)", 2: "automatic", 3: "on demand",
          4: "disabled"}
TYPES = {0x1: "a kernel driver", 0x2: "a file system driver", 0x10: "a process of its own",
         0x20: "a process shared with other services"}
CONFIG_FAILURE_ACTIONS = 2      # SERVICE_CONFIG_FAILURE_ACTIONS: level 2 (measured, Z: 64 bytes for three actions)
CONFIG_DELAYED = 3              # SERVICE_CONFIG_DELAYED_AUTO_START_INFO: level 3 (measured, Z: 4 bytes)
CONFIG_FAILURE_FLAG = 4         # SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: level 4 (measured, Z: 4 bytes)
ACTIONS_MAX = 64                # actions read at most; a count past it is said and its array not read (Z-1)
AUTO_START = 2                  # what Raqib's install writes (raqib/wininstall.py, X-5, X-9; a test ties each to its
RESTART = 1                     # own): the start automatic and not delayed; SC_ACTION_RESTART after each of DELAYS
DELAYS = (5000, 30000, 300000)  # (milliseconds); the count forgotten after RESET_PERIOD seconds; the flag set
RESET_PERIOD = 3600
NEVER = 0xFFFFFFFF              # INFINITE as the seconds of the count: it is never forgotten
ACTION_WORDS = {0: "nothing", 1: "start it again", 2: "restart the machine", 3: "run a command"}
ERROR_WORDS = {DENIED: "access denied: the caller may not ask this of the service manager",
               NO_ROOM: "the room given was not enough", NOT_THERE: "no service of the name"}


class Refused(Exception):
    """A usage refusal of `raqib service status` (said by raqib/cli.py, exit 2)."""


class System:
    """Every call `raqib service status` makes of the system on Windows, here alone (a test hands an object of its
    own). Each method returns (what was read, 0), (None, the system's error number) or (None, words); none raises."""

    def __init__(self):
        self._api = None

    def platform(self):
        return sys.platform

    def _win(self):
        """The system's calls by ctypes, declared at the first call, never at import (as raqib/winservice.py)."""
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

        class QUERY_SERVICE_CONFIGW(ctypes.Structure):
            _fields_ = [("dwServiceType", wintypes.DWORD), ("dwStartType", wintypes.DWORD),
                        ("dwErrorControl", wintypes.DWORD), ("lpBinaryPathName", wintypes.LPWSTR),
                        ("lpLoadOrderGroup", wintypes.LPWSTR), ("dwTagId", wintypes.DWORD),
                        ("lpDependencies", wintypes.LPWSTR), ("lpServiceStartName", wintypes.LPWSTR),
                        ("lpDisplayName", wintypes.LPWSTR)]

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

        class SERVICE_DELAYED_AUTO_START_INFO(ctypes.Structure):
            _fields_ = [("fDelayedAutostart", wintypes.BOOL)]
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.OpenSCManagerW.restype = wintypes.HANDLE
        adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        adv.OpenServiceW.restype = wintypes.HANDLE
        adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        adv.QueryServiceStatusEx.restype = wintypes.BOOL
        adv.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
        adv.QueryServiceConfigW.restype = wintypes.BOOL
        adv.QueryServiceConfigW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
        adv.QueryServiceConfig2W.restype = wintypes.BOOL
        adv.QueryServiceConfig2W.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
        adv.CloseServiceHandle.restype = wintypes.BOOL
        adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        self._api = types.SimpleNamespace(ctypes=ctypes, w=wintypes, adv=adv, status=SERVICE_STATUS_PROCESS,
                                          config=QUERY_SERVICE_CONFIGW, description=SERVICE_DESCRIPTIONW,
                                          action=SC_ACTION, failure=SERVICE_FAILURE_ACTIONSW,
                                          flag=SERVICE_FAILURE_ACTIONS_FLAG, delayed=SERVICE_DELAYED_AUTO_START_INFO)
        return self._api

    def connect(self):
        """OpenSCManagerW of this machine's manager and its active list, with MANAGER_RIGHTS: (handle, 0)."""
        try:
            api = self._win()
            handle = api.adv.OpenSCManagerW(None, None, MANAGER_RIGHTS)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:   # never raises past the module: said as what failed
            return None, _failed(exc)

    def open(self, manager, name):
        """OpenServiceW of `name` with SERVICE_RIGHTS: (handle, 0); a name not there is (None, 1060)."""
        try:
            api = self._win()
            handle = api.adv.OpenServiceW(manager, name, SERVICE_RIGHTS)
            return (handle, 0) if handle else (None, _last(api.ctypes.get_last_error()))
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

    def making(self, service):
        """QueryServiceConfigW: a first ask with no room (error 122 and the bytes it needs, room()), then one with
        those bytes: ({type, start, command, account}, 0)."""
        try:
            api = self._win()
            needed = api.w.DWORD(0)
            done = api.adv.QueryServiceConfigW(service, None, 0, api.ctypes.byref(needed))
            size, why = room(done, 0 if done else api.ctypes.get_last_error(), needed.value,
                             api.ctypes.sizeof(api.config))
            if why is not None:
                return None, why
            raw = api.ctypes.create_string_buffer(size)
            if not api.adv.QueryServiceConfigW(service, raw, size, api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            got = api.ctypes.cast(raw, api.ctypes.POINTER(api.config)).contents
            return {"type": got.dwServiceType, "start": got.dwStartType, "command": got.lpBinaryPathName,
                    "account": got.lpServiceStartName}, 0
        except Exception as exc:
            return None, _failed(exc)

    def description(self, service):
        """QueryServiceConfig2W at level 1, by the same two asks: (its text, or None where it has none, 0)."""
        try:
            api = self._win()
            needed = api.w.DWORD(0)
            done = api.adv.QueryServiceConfig2W(service, CONFIG_DESCRIPTION, None, 0, api.ctypes.byref(needed))
            size, why = room(done, 0 if done else api.ctypes.get_last_error(), needed.value,
                             api.ctypes.sizeof(api.description))
            if why is not None:
                return None, why
            raw = api.ctypes.create_string_buffer(size)
            if not api.adv.QueryServiceConfig2W(service, CONFIG_DESCRIPTION, raw, size, api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            return api.ctypes.cast(raw, api.ctypes.POINTER(api.description)).contents.lpDescription, 0
        except Exception as exc:
            return None, _failed(exc)

    def actions(self, service):
        """QueryServiceConfig2W at level 2, by the same two asks: ({reset, message, command, actions}, 0), each action
        (its kind, its delay in ms) read out of the bytes at the offset array_at() gives - the count bounded first,
        the array inside the bytes read - and every value read before the bytes are let go."""
        try:
            api = self._win()
            needed = api.w.DWORD(0)
            done = api.adv.QueryServiceConfig2W(service, CONFIG_FAILURE_ACTIONS, None, 0, api.ctypes.byref(needed))
            size, why = room(done, 0 if done else api.ctypes.get_last_error(), needed.value,
                             api.ctypes.sizeof(api.failure))
            if why is not None:
                return None, why
            raw = api.ctypes.create_string_buffer(size)
            if not api.adv.QueryServiceConfig2W(service, CONFIG_FAILURE_ACTIONS, raw, size,
                                                api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            got = api.ctypes.cast(raw, api.ctypes.POINTER(api.failure)).contents
            count, where = got.cActions, api.ctypes.cast(got.lpsaActions, api.ctypes.c_void_p).value
            offset, why = array_at(count, where, api.ctypes.addressof(raw), size, api.ctypes.sizeof(api.action))
            if why is not None:
                return None, why
            array = (api.action * count).from_buffer(raw, offset) if count else ()
            return {"reset": got.dwResetPeriod, "message": got.lpRebootMsg, "command": got.lpCommand,
                    "actions": [(one.Type, one.Delay) for one in array]}, 0
        except Exception as exc:
            return None, _failed(exc)

    def flag(self, service):
        """QueryServiceConfig2W at level 4, by the same two asks: (the failure flag, the number read, 0)."""
        try:
            api = self._win()
            needed = api.w.DWORD(0)
            done = api.adv.QueryServiceConfig2W(service, CONFIG_FAILURE_FLAG, None, 0, api.ctypes.byref(needed))
            size, why = room(done, 0 if done else api.ctypes.get_last_error(), needed.value,
                             api.ctypes.sizeof(api.flag))
            if why is not None:
                return None, why
            raw = api.ctypes.create_string_buffer(size)
            if not api.adv.QueryServiceConfig2W(service, CONFIG_FAILURE_FLAG, raw, size, api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            return api.ctypes.cast(raw, api.ctypes.POINTER(api.flag)).contents.fFailureActionsOnNonCrashFailures, 0
        except Exception as exc:
            return None, _failed(exc)

    def delayed(self, service):
        """QueryServiceConfig2W at level 3, by the same two asks: (the delayed start, the number read, 0)."""
        try:
            api = self._win()
            needed = api.w.DWORD(0)
            done = api.adv.QueryServiceConfig2W(service, CONFIG_DELAYED, None, 0, api.ctypes.byref(needed))
            size, why = room(done, 0 if done else api.ctypes.get_last_error(), needed.value,
                             api.ctypes.sizeof(api.delayed))
            if why is not None:
                return None, why
            raw = api.ctypes.create_string_buffer(size)
            if not api.adv.QueryServiceConfig2W(service, CONFIG_DELAYED, raw, size, api.ctypes.byref(needed)):
                return None, _last(api.ctypes.get_last_error())
            return api.ctypes.cast(raw, api.ctypes.POINTER(api.delayed)).contents.fDelayedAutostart, 0
        except Exception as exc:
            return None, _failed(exc)

    def close(self, handle):
        """CloseServiceHandle: (True, 0)."""
        try:
            api = self._win()
            return (True, 0) if api.adv.CloseServiceHandle(handle) else (None, _last(api.ctypes.get_last_error()))
        except Exception as exc:
            return None, _failed(exc)


def room(done, error, needed, least, bound=ASK_MAX):
    """V-3: the bytes the second ask is given, from what the first ask with no room answered: (bytes, None), or
    (None, why) - its own error number where it was not 122, words where it was answered as done or named bytes
    outside `least` (the structure's own size) to `bound`."""
    if done:
        return None, "the first ask with no room was answered as done, not with error %d" % NO_ROOM
    if error != NO_ROOM:
        return None, _last(error)
    if not isinstance(needed, int) or not least <= needed <= bound:
        return None, "the first ask named %s bytes, not from %d to %d (the bound)" % (_said(needed), least, bound)
    return needed, None


def array_at(count, where, base, size, width, bound=ACTIONS_MAX):
    """Z-1: where the array of `count` actions of `width` bytes each lies in the `size` bytes read at `base`: (its
    offset, None), or (None, why) - a count outside 0 to `bound` (said before any of the array is read), an array that
    is NULL with a count, or one that does not lie wholly inside the bytes read. A count of 0 reads nothing."""
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= bound:
        return None, "%s actions, not from 0 to %d (the bound)" % (_said(count), bound)
    if count == 0:
        return 0, None
    if not where:
        return None, "%d actions and no array (NULL)" % count
    offset = where - base
    if offset < 0 or offset + count * width > size:
        return None, "%d actions whose array does not lie inside the %d bytes read" % (count, size)
    return offset, None


def _last(number):
    """The system's error number, or words where it gave none (a call that failed and set no number)."""
    return number if number else "it failed and the system gave no error number"


def _failed(exc):
    number = getattr(exc, "winerror", None)
    return "an exception, %s%s" % (type(exc).__name__, " (error %s)" % number if number else "")


def _said(value):
    """A text read from the manager as one line of printable ASCII, cut at SAID_MAX and the cut marked: a character
    that is not printable is `?`, and a printable one outside ASCII is written as its number (\\uXXXX, or
    \\UXXXXXXXX past that), so that a letter of another script that looks like a Latin one is seen for what it is
    (ADR-0013 W-3)."""
    text = "".join(c if c.isascii() and c.isprintable() else
                   ("\\u%04X" if ord(c) < 0x10000 else "\\U%08X") % ord(c) if c.isprintable() else "?"
                   for c in str(value)[:SAID_MAX + 1])
    return text if len(text) <= SAID_MAX else text[:SAID_MAX] + "..."


def _error_said(error):
    if isinstance(error, bool) or not isinstance(error, int):
        return _said(error)
    return "error %d%s" % (error, " (%s)" % ERROR_WORDS[error] if error in ERROR_WORDS else "")


def _number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _word(table, value, what):
    number = _number(value)
    if number in table:
        return "%d, %s" % (number, table[number])
    return "%s, %s this command has no word for" % (_said(value), what)


def marked(text):
    """V-2: True where `text` (the description read) begins with MARK, and the mark ends there or at a space."""
    return isinstance(text, str) and text.startswith(MARK) and (text == MARK or text[len(MARK)].isspace())


def command_form(command):
    """V-3: (the form, the path it names) where `command` is, whole, one of the two forms Raqib's install writes (a
    quoted path, then exactly the words); else None."""
    got = COMMAND.fullmatch(command) if isinstance(command, str) else None
    return (got.group(2), got.group(1)) if got else None


def _mark_said(text):
    if marked(text):
        return "installed: it carries Raqib's mark, %s, at the start of its description" % MARK
    if text is None:
        why = "it has no description"
    elif not isinstance(text, str):
        why = "its description is not text (%s)" % type(text).__name__
    elif not text:
        why = "its description is empty"
    else:
        why = "its description does not begin with %s: \"%s\"" % (MARK, _said(text))
    return "not installed by Raqib: %s; a service of the name without Raqib's mark is not Raqib's" % why


def _making(making, out):
    """V-3: the command, its form and path, the type, the start and the account, one line each; what differs from
    the making Raqib's install gives, as a list."""
    command, differ = making.get("command"), []
    out.write("  command: %s (as the service manager holds it)\n" % (_said(command) if command is not None else
                                                                     "none"))
    form = command_form(command)
    if form:
        out.write("  its form: a quoted path, then `%s` (%s), one of the two Raqib's install writes; the path it"
                  " names: %s\n" % (form[0], FORM_WORDS[form[0]], _said(form[1])))
    else:
        out.write("  its form: not one of the two Raqib's install writes (a quoted path, then `%s`; a quoted path,"
                  " then `%s`)\n" % FORMS)
        differ.append("the command is not one of the two forms Raqib's install writes")
    kind = _number(making.get("type"))
    out.write("  type: %s\n" % ("0x%X, %s" % (kind, TYPES.get(kind, "a type this command has no word for"))
                                if kind is not None else "%s, not a number" % _said(making.get("type"))))
    if kind != OWN_PROCESS:
        differ.append("the type is not a process of its own (0x%X)" % OWN_PROCESS)
    start = _word(STARTS, making.get("start"), "a start")
    out.write("  start: %s\n" % start)
    if _number(making.get("start")) != AUTO_START:
        differ.append("start: %s; the install writes %s" % (start, _word(STARTS, AUTO_START, "a start")))
    account = making.get("account")
    system = isinstance(account, str) and account.lower() == SYSTEM_ACCOUNT.lower()
    out.write("  account: %s%s\n" % (_said(account) if account is not None else "none said",
                                     " (the system's)" if system else ""))
    if not system:
        differ.append("the account is not the system's (%s)" % SYSTEM_ACCOUNT)
    return differ


def _seconds(ms):
    number = _number(ms)
    if number is None:
        return "%s ms, not a number" % _said(ms)
    return "%d s" % (number // 1000) if number % 1000 == 0 else "%d.%03d s" % divmod(number, 1000)


def _action_said(action):
    """Z-1: one action, by its kind's word (any other kind by its number), and its seconds."""
    kind, delay = action
    word = ACTION_WORDS.get(_number(kind))
    return "%s after %s" % (word if word else "the kind %s, which this command has no word for," % _said(kind),
                            _seconds(delay))


def _failure(got, out):
    """Z-1, Z-2: the line of what the system does after an end that was no Stop; the texts kept beside the actions,
    each on a line of its own and only where it is there; what differs from what the install writes, as a list."""
    actions, reset, differ = [tuple(a) for a in got.get("actions")], got.get("reset"), []
    said = ", ".join(_action_said(a) for a in actions) or "none"
    number = _number(reset)
    count = ("the count never forgotten (0x%X, INFINITE)" % NEVER if number == NEVER else
             "the count forgotten after %s" % ("%d s" % number if number is not None else
                                               "%s, not a number" % _said(reset)))
    out.write("  after an end that was no Stop: %s; %s\n" % (said, count))
    for key, words in (("message", "the message kept for a restart of the machine"),
                       ("command", "the command kept to run")):
        text = got.get(key)
        if text is not None and text != "":
            out.write("  %s: \"%s\" (another party's text)\n" % (words, _said(text)))
    if [(_number(k), _number(d)) for k, d in actions] != [(RESTART, d) for d in DELAYS]:
        differ.append("after an end that was no Stop: %s; the install writes %s" % (
            said, ", ".join(_action_said((RESTART, d)) for d in DELAYS)))
    if number != RESET_PERIOD:
        differ.append("%s; the install writes %d s" % (count, RESET_PERIOD))
    return differ


def _flag(value, out):
    """Z-1, Z-2: the line of the failure flag; a list holding the difference where it is not set."""
    number = _number(value)
    said = ("%d, %s" % (number, "set (an end the service itself reports with an error is such an end too)" if
                        number else "not set (an end the service itself reports with an error is not such an end)")
            if number is not None else "%s, not a number" % _said(value))
    out.write("  the failure flag: %s\n" % said)
    return [] if number else ["the failure flag: %s; the install writes 1, set" % said.split(" (")[0]]


def _delayed(value, out):
    """Z-1, Z-2: the line of the delayed start; a list holding the difference where it is delayed."""
    number = _number(value)
    said = ("%d, %s" % (number, "delayed" if number else "not delayed") if number is not None else
            "%s, not a number" % _said(value))
    out.write("  delayed start: %s\n" % said)
    return [] if number == 0 else ["delayed start: %s; the install writes 0, not delayed" % said]


def _exit(got, out, ws, state, ours):
    """V-3, W-2: where it is not running, the exit the system holds. Its words are said only where they were read:
    "stopped" of a stopped service alone, and the runner's own words (winservice.told, and the text file for 15) of
    a service that carries Raqib's mark alone - a service without it is not read as Raqib's runner."""
    code, own = _number(got.get("exit")), _number(got.get("own"))
    if code == 0 and state == STOPPED:
        out.write("  exit: 0, stopped with no failure\n")
    elif code == 0:
        out.write("  exit the system holds: 0\n")
    elif code == NEVER_STARTED:
        out.write("  exit: %d, never started (since it was made, or since the system started)\n" % NEVER_STARTED)
    elif code == ws.SERVICE_SPECIFIC:
        if not ours:
            out.write("  exit: %d, a number of the service's own: %s\n" % (
                code, "%d (0x%08X)" % (own, own) if own is not None else _said(got.get("own"))))
        elif own in ws.EXIT_WORDS:
            out.write("  exit: %d, the service's own number: %s\n" % (code, ws.told(own)))
        else:
            out.write("  exit: %d, the service's own number: %s, a number the runner does not give\n" % (
                code, "%d (0x%08X)" % (own, own) if own is not None else _said(got.get("own"))))
        if ours and own == ws.EXIT_NOT_ALONE:
            out.write("  what was refused is in its text file: %s in the place (%s under ProgramData, as the runner"
                      " took it at that start)\n" % (ws.TEXT_NAME, ws.PLACE_NAME))
    elif code is not None:
        out.write("  exit: %d, the system's number for the service's end (its words are not read here)\n" % code)
    else:
        out.write("  exit: %s, not a number\n" % _said(got.get("exit")))


def _call(method, *args):
    """One call of the system object: (what was read, 0) or (None, its error); a stand-in that raises is said."""
    try:
        value, error = method(*args)
    except Exception as exc:
        return None, _failed(exc)
    return (value, 0) if error == 0 and not isinstance(error, bool) else (None, error if error else _last(error))


def _read(system, out, ws, opened):
    """What status reads and says (V-3), in its order; (the exit, the RESULT's words). Each handle opened is put in
    `opened` at once, for the caller to close."""
    name = ws.SERVICE_NAME
    manager, error = _call(system.connect)
    if error:
        out.write("  the service manager: OpenSCManagerW (rights 0x%X, to connect) failed: %s\n" % (
            MANAGER_RIGHTS, _error_said(error)))
        return 3, "NOT KNOWN"
    opened.append(("the service manager", manager))
    service, error = _call(system.open, manager, name)
    if error == NOT_THERE:
        out.write("  not installed: the service manager holds no service named %s (OpenServiceW: error %d)\n" % (
            name, NOT_THERE))
        return 3, "NOT INSTALLED"
    if error:
        out.write("  the service %s: OpenServiceW (rights 0x%X, to ask its state and its making) failed: %s\n" % (
            name, SERVICE_RIGHTS, _error_said(error)))
        return 3, "NOT KNOWN"
    opened.append(("the service %s" % name, service))
    out.write("  a service named %s is there (opened with the rights 0x%X, to ask its state and its making)\n" % (
        name, SERVICE_RIGHTS))
    reads, ours, differ = {}, False, []
    for key, call, words in (("description", system.description, "QueryServiceConfig2W (level 1)"),
                             ("making", system.making, "QueryServiceConfigW"),
                             ("failure actions", system.actions, "QueryServiceConfig2W (level 2)"),
                             ("failure flag", system.flag, "QueryServiceConfig2W (level 4)"),
                             ("delayed start", system.delayed, "QueryServiceConfig2W (level 3)"),
                             ("state", system.state, "QueryServiceStatusEx")):
        reads[key], error = _call(call, service)
        if error:
            out.write("  its %s: %s failed: %s\n" % (key, words, _error_said(error)))
            return 3, "NOT KNOWN"
        if key == "description":
            ours = marked(reads[key])
            out.write("  %s\n" % _mark_said(reads[key]))
        elif key == "making":
            differ = _making(reads[key], out)
        elif key == "failure actions":
            differ += _failure(reads[key], out)
        elif key == "failure flag":
            differ += _flag(reads[key], out)
        elif key == "delayed start":
            differ += _delayed(reads[key], out)
    got = reads["state"]
    state = _number(got.get("state"))
    out.write("  state: %s (its process's id: %s)\n" % (_word(STATES, got.get("state"), "a state"),
                                                      _said(got.get("pid"))))
    if state != RUNNING:
        _exit(got, out, ws, state, ours)
    if state == START_PENDING and ours:
        out.write("  a start may be long: before the watch the runner checks its own code (ADR-0013 T-2) and tells"
                  " the system to wait up to %d s; ask again\n" % (ws.CHECK_WAIT_HINT // 1000))
    if not ours:
        word = STATES[state].upper() if state in STATES else "IN A STATE THIS COMMAND HAS NO WORD FOR"
        return 3, "NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS %s" % word
    for line in differ:
        out.write("  NOT AS INSTALLED: %s\n" % line)
    if state == RUNNING and not differ:
        out.write("  ACTIVE says the service runs, not that the watch writes its record\n")
        return 0, "ACTIVE"
    if state == RUNNING:
        return 1, "ACTIVE, NOT AS INSTALLED"
    return 1, "INSTALLED, NOT ACTIVE%s" % (", NOT AS INSTALLED" if differ else "")


def status(system, out):
    """V-2 to V-4: Raqib's service of Windows as the service manager holds it, with no rights; the exit (0 ACTIVE, 1
    installed and not active or not as installed, 3 not installed, not Raqib's or not known, 2 not Windows)."""
    from raqib import winservice   # E2: told and the runner's numbers, at the call alone
    try:
        platform = system.platform()
    except Exception as exc:
        platform = _failed(exc)
    if platform != "win32":
        out.write("raqib service status: Windows only here (the system's service manager); this is %s; nothing"
                  " asked\n" % _said(platform))
        return 2
    out.write("raqib service status\n")
    opened = []
    try:
        code, result = _read(system, out, winservice, opened)
    except Exception as exc:   # an answer of a shape this command does not read: said, never raised
        out.write("  an answer this command cannot read, or a fault of its own (%s)\n" % type(exc).__name__)
        code, result = 3, "NOT KNOWN"
    for what, handle in reversed(opened):   # every handle opened is closed, on every road
        _, error = _call(system.close, handle)
        if error:
            out.write("  %s: CloseServiceHandle failed: %s\n" % (what, _error_said(error)))
            code, result = 3, "NOT KNOWN"
    out.write("RESULT: %s\n" % result)
    return code


def cli_run(args, out, system=None):
    """`raqib service status` on Windows, from raqib/cli.py (its only importer). Refused: exit 2, said by the
    caller, in the Linux command's words."""
    if args.no_start:
        raise Refused("raqib service: --no-start is install's only")
    if args.purge:
        raise Refused("raqib service: --purge is remove's only")
    if args.action != "status":
        raise Refused("raqib service %s: not asked of raqib/winmanager.py" % args.action)
    return status(system or System(), out)
