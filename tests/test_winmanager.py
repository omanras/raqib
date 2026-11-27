"""M12.4c2b2a (ADR-0013 Amendment V, V-2 to V-5): `raqib service status` on Windows, by the system's own calls and
with no rights (raqib/winmanager.py); M12.4c2b2c (Amendment Z): and the start-again settings the install makes.

Every call of the system goes through a made-up service manager (Manager, in place of winmanager.System): no test
here needs Windows or a service manager, none loads a library, and none makes, starts, stops, changes or removes a
service - the Manager has no call that writes anything. It counts the handles it gives and the ones closed. The real
object is read by its syntax tree (E1) and, off Windows only, asked once to show that it never raises.
"""
import ast
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, service, winmanager, winservice  # noqa: E402

SOURCE = (ROOT / "raqib" / "winmanager.py").read_text(encoding="ascii")
PACKED = '"C:\\Program Files\\Raqib\\raqib.exe" service run'
PLAIN = '"C:\\Program Files\\Raqib\\Python311\\python.exe" -I -m raqib service run'
MAKING = {"type": 0x10, "start": 2, "command": PACKED, "account": "LocalSystem"}
STATE = {"type": 0x10, "state": 4, "exit": 0, "own": 0, "pid": 4321}
MARKED = "raqib-service/1 Raqib's watch of this host as a service of Windows (ADR-0013)"
FAILURE = {"reset": 3600, "message": None, "command": None, "actions": [(1, 5000), (1, 30000), (1, 300000)]}
CALLS = ("connect", "open", "description", "making", "actions", "flag", "delayed", "state")
# Z-1: the three lines a service the install made reads, after the account's and before the state's
AS_MADE = ["  after an end that was no Stop: start it again after 5 s, start it again after 30 s, start it again"
           " after 300 s; the count forgotten after 3600 s",
           "  the failure flag: 1, set (an end the service itself reports with an error is such an end too)",
           "  delayed start: 0, not delayed"]


class Manager:
    """A made-up service manager: it answers each call winmanager.status makes, as the real object's methods do -
    (what was read, 0) or (None, an error) - gives each handle a number of its own and records every call in order.
    fail: {call: error}; raises: the calls that raise. failure, flag, delayed: levels 2, 4 and 3 (Z-1), by default
    as Raqib's install makes them. It has no call that writes anything."""

    def __init__(self, platform="win32", there=True, description=MARKED, making=None, state=None, fail=None,
                 raises=(), failure=None, flag=1, delayed=0):
        self.os, self.there, self.text = platform, there, description
        self.made, self.got = dict(MAKING, **(making or {})), dict(STATE, **(state or {}))
        self.failure, self.flag_read, self.delayed_read = dict(FAILURE, **(failure or {})), flag, delayed
        self.fail, self.raises = dict(fail or {}), set(raises)
        self.opened, self.closed, self.log, self.next = [], [], [], 100
        self.breaches = []   # a call with a handle not held, or another name: kept, and asked() holds none

    def _answer(self, call, value):
        self.log.append(call)
        if call in self.raises:
            raise RuntimeError("made up")
        if call in self.fail:
            return None, self.fail[call]
        return value, 0

    def _give(self):
        self.next += 1
        self.opened.append(self.next)
        return self.next

    def _held(self, handle):
        if handle not in self.opened or handle in self.closed:
            self.breaches.append(("a handle not held", handle))

    def platform(self):
        self.log.append("platform")
        return self.os

    def connect(self):
        value, error = self._answer("connect", None)
        return (self._give(), 0) if "connect" not in self.fail else (None, error)

    def open(self, manager, name):
        self._held(manager)
        if name != winservice.SERVICE_NAME or manager != self.opened[0]:
            self.breaches.append(("opened otherwise", manager, name))
        if not self.there and "open" not in self.fail:
            self.log.append("open")
            return None, 1060
        value, error = self._answer("open", None)
        return (self._give(), 0) if "open" not in self.fail else (None, error)

    def description(self, handle):
        self._held(handle)
        return self._answer("description", self.text)

    def making(self, handle):
        self._held(handle)
        return self._answer("making", dict(self.made))

    def actions(self, handle):
        self._held(handle)
        return self._answer("actions", dict(self.failure))

    def flag(self, handle):
        self._held(handle)
        return self._answer("flag", self.flag_read)

    def delayed(self, handle):
        self._held(handle)
        return self._answer("delayed", self.delayed_read)

    def state(self, handle):
        self._held(handle)
        return self._answer("state", dict(self.got))

    def close(self, handle):
        self._held(handle)
        self.closed.append(handle)
        return self._answer("close", True)


def asked(manager):
    out = io.StringIO()
    code = winmanager.status(manager, out)
    lines = out.getvalue().splitlines()
    assert sorted(manager.closed) == sorted(manager.opened), (manager.opened, manager.closed)   # every handle closed
    assert manager.closed == manager.opened[::-1]   # the service's before the manager's, each once
    assert manager.breaches == [], manager.breaches   # no call with a handle not held (kept, never swallowed)
    if code != 2:
        assert lines[0] == "raqib service status" and lines[-1].startswith("RESULT: ")
        assert sum(1 for x in lines if x.startswith("RESULT:")) == 1
        assert all(x.startswith("  ") for x in lines[1:-1]), lines
    assert all(x.isascii() and x.isprintable() for x in lines)
    return code, lines


def result(manager):
    code, lines = asked(manager)
    return code, lines[-1]


# --- E2, E3: the answers -------------------------------------------------------------------------------------------

def test_e3_active_where_running_and_as_installed_in_both_forms_with_the_lines_of_v3_in_order():
    for command, form, words in ((PACKED, "service run", "a packed program's"),
                                 (PLAIN, "-I -m raqib service run", "a plain interpreter's")):
        manager = Manager(making={"command": command})
        code, lines = asked(manager)
        path = command.split('"')[1]
        assert code == 0 and lines == [
            "raqib service status",
            "  a service named RaqibWatch is there (opened with the rights 0x5, to ask its state and its making)",
            "  installed: it carries Raqib's mark, raqib-service/1, at the start of its description",
            "  command: %s (as the service manager holds it)" % command,
            "  its form: a quoted path, then `%s` (%s), one of the two Raqib's install writes; the path it names: %s"
            % (form, words, path),
            "  type: 0x10, a process of its own",
            "  start: 2, automatic",
            "  account: LocalSystem (the system's)"] + AS_MADE + [   # M12.4c2b2c (Z-1): the three lines added
            "  state: 4, running (its process's id: 4321)",
            "  ACTIVE says the service runs, not that the watch writes its record",
            "RESULT: ACTIVE"]
        assert manager.log == ["platform", "connect", "open", "description", "making", "actions", "flag", "delayed",
                               "state", "close", "close"]   # M12.4c2b2c: levels 2, 4 and 3 after the making


def test_e2_the_mark_is_services_mark_without_its_hash_and_must_begin_the_description():
    assert winmanager.MARK == service.MARK[2:] == "raqib-service/1" and service.MARK == "# " + winmanager.MARK
    assert winmanager.marked("raqib-service/1") and winmanager.marked("raqib-service/1 the watch")
    assert winmanager.marked("raqib-service/1\tthe watch")
    for text in ("raqib-service/10", "raqib-service/1x", " raqib-service/1", "the watch raqib-service/1", "",
                 "RAQIB-SERVICE/1", None, b"raqib-service/1", 1):
        assert not winmanager.marked(text), text


@pytest.mark.parametrize("text, said", [
    (None, "not installed by Raqib: it has no description; a service of the name without Raqib's mark is not"
           " Raqib's"),
    ("", "not installed by Raqib: its description is empty;"),
    (b"raqib-service/1", "not installed by Raqib: its description is not text (bytes);"),
    (7, "not installed by Raqib: its description is not text (int);"),
    ("Another program's service", "its description does not begin with raqib-service/1: \"Another program's"
                                  " service\""),
    ("raqib-service/10 a later one", "does not begin with raqib-service/1: \"raqib-service/10 a later one\""),
    ("a\x00b\nc\u202ed", "does not begin with raqib-service/1: \"a?b?c?d\""),
])
def test_e3_a_service_of_the_name_without_the_mark_is_not_raqibs_and_its_state_is_said(text, said):
    for number, word in sorted(winmanager.STATES.items()):
        code, lines = asked(Manager(description=text, state={"state": number}))
        assert code == 3 and lines[-1] == "RESULT: NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS %s" % (
            word.upper()), lines
        assert said in lines[2] and lines[2].startswith("  not installed by Raqib: ")
        assert not [x for x in lines if "NOT AS INSTALLED" in x or "ACTIVE" in x]
    code, lines = asked(Manager(description=text, state={"state": 9}))
    assert lines[-1] == "RESULT: NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS IN A STATE THIS COMMAND HAS" \
                        " NO WORD FOR"


def test_e2_a_description_over_the_bound_is_cut_and_marked_and_the_mark_still_read():
    long = "x" * (winmanager.SAID_MAX + 50)
    code, lines = asked(Manager(description=long))
    assert code == 3 and lines[2].endswith(": \"%s...\"; a service of the name without Raqib's mark is not"
                                           " Raqib's" % ("x" * winmanager.SAID_MAX))
    code, lines = asked(Manager(description=MARKED + "y" * 100000))
    assert code == 0 and lines[2] == "  installed: it carries Raqib's mark, raqib-service/1, at the start of its" \
                                     " description"
    weird = '"C:\\x\\%s.exe" service run' % ("\x01" * 400)
    code, lines = asked(Manager(making={"command": weird}))
    command = [x for x in lines if x.startswith("  command: ")][0]
    assert code == 1 and command == "  command: %s... (as the service manager holds it)" % (
        '"C:\\x\\' + "?" * (winmanager.SAID_MAX - 6))


def test_e3_not_installed_where_the_name_is_not_there_1060():
    manager = Manager(there=False)
    code, lines = asked(manager)
    assert code == 3 and lines == ["raqib service status", "  not installed: the service manager holds no service"
                                   " named RaqibWatch (OpenServiceW: error 1060)", "RESULT: NOT INSTALLED"]
    assert manager.log == ["platform", "connect", "open", "close"] and len(manager.opened) == 1


@pytest.mark.parametrize("number, word", sorted(winmanager.STATES.items()) + [(9, None), (0, None)])
def test_e3_every_state_by_its_number_and_word_and_only_running_is_active(number, word):
    code, lines = asked(Manager(state={"state": number, "pid": 0 if number != 4 else 77, "exit": 0}))
    state = [x for x in lines if x.startswith("  state: ")]
    if word:
        assert state == ["  state: %d, %s (its process's id: %d)" % (number, word, 0 if number != 4 else 77)]
    else:
        assert state == ["  state: %d, a state this command has no word for (its process's id: 0)" % number]
    if number == 4:
        assert (code, lines[-1]) == (0, "RESULT: ACTIVE")
        assert not [x for x in lines if x.startswith("  exit: ")]   # where it runs, no exit is said
    else:
        assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE")
        # W-2: "stopped" is said of a stopped service alone; of any other state only the number the system holds
        assert [x for x in lines if "exit" in x] == ["  exit: 0, stopped with no failure" if number == 1 else
                                                     "  exit the system holds: 0"]
        assert ("stopped" in " ".join(lines[1:-1])) == (number == 1)
        assert "ACTIVE says the service runs" not in " ".join(lines)
    starting = [x for x in lines if "a start may be long" in x]
    assert starting == ([] if number != 2 else ["  a start may be long: before the watch the runner checks its own"
                                                " code (ADR-0013 T-2) and tells the system to wait up to 60 s; ask"
                                                " again"])
    assert winservice.CHECK_WAIT_HINT == 60000


def test_e3_each_exit_where_it_is_not_running():
    def exit_lines(**state):
        code, lines = asked(Manager(state=dict({"state": 1, "pid": 0}, **state)))
        assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE")
        return [x for x in lines if x.startswith("  exit: ") or "text file" in x]
    assert exit_lines(exit=0) == ["  exit: 0, stopped with no failure"]
    assert exit_lines(exit=1077) == ["  exit: 1077, never started (since it was made, or since the system started)"]
    assert exit_lines(exit=1067) == ["  exit: 1067, the system's number for the service's end (its words are not"
                                     " read here)"]
    assert exit_lines(exit="x\x00") == ["  exit: x?, not a number"]
    for own in sorted(winservice.EXIT_WORDS):   # 10 to 23: each in the runner's own words, by told()
        got = exit_lines(exit=winservice.SERVICE_SPECIFIC, own=own)
        assert got[0] == "  exit: 1066, the service's own number: %s" % winservice.told(own)
        assert winservice.EXIT_WORDS[own] in got[0] and "0x%08X" % own in got[0]
        if own == winservice.EXIT_NOT_ALONE:
            assert got[1:] == ["  what was refused is in its text file: service.txt in the place (Raqib under"
                               " ProgramData, as the runner took it at that start)"]
            assert winservice.TEXT_NAME == "service.txt" and winservice.PLACE_NAME == "Raqib"
        else:
            assert got[1:] == []
    assert {n - winservice.EXIT_BASE for n in winservice.EXIT_WORDS} == set(range(10, 24)) - {19}
    for own in (winservice.EXIT_BASE + 19, winservice.EXIT_BASE + 24, 7, 0):
        assert exit_lines(exit=1066, own=own) == ["  exit: 1066, the service's own number: %d (0x%08X), a number the"
                                                  " runner does not give" % (own, own)]
    assert exit_lines(exit=1066, own=None) == ["  exit: 1066, the service's own number: None, a number the runner"
                                               " does not give"]


@pytest.mark.parametrize("making, differs", [
    ({"command": '"C:\\Program Files\\Raqib\\raqib.exe" service run '}, "the command is not one of the two forms"),
    ({"command": 'C:\\Program Files\\Raqib\\raqib.exe service run'}, "the command is not one of the two forms"),
    ({"command": '"C:\\Program Files\\Raqib\\raqib.exe" service  run'}, "the command is not one of the two forms"),
    ({"command": '"C:\\Program Files\\Raqib\\raqib.exe" watch --host'}, "the command is not one of the two forms"),
    ({"command": '"C:\\Program Files\\Raqib\\python.exe" -m raqib service run'}, "the command is not one of the two"),
    ({"command": '"C:\\Program Files\\Raqib\\python.exe" -I -m raqib service run -x'}, "not one of the two forms"),
    ({"command": '"" service run'}, "the command is not one of the two forms"),
    ({"command": '"C:\\a"b" service run'}, "the command is not one of the two forms"),
    ({"command": '"C:\\a\tb" service run'}, "the command is not one of the two forms"),
    ({"command": None}, "the command is not one of the two forms"),
    ({"command": 7}, "the command is not one of the two forms"),
    ({"type": 0x20}, "the type is not a process of its own (0x10)"),
    ({"type": 0x110}, "the type is not a process of its own (0x10)"),
    ({"type": "0x10"}, "the type is not a process of its own (0x10)"),
    ({"account": ".\\user"}, "the account is not the system's (LocalSystem)"),
    ({"account": "NT AUTHORITY\\LocalService"}, "the account is not the system's (LocalSystem)"),
    ({"account": None}, "the account is not the system's (LocalSystem)"),
])
def test_e3_not_as_installed_with_what_differs_running_or_not(making, differs):
    code, lines = asked(Manager(making=making))
    assert (code, lines[-1]) == (1, "RESULT: ACTIVE, NOT AS INSTALLED")
    assert "ACTIVE says the service" not in str(lines)
    said = [x for x in lines if x.startswith("  NOT AS INSTALLED: ")]
    assert len(said) == 1 and differs in said[0], lines
    code, lines = asked(Manager(making=making, state={"state": 1, "exit": 1077}))
    assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE, NOT AS INSTALLED")
    assert [x for x in lines if x.startswith("  NOT AS INSTALLED: ")] == said


def test_e2_each_line_of_the_making_in_words_and_every_difference_said():
    code, lines = asked(Manager(making={"command": "x", "type": 0x20, "start": 9, "account": "LocalSystem2"}))
    assert code == 1 and lines[3:12] == [
        "  command: x (as the service manager holds it)",
        "  its form: not one of the two Raqib's install writes (a quoted path, then `service run`; a quoted path,"
        " then `-I -m raqib service run`)",
        "  type: 0x20, a process shared with other services",
        "  start: 9, a start this command has no word for",
        "  account: LocalSystem2"] + AS_MADE + [   # M12.4c2b2c (Z-1): the three lines added
        "  state: 4, running (its process's id: 4321)"]
    assert [x for x in lines if "NOT AS INSTALLED:" in x] == [
        "  NOT AS INSTALLED: the command is not one of the two forms Raqib's install writes",
        "  NOT AS INSTALLED: the type is not a process of its own (0x10)",
        "  NOT AS INSTALLED: start: 9, a start this command has no word for; the install writes 2, automatic",   # Z-2
        "  NOT AS INSTALLED: the account is not the system's (LocalSystem)"]
    for number, word in sorted(winmanager.STARTS.items()):
        assert "  start: %d, %s" % (number, word) in asked(Manager(making={"start": number}))[1]
    assert "  account: localsystem (the system's)" in asked(Manager(making={"account": "localsystem"}))[1]
    assert "  type: 0x1, a kernel driver" in asked(Manager(making={"type": 1}))[1]


# --- E3: each call failing is NOT KNOWN, with the call and the system's number -------------------------------------

@pytest.mark.parametrize("call, words", [
    ("connect", "  the service manager: OpenSCManagerW (rights 0x1, to connect) failed: "),
    ("open", "  the service RaqibWatch: OpenServiceW (rights 0x5, to ask its state and its making) failed: "),
    ("description", "  its description: QueryServiceConfig2W (level 1) failed: "),
    ("making", "  its making: QueryServiceConfigW failed: "),
    ("actions", "  its failure actions: QueryServiceConfig2W (level 2) failed: "),   # M12.4c2b2c (Z-1)
    ("flag", "  its failure flag: QueryServiceConfig2W (level 4) failed: "),
    ("delayed", "  its delayed start: QueryServiceConfig2W (level 3) failed: "),
    ("state", "  its state: QueryServiceStatusEx failed: "),
])
def test_e3_each_call_failing_is_not_known_the_call_and_its_number_said_5_the_caller_may_not_ask(call, words):
    for error, said in ((5, "error 5 (access denied: the caller may not ask this of the service manager)"),
                        (6, "error 6"), (122, "error 122 (the room given was not enough)"),
                        ("the first ask named 9000 bytes, not from 36 to 8192 (the bound)",
                         "the first ask named 9000 bytes, not from 36 to 8192 (the bound)"),
                        (None, "it failed and the system gave no error number"),
                        (False, "it failed and the system gave no error number")):
        manager = Manager(fail={call: error})
        code, lines = asked(manager)
        assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and words + said in lines, lines
        assert manager.log[-1 - len(manager.opened):] == [call] + ["close"] * len(manager.opened)
        later = CALLS[CALLS.index(call) + 1:]
        assert not set(later) & set(manager.log)   # nothing asked after a failure
        assert len(manager.opened) == min(CALLS.index(call), 2)
    manager = Manager(raises={call})
    code, lines = asked(manager)
    assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and words + "an exception, RuntimeError" in lines


def test_e3_a_close_that_fails_is_said_and_the_answer_is_not_known_every_handle_still_closed():
    for error, said in ((6, "error 6"), ("an exception, OSError (error 6)", "an exception, OSError (error 6)")):
        manager = Manager(fail={"close": error})
        code, lines = asked(manager)
        assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and lines[-3:-1] == [
            "  the service RaqibWatch: CloseServiceHandle failed: %s" % said,
            "  the service manager: CloseServiceHandle failed: %s" % said]
        assert "RESULT: ACTIVE" not in lines
    manager = Manager(raises={"close"}, there=False)
    code, lines = asked(manager)
    assert (code, lines[-2:]) == (3, ["  the service manager: CloseServiceHandle failed: an exception, RuntimeError",
                                      "RESULT: NOT KNOWN"])


def test_e3_an_answer_of_a_shape_this_command_does_not_read_is_not_known_never_raised_handles_closed():
    class Odd(Manager):
        def state(self, handle):
            return "not a pair"
    code, lines = asked(Odd())
    assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and "an exception, ValueError" in lines[-2]

    class Shapeless(Manager):
        def making(self, handle):
            return ["no", "get"], 0
    code, lines = asked(Shapeless())
    assert (code, lines[-2:]) == (3, ["  an answer this command cannot read, or a fault of its own (AttributeError)",
                                      "RESULT: NOT KNOWN"])


def test_e3_not_windows_is_2_nothing_asked_and_one_line():
    for platform in ("linux", "darwin", "cygwin", "win32 "):
        manager = Manager(platform=platform)
        out = io.StringIO()
        assert winmanager.status(manager, out) == 2 and manager.log == ["platform"] and not manager.opened
        assert out.getvalue() == "raqib service status: Windows only here (the system's service manager); this is" \
                                 " %s; nothing asked\n" % platform


def test_e3_the_first_ask_with_no_room_must_answer_122_and_name_bytes_inside_the_bound():
    assert winmanager.room(0, 122, 36, 36) == (36, None) and winmanager.room(False, 122, 8192, 36) == (8192, None)
    assert winmanager.room(1, 0, 0, 36) == (None, "the first ask with no room was answered as done, not with error"
                                                  " 122")
    assert winmanager.room(0, 5, 100, 36) == (None, 5) and winmanager.room(0, 1060, 100, 36) == (None, 1060)
    assert winmanager.room(0, 0, 100, 36) == (None, "it failed and the system gave no error number")
    for needed in (0, 35, 8193, 1 << 40, None, "36"):
        assert winmanager.room(0, 122, needed, 36) == (None, "the first ask named %s bytes, not from 36 to 8192 (the"
                                                             " bound)" % needed)
    assert winmanager.ASK_MAX == 8192 and winmanager.room(0, 122, 100, 8, bound=99) == (
        None, "the first ask named 100 bytes, not from 8 to 99 (the bound)")


def test_e2_the_command_is_parsed_strictly_a_quoted_path_then_exactly_the_words():
    assert winmanager.COMMAND.pattern.endswith(" (%s)" % "|".join(winmanager.FORMS))
    assert winmanager.command_form(PACKED) == ("service run", "C:\\Program Files\\Raqib\\raqib.exe")
    assert winmanager.command_form(PLAIN) == ("-I -m raqib service run",
                                              "C:\\Program Files\\Raqib\\Python311\\python.exe")
    for bad in (PACKED + " ", " " + PACKED, PACKED.replace('"', ""), PACKED + "\n", PLAIN.replace("-I ", "-i "),
                PLAIN.replace("-I -m", "-I  -m"), '"C:\\x" service run --x', '"C:\\x"service run', None, b"x"):
        assert winmanager.command_form(bad) is None, bad


# --- E1: the system object -----------------------------------------------------------------------------------------

def tree_of():
    tree = ast.parse(SOURCE)
    system = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System")
    return tree, system, {n.name: n for n in system.body if isinstance(n, ast.FunctionDef)}


DECLARED = {
    "OpenSCManagerW": ("wintypes.HANDLE", "[wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]"),
    "OpenServiceW": ("wintypes.HANDLE", "[wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]"),
    "QueryServiceStatusEx": ("wintypes.BOOL", "[wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,"
                                              " ctypes.POINTER(wintypes.DWORD)]"),
    "QueryServiceConfigW": ("wintypes.BOOL", "[wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,"
                                             " ctypes.POINTER(wintypes.DWORD)]"),
    "QueryServiceConfig2W": ("wintypes.BOOL", "[wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,"
                                              " ctypes.POINTER(wintypes.DWORD)]"),
    "CloseServiceHandle": ("wintypes.BOOL", "[wintypes.HANDLE]"),
}


def test_e1_one_system_object_whose_methods_are_the_systems_own_calls_each_declared():
    tree, system, methods = tree_of()
    assert [n.name for n in tree.body if isinstance(n, ast.ClassDef)] == ["Refused", "System"]
    assert set(methods) == {"__init__", "platform", "_win", "connect", "open", "state", "making", "description",
                            "actions", "flag", "delayed", "close"}   # M12.4c2b2c (Z-1): levels 2, 4 and 3
    declared = {}
    for node in ast.walk(methods["_win"]):
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]).startswith("adv."):
            _, call, kind = ast.unparse(node.targets[0]).split(".")
            declared.setdefault(call, {})[kind] = ast.unparse(node.value)
    assert {k: (v["restype"], v["argtypes"]) for k, v in declared.items()} == DECLARED
    # W-4: the three structures, field by field in the system's own order, and the two asks bounded by room()
    fields = {n.name: ast.unparse(n.body[0]) for n in ast.walk(methods["_win"]) if isinstance(n, ast.ClassDef)}
    assert fields == {name: "_fields_ = [%s]" % ", ".join("('%s', %s)" % (n, t if "." in t else "wintypes." + t)
                                                          for n, t in listed)
                      for name, listed in STRUCTURES.items()}
    for call, structure in (("making", "config"), ("description", "description"), ("actions", "failure"),
                            ("flag", "flag"), ("delayed", "delayed")):
        assert ("room(done, 0 if done else api.ctypes.get_last_error(), needed.value, api.ctypes.sizeof(api.%s))"
                % structure) in ast.unparse(methods[call]), call
    loads = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call) and "WinDLL" in ast.unparse(n.func)]
    assert loads == ["ctypes.WinDLL('advapi32', use_last_error=True)"]
    used = {}
    for name, fn in methods.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and ast.unparse(node.func).startswith("api.adv."):
                used.setdefault(ast.unparse(node.func).split(".")[2], set()).add(name)
    assert used == {"OpenSCManagerW": {"connect"}, "OpenServiceW": {"open"}, "QueryServiceStatusEx": {"state"},
                    "QueryServiceConfigW": {"making"},
                    "QueryServiceConfig2W": {"description", "actions", "flag", "delayed"},
                    "CloseServiceHandle": {"close"}}
    calls = {ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "api.adv.OpenSCManagerW(None, None, MANAGER_RIGHTS)" in calls and winmanager.MANAGER_RIGHTS == 0x1
    assert "api.adv.OpenServiceW(manager, name, SERVICE_RIGHTS)" in calls and winmanager.SERVICE_RIGHTS == 0x5
    assert "api.adv.QueryServiceConfigW(service, None, 0, api.ctypes.byref(needed))" in calls   # the first ask
    assert "api.adv.QueryServiceConfig2W(service, CONFIG_DESCRIPTION, None, 0, api.ctypes.byref(needed))" in calls
    assert winmanager.CONFIG_DESCRIPTION == 1 and winmanager.STATUS_PROCESS_INFO == 0 and winmanager.NO_ROOM == 122
    for level in ("CONFIG_FAILURE_ACTIONS", "CONFIG_FAILURE_FLAG", "CONFIG_DELAYED"):   # Z-1: each first ask
        assert "api.adv.QueryServiceConfig2W(service, %s, None, 0, api.ctypes.byref(needed))" % level in calls
    assert (winmanager.CONFIG_FAILURE_ACTIONS, winmanager.CONFIG_DELAYED, winmanager.CONFIG_FAILURE_FLAG) == (2, 3, 4)
    # Z-1: the count of actions is bounded, and the array placed inside the bytes read, before any of it is read;
    # the array is read out of the bytes at that offset, never by the pointer the structure holds
    actions = ast.unparse(methods["actions"])
    assert actions.index("array_at(count, where, api.ctypes.addressof(raw), size, api.ctypes.sizeof(api.action))") \
        < actions.index("(api.action * count).from_buffer(raw, offset)") and "contents" not in actions.split(
            "array_at(count, where")[1] and winmanager.ACTIONS_MAX == 64
    for name in ("connect", "open", "state", "making", "description", "actions", "flag", "delayed",
                 "close"):   # each: errors read, never raised
        body = methods[name].body
        tries = [n for n in body if isinstance(n, ast.Try)]
        assert len(tries) == 1 and [ast.unparse(h.type) for h in tries[0].handlers] == ["Exception"], name
        assert "api.ctypes.get_last_error()" in ast.unparse(methods[name]), name
        assert all(isinstance(r.value, ast.Tuple) or isinstance(r.value, ast.IfExp)
                   for r in ast.walk(methods[name]) if isinstance(r, ast.Return)), name


def test_e1_standard_library_only_ctypes_inside_system_nothing_at_import_no_program_no_file_no_registry():
    tree, system, methods = tree_of()
    for node in tree.body:   # nothing runs at import: a docstring, imports, constants, classes and functions
        assert isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.ClassDef, ast.FunctionDef))
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant) and node is tree.body[0]
        if isinstance(node, ast.Assign):
            assert not [c for c in ast.walk(node.value) if isinstance(c, ast.Call)
                        and ast.unparse(c.func) not in ("re.compile", "dict")], \
                ast.unparse(node)
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = [(a.name if isinstance(n, ast.Import) else "%s.%s" % (n.module, a.name))
             for n in imports for a in n.names]
    assert sorted(names) == ["__future__.annotations", "ctypes", "ctypes.wintypes", "raqib.winservice", "re", "sys",
                             "types"]
    inside = {id(n) for n in ast.walk(methods["_win"])}
    assert [ast.unparse(n) for n in imports if id(n) in inside] == ["import ctypes", "from ctypes import wintypes"]
    status = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "status")
    assert [ast.unparse(n) for n in ast.walk(status) if isinstance(n, ast.ImportFrom)] == [
        "from raqib import winservice"]
    for words in ("subprocess", "os.", "open(", "winreg", "socket", "kernel32", "CreateService", "StartService",
                  "ControlService", "DeleteService", "ChangeServiceConfig", "OpenSCManagerA", "SC_MANAGER_ALL",
                  "Popen", "system(", "import service", "write_bytes", "write_text", "Reg"):
        assert words not in SOURCE.replace("api.adv.OpenServiceW(", "").replace("def open(", ""), words
    assert (ROOT / "raqib" / "winmanager.py").read_bytes().isascii()
    assert max(len(x) for x in SOURCE.splitlines()) <= 118


def test_e1_e4_the_module_is_imported_nowhere_but_in_cmd_service():
    where = []
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(fn):
                if isinstance(node, (ast.Import, ast.ImportFrom)) and "winmanager" in ast.unparse(node):
                    where.append((path.name, fn.name, ast.unparse(node)))
        assert not [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
                    and "winmanager" in ast.unparse(n)], path
    assert where[0] == ("cli.py", "cmd_service", "from raqib import winmanager")   # M12.4c2b2b (X-2): and the
    assert sorted({(f, i) for f, _, i in where[1:]}) == [   # install's functions, which read its own work back
        ("wininstall.py", "from raqib import wincode, winmanager, winservice"),
        ("wininstall.py", "from raqib import winmanager"),
        ("wininstall.py", "from raqib import winmanager, winservice")]
    assert all(f == "wininstall.py" for f, _, _ in where[1:]) and len(where) >= 4   # and nowhere else


STRUCTURES = {   # as the system documents them (winsvc.h), each field by its name and type, in order
    "SERVICE_STATUS_PROCESS": [(name, "DWORD") for name in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode", "dwServiceSpecificExitCode",
        "dwCheckPoint", "dwWaitHint", "dwProcessId", "dwServiceFlags")],
    "QUERY_SERVICE_CONFIGW": [("dwServiceType", "DWORD"), ("dwStartType", "DWORD"), ("dwErrorControl", "DWORD"),
                              ("lpBinaryPathName", "LPWSTR"), ("lpLoadOrderGroup", "LPWSTR"), ("dwTagId", "DWORD"),
                              ("lpDependencies", "LPWSTR"), ("lpServiceStartName", "LPWSTR"),
                              ("lpDisplayName", "LPWSTR")],
    "SERVICE_DESCRIPTIONW": [("lpDescription", "LPWSTR")],
    # M12.4c2b2c (Z-1): QueryServiceConfig2W's levels 2, 4 and 3 (and raqib/wininstall.py's, the same, a test ties)
    "SC_ACTION": [("Type", "ctypes.c_int"), ("Delay", "DWORD")],
    "SERVICE_FAILURE_ACTIONSW": [("dwResetPeriod", "DWORD"), ("lpRebootMsg", "LPWSTR"), ("lpCommand", "LPWSTR"),
                                 ("cActions", "DWORD"), ("lpsaActions", "ctypes.POINTER(SC_ACTION)")],
    "SERVICE_FAILURE_ACTIONS_FLAG": [("fFailureActionsOnNonCrashFailures", "BOOL")],
    "SERVICE_DELAYED_AUTO_START_INFO": [("fDelayedAutostart", "BOOL")],
}


class Library:
    """A made-up advapi32 for the real object's own logic (W-4): its six calls fill the real structures as the
    system's do - a first ask with no room answers `first` and names the bytes, the second fills the buffer - and
    keep what they were asked. Nothing of the system is called. M12.4c2b2c (Z-1): QueryServiceConfig2W answers levels
    2, 4 and 3 too, by default as Raqib's install makes them - level 2's array of actions inside the same bytes, after
    the structure, as the system lays it; failure may hold `count` (cActions said otherwise than the array) and
    `where` ("null": no array; "outside": an array outside the bytes); fails: {level: the first ask's error}."""

    def __init__(self, real, description=MARKED, first=122, failure=None, flag=1, delayed=0, fails=None):
        self.real, self.text, self.first, self.last, self.closed, self.kept = real, description, first, 0, [], []
        self.failure, self.set_flag, self.set_delayed = dict(FAILURE, **(failure or {})), flag, delayed
        self.fails, self.levels = dict(fails or {}), []
        for name in DECLARED:
            setattr(self, name, _Callable(getattr(self, "_" + name)))

    def _ask(self, kind, buffer, size, needed, more, first=None):
        import ctypes
        if buffer is None:
            needed._obj.value, self.last = ctypes.sizeof(kind) + more, self.first if first is None else first
            return 0
        assert size == ctypes.sizeof(kind) + more and len(buffer) == size
        got = kind.from_buffer(buffer)
        self.kept.append(got)   # the texts a field points at live as long as this
        return got

    def _OpenSCManagerW(self, machine, base, rights):
        return 11 if (machine, base, rights) == (None, None, 0x1) else None

    def _OpenServiceW(self, manager, name, rights):
        return 12 if (manager, name, rights) == (11, winservice.SERVICE_NAME, 0x5) else None

    def _QueryServiceStatusEx(self, service, level, buffer, size, needed):
        import ctypes
        got = buffer._obj
        assert (service, level, size) == (12, 0, ctypes.sizeof(got))
        got.dwServiceType, got.dwCurrentState, got.dwWin32ExitCode = 0x10, 1, winservice.SERVICE_SPECIFIC
        got.dwServiceSpecificExitCode, got.dwProcessId = winservice.EXIT_NOT_ALONE, 0
        return 1

    def _QueryServiceConfigW(self, service, buffer, size, needed):
        got = self._ask(self.real._api.config, buffer, size, needed, 200)
        if got == 0:
            return 0
        got.dwServiceType, got.dwStartType = 0x10, 2
        got.lpBinaryPathName, got.lpServiceStartName = PLAIN, "LocalSystem"
        return 1

    def _QueryServiceConfig2W(self, service, level, buffer, size, needed):
        import ctypes
        api, actions = self.real._api, list(self.failure["actions"])
        assert service == 12 and level in (1, 2, 3, 4)   # the service's handle, as opened (0x5)
        self.levels.append((level, "first" if buffer is None else "second"))
        kind, more = {1: (api.description, 160), 2: (api.failure, ctypes.sizeof(api.action) * len(actions)),
                      3: (api.delayed, 0), 4: (api.flag, 0)}[level]
        got = self._ask(kind, buffer, size, needed, more, self.fails.get(level))
        if got == 0:
            return 0
        if level == 1:
            got.lpDescription = self.text   # None: the system's NULL where a service has no description
        elif level == 2:
            at = ctypes.sizeof(kind)   # the array after the structure, inside the same bytes
            for one, (kind_of, delay) in zip((api.action * len(actions)).from_buffer(buffer, at), actions):
                one.Type, one.Delay = kind_of, delay
            got.dwResetPeriod, got.cActions = self.failure["reset"], self.failure.get("count", len(actions))
            got.lpRebootMsg, got.lpCommand = self.failure["message"], self.failure["command"]
            where = self.failure.get("where", "inside" if actions else "null")
            if where == "inside":
                got.lpsaActions = ctypes.cast(ctypes.addressof(buffer) + at, ctypes.POINTER(api.action))
            elif where == "outside":
                self.kept.append((api.action * len(actions))(*[api.action(*a) for a in actions]))
                got.lpsaActions = ctypes.cast(self.kept[-1], ctypes.POINTER(api.action))
        elif level == 3:
            got.fDelayedAutostart = self.set_delayed
        else:
            got.fFailureActionsOnNonCrashFailures = self.set_flag
        return 1

    def _CloseServiceHandle(self, handle):
        self.closed.append(handle)
        return 1


class _Callable:
    """A call of the made-up library: it takes the declarations the real object sets on it, and answers."""

    def __init__(self, answer):
        self.answer = answer

    def __call__(self, *given):
        return self.answer(*given)


def real_with(monkeypatch, **kw):
    import ctypes
    real = winmanager.System()
    library = Library(real, **kw)
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, use_last_error=False: library, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: library.last, raising=False)
    monkeypatch.setattr(real, "platform", lambda: "win32")
    out = io.StringIO()
    code = winmanager.status(real, out)
    return code, out.getvalue().splitlines(), library


def test_w4_the_real_objects_own_logic_runs_against_a_made_up_library_the_two_asks_the_cast_and_the_texts(
        monkeypatch):
    code, lines, library = real_with(monkeypatch)
    assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE"), lines
    assert "  command: %s (as the service manager holds it)" % PLAIN in lines
    assert "  account: LocalSystem (the system's)" in lines and "  start: 2, automatic" in lines
    assert "  installed: it carries Raqib's mark, raqib-service/1, at the start of its description" in lines
    assert "  exit: 1066, the service's own number: %s" % winservice.told(winservice.EXIT_NOT_ALONE) in lines
    assert library.closed == [12, 11]                       # the service's handle, then the manager's
    declared = {name: (getattr(library, name).restype, getattr(library, name).argtypes) for name in DECLARED}
    assert all(restype is not None and argtypes for restype, argtypes in declared.values())
    # a service with no description: the system's NULL is "no description", read without a fault
    code, lines, library = real_with(monkeypatch, description=None)
    assert code == 3 and "  not installed by Raqib: it has no description; a service of the name without Raqib's" \
                         " mark is not Raqib's" in lines and library.closed == [12, 11]
    # a first ask that answers another number than 122: nothing is read past it, and both handles are closed
    code, lines, library = real_with(monkeypatch, first=5)
    assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and library.closed == [12, 11]
    assert [x for x in lines if "QueryServiceConfig2W (level 1) failed" in x and "error 5" in x], lines


def test_w2_a_service_without_the_mark_is_not_read_as_raqibs_runner_no_words_of_its_own_no_text_file_no_t2():
    own = winservice.EXIT_NOT_ALONE
    refused = {"state": 1, "pid": 0, "exit": winservice.SERVICE_SPECIFIC, "own": own}
    code, lines = asked(Manager(description="Another program's service", state=refused))
    said = " ".join(lines)
    assert code == 3 and "  exit: 1066, a number of the service's own: %d (0x%08X)" % (own, own) in lines
    assert winservice.EXIT_WORDS[own] not in said and "text file" not in said and "service.txt" not in said
    code, lines = asked(Manager(description=None, state={"state": 2, "pid": 0}))
    assert "  exit the system holds: 0" in lines and "a start may be long" not in " ".join(lines)
    # the same two states of a service that carries the mark say them
    said = " ".join(asked(Manager(state=refused))[1])
    assert winservice.EXIT_WORDS[own] in said and "service.txt" in said
    assert "a start may be long" in " ".join(asked(Manager(state={"state": 2, "pid": 0}))[1])


def test_w3_text_read_from_the_manager_is_said_in_ascii_a_letter_of_another_script_by_its_number():
    look = '"C:\\Program Files\\Raqib\\r\u0430qib.exe" service run'   # a Cyrillic letter that reads as Latin
    code, lines = asked(Manager(making={"command": look, "account": "LocalSystem\u200b"}))
    assert ('  command: "C:\\Program Files\\Raqib\\r\\u0430qib.exe" service run (as the service manager holds'
            ' it)') in lines
    assert [x for x in lines if x.startswith("  its form: ") and x.endswith("r\\u0430qib.exe")], lines
    assert "  account: LocalSystem?" in lines and code == 1
    assert "  NOT AS INSTALLED: the account is not the system's (LocalSystem)" in lines
    assert winmanager._said("\u0430\u00e9\U0001F600 a") == "\\u0430\\u00E9\\U0001F600 a"
    assert winmanager._said("\u0430" * 400).endswith("...") and len(winmanager._said("\u0430" * 400)) == 303


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: on Windows the real object asks the manager")
def test_e1_the_real_object_off_windows_never_raises_and_says_what_failed():
    real = winmanager.System()
    assert real.platform() == sys.platform
    for name, args in (("connect", ()), ("open", (1, "RaqibWatch")), ("state", (1,)), ("making", (1,)),
                       ("description", (1,)), ("actions", (1,)), ("flag", (1,)), ("delayed", (1,)), ("close", (1,))):
        value, error = getattr(real, name)(*args)
        assert value is None and isinstance(error, str) and error.startswith("an exception, "), (name, error)
    out = io.StringIO()
    assert winmanager.status(real, out) == 2 and out.getvalue().startswith("raqib service status: Windows only here")


# --- E4: the command ---------------------------------------------------------------------------------------------

def args(action="status", **kw):
    return SimpleNamespace(action=action, no_start=kw.get("no_start", False), purge=kw.get("purge", False))


def test_e4_status_on_windows_goes_to_the_new_module_on_linux_to_service_as_before(monkeypatch):
    from raqib import wininstall   # M12.4c2b2b (ADR-0013 X-2): install and remove on Windows are its own
    got = []
    monkeypatch.setattr(winmanager, "cli_run", lambda a, out: got.append(("win", a.action)) or 7)
    monkeypatch.setattr(service, "cli_run", lambda a, out: got.append(("linux", a.action)) or 5)
    monkeypatch.setattr(wininstall, "cli_run", lambda a, out: got.append(("wininstall", a.action)) or 6)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert cli.cmd_service(args(), io.StringIO()) == 7
    assert cli.cmd_service(args("install"), io.StringIO()) == 6
    assert cli.cmd_service(args("remove"), io.StringIO()) == 6
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert cli.cmd_service(args(), io.StringIO()) == 5
    assert got == [("win", "status"), ("wininstall", "install"), ("wininstall", "remove"), ("linux", "status")]


def test_e4_on_windows_install_and_remove_answer_as_today_and_statuss_flags_are_refused(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    for action in ("install", "remove"):   # the Linux command's own refusal, asked of it (M12.4c2b2b: on Windows
        with pytest.raises(service.Refused) as caught:   # cmd_service turns them to raqib/wininstall.py)
            service.cli_run(args(action), io.StringIO(), system=SimpleNamespace(platform=lambda: "win32"))
        assert str(caught.value) == "raqib service %s: Linux only (systemd); this is win32" % action
    for kw, words in (({"no_start": True}, "raqib service: --no-start is install's only"),
                      ({"purge": True}, "raqib service: --purge is remove's only")):
        with pytest.raises(cli.UsageError) as caught:
            cli.cmd_service(args(**kw), io.StringIO())
        assert str(caught.value) == words
    manager, out = Manager(), io.StringIO()
    assert winmanager.cli_run(args(), out, system=manager) == 0 and out.getvalue().endswith("RESULT: ACTIVE\n")
    with pytest.raises(winmanager.Refused):
        winmanager.cli_run(args("run"), io.StringIO(), system=Manager())


def test_e4_the_help_and_the_docstrings_say_both_and_where_wincode_is_imported():
    helps = " ".join(cli._parser().format_help().split())
    sub = [a for a in cli._parser()._actions if getattr(a, "choices", None) and "service" in a.choices][0]
    said = " ".join(sub.choices["service"].format_help().split())
    assert "say its status" in helps or "say its status" in said
    for words in ("status (no rights): on Linux installed, enabled, active", "on Windows, by the service manager's"
                  " own calls, the service RaqibWatch", "3 not installed, not Raqib's or not known; ADR-0013"
                  " Amendment V"):
        assert words in said, words
    doc = " ".join(cli.cmd_service.__doc__.split())
    assert "raqib/wincode.py, imported here and in raqib/winservice.py's System.own_check" in doc and "U-4" in doc
    assert "raqib/winmanager.py, imported here and in raqib/wininstall.py's functions" in doc   # M12.4c2b2b
    assert "import wincode" in ast.unparse(next(n for n in ast.walk(ast.parse((ROOT / "raqib" / "winservice.py")
                                                                              .read_text(encoding="ascii")))
                                                if isinstance(n, ast.FunctionDef) and n.name == "own_check"))
    assert "On Windows status asks the system's service manager, with no rights" in " ".join(cli.__doc__.split())


# --- M12.4c2b2c (ADR-0013 Amendment Z): the start-again settings the install makes ----------------------------------

def test_z2_the_numbers_as_installed_are_the_installs_own_and_its_structures_the_same():
    from raqib import wininstall
    assert (winmanager.AUTO_START, winmanager.RESTART, winmanager.DELAYS, winmanager.RESET_PERIOD) == (
        wininstall.AUTO_START, wininstall.RESTART, wininstall.DELAYS, wininstall.RESET_PERIOD) == (
        2, 1, (5000, 30000, 300000), 3600)
    assert (winmanager.CONFIG_FAILURE_ACTIONS, winmanager.CONFIG_FAILURE_FLAG) == (
        wininstall.CONFIG_FAILURE_ACTIONS, wininstall.CONFIG_FAILURE_FLAG)
    assert FAILURE["actions"] == [(wininstall.RESTART, d) for d in wininstall.DELAYS]   # the stand-in's default
    assert FAILURE["reset"] == wininstall.RESET_PERIOD and Manager().failure == FAILURE
    theirs = ast.parse((ROOT / "raqib" / "wininstall.py").read_text(encoding="ascii"))
    theirs = {n.name: ast.unparse(n) for n in ast.walk(theirs) if isinstance(n, ast.ClassDef)}
    ours = {n.name: ast.unparse(n) for n in ast.walk(tree_of()[2]["_win"]) if isinstance(n, ast.ClassDef)}
    for name in ("SC_ACTION", "SERVICE_FAILURE_ACTIONSW", "SERVICE_FAILURE_ACTIONS_FLAG"):   # what it writes, read
        assert ours[name] == theirs[name], name   # ZA-4: the whole class, not its first statement alone
    for tree in (tree_of()[2]["_win"], ast.parse((ROOT / "raqib" / "wininstall.py").read_text(encoding="ascii"))):
        for n in ast.walk(tree):   # and a structure is its fields and nothing set beside them (a packing, say)
            if isinstance(n, ast.ClassDef) and n.bases and "Structure" in ast.unparse(n.bases[0]):
                assert len(n.body) == 1 and ast.unparse(n.body[0]).startswith("_fields_ = "), n.name


def not_as_installed(lines):
    return [x[len("  NOT AS INSTALLED: "):] for x in lines if x.startswith("  NOT AS INSTALLED: ")]


INSTALLS = "start it again after 5 s, start it again after 30 s, start it again after 300 s"


@pytest.mark.parametrize("kw, said, differs", [
    ({"making": {"start": 3}}, "  start: 3, on demand", "start: 3, on demand; the install writes 2, automatic"),
    ({"making": {"start": 4}}, "  start: 4, disabled", "start: 4, disabled; the install writes 2, automatic"),
    ({"making": {"start": None}}, "  start: None, a start this command has no word for",
     "start: None, a start this command has no word for; the install writes 2, automatic"),
    ({"delayed": 1}, "  delayed start: 1, delayed",
     "delayed start: 1, delayed; the install leaves it 0, not delayed"),
    ({"delayed": "x"}, "  delayed start: x, not a number",
     "delayed start: x, not a number; the install leaves it 0, not delayed"),
    ({"failure": {"actions": []}}, "  after an end that was no Stop: none; the count forgotten after 3600 s",
     "after an end that was no Stop: none; the install writes " + INSTALLS),
    ({"failure": {"actions": [(1, 5000), (1, 30000)]}}, "  after an end that was no Stop: start it again after 5 s,"
     " start it again after 30 s; the count forgotten after 3600 s", "after an end that was no Stop: start it again"
     " after 5 s, start it again after 30 s; the install writes " + INSTALLS),
    ({"failure": {"actions": FAILURE["actions"] + [(1, 300000)]}}, "start it again after 300 s, start it again after"
     " 300 s; the count", "after an end that was no Stop: %s, start it again after 300 s; the install writes %s" % (
         INSTALLS, INSTALLS)),
    ({"failure": {"actions": [(1, 5000), (1, 30000), (1, 300001)]}}, "start it again after 300.001 s;",
     "after an end that was no Stop: start it again after 5 s, start it again after 30 s, start it again after"
     " 300.001 s; the install writes " + INSTALLS),
    ({"failure": {"actions": [(0, 5000), (1, 30000), (1, 300000)]}}, ": nothing after 5 s, start it again after 30 s",
     "after an end that was no Stop: nothing after 5 s, start it again after 30 s, start it again after 300 s; the"
     " install writes " + INSTALLS),
    ({"failure": {"actions": [(2, 60000)]}}, ": restart the machine after 60 s;",
     "after an end that was no Stop: restart the machine after 60 s; the install writes " + INSTALLS),
    ({"failure": {"actions": [(3, 1500)]}}, ": run a command after 1.500 s;",
     "after an end that was no Stop: run a command after 1.500 s; the install writes " + INSTALLS),
    ({"failure": {"actions": [(7, 5000), (1, 30000), (1, 300000)]}}, ": the kind 7, which this command has no word"
     " for, after 5 s, start it again after 30 s", "after an end that was no Stop: the kind 7, which this command has"
     " no word for, after 5 s, start it again after 30 s, start it again after 300 s; the install writes "
     + INSTALLS),
    ({"failure": {"reset": 60}}, "; the count forgotten after 60 s", "the count forgotten after 60 s; the install"
     " writes 3600 s"),
    ({"failure": {"reset": 0}}, "; the count forgotten after 0 s", "the count forgotten after 0 s; the install writes"
     " 3600 s"),
    ({"failure": {"reset": 0xFFFFFFFF}}, "; the count never forgotten (0xFFFFFFFF, INFINITE)", "the count never"
     " forgotten (0xFFFFFFFF, INFINITE); the install writes 3600 s"),
    ({"flag": 0}, "  the failure flag: 0, not set (an end the service itself reports with an error is not such an"
     " end)", "the failure flag: 0, not set; the install writes 1, set"),
    ({"flag": None}, "  the failure flag: None, not a number", "the failure flag: None, not a number; the install"
     " writes 1, set"),
])
def test_z2_each_difference_alone_said_by_what_was_read_and_what_the_install_writes_running_and_stopped(
        kw, said, differs):
    for state, result in ((None, "RESULT: ACTIVE, NOT AS INSTALLED"),
                          ({"state": 1, "exit": 0, "pid": 0}, "RESULT: INSTALLED, NOT ACTIVE, NOT AS INSTALLED")):
        code, lines = asked(Manager(state=state, **kw))
        assert (code, lines[-1]) == (1, result), lines
        assert [x for x in lines if said in x], (said, lines)
        assert not_as_installed(lines) == [differs], lines
        assert "ACTIVE says the service" not in " ".join(lines)
        account = lines.index("  account: LocalSystem (the system's)")   # Z-1: after the account's, before the state
        assert [x.split(":")[0] for x in lines[account + 1:account + 5]] == [
            "  after an end that was no Stop", "  the failure flag", "  delayed start", "  state"]


def test_z2_every_difference_together_in_the_order_of_the_lines_running_and_stopped():
    odd = {"making": {"start": 3}, "failure": {"actions": [(3, 1000)], "reset": 86400}, "flag": 0, "delayed": 1}
    for state, result in ((None, "RESULT: ACTIVE, NOT AS INSTALLED"),
                          ({"state": 1, "exit": 1077}, "RESULT: INSTALLED, NOT ACTIVE, NOT AS INSTALLED")):
        code, lines = asked(Manager(state=state, **odd))
        assert (code, lines[-1]) == (1, result)
        assert lines[6:10] == ["  start: 3, on demand", "  account: LocalSystem (the system's)",
                               "  after an end that was no Stop: run a command after 1 s; the count forgotten after"
                               " 86400 s",
                               "  the failure flag: 0, not set (an end the service itself reports with an error is"
                               " not such an end)"]
        assert lines[10] == "  delayed start: 1, delayed" and lines[11].startswith("  state: ")
        assert not_as_installed(lines) == [
            "start: 3, on demand; the install writes 2, automatic",
            "after an end that was no Stop: run a command after 1 s; the install writes " + INSTALLS,
            "the count forgotten after 86400 s; the install writes 3600 s",
            "the failure flag: 0, not set; the install writes 1, set",
            "delayed start: 1, delayed; the install leaves it 0, not delayed"]
    # with the earlier differences too, those first and in their order
    code, lines = asked(Manager(**dict(odd, making={"start": 4, "type": 0x20, "account": None})))
    assert [x.split(";")[0].split(" (")[0] for x in not_as_installed(lines)] == [
        "the type is not a process of its own", "start: 4, disabled", "the account is not the system's",
        "after an end that was no Stop: run a command after 1 s", "the count forgotten after 86400 s",
        "the failure flag: 0, not set", "delayed start: 1, delayed"]


def test_z2_a_service_the_install_made_is_still_active_and_a_text_kept_beside_its_actions_is_said_and_judged():
    code, lines = asked(Manager())
    assert (code, lines[-1]) == (0, "RESULT: ACTIVE") and lines[8:11] == AS_MADE and not not_as_installed(lines)
    texts = {"message": "the host restarts now", "command": "C:\\x\\after.cmd \u0430\x00" + "y" * 400}
    code, lines = asked(Manager(failure=texts))
    # ZA-2: the install writes no text there, so one that is there is a difference, each said by its own line
    assert (code, lines[-1]) == (1, "RESULT: ACTIVE, NOT AS INSTALLED") and lines[8] == AS_MADE[0]
    assert not_as_installed(lines) == [
        "the message kept for a restart of the machine is there; the install writes none",
        "the command kept to run is there; the install writes none"]
    for key in ("message", "command"):   # each alone
        alone = asked(Manager(failure={key: "x"}))[1]
        assert len(not_as_installed(alone)) == 1 and "is there; the install writes none" in alone[-2]
    assert lines[9:11] == ["  the message kept for a restart of the machine: \"the host restarts now\" (another"
                           " party's text)",
                           "  the command kept to run: \"C:\\x\\after.cmd \\u0430?%s...\" (another party's text)"
                           % ("y" * (winmanager.SAID_MAX - 22))]
    assert lines[11:13] == AS_MADE[1:]
    for empty in (None, ""):   # said only where it is there
        code, lines = asked(Manager(failure={"message": empty, "command": empty}))
        assert lines[8:11] == AS_MADE and "kept" not in " ".join(lines)


def test_z2_a_service_without_the_mark_with_odd_settings_has_them_said_and_nothing_judged():
    odd = {"making": {"start": 3}, "failure": {"actions": [(2, 0)], "reset": 1, "command": "x"}, "flag": 0,
           "delayed": 1}
    for text in (None, "Another program's service"):
        code, lines = asked(Manager(description=text, **odd))
        assert (code, lines[-1]) == (3, "RESULT: NOT INSTALLED BY RAQIB, YET A SERVICE OF THE NAME IS RUNNING")
        assert lines[8:12] == ["  after an end that was no Stop: restart the machine after 0 s; the count forgotten"
                               " after 1 s",
                               "  the command kept to run: \"x\" (another party's text)",
                               "  the failure flag: 0, not set (an end the service itself reports with an error is"
                               " not such an end)",
                               "  delayed start: 1, delayed"]
        assert not [x for x in lines if "NOT AS INSTALLED" in x or "the install writes" in x]


def test_z1_array_at_bounds_the_count_first_and_places_the_array_inside_the_bytes_read():
    at = winmanager.array_at
    assert at(3, 1040, 1000, 64, 8) == (40, None) and at(0, None, 1000, 40, 8) == (0, None)
    assert at(0, 5, 1000, 40, 8) == (0, None)   # a count of 0 reads nothing, wherever it points
    assert at(64, 1000, 1000, 512, 8) == (0, None)
    for count in (65, 1 << 31, -1):   # past the bound: said, never read
        assert at(count, 1040, 1000, 1 << 20, 8) == (None, "%s actions, not from 0 to 64 (the bound)" % count)
    for count in (None, True, "3"):   # and one that is no number is said as that, not as a number inside the bound
        assert at(count, 1040, 1000, 1 << 20, 8) == (None, "a count of actions that is not a number (%s)" % count)
    assert at(3, None, 1000, 64, 8) == (None, "3 actions and no array (NULL)")
    assert at(3, 0, 1000, 64, 8) == (None, "3 actions and no array (NULL)")
    for where in (999, 1041, 2000, 0x10):
        assert at(3, where, 1000, 64, 8) == (None, "3 actions whose array does not lie inside the 64 bytes read")
    assert at(2, 1000, 1000, 8, 8, bound=1) == (None, "2 actions, not from 0 to 1 (the bound)")


def test_z1_the_real_objects_own_logic_reads_levels_2_4_and_3_against_the_made_up_library(monkeypatch):
    import ctypes
    code, lines, library = real_with(monkeypatch)
    assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE") and not not_as_installed(lines), lines
    account = lines.index("  account: LocalSystem (the system's)")
    assert lines[account + 1:account + 4] == AS_MADE   # the array read out of the same bytes, after the structure
    assert library.levels == [(1, "first"), (1, "second"), (2, "first"), (2, "second"), (4, "first"), (4, "second"),
                              (3, "first"), (3, "second")] and library.closed == [12, 11]
    api = library.real._api   # the sizes measured (Amendment Z): 64 bytes for three actions, 4 and 4, on 64 bits -
    three = ctypes.sizeof(api.failure) + 3 * ctypes.sizeof(api.action)   # held on Windows alone (the gate's jobs):
    if sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8:  # off it a DWORD is not 4 bytes
        assert three == 64 and ctypes.sizeof(api.action) == 8
    if sys.platform == "win32":
        assert ctypes.sizeof(api.flag) == ctypes.sizeof(api.delayed) == 4
    # a NULL array with a count of 0: none, and not as installed
    code, lines, library = real_with(monkeypatch, failure={"actions": []})
    assert (code, lines[-1]) == (1, "RESULT: INSTALLED, NOT ACTIVE, NOT AS INSTALLED")
    assert "  after an end that was no Stop: none; the count forgotten after 3600 s" in lines
    # the texts kept beside, the flag and the delayed start as read, each difference said
    code, lines, library = real_with(monkeypatch, failure={"message": "m", "command": "c", "reset": 60}, flag=0,
                                     delayed=1)
    assert "  the message kept for a restart of the machine: \"m\" (another party's text)" in lines
    assert "  the command kept to run: \"c\" (another party's text)" in lines
    assert not_as_installed(lines) == ["the count forgotten after 60 s; the install writes 3600 s",
                                       "the message kept for a restart of the machine is there; the install writes"
                                       " none", "the command kept to run is there; the install writes none",
                                       "the failure flag: 0, not set; the install writes 1, set",
                                       "delayed start: 1, delayed; the install leaves it 0, not delayed"]
    # a count over the bound, a count with no array, an array outside the bytes read: NOT KNOWN, the handles closed
    for failure, why in (({"count": 65}, "65 actions, not from 0 to 64 (the bound)"),
                         ({"count": 1 << 31}, "2147483648 actions, not from 0 to 64 (the bound)"),
                         ({"where": "null"}, "3 actions and no array (NULL)"),
                         ({"where": "outside"},
                          "3 actions whose array does not lie inside the %d bytes read" % three)):
        code, lines, library = real_with(monkeypatch, failure=failure)
        assert (code, lines[-1]) == (3, "RESULT: NOT KNOWN") and library.closed == [12, 11], lines
        assert lines[-2].startswith("  its failure actions: QueryServiceConfig2W (level 2) failed: " + why), lines
        assert "  state: " not in " ".join(lines)
    # each level's first ask answering another number than 122: its call and number said, nothing read past it
    for level, words in ((2, "failure actions"), (4, "failure flag"), (3, "delayed start")):
        code, lines, library = real_with(monkeypatch, fails={level: 5})
        assert (code, lines[-2:]) == (3, ["  its %s: QueryServiceConfig2W (level %d) failed: error 5 (access denied:"
                                          " the caller may not ask this of the service manager)" % (words, level),
                                          "RESULT: NOT KNOWN"]) and library.closed == [12, 11]
        assert library.levels[-1] == (level, "first")
