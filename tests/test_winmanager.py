"""M12.4c2b2a (ADR-0013 Amendment V, V-2 to V-5): `raqib service status` on Windows, by the system's own calls and
with no rights (raqib/winmanager.py).

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
CALLS = ("connect", "open", "description", "making", "state")


class Manager:
    """A made-up service manager: it answers each call winmanager.status makes, as the real object's methods do -
    (what was read, 0) or (None, an error) - gives each handle a number of its own and records every call in order.
    fail: {call: error}; raises: the calls that raise. It has no call that writes anything."""

    def __init__(self, platform="win32", there=True, description=MARKED, making=None, state=None, fail=None,
                 raises=()):
        self.os, self.there, self.text = platform, there, description
        self.made, self.got = dict(MAKING, **(making or {})), dict(STATE, **(state or {}))
        self.fail, self.raises = dict(fail or {}), set(raises)
        self.opened, self.closed, self.log, self.next = [], [], [], 100

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
        assert handle in self.opened and handle not in self.closed, handle

    def platform(self):
        self.log.append("platform")
        return self.os

    def connect(self):
        value, error = self._answer("connect", None)
        return (self._give(), 0) if "connect" not in self.fail else (None, error)

    def open(self, manager, name):
        self._held(manager)
        assert name == winservice.SERVICE_NAME and manager == self.opened[0]
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
            "  account: LocalSystem (the system's)",
            "  state: 4, running (its process's id: 4321)",
            "  ACTIVE says the service runs, not that the watch writes its record",
            "RESULT: ACTIVE"]
        assert manager.log == ["platform", "connect", "open", "description", "making", "state", "close", "close"]


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
        assert "  exit: 0, stopped with no failure" in lines
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
            assert got[1:] == ["  the whole refusal is in its text file: service.txt in the place (Raqib under"
                               " ProgramData, the system's and the administrators' alone)"]
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
    assert code == 1 and lines[3:9] == [
        "  command: x (as the service manager holds it)",
        "  its form: not one of the two Raqib's install writes (a quoted path, then `service run`; a quoted path,"
        " then `-I -m raqib service run`)",
        "  type: 0x20, a process shared with other services",
        "  start: 9, a start this command has no word for",
        "  account: LocalSystem2",
        "  state: 4, running (its process's id: 4321)"]
    assert [x for x in lines if "NOT AS INSTALLED:" in x] == [
        "  NOT AS INSTALLED: the command is not one of the two forms Raqib's install writes",
        "  NOT AS INSTALLED: the type is not a process of its own (0x10)",
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
    assert (code, lines[-2:]) == (3, ["  what the service manager answered cannot be read here (AttributeError)",
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
                            "close"}
    declared = {}
    for node in ast.walk(methods["_win"]):
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]).startswith("adv."):
            _, call, kind = ast.unparse(node.targets[0]).split(".")
            declared.setdefault(call, {})[kind] = ast.unparse(node.value)
    assert {k: (v["restype"], v["argtypes"]) for k, v in declared.items()} == DECLARED
    loads = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call) and "WinDLL" in ast.unparse(n.func)]
    assert loads == ["ctypes.WinDLL('advapi32', use_last_error=True)"]
    used = {}
    for name, fn in methods.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and ast.unparse(node.func).startswith("api.adv."):
                used.setdefault(ast.unparse(node.func).split(".")[2], set()).add(name)
    assert used == {"OpenSCManagerW": {"connect"}, "OpenServiceW": {"open"}, "QueryServiceStatusEx": {"state"},
                    "QueryServiceConfigW": {"making"}, "QueryServiceConfig2W": {"description"},
                    "CloseServiceHandle": {"close"}}
    calls = {ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "api.adv.OpenSCManagerW(None, None, MANAGER_RIGHTS)" in calls and winmanager.MANAGER_RIGHTS == 0x1
    assert "api.adv.OpenServiceW(manager, name, SERVICE_RIGHTS)" in calls and winmanager.SERVICE_RIGHTS == 0x5
    assert "api.adv.QueryServiceConfigW(service, None, 0, api.ctypes.byref(needed))" in calls   # the first ask
    assert "api.adv.QueryServiceConfig2W(service, CONFIG_DESCRIPTION, None, 0, api.ctypes.byref(needed))" in calls
    assert winmanager.CONFIG_DESCRIPTION == 1 and winmanager.STATUS_PROCESS_INFO == 0 and winmanager.NO_ROOM == 122
    for name in ("connect", "open", "state", "making", "description", "close"):   # each: errors read, never raised
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
    assert where == [("cli.py", "cmd_service", "from raqib import winmanager")]


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: on Windows the real object asks the manager")
def test_e1_the_real_object_off_windows_never_raises_and_says_what_failed():
    real = winmanager.System()
    assert real.platform() == sys.platform
    for name, args in (("connect", ()), ("open", (1, "RaqibWatch")), ("state", (1,)), ("making", (1,)),
                       ("description", (1,)), ("close", (1,))):
        value, error = getattr(real, name)(*args)
        assert value is None and isinstance(error, str) and error.startswith("an exception, "), (name, error)
    out = io.StringIO()
    assert winmanager.status(real, out) == 2 and out.getvalue().startswith("raqib service status: Windows only here")


# --- E4: the command ---------------------------------------------------------------------------------------------

def args(action="status", **kw):
    return SimpleNamespace(action=action, no_start=kw.get("no_start", False), purge=kw.get("purge", False))


def test_e4_status_on_windows_goes_to_the_new_module_on_linux_to_service_as_before(monkeypatch):
    got = []
    monkeypatch.setattr(winmanager, "cli_run", lambda a, out: got.append(("win", a.action)) or 7)
    monkeypatch.setattr(service, "cli_run", lambda a, out: got.append(("linux", a.action)) or 5)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert cli.cmd_service(args(), io.StringIO()) == 7
    assert cli.cmd_service(args("install"), io.StringIO()) == 5
    assert cli.cmd_service(args("remove"), io.StringIO()) == 5
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert cli.cmd_service(args(), io.StringIO()) == 5
    assert got == [("win", "status"), ("linux", "install"), ("linux", "remove"), ("linux", "status")]


def test_e4_on_windows_install_and_remove_answer_as_today_and_statuss_flags_are_refused(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    for action in ("install", "remove"):
        with pytest.raises(cli.UsageError) as caught:
            cli.cmd_service(args(action), io.StringIO())
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
    assert "raqib/winmanager.py, imported here only" in doc
    assert "import wincode" in ast.unparse(next(n for n in ast.walk(ast.parse((ROOT / "raqib" / "winservice.py")
                                                                              .read_text(encoding="ascii")))
                                                if isinstance(n, ast.FunctionDef) and n.name == "own_check"))
    assert "On Windows status asks the system's service manager, with no rights" in " ".join(cli.__doc__.split())
