"""M12.4c2b2b (ADR-0013 Amendment X, X-2 to X-8): `raqib service install | remove` on Windows, by the system's own
calls (raqib/wininstall.py).

Every call goes to a made-up service manager (Manager, in place of both wininstall.System and the reader,
winmanager.System: one object, so one log holds every call in order), a made-up check's object (Code) and a made-up
reader of the place (Place): no test here needs Windows or a service manager, and none makes, starts, stops or removes
a real service on any machine - the real objects are asked only behind a made-up advapi32 (Library), or off Windows,
where their library cannot be loaded. The waits run by the Manager's clock alone: the real clock and sleep are made to
fail in every test that waits.
"""
import ast
import io
import ntpath
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, host, service, wincode, wininstall, winmanager, winservice  # noqa: E402

SOURCE = (ROOT / "raqib" / "wininstall.py").read_text(encoding="ascii")
PROGRAM = "C:\\Program Files\\Raqib\\raqib.exe"
PYTHON = "C:\\Program Files\\Raqib\\Python311\\python.exe"
ALONE = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
OPEN = "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BU)"
CLOSED = "O:BA" + winservice.CLOSED_AS_MADE
MAKERS = ("create", "describe", "failure_actions", "failure_flag", "start", "stop", "delete")
BASE = {"type": 0x10, "state": 1, "exit": 1077, "own": 0, "pid": 0}
RUNS = {"state": 4, "exit": 0, "pid": 4321}
REFUSED_15 = {"state": 1, "exit": winservice.SERVICE_SPECIFIC, "own": winservice.EXIT_NOT_ALONE}
PLACE = "C:\\ProgramData\\Raqib"
DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {k + d for k in ("COM", "LPT")
                                                                     for d in "0123456789\u00b9\u00b2\u00b3"}


def rewritten(part):
    """ZF-1, the tests' own judgement of one part of a path: a form Windows makes another name of, or no name."""
    return (part in ("", ".", "..") or [c for c in part if c in "/:\0"] != [] or part[-1] in ". "
            or part.split(".")[0].rstrip(" ").upper() in DEVICE_NAMES)

# M12.4c2b4: a record of the shape ZE measured after Raqib's remove - 3 folders and 11 files, no reparse point
HOST = PLACE + "\\.raqib\\host"
TREE = dict([(PLACE + "\\.raqib", 0x10), (HOST, 0x10), (HOST + "\\cases", 0x10)]
            + [(HOST + "\\" + n, 0x20) for n in ("events.jsonl", "events.jsonl.1", "seen.json", "state.json")]
            + [(HOST + "\\cases\\case-%d.json" % i, 0x20) for i in range(5)]
            + [(PLACE + "\\.raqib\\host.lock", 0x20), (PLACE + "\\watch.log", 0x20)])


class Manager:
    """A made-up service manager for both objects: each call answers as the real methods do - (what was done or
    read, 0) or (None, an error) - gives each handle a number of its own and records every call in order. there: a
    service of the name before; text: its description; fail: {call: error, or a list of errors, one per call};
    states: the states read one after another once it was started (the last stays); stops: the Stop's answers in
    turn; lingers: the name still there after DeleteService. The clock moves only by its own sleep. M12.4c2b4 (ZE-2):
    tree, the record made up - {each path under the place: its attributes} - answered by listed, remove_file and
    remove_folder; refuse: {a path: the error any call naming it answers}; every path handed is kept in `paths`, and
    one outside the place, a link entered or removed, or a folder removed with names in it is a breach."""

    def __init__(self, platform="win32", there=False, text=None, fail=None, raises=(), states=None, stops=None,
                 lingers=False, before=None, tree=None, refuse=None):
        self.tree, self.refuse, self.paths, self.removed = dict(tree or {}), dict(refuse or {}), [], []
        self.place_gone = False
        self.os, self.fail, self.raises, self.lingers = platform, dict(fail or {}), set(raises), lingers
        self.states = [dict(BASE, **s) for s in (states or [RUNS])]
        self.stops = list(stops or [0])
        self.service = ({"description": text, "command": '"%s" service run' % PROGRAM, "deleted": False}
                        if there else None)
        self.now = dict(BASE, **(before or {})) if there else dict(BASE)
        self.opened, self.closed, self.log, self.next, self.clock_at = [], [], [], 100, 1000.0
        self.breaches, self.services = [], []   # services: the handles given for the service itself

    def _answer(self, call, value):
        self.log.append(call)
        if call in self.raises:
            raise RuntimeError("made up")
        if call in self.fail:
            error = self.fail[call]
            if isinstance(error, list):
                error = error.pop(0) if error else 0
            if error:
                return None, error
        return value, 0

    def _give(self):
        self.next += 1
        self.opened.append(self.next)
        return self.next

    def _held(self, handle, service=False):
        if handle not in self.opened or handle in self.closed:
            self.breaches.append(("a handle not held", handle))
        if service and handle not in self.services:   # Y-5: a call on the service given another handle
            self.breaches.append(("not the service's handle", handle))

    def _there(self):
        return self.service is not None and (not self.service["deleted"] or self.lingers)

    def platform(self):
        self.log.append("platform")
        return self.os

    def make_manager(self):
        value, error = self._answer("make_manager", None)
        return (self._give(), 0) if not error else (None, error)

    def connect(self):
        value, error = self._answer("connect", None)
        return (self._give(), 0) if not error else (None, error)

    def _open(self, call, manager, name):
        self._held(manager)
        if name != winservice.SERVICE_NAME:
            self.breaches.append(("another name", name))
        value, error = self._answer(call, None)
        if error:
            return None, error
        if not self._there():
            return None, 1060
        self.services.append(self._give())
        return self.services[-1], 0

    def open(self, manager, name):            # the reader's (0x5)
        return self._open("open", manager, name)

    def open_to_remove(self, manager, name):  # wininstall's (0x10025)
        return self._open("open_to_remove", manager, name)

    def create(self, manager, name, command):
        self._held(manager)
        value, error = self._answer("create", None)
        if error:
            return None, error
        self.service = {"description": None, "command": command, "deleted": False, "name": name}
        self.services.append(self._give())
        return self.services[-1], 0

    def describe(self, handle, text):
        self._held(handle, service=True)
        value, error = self._answer("describe", True)
        if not error:
            self.service["description"] = text
        return value, error

    def failure_actions(self, handle):
        self._held(handle, service=True)
        return self._answer("failure_actions", True)

    def failure_flag(self, handle):
        self._held(handle, service=True)
        return self._answer("failure_flag", True)

    def start(self, handle):
        self._held(handle, service=True)
        value, error = self._answer("start", True)
        if not error:
            self.now = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return value, error

    def state(self, handle):
        self._held(handle, service=True)
        value, error = self._answer("state", None)
        if error:
            return None, error
        got = dict(self.now)
        if self.states:   # the next ask reads the next state; the last stays
            self.now = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return got, 0

    def stop(self, handle):
        self._held(handle, service=True)
        self.log.append("stop")
        if "stop" in self.raises:
            raise RuntimeError("made up")
        error = self.stops.pop(0) if self.stops else 0
        if error:
            return None, error
        self.states = [dict(BASE, state=1, exit=0)]
        self.now = dict(BASE, state=3, exit=0)
        return {"state": 3}, 0

    def delete(self, handle):
        self._held(handle, service=True)
        value, error = self._answer("delete", True)
        if not error:
            self.service["deleted"] = True
        return value, error

    def close(self, handle):
        self._held(handle)
        self.closed.append(handle)
        return self._answer("close", True)

    def sleep(self, seconds):
        self.clock_at += seconds
        return self._answer("sleep", True)

    def clock(self):
        return self._answer("clock", self.clock_at)

    def description(self, handle):            # the reader's
        self._held(handle, service=True)
        return self._answer("description", self.service["description"] if self.service else None)

    def making(self, handle):                 # the reader's
        self._held(handle)
        return self._answer("making", {"type": 0x10, "start": 2, "command": self.service["command"],
                                       "account": "LocalSystem"})

    # M12.4c2b2c (ADR-0013 Z-1): the reader's levels 2, 4 and 3, answered as the install makes them (X-5, X-9); not
    # kept in the log, which holds the install's calls and the reader's of 0.16.0 in the tests here
    def actions(self, handle):                # the reader's
        self._held(handle, service=True)
        return {"reset": wininstall.RESET_PERIOD, "message": None, "command": None,
                "actions": [(wininstall.RESTART, delay) for delay in wininstall.DELAYS]}, 0

    def flag(self, handle):                   # the reader's
        self._held(handle, service=True)
        return 1, 0

    def delayed(self, handle):                # the reader's
        self._held(handle, service=True)
        return 0, 0

    # M12.4c2b4 (ZE-2): the record's calls, answered from the made-up tree
    def _path(self, call, path):
        self.paths.append(path)
        parts = path[len(PLACE) + 1:].split("\\") if path.startswith(PLACE + "\\") else []
        if path != PLACE and (not parts or [p for p in parts if rewritten(p)]):   # ZF-1: every part, not the prefix
            self.breaches.append(("outside the place, or a name the system rewrites", call, path))
        elif path != PLACE and path not in self.tree:
            self.breaches.append(("a name not listed", call, path))
        if path != PLACE and self.tree.get(path, 0) & winservice.ATTRIBUTE_REPARSE:
            self.breaches.append(("a link entered or removed", call, path))
        value, error = self._answer(call, True)
        refused = self.refuse.get(path, 0)
        if isinstance(refused, list):   # in turn, then let go
            refused = refused.pop(0) if refused else 0
        return error or refused

    def listed(self, folder):
        error = self._path("listed", folder)
        if error:
            return None, error
        return [(ntpath.basename(p), a) for p, a in sorted(self.tree.items()) if ntpath.dirname(p) == folder], 0

    def remove_file(self, path):
        error = self._path("remove_file", path)
        if error:
            return None, error
        del self.tree[path]
        self.removed.append(path)
        return True, 0

    def remove_folder(self, path):
        error = self._path("remove_folder", path)
        if error:
            return None, error
        if [p for p in self.tree if p.startswith(path + "\\")]:
            self.breaches.append(("a folder removed with names in it", path))
            return None, 145
        self.tree.pop(path, None)
        self.removed.append(path)
        self.place_gone = self.place_gone or path == PLACE
        return True, 0


class Code:
    """A made-up check's object (wincode.System's calls), packed: the program's folder and its modules' folder, each
    the system's alone unless `program_open`; or a plain interpreter (packed=False)."""

    def __init__(self, program=PROGRAM, packed=True, program_open=False, isolated=True, no_site=False):
        self.path, self.is_packed, self.program_open = program, packed, program_open
        self.is_isolated, self.has_no_site = isolated, no_site
        self.root = ntpath.dirname(program)

    def platform(self):
        return "win32"

    def packed(self):
        return self.is_packed

    def program(self):
        return self.path

    def modules(self):
        return ntpath.join(self.root, "_internal")

    def version(self):
        return (3, 12)

    def read(self, path):
        if path == self.path:
            return 0x20, OPEN if self.program_open else ALONE
        return 0x10, ALONE

    def drive(self, root):
        return 3, "\\Device\\HarddiskVolume3"

    def listdir(self, path):
        return [ntpath.basename(self.path), "_internal"] if path == self.root else []

    def isolated(self):
        return self.is_isolated

    def no_site(self):
        return self.has_no_site


class Place:
    """A made-up reader of the place (winservice.System's getenv and read_place): `reading` (attributes, text), or
    the error number read_place raises (2: not there). It counts any making asked (prepare's make_closed)."""

    def __init__(self, reading=None, error=2, root="C:\\ProgramData", holds=None, gone_with=None):
        self.reading, self.error, self.root, self.read, self.made = reading, error, root, [], []
        self.holds, self.gone_with, self.held_asked = holds, gone_with, []   # M12.4c2b4 (ZF-2, ZF-5)

    def getenv(self, name):
        return self.root if name == "ProgramData" else None

    def read_place(self, path):
        self.read.append(path)
        if self.reading is None or (self.gone_with is not None and self.gone_with.place_gone):
            raise OSError(self.error if self.reading is None else 2, "made up")
        return self.reading

    def held(self, place):   # ZF-2: winservice.System.held, the runner's own call; not held unless `holds` says
        self.held_asked.append(place)
        if isinstance(self.holds, BaseException):
            raise self.holds
        return {"held": "none", "why": "no state"} if self.holds is None else self.holds

    def make_closed(self, path, sddl):   # for winservice.prepare in the tie, never asked by the install
        self.made.append(path)
        return winservice.ALREADY_EXISTS


@pytest.fixture(autouse=True)
def no_real_clock(monkeypatch):
    def boom(*a):
        raise AssertionError("the real clock or sleep was asked")
    monkeypatch.setattr(wininstall.time, "sleep", boom)
    monkeypatch.setattr(wininstall.time, "monotonic", boom)


def held_right(manager):
    assert sorted(manager.closed) == sorted(manager.opened), (manager.opened, manager.closed)   # every one closed
    assert len(set(manager.closed)) == len(manager.closed)   # each once
    assert manager.breaches == [], manager.breaches


def lines_right(code, lines, head):
    if code != 2:
        assert lines[0] == head and lines[-1].startswith("RESULT: ")
        assert sum(1 for x in lines if x.startswith("RESULT:")) == 1
        assert all(x.startswith("  ") for x in lines[1:-1]), lines
    assert all(x.isascii() and x.isprintable() and len(x) < 2000 for x in lines)


def install(manager=None, code=None, place=None, start=True):
    manager = manager or Manager()
    out = io.StringIO()
    got = wininstall.install(manager, out, start=start, code=code or Code(), place=place or Place(), reader=manager)
    lines = out.getvalue().splitlines()
    held_right(manager)
    lines_right(got, lines, "raqib service install")
    return got, lines, manager


def remove(manager, purge=False, place=None):
    out = io.StringIO()   # the system, the reader and the place: each a stand-in, always (never the real objects)
    got = wininstall.remove(manager, out, reader=manager, purge=purge, place=place or Place())
    lines = out.getvalue().splitlines()
    held_right(manager)
    lines_right(got, lines, "raqib service remove")
    return got, lines


def made_nothing(manager):
    assert not [c for c in manager.log if c in MAKERS], manager.log


# --- E2, E3: install ----------------------------------------------------------------------------------------------

def test_e2_installed_and_active_each_step_one_line_in_order_and_statuss_own_lines_indented():
    code, lines, manager = install()
    assert code == 0 and lines[-1] == "RESULT: installed and started: raqib service status answers ACTIVE"
    assert lines[1] == "  Windows: the service manager's own calls (ADR-0013 X-2)"
    assert lines[2].startswith("  raqib service check: the code a service would run is the system's alone: checked ")
    assert lines[3] == ("  the place: C:\\ProgramData\\Raqib is not there: the runner makes it at its first start, as"
                        " the system, closed (ADR-0013 X-8); the install makes nothing there")
    assert lines[4] == "  no service named RaqibWatch yet (OpenServiceW: error 1060)"
    assert lines[5] == ('  its command: "%s" service run (a packed program\'s, by the path the check judged)'
                        % PROGRAM)
    assert lines[6] == ("  made: the service RaqibWatch, shown as Raqib watch, a process of its own (0x10), automatic"
                        " start (2), error control 1, the system's account (none named)")
    assert lines[7:10] == [
        "  set: its description, Raqib's mark first (ChangeServiceConfig2W, level 1)",
        "  set: after an end that was no Stop, started again after 5, 30, 300 s, the count forgotten after 3600 s"
        " (ChangeServiceConfig2W, level 2)",
        "  set: the same after an exit of the service's own (ChangeServiceConfig2W, level 4, the failure flag)"]
    assert lines[10] == ("  started (StartServiceW); its state asked every 0.25 s until it runs or stops, for at most"
                         " 80 s")
    assert lines[11] == "  after 0.00 s: 4, running"
    assert lines[12] == "  raqib service status" and "  RESULT: ACTIVE" in lines and lines[-2] == "  RESULT: ACTIVE"
    assert manager.log == ["platform", "make_manager", "open", "create", "describe", "failure_actions",
                           "failure_flag", "start", "clock", "state", "clock", "close", "close", "platform",
                           "connect", "open", "description", "making", "state", "close", "close"]
    assert manager.service["description"] == wininstall.DESCRIPTION and winmanager.marked(wininstall.DESCRIPTION)
    assert manager.service["command"] == '"%s" service run' % PROGRAM


def test_e2_the_plain_road_writes_its_own_form_by_the_path_the_check_judged(monkeypatch):
    monkeypatch.setattr(wincode, "check", lambda system, drives: (None, {"folders": 1, "files": 2, "above": 3}))
    code, lines, manager = install(code=Code(program=PYTHON, packed=False))
    assert code == 0 and manager.service["command"] == '"%s" -I -m raqib service run' % PYTHON
    assert winmanager.command_form(manager.service["command"]) == ("-I -m raqib service run", PYTHON)
    assert "(a plain interpreter's, by the path the check judged)" in lines[5]


def test_e2_not_windows_is_2_nothing_asked_one_line():
    manager = Manager(platform="linux")
    code, lines, _ = install(manager)
    assert code == 2 and lines == ["raqib service install: Windows only here (the system's service manager); this is"
                                   " linux; nothing done"] and manager.log == ["platform"]
    code, lines = remove(Manager(platform="darwin"))
    assert code == 2 and lines[0].startswith("raqib service remove: Windows only here")


def test_e2_the_check_refused_in_its_own_words_nothing_asked_of_the_manager():
    code, lines, manager = install(code=Code(program_open=True))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, nothing made"
    assert lines[2].startswith("  raqib service check: NOT the system's alone: %s, " % PROGRAM)
    assert manager.log == ["platform"]


def test_e2_a_plain_interpreter_not_started_with_i_is_refused_with_the_command_to_ask_it_by():
    code, lines, manager = install(code=Code(program=PYTHON, packed=False, isolated=False))
    assert code == 1 and manager.log == ["platform"] and lines[-1] == "RESULT: NOT INSTALLED, nothing made"
    assert lines[2].startswith("  raqib service check: %s: a plain interpreter that was not started with -I" % PYTHON)
    assert lines[3] == ('  so the install is asked as the service will run it: "%s" -I -m raqib service install'
                        % PYTHON)


READINGS = [   # (the reading, the number prepare refuses it with)
    ((0x410, CLOSED), winservice.EXIT_REPARSE),
    ((0x20, CLOSED), winservice.EXIT_NOT_FOLDER),
    ((0x10, "O:S-1-5-21-1-2-3-1001" + winservice.CLOSED_AS_MADE), winservice.EXIT_OWNER),
    ((0x10, winservice.CLOSED_AS_MADE), winservice.EXIT_OWNER),
    ((0x10, "O:BA" + winservice.CLOSED_AS_SET), winservice.EXIT_OPEN),
    ((0x10, "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"), winservice.EXIT_OPEN),
]


@pytest.mark.parametrize("reading, number", READINGS)
def test_x8_a_place_there_is_refused_as_the_runners_prepare_refuses_the_same_reading_never_made(reading, number):
    with pytest.raises(winservice.Refusal) as caught:
        winservice.prepare(Place(reading=reading))
    assert caught.value.number == number   # what the runner would do at its start, for this reading
    got = wininstall.place_judged(Place(reading=reading))
    assert got[:2] == ("refused", number)
    place = Place(reading=reading)
    code, lines, manager = install(place=place)
    assert code == 1 and manager.log == ["platform"] and place.made == [] and lines[-1].endswith("nothing made")
    assert lines[3].startswith("  the place: C:\\ProgramData\\Raqib")
    assert lines[3].endswith("; the runner would refuse it at its start (%s), so no service is made (ADR-0013 X-8)"
                             % winservice.told(number))


def test_x8_the_place_unread_or_programdata_not_a_drive_refused_as_prepare_and_one_taken_is_said_not_changed():
    for place, number in ((Place(error=5), winservice.EXIT_UNREAD), (Place(root=None),
                                                                     winservice.EXIT_NO_PROGRAMDATA),
                          (Place(root="ProgramData"), winservice.EXIT_NO_PROGRAMDATA)):
        with pytest.raises(winservice.Refusal) as caught:
            winservice.prepare(Place(reading=None, error=place.error, root=place.root))
        assert caught.value.number == number == wininstall.place_judged(place)[1]
        code, lines, manager = install(place=place)
        assert code == 1 and manager.log == ["platform"] and place.made == []
    assert "an administrator is needed" in wininstall.place_judged(Place(error=5))[2]
    taken = Place(reading=(0x10, CLOSED))
    assert winservice.prepare(Place(reading=(0x10, CLOSED)))[1:3] == ("found", "BA")
    code, lines, manager = install(place=taken)
    assert code == 0 and taken.made == [] and taken.read == ["C:\\ProgramData\\Raqib"]
    assert lines[3] == ("  the place: C:\\ProgramData\\Raqib is there, a folder owned by BA with the closed list, as"
                        " the runner takes it at a start; not changed")
    # Y-3: the place's own name not there (2) is the runner's to make; a folder above not there (3) is not
    assert wininstall.place_judged(Place(error=2)) == ("absent", "C:\\ProgramData\\Raqib")
    kind, number, words = wininstall.place_judged(Place(error=3))
    assert (kind, number) == ("refused", winservice.EXIT_UNREAD) and "could not be read" in words
    code, lines, manager = install(place=Place(error=3))
    assert code == 1 and manager.log == ["platform"] and lines[-1] == "RESULT: NOT INSTALLED, nothing made"


def test_e2_the_manager_refused_5_an_administrator_is_needed_nothing_made():
    code, lines, manager = install(Manager(fail={"make_manager": 5}))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, nothing made"
    assert ("  the service manager: OpenSCManagerW (rights 0x3, to connect and to make a service) failed: error 5"
            " (access denied: an administrator is needed (a prompt opened as administrator)); nothing made") in lines
    made_nothing(manager)


@pytest.mark.parametrize("text, said", [
    (wininstall.DESCRIPTION, "and carries Raqib's mark: it is not changed; remove it first (raqib service remove),"
                             " then install"),
    ("Another program's service", "without Raqib's mark: it is not Raqib's and is not touched"),
    (None, "without Raqib's mark: it is not Raqib's and is not touched"),
])
def test_e2_a_service_of_the_name_is_never_touched_raqibs_own_a_second_install_and_anothers(text, said):
    code, lines, manager = install(Manager(there=True, text=text))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, nothing made"
    assert "  a service named RaqibWatch is there %s" % said in lines
    made_nothing(manager)
    assert manager.log == ["platform", "make_manager", "open", "description", "close", "close"]


def test_e2_the_name_unread_and_the_making_answering_1073_1072_or_5_make_nothing():
    code, lines, manager = install(Manager(there=True, fail={"description": 5}))
    assert code == 1 and "it is not touched" in lines[-2] and lines[-1].endswith("nothing made")
    made_nothing(manager)
    code, lines, manager = install(Manager(fail={"open": 6}))
    assert code == 1 and "OpenServiceW (rights 0x5, to ask) failed: error 6; nothing made" in lines[-2]
    made_nothing(manager)
    for error, words in ((1073, "a service of the name is there"),
                         (1072, "a service of the name is marked for removal and not yet gone")):
        code, lines, manager = install(Manager(fail={"create": error}))
        assert code == 1 and lines[-2] == "  CreateServiceW: error %d (%s); it is not touched, nothing made" % (
            error, words)
        assert manager.log[-3:] == ["create", "close", "close"] or manager.log[-2:] == ["create", "close"]
        assert [c for c in manager.log if c in MAKERS] == ["create"]
    code, lines, manager = install(Manager(fail={"create": 5}))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, nothing made"


@pytest.mark.parametrize("path, why", [
    ('C:\\Program Files\\R"x\\raqib.exe', "holds a quote"),
    ("C:\\Program Files\\R\u200bx\\raqib.exe", "holds a character that is not printable"),
    ("C:\\Program Files\\R\x7fx\\raqib.exe", "holds a character that is not printable"),
    ("", "is not a path"),
    # Y-2: a percent sign, which the system may read in a service's command as a variable's name
    ("C:\\Program Files\\R%TEMP%x\\raqib.exe", "holds a percent sign"),
    ("C:\\Program Files\\100%\\raqib.exe", "holds a percent sign"),
])
def test_e2_the_command_refused_where_the_path_holds_a_quote_or_a_character_not_printable(monkeypatch, path, why):
    monkeypatch.setattr(wincode, "check", lambda system, drives: (None, {"folders": 1, "files": 1, "above": 1}))
    code, lines, manager = install(code=Code(program=path))
    assert code == 1 and why in lines[-2] and lines[-2].startswith("  the command: the path the check judged, ")
    made_nothing(manager)
    assert wininstall.path_refused(path) and wininstall.path_refused(None) == "is not a path (NoneType)"
    assert wininstall.path_refused(PROGRAM) is None


@pytest.mark.parametrize("call, words", [
    ("describe", "its description, Raqib's mark first (ChangeServiceConfig2W, level 1): failed: error 87"),
    ("failure_actions", "(ChangeServiceConfig2W, level 2): failed: error 87"),
    ("failure_flag", "(ChangeServiceConfig2W, level 4, the failure flag): failed: error 87"),
])
def test_e3_each_of_the_three_settings_failing_removes_what_was_made_and_says_so(call, words):
    code, lines, manager = install(Manager(fail={call: 87}))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, what was made was removed again"
    assert lines[-3].endswith(words) and lines[-2] == (
        "  what was made was removed again: DeleteService done on it; it is gone once every handle on it is closed"
        " (raqib service status says what is there)")
    assert manager.log[manager.log.index(call) + 1] == "delete" and "start" not in manager.log
    assert manager.service["deleted"]
    # and a removal that then fails too: a service of the name is left, not as installed
    code, lines, manager = install(Manager(fail={call: 87, "delete": 5}))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED: a service of the name is left, not as installed"
    assert lines[-3].startswith("  what was made could not be removed again: DeleteService failed: error 5")
    # Y-4: whether what is left carries the mark, and so whether Raqib's own remove reaches it
    assert lines[-2] == "  " + (wininstall.LEFT_UNMARKED if call == "describe" else wininstall.LEFT_MARKED)
    assert ("will not touch it" in lines[-2]) == (call == "describe") == (manager.service["description"] is None)
    assert "start" not in manager.log


def test_e3_the_start_refused_by_the_system_stays_with_statuss_words():
    code, lines, manager = install(Manager(fail={"start": 1053}))
    assert code == 1 and lines[-1] == "RESULT: installed, NOT STARTED: the start was refused; it stays"
    assert "  StartServiceW failed: error 1053" in lines and "  RESULT: INSTALLED, NOT ACTIVE" in lines
    assert "    exit: 1077, never started (since it was made, or since the system started)" in lines


def test_e3_a_start_the_check_refuses_with_15_says_statuss_words_for_it_and_the_failure_actions():
    code, lines, manager = install(Manager(states=[{"state": 2}, REFUSED_15]))
    assert code == 1 and lines[-1] == ("RESULT: installed, NOT ACTIVE as raqib service status reads it (INSTALLED,"
                                       " NOT ACTIVE); it stays")
    assert "    exit: 1066, the service's own number: %s" % winservice.told(winservice.EXIT_NOT_ALONE) in lines
    assert "  after 0.25 s: 1, stopped" in lines
    assert ("  the system starts it again after 5 s, 30 s, then every 300 s (its failure actions); raqib service"
            " remove removes it") in lines


def test_x4_a_start_that_never_leaves_start_pending_within_the_bound_is_said_and_left_by_the_clock_alone():
    code, lines, manager = install(Manager(states=[{"state": 2}]))
    assert code == 1 and lines[-1] == "RESULT: installed, STILL STARTING after 80 s; left as it is"
    assert wininstall.start_bound() == (winservice.START_WAIT_HINT + winservice.CHECK_WAIT_HINT) / 1000 + 15 == 80
    waits = manager.log.count("sleep")
    assert waits == 80 / 0.25 and manager.clock_at == 1080.0   # asked every quarter second, to the bound
    assert "  after 80.00 s: 2, starting" in lines and "  RESULT: INSTALLED, NOT ACTIVE" in lines
    assert "  still starting: the runner checks its own code first and may take long (ADR-0013 T-2)" in lines


def test_e3_no_start_ends_after_the_settings_0():
    code, lines, manager = install(start=False)
    assert code == 0 and lines[-1] == "RESULT: installed, not started (--no-start)"
    assert "start" not in manager.log and "state" not in manager.log and lines[-2].startswith("  --no-start: ")


def test_e3_a_call_that_raises_a_state_that_fails_and_a_close_that_fails_are_said_handles_closed():
    code, lines, manager = install(Manager(raises={"failure_flag"}))
    assert code == 1 and "an exception, RuntimeError" in lines[-3] and lines[-1].endswith("removed again")
    code, lines, manager = install(Manager(fail={"state": 6}))
    assert code == 1 and lines[-1] == "RESULT: installed and started, its state NOT KNOWN; it stays"
    code, lines, manager = install(Manager(fail={"close": [5]}))
    assert code == 1 and [x for x in lines if "CloseServiceHandle failed: error 5" in x]
    assert lines[-1].startswith("RESULT: ") and lines[-1].endswith(wininstall.NOT_CLOSED)   # Y-4: never "done" with 1
    code, lines, manager = install(Manager(raises={"open"}))
    assert code == 1 and lines[-1] == "RESULT: NOT INSTALLED, nothing made"


# --- E4: remove ---------------------------------------------------------------------------------------------------

def ours(**kw):
    return Manager(there=True, text=wininstall.DESCRIPTION, **kw)


def test_e4_running_stopped_removed_and_the_name_gone_0_the_record_said_and_kept():
    manager = ours(before=RUNS)
    code, lines = remove(manager)
    assert code == 0 and lines == [
        "raqib service remove",
        "  a service named RaqibWatch is there and carries Raqib's mark",
        "  a Stop: sent (ControlService)",
        "  stopped after 0.25 s (1, stopped)",
        "  removed (DeleteService)",
        "  the name asked for again: no service named RaqibWatch (error 1060)",
        wininstall.RECORD.rstrip("\n"),
        "RESULT: removed"]
    assert manager.log == ["platform", "connect", "open_to_remove", "description", "stop", "clock", "state", "clock",
                           "sleep", "state", "clock", "delete", "close", "close", "connect", "open", "close"]


def test_e4_nothing_installed_0_and_without_the_mark_not_touched_1():
    code, lines = remove(Manager())
    assert code == 0 and lines[1] == ("  no service named RaqibWatch (OpenServiceW: error 1060): nothing to stop or"
                                      " remove") and lines[-1] == "RESULT: nothing installed"
    for text in ("Another program's service", None, "raqib-service/10 not it"):
        manager = Manager(there=True, text=text)
        code, lines = remove(manager)
        assert code == 1 and lines[-1] == "RESULT: nothing touched: a service of the name is not Raqib's"
        made_nothing(manager)


def test_e4_a_service_that_does_not_run_1062_is_taken():
    manager = ours(stops=[1062])
    code, lines = remove(manager)
    assert code == 0 and "  a Stop: error 1062 (it does not run)" in lines and "  stopped after 0.00 s (1, stopped)" \
        in lines and lines[-1] == "RESULT: removed"


def test_e4_a_service_starting_1052_is_waited_for_and_asked_again_by_the_clock_alone():
    manager = ours(before={"state": 2}, states=[{"state": 2}, RUNS], stops=[1052, 0])
    code, lines = remove(manager)
    assert code == 0 and lines[2] == "  a Stop: error 1052 (the system takes no Stop while it starts): its start is" \
                                     " waited for, at most 80 s"
    assert lines[3] == "  after 0.50 s: 4, running; a Stop asked again"
    assert lines[4] == "  a Stop: sent (ControlService)"
    assert manager.log.count("stop") == 2 and lines[-1] == "RESULT: removed"
    manager = ours(before={"state": 2}, states=[{"state": 2}], stops=[1052])
    code, lines = remove(manager)
    assert code == 1 and lines[-1] == "RESULT: NOT REMOVED: still starting; left as it is"
    assert "  still starting after 80.00 s; nothing removed" in lines and "delete" not in manager.log


def test_e4_not_stopped_within_the_runners_bound_nothing_removed():
    manager = ours(before=RUNS, states=[RUNS])
    manager.stop = lambda handle: (manager.log.append("stop"), ({"state": 3}, 0))[1]   # it never stops
    code, lines = remove(manager)
    assert wininstall.stop_bound() == winservice.STOP_WAIT_HINT / 1000 + 15 == 45
    assert code == 1 and lines[-1] == "RESULT: NOT REMOVED: not stopped; left as it is"
    assert "  not stopped after 45.00 s (4, running); nothing removed" in lines and "delete" not in manager.log


@pytest.mark.parametrize("kw, result, said", [
    ({"fail": {"connect": 5}}, "NOT REMOVED, nothing touched", "OpenSCManagerW (rights 0x1, to connect) failed"),
    ({"fail": {"open_to_remove": 5}}, "NOT REMOVED, nothing touched", "OpenServiceW (rights 0x10025, to ask its"
     " state and its making, to stop it and to remove it) failed: error 5"),
    ({"fail": {"description": 6}}, "NOT REMOVED, nothing touched", "its description: QueryServiceConfig2W"),
    ({"stops": [1061]}, "NOT REMOVED: the Stop failed; left as it is", "a Stop: ControlService failed: error 1061"),
    ({"fail": {"delete": 5}}, "NOT REMOVED: stopped, DeleteService failed; left as it is", "DeleteService failed"),
    ({"fail": {"state": 6}}, "NOT REMOVED: its state not known; left as it is", "QueryServiceStatusEx failed"),
    ({"fail": {"delete": 1072}, "lingers": True}, "marked for removal, not yet gone", "it was marked already"),
    ({"lingers": True}, "marked for removal, not yet gone", "is still there; it goes once every handle on it is"),
])
def test_e4_each_call_failing_is_said_with_its_answer(kw, result, said):
    manager = ours(**kw)
    code, lines = remove(manager)
    assert code == 1 and lines[-1] == "RESULT: %s" % result and [x for x in lines if said in x], lines
    assert lines[-2] == wininstall.RECORD.rstrip("\n")
    if "delete" not in kw.get("fail", {}) and not kw.get("lingers"):
        assert "delete" not in manager.log


def test_e4_the_name_asked_again_failing_is_not_known():
    manager = ours(fail={"connect": [0, 6]})
    code, lines = remove(manager)
    assert code == 1 and lines[-1] == "RESULT: removed by DeleteService, whether it is gone NOT KNOWN"


# --- M12.4c2b4 (ADR-0013 Amendments ZE and ZF): remove --purge removes the record too ---------------------------

TAKEN = (0x10, CLOSED)
RECORD_CALLED = ("listed", "remove_file", "remove_folder")
FRESH = {"held": "fresh", "why": "unfinished, its heartbeat fresh", "age": 3.4, "stale": 30, "run": "run-1",
         "pid": 4321, "heartbeat": "2026-11-27T10:00:00.000000Z"}
SERVICE_LINES = [
    "  a service named RaqibWatch is there and carries Raqib's mark", "  a Stop: sent (ControlService)",
    "  stopped after 0.25 s (1, stopped)", "  removed (DeleteService)",
    "  the name asked for again: no service named RaqibWatch (error 1060)"]
READ_TAKEN = ("  the record (--purge): C:\\ProgramData\\Raqib is there, a folder owned by BA with the closed list, as"
              " the runner makes it: to be removed bottom up, no link followed")


def taken(manager, **kw):
    """The place read as the runner makes it, and read as not there once the made-up record's place is removed."""
    return Place(reading=TAKEN, gone_with=manager, **kw)


def inside_only(manager):
    """ZE-1: every path handed to the system object begins with the place's own path (and the stand-in judged each
    part of it: ZF-1)."""
    assert manager.paths and all(p == PLACE or p.startswith(PLACE + "\\") for p in manager.paths), manager.paths


def bottom_up(manager):
    """ZE-2: a folder removed only after every name in it was."""
    for at, path in enumerate(manager.removed):
        assert not [p for p in manager.removed[at + 1:] if p.startswith(path + "\\")], (path, manager.removed)


def listing_with(manager, extra):
    """The place's own listing with `extra` names after its own."""
    real = manager.listed

    def listed(folder):
        got, error = real(folder)
        return (got + list(extra) if folder == PLACE and not error else got), error
    manager.listed = listed


def test_zE1_zE4_zF5_purge_after_the_service_removed_takes_the_place_bottom_up_and_read_again_it_is_gone_0():
    manager = ours(before=RUNS, tree=TREE)
    place = taken(manager)
    code, lines = remove(manager, purge=True, place=place)
    assert code == 0 and lines[1:6] == SERVICE_LINES   # the service's own remove first, unchanged (ZE-3, X-6)
    assert lines[6:] == [
        READ_TAKEN,
        "  the record: removed 3 folders and 11 files inside it, then the place itself: C:\\ProgramData\\Raqib, read"
        " again, is gone",
        "RESULT: the service removed; the record removed"]   # the rig's words (X56), as they were
    service = ["platform", "connect", "open_to_remove", "description", "stop", "clock", "state", "clock", "sleep",
               "state", "clock", "delete", "close", "close", "connect", "open", "close"]
    assert manager.log[:len(service)] == service and set(manager.log[len(service):]) == set(RECORD_CALLED)
    assert manager.tree == {} and manager.place_gone and manager.removed[-1] == PLACE and len(manager.removed) == 15
    assert place.read == [PLACE, PLACE] and place.held_asked == [PLACE] and place.made == []   # read again (ZF-5)
    inside_only(manager)
    bottom_up(manager)
    manager = Manager(tree=TREE)   # ZE-3: none installed is the service's 0 too
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 0 and lines[-1] == "RESULT: nothing installed; the record removed" and manager.place_gone


def test_zF5_the_place_read_again_and_still_there_is_said_as_it_answered_not_gone_1():
    manager = ours(tree=TREE)
    place = Place(reading=TAKEN)   # it reads as taken whatever was removed
    code, lines = remove(manager, purge=True, place=place)
    assert code == 1 and lines[-2] == ("  the record: removed 3 folders and 11 files inside it, then the place"
                                       " itself; read again, it answers: C:\\ProgramData\\Raqib is there, a folder"
                                       " owned by BA with the closed list")
    assert lines[-1] == "RESULT: the service removed; the record NOT removed: the place, read again, is not absent" \
        " (said above)"
    assert place.read == [PLACE, PLACE] and "is gone" not in "\n".join(lines)


def test_zE1_the_place_not_there_is_nothing_to_remove_0_nothing_asked_of_the_system():
    manager, place = ours(tree=TREE), Place(error=2)
    code, lines = remove(manager, purge=True, place=place)
    assert code == 0 and lines[-2:] == [
        "  the record (--purge): C:\\ProgramData\\Raqib is not there: nothing to remove",
        "RESULT: the service removed; no record to remove"]
    assert not [c for c in manager.log if c in RECORD_CALLED] and manager.paths == [] and place.read == [PLACE]
    assert place.held_asked == []


@pytest.mark.parametrize("reading, number", READINGS)
def test_zE1_a_place_the_runner_would_refuse_is_left_exactly_as_it_is_in_prepares_own_reading_1(reading, number):
    with pytest.raises(winservice.Refusal) as caught:
        winservice.prepare(Place(reading=reading))
    assert caught.value.number == number   # place_judged, the install's reading, tied to the runner's prepare
    kind, judged, words = wininstall.place_judged(Place(reading=reading))
    assert (kind, judged) == ("refused", number)
    manager, place = ours(tree=TREE), Place(reading=reading)
    code, lines = remove(manager, purge=True, place=place)
    assert code == 1 and lines[-2] == ("  the record (--purge): %s; not the place as Raqib's service makes it, so it"
                                       " is left exactly as it is (ADR-0013 ZE-1)" % words)
    assert lines[-1] == ("RESULT: the service removed; the record NOT removed: not the place as Raqib's service"
                         " makes it")   # the rig's words for a place read and refused (X56), as they were
    assert manager.tree == TREE and manager.paths == [] and place.held_asked == [] and "delete" in manager.log


def test_zF5_a_place_that_could_not_be_read_at_all_is_said_so_in_the_result_nothing_touched_1():
    for place, number in ((Place(error=5), winservice.EXIT_UNREAD), (Place(error=3), None),
                          (Place(root=None), winservice.EXIT_NO_PROGRAMDATA),
                          (Place(root="ProgramData"), winservice.EXIT_NO_PROGRAMDATA)):
        words = wininstall.place_judged(place)[2]
        if number is not None:   # as the install's test ties them; 3 is Y-3's, judged by place_judged alone
            with pytest.raises(winservice.Refusal) as caught:
                winservice.prepare(Place(reading=None, error=place.error, root=place.root))
            assert caught.value.number == number == wininstall.place_judged(place)[1]
        manager = Manager(tree=TREE)
        code, lines = remove(manager, purge=True, place=place)
        assert code == 1 and lines[-2] == ("  the record (--purge): %s; the place could not be read, so nothing of it"
                                           " is touched (ADR-0013 ZF-5)" % words)
        assert lines[-1] == "RESULT: nothing installed; the record NOT removed: the place could not be read"
        assert manager.tree == TREE and manager.paths == [] and place.held_asked == []
    # ZE-4: one who is no administrator is refused by the place's own list, in place_judged's own sentence
    assert "an administrator is needed" in wininstall.place_judged(Place(error=5))[2]


def test_zF2_a_host_watch_that_still_holds_the_place_fresh_leaves_it_untouched_its_age_said_1():
    assert winservice.HELD_FRESH == host.HELD_FRESH == FRESH["held"] and callable(winservice.System.held)
    manager = Manager(tree=TREE)   # nothing named RaqibWatch; a service of another name may run the runner here
    place = taken(manager, holds=FRESH)
    code, lines = remove(manager, purge=True, place=place)
    assert code == 1 and lines[-2] == (
        "  the record (--purge): a host watch's state still holds the place (its heartbeat 3 s ago, stale after 30"
        " s): that watch still watches, or was ended without its end, or its heartbeat is ahead of this clock;"
        " nothing removed: ask for the record again when it has ended (ADR-0013 ZF-2)")
    assert lines[-1] == "RESULT: nothing installed; the record NOT removed: a watch still holds the place"
    assert manager.paths == [] and manager.tree == TREE and place.held_asked == [PLACE] and lines[-3] == READ_TAKEN
    # stale or none: no watch holds it, and it is removed
    for answer in (dict(FRESH, held="stale", age=31.0), {"held": "none"}):
        manager = Manager(tree=TREE)
        code, lines = remove(manager, purge=True, place=taken(manager, holds=answer))
        assert code == 0 and manager.place_gone, answer
    # ZG-1: a state that cannot be read, or an answer not known, is no leave to remove (the watch's own D-6)
    for answer, why in (({"held": "unparsed", "why": "the heartbeat cannot be parsed"},
                         "the heartbeat cannot be parsed"),
                        ({"held": "unreadable", "why": "the state cannot be read (ValueError: made up)"},
                         "the state cannot be read (ValueError: made up)"),
                        ({"held": "later"}, "its state gave an answer this command does not know"),
                        (["fresh"], "its state gave an answer this command does not know")):
        manager = Manager(tree=TREE)
        code, lines = remove(manager, purge=True, place=taken(manager, holds=answer))
        assert code == 1 and manager.paths == [] and manager.tree == TREE, answer
        assert lines[-2] == ("  the record (--purge): whether a host watch still holds the place is not known: %s; a"
                             " state that cannot be read is no leave to remove (ADR-0013 ZG-1): nothing touched;"
                             " where no watch runs there, the place is removed by hand" % why), lines[-2]
        assert lines[-1] == ("RESULT: nothing installed; the record NOT removed: whether a watch still holds the"
                             " place NOT KNOWN")
    assert {host.HELD_NONE, host.HELD_STALE, host.HELD_FRESH, host.HELD_UNPARSED, host.HELD_UNREADABLE} == {
        "none", "stale", "fresh", "unparsed", "unreadable"}   # the answers this reading was written against
    assert wininstall.HELD_CLEAR == (host.HELD_NONE, host.HELD_STALE)
    # an exception out of it: said, nothing touched
    manager = Manager(tree=TREE)
    code, lines = remove(manager, purge=True, place=taken(manager, holds=RecursionError("made up")))
    assert code == 1 and lines[-2] == ("  the record (--purge): whether a host watch still holds the place could not"
                                       " be asked (RecursionError): nothing touched")
    assert lines[-1] == ("RESULT: nothing installed; the record NOT removed: whether a watch still holds the place"
                         " NOT KNOWN")
    assert manager.paths == [] and manager.tree == TREE


def test_zE2_a_reparse_point_inside_is_neither_entered_nor_removed_counted_and_said_and_the_place_stays_1():
    link = HOST + "\\\u0644ink"   # a link to a folder elsewhere (its name not ASCII; not the first said here)
    manager = ours(tree=dict(TREE, **{link: 0x410, PLACE + "\\file-link": 0x420}))
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and lines[-2] == (
        "  the record: NOT all removed: 1 folder and 11 files removed; left: 2 reparse points, neither entered nor"
        " removed (the first: C:\\ProgramData\\Raqib\\file-link, attributes 0x420); the place stays")
    assert lines[-1] == "RESULT: the service removed; the record NOT removed: part of it is left (said above)"
    assert link not in manager.paths and PLACE + "\\file-link" not in manager.paths   # neither entered nor removed
    assert set(manager.tree) == {link, PLACE + "\\file-link", PLACE + "\\.raqib", HOST} and not manager.place_gone
    assert "remove_folder" in manager.log and HOST + "\\cases" in manager.removed
    inside_only(manager)
    bottom_up(manager)


def test_zE4_a_name_not_ascii_is_said_as_its_number_where_it_is_the_first_link_and_the_first_error_1():
    link, odd = PLACE + "\\\u0644ink", PLACE + "\\\u00e9vents.jsonl"
    manager = Manager(tree=dict(TREE, **{link: 0x410, odd: 0x20}), refuse={odd: 5})
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and ("1 reparse point, neither entered nor removed (the first:"
                          " C:\\ProgramData\\Raqib\\\\u0644ink, attributes 0x410)") in lines[-2]
    assert lines[-2].endswith("once; the first at C:\\ProgramData\\Raqib\\\\u00E9vents.jsonl; the place stays")


def test_zE2_zF4_each_error_counted_by_its_number_the_first_ones_path_said_5_as_a_read_only_file_never_an_admin_1():
    refuse = {HOST + "\\events.jsonl": 5, HOST + "\\seen.json": 5, HOST + "\\cases": 32}
    manager = Manager(tree=TREE, refuse=refuse)   # none installed: no wait on 32 (ZF-3)
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and lines[-2] == (
        "  the record: NOT all removed: 0 folders and 4 files removed; left: error 5 (access denied: a read-only"
        " file, or a name the system holds) 2 times, error 32 (in use by another process) once; the first at"
        " C:\\ProgramData\\Raqib\\.raqib\\host\\events.jsonl; the place stays")
    assert "administrator" not in lines[-2] and not manager.place_gone   # ZF-4: the caller has just read the place
    assert lines[-1] == "RESULT: nothing installed; the record NOT removed: part of it is left (said above)"
    assert set(manager.tree) == set(refuse) | {PLACE + "\\.raqib", HOST} | {p for p in TREE if "case-" in p}
    inside_only(manager)
    # a listing that fails leaves its folder and every one above; one that gives no attributes is such a failure
    for error, said in ((5, "error 5 (access denied: a read-only file"), ("an exception, AttributeError",
                                                                          "an exception, AttributeError once")):
        manager = ours(tree=TREE, refuse={PLACE + "\\.raqib": error})
        code, lines = remove(manager, purge=True, place=taken(manager))
        assert code == 1 and "0 folders and 1 file removed; left: " + said in lines[-2] and manager.paths == [
            PLACE, PLACE + "\\watch.log", PLACE + "\\.raqib"]
    manager = ours(tree=TREE, fail={"listed": ["an exception, AttributeError"]})   # the place's own listing
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and lines[-2] == ("  the record: NOT all removed: 0 folders and 0 files removed; left: an"
                                       " exception, AttributeError once; the first at C:\\ProgramData\\Raqib; the"
                                       " place stays") and manager.paths == [PLACE] and manager.tree == TREE


DELAY = 1000.25   # the stand-in clock after the service's own remove (ours, RUNS), before the record


def test_zF3_a_removal_answering_32_after_this_command_removed_the_service_is_asked_again_and_lets_go_0():
    lock = HOST + "\\events.jsonl"
    manager = ours(before=RUNS, tree=TREE)
    remove(manager, purge=True, place=taken(manager))
    assert manager.clock_at == DELAY   # without a 32 the record waits for nothing
    manager = ours(before=RUNS, tree=TREE, refuse={lock: [32, 32]})   # twice, then let go
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 0 and lines[-1] == "RESULT: the service removed; the record removed" and manager.place_gone
    assert manager.paths.count(lock) == 3 and manager.clock_at == DELAY + 1.0   # by the system object's own clock


def test_zF3_a_removal_that_never_lets_go_is_asked_for_20_s_on_the_stand_in_clock_then_counted_1():
    lock = HOST + "\\events.jsonl"
    manager = ours(before=RUNS, tree=TREE, refuse={lock: 32})
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and manager.clock_at == DELAY + wininstall.IN_USE_BOUND == DELAY + 20.0
    assert manager.paths.count(lock) == 1 + 40 and (wininstall.IN_USE_EVERY, wininstall.IN_USE) == (0.5, 32)
    assert "left: error 32 (in use by another process) once; the first at %s" % lock in lines[-2]
    # the place's own removal answering 32 is not inside the place: not asked again
    manager = ours(before=RUNS, tree=TREE, fail={"remove_folder": [0, 0, 0, 32]})
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and manager.clock_at == DELAY and manager.log.count("remove_folder") == 4
    assert lines[-2] == ("  the record: NOT all removed: 3 folders and 11 files removed; left: error 32 (in use by"
                         " another process) once; the first at C:\\ProgramData\\Raqib; the place stays")


def test_zF3_with_nothing_installed_by_this_command_there_is_no_waiting_at_all_1():
    lock = HOST + "\\events.jsonl"
    manager = Manager(tree=TREE, refuse={lock: [32, 32]})
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and manager.paths.count(lock) == 1 and "sleep" not in manager.log and "clock" not in manager.log
    assert "left: error 32 (in use by another process) once" in lines[-2]


REWRITTEN = ["", "x.", "x ", "...", "a\\b", "a/b", "a:b", "a\0b", "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
             "COM1", "LPT9", "COM\u00b9", "con", "Nul.txt", "aux.tar.gz", "con .txt", 7]


@pytest.mark.parametrize("name", REWRITTEN, ids=[ascii(n) for n in REWRITTEN])
def test_zF1_a_name_the_system_would_rewrite_is_counted_never_handed_and_the_place_stays_1(name):
    manager = ours(tree=TREE)
    listing_with(manager, [(name, 0x20)])
    code, lines = remove(manager, purge=True, place=taken(manager))   # the stand-in judges every part handed
    said = "left: a name listed that is not one plain name once; the first at C:\\ProgramData\\Raqib\\"
    assert code == 1 and said in lines[-2] and lines[-2].endswith("; the place stays")
    assert not manager.place_gone and manager.tree == {} and manager.removed[-1] == PLACE + "\\.raqib"   # the rest
    inside_only(manager)


@pytest.mark.parametrize("name", ["CONSOLE.txt", "COM10", "LPTX", "x.y", ".hidden", "nul_", "a b"])
def test_zF1_a_name_near_those_forms_is_one_plain_name_and_removed_0(name):
    manager = ours(tree=dict(TREE, **{PLACE + "\\" + name: 0x20}))
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 0 and PLACE + "\\" + name in manager.removed and manager.place_gone


def test_zF1_the_stand_in_judges_every_part_of_a_path_under_the_place_not_its_prefix_alone():
    for path in (PLACE + "\\..\\x", PLACE + "\\a\\CON", PLACE + "\\x.\\y", "D:\\x", PLACE + "\\", PLACE + "x"):
        manager = Manager(tree={path: 0x20})
        manager.remove_file(path)
        assert manager.breaches, path
    manager = Manager(tree=TREE)
    assert manager.remove_file(HOST + "\\seen.json") == (True, 0) and manager.breaches == []


@pytest.mark.parametrize("kw, result", [
    ({"there": True, "text": "Another program's service"}, "nothing touched: a service of the name is not Raqib's"),
    ({"there": True, "text": wininstall.DESCRIPTION, "fail": {"open_to_remove": 5}}, "NOT REMOVED, nothing touched"),
    ({"there": True, "text": wininstall.DESCRIPTION, "stops": [1061]}, "NOT REMOVED: the Stop failed; left as it is"),
    ({"there": True, "text": wininstall.DESCRIPTION, "lingers": True}, "marked for removal, not yet gone"),
    ({"there": True, "text": wininstall.DESCRIPTION, "fail": {"close": [0, 6]}},
     "removed" + wininstall.NOT_CLOSED),
    ({"there": True, "text": wininstall.DESCRIPTION, "odd": True}, "NOT KNOWN what was done: a fault of its own"),
    ({"there": True, "text": wininstall.DESCRIPTION, "fail": {"connect": [0, 6]}}, wininstall.GONE_NOT_KNOWN),
])
def test_zE3_the_services_remove_not_ending_gone_or_none_installed_leaves_the_record_untouched_said_1(kw, result):
    kw = dict(kw)
    odd = kw.pop("odd", False)
    manager = Manager(tree=TREE, **kw)
    if odd:   # the service's remove raising: a state of a shape it does not read
        manager.state = lambda handle: (manager.log.append("state"), (["not a state"], 0))[1]
    place = taken(manager)
    code, lines = remove(manager, purge=True, place=place)
    assert code == 1 and lines[-2] == wininstall.RECORD_UNTOUCHED.rstrip("\n") == (
        "  the record (--purge): not touched: the service's remove did not end with it gone or none installed, and a"
        " service that may still run may still write; the place, Raqib under ProgramData, is left as it is (ADR-0013"
        " ZE-3)")
    assert lines[-1] == "RESULT: %s; the record NOT removed: not touched" % result
    assert place.read == [] and place.held_asked == [] and manager.paths == [] and manager.tree == TREE


def test_zE4_without_purge_the_records_line_says_purge_removes_it_and_the_place_is_not_read():
    manager, place = ours(tree=TREE), taken(Manager())
    code, lines = remove(manager, place=place)
    assert code == 0 and lines[-2] == wininstall.RECORD.rstrip("\n") and lines[-1] == "RESULT: removed"
    assert "--purge removes it where it reads as the runner makes it" in lines[-2]
    assert place.read == [] and place.held_asked == [] and manager.paths == [] and manager.tree == TREE


# --- E5: the command ----------------------------------------------------------------------------------------------

def args(action, **kw):
    return SimpleNamespace(action=action, no_start=kw.get("no_start", False), purge=kw.get("purge", False))


def test_e5_install_and_remove_on_windows_go_to_the_new_module_on_linux_to_service_status_unchanged(monkeypatch):
    got = []
    monkeypatch.setattr(wininstall, "cli_run", lambda a, out: got.append(("install", a.action)) or 6)
    monkeypatch.setattr(winmanager, "cli_run", lambda a, out: got.append(("status", a.action)) or 7)
    monkeypatch.setattr(service, "cli_run", lambda a, out: got.append(("linux", a.action)) or 5)
    monkeypatch.setattr(cli.sys, "platform", "win32")
    assert [cli.cmd_service(args(a), io.StringIO()) for a in ("install", "remove", "status")] == [6, 6, 7]
    monkeypatch.setattr(cli.sys, "platform", "linux")
    assert [cli.cmd_service(args(a), io.StringIO()) for a in ("install", "remove", "status")] == [5, 5, 5]
    assert got == [("install", "install"), ("install", "remove"), ("status", "status"), ("linux", "install"),
                   ("linux", "remove"), ("linux", "status")]


def test_e5_the_flags_not_its_own_are_refused_2_with_words_and_purge_goes_to_remove(monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")
    for a, words in ((args("install", purge=True), "raqib service: --purge is remove's only"),
                     (args("remove", no_start=True), "raqib service: --no-start is install's only")):
        with pytest.raises(cli.UsageError) as caught:
            cli.cmd_service(a, io.StringIO())
        assert str(caught.value) == words
    assert not hasattr(wininstall, "PURGE_REFUSED") and "not built" not in SOURCE   # M12.4c2b4: built (ZE)
    with pytest.raises(wininstall.Refused):
        wininstall.cli_run(args("status"), io.StringIO(), system=Manager())
    manager = Manager()
    out = io.StringIO()
    assert wininstall.cli_run(args("install", no_start=True), out, system=manager, code=Code(), place=Place(),
                              reader=manager) == 0 and out.getvalue().endswith("(--no-start)\n")
    assert wininstall.cli_run(args("remove"), io.StringIO(), system=Manager(), reader=Manager(), place=Place()) == 0
    # M12.4c2b4 (ZE-3): --purge is handed to remove, as given; with install it stays refused (above)
    for purge, said in ((False, wininstall.RECORD), (True, wininstall.PURGED % "nothing installed")):
        manager, out = Manager(tree=TREE), io.StringIO()
        place = Place(reading=(0x10, CLOSED), gone_with=manager)
        assert wininstall.cli_run(args("remove", purge=purge), out, system=manager, reader=manager, place=place) == 0
        assert said in out.getvalue() and bool(place.read) == purge and manager.place_gone == purge
        held_right(manager)


def test_e5_the_help_and_the_docstring_say_install_and_remove_on_windows():
    sub = [a for a in cli._parser()._actions if getattr(a, "choices", None) and "service" in a.choices][0]
    said = " ".join(sub.choices["service"].format_help().split())
    assert "on Windows, install (an administrator) makes the service RaqibWatch" in said, said
    doc = " ".join(cli.cmd_service.__doc__.split())
    assert "raqib/wininstall.py, imported here only" in doc
    assert "On Windows install and remove make and remove the service RaqibWatch" in " ".join(cli.__doc__.split())


# --- E1: the system object ----------------------------------------------------------------------------------------

def tree_of():
    tree = ast.parse(SOURCE)
    system = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System")
    return tree, system, {n.name: n for n in system.body if isinstance(n, ast.FunctionDef)}


DECLARED = {
    "OpenSCManagerW": ("wintypes.HANDLE", "[wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]"),
    "CreateServiceW": ("wintypes.HANDLE", "[wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,"
                                          " wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR,"
                                          " wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR,"
                                          " wintypes.LPCWSTR, wintypes.LPCWSTR]"),
    "ChangeServiceConfig2W": ("wintypes.BOOL", "[wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]"),
    "StartServiceW": ("wintypes.BOOL", "[wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR)]"),
    "QueryServiceStatusEx": ("wintypes.BOOL", "[wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,"
                                              " ctypes.POINTER(wintypes.DWORD)]"),
    "OpenServiceW": ("wintypes.HANDLE", "[wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]"),
    "ControlService": ("wintypes.BOOL", "[wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SERVICE_STATUS)]"),
    "DeleteService": ("wintypes.BOOL", "[wintypes.HANDLE]"),
    "CloseServiceHandle": ("wintypes.BOOL", "[wintypes.HANDLE]"),
}
DWORDS = ("dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode", "dwServiceSpecificExitCode",
          "dwCheckPoint", "dwWaitHint")
STRUCTURES = {   # as the system documents them (winsvc.h), each field by its name and type, in order
    "SERVICE_STATUS_PROCESS": [(n, "wintypes.DWORD") for n in DWORDS + ("dwProcessId", "dwServiceFlags")],
    "SERVICE_STATUS": [(n, "wintypes.DWORD") for n in DWORDS],
    "SERVICE_DESCRIPTIONW": [("lpDescription", "wintypes.LPWSTR")],
    "SC_ACTION": [("Type", "ctypes.c_int"), ("Delay", "wintypes.DWORD")],
    "SERVICE_FAILURE_ACTIONSW": [("dwResetPeriod", "wintypes.DWORD"), ("lpRebootMsg", "wintypes.LPWSTR"),
                                 ("lpCommand", "wintypes.LPWSTR"), ("cActions", "wintypes.DWORD"),
                                 ("lpsaActions", "ctypes.POINTER(SC_ACTION)")],
    "SERVICE_FAILURE_ACTIONS_FLAG": [("fFailureActionsOnNonCrashFailures", "wintypes.BOOL")],
}
CALLED = {   # each call as Amendment X measured it, with its rights
    "api.adv.OpenSCManagerW(None, None, MAKE_RIGHTS)": "make_manager",
    "api.adv.OpenSCManagerW(None, None, CONNECT_RIGHTS)": "connect",
    "api.adv.CreateServiceW(manager, name, DISPLAY_NAME, MADE_RIGHTS, OWN_PROCESS, AUTO_START, ERROR_NORMAL,"
    " command, None, None, None, None, None)": "create",
    "api.adv.ChangeServiceConfig2W(service, CONFIG_DESCRIPTION, api.ctypes.byref(given))": "describe",
    "api.adv.ChangeServiceConfig2W(service, CONFIG_FAILURE_ACTIONS, api.ctypes.byref(given))": "failure_actions",
    "api.adv.ChangeServiceConfig2W(service, CONFIG_FAILURE_FLAG, api.ctypes.byref(given))": "failure_flag",
    "api.adv.StartServiceW(service, 0, None)": "start",
    "api.adv.QueryServiceStatusEx(service, STATUS_PROCESS_INFO, api.ctypes.byref(got), api.ctypes.sizeof(got),"
    " api.ctypes.byref(needed))": "state",
    "api.adv.OpenServiceW(manager, name, REMOVE_RIGHTS)": "open_to_remove",
    "api.adv.ControlService(service, CONTROL_STOP, api.ctypes.byref(got))": "stop",
    "api.adv.DeleteService(service)": "delete",
    "api.adv.CloseServiceHandle(handle)": "close",
}
RECORD_CALLS = {"listed": "os.scandir(folder)", "remove_file": "os.unlink(path)", "remove_folder": "os.rmdir(path)"}


def test_e1_one_system_object_whose_methods_are_the_systems_own_calls_each_declared_with_the_rights_measured():
    tree, system, methods = tree_of()
    assert [n.name for n in tree.body if isinstance(n, ast.ClassDef)] == ["Refused", "System", "_Held"]
    assert set(methods) == {"__init__", "platform", "_win", "make_manager", "connect", "create", "describe",
                            "failure_actions", "failure_flag", "start", "state", "open_to_remove", "stop", "delete",
                            "close", "sleep", "clock"} | set(RECORD_CALLS)
    declared = {}
    for node in ast.walk(methods["_win"]):
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]).startswith("adv."):
            _, call, kind = ast.unparse(node.targets[0]).split(".")
            declared.setdefault(call, {})[kind] = ast.unparse(node.value)
    assert {k: (v["restype"], v["argtypes"]) for k, v in declared.items()} == DECLARED
    fields = {n.name: ast.unparse(n.body[0]) for n in ast.walk(methods["_win"]) if isinstance(n, ast.ClassDef)}
    assert fields == {name: "_fields_ = [%s]" % ", ".join("('%s', %s)" % f for f in listed)
                      for name, listed in STRUCTURES.items()}
    loads = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call) and "WinDLL" in ast.unparse(n.func)]
    assert loads == ["ctypes.WinDLL('advapi32', use_last_error=True)"]
    used = {}
    for name, fn in methods.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and ast.unparse(node.func).startswith("api.adv."):
                used[ast.unparse(node)] = name
    assert used == CALLED
    assert (wininstall.MAKE_RIGHTS, wininstall.CONNECT_RIGHTS, wininstall.MADE_RIGHTS, wininstall.REMOVE_RIGHTS) == (
        0x3, 0x1, 0x10017, 0x10025)
    assert (wininstall.OWN_PROCESS, wininstall.AUTO_START, wininstall.ERROR_NORMAL, wininstall.DISPLAY_NAME) == (
        0x10, 2, 1, "Raqib watch")
    assert (wininstall.CONFIG_DESCRIPTION, wininstall.CONFIG_FAILURE_ACTIONS,
            wininstall.CONFIG_FAILURE_FLAG) == (1, 2, 4)
    assert (wininstall.RESTART, wininstall.RESET_PERIOD, wininstall.DELAYS, wininstall.CONTROL_STOP) == (
        1, 3600, (5000, 30000, 300000), 1)
    for name in set(methods) - {"__init__", "platform", "_win"}:   # each: errors read at once, never raised
        tries = [n for n in methods[name].body if isinstance(n, ast.Try)]
        assert len(tries) == 1 and [ast.unparse(h.type) for h in tries[0].handlers] == ["Exception"], name
        if name in RECORD_CALLS:   # M12.4c2b4 (ZE-2): the standard library's one call each, its number read
            calls = [ast.unparse(n) for n in ast.walk(methods[name]) if isinstance(n, ast.Call)
                     and ast.unparse(n.func).startswith("os.")]
            assert calls == [RECORD_CALLS[name]] and "_number(exc)" in ast.unparse(tries[0].handlers[0]), name
        elif name not in ("sleep", "clock"):
            assert "_last(api.ctypes.get_last_error())" in ast.unparse(methods[name]), name
        assert all(isinstance(r.value, (ast.Tuple, ast.IfExp)) for r in ast.walk(methods[name])
                   if isinstance(r, ast.Return)), name
    assert winservice.SERVICE_NAME == "RaqibWatch" and wininstall.DESCRIPTION.startswith(winmanager.MARK + " ")


def test_e1_standard_library_only_nothing_at_import_no_program_no_file_no_registry_never_prepare():
    tree, system, methods = tree_of()
    for node in tree.body:
        assert isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.ClassDef, ast.FunctionDef))
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant) and node is tree.body[0]
        if isinstance(node, ast.Assign):
            assert not [c for c in ast.walk(node.value) if isinstance(c, ast.Call)], ast.unparse(node)
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    tops = sorted(ast.unparse(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom)))
    assert tops == ["from __future__ import annotations", "import ntpath", "import os", "import sys", "import time",
                    "import types"]
    # M12.4c2b4 (ZE-2): os is named for its three calls alone, each in the one System method that is it
    assert sorted(set(re.findall(r"\bos\.\w+", SOURCE))) == ["os.rmdir", "os.scandir", "os.unlink"]
    named = [(fn.name, ast.unparse(n.func)) for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef)
             for n in ast.walk(fn) if isinstance(n, ast.Call) and ast.unparse(n.func).startswith("os.")]
    assert sorted(named) == [("listed", "os.scandir"), ("remove_file", "os.unlink"), ("remove_folder", "os.rmdir")]
    assert "follow_symlinks=False" in ast.unparse(methods["listed"])
    # ZF-6 (finding 10): every name os at all is the value of one of those three calls, inside its own method
    os_names = {id(n) for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "os"}
    of_os = [(name, c) for name, fn in methods.items() for c in ast.walk(fn) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name) and c.func.value.id == "os"]
    held_to = [(name, ast.unparse(c)) for name, c in of_os]
    held_ids = {id(c.func.value) for _, c in of_os}
    assert sorted(held_to) == sorted(RECORD_CALLS.items()) and os_names == held_ids and len(os_names) == 3
    inside = {id(n) for n in ast.walk(methods["_win"])}
    assert [ast.unparse(n) for n in imports if id(n) in inside] == ["import ctypes", "from ctypes import wintypes"]
    others = {ast.unparse(n) for n in imports if id(n) not in inside and n not in tree.body}
    assert others <= {"import io", "from raqib import winmanager", "from raqib import winservice",
                      "from raqib import wincode, winmanager, winservice", "from raqib import winmanager, winservice",
                      "from raqib import wincode, winservice as ws", "from raqib import wincode, winservice"}, others
    calls = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not [c for c in calls if c.endswith(("prepare", "make_closed", "begin_text", "own_check"))], calls
    for words in ("subprocess", "os.walk", "shutil", "rmtree", "chmod", "SetFileAttributes", "winreg", "socket",
                  "kernel32", "Popen", "system(", "import service",
                  "write_bytes", "write_text", "OpenSCManagerA", "SC_MANAGER_ALL", "ChangeServiceConfigW(",
                  "CreateFile", "ShellExecute", "CreateProcess", "Reg", "os.environ"):
        assert words not in SOURCE, words
    assert (ROOT / "raqib" / "wininstall.py").read_bytes().isascii()
    assert max(len(x) for x in SOURCE.splitlines()) <= 118


def test_e1_e5_the_module_is_imported_nowhere_but_in_cmd_service():
    where = []
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(fn):
                if isinstance(node, (ast.Import, ast.ImportFrom)) and "wininstall" in ast.unparse(node):
                    where.append((path.name, fn.name, ast.unparse(node)))
        assert not [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
                    and "wininstall" in ast.unparse(n)], path
    assert where == [("cli.py", "cmd_service", "from raqib import wininstall")]


# --- E1: the real objects' own logic, against a made-up advapi32 --------------------------------------------------

class _Callable:
    def __init__(self, answer):
        self.answer = answer

    def __call__(self, *given):
        return self.answer(*given)


class Library:
    """A made-up advapi32 for the real wininstall.System and winmanager.System together: each call answers as the
    system's does and keeps what it was asked, the structures read back field by field from the memory handed.
    Nothing of the system is called."""

    NAMES = tuple(DECLARED) + ("QueryServiceConfigW", "QueryServiceConfig2W")

    def __init__(self, reader):
        self.reader, self.last, self.asked, self.closed, self.kept, self.next = reader, 0, [], [], [], 20
        self.service = None
        for name in self.NAMES:
            setattr(self, name, _Callable(getattr(self, "_" + name)))

    def _give(self):
        self.next += 1
        return self.next

    def _OpenSCManagerW(self, machine, base, rights):
        self.asked.append(("OpenSCManagerW", machine, base, rights))
        return self._give()

    def _OpenServiceW(self, manager, name, rights):
        self.asked.append(("OpenServiceW", name, rights))
        if self.service is None:
            self.last = 1060
            return None
        return self._give()

    def _CreateServiceW(self, *given):
        self.asked.append(("CreateServiceW",) + given[1:])
        self.service = {"command": given[7], "description": None, "state": 1}
        return self._give()

    def _ChangeServiceConfig2W(self, service, level, info):
        got = info._obj
        if level == 1:
            said = got.lpDescription
            self.service["description"] = said
        elif level == 2:
            said = (got.dwResetPeriod, got.lpRebootMsg, got.lpCommand, got.cActions,
                    [(got.lpsaActions[i].Type, got.lpsaActions[i].Delay) for i in range(got.cActions)])
        else:
            said = got.fFailureActionsOnNonCrashFailures
        self.asked.append(("ChangeServiceConfig2W", level, type(got).__name__, said))
        return 1

    def _StartServiceW(self, service, count, vector):
        self.asked.append(("StartServiceW", count, vector))
        self.service["state"] = 4
        return 1

    def _QueryServiceStatusEx(self, service, level, buffer, size, needed):
        import ctypes
        got = buffer._obj
        assert level == 0 and size == ctypes.sizeof(got)
        got.dwServiceType, got.dwCurrentState = 0x10, self.service["state"]
        got.dwWin32ExitCode, got.dwProcessId = (0, 4321) if self.service["state"] == 4 else (1077, 0)
        return 1

    def _ControlService(self, service, control, status):
        self.asked.append(("ControlService", control, type(status._obj).__name__))
        status._obj.dwCurrentState = 3
        self.service["state"] = 1
        return 1

    def _DeleteService(self, service):
        self.asked.append(("DeleteService",))
        self.service = None
        return 1

    def _CloseServiceHandle(self, handle):
        self.closed.append(handle)
        return 1

    def _ask(self, kind, buffer, size, needed, more):
        import ctypes
        if buffer is None:
            needed._obj.value, self.last = ctypes.sizeof(kind) + more, 122
            return 0
        got = kind.from_buffer(buffer)
        self.kept.append(got)
        return got

    def _QueryServiceConfigW(self, service, buffer, size, needed):
        got = self._ask(self.reader._api.config, buffer, size, needed, 200)
        if got == 0:
            return 0
        got.dwServiceType, got.dwStartType = 0x10, 2
        got.lpBinaryPathName, got.lpServiceStartName = self.service["command"], "LocalSystem"
        return 1

    def _QueryServiceConfig2W(self, service, level, buffer, size, needed):
        import ctypes
        api = self.reader._api   # M12.4c2b2c (ADR-0013 Z-1): levels 2, 4 and 3 too, as the install makes them
        kind, more = {1: (api.description, 200), 2: (api.failure, ctypes.sizeof(api.action) * len(wininstall.DELAYS)),
                      3: (api.delayed, 0), 4: (api.flag, 0)}[level]
        got = self._ask(kind, buffer, size, needed, more)
        if got == 0:
            return 0
        if level == 1:
            got.lpDescription = self.service["description"]
        elif level == 2:   # the array inside the same bytes, after the structure, as the system lays it
            at = ctypes.sizeof(kind)
            for one, delay in zip((api.action * len(wininstall.DELAYS)).from_buffer(buffer, at), wininstall.DELAYS):
                one.Type, one.Delay = wininstall.RESTART, delay
            got.dwResetPeriod, got.cActions = wininstall.RESET_PERIOD, len(wininstall.DELAYS)
            got.lpsaActions = ctypes.cast(ctypes.addressof(buffer) + at, ctypes.POINTER(api.action))
        elif level == 4:
            got.fFailureActionsOnNonCrashFailures = 1
        return 1


def test_x2_the_real_objects_own_logic_runs_against_a_made_up_library_install_then_remove(monkeypatch):
    import ctypes
    real, reader = wininstall.System(), winmanager.System()
    library = Library(reader)
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, use_last_error=False: library, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: library.last, raising=False)
    for one in (real, reader):
        monkeypatch.setattr(one, "platform", lambda: "win32")
    monkeypatch.setattr(wininstall.time, "monotonic", lambda: 5.0)   # the clock made up; no wait sleeps here
    out = io.StringIO()
    code = wininstall.install(real, out, code=Code(), place=Place(), reader=reader)
    lines = out.getvalue().splitlines()
    assert code == 0 and lines[-1] == "RESULT: installed and started: raqib service status answers ACTIVE", lines
    command = '"%s" service run' % PROGRAM
    assert library.asked[:2] == [("OpenSCManagerW", None, None, 0x3), ("OpenServiceW", "RaqibWatch", 0x5)]
    assert library.asked[2] == ("CreateServiceW", "RaqibWatch", "Raqib watch", 0x10017, 0x10, 2, 1, command, None,
                                None, None, None, None)
    assert library.asked[3:7] == [
        ("ChangeServiceConfig2W", 1, "SERVICE_DESCRIPTIONW", wininstall.DESCRIPTION),
        ("ChangeServiceConfig2W", 2, "SERVICE_FAILURE_ACTIONSW", (3600, None, None, 3, [(1, 5000), (1, 30000),
                                                                                      (1, 300000)])),
        ("ChangeServiceConfig2W", 4, "SERVICE_FAILURE_ACTIONS_FLAG", 1),
        ("StartServiceW", 0, None)]
    assert "  command: %s (as the service manager holds it)" % command in [x[2:] for x in lines]
    declared = {name: (getattr(library, name).restype, getattr(library, name).argtypes) for name in DECLARED}
    assert all(restype is not None and argtypes for restype, argtypes in declared.values())
    assert sorted(library.closed) == list(range(21, library.next + 1))   # every handle given was closed
    library.asked, library.closed, first = [], [], library.next
    out = io.StringIO()
    code = wininstall.remove(real, out, reader=reader, place=Place())
    lines = out.getvalue().splitlines()
    assert code == 0 and lines[-1] == "RESULT: removed", lines
    assert library.asked == [("OpenSCManagerW", None, None, 0x1), ("OpenServiceW", "RaqibWatch", 0x10025),
                             ("ControlService", 1, "SERVICE_STATUS"), ("DeleteService",),
                             ("OpenSCManagerW", None, None, 0x1), ("OpenServiceW", "RaqibWatch", 0x5)]
    assert sorted(library.closed) == list(range(first + 1, library.next + 1))
    # a call the system refuses: its own number read at once, said, and every handle still closed
    library.asked, library.closed, first = [], [], library.next
    library._CreateServiceW = lambda *given: setattr(library, "last", 5) or None
    library.CreateServiceW = _Callable(library._CreateServiceW)
    out = io.StringIO()
    assert wininstall.install(real, out, code=Code(), place=Place(), reader=reader) == 1
    assert "  CreateServiceW failed: error 5 (access denied: an administrator is needed (a prompt opened as" \
           " administrator)); nothing made" in out.getvalue().splitlines()
    assert sorted(library.closed) == list(range(first + 1, library.next + 1))


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: on Windows the real object asks the manager")
def test_e1_the_real_object_off_windows_never_raises_and_says_what_failed():
    real = wininstall.System()
    assert real.platform() == sys.platform
    for name, given in (("make_manager", ()), ("connect", ()), ("create", (1, "RaqibWatch", "x")),
                        ("describe", (1, "x")), ("failure_actions", (1,)), ("failure_flag", (1,)), ("start", (1,)),
                        ("state", (1,)), ("open_to_remove", (1, "RaqibWatch")), ("stop", (1,)), ("delete", (1,)),
                        ("close", (1,))):
        value, error = getattr(real, name)(*given)
        assert value is None and isinstance(error, str) and error.startswith("an exception, "), (name, error)
    out = io.StringIO()
    assert wininstall.install(real, out) == 2 and out.getvalue().startswith("raqib service install: Windows only")
    assert wininstall.remove(real, io.StringIO()) == 2   # the default road, no stand-in (off Windows only)
    assert wininstall.remove(real, io.StringIO(), reader=Manager(), purge=True, place=Place()) == 2


class FakeOs:
    """M12.4c2b4: a made-up os for the real System's three record calls - a listing of two names, and each call's
    answer kept; nothing of the file system is called. `error`: what each call raises instead."""

    def __init__(self, error=None, attributes=True):
        self.error, self.asked, self.attributes = error, [], attributes

    def _ask(self, *what):
        self.asked.append(what)
        if self.error:
            raise self.error

    def scandir(self, folder):
        self._ask("scandir", folder)
        fake = self

        class Entry:
            def __init__(self, name, attributes):
                self.name, self.attributes = name, attributes

            def stat(self, follow_symlinks=True):
                fake.asked.append(("stat", self.name, follow_symlinks))
                if not fake.attributes:   # ZF-6: a stat that gives no attributes
                    return SimpleNamespace()
                return SimpleNamespace(st_file_attributes=self.attributes if not follow_symlinks else 0x10)

        class Listing:
            def __enter__(self):
                return iter([Entry("events.jsonl", 0x20), Entry("link", 0x410)])

            def __exit__(self, *a):
                fake.asked.append(("closed", folder))
        return Listing()

    def unlink(self, path):
        self._ask("unlink", path)

    def rmdir(self, path):
        self._ask("rmdir", path)


def test_zE2_the_real_systems_record_calls_list_without_following_a_link_and_answer_the_systems_number(monkeypatch):
    real = wininstall.System()
    fake = FakeOs()
    monkeypatch.setattr(wininstall, "os", fake)   # the module's own name for os alone; the real os is not touched
    assert real.listed(PLACE) == ([("events.jsonl", 0x20), ("link", 0x410)], 0)
    assert real.remove_file(PLACE + "\\watch.log") == (True, 0)
    assert real.remove_folder(PLACE + "\\.raqib") == (True, 0)
    assert fake.asked == [("scandir", PLACE), ("stat", "events.jsonl", False), ("stat", "link", False),
                          ("closed", PLACE), ("unlink", PLACE + "\\watch.log"), ("rmdir", PLACE + "\\.raqib")]
    denied = PermissionError(13, "made up")
    denied.winerror = 5   # as Windows gives it
    for error, said in ((denied, 5), (FileNotFoundError(2, "made up"), "an exception, FileNotFoundError")):
        monkeypatch.setattr(wininstall, "os", FakeOs(error))
        for name, given in (("listed", PLACE), ("remove_file", PLACE + "\\x"), ("remove_folder", PLACE)):
            assert getattr(real, name)(given) == (None, said), (name, error)
    fake = FakeOs(attributes=False)   # a listing that gives no attributes fails whole: nothing of it is handed
    monkeypatch.setattr(wininstall, "os", fake)
    assert real.listed(PLACE) == (None, "an exception, AttributeError") and ("closed", PLACE) in fake.asked


def test_zG2_one_bound_for_the_whole_purge_two_names_in_use_wait_20_s_in_all_not_each():
    """ADR-0013 ZG-2: two files the ended service has not let go: the whole purge asks again for 20 s in all, 40 asks,
    not 20 s for each."""
    first, second = sorted(p for p, attributes in TREE.items() if not attributes & 0x10)[:2]
    manager = ours(before=RUNS, tree=TREE, refuse={first: 32, second: 32})
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and "error 32 (in use by another process) 2 times" in lines[-2], lines[-2]
    assert manager.clock_at == DELAY + wininstall.IN_USE_BOUND
    assert manager.paths.count(first) + manager.paths.count(second) == 2 + wininstall.IN_USE_ASKS == 42
    assert wininstall.IN_USE_ASKS == wininstall.IN_USE_BOUND / wininstall.IN_USE_EVERY


@pytest.mark.parametrize("broken, said", [("sleep", "its pause failed"), ("clock", "its clock failed")])
def test_zG3_a_pause_or_a_clock_that_fails_ends_the_waiting_and_is_said_never_passed_off_as_made(broken, said):
    lock = HOST + "\\events.jsonl"
    manager = ours(before=RUNS, tree=TREE, refuse={lock: 32})
    real = getattr(manager, broken)

    def failing(*args):
        if manager.paths.count(lock) and (broken == "clock" or args == (wininstall.IN_USE_EVERY,)):
            raise OSError("made up")     # only the purge's own wait: the remove's waits before it are as they were
        return real(*args)
    setattr(manager, broken, failing)
    code, lines = remove(manager, purge=True, place=taken(manager))
    assert code == 1 and manager.paths.count(lock) == 1, manager.paths.count(lock)
    assert lines[-2].endswith("left: error 32 (in use by another process) once; the first at %s; the wait for a name in"
                              " use could not be made (%s): no name was asked again after that; the place stays"
                              % (lock, said)), lines[-2]
