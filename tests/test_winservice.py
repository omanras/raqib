"""M12.4a (ADR-0013 Amendment E, AE-1, AE-3, AE-4; Amendment F, AF-1 to AF-4): `raqib service run`, the host watch
as a service of Windows.

Every call of the system goes through a made-up Windows (Machine, in place of winservice.System): no test here
needs Windows, a service manager or ProgramData, and none makes a user, a service or a folder under ProgramData.
The place is a record in the Machine, and the Machine has no call that sets anything on it; the text file is a
real file in the test's own temp folder. One test raises the real interrupt (SIGINT) in the test's main thread,
only while the runner is inside its `except KeyboardInterrupt`. One test, skipped off Windows, makes a folder of
its own under its temp folder through the real object and reads it and its neighbours by one handle (E5).
"""
import ast
import copy
import io
import ntpath
import os
import signal
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, host, winservice  # noqa: E402
from raqib.winservice import (CLOSED_AS_MADE, CLOSED_AS_SET, CONTROL_INTERROGATE, CONTROL_STOP,  # noqa: E402
                              RUNNING, SERVICE_SPECIFIC, START_PENDING, STOP_PENDING, STOPPED)

PLACE = "C:\\ProgramData\\Raqib"
OPEN = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
STRANGER = "S-1-5-21-1004336348-1177238915-682003330-1001"
FOLDER, FILE, REPARSE = 0x10, 0x20, 0x400
NOW = 1793707200.0     # the Machine's clocks at its start (2026-11-03T12:00:00Z)
SAID = "raqib: raqib service run: Windows only (the system's service manager runs it); this is %s\n"


def args(**kw):
    return SimpleNamespace(action="run", no_start=kw.get("no_start", False), purge=kw.get("purge", False))


def thing(attributes=FOLDER, owner="SY", dacl=CLOSED_AS_MADE, items=()):
    return {"attributes": attributes, "owner": owner, "dacl": dacl, "items": list(items)}


def ends_on_the_interrupt(machine, argv, out):
    """A stand-in watch: a Stop comes from the system while it runs; it ends on the interrupt with its report."""
    if machine.stop:
        threading.Thread(target=machine.handler, args=(CONTROL_STOP,)).start()
        assert machine.interrupted.wait(10)
    print("a report line")
    sys.stderr.write("an error line\n")
    out.write("stopped (Ctrl-C)\n")
    machine.log.append("watch ended")
    return machine.result


class Machine:
    """A made-up Windows: it answers every call winservice makes of the system, and records in order the ones that
    make, read or tell something (statuses, the interrupt, the place's making and reading, the text, the watch).
    It has no call that sets an owner or a list."""

    def __init__(self, tmp, place=None, program_data="C:\\ProgramData", manager=True, result=0, stop=True,
                 platform="win32", made_owner="BA", made_dacl=CLOSED_AS_MADE, make_error=None, read_error=None,
                 watch=ends_on_the_interrupt, on_text=None, text_error=None, register_error=None, connects=True,
                 raw=None, on_setenv=None, real_interrupt=False):
        self.tmp, self.manager, self.result, self.stop = tmp, manager, result, stop
        self.place = copy.deepcopy(place)   # its own copy
        self.env = {} if program_data is None else {"ProgramData": program_data}
        self.os, self.made_owner, self.made_dacl = platform, made_owner, made_dacl
        self.make_error, self.read_error, self.text_error = make_error, read_error, text_error
        self.register_error, self.connects, self.raw, self.on_setenv = register_error, connects, raw, on_setenv
        self.watch_fn, self.on_text, self.real_interrupt = watch, on_text, real_interrupt
        self.log, self.handler, self.interrupted, self.release = [], None, threading.Event(), threading.Event()
        # M12.4b (AH-2): the state of the watch before is a made-up file under tmp/place (the place's stand-in for
        # raqib/host.py's holder()); its wall clock and its monotonic one are `now`, moved by pause() alone
        self.now, self.on_pause = NOW, None

    def platform(self):
        return self.os

    def getenv(self, name):
        return self.env.get(name)

    def setenv(self, name, value):
        if self.on_setenv:
            self.on_setenv(self)
        self.env[name] = value
        self.log.append(("setenv", name, value))

    def dispatch(self, name, main):
        self.log.append(("dispatch", name))
        if not self.manager:
            return winservice.NOT_BY_THE_MANAGER
        if not self.connects:
            self.release.wait(30)
            return 0
        t = threading.Thread(target=main, name="service-main")   # the system calls the service's main so
        t.start()
        t.join(30)
        return 0

    def register(self, name, handler):
        if self.register_error:
            raise self.register_error
        self.handler = handler
        return "handle"

    def set_status(self, handle, state, accepted, win32_exit, specific_exit, wait_hint):
        assert handle == "handle"
        self.log.append(("status", state, win32_exit, specific_exit))
        return True

    def raise_interrupt(self):
        self.log.append("interrupt")
        self.interrupted.set()
        if self.real_interrupt:
            winservice.System().raise_interrupt()   # the real method: signal.raise_signal(signal.SIGINT)

    def make_closed(self, path, sddl):
        assert path == PLACE and sddl == winservice.MADE_WITH
        self.log.append(("make", path))
        if isinstance(self.make_error, OSError):
            raise self.make_error
        if self.make_error is not None:
            return self.make_error
        if self.place is not None:
            return winservice.ALREADY_EXISTS
        self.place = thing(owner=self.made_owner, dacl=self.made_dacl)
        return 0

    def read_place(self, path):
        assert path == PLACE
        self.log.append(("read", path))
        if isinstance(self.read_error, Exception):
            raise self.read_error
        if self.place is None:
            raise OSError(2, "The system cannot find the file specified")
        return self.place["attributes"], "O:%s%s" % (self.place["owner"], self.place["dacl"])

    def begin_text(self, path, before):
        assert ntpath.dirname(path) == PLACE and ntpath.dirname(before) == PLACE
        self.log.append(("text", ntpath.basename(path)))
        if self.on_text:
            self.on_text(self)
        if self.text_error:
            raise self.text_error
        if self.raw is not None:
            return self.raw
        return winservice.System().begin_text(str(self.tmp / ntpath.basename(path)),
                                              str(self.tmp / ntpath.basename(before)))

    def held(self, place):
        assert place == PLACE
        self.log.append(("held", place))
        return host.holder(home=str(self.tmp / "place"), wall=lambda: self.now)

    def clock(self):
        return self.now

    def pause(self, seconds, stop):
        """No real second: a Stop set is returned at once, else the clocks move by `seconds`."""
        self.log.append(("pause", seconds))
        if self.on_pause:
            self.on_pause(self)
        if stop.is_set():
            return True
        self.now += seconds
        return stop.is_set()

    def watch(self, argv, out):
        self.log.append(("watch", tuple(argv)))
        return self.watch_fn(self, argv, out)

    def statuses(self):
        return [e[1:] for e in self.log if isinstance(e, tuple) and e[0] == "status"]

    def text(self):
        return (self.tmp / winservice.TEXT_NAME).read_text(encoding="utf-8")


def served(machine, monkeypatch, streams=None):
    """The runner's road on `machine`, with sys.stdout and sys.stderr as given (None: a service's)."""
    if streams is not None:
        monkeypatch.setattr(sys, "stdout", streams[0])
        monkeypatch.setattr(sys, "stderr", streams[1])
    monkeypatch.setattr(winservice, "CONNECT_WAIT", 10.0)
    runner = winservice.Runner(machine)
    code = runner.run()
    if runner.text is not None:
        runner.text.close()
    return code, runner


def kinds(machine, *names):
    return [e if isinstance(e, str) else e[:2] for e in machine.log
            if e in names or isinstance(e, tuple) and e[0] in names]


# --- E1 (AE-1, AF-1): the command, and the place ---------------------------------------------------------------
@pytest.mark.parametrize("kw", [{}, {"no_start": True}, {"purge": True}, {"no_start": True, "purge": True}])
def test_e1_not_windows_one_line_exit_2_whatever_the_arguments_and_nothing_asked(kw, tmp_path, capsys):
    for platform in ("linux", "darwin"):
        m = Machine(tmp_path, platform=platform)
        assert winservice.cli_run(args(**kw), io.StringIO(), system=m) == 2
        out, err = capsys.readouterr()
        assert out == "" and err == SAID % platform
        assert m.log == []


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: the one line of a command that is Windows'")
@pytest.mark.parametrize("more", [[], ["--purge"], ["--no-start"]])
def test_e1_cli_service_run_off_windows_one_line_exit_2(more, capsys):
    assert cli.main(["service", "run"] + more, io.StringIO()) == 2
    out, err = capsys.readouterr()
    assert out == "" and err == SAID % sys.platform


def test_e1_not_started_by_the_service_manager_1063_said_no_watch_exit_2(tmp_path, capsys):
    m = Machine(tmp_path, manager=False)
    assert winservice.cli_run(args(), io.StringIO(), system=m) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "not started by the service manager (error 1063)" in err
    assert "no watch started" in err
    assert m.log == [("dispatch", winservice.SERVICE_NAME)]   # no place touched, no status, no watch


def test_e1_a_handler_not_registered_is_said_no_status_no_place_no_watch(tmp_path, capsys):
    m = Machine(tmp_path, register_error=OSError(1, "Incorrect function"))
    assert winservice.cli_run(args(), io.StringIO(), system=m) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "the service's handler was not registered (Incorrect function (error 1))" in err
    assert m.log == [("dispatch", winservice.SERVICE_NAME)]


def test_e1_a_dispatcher_that_does_not_connect_within_connect_wait_is_said_no_watch(tmp_path, monkeypatch, capsys):
    m = Machine(tmp_path, connects=False)
    monkeypatch.setattr(winservice, "CONNECT_WAIT", 0.3)
    started = time.monotonic()
    try:
        assert winservice.Runner(m).run() == 2
    finally:
        m.release.set()
    assert 0.25 < time.monotonic() - started < 5
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "the service manager did not answer in" in err and "no watch started" in err
    assert m.log == [("dispatch", winservice.SERVICE_NAME)]


def test_e1_a_dispatcher_that_fails_otherwise_is_said(tmp_path, monkeypatch, capsys):
    m = Machine(tmp_path)
    monkeypatch.setattr(m, "dispatch", lambda name, main: 5)
    assert winservice.Runner(m).run() == 2
    assert "the service manager's dispatcher failed (error 5); no watch started" in capsys.readouterr().err


def test_e1_the_real_objects_watch_is_cli_main_with_the_text_file(monkeypatch):
    got = []
    monkeypatch.setattr(cli, "main", lambda argv, out: got.append((argv, out)) or 0)
    out = io.StringIO()
    assert winservice.System().watch(winservice.WATCH_ARGV, out) == 0
    assert got == [(["watch", "--host", "--no-page", "--no-notify"], out)]


def test_e1_the_other_actions_flags_are_refused_with_run_on_windows(tmp_path, capsys):
    for kw, words in (({"no_start": True}, "--no-start is install's only"), ({"purge": True}, "--purge is remove's")):
        m = Machine(tmp_path)
        assert winservice.cli_run(args(**kw), io.StringIO(), system=m) == 2
        assert words in capsys.readouterr().err and m.log == []


def test_e1_standard_library_only_ctypes_inside_system_nothing_at_import_no_start():
    source = (ROOT / "raqib" / "winservice.py").read_text(encoding="ascii")
    tree = ast.parse(source)
    for node in tree.body:   # nothing runs at import: a docstring, imports, constants, classes and functions
        assert isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.ClassDef, ast.FunctionDef))
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant) and node is tree.body[0]
        if isinstance(node, ast.Assign):   # a constant's value calls nothing
            assert not [n for n in ast.walk(node.value) if isinstance(n, ast.Call)], ast.dump(node)[:80]
    top = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    top |= {n.module for n in tree.body if isinstance(n, ast.ImportFrom)}
    assert top - {"__future__"} <= set(sys.stdlib_module_names)
    assert not top & {"ctypes", "subprocess", "socket", "ssl", "http", "urllib", "asyncio", "multiprocessing"}
    system = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System")
    inside = {id(n) for n in ast.walk(system)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            if any(x.split(".")[0] == "ctypes" for x in names):
                assert id(node) in inside
            assert not any(x.split(".")[0] in ("subprocess", "socket") for x in names)
    for words in ("os.system", "Popen", "spawn", "startfile", "execv"):
        assert words not in source, words
    assert (ROOT / "raqib" / "winservice.py").read_bytes().isascii()


def test_e1_nothing_sets_an_owner_or_a_list_on_anything_that_exists_and_15_is_gone():
    source = (ROOT / "raqib" / "winservice.py").read_text(encoding="ascii")
    for name in ("SetNamedSecurityInfo", "SetSecurityInfo", "SetFileSecurity", "SetKernelObjectSecurity",
                 "GetNamedSecurityInfo", "close_folder", "listdir", "lstat", "EXIT_NOT_CLOSED", "PROTECTED_DACL"):
        assert name not in source, name
    assert winservice.EXIT_BASE + 15 not in winservice.EXIT_WORDS
    assert not hasattr(winservice.System, "close_folder") and not hasattr(Machine, "close_folder")


def test_e1_cli_service_run_is_handed_to_winservice(monkeypatch):
    got = []
    monkeypatch.setattr(winservice, "cli_run", lambda a, out: got.append(a.action) or 7)
    assert cli.main(["service", "run"], io.StringIO()) == 7 and got == ["run"]


def test_e1_the_closed_list_is_taken_in_one_form_as_made_and_the_owners_are_two():
    assert winservice.CLOSED_AS_MADE == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert winservice.CLOSED_AS_SET == "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert winservice.MADE_WITH == CLOSED_AS_SET and not hasattr(winservice, "CLOSED_LISTS")   # AG-1: one form taken
    assert winservice.OWNERS == ("SY", "BA") and winservice.ALREADY_EXISTS == 183
    assert winservice.PLACE_NAME == "Raqib" and winservice.HOME_NAMES == ("HOME", "USERPROFILE")
    assert winservice.owner_and_list("O:BAD:P(A;;FA;;;SY)") == ("BA", "D:P(A;;FA;;;SY)")
    assert winservice.owner_and_list("O:%sD:PAI(x)" % STRANGER) == (STRANGER, "D:PAI(x)")
    assert winservice.owner_and_list("D:P(x)") == ("", "D:P(x)")


@pytest.mark.parametrize("given, road", [
    (None, "made"),                                                  # absent: made closed in one call, then read
    (thing(owner="SY", dacl=CLOSED_AS_MADE), "found"),               # as the system writes a list it was made with
    (thing(owner="BA", dacl=CLOSED_AS_MADE, items=["x"]), "found"),  # a run's record before in it: untouched
])
def test_e1_the_roads_that_take_the_place_one_make_call_and_one_read(given, road, tmp_path, monkeypatch):
    m = Machine(tmp_path, place=given)
    got = winservice.prepare(m)
    assert got == (PLACE, road, m.place["owner"], m.place["dacl"]) and got[3] == CLOSED_AS_MADE
    assert m.log == [("make", PLACE), ("read", PLACE)]               # one making call, one read: nothing set
    if given is not None:
        assert m.place == given                                      # what was found is as it was
    m = Machine(tmp_path, place=given)
    code, runner = served(m, monkeypatch)
    assert code == 0 and m.env["HOME"] == PLACE and m.env["USERPROFILE"] == PLACE
    assert m.log.index(("setenv", "HOME", PLACE)) < m.log.index(("watch", winservice.WATCH_ARGV))
    assert "the place %s (%s; owner %s, its list %s)" % (PLACE, road, m.place["owner"], m.place["dacl"]) in m.text()


B = winservice.EXIT_BASE
REFUSALS = [
    ({"program_data": None}, B + 10, "absent from the environment"),
    ({"program_data": "ProgramData"}, B + 10, "not a whole path of a drive"),
    ({"program_data": "\\\\server.example\\share"}, B + 10, "not a whole path of a drive"),
    ({"program_data": "C:\\Users\\..\\ProgramData"}, B + 10, "not a whole path"),
    ({"place": thing(FOLDER | REPARSE, owner=STRANGER, dacl=OPEN)}, B + 11, "is a reparse point"),   # a junction
    ({"place": thing(FOLDER | REPARSE, owner="BA", dacl=CLOSED_AS_MADE)}, B + 11, "is a reparse point"),  # a link
    ({"place": thing(FILE | REPARSE)}, B + 11, "is a reparse point"),                               # a link to a file
    ({"place": thing(FILE)}, B + 12, "is not a folder"),
    ({"place": thing(owner=STRANGER, dacl=OPEN)}, B + 13, "is owned by " + STRANGER),
    ({"place": thing(owner=STRANGER)}, B + 13, "neither the system (SY) nor the administrators"),
    ({"place": thing(owner="")}, B + 13, "is owned by nobody said"),
    ({"made_owner": STRANGER}, B + 13, "is owned by " + STRANGER),
    ({"place": thing(owner="BA", dacl=OPEN, items=["left.txt"])}, B + 14, "not the closed one"),
    ({"place": thing(owner="BA", dacl=OPEN)}, B + 14, "not the closed one"),                        # open, empty
    ({"place": thing(owner="BA", dacl=CLOSED_AS_SET)}, B + 14, "as a folder made closed reads"),    # AG-1: closed after
    ({"place": thing(owner="SY", dacl=CLOSED_AS_SET, items=["x"])}, B + 14, "not the closed one"),  # it existed
    ({"place": thing(dacl=CLOSED_AS_MADE + "(A;OICI;FR;;;BU)")}, B + 14, "not the closed one"),
    ({"place": thing(dacl="D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")}, B + 14, "not the closed one"),   # by the letter
    ({"made_dacl": OPEN}, B + 14, "not the closed one"),
    ({"make_error": 5}, B + 17, "could not be made (error 5)"),
    ({"make_error": OSError(87, "The parameter is incorrect")}, B + 17, "could not be made"),
    ({"place": thing(), "read_error": OSError(5, "Access is denied")}, B + 17, "through one handle"),
    ({"make_error": winservice.ALREADY_EXISTS}, B + 17, "(found) could not be read"),                # gone at read
]


@pytest.mark.parametrize("kw, number, words", REFUSALS)
def test_e1_e2_each_refusal_is_left_as_it_is_stopped_from_start_pending_and_holds_at_the_next_start(
        kw, number, words, tmp_path, monkeypatch, capsys):
    m = Machine(tmp_path, **kw)
    with pytest.raises(winservice.Refusal) as got:
        winservice.prepare(m)
    assert got.value.number == number and words in got.value.words
    m = Machine(tmp_path, **kw)
    for start in (1, 2):                      # the review's item 7: two starts in a row on one machine
        before = copy.deepcopy(m.place)
        m.log = []
        code, runner = served(m, monkeypatch)
        assert code == 2 and runner.text is None, start
        assert not [e for e in m.log if isinstance(e, tuple) and e[0] in ("watch", "setenv", "text")]
        assert m.statuses() == [(START_PENDING, 0, 0), (STOPPED, SERVICE_SPECIFIC, number)]   # no RUNNING ever
        if start == 2 or "made_owner" not in kw and "made_dacl" not in kw:
            assert m.place == before, start   # refused again, nothing changed
        err = capsys.readouterr().err
        assert err.count("\n") == 1 and "no watch started (the system is told the service's own exit %d (0x%08X"\
            % (number, number) in err


# --- E2 (AF-2): the order of the statuses ----------------------------------------------------------------------
def test_e2_start_pending_the_place_and_the_text_then_running_then_the_watch(tmp_path, monkeypatch):
    m = Machine(tmp_path)
    code, _ = served(m, monkeypatch)
    assert code == 0
    assert kinds(m, "status", "make", "read", "text", "setenv", "watch", "interrupt", "watch ended") == [
        ("status", START_PENDING), ("make", PLACE), ("read", PLACE), ("text", winservice.TEXT_NAME),
        ("setenv", "HOME"), ("setenv", "USERPROFILE"), ("status", RUNNING), ("watch", winservice.WATCH_ARGV),
        ("status", STOP_PENDING), "interrupt", "watch ended", ("status", STOPPED)]
    assert m.statuses()[-1] == (STOPPED, 0, 0)


def test_e2_the_text_files_refusal_16_is_stopped_from_start_pending(tmp_path, monkeypatch, capsys):
    m = Machine(tmp_path, text_error=OSError(5, "Access is denied"))
    code, runner = served(m, monkeypatch)
    assert code == 2 and runner.text is None and ("watch", winservice.WATCH_ARGV) not in m.log
    assert m.statuses() == [(START_PENDING, 0, 0), (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_TEXT)]
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "the text file was not begun in %s: Access is denied (error 5)" % PLACE in err


# --- E3 (AF-3): the numbers ------------------------------------------------------------------------------------
def test_e3_every_exit_is_the_base_plus_its_own_and_the_spec_lists_each_in_both_forms():
    assert winservice.EXIT_BASE == 0x20000000 and winservice.SERVICE_SPECIFIC == 1066
    names = [n for n in dir(winservice) if n.startswith("EXIT_") and n not in ("EXIT_WORDS", "EXIT_BASE")]
    numbers = [getattr(winservice, n) for n in names]
    assert sorted(numbers) == sorted(winservice.EXIT_WORDS) and len(set(numbers)) == len(numbers) == 12
    assert sorted(n - winservice.EXIT_BASE for n in numbers) == [10, 11, 12, 13, 14, 16, 17, 18, 20, 21, 22, 23]
    spec = (ROOT / "docs" / "specs" / "SERVICE.md").read_text(encoding="utf-8")
    for number, words in winservice.EXIT_WORDS.items():
        row = "| %d | %d | 0x%08X | %s |" % (number - winservice.EXIT_BASE, number, number, words)
        assert row in spec, row
    assert "| 14 | 536870926 | 0x2000000E |" in spec and 0 not in winservice.EXIT_WORDS


# --- the text file (AE-3) ---------------------------------------------------------------------------------------
def test_the_text_file_is_bounded_and_its_last_line_says_so_once():
    raw = io.BytesIO()
    text = winservice.Text(raw, bound=200)
    for i in range(50):
        text.write("line %d of the watch's report\n" % i)
    text.write("partial")
    data = raw.getvalue()
    assert len(data) <= 200 and data.endswith(winservice.FULL_LINE.encode("ascii")) and len(data) > 150
    assert data.count(b"reached its bound") == 1 and b"line 0 " in data and b"line 49" not in data
    assert text.failed is None
    raw = io.BytesIO()
    text = winservice.Text(raw, bound=200)
    text.write("no end of line " * 4)
    text.write("x" * 200)
    assert raw.getvalue().split(b"\n")[1] + b"\n" == winservice.FULL_LINE.encode("ascii")   # on a line of its own
    assert len(raw.getvalue()) <= 200
    assert winservice.TEXT_MAX == 8 * 1024 * 1024 and str(winservice.TEXT_MAX) in winservice.FULL_LINE


def test_the_text_file_begun_anew_at_each_start_the_one_before_kept_once(tmp_path):
    system = winservice.System()
    now, before = str(tmp_path / winservice.TEXT_NAME), str(tmp_path / winservice.TEXT_BEFORE)
    for n in (1, 2, 3):
        with system.begin_text(now, before) as f:
            f.write(b"start %d\n" % n)
    assert (tmp_path / winservice.TEXT_NAME).read_bytes() == b"start 3\n"
    assert (tmp_path / winservice.TEXT_BEFORE).read_bytes() == b"start 2\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([winservice.TEXT_NAME, winservice.TEXT_BEFORE])


def test_streams_that_are_none_are_the_text_file_and_the_watch_prints_and_writes_errors(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing())
    code, runner = served(m, monkeypatch, streams=(None, None))
    assert code == 0 and sys.stdout is runner.text and sys.stderr is runner.text
    said = m.text()
    for line in ("a report line\n", "an error line\n", "stopped (Ctrl-C)\n"):
        assert line in said, line
    assert said.splitlines()[0].startswith("raqib service run: the place %s" % PLACE)
    assert said.splitlines()[-1] == ("raqib service run: the watch returned with 0; a Stop was asked; the system is"
                                     " told exit 0")


class Failing:
    """A raw file whose writes fail from the n-th on (`once`: that one only)."""

    def __init__(self, n, once):
        self.n, self.once, self.writes, self.data = n, once, 0, io.BytesIO()

    def write(self, data):
        self.writes += 1
        if self.writes == self.n or not self.once and self.writes > self.n:
            raise OSError(28, "There is not enough space on the disk")
        return self.data.write(data)

    def flush(self):
        pass

    def close(self):
        pass


def test_e4_a_write_that_fails_ends_the_text_with_one_last_line_where_it_can_and_the_runner_knows(tmp_path,
                                                                                               monkeypatch):
    raw = Failing(2, once=True)
    text = winservice.Text(raw)
    for words in ("one\n", "two\n", "three\n"):
        text.write(words)
    assert raw.data.getvalue().splitlines() == [b"one", b"raqib service run: a write failed (There is not enough"
                                                b" space on the disk (error 28)); nothing more is written to this"
                                                b" file"]
    assert text.failed == "There is not enough space on the disk (error 28)"
    raw = Failing(1, once=False)
    text = winservice.Text(raw)
    text.write("one\n")
    text.write("two\n")
    assert raw.data.getvalue() == b"" and text.failed and raw.writes == 2   # the last line could not be written
    m = Machine(tmp_path, raw=Failing(2, once=True))
    code, runner = served(m, monkeypatch)
    assert runner.text.failed and code == 2
    assert m.statuses()[-1] == (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_TEXT_ENDED)
    assert m.raw.data.getvalue().endswith(b"nothing more is written to this file\n")


# --- E4 (AE-4, AF-4): a Stop, and the ends -----------------------------------------------------------------------
@pytest.mark.parametrize("result, stop, number", [
    (0, True, 0), (1, True, 0), (3, True, 0),                   # a watch's result is no failure of the service
    (2, True, winservice.EXIT_WATCH_REFUSED), (2, False, winservice.EXIT_WATCH_REFUSED),
    (0, False, winservice.EXIT_WATCH_ENDED), (1, False, winservice.EXIT_WATCH_ENDED),
    (None, True, winservice.EXIT_WATCH_ENDED),
])
def test_e4_the_watchs_result_and_the_systems_exit(result, stop, number, tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), result=result, stop=stop)
    code, _ = served(m, monkeypatch)
    assert code == (0 if number == 0 else 2)
    assert m.statuses()[-1] == ((STOPPED, 0, 0) if number == 0 else (STOPPED, SERVICE_SPECIFIC, number))
    assert ("interrupt" in m.log) is stop


def test_e4_an_exception_out_of_the_watch_is_its_own_number_and_its_trace_is_in_the_text(tmp_path, monkeypatch):
    def breaks(machine, argv, out):
        raise RuntimeError("the watch broke")
    m = Machine(tmp_path, place=thing(), watch=breaks)
    code, _ = served(m, monkeypatch)
    assert code == 2 and m.statuses()[-1] == (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_WATCH_FAILED)
    assert "RuntimeError: the watch broke" in m.text() and "the watch ended by RuntimeError" in m.text()


def test_e4_an_exception_of_the_runners_own_has_its_own_number_and_its_trace_where_a_text_is_begun(
        tmp_path, monkeypatch, capsys):
    def breaks(machine):
        raise RuntimeError("the runner broke")
    m = Machine(tmp_path, on_setenv=breaks)
    code, runner = served(m, monkeypatch)
    assert code == 2 and ("watch", winservice.WATCH_ARGV) not in m.log
    assert m.statuses() == [(START_PENDING, 0, 0), (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_RUNNER_FAILED)]
    said = m.text()
    assert "Traceback" in said and "RuntimeError: the runner broke" in said
    assert said.splitlines()[-1].startswith("raqib service run: the runner ended by RuntimeError; the system is told"
                                            " the service's own exit %d" % winservice.EXIT_RUNNER_FAILED)
    m = Machine(tmp_path, read_error=ValueError("not a path"))   # before any text file: said where it can be
    code, runner = served(m, monkeypatch)
    assert code == 2 and runner.text is None
    assert m.statuses() == [(START_PENDING, 0, 0), (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_RUNNER_FAILED)]
    assert "the runner ended by ValueError: not a path" in capsys.readouterr().err


def test_e4_a_stop_before_the_watch_begins_is_obeyed_told_0_and_said_in_one_line(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), on_text=lambda machine: machine.handler(CONTROL_STOP))
    code, _ = served(m, monkeypatch)
    assert code == 0 and "interrupt" not in m.log
    assert not [e for e in m.log if isinstance(e, tuple) and e[0] == "watch"]
    assert m.statuses() == [(START_PENDING, 0, 0), (STOP_PENDING, 0, 0), (STOPPED, 0, 0)]
    said = [line for line in m.text().splitlines() if "stopped before it gave a report" in line]
    assert said == ["raqib service run: the watch was stopped before it gave a report (it was not begun); the Stop"
                    " was obeyed; the system is told exit 0"]


def waits_and_is_ended_by_the_real_interrupt(machine, argv, out):
    """A stand-in watch that waits, as a watch does, until its interrupt: the system's Stop comes to the handler
    here, in the main thread, inside the runner's `try ... except KeyboardInterrupt`, and the real method raises
    the real SIGINT. Bounded: never interrupted, it says so and returns."""
    out.write("watching\n")
    end = time.monotonic() + 10
    asked = False
    while time.monotonic() < end:
        if not asked:
            asked = True
            machine.handler(CONTROL_STOP)
        time.sleep(0.01)
    machine.log.append("not interrupted")
    return 0


def test_e4_a_watch_ended_by_the_real_interrupt_is_interrupted_told_0_and_said_in_one_line(tmp_path, monkeypatch):
    assert threading.current_thread() is threading.main_thread()
    before = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        m = Machine(tmp_path, place=thing(), watch=waits_and_is_ended_by_the_real_interrupt, real_interrupt=True)
        try:
            code, runner = served(m, monkeypatch)
        except KeyboardInterrupt:               # a runner that let it out must fail this test, not end the run
            pytest.fail("the interrupt came out of the runner")
        consumed = True
        try:
            time.sleep(0.05)                    # nothing is left to surface
        except KeyboardInterrupt:
            consumed = False
    finally:
        signal.signal(signal.SIGINT, before)
    assert consumed and code == 0 and "interrupt" in m.log and "not interrupted" not in m.log
    assert runner.outcome[0] == "interrupted" and runner.caught == []
    assert m.statuses() == [(START_PENDING, 0, 0), (RUNNING, 0, 0), (STOP_PENDING, 0, 0), (STOPPED, 0, 0)]
    assert m.text().splitlines()[-1] == ("raqib service run: the watch was stopped before it gave a report (it was"
                                         " interrupted); the Stop was obeyed; the system is told exit 0")


def test_e4_a_stop_after_the_watch_returned_raises_no_interrupt(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), stop=False)
    real = winservice.verdict

    def stop_then(how, result, asked):
        m.handler(CONTROL_STOP)               # the system's Stop, after the watch's call is over
        return real(how, result, asked)
    monkeypatch.setattr(winservice, "verdict", stop_then)
    code, runner = served(m, monkeypatch)
    assert "interrupt" not in m.log and runner.caught == []
    assert m.statuses() == [(START_PENDING, 0, 0), (RUNNING, 0, 0), (STOP_PENDING, 0, 0),
                            (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_WATCH_ENDED)]


def test_e4_a_keyboard_interrupt_in_the_runner_outside_the_watchs_call_is_caught(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing())
    real, calls = winservice.verdict, []

    def interrupted_once(how, result, asked):
        calls.append(how)
        if len(calls) == 1:
            raise KeyboardInterrupt
        return real(how, result, asked)
    monkeypatch.setattr(winservice, "verdict", interrupted_once)
    code, runner = served(m, monkeypatch)
    assert code == 0 and calls == ["returned", "returned"]
    assert runner.caught == ["in the runner, outside the watch's call"] and m.statuses()[-1] == (STOPPED, 0, 0)
    lines = m.text().splitlines()
    assert "raqib service run: an interrupt came in the runner, outside the watch's call; it was caught" in lines[-2]
    assert lines[-1].startswith("raqib service run: the watch returned with 0;") and "is told exit 0" in lines[-1]
    assert runner.finished and runner.decided                    # AG-2: the last line is the watch's end, always


def test_ag2_an_interrupt_inside_the_end_itself_still_leaves_the_last_line_and_the_trace(tmp_path, monkeypatch):
    def fails(machine, argv, out):
        raise ValueError("the watch's own")
    m = Machine(tmp_path, place=thing(), watch=fails)
    runner = winservice.Runner(m)
    real, calls = runner._note, []

    def interrupted_at_the_end_line(text):
        calls.append(text)
        if text.startswith("the watch ended by ValueError") and len([c for c in calls if c == text]) == 1:
            raise KeyboardInterrupt
        return real(text)
    monkeypatch.setattr(runner, "_note", interrupted_at_the_end_line)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    code = runner.run()
    text = m.text()
    assert code == 2 and runner.caught == ["in the runner, outside the watch's call"] and runner.finished
    assert "ValueError: the watch's own" in text and text.splitlines()[-1].startswith(
        "raqib service run: the watch ended by ValueError")
    assert m.statuses()[-1] == (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_WATCH_FAILED)   # the watch's, not 23


class _InterruptsAt:
    """A lock that raises the interrupt once, at its nth entering: the Stop's interrupt surfacing there."""

    def __init__(self, real, nth):
        self.real, self.nth, self.n = real, nth, 0

    def __enter__(self):
        self.n += 1
        if self.n == self.nth:
            raise KeyboardInterrupt
        return self.real.__enter__()

    def __exit__(self, *exc):
        return self.real.__exit__(*exc)


def test_ag2_an_interrupt_right_after_the_watch_returned_keeps_its_result(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), stop=False)
    runner = winservice.Runner(m)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    real = runner._watch

    def watch_with_the_lock_that_interrupts():
        runner.lock = _InterruptsAt(runner.lock, 2)    # 1: before the watch's call; 2: the finally after it returned
        return real()
    monkeypatch.setattr(runner, "_watch", watch_with_the_lock_that_interrupts)
    runner.run()
    assert runner.outcome == ("returned", 0, "") and runner.caught == ["after the watch returned"]
    assert runner.finished and m.text().splitlines()[-1].startswith("raqib service run: the watch returned with 0;")


def test_ag2_an_interrupt_as_the_runner_ended_is_caught_and_the_service_still_stops(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), stop=False)
    runner = winservice.Runner(m)
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    real, calls = runner._end, []

    def end_interrupted_once():
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt
        return real()
    monkeypatch.setattr(runner, "_end", end_interrupted_once)
    runner.run()                                     # nothing comes out of it
    assert len(calls) == 2 and runner.caught == ["as the runner ended"]
    assert m.statuses()[-1][0] == STOPPED and runner.finished


def test_e4_stop_pending_is_never_reported_after_stopped_and_one_stop_is_acted_on_once(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), stop=False)
    code, runner = served(m, monkeypatch)
    told = m.statuses()
    assert told[-1][0] == STOPPED
    runner._control(CONTROL_STOP)
    runner._control(winservice.CONTROL_SHUTDOWN)
    assert m.statuses() == told and "interrupt" not in m.log
    m = Machine(tmp_path)
    runner = winservice.Runner(m)
    runner.handle = "handle"
    runner._control(CONTROL_INTERROGATE)
    assert m.log == []
    runner.watching = True
    runner._control(winservice.CONTROL_SHUTDOWN)
    runner._control(CONTROL_STOP)
    assert m.log == [("status", STOP_PENDING, 0, 0), "interrupt"]


# --- E5: the real object, on Windows only ------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="the system's own calls: Windows only")
def test_e5_the_real_object_makes_a_folder_closed_in_one_call_and_reads_names_by_one_handle(tmp_path):
    system = winservice.System()   # folders of the test's own, under its temp folder; never ProgramData
    place = str(tmp_path / "place")
    assert system.make_closed(place, winservice.MADE_WITH) == 0
    attributes, text = system.read_place(place)
    assert attributes & FOLDER and not attributes & REPARSE
    owner, dacl = winservice.owner_and_list(text)
    assert dacl == CLOSED_AS_MADE, text
    assert system.make_closed(place, winservice.MADE_WITH) == winservice.ALREADY_EXISTS
    (tmp_path / "a file").write_text("x")
    attributes, _ = system.read_place(str(tmp_path / "a file"))
    assert not attributes & FOLDER and not attributes & REPARSE
    with pytest.raises(OSError) as got:
        system.read_place(str(tmp_path / "absent"))
    assert got.value.errno == 2
    target = tmp_path / "target"
    target.mkdir()
    links = []
    try:
        os.symlink(str(target), str(tmp_path / "link"), target_is_directory=True)
        links.append(str(tmp_path / "link"))
    except OSError:
        pass                               # the system refuses a link to this user: that part is skipped
    try:
        import _winapi
        _winapi.CreateJunction(str(target), str(tmp_path / "junction"))
        links.append(str(tmp_path / "junction"))
    except (ImportError, AttributeError, OSError, TypeError):   # a private call of CPython's: absent, refused or
        pass                                                    # changed, that part is not read
    for link in links:
        attributes, _ = system.read_place(link)
        assert attributes & FOLDER and attributes & REPARSE, link
    if owner not in winservice.OWNERS:
        import ctypes
        # Measured (ADR-0013 Amendment G): the same administrator's process makes a folder owned by the
        # administrators from PowerShell (the gate) and by the user himself from Git's bash. The runner would
        # refuse such a place with 13; here it is said, not judged. The service is started by the system (BA).
        assert winservice.owner_and_list(text)[0] == owner and owner
        pytest.skip("this process makes folders owned by %s, not by the system or the administrators (said, not"
                    " judged; admin: %s)" % (owner, bool(ctypes.windll.shell32.IsUserAnAdmin())))
    if not links:
        pytest.skip("neither a link nor a junction could be made here: that part is not read")


# --- M12.4b E3 (ADR-0013 AH-2): after RUNNING, the service waits for the state of the watch before to go stale ---
WAITING = "another host watch's state still holds the place"


def before(machine, age, stale=30, **fields):
    """A made-up state of a watch before, unfinished, its heartbeat `age` s before the Machine's clock."""
    import datetime
    import json
    path = machine.tmp / "place" / ".raqib" / "host" / "rounds.jsonl.watch.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    beat = host.iso(datetime.datetime.fromtimestamp(machine.now - age, datetime.timezone.utc))
    state = dict({"mode": "host", "run": "20261103T115950Z-4242", "pid": 4242, "heartbeat": beat,
                  "stale_after_seconds": stale, "finished": None}, **fields)
    path.write_text(json.dumps(state), encoding="ascii")
    return path


def returns(result):
    def stand_in(machine, argv, out):
        machine.log.append("watch ended")
        return result
    return stand_in


def pauses(machine):
    return [e[1] for e in machine.log if isinstance(e, tuple) and e[0] == "pause"]


@pytest.mark.parametrize("given", ["none", "finished", "stale", "unparsed", "no host watch's"])
def test_ah2_not_held_or_stale_or_unparsed_no_wait_and_no_line(given, tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing())
    if given != "none":
        before(m, 31 if given == "stale" else 2, **{"finished": {"finished": "2026-11-03T11:59:59.000Z"},
                                                   "unparsed": {"heartbeat": "garbled"},
                                                   "no host watch's": {"mode": "project"}}.get(given, {}))
    code, _ = served(m, monkeypatch)
    assert code == 0 and pauses(m) == [] and WAITING not in m.text()
    assert kinds(m, "status", "held", "watch") == [("status", START_PENDING), ("status", RUNNING),
                                                   ("held", PLACE), ("watch", winservice.WATCH_ARGV),
                                                   ("status", STOP_PENDING), ("status", STOPPED)]


def test_ah2_held_and_fresh_one_line_a_wait_asked_every_second_until_stale_then_the_watch(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing())
    before(m, 4)                                  # 4 s old of 30: stale once it is older than 30 s
    code, _ = served(m, monkeypatch)
    assert code == 0 and m.statuses()[-1] == (STOPPED, 0, 0)
    (line,) = [x for x in m.text().splitlines() if WAITING in x]
    assert line == ("raqib service run: another host watch's state still holds the place (run 20261103T115950Z-4242,"
                    " pid 4242, heartbeat 4 s ago, stale after 30 s): it was ended without its end, or it still"
                    " watches; waiting up to 27.0 s for it to go stale, asked again every 1 s, then the watch")
    assert pauses(m) == [1.0] * 27 and m.now == NOW + 27   # asked again each second; stale at 31 s: the watch
    assert kinds(m, "status", "watch")[:3] == [("status", START_PENDING), ("status", RUNNING),
                                               ("watch", winservice.WATCH_ARGV)]
    first_pause = m.log.index(("pause", 1.0))
    assert m.log.index(("status", RUNNING, 0, 0)) < m.log.index(("held", PLACE)) < first_pause
    assert first_pause < m.log.index(("watch", winservice.WATCH_ARGV))   # AF-2's order kept: RUNNING while it waits


def test_ah2_a_state_still_fresh_after_the_wait_the_watch_starts_and_its_refusal_stands_20(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing(), watch=returns(2), stop=False)
    before(m, 10)
    m.on_pause = lambda machine: before(machine, 0.5)   # a living watch: its heartbeat goes on
    code, _ = served(m, monkeypatch)
    assert pauses(m) == [1.0] * 21 and m.now == NOW + 21  # 30 - 10 + 1 s, and no longer
    assert "waiting up to 21.0 s" in m.text() and code == 2
    assert kinds(m, "watch", "watch ended")[0] == ("watch", winservice.WATCH_ARGV)
    assert m.statuses()[-1] == (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_WATCH_REFUSED)


def test_ah2_the_wait_is_bounded_by_60_s_whatever_the_states_staleness(tmp_path, monkeypatch):
    assert winservice.HELD_WAIT_MAX == 60.0 and winservice.HELD_ASK_EVERY == 1.0
    assert winservice.HELD_FRESH == host.HELD_FRESH
    m = Machine(tmp_path, place=thing(), watch=returns(2), stop=False)
    before(m, 1, stale=3600)
    code, _ = served(m, monkeypatch)
    assert "stale after 3600 s" in m.text() and "waiting up to 60.0 s" in m.text()
    assert sum(pauses(m)) == 60.0 and m.now == NOW + 60 and code == 2
    m = Machine(tmp_path / "half", place=thing())
    (tmp_path / "half").mkdir()
    before(m, 2.5, stale=5)                       # 5 - 2.5 + 1 = 3.5 s: the last ask waits the half second left
    served(m, monkeypatch)
    assert pauses(m) == [1.0, 1.0, 1.0] and "waiting up to 3.5 s" in m.text()   # stale at 5.5 s: the third ask


def test_ah2_a_stop_during_the_wait_ends_it_at_once_no_watch_begun_told_0_and_af4s_line(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=thing())
    before(m, 4)
    asked = []

    def stop_at_the_third(machine):
        asked.append(1)
        if len(asked) == 3:
            machine.handler(CONTROL_STOP)
    m.on_pause = stop_at_the_third
    code, _ = served(m, monkeypatch)
    assert code == 0 and len(pauses(m)) == 3 and m.now == NOW + 2   # the third pause returned at once
    assert "interrupt" not in m.log and not kinds(m, "watch")
    assert m.statuses() == [(START_PENDING, 0, 0), (RUNNING, 0, 0), (STOP_PENDING, 0, 0), (STOPPED, 0, 0)]
    assert m.text().count(WAITING) == 1
    assert ("raqib service run: the watch was stopped before it gave a report (it was not begun); the Stop was"
            " obeyed; the system is told exit 0") in m.text().splitlines()


def test_ah2_the_real_objects_wait_returns_at_once_on_a_stop_and_reads_the_watchs_own_state(tmp_path):
    real = winservice.System()
    stop = threading.Event()
    stop.set()
    began = time.monotonic()
    assert real.pause(30, stop) is True and time.monotonic() - began < 5   # never a real wait once a Stop is set
    assert isinstance(real.clock(), float)
    got = real.held(str(tmp_path))
    assert got["held"] == host.HELD_NONE and got["path"] == os.path.join(str(tmp_path), ".raqib", "host",
                                                                         "rounds.jsonl.watch.json")
