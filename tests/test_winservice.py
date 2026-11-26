"""M12.4a (ADR-0013 Amendment E, AE-1 to AE-4): `raqib service run`, the host watch as a service of Windows.

Every call of the system goes through a made-up Windows (Machine, in place of winservice.System): no test here
needs Windows, a service manager or ProgramData, and none makes a user, a service or a folder under ProgramData.
The place is a record in the Machine; the text file is a real file in the test's own temp folder. One test,
skipped off Windows, reads a scratch folder's owner and list through the real object and closes it (E5).
"""
import ast
import io
import ntpath
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, winservice  # noqa: E402
from raqib.winservice import (CLOSED, CONTROL_INTERROGATE, CONTROL_STOP, RUNNING, SERVICE_SPECIFIC,  # noqa: E402
                              STOP_PENDING, STOPPED)

PLACE = "C:\\ProgramData\\Raqib"
OPEN = "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
STRANGER = "S-1-5-21-1004336348-1177238915-682003330-1001"


def args(**kw):
    return SimpleNamespace(action="run", no_start=kw.get("no_start", False), purge=kw.get("purge", False))


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
    change or tell something (statuses, the interrupt, the place's making, closing and reading, the watch)."""

    def __init__(self, tmp, place=None, program_data="C:\\ProgramData", manager=True, result=0, stop=True,
                 platform="win32", made_owner="SY", close_gives=None, planted=False, watch=ends_on_the_interrupt,
                 unreadable=False, on_text=None):
        self.tmp, self.manager, self.result, self.stop = tmp, manager, result, stop
        self.place = None if place is None else dict(place, items=list(place["items"]))   # its own copy
        self.env = {} if program_data is None else {"ProgramData": program_data}
        self.os, self.made_owner, self.close_gives, self.planted = platform, made_owner, close_gives, planted
        self.watch_fn, self.unreadable, self.on_text = watch, unreadable, on_text
        self.log, self.handler, self.interrupted = [], None, threading.Event()

    def platform(self):
        return self.os

    def getenv(self, name):
        return self.env.get(name)

    def setenv(self, name, value):
        self.env[name] = value
        self.log.append(("setenv", name, value))

    def dispatch(self, name, main):
        self.log.append(("dispatch", name))
        if not self.manager:
            return winservice.NOT_BY_THE_MANAGER
        t = threading.Thread(target=main, name="service-main")   # the system calls the service's main so
        t.start()
        t.join(30)
        return 0

    def register(self, name, handler):
        self.handler = handler
        return "handle"

    def set_status(self, handle, state, accepted, win32_exit, specific_exit, wait_hint):
        assert handle == "handle"
        self.log.append(("status", state, win32_exit, specific_exit))
        return True

    def raise_interrupt(self):
        self.log.append("interrupt")
        self.interrupted.set()

    def kind(self, path):
        assert path == PLACE
        return "absent" if self.place is None else self.place["kind"]

    def make_folder(self, path):
        assert path == PLACE and self.place is None
        self.log.append(("make", path))
        self.place = {"kind": "folder", "owner": self.made_owner, "dacl": OPEN, "items": []}

    def listdir(self, path):
        assert path == PLACE
        return list(self.place["items"])

    def read_security(self, path):
        assert path == PLACE
        if self.unreadable:
            raise OSError(5, "Access is denied")
        self.log.append(("read", path))
        return self.place["owner"], self.place["dacl"]

    def close_folder(self, path, sddl):
        assert path == PLACE and sddl == CLOSED
        self.log.append(("close", path))
        self.place["dacl"] = self.close_gives or sddl
        if self.planted:
            self.place["items"].append("planted.txt")

    def begin_text(self, path, before):
        assert ntpath.dirname(path) == PLACE and ntpath.dirname(before) == PLACE
        self.log.append(("text", ntpath.basename(path)))
        if self.on_text:
            self.on_text(self)
        return winservice.System().begin_text(str(self.tmp / ntpath.basename(path)),
                                              str(self.tmp / ntpath.basename(before)))

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


def place(kind="folder", owner="SY", dacl=CLOSED, items=()):
    return {"kind": kind, "owner": owner, "dacl": dacl, "items": list(items)}


# --- E1 (AE-1) ---------------------------------------------------------------------------------------------------
def test_e1_not_windows_one_line_exit_2_and_nothing_asked_of_the_system(tmp_path, capsys):
    for platform in ("linux", "darwin"):
        m = Machine(tmp_path, platform=platform)
        assert winservice.cli_run(args(), io.StringIO(), system=m) == 2
        out, err = capsys.readouterr()
        assert out == "" and err == ("raqib: raqib service run: Windows only (the system's service manager runs it);"
                                     " this is %s\n" % platform)
        assert m.log == []


def test_e1_not_started_by_the_service_manager_1063_said_no_watch_exit_2(tmp_path, capsys):
    m = Machine(tmp_path, manager=False)
    assert winservice.cli_run(args(), io.StringIO(), system=m) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "not started by the service manager (error 1063)" in err
    assert "no watch started" in err
    assert m.log == [("dispatch", winservice.SERVICE_NAME)]   # no place touched, no status, no watch


def test_e1_running_reported_before_the_watch_started_by_the_entry_with_the_units_arguments(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=place())
    code, _ = served(m, monkeypatch)
    assert code == 0
    assert winservice.WATCH_ARGV == ("watch", "--host", "--no-page", "--no-notify")
    assert m.log.index(("status", RUNNING, 0, 0)) < m.log.index(("watch", winservice.WATCH_ARGV))


def test_e1_the_real_objects_watch_is_cli_main_with_the_text_file(monkeypatch):
    got = []
    monkeypatch.setattr(cli, "main", lambda argv, out: got.append((argv, out)) or 0)
    out = io.StringIO()
    assert winservice.System().watch(winservice.WATCH_ARGV, out) == 0
    assert got == [(["watch", "--host", "--no-page", "--no-notify"], out)]


def test_e1_the_other_actions_flags_are_refused_with_run(tmp_path, capsys):
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


def test_e1_cli_service_run_is_handed_to_winservice(monkeypatch):
    got = []
    monkeypatch.setattr(winservice, "cli_run", lambda a, out: got.append(a.action) or 7)
    assert cli.main(["service", "run"], io.StringIO()) == 7 and got == ["run"]


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: the one line of a command that is Windows'")
def test_e1_cli_service_run_off_windows_one_line_exit_2(capsys):
    assert cli.main(["service", "run"], io.StringIO()) == 2
    out, err = capsys.readouterr()
    assert out == "" and err == ("raqib: raqib service run: Windows only (the system's service manager runs it);"
                                 " this is %s\n" % sys.platform)


# --- E2 (AE-2) ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("given, road, closes", [
    (None, "made", True),                                     # absent: made, closed, read back
    (place(owner="BA", dacl=OPEN), "closed", True),           # open and empty: closed, read back
    (place(owner="SY", items=["x"]), "taken as it is", False),   # closed and owned right: taken as it is
])
def test_e2_the_roads_that_end_closed_and_owned_right(given, road, closes, tmp_path, monkeypatch):
    m = Machine(tmp_path, place=given)
    assert winservice.prepare(m) == (PLACE, road, m.place["owner"])
    assert (("close", PLACE) in m.log) is closes and (("make", PLACE) in m.log) is (given is None)
    assert m.log[-1] == ("read", PLACE) and m.place["dacl"] == CLOSED   # read back last
    if given is not None and not closes:
        assert m.place["items"] == ["x"]                      # an existing closed place's contents untouched
    m = Machine(tmp_path, place=given)
    code, runner = served(m, monkeypatch)
    assert code == 0 and m.env["HOME"] == PLACE and m.env["USERPROFILE"] == PLACE
    assert m.log.index(("setenv", "HOME", PLACE)) < m.log.index(("watch", winservice.WATCH_ARGV))
    assert "the place %s (%s; owner" % (PLACE, road) in m.text()


@pytest.mark.parametrize("kw, number, words", [
    ({"program_data": None}, winservice.EXIT_NO_PROGRAMDATA, "absent from the environment"),
    ({"program_data": "ProgramData"}, winservice.EXIT_NO_PROGRAMDATA, "not a whole path of a drive"),
    ({"program_data": "\\\\server.example\\share"}, winservice.EXIT_NO_PROGRAMDATA, "not a whole path of a drive"),
    ({"program_data": "C:\\Users\\..\\ProgramData"}, winservice.EXIT_NO_PROGRAMDATA, "not a whole path"),
    ({"place": place(kind="link")}, winservice.EXIT_LINK, "is a link"),
    ({"place": place(kind="other")}, winservice.EXIT_NOT_FOLDER, "is not a folder"),
    ({"place": place(owner=STRANGER, dacl=OPEN)}, winservice.EXIT_OWNER, "is owned by " + STRANGER),
    ({"place": place(owner=STRANGER)}, winservice.EXIT_OWNER, "neither the system (SY) nor the administrators"),
    ({"place": place(owner="BA", dacl=OPEN, items=["left.txt"])}, winservice.EXIT_OPEN, "is open"),
    ({"made_owner": STRANGER}, winservice.EXIT_OWNER, "is owned by"),
    ({"close_gives": CLOSED + "(A;OICI;FR;;;BU)"}, winservice.EXIT_NOT_CLOSED, "read back"),
    ({"place": place(owner="SY", dacl=OPEN), "close_gives": OPEN}, winservice.EXIT_NOT_CLOSED, "read back"),
    ({"planted": True}, winservice.EXIT_NOT_CLOSED, "was not empty after it was closed"),
    ({"place": place(), "unreadable": True}, winservice.EXIT_NOT_CLOSED, "could not be read"),
])
def test_e2_each_refusal_starts_no_watch_and_stops_with_its_own_number(kw, number, words, tmp_path, monkeypatch,
                                                                       capsys):
    m = Machine(tmp_path, **kw)
    with pytest.raises(winservice.Refusal) as got:
        winservice.prepare(m)
    assert got.value.number == number and words in got.value.words
    if number in (winservice.EXIT_LINK, winservice.EXIT_NOT_FOLDER, winservice.EXIT_OPEN) or "place" in kw and \
            number == winservice.EXIT_OWNER:
        assert ("close", PLACE) not in m.log                   # refused before anything is changed
    m = Machine(tmp_path, **kw)
    code, runner = served(m, monkeypatch)
    assert code == 2 and runner.text is None
    assert not [e for e in m.log if isinstance(e, tuple) and e[0] in ("watch", "setenv", "text")]
    assert m.statuses() == [(RUNNING, 0, 0), (STOPPED, SERVICE_SPECIFIC, number)]
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "no watch started (exit %d to the system" % number in err


def test_e2_the_closed_list_is_one_constant():
    assert winservice.CLOSED == "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" and winservice.OWNERS == ("SY", "BA")
    assert winservice.PLACE_NAME == "Raqib" and winservice.HOME_NAMES == ("HOME", "USERPROFILE")


# --- E3 (AE-3) ---------------------------------------------------------------------------------------------------
def test_e3_the_text_file_is_bounded_and_its_last_line_says_so_once():
    raw = io.BytesIO()
    text = winservice.Text(raw, bound=200)
    for i in range(50):
        text.write("line %d of the watch's report\n" % i)
    text.write("partial")
    data = raw.getvalue()
    assert len(data) <= 200 and data.endswith(winservice.FULL_LINE.encode("ascii")) and len(data) > 150
    assert data.count(b"reached its bound") == 1 and b"line 0 " in data and b"line 49" not in data
    raw = io.BytesIO()
    text = winservice.Text(raw, bound=200)
    text.write("no end of line " * 4)
    text.write("x" * 200)
    assert raw.getvalue().split(b"\n")[1] + b"\n" == winservice.FULL_LINE.encode("ascii")   # on a line of its own
    assert len(raw.getvalue()) <= 200
    assert winservice.TEXT_MAX == 8 * 1024 * 1024 and str(winservice.TEXT_MAX) in winservice.FULL_LINE


def test_e3_begun_anew_at_each_start_the_one_before_kept_once(tmp_path):
    system = winservice.System()
    now, before = str(tmp_path / winservice.TEXT_NAME), str(tmp_path / winservice.TEXT_BEFORE)
    for n in (1, 2, 3):
        with system.begin_text(now, before) as f:
            f.write(b"start %d\n" % n)
    assert (tmp_path / winservice.TEXT_NAME).read_bytes() == b"start 3\n"
    assert (tmp_path / winservice.TEXT_BEFORE).read_bytes() == b"start 2\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([winservice.TEXT_NAME, winservice.TEXT_BEFORE])


def test_e3_streams_that_are_none_are_the_text_file_and_the_watch_prints_and_writes_errors(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=place())
    code, runner = served(m, monkeypatch, streams=(None, None))
    assert code == 0 and sys.stdout is runner.text and sys.stderr is runner.text
    said = m.text()
    for line in ("a report line\n", "an error line\n", "stopped (Ctrl-C)\n"):
        assert line in said, line
    assert said.splitlines()[0].startswith("raqib service run: the place %s" % PLACE)
    assert said.splitlines()[-1].startswith("raqib service run: the watch returned with 0; a Stop was asked;"
                                            " the system is told exit 0")


# --- E4 (AE-4) ---------------------------------------------------------------------------------------------------
def test_e4_stop_pending_the_interrupt_the_watchs_end_stopped_in_that_order(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=place())
    code, _ = served(m, monkeypatch)
    assert code == 0
    told = [e if isinstance(e, str) else e[:2] for e in m.log
            if e in ("interrupt", "watch ended") or isinstance(e, tuple) and e[0] in ("status", "watch")]
    assert told == [("status", RUNNING), ("watch", winservice.WATCH_ARGV), ("status", STOP_PENDING), "interrupt",
                    "watch ended", ("status", STOPPED)]
    assert m.statuses()[-1] == (STOPPED, 0, 0)


@pytest.mark.parametrize("result, stop, number", [
    (0, True, 0), (1, True, 0), (3, True, 0),                   # a watch's result is no failure of the service
    (2, True, winservice.EXIT_WATCH_REFUSED), (2, False, winservice.EXIT_WATCH_REFUSED),
    (0, False, winservice.EXIT_WATCH_ENDED), (1, False, winservice.EXIT_WATCH_ENDED),
    (None, True, winservice.EXIT_WATCH_ENDED),
])
def test_e4_the_watchs_result_and_the_systems_exit(result, stop, number, tmp_path, monkeypatch):
    m = Machine(tmp_path, place=place(), result=result, stop=stop)
    code, _ = served(m, monkeypatch)
    assert code == (0 if number == 0 else 2)
    assert m.statuses()[-1] == ((STOPPED, 0, 0) if number == 0 else (STOPPED, SERVICE_SPECIFIC, number))
    assert ("interrupt" in m.log) is stop


def test_e4_an_exception_out_of_the_watch_is_its_own_number_and_its_trace_is_in_the_text(tmp_path, monkeypatch):
    def breaks(machine, argv, out):
        raise RuntimeError("the watch broke")
    m = Machine(tmp_path, place=place(), watch=breaks)
    code, _ = served(m, monkeypatch)
    assert code == 2 and m.statuses()[-1] == (STOPPED, SERVICE_SPECIFIC, winservice.EXIT_WATCH_FAILED)
    assert "RuntimeError: the watch broke" in m.text() and "the watch ended by RuntimeError" in m.text()


def test_e4_a_stop_before_the_watch_begins_begins_none_and_raises_no_interrupt(tmp_path, monkeypatch):
    m = Machine(tmp_path, place=place(), on_text=lambda machine: machine.handler(CONTROL_STOP))
    code, _ = served(m, monkeypatch)
    assert code == 0 and "interrupt" not in m.log
    assert not [e for e in m.log if isinstance(e, tuple) and e[0] == "watch"]
    assert m.statuses() == [(RUNNING, 0, 0), (STOP_PENDING, 0, 0), (STOPPED, 0, 0)]


def test_e4_one_stop_is_acted_on_once_and_other_controls_change_nothing(tmp_path):
    m = Machine(tmp_path)
    runner = winservice.Runner(m)
    runner.handle = "handle"
    runner._control(CONTROL_INTERROGATE)
    assert m.log == []
    runner.watching = True
    runner._control(winservice.CONTROL_SHUTDOWN)
    runner._control(CONTROL_STOP)
    assert m.log == [("status", STOP_PENDING, 0, 0), "interrupt"]


def test_e4_the_numbers_are_constants_each_its_own_and_listed_in_the_spec_with_their_words():
    numbers = [getattr(winservice, n) for n in dir(winservice) if n.startswith("EXIT_") and n != "EXIT_WORDS"]
    assert sorted(numbers) == sorted(winservice.EXIT_WORDS) and len(set(numbers)) == len(numbers) == 10
    spec = (ROOT / "docs" / "specs" / "SERVICE.md").read_text(encoding="utf-8")
    for number, words in winservice.EXIT_WORDS.items():
        assert "| %d | %s |" % (number, words) in spec, number
    assert winservice.SERVICE_SPECIFIC == 1066 and 0 not in winservice.EXIT_WORDS


# --- E5: the real object, on Windows only ------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="the system's own calls: Windows only")
def test_e5_the_real_object_reads_a_scratch_folders_owner_and_list_and_closes_it(tmp_path):
    folder = tmp_path / "scratch"   # a folder of the test's own, under its temp folder; never ProgramData
    folder.mkdir()
    system = winservice.System()
    assert system.kind(str(folder)) == "folder" and system.kind(str(tmp_path / "absent")) == "absent"
    owner, before = system.read_security(str(folder))
    assert owner and not owner.startswith("O:") and before.startswith("D:") and before != CLOSED
    system.close_folder(str(folder), CLOSED)
    assert system.read_security(str(folder)) == (owner, CLOSED)
