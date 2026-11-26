"""M17.2b (ADR-0007 Amendment CI): what a packed Raqib hands to the programs it starts.

E1 (CI-1): own.handed() - not packed, a copy of the environment value for value; packed, without the packer's
names, and on Linux with the loader's search path put back to what was handed. The fixtures are the environments
Amendment CI measured (what a packed start adds on each system), written with made-up folders and values - all but
LINUX_EMPTY, which is MADE UP and NOT MEASURED (an LD_LIBRARY_PATH handed empty; ADR-0007 CJ-6).
E3 (CI-2), REDO E4 (CJ-4): every start of a program in raqib/ of the kinds tests/test_own_tree.py lists hands on no
whole environment but own.handed(...) (read by `ast`, not by a pattern; what the scan does not see: _scan_all).
E4 (CI-3): own.library_folder() - packed and on Windows, SetDllDirectoryW(NULL) once; never an exception.
REDO E2 (CJ-2), E3 (item 14): own.library_folder_hole() in each state; the words of a result that raised.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "tests"))

from raqib import own  # noqa: E402
from test_own_tree import OTHER_STARTS, STARTS  # noqa: E402  (CJ-4: the one list of starts, the tree's)

FOLDER = "/opt/raqib.example/raqib/_internal"   # a made-up packed program's folder

# What was handed to the packed watch (its starter's environment): the same on every fixture but its loader path.
HANDED = {"HOME": "/home/user.example", "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
          "LC_ALL": "C", "RAQIB_HOME": "/home/user.example/.raqib", "PYTHONPATH": "/srv/elsewhere.example"}
# CI: what a packed start adds, on the three systems
PACKER_ADDED = {"_PYI_ARCHIVE_FILE": FOLDER.rsplit("/", 1)[0] + "/raqib", "_PYI_PARENT_PROCESS_LEVEL": "1"}

# Linux, handed an LD_LIBRARY_PATH: the start puts its own folder first, the handed value behind it, and keeps it
LINUX_HANDED = dict(HANDED, LD_LIBRARY_PATH="/usr/lib/handed.example")
LINUX_WITH = dict(LINUX_HANDED, **PACKER_ADDED, LD_LIBRARY_PATH=FOLDER + ":/usr/lib/handed.example",
                  LD_LIBRARY_PATH_ORIG="/usr/lib/handed.example")
# Linux, handed none: the start sets it to its own folder, and keeps no _ORIG
LINUX_WITHOUT = dict(HANDED, **PACKER_ADDED, LD_LIBRARY_PATH=FOLDER)
# Linux, handed an empty one: MADE UP, NOT MEASURED (CJ-6: no run of CI handed an empty value; what the packer does
# with one is this fixture's guess): _ORIG holds the empty value, and it is what is put back
LINUX_EMPTY_HANDED = dict(HANDED, LD_LIBRARY_PATH="")
LINUX_EMPTY = dict(LINUX_EMPTY_HANDED, **PACKER_ADDED, LD_LIBRARY_PATH=FOLDER + ":", LD_LIBRARY_PATH_ORIG="")
# Windows: os.environ's names are upper case; the system takes a name in any case
WIN_HANDED = {"PATH": "C:\\Windows\\system32;C:\\Windows", "SYSTEMROOT": "C:\\Windows",
              "USERPROFILE": "C:\\Users\\user.example", "LD_LIBRARY_PATH": "C:\\handed.example",
              "LD_LIBRARY_PATH_ORIG": "C:\\orig.example"}
WIN_PACKED = dict(WIN_HANDED, _PYI_ARCHIVE_FILE="C:\\Program Files\\raqib.example\\raqib.exe",
                  _PYI_PARENT_PROCESS_LEVEL="1", _MEIPASS2="C:\\stale.example")
# macOS: the packer adds its two names and touches no DYLD_ name; whatever was handed stays
MAC_HANDED = dict(HANDED, DYLD_LIBRARY_PATH="/usr/local/lib/handed.example",
                  DYLD_INSERT_LIBRARIES="/usr/local/lib/handed.example/x.dylib",
                  DYLD_FALLBACK_LIBRARY_PATH="/usr/lib", LD_LIBRARY_PATH_ORIG="/kept.example")
MAC_PACKED = dict(MAC_HANDED, **PACKER_ADDED)


# --- E1 (CI-1): own.handed ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("env", [LINUX_WITH, LINUX_WITHOUT, WIN_PACKED, MAC_PACKED, {}])
@pytest.mark.parametrize("platform", ["linux", "win32", "darwin"])
@pytest.mark.parametrize("frozen", [False, None, 0, ""])
def test_e1_not_packed_a_copy_equal_value_for_value(env, platform, frozen, monkeypatch):
    """The negative of every fixture: a Raqib that is not packed hands on what it has, every packer's name too."""
    monkeypatch.delattr(sys, "frozen", raising=False)
    got = own.handed(env, frozen=frozen, platform=platform)
    assert got == env and got is not env and type(got) is dict


def test_e1_its_defaults_are_os_environ_sys_frozen_and_sys_platform(monkeypatch):
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "/opt/raqib.example/raqib")
    monkeypatch.setenv("RAQIB_M17_2B_KEPT", "kept")
    monkeypatch.delattr(sys, "frozen", raising=False)
    plain = own.handed()
    assert plain == dict(os.environ) and plain is not os.environ and plain["_PYI_ARCHIVE_FILE"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    packed = own.handed()
    assert "_PYI_ARCHIVE_FILE" not in packed and packed["RAQIB_M17_2B_KEPT"] == "kept"
    assert packed == own.handed(os.environ, frozen=True, platform=sys.platform)
    assert os.environ["_PYI_ARCHIVE_FILE"] == "/opt/raqib.example/raqib"   # os.environ is not changed


@pytest.mark.parametrize("packed,handed", [(LINUX_WITH, LINUX_HANDED), (LINUX_WITHOUT, HANDED),
                                           (LINUX_EMPTY, LINUX_EMPTY_HANDED)])
@pytest.mark.parametrize("platform", ["linux", "linux2"])
def test_e1_linux_packed_gives_exactly_what_was_handed_to_the_packed_start(packed, handed, platform):
    assert own.handed(packed, frozen=True, platform=platform) == handed


def test_e1_linux_packed_every_pyi_name_and_meipass2_go_other_cases_and_names_stay():
    env = dict(LINUX_WITHOUT, _PYI_APPLICATION_HOME_DIR="/x.example", _PYI_ANY_LATER="1", _MEIPASS2="/m.example",
               _pyi_lower="stays", _MEIPASS="stays", PYI_NOT_PREFIXED="stays", X_PYI_="stays")
    got = own.handed(env, frozen=True, platform="linux")
    assert not [k for k in got if k.startswith("_PYI_") or k == "_MEIPASS2"]
    assert {k: got[k] for k in ("_pyi_lower", "_MEIPASS", "PYI_NOT_PREFIXED", "X_PYI_")} == dict.fromkeys(
        ("_pyi_lower", "_MEIPASS", "PYI_NOT_PREFIXED", "X_PYI_"), "stays")
    assert "LD_LIBRARY_PATH" not in got and "LD_LIBRARY_PATH_ORIG" not in got


def test_e1_windows_packed_the_packers_names_go_whatever_their_case_and_nothing_else_moves():
    env = dict(WIN_PACKED, _pyi_archive_file="x", _Pyi_Other="y", _meipass2="z")
    got = own.handed(env, frozen=True, platform="win32")
    assert got == WIN_HANDED   # the loader names are not Linux's here: LD_LIBRARY_PATH and its _ORIG stay as handed


def test_e1_macos_packed_the_dyld_names_stay_as_handed():
    got = own.handed(MAC_PACKED, frozen=True, platform="darwin")
    assert got == MAC_HANDED and got["DYLD_INSERT_LIBRARIES"] == MAC_HANDED["DYLD_INSERT_LIBRARIES"]
    assert own.handed(dict(MAC_PACKED, LD_LIBRARY_PATH=FOLDER), frozen=True, platform="darwin")[
        "LD_LIBRARY_PATH"] == FOLDER   # not Linux: no loader path is put back


@pytest.mark.parametrize("env,platform", [(LINUX_WITH, "linux"), (LINUX_WITHOUT, "linux"), (WIN_PACKED, "win32"),
                                          (MAC_PACKED, "darwin")])
def test_e1_pure_it_starts_nothing_and_changes_neither_its_mapping_nor_os_environ(env, platform, monkeypatch):
    def no_start(*a, **k):
        raise AssertionError("handed() started a program")
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, no_start)
    monkeypatch.setattr(os, "system", no_start)
    before, environ = dict(env), dict(os.environ)
    given = types.MappingProxyType(dict(env))   # a mapping that cannot be changed: a change would raise
    got = own.handed(given, frozen=True, platform=platform)
    assert dict(given) == before and dict(os.environ) == environ and got is not given
    got["NEW"] = "1"   # what it gives is a new dict: a change to it reaches neither the mapping nor os.environ
    assert "NEW" not in given and "NEW" not in os.environ and env == before


# --- E3 (CI-2), REDO E4 (CJ-4): no start in raqib/ hands on a whole environment but own.handed(...) ---------------------
# One list of what starts a program: tests/test_own_tree.py's (STARTS: subprocess's; OTHER_STARTS: os's and asyncio's).
# Of it, these take an environment by name (env=); every other name in it can take none by name and fails outright.
TAKES_ENV = {"Popen", "run", "call", "check_call", "check_output", "create_subprocess_exec", "create_subprocess_shell"}
MODULES = {"subprocess": STARTS, "os": OTHER_STARTS, "asyncio": OTHER_STARTS}   # as test_own_tree.py reads them
# CJ-4: the starts the scan finds in raqib/ today, by (file, function); a scan gone blind finds fewer and fails
RAQIB_STARTS = {("raqib/discover.py", "run_ss"), ("raqib/doctor.py", "run_version"),
                ("raqib/hooks/os_sysmon.py", "read_live"), ("raqib/hooks/os_sysmon.py", "read_live_bounded"),
                ("raqib/notify.py", "run_program"), ("raqib/procevents.py", "start"),
                ("raqib/service.py", "run_systemctl")}


def _scan_all(source, filename, modules=MODULES):
    """[(filename, line, function, what, fault)] of every start in `source`: function is the nearest def that holds
    it ("<module>" where none); fault is None where it names an environment the scan takes, else why not (CJ-4):
    a start in the list that can take no environment by name; env= absent, None, os.environ, dict(os.environ) or
    os.environ.copy() (a copy with more in it too: dict(os.environ, ...), {**os.environ, ...}), as a keyword or as
    the "env" value of a dict given with ** (every plain assignment of that name in its function is read).
    own.handed(...) passes. Any other value passes UNREAD: the scan reads the shape of what is written at the
    start, not what a name holds - `env=env`, or `dict(env)` of a parameter, passes whatever the name was given
    (four of raqib's seven starts give a list of named variables built so; CK-2).

    What it does not see, and so does not fail on (CJ-4): a start reached by getattr(subprocess, "Popen"); a module
    bound again by assignment (sp = subprocess); functools.partial; a subclass of Popen; a start handed to a
    function by position (only defaults and keyword arguments bind); a tuple target; a ** dict changed after it is
    assigned (kw.update, kw["env"] = ..., del, pop, +=); an environment name reached otherwise than by os.environ or
    a name imported from os; an env value held in a name or handed in as a parameter (above); a copy of the whole
    environment written another way (dict(**os.environ), os.environ | {...}, a comprehension over it,
    copy.copy(os.environ), os.environb); the event loop's subprocess_exec and subprocess_shell, pty and
    multiprocessing. It fails on a start of the kinds it lists, not on every start that inherits."""
    tree = ast.parse(source, filename)
    bound_to = {m: set() for m in modules}   # the names each module is bound to in this file
    bound = {}                               # a name bound to a start -> (module, its name)
    environ = set()                          # names bound to os.environ by `from os import environ`
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in modules:
                    bound_to[a.name].add(a.asname or a.name)
                elif a.asname is None and a.name.split(".")[0] in modules:   # import os.path binds os
                    bound_to[a.name.split(".")[0]].add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module in modules and not node.level:
            for a in node.names:
                if a.name == "*":
                    bound.update({n: (node.module, n) for n in modules[node.module]})
                elif a.name in modules[node.module]:
                    bound[a.asname or a.name] = (node.module, a.name)
                elif node.module == "os" and a.name == "environ":
                    environ.add(a.asname or a.name)

    def start_of(expr):
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            for module, names in bound_to.items():
                if expr.value.id in names and expr.attr in modules[module]:
                    return module, expr.attr
        if isinstance(expr, ast.Name) and expr.id in bound:
            return bound[expr.id]
        return None

    for _ in range(3):   # a name bound to a name bound to a start: followed a few steps
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                pairs = [(t, node.value) for t in targets]
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                args = node.args.posonlyargs + node.args.args
                pairs = list(zip(args[len(args) - len(node.args.defaults):], node.args.defaults))
                pairs += [(a, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None]
            elif isinstance(node, ast.keyword) and node.arg:
                pairs = [(types.SimpleNamespace(id=node.arg), node.value)]
            for target, value in pairs:
                values = [value.body, value.orelse] if isinstance(value, ast.IfExp) else (
                    value.values if isinstance(value, ast.BoolOp) else [value])
                for v in values:
                    found = start_of(v)
                    name = getattr(target, "id", None) or getattr(target, "arg", None) or getattr(
                        target, "attr", None)
                    if found and name:
                        bound[name] = found

    def is_environ(node):
        return (isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name)
                and node.value.id in bound_to.get("os", ())) or (isinstance(node, ast.Name) and node.id in environ)

    def value_fault(node):
        if isinstance(node, ast.IfExp):
            return value_fault(node.body) or value_fault(node.orelse)
        if isinstance(node, ast.Constant) and node.value is None:
            return "env None: it inherits"
        if is_environ(node):
            return "env os.environ: the whole environment, the packer's names in it"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict" and (
                node.args and is_environ(node.args[0])):
            return "env dict(os.environ): a copy of the whole environment"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "copy" and (
                is_environ(node.func.value)):
            return "env os.environ.copy(): a copy of the whole environment"
        if isinstance(node, ast.Dict) and any(k is None and is_environ(v) for k, v in zip(node.keys, node.values)):
            return "env {**os.environ}: a copy of the whole environment"
        return None

    def dict_env(node):
        """(True, the env value) for a dict display or dict(...) holding "env", else (False, None)."""
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "env":
                    return True, v
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            for k in node.keywords:
                if k.arg == "env":
                    return True, k.value
        return False, None

    def env_fault(call, function):
        for kw in call.keywords:
            if kw.arg == "env":
                return value_fault(kw.value)
        for kw in call.keywords:
            if kw.arg is not None:
                continue
            if isinstance(kw.value, (ast.Dict, ast.Call)):
                values = [kw.value]
            elif isinstance(kw.value, ast.Name) and function is not None:
                values = [n.value for n in ast.walk(function) if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == kw.value.id for t in n.targets)]
            else:
                values = []
            held = [dict_env(v) for v in values]
            if held and all(has for has, _ in held):
                return next((f for f in (value_fault(v) for _, v in held) if f), None)
        return "no env given: it inherits"

    out = []

    def visit(node, function):
        for child in ast.iter_child_nodes(node):
            fn = child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else function
            if isinstance(child, ast.Call):
                found = start_of(child.func)
                if found is None and isinstance(child.func, ast.Attribute) and child.func.attr in bound and not (
                        isinstance(child.func.value, ast.Name) and any(
                            child.func.value.id in names for names in bound_to.values())):
                    found = bound[child.func.attr]   # self.runner = subprocess.run ... self.runner(...)
                if found:
                    fault = ("%s: not a start that names its environment as env= (CJ-4: it fails outright)" % found[1]) if (
                        found[1] not in TAKES_ENV) else env_fault(child, function)
                    out.append((filename, child.lineno, function.name if function is not None else "<module>",
                                "%s.%s" % found, fault))
            visit(child, fn)
    visit(tree, None)
    return out


def _scan(source, filename, modules=MODULES):
    """[(filename, line, what)] of every start in `source` that hands on a whole environment (CI-2, CJ-4)."""
    return [(f, line, what) for f, line, _, what, fault in _scan_all(source, filename, modules) if fault]


def _raqib(modules=MODULES):
    found = []
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        found += _scan_all(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix(), modules)
    return found


def test_e3_every_start_in_raqib_names_the_environment_it_gives():
    found = _raqib()
    faults = [(f, line, what, fault) for f, line, _, what, fault in found if fault]
    assert not faults, "a start that hands on a whole environment (ADR-0007 CI-2, CJ-4): %s" % "; ".join(
        "%s line %d: %s (%s)" % f for f in faults)
    assert {(f, fn) for f, _, fn, _, _ in found} == RAQIB_STARTS   # CJ-4: what it found, so a blind scan fails


def test_cj4_one_list_of_starts_the_trees_and_a_blind_scan_fails():
    assert TAKES_ENV <= STARTS | OTHER_STARTS and MODULES["subprocess"] is STARTS and MODULES["os"] is OTHER_STARTS
    assert {"getoutput", "getstatusoutput"} <= STARTS - TAKES_ENV   # CJ-4's starts that take no environment
    assert {"system", "popen", "startfile", "fork", "forkpty", "execv", "execve", "spawnv", "spawnve",
            "posix_spawn"} <= OTHER_STARTS - TAKES_ENV
    blind = _raqib({"subprocess": set(), "os": set(), "asyncio": set()})   # a scan with no list finds nothing
    assert blind == []
    # CK-2: a scan that lost one name of the list finds fewer of raqib's starts, and the held set tells it
    less = {(f, fn) for f, _, fn, _, _ in _raqib(dict(MODULES, subprocess=STARTS - {"Popen"}))}
    assert less < RAQIB_STARTS and ("raqib/notify.py", "run_program") in RAQIB_STARTS - less
    assert {(f, fn) for f, _, fn, _, _ in _raqib()} == RAQIB_STARTS


H = "import os, subprocess\nfrom raqib import own\n"   # the head of each fixture below


@pytest.mark.parametrize("source,lines", [
    ("import subprocess\nsubprocess.run(['x'])\n", [2]),                                    # positive: no env
    ("import subprocess\nsubprocess.run(['x'], env=None)\n", [2]),                           # env=None inherits
    ("import subprocess as sp\nsp.Popen(['x'], cwd='/')\n", [2]),                            # an alias
    ("from subprocess import check_output as co\nco(['x'])\n", [2]),                         # a name from it
    ("import subprocess\np = subprocess.Popen\np(['x'])\n", [3]),                            # a name bound to it
    ("import subprocess\ndef f(runner=subprocess.call):\n    runner(['x'])\n", [3]),          # a default
    ("import subprocess\nclass A:\n    def __init__(self):\n        self.go = subprocess.check_call\n"
     "    def b(self):\n        self.go(['x'])\n", [6]),                                     # an attribute
    ("import subprocess\ndef f(p=None):\n    p = p or subprocess.Popen\n    kw = {'cwd': '/'}\n"
     "    p(['x'], **kw)\n", [5]),                                                          # **kw without env
    ("import os\nos.system('x')\nos.popen('x')\nos.execv('x', ['x'])\nos.spawnl(0, 'x')\nos.startfile('x')\n"
     "os.execve('x', ['x'], {})\n", [2, 3, 4, 5, 6, 7]),                                     # os: always found
    ("from os import system\nsystem('x')\n", [2]),
    ("import subprocess\nsubprocess.run(['x'], env={})\nsubprocess.Popen(['x'], env=own.handed())\n", []),
    ("import subprocess\ndef f(p=None):\n    p = p or subprocess.Popen\n    kw = {'cwd': '/', 'env': {}}\n"
     "    p(['x'], **kw)\n", []),                                                           # negative: **kw with env
    ("import os\nos.path.join('a')\nos.getenv('x')\nos.environ.get('x')\n", []),             # negative: no start
    ("def run(x):\n    pass\nrun(['x'])\n", []),                                             # negative: not subprocess's
    # REDO (CJ-4), a positive and a negative for each clause:
    # env absent, as a keyword and in a ** dict
    (H + "subprocess.Popen(['x'], cwd='/')\n", [3]),
    (H + "subprocess.Popen(['x'], cwd='/', env=own.handed())\n", []),
    (H + "def f():\n    kw = dict(cwd='/')\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = dict(cwd='/', env=own.handed())\n    subprocess.run(['x'], **kw)\n", []),
    # env None
    (H + "subprocess.call(['x'], env=None)\n", [3]),
    (H + "subprocess.call(['x'], env=own.handed(None))\n", []),
    (H + "def f():\n    kw = {'env': None}\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = dict(env=None)\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = {'env': own.handed()}\n    subprocess.run(['x'], **kw)\n", []),
    (H + "subprocess.run(['x'], **{'env': None})\n", [3]),
    (H + "subprocess.run(['x'], **{'env': own.handed()})\n", []),
    (H + "subprocess.run(['x'], env=None if own else own.handed())\n", [3]),
    # env os.environ
    (H + "subprocess.check_call(['x'], env=os.environ)\n", [3]),
    (H + "subprocess.check_call(['x'], env=own.handed(os.environ))\n", []),
    ("import os as o, subprocess\nsubprocess.run(['x'], env=o.environ)\n", [2]),
    ("import os.path, subprocess\nsubprocess.run(['x'], env=os.environ)\n", [2]),
    ("from os import environ as e\nimport subprocess\nsubprocess.run(['x'], env=e)\n", [3]),
    (H + "def f():\n    kw = {'env': os.environ}\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = {'env': own.handed(os.environ)}\n    subprocess.run(['x'], **kw)\n", []),
    # env dict(os.environ)
    (H + "subprocess.check_output(['x'], env=dict(os.environ))\n", [3]),
    (H + "subprocess.check_output(['x'], env=dict(os.environ, LC_ALL='C'))\n", [3]),
    (H + "subprocess.check_output(['x'], env={**os.environ})\n", [3]),
    (H + "subprocess.check_output(['x'], env=own.handed(dict(os.environ)))\n", []),
    (H + "subprocess.check_output(['x'], env=dict(LC_ALL='C'))\n", []),                       # a named list
    (H + "def f():\n    kw = dict(env=dict(os.environ))\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = dict(env={'LC_ALL': 'C'})\n    subprocess.run(['x'], **kw)\n", []),
    # env os.environ.copy()
    (H + "subprocess.Popen(['x'], env=os.environ.copy())\n", [3]),
    (H + "subprocess.Popen(['x'], env=own.handed(os.environ.copy()))\n", []),
    (H + "def f():\n    kw = {'env': os.environ.copy()}\n    subprocess.run(['x'], **kw)\n", [5]),
    (H + "def f():\n    kw = {'env': own.handed().copy()}\n    subprocess.run(['x'], **kw)\n", []),
    # a start that can take no environment fails outright, whatever it is given
    (H + "subprocess.getoutput('x')\nsubprocess.getstatusoutput('x')\nos.fork()\nos.forkpty()\n"
     "os.posix_spawn('x', ['x'], own.handed())\nos.spawnve(0, 'x', ['x'], own.handed())\n"
     "os.execvpe('x', ['x'], own.handed())\n", [3, 4, 5, 6, 7, 8, 9]),
    ("from subprocess import getoutput\ngetoutput('x')\n", [2]),
    ("from subprocess import *\ngetstatusoutput('x')\nrun(['x'])\n", [2, 3]),
    (H + "os.getpid()\nos.getcwd()\nsubprocess.list2cmdline(['x'])\n", []),                 # negative: no start
    # CK-2: the three roads a name is bound to a start by, each with a positive and a negative
    ("import subprocess\np: object = subprocess.Popen\np(['x'])\n", [3]),                   # an annotated assignment
    (H + "p: object = subprocess.Popen\np(['x'], env=own.handed())\n", []),
    ("import subprocess\ndef g(runner):\n    runner(['x'])\ng(runner=subprocess.run)\n", [3]),   # a keyword argument
    (H + "def g(runner):\n    runner(['x'], env=own.handed())\ng(runner=subprocess.run)\n", []),
    ("import subprocess\np = subprocess.Popen if 1 else subprocess.run\np(['x'])\n", [3]),   # one of two
    (H + "p = subprocess.Popen if 1 else subprocess.run\np(['x'], env=own.handed())\n", []),
    # asyncio's starts take an environment as subprocess's do
    ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec('x')\n", [3]),
    ("import asyncio\nfrom raqib import own\nasync def f():\n"
     "    await asyncio.create_subprocess_shell('x', env=own.handed())\n", []),
])
def test_e3_the_scan_finds_a_start_that_inherits_and_names_its_file_and_line(source, lines):
    got = _scan(source, "raqib/made_up.py")
    assert [line for _, line, _ in got] == lines and all(f == "raqib/made_up.py" for f, _, _ in got)


def test_cj4_the_scan_holds_each_start_by_file_and_function():
    source = H + ("def a():\n    subprocess.run(['x'], env=own.handed())\n"
                  "class B:\n    def b(self):\n        return subprocess.getoutput('x')\n"
                  "subprocess.call(['x'], env={})\n")
    got = [(f, fn, what, fault is None) for f, _, fn, what, fault in _scan_all(source, "raqib/made_up.py")]
    assert got == [("raqib/made_up.py", "a", "subprocess.run", True),
                   ("raqib/made_up.py", "b", "subprocess.getoutput", False),
                   ("raqib/made_up.py", "<module>", "subprocess.call", True)]


# --- E4 (CI-3): own.library_folder ---------------------------------------------------------------------------------
@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(own, "LIBRARY_FOLDER", None)
    calls = []

    def stand_in(result):
        def call(folder):
            calls.append(folder)
            if isinstance(result, BaseException):
                raise result
            return result
        return call
    stand_in.calls = calls
    return stand_in


def test_e4_packed_on_windows_called_once_with_null_and_put_back(fresh):
    assert own.library_folder(call=fresh(1), frozen=True, platform="win32") is True
    assert own.library_folder(call=fresh(1), frozen=True, platform="win32") is None   # once in this process
    assert fresh.calls == [None] and own.LIBRARY_FOLDER is True and own.library_folder_hole() is None


@pytest.mark.parametrize("frozen,platform", [(False, "win32"), (None, "win32"), (True, "linux"), (True, "darwin"),
                                             (True, "freebsd14"), (False, "linux")])
def test_e4_not_called_where_plain_where_linux_where_macos(frozen, platform, fresh, monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert own.library_folder(fresh(1), frozen=frozen, platform=platform) is None
    assert own.library_folder(fresh(1), frozen=frozen, platform=platform) is None
    assert fresh.calls == [] and own.LIBRARY_FOLDER is None and own.library_folder_hole() is None


@pytest.mark.parametrize("result,words", [
    (0, "SetDllDirectoryW(NULL) returned 0"), (False, "SetDllDirectoryW(NULL) returned False"),
    (OSError(87, "The parameter is incorrect"), "SetDllDirectoryW(NULL) failed: OSError: [Errno 87] The parameter"),
    (RuntimeError("caf\u00e9\nnext"), "SetDllDirectoryW(NULL) failed: RuntimeError: caf next"),
])
def test_e4_a_stand_in_that_returns_0_or_raises_is_a_result_said_in_words_never_an_exception(result, words, fresh):
    got = own.library_folder(call=fresh(result), frozen=True, platform="win32")
    assert isinstance(got, str) and got.startswith(words) and got.isascii() and "\n" not in got
    hole = own.library_folder_hole()
    assert hole.startswith("what the watch starts searches the packed program's folder first for its libraries")
    assert words in hole and hole.isascii() and fresh.calls == [None]


FAILURE = "SetDllDirectoryW(NULL) returned 0"


@pytest.mark.parametrize("kept,frozen,platform,said", [
    (None, True, "win32", "no call"),     # packed, Windows, no call made in this process: words of its own
    (None, 1, "win32", "no call"),
    (None, False, "win32", None),         # not packed
    (None, None, "win32", None),          # not packed: sys.frozen absent
    (None, True, "linux", None),          # not Windows
    (None, True, "darwin", None),
    (True, True, "win32", None),          # put back
    (FAILURE, True, "win32", "failed"),   # the call failed
    (FAILURE, False, "linux", "failed"),  # a failure kept is said whatever is asked
])
def test_cj2_the_hole_in_each_state_and_own_library_folder_reset_around_it(kept, frozen, platform, said,
                                                                           monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    before = own.LIBRARY_FOLDER
    own.LIBRARY_FOLDER = kept
    try:
        got = own.library_folder_hole(frozen=frozen, platform=platform)
    finally:
        own.LIBRARY_FOLDER = before
    assert own.LIBRARY_FOLDER is before
    if said is None:
        assert got is None
    elif said == "no call":
        assert got == own.LIBRARY_NO_CALL and "was not put back, because this entry made no call" in got
        assert got.startswith("the folder Windows searches first for a library was not put back") and got.isascii()
        assert "was not measured" in got and "may search the packed program's folder first" in got   # CK-1
    else:
        assert got == own.LIBRARY_HOLE % FAILURE and FAILURE in got and "made no call" not in got


def test_cj2_its_defaults_are_sys_frozen_and_sys_platform_and_a_call_made_ends_it(fresh, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert own.library_folder_hole() == (own.LIBRARY_NO_CALL if sys.platform == "win32" else None)
    monkeypatch.setattr(sys, "platform", "win32")
    assert own.library_folder_hole() == own.LIBRARY_NO_CALL
    assert own.library_folder(fresh(1)) is True and own.library_folder_hole() is None   # put back: nothing said
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert own.library_folder_hole(frozen=True) is None


class _NoTruth:
    def __bool__(self):
        raise ValueError("no truth")


class _NoWords:
    def __bool__(self):
        return False

    def __repr__(self):
        raise ValueError("no words")


class _ExcNoWords(Exception):
    def __str__(self):
        raise ValueError("no words")


@pytest.mark.parametrize("result,words", [
    (_NoTruth(), "SetDllDirectoryW(NULL) was called, its result could not be read: ValueError: no truth"),
    (_NoWords(), "SetDllDirectoryW(NULL) was called, its result could not be read: ValueError: no words"),
    (_ExcNoWords(), "SetDllDirectoryW(NULL) failed: _ExcNoWords: its own words could not be read"),
])
def test_cj6_a_result_that_raised_while_it_was_read_is_said_as_it_happened(result, words, fresh):
    got = own.library_folder(fresh(result), frozen=True, platform="win32")
    assert got == words and fresh.calls == [None] and "was not called" not in got   # the call was made
    assert own.library_folder_hole() == own.LIBRARY_HOLE % words


def test_cj6_a_frozen_state_that_cannot_be_read_is_not_called_and_said_so(fresh):
    got = own.library_folder(fresh(1), frozen=_NoTruth(), platform="win32")
    assert got == "SetDllDirectoryW(NULL) was not called: ValueError: no truth" and fresh.calls == []
    assert own.library_folder_hole(frozen=_NoTruth(), platform="win32") == own.LIBRARY_HOLE % got


def test_ck3_a_state_that_cannot_be_read_with_no_call_kept_is_said_not_taken_for_none(fresh):
    got = own.library_folder_hole(frozen=_NoTruth(), platform="win32")   # no call was made, and frozen has no truth
    assert got == own.LIBRARY_UNREAD % "ValueError: no truth" and got.isascii() and "could not be told" in got
    assert own.library_folder_hole(frozen=False, platform="win32") is None and own.LIBRARY_FOLDER is None


def test_e4_own_imports_no_ctypes_the_call_is_given_to_it():
    tree = ast.parse((ROOT / "raqib" / "own.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    assert "ctypes" not in names and "wintypes" not in names


def test_e1_e4_the_files_are_ascii():
    for path in ("raqib/own.py", "tests/test_own_env.py"):
        assert (ROOT / path).read_text(encoding="utf-8").isascii(), path


def test_e5_the_spec_and_the_threat_model_say_what_the_packed_helper_is_handed():
    threat = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
    spec = " ".join((ROOT / "docs" / "specs" / "PROC-EVENTS.md").read_text(encoding="utf-8").split())
    assert "was not measured (CH-3)" not in threat
    for words in ("CI-1, built", "CI-3, built", "Not held (CI-4)", "LD_PRELOAD", "who starts it",
                  "searches the packed program's folder first for its libraries", "`_PYI_PARENT_PROCESS_LEVEL`"):
        assert words in threat, words
    for words in ("`env=own.handed()`", "`_MEIPASS2`", "LD_LIBRARY_PATH_ORIG", "value for value", "CI-2"):
        assert words in spec, words


def _flat(*parts):
    return " ".join((ROOT.joinpath(*parts)).read_text(encoding="utf-8").split())


def test_cj6_the_documents_say_what_was_measured_and_no_more():
    threat, spec = _flat("docs", "THREAT_MODEL.md"), _flat("docs", "specs", "PROC-EVENTS.md")
    for gone, where in (("not measured beyond that run", spec),                                   # item 17
                        ("none of the interpreter's PYTHON* variables", threat),                  # item 18
                        ("none of the interpreter's PYTHON* variables", spec),
                        ("does not have the packed program's folder first", threat),              # item 19
                        ("so wevtutil, PowerShell and whatever the watch starts load", threat),   # item 20
                        ("fails on a start that inherits", spec),                                 # item 21
                        ("hands its environment on value for value", threat),                    # item 22
                        ("starts from the environment the watch was handed", spec),
                        ("put back to the value the watch was handed", threat),                   # item 27
                        ("as a hole of its own", threat)):                                        # CJ-1
        assert gone not in where, gone
    for words in ("none of the ten interpreter's variables tried", "PYTHONWARNINGS", "`cli.main`", "blind spot",
                  "is not handed the packed program's folder first", "puts its folder first again",
                  "to the helper alone", "where that name is the packer's", "only it", "CJ-3", "CJ-2"):
        assert words in threat, words
    for words in ("none of the ten interpreter's variables tried", "`cli.main` alone", "not on every start that"
                  " inherits", "`getoutput`", "`os.environ.copy()`", "the set of starts", "is dropped too",
                  "is not handed them", "CJ-1", "CJ-2", "CJ-3", "CJ-4"):
        assert words in spec, words
    # CJ-6's three things not measured, said so in both
    for doc in (threat, spec):
        assert "LD_LIBRARY_PATH_ORIG itself" in doc and "handed empty" in doc and "not measured on a real machine" in doc


def test_cj5_cj6_the_modules_say_what_they_do():
    procevents, own_words = _flat("raqib", "procevents.py"), _flat("raqib", "own.py")
    assert "The standard library only." not in procevents
    assert "The served program (SERVE_PROGRAM, serve, main) is the standard library only; the client's start" \
           " (Helper.start) takes the helper's environment from raqib.own" in procevents
    assert "no process started or touched" not in own_words                                      # item 29
    assert "changes this process's own library search" in own_words and "cli.main alone" in own_words
