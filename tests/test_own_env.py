"""M17.2b (ADR-0007 Amendment CI): what a packed Raqib hands to the programs it starts.

E1 (CI-1): own.handed() - not packed, a copy of the environment value for value; packed, without the packer's
names, and on Linux with the loader's search path put back to what was handed. The fixtures are the environments
Amendment CI measured (what a packed start adds on each system), written with made-up folders and values.
E3 (CI-2): every start of a program in raqib/ names the environment it gives (read by `ast`, not by a pattern).
E4 (CI-3): own.library_folder() - packed and on Windows, SetDllDirectoryW(NULL) once; never an exception.
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

from raqib import own  # noqa: E402

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
# Linux, handed an empty one: _ORIG holds the empty value, and it is what is put back
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


# --- E3 (CI-2): no start in raqib/ without a named environment ------------------------------------------------------
SUBPROCESS_STARTS = {"Popen", "run", "call", "check_call", "check_output"}
OS_STARTS = ("system", "popen", "startfile", "spawn", "exec")   # os.spawn*, os.exec* by their beginning


def _os_start(name):
    return name in ("system", "popen", "startfile") or name.startswith(("spawn", "exec"))


def _given_env(call, function):
    """True where the call gives an environment: env= of a value that is not None, or **name where every
    assignment of that name in its function is a dict holding "env" (a dict display, or dict(..., env=...))."""
    for kw in call.keywords:
        if kw.arg == "env":
            return not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
    for kw in call.keywords:
        if kw.arg is None and isinstance(kw.value, ast.Name) and function is not None:
            values = [n.value for n in ast.walk(function) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == kw.value.id for t in n.targets)]
            if values and all(_dict_with_env(v) for v in values):
                return True
    return False


def _dict_with_env(node):
    if isinstance(node, ast.Dict):
        return any(isinstance(k, ast.Constant) and k.value == "env" for k in node.keys if k is not None)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        return any(k.arg == "env" for k in node.keywords)
    return False


def _scan(source, filename):
    """[(filename, line, what)] of every start in `source` that gives no environment (CI-2)."""
    tree = ast.parse(source, filename)
    modules = {"subprocess": set(), "os": set()}   # the names each module is bound to in this file
    bound = {}                                      # a name bound to a start -> ("subprocess"|"os", its name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in modules:
                    modules[a.name].add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom) and node.module in modules and not node.level:
            for a in node.names:
                if (node.module == "subprocess" and a.name in SUBPROCESS_STARTS) or (
                        node.module == "os" and _os_start(a.name)):
                    bound[a.asname or a.name] = (node.module, a.name)

    def start_of(expr):
        """("subprocess"|"os", name) where expr is a start of one of them, else None."""
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            for module, names in modules.items():
                if expr.value.id in names and ((module == "subprocess" and expr.attr in SUBPROCESS_STARTS) or (
                        module == "os" and _os_start(expr.attr))):
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
    out = []

    def visit(node, function):
        for child in ast.iter_child_nodes(node):
            fn = child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else function
            if isinstance(child, ast.Call):
                found = start_of(child.func)
                if found is None and isinstance(child.func, ast.Attribute) and child.func.attr in bound and not (
                        isinstance(child.func.value, ast.Name) and child.func.value.id in modules["os"]):
                    found = bound[child.func.attr]   # self.runner = subprocess.run ... self.runner(...)
                if found and (found[0] == "os" or not _given_env(child, function)):
                    out.append((filename, child.lineno, "%s.%s" % found))
            visit(child, fn)
    visit(tree, None)
    return out


def test_e3_every_start_in_raqib_names_the_environment_it_gives():
    found = []
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        found += _scan(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
    assert not found, "a start that inherits its environment (ADR-0007 CI-2): %s" % "; ".join(
        "%s line %d: %s" % f for f in found)


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
])
def test_e3_the_scan_finds_a_start_that_inherits_and_names_its_file_and_line(source, lines):
    got = _scan(source, "raqib/made_up.py")
    assert [line for _, line, _ in got] == lines and all(f == "raqib/made_up.py" for f, _, _ in got)


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
