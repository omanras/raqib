"""M12.4c2a (ADR-0013 Amendment P, P-2): every library Raqib loads by name, held by one list.

Read in the interpreter's library (Lib/ctypes/__init__.py at 3.11.9 and 3.12.10; Amendment P), not measured: a
library asked for by a bare name is searched with the system's default folders - the application's own folder,
System32, and folders the process itself added - and not along the PATH or in the folder the process was started in.
So this test reads every .py file of raqib/ by its syntax tree and finds every place a library is loaded: ctypes'
classes (WinDLL, CDLL, OleDLL, PyDLL), its loaders (windll, cdll, oledll, pydll) by attribute and by LoadLibrary,
ctypes.util.find_library, and each of Raqib's own loader functions that take a name (found by the scan: a load whose
name is a parameter of the function that holds it; then every call of that function is read). It holds: every name
given is a string written in the code - followed through a name bound in its function to a table of strings at the
top of its module, or failed - with no path separator and no dot but a final `.dll`, and on one list (LIBRARIES); no
call gives a search mode (winmode); nothing adds a folder to the search, sets PATH (os.environ, os.putenv; a setter
that takes the variable's name is followed to its callers as a loader is) or loads by a name worked out at run time.
The one call that takes a folder off the search, SetDllDirectoryW with no folder (ADR-0007 CI-3, raqib/cli.py), is
named and allowed as what it is. On Windows only: each name of the list is a file in System32.

What the scan does not see, and so does not fail on: a load reached by a name bound again (k = ctypes.WinDLL; k(x)),
by functools.partial or by a subclass; a module bound by assignment; exec or importlib; whether a library's own
dependencies are searched as the library is (Amendment P: not measured).
"""
import ast
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

CLASSES = ("WinDLL", "CDLL", "OleDLL", "PyDLL")         # ctypes' classes that load a library by its name
LOADERS = ("windll", "cdll", "oledll", "pydll")         # ctypes' LibraryLoader objects: X.name, X.LoadLibrary(name)
FINDERS = ("find_library",)                             # ctypes.util: searches the PATH's folders on Windows
SEARCH = ("SetDllDirectoryW", "SetDllDirectoryA", "AddDllDirectory", "RemoveDllDirectory", "SetDefaultDllDirectories",
          "LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA", "LoadPackagedLibrary",
          "add_dll_directory")                          # the system's calls that change the search, or load past it
# ADR-0007 CI-3: the one call of SEARCH in raqib/, which puts the folder searched first back to the system's own
ALLOWED_SEARCH = {("raqib/cli.py", "main.set_dll_directory_w", "SetDllDirectoryW")}
# P-2: the one list - every name raqib/ loads a library by
LIBRARIES = ("advapi32", "dnsapi", "dwmapi", "iphlpapi", "kernel32", "shcore", "shell32", "user32")
# What the scan finds in raqib/ today: (file, function, form); a scan gone blind finds fewer and fails
RAQIB_LOADS = {
    ("raqib/app.py", "_win_api.Api.SetProcessDpiAwareness", "windll"),
    ("raqib/app.py", "_win_api.Api.DwmSetWindowAttribute", "windll"),
    ("raqib/autostart.py", "_windows_opener", "WinDLL"),
    ("raqib/autostart.py", "_windows_drive_kind", "WinDLL"),
    ("raqib/cli.py", "main.set_dll_directory_w", "WinDLL"),
    ("raqib/etwnet.py", "Api.__init__", "loader"),
    ("raqib/forward.py", "EventLogApi.__init__", "loader"),
    ("raqib/hostwin.py", "Api.__init__", "loader"),
    ("raqib/hostwin.py", "probe", "loader"),
    ("raqib/tray.py", "_BoxApi.__init__", "WinDLL"),
    ("raqib/tray.py", "_Api.__init__", "WinDLL"),
    ("raqib/ui.py", "Kernel32.__init__", "WinDLL"),
    ("raqib/winservice.py", "System._win", "WinDLL"),
}
# Raqib's own loader functions that take a name, found by the scan (file, the function that holds the load)
RAQIB_LOADERS = {("raqib/etwnet.py", "Api.__init__"), ("raqib/hostwin.py", "Api.__init__"),
                 ("raqib/hostwin.py", "probe"), ("raqib/forward.py", "eventlog_dll")}
ENV_NAMES = {"HOME", "USERPROFILE"}   # what raqib/ sets in its own environment (winservice: the place, AF)


class Scan:
    """One scan of many files: loads, loader functions, the search calls, the environment's names set, faults."""

    def __init__(self, classes=CLASSES, loaders=LOADERS):
        self.classes, self.loader_objects = tuple(classes), tuple(loaders)   # a test narrows them: a blind scan
        self.loads, self.loaders, self.search, self.env, self.faults = [], set(), set(), set(), []
        self.files, self.defs, self.setters = {}, {}, {}

    def add(self, source, filename):
        tree = ast.parse(source, filename)
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        self.files[filename] = (tree, parents)

    # --- where a node is ---
    @staticmethod
    def where(node, parents):
        names, n = [], parents.get(node)
        while n is not None:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(n.name)
            n = parents.get(n)
        return ".".join(reversed(names)) or "<module>"

    @classmethod
    def qual(cls, fn, parents):
        """The function's own qualified name: the defs and classes that hold it, and its name."""
        up = cls.where(fn, parents)
        return fn.name if up == "<module>" else "%s.%s" % (up, fn.name)

    @staticmethod
    def holder(node, parents):
        n = parents.get(node)
        while n is not None and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            n = parents.get(n)
        return n

    @staticmethod
    def params(fn):
        a = fn.args
        return {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x is not None}

    # --- a name followed to strings written in the code ---
    def table(self, tree, name):
        """The strings of a top-level table `name` (a dict's keys, a tuple's, list's or set's items), or None."""
        values = [n.value for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        if len(values) != 1:
            return None
        v = values[0]
        items = v.keys if isinstance(v, ast.Dict) else v.elts if isinstance(v, (ast.Tuple, ast.List, ast.Set)) \
            else None
        if items is None or not all(isinstance(i, ast.Constant) and isinstance(i.value, str) for i in items):
            return None
        return [i.value for i in items]

    def strings(self, expr, scope, tree):
        """(the strings `expr` can be, None) or (None, why not): a string written there; a name bound in its function
        by a `for` over a top-level table (its keys by .items() or .keys(), or its items) or by an assignment of one;
        nothing else (a parameter, a call, a name bound otherwise: worked out at run time)."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [expr.value], None
        said = "a name worked out at run time (%s)" % ast.unparse(expr)
        if not isinstance(expr, ast.Name) or scope is None or expr.id in self.params(scope):
            return None, said
        got = []
        for n in ast.walk(scope):
            if isinstance(n, ast.For):
                if isinstance(n.target, ast.Name) and n.target.id == expr.id:
                    index = None
                elif isinstance(n.target, ast.Tuple) and n.target.elts and isinstance(n.target.elts[0], ast.Name) \
                        and n.target.elts[0].id == expr.id:
                    index = 0
                else:
                    continue
                it = n.iter
                if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and not it.args and (
                        it.func.attr == "items" and index == 0 or it.func.attr == "keys" and index is None):
                    it = it.func.value
                elif index is not None:
                    return None, said
                values = self.table(tree, it.id) if isinstance(it, ast.Name) else None
                if values is None:
                    return None, said
                got += values
            elif isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == expr.id for t in n.targets):
                values, why = self.strings(n.value, None, tree)
                if why:
                    return None, said
                got += values
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr, ast.With, ast.comprehension)) and \
                    expr.id in {x.id for x in ast.walk(getattr(n, "target", None) or n) if isinstance(x, ast.Name)
                                and isinstance(x.ctx, ast.Store)}:
                return None, said
        return (got, None) if got else (None, said)

    # --- the scan ---
    def run(self):
        for filename, (tree, parents) in sorted(self.files.items()):
            self._file(filename, tree, parents)
        for (filename, function), (name, kind) in sorted(self.defs.items()):   # a loader def: every call of it
            self._callers(name, filename, function, kind)
        return self

    def _fault(self, filename, node, words):
        self.faults.append((filename, getattr(node, "lineno", 0), words))

    def _file(self, filename, tree, parents):
        mods, bound, utils, oses, environ = set(), {}, set(), set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    if top == "_ctypes":
                        self._fault(filename, node, "imports _ctypes, whose loads this scan does not read")
                    if a.name == "ctypes" or (top == "ctypes" and a.asname is None):
                        mods.add(a.asname or "ctypes")
                    if a.name == "ctypes.util" and a.asname:
                        utils.add(a.asname)
                    if a.name == "os":
                        oses.add(a.asname or "os")
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                top = node.module.split(".")[0]
                for a in node.names:
                    if top == "_ctypes" or (top == "ctypes" and a.name == "*"):
                        self._fault(filename, node, "from %s import %s: not read by this scan" % (
                            node.module, a.name))
                    elif node.module == "ctypes" and a.name in CLASSES + LOADERS:
                        bound[a.asname or a.name] = a.name
                    elif node.module == "ctypes" and a.name == "util":
                        utils.add(a.asname or "util")
                    elif node.module == "ctypes.util" and a.name in FINDERS:
                        bound[a.asname or a.name] = a.name
                    elif node.module == "os" and a.name in ("environ", "putenv"):
                        environ.add(a.asname or a.name)

        def of_ctypes(e):
            known = self.classes + self.loader_objects
            if isinstance(e, ast.Name):
                return bound.get(e.id) if bound.get(e.id) in known + FINDERS else None
            if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Name):
                if e.value.id in mods and e.attr in known or e.value.id in utils and e.attr in FINDERS:
                    return e.attr
            if isinstance(e, ast.Attribute) and isinstance(e.value, ast.Attribute) and e.attr in FINDERS and \
                    e.value.attr == "util" and isinstance(e.value.value, ast.Name) and e.value.value.id in mods:
                return e.attr
            return None

        def is_environ(e):
            return isinstance(e, ast.Name) and e.id in environ or isinstance(e, ast.Attribute) and \
                e.attr == "environ" and isinstance(e.value, ast.Name) and e.value.id in oses

        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "winmode":
                self._fault(filename, parents.get(node), "a search mode given (winmode=)")
            if isinstance(node, (ast.Attribute, ast.Name)):
                word = node.attr if isinstance(node, ast.Attribute) else node.id
                if word in SEARCH:
                    self.search.add((filename, self.where(node, parents), word))
                    if (filename, self.where(node, parents), word) not in ALLOWED_SEARCH:
                        self._fault(filename, node, "%s: a call that changes the library search" % word)
            if isinstance(node, ast.Attribute) and of_ctypes(node.value) in LOADERS and node.attr != "LoadLibrary":
                if node.attr.startswith("_"):
                    self._fault(filename, node, "%s: not a library's name" % ast.unparse(node))
                else:
                    self._load(filename, node, parents, of_ctypes(node.value), node.attr)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and \
                    len(node.args) > 1:   # a loader by getattr, or a class of ctypes' by a name not written
                word = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                if of_ctypes(node.args[0]) in LOADERS or isinstance(node.args[0], ast.Name) and \
                        node.args[0].id in mods and (word in CLASSES + LOADERS + FINDERS
                                                     or not isinstance(word, str)):
                    self._fault(filename, node, "%s: a load this scan cannot read" % ast.unparse(node)[:80])
            if not isinstance(node, ast.Call):
                if isinstance(node, (ast.Assign, ast.AugAssign)):
                    for t in getattr(node, "targets", None) or [node.target]:
                        if isinstance(t, ast.Subscript) and is_environ(t.value):
                            self._env(filename, t.slice, node, parents)
                continue
            what = of_ctypes(node.func)
            if what in FINDERS:
                self._fault(filename, node, "find_library: it searches the PATH's folders on Windows")
            elif what in CLASSES or (isinstance(node.func, ast.Attribute) and node.func.attr == "LoadLibrary"
                                     and of_ctypes(node.func.value) in LOADERS):
                arg = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "name"), None)
                self._name(filename, node, parents, what or "LoadLibrary", arg)
            elif isinstance(node.func, ast.Attribute) and is_environ(node.func.value) and node.func.attr in (
                    "update", "setdefault", "__setitem__"):
                for k in node.keywords:
                    self._env_word(filename, node, k.arg)
                if node.args:
                    arg = node.args[0]
                    keys = arg.keys if isinstance(arg, ast.Dict) else [arg] if node.func.attr != "update" else None
                    if keys is None:
                        self._fault(filename, node, "the environment updated from %s: not read" % ast.unparse(arg))
                    for k in keys or ():
                        self._env(filename, k, node, parents)
            elif isinstance(node.func, ast.Name) and node.func.id in environ and node.func.id == "putenv" or \
                    isinstance(node.func, ast.Attribute) and node.func.attr == "putenv" and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id in oses:
                self._env(filename, node.args[0] if node.args else None, node, parents)

    def _load(self, filename, node, parents, form, name):
        self.loads.append((filename, self.where(node, parents), form, name))

    def _name(self, filename, call, parents, form, arg):
        scope = self.holder(call, parents)
        if isinstance(arg, ast.Name) and scope is not None and arg.id in self.params(scope):
            self._loader(filename, scope, parents)   # a loader that takes a name: its callers give the names
            return
        if arg is None:
            self._fault(filename, call, "%s: no name given" % ast.unparse(call)[:80])
            return
        values, why = self.strings(arg, scope, self.files[filename][0])
        if why:
            self._fault(filename, call, "%s: %s" % (form, why))
        for v in values or ():
            self._load(filename, call, parents, form, v)

    def _loader(self, filename, scope, parents):
        if isinstance(scope, ast.Lambda):    # bound to a name in the function that holds it: its calls there
            fn, up = self.holder(scope, parents), parents.get(scope)
            while up is not None and not isinstance(up, ast.Assign):
                up = parents.get(up)
            names = [t.id for t in (up.targets if up is not None else []) if isinstance(t, ast.Name)]
            if fn is None or len(names) != 1:
                self._fault(filename, scope, "a loader lambda not bound to one name in a function: not followed")
                return
            self.loaders.add((filename, self.where(scope, parents)))
            calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                     and c.func.id == names[0]]
            if not calls:
                self._fault(filename, scope, "a loader whose calls this scan does not find")
            for c in calls:
                self._given(filename, c, "loader")
        else:                                # a def: every call of it, in every file, by its name
            self.loaders.add((filename, self.qual(scope, parents)))
            self.defs[(filename, self.qual(scope, parents))] = (scope.name, "loader")

    def _callers(self, name, filename, function, kind):
        found = 0
        for other, (tree, parents) in sorted(self.files.items()):
            for c in ast.walk(tree):
                if not isinstance(c, ast.Call):
                    continue
                f = c.func
                heads = f.values if isinstance(f, ast.BoolOp) else [f]
                if any(isinstance(h, ast.Name) and h.id == name or isinstance(h, ast.Attribute) and h.attr == name
                       for h in heads):
                    found += 1
                    if kind == "loader":
                        self._given(other, c, "loader")
                    else:
                        self._env(other, c.args[0] if c.args else None, c, parents)
        if not found:
            self._fault(filename, None, "%s %s: its calls are not found by this scan" % (kind, function))

    def _given(self, filename, call, form):
        tree, parents = self.files[filename]
        if not call.args:
            self._fault(filename, call, "%s: no name given" % ast.unparse(call)[:80])
            return
        values, why = self.strings(call.args[0], self.holder(call, parents), tree)
        if why:
            self._fault(filename, call, "%s: %s" % (form, why))
        for v in values or ():
            self._load(filename, call, parents, form, v)

    def _env(self, filename, key, node, parents):
        tree = self.files[filename][0]
        scope = self.holder(node, parents)
        if isinstance(key, ast.Name) and scope is not None and isinstance(scope, ast.FunctionDef) and \
                key.id in self.params(scope):   # a setter that takes the variable's name: its callers give it
            self.defs[(filename, self.qual(scope, parents))] = (scope.name, "setter")
            return
        values, why = self.strings(key, scope, tree) if key is not None else (None, "no name")
        if why:
            self._fault(filename, node, "the environment set by %s" % why)
        for v in values or ():
            self._env_word(filename, node, v)

    def _env_word(self, filename, node, word):
        if word is None:
            self._fault(filename, node, "the environment updated with ** : not read")
            return
        self.env.add(word)
        if word.upper() == "PATH":
            self._fault(filename, node, "sets PATH")


def scan_raqib(**kw):
    """The scan of every .py file of raqib/ (kw: a narrowed scan's lists, for the blind test)."""
    s = Scan(**kw)
    for path in sorted((ROOT / "raqib").rglob("*.py")):
        s.add(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
    return s.run()


def scan_of(source, filename="raqib/made_up.py"):
    s = Scan()
    s.add(source, filename)
    return s.run()


def plain_name(name):
    return not any(c in name for c in "\\/:") and (name.count(".") == 0 or (
        name.count(".") == 1 and name.lower().endswith(".dll") and len(name) > 4))


def test_p2_every_library_raqib_loads_is_a_plain_name_written_in_the_code_on_one_list():
    s = scan_raqib()
    assert not s.faults, "ADR-0013 P-2: %s" % "; ".join("%s line %d: %s" % f for f in s.faults)
    assert {(f, w, form) for f, w, form, _ in s.loads} == RAQIB_LOADS   # what it found, so a blind scan fails
    assert s.loaders == RAQIB_LOADERS
    names = {n for _, _, _, n in s.loads}
    assert names == set(LIBRARIES) and list(LIBRARIES) == sorted(LIBRARIES)
    assert all(plain_name(n) for n in names), names
    assert s.search == ALLOWED_SEARCH   # CI-3's one call, named and allowed as what it is
    assert s.env == ENV_NAMES and not {n for n in s.env if n.upper() == "PATH"}


def test_p2_the_one_search_call_is_cis_and_takes_the_folder_off_the_search():
    source = (ROOT / "raqib" / "cli.py").read_text(encoding="utf-8")
    assert source.count("SetDllDirectoryW") == 1 and "own.library_folder(set_dll_directory_w)" in source
    own = (ROOT / "raqib" / "own.py").read_text(encoding="utf-8")
    calls = [ast.unparse(n) for n in ast.walk(ast.parse(own)) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "call"]
    assert calls == ["call(None)"]   # the folder searched first goes back to the system's own: none is added


MADE_UP = [   # (source, the names found, the forms found, a piece of a fault or None)
    ("import ctypes\ndef f():\n    ctypes.WinDLL('kernel32')\n", {"kernel32"}, {"WinDLL"}, None),
    ("import ctypes\ndef f():\n    ctypes.CDLL('a.dll')\n    ctypes.OleDLL('b')\n    ctypes.PyDLL('c')\n",
     {"a.dll", "b", "c"}, {"CDLL", "OleDLL", "PyDLL"}, None),
    ("import ctypes\ndef f():\n    return ctypes.windll.shcore.F\n", {"shcore"}, {"windll"}, None),
    ("import ctypes\ndef f():\n    ctypes.cdll.LoadLibrary('x')\n    ctypes.oledll.y\n", {"x", "y"},
     {"LoadLibrary", "oledll"}, None),
    ("from ctypes import WinDLL as W, windll\ndef f():\n    W('k')\n    windll.u\n", {"k", "u"},
     {"WinDLL", "windll"}, None),
    ("import ctypes as c\ndef f():\n    c.WinDLL('k')\n", {"k"}, {"WinDLL"}, None),
    ("import ctypes\nT = {'a': 1, 'b': 2}\ndef f():\n    for n, v in T.items():\n        ctypes.WinDLL(n)\n",
     {"a", "b"}, {"WinDLL"}, None),
    ("import ctypes\ndef f(loader=None):\n    loader = loader or (lambda name: ctypes.WinDLL(name))\n"
     "    loader('one')\n    loader('two')\n", {"one", "two"}, {"loader"}, None),
    ("import ctypes\ndef load(name):\n    return ctypes.WinDLL(name)\nclass A:\n    def __init__(self, l=None):\n"
     "        (l or load)('adv')\n", {"adv"}, {"loader"}, None),
    # each a fault: a name worked out at run time, a search mode, a folder added, PATH set, find_library
    ("import ctypes\ndef f(x):\n    ctypes.WinDLL(x + '.dll')\n", set(), set(), "a name worked out at run time"),
    ("import ctypes, os\ndef f():\n    ctypes.WinDLL(os.environ['X'])\n", set(), set(), "worked out at run time"),
    ("import ctypes\ndef f():\n    n = g()\n    ctypes.WinDLL(n)\n", set(), set(), "worked out at run time"),
    ("import ctypes\ndef f(names):\n    for n in names:\n        ctypes.WinDLL(n)\n", set(), set(),
     "worked out at run time"),
    ("import ctypes\ndef load(name):\n    return ctypes.WinDLL(name)\ndef g(x):\n    load(x)\n", set(), set(),
     "worked out at run time"),
    ("import ctypes\ndef load(name):\n    return ctypes.WinDLL(name)\n", set(), set(), "its calls are not found"),
    ("import ctypes\ndef f():\n    ctypes.WinDLL('k', winmode=0)\n", {"k"}, {"WinDLL"}, "a search mode given"),
    ("import os\ndef f():\n    os.add_dll_directory('C:\\\\x')\n", set(), set(), "add_dll_directory"),
    ("import ctypes\ndef f():\n    ctypes.windll.kernel32.AddDllDirectory('C:\\\\x')\n", {"kernel32"}, {"windll"},
     "AddDllDirectory: a call that changes the library search"),
    ("import ctypes\ndef f():\n    ctypes.WinDLL('kernel32').LoadLibraryW('x')\n", {"kernel32"}, {"WinDLL"},
     "LoadLibraryW"),
    ("import os\ndef f():\n    os.environ['PATH'] = 'C:\\\\x'\n", set(), set(), "sets PATH"),
    ("import os\ndef f():\n    os.environ.update(Path='C:\\\\x')\n", set(), set(), "sets PATH"),
    ("from os import environ, putenv\ndef f():\n    putenv('PATH', 'x')\n    environ.setdefault('path', 'x')\n",
     set(), set(), "sets PATH"),
    ("import os\nclass S:\n    def setenv(self, n, v):\n        os.environ[n] = v\ndef f(s):\n"
     "    s.setenv('PATH', 'x')\n", set(), set(), "sets PATH"),
    ("import os\ndef f(n):\n    os.environ[n] = 'x'\n", set(), set(), "its calls are not found"),
    ("import ctypes.util\ndef f():\n    ctypes.util.find_library('c')\n", set(), set(), "find_library"),
    ("from ctypes.util import find_library\ndef f():\n    find_library('c')\n", set(), set(), "find_library"),
    ("import ctypes\ndef f():\n    getattr(ctypes.windll, 'k')\n", set(), set(), "a load this scan cannot read"),
    ("import ctypes\ndef f(n):\n    getattr(ctypes, n)('k')\n", set(), set(), "a load this scan cannot read"),
    ("import ctypes\ndef f():\n    getattr(ctypes, 'get_last_error')()\n", set(), set(), None),   # not a load
    ("import _ctypes\n", set(), set(), "imports _ctypes"),
    ("def WinDLL(x):\n    pass\ndef f(y):\n    WinDLL(y)\n", set(), set(), None),   # not ctypes': not a load
]


@pytest.mark.parametrize("source, names, forms, fault", MADE_UP)
def test_p2_the_scan_is_not_blind_each_form_is_found_and_a_worked_out_name_fails(source, names, forms, fault):
    s = scan_of(source)
    assert {n for _, _, _, n in s.loads} == names and {f for _, _, f, _ in s.loads} == forms, s.loads
    if fault is None:
        assert not s.faults, s.faults
    else:
        assert [f for f in s.faults if fault in f[2]], s.faults


def test_p2_a_blind_scan_fails_the_held_sets():
    blind = scan_raqib(classes=(), loaders=())   # a scan with no list finds nothing
    assert blind.loads == [] and blind.loaders == set()
    less = scan_raqib(classes=("CDLL", "OleDLL", "PyDLL"))   # one class lost: every loader and most loads go
    found = {(f, w, form) for f, w, form, _ in less.loads}
    assert found < RAQIB_LOADS and ("raqib/hostwin.py", "probe", "loader") in RAQIB_LOADS - found
    assert found == {x for x in RAQIB_LOADS if x[2] == "windll"} and less.loaders == set()
    assert not plain_name("C:\\Windows\\System32\\kernel32.dll") and not plain_name("..\\x") and not plain_name(
        "x.y.dll") and not plain_name("x.so") and not plain_name(".dll") and plain_name("kernel32.DLL")


@pytest.mark.skipif(sys.platform != "win32", reason="System32 is Windows' (ADR-0013 P-2)")
def test_p2_each_name_of_the_list_is_a_file_in_system32():
    system32 = Path(os.environ.get("SystemRoot") or "C:\\Windows") / "System32"
    for name in LIBRARIES:
        file = name if name.lower().endswith(".dll") else name + ".dll"
        assert (system32 / file).is_file(), name
