"""M12.4c2a (ADR-0013 P-2, Q-4) and M12.4c2a2 (Amendment R, R-3): every library Raqib loads by name, held by one list;
and every mention in raqib/ by which one could be loaded otherwise, held as it is.

Read in the interpreter's library (Lib/ctypes/__init__.py at 3.11.9 and 3.12.10; Amendment P), not measured: a
library asked for by a bare name is searched with the system's default folders - the application's own folder,
System32, and folders the process itself added - and not along the PATH or in the folder the process was started in.

The first hold (Scan; P-2, Q-4) reads every .py file of raqib/ by its syntax tree, finds every place a library is
loaded (ctypes' classes, its loaders by attribute and by LoadLibrary, find_library, and Raqib's own loader functions
and lambdas, whose callers give the names), and holds: every name is a string written in the code, followed through
a table of strings written once, plain, and on one list (LIBRARIES); no search mode, no folder added, PATH never set;
CI-3's one call (SetDllDirectoryW with no folder, raqib/cli.py) on its one road. It refuses the forms it knows.

The hold on it (Mentions; R-3) is turned round: what is in the tree is held as it is, and anything else fails. Each
table below is what the scan found in raqib/, printed by dump_held() and pasted, compared whole and exactly - a
mention more fails, a mention fewer fails, a statement changed by one token fails:
- E1 MENTIONS: every mention of a word of WORDS (by which a library is loaded, the search changed, the environment
  set past os.environ, or ctypes and its loaders reached by another road) and of sys.modules - as a name, an
  attribute, each part of an imported or aliased name, a keyword, a parameter, a def's name, and as a whole word in
  every string and bytes constant, docstrings too - by (file, function, word): count. ENVIRON: every use of
  os.environ but a read of one name (a subscript read, .get given a string written in the code, `in`), by file,
  function and its statement's text.
- E2 STATEMENTS: the statement around each mention in code of a loader's, a search call's or a setter's word, as
  ast.unparse writes it. E3 CI3_TEXT, CI3_HANDOVER: CI-3's function in cli.main and own.library_folder, whole
  (docstrings apart), and the one statement that hands the first to the second.
- E4 CTYPES_ATTRS, CTYPES_IMPORTS, CTYPES_BOUND: every attribute taken of ctypes or ctypes.wintypes (through any name
  an import, an assignment or an object's attribute binds to it), on one list; every import of ctypes or of a part
  of it; every place a module of ctypes is bound, stored or handed on, by its statement.
- E5 TABLES, LOADER_BODIES, E5_NAMES, NAMED: each table of names the first hold follows and each of Raqib's own
  loaders, its value or body as written, and every mention of its name (in its own file by name; in any other as an
  attribute, an imported name or a keyword), by file, function and count.
- E6 HANDED_OBJECTS, REBOUND, OTHER_USES: an object a load gives is used by taking a function of it by name (an
  attribute not beginning with `_`; getattr given a string written in the code, or a parameter every call of its
  def gives one); handed to a call or kept on an object only where held, and followed there; its name bound again,
  or put to any other use, only where held by its statement (autostart._windows_drive_kind, as the tree has it).
ESCAPES: each form the two reviews found, put in a copy of the file it would live in, fails at its own line.
On Windows only: each name of the list is a file in System32.

Not held, said plainly: loads the interpreter itself makes, outside raqib/ (ctypes' own windll.kernel32 at its
import, _ctypes' dependencies, tkinter's libraries); folders the interpreter's own start adds to the search (site, a
*.pth line, sitecustomize), which no test here reads; a word built from pieces at run time that is on no list (a
name joined from parts and given to getattr, a name read from a file); whether a library's own dependencies are
searched as the library is (Amendment P: not measured).
"""
import ast
import copy
import os
import re
import sys
from collections import Counter
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
LOW = ("_dlopen", "LibraryLoader")    # Q-4: ctypes' own low loader, and the class its loaders are made by
ENV_SET = ("SetEnvironmentVariableW", "SetEnvironmentVariableA", "putenv")   # Q-4: the environment set past
#                                                                            os.environ
# Q-4: where a name of SEARCH, ENV_SET or LOW may be written in a string (file, where, word): own.py's words for
# CI-3's result ("SetDllDirectoryW(NULL) failed: ..."), which name the call and make none
ALLOWED_WORDS = {("raqib/own.py", "library_folder", "SetDllDirectoryW")}
ALLOWED_HANDED = set()                # Q-4: where a loader may be handed on as a value (file, where, name): nowhere
CI3_CALLER = ("raqib/own.py", "library_folder")   # CI-3: handed the function that holds the call; calls it once, None
CI3_FILES = {"raqib/cli.py", "raqib/own.py"}       # the two files CI-3's road is read in
CHANGERS = ("update", "append", "extend", "insert", "setdefault", "add", "pop", "popitem", "remove", "discard",
            "clear", "sort", "reverse", "__setitem__", "__delitem__", "__iadd__", "__ior__")   # what changes a table


class Scan:
    """One scan of many files: loads, loader functions, the search calls, the environment's names set, faults."""

    def __init__(self, classes=CLASSES, loaders=LOADERS):
        self.classes, self.loader_objects = tuple(classes), tuple(loaders)   # a test narrows them: a blind scan
        self.loads, self.loaders, self.search, self.env, self.faults = [], set(), set(), set(), []
        self.files, self.defs, self.setters = {}, {}, {}
        self.words, self.handed, self.ci3, self.lambdas = set(), set(), set(), []   # Q-4
        self.load_nodes, self.loader_nodes, self.tables_read = [], {}, set()   # R-3: what the layers on it read

    def add(self, source, filename):
        self.files[filename] = parsed(source, filename)

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
        """(the strings of a top-level table `name` - a dict's keys, a tuple's, list's or set's items - None) or
        (None, why not): written once and never changed after (Q-4: no second binding or deletion of its name, no
        item stored or deleted, no method of CHANGERS, no `global` of it)."""
        values = [n.value for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        if not values:
            return None, None
        binds = [n for n in nodes(tree) if isinstance(n, ast.Name) and n.id == name
                 and isinstance(n.ctx, (ast.Store, ast.Del))]
        changed = [n for n in nodes(tree) if isinstance(n, (ast.Subscript, ast.Attribute))
                   and isinstance(n.value, ast.Name) and n.value.id == name
                   and (isinstance(n.ctx, (ast.Store, ast.Del))
                        or isinstance(n, ast.Attribute) and n.attr in CHANGERS)]
        named = [n for n in nodes(tree) if isinstance(n, (ast.Global, ast.Nonlocal)) and name in n.names]
        if len(values) != 1 or len(binds) != 1 or changed or named:
            return None, "a table of names changed after its one assignment (%s)" % name
        v = values[0]
        items = v.keys if isinstance(v, ast.Dict) else v.elts if isinstance(v, (ast.Tuple, ast.List, ast.Set)) \
            else None
        if items is None or not all(isinstance(i, ast.Constant) and isinstance(i.value, str) for i in items):
            return None, None
        return [i.value for i in items], None

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
                values, changed = self.table(tree, it.id) if isinstance(it, ast.Name) else (None, None)
                if values is None:
                    return None, changed or said
                self.tables_read.update((f, it.id) for f, (t, _) in self.files.items() if t is tree)
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
            key = (id(tree), filename, self.classes, self.loader_objects)
            one = _SCANNED.get(key)   # one file's own reading, kept: a made-up tree re-reads only what it changes
            if one is None:
                one = _SCANNED[key] = Scan(self.classes, self.loader_objects)
                one.files = {filename: (tree, parents)}
                one._file(filename, tree, parents)
            for k in ("loads", "faults", "lambdas", "load_nodes"):
                getattr(self, k).extend(getattr(one, k))
            for k in ("loaders", "search", "env", "words", "tables_read", "defs", "loader_nodes", "setters"):
                getattr(self, k).update(getattr(one, k))
        for (filename, function), (name, kind) in sorted(self.defs.items()):   # a loader def: every call of it
            self._callers(name, filename, function, kind)
        self._handed()
        self._ci3()
        return self

    def _fault(self, filename, node, words):
        self.faults.append((filename, getattr(node, "lineno", 0), words))

    def _file(self, filename, tree, parents):
        mods, bound, utils, oses, environ, putenvs = set(), {}, set(), set(), set(), set()
        for node in nodes(tree):
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
                    if top == "_ctypes" or (top == "ctypes" and a.name in ("*",) + LOW):
                        self._fault(filename, node, "from %s import %s: not read by this scan" % (
                            node.module, a.name))
                    elif node.module == "ctypes" and a.name in CLASSES + LOADERS:
                        bound[a.asname or a.name] = a.name
                    elif node.module == "ctypes" and a.name == "util":
                        utils.add(a.asname or "util")
                    elif node.module == "ctypes.util" and a.name in FINDERS:
                        bound[a.asname or a.name] = a.name
                    elif node.module == "os" and a.name in ("environ", "putenv"):
                        (environ if a.name == "environ" else putenvs).add(a.asname or a.name)

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

        said = {id(n.value) for n in nodes(tree) if isinstance(n, ast.Expr)}   # docstrings: words, not values
        heads = {id(c.func) for c in nodes(tree) if isinstance(c, ast.Call)}
        for node in nodes(tree):
            if isinstance(node, ast.keyword) and node.arg == "winmode":
                self._fault(filename, parents.get(node), "a search mode given (winmode=)")
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and id(node) not in said:
                text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                for word in SEARCH + ENV_SET + LOW:   # Q-4: a search call's name as a string (getattr, a table)
                    if word in text:
                        key = (filename, self.where(node, parents), word)
                        self.words.add(key)
                        if key not in ALLOWED_WORDS:
                            self._fault(filename, node, "%s: a search call's or a setter's name written in a string"
                                        % word)
            if isinstance(node, (ast.Attribute, ast.Name)):
                word = node.attr if isinstance(node, ast.Attribute) else node.id
                if word in SEARCH:
                    self.search.add((filename, self.where(node, parents), word))
                    if (filename, self.where(node, parents), word) not in ALLOWED_SEARCH:
                        self._fault(filename, node, "%s: a call that changes the library search" % word)
                if word in ENV_SET and (isinstance(node, ast.Attribute) or word != "putenv") or \
                        isinstance(node, ast.Name) and word in putenvs:
                    self._fault(filename, node, "%s: the environment set past os.environ" % word)
                if isinstance(node, ast.Attribute) and node.attr in LOW and isinstance(node.value, ast.Name) and \
                        node.value.id in mods:
                    self._fault(filename, node, "%s: ctypes' low loader, or the class its loaders are made by" %
                                ast.unparse(node))
                up = parents.get(node)
                if of_ctypes(node) and id(node) not in heads and not (
                        isinstance(up, (ast.Attribute, ast.Subscript)) and up.value is node):
                    self._fault(filename, node, "%s: a class, loader or finder of ctypes' handed on as a value"
                                % ast.unparse(node))
            if isinstance(node, ast.Subscript) and of_ctypes(node.value) in LOADERS:
                self._fault(filename, node, "%s: a loader asked by index" % ast.unparse(node)[:80])
            if isinstance(node, ast.Attribute) and of_ctypes(node.value) in LOADERS and node.attr != "LoadLibrary":
                if node.attr.startswith("_"):
                    self._fault(filename, node, "%s: not a library's name" % ast.unparse(node))
                else:
                    self._load(filename, node, parents, of_ctypes(node.value), node.attr)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and \
                    len(node.args) > 1:   # a loader by getattr, or a class of ctypes' by a name not written
                word = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                if of_ctypes(node.args[0]) in LOADERS or isinstance(node.args[0], ast.Name) and \
                        node.args[0].id in mods and (word in CLASSES + LOADERS + FINDERS + LOW
                                                     or not isinstance(word, str)):
                    self._fault(filename, node, "%s: a load this scan cannot read" % ast.unparse(node)[:80])
            if not isinstance(node, ast.Call):
                if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    for t in getattr(node, "targets", None) or [node.target]:
                        if isinstance(t, ast.Subscript) and is_environ(t.value):
                            self._env(filename, t.slice, node, parents)
                        elif is_environ(t):   # Q-4: `os.environ |= ...`, `os.environ = ...`
                            self._fault(filename, node, "the environment written whole (%s)" % ast.unparse(node)[:80])
                continue
            what = of_ctypes(node.func)
            if what in FINDERS:
                self._fault(filename, node, "find_library: it searches the PATH's folders on Windows")
            elif what in CLASSES or (isinstance(node.func, ast.Attribute) and node.func.attr == "LoadLibrary"
                                     and of_ctypes(node.func.value) in LOADERS):
                self._only_a_name(filename, node)
                arg = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "name"), None)
                self._name(filename, node, parents, what or "LoadLibrary", arg)
            elif isinstance(node.func, ast.Attribute) and is_environ(node.func.value) and node.func.attr in (
                    "update", "setdefault", "__setitem__", "__ior__"):
                if node.func.attr in ("update", "__ior__"):   # Q-4: written from a table, never read whole
                    self._fault(filename, node, "os.environ.%s: the environment written from a table" %
                                node.func.attr)
                for k in node.keywords:
                    self._env_word(filename, node, k.arg)
                if node.args:
                    arg = node.args[0]
                    keys = arg.keys if isinstance(arg, ast.Dict) else [arg] if node.func.attr != "update" else None
                    if keys is None:
                        self._fault(filename, node, "the environment updated from %s: not read" % ast.unparse(arg))
                    for k in keys or ():
                        self._env(filename, k, node, parents)
            elif isinstance(node.func, ast.Name) and node.func.id in putenvs or \
                    isinstance(node.func, ast.Attribute) and node.func.attr == "putenv" and \
                    isinstance(node.func.value, ast.Name) and node.func.value.id in oses:
                self._env(filename, node.args[0] if node.args else None, node, parents)

    def _only_a_name(self, filename, call):
        """Q-4: a loading call is given its name and nothing more by position, and no `*` or `**`."""
        if len(call.args) > 1 or any(isinstance(a, ast.Starred) for a in call.args) or \
                any(k.arg is None for k in call.keywords):
            self._fault(filename, call, "%s: a loading call given more than its name (a second positional argument,"
                                        " * or **)" % ast.unparse(call)[:80])

    def _load(self, filename, node, parents, form, name):
        self.loads.append((filename, self.where(node, parents), form, name))
        self.load_nodes.append((filename, node))

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
            self.loader_nodes[(filename, self.where(scope, parents))] = (scope, names[0])
            self.lambdas.append((filename, fn, names[0], up))
            calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                     and c.func.id == names[0]]
            if not calls:
                self._fault(filename, scope, "a loader whose calls this scan does not find")
            for c in calls:
                self._given(filename, c, "loader")
        else:                                # a def: every call of it, in every file, by its name
            self.loaders.add((filename, self.qual(scope, parents)))
            self.loader_nodes[(filename, self.qual(scope, parents))] = (scope, scope.name)
            self.defs[(filename, self.qual(scope, parents))] = (scope.name, "loader")

    def _callers(self, name, filename, function, kind):
        found = 0
        for other, (tree, parents) in sorted(self.files.items()):
            for c in nodes(tree):
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
        self._only_a_name(filename, call)
        values, why = self.strings(call.args[0], self.holder(call, parents), tree)
        if why:
            self._fault(filename, call, "%s: %s" % (form, why))
        for v in values or ():
            self._load(filename, call, parents, form, v)

    def _handed(self):
        """Q-4: each of Raqib's own loaders - a def, by its name in every file; a lambda, by the one name it is bound
        to in its function (its binding's own line apart) - is met only as what a call calls (or a part of an `or`
        that a call calls); anywhere else it is handed on as a value, which only ALLOWED_HANDED may name."""
        names = {name for (name, kind) in self.defs.values() if kind == "loader"}
        places = [(f, tree, None, names, None) for f, (tree, _) in sorted(self.files.items())]
        places += [(f, fn, bound, {name}, bound) for f, fn, name, bound in self.lambdas]
        for filename, top, bound, words, skip in places:
            parents = self.files[filename][1]
            heads = {id(h) for c in nodes(top) if isinstance(c, ast.Call)
                     for h in (c.func.values if isinstance(c.func, ast.BoolOp) else [c.func])}
            inside = {id(x) for x in ast.walk(skip)} if skip is not None else set()
            for n in nodes(top):
                word = n.id if isinstance(n, ast.Name) else n.attr if isinstance(n, ast.Attribute) else None
                if word in words and isinstance(n.ctx, ast.Load) and id(n) not in heads and id(n) not in inside:
                    key = (filename, self.where(n, parents), word)
                    self.handed.add(key)
                    if key not in ALLOWED_HANDED:
                        self._fault(filename, n, "%s: a loader handed on as a value, not called where it is named"
                                    % word)

    def _ci3(self):
        """Q-4 (the review's finding 15): CI-3's one road. In raqib/cli.py the function that holds the allowed call
        (ALLOWED_SEARCH) takes one folder, reads the call once and calls it once, given that folder; that function is
        named once in raqib/, as the one thing handed to library_folder; and own.library_folder (CI3_CALLER) calls
        what it is handed once, with None, and does nothing else with it. Each file read is said in self.ci3."""
        for filename, where, word in sorted(ALLOWED_SEARCH):
            if filename not in self.files:
                continue
            tree, parents = self.files[filename]
            self.ci3.add(filename)
            fns = [n for n in nodes(tree) if isinstance(n, ast.FunctionDef) and self.qual(n, parents) == where]
            if len(fns) != 1:
                self._fault(filename, None, "CI-3: the function %s that holds %s is not found once" % (where, word))
                continue
            fn = fns[0]
            params = [x.arg for x in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
            reads = [n for n in ast.walk(fn) if isinstance(n, ast.Attribute) and n.attr == word]
            names = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign) and any(n.value is r for r in reads)
                     for t in n.targets if isinstance(t, ast.Name)}
            calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and (any(c.func is r for r in reads) or
                     isinstance(c.func, ast.Name) and c.func.id in names)]
            other = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id in names and
                     isinstance(n.ctx, ast.Load) and not any(c.func is n for c in calls) and not (
                         isinstance(parents.get(n), ast.Attribute) and isinstance(parents.get(n).ctx, ast.Store))]
            if len(params) != 1 or fn.args.vararg or fn.args.kwarg or len(reads) != 1 or len(calls) != 1 or other \
                    or calls[0].keywords or [ast.unparse(x) for x in calls[0].args] != params:
                self._fault(filename, fn, "CI-3: %s is read or called more than once, or given other than the one"
                                          " folder its function is given" % word)
            refs = [(f, n) for f, (t, _) in sorted(self.files.items()) for n in nodes(t)
                    if isinstance(n, ast.Name) and n.id == fn.name
                    or isinstance(n, ast.Attribute) and n.attr == fn.name]
            up = parents.get(refs[0][1]) if len(refs) == 1 else None
            if not (len(refs) == 1 and refs[0][0] == filename and isinstance(up, ast.Call) and not up.keywords
                    and len(up.args) == 1 and up.args[0] is refs[0][1] and CI3_CALLER[1] == (
                        up.func.attr if isinstance(up.func, ast.Attribute) else getattr(up.func, "id", None))):
                self._fault(filename, fn, "CI-3: %s is named other than once, as the one thing handed to %s" % (
                    fn.name, CI3_CALLER[1]))
        if CI3_CALLER[0] in self.files:
            tree, parents = self.files[CI3_CALLER[0]]
            self.ci3.add(CI3_CALLER[0])
            fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == CI3_CALLER[1]]
            a = fns[0].args if len(fns) == 1 else None
            first = (a.posonlyargs + a.args)[0].arg if a is not None and a.posonlyargs + a.args else None
            uses = [n for n in ast.walk(fns[0]) if isinstance(n, ast.Name) and n.id == first] if first else []
            calls = [c for c in ast.walk(fns[0]) if isinstance(c, ast.Call) and any(c.func is n for n in uses)] \
                if first else []
            if not (len(calls) == 1 and len(uses) == 1 and not calls[0].keywords and len(calls[0].args) == 1
                    and isinstance(calls[0].args[0], ast.Constant) and calls[0].args[0].value is None):
                self._fault(CI3_CALLER[0], fns[0] if fns else None, "CI-3: %s does not call what it is handed once,"
                                                                    " with None, and nothing else" % CI3_CALLER[1])

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
    """The scan of one made-up source, or of several ({filename: source})."""
    s = Scan()
    for name, text in sorted((source if isinstance(source, dict) else {filename: source}).items()):
        s.add(text, name)
    return s.run()


# --- ADR-0013 R-3 (M12.4c2a2): what is in the tree, held as it is, mention by mention; anything else fails ---
LOAD_WORDS = CLASSES + LOADERS + ("pythonapi", "LibraryLoader", "_dlopen", "dlopen", "_ctypes", "LoadLibrary",
                                  "LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA",
                                  "LoadPackagedLibrary", "find_library", "find_msvcrt", "winmode")   # E1, E2
SEARCH_WORDS = ("add_dll_directory", "_add_dll_directory", "AddDllDirectory", "RemoveDllDirectory",
                "SetDllDirectoryW", "SetDllDirectoryA", "SetDefaultDllDirectories")   # E1, E2: the search changed
ENV_WORDS = ("putenv", "_putenv", "_wputenv", "unsetenv", "environb", "SetEnvironmentVariableW",
             "SetEnvironmentVariableA", "SetEnvironmentStringsW")   # E1, E2: the environment set past os.environ
ROAD_WORDS = ("__import__", "importlib", "import_module", "__class__", "__base__", "__bases__", "__mro__",
              "__subclasses__", "__doc__", "__dict__", "__getattribute__", "__builtins__", "builtins", "globals",
              "vars", "locals", "exec", "eval", "compile")   # E1: ctypes and its loaders reached by another road
WORDS = LOAD_WORDS + SEARCH_WORDS + ENV_WORDS + ROAD_WORDS
SYS_MODULES = "sys.modules"   # E1: held as a word of its own (an attribute of sys, an imported name, a string)
PATTERNS = {w: re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(w)) for w in WORDS + (SYS_MODULES,)}
STATEMENT_WORDS = LOAD_WORDS + SEARCH_WORDS + ENV_WORDS   # E2: where one is code, its statement is held
CI3_FUNCTIONS = (("raqib/cli.py", "main.set_dll_directory_w"), ("raqib/own.py", "library_folder"))   # E3
_PARSED, _NODES, _INDEX, _FACTS, _SCANNED = {}, {}, {}, {}, {}


def parsed(source, filename):
    """(tree, {child: parent}) of a source, parsed once (a made-up tree re-parses only the file it changes); its
    nodes and the words its code writes are kept beside it (nodes(), index())."""
    key = (filename, source)
    if key not in _PARSED:
        tree = ast.parse(source, filename)
        every = list(ast.walk(tree))
        _PARSED[key] = (tree, {c: n for n in every for c in ast.iter_child_nodes(n)})
        _NODES[id(tree)], _INDEX[id(tree)] = every, {}
        for n in every:
            for word in named(n):
                _INDEX[id(tree)].setdefault(word, []).append(n)
    return _PARSED[key]


def nodes(tree):
    """ast.walk's nodes of a tree, from the list kept for a parsed file."""
    return _NODES[id(tree)] if id(tree) in _NODES else list(ast.walk(tree))


def index(tree):
    """{word: [the nodes that write it as code]} of a parsed file."""
    return _INDEX[id(tree)]


def statement(node, parents):
    while node is not None and not isinstance(node, ast.stmt):
        node = parents.get(node)
    return node


def whole(fn):
    """A def's text as ast.unparse writes it, its docstring apart (E3, E5)."""
    fn = copy.deepcopy(fn)
    if fn.body and isinstance(fn.body[0], ast.Expr) and isinstance(fn.body[0].value, ast.Constant) and \
            isinstance(fn.body[0].value.value, str):
        fn.body = fn.body[1:] or [ast.Pass()]
    return ast.unparse(fn)


def named(node):
    """The words a node writes as code: a name, an attribute, a parameter, a keyword, each part of an imported or
    aliased name, a def's or a class's name, a name an except, a global or a pattern binds."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.alias):
        return node.name.split(".") + ([node.asname] if node.asname else [])
    if isinstance(node, ast.ImportFrom):
        return node.module.split(".") if node.module else []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    name = node.arg if isinstance(node, ast.keyword) else node.rest if isinstance(node, ast.MatchMapping) else \
        node.name if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) else None
    return [name] if isinstance(name, str) else []


class Mentions:
    """R-3: the layers held on the first hold's scan (the same trees): every mention of WORDS (E1), the environment
    used past a read of one name (E1), the statement around each load (E2), CI-3's road (E3), ctypes' attributes,
    imports and bindings (E4), the tables and loaders (E5), and every use of a library's object (E6)."""

    def __init__(self, scan=None):
        self.scan, self.files = scan, scan.files if scan is not None else {}
        self.words, self.lines = Counter(), {}                     # E1: {(file, function, word): count}, its lines
        self.environ, self.statements, self.imports, self.bound, self.rebound = [], [], [], [], []
        self.attrs, self.whole, self.handover = {}, {}, []         # E4: {"ctypes.X": [(file, line)]}; E3
        self.tables, self.bodies, self.named, self.named_lines, self.names = {}, {}, Counter(), {}, set()   # E5
        self.handed, self.handed_lines, self.other, self.faults = Counter(), {}, [], []  # E6

    def run(self):
        for f, (tree, parents) in sorted(self.files.items()):
            one = _FACTS.get(id(tree))   # what one file holds of itself, kept for a made-up tree of one file more
            if one is None:
                one = _FACTS[id(tree)] = Mentions()
                one._file(f, tree, parents)
                one._ctypes(f, tree, parents)
            self.words.update(one.words)
            for mine, its in ((self.lines, one.lines), (self.attrs, one.attrs)):
                for k, v in its.items():
                    mine.setdefault(k, []).extend(v)
            for mine, its in ((self.environ, one.environ), (self.statements, one.statements),
                              (self.imports, one.imports), (self.bound, one.bound)):
                mine.extend(its)
        self._ci3()
        self._tables_and_loaders()
        seen, done = set(), set()
        for f, node in self.scan.load_nodes:
            if id(node) not in done:
                done.add(id(node))
                self._use(f, node, seen)
        return self

    @staticmethod
    def _line(node, parents):
        return getattr(node, "lineno", None) or getattr(statement(node, parents), "lineno", 0)

    def _held(self, into, f, node, parents, done=None):
        s = statement(node, parents)
        if done is not None:
            if id(s) in done:
                return
            done.add(id(s))
        into.append((f, Scan.where(s, parents), ast.unparse(s), s.lineno))

    def _count(self, f, node, parents, word):
        key = (f, Scan.where(node, parents), word)
        self.words[key] += 1
        self.lines.setdefault(key, []).append(self._line(node, parents))

    # --- E1, E2: every mention; the environment; the statement around a load ---
    def _file(self, f, tree, parents):
        imports = [a for n in nodes(tree) if isinstance(n, ast.Import) for a in n.names]
        sys_names = {a.asname or "sys" for a in imports if a.name == "sys"}
        os_names = {a.asname or "os" for a in imports if a.name == "os"} | {
            "os" for a in imports if a.name.startswith("os.") and not a.asname}
        environ_names = {a.asname or a.name for n in nodes(tree) if isinstance(n, ast.ImportFrom)
                         and n.module == "os" for a in n.names if a.name == "environ"}
        stated, env, words = set(), set(), index(tree)
        for word in WORDS:
            for node in words.get(word, ()):
                self._count(f, node, parents, word)
                if word in STATEMENT_WORDS:
                    self._held(self.statements, f, node, parents, stated)
        for node in nodes(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
                for word, pattern in PATTERNS.items():
                    if word in text:
                        for _ in pattern.finditer(text):
                            self._count(f, node, parents, word)
                continue
            if isinstance(node, ast.Attribute) and node.attr == "modules" and isinstance(node.value, ast.Name) and \
                    node.value.id in sys_names or isinstance(node, ast.ImportFrom) and node.module == "sys" and \
                    any(a.name == "modules" for a in node.names):
                self._count(f, node, parents, SYS_MODULES)
            if isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name) and \
                    node.value.id in os_names or isinstance(node, ast.Name) and node.id in environ_names or \
                    isinstance(node, ast.ImportFrom) and node.module == "os" and \
                    any(a.name == "environ" for a in node.names):
                if not self._read(node, parents):
                    self._held(self.environ, f, node, parents, env)

    @staticmethod
    def _read(node, parents):
        """os.environ read for one name: a subscript read, .get given a string written in the code, `in`."""
        up = parents.get(node)
        if isinstance(up, ast.Subscript) and up.value is node and isinstance(up.ctx, ast.Load):
            return True
        if isinstance(up, ast.Attribute) and up.value is node and up.attr == "get":
            call = parents.get(up)
            return isinstance(call, ast.Call) and call.func is up and not call.keywords and \
                1 <= len(call.args) <= 2 and isinstance(call.args[0], ast.Constant) and \
                isinstance(call.args[0].value, str) and not any(isinstance(a, ast.Starred) for a in call.args)
        if isinstance(up, ast.Compare):
            return any(c is node and isinstance(op, (ast.In, ast.NotIn)) for c, op in zip(up.comparators, up.ops))
        return False

    # --- E4: ctypes itself ---
    def _ctypes(self, f, tree, parents):
        names, via, done = {}, {"ctypes": "ctypes", "wintypes": "ctypes.wintypes"}, set()
        for node in nodes(tree):
            if isinstance(node, ast.Import) and any(a.name.split(".")[0] in ("ctypes", "_ctypes")
                                                    for a in node.names):
                self._held(self.imports, f, node, parents)
                for a in node.names:
                    if a.name.split(".")[0] in ("ctypes", "_ctypes"):
                        names[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in ("ctypes",
                                                                                                    "_ctypes"):
                self._held(self.imports, f, node, parents)
                for a in node.names:
                    sub = "%s.%s" % (node.module, a.name)
                    if sub in ("ctypes.wintypes", "ctypes.util"):
                        names[a.asname or a.name] = sub
                    self.attrs.setdefault(sub, []).append((f, node.lineno))

        def module(e):
            if isinstance(e, ast.Name):
                return names.get(e.id)
            if isinstance(e, ast.Attribute):
                up = module(e.value)
                if up == "ctypes" and e.attr in ("wintypes", "util"):
                    return "ctypes." + e.attr
                if up is None and e.attr in via:
                    return via[e.attr]
            return None

        for _ in range(3):   # a module's name handed to a keyword, stored on an object, or bound by assignment
            for node in nodes(tree):
                if isinstance(node, ast.keyword) and node.arg and module(node.value):
                    via.setdefault(node.arg, module(node.value))
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        pairs = zip(t.elts, node.value.elts) if isinstance(t, ast.Tuple) and isinstance(
                            node.value, ast.Tuple) and len(t.elts) == len(node.value.elts) else [(t, node.value)]
                        for target, value in pairs:
                            if module(value) and isinstance(target, ast.Attribute):
                                via.setdefault(target.attr, module(value))
                            elif module(value) and isinstance(target, ast.Name):
                                names.setdefault(target.id, module(value))
        for node in nodes(tree):
            if isinstance(node, ast.Attribute) and module(node.value):
                self.attrs.setdefault("%s.%s" % (module(node.value), node.attr), []).append((f, node.lineno))
            up = parents.get(node)
            if isinstance(node, (ast.Name, ast.Attribute)) and module(node) and not (
                    isinstance(up, ast.Attribute) and up.value is node and isinstance(node.ctx, ast.Load)):
                self._held(self.bound, f, node, parents, done)   # handed on, bound or stored: held by its statement

    # --- E3: CI-3's road ---
    def _ci3(self):
        for f, w in CI3_FUNCTIONS:
            if f in self.files:
                tree, parents = self.files[f]
                self.whole[(f, w)] = [n for n in nodes(tree) if isinstance(n, ast.FunctionDef)
                                      and Scan.qual(n, parents) == w]
        f, w = CI3_FUNCTIONS[0]
        for g, (tree, parents) in sorted(self.files.items()):
            for n in index(tree).get(w.split(".")[-1], ()):
                if isinstance(n, (ast.Name, ast.Attribute)):
                    self._held(self.handover, g, n, parents)

    # --- E5: tables and loaders ---
    def _tables_and_loaders(self):
        """Each table the first hold followed a name to, and each loader it found: its value or body as written;
        and every mention of its name - and of each name held (E5_NAMES), so that a table the first hold no longer
        follows (changed, and so refused) is still counted where it is changed."""
        for f, name in sorted(self.scan.tables_read | {k for k in TABLES if k[0] in self.files}):
            values = [n.value for n in self.files[f][0].body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
            self.tables[(f, name)] = " | ".join(ast.unparse(v) for v in values)
            self.names.add((f, name))
        for (f, w), (node, name) in sorted(self.scan.loader_nodes.items()):
            self.bodies[(f, w)] = ast.unparse(node) if isinstance(node, ast.Lambda) else whole(node)
            self.names.add((f, name))
        names = self.names | set(E5_NAMES)
        for g, (tree, parents) in sorted(self.files.items()):
            for word in sorted({name for _, name in names}):
                for node in index(tree).get(word, ()):
                    if (g, word) in names or isinstance(node, (ast.Attribute, ast.alias, ast.keyword)):
                        key = (g, Scan.where(node, parents), word)
                        self.named[key] += 1
                        self.named_lines.setdefault(key, []).append(self._line(node, parents))

    # --- E6: a library's object ---
    def _use(self, f, node, seen):
        """Where an expression whose value is a library's object goes: a function of it taken by name, or handed to
        a call (held by callee, and followed into a def of its file), or bound to a name (followed); else a fault."""
        tree, parents = self.files[f]
        up, here = parents.get(node), Scan.where(node, parents)
        if isinstance(up, ast.Attribute) and up.value is node and not up.attr.startswith("_"):
            return   # a function of it, taken by name
        if isinstance(up, ast.Call) and any(a is node for a in up.args):
            callee, i = ast.unparse(up.func), [k for k, a in enumerate(up.args) if a is node][0]
            if callee == "getattr" and i == 0 and len(up.args) in (2, 3) and self._written(f, up.args[1]):
                return
            key = (f, here, callee)
            self.handed[key] += 1
            self.handed_lines.setdefault(key, []).append(up.lineno)
            d = self._def(f, up, callee)
            if d is not None and not any(isinstance(a, ast.Starred) for a in up.args[:i + 1]):
                params = [p.arg for p in d.args.posonlyargs + d.args.args]
                if i < len(params):
                    self._bound(f, d, params[i], None, seen)
            return
        if isinstance(up, ast.keyword) and up.value is node and isinstance(parents.get(up), ast.Call):
            key = (f, here, "%s(%s=)" % (ast.unparse(parents.get(up).func), up.arg))
            self.handed[key] += 1
            self.handed_lines.setdefault(key, []).append(up.value.lineno)
            self._attribute(f, up.arg, seen)
            return
        target = self._target(node, parents)
        if target is not None:
            self._bound(f, self._scope(target[0], parents) or tree, target[1], target[0], seen)
            return
        if isinstance(up, ast.Assign) and up.value is node and len(up.targets) == 1 and \
                isinstance(up.targets[0], ast.Attribute):   # kept on an object: held, and its attribute followed
            key = (f, here, "%s=" % ast.unparse(up.targets[0]))
            self.handed[key] += 1
            self.handed_lines.setdefault(key, []).append(up.lineno)
            self._attribute(f, up.targets[0].attr, seen)
            return
        self._held(self.other, f, node, parents)   # any other use: held by its statement, where the tree has it

    def _attribute(self, f, attr, seen):
        if (f, "." + str(attr)) not in seen:
            seen.add((f, "." + str(attr)))
            for n in index(self.files[f][0]).get(attr, ()):   # an object's attribute of that name, in its file
                if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
                    self._use(f, n, seen)

    @staticmethod
    def _scope(node, parents):
        n = parents.get(node)
        while n is not None and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n = parents.get(n)
        return n

    @staticmethod
    def _target(node, parents):
        """(the Assign, the name) where `node` is bound to one name, alone or in a tuple of the same length."""
        up = parents.get(node)
        if isinstance(up, ast.Assign) and up.value is node and len(up.targets) == 1 and \
                isinstance(up.targets[0], ast.Name):
            return up, up.targets[0].id
        if isinstance(up, ast.Tuple) and isinstance(parents.get(up), ast.Assign) and parents.get(up).value is up:
            a = parents.get(up)
            i = [k for k, e in enumerate(up.elts) if e is node][0]
            if len(a.targets) == 1 and isinstance(a.targets[0], ast.Tuple) and \
                    len(a.targets[0].elts) == len(up.elts) and isinstance(a.targets[0].elts[i], ast.Name):
                return a, a.targets[0].elts[i].id
        return None

    def _bound(self, f, scope, name, binding, seen):
        if (f, id(scope), name) in seen:
            return
        seen.add((f, id(scope), name))
        parents = self.files[f][1]
        inside = {id(x) for x in ast.walk(binding)} if binding is not None else set()
        for n in ast.walk(scope):
            if isinstance(n, ast.Name) and n.id == name and id(n) not in inside:
                if isinstance(n.ctx, ast.Load):
                    self._use(f, n, seen)
                else:   # its name bound again (or deleted): held by its statement
                    self._held(self.rebound, f, n, parents)

    def _def(self, f, call, callee):
        """The def of this file a call by a plain name calls: in the function that makes the call, else at the top."""
        tree, parents = self.files[f]
        if not isinstance(call.func, ast.Name):
            return None
        scope = self._scope(call, parents)
        for top in ([scope] if scope is not None else []) + [tree]:
            body = ast.walk(top) if top is scope else iter(tree.body)
            got = [n for n in body if isinstance(n, ast.FunctionDef) and n.name == callee]
            if got:
                return got[0]
        return None

    def _written(self, f, expr):
        """A string written in the code: here, or a parameter every call of its def (in its file) gives as one."""
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return True
        tree, parents = self.files[f]
        scope = self._scope(expr, parents)
        if not isinstance(expr, ast.Name) or scope is None:
            return False
        params = [p.arg for p in scope.args.posonlyargs + scope.args.args]
        if expr.id not in params or any(isinstance(n, ast.Name) and n.id == expr.id and not isinstance(
                n.ctx, ast.Load) for n in ast.walk(scope)):
            return False
        i = params.index(expr.id)
        calls = [c for c in nodes(tree) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                 and c.func.id == scope.name]
        return bool(calls) and all(len(c.args) > i and not any(isinstance(a, ast.Starred) for a in c.args[:i + 1])
                                   and isinstance(c.args[i], ast.Constant) and isinstance(c.args[i].value, str)
                                   for c in calls)


def scan_all(sources):
    """(the first hold's scan, the layers on it) of {filename: source}."""
    s = Scan()
    for name, text in sorted(sources.items()):
        s.add(text, name)
    return s, Mentions(s.run()).run()


_REAL = {}


def real_sources():
    """{filename: source} of every .py file of raqib/, read once."""
    if not _REAL:
        for path in sorted((ROOT / "raqib").rglob("*.py")):
            _REAL[path.relative_to(ROOT).as_posix()] = path.read_text(encoding="utf-8")
    return dict(_REAL)


def _counted(out, found, lines, held, what):
    for key in sorted(set(found) | set(held)):
        if found.get(key, 0) > held.get(key, 0):
            out += [(key[0], n, "%s: a mention more than held, %r: %d, held %d" % (what, key, found[key],
                                                                                held.get(key, 0)))
                    for n in sorted(set(lines.get(key) or [0]))]
        elif found.get(key, 0) < held.get(key, 0):
            out.append((key[0], 0, "%s: a mention fewer than held, %r: %d, held %d" % (what, key, found.get(key, 0),
                                                                                    held[key])))


def _listed(out, found, held, what):
    got, kept = Counter((f, w, t) for f, w, t, _ in found), Counter(held)
    for f, w, t, n in found:
        if got[(f, w, t)] > kept[(f, w, t)]:
            out.append((f, n, "%s: a statement not held, in %s: %s" % (what, w, t[:200])))
    for (f, w, t), k in sorted((kept - got).items()):
        out.append((f, 0, "%s: a held statement not found, in %s: %s" % (what, w, t[:200])))


def problems(m):
    """What the layers found that the held tables do not hold, or held that they did not find: [(file, line, why)],
    each line where it was found (0: a held thing not found)."""
    out = list(m.faults)
    _counted(out, m.words, m.lines, MENTIONS, "E1")
    _listed(out, m.environ, ENVIRON, "E1 (os.environ)")
    _listed(out, m.statements, STATEMENTS, "E2")
    for (f, w), text in sorted(CI3_TEXT.items()):
        fns = m.whole.get((f, w), [])
        if len(fns) != 1:
            out.append((f, fns[1].lineno if len(fns) > 1 else 0, "E3: %s is not found once" % w))
            continue
        if whole(fns[0]) != text:
            kept = {line.strip() for line in text.split("\n")}
            changed = [s.lineno for s in ast.walk(fns[0]) if isinstance(s, ast.stmt) and s is not fns[0]
                       and any(line.strip() not in kept for line in ast.unparse(s).split("\n"))]
            out += [(f, n, "E3: %s is not held word for word" % w) for n in sorted(set(changed) or {fns[0].lineno})]
    _listed(out, m.handover, CI3_HANDOVER, "E3 (the hand-over)")
    for attr in sorted(set(m.attrs) - set(CTYPES_ATTRS)):
        out += [(f, n, "E4: %s: an attribute of ctypes not on the list" % attr) for f, n in m.attrs[attr]]
    out += [("", 0, "E4: %s: on the list, not found" % a) for a in sorted(set(CTYPES_ATTRS) - set(m.attrs))]
    _listed(out, m.imports, CTYPES_IMPORTS, "E4 (an import)")
    _listed(out, m.bound, CTYPES_BOUND, "E4 (ctypes bound or handed on)")
    for key in sorted(set(m.tables) | set(TABLES)):
        if m.tables.get(key) != TABLES.get(key):
            out.append((key[0], 0, "E5: the table %s is not held as written: %s" % (key[1], m.tables.get(key))))
    for key in sorted(set(m.bodies) | set(LOADER_BODIES)):
        if m.bodies.get(key) != LOADER_BODIES.get(key):
            out.append((key[0], 0, "E5: the loader in %s is not held as written: %s" % (key[1], m.bodies.get(key))))
    if m.names != set(E5_NAMES):
        out.append(("", 0, "E5: the tables and loaders found are not those held: %s" % sorted(m.names)))
    _counted(out, m.named, m.named_lines, NAMED, "E5")
    _counted(out, m.handed, m.handed_lines, HANDED_OBJECTS, "E6 (a library's object handed to)")
    _listed(out, m.rebound, REBOUND, "E6 (a library's object's name bound again)")
    _listed(out, m.other, OTHER_USES, "E6 (a library's object used otherwise)")
    return out


def _table(text):
    """{(file, function, word): count} of a held table's lines, `file function word count` (no key twice)."""
    out = {}
    for line in text.strip().splitlines():
        f, w, word, n = line.split()
        assert (f, w, word) not in out, line
        out[(f, w, word)] = int(n)
    return out


def _lit(s, indent):
    """A string as adjacent literals, each under the line's width (for the held tables' text)."""
    parts, chunk = [], ""
    for c in s:
        if len(repr(chunk + c)) > 112 - indent:
            parts.append(repr(chunk))
            chunk = ""
        chunk += c
    parts.append(repr(chunk))
    return ("\n" + " " * indent).join(parts)


def dump_held():   # not a test: prints what the layers find in raqib/, to be pasted as the held tables
    m = scan_all(real_sources())[1]

    def table(name, counts):
        print("%s = _table(\"\"\"" % name)
        for k in sorted(counts):
            print("%s %s %s %d" % (k + (counts[k],)))
        print("\"\"\")")

    def listed(name, rows):
        print("%s = (" % name)
        for f, w, t in sorted(rows):
            print("    (%r, %r,\n     %s)," % (f, w, _lit(t, 5)))
        print(")")
    table("MENTIONS", m.words)
    listed("ENVIRON", [r[:3] for r in m.environ])
    listed("STATEMENTS", [r[:3] for r in m.statements])
    print("CI3_TEXT = {")
    for k, fns in sorted(m.whole.items()):
        print("    %r:\n        %s," % (k, _lit(whole(fns[0]), 8)))
    print("}")
    listed("CI3_HANDOVER", [r[:3] for r in m.handover])
    print("CTYPES_ATTRS = (")
    line = "   "
    for a in sorted(m.attrs):
        if len(line) + len(repr(a)) + 2 > 116:
            print(line)
            line = "   "
        line += " %r," % a
    print(line + "\n)")
    listed("CTYPES_IMPORTS", [r[:3] for r in m.imports])
    listed("CTYPES_BOUND", [r[:3] for r in m.bound])
    print("TABLES = {")
    for k, t in sorted(m.tables.items()):
        print("    %r:\n        %s," % (k, _lit(t, 8)))
    print("}\nLOADER_BODIES = {")
    for k, t in sorted(m.bodies.items()):
        print("    %r:\n        %s," % (k, _lit(t, 8)))
    print("}")
    table("NAMED", m.named)
    table("HANDED_OBJECTS", m.handed)
    listed("REBOUND", [r[:3] for r in m.rebound])
    listed("OTHER_USES", [r[:3] for r in m.other])
    print("# faults: %r" % (m.faults,))


# --- the held tables (R-3): pasted from what dump_held() prints of raqib/, compared whole and exactly ---
MENTIONS = _table("""
raqib/app.py <module> importlib 1
raqib/app.py Window._wide eval 1
raqib/app.py _win_api.Api.DwmSetWindowAttribute windll 1
raqib/app.py _win_api.Api.SetProcessDpiAwareness windll 1
raqib/app.py probe_tk import_module 1
raqib/app.py probe_tk importlib 1
raqib/autostart.py <module> compile 2
raqib/autostart.py _windows_drive_kind WinDLL 1
raqib/autostart.py _windows_opener WinDLL 1
raqib/cli.py <module> eval 5
raqib/cli.py _parser eval 1
raqib/cli.py cmd_eval eval 1
raqib/cli.py main eval 1
raqib/cli.py main.set_dll_directory_w SetDllDirectoryW 1
raqib/cli.py main.set_dll_directory_w WinDLL 1
raqib/discover.py <module> compile 10
raqib/discover.py _merge_procs exec 1
raqib/discover.py _programs_of exec 1
raqib/discover.py parse_procevents exec 1
raqib/etwnet.py <module> compile 1
raqib/etwnet.py Api WinDLL 1
raqib/etwnet.py Api.__init__ WinDLL 1
raqib/event.py <module> compile 7
raqib/forward.py <module> compile 8
raqib/forward.py eventlog_dll WinDLL 1
raqib/hooks/capture.py <module> globals 1
raqib/hooks/capture.py _load_common importlib 3
raqib/hooks/common.py <module> compile 14
raqib/hooks/common.py _program_name builtins 1
raqib/hooks/os_sysmon.py <module> compile 7
raqib/host.py HostWatch._give_kept __dict__ 1
raqib/host.py HostWatch._host_lines __dict__ 3
raqib/host.py HostWatch._keep_child __dict__ 2
raqib/host.py HostWatch.procevents_lines exec 1
raqib/host.py child_names exec 1
raqib/hostwin.py <module> compile 1
raqib/hostwin.py Api WinDLL 1
raqib/hostwin.py Api.__init__ WinDLL 1
raqib/hostwin.py probe WinDLL 1
raqib/install.py <module> compile 2
raqib/install.py <module> exec 1
raqib/install.py <module> globals 1
raqib/link.py <module> compile 2
raqib/notify.py <module> compile 1
raqib/notify.py <module> exec 1
raqib/overlay.py load_measured __import__ 1
raqib/own.py library_folder SetDllDirectoryW 5
raqib/procevents.py <module> exec 18
raqib/procevents.py Reader.__init__ exec 1
raqib/procevents.py Reader._missed_words exec 1
raqib/procevents.py Reader._on_exec exec 1
raqib/procevents.py Reader._read_exec exec 2
raqib/procevents.py Reader._start exec 1
raqib/procevents.py Reader._take exec 1
raqib/procevents.py Reader.counts exec 2
raqib/procevents.py parse exec 2
raqib/procevents.py serve exec 1
raqib/procevents.py stat_name exec 1
raqib/ruleform.py <module> compile 2
raqib/ruleform.py <module> exec 2
raqib/rules/engine.py <module> compile 9
raqib/rules/engine.py _predicate compile 1
raqib/rules/engine.py compile_rule compile 1
raqib/rules/fixturegen.py <module> compile 1
raqib/rules/trace.py <module> compile 2
raqib/rules/trace.py strict_problem eval 1
raqib/rules/yamlite.py <module> compile 4
raqib/service.py <module> compile 2
raqib/tray.py _Api windll 1
raqib/tray.py _Api.__init__ WinDLL 3
raqib/tray.py _BoxApi.__init__ WinDLL 1
raqib/ui.py Kernel32.__init__ WinDLL 1
raqib/wincode.py <module> compile 8
raqib/wincode.py <module> exec 2
raqib/wincode.py _plain exec 6
raqib/wincode.py plain_words exec 4
raqib/winservice.py System._win WinDLL 2
""")
ENVIRON = (
    ('raqib/app.py', 'Controller.open_page',
     'environ = os.environ if self.options is None or self.options.environ is None else self.options.environ'),
    ('raqib/app.py', 'run',
     'environ = os.environ if options.environ is None else options.environ'),
    ('raqib/autostart.py', '_sure',
     'held = os.environ if environ is None else environ'),
    ('raqib/autostart.py', 'default_folders',
     'environ = os.environ if environ is None else environ'),
    ('raqib/cli.py', '_gap_seconds',
     'return silence.gap_seconds_from(os.environ)'),
    ('raqib/cli.py', '_watch_setup',
     'gap = silence.gap_seconds_from(os.environ)'),
    ('raqib/cli.py', 'cmd_eval',
     'result = evaluation.evaluate(events, _catalog(args.catalog), backends, args.threshold, args.window, silen'
     'ce.gap_seconds_from(os.environ))'),
    ('raqib/discover.py', 'collect_live',
     'system_root, _ = notify.windows_root(os.environ)'),
    ('raqib/doctor.py', 'checks',
     'environ = os.environ if environ is None else environ'),
    ('raqib/hooks/os_sysmon.py', 'read_live',
     'environ = os.environ if environ is None else environ'),
    ('raqib/hooks/os_sysmon.py', 'read_live_bounded',
     'environ = os.environ if environ is None else environ'),
    ('raqib/host.py', 'start',
     'environ = os.environ if environ is None else environ'),
    ('raqib/notify.py', 'Notifier.__init__',
     'self.environ = dict(os.environ if environ is None else environ)'),
    ('raqib/own.py', 'handed',
     'out = dict(os.environ if environ is None else environ)'),
    ('raqib/watch.py', 'open_page',
     'environ = os.environ if environ is None else environ'),
    ('raqib/watch.py', 'start',
     'environ = os.environ if environ is None else environ'),
    ('raqib/winservice.py', 'System.getenv',
     'return os.environ.get(name)'),
    ('raqib/winservice.py', 'System.setenv',
     'os.environ[name] = value'),
)
STATEMENTS = (
    ('raqib/app.py', '_win_api.Api.DwmSetWindowAttribute',
     'fn = ctypes.windll.dwmapi.DwmSetWindowAttribute'),
    ('raqib/app.py', '_win_api.Api.SetProcessDpiAwareness',
     'fn = ctypes.windll.shcore.SetProcessDpiAwareness'),
    ('raqib/autostart.py', '_windows_drive_kind',
     "k = ctypes.WinDLL('kernel32')"),
    ('raqib/autostart.py', '_windows_opener',
     "k = ctypes.WinDLL('kernel32', use_last_error=True)"),
    ('raqib/cli.py', 'main.set_dll_directory_w',
     "fn = ctypes.WinDLL('kernel32', use_last_error=True).SetDllDirectoryW"),
    ('raqib/etwnet.py', 'Api.__init__',
     'loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))'),
    ('raqib/forward.py', 'eventlog_dll',
     'return ctypes.WinDLL(name, use_last_error=True)'),
    ('raqib/hostwin.py', 'Api.__init__',
     'loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))'),
    ('raqib/hostwin.py', 'probe',
     'loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))'),
    ('raqib/tray.py', '_Api.__init__',
     "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)"),
    ('raqib/tray.py', '_Api.__init__',
     "shell32 = ctypes.WinDLL('shell32', use_last_error=True)"),
    ('raqib/tray.py', '_Api.__init__',
     "user32 = ctypes.WinDLL('user32', use_last_error=True)"),
    ('raqib/tray.py', '_BoxApi.__init__',
     "user32 = ctypes.WinDLL('user32', use_last_error=True)"),
    ('raqib/ui.py', 'Kernel32.__init__',
     "k = ctypes.WinDLL('kernel32', use_last_error=True)"),
    ('raqib/winservice.py', 'System._win',
     "adv = ctypes.WinDLL('advapi32', use_last_error=True)"),
    ('raqib/winservice.py', 'System._win',
     "k32 = ctypes.WinDLL('kernel32', use_last_error=True)"),
)
CI3_TEXT = {
    ('raqib/cli.py', 'main.set_dll_directory_w'):
        'def set_dll_directory_w(folder):\n    import ctypes\n    from ctypes import wintypes\n    fn = ctypes.'
        "WinDLL('kernel32', use_last_error=True).SetDllDirectoryW\n    fn.argtypes, fn.restype = ([wintypes.LPC"
        'WSTR], wintypes.BOOL)\n    if fn(folder):\n        return 1\n    raise ctypes.WinError(ctypes.get_last'
        '_error())',
    ('raqib/own.py', 'library_folder'):
        'def library_folder(call, frozen=None, platform=None):\n    global LIBRARY_FOLDER\n    made = False\n  '
        '  try:\n        if LIBRARY_FOLDER is not None or not _frozen(frozen) or (not _windows(platform)):\n   '
        '         return None\n        made = True\n        try:\n            got = call(None)\n        except '
        "Exception as exc:\n            result = 'SetDllDirectoryW(NULL) failed: %s' % _said(exc)\n        else"
        ":\n            result = True if got else 'SetDllDirectoryW(NULL) returned %s' % _words(repr(got))\n   "
        " except Exception as exc:\n        if made:\n            result = 'SetDllDirectoryW(NULL) was called, "
        "its result could not be read: %s' % _said(exc)\n        else:\n            result = 'SetDllDirectoryW("
        "NULL) was not called: %s' % _said(exc)\n    LIBRARY_FOLDER = result\n    return result",
}
CI3_HANDOVER = (
    ('raqib/cli.py', 'main',
     "if isinstance(own.library_folder(set_dll_directory_w), str):\n    try:\n        sys.stderr.write('raqib: "
     "%s\\n' % own.library_folder_hole())\n        sys.stderr.flush()\n    except Exception:\n        pass"),
)
CTYPES_ATTRS = (
    'ctypes.ArgumentError', 'ctypes.POINTER', 'ctypes.Structure', 'ctypes.Union', 'ctypes.WINFUNCTYPE',
    'ctypes.WinDLL', 'ctypes.WinError', 'ctypes.addressof', 'ctypes.byref', 'ctypes.c_char_p', 'ctypes.c_int',
    'ctypes.c_int32', 'ctypes.c_int64', 'ctypes.c_long', 'ctypes.c_size_t', 'ctypes.c_ssize_t', 'ctypes.c_uint',
    'ctypes.c_uint16', 'ctypes.c_uint32', 'ctypes.c_uint64', 'ctypes.c_uint8', 'ctypes.c_ulong', 'ctypes.c_ushort',
    'ctypes.c_void_p', 'ctypes.c_wchar_p', 'ctypes.cast', 'ctypes.create_string_buffer',
    'ctypes.create_unicode_buffer', 'ctypes.get_last_error', 'ctypes.sizeof', 'ctypes.string_at', 'ctypes.windll',
    'ctypes.wintypes', 'ctypes.wintypes.ATOM', 'ctypes.wintypes.BOOL', 'ctypes.wintypes.BYTE',
    'ctypes.wintypes.DWORD', 'ctypes.wintypes.HANDLE', 'ctypes.wintypes.HBRUSH', 'ctypes.wintypes.HICON',
    'ctypes.wintypes.HINSTANCE', 'ctypes.wintypes.HMENU', 'ctypes.wintypes.HMODULE', 'ctypes.wintypes.HWND',
    'ctypes.wintypes.LPARAM', 'ctypes.wintypes.LPCWSTR', 'ctypes.wintypes.LPVOID', 'ctypes.wintypes.LPWSTR',
    'ctypes.wintypes.MSG', 'ctypes.wintypes.POINT', 'ctypes.wintypes.UINT', 'ctypes.wintypes.ULONG',
    'ctypes.wintypes.WCHAR', 'ctypes.wintypes.WORD', 'ctypes.wintypes.WPARAM',
)
CTYPES_IMPORTS = (
    ('raqib/app.py', '_win_api',
     'import ctypes'),
    ('raqib/autostart.py', '_windows_drive_kind',
     'from ctypes import wintypes'),
    ('raqib/autostart.py', '_windows_drive_kind',
     'import ctypes'),
    ('raqib/autostart.py', '_windows_opener',
     'from ctypes import wintypes'),
    ('raqib/autostart.py', '_windows_opener',
     'import ctypes'),
    ('raqib/cli.py', 'main.set_dll_directory_w',
     'from ctypes import wintypes'),
    ('raqib/cli.py', 'main.set_dll_directory_w',
     'import ctypes'),
    ('raqib/etwnet.py', '<module>',
     'import ctypes'),
    ('raqib/forward.py', '<module>',
     'import ctypes'),
    ('raqib/hostwin.py', '<module>',
     'import ctypes'),
    ('raqib/tray.py', '_Api.__init__',
     'from ctypes import wintypes as w'),
    ('raqib/tray.py', '_Api.__init__',
     'import ctypes'),
    ('raqib/tray.py', '_BoxApi.__init__',
     'from ctypes import wintypes as w'),
    ('raqib/tray.py', '_BoxApi.__init__',
     'import ctypes'),
    ('raqib/ui.py', 'Kernel32.__init__',
     'from ctypes import wintypes'),
    ('raqib/ui.py', 'Kernel32.__init__',
     'import ctypes'),
    ('raqib/winservice.py', 'System._win',
     'from ctypes import wintypes'),
    ('raqib/winservice.py', 'System._win',
     'import ctypes'),
)
CTYPES_BOUND = (
    ('raqib/forward.py', 'EventLogApi.__init__',
     "self.last_error = last_error or getattr(ctypes, 'get_last_error', None)"),
    ('raqib/tray.py', '_Api.__init__',
     'self.ctypes, self.w = (ctypes, w)'),
    ('raqib/ui.py', 'Kernel32.__init__',
     'self.ctypes, self.wintypes = (ctypes, wintypes)'),
    ('raqib/winservice.py', 'System._win',
     'self._api = types.SimpleNamespace(ctypes=ctypes, w=wintypes, adv=adv, k32=k32, status=SERVICE_STATUS, att'
     'ributes=SECURITY_ATTRIBUTES, entry=SERVICE_TABLE_ENTRY, handler=handler_ex, main=service_main)'),
    ('raqib/winservice.py', 'System.make_closed',
     'ctypes, w = (api.ctypes, api.w)'),
    ('raqib/winservice.py', 'System.read_drive',
     'ctypes, k32 = (api.ctypes, api.k32)'),
    ('raqib/winservice.py', 'System.read_place',
     'ctypes, w, k32 = (api.ctypes, api.w, api.k32)'),
)
TABLES = {
    ('raqib/hostwin.py', 'SYMBOLS'):
        "{'kernel32': ('CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW', 'OpenProcess', 'QueryFu"
        "llProcessImageNameW', 'GetProcessTimes', 'CloseHandle'), 'iphlpapi': ('GetExtendedTcpTable',), 'dnsapi"
        "': ('DnsGetCacheDataTable', 'DnsFree', 'DnsQuery_W', 'DnsRecordListFree')}",
    ('raqib/winservice.py', 'HOME_NAMES'):
        "('HOME', 'USERPROFILE')",
}
LOADER_BODIES = {
    ('raqib/etwnet.py', 'Api.__init__'):
        'lambda name: ctypes.WinDLL(name, use_last_error=True)',
    ('raqib/forward.py', 'eventlog_dll'):
        'def eventlog_dll(name):\n    return ctypes.WinDLL(name, use_last_error=True)',
    ('raqib/hostwin.py', 'Api.__init__'):
        'lambda name: ctypes.WinDLL(name, use_last_error=True)',
    ('raqib/hostwin.py', 'probe'):
        'lambda name: ctypes.WinDLL(name, use_last_error=True)',
}
E5_NAMES = (("raqib/etwnet.py", "loader"), ("raqib/forward.py", "eventlog_dll"), ("raqib/hostwin.py", "SYMBOLS"),
            ("raqib/hostwin.py", "loader"), ("raqib/winservice.py", "HOME_NAMES"))   # (file, name): E5's names
NAMED = _table("""
raqib/etwnet.py Api.__init__ loader 4
raqib/forward.py <module> eventlog_dll 1
raqib/forward.py EventLogApi.__init__ eventlog_dll 1
raqib/forward.py Forwarder.__init__ loader 1
raqib/forward.py Forwarder.eventlog_api loader 1
raqib/hooks/capture.py _load_common loader 1
raqib/hostwin.py <module> SYMBOLS 1
raqib/hostwin.py Api.__init__ loader 6
raqib/hostwin.py probe SYMBOLS 1
raqib/hostwin.py probe loader 4
raqib/winservice.py <module> HOME_NAMES 1
raqib/winservice.py Runner._serve HOME_NAMES 1
""")
HANDED_OBJECTS = _table("""
raqib/autostart.py _windows_opener share_opener 1
raqib/etwnet.py Api.__init__ fn 7
raqib/hostwin.py Api.__init__ fn 12
raqib/hostwin.py probe hasattr 1
raqib/tray.py _Api.__init__ fn 23
raqib/ui.py Kernel32.__init__ self.k= 1
raqib/winservice.py System._win types.SimpleNamespace(adv=) 1
raqib/winservice.py System._win types.SimpleNamespace(k32=) 1
""")
REBOUND = (
    ('raqib/autostart.py', '_windows_drive_kind',
     'k = kernel32'),
)
OTHER_USES = (
    ('raqib/autostart.py', '_windows_drive_kind',
     'if k is None:\n    try:\n        import ctypes\n        from ctypes import wintypes\n        k = ctypes.W'
     "inDLL('kernel32')\n        k.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]\n        k.GetDriveTypeW.restype"
     ' = wintypes.UINT\n    except Exception:\n        return None'),
)


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
    assert s.words == ALLOWED_WORDS and s.handed == ALLOWED_HANDED and s.ci3 == CI3_FILES   # Q-4: each read
    assert len(s.lambdas) == 3 and {f for f, _, _, _ in s.lambdas} == {"raqib/etwnet.py", "raqib/hostwin.py"}


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
    # Q-4 (the review's finding 9): each a fault
    ("import ctypes\ndef f():\n    return ctypes.windll['kernel32'].F\n", set(), set(), "a loader asked by index"),
    ("import ctypes\ndef f(n):\n    ctypes.cdll[n]\n", set(), set(), "a loader asked by index"),
    ("from ctypes import oledll as o\ndef f():\n    o['x']\n", set(), set(), "a loader asked by index"),
    ("import ctypes\ndef f():\n    ctypes._dlopen('x', 0)\n", set(), set(), "ctypes' low loader"),
    ("from ctypes import _dlopen\n", set(), set(), "from ctypes import _dlopen"),
    ("import ctypes\ndef f():\n    return getattr(ctypes, '_dlopen')\n", set(), set(), "a load this scan cannot"),
    ("import ctypes\ndef f():\n    return ctypes.LibraryLoader(ctypes.WinDLL).k\n", set(), set(),
     "ctypes.LibraryLoader: ctypes' low loader, or the class"),
    ("from ctypes import LibraryLoader\n", set(), set(), "from ctypes import LibraryLoader"),
    ("import ctypes\ndef f():\n    ctypes.WinDLL('k', 0, None, False, False, 0)\n", {"k"}, {"WinDLL"},
     "a loading call given more than its name"),
    ("import ctypes\ndef f(kw):\n    ctypes.CDLL('k', **kw)\n", {"k"}, {"CDLL"}, "a loading call given more"),
    ("import ctypes\ndef f(a):\n    ctypes.WinDLL('k', *a)\n", {"k"}, {"WinDLL"}, "a loading call given more"),
    ("import ctypes\ndef f():\n    ctypes.cdll.LoadLibrary('k', 0)\n", {"k"}, {"LoadLibrary"},
     "a loading call given more"),
    ("import ctypes\ndef f(loader=None):\n    loader = loader or (lambda name, *a: ctypes.WinDLL(name, *a))\n"
     "    loader('one', 8)\n", {"one"}, {"loader"}, "a loading call given more"),
    ("import ctypes\ndef f():\n    getattr(ctypes.WinDLL('kernel32'), 'LoadLibraryW')('x')\n", {"kernel32"},
     {"WinDLL"}, "LoadLibraryW: a search call's or a setter's name written in a string"),
    ("import os\ndef f():\n    getattr(os, 'add_dll_directory')('C:\\\\x')\n", set(), set(),
     "add_dll_directory: a search call's"),
    ("T = ('SetDefaultDllDirectories', 'x')\n", set(), set(), "SetDefaultDllDirectories: a search call's"),
    ("def f():\n    return b'AddDllDirectory'\n", set(), set(), "AddDllDirectory: a search call's"),
    ("import os\ndef f():\n    os.environ |= {'X': 'y'}\n", set(), set(), "the environment written whole"),
    ("from os import environ\ndef f():\n    environ |= {'X': 'y'}\n", set(), set(), "the environment written whole"),
    ("import os\ndef f():\n    os.environ = {}\n", set(), set(), "the environment written whole"),
    ("import os\ndef f():\n    os.environ.update({'X': 'y'})\n", set(), set(), "the environment written from"),
    ("import os\ndef f():\n    os.putenv('X', 'y')\n", set(), set(), "putenv: the environment set past"),
    ("import ctypes\ndef f():\n    ctypes.windll.kernel32.SetEnvironmentVariableW('X', 'y')\n", {"kernel32"},
     {"windll"}, "SetEnvironmentVariableW: the environment set past os.environ"),
    ("import ctypes\ndef f():\n    getattr(ctypes.windll.kernel32, 'SetEnvironmentVariableW')('X', 'y')\n",
     {"kernel32"}, {"windll"}, "SetEnvironmentVariableW: a search call's or a setter's name written in a string"),
    ("import ctypes\ndef load(name):\n    return ctypes.WinDLL(name)\ndef f(g):\n    load('a')\n    g(load)\n",
     {"a"}, {"loader"}, "load: a loader handed on as a value"),
    ("import ctypes\ndef load(name):\n    return ctypes.WinDLL(name)\nclass A:\n    pick = load\n"
     "    def f(self):\n        load('a')\n", {"a"}, {"loader"}, "load: a loader handed on as a value"),
    ("import ctypes\ndef f(g, loader=None):\n    loader = loader or (lambda name: ctypes.WinDLL(name))\n"
     "    loader('one')\n    g(loader)\n", {"one"}, {"loader"}, "loader: a loader handed on as a value"),
    ("import ctypes\ndef f():\n    k = ctypes.WinDLL\n    k('x')\n", set(), set(), "handed on as a value"),
    ("import ctypes, functools\ndef f():\n    functools.partial(ctypes.CDLL)('x')\n", set(), set(),
     "handed on as a value"),
    ("import ctypes\nclass K(ctypes.WinDLL):\n    pass\n", set(), set(), "handed on as a value"),
    ("import ctypes\ndef f():\n    w = ctypes.windll\n    return w.k\n", set(), set(), "handed on as a value"),
] + [   # Q-4: a table of names changed after its one assignment, each way, at the top or in a function
    ("import ctypes\nT = %s\n%s\ndef f():\n    for n in T:\n        ctypes.WinDLL(n)\n" % (table, change), set(),
     set(), "a table of names changed after its one assignment (T)")
    for table, changes in (("['a']", ("T += ['b']", "T[0] = 'b'", "T.append('b')", "T.extend(['b'])",
                                      "T.insert(0, 'b')", "del T[0]", "T = ['b']", "del T",
                                      "def g():\n    global T\n    T = ['b']")),
                           ("{'a': 1}", ("T.update(b=1)", "T.setdefault('b', 1)", "T['b'] = 1", "T |= {'b': 1}")))
    for change in changes + ("def g():\n    %s" % changes[2],)
]
CLI = ("import ctypes\nfrom raqib import own\ndef main():\n    def set_dll_directory_w(folder):\n"
       "        fn = ctypes.WinDLL('kernel32', use_last_error=True).SetDllDirectoryW\n        fn.argtypes = []\n"
       "        if fn(folder):\n            return 1\n    own.library_folder(set_dll_directory_w)\n%s")
OWN = "def library_folder(call, frozen=None):\n    got = call(None)\n    return %s\n"
MADE_UP += [   # Q-4 (the review's finding 15): CI-3's one road - as it is, then each way off it
    ({"raqib/cli.py": CLI % "", "raqib/own.py": OWN % "got"}, {"kernel32"}, {"WinDLL"}, None),
    ({"raqib/cli.py": CLI % "    set_dll_directory_w('C:\\\\x')\n", "raqib/own.py": OWN % "got"}, {"kernel32"},
     {"WinDLL"}, "CI-3: set_dll_directory_w is named other than once"),
    ({"raqib/cli.py": CLI % "    own.library_folder(set_dll_directory_w)\n", "raqib/own.py": OWN % "got"},
     {"kernel32"}, {"WinDLL"}, "CI-3: set_dll_directory_w is named other than once"),
    ({"raqib/cli.py": CLI.replace("        if fn(folder):", "        fn('C:\\\\x')\n        if fn(folder):") % "",
      "raqib/own.py": OWN % "got"}, {"kernel32"}, {"WinDLL"}, "CI-3: SetDllDirectoryW is read or called more"),
    ({"raqib/cli.py": CLI.replace("if fn(folder):", "if fn('C:\\\\x'):") % "", "raqib/own.py": OWN % "got"},
     {"kernel32"}, {"WinDLL"}, "CI-3: SetDllDirectoryW is read or called more"),
    ({"raqib/cli.py": CLI % "", "raqib/own.py": OWN % "call(None)"}, {"kernel32"}, {"WinDLL"},
     "CI-3: library_folder does not call what it is handed once"),
    ({"raqib/cli.py": CLI % "", "raqib/own.py": OWN.replace("call(None)", "call('C:\\\\x')") % "got"},
     {"kernel32"}, {"WinDLL"}, "CI-3: library_folder does not call what it is handed once"),
    ({"raqib/cli.py": CLI % "", "raqib/own.py": OWN % "call"}, {"kernel32"}, {"WinDLL"},
     "CI-3: library_folder does not call what it is handed once"),
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


def edited(filename, anchor, lines, replace=False):
    """({filename: source} of raqib/ with `lines` put after the one line that holds `anchor` - or in its place - at
    its indentation (one deeper after a line that opens a block; at the end, at none, where anchor is None), the
    number of the first line put)."""
    sources = real_sources()
    text = sources[filename].split("\n")
    if anchor is None:
        at, indent = len(text), ""
    else:
        found = [i for i, line in enumerate(text) if anchor in line]
        assert len(found) == 1, (filename, anchor, found)
        at = found[0]
        indent = text[at][:len(text[at]) - len(text[at].lstrip())]
        indent += "    " if not replace and text[at].rstrip().endswith(":") else ""
        at += 0 if replace else 1
    text[at:at + (1 if replace else 0)] = [indent + line for line in lines]
    sources[filename] = "\n".join(text)
    return sources, at + 1


def test_r3_every_mention_in_raqib_is_held_exactly():
    s, m = scan_all(real_sources())
    assert not s.faults and problems(m) == [], problems(m)
    assert set(MENTIONS) == set(m.words) and sum(MENTIONS.values()) == sum(m.words.values())   # E1: whole, exact
    assert {w for _, _, w in MENTIONS} <= set(WORDS) | {SYS_MODULES} and len(set(WORDS)) == len(WORDS)
    assert {(f, w) for f, w, _ in STATEMENTS} == {(f, w) for f, w, form in RAQIB_LOADS if form != "loader"} | \
        RAQIB_LOADERS   # E2: a statement held at each load of ctypes', and at each of Raqib's own loaders
    assert m.names == set(E5_NAMES) == {(f, n) for f, n in TABLES} | {
        (f, n) for f, _, n in NAMED if (f, n) in m.names}   # E5: each table's and loader's name, as found
    assert set(LOADER_BODIES) == RAQIB_LOADERS and {f for f, _ in TABLES} == {"raqib/hostwin.py",
                                                                              "raqib/winservice.py"}
    assert set(CI3_TEXT) == set(CI3_FUNCTIONS) and len(CI3_HANDOVER) == 1   # E3


W32 = "raqib/winservice.py"    # System._win: where kernel32 is bound as k32
K32 = 'k32 = ctypes.WinDLL("kernel32", use_last_error=True)'
CLI_ARGS = "fn.argtypes, fn.restype = [wintypes.LPCWSTR], wintypes.BOOL"   # CI-3's function, before its call
PROBE = "    out = {}"         # hostwin.probe, after its loader is bound
DPI = "fn = ctypes.windll.shcore.SetProcessDpiAwareness"                    # app.py, a windll load
ESCAPES = [   # (the review's finding, the file it would live in, the line it goes after (or in place of), its lines)
    ("redo-1 a folder bound again in CI-3's function", "raqib/cli.py", CLI_ARGS, ['folder = folder or "C:\\\\x"']),
    ("redo-2 a loader lambda handed on in its own binding line", "raqib/etwnet.py",
     "loader = loader or (lambda name: ctypes.WinDLL(name, use_last_error=True))",
     ["loader = loader or wrap(lambda name: ctypes.WinDLL(name, use_last_error=True))"], True),
    ("redo-3 a table of names changed from another module", "raqib/doctor.py", None, ['hostwin.SYMBOLS["x"] = ()']),
    ("redo-3 a table of names imported and updated", "raqib/doctor.py", None,
     ["from raqib.hostwin import SYMBOLS", "SYMBOLS.update(x=())"]),
    ("redo-4a the interpreter's own low call", "raqib/hostwin.py", PROBE, ["nt._add_dll_directory(path)"]),
    ("redo-4b ctypes by __import__", "raqib/hostwin.py", PROBE, ['__import__("ctypes").WinDLL(path)']),
    ("redo-4b _ctypes by __import__", "raqib/hostwin.py", PROBE, ['__import__("_ctypes").LoadLibrary(path)']),
    ("redo-4b _ctypes by sys.modules", "raqib/hostwin.py", PROBE, ['low = sys.modules["_ctypes"]']),
    ("redo-4c a loader's LoadLibrary bound to a name", "raqib/app.py", DPI,
     ["f = ctypes.windll.LoadLibrary", "f(path)"]),
    ("redo-4c a loader's LoadLibrary handed to map", "raqib/app.py", DPI, ["map(ctypes.windll.LoadLibrary, names)"]),
    ("redo-4c a class's __base__", W32, K32, ["ctypes.WinDLL.__base__(path)"]),
    ("redo-4c a class's __init__", W32, K32, ["ctypes.CDLL.__init__(obj, path)"]),
    ("redo-4c an instance's __class__", W32, K32, ["k32.__class__(path)"]),
    ("redo-4c type() of an instance", W32, K32, ["type(k32)(path)"]),
    ("redo-4c an instance's __init__", W32, K32, ["k32.__init__(path)"]),
    ("redo-4d a function asked by ordinal", W32, K32, ["first = k32[1]"]),
    ("redo-4e the whole environment set by the system's call", W32, K32, ["k32.SetEnvironmentStringsW(block)"]),
    ("redo-4f a docstring read as a value", W32, K32, ["getattr(k32, f.__doc__)"]),
    ("redo-15 CI-3's call in a loop", "raqib/cli.py", CLI_ARGS, ["for _ in range(2): fn(folder)"]),
    ("first-9 a loader asked by index", "raqib/app.py", DPI, ['k = ctypes.windll["kernel32"]']),
    ("first-9 ctypes' low loader", "raqib/hostwin.py", PROBE, ["ctypes._dlopen(path, 0)"]),
    ("first-9 winmode by position", "raqib/tray.py", 'kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)',
     ['kernel32 = ctypes.WinDLL("kernel32", 0, None, False, True, 0)'], True),
    ("first-9 winmode by **", "raqib/ui.py", 'k = ctypes.WinDLL("kernel32", use_last_error=True)',
     ['k = ctypes.WinDLL("kernel32", **kw)'], True),
    ("first-9 a search call's name as a string in getattr", W32, K32, ['getattr(k32, "LoadLibraryW")(path)']),
    ("first-9 getattr of os's add_dll_directory", "raqib/hostwin.py", PROBE, ['getattr(os, "add_dll_directory")']),
    ("first-9 os.environ |=", "raqib/own.py", "    out = dict(os.environ if environ is None else environ)",
     ['os.environ |= {"X": "y"}']),
    ("first-9 a table changed after its assignment", "raqib/hostwin.py", None, ['SYMBOLS["x"] = ()']),
    ("first-9 a loader handed on as a value", "raqib/hostwin.py", PROBE, ["register(loader)"]),
    ("first-9 ctypes.LibraryLoader", "raqib/hostwin.py", PROBE, ["k = ctypes.LibraryLoader(ctypes.WinDLL).k"]),
    ("first-9 a module of ctypes on an attribute", W32, "        ctypes, k32 = api.ctypes, api.k32",
     ["api.ctypes.WinDLL(path)"]),
]
ESCAPES = [e if len(e) == 5 else e + (False,) for e in ESCAPES]


@pytest.mark.parametrize("finding, filename, anchor, lines, replace", ESCAPES, ids=[e[0] for e in ESCAPES])
def test_r3_each_escape_the_reviews_found_fails_for_its_line(finding, filename, anchor, lines, replace):
    sources, at = edited(filename, anchor, lines, replace)
    s, m = scan_all(sources)
    found = problems(m)
    assert [p for p in found if p[0] == filename and p[1] == at], (finding, at, found, s.faults)


NOT_VACUOUS = [   # (the file, the line it goes after (or in place of), its lines, in place, the reason it fails)
    ("raqib/hostwin.py", PROBE, ['why = "exec"'], False, "E1: a mention more than held"),
    ("raqib/overlay.py", 'data = __import__("json").load(f)', ["data = json.load(f)"], True,
     "E1: a mention fewer than held"),
    ("raqib/tray.py", 'user32 = ctypes.WinDLL("user32", use_last_error=True)\n        shell32',
     None, True, "E2: a statement not held"),
    (W32, K32, ["ctypes.memmove(a, b, 1)"], False, "E4: ctypes.memmove: an attribute of ctypes not on the list"),
]


@pytest.mark.parametrize("filename, anchor, lines, replace, why", NOT_VACUOUS)
def test_r3_the_held_tables_are_not_vacuous(filename, anchor, lines, replace, why):
    if lines is None:   # one token changed: True to False in the second user32 load of tray.py
        sources = real_sources()
        text = sources[filename]
        assert text.count(anchor) == 1
        at = text[:text.index(anchor)].count("\n") + 1
        sources[filename] = text.replace(anchor, anchor.replace("True", "False", 1))
    else:
        sources, at = edited(filename, anchor, lines, replace)
    found = problems(scan_all(sources)[1])
    assert [p for p in found if why in p[2] and p[1] in (at, 0)], found
    assert all(p[1] in (at, 0) for p in found), found   # for that reason, at that line, and nothing else
