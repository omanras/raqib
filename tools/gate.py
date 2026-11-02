#!/usr/bin/env python3
"""The constitutional gate. Green = exit 0. Every landed: commit must pass it.

tools/gate.sh runs this on POSIX; on Windows run `python -I tools/gate.py`
(M5.1 E4). It makes the checks gate.sh made with git grep and bash, in the
same order, on the files git tracks, with the rule kinds second:
1. secret scan: a secret-like string in any tracked file, binary or not;
2. ADR-0002 rule kinds (Amendment B, B-2 and B-5): the tracked rule files
   under raqib/rules/catalog/ load with this checkout's own loader (which
   rejects a rule without a kind, or a signature without evasion); every
   catalog and silence rule has one of the gate's three kinds; every
   silence rule of report.SILENCE_RULES has one in silence.RULE_KINDS; and
   one line gives the ratio `rule kinds: signature=N demand=N anchor=N` (a
   health number, not a budget: it never fails the gate by itself);
3. HANDOFF.md has at most 30 lines;
4. private-tree leak check: a reference to a private tree in a text file;
5. ADR-0001 B-3: only raqib/suspect/backends.py imports the anthropic SDK;
6. the tests in tests/, with pytest; if pytest is missing it is installed
   with pip, which needs the network (ADR-0001 A-7).
A check that read nothing has not passed (A3): the gate is RED when git
cannot list the tracked files, when it lists none, when tests/ is missing or
holds no test_*.py, and when the rules cannot be read from this checkout.

Check 2 runs tree code, so it runs in a child process, `python -I
tools/gate.py --rule-kinds-child`: the child imports the standard library
modules the rules use (PREIMPORT) before it puts the checkout at the END of
sys.path, so a tracked json.py or os.py is never imported, and the gate
reads only the child's exit status and its one line of output, so no
SystemExit in tree code can end the gate with exit 0. The child could still
print a forged line and exit 0; so can the tests (check 6), which run tree
code in the pytest process. That exposure is inherent (B-2).
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The gate's own files hold its patterns, so the scans skip them.
GATE_FILES = ("tools/gate.sh", "tools/gate.py")
SECRET = re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"
                    r"|xox[baprs]-[0-9A-Za-z-]{10,})")
LEAK = re.compile(r"haris[-_]?backup|D:\\+haris|falak\.git")
LEAK_EXEMPT = GATE_FILES + ("docs/CONSTITUTION.md",)
HANDOFF_MAX_LINES = 30
SDK_ALLOWED = "raqib/suspect/backends.py"
# Python files are parsed, so a docstring or comment naming the SDK does not
# count and `import os, anthropic` or importlib does; a file that cannot be
# parsed cannot be cleared. Shell files are searched line by line.
SH_IMPORT = re.compile(r"\b(?:import\s+(?:[\w.]+\s*,\s*)*anthropic\b|from\s+anthropic\b)")
# ADR-0002. The gate's own copy, so a loader that came to accept a fourth
# kind would still be caught here.
KINDS = ("signature", "demand", "anchor")
CATALOG = "raqib/rules/catalog/"   # as git lists tracked paths
CHILD_FLAG = "--rule-kinds-child"
CHILD_TIMEOUT_SECONDS = 120
KINDS_LINE = re.compile(r"rule kinds: signature=[0-9]+ demand=[0-9]+ anchor=[0-9]+\Z")
# Every standard library module raqib/__init__.py, raqib/report.py and
# raqib/rules/{__init__,engine,yamlite,trace,silence}.py import (a test holds
# this list to them). The child imports them before the checkout is on sys.path.
PREIMPORT = ("__future__", "datetime", "fnmatch", "glob", "json", "math", "os", "posixpath", "re")


class Red(Exception):
    pass


def say(text):
    print("[gate] " + text, flush=True)


def tracked_files():
    proc = subprocess.run(["git", "ls-files", "-z"], capture_output=True)
    if proc.returncode != 0:
        raise Red("cannot list tracked files (git ls-files: %s)"
                  % proc.stderr.decode("utf-8", "replace").strip())
    files = [p for p in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if p]
    if not files:
        raise Red("git ls-files listed no files; nothing would be scanned")
    return files


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None  # like git grep: a tracked file missing from the tree is not searched


def is_binary(data):
    return b"\0" in data[:8000]  # git's own test, as `git grep -I` uses it


def secret_scan(files):
    say("secret scan")
    for path in files:
        data = read_bytes(path) if path not in GATE_FILES else None
        if data is not None and SECRET.search(data.decode("latin-1")):
            raise Red("secret-like string in tree")


def handoff_length():
    say("handoff length")
    data = read_bytes("HANDOFF.md")
    if data is None:
        raise Red("HANDOFF.md cannot be read")
    if data.count(b"\n") > HANDOFF_MAX_LINES:
        raise Red("HANDOFF.md > %d lines" % HANDOFF_MAX_LINES)


def leak_check(files):
    say("private-tree leak check")
    for path in files:
        data = read_bytes(path) if path not in LEAK_EXEMPT else None
        if data is not None and not is_binary(data) and LEAK.search(data.decode("latin-1")):
            raise Red("reference to a private tree")


def sdk_root(name):
    return isinstance(name, str) and name.split(".")[0] == "anthropic"


def sdk_imports(files):
    say("anthropic SDK imported only by raqib/suspect/backends.py (ADR-0001 B-3)")
    bad = []
    for path in files:
        if not path.endswith((".py", ".sh")) or path in ("tools/gate.sh", SDK_ALLOWED):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as exc:
            bad.append("%s: cannot be read (%s)" % (path, exc.strerror))
            continue
        if path.endswith(".sh"):
            bad += ["%s:%d" % (path, n) for n, line in enumerate(text.splitlines(), 1) if SH_IMPORT.search(line)]
            continue
        try:
            tree = ast.parse(text, path)
        except SyntaxError as exc:
            bad.append("%s:%s: cannot be parsed (%s)" % (path, exc.lineno, exc.msg))
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                hit = any(sdk_root(a.name) for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                hit = node.level == 0 and sdk_root(node.module)
            elif isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                hit = (name in ("import_module", "__import__") and node.args
                       and isinstance(node.args[0], ast.Constant) and sdk_root(node.args[0].value))
            else:
                continue
            if hit:
                bad.append("%s:%d" % (path, node.lineno))
    for b in bad:
        say("  " + b)
    if bad:
        raise Red("anthropic imported outside raqib/suspect/backends.py")


def rule_kinds(files):
    """Check 2: run the child on the tracked rule files; print its one line,
    or RED with its reason. Nothing the child does can end the gate."""
    catalog = sorted(p for p in files if p.startswith(CATALOG) and "/" not in p[len(CATALOG):])
    request = json.dumps({"root": ROOT, "catalog": catalog}).encode("utf-8")
    try:
        proc = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), CHILD_FLAG], input=request,
                              capture_output=True, timeout=CHILD_TIMEOUT_SECONDS, cwd=ROOT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Red("rule kinds: the check did not run (%s: %s)" % (type(exc).__name__, exc))
    out = proc.stdout.decode("ascii", "replace").splitlines()
    if proc.returncode == 0 and len(out) == 1 and KINDS_LINE.match(out[0]):
        say(out[0])
        return
    reds = [line[len("RED: "):] for line in out if line.startswith("RED: ")]
    if proc.returncode == 1 and len(reds) == 1:
        raise Red("rule kinds: " + reds[0])
    raise Red("rule kinds: the check exited %d without its one line (stdout %r, stderr %r)"
              % (proc.returncode, proc.stdout[-300:], proc.stderr[-300:]))


class ChildRed(Exception):
    pass


def kinds_child():
    """The child of check 2. stdin: {"root", "catalog": [tracked paths]}.
    Prints `rule kinds: ...` and returns 0, or `RED: <reason>` and returns 1."""
    try:
        for name in PREIMPORT:
            __import__(name)
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        root, catalog = request["root"], request["catalog"]
        sys.path.append(root)  # at the END, after the standard library (B-2)
        line, code = count_kinds(root, catalog), 0
    except ChildRed as exc:
        line, code = "RED: %s" % exc, 1
    except BaseException as exc:  # tree code may raise anything, SystemExit too
        line, code = "RED: %s while reading the rules: %s" % (type(exc).__name__, exc), 1
    sys.stdout.buffer.write((" ".join(line.split()) + "\n").encode("ascii", "backslashreplace"))
    sys.stdout.flush()
    return code


def count_kinds(root, catalog):
    try:
        from raqib import report
        from raqib.rules import engine, silence
    except Exception as exc:
        raise ChildRed("cannot import raqib.rules from this checkout (%s: %s)" % (type(exc).__name__, exc))
    here = os.path.normcase(os.path.realpath(os.path.join(root, "raqib")))
    for module, sub in ((report, ""), (engine, "rules"), (silence, "rules")):
        where = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(module.__file__))))
        if where != os.path.join(here, sub).rstrip(os.sep):
            raise ChildRed("%s was imported from %s, not from this checkout" % (module.__name__, where))
    stray = [p for p in catalog if p.lower().endswith((".yml", ".yaml")) and not p.endswith(".yaml")]
    if stray:
        raise ChildRed("rule files must end in .yaml: %s" % ", ".join(stray))
    paths = [p for p in catalog if p.endswith(".yaml")]
    if not paths:
        raise ChildRed("the catalog does not load: no tracked rule file under %s" % CATALOG)
    try:
        rules = [engine.load_rule(os.path.join(root, *p.split("/"))) for p in paths]
    except engine.RuleError as exc:
        raise ChildRed("the catalog does not load: %s" % exc)
    declared = getattr(silence, "RULE_KINDS", None)
    if not (isinstance(declared, dict) and declared):
        raise ChildRed("raqib/rules/silence.py declares no RULE_KINDS (rule id -> kind)")
    uncovered = [rule_id for rule_id, _ in report.SILENCE_RULES if rule_id not in declared]
    if uncovered:
        raise ChildRed("report.SILENCE_RULES names %s, with no kind in silence.RULE_KINDS" % ", ".join(uncovered))
    kinds = [(r.id, getattr(r, "kind", None)) for r in rules] + list(declared.items())
    missing = [str(rule_id) for rule_id, kind in kinds if not (isinstance(kind, str) and kind in KINDS)]
    if missing:
        raise ChildRed("no kind (one of %s) for %s" % ("|".join(KINDS), ", ".join(missing)))
    return "rule kinds: " + " ".join("%s=%d" % (k, sum(1 for _, v in kinds if v == k)) for k in KINDS)


def tests():
    say("tests")
    python = sys.executable
    if subprocess.run([python, "-m", "pytest", "--version"], capture_output=True).returncode != 0:
        pip = [python, "-m", "pip", "install", "-q", "pytest"]
        if subprocess.run(pip + ["--break-system-packages"], capture_output=True).returncode != 0:
            subprocess.run(pip, capture_output=True)
    if not os.path.isdir("tests") or not any(
            n.startswith("test_") and n.endswith(".py") for n in os.listdir("tests")):
        raise Red("no tests: tests/ is missing or holds no test_*.py")
    return subprocess.run([python, "-m", "pytest", "-q", "tests"]).returncode


def main():
    os.chdir(ROOT)
    try:
        files = tracked_files()
        secret_scan(files)
        rule_kinds(files)
        handoff_length()
        leak_check(files)
        sdk_imports(files)
        code = tests()
    except Red as exc:
        say("RED: %s" % exc)
        return 1
    if code != 0:
        return code
    say("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(kinds_child() if sys.argv[1:] == [CHILD_FLAG] else main())
