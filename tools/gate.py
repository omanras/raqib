#!/usr/bin/env python3
"""The constitutional gate. Green = exit 0. Every landed: commit must pass it.

tools/gate.sh runs this on POSIX; on Windows run `python -I tools/gate.py`
(M5.1 E4). It makes the checks gate.sh made with git grep and bash, in the
same order, on the files git tracks:
1. secret scan: a secret-like string in any tracked file, binary or not;
2. HANDOFF.md has at most 30 lines;
3. private-tree leak check: a reference to a private tree in a text file;
4. ADR-0001 B-3: only raqib/suspect/backends.py imports the anthropic SDK;
5. ADR-0002 rule kinds: the catalog loads with this checkout's own loader
   (which rejects a rule without a kind, or a signature without evasion),
   every catalog and silence rule has a kind, and one line gives the ratio
   `rule kinds: signature=N demand=N anchor=N` (a health number, not a
   budget: it never fails the gate by itself);
6. the tests in tests/, with pytest; if pytest is missing it is installed
   with pip, which needs the network (ADR-0001 A-7).
A check that read nothing has not passed (A3): the gate is RED when git
cannot list the tracked files, when it lists none, when tests/ is missing or
holds no test_*.py, and when the rules cannot be read from this checkout.
"""
from __future__ import annotations

import ast
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
CATALOG = os.path.join("raqib", "rules", "catalog")


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


def rule_kinds():
    """ADR-0002: every rule has a kind; print the ratio. The rules are read
    from this checkout (python -I leaves it off sys.path), never from an
    installed raqib."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from raqib.rules import engine, silence
    except Exception as exc:
        raise Red("rule kinds: cannot import raqib.rules from this checkout (%s: %s)" % (type(exc).__name__, exc))
    here = os.path.normcase(os.path.realpath(os.path.join(ROOT, "raqib", "rules")))
    for module in (engine, silence):
        where = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(module.__file__))))
        if where != here:
            raise Red("rule kinds: %s was imported from %s, not from this checkout" % (module.__name__, where))
    try:
        rules = engine.load_catalog(os.path.join(ROOT, CATALOG))
    except engine.RuleError as exc:
        raise Red("rule kinds: the catalog does not load: %s" % exc)
    declared = getattr(silence, "RULE_KINDS", None)
    if not (isinstance(declared, dict) and declared):
        raise Red("rule kinds: raqib/rules/silence.py declares no RULE_KINDS (rule id -> kind)")
    kinds = [(r.id, getattr(r, "kind", None)) for r in rules] + list(declared.items())
    missing = [rule_id for rule_id, kind in kinds if not (isinstance(kind, str) and kind in KINDS)]
    if missing:
        raise Red("rule kinds: no kind (one of %s) for %s" % ("|".join(KINDS), ", ".join(map(str, missing))))
    say("rule kinds: " + " ".join("%s=%d" % (k, sum(1 for _, v in kinds if v == k)) for k in KINDS))


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
        handoff_length()
        leak_check(files)
        sdk_imports(files)
        rule_kinds()
        code = tests()
    except Red as exc:
        say("RED: %s" % exc)
        return 1
    if code != 0:
        return code
    say("GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
