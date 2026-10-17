#!/usr/bin/env bash
# The constitutional gate. Green = exit 0. Every landed: commit must pass it.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[gate] secret scan"
if git grep -nE '(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,})' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: secret-like string in tree"; exit 1
fi

echo "[gate] handoff length"
if [ "$(wc -l < HANDOFF.md)" -gt 30 ]; then echo "[gate] RED: HANDOFF.md > 30 lines"; exit 1; fi

echo "[gate] private-tree leak check"
if git grep -nIE 'haris[-_]?backup|D:\\\\haris|falak\.git' -- . ':!tools/gate.sh' ':!docs/CONSTITUTION.md' >/dev/null 2>&1; then
  echo "[gate] RED: reference to a private tree"; exit 1
fi

echo "[gate] anthropic SDK imported only by raqib/suspect/backends.py (ADR-0001 B-3)"
# Python files are parsed, so a docstring or comment naming the SDK does not
# count and `import os, anthropic` or importlib does; a file that cannot be
# parsed cannot be cleared. Shell files are searched line by line.
if ! git ls-files -z -- '*.py' '*.sh' ':!tools/gate.sh' | python3 -I -c '
import ast, re, sys
ALLOWED = "raqib/suspect/backends.py"
SH = re.compile(r"\b(?:import\s+(?:[\w.]+\s*,\s*)*anthropic\b|from\s+anthropic\b)")
def root(name):
    return isinstance(name, str) and name.split(".")[0] == "anthropic"
bad = []
for path in sys.stdin.buffer.read().decode().split("\0"):
    if not path or path == ALLOWED:
        continue
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        bad.append("%s: cannot be read (%s)" % (path, exc.strerror))
        continue
    if path.endswith(".sh"):
        bad += ["%s:%d" % (path, n) for n, line in enumerate(text.splitlines(), 1) if SH.search(line)]
        continue
    try:
        tree = ast.parse(text, path)
    except SyntaxError as exc:
        bad.append("%s:%s: cannot be parsed (%s)" % (path, exc.lineno, exc.msg))
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            hit = any(root(a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            hit = node.level == 0 and root(node.module)
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            hit = (name in ("import_module", "__import__") and node.args
                   and isinstance(node.args[0], ast.Constant) and root(node.args[0].value))
        else:
            continue
        if hit:
            bad.append("%s:%d" % (path, node.lineno))
for b in bad:
    print("[gate]   " + b)
sys.exit(1 if bad else 0)
'; then
  echo "[gate] RED: anthropic imported outside raqib/suspect/backends.py"; exit 1
fi

echo "[gate] tests"
python3 -m pytest --version >/dev/null 2>&1 || pip install -q pytest --break-system-packages >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1
if ls tests/test_*.py >/dev/null 2>&1; then
  python3 -m pytest -q tests
else
  echo "[gate] no tests yet (phase 0 start)"
fi
echo "[gate] GREEN"
