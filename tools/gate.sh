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
if git grep -nIE 'haris[-_]?backup|D:\\\\haris|falak\.git|10\.136\.' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: reference to a private tree or network"; exit 1
fi

echo "[gate] import policy: no network modules in mizan/; pySigma only in mizan/export.py (A6)"
if ! git ls-files -z -- 'mizan/*.py' | python3 -I -c '
import ast, sys
NET = {"urllib", "socket", "http", "requests", "httpx", "ftplib", "smtplib", "ssl", "asyncio", "subprocess"}
SIGMA_ALLOWED = "mizan/export.py"
bad = []
for path in sys.stdin.buffer.read().decode().split("\0"):
    if not path:
        continue
    try:
        tree = ast.parse(open(path, encoding="utf-8").read(), path)
    except (OSError, SyntaxError) as exc:
        bad.append("%s: cannot be parsed (%s)" % (path, exc)); continue
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            root = name.split(".")[0]
            if root in NET:
                bad.append("%s:%d imports %s (no network, no subprocess in the engine)" % (path, node.lineno, root))
            if root == "sigma" and path != SIGMA_ALLOWED:
                bad.append("%s:%d imports pySigma outside export.py" % (path, node.lineno))
for b in bad:
    print("[gate]   " + b)
sys.exit(1 if bad else 0)
'; then
  echo "[gate] RED: import policy violated"; exit 1
fi

echo "[gate] dependencies"
python3 -c "import yaml" >/dev/null 2>&1 || pip install -q pyyaml --break-system-packages >/dev/null 2>&1 || pip install -q pyyaml >/dev/null 2>&1
python3 -m pytest --version >/dev/null 2>&1 || pip install -q pytest --break-system-packages >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1

echo "[gate] tests"
if ls tests/test_*.py >/dev/null 2>&1; then
  python3 -m pytest -q tests
else
  echo "[gate] no tests yet (phase 0 start)"
fi

echo "[gate] self-check: the example rule set"
if ls rules/*.yml >/dev/null 2>&1 && [ -f mizan/cli.py ] && grep -q '"check"' mizan/cli.py; then
  python3 -m mizan check rules/ --corpus corpus/
else
  echo "[gate] no rule set or no check command yet (before M1.3)"
fi
echo "[gate] GREEN"
