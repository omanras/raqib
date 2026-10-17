#!/usr/bin/env bash
# The constitutional gate. Green = exit 0. Every landed: commit must pass it.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[gate] secret scan"
if git grep -nE '(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,})' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: secret-like string in tree"; exit 1
fi

echo "[gate] handoff length"
if [ "$(wc -l < HANDOFF.md)" -gt 40 ]; then echo "[gate] RED: HANDOFF.md > 40 lines"; exit 1; fi

echo "[gate] private data leak check"
if git grep -nIE 'haris[-_]?backup|falak\.git|10\.136\.|getbaraka|alpaca' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: reference to a private tree, network or real account"; exit 1
fi

echo "[gate] import policy: no network, no subprocess, no float money in qayd/ (A5, A7)"
if ! git ls-files -z -- 'qayd/*.py' | python3 -I -c '
import ast, sys
NET = {"urllib", "socket", "http", "requests", "httpx", "ftplib", "smtplib", "ssl", "asyncio", "subprocess", "webbrowser"}
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
            if name.split(".")[0] in NET:
                bad.append("%s:%d imports %s" % (path, node.lineno, name))
        # float(...) on money is forbidden; Decimal only (A5). review.py may
        # use float for pixel geometry only.
        if path != "qayd/review.py" and isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "float":
            bad.append("%s:%d calls float() (use Decimal, A5)" % (path, node.lineno))
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

echo "[gate] self-check: the example household"
if [ -f examples/policies.yml ] && [ -f qayd/cli.py ] && grep -q '"check"' qayd/cli.py; then
  python3 -m qayd check --dir examples/ --as-of 2026-09-30 || echo "[gate] (example verdicts include planned reds; tests assert the exact set)"
else
  echo "[gate] no example household or no check command yet (before M1.3)"
fi
echo "[gate] GREEN"
