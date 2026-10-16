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

echo "[gate] tests"
python3 -m pytest --version >/dev/null 2>&1 || pip install -q pytest --break-system-packages >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1
if ls tests/test_*.py >/dev/null 2>&1; then
  python3 -m pytest -q tests
else
  echo "[gate] no tests yet (phase 0 start)"
fi
echo "[gate] GREEN"
