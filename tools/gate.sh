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

echo "[gate] reference/ is read-only (A10)"
if [ -n "$(git diff --name-only HEAD~1 -- reference/ 2>/dev/null)" ] && [ "$(git rev-list --count HEAD)" -gt 1 ]; then
  echo "[gate] RED: reference/ changed in the last commit"; exit 1
fi

if [ -d src ]; then
  echo "[gate] no runtime network in src/ (A7)"
  if git grep -nE '\b(fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource|importScripts)\s*\(' -- 'src/' >/dev/null 2>&1 \
     || git grep -nE '(src|href)=["'"'"']https?://' -- 'src/' 'index.html' >/dev/null 2>&1; then
    echo "[gate] RED: runtime network API or remote resource in src/"; exit 1
  fi
  echo "[gate] no JS-number money in src/engine/ (A5)"
  if [ -d src/engine ] && git grep -nE '\b(parseFloat|Number)\s*\(|\btoFixed\s*\(' -- 'src/engine/' >/dev/null 2>&1; then
    echo "[gate] RED: parseFloat/Number/toFixed in src/engine/ (use Decimal)"; exit 1
  fi
fi

if [ -f package.json ]; then
  echo "[gate] install (lockfile)"
  if [ -f package-lock.json ]; then npm ci --no-audit --no-fund --loglevel=error >/dev/null; else npm install --no-audit --no-fund --loglevel=error >/dev/null; fi
  echo "[gate] typecheck"; npx tsc --noEmit
  echo "[gate] unit + differential tests"; npx vitest run --reporter=dot 2>&1 | tail -5
  echo "[gate] build"; npx vite build --logLevel error >/dev/null
  if [ ! -f dist/index.html ]; then echo "[gate] RED: dist/index.html missing"; exit 1; fi
  n="$(ls dist | wc -l)"; if [ "$n" -ne 1 ]; then echo "[gate] RED: dist has $n files, expected one (single-file build)"; exit 1; fi
  sz="$(wc -c < dist/index.html)"; if [ "$sz" -gt 1572864 ]; then echo "[gate] RED: dist/index.html is $sz bytes (> 1.5 MB)"; exit 1; fi
  if grep -qE '(src|href)=["'"'"']https?://' dist/index.html; then echo "[gate] RED: remote resource in dist/index.html"; exit 1; fi
  if [ -d e2e ] && ls e2e/*.spec.ts >/dev/null 2>&1; then
    echo "[gate] e2e (Playwright, Chromium)"; npx playwright test --reporter=line 2>&1 | tail -5
  fi
else
  echo "[gate] no package.json yet (phase 0 start)"
fi
echo "[gate] GREEN"
