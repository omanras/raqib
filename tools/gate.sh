#!/usr/bin/env bash
# The constitutional gate. Green = exit 0. Every landed: commit must pass it.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[gate] secret scan"
if git grep -nE '(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----|xox[baprs]-[0-9A-Za-z-]{10,})' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: secret-like string in tree"; exit 1
fi
if git ls-files | grep -qE '(^|/)\.env$|\.sqlite$'; then echo "[gate] RED: .env or database file committed"; exit 1; fi

echo "[gate] handoff length"
if [ "$(wc -l < HANDOFF.md)" -gt 40 ]; then echo "[gate] RED: HANDOFF.md > 40 lines"; exit 1; fi

echo "[gate] private data leak check"
if git grep -nIE 'haris[-_]?backup|falak\.git|10\.136\.' -- . ':!tools/gate.sh' >/dev/null 2>&1; then
  echo "[gate] RED: reference to a private tree or network"; exit 1
fi

if [ -d server ] || [ -d client ] || [ -d shared ]; then
  echo "[gate] no outbound network in server/ and shared/ (A7); no remote resources in client/"
  if git grep -nE '\b(fetch|undici|axios|got|node-fetch|https?\.request|https?\.get|dns\.)\b' -- 'server/' 'shared/' ':!server/**/*.test.ts' >/dev/null 2>&1; then
    echo "[gate] RED: outbound network API in server/ or shared/"; exit 1
  fi
  if git grep -nE '(src|href)=["'"'"']https?://|@import\s+url\(["'"'"']?https?://' -- 'client/' >/dev/null 2>&1; then
    echo "[gate] RED: remote resource in client/"; exit 1
  fi
  echo "[gate] no float money (A4)"
  if git grep -nE '\b(parseFloat|toFixed)\s*\(' -- 'shared/' 'server/' >/dev/null 2>&1; then
    echo "[gate] RED: parseFloat/toFixed in shared/ or server/ (integer minor units only)"; exit 1
  fi
  echo "[gate] no innerHTML / dangerouslySetInnerHTML with data (S4.3)"
  if git grep -nE 'dangerouslySetInnerHTML|\.innerHTML\s*=' -- 'client/' >/dev/null 2>&1; then
    echo "[gate] RED: raw HTML injection point in client/"; exit 1
  fi
fi

if [ -d deploy ]; then
  echo "[gate] deploy scripts parse"
  for f in deploy/*.sh; do bash -n "$f" || { echo "[gate] RED: $f does not parse"; exit 1; }; done
  for f in deploy/*.mjs; do node --check "$f" || { echo "[gate] RED: $f does not parse"; exit 1; }; done
fi

if [ -f package.json ] && [ -f README.md ]; then
  echo "[gate] commands in README and OPERATIONS exist (npm scripts, repository paths)"
  node --input-type=module - README.md docs/OPERATIONS.md <<'JS' || exit 1
import { existsSync, readFileSync } from 'node:fs';
const scripts = JSON.parse(readFileSync('package.json', 'utf8')).scripts ?? {};
// npm's own commands are not scripts; every other `npm <x>` / `npm run <x>` must be one.
const builtin = new Set(['ci', 'install', 'i', 'audit', 'version', 'outdated', 'ls', 'pack', 'exec', 'help', 'config', 'prune', 'rebuild', 'update', 'view']);
const missing = [];
for (const doc of process.argv.slice(2).filter((f) => existsSync(f))) {
  const text = readFileSync(doc, 'utf8');
  // Only code: fenced blocks and inline `code`.
  const code = [...text.matchAll(/```[^\n]*\n([\s\S]*?)```|`([^`\n]+)`/g)].map((m) => m[1] ?? m[2]).join('\n');
  for (const m of code.matchAll(/\bnpm\s+(?:run(?:-script)?\s+)?([a-z][\w:-]*)/g)) {
    const isRun = /\bnpm\s+run/.test(m[0]);
    if (isRun ? !(m[1] in scripts) : !builtin.has(m[1]) && !(m[1] in scripts)) missing.push(`${doc}: npm script "${m[1]}"`);
  }
  for (const m of code.matchAll(/(?:^|[\s"'(=])((?:deploy|tools|docs)\/[\w./-]*[\w-])/g)) {
    // deploy/.env is the operator's own file (never committed).
    if (m[1] !== 'deploy/.env' && !existsSync(m[1])) missing.push(`${doc}: path ${m[1]}`);
  }
}
if (missing.length) {
  console.error(`[gate] RED: documented commands that do not exist:\n  ${[...new Set(missing)].join('\n  ')}`);
  process.exit(1);
}
JS
fi

if [ -f package.json ]; then
  echo "[gate] install (lockfile)"
  if [ -f package-lock.json ]; then npm ci --no-audit --no-fund --loglevel=error >/dev/null; else npm install --no-audit --no-fund --loglevel=error >/dev/null; fi
  echo "[gate] typecheck"; npx tsc -p tsconfig.json --noEmit
  echo "[gate] unit + api tests"; npx vitest run --reporter=dot 2>&1 | tail -5
  echo "[gate] build"; npm run build --silent
  echo "[gate] dependency audit (high+)"
  if ! npm audit --audit-level=high --omit=dev >/dev/null 2>&1; then
    if [ -f docs/review/audit-exceptions.md ]; then echo "[gate] audit findings present; exceptions documented in docs/review/audit-exceptions.md"; else echo "[gate] RED: npm audit high+ findings and no docs/review/audit-exceptions.md"; exit 1; fi
  fi
  if [ -d tests/e2e ] && ls tests/e2e/*.spec.ts >/dev/null 2>&1; then
    echo "[gate] e2e (Playwright, Chromium)"; npx playwright test --reporter=line 2>&1 | tail -5
  fi
else
  echo "[gate] no package.json yet (phase 0 start)"
fi
echo "[gate] GREEN"
