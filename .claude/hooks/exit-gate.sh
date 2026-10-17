#!/usr/bin/env bash
# Stop hook: refuse to end the session unless the tree is clean, the last commit
# is landed:/STOP:, and tools/gate.sh is green.
set -u
ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$ROOT" || exit 0

block() { printf '{"decision":"block","reason":"%s"}\n' "$1"; exit 0; }

if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  block "exit-gate: working tree is dirty. Commit as landed: or STOP: before stopping."
fi
msg="$(git log -1 --pretty=%s 2>/dev/null)"
case "$msg" in
  landed:*|STOP:*) ;;
  *) block "exit-gate: last commit message must start with landed: or STOP: (got: $msg)";;
esac
if [ -x tools/gate.sh ] && ! tools/gate.sh >/dev/null 2>&1; then
  case "$msg" in
    STOP:*) ;;   # a STOP may leave the gate red; the reason is in docs/review
    *) block "exit-gate: tools/gate.sh is red but commit says landed:. Fix or convert to STOP.";;
  esac
fi
exit 0
