#!/usr/bin/env bash
# Advances HANDOFF.md to the next task from docs/handoffs/<id>.md if it exists;
# otherwise stops the loop so the commander writes it. The builder never writes
# its own next task (SESSION_PROTOCOL §6).
set -euo pipefail
cd "$(dirname "$0")/.."
cur="$(sed -n 's/^# HANDOFF — \([A-Z0-9.]*\).*/\1/p' HANDOFF.md | head -1)"
mkdir -p docs/handoffs
next="$(ls docs/handoffs 2>/dev/null | sort -V | awk -v c="$cur.md" '$0>c{print;exit}')"
if [ -z "$next" ]; then
  echo "[next-task] no prepared HANDOFF after $cur — commander must write docs/handoffs/<next>.md"; exit 2
fi
cp "docs/handoffs/$next" HANDOFF.md
git add HANDOFF.md && git commit -qm "HANDOFF -> ${next%.md}"
echo "[next-task] advanced to ${next%.md}"
