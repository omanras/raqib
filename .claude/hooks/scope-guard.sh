#!/usr/bin/env bash
# PreToolUse guard for Edit|Write: deny any path not listed under "Scope:" in HANDOFF.md.
# Reads the hook JSON on stdin; prints a permissionDecision JSON on stdout.
set -u
ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
HANDOFF="$ROOT/HANDOFF.md"
INPUT="$(cat)"

path="$(printf '%s' "$INPUT" | python3 -c 'import json,sys
d=json.load(sys.stdin); ti=d.get("tool_input",{})
print(ti.get("file_path") or ti.get("path") or "")' 2>/dev/null)"
[ -z "$path" ] && exit 0   # nothing to judge → normal permission flow

rel="${path#"$ROOT"/}"
scope="$(sed -n 's/^Scope:[[:space:]]*//p' "$HANDOFF" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$')"
# Scope lines may continue on following indented lines; include them.
scope="$scope
$(awk '/^Scope:/{f=1;next} f&&/^[[:space:]]/{print} f&&!/^[[:space:]]/{f=0}' "$HANDOFF" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v '^$')"

allowed=0
while IFS= read -r s; do
  [ -z "$s" ] && continue
  case "$rel" in
    "$s"|"$s"*) allowed=1; break;;
  esac
done <<< "$scope"

if [ "$allowed" -eq 1 ]; then
  exit 0
fi
cat <<EOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"MIZAN scope-guard: '$rel' is outside HANDOFF Scope. Write a questions file and STOP instead."}}
EOF
exit 0
