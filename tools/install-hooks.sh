#!/usr/bin/env bash
# Install the Raqib capture hook into a watched project (M0.3).
#
# Usage: tools/install-hooks.sh [--log PATH] <watched-project>
#
# Writes or merges six hook entries (ADR-0001 Amendment A-4: PreToolUse,
# PostToolUse, PostToolUseFailure, SessionStart, SessionEnd, Stop) into
# <watched-project>/.claude/settings.json, each running raqib/hooks/capture.py
# from this checkout. Other settings and hooks are preserved. Running it again
# changes nothing; a Raqib entry from an older path is replaced, never doubled.
# --log PATH sets RAQIB_LOG in the hook command (default: raqib.log.jsonl in
# the directory Claude Code runs hooks from, i.e. the project).
# Exit: 0 installed, 1 existing settings unreadable (left untouched), 2 usage.
set -euo pipefail

usage() { echo "usage: tools/install-hooks.sh [--log PATH] <watched-project>" >&2; exit 2; }

RAQIB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAPTURE="$RAQIB_ROOT/raqib/hooks/capture.py"
LOG=""
PROJECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --log) [ $# -ge 2 ] || usage; LOG="$2"; shift 2;;
    -h|--help) usage;;
    -*) usage;;
    *) [ -z "$PROJECT" ] || usage; PROJECT="$1"; shift;;
  esac
done
[ -n "$PROJECT" ] || usage
[ -d "$PROJECT" ] || { echo "install-hooks: not a directory: $PROJECT" >&2; exit 2; }
[ -f "$CAPTURE" ] || { echo "install-hooks: missing $CAPTURE" >&2; exit 2; }
PROJECT="$(cd "$PROJECT" && pwd)"

exec python3 - "$PROJECT" "$CAPTURE" "$LOG" <<'PY'
import json
import os
import shlex
import sys
import tempfile

project, capture, log = sys.argv[1:4]
MARK = "raqib/hooks/capture.py"
# (event, matcher): tool events match every tool; session events take none.
EVENTS = [
    ("PreToolUse", "*"),
    ("PostToolUse", "*"),
    ("PostToolUseFailure", "*"),
    ("SessionStart", None),
    ("SessionEnd", None),
    ("Stop", None),
]


def fail(msg):
    print("install-hooks: " + msg, file=sys.stderr)
    sys.exit(1)


command = "python3 " + shlex.quote(capture)
if log:
    command = "RAQIB_LOG=" + shlex.quote(os.path.abspath(log)) + " " + command

settings_dir = os.path.join(project, ".claude")
settings_path = os.path.join(settings_dir, "settings.json")
settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as f:
            text = f.read()
        settings = json.loads(text) if text.strip() else {}
    except (OSError, ValueError) as exc:
        fail("cannot read %s (%s); nothing changed" % (settings_path, exc))
    if not isinstance(settings, dict):
        fail("%s is not a JSON object; nothing changed" % settings_path)

hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    fail('"hooks" in %s is not an object; nothing changed' % settings_path)


def is_raqib(hook):
    return isinstance(hook, dict) and MARK in str(hook.get("command", ""))


def wanted_group(matcher):
    group = {"hooks": [{"type": "command", "command": command}]}
    if matcher is not None:
        group = {"matcher": matcher, **group}
    return group


report = []
for event, matcher in EVENTS:
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        fail('"hooks.%s" in %s is not a list; nothing changed' % (event, settings_path))
    ours = [(g, h) for g in groups if isinstance(g, dict)
            for h in (g.get("hooks") if isinstance(g.get("hooks"), list) else []) if is_raqib(h)]
    want = wanted_group(matcher)
    if len(ours) == 1 and ours[0][0] == want:
        report.append((event, "unchanged"))
        continue
    kept = []
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list) and any(is_raqib(h) for h in g["hooks"]):
            rest = [h for h in g["hooks"] if not is_raqib(h)]
            if rest:
                kept.append(dict(g, hooks=rest))
            continue
        kept.append(g)
    kept.append(want)
    hooks[event] = kept
    report.append((event, "updated" if ours else "added"))

os.makedirs(settings_dir, exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix=".settings.", suffix=".json", dir=settings_dir)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, settings_path)
except BaseException:
    if os.path.exists(tmp):
        os.unlink(tmp)
    raise

print("install-hooks: %s" % settings_path)
for event, status in report:
    print("  %-19s %s" % (event, status))
print("  command: %s" % command)
PY
