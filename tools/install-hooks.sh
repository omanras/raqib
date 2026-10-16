#!/usr/bin/env bash
# Install the Raqib capture hook into a watched project (M0.3).
#
# Usage: tools/install-hooks.sh [--log PATH] <watched-project>
#
# Writes or merges six hook entries (ADR-0001 Amendment A-4: PreToolUse,
# PostToolUse, PostToolUseFailure, SessionStart, SessionEnd, Stop) into
# <watched-project>/.claude/settings.json, each running raqib/hooks/capture.py
# from this checkout. Other settings and hooks are preserved; the file is only
# rewritten when something changes, keeping its mode (and following a symlink).
#
# The trace goes to --log PATH, else to the RAQIB_LOG an earlier install chose,
# else to <watched-project>/raqib.log.jsonl (an absolute path, so a `cd` by the
# agent cannot split the trace).
#
# The installed command can never block the agent: if python3 or capture.py is
# missing, or capture fails to start, it prints one RAQIB-SILENCE: line to
# stderr and exits 0 (never 2, which Claude Code treats as "block").
#
# Exit: 0 installed; 1 settings unreadable or unwritable (left untouched);
#       2 usage; 3 installed, but disableAllHooks is set, so nothing will run.
set -euo pipefail
unset CDPATH

usage() { echo "usage: tools/install-hooks.sh [--log PATH] <watched-project>" >&2; exit 2; }

RAQIB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAPTURE="$RAQIB_ROOT/raqib/hooks/capture.py"
LOG=""
LOG_SET=0
PROJECT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --log) [ $# -ge 2 ] && [ -n "$2" ] || usage; LOG="$2"; LOG_SET=1; shift 2;;
    -h|--help) usage;;
    -*) usage;;
    *) [ -z "$PROJECT" ] || usage; PROJECT="$1"; shift;;
  esac
done
[ -n "$PROJECT" ] || usage
[ -d "$PROJECT" ] || { echo "install-hooks: not a directory: $PROJECT" >&2; exit 2; }
[ -f "$CAPTURE" ] || { echo "install-hooks: missing $CAPTURE" >&2; exit 2; }
PROJECT="$(cd "$PROJECT" && pwd)"
if [ "$LOG_SET" = 1 ]; then
  case "$LOG" in /*) ;; *) LOG="$(pwd)/$LOG";; esac
fi

# -I: isolated mode, so modules in the caller's cwd or PYTHONPATH are not imported.
exec python3 -I - "$PROJECT" "$CAPTURE" "$LOG" "$LOG_SET" <<'PY'
import json
import os
import re
import shlex
import sys
import tempfile

project, capture, log_arg, log_set = sys.argv[1:5]
MARK = "RAQIB_HOOK=capture"
# Entries written before the marker existed: `[RAQIB_LOG=x ]python3 <path>`.
LEGACY = re.compile(r"(?:RAQIB_LOG=\S+ )?python3 \S*raqib/hooks/capture\.py\Z")
# (event, matcher): tool events match every tool; session events take none.
EVENTS = [
    ("PreToolUse", "*"),
    ("PostToolUse", "*"),
    ("PostToolUseFailure", "*"),
    ("SessionStart", None),
    ("SessionEnd", None),
    ("Stop", None),
]
TIMEOUT = 10  # seconds; a slow capture must not hold the agent up


def fail(msg):
    print("install-hooks: " + msg, file=sys.stderr)
    sys.exit(1)


def strict_object(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key %r" % key)
        seen[key] = value
    return seen


def reject_constant(name):
    raise ValueError("non-standard JSON constant %s" % name)


def is_raqib(hook):
    if not isinstance(hook, dict):
        return False
    command = str(hook.get("command", ""))
    return command.startswith(MARK + " ") or bool(LEGACY.match(command))


def log_of(hook):
    try:
        words = shlex.split(str(hook.get("command", "")))
    except ValueError:
        return None
    for word in words:
        if word.startswith("RAQIB_LOG="):
            return word[len("RAQIB_LOG="):]
        if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", word):
            return None
    return None


settings_dir = os.path.join(project, ".claude")
settings_path = os.path.join(settings_dir, "settings.json")
old_text = None
settings = {}
if os.path.lexists(settings_path):
    try:
        with open(settings_path, encoding="utf-8") as f:
            old_text = f.read()
        if old_text.strip():
            settings = json.loads(old_text, object_pairs_hook=strict_object,
                                  parse_constant=reject_constant)
    except (OSError, ValueError) as exc:
        fail("cannot read %s (%s); nothing changed" % (settings_path, exc))
    if not isinstance(settings, dict):
        fail("%s is not a JSON object; nothing changed" % settings_path)

hooks = settings.setdefault("hooks", {})
if not isinstance(hooks, dict):
    fail('"hooks" in %s is not an object; nothing changed' % settings_path)
for event, _ in EVENTS:
    if not isinstance(hooks.get(event, []), list):
        fail('"hooks.%s" in %s is not a list; nothing changed' % (event, settings_path))


def raqib_entries(groups):
    return [(g, h) for g in groups if isinstance(g, dict) and isinstance(g.get("hooks"), list)
            for h in g["hooks"] if is_raqib(h)]


existing = [h for event, _ in EVENTS for _, h in raqib_entries(hooks.get(event, []))]
if log_set == "1":
    log, log_source = log_arg, "--log"
else:
    kept = sorted({log_of(h) for h in existing} - {None})
    if kept:
        log, log_source = kept[0], "kept from the existing install"
    else:
        log, log_source = os.path.join(project, "raqib.log.jsonl"), "default"

command = "%s RAQIB_LOG=%s python3 -I %s || echo 'RAQIB-SILENCE: capture hook failed, exit' \"$?\" %s >&2" % (
    MARK, shlex.quote(log), shlex.quote(capture), shlex.quote(capture))

report = []
replaced = []
for event, matcher in EVENTS:
    groups = hooks.setdefault(event, [])
    ours = raqib_entries(groups)
    if len(ours) == 1:
        group, hook = ours[0]
        if (group.get("matcher") == matcher and len(group["hooks"]) == 1
                and hook.get("type") == "command" and hook.get("command") == command):
            report.append((event, "unchanged"))
            continue
    kept_groups = []
    for g in groups:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list) and any(is_raqib(h) for h in g["hooks"]):
            rest = [h for h in g["hooks"] if not is_raqib(h)]
            if rest:
                kept_groups.append(dict(g, hooks=rest))
            continue
        kept_groups.append(g)
    # Keep keys a user added to our entry (e.g. their own timeout).
    hook = {"timeout": TIMEOUT, **ours[0][1]} if ours else {"timeout": TIMEOUT}
    hook.update({"type": "command", "command": command})
    group = {"hooks": [hook]} if matcher is None else {"matcher": matcher, "hooks": [hook]}
    kept_groups.append(group)
    hooks[event] = kept_groups
    replaced += [h.get("command") for _, h in ours if h.get("command") != command]
    report.append((event, "updated" if ours else "added"))

changed = any(status != "unchanged" for _, status in report)
if changed:
    new_text = json.dumps(settings, indent=2, ensure_ascii=False) + "\n"
    target = os.path.realpath(settings_path) if os.path.lexists(settings_path) else settings_path
    target_dir = os.path.dirname(target)
    tmp = None
    try:
        os.makedirs(target_dir, exist_ok=True)
        mode = os.stat(target).st_mode & 0o7777 if os.path.exists(target) else 0o644
        fd, tmp = tempfile.mkstemp(prefix=".settings.", suffix=".json", dir=target_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
        tmp = None
    except OSError as exc:
        fail("cannot write %s (%s); nothing changed" % (target, exc))
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)

print("install-hooks: %s%s" % (settings_path, "" if changed else " (file not rewritten)"))
for event, status in report:
    print("  %-19s %s" % (event, status))
for old in sorted(set(replaced)):
    print("  replaced: %s" % old)
print("  trace: %s (%s)" % (log, log_source))
print("  command: %s" % command)
if os.path.dirname(log) == project:
    print("  note: the trace is inside the project; add raqib.log.jsonl to its .gitignore,"
          " or use --log to keep it out of the agent's working tree")

disabled = []
for path in (settings_path, os.path.join(settings_dir, "settings.local.json"),
             os.path.join(os.path.expanduser("~"), ".claude", "settings.json")):
    try:
        with open(path, encoding="utf-8") as f:
            if json.load(f).get("disableAllHooks") is True:
                disabled.append(path)
    except (OSError, ValueError, AttributeError):
        pass
if disabled:
    print("RAQIB-SILENCE: disableAllHooks is true in %s; capture will not run"
          % ", ".join(disabled), file=sys.stderr)
    sys.exit(3)
PY
