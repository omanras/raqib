#!/usr/bin/env python3
"""Install the Raqib capture hook into a watched project (M0.3, M5.1).

Usage: python3 tools/install_hooks.py [--log PATH] <watched-project>
       (tools/install-hooks.sh runs this with `python3 -I`; on Windows run
       it with the Python that should run the hook, e.g. `py -I ...`)

Writes or merges six hook entries (ADR-0001 Amendment A-4: PreToolUse,
PostToolUse, PostToolUseFailure, SessionStart, SessionEnd, Stop) into
<watched-project>/.claude/settings.json, each running raqib/hooks/capture.py
from this checkout. Other settings and hooks are preserved; the file is only
rewritten when something changes, keeping its mode (and following a symlink).

The trace goes to --log PATH, else to the trace an earlier install chose,
else to <watched-project>/raqib.log.jsonl (an absolute path, so a `cd` by the
agent cannot split the trace).

The hook command depends on the platform:
- POSIX: `RAQIB_HOOK=capture RAQIB_LOG=<log> python3 -I <capture> || echo
  ...`. It can never block the agent: if python3 or capture.py is missing,
  or capture fails to start, it prints one RAQIB-SILENCE: line to stderr and
  exits 0 (never 2, which Claude Code treats as "block").
- Windows (ruling Amendment 2, P3): `"<python.exe>" -I -c "<LAUNCHER>"
  "<capture.py>" "<log>"`. No shell syntax: every word but -I and -c is in
  double quotes, paths with forward slashes, and LAUNCHER holds nothing a
  shell expands, so cmd.exe, a POSIX shell and a direct exec read the same
  arguments. LAUNCHER runs capture.py with the log as its argument; if
  capture.py is missing it prints one RAQIB-SILENCE: line and exits 1, never
  2 (Python's own status for a missing script, which Claude Code treats as
  "block"). A path that holds a character some shell expands inside double
  quotes (" % $ ` !) or a control character is refused.

Exit: 0 installed; 1 settings unreadable or unwritable (left untouched);
      2 usage; 3 installed, but disableAllHooks is set, so nothing will run.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tempfile

WINDOWS = os.name == "nt"
# This file's path; as the shell gave it when run as a script (see the end),
# so the checkout is named as `cd "$(dirname "$0")/.." && pwd` names it.
SCRIPT = __file__
USAGE = "usage: tools/install_hooks.py [--log PATH] <watched-project>"
MARK = "RAQIB_HOOK=capture"
# Entries written before the marker existed: `[RAQIB_LOG=x ]python3 <path>`,
# where x and <path> may be shell-quoted.
LEGACY_TAIL = "raqib/hooks/capture.py"
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
# Amendment 2 (P3): the -c program of the Windows command. sys.argv is
# ["-c", capture, log]; capture.py then sees [capture, log], as if run itself.
LAUNCHER = ("import os,runpy,sys;p=sys.argv[1];os.path.isfile(p) or sys.exit("
            "'RAQIB-SILENCE: capture hook failed, missing '+p);sys.argv[:]=sys.argv[1:];"
            "runpy.run_path(p,run_name='__main__')")
# The Windows form, as written by windows_command(). Any -c program and no
# log word are recognised too, so an older or hand-made entry is replaced.
WINDOWS_FORM = re.compile(r'\s*"([^"]+)"\s+-I(?:\s+-c\s+"[^"]*")?\s+"([^"]+)"(?:\s+"([^"]*)")?\s*\Z')
# Expanded inside double quotes by cmd.exe (% !) or a POSIX shell ($ ` ").
WINDOWS_UNSAFE = re.compile(r'["%$`!\x00-\x1f\x7f]')


class Exit(Exception):
    def __init__(self, code, message=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


def fail(msg):
    raise Exit(1, "install-hooks: " + msg)


def usage():
    raise Exit(2, USAGE)


def strict_object(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key %r" % key)
        seen[key] = value
    return seen


def reject_constant(name):
    raise ValueError("non-standard JSON constant %s" % name)


def is_legacy(command):
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if words and words[0].startswith("RAQIB_LOG="):
        words = words[1:]
    return (len(words) == 2 and words[0] == "python3"
            and (words[1] == LEGACY_TAIL or words[1].endswith("/" + LEGACY_TAIL)))


def windows_words(command):
    """(interpreter, capture, log or None) of a Windows-form Raqib command, else None."""
    match = WINDOWS_FORM.match(command)
    if match is None:
        return None
    capture = match.group(2).replace("\\", "/")
    if capture != LEGACY_TAIL and not capture.endswith("/" + LEGACY_TAIL):
        return None
    return match.group(1), match.group(2), match.group(3) or None


def is_raqib(hook):
    if not isinstance(hook, dict):
        return False
    command = str(hook.get("command", ""))
    return command.startswith(MARK + " ") or is_legacy(command) or windows_words(command) is not None


def log_of(hook):
    command = str(hook.get("command", ""))
    words = windows_words(command)
    if words is not None:
        return words[2]
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    for word in words:
        if word.startswith("RAQIB_LOG="):
            return word[len("RAQIB_LOG="):]
        if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", word):
            return None
    return None


def windows_word(path):
    word = path.replace("\\", "/")
    bad = WINDOWS_UNSAFE.search(word)
    if bad:
        raise Exit(2, "install-hooks: %s holds %r, which a shell may expand inside a Windows hook"
                      " command; move it to a path without it" % (path, bad.group(0)))
    return word


def posix_command(log, capture):
    return "%s RAQIB_LOG=%s python3 -I %s || echo 'RAQIB-SILENCE: capture hook failed, exit' \"$?\" %s >&2" % (
        MARK, shlex.quote(log), shlex.quote(capture), shlex.quote(capture))


def windows_command(log, capture, interpreter):
    """Amendment 2 (P3): interpreter, -I, the launcher and the two paths,
    quoted, no shell syntax (see the module docstring)."""
    return '"%s" -I -c "%s" "%s" "%s"' % (windows_word(interpreter), windows_word(LAUNCHER),
                                          windows_word(capture), windows_word(log))


def logical_cwd():
    """The cwd as the shell sees it ($PWD, like `pwd`), so a project reached
    through a symlink keeps that path, as the bash installer did; else the
    physical cwd. Windows has no $PWD of its own."""
    cwd = os.getcwd()
    pwd = os.environ.get("PWD", "")
    if not WINDOWS and pwd.startswith("/") and os.path.normpath(pwd) == pwd:
        try:
            if os.path.samefile(pwd, cwd):
                return pwd
        except OSError:
            pass
    return cwd


def absolute(path):
    """Like `cd path && pwd`: absolute, `.` and `..` resolved by name."""
    return os.path.normpath(os.path.join(logical_cwd(), path))


def absolute_log(log):
    """Like the bash installer's "$(pwd)/$LOG" for a relative --log: not
    normalised. os.path.join on Windows also keeps a drive and a root."""
    if WINDOWS:
        return os.path.join(logical_cwd(), log)
    return log if log.startswith("/") else logical_cwd() + "/" + log


def parse_args(argv):
    log, log_set, project = "", False, ""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--log":
            if i + 1 >= len(argv) or not argv[i + 1]:
                usage()
            log, log_set = argv[i + 1], True
            i += 2
        elif arg.startswith("-"):
            usage()
        else:
            if project:
                usage()
            project = arg
            i += 1
    if not project:
        usage()
    return project, log, log_set


def write_atomically(settings_path, new_text):
    """Replace the settings file (or its symlink's target) through a temp file."""
    target = os.path.realpath(settings_path) if os.path.lexists(settings_path) else settings_path
    target_dir = os.path.dirname(target)
    tmp = None
    try:
        os.makedirs(target_dir, exist_ok=True)
        # Windows has no POSIX modes or umask: the new file takes the
        # directory's inherited permissions, and chmod would only set the
        # read-only flag.
        mode = None
        if not WINDOWS:
            if os.path.exists(target):
                mode = os.stat(target).st_mode & 0o7777
            else:
                umask = os.umask(0)
                os.umask(umask)
                mode = 0o666 & ~umask
        fd, tmp = tempfile.mkstemp(prefix=".settings.", suffix=".json", dir=target_dir)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_text)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, target)
        tmp = None
    except OSError as exc:
        fail("cannot write %s (%s); nothing changed" % (target, exc))
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)
    # The rename is durable only once the directory is synced. The file is
    # already replaced, so a failure here is a warning, not "nothing changed".
    # Windows cannot open a directory to sync it; there is no such step.
    if WINDOWS:
        return
    try:
        dir_fd = os.open(target_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        print("install-hooks: warning: %s was written, but its directory could not be synced (%s)"
              % (target, exc), file=sys.stderr)


def raqib_entries(groups):
    return [(g, h) for g in groups if isinstance(g, dict) and isinstance(g.get("hooks"), list)
            for h in g["hooks"] if is_raqib(h)]


def install(argv):
    project, log_arg, log_set = parse_args(argv)
    root = absolute(os.path.join(os.path.dirname(SCRIPT), ".."))
    capture = os.path.join(root, "raqib", "hooks", "capture.py")
    if not os.path.isdir(project):
        raise Exit(2, "install-hooks: not a directory: %s" % project)
    if not os.path.isfile(capture):
        raise Exit(2, "install-hooks: missing %s" % capture)
    project = absolute(project)
    if log_set:
        log_arg = absolute_log(log_arg)

    settings_dir = os.path.join(project, ".claude")
    settings_path = os.path.join(settings_dir, "settings.json")
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

    existing = [h for event, _ in EVENTS for _, h in raqib_entries(hooks.get(event, []))]
    if log_set:
        log, log_source = log_arg, "--log"
    else:
        # A relative RAQIB_LOG was resolved by the hook against the session's
        # cwd, normally the project.
        kept = sorted({os.path.normpath(os.path.join(project, x))
                       for x in (log_of(h) for h in existing) if x})
        if len(kept) > 1:
            fail("existing Raqib entries write to different traces (%s); pass --log to choose one;"
                 " nothing changed" % ", ".join(kept))
        if kept:
            log, log_source = kept[0], "kept from the existing install"
        else:
            log, log_source = os.path.join(project, "raqib.log.jsonl"), "default"

    if WINDOWS:
        if not sys.executable:
            raise Exit(2, "install-hooks: cannot tell which Python runs this; nothing changed")
        command = windows_command(log, capture, sys.executable)
    else:
        command = posix_command(log, capture)

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
        write_atomically(settings_path, json.dumps(settings, indent=2, ensure_ascii=False) + "\n")

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
        return 3
    return 0


def main(argv=None):
    try:
        return install(sys.argv[1:] if argv is None else argv)
    except Exit as exc:
        if exc.message:
            print(exc.message, file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    SCRIPT = sys.argv[0]
    # A path the console cannot encode is escaped, not a crash after the write.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    sys.exit(main())
