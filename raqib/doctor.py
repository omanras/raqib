"""raqib doctor (M6.3, ADR-0005 Consequences): what is missing, in one screen.

`raqib doctor [PROJECT]` (default: the current directory) prints one line
per check, OK or MISSING, then a summary line, and exits 1 when any line is
MISSING, else 0:
- python    this Python is MIN_PYTHON or newer; on POSIX the hooks run
            `python3` from PATH, so python3 must be found on PATH (this
            shell's PATH; Claude Code's may differ). On Windows the hooks run
            this Python by its path.
- claude    `claude` is found on PATH by shutil.which, and only as an
            absolute path (a relative PATH entry, or on Windows the current
            directory, is refused, never run). That path is run with
            --version, a minimal environment (CLAUDE_ENV) and a
            CLAUDE_TIMEOUT limit; its first line is the version.
- hooks     PROJECT/.claude/settings.json, per event of the six:
            installed (the entry this raqib writes: its own capture.py, on
            Windows this Python, the right matcher), foreign (a Raqib entry
            unlike that one: another checkout or install, another Python, an
            older form or matcher), or missing (no Raqib entry). OK only when
            all six are installed and no settings file sets disableAllHooks.
            `raqib watch PROJECT` installs or replaces them.
- notifier  the backend `raqib watch` would use (raqib/notify.py): OK for a
            Windows toast, osascript or notify-send; MISSING when only the
            terminal bell is left or notifications are off (CI is set, or
            SystemRoot is not trusted).
- sysmon    Windows only: the event channel Microsoft-Windows-Sysmon/Operational
            is registered and enabled (HKLM, read with winreg). That is the
            Sysmon source `raqib discover` reads (ADR-0004); whether the
            service is running is not checked.
- trace     the trace `raqib watch` would choose (watch.choose_trace) can be
            written: the file if it exists, else the nearest existing
            directory above it, where watch creates the rest.

Read-only: doctor writes no file and creates no directory. The only
program it starts is `claude --version`, by absolute path; one that does
not answer within CLAUDE_TIMEOUT is left running and recorded, never
signalled (A4, as raqib/notify.py does).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys

import raqib
from raqib import install, notify, watch

MIN_PYTHON = (3, 11)   # pyproject.toml requires-python (a test keeps them equal)
CLAUDE_TIMEOUT = 10    # seconds
VERSION_MAX = 80
# The environment `claude --version` gets, when these are set; nothing else.
# PATH is kept so a launcher that starts with `#!/usr/bin/env node` finds node.
CLAUDE_ENV = ("PATH", "HOME")
CLAUDE_ENV_WINDOWS = ("PATH", "PATHEXT", "SystemRoot", "ComSpec", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                      "TEMP", "TMP")
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\" + SYSMON_CHANNEL


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _which(which, name, environ):
    """which(name) on environ's PATH only; None when PATH is not set."""
    path = notify.env_value(environ, "PATH")
    return which(name, path=path) if path else None


def run_version(argv, env, timeout=CLAUDE_TIMEOUT):
    """Run a version query: (exit status or None, stdout text, error or
    None). argv[0] must be an absolute path. A program still running after
    timeout seconds is left running, never signalled (A4)."""
    if not argv or not os.path.isabs(argv[0]):
        return None, "", "%r is not an absolute path: nothing is looked up through PATH" % (argv[:1],)
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": dict(env)}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.Popen(list(argv), **options)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, "", "could not be started: %s" % exc
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", "did not answer within %g s; it was left running, not signalled (A4)" % timeout
    return proc.returncode, out.decode("utf-8", "replace"), None


def read_registry_key(key_path):
    """{name: value} of an HKEY_LOCAL_MACHINE key, None when it does not
    exist; OSError for anything else. Windows only; reads only."""
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
    except FileNotFoundError:
        return None
    values = {}
    with key:
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            values[name] = value
            index += 1
    return values


# --- the checks: each returns (ok, text) --------------------------------------------

def check_python(version_info, executable, windows, which, environ):
    version = ".".join(str(n) for n in tuple(version_info)[:3])
    problems = []
    if tuple(version_info)[:2] < MIN_PYTHON:
        problems.append("Raqib needs Python %d.%d or newer" % MIN_PYTHON)
    if windows:
        if executable:
            hook = "the hooks run this Python by its path"
        else:
            problems.append("cannot tell which Python runs this, so the hooks cannot name it")
            hook = None
    else:
        found = _which(which, "python3", environ)
        if found:
            hook = "the hooks run python3 from PATH: %s" % found
        else:
            problems.append("the hooks run python3 and there is none on PATH")
            hook = None
    text = "%s at %s" % (version, executable or "?")
    return not problems, "; ".join([text] + ([hook] if hook else []) + problems)


def claude_env(environ, windows):
    names = CLAUDE_ENV_WINDOWS if windows else CLAUDE_ENV
    env = {} if windows else {"LC_ALL": "C"}
    for name in names:
        value = notify.env_value(environ, name)
        if value:
            env[name] = value
    return env


def check_claude(environ, windows, which, runner):
    found = _which(which, "claude", environ)
    if not found:
        return False, "not on PATH (install Claude Code; the hooks are Claude Code hooks)"
    if not os.path.isabs(found):
        return False, ("found only as %s, a relative path (the current directory or a relative PATH"
                       " entry); doctor runs only an absolute path, and a claude there may shadow the real one"
                       % found)
    code, out, error = runner([found, "--version"], claude_env(environ, windows), CLAUDE_TIMEOUT)
    if error:
        return False, "%s --version %s" % (found, error)
    if code != 0:
        return False, "%s --version exited %s" % (found, code)
    first = next((x.strip() for x in out.splitlines() if x.strip()), "")
    if not first:
        return False, "%s --version printed no version" % found
    if len(first) > VERSION_MAX:
        first = first[:VERSION_MAX - 3] + "..."
    return True, "%s at %s" % (first, found)


def _runs(hook):
    """The capture.py a Raqib entry runs, for the message."""
    command = str(hook.get("command", ""))
    words = install.windows_words(command)
    if words is not None:
        return words[1]
    try:
        words = shlex.split(command)
    except ValueError:
        return "?"
    tail = install.LEGACY_TAIL
    return next((w for w in words if w.replace("\\", "/") == tail or w.replace("\\", "/").endswith("/" + tail)), "?")


def _is_this(group, hook, matcher, capture, windows):
    """True when an entry is the one this raqib writes (any trace)."""
    if group.get("matcher") != matcher or len(group["hooks"]) != 1 or hook.get("type") != "command":
        return False
    log = install.log_of(hook)
    if not log:
        return False
    try:
        return hook.get("command") == install.hook_command(log, capture, windows)
    except install.Exit:
        return False


def hook_states(project, windows, capture=None):
    """(states, traces, problem): states is [(event, "installed" | "foreign"
    | "missing", the capture.py it runs or None)] for the six events and
    traces the traces the Raqib entries write to; or (None, None, the
    reason the settings could not be judged)."""
    if not os.path.isdir(project):
        return None, None, "not a directory: %s" % project
    capture = capture or install.capture_path(windows=windows)
    if not os.path.isfile(capture):
        return None, None, "this raqib has no capture hook at %s" % capture
    try:
        _, hooks = install.read_settings(os.path.join(project, ".claude", "settings.json"))
    except install.Exit as exc:
        return None, None, exc.message
    states = []
    for event, matcher in install.EVENTS:
        ours = install.raqib_entries(hooks.get(event, []))
        if not ours:
            states.append((event, "missing", None))
        elif len(ours) == 1 and _is_this(ours[0][0], ours[0][1], matcher, capture, windows):
            states.append((event, "installed", capture))
        else:
            states.append((event, "foreign", ", ".join(sorted({_runs(h) for _, h in ours}))))
    return states, install.kept_traces(project, hooks), None


def check_hooks(project, windows, capture=None):
    settings_dir = os.path.join(project, ".claude")
    settings = os.path.join(settings_dir, "settings.json")
    states, traces, problem = hook_states(project, windows, capture)
    if states is None:
        return False, problem
    disabled = install.hooks_disabled(settings_dir)
    by = {s: [e for e, state, _ in states if state == s] for s in ("installed", "foreign", "missing")}
    parts = []
    if len(by["missing"]) == len(states):
        parts.append("missing for all %d events" % len(states))
    elif by["missing"]:
        parts.append("missing for %s" % ", ".join(by["missing"]))
    if by["foreign"]:
        runs = sorted({r for _, state, r in states if state == "foreign"})
        parts.append("foreign for %s (a Raqib entry unlike the one this raqib writes; it runs %s)"
                     % (", ".join(by["foreign"]), "; ".join(runs)))
    if parts:
        parts.append("`raqib watch` installs this raqib's")
    if disabled:
        parts.append("disableAllHooks is true in %s, so capture will not run" % ", ".join(disabled))
    if parts:
        return False, "%s: %s" % (settings, "; ".join(parts))
    return True, "%s: installed for all %d events (trace %s)" % (settings, len(states), ", ".join(traces))


def check_notifier(project, environ, platform, isfile, isdir):
    n = notify.Notifier(project, environ=environ, platform=platform, isfile=isfile, isdir=isdir)
    if n.backend in ("windows-toast", "osascript", "notify-send"):
        return True, "%s (%s)" % (n.backend, n.program)
    if n.backend == "terminal":
        return False, "terminal bell and stderr only (%s)" % n.reason
    return False, "off (%s)" % n.reason


def check_sysmon(registry):
    try:
        values = registry(SYSMON_KEY)
    except OSError as exc:
        return False, "cannot read HKLM\\%s: %s" % (SYSMON_KEY, exc)
    if values is None:
        return False, ("no event channel %s: Sysmon is not installed, so `raqib discover` has no Sysmon"
                       " source on this host (ADR-0004)" % SYSMON_CHANNEL)
    if values.get("Enabled") != 1:
        return False, "event channel %s is registered but not enabled" % SYSMON_CHANNEL
    return True, ("event channel %s registered and enabled (registry; whether the service runs is not"
                  " checked)" % SYSMON_CHANNEL)


def writable(path):
    """(True, how) when the trace can be appended to or created, else
    (False, why). Reads only: nothing is created to find out."""
    if os.path.isdir(path):
        return False, "is a directory"
    if os.path.lexists(path):
        if os.access(path, os.W_OK):
            return True, "exists and is writable"
        return False, "exists and is not writable"
    parent = os.path.dirname(path)
    while not os.path.lexists(parent):
        up = os.path.dirname(parent)
        if up == parent:
            break
        parent = up
    if not os.path.isdir(parent):
        return False, "cannot be created: %s is not a directory" % parent
    if not os.access(parent, os.W_OK | os.X_OK):
        return False, "cannot be created: %s is not writable" % parent
    if parent == os.path.dirname(path):
        return True, "can be created"
    return True, "can be created under %s" % parent


def check_trace(project, home):
    try:
        path, source, _ = watch.choose_trace(install, project, None, home)
    except watch.WatchError as exc:
        return False, "watch cannot choose one: %s" % exc
    ok, how = writable(path)
    return ok, "%s (%s) %s" % (path, source, how)


# --- the command ---------------------------------------------------------------------

def run(project, out, environ=None, platform=None, which=None, runner=None, version_info=None,
        executable=None, home=None, registry=None, isfile=None, isdir=None):
    """Print the checks for `project` (default: the current directory) to
    out; 0 when every line is OK, 1 when any is MISSING."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    windows = platform == "win32"
    which = which or shutil.which
    runner = runner or run_version
    version_info = sys.version_info if version_info is None else version_info
    executable = sys.executable if executable is None else executable
    registry = registry or read_registry_key
    project = install.absolute(project or ".", windows)

    lines = [("python", check_python(version_info, executable, windows, which, environ)),
             ("claude", check_claude(environ, windows, which, runner)),
             ("hooks", check_hooks(project, windows)),
             ("notifier", check_notifier(project, environ, platform, isfile, isdir))]
    if windows:
        lines.append(("sysmon", check_sysmon(registry)))
    lines.append(("trace", check_trace(project, home)))

    out.write("raqib doctor: raqib %s (%s); project %s\n" % (
        raqib.__version__, _safe(os.path.join(install.PACKAGE_ROOT, "raqib")), _safe(project)))
    for name, (ok, text) in lines:
        out.write("%-8s%-9s%s\n" % ("OK" if ok else "MISSING", name, _safe(text)))
    missing = sum(1 for _, (ok, _) in lines if not ok)
    out.write("raqib doctor: %s\n" % ("%d MISSING" % missing if missing else "all OK"))
    return 1 if missing else 0
