"""raqib doctor (M6.3, ADR-0005 Consequences): what is missing, in one screen.

`raqib doctor [PROJECT]` (default: the current directory) prints one line
per check, OK, MISSING or UNSURE (a check that cannot be made here;
Amendment H-1), then a summary line ("all OK", or "N MISSING, M UNSURE"),
and exits 1 when any line is MISSING, else 0:
- python    this Python is MIN_PYTHON or newer; on POSIX the hooks run
            `python3` from PATH, so python3 must be found on PATH (this
            shell's PATH; Claude Code's may differ), and as an absolute path:
            a relative one may shadow the real one in the agent's working
            directory (G-3). On Windows the hooks run this Python by its path.
- claude    `claude` is found on PATH by shutil.which, and only as an
            absolute path outside PROJECT (a relative PATH entry, on Windows
            the current directory, or a directory inside the project is
            refused, never run). That path is run with --version, a minimal
            environment (CLAUDE_ENV) whose PATH keeps only the absolute
            entries outside the project, a fresh empty temporary directory as
            its cwd (G-4), and a CLAUDE_TIMEOUT limit; its first line is the
            version.
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
- tkinter   `raqib app` (M6.4, ADR-0006) can open its window: tkinter
            imports in this Python (OK with the Tk version; UNSURE, "the
            window needs it (python3-tk); watch does not", when it does not:
            ADR-0006 A-9, a missing tkinter never fails doctor's exit),
            and on Linux and other X11 systems DISPLAY is set (UNSURE when
            it is not: no window can open in this session; nothing is opened
            to find out).
- sysmon    Windows only: the event channel Microsoft-Windows-Sysmon/Operational
            is registered and enabled (HKLM, read with winreg). That is the
            Sysmon source `raqib discover` reads (ADR-0004); whether the
            service is running is not checked.
- host      M7.1 (ADR-0007): live discovery can read this host. On Windows
            the three APIs `raqib discover` reads in-process resolve
            (kernel32 Toolhelp32 and the process queries, iphlpapi
            GetExtendedTcpTable, dnsapi DnsGetCacheDataTable): OK; OK with
            "names: no" when only dnsapi is missing; MISSING per API
            otherwise. Names are resolved, no function is called and no
            sample is taken. Elsewhere: OK, "live discovery reads /proc".
- trace     the trace `raqib watch` would choose (watch.choose_trace) can be
            written: the file if it exists, else the nearest existing
            directory above it, where watch creates the rest; choose_trace's
            notes are printed below the line. On Windows os.access cannot
            tell (W_OK on a directory always succeeds), and nothing is
            written to find out, so the line says "not checked" and is
            UNSURE, never OK (G-5, H-1).

Read-only: doctor writes no file in the project, the home or the trace's
directory. The only thing it creates is the empty temporary directory
`claude --version` runs in, removed afterwards. The only program it starts
is `claude --version`, by absolute path; one that does not answer within
CLAUDE_TIMEOUT is left running and recorded, never signalled (A4, as
raqib/notify.py does).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile

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
NOT_CHECKED = "not checked (os.access cannot tell on Windows)"
# A check's verdict: True (OK), False (MISSING) or UNSURE: it cannot be made here (H-1).
UNSURE = "UNSURE"
VERDICTS = {True: "OK", False: "MISSING", UNSURE: "UNSURE"}


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _which(which, name, environ):
    """which(name) on environ's PATH only; None when PATH is not set."""
    path = notify.env_value(environ, "PATH")
    return which(name, path=path) if path else None


def _in_project(path, project):
    """True when an absolute path is the project or under it (symlinks resolved)."""
    return bool(project) and os.path.isabs(path) and watch.inside(path, project)


def run_version(argv, env, timeout=CLAUDE_TIMEOUT, cwd=None):
    """Run a version query in cwd: (exit status or None, stdout text, error
    or None). argv[0] must be an absolute path. A program still running
    after timeout seconds is left running, never signalled (A4)."""
    if not argv or not os.path.isabs(argv[0]):
        return None, "", "%r is not an absolute path: nothing is looked up through PATH" % (argv[:1],)
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": dict(env),
               "cwd": cwd}
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
        if found and not os.path.isabs(found):
            problems.append("python3 is found only as %s, a relative path (the current directory or a relative PATH"
                            " entry): the hooks run python3 in the agent's working directory, where one may shadow"
                            " the real one" % found)
            hook = None
        elif found:
            hook = "the hooks run python3 from PATH: %s" % found
        else:
            problems.append("the hooks run python3 and there is none on PATH")
            hook = None
    text = "%s at %s" % (version, executable or "?")
    return not problems, "; ".join([text] + ([hook] if hook else []) + problems)


def claude_path(environ, project=None):
    """The PATH `claude --version` gets: the absolute entries of environ's
    PATH (this host's separator and path rules), none inside the project (G-4)."""
    entries = (notify.env_value(environ, "PATH") or "").split(os.pathsep)
    return os.pathsep.join(e for e in entries if e and os.path.isabs(e) and not _in_project(e, project))


def claude_env(environ, windows, project=None):
    names = CLAUDE_ENV_WINDOWS if windows else CLAUDE_ENV
    env = {} if windows else {"LC_ALL": "C"}
    for name in names:
        value = claude_path(environ, project) if name == "PATH" else notify.env_value(environ, name)
        if value:
            env[name] = value
    return env


def check_claude(environ, windows, which, runner, project=None):
    found = _which(which, "claude", environ)
    if not found:
        return False, "not on PATH (install Claude Code; the hooks are Claude Code hooks)"
    if not os.path.isabs(found):
        return False, ("found only as %s, a relative path (the current directory or a relative PATH"
                       " entry); doctor runs only an absolute path, and a claude there may shadow the real one"
                       % found)
    if _in_project(found, project):
        return False, ("found as %s, inside the project, which the agent can write; doctor does not run it,"
                       " and a claude there may shadow the real one" % found)
    # A fresh, empty cwd: nothing of the project's is in the query's working directory (G-4).
    with tempfile.TemporaryDirectory(prefix="raqib-doctor-", ignore_cleanup_errors=True) as cwd:
        code, out, error = runner([found, "--version"], claude_env(environ, windows, project), CLAUDE_TIMEOUT, cwd)
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


def check_host(platform, prober=None):
    """M7.1 E3: (ok, text) of live discovery on this host. Read-only: on
    Windows only DLL symbols are resolved (hostwin.probe); nothing is called."""
    if platform.startswith("linux"):
        return True, "live discovery reads /proc (raqib discover; Linux)"
    if platform != "win32":     # ADR-0007 A-12: discover there reads the homes only and ends incomplete
        return UNSURE, "homes only; no live reader"
    if prober is None:
        if os.name != "nt":
            return UNSURE, "a Windows doctor run on %s: the Win32 API is not here to resolve; not checked" % sys.platform
        from raqib import hostwin
        prober = hostwin.probe
    try:
        found = prober()
    except Exception as exc:     # a probe that fails is a MISSING line, never a crash of doctor
        return False, "the Win32 API could not be probed: %s: %s" % (type(exc).__name__, exc)
    what = (("kernel32", "Toolhelp32 processes"), ("iphlpapi", "GetExtendedTcpTable"),
            ("dnsapi", "DnsGetCacheDataTable"))
    parts = ["%s %s %s" % (dll, name, "OK" if not found.get(dll, "not probed") else "MISSING (%s)" % found.get(
        dll, "not probed")) for dll, name in what]
    core = not found.get("kernel32", "not probed") and not found.get("iphlpapi", "not probed")
    if not core:
        return False, "raqib discover cannot run live: %s" % "; ".join(parts)
    if found.get("dnsapi", "not probed"):
        return True, "raqib discover runs live; names: no (%s)" % "; ".join(parts)
    return True, "raqib discover runs live: %s" % "; ".join(parts)


def writable(path, windows=False):
    """(True, how) when the trace can be appended to or created, else
    (False, why). Reads only: nothing is created to find out. On Windows
    os.access cannot tell: what is certain without it is said, and the rest
    is (UNSURE, "... not checked ...")."""
    if os.path.isdir(path):
        return False, "is a directory"
    if os.path.lexists(path):
        if windows:
            return UNSURE, "exists; " + NOT_CHECKED
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
    if windows:
        return UNSURE, "would be created under %s; %s" % (parent, NOT_CHECKED)
    if not os.access(parent, os.W_OK | os.X_OK):
        return False, "cannot be created: %s is not writable" % parent
    if parent == os.path.dirname(path):
        return True, "can be created"
    return True, "can be created under %s" % parent


TK_UNSURE = "the window needs it (python3-tk); watch does not"


def check_tkinter(environ, platform, importer=None):
    """M6.4 E5: the window's toolkit. Imports tkinter (opens no window)."""
    from raqib import app   # app imports doctor: imported here, not at the top
    tk, why = app.probe_tk(importer)
    if tk is None:   # ADR-0006 A-9: UNSURE, not MISSING - `raqib watch` does not need it
        return UNSURE, "%s; %s" % (TK_UNSURE, why)
    version = getattr(tk, "TkVersion", "?")
    problem = app.display_problem(environ, platform)
    if problem:
        return UNSURE, "Tk %s (tkinter imports); %s" % (version, problem)
    return True, "Tk %s (tkinter); `raqib app` can open its window" % version


def check_trace(project, home, windows=False):
    """(ok, text, notes): notes are choose_trace's, printed below the line (P7)."""
    try:
        path, source, notes = watch.choose_trace(install, project, None, home)
    except watch.WatchError as exc:
        return False, "watch cannot choose one: %s" % exc, []
    ok, how = writable(path, windows)
    return ok, "%s (%s) %s" % (path, source, how), notes


# --- the command ---------------------------------------------------------------------

def checks(project, environ=None, platform=None, which=None, runner=None, version_info=None,
           executable=None, home=None, registry=None, isfile=None, isdir=None, importer=None, prober=None):
    """(project made absolute, [(name, (verdict, text))], notes): the checks
    run() prints and the window's first screen shows (M6.4)."""
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
             ("claude", check_claude(environ, windows, which, runner, project)),
             ("hooks", check_hooks(project, windows)),
             ("notifier", check_notifier(project, environ, platform, isfile, isdir)),
             ("tkinter", check_tkinter(environ, platform, importer))]
    if windows:
        lines.append(("sysmon", check_sysmon(registry)))
    lines.append(("host", check_host(platform, prober)))
    ok, text, notes = check_trace(project, home, windows)
    lines.append(("trace", (ok, text)))
    return project, lines, notes


def summary(lines):
    """The last line's text: "all OK", or "N MISSING, M UNSURE"; and the exit."""
    missing = sum(1 for _, (ok, _) in lines if ok is False)
    unsure = sum(1 for _, (ok, _) in lines if ok == UNSURE)
    return ("%d MISSING, %d UNSURE" % (missing, unsure) if missing or unsure else "all OK"), (1 if missing else 0)


def run(project, out, environ=None, platform=None, which=None, runner=None, version_info=None,
        executable=None, home=None, registry=None, isfile=None, isdir=None, importer=None, prober=None):
    """Print the checks for `project` (default: the current directory) to
    out; 1 when any line is MISSING, else 0 (an UNSURE line does not fail it)."""
    project, lines, notes = checks(project, environ, platform, which, runner, version_info, executable, home,
                                   registry, isfile, isdir, importer, prober)
    out.write("raqib doctor: raqib %s (%s); project %s\n" % (
        raqib.__version__, _safe(os.path.join(install.PACKAGE_ROOT, "raqib")), _safe(project)))
    for name, (ok, text) in lines:
        out.write("%-8s%-9s%s\n" % (VERDICTS[ok], name, _safe(text)))
    for note in notes:
        out.write("%17snote: %s\n" % ("", _safe(note)))
    text, code = summary(lines)
    out.write("raqib doctor: %s\n" % text)
    return code
