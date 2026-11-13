"""OS notifications for `raqib watch` (M6.1, ADR-0005 decision 3): the knock.

A notification names the event (a rule id, SILENCE-LIVE, RAQIB-SILENCE or
TRACE-HOLE), the project and the trace seq or line it cites (M7.2, `raqib
watch --host`: "host, <image name> pid <n> (named|unknown)" for NEW-AGENT,
the agent's name and the round for AGENT-DARK-LIVE, the round for
HOST-HOLE); never a path,
command or output the agent produced, because a toast is a world-readable
surface. Every character outside [A-Za-z0-9 ._,:+()-] is replaced and the
text is bounded.

Backends, chosen by platform. Each program is run by absolute path with a
minimal environment, never looked up through PATH (ADR-0004 B-1), and the
text reaches it through a temp file, never through the command built here:
- win32:  %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
          -NoProfile -NonInteractive -ExecutionPolicy Bypass -File toast.ps1
          TEXTFILE. toast.ps1 is constant: it reads TEXTFILE and shows a
          WinRT toast (ToastNotificationManager) under PowerShell's AppUserModelID.
- darwin: /usr/bin/osascript notify.applescript TEXTFILE. The constant script
          reads TEXTFILE and calls display notification; nothing is
          interpolated into AppleScript source.
- other:  /usr/bin/notify-send or /bin/notify-send, through /bin/sh -c and a
          constant script that reads the two lines of TEXTFILE with the
          `read` builtin and execs notify-send with them. notify-send takes
          its text only as arguments, so its own argv holds the (cleaned) text.
- none of these programs: the terminal bell and one line on stderr.

Files (ADR-0005 B-5): every temp file is under ~/.raqib/tmp, never the cwd
or the system temp directory. toast.ps1 and notify.applescript are checked
against the sha256 of their in-code text before every use; a file that
differs or is gone is rewritten, and that is a hole. The notify-send wrapper
is never a file: it is passed inline with sh -c. On Windows, SystemRoot
must be an existing directory named Windows, else notifications are off and
that is a hole.

Off when CI is set in the environment, or with --no-notify; off is shown in
the state and in the page band, never hidden. Rate limit: one notification
per rate-limit id (the event, unless the caller gives another) per
LIMIT_SECONDS; the rest are folded into a count, sent once that minute is
over (tick()) or carried by the next notification of that id. A fold names
its first and last seq or line; on_folds(tokens, status, count) tells the
caller what became of each folded notification (ADR-0005 D-4). A delivery that fails (the program cannot be
started, exits with a status other than 0, or does not exit within
TIMEOUT_SECONDS) is a hole (A3) and falls back to the bell and stderr.
Nothing is ever signalled (A4): a program that does not exit in time is left
running, and that is recorded.
"""
from __future__ import annotations

import datetime
import hashlib
import ntpath
import os
import re
import subprocess
import sys
import tempfile

from raqib import own

LIMIT_SECONDS = 60
TIMEOUT_SECONDS = 10
TEXT_MAX = 120
PROJECT_MAX = 40
SUBJECT_MAX = 40   # M7.5 E3: the word a title may carry after the event (an image name)
UNSAFE = re.compile(r"[^A-Za-z0-9 ._,:+()-]")
NOTIFY_SEND_PATHS = ("/usr/bin/notify-send", "/bin/notify-send")
SH = "/bin/sh"
OSASCRIPT = "/usr/bin/osascript"
POWERSHELL_UNDER_SYSTEMROOT = ("System32", "WindowsPowerShell", "v1.0", "powershell.exe")
POWERSHELL_ARGS = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File")
# The AppUserModelID Windows PowerShell's own shortcut carries ({1AC14E77-...}
# is the System32 known folder), so the toast is shown without registering one.
POWERSHELL_APP_ID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
# Environment names each backend is given, when they are set; nothing else
# (no PATH, no PSModulePath). LC_ALL=C is added on POSIX.
WINDOWS_ENV = ("SystemRoot", "SystemDrive", "WINDIR", "TEMP", "TMP", "USERPROFILE", "APPDATA",
               "LOCALAPPDATA", "USERNAME", "USERDOMAIN", "COMPUTERNAME")
NOTIFY_SEND_ENV = ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY")
OSASCRIPT_ENV = ("HOME",)

# $0 is the notify-send path, $1 the text file: two lines, title and body.
NOTIFY_SEND_SH = ('{ IFS= read -r t && IFS= read -r b; } < "$1" && '
                  'exec "$0" --app-name=Raqib --urgency=critical -- "$t" "$b"')
TOAST_PS1 = "\r\n".join([
    "# raqib/notify.py: show one toast; the text is in the file named by the first argument.",
    "$ErrorActionPreference = 'Stop'",
    "$lines = [System.IO.File]::ReadAllLines($args[0])",
    "$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications,"
    " ContentType = WindowsRuntime]",
    "$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]",
    "$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02)",
    "$nodes = $xml.GetElementsByTagName('text')",
    "$null = $nodes.Item(0).AppendChild($xml.CreateTextNode($lines[0]))",
    "$null = $nodes.Item(1).AppendChild($xml.CreateTextNode($lines[1]))",
    "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)",
    "$app = '%s'" % POWERSHELL_APP_ID,
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)",
    ""])
OSA_SCRIPT = "\n".join([
    "-- raqib/notify.py: show one notification; the text is in the file named by the first argument.",
    "on run argv",
    "\tset p to paragraphs of (read (POSIX file (item 1 of argv)))",
    "\tdisplay notification (item 2 of p) with title (item 1 of p)",
    "end run",
    ""])
SCRIPTS = {"toast.ps1": TOAST_PS1, "notify.applescript": OSA_SCRIPT}
SCRIPT_SHA256 = {name: hashlib.sha256(text.encode("ascii")).hexdigest() for name, text in SCRIPTS.items()}


def default_tmp_root():
    """~/.raqib/tmp: where every notifier temp file lives (B-5)."""
    return os.path.join(os.path.expanduser("~"), ".raqib", "tmp")


def clean(text, limit=TEXT_MAX):
    """Text a notification may carry: the safe alphabet, bounded."""
    return UNSAFE.sub("_", str(text))[:limit]


def project_name(path):
    """The last part of a project path, cleaned, for notification text."""
    name = os.path.basename(str(path).rstrip("/\\")) or str(path)
    return clean(name, PROJECT_MAX).lstrip("-") or "project"


def _bounded(text, limit=160):
    text = "".join(c if c.isprintable() else "?" for c in text.strip())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def run_program(argv, env, timeout=TIMEOUT_SECONDS, wait=True):
    """Run one program; (exit status or None, error text or None). argv[0]
    must be an absolute path: nothing is looked up through PATH (B-1). With
    wait, a program that has not exited after timeout seconds is left
    running, never signalled (A4); without wait, returns once it started."""
    if not argv or not os.path.isabs(argv[0]):
        return None, "%r is not an absolute path: no program is looked up through PATH" % (argv[:1],)
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
               "stderr": subprocess.PIPE if wait else subprocess.DEVNULL, "env": dict(env)}
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = own.started(subprocess.Popen(list(argv), **options))   # ADR-0007 BH-1: recorded as it starts
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, "%s could not be started: %s" % (argv[0], exc)
    if not wait:
        return None, None
    try:
        _, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, ("%s did not exit within %g s; it was left running, not signalled (A4)"
                      % (argv[0], timeout))
    if proc.returncode != 0:
        return proc.returncode, "%s exited %d: %s" % (
            argv[0], proc.returncode, _bounded((err or b"").decode("utf-8", "replace")))
    return 0, None


def env_value(environ, name):
    """environ[name]; a plain dict is searched case-insensitively, as Windows does."""
    if name in environ:
        return environ[name]
    for key, value in environ.items():
        if key.upper() == name.upper():
            return value
    return None


def windows_root(environ, isdir=None):
    """(SystemRoot, None) when it is an existing directory named Windows,
    else (None, why). notify and the page opener both use it (B-5, D-3)."""
    isdir = isdir or os.path.isdir
    root = env_value(environ, "SystemRoot")
    if not root:
        return None, "SystemRoot is not set, so no program under it can be placed"
    if not (isdir(root) and ntpath.basename(root.rstrip("\\/")).lower() == "windows"):
        return None, "SystemRoot %r is not an existing directory named Windows, so no program under it is trusted" % (
            root,)
    return root, None


def fold_text(count, first, last):
    """What a fold says: how many, and the first and last seq or line (D-4)."""
    if count == 1:
        return "1 more (%s)" % last
    return "%d more (first %s, last %s)" % (count, first, last)


FIRST_EVENT = "FIRST-FINDING"          # M6.4 E3: the knock on the first finding of a watch
FIRST_LIMIT = "FIRST-FINDING (window)"  # its own rate-limit id, apart from every rule's
BY_THE_RULE = "by the rule"             # ADR-0006 A-5: a high first finding's knock was its rule's own
RULE_KNOCKS = ("sent", "terminal", "failed", "folded")   # a rule's notice that says it knocked (or tried to)


class FirstFinding:
    """M6.4 E3 (ADR-0006 "the knock"): the first finding of a watch knocks
    once, whatever its severity, through the watch's Notifier under its own
    rate-limit id. A finding counts when it is live (not history, B-3) and
    settled (a pending one can still be taken back, B-1). The text is the
    A-4 text: "Raqib: FIRST-FINDING" and "project <name>, <rule id>
    <severity> seq <n>" - the rule id and severity come from the catalog,
    the seq is a number; never agent content."""

    def __init__(self, notifier):
        self.notifier = notifier
        self.knocked = None   # {"rule_id", "severity", "where", "status", "now"} once it knocked

    @staticmethod
    def first(findings):
        """The first live, settled finding entry (watch.json's shape), or None."""
        for entry in findings:
            if isinstance(entry, dict) and not entry.get("history") and entry.get("state") == "settled":
                return entry
        return None

    @staticmethod
    def where(entry):
        seqs = [str(s) for s in entry.get("cited_seq") or []]
        shown = ",".join(seqs[:3]) + (" +%d more" % (len(seqs) - 3) if len(seqs) > 3 else "")
        return clean("%s %s seq %s" % (entry.get("rule_id"), entry.get("severity"), shown or "-"))

    @staticmethod
    def by_the_rule(entry):
        """The rule's own knock of this finding, when it had one (ADR-0006
        A-5): a live settled high finding knocked as its rule when it
        settled (watch._settle), and its notice is that knock's outcome."""
        notice = entry.get("notice")
        if entry.get("severity") != "high" or not isinstance(notice, str):
            return None
        if notice in RULE_KNOCKS or notice.startswith("folded: "):
            return notice
        return None

    def check(self, findings, now):
        """Knock for the first live settled finding, once; the record, or
        None when nothing knocked now. A high first finding has already
        knocked as its rule: that knock is recorded as the first one, with
        status "by the rule", and FIRST-FINDING is not sent (A-5: once)."""
        if self.knocked is not None:
            return None
        entry = self.first(findings)
        if entry is None:
            return None
        where = self.where(entry)
        rule_notice = self.by_the_rule(entry)
        if rule_notice is not None:
            status = BY_THE_RULE
        else:
            status = self.notifier.notify(FIRST_EVENT, where, now, limit_id=FIRST_LIMIT)
        self.knocked = {"rule_id": entry.get("rule_id"), "severity": entry.get("severity"), "where": where,
                        "status": status, "now": now, "rule_notice": rule_notice}
        return self.knocked


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Notifier:
    """One project's notifications. notify() and tick() take `now`, a
    monotonic time in seconds; stamp(now) turns it into the time recorded
    with a hole."""

    def __init__(self, project, enabled=True, reason=None, environ=None, platform=None, runner=None,
                 isfile=None, stderr=None, limit_seconds=LIMIT_SECONDS, stamp=None, isdir=None, tmp_root=None,
                 host=False):
        self.project = project_name(project)
        self.host = host   # M7.2: raqib watch --host; the body names the host, not a project
        self.environ = dict(os.environ if environ is None else environ)
        self.platform = platform or sys.platform
        self.runner = runner or run_program
        self.isfile = isfile or os.path.isfile
        self.isdir = isdir or os.path.isdir
        self.tmp_root = tmp_root or default_tmp_root()
        self.stderr = stderr
        self.limit = limit_seconds
        self.stamp = stamp or (lambda now: _now_iso())
        self.counts = {"sent": 0, "terminal": 0, "failed": 0, "folded": 0, "off": 0}
        self.holes = []
        self.last = {}     # rate-limit id -> time of the last delivery
        self.folded = {}   # rate-limit id -> {"event", "count", "first", "last", "tokens"}
        self.on_folds = None  # on_folds(tokens, status, count): what became of folded notifications
        self.tmpdir = None
        self.scripts = set()   # script names written once
        self.files = 0
        self.backend, self.program, self.reason = self._choose(enabled, reason)

    def _choose(self, enabled, reason):
        if not enabled:
            return "off", None, reason or "switched off"
        if self.environ.get("CI"):
            return "off", None, "CI is set: no notification is shown in CI"
        if self.platform == "win32":
            root, why = windows_root(self.environ, self.isdir)
            if root is None:
                self._hole(None, why, "notify-off")
                return "off", None, why
            program = ntpath.join(root, *POWERSHELL_UNDER_SYSTEMROOT)
            if not self.isfile(program):
                return "terminal", None, "no %s" % program
            return "windows-toast", program, None
        if self.platform == "darwin":
            if not self.isfile(OSASCRIPT):
                return "terminal", None, "no %s" % OSASCRIPT
            return "osascript", OSASCRIPT, None
        program = next((p for p in NOTIFY_SEND_PATHS if self.isfile(p)), None)
        if program is None:
            return "terminal", None, "no %s" % " or ".join(NOTIFY_SEND_PATHS)
        if not self.isfile(SH):
            return "terminal", None, "no %s to read the text file for notify-send" % SH
        return "notify-send", program, None

    # --- what watch calls ------------------------------------------------------

    def notify(self, event, where, now, token=None, limit_id=None, subject=None):
        """Knock once for an event. Returns "sent", "terminal" (bell and
        stderr), "failed" (a hole; bell and stderr instead), "folded" (rate
        limit) or "off". limit_id: the rate-limit id (default: the event);
        token: handed back through on_folds when a fold is delivered;
        subject: a word the title carries after the event (M7.5 E3: "Raqib:
        NEW-AGENT kimi"), cleaned like the rest."""
        event = clean(event, 48) or "RAQIB"
        key = limit_id or event
        if self.backend == "off":
            self.counts["off"] += 1
            return "off"
        last = self.last.get(key)
        if last is not None and now - last < self.limit:
            fold = self.folded.setdefault(key, {"event": event, "count": 0, "first": where, "last": where,
                                                "tokens": [], "subject": subject})
            fold["count"] += 1
            fold["last"] = where
            if token is not None:
                fold["tokens"].append(token)
            self.counts["folded"] += 1
            return "folded"
        self.last[key] = now
        fold = self.folded.pop(key, None)
        if fold:
            where = "%s, and %s" % (where, fold_text(fold["count"], fold["first"], fold["last"]))
        status = self._deliver(event, where, now, subject)
        if fold:
            self._folds_done(fold, status)
        return status

    def tick(self, now):
        """Send the folded count of each rate-limit id whose minute is over.
        Returns [(event, count, status)]."""
        out = []
        for key in sorted(self.folded):
            fold = self.folded[key]
            if now - self.last[key] >= self.limit:
                del self.folded[key]
                self.last[key] = now
                status = self._deliver(fold["event"], fold_text(fold["count"], fold["first"], fold["last"]), now,
                                       fold.get("subject"))
                self._folds_done(fold, status)
                out.append((fold["event"], fold["count"], status))
        return out

    def _folds_done(self, fold, status):
        if self.on_folds is not None and fold["tokens"]:
            self.on_folds(fold["tokens"], status, fold["count"])

    def state(self):
        """The notifier as recorded in <trace>.watch.json."""
        return {"backend": self.backend, "program": self.program, "reason": self.reason,
                "on": self.backend != "off", "limit_seconds": self.limit, "counts": dict(self.counts),
                "folded_waiting": {k: f["count"] for k, f in sorted(self.folded.items())}}

    def band(self):
        """(level, text) for the page band."""
        if self.backend == "off":
            return "incomplete", "notifications: off (%s)" % self.reason
        if self.counts["failed"]:
            return "alarm", "notifications: %d not delivered by %s (holes; bell and stderr instead)" % (
                self.counts["failed"], self.backend)
        if self.backend == "terminal":
            return "incomplete", "notifications: terminal bell and stderr only (%s)" % self.reason
        return "clean", "notifications: on (%s)" % self.backend

    def close(self):
        """Remove the temp files; a program left running may still hold one."""
        if self.tmpdir is None:
            return
        try:
            names = os.listdir(self.tmpdir)
        except OSError:
            names = []
        for name in names:
            try:
                os.remove(os.path.join(self.tmpdir, name))
            except OSError:
                pass
        try:
            os.rmdir(self.tmpdir)
        except OSError:
            pass
        self.tmpdir = None

    # --- delivery --------------------------------------------------------------

    @staticmethod
    def title(event, subject=None):
        """The title: "Raqib: <event>", and the subject after it when one is
        given (M7.5 E3), in the A-4 alphabet."""
        subject = clean(subject, SUBJECT_MAX).strip() if subject else ""
        return clean("Raqib: %s%s" % (event, " " + subject if subject else ""))

    def texts(self, event, where, subject=None):
        """(title, body) of a notification."""
        if self.host:   # M7.2 (A-4 alphabet): "host, <image name> pid <n> (named|unknown)"
            return self.title(event, subject), clean("host, %s" % clean(where))
        return (self.title(event, subject),
                clean("project %s, %s" % (self.project, clean(where))))

    def _deliver(self, event, where, now, subject=None):
        title, body = self.texts(event, where, subject)
        if self.backend == "terminal":
            self.counts["terminal"] += 1
            self._bell(title, body)
            return "terminal"
        error = self._run(title, body, now)
        if error is None:
            self.counts["sent"] += 1
            return "sent"
        self.counts["failed"] += 1
        self._hole(now, "%s: %s" % (self.backend, error))
        self._bell(title, body)
        return "failed"

    def _bell(self, title, body):
        stream = self.stderr or sys.stderr
        stream.write("\araqib watch: NOTICE %s - %s\n" % (title, body))
        stream.flush()

    def _hole(self, now, detail, kind="notify-failed"):
        at = self.stamp(now) if now is not None else _now_iso()
        for hole in self.holes:
            if hole["kind"] == kind and hole["detail"] == detail:
                hole["count"] += 1
                hole["last"] = at
                return
        self.holes.append({"kind": kind, "detail": detail, "count": 1, "at": at, "last": at})

    def _file(self, name, text):
        if self.tmpdir is None:
            if not os.path.isabs(self.tmp_root):
                raise OSError("the temp directory %r is not an absolute path (is HOME set?)" % self.tmp_root)
            os.makedirs(self.tmp_root, mode=0o700, exist_ok=True)
            self.tmpdir = tempfile.mkdtemp(prefix="raqib-notify-", dir=self.tmp_root)
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", encoding="ascii", newline="") as f:
            f.write(text)
        return path

    def _sha256_of(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except FileNotFoundError:
            return None

    def _script(self, name, now):
        """The path of a helper script whose bytes have the sha256 of its
        in-code text, checked now, right before it is used (B-5)."""
        want = SCRIPT_SHA256[name]
        path = os.path.join(self.tmpdir, name) if self.tmpdir is not None else None
        have = self._sha256_of(path) if path else None
        if have == want:
            return path
        if name in self.scripts:
            self._hole(now, "%s %s; it was rewritten from the in-code text (sha256 %s)" % (
                path, "was gone" if have is None else "had sha256 %s, not its in-code %s" % (have, want), want),
                "script-changed")
        path = self._file(name, SCRIPTS[name])
        self.scripts.add(name)
        have = self._sha256_of(path)
        if have != want:
            raise OSError("%s still has sha256 %s after it was rewritten, not %s" % (path, have, want))
        return path

    def argv(self, text_path, now=None):
        """The command for one notification; the text is only in text_path."""
        if self.backend == "windows-toast":
            return [self.program] + list(POWERSHELL_ARGS) + [self._script("toast.ps1", now), text_path]
        if self.backend == "osascript":
            return [self.program, self._script("notify.applescript", now), text_path]
        return [SH, "-c", NOTIFY_SEND_SH, self.program, text_path]

    def env(self):
        if self.backend == "windows-toast":
            names = WINDOWS_ENV
            env = {}
        else:
            names = OSASCRIPT_ENV if self.backend == "osascript" else NOTIFY_SEND_ENV
            env = {"LC_ALL": "C"}
        for name in names:
            value = env_value(self.environ, name)
            if value:
                env[name] = value
        return env

    def _run(self, title, body, now=None):
        """None when delivered, else why not."""
        try:
            self.files += 1
            text_path = self._file("text-%d.txt" % self.files, "%s\n%s\n" % (title, body))
            argv = self.argv(text_path, now)
        except OSError as exc:
            return "cannot prepare the notification files: %s" % (exc.strerror or exc)
        code, error = self.runner(argv, self.env(), TIMEOUT_SECONDS)
        if code is not None:  # it exited: nothing reads the file any more
            try:
                os.remove(text_path)
            except OSError:
                pass
        if error is None and code != 0:
            error = "exited %r" % (code,)
        return error
