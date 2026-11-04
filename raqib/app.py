"""raqib app (M6.4, ADR-0006; M7.3, ADR-0007 decision 5): Raqib as an
ordinary desktop program window that starts from the host.

`raqib app [PROJECT]` (or the `raqib-app` gui-script, which on Windows runs
under pythonw with no console) opens one tkinter window, standard library
only:
- first screen, the HOST (M7.3): one discover round at open - the reader
  of `raqib watch --host` (host.live_reader, read-only) in a thread
  (HostProbe), with the watch's deadline 2 x T; the band says "reading the
  host..." and a reader not back by then is READER LATE, a hole. Then the
  trees found (image, pid, named / unknown / benign, first seen, acts,
  endpoints; never a command line), or "no agent seen (N records, M holes).
  Not a clearance."; a round that read nothing is NOTHING READ. The doctor
  lines fold under "Checks" (open when any is MISSING). "Watch this host"
  runs the HostWatch of `raqib watch --host` (HostSession: host.start,
  host.loop with Stop, host.conclude, host.close; a round every --every T
  seconds) in a worker: its table, its NEW-AGENT / AGENT-DARK-LIVE lines,
  and its knocks through its own Notifier (each tree under its own
  rate-limit id, ADR-0007 C-5); the band reads WATCHING HOST, READER LATE,
  HOST READER FAILED or NOTHING READ; Stop shows its final report (exit
  0 / 1 / 3, C-10). A second host watch on this home is refused by
  HostWatch (C-2, D-6): the refusal is a hole line, not a crash (exit 2,
  F-8). Nothing of the host round or watch writes outside ~/.raqib (A4).
  M7.3 REDO (ADR-0007 Amendment F): the look's level follows C-10's codes
  from its own sources, never discover's word (F-1, F-7); its holes and its
  AGENT-DARK lines are listed; it is written to ~/.raqib/host/look.json
  (F-10) and its holes stand in the footer and the log until the watch's
  first round, whose reader waits for the look's (F-3). A header with
  "Host" and "Project" reaches both screens while their watches run (F-2);
  the host screen has its Log pane and Open page (F-6, F-11).
- "Watch a project" opens the project screen of M6.4, unchanged: what
  `raqib doctor` says for the project (OK / MISSING /
  UNSURE, run in a thread so the window never waits on `claude --version`),
  a project field with Browse, Check again and Start; PROJECT on the
  command line is preselected there. The host and a project may be watched
  at once (two sessions, read by the same tick);
- watching screen: the band (the state word of ui.status, the notifier, the
  holes), the findings by severity, the holes, the page URL, Stop;
- after the watch: the final report of watch.finish(), and Back.

Start runs the same watch as `raqib watch` - watch.start(), watch.loop(),
watch.conclude(), watch.close(): the hooks, the trace, <trace>.watch.json,
the registry row and the read-only page on 127.0.0.1 - in a worker thread.
Stop is that loop's Stop, the equivalent of Ctrl-C. The window reads the
watch's state under the Watch lock from after(), never from the page; the
heartbeat's age is recomputed at every tick from the wall clock, so a watch
stuck under its lock reads "CRASHED or stuck (N s)" (ADR-0006 A-2). It
sends nothing to the agent (A4): Start and Stop control Raqib's own
watching. The programs that run are those of `raqib doctor` - `claude
--version`, at open, on Browse and on Check again - and nothing else here
(A-11), besides the host's reader, which is `raqib watch --host`'s (the OS
API through ctypes on Windows, /proc on Linux and `ss` by absolute path
only when /proc/net/tcp cannot be read, M5.0 B-1); the watch it starts runs
the notifier as `raqib watch` does, and
the "Open page" button runs the same opener as `raqib watch` (watch.open_page,
never under CI), only when the person clicks it (A-13). The page is not
opened by itself; its URL is shown.

The knock (E3): the first live, settled finding of a watch, whatever its
severity, knocks once through the watch's Notifier under its own rate-limit
id (notify.FirstFinding, run by watch.first_step); a high first finding has
knocked as its rule already, and that knock is the first one ("by the
rule", A-5). The watching screen shows "first finding: <rule> <severity>
(<status>)", and a Log pane shows the watch's own lines at any time.

Holes (A3): a tray that fails, a knock that fails, a worker that crashes, a
state the window cannot read - each is a line under "holes" in the window,
never swallowed and never a crash of the window. On Windows the tray icon
(raqib/tray.py) has Show / Stop / Quit and closing the window while
watching hides it there; elsewhere there is no tray (recorded as a note)
and closing the window while watching stops the watch, leaving the final
report on screen; closing it again quits.

Without tkinter, or on X11 without DISPLAY, `raqib app` exits 2 with one
sentence (AppError). Under the `raqib-app` gui-script (gui_main) the watch's
lines and the final report go to ~/.raqib/app.log (truncated at start,
bounded), and a failure before the window is up is one message box on
Windows (tray.message_box) and a line on stderr elsewhere (A-4). Quit waits
JOIN_SECONDS for the final report; a watch that does not end by then brings
the window back with a hole, and nothing is killed (A-3). The logic - the views, the Session over a watch, the
Controller that decides what a close or a tray action does - is plain
Python, tested with fakes; only Window touches Tk, and tkinter is imported
only when the window is made.
"""
from __future__ import annotations

import copy
import importlib
import os
import queue
import sys
import threading
import time
import traceback

from raqib import host as hostmod, notify, tray as traymod, ui, watch

TITLE = "Raqib"
TICK_MS = 500                 # how often the window reads the state (after())
LOCK_SECONDS = 0.2            # how long one read waits for the Watch lock before it shows the last state
JOIN_SECONDS = 30.0           # how long Quit waits for the worker's final report
LOG_MAX = 1000000             # characters of the watch's own lines kept for the window
APP_LOG = "app.log"           # A-4: under ~/.raqib, the gui-script's output
APP_LOG_MAX = 4000000         # bytes of app.log; beyond, one line says the rest is not written
LOG_VIEW_MAX = 200000        # characters of the log the Log pane shows (A-5)
ERR_MAX = 64000               # characters of stderr kept to show in the message (A-4)
LEVEL_COLORS = {"alarm": "#b00020", "incomplete": "#9a5000", "clean": "#1b6e35"}
VERDICT_COLORS = {"OK": "clean", "MISSING": "alarm", "UNSURE": "incomplete"}
NO_TK = ("tkinter cannot be imported in this Python (%s): install python3-tk (Debian and Ubuntu: sudo apt install"
         " python3-tk) or use a python.org Python, which ships it; `raqib watch` works without it")
NO_DISPLAY = ("DISPLAY is not set: no window can open in this session (Tk on %s needs an X display; under Wayland"
              " XWayland sets DISPLAY)")


class AppError(Exception):
    """raqib app cannot open its window (exit 2)."""


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


# --- can a window open here ------------------------------------------------------------

def probe_tk(importer=None):
    """(the tkinter module, None), or (None, the sentence naming python3-tk).
    Imports tkinter; opens no window."""
    importer = importer or importlib.import_module
    try:
        return importer("tkinter"), None
    except ImportError as exc:
        return None, NO_TK % _safe(exc)


def display_problem(environ, platform=None):
    """None when a Tk window can be asked for, else why not. Windows and
    macOS need no DISPLAY; X11 does. Nothing is opened to find out."""
    platform = platform or sys.platform
    if platform in ("win32", "darwin") or notify.env_value(environ, "DISPLAY"):
        return None
    return NO_DISPLAY % platform


# --- what the window shows (pure) ----------------------------------------------------------

def doctor_lines(lines, notes=()):
    """[(verdict word, level, text line)] of doctor's checks, notes below."""
    from raqib import doctor
    out = []
    for name, (ok, text) in lines:
        word = doctor.VERDICTS[ok]
        out.append((word, VERDICT_COLORS[word], "%-8s%-9s%s" % (word, name, _safe(text))))
    out += [("", "incomplete", "%17snote: %s" % ("", _safe(n))) for n in notes]
    return out


def finding_line(entry):
    """One finding of watch.json's inventory as the window lists it: the
    rule, its state, the session and seqs, the summary, how it knocked."""
    seqs = entry.get("cited_seq") or []
    return _safe("%s %s%s session %s %s: %s [%s]" % (
        entry.get("rule_id"), entry.get("state"), " (history)" if entry.get("history") else "",
        entry.get("session_id"), watch.seq_text(list(seqs)), entry.get("summary"), entry.get("notice")))


def hole_line(hole):
    more = " (%d times, last at %s)" % (hole["count"], hole.get("last")) if hole.get("count", 1) > 1 else ""
    past = " (history)" if hole.get("history") else ""
    return _safe("%s: %s at %s%s%s" % (hole.get("kind"), hole.get("detail"), hole.get("at"), more, past))


def watch_view(state, extra_holes=()):
    """What the watching screen shows of a watch's state (watch.json's
    shape): {word, level, detail, badges, findings, holes, url}. findings is
    [(severity, [lines])], high first (ui.severity_groups); holes the
    watch's and the notifier's holes, open silence windows, and extra_holes
    (the window's own: tray, knock, worker)."""
    word, level, detail = ui.status(state)
    age, stale = stale_age(state)
    if age is not None:   # A-2, ADR-0005 C-4: the watcher itself is silent
        word, level = "CRASHED or stuck (%d s)" % age, "alarm"
    entries = [e for e in state.get("findings") or [] if isinstance(e, dict)]
    groups = [(sev, [finding_line(e) for e in items]) for sev, items in ui.severity_groups(entries)]
    holes = [hole_line(h) for h in state.get("holes") or [] if isinstance(h, dict)]
    for w in state.get("silence") or []:
        if isinstance(w, dict) and w.get("closed") is None:
            holes.append(_safe("silence-window: no line since %s (%s): open" % (w.get("since"), w.get("after"))))
    holes += [_safe(h) for h in extra_holes]
    return {"word": word, "level": level, "detail": _safe(detail),
            "badges": [(lv, _safe(text)) for lv, text in ui.band_items(state)[1:]],
            "findings": groups, "holes": holes, "url": state.get("url") or "-"}


def stale_age(state):
    """(age in s, stale_after) when a watching state's heartbeat is older
    than stale_after_seconds (C-4), else (None, stale_after)."""
    stale = state.get("stale_after_seconds")
    age = state.get("heartbeat_age_seconds")
    if state.get("finished") or not isinstance(stale, (int, float)) or not isinstance(age, (int, float)):
        return None, stale
    return (age if age > stale else None), stale


def aged(state, wall_now):
    """A-2: the state with heartbeat_age_seconds recomputed from its
    heartbeat (wall time) and the wall clock now, never frozen at the read.
    The age only grows: a state read long ago is as old as its heartbeat."""
    if not state:
        return state
    beat = ui._when(state.get("heartbeat"))
    if beat is None:
        return state
    age = wall_now - beat.timestamp()
    out = dict(state)
    old = state.get("heartbeat_age_seconds")
    out["heartbeat_age_seconds"] = round(max(age, old if isinstance(old, (int, float)) else 0.0), 3)
    return out


def first_line(knock):
    """A-5: what the watching screen says of the first-finding knock."""
    if not knock:
        return "first finding: none yet (it knocks once, whatever its severity)"
    severity = knock.get("severity")
    return _safe("first finding: %s %s (%s)" % (knock.get("rule_id"), severity, knock.get("status")))


def body_text(view):
    """The watching screen's text: findings by severity, then holes."""
    out = []
    count = sum(len(lines) for _, lines in view["findings"])
    out.append("FINDINGS: %d" % count)
    for sev, lines in view["findings"]:
        out.append("  %s (%d)" % (sev, len(lines)))
        out += ["    %s" % line for line in lines]
    out.append("")
    out.append("HOLES (A3): %d" % len(view["holes"]))
    out += ["  - %s" % h for h in view["holes"]]
    return "\n".join(out) + "\n"


# --- the watch in a worker thread ------------------------------------------------------------

class LogBuffer:
    """Where the watch writes its lines (out and err): kept for the window,
    thread-safe, bounded; tee is the terminal (or app.log) when there is
    one. A tee that fails is a hole (A-8), kept in holes, never dropped."""

    def __init__(self, tee=None, limit=LOG_MAX):
        self.lock = threading.Lock()
        self.parts = []
        self.size = 0
        self.dropped = 0
        self.tee = tee
        self.limit = limit
        self.tee_error = None
        self.holes = []

    def _hole(self, text):
        if text not in self.holes:
            self.holes.append(text)

    def write(self, text):
        text = str(text)
        with self.lock:
            self.parts.append(text)
            self.size += len(text)
            while self.size > self.limit and len(self.parts) > 1:
                gone = self.parts.pop(0)
                self.size -= len(gone)
                self.dropped += len(gone)
            if self.tee is not None:
                try:
                    self.tee.write(text)
                except Exception as exc:   # the terminal went away: the window still has the lines
                    self.tee_error = "%s: %s" % (type(exc).__name__, exc)
                    self.tee = None
                    self._hole("the log's copy to the terminal or app.log failed, and stopped: %s" % self.tee_error)
        return len(text)

    def flush(self):
        with self.lock:
            if self.tee is not None:
                try:
                    self.tee.flush()
                except Exception as exc:
                    self._hole("the log's copy to the terminal or app.log could not be flushed: %s: %s"
                               % (type(exc).__name__, exc))

    def text(self):
        with self.lock:
            head = "[%d earlier characters dropped]\n" % self.dropped if self.dropped else ""
            return head + "".join(self.parts)


class Options:
    """What `raqib app` passes to every watch it starts."""

    def __init__(self, evaluator, rules, gap_seconds, log=None, no_notify=False, port=None, refresh=None,
                 environ=None, home=None, log_project=None, every=None, catalog=None, host_reader=None,
                 host_port=None, attach_hooks=False, host_kw=None):
        self.evaluator = evaluator
        # M7.2b (ADR-0007 H-1): the window's checkbox "attach hooks to Claude Code projects", off by default; only
        # when it is ticked does a host watch write into a project (the hook settings), as --attach-hooks does.
        self.attach_hooks = bool(attach_hooks)
        self.host_kw = dict(host_kw or {})   # tests: the HostWatch's sysmon / installer / os_follow fakes
        self.suspect = ""                    # M7.4 E3: the window's "suspect unknown trees" field, empty = off
        self.every = hostmod.EVERY_DEFAULT if every is None else every   # M7.3: --every T, the host rounds
        self.catalog = catalog           # M7.3: discover's catalog (None: loaded when the host is read)
        self.host_reader = host_reader   # M7.3: tests give a fake reader; None is the live one
        self.host_port = host_port       # M7.3: the host watch's page port (None: watch --host's default)
        self.rules = rules
        self.gap_seconds = gap_seconds
        self.log = log
        self.log_project = log_project   # A-10: --log is the trace of this project only (the command line's)
        self.no_notify = no_notify
        self.port = port
        self.refresh = refresh
        self.environ = environ
        self.home = home

    def host_catalog(self):
        if self.catalog is None:
            from raqib import discover
            self.catalog = discover.load_catalog(discover.CATALOG)
        return self.catalog

    def reader(self):
        """The host's reader: the live one of `raqib watch --host` (read-only, A4), or a test's."""
        return self.host_reader or hostmod.live_reader(self.host_catalog(), 0.0)

    def log_for(self, project):
        """A-10: --log for the project named on the command line; any other
        project (one chosen by Browse) gets its default trace (None)."""
        if self.log is None or self.log_project is None:
            return None
        same = os.path.normcase(os.path.abspath(project)) == os.path.normcase(os.path.abspath(self.log_project))
        return self.log if same else None


class Session:
    """One watch of one project, run in a worker thread by watch.start /
    loop / conclude / close. phase: starting, watching, stopping, finished
    (the final report is there) or failed (watch could not start: error).
    holes: what went wrong around the watch (a knock, the worker); A3."""

    def __init__(self, project, options, log=None, starter=None, clock=None, wall=None, steps=None):
        self.project = project
        self.options = options
        self.log = log or LogBuffer()
        self.starter = starter or watch.start
        self.clock = clock or time.monotonic
        self.wall = wall or time.time      # A-2: the heartbeat's age is wall time
        self.steps = steps or watch.first_step
        self.stop_flag = watch.Stop()
        self.lock = threading.Lock()
        self.phase = "starting"
        self.error = None
        self.final_text, self.final_exit = None, None
        self.running = None
        self.holes = []
        self.last_state = None
        self.last_read = None    # monotonic time of the last good read
        self.read_note = None    # why the last read showed an older state
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._work, name="raqib-app-watch", daemon=True)
        self.thread.start()
        return self

    def stop(self, reason):
        """End the watch like Ctrl-C (finish(), the final report)."""
        with self.lock:
            if self.phase in ("starting", "watching"):
                self.phase = "stopping"
        self.stop_flag.set(reason)

    def alive(self):
        return self.thread is not None and self.thread.is_alive()

    def _hole(self, text):
        with self.lock:
            if text not in self.holes:
                self.holes.append(text)

    START_FAILED = "the watch did not start: %s"
    REFUSAL = False   # M6.4: a project watch that did not start is exit 1
    refused = False

    def _open(self):
        """watch.start for this project (raises watch.WatchError)."""
        o = self.options
        return self.starter(self.project, o.log_for(self.project), True, o.no_notify, o.port, self.log,
                            o.evaluator, o.rules, o.gap_seconds, environ=o.environ, err=self.log,
                            home=o.home, refresh=o.refresh)

    def _loop(self, running):
        return watch.loop(running, self.stop_flag, on_step=self._step)

    def _conclude(self, running, crash):
        return watch.conclude(running, crash)

    def _close(self, running):
        watch.close(running)

    def _work(self):
        try:
            try:
                running = self._open()
            except watch.WatchError as exc:
                with self.lock:
                    self.phase, self.error = "failed", self.START_FAILED % exc
                    self.refused = self.REFUSAL   # F-8: a host watch refused (C-2, D-6) is exit 2
                return
            with self.lock:
                self.running = running
                if self.phase == "starting":
                    self.phase = "watching"
            try:
                crash = self._loop(running)
                text, code = self._conclude(running, crash)
                with self.lock:   # A-8: the final report is kept before close() runs
                    self.final_text, self.final_exit = text, code
            finally:
                try:
                    self._close(running)
                except Exception as exc:   # A-8: the report and its exit stay; the failed close is a hole
                    self.log.write(traceback.format_exc())
                    self._hole("the watch did not close cleanly (page server or notifier): %s: %s"
                               % (type(exc).__name__, exc))
            with self.lock:
                self.phase = "finished"
        except Exception as exc:   # A3: a crashed worker is a hole in the window, never silence
            self.log.write(traceback.format_exc())
            with self.lock:
                self.error = "the watch worker crashed: %s: %s" % (type(exc).__name__, exc)
                if self.final_text is not None:
                    self.phase = "finished"
                elif self.phase != "finished":
                    self.phase = "failed"
                if self.error not in self.holes:
                    self.holes.append(self.error)

    def _step(self, watcher):
        """After every poll, in the worker: the first-finding knock (E3),
        the same step as `raqib watch` in a terminal (A-12)."""
        try:
            done = self.steps(self.running)
            if done is not None and done["status"] == "failed":
                self._hole("the first-finding knock was not delivered (%s); see the notifier's holes" % done["where"])
        except Exception as exc:
            self._hole("the first-finding knock failed: %s: %s" % (type(exc).__name__, exc))

    def state(self):
        """A copy of the watch's state, read under the Watch lock; the last
        one (and read_note, with how old it is) when the lock is held longer
        than LOCK_SECONDS. Either way the heartbeat's age is recomputed now
        from the wall clock (A-2)."""
        running = self.running
        if running is None:
            return None
        watcher = running.watcher
        if not watcher.lock.acquire(timeout=LOCK_SECONDS):
            ago = (self.clock() - self.last_read) if self.last_read is not None else None
            self.read_note = ("the watch held its state for more than %g s at the last read; the state shown was"
                              " read %s ago" % (LOCK_SECONDS, "%d s" % ago if ago is not None else "never"))
            return aged(self.last_state, self.wall())
        try:
            state = copy.deepcopy(watcher.state(watcher.clock()))
        except Exception as exc:
            self.read_note = "the window could not read the watch's state: %s: %s" % (type(exc).__name__, exc)
            return aged(self.last_state, self.wall())
        finally:
            watcher.lock.release()
        self.read_note = None
        self.last_state = state
        self.last_read = self.clock()
        return aged(state, self.wall())

    def snapshot(self):
        knock = getattr(self.running, "knock", None) if self.running is not None else None
        with self.lock:
            return {"phase": self.phase, "error": self.error, "final_text": self.final_text,
                    "final_exit": self.final_exit, "holes": list(self.holes) + list(self.log.holes),
                    "knock": dict(knock.knocked) if knock is not None and knock.knocked else None}


# --- the host screen (M7.3, ADR-0007 decision 5) -----------------------------------------------

HOST_COLUMNS = (("image", 22), ("pid", 8), ("named", 22), ("first seen", 25), ("acts", 5), ("source", 24),
                ("findings", 20), ("rhythm / suspicion", 24),   # M7.4 E4
                ("endpoints", 0))   # M7.2b E4: the source column and its findings by severity
NOT_CLEARANCE = "Not a clearance."


def empty_line(records, holes):
    """E1: what the host screen says when no tree is seen, with what was read."""
    return "no agent seen (%s records, %s holes). %s" % (records, holes, NOT_CLEARANCE)


def tree_kind(tree):
    """F-5 (A2): the kind word, in the order named, unknown, benign: a named
    tree is never shown as benign (an agent that takes a benign program's
    name is C-1d's evasion), so "named, benign image" says both. Then what the
    watch knows of the tree: act-root, history (there at the start, not
    knocked), new (it knocked), gone."""
    if tree.get("named"):
        word = "named, benign image" if tree.get("benign") else "named"
    else:
        word = "benign" if tree.get("benign") else "unknown"
    flags = []
    if tree.get("class") == "act-root":
        flags.append("act-root")
    if tree.get("history"):
        flags.append("history")
    if tree.get("knocked"):
        flags.append("new")
    if tree.get("present") is False:
        flags.append("gone")
    return "%s%s" % (word, " (%s)" % ", ".join(flags) if flags else "")


def host_rows(trees, first_seen=None):
    """E1: one row per tree: image, pid, named/unknown/benign, first seen,
    acts, endpoints. Never a command line, never a cited record's text, never
    the executable's path (what the window shows of a process is its name)."""
    rows = []
    for t in trees:
        if not isinstance(t, dict):
            continue
        rows.append((_safe(t.get("image") or "?"), _safe(t.get("pid")), tree_kind(t),
                     _safe(t.get("first_seen") or first_seen or "-"), _safe(t.get("acts", 0)),
                     _safe(source_word(t)), _safe(ui.severity_counts(t.get("source_findings"))),
                     _safe(ui.tree_rhythm_text(t)),   # M7.4 E4
                     _safe(", ".join(str(e) for e in t.get("endpoints") or ()) or "-")))
    return rows


def source_word(tree):
    """M7.2b E4: the source column: os / host / hooks: project P / none, or
    "-" where no source is attached yet (the look at open attaches none)."""
    src = tree.get("source")
    if src is None:
        return "-"
    if src == "hooks":
        return "hooks: project %s" % os.path.basename(str(tree.get("source_project") or "").rstrip("/\\")) \
            if tree.get("source_project") else "hooks"
    return str(src)


def host_table(rows):
    """The tree table as fixed-width text lines (a header, then the rows)."""
    def fmt(cells):
        out = []
        for (name, width), cell in zip(HOST_COLUMNS, cells):
            cell = str(cell)
            if width and len(cell) >= width:
                cell = cell[:width - 2] + ".."
            out.append(cell.ljust(width) if width else cell)
        return " ".join(out).rstrip()
    return [fmt([name for name, _ in HOST_COLUMNS])] + [fmt(r) for r in rows]


ATTACH_TEXT = "attach hooks to Claude Code projects"   # M7.2b (ADR-0007 H-1): the checkbox, off by default
SUSPECT_TEXT = "suspect unknown trees"   # M7.4 E3: the field, empty (off) by default: ollama[:M], anthropic[:M]
CODE_LEVELS = {0: "clean", 1: "alarm", 3: "incomplete"}   # F-7: C-10's exit codes; 0 green, 1 red, 3 amber


def code_level(code):
    return CODE_LEVELS.get(code, "alarm")


def dark_line(d):
    """F-1: an AGENT-DARK footprint of the look, as its own line."""
    return _safe("AGENT-DARK %s footprint %s: no tree in the round talks and acts as %s (cites %s)" % (
        d.get("agent"), d.get("path"), d.get("agent"),
        " ".join("%s:%s" % (c.get("src"), c.get("line")) for c in d.get("cites") or ()) or "-"))


def probe_view(inv, catalog, at, seconds=None, late=False, deadline=None):
    """E1: the host screen after the discover round at open (the look): its
    trees (as the host watch keys them, hostmod.trees_of), its AGENT-DARK
    footprints as their own lines, and its holes listed with their count
    (F-1). The level is never read from discover's result word: it follows
    C-10's codes (F-7): 3 (amber, incomplete) when a source was not read or
    partly read, a line could not be parsed, nothing was read, the inventory
    says it is incomplete or the reader was late - trees or not; else 1 (red)
    when a tree or an AGENT-DARK footprint is seen; 0 (green) only when it
    read records with none of these and found no tree, and then it says
    "Not a clearance.". A round that read
    nothing is NOTHING READ, never "no agent seen" (D-2). Nothing here is
    knocked: it is one look."""
    records, inv_holes = inv.get("records"), [str(h) for h in inv.get("holes") or []]
    trees = list(hostmod.trees_of(inv, catalog).values())
    dark = [d for d in inv.get("agent_dark") or [] if isinstance(d, dict)]
    unread = hostmod.unread_sources(inv)
    problems = inv.get("problems") or []
    nothing = hostmod.nothing_read(inv)
    took = " (late, %.1f s)" % seconds if late and seconds is not None else ""
    holes = []
    if late:
        holes.append("reader-late: the round at open came back after %.1f s, past its deadline %g s (2 x T)" % (
            seconds or 0, deadline or 0))
    holes += ["unread source: %s" % r for r in unread]
    holes += ["incomplete: %s" % r for r in inv.get("incomplete") or [] if str(r) not in unread]
    if problems:
        holes.append("%d line(s) could not be read (A3): %s" % (len(problems), "; ".join(
            hostmod.cite_text("%s:%s %s" % (p.get("src"), p.get("line"), p.get("reason")) if isinstance(p, dict)
                              else str(p)) for p in problems[:3])))
    holes += ["inventory: %s" % h for h in inv_holes]
    blind = bool(unread or problems or nothing or inv.get("incomplete") or late)
    code = 3 if blind else 1 if trees or dark else 0   # F-1: a partly blind look is incomplete, trees or not
    lines = [dark_line(d) for d in dark]
    counts = "%s records read, %d holes" % (records, len(holes))
    if nothing:
        word = "NOTHING READ"
        detail = "the round at open%s read no record from any source: an unread round. %s" % (took, NOT_CLEARANCE)
        lines.append("nothing read (%s records, %d holes): no agent is said seen or unseen. %s" % (
            records, len(holes), NOT_CLEARANCE))
    elif not trees:
        word = "NO AGENT SEEN" if not blind else "NO AGENT SEEN, PARTLY BLIND"
        detail = "the round at open%s: %s; one look, not a watch. %s" % (took, counts, NOT_CLEARANCE)
        lines.insert(0, empty_line(records, len(holes)))
    else:
        word = "HOST: %d TREE(S)" % len(trees)
        detail = ("the round at open%s: %s%s; %d tree(s) that talk and act, listed, not knocked"
                  " (one look; \"Watch this host\" watches it)" % (
                      took, counts, "; partly blind (see the holes)" if blind else "", len(trees)))
    if dark:
        detail += "; %d AGENT-DARK footprint(s)" % len(dark)
    return {"word": word, "level": code_level(code), "code": code, "detail": _safe(detail),
            "rows": host_rows(trees, first_seen=at), "lines": [_safe(x) for x in lines], "findings": [],
            "holes": [_safe(h) for h in holes], "badges": [], "final": None, "trees": len(trees), "new": 0,
            "dark": len(dark), "records": records, "unread": unread}


def host_finding_line(f):
    """F-4 (A5): a host finding cites (run, seq) as finding_line cites seqs."""
    where = f.get("tree") or f.get("path")
    seqs = f.get("cited_seq") or []
    beats = "".join("; talk round %s seq %s, act round %s seq %s" % (
        b.get("talk_round"), b.get("talk_seq"), b.get("round"), b.get("seq"))
        for b in f.get("beats") or () if isinstance(b, dict))   # K-7: rhythm beats carry round and seq
    return _safe("%s [%s] round %s: %s: %s [%s] cites run %s %s%s" % (
        f.get("rule_id"), f.get("severity"), f.get("round"), where, f.get("summary"), f.get("notice"),
        f.get("run"), watch.seq_text(list(seqs)), beats))


def suspicion_line(f):
    """M7.4 E4 (A2, A5): a raised suspicion on a tree, as a finding line,
    citing the seqs of the tree's source file."""
    return _safe("SUSPECT [suspicion %.2f] round %s: %s: %s [%s] by %s/%s cites %s seq %s" % (
        f.get("suspicion") or 0, f.get("round"), f.get("tree"), "; ".join(f.get("reasons") or []), f.get("notice"),
        f.get("backend"), f.get("model"), f.get("trace"), ",".join(str(x) for x in f.get("cited_seq") or [])))


def suspect_spec(text):
    """M7.4 E3: the window's "suspect unknown trees" field: empty (the
    default) is off; else a backend spec as --suspect takes it
    (ollama[:MODEL], anthropic[:MODEL], fake:FILE). (backend or None,
    error or None)."""
    text = (text or "").strip()
    if not text:
        return None, None
    try:
        return hostmod.suspect_backend(text), None
    except ValueError as exc:
        return None, str(exc)


def host_watch_view(state, extra_holes=()):
    """E2: the host screen while the host is watched, from HostWatch's state
    (mode host): the band word of ui.status (READER LATE and HOST READER
    FAILED before WATCHING, C-7), NOTHING READ for a round that read nothing
    (D-2), else WATCHING HOST; the trees, the NEW-AGENT and AGENT-DARK-LIVE
    lines, the holes."""
    word, level, detail = ui.status(state)
    age, _ = stale_age(state)
    h = state.get("host") if isinstance(state.get("host"), dict) else {}
    last = h.get("last_round") if isinstance(h.get("last_round"), dict) else {}
    if age is not None:
        word, level = "CRASHED or stuck (%d s)" % age, "alarm"
    elif word == "WATCHING":
        if last.get("nothing_read"):
            word, level = "NOTHING READ", "alarm"
            detail = "round %s at %s read no record from any source: an unread round. %s" % (
                last.get("round"), last.get("at"), NOT_CLEARANCE)
        else:
            word = "WATCHING HOST"
            if level == "clean":   # F-7: every green state says it
                detail = "%s. %s" % (detail, NOT_CLEARANCE)
    trees = [t for t in h.get("trees") or [] if isinstance(t, dict)]
    lines = []
    if not trees:
        if last and not last.get("error") and not last.get("nothing_read"):
            lines.append(empty_line(last.get("records"), last.get("holes")))
        elif not last:
            lines.append("no round has given an inventory yet")
    holes = [hole_line(x) for x in state.get("holes") or [] if isinstance(x, dict)] + [_safe(x) for x in extra_holes]
    findings = [host_finding_line(f) for f in h.get("findings") or [] if isinstance(f, dict)]
    findings += [suspicion_line(f) for f in h.get("suspicions") or [] if isinstance(f, dict)]   # M7.4 E4
    return {"word": word, "level": level, "detail": _safe(detail), "rows": host_rows(trees),
            "lines": lines, "findings": findings, "holes": holes,
            "badges": [(lv, _safe(text)) for lv, text in ui.host_band(state)], "final": None,
            "trees": h.get("now") or 0, "new": h.get("new") or 0, "url": state.get("url") or "-"}


def host_body(view):
    """The host screen's text: the table (or the empty line), the findings,
    the holes; or the final report when the host watch ended."""
    if view.get("final"):
        return view["final"] + "".join("hole: %s\n" % x for x in view["holes"])
    out = host_table(view["rows"]) if view["rows"] else []
    out += view["lines"]
    out += ["", "FINDINGS: %d" % len(view["findings"])] + ["  %s" % f for f in view["findings"]]
    out += ["", "HOLES (A3): %d" % len(view["holes"])] + ["  - %s" % x for x in view["holes"]]
    return "\n".join(out) + "\n"


def checks_state(lines):
    """("Checks: ..." button text, open?): the doctor lines fold under a
    toggle, open when any is MISSING (E1)."""
    if lines is None:
        return "Checks: running...", False
    missing = sum(1 for word, _, _ in lines if word == "MISSING")
    unsure = sum(1 for word, _, _ in lines if word == "UNSURE")
    if missing:
        return "Checks: %d MISSING" % missing, True
    return "Checks: %s" % ("%d UNSURE" % unsure if unsure else "all OK"), False


LOOK_NAME = "look.json"


class HostProbe:
    """E1: one discover round at open (the look), the host watch's reader in
    a worker thread (hostmod.Worker), with the watch's deadline (2 x T). It
    knocks nothing and is not round 1 (history begins at "Watch this host",
    F-10). view(now) is the host screen's state of it: reading, late (a hole
    in the band, kept when the reader comes back late, F-3), failed, or the
    trees. F-10: the look is written to ~/.raqib/host/look.json (the latest
    only: its word, level, trees, dark footprints, holes and the reader's
    timing), when it comes back and when it is first seen late."""

    def __init__(self, reader, catalog, deadline, clock=None, wall=None, home=None):
        self.reader = reader
        self.catalog = catalog
        self.deadline = deadline
        self.clock = clock or time.monotonic
        self.wall = wall or time.time
        self.home = home
        self.worker = None
        self.began = None
        self.at = None
        self.seen_late = False   # F-3: the look was READER LATE at some view; that hole stays when it comes back
        self.written = None      # F-10: what look.json holds now ("late", "done"), or None
        self.write_error = None

    def start(self):
        import datetime
        self.began = self.clock()
        self.at = hostmod.iso(datetime.datetime.fromtimestamp(self.wall(), datetime.timezone.utc))
        self.worker = hostmod.Worker(self.reader)
        return self

    def done(self):
        return self.worker is not None and self.worker.done()

    def path(self):
        return os.path.join(hostmod.host_dir(self.home), LOOK_NAME)

    def view(self, now=None):
        now = self.clock() if now is None else now
        view = self._view(now)
        if self.home is not None:
            stage = "done" if self.done() else "late" if view["word"] == "READER LATE" else None
            if stage is not None and stage != self.written:
                self._write(view, now, stage)
        if self.write_error:
            view = dict(view, holes=view["holes"] + [self.write_error])
        return view

    def _write(self, view, now, stage):
        out = self.worker.outcome if self.worker is not None else None
        record = {"raqib_look": 1, "at": self.at, "stage": stage, "deadline_seconds": self.deadline,
                  "reader_seconds": round(out[2], 3) if out else None,
                  "reader_out_seconds": None if out else round(now - self.began, 3),
                  "word": view["word"], "level": view["level"], "code": view.get("code"), "detail": view["detail"],
                  "rows": [list(r) for r in view["rows"]], "lines": view["lines"], "holes": view["holes"],
                  "records": view.get("records"), "trees": view.get("trees"), "dark": view.get("dark"),
                  "note": "the first look of raqib app: not a round of the host watch; history begins at"
                          " \"Watch this host\" (ADR-0007 F-10)"}
        try:
            os.makedirs(os.path.dirname(self.path()), exist_ok=True)
            hostmod.write_json(self.path(), record)
            self.written, self.write_error = stage, None
        except OSError as exc:
            self.write_error = "look.json was not written (%s): %s" % (self.path(), exc.strerror or exc)
            self.written = stage

    def _view(self, now):
        out = self.worker.outcome if self.worker is not None else None
        late = now - self.began >= self.deadline if self.began is not None else False
        if out is None:
            if late:
                self.seen_late = True
                return dict(_empty_view(), word="READER LATE", level="incomplete", code=3, detail=(
                    "the reader of the round at open is not back after %d s (deadline %g s): a hole; the host is not"
                    " read yet" % (now - self.began, self.deadline)),
                    holes=["reader-late: the round at open was not back within %g s (2 x T)" % self.deadline])
            return dict(_empty_view(), word="READING HOST", level="incomplete",
                        detail="reading the host... (one discover round, read-only; deadline %g s)" % self.deadline)
        inv, error, seconds = out
        if error:
            return dict(_empty_view(), word="HOST READER FAILED", level="incomplete", code=3,
                        detail="the reader of the round at open failed: %s" % _safe(error),
                        holes=["reader-failed: the round at open: %s" % _safe(error)])
        try:
            return probe_view(inv, self.catalog, self.at, seconds, late=seconds > self.deadline or self.seen_late,
                              deadline=self.deadline)
        except Exception as exc:   # A3: an inventory the window cannot show says so
            return dict(_empty_view(), word="HOST READER FAILED", level="incomplete", code=3,
                        detail="the inventory of the round at open could not be shown: %s: %s" % (
                            type(exc).__name__, _safe(exc)),
                        holes=["the inventory of the round at open could not be shown: %s" % type(exc).__name__])


def _empty_view():
    return {"word": "", "level": "incomplete", "code": None, "detail": "", "rows": [], "lines": [], "findings": [],
            "holes": [], "badges": [], "final": None, "trees": 0, "new": 0}


class HostSession(Session):
    """E2: the host watch of `raqib watch --host` - host.start, host.loop
    with this Stop, host.conclude, host.close - in a worker thread, a
    sibling of the project Session. The knocks are HostWatch's own, through
    its Notifier (C-5: each tree under its own rate-limit id); the page is
    served, not opened. A second host watch on this home is refused by
    HostWatch (C-2, D-6): the refusal is this session's error, shown as a
    hole line, never a crash."""

    START_FAILED = "the host watch did not start: %s"
    REFUSAL = True    # F-8: the start was refused (one host watch per home), exit 2

    def __init__(self, options, log=None, starter=None, clock=None, wall=None, wait_for=None):
        super().__init__(hostmod.HOST, options, log=log, starter=starter or hostmod.start, clock=clock, wall=wall,
                         steps=lambda running: None)
        self.wait_for = wait_for   # F-3: the look's reader thread; round 1's reader waits for it

    def reader(self):
        """The watch's reader. F-3: never two readers at once - the first
        round's reader waits for the look's reader to be back (HostWatch's
        own deadline still holds: a look that never returns makes round 1
        late, a hole)."""
        real = self.options.reader()
        look = self.wait_for

        def read():
            if look is not None and look.is_alive():
                self.log.write("raqib app: round 1 waits for the reader of the round at open (never two readers)\n")
                look.join()
            return real()
        return read

    def _open(self):
        o = self.options
        kw = dict(o.host_kw)
        backend, error = suspect_spec(getattr(o, "suspect", ""))   # M7.4 E3: the field's word for this watch
        if error:
            raise watch.WatchError("%s: %s" % (SUSPECT_TEXT, error))
        if backend is not None:
            kw["suspect"] = backend
        return self.starter(o.host_catalog(), o.rules, every=o.every, no_open=True, no_notify=o.no_notify,
                            port=o.host_port, out=self.log, err=self.log, environ=o.environ, home=o.home,
                            refresh=o.refresh, reader=self.reader(), attach_hooks=o.attach_hooks, **kw)

    def _loop(self, running):
        return hostmod.loop(running, self.stop_flag)

    def _conclude(self, running, crash):
        return hostmod.conclude(running, crash)

    def _close(self, running):
        hostmod.close(running)


class Controller:
    """What a close, Stop, Start or a tray action does, without Tk. Tray
    actions arrive from the tray thread through a queue, read by drain()."""

    def __init__(self, options, tray=None, make_session=None, tee=None, clock=None, opener=None, make_host=None):
        self.options = options
        self.tray = tray
        # each watch has its own LogBuffer; tee is the terminal (or app.log) when there is one
        self.make_session = make_session or (lambda project: Session(project, options, log=LogBuffer(tee=tee)))
        # M7.3: the host watch, a sibling of the project watch; both may run at once
        self.make_host = make_host or (lambda: HostSession(options, log=LogBuffer(tee=tee), wait_for=self.look_thread()))
        self.session = None
        self.host = None
        self.tip = traymod.TIP   # what the tray's tooltip says now (M7.3: "Raqib: N trees, K new")
        self.actions = queue.Queue()
        self.quitting = False
        self.quit_at = None     # A-3: when Quit was asked (monotonic)
        self.clock = clock or time.monotonic
        self.opener = opener or watch.open_page
        self.tee = tee
        self.page_note = None   # what the last "Open page" said (A-13)
        self.notes = []   # by design, not holes: "no tray on this platform"
        self.probe = None        # M7.3 E1: the discover round at open (HostProbe)
        self.probe_error = None
        self.host_note = None    # why "Watch this host" did not start
        self.past = []           # F-8: the watches a new Start replaced; their reports and exits are kept
        self.reported = set()    # F-8: id() of the sessions whose final report was appended to the log
        self.look_logged = set() # F-3: the look's holes already written to the log
        self.holes = []   # the window's own holes: a tray that failed, a tick that failed (A-8)

    # tray
    def start_tray(self):
        if self.tray is None:
            self.tray = traymod.Tray(self.actions.put)
        try:
            why = self.tray.start()
        except Exception as exc:   # never into the window (A3)
            why = "the tray failed to start: %s: %s" % (type(exc).__name__, exc)
            self.tray = None
            self.hole("tray: %s" % why)
            return why
        if why is None:
            return None
        if traymod.unsupported(getattr(self.tray, "platform", None)) == why:
            self.notes.append("tray: %s" % why)
            self.tray = None
        else:
            self.hole("tray: %s" % why)
            # A-6: a tray that timed out is kept, so its late thread is cancelled, stopped and its holes shown
            if not getattr(self.tray, "cancelled", False):
                self.tray = None
        return why

    def tray_up(self):
        return self.tray is not None and bool(getattr(self.tray, "running", False))

    def tray_holes(self):
        """The tray's holes, among them "tray ended: <reason>" (A-6) and a
        failed re-add (A-1); the tray's own words, each once."""
        return ["tray: %s" % h for h in (getattr(self.tray, "holes", []) if self.tray is not None else [])]

    def hole(self, text):
        """The window's own hole, kept once and never overwritten (A-8)."""
        if text not in self.holes:
            self.holes.append(text)

    def log_line(self, text):
        """A line of the window's own (A-4): into the watch's log, when a
        watch ran, and to the terminal or app.log."""
        line = "raqib app: %s\n" % _safe(text)
        session = self.session
        log = getattr(session, "log", None)
        if log is not None:
            log.write(line)   # its tee is self.tee
            return
        if self.tee is not None:
            try:
                self.tee.write(line)
                self.tee.flush()
            except Exception as exc:
                self.hole("the window's log line was not written: %s: %s" % (type(exc).__name__, exc))

    def callback_error(self, kind, value, tb):
        """Tk's report_callback_exception (A-4): an exception in a button,
        a close or an after() is a hole and a log line, never lost."""
        text = "a window callback failed: %s: %s" % (getattr(kind, "__name__", kind), value)
        self.hole(text)
        self.log_line(text)
        self.log_line("".join(traceback.format_exception(kind, value, tb)).rstrip("\n"))

    def sessions(self):
        """The watches running or shown in this window: the project's and the host's."""
        return [x for x in (self.session, self.host) if x is not None]

    def all_sessions(self):
        """F-8: every watch this window started, those a new Start replaced first."""
        return self.past + self.sessions()

    def look_thread(self):
        """F-3: the look's reader thread, when it is still out."""
        worker = getattr(self.probe, "worker", None)
        thread = getattr(worker, "thread", None)
        return thread if thread is not None and thread.is_alive() else None

    def look_holes(self):
        """F-3: the look's holes stand (footer, log) until the host watch's
        first round replaces them; each is written to the log once."""
        if self.probe is None or self.host_first_round():
            return []
        holes = ["round at open: %s" % h for h in self.probe.view()["holes"]]
        for h in holes:
            if h not in self.look_logged:
                self.look_logged.add(h)
                self.log_line(h)
        return holes

    def host_first_round(self):
        """True once the host watch has a round of its own (a reader back, or failed)."""
        session = self.host
        if session is None or getattr(session, "running", None) is None:
            return False
        state = session.state() or {}
        return bool((state.get("host") or {}).get("last_round"))

    def report_finished(self):
        """F-8: each finished watch's final report is appended to the log
        (the terminal or app.log) once, never replaced by a later watch."""
        for session in self.all_sessions():
            snap = session.snapshot()
            if snap.get("final_text") and id(session) not in self.reported:
                self.reported.add(id(session))
                if self.tee is not None:
                    try:
                        self.tee.write("\n" + snap["final_text"])
                        self.tee.flush()
                    except Exception as exc:
                        self.hole("a final report was not written to the log: %s: %s" % (type(exc).__name__, exc))

    def finish_wait(self, err=None, rounds=None):
        """A-3: the process does not exit while a watch has not
        concluded: wait for the workers JOIN_SECONDS at a time, saying so
        each time; nothing is killed. True when they ended (rounds: a bound
        for tests; None waits for as long as it takes)."""
        n = 0
        while True:
            thread = next((t for t in (getattr(x, "thread", None) for x in self.sessions())
                           if t is not None and t.is_alive()), None)
            if thread is None:
                break
            if rounds is not None and n >= rounds:
                return False
            n += 1
            text = "the watch did not end in %g s: still waiting for its final report (nothing is killed)" % (
                JOIN_SECONDS * n)
            self.log_line(text)
            if err is not None:
                try:
                    err.write("raqib app: %s\n" % text)
                except Exception:
                    pass
            thread.join(JOIN_SECONDS)
        return True

    # the watch
    @staticmethod
    def _live(session):
        return session is not None and session.snapshot()["phase"] in ("starting", "watching", "stopping")

    def project_watching(self):
        return self._live(self.session)

    def host_watching(self):
        return self._live(self.host)

    def watching(self):
        """Any watch of this window runs: the project's or the host's."""
        return self.project_watching() or self.host_watching()

    def start(self, project):
        """A new watch of project; None, or why not. F-2: a refusal names the
        running watch."""
        if self.project_watching():
            return "a watch is running: the project watch of %s; stop it first" % _safe(self.session.project)
        if not project or not os.path.isdir(project):
            return "not a directory: %s" % (project or "(empty)")
        if self.session is not None:
            self.past.append(self.session)    # F-8: its report and exit are kept
        self.session = self.make_session(project).start()
        return None

    def running_text(self):
        """F-2: the header's line: which watches run now."""
        names = (["host watch"] if self.host_watching() else []) + (
            ["project watch of %s" % _safe(self.session.project)] if self.project_watching() else [])
        return "running: %s" % (", ".join(names) if names else "none")

    def project_screen(self):
        """F-2: where "Project" leads: the project watch's screen while it
        runs, else the project field (M6.4's first screen)."""
        return "watching" if self.project_watching() else "first"

    def start_host(self):
        """E2: a new watch of this host (HostSession); None, or why not. A
        second host watch on this home is refused by HostWatch itself (C-2):
        that refusal is the session's error, shown as a hole line."""
        if self.host_watching():
            return "a watch is running: the host watch; stop it first"
        if self.host is not None:
            self.past.append(self.host)       # F-8: its report and exit are kept
        self.host = self.make_host().start()
        return None

    def stop(self, reason):
        """Every watch of the window ends (the tray's Stop, a close)."""
        for session in self.sessions():
            session.stop(reason)

    def stop_project(self, reason):
        if self.session is not None:
            self.session.stop(reason)

    def stop_host(self, reason):
        if self.host is not None:
            self.host.stop(reason)

    def host_tip(self, trees=None, new=None):
        """The tray's tooltip: "Raqib: N trees, K new" while the host is
        watched (from the host view), else "Raqib". Changed only when the
        text changes; a tray that cannot take it keeps a hole of its own."""
        text = traymod.tip_text(trees, new) if self.host_watching() and trees is not None else traymod.TIP
        if text == self.tip:
            return text
        self.tip = text
        setter = getattr(self.tray, "set_tip", None) if self.tray is not None else None
        if setter is not None:
            try:
                setter(text)
            except Exception as exc:
                self.hole("tray: the tooltip could not be set: %s: %s" % (type(exc).__name__, exc))
        return text

    def close_request(self):
        """The window's close button: "hide" (to the tray, while watching),
        "stop" (the watch ends, the final report stays on screen) or "quit"."""
        if self.watching():
            if self.tray_up():
                return "hide"
            self.stop("window closed")
            return "stop"
        return "quit"

    def start_probe(self, make=None):
        """E1: the discover round at open, in a thread (HostProbe over the
        host watch's reader, deadline 2 x T). A probe that cannot start is a
        hole and the host screen says HOST NOT READ, never a crash."""
        try:
            if make is not None:
                self.probe = make()
            elif self.options is None:
                self.probe_error = "the host is not read: this window was given no reader"
                return None
            else:
                o = self.options
                # F-10: the look is written under the window's home (the user's, as every watch's ~/.raqib)
                self.probe = HostProbe(o.reader(), o.host_catalog(), hostmod.DEADLINE_FACTOR * o.every,
                                       home=o.home or os.path.expanduser("~"))
            self.probe.start()
        except Exception as exc:
            self.probe = None
            self.probe_error = "the host could not be read at open: %s: %s" % (type(exc).__name__, _safe(exc))
            self.hole(self.probe_error)
        return self.probe

    def host_view(self, now=None):
        """What the host screen shows now: the round at open (HostProbe), or
        the host watch (HostSession): starting, watching, refused (a hole
        line), finished (its final report). Plain Python; Window draws it."""
        if self.probe is not None:
            probe = self.probe.view(now)
        else:
            probe = dict(_empty_view(), word="HOST NOT READ", level="alarm",
                         detail=self.probe_error or "the round at open did not start")
        session = self.host
        if session is None:
            if self.host_note:
                probe = dict(probe, holes=probe["holes"] + [self.host_note])
            return probe
        look = [] if self.host_first_round() else ["round at open: %s" % h for h in probe["holes"]]   # F-3
        snap = session.snapshot()
        extra = []
        for text in list(snap.get("holes") or []) + ([session.read_note] if getattr(session, "read_note", None) else []):
            if text not in extra:
                extra.append(text)
        if snap["phase"] == "failed" and snap.get("final_text") is None:
            error = snap.get("error") or "the host watch did not start"
            holes = probe["holes"] + [h for h in [error] + extra if h not in probe["holes"]]
            return dict(probe, word="HOST NOT WATCHED", level="alarm", detail=_safe(error), holes=[_safe(h) for h in holes])
        if snap["phase"] == "finished":
            code = snap.get("final_exit")   # F-7: C-10's code gives the colour, as at open
            return dict(_empty_view(), word="HOST WATCH FINISHED", level=code_level(code), code=code,
                        detail="the host watch ended; its final report is below (exit %s)%s" % (
                            code, ". " + NOT_CLEARANCE if code == 0 else ""),
                        final=snap.get("final_text") or "", holes=[_safe(h) for h in extra])
        state = session.state()
        if state is None:
            every = getattr(self.options, "every", hostmod.EVERY_DEFAULT)
            return dict(probe, word="STARTING HOST WATCH", level="incomplete",
                        detail="starting the host watch of `raqib watch --host` (a round every %g s)" % every)
        view = host_watch_view(state, look + extra)
        if snap["phase"] == "stopping":
            view["word"] += " (stopping)"
        return view

    def open_page(self, which="project"):
        """A-13 (Q-6), F-11: the "Open page" button of the project screen or
        of the host screen; the same opener as `raqib watch` (watch.open_page),
        never under CI. None, or why not."""
        session = self.host if which == "host" else self.session
        state = session.state() if session is not None else None
        url = (state or {}).get("url")
        if not url:
            return "no page yet: the watch has not started"
        environ = os.environ if self.options is None or self.options.environ is None else self.options.environ
        if environ.get("CI"):
            return "CI is set: the page is not opened"
        try:
            why = self.opener(url, environ)
        except Exception as exc:
            why = "%s: %s" % (type(exc).__name__, exc)
        return "the page was not opened (%s); open %s by hand" % (why, url) if why else None

    def drain(self):
        """The tray's actions since the last call, done: ["show" | "stop" | "quit"]."""
        done = []
        while True:
            try:
                action = self.actions.get_nowait()
            except queue.Empty:
                return done
            if action == "stop":
                self.stop("Stop in the tray menu")
            elif action == "quit":
                self.quit("Quit in the tray menu")
            done.append(action)

    def quit(self, reason):
        if not self.quitting:
            self.quitting, self.quit_at = True, self.clock()
        self.stop(reason)

    def worker_alive(self):
        for session in self.sessions():
            alive = getattr(session, "alive", None)
            if bool(alive()) if alive is not None else self._live(session):
                return True
        return False

    def can_exit(self):
        """Quit asked and the watch concluded (its worker ended). A-3: never
        with a watch that has not concluded."""
        return self.quitting and not self.watching() and not self.worker_alive()

    def quit_overdue(self):
        """A-3: Quit asked JOIN_SECONDS ago and the worker is still alive:
        the quit is given up (the window comes back) with the hole "the
        watch did not end in N s"; True once, then Quit can be asked again.
        Nothing is killed."""
        if not self.quitting or self.can_exit() or self.clock() - self.quit_at < JOIN_SECONDS:
            return False
        self.quitting, self.quit_at = False, None
        self.hole("the watch did not end in %g s after Quit: the window stays; Quit again, or see the log"
                  % JOIN_SECONDS)
        return True

    def shutdown(self):
        """The window is going: the watch ends, the worker is waited for
        (JOIN_SECONDS), the tray goes. True when no worker is left alive."""
        done = True
        for session in self.sessions():
            session.stop("the window was closed")
        for session in self.sessions():
            if session.thread is not None:
                session.thread.join(JOIN_SECONDS)
                done = done and not session.thread.is_alive()
        self._tray_down()
        return done

    def _tray_down(self):
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass

    def exit_code(self):
        """The exit of the window: every watch's report (the project's as in
        M6.4, the host's C-10: 0, 1, 3; a refused host watch 2, F-8), the
        replaced ones too; an alarm (1) first, then any other non-zero code;
        0 when none ran."""
        codes = []
        for session in self.all_sessions():
            snap = session.snapshot()
            if snap["final_exit"] is not None:
                codes.append(snap["final_exit"])
            elif snap["phase"] == "failed":   # F-8: a refused host watch is 2 (a refusal), not a finding
                codes.append(2 if getattr(session, "refused", False) else 1)
            else:
                codes.append(0)
        if 1 in codes:
            return 1
        return next((c for c in codes if c), 0)


# --- the doctor in a thread ---------------------------------------------------------------

class DoctorJob:
    """doctor.checks() for one project in a thread; result() is None until done."""

    def __init__(self, project, environ=None, home=None, checks=None):
        from raqib import doctor
        self.project = project
        self.checks = checks or (lambda p: doctor.checks(p, environ=environ, home=home))
        self._result = None
        self.thread = threading.Thread(target=self._run, name="raqib-app-doctor", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        try:
            project, lines, notes = self.checks(self.project)
            from raqib import doctor
            text, _ = doctor.summary(lines)
            self._result = (project, doctor_lines(lines, notes), "raqib doctor: %s" % text)
        except Exception as exc:   # A3: a doctor that failed says so
            self._result = (self.project, [("MISSING", "alarm", "doctor failed: %s: %s" % (type(exc).__name__, exc))],
                            "raqib doctor: it could not run")

    def result(self):
        return self._result


# --- the window (Tk) ----------------------------------------------------------------------

def log_view(text, limit=None):
    """The Log pane's text: the last `limit` characters of the watch's
    lines (bounded, A-5), with a line saying how much is not shown."""
    limit = LOG_VIEW_MAX if limit is None else limit
    if len(text) <= limit:
        return text
    return "[%d earlier characters not shown here]\n%s" % (len(text) - limit, text[-limit:])


class Window:
    """The Tk window over a Controller. Only this class calls Tk."""

    def __init__(self, tk, root, controller, project, environ=None, home=None, doctor_job=None, probe=None):
        self.tk = tk
        self.root = root
        self.c = controller
        self.environ = environ
        self.home = home
        self.make_doctor = doctor_job or (lambda p: DoctorJob(p, environ=environ, home=home))
        self.doctor = None
        self.screen = None
        self.shown = {}
        self.after_id = None
        self.closed = False
        root.title(TITLE)
        root.geometry("960x660")
        root.minsize(640, 420)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = controller.callback_error   # A-4: a hole and a log line
        self.log_open = False
        self.host_log_open = False
        self.checks_open = False
        self.doctor_band = None
        self.refusal = None
        self._build(project)
        self.show_host()                  # M7.3: the first screen is the host
        controller.start_probe(probe)     # E1: one discover round at open, in a thread
        self.check()
        self.after_id = root.after(TICK_MS, self.tick)

    def _text(self, parent, height):
        frame = self.tk.Frame(parent)
        text = self.tk.Text(frame, height=height, wrap="word", font=("Courier", 10))
        bar = self.tk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=bar.set, state="disabled")
        bar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        for level, color in LEVEL_COLORS.items():
            text.tag_configure(level, foreground=color)
        return frame, text

    def _build(self, project):
        tk = self.tk
        self.band = tk.Label(self.root, text="", anchor="w", font=("TkDefaultFont", 14, "bold"))
        self.band.pack(fill="x", padx=10, pady=(10, 0))
        self.detail = tk.Label(self.root, text="", anchor="w", justify="left", wraplength=920)
        self.detail.pack(fill="x", padx=10)
        # F-2: the header: "Host" and "Project" switch between the two screens at any time, watches running
        head = tk.Frame(self.root)
        self.host_tab = tk.Button(head, text="Host", command=self.show_host)
        self.host_tab.pack(side="left")
        self.project_tab = tk.Button(head, text="Project", command=self.show_project)
        self.project_tab.pack(side="left", padx=6)
        self.head_note = tk.Label(head, text="", anchor="w")
        self.head_note.pack(side="left", fill="x", expand=True)
        head.pack(fill="x", padx=10, pady=(6, 0))
        # the host screen (M7.3): the first one
        self.hostf = tk.Frame(self.root)
        row = tk.Frame(self.hostf)
        self.host_button = tk.Button(row, text="Watch this host", command=self.host_toggle)
        self.host_button.pack(side="left")
        tk.Button(row, text="Watch a project", command=self.show_project).pack(side="left", padx=6)
        self.checks_button = tk.Button(row, text=checks_state(None)[0], command=self.toggle_checks)
        self.checks_button.pack(side="left")
        # M7.2b (ADR-0007 H-1): off by default; read when "Watch this host" starts a watch
        # options may be None (a Controller without Options, as the M6.4 Tk tests build it): off, as by default
        self.attach_var = tk.BooleanVar(value=bool(getattr(self.c.options, "attach_hooks", False)))
        self.attach_box = tk.Checkbutton(row, text=ATTACH_TEXT, variable=self.attach_var)
        self.attach_box.pack(side="left", padx=6)
        # M7.4 E3: "suspect unknown trees", empty (off) by default; read when "Watch this host" starts a watch
        tk.Label(row, text=SUSPECT_TEXT).pack(side="left")
        self.suspect_var = tk.StringVar(value=str(getattr(self.c.options, "suspect", "") or ""))
        tk.Entry(row, textvariable=self.suspect_var, width=16).pack(side="left", padx=(2, 6))
        self.host_url = tk.StringVar(value="-")
        tk.Entry(row, textvariable=self.host_url, state="readonly").pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(row, text="Open page", command=self.open_host_page).pack(side="left", padx=(0, 6))   # F-11
        self.host_log_button = tk.Button(row, text="Log", command=self.toggle_host_log)                # F-6
        self.host_log_button.pack(side="left")
        row.pack(fill="x", pady=6)
        self.host_badges = tk.Label(self.hostf, text="", anchor="w", justify="left", wraplength=920)
        self.host_badges.pack(fill="x")
        self.checks_frame, self.checks_text = self._text(self.hostf, 8)   # folded under "Checks"
        frame, self.host_text = self._text(self.hostf, 20)
        frame.pack(fill="both", expand=True)
        self.host_log_frame, self.host_log_text = self._text(self.hostf, 10)   # F-6: shown by its Log button
        # the project screen (M6.4's first screen)
        self.first = tk.Frame(self.root)
        row = tk.Frame(self.first)
        tk.Label(row, text="Project").pack(side="left")
        self.project = tk.StringVar(value=project)
        tk.Entry(row, textvariable=self.project).pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(row, text="Browse...", command=self.browse).pack(side="left")
        tk.Button(row, text="Check again", command=self.check).pack(side="left", padx=6)
        self.start_button = tk.Button(row, text="Start", command=self.start)
        self.start_button.pack(side="left")
        row.pack(fill="x", pady=6)
        frame, self.doctor_text = self._text(self.first, 14)
        frame.pack(fill="both", expand=True)
        # watching screen
        self.watching = tk.Frame(self.root)
        row = tk.Frame(self.watching)
        tk.Label(row, text="Page (read-only)").pack(side="left")
        self.url = tk.StringVar(value="-")
        tk.Entry(row, textvariable=self.url, state="readonly").pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(row, text="Open page", command=self.open_page).pack(side="left", padx=(0, 6))   # A-13
        self.log_button = tk.Button(row, text="Log", command=self.toggle_log)                    # A-5
        self.log_button.pack(side="left", padx=(0, 6))
        self.stop_button = tk.Button(row, text="Stop", command=self.stop)
        self.stop_button.pack(side="left")
        self.back_button = tk.Button(row, text="Back", command=self.show_first)
        row.pack(fill="x", pady=6)
        self.knock_label = tk.Label(self.watching, text=first_line(None), anchor="w")   # A-5
        self.knock_label.pack(fill="x")
        self.badges = tk.Label(self.watching, text="", anchor="w", justify="left", wraplength=920)
        self.badges.pack(fill="x")
        frame, self.body = self._text(self.watching, 18)
        frame.pack(fill="both", expand=True)
        self.log_frame, self.log_text = self._text(self.watching, 10)   # A-5: shown by the Log button
        # the window's own notes and holes, on both screens
        self.foot = tk.Label(self.root, text="", anchor="w", justify="left", wraplength=920)
        self.foot.pack(side="bottom", fill="x", padx=10, pady=(0, 8))

    # screens
    def _show(self, name):
        if self.screen == name:
            return False
        for key, frame in (("host", self.hostf), ("first", self.first), ("watching", self.watching)):
            if key != name:
                frame.pack_forget()
        {"host": self.hostf, "first": self.first, "watching": self.watching}[name].pack(
            fill="both", expand=True, padx=10)
        self.screen = name
        return True

    def show_host(self):
        self._show("host")

    def show_first(self):
        """The project screen (M6.4's first screen, "Watch a project")."""
        if self._show("first"):
            self.shown.pop("body", None)
            if self.doctor_band is not None:
                self._band(*self.doctor_band)

    def show_watching(self):
        self._show("watching")

    def show_project(self):
        """F-2: "Project" (and "Watch a project"): the running project watch's
        screen, else the project field."""
        if self.c.project_screen() == "watching":
            self.show_watching()
        else:
            self.show_first()

    def open_host_page(self):
        """F-11: the host watch's page, by the person's click (never under CI)."""
        self.c.page_note = self.c.open_page("host")

    def toggle_host_log(self):
        """F-6: the host watch's own lines, at any time (bounded), as A-5."""
        self.host_log_open = not self.host_log_open
        if self.host_log_open:
            self.host_log_frame.pack(fill="both", expand=True, pady=(6, 0))
            self.host_log_button.configure(text="Hide log")
        else:
            self.host_log_frame.pack_forget()
            self.host_log_button.configure(text="Log")
            self.shown.pop("host_log", None)

    def toggle_checks(self):
        """E1: the doctor lines, folded under "Checks"."""
        self.checks_open = not self.checks_open
        if self.checks_open:
            self.checks_frame.pack(fill="x", pady=(0, 6), before=self.host_text.master)
        else:
            self.checks_frame.pack_forget()

    def host_toggle(self):
        """E2: "Watch this host" starts the host watch; while it runs the
        button is its Stop, which ends it with its final report."""
        if self.c.host_watching():
            self.c.stop_host("Stop in the window")
            return
        if self.c.options is not None:   # H-1: the box's word for this watch
            self.c.options.attach_hooks = bool(self.attach_var.get())
            self.c.options.suspect = str(self.suspect_var.get() or "").strip()   # M7.4 E3: empty is off
        self.c.host_note = self.c.start_host()
        self.show_host()

    def _set(self, widget, key, content, tags=None):
        """Replace a Text widget's content when it changed (no flicker, the scroll kept)."""
        if self.shown.get(key) == (content, tags):
            return
        self.shown[key] = (content, tags)
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if tags is None:
            widget.insert("end", content)
        else:
            for line, tag in tags:
                widget.insert("end", line + "\n", (tag,) if tag else ())
        widget.configure(state="disabled")

    def _band(self, word, level, detail):
        self.band.configure(text=word, fg=LEVEL_COLORS.get(level, LEVEL_COLORS["incomplete"]))
        self.detail.configure(text=detail)

    # actions
    def browse(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(parent=self.root, initialdir=self.project.get() or os.getcwd(),
                                         title="The project the agent works in")
        if chosen:
            self.project.set(os.path.normpath(chosen))
            self.check()

    def check(self):
        self.doctor = self.make_doctor(self.project.get()).start()
        self.doctor_band = ("CHECKING", "incomplete", "raqib doctor is running for %s" % _safe(self.project.get()))
        if self.screen == "first":
            self._band(*self.doctor_band)

    def start(self):
        why = self.c.start(self.project.get())
        if why:
            if self.c.project_watching():   # F-2: the refusal names the running watch and goes to its screen
                self.show_watching()
            self._band("NOT STARTED", "alarm", why)
            self.refusal = why
            return
        self.refusal = None
        self.show_watching()

    def stop(self):
        self.c.stop_project("Stop in the window")

    def open_page(self):
        self.c.page_note = self.c.open_page()

    def toggle_log(self):
        """A-5: the watch's own lines, at any time (bounded)."""
        self.log_open = not self.log_open
        if self.log_open:
            self.log_frame.pack(fill="both", expand=True, pady=(6, 0))
            self.log_button.configure(text="Hide log")
        else:
            self.log_frame.pack_forget()
            self.log_button.configure(text="Log")
            self.shown.pop("log", None)

    def on_close(self):
        action = self.c.close_request()
        if action == "hide":
            self.root.withdraw()
        elif action == "quit":
            self.destroy()
        elif self.screen != "host" and self.c.session is not None:
            self.show_watching()   # the project watch's final report stays on screen
        else:
            self.show_host()       # the host watch's final report stays on screen

    def destroy(self):
        if self.closed:
            return
        self.closed = True
        if self.after_id is not None:
            try:
                self.root.after_cancel(self.after_id)
            except Exception:
                pass
        self.c.shutdown()
        self.root.destroy()

    # the after() cycle
    def tick(self):
        self.after_id = None
        try:
            self._tick()
        except Exception as exc:   # A3, A-8: the window says what broke, keeps it, and keeps going
            self.c.hole("the window failed to update: %s: %s" % (type(exc).__name__, exc))
            self._foot()
        if self.closed:
            return
        if self.c.can_exit():
            self.destroy()
            return
        if self.c.quit_overdue():   # A-3: the watch did not end: the window comes back, nothing is killed
            self.root.deiconify()
            self.root.lift()
            self._foot()
        self.after_id = self.root.after(TICK_MS, self.tick)

    def _foot(self):
        holes = self.c.holes + self.c.tray_holes() + self.c.look_holes()   # F-3: the look's, until round 1
        notes = list(self.c.notes) + (["page: %s" % self.c.page_note] if self.c.page_note else [])
        foot = ["hole: %s" % h for h in holes] + ["note: %s" % n for n in notes]
        self.foot.configure(text="\n".join(foot), fg=LEVEL_COLORS["alarm" if holes else "incomplete"])
        return holes

    def _tick(self):
        for action in self.c.drain():
            if action in ("show", "stop"):
                self.root.deiconify()
                self.root.lift()
        holes = self._foot()
        self.c.report_finished()   # F-8: each finished watch's report, appended to the log once
        self.head_note.configure(text=self.c.running_text() + (
            "   %s" % self.refusal if self.refusal and self.c.project_watching() else ""))
        fresh = self._tick_doctor()
        view = self.c.host_view()
        self.c.host_tip(view.get("trees"), view.get("new"))   # E3: the tray's tooltip
        if self.screen == "host":
            self._tick_host(view)
            return
        session = self.c.session
        if self.screen == "first" or session is None:
            if fresh and self.screen == "first":
                self._band(*self.doctor_band)
            return
        snap = session.snapshot()
        state = session.state()
        extra = snap["holes"] + holes + ([session.read_note] if session.read_note else [])
        self.knock_label.configure(text=first_line(snap.get("knock")))
        if self.log_open:
            self._set(self.log_text, "log", log_view(session.log.text()))
        if snap["phase"] == "failed" and snap["final_text"] is None:
            self._band("NOT WATCHING", "alarm", snap["error"] or "the watch did not start")
            self._set(self.body, "body", (session.log.text() or "") + "\n" + (snap["error"] or "") + "\n")
            self.stop_button.pack_forget()
            self.back_button.pack(side="left")
            return
        if snap["phase"] == "finished":
            self._band("FINISHED", "alarm" if snap["final_exit"] else "clean",
                       "the watch ended; its final report is below (exit %s)" % snap["final_exit"])
            self._set(self.body, "body", snap["final_text"] + ("".join("hole: %s\n" % h for h in extra)))
            self.stop_button.pack_forget()
            self.back_button.pack(side="left")
            return
        self.back_button.pack_forget()
        self.stop_button.pack(side="left")
        if state is None:
            self._band("STARTING", "incomplete", "installing the hooks and starting the watch of %s"
                       % _safe(session.project))
            return
        view = watch_view(state, extra)
        word = view["word"] + (" (stopping)" if snap["phase"] == "stopping" else "")
        self._band(word, view["level"], view["detail"])
        self.badges.configure(text="   ".join(text for _, text in view["badges"]))
        self.url.set(view["url"])
        self._set(self.body, "body", body_text(view))

    def _tick_host(self, view):
        """E1/E2: the host screen from the controller's host view."""
        self._band(view["word"], view["level"], view["detail"])
        self.host_badges.configure(text="   ".join(text for _, text in view.get("badges") or []))
        self.host_url.set(view.get("url") or "-")
        self._set(self.host_text, "host", host_body(view))
        if self.host_log_open:   # F-6
            log = getattr(self.c.host, "log", None)
            self._set(self.host_log_text, "host_log", log_view(log.text()) if log is not None else
                      "the host watch has not started: no log yet\n")
        self.host_button.configure(text="Stop host watch" if self.c.host_watching() else "Watch this host")

    def _tick_doctor(self):
        """The doctor's result, when it comes: the project screen's lines
        and band, and the host screen's "Checks" (open when any MISSING)."""
        job = self.doctor
        result = job.result() if job is not None else None
        if result is None:
            return False
        project, lines, summary = result
        tags = tuple((text, level) for _, level, text in lines) + (("", None), (summary, None))
        self._set(self.doctor_text, "doctor", None, tags)
        self._set(self.checks_text, "checks", None, tags)
        label, open_ = checks_state(lines)
        self.checks_button.configure(text=label)
        if open_ != self.checks_open:
            self.toggle_checks()
        missing = any(word == "MISSING" for word, _, _ in lines)
        self.doctor_band = ("DOCTOR: %s" % summary.split(": ", 1)[-1], "alarm" if missing else "clean",
                            "project %s; Start installs the hooks and watches it, as `raqib watch` does" % _safe(project))
        self.doctor = None
        return True


# --- the command ------------------------------------------------------------------------

def run(project, options, out=None, tk=None, err=None):
    """raqib app: open the window, run until it closes; the exit code of
    the last watch's final report (0 when none ran)."""
    err = err or sys.stderr
    environ = os.environ if options.environ is None else options.environ
    if tk is None:
        tk, why = probe_tk()
        if tk is None:
            raise AppError(why)
    problem = display_problem(environ)
    if problem:
        raise AppError("raqib app: %s; `raqib watch` works without a window" % problem)
    try:
        root = tk.Tk()
    except Exception as exc:   # tkinter.TclError: no display it can use
        raise AppError("raqib app: no window could be opened (%s: %s); `raqib watch` works without one"
                       % (type(exc).__name__, _safe(exc)))
    controller = Controller(options, tee=out)
    project = os.path.abspath(project or ".")
    try:
        controller.start_tray()
        window = Window(tk, root, controller, project, environ=options.environ, home=options.home)
        root.mainloop()
        if not window.closed:
            window.destroy()
    finally:
        controller.shutdown()
        controller.finish_wait(err=err)   # A-3: never exit with a watch that has not concluded
    controller.report_finished()   # F-8: every watch's report, appended once
    return controller.exit_code()


class AppLog:
    """A-4: ~/.raqib/app.log, the gui-script's stdout: truncated at start,
    bounded at `limit` bytes (one line then says the rest is not written).
    A write that fails is kept in error, never raised into the watch."""

    def __init__(self, path, limit=APP_LOG_MAX):
        self.path = path
        self.limit = limit
        self.lock = threading.Lock()
        self.size = 0
        self.full = False
        self.error = None
        self.file = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.file = open(path, "w", encoding="utf-8", errors="backslashreplace", newline="\n")
        except OSError as exc:
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def write(self, text):
        text = str(text)
        with self.lock:
            if self.file is None or self.full:
                return len(text)
            data = text.encode("utf-8", "backslashreplace")
            try:
                if self.size + len(data) > self.limit:
                    self.full = True
                    self.file.write("\n[raqib app: app.log reached %d bytes; the rest is not written]\n" % self.limit)
                else:
                    self.file.write(text)
                    self.size += len(data)
                self.file.flush()
            except (OSError, ValueError) as exc:
                self.error = "%s: %s" % (type(exc).__name__, exc)
                self.file = None
        return len(text)

    def flush(self):
        pass

    def close(self):
        with self.lock:
            if self.file is not None:
                try:
                    self.file.close()
                except OSError:
                    pass
                self.file = None


class Tail:
    """A bounded stderr (A-4): the last `limit` characters, and a copy to
    another stream (app.log)."""

    def __init__(self, copy_to=None, limit=ERR_MAX):
        self.copy_to = copy_to
        self.limit = limit
        self.text = ""

    def write(self, text):
        text = str(text)
        self.text = (self.text + text)[-self.limit:]
        if self.copy_to is not None:
            self.copy_to.write(text)
        return len(text)

    def flush(self):
        pass


def app_log_path(home=None):
    return os.path.join(home or os.path.expanduser("~"), ".raqib", APP_LOG)


def tell(text, platform=None, box=None, stream=None):
    """A-4: a failure before the window is up, said where the person sees
    it: one message box on Windows (tray.message_box), stderr elsewhere (and
    when the box cannot be shown). Never raises."""
    platform = platform or sys.platform
    if platform == "win32":
        why = (box or traymod.message_box)(text, TITLE + ": the window did not open")
        if why is None:
            return "box"
        text = "%s\n(the message box could not be shown: %s)" % (text, why)
    stream = stream if stream is not None else sys.__stderr__
    try:
        if stream is not None:
            stream.write(text.rstrip("\n") + "\n")
            stream.flush()
            return "stderr"
    except Exception:
        pass
    return None


def gui_main(argv=None, home=None, platform=None, box=None, stream=None):
    """The `raqib-app` gui-script (A-4). On Windows pythonw runs it with no
    console. The watch's lines and the final report go to ~/.raqib/app.log
    (truncated at start, bounded); stderr is kept, bounded, and copied
    there. When it ends with exit 2 (the window could not open, e.g. no
    tkinter) or an exception before the window was up, the sentence is one
    message box on Windows and a line on stderr elsewhere."""
    argv = sys.argv[1:] if argv is None else list(argv)
    path = app_log_path(home)
    log = AppLog(path)
    tail = Tail(copy_to=log)
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = log, tail
    try:
        from raqib import cli   # cli imports this module: imported here, not at the top
        try:
            code = cli.main(["app"] + argv, out=log)
        except BaseException as exc:   # a startup exception: said, never a silent pythonw exit
            if isinstance(exc, KeyboardInterrupt):
                raise
            log.write(traceback.format_exc())
            tail.text += "raqib: the window failed before it opened: %s: %s\n" % (type(exc).__name__, _safe(exc))
            code = 2
    finally:
        sys.stdout, sys.stderr = saved
        log.close()
    if code == 2 and tail.text.strip():
        where = ("(this and the log are in %s)" % path) if log.error is None else (
            "(app.log could not be written: %s)" % log.error)
        tell("%s\n%s" % (tail.text.strip(), where), platform=platform, box=box, stream=stream)
    return code
