"""raqib app (M6.4, ADR-0006): Raqib as an ordinary desktop program window.

`raqib app [PROJECT]` (or the `raqib-app` gui-script, which on Windows runs
under pythonw with no console) opens one tkinter window, standard library
only:
- first screen: what `raqib doctor` says for the project (OK / MISSING /
  UNSURE, run in a thread so the window never waits on `claude --version`),
  a project field with Browse, Check again and Start;
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
(A-11); the watch it starts runs the notifier as `raqib watch` does, and
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

from raqib import notify, tray as traymod, ui, watch

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
                 environ=None, home=None, log_project=None):
        self.evaluator = evaluator
        self.rules = rules
        self.gap_seconds = gap_seconds
        self.log = log
        self.log_project = log_project   # A-10: --log is the trace of this project only (the command line's)
        self.no_notify = no_notify
        self.port = port
        self.refresh = refresh
        self.environ = environ
        self.home = home

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

    def _work(self):
        o = self.options
        try:
            try:
                running = self.starter(self.project, o.log_for(self.project), True, o.no_notify, o.port, self.log,
                                       o.evaluator, o.rules, o.gap_seconds, environ=o.environ, err=self.log,
                                       home=o.home, refresh=o.refresh)
            except watch.WatchError as exc:
                with self.lock:
                    self.phase, self.error = "failed", "the watch did not start: %s" % exc
                return
            with self.lock:
                self.running = running
                if self.phase == "starting":
                    self.phase = "watching"
            try:
                crash = watch.loop(running, self.stop_flag, on_step=self._step)
                text, code = watch.conclude(running, crash)
                with self.lock:   # A-8: the final report is kept before close() runs
                    self.final_text, self.final_exit = text, code
            finally:
                try:
                    watch.close(running)
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


class Controller:
    """What a close, Stop, Start or a tray action does, without Tk. Tray
    actions arrive from the tray thread through a queue, read by drain()."""

    def __init__(self, options, tray=None, make_session=None, tee=None, clock=None, opener=None):
        self.options = options
        self.tray = tray
        # each watch has its own LogBuffer; tee is the terminal (or app.log) when there is one
        self.make_session = make_session or (lambda project: Session(project, options, log=LogBuffer(tee=tee)))
        self.session = None
        self.actions = queue.Queue()
        self.quitting = False
        self.quit_at = None     # A-3: when Quit was asked (monotonic)
        self.clock = clock or time.monotonic
        self.opener = opener or watch.open_page
        self.tee = tee
        self.page_note = None   # what the last "Open page" said (A-13)
        self.notes = []   # by design, not holes: "no tray on this platform"
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

    def finish_wait(self, err=None, rounds=None):
        """A-3: the process does not exit while the watch has not
        concluded: wait for the worker JOIN_SECONDS at a time, saying so
        each time; nothing is killed. True when it ended (rounds: a bound
        for tests; None waits for as long as it takes)."""
        session = self.session
        thread = getattr(session, "thread", None)
        n = 0
        while thread is not None and thread.is_alive():
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
    def watching(self):
        return self.session is not None and self.session.snapshot()["phase"] in ("starting", "watching", "stopping")

    def start(self, project):
        """A new watch of project; None, or why not."""
        if self.watching():
            return "a watch is running: stop it first"
        if not project or not os.path.isdir(project):
            return "not a directory: %s" % (project or "(empty)")
        self.session = self.make_session(project).start()
        return None

    def stop(self, reason):
        if self.session is not None:
            self.session.stop(reason)

    def close_request(self):
        """The window's close button: "hide" (to the tray, while watching),
        "stop" (the watch ends, the final report stays on screen) or "quit"."""
        if self.watching():
            if self.tray_up():
                return "hide"
            self.stop("window closed")
            return "stop"
        return "quit"

    def open_page(self):
        """A-13 (Q-6): the "Open page" button; the same opener as `raqib
        watch` (watch.open_page), never under CI. None, or why not."""
        session = self.session
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
        session = self.session
        if session is None:
            return False
        alive = getattr(session, "alive", None)
        return bool(alive()) if alive is not None else self.watching()

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
        if self.session is not None:
            self.session.stop("the window was closed")
            if self.session.thread is not None:
                self.session.thread.join(JOIN_SECONDS)
                done = not self.session.thread.is_alive()
        self._tray_down()
        return done

    def _tray_down(self):
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass

    def exit_code(self):
        snap = self.session.snapshot() if self.session is not None else None
        if snap is None:
            return 0
        if snap["final_exit"] is not None:
            return snap["final_exit"]
        return 1 if snap["phase"] == "failed" else 0


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

    def __init__(self, tk, root, controller, project, environ=None, home=None, doctor_job=None):
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
        self._build(project)
        self.show_first()
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
        # first screen
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
    def show_first(self):
        if self.screen == "first":
            return
        self.watching.pack_forget()
        self.first.pack(fill="both", expand=True, padx=10)
        self.screen = "first"
        self.shown.pop("body", None)

    def show_watching(self):
        if self.screen == "watching":
            return
        self.first.pack_forget()
        self.watching.pack(fill="both", expand=True, padx=10)
        self.screen = "watching"

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
        self._band("CHECKING", "incomplete", "raqib doctor is running for %s" % _safe(self.project.get()))

    def start(self):
        why = self.c.start(self.project.get())
        if why:
            self._band("NOT STARTED", "alarm", why)
            return
        self.show_watching()

    def stop(self):
        self.c.stop("Stop in the window")

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
        else:
            self.show_watching()

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
        holes = self.c.holes + self.c.tray_holes()
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
        session = self.c.session
        if self.screen == "first" or session is None:
            self._tick_first()
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

    def _tick_first(self):
        job = self.doctor
        result = job.result() if job is not None else None
        if result is None:
            return
        project, lines, summary = result
        self._set(self.doctor_text, "doctor", None, tuple((text, level) for _, level, text in lines) +
                  (("", None), (summary, None)))
        missing = any(word == "MISSING" for word, _, _ in lines)
        self._band("DOCTOR: %s" % summary.split(": ", 1)[-1], "alarm" if missing else "clean",
                   "project %s; Start installs the hooks and watches it, as `raqib watch` does" % _safe(project))
        self.doctor = None


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
    snap = controller.session.snapshot() if controller.session is not None else None
    if out is not None and snap and snap["final_text"]:
        try:
            out.write("\n" + snap["final_text"])
        except Exception:
            pass
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
