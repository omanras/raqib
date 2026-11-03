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
watch's state under the Watch lock from after(), never from the page. It
starts no program and sends nothing to the agent (A4): Start and Stop
control Raqib's own watching. The page is not opened in a browser; its URL
is shown.

The knock (E3): the first live, settled finding of a watch, whatever its
severity, knocks once through the watch's Notifier under its own rate-limit
id (notify.FirstFinding), on top of the per-rule knocks.

Holes (A3): a tray that fails, a knock that fails, a worker that crashes, a
state the window cannot read - each is a line under "holes" in the window,
never swallowed and never a crash of the window. On Windows the tray icon
(raqib/tray.py) has Show / Stop / Quit and closing the window while
watching hides it there; elsewhere there is no tray (recorded as a note)
and closing the window while watching stops the watch, leaving the final
report on screen; closing it again quits.

Without tkinter, or on X11 without DISPLAY, `raqib app` exits 2 with one
sentence (AppError). The logic - the views, the Session over a watch, the
Controller that decides what a close or a tray action does - is plain
Python, tested with fakes; only Window touches Tk, and tkinter is imported
only when the window is made.
"""
from __future__ import annotations

import copy
import importlib
import io
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
    thread-safe, bounded; tee is the terminal when there is one."""

    def __init__(self, tee=None, limit=LOG_MAX):
        self.lock = threading.Lock()
        self.parts = []
        self.size = 0
        self.dropped = 0
        self.tee = tee
        self.limit = limit
        self.tee_error = None

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
        return len(text)

    def flush(self):
        with self.lock:
            if self.tee is not None:
                try:
                    self.tee.flush()
                except Exception:
                    pass

    def text(self):
        with self.lock:
            head = "[%d earlier characters dropped]\n" % self.dropped if self.dropped else ""
            return head + "".join(self.parts)


class Options:
    """What `raqib app` passes to every watch it starts."""

    def __init__(self, evaluator, rules, gap_seconds, log=None, no_notify=False, port=None, refresh=None,
                 environ=None, home=None):
        self.evaluator = evaluator
        self.rules = rules
        self.gap_seconds = gap_seconds
        self.log = log
        self.no_notify = no_notify
        self.port = port
        self.refresh = refresh
        self.environ = environ
        self.home = home


class Session:
    """One watch of one project, run in a worker thread by watch.start /
    loop / conclude / close. phase: starting, watching, stopping, finished
    (the final report is there) or failed (watch could not start: error).
    holes: what went wrong around the watch (a knock, the worker); A3."""

    def __init__(self, project, options, log=None, starter=None, clock=None):
        self.project = project
        self.options = options
        self.log = log or LogBuffer()
        self.starter = starter or watch.start
        self.clock = clock or time.monotonic
        self.stop_flag = watch.Stop()
        self.lock = threading.Lock()
        self.phase = "starting"
        self.error = None
        self.final_text, self.final_exit = None, None
        self.running = None
        self.knock = None        # the FirstFinding of this watch, once it started
        self.holes = []
        self.last_state = None
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
                running = self.starter(self.project, o.log, True, o.no_notify, o.port, self.log, o.evaluator,
                                       o.rules, o.gap_seconds, environ=o.environ, err=self.log, home=o.home,
                                       refresh=o.refresh)
            except watch.WatchError as exc:
                with self.lock:
                    self.phase, self.error = "failed", "the watch did not start: %s" % exc
                return
            with self.lock:
                self.running = running
                self.knock = notify.FirstFinding(running.notifier)
                if self.phase == "starting":
                    self.phase = "watching"
            try:
                crash = watch.loop(running, self.stop_flag, on_step=self._step)
                text, code = watch.conclude(running, crash)
            finally:
                watch.close(running)
            with self.lock:
                self.final_text, self.final_exit, self.phase = text, code, "finished"
        except Exception as exc:   # A3: a crashed worker is a hole in the window, never silence
            self.log.write(traceback.format_exc())
            with self.lock:
                self.error = "the watch worker crashed: %s: %s" % (type(exc).__name__, exc)
                if self.phase != "finished":
                    self.phase = "failed"
                self.holes.append(self.error)

    def _step(self, watcher):
        """After every poll, in the worker: the first-finding knock (E3)."""
        try:
            with watcher.lock:
                findings = list(watcher.inventory.values())
                done = self.knock.check(findings, watcher.clock())
            if done is not None:
                self.log.write("raqib app: first finding of this watch knocked: %s (%s)\n"
                               % (done["where"], done["status"]))
                if done["status"] == "failed":
                    self._hole("the first-finding knock was not delivered (%s); see the notifier's holes"
                               % done["where"])
        except Exception as exc:
            self._hole("the first-finding knock failed: %s: %s" % (type(exc).__name__, exc))

    def state(self):
        """A copy of the watch's state, read under the Watch lock; the last
        one (and read_note) when the lock is held longer than LOCK_SECONDS."""
        running = self.running
        if running is None:
            return None
        watcher = running.watcher
        if not watcher.lock.acquire(timeout=LOCK_SECONDS):
            self.read_note = "the watch held its state for more than %g s at the last read" % LOCK_SECONDS
            return self.last_state
        try:
            state = copy.deepcopy(watcher.state(watcher.clock()))
        except Exception as exc:
            self.read_note = "the window could not read the watch's state: %s: %s" % (type(exc).__name__, exc)
            return self.last_state
        finally:
            watcher.lock.release()
        self.read_note = None
        self.last_state = state
        return state

    def snapshot(self):
        with self.lock:
            return {"phase": self.phase, "error": self.error, "final_text": self.final_text,
                    "final_exit": self.final_exit, "holes": list(self.holes),
                    "knock": dict(self.knock.knocked) if self.knock and self.knock.knocked else None}


class Controller:
    """What a close, Stop, Start or a tray action does, without Tk. Tray
    actions arrive from the tray thread through a queue, read by drain()."""

    def __init__(self, options, tray=None, make_session=None, tee=None):
        self.options = options
        self.tray = tray
        # each watch has its own LogBuffer; tee is the terminal when there is one
        self.make_session = make_session or (lambda project: Session(project, options, log=LogBuffer(tee=tee)))
        self.session = None
        self.actions = queue.Queue()
        self.quitting = False
        self.notes = []   # by design, not holes: "no tray on this platform"
        self.holes = []   # the window's own holes: a tray that failed

    # tray
    def start_tray(self):
        if self.tray is None:
            self.tray = traymod.Tray(self.actions.put)
        try:
            why = self.tray.start()
        except Exception as exc:   # never into the window (A3)
            why = "the tray failed to start: %s: %s" % (type(exc).__name__, exc)
            self.tray = None
            self.holes.append("tray: %s" % why)
            return why
        if why is None:
            return None
        if traymod.unsupported(getattr(self.tray, "platform", None)) == why:
            self.notes.append("tray: %s" % why)
        else:
            self.holes.append("tray: %s" % why)
        self.tray = None
        return why

    def tray_up(self):
        return self.tray is not None and bool(getattr(self.tray, "running", False))

    def tray_holes(self):
        return ["tray: %s" % h for h in (getattr(self.tray, "holes", []) if self.tray is not None else [])]

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
        self.quitting = True
        self.stop(reason)

    def can_exit(self):
        """Quit asked and no watch is left running (or it did not end in JOIN_SECONDS)."""
        return self.quitting and not self.watching()

    def shutdown(self):
        """The window is going: the watch ends, the worker is waited for, the tray goes."""
        if self.session is not None:
            self.session.stop("the window was closed")
            if self.session.thread is not None:
                self.session.thread.join(JOIN_SECONDS)
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
        self.stop_button = tk.Button(row, text="Stop", command=self.stop)
        self.stop_button.pack(side="left")
        self.back_button = tk.Button(row, text="Back", command=self.show_first)
        row.pack(fill="x", pady=6)
        self.badges = tk.Label(self.watching, text="", anchor="w", justify="left", wraplength=920)
        self.badges.pack(fill="x")
        frame, self.body = self._text(self.watching, 18)
        frame.pack(fill="both", expand=True)
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
        except Exception as exc:   # A3: the window says what broke, and keeps going
            self.foot.configure(text="hole: the window failed to update: %s: %s" % (type(exc).__name__, exc),
                                fg=LEVEL_COLORS["alarm"])
        if self.closed:
            return
        if self.c.can_exit():
            self.destroy()
            return
        self.after_id = self.root.after(TICK_MS, self.tick)

    def _tick(self):
        for action in self.c.drain():
            if action in ("show", "stop"):
                self.root.deiconify()
                self.root.lift()
        holes = self.c.holes + self.c.tray_holes()
        foot = ["hole: %s" % h for h in holes] + ["note: %s" % n for n in self.c.notes]
        self.foot.configure(text="\n".join(foot), fg=LEVEL_COLORS["alarm" if holes else "incomplete"])
        session = self.c.session
        if self.screen == "first" or session is None:
            self._tick_first()
            return
        snap = session.snapshot()
        state = session.state()
        extra = snap["holes"] + holes + ([session.read_note] if session.read_note else [])
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

def run(project, options, out=None, tk=None):
    """raqib app: open the window, run until it closes; the exit code of
    the last watch's final report (0 when none ran)."""
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
    snap = controller.session.snapshot() if controller.session is not None else None
    if out is not None and snap and snap["final_text"]:
        try:
            out.write("\n" + snap["final_text"])
        except Exception:
            pass
    return controller.exit_code()


def gui_main():
    """The `raqib-app` gui-script: on Windows pythonw runs it with no console,
    so sys.stdout and sys.stderr may be None; they become buffers."""
    if sys.stdout is None:
        sys.stdout = io.StringIO()
    if sys.stderr is None:
        sys.stderr = io.StringIO()
    from raqib import cli   # cli imports this module: imported here, not at the top
    return cli.main(["app"] + sys.argv[1:], out=sys.stdout)
