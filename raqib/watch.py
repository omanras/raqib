"""raqib watch (M6.1, ADR-0005 decision 1, Amendments A and B): one command
watches a project.

`raqib watch [PROJECT]` installs the capture hooks with tools/install_hooks.py
(idempotent; its lines are printed), tails the trace by polling every
POLL_SECONDS, judges what arrives, keeps the findings, the live silence
windows and the holes in memory and in <trace>.watch.json, serves the
read-only page on 127.0.0.1 (ui.make_server), opens it once, and runs until
Ctrl-C. Then it prints the final report. Any other exception also ends in
the final report, with the watch marked crashed (B-4).

The trace: --log PATH; else the one trace an earlier install chose, if it is
outside the project; else ~/.raqib/traces/<name>-<sha256(project)[:12]>/
raqib.log.jsonl. Watch writes nothing into the project but the hook settings
the installer writes, so a --log inside the project is refused and an
earlier install's trace inside the project is replaced (the old file is left
as it is). It never signals a process (A4): the only programs it starts are
the notifier and the page opener, by absolute path (raqib/notify.py). The
rules get the Scope of <project>/HANDOFF.md as context when that file
exists, as `report --handoff` does (B-6).

History (B-3): the lines already in the trace when watch starts are parsed,
judged and shown, and counted in one printed line ("N prior findings in the
trace, not knocked"); they are never notified. Knocks start with the first
line appended after the start, and history is epoch 0 only (D-1). A
finding is history when every line of every seq it cites was there at the
start, and so was the line that settled it (D-5).

Incremental. Only the bytes appended since the last poll are read; complete
lines are parsed by the batch parser (trace._parse, as trace.read_numbered
uses it) with line numbers continued, so the records equal a batch read of
the final file. The rules are pure functions over a record list, so when
lines arrive they are re-run on the whole growing list. Every finding is
keyed by (epoch, rule_id, session_id, cited_seq, summary) (B-2): two
findings never share a key, and a key seen before is not reported or
notified again. A pending SILENCE-OPEN whose citation moved with the trace
takes over the entry of the same rule and session; a settled or vanished
entry is never taken over, so a new key after it is a new finding (D-2).

Pending (B-1): SILENCE-OPEN, and SILENCE-HALF on a seq with more pres than
posts, can still be taken back by later lines. Such a finding is settled -
and knocks if it is high - when its session shows a later stop or
session_end (SILENCE-HALF), or when the live silence window opens (both);
one that vanishes first is dropped; one left at exit is in the final report.

Silence is an alarm (A3):
- no new line for RAQIB_GAP_SECONDS opens a live window (SILENCE-LIVE open),
  the next line closes it (SILENCE-LIVE closed); both are notified;
- a line starting with RAQIB-SILENCE in the trace, or hooks the installer
  reports disabled, is a capture failure (RAQIB-SILENCE, notified);
- a live line that does not parse as a trace record knocks as TRACE-HOLE
  (B-4; the notifier limits it to one per minute);
- a trace that shrank, was replaced, was rewritten from its start, was
  removed or cannot be read is a hole (TRACE-HOLE, notified); after a reset
  reading starts again at line 1 in a new epoch, and the findings of the old
  content stay in the state and in the final report;
- the watcher itself (B-4): watch.json carries a heartbeat written on every
  poll; the page reads a heartbeat older than STALE_SECONDS, or a state the
  page cannot get within PAGE_LOCK_SECONDS, as crashed or stuck.
Settled findings of severity high are notified (ADR-0005); the others are
shown. Notifications are rate-limited by raqib/notify.py.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import ntpath
import os
import sys
import tempfile
import threading
import time
import traceback

from raqib import notify, report, ui
from raqib.rules import silence, trace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, "tools", "install_hooks.py")
POLL_SECONDS = 0.5
DEFAULT_PORT = 8765
HEAD_BYTES = 64
STALE_SECONDS = 30       # a heartbeat older than this reads as crashed (B-4)
PAGE_LOCK_SECONDS = 15   # longer than one delivery may take (notify.TIMEOUT_SECONDS)
TRACE_NAME = "raqib.log.jsonl"
STATE_SUFFIX = ".watch.json"
MARKER = "RAQIB-SILENCE"
LIVE = "SILENCE-LIVE"
HOLE = "TRACE-HOLE"
GROWS = ("SILENCE-OPEN",)  # its citation moves with the trace, like an aggregate rule's
HISTORY_NOTICE = "history: not knocked"
PARSE_LIMIT = "TRACE-HOLE (line)"  # parse problems' own rate-limit id; tail holes use TRACE-HOLE (D-6)
SOURCE = "raqib watch: the rules re-run on the trace as it grows"
OPENERS = ("/usr/bin/xdg-open", "/bin/xdg-open")
MAC_OPENER = "/usr/bin/open"
# xdg-open is a shell script that finds the browser through PATH: it gets
# the system directories, not the PATH of the shell watch was started from.
OPENER_PATH = "/usr/local/bin:/usr/bin:/bin"
OPENER_ENV = ("HOME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
              "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "DESKTOP_SESSION")

_sleep = time.sleep  # the poll wait; tests replace it


class WatchError(Exception):
    """Watch cannot start (exit 2)."""


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def _key_list(key):
    """A finding key as watch.json holds it."""
    return [key[0], key[1], key[2], list(key[3]), key[4]]


def seq_text(seqs):
    shown = ",".join(str(s) for s in seqs[:3])
    return "seq %s%s" % (shown, " +%d more" % (len(seqs) - 3) if len(seqs) > 3 else "")


class Tail:
    """What was appended to a file since the last poll."""

    def __init__(self, path):
        self.path = path
        self.ident = None   # (st_dev, st_ino) of the file being read
        self.offset = 0     # bytes read
        self.head = b""     # its first HEAD_BYTES bytes, to see a rewrite
        self.partial = b""  # bytes after the last newline
        self.error = None

    def _restart(self):
        self.ident, self.offset, self.head, self.partial = None, 0, b"", b""

    def _torn(self):
        return "; %d bytes after the last newline never became a line" % len(self.partial) if self.partial else ""

    def poll(self):
        """(new complete lines as bytes, holes). A hole is (kind, detail,
        restarted); restarted means reading began again at byte 0 (A3)."""
        holes = []
        try:
            f = open(self.path, "rb")
        except FileNotFoundError:
            if self.ident is not None:
                holes.append(("trace-missing", "%s was removed or renamed after %d bytes were read%s"
                              % (self.path, self.offset, self._torn()), True))
                self._restart()
            return [], holes
        except OSError as exc:
            return [], self._unreadable(exc)
        try:
            with f:
                st = os.fstat(f.fileno())
                ident = (st.st_dev, st.st_ino)
                if self.ident is not None:
                    why = None
                    if st.st_ino and self.ident[1] and ident != self.ident:
                        why = ("trace-replaced", "%s is another file now (device and inode changed) after %d bytes"
                               " were read%s" % (self.path, self.offset, self._torn()))
                    elif st.st_size < self.offset:
                        why = ("trace-truncated", "%s shrank from %d to %d bytes%s"
                               % (self.path, self.offset, st.st_size, self._torn()))
                    elif f.read(len(self.head)) != self.head:
                        why = ("trace-rewritten", "the first %d bytes of %s changed after %d bytes were read%s"
                               % (len(self.head), self.path, self.offset, self._torn()))
                    if why:
                        holes.append(why + (True,))
                        self._restart()
                f.seek(self.offset)
                data = f.read()
        except OSError as exc:
            return [], holes + self._unreadable(exc)
        self.error = None
        self.ident = ident
        self.offset += len(data)
        if len(self.head) < HEAD_BYTES:
            self.head = (self.head + data)[:HEAD_BYTES]
        pieces = (self.partial + data).split(b"\n")
        self.partial = pieces.pop()
        return pieces, holes

    def _unreadable(self, exc):
        detail = "cannot read %s: %s" % (self.path, exc.strerror or exc)
        if detail == self.error:
            return []
        self.error = detail
        return [("trace-unreadable", detail, False)]

    def rest(self):
        """The bytes after the last newline as a last line, as a batch read
        of the file takes them."""
        rest, self.partial = self.partial, b""
        return [rest] if rest else []


class Watch:
    """The state of one watched trace. step() polls once; finish() reads
    what is left and returns the final report. clock() is monotonic."""

    def __init__(self, project, trace_path, evaluate, rules, gap_seconds, notifier, out=None,
                 err=None, clock=None, started=None, state_path=None):
        self.project = project
        self.name = notify.project_name(project)
        self.trace_path = trace_path
        self.state_path = state_path or trace_path + STATE_SUFFIX
        self.evaluate = evaluate            # records -> (findings, notes)
        self.rules = rules
        self.grows = {r.id for r in rules if r.aggregate is not None} | set(GROWS)
        self.gap = gap_seconds
        self.notifier = notifier
        self.out = out
        self.err = err
        self.clock = clock or time.monotonic
        self.t0 = self.clock()
        self.started = started or datetime.datetime.now(datetime.timezone.utc)
        notifier.stamp = self.at
        notifier.on_folds = self._folds   # D-4: what became of a folded knock is written back
        self.lock = threading.Lock()
        self.tail = Tail(trace_path)
        try:  # B-3: what is in the trace now is history
            self.history_bytes = os.path.getsize(trace_path)
        except OSError:
            self.history_bytes = 0
        self.done_bytes = 0       # bytes of the lines taken in this epoch
        self.history_line = 0     # the last line that was in the trace at the start
        self.history_said = False
        self.epoch = 0
        self.lines = 0
        self.numbered, self.problems = [], []
        self.problem_notices = {}  # line -> notice of a live parse problem or RAQIB-SILENCE line
        self.problem_events = {}   # line -> the event it knocked as
        self.found, self.notes = evaluate([])
        self.inventory = {}   # key -> finding entry, in the order first seen
        self.windows = []     # live silence windows
        self.holes = []
        self.last_line = None
        self.last_at = self.t0
        self.beat = self.t0       # the last completed poll (B-4)
        self.url = None
        self.port = None          # {"requested", "used", "warning"} (B-7)
        self.scope = None         # where the rules' scope came from (B-6)
        self.status = "watching"
        self.error = None
        self.finished = None
        self.state_error = None
        self.final_text, self.final_exit = None, None

    # --- time and output -----------------------------------------------------

    def at(self, now):
        moment = self.started + datetime.timedelta(seconds=now - self.t0)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)

    def _say(self, now, text):
        if self.out is not None:
            self.out.write("[%sZ] %s\n" % (self.at(now)[11:19], _safe(text)))
            self.out.flush()

    def _knock(self, now, event, where, token=None, limit_id=None):
        """Notify; token is (container, key): where the notice is kept, so a
        fold's outcome can be written back to it (D-4)."""
        status = self.notifier.notify(event, where, now, token=token, limit_id=limit_id)
        if token is not None:
            token[0][token[1]] = status
        return status

    def _folds(self, tokens, status, count):
        for container, key in tokens:
            container[key] = "folded: %s as %d more" % (status, count)

    def _hole(self, now, kind, detail, history=False):
        hole = {"kind": kind, "detail": detail, "at": self.at(now), "epoch": self.epoch, "history": history,
                "notice": HISTORY_NOTICE if history else None}
        self.holes.append(hole)
        return hole

    def window(self):
        return self.windows[-1] if self.windows and self.windows[-1]["closed"] is None else None

    # --- one poll --------------------------------------------------------------

    def step(self, now=None):
        """Poll once; watch.json is written on every poll (the heartbeat)."""
        with self.lock:
            now = self.clock() if now is None else now
            self._poll(now)
            self._silence(now)
            for event, count, status in self.notifier.tick(now):
                self._say(now, "%s: %d more, folded into one notification (%s)" % (event, count, status))
            self.beat = now
            self._write_state(now)

    def capture_off(self, detail, now=None):
        """Capture will not run (the installer said so): a hole, notified."""
        with self.lock:
            now = self.clock() if now is None else now
            hole = self._hole(now, "capture-failed", detail)
            status = self._knock(now, MARKER, "hooks disabled", (hole, "notice"))
            self._say(now, "%s: %s (%s)" % (MARKER, detail, status))

    def _poll(self, now):
        lines, holes = self.tail.poll()
        for kind, detail, restarted in holes:
            where = "after line %d" % self.lines if self.lines else "before any line"
            hole = self._hole(now, kind, detail)
            status = self._knock(now, HOLE, where, (hole, "notice"))
            self._say(now, "%s %s: %s (%s)" % (HOLE, kind, detail, status))
            if restarted:
                self._restart()
        if lines:
            self._take(lines, now)
        if not self.history_said and self.history_line and self.done_bytes >= self.history_bytes:
            self.history_said = True
            prior = sum(1 for e in self.inventory.values() if e["history"])
            self._say(now, "%d prior findings in the trace, not knocked (lines 1-%d were there at the start:"
                           " history, shown on the page and in the final report)" % (prior, self.history_line))

    def _restart(self):
        self.epoch += 1
        self.lines = 0
        self.done_bytes = 0
        self.history_bytes = 0    # D-1: history is epoch 0 only; in a later epoch every line is live
        self.history_line = 0
        self.problem_notices, self.problem_events = {}, {}
        self.numbered, self.problems = [], []
        self.found, self.notes = self.evaluate([])
        for key in [k for k, e in self.inventory.items() if e["state"] == "pending"]:
            del self.inventory[key]

    def _take(self, lines, now, terminated=True):
        base = self.lines
        self.lines += len(lines)
        pairs = []
        for i, raw in enumerate(lines, start=1):
            try:
                pairs.append((raw.decode("utf-8"), True))
            except UnicodeDecodeError:
                pairs.append((raw.decode("utf-8", "replace"), False))
            self.done_bytes += len(raw) + (1 if terminated else 0)
            if self.epoch == 0 and self.done_bytes <= self.history_bytes:
                self.history_line = base + i
        # The batch parser, so the records equal trace.read_numbered of the file.
        numbered, problems = trace._parse(pairs)
        numbered = [(n + base, rec) for n, rec in numbered]
        problems = [dict(p, line=p["line"] + base) for p in problems]
        self.numbered += numbered
        self.problems += problems
        content = [base + i for i, (text, _) in enumerate(pairs, start=1) if text.strip()]
        live = [n for n in content if n > self.history_line]
        seqs = {n: rec["seq"] for n, rec in numbered}
        window = self.window()
        if window is not None and live:
            first = live[0]
            where = "line %d" % first + (", seq %d" % seqs[first] if first in seqs else "")
            window.update(closed=self.at(now), seconds=round(now - self.last_at, 3), closed_by_line=first,
                          closed_by_seq=seqs.get(first))
            self._knock(now, LIVE + " closed", where, (window, "notice_closed"))
            self._say(now, "%s closed after %.1fs by %s (%s)" % (LIVE, now - self.last_at, where,
                                                                window["notice_closed"]))
        if content:
            self.last_at = now
            self.last_line = {"line": content[-1], "seq": seqs.get(content[-1]), "at": self.at(now),
                              "epoch": self.epoch}
        markers = set()
        for i, (text, _) in enumerate(pairs, start=1):
            n = base + i
            if text.lstrip().startswith(MARKER):
                markers.add(n)
                history = n <= self.history_line
                hole = self._hole(now, "capture-failed", "line %d of the trace is a %s line: an event was not"
                                  " captured" % (n, MARKER), history)
                self.problem_events[n] = MARKER
                if not history:  # D-6: a live one is live, and knocks as RAQIB-SILENCE
                    status = self._knock(now, MARKER, "line %d" % n, (hole, "notice"))
                    self.problem_notices[n] = status
                    self._say(now, "%s at line %d: capture failed (%s)" % (MARKER, n, status))
        reasons = {}
        for p in problems:  # B-4: a live line that is not a sound record knocks, once per line
            if p["line"] > self.history_line and p["line"] not in markers:
                reasons.setdefault(p["line"], []).append(p["reason"])
        for n in sorted(reasons):  # D-6: their own rate-limit id, apart from the tail's holes
            self.problem_events[n] = HOLE
            status = self._knock(now, HOLE, "line %d" % n, (self.problem_notices, n), PARSE_LIMIT)
            self._say(now, "%s line %d: %s (%s)" % (HOLE, n, "; ".join(reasons[n]), status))
        if numbered or problems:
            self._judge(now)

    def key(self, finding):
        """B-2: two findings never share a key."""
        return (self.epoch, finding["rule_id"], finding["session_id"], tuple(finding["cited_seq"]),
                finding["summary"])

    def _grown(self, key, finding, keys):
        """The entry of the same rule and session that this finding grew
        from (its key is gone), moved to the new key; or None. Only a
        pending entry that was present until now is handed over; a settled
        or vanished one never is: a new key after it is a new finding (D-2)."""
        for old, entry in self.inventory.items():
            if (old not in keys and entry["epoch"] == self.epoch and entry["rule_id"] == finding["rule_id"]
                    and entry["session_id"] == finding["session_id"] and entry["present"]
                    and entry["state"] == "pending"):
                del self.inventory[old]
                entry["key"] = _key_list(key)
                entry["grown"] = entry.get("grown", 0) + 1
                self.inventory[key] = entry
                return entry
        return None

    def _judge(self, now):
        records = [rec for _, rec in self.numbered]
        self.found, self.notes = self.evaluate(records)
        calls, first_pre, last_close, line_of = {}, {}, {}, {}
        for n, rec in self.numbered:
            at = (rec["session_id"], rec["seq"])
            line_of[at] = n
            phase = rec.get("phase")
            if phase in ("pre", "post"):
                calls.setdefault(at, [0, 0])[phase == "post"] += 1
                if phase == "pre":
                    first_pre.setdefault(at, n)
            elif phase in silence.CLOSING:
                last_close[rec["session_id"]] = n
        current = [(self.key(f), f) for f in self.found]
        keys = {k for k, _ in current}
        for key, f in current:
            entry = self.inventory.get(key)
            if entry is None and f["rule_id"] in self.grows:
                entry = self._grown(key, f, keys)
            if entry is None:
                entry = self.inventory[key] = {"key": _key_list(key), "epoch": self.epoch, "first_seen": self.at(now),
                                               "notice": None, "state": "pending", "settled_by": None}
            cited_history = self.epoch == 0 and all(
                line_of.get((f["session_id"], s), 0) <= self.history_line for s in f["cited_seq"])
            entry.update({"rule_id": f["rule_id"], "class": f.get("class"), "severity": f["severity"],
                          "session_id": f["session_id"], "cited_seq": list(f["cited_seq"]),
                          "summary": f["summary"], "ts": f["ts"], "present": True, "cited_history": cited_history})
            if entry["state"] == "settled":
                continue
            entry["history"] = cited_history  # until it settles (D-5)
            by, line = self._settled_by(f, calls, first_pre, last_close)
            if by is not None:
                self._settle(entry, now, by, line)
        for key in list(self.inventory):
            entry = self.inventory[key]
            if entry["epoch"] == self.epoch and key not in keys:
                if entry["state"] == "pending":
                    del self.inventory[key]
                else:
                    entry["present"] = False

    def _settled_by(self, finding, calls, first_pre, last_close):
        """(None, None) while later lines can still take the finding back
        (B-1), else (what settled it, the line that did, or None when it is
        the finding's own cited lines)."""
        rule = finding["rule_id"]
        if rule == "SILENCE-OPEN":
            return None, None
        if rule == "SILENCE-HALF":
            at = (finding["session_id"], finding["cited_seq"][0])
            pres, posts = calls.get(at, (0, 0))
            if pres > posts:
                if last_close.get(at[0], 0) > first_pre.get(at, 0):
                    return "a later stop or session_end of its session", last_close[at[0]]
                return None, None
        return "its lines", None

    def _settle(self, entry, now, by, line=None):
        """Settle and knock. History is a finding settled by history: its
        cited lines, and the line that settled it, were all there at the
        start (D-5); a live settling line makes it live."""
        history = entry["cited_history"] and (line is None or (self.epoch == 0 and line <= self.history_line))
        entry["history"] = history
        if history:
            notice = HISTORY_NOTICE
        elif entry["severity"] == "high":
            notice = self._knock(now, entry["rule_id"], seq_text(entry["cited_seq"]), (entry, "notice"))
        else:
            notice = "not notified: severity %s" % entry["severity"]
        entry.update(state="settled", notice=notice, settled_by=by, settled_at=self.at(now))
        if not entry["history"]:
            self._say(now, "FINDING [%s] %s session %s %s: %s (%s%s)" % (
                entry["severity"], entry["rule_id"], entry["session_id"], seq_text(entry["cited_seq"]),
                entry["summary"], notice, "" if by == "its lines" else "; settled by " + by))

    def _silence(self, now):
        if self.window() is not None or now - self.last_at <= self.gap:
            return
        last = self.last_line
        if last is None:
            where = "no line since watch start"
        else:
            where = "after line %d" % last["line"] + (", seq %d" % last["seq"] if last["seq"] is not None else "")
        window = {"epoch": self.epoch, "since": self.at(self.last_at), "opened": self.at(now), "closed": None,
                  "seconds": None, "after": where, "closed_by_line": None, "closed_by_seq": None,
                  "notice_open": None, "notice_closed": None}
        self.windows.append(window)
        self._knock(now, LIVE + " open", where, (window, "notice_open"))
        self._say(now, "%s open: no line for more than %gs (%s) (%s)" % (LIVE, self.gap, where,
                                                                        window["notice_open"]))
        for entry in list(self.inventory.values()):  # B-1: pending for good is silence
            if entry["epoch"] == self.epoch and entry["present"] and entry["state"] == "pending":
                self._settle(entry, now, "the live silence window")

    def finish(self, now=None, status="finished", error=None):
        """Read what is left (the bytes after the last newline as a last
        line), mark pending findings, write the state; the final report.
        status "crashed" with error when an exception ended the watch (B-4).
        Nothing here may stop the final word (D-7): the state write, the
        report and the summary are each guarded, and final_text holds the
        final report or a one-line reason it could not be built."""
        with self.lock:
            now = self.clock() if now is None else now
            try:
                self._poll(now)
                rest = self.tail.rest()
                if rest:
                    self._take(rest, now, terminated=False)
            except Exception as exc:
                status = "crashed"
                error = "%s%s while finishing: %s" % (error + "; " if error else "", type(exc).__name__, exc)
            for entry in self.inventory.values():
                if entry["state"] == "pending":
                    entry["state"] = "pending at exit"
            self.status, self.error = status, error
            self.finished = self.at(now)
            self.beat = now
            try:
                self._write_state(now)
            except Exception as exc:
                self.state_error = "cannot write %s: %s: %s" % (self.state_path, type(exc).__name__, exc)
        rep, body = None, None
        try:
            rep = self.report()[0]
            body = report.render_text(rep)
        except Exception as exc:
            body = "raqib watch: no final report: it could not be built (%s: %s)\n" % (type(exc).__name__,
                                                                                      _safe(exc))
        try:
            summary = self.summary_text()
        except Exception as exc:
            summary = "raqib watch: no watch summary: it could not be built (%s: %s)\n\n" % (
                type(exc).__name__, _safe(exc))
        self.final_text = summary + body
        self.final_exit = rep["exit"] if rep is not None and body.startswith("Raqib report") else 1
        return rep

    # --- what is shown ---------------------------------------------------------

    def alarms(self):
        """Watch's own alarms for the report: a crash, silence windows,
        holes, the findings of trace content that is gone, an unwritable
        state file."""
        out = []
        if self.status == "crashed":
            out.append({"kind": "watch-crashed", "detail": "the watch ended on an exception: %s" % self.error})
        for w in self.windows:
            if w["closed"] is None:
                detail = "no line since %s (%s; limit %gs): still open%s" % (
                    w["since"], w["after"], self.gap, " at exit" if self.finished else "")
            else:
                detail = "no line from %s to %s (%.1fs; limit %gs) %s; closed by line %d" % (
                    w["since"], w["closed"], w["seconds"], self.gap, w["after"], w["closed_by_line"])
            out.append({"kind": "silence-window", "detail": detail})
        for h in self.holes + self.notifier.holes:
            more = " (%d times, last at %s)" % (h["count"], h["last"]) if h.get("count", 1) > 1 else ""
            past = " (history)" if h.get("history") else ""
            out.append({"kind": h["kind"], "detail": "%s at %s%s%s" % (h["detail"], h["at"], more, past)})
        for e in self.inventory.values():
            if e["epoch"] != self.epoch and e["state"] == "settled":
                out.append({"kind": "finding-before-hole", "detail": "%s [%s] session %s %s, seen at %s in trace"
                            " content that is gone (epoch %d): %s" % (
                                e["rule_id"], e["severity"], e["session_id"], seq_text(e["cited_seq"]),
                                e["first_seen"], e["epoch"], e["summary"])})
        if self.state_error:
            out.append({"kind": "state-unwritable", "detail": self.state_error})
        return out

    def band(self, now=None):
        now = self.clock() if now is None else now
        window = self.window()
        if self.status == "crashed":
            items = [("alarm", "CRASHED: %s" % self.error)]
        elif self.finished:
            items = [("incomplete", "finished at %s" % self.finished)]
        elif now - self.beat > STALE_SECONDS:
            items = [("alarm", "CRASHED or stuck: no heartbeat for %d s (last at %s)" % (now - self.beat,
                                                                                      self.at(self.beat)))]
        elif window is not None:
            items = [("alarm", "SILENT for %d s (no line since %s)" % (now - self.last_at, window["since"]))]
        else:
            items = [("clean", "watching %s: %d lines" % (self.name, self.lines))]
        items.append(self.notifier.band())
        holes = len(self.holes) + len(self.notifier.holes)
        if holes:
            items.append(("alarm", "%d holes (see the alarms)" % holes))
        if self.port and self.port.get("warning"):
            items.append(("incomplete", self.port["warning"]))
        return items

    def _snapshot(self):
        return (list(self.numbered), list(self.problems), list(self.found), list(self.notes), self.alarms())

    def _build(self, numbered, problems, found, notes, extra):
        return report.build(self.trace_path, numbered, problems, found, notes, report.rule_table(self.rules),
                            SOURCE, extra_alarms=extra)

    def report(self):
        """(report, numbered, problems) of what was read so far."""
        with self.lock:
            numbered, problems, found, notes, extra = self._snapshot()
        return self._build(numbered, problems, found, notes, extra), numbered, problems

    def page(self):
        """The page ui.make_server serves: the report so far and the band.
        A watch loop that holds the state too long is reported, not waited
        for (B-4): the server answers with its error page."""
        if not self.lock.acquire(timeout=PAGE_LOCK_SECONDS):
            raise RuntimeError("raqib watch is not responding: its watch loop has held the state for more than"
                               " %gs (last heartbeat %s); it may be stuck or crashed (A3)"
                               % (PAGE_LOCK_SECONDS, self.at(self.beat)))
        try:
            numbered, problems, found, notes, extra = self._snapshot()
            band = self.band()
        finally:
            self.lock.release()
        rep = self._build(numbered, problems, found, notes, extra)
        return ui.render(rep, numbered, problems, self.gap, band=band)

    def state(self, now):
        window = self.window()
        if self.finished:
            status = self.status
        else:
            status = "silent" if window else "watching"
        return {
            "raqib_watch": 1, "project": self.project, "trace": self.trace_path, "state": self.state_path,
            "pid": os.getpid(), "url": self.url, "port": self.port, "scope": self.scope,
            "started": self.at(self.t0), "updated": self.at(now), "heartbeat": self.at(self.beat),
            "heartbeat_every_seconds": POLL_SECONDS, "stale_after_seconds": STALE_SECONDS,
            "finished": self.finished, "error": self.error, "gap_seconds": self.gap, "poll_seconds": POLL_SECONDS,
            "status": status, "epoch": self.epoch, "lines": self.lines, "records": len(self.numbered),
            "history": {"bytes": self.history_bytes if self.epoch == 0 else 0, "lines": self.history_line,
                        "prior_findings": sum(1 for e in self.inventory.values() if e["history"])},
            "problems": len(self.problems),
            "trace_problems": [self._problem(p) for p in self.problems],
            "last_line": self.last_line, "findings": list(self.inventory.values()), "silence": self.windows,
            "holes": self.holes + self.notifier.holes, "notifications": self.notifier.state(),
        }

    def _problem(self, p):
        """A parse problem as watch.json holds it: live or history, and how it knocked (D-6)."""
        history = self.epoch == 0 and p["line"] <= self.history_line
        return dict(p, history=history, knocked_as=None if history else self.problem_events.get(p["line"]),
                    notice=HISTORY_NOTICE if history else self.problem_notices.get(p["line"]))

    def _write_state(self, now):
        text = json.dumps(self.state(now), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".raqib-watch-", suffix=".tmp",
                                       dir=os.path.dirname(os.path.abspath(self.state_path)))
            with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
            os.replace(tmp, self.state_path)
            tmp = None
            self.state_error = None
        except OSError as exc:
            detail = "cannot write %s: %s" % (self.state_path, exc.strerror or exc)
            if detail != self.state_error:
                (self.err or sys.stderr).write("raqib watch: %s\n" % detail)
            self.state_error = detail
        finally:
            if tmp is not None and os.path.exists(tmp):
                os.remove(tmp)

    def summary_text(self):
        """The watch part of the final report."""
        with self.lock:
            alarms = self.alarms()
            entries = list(self.inventory.values())
            notifier = self.notifier.state()
            band = self.notifier.band()[1].replace("notifications: ", "", 1)
        out = ["Raqib watch", "project: %s" % self.project, "trace: %s" % self.trace_path,
               "state: %s (%s)" % (self.state_path, self.status),
               "scope: %s" % (self.scope or "-"),
               "watched: %s to %s; %d lines read in this trace content; %d trace resets"
               % (self.at(self.t0), self.finished or "-", self.lines, self.epoch)]
        if self.port and self.port.get("warning"):
            out.append("WARNING: %s" % self.port["warning"])
        out.append("")
        windows = [a for a in alarms if a["kind"] == "silence-window"]
        out.append("LIVE SILENCE WINDOWS (A3, limit %gs): %d" % (self.gap, len(windows)))
        out += ["  - %s" % a["detail"] for a in windows]
        holes = [a for a in alarms if a["kind"] != "silence-window"]
        out.append("HOLES (A3): %d" % len(holes))
        out += ["  - %s: %s" % (a["kind"], a["detail"]) for a in holes]
        out.append("PRIOR FINDINGS (history, in the trace at the start, not knocked): %d"
                   % sum(1 for e in entries if e["history"]))
        live = [e for e in entries if not e["history"]]
        settled = [e for e in live if e["state"] == "settled"]
        out.append("FINDINGS SEEN LIVE: %d settled, %d pending at exit" % (
            len(settled), sum(1 for e in live if e["state"] == "pending at exit")))
        out += ["  [%s] %s session %s %s: %s%s" % (
            e["severity"], e["rule_id"], e["session_id"], seq_text(e["cited_seq"]), e["notice"],
            "" if e["settled_by"] == "its lines" else " (settled by %s)" % e["settled_by"]) for e in settled]
        counts = notifier["counts"]
        out.append("NOTIFICATIONS: %s; sent %d, terminal %d, failed %d, folded %d (%d still waiting), off %d"
                   % (band, counts["sent"], counts["terminal"], counts["failed"], counts["folded"],
                      sum(notifier["folded_waiting"].values()), counts["off"]))
        return "\n".join(_safe(line) for line in out) + "\n\n"


# --- the command ------------------------------------------------------------------

def load_installer():
    """tools/install_hooks.py of this checkout, as a module (its API)."""
    spec = importlib.util.spec_from_file_location("raqib_install_hooks", INSTALLER)
    if spec is None or spec.loader is None:
        raise WatchError("cannot load %s" % INSTALLER)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as exc:
        raise WatchError("cannot load %s: %s" % (INSTALLER, exc))
    return module


def inside(path, root):
    """True when path is root or under it (symlinks resolved)."""
    path = os.path.normcase(os.path.realpath(path))
    root = os.path.normcase(os.path.realpath(root))
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # another drive
        return False


def default_trace(project, home=None):
    home = home or os.path.expanduser("~")
    digest = hashlib.sha256(project.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return os.path.join(home, ".raqib", "traces", "%s-%s" % (notify.project_name(project), digest), TRACE_NAME)


def choose_trace(installer, project, log=None, home=None):
    """(trace, source, notes): --log, else the earlier install's trace if
    it is outside the project, else default_trace()."""
    if log:
        path = os.path.normpath(installer.absolute_log(log))
        if inside(path, project):
            raise WatchError("--log %s is inside the project %s; watch writes nothing into the project but"
                             " the hook settings: choose a path outside it" % (path, project))
        if os.path.isdir(path):
            raise WatchError("--log %s is a directory" % path)
        return path, "--log", []
    try:
        kept = installer.installed_traces(project)
    except installer.Exit as exc:
        raise WatchError(exc.message or "cannot read the hook settings of %s" % project)
    outside = [k for k in kept if not inside(k, project)]
    if len(outside) > 1:
        raise WatchError("the Raqib hooks of %s write to different traces (%s); pass --log to choose one"
                         % (project, ", ".join(outside)))
    if outside:
        path, source = outside[0], "kept from the existing install"
    else:
        path, source = default_trace(project, home), "watch default, outside the project"
        if inside(path, project):
            raise WatchError("the default trace %s would be inside the project %s; pass --log PATH outside it"
                             % (path, project))
    notes = ["the trace an earlier install chose, %s, is inside the project; capture moves to %s, because"
             " watch writes nothing into the project but the hook settings (the old file is left as it is)"
             % (k, path) for k in kept if inside(k, project)]
    return path, source, notes


def open_page(url, environ=None, platform=None, isfile=None, runner=None, isdir=None):
    """Open the page once in the browser, by absolute path; None, or why not.
    On Windows SystemRoot is checked as notify checks it (D-3)."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    isfile = isfile or os.path.isfile
    runner = runner or notify.run_program
    if platform == "win32":
        root, why = notify.windows_root(environ, isdir)
        if root is None:
            return why
        program = ntpath.join(root, "explorer.exe")
        env = {"SystemRoot": root}
    elif platform == "darwin":
        program, env = MAC_OPENER, {}
    else:
        program = next((p for p in OPENERS if isfile(p)), None)
        env = {"PATH": OPENER_PATH}
        env.update({k: environ[k] for k in OPENER_ENV if environ.get(k)})
    if not program or not isfile(program):
        return "no %s" % (program or " or ".join(OPENERS))
    return runner([program, url], env, None, wait=False)[1]


def _serve(page, port):
    """(server, port record). A requested port (--port N, else DEFAULT_PORT)
    that cannot be bound gives another port and a warning, never silence
    (B-7); OverflowError (no such port) is the caller's usage error."""
    requested = DEFAULT_PORT if port is None else port
    try:
        server = ui.make_server(page, requested)
        return server, {"requested": requested, "used": server.server_address[1], "warning": None}
    except OSError as exc:
        why = exc.strerror or str(exc)
    server = ui.make_server(page, 0)
    used = server.server_address[1]
    return server, {"requested": requested, "used": used,
                    "warning": "port %d on 127.0.0.1 is not available (%s); the page is on port %d instead"
                               % (requested, why, used)}


def command(project, log, no_open, no_notify, port, out, evaluator, rules, gap_seconds, environ=None,
            err=None, home=None):
    """raqib watch; returns the exit code of the final report.
    evaluator(project) -> (evaluate, scope note): evaluate(records) gives
    (findings, notes) with the project's context (B-6)."""
    environ = os.environ if environ is None else environ
    err = err or sys.stderr
    project = project or "."
    if not os.path.isdir(project):
        raise WatchError("not a directory: %s" % project)
    installer = load_installer()
    project = installer.absolute(project)
    evaluate, scope = evaluator(project)
    trace_path, source, notes = choose_trace(installer, project, log, home)
    out.write("raqib watch: project %s\n" % _safe(project))
    for note in notes:
        out.write("raqib watch: note: %s\n" % _safe(note))
    try:
        os.makedirs(os.path.dirname(trace_path), exist_ok=True)
    except OSError as exc:
        raise WatchError("cannot create the trace directory %s: %s" % (os.path.dirname(trace_path), exc))
    try:
        installed = installer.install_project(project, log=trace_path, log_source=source, out=out, err=err)
    except installer.Exit as exc:
        raise WatchError("%s (install-hooks exit %d)" % (exc.message or "the hooks were not installed", exc.code))
    notifier = notify.Notifier(project, enabled=not no_notify, reason="--no-notify" if no_notify else None,
                               environ=environ, stderr=err)
    watcher = Watch(project, trace_path, evaluate, rules, gap_seconds, notifier, out=out, err=err)
    watcher.scope = scope
    out.write("raqib watch: trace %s (%s)\nraqib watch: state %s\n" % (_safe(trace_path), source,
                                                                      _safe(watcher.state_path)))
    out.write("raqib watch: scope: %s\n" % _safe(scope))  # D-7: the agent can write HANDOFF.md
    out.write("raqib watch: silence limit %gs (RAQIB_GAP_SECONDS); polling every %gs\n" % (gap_seconds, POLL_SECONDS))
    out.write("raqib watch: %s\n" % notifier.band()[1])
    if installed["code"] == 3:
        watcher.capture_off("the installer reports disableAllHooks: the hooks will not run")
    try:
        server, watcher.port = _serve(watcher.page, port)
    except (OSError, OverflowError) as exc:
        notifier.close()
        raise WatchError("cannot serve on 127.0.0.1:%s: %s" % (port, exc))
    watcher.url = "http://127.0.0.1:%d/" % server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, name="raqib-watch-page", daemon=True)
    thread.start()
    crash = None
    try:
        try:
            if watcher.port["warning"]:
                out.write("raqib watch: WARNING: %s\n" % watcher.port["warning"])
            out.write("raqib watch: page %s (read-only; Ctrl-C stops the watch and prints the final report)\n"
                      % watcher.url)
            if no_open or environ.get("CI"):
                out.write("raqib watch: page not opened (%s)\n" % ("--no-open" if no_open else "CI is set"))
            else:
                why = open_page(watcher.url, environ)
                if why:
                    out.write("raqib watch: page not opened (%s); open it by hand\n" % why)
            out.flush()
            watcher.step()
            while True:
                _sleep(POLL_SECONDS)
                watcher.step()
        except KeyboardInterrupt:
            out.write("\nraqib watch: stopped (Ctrl-C)\n")
        except Exception as exc:  # B-4: the watcher's own failure ends in the final report
            crash = "%s: %s" % (type(exc).__name__, exc)
            out.write("\nraqib watch: CRASHED: %s\n" % _safe(crash))
            traceback.print_exc(file=err)
        try:
            watcher.finish(status="crashed" if crash else "finished", error=crash)
            text, code = watcher.final_text, watcher.final_exit
        except Exception as exc:  # D-7: a final report, or one line saying why there is none
            text, code = "raqib watch: no final report: %s: %s\n" % (type(exc).__name__, _safe(exc)), 1
    finally:
        server.shutdown()
        server.server_close()
        notifier.close()
    out.write("\n" + text)
    return code
