"""raqib watch (M6.1, ADR-0005 decision 1, Amendments A and B): one command
watches a project.

`raqib watch [PROJECT]` installs the capture hooks with raqib/install.py
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
After a session_end, while it is the newest record, no live window opens
until the next line: the agent is gone, and the band says AGENT GONE (I-2).
Capture fails while the newest line is a RAQIB-SILENCE marker, or from the
start when the hook check (raqib doctor's, read-only) finds the hooks
missing or foreign; the next good record clears it, "recovered at seq N"
(I-3).

The page (M6.2, ADR-0005 Amendment I) is ui.render of the state this
watch holds in memory (I-4), reloaded every --refresh seconds, with
GET /discover for <trace dir>/discover.json. Each watch adds one row
(pid, project, port, trace, state, started) to ~/.raqib/watches.json once
its page is bound, and marks it finished at the end; the row is never
removed (A3, I-5). The registry is written under an O_EXCL lock file, which
is broken when it is older than LOCK_STALE_SECONDS, with a note in the row.
A registry that is not one is left as it is and becomes a hole, and one
that would lie inside the project (watching a home) is not written (J-4).
The heartbeat and "updated" are wall time (time.time(), J-5); intervals
(silence, a stale heartbeat, step_seconds) are measured on the monotonic
clock. A start-time capture failure is cleared only by a live good record
(J-2); AGENT GONE also needs every started session closed (J-3).
Settled findings of severity high are notified (ADR-0005); the others are
shown. Notifications are rate-limited by raqib/notify.py. Every finding
entry carries its rule's kind; one without a kind is printed once as a
"NOTICE no-kind" line, and the report raises it as a no-kind alarm
(ADR-0002 B-3).
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
import ntpath
import os
import sys
import tempfile
import threading
import time
import traceback

from raqib import install, notify, overlay, report, ui
from raqib.rules import silence, trace

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
REGISTRY_NAME = "watches.json"   # under ~/.raqib (I-5)
LOCK_STALE_SECONDS = 10          # an older registry lock is broken, with a note in the row (I-5)
LOCK_WAIT_SECONDS = LOCK_STALE_SECONDS + 1
LOCK_POLL_SECONDS = 0.05
REPLACE_TRIES = 20               # Windows: os.replace fails while a reader has the file open
HEARTBEATS_FRESH = 3             # I-6: ALIVE needs a heartbeat younger than 3 heartbeat intervals
STATE_RETRIES = 3                # J-13: watch.json's os.replace is retried 3 times, 50 ms apart
STATE_RETRY_SECONDS = 0.05
OPENERS = ("/usr/bin/xdg-open", "/bin/xdg-open")
MAC_OPENER = "/usr/bin/open"
# xdg-open is a shell script that finds the browser through PATH: it gets
# the system directories, not the PATH of the shell watch was started from.
OPENER_PATH = "/usr/local/bin:/usr/bin:/bin"
OPENER_ENV = ("HOME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
              "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "DESKTOP_SESSION")

_sleep = time.sleep  # the poll wait; tests replace it
_retry_sleep = time.sleep  # the wait between os.replace attempts; tests replace it


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
                 err=None, clock=None, started=None, state_path=None, wall=None):
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
        self.ever_read = False    # M8.1 REDO C-1: whether this watch ever read a line, whatever came after
        self.numbered, self.problems = [], []
        self.problem_notices = {}  # line -> notice of a live parse problem or RAQIB-SILENCE line
        self.problem_events = {}   # line -> the event it knocked as
        self.found, self.notes = evaluate([])
        self.inventory = {}   # key -> finding entry, in the order first seen
        self.windows = []     # live silence windows
        self.holes = []
        self.last_line = None
        self.last_at = self.t0
        self.beat = self.t0       # the last completed poll (B-4), monotonic: for intervals
        self.wall_clock = wall or time.time   # J-5: the heartbeat and "now" are wall time
        self.beat_wall = self.wall_clock()
        self.step_seconds = 0.0   # J-5: how long the last step took
        self.url = None
        self.port = None          # {"requested", "used", "warning"} (B-7)
        self.scope = None         # where the rules' scope came from (B-6)
        self.status = "watching"
        self.error = None
        self.finished = None
        self.state_error = None
        self.final_text, self.final_exit = None, None
        self.refresh = ui.REFRESH_DEFAULT   # I-1: the page's reload, --refresh
        # I-3, J-2: "start" (hooks at start) clears only on a live good record; "marker" on any good record.
        self.capture = {"failed": None, "line": None, "since": None, "recovered": None, "hooks": None,
                        "start": None, "marker": None}
        self.registry = None      # the Registry this watch is a row of (I-5)
        self.registry_state = None
        self.first_knock = None   # ADR-0006 A-12: the FirstFinding record of this watch, once it knocked
        # M7.6 (ADR-0008): the overlay this watch started with, and what each rule off did not judge (A3, A6)
        self.rules_overlay = overlay.describe(rules)
        self.off_rules = [r for r in rules if r.status == "disabled"]
        self.not_judged = {}

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
            begin = self.clock()
            now = begin if now is None else now
            self._poll(now)
            self._silence(now)
            for event, count, status in self.notifier.tick(now):
                self._say(now, "%s: %d more, folded into one notification (%s)" % (event, count, status))
            self.beat = now
            self.beat_wall = self.wall_clock()
            self.step_seconds = round(max(0.0, self.clock() - begin), 3)
            self._write_state(now)

    def capture_off(self, detail, now=None):
        """Capture will not run (the installer said so): a hole, notified."""
        with self.lock:
            now = self.clock() if now is None else now
            hole = self._hole(now, "capture-failed", detail)
            status = self._knock(now, MARKER, "hooks disabled", (hole, "notice"))
            self._say(now, "%s: %s (%s)" % (MARKER, detail, status))
            self._capture_failed(now, detail, start=True)

    def hooks_at_start(self, ok, detail, kinds=(), now=None):
        """I-3: the hook check of raqib doctor (read-only) after the install.
        kinds (J-9): which of "disabled", "missing", "foreign" (or
        "unchecked") it found. A failure here is a start-time failure: only
        a live good record clears it (J-2)."""
        with self.lock:
            now = self.clock() if now is None else now
            which = "/".join(kinds) or "missing or foreign"
            self.capture["hooks"] = {"ok": bool(ok), "detail": detail, "kinds": list(kinds)}
            if ok:
                return
            if not any(h["kind"] == "capture-failed" and not h["history"] for h in self.holes):
                hole = self._hole(now, "capture-failed", "hooks %s at start: %s" % (which, detail))
                status = self._knock(now, MARKER, "hooks at start", (hole, "notice"))
                self._say(now, "%s: hooks %s at start: %s (%s)" % (MARKER, which, detail, status))
            self._capture_failed(now, "hooks %s at start: %s" % (which, detail), start=True)

    def _capture_failed(self, now, why, line=None, start=False):
        self.capture["start" if start else "marker"] = {"why": why, "line": line, "since": self.at(now)}
        self.capture["recovered"] = None
        self._capture_view()

    def _capture_good(self, now, line, seq, live):
        """I-3: a good record clears a marker's failure; J-2: a start-time
        failure is cleared only by a live one, never by history."""
        cleared = False
        if self.capture["marker"]:
            self.capture["marker"], cleared = None, True
        if self.capture["start"] and live:
            self.capture["start"], cleared = None, True
        if cleared and not (self.capture["marker"] or self.capture["start"]):
            self.capture["recovered"] = {"seq": seq, "line": line, "at": self.at(now)}
        self._capture_view()

    def _capture_view(self):
        """failed, line and since as the band reads them: the start-time failure first."""
        parts = [p for p in (self.capture["start"], self.capture["marker"]) if p]
        self.capture.update(failed="; ".join(p["why"] for p in parts) or None,
                            line=self.capture["marker"]["line"] if self.capture["marker"] else None,
                            since=parts[0]["since"] if parts else None)

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
        self.ever_read = self.ever_read or bool(lines)   # M8.1 REDO C-1
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
            ts_of = {n: rec.get("ts") for n, rec in numbered}
            self.last_line = {"line": content[-1], "seq": seqs.get(content[-1]), "at": self.at(now),
                              "ts": ts_of.get(content[-1]), "epoch": self.epoch}
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
        for n in content:  # I-3: a marker fails capture; the next good record clears it
            if n in markers:
                self._capture_failed(now, "line %d of the trace is a %s marker: an event was not captured" % (
                    n, MARKER), n)
            elif n in seqs:
                self._capture_good(now, n, seqs[n], live=n > self.history_line)
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
        if self.off_rules:   # M7.6: run anyway, counted, never a finding (ADR-0008 decision 3)
            self.not_judged = overlay.count_not_judged(self.off_rules, records,
                                                       getattr(self.evaluate, "context", None) or {}, {})
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
                if f.get("kind") is None:  # ADR-0002 B-3: a finding without a kind is said, once (A3)
                    self._say(now, "NOTICE no-kind: %s session %s %s has no kind (ADR-0002); the report raises a"
                                   " no-kind alarm" % (f["rule_id"], f["session_id"], seq_text(f["cited_seq"])))
            cited_history = self.epoch == 0 and all(
                line_of.get((f["session_id"], s), 0) <= self.history_line for s in f["cited_seq"])
            entry.update({"rule_id": f["rule_id"], "class": f.get("class"), "kind": f.get("kind"),
                          "severity": f["severity"], "session_id": f["session_id"], "cited_seq": list(f["cited_seq"]),
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

    def open_sessions(self):
        """Sessions of this trace content that started and whose last record
        is not a stop or session_end (J-3)."""
        started, last = set(), {}
        for _, rec in self.numbered:
            if rec.get("phase") == "session_start":
                started.add(rec["session_id"])
            last[rec["session_id"]] = rec.get("phase")
        return sorted(sid for sid in started if last.get(sid) not in silence.CLOSING)

    def agent_gone(self):
        """I-2, J-3: the newest line of this trace content is a session_end
        record and no session is open: {line, seq, session_id, at, ts}, else
        None. With a session still open, silence is judged as before."""
        last = self.last_line
        if last is None or last["epoch"] != self.epoch or not self.numbered:
            return None
        number, rec = self.numbered[-1]
        if number != last["line"] or rec.get("phase") != "session_end" or self.open_sessions():
            return None
        return {"line": number, "seq": rec["seq"], "session_id": rec["session_id"], "at": last["at"],
                "ts": rec.get("ts")}

    def _silence(self, now):
        # I-2: after a session_end no window opens until the next line.
        if self.window() is not None or now - self.last_at <= self.gap or self.agent_gone() is not None:
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
            self.beat_wall = self.wall_clock()
            try:
                self._write_state(now)
            except Exception as exc:
                self.state_error = "cannot write %s: %s: %s" % (self.state_path, type(exc).__name__, exc)
        rep, body = None, None
        try:
            rep = self.report()[0]
            body = report.render_text(rep)
            if rep["result"] == "clean" and overlay.suppressed(self.not_judged):   # M7.6 REDO A-2: not "CLEAN" alone
                body = body.replace("RESULT: CLEAN (exit", "RESULT: %s (exit" % overlay.clean_word(
                    "CLEAN", self.not_judged), 1)
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

    def status_word(self, now=None):
        """(word, level, detail) of the band (I-3), from the state in memory."""
        with self.lock:
            return ui.status(self.state(self.clock() if now is None else now))

    def band(self, now=None):
        """The band's badges: the state word, the notifier, the holes."""
        with self.lock:
            return ui.band_items(self.state(self.clock() if now is None else now))

    def _snapshot(self):
        return (list(self.numbered), list(self.problems), list(self.found), list(self.notes), self.alarms())

    def _build(self, numbered, problems, found, notes, extra):
        return report.build(self.trace_path, numbered, problems, found, notes, report.rule_table(self.rules),
                            SOURCE, extra_alarms=extra)

    def code_so_far(self):
        """M8.1 REDO B-4 (ADR-0009 Amendment B): the exit code this watch would
        end with if it were stopped now: the exit of its report of what was
        read so far (report.build, the report finish() keeps), built again only
        when what it reads has changed. finish() may still read the last bytes
        and mark pending findings. A report that cannot be built is 1, as in
        finish(). The caller holds the lock (state() is read under it).
        M8.1 REDO C-2: why a code could not be computed is kept in
        code_error (the state's field beside the code), and alarms() and the
        key are inside the guard: the watch says it, and goes on."""
        try:
            alarms = self.alarms()
            key = (len(self.numbered), len(self.problems), len(self.found), repr(self.notes), repr(alarms))
            cached = getattr(self, "_code_key", None)
            if cached is not None and cached[0] == key:
                self.code_error = cached[2]
                return cached[1]
            try:
                code, error = self._build(list(self.numbered), list(self.problems), list(self.found),
                                          list(self.notes), alarms)["exit"], None
            except Exception as exc:
                code, error = 1, "%s: %s" % (type(exc).__name__, exc)
            self._code_key = (key, code, error)
        except Exception as exc:
            code, error = 1, "%s: %s" % (type(exc).__name__, exc)
        self.code_error = error
        return code

    def report(self):
        """(report, numbered, problems) of what was read so far."""
        with self.lock:
            numbered, problems, found, notes, extra = self._snapshot()
        return self._build(numbered, problems, found, notes, extra), numbered, problems

    def wall(self):
        """Now, by the wall clock (J-5), as an aware datetime."""
        return datetime.datetime.fromtimestamp(self.wall_clock(), datetime.timezone.utc)

    def own(self):
        """This watch's registry row key: (pid, trace, started)."""
        return os.getpid(), self.trace_path, self.at(self.t0)

    def page(self):
        """The page ui.make_server serves: the report so far, the band and
        the watches, built from the state in memory (I-4); the other watches
        from the registry on disk. A watch loop that holds the state too
        long is reported, not waited for (B-4): the server answers with its
        error page."""
        if not self.lock.acquire(timeout=PAGE_LOCK_SECONDS):
            raise RuntimeError("raqib watch is not responding: its watch loop has held the state for more than"
                               " %gs (last heartbeat %s); it may be stuck or crashed (A3)"
                               % (PAGE_LOCK_SECONDS, self.at(self.beat)))
        try:
            numbered, problems, found, notes, extra = self._snapshot()
            now = self.clock()
            state = copy.deepcopy(self.state(now))
            registry = self.registry.path if self.registry else None
            own = dict(self.registry_state or {})
        finally:
            self.lock.release()
        rep = self._build(numbered, problems, found, notes, extra)
        watches = None
        if registry:
            watches = ui.read_watches(registry, self.wall(), HEARTBEATS_FRESH * POLL_SECONDS, own=self.own())
        return ui.render(rep, numbered, problems, self.gap, refresh=self.refresh,
                         live={"state": state, "watches": watches, "own": own}, discover=ui.DISCOVER_ROUTE)

    def discover_page(self):
        """GET /discover (I-8): <trace dir>/discover.json, with its age."""
        return ui.discover_page(ui.discover_path(self.trace_path), self.refresh, self.wall())

    # --- the registry (I-5) --------------------------------------------------------

    def register(self, registry, now=None):
        """This watch's row, once the page is bound (serve wiring); never
        raises: a registry that cannot be written is a hole."""
        row = {"pid": os.getpid(), "project": self.project, "port": (self.port or {}).get("used"),
               "trace": self.trace_path, "state": self.state_path, "url": self.url, "started": self.at(self.t0),
               "finished": None, "status": "watching", "notes": []}

        def edit(rows, note):
            rows.append(dict(row, notes=[note] if note else []))
        self.registry = registry
        return self._registry_change(edit, "registered", now)

    def unregister(self, now=None):
        """At the end: this watch's row is marked finished, never removed (A3)."""
        if self.registry is None:
            return None
        own = self.own()

        def edit(rows, note):
            mine = [r for r in rows if isinstance(r, dict) and (r.get("pid"), r.get("trace"), r.get("started")) == own]
            for r in mine:
                r.update(finished=self.finished, status=self.status)
                if note:
                    r["notes"] = (r["notes"] if isinstance(r.get("notes"), list) else []) + [note]
            if not mine:
                rows.append({"pid": own[0], "project": self.project, "port": (self.port or {}).get("used"),
                             "trace": self.trace_path, "state": self.state_path, "url": self.url,
                             "started": own[2], "finished": self.finished, "status": self.status,
                             "notes": ["this row was not in the registry at the end: added again"] +
                                      ([note] if note else [])})
        return self._registry_change(edit, "marked %s" % self.status, now)

    def registry_off(self, path, why, now=None):
        """J-4: the registry is not written; the hole is in the band and the alarms."""
        with self.lock:
            now = self.clock() if now is None else now
            self.registry = None
            self.registry_state = {"path": path, "row": "not written", "note": None, "hole": why}
            h = self._hole(now, "registry", why)
            h["notice"] = "not knocked: the registry is not capture"
            self._write_state(now)
        return why

    def _registry_change(self, edit, what, now=None):
        try:
            note, hole = self.registry.change(edit)
        except Exception as exc:  # never the end of the watch: a hole
            note, hole = None, "the registry %s was not written (%s): %s" % (
                self.registry.path, what, getattr(exc, "strerror", None) or exc)
        with self.lock:
            now = self.clock() if now is None else now
            self.registry_state = {"path": self.registry.path, "row": what, "note": note, "hole": hole}
            if hole:
                h = self._hole(now, "registry", hole)
                h["notice"] = "not knocked: the registry is not capture"
            self._write_state(now)
        return hole

    def state(self, now):
        window = self.window()
        if self.finished:
            status = self.status
        else:
            status = "silent" if window else "watching"
        state = {
            "raqib_watch": 1, "project": self.project, "trace": self.trace_path, "state": self.state_path,
            "pid": os.getpid(), "url": self.url, "port": self.port, "scope": self.scope,
            "started": self.at(self.t0), "updated": ui._iso(self.wall()),
            "heartbeat": ui._iso(datetime.datetime.fromtimestamp(self.beat_wall, datetime.timezone.utc)),
            "heartbeat_age_seconds": round(now - self.beat, 3), "quiet_seconds": round(now - self.last_at, 3),
            "step_seconds": self.step_seconds,
            "heartbeat_every_seconds": POLL_SECONDS, "stale_after_seconds": STALE_SECONDS,
            "finished": self.finished, "error": self.error, "gap_seconds": self.gap, "poll_seconds": POLL_SECONDS,
            "status": status, "epoch": self.epoch, "lines": self.lines, "records": len(self.numbered),
            "history": {"bytes": self.history_bytes if self.epoch == 0 else 0, "lines": self.history_line,
                        "prior_findings": sum(1 for e in self.inventory.values() if e["history"])},
            "problems": len(self.problems),
            "trace_problems": [self._problem(p) for p in self.problems],
            "last_line": self.last_line, "findings": list(self.inventory.values()), "silence": self.windows,
            "holes": self.holes + self.notifier.holes, "notifications": self.notifier.state(),
            "capture": self.capture, "agent_gone": self.agent_gone(), "open_sessions": self.open_sessions(),
            "state_error": self.state_error, "refresh_seconds": self.refresh, "registry": self.registry_state,
            "first_knock": dict(self.first_knock) if self.first_knock else None,   # A-12
            "rules_overlay": dict(self.rules_overlay, not_judged=self.not_judged),   # M7.6 (ADR-0008)
        }
        state["band"] = ui.status(state)[0]   # J-6: the owner's state word, for the pages of other watches
        state["code_so_far"] = self.code_so_far()   # M8.1 REDO B-4: the code of what has been read so far
        state["code_error"] = self.code_error        # M8.1 REDO C-2: why that code could not be computed, or None
        state["ever_read"] = self.ever_read          # M8.1 REDO C-1: whether a line was ever read (lines: this content's)
        return state

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
            for attempt in range(STATE_RETRIES + 1):   # J-13: Windows refuses while a page reads the file
                try:
                    os.replace(tmp, self.state_path)
                    break
                except PermissionError:
                    if attempt == STATE_RETRIES:
                        raise
                    _retry_sleep(STATE_RETRY_SECONDS)
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
        rules_off = overlay.report_lines(self.rules_overlay, self.not_judged)   # M7.6 (ADR-0008 decision 3)
        first = bool(overlay.suppressed(self.not_judged))   # REDO A-2: first when it suppressed anything
        if first:
            out += rules_off
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
        if not first:
            out += rules_off
        counts = notifier["counts"]
        out.append("NOTIFICATIONS: %s; sent %d, terminal %d, failed %d, folded %d (%d still waiting), off %d"
                   % (band, counts["sent"], counts["terminal"], counts["failed"], counts["folded"],
                      sum(notifier["folded_waiting"].values()), counts["off"]))
        return "\n".join(_safe(line) for line in out) + "\n\n"


# --- the registry of watches (I-5) --------------------------------------------------

class RegistryError(Exception):
    """The registry lock could not be taken."""


def registry_path(home=None):
    return os.path.join(home or os.path.expanduser("~"), ".raqib", REGISTRY_NAME)


class Registry:
    """~/.raqib/watches.json: {"raqib_watches": 1, "watches": [row, ...]}.
    Rows are added and marked under an O_EXCL lock file (path + ".lock"); a
    lock older than LOCK_STALE_SECONDS is broken, and the change notes it in
    the row. No row is ever removed (A3): the person deletes the file. A
    file that is not a registry is left as it is (I-5)."""

    def __init__(self, path, wall=None, sleep=None):
        self.path = path
        self.lock_path = path + ".lock"
        self.wall = wall or time.time
        self.sleep = sleep or time.sleep

    def _acquire(self):
        """None, or the note that a stale lock was broken."""
        deadline = self.wall() + LOCK_WAIT_SECONDS
        note = None
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                try:
                    age = self.wall() - os.stat(self.lock_path).st_mtime
                except FileNotFoundError:
                    continue
                if age > LOCK_STALE_SECONDS:
                    try:
                        os.remove(self.lock_path)
                    except FileNotFoundError:
                        pass
                    note = ("the registry lock %s was %.1f s old, more than %d s: broken by pid %d"
                            % (self.lock_path, age, LOCK_STALE_SECONDS, os.getpid()))
                    continue
                if self.wall() >= deadline:
                    raise RegistryError("the registry lock %s is held (%.1f s old) and was not let go within %d s"
                                        % (self.lock_path, age, LOCK_WAIT_SECONDS))
                self.sleep(LOCK_POLL_SECONDS)
                continue
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write("pid %d\n" % os.getpid())
            return note

    def _release(self):
        try:
            os.remove(self.lock_path)
        except OSError:
            pass  # left behind, it is broken by the next writer after LOCK_STALE_SECONDS

    def read(self):
        """(registry, None), or (None, why it is left as it is). Read as the
        page reads it (ui.read_json): a FIFO is never opened, the size is
        bounded, so a planted file cannot hold the watch."""
        data, error, st = ui.read_json(self.path)
        if error:
            return None, error
        if st is None:
            return {"raqib_watches": 1, "watches": []}, None
        if not isinstance(data, dict) or not isinstance(data.get("watches"), list):
            return None, "is not a Raqib registry (no list of watches)"
        return data, None

    def _write(self, data):
        text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        fd, tmp = tempfile.mkstemp(prefix=".raqib-watches-", suffix=".tmp", dir=os.path.dirname(self.path))
        try:
            with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
            for attempt in range(REPLACE_TRIES):
                try:
                    os.replace(tmp, self.path)
                    tmp = None
                    return
                except PermissionError:   # Windows: a page is reading it
                    if attempt == REPLACE_TRIES - 1:
                        raise
                    self.sleep(LOCK_POLL_SECONDS)
        finally:
            if tmp is not None and os.path.exists(tmp):
                os.remove(tmp)

    def change(self, edit):
        """edit(rows, note) under the lock, then write; (note, hole)."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        note = self._acquire()
        try:
            data, why = self.read()
            if data is None:
                return note, "the registry %s %s: it is left as it is, and this watch is not in it (I-5)" % (
                    self.path, why)
            edit(data["watches"], note)
            self._write(data)
            return note, None
        finally:
            self._release()


# --- the command ------------------------------------------------------------------

def hook_kinds(doctor, installer, project):
    """J-9: which of disabled, missing, foreign the hook check found."""
    kinds = []
    if installer.hooks_disabled(os.path.join(project, ".claude")):
        kinds.append("disabled")
    states, _, problem = doctor.hook_states(project, installer.WINDOWS)
    if states is None:
        return kinds + ["unreadable"]
    for kind in ("missing", "foreign"):
        if any(state == kind for _, state, _ in states):
            kinds.append(kind)
    return kinds


def load_installer():
    """The installer's API: raqib/install.py, imported with the package, never
    loaded by path from a checkout (W14, M6.3)."""
    return install


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


def _serve(page, port, routes=None, refresh=None):
    """(server, port record). A requested port (--port N, else DEFAULT_PORT)
    that cannot be bound gives another port and a warning, never silence
    (B-7); OverflowError (no such port) is the caller's usage error.
    routes: the pages beside / (GET /discover, I-8)."""
    requested = DEFAULT_PORT if port is None else port
    try:
        server = ui.make_server(page, requested, routes=routes, refresh=refresh)
        return server, {"requested": requested, "used": server.server_address[1], "warning": None}
    except OSError as exc:
        why = exc.strerror or str(exc)
    server = ui.make_server(page, 0, routes=routes, refresh=refresh)
    used = server.server_address[1]
    return server, {"requested": requested, "used": used,
                    "warning": "port %d on 127.0.0.1 is not available (%s); the page is on port %d instead"
                               % (requested, why, used)}


class Stop:
    """What ends loop() when it runs in a worker thread (the window, M6.4):
    the equivalent of Ctrl-C. set(reason) is the first reason that counts."""

    def __init__(self):
        self.event = threading.Event()
        self.reason = None

    def set(self, reason):
        if not self.event.is_set():
            self.reason = reason
            self.event.set()

    def is_set(self):
        return self.event.is_set()

    def wait(self, seconds):
        return self.event.wait(seconds)


class Running:
    """What start() set up and loop(), conclude() and close() use. knock:
    the watch's first-finding knock (notify.FirstFinding, ADR-0006 A-12)."""

    def __init__(self, watcher, server, notifier, thread, refresh, environ, no_open, out, err):
        self.knock = notify.FirstFinding(notifier)
        self.watcher = watcher
        self.server = server
        self.notifier = notifier
        self.thread = thread
        self.refresh = refresh
        self.environ = environ
        self.no_open = no_open
        self.out = out
        self.err = err


class AskedStop(KeyboardInterrupt):
    """M9.1 (ADR-0010 decision 1): a stop asked from outside the watch (SIGTERM, SIGHUP, SIGBREAK: raqib/cli.py's
    Stops raises it while the watch waits between polls). loop() ends on it as on Ctrl-C and says its name."""

    def __init__(self, name):
        KeyboardInterrupt.__init__(self, name)
        self.name = name


def stopped_by(exc):
    """What the "stopped (...)" line names: an AskedStop's name, else Ctrl-C (its words, as before)."""
    return exc.name if isinstance(exc, AskedStop) else "Ctrl-C"


class Speech:
    """M9.1 REDO (ADR-0010 Amendment B, B-1): a stop never depends on its own words being written. The out and
    err of a terminal watch (command() here, host.command()) are written through this. A write or a flush that
    fails - a hung-up terminal (EIO), a closed pipe (EPIPE), a closed stream - is dropped and never raised, so
    no failure to write skips what the watch keeps or changes its code. On a stop (Ctrl-C or a stop signal)
    loop() calls hold(): from then every word of out and err is queued, in its order, until release(), which
    command() calls once conclude() has kept the record (watch.json finished, the registry row; the host
    watch's sources and channel closed). What is kept is written first, what is printed after; a terminal
    that takes the words gets them as before, in the same order. The window (raqib/app.py) does not use it."""

    def __init__(self, out, err):
        self.lock = threading.Lock()
        self.queue = None   # [(stream, text; None for a flush)] from hold() to release()
        self.out, self.err = _Said(self, out), _Said(self, err)

    def hold(self):
        with self.lock:
            if self.queue is None:
                self.queue = []

    def release(self):
        """What was held, written in its order (a word another thread says meanwhile joins the queue)."""
        while True:
            with self.lock:
                if not self.queue:
                    self.queue = None
                    return
                said, text = self.queue.pop(0)
            said.put(text)

    def queued(self, said, text):
        with self.lock:
            if self.queue is None:
                return False
            self.queue.append((said, text))
            return True


class _Said:
    """One stream of a Speech (its out or its err): write and flush as the stream's, never raising OSError or
    ValueError; every other attribute is the stream's own."""

    def __init__(self, speech, stream):
        self.speech, self.stream = speech, stream

    def write(self, text):
        if not self.speech.queued(self, text):
            self.put(text)
        return len(text)

    def flush(self):
        if not self.speech.queued(self, None):
            self.put(None)

    def put(self, text):
        try:
            if text is None:
                self.stream.flush()
            else:
                self.stream.write(text)
        except (OSError, ValueError):   # a terminal that is gone: the words are lost, the watch goes on (B-1)
            pass

    def __getattr__(self, name):
        return getattr(self.stream, name)


def first_step(running):
    """The first-finding knock after a poll (ADR-0006 E3, A-12): the
    FirstFinding record when it knocked now (also kept as watch.json's
    first_knock, and said through out as "first finding knocked: ..."),
    else None. The terminal's loop() and the window's worker both call it."""
    watcher = running.watcher
    with watcher.lock:
        now = watcher.clock()
        done = running.knock.check(list(watcher.inventory.values()), now)
        if done is None:
            return None
        watcher.first_knock = {k: done[k] for k in ("rule_id", "severity", "where", "status")}
        watcher.first_knock["at"] = watcher.at(now)
        if done.get("rule_notice") is not None:
            watcher.first_knock["rule_notice"] = done["rule_notice"]
        watcher._say(now, "first finding knocked: %s (%s)" % (done["where"], done["status"]))
        return dict(watcher.first_knock)


def command(project, log, no_open, no_notify, port, out, evaluator, rules, gap_seconds, environ=None,
            err=None, home=None, refresh=None, stops=None):
    """raqib watch; returns the exit code of the final report.
    evaluator(project) -> (evaluate, scope note): evaluate(records) gives
    (findings, notes) with the project's context (B-6). refresh: the page's
    reload in seconds (I-1, default ui.REFRESH_DEFAULT). The loop is split
    (M6.4) into start(), loop(), conclude() and close(), so the window runs
    the same watch in a worker thread and ends it with a Stop. stops (M9.1):
    the terminal's stop signals (raqib/cli.py's Stops), waited on between
    polls; None: Ctrl-C only, as before. out and err are written through a
    Speech (M9.1 REDO B-1): a terminal that is gone loses the words, never
    the record or the code."""
    speech = Speech(out, err or sys.stderr)
    running = start(project, log, no_open, no_notify, port, speech.out, evaluator, rules, gap_seconds,
                    environ=environ, err=speech.err, home=home, refresh=refresh)
    try:
        crash = loop(running, stops=stops, on_stop=speech.hold)
        text, code = conclude(running, crash)
    finally:
        speech.release()   # B-1: the record is kept; now what was said since the stop
        close(running)
    speech.out.write("\n" + text)
    return code


def start(project, log, no_open, no_notify, port, out, evaluator, rules, gap_seconds, environ=None,
          err=None, home=None, refresh=None):
    """Everything before the poll loop: the hooks, the trace, the notifier,
    the Watch, the page server and the registry row; a Running."""
    refresh = ui.REFRESH_DEFAULT if refresh is None else ui.check_refresh(refresh)
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
    watcher.refresh = refresh
    out.write("raqib watch: trace %s (%s)\nraqib watch: state %s\n" % (_safe(trace_path), source,
                                                                      _safe(watcher.state_path)))
    out.write("raqib watch: scope: %s\n" % _safe(scope))  # D-7: the agent can write HANDOFF.md
    out.write("raqib watch: silence limit %gs (RAQIB_GAP_SECONDS); polling every %gs\n" % (gap_seconds, POLL_SECONDS))
    out.write("raqib watch: %s\n" % notifier.band()[1])
    for line in overlay.start_lines(watcher.rules_overlay):   # M7.6 (ADR-0008 decision 2): said at the start
        out.write("raqib watch: %s\n" % _safe(line))
    if installed["code"] == 3:
        watcher.capture_off("the installer reports disableAllHooks: the hooks will not run")
    try:  # I-3: the hooks as doctor reads them (read-only), after the install
        from raqib import doctor  # doctor imports this module: imported here, not at the top
        ok, detail = doctor.check_hooks(project, installer.WINDOWS)
        kinds = hook_kinds(doctor, installer, project) if not ok else []
    except Exception as exc:
        ok, detail, kinds = False, "the hook check failed: %s: %s" % (type(exc).__name__, exc), ["unchecked"]
    watcher.hooks_at_start(ok, detail, kinds)
    try:
        server, watcher.port = _serve(watcher.page, port, routes={ui.DISCOVER_ROUTE: watcher.discover_page},
                                      refresh=refresh)
    except (OSError, OverflowError) as exc:
        notifier.close()
        raise WatchError("cannot serve on 127.0.0.1:%s: %s" % (port, exc))
    watcher.url = "http://127.0.0.1:%d/" % server.server_address[1]
    registry = Registry(registry_path(home))
    if inside(os.path.dirname(registry.path), project):   # J-4 (A4): watching a home; nothing into the project
        hole = watcher.registry_off(registry.path, "the registry %s is inside the project %s: it is not written"
                                    " (A4: watch writes nothing into the project)" % (registry.path, project))
    else:
        hole = watcher.register(registry)   # I-5, under ~/.raqib
    if hole:
        out.write("raqib watch: %s\n" % _safe(hole))
    thread = threading.Thread(target=server.serve_forever, name="raqib-watch-page", daemon=True)
    thread.start()
    return Running(watcher, server, notifier, thread, refresh, environ, no_open, out, err)


def loop(running, stop=None, on_step=None, stops=None, on_stop=None):
    """Poll until Ctrl-C (stop None: the terminal) or until stop is set (the
    window's worker thread); None, or the crash text when an exception ended
    it (B-4). The window's Stop is the equivalent of Ctrl-C. stops (M9.1,
    ADR-0010 decision 1; the terminal only): the wait between polls is
    stops.nap(), which ends in an AskedStop when a stop signal came, said as
    "stopped (SIGTERM)" where Ctrl-C says "stopped (Ctrl-C)"; the first lines
    say what stops it and what was left ignored (stops.line(), REDO B-3).
    on_stop() (REDO B-1: the terminal's Speech.hold) is called on Ctrl-C or
    a stop signal before the "stopped" line is written. on_step(watcher)
    runs after every poll, in this thread, outside the Watch lock; without
    one it is the first-finding knock (first_step, ADR-0006 A-12), so a
    terminal watch knocks on its first finding as the window does."""
    watcher, out, err, environ = running.watcher, running.out, running.err, running.environ
    if on_step is None:
        def on_step(w):
            try:
                first_step(running)
            except Exception as exc:   # A3: a knock that broke is a hole, never the end of the watch
                with w.lock:
                    detail = "the first-finding knock failed: %s: %s" % (type(exc).__name__, exc)
                    if not any(h["kind"] == "first-knock" and h["detail"] == detail for h in w.holes):
                        w._hole(w.clock(), "first-knock", detail)
    crash = None
    try:
        if watcher.port["warning"]:
            out.write("raqib watch: WARNING: %s\n" % watcher.port["warning"])
        out.write("raqib watch: page %s (read-only, reloads every %d s; %s stops the watch and prints the"
                  " final report)\n" % (watcher.url, running.refresh, "Ctrl-C" if stop is None else "Stop"))
        if stops is not None:   # M9.1 REDO B-3 (A3): which signals stop it, which were left ignored
            out.write("raqib watch: %s\n" % stops.line())
        if watcher.registry is not None:
            out.write("raqib watch: registry %s (this watch is a row; rows are never removed)\n"
                      % _safe(watcher.registry.path))
        if running.no_open or environ.get("CI"):
            out.write("raqib watch: page not opened (%s)\n" % ("--no-open" if running.no_open else "CI is set"))
        else:
            why = open_page(watcher.url, environ)
            if why:
                out.write("raqib watch: page not opened (%s); open it by hand\n" % why)
        out.flush()
        watcher.step()
        if on_step is not None:
            on_step(watcher)
        while True:
            if stop is None and stops is not None:
                stops.nap(_sleep, POLL_SECONDS)   # M9.1: a stop signal ends the wait as Ctrl-C does
            elif stop is None:
                _sleep(POLL_SECONDS)
            elif stop.wait(POLL_SECONDS):
                out.write("\nraqib watch: stopped (%s)\n" % _safe(stop.reason))
                break
            watcher.step()
            if on_step is not None:
                on_step(watcher)
    except KeyboardInterrupt as exc:   # Ctrl-C, or (M9.1) a stop signal: an AskedStop
        if on_stop is not None:
            on_stop()   # REDO B-1: what the stop keeps is written before what it says
        out.write("\nraqib watch: stopped (%s)\n" % _safe(stopped_by(exc)))
    except Exception as exc:  # B-4: the watcher's own failure ends in the final report
        crash = "%s: %s" % (type(exc).__name__, exc)
        out.write("\nraqib watch: CRASHED: %s\n" % _safe(crash))
        traceback.print_exc(file=err)
    return crash


def conclude(running, crash):
    """finish() and the registry row marked: (final text, exit code)."""
    watcher, out = running.watcher, running.out
    try:
        watcher.finish(status="crashed" if crash else "finished", error=crash)
        text, code = watcher.final_text, watcher.final_exit
    except Exception as exc:  # D-7: a final report, or one line saying why there is none
        text, code = "raqib watch: no final report: %s: %s\n" % (type(exc).__name__, _safe(exc)), 1
    try:  # I-5: the row stays, marked finished
        hole = watcher.unregister()
    except Exception as exc:
        hole = "the registry was not marked: %s: %s" % (type(exc).__name__, exc)
    if hole:
        out.write("raqib watch: %s\n" % _safe(hole))
    return text, code


def close(running):
    """The page server down, the notifier's temp files removed."""
    try:
        running.server.shutdown()
        running.server.server_close()
    finally:
        running.notifier.close()
