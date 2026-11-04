"""raqib watch --host (M7.2, ADR-0007 decision 2): the host is watched, not
a name.

A HostWatch runs rounds. A round is one live discover (raqib/discover.py:
collect_live and run, the path `raqib discover` takes live; on Linux a
/proc snapshot, or --window S seconds of them; on Windows one sample of the
OS API through raqib/hostwin.py), read-only (A4), in a worker thread. Rounds
start every T seconds, start to start. A reader that is not back within
2 x T is a hole and a knock (HOST-HOLE, A3); no second reader is started
while one is out: the next round waits for it, and its inventory, when it
comes, is that round's, marked late. A reader that raises is a hole and a
knock too, and the round has no inventory.

Each inventory is turned into host lines, one per tree (a candidate or an
act-root of the inventory; tool HostTree) and one per footprint the
inventory lists (tool HostFootprint), in the line shape of a trace
(session "host", source os: the operating system's own record, ADR-0003),
with a running seq. Two anchors of the rule catalog judge them, through
the same engine as every YAML rule (raqib/rules/engine.py):
- NEW-AGENT (high) and NEW-AGENT-UNKNOWN (medium; M7.2 REDO C-1c, the
  engine's severity is per rule, so the unknown tree is its own rule): a
  candidate tree that is not history, not benign and was not a candidate
  in any earlier round of this watch; NEW-AGENT when the catalog names it,
  NEW-AGENT-UNKNOWN when it does not. Benign (C-1d): the root's image is a
  program of the catalog's benign_images block AND its image path, read
  from the process's record, is under a listed system or program-files
  directory; such a tree is listed with `benign`, never knocked. A tree is keyed by (root
  pid, image name, creation time where the reader gives it: Windows
  CreationDate; Linux /proc gives none, a recorded hole). History (ADR-0005
  B-3): the candidates of the first round that has an inventory were there
  at the start: listed, never knocked. An act-root that becomes a candidate
  (it was seen to act, then to talk) is new as a candidate; a tree that is
  gone and back is not new again (once per tree).
- AGENT-DARK-LIVE (medium): a footprint the inventory calls AGENT-DARK in
  DARK_ROUNDS consecutive rounds with an inventory; it fires on the third
  and knocks once. A round where the footprint links to a tree clears the
  streak, with a note when it had fired. A round where the footprint is
  unjudged, and a round with no inventory, neither counts nor clears.
The engine reads only the host lines; the history, the streak and the
"candidate before" are facts of the record that this module computes from
the inventories, deterministically (A1). Every finding cites its host line;
the host line carries the round, the sample (the inventory's window) and
the cited record lines of the inventory, with their text (A5, C-6).

Run (M7.2 REDO C-2): every host watch has a run id (its start time and
pid) carried on every line of rounds.jsonl, in inventory.json and in the
state; seqs continue from the last line of rounds.jsonl, read at the start
(a last line that does not parse is a hole, and seqs continue after the
last good one), so a cited seq is (run, seq) and resolves to one host line.
A second host watch on the same home while the state's heartbeat is fresh
is refused (one host watch per home).

Exit (C-10): 0 when trees are listed and nothing is new (CLEAN), or no
tree is seen (NONE-SEEN); 1 for a finding (ALARM); 3 when a round could not
be read, or another hole of the watch (INCOMPLETE). --rounds and Stop end
the watch at the outstanding reader's deadline (2 x T) at the latest (C-3).

Files, all under <home>/.raqib/host/ (A4: nothing else is written but the
registry row and the notifier's temp files, as for every watch):
- inventory.json: the latest round's inventory, as `raqib discover --json`;
- rounds.jsonl: one line per round (its deltas, counts, holes, times, and
  its host lines), appended; it is the host watch's record, its "trace";
- rounds.jsonl.watch.json: the state (watch.json's shape, mode "host"),
  written on every tick with a heartbeat, as every watch writes its own.

Nothing here signals, attaches to or writes to a process (A4): the reader
reads the host's records; the only programs started are the notifier's and
the page opener, as in raqib/watch.py.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import tempfile
import threading
import time
import traceback

from raqib import discover, notify, ui
from raqib.rules import engine

HOST = "host"
SESSION = "host"
SOURCE = "os"
TREE_TOOL = "HostTree"
FOOTPRINT_TOOL = "HostFootprint"
CWD = "host"                       # host lines carry no working directory; the line shape needs one
NEW_AGENT = "NEW-AGENT"
NEW_UNKNOWN = "NEW-AGENT-UNKNOWN"   # C-1c: the unknown new tree, medium
NEW_RULES = (NEW_AGENT, NEW_UNKNOWN)
DARK_LIVE = "AGENT-DARK-LIVE"
RULES = (NEW_AGENT, NEW_UNKNOWN, DARK_LIVE)
EXIT = {"clean": 0, "none-seen": 0, "alarm": 1, "incomplete": 3}   # C-10
CITE_TEXT_MAX = 240                # the text of a cited record line on a host line (C-6)
TAIL_BYTES = 1 << 20               # how much of rounds.jsonl is read at the start for its last line (C-2)
READER_HOLES = ("reader-late", "reader-failed", "reader-out", "reader-held")
DARK_ROUNDS = 3                    # AGENT-DARK-LIVE.yaml fires at streak 3 (a test holds them equal)
HOLE_EVENT = "HOST-HOLE"
EVERY_DEFAULT = 10.0
DEADLINE_FACTOR = 2                # a reader not back within 2 x T is a hole
POLL_SECONDS = 0.5                 # the tick: heartbeat and state, as raqib watch polls
STALE_SECONDS = 30
HEARTBEATS_FRESH = 3
ROUNDS_KEPT = 50                   # round lines kept in memory for the page and the state
CITES_KEPT = 6                     # record lines cited per host line
IMAGE_MAX = 40                     # an image name in a notification
DIR_NAME = "host"
INVENTORY_NAME = "inventory.json"
ROUNDS_NAME = "rounds.jsonl"
STATE_SUFFIX = ".watch.json"
LINUX_HOLE = ("Linux: /proc gives no creation time, so a tree is keyed by (pid, image) only: a pid reused by a"
              " process of the same image between rounds is taken for the same tree and is not new")


class HostError(Exception):
    pass


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


def host_dir(home=None):
    return os.path.join(home or os.path.expanduser("~"), ".raqib", DIR_NAME)


def iso(moment):
    moment = moment.astimezone(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def write_json(path, value):
    """Atomic write (tempfile + os.replace in the same directory)."""
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".raqib-host-", suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
            f.write(text)
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                tmp = None
                return
            except PermissionError:   # Windows: a page is reading it
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.remove(tmp)


# --- the reader ------------------------------------------------------------------

def live_reader(catalog, window=0.0, platform=None, homes=None):
    """The live round: discover's live collection, one sample on Windows
    (--window S on Linux: S seconds of snapshots, 1 s apart), built into an
    inventory as `raqib discover` builds it live. Read-only (A4)."""
    def read():
        info = {}     # D-3: the run record of this round (hostwin: SystemRoot's drive)
        texts, holes, _ = discover.collect_live(catalog, window=window, homes=homes, platform=platform,
                                                win_samples=1, win_every=0.0, run_info=info)
        return discover.run(texts, catalog, holes=holes, live=True, run=info)
    return read


class Worker:
    """One reader call in a daemon thread: done(), and then outcome =
    (inventory or None, error text or None, seconds it took)."""

    def __init__(self, fn, clock=time.monotonic):
        self.outcome = None
        self.began = clock()
        self.clock = clock
        self.thread = threading.Thread(target=self._run, args=(fn,), name="raqib-host-reader", daemon=True)
        self.thread.start()

    def _run(self, fn):
        begin = time.monotonic()
        try:
            inv = fn()
            if not (isinstance(inv, dict) and isinstance(inv.get("candidates"), list)):
                raise HostError("the reader gave no inventory")
            self.outcome = (inv, None, time.monotonic() - begin)
        except BaseException as exc:   # the reader's failure is a hole, never the end of the watch
            self.outcome = (None, "%s: %s" % (type(exc).__name__, " ".join(str(exc).split())),
                            time.monotonic() - begin)

    def wait(self, seconds):
        if seconds:
            self.thread.join(seconds)
        return self.done()

    def done(self):
        return self.outcome is not None


# --- the trees of an inventory ----------------------------------------------------

def _cite_list(cites):
    out = []
    for c in cites or ():
        if isinstance(c, dict) and (c.get("src"), c.get("line")) not in [(x["src"], x["line"]) for x in out]:
            out.append({"src": c.get("src"), "line": c.get("line"), "text": c.get("text")})
    return out


def sample_of(inv):
    """The sample a round's claims rest on: the inventory's window."""
    w = inv.get("window") or {}
    read = w.get("samples_read") or []
    return "window %s .. %s; %s" % (w.get("start") or "-", w.get("end") or "-",
                                    "Windows sample(s) %s" % ",".join(str(s) for s in read) if read
                                    else "%s snapshot(s)" % w.get("snapshots", 0))


def named(tree, catalog):
    """(True, why) when the catalog knows the tree: its image (or the last
    part of its executable path) is a footprint agent's name, or it talks
    to a catalog endpoint; else (False, None): "unknown"."""
    agents = sorted({f["agent"] for f in catalog.get("footprints") or ()})
    names = {n for n in (tree.get("image"), discover.image_name(tree.get("exe"))) if n}
    for agent in agents:
        for n in sorted(names):
            if n == agent or n.startswith(agent + "-"):
                return True, "image %s is the catalog's %s" % (n, agent)
    for t in tree.get("talks") or ():
        for m in t.get("endpoint") or ():
            return True, "talks to the catalog's %s endpoint %s" % (m.get("vendor"), m.get("name") or m.get("match"))
    return False, None


def trees_of(inv, catalog, no_drive=None):
    """{key: tree} of an inventory: its candidates and its act-roots, keyed
    by (pid, image, started). no_drive (a list): the trees whose benign
    check needed the system drive the run record did not give (D-3)."""
    out = {}
    drive = inv.get("system_drive")
    for cls, group in (("candidate", inv.get("candidates") or []), ("act-root", inv.get("act_roots") or [])):
        for t in group:
            key = (t.get("pid"), t.get("image"), t.get("started"))
            if key in out:     # a pid both: the candidate stands
                continue
            ok, why = named(t, catalog)
            benign_by, no = discover.benign_check(t.get("image"), t.get("exe"), t.get("exe_from"), catalog, drive)
            if no and no_drive is not None:
                no_drive.append("%s pid %s" % (t.get("image"), t.get("pid")))
            endpoints = []
            for talk in t.get("talks") or ():
                eps = ["%s %s" % (m.get("vendor"), m.get("match")) for m in talk.get("endpoint") or ()]
                endpoints.append("%s%s" % (talk.get("remote"), " [%s]" % "; ".join(eps) if eps else ""))
            cites = _cite_list(t.get("cites"))
            for talk in t.get("talks") or ():
                cites += [c for c in _cite_list(talk.get("cites")) if c not in cites]
            for a in (t.get("acts") or [])[:3]:
                cites += [c for c in _cite_list(a.get("cites")) if c not in cites]
            out[key] = {"key": list(key), "pid": t.get("pid"), "image": t.get("image"), "exe": t.get("exe"),
                        "started": t.get("started"), "class": cls, "id": t.get("id"), "named": ok,
                        "named_by": why, "benign": benign_by is not None, "benign_by": benign_by,
                        "acts": len(t.get("acts") or []), "endpoints": endpoints,
                        "cites": [dict(c, text=cite_text(c.get("text"))) for c in cites[:CITES_KEPT]]}
    return out


def cite_text(text):
    """C-6: a cited record line's text, printable and bounded."""
    if text is None:
        return None
    text = _safe(text)
    if len(text) > CITE_TEXT_MAX:
        keep = CITE_TEXT_MAX - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    return text


def run_id(started, pid):
    """C-2: a host watch's run id, its start time (UTC, ms) and its pid."""
    return "%s-%d" % (iso(started).replace("-", "").replace(":", ""), pid)


def nothing_read(inv):
    """D-2: True when a round's inventory says nothing was read (no record
    from any source)."""
    return not inv.get("records") or any(str(a).startswith("nothing read") for a in inv.get("alarms") or ())


UNREAD_PREFIXES = ("source ", "no process source read", "no connection source read")


def unread_sources(inv):
    """F-9 (M7.3 REDO, A3): the sources of a round's inventory that were not
    read or only partly read: discover's own reasons ("source X not read: ...",
    "source X partly read: ...", "no process/connection source read") and any
    source the inventory lists with an error. A tree seen beside them was seen
    by a partly blind round."""
    out = [str(r) for r in inv.get("incomplete") or () if str(r).startswith(UNREAD_PREFIXES)]
    for src in inv.get("sources") or ():
        if isinstance(src, dict) and src.get("error"):
            text = "source %s %s: %s" % (src.get("name"), "partly read" if src.get("text_read") else "not read",
                                         src.get("error"))
            if text not in out:
                out.append(text)
    return out


def tree_word(key):
    pid, image, started = key
    return "%s:%s:%s" % (pid, image, started or "-")


# --- the watch --------------------------------------------------------------------

class HostWatch:
    """The state of one host watch. tick(now) does one step: it starts a
    round when one is due and no reader is out, takes a reader's result,
    marks a late reader, sends folded knocks and writes the state."""

    def __init__(self, reader, catalog, rules, notifier, every=EVERY_DEFAULT, window=0.0, rounds_max=None,
                 out=None, err=None, clock=None, wall=None, home=None, platform=None, deadline=None, run=None):
        self.reader = reader
        self.catalog = catalog
        self.rules = [r for r in rules if r.id in RULES]
        self.missing_rules = sorted(set(RULES) - {r.id for r in self.rules})
        self.notifier = notifier
        self.every = float(every)
        self.window = float(window)
        self.deadline_seconds = DEADLINE_FACTOR * self.every if deadline is None else deadline
        self.rounds_max = rounds_max
        self.out, self.err = out, err
        self.clock = clock or time.monotonic
        self.wall_clock = wall or time.time
        self.platform = platform or sys.platform
        self.t0 = self.clock()
        self.started = datetime.datetime.fromtimestamp(self.wall_clock(), datetime.timezone.utc)
        notifier.stamp = self.at
        notifier.on_folds = self._folds   # C-5 (ADR-0005 D-4): what became of a folded knock is written back
        self.run = run or run_id(self.started, os.getpid())
        self.lock = threading.Lock()
        self.dir = host_dir(home)
        self.inventory_path = os.path.join(self.dir, INVENTORY_NAME)
        self.rounds_path = os.path.join(self.dir, ROUNDS_NAME)
        self.state_path = self.rounds_path + STATE_SUFFIX
        self.rounds = 0              # rounds started
        self.applied = 0             # rounds whose reader came back with an inventory
        self.round_lines = []        # the last ROUNDS_KEPT round records
        self.worker = None           # the reader out now
        self.worker_round = None
        self.worker_late = False
        self.worker_began = None
        self.round_began = None      # D-1: when the latest attempted round began (a held one: its deadline)
        self.stopping = False        # C-3: Stop was asked; no new round starts
        self.newline_owed = False    # C-2: rounds.jsonl ended in a torn line; the next line starts on its own
        self.next_round = self.t0
        self.trees = {}              # key -> tree entry, every tree seen in this watch
        self.present = set()         # keys in the last inventory
        self.prev_class = {}         # key -> class in the last inventory
        self.history_round = None    # the first round with an inventory
        self.footprints = {}         # path -> {agent, streak, state, fired, ...}
        self.findings = []
        self.notes = []              # cleared darks and other notes
        self.holes = []
        self.seq = 0
        self.last_round = None
        self.last_inventory = None
        self.results = []            # each round's inventory result
        self.unread = []             # F-9: (round, [unread or partly read sources]) of the rounds that had some
        self.beat = self.t0
        self.beat_wall = self.wall_clock()
        self.step_seconds = 0.0
        self.url = None
        self.port = None
        self.status = "watching"
        self.error = None
        self.finished = None
        self.state_error = None
        self.final_text, self.final_exit = None, None
        self.refresh = ui.REFRESH_DEFAULT
        self.registry = None
        self.registry_state = None
        if self.missing_rules:
            self._hole(self.t0, "host-rule", "rule(s) %s not in the catalog: what they judge is not judged"
                       % ", ".join(self.missing_rules))
        for r in self.rules:
            if r.status == "disabled":
                self._hole(self.t0, "host-rule", "%s has status disabled in %s (A6): it judges nothing; the"
                           " trees and footprints are still listed" % (r.id, r.source))
        if self.platform.startswith("linux"):
            self.notes.append(LINUX_HOLE)
        self._refuse_second()
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:
            raise HostError("cannot create %s: %s" % (self.dir, exc.strerror or exc))
        self.seq = self.first_seq = self._resume()

    # --- one host watch per home; seqs continue (C-2) ----------------------------

    def _refuse_second(self):
        """HostError when another host watch holds this home: its state is
        not finished and its heartbeat is fresh (stale after its own
        stale_after_seconds, as every watch reads it), or (D-6) its
        heartbeat cannot be parsed. Two watches started in the same instant
        both find no state: a recorded hole (D-6)."""
        try:
            with open(self.state_path, encoding="ascii") as f:
                other = json.load(f)
        except (OSError, ValueError):
            return
        if not (isinstance(other, dict) and other.get("mode") == HOST and not other.get("finished")):
            return
        try:
            beat = datetime.datetime.strptime(str(other.get("heartbeat")), "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:   # D-6: an unknown state is not clearance (A3)
            raise HostError("the host watch state %s holds a heartbeat that cannot be parsed (%s) and is not"
                            " finished: another raqib watch --host may be watching this home; one host watch per"
                            " home; stop it, or remove that file once no host watch runs" % (
                                self.state_path, _safe(str(other.get("heartbeat"))[:40])))
        stale = other.get("stale_after_seconds")
        stale = stale if isinstance(stale, (int, float)) and not isinstance(stale, bool) else STALE_SECONDS
        age = self.wall_clock() - beat
        if age <= stale:
            raise HostError("another raqib watch --host is watching this home (run %s, pid %s, heartbeat %.0f s"
                            " ago): one host watch per home; stop it first (%s)" % (
                                _safe(other.get("run")), _safe(other.get("pid")), max(age, 0), self.state_path))

    def _resume(self):
        """The last seq of rounds.jsonl, read from its last good line at the
        start; 0 when there is none. A last line that does not parse is a
        hole, and seqs continue after the last good line."""
        try:
            with open(self.rounds_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - TAIL_BYTES))
                data = f.read()
        except FileNotFoundError:
            return 0
        except OSError as exc:
            self._hole(self.t0, "rounds-unreadable", "cannot read %s at the start: %s; seqs start at 1 (a cited"
                       " seq is still one line with this run's id)" % (self.rounds_path, exc.strerror or exc))
            return 0
        self.newline_owed = bool(data) and not data.endswith(b"\n")
        parts = [p for p in data.split(b"\n") if p.strip()]
        if size > TAIL_BYTES and parts:
            parts = parts[1:]          # the first part of the tail may be cut
        bad = 0
        for raw in reversed(parts):
            last = self._last_seq_of(raw)
            if last == ():         # a round record with no seq (a failed round of an older run): look further back
                continue
            if last is not None:
                if bad:
                    self._hole(self.t0, "rounds-corrupt", "the last %d line(s) of %s are not round records (a torn"
                               " or foreign write): seqs continue after the last good line, seq %d" % (
                                   bad, self.rounds_path, last))
                return last
            bad += 1
        if bad:
            self._hole(self.t0, "rounds-corrupt", "no line of the last %d byte(s) of %s is a round record: seqs"
                       " start at 1 (a cited seq is still one line with this run's id)" % (len(data), self.rounds_path))
        return 0

    @staticmethod
    def _last_seq_of(raw):
        """The last seq a round record carries; () for a round record with
        none; None for a line that is not a round record."""
        try:
            rec = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not (isinstance(rec, dict) and "round" in rec and isinstance(rec.get("lines"), list)):
            return None
        last = rec.get("last_seq")
        if isinstance(last, int) and not isinstance(last, bool) and last >= 0:
            return last
        seqs = [l.get("seq") for l in rec["lines"] if isinstance(l, dict)]
        seqs = [q for q in seqs if isinstance(q, int) and not isinstance(q, bool)]
        return max(seqs) if seqs else ()

    def _folds(self, tokens, status, count):
        """C-5: a folded knock, when its fold is delivered, says so where it was recorded."""
        for container, key in tokens:
            container[key] = "folded: %s as %d more" % (status, count)
            tree = self.trees.get(tuple(container.get("tree_key") or ())) if isinstance(container, dict) else None
            if tree is not None:
                tree["knocked"] = container[key]

    # --- time and output -------------------------------------------------------

    def at(self, now):
        return iso(self.started + datetime.timedelta(seconds=now - self.t0))

    def _say(self, now, text):
        if self.out is not None:
            self.out.write("[%sZ] %s\n" % (self.at(now)[11:19], _safe(text)))
            self.out.flush()

    def _hole(self, now, kind, detail, knock=None, round_=None):
        hole = {"kind": kind, "detail": detail, "at": self.at(now), "notice": None, "round": round_}
        self.holes.append(hole)
        if knock:
            hole["notice"] = self.notifier.notify(HOLE_EVENT, knock, now, token=(hole, "notice"))
        return hole

    # --- one tick ---------------------------------------------------------------

    def settled(self, now=None):
        """C-3: no reader is out, or the one out is past its deadline (2 x T):
        the watch may end now; a reader still out is a hole in the report."""
        now = self.clock() if now is None else now
        return self.worker is None or now - self.worker_began >= self.deadline_seconds

    def done_rounds(self, now=None):
        """D-1 (C-3): True when --rounds N rounds have been attempted. A
        round is attempted when its reader came back or reached its deadline
        (2 x T, a reader-late hole); while that reader is still out each
        further round is held at the deadline (a reader-held hole: never two
        readers at once) and is attempted too. So the watch ends at the N-th
        round's deadline at the latest, whatever the reader does."""
        now = self.clock() if now is None else now
        return self.rounds_max is not None and self.rounds >= self.rounds_max and (
            self.worker is None or now - self.round_began >= self.deadline_seconds)

    def tick(self, now=None, wait=0.0):
        """One step. wait: real seconds to wait for a reader that is out
        (tests; the loop waits by its own sleep)."""
        with self.lock:
            begin = self.clock()
            now = begin if now is None else now
            self._step(now, wait)
            for event, count, status in self.notifier.tick(now):
                self._say(now, "%s: %d more, folded into one notification (%s)" % (event, count, status))
            self.beat = now
            self.beat_wall = self.wall_clock()
            self.step_seconds = round(max(0.0, self.clock() - begin), 3)
            self._write_state(now)

    def _step(self, now, wait):
        if self.worker is None and now >= self.next_round and not self.stopping and not (
                self.rounds_max is not None and self.rounds >= self.rounds_max):
            self.rounds += 1
            self.worker_round = self.rounds
            self.worker_late = False
            self.worker_began = self.round_began = now
            self.next_round = max(self.next_round + self.every, now)
            self.worker = Worker(self.reader)
        if self.worker is None:
            return
        if self.worker.wait(wait):
            inv, error, seconds = self.worker.outcome
            worker, n, late = self.worker, self.worker_round, self.worker_late
            self.worker = None
            if late:   # the next round waited for it (never two readers at once)
                self.next_round = max(self.next_round, now)
            if error:
                self._failed(now, n, error, seconds)
            else:
                self._apply(now, n, inv, seconds, late)
            return
        if not self.worker_late and now - self.worker_began >= self.deadline_seconds:
            self.worker_late = True
            hole = self._hole(now, "reader-late", "round %d: the reader was not back within %g s (2 x T); no"
                              " other reader is started until it is" % (self.worker_round, self.deadline_seconds),
                              knock="round %d, reader not back in %g s" % (self.worker_round, self.deadline_seconds),
                              round_=self.worker_round)
            self._say(now, "%s round %d: the reader is not back within %g s (%s)" % (
                HOLE_EVENT, self.worker_round, self.deadline_seconds, hole["notice"]))
        # D-1: under --rounds N, a round the late reader holds up is attempted at the deadline, as a hole
        while (self.worker_late and self.rounds_max is not None and self.rounds < self.rounds_max
               and not self.stopping and now - self.round_began >= self.deadline_seconds):
            self.rounds += 1
            self.round_began += self.deadline_seconds
            self._hole(now, "reader-held", "round %d: not read: the reader of round %d is still out (%.1f s);"
                       " never two readers at once, so this round is attempted without one" % (
                           self.rounds, self.worker_round, now - self.worker_began), round_=self.rounds)
            self._say(now, "%s round %d: not read: round %d's reader is still out" % (
                HOLE_EVENT, self.rounds, self.worker_round))

    def _record(self, line):
        line["run"] = self.run           # C-2: every line names its run
        line["last_seq"] = self.seq
        self.round_lines.append(line)
        del self.round_lines[:-ROUNDS_KEPT]
        try:
            with open(self.rounds_path, "a", encoding="ascii", newline="\n") as f:
                f.write(("\n" if self.newline_owed else "") + json.dumps(line, sort_keys=True, ensure_ascii=True) + "\n")
            self.newline_owed = False
        except OSError as exc:
            detail = "cannot append to %s: %s" % (self.rounds_path, exc.strerror or exc)
            if not any(h["detail"] == detail for h in self.holes):
                self._hole(self.clock(), "rounds-unwritable", detail)

    def _failed(self, now, n, error, seconds):
        hole = self._hole(now, "reader-failed", "round %d: the reader failed: %s" % (n, error),
                          knock="round %d, reader failed" % n, round_=n)
        line = {"round": n, "at": self.at(now), "seconds": round(seconds, 3), "late": False, "error": error,
                "records": None, "holes": None, "result": None, "trees": None, "new": [], "gone": [], "back": [],
                "dark": [], "cleared": [], "findings": [], "lines": []}
        self.last_round = line
        self._record(line)
        self._say(now, "round %d: reader FAILED: %s (%s)" % (n, error, hole["notice"]))

    def _apply(self, now, n, inv, seconds, late):
        """One round's inventory: deltas, host lines, the two rules."""
        self.applied += 1
        self.last_inventory = inv
        self.results.append(inv.get("result"))
        # D-2: a round whose inventory read nothing is an unread round; lines that could not be read are a hole
        nothing = nothing_read(inv)
        problems = inv.get("problems") or []
        if nothing:
            self._hole(now, "round-unread", "round %d: nothing read: the inventory holds no record from any"
                       " source (A3): an unread round, not \"no agent seen\"" % n, round_=n)
        if problems:
            self._hole(now, "lines-unread", "round %d: %d line(s) could not be read (A3): %s" % (
                n, len(problems), "; ".join(cite_text("%s:%s %s" % (p.get("src"), p.get("line"), p.get("reason"))
                                                    if isinstance(p, dict) else str(p)) for p in problems[:3])),
                       round_=n)
        blind = unread_sources(inv)
        if blind:   # F-9: a tree seen beside an unread source was seen by a partly blind round
            self.unread.append((n, blind))
        first = self.history_round is None
        if first:
            self.history_round = n
        sample = sample_of(inv)
        ts = self.at(now)
        no_drive = []
        current = trees_of(inv, self.catalog, no_drive)
        if no_drive:   # D-3: said as a hole, once per round
            self._hole(now, "benign-no-drive", "round %d: %s; judged as not benign: %s" % (
                n, discover.NO_DRIVE, ", ".join(no_drive)), round_=n)
        lines, new, back, gone, benign_new = [], [], [], [], []
        for key in sorted(current, key=lambda k: (str(k[0]), str(k[1]), str(k[2]))):
            t = current[key]
            entry = self.trees.get(key)
            was = self.prev_class.get(key, "absent")
            if entry is None:
                entry = self.trees[key] = dict(t, first_round=n, first_seen=ts, history=False,
                                               candidate_round=None, knocked=None, rounds_seen=0)
            elif key not in self.present:
                back.append(tree_word(key))
            candidate_before = entry["candidate_round"] is not None
            history = (first and t["class"] == "candidate") or entry["history"]
            entry.update({k: t[k] for k in ("class", "id", "named", "named_by", "benign", "benign_by", "acts",
                                            "endpoints", "cites", "exe")})
            entry.update(last_round=n, last_seen=ts, present=True, rounds_seen=entry["rounds_seen"] + 1,
                         history=history)
            self.seq += 1
            line = {"ts": ts, "seq": self.seq, "session_id": SESSION, "phase": "pre", "tool": TREE_TOOL,
                    "cwd": CWD, "source": SOURCE,
                    "input_meta": {"round": n, "tree": tree_word(key), "pid": t["pid"], "image": t["image"],
                                   "started": t["started"], "class": t["class"], "was": was,
                                   "history": history, "candidate_before": candidate_before,
                                   "named": t["named"], "named_word": "named" if t["named"] else "unknown",
                                   "named_by": t["named_by"], "benign": t["benign"], "benign_by": t["benign_by"],
                                   "acts": t["acts"], "endpoints": t["endpoints"], "run": self.run,
                                   "sample": sample, "cites": [dict(c) for c in t["cites"]]}}
            lines.append(line)
            entry["line_seq"] = self.seq
            if t["class"] == "candidate" and entry["candidate_round"] is None:
                entry["candidate_round"] = n
            if not candidate_before and t["class"] == "candidate" and not history:
                (benign_new if t["benign"] else new).append(tree_word(key))
        for key in sorted(self.present - set(current), key=lambda k: (str(k[0]), str(k[1]), str(k[2]))):
            self.trees[key]["present"] = False
            gone.append(tree_word(key))
        self.present = set(current)
        self.prev_class = {k: v["class"] for k, v in current.items()}

        # Footprints: dark, linked, or unjudged in this round.
        dark_paths = {d.get("path"): d for d in inv.get("agent_dark") or []}
        listed = {}
        for f in inv.get("footprints") or []:
            listed.setdefault(f.get("path"), f)
        dark_now, cleared = [], []
        for path in sorted(set(listed) | set(dark_paths) | set(self.footprints), key=str):
            f = listed.get(path) or dark_paths.get(path)
            fp = self.footprints.setdefault(path, {"path": path, "agent": (f or {}).get("agent"), "streak": 0,
                                                   "fired": False, "state": None, "first_round": n,
                                                   "dark_since": None, "cleared": []})
            if f is None:
                state, link = "gone", None
            elif path in dark_paths:
                state, link = "dark", None
            elif f.get("candidate") or f.get("act_root"):
                state, link = "linked", f.get("candidate") or f.get("act_root")
            else:
                state, link = "unjudged", None
            if state == "dark":
                fp["streak"] += 1
                fp["dark_since"] = fp["dark_since"] or n
                dark_now.append(path)
            elif state in ("linked", "gone"):
                if fp["fired"]:
                    note = "round %d: AGENT-DARK-LIVE of the %s footprint cleared: %s" % (
                        n, fp["agent"], "linked to tree %s" % link if link else "the footprint is gone from the listing")
                    fp["cleared"].append(note)
                    cleared.append(note)
                    self.notes.append(note)
                fp.update(streak=0, fired=False, dark_since=None)
            fp["state"] = state
            fp["link"] = link
            if state == "gone" and f is None:
                continue
            d = dark_paths.get(path) or {}
            cites = [dict(c, text=cite_text(c.get("text"))) for c in _cite_list(d.get("cites") or (f or {}).get("cites"))]
            self.seq += 1
            lines.append({"ts": ts, "seq": self.seq, "session_id": SESSION, "phase": "pre", "tool": FOOTPRINT_TOOL,
                          "cwd": CWD, "source": SOURCE,
                          "input_meta": {"round": n, "path": path, "agent": fp["agent"], "state": state,
                                         "dark": state == "dark", "streak": fp["streak"], "linked": link,
                                         "sample": sample, "run": self.run,
                                         "cites": [dict(c) for c in cites[:CITES_KEPT]]}})
            fp["cites"] = cites[:CITES_KEPT]
            fp["line_seq"] = self.seq

        found, notes = engine.evaluate(self.rules, lines)
        by_seq = {l["seq"]: l for l in lines}
        fired = []
        for f in found:
            line = by_seq[f["cited_seq"][0]]
            meta = line["input_meta"]
            entry = {"rule_id": f["rule_id"], "kind": f["kind"], "class": f.get("class"), "severity": f["severity"],
                     "summary": f["summary"], "cited_seq": f["cited_seq"], "round": n, "sample": sample, "at": ts,
                     "session_id": f["session_id"], "run": self.run, "notice": None}
            if f["rule_id"] in NEW_RULES:
                key = next(k for k, v in self.trees.items() if v.get("line_seq") == line["seq"])
                tree = self.trees[key]
                entry.update(tree=tree_word(key), tree_key=list(key), image=meta["image"], pid=meta["pid"],
                             named=meta["named_word"], cites=tree["cites"])
                where = "%s pid %s (%s)" % (str(meta["image"] or "?")[:IMAGE_MAX], meta["pid"], meta["named_word"])
                limit = "%s pid %s" % (f["rule_id"], meta["pid"])   # C-5: each tree knocks under its own id
            else:
                fp = self.footprints[meta["path"]]
                fp["fired"] = True
                entry.update(path=meta["path"], agent=meta["agent"], cites=fp["cites"], streak=meta["streak"])
                where = "%s footprint, %d rounds (round %d)" % (str(meta["agent"] or "?")[:IMAGE_MAX],
                                                               meta["streak"], n)
                limit = "%s %s" % (f["rule_id"], meta["path"])     # each footprint under its own id
            entry["notice"] = self.notifier.notify(f["rule_id"], where, now, token=(entry, "notice"), limit_id=limit)
            if f["rule_id"] in NEW_RULES:
                tree["knocked"] = entry["notice"]
            self.findings.append(entry)
            fired.append("%s %s" % (f["rule_id"], entry.get("tree") or entry.get("path")))
            self._say(now, "FINDING [%s] %s round %d: %s (%s)" % (f["severity"], f["rule_id"], n, f["summary"],
                                                                 entry["notice"]))
        for note in notes:
            if note["status"] != "disabled":
                text = "round %d: rule %s %s: %s" % (n, note["rule_id"], note["status"], note["detail"])
                self._hole(now, "host-rule", text)
        record = {"round": n, "at": ts, "seconds": round(seconds, 3), "late": late, "error": None,
                  "sample": sample, "records": inv.get("records"), "holes": len(inv.get("holes") or []),
                  "incomplete": list(inv.get("incomplete") or []), "result": inv.get("result"),
                  "nothing_read": nothing, "unread_lines": len(problems),
                  "trees": sorted(tree_word(k) for k in current),
                  "candidates": sum(1 for t in current.values() if t["class"] == "candidate"),
                  "act_roots": sum(1 for t in current.values() if t["class"] == "act-root"),
                  "history": first, "new": new, "benign": benign_new, "gone": gone, "back": back, "dark": dark_now,
                  "cleared": cleared, "findings": fired, "lines": lines}
        self.last_round = record
        self._record(record)
        try:   # C-2: the inventory names the run and the round it is of
            write_json(self.inventory_path, dict(inv, host_watch={"run": self.run, "round": n, "at": ts}))
        except OSError as exc:
            detail = "cannot write %s: %s" % (self.inventory_path, exc.strerror or exc)
            if not any(h["detail"] == detail for h in self.holes):
                self._hole(now, "inventory-unwritable", detail)
        self._say(now, self.round_text(record))
        for note in cleared:
            self._say(now, note)

    def round_text(self, r):
        head = "round %d%s: %s records read, %s holes" % (r["round"], " (late, %.1f s)" % r["seconds"] if r["late"]
                                                          else "", r["records"], r["holes"])
        if r.get("unread_lines"):
            head += ", %d line(s) could not be read" % r["unread_lines"]
        if r.get("nothing_read"):   # D-2: never "no agent seen" of a round that read nothing
            return "%s; NOTHING READ: an unread round (%s). Not a clearance." % (head, r["sample"])
        if not r["trees"]:
            return "%s; NO AGENT SEEN (%s; %s). Not a clearance." % (head, r["sample"], r["result"])
        parts = ["%d tree(s) now: %d candidate(s), %d act-root(s)" % (len(r["trees"]), r["candidates"], r["act_roots"])]
        if r["history"]:
            parts.append("history (there at the start, not knocked)")
        for word in ("new", "benign", "back", "gone", "dark"):
            if r.get(word):
                parts.append("%s: %s" % (word, ", ".join(r[word])))
        return "%s; %s" % (head, "; ".join(parts))

    # --- the end --------------------------------------------------------------------

    def finish(self, now=None, status="finished", error=None):
        with self.lock:
            now = self.clock() if now is None else now
            if self.worker is not None:
                self._hole(now, "reader-out", "round %d: the reader was still out at the end (%.1f s after it"
                           " started, deadline %g s); what it would have read is not seen" % (
                               self.worker_round, now - self.worker_began, self.deadline_seconds), round_=self.worker_round)
            self.status, self.error = status, error
            self.finished = self.at(now)
            self.beat = now
            self.beat_wall = self.wall_clock()
            try:
                self._write_state(now)
            except Exception as exc:
                self.state_error = "cannot write %s: %s: %s" % (self.state_path, type(exc).__name__, exc)
            try:
                self.final_text, self.final_exit = self.summary()
            except Exception as exc:
                self.final_text, self.final_exit = "raqib watch --host: no final report (%s: %s)\n" % (
                    type(exc).__name__, _safe(exc)), 1
        return self.final_text, self.final_exit

    def result(self):
        """(result, reasons), C-10: alarm (exit 1) for a finding of a host
        rule or a crash; incomplete (3) when a round could not be read (a
        reader hole), no round gave an inventory, an inventory was
        incomplete, or another hole of the watch; else clean (0) with the
        trees named, or none-seen (0) when no tree was seen. A tree that was
        there at the start, or is benign, is listed, not an alarm (B-3); a
        new one is a finding."""
        alarms, incomplete = [], []
        if self.status == "crashed":
            alarms.append("the watch crashed: %s" % self.error)
        if self.findings:
            alarms.append("%d finding(s): %s" % (len(self.findings), ", ".join(sorted(
                {f["rule_id"] for f in self.findings}))))
        if not self.applied:
            incomplete.append("no round gave an inventory: nothing read (A3)")
        unread_rounds = sorted({h.get("round") for h in self.holes if h["kind"] == "round-unread"}, key=str)
        if unread_rounds:   # D-2: exit 3, never none-seen
            incomplete.append("%d round(s) read nothing (round %s): unread round(s)" % (
                len(unread_rounds), ", ".join(map(str, unread_rounds))))
        lines_unread = [h for h in self.holes if h["kind"] == "lines-unread"]
        if lines_unread:    # D-2: a hole, exit 3 unless a finding makes it 1
            incomplete.append("%d round(s) with line(s) that could not be read (round %s)" % (
                len(lines_unread), ", ".join(str(h.get("round")) for h in lines_unread)))
        reader = [h for h in self.holes if h["kind"] in READER_HOLES]
        unread = sorted({h.get("round") for h in reader if h["kind"] != "reader-late"}, key=str)
        late = sorted({h.get("round") for h in reader if h["kind"] == "reader-late"}, key=str)
        if unread:
            incomplete.append("%d round(s) could not be read (round %s): %d reader hole(s)" % (
                len(unread), ", ".join(map(str, unread)), len(reader)))
        if late:
            incomplete.append("%d round(s) whose reader was not back within %g s (round %s): a hole" % (
                len(late), self.deadline_seconds, ", ".join(map(str, late))))
        if self.unread:   # F-9: never CLEAN beside an unread or partly read source, whatever discover's word
            incomplete.append("%d round(s) with a source not read or partly read (round %s): %s" % (
                len(self.unread), ", ".join(str(n) for n, _ in self.unread),
                "; ".join(sorted({r for _, rs in self.unread for r in rs}))))
        if "incomplete" in self.results:
            incomplete.append("%d round(s) whose inventory is incomplete" % self.results.count("incomplete"))
        others = [h for h in self.holes if h not in reader and h["kind"] not in ("round-unread", "lines-unread")]
        if others:
            incomplete.append("%d hole(s) of the watch" % len(others))
        if self.state_error:
            incomplete.append(self.state_error)
        if alarms:
            return "alarm", alarms + incomplete
        if incomplete:
            return "incomplete", incomplete
        if self.trees:
            return "clean", ["%d tree(s) listed, none new: %s" % (len(self.trees), ", ".join(
                "%s pid %s" % (t["image"] or "?", t["pid"]) for t in self.trees.values()))]
        return "none-seen", []

    def summary(self):
        result, reasons = self.result()
        code = EXIT[result]
        out = ["Raqib watch --host (ADR-0007): the host, not a name",
               "host: %s; a round every %g s; window %g s; rounds %d%s" % (
                   self.platform, self.every, self.window, self.rounds,
                   " of %d" % self.rounds_max if self.rounds_max else ""),
               "state: %s (%s)" % (self.state_path, self.status),
               "record: %s; latest inventory: %s" % (self.rounds_path, self.inventory_path),
               "run: %s (seqs %d..%d of the record)" % (self.run, self.first_seq + 1, self.seq),
               "watched: %s to %s" % (self.at(self.t0), self.finished or "-"), ""]
        late = sum(1 for r in self.round_lines if r.get("late"))
        failed = sum(1 for r in self.round_lines if r.get("error"))
        out.append("ROUNDS: %d started, %d with an inventory, %d late, %d failed" % (
            self.rounds, self.applied, late, failed))
        out += ["  %s" % (self.round_text(r) if not r.get("error") else "round %d: reader FAILED: %s" % (
            r["round"], r["error"])) for r in self.round_lines]
        out.append("TREES SEEN: %d (%d now)" % (len(self.trees), len(self.present)))
        for key, t in self.trees.items():
            out.append("  %s pid %s %s (%s%s): %s; first round %d%s%s; last round %d; %d act(s)%s%s" % (
                "[%s]" % t["class"], t["pid"], t["image"] or "?", "named" if t["named"] else "unknown",
                ": " + t["named_by"] if t["named_by"] else "", "now" if t["present"] else "gone",
                t["first_round"], " (history, not knocked)" if t["history"] else "",
                " (benign: %s, not knocked)" % t["benign_by"] if t.get("benign") else "", t["last_round"], t["acts"],
                "; endpoints %s" % ", ".join(t["endpoints"]) if t["endpoints"] else "",
                "; %s %s" % (NEW_AGENT if t["named"] else NEW_UNKNOWN, t["knocked"]) if t["knocked"] else ""))
        if not self.trees:   # D-2: "no agent seen" only of rounds that read records
            read = [r for r in self.round_lines if not r.get("error") and not r.get("nothing_read")]
            unread = [r for r in self.round_lines if not r.get("error") and r.get("nothing_read")]
            if read:
                out.append("  NO AGENT SEEN in %d round(s) that read records (records read: %s). Not a clearance." % (
                    len(read), ", ".join(str(r.get("records")) for r in read)))
            if unread or not read:
                out.append("  NOTHING READ in %d round(s): no agent is said seen or unseen there (A3)." % (
                    len(unread) + (self.rounds - self.applied if not read else 0)))
        out.append("FINDINGS: %d" % len(self.findings))
        for f in self.findings:
            out.append("  [%s] %s round %d (%s): %s; %s; cites %s" % (
                f["severity"], f["rule_id"], f["round"], f["sample"], f["summary"], f["notice"],
                " ".join("%s:%s" % (c["src"], c["line"]) for c in f.get("cites") or []) or "-"))
        out.append("FOOTPRINTS: %d" % len(self.footprints))
        for fp in self.footprints.values():
            out.append("  %s (%s): %s%s" % (fp["path"], fp["agent"], fp["state"],
                                            ", dark %d round(s) in a row" % fp["streak"] if fp["streak"] else ""))
        out.append("NOTES: %d" % len(self.notes))
        out += ["  - %s" % n for n in self.notes]
        holes = self.holes + self.notifier.holes
        out.append("HOLES (A3): %d" % len(holes))
        out += ["  - %s: %s at %s%s" % (h["kind"], h["detail"], h["at"], " (%s)" % h["notice"] if h.get("notice")
                                        else "") for h in holes]
        n = self.notifier.state()
        counts = n["counts"]
        out.append("NOTIFICATIONS: %s; sent %d, terminal %d, failed %d, folded %d (%d still waiting), off %d" % (
            self.notifier.band()[1].replace("notifications: ", "", 1), counts["sent"], counts["terminal"],
            counts["failed"], counts["folded"], sum(n["folded_waiting"].values()), counts["off"]))
        why = {"clean": "trees listed, nothing new", "none-seen": "no tree seen in rounds that read records; not a"
               " clearance",
               "alarm": "a finding", "incomplete": "a round could not be read or the watch has a hole"}[result]
        out += ["", "ALARMS: %s" % ("; ".join(reasons) if result == "alarm" else "none"),
                "INCOMPLETE: %s" % ("; ".join(reasons) if result == "incomplete" else "none"),
                "CLEAN: %s" % ("; ".join(reasons) if result == "clean" else "none"),
                "RESULT: %s (exit %d: %s)" % (result.upper(), code, why)]
        return "\n".join(_safe(line) for line in out) + "\n", code

    # --- the state and the page -----------------------------------------------------

    def wall(self):
        return datetime.datetime.fromtimestamp(self.wall_clock(), datetime.timezone.utc)

    def state(self, now):
        reader = None
        if self.worker is not None:
            reader = {"round": self.worker_round, "since": self.at(self.worker_began),
                      "seconds": round(now - self.worker_began, 3), "late": self.worker_late}
        state = {
            "raqib_watch": 1, "mode": HOST, "project": HOST, "run": self.run, "first_seq": self.first_seq,
            "last_seq": self.seq, "trace": self.rounds_path, "state": self.state_path,
            "inventory": self.inventory_path, "pid": os.getpid(), "url": self.url, "port": self.port,
            "started": self.at(self.t0), "updated": iso(self.wall()),
            "heartbeat": iso(datetime.datetime.fromtimestamp(self.beat_wall, datetime.timezone.utc)),
            "heartbeat_age_seconds": round(now - self.beat, 3), "step_seconds": self.step_seconds,
            "heartbeat_every_seconds": POLL_SECONDS, "stale_after_seconds": STALE_SECONDS,
            "finished": self.finished, "error": self.error, "status": self.status,
            "every_seconds": self.every, "window_seconds": self.window, "deadline_seconds": self.deadline_seconds,
            "rounds_max": self.rounds_max, "platform": self.platform,
            "host": {"rounds": self.rounds, "applied": self.applied, "reader": reader,
                     "last_round": self._public(self.last_round),
                     "history_round": self.history_round,
                     "trees": list(self.trees.values()), "now": len(self.present),
                     "new": sum(1 for f in self.findings if f["rule_id"] in NEW_RULES),
                     "dark": [fp for fp in self.footprints.values() if fp["state"] == "dark"],
                     "footprints": list(self.footprints.values()), "findings": self.findings,
                     "notes": self.notes, "rounds_tail": [self._public(r) for r in self.round_lines]},
            "holes": self.holes + self.notifier.holes, "notifications": self.notifier.state(),
            "state_error": self.state_error, "refresh_seconds": self.refresh, "registry": self.registry_state,
        }
        state["band"] = ui.status(state)[0]
        return state

    @staticmethod
    def _public(r):
        return None if r is None else {k: v for k, v in r.items() if k != "lines"}

    def _write_state(self, now):
        try:
            write_json(self.state_path, self.state(now))
            self.state_error = None
        except OSError as exc:
            detail = "cannot write %s: %s" % (self.state_path, exc.strerror or exc)
            if detail != self.state_error:
                (self.err or sys.stderr).write("raqib watch --host: %s\n" % detail)
            self.state_error = detail

    def own(self):
        return os.getpid(), self.rounds_path, self.at(self.t0)

    def page(self):
        from raqib import watch   # the registry reader's freshness, as every watch reads it
        if not self.lock.acquire(timeout=15):
            raise RuntimeError("raqib watch --host is not responding: its loop has held the state for more than"
                               " 15 s (last heartbeat %s) (A3)" % self.at(self.beat))
        try:
            state = json.loads(json.dumps(self.state(self.clock())))
            registry = self.registry.path if self.registry else None
            own = dict(self.registry_state or {})
        finally:
            self.lock.release()
        watches = None
        if registry:
            watches = ui.read_watches(registry, self.wall(), HEARTBEATS_FRESH * POLL_SECONDS, own=self.own())
        return ui.host_page(state, refresh=self.refresh, watches=watches, own=own)

    def discover_page(self):
        return ui.discover_page(self.inventory_path, self.refresh, self.wall())

    # --- the registry row (E5) -------------------------------------------------------

    def register(self, registry):
        row = {"pid": os.getpid(), "project": HOST, "mode": HOST, "port": (self.port or {}).get("used"),
               "trace": self.rounds_path, "state": self.state_path, "url": self.url, "started": self.at(self.t0),
               "finished": None, "status": "watching", "notes": []}

        def edit(rows, note):
            rows.append(dict(row, notes=[note] if note else []))
        self.registry = registry
        return self._registry_change(edit, "registered")

    def unregister(self):
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
                rows.append({"pid": own[0], "project": HOST, "mode": HOST, "port": (self.port or {}).get("used"),
                             "trace": self.rounds_path, "state": self.state_path, "url": self.url,
                             "started": own[2], "finished": self.finished, "status": self.status,
                             "notes": ["this row was not in the registry at the end: added again"]})
        return self._registry_change(edit, "marked %s" % self.status)

    def _registry_change(self, edit, what):
        try:
            note, hole = self.registry.change(edit)
        except Exception as exc:
            note, hole = None, "the registry %s was not written (%s): %s" % (
                self.registry.path, what, getattr(exc, "strerror", None) or exc)
        with self.lock:
            now = self.clock()
            self.registry_state = {"path": self.registry.path, "row": what, "note": note, "hole": hole}
            if hole:
                self._hole(now, "registry", hole)
            self._write_state(now)
        return hole


# --- the command ------------------------------------------------------------------

class Running:
    def __init__(self, watcher, server, notifier, thread, no_open, environ, out, err):
        self.watcher, self.server, self.notifier, self.thread = watcher, server, notifier, thread
        self.no_open, self.environ, self.out, self.err = no_open, environ, out, err


def start(catalog, rules, every=EVERY_DEFAULT, window=0.0, rounds=None, no_open=False, no_notify=False, port=None,
          out=None, err=None, environ=None, home=None, refresh=None, reader=None, platform=None):
    """Everything before the loop: the notifier, the HostWatch, the page
    server and the registry row (raqib/watch.py's, reused)."""
    from raqib import watch
    out = out or sys.stdout
    err = err or sys.stderr
    environ = os.environ if environ is None else environ
    refresh = ui.REFRESH_DEFAULT if refresh is None else ui.check_refresh(refresh)
    platform = platform or sys.platform
    reader = reader or live_reader(catalog, window, platform)
    notifier = notify.Notifier(HOST, enabled=not no_notify, reason="--no-notify" if no_notify else None,
                               environ=environ, stderr=err, host=True,
                               tmp_root=os.path.join(home, ".raqib", "tmp") if home else None)
    try:
        watcher = HostWatch(reader, catalog, rules, notifier, every=every, window=window, rounds_max=rounds,
                            out=out, err=err, home=home, platform=platform)
    except HostError as exc:
        notifier.close()
        raise watch.WatchError(str(exc))
    watcher.refresh = refresh
    out.write("raqib watch --host: the host, not a name (ADR-0007); nothing is installed, no project is touched\n")
    out.write("raqib watch --host: a round every %g s (%s), the reader's deadline %g s; %s\n" % (
        every, "a /proc snapshot" if platform.startswith("linux") and not window else
        "%g s of /proc snapshots" % window if platform.startswith("linux") else
        "one sample of the OS API" if platform == "win32" else "the homes only (no live reader here)",
        watcher.deadline_seconds, "%d round(s)" % rounds if rounds else "until Ctrl-C"))
    out.write("raqib watch --host: record %s\nraqib watch --host: state %s\n" % (
        _safe(watcher.rounds_path), _safe(watcher.state_path)))
    out.write("raqib watch --host: %s\n" % notifier.band()[1])
    for note in watcher.notes:
        out.write("raqib watch --host: hole: %s\n" % _safe(note))
    try:
        server, watcher.port = watch._serve(watcher.page, port, routes={ui.DISCOVER_ROUTE: watcher.discover_page},
                                            refresh=refresh)
    except (OSError, OverflowError) as exc:
        notifier.close()
        raise watch.WatchError("cannot serve on 127.0.0.1:%s: %s" % (port, exc))
    watcher.url = "http://127.0.0.1:%d/" % server.server_address[1]
    hole = watcher.register(watch.Registry(watch.registry_path(home)))
    if hole:
        out.write("raqib watch --host: %s\n" % _safe(hole))
    thread = threading.Thread(target=server.serve_forever, name="raqib-host-page", daemon=True)
    thread.start()
    return Running(watcher, server, notifier, thread, no_open, environ, out, err)


_sleep = time.sleep   # the tick wait; tests replace it


def loop(running, stop=None):
    """Tick until --rounds are done, Ctrl-C, or stop is set; None, or the
    crash text."""
    from raqib import watch
    watcher, out = running.watcher, running.out
    crash = None
    try:
        if watcher.port["warning"]:
            out.write("raqib watch --host: WARNING: %s\n" % watcher.port["warning"])
        out.write("raqib watch --host: page %s (read-only, reloads every %d s; %s ends the watch)\n" % (
            watcher.url, watcher.refresh, "Ctrl-C" if stop is None else "Stop"))
        if running.no_open or running.environ.get("CI"):
            out.write("raqib watch --host: page not opened (%s)\n" % ("--no-open" if running.no_open else "CI is set"))
        else:
            why = watch.open_page(watcher.url, running.environ)
            if why:
                out.write("raqib watch --host: page not opened (%s); open it by hand\n" % why)
        out.flush()
        stopped = None
        while True:
            watcher.tick()
            if watcher.done_rounds():
                out.write("raqib watch --host: %d round(s) done (--rounds)%s\n" % (
                    watcher.rounds, "" if watcher.worker is None else
                    "; round %d's reader is past its deadline (%g s) and is left out: a hole%s" % (
                        watcher.worker_round, watcher.deadline_seconds,
                        "; round(s) %d..%d attempted without a reader (D-1)" % (watcher.worker_round + 1, watcher.rounds)
                        if watcher.rounds > watcher.worker_round else "")))
                break
            if stopped is None and stop is not None and stop.is_set():
                stopped = stop.reason
                watcher.stopping = True   # C-3: no new round; the one out has until its deadline
            if stopped is not None and watcher.settled():
                out.write("\nraqib watch --host: stopped (%s)\n" % _safe(stopped))
                break
            if stop is None or stopped is not None:
                _sleep(POLL_SECONDS)
            else:
                stop.wait(POLL_SECONDS)
    except KeyboardInterrupt:
        out.write("\nraqib watch --host: stopped (Ctrl-C)\n")
    except Exception as exc:
        crash = "%s: %s" % (type(exc).__name__, exc)
        out.write("\nraqib watch --host: CRASHED: %s\n" % _safe(crash))
        traceback.print_exc(file=running.err)
    return crash


def conclude(running, crash):
    watcher, out = running.watcher, running.out
    text, code = watcher.finish(status="crashed" if crash else "finished", error=crash)
    try:
        hole = watcher.unregister()
    except Exception as exc:
        hole = "the registry was not marked: %s: %s" % (type(exc).__name__, exc)
    if hole:
        out.write("raqib watch --host: %s\n" % _safe(hole))
    return text, code


def close(running):
    try:
        running.server.shutdown()
        running.server.server_close()
    finally:
        running.notifier.close()


def command(catalog, rules, every=EVERY_DEFAULT, window=0.0, rounds=None, no_open=False, no_notify=False, port=None,
            out=None, err=None, environ=None, home=None, refresh=None, reader=None, platform=None):
    """raqib watch --host; the exit code of the final report."""
    out = out or sys.stdout
    running = start(catalog, rules, every, window, rounds, no_open, no_notify, port, out, err, environ, home,
                    refresh, reader, platform)
    try:
        crash = loop(running)
        text, code = conclude(running, crash)
    finally:
        close(running)
    out.write("\n" + text)
    return code
