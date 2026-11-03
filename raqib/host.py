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
- NEW-AGENT (high): a candidate tree that is not history and was not a
  candidate in any earlier round of this watch. A tree is keyed by (root
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
the cited record lines of the inventory, with their text (A5).

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
DARK_LIVE = "AGENT-DARK-LIVE"
RULES = (NEW_AGENT, DARK_LIVE)
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
        texts, holes, _ = discover.collect_live(catalog, window=window, homes=homes, platform=platform,
                                                win_samples=1, win_every=0.0)
        return discover.run(texts, catalog, holes=holes, live=True)
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


def trees_of(inv, catalog):
    """{key: tree} of an inventory: its candidates and its act-roots, keyed
    by (pid, image, started)."""
    out = {}
    for cls, group in (("candidate", inv.get("candidates") or []), ("act-root", inv.get("act_roots") or [])):
        for t in group:
            key = (t.get("pid"), t.get("image"), t.get("started"))
            if key in out:     # a pid both: the candidate stands
                continue
            ok, why = named(t, catalog)
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
                        "named_by": why, "acts": len(t.get("acts") or []), "endpoints": endpoints,
                        "cites": cites[:CITES_KEPT]}
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
                 out=None, err=None, clock=None, wall=None, home=None, platform=None, deadline=None):
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
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as exc:
            raise HostError("cannot create %s: %s" % (self.dir, exc.strerror or exc))

    # --- time and output -------------------------------------------------------

    def at(self, now):
        return iso(self.started + datetime.timedelta(seconds=now - self.t0))

    def _say(self, now, text):
        if self.out is not None:
            self.out.write("[%sZ] %s\n" % (self.at(now)[11:19], _safe(text)))
            self.out.flush()

    def _hole(self, now, kind, detail, knock=None):
        hole = {"kind": kind, "detail": detail, "at": self.at(now), "notice": None}
        self.holes.append(hole)
        if knock:
            hole["notice"] = self.notifier.notify(HOLE_EVENT, knock, now, token=(hole, "notice"))
        return hole

    # --- one tick ---------------------------------------------------------------

    def done_rounds(self):
        """True when --rounds N have run and none is out."""
        return self.rounds_max is not None and self.rounds >= self.rounds_max and self.worker is None

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
        if self.worker is None and now >= self.next_round and not (
                self.rounds_max is not None and self.rounds >= self.rounds_max):
            self.rounds += 1
            self.worker_round = self.rounds
            self.worker_late = False
            self.worker_began = now
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
                              knock="round %d, reader not back in %g s" % (self.worker_round, self.deadline_seconds))
            self._say(now, "%s round %d: the reader is not back within %g s (%s)" % (
                HOLE_EVENT, self.worker_round, self.deadline_seconds, hole["notice"]))

    def _record(self, line):
        self.round_lines.append(line)
        del self.round_lines[:-ROUNDS_KEPT]
        try:
            with open(self.rounds_path, "a", encoding="ascii", newline="\n") as f:
                f.write(json.dumps(line, sort_keys=True, ensure_ascii=True) + "\n")
        except OSError as exc:
            detail = "cannot append to %s: %s" % (self.rounds_path, exc.strerror or exc)
            if not any(h["detail"] == detail for h in self.holes):
                self._hole(self.clock(), "rounds-unwritable", detail)

    def _failed(self, now, n, error, seconds):
        hole = self._hole(now, "reader-failed", "round %d: the reader failed: %s" % (n, error),
                          knock="round %d, reader failed" % n)
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
        first = self.history_round is None
        if first:
            self.history_round = n
        sample = sample_of(inv)
        ts = self.at(now)
        current = trees_of(inv, self.catalog)
        lines, new, back, gone = [], [], [], []
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
            entry.update({k: t[k] for k in ("class", "id", "named", "named_by", "acts", "endpoints", "cites", "exe")})
            entry.update(last_round=n, last_seen=ts, present=True, rounds_seen=entry["rounds_seen"] + 1,
                         history=history)
            self.seq += 1
            line = {"ts": ts, "seq": self.seq, "session_id": SESSION, "phase": "pre", "tool": TREE_TOOL,
                    "cwd": CWD, "source": SOURCE,
                    "input_meta": {"round": n, "tree": tree_word(key), "pid": t["pid"], "image": t["image"],
                                   "started": t["started"], "class": t["class"], "was": was,
                                   "history": history, "candidate_before": candidate_before,
                                   "named": t["named"], "named_word": "named" if t["named"] else "unknown",
                                   "named_by": t["named_by"], "acts": t["acts"], "endpoints": t["endpoints"],
                                   "sample": sample, "cites": ["%s:%s" % (c["src"], c["line"]) for c in t["cites"]]}}
            lines.append(line)
            entry["line_seq"] = self.seq
            if t["class"] == "candidate" and entry["candidate_round"] is None:
                entry["candidate_round"] = n
            if not candidate_before and t["class"] == "candidate" and not history:
                new.append(tree_word(key))
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
            cites = _cite_list(d.get("cites") or (f or {}).get("cites"))
            self.seq += 1
            lines.append({"ts": ts, "seq": self.seq, "session_id": SESSION, "phase": "pre", "tool": FOOTPRINT_TOOL,
                          "cwd": CWD, "source": SOURCE,
                          "input_meta": {"round": n, "path": path, "agent": fp["agent"], "state": state,
                                         "dark": state == "dark", "streak": fp["streak"], "linked": link,
                                         "sample": sample,
                                         "cites": ["%s:%s" % (c["src"], c["line"]) for c in cites[:CITES_KEPT]]}})
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
                     "session_id": f["session_id"], "notice": None}
            if f["rule_id"] == NEW_AGENT:
                key = next(k for k, v in self.trees.items() if v.get("line_seq") == line["seq"])
                tree = self.trees[key]
                entry.update(tree=tree_word(key), image=meta["image"], pid=meta["pid"], named=meta["named_word"],
                             cites=tree["cites"])
                where = "%s pid %s (%s)" % (str(meta["image"] or "?")[:IMAGE_MAX], meta["pid"], meta["named_word"])
            else:
                fp = self.footprints[meta["path"]]
                fp["fired"] = True
                entry.update(path=meta["path"], agent=meta["agent"], cites=fp["cites"], streak=meta["streak"])
                where = "%s footprint, %d rounds (round %d)" % (str(meta["agent"] or "?")[:IMAGE_MAX],
                                                               meta["streak"], n)
            entry["notice"] = self.notifier.notify(f["rule_id"], where, now, token=(entry, "notice"))
            if f["rule_id"] == NEW_AGENT:
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
                  "trees": sorted(tree_word(k) for k in current),
                  "candidates": sum(1 for t in current.values() if t["class"] == "candidate"),
                  "act_roots": sum(1 for t in current.values() if t["class"] == "act-root"),
                  "history": first, "new": new, "gone": gone, "back": back, "dark": dark_now, "cleared": cleared,
                  "findings": fired, "lines": lines}
        self.last_round = record
        self._record(record)
        try:
            write_json(self.inventory_path, inv)
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
        if not r["trees"]:
            return "%s; NO AGENT SEEN (%s; %s). Not a clearance." % (head, r["sample"], r["result"])
        parts = ["%d tree(s) now: %d candidate(s), %d act-root(s)" % (len(r["trees"]), r["candidates"], r["act_roots"])]
        if r["history"]:
            parts.append("history (there at the start, not knocked)")
        for word in ("new", "back", "gone", "dark"):
            if r[word]:
                parts.append("%s: %s" % (word, ", ".join(r[word])))
        return "%s; %s" % (head, "; ".join(parts))

    # --- the end --------------------------------------------------------------------

    def finish(self, now=None, status="finished", error=None):
        with self.lock:
            now = self.clock() if now is None else now
            if self.worker is not None:
                self._hole(now, "reader-out", "round %d: the reader was still out at the end (%.1f s after it"
                           " started); what it would have read is not seen" % (self.worker_round,
                                                                               now - self.worker_began))
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
        """(result, reasons): alarm (1), incomplete (3) or none-seen (0)."""
        alarms, incomplete = [], []
        if self.status == "crashed":
            alarms.append("the watch crashed: %s" % self.error)
        if not self.applied:
            alarms.append("no round gave an inventory: nothing read (A3)")
        if self.trees:
            alarms.append("%d tree(s) seen that talk and act (or act, talk not seen)" % len(self.trees))
        if self.findings:
            alarms.append("%d finding(s)" % len(self.findings))
        reader = [h for h in self.holes if h["kind"] in ("reader-late", "reader-failed", "reader-out")]
        if reader:
            alarms.append("%d reader hole(s)" % len(reader))
        if "alarm" in self.results:
            alarms.append("%d round(s) whose inventory is an alarm" % self.results.count("alarm"))
        if "incomplete" in self.results:
            incomplete.append("%d round(s) whose inventory is incomplete" % self.results.count("incomplete"))
        others = [h for h in self.holes if h not in reader]
        if others:
            incomplete.append("%d hole(s) of the watch" % len(others))
        if self.state_error:
            incomplete.append(self.state_error)
        if alarms:
            return "alarm", alarms
        return ("incomplete", incomplete) if incomplete else ("none-seen", [])

    def summary(self):
        result, reasons = self.result()
        code = discover.EXIT[result]
        out = ["Raqib watch --host (ADR-0007): the host, not a name",
               "host: %s; a round every %g s; window %g s; rounds %d%s" % (
                   self.platform, self.every, self.window, self.rounds,
                   " of %d" % self.rounds_max if self.rounds_max else ""),
               "state: %s (%s)" % (self.state_path, self.status),
               "record: %s; latest inventory: %s" % (self.rounds_path, self.inventory_path),
               "watched: %s to %s" % (self.at(self.t0), self.finished or "-"), ""]
        late = sum(1 for r in self.round_lines if r.get("late"))
        failed = sum(1 for r in self.round_lines if r.get("error"))
        out.append("ROUNDS: %d started, %d with an inventory, %d late, %d failed" % (
            self.rounds, self.applied, late, failed))
        out += ["  %s" % (self.round_text(r) if not r.get("error") else "round %d: reader FAILED: %s" % (
            r["round"], r["error"])) for r in self.round_lines]
        out.append("TREES SEEN: %d (%d now)" % (len(self.trees), len(self.present)))
        for key, t in self.trees.items():
            out.append("  %s pid %s %s (%s%s): %s; first round %d%s; last round %d; %d act(s)%s%s" % (
                "[%s]" % t["class"], t["pid"], t["image"] or "?", "named" if t["named"] else "unknown",
                ": " + t["named_by"] if t["named_by"] else "", "now" if t["present"] else "gone",
                t["first_round"], " (history, not knocked)" if t["history"] else "", t["last_round"], t["acts"],
                "; endpoints %s" % ", ".join(t["endpoints"]) if t["endpoints"] else "",
                "; NEW-AGENT %s" % t["knocked"] if t["knocked"] else ""))
        if not self.trees:
            out.append("  NO AGENT SEEN in %d round(s) with an inventory (records read: %s). Not a clearance." % (
                self.applied, ", ".join(str(r.get("records")) for r in self.round_lines if not r.get("error")) or "none"))
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
        out.append("NOTIFICATIONS: %s; sent %d, terminal %d, failed %d, folded %d, off %d" % (
            self.notifier.band()[1].replace("notifications: ", "", 1), counts["sent"], counts["terminal"],
            counts["failed"], counts["folded"], counts["off"]))
        out += ["", "ALARMS: %s" % ("; ".join(reasons) if result == "alarm" else "none"),
                "INCOMPLETE: %s" % ("; ".join(reasons) if result == "incomplete" else "none"),
                "RESULT: %s (exit %d)" % (result.upper(), code)]
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
            "raqib_watch": 1, "mode": HOST, "project": HOST, "trace": self.rounds_path, "state": self.state_path,
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
                     "new": sum(1 for f in self.findings if f["rule_id"] == NEW_AGENT),
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
        while True:
            watcher.tick()
            if watcher.done_rounds():
                out.write("raqib watch --host: %d round(s) done (--rounds)\n" % watcher.rounds)
                break
            if stop is None:
                _sleep(POLL_SECONDS)
            elif stop.wait(POLL_SECONDS):
                out.write("\nraqib watch --host: stopped (%s)\n" % _safe(stop.reason))
                break
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
