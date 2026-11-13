"""The events file: the watch says its events while it runs (ADR-0011 Amendment F, F-1 to F-6).

One writer, outside the judging (F-1). It is given the file, the watch's
facts (event.facts) and the rule table ({rule id: row of report.rule_table});
it keeps the run's count (n, from 1) and, for each thing by its `about`, the
revision last said and what was said (the event without its id, n, rev and
time). say() builds the event with raqib/event.py and writes one line -
appended, flushed - when the thing is new (rev 1) or what would be said of it
changed (the next rev); the same again is not written. A heartbeat and the
watch's end are written whatever else changed (F-3).

ledgers() is the watch's pass over its own lists (F-2): the watch gives each
list apart and names nothing by guessing from what an entry holds: its trees
("tree:<word>"), findings ("finding:i"), source findings ("source-finding:i"),
its own holes ("hole:i"), the notifier's ("notifier-hole:i"), blind spots
("blind:i"), its own notes ("note:i"), the note of the words a terminal lost
("note:lost-words") and the knock rows ("knock:i"). A blind spot's count and
the lost-words note change every round or every lost word: once said, they
are said again only with a beat (F-3).

What cannot be said is said (F-4): a builder that raises is returned as a
problem, once per thing, naming the thing and the key (the watch makes it a
hole and the pass goes on); a line that cannot be written is counted
(not_written) and its reason returned once. Its number is used all the same:
a collector sees the gap in n. The module reads no clock and no network:
the caller gives every time (B-4); the host's name is read once by
host_name() from the system's own call, platform.node() (CLAUDE.md rule 5).
"""
import platform as _platform

from raqib import event

NAME = "events.jsonl"     # beside the watch's record (rounds.jsonl)
BEAT_DEFAULT = 60.0       # F-3: seconds; never shorter than a round
UNNAMED = "unnamed"       # F-6: the host's name where the system gives none
VARY = ("id", "n", "rev", "time")   # what changes with each saying, not with the thing


def TREE_CORE(said):
    """What of a tree is said again at once when it changes (named, benign, history, knocked ...); its evidence -
    the HostTree line of the latest round and that round's cites, which move every round - waits for a beat."""
    return {k: v for k, v in said.items() if k != "evidence"}


def host_name(given=None, system=None):
    """F-6: (name, from): the name given (--event-host) replaces the system's; the system's own is read once,
    platform.node() (the platform's own name of this machine: no network call, no lookup, no socket); none:
    UNNAMED. from is "given", "system" or "none"."""
    if isinstance(given, str) and given.strip():
        return given.strip(), "given"
    for read in (system,) if system is not None else (_platform.node,):
        try:
            name = read()
        except (OSError, ValueError):
            name = None
        if isinstance(name, str) and name.strip():
            return name.strip(), "system"
    return UNNAMED, "none"


class EventLog:
    def __init__(self, path, facts, rules, beat=BEAT_DEFAULT):
        self.path = path
        self.facts = dict(facts)
        self.rules = rules if isinstance(rules, dict) else {}
        self.beat = float(beat)
        self.n = 0                 # the run's count: the last number used
        self.said = {}             # about -> (rev, what was said)
        self.unbuilt = {}          # about -> why it could not be built (F-4: one hole per thing)
        self.written = 0
        self.heartbeats = 0
        self.not_written = 0
        self.write_error = None    # why the first line was not written (said once)
        self.next_beat = None      # the monotonic time the next beat is due
        self.ended = False

    @property
    def not_built(self):
        return len(self.unbuilt)

    def counts(self):
        """F-7: the numbers the report's EVENTS line and the state carry."""
        return {"file": self.path, "written": self.written, "heartbeats": self.heartbeats,
                "not_built": self.not_built, "not_written": self.not_written, "beat_seconds": self.beat,
                "host": self.facts.get("host"), "last_n": self.n, "write_error": self.write_error}

    def say(self, about, build, again=True, force=False, core=None):
        """One thing: build(n, rev) -> its event. again=False: a thing already said is not said again now (F-3: a
        blind spot's count, the lost-words note, between two beats); with core (event -> its part that is said at
        once when it changes), only what is outside core waits for the beat (a tree's record line, which moves every
        round). force: written though nothing changed (a heartbeat, the end). Returns (what, detail): ("written", event), ("same", None), ("held", None),
        ("not built", why or None when said before), ("not written", why or None when said before)."""
        last = self.said.get(about)
        if last is not None and not again and not force and core is None:
            return "held", None
        rev = 1 if last is None else last[0] + 1
        try:
            ev = build(self.n + 1, rev)
        except Exception as exc:   # C-10: an entry that lacks what its kind requires; never a half event
            first = about not in self.unbuilt
            self.unbuilt.setdefault(about, "%s" % exc)
            return "not built", ("%s: %s" % (about, exc)) if first else None
        self.unbuilt.pop(about, None)
        said = {k: v for k, v in ev.items() if k not in VARY}
        what = event.line(said)
        kernel = event.line(core(said)) if core is not None else None
        if last is not None and not force:
            if last[1] == what:
                return "same", None
            if not again and core is not None and last[2] == kernel:
                return "held", None
        self.n += 1   # used even when the line is not written: a collector sees the gap (rule 4)
        try:
            with open(self.path, "a", encoding="ascii", newline="\n") as f:
                f.write(event.line(ev) + "\n")
                f.flush()
        except (OSError, ValueError) as exc:
            self.not_written += 1
            if self.write_error is None:
                self.write_error = "cannot append to %s: %s" % (self.path, getattr(exc, "strerror", None) or exc)
                return "not written", self.write_error
            return "not written", None
        self.said[about] = (rev, what, kernel)
        self.written += 1
        if ev.get("kind") == "heartbeat":
            self.heartbeats += 1
        return "written", ev

    # --- the watch's moments --------------------------------------------------------------------------------

    def start(self, time, now):
        """F-2: the first event of the watch, "watch" rev 1; the beat is counted from it."""
        self.next_beat = now + self.beat
        return self.say("watch", lambda n, rev: event.watch_start({}, self.facts, time, n, rev=rev), force=True)

    def due(self, now):
        return self.next_beat is not None and not self.ended and now >= self.next_beat

    def heartbeat(self, state, time, now):
        """F-3: the watch's beat ("watch", the next rev), written though nothing else changed."""
        while self.next_beat is not None and self.next_beat <= now:
            self.next_beat += self.beat
        return self.say("watch", lambda n, rev: event.heartbeat(state, self.facts, time, n, rev=rev), force=True)

    def end(self, state, time, exit):
        """F-2: the last event, the watch's end with the report's exit (said again, the next rev, if the report's
        exit is found to differ)."""
        self.ended = True
        return self.say("watch", lambda n, rev: event.watch_end(state, self.facts, time, n, exit, rev=rev),
                        force=True)

    def ledgers(self, time, trees=(), findings=(), source_findings=(), holes=(), notifier_holes=(), blind=(),
                notes=(), dark_notes=(), lost=None, knocks=(), record=None, beat=False):
        """F-2: one pass over the watch's lists, each named from the list it is in. An entry's own time ("at", a
        tree's first_seen) where it is a real instant, else the time given. holes is iterated as it grows (a hole
        the caller appends while the pass runs is said in it). Returns the problems said for the first time:
        [(what, detail)] with what "not built" or "not written"."""
        problems = []
        rules = self.rules

        def own(entry, key="at"):
            return entry[key] if isinstance(entry, dict) and event.instant(entry.get(key)) else time

        def one(about, build, again=True, core=None):
            what, detail = self.say(about, build, again=again, core=core)
            if what in ("not built", "not written") and detail:
                problems.append((what, detail))

        for row in trees:
            word = event.tree_word(row["key"]) if isinstance(row, dict) and isinstance(
                row.get("key"), (list, tuple)) and len(row["key"]) == 3 else "?"
            one("tree:%s" % word, lambda n, rev, r=row, a="tree:%s" % word: event.tree(
                r, self.facts, own(r, "first_seen"), n, a, rev, record=record), again=beat, core=TREE_CORE)
        for i, e in enumerate(findings, 1):
            one("finding:%d" % i, lambda n, rev, e=e, a="finding:%d" % i: event.finding(
                e, self.facts, own(e), n, a, rev, rule=rules.get(e.get("rule_id")), record=record))
        for i, e in enumerate(source_findings, 1):
            one("source-finding:%d" % i, lambda n, rev, e=e, a="source-finding:%d" % i: event.source_finding(
                e, self.facts, own(e), n, a, rev, rule=rules.get(e.get("rule_id"))))
        for whose, ledger in (("hole", holes), ("notifier-hole", notifier_holes)):
            i = 0
            while i < len(ledger):
                e, i = ledger[i], i + 1
                one("%s:%d" % (whose, i), lambda n, rev, e=e, a="%s:%d" % (whose, i): event.hole(
                    e, self.facts, own(e), n, a, rev))
        for i, e in enumerate(blind, 1):
            one("blind:%d" % i, lambda n, rev, e=e, a="blind:%d" % i: event.hole(e, self.facts, own(e), n, a, rev),
                again=beat)
        dark = {d.get("text"): d for d in dark_notes if isinstance(d, dict)}
        for i, text in enumerate(notes, 1):
            e = dark.get(text, text)
            one("note:%d" % i, lambda n, rev, e=e, a="note:%d" % i: event.note(e, self.facts, own(e), n, a, rev,
                                                                              record=record))
        if isinstance(lost, str) and lost:
            one(event.LOST, lambda n, rev: event.note(lost, self.facts, time, n, event.LOST, rev), again=beat)
        for i, row in enumerate(knocks, 1):
            one("knock:%d" % i, lambda n, rev, r=row, a="knock:%d" % i: event.knock(r, self.facts, own(r), n, a, rev))
        return problems
