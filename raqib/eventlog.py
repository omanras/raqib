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
("note:lost-words") and the knock rows ("knock:i"). The lost-words note is
said again only with a beat (F-3); a tree's evidence and a blind spot's count
only at the finish (G-2). Between beats a pass looks only at what is new and
what can still change (G-6 c); nothing it calls can end it (G-6 a); a line
is never glued to a torn one (G-6 b).

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
        self.whole = False         # G-6 (b): the file is known to end in a newline (after a line written here)
        self.mended = 0            # G-6 (b): torn lines ended with a newline before the next line
        self.marks = {}            # G-6 (c): list -> how many of its first entries are said (or cannot be built)
        self.open = {}             # G-6 (c): list -> the places of entries said that can still change
        self.folded = set()        # G-1: the places of source findings said as one act with another
        self.builds = 0            # G-6 (c): the builder calls (what a pass cost)
        self.longest = 0.0         # G-6 (c): the longest pass, in seconds (the watch measures it)

    @property
    def not_built(self):
        return len(self.unbuilt)

    def counts(self):
        """F-7: the numbers the report's EVENTS line and the state carry."""
        return {"file": self.path, "written": self.written, "heartbeats": self.heartbeats,
                "not_built": self.not_built, "not_written": self.not_written, "beat_seconds": self.beat,
                "host": self.facts.get("host"), "last_n": self.n, "write_error": self.write_error,
                "longest_pass_seconds": round(self.longest, 3), "mended": self.mended}

    def say(self, about, build, again=True, force=False, core=None):
        """One thing: build(n, rev) -> its event. again=False: a thing already said is not said again now (G-2: a
        tree's evidence and a blind spot's count until the finish; F-3: the lost-words note until a beat); with core
        (event -> its part that is said at once when it changes), only what is outside core waits (a tree's record
        line, which moves every round). force: written though nothing changed (a heartbeat, the end). G-6 (a):
        nothing in it can raise; a line that cannot be made is a thing not built. Returns (what, detail):
        ("written", event), ("same", None), ("held", None), ("not built", why or None when said before),
        ("not written", why or None when said before)."""
        last = self.said.get(about)
        if last is not None and not again and not force and core is None:
            return "held", None
        rev = 1 if last is None else last[0] + 1
        try:
            self.builds += 1
            ev = build(self.n + 1, rev)
            said = {k: v for k, v in ev.items() if k not in VARY}
            what = event.line(said)
            kernel = event.line(core(said)) if core is not None else None
            data = (event.line(ev) + "\n").encode("ascii")
        except Exception as exc:   # C-10: an entry that lacks what its kind requires; never a half event
            first = about not in self.unbuilt
            self.unbuilt.setdefault(about, "%s" % exc)
            return "not built", ("%s: %s" % (about, exc)) if first else None
        self.unbuilt.pop(about, None)
        if last is not None and not force:
            if last[1] == what:
                return "same", None
            if not again and core is not None and last[2] == kernel:
                return "held", None
        self.n += 1   # used even when the line is not written: a collector sees the gap (rule 4)
        try:
            with open(self.path, "a+b") as f:
                if not self.whole:   # G-6 (b): a line is never glued to a torn one (as the record's own writer)
                    f.seek(0, 2)
                    if f.tell():
                        f.seek(-1, 2)
                        if f.read(1) != b"\n":
                            f.seek(0, 2)
                            f.write(b"\n")
                            self.mended += 1
                f.write(data)
                f.flush()
        except (OSError, ValueError) as exc:
            self.whole = False   # what landed of it, if anything, is torn: the next line begins on a line of its own
            self.not_written += 1
            if self.write_error is None:
                self.write_error = "cannot append to %s: %s" % (self.path, getattr(exc, "strerror", None) or exc)
                return "not written", self.write_error
            return "not written", None
        self.whole = True
        self.said[about] = (rev, what, kernel)   # G-6 (b): only a line written is said
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
        """F-3: the watch's beat ("watch", the next rev), written though nothing else changed. The beat is counted
        on before the state is read (state: the state or a function giving it), so a state that cannot be read is
        a beat not built, said once, and never a beat tried again at every tick (G-6 a)."""
        while self.next_beat is not None and self.next_beat <= now:
            self.next_beat += self.beat
        return self.say("watch", lambda n, rev: event.heartbeat(state() if callable(state) else state, self.facts,
                                                                time, n, rev=rev), force=True)

    def end(self, state, time, exit, word=None, suppressed=None):
        """F-2, G-4, G-10: the last event, once: the watch's end with the exit and the word the watch gives (the
        report's own: CLEAN, ALARM, INCOMPLETE or NONE-SEEN) and the findings its overlay suppressed."""
        self.ended = True
        return self.say("watch", lambda n, rev: event.watch_end(state() if callable(state) else state, self.facts,
                                                                time, n, exit, rev=rev, word=word,
                                                                suppressed=suppressed), force=True)

    def ledgers(self, time, trees=(), findings=(), source_findings=(), holes=(), notifier_holes=(), blind=(),
                notes=(), dark_notes=(), lost=None, knocks=(), record=None, beat=False, final=False, same=None):
        """F-2: one pass over the watch's lists, each named from the list it is in. beat: a heartbeat is due (the
        lost-words note is said again); final: the finish (G-2: a tree's evidence and a blind spot's count are said
        once, their last). G-6 (c): at a beat and at the finish every entry is looked at; between beats only what is
        new in each list (from the first entry not yet said) and what can still change: the trees, the notifier's
        holes (they count), the source findings not yet settled and the knocks not yet decided (each said open the
        last time it was looked at) and those `same` names. same: {place of a source finding: the about of the
        entry it is one with} (G-1: said with alarm false and evidence.same_as). G-3: an entry's own time ("at", a
        tree's first_seen, where it is a real instant, else the time given) at rev 1, the pass's time at a later
        rev. G-6 (a): each list and each entry in its own guard, its naming too. holes is iterated as it grows (a
        hole the caller appends while the pass runs is said in it). A knock row's "for" is kept only when it names
        a thing said in this file (G-9). Returns the problems said for the first time: [(what, detail)] with what
        "not built" or "not written"."""
        problems = []
        rules, facts, full = self.rules, self.facts, bool(beat or final)
        same = same if isinstance(same, dict) else {}

        def at(e, rev, key="at"):
            return e[key] if rev == 1 and isinstance(e, dict) and event.instant(e.get(key)) else time

        def one(about, build, again=True, core=None):
            try:
                what, detail = self.say(about, build, again=again, core=core)
            except Exception as exc:   # never: say guards itself; the pass goes on all the same
                what, detail = "not built", "%s: %s: %s" % (about, type(exc).__name__, exc)
            if what in ("not built", "not written") and detail:
                problems.append((what, detail))
            return what

        def each(prefix, entries, make, again=True, changes=None, extra=()):
            try:
                open_ = self.open.setdefault(prefix, set())
                start = 0 if full or changes == "all" else self.marks.get(prefix, 0)
                look = sorted(j for j in open_.union(extra) if j <= start) if start else []
                i = start
                while i < len(entries) or look:
                    if look:
                        j = look.pop(0)
                    else:
                        i, j = i + 1, i + 1
                    if j > len(entries):
                        continue
                    e, about = entries[j - 1], "%s:%d" % (prefix, j)
                    what = one(about, lambda n, rev, e=e, j=j, a=about: make(e, j, n, a, rev), again=again)
                    if callable(changes) and what in ("written", "same", "held"):
                        try:
                            (open_.add if changes(e) else open_.discard)(j)
                        except Exception:
                            open_.add(j)
                m = self.marks.get(prefix, 0)
                while m < len(entries) and ("%s:%d" % (prefix, m + 1) in self.said
                                            or "%s:%d" % (prefix, m + 1) in self.unbuilt):
                    m += 1
                self.marks[prefix] = m
            except Exception as exc:   # G-6 (a): a list that cannot be read stops neither the next nor the beat
                problems.append(("not built", "%s: the list was not said: %s: %s" % (prefix, type(exc).__name__,
                                                                                    exc)))
        try:
            for row in list(trees):
                try:
                    about = "tree:%s" % event.tree_word(row["key"])
                except Exception:
                    about = "tree:?"
                one(about, lambda n, rev, r=row, a=about: event.tree(r, facts, at(r, rev, "first_seen"), n, a, rev,
                                                                     record=record), again=final, core=TREE_CORE)
        except Exception as exc:
            problems.append(("not built", "tree: the list was not said: %s: %s" % (type(exc).__name__, exc)))
        each("finding", findings, lambda e, j, n, a, rev: event.finding(
            e, facts, at(e, rev), n, a, rev, rule=rules.get(e.get("rule_id")), record=record))
        each("source-finding", source_findings, lambda e, j, n, a, rev: event.source_finding(
            e, facts, at(e, rev), n, a, rev, rule=rules.get(e.get("rule_id")), same_as=same.get(j)),
            changes=lambda e: not e.get("settled") or bool(e.get("pending")), extra=set(same) | self.folded)
        self.folded = set(same)
        each("hole", holes, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a, rev))
        each("notifier-hole", notifier_holes, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a, rev),
             changes="all")
        each("blind", blind, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a, rev), again=final)
        try:
            dark = {d.get("text"): d for d in dark_notes if isinstance(d, dict)}
        except Exception:
            dark = {}
        each("note", notes, lambda e, j, n, a, rev: event.note(dark.get(e, e), facts, at(dark.get(e, e), rev), n, a,
                                                               rev, record=record))
        if isinstance(lost, str) and lost:
            one(event.LOST, lambda n, rev: event.note(lost, facts, time, n, event.LOST, rev), again=full)

        def knock(r, j, n, a, rev):
            r = dict(r)
            if r.get("for") not in self.said:   # G-9: only a thing said in this file
                r.pop("for", None)
            return event.knock(r, facts, at(r, rev), n, a, rev)
        each("knock", knocks, knock, changes=lambda r: r.get("status") == "folded" or r.get("called") == "folded")
        return problems


class Lazy:
    """A list read on demand (G-6 c): the pass reads only the entries it looks at (the knock rows)."""

    def __init__(self, size, get):
        self.size, self.get = size, get

    def __len__(self):
        return self.size

    def __getitem__(self, i):
        return self.get(i)
