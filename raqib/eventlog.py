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
only at the finish (G-2). H-1: every pass looks at every entry of every list
that can change, and at the notes that are new or that the watch replaced in
place; for each thing the writer keeps the values its event is built from
(values(): exactly the keys its builder reads, and what the pass adds) and
builds nothing where they are what they were. Nothing it calls can end it,
the read of an entry included (G-6 a, H-3); a line is never glued to a
fragment, whoever left it (G-6 b, H-4); what a failed write left unsaid is
said at the next pass, the start before anything else (H-4).

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
# H-1: per kind, exactly the keys of an entry its builder in raqib/event.py reads (a note that is a text: the text);
# the pass adds the rest of what an event is built from (a source finding's same_as; a knock's "for", a tree's
# candidate_by: on the row it gives). The time ("at", "first_seen") is left out: it is never what is compared (VARY).
READS = {
    "finding": ("tree", "pid", "image", "agent", "path", "named", "run", "round", "cycle_rounds", "cited_seq",
                "cites", "severity", "summary", "rule_id", "class", "kind", "notice"),
    "source-finding": ("tree", "pid", "image", "run", "source", "trace", "cited_seq", "lines", "judged_on",
                       "history", "pending", "benign_note", "settled", "severity", "summary", "rule_id", "class",
                       "kind", "notice"),
    "note": ("text", "live_tree", "agent", "path", "run", "round", "cited_seq", "cites"),
    "tree": ("key", "pid", "image", "named", "benign", "history", "candidate_by", "line_seq", "cites", "knocked"),
    "hole": ("class", "kind", "detail", "count", "last", "rounds", "round", "notice"),
    "knock": ("body", "round", "status", "called", "event", "title", "limit_id", "for"),
}
TREE_READS_CORE = ("key", "pid", "image", "named", "benign", "history", "candidate_by", "knocked")   # G-2: at once


def _frozen(v):
    """A value as it is now, copied (a list the watch changes in place later is not the one kept) and typed (True is
    not 1)."""
    if isinstance(v, dict):
        return ("{",) + tuple(sorted((str(k), _frozen(x)) for k, x in v.items()))
    if isinstance(v, (list, tuple)):
        return ("[",) + tuple(_frozen(x) for x in v)
    return (type(v).__name__, v)


def values(kind, entry, *more, keys=None):
    """H-1: the values an event of this kind is built from: the entry's keys its builder reads (READS), and more,
    what the pass adds (a source finding's same_as). Two equal values give the same event but for VARY."""
    if not isinstance(entry, dict):
        return (kind, _frozen(entry)) + tuple(_frozen(x) for x in more)
    return (kind,) + tuple(_frozen(entry.get(k)) for k in (keys or READS[kind])) + tuple(_frozen(x) for x in more)


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
        self.beat = float(beat)
        self.facts = dict(facts, beat=self.beat)   # H-6: the beat is on every event (watch.beat)
        self.rules = rules if isinstance(rules, dict) else {}
        self.n = 0                 # the run's count: the last number used
        self.said = {}             # about -> (rev, what was said, its core)
        self.unbuilt = {}          # about -> why it could not be built (F-4: one hole per thing)
        self.kept = {}             # H-1: about -> the values its event was last built from (said, same, not built)
        self.kept_core = {}        # H-1: about -> the values of what is said of it at once (a tree's core)
        self.written = 0
        self.heartbeats = 0
        self.not_written = 0
        self.write_error = None    # why the first line was not written (said once)
        self.next_beat = None      # the monotonic time the next beat is due
        self.ended = False
        self.started = None        # H-4: the start's time while its line is not written (said before anything else)
        self.watch_rev = 0         # H-4: the last rev of "watch" used (a heartbeat never reuses one)
        self.mended = 0            # G-6 (b), H-4: fragments ended with a newline before the next line
        self.note_mark = 0         # H-1: the notes looked at (a note is new from here)
        self.note_again = set()    # H-4: places of notes whose last line was not written
        self.failed = set()        # H-3: the lists whose own failure was said (once for the watch's life)
        self.builds = 0            # H-1: the builder calls (what a pass cost)
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

    def say(self, about, build, again=True, force=False, core=None, rev=None):
        """One thing: build(n, rev) -> its event. again=False: a thing already said is not said again now (G-2: a
        tree's evidence and a blind spot's count until the finish; F-3: the lost-words note until a beat); with core
        (event -> its part that is said at once when it changes), only what is outside core waits (a tree's record
        line, which moves every round). force: written though nothing changed (a heartbeat, the end). rev: the rev
        to use (the watch's, H-4); else the last said and one. G-6 (a): nothing in it can raise; a line that cannot
        be made is a thing not built. Returns (what, detail): ("written", event), ("same", None), ("held", None),
        ("not built", why or None when said before), ("not written", why or None when said before)."""
        last = self.said.get(about)
        if last is not None and not again and not force and core is None:
            return "held", None
        if rev is None:
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
                f.seek(0, 2)   # G-6 (b), H-4: before every line, a file that does not end in a newline gets one
                if f.tell():
                    f.seek(-1, 2)
                    if f.read(1) != b"\n":
                        f.seek(0, 2)
                        f.write(b"\n")
                        self.mended += 1
                f.seek(0, 2)
                f.write(data)
                f.flush()
        except (OSError, ValueError) as exc:
            self.not_written += 1
            if self.write_error is None:
                self.write_error = "cannot append to %s: %s" % (self.path, getattr(exc, "strerror", None) or exc)
                return "not written", self.write_error
            return "not written", None
        self.said[about] = (rev, what, kernel)   # G-6 (b): only a line written is said
        self.written += 1
        if ev.get("kind") == "heartbeat":
            self.heartbeats += 1
        return "written", ev

    # --- the watch's moments --------------------------------------------------------------------------------

    def start(self, time, now):
        """F-2: the first event of the watch, "watch" rev 1; the beat is counted from it. H-4: a start whose line
        was not written is written again before anything else, at the next pass, beat or end."""
        self.next_beat = now + self.beat
        self.started = time
        self.watch_rev = max(self.watch_rev, 1)
        return self._start()

    def _start(self):
        if self.started is None:
            return "same", None
        time = self.started
        got = self.say("watch", lambda n, rev: event.watch_start({}, self.facts, time, n, rev=rev), force=True, rev=1)
        if got[0] == "written":
            self.started = None
        return got

    def _watch(self, build):
        """H-4: a heartbeat or the end: the start first where it is still unsaid; then the next rev of "watch",
        never one used before (a rev whose line was not written is used all the same)."""
        try:
            self._start()
        except Exception:   # never: say guards itself
            pass
        self.watch_rev += 1
        return self.say("watch", build, force=True, rev=self.watch_rev)

    def due(self, now):
        return self.next_beat is not None and not self.ended and now >= self.next_beat

    def heartbeat(self, state, time, now):
        """F-3: the watch's beat ("watch", the next rev), written though nothing else changed. The beat is counted
        on before the state is read (state: the state or a function giving it), so a state that cannot be read is
        a beat not built, said once, and never a beat tried again at every tick (G-6 a)."""
        while self.next_beat is not None and self.next_beat <= now:
            self.next_beat += self.beat
        return self._watch(lambda n, rev: event.heartbeat(state() if callable(state) else state, self.facts,
                                                          time, n, rev=rev))

    def end(self, state, time, exit, word=None, suppressed=None):
        """F-2, G-4, G-10: the last event, once: the watch's end with the exit and the word the watch gives (the
        report's own: CLEAN, ALARM, INCOMPLETE or NONE-SEEN) and the findings its overlay suppressed."""
        self.ended = True
        return self._watch(lambda n, rev: event.watch_end(state() if callable(state) else state, self.facts,
                                                          time, n, exit, rev=rev, word=word, suppressed=suppressed))

    def ledgers(self, time, trees=(), findings=(), source_findings=(), holes=(), notifier_holes=(), blind=(),
                notes=(), dark_notes=(), lost=None, knocks=(), record=None, beat=False, final=False, same=None,
                notes_changed=()):
        """F-2: one pass over the watch's lists, each named from the list it is in. beat: a heartbeat is due (the
        lost-words note is said again); final: the finish (G-2: a tree's evidence and a blind spot's count are said
        once, their last). H-1: every entry of every list is looked at, every pass; of the notes, those new since
        the last pass, those the watch replaced in place (notes_changed: their places from 1) and those whose line
        was not written (at a beat and at the finish, all); an entry whose values (values()) are what they were
        when it was last built is not built again. same: {place of a source finding: the about of the entry it is
        one with} (G-1: said with alarm false and evidence.same_as); H-2: only while that entry is said in this
        file (else the act would have no alarm), and the kept halves are looked at first. G-3: an entry's own time
        ("at", a tree's first_seen, where it is a real instant, else the time given) at rev 1, the pass's time at a
        later rev. G-6 (a), H-3: each list, each entry and its read in its own guard; a list's own failure is said
        once for the watch's life. A list is iterated as it grows (a hole the caller appends while the pass runs is
        said in it). A knock row's "for" is kept only when it names a thing said in this file (G-9). Returns the
        problems said for the first time: [(what, detail)] with what "not built" or "not written"."""
        problems = []
        rules, facts, full = self.rules, self.facts, bool(beat or final)
        same = same if isinstance(same, dict) else {}
        try:
            what, detail = self._start()   # H-4: the start before anything else
            if what.startswith("not") and detail:
                problems.append((what, detail))
        except Exception:
            pass

        def at(e, rev, key="at"):
            return e[key] if rev == 1 and isinstance(e, dict) and event.instant(e.get(key)) else time

        def once(prefix, exc):   # H-3: a list that cannot be read: one problem for the watch's life
            if prefix not in self.failed:
                self.failed.add(prefix)
                problems.append(("not built", "%s: the list was not said: %s: %s" % (prefix, type(exc).__name__,
                                                                                    exc)))

        def one(about, vals, build, again=True, core=None, cvals=None):
            if self.kept.get(about, self) == vals:   # H-1: nothing it is built from changed: nothing is built
                return "same"
            if cvals is not None and not again and about in self.said and self.kept_core.get(about, self) == cvals:
                return "held"
            try:
                what, detail = self.say(about, build, again=again, core=core)
            except Exception as exc:   # never: say guards itself; the pass goes on all the same
                what, detail = "not built", "%s: %s: %s" % (about, type(exc).__name__, exc)
            if what in ("written", "same", "not built"):
                self.kept[about] = vals
            else:   # held (said at a beat or the finish) or not written (H-4: said at the next pass)
                self.kept.pop(about, None)
            if what in ("written", "same", "held") and cvals is not None:
                self.kept_core[about] = cvals
            if what in ("not built", "not written") and detail:
                problems.append((what, detail))
            return what

        def order(entries, first, start):
            for j in sorted(first):
                if 1 <= j <= len(entries):
                    yield j
            j = start
            while j < len(entries):
                j += 1
                if j not in first:
                    yield j

        def each(prefix, kind, entries, make, again=True, first=(), start=0, more=None, seen=None):
            try:
                for j in order(entries, set(first), start):
                    about = "%s:%d" % (prefix, j)
                    try:   # H-3: the read of an entry stops only itself
                        e = entries[j - 1]
                        add = more(e, j) if more is not None else ()
                        vals = values(kind, e, *add)
                    except Exception as exc:
                        if about not in self.unbuilt:
                            self.unbuilt[about] = "cannot be read: %s: %s" % (type(exc).__name__, exc)
                            problems.append(("not built", "%s: cannot be read: %s: %s" % (about, type(exc).__name__,
                                                                                         exc)))
                        continue
                    what = one(about, vals, lambda n, rev, e=e, j=j, a=about, add=add: make(e, j, n, a, rev, *add),
                               again=again)
                    if seen is not None:
                        seen(j, what)
            except Exception as exc:   # G-6 (a): a list that cannot be read stops neither the next nor the beat
                once(prefix, exc)
        try:
            for row in list(trees):
                try:
                    about = "tree:%s" % event.tree_word(row["key"])
                    vals = values("tree", row)
                    cvals = values("tree", row, keys=TREE_READS_CORE)
                except Exception as exc:
                    about = "tree:?"
                    if about not in self.unbuilt:
                        self.unbuilt[about] = "cannot be read: %s: %s" % (type(exc).__name__, exc)
                        problems.append(("not built", "%s: cannot be read: %s: %s" % (about, type(exc).__name__,
                                                                                     exc)))
                    continue
                one(about, vals, lambda n, rev, r=row, a=about: event.tree(r, facts, at(r, rev, "first_seen"), n, a,
                                                                           rev, record=record),
                    again=final, core=TREE_CORE, cvals=cvals)
        except Exception as exc:
            once("tree", exc)
        each("finding", "finding", findings, lambda e, j, n, a, rev: event.finding(
            e, facts, at(e, rev), n, a, rev, rule=rules.get(e.get("rule_id")), record=record))
        kept = set()
        for about in same.values():
            try:
                kept.add(int(about.rsplit(":", 1)[1]))
            except Exception:
                pass
        each("source-finding", "source-finding", source_findings, lambda e, j, n, a, rev, as_: event.source_finding(
            e, facts, at(e, rev), n, a, rev, rule=rules.get(e.get("rule_id")), same_as=as_),
            first=kept, more=lambda e, j: (same[j] if same.get(j) in self.said else None,))   # H-2
        each("hole", "hole", holes, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a, rev))
        each("notifier-hole", "hole", notifier_holes, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a,
                                                                                         rev))
        each("blind", "hole", blind, lambda e, j, n, a, rev: event.hole(e, facts, at(e, rev), n, a, rev), again=final)
        try:
            dark = {d.get("text"): d for d in dark_notes if isinstance(d, dict)}
        except Exception:
            dark = {}
        try:
            changed = set(notes_changed or ()) | self.note_again
        except Exception:
            changed = set(self.note_again)
        mark = [self.note_mark]

        def seen(j, what):
            mark[0] = max(mark[0], j)
            (self.note_again.add if what == "not written" else self.note_again.discard)(j)
        each("note", "note", Lazy(lambda: len(notes), lambda i: dark.get(notes[i], notes[i])),
             lambda e, j, n, a, rev: event.note(e, facts, at(e, rev), n, a, rev, record=record),
             first=() if full else changed, start=0 if full else self.note_mark, seen=seen)
        self.note_mark = mark[0]
        if isinstance(lost, str) and lost:
            one(event.LOST, values("note", lost), lambda n, rev: event.note(lost, facts, time, n, event.LOST, rev),
                again=full)

        def row(i):
            r = dict(knocks[i])
            if r.get("for") not in self.said:   # G-9: only a thing said in this file
                r.pop("for", None)
            return r
        each("knock", "knock", Lazy(lambda: len(knocks), row), lambda r, j, n, a, rev: event.knock(
            r, facts, at(r, rev), n, a, rev))
        return problems


class Lazy:
    """A list read on demand: the pass reads each entry inside its own guard (H-3; the knock rows, the notes as
    their dark notes). size: a number or a function giving it (a list that grows while it is read)."""

    def __init__(self, size, get):
        self.size, self.get = size, get

    def __len__(self):
        return self.size() if callable(self.size) else self.size

    def __getitem__(self, i):
        return self.get(i)
