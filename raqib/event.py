"""The event, raqib-event/1 (ADR-0011 Amendment B, as Amendments C and D rule it; M10.1 REDO 2).

The one module that builds an event (B-1). Each function takes a ledger
entry of raqib/host.py's HostWatch as the watch keeps it (a finding, a
source finding, a hole, a blind spot, a note or a dark note, a knock row of
knock_rows(), a tree row of state(), the state itself), the watch's facts
(facts()) and what the caller gives - the time, the event's number n, what
the event is about (`about`) and its revision (`rev`) - and returns a dict.
It reads no clock, no file, no network and no environment: what it is not
given it does not say (B-4). A key the entry does not hold is absent, never
filled with null or guessed (C-2).

An event is a thing said once (C-1): `id` ("<run>:<n>") names the saying;
`about` names the ledger entry it is about, by its place in a list that only
grows (D-1), a name within one run (D-2), and `rev` how many times it has
been said. snapshot() is the events of one state in one call, n from 1 and
rev 1: it is not how a running watch says events (raqib/eventlog.py, M10.2,
keeps the count and says a changed thing again).

check(obj) returns the problems of an event (an empty list: none); every
event this module builds has none, and a builder that would build one with a
problem raises ValueError naming the key instead (C-10). line(obj) is the one
line of it (B-3): JSON, keys sorted, compact, ASCII. docs/specs/EVENT.md is
the contract (B-6, C-11).
"""
import datetime
import json
import re

from raqib import __version__

SCHEMA = "raqib-event/1"
KINDS = ("finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch")
# C-2: the keys, in C-2's order (a line sorts them; a dict built here keeps this order)
KEYS = ("schema", "id", "n", "time", "kind", "about", "rev", "severity", "alarm", "summary", "rule", "subject",
        "evidence", "hole", "knocked", "state", "result", "counts", "watch")
PARTS = {
    "rule": ("id", "class", "kind", "fp_budget", "attack"),
    "subject": ("tree", "pid", "image", "started", "named", "agent", "path", "benign", "history", "by"),
    "evidence": ("run", "round", "rounds", "record", "source", "trace", "seqs", "lines", "cites", "cites_left_out",
                 "same_as"),   # G-1: same_as, the about of the source finding this one is one act with
    "hole": ("kind", "class", "count", "last"),
    "knocked": ("status", "event", "title", "limit_id", "called", "for"),   # F-5: for, the thing knocked for
    "result": ("word", "exit", "suppressed"),   # G-4: suppressed, on a watch's end only
    "counts": ("rounds", "findings", "source_findings", "holes", "blind", "notes", "trees", "knocks"),
    "watch": ("run", "mode", "platform", "version", "host"),
}
CITE = ("src", "line", "round", "seq")   # C-3: a cite, never its text
BASE = ("schema", "id", "n", "time", "kind", "about", "rev", "severity", "watch")
BASE_PARTS = ("watch.run", "watch.host")   # D-3: required in every event beside BASE (a collector keys by the host)
REQUIRED = {   # C-10: per kind, beside BASE (a dotted name: a key of that part)
    "finding": ("alarm", "summary", "rule", "rule.id", "rule.attack", "evidence"),
    "source-finding": ("alarm", "summary", "rule", "rule.id", "rule.attack", "subject", "evidence", "state"),
    "note": ("summary",),
    "tree": ("subject", "subject.tree"),
    "hole": ("alarm", "summary", "hole", "hole.kind", "hole.class"),
    "knock": ("summary", "knocked", "knocked.status"),
    "heartbeat": ("state", "result", "result.exit", "counts"),
    "watch": ("state",),
}
REQUIRED_END = ("result", "result.word", "result.exit", "counts")   # C-10, G-4: a watch's end, beside REQUIRED["watch"]
ALLOWED = {   # per kind, the keys it may hold
    "finding": BASE + ("alarm", "summary", "rule", "subject", "evidence", "knocked"),
    "source-finding": BASE + ("alarm", "summary", "rule", "subject", "evidence", "knocked", "state"),
    "note": BASE + ("summary", "subject", "evidence"),
    "tree": BASE + ("subject", "evidence", "knocked"),
    "hole": BASE + ("alarm", "summary", "evidence", "hole", "knocked"),
    "knock": BASE + ("summary", "evidence", "knocked"),
    "heartbeat": BASE + ("state", "result", "counts"),
    "watch": BASE + ("state", "result", "counts"),
}
SEVERITIES = ("high", "medium", "low")
# C-4: a source finding's state, the report's word (host.py HostWatch._word), in the report's order of precedence
SOURCE_STATES = ("judged on another tree", "history", "pending at exit", "noted", "not settled", "settled")
ALARM_STATES = ("pending at exit", "not settled", "settled")   # C-4: the report's ALARMS (source_alarms)
WATCH_STATES = ("start", "end")
# D-4: a heartbeat's state, the band's word (ui.status) without its number ("SILENT for 12 s" is SILENT)
# D-4 as E-1 completes it: every word a band can be (raqib/ui.py status), the host watch's two among them
BEAT_STATES = ("WATCHING", "SILENT", "AGENT GONE", "CAPTURE FAILED", "READER LATE", "HOST READER FAILED", "FINISHED")
BAND_NUMBER = re.compile(r" for \d+ s\Z")
LOST = "note:lost-words"   # D-1: the note of the words a terminal lost (always last, its text changes)
HOLE = "hole"
BLIND = "blind spot"
HOLE_CLASSES = (HOLE, BLIND)   # C-6
WORDS = {0: "CLEAN", 1: "ALARM", 3: "INCOMPLETE"}   # C-5: the fixed three; another code has no word (a heartbeat)
# G-4: a watch's end says the report's own word, one of four, and the exit each has; the watch gives it
END_WORDS = {"CLEAN": 0, "ALARM": 1, "INCOMPLETE": 3, "NONE-SEEN": 0}
SUPPRESSING = ("CLEAN", "NONE-SEEN")   # G-4: the words with which the overlay's suppressed findings are counted
NAMED = {"named": True, "unknown": False}   # C-7: the report's two words of a finding's named
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
ID = re.compile(r"(.+):([1-9][0-9]*)\Z")
ABOUT = re.compile(r"(finding|source-finding|hole|notifier-hole|blind|note|knock):[1-9][0-9]*\Z|note:lost-words\Z"
                   r"|tree:.+\Z|watch\Z")
ABOUT_OF = {"finding": ("finding",), "source-finding": ("source-finding",), "note": ("note",), "tree": ("tree",),
            "hole": ("hole", "notifier-hole", "blind"), "knock": ("knock",), "heartbeat": ("watch",),
            "watch": ("watch",)}
# C-10: the type of each key ("instant": a string that is a real UTC instant; "count": an integer from 0;
# "number": an integer or a float; "ints": a list of integers from 0; "ids": a list of technique ids, none twice;
# D-5: a round, a pid, a seq, a line and n are never negative)
TYPES = {
    "schema": "str", "id": "str", "n": "pos", "time": "instant", "kind": "str", "about": "str", "rev": "pos",
    "severity": "str", "alarm": "bool", "summary": "str", "state": "str",
    "rule": "object", "subject": "object", "evidence": "object", "hole": "object", "knocked": "object",
    "result": "object", "counts": "object", "watch": "object",
    "rule.id": "str", "rule.class": "str", "rule.kind": "str", "rule.fp_budget": "number", "rule.attack": "ids",
    "subject.tree": "str", "subject.pid": "count", "subject.image": "str", "subject.started": "str",
    "subject.named": "bool", "subject.agent": "str", "subject.path": "str", "subject.benign": "bool",
    "subject.history": "bool", "subject.by": "str",
    "evidence.run": "str", "evidence.round": "count", "evidence.rounds": "ints", "evidence.record": "str",
    "evidence.source": "str", "evidence.trace": "str", "evidence.seqs": "ints", "evidence.lines": "ints",
    "evidence.cites": "cites", "evidence.cites_left_out": "pos", "evidence.same_as": "str",
    "hole.kind": "str", "hole.class": "str", "hole.count": "count", "hole.last": "str",
    "knocked.status": "str", "knocked.event": "str", "knocked.title": "str", "knocked.limit_id": "str",
    "knocked.called": "str", "knocked.for": "str",
    "result.word": "str", "result.exit": "int", "result.suppressed": "pos",
    "watch.run": "str", "watch.mode": "str", "watch.platform": "str", "watch.version": "str", "watch.host": "str",
}
TYPES.update({"counts.%s" % k: "count" for k in PARTS["counts"]})


# --- the parts ------------------------------------------------------------------------------------------------

def facts(state, host=None, version=__version__):
    """The watch's facts (C-2 watch) from its state() and the host's name the caller gives: required (D-3, a
    collector keys by it); without it, ValueError."""
    if not (isinstance(host, str) and host):
        raise ValueError("watch.host: facts must be given the host's name (D-3: required on every event)")
    out = {"run": state.get("run"), "mode": state.get("mode"), "platform": state.get("platform"),
           "version": version, "host": host}
    return {k: v for k, v in out.items() if v is not None and v != ""}


def tree_word(key):
    """A tree's word as the report says it (host.tree_word: pid:image:started, "-" for no start)."""
    pid, image, started = key
    return "%s:%s:%s" % (pid, image, started or "-")


def instant(text):
    """C-10: whether text is a real UTC instant, ISO 8601 with milliseconds and Z (strptime reads no clock)."""
    if not (isinstance(text, str) and TIME.match(text)):
        return False
    try:
        datetime.datetime.strptime(text[:-1], "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return False
    return True


def _held(entry, pairs):
    """{event key: entry value} for each (event key, entry key) the entry holds (not None, D-5: not "")."""
    out = {}
    for key, src in pairs:
        if isinstance(entry, dict) and entry.get(src) is not None and entry.get(src) != "":
            v = entry[src]
            out[key] = list(v) if isinstance(v, tuple) else v
    return out


def _cites(cites):
    """C-3: a cite is {src, line} and {round, seq} where the entry's cite holds them: never its text. D-5: a cite
    that lacks its src or its line is left out whole, never half."""
    out = []
    for c in cites or ():
        if isinstance(c, dict) and isinstance(c.get("src"), str) and c["src"] and _int(c.get("line")):
            out.append({k: c[k] for k in CITE if c.get(k) is not None and c.get(k) != ""})
    return out


def _cited(evidence, cites):
    """F-4: the cites an event may hold, and how many were left out (evidence.cites_left_out); never an empty
    list of cites (an entry whose every cite was left out says only their number)."""
    if cites:
        kept = _cites(cites)
        if kept:
            evidence["cites"] = kept
        if len(kept) < len(cites):
            evidence["cites_left_out"] = len(cites) - len(kept)
    return evidence


def _named(value):
    """C-7: subject.named is a boolean: a tree row's as it is, a finding's word as the boolean it means."""
    if isinstance(value, bool):
        return value
    return NAMED.get(value) if isinstance(value, str) else None


def _base(kind, severity, facts_, time, n, about, rev):
    return {"schema": SCHEMA, "id": "%s:%s" % (facts_.get("run"), n), "n": n, "time": time, "kind": kind,
            "about": about, "rev": rev, "severity": severity}


def _rule(entry, rule):
    """C-2 rule: id, class and kind from the entry (the finding as the rule gave it); fp_budget and attack from
    the rule's row of report.rule_table (absent without one: the builder then refuses, C-10)."""
    out = _held(entry, (("id", "rule_id"), ("class", "class"), ("kind", "kind")))
    if isinstance(rule, dict):
        out.update(_held(rule, (("fp_budget", "fp_budget"),)))
        if isinstance(rule.get("attack"), (list, tuple)):
            out["attack"] = list(rule["attack"])
    return out


def _knocked(status, **more):
    out = {"status": status} if isinstance(status, str) and status else {}
    out.update({k: v for k, v in more.items() if isinstance(v, str) and v})
    return out


def _finish(ev, facts_, **parts):
    for key in KEYS:
        if key in parts and parts[key] is not None and parts[key] != {} and parts[key] != "":
            ev[key] = parts[key]
    ev["watch"] = dict(facts_)
    ev = {k: ev[k] for k in KEYS if k in ev}
    for part, keys in PARTS.items():
        if isinstance(ev.get(part), dict):
            ev[part] = {k: ev[part][k] for k in keys if k in ev[part]} or ev[part]
    problems = check(ev)
    if problems:   # C-10: never a half event; M10.2 turns this into a hole
        raise ValueError("%s %s: %s" % (ev.get("kind"), ev.get("about"), "; ".join(problems)))
    return ev


# --- one function per kind ------------------------------------------------------------------------------------

def finding(entry, facts_, time, n, about, rev=1, rule=None, record=None):
    """A finding of the rounds (HostWatch.findings): a tree's or a footprint's. record: the file its seqs are in
    (the state's trace, C-3)."""
    subject = _held(entry, (("tree", "tree"), ("pid", "pid"), ("image", "image"), ("agent", "agent"),
                            ("path", "path")))
    if _named(entry.get("named")) is not None:
        subject["named"] = _named(entry["named"])
    evidence = _held(entry, (("run", "run"), ("round", "round"), ("rounds", "cycle_rounds"), ("seqs", "cited_seq")))
    if record is not None and "seqs" in evidence:
        evidence["record"] = record
    _cited(evidence, entry.get("cites"))
    return _finish(_base("finding", entry.get("severity"), facts_, time, n, about, rev), facts_, alarm=True,
                   summary=entry.get("summary"), rule=_rule(entry, rule), subject=subject, evidence=evidence,
                   knocked=_knocked(entry.get("notice")))


def source_state(entry):
    """C-4: a source finding's state, by the report's word and order (host.py HostWatch._word): judged on another
    tree, history, pending at exit, noted (the report's "noted (benign)"), not settled, settled (where the report
    prints the severity)."""
    if entry.get("judged_on") is not None:
        return "judged on another tree"
    if entry.get("history"):
        return "history"
    if entry.get("pending"):
        return "pending at exit"
    if entry.get("benign_note"):
        return "noted"
    if not entry.get("settled"):
        return "not settled"
    return "settled"


def source_finding(entry, facts_, time, n, about, rev=1, rule=None, same_as=None):
    """A finding of a tree's source file (HostWatch.source_findings). G-1: same_as, the about of the entry the
    report's listing takes it to be one act with (host.told_twice): it is said with alarm false and
    evidence.same_as, so that one act is one alarm."""
    subject = _held(entry, (("tree", "tree"), ("pid", "pid"), ("image", "image")))
    evidence = _held(entry, (("run", "run"), ("source", "source"), ("trace", "trace"), ("seqs", "cited_seq"),
                             ("lines", "lines")))
    state = source_state(entry)
    if same_as is not None:
        evidence["same_as"] = same_as
    return _finish(_base("source-finding", entry.get("severity"), facts_, time, n, about, rev), facts_,
                   alarm=state in ALARM_STATES and same_as is None, summary=entry.get("summary"), rule=_rule(entry, rule),
                   subject=subject, evidence=evidence, knocked=_knocked(entry.get("notice")), state=state)


def note(entry, facts_, time, n, about, rev=1, record=None):
    """A note: a text of HostWatch.notes, or a dark note (HostWatch.dark_notes), which says its footprint."""
    if isinstance(entry, str):
        return _finish(_base("note", "info", facts_, time, n, about, rev), facts_, summary=entry)
    subject = _held(entry, (("tree", "live_tree"), ("agent", "agent"), ("path", "path")))
    evidence = _held(entry, (("run", "run"), ("round", "round"), ("seqs", "cited_seq")))
    if record is not None and "seqs" in evidence:
        evidence["record"] = record
    _cited(evidence, entry.get("cites"))
    return _finish(_base("note", "info", facts_, time, n, about, rev), facts_, summary=entry.get("text"),
                   subject=subject, evidence=evidence)


def tree(row, facts_, time, n, about, rev=1, record=None):
    """A tree row of state()'s host.trees (C-7): its word, pid, image, start, named, benign, history and how it
    became a candidate where the row says; its HostTree line's seq and record lines."""
    subject = {}
    key = row.get("key")
    if isinstance(key, (list, tuple)) and len(key) == 3:
        subject["tree"] = tree_word(key)
        if isinstance(key[2], str) and key[2]:
            subject["started"] = key[2]
    subject.update(_held(row, (("pid", "pid"), ("image", "image"))))
    for k in ("named", "benign", "history"):
        if isinstance(row.get(k), bool):
            subject[k] = row[k]
    if isinstance(row.get("candidate_by"), str) and row["candidate_by"]:
        subject["by"] = row["candidate_by"]
    evidence = {}
    if isinstance(row.get("line_seq"), int) and not isinstance(row.get("line_seq"), bool):
        evidence["seqs"] = [row["line_seq"]]
        if record is not None:
            evidence["record"] = record
    _cited(evidence, row.get("cites"))
    return _finish(_base("tree", "info", facts_, time, n, about, rev), facts_, subject=subject, evidence=evidence,
                   knocked=_knocked(row.get("knocked")))


def hole(entry, facts_, time, n, about, rev=1):
    """A hole (state()'s holes: the watch's and the notifier's) or a blind spot (state()'s host.blind, C-6): the
    report's line of it, "kind: detail"; its kind and class, and count and last where it holds them (a notifier's
    hole); a blind spot's count is the number of rounds it was seen in (D-5)."""
    blind = entry.get("class") == BLIND
    part = dict(_held(entry, (("kind", "kind"),)), **{"class": BLIND if blind else HOLE})
    part.update(_held(entry, (("count", "count"), ("last", "last"))))
    if blind and isinstance(entry.get("rounds"), list):
        part["count"] = len(entry["rounds"])
    summary = "%s: %s" % (entry.get("kind"), entry.get("detail"))
    return _finish(_base("hole", "info" if blind else HOLE, facts_, time, n, about, rev), facts_, alarm=not blind,
                   summary=summary, evidence=_held(entry, (("round", "round"),)), hole=part,
                   knocked=_knocked(entry.get("notice")))


def knock(row, facts_, time, n, about, rev=1):
    """A knock row of HostWatch.knock_rows() (C-8): its body; its status now, event, title, rate-limit id and what
    the notifier said at the call; F-5: the `about` of the thing it knocked for, where the row says (its "for")."""
    return _finish(_base("knock", "info", facts_, time, n, about, rev), facts_, summary=row.get("body"),
                   evidence=_held(row, (("round", "round"),)),
                   knocked=_knocked(row.get("status") or row.get("called"), event=row.get("event"),
                                    title=row.get("title"), limit_id=row.get("limit_id"), called=row.get("called"),
                                    **{"for": row.get("for")}))


def _counts(state):
    h = state.get("host") or {}
    older = h.get("knocks_older") if isinstance(h.get("knocks_older"), int) else 0
    return {"rounds": h.get("rounds"), "findings": len(h.get("findings") or ()),
            "source_findings": len(h.get("source_findings") or ()), "holes": len(state.get("holes") or ()),
            "blind": len(h.get("blind") or ()), "notes": len(h.get("notes") or ()),
            "trees": len(h.get("trees") or ()), "knocks": len(h.get("knocks") or ()) + older}


def _result(code):
    """C-5: an exit and its word (0 CLEAN, 1 ALARM, 3 INCOMPLETE; another code has only the exit)."""
    if not (isinstance(code, int) and not isinstance(code, bool)):
        return {}
    return dict({"word": WORDS[code]} if code in WORDS else {}, exit=code)


def beat_word(band):
    """D-4: the band's word without its number ("SILENT for 12 s" is SILENT); another value as it is."""
    return BAND_NUMBER.sub("", band) if isinstance(band, str) else band


def heartbeat(state, facts_, time, n, about="watch", rev=1):
    """C-5, D-4: the watch's beat: its state is the band's word without its number, one of BEAT_STATES (a band
    outside them is refused: ValueError); its result is the exit it would end with now (the state's code so far)
    and that code's word; its counts."""
    return _finish(_base("heartbeat", "info", facts_, time, n, about, rev), facts_,
                   state=beat_word(state.get("band")), result=_result(state.get("code_so_far")), counts=_counts(state))


def watch_start(state, facts_, time, n=1, about="watch", rev=1):
    return _finish(_base("watch", "info", facts_, time, n, about, rev), facts_, state="start")


def watch_end(state, facts_, time, n, exit, about="watch", rev=1, word=None, suppressed=None):
    """G-4: the watch's end: the exit and the word the watch gives (the report's own, one of END_WORDS; the module
    does not derive it from the exit: without a word the end is refused), and suppressed, the findings the
    person's overlay suppressed (a number from 1, with CLEAN or NONE-SEEN); its counts."""
    result = dict({"word": word} if word is not None else {}, **({"exit": exit} if exit is not None else {}))
    if suppressed:
        result["suppressed"] = suppressed
    return _finish(_base("watch", "info", facts_, time, n, about, rev), facts_, state="end", result=result,
                   counts=_counts(state))


def snapshot(state, facts_, time, knocks, rules, end=False, exit=None, lost=None, word=None, suppressed=None):
    """C-1: the events of one state in one call, n from 1, rev 1, in one order: the watch's start, its trees
    ("tree:<word>"), findings ("finding:i"), source findings ("source-finding:i"), holes, blind spots ("blind:i"),
    notes, knocks ("knock:i") and a heartbeat (or, end=True, the watch's end with the exit, word and suppressed
    given, G-4), each about
    "watch". D-1: a name is a place in a list that only grows: a hole of the watch is "hole:i" and a hole of the
    notifier (the entry that holds a count) "notifier-hole:i", each counted in its own list; a note is "note:i"
    over the watch's own notes (a dark note's text as its dark note), and the note of the words a terminal lost
    (always last, its text changes) is "note:lost-words" when its text is given as lost (watch.lost_note of the
    watch's out); without lost that note is numbered as any other. Not how a running watch says events:
    M10.2 keeps the count and says a changed thing again. knocks: knock_rows(), all of them (C-8: the state
    keeps only the newest), required. rules: {rule id: row of report.rule_table}, required (C-10: a finding
    needs its rule's attack). time: of the heartbeat or the end; the start's is the state's started, a tree's
    its first_seen, an entry's its own "at", where it is a real instant (else the time given)."""
    if knocks is None:
        raise ValueError("knocks: snapshot must be given the knock rows (knock_rows(): the state keeps the newest)")
    if not isinstance(rules, dict):
        raise ValueError("rules: snapshot must be given the rule table ({rule id: row}); a finding needs attack")
    h = state.get("host") or {}
    record = state.get("trace") if isinstance(state.get("trace"), str) and state.get("trace") else None

    def at(entry, key="at"):
        return entry[key] if isinstance(entry, dict) and instant(entry.get(key)) else time
    out = [watch_start(state, facts_, at(state, "started"))]
    for row in h.get("trees") or ():
        out.append(tree(row, facts_, at(row, "first_seen"), len(out) + 1, "tree:%s" % tree_word(row["key"]),
                        record=record))
    for i, e in enumerate(h.get("findings") or (), 1):
        out.append(finding(e, facts_, at(e), len(out) + 1, "finding:%d" % i, rule=rules.get(e.get("rule_id")),
                           record=record))
    for i, e in enumerate(h.get("source_findings") or (), 1):
        out.append(source_finding(e, facts_, at(e), len(out) + 1, "source-finding:%d" % i,
                                  rule=rules.get(e.get("rule_id"))))
    places = {"hole": 0, "notifier-hole": 0}
    for e in state.get("holes") or ():
        whose = "notifier-hole" if isinstance(e, dict) and "count" in e else "hole"
        places[whose] += 1
        out.append(hole(e, facts_, at(e), len(out) + 1, "%s:%d" % (whose, places[whose])))
    for i, e in enumerate(h.get("blind") or (), 1):
        out.append(hole(e, facts_, at(e), len(out) + 1, "blind:%d" % i))
    dark = {d.get("text"): d for d in h.get("dark_notes") or () if isinstance(d, dict)}
    notes = list(h.get("notes") or ())
    last = notes.pop() if isinstance(lost, str) and lost and notes and notes[-1] == lost else None
    for i, text in enumerate(notes, 1):
        e = dark.get(text, text)
        out.append(note(e, facts_, at(e), len(out) + 1, "note:%d" % i, record=record))
    if last is not None:
        out.append(note(last, facts_, time, len(out) + 1, LOST))
    for i, row in enumerate(knocks, 1):
        out.append(knock(row, facts_, at(row), len(out) + 1, "knock:%d" % i))
    if end:
        out.append(watch_end(state, facts_, time, len(out) + 1, exit, word=word, suppressed=suppressed))
    else:
        out.append(heartbeat(state, facts_, time, len(out) + 1))
    return out


# --- the line and its check -----------------------------------------------------------------------------------

def line(obj):
    """B-3: the one line of an event: JSON, keys sorted, compact, ASCII (non-ASCII escaped); no newline."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _typed(kind_of, v):
    if kind_of == "str":
        return isinstance(v, str) and v != ""
    if kind_of == "int":
        return _int(v)
    if kind_of == "pos":
        return _int(v) and v >= 1
    if kind_of == "count":
        return _int(v) and v >= 0
    if kind_of == "bool":
        return isinstance(v, bool)
    if kind_of == "number":
        return (_int(v) or isinstance(v, float)) and v == v
    if kind_of == "instant":
        return instant(v)
    if kind_of == "object":
        return isinstance(v, dict) and bool(v)
    if kind_of == "ints":
        return isinstance(v, list) and all(_int(x) and x >= 0 for x in v)
    if kind_of == "ids":
        return isinstance(v, list) and all(isinstance(a, str) and ATTACK_ID.match(a) for a in v) and len(
            set(v)) == len(v)
    if kind_of == "cites":   # F-4: never an empty list
        return isinstance(v, list) and bool(v) and all(
            isinstance(c, dict) and set(c) <= set(CITE) and isinstance(c.get("src"), str) and c["src"]
            and all(_int(c[k]) and c[k] >= 0 for k in ("line", "round", "seq") if k in c) and "line" in c
            for c in v)
    return False


def _get(obj, dotted):
    head, _, tail = dotted.partition(".")
    if head not in obj:
        return False, None
    if not tail:
        return True, obj[head]
    part = obj[head]
    return (tail in part, part.get(tail)) if isinstance(part, dict) else (False, None)


def check(obj):
    """C-10: the problems of an event, as texts each beginning with the key; [] when it has none."""
    if not isinstance(obj, dict):
        return ["event: an event is a JSON object"]
    out = []
    kind = obj.get("kind")
    if obj.get("schema") != SCHEMA:
        out.append("schema: must be %s" % SCHEMA)
    if kind not in KINDS:
        return out + ["kind: must be one of %s" % "|".join(KINDS)]
    for key in obj:
        if key not in ALLOWED[kind]:
            out.append("%s: not a key of a %s event" % (key, kind))
    end = kind == "watch" and obj.get("state") == "end"
    need = BASE + BASE_PARTS + REQUIRED[kind] + (REQUIRED_END if end else ())
    for key in need:
        if not _get(obj, key)[0]:
            out.append("%s: missing (required in a %s event)" % (key, kind))
    for key, value in obj.items():
        if key in TYPES and not _typed(TYPES[key], value):
            out.append("%s: must be %s" % (key, TYPES[key]))
        if key in PARTS and isinstance(value, dict):
            for k, v in value.items():
                dotted = "%s.%s" % (key, k)
                if k not in PARTS[key]:
                    out.append("%s: not a key of %s" % (dotted, key))
                elif not _typed(TYPES[dotted], v):
                    out.append("%s: must be %s" % (dotted, TYPES[dotted]))
    w = obj.get("watch") if isinstance(obj.get("watch"), dict) else {}
    m = ID.match(obj.get("id")) if isinstance(obj.get("id"), str) else None
    if not m or m.group(1) != w.get("run") or m.group(2) != str(obj.get("n")):
        out.append("id: must be <run>:<n> of this event's watch.run and n")
    about = obj.get("about")
    if not (isinstance(about, str) and ABOUT.match(about) and about.split(":")[0] in ABOUT_OF[kind]):
        out.append("about: must be %s for a %s event" % (" or ".join("%s:..." % a if a != "watch" else a
                                                                     for a in ABOUT_OF[kind]), kind))
    sev = obj.get("severity")
    hole_class = (obj.get("hole") or {}).get("class") if isinstance(obj.get("hole"), dict) else None
    want = (SEVERITIES if kind in ("finding", "source-finding") else ("info",) if kind != "hole" or hole_class == BLIND
            else (HOLE,))
    if sev not in want:
        out.append("severity: must be one of %s for a %s event" % ("|".join(want), kind))
    if kind == "hole":
        if hole_class not in HOLE_CLASSES:
            out.append("hole.class: must be one of %s" % "|".join(HOLE_CLASSES))
        elif (about or "").startswith("blind:") != (hole_class == BLIND):
            out.append("about: blind:<i> names a blind spot, hole:<i> a hole")
        if "alarm" in obj and obj["alarm"] is not (hole_class == HOLE):
            out.append("alarm: true for a hole, false for a blind spot")
        has_count = isinstance(obj.get("hole"), dict) and "count" in obj["hole"]
        if (about or "").startswith("notifier-hole:") and not has_count:
            out.append("hole.count: missing (a notifier's hole holds its count, D-1)")
        elif (about or "").startswith("hole:") and has_count:
            out.append("hole.count: not a key of a watch's hole (a hole that holds a count is the notifier's)")
    knocked = obj.get("knocked") if isinstance(obj.get("knocked"), dict) else {}
    evidence_ = obj.get("evidence") if isinstance(obj.get("evidence"), dict) else {}
    if "for" in knocked and not (kind == "knock" and isinstance(knocked["for"], str) and ABOUT.match(knocked["for"])
                                 and knocked["for"] != "watch"):
        out.append("knocked.for: the about of the thing a knock knocked for, on a knock event only (F-5)")
    if kind == "finding" and obj.get("alarm") is not True:
        out.append("alarm: true for a finding of the rounds")
    state = obj.get("state")
    if kind == "source-finding" and "state" in obj:
        if state not in SOURCE_STATES:
            out.append("state: must be one of %s" % "|".join(SOURCE_STATES))
        elif "alarm" in obj and obj["alarm"] is not (state in ALARM_STATES and "same_as" not in evidence_):
            out.append("alarm: true for a source finding %s and not one act with another (evidence.same_as),"
                       " false otherwise" % ", ".join(ALARM_STATES))
    if "same_as" in evidence_ and not (kind == "source-finding" and isinstance(evidence_["same_as"], str)
                                       and re.match(r"source-finding:[1-9][0-9]*\Z", evidence_["same_as"])
                                       and evidence_["same_as"] != obj.get("about")):
        out.append("evidence.same_as: the about of another source finding, on a source finding only (G-1)")
    if kind == "heartbeat" and "state" in obj and state not in BEAT_STATES:
        out.append("state: must be one of %s for a heartbeat (D-4)" % "|".join(BEAT_STATES))
    if kind == "watch":
        if state not in WATCH_STATES:
            out.append("state: must be start or end")
        elif state == "start":
            out += ["%s: not a key of a watch start" % k for k in ("result", "counts") if k in obj]
    result = obj.get("result") if isinstance(obj.get("result"), dict) else {}
    if kind == "watch" and state == "end":   # G-4: the report's own word, one of four, and its exit
        if "word" in result and (result["word"] not in END_WORDS or END_WORDS[result["word"]] != result.get("exit")):
            out.append("result.word: must be one of %s, of its exit (%s)" % (", ".join(END_WORDS), ", ".join(
                "%s %d" % kv for kv in END_WORDS.items())))
        if "suppressed" in result and result.get("word") not in SUPPRESSING:
            out.append("result.suppressed: only with %s (G-4)" % " or ".join(SUPPRESSING))
    else:
        if "word" in result and (result["word"] not in WORDS.values()
                                 or result["word"] != WORDS.get(result.get("exit"))):
            out.append("result.word: must be the word of result.exit (%s)" % ", ".join(
                "%d %s" % kv for kv in sorted(WORDS.items())))
        if _int(result.get("exit")) and result["exit"] in WORDS and "word" not in result:
            out.append("result.word: missing (exit %d has a word)" % result["exit"])
        if "suppressed" in result:
            out.append("result.suppressed: on a watch's end only (G-4)")
    if isinstance(obj.get("counts"), dict):
        out += ["counts.%s: missing" % k for k in PARTS["counts"] if k not in obj["counts"]]
    try:
        line(obj)
    except (TypeError, ValueError) as exc:
        out.append("event: not JSON: %s" % exc)
    return out
