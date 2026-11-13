"""The event, raqib-event/1 (ADR-0011 Amendment B, M10.1).

The one module that builds an event (B-1). Each function takes a ledger
entry of raqib/host.py's HostWatch as the watch keeps it (a finding, a
source finding, a hole, a note or a dark note, a knock row of knock_rows(),
a tree row of state(), the state itself), the watch's facts (facts()) and
the time and number the caller gives, and returns a dict. It reads no
clock, no file, no network and no environment: what it is not given it
does not say (B-4). A key the entry does not hold is absent, never filled
with null or guessed (B-2).

check(obj) returns the problems of an event (an empty list: none); every
event this module builds has none. line(obj) is the one line of it (B-3):
JSON, keys sorted, compact, ASCII. The watch does not write events yet
(M10.2); docs/specs/EVENT.md is the contract (B-6).
"""
import json
import re

from raqib import __version__

SCHEMA = "raqib-event/1"
KINDS = ("finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch")
# B-2: the keys, in B-2's order of meaning (a line sorts them; a dict built here keeps this order)
KEYS = ("schema", "id", "n", "time", "kind", "severity", "summary", "rule", "subject", "evidence", "knocked",
        "state", "result", "counts", "watch")
PARTS = {
    "rule": ("id", "class", "kind", "fp_budget", "attack"),
    "subject": ("tree", "pid", "image", "named", "agent", "path"),
    "evidence": ("run", "round", "record", "source", "trace", "seqs", "lines", "cites"),
    "knocked": ("status", "event"),
    "result": ("word", "exit"),
    "counts": ("rounds", "findings", "source_findings", "holes", "notes", "trees"),
    "watch": ("run", "mode", "platform", "version", "host"),
}
BASE = ("schema", "id", "n", "time", "kind", "severity", "watch")
REQUIRED = {   # per kind, beside BASE
    "finding": ("summary", "rule", "evidence"),
    "source-finding": ("summary", "rule", "subject", "evidence", "state"),
    "note": ("summary",),
    "tree": ("subject",),
    "hole": ("summary",),
    "knock": ("summary", "knocked"),
    "heartbeat": ("result", "counts"),
    "watch": ("state",),
}
ALLOWED = {   # per kind, the keys it may hold
    "finding": BASE + ("summary", "rule", "subject", "evidence", "knocked"),
    "source-finding": BASE + ("summary", "rule", "subject", "evidence", "knocked", "state"),
    "note": BASE + ("summary", "subject", "evidence"),
    "tree": BASE + ("subject", "evidence", "knocked"),
    "hole": BASE + ("summary", "evidence", "knocked"),
    "knock": BASE + ("summary", "evidence", "knocked"),
    "heartbeat": BASE + ("result", "counts"),
    "watch": BASE + ("state", "result", "counts"),
}
SEVERITIES = ("high", "medium", "low")
# B-2: a source finding's state; "pending at exit" is the entry's own word for one whose post never came (host.py
# PENDING_EXIT: silence, an alarm), which B-2's list does not name (docs/review/2026-11-13-M10.1-questions.md Q2)
SOURCE_STATES = ("settled", "history", "judged on another tree", "noted", "pending at exit")
WATCH_STATES = ("start", "end")
TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\Z")
ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
ID = re.compile(r"(.+):([1-9][0-9]*)\Z")


# --- the parts ------------------------------------------------------------------------------------------------

def facts(state, host=None, version=__version__):
    """The watch's facts (B-2 watch) from its state() and the host's name the caller gives (None: absent)."""
    out = {"run": state.get("run"), "mode": state.get("mode"), "platform": state.get("platform"),
           "version": version, "host": host}
    return {k: v for k, v in out.items() if v is not None}


def tree_word(key):
    """A tree's word as the report says it (host.tree_word: pid:image:started, "-" for no start)."""
    pid, image, started = key
    return "%s:%s:%s" % (pid, image, started or "-")


def _held(entry, pairs):
    """{event key: entry value} for each (event key, entry key) the entry holds (not None)."""
    out = {}
    for key, src in pairs:
        if isinstance(entry, dict) and entry.get(src) is not None:
            out[key] = entry[src]
    return out


def _list(value):
    return list(value) if isinstance(value, (list, tuple)) else value


def _base(kind, severity, facts_, time, n):
    return {"schema": SCHEMA, "id": "%s:%d" % (facts_.get("run"), n), "n": n, "time": time, "kind": kind,
            "severity": severity}


def _rule(entry, rule):
    """B-2 rule: id, class and kind from the entry (the finding as the rule gave it); fp_budget and attack from
    the rule's row of report.rule_table (absent without one)."""
    out = _held(entry, (("id", "rule_id"), ("class", "class"), ("kind", "kind")))
    if isinstance(rule, dict):
        out.update(_held(rule, (("fp_budget", "fp_budget"),)))
        if isinstance(rule.get("attack"), (list, tuple)):
            out["attack"] = list(rule["attack"])
    return out


def _knocked(status, event=None):
    out = {}
    if isinstance(status, str) and status:
        out["status"] = status
    if isinstance(event, str) and event:
        out["event"] = event
    return out


def _finish(ev, facts_, **parts):
    for key in KEYS:
        if key in parts and parts[key] not in (None, {}, ""):
            ev[key] = parts[key]
    ev["watch"] = dict(facts_)
    return {k: ev[k] for k in KEYS if k in ev}


# --- one function per kind ------------------------------------------------------------------------------------

def finding(entry, facts_, time, n, rule=None):
    """A finding of the rounds (HostWatch.findings): a tree's or a footprint's."""
    subject = _held(entry, (("tree", "tree"), ("pid", "pid"), ("image", "image"), ("named", "named"),
                            ("agent", "agent"), ("path", "path")))
    evidence = _held(entry, (("run", "run"), ("round", "round"), ("seqs", "cited_seq"), ("cites", "cites")))
    evidence = {k: _list(v) for k, v in evidence.items()}
    return _finish(_base("finding", entry.get("severity"), facts_, time, n), facts_, summary=entry.get("summary"),
                   rule=_rule(entry, rule), subject=subject, evidence=evidence,
                   knocked=_knocked(entry.get("notice")))


def source_state(entry):
    """B-2: a source finding's state, from what the entry holds."""
    if entry.get("judged_on") is not None:
        return "judged on another tree"
    if entry.get("history"):
        return "history"
    if entry.get("benign_note"):
        return "noted"
    return entry.get("state")


def source_finding(entry, facts_, time, n, rule=None):
    """A finding of a tree's source file (HostWatch.source_findings)."""
    subject = _held(entry, (("tree", "tree"), ("pid", "pid"), ("image", "image")))
    evidence = _held(entry, (("run", "run"), ("source", "source"), ("trace", "trace"), ("seqs", "cited_seq"),
                             ("lines", "lines")))
    evidence = {k: _list(v) for k, v in evidence.items()}
    return _finish(_base("source-finding", entry.get("severity"), facts_, time, n), facts_,
                   summary=entry.get("summary"), rule=_rule(entry, rule), subject=subject, evidence=evidence,
                   knocked=_knocked(entry.get("notice")), state=source_state(entry))


def note(entry, facts_, time, n):
    """A note: a text of HostWatch.notes, or a dark note (HostWatch.dark_notes), which says its footprint."""
    if isinstance(entry, str):
        return _finish(_base("note", "info", facts_, time, n), facts_, summary=entry)
    subject = _held(entry, (("tree", "live_tree"), ("agent", "agent"), ("path", "path")))
    evidence = _held(entry, (("run", "run"), ("round", "round"), ("seqs", "cited_seq"), ("cites", "cites")))
    evidence = {k: _list(v) for k, v in evidence.items()}
    return _finish(_base("note", "info", facts_, time, n), facts_, summary=entry.get("text"), subject=subject,
                   evidence=evidence)


def tree(row, facts_, time, n):
    """A tree row of state()'s host.trees."""
    subject = {}
    if isinstance(row.get("key"), (list, tuple)) and len(row["key"]) == 3:
        subject["tree"] = tree_word(row["key"])
    subject.update(_held(row, (("pid", "pid"), ("image", "image"), ("named", "named"))))
    evidence = {}
    if isinstance(row.get("line_seq"), int) and not isinstance(row.get("line_seq"), bool):
        evidence["seqs"] = [row["line_seq"]]
    if row.get("cites"):
        evidence["cites"] = list(row["cites"])
    return _finish(_base("tree", "info", facts_, time, n), facts_, subject=subject, evidence=evidence,
                   knocked=_knocked(row.get("knocked")))


def hole(entry, facts_, time, n):
    """A hole (state()'s holes): the report's line of it, "kind: detail"."""
    summary = "%s: %s" % (entry.get("kind"), entry.get("detail"))
    return _finish(_base("hole", "hole", facts_, time, n), facts_, summary=summary,
                   evidence=_held(entry, (("round", "round"),)), knocked=_knocked(entry.get("notice")))


def knock(row, facts_, time, n):
    """A knock row of HostWatch.knock_rows(): its body, its event and its status now."""
    return _finish(_base("knock", "info", facts_, time, n), facts_, summary=row.get("body"),
                   evidence=_held(row, (("round", "round"),)), knocked=_knocked(row.get("status"), row.get("event")))


def _counts(state):
    h = state.get("host") or {}
    return {"rounds": h.get("rounds"), "findings": len(h.get("findings") or ()),
            "source_findings": len(h.get("source_findings") or ()), "holes": len(state.get("holes") or ()),
            "notes": len(h.get("notes") or ()), "trees": len(h.get("trees") or ())}


def heartbeat(state, facts_, time, n):
    """The watch's beat: its word now (the window's band) and its counts."""
    return _finish(_base("heartbeat", "info", facts_, time, n), facts_,
                   result=_held(state, (("word", "band"),)), counts=_counts(state))


def watch_start(state, facts_, time, n=1):
    return _finish(_base("watch", "info", facts_, time, n), facts_, state="start")


def watch_end(state, facts_, time, n, exit=None):
    """The watch's end: its word (the band of its last state), the exit the caller gives, its counts."""
    result = _held(state, (("word", "band"),))
    if isinstance(exit, int) and not isinstance(exit, bool):
        result["exit"] = exit
    return _finish(_base("watch", "info", facts_, time, n), facts_, state="end", result=result,
                   counts=_counts(state))


def ledger(state, facts_, time, rules=None, knocks=None, end=False, exit=None):
    """Every event of one state, numbered from 1 in one order: the watch's start, its trees, findings, source
    findings, holes, notes (a dark note's text as its dark note), knocks (knock_rows(): the state keeps only the
    newest), and a heartbeat (or, end=True, the watch's end). time: of the start (the state's started) where
    it holds one; an entry's own "at" where it holds one; else the time given. rules: {rule id: row of
    report.rule_table}."""
    rules = rules or {}
    h = state.get("host") or {}

    def at(entry):
        return entry["at"] if isinstance(entry, dict) and isinstance(entry.get("at"), str) and TIME.match(
            entry["at"]) else time
    out = [watch_start(state, facts_, state["started"] if TIME.match(str(state.get("started"))) else time)]
    for row in h.get("trees") or ():
        out.append(tree(row, facts_, time, len(out) + 1))
    for e in h.get("findings") or ():
        out.append(finding(e, facts_, at(e), len(out) + 1, rules.get(e.get("rule_id"))))
    for e in h.get("source_findings") or ():
        out.append(source_finding(e, facts_, at(e), len(out) + 1, rules.get(e.get("rule_id"))))
    for e in state.get("holes") or ():
        out.append(hole(e, facts_, at(e), len(out) + 1))
    dark = {d.get("text"): d for d in h.get("dark_notes") or () if isinstance(d, dict)}
    for text in h.get("notes") or ():
        e = dark.get(text, text)
        out.append(note(e, facts_, at(e), len(out) + 1))
    for row in (h.get("knocks") or ()) if knocks is None else knocks:
        out.append(knock(row, facts_, at(row), len(out) + 1))
    if end:
        out.append(watch_end(state, facts_, time, len(out) + 1, exit=exit))
    else:
        out.append(heartbeat(state, facts_, time, len(out) + 1))
    return out


# --- the line and its check -----------------------------------------------------------------------------------

def line(obj):
    """B-3: the one line of an event: JSON, keys sorted, compact, ASCII (non-ASCII escaped); no newline."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _nulls(value, where, out):
    if value is None:
        out.append("%s: null (a key the entry does not hold is absent)" % where)
    elif isinstance(value, dict):
        for k, v in value.items():
            _nulls(v, "%s.%s" % (where, k), out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _nulls(v, "%s[%d]" % (where, i), out)


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check(obj):
    """The problems of an event (B-2, B-3), as texts; [] when it has none."""
    if not isinstance(obj, dict):
        return ["an event is a JSON object"]
    out = []
    kind = obj.get("kind")
    if obj.get("schema") != SCHEMA:
        out.append("schema: must be %s" % SCHEMA)
    if kind not in KINDS:
        return out + ["kind: must be one of %s" % "|".join(KINDS)]
    for key in obj:
        if key not in ALLOWED[kind]:
            out.append("%s: not a key of a %s event" % (key, kind))
    for key in BASE + REQUIRED[kind]:
        if key not in obj:
            out.append("%s: missing (required in a %s event)" % (key, kind))
    _nulls(obj, "event", out)
    n = obj.get("n")
    if not (_int(n) and n >= 1):
        out.append("n: must be an integer from 1")
    m = ID.match(obj.get("id")) if isinstance(obj.get("id"), str) else None
    w = obj.get("watch") if isinstance(obj.get("watch"), dict) else {}
    if not m or m.group(1) != w.get("run") or m.group(2) != str(n):
        out.append("id: must be <run>:<n> of this event's watch.run and n")
    if not (isinstance(obj.get("time"), str) and TIME.match(obj["time"])):
        out.append("time: must be UTC ISO 8601 with milliseconds and Z")
    sev = obj.get("severity")
    want = SEVERITIES if kind in ("finding", "source-finding") else ("hole",) if kind == "hole" else ("info",)
    if sev not in want:
        out.append("severity: must be one of %s for a %s event" % ("|".join(want), kind))
    for part, keys in PARTS.items():
        if part in obj:
            if not (isinstance(obj[part], dict) and obj[part]):
                out.append("%s: must be a non-empty object" % part)
                continue
            out += ["%s.%s: not a key of %s" % (part, k, part) for k in obj[part] if k not in keys]
    if "summary" in obj and not (isinstance(obj["summary"], str) and obj["summary"]):
        out.append("summary: must be a non-empty string")
    if isinstance(obj.get("rule"), dict):
        if "id" not in obj["rule"]:
            out.append("rule.id: missing")
        attack = obj["rule"].get("attack", [])
        if not (isinstance(attack, list) and all(isinstance(a, str) and ATTACK_ID.match(a) for a in attack)):
            out.append("rule.attack: must be a list of technique ids (T and four digits, .NNN)")
    if kind == "source-finding" and "state" in obj and obj["state"] not in SOURCE_STATES:
        out.append("state: must be one of %s" % "|".join(SOURCE_STATES))
    if kind == "watch" and obj.get("state") not in WATCH_STATES:
        out.append("state: must be start or end")
    if kind == "watch" and obj.get("state") == "end":
        out += ["%s: missing (required in a watch end)" % k for k in ("result", "counts") if k not in obj]
    if kind == "watch" and obj.get("state") == "start":
        out += ["%s: not a key of a watch start" % k for k in ("result", "counts") if k in obj]
    if isinstance(obj.get("counts"), dict):
        out += ["counts.%s: missing or not a count" % k for k in PARTS["counts"]
                if not (_int(obj["counts"].get(k)) and obj["counts"][k] >= 0)]
    if isinstance(obj.get("result"), dict) and "exit" in obj["result"] and not _int(obj["result"]["exit"]):
        out.append("result.exit: must be an integer")
    for k in ("run", "mode", "platform", "version", "host"):
        if k in w and not (isinstance(w[k], str) and w[k]):
            out.append("watch.%s: must be a non-empty string" % k)
    if "run" not in w:
        out.append("watch.run: missing")
    try:
        line(obj)
    except (TypeError, ValueError) as exc:
        out.append("not JSON: %s" % exc)
    return out
