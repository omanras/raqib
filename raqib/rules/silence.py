"""Silence rules (M0.2): constitution A3, ADR-0001 sections 3 and 6.

A capture gap, a session that never closes and half of a tool call are
findings, not "nothing happened". findings() is a pure function: it reads
only its arguments and returns new dicts.

- SILENCE-GAP   two consecutive lines of one session are more than
                gap_seconds apart; cites [seq_before, seq_after].
- SILENCE-OPEN  a session has session_start but no later session_end or stop;
                cites the session's last seq.
- SILENCE-HALF  a pre with no post of the same seq, or a post with no pre;
                cites that seq.

Lines are trace records in file (capture) order. Records without a
session_id and an int seq are ignored here; trace.parse() reports them.
"""
from __future__ import annotations

import math

from raqib.rules.trace import is_record, parse_ts

DEFAULT_GAP_SECONDS = 60
GAP_ENV = "RAQIB_GAP_SECONDS"
SEVERITY = "high"  # A3: silence is a finding of the highest class


def gap_seconds_from(environ):
    """RAQIB_GAP_SECONDS from a mapping (e.g. os.environ); default 60.
    Raises ValueError on a value that is not a positive number."""
    raw = environ.get(GAP_ENV)
    if raw is None or raw == "":
        return DEFAULT_GAP_SECONDS
    value = float(raw)
    # nan and inf would quietly switch gap detection off.
    if not (value > 0 and math.isfinite(value)):
        raise ValueError("%s must be a positive number, got %r" % (GAP_ENV, raw))
    return value


def findings(lines, gap_seconds=DEFAULT_GAP_SECONDS):
    """Return SILENCE-GAP, SILENCE-OPEN and SILENCE-HALF findings, ordered by
    session (first appearance), then cited seq, then rule_id."""
    sessions = {}
    for rec in lines:
        if is_record(rec):
            sessions.setdefault(rec["session_id"], []).append(rec)
    out = []
    for session_id, recs in sessions.items():
        found = _gaps(session_id, recs, gap_seconds)
        found += _open(session_id, recs)
        found += _halves(session_id, recs)
        found.sort(key=lambda f: (f["cited_seq"][0], f["rule_id"]))
        out += found
    return out


def _finding(rule_id, session_id, cited_seq, ts, summary):
    return {
        "ts": ts,
        "rule_id": rule_id,
        "severity": SEVERITY,
        "session_id": session_id,
        "cited_seq": list(cited_seq),
        "summary": summary,
    }


def _gaps(session_id, recs, gap_seconds):
    out = []
    timed = [(parse_ts(r.get("ts")), r) for r in recs]
    timed = [(t, r) for t, r in timed if t is not None]
    for (t0, before), (t1, after) in zip(timed, timed[1:]):
        gap = (t1 - t0).total_seconds()
        if gap > gap_seconds:
            out.append(_finding(
                "SILENCE-GAP", session_id, [before["seq"], after["seq"]], after["ts"],
                "no capture for %.1fs between seq %d and seq %d (limit %gs)"
                % (gap, before["seq"], after["seq"], gap_seconds)))
    return out


def _open(session_id, recs):
    started = False
    closed = False
    for rec in recs:
        phase = rec.get("phase")
        if phase == "session_start":
            started = True
        elif started and phase in ("session_end", "stop"):
            closed = True
    if not started or closed:
        return []
    last = recs[-1]
    return [_finding(
        "SILENCE-OPEN", session_id, [last["seq"]], last.get("ts"),
        "session started but has no session_end or stop; last seq %d" % last["seq"])]


def _halves(session_id, recs):
    pres = {}
    posts = {}
    for rec in recs:
        if rec.get("phase") == "pre":
            pres.setdefault(rec["seq"], rec)
        elif rec.get("phase") == "post":
            posts.setdefault(rec["seq"], rec)
    out = []
    for seq, rec in pres.items():
        if seq not in posts:
            out.append(_finding(
                "SILENCE-HALF", session_id, [seq], rec.get("ts"),
                "pre of %s at seq %d has no post" % (rec.get("tool", "?"), seq)))
    for seq, rec in posts.items():
        if seq not in pres:
            out.append(_finding(
                "SILENCE-HALF", session_id, [seq], rec.get("ts"),
                "post of %s at seq %d has no pre" % (rec.get("tool", "?"), seq)))
    return out
