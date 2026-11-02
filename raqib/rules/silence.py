"""Silence rules (M0.2): constitution A3, ADR-0001 sections 3 and 6.

A capture gap, a session that never closes, half of a tool call and a trace
that runs backwards are findings, not "nothing happened". findings() is a
pure function: it reads only its arguments and returns new dicts.

- SILENCE-GAP    two consecutive lines of one session are more than
                 gap_seconds apart; cites [seq_before, seq_after].
- SILENCE-OPEN   a session has a session_start and its last line is not a
                 session_end or stop: the trace stopped mid-session. Cites the
                 session's last line.
- SILENCE-HALF   a seq has more pre lines than post lines, or more posts than
                 pres; cites that seq.
- SILENCE-ORDER  a line that takes a new seq (pre or a session event) has a
                 seq no higher than one already seen, or a ts earlier than the
                 line before it: the trace was truncated, rotated, merged or
                 its clock moved. Cites [earlier seq, this seq].
- SILENCE-EMPTY  a session that has a session_end and no pre, post or stop
                 line (M4.2, ruling D-6): it started and ended with nothing
                 seen in between (a failed start, or work that was not
                 captured), or it ended with no session_start in the trace
                 at all ("no start"). Cites its session_start and session_end
                 lines. A session_start with nothing after it is not empty:
                 that is SILENCE-OPEN's finding (one fact, one finding); a
                 stop is a turn, so start + stop + end is not empty either.

Each rule declares its kind in code (ADR-0002), in RULE_KINDS, and every
finding carries it. All five are demands: each requires evidence of an act
(a line within the gap, a close, the other half of a call, a seq and ts that
go forward, a tool call or a turn in a session that ended), and the absence
of that evidence is the finding. An agent that knows them is helped only by
complying.

Lines are trace records in file (capture) order. Records without a
session_id and an int seq cannot be cited (A5) and are skipped here;
trace.parse() reports them, and bad timestamps, as problems.
"""
from __future__ import annotations

import math

from raqib.rules.trace import is_record, parse_ts

DEFAULT_GAP_SECONDS = 60
MAX_GAP_SECONDS = 7 * 24 * 3600  # a larger limit would switch SILENCE-GAP off in practice
GAP_ENV = "RAQIB_GAP_SECONDS"
SEVERITY = "high"  # A3: silence is a finding of the highest class
CLOSING = ("session_end", "stop")
NEW_SEQ = ("pre", "session_start", "session_end", "stop")  # capture gives these max+1
RULE_KINDS = {  # ADR-0002: rule id -> kind; a rule not listed here cannot emit
    "SILENCE-GAP": "demand",
    "SILENCE-OPEN": "demand",
    "SILENCE-HALF": "demand",
    "SILENCE-ORDER": "demand",
    "SILENCE-EMPTY": "demand",
}
WORK = ("pre", "post", "stop")  # SILENCE-EMPTY: lines that show a session did something


def gap_seconds_from(environ):
    """RAQIB_GAP_SECONDS from a mapping (e.g. os.environ); default 60.
    Raises ValueError on a value that is not a positive number of at most
    7 days."""
    raw = environ.get(GAP_ENV)
    if raw is None or raw == "":
        return DEFAULT_GAP_SECONDS
    return check_gap_seconds(float(raw), GAP_ENV)


def check_gap_seconds(value, name="gap_seconds"):
    # nan, inf, huge values and 0 would quietly switch gap detection off or
    # flag every line.
    ok = (isinstance(value, (int, float)) and not isinstance(value, bool)
          and math.isfinite(value) and 0 < value <= MAX_GAP_SECONDS)
    if not ok:
        raise ValueError("%s must be a positive number of at most %d seconds, got %r"
                         % (name, MAX_GAP_SECONDS, value))
    return value


def findings(lines, gap_seconds=DEFAULT_GAP_SECONDS):
    """Return SILENCE-* findings, ordered by session (first appearance), then
    first cited seq, then rule_id."""
    check_gap_seconds(gap_seconds)
    sessions = {}
    for rec in lines:
        if is_record(rec):
            sessions.setdefault(rec["session_id"], []).append(rec)
    out = []
    for session_id, recs in sessions.items():
        found = _gaps(session_id, recs, gap_seconds)
        found += _open(session_id, recs)
        found += _halves(session_id, recs)
        found += _order(session_id, recs)
        found += _empty(session_id, recs)
        found.sort(key=lambda f: (f["cited_seq"][0], f["rule_id"]))
        out += found
    return out


def _finding(rule_id, session_id, cited_seq, ts, summary):
    return {
        "ts": ts,
        "rule_id": rule_id,
        "kind": RULE_KINDS[rule_id],
        "severity": SEVERITY,
        "session_id": session_id,
        "cited_seq": list(cited_seq),
        "summary": summary,
    }


def _ts_at(recs, index):
    """ts of recs[index], or of the nearest earlier line with a valid ts."""
    for rec in reversed(recs[:index + 1]):
        if parse_ts(rec.get("ts")) is not None:
            return rec["ts"]
    return None


def _label(rec):
    return "%s seq %d" % (rec.get("phase", "?"), rec["seq"])


def _gaps(session_id, recs, gap_seconds):
    out = []
    timed = [(parse_ts(r.get("ts")), r) for r in recs]
    timed = [(t, r) for t, r in timed if t is not None]
    for (t0, before), (t1, after) in zip(timed, timed[1:]):
        gap = (t1 - t0).total_seconds()
        if gap > gap_seconds:
            out.append(_finding(
                "SILENCE-GAP", session_id, [before["seq"], after["seq"]], after["ts"],
                "no capture for %.3fs from %s (%s) to %s (%s); limit %gs"
                % (gap, before["ts"], _label(before), after["ts"], _label(after), gap_seconds)))
    return out


def _open(session_id, recs):
    starts = [i for i, r in enumerate(recs) if r.get("phase") == "session_start"]
    if not starts or recs[-1].get("phase") in CLOSING:
        return []
    last = recs[-1]
    return [_finding(
        "SILENCE-OPEN", session_id, [last["seq"]], _ts_at(recs, len(recs) - 1),
        "session started but its trace ends at %s without session_end or stop" % _label(last))]


def _empty(session_id, recs):
    """SILENCE-EMPTY (D-6): a session_end, and no pre, post or stop line."""
    ends = [i for i, r in enumerate(recs) if r.get("phase") == "session_end"]
    if not ends or any(r.get("phase") in WORK for r in recs):
        return []
    starts = [r["seq"] for r in recs if r.get("phase") == "session_start"]
    cited = sorted(set(starts + [recs[i]["seq"] for i in ends]))
    last = recs[ends[-1]]
    if starts:
        summary = ("session started at seq %d and ended at %s with no tool call and no stop:"
                   " a failed start, or work that was not captured" % (starts[0], _label(last)))
    else:
        summary = ("%s with no session_start in the trace (no start), no tool call and no stop"
                   % _label(last))
    return [_finding("SILENCE-EMPTY", session_id, cited, _ts_at(recs, ends[-1]), summary)]


def _halves(session_id, recs):
    counts = {}  # seq -> [pre lines, post lines, index of first line]
    for i, rec in enumerate(recs):
        phase = rec.get("phase")
        if phase in ("pre", "post"):
            entry = counts.setdefault(rec["seq"], [0, 0, i])
            entry[0 if phase == "pre" else 1] += 1
    out = []
    for seq, (pres, posts, index) in counts.items():
        if pres == posts:
            continue
        first = recs[index]
        missing = "post" if pres > posts else "pre"
        out.append(_finding(
            "SILENCE-HALF", session_id, [seq], _ts_at(recs, index),
            "seq %d of %s has %d pre and %d post line(s): a %s is missing"
            % (seq, first.get("tool", "?"), pres, posts, missing)))
    return out


def _order(session_id, recs):
    out = []
    max_seq = None
    max_rec = None
    prev_t = None
    prev_rec = None
    for i, rec in enumerate(recs):
        seq = rec["seq"]
        if rec.get("phase") in NEW_SEQ and max_seq is not None and seq <= max_seq:
            out.append(_finding(
                "SILENCE-ORDER", session_id, [max_seq, seq], _ts_at(recs, i),
                "%s comes after %s: seq went back (trace truncated, rotated or merged?)"
                % (_label(rec), _label(max_rec))))
        if max_seq is None or seq > max_seq:
            max_seq, max_rec = seq, rec
        t = parse_ts(rec.get("ts"))
        if t is not None:
            if prev_t is not None and t < prev_t:
                out.append(_finding(
                    "SILENCE-ORDER", session_id, [prev_rec["seq"], seq], rec["ts"],
                    "%s at %s is %.3fs earlier than %s at %s: time went back"
                    % (_label(rec), rec["ts"], (prev_t - t).total_seconds(),
                       _label(prev_rec), prev_rec["ts"])))
            prev_t, prev_rec = t, rec
    return out
