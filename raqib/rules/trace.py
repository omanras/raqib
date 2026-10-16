"""Reading trace files (ADR-0001 section 3).

parse() is pure: it turns trace text into records and reports every line that
is not a sound trace record, so corruption is surfaced, never skipped
silently (constitution A3). read() is the only function here that does I/O.

A problem is {"line": n, "reason": str}; n counts "\n"-separated lines from 1.
- not JSON, not an object, no session_id, or no int seq: the line is dropped
  from the records (it cannot be cited, A5) and reported;
- a bad or missing ts, an unknown phase, or invalid UTF-8: the record is kept
  (it still has a seq) and reported.
"""
from __future__ import annotations

import datetime
import json

PHASES = ("pre", "post", "session_start", "session_end", "stop")


def parse(text):
    """Return (records, problems) for trace text."""
    return _parse((line, True) for line in text.split("\n"))


def read(path):
    """Read and parse a trace file; returns (records, problems)."""
    with open(path, "rb") as f:
        data = f.read()
    lines = []
    for raw in data.split(b"\n"):
        try:
            lines.append((raw.decode("utf-8"), True))
        except UnicodeDecodeError:
            lines.append((raw.decode("utf-8", "replace"), False))
    return _parse(lines)


def _parse(lines):
    records = []
    problems = []
    for number, (raw, decoded) in enumerate(lines, start=1):
        raw = raw.rstrip("\r")
        if not raw.strip():
            continue
        if not decoded:
            problems.append({"line": number, "reason": "invalid UTF-8"})
        try:
            rec = json.loads(raw)
        except ValueError:
            problems.append({"line": number, "reason": "not JSON"})
            continue
        reason = _unusable(rec)
        if reason:
            problems.append({"line": number, "reason": reason})
            continue
        if parse_ts(rec.get("ts")) is None:
            problems.append({"line": number, "reason": "missing or bad ts"})
        if rec.get("phase") not in PHASES:
            problems.append({"line": number, "reason": "unknown phase %r" % (rec.get("phase"),)})
        records.append(rec)
    return records, problems


def _unusable(rec):
    if not isinstance(rec, dict):
        return "not a JSON object"
    if not (isinstance(rec.get("session_id"), str) and rec["session_id"]):
        return "no session_id"
    if not is_seq(rec.get("seq")):
        return "no int seq"
    return None


def is_seq(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_record(rec):
    """True for a dict with a non-empty session_id and an int seq."""
    return _unusable(rec) is None


def parse_ts(value):
    """ISO-8601 timestamp with a UTC offset -> aware datetime, else None."""
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        return None
    return ts
