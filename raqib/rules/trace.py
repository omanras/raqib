"""Reading trace files (ADR-0001 section 3).

parse() is pure: it turns trace text into records and reports every line that
is not a trace record, so a corrupt line is surfaced, never skipped silently
(constitution A3). read() is the only function here that does I/O.
"""
from __future__ import annotations

import datetime
import json


def parse(text):
    """Return (records, bad_lines). bad_lines lists 1-based line numbers of
    non-blank lines that are not JSON objects with a session_id and an int seq."""
    records = []
    bad_lines = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            bad_lines.append(number)
            continue
        if not is_record(rec):
            bad_lines.append(number)
            continue
        records.append(rec)
    return records, bad_lines


def is_record(rec):
    if not isinstance(rec, dict):
        return False
    seq = rec.get("seq")
    session_id = rec.get("session_id")
    return (isinstance(seq, int) and not isinstance(seq, bool)
            and isinstance(session_id, str) and bool(session_id))


def read(path):
    """Read and parse a trace file; returns (records, bad_lines)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse(f.read())


def parse_ts(value):
    """ISO-8601 timestamp -> aware datetime, or None if it is not one."""
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        return None
    return ts
