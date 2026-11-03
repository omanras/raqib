"""Reading trace files (ADR-0001 section 3).

parse() is pure: it turns trace text into records and reports every line that
is not a sound trace record, so corruption is surfaced, never skipped
silently (constitution A3). read() is the only function here that does I/O.

A problem is {"line": n, "reason": str}; n counts "\n"-separated lines from 1.
- not JSON, not an object, no session_id, or no int seq: the line is dropped
  from the records (it cannot be cited, A5) and reported;
- a bad or missing ts, an unknown phase, an unknown source, or invalid
  UTF-8: the record is kept (it still has a seq) and reported.

Capture sources (ADR-0003, M5.2): a record names the source that wrote it,
"hook", "proxy" or "os". A record without the field was written by the hook
(every trace before M5.2), so source_of() reads it as "hook". Records are
returned exactly as they were read: nothing is added to them, so an old
trace loads as it always did.
"""
from __future__ import annotations

import datetime
import json

PHASES = ("pre", "post", "session_start", "session_end", "stop")
SOURCES = ("hook", "proxy", "os")  # ADR-0003
DEFAULT_SOURCE = "hook"            # a record without "source" (ADR-0003: v0.1 traces stay valid)


def parse(text):
    """Return (records, problems) for trace text."""
    numbered, problems = parse_numbered(text)
    return [rec for _, rec in numbered], problems


def read(path):
    """Read and parse a trace file; returns (records, problems)."""
    numbered, problems = read_numbered(path)
    return [rec for _, rec in numbered], problems


def parse_numbered(text):
    """Like parse(), but records come as (line number, record) pairs, so a
    report can cite the exact lines of a trace file (A5)."""
    return _parse((line, True) for line in text.split("\n"))


def read_numbered(path):
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
    records = []  # (line number, record)
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
        if "source" in rec and rec["source"] not in SOURCES:
            problems.append({"line": number, "reason": "unknown source %r" % (rec["source"],)})
        records.append((number, rec))
    return records, problems


def _unusable(rec):
    if not isinstance(rec, dict):
        return "not a JSON object"
    if not (isinstance(rec.get("session_id"), str) and rec["session_id"]):
        return "no session_id"
    if not is_seq(rec.get("seq")):
        return "no int seq"
    return None


def source_of(rec):
    """The capture source of a record: its "source", or "hook" when it has
    none (ADR-0003). An unknown value is returned as it is, as text; parse()
    has reported it."""
    if not isinstance(rec, dict) or "source" not in rec:
        return DEFAULT_SOURCE
    value = rec["source"]
    return value if isinstance(value, str) else json.dumps(value)


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


FIELDS = ("ts", "seq", "session_id", "phase", "tool", "tool_use_id", "input_sha256", "input_meta",
          "output_sha256", "output_meta", "ok", "error_class", "cwd", "source")


def strict_problem(rec):
    """Why a hand-written line (a fixture or an eval event) is not in the shape
    capture writes, or None. Stricter than parse(): an unknown or misspelled
    field, or a tool line without its tool, input_meta or ok, would otherwise
    be judged "does not apply" and pass as a clean negative (A6)."""
    if not is_record(rec):
        return "no session_id and int seq"
    if parse_ts(rec.get("ts")) is None:
        return "no valid ts"
    if rec.get("phase") not in PHASES:
        return "unknown phase %r" % (rec.get("phase"),)
    if "source" in rec and rec["source"] not in SOURCES:
        return "unknown source %r" % (rec["source"],)
    unknown = sorted(set(rec) - set(FIELDS))
    if unknown:
        return "unknown field(s) %s" % ", ".join(unknown)
    if not (isinstance(rec.get("tool"), str) and rec["tool"]):
        return "no tool"
    if not (isinstance(rec.get("cwd"), str) and rec["cwd"]):
        return "no cwd"
    if rec["phase"] in ("pre", "post"):
        if not isinstance(rec.get("input_meta"), dict):
            return "a tool line needs input_meta"
        if rec["phase"] == "post" and not isinstance(rec.get("ok"), bool):
            return "a post needs ok"
        if "output_meta" in rec and not isinstance(rec["output_meta"], dict):
            return "output_meta must be a mapping"
    return None
