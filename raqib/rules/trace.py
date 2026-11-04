"""Reading trace files (ADR-0001 section 3).

parse() is pure: it turns trace text into records and reports every line that
is not a sound trace record, so corruption is surfaced, never skipped
silently (constitution A3). read() is the only function here that does I/O.

A problem is {"line": n, "reason": str}; n counts "\n"-separated lines from 1.
- not JSON, not an object, no session_id, or no int seq: the line is dropped
  from the records (it cannot be cited, A5) and reported; a line starting
  with RAQIB-SILENCE is reported as such (ADR-0003 Amendment A, A-13);
- a bad or missing ts, an unknown phase, an unknown source, or invalid
  UTF-8: the record is kept (it still has a seq) and reported.

Capture sources (ADR-0003, M5.2): a record names the source that wrote it,
"hook", "proxy", "os" or "host" (M7.2b, ADR-0007 decision 3 and Amendment
H: the host's own record of a discovered tree, written by raqib/host.py,
tools HostChild, HostConnection and HostGone). A record without the field was written by the hook
(every trace before M5.2), so source_of() reads it as "hook". Records are
returned exactly as they were read: nothing is added to them, so an old
trace loads as it always did. An os session_start may carry
`missing_events`, the Sysmon event ids its export did not hold (M5.3,
ADR-0003 Amendment C, C-7). Since M4.3 (ADR-0002 Amendment J, J-2 and J-5)
the hook's session_start, stop and session_end lines carry GIT_KEYS, the
local git state read from files: strict_problem holds their shape.
"""
from __future__ import annotations

import datetime
import json
import re

# "history": the proxy's one line per conversation for the tool results that
# predate it (ADR-0003 Amendment A, A-4); no rule judges it.
PHASES = ("pre", "post", "session_start", "session_end", "stop", "history")
SOURCES = ("hook", "proxy", "os", "host")  # ADR-0003; "host": M7.2b (ADR-0007 H-2)
DEFAULT_SOURCE = "hook"            # a record without "source" (ADR-0003: v0.1 traces stay valid)
SILENCE_MARKER = "RAQIB-SILENCE"   # a line a capture source wrote when it could not capture (A3)
SILENCE_REASON = "a RAQIB-SILENCE line: something was not captured (A3)"


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
        if raw.lstrip().startswith(SILENCE_MARKER):
            # Ruling A-13: named as what it is, a capture failure (A3), not "not JSON".
            problems.append({"line": number, "reason": SILENCE_REASON})
            continue
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
          "output_sha256", "output_meta", "ok", "error_class", "cwd", "source",
          # proxy lines (ADR-0003 Amendment A): A-2, and the history line of A-4
          "tool_hashed", "results", "tool_use_ids", "output_sha256s",
          # os lines (ADR-0003 Amendment C, C-7): the Sysmon event ids an export did not hold
          "missing_events",
          # hook boundary lines (M4.3, ADR-0002 Amendment J, J-2): the git state read from files
          "git_head", "git_index_sha256", "git_error")
# J-2, J-5: the git keys, all three together, on session_start, stop and
# session_end lines only. git_error is one of GIT_ERRORS (the closed set of
# raqib/hooks/common.py, which a test holds this copy to) or null, and it is
# null exactly when both values were read.
GIT_KEYS = ("git_head", "git_index_sha256", "git_error")
GIT_ERRORS = ("no repo", "symlink", "gitdir", "unreadable", "no ref", "no index", "index too large", "budget")
GIT_PHASES = ("session_start", "stop", "session_end")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


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
    return git_problem(rec)


def git_problem(rec):
    """Why a record's git keys (J-2) are not in the shape the hook writes, or
    None: all three or none, only on a session_start, stop or session_end
    line; git_head 40-hex or null, git_index_sha256 64-hex or null, git_error
    one of GIT_ERRORS or null, and null exactly when both values are read."""
    present = [k for k in GIT_KEYS if k in rec]
    if not present:
        return None
    if len(present) != len(GIT_KEYS):
        return "git keys come together: %s without %s" % (", ".join(present),
                                                          ", ".join(k for k in GIT_KEYS if k not in rec))
    if rec.get("phase") not in GIT_PHASES:
        return "git keys only on session_start, stop and session_end lines, not on %r" % (rec.get("phase"),)
    head, index, error = (rec[k] for k in GIT_KEYS)
    if not (head is None or (isinstance(head, str) and HEX40.match(head))):
        return "git_head must be 40 lower-case hex digits or null"
    if not (index is None or (isinstance(index, str) and HEX64.match(index))):
        return "git_index_sha256 must be 64 lower-case hex digits or null"
    if not (error is None or (isinstance(error, str) and error in GIT_ERRORS)):
        return "git_error must be one of %s, or null" % ", ".join(GIT_ERRORS)
    if (error is None) != (head is not None and index is not None):
        return "git_error must be null exactly when git_head and git_index_sha256 are both read"
    return None
