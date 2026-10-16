#!/usr/bin/env python3
"""Raqib capture hook (M0.1).

Installed as a Claude Code PreToolUse + PostToolUse hook. Reads the hook JSON
on stdin and appends one trace line (docs/specs/ADR-0001 section 3) to
$RAQIB_LOG (default ./raqib.log.jsonl).

Invariants:
- Never blocks the agent: always exits 0 and never writes to stdout.
- Silence is an alarm (A3): if an event cannot be captured, exactly one line
  starting with "RAQIB-SILENCE:" is written to stderr.
- Offline: stdlib only, no network.
- Privacy: tool input and output are stored only as sha256 of canonical JSON.

seq is per session_id and derived from the log itself: a pre takes
max(seq) + 1; a post takes the seq of the oldest pre in the same session with
the same tool and input_sha256 that has no post yet (else max(seq) + 1).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import urllib.parse

try:
    import fcntl
except ImportError:  # non-POSIX: append without an inter-process lock
    fcntl = None

DEFAULT_LOG = "raqib.log.jsonl"
SILENCE = "RAQIB-SILENCE:"

# hook_event_name -> trace phase. M0.1 captures tool events only.
PHASES = {
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "PostToolUseFailure": "post",
}


class CaptureError(Exception):
    pass


def canonical_sha256(value):
    """sha256 hex of canonical JSON: sorted keys, no whitespace, ASCII escapes."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def input_meta(tool_input):
    """Small rule-relevant extract of tool_input: {path?, url_host?}."""
    meta = {}
    if not isinstance(tool_input, dict):
        return meta
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            meta["path"] = value
            break
    url = tool_input.get("url")
    if isinstance(url, str):
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            meta["url_host"] = host
    return meta


def is_ok(event, tool_response):
    """False on an explicit failure marker; True otherwise."""
    if event == "PostToolUseFailure":
        return False
    if isinstance(tool_response, dict):
        if tool_response.get("success") is False:
            return False
        if tool_response.get("is_error") is True:
            return False
        if tool_response.get("interrupted") is True:
            return False
    return True


def session_state(log_text, session_id):
    """Return (max_seq, open_pres) for session_id; open_pres in log order."""
    max_seq = 0
    open_pres = []  # (tool, input_sha256, seq) of pre lines with no post yet
    needle = json.dumps(session_id)
    for raw in log_text.splitlines():
        if needle not in raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("session_id") != session_id:
            continue
        seq = rec.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            continue
        max_seq = max(max_seq, seq)
        if rec.get("phase") == "pre":
            open_pres.append((rec.get("tool"), rec.get("input_sha256"), seq))
        elif rec.get("phase") == "post":
            open_pres = [p for p in open_pres if p[2] != seq]
    return max_seq, open_pres


def validate(payload):
    """Reject anything that cannot become a trace line, before touching the log."""
    if not isinstance(payload, dict):
        raise CaptureError("hook input is not a JSON object")
    event = payload.get("hook_event_name")
    if event not in PHASES:
        raise CaptureError("hook event %r is not captured" % (event,))
    for key in ("session_id", "tool_name"):
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise CaptureError("hook input has no %s" % key)


def build_record(payload, log_text):
    event = payload["hook_event_name"]
    phase = PHASES[event]
    session_id = payload["session_id"]
    tool = payload["tool_name"]
    tool_input = payload.get("tool_input")
    input_sha = canonical_sha256(tool_input)

    max_seq, open_pres = session_state(log_text, session_id)
    seq = max_seq + 1
    if phase == "post":
        for pre_tool, pre_sha, pre_seq in open_pres:
            if pre_tool == tool and pre_sha == input_sha:
                seq = pre_seq
                break

    now = datetime.datetime.now(datetime.timezone.utc)
    rec = {
        "ts": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "seq": seq,
        "session_id": session_id,
        "phase": phase,
        "tool": tool,
        "input_sha256": input_sha,
        "input_meta": input_meta(tool_input),
    }
    if phase == "post":
        tool_response = payload.get("tool_response")
        output = tool_response if "tool_response" in payload else payload.get("error")
        rec["output_sha256"] = canonical_sha256(output)
        rec["ok"] = is_ok(event, tool_response)
    cwd = payload.get("cwd")
    rec["cwd"] = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    return rec


def append(log_path, payload):
    # Read and append under one exclusive lock so concurrent hooks cannot
    # hand out the same seq. The lock is released when the file is closed.
    with open(log_path, "a+", encoding="utf-8", errors="replace", newline="") as f:
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.seek(0)
        log_text = f.read()
        rec = build_record(payload, log_text)
        # A torn last line must not swallow this one.
        prefix = "\n" if log_text and not log_text.endswith("\n") else ""
        f.write(prefix + json.dumps(rec, separators=(",", ":"), ensure_ascii=True) + "\n")
        f.flush()


def silence(event, log_path, exc):
    msg = "%s capture failed event=%s log=%s: %s: %s" % (
        SILENCE, event, log_path, type(exc).__name__, exc)
    msg = msg.replace("\r", " ").replace("\n", " ")
    try:
        sys.stderr.write(msg.encode("ascii", "backslashreplace").decode("ascii") + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def main():
    log_path = os.environ.get("RAQIB_LOG") or DEFAULT_LOG
    event = "-"
    try:
        payload = json.loads(sys.stdin.buffer.read())
        if isinstance(payload, dict):
            event = payload.get("hook_event_name", "-")
        validate(payload)
        append(log_path, payload)
    except Exception as exc:
        silence(event, log_path, exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
