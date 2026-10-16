#!/usr/bin/env python3
"""Raqib capture hook (M0.1, M0.1b, M0.3).

Installed as a Claude Code hook for PreToolUse, PostToolUse,
PostToolUseFailure, SessionStart, SessionEnd and Stop (tools/install-hooks.sh).
Reads the hook JSON on stdin and appends one trace line (docs/specs/ADR-0001
section 3 and Amendment A) to $RAQIB_LOG (default ./raqib.log.jsonl).

Session events (A-3) become a line with phase session_start, session_end or
stop, tool "-", and no hashes or input_meta. A PostToolUseFailure (A-4) is a
post with ok false and an error_class.

Invariants:
- Never blocks the agent: always exits 0 and never writes to stdout.
- Silence is an alarm (A3): if an event cannot be captured, exactly one line
  starting with "RAQIB-SILENCE:" is written to stderr.
- Offline: stdlib only, no network.
- Privacy: tool input and output are stored only as sha256 of canonical JSON;
  input_meta keeps a small extract (path, url_host, Bash command_head) and
  output_meta the names of secret patterns the output matched, never the text.

seq is per session_id and derived from the log itself: a pre takes
max(seq) + 1. A post takes the seq of the oldest open pre (no post yet) in
the same session with the same tool_use_id (A-2). If none matches, or the
post has no tool_use_id, it falls back to the oldest open pre with the same
tool and input_sha256 where either side has no tool_use_id. Else the post
takes max(seq) + 1.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import urllib.parse

try:
    import fcntl
except ImportError:  # non-POSIX: append without an inter-process lock
    fcntl = None

DEFAULT_LOG = "raqib.log.jsonl"
SILENCE = "RAQIB-SILENCE:"

# hook_event_name -> trace phase.
PHASES = {
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "PostToolUseFailure": "post",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "Stop": "stop",
}
TOOL_PHASES = ("pre", "post")
SESSION_TOOL = "-"

# A-1: leading shell assignments (NAME=value) are not the command.
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
COMMAND_HEAD_MAX = 64

# A-4: a whole class name ending in Error or Exception, such as the leading
# "TimeoutError" of "TimeoutError: ..." or a structured error's type; anything
# else, or a name over 64 chars, is recorded as "failure". Never message text.
LEADING_WORD = re.compile(r"\s*([A-Za-z0-9_.]+)")
CLASS_NAME = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_.]*)?(?:Error|Exception)\Z")
ERROR_CLASS_MAX = 64

# M1.2: names of the secret patterns found in a tool's output. Only the names
# reach the trace, never the matched text (A-5: no raw content).
SECRET_PATTERNS = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("sk_api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
)


class CaptureError(Exception):
    pass


def canonical_sha256(value):
    """sha256 hex of canonical JSON: sorted keys, no whitespace, ASCII escapes."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def tool_use_id(value):
    """The pairing key (A-2) if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def command_head(command):
    """A-1: basename of the first whitespace-separated token of a Bash command,
    skipping leading NAME=value assignments; at most 64 chars. None if there
    is no such token."""
    if not isinstance(command, str):
        return None
    for token in command.split():
        if ASSIGNMENT.match(token):
            continue
        # basename(1): trailing slashes do not count; "/" stays "/".
        name = token.rstrip("/").rsplit("/", 1)[-1] or "/"
        return name[:COMMAND_HEAD_MAX]
    return None


def input_meta(tool, tool_input):
    """Small rule-relevant extract of tool_input: {path?, command_head?, url_host?}."""
    meta = {}
    if not isinstance(tool_input, dict):
        return meta
    if tool == "Bash":
        head = command_head(tool_input.get("command"))
        if head is not None:
            meta["command_head"] = head
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


def error_class(error):
    """A-4: the exception class name of a PostToolUseFailure error, else "failure"."""
    if isinstance(error, dict):
        candidates = [error.get(key) for key in ("type", "name", "class")]
    elif isinstance(error, str):
        match = LEADING_WORD.match(error)
        candidates = [match.group(1)] if match else []
    else:
        candidates = []
    for value in candidates:
        if (isinstance(value, str) and len(value) <= ERROR_CLASS_MAX
                and CLASS_NAME.match(value)):
            return value
    return "failure"


def strings_in(value):
    """Every string in a JSON value (keys included), depth-first."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def secret_kinds(value):
    """Sorted names of SECRET_PATTERNS found in any string of value."""
    found = set()
    for text in strings_in(value):
        for name, pattern in SECRET_PATTERNS:
            if name not in found and pattern.search(text):
                found.add(name)
    return sorted(found)


def session_state(log_text, session_id):
    """Return (max_seq, open_pres) for session_id; open_pres in log order."""
    max_seq = 0
    # (tool, input_sha256, tool_use_id, seq) of pre lines with no post yet
    open_pres = []
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
            open_pres.append((rec.get("tool"), rec.get("input_sha256"),
                              tool_use_id(rec.get("tool_use_id")), seq))
        elif rec.get("phase") == "post":
            open_pres = [p for p in open_pres if p[3] != seq]
    return max_seq, open_pres


def paired_seq(open_pres, tool, input_sha, use_id):
    """seq of the open pre a post closes (A-2), or None."""
    if use_id is not None:
        for _, _, pre_id, pre_seq in open_pres:
            if pre_id == use_id:
                return pre_seq
    for pre_tool, pre_sha, pre_id, pre_seq in open_pres:
        # Two different tool_use_ids are two different calls, whatever the input.
        if use_id is not None and pre_id is not None:
            continue
        if pre_tool == tool and pre_sha == input_sha:
            return pre_seq
    return None


def validate(payload):
    """Reject anything that cannot become a trace line, before touching the log."""
    if not isinstance(payload, dict):
        raise CaptureError("hook input is not a JSON object")
    event = payload.get("hook_event_name")
    if event not in PHASES:
        raise CaptureError("hook event %r is not captured" % (event,))
    required = ("session_id", "tool_name") if PHASES[event] in TOOL_PHASES else ("session_id",)
    for key in required:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise CaptureError("hook input has no %s" % key)


def session_record(payload, log_text):
    """A-3: session_start / session_end / stop line; no hashes, no input_meta."""
    session_id = payload["session_id"]
    max_seq, _ = session_state(log_text, session_id)
    return {
        "ts": now_ts(),
        "seq": max_seq + 1,
        "session_id": session_id,
        "phase": PHASES[payload["hook_event_name"]],
        "tool": SESSION_TOOL,
        "cwd": record_cwd(payload),
    }


def now_ts():
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def record_cwd(payload):
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else os.getcwd()


def build_record(payload, log_text):
    event = payload["hook_event_name"]
    phase = PHASES[event]
    if phase not in TOOL_PHASES:
        return session_record(payload, log_text)
    session_id = payload["session_id"]
    tool = payload["tool_name"]
    tool_input = payload.get("tool_input")
    input_sha = canonical_sha256(tool_input)
    use_id = tool_use_id(payload.get("tool_use_id"))

    max_seq, open_pres = session_state(log_text, session_id)
    seq = max_seq + 1
    if phase == "post":
        pre_seq = paired_seq(open_pres, tool, input_sha, use_id)
        if pre_seq is not None:
            seq = pre_seq

    rec = {
        "ts": now_ts(),
        "seq": seq,
        "session_id": session_id,
        "phase": phase,
        "tool": tool,
    }
    if use_id is not None:
        rec["tool_use_id"] = use_id
    rec["input_sha256"] = input_sha
    rec["input_meta"] = input_meta(tool, tool_input)
    if phase == "post":
        tool_response = payload.get("tool_response")
        output = tool_response if "tool_response" in payload else payload.get("error")
        rec["output_sha256"] = canonical_sha256(output)
        kinds = secret_kinds(output)
        rec["output_meta"] = {"secret_kinds": kinds} if kinds else {}
        rec["ok"] = is_ok(event, tool_response)
        if event == "PostToolUseFailure":
            rec["error_class"] = error_class(payload.get("error"))
    rec["cwd"] = record_cwd(payload)
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
