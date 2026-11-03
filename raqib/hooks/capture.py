#!/usr/bin/env python3
"""Raqib capture hook (M0.1, M0.1b, M0.3, M1.2).

Installed as a Claude Code hook for PreToolUse, PostToolUse,
PostToolUseFailure, SessionStart, SessionEnd and Stop (tools/install_hooks.py).
Reads the hook JSON on stdin and appends one trace line (docs/specs/ADR-0001
section 3 and Amendment A) to the log: the one argument if given (the Windows
hook command has no shell to set a variable, M5.1), else $RAQIB_LOG, else
./raqib.log.jsonl. More than one argument is a capture failure.

Session events (A-3) become a line with phase session_start, session_end or
stop, tool "-", and no hashes or input_meta. A PostToolUseFailure (A-4) is a
post with ok false and an error_class. Every line ends with
"source": "hook" (ADR-0003, M5.2 E3), so a line written before M5.2 is a
byte prefix of the line written now for the same event.

Hashing, input_meta, command_head, command_programs, redaction and the
output scan live in common.py, shared with the proxy source (M5.2 E1); this
file keeps every name it had. Run as the hook, it loads common.py from its
own directory by path; if it cannot, the one RAQIB-SILENCE line below says so,
on stderr and in the trace (ADR-0003 Amendment A, A-7).

Invariants:
- Never blocks the agent: always exits 0 and never writes to stdout.
- Silence is an alarm (A3): if an event cannot be captured, exactly one line
  starting with "RAQIB-SILENCE:" is written to stderr.
- Offline: stdlib only, no network.
- Privacy: tool input and output are stored only as sha256 of canonical JSON;
  input_meta keeps a small extract (path, url_host, Bash command_head and,
  M4.2, command_programs: program basenames, never an argument, or
  command_unread: true when they could not be read) and
  output_meta the names of secret patterns the output matched, never the text.
  A secret inside a path is replaced by [redacted:<kind>].
- Bounded work under the lock: hashing and the secret scan (capped at
  SCAN_MAX_CHARS) run before the log lock is taken; the lock wait is capped
  at LOCK_WAIT_SECONDS and the whole capture at DEADLINE_SECONDS, below the
  installed hook timeout, so a slow capture ends in RAQIB-SILENCE, not a kill.
  Where SIGALRM is missing (Windows) a timer thread keeps the same deadline:
  the same RAQIB-SILENCE line, then exit 0 (ruling Amendment 2, Q-3).
- Every append is locked (M5.1 E2): fcntl.flock on POSIX, msvcrt.locking of
  one byte far beyond EOF on Windows; with neither, capture fails with
  RAQIB-SILENCE instead of appending without a lock.

output_meta on a post line (M1.2):
- {"scan": "full", "secret_kinds": [...]}: every string of tool_response (and
  of error, if present) was scanned; [] means nothing matched.
- {"scan": "partial", ...}: the output was larger than SCAN_MAX_CHARS and only
  its start was scanned; secret_kinds is present only if something matched,
  so a partial scan is never read as clean.
- {"scan": "none"}: the payload had no tool_response or error that is not
  null: nothing to scan, so no secret_kinds either.
- "placeholder_kinds": [...] (only when non-empty): patterns that matched only
  text that looks like a placeholder or a published sample (EXAMPLE, your-...,
  XXXX, the jwt.io sample token), so they were not counted.

seq is per session_id and derived from the log itself: a pre takes
max(seq) + 1. A post takes the seq of the oldest open pre (no post yet) in
the same session with the same tool_use_id (A-2). If none matches, or the
post has no tool_use_id, it falls back to the oldest open pre with the same
tool and input_sha256 where either side has no tool_use_id. Else the post
takes max(seq) + 1.
"""
from __future__ import annotations

import errno
import json
import os
import signal
import sys
import threading
import time

try:
    import fcntl
except ImportError:  # Windows: msvcrt below (M5.1 E2)
    fcntl = None
try:
    import msvcrt
except ImportError:  # POSIX
    msvcrt = None

DEFAULT_LOG = "raqib.log.jsonl"
SILENCE = "RAQIB-SILENCE:"
SOURCE = "hook"  # ADR-0003: the capture source written on every line (M5.2 E3)
COMMON = "common.py"


def _load_common():
    """raqib/hooks/common.py (M5.2 E1). Imported as raqib.hooks.common when
    this file is imported as raqib.hooks.capture (the proxy does); else, run
    as the hook (python -I: neither this directory nor the checkout is on
    sys.path) or loaded by path, the file next to this one, by path."""
    if __package__:
        from raqib.hooks import common
        return common
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), COMMON)
    spec = importlib.util.spec_from_file_location("raqib_hooks_common", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMON_ERROR = None  # run as the hook with no loadable common.py: main() reports it (A3, ruling A-7)
try:
    common = _load_common()
except Exception as _exc:
    if __name__ != "__main__":
        raise
    common, _COMMON_ERROR = None, _exc
if common is not None:
    # Every shared helper under the name capture.py has always given it (E1),
    # so capture.input_meta, capture.SECRET_PATTERNS, ... are common's.
    globals().update((_name, getattr(common, _name)) for _name in common.__all__)

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

LOCK_WAIT_SECONDS = 5.0       # longer: RAQIB-SILENCE instead of waiting for the kill
DEADLINE_SECONDS = 8          # below the installed hook timeout of 10 s
# Windows (M5.1 E2): msvcrt.locking locks bytes from the file position, and
# the lock is mandatory: a reader that does not lock (`raqib report` on a live
# trace) would fail on locked bytes. Writers lock this one byte instead, far
# beyond the end of any trace (1 TiB); a lock past EOF is allowed.
LOCK_OFFSET = 1 << 40


class CaptureError(Exception):
    pass


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


def record_cwd(payload):
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) and cwd else os.getcwd()


def prepare(payload):
    """The parts of a record that do not depend on the log: hashes, input_meta
    and the output scan. Computed before the log lock is taken (review F9)."""
    event = payload["hook_event_name"]
    phase = PHASES[event]
    parts = {"session_id": payload["session_id"], "phase": phase, "cwd": record_cwd(payload)}
    if phase not in TOOL_PHASES:
        parts["tool"] = SESSION_TOOL
        return parts
    tool = payload["tool_name"]
    tool_input = payload.get("tool_input")
    parts.update(tool=tool, use_id=tool_use_id(payload.get("tool_use_id")),
                 input_sha256=canonical_sha256(tool_input), input_meta=input_meta(tool, tool_input))
    if phase == "post":
        tool_response = payload.get("tool_response")
        output = tool_response if "tool_response" in payload else payload.get("error")
        parts["output_sha256"] = canonical_sha256(output)
        parts["output_meta"] = output_meta(payload)
        parts["ok"] = is_ok(event, tool_response)
        if event == "PostToolUseFailure":
            parts["error_class"] = error_class(payload.get("error"))
    return parts


def finish(parts, log_text):
    """The trace line: seq from the log (under the lock) and ts taken there,
    so lines are written in ts order."""
    session_id, phase = parts["session_id"], parts["phase"]
    max_seq, open_pres = session_state(log_text, session_id)
    seq = max_seq + 1
    if phase == "post":
        pre_seq = paired_seq(open_pres, parts["tool"], parts["input_sha256"], parts["use_id"])
        if pre_seq is not None:
            seq = pre_seq
    rec = {"ts": now_ts(), "seq": seq, "session_id": session_id, "phase": phase,
           "tool": parts["tool"]}
    if phase in TOOL_PHASES:
        # A-3: session lines carry no hashes and no input_meta.
        if parts["use_id"] is not None:
            rec["tool_use_id"] = parts["use_id"]
        rec["input_sha256"] = parts["input_sha256"]
        rec["input_meta"] = parts["input_meta"]
        for key in ("output_sha256", "output_meta", "ok", "error_class"):
            if key in parts:
                rec[key] = parts[key]
    rec["cwd"] = parts["cwd"]
    # ADR-0003: last, so a line of an older raqib is a byte prefix of this one.
    rec["source"] = SOURCE
    return rec


def build_record(payload, log_text):
    return finish(prepare(payload), log_text)


def lock(f, wait=None):
    """Exclusive lock on f, or CaptureError after `wait` seconds (B4).
    fcntl.flock on POSIX, else msvcrt.locking on Windows; with neither,
    CaptureError: no platform appends without a lock (M5.1 E2)."""
    if fcntl is not None:
        attempt = _flock_once
    elif msvcrt is not None:
        attempt = _msvcrt_once
    else:
        raise CaptureError("no inter-process lock on this platform (no fcntl, no msvcrt)")
    wait = LOCK_WAIT_SECONDS if wait is None else wait
    deadline = time.monotonic() + wait
    delay = 0.005
    while not attempt(f):
        if time.monotonic() >= deadline:
            raise CaptureError("log lock not acquired within %gs" % wait)
        time.sleep(delay)
        delay = min(delay * 2, 0.1)


def _flock_once(f):
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _lock_byte(f, mode):
    """msvcrt.locking(mode) on the one byte at LOCK_OFFSET. The file position
    is put back, so the read and the append that follow do not move."""
    fd = f.fileno()
    pos = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, LOCK_OFFSET, os.SEEK_SET)
    try:
        msvcrt.locking(fd, mode, 1)
    finally:
        os.lseek(fd, pos, os.SEEK_SET)


def _msvcrt_once(f):
    try:
        _lock_byte(f, msvcrt.LK_NBLCK)
        return True
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EDEADLK):  # another writer holds it
            return False
        raise


def unlock(f):
    """Release a Windows lock before the file is closed: Windows frees a lock
    left at close only in its own time. A flock lock goes with the close."""
    if fcntl is None and msvcrt is not None:
        try:
            _lock_byte(f, msvcrt.LK_UNLCK)
        except OSError:
            pass  # the line is written; closing the file releases the lock too


def append(log_path, payload):
    parts = prepare(payload)
    # Read and append under one exclusive lock so concurrent hooks cannot
    # hand out the same seq.
    with open(log_path, "a+", encoding="utf-8", errors="replace", newline="") as f:
        lock(f)
        try:
            f.seek(0)
            log_text = f.read()
            rec = finish(parts, log_text)
            # A torn last line must not swallow this one.
            prefix = "\n" if log_text and not log_text.endswith("\n") else ""
            # The line is built: the deadline must not tear it or report a line
            # that was written as lost (REDO 2 review B4).
            cancel_deadline()
            f.write(prefix + json.dumps(rec, separators=(",", ":"), ensure_ascii=True) + "\n")
            f.flush()
        finally:
            unlock(f)


class Deadline(Exception):
    pass


def deadline_error():
    return Deadline("capture did not finish within %ds" % DEADLINE_SECONDS)


def on_deadline(signum, frame):
    raise deadline_error()


class TimerDeadline:
    """The deadline where there is no SIGALRM (Windows): a timer thread that,
    unless cancelled first, writes the RAQIB-SILENCE line and ends the process
    with status 0, before the hook timeout can kill it silently (A3). Cancel
    and fire share a lock, so a cancelled deadline never fires mid-write."""

    def __init__(self, seconds, report):
        self._lock = threading.Lock()
        self._done = False
        self._report = report
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def _fire(self):
        with self._lock:
            if self._done:
                return
            self._done = True
            self._report()
            os._exit(0)

    def cancel(self):
        with self._lock:
            self._done = True
        self._timer.cancel()


_timer_deadline = None  # the running TimerDeadline, if any


def cancel_deadline():
    if hasattr(signal, "SIGALRM"):
        signal.alarm(0)
    elif _timer_deadline is not None:
        _timer_deadline.cancel()


def silence_text(event, log_path, exc):
    msg = "%s capture failed event=%s log=%s: %s: %s" % (
        SILENCE, event, log_path, type(exc).__name__, exc)
    return msg.replace("\r", " ").replace("\n", " ").encode("ascii", "backslashreplace").decode("ascii")


def silence(event, log_path, exc):
    try:
        sys.stderr.write(silence_text(event, log_path, exc) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def silence_into_trace(event, log_path, exc):
    """Ruling A-7: a hook that cannot load common.py writes its RAQIB-SILENCE
    line into the trace too, under the lock (raqib watch reads such a line
    as a capture failure), as well as to stderr. Never raises."""
    silence(event, log_path, exc)
    try:
        with open(log_path, "ab+") as f:
            lock(f)
            try:
                end = f.seek(0, os.SEEK_END)
                torn = end > 0 and f.seek(end - 1) >= 0 and f.read(1) != b"\n"
                f.write((b"\n" if torn else b"") + silence_text(event, log_path, exc).encode("ascii") + b"\n")
                f.flush()
            finally:
                unlock(f)
    except Exception:
        pass  # stderr has the line; the trace could not take it


def main(argv=()):
    """argv: the command-line arguments (none, or the log path)."""
    global _timer_deadline
    log_path = (argv[0] if argv else None) or os.environ.get("RAQIB_LOG") or DEFAULT_LOG
    seen = {"event": "-"}
    # The hook is killed at its timeout with no chance to report; end first,
    # with a RAQIB-SILENCE line (B4). SIGALRM exists on Linux and macOS (A-6);
    # elsewhere a timer thread does the same.
    alarm = getattr(signal, "SIGALRM", None)
    if alarm is not None:
        signal.signal(alarm, on_deadline)
        signal.alarm(DEADLINE_SECONDS)
    else:
        _timer_deadline = TimerDeadline(
            DEADLINE_SECONDS, lambda: silence(seen["event"], log_path, deadline_error()))
    try:
        raw = sys.stdin.buffer.read()
        if _COMMON_ERROR is not None:
            cancel_deadline()
            try:
                event = json.loads(raw).get("hook_event_name", "-")
            except Exception:
                event = "-"
            silence_into_trace(event if isinstance(event, str) else "-", log_path, CaptureError(
                "cannot load %s: %s: %s" % (COMMON, type(_COMMON_ERROR).__name__, _COMMON_ERROR)))
            return 0
        payload = json.loads(raw)
        if isinstance(payload, dict):
            seen["event"] = payload.get("hook_event_name", "-")
        if len(argv) > 1:
            raise CaptureError("expected at most one argument (the log), got %d" % len(argv))
        validate(payload)
        append(log_path, payload)
    except Exception as exc:
        # The deadline goes first, so it cannot add a second line (review F12).
        cancel_deadline()
        silence(seen["event"], log_path, exc)
    finally:
        cancel_deadline()
        _timer_deadline = None
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
