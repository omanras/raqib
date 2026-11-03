"""Read-only web view (M3.1; dashboard v2, M6.2, ADR-0005 Amendment I).

One page builder for `raqib ui` and `raqib watch` (I-9). In this order:
- the band (watch only): one state word and a detail line (I-3), the
  notifications on or off, the trace path and the time of the last line;
- the alarms, capture holes first (A3);
- the findings, grouped high > medium > low. Empty groups are left out,
  and a severity outside those three goes in "other", last, with a note.
  Each finding cites its trace lines (A5);
- the timeline of every trace line in file order, with the silence drawn
  into it (A3): a band where a session went quiet for longer than the gap
  limit, a "no post" mark on a pre that never completed (and the
  reverse), a band where a started session ends without stop or
  session_end, a row for every corrupt line, and (watch) the live silence
  windows, the closed ones lighter and the open one marked (I-10);
- then the other watches (watch only), the suspicion lines, the rules that
  did not run and the rule table (A6). Each finding and each rule row
  names its kind (ADR-0002 B-1).

Live (I-1): a served page reloads itself by <meta http-equiv="refresh">
every N seconds (--refresh, 1..3600, default 5). A static file never
does. The Content-Security-Policy is unchanged: no script runs and
nothing is loaded.

The watch page is built from the state dict that watch holds in memory
(I-4). The other watches come from the registry on disk
(~/.raqib/watches.json), which any process of the user can write. The
page says so (forgeable), and reads the registry without ever writing it
(I-5). A row is ALIVE only when its pid is alive and the heartbeat in its
own <trace>.watch.json is younger than max(1.5 s, 3 x its step_seconds),
at most 30 s (I-6, J-5); that file is opened only when it is a local
absolute path, never UNC (J-7), and at most 64 rows are shown. The pid is checked without a signal (A4): on POSIX
os.kill(pid, 0); on Windows OpenProcess and GetExitCodeProcess through
ctypes, never os.kill, because 0 is CTRL_C_EVENT there. A link is only
ever http://127.0.0.1:<whole-number port>/ (I-7).

Discover (I-8): <trace dir>/discover.json (`raqib discover --json`) is
shown with its candidates, holes and cited lines, and with its age. On
watch's server it is GET /discover; in `raqib ui` it is a section of the
page, present only when the file exists. A file that cannot be read or is
not an inventory is an alarm on the tab (A3).

Safe by construction: every value from the trace, the state, the
registry or the inventory is escaped, and each non-printable character is
replaced by "?" (I-11), because the watched agent controls them. The only
hrefs are #L<line>, #<section>, /, /discover and the links above.
serve() binds 127.0.0.1 only, answers GET and HEAD, refuses a Host header
that is not local, and never writes (A4).
"""
from __future__ import annotations

import datetime
import html
import json
import http.server
import os
import re
import socketserver
import stat
import sys

from raqib.rules import silence, trace

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
CELL_MAX = 400
RESULT_TEXT = {"alarm": "ALARM", "incomplete": "INCOMPLETE", "clean": "CLEAN"}
REFRESH_DEFAULT = 5       # I-1: seconds between reloads of a served page
REFRESH_MAX = 3600
SEVERITIES = ("high", "medium", "low")
OTHER = "other"
# J-8: the hole kinds, first among the alarms and in this order; the rest as they came.
HOLE_ORDER = ("capture-failed", "trace-missing", "trace-unreadable", "trace-truncated", "trace-replaced",
              "trace-rewritten", "state-unwritable", "watch-crashed")
CAPTURE_KINDS = HOLE_ORDER[:1]
ROWS_MAX = 64          # J-7: registry rows judged on a page; the rest are counted
FRESH_CAP = 30.0       # J-5: the longest heartbeat age a row can be ALIVE with
DISCOVER_NAME = "discover.json"
DISCOVER_ROUTE = "/discover"
DISCOVER_ACTS_SHOWN = 12  # discover.ACTS_SHOWN (a test keeps them equal)
READ_MAX = 16 * 1024 * 1024  # bytes read of discover.json, another watch's watch.json, the registry
PORT_MAX = 65535
PID_MAX = 2 ** 31 - 1
STILL_ACTIVE = 259                         # GetExitCodeProcess of a running process
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
ERROR_ACCESS_DENIED = 5
FORGEABLE = ("this file can be written by any process of the user the agent runs as, so a row can be forged"
             " (ADR-0005 I-4)")
PID_REUSE = "A pid that another process took over reads as alive (a known hole, I-6)"

STYLE = """
:root { --bg: #ffffff; --fg: #1d1f21; --muted: #5f6368; --line: #d9dce0; --panel: #f6f7f9;
  --alarm: #b3261e; --alarm-bg: #fce8e6; --warn: #8a5a00; --warn-bg: #fef3d6;
  --ok: #1e6b34; --ok-bg: #e6f4ea; --flag-bg: #fff4e5; --band-bg: #fde7e9; --live-bg: #fbf1f2; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #15171a; --fg: #e3e5e8; --muted: #9aa0a6; --line: #33373c; --panel: #1e2125;
    --alarm: #f28b82; --alarm-bg: #3c1d1b; --warn: #fdd663; --warn-bg: #3a3016;
    --ok: #81c995; --ok-bg: #1b3324; --flag-bg: #33291a; --band-bg: #3a1e22; --live-bg: #2a1d20; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 16px; background: var(--bg); color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 20px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 28px 0 8px; }
h3 { font-size: 14px; margin: 16px 0 4px; }
code, td, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
.meta { color: var(--muted); overflow-wrap: anywhere; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 600; }
.alarm { color: var(--alarm); background: var(--alarm-bg); }
.incomplete { color: var(--warn); background: var(--warn-bg); }
.clean { color: var(--ok); background: var(--ok-bg); }
.band { border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px; margin: 8px 0; overflow-wrap: anywhere; }
.band .state { font-size: 15px; }
.nav a { margin-right: 12px; }
.card { border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin: 8px 0;
  background: var(--panel); overflow-wrap: anywhere; }
.card .head { font-weight: 600; } .card ul { margin: 6px 0 0; padding-left: 18px; }
.empty { color: var(--muted); }
.scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: var(--panel); position: sticky; top: 0; font-weight: 600; }
td.wrap { overflow-wrap: anywhere; min-width: 16ch; }
td.nowrap { white-space: nowrap; }
tr.flag td { background: var(--flag-bg); }
tr.band td { background: var(--band-bg); color: var(--alarm); font-weight: 600; }
tr.band.live td { background: var(--live-bg); font-weight: 400; }
tr.band.live.open td { background: var(--band-bg); font-weight: 700; }
tr:target td { outline: 2px solid var(--alarm); outline-offset: -2px; }
.tag { display: inline-block; padding: 0 6px; margin: 1px 2px 1px 0; border-radius: 4px; font-size: 11.5px;
  background: var(--alarm-bg); color: var(--alarm); white-space: nowrap; }
a { color: inherit; }
"""


def _text(value):
    """Escaped, printable, bounded text for any value from the trace."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)
    text = "".join(c if c.isprintable() else "?" for c in text)
    if len(text) > CELL_MAX:
        keep = CELL_MAX - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    return html.escape(text, quote=True)


def _anchor(line):
    return "L%d" % line


def _int(value):
    """value when it is a whole number (not a bool), else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _when(value):
    return trace.parse_ts(value)


def _iso(moment):
    moment = moment.astimezone(datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def check_refresh(value):
    """I-1: N of --refresh, a whole number of seconds from 1 to REFRESH_MAX."""
    text = value if isinstance(value, str) else str(value)
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,5}", text) or not 1 <= int(text) <= REFRESH_MAX:
        raise ValueError("--refresh must be a whole number of seconds from 1 to %d, not %r" % (REFRESH_MAX, value))
    return int(text)


def port_url(port):
    """I-7: the only link to another watch, or None."""
    port = _int(port)
    return "http://127.0.0.1:%d/" % port if port is not None and 1 <= port <= PORT_MAX else None


def _head(title, refresh):
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="%s">' % CSP,
           '<meta name="referrer" content="no-referrer">']
    if refresh is not None:
        out.append('<meta http-equiv="refresh" content="%d">' % check_refresh(refresh))
    out += ["<title>%s</title>" % title, "<style>%s</style>" % STYLE, "</head>", "<body><main>"]
    return out


# --- reading files the agent may have written ------------------------------------------

def read_json(path, limit=None):
    """(value, error, os.stat result) of a JSON file; (None, None, None) when
    there is no such file. A FIFO or a device is never opened, and at most
    limit + 1 bytes are read (default READ_MAX)."""
    limit = READ_MAX if limit is None else limit
    try:
        st = os.stat(path)
    except FileNotFoundError:
        if os.path.lexists(path):   # J-11: a link to nothing is an unreadable file, not an absent one
            return None, "cannot be read: it is a link to nothing", os.lstat(path)
        return None, None, None
    except (OSError, ValueError) as exc:
        return None, "cannot be read: %s" % (getattr(exc, "strerror", None) or exc), None
    if not stat.S_ISREG(st.st_mode):
        return None, "is not a regular file", st
    if st.st_size > limit:
        return None, "is %d bytes, more than the %d bytes Raqib reads" % (st.st_size, limit), st
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None, "is not a regular file", st
            raw = f.read(limit + 1)
    except FileNotFoundError:
        return None, None, None
    except OSError as exc:
        return None, "cannot be read: %s" % (exc.strerror or exc), st
    if len(raw) > limit:
        return None, "is more than the %d bytes Raqib reads" % limit, st
    try:
        return json.loads(raw.decode("utf-8")), None, st
    except UnicodeDecodeError:
        return None, "is not UTF-8", st
    except (ValueError, RecursionError) as exc:
        return None, "is not JSON (%s)" % exc, st


def discover_path(trace_path):
    """I-8: discover.json next to the trace."""
    return os.path.join(os.path.dirname(str(trace_path)) or ".", DISCOVER_NAME)


def read_discover(path, now=None):
    """The inventory at path for the discover tab: {path, exists, data,
    error, written, age}. Unreadable or not an inventory: error (A3)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    data, error, st = read_json(path)
    info = {"path": path, "exists": st is not None or error is not None, "data": None, "error": error,
            "written": None, "age": None}
    if st is not None:
        written = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc)
        info["written"], info["age"] = _iso(written), (now - written).total_seconds()
    if error is None and info["exists"]:
        if not isinstance(data, dict):
            info["error"] = "is not an inventory: not a JSON object"
        else:
            bad = [k for k in ("candidates", "holes") if not isinstance(data.get(k), list)]
            if bad:
                info["error"] = "is not an inventory of raqib discover --json: %s %s not a list" % (
                    " and ".join(bad), "is" if len(bad) == 1 else "are")
            else:
                info["data"] = data
    return info


# --- liveness of another watch (I-6) ------------------------------------------------------

def valid_pid(pid):
    pid = _int(pid)
    return pid is not None and 0 < pid <= PID_MAX


def pid_alive(pid, platform=None, kill=None, kernel32=None):
    """True, False, or None when it cannot be told. Never a signal (A4): on
    POSIX os.kill(pid, 0) only checks; on Windows os.kill is never called
    (signal 0 is CTRL_C_EVENT there, any other value TerminateProcess)."""
    if not valid_pid(pid):
        return False
    if (platform or sys.platform) == "win32":
        return _windows_alive(pid, kernel32)
    kill = kill or os.kill
    try:
        kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:   # another user's process: it exists
        return True
    except OSError:
        return None
    return True


class Kernel32:
    """OpenProcess, GetExitCodeProcess and CloseHandle by ctypes; nothing else."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes = ctypes, wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k.OpenProcess.restype = wintypes.HANDLE
        k.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        k.GetExitCodeProcess.restype = wintypes.BOOL
        k.CloseHandle.argtypes = (wintypes.HANDLE,)
        k.CloseHandle.restype = wintypes.BOOL
        self.k = k

    def open_process(self, pid):
        """(handle, 0) or (None, the Windows error code)."""
        handle = self.k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        return (handle, 0) if handle else (None, self.ctypes.get_last_error())

    def exit_code(self, handle):
        code = self.wintypes.DWORD()
        return code.value if self.k.GetExitCodeProcess(handle, self.ctypes.byref(code)) else None

    def close(self, handle):
        self.k.CloseHandle(handle)


def _windows_alive(pid, kernel32=None):
    try:
        api = kernel32 or Kernel32()
    except (ImportError, OSError, AttributeError, ValueError):   # no kernel32 here: cannot tell
        return None
    handle, error = api.open_process(pid)
    if handle is None:
        return True if error == ERROR_ACCESS_DENIED else False
    try:
        code = api.exit_code(handle)
        return None if code is None else code == STILL_ACTIVE
    finally:
        api.close(handle)


def read_watches(path, now, fresh_seconds, own=None, alive=None):
    """I-4..I-7: the registry at path, read and never written. {path, rows,
    holes, more}; own (pid, trace, started) is the watch serving the page,
    shown from memory, so its row is skipped here. now: an aware datetime.
    At most ROWS_MAX rows are judged, the newest; the rest are counted (J-7)."""
    alive = alive or pid_alive
    info = {"path": path, "rows": [], "holes": [], "more": 0, "fresh_seconds": fresh_seconds}
    data, error, _ = read_json(path)
    if error:
        info["holes"].append("the registry %s %s; it is left as it is (I-5)" % (path, error))
        return info
    if data is None:
        return info
    if not isinstance(data, dict) or not isinstance(data.get("watches"), list):
        info["holes"].append("the registry %s is not a Raqib registry (no list of watches); it is left as it"
                             " is (I-5)" % path)
        return info
    rows = []
    for raw in data["watches"]:
        if not isinstance(raw, dict):
            info["holes"].append("a row of the registry %s is not an object: %s" % (path, json.dumps(raw)[:80]))
            continue
        if own is not None and (raw.get("pid"), raw.get("trace"), raw.get("started")) == tuple(own):
            continue
        rows.append(raw)
    info["more"] = max(0, len(rows) - ROWS_MAX)
    info["rows"] = [judge_row(raw, now, fresh_seconds, alive) for raw in rows[-ROWS_MAX:]]
    return info


def local_state_path(trace_path):
    """J-7 (no network): <trace>.watch.json when it is a local absolute path
    that is not UNC (no leading \\\\ or //), else None. Only this file is
    opened for a registry row."""
    if not isinstance(trace_path, str) or not trace_path or "\x00" in trace_path:
        return None
    path = trace_path + ".watch.json"
    if path[:2] in ("\\\\", "//", "\\/", "/\\"):
        return None
    if os.name == "nt":
        return path if re.match(r"[A-Za-z]:[\\/]", path) else None
    return path if path.startswith("/") else None


def fresh_limit(base, step_seconds):
    """J-5: ALIVE needs a heartbeat younger than max(base, 3 x step_seconds), at most FRESH_CAP."""
    step = step_seconds if isinstance(step_seconds, (int, float)) and not isinstance(step_seconds, bool) else 0
    return min(FRESH_CAP, max(base, 3 * step)) if step == step else base   # NaN: the base


def judge_row(raw, now, fresh_seconds, alive=None):
    """ALIVE needs the pid alive and a heartbeat younger than fresh_limit()
    in the row's own <trace>.watch.json; else GONE, with the reasons (I-6).
    word: the row's state word: its watch.json's band (J-6), or CRASHED for
    a crash or a stale heartbeat (J-13, C-4), or FINISHED."""
    alive = alive or pid_alive
    row = {k: raw.get(k) for k in ("pid", "project", "port", "trace", "started", "finished", "status")}
    row["notes"] = [n for n in _list(raw.get("notes")) if isinstance(n, str)]
    reasons = []
    pid = raw.get("pid")
    if not valid_pid(pid):
        reasons.append("pid %s is not a process number" % json.dumps(pid)[:40])
    else:
        state = alive(pid)
        if state is None:
            reasons.append("pid %d cannot be checked" % pid)
        elif not state:
            reasons.append("pid %d is gone" % pid)
    state_path = local_state_path(raw.get("trace"))
    row.update(state=state_path, watch_status=None, watch_band=None, heartbeat=None, fresh=fresh_seconds)
    stale = False
    if state_path is None:
        reasons.append("its watch.json is not opened: the trace %s is not a local absolute path (no network, J-7)"
                       % json.dumps(raw.get("trace"))[:200])
    else:
        data, error, _ = read_json(state_path)
        beat = None
        if error:
            reasons.append("its watch.json %s" % error)
        elif data is None:
            reasons.append("its watch.json is gone, so no heartbeat")
        elif not isinstance(data, dict):
            reasons.append("its watch.json is not an object, so no heartbeat")
        elif (data.get("pid"), data.get("started")) != (raw.get("pid"), raw.get("started")):
            # Another watch of the same trace writes that file now: its heartbeat is not this row's.
            reasons.append("its watch.json belongs to another watch now (pid %s, started %s)" % (
                json.dumps(data.get("pid"))[:40], json.dumps(data.get("started"))[:40]))
        else:
            row["watch_status"] = data.get("status")
            row["watch_band"] = data.get("band")
            row["heartbeat"] = data.get("heartbeat")
            row["fresh"] = fresh_limit(fresh_seconds, data.get("step_seconds"))
            beat = _when(data.get("heartbeat"))
            if beat is None:
                reasons.append("its watch.json has no heartbeat")
        if beat is not None:
            age = (now - beat).total_seconds()
            if age >= row["fresh"]:
                stale = True
                reasons.append("no heartbeat for %.1f s (ALIVE needs one younger than %g s)" % (age, row["fresh"]))
            elif age < -row["fresh"]:
                reasons.append("its heartbeat is %.1f s in the future" % -age)
    row["alive"] = not reasons
    row["why"] = "; ".join(reasons)
    row["link"] = port_url(raw.get("port")) if row["alive"] else None   # J-10: a GONE row's port is text
    status_text = row["watch_status"] or row["status"]
    if status_text == "finished":
        row["word"] = "FINISHED"
    elif status_text == "crashed" or stale:
        row["word"] = "CRASHED"   # J-13: a crash or a stale heartbeat (C-4), for other watches' rows only
    else:
        row["word"] = row["watch_band"] or status_text or "-"
    return row


# --- the band (I-2, I-3) ---------------------------------------------------------------

def _open_window(state):
    windows = [w for w in _list(state.get("silence")) if isinstance(w, dict)]
    last = windows[-1] if windows else None
    if last is not None and last.get("closed") is None and last.get("epoch") == state.get("epoch"):
        return last
    return None


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _seconds(later, earlier):
    a, b = _when(later), _when(earlier)
    return (a - b).total_seconds() if a is not None and b is not None else None


def status(state):
    """(word, level, detail) of a watch's state (watch.json's shape), in the
    order of I-3: FINISHED (the watch ended), CAPTURE FAILED, SILENT for N s,
    AGENT GONE, WATCHING. The crash texts of C-4 are details."""
    if state.get("finished"):
        if state.get("status") == "crashed":
            return "FINISHED", "alarm", "CRASHED: %s" % state.get("error")
        return "FINISHED", "incomplete", "finished at %s" % state["finished"]
    quiet = _number(state.get("heartbeat_age_seconds"))   # J-5: an interval, by the monotonic clock
    if quiet is None:
        quiet = _seconds(state.get("updated"), state.get("heartbeat"))
    stale = state.get("stale_after_seconds")
    if quiet is not None and isinstance(stale, (int, float)) and quiet > stale:
        # J-13: CRASHED is a word for other watches' rows; this band keeps C-4's text in its detail.
        return "CAPTURE FAILED", "alarm", "CRASHED or stuck: no heartbeat for %d s (last at %s)" % (
            quiet, state.get("heartbeat"))
    capture = _dict(state.get("capture"))
    if capture.get("failed"):
        return "CAPTURE FAILED", "alarm", "%s; the next good line clears it" % capture["failed"]
    window = _open_window(state)
    if window is not None:
        silent = _number(state.get("quiet_seconds"))
        if silent is None:
            silent = _seconds(state.get("updated"), window.get("since")) or 0
        return "SILENT for %d s" % silent, "alarm", "no line read since %s (read time; %s; limit %g s)" % (
            window.get("since"), window.get("after"), state.get("gap_seconds") or 0)
    gone = _dict(state.get("agent_gone"))
    if gone:
        return "AGENT GONE", "incomplete", ("the newest record is a session_end and no session is open: session"
                                            " %s, line %s, seq %s; no line read since %s (read time), so no"
                                            " silence window opens until the next line"
                                            % (gone.get("session_id"), gone.get("line"), gone.get("seq"),
                                               gone.get("at")))
    detail = "%s lines in this trace content" % state.get("lines")
    recovered = _dict(capture.get("recovered"))
    if recovered:
        detail += "; capture recovered at seq %s (line %s, %s)" % (recovered.get("seq"), recovered.get("line"),
                                                                     recovered.get("at"))
    return "WATCHING", "clean", detail


def notifications(state):
    """(level, text) of the notifier in a watch's state: on or off (E2)."""
    n = _dict(state.get("notifications"))
    backend, reason = n.get("backend"), n.get("reason")
    failed = _int(_dict(n.get("counts")).get("failed"))
    if not n:
        return "alarm", "notifications: unknown (no notifier in the state)"
    if backend == "off":
        return "incomplete", "notifications: off (%s)" % reason
    if failed:
        return "alarm", "notifications: on, %d not delivered by %s (holes; bell and stderr instead)" % (
            failed, backend)
    if backend == "terminal":
        return "incomplete", "notifications: on, terminal bell and stderr only (%s)" % reason
    return "clean", "notifications: on (%s)" % backend


def band_items(state):
    """[(level, text)]: the state word first, then the notifier and the holes."""
    word, level, _ = status(state)
    items = [(level, word), notifications(state)]
    holes = len(_list(state.get("holes")))
    if holes:
        items.append(("alarm", "%d holes (see the alarms)" % holes))
    if state.get("state_error"):
        items.append(("alarm", "watch.json cannot be written: %s (a hole)" % state["state_error"]))
    hole = _dict(state.get("registry")).get("hole")
    if hole:
        items.append(("alarm", "registry: %s" % hole))   # J-4
    port = _dict(state.get("port"))
    if port.get("warning"):
        items.append(("incomplete", port["warning"]))
    return items


BAND_LEVELS = ("alarm", "incomplete", "clean")


def _badges(items):
    return " ".join('<span class="badge %s">%s</span>' % (level if level in BAND_LEVELS else "incomplete",
                                                           _text(text)) for level, text in items)


def _live_band(state, refresh):
    word, level, detail = status(state)
    items = band_items(state)
    last = _dict(state.get("last_line"))
    if last:   # J-12: the record's own ts, and the time watch read the line, each labelled
        when = "last line %s (seq %s): record ts %s, read at %s" % (
            last.get("line"), last.get("seq"), last.get("ts") or "- (not a record)", last.get("at"))
    else:
        when = "no line read yet (watching since %s)" % state.get("started")
    out = ['<div class="band">',
           '<p><span class="badge state %s">%s</span> %s</p>' % (
               level if level in BAND_LEVELS else "incomplete", _text(word), _badges(items[1:])),
           '<p class="detail">%s</p>' % _text(detail),
           '<p class="meta">trace <code>%s</code> &middot; %s%s</p>' % (
               _text(state.get("trace")), _text(when),
               " &middot; this page reloads every %d s" % refresh if refresh is not None else ""),
           "</div>"]
    return out


# --- the timeline -----------------------------------------------------------------------

def _timeline(numbered, problems, report, gap_seconds, windows=(), quiet=None):
    """Rows of the timeline: trace lines, corrupt lines and silence bands;
    windows: the live silence windows of this trace content (I-10)."""
    marks = {}
    for f in report["findings"]:
        for seq in f["cited_seq"]:
            marks.setdefault((f["session_id"], seq), set()).add(f["rule_id"])
    for s in report["suspicion"]:
        for seq in s["cited_seq"]:
            marks.setdefault((s["session_id"], seq), set()).add("suspicion")
    counts = {}
    for _, rec in numbered:
        if rec.get("phase") in ("pre", "post"):
            entry = counts.setdefault((rec["session_id"], rec["seq"]), [0, 0])
            entry[0 if rec["phase"] == "pre" else 1] += 1
    last_seen = {}
    last_line = {}
    started = set()
    rows = []
    items = [(number, "rec", rec) for number, rec in numbered]
    items += [(p["line"], "problem", p) for p in problems]
    for number, kind, item in sorted(items, key=lambda x: x[0]):
        if kind == "problem":
            rows.append(("band", number, "line %d is corrupt: %s" % (number, item["reason"])))
            continue
        rec = item
        sid = rec["session_id"]
        t = trace.parse_ts(rec.get("ts"))
        if t is not None and sid in last_seen:
            gap = (t - last_seen[sid]).total_seconds()
            if gap > gap_seconds:
                rows.append(("band", None, "session %s: no capture for %.1fs (limit %gs)"
                             % (sid, gap, gap_seconds)))
        if t is not None:
            last_seen[sid] = t
        if rec.get("phase") == "session_start":
            started.add(sid)
        tags = sorted(marks.get((sid, rec["seq"]), ()))
        pres, posts = counts.get((sid, rec["seq"]), (0, 0))
        if rec.get("phase") == "pre" and pres > posts:
            tags.append("no post")
        if rec.get("phase") == "post" and posts > pres:
            tags.append("no pre")
        rows.append(("rec", number, rec, tags))
        last_line[sid] = (len(rows), rec)
    for sid, (position, rec) in sorted(last_line.items(), key=lambda x: x[1][0], reverse=True):
        if sid in started and rec.get("phase") not in silence.CLOSING:
            rows.insert(position, ("band", None, "session %s: the trace ends at seq %s without stop or"
                                                 " session_end" % (sid, rec["seq"])))
    for w in windows:  # I-10: a closed window just before the line that closed it, the open one last
        closed_by = _int(w.get("closed_by_line"))
        if w.get("closed") is None:
            rows.append(("live", True, "live silence (raqib watch), open: no line read since %s (%s), %s s so"
                                       " far; limit %g s" % (w.get("since"), w.get("after"), _round(quiet),
                                                             gap_seconds)))
            continue
        text = "live silence (raqib watch), closed: no line from %s to %s (%s s; limit %g s) %s; closed by line %s" % (
            w.get("since"), w.get("closed"), w.get("seconds"), gap_seconds, w.get("after"), closed_by)
        at = next((i for i, row in enumerate(rows) if row[0] in ("rec", "band") and row[1] == closed_by), None)
        if at is None:
            rows.append(("live", False, text + " (that line is not in this view)"))
        else:
            rows.insert(at, ("live", False, text))
    return rows


def _round(value):
    return "?" if value is None else "%.1f" % value


# --- the page ---------------------------------------------------------------------------

def _cited(item):
    parts = []
    for cite in item["cites"]:
        for line in cite["lines"]:
            parts.append('<li><a href="#%s">line %d</a> <code>%s</code></li>'
                         % (_anchor(line["line"]), line["line"], _text(line["text"])))
        if not cite["lines"]:
            parts.append("<li>seq %d: <span class=\"tag\">no line in the trace</span></li>" % cite["seq"])
    return "<ul>%s</ul>" % "".join(parts)


def _finding_card(f):
    return ('<div class="card"><div class="head"><span class="tag">%s</span> %s (%s, %s) '
            '<span class="meta">session %s, seq %s</span></div><div>%s</div>%s</div>'
            % (_text(f["severity"]), _text(f["rule_id"]), _text(f.get("class", "-")),
               _text(f.get("kind") or "-"),
               _text(f["session_id"]), _text(", ".join(map(str, f["cited_seq"]))),
               _text(f["summary"]), _cited(f)))


def severity_groups(findings):
    """I-9: [(group, findings)] high > medium > low > other, empty groups left out."""
    groups = {}
    for f in findings:
        groups.setdefault(f["severity"] if f.get("severity") in SEVERITIES else OTHER, []).append(f)
    return [(name, groups[name]) for name in SEVERITIES + (OTHER,) if groups.get(name)]


def alarm_order(alarms):
    """I-9, J-8: the holes first, in HOLE_ORDER (A3); the rest as they came."""
    rank = {kind: i for i, kind in enumerate(HOLE_ORDER)}
    return sorted(alarms, key=lambda a: rank.get(a.get("kind"), len(HOLE_ORDER)))


def render(report, numbered, problems, gap_seconds=silence.DEFAULT_GAP_SECONDS, band=None, refresh=None,
           live=None, discover=None, now=None):
    """The whole page as a string.
    band: [(level, text)] badges under the result (level one of BAND_LEVELS,
    anything else is drawn as incomplete); None: no such badges.
    refresh: N for <meta http-equiv="refresh"> on a served page (I-1); None
    for a static file, which never reloads.
    live (raqib watch): {"state": the watch's state dict, "watches": what
    read_watches gave or None, "own": this watch's registry row or None}.
    discover: None looks for discover.json next to the trace and shows it
    as a section of this page; a route ("/discover") links the served tab
    when the file is there; False: no discover tab."""
    state = live["state"] if live else None
    out = _head("Raqib trace view", refresh)
    result = report["result"]
    out.append('<h1 id="top">Raqib trace view</h1>')
    out.append('<p class="meta">%s &middot; %d records &middot; %d sessions &middot; findings: %s</p>'
               % (_text(report["trace"]), report["records"], len(report["sessions"]),
                  _text(report["findings_source"])))
    out.append('<p><span class="badge %s">%s</span> <span class="meta">exit %d</span></p>'
               % (result, RESULT_TEXT[result], report["exit"]))
    inline = None
    nav = []
    if discover is not False:
        where = discover_path(report["trace"])
        if isinstance(discover, str):
            if os.path.lexists(where):
                nav.append('<a href="%s">discover</a>' % discover)
        else:
            inline = read_discover(where, now)
            if inline["exists"]:
                nav.append('<a href="#discover">discover</a>')
            else:
                inline = None
    if live:
        nav.append('<a href="#watches">watches</a>')
    if nav:
        out.append('<p class="nav">%s</p>' % "".join(['<a href="%s">trace</a>' % (
            "/" if isinstance(discover, str) else "#top")] + nav))
    if state is not None:
        out += _live_band(state, refresh)
    if band:
        out.append('<p class="band">%s</p>' % _badges(band))

    alarms = alarm_order(report["alarms"])
    out.append("<h2>Alarms (%d)</h2>" % len(alarms))
    if alarms:
        for a in alarms:
            where = ' <a href="#%s">line %d</a>' % (_anchor(a["line"]), a["line"]) if "line" in a else ""
            out.append('<div class="card"><span class="tag">%s</span>%s %s</div>'
                       % (_text(a["kind"]), where, _text(a["detail"])))
    else:
        out.append('<p class="empty">None.</p>')
    # J-13 (Q-16): a rule that did not run makes the result incomplete (A3), so it is in the alarms block.
    out.append("<h3>Rules that did not run (%d)</h3>" % len(report["notes"]))
    if report["notes"]:
        out.append("<ul>%s</ul>" % "".join(
            "<li><code>%s</code> %s: %s</li>" % (_text(n["rule_id"]), _text(n["status"]), _text(n["detail"]))
            for n in report["notes"]))
    else:
        out.append('<p class="empty">Every rule ran on every line.</p>')

    out.append("<h2>Findings (%d)</h2>" % len(report["findings"]))
    if report["findings"]:
        for name, group in severity_groups(report["findings"]):
            out.append("<h3>%s (%d)</h3>" % (name, len(group)))
            if name == OTHER:
                out.append('<p class="meta">A severity that is not high, medium or low: shown here, last, and'
                           " never dropped (I-9).</p>")
            out += [_finding_card(f) for f in group]
    else:
        out.append('<p class="empty">None.</p>')

    windows = []
    if state is not None:
        windows = [w for w in _list(state.get("silence")) if isinstance(w, dict)
                   and w.get("epoch") == state.get("epoch")]
    out.append("<h2>Timeline (%d lines)</h2>" % (len(numbered) + len(problems)))
    out.append('<p class="meta">Red bands are silence: no capture for longer than %gs, a session that '
               'never closed, or a corrupt line. Highlighted rows are cited by a finding.%s</p>' % (
                   gap_seconds, " Live silence windows of raqib watch are drawn too: the closed ones lighter,"
                                " the open one marked OPEN." if state is not None else ""))
    out.append('<div class="scroll"><table><thead><tr><th>line</th><th>ts</th><th>session</th><th>seq</th>'
               "<th>phase</th><th>tool</th><th>input_meta</th><th>output_meta</th><th>ok</th>"
               "<th>marks</th></tr></thead><tbody>")
    record_lines = {number for number, _ in numbered}
    used = set()
    for row in _timeline(numbered, problems, report, gap_seconds, windows,
                         _number(state.get("quiet_seconds")) if state is not None else None):
        if row[0] == "live":
            out.append('<tr class="band live%s"><td colspan="10">%s%s</td></tr>' % (
                " open" if row[1] else "", '<span class="tag">OPEN</span> ' if row[1] else "", _text(row[2])))
            continue
        if row[0] == "band":
            # A line that is both a record and a problem keeps its anchor on
            # the record row; ids stay unique.
            free = row[1] is not None and row[1] not in record_lines and row[1] not in used
            anchor = ' id="%s"' % _anchor(row[1]) if free else ""
            if free:
                used.add(row[1])
            out.append('<tr class="band"%s><td colspan="10">%s</td></tr>' % (anchor, _text(row[2])))
            continue
        _, number, rec, tags = row
        ok = rec.get("ok")
        ok_text = "" if ok is None else ("true" if ok else "false " + str(rec.get("error_class", "")))
        out.append('<tr id="%s"%s><td>%d</td><td class="nowrap">%s</td><td class="wrap">%s</td><td>%s</td><td>%s</td>'
                   '<td>%s</td><td class="wrap">%s</td><td class="wrap">%s</td><td>%s</td><td>%s</td></tr>'
                   % (_anchor(number), ' class="flag"' if tags else "", number, _text(rec.get("ts", "-")),
                      _text(rec["session_id"]), _text(rec["seq"]), _text(rec.get("phase", "?")),
                      _text(rec.get("tool", "?")), _text(rec["input_meta"]) if rec.get("input_meta") else "",
                      _text(rec["output_meta"]) if rec.get("output_meta") else "", _text(ok_text),
                      "".join('<span class="tag">%s</span>' % _text(t) for t in tags)))
    out.append("</tbody></table></div>")

    if live:
        out += _watches_section(state, live.get("own"), live.get("watches"))

    out.append("<h2>Suspicion (%d)</h2>" % len(report["suspicion"]))
    run = report.get("suspicion_run")
    if not report.get("suspicion_given"):
        out.append('<p class="meta">No model was run for this report.</p>')
    elif run:
        out.append('<p class="meta">%d windows judged by %s/%s: %d raised, %d errors, %d below threshold %s'
                   ' (below threshold is not a clearance)%s.</p>'
                   % (run["windows"], _text(run["backend"]), _text(run["model"]), run["raised"],
                      run["errors"], run["below_threshold"], _text("%g" % run["threshold"]),
                      "; %d answered by another model" % run["answered_by_other_model"]
                      if run.get("answered_by_other_model") else ""))
    else:
        out.append('<p class="meta">The model run cannot be accounted for: see the alarms.</p>')
    out.append('<p class="meta">A model can raise suspicion; it can never clear anything (A2).</p>')
    for s in report["suspicion"]:
        out.append('<div class="card"><div class="head"><span class="tag">%s</span> %s/%s '
                   '<span class="meta">session %s, window seq %s to %s</span></div><ul>%s</ul>%s</div>'
                   % (_text("%.2f" % s["suspicion"]), _text(s.get("backend")), _text(s.get("model")),
                      _text(s["session_id"]), _text(s["window"][0]), _text(s["window"][1]),
                      "".join("<li>%s</li>" % _text(r) for r in s["reasons"]), _cited(s)))

    out.append("<h2>Rules (%d)</h2>" % len(report["rules"]))
    out.append('<div class="scroll"><table><thead><tr><th>id</th><th>class</th><th>kind</th><th>severity</th>'
               "<th>fp_budget</th><th>status</th><th>title</th></tr></thead><tbody>")
    for r in report["rules"]:
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                   "<td class=\"wrap\">%s</td></tr>"
                   % (_text(r["id"]), _text(r["class"]), _text(r.get("kind") or "-"), _text(r["severity"]),
                      "-" if r["fp_budget"] is None else _text("%g" % r["fp_budget"]),
                      _text(r["status"]), _text(r["title"])))
    out.append("</tbody></table></div>")
    if inline is not None:
        out += _discover_body(inline, '<h2 id="discover">Discover</h2>')
    out.append('<p class="meta">Raqib: deterministic rules first; a model may raise suspicion, never acquit. '
               "This page is read-only and runs no script.</p>")
    out.append("</main></body></html>")
    return "\n".join(out) + "\n"


def _watches_section(state, own, info):
    """I-4..I-7: this watch from memory, then the registry's other rows."""
    rows = []
    if state is not None:
        word = status(state)[0]
        url = port_url(_dict(state.get("port")).get("used"))
        rows.append("<tr><td>this watch (from memory)</td><td>%s</td><td class=\"wrap\">%s</td>"
                    "<td class=\"wrap\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        _text(word), _text(state.get("project")), _text(state.get("trace")),
                        _text(state.get("pid")), '<a href="%s">%s</a>' % (url, url) if url else "-",
                        _text(state.get("started")), "ALIVE (this process)"))
    info = info or {"path": None, "rows": [], "holes": []}
    for r in info["rows"]:
        if r["link"]:
            link = '<a href="%s">%s</a>' % (r["link"], r["link"])
        elif port_url(r.get("port")):   # J-10: a GONE row's port is text, not a link
            link = "port %s (not linked: GONE)" % _text(r.get("port"))
        else:
            link = '<span class="tag">no link</span> port %s is not a whole number from 1 to %d' % (
                _text(r.get("port")), PORT_MAX)
        alive = "ALIVE" if r["alive"] else '<span class="tag">GONE</span> %s' % _text(r["why"])
        notes = "".join("; note: %s" % _text(n) for n in r["notes"])
        rows.append("<tr><td>registry row</td><td>%s</td><td class=\"wrap\">%s</td><td class=\"wrap\">%s</td>"
                    "<td>%s</td><td>%s</td><td>%s</td><td class=\"wrap\">%s%s</td></tr>" % (
                        _text(r.get("word")), _text(r.get("project")),
                        _text(r.get("trace")), _text(r.get("pid")), link, _text(r.get("started")), alive, notes))
    out = ['<h2 id="watches">Watches (%d)</h2>' % len(rows)]
    if info.get("path"):
        out.append('<p class="meta">Other watches are read from <code>%s</code>; %s. A row is ALIVE only when its'
                   " pid is alive and the heartbeat in its own &lt;trace&gt;.watch.json (a local path only) is"
                   " younger than max(%g s, 3 x its step_seconds), at most %g s; else GONE, with the reason. GONE"
                   " rows are never removed by Raqib (A3); delete the file to clear them. %s.</p>" % (
                       _text(info["path"]), FORGEABLE, info.get("fresh_seconds") or 0, FRESH_CAP, PID_REUSE))
    if info.get("more"):
        out.append('<p class="meta">%d older rows of the registry are not shown (at most %d are, J-7).</p>' % (
            info["more"], ROWS_MAX))
    for hole in info["holes"]:
        out.append('<div class="card"><span class="tag">registry hole</span> %s</div>' % _text(hole))
    if own and own.get("hole"):
        out.append('<div class="card"><span class="tag">registry hole</span> %s</div>' % _text(own["hole"]))
    out.append('<div class="scroll"><table><thead><tr><th>row</th><th>state</th><th>project</th><th>trace</th>'
               "<th>pid</th><th>page</th><th>started</th><th>liveness</th></tr></thead><tbody>")
    out += rows
    out.append("</tbody></table></div>")
    return out


# --- discover (I-8) ---------------------------------------------------------------------

def _cites_text(cites):
    return " ".join("%s:%s" % (_text(_dict(c).get("src")), _text(_dict(c).get("line"))) for c in _list(cites))


def _discover_body(info, heading):
    """The discover view: candidates, holes and cited lines of an inventory."""
    out = [heading]
    age = info.get("age")
    out.append('<p class="meta"><code>%s</code> &middot; written at %s, %s s ago &middot; a snapshot of'
               " <code>raqib discover --json</code>, not live</p>" % (
                   _text(info["path"]), _text(info.get("written") or "-"), _round(age)))
    if not info["exists"]:
        out.append('<p class="empty">No inventory: there is no %s next to the trace. <code>raqib discover --json'
                   ' -o %s</code> writes one.</p>' % (DISCOVER_NAME, _text(info["path"])))
        return out
    if info["error"]:
        out.append('<div class="card"><span class="badge alarm">ALARM</span> the inventory %s %s; it cannot be'
                   " shown (A3)</div>" % (_text(info["path"]), _text(info["error"])))
        return out
    inv = info["data"]
    result = inv.get("result")
    out.append('<p><span class="badge %s">%s</span> <span class="meta">exit %s</span></p>' % (
        {"alarm": "alarm", "none-seen": "clean"}.get(result, "incomplete") if isinstance(result, str) else
        "incomplete", _text(str(result).upper() if isinstance(result, str) else result), _text(inv.get("exit"))))
    for title, key in (("Alarms", "alarms"), ("Incomplete", "incomplete")):
        values = _list(inv.get(key))
        if values:
            out.append("<h3>%s (%d)</h3><ul>%s</ul>" % (title, len(values),
                                                        "".join("<li>%s</li>" % _text(v) for v in values)))
    lines = {}

    def cites(value):
        for c in _list(value):
            c = _dict(c)
            line = _int(c.get("line"))
            lines[(str(c.get("src")), line if line is not None else -1, json.dumps(c.get("line"), sort_keys=True))] = c
        return _cites_text(value)

    candidates = inv["candidates"]
    out.append("<h3>Candidates (%d)</h3>" % len(candidates))
    if not candidates:
        out.append('<p class="empty">No agent seen in this inventory; not a clearance.</p>')
    for c in candidates:
        c = _dict(c)
        seen, source = _dict(c.get("seen")), _dict(c.get("source"))
        parts = ['<div class="card"><div class="head"><span class="tag">%s</span> pid %s %s <span class="meta">%s%s'
                 "</span></div>" % (_text(c.get("id")), _text(c.get("pid")), _text(c.get("image") or "?"),
                                    _text(c.get("exe") or "-"),
                                    " (inside %s)" % _text(c.get("inside")) if c.get("inside") else ""),
                 "<div>cwd %s; seen %s .. %s (%s) %s</div>" % (
                     _text(c.get("cwd") or "-"), _text(seen.get("first") or "-"), _text(seen.get("last") or "-"),
                     _text(seen.get("basis")), cites(c.get("cites"))),
                 "<div>suggested source: %s - %s %s</div>" % (_text(source.get("suggested")), _text(source.get("why")),
                                                             cites(source.get("cites"))),
                 "<ul>"]
        for t in _list(c.get("talks")):
            t = _dict(t)
            eps = "; ".join("%s %s%s" % (_text(_dict(m).get("vendor")), _text(_dict(m).get("match")),
                                         " (%s)" % _text(_dict(m).get("name")) if _dict(m).get("name") else "")
                            for m in _list(t.get("endpoint"))) or "no catalog match"
            parts.append("<li>talks %s %s x%s [%s] %s</li>" % (_text(t.get("remote")), _text(t.get("state")),
                                                               _text(t.get("lines")), eps, cites(t.get("cites"))))
        acts = _list(c.get("acts"))
        for a in acts[:DISCOVER_ACTS_SHOWN]:
            a = _dict(a)
            what = ("wrote %s" % _text(a.get("path")) if a.get("how") == "file-write" else "%s%s%s" % (
                _text(a.get("image") or "?"),
                " via pid %s" % _text(",".join(str(v) for v in _list(a.get("via"))) or a.get("via"))
                if a.get("via") else " (child)",
                " [listed]" if a.get("listed") else " [unlisted]"))
            parts.append("<li>acts: pid %s %s %s</li>" % (_text(a.get("pid")), what, cites(a.get("cites"))))
        if len(acts) > DISCOVER_ACTS_SHOWN:
            parts.append("<li>... %d more acts (all in the JSON)</li>" % (len(acts) - DISCOVER_ACTS_SHOWN))
        for t in _list(c.get("talking_ancestors")):
            t = _dict(t)
            parts.append("<li>talking ancestor: pid %s %s %s</li>" % (_text(t.get("pid")), _text(t.get("image") or "?"),
                                                                       cites(t.get("cites"))))
        for e in _list(c.get("env_footprints")):
            e = _dict(e)
            parts.append("<li>env footprint: %s %s</li>" % (_text(e.get("name")), cites(e.get("cites"))))
        parts.append("</ul></div>")
        out.append("".join(parts))
    holes = inv["holes"]
    out.append("<h3>Holes (A3) (%d)</h3>" % len(holes))
    out.append("<ul>%s</ul>" % "".join("<li>%s</li>" % _text(h) for h in holes) if holes else
               '<p class="empty">None.</p>')
    problems = _list(inv.get("problems"))
    if problems:
        out.append("<h3>Unread lines (%d)</h3><ul>%s</ul>" % (len(problems), "".join(
            "<li>%s:%s %s</li>" % (_text(_dict(p).get("src")), _text(_dict(p).get("line")),
                                   _text(_dict(p).get("reason"))) for p in problems)))
    dark = _list(inv.get("agent_dark"))
    if dark:
        out.append("<h3>AGENT-DARK (%d)</h3><ul>%s</ul>" % (len(dark), "".join(
            "<li>%s %s</li>" % (_text(_dict(d).get("summary")), cites(_dict(d).get("cites"))) for d in dark)))
    out.append("<h3>Cited lines (A5) (%d)</h3>" % len(lines))
    if lines:
        out.append('<div class="scroll"><table><thead><tr><th>source</th><th>line</th><th>text</th></tr></thead>'
                   "<tbody>%s</tbody></table></div>" % "".join(
                       '<tr><td>%s</td><td>%s</td><td class="wrap">%s</td></tr>' % (
                           _text(c.get("src")), _text(c.get("line")), _text(c.get("text")))
                       for _, c in sorted(lines.items())))
    return out


def discover_page(path, refresh=None, now=None):
    """GET /discover on watch's server (I-8): the same head, CSP and refresh."""
    out = _head("Raqib discover", refresh)
    out.append("<h1>Raqib discover</h1>")
    out.append('<p class="nav"><a href="/">trace</a><a href="%s">discover</a></p>' % DISCOVER_ROUTE)
    out += _discover_body(read_discover(path, now), "<h2>Inventory</h2>")
    out.append('<p class="meta">This page is read-only and runs no script.</p>')
    out.append("</main></body></html>")
    return "\n".join(out) + "\n"


# --- the server -------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    page = None    # a callable returning the page text
    routes = None  # {path: callable} served beside /
    refresh = None
    port = None

    def _local_host(self):
        host = self.headers.get("Host", "")
        return host in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port)

    timeout = 10  # an idle connection cannot hold the view

    def _send(self, body_wanted):
        if not self._local_host():
            self.send_error(403, "Host must be 127.0.0.1 or localhost")
            return
        if self.path in ("/", "/index.html"):
            build = self.page
        elif self.routes and self.path in self.routes:
            build = self.routes[self.path]
        else:
            self.send_error(404)
            return
        status = 200
        try:
            text = build()
        except Exception as exc:
            # The trace or catalog became unreadable: say so, never a blank page (A3).
            status, text = 500, error_page("%s: %s" % (type(exc).__name__, exc), self.refresh)
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body_wanted:
            self.wfile.write(body)

    def do_GET(self):
        self._send(True)

    def do_HEAD(self):
        self._send(False)

    def _refuse(self):
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse

    def log_message(self, format, *args):
        pass


def error_page(message, refresh=None):
    """A page that says the view could not be built, as an alarm; a served
    one keeps reloading, so it goes when the cause does."""
    return "\n".join(_head("Raqib trace view", refresh) + [
        "<h1>Raqib trace view</h1>",
        '<p><span class="badge alarm">ALARM</span> the view could not be built (A3)</p>',
        '<div class="card">%s</div>' % _text(message), "</main></body></html>"]) + "\n"


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def make_server(page, port=0, routes=None, refresh=None):
    """An HTTP server on 127.0.0.1 that serves page() at / and each of
    routes ({path: callable}) at its path (port 0: any free port). One
    thread per connection, each with a timeout. refresh: the error page's
    reload (I-1)."""
    handler = type("Handler", (_Handler,), {"page": staticmethod(page), "routes": dict(routes or {}),
                                            "refresh": refresh})
    server = _Server(("127.0.0.1", port), handler)
    handler.port = server.server_address[1]
    return server
