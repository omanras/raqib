"""raqib app (M6.4, ADR-0006; M7.3, ADR-0007 decision 5): Raqib as an
ordinary desktop program window that starts from the host.

`raqib app [PROJECT]` (or the `raqib-app` gui-script, which on Windows runs
under pythonw with no console) opens one tkinter window, standard library
only:
- first screen, the HOST (M7.3): one discover round at open - the reader
  of `raqib watch --host` (host.live_reader, read-only) in a thread
  (HostProbe), with the watch's deadline 2 x T; the band says "reading the
  host..." and a reader not back by then is READER LATE, a hole. Then the
  trees found (image, pid, named / unknown / benign, first seen, acts,
  endpoints; never a command line), or "no agent seen (N records, M holes).
  Not a clearance."; a round that read nothing is NOTHING READ. The doctor
  lines fold under "Checks" (M8.1: it opens only on a click). "Watch this host"
  runs the HostWatch of `raqib watch --host` (HostSession: host.start,
  host.loop with Stop, host.conclude, host.close; a round every --every T
  seconds) in a worker: its table, its NEW-AGENT / AGENT-DARK-LIVE lines,
  and its knocks through its own Notifier (each tree under its own
  rate-limit id, ADR-0007 C-5); the band reads WATCHING HOST, READER LATE,
  HOST READER FAILED or NOTHING READ; Stop shows its final report (exit
  0 / 1 / 3, C-10). A second host watch on this home is refused by
  HostWatch (C-2, D-6): the refusal is a hole line, not a crash (exit 2,
  F-8). Nothing of the host round or watch writes outside ~/.raqib (A4).
  M7.3 REDO (ADR-0007 Amendment F): the look's level follows C-10's codes
  from its own sources, never discover's word (F-1, F-7); its holes and its
  AGENT-DARK lines are listed; it is written to ~/.raqib/host/look.json
  (F-10) and its holes stand in the footer and the log until the watch's
  first round, whose reader waits for the look's (F-3). A header with
  "Host" and "Project" reaches both screens while their watches run (F-2);
  the host screen has its Log pane and Open page (F-6, F-11).
- "Watch a project" opens the project screen of M6.4, unchanged: what
  `raqib doctor` says for the project (OK / MISSING /
  UNSURE, run in a thread so the window never waits on `claude --version`),
  a project field with Browse, Check again and Start; PROJECT on the
  command line is preselected there. The host and a project may be watched
  at once (two sessions, read by the same tick);
- watching screen: the band (the state word of ui.status, the notifier, the
  holes), the findings by severity, the holes, the page URL, Stop;
- after the watch: the final report of watch.finish(), and Back.

Start runs the same watch as `raqib watch` - watch.start(), watch.loop(),
watch.conclude(), watch.close(): the hooks, the trace, <trace>.watch.json,
the registry row and the read-only page on 127.0.0.1 - in a worker thread.
Stop is that loop's Stop, the equivalent of Ctrl-C. The window reads the
watch's state under the Watch lock from after(), never from the page; the
heartbeat's age is recomputed at every tick from the wall clock, so a watch
stuck under its lock reads "CRASHED or stuck (N s)" (ADR-0006 A-2). It
sends nothing to the agent (A4): Start and Stop control Raqib's own
watching. The programs that run are those of `raqib doctor` - `claude
--version`, at open, on Browse and on Check again - and nothing else here
(A-11), besides the host's reader, which is `raqib watch --host`'s (the OS
API through ctypes on Windows, /proc on Linux and `ss` by absolute path
only when /proc/net/tcp cannot be read, M5.0 B-1); the watch it starts runs
the notifier as `raqib watch` does, and
the "Open page" button runs the same opener as `raqib watch` (watch.open_page,
never under CI), only when the person clicks it (A-13). The page is not
opened by itself; its URL is shown.

The knock (E3): the first live, settled finding of a watch, whatever its
severity, knocks once through the watch's Notifier under its own rate-limit
id (notify.FirstFinding, run by watch.first_step); a high first finding has
knocked as its rule already, and that knock is the first one ("by the
rule", A-5). The watching screen shows "first finding: <rule> <severity>
(<status>)", and a Log pane shows the watch's own lines at any time.

Holes (A3): a tray that fails, a knock that fails, a worker that crashes, a
state the window cannot read - each is a line under "holes" in the window,
never swallowed and never a crash of the window. On Windows the tray icon
(raqib/tray.py) has Show / Stop / Quit and closing the window while
watching hides it there; elsewhere there is no tray (recorded as a note)
and closing the window while watching stops the watch, leaving the final
report on screen; closing it again quits.

Without tkinter, or on X11 without DISPLAY, `raqib app` exits 2 with one
sentence (AppError). Under the `raqib-app` gui-script (gui_main) the watch's
lines and the final report go to ~/.raqib/app.log (truncated at start,
bounded), and a failure before the window is up is one message box on
Windows (tray.message_box) and a line on stderr elsewhere (A-4). Quit waits
JOIN_SECONDS for the final report; a watch that does not end by then brings
the window back with a hole, and nothing is killed (A-3). The logic - the views, the Session over a watch, the
Controller that decides what a close or a tray action does - is plain
Python, tested with fakes; only Window touches Tk, and tkinter is imported
only when the window is made.

The look (M8.1, ADR-0009 decisions 1-3; after M7.6b, ADR-0008 decision 6) is
presentation only, over the same Controller, Session, HostSession and
RulesPanel: one THEME table (ADR-0009's tokens, light and dark - dark when
Windows says so in AppsUseLightTheme, read-only - the levels by the exit-code
scheme, the font families, the four sizes, every pixel size before scaled()),
a word beside every colour; a navigation rail (the name, what is watched,
Host / Project / Rules / Log, the rules off, Open page, the doctrine); on each
screen a verdict header (one sentence, the level's pill, one primary action),
the round strip under the host's verdict, the status pills, the disclosures
("could not see (N)" with every hole, the checks as rows, the watch options,
what the overlay applies; closed until clicked) and cards; the Rules screen a
list of rules with switches and steppers; the Log screen. The controls are
drawn by the window (pictures from THEME's colours as ttk elements). On
Windows only, before Tk starts, the process declares itself DPI-aware, and
in dark mode its own title bar is made dark (ctypes, two calls, A4); a
failure of either is a line in the log. Every screen fits 900x600.
"""
from __future__ import annotations

import copy
import gc
import importlib
import os
import queue
import sys
import threading
import time
import traceback

from raqib import host as hostmod, notify, overlay, ruleform, tray as traymod, ui, watch

TITLE = "Raqib"
TICK_MS = 500                 # how often the window reads the state (after())
LOCK_SECONDS = 0.2            # how long one read waits for the Watch lock before it shows the last state
JOIN_SECONDS = 30.0           # how long Quit waits for the worker's final report
LOG_MAX = 1000000             # characters of the watch's own lines kept for the window
APP_LOG = "app.log"           # A-4: under ~/.raqib, the gui-script's output
APP_LOG_MAX = 4000000         # bytes of app.log; beyond, one line says the rest is not written
LOG_VIEW_MAX = 200000        # characters of the log the Log pane shows (A-5)
ERR_MAX = 64000               # characters of stderr kept to show in the message (A-4)
VERDICT_COLORS = {"OK": "clean", "MISSING": "alarm", "UNSURE": "incomplete"}
NO_TK = ("tkinter cannot be imported in this Python (%s): install python3-tk (Debian and Ubuntu: sudo apt install"
         " python3-tk) or use a python.org Python, which ships it; `raqib watch` works without it")
NO_DISPLAY = ("DISPLAY is not set: no window can open in this session (Tk on %s needs an X display; under Wayland"
              " XWayland sets DISPLAY)")

# --- the look (M8.1, ADR-0009 decisions 1-3) ------------------------------------------------------------
# THEME is the only place a colour lives in this file (a test reads the AST): ADR-0009's tokens (ground, card,
# ink, muted, the rail, the one accent blue) for light and dark, the exit-code scheme of ADR-0007 F-7 / C-10
# for the levels (0 green, 1 red, 3 amber; notes grey, holes amber, the suppressed badge red, ADR-0008 A-2)
# with a pill ground per level, the font families tried in order (named system fonts, nothing shipped), the
# four type sizes, and every pixel size before scaling (scaled() is the one scale function, E6). "pairs" are
# the text / ground pairs the window draws; each has a contrast of at least 4.5:1 (a test holds it). The
# drawn controls (cards, buttons, fields, pills, the switch, the disclosure's chevron, the round strip) are
# painted from these colours; their anti-aliased edges are the only mixed colours, blends of two of them.
THEME = {
    "light": {
        "ground": "#F4F6FA", "card": "#FFFFFF", "ink": "#18212F", "muted": "#566179", "head": "#F7F8FB",
        "line": "#E1E6EE", "field": "#FFFFFF", "field_line": "#AEB7C7", "hover": "#EDF1F7", "chip": "#E9EDF4",
        "accent": "#2B59D9", "accent_hover": "#2149B8", "on_accent": "#FFFFFF", "select": "#E1E9FC",
        "track_off": "#8F99AB", "knob": "#FFFFFF", "thumb": "#C3CAD6", "thumb_hover": "#98A2B3",
        "rail": "#141C2B", "rail_ink": "#E7EBF3", "rail_muted": "#9AA6BA", "rail_on": "#26324D",
        "rail_hover": "#1C2638", "rail_accent": "#7AA2FF",
        "levels": {"clean": "#1B6E35", "alarm": "#B00020", "incomplete": "#9A5000", "note": "#566179",
                   "hole": "#9A5000", "suppressed": "#B00020"},
        "pill": {"clean": "#E3F2E7", "alarm": "#FBE6E9", "incomplete": "#FCEFD9", "note": "#E9EDF4",
                 "hole": "#FCEFD9", "suppressed": "#FBE6E9"},
        "rail_levels": {"clean": "#63C784", "alarm": "#FF7A87", "incomplete": "#EFA654", "note": "#9AA6BA",
                        "hole": "#EFA654", "suppressed": "#FF7A87"},
    },
    "dark": {
        "ground": "#111620", "card": "#1A2130", "ink": "#E7EBF3", "muted": "#9AA6BA", "head": "#1F2738",
        "line": "#283247", "field": "#141B28", "field_line": "#56637C", "hover": "#232D41", "chip": "#253046",
        "accent": "#7AA2FF", "accent_hover": "#9DBBFF", "on_accent": "#0E1420", "select": "#1E2D50",
        "track_off": "#5E6B83", "knob": "#E7EBF3", "thumb": "#3A465E", "thumb_hover": "#56637C",
        "rail": "#141C2B", "rail_ink": "#E7EBF3", "rail_muted": "#9AA6BA", "rail_on": "#26324D",
        "rail_hover": "#1C2638", "rail_accent": "#7AA2FF",
        "levels": {"clean": "#63C784", "alarm": "#FF6B7A", "incomplete": "#EFA654", "note": "#9AA6BA",
                   "hole": "#EFA654", "suppressed": "#FF6B7A"},
        "pill": {"clean": "#173527", "alarm": "#3D1A22", "incomplete": "#3A2A14", "note": "#253046",
                 "hole": "#3A2A14", "suppressed": "#3D1A22"},
        "rail_levels": {"clean": "#63C784", "alarm": "#FF7A87", "incomplete": "#EFA654", "note": "#9AA6BA",
                        "hole": "#EFA654", "suppressed": "#FF7A87"},
    },
    # (text, ground): every pair the window draws text in. "levels" is each level's colour; on "pill" it is
    # read on its own level's pill ground; "rail_levels" on the rail.
    "pairs": (("ink", "ground"), ("ink", "card"), ("ink", "head"), ("ink", "hover"), ("ink", "chip"),
              ("ink", "select"), ("ink", "field"), ("muted", "ground"), ("muted", "card"), ("muted", "head"),
              ("muted", "chip"), ("muted", "hover"), ("on_accent", "accent"), ("on_accent", "accent_hover"),
              ("accent", "card"), ("accent", "ground"), ("rail_ink", "rail"), ("rail_ink", "rail_on"),
              ("rail_ink", "rail_hover"), ("rail_muted", "rail"), ("rail_muted", "rail_hover"),
              ("rail_accent", "rail"), ("levels", "ground"), ("levels", "card"), ("levels", "select"),
              ("levels", "head"), ("levels", "hover"), ("levels", "pill"), ("rail_levels", "rail"),
              ("rail_levels", "rail_hover"), ("muted", "line"), ("accent", "hover"), ("accent", "chip"),
              ("muted", "field")),
    "fonts": {
        "ui": ("Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", "Inter", "Noto Sans", "DejaVu Sans"),
        "display": ("Segoe UI Variable Display", "Segoe UI Variable", "Segoe UI", "Inter Display", "Inter",
                    "Noto Sans", "DejaVu Sans"),
        "mono": ("Cascadia Mono", "Consolas", "DejaVu Sans Mono"),
        "verdict": 15, "title": 11, "body": 10, "meta": 9,   # the four sizes, in points (Tk scales points itself)
    },
    # every pixel size, before scaled(): the rail, the outer padding, the gap between cards, the card's own
    # padding and corner, the buttons, a table row's padding, a strip cell, the switch, a scrollbar
    "px": {"rail": 184, "pad": 20, "gap": 12, "card_pad": 12, "card_radius": 10, "radius": 6, "row_pad": 7,
           "cell": 10, "cell_gap": 4, "switch": (34, 18), "scroll": 10, "chevron": 12, "wrap": 420, "list_h": 180, "form_h": 196,
           "focus": 2},
    "min_size": (900, 600), "size": (1100, 720),
}
LEVEL_WORDS = {"clean": "clean", "alarm": "alarm", "incomplete": "incomplete", "note": "note",
               "hole": "hole", "suppressed": "suppressed"}   # E1: a word beside every colour (C-10's result words)
DOCTRINE = "Rules decide; a model may only raise suspicion."
FIRST_RUN = (
    "This window shows what Raqib sees on this machine: the agents found on the host, a project's watch,"
    " the rules it judges with, and its log.",
    "Raqib reads (processes, connections, trace files) and never touches an agent: it sends it nothing,"
    " steers nothing, stops nothing.",
    "\"No agent seen\" is never a clearance: it says what was read, and what was not read is a hole.")
PERSONALIZE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"


RESULT_WORDS = (("CLEAN", "clean"), ("ALARM", "alarm"), ("INCOMPLETE", "incomplete"))


def level_of(code, word=None):
    """REDO C-1: THE function every band, badge, row and text level comes
    from. code: an exit code (C-10: 0 clean, 1 alarm, 3 incomplete; any
    other code alarm) or a level name as given (an unknown name reads
    incomplete, as the band always did); word: a result word ("CLEAN (N
    findings suppressed by the overlay)", "ALARM", "INCOMPLETE"), read when
    no exit code is given."""
    if isinstance(code, int) and not isinstance(code, bool):
        return CODE_LEVELS.get(code, "alarm")
    if word is not None:
        text = str(word).strip().upper()
        return next((lv for w, lv in RESULT_WORDS if text.startswith(w)), "incomplete")
    return code if code in LEVEL_WORDS else "incomplete"


def verdict_note(level, suppressed=0, result=False, detail=""):
    """M8.1 E2, REDO C-3: what stands beside the verdict's pill (the pill
    says the level's word): in a watch's green state
    "Not a clearance.", after the suppressed count when there is one ("2
    findings suppressed by the overlay. Not a clearance."); "" otherwise, and
    "" when the detail says "Not a clearance." already and nothing was
    suppressed."""
    if not (result and level_of(level) == "clean"):
        return ""
    if suppressed:
        return "%d findings suppressed by the overlay. %s" % (suppressed, NOT_CLEARANCE)
    return "" if NOT_CLEARANCE in str(detail) else NOT_CLEARANCE


def report_result(text):
    """REDO C-1, C-3: (result word, suppressed count) of a final report's
    "RESULT: <WORD> (exit N)" line: ("CLEAN", 2) for "RESULT: CLEAN (2
    findings suppressed by the overlay) (exit 0)"; (None, 0) without one."""
    for line in str(text or "").splitlines():
        if line.startswith("RESULT: "):
            word = line[len("RESULT: "):]
            n = word.split(" findings suppressed by the overlay", 1)[0].rsplit("(", 1)
            count = int(n[1]) if len(n) == 2 and n[1].isdigit() and "suppressed by the overlay" in word else 0
            return word.split(" ", 1)[0], count
    return None, 0


def report_level(code, text=None):
    """REDO C-1: a finished watch's level from its exit code, else from its
    report's result word; both through level_of."""
    if isinstance(code, int) and not isinstance(code, bool):
        return level_of(code)
    word, _ = report_result(text)
    return level_of(None, word=word) if word else "incomplete"


def badge_items(badges):
    """REDO C-2, M8.1 E4: the (level, text) badges of ui.band_items /
    host_band as pills: (word, text, level), each with its own level
    (through level_of) and that level's word; the overlay's badge is
    "suppressed" (red) while it counts suppressed findings."""
    out = []
    for level, text in badges:
        level = level_of(level)
        if level == "alarm" and "suppressed by the overlay" in str(text):
            level = "suppressed"
        out.append((level_word(level), _safe(text), level))
    return out


def flow_rows(widths, width, gap=0):
    """M8.1: items of the given pixel widths laid in rows of at most
    `width` (an item wider than that has a row of its own): [[index]]."""
    rows, line, used = [], [], 0
    for i, w in enumerate(widths):
        if line and used + gap + w > width:
            rows.append(line)
            line, used = [], 0
        used += w + (gap if line else 0)
        line.append(i)
    return rows + ([line] if line else [])


def level_word(code):
    """E1: the word shown beside a level's colour (never colour alone)."""
    return LEVEL_WORDS[level_of(code)]


def os_mode(platform=None, read=None):
    """E1: "dark" or "light" as the OS says where it can be read: on
    Windows the registry value AppsUseLightTheme (HKCU, read-only, stdlib
    winreg; 0 is dark); anything else, or a value that cannot be read, is
    light. read: tests give the value's reader."""
    platform = platform or sys.platform
    if platform != "win32" and read is None:
        return "light"
    try:
        value = (read or _apps_use_light_theme)()
    except Exception:   # no key, no winreg: light, as everywhere else
        return "light"
    return "dark" if value == 0 else "light"


def _apps_use_light_theme():
    import winreg   # Windows only, stdlib; opened for reading, never written
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSONALIZE_KEY, 0, winreg.KEY_READ) as key:
        return winreg.QueryValueEx(key, "AppsUseLightTheme")[0]


def pick_font(candidates, available):
    """The first family of candidates the system has (case-insensitive), or
    None (Tk's own default font then stays)."""
    have = {str(f).lower(): f for f in available}
    return next((have[c.lower()] for c in candidates if c.lower() in have), None)


def scaled(n, scale=1.0):
    """M8.1 E6: THE scale function: a pixel size of THEME at the display's
    scale (1.0 at 96 dpi, 1.25 at 120, 1.5 at 144), never below 1 for a size
    that is not 0. A pair is scaled per item."""
    if isinstance(n, (tuple, list)):
        return tuple(scaled(x, scale) for x in n)
    if not n:
        return 0
    return max(1, int(round(n * scale)))


def screen_scale(dpi):
    """E6: the scale of a display of `dpi` dots per inch (Tk's winfo_fpixels
    of 1i): dpi / 96 to the nearest quarter, at least 1.0."""
    try:
        value = float(dpi) / 96.0
    except (TypeError, ValueError):
        return 1.0
    return max(1.0, round(value * 4) / 4.0)


def look_path(home=None):
    """~/.raqib/host/look.json: the first look writes it (ADR-0007 F-10)."""
    return os.path.join(hostmod.host_dir(home), "look.json")


def first_run_lines(home=None, exists=None):
    """E4: the three first-run lines while no look has been written yet
    (no ~/.raqib/host/look.json), else none: the first look writes it."""
    return [] if (exists or os.path.exists)(look_path(home)) else list(FIRST_RUN)


def sentence(text):
    """M8.1: a text in sentence case for the window: its first letter capital."""
    text = str(text or "")
    return text[:1].upper() + text[1:]


# M8.1 E2: the verdict header says the state as a person would, in one sentence in sentence case. The words
# are the window's; the state words of ui.status and the views stay what the page, the report and the
# terminal read.
SENTENCES = {
    "READING HOST": "Reading the host...", "READER LATE": "The host reader is late",
    "HOST READER FAILED": "The host reader failed", "HOST NOT READ": "The host was not read",
    "NOTHING READ": "Nothing was read", "NO AGENT SEEN": "No agent seen on this host",
    "NO AGENT SEEN, PARTLY BLIND": "No agent seen, partly blind", "STARTING HOST WATCH": "Starting the host watch",
    "WATCHING HOST": "Watching this host", "HOST NOT WATCHED": "The host watch did not start",
    "HOST WATCH FINISHED": "The host watch finished", "CHECKING": "Checking the project...",
    "NOT STARTED": "The watch did not start", "STARTING": "Starting the project watch",
    "WATCHING": "Watching the project", "FINISHED": "The project watch finished",
    "NOT WATCHING": "The project watch did not start", "RULES": "Rules for the next watch",
    "RULES: REFUSED": "The change was refused", "RULES: MEASURING": "Measuring the thresholds...",
    "NEW RULE": "A new rule, from a form", "NEW RULE: PASSED": "The test passed: the rule can be added",
    "NEW RULE: REFUSED": "The rule was refused", "NEW RULE: ADDED": "The rule was added",
    "NEW RULE: CHANGED": "Changed since the test: test again",
    "CAPTURE FAILED": "Capture failed", "AGENT GONE": "The agent is gone",
    "LOG": "The watch's own lines", "NO LOG": "No log yet"}
STOPPING = " (stopping)"


def verdict_sentence(word):
    """M8.1 E2: the verdict header's sentence for a state word: "HOST: 2
    TREE(S)" -> "2 trees on this host", "DOCTOR: 1 MISSING, 0 UNSURE" ->
    "Checks: 1 missing, 0 unsure", "SILENT for 70 s" -> "Silent for 70 s";
    " (stopping)" is kept."""
    text = str(word or "").strip()
    stopping = text.endswith(STOPPING)
    if stopping:
        text = text[:-len(STOPPING)]
    if text in SENTENCES:
        out = SENTENCES[text]
    elif text.startswith("HOST: ") and text.endswith(" TREE(S)") and text[6:-8].isdigit():
        n = int(text[6:-8])
        out = "%d %s on this host" % (n, "tree" if n == 1 else "trees")
    elif text.startswith("DOCTOR: "):
        out = "Checks: %s" % " ".join(w if w == "OK" else w.lower() for w in text[8:].split(" "))
    else:
        out = sentence(text.lower())
    return out + (STOPPING if stopping else "")


def live_level(code, word, fresh=False):
    """REDO A-2, B-2, B-5, C-1: a running watch's level: the level of the
    code it would end with if stopped now (the state's code_so_far, the
    watch's own rule, through level_of); a code not known yet is never
    clean: incomplete; a watch whose heartbeat is stale is alarm (C-4). One
    state is the window's to soften (fresh, never_read): a project watch
    that says it has never read a line, holds no hole and no finding, and
    whose own word is WATCHING is incomplete, not an alarm at the moment of
    Start; every other state keeps the level of the code."""
    word = str(word or "")
    if word.startswith("CRASHED or stuck"):
        return "alarm"
    if fresh and word == "WATCHING":   # only where the watch's own word says nothing is wrong yet
        return "incomplete"
    return level_of(code) if isinstance(code, int) and not isinstance(code, bool) else "incomplete"


def never_read(state, word):
    """REDO C-1: the one state the window softens, as the watch names it: it
    says it never read a line (ever_read False, never inferred from a
    count), its state holds no hole and no finding, its word is WATCHING."""
    return (isinstance(state, dict) and state.get("ever_read") is False and not state.get("holes")
            and not state.get("findings") and str(word or "") == "WATCHING")


RESTART_HOLES = ("trace-missing", "trace-replaced", "trace-truncated", "trace-rewritten")


def _many(n, one, many=None):
    return "%d %s" % (n, one if n == 1 else (many or one + "s"))


def watch_causes(state):
    """REDO C-1, C-2, C-3: what makes a project watch's code 1 beside its
    findings, from its own alarms as its state counts them: a code it could
    not compute, a trace emptied or replaced (a restart), no line read yet,
    holes, silence windows open and closed, lines that could not be read, a
    state file that cannot be written."""
    state = state if isinstance(state, dict) else {}
    out = ["the watch could not judge itself"] if state.get("code_error") else []
    holes = [h for h in state.get("holes") or [] if isinstance(h, dict)]
    if (state.get("epoch") or 0) > 0 or any(h.get("kind") in RESTART_HOLES for h in holes):
        out.append("the trace was emptied or replaced")
    elif state.get("ever_read") is False and not state.get("records"):
        out.append("no line read yet")
    rest = [h for h in holes if h.get("kind") not in RESTART_HOLES]
    if rest:
        out.append(_many(len(rest), "hole"))
    windows = [w for w in state.get("silence") or [] if isinstance(w, dict)]
    opened = sum(1 for w in windows if w.get("closed") is None)
    if opened:
        out.append(_many(opened, "silence window") + ", open")
    if len(windows) - opened:
        out.append(_many(len(windows) - opened, "silence window") + ", closed")
    problems = state.get("problems") if isinstance(state.get("problems"), int) else 0
    if problems:
        out.append(_many(problems, "line that could not be read", "lines that could not be read"))
    if state.get("state_error"):
        out.append("the state file cannot be written")
    return out


def host_causes(state):
    """REDO C-2, C-3: what makes a host watch's code more than its findings
    say, from its state: a code it could not compute; its holes."""
    state = state if isinstance(state, dict) else {}
    out = ["the watch could not judge itself"] if state.get("code_error") else []
    holes = [h for h in state.get("holes") or [] if isinstance(h, dict)]
    if holes:
        out.append(_many(len(holes), "hole"))
    return out


def live_cause(code, findings, suspicions=0, causes=(), fresh=False):
    """REDO B-2, B-5, C-1..C-3: the words that say why when the level is
    not what the findings alone say: "no line read yet" (fresh), "not
    judged yet" (no code known), else the watch's own causes (watch_causes,
    host_causes) while its code is not 0; a code 1 that nothing in the state
    names is said as the report's."""
    if fresh:
        return "no line read yet"
    if not isinstance(code, int) or isinstance(code, bool):
        return "not judged yet"
    if code and causes:
        return "; ".join(causes)
    if code == 1 and not findings and not suspicions:
        return "an alarm of the watch (its report says)"
    return ""


def so_far(text, findings, suspicions=0, cause=""):
    """REDO A-2, B-5: a watching sentence says what the watch found so far:
    "Watching this host: 3 findings so far" (a suspicion named apart, A2),
    and why when that is not the whole of it ("; 1 hole")."""
    words = "%d finding%s so far" % (findings, "" if findings == 1 else "s") if findings else "no finding so far"
    if suspicions:
        words += ", %d suspicion%s" % (suspicions, "" if suspicions == 1 else "s")
    return "%s: %s%s" % (text, words, "; %s" % cause if cause else "")


def host_counts(state):
    """REDO A-2: (findings, suspicions) of a host watch's state: its findings
    and its sources' live findings, which the watch's rule counts as findings;
    its raised suspicions apart (A2)."""
    h = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else {}
    found = [x for x in h.get("findings") or [] if isinstance(x, dict)]
    found += [x for x in h.get("source_findings") or [] if source_alarm(x)]
    return len(found), len([x for x in h.get("suspicions") or [] if isinstance(x, dict)])


def source_alarm(f):
    """Where M8.1 meets M7.8 (ADR-0007 T-1, T-2, V-1): a source's finding is a
    finding of the watch as the watch's own rule counts it (host.py's
    source_alarms): not history, not a copy judged on another tree, not a
    note on a benign tree. The window counts what the exit code counts."""
    return (isinstance(f, dict) and not f.get("history") and f.get("judged_on") is None
            and not f.get("benign_note"))


def source_note(f):
    """ADR-0007 T-2: a catalog finding standing on a benign tree: noted, not
    knocked, not an alarm; the window lists it apart, grey, with its cite."""
    return isinstance(f, dict) and bool(f.get("benign_note")) and f.get("judged_on") is None


def project_count(state):
    """REDO B-6: a project watch's findings, as the verdict, the rail, the
    card's title and the tray count them: the state's findings."""
    found = state.get("findings") if isinstance(state, dict) else None
    return len([e for e in found or () if isinstance(e, dict)])


def rail_state(word, level, findings, suspicions=0, cause=""):
    """REDO A-8: a running watch in the rail: (its level, its state in
    words): "3 findings", "no finding", or what is wrong ("Silent for 40 s",
    "The host reader is late")."""
    if str(word or "").split(" (", 1)[0] in ("WATCHING", "WATCHING HOST", "STARTING", "STARTING HOST WATCH"):
        text = "%d finding%s" % (findings, "" if findings == 1 else "s") if findings else "no finding"
        text += ", %d suspicion%s" % (suspicions, "" if suspicions == 1 else "s") if suspicions else ""
        text += "; %s" % cause if cause else ""
    else:
        text = verdict_sentence(word)
    return level_of(level), text


def watch_words(host_on, project=None):
    """M8.1 E2: the rail's words for what is watched now."""
    name = os.path.basename(str(project).rstrip("/\\")) if project else None
    if host_on and name:
        return "Watching the host and project %s" % _safe(name)
    if host_on:
        return "Watching the host"
    if name:
        return "Watching project %s" % _safe(name)
    return "Not watching"


VERDICT_WORDS = {"OK": "OK", "MISSING": "missing", "UNSURE": "unsure"}


def check_rows(lines):
    """M8.1 E4: doctor's checks as rows: (pill word, level, name, sentence)
    from doctor_lines' (verdict, level, "%-8s%-9s%s" line); a note is a row
    of its own in the note level (grey, the word "note")."""
    out = []
    for word, level, text in lines or ():
        if not word:
            out.append(("note", "note", "", sentence(str(text).strip()[len("note: "):])))
            continue
        name, _, rest = str(text)[8:].partition(" ")
        out.append((VERDICT_WORDS.get(word, word.lower()), level, name, sentence(rest.strip())))
    return out


def checks_state(lines):
    """("Checks: ..." title, level): the doctor's rows fold under a
    disclosure, closed until it is clicked; its title says what is missing
    or unsure in sentence case, in the level's colour (alarm when any is
    MISSING, incomplete when any is UNSURE, else None) (M8.1)."""
    if lines is None:
        return "Checks: running...", None
    missing = sum(1 for word, _, _ in lines if word == "MISSING")
    unsure = sum(1 for word, _, _ in lines if word == "UNSURE")
    if missing:
        return "Checks: %d missing" % missing, "alarm"
    return "Checks: %s" % ("%d unsure" % unsure if unsure else "all OK"), "incomplete" if unsure else None


# M8.1 E3 (ADR-0009 decision 2): the round strip. Its cells: a round read with nothing new, a round with a
# finding, a round not read (failed, nothing read, held, partly read) or late, a place before the watch began.
STRIP_KINDS = ("clean", "finding", "unread", "before")
STRIP_IDLE = 12   # places drawn before a host watch starts: the strip's shape, quiet
UNREAD_HOLES = ("reader-late", "reader-held", "reader-failed", "reader-out", "round-unread", "lines-unread")


def strip_progress(state):
    """REDO A-4: the round a host watch is reading now (its reader out, not
    late, the watch not ended), else None: it is named apart, not drawn."""
    host = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else None
    if host is None or state.get("finished"):
        return None
    reader = host.get("reader") if isinstance(host.get("reader"), dict) else {}
    started = host.get("rounds") if isinstance(host.get("rounds"), int) else None
    out = {h.get("round") for h in state.get("holes") or [] if isinstance(h, dict) and h.get("kind") == "reader-out"}
    if started and reader.get("round") == started and not reader.get("late") and started not in out:
        return started
    return None


def strip_suspected(state):
    """REDO A-4: the rounds in which a model raised a suspicion (A2: named apart, never a level)."""
    host = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else {}
    return {f.get("round") for f in host.get("suspicions") or [] if isinstance(f, dict)}


def strip_cells(state, fit):
    """E3: the last rounds of a host watch's state as at most `fit` cells,
    oldest first (newest at the right): [(round or None, kind, why)], kind
    one of STRIP_KINDS, why "", "late", "not read" or "partly read". A
    round the watch started and did not read is drawn, never skipped (A3);
    a round whose reader is out and not yet late is not drawn yet; rounds
    older than the lines the state keeps are not drawn; places before round
    1 fill the strip while the watch is young. No state: all before."""
    fit = max(0, int(fit))
    host = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else None
    if host is None:
        return [(None, "before", "")] * min(fit, STRIP_IDLE)
    tail = {r["round"]: r for r in host.get("rounds_tail") or [] if isinstance(r, dict)
            and isinstance(r.get("round"), int)}
    started = host.get("rounds") if isinstance(host.get("rounds"), int) else max(tail or [0])
    reader = host.get("reader") if isinstance(host.get("reader"), dict) else {}
    found = {f.get("round") for f in host.get("findings") or [] if isinstance(f, dict)}
    unread = {h.get("round") for h in state.get("holes") or [] if isinstance(h, dict)
              and h.get("kind") in UNREAD_HOLES}
    last = started - 1 if strip_progress(state) == started else started
    first = min(tail) if tail and len(tail) >= hostmod.ROUNDS_KEPT else 1
    cells = []
    for n in range(max(first, last - fit + 1), last + 1):
        r = tail.get(n)
        if n in found or (r is not None and (r.get("findings") or r.get("source_findings"))):
            cells.append((n, "finding", ""))
        elif r is None or r.get("error") or r.get("nothing_read"):
            late = r is None and reader.get("round") == n and reader.get("late")
            cells.append((n, "unread", "late" if late else "not read"))
        elif r.get("late"):
            cells.append((n, "unread", "late"))
        elif r.get("incomplete") or r.get("unread_lines") or n in unread:
            cells.append((n, "unread", "partly read"))
        else:
            cells.append((n, "clean", ""))
    if first == 1 and len(cells) < fit:
        cells = [(None, "before", "")] * (fit - len(cells)) + cells
    return cells


def strip_text(cells, total=None, progress=None, suspected=()):
    """E3: the strip's words: "40 rounds: 36 clean, 3 with findings, 1 not
    read" (", 2 partly read", ", 1 late", ", 2 with a suspicion" when there
    are); "the last 40 of 212 rounds: ..." when the watch has more rounds
    than are drawn (total: the rounds it could draw, the one in progress
    not among them); "; round N in progress" (REDO A-4); "No rounds yet"
    before the first."""
    rounds = [c for c in cells if c[1] != "before"]
    if not rounds:
        return "No rounds yet" + ("; round %d in progress" % progress if progress else "")
    count = {k: sum(1 for c in rounds if c[1] == k) for k in STRIP_KINDS}
    whys = {w: sum(1 for c in rounds if c[2] == w) for w in ("not read", "partly read", "late")}
    head = "%d round%s" % (len(rounds), "" if len(rounds) == 1 else "s")
    if isinstance(total, int) and total > len(rounds):
        head = "The last %d of %d rounds" % (len(rounds), total)
    out = "%s: %d clean, %d with findings, %d not read" % (head, count["clean"], count["finding"], whys["not read"])
    out += "".join(", %d %s" % (whys[w], w) for w in ("partly read", "late") if whys[w])
    sus = sum(1 for c in rounds if c[0] in set(suspected or ()))
    out += ", %d with a suspicion" % sus if sus else ""
    return out + ("; round %d in progress" % progress if progress else "")


def strip_total(state):
    """REDO A-4: the rounds a host watch can draw now: every round it began but the one in progress."""
    host = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else None
    if host is None or not isinstance(host.get("rounds"), int):
        return None
    return host["rounds"] - (1 if strip_progress(state) else 0)


BY_HAND = "Not a rule Raqib wrote: delete it by hand if you mean to:"
BY_HAND_LINK = "A link in rules.d, not a rule Raqib wrote: remove the link by hand if you mean to (not what it leads to):"


def rule_items(rows, titles=None):
    """M8.1 E5: the Rules screen's rows from RulesPanel.rows: per rule its
    id, the YAML's title, on, the overlay state in words ("off by the
    overlay", "off in its YAML", "thresholds set" or ""), its pills (kind,
    severity, origin), class and budget, each editable threshold as a
    stepper (name, value, low, high and the measurement's words), each
    fixed one as words, and whether Reset has something to undo."""
    titles = titles or {}
    out = []
    for r in rows:
        steps = [dict(t, words=stepper_words(t)) for t in r.get("thresholds") or ()]
        changed = any(t.get("value") != t.get("yaml") for t in steps)
        on = r.get("status") != "off"
        state = ("off in its YAML" if r.get("off_by") == "yaml" else "off by the overlay") if not on else (
            "thresholds set" if changed else "")
        if r.get("refused"):   # M8.2 REDO E-6: a person's rule refused at load is a row, with its Remove
            state = "refused at load"
        place = r.get("place") if r.get("origin") == "user" else None
        # M8.2 REDO 2 F-3: a person's row is keyed by its own place in rules.d (a folder or a loose file), never by
        # a name looked up again; a place Raqib could not have written gets no Remove, only its path to delete it by
        key = _safe(place) if place else _safe(r.get("id"))
        if place and r.get("refused") and key in {x.get("id") for x in rows if x.get("origin") != "user"}:
            key = "rules.d/" + key   # a folder named as a package rule: its own row
        out.append({"id": _safe(r.get("id")), "key": key, "place": _safe(place) if place else None,
                    "removable": bool(place) and r.get("removable", overlay.removable(place, "folder")),
                    "path": _safe(r.get("path")) if r.get("path") else None,
                    "no_remove": _safe(r.get("no_remove") or BY_HAND),   # REDO 3 G-5, G-6: why no Remove
                    "title": "" if r.get("refused") else _safe(titles.get(r.get("id")) or ""), "on": on,
                    "state": state, "pills": [_safe(r.get(k)) for k in ("kind", "severity", "origin")],
                    "meta": ("why: %s" % _safe(r["refused"]) if r.get("refused") else
                             "class %s, budget %g" % (_safe(r.get("class")), r.get("budget") or 0)),
                    "refused": bool(r.get("refused")),
                    "steppers": steps, "resettable": r.get("off_by") == "overlay" or changed,
                    "fixed": [overlay.threshold_text(t) for t in r.get("fixed") or ()],
                    "level": "alarm" if r.get("refused") else (None if on else "incomplete"),
                    "origin": _safe(r.get("origin"))})   # M8.2: Remove
    return out


def stepper_words(t):
    """E5 (ADR-0008 E): the words beside a threshold's stepper: its bounds,
    the range the measurement accepts when it differs, the YAML's value
    when the overlay changed it."""
    text = "%d..%d" % (t["low"], t["high"])
    if "lo" in t and (t["lo"], t["hi"]) != (t["low"], t["high"]):
        text += ", measured %d..%d" % (t["lo"], t["hi"])
    if t.get("yaml") is not None and t["value"] != t["yaml"]:
        text += ", YAML %d" % t["yaml"]
    return text


def rule_matches(item, text):
    """E5: the filter box: every word of text in the rule's id, title, pills or state (case-insensitive)."""
    hay = " ".join([item["id"], item["title"], item["state"], item["meta"]] + item["pills"]).casefold()
    return all(w in hay for w in str(text or "").casefold().split())


# The host screen's tree table (E2): (column id, heading, width px, index in a host_rows row, sort kind).
# Eight columns; "acts" (row index 4) is in the detail card.
TREE_ORDER = (1, 2, 4, 0, 6, 3, 7, 5)   # REDO A-11: pid, kind, findings, image, first seen, then the rest may be cut
TREE_COLUMNS = (("image", "image", 96, 0, "text"), ("pid", "pid", 48, 1, "number"),
                ("kind", "kind", 90, 2, "text"), ("source", "source", 64, 5, "text"),
                ("findings", "findings", 72, 6, "severity"), ("rhythm", "rhythm", 80, 7, "text"),
                ("first", "first seen", 86, 3, "text"), ("endpoints", "endpoints", 64, 8, "text"))
TREE_WHOLE = ("pid", "kind", "findings")   # REDO B-7: cells given their width before any other wants more
TREE_NEED_ORDER = (4, 1, 2)                 # the severities, the pid, then the kind (its flags, then its word)
# where M8.1 meets M7.8: the words ui.severity_counts gives a tree since ADR-0007 R-3, T-2, V-1, in its order
SEVERITY_RANK = ("high", "medium", "low", "not settled", "history", "pending at exit", "pending",
                 "judged on another tree", "noted (benign)")


def sort_key(kind, cell):
    """E2: the key a column sorts by. number: the integer (a cell that is
    not one sorts after, by its text); severity: the severity counts of
    ui.severity_counts, the gravest first ("none" and "-" last); a bare
    severity word by its rank; text: case-folded, numbers in it compared as
    numbers ("-" last)."""
    text = str(cell).strip()
    if kind == "number":
        try:
            return (0, float(text), "")
        except ValueError:
            return (1, 0.0, text.casefold())
    if kind == "severity":
        if text in SEVERITY_RANK:
            return (0, SEVERITY_RANK.index(text))
        counts = dict.fromkeys(SEVERITY_RANK, 0)
        for part in text.split(","):
            word, _, n = part.strip().rpartition(" ")
            if word in counts and n.isdigit():
                counts[word] = int(n)
        if not any(counts.values()):
            return (1, len(SEVERITY_RANK))
        return (0,) + tuple(-counts[w] for w in SEVERITY_RANK)
    if text in ("", "-"):
        return (1, ())
    parts, digits = [], ""
    for ch in text.casefold() + "\0":
        if ch.isdigit():
            digits += ch
            continue
        if digits:
            parts.append((0, int(digits), ""))
            digits = ""
        if ch != "\0":
            parts.append((1, 0, ch))
    return (0, tuple(parts))


def sort_rows(rows, columns, column, reverse=False, get=None):
    """E2, REDO C-7: rows (tuples; get(item) gives the row of an item) sorted
    by the column id of columns, stable both ways; a cell with no value
    ("-", "", "none", not a number in a number column) sorts last in both
    directions, in its first order. The window sorts through this."""
    spec = next(c for c in columns if c[0] == column)
    pick = get or (lambda item: item)

    def key(item):
        row = pick(item)
        return sort_key(spec[4], row[spec[3]] if spec[3] < len(row) else "")
    keyed = [(key(item), item) for item in rows]
    filled = sorted((x for x in keyed if x[0][0] == 0), key=lambda x: x[0], reverse=reverse)
    return [item for _, item in filled] + [item for k, item in keyed if k[0] != 0]


def table_iids(values_list):
    """REDO C-7: a Treeview row id per row, from its first two cells (image
    and pid; a rule's id), numbered in the rows' own order when two rows
    share them, so an id does not move when the table is sorted or
    refreshed and the selection survives."""
    seen, out = {}, []
    for values in values_list:
        base = "%s|%s" % (values[0], values[1] if len(values) > 1 else "")
        seen[base] = seen.get(base, 0) + 1
        out.append(base if seen[base] == 1 else "%s+%d" % (base, seen[base] - 1))
    return out


ELLIPSIS = "\u2026"


def first_seen_text(stamp, today):
    """REDO A-11: "first seen" in the record's own UTC: the time when its
    date is today's (UTC), else the date and the minute."""
    text = str(stamp or "")
    if len(text) >= 19 and text[4] == "-" and text[10] == "T":
        return text[11:19] if text[:10] == today else "%s %s" % (text[:10], text[11:16])
    return text


def fit_cell(text, width, measure, flags=True):
    """REDO A-11: a cell cut to `width` pixels (measure(text) gives a
    text's) ends in an ellipsis; the state words in its last brackets
    ("(new)", "(quiet)", "(gone)") are kept whole: the words before them are
    cut. REDO C-7: flags=False (a cell whose first words matter most, the
    rhythm cell's suspicion) cuts at the end; brackets wider than the cell
    are cut too."""
    text = str(text)
    if width <= 0 or measure(text) <= width:
        return text
    head, kept = text, ""
    if flags and text.endswith(")") and " (" in text and measure(ELLIPSIS + " (" + text.rsplit(" (", 1)[1]) <= width:
        head, rest = text.rsplit(" (", 1)
        kept = " (" + rest
    flags = kept
    while head and measure(head + ELLIPSIS + flags) > width:
        head = head[:-1]
    return head.rstrip() + ELLIPSIS + flags


def column_widths(avail, mins, wants, order=None, needs=(), need_order=None):
    """REDO A-11: a table's columns in `avail` pixels: each at least its
    heading's width (mins); REDO B-7: then each list of needs in turn, in
    need_order (the words that must not be cut: the severities, the kind's
    flags); what is left given to the columns whose cells want more, as far
    as they want it, in `order`, the rest shared evenly."""
    widths = list(mins)
    left = avail - sum(widths)
    if left <= 0 or not widths:
        return widths
    for wanted in needs:
        for i in need_order if need_order is not None else range(len(widths)):
            give = min(max(0, wanted[i] - widths[i]), left)
            widths[i] += give
            left -= give
    for i in order if order is not None else range(len(widths)):
        give = min(max(0, wants[i] - widths[i]), left)
        widths[i] += give
        left -= give
    share = left // len(widths)
    widths = [w + share for w in widths]
    widths[-1] += left - share * len(widths)
    return widths


def tree_values(row):
    """The Treeview's values of one host_rows row, in TREE_COLUMNS order."""
    return tuple(row[c[3]] if c[3] < len(row) else "" for c in TREE_COLUMNS)


def empty_trees_text(view):
    """M8.1: what the trees' card says when the table has no row: the view's
    lines ("No agent seen (30 records, 4 holes). Not a clearance."; an
    AGENT-DARK footprint is a finding item, not this), else that no tree is
    read yet or none was in the round."""
    return "\n".join(sentence(x) for x in (view or {}).get("lines") or () if not x.startswith("AGENT-DARK ")) or (
        "No tree yet" if (view or {}).get("word") in ("READING HOST", "STARTING HOST WATCH") else
        "No tree in this round")


def row_level(row):
    """E1: the level of a tree's row: alarm when it knocked (new) or its
    source has findings, note when it is gone, else None (the default
    colour); the kind and findings columns say it in words."""
    kind = str(row[2]) if len(row) > 2 else ""
    flags = [f.strip(" )") for f in kind.split("(", 1)[1].split(",")] if "(" in kind else []
    findings = str(row[6]) if len(row) > 6 else "none"
    if "new" in flags or any(w in findings for w in ("high", "medium", "low", "not settled", "pending at exit")):
        return "alarm"
    if "gone" in flags or "quiet" in flags:
        return "note"
    return None


def overlay_holes(info, error=None):
    """REDO A-3: the overlay's holes, counted where every hole is: a
    rules.yaml that cannot be read, an entry refused at load, a person's
    rule refused at load, a catalog that could not be loaded."""
    info = info or {}
    out = ["rules: %s" % error] if error else []
    if info.get("file") == "malformed":
        out.append("rules overlay %s is not applied: %s" % (info.get("path"), info.get("hole")))
    out += ["rules overlay: an entry refused at load: %s" % r for r in info.get("refused") or []]
    out += ["rules: a user rule refused at load: %s" % r for r in info.get("user_refused") or []]
    return [_safe(x) for x in out]


def missing_checks(lines):
    """REDO A-7: each MISSING check of doctor is a line of "could not see"."""
    return [_safe("check missing: %s: %s" % (name, text)) for word, level, name, text in check_rows(lines)
            if level == "alarm"]


def rail_rules(info, error=None, states=()):
    """REDO A-3, A-10: the rail's rules line, bounded (the ids and the
    reasons are on the Rules screen and in "could not see"): (text, level):
    "N rules off" (red with the suppressed count while a running watch's off
    rules would have fired, ADR-0008 A-2), "rules: N refused" beside it."""
    if info is None and not error:
        return "Rules: not loaded", "incomplete"
    off = len([o for o in (info or {}).get("off") or [] if not o.get("refused")])   # B-9: refused, not off too
    refused = len(overlay_holes(info, error))
    n = sum(ui.suppressed(s) for s in states if isinstance(s, dict))
    text = "%d rule%s off" % (off, "" if off == 1 else "s") if off else "No rule off"
    text += "; %d finding%s suppressed" % (n, "" if n == 1 else "s") if n else ""
    text += "; rules: %d refused" % refused if refused else ""
    return text, "suppressed" if n else "incomplete" if off or refused else None


def seen_lines(holes, notes, look=()):
    """M8.1 E4 (replaces C-5's footer; F-3): the lines of "could not see
    (N)", every one: the window's own holes, each of the first look's holes
    (they stand until the host watch's first round), the notes."""
    return ["hole: %s" % h for h in list(holes) + list(look)] + ["note: %s" % n for n in notes]


def seen_title(lines):
    """E4: the disclosure's title: "Could not see (N)", N the holes among
    lines, and how many notes stand under them."""
    holes = sum(1 for x in lines if x.startswith("hole: "))
    notes = len(lines) - holes
    return "Could not see (%d)%s" % (holes, ", %d note%s" % (notes, "" if notes == 1 else "s") if notes else "")


def text_tags(text):
    """E1: (line, level) for a screen's text: under "FINDINGS: n" (n > 0)
    alarm, under "HOLES (A3): n" (n > 0) hole, under "NOTES" note; the
    section lines themselves carry the word. Other lines untagged."""
    out, level = [], None
    for line in text.rstrip("\n").split("\n"):
        head = line.split(":", 1)
        if not line.startswith(" ") and len(head) == 2:
            name, rest = head[0], head[1].strip()
            count = int(rest) if rest.isdigit() else None
            words = " ".join(rest.split("(")).split()   # REDO C-5: "SOURCE FINDINGS: 3 (2 live, ...)"
            live = int(words[1]) if len(words) > 2 and words[1].isdigit() and words[2].startswith("live") else 0
            if name == "FINDINGS" or name.startswith("NOT SETTLED"):
                level = "alarm" if count else None
            elif name == "SOURCE FINDINGS":
                level = "alarm" if live else None
            elif name.startswith("ON BENIGN TREES"):
                level = "note" if count else None
            elif name == "HOLES (A3)":
                level = "hole" if count else None
            elif name.startswith("NOTES"):
                level = "note"
            elif name.startswith("hole"):
                out.append((line, "hole"))
                continue
            else:
                level = None
        elif not line.startswith(" ") and line:
            level = None
        out.append((line, level))
    return tuple(out)


def tree_name(word):
    """REDO A-13(a): a tree's word ("4242:scribe:2026-11-10T09:12:00Z") as a person reads it: "scribe pid 4242"."""
    parts = str(word or "").split(":", 2)
    return "%s pid %s" % (parts[1], parts[0]) if len(parts) >= 2 and parts[0].isdigit() else _safe(word)


def _where(*parts):
    """REDO A-13(a): the quiet line of a finding: its parts that are there, joined; an absent one is not printed."""
    return " \u00b7 ".join(_safe(x) for x in parts if x not in (None, "", "None", "-"))


def finding_items(entries):
    """REDO A-13(a): the project watch's findings as items, the gravest
    first: (pill word, level, rule, sentence, where). The pill is the
    severity with its word, red for a finding, amber while it is pending,
    grey for history; the where line says the session, the seqs it cites
    (A5), its state and how it knocked."""
    out = []
    for sev, items in ui.severity_groups([e for e in entries or () if isinstance(e, dict)]):
        for e in items:
            history = e.get("history") or e.get("state") == "history"
            level = "note" if history else "incomplete" if str(e.get("state", "")).startswith("pending") else "alarm"
            seqs = watch.seq_text(list(e.get("cited_seq") or []))
            out.append((_safe(e.get("severity") or sev), level, _safe(e.get("rule_id")), sentence(_safe(e.get("summary"))),
                        _where("session %s" % e.get("session_id") if e.get("session_id") else None, seqs,
                               e.get("state"), "history" if e.get("history") else None,
                               "knocked: %s" % e.get("notice") if e.get("notice") else None)))
    return out


def host_finding_items(state, view=None):
    """REDO A-13(a): the host screen's findings as items: (pill word, level,
    rule, sentence, where). A finding: its severity's pill (red), the tree,
    the round, how it knocked, what it cites (run and seq, A5; rhythm's
    beats); a suspicion apart, named so (A2); a note (never an alarm) grey;
    the look's AGENT-DARK footprints red, as the look's lines say them."""
    h = state.get("host") if isinstance(state, dict) and isinstance(state.get("host"), dict) else None
    out = []
    if h is None:
        for line in (view or {}).get("lines") or ():
            if line.startswith("AGENT-DARK "):
                head, _, rest = line[len("AGENT-DARK "):].partition(": ")
                out.append(("footprint", "alarm", "AGENT-DARK", sentence(rest or head), _safe(head)))
        return out
    for f in sorted((x for x in h.get("findings") or [] if isinstance(x, dict)),
                    key=lambda x: SEVERITY_RANK.index(x.get("severity")) if x.get("severity") in SEVERITY_RANK
                    else len(SEVERITY_RANK)):
        beats = ["talk round %s seq %s, act round %s seq %s" % (b.get("talk_round"), b.get("talk_seq"), b.get("round"),
                                                                b.get("seq")) for b in f.get("beats") or ()
                 if isinstance(b, dict)]
        out.append((_safe(f.get("severity")), "alarm", _safe(f.get("rule_id")), sentence(_safe(f.get("summary"))),
                    _where("round %s" % f.get("round") if f.get("round") is not None else None,
                           tree_name(f.get("tree")) if f.get("tree") else f.get("path"),
                           "knocked: %s" % f.get("notice") if f.get("notice") else None,
                           "cites run %s %s" % (f.get("run"), watch.seq_text(list(f.get("cited_seq") or [])))
                           if f.get("run") else None, *beats)))
    for f in h.get("source_findings") or []:   # REDO B-6: a source's live finding is an item, its cite with it
        if source_alarm(f):
            out.append((_safe(f.get("severity")), "alarm", _safe(f.get("rule_id")),   # REDO C-5: pending is an alarm
                        sentence(_safe(f.get("summary"))),
                        _where(tree_name(f.get("tree")) if f.get("tree") else None, "source %s" % f.get("trace")
                               if f.get("trace") else None, watch.seq_text(list(f.get("cited_seq") or [])),
                               "pending" if f.get("pending") else None,
                               "knocked: %s" % f.get("notice") if f.get("notice") else None)))
    for f in h.get("suspicions") or []:
        if isinstance(f, dict):
            out.append(("suspicion", "note", "SUSPECT", sentence(_safe("; ".join(f.get("reasons") or []) or "raised")),
                        _where("%.2f" % (f.get("suspicion") or 0), "round %s" % f.get("round"),
                               tree_name(f.get("tree")),
                               "by %s/%s" % (f.get("backend"), f.get("model")),
                               "knocked: %s" % f.get("notice") if f.get("notice") else None,
                               "cites %s seq %s" % (f.get("trace"), ",".join(str(x) for x in f.get("cited_seq") or [])))))
    for f in h.get("source_findings") or []:   # ADR-0007 T-2: what a benign tree's acts matched, noted apart
        if source_note(f):
            out.append(("noted", "note", _safe(f.get("rule_id")), sentence(_safe(f.get("summary"))),
                        _where("on a benign tree: noted, not knocked",
                               tree_name(f.get("tree")) if f.get("tree") else None,
                               "source %s" % f.get("trace") if f.get("trace") else None,
                               watch.seq_text(list(f.get("cited_seq") or [])))))
    for d in h.get("dark_notes") or []:
        if isinstance(d, dict):
            out.append(("note", "note", "NOTE", sentence(_safe(d.get("text"))), ""))
    return out


# M8.1 REDO A-1 (ADR-0009 Amendment A): every event sequence the window binds, in one table. Each is a
# sequence Tk accepts on every platform (a test binds them all and refuses any other in the code): no X11-only
# keysym (Tk on Windows refuses the bind, and the window would not open); Shift-Tab is Tk's own virtual event
# <<PrevWindow>>, which Tk defines for each windowing system.
KEYS = {
    "act": ("<Return>", "<KP_Enter>"),      # Enter acts as Space does on a button, a switch, a disclosure
    "next": ("<Tab>",),                      # out of a text, forwards
    "prev": ("<<PrevWindow>>",),             # out of a text, backwards (Shift-Tab, whatever the platform)
    "wheel": ("<MouseWheel>",),              # the wheel on Windows (and macOS)
    "wheel_up": ("<Button-4>",),             # the wheel under X11 (never sent on Windows, accepted there)
    "wheel_down": ("<Button-5>",),
    "resize": ("<Configure>",), "focus": ("<FocusIn>",), "select": ("<<TreeviewSelect>>",),
    "map": ("<Map>",),                       # REDO C-4: the window is back on the screen (Tk's own, every platform)
}

# --- Windows only (M8.1 E6, A4): Raqib's own process and its own window ------------------------------------
DPI_SYSTEM_AWARE = 1                 # PROCESS_SYSTEM_DPI_AWARE: Tk 8.6 scales its fonts to the system DPI
E_ACCESSDENIED = -2147024891         # 0x80070005: the awareness was declared already (a manifest): fine
DARK_TITLE_ATTRIBUTES = (20, 19)     # DWMWA_USE_IMMERSIVE_DARK_MODE: Windows 11 and 10 20H1+, then 10 1809+


def _win_api():
    """The two Win32 calls of the window (and nothing else): the process's
    DPI awareness (shcore.SetProcessDpiAwareness) and its own title bar's
    dark mode (dwmapi.DwmSetWindowAttribute). Windows only; tests give fakes."""
    import ctypes   # Windows only, stdlib

    class Api:
        def SetProcessDpiAwareness(self, value):
            fn = ctypes.windll.shcore.SetProcessDpiAwareness
            fn.argtypes, fn.restype = [ctypes.c_int], ctypes.c_long   # HRESULT (PROCESS_DPI_AWARENESS)
            return fn(value)

        def DwmSetWindowAttribute(self, hwnd, attribute, on):
            fn = ctypes.windll.dwmapi.DwmSetWindowAttribute
            fn.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]   # HWND, DWORD, LPCVOID
            fn.restype = ctypes.c_long                                                      # HRESULT
            flag = ctypes.c_int(1 if on else 0)
            return fn(hwnd, attribute, ctypes.byref(flag), ctypes.sizeof(flag))
    return Api()


def declare_dpi_awareness(platform=None, api=None):
    """E6: on Windows, before Tk starts, the process says it is DPI-aware
    (system awareness, as IDLE does), so Windows draws its text sharp
    instead of stretching a 96-dpi bitmap. None, or the failure's line (the
    window then opens as before, blurred on a scaled display)."""
    if (platform or sys.platform) != "win32":
        return None
    try:
        result = (api or _win_api()).SetProcessDpiAwareness(DPI_SYSTEM_AWARE)
    except Exception as exc:
        return "DPI awareness was not declared: %s: %s" % (type(exc).__name__, _safe(exc))
    if result not in (0, None, E_ACCESSDENIED):
        return "DPI awareness was not declared: SetProcessDpiAwareness returned 0x%08x" % (int(result) & 0xFFFFFFFF)
    return None


def dark_title_bar(hwnd, mode, platform=None, api=None):
    """E6: on Windows in dark mode, the window's own title bar is made dark
    (DwmSetWindowAttribute on hwnd, Raqib's own frame); light mode keeps
    the default. None, or the failure's line (the title bar stays light)."""
    if (platform or sys.platform) != "win32" or mode != "dark":
        return None
    try:
        api = api or _win_api()
        results = []
        for attribute in DARK_TITLE_ATTRIBUTES:
            result = api.DwmSetWindowAttribute(int(hwnd), attribute, True)
            if result in (0, None):
                return None
            results.append("0x%08x" % (int(result) & 0xFFFFFFFF))
    except Exception as exc:
        return "the title bar was not made dark: %s: %s" % (type(exc).__name__, _safe(exc))
    return "the title bar was not made dark: DwmSetWindowAttribute returned %s" % ", ".join(results)


# --- the drawn controls (M8.1 E4): pixels from THEME's colours, pure, for Tk's PhotoImage ---------------------

def _rgb(colour):
    c = colour.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _cover_rect(px, py, x0, y0, x1, y1, r, n=4):
    """How much of pixel (px, py) the rounded rectangle [x0, x1] x [y0, y1] of radius r covers (0..1)."""
    if px + 1 <= x0 or py + 1 <= y0 or px >= x1 or py >= y1:
        return 0.0
    inside = px >= x0 and py >= y0 and px + 1 <= x1 and py + 1 <= y1
    if inside and (x0 + r <= px and px + 1 <= x1 - r or y0 + r <= py and py + 1 <= y1 - r):
        return 1.0
    hit = 0
    for i in range(n):
        sx = px + (i + 0.5) / n
        for j in range(n):
            sy = py + (j + 0.5) / n
            if x0 <= sx <= x1 and y0 <= sy <= y1:
                cx, cy = min(max(sx, x0 + r), x1 - r), min(max(sy, y0 + r), y1 - r)
                hit += (sx - cx) ** 2 + (sy - cy) ** 2 <= r * r
    return hit / float(n * n)


def _cover_line(px, py, x0, y0, x1, y1, width):
    """How much of pixel (px, py) a line from (x0, y0) to (x1, y1) of `width` covers, by its distance."""
    cx, cy = px + 0.5, py + 0.5
    dx, dy = x1 - x0, y1 - y0
    t = 0.0 if dx == dy == 0 else max(0.0, min(1.0, ((cx - x0) * dx + (cy - y0) * dy) / float(dx * dx + dy * dy)))
    d = ((cx - x0 - t * dx) ** 2 + (cy - y0 - t * dy) ** 2) ** 0.5
    return max(0.0, min(1.0, width / 2.0 - d + 0.5))


def paint(w, h, ground, shapes):
    """E4: a w x h picture: the ground colour, then each shape in order -
    ("rect", x0, y0, x1, y1, radius, colour), ("circle", cx, cy, r, colour),
    ("line", x0, y0, x1, y1, width, colour) - its edges blended into what is
    under it. Rows of "#rrggbb" for PhotoImage.put. Pure."""
    base = _rgb(ground)
    shapes = [(s[0], s[1:-1], _rgb(s[-1])) for s in shapes]
    rows = []
    for y in range(h):
        row = []
        for x in range(w):
            r, g, b = base
            for kind, a, colour in shapes:
                if kind == "rect":
                    t = _cover_rect(x, y, *a)
                elif kind == "circle":
                    t = max(0.0, min(1.0, a[2] - ((x + 0.5 - a[0]) ** 2 + (y + 0.5 - a[1]) ** 2) ** 0.5 + 0.5))
                else:
                    t = _cover_line(x, y, *a)
                if t > 0:
                    r, g, b = r + (colour[0] - r) * t, g + (colour[1] - g) * t, b + (colour[2] - b) * t
            row.append("#%02x%02x%02x" % (int(round(r)), int(round(g)), int(round(b))))
        rows.append(row)
    return rows


def box(w, h, radius, fill, ground, border=None, width=1):
    """E4: a rounded box (a card, a button, a field, a pill): fill, an
    optional border of `width`, on ground."""
    shapes = []
    if border:
        shapes.append(("rect", 0, 0, w, h, radius, border))
        shapes.append(("rect", width, width, w - width, h - width, max(radius - width, 0), fill))
    else:
        shapes.append(("rect", 0, 0, w, h, radius, fill))
    return paint(w, h, ground, shapes)


def switch_shape(w, h, on, track, knob, ground, ring=None, margin=0, after=0):
    """E4: the Switch: a track of w x h (the accent when on, grey when off)
    with its knob at the right when on, at the left when off; `ring` is the
    focus ring drawn in the margin around it; `after` pixels of ground on
    its right (the space before its label)."""
    W, H = w + 2 * margin + after, h + 2 * margin
    shapes = []
    if ring:
        shapes.append(("rect", 0, 0, w + 2 * margin, H, H / 2.0, ring))
        shapes.append(("rect", 1.5, 1.5, w + 2 * margin - 1.5, H - 1.5, H / 2.0 - 1.5, ground))
    shapes.append(("rect", margin, margin, margin + w, margin + h, h / 2.0, track))
    k = h / 2.0 - max(2.0, h / 9.0)
    shapes.append(("circle", margin + (w - h / 2.0 if on else h / 2.0), margin + h / 2.0, k, knob))
    return paint(W, H, ground, shapes)


def chevron_shapes(size, direction, colour, width=1.6, dx=0.0, dy=0.0):
    """E4: the two strokes of a chevron in a size x size square at (dx, dy):
    "right" (a disclosure closed), "down" (open), "up" (a sort arrow)."""
    s, m = float(size), size * 0.3
    points = {"right": ((m + 1, m * 0.7), (s - m + 1, s / 2.0), (m + 1, s - m * 0.7)),
              "down": ((m * 0.7, m + 1), (s / 2.0, s - m + 1), (s - m * 0.7, m + 1)),
              "up": ((m * 0.7, s - m - 1), (s / 2.0, m - 1), (s - m * 0.7, s - m - 1))}[direction]
    (ax, ay), (bx, by), (cx, cy) = [(x + dx, y + dy) for x, y in points]
    return [("line", ax, ay, bx, by, width, colour), ("line", bx, by, cx, cy, width, colour)]


def chevron(size, direction, colour, ground, width=1.6):
    """E4: a chevron alone (the sort arrow of a table's heading)."""
    return paint(size, size, ground, chevron_shapes(size, direction, colour, width))


def sign(size, plus, colour, ground, width=1.6):
    """E5: the stepper's minus and plus, drawn (no glyph)."""
    s, m = float(size), size * 0.25
    shapes = [("line", m, s / 2.0, s - m, s / 2.0, width, colour)]
    if plus:
        shapes.append(("line", s / 2.0, m, s / 2.0, s - m, width, colour))
    return paint(size, size, ground, shapes)


def image_data(rows):
    """PhotoImage.put's data for rows of colours."""
    return " ".join("{%s}" % " ".join(row) for row in rows)


class AppError(Exception):
    """raqib app cannot open its window (exit 2)."""


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


# --- can a window open here ------------------------------------------------------------

def probe_tk(importer=None):
    """(the tkinter module, None), or (None, the sentence naming python3-tk).
    Imports tkinter; opens no window."""
    importer = importer or importlib.import_module
    try:
        return importer("tkinter"), None
    except ImportError as exc:
        return None, NO_TK % _safe(exc)


def display_problem(environ, platform=None):
    """None when a Tk window can be asked for, else why not. Windows and
    macOS need no DISPLAY; X11 does. Nothing is opened to find out."""
    platform = platform or sys.platform
    if platform in ("win32", "darwin") or notify.env_value(environ, "DISPLAY"):
        return None
    return NO_DISPLAY % platform


# --- what the window shows (pure) ----------------------------------------------------------

def doctor_lines(lines, notes=()):
    """[(verdict word, level, text line)] of doctor's checks, notes below."""
    from raqib import doctor
    out = []
    for name, (ok, text) in lines:
        word = doctor.VERDICTS[ok]
        out.append((word, VERDICT_COLORS[word], "%-8s%-9s%s" % (word, name, _safe(text))))
    out += [("", "incomplete", "%17snote: %s" % ("", _safe(n))) for n in notes]
    return out


def finding_line(entry):
    """One finding of watch.json's inventory as the window lists it: the
    rule, its state, the session and seqs, the summary, how it knocked."""
    seqs = entry.get("cited_seq") or []
    return _safe("%s %s%s session %s %s: %s [%s]" % (
        entry.get("rule_id"), entry.get("state"), " (history)" if entry.get("history") else "",
        entry.get("session_id"), watch.seq_text(list(seqs)), entry.get("summary"), entry.get("notice")))


def hole_line(hole):
    more = " (%d times, last at %s)" % (hole["count"], hole.get("last")) if hole.get("count", 1) > 1 else ""
    past = " (history)" if hole.get("history") else ""
    return _safe("%s: %s at %s%s%s" % (hole.get("kind"), hole.get("detail"), hole.get("at"), more, past))


def watch_view(state, extra_holes=()):
    """What the watching screen shows of a watch's state (watch.json's
    shape): {word, level, detail, badges, findings, holes, url}. findings is
    [(severity, [lines])], high first (ui.severity_groups); holes the
    watch's and the notifier's holes, open silence windows, and extra_holes
    (the window's own: tray, knock, worker)."""
    word, level, detail = ui.status(state)
    age, stale = stale_age(state)
    if age is not None:   # A-2, ADR-0005 C-4: the watcher itself is silent
        word, level = "CRASHED or stuck (%d s)" % age, "alarm"
    entries = [e for e in state.get("findings") or [] if isinstance(e, dict)]
    groups = [(sev, [finding_line(e) for e in items]) for sev, items in ui.severity_groups(entries)]
    holes = [hole_line(h) for h in state.get("holes") or [] if isinstance(h, dict)]
    for w in state.get("silence") or []:
        if isinstance(w, dict) and w.get("closed") is None:
            holes.append(_safe("silence-window: no line since %s (%s): open" % (w.get("since"), w.get("after"))))
        elif isinstance(w, dict):   # REDO C-3: a closed window is an alarm of the watch too, listed as one
            holes.append(_safe("silence-window: no line from %s to %s (%s): closed by line %s" % (
                w.get("since"), w.get("closed"), w.get("after"), w.get("closed_by_line"))))
    if state.get("code_error"):   # REDO C-2: the watch could not compute its code
        holes.append(_safe("the watch could not judge itself: %s" % state["code_error"]))
    holes += [_safe(h) for h in extra_holes]
    return {"word": word, "level": level, "detail": _safe(detail),
            "badges": [(lv, _safe(text)) for lv, text in ui.band_items(state)[1:]],
            "findings": groups, "holes": holes, "url": state.get("url") or "-"}


def stale_age(state):
    """(age in s, stale_after) when a watching state's heartbeat is older
    than stale_after_seconds (C-4), else (None, stale_after)."""
    stale = state.get("stale_after_seconds")
    age = state.get("heartbeat_age_seconds")
    if state.get("finished") or not isinstance(stale, (int, float)) or not isinstance(age, (int, float)):
        return None, stale
    return (age if age > stale else None), stale


def aged(state, wall_now):
    """A-2: the state with heartbeat_age_seconds recomputed from its
    heartbeat (wall time) and the wall clock now, never frozen at the read.
    The age only grows: a state read long ago is as old as its heartbeat."""
    if not state:
        return state
    beat = ui._when(state.get("heartbeat"))
    if beat is None:
        return state
    age = wall_now - beat.timestamp()
    out = dict(state)
    old = state.get("heartbeat_age_seconds")
    out["heartbeat_age_seconds"] = round(max(age, old if isinstance(old, (int, float)) else 0.0), 3)
    return out


def first_line(knock):
    """A-5: what the watching screen says of the first-finding knock."""
    if not knock:
        return "first finding: none yet (it knocks once, whatever its severity)"
    severity = knock.get("severity")
    return _safe("first finding: %s %s (%s)" % (knock.get("rule_id"), severity, knock.get("status")))


# --- the watch in a worker thread ------------------------------------------------------------

class LogBuffer:
    """Where the watch writes its lines (out and err): kept for the window,
    thread-safe, bounded; tee is the terminal (or app.log) when there is
    one. A tee that fails is a hole (A-8), kept in holes, never dropped."""

    def __init__(self, tee=None, limit=LOG_MAX):
        self.lock = threading.Lock()
        self.parts = []
        self.size = 0
        self.dropped = 0
        self.tee = tee
        self.limit = limit
        self.tee_error = None
        self.holes = []

    def _hole(self, text):
        if text not in self.holes:
            self.holes.append(text)

    def write(self, text):
        text = str(text)
        with self.lock:
            self.parts.append(text)
            self.size += len(text)
            while self.size > self.limit and len(self.parts) > 1:
                gone = self.parts.pop(0)
                self.size -= len(gone)
                self.dropped += len(gone)
            if self.tee is not None:
                try:
                    self.tee.write(text)
                except Exception as exc:   # the terminal went away: the window still has the lines
                    self.tee_error = "%s: %s" % (type(exc).__name__, exc)
                    self.tee = None
                    self._hole("the log's copy to the terminal or app.log failed, and stopped: %s" % self.tee_error)
        return len(text)

    def flush(self):
        with self.lock:
            if self.tee is not None:
                try:
                    self.tee.flush()
                except Exception as exc:
                    self._hole("the log's copy to the terminal or app.log could not be flushed: %s: %s"
                               % (type(exc).__name__, exc))

    def text(self):
        with self.lock:
            head = "[%d earlier characters dropped]\n" % self.dropped if self.dropped else ""
            return head + "".join(self.parts)


class Options:
    """What `raqib app` passes to every watch it starts."""

    def __init__(self, evaluator, rules, gap_seconds, log=None, no_notify=False, port=None, refresh=None,
                 environ=None, home=None, log_project=None, every=None, catalog=None, host_reader=None,
                 host_port=None, attach_hooks=False, host_kw=None, setup=None):
        self.evaluator = evaluator
        # M7.6 (ADR-0008): setup() -> (rules, gap, evaluator), cli's _watch_setup: every watch the window starts
        # loads the catalog with ~/.raqib/rules.d and the overlay afresh, so a change in the Rules panel applies
        # to the next watch (a running watch keeps the rules it started with). None: the rules given (tests).
        self.setup = setup
        # M7.2b (ADR-0007 H-1): the window's checkbox "attach hooks to Claude Code projects", off by default; only
        # when it is ticked does a host watch write into a project (the hook settings), as --attach-hooks does.
        self.attach_hooks = bool(attach_hooks)
        self.host_kw = dict(host_kw or {})   # tests: the HostWatch's sysmon / installer / os_follow fakes
        self.suspect = ""                    # M7.4 E3: the window's "suspect unknown trees" field, empty = off
        self.suspect_every = ""              # M7.6c REDO E-3: its "every N rounds" field, empty = the default (10)
        self.every = hostmod.EVERY_DEFAULT if every is None else every   # M7.3: --every T, the host rounds
        self.catalog = catalog           # M7.3: discover's catalog (None: loaded when the host is read)
        self.host_reader = host_reader   # M7.3: tests give a fake reader; None is the live one
        self.host_port = host_port       # M7.3: the host watch's page port (None: watch --host's default)
        self.rules = rules
        self.gap_seconds = gap_seconds
        self.log = log
        self.log_project = log_project   # A-10: --log is the trace of this project only (the command line's)
        self.no_notify = no_notify
        self.port = port
        self.refresh = refresh
        self.environ = environ
        self.home = home

    def host_catalog(self):
        if self.catalog is None:
            from raqib import discover
            self.catalog = discover.load_catalog(discover.CATALOG)
        return self.catalog

    def reader(self):
        """The host's reader: the live one of `raqib watch --host` (read-only, A4), or a test's."""
        return self.host_reader or hostmod.live_reader(self.host_catalog(), 0.0)

    def rules_now(self):
        """M7.6: the rules (and evaluator) of the next watch, from setup()
        when there is one; a catalog that cannot be loaded is the watch's
        start failure (watch.WatchError), never a crash."""
        if self.setup is None:
            return self.rules
        try:
            self.rules, self.gap_seconds, self.evaluator = self.setup()
        except Exception as exc:
            raise watch.WatchError("the rules could not be loaded: %s" % _safe(exc))
        return self.rules

    def log_for(self, project):
        """A-10: --log for the project named on the command line; any other
        project (one chosen by Browse) gets its default trace (None)."""
        if self.log is None or self.log_project is None:
            return None
        same = os.path.normcase(os.path.abspath(project)) == os.path.normcase(os.path.abspath(self.log_project))
        return self.log if same else None


class Session:
    """One watch of one project, run in a worker thread by watch.start /
    loop / conclude / close. phase: starting, watching, stopping, finished
    (the final report is there) or failed (watch could not start: error).
    holes: what went wrong around the watch (a knock, the worker); A3."""

    def __init__(self, project, options, log=None, starter=None, clock=None, wall=None, steps=None):
        self.project = project
        self.options = options
        self.log = log or LogBuffer()
        self.starter = starter or watch.start
        self.clock = clock or time.monotonic
        self.wall = wall or time.time      # A-2: the heartbeat's age is wall time
        self.steps = steps or watch.first_step
        self.stop_flag = watch.Stop()
        self.lock = threading.Lock()
        self.phase = "starting"
        self.error = None
        self.final_text, self.final_exit = None, None
        self.final_state = None   # REDO C-4: the watch's state once finished, read once by the worker
        self.running = None
        self.holes = []
        self.last_state = None
        self.last_read = None    # monotonic time of the last good read
        self.read_note = None    # why the last read showed an older state
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._work, name="raqib-app-watch", daemon=True)
        self.thread.start()
        return self

    def stop(self, reason):
        """End the watch like Ctrl-C (finish(), the final report)."""
        with self.lock:
            if self.phase in ("starting", "watching"):
                self.phase = "stopping"
        self.stop_flag.set(reason)

    def alive(self):
        return self.thread is not None and self.thread.is_alive()

    def _hole(self, text):
        with self.lock:
            if text not in self.holes:
                self.holes.append(text)

    START_FAILED = "the watch did not start: %s"
    REFUSAL = False   # M6.4: a project watch that did not start is exit 1
    refused = False

    def _open(self):
        """watch.start for this project (raises watch.WatchError)."""
        o = self.options
        o.rules_now()   # M7.6: the overlay as it is now
        return self.starter(self.project, o.log_for(self.project), True, o.no_notify, o.port, self.log,
                            o.evaluator, o.rules, o.gap_seconds, environ=o.environ, err=self.log,
                            home=o.home, refresh=o.refresh)

    def _loop(self, running):
        return watch.loop(running, self.stop_flag, on_step=self._step)

    def _conclude(self, running, crash):
        return watch.conclude(running, crash)

    def _close(self, running):
        watch.close(running)

    def _work(self):
        try:
            try:
                running = self._open()
            except watch.WatchError as exc:
                with self.lock:
                    self.phase, self.error = "failed", self.START_FAILED % exc
                    self.refused = self.REFUSAL   # F-8: a host watch refused (C-2, D-6) is exit 2
                return
            with self.lock:
                self.running = running
                if self.phase == "starting":
                    self.phase = "watching"
            try:
                crash = self._loop(running)
                text, code = self._conclude(running, crash)
                final = self._final_state(running)   # REDO C-4: the holes finish() added, read once, here
                with self.lock:   # A-8: the final report is kept before close() runs
                    self.final_text, self.final_exit = text, code
                    self.final_state = final
            finally:
                try:
                    self._close(running)
                except Exception as exc:   # A-8: the report and its exit stay; the failed close is a hole
                    self.log.write(traceback.format_exc())
                    self._hole("the watch did not close cleanly (page server or notifier): %s: %s"
                               % (type(exc).__name__, exc))
            with self.lock:
                self.phase = "finished"
        except Exception as exc:   # A3: a crashed worker is a hole in the window, never silence
            self.log.write(traceback.format_exc())
            with self.lock:
                self.error = "the watch worker crashed: %s: %s" % (type(exc).__name__, exc)
                if self.final_text is not None:
                    self.phase = "finished"
                elif self.phase != "finished":
                    self.phase = "failed"
                if self.error not in self.holes:
                    self.holes.append(self.error)

    def _final_state(self, running):
        """REDO C-4: the watch's state once finished (what finish() added -
        a reader out, the last source poll, what was never sent - with it),
        read once in the worker under the watch's lock; None and a hole when
        it cannot be read."""
        try:
            watcher = running.watcher
            with watcher.lock:
                return copy.deepcopy(watcher.state(watcher.clock()))
        except Exception as exc:
            self._hole("the watch's final state could not be read: %s: %s" % (type(exc).__name__, exc))
            return None

    def _step(self, watcher):
        """After every poll, in the worker: the first-finding knock (E3),
        the same step as `raqib watch` in a terminal (A-12)."""
        try:
            done = self.steps(self.running)
            if done is not None and done["status"] == "failed":
                self._hole("the first-finding knock was not delivered (%s); see the notifier's holes" % done["where"])
        except Exception as exc:
            self._hole("the first-finding knock failed: %s: %s" % (type(exc).__name__, exc))

    def state(self):
        """A copy of the watch's state, read under the Watch lock; the last
        one (and read_note, with how old it is) when the lock is held longer
        than LOCK_SECONDS. Either way the heartbeat's age is recomputed now
        from the wall clock (A-2)."""
        running = self.running
        if running is None:
            return None
        watcher = running.watcher
        if not watcher.lock.acquire(timeout=LOCK_SECONDS):
            ago = (self.clock() - self.last_read) if self.last_read is not None else None
            self.read_note = ("the watch held its state for more than %g s at the last read; the state shown was"
                              " read %s ago" % (LOCK_SECONDS, "%d s" % ago if ago is not None else "never"))
            return aged(self.last_state, self.wall())
        try:
            state = copy.deepcopy(watcher.state(watcher.clock()))
        except Exception as exc:
            self.read_note = "the window could not read the watch's state: %s: %s" % (type(exc).__name__, exc)
            return aged(self.last_state, self.wall())
        finally:
            watcher.lock.release()
        self.read_note = None
        self.last_state = state
        self.last_read = self.clock()
        return aged(state, self.wall())

    def snapshot(self):
        knock = getattr(self.running, "knock", None) if self.running is not None else None
        with self.lock:
            return {"phase": self.phase, "error": self.error, "final_text": self.final_text,
                    "final_exit": self.final_exit, "holes": list(self.holes) + list(self.log.holes),
                    "knock": dict(knock.knocked) if knock is not None and knock.knocked else None}


# --- the host screen (M7.3, ADR-0007 decision 5) -----------------------------------------------

NOT_CLEARANCE = "Not a clearance."


def empty_line(records, holes):
    """E1: what the host screen says when no tree is seen, with what was read."""
    return "no agent seen (%s records, %s holes). %s" % (records, holes, NOT_CLEARANCE)


def tree_kind(tree):
    """F-5 (A2): the kind word, in the order named, unknown, benign: a named
    tree is never shown as benign (an agent that takes a benign program's
    name is C-1d's evasion), so "named, benign image" says both. Then what the
    watch knows of the tree: act-root, history (there at the start, not
    knocked), new (it knocked), gone."""
    if tree.get("named"):
        word = "named, benign image" if tree.get("benign") else "named"
    else:
        word = "benign" if tree.get("benign") else "unknown"
    flags = []
    if tree.get("class") == "act-root":
        flags.append("act-root")
    if tree.get("history"):
        flags.append("history")
    if tree.get("knocked"):
        flags.append("new")
    if tree.get("quiet"):   # M8.1 REDO A-13(d), ADR-0007 P-2: a tree the state marks quiet is never said gone
        flags.append("quiet")
    elif tree.get("present") is False:
        flags.append("gone")
    return "%s%s" % (word, " (%s)" % ", ".join(flags) if flags else "")


def host_rows(trees, first_seen=None):
    """E1: one row per tree: image, pid, named/unknown/benign, first seen,
    acts, endpoints. Never a command line, never a cited record's text, never
    the executable's path (what the window shows of a process is its name)."""
    rows = []
    for t in trees:
        if not isinstance(t, dict):
            continue
        rows.append((_safe(t.get("image") or "?"), _safe(t.get("pid")), tree_kind(t),
                     _safe(t.get("first_seen") or first_seen or "-"), _safe(t.get("acts", 0)),
                     _safe(source_word(t)), _safe(ui.severity_counts(t.get("source_findings"))),
                     _safe(rhythm_cell(t)),   # M7.4 E4; REDO C-7: a suspicion first
                     _safe(", ".join(str(e) for e in t.get("endpoints") or ()) or "-")))
    return rows


def rhythm_cell(t):
    """REDO C-7 (A2): the rhythm cell with a raised suspicion first, so an
    ellipsis cut at the column's width never hides it; else as
    ui.tree_rhythm_text says the rhythm."""
    if not t.get("suspicion"):
        return ui.tree_rhythm_text(t)
    rest = ui.tree_rhythm_text(dict(t, suspicion=None))
    first = "suspicion %.2f (%s)" % (t.get("suspicion") or 0, t.get("suspect_knock"))
    return first if rest == "-" else "%s; %s" % (first, rest)


def _of_tree(item, tree):
    """Whether a host finding, suspicion or dark note is of this tree (its
    tree key, its tree word, or its live tree)."""
    key = tree.get("key")
    word = hostmod.tree_word(tuple(key)) if isinstance(key, (list, tuple)) and len(key) == 3 else None
    if item.get("tree_key") is not None:
        return list(item.get("tree_key")) == list(key or ())
    return word is not None and word in (item.get("tree"), item.get("live_tree"))


def source_line(f):
    """REDO C-5: a source's finding in the detail pane, with its word (as the
    row's cell counts it) and its cite (A5)."""
    return _safe("%s [%s] %s: %s; source %s %s" % (
        f.get("rule_id"), f.get("severity"), f.get("count_word") or ("history" if f.get("history") else "live"),
        f.get("summary"), f.get("trace"), watch.seq_text(list(f.get("cited_seq") or []))))


def tree_words(t, round_now=None):
    """REDO C-5 (ADR-0007 Amendment W): what the state says of a tree in its
    own words: the benign word and what knocked on it, quiet and its round,
    "not judged this round", the os events before the watch's start."""
    out = []
    if t.get("benign"):
        out.append(_safe(t.get("benign_word") or "benign") + (
            "; knocked here: %s" % ", ".join(map(str, t["benign_knocked"])) if t.get("benign_knocked") and
            "knocked here" not in str(t.get("benign_word")) else ""))
    if t.get("quiet"):
        out.append(_safe(t.get("quiet_text") or "quiet") + (" (round %s)" % t["quiet_round"] if t.get("quiet_round")
                                                           is not None else ""))
    if t.get("not_judged_round") is not None and t.get("not_judged_round") == round_now:
        out.append("not judged this round (round %s)" % t["not_judged_round"])
    if t.get("before_start"):
        out.append("%s os event(s) before the watch's start: history (never knocked)" % _safe(t["before_start"]))
    return out


def tree_details(trees, findings=(), suspicions=(), notes=(), sources=(), round_now=None):
    """E2: what the detail pane says of each tree, aligned with host_rows:
    its acts, class, source, cites (where: src:line, never the record's
    text), its findings and suspicions as the finding lines say them, and
    its notes. REDO C-5: it counts what its row counts - the tree's source
    findings that the watch counts as alarms are findings, a note on a
    benign tree, history and a copy judged on another tree are notes - and
    says the tree's own words (tree_words). Nothing here is not already in
    the host state."""
    out = []
    for t in trees:
        if not isinstance(t, dict):
            continue
        mine = [f for f in sources if isinstance(f, dict) and _of_tree(f, t)]
        out.append({
            "acts": _safe(t.get("acts", 0)), "class": _safe(t.get("class") or "-"),
            "started": _safe(t.get("started") or "-"),
            "cites": [_safe("%s:%s" % (c.get("src"), c.get("line")))
                      for c in t.get("cites") or () if isinstance(c, dict)],
            "findings": [host_finding_line(f) for f in findings if isinstance(f, dict) and _of_tree(f, t)]
            + [suspicion_line(f) for f in suspicions if isinstance(f, dict) and _of_tree(f, t)]
            + [source_line(f) for f in mine if source_alarm(f)],
            "notes": [_safe(d.get("text")) for d in notes if isinstance(d, dict) and _of_tree(d, t)]
            + [source_line(f) for f in mine if not source_alarm(f)],
            "words": tree_words(t, round_now)})
    return out


def tree_detail_text(row, detail=None):
    """E2: the detail pane's text for the selected tree (a host_rows row and
    its tree_details entry)."""
    detail = detail or {}
    get = (lambda i: row[i] if i < len(row) else "-")
    out = ["%s pid %s: %s" % (get(0), get(1), get(2)),
           "class %s, started %s, first seen %s, acts %s" % (detail.get("class", "-"), detail.get("started", "-"),
                                                             get(3), detail.get("acts", get(4))),
           "source: %s; its findings: %s" % (get(5), get(6)),
           "rhythm / suspicion: %s" % get(7),
           "endpoints: %s" % get(8),
           "cites: %s" % (", ".join(detail.get("cites") or ()) or "-")]
    out += list(detail.get("words") or ())   # REDO C-5: the tree's own words, from the state
    out += ["", "FINDINGS: %d" % len(detail.get("findings") or ())]
    out += ["  - %s" % f for f in detail.get("findings") or ()]
    out += ["", "NOTES (not alarms): %d" % len(detail.get("notes") or ())]
    out += ["  - %s" % n for n in detail.get("notes") or ()]
    return "\n".join(out) + "\n"


def source_word(tree):
    """M7.2b E4: the source column: os / host / hooks: project P / none, or
    "-" where no source is attached yet (the look at open attaches none)."""
    src = tree.get("source")
    if src is None:
        return "-"
    if src == "hooks":
        return "hooks: project %s" % os.path.basename(str(tree.get("source_project") or "").rstrip("/\\")) \
            if tree.get("source_project") else "hooks"
    return str(src)


ATTACH_TEXT = "attach hooks to Claude Code projects"   # M7.2b (ADR-0007 H-1): the checkbox, off by default
SUSPECT_TEXT = "suspect unknown trees"   # M7.4 E3: the field, empty (off) by default: ollama[:M], anthropic[:M]
CODE_LEVELS = {0: "clean", 1: "alarm", 3: "incomplete"}   # F-7: C-10's exit codes; 0 green, 1 red, 3 amber


def code_level(code):
    """F-7: C-10's code -> level, through level_of (REDO C-1); not a code: alarm."""
    return level_of(code if isinstance(code, int) and not isinstance(code, bool) else -1)


def dark_line(d):
    """F-1: an AGENT-DARK footprint of the look, as its own line."""
    return _safe("AGENT-DARK %s footprint %s: no tree in the round talks and acts as %s (cites %s)" % (
        d.get("agent"), d.get("path"), d.get("agent"),
        " ".join("%s:%s" % (c.get("src"), c.get("line")) for c in d.get("cites") or ()) or "-"))


def probe_view(inv, catalog, at, seconds=None, late=False, deadline=None):
    """E1: the host screen after the discover round at open (the look): its
    trees (as the host watch keys them, hostmod.trees_of), its AGENT-DARK
    footprints as their own lines, and its holes listed with their count
    (F-1). The level is never read from discover's result word: it follows
    C-10's codes (F-7): 3 (amber, incomplete) when a source was not read or
    partly read, a line could not be parsed, nothing was read, the inventory
    says it is incomplete or the reader was late - trees or not; else 1 (red)
    when a tree or an AGENT-DARK footprint is seen; 0 (green) only when it
    read records with none of these and found no tree, and then it says
    "Not a clearance.". A round that read
    nothing is NOTHING READ, never "no agent seen" (D-2). Nothing here is
    knocked: it is one look."""
    records, inv_holes = inv.get("records"), [str(h) for h in inv.get("holes") or []]
    trees = list(hostmod.trees_of(inv, catalog).values())
    dark = [d for d in inv.get("agent_dark") or [] if isinstance(d, dict)]
    unread = hostmod.unread_sources(inv)
    problems = inv.get("problems") or []
    nothing = hostmod.nothing_read(inv)
    took = " (late, %.1f s)" % seconds if late and seconds is not None else ""
    holes = []
    if late:
        holes.append("reader-late: the round at open came back after %.1f s, past its deadline %g s (2 x T)" % (
            seconds or 0, deadline or 0))
    holes += ["unread source: %s" % r for r in unread]
    holes += ["incomplete: %s" % r for r in inv.get("incomplete") or [] if str(r) not in unread]
    if problems:
        holes.append("%d line(s) could not be read (A3): %s" % (len(problems), "; ".join(
            hostmod.cite_text("%s:%s %s" % (p.get("src"), p.get("line"), p.get("reason")) if isinstance(p, dict)
                              else str(p)) for p in problems[:3])))
    holes += ["inventory: %s" % h for h in inv_holes]
    blind = bool(unread or problems or nothing or inv.get("incomplete") or late)
    code = 3 if blind else 1 if trees or dark else 0   # F-1: a partly blind look is incomplete, trees or not
    lines = [dark_line(d) for d in dark]
    counts = "%s records read, %d holes" % (records, len(holes))
    if nothing:
        word = "NOTHING READ"
        detail = "the round at open%s read no record from any source: an unread round. %s" % (took, NOT_CLEARANCE)
        lines.append("nothing read (%s records, %d holes): no agent is said seen or unseen. %s" % (
            records, len(holes), NOT_CLEARANCE))
    elif not trees:
        word = "NO AGENT SEEN" if not blind else "NO AGENT SEEN, PARTLY BLIND"
        detail = "the round at open%s: %s; one look, not a watch. %s" % (took, counts, NOT_CLEARANCE)
        lines.insert(0, empty_line(records, len(holes)))
    else:
        word = "HOST: %d TREE(S)" % len(trees)
        detail = ("the round at open%s: %s%s; %d tree(s) that talk and act, listed, not knocked"
                  " (one look; \"Watch this host\" watches it)" % (
                      took, counts, "; partly blind (see the holes)" if blind else "", len(trees)))
    if dark:
        detail += "; %d AGENT-DARK footprint(s)" % len(dark)
    return {"word": word, "level": code_level(code), "code": code, "detail": _safe(detail),
            "rows": host_rows(trees, first_seen=at), "details": tree_details(trees),
            "lines": [_safe(x) for x in lines], "findings": [],
            "holes": [_safe(h) for h in holes], "badges": [], "final": None, "trees": len(trees), "new": 0,
            "dark": len(dark), "records": records, "unread": unread}


def host_finding_line(f):
    """F-4 (A5): a host finding cites (run, seq) as finding_line cites seqs."""
    where = f.get("tree") or f.get("path")
    seqs = f.get("cited_seq") or []
    beats = "".join("; talk round %s seq %s, act round %s seq %s" % (
        b.get("talk_round"), b.get("talk_seq"), b.get("round"), b.get("seq"))
        for b in f.get("beats") or () if isinstance(b, dict))   # K-7: rhythm beats carry round and seq
    return _safe("%s [%s] round %s: %s: %s [%s] cites run %s %s%s" % (
        f.get("rule_id"), f.get("severity"), f.get("round"), where, f.get("summary"), f.get("notice"),
        f.get("run"), watch.seq_text(list(seqs)), beats))


def suspicion_line(f):
    """M7.4 E4 (A2, A5): a raised suspicion on a tree, as a finding line,
    citing the seqs of the tree's source file."""
    return _safe("SUSPECT [suspicion %.2f] round %s: %s: %s [%s] by %s/%s cites %s seq %s" % (
        f.get("suspicion") or 0, f.get("round"), f.get("tree"), "; ".join(f.get("reasons") or []), f.get("notice"),
        f.get("backend"), f.get("model"), f.get("trace"), ",".join(str(x) for x in f.get("cited_seq") or [])))


SUSPECT_EVERY_TEXT = "every N rounds"   # M7.6c REDO E-3: the suspect period, a watch option (--suspect-every)


def suspect_every_spec(text):
    """M7.6c REDO E-3: the window's "every N rounds" field: empty is the
    default (None: host.SUSPECT_EVERY); else a whole number of rounds as
    --suspect-every takes it. (value or None, error or None)."""
    text = str(text or "").strip()
    if not text:
        return None, None
    if not (text.isdigit() and text.isascii()):
        return None, "must be a whole number of rounds, not %r" % text
    try:
        return hostmod.check_suspect_every(int(text)), None
    except ValueError as exc:
        return None, str(exc)


def suspect_spec(text):
    """M7.4 E3: the window's "suspect unknown trees" field: empty (the
    default) is off; else a backend spec as --suspect takes it
    (ollama[:MODEL], anthropic[:MODEL], fake:FILE). (backend or None,
    error or None)."""
    text = (text or "").strip()
    if not text:
        return None, None
    try:
        return hostmod.suspect_backend(text), None
    except ValueError as exc:
        return None, str(exc)


def host_watch_view(state, extra_holes=()):
    """E2: the host screen while the host is watched, from HostWatch's state
    (mode host): the band word of ui.status (READER LATE and HOST READER
    FAILED before WATCHING, C-7), NOTHING READ for a round that read nothing
    (D-2), else WATCHING HOST; the trees, the NEW-AGENT and AGENT-DARK-LIVE
    lines, the holes."""
    word, level, detail = ui.status(state)
    if word == "FINISHED":   # REDO C-7: the host watch's own sentence, never the project's
        word = "HOST WATCH FINISHED"
    age, _ = stale_age(state)
    h = state.get("host") if isinstance(state.get("host"), dict) else {}
    last = h.get("last_round") if isinstance(h.get("last_round"), dict) else {}
    if age is not None:
        word, level = "CRASHED or stuck (%d s)" % age, "alarm"
    elif word == "WATCHING":
        if last.get("nothing_read"):
            word, level = "NOTHING READ", "alarm"
            detail = "round %s at %s read no record from any source: an unread round. %s" % (
                last.get("round"), last.get("at"), NOT_CLEARANCE)
        else:
            word = "WATCHING HOST"
            if level == "clean":   # F-7: every green state says it
                detail = "%s. %s" % (detail, NOT_CLEARANCE)
    trees = [t for t in h.get("trees") or [] if isinstance(t, dict)]
    lines = []
    if not trees:
        if last and not last.get("error") and not last.get("nothing_read"):
            lines.append(empty_line(last.get("records"), last.get("holes")))
        elif not last:
            lines.append("no round has given an inventory yet")
    holes = [hole_line(x) for x in state.get("holes") or [] if isinstance(x, dict)] + [_safe(x) for x in extra_holes]
    if state.get("code_error"):   # REDO C-2: the host watch could not compute its code
        holes.append(_safe("the watch could not judge itself: %s" % state["code_error"]))
    findings = [host_finding_line(f) for f in h.get("findings") or [] if isinstance(f, dict)]
    findings += [suspicion_line(f) for f in h.get("suspicions") or [] if isinstance(f, dict)]   # M7.4 E4
    # M7.5 E1/E4: notes apart from the findings (a note is never an alarm)
    notes = [_safe(d.get("text")) for d in h.get("dark_notes") or [] if isinstance(d, dict)]
    return {"word": word, "level": level, "detail": _safe(detail), "rows": host_rows(trees),
            "details": tree_details(trees, h.get("findings") or (), h.get("suspicions") or (),
                                    h.get("dark_notes") or (), h.get("source_findings") or (),
                                    h.get("rounds")),   # M7.6b E2: the detail pane; REDO C-5
            "lines": lines, "findings": findings, "notes": notes, "holes": holes,
            "badges": [(lv, _safe(text)) for lv, text in ui.host_band(state)], "final": None,
            "trees": h.get("now") or 0, "new": h.get("new") or 0, "url": state.get("url") or "-",
            "suspicions": len([f for f in h.get("suspicions") or [] if isinstance(f, dict)])}   # REDO C-4: apart


LOOK_NAME = "look.json"


class HostProbe:
    """E1: one discover round at open (the look), the host watch's reader in
    a worker thread (hostmod.Worker), with the watch's deadline (2 x T). It
    knocks nothing and is not round 1 (history begins at "Watch this host",
    F-10). view(now) is the host screen's state of it: reading, late (a hole
    in the band, kept when the reader comes back late, F-3), failed, or the
    trees. F-10: the look is written to ~/.raqib/host/look.json (the latest
    only: its word, level, trees, dark footprints, holes and the reader's
    timing), when it comes back and when it is first seen late."""

    def __init__(self, reader, catalog, deadline, clock=None, wall=None, home=None):
        self.reader = reader
        self.catalog = catalog
        self.deadline = deadline
        self.clock = clock or time.monotonic
        self.wall = wall or time.time
        self.home = home
        self.worker = None
        self.began = None
        self.at = None
        self.seen_late = False   # F-3: the look was READER LATE at some view; that hole stays when it comes back
        self.written = None      # F-10: what look.json holds now ("late", "done"), or None
        self.write_error = None

    def start(self):
        import datetime
        self.began = self.clock()
        self.at = hostmod.iso(datetime.datetime.fromtimestamp(self.wall(), datetime.timezone.utc))
        self.worker = hostmod.Worker(self.reader)
        return self

    def done(self):
        return self.worker is not None and self.worker.done()

    def path(self):
        return os.path.join(hostmod.host_dir(self.home), LOOK_NAME)

    def view(self, now=None):
        now = self.clock() if now is None else now
        view = self._view(now)
        if self.home is not None:
            stage = "done" if self.done() else "late" if view["word"] == "READER LATE" else None
            if stage is not None and stage != self.written:
                self._write(view, now, stage)
        if self.write_error:
            view = dict(view, holes=view["holes"] + [self.write_error])
        return view

    def _write(self, view, now, stage):
        out = self.worker.outcome if self.worker is not None else None
        record = {"raqib_look": 1, "at": self.at, "stage": stage, "deadline_seconds": self.deadline,
                  "reader_seconds": round(out[2], 3) if out else None,
                  "reader_out_seconds": None if out else round(now - self.began, 3),
                  "word": view["word"], "level": view["level"], "code": view.get("code"), "detail": view["detail"],
                  "rows": [list(r) for r in view["rows"]], "lines": view["lines"], "holes": view["holes"],
                  "records": view.get("records"), "trees": view.get("trees"), "dark": view.get("dark"),
                  "note": "the first look of raqib app: not a round of the host watch; history begins at"
                          " \"Watch this host\" (ADR-0007 F-10)"}
        try:
            os.makedirs(os.path.dirname(self.path()), exist_ok=True)
            hostmod.write_json(self.path(), record)
            self.written, self.write_error = stage, None
        except OSError as exc:
            self.write_error = "look.json was not written (%s): %s" % (self.path(), exc.strerror or exc)
            self.written = stage

    def _view(self, now):
        out = self.worker.outcome if self.worker is not None else None
        late = now - self.began >= self.deadline if self.began is not None else False
        if out is None:
            if late:
                self.seen_late = True
                return dict(_empty_view(), word="READER LATE", level="incomplete", code=3, detail=(
                    "the reader of the round at open is not back after %d s (deadline %g s): a hole; the host is not"
                    " read yet" % (now - self.began, self.deadline)),
                    holes=["reader-late: the round at open was not back within %g s (2 x T)" % self.deadline])
            return dict(_empty_view(), word="READING HOST", level="incomplete",
                        detail="reading the host... (one discover round, read-only; deadline %g s)" % self.deadline)
        inv, error, seconds = out
        if error:
            return dict(_empty_view(), word="HOST READER FAILED", level="incomplete", code=3,
                        detail="the reader of the round at open failed: %s" % _safe(error),
                        holes=["reader-failed: the round at open: %s" % _safe(error)])
        try:
            return probe_view(inv, self.catalog, self.at, seconds, late=seconds > self.deadline or self.seen_late,
                              deadline=self.deadline)
        except Exception as exc:   # A3: an inventory the window cannot show says so
            return dict(_empty_view(), word="HOST READER FAILED", level="incomplete", code=3,
                        detail="the inventory of the round at open could not be shown: %s: %s" % (
                            type(exc).__name__, _safe(exc)),
                        holes=["the inventory of the round at open could not be shown: %s" % type(exc).__name__])


def _empty_view():
    return {"word": "", "level": "incomplete", "code": None, "detail": "", "rows": [], "lines": [], "findings": [],
            "holes": [], "badges": [], "final": None, "trees": 0, "new": 0}


class HostSession(Session):
    """E2: the host watch of `raqib watch --host` - host.start, host.loop
    with this Stop, host.conclude, host.close - in a worker thread, a
    sibling of the project Session. The knocks are HostWatch's own, through
    its Notifier (C-5: each tree under its own rate-limit id); the page is
    served, not opened. A second host watch on this home is refused by
    HostWatch (C-2, D-6): the refusal is this session's error, shown as a
    hole line, never a crash."""

    START_FAILED = "the host watch did not start: %s"
    REFUSAL = True    # F-8: the start was refused (one host watch per home), exit 2

    def __init__(self, options, log=None, starter=None, clock=None, wall=None, wait_for=None):
        super().__init__(hostmod.HOST, options, log=log, starter=starter or hostmod.start, clock=clock, wall=wall,
                         steps=lambda running: None)
        self.wait_for = wait_for   # F-3: the look's reader thread; round 1's reader waits for it

    def reader(self):
        """The watch's reader. F-3: never two readers at once - the first
        round's reader waits for the look's reader to be back (HostWatch's
        own deadline still holds: a look that never returns makes round 1
        late, a hole)."""
        real = self.options.reader()
        look = self.wait_for

        def read():
            if look is not None and look.is_alive():
                self.log.write("raqib app: round 1 waits for the reader of the round at open (never two readers)\n")
                look.join()
            return real()
        return read

    def _open(self):
        o = self.options
        kw = dict(o.host_kw)
        backend, error = suspect_spec(getattr(o, "suspect", ""))   # M7.4 E3: the field's word for this watch
        if error:
            raise watch.WatchError("%s: %s" % (SUSPECT_TEXT, error))
        if backend is not None:
            kw["suspect"] = backend
        period, error = suspect_every_spec(getattr(o, "suspect_every", ""))   # M7.6c REDO E-3
        if error:
            raise watch.WatchError("suspect %s: %s" % (SUSPECT_EVERY_TEXT, error))
        if period is not None:
            kw["suspect_every"] = period
        o.rules_now()   # M7.6: the overlay as it is now
        return self.starter(o.host_catalog(), o.rules, every=o.every, no_open=True, no_notify=o.no_notify,
                            port=o.host_port, out=self.log, err=self.log, environ=o.environ, home=o.home,
                            refresh=o.refresh, reader=self.reader(), attach_hooks=o.attach_hooks, **kw)

    def _loop(self, running):
        return hostmod.loop(running, self.stop_flag)

    def _conclude(self, running, crash):
        return hostmod.conclude(running, crash)

    def _close(self, running):
        hostmod.close(running)


# --- the Rules panel (M7.6, ADR-0008 decisions 1, 4, 5) ----------------------------------------------------

RULES_INTRO = ("Rules: what the next watch judges with. On / Off and a threshold change ~/.raqib/rules.yaml only;"
               " Add copies a rule file, checked by the loader and the fixture runner, into ~/.raqib/rules.d."
               " Nothing here reaches a watched agent or a project (A4). A threshold is measured before it is"
               " allowed: the rule's fixtures are made at the new value and run (ok / refused: why).")


class RulesPanel:
    """The Rules screen's logic, without Tk: the listing of every rule as
    the next watch loads it (overlay.load), and the changes - on / off, a
    threshold within its bounds, Add (a file, validated), Reset - each
    through raqib/overlay.py, which writes ~/.raqib/rules.yaml and copies
    into ~/.raqib/rules.d and nothing else (A4). message: the last change's
    line, or its refusal with the reason; level: clean or alarm."""

    def __init__(self, home=None, catalog=None, say=None):
        self.home = home
        self.catalog = catalog
        # M7.6c REDO E-7: told when a measurement of the overlay's thresholds runs (the window's band says it); a
        # reload with nothing changed since the last measurement measures nothing (rules.measured.json)
        self.say = say
        self.measuring = []   # the lines said (tests read them)
        self.rows, self.info, self.error, self.titles = [], None, None, {}
        self.message, self.level = None, "clean"
        self.form_passed = None   # M8.2: the fingerprint of the answers whose Test passed
        self.reload()

    def _say(self, line):
        self.measuring.append(line)
        if self.say is not None:
            self.say(line)

    def reload(self):
        try:
            rules = overlay.load(self.home, self.catalog, say=self._say)
            self.rows, self.info, self.error = overlay.listing(rules), overlay.describe(rules), None
            self.titles = {r.id: getattr(r, "title", "") for r in rules}   # M8.1 E5: the YAML's title, shown
        except Exception as exc:   # A3: a catalog that cannot be loaded is said, never a crash
            self.rows, self.info, self.titles = [], None, {}
            self.error = "the rules could not be loaded: %s: %s" % (type(exc).__name__, _safe(exc))
        return self

    def _do(self, change, *args, running=False, **kw):
        try:
            said = change(*args, home=self.home, catalog=self.catalog, **kw)
            self.message, self.level = said + (
                "; a watch is running: it keeps the rules it started with" if running else ""), "clean"
        except overlay.OverlayError as exc:
            self.message, self.level = "REFUSED: %s" % exc, "alarm"
        except Exception as exc:   # M8.2 REDO 3 G-5: whatever else fails is a refusal with words, never nothing
            self.message, self.level = "REFUSED: the change could not be made: %s: %s" % (
                type(exc).__name__, _safe(exc)), "alarm"
        self.reload()
        return self.message

    def set(self, rule_id, on, running=False):
        return self._do(overlay.set_status, str(rule_id or "").strip(), "on" if on else "off", running=running)

    def threshold(self, rule_id, field, value, running=False):
        """M7.6c (ADR-0008 Amendment B): the change and its measurement's
        result: "threshold ok (measured): ..." with what was measured, or
        "REFUSED: threshold refused: <why>" (the fixture named)."""
        self._do(overlay.set_threshold, str(rule_id or "").strip(), str(field or "").strip(), str(value or ""),
                 running=running, say=self._say)   # E-7: measured on set (the band says it while it runs)
        if self.level == "clean":
            self.message = "threshold ok (measured): %s" % self.message
        elif self.level == "alarm" and self.message.startswith("REFUSED: "):
            self.message = "REFUSED: threshold refused: %s" % self.message[len("REFUSED: "):]
        return self.message

    def reset(self, rule_id, running=False):
        return self._do(overlay.reset, str(rule_id or "").strip(), running=running)

    def add(self, path, running=False):
        if not path:
            self.message, self.level = "no file chosen: nothing added", "incomplete"
            return self.message
        return self._do(overlay.add_rule, path, running=running)

    def remove_rule(self, rule_id, running=False, place=None):
        """M8.2 E4: a person's rule removed from rules.d with its overlay lines (overlay.remove_rule); a
        package rule refused ("switch it off instead"). place: the row's own entry of rules.d (REDO 2 F-3:
        Remove acts on it, never on a name looked up again)."""
        return self._do(overlay.remove_rule, str(rule_id or "").strip(), running=running, place=place)

    def refused_rows(self):
        """M8.2 REDO E-6: a row for each person's rule refused at load (its folder or loose file is in rules.d),
        so it can be removed from the window - with its own place (REDO 2 F-3); a place Raqib could not have
        written (a folder whose name is no id) has no Remove: the row gives its path, to delete it by hand."""
        out = []
        rules_d = (self.info or {}).get("user_dir")
        try:   # REDO 3 G-5: a rules.d that cannot be listed is said on each row, never a crash while drawing
            kinds, unlisted = dict(overlay.user_entries(rules_d)), None
        except Exception as exc:
            kinds, unlisted = {}, "%s could not be listed (%s: %s): Remove is not offered" % (
                rules_d, type(exc).__name__, exc)
        for u in (self.info or {}).get("user_refused_ids") or ():
            place = u.get("place") or u["rule_id"]
            kind = kinds.get(place, "other")
            path = os.path.join(rules_d or "", place)
            unread = unlisted   # H-3: one row's failure is that row's, never the next row's
            try:
                link = kind == "other" and overlay.is_link(path)
            except Exception as exc:   # an entry that cannot be looked at: said, no Remove
                link, unread = False, unlisted or "%s cannot be read (%s: %s): Remove is not offered" % (
                    path, type(exc).__name__, exc)
            out.append({"id": u["rule_id"], "kind": "-", "class": "-", "severity": "-", "budget": 0, "status": "off",
                        "off_by": "refused", "origin": "user", "thresholds": [], "fixed": [], "refused": u["reason"],
                        "place": place, "removable": unread is None and overlay.removable(place, kind),
                        "path": path, "no_remove": unread or (BY_HAND_LINK if link else BY_HAND)})
        return out

    def origin(self, rule_id):
        return next((r["origin"] for r in self.rows if r["id"] == rule_id), None)

    def test_form(self, answers):
        """M8.2 E1-E3: the form's Test - ruleform.test (staged, judged by the engine, run on the records;
        nothing written in rules.d). A pass remembers the answers' fingerprint: Add is for those only."""
        res = ruleform.test(answers, self.home, self.catalog)
        self.form_passed = ruleform.fingerprint(answers) if res.ok else None
        return res

    def can_add(self, answers):
        return self.form_passed is not None and self.form_passed == ruleform.fingerprint(answers)

    def add_form(self, answers, running=False):
        """M8.2 E2: the form's Add, after a passing Test of the same answers: ruleform.add (overlay.add_rule's
        path); the message said as every change is."""
        if not self.can_add(answers):
            res = ruleform.Result()
            res.refusals = [("rule", "Test these answers first: Add is for answers that passed a Test")]
            return res
        res = ruleform.add(answers, self.home, self.catalog)
        if res.ok:
            self.message, self.level = res.said + (
                "; a watch is running: it keeps the rules it started with" if running else ""), "clean"
            self.form_passed = None
        else:
            self.message, self.level = "REFUSED: %s" % "; ".join(res.text()), "alarm"
        self.reload()
        return res

    def header(self):
        """The header's word: "N rules off: <ids>" (or "no rule off")."""
        if self.info is None:
            return "rules: not loaded"
        return overlay.off_text(self.info) or "no rule off"

    def notes_text(self):
        """M7.6b E3: the screen's text under the Rules table (the rows are
        in the Treeview): text() without the table."""
        return self.text(table=False)

    def text(self, table=True):
        """The screen's text: the intro, the table, what the overlay applied
        or refused, the last change."""
        out = [RULES_INTRO, ""]
        if self.error:
            out.append("HOLE: %s" % self.error)
        else:
            if table:
                out.append(overlay.table_text(self.rows).rstrip("\n"))
                out.append("")
            out += overlay.start_lines(self.info)
        if self.message:
            out += ["", self.message]
        return "\n".join(_safe(line) for line in out) + "\n"


class Controller:
    """What a close, Stop, Start or a tray action does, without Tk. Tray
    actions arrive from the tray thread through a queue, read by drain()."""

    def __init__(self, options, tray=None, make_session=None, tee=None, clock=None, opener=None, make_host=None):
        self.options = options
        self.tray = tray
        # each watch has its own LogBuffer; tee is the terminal (or app.log) when there is one
        self.make_session = make_session or (lambda project: Session(project, options, log=LogBuffer(tee=tee)))
        # M7.3: the host watch, a sibling of the project watch; both may run at once
        self.make_host = make_host or (lambda: HostSession(options, log=LogBuffer(tee=tee), wait_for=self.look_thread()))
        self.session = None
        self.host = None
        self.tip = traymod.IDLE_TIP   # what the tray's tooltip says now (M7.6b E5: "Raqib: N trees, K new, F findings")
        self.actions = queue.Queue()
        self.quitting = False
        self.quit_at = None     # A-3: when Quit was asked (monotonic)
        self.clock = clock or time.monotonic
        self.opener = opener or watch.open_page
        self.tee = tee
        self.page_note = None   # what the last "Open page" said (A-13)
        self.notes = []   # by design, not holes: "no tray on this platform"
        self.probe = None        # M7.3 E1: the discover round at open (HostProbe)
        self.probe_error = None
        self.host_note = None    # why "Watch this host" did not start
        self.past = []           # F-8: the watches a new Start replaced; their reports and exits are kept
        self.reported = set()    # F-8: id() of the sessions whose final report was appended to the log
        self.look_logged = set() # F-3: the look's holes already written to the log
        self.holes = []   # the window's own holes: a tray that failed, a tick that failed (A-8)

    # tray
    def start_tray(self):
        if self.tray is None:
            self.tray = traymod.Tray(self.actions.put)
        try:
            why = self.tray.start()
        except Exception as exc:   # never into the window (A3)
            why = "the tray failed to start: %s: %s" % (type(exc).__name__, exc)
            self.tray = None
            self.hole("tray: %s" % why)
            return why
        if why is None:
            return None
        if traymod.unsupported(getattr(self.tray, "platform", None)) == why:
            self.notes.append("tray: %s" % why)
            self.tray = None
        else:
            self.hole("tray: %s" % why)
            # A-6: a tray that timed out is kept, so its late thread is cancelled, stopped and its holes shown
            if not getattr(self.tray, "cancelled", False):
                self.tray = None
        return why

    def tray_up(self):
        return self.tray is not None and bool(getattr(self.tray, "running", False))

    def tray_holes(self):
        """The tray's holes, among them "tray ended: <reason>" (A-6) and a
        failed re-add (A-1); the tray's own words, each once."""
        return ["tray: %s" % h for h in (getattr(self.tray, "holes", []) if self.tray is not None else [])]

    def hole(self, text):
        """The window's own hole, kept once and never overwritten (A-8)."""
        if text not in self.holes:
            self.holes.append(text)

    def log_line(self, text):
        """A line of the window's own (A-4): into the watch's log, when a
        watch ran, and to the terminal or app.log."""
        line = "raqib app: %s\n" % _safe(text)
        session = self.session
        log = getattr(session, "log", None)
        if log is not None:
            log.write(line)   # its tee is self.tee
            return
        if self.tee is not None:
            try:
                self.tee.write(line)
                self.tee.flush()
            except Exception as exc:
                self.hole("the window's log line was not written: %s: %s" % (type(exc).__name__, exc))

    def callback_error(self, kind, value, tb):
        """Tk's report_callback_exception (A-4): an exception in a button,
        a close or an after() is a hole and a log line, never lost."""
        text = "a window callback failed: %s: %s" % (getattr(kind, "__name__", kind), value)
        self.hole(text)
        self.log_line(text)
        self.log_line("".join(traceback.format_exception(kind, value, tb)).rstrip("\n"))

    def sessions(self):
        """The watches running or shown in this window: the project's and the host's."""
        return [x for x in (self.session, self.host) if x is not None]

    def all_sessions(self):
        """F-8: every watch this window started, those a new Start replaced first."""
        return self.past + self.sessions()

    def look_thread(self):
        """F-3: the look's reader thread, when it is still out."""
        worker = getattr(self.probe, "worker", None)
        thread = getattr(worker, "thread", None)
        return thread if thread is not None and thread.is_alive() else None

    def look_holes(self):
        """F-3: the look's holes stand (footer, log) until the host watch's
        first round replaces them; each is written to the log once."""
        if self.probe is None or self.host_first_round():
            return []
        holes = ["round at open: %s" % h for h in self.probe.view()["holes"]]
        for h in holes:
            if h not in self.look_logged:
                self.look_logged.add(h)
                self.log_line(h)
        return holes

    def host_first_round(self):
        """True once the host watch has a round of its own (a reader back, or failed)."""
        session = self.host
        if session is None or getattr(session, "running", None) is None:
            return False
        state = session.state() or {}
        return bool((state.get("host") or {}).get("last_round"))

    def report_finished(self):
        """F-8: each finished watch's final report is appended to the log
        (the terminal or app.log) once, never replaced by a later watch."""
        for session in self.all_sessions():
            snap = session.snapshot()
            if snap.get("final_text") and id(session) not in self.reported:
                self.reported.add(id(session))
                if self.tee is not None:
                    try:
                        self.tee.write("\n" + snap["final_text"])
                        self.tee.flush()
                    except Exception as exc:
                        self.hole("a final report was not written to the log: %s: %s" % (type(exc).__name__, exc))

    def finish_wait(self, err=None, rounds=None):
        """A-3: the process does not exit while a watch has not
        concluded: wait for the workers JOIN_SECONDS at a time, saying so
        each time; nothing is killed. True when they ended (rounds: a bound
        for tests; None waits for as long as it takes)."""
        n = 0
        while True:
            thread = next((t for t in (getattr(x, "thread", None) for x in self.sessions())
                           if t is not None and t.is_alive()), None)
            if thread is None:
                break
            if rounds is not None and n >= rounds:
                return False
            n += 1
            text = "the watch did not end in %g s: still waiting for its final report (nothing is killed)" % (
                JOIN_SECONDS * n)
            self.log_line(text)
            if err is not None:
                try:
                    err.write("raqib app: %s\n" % text)
                except Exception:
                    pass
            thread.join(JOIN_SECONDS)
        return True

    # the watch
    @staticmethod
    def _live(session):
        return session is not None and session.snapshot()["phase"] in ("starting", "watching", "stopping")

    def project_watching(self):
        return self._live(self.session)

    def host_watching(self):
        return self._live(self.host)

    def watching(self):
        """Any watch of this window runs: the project's or the host's."""
        return self.project_watching() or self.host_watching()

    def start(self, project):
        """A new watch of project; None, or why not. F-2: a refusal names the
        running watch."""
        if self.project_watching():
            return "a watch is running: the project watch of %s; stop it first" % _safe(self.session.project)
        if not project or not os.path.isdir(project):
            return "not a directory: %s" % (project or "(empty)")
        if self.session is not None:
            self.past.append(self.session)    # F-8: its report and exit are kept
        self.session = self.make_session(project).start()
        return None

    def project_screen(self):
        """F-2: where "Project" leads: the project watch's screen while it
        runs, else the project field (M6.4's first screen)."""
        return "watching" if self.project_watching() else "first"

    def start_host(self):
        """E2: a new watch of this host (HostSession); None, or why not. A
        second host watch on this home is refused by HostWatch itself (C-2):
        that refusal is the session's error, shown as a hole line."""
        if self.host_watching():
            return "a watch is running: the host watch; stop it first"
        if self.host is not None:
            self.past.append(self.host)       # F-8: its report and exit are kept
        self.host = self.make_host().start()
        return None

    def stop(self, reason):
        """Every watch of the window ends (the tray's Stop, a close)."""
        for session in self.sessions():
            session.stop(reason)

    def stop_project(self, reason):
        if self.session is not None:
            self.session.stop(reason)

    def stop_host(self, reason):
        if self.host is not None:
            self.host.stop(reason)

    def host_tip(self, trees=None, new=None, findings=None, suspicions=None, project_findings=None):
        """The tray's tooltip (M7.6b E5, REDO C-4), the host watch's: "Raqib:
        N trees, K new, F findings" (and " +S suspicions" when any) only
        while the host is watched; with a project watch only, "Raqib:
        project <name>, F findings" (that watch's findings); else "Raqib:
        idle". Changed only when the text changes; a tray that cannot take
        it keeps a hole of its own."""
        if self.host_watching():
            text = traymod.tip_text(trees, new, findings, suspicions)
        elif self.project_watching():
            name = os.path.basename(str(self.session.project).rstrip("/\\")) or str(self.session.project)
            text = traymod.project_tip(_safe(name), project_findings)
        else:
            text = traymod.IDLE_TIP
        if text == self.tip:
            return text
        self.tip = text
        setter = getattr(self.tray, "set_tip", None) if self.tray is not None else None
        if setter is not None:
            try:
                setter(text)
            except Exception as exc:
                self.hole("tray: the tooltip could not be set: %s: %s" % (type(exc).__name__, exc))
        return text

    def close_request(self):
        """The window's close button: "hide" (to the tray, while watching),
        "stop" (the watch ends, the final report stays on screen) or "quit"."""
        if self.watching():
            if self.tray_up():
                return "hide"
            self.stop("window closed")
            return "stop"
        return "quit"

    def start_probe(self, make=None):
        """E1: the discover round at open, in a thread (HostProbe over the
        host watch's reader, deadline 2 x T). A probe that cannot start is a
        hole and the host screen says HOST NOT READ, never a crash."""
        try:
            if make is not None:
                self.probe = make()
            elif self.options is None:
                self.probe_error = "the host is not read: this window was given no reader"
                return None
            else:
                o = self.options
                # F-10: the look is written under the window's home (the user's, as every watch's ~/.raqib)
                self.probe = HostProbe(o.reader(), o.host_catalog(), hostmod.DEADLINE_FACTOR * o.every,
                                       home=o.home or os.path.expanduser("~"))
            self.probe.start()
        except Exception as exc:
            self.probe = None
            self.probe_error = "the host could not be read at open: %s: %s" % (type(exc).__name__, _safe(exc))
            self.hole(self.probe_error)
        return self.probe

    def host_view(self, now=None):
        """What the host screen shows now: the round at open (HostProbe), or
        the host watch (HostSession): starting, watching, refused (a hole
        line), finished (its final report). Plain Python; Window draws it."""
        if self.probe is not None:
            probe = self.probe.view(now)
        else:
            probe = dict(_empty_view(), word="HOST NOT READ", level="alarm",
                         detail=self.probe_error or "the round at open did not start")
        session = self.host
        if session is None:
            if self.host_note:
                probe = dict(probe, holes=probe["holes"] + [self.host_note])
            return probe
        look = [] if self.host_first_round() else ["round at open: %s" % h for h in probe["holes"]]   # F-3
        snap = session.snapshot()
        extra = []
        for text in list(snap.get("holes") or []) + ([session.read_note] if getattr(session, "read_note", None) else []):
            if text not in extra:
                extra.append(text)
        if snap["phase"] == "failed" and snap.get("final_text") is None:
            error = snap.get("error") or "the host watch did not start"
            holes = probe["holes"] + [h for h in [error] + extra if h not in probe["holes"]]
            return dict(probe, word="HOST NOT WATCHED", level="alarm", detail=_safe(error), holes=[_safe(h) for h in holes])
        if snap["phase"] == "finished":
            code = snap.get("final_exit")   # F-7: C-10's code gives the colour, as at open
            return dict(_empty_view(), word="HOST WATCH FINISHED", level=code_level(code), code=code,
                        detail="the host watch ended; its final report is below (exit %s)%s" % (
                            code, ". " + NOT_CLEARANCE if code == 0 else ""),
                        final=snap.get("final_text") or "", holes=[_safe(h) for h in extra])
        state = session.state()
        if state is None:
            every = getattr(self.options, "every", hostmod.EVERY_DEFAULT)
            return dict(probe, word="STARTING HOST WATCH", level="incomplete",
                        detail="starting the host watch of `raqib watch --host` (a round every %g s)" % every)
        view = host_watch_view(state, look + extra)
        if snap["phase"] == "stopping":
            view["word"] += " (stopping)"
        return view

    def open_page(self, which="project"):
        """A-13 (Q-6), F-11: the "Open page" button of the project screen or
        of the host screen; the same opener as `raqib watch` (watch.open_page),
        never under CI. None, or why not."""
        session = self.host if which == "host" else self.session
        state = session.state() if session is not None else None
        url = (state or {}).get("url")
        if not url:
            return "no page yet: the watch has not started"
        environ = os.environ if self.options is None or self.options.environ is None else self.options.environ
        if environ.get("CI"):
            return "CI is set: the page is not opened"
        try:
            why = self.opener(url, environ)
        except Exception as exc:
            why = "%s: %s" % (type(exc).__name__, exc)
        return "the page was not opened (%s); open %s by hand" % (why, url) if why else None

    def drain(self):
        """The tray's actions since the last call, done: ["show" | "stop" | "quit"]."""
        done = []
        while True:
            try:
                action = self.actions.get_nowait()
            except queue.Empty:
                return done
            if action == "stop":
                self.stop("Stop in the tray menu")
            elif action == "quit":
                self.quit("Quit in the tray menu")
            done.append(action)

    def quit(self, reason):
        if not self.quitting:
            self.quitting, self.quit_at = True, self.clock()
        self.stop(reason)

    def worker_alive(self):
        for session in self.sessions():
            alive = getattr(session, "alive", None)
            if bool(alive()) if alive is not None else self._live(session):
                return True
        return False

    def can_exit(self):
        """Quit asked and the watch concluded (its worker ended). A-3: never
        with a watch that has not concluded."""
        return self.quitting and not self.watching() and not self.worker_alive()

    def quit_overdue(self):
        """A-3: Quit asked JOIN_SECONDS ago and the worker is still alive:
        the quit is given up (the window comes back) with the hole "the
        watch did not end in N s"; True once, then Quit can be asked again.
        Nothing is killed."""
        if not self.quitting or self.can_exit() or self.clock() - self.quit_at < JOIN_SECONDS:
            return False
        self.quitting, self.quit_at = False, None
        self.hole("the watch did not end in %g s after Quit: the window stays; Quit again, or see the log"
                  % JOIN_SECONDS)
        return True

    def shutdown(self):
        """The window is going: the watch ends, the worker is waited for
        (JOIN_SECONDS), the tray goes. True when no worker is left alive."""
        done = True
        for session in self.sessions():
            session.stop("the window was closed")
        for session in self.sessions():
            if session.thread is not None:
                session.thread.join(JOIN_SECONDS)
                done = done and not session.thread.is_alive()
        self._tray_down()
        return done

    def _tray_down(self):
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass

    def exit_code(self):
        """The exit of the window: every watch's report (the project's as in
        M6.4, the host's C-10: 0, 1, 3; a refused host watch 2, F-8), the
        replaced ones too; an alarm (1) first, then any other non-zero code;
        0 when none ran."""
        codes = []
        for session in self.all_sessions():
            snap = session.snapshot()
            if snap["final_exit"] is not None:
                codes.append(snap["final_exit"])
            elif snap["phase"] == "failed":   # F-8: a refused host watch is 2 (a refusal), not a finding
                codes.append(2 if getattr(session, "refused", False) else 1)
            else:
                codes.append(0)
        if 1 in codes:
            return 1
        return next((c for c in codes if c), 0)


# --- the doctor in a thread ---------------------------------------------------------------

class DoctorJob:
    """doctor.checks() for one project in a thread; result() is None until done."""

    def __init__(self, project, environ=None, home=None, checks=None):
        from raqib import doctor
        self.project = project
        self.checks = checks or (lambda p: doctor.checks(p, environ=environ, home=home))
        self._result = None
        self.thread = threading.Thread(target=self._run, name="raqib-app-doctor", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        try:
            project, lines, notes = self.checks(self.project)
            from raqib import doctor
            text, _ = doctor.summary(lines)
            self._result = (project, doctor_lines(lines, notes), "raqib doctor: %s" % text)
        except Exception as exc:   # A3: a doctor that failed says so
            self._result = (self.project, [("MISSING", "alarm", "doctor failed: %s: %s" % (type(exc).__name__, exc))],
                            "raqib doctor: it could not run")

    def result(self):
        return self._result


# --- the window (Tk) ----------------------------------------------------------------------

def log_view(text, limit=None):
    """The Log screen's text: the last `limit` characters of the watch's
    lines (bounded, A-5), with a line saying how much is not shown."""
    limit = LOG_VIEW_MAX if limit is None else limit
    if len(text) <= limit:
        return text
    return "[%d earlier characters not shown here]\n%s" % (len(text) - limit, text[-limit:])


class Disclosure:
    """M8.1 E4: a disclosure drawn by the window: a toggle (a chevron and
    its title; Tab reaches it, Space or Enter opens and closes it, focus is
    drawn) and its panel, a card the window lays out when it is open. Closed
    by default; one open at a time, so an open panel never takes the
    screen's table from it (its text is bounded and scrolls)."""

    def __init__(self, window, row, panels, title, name):
        self.window, self.name = window, name
        self.var = window.tk.BooleanVar(master=window.root, value=False)
        self.toggle = window.ttk.Checkbutton(row, text=title, variable=self.var, style="Disclosure.TCheckbutton",
                                             command=lambda: window._opened(self), takefocus=True)
        self.panel, self.inner, _ = window._card(panels)

    def is_open(self):
        return bool(self.var.get())

    def set_open(self, value):
        if bool(value) != self.is_open():
            self.var.set(bool(value))
            self.window._opened(self)

    def invoke(self):
        self.toggle.invoke()

    def title(self):
        return str(self.toggle.cget("text"))

    def set_title(self, text, style="Disclosure.TCheckbutton"):
        if self.title() != text or str(self.toggle.cget("style")) != style:
            self.toggle.configure(text=text, style=style)


class Window:
    """M8.1 (ADR-0009 decisions 1-3): the Tk window over a Controller. Only
    this class calls Tk. A navigation rail (the name, what is watched, Host /
    Project / Rules / Log, the rules off, Open page, the doctrine) and one
    content column: a verdict header (one sentence, the level's pill with
    its word, the screen's one primary action), the round strip under the
    host's verdict, the status pills, the disclosures ("could not see (N)",
    the checks, the watch options, what the overlay applies) and the
    screen's cards. Its look is THEME's through ttk styles and pictures
    drawn once in _style; nothing it shows is computed here."""

    SCREENS = ("host", "first", "watching", "rules", "log")

    def __init__(self, tk, root, controller, project, environ=None, home=None, doctor_job=None, probe=None,
                 rules_panel=None, scale=None, win_api=None):
        self.tk = tk
        from tkinter import ttk   # the themed widgets (stdlib)
        self.ttk = ttk
        self.rules_panel = rules_panel or RulesPanel(home=home)   # M7.6: the Rules screen's logic
        self.root = root
        self.c = controller
        self.environ = environ
        self.home = home
        self.make_doctor = doctor_job or (lambda p: DoctorJob(p, environ=environ, home=home))
        self.doctor = None
        self.checks_lines = None
        self.screen = None
        self.shown = {}
        self.after_id = None
        self.closed = False
        self.mode = os_mode()                  # E1: dark or light as the OS says, else light
        self.palette = THEME[self.mode]
        self.scale = scale or screen_scale(root.winfo_fpixels("1i"))   # E6: 1.0 at 96 dpi
        self.images = {}                       # the drawn pictures (Tk drops a PhotoImage no one holds)
        self.styles = set()
        root.title(TITLE)
        width, height = self.px(THEME["size"])
        root.geometry("%dx%d" % (min(width, max(root.winfo_screenwidth() - self.px(40), self.px(900))),
                                 min(height, max(root.winfo_screenheight() - self.px(80), self.px(600)))))
        root.minsize(*self.px(THEME["min_size"]))   # E6: every screen fits 900x600 at scale 1.0
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = controller.callback_error   # A-4: a hole and a log line
        self.doctor_band = None
        self.refusal = None
        self.verdict_word = None
        self.sorting = {"host": (None, False)}   # E2: (column, descending)
        self.payload = {"host": {}}              # iid -> what a selected row shows
        self.first_run_shown = False
        self.log_source = "host"
        self.rule_vars = {}
        self.rule_widgets = {}
        self.rule_rows = []
        self.rule_said = None   # REDO A-6: (rule id, the refusal's words) shown beside its row
        self.rule_confirm = None   # M8.2 E4: the user rule whose Remove asks its one confirmation
        self.strip_fit = 0
        self.codes = {}    # REDO B-2: id(session) -> the last code its state said
        self.laying = False
        self.live = {}     # REDO A-2, A-8: each running watch's word, level, findings, suspicions
        self.live_states, self.counts = {}, {"host": (0, 0), "project": 0}   # REDO B-6: the tick's states, counts
        self.cut_badges = {}   # REDO C-4: badge key -> [(level, whole text)] of the badges cut to their line
        self._style()
        self._build(project)
        self.show_host()                  # M7.3: the first screen is the host
        controller.start_probe(probe)     # E1: one discover round at open, in a thread
        self.check()
        self.title_note = self._title_bar(win_api)
        self.after_id = root.after(TICK_MS, self.tick)

    def px(self, n):
        """E6: a pixel size of THEME at this display's scale (scaled())."""
        return scaled(n, self.scale)

    # --- the look -------------------------------------------------------------------------------
    def _picture(self, key, rows):
        """A drawn picture (rows of colours) as a PhotoImage, made once."""
        if key not in self.images:
            img = self.tk.PhotoImage(master=self.root, width=len(rows[0]), height=len(rows))
            img.put(image_data(rows))
            self.images[key] = img
        return self.images[key]

    def _element(self, name, pictures, border, sticky="nswe", padding=0):
        """A ttk image element from (state, picture) pairs, the first the
        default; its corners `border` wide stay, its middle stretches; its
        own padding is `padding` (the style's padding places the content)."""
        if name in self.styles:
            return
        self.styles.add(name)
        self.style.element_create(name, "image", pictures[0][1], *[tuple(pair) for pair in pictures[1:]],
                                  border=border, sticky=sticky, padding=padding)

    def _button_style(self, name, fill, hover, pressed, text, ground, border=None, ring=None, bar=None,
                      padding=(14, 6), font=None, anchor="center"):
        """E4: a flat button drawn by the window: its box in each state (the
        focus ring drawn around it, the hover and pressed fills), its text."""
        p, r, m = self.palette, self.px(THEME["px"]["radius"]), self.px(THEME["px"]["focus"])
        size = 2 * (r + m) + 4

        def draw(fill_, ring_=None, disabled=False):
            shapes = []
            if ring_:
                shapes += [("rect", 0, 0, size, size, r + m, ring_),
                           ("rect", 1.5 * self.scale, 1.5 * self.scale, size - 1.5 * self.scale,
                            size - 1.5 * self.scale, r + m - 1.5 * self.scale, ground)]
            if border:
                shapes += [("rect", m, m, size - m, size - m, r, border if not disabled else p["line"]),
                           ("rect", m + 1, m + 1, size - m - 1, size - m - 1, max(r - 1, 0), fill_)]
            else:
                shapes.append(("rect", m, m, size - m, size - m, r, fill_))
            if bar:
                shapes.append(("rect", m, m + r / 2.0, m + 3 * self.scale, size - m - r / 2.0, 1, bar))
            return self._picture(("button", name, fill_, ring_, disabled), paint(size, size, ground, shapes))
        self._element(name + ".box", [("", draw(fill)), ("disabled", draw(fill if border else p["line"], None, True)),
                                      ("pressed", draw(pressed, ring)), ("focus", draw(fill, ring)),
                                      ("active", draw(hover))], r + m + 1, padding=m)
        self.style.layout(name, [(name + ".box", {"sticky": "nswe", "children": [
            ("Button.padding", {"sticky": "nswe", "children": [("Button.label", {"sticky": "nswe"})]})]})])
        self.style.configure(name, foreground=text, background=ground, padding=self.px(padding), anchor=anchor,
                             font=font or "TkDefaultFont", width=0, relief="flat", borderwidth=0)
        self.style.map(name, foreground=[("disabled", p["muted"])], background=[("active", ground)])

    def _pill_style(self, kind, ground="ground"):
        """E4: the Pill drawn by the window, for a level (its colour on its
        pill ground) or "chip" (a neutral kind, severity or origin), on the
        card or on the ground: the style's name, made on first use."""
        name = "%s.%s.Pill.TLabel" % (kind, ground)
        if name in self.styles:
            return name
        p = self.palette
        fill, text = (p["chip"], p["ink"]) if kind == "chip" else (p["pill"][kind], p["levels"][kind])
        r = self.pill_r
        rows = box(2 * r + 2, 2 * r + 2, r, fill, p[ground])
        self._element(name + ".box", [("", self._picture(("pill", kind, ground), rows))], r)
        self.styles.add(name)
        self.style.layout(name, [(name + ".box", {"sticky": "nswe", "children": [
            ("Label.padding", {"sticky": "nswe", "children": [("Label.label", {"sticky": "nswe"})]})]})])
        self.style.configure(name, foreground=text, background=fill, font=self.font_meta_bold,
                             padding=(r, self.pill_pad, r, self.pill_pad), anchor="center")
        return name

    def _style(self):
        """E1, E4: fonts from THEME's families (pick_font), and every ttk
        style: the cards, the buttons (one filled primary, flat secondary
        ones), the rail's items, the fields, the thin scrollbars, the
        tables (tall rows, no grid lines, a quiet header, a tinted
        selection), the Switch, the disclosure, the pills; their pictures
        drawn here at this display's scale."""
        from tkinter import font as tkfont
        f, p, X = THEME["fonts"], self.palette, THEME["px"]
        families = tkfont.families(self.root)
        ui, mono = pick_font(f["ui"], families), pick_font(f["mono"], families)
        display = pick_font(f["display"], families) or ui
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            tkfont.nametofont(name).configure(size=f["body"], weight="normal", **({"family": ui} if ui else {}))
        tkfont.nametofont("TkFixedFont").configure(size=f["meta"], **({"family": mono} if mono else {}))
        base = tkfont.nametofont("TkDefaultFont").actual("family")

        def font(size, bold=False, family=None):
            return tkfont.Font(root=self.root, family=family or base, size=size, weight="bold" if bold else "normal")
        self.font_verdict = font(f["verdict"], True, display)
        self.font_title = font(f["title"], True)
        self.font_body = tkfont.nametofont("TkDefaultFont")
        self.font_bold = font(f["body"], True)
        self.font_meta = font(f["meta"])
        self.font_meta_bold = font(f["meta"], True)
        self.pill_pad = self.px(2)   # a pill is a capsule: its radius half its height
        self.pill_r = (self.font_meta_bold.metrics("linespace") + 2 * self.pill_pad) // 2
        style = self.style = self.ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")       # takes every colour of THEME, on Windows and Linux alike
        g, card = p["ground"], p["card"]
        style.configure(".", background=g, foreground=p["ink"], bordercolor=p["line"], lightcolor=g, darkcolor=g,
                        troughcolor=card, selectbackground=p["select"], selectforeground=p["ink"],
                        insertcolor=p["ink"], fieldbackground=p["field"], focuscolor=p["accent"],
                        font="TkDefaultFont")
        style.configure("TFrame", background=g)
        style.configure("Inner.TFrame", background=card)
        style.configure("Rail.TFrame", background=p["rail"])
        style.configure("TLabel", background=g, foreground=p["ink"])
        style.configure("Muted.TLabel", foreground=p["muted"], font=self.font_meta)
        style.configure("Verdict.TLabel", font=self.font_verdict)
        style.configure("Card.TLabel", background=card)
        style.configure("Muted.Card.TLabel", foreground=p["muted"], font=self.font_meta)
        style.configure("Title.Card.TLabel", font=self.font_title)
        style.configure("Bold.Card.TLabel", font=self.font_bold)
        for level, colour in p["levels"].items():
            style.configure("%s.Level.TLabel" % level, foreground=colour)
            style.configure("%s.Level.Card.TLabel" % level, foreground=colour, font=self.font_meta)
        style.configure("TSeparator", background=p["line"])
        # the card: a rounded box with a hairline, on the ground
        r = self.px(X["card_radius"])
        self._element("Card.box", [("", self._picture(("card",), box(2 * r + 4, 2 * r + 4, r, card, g, p["line"])))],
                      r + 1)
        style.layout("Card.TFrame", [("Card.box", {"sticky": "nswe"})])
        # the buttons: one filled primary per screen; flat secondary ones on the ground and on a card
        self._button_style("Primary.TButton", p["accent"], p["accent_hover"], p["accent_hover"], p["on_accent"], g,
                           ring=p["accent"], font=self.font_bold)
        self._button_style("TButton", card, p["hover"], p["chip"], p["ink"], g, border=p["field_line"],
                           ring=p["accent"], padding=(12, 5))
        self._button_style("Card.TButton", card, p["hover"], p["chip"], p["ink"], card, border=p["field_line"],
                           ring=p["accent"], padding=(12, 5))
        self._button_style("Link.TButton", card, p["hover"], p["chip"], p["accent"], card, ring=p["accent"],
                           padding=(6, 2), font=self.font_meta)
        self._button_style("Step.TButton", card, p["hover"], p["chip"], p["ink"], card, border=p["field_line"],
                           ring=p["accent"], padding=(4, 4))
        self._button_style("Segment.TButton", card, p["hover"], p["chip"], p["muted"], card, ring=p["accent"],
                           padding=(12, 5))
        self._button_style("Current.Segment.TButton", p["select"], p["select"], p["select"], p["ink"], card,
                           ring=p["accent"], padding=(12, 5), font=self.font_bold)
        # the rail's items: flat on the rail, the current one lit with an accent bar
        self._button_style("Rail.TButton", p["rail"], p["rail_hover"], p["rail_on"], p["rail_ink"], p["rail"],
                           ring=p["rail_accent"], padding=(12, 7), anchor="w")
        self._button_style("Current.Rail.TButton", p["rail_on"], p["rail_on"], p["rail_on"], p["rail_ink"],
                           p["rail"], ring=p["rail_accent"], bar=p["rail_accent"], padding=(12, 7), anchor="w",
                           font=self.font_bold)
        style.map("Rail.TButton", foreground=[("disabled", p["rail_muted"])])
        # the fields: rounded, a hairline that turns the accent with focus
        m = self.px(X["radius"])

        def field(border_, width=1):
            return self._picture(("field", border_, width), box(2 * m + 4, 2 * m + 4, m, p["field"], card, border_,
                                                                width))
        self._element("Field.box", [("", field(p["field_line"])), ("focus", field(p["accent"], self.px(2))),
                                    ("disabled", field(p["line"]))], m + 1, padding=self.px(2))
        style.layout("TEntry", [("Field.box", {"sticky": "nswe", "children": [("Entry.padding", {
            "sticky": "nswe", "children": [("Entry.textarea", {"sticky": "nswe"})]})]})])
        style.configure("TEntry", padding=self.px((8, 4)), foreground=p["ink"], fieldbackground=p["field"])
        style.map("TEntry", foreground=[("disabled", p["muted"])])
        # the thin scrollbars: a rounded thumb, no arrows, on the card
        w = self.px(X["scroll"])
        k = max(2, w // 2 - 1)

        def thumb(colour):
            return self._picture(("thumb", colour), paint(w, 2 * k + 4, card, [
                ("rect", 2 * self.scale, 0, w - 2 * self.scale, 2 * k + 4, k - 1, colour)]))
        self._element("Thin.thumb", [("", thumb(p["thumb"])), ("active", thumb(p["thumb_hover"])),
                                     ("pressed", thumb(p["thumb_hover"]))], k)
        style.layout("Thin.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
            ("Thin.thumb", {"expand": "1", "sticky": "nswe"})]})])
        style.configure("Thin.Vertical.TScrollbar", troughcolor=card, background=card, bordercolor=card,
                        lightcolor=card, darkcolor=card, arrowsize=w, gripcount=0, relief="flat", borderwidth=0)
        # the tables: tall rows, no grid lines, a quiet header, a tinted selection (the sort arrow drawn)
        rows = self.font_body.metrics("linespace") + 2 * self.px(X["row_pad"])
        def table(ring):
            return self._picture(("table", ring), box(2 * m + 4, 2 * m + 4, m, card, card, ring, self.px(2)))
        self._element("Table.box", [("", table(card)), ("focus", table(p["accent"]))], m + 1, padding=self.px(2))
        style.layout("Treeview", [("Table.box", {"sticky": "nswe", "children": [("Treeview.padding", {
            "sticky": "nswe", "children": [("Treeview.treearea", {"sticky": "nswe"})]})]})])
        style.configure("Treeview", background=card, fieldbackground=card, foreground=p["ink"], rowheight=rows,
                        borderwidth=0, relief="flat")
        style.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["ink"])])
        style.configure("Treeview.Heading", background=p["head"], foreground=p["muted"], font=self.font_meta_bold,
                        relief="flat", borderwidth=0, bordercolor=p["head"], lightcolor=p["head"],
                        darkcolor=p["head"], padding=self.px((8, 6)))
        style.map("Treeview.Heading", background=[("active", p["hover"])])
        c = self.px(X["chevron"])
        for d in ("up", "down"):
            self._picture(("arrow", d), chevron(c, d, p["muted"], p["head"], 1.4 * self.scale))
        # the Switch: a track and its knob, a focus ring drawn around it
        sw, sh = self.px(X["switch"])
        gap = self.px(8)

        def switch(on, ring=None, track=None):
            return self._picture(("switch", on, ring, track), switch_shape(
                sw, sh, on, track or (p["accent"] if on else p["track_off"]), p["knob"], card, ring, m // 2 + 1, gap))
        self._element("Switch.indicator", [
            ("", switch(False)), ("disabled", switch(False, None, p["line"])),
            ("focus selected", switch(True, p["accent"])), ("focus", switch(False, p["accent"])),
            ("selected", switch(True))], 0, sticky="w")
        style.layout("Switch.TCheckbutton", [("Checkbutton.padding", {"sticky": "nswe", "children": [
            ("Switch.indicator", {"side": "left", "sticky": ""}),
            ("Checkbutton.label", {"side": "left", "sticky": "w"})]})])
        style.configure("Switch.TCheckbutton", background=card, foreground=p["ink"], padding=0)
        style.map("Switch.TCheckbutton", background=[("active", card)])
        # the disclosure: a chevron that turns down when open, its title; a ring around it with the focus
        def turn(direction, ring=None):
            size, rr, t = c + self.px(8), self.px(5), 2 * self.scale
            shapes = [("rect", 0, 0, size, size, rr, ring),
                      ("rect", t, t, size - t, size - t, rr - t, g)] if ring else []
            shapes += chevron_shapes(c, direction, p["ink"], 1.6 * self.scale, self.px(4), self.px(4))
            return self._picture(("turn", direction, ring), paint(size + gap, size, g, shapes))
        self._element("Disclosure.indicator", [("", turn("right")), ("focus selected", turn("down", p["accent"])),
                                               ("focus", turn("right", p["accent"])), ("selected", turn("down"))],
                      0, sticky="w")
        style.layout("Disclosure.TCheckbutton", [("Checkbutton.padding", {"sticky": "nswe", "children": [
            ("Disclosure.indicator", {"side": "left", "sticky": ""}),
            ("Checkbutton.label", {"side": "left", "sticky": "w"})]})])
        style.configure("Disclosure.TCheckbutton", background=g, foreground=p["ink"], padding=(0, self.px(2)),
                        font=self.font_bold)
        style.map("Disclosure.TCheckbutton", background=[("active", g)])
        style.configure("Hole.Disclosure.TCheckbutton", foreground=p["levels"]["hole"])
        for level in ("alarm", "incomplete"):
            style.configure("%s.Disclosure.TCheckbutton" % level, foreground=p["levels"][level])
        for kind in ("minus", "plus"):
            self._picture((kind,), sign(self.px(12), kind == "plus", p["ink"], card, 1.6 * self.scale))
            self._picture((kind, "off"), sign(self.px(12), kind == "plus", p["line"], card, 1.6 * self.scale))
        self.root.configure(background=g)
        for cls in ("TButton", "TCheckbutton", "TRadiobutton"):   # E4: Enter acts as Space does (M8.2: the form)
            for key in KEYS["act"]:
                self.root.bind_class(cls, key, lambda e: e.widget.invoke())

    def _wrap(self, label, start=None, fill=True):
        """A label that wraps at the width it is given. REDO B-1: it asks for
        one character of width (fill: it is packed or gridded to fill its
        container), so no width of the window comes from its words; its wrap
        follows the width it really has."""
        if fill:
            label.configure(width=1)
        label.configure(wraplength=start or self.px(THEME["px"]["wrap"]))
        label.bind(KEYS["resize"][0], lambda e, w=label: w.configure(wraplength=max(e.width - self.px(4),
                                                                                       self.px(120))))
        return label

    def _card(self, parent, title=None):
        """A card: a rounded box on the ground, its own padding, an optional
        title. (outer, inner, title label)."""
        outer = self.ttk.Frame(parent, style="Card.TFrame")
        inner = self.ttk.Frame(outer, style="Inner.TFrame")
        pad = self.px(THEME["px"]["card_pad"])
        inner.pack(fill="both", expand=True, padx=pad, pady=pad)
        label = None
        if title is not None:
            label = self.ttk.Label(inner, text=title, style="Title.Card.TLabel")
            label.pack(anchor="w", pady=(0, self.px(4)))
        return outer, inner, label

    def _text(self, parent, height, mono=False):
        """A read-only text on a card, its thin scrollbar, the levels' tags;
        Tab passes on (it never stops in the text)."""
        p = self.palette
        frame = self.ttk.Frame(parent, style="Inner.TFrame")
        text = self.tk.Text(frame, height=height, width=20, wrap="word", font="TkFixedFont" if mono else "TkTextFont",
                            background=p["card"], foreground=p["ink"], insertbackground=p["ink"],
                            selectbackground=p["select"], selectforeground=p["ink"], highlightthickness=self.px(1),
                            highlightbackground=p["card"], highlightcolor=p["accent"], relief="flat", borderwidth=0,
                            padx=self.px(2), pady=self.px(2), spacing1=self.px(1), spacing3=self.px(2))
        bar = self.ttk.Scrollbar(frame, command=text.yview, style="Thin.Vertical.TScrollbar")
        text.pack(side="left", fill="both", expand=True)
        text.configure(yscrollcommand=self._scroller(bar, text), state="disabled")
        for level, colour in p["levels"].items():
            text.tag_configure(level, foreground=colour)
        text.tag_configure("head", font=self.font_bold)
        for key in KEYS["next"]:
            text.bind(key, lambda e: self._pass_focus(e, False))
        for key in KEYS["prev"]:
            text.bind(key, lambda e: self._pass_focus(e, True))
        return frame, text

    def _scroller(self, bar, view):
        """A thin scrollbar shown only while there is something to scroll."""
        def scroll(first, last):
            bar.set(first, last)
            need = float(first) > 0.0 or float(last) < 1.0
            if need and not bar.winfo_manager():
                bar.pack(side="right", fill="y", padx=(self.px(4), 0), before=view)
            elif not need and bar.winfo_manager():
                bar.pack_forget()
        return scroll

    @staticmethod
    def _pass_focus(event, back):
        nxt = event.widget.tk_focusPrev() if back else event.widget.tk_focusNext()
        if nxt is not None:
            nxt.focus_set()
        return "break"

    def _title_bar(self, api):
        """E6: the title bar follows dark mode (Windows, this window only); a failure is a line in the log."""
        if sys.platform != "win32" and api is None:
            return None
        try:
            self.root.update_idletasks()
            why = dark_title_bar(int(str(self.root.wm_frame()), 16), self.mode, api=api,
                                 platform="win32" if api is not None else None)
        except Exception as exc:
            why = "the title bar was not made dark: %s: %s" % (type(exc).__name__, _safe(exc))
        if why:
            self.c.log_line(why)
        return why

    # --- the frame of every screen: the rail and the verdict header ----------------------------------
    def _build(self, project):
        tk, ttk, p, X = self.tk, self.ttk, self.palette, THEME["px"]
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self._build_rail()
        main = self.main = ttk.Frame(self.root)
        main.grid(row=0, column=1, sticky="nsew")
        pad, gap = self.px(X["pad"]), self.px(X["gap"])
        head = self.head = ttk.Frame(main)
        head.pack(fill="x", padx=pad, pady=(self.px(14), 0))
        row = ttk.Frame(head)
        row.pack(fill="x")
        self.primary = ttk.Frame(row)   # the screen's one primary action, at the right
        self.primary.pack(side="right", anchor="n")
        self.pill = ttk.Label(row, text="", style=self._pill_style("note"))
        self.pill.pack(side="left", anchor="center", padx=(0, self.px(10)))
        self.verdict = self._wrap(ttk.Label(row, text="", style="Verdict.TLabel", anchor="w", justify="left"),
                                  self.px(360))
        self.verdict.pack(side="left", fill="x", expand=True, anchor="center")
        self.note = self._wrap(tk.Label(head, text="", anchor="w", justify="left", font=self.font_meta_bold,
                                        background=p["ground"], foreground=p["muted"], borderwidth=0, padx=0))
        self.detail = self._wrap(ttk.Label(head, text="", style="Muted.TLabel", anchor="w", justify="left"))
        self.detail.pack(fill="x", pady=(self.px(4), 0))
        # E3: the round strip, under the host's verdict
        strip = self.strip_row = ttk.Frame(main)
        self.strip = tk.Canvas(strip, height=self.px(X["cell"] + 2), width=self.px(80), background=p["ground"],
                               highlightthickness=0, borderwidth=0)   # REDO B-1: asks little, draws what it gets
        self.strip.pack(fill="x")
        self.strip_label = self._wrap(ttk.Label(strip, text="", style="Muted.TLabel", anchor="w", justify="left"))
        self.strip_label.pack(fill="x", pady=(self.px(2), 0))
        self.strip.bind(KEYS["resize"][0], lambda e: self._draw_strip())
        self.host_badges = ttk.Frame(main, width=1, height=1)   # REDO C-2: one pill per badge, its colour and word
        self.badges = ttk.Frame(main, width=1, height=1)
        for frame in (self.host_badges, self.badges):   # REDO B-1: no width from the pills' words
            frame.pack_propagate(False)
        for frame in (self.host_badges, self.badges):
            frame.bind(KEYS["resize"][0], lambda e, f=frame: self._flow(f))
        self.root.bind(KEYS["resize"][0], self._resized, add="+")
        self.root.bind(KEYS["map"][0], self._mapped, add="+")   # REDO C-4: back on the screen, the panel re-laid
        # E4: the disclosures under the header, their panels below them
        tools = self.tools = ttk.Frame(main, width=1, height=1)
        tools.pack_propagate(False)   # REDO B-1: the toggles' words ask no width; their lines give the height
        tools.pack(fill="x", padx=pad, pady=(self.px(8), 0))
        self.tools_lines = [ttk.Frame(tools), ttk.Frame(tools)]   # REDO B-1: the toggles flow to a second line
        tools.bind(KEYS["resize"][0], lambda e: self._flow_tools())
        panels = self.panels = ttk.Frame(main)
        panels.pack(fill="x", padx=pad)
        self.seen = Disclosure(self, tools, panels, seen_title([]), "seen")
        self.seen_frame, self.seen_text = self._text(self.seen.inner, 2)
        self.seen_frame.pack(fill="both", expand=True)
        self.checks = Disclosure(self, tools, panels, checks_state(None)[0], "checks")
        frame, self.checks_rows = self._text(self.checks.inner, 2)
        frame.pack(fill="x")
        self.options = Disclosure(self, tools, panels, "Watch options", "options")
        self.overlay = Disclosure(self, tools, panels, "What the overlay applies", "overlay")
        self.disclosures = (self.seen, self.checks, self.options, self.overlay)
        self.screens = ttk.Frame(main)
        self.screens.pack(fill="both", expand=True, padx=pad, pady=(gap, self.px(14)))
        # REDO B-1: the column asks the width it has in a window of the minimum size, no less (a window shown at its
        # natural size - a withdrawn one on Windows - lays its words as at 900 px) and, by construction, no more
        ttk.Frame(main, width=self.px(THEME["min_size"][0] - THEME["px"]["rail"]), height=0).pack(side="bottom")
        self.rules_panel.say = self._rules_measuring   # M7.6c REDO E-7: the header says a measurement runs
        self._build_host()
        self._build_options()
        self._build_project(project)
        self._build_rules()
        self._build_log()
        self._first_run()

    def _build_rail(self):
        """E2: the rail: the name, what is watched, Host / Project / Rules /
        Log, the rules off (red while suppressed > 0), Open page, the doctrine."""
        tk, ttk, p, X = self.tk, self.ttk, self.palette, THEME["px"]
        width, pad = self.px(X["rail"]), self.px(14)
        rail = self.rail = tk.Frame(self.root, background=p["rail"], width=width)
        rail.grid(row=0, column=0, sticky="ns")
        rail.pack_propagate(False)
        brand = tk.Frame(rail, background=p["rail"])
        brand.pack(fill="x", padx=pad + self.px(6), pady=(self.px(20), self.px(2)))
        cell, step = self.px(6), self.px(9)
        one = self.px(1)
        mark = tk.Canvas(brand, width=4 * step, height=cell + 2 * one, background=p["rail"], highlightthickness=0,
                         borderwidth=0)
        for i in range(4):   # the mark: four rounds, the last not yet read
            x = one + i * step
            mark.create_rectangle(x, one, x + cell, one + cell, outline=p["rail_accent"],
                                  fill=p["rail_accent"] if i < 3 else p["rail"])
        mark.pack(side="left", padx=(0, self.px(8)))
        tk.Label(brand, text=TITLE, font=self.font_verdict, background=p["rail"], foreground=p["rail_ink"],
                 borderwidth=0, padx=0).pack(side="left")
        wrap = width - 2 * (pad + self.px(6))
        self.running_note = tk.Label(rail, text="", anchor="w", justify="left", font=self.font_meta,
                                     background=p["rail"], foreground=p["rail_muted"], wraplength=wrap)
        self.running_note.pack(fill="x", padx=pad + self.px(6), pady=(0, self.px(8)))
        self.rail_watches = tk.Frame(rail, background=p["rail"])   # REDO A-8: each running watch, its pill
        self.rail_watches.pack(fill="x", padx=pad + self.px(6), pady=(0, self.px(10)))
        self.host_tab = ttk.Button(rail, text="Host", command=self.show_host, style="Rail.TButton")
        self.project_tab = ttk.Button(rail, text="Project", command=self.show_project, style="Rail.TButton")
        self.rules_tab = ttk.Button(rail, text="Rules", command=self.show_rules, style="Rail.TButton")   # M7.6
        self.log_tab = ttk.Button(rail, text="Log", command=self.show_log, style="Rail.TButton")   # A-5, F-6
        for tab in (self.host_tab, self.project_tab, self.rules_tab, self.log_tab):
            tab.pack(fill="x", padx=self.px(8), pady=(0, self.px(2)))
        self.doctrine = tk.Label(rail, text=DOCTRINE, anchor="w", justify="left", font=self.font_meta,
                                 background=p["rail"], foreground=p["rail_muted"], wraplength=wrap)
        self.doctrine.pack(side="bottom", fill="x", padx=pad + self.px(6), pady=(self.px(8), self.px(18)))
        # F-11 and A-13: Open page, the host watch's on the host screen, the project watch's on the project's
        self.page_slot = tk.Frame(rail, background=p["rail"])
        self.page_slot.pack(side="bottom", fill="x", padx=self.px(8))
        self.host_page_button = ttk.Button(self.page_slot, text="Open page", command=self.open_host_page,
                                           style="Rail.TButton")
        self.page_button = ttk.Button(self.page_slot, text="Open page", command=self.open_page, style="Rail.TButton")
        self.rules_note = tk.Label(rail, text="", anchor="w", justify="left", font=self.font_meta,
                                   background=p["rail"], foreground=p["rail_muted"], wraplength=wrap)
        self.rules_note.pack(side="bottom", fill="x", padx=pad + self.px(6), pady=(0, self.px(6)))

    # --- the screens ---------------------------------------------------------------------------------
    def _build_host(self):
        ttk, X = self.ttk, THEME["px"]
        gap = self.px(X["gap"])
        f = self.hostf = ttk.Frame(self.screens)
        f.grid_columnconfigure(0, weight=1, uniform="half")
        f.grid_columnconfigure(1, weight=1, uniform="half")
        f.grid_rowconfigure(1, weight=3)
        f.grid_rowconfigure(2, weight=2)
        # E4: the first-run lines, at the top of the first screen until the first look is written

        # E2: the trees, a table that sorts by a click on its heading; the selected tree's detail below
        outer, inner, _ = self._card(f)
        outer.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.trees_card = outer
        # E4: the first-run lines, in the trees' card until the first look is written
        self.first_run_label = self._wrap(ttk.Label(inner, text="", style="Muted.Card.TLabel", anchor="w",
                                                    justify="left"))
        frame, self.host_tree = self._table(inner, "host", TREE_COLUMNS, 3)
        frame.configure(width=1)
        frame.pack_propagate(False)   # REDO B-1: the columns' widths ask nothing of the window; the card gives them
        frame.pack(fill="both", expand=True)
        self.host_table_frame = frame
        self.host_tree.bind(KEYS["select"][0], lambda e: self._show_tree_detail())
        self.host_tree.bind(KEYS["resize"][0], lambda e: self._table_widths(e.width), add="+")
        self.trees_empty = self._wrap(ttk.Label(inner, text="", style="Muted.Card.TLabel", anchor="center",
                                                justify="center"), self.px(380), fill=False)   # placed: asks nothing
        outer, inner, self.findings_title = self._card(f, "Findings")
        outer.grid(row=2, column=0, sticky="nsew", pady=(gap, 0), padx=(0, gap // 2))
        self.findings_card = outer
        frame, self.host_text = self._text(inner, 2)
        frame.pack(fill="both", expand=True)
        outer, inner, _ = self._card(f, "Selected tree")
        outer.grid(row=2, column=1, sticky="nsew", pady=(gap, 0), padx=(gap // 2, 0))
        self.detail_card = outer
        self.host_detail_frame, self.host_detail = self._text(inner, 2)
        self.host_detail_frame.pack(fill="both", expand=True)
        self._set(self.host_detail, "host_detail", "Pick a tree in the table: its findings and notes are shown"
                                                   " here.\n")
        self.host_button = ttk.Button(self.primary, text="Watch this host", command=self.host_toggle,
                                      style="Primary.TButton")

    def _build_options(self):
        """M7.2b, M7.4, M7.6c options of "Watch this host", in a disclosure
        closed by default; each is read when the watch starts."""
        tk, ttk = self.tk, self.ttk
        inner = self.options.inner
        gap = self.px(THEME["px"]["gap"])
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x")
        # M7.2b (ADR-0007 H-1): off by default; options may be None (a Controller without Options): off
        self.attach_var = tk.BooleanVar(master=self.root, value=bool(getattr(self.c.options, "attach_hooks", False)))
        self.attach_box = ttk.Checkbutton(row, text=sentence(ATTACH_TEXT), variable=self.attach_var,
                                          style="Switch.TCheckbutton")
        self.attach_box.pack(side="left")
        self.host_url = tk.StringVar(master=self.root, value="-")
        ttk.Entry(row, textvariable=self.host_url, state="readonly", width=1).pack(
            side="right", fill="x", expand=True, padx=(self.px(8), 0))
        ttk.Label(row, text="Page", style="Card.TLabel").pack(side="right", padx=(self.px(24), 0))
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x", pady=(self.px(8), 0))
        # M7.4 E3: "suspect unknown trees", empty (off) by default; M7.6c REDO E-3: its period
        ttk.Label(row, text=sentence(SUSPECT_TEXT), style="Card.TLabel").pack(side="left")
        self.suspect_var = tk.StringVar(master=self.root, value=str(getattr(self.c.options, "suspect", "") or ""))
        ttk.Entry(row, textvariable=self.suspect_var, width=10).pack(side="left", padx=(self.px(8), self.px(8)))
        ttk.Label(row, text="every", style="Card.TLabel").pack(side="left")
        self.suspect_every_var = tk.StringVar(master=self.root,
                                              value=str(getattr(self.c.options, "suspect_every", "") or ""))
        ttk.Entry(row, textvariable=self.suspect_every_var, width=4).pack(side="left", padx=self.px(8))
        ttk.Label(row, text="rounds (empty: off; every 10)", style="Muted.Card.TLabel").pack(side="left")

    def _build_project(self, project):
        tk, ttk = self.tk, self.ttk
        gap = self.px(THEME["px"]["gap"])
        f = self.first = ttk.Frame(self.screens)
        outer, inner, _ = self._card(f, "Project folder")
        outer.pack(fill="x")
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x")
        self.project = tk.StringVar(master=self.root, value=project)
        ttk.Entry(row, textvariable=self.project, width=1).pack(side="left", fill="x", expand=True,
                                                                padx=(0, self.px(8)))
        ttk.Button(row, text="Browse...", command=self.browse, style="Card.TButton").pack(side="left")
        ttk.Button(row, text="Check again", command=self.check, style="Card.TButton").pack(side="left",
                                                                                       padx=(self.px(6), 0))
        outer, inner, _ = self._card(f, "Checks")
        outer.pack(fill="both", expand=True, pady=(gap, 0))
        frame, self.doctor_rows = self._text(inner, 4)
        frame.pack(fill="both", expand=True)
        self.start_button = ttk.Button(self.primary, text="Start watching", command=self.start,
                                       style="Primary.TButton")
        # the watching screen: what the watch knocked and its page, then its findings or its final report
        f = self.watching = ttk.Frame(self.screens)
        outer, inner, _ = self._card(f)
        outer.pack(fill="x")
        self.knock_label = self._wrap(ttk.Label(inner, text=sentence(first_line(None)), style="Card.TLabel", anchor="w",
                                                justify="left"))   # A-5
        self.knock_label.pack(fill="x")
        self.refusal_label = self._wrap(ttk.Label(inner, text="", style="alarm.Level.Card.TLabel", anchor="w",
                                                  justify="left"))
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x", pady=(self.px(8), 0))
        ttk.Label(row, text="Page (read-only)", style="Card.TLabel").pack(side="left")
        self.url = tk.StringVar(master=self.root, value="-")
        ttk.Entry(row, textvariable=self.url, state="readonly", width=1).pack(side="left", fill="x", expand=True,
                                                                     padx=(self.px(8), 0))
        outer, inner, self.body_title = self._card(f, "Findings")
        outer.pack(fill="both", expand=True, pady=(gap, 0))
        frame, self.body = self._text(inner, 3)
        frame.pack(fill="both", expand=True)
        self.stop_button = ttk.Button(self.primary, text="Stop", command=self.stop, style="Primary.TButton")
        self.back_button = ttk.Button(self.primary, text="Back", command=self.show_first, style="Primary.TButton")

    def _build_rules(self):
        """M7.6 (ADR-0008), M8.1 E5: the Rules screen - one row per rule, a
        filter box, Add rule file...; it writes the overlay only."""
        tk, ttk, p = self.tk, self.ttk, self.palette
        f = self.rulesf = ttk.Frame(self.screens)
        outer, inner, _ = self._card(f)
        outer.pack(fill="both", expand=True)
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Filter", style="Card.TLabel").pack(side="left")
        self.rule_filter = tk.StringVar(master=self.root, value="")
        self.rule_filter_entry = ttk.Entry(row, textvariable=self.rule_filter, width=1)
        self.rule_filter_entry.pack(side="left", fill="x", expand=True, padx=(self.px(8), self.px(12)))
        self.rule_filter.trace_add("write", lambda *a: self._rules_filter(True))
        self.rules_count = ttk.Label(row, text="", style="Muted.Card.TLabel")
        self.rules_count.pack(side="left")
        # M8.2 E5: "New rule" is the screen's primary action; a YAML file can still be added (secondary)
        self.rules_add_button = ttk.Button(row, text="Add rule file...", command=self.rules_add, style="Card.TButton")
        self.rules_add_button.pack(side="right", padx=(self.px(12), 0))
        ttk.Separator(inner).pack(fill="x", pady=(self.px(10), 0))
        box_ = ttk.Frame(inner, style="Inner.TFrame")
        box_.pack(fill="both", expand=True)
        self.rules_canvas = tk.Canvas(box_, background=p["card"], highlightthickness=0, borderwidth=0,
                                      height=self.px(THEME["px"]["list_h"]), width=self.px(300),
                                      yscrollincrement=self.px(24))
        bar = ttk.Scrollbar(box_, command=self.rules_canvas.yview, style="Thin.Vertical.TScrollbar")
        self.rules_canvas.pack(side="left", fill="both", expand=True)
        self.rules_canvas.configure(yscrollcommand=self._scroller(bar, self.rules_canvas))
        self.rules_list = ttk.Frame(self.rules_canvas, style="Inner.TFrame")
        self.rules_list.grid_columnconfigure(1, weight=1)
        self.rules_window = self.rules_canvas.create_window(0, 0, window=self.rules_list, anchor="nw")
        self.rules_list.bind(KEYS["resize"][0], lambda e: self.rules_canvas.configure(
            scrollregion=self.rules_canvas.bbox("all")))
        self.rules_canvas.bind(KEYS["resize"][0], lambda e: self.rules_canvas.itemconfigure(self.rules_window,
                                                                                       width=e.width))
        self.root.bind_all(KEYS["wheel"][0], lambda e: self._wheel(-1 if e.delta > 0 else 1), add="+")
        self.root.bind_all(KEYS["wheel_up"][0], lambda e: self._wheel(-1), add="+")
        self.root.bind_all(KEYS["wheel_down"][0], lambda e: self._wheel(1), add="+")
        frame, self.rules_text = self._text(self.overlay.inner, 4)   # the intro and what the overlay applies
        frame.pack(fill="both", expand=True)
        self.rules_new_button = ttk.Button(self.primary, text="New rule", command=self.rules_new,
                                           style="Primary.TButton")
        self._build_rules_form()

    def _build_rules_form(self):
        """M8.2 E5 (ADR-0009 decision 4): the form a rule is made from, a screen of the Rules item: the four
        choices in words, the fields, the two examples (prefilled from the first name), Test, and Add - the
        screen's primary action, enabled only after a passing Test of the same answers. Each refusal stands
        beside its field. Every entry asks for one character of width (REDO B-1)."""
        tk, ttk, p = self.tk, self.ttk, self.palette
        style = ttk.Style(self.root)
        style.configure("Card.TRadiobutton", background=p["card"], foreground=p["ink"], font=self.font_body,
                        padding=(0, self.px(1)), indicatorbackground=p["field"], indicatorforeground=p["accent"],
                        upperbordercolor=p["field_line"], lowerbordercolor=p["field_line"])
        style.map("Card.TRadiobutton", background=[("active", p["hover"])], foreground=[("disabled", p["muted"])],
                  indicatorbackground=[("pressed", p["chip"]), ("selected", p["field"])])
        f = self.formf = ttk.Frame(self.screens)
        outer, inner, _ = self._card(f)
        outer.pack(fill="both", expand=True)
        # the fields scroll in a canvas whose height is theirs up to form_h, so a long refusal never pushes the
        # screen past 900x600 (REDO B-1); the focused field is scrolled into view
        box_ = ttk.Frame(inner, style="Inner.TFrame")
        box_.pack(fill="both", expand=True)
        self.form_canvas = tk.Canvas(box_, background=p["card"], highlightthickness=0, borderwidth=0,
                                     height=self.px(THEME["px"]["form_h"]), width=self.px(300),
                                     yscrollincrement=self.px(24))
        bar = ttk.Scrollbar(box_, command=self.form_canvas.yview, style="Thin.Vertical.TScrollbar")
        self.form_canvas.pack(side="left", fill="both", expand=True)
        self.form_canvas.configure(yscrollcommand=self._scroller(bar, self.form_canvas))
        grid = ttk.Frame(self.form_canvas, style="Inner.TFrame")
        self.form_grid = grid
        window_ = self.form_canvas.create_window(0, 0, window=grid, anchor="nw")
        grid.bind(KEYS["resize"][0], lambda e: self.form_canvas.configure(
            scrollregion=self.form_canvas.bbox("all"), height=min(e.height, self.px(THEME["px"]["form_h"]))))
        self.form_canvas.bind(KEYS["resize"][0], lambda e: self.form_canvas.itemconfigure(window_, width=e.width))
        for col in (0, 1):
            grid.grid_columnconfigure(col, weight=1, uniform="form")
        self.form_vars, self.form_said, self.form_fields, self.form_prefilled = {}, {}, {}, ("", "")
        self.form_result = None   # the last Test's or Add's Result
        self.form_after = {}   # the widget a field's refusal is packed after, beside its field

        def block(row, col):
            box_ = ttk.Frame(grid, style="Inner.TFrame")
            box_.grid(row=row, column=col, sticky="new", padx=(0, self.px(12)) if col == 0 else (0, 0),
                      pady=(0, self.px(6)))
            return box_

        def said(name, box_):
            label = self._wrap(ttk.Label(box_, text="", style="alarm.Level.Card.TLabel", anchor="w",
                                         justify="left"), self.px(200))
            self.form_said[name] = label   # packed only while it says something
            return label

        def entry(name, label, row, col):
            box_ = block(row, col)
            ttk.Label(box_, text=label, style="Bold.Card.TLabel").pack(anchor="w")
            var = tk.StringVar(master=self.root, value="")
            field = ttk.Entry(box_, textvariable=var, width=1)
            field.pack(fill="x", pady=(self.px(2), 0))
            field.bind(KEYS["focus"][0], lambda e: self._rules_form_see(e.widget), add="+")
            self.form_vars[name], self.form_fields[name], self.form_after[name] = var, field, field
            said(name, box_)
            return box_

        def choices(name, label, box_, options, side):
            ttk.Label(box_, text=label, style="Bold.Card.TLabel").pack(anchor="w", pady=(self.px(4), 0))
            var = tk.StringVar(master=self.root, value=options[0][0])
            line = ttk.Frame(box_, style="Inner.TFrame")
            line.pack(anchor="w", fill="x")
            buttons = []
            for value, words in options:
                b = ttk.Radiobutton(line, text=words, value=value, variable=var, style="Card.TRadiobutton")
                b.pack(side=side, anchor="w", padx=(0, self.px(10)) if side == "left" else 0)
                b.bind(KEYS["focus"][0], lambda e: self._rules_form_see(e.widget), add="+")
                buttons.append(b)
            self.form_vars[name], self.form_fields[name], self.form_after[name] = var, buttons[0], line
            said(name, box_)
        entry("id", ruleform.FIELD_WORDS["id"] + " (MY-RULE)", 0, 0)
        entry("title", ruleform.FIELD_WORDS["title"] + " (optional)", 0, 1)
        choices("when", ruleform.FIELD_WORDS["when"], block(1, 0),
                [(k, ruleform.FORM_WORDS[k][:1].upper() + ruleform.FORM_WORDS[k][1:]) for k in ruleform.FORMS], "top")
        values = entry("values", ruleform.FIELD_WORDS["values"], 1, 1)
        self.form_hint = self._wrap(ttk.Label(values, text="", style="Muted.Card.TLabel", anchor="w", justify="left"),
                                    self.px(200))
        self.form_hint.pack(anchor="w", fill="x")
        choices("severity", ruleform.FIELD_WORDS["severity"], values, [(k, k) for k in ruleform.SEVERITIES], "left")
        self.form_vars["severity"].set("medium")
        entry("fires", ruleform.FIELD_WORDS["fires"], 2, 0)
        entry("quiet", ruleform.FIELD_WORDS["quiet"], 2, 1)
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x", pady=(self.px(2), self.px(6)))
        self.rules_form_test_button = ttk.Button(row, text="Test", command=self.rules_form_test, style="Card.TButton")
        self.rules_form_test_button.pack(side="left")
        self.rules_form_back = ttk.Button(row, text="Back to the rules", command=self.rules_form_back_to,
                                          style="Link.TButton")
        self.rules_form_back.pack(side="left", padx=(self.px(8), 0))
        self.form_status = self._wrap(ttk.Label(row, text="", style="Muted.Card.TLabel", anchor="w",
                                                justify="left"), self.px(200))
        self.form_status.pack(side="left", fill="x", expand=True, padx=(self.px(12), 0))
        frame, self.form_text = self._text(inner, 3, mono=True)   # the YAML it will write, and "on your records"
        self.form_text.configure(takefocus=1)   # REDO E-10: the preview is reached and read by keyboard
        frame.pack(fill="both", expand=True)
        self.rules_form_add_button = ttk.Button(self.primary, text="Add rule", command=self.rules_form_add,
                                                style="Primary.TButton")
        self.rules_form_add_button.state(["disabled"])
        for name in ruleform.FIELDS:
            self.form_vars[name].trace_add("write", lambda *a, n=name: self._rules_form_changed(n))
        self._rules_form_changed("when")

    def _build_log(self):
        """A-5, F-6, M8.1 E2: the Log screen - the host watch's or the
        project watch's own lines, at any time (bounded)."""
        ttk = self.ttk
        f = self.logf = ttk.Frame(self.screens)
        outer, inner, _ = self._card(f)
        outer.pack(fill="both", expand=True)
        row = ttk.Frame(inner, style="Inner.TFrame")
        row.pack(fill="x", pady=(0, self.px(8)))
        self.log_host_button = ttk.Button(row, text="Host watch", command=lambda: self.show_log("host"),
                                          style="Segment.TButton")
        self.log_host_button.pack(side="left")
        self.log_project_button = ttk.Button(row, text="Project watch", command=lambda: self.show_log("project"),
                                             style="Segment.TButton")
        self.log_project_button.pack(side="left", padx=(self.px(4), 0))
        frame, self.log_text = self._text(inner, 4, mono=True)
        frame.pack(fill="both", expand=True)
        self.log_jump = ttk.Button(self.primary, text="Jump to newest", command=lambda: self.log_text.see("end"),
                                   style="Primary.TButton")

    def _table(self, parent, key, columns, height):
        """E2: a Treeview whose columns sort when their heading is clicked."""
        frame = self.ttk.Frame(parent, style="Inner.TFrame")
        tree = self.ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height,
                                 selectmode="browse")
        for cid, heading, width, _, _ in columns:
            tree.heading(cid, text=heading, anchor="w", command=lambda c=cid: self.sort_by(key, c))
            tree.column(cid, width=self.px(width), minwidth=self.px(40), stretch=True, anchor="w")
        for level, colour in self.palette["levels"].items():
            tree.tag_configure(level, foreground=colour)
        bar = self.ttk.Scrollbar(frame, command=tree.yview, style="Thin.Vertical.TScrollbar")
        tree.pack(side="left", fill="both", expand=True)
        tree.configure(yscrollcommand=self._scroller(bar, tree))
        return frame, tree

    # --- the screens shown ----------------------------------------------------------------------------
    def _show(self, name):
        if self.screen == name:
            return False
        if name != "rules":   # M8.2 REDO E-5: leaving the Rules screen withdraws a pending Remove
            self.rule_confirm = None
        frames = {"host": self.hostf, "first": self.first, "watching": self.watching, "rules": self.rulesf,
                  "log": self.logf, "ruleform": self.formf}
        for key, frame in frames.items():
            if key != name:
                frame.pack_forget()
        frames[name].pack(fill="both", expand=True)
        self.screen = name
        self._sync_frame()
        return True

    def _sync_frame(self):
        """E2: the rail's current item, its Open page; the screen's primary
        action, its strip and pills, its disclosures."""
        current = {"host": self.host_tab, "first": self.project_tab, "watching": self.project_tab,
                   "rules": self.rules_tab, "ruleform": self.rules_tab, "log": self.log_tab}.get(self.screen)
        for tab in (self.host_tab, self.project_tab, self.rules_tab, self.log_tab):
            style = "Current.Rail.TButton" if tab is current else "Rail.TButton"
            if str(tab.cget("style")) != style:
                tab.configure(style=style)
        page = {"host": self.host_page_button, "first": self.page_button, "watching": self.page_button,
                "log": self.host_page_button if self.log_source == "host" else self.page_button,
                # REDO A-8: on every screen; on Rules the host watch's page, else the project watch's
                "rules": self.host_page_button if self.c.host is not None or self.c.session is None
                else self.page_button}.get(self.screen)
        for button in (self.host_page_button, self.page_button):
            if button is not page and button.winfo_manager():
                button.pack_forget()
        if page is not None and not page.winfo_manager():
            page.pack(fill="x")
        self._sync_primary()
        main_pad = self.px(THEME["px"]["pad"])
        before = self.tools
        if self.screen == "host":
            self.strip_row.pack(fill="x", padx=main_pad, pady=(self.px(8), 0), before=before)
        else:
            self.strip_row.pack_forget()
        for frame, on in ((self.host_badges, self.screen == "host"), (self.badges, self.screen == "watching")):
            if on and not frame.winfo_manager():
                frame.pack(fill="x", padx=main_pad, pady=(self.px(6), 0), before=before)
            elif not on and frame.winfo_manager():
                frame.pack_forget()
        shown = {"seen": True, "checks": self.screen == "host", "options": self.screen == "host",
                 "overlay": self.screen == "rules"}
        for d in self.disclosures:
            d.toggle.pack_forget()
        self.shown.pop("tools_flow", None)
        self._flow_tools([d for d in self.disclosures if shown[d.name]])
        self._lay_panels()

    def _width(self):
        """The content column's width: its real one, else the window's geometry less the rail and the pads."""
        if self.tools.winfo_width() > 1:
            return self.tools.winfo_width()
        w, _ = self._geometry()
        return w - self.px(THEME["px"]["rail"]) - 2 * self.px(THEME["px"]["pad"])

    def _geometry(self):
        """REDO B-1: the window's size as its geometry says (a withdrawn window too), else the minimum."""
        try:
            size = str(self.root.wm_geometry()).split("+", 1)[0].split("x")
            w, h = int(size[0]), int(size[1])
        except (ValueError, IndexError):
            w, h = 1, 1
        mw, mh = self.px(THEME["min_size"])
        return (w if w > 1 else mw), (h if h > 1 else mh)

    def _flow_tools(self, toggles=None):
        """REDO B-1: the disclosure toggles of the screen in lines of the column's width."""
        if toggles is None:
            toggles = [d for d in self.disclosures if d.toggle.winfo_manager()]
        else:
            self.tools_toggles = toggles
        toggles = getattr(self, "tools_toggles", toggles)
        gap = self.px(18)
        rows = flow_rows([d.toggle.winfo_reqwidth() + gap for d in toggles], self._width())
        key = (rows, [d.name for d in toggles])
        if self.shown.get("tools_flow") == key:
            return
        self.shown["tools_flow"] = key
        for line in self.tools_lines:
            line.pack_forget()
        for d in self.disclosures:
            d.toggle.pack_forget()
        for line, row in zip(self.tools_lines, rows[:1] + [sum(rows[1:], [])]):
            if row:
                line.pack(fill="x")
                for i in row:
                    toggles[i].toggle.pack(in_=line, side="left", padx=(0, gap))
                    toggles[i].toggle.lift(line)
        line_h = max([d.toggle.winfo_reqheight() for d in toggles] + [1])
        self.tools.configure(height=max(1, min(2, len(rows)) * line_h))

    def _sync_primary(self):
        """The one primary action of the screen, at the right of its verdict."""
        want = {"host": [self.host_button], "first": [self.start_button], "rules": [self.rules_new_button],
                "ruleform": [self.rules_form_add_button], "log": [self.log_jump]}.get(self.screen)
        if want is None:   # the watching screen: Stop while it runs, Back after it
            session = self.c.session
            ended = session is not None and session.snapshot()["phase"] in ("finished", "failed")
            want = [self.back_button if ended else self.stop_button]
        for button in (self.host_button, self.start_button, self.stop_button, self.back_button,
                       self.rules_new_button, self.rules_form_add_button, self.log_jump):
            if button not in want and button.winfo_manager():
                button.pack_forget()
        for button in want:
            if not button.winfo_manager():
                button.pack(side="right")

    def _opened(self, disclosure):
        """One disclosure open at a time: opening one closes the others."""
        self.opened_now = None   # REDO B-7: the one that opens is scrolled to its named line, once
        if disclosure.is_open():
            for d in self.disclosures:
                if d is not disclosure and d.is_open():
                    d.var.set(False)
        self._lay_panels()

    def _panel_lines(self, text):
        """REDO A-13(c), B-1: an open panel's text shows as many lines as the
        pixels left in the window give (its height from the geometry, less
        what everything else asks for), at the text font's own line height
        read now; at least two, at most its content's."""
        from tkinter import font as tkfont
        line = max(1, tkfont.nametofont(str(text.cget("font"))).metrics("linespace") + int(text.cget("spacing1"))
                   + int(text.cget("spacing3")))   # a line as the text lays it out, its spacing with it
        self.root.update_idletasks()
        _, height = self._geometry()
        if not self.root.winfo_viewable():
            # the Table, 2026-11-11 (CI run 42901903944): a window that is not on the screen has no height to
            # trust - on Windows a withdrawn root reports the size it asks for, so the panel fed its own growth
            # (675 px of 600). Off the screen the lines are those the minimum size gives.
            height = self.px(THEME["min_size"])[1]
        slack = height - self.root.winfo_reqheight()
        lines = int(text.cget("height")) + slack // line   # floor: a line short of room is not given
        shown = text.count("1.0", "end", "displaylines") if text.winfo_ismapped() else None
        want = (shown[0] if isinstance(shown, tuple) else shown) or int(text.index("end-1c").split(".")[0])
        return max(2, min(want, lines))

    def _lay_panels(self):
        """E4: the open disclosures' panels, in their order, under the toggles;
        packed again only when which are open changed (REDO B-1: a re-lay
        that changes nothing changes no size, so no resize answers it)."""
        if self.laying:
            return
        visible = {d.name for d in self.disclosures if d.toggle.winfo_manager()}
        open_ = [d for d in self.disclosures if d.name in visible and d.is_open()]
        if self.shown.get("panels_open") != [d.name for d in open_]:
            self.shown["panels_open"] = [d.name for d in open_]
            for d in self.disclosures:
                if d.panel.winfo_manager():
                    d.panel.pack_forget()
            for d in open_:
                d.panel.pack(fill="x", pady=(self.px(6), 0))
            if not open_:   # an emptied pack master keeps its last size: it is told it holds nothing now
                self.panels.configure(height=1)
        rows = 2 if open_ else 3   # the trees keep the stretch; with a panel open they ask for two rows (900x600)
        if int(self.host_tree.cget("height")) != rows or not self.shown.get("table_h"):
            self.host_tree.configure(height=rows)
            self.shown["table_h"] = True
            self.root.update_idletasks()
            self.host_table_frame.configure(height=self.host_tree.winfo_reqheight())
        self.laying = True   # what is read and set here answers no resize of its own
        try:
            for d in open_:
                text = {"seen": self.seen_text, "checks": self.checks_rows, "overlay": self.rules_text}.get(d.name)
                if text is None:
                    continue
                for _ in range(3):   # settled when the window asks for no more than it has
                    lines = self._panel_lines(text)
                    if lines == int(text.cget("height")):
                        break
                    self._put(text, height=lines)
                named = getattr(text, "named_line", None)
                if named and d.name != getattr(self, "opened_now", None):   # B-7: only when it opens
                    self.opened_now = d.name
                    text.see(named)
            if hasattr(self, "first_run_label"):
                self._first_run()
        finally:
            self.laying = False

    def _mapped(self, event):
        """REDO C-4: the window came back on the screen (shown, restored): an
        open panel takes the lines the screen gives it now."""
        if event.widget is self.root and any(d.is_open() for d in self.disclosures):
            self.shown["laid_at"] = self._geometry()
            self._lay_panels()

    def _resized(self, event):
        """REDO B-1: the window's size changed: an open panel takes the lines the new size gives."""
        if event.widget is self.root and self.shown.get("laid_at") != self._geometry():
            self.shown["laid_at"] = self._geometry()
            self._lay_panels()

    def show_host(self):
        self._show("host")

    def show_first(self):
        """The project screen (M6.4's first screen, "Watch a project")."""
        if self._show("first"):
            if self.doctor_band is not None:
                self._verdict(*self.doctor_band)

    def show_watching(self):
        self._show("watching")

    def show_project(self):
        """F-2: "Project": the running project watch's screen, else the project field."""
        if self.c.project_screen() == "watching":
            self.show_watching()
        else:
            self.show_first()

    def show_log(self, source=None):
        """A-5, F-6: the Log screen, of the host watch or the project watch
        (by default the one of the screen it is opened from)."""
        if source is None:
            source = "project" if self.screen in ("first", "watching") and self.c.session is not None else (
                self.log_source if self.screen == "log" else "host")
        changed = source != self.log_source
        self.log_source = source
        self.shown.pop("log", None)
        for button, which in ((self.log_host_button, "host"), (self.log_project_button, "project")):
            button.configure(style="Current.Segment.TButton" if which == source else "Segment.TButton")
        if not self._show("log") and changed:
            self._sync_frame()
        self._tick_log()

    def show_rules(self):
        """M7.6: the Rules screen, from the rail at any time (watches running)."""
        if self._show("rules"):
            self.rules_panel.reload()
            self._rules_fill()
            self._rules_band()

    # --- the Rules screen's actions (RulesPanel's, unchanged) ---------------------------------------------
    def rules_set(self, rule_id, on):
        """E5: a rule's switch: RulesPanel.set."""
        self.rules_panel.set(rule_id, on, running=self.c.watching())
        self._rules_changed(rule_id, "switch")

    def rules_threshold(self, rule_id, field, value, part=None):
        """E5: a stepper's step: RulesPanel.threshold (measured, or refused with the fixture named)."""
        self.rules_panel.threshold(rule_id, field, str(value), running=self.c.watching())
        self._rules_changed(rule_id, part or field)

    def rules_reset(self, rule_id):
        self.rules_panel.reset(rule_id, running=self.c.watching())
        self._rules_changed(rule_id, "reset")

    def rules_add(self):
        from tkinter import filedialog
        chosen = filedialog.askopenfilename(parent=self.root, title="A rule file (.yaml) with its fixtures beside it",
                                            filetypes=[("Raqib rule", "*.yaml")])
        self.rules_panel.add(chosen or None, running=self.c.watching())
        self._rules_changed(None, None)

    def rules_remove(self, key, confirmed=False):
        """M8.2 E4: a person's rule's Remove - first a confirmation beside its row, then RulesPanel.remove
        (its folder under rules.d and its overlay lines; a running watch keeps the rules it started with). key:
        the row's own key; the removal acts on the row's place in rules.d (REDO 2 F-3)."""
        if not confirmed:
            self.rule_confirm = key
            self.shown.pop("rules_rows", None)
            self._rules_fill()
            widget = self.rule_widgets.get((key, "keep"))   # REDO E-5: a second deliberate act deletes
            if widget is not None:
                widget.focus_set()
            return
        self.rule_confirm = None
        item = next((i for i, _ in self.rule_rows if i["key"] == key), None)
        if item is None or not item.get("place"):
            self.rules_panel.message, self.rules_panel.level = "REFUSED: no row %s to remove" % key, "alarm"
        else:
            self.rules_panel.remove_rule(item["id"], running=self.c.watching(), place=item["place"])
        self._rules_changed(key, "remove")
        if self.rules_panel.level == "clean" and self.screen == "rules":
            self.rules_new_button.focus_set()

    def rules_keep(self, rule_id):
        self.rule_confirm = None
        self._rules_changed(rule_id, "remove")

    def rules_new(self):
        """M8.2 E5: the form, from the Rules screen's primary action; the first field has the focus."""
        self._show("ruleform")
        self._sync_primary()
        self._rules_form_verdict(self._rules_form_state())   # REDO E-10: a passed Test of these answers: passed
        self.form_fields["id"].focus_set()

    def _rules_form_state(self):
        """The form's state for its header: the passed Test when the answers are the same, "changed" when a field
        was edited after a passed Test (REDO 2 F-10), else None (not tested)."""
        last = getattr(self, "form_result", None)
        if last is None or not last.ok or last.records is None:
            return None
        return last if self.rules_panel.can_add(self._rules_form_answers()) else "changed"

    def _rules_form_see(self, widget):
        """The form's canvas scrolls to the field that has the keyboard's focus."""
        self.root.update_idletasks()
        top = widget.winfo_rooty() - self.form_grid.winfo_rooty()
        height = widget.winfo_height()
        total = max(self.form_grid.winfo_height(), 1)
        view = self.form_canvas.yview()
        if top / float(total) < view[0] or (top + height) / float(total) > view[1]:
            self.form_canvas.yview_moveto(max(0.0, (top - self.px(24)) / float(total)))

    def rules_form_back_to(self):
        self.show_rules()
        self.rules_new_button.focus_set()

    def _rules_form_answers(self):
        return {name: self.form_vars[name].get() for name in ruleform.FIELDS}

    def _rules_form_changed(self, name):
        """The examples follow the first name while the person has not written their own; the hint follows
        the choice; Add is enabled only for the answers that passed a Test."""
        when = self.form_vars["when"].get()
        if name in ("when", "values"):
            self.form_hint.configure(text=ruleform.VALUE_HINTS.get(when, ""))
            fires, quiet = ruleform.examples(when, self.form_vars["values"].get())
            for field, value, was in (("fires", fires, self.form_prefilled[0]), ("quiet", quiet,
                                                                                 self.form_prefilled[1])):
                if self.form_vars[field].get() in ("", was) and self.form_vars[field].get() != value:
                    self.form_vars[field].set(value)
            self.form_prefilled = (fires, quiet)
        ok = self.rules_panel.can_add(self._rules_form_answers())
        self.rules_form_add_button.state(["!disabled"] if ok else ["disabled"])
        if name != "test" and getattr(self, "screen", None) == "ruleform" and self._rules_form_state() is not None:
            state = self._rules_form_state()
            self._rules_form_verdict(state)   # REDO 2 F-10: the header never goes stale
            if state == "changed":
                self.form_status.configure(text="changed since the test: test again", style="Muted.Card.TLabel")
                self._rules_form_preview(self.form_result, stale=True)   # REDO 3 G-7: marked as the last test's
            elif self.form_status.cget("text") == "changed since the test: test again":
                self._rules_form_said(state)   # the same answers again: the passed Test's words back

    def _rules_form_said(self, res):
        """Each refusal beside its field (the rule's own beside Test), the YAML and "on your records"."""
        by, notes = {}, {}
        for field, why in res.refusals:
            by.setdefault(field if field in self.form_said else "rule", []).append(why)
        for field, words in res.notes:   # REDO E-3, E-4: what a name or place is also matched as
            notes.setdefault(field if field in self.form_said else "rule", []).append(words)
        for field, label in self.form_said.items():
            text = "; ".join(by.get(field, []) or notes.get(field, []))
            label.configure(text=text, style="alarm.Level.Card.TLabel" if by.get(field) else "Muted.Card.TLabel")
            if text and not label.winfo_manager():
                label.pack(anchor="w", fill="x", pady=(self.px(2), 0), after=self.form_after[field])
            elif not text and label.winfo_manager():
                label.pack_forget()
        rule = "; ".join(by.get("rule", []))
        short = "test passed: nothing is written in rules.d; the staging folder is removed" if (
            res.ok and res.records is not None) else (res.said or "")   # the header says what was measured
        said = "; ".join([short] + notes.get("rule", [])).strip("; ")
        self.form_status.configure(text=rule or said, style="alarm.Level.Card.TLabel" if rule else
                                   "Muted.Card.TLabel")
        self._rules_form_preview(res)
        first = next((f for f in ruleform.FIELDS if f in by), None)
        if first is not None:
            self.form_fields[first].focus_set()

    STALE = ("THE LAST TEST'S, NOT THESE ANSWERS: a field changed since the test; the YAML and \"on your records\""
             " below are what the last test gave - test again")

    def _rules_form_preview(self, res, stale=False):
        """The YAML it will write and "on your records" (read-only); stale (REDO 3 G-7): after a field changed,
        marked as the last test's, not the form's present state."""
        lines = []
        if res.records is not None:
            lines = [ruleform.records_text(res.records)] + ["  " + c for c in ruleform.cited_text(res.records)] + [""]
        text = "\n".join(lines) + (res.yaml or "") if res.ok else "\n".join(
            "refused: %s: %s" % (ruleform.FIELD_WORDS.get(f, f), w) for f, w in res.refusals)
        self._set(self.form_text, "ruleform", (self.STALE + "\n\n" + text) if stale else text)

    def _rules_form_verdict(self, res=None):
        """The form's header; its pill says the Test's word (passed, refused, not tested), not an exit code's."""
        if res is None:
            self._verdict("NEW RULE", "incomplete", "not tested yet: Test runs it on its examples and on your"
                          " records, and writes nothing in rules.d")
            word = "not tested"
        elif res == "changed":   # REDO 2 F-10: a field edited after a passed Test
            self._verdict("NEW RULE: CHANGED", "incomplete", "changed since the test: test again (Add is for the"
                          " answers that passed a Test)")
            word = "changed"
        elif res.ok and res.records is not None:
            self._verdict("NEW RULE: PASSED", "clean", "the loader and the fixture runner accept it (%s); Add puts"
                          " it in rules.d for the next watch" % ruleform.MEASURED)
            word = "passed"
        elif res.ok:
            self._verdict("NEW RULE: ADDED", "clean", res.said)
            word = "added"
        else:
            wrote = any("cannot write under" in str(w) for _, w in res.refusals)   # add_rule stopped while writing
            self._verdict("NEW RULE: REFUSED", "alarm", "%d refusal%s, each beside its field; %s" % (
                len(res.refusals), "" if len(res.refusals) == 1 else "s", "Add stopped while writing in rules.d: what"
                " it wrote is a rule with no YAML (refused at load, listed with Remove)" if wrote else
                "nothing was written in rules.d"))
            word = "refused"
        self.pill.configure(text=word)

    def rules_form_test(self):
        """M8.2 E1-E3: Test - RulesPanel.test_form (staged, judged by the engine, run on the records)."""
        self.form_status.configure(text="testing... (the rule is staged, judged on its examples, and run on your"
                                   " records)", style="Muted.Card.TLabel")
        self.root.update_idletasks()   # REDO E-9: said before it reads
        res = self.form_result = self.rules_panel.test_form(self._rules_form_answers())
        self._rules_form_said(res)
        self._rules_form_verdict(res)
        self._rules_form_changed("test")
        if res.ok:
            self.rules_form_add_button.focus_set()

    def rules_form_add(self):
        """M8.2 E2: Add - RulesPanel.add_form (overlay.add_rule's path); back to the list, the new row seen."""
        answers = self._rules_form_answers()
        res = self.form_result = self.rules_panel.add_form(answers, running=self.c.watching())
        if not res.ok:
            self._rules_form_said(res)
            self._rules_form_verdict(res)
            self._rules_form_changed("add")
            return
        for name in ("id", "title", "values", "fires", "quiet"):
            self.form_vars[name].set("")
        self._rules_form_said(ruleform.Result())
        self.show_rules()
        self._rules_changed(answers["id"].strip(), "switch")

    def _rules_changed(self, rule_id, part):
        """REDO A-6: after a change the rows are drawn again from the rules as
        they are (a refused switch or step goes back at once), and a refusal's
        reason stands beside its rule's row."""
        p = self.rules_panel
        rule_id = self._row_key(rule_id)
        self.rule_said = (rule_id, p.message) if p.level == "alarm" and rule_id else None
        self.shown.pop("rules_rows", None)
        self._rules_band()
        self._rules_fill()
        widget = self.rule_widgets.get((rule_id, part)) or self.rule_widgets.get((rule_id, "switch"))
        if widget is not None and self.screen == "rules":
            widget.focus_set()

    def _row_key(self, rule_id):
        """REDO 2 F-3: the key of the row a change was made on: a row's key as given, else the loaded row of that
        rule id (a person's rule whose folder is not named as its id)."""
        rows = getattr(self, "rule_rows", None) or []
        if rule_id is None or any(i["key"] == rule_id for i, _ in rows):
            return rule_id
        return next((i["key"] for i, _ in rows if i["id"] == rule_id and not i.get("refused")), rule_id)

    def _rules_measuring(self, line):
        """M7.6c REDO E-7: the header says a measurement runs (it may take seconds), drawn before it starts."""
        try:
            self._verdict("RULES: MEASURING", "incomplete", line)
            self.root.update_idletasks()
        except Exception:   # a header not built yet (the panel's first load) is not a crash
            pass

    def _rules_band(self):
        """The Rules screen's verdict: the last change's words; else what is
        off and, REDO A-3, incomplete while an overlay hole stands."""
        p = self.rules_panel
        holes = overlay_holes(p.info, p.error)
        if p.message:   # REDO B-3: an overlay hole decides before the last change's word does
            word = "RULES: REFUSED" if p.level == "alarm" else "RULES"
            level = "incomplete" if holes and p.level == "clean" else p.level
            self._verdict(word, level, p.message + ("; %d overlay line%s not applied (in \"Could not see\")" % (
                len(holes), "" if len(holes) == 1 else "s") if holes else ""))
            return
        off = p.info.get("off") if p.info else None
        detail = "%s; a change applies to the next watch" % sentence(p.header())
        if holes:
            detail += "; %d overlay line%s not applied (in \"Could not see\")" % (len(holes), "" if len(holes) == 1
                                                                               else "s")
        self._verdict("RULES", "incomplete" if off or holes else "clean", detail)

    def _rules_fill(self):
        """E5: one row per rule - its switch, its name and title, pills for
        kind, severity and origin, a stepper per threshold with the
        measurement's words, what is fixed, Reset when there is something
        to undo; rebuilt when the panel's rows change."""
        p = self.rules_panel
        items = rule_items(p.rows + p.refused_rows(), getattr(p, "titles", None))
        key = (repr(items), p.error, self.rule_said, self.rule_confirm)
        if self.shown.get("rules_rows") == key:
            return
        self.shown["rules_rows"] = key
        self._set(self.rules_text, "rules", p.notes_text())
        for child in self.rules_list.winfo_children():
            child.destroy()
        self.rule_vars, self.rule_widgets, self.rule_rows = {}, {}, []
        if p.error:
            self.ttk.Label(self.rules_list, text="hole: %s" % p.error, style="hole.Level.Card.TLabel").grid(
                row=0, column=0, columnspan=3, sticky="w")
        for item in items:
            self.rule_rows.append((item, self._rules_row(item)))
        self._rules_filter()

    def _rules_row(self, item):
        tk, ttk, p, X = self.tk, self.ttk, self.palette, THEME["px"]
        rid, key = item["id"], item["key"]   # REDO 2 F-3: widgets keyed by the row's own key (a person's: its place)
        frame = ttk.Frame(self.rules_list, style="Inner.TFrame")
        frame.grid_columnconfigure(1, weight=1)
        var = tk.BooleanVar(master=self.root, value=item["on"])
        self.rule_vars[key] = var
        switch = ttk.Checkbutton(frame, variable=var, style="Switch.TCheckbutton",
                                 command=lambda r=rid, v=var: self.rules_set(r, v.get()))
        switch.grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, self.px(6)), pady=(self.px(2), 0))
        if item.get("refused"):   # E-6: nothing to switch; Remove below
            switch.state(["disabled"])
        self.rule_widgets[(key, "switch")] = switch
        head = ttk.Frame(frame, style="Inner.TFrame")
        head.grid(row=0, column=1, sticky="ew")
        ttk.Label(head, text=rid, style="Bold.Card.TLabel").pack(side="left")
        if item["state"]:
            ttk.Label(head, text=item["state"], style="%s.Level.Card.TLabel" % (item["level"] or "note")).pack(
                side="left", padx=(self.px(8), 0))
        pills = ttk.Frame(frame, style="Inner.TFrame")
        pills.grid(row=0, column=2, sticky="ne")
        for text in item["pills"]:
            ttk.Label(pills, text=text, style=self._pill_style("chip", "card")).pack(side="left",
                                                                                   padx=(self.px(4), 0))
        line = self._wrap(ttk.Label(frame, text="%s%s" % (item["title"], "  \u00b7  %s" % item["meta"] if item["title"]
                                                          else item["meta"]), style="Muted.Card.TLabel", anchor="w",
                                    justify="left"), self.px(300))
        line.grid(row=1, column=1, columnspan=2, sticky="ew")
        row = 2
        if item["steppers"] or item["fixed"] or item["resettable"]:
            steps = ttk.Frame(frame, style="Inner.TFrame")
            steps.grid(row=row, column=1, columnspan=2, sticky="ew", pady=(self.px(6), 0))
            for t in item["steppers"]:
                self._rules_stepper(steps, rid, t, key)
            for text in item["fixed"]:
                self._wrap(ttk.Label(steps, text=text, style="Muted.Card.TLabel", anchor="w", justify="left")).pack(
                    anchor="w", fill="x", pady=(0, self.px(4)))
            if item["resettable"]:
                reset = ttk.Button(steps, text="Reset to the YAML", style="Link.TButton",
                                   command=lambda r=rid: self.rules_reset(r))
                reset.pack(anchor="w")
                self.rule_widgets[(key, "reset")] = reset
        if item.get("origin") == "user" and item.get("place"):   # M8.2 E4: a person's rule can be removed
            row += 1
            gone = ttk.Frame(frame, style="Inner.TFrame")
            gone.grid(row=row, column=1, columnspan=2, sticky="ew", pady=(self.px(4), 0))
            what = "Its YAML and its fixtures are" if item["place"] == item["id"] or not item.get("refused") else (
                "%s is" % item["place"])
            if not item.get("removable"):   # REDO 2 F-3: not a place Raqib could have written: no Remove
                self._wrap(ttk.Label(gone, text=item.get("no_remove") or BY_HAND, style="Muted.Card.TLabel",
                                     anchor="w", justify="left"), self.px(300)).pack(anchor="w", fill="x")
                # REDO 3 G-7: the path is reached by Tab and can be selected and copied (read-only)
                path = ttk.Entry(gone, width=1, takefocus=True)
                path.insert(0, item.get("path") or item["place"])
                path.state(["readonly"])
                path.pack(anchor="w", fill="x", pady=(self.px(2), 0))
                self.rule_widgets[(key, "path")] = path
            elif self.rule_confirm == key:
                self._wrap(ttk.Label(gone, text="Remove %s? %s deleted from rules.d." % (item["place"], what),
                                     style="alarm.Level.Card.TLabel", anchor="w", justify="left"),
                           self.px(300)).pack(anchor="w", fill="x")
                sure = ttk.Button(gone, text="Remove it", style="Card.TButton",
                                  command=lambda r=key: self.rules_remove(r, confirmed=True))
                sure.pack(side="left", pady=(self.px(4), 0))
                keep = ttk.Button(gone, text="Keep it", style="Link.TButton", command=lambda r=key: self.rules_keep(r))
                keep.pack(side="left", padx=(self.px(8), 0), pady=(self.px(4), 0))
                self.rule_widgets[(key, "confirm")] = sure
                self.rule_widgets[(key, "keep")] = keep
            else:
                remove = ttk.Button(gone, text="Remove", style="Link.TButton", command=lambda r=key: self.rules_remove(r))
                remove.pack(anchor="w")
                self.rule_widgets[(key, "remove")] = remove
        if self.rule_said and self.rule_said[0] == key:   # REDO A-6: the refusal, beside its rule
            row += 1
            self._wrap(ttk.Label(frame, text=self.rule_said[1], style="alarm.Level.Card.TLabel", anchor="w",
                                 justify="left"), self.px(300)).grid(row=row, column=1, columnspan=2, sticky="ew",
                                                                    pady=(self.px(4), 0))
        ttk.Separator(frame).grid(row=row + 1, column=0, columnspan=3, sticky="ew", pady=(self.px(10), 0))
        for (r, _), widget in self.rule_widgets.items():
            if r == key:
                widget.bind(KEYS["focus"][0], lambda e, f=frame: self._rules_see(f), add="+")
        return frame

    def _rules_stepper(self, parent, rid, t, key=None):
        """E5: a threshold's stepper within its bounds: minus, the value, plus, and its words (its widgets
        keyed by the row's key, REDO 2 F-3)."""
        ttk = self.ttk
        row_key = rid if key is None else key
        box_ = ttk.Frame(parent, style="Inner.TFrame")
        box_.pack(anchor="w", pady=(0, self.px(4)))
        ttk.Label(box_, text=t["name"], style="Bold.Card.TLabel").pack(side="left", padx=(0, self.px(6)))
        for part, step in (("minus", -1), ("value", 0), ("plus", 1)):
            if not step:   # REDO A-12: the value can be typed; Enter sets it, measured as a step is
                entry = ttk.Entry(box_, width=5, justify="center")
                entry.insert(0, str(t["value"]))
                entry.pack(side="left", padx=self.px(4))
                for key in KEYS["act"]:
                    entry.bind(key, lambda e, n=t["name"]: self.rules_threshold(rid, n, e.widget.get().strip(),
                                                                               n + "="))
                self.rule_widgets[(row_key, t["name"] + "=")] = entry
                continue
            target = t["value"] + step
            ok = t["low"] <= target <= t["high"]
            key = t["name"] if step > 0 else t["name"] + "-"
            button = ttk.Button(box_, image=self.images[(part,) if ok else (part, "off")], style="Step.TButton",
                                command=lambda n=t["name"], v=target, k=key: self.rules_threshold(rid, n, v, k))
            if not ok:
                button.state(["disabled"])
            button.pack(side="left")
            self.rule_widgets[(row_key, key)] = button
        ttk.Label(box_, text=t["words"], style="Muted.Card.TLabel").pack(side="left", padx=(self.px(8), 0))

    def _rules_filter(self, top=False):
        """E5: the rows the filter box keeps, in catalog order (top: back to the first)."""
        text = self.rule_filter.get()
        shown = 0
        for i, (item, frame) in enumerate(self.rule_rows):
            if rule_matches(item, text):
                frame.grid(row=i + 1, column=0, columnspan=3, sticky="ew", pady=(self.px(10), 0))
                shown += 1
            else:
                frame.grid_remove()
        total = len(self.rule_rows)
        off = sum(1 for item, _ in self.rule_rows if not item["on"])
        self.rules_count.configure(text="%d rules, %d off%s" % (total, off, "; %d shown" % shown if shown != total
                                                                 else ""))
        if top:
            self.rules_canvas.yview_moveto(0)

    def _rules_see(self, frame):
        """E5: the list scrolls to the row that has the keyboard's focus."""
        self.root.update_idletasks()
        top, height = frame.winfo_y(), frame.winfo_height()
        total = max(self.rules_list.winfo_height(), 1)
        view = self.rules_canvas.yview()
        if top / float(total) < view[0] or (top + height) / float(total) > view[1]:
            self.rules_canvas.yview_moveto(max(0.0, (top - self.px(8)) / float(total)))

    def _wheel(self, step):
        """The mouse wheel scrolls the Rules list (M8.2: or the form) while the pointer is over it."""
        canvas = self.form_canvas if self.screen == "ruleform" else self.rules_canvas
        if self.screen not in ("rules", "ruleform") or not canvas.winfo_ismapped():
            return
        x, y = self.root.winfo_pointerxy()
        left, top = canvas.winfo_rootx(), canvas.winfo_rooty()
        if left <= x < left + canvas.winfo_width() and top <= y < top + canvas.winfo_height():
            canvas.yview_scroll(step, "units")

    # --- the host's actions -------------------------------------------------------------------------
    def open_host_page(self):
        """F-11: the host watch's page, by the person's click (never under CI)."""
        self.c.page_note = self.c.open_page("host")

    def host_toggle(self):
        """E2: "Watch this host" starts the host watch; while it runs the
        button is its Stop, which ends it with its final report."""
        if self.c.host_watching():
            self.c.stop_host("Stop in the window")
            return
        if self.c.options is not None:   # H-1: the box's word for this watch
            self.c.options.attach_hooks = bool(self.attach_var.get())
            self.c.options.suspect = str(self.suspect_var.get() or "").strip()   # M7.4 E3: empty is off
            self.c.options.suspect_every = str(self.suspect_every_var.get() or "").strip()   # M7.6c REDO E-3
        self.c.host_note = self.c.start_host()
        self.show_host()

    # --- drawing what the controller says ---------------------------------------------------------
    def _set(self, widget, key, content, tags=None, follow=False):
        """Replace a Text widget's content when it changed (no flicker); a
        followed text stays at its end when it was there, else keeps its place."""
        if self.shown.get(key) == (content, tags):
            return
        self.shown[key] = (content, tags)
        first, last = widget.yview()
        widget.configure(state="normal")
        for child in widget.winfo_children():   # pills of items drawn before (A-13)
            child.destroy()
        widget.delete("1.0", "end")
        if tags is None:
            widget.insert("end", content)
        else:
            for line, tag in tags:
                widget.insert("end", line + "\n", (tag,) if tag else ())
        widget.configure(state="disabled")
        if follow:
            if last >= 0.999:
                widget.see("end")
            else:
                widget.yview_moveto(first)

    def _items(self, text, key, items, empty):
        """REDO A-13(a): findings as items in a text that scrolls: the pill
        (the severity and its word), the rule's id, its sentence; under them,
        quiet, where and when (round or seq, how it knocked, what it cites)."""
        if self.shown.get(key) == ("items", items):
            return
        self.shown[key] = ("items", items)
        p = self.palette
        first = max([self.font_meta_bold.measure(i[0]) for i in items] + [0]) + 2 * self.pill_r + self.px(10)
        text.configure(state="normal", tabs=(first,))
        text.tag_configure("item", lmargin2=first, spacing1=self.px(6))
        text.tag_configure("rule", font=self.font_bold)
        text.tag_configure("where", lmargin1=first, lmargin2=first, font=self.font_meta, foreground=p["muted"],
                           spacing3=self.px(2))
        for child in text.winfo_children():
            child.destroy()
        text.delete("1.0", "end")
        if not items:
            text.insert("end", empty + "\n")
        for word, level, rule, sentence_, where in items:
            text.window_create("end", window=self.ttk.Label(text, text=word, style=self._pill_style(level, "card")),
                               align="center")
            text.insert("end", "\t", "item")
            text.insert("end", rule, ("item", "rule"))
            text.insert("end", "  %s\n" % sentence_, "item")
            if where:
                text.insert("end", where + "\n", "where")
        text.configure(state="disabled")

    @staticmethod
    def _put(widget, **kw):
        """Configure only what changed (nothing is redrawn at every tick)."""
        changed = {k: v for k, v in kw.items() if str(widget.cget(k)) != str(v)}
        if changed:
            widget.configure(**changed)

    def _verdict(self, word, level, detail, result=False, suppressed=0, counts=None):
        """E2: the verdict header: the level's pill with its word (level_of,
        REDO C-1), the state in one sentence, what goes beside a watch's
        green state ("Not a clearance.", the suppressed count, REDO C-3), the
        detail."""
        level = level_of(level)
        self.verdict_word = word
        p = self.palette
        style = self._pill_style(level)
        if self.pill.cget("text") != level_word(level) or str(self.pill.cget("style")) != style:
            self.pill.configure(text=level_word(level), style=style)
        text = verdict_sentence(word)
        if counts is not None and word in ("WATCHING HOST", "WATCHING"):   # REDO A-2, B-5: what so far, and why
            text = so_far(text, *counts)
        if self.verdict.cget("text") != text:
            self.verdict.configure(text=text)
        note = verdict_note(level, suppressed, result, detail)
        colour = p["levels"]["suppressed"] if suppressed else p["muted"]
        if self.note.cget("text") != note or str(self.note.cget("foreground")) != colour:
            self.note.configure(text=note, foreground=colour)
        if note and not self.note.winfo_manager():
            self.note.pack(fill="x", pady=(self.px(4), 0), before=self.detail)
        elif not note and self.note.winfo_manager():
            self.note.pack_forget()
        detail = sentence(detail)
        if self.detail.cget("text") != detail:
            self.detail.configure(text=detail)

    def _badges(self, frame, key, badges):
        """REDO C-2, E4: each (level, text) badge its own pill, its level's
        colour with its word in bold; laid in rows that fit the column.
        REDO C-4: a badge too long for its line ends in an ellipsis, and its
        whole text is a line of "Could not see" (cut_badges)."""
        items = badge_items(badges)
        room = frame.winfo_width() if frame.winfo_width() > 1 else self._width()
        if self.shown.get(key) == (items, room):
            return
        self.shown[key] = (items, room)
        self.cut_badges[key] = []
        for child in frame.winfo_children():
            child.destroy()
        p = self.palette
        for word, whole, level in items:
            fixed = self.font_meta_bold.measure(word) + 2 * self.pill_r + self.px(12) if level != "clean" else self.px(8)
            text = fit_cell(whole, room - fixed, self.font_meta.measure)
            if text != whole:
                self.cut_badges[key].append((level, "badge in full: %s" % whole))
            if level == "clean":   # REDO A-13(b): a clean badge is quiet text; green is the verdict's and the strip's
                pill = self.tk.Label(frame, text=text, font=self.font_meta, background=p["ground"],
                                     foreground=p["muted"], borderwidth=0, padx=0, pady=self.pill_pad)
                pill.width, pill.level = self.font_meta.measure(text) + self.px(6), level
                continue
            pill = self.ttk.Frame(frame, style=self._pill_frame_style(level))
            for part, font, pad in ((word, self.font_meta_bold, (self.pill_r, self.px(5))),
                                    (text, self.font_meta, (0, self.pill_r))):
                self.tk.Label(pill, text=part, font=font, background=p["pill"][level], foreground=p["levels"][level],
                              borderwidth=0, padx=0, pady=self.pill_pad).pack(side="left", padx=pad)
            pill.width = self.font_meta_bold.measure(word) + self.font_meta.measure(text) + 2 * self.pill_r + self.px(5)
            pill.level = level
        self._flow(frame)

    def _pill_frame_style(self, level):
        """A pill's ground for a frame of two labels (the badges)."""
        name = "%s.Pill.TFrame" % level
        if name not in self.styles:
            label = self._pill_style(level)
            self.styles.add(name)
            self.style.layout(name, [(label + ".box", {"sticky": "nswe"})])
        return name

    def _flow(self, frame):
        """The pills of frame in rows of the frame's width (flow_rows), each row its own line."""
        pills = [w for w in frame.winfo_children() if hasattr(w, "width")]
        width = frame.winfo_width() if frame.winfo_width() > 1 else self.px(600)
        rows = flow_rows([w.width for w in pills], width, self.px(6))
        if self.shown.get(("flow", str(frame))) == (rows, width, len(pills)):
            return
        self.shown[("flow", str(frame))] = (rows, width, len(pills))
        line_h = max([w.winfo_reqheight() for w in pills] + [1]) + self.px(3)
        frame.configure(height=max(1, len(rows) * line_h))
        for old in [w for w in frame.winfo_children() if not hasattr(w, "width")]:
            old.destroy()
        for row in rows:
            line = self.ttk.Frame(frame)
            line.pack(fill="x", pady=(0, self.px(3)))
            for i in row:
                pills[i].pack(in_=line, side="left", padx=(0, self.px(6)))
                pills[i].lift(line)   # above its line, which was made after it

    def _seen(self, lines):
        """E4: "could not see (N)": every hole of the screen, one click
        away, never dropped; the notes below them."""
        holes = sum(1 for x in lines if x.startswith("hole: "))
        grew = self.shown.get("seen_lines") != list(lines)
        self.shown["seen_lines"] = list(lines)
        self.seen.set_title(seen_title(lines), "Hole.Disclosure.TCheckbutton" if holes else "Disclosure.TCheckbutton")
        self._set(self.seen_text, "seen", None, tuple((x, "hole" if x.startswith("hole:") else "note") for x in lines)
                  or (("No hole on this screen.", None),))
        if grew and self.seen.is_open():   # REDO B-7: the panel grows with the lines that arrive
            self._lay_panels()

    def _fill(self, key, tree, items, columns):
        """E2: a Treeview's rows [(values, level, payload, row)], sorted
        as its heading was last clicked through sort_rows (REDO C-7: the row
        is what columns index); each row's id from table_iids, given before
        the sort, so the selection survives a sort and a refresh."""
        column, reverse = self.sorting[key]
        items = [(iid,) + tuple(it) for iid, it in zip(table_iids([it[0] for it in items]), items)]
        if column is not None:
            items = sort_rows(items, columns, column, reverse, get=lambda it: it[4])
        if self.shown.get("table:" + key) == items:
            return False
        self.shown["table:" + key] = items
        picked = tree.selection()
        tree.delete(*tree.get_children())
        self.payload[key] = {}
        for iid, values, level, payload, _ in items:
            tree.insert("", "end", iid=iid, values=values, tags=(level,) if level else ())
            self.payload[key][iid] = payload
        for cid, heading, _, _, _ in columns:   # the sort arrow, drawn
            tree.heading(cid, text=heading, image=self.images[("arrow", "down" if reverse else "up")]
                         if cid == column else "")
        keep = [i for i in picked if i in self.payload[key]]
        if keep:
            tree.selection_set(keep)
        return True

    def sort_by(self, key, column):
        """E2: a heading clicked: sort by that column; clicked again, the other way."""
        current, reverse = self.sorting[key]
        self.sorting[key] = (column, not reverse if current == column else False)
        self.shown.pop("table:" + key, None)
        self.shown.pop("host_widths", None)
        self._fill_host(self.c.host_view())
        self._table_widths()   # the sorted column has room for its arrow

    def _table_widths(self, width=None):
        """REDO A-11: the trees' columns in the card's whole width (each at
        least its heading, with room for the sort arrow on the sorted one);
        the cells drawn again, cut with an ellipsis where they must be."""
        width = width or self.host_tree.winfo_width()
        if width <= 1:
            return
        column = self.sorting["host"][0]
        pad, arrow = self.px(16), self.px(THEME["px"]["chevron"] + 6)
        mins = [self.font_meta_bold.measure(c[1]) + pad + (arrow if c[0] == column else 0) for c in TREE_COLUMNS]
        rows = [self._display(row) for row in (self.shown.get("host_rows") or [])]
        cell = self.px(12)

        def need(i, whole):   # REDO B-7: the severities, the pid and the kind's flags first; then the kind whole
            name = TREE_COLUMNS[i][0]
            if name not in TREE_WHOLE:
                return mins[i]
            texts = [str(r[i]) for r in rows]
            if name == "kind" and not whole:
                texts = [ELLIPSIS + " (" + t.split(" (", 1)[1] for t in texts if t.endswith(")") and " (" in t]
            return max([self.font_body.measure(t) + cell for t in texts] + [mins[i]])
        needs = ([need(i, False) for i in range(len(mins))], [need(i, True) for i in range(len(mins))])
        wants = [max([self.font_body.measure(r[i]) + self.px(12) for r in rows] + [mins[i]]) for i in range(len(mins))]
        tree = self.host_tree   # what the table asks beyond its columns (its frame, its padding)
        extra = max(0, tree.winfo_reqwidth() - sum(int(tree.column(c[0], "width")) for c in TREE_COLUMNS))
        extra = min(extra, self.px(12))   # REDO B-7: a size not yet recomputed is not taken from the card
        widths = column_widths(width - extra - self.px(2), mins, wants, TREE_ORDER, needs, TREE_NEED_ORDER)
        if self.shown.get("host_widths") != widths:
            self.shown["host_widths"] = widths
            for c, w in zip(TREE_COLUMNS, widths):
                self.host_tree.column(c[0], width=w, minwidth=min(w, self.px(30)), stretch=False)
            self.shown.pop("table:host", None)
            self._fill_host(self.shown.get("host_view") or {})

    def _display(self, row):
        """The values a tree's row shows: tree_values, "first seen" as a time when it is today's (UTC)."""
        import datetime
        today = datetime.datetime.fromtimestamp(time.time(), datetime.timezone.utc).strftime("%Y-%m-%d")
        values = list(tree_values(row))
        first = [c[0] for c in TREE_COLUMNS].index("first")
        values[first] = first_seen_text(values[first], today)
        return values

    def _fill_host(self, view):
        details = view.get("details") or []
        rows_now = list(view.get("rows") or [])
        changed = self.shown.get("host_rows") != rows_now
        self.shown["host_view"], self.shown["host_rows"] = view, rows_now
        if changed and self.shown.get("host_widths") is not None:   # new cells: the columns shared again
            self.shown.pop("host_widths", None)
            self._table_widths()
            return
        widths = self.shown.get("host_widths")
        pad = self.px(10)

        def shown(row):
            values = self._display(row)
            if widths:   # REDO A-11: a cell that must be cut ends in an ellipsis; the full text is in Selected tree
                values = [fit_cell(v, w - pad, self.font_body.measure, flags=c[0] == "kind")
                          for v, w, c in zip(values, widths, TREE_COLUMNS)]   # REDO C-7: brackets kept in kind only
            return tuple(values)
        items = [(shown(row), row_level(row), (row, details[i] if i < len(details) else None), row)
                 for i, row in enumerate(view.get("rows") or [])]
        if self._fill("host", self.host_tree, items, TREE_COLUMNS):
            self._show_tree_detail()
        empty = "" if items else empty_trees_text(view)
        if self.trees_empty.cget("text") != empty:
            self.trees_empty.configure(text=empty)
        if empty and not self.trees_empty.winfo_manager():
            self.trees_empty.place(relx=0.5, rely=0.55, anchor="center")
        elif not empty and self.trees_empty.winfo_manager():
            self.trees_empty.place_forget()

    def _show_tree_detail(self):
        picked = self.host_tree.selection()
        payload = self.payload["host"].get(picked[0]) if picked else None
        if payload is None:
            text = ("Pick a tree in the table: its findings and notes are shown here.\n" if self.payload["host"]
                    else "No tree in the table.\n")
            self._set(self.host_detail, "host_detail", text)
            return
        self._set(self.host_detail, "host_detail", None, text_tags(tree_detail_text(*payload)))

    def _first_run(self):
        """E4: the three first-run lines while ~/.raqib/host/look.json does
        not exist; M8.1: not while the host is watched (they say what the
        window shows before the first look; the watch's verdict says the
        rest) nor while a disclosure is open (one explanation at a time, so
        the screen keeps 900x600)."""
        panel = any(d.is_open() and d.toggle.winfo_manager() for d in self.disclosures)
        lines = first_run_lines(self.home) if not (self.c.host_watching() or panel) else []
        if lines and not self.first_run_shown:
            self.first_run_label.configure(text="\n".join(lines))
            self.first_run_label.pack(fill="x", pady=(0, self.px(10)), before=self.host_table_frame)
            self.first_run_shown = True
        elif not lines and self.first_run_shown:
            self.first_run_label.pack_forget()
            self.first_run_label.configure(text="")
            self.first_run_shown = False

    def _check_rows(self, text, key, lines):
        """E4: doctor's checks as rows in a text that scrolls: the pill with
        its word, the name, the sentence (wrapped under itself)."""
        rows = check_rows(lines)
        if self.shown.get(key) == rows:
            return
        self.shown[key] = rows
        pill = max(self.font_meta_bold.measure(w) for w in ("OK", "missing", "unsure", "note")) + 2 * self.pill_r
        names = max([self.font_bold.measure(n) for _, _, n, _ in rows] or [0])
        first, second = pill + self.px(12), pill + names + self.px(24)
        text.configure(state="normal", tabs=(first, second))
        text.tag_configure("row", lmargin2=second, spacing1=self.px(3), spacing3=self.px(3))
        text.tag_configure("name", font=self.font_bold)
        for child in text.winfo_children():
            child.destroy()
        text.delete("1.0", "end")
        named = [i for i, r in enumerate(rows) if r[1] == "alarm"] or [i for i, r in enumerate(rows)
                                                                        if r[1] == "incomplete"]
        text.named_line = "%d.0" % (named[0] + 1) if named else None   # what the disclosure's title names
        for word, level, name, sentence_ in rows:
            label = self.ttk.Label(text, text=word, style=self._pill_style(level, "card"))
            text.window_create("end", window=label, align="center")
            text.insert("end", "\t", "row")
            text.insert("end", name, ("row", "name"))
            text.insert("end", "\t%s\n" % sentence_, "row")
        text.configure(state="disabled")

    # --- actions ----------------------------------------------------------------------------------
    def browse(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(parent=self.root, initialdir=self.project.get() or os.getcwd(),
                                         title="The project the agent works in")
        if chosen:
            self.project.set(os.path.normpath(chosen))
            self.check()

    def check(self):
        self.doctor = self.make_doctor(self.project.get()).start()
        self.doctor_band = ("CHECKING", "incomplete", "raqib doctor is running for %s" % _safe(self.project.get()))
        if self.screen == "first":
            self._verdict(*self.doctor_band)

    def start(self):
        why = self.c.start(self.project.get())
        if why:
            if self.c.project_watching():   # F-2: the refusal names the running watch and goes to its screen
                self.show_watching()
            self._verdict("NOT STARTED", "alarm", why)
            self.refusal = why
            return
        self.refusal = None
        self.show_watching()

    def stop(self):
        self.c.stop_project("Stop in the window")

    def open_page(self):
        self.c.page_note = self.c.open_page()

    def on_close(self):
        action = self.c.close_request()
        if action == "hide":
            self.root.withdraw()
        elif action == "quit":
            self.destroy()
        elif self.screen != "host" and self.c.session is not None:
            self.show_watching()   # the project watch's final report stays on screen
        else:
            self.show_host()       # the host watch's final report stays on screen

    def destroy(self):
        if self.closed:
            return
        self.closed = True
        if self.after_id is not None:
            try:
                self.root.after_cancel(self.after_id)
            except Exception:
                pass
        self.c.shutdown()
        self.root.destroy()

    # the after() cycle
    def tick(self):
        """The after() cycle; REDO C-4: whatever fails in it, the next tick is
        scheduled (a failure in the panels' layout cannot stop the window)."""
        self.after_id = None
        try:
            try:
                self._tick()
            except Exception as exc:   # A3, A-8: the window says what broke, keeps it, and keeps going
                self.c.hole("the window failed to update: %s: %s" % (type(exc).__name__, exc))
                self._seen_safely()   # REDO A-5: added to the list it had, nothing leaves it
            if self.closed:
                return
            if self.c.can_exit():
                self.destroy()
                return
            if self.c.quit_overdue():   # A-3: the watch did not end: the window comes back, nothing is killed
                self.root.deiconify()
                self.root.lift()
                self._seen_safely()
        finally:
            if not self.closed and self.after_id is None:
                self.after_id = self.root.after(TICK_MS, self.tick)

    def _seen_safely(self):
        """REDO C-4: "could not see" after a failed tick; if laying it out fails
        too, the line is kept (the controller's holes) and the tick goes on."""
        try:
            self._seen(self._kept_lines())
        except Exception as exc:
            self.c.hole("the window could not lay out \"Could not see\": %s: %s" % (type(exc).__name__, exc))

    def _own(self):
        """The window's own holes (a tray, a callback, a tick) and the look's
        until the host watch's first round (F-3); the notes."""
        own = self.c.holes + self.c.tray_holes()
        own += overlay_holes(self.rules_panel.info, self.rules_panel.error)   # REDO A-3: the overlay's, everywhere
        own += missing_checks(self.checks_lines)                             # REDO A-7: each MISSING check
        notes = list(self.c.notes) + (["page: %s" % self.c.page_note] if self.c.page_note else [])
        return own, self.c.look_holes(), notes

    def _kept_lines(self):
        """REDO A-5: the list "could not see" had, with the window's own
        holes added: a tick that fails takes no line out of it."""
        kept = list(self.shown.get("seen_lines") or [])
        own = self.c.holes + self.c.tray_holes()
        holes = [x for x in kept if x.startswith("hole: ")] + ["hole: %s" % h for h in own
                                                                if "hole: %s" % h not in kept]
        return holes + [x for x in kept if not x.startswith("hole: ")]

    def _live(self, view):
        """REDO A-2, B-2, B-4, B-5, B-6: each running watch's state word,
        level (the code its state says it would end with so far; the last one
        known while a state has none; incomplete before any), its findings and
        suspicions (one count), and why when the level needs it."""
        self.live = {}
        host = self.c.host
        state = (getattr(host, "last_state", None) or host.state()) if host is not None else None
        session = self.c.session
        pstate = session.state() if self.c.project_watching() else None
        self.live_states = {"host": state, "project": pstate}   # REDO B-6: what this tick counts, read once
        self.counts = {"host": host_counts(state or {}), "project": project_count(pstate)}
        if self.c.host_watching() and not view.get("final"):
            found, sus = self.counts["host"]
            code = self._known(self.c.host, (state or {}).get("code_so_far"))
            self.live["host"] = (view["word"], live_level(code, view["word"]), found, sus,
                                 live_cause(code, found, sus, host_causes(state)))   # REDO C-2, C-3
        if self.c.project_watching():
            if not pstate:
                self.live["project"] = ("STARTING", "incomplete", 0, 0, "not judged yet")
            else:
                pview = watch_view(pstate)
                found = self.counts["project"]
                code = self._known(session, pstate.get("code_so_far"))
                fresh = never_read(pstate, pview["word"])   # REDO C-1: as the watch says it, never inferred
                self.live["project"] = (pview["word"], live_level(code, pview["word"], fresh), found, 0,
                                        live_cause(code, found, 0, watch_causes(pstate), fresh))

    def _known(self, session, code):
        """REDO B-2: the code a state says, or the last one this session's states said."""
        if isinstance(code, int) and not isinstance(code, bool):
            self.codes[id(session)] = code
            return code
        return self.codes.get(id(session))

    def _rail(self):
        """E2, REDO A-8: the rail's words: what is watched, each running
        watch's state in words and its level's pill; the rules line (red while
        a running watch's off rules would have fired, ADR-0008 A-2; how many
        were refused, REDO A-3)."""
        p = self.palette
        host_on, project_on = "host" in self.live, "project" in self.live
        words = watch_words(host_on, self.c.session.project if project_on else None)
        self._put(self.running_note, text=words, foreground=p["rail_ink" if host_on or project_on else "rail_muted"])
        rows = []
        for key, title in (("host", "Host"), ("project", "Project")):
            if key in self.live:
                word, level, found, sus, cause = self.live[key]
                rows.append((title,) + rail_state(word, level, found, sus, cause))
        if self.shown.get("rail_watches") != rows:
            self.shown["rail_watches"] = rows
            for child in self.rail_watches.winfo_children():
                child.destroy()
            for title, level, text in rows:
                row = self.tk.Frame(self.rail_watches, background=p["rail"])
                row.pack(fill="x", pady=(0, self.px(6)))
                self.tk.Label(row, text=title, font=self.font_meta_bold, background=p["rail"], foreground=p["rail_ink"],
                              borderwidth=0, padx=0).pack(side="left")
                self.ttk.Label(row, text=level_word(level), style=self._pill_style(level, "rail")).pack(side="right")
                self.tk.Label(self.rail_watches, text=text, font=self.font_meta, background=p["rail"], anchor="w",
                              justify="left", foreground=p["rail_levels"][level] if level != "clean" else p["rail_muted"],
                              wraplength=self.px(THEME["px"]["rail"] - 40), borderwidth=0, padx=0).pack(
                    fill="x", pady=(0, self.px(8)))
        states = [getattr(x, "last_state", None) for x in self.c.sessions() if Controller._live(x)]
        text, level = rail_rules(self.rules_panel.info, self.rules_panel.error, states)
        colour = p["rail_levels"][level] if level else p["rail_muted"]
        self._put(self.rules_note, text=text, foreground=colour)

    def _tick(self):
        for action in self.c.drain():
            if action in ("show", "stop"):
                self.root.deiconify()
                self.root.lift()
        fresh = self._tick_doctor()
        own, look, notes = self._own()
        self.c.report_finished()   # F-8: each finished watch's report, appended to the log once
        view = self.c.host_view()
        self._live(view)           # REDO A-2: each running watch's level, the code it would end with now
        self._rail()               # M7.6: rules off; REDO A-8: each running watch's state
        self._first_run()          # E4: gone once the first look is written (and while the host is watched)
        if self.shown.get("laid_at") != self._geometry() and any(d.is_open() for d in self.disclosures):
            self.shown["laid_at"] = self._geometry()   # REDO B-1: an open panel follows the window's size
            self._lay_panels()
        found, sus = self.counts["host"]   # REDO B-6: one count, the verdict's, the rail's and the card's
        self.c.host_tip(view.get("trees"), view.get("new"), found, sus, self.counts["project"])   # E5: the tray
        self._sync_primary()
        if self.screen in ("rules", "ruleform"):   # M8.2: the form is a screen of the Rules item
            if self.screen == "rules":
                self._rules_fill()
            self._seen(seen_lines(own, notes, look))
            return
        if self.screen == "log":
            self._tick_log()
            self._seen(seen_lines(own, notes, look))
            return
        if self.screen == "host":
            self._tick_host(view, own, notes)
            return
        session = self.c.session
        if self.screen == "first" or session is None:
            if fresh and self.screen == "first":
                self._verdict(*self.doctor_band)
            self._seen(seen_lines(own, notes, look))
            return
        snap = session.snapshot()
        state = self.live_states.get("project") if self.c.project_watching() else session.state()   # B-6: one read
        extra = snap["holes"] + own + look + ([session.read_note] if session.read_note else [])
        self._put(self.knock_label, text=sentence(first_line(snap.get("knock"))))
        refused = self.refusal and self.c.project_watching()
        if refused and not self.refusal_label.winfo_manager():
            self.refusal_label.pack(fill="x", pady=(self.px(4), 0), before=self.knock_label)
        elif not refused and self.refusal_label.winfo_manager():
            self.refusal_label.pack_forget()
        self._put(self.refusal_label, text="Not started: %s" % self.refusal if refused else "")
        if snap["phase"] == "failed" and snap["final_text"] is None:
            self._verdict("NOT WATCHING", "alarm", snap["error"] or "the watch did not start")
            self._put(self.body_title, text="The watch's lines")
            self._set(self.body, "body", (session.log.text() or "") + "\n" + (snap["error"] or "") + "\n")
            self._seen(seen_lines(extra, notes))
            return
        if snap["phase"] == "finished":
            self._verdict("FINISHED", report_level(snap["final_exit"], snap["final_text"]),   # REDO C-1: exit 3 amber
                          "the watch ended; its final report is below (exit %s)" % snap["final_exit"], result=True,
                          suppressed=report_result(snap["final_text"])[1])                   # REDO C-3
            self._put(self.body_title, text="Final report")
            self._put(self.body, font="TkFixedFont")
            self._set(self.body, "body", None, text_tags(snap["final_text"]))
            self._seen(seen_lines(extra, notes))
            return
        if state is None:
            self._verdict("STARTING", "incomplete", "installing the hooks and starting the watch of %s"
                          % _safe(session.project))
            self._seen(seen_lines(extra, notes))
            return
        view = watch_view(state, extra)
        word = view["word"] + (STOPPING if snap["phase"] == "stopping" else "")
        live = self.live.get("project")   # REDO A-2: the level of the code it would end with now
        self._verdict(word, live[1] if live else view["level"], view["detail"], result=True,
                      suppressed=ui.suppressed(state), counts=live[2:] if live else None)   # REDO C-3
        self._badges(self.badges, "badges", view["badges"])                                                 # REDO C-2
        self.url.set(view["url"])
        self._put(self.body_title, text="Findings (%d)" % project_count(state))   # REDO B-6: one count
        self._put(self.body, font="TkTextFont")
        self._items(self.body, "body", finding_items(state.get("findings")),
                    "None yet: a finding of this watch is listed here as it lands.")
        cut = self.cut_badges.get("badges", ())   # REDO C-4: a cut badge's whole text
        self._seen(seen_lines(view["holes"] + [t for lv, t in cut if lv != "note" and t not in view["holes"]],
                              notes + [t for lv, t in cut if lv == "note"]))

    def _tick_host(self, view, own, notes):
        """E1/E2: the host screen from the controller's host view."""
        state = self.live_states.get("host") if self.c.host is not None else None   # REDO B-6: the tick's state
        suppressed = report_result(view.get("final"))[1] if view.get("final") else ui.suppressed(state or {})
        live = self.live.get("host")      # REDO A-2: the level of the code it would end with now
        detail = view["detail"]
        if live and live[1] != "clean" and detail.endswith(" " + NOT_CLEARANCE):   # said only where it is green
            detail = detail[:-len(" " + NOT_CLEARANCE)]
        self._verdict(view["word"], live[1] if live else view["level"], detail, result=True,
                      suppressed=suppressed, counts=live[2:] if live else None)   # REDO C-3
        self._badges(self.host_badges, "host_badges", view.get("badges") or [])                           # REDO C-2
        self.host_url.set(view.get("url") or "-")
        self.strip_state = state
        self._draw_strip()
        self._fill_host(view)
        self._host_layout(bool(view.get("final")))
        if view.get("final"):
            self._put(self.findings_title, text="Final report")
            self._put(self.host_text, font="TkFixedFont")
            self._set(self.host_text, "host", None, text_tags(view["final"]))
        else:
            watched = self.c.host is not None and state is not None
            items = host_finding_items(state if watched else None, view)
            found, sus = self.counts["host"] if watched else (0, 0)   # REDO B-6: the verdict's and the rail's
            self._put(self.findings_title, text="Findings (%d)%s" % (found, ", %d suspicion%s" % (
                sus, "" if sus == 1 else "s") if sus else ""))
            self._put(self.host_text, font="TkTextFont")
            self._items(self.host_text, "host", items, "None yet: a finding of this watch is listed here as it"
                        " lands." if watched else "None: the round at open is one look and judges nothing; the rules"
                        " judge the rounds of \"Watch this host\".")
        holes = view["holes"] + [h for h in own if h not in view["holes"]]
        if view.get("final"):   # REDO B-7, C-4: a finished watch's holes, from its final state (read once, at end)
            final = getattr(self.c.host, "final_state", None) if self.c.host is not None else None
            holes += [x for x in (hole_line(h) for h in (final if final is not None else state or {}).get("holes")
                                  or [] if isinstance(h, dict)) if x not in holes]
        holes += [t for lv, t in self.cut_badges.get("host_badges", ()) if lv != "note" and t not in holes]
        self._seen(seen_lines(holes, notes))
        word = "Stop host watch" if self.c.host_watching() else "Watch this host"
        if self.host_button.cget("text") != word:
            self.host_button.configure(text=word)

    def _host_layout(self, final):
        """While a host watch's final report is shown it takes the screen's
        cards (its trees and findings are in it); else trees above, findings
        and the selected tree below."""
        if self.shown.get("host_layout") == final:
            return
        self.shown["host_layout"] = final
        gap = self.px(THEME["px"]["gap"])
        if final:
            self.trees_card.grid_remove()
            self.detail_card.grid_remove()
            self.findings_card.grid(row=1, column=0, rowspan=2, columnspan=2, sticky="nsew", pady=0, padx=0)
        else:
            self.trees_card.grid()
            self.detail_card.grid()
            self.findings_card.grid(row=2, column=0, rowspan=1, columnspan=1, sticky="nsew", pady=(gap, 0),
                                    padx=(0, gap // 2))

    def _draw_strip(self):
        """E3: the round strip on its Canvas, as many cells as fit; its words on their own line under it."""
        canvas, p, X = self.strip, self.palette, THEME["px"]
        cell, gap = self.px(X["cell"]), self.px(X["cell_gap"])
        state = getattr(self, "strip_state", None)
        width = self.strip.winfo_width()
        width = width if width > 1 else self._width()
        total, progress, suspected = strip_total(state), strip_progress(state), strip_suspected(state)
        tail = "" if state or self.c.host_watching() else ": the host is not watched"
        fit = 50
        while True:   # as many cells as fit after the words have their full width
            cells = strip_cells(state, fit)
            text = strip_text(cells, total, progress, suspected) + tail
            if fit <= 8 or fit * (cell + gap) <= width:   # REDO B-1: the words have their own line
                break
            fit -= 1
        key = (cells, text, cell)
        if self.shown.get("strip") == key:
            return
        self.shown["strip"] = key
        canvas.delete("all")
        one = self.px(1)
        lv = p["levels"]
        for i, (_, kind, _) in enumerate(cells):
            x = one + i * (cell + gap)
            if kind == "clean":
                canvas.create_rectangle(x, one, x + cell, one + cell, fill=lv["clean"], outline=lv["clean"])
            elif kind == "finding":
                canvas.create_rectangle(x, one, x + cell, one + cell, fill=lv["alarm"], outline=lv["alarm"])
            elif kind == "unread":
                canvas.create_rectangle(x + one, 2 * one, x + cell - one, cell, outline=lv["incomplete"],
                                        width=2 * one)
            else:
                canvas.create_rectangle(x, one, x + cell - one, cell, outline=p["line" if state is None else
                                                                               "field_line"], width=one)
        self.strip_label.configure(text=text)

    def _tick_log(self):
        """A-5, F-6: the chosen watch's own lines, at any time (bounded); the newest kept in view."""
        session = self.c.host if self.log_source == "host" else self.c.session
        log = getattr(session, "log", None)
        which = "host watch" if self.log_source == "host" else "project watch"
        if log is None:
            self._verdict("NO LOG", "note", "the %s has not started: no log yet" % which)
            self._set(self.log_text, "log", "The %s has not started: no log yet.\n" % which)
            return
        text = log_view(log.text())
        self._verdict("LOG", "note", "the %s's lines, %d characters; the newest at the end" % (which, len(text)))
        self._set(self.log_text, "log", text, follow=True)

    def _tick_doctor(self):
        """The doctor's result, when it comes: the project screen's rows and
        header, and the host screen's "Checks" (its title in the level's
        colour; it opens only on a click, REDO A-7)."""
        job = self.doctor
        result = job.result() if job is not None else None
        if result is None:
            return False
        project, lines, summary = result
        self.checks_lines = lines
        self._check_rows(self.doctor_rows, "doctor", lines)
        self._check_rows(self.checks_rows, "checks", lines)
        label, level = checks_state(lines)
        self.checks.set_title(label, "%s.Disclosure.TCheckbutton" % level if level else "Disclosure.TCheckbutton")
        self.doctor_band = ("DOCTOR: %s" % summary.split(": ", 1)[-1], level or "clean",   # REDO A-12: one level
                            "project %s; Start installs the hooks and watches it, as `raqib watch` does"
                            % _safe(project))
        self.doctor = None
        return True


# --- the command ------------------------------------------------------------------------

def run(project, options, out=None, tk=None, err=None):
    """raqib app: open the window, run until it closes; the exit code of
    the last watch's final report (0 when none ran)."""
    err = err or sys.stderr
    environ = os.environ if options.environ is None else options.environ
    if tk is None:
        tk, why = probe_tk()
        if tk is None:
            raise AppError(why)
    problem = display_problem(environ)
    if problem:
        raise AppError("raqib app: %s; `raqib watch` works without a window" % problem)
    dpi = declare_dpi_awareness()   # M8.1 E6: before Tk starts (Windows; this process only)
    try:
        root = tk.Tk()
    except Exception as exc:   # tkinter.TclError: no display it can use
        raise AppError("raqib app: no window could be opened (%s: %s); `raqib watch` works without one"
                       % (type(exc).__name__, _safe(exc)))
    controller = Controller(options, tee=out)
    if dpi:   # E6: a failure is a line in the log (app.log under raqib-app); the window opens as before
        controller.log_line(dpi)
    project = os.path.abspath(project or ".")
    try:
        controller.start_tray()
        window = Window(tk, root, controller, project, environ=options.environ, home=options.home)
        root.mainloop()
        if not window.closed:
            window.destroy()
    finally:
        # REDO A-16: the window's Tk objects (its images, its variables) are let go and finalised here, on the
        # main thread, before the workers are waited for: none is left for another thread's garbage collection
        window = root = None
        gc.collect()
        controller.shutdown()
        controller.finish_wait(err=err)   # A-3: never exit with a watch that has not concluded
    controller.report_finished()   # F-8: every watch's report, appended once
    return controller.exit_code()


class AppLog:
    """A-4: ~/.raqib/app.log, the gui-script's stdout: truncated at start,
    bounded at `limit` bytes (one line then says the rest is not written).
    A write that fails is kept in error, never raised into the watch."""

    def __init__(self, path, limit=APP_LOG_MAX):
        self.path = path
        self.limit = limit
        self.lock = threading.Lock()
        self.size = 0
        self.full = False
        self.error = None
        self.file = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.file = open(path, "w", encoding="utf-8", errors="backslashreplace", newline="\n")
        except OSError as exc:
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def write(self, text):
        text = str(text)
        with self.lock:
            if self.file is None or self.full:
                return len(text)
            data = text.encode("utf-8", "backslashreplace")
            try:
                if self.size + len(data) > self.limit:
                    self.full = True
                    self.file.write("\n[raqib app: app.log reached %d bytes; the rest is not written]\n" % self.limit)
                else:
                    self.file.write(text)
                    self.size += len(data)
                self.file.flush()
            except (OSError, ValueError) as exc:
                self.error = "%s: %s" % (type(exc).__name__, exc)
                self.file = None
        return len(text)

    def flush(self):
        pass

    def close(self):
        with self.lock:
            if self.file is not None:
                try:
                    self.file.close()
                except OSError:
                    pass
                self.file = None


class Tail:
    """A bounded stderr (A-4): the last `limit` characters, and a copy to
    another stream (app.log)."""

    def __init__(self, copy_to=None, limit=ERR_MAX):
        self.copy_to = copy_to
        self.limit = limit
        self.text = ""

    def write(self, text):
        text = str(text)
        self.text = (self.text + text)[-self.limit:]
        if self.copy_to is not None:
            self.copy_to.write(text)
        return len(text)

    def flush(self):
        pass


def app_log_path(home=None):
    return os.path.join(home or os.path.expanduser("~"), ".raqib", APP_LOG)


def tell(text, platform=None, box=None, stream=None):
    """A-4: a failure before the window is up, said where the person sees
    it: one message box on Windows (tray.message_box), stderr elsewhere (and
    when the box cannot be shown). Never raises."""
    platform = platform or sys.platform
    if platform == "win32":
        why = (box or traymod.message_box)(text, TITLE + ": the window did not open")
        if why is None:
            return "box"
        text = "%s\n(the message box could not be shown: %s)" % (text, why)
    stream = stream if stream is not None else sys.__stderr__
    try:
        if stream is not None:
            stream.write(text.rstrip("\n") + "\n")
            stream.flush()
            return "stderr"
    except Exception:
        pass
    return None


def gui_main(argv=None, home=None, platform=None, box=None, stream=None):
    """The `raqib-app` gui-script (A-4). On Windows pythonw runs it with no
    console. The watch's lines and the final report go to ~/.raqib/app.log
    (truncated at start, bounded); stderr is kept, bounded, and copied
    there. When it ends with exit 2 (the window could not open, e.g. no
    tkinter) or an exception before the window was up, the sentence is one
    message box on Windows and a line on stderr elsewhere."""
    argv = sys.argv[1:] if argv is None else list(argv)
    path = app_log_path(home)
    log = AppLog(path)
    tail = Tail(copy_to=log)
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = log, tail
    try:
        from raqib import cli   # cli imports this module: imported here, not at the top
        try:
            code = cli.main(["app"] + argv, out=log)
        except BaseException as exc:   # a startup exception: said, never a silent pythonw exit
            if isinstance(exc, KeyboardInterrupt):
                raise
            log.write(traceback.format_exc())
            tail.text += "raqib: the window failed before it opened: %s: %s\n" % (type(exc).__name__, _safe(exc))
            code = 2
    finally:
        sys.stdout, sys.stderr = saved
        log.close()
    if code == 2 and tail.text.strip():
        where = ("(this and the log are in %s)" % path) if log.error is None else (
            "(app.log could not be written: %s)" % log.error)
        tell("%s\n%s" % (tail.text.strip(), where), platform=platform, box=box, stream=stream)
    return code
