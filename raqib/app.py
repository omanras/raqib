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
  lines fold under "Checks" (open when any is MISSING). "Watch this host"
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

The look (M7.6b, ADR-0008 decision 6) is presentation only: one THEME table
(colours by the exit-code scheme, light and dark - dark when Windows says so
in AppsUseLightTheme, read-only - fonts, paddings, ttk style names), a word
beside every colour, the tree and rules tables as sortable ttk.Treeviews
with the selected tree's detail below, one header bar (Host | Project |
Rules | Log, the running watches, "N rules off", Open page), three
first-run lines until ~/.raqib/host/look.json exists, the doctrine under
the band, and every screen within 900x600.
"""
from __future__ import annotations

import copy
import importlib
import os
import queue
import sys
import threading
import time
import traceback

from raqib import host as hostmod, notify, overlay, tray as traymod, ui, watch

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

# --- the look (M7.6b, ADR-0008 decision 6) ------------------------------------------------------------
# THEME is the only place a colour lives in this file (a test reads the AST): the exit-code scheme of
# ADR-0007 F-7 / C-10 (0 green, 1 red, 3 amber), notes grey, holes amber, the suppressed badge red
# (ADR-0008 A-2); a band background per level; the font families tried in order (named system fonts,
# nothing shipped); the paddings; the ttk style names. Every level is shown with a word beside it.
THEME = {
    "light": {
        "bg": "#f6f6f4", "surface": "#ffffff", "fg": "#1f2328", "muted": "#5c6370", "border": "#c9ced6",
        "select_bg": "#dbe7f6", "select_fg": "#1f2328", "tab_bg": "#e9eaec", "tab_current": "#ffffff",
        "levels": {"clean": "#1b6e35", "alarm": "#b00020", "incomplete": "#9a5000", "note": "#5c6066",
                   "hole": "#9a5000", "suppressed": "#b00020"},
        "band_bg": {"clean": "#e6f3e9", "alarm": "#fbe8ea", "incomplete": "#fdf1e2", "note": "#eeeff1"},
    },
    "dark": {
        "bg": "#1e1f22", "surface": "#26282c", "fg": "#e4e5e7", "muted": "#a0a5ad", "border": "#41454c",
        "select_bg": "#1c2e45", "select_fg": "#ffffff", "tab_bg": "#2b2d31", "tab_current": "#3a3d43",
        "levels": {"clean": "#63c784", "alarm": "#ff6b7a", "incomplete": "#efa654", "note": "#a0a5ad",
                   "hole": "#efa654", "suppressed": "#ff6b7a"},
        "band_bg": {"clean": "#17321f", "alarm": "#3e1a1f", "incomplete": "#3a2a15", "note": "#2c2e32"},
    },
    "fonts": {
        "ui": ("Segoe UI", "Cantarell", "Noto Sans", "DejaVu Sans", "Liberation Sans", "Helvetica", "Arial"),
        "mono": ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Liberation Mono", "Noto Sans Mono",
                 "Courier New", "Courier"),
        "size": 10, "small": 9, "band": 15, "mono_size": 10,
    },
    "pad": {"outer": 12, "gap": 6, "row": 4, "band_x": 10, "band_y": 6},
    "styles": {"tab": "Tab.TButton", "tab_current": "Current.Tab.TButton", "muted": "Muted.TLabel",
               "level": "%s.Level.TLabel"},
    "min_size": (900, 600), "size": (960, 660),
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


def chip_text(level, suppressed=0, result=False):
    """E1, REDO C-3: the word beside the band's colour: "[level]"; in a
    watch's green state (result=True) it says "Not a clearance." and, when
    the overlay suppressed findings, how many: "[clean] (N findings
    suppressed by the overlay). Not a clearance." (A3, ADR-0008 A-2)."""
    word = "[%s]" % level_word(level)
    if result and level_of(level) == "clean":
        return "%s%s. %s" % (word, " (%d findings suppressed by the overlay)" % suppressed if suppressed else "",
                             NOT_CLEARANCE)
    return word


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


BADGE_LINE = 130   # characters of badges on one line of the badge rows (E5: within 900 px)


def badge_items(badges):
    """REDO C-2: the (level, text) badges of ui.band_items / host_band, each
    with its own level (through level_of) and its word; the overlay's
    badge is "suppressed" (red) while it counts suppressed findings."""
    out = []
    for level, text in badges:
        level = level_of(level)
        if level == "alarm" and "suppressed by the overlay" in str(text):
            level = "suppressed"
        out.append(("%s [%s]" % (_safe(text), level_word(level)), level))
    return out


def badge_rows(badges, width=BADGE_LINE):
    """REDO C-2: the badge items laid in rows of at most `width` characters
    (a badge longer than that has a row of its own)."""
    rows, line, used = [], [], 0
    for text, level in badge_items(badges):
        if line and used + 3 + len(text) > width:
            rows.append(line)
            line, used = [], 0
        line.append((text, level))
        used += len(text) + (3 if used else 0)
    return rows + ([line] if line else [])


def contrast_ratio(a, b):
    """REDO C-6: the WCAG 2 contrast ratio of two #rrggbb colours."""
    def lum(colour):
        c = colour.lstrip("#")
        rgb = [int(c[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
        lin = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in rgb]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def level_colour(code, mode="light"):
    """E1: the colour of a level (or of an exit code) in the theme of mode."""
    return THEME[mode if mode in ("light", "dark") else "light"]["levels"][level_of(code)]


def band_colours(code, mode="light"):
    """(foreground, background) of the band for a level or an exit code."""
    palette = THEME[mode if mode in ("light", "dark") else "light"]
    level = level_of(code)
    return palette["levels"][level], palette["band_bg"].get(level, palette["band_bg"]["note"])


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


def look_path(home=None):
    """~/.raqib/host/look.json: the first look writes it (ADR-0007 F-10)."""
    return os.path.join(hostmod.host_dir(home), "look.json")


def first_run_lines(home=None, exists=None):
    """E4: the three first-run lines while no look has been written yet
    (no ~/.raqib/host/look.json), else none: the first look writes it."""
    return [] if (exists or os.path.exists)(look_path(home)) else list(FIRST_RUN)


# The host screen's tree table (E2): (column id, heading, width px, index in a host_rows row, sort kind).
# Eight columns; "acts" (row index 4) is in the detail pane.
TREE_COLUMNS = (("image", "image", 120, 0, "text"), ("pid", "pid", 55, 1, "number"),
                ("kind", "kind", 120, 2, "text"), ("source", "source", 90, 5, "text"),
                ("findings", "findings", 90, 6, "severity"), ("rhythm", "rhythm / suspicion", 130, 7, "text"),
                ("first", "first seen", 115, 3, "text"), ("endpoints", "endpoints", 85, 8, "text"))
# The Rules table (E3): the overlay state per row.
RULES_COLUMNS = (("id", "rule", 140, 0, "text"), ("kind", "kind", 65, 1, "text"), ("class", "class", 75, 2, "text"),
                 ("severity", "severity", 65, 3, "severity"), ("budget", "budget", 50, 4, "number"),
                 ("status", "status", 50, 5, "text"), ("overlay", "overlay", 120, 6, "text"),
                 ("origin", "origin", 55, 7, "text"), ("thresholds", "thresholds", 160, 8, "text"))
SEVERITY_RANK = ("high", "medium", "low", "history", "pending at exit", "pending")


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


def tree_values(row):
    """The Treeview's values of one host_rows row, in TREE_COLUMNS order."""
    return tuple(row[c[3]] if c[3] < len(row) else "" for c in TREE_COLUMNS)


def row_level(row):
    """E1: the level of a tree's row: alarm when it knocked (new) or its
    source has findings, note when it is gone, else None (the default
    colour); the kind and findings columns say it in words."""
    kind = str(row[2]) if len(row) > 2 else ""
    flags = [f.strip(" )") for f in kind.split("(", 1)[1].split(",")] if "(" in kind else []
    findings = str(row[6]) if len(row) > 6 else "none"
    if "new" in flags or any(w in findings for w in ("high", "medium", "low")):
        return "alarm"
    if "gone" in flags:
        return "note"
    return None


def rules_rows(rows):
    """E3: the Rules table: [(values in RULES_COLUMNS order, level)], with
    the overlay state of each rule in words: "off by the overlay", "off in
    its YAML", "thresholds set" (a value the overlay changed), or "-". An
    off rule is amber (incomplete), as in the band."""
    out = []
    for r in rows:
        changed = [t for t in r.get("thresholds") or () if t.get("value") != t.get("yaml")]
        if r.get("status") == "off":
            state = "off in its YAML" if r.get("off_by") == "yaml" else "off by the overlay"
        else:
            state = "thresholds set" if changed else "-"
        values = (r.get("id"), r.get("kind"), r.get("class"), r.get("severity"), "%g" % (r.get("budget") or 0),
                  r.get("status"), state, r.get("origin"),
                  ", ".join(overlay.threshold_text(t) for t in r.get("thresholds") or ()) or "-")
        out.append((tuple(_safe(v) for v in values), "incomplete" if r.get("status") == "off" else None))
    return out


def header_rules(text, states=()):
    """E3: the header's rules item: (text, level). Red (suppressed) while a
    running watch's off rules would have fired (ADR-0008 A-2), with the
    count; amber when a rule is off; muted when none is."""
    n = sum(ui.suppressed(s) for s in states if isinstance(s, dict))
    if n:
        return "%s; %d finding(s) suppressed by the overlay" % (text, n), "suppressed"
    return text, ("incomplete" if text not in ("no rule off",) else None)


FOOT_LINES = 3   # REDO C-5: the footer shows three lines and scrolls; "(N more)" counts the rest


def foot_lines(holes, notes, look=()):
    """E5, REDO C-5 (F-3): the footer's lines, every one: the window's own
    holes, each of the first look's holes (they stand until the host
    watch's first round), the notes. The footer shows FOOT_LINES of them
    and scrolls (foot_more)."""
    return ["hole: %s" % h for h in list(holes) + list(look)] + ["note: %s" % n for n in notes]


def foot_more(lines, cap=FOOT_LINES):
    """REDO C-5: "(N more)" when the footer holds more lines than it shows, else ""."""
    return "(%d more)" % (len(lines) - cap) if len(lines) > cap else ""


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
            if name == "FINDINGS":
                level = "alarm" if count else None
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


def body_text(view):
    """The watching screen's text: findings by severity, then holes."""
    out = []
    count = sum(len(lines) for _, lines in view["findings"])
    out.append("FINDINGS: %d" % count)
    for sev, lines in view["findings"]:
        out.append("  %s (%d)" % (sev, len(lines)))
        out += ["    %s" % line for line in lines]
    out.append("")
    out.append("HOLES (A3): %d" % len(view["holes"]))
    out += ["  - %s" % h for h in view["holes"]]
    return "\n".join(out) + "\n"


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
                with self.lock:   # A-8: the final report is kept before close() runs
                    self.final_text, self.final_exit = text, code
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

HOST_COLUMNS = (("image", 22), ("pid", 8), ("named", 22), ("first seen", 25), ("acts", 5), ("source", 24),
                ("findings", 20), ("rhythm / suspicion", 24),   # M7.4 E4
                ("endpoints", 0))   # M7.2b E4: the source column and its findings by severity
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
    if tree.get("present") is False:
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
                     _safe(ui.tree_rhythm_text(t)),   # M7.4 E4
                     _safe(", ".join(str(e) for e in t.get("endpoints") or ()) or "-")))
    return rows


def _of_tree(item, tree):
    """Whether a host finding, suspicion or dark note is of this tree (its
    tree key, its tree word, or its live tree)."""
    key = tree.get("key")
    word = hostmod.tree_word(tuple(key)) if isinstance(key, (list, tuple)) and len(key) == 3 else None
    if item.get("tree_key") is not None:
        return list(item.get("tree_key")) == list(key or ())
    return word is not None and word in (item.get("tree"), item.get("live_tree"))


def tree_details(trees, findings=(), suspicions=(), notes=()):
    """E2: what the detail pane says of each tree, aligned with host_rows:
    its acts, class, source, cites (where: src:line, never the record's
    text), its findings and suspicions as the finding lines say them, and
    its notes. Nothing here is not already in the host state."""
    out = []
    for t in trees:
        if not isinstance(t, dict):
            continue
        out.append({
            "acts": _safe(t.get("acts", 0)), "class": _safe(t.get("class") or "-"),
            "started": _safe(t.get("started") or "-"),
            "cites": [_safe("%s:%s" % (c.get("src"), c.get("line")))
                      for c in t.get("cites") or () if isinstance(c, dict)],
            "findings": [host_finding_line(f) for f in findings if isinstance(f, dict) and _of_tree(f, t)]
            + [suspicion_line(f) for f in suspicions if isinstance(f, dict) and _of_tree(f, t)],
            "notes": [_safe(d.get("text")) for d in notes if isinstance(d, dict) and _of_tree(d, t)]})
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
           "cites: %s" % (", ".join(detail.get("cites") or ()) or "-"), "",
           "FINDINGS: %d" % len(detail.get("findings") or ())]
    out += ["  - %s" % f for f in detail.get("findings") or ()]
    out += ["", "NOTES (not alarms): %d" % len(detail.get("notes") or ())]
    out += ["  - %s" % n for n in detail.get("notes") or ()]
    return "\n".join(out) + "\n"


def host_text_body(view):
    """The host screen's text under the tree table: host_body without the
    table (the rows are in the Treeview, E2), or the final report."""
    return host_body(dict(view, rows=[])).lstrip("\n")


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


def host_table(rows):
    """The tree table as fixed-width text lines (a header, then the rows)."""
    def fmt(cells):
        out = []
        for (name, width), cell in zip(HOST_COLUMNS, cells):
            cell = str(cell)
            if width and len(cell) >= width:
                cell = cell[:width - 2] + ".."
            out.append(cell.ljust(width) if width else cell)
        return " ".join(out).rstrip()
    return [fmt([name for name, _ in HOST_COLUMNS])] + [fmt(r) for r in rows]


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
    findings = [host_finding_line(f) for f in h.get("findings") or [] if isinstance(f, dict)]
    findings += [suspicion_line(f) for f in h.get("suspicions") or [] if isinstance(f, dict)]   # M7.4 E4
    # M7.5 E1/E4: notes apart from the findings (a note is never an alarm)
    notes = [_safe(d.get("text")) for d in h.get("dark_notes") or [] if isinstance(d, dict)]
    return {"word": word, "level": level, "detail": _safe(detail), "rows": host_rows(trees),
            "details": tree_details(trees, h.get("findings") or (), h.get("suspicions") or (),
                                    h.get("dark_notes") or ()),   # M7.6b E2: the detail pane
            "lines": lines, "findings": findings, "notes": notes, "holes": holes,
            "badges": [(lv, _safe(text)) for lv, text in ui.host_band(state)], "final": None,
            "trees": h.get("now") or 0, "new": h.get("new") or 0, "url": state.get("url") or "-",
            "suspicions": len([f for f in h.get("suspicions") or [] if isinstance(f, dict)])}   # REDO C-4: apart


def host_body(view):
    """The host screen's text: the table (or the empty line), the findings,
    the holes; or the final report when the host watch ended."""
    if view.get("final"):
        return view["final"] + "".join("hole: %s\n" % x for x in view["holes"])
    out = host_table(view["rows"]) if view["rows"] else []
    out += view["lines"]
    out += ["", "FINDINGS: %d" % len(view["findings"])] + ["  %s" % f for f in view["findings"]]
    if view.get("notes"):   # M7.5 E4: apart from the findings; never an alarm
        out += ["", "NOTES (not alarms): %d" % len(view["notes"])] + ["  - %s" % x for x in view["notes"]]
    out += ["", "HOLES (A3): %d" % len(view["holes"])] + ["  - %s" % x for x in view["holes"]]
    return "\n".join(out) + "\n"


def checks_state(lines):
    """("Checks: ..." button text, open?): the doctor lines fold under a
    toggle, open when any is MISSING (E1)."""
    if lines is None:
        return "Checks: running...", False
    missing = sum(1 for word, _, _ in lines if word == "MISSING")
    unsure = sum(1 for word, _, _ in lines if word == "UNSURE")
    if missing:
        return "Checks: %d MISSING" % missing, True
    return "Checks: %s" % ("%d UNSURE" % unsure if unsure else "all OK"), False


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

    def __init__(self, home=None, catalog=None):
        self.home = home
        self.catalog = catalog
        self.rows, self.info, self.error = [], None, None
        self.message, self.level = None, "clean"
        self.reload()

    def reload(self):
        try:
            rules = overlay.load(self.home, self.catalog)
            self.rows, self.info, self.error = overlay.listing(rules), overlay.describe(rules), None
        except Exception as exc:   # A3: a catalog that cannot be loaded is said, never a crash
            self.rows, self.info = [], None
            self.error = "the rules could not be loaded: %s: %s" % (type(exc).__name__, _safe(exc))
        return self

    def _do(self, change, *args, running=False):
        try:
            said = change(*args, home=self.home, catalog=self.catalog)
            self.message, self.level = said + (
                "; a watch is running: it keeps the rules it started with" if running else ""), "clean"
        except overlay.OverlayError as exc:
            self.message, self.level = "REFUSED: %s" % exc, "alarm"
        self.reload()
        return self.message

    def set(self, rule_id, on, running=False):
        return self._do(overlay.set_status, str(rule_id or "").strip(), "on" if on else "off", running=running)

    def threshold(self, rule_id, field, value, running=False):
        """M7.6c (ADR-0008 Amendment B): the change and its measurement's
        result: "threshold ok (measured): ..." with what was measured, or
        "REFUSED: threshold refused: <why>" (the fixture named)."""
        self._do(overlay.set_threshold, str(rule_id or "").strip(), str(field or "").strip(), str(value or ""),
                 running=running)
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

    def running_text(self):
        """F-2: the header's line: which watches run now."""
        names = (["host watch"] if self.host_watching() else []) + (
            ["project watch of %s" % _safe(self.session.project)] if self.project_watching() else [])
        return "running: %s" % (", ".join(names) if names else "none")

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
    """The Log pane's text: the last `limit` characters of the watch's
    lines (bounded, A-5), with a line saying how much is not shown."""
    limit = LOG_VIEW_MAX if limit is None else limit
    if len(text) <= limit:
        return text
    return "[%d earlier characters not shown here]\n%s" % (len(text) - limit, text[-limit:])


class Window:
    """The Tk window over a Controller. Only this class calls Tk. M7.6b:
    its look comes from THEME (ttk.Style configured once in _style); the
    tree tables are ttk.Treeviews; nothing it shows is computed here."""

    def __init__(self, tk, root, controller, project, environ=None, home=None, doctor_job=None, probe=None,
                 rules_panel=None):
        self.tk = tk
        from tkinter import ttk   # M7.6b: the themed widgets (stdlib)
        self.ttk = ttk
        self.rules_panel = rules_panel or RulesPanel(home=home)   # M7.6: the Rules screen's logic
        self.root = root
        self.c = controller
        self.environ = environ
        self.home = home
        self.make_doctor = doctor_job or (lambda p: DoctorJob(p, environ=environ, home=home))
        self.doctor = None
        self.screen = None
        self.shown = {}
        self.after_id = None
        self.closed = False
        self.mode = os_mode()                  # E1: dark or light as the OS says, else light
        self.palette = THEME[self.mode]
        root.title(TITLE)
        root.geometry("%dx%d" % THEME["size"])
        root.minsize(*THEME["min_size"])       # E5: every screen fits 900x600
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.report_callback_exception = controller.callback_error   # A-4: a hole and a log line
        self.log_open = False
        self.host_log_open = False
        self.checks_open = False
        self.doctor_band = None
        self.refusal = None
        self.sorting = {"host": (None, False), "rules": (None, False)}   # E2: (column, descending) per table
        self.payload = {"host": {}, "rules": {}}   # iid -> what a selected row shows
        self.first_run_shown = False
        self._style()
        self._build(project)
        self.show_host()                  # M7.3: the first screen is the host
        controller.start_probe(probe)     # E1: one discover round at open, in a thread
        self.check()
        self.after_id = root.after(TICK_MS, self.tick)

    # the look
    def _style(self):
        """E1: fonts and ttk styles from THEME, once. A named system font
        that is not installed falls back to the next, then to Tk's own."""
        from tkinter import font as tkfont
        fonts, pad, p = THEME["fonts"], THEME["pad"], self.palette
        families = tkfont.families(self.root)
        ui, mono = pick_font(fonts["ui"], families), pick_font(fonts["mono"], families)
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            named = tkfont.nametofont(name)
            named.configure(size=fonts["size"], **({"family": ui} if ui else {}))
        tkfont.nametofont("TkFixedFont").configure(size=fonts["mono_size"], **({"family": mono} if mono else {}))
        base = tkfont.nametofont("TkDefaultFont").actual("family")
        self.band_font = tkfont.Font(root=self.root, family=base, size=fonts["band"], weight="bold")
        self.small_font = tkfont.Font(root=self.root, family=base, size=fonts["small"])
        self.bold_font = tkfont.Font(root=self.root, family=base, size=fonts["size"], weight="bold")
        style = self.ttk.Style(self.root)
        names = style.theme_names()
        if self.mode == "light" and sys.platform == "win32" and "vista" in names:
            style.theme_use("vista")      # the native look; its buttons keep the OS colours
        elif "clam" in names:
            style.theme_use("clam")       # takes every colour of the theme (dark mode, Linux)
        s = THEME["styles"]
        style.configure(".", background=p["bg"], foreground=p["fg"], fieldbackground=p["surface"],
                        bordercolor=p["border"], lightcolor=p["bg"], darkcolor=p["border"],
                        troughcolor=p["tab_bg"], selectbackground=p["select_bg"], selectforeground=p["select_fg"],
                        insertcolor=p["fg"])
        style.configure("TFrame", background=p["bg"])
        style.configure("TLabel", background=p["bg"], foreground=p["fg"])
        style.configure("TCheckbutton", background=p["bg"], foreground=p["fg"])
        style.map("TCheckbutton", background=[("active", p["bg"])])
        style.configure("TButton", padding=(8, 2), width=-6, background=p["tab_bg"], foreground=p["fg"])
        style.map("TButton", background=[("active", p["tab_current"])])
        style.configure("TEntry", fieldbackground=p["surface"], foreground=p["fg"])
        style.configure(s["muted"], foreground=p["muted"])
        style.configure(s["tab"], padding=(10, 3), width=-5)
        style.configure(s["tab_current"], padding=(10, 3), width=-5, background=p["tab_current"],
                        font=self.bold_font)
        for level, colour in p["levels"].items():
            style.configure(s["level"] % level, foreground=colour)
        rows = tkfont.nametofont("TkDefaultFont").metrics("linespace") + pad["row"] + 2
        style.configure("Treeview", background=p["surface"], fieldbackground=p["surface"], foreground=p["fg"],
                        rowheight=rows)
        style.map("Treeview", background=[("selected", p["select_bg"])], foreground=[("selected", p["select_fg"])])
        style.configure("Treeview.Heading", background=p["tab_bg"], foreground=p["fg"], font=self.bold_font)
        self.root.configure(background=p["bg"])

    def _wrap(self, label, start=860):
        """A label that wraps at the width it is given (never wider than the window)."""
        label.configure(wraplength=start)
        label.bind("<Configure>", lambda e, w=label: w.configure(wraplength=max(e.width - 4, 120)))
        return label

    def _text(self, parent, height, mono=False):
        p = self.palette
        frame = self.ttk.Frame(parent)
        text = self.tk.Text(frame, height=height, width=20, wrap="word", font="TkFixedFont" if mono else "TkTextFont",
                            background=p["surface"], foreground=p["fg"], insertbackground=p["fg"],
                            selectbackground=p["select_bg"], selectforeground=p["select_fg"],
                            highlightthickness=1, highlightbackground=p["border"], highlightcolor=p["border"],
                            relief="flat", borderwidth=0, padx=THEME["pad"]["gap"], pady=THEME["pad"]["row"])
        bar = self.ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=bar.set, state="disabled")
        bar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        for level, colour in p["levels"].items():
            text.tag_configure(level, foreground=colour)
        return frame, text

    def _table(self, parent, key, columns, height):
        """E2/E3: a Treeview with columns that sort when their heading is clicked."""
        frame = self.ttk.Frame(parent)
        tree = self.ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height,
                                 selectmode="browse")
        for cid, heading, width, _, _ in columns:
            tree.heading(cid, text=heading, anchor="w", command=lambda c=cid: self.sort_by(key, c))
            tree.column(cid, width=width, minwidth=40, stretch=True, anchor="w")
        for level, colour in self.palette["levels"].items():
            tree.tag_configure(level, foreground=colour)
        bar = self.ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        return frame, tree

    def _build(self, project):
        tk, ttk, p, pad = self.tk, self.ttk, self.palette, THEME["pad"]
        s = THEME["styles"]
        out = pad["outer"]
        # E3: the header, one bar: Host | Project | Rules | Log, the running watches, "N rules off", Open page.
        # F-2: "Host" and "Project" switch between the two screens at any time, watches running.
        head = ttk.Frame(self.root)
        self.host_tab = ttk.Button(head, text="Host", command=self.show_host, style=s["tab"])
        self.host_tab.pack(side="left")
        self.project_tab = ttk.Button(head, text="Project", command=self.show_project, style=s["tab"])
        self.project_tab.pack(side="left", padx=(2, 0))
        self.rules_tab = ttk.Button(head, text="Rules", command=self.show_rules, style=s["tab"])   # M7.6
        self.rules_tab.pack(side="left", padx=(2, 0))
        self.log_tab = ttk.Button(head, text="Log", command=self.toggle_screen_log, style=s["tab"])   # A-5, F-6
        self.log_tab.pack(side="left", padx=(2, pad["gap"]))
        # F-11 and A-13: Open page, the host watch's on the host screen, the project watch's on the project's
        self.host_page_button = ttk.Button(head, text="Open page", command=self.open_host_page)
        self.page_button = ttk.Button(head, text="Open page", command=self.open_page)
        notes = self.head_notes = ttk.Frame(head)
        self.running_note = self._wrap(ttk.Label(notes, text="", anchor="w", style=s["muted"]), 300)
        self.running_note.pack(fill="x")
        self.head_note = self._wrap(ttk.Label(notes, text="", anchor="w"), 300)   # M7.6: "N rules off"
        self.head_note.pack(fill="x")
        notes.pack(side="left", fill="x", expand=True)
        head.pack(fill="x", padx=out, pady=(pad["gap"], pad["row"]))
        # the band: the state word, its level in a word beside the colour (E1), the detail
        self.bandf = tk.Frame(self.root, background=p["band_bg"]["note"])
        top = tk.Frame(self.bandf, background=p["band_bg"]["note"])
        self.band = tk.Label(top, text="", anchor="w", font=self.band_font, background=p["band_bg"]["note"],
                             foreground=p["fg"])
        self.band.pack(side="left")
        self.band_level = tk.Label(top, text="", anchor="w", font=self.small_font, background=p["band_bg"]["note"],
                                   foreground=p["fg"])
        self.band_level.pack(side="left", padx=(pad["band_x"], 0))
        top.pack(fill="x", padx=pad["band_x"], pady=(pad["band_y"], 0))
        self.detail = self._wrap(tk.Label(self.bandf, text="", anchor="w", justify="left",
                                          background=p["band_bg"]["note"], foreground=p["fg"]), 860)
        self.detail.pack(fill="x", padx=pad["band_x"], pady=(0, pad["band_y"]))
        self.bandf.pack(fill="x", padx=out)
        # E4: the doctrine, under the band, always
        self.doctrine = ttk.Label(self.root, text=DOCTRINE, anchor="w", style=s["muted"])
        self.doctrine.pack(fill="x", padx=out, pady=(0, pad["row"]))
        # the window's own notes and holes, on every screen
        # REDO C-5: every line (F-3: each of the look's holes until round 1), three shown, the rest scrolled;
        # "(N more)" leads to the Host screen, where the look's holes are listed in full
        footf = ttk.Frame(self.root)
        self.foot_more = ttk.Button(footf, text="", command=self.show_host)
        self.foot_frame, self.foot = self._text(footf, FOOT_LINES)
        self.foot.configure(font=self.small_font)
        self.foot_frame.pack(side="left", fill="x", expand=True)
        footf.pack(side="bottom", fill="x", padx=out, pady=(0, pad["gap"]))
        # the host screen (M7.3): the first one
        self.hostf = ttk.Frame(self.root)
        # E4: the first-run lines, at the top of the first screen until the first look is written
        self.first_run_label = self._wrap(ttk.Label(self.hostf, text="", anchor="w", justify="left",
                                                    font=self.small_font), 860)
        row = ttk.Frame(self.hostf)
        self.host_button = ttk.Button(row, text="Watch this host", command=self.host_toggle)
        self.host_button.pack(side="left")
        ttk.Button(row, text="Watch a project", command=self.show_project).pack(side="left", padx=pad["gap"])
        self.checks_button = ttk.Button(row, text=checks_state(None)[0], command=self.toggle_checks)
        self.checks_button.pack(side="left")
        row.pack(fill="x", pady=(0, pad["row"]))
        self.host_row = row
        row = ttk.Frame(self.hostf)
        # M7.2b (ADR-0007 H-1): off by default; read when "Watch this host" starts a watch
        # options may be None (a Controller without Options, as the M6.4 Tk tests build it): off, as by default
        self.attach_var = tk.BooleanVar(value=bool(getattr(self.c.options, "attach_hooks", False)))
        self.attach_box = ttk.Checkbutton(row, text=ATTACH_TEXT, variable=self.attach_var)
        self.attach_box.pack(side="left")
        # M7.4 E3: "suspect unknown trees", empty (off) by default; read when "Watch this host" starts a watch
        ttk.Label(row, text=SUSPECT_TEXT).pack(side="left", padx=(pad["gap"] * 2, 0))
        self.suspect_var = tk.StringVar(value=str(getattr(self.c.options, "suspect", "") or ""))
        ttk.Entry(row, textvariable=self.suspect_var, width=16).pack(side="left", padx=(pad["row"], pad["gap"] * 2))
        ttk.Label(row, text="page").pack(side="left")
        self.host_url = tk.StringVar(value="-")
        ttk.Entry(row, textvariable=self.host_url, state="readonly", width=24).pack(side="left", fill="x", expand=True,
                                                                                  padx=(pad["row"], 0))
        row.pack(fill="x", pady=(0, pad["row"]))
        self.host_badges = ttk.Frame(self.hostf)   # REDO C-2: one label per badge
        self.host_badges.pack(fill="x", pady=(0, pad["row"]))
        self.checks_frame, self.checks_text = self._text(self.hostf, 2, mono=True)   # folded under "Checks"
        # E2: the tree table, then the screen's text (findings, notes, holes) beside the selected tree's detail
        self.host_paned = ttk.PanedWindow(self.hostf, orient="vertical")
        frame, self.host_tree = self._table(self.host_paned, "host", TREE_COLUMNS, 3)
        self.host_tree.bind("<<TreeviewSelect>>", lambda e: self._show_tree_detail())
        self.host_paned.add(frame, weight=3)
        lower = ttk.PanedWindow(self.host_paned, orient="horizontal")
        frame, self.host_text = self._text(lower, 2)
        lower.add(frame, weight=1)
        self.host_detail_frame, self.host_detail = self._text(lower, 2)
        lower.add(self.host_detail_frame, weight=1)
        self.host_lower = lower
        self.host_paned.add(lower, weight=2)
        self.host_paned.pack(fill="both", expand=True)
        self.host_log_frame, self.host_log_text = self._text(lower, 2, mono=True)   # F-6: in the detail's place
        self._set(self.host_detail, "host_detail", "the selected tree's findings and notes are shown here\n")
        # the project screen (M6.4's first screen)
        self.first = ttk.Frame(self.root)
        row = ttk.Frame(self.first)
        ttk.Label(row, text="Project").pack(side="left")
        self.project = tk.StringVar(value=project)
        ttk.Entry(row, textvariable=self.project).pack(side="left", fill="x", expand=True, padx=pad["gap"])
        ttk.Button(row, text="Browse...", command=self.browse).pack(side="left")
        ttk.Button(row, text="Check again", command=self.check).pack(side="left", padx=pad["gap"])
        self.start_button = ttk.Button(row, text="Start", command=self.start)
        self.start_button.pack(side="left")
        row.pack(fill="x", pady=(0, pad["gap"]))
        frame, self.doctor_text = self._text(self.first, 8, mono=True)
        frame.pack(fill="both", expand=True)
        # watching screen
        self.watching = ttk.Frame(self.root)
        row = ttk.Frame(self.watching)
        ttk.Label(row, text="Page (read-only)").pack(side="left")
        self.url = tk.StringVar(value="-")
        ttk.Entry(row, textvariable=self.url, state="readonly").pack(side="left", fill="x", expand=True,
                                                                     padx=pad["gap"])
        self.stop_button = ttk.Button(row, text="Stop", command=self.stop)
        self.stop_button.pack(side="left")
        self.back_button = ttk.Button(row, text="Back", command=self.show_first)
        row.pack(fill="x", pady=(0, pad["row"]))
        self.knock_label = ttk.Label(self.watching, text=first_line(None), anchor="w")   # A-5
        self.knock_label.pack(fill="x")
        self.badges = ttk.Frame(self.watching)     # REDO C-2: one label per badge
        self.badges.pack(fill="x", pady=(0, pad["row"]))
        # M7.6b follow-up: the body and the log share one vertical PanedWindow, as on the host screen, so
        # they shrink before the window does (900x600 on Windows: Tk 8.6, Segoe UI, Consolas)
        self.watch_paned = ttk.PanedWindow(self.watching, orient="vertical")
        frame, self.body = self._text(self.watch_paned, 5)
        self.watch_paned.add(frame, weight=3)
        self.watch_paned.pack(fill="both", expand=True)
        self.log_frame, self.log_text = self._text(self.watch_paned, 3, mono=True)   # A-5: the header's Log
        # M7.6 (ADR-0008): the Rules screen - the table, on / off, a threshold, Add, Reset; it writes the overlay only
        self.rulesf = ttk.Frame(self.root)
        row = ttk.Frame(self.rulesf)
        ttk.Label(row, text="Rule").pack(side="left")
        self.rule_id = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.rule_id, width=22).pack(side="left", padx=(pad["row"], pad["gap"]))
        ttk.Button(row, text="On", command=lambda: self.rules_set(True)).pack(side="left")
        ttk.Button(row, text="Off", command=lambda: self.rules_set(False)).pack(side="left", padx=(2, pad["gap"]))
        ttk.Button(row, text="Reset", command=self.rules_reset).pack(side="left", padx=(0, pad["gap"] * 2))
        ttk.Button(row, text="Add rule file...", command=self.rules_add).pack(side="left")
        row.pack(fill="x", pady=(0, pad["row"]))
        row = ttk.Frame(self.rulesf)
        ttk.Label(row, text="Threshold").pack(side="left")
        self.rule_field = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.rule_field, width=14).pack(side="left", padx=pad["row"])
        ttk.Label(row, text="=").pack(side="left")
        self.rule_value = tk.StringVar(value="")
        ttk.Entry(row, textvariable=self.rule_value, width=8).pack(side="left", padx=pad["row"])
        ttk.Button(row, text="Set", command=self.rules_threshold).pack(side="left", padx=(2, 0))
        row.pack(fill="x", pady=(0, pad["row"]))
        frame, self.rules_tree = self._table(self.rulesf, "rules", RULES_COLUMNS, 5)
        self.rules_tree.bind("<<TreeviewSelect>>", lambda e: self._on_rule_pick())
        frame.pack(fill="both", expand=True)
        frame, self.rules_text = self._text(self.rulesf, 3)
        frame.pack(fill="x", pady=(pad["gap"], 0))
        self._first_run()

    # screens
    def _show(self, name):
        if self.screen == name:
            return False
        frames = {"host": self.hostf, "first": self.first, "watching": self.watching, "rules": self.rulesf}
        for key, frame in frames.items():
            if key != name:
                frame.pack_forget()
        frames[name].pack(
            fill="both", expand=True, padx=THEME["pad"]["outer"])
        self.screen = name
        self._sync_header()
        return True

    def _sync_header(self):
        """E3: the current screen's tab in its own style, the Log tab's word
        for the current screen's log, its Open page."""
        s = THEME["styles"]
        current = {"host": self.host_tab, "first": self.project_tab, "watching": self.project_tab,
                   "rules": self.rules_tab}.get(self.screen)
        for tab in (self.host_tab, self.project_tab, self.rules_tab):
            tab.configure(style=s["tab_current"] if tab is current else s["tab"])
        has_log = self.screen in ("host", "watching")
        shown = self.host_log_open if self.screen == "host" else self.log_open
        self.log_tab.configure(text="Hide log" if has_log and shown else "Log",
                               state="normal" if has_log else "disabled")
        page = {"host": self.host_page_button, "first": self.page_button, "watching": self.page_button}.get(self.screen)
        for button in (self.host_page_button, self.page_button):
            if button is not page:
                button.pack_forget()
        if page is not None and not page.winfo_manager():
            page.pack(side="right", padx=(THEME["pad"]["gap"], 0), before=self.head_notes)

    def show_host(self):
        self._show("host")

    def show_first(self):
        """The project screen (M6.4's first screen, "Watch a project")."""
        if self._show("first"):
            self.shown.pop("body", None)
            if self.doctor_band is not None:
                self._band(*self.doctor_band)

    def show_watching(self):
        self._show("watching")

    def show_rules(self):
        """M7.6: the Rules screen, from the header at any time (watches running)."""
        if self._show("rules"):
            self.rules_panel.reload()
            self._band("RULES", "incomplete" if self.rules_panel.info and self.rules_panel.info.get("off") else "clean",
                       "%s; a change applies to the next watch" % self.rules_panel.header())

    def rules_set(self, on):
        self.rules_panel.set(self.rule_id.get(), on, running=self.c.watching())
        self._rules_band()

    def rules_reset(self):
        self.rules_panel.reset(self.rule_id.get(), running=self.c.watching())
        self._rules_band()

    def rules_threshold(self):
        self.rules_panel.threshold(self.rule_id.get(), self.rule_field.get(), self.rule_value.get(),
                                   running=self.c.watching())
        self._rules_band()

    def rules_add(self):
        from tkinter import filedialog
        chosen = filedialog.askopenfilename(parent=self.root, title="A rule file (.yaml) with its fixtures beside it",
                                            filetypes=[("Raqib rule", "*.yaml")])
        self.rules_panel.add(chosen or None, running=self.c.watching())
        self._rules_band()

    def _rules_band(self):
        p = self.rules_panel
        self._band("RULES" if p.level == "clean" else "RULES: REFUSED" if p.level == "alarm" else "RULES",
                   p.level, p.message or p.header())

    def _on_rule_pick(self):
        """E3: a row picked in the Rules table fills the Rule field (nothing is changed until a button is pressed)."""
        picked = self.rules_tree.selection()
        if picked and picked[0] in self.payload["rules"]:
            self.rule_id.set(self.payload["rules"][picked[0]])

    def show_project(self):
        """F-2: "Project" (and "Watch a project"): the running project watch's
        screen, else the project field."""
        if self.c.project_screen() == "watching":
            self.show_watching()
        else:
            self.show_first()

    def open_host_page(self):
        """F-11: the host watch's page, by the person's click (never under CI)."""
        self.c.page_note = self.c.open_page("host")

    def toggle_screen_log(self):
        """E3: the header's Log: the current screen's log pane (host or project watch)."""
        if self.screen == "host":
            self.toggle_host_log()
        elif self.screen == "watching":
            self.toggle_log()

    def toggle_host_log(self):
        """F-6: the host watch's own lines, at any time (bounded), as A-5."""
        self.host_log_open = not self.host_log_open
        if self.host_log_open:   # M7.6b E5: the log takes the detail pane's place, so the screen keeps its size
            self.host_lower.forget(self.host_detail_frame)
            self.host_lower.add(self.host_log_frame, weight=1)
        else:
            self.host_lower.forget(self.host_log_frame)
            self.host_lower.add(self.host_detail_frame, weight=1)
            self.shown.pop("host_log", None)
        self._sync_header()

    def toggle_checks(self):
        """E1: the doctor lines, folded under "Checks"."""
        self.checks_open = not self.checks_open
        if self.checks_open:
            self.checks_frame.pack(fill="x", pady=(0, THEME["pad"]["gap"]), before=self.host_paned)
        else:
            self.checks_frame.pack_forget()

    def host_toggle(self):
        """E2: "Watch this host" starts the host watch; while it runs the
        button is its Stop, which ends it with its final report."""
        if self.c.host_watching():
            self.c.stop_host("Stop in the window")
            return
        if self.c.options is not None:   # H-1: the box's word for this watch
            self.c.options.attach_hooks = bool(self.attach_var.get())
            self.c.options.suspect = str(self.suspect_var.get() or "").strip()   # M7.4 E3: empty is off
        self.c.host_note = self.c.start_host()
        self.show_host()

    def _set(self, widget, key, content, tags=None):
        """Replace a Text widget's content when it changed (no flicker, the scroll kept)."""
        if self.shown.get(key) == (content, tags):
            return
        self.shown[key] = (content, tags)
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if tags is None:
            widget.insert("end", content)
        else:
            for line, tag in tags:
                widget.insert("end", line + "\n", (tag,) if tag else ())
        widget.configure(state="disabled")

    def _band(self, word, level, detail, result=False, suppressed=0):
        """E1: the band in its level's colours (level_of, REDO C-1), the
        level's word beside the state word; a watch's green state (result)
        says "Not a clearance." and what the overlay suppressed (REDO C-3)."""
        level = level_of(level)
        fg, bg = band_colours(level, self.mode)
        self.bandf.configure(background=bg)
        for part in (self.band.master, self.band, self.band_level, self.detail):
            part.configure(background=bg)
        self.band.configure(text=word, foreground=fg)
        self.band_level.configure(text=chip_text(level, suppressed, result), foreground=fg)
        self.detail.configure(text=detail, foreground=self.palette["fg"])

    def _badges(self, frame, key, badges):
        """REDO C-2: each (level, text) badge its own label, in its level's
        colour with its word; rows that fit the window."""
        rows = badge_rows(badges)
        if self.shown.get(key) == rows:
            return
        self.shown[key] = rows
        for child in frame.winfo_children():
            child.destroy()
        for row in rows:
            line = self.ttk.Frame(frame)
            for text, level in row:
                self.ttk.Label(line, text=text, style=THEME["styles"]["level"] % level, font=self.small_font).pack(
                    side="left", padx=(0, THEME["pad"]["gap"] * 2))
            line.pack(fill="x")

    def foot_text(self):
        """The footer's lines, every one (REDO C-5: the widget shows three and scrolls)."""
        return self.foot.get("1.0", "end").rstrip("\n")

    def _fill(self, key, tree, items, columns):
        """E2/E3: a Treeview's rows [(values, level, payload, row)], sorted
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
        for cid, heading, _, _, _ in columns:
            mark = (" v" if reverse else " ^") if cid == column else ""
            tree.heading(cid, text=heading + mark)
        keep = [i for i in picked if i in self.payload[key]]
        if keep:
            tree.selection_set(keep)
        return True

    def sort_by(self, key, column):
        """E2: a heading clicked: sort by that column; clicked again, the other way."""
        current, reverse = self.sorting[key]
        self.sorting[key] = (column, not reverse if current == column else False)
        self.shown.pop("table:" + key, None)
        if key == "host":
            self._fill_host(self.c.host_view())
        else:
            self._fill_rules()

    def _fill_host(self, view):
        details = view.get("details") or []
        items = [(tree_values(row), row_level(row), (row, details[i] if i < len(details) else None), row)
                 for i, row in enumerate(view.get("rows") or [])]
        if self._fill("host", self.host_tree, items, TREE_COLUMNS):
            self._show_tree_detail()

    def _show_tree_detail(self):
        picked = self.host_tree.selection()
        payload = self.payload["host"].get(picked[0]) if picked else None
        if payload is None:
            text = ("the selected tree's findings and notes are shown here\n" if self.payload["host"]
                    else "no tree in the table\n")
            self._set(self.host_detail, "host_detail", text)
            return
        self._set(self.host_detail, "host_detail", None, text_tags(tree_detail_text(*payload)))

    def _fill_rules(self):
        items = [(values, level, values[0], values) for values, level in rules_rows(self.rules_panel.rows)]
        self._fill("rules", self.rules_tree, items, RULES_COLUMNS)

    def _first_run(self):
        """E4: the three first-run lines while ~/.raqib/host/look.json does not exist."""
        lines = first_run_lines(self.home)
        if lines and not self.first_run_shown:
            self.first_run_label.configure(text="\n".join(lines))
            self.first_run_label.pack(fill="x", pady=(0, THEME["pad"]["gap"]), before=self.host_row)
            self.first_run_shown = True
        elif not lines and self.first_run_shown:
            self.first_run_label.pack_forget()
            self.first_run_label.configure(text="")
            self.first_run_shown = False

    # actions
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
            self._band(*self.doctor_band)

    def start(self):
        why = self.c.start(self.project.get())
        if why:
            if self.c.project_watching():   # F-2: the refusal names the running watch and goes to its screen
                self.show_watching()
            self._band("NOT STARTED", "alarm", why)
            self.refusal = why
            return
        self.refusal = None
        self.show_watching()

    def stop(self):
        self.c.stop_project("Stop in the window")

    def open_page(self):
        self.c.page_note = self.c.open_page()

    def toggle_log(self):
        """A-5: the watch's own lines, at any time (bounded)."""
        self.log_open = not self.log_open
        if self.log_open:   # M7.6b follow-up: a pane under the body, sharing its height
            self.watch_paned.add(self.log_frame, weight=2)
        else:
            self.watch_paned.forget(self.log_frame)
            self.shown.pop("log", None)
        self._sync_header()

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
        self.after_id = None
        try:
            self._tick()
        except Exception as exc:   # A3, A-8: the window says what broke, keeps it, and keeps going
            self.c.hole("the window failed to update: %s: %s" % (type(exc).__name__, exc))
            self._foot()
        if self.closed:
            return
        if self.c.can_exit():
            self.destroy()
            return
        if self.c.quit_overdue():   # A-3: the watch did not end: the window comes back, nothing is killed
            self.root.deiconify()
            self.root.lift()
            self._foot()
        self.after_id = self.root.after(TICK_MS, self.tick)

    def _foot(self):
        own = self.c.holes + self.c.tray_holes()
        look = self.c.look_holes()   # F-3: the look's, until round 1
        holes = own + look
        notes = list(self.c.notes) + (["page: %s" % self.c.page_note] if self.c.page_note else [])
        # E1: holes amber, notes grey, each line says "hole:" or "note:"; REDO C-5: every line, three shown
        lines = foot_lines(own, notes, look)
        self._set(self.foot, "foot", None, tuple((x, "hole" if x.startswith("hole:") else "note") for x in lines))
        more = foot_more(lines)
        self.foot_more.configure(text=more)
        if more and not self.foot_more.winfo_manager():
            self.foot_more.pack(side="right", padx=(THEME["pad"]["gap"], 0), before=self.foot_frame)
        elif not more and self.foot_more.winfo_manager():
            self.foot_more.pack_forget()
        return holes

    def _head(self):
        """E3: the header's words: the running watches; the rules off (red
        while a running watch's off rules would have fired, ADR-0008 A-2)."""
        self.running_note.configure(text=self.c.running_text())
        states = [getattr(x, "last_state", None) for x in self.c.sessions() if Controller._live(x)]
        text, level = header_rules(self.rules_panel.header(), states)
        if self.refusal and self.c.project_watching():
            text += "   %s" % self.refusal
        self.head_note.configure(text=text, foreground=level_colour(level, self.mode) if level else
                                 self.palette["muted"])

    def _tick(self):
        for action in self.c.drain():
            if action in ("show", "stop"):
                self.root.deiconify()
                self.root.lift()
        holes = self._foot()
        self.c.report_finished()   # F-8: each finished watch's report, appended to the log once
        self._head()               # M7.6: rules off
        if self.first_run_shown:
            self._first_run()      # E4: gone once the first look is written
        fresh = self._tick_doctor()
        view = self.c.host_view()
        project = getattr(self.c.session, "last_state", None) if self.c.project_watching() else None
        sus = view.get("suspicions") or 0   # REDO C-4: suspicions apart from the findings (A2)
        self.c.host_tip(view.get("trees"), view.get("new"), len(view.get("findings") or []) - sus, sus,
                        len((project or {}).get("findings") or []))   # E5: the tray's tooltip
        if self.screen == "rules":
            self._fill_rules()
            self._set(self.rules_text, "rules", self.rules_panel.notes_text())
            return
        if self.screen == "host":
            self._tick_host(view)
            return
        session = self.c.session
        if self.screen == "first" or session is None:
            if fresh and self.screen == "first":
                self._band(*self.doctor_band)
            return
        snap = session.snapshot()
        state = session.state()
        extra = snap["holes"] + holes + ([session.read_note] if session.read_note else [])
        self.knock_label.configure(text=first_line(snap.get("knock")))
        if self.log_open:
            self._set(self.log_text, "log", log_view(session.log.text()))
        if snap["phase"] == "failed" and snap["final_text"] is None:
            self._band("NOT WATCHING", "alarm", snap["error"] or "the watch did not start")
            self._set(self.body, "body", (session.log.text() or "") + "\n" + (snap["error"] or "") + "\n")
            self.stop_button.pack_forget()
            self.back_button.pack(side="left")
            return
        if snap["phase"] == "finished":
            self._band("FINISHED", report_level(snap["final_exit"], snap["final_text"]),   # REDO C-1: exit 3 amber
                       "the watch ended; its final report is below (exit %s)" % snap["final_exit"], result=True,
                       suppressed=report_result(snap["final_text"])[1])                   # REDO C-3
            self._set(self.body, "body", None, text_tags(snap["final_text"] + "".join("hole: %s\n" % h for h in extra)))
            self.stop_button.pack_forget()
            self.back_button.pack(side="left")
            return
        self.back_button.pack_forget()
        self.stop_button.pack(side="left")
        if state is None:
            self._band("STARTING", "incomplete", "installing the hooks and starting the watch of %s"
                       % _safe(session.project))
            return
        view = watch_view(state, extra)
        word = view["word"] + (" (stopping)" if snap["phase"] == "stopping" else "")
        self._band(word, view["level"], view["detail"], result=True, suppressed=ui.suppressed(state))   # REDO C-3
        self._badges(self.badges, "badges", view["badges"])                                           # REDO C-2
        self.url.set(view["url"])
        self._set(self.body, "body", None, text_tags(body_text(view)))

    def _tick_host(self, view):
        """E1/E2: the host screen from the controller's host view."""
        state = getattr(self.c.host, "last_state", None) if self.c.host is not None else None
        suppressed = report_result(view.get("final"))[1] if view.get("final") else ui.suppressed(state or {})
        self._band(view["word"], view["level"], view["detail"], result=True, suppressed=suppressed)   # REDO C-3
        self._badges(self.host_badges, "host_badges", view.get("badges") or [])                       # REDO C-2
        self.host_url.set(view.get("url") or "-")
        self._fill_host(view)
        self._set(self.host_text, "host", None, text_tags(host_text_body(view)))
        if self.host_log_open:   # F-6
            log = getattr(self.c.host, "log", None)
            self._set(self.host_log_text, "host_log", log_view(log.text()) if log is not None else
                      "the host watch has not started: no log yet\n")
        self.host_button.configure(text="Stop host watch" if self.c.host_watching() else "Watch this host")

    def _tick_doctor(self):
        """The doctor's result, when it comes: the project screen's lines
        and band, and the host screen's "Checks" (open when any MISSING)."""
        job = self.doctor
        result = job.result() if job is not None else None
        if result is None:
            return False
        project, lines, summary = result
        tags = tuple((text, level) for _, level, text in lines) + (("", None), (summary, None))
        self._set(self.doctor_text, "doctor", None, tags)
        self._set(self.checks_text, "checks", None, tags)
        label, open_ = checks_state(lines)
        self.checks_button.configure(text=label)
        if open_ != self.checks_open:
            self.toggle_checks()
        missing = any(word == "MISSING" for word, _, _ in lines)
        self.doctor_band = ("DOCTOR: %s" % summary.split(": ", 1)[-1], "alarm" if missing else "clean",
                            "project %s; Start installs the hooks and watches it, as `raqib watch` does" % _safe(project))
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
    try:
        root = tk.Tk()
    except Exception as exc:   # tkinter.TclError: no display it can use
        raise AppError("raqib app: no window could be opened (%s: %s); `raqib watch` works without one"
                       % (type(exc).__name__, _safe(exc)))
    controller = Controller(options, tee=out)
    project = os.path.abspath(project or ".")
    try:
        controller.start_tray()
        window = Window(tk, root, controller, project, environ=options.environ, home=options.home)
        root.mainloop()
        if not window.closed:
            window.destroy()
    finally:
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
