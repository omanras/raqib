"""CROSS-SOURCE (M5.3, ADR-0003 and its Amendment C, rulings C-1 to C-4 and
C-8 of docs/review/2026-11-03-M5.3-ruling.md): the gap between what the
agent asked for and what the operating system saw happen.

A code rule (C-1), not YAML: it joins lines of two sources, in different
sessions, by time, which no construct of the rule language does. It
declares its kind here, in RULE_KINDS, as silence.py does; the gate counts
it, and report lists it beside the silence rules, class CROSS, severity high
(A3: one source is silent about what the other recorded).

ADR-0002 kind: anchor. The os lines (raqib/hooks/os_sysmon.py) are written
by Sysmon, not by the agent: the agent may know this rule; it cannot move
the record it is measured against.

The two sides:
- asked: a `pre` of a shell tool from the hook or the proxy. A shell tool is
  `Bash`, or any tool whose name, lower-cased, contains one of
  SHELL_TOOL_WORDS (C-4). Its programs are input_meta.command_programs and
  command_head; with neither (command_unread), they are unknown.
- done: a `pre` of tool `process` from the os source; its program is
  input_meta.command_head, its depth input_meta.depth (0 the root, 1 the
  root's direct children).
Programs are folded on both sides before they are compared (C-4): lower
case, a trailing .exe, .cmd or .bat dropped. SHELL_IMAGES are the shells
whose own process a shell call starts.

Judged only when the trace holds os lines (C-2): with none the rule emits
nothing and no note, so a trace without the os source (Linux, macOS, or
os-sysmon not run) reads as before; the report's `sources:` line shows the
absence. With os lines, W = WINDOW_SECONDS (C-3, reading B):
- asked-not-done: a shell pre at t with no os process in [t, t+W] whose
  program is one of the pre's programs or is a shell image. Judged only
  when t is inside the span of the os records (first to last ts);
  outside it the line is unknown. A pre whose programs are unknown is a
  finding only when no os process at all starts in the window, else it is
  matched by a shell image or unknown;
- done-not-asked: an os process at t, at depth 2 or more, whose program is
  in no shell pre in [t-W, t]. Judged only when t is inside the span of the
  hook and proxy records; outside it the line is unknown, as it is when its
  program or depth cannot be read, or when a pre in the window has unknown
  programs. The root (depth 0) and its direct children (depth 1) are the
  agent's own: its helpers (rg for a search tool, git, MCP servers) and the
  shell it starts for a shell call. They are not judged (C-4).
Every finding cites the one line it is about, in its own session (A5): the
other side has no line, which is the finding. Unknown lines are a
`partial` note. An os session whose session_start carries
`missing_events` (os-sysmon: an event id the export does not hold) is a
`source-incomplete` note: the os source is incomplete (exit 3), not an
alarm (C-7: Sysmon logs network connections only with -n).

Known holes, named in THREAT_MODEL and the README:
- an agent that runs its acts as its own direct children, not through a
  shell, is not judged on the done side (C-4);
- a shell that starts a copy of itself below the shell call (a subshell,
  a pipeline under MSYS bash) is a process whose program is in no pre
  unless the command names that shell: a false-positive source;
- the window is fixed (W = 10 s): an act started later than W after its
  call, or a pre written later than W after its act, is a finding;
- clocks are not compared: hook, proxy and Sysmon read one host's clock.
fp_budget 0.1 until the field test (C-8); the fixtures are in FIXTURES.
"""
from __future__ import annotations

import datetime

from raqib.rules.trace import is_record, parse_ts, source_of

RULE_ID = "CROSS-SOURCE"
RULE_KINDS = {RULE_ID: "anchor"}  # ADR-0002: rule id -> kind; read by the gate (C-1)
CLASS = "CROSS"
SEVERITY = "high"
TITLE = ("a shell call with no os process of its programs within 10 s, or an os process below the agent's"
         " own children that no shell call asked for")
WINDOW_SECONDS = 10
FP_BUDGET = 0.1                       # C-8: until the field test
AGENT_SOURCES = ("hook", "proxy")
OS_SOURCE = "os"
SHELL_TOOL_WORDS = ("bash", "shell", "execute_command", "run_command", "cmd")   # C-4
SHELL_IMAGES = ("bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh")
FOLD_SUFFIXES = (".exe", ".cmd", ".bat")                                       # C-4
AGENT_DEPTH = 1   # depth 0 is the root, 1 its direct children: the agent's own (C-4)
FIXTURES = {
    "positive": ["tests/fixtures/cross/asked-not-done.log", "tests/fixtures/cross/done-not-asked.log"],
    "negative": ["tests/fixtures/cross/matched.log", "tests/fixtures/cross/rg-helper.log"],
}
UNKNOWN_SHOWN = 5


def is_shell_tool(tool):
    return isinstance(tool, str) and (tool == "Bash" or any(w in tool.lower() for w in SHELL_TOOL_WORDS))


def fold(name):
    """A program name as both sides are compared: lower case, without a
    trailing .exe, .cmd or .bat; None for anything that is not a name."""
    if not isinstance(name, str) or not name:
        return None
    name = name.lower()
    for suffix in FOLD_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return name


def asked_programs(rec):
    """The folded programs of a shell pre, or None when they are unknown."""
    meta = rec.get("input_meta")
    if not isinstance(meta, dict):
        return None
    names = set()
    programs = meta.get("command_programs")
    if isinstance(programs, list):
        names |= {fold(p) for p in programs if isinstance(p, str)}
    names.add(fold(meta.get("command_head")))
    names.discard(None)
    return names or None


def done_program(rec):
    meta = rec.get("input_meta")
    return fold(meta.get("command_head")) if isinstance(meta, dict) else None


def done_depth(rec):
    meta = rec.get("input_meta")
    depth = meta.get("depth") if isinstance(meta, dict) else None
    return depth if isinstance(depth, int) and not isinstance(depth, bool) and depth >= 0 else None


def _span(records):
    times = [t for t in (parse_ts(r.get("ts")) for r in records) if t is not None]
    return (min(times), max(times)) if times else None


def _inside(span, t):
    return span is not None and span[0] <= t <= span[1]


def findings(lines, window=WINDOW_SECONDS):
    """(findings, notes) of CROSS-SOURCE on trace records. Pure."""
    records = [r for r in lines if is_record(r)]
    os_lines = [r for r in records if source_of(r) == OS_SOURCE]
    if not os_lines:
        return [], []   # C-2: the os source is opt-in
    agent = [r for r in records if source_of(r) in AGENT_SOURCES]
    os_span, agent_span = _span(os_lines), _span(agent)
    width = datetime.timedelta(seconds=window)
    pres = [(parse_ts(r.get("ts")), r, asked_programs(r)) for r in agent
            if r.get("phase") == "pre" and is_shell_tool(r.get("tool"))]
    procs = [(parse_ts(r.get("ts")), r, done_program(r)) for r in os_lines
             if r.get("phase") == "pre" and r.get("tool") == "process"]
    out, unknown = [], []
    for t, rec, programs in pres:
        if t is None or not _inside(os_span, t):
            unknown.append(rec)
            continue
        near = [(name, q) for u, q, name in procs if u is not None and t <= u <= t + width]
        if any(name in SHELL_IMAGES or (programs and name in programs) for name, _ in near):
            continue
        if (programs is None and near) or any(name is None for name, _ in near):
            unknown.append(rec)
            continue
        asked = ", ".join(sorted(programs)) if programs else "unknown programs"
        out.append(_finding(rec, "asked, not done: %s seq %d (%s) has no os process of %s or of a shell within %gs"
                                 " after it, though Sysmon recorded the tree until %s"
                                 % (rec.get("tool"), rec["seq"], _source(rec), asked, window,
                                    _iso(os_span[1]))))
    for t, rec, name in procs:
        depth = done_depth(rec)
        if depth is not None and depth <= AGENT_DEPTH:
            continue   # C-4: the root and its direct children are the agent's own
        if t is None or name is None or depth is None or not _inside(agent_span, t):
            unknown.append(rec)
            continue
        near = [p for u, _, p in pres if u is not None and t - width <= u <= t]
        if any(p and name in p for p in near):
            continue
        if any(p is None for p in near):
            unknown.append(rec)
            continue
        out.append(_finding(rec, "done, not asked: os process %s at seq %d (session %s, depth %d) is in no shell"
                                 " call of the hook or proxy within %gs before it"
                                 % (name, rec["seq"], rec["session_id"], depth, window)))
    notes = []
    if unknown:
        shown = ", ".join("%s:%d" % (r["session_id"], r["seq"]) for r in unknown[:UNKNOWN_SHOWN])
        notes.append({"rule_id": RULE_ID, "status": "partial",
                      "detail": "could not judge %d line(s) (session:seq %s%s): its time is outside the span of the"
                                " other source's records, or a program or depth could not be read"
                                % (len(unknown), shown, " ..." if len(unknown) > UNKNOWN_SHOWN else "")})
    for rec in os_lines:
        missing = rec.get("missing_events") if rec.get("phase") == "session_start" else None
        if isinstance(missing, list) and missing:
            ids = ", ".join(str(m) for m in missing)
            notes.append({"rule_id": "*", "status": "source-incomplete",
                          "detail": "os session %s (seq %d): the Sysmon export held no event %s, so the os source"
                                    " is incomplete%s" % (rec["session_id"], rec["seq"], ids,
                                                          "; Sysmon logs network connections (event 3) only"
                                                          " when installed with -n" if 3 in missing else "")})
    order = {}
    for rec in records:
        order.setdefault(rec["session_id"], len(order))
    out.sort(key=lambda f: (order[f["session_id"]], f["cited_seq"][0]))
    return out, notes


def _source(rec):
    return source_of(rec)


def _iso(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _finding(rec, summary):
    return {
        "ts": rec["ts"] if parse_ts(rec.get("ts")) is not None else None,
        "rule_id": RULE_ID,
        "class": CLASS,
        "kind": RULE_KINDS[RULE_ID],
        "severity": SEVERITY,
        "session_id": rec["session_id"],
        "cited_seq": [rec["seq"]],
        "summary": summary,
    }
