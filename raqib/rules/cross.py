"""CROSS-SOURCE (M5.3, ADR-0003 and its Amendments C and D, rulings C-1 to
C-4 and C-8 of docs/review/2026-11-03-M5.3-ruling.md and D-7 to D-11 of
docs/review/2026-11-03-M5.3-redo-ruling.md): the gap between what the agent
asked for and what the operating system saw happen.

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
  SHELL_TOOL_WORDS (C-4; "cmd" and "command", D-10). Its programs are
  input_meta.command_programs and command_head; with neither
  (command_unread), they are unknown.
- done: a `pre` of tool `process` from the os source; its program is
  input_meta.command_head, its depth input_meta.depth (0 the root, 1 the
  root's direct children), its parent input_meta.parent_seq (the seq of
  the parent's process line in the same os session).
Programs are folded on both sides before they are compared (C-4): lower
case, a trailing .exe, .cmd or .bat dropped. SHELL_IMAGES are the shells
whose own process a shell call starts.

C-2, both directions: a trace with no os line is not judged at all (no
finding, no note), so a trace without the os source (Linux, macOS, or
os-sysmon not run) reads as before, and the report's `sources:` line shows
the absence. A trace with os lines and no hook or proxy line leaves every
os process below the agent's own children unknown (a partial note); when it
has none, the note says "nothing to judge (every os process is the agent's
own)" (D-7). Either way such a trace is INCOMPLETE, never CLEAN.

Spans (D-8): each os session spans its first to its last line; the agent
side is the union of the hook and proxy sessions, each first to last. A
line is judged only inside the other side's span. A shell pre outside every
os session (before os-sysmon's export, after it, or between two) is history:
not judged and no note, so a long-lived project trace does not become
INCOMPLETE after one os-sysmon run. An os process outside every hook and
proxy session is unknown (a partial note), as is any line whose program or
depth cannot be read. W = WINDOW_SECONDS (C-3, reading B):
- asked-not-done: a shell pre at t with no os process in [t, t+W] whose
  program is one of the pre's programs or is a shell image. A pre whose
  programs are unknown is a finding only when no os process at all starts
  in the window, else it is matched by a shell image or unknown;
- done-not-asked: an os process at t, at depth 2 or more, that is not asked.
  A process is asked when its program is in a shell pre in [t-W, t], when
  it is a shell image and a shell pre is in [t-W, t] (a subshell or a
  forked bash below the shell), or when its parent below the shell is asked
  (D-9: the descendants of an asked process are asked: npm -> node, git ->
  sh). A pre in its window with unknown programs makes it unknown, and the
  partial note names that pre (D-10). The root (depth 0) and its direct
  children (depth 1) are the agent's own: its helpers (rg for a search
  tool, git, MCP servers) and the shell it starts for a shell call. They
  are not judged (C-4).
Every finding cites the one line it is about, in its own session (A5): the
other side has no line, which is the finding. Unknown lines are a
`partial` note. An os session whose session_start carries
`missing_events` (os-sysmon: an event id the export does not hold) is a
`source-incomplete` note: the os source is incomplete (exit 3), not an
alarm (C-7: Sysmon logs network connections only with -n).

Known holes, named in THREAT_MODEL and the README:
- an agent that runs its acts as its own direct children, not through a
  shell, is not judged on the done side (C-4);
- names only (D-10): a program is matched by its file name, so a renamed
  binary (curl copied to ls.exe) passes as the program it is named for;
- descendants (D-9): whatever an asked process starts is asked, at any
  depth and any time later, and so is anything a shell image started
  within W of any shell pre starts; the shape of an MSYS bash fork under
  Sysmon is unchecked until the field test;
- the window is fixed (W = 10 s): an act started later than W after its
  call, or a pre written later than W after its act, is a finding;
- a tool whose name holds a shell word but which starts no process (a
  "command palette") is a false-positive source on the asked side (D-10);
- clocks are not compared: hook, proxy and Sysmon read one host's clock.
fp_budget 0.1 until the field test (C-8); the fixtures are in FIXTURES;
`raqib check-rules` measures them (check(), D-11). STATUS is active or
disabled; a disabled rule writes only a `disabled` note.
"""
from __future__ import annotations

import datetime
import os

from raqib.rules.trace import is_record, parse_ts, source_of

RULE_ID = "CROSS-SOURCE"
RULE_KINDS = {RULE_ID: "anchor"}  # ADR-0002: rule id -> kind; read by the gate (C-1)
ATTACK = {RULE_ID: ("T1562",)}   # ADR-0011 B-5 (M10.1): what its finding is consistent with: impaired defenses
CLASS = "CROSS"
SEVERITY = "high"
TITLE = ("a shell call with no os process of its programs within 10 s, or an os process below the agent's"
         " own children that no shell call asked for")
WINDOW_SECONDS = 10
FP_BUDGET = 0.1                       # C-8: until the field test
STATUS = "active"                     # D-11: active | disabled (A6: a rule above budget is disabled)
AGENT_SOURCES = ("hook", "proxy")
OS_SOURCE = "os"
SHELL_TOOL_WORDS = ("bash", "shell", "execute_command", "run_command", "cmd", "command")   # C-4, D-10
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


def _spans(records):
    """[(first, last)] of each session's records with a valid ts."""
    out = {}
    for r in records:
        t = parse_ts(r.get("ts"))
        if t is not None:
            lo, hi = out.get(r["session_id"], (t, t))
            out[r["session_id"]] = (min(lo, t), max(hi, t))
    return list(out.values())


def _inside(spans, t):
    return any(lo <= t <= hi for lo, hi in spans)


def _key(rec):
    return "%s:%d" % (rec["session_id"], rec["seq"])


def findings(lines, window=WINDOW_SECONDS):
    """(findings, notes) of CROSS-SOURCE on trace records. Pure."""
    records = [r for r in lines if is_record(r)]
    os_lines = [r for r in records if source_of(r) == OS_SOURCE]
    if not os_lines:
        return [], []   # C-2: the os source is opt-in
    if STATUS == "disabled":
        return [], [{"rule_id": RULE_ID, "status": "disabled", "detail": "STATUS = disabled in raqib/rules/cross.py (A6)"}]
    agent = [r for r in records if source_of(r) in AGENT_SOURCES]
    os_spans, agent_spans = _spans(os_lines), _spans(agent)   # D-8: per session; the agent side their union
    width = datetime.timedelta(seconds=window)
    pres = [(parse_ts(r.get("ts")), r, asked_programs(r)) for r in agent
            if r.get("phase") == "pre" and is_shell_tool(r.get("tool"))]
    procs = [(parse_ts(r.get("ts")), r, done_program(r)) for r in os_lines
             if r.get("phase") == "pre" and r.get("tool") == "process"]
    out, unknown = [], []   # unknown: (line, why or None)
    for t, rec, programs in pres:
        if t is None:
            unknown.append((rec, None))
            continue
        if not _inside(os_spans, t):
            continue   # D-8: before, after or between os sessions: history, not judged and no note
        near = [(name, q) for u, q, name in procs if u is not None and t <= u <= t + width]
        if any(name in SHELL_IMAGES or (programs and name in programs) for name, _ in near):
            continue
        blind = [q for name, q in near if name is None]
        if blind or (programs is None and near):
            unknown.append((rec, "unread os process %s" % _key(blind[0]) if blind else None))
            continue
        asked = ", ".join(sorted(programs)) if programs else "unknown programs"
        out.append(_finding(rec, "asked, not done: %s seq %d (%s) has no os process of %s or of a shell within %gs"
                                 " after it, inside os session time" % (rec.get("tool"), rec["seq"], _source(rec),
                                                                       asked, window)))
    by_line = {(r["session_id"], r["seq"]): (t, r, name) for t, r, name in procs}
    verdicts = {}

    def verdict(key):
        """("asked" | "not" | "unknown", why) of the os process at key (D-9:
        asked when it, or an ancestor below the shell, was asked)."""
        if key in verdicts:
            return verdicts[key]
        verdicts[key] = ("unknown", None)   # a cycle in parent_seq is unknown
        t, rec, name = by_line[key]
        depth = done_depth(rec)
        if t is None or depth is None or not _inside(agent_spans, t):
            result = ("unknown", None)
        else:
            near = [(p, q) for u, q, p in pres if u is not None and t - width <= u <= t]
            if (name is not None and any(p and name in p for p, _ in near)) or (name in SHELL_IMAGES and near):
                result = ("asked", None)
            else:
                parent = ("not", None)
                if depth > AGENT_DEPTH + 1:   # its parent is below the shell too
                    meta = rec.get("input_meta") or {}
                    link = (rec["session_id"], meta.get("parent_seq"))
                    parent = verdict(link) if link in by_line else ("unknown", None)
                unread = [q for p, q in near if p is None]
                if parent[0] == "asked":
                    result = ("asked", None)
                elif name is None:
                    result = ("unknown", None)
                elif unread:
                    result = ("unknown", "unread pre %s" % _key(unread[0]))
                elif parent[0] == "unknown":
                    result = ("unknown", parent[1] or "its parent could not be judged")
                else:
                    result = ("not", None)
        verdicts[key] = result
        return result

    judged = 0
    for t, rec, name in procs:
        depth = done_depth(rec)
        if depth is not None and depth <= AGENT_DEPTH:
            continue   # C-4: the root and its direct children are the agent's own
        judged += 1
        state, why = verdict((rec["session_id"], rec["seq"]))
        if state == "unknown":
            unknown.append((rec, why))
        elif state == "not":
            out.append(_finding(rec, "done, not asked: os process %s at seq %d (session %s, depth %d) is in no shell"
                                     " call of the hook or proxy within %gs before it, nor below a process that is"
                                     % (name, rec["seq"], rec["session_id"], depth, window)))
    notes = []
    if unknown:
        shown = ", ".join(_key(r) + (" (%s)" % why if why else "") for r, why in unknown[:UNKNOWN_SHOWN])
        notes.append({"rule_id": RULE_ID, "status": "partial",
                      "detail": "could not judge %d line(s) (session:seq %s%s): its time is outside the other source's"
                                " sessions, a program or depth could not be read, or a pre in its window has"
                                " unknown programs" % (len(unknown), shown,
                                                       " ..." if len(unknown) > UNKNOWN_SHOWN else "")})
    if not agent and not judged:   # D-7
        notes.append({"rule_id": RULE_ID, "status": "nothing-to-judge",
                      "detail": "nothing to judge (every os process is the agent's own): the trace holds no hook or"
                                " proxy line and no os process below the agent's direct children"})
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


def check(load, root, benign=()):
    """check-rules' report for CROSS-SOURCE (ruling D-11), in the shape of
    fixtures.check_rule: its positives must fire; a negative, or a benign
    file, is measured only when it holds os lines and left no partial note
    (a file with no os line is not judged at all, C-2). load is
    fixtures.load_fixture; paths are relative to root."""
    positives = []
    for rel in FIXTURES["positive"]:
        found, _ = findings(load(os.path.join(str(root), rel))[0])
        positives.append({"path": rel, "fired": bool(found), "missing_seq": []})
    negatives = []
    for path in [os.path.join(str(root), rel) for rel in FIXTURES["negative"]] + list(benign):
        lines = load(path)[0]
        found, notes = findings(lines)
        judged = any(source_of(r) == OS_SOURCE for r in lines if is_record(r)) and not any(
            n["status"] in ("partial", "nothing-to-judge") for n in notes)
        negatives.append({"path": os.path.relpath(path, str(root)), "fired": bool(found),
                          "measured": bool(found) or judged})
    measured = [n for n in negatives if n["measured"]]
    fp_rate = sum(n["fired"] for n in measured) / len(measured) if measured else None
    if not all(p["fired"] for p in positives):
        verdict = "positive-missed"
    elif not measured:
        verdict = "unmeasured"
    elif STATUS == "disabled":
        verdict = "disabled"
    elif fp_rate > FP_BUDGET:
        verdict = "over-budget"
    else:
        verdict = "ok"
    return {"rule_id": RULE_ID, "status": STATUS, "fp_budget": FP_BUDGET, "fp_rate": fp_rate,
            "measured": len(measured), "unmeasured": len(negatives) - len(measured), "positives": positives,
            "negatives": negatives, "verdict": verdict}


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
