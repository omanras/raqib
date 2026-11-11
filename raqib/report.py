"""Report (M1.3): findings with the trace lines they cite (A5), every rule with
its fp_budget (A6), and every alarm or gap (A3). Pure: build() takes data and
returns a dict; render_text() turns it into text. The CLI does the I/O.

Result:
- "alarm"      (exit 1) any finding, an empty trace, a corrupt trace line, a
               rejected finding, a finding without a kind (no-kind,
               ADR-0002 B-3), or a citation with no line in the trace;
- "incomplete" (exit 3) no alarm, but some rule did not run, or it is unknown
               which rules ran;
- "clean"      (exit 0) none of the above.

Every finding line and every row of the RULES table names the rule's kind
(signature, demand or anchor; ADR-0002 B-1).

Every finding names the capture source of the lines it cites (ADR-0003,
M5.2 E4): "hook", "proxy" or "os" (a line without the field is "hook"),
several joined by "+" when its lines come from more than one, "-" when none
of its lines is in the trace. A trace may mix sources; the header counts the
records of each.
"""
from __future__ import annotations

import json

from raqib.rules import cross, engine, silence, trace, tree

SILENCE_RULES = (
    ("SILENCE-GAP", "consecutive lines of a session more than RAQIB_GAP_SECONDS apart"),
    ("SILENCE-OPEN", "a started session whose last line is not a stop or session_end"),
    ("SILENCE-HALF", "a seq with more pre than post lines, or the reverse"),
    ("SILENCE-ORDER", "seq or ts going back: trace truncated, rotated or merged"),
    ("SILENCE-EMPTY", "a session that ended with no tool call and no stop, or ended with no start and no tool call"),
)
# M5.3 (ruling C-1): the code rule of raqib/rules/cross.py, listed beside the
# silence rules; its kind is cross.RULE_KINDS, its class CROSS.
CROSS_RULES = (
    (cross.RULE_ID, cross.TITLE),
)
# M4.3 (ruling J-1): the two code rules of raqib/rules/tree.py, listed after
# CROSS-SOURCE; their kinds are tree.RULE_KINDS, their class DRIFT.
TREE_RULES = tuple((rid, tree.TITLES[rid]) for rid in tree.RULES)
EXIT = {"clean": 0, "alarm": 1, "incomplete": 3}
LINE_TEXT_MAX = 240


def rule_table(rules):
    """[{id, class, kind, severity, fp_budget, status, title}] for the silence
    rules (Python, no declared budget yet; kind from silence.RULE_KINDS, None
    if it declares none), the cross-source rule (Python, class CROSS, its
    budget and kind from raqib/rules/cross.py), the two tree anchors (Python,
    class DRIFT, their budgets and kinds from raqib/rules/tree.py, M4.3 J-1)
    and the catalog rules."""
    table = [{"id": rid, "class": "SILENCE", "kind": silence.RULE_KINDS.get(rid), "severity": "high",
              "fp_budget": None, "status": "active", "title": title} for rid, title in SILENCE_RULES]
    table += [{"id": rid, "class": cross.CLASS, "kind": cross.RULE_KINDS.get(rid), "severity": cross.SEVERITY,
               "fp_budget": cross.FP_BUDGET, "status": cross.STATUS, "title": title} for rid, title in CROSS_RULES]
    table += [{"id": rid, "class": tree.CLASS, "kind": tree.RULE_KINDS.get(rid), "severity": tree.SEVERITY,
               "fp_budget": tree.FP_BUDGET.get(rid), "status": tree.STATUS.get(rid), "title": title}
              for rid, title in TREE_RULES]
    table += [{"id": r.id, "class": r.cls, "kind": r.kind, "severity": r.severity, "fp_budget": r.fp_budget,
               "status": r.status, "title": r.title} for r in rules]
    return table


def with_silence_class(findings):
    """Silence findings carry class SILENCE like catalog findings carry theirs."""
    return [dict(f, **{"class": "SILENCE"}) if "class" not in f else dict(f) for f in findings]


def describe(rec):
    """One-line, bounded rendering of a trace record (hashes left out). The
    middle is elided, so the end of a long path stays visible. On a
    session_start, stop or session_end line the three git keys follow, after
    the elision, so a tree finding's cited lines show what was compared
    (M4.3, ruling K-8): each value as JSON when it is in the hook's shape
    (40-hex, 64-hex, one of the closed set, or null), else "?"."""
    parts = ["%s %s seq %s" % (rec.get("phase", "?"), rec.get("tool", "?"), rec.get("seq")),
             str(rec.get("ts", "-"))]
    for key in ("ok", "error_class"):
        if key in rec:
            parts.append("%s=%s" % (key, json.dumps(rec[key])))
    for key in ("input_meta", "output_meta"):
        if rec.get(key):
            parts.append("%s=%s" % (key, json.dumps(rec[key], sort_keys=True)))
    if "cwd" in rec:
        parts.append("cwd=%s" % json.dumps(rec["cwd"]))
    text = "  ".join(parts)
    text = "".join(c if c.isprintable() else "?" for c in text)
    if len(text) > LINE_TEXT_MAX:
        keep = LINE_TEXT_MAX - 3
        text = text[:keep // 2] + "..." + text[-(keep - keep // 2):]
    if rec.get("phase") in trace.GIT_PHASES:
        shown = ["%s=%s" % (key, _git_value(key, rec[key])) for key in trace.GIT_KEYS if key in rec]
        if shown:
            text += "  " + "  ".join(shown)
    return text


def _git_value(key, value):
    """A git key's value as describe shows it: JSON when in the hook's shape, else "?" (bounded, K-8)."""
    if value is None:
        return "null"
    shape = {"git_head": trace.HEX40, "git_index_sha256": trace.HEX64}.get(key)
    if isinstance(value, str) and (shape.match(value) if shape else value in trace.GIT_ERRORS):
        return json.dumps(value)
    return '"?"'


def build(trace_path, numbered, problems, findings, notes, rules, findings_source,
          suspicion=None, suspicion_run=None, extra_alarms=()):
    """numbered: [(line number, record)]; problems: trace.parse problems;
    findings: dicts (from the engine or a findings file); notes: rule notes,
    or None when it is unknown which rules ran; rules: rule_table();
    suspicion: lines of a suspicion.jsonl (M2.1), suspicion_run: its run record;
    extra_alarms: alarms found by the caller (e.g. findings for another trace)."""
    index = {}
    sessions = []
    for number, rec in numbered:
        index.setdefault((rec["session_id"], rec["seq"]), []).append((number, rec))
        if rec["session_id"] not in sessions:
            sessions.append(rec["session_id"])
    alarms = []
    if not numbered:
        alarms.append({"kind": "empty-trace",
                       "detail": "the trace has no records; silence is an alarm (A3)"})
    for p in problems:
        alarms.append({"kind": "trace-problem", "line": p["line"], "detail": p["reason"]})
    alarms += [dict(a) for a in extra_alarms]
    items = []
    for f in findings:
        try:
            engine.check_finding(f)
        except engine.NoKindError as exc:  # B-3: sound but for its kind; not passed over (A3)
            alarms.append({"kind": "no-kind", "detail": str(exc)})
            continue
        except engine.FindingError as exc:
            alarms.append({"kind": "rejected-finding", "detail": str(exc)})
            continue
        cites = _cites(index, f["session_id"], f["cited_seq"], f["rule_id"], alarms)
        items.append(dict(f, cites=cites, source=_source(index, f["session_id"], f["cited_seq"])))
    raised = []
    for s in suspicion or []:
        problem = suspicion_problem(s)
        if problem:
            alarms.append({"kind": "rejected-suspicion", "detail": problem})
        elif s["kind"] == "error":
            alarms.append({"kind": "suspicion-error",
                           "detail": "the model did not judge session %s seq %s to %s: %s"
                                     % (s["session_id"], s["window"][0], s["window"][1], s["error"])})
        else:
            label = "suspicion (%s/%s)" % (s.get("backend"), s.get("model"))
            raised.append(dict(s, cites=_cites(index, s["session_id"], s["cited_seq"], label, alarms)))
    if suspicion is not None:
        run_problem = suspicion_run_problem(suspicion_run, suspicion)
        if run_problem:
            alarms.append({"kind": "suspicion-run", "detail": run_problem})
            suspicion_run = None
    if notes is None:
        notes = [{"rule_id": "*", "status": "unknown",
                  "detail": "no rule notes next to the findings file; which rules ran is unknown"}]
    if alarms or items or raised:
        result = "alarm"
    elif any(n["status"] != "disabled" for n in notes):
        result = "incomplete"
    else:
        result = "clean"
    sources = {}
    for _, rec in numbered:
        name = trace.source_of(rec)
        sources[name] = sources.get(name, 0) + 1
    return {
        "trace": str(trace_path),
        "records": len(numbered),
        "sources": sources,
        "sessions": sessions,
        "findings_source": findings_source,
        "findings": items,
        "suspicion": raised,
        "suspicion_given": suspicion is not None,
        "suspicion_run": suspicion_run,
        "alarms": alarms,
        "notes": notes,
        "rules": rules,
        "result": result,
        "exit": EXIT[result],
    }


def _source(index, session_id, seqs):
    """The capture source(s) of the lines a finding cites (ADR-0003): one
    name, several joined by "+", or "-" when no cited line is in the trace."""
    names = sorted({trace.source_of(rec) for seq in seqs for _, rec in index.get((session_id, seq), [])})
    return "+".join(names) or "-"


def _cites(index, session_id, seqs, label, alarms):
    cites = []
    for seq in seqs:
        lines = index.get((session_id, seq), [])
        if not lines:
            alarms.append({"kind": "missing-citation",
                           "detail": "%s cites session %s seq %d, which has no line in the trace"
                                     % (label, session_id, seq)})
        cites.append({"seq": seq, "lines": [{"line": n, "text": describe(r)} for n, r in lines]})
    return cites


def suspicion_problem(line):
    """Why a suspicion.jsonl line is unusable, or None (A2, A5)."""
    if not isinstance(line, dict) or line.get("kind") not in ("suspicion", "error"):
        return "not a suspicion or error line: %r" % (line,)
    window = line.get("window")
    if not (isinstance(line.get("session_id"), str) and isinstance(window, list) and len(window) == 2):
        return "line without session_id and window: %r" % (line,)
    if line["kind"] == "error":
        return None if isinstance(line.get("error"), str) else "error line without error text"
    s = line.get("suspicion")
    if not (isinstance(s, (int, float)) and not isinstance(s, bool) and 0 < s <= 1):
        return "suspicion must be a number above 0 and at most 1 (A2): %r" % (s,)
    cited = line.get("cited_seq")
    if not (isinstance(cited, list) and cited and all(isinstance(c, int) and not isinstance(c, bool)
                                                       for c in cited)):
        return "suspicion without cited_seq is rejected (A5)"
    if not all(isinstance(w, int) for w in window) or not all(window[0] <= c <= window[1] for c in cited):
        return "suspicion cites seqs outside its window %r (A5): %r" % (window, cited)
    reasons = line.get("reasons")
    if not (isinstance(reasons, list) and reasons and all(isinstance(r, str) for r in reasons)):
        return "suspicion without reasons"
    return None


RUN_KEYS = {"windows": int, "raised": int, "errors": int, "below_threshold": int,
            "backend": str, "model": str, "threshold": (int, float)}


def suspicion_run_problem(run, lines):
    """Why a suspicion run record does not account for its suspicion file,
    or None. Without it, "nothing raised" and "the model never ran" look the
    same (A3)."""
    if run is None:
        return ("no run record next to the suspicion file: whether, and how far, the model ran"
                " is unknown")
    if not isinstance(run, dict) or not all(
            isinstance(run.get(k), t) and not isinstance(run.get(k), bool) for k, t in RUN_KEYS.items()):
        return "the run record is malformed: %r" % (run,)
    kinds = [x.get("kind") if isinstance(x, dict) else None for x in lines]
    raised, errors = kinds.count("suspicion"), kinds.count("error")
    if (run["raised"], run["errors"]) != (raised, errors):
        return ("the run record counts %d raised and %d errors, but the file holds %d and %d:"
                " lines were added or removed" % (run["raised"], run["errors"], raised, errors))
    if run["windows"] != run["raised"] + run["errors"] + run["below_threshold"]:
        return "the run record's counts do not add up to its %d windows" % run["windows"]
    return None


def _safe(text):
    return "".join(c if c.isprintable() else "?" for c in str(text))


# M9.1 (ADR-0010 decision 5): the line under "ALARMS (A3, A5): N" in the text report (the JSON report has none).
# M9.1 REDO (Amendment B, B-5): what it counts truly - the trace's alarms and the watch's own.
ALARMS_SAYS = ("  (the trace's and the watch's own: what could not be read, cited or kept; every finding below also"
               " makes the RESULT an ALARM)")


def render_text(report):
    out = ["Raqib report",
           "trace: %s (%d records, %d sessions)" % (report["trace"], report["records"],
                                                   len(report["sessions"]))]
    sources = report.get("sources") or {}
    if sources:
        out.append("sources: %s" % ", ".join("%s %d" % (name, sources[name]) for name in sorted(sources)))
    out += ["findings: %s" % report["findings_source"], ""]
    out.append("ALARMS (A3, A5): %d" % len(report["alarms"]))
    out.append(ALARMS_SAYS)   # M9.1 (ADR-0010 decision 5): what the line counts; the text report only
    for a in report["alarms"]:
        where = "line %d: " % a["line"] if "line" in a else ""
        out.append("  - %s: %s%s" % (a["kind"], where, a["detail"]))
    out.append("")
    out.append("FINDINGS: %d" % len(report["findings"]))
    for f in report["findings"]:
        out.append("  [%s] %s (%s, %s) session %s seq %s" % (
            f["severity"], f["rule_id"], f.get("class", "?"), f["kind"], f["session_id"],
            ",".join(str(s) for s in f["cited_seq"])))
        out.append("      source: %s" % f.get("source", "-"))
        out.append("      %s" % f["summary"])
        for c in f["cites"]:
            if not c["lines"]:
                out.append("      seq %d: NO LINE IN TRACE" % c["seq"])
            for ln in c["lines"]:
                out.append("      seq %d: line %d  %s" % (c["seq"], ln["line"], ln["text"]))
    out.append("")
    run = report.get("suspicion_run")
    out.append("SUSPICION (model, raises only, A2): %d" % len(report.get("suspicion") or []))
    if run:
        out.append("  %d windows judged by %s/%s: %d raised, %d errors, %d below threshold %g"
                   " (below threshold is not a clearance)" % (
                       run["windows"], _safe(run["backend"]), _safe(run["model"]), run["raised"],
                       run["errors"], run["below_threshold"], run["threshold"]))
    for s in report.get("suspicion") or []:
        out.append("  [%.2f] session %s seq %s to %s (%s/%s)" % (
            s["suspicion"], s["session_id"], s["window"][0], s["window"][1],
            _safe(s.get("backend")), _safe(s.get("model"))))
        for reason in s["reasons"]:
            out.append("      - %s" % _safe(reason))
        for c in s["cites"]:
            if not c["lines"]:
                out.append("      seq %d: NO LINE IN TRACE" % c["seq"])
            for ln in c["lines"]:
                out.append("      seq %d: line %d  %s" % (c["seq"], ln["line"], ln["text"]))
    out.append("")
    out.append("RULES THAT DID NOT RUN: %d" % len(report["notes"]))
    for n in report["notes"]:
        out.append("  - %s %s: %s" % (n["rule_id"], n["status"], n["detail"]))
    out.append("")
    out.append("RULES (A6 fp_budget): %d" % len(report["rules"]))
    out.append("  %-15s %-9s %-9s %-7s %-9s %s" % ("id", "class", "kind", "sev", "fp_budget", "status"))
    for r in report["rules"]:
        budget = "-" if r["fp_budget"] is None else "%g" % r["fp_budget"]
        out.append("  %-15s %-9s %-9s %-7s %-9s %s" % (r["id"], r["class"], r.get("kind") or "-", r["severity"],
                                                      budget, r["status"]))
    out.append("")
    out.append("RESULT: %s (exit %d)" % (report["result"].upper(), report["exit"]))
    # Every value can come from the trace or from files the agent can write:
    # no control character may reach the terminal (a newline in a session id
    # could print a fake RESULT line).
    return "\n".join(_safe(line) for line in out) + "\n"
