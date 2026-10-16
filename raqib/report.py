"""Report (M1.3): findings with the trace lines they cite (A5), every rule with
its fp_budget (A6), and every alarm or gap (A3). Pure: build() takes data and
returns a dict; render_text() turns it into text. The CLI does the I/O.

Result:
- "alarm"      (exit 1) any finding, an empty trace, a corrupt trace line, a
               rejected finding, or a citation with no line in the trace;
- "incomplete" (exit 3) no alarm, but some rule did not run, or it is unknown
               which rules ran;
- "clean"      (exit 0) none of the above.
"""
from __future__ import annotations

import json

from raqib.rules import engine

SILENCE_RULES = (
    ("SILENCE-GAP", "consecutive lines of a session more than RAQIB_GAP_SECONDS apart"),
    ("SILENCE-OPEN", "a started session whose last line is not a stop or session_end"),
    ("SILENCE-HALF", "a seq with more pre than post lines, or the reverse"),
    ("SILENCE-ORDER", "seq or ts going back: trace truncated, rotated or merged"),
)
EXIT = {"clean": 0, "alarm": 1, "incomplete": 3}
LINE_TEXT_MAX = 240


def rule_table(rules):
    """[{id, class, severity, fp_budget, status, title}] for the silence rules
    (Python, no declared budget yet) and the catalog rules."""
    table = [{"id": rid, "class": "SILENCE", "severity": "high", "fp_budget": None,
              "status": "active", "title": title} for rid, title in SILENCE_RULES]
    table += [{"id": r.id, "class": r.cls, "severity": r.severity, "fp_budget": r.fp_budget,
               "status": r.status, "title": r.title} for r in rules]
    return table


def with_silence_class(findings):
    """Silence findings carry class SILENCE like catalog findings carry theirs."""
    return [dict(f, **{"class": "SILENCE"}) if "class" not in f else dict(f) for f in findings]


def describe(rec):
    """One-line, bounded rendering of a trace record (hashes left out). The
    middle is elided, so the end of a long path stays visible."""
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
    return text


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
        except engine.FindingError as exc:
            alarms.append({"kind": "rejected-finding", "detail": str(exc)})
            continue
        items.append(dict(f, cites=_cites(index, f["session_id"], f["cited_seq"], f["rule_id"], alarms)))
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
    return {
        "trace": str(trace_path),
        "records": len(numbered),
        "sessions": sessions,
        "findings_source": findings_source,
        "findings": items,
        "suspicion": raised,
        "suspicion_run": suspicion_run,
        "alarms": alarms,
        "notes": notes,
        "rules": rules,
        "result": result,
        "exit": EXIT[result],
    }


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


def render_text(report):
    out = ["Raqib report",
           "trace: %s (%d records, %d sessions)" % (report["trace"], report["records"],
                                                   len(report["sessions"])),
           "findings: %s" % report["findings_source"], ""]
    out.append("ALARMS (A3, A5): %d" % len(report["alarms"]))
    for a in report["alarms"]:
        where = "line %d: " % a["line"] if "line" in a else ""
        out.append("  - %s: %s%s" % (a["kind"], where, a["detail"]))
    out.append("")
    out.append("FINDINGS: %d" % len(report["findings"]))
    for f in report["findings"]:
        out.append("  [%s] %s (%s) session %s seq %s" % (
            f["severity"], f["rule_id"], f.get("class", "?"), f["session_id"],
            ",".join(str(s) for s in f["cited_seq"])))
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
    out.append("  %-15s %-9s %-7s %-9s %s" % ("id", "class", "sev", "fp_budget", "status"))
    for r in report["rules"]:
        budget = "-" if r["fp_budget"] is None else "%g" % r["fp_budget"]
        out.append("  %-15s %-9s %-7s %-9s %s" % (r["id"], r["class"], r["severity"], budget, r["status"]))
    out.append("")
    out.append("RESULT: %s (exit %d)" % (report["result"].upper(), report["exit"]))
    # Every value can come from the trace or from files the agent can write:
    # no control character may reach the terminal (a newline in a session id
    # could print a fake RESULT line).
    return "\n".join(_safe(line) for line in out) + "\n"
