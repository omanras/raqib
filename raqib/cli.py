"""Command line (M1.3): python -m raqib <command>.

  rules TRACE [-o FILE] [--scope P]... [--handoff FILE] [--gap-seconds N]
      Run the silence rules and the rule catalog on a trace. Findings go to
      FILE (one JSON finding per line; ADR-0001 section 6) or stdout. With -o,
      FILE.notes.json records which rules did not run and why.
  report TRACE [--findings FILE] [--scope P]... [--handoff FILE] [--json]
      Show the findings with the trace lines they cite (A5), the alarms, the
      rules that did not run (A3) and every rule's fp_budget (A6). Without
      --findings the rules are run on TRACE first.
  check-rules [--json]
      Run every catalog rule on its fixtures and the benign corpus; print the
      measured fp_rate against the declared fp_budget (A6).

Exit codes: 0 clean, 1 alarm (any finding, empty or corrupt trace),
3 incomplete (a rule did not run), 2 usage or unreadable input.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from raqib import report
from raqib.rules import context as rule_context
from raqib.rules import engine, fixtures, silence, trace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")


class UsageError(Exception):
    pass


def _parser():
    p = argparse.ArgumentParser(prog="raqib", description="Raqib: an external watcher for AI agents.")
    sub = p.add_subparsers(dest="command", required=True)

    def rule_options(sp):
        sp.add_argument("trace", help="trace file written by raqib/hooks/capture.py")
        sp.add_argument("--scope", action="append", default=[], metavar="PATH",
                        help="a path of the task's declared scope (repeatable)")
        sp.add_argument("--handoff", metavar="FILE", help="read the scope from a HANDOFF.md Scope: block")
        sp.add_argument("--gap-seconds", type=float, metavar="N",
                        help="SILENCE-GAP limit (default: RAQIB_GAP_SECONDS or 60)")
        sp.add_argument("--catalog", default=CATALOG, metavar="DIR", help="rule catalog directory")

    r = sub.add_parser("rules", help="write findings for a trace")
    rule_options(r)
    r.add_argument("-o", "--out", metavar="FILE", help="findings file (default: stdout)")
    rep = sub.add_parser("report", help="report findings with their cited trace lines")
    rule_options(rep)
    rep.add_argument("--findings", metavar="FILE", help="use this findings file instead of running the rules")
    rep.add_argument("--json", action="store_true", help="print the report as JSON")
    c = sub.add_parser("check-rules", help="measure every rule against its fixtures (A6)")
    c.add_argument("--catalog", default=CATALOG, metavar="DIR")
    c.add_argument("--json", action="store_true")
    return p


def _context(args):
    scope = list(args.scope)
    if args.handoff:
        scope += rule_context.scope_from_handoff(_read_text(args.handoff, "HANDOFF"))
    return {"scope": scope} if scope else {}


def _gap_seconds(args):
    try:
        if args.gap_seconds is not None:
            return silence.check_gap_seconds(args.gap_seconds, "--gap-seconds")
        return silence.gap_seconds_from(os.environ)
    except ValueError as exc:
        raise UsageError(str(exc))


def _read_text(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise UsageError("cannot read %s %s: %s" % (what, path, exc))


def _read_trace(path):
    try:
        return trace.read_numbered(path)
    except OSError as exc:
        raise UsageError("cannot read trace %s: %s" % (path, exc))


def _catalog(directory):
    try:
        return engine.load_catalog(directory)
    except engine.RuleError as exc:
        raise UsageError(str(exc))


def run_rules(records, rules, ctx, gap_seconds):
    """All findings (silence + catalog) and the notes of rules that did not run."""
    found = report.with_silence_class(silence.findings(records, gap_seconds))
    catalog_found, notes = engine.evaluate(rules, records, ctx)
    return found + catalog_found, notes


def cmd_rules(args, out):
    numbered, problems = _read_trace(args.trace)
    rules = _catalog(args.catalog)
    records = [rec for _, rec in numbered]
    found, notes = run_rules(records, rules, _context(args), _gap_seconds(args))
    text = "".join(json.dumps(f, sort_keys=True, ensure_ascii=True) + "\n" for f in found)
    if args.out:
        sidecar = {"trace": args.trace, "notes": notes, "rules": report.rule_table(rules),
                   "context": _context(args), "problems": problems}
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
            with open(args.out + ".notes.json", "w", encoding="ascii") as f:
                f.write(json.dumps(sidecar, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: %d findings -> %s (notes: %s.notes.json)\n" % (len(found), args.out, args.out))
    else:
        out.write(text)
    rep = report.build(args.trace, numbered, problems, found, notes, report.rule_table(rules), "rules")
    return rep["exit"]


def _read_findings(path):
    """Findings from a file; lines that are not JSON objects become rejected
    findings so the report raises them (A5)."""
    found = []
    for number, raw in enumerate(_read_text(path, "findings file").split("\n"), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except ValueError:
            item = None
        found.append(item if isinstance(item, dict) else {"_line": number})
    notes_path = path + ".notes.json"
    notes = None
    if os.path.exists(notes_path):
        try:
            notes = json.loads(_read_text(notes_path, "notes file"))["notes"]
        except (ValueError, KeyError, TypeError) as exc:
            raise UsageError("bad notes file %s: %s" % (notes_path, exc))
    return found, notes


def cmd_report(args, out):
    numbered, problems = _read_trace(args.trace)
    rules = _catalog(args.catalog)
    if args.findings:
        found, notes = _read_findings(args.findings)
        source = "file %s" % args.findings
    else:
        records = [rec for _, rec in numbered]
        found, notes = run_rules(records, rules, _context(args), _gap_seconds(args))
        source = "rules run on this trace (catalog %s)" % os.path.relpath(args.catalog, ROOT) \
            if os.path.abspath(args.catalog).startswith(ROOT) else "rules run on this trace"
    rep = report.build(args.trace, numbered, problems, found, notes, report.rule_table(rules), source)
    if args.json:
        out.write(json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    else:
        out.write(report.render_text(rep))
    return rep["exit"]


def benign_default():
    corpus = fixtures.benign_corpus(os.path.join(ROOT, "tests", "fixtures", "rules", "benign"))
    real = sorted(os.path.join(ROOT, "tests", "fixtures", n)
                  for n in os.listdir(os.path.join(ROOT, "tests", "fixtures")) if n.endswith(".log"))
    return corpus + real


def cmd_check_rules(args, out):
    rules = _catalog(args.catalog)
    try:
        reports = fixtures.check_catalog(rules, ROOT, benign_default())
    except (fixtures.FixtureError, OSError) as exc:
        raise UsageError(str(exc))
    if args.json:
        out.write(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    else:
        out.write("%-15s %-16s %-8s %-9s %s\n" % ("rule", "verdict", "fp_rate", "fp_budget", "fixtures"))
        for r in reports:
            out.write("%-15s %-16s %-8.3f %-9g %d positive, %d negative incl. benign\n" % (
                r["rule_id"], r["verdict"], r["fp_rate"], r["fp_budget"],
                len(r["positives"]), len(r["negatives"])))
    return 0 if all(r["verdict"] in ("ok", "disabled") for r in reports) else 1


def main(argv=None, out=None):
    out = out or sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        command = {"rules": cmd_rules, "report": cmd_report, "check-rules": cmd_check_rules}[args.command]
        return command(args, out)
    except UsageError as exc:
        sys.stderr.write("raqib: %s\n" % exc)
        return 2
