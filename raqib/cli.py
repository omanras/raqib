"""Command line (M1.3): raqib <command>, or python -m raqib <command>.

`raqib` is the console script of an installed raqib (pyproject.toml, M6.3:
raqib = raqib.cli:main); from a checkout, python -m raqib runs the same main.

  rules TRACE [-o FILE] [--scope P]... [--handoff FILE] [--gap-seconds N]
      Run the silence rules and the rule catalog on a trace. Findings go to
      FILE (one JSON finding per line; ADR-0001 section 6) or stdout. With -o,
      FILE.notes.json records which rules did not run and why.
  report TRACE [--findings FILE] [--scope P]... [--handoff FILE] [--json]
      Show the findings with the trace lines they cite (A5), the alarms, the
      rules that did not run (A3) and every rule's fp_budget (A6). Without
      --findings the rules are run on TRACE first.
  check-rules [--json] [--fixtures-root DIR]
      Run every catalog rule on its fixtures and the benign corpus; print the
      measured fp_rate against the declared fp_budget (A6). The fixtures are
      those of a checkout (DIR/tests/fixtures; default: the checkout this
      raqib runs from). An installed raqib carries the catalog but no
      fixtures: without --fixtures-root it says so and exits 2.
  suspect TRACE [--findings FILE] [--backend ollama|anthropic|fake] [--allow-fallback] [-o FILE]
      Ask a model to raise suspicion over windows of the trace (ADR-0001
      section 5). It can only raise (A2): answers below --threshold are
      dropped, never recorded as clean; failures become error lines (A3).
      With -o, FILE.run.json records how many windows were judged.
      report TRACE --suspicion FILE shows the result with cited lines.
      --allow-fallback lets another model answer a window the anthropic
      model refuses (off by default; ADR-0001 B-5).
      Exit 1 if anything was raised (or the trace is empty or corrupt), 3 if
      no suspicion was raised but some window could not be judged, 0 if
      nothing was raised (not a clearance, A2).
  ui TRACE [--findings FILE] [--suspicion FILE] [-o FILE | --serve [--port N]]
      Write the report as one static, read-only HTML page (timeline,
      findings, silence windows), or serve it on 127.0.0.1. Exit codes as
      for report; --serve runs until interrupted.
  eval [--events FILE] [--candidate SPEC]... [--json] [-o FILE]
      Score the rules, and each candidate model, on labelled events (M2.2;
      a checkout's tests/fixtures/eval/events.json or --events FILE; an
      installed raqib carries none and exits 2 without --events):
      false negatives, false positives and errors, ranked by FN first. SPEC is
      ollama[:MODEL], anthropic[:MODEL] or fake:ANSWERS.json. Exit 0 when
      every row judged every event, 3 when some row has errors, 2 on bad
      input.
  discover [--from DIR] [--read KIND=FILE]... [--window S] [--home DIR]... [--save DIR] [--json] [-o FILE]
      Find AI agents on a host by what they do (M5.0, ADR-0004 Amendment B):
      trees that talk (outbound TCP) and have a child, or write a file
      outside config space, each claim with its cited lines. Without
      --from/--read it reads this host (Linux: /proc and /proc/net/tcp, ss
      by absolute path only as fallback; elsewhere the homes only), offline
      and read-only. Exit 1 when a candidate, an AGENT-DARK footprint or an
      unread line is found, or nothing was read; 3 when a process or
      connection source failed (even in one sample), held no record, or left
      a talking line without an owner; 0 only when those sources were
      complete and nothing was seen (not a clearance); 2 on bad input.
      --save DIR writes the texts and a run.json (each source's error, the
      live holes); --from DIR replays them, incomplete if the run was.
  watch [PROJECT] [--log PATH] [--no-open] [--no-notify] [--port N]
      Watch a project (M6.1, ADR-0005; default: the current directory):
      install the hooks (idempotent; the installer's lines are printed),
      tail the trace (by default outside the project, under ~/.raqib/traces),
      judge each new line with the Scope of PROJECT/HANDOFF.md if there is
      one, notify the OS of settled high findings, live silence
      (RAQIB_GAP_SECONDS), capture failures and trace holes, keep it all in
      TRACE.watch.json with a heartbeat, serve the page on 127.0.0.1 (--port
      N, default 8765; a busy port gives another one and a WARNING) and open
      it once. Lines already in the trace at the start are history: shown,
      never notified. Notifications are off under CI or with --no-notify.
      Ctrl-C, or a crash, prints the final report; exit as for report.
  doctor [PROJECT]
      Say in one screen what `watch` needs and is missing (M6.3,
      raqib/doctor.py): Python, `claude` on PATH and its version, the hook
      settings of PROJECT (installed / foreign / missing), the notifier, Sysmon
      (Windows) and whether the trace can be written. One line per check, OK
      or MISSING; exit 1 if any is MISSING, else 0. Read-only; the only
      program it runs is `claude --version`, by absolute path.

Exit codes (rules, report, ui): 0 clean, 1 alarm (any finding, empty or
corrupt trace, findings made for another trace), 3 incomplete (a rule did
not run), 2 usage or unreadable input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from raqib import discover
from raqib import doctor
from raqib import eval as evaluation
from raqib import report
from raqib import ui
from raqib import watch
from raqib.rules import context as rule_context
from raqib.rules import engine, fixtures, silence, trace
from raqib.suspect import backends as suspect_backends
from raqib.suspect import core as suspect_core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "raqib", "rules", "catalog")
EVENTS = os.path.join(ROOT, "tests", "fixtures", "eval", "events.json")
# G-6: where eval's labelled events come from, in --help and in the exit-2 message.
EVENTS_SOURCE = "a checkout's tests/fixtures/eval/events.json or --events FILE"


class UsageError(Exception):
    pass


def _parser():
    p = argparse.ArgumentParser(prog="raqib", description="Raqib: an external watcher for AI agents.")
    sub = p.add_subparsers(dest="command", required=True)

    def rule_options(sp):
        sp.add_argument("trace", help="trace file written by raqib/hooks/capture.py")
        sp.add_argument("--scope", action="append", default=[], metavar="PATH",
                        help="a path of the task's declared scope (repeatable)")
        sp.add_argument("--handoff", metavar="FILE",
                        help="read the scope from a HANDOFF.md Scope: block (root: the file's directory)")
        sp.add_argument("--root", metavar="DIR",
                        help="directory the scope paths are relative to (default: each line's cwd)")
        sp.add_argument("--gap-seconds", type=float, metavar="N",
                        help="SILENCE-GAP limit (default: RAQIB_GAP_SECONDS or 60)")
        sp.add_argument("--catalog", default=CATALOG, metavar="DIR", help="rule catalog directory")

    r = sub.add_parser("rules", help="write findings for a trace")
    rule_options(r)
    r.add_argument("-o", "--out", metavar="FILE", help="findings file (default: stdout)")
    rep = sub.add_parser("report", help="report findings with their cited trace lines")
    rule_options(rep)
    rep.add_argument("--findings", metavar="FILE", help="use this findings file instead of running the rules")
    rep.add_argument("--suspicion", metavar="FILE", help="suspicion.jsonl written by `suspect`")
    rep.add_argument("--json", action="store_true", help="print the report as JSON")
    c = sub.add_parser("check-rules", help="measure every rule against its fixtures (A6)")
    c.add_argument("--catalog", default=CATALOG, metavar="DIR")
    c.add_argument("--json", action="store_true")
    c.add_argument("--fixtures-root", default=None, metavar="DIR",
                   help="a Raqib checkout: the catalog's fixture paths (tests/fixtures/...) are relative to it"
                        " (default: the checkout this raqib runs from; an installed raqib has no fixtures)")
    s = sub.add_parser("suspect", help="ask a model to raise suspicion (A2: never acquit)")
    rule_options(s)
    s.add_argument("--findings", metavar="FILE", help="findings file (default: run the rules)")
    s.add_argument("--backend", default="ollama", choices=("ollama", "anthropic", "fake"))
    s.add_argument("--model", help="model name (ollama default %s, anthropic default %s)"
                   % (suspect_backends.DEFAULT_OLLAMA_MODEL, suspect_backends.DEFAULT_ANTHROPIC_MODEL))
    s.add_argument("--ollama-url", metavar="URL", help="default: OLLAMA_HOST or http://localhost:11434")
    s.add_argument("--effort", default=suspect_backends.DEFAULT_EFFORT, choices=suspect_backends.EFFORTS,
                   help="anthropic effort level")
    s.add_argument("--allow-fallback", action="store_true",
                   help="anthropic only: let another model answer a refused window (default off;"
                        " such answers are labelled answered_by and counted)")
    s.add_argument("--answers", metavar="FILE", help="canned answers for the fake backend")
    s.add_argument("--threshold", type=float, default=suspect_core.DEFAULT_THRESHOLD)
    s.add_argument("--window", type=int, default=suspect_core.DEFAULT_WINDOW, help="lines per window")
    s.add_argument("-o", "--out", metavar="FILE", help="suspicion file (default: stdout)")
    u = sub.add_parser("ui", help="read-only HTML view of a trace (timeline, findings, silence)")
    rule_options(u)
    u.add_argument("--findings", metavar="FILE", help="use this findings file instead of running the rules")
    u.add_argument("--suspicion", metavar="FILE", help="suspicion.jsonl written by `suspect`")
    u.add_argument("-o", "--out", metavar="FILE", help="HTML file to write (default: stdout)")
    u.add_argument("--serve", action="store_true", help="serve the page on 127.0.0.1 instead")
    u.add_argument("--port", type=int, default=8765, help="port for --serve (default 8765; 0: any free port)")
    e = sub.add_parser("eval", help="score rules and candidate models on labelled events (M2.2)")
    e.add_argument("--events", default=None, metavar="FILE",
                   help="labelled events (default: %s; an installed raqib has none)" % EVENTS_SOURCE)
    e.add_argument("--candidate", action="append", default=[], metavar="SPEC",
                   help="ollama[:MODEL], anthropic[:MODEL] or fake:ANSWERS.json (repeatable)")
    e.add_argument("--catalog", default=CATALOG, metavar="DIR", help="rule catalog directory")
    e.add_argument("--ollama-url", metavar="URL", help="default: OLLAMA_HOST or http://localhost:11434")
    e.add_argument("--effort", default=suspect_backends.DEFAULT_EFFORT, choices=suspect_backends.EFFORTS,
                   help="anthropic effort level")
    e.add_argument("--threshold", type=float, default=suspect_core.DEFAULT_THRESHOLD)
    e.add_argument("--window", type=int, default=suspect_core.DEFAULT_WINDOW, help="lines per window")
    e.add_argument("--json", action="store_true", help="print the result as JSON")
    e.add_argument("-o", "--out", metavar="FILE", help="write the result here (default: stdout)")
    d = sub.add_parser("discover", help="find AI agents on a host by what they do (ADR-0004)")
    d.add_argument("--from", dest="from_dir", metavar="DIR",
                   help="read the source texts in DIR: %s" % ", ".join(discover.FILE_NAMES[k] for k in discover.SOURCES))
    d.add_argument("--read", action="append", default=[], metavar="KIND=FILE",
                   help="read one source text; KIND is one of %s (repeatable)" % ", ".join(discover.SOURCES))
    d.add_argument("--window", type=float, default=0.0, metavar="S",
                   help="live: sample for S seconds, 1 s apart (default 0: one snapshot);"
                        " files: keep timed records of the last S seconds")
    d.add_argument("--home", action="append", metavar="DIR",
                   help="live: a home to list footprints in (default: ~, /root and /home/*; Windows: C:\\Users\\*)")
    d.add_argument("--catalog", default=discover.CATALOG, metavar="FILE", help="endpoint and footprint catalog")
    d.add_argument("--save", metavar="DIR", help="live: write the texts read to DIR, to repeat the run with"
                                                 " --from DIR and check every cited line (A5)")
    d.add_argument("--json", action="store_true", help="print the inventory as JSON")
    d.add_argument("-o", "--out", metavar="FILE", help="write the inventory here (default: stdout)")
    w = sub.add_parser("watch", help="install the hooks, watch the trace live, notify, serve the page (M6.1)")
    w.add_argument("project", nargs="?", default=None, help="the project the agent works in (default: .)")
    w.add_argument("--log", metavar="PATH", help="the trace (default: one outside the project)")
    w.add_argument("--no-open", action="store_true", help="do not open the page in the browser")
    w.add_argument("--no-notify", action="store_true", help="no OS notifications (also off when CI is set)")
    w.add_argument("--port", type=int, default=None, metavar="N",
                   help="port of the page on 127.0.0.1 (default %d, else any free port)" % watch.DEFAULT_PORT)
    dr = sub.add_parser("doctor", help="say in one screen what watch needs and is missing (M6.3; read-only)")
    dr.add_argument("project", nargs="?", default=None, help="the project the agent works in (default: .)")
    return p


def _context(args):
    scope = list(args.scope)
    root = os.path.abspath(args.root) if args.root else None
    if args.handoff:
        scope += rule_context.scope_from_handoff(_read_text(args.handoff, "HANDOFF"))
        root = root or os.path.dirname(os.path.abspath(args.handoff))
    ctx = {"scope": scope} if scope else {}
    if ctx and root:
        ctx["root"] = root
    return ctx


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
        sidecar = {"trace": args.trace, "trace_sha256": _trace_sha256(args.trace), "records": len(records),
                   "notes": notes, "rules": report.rule_table(rules), "context": _context(args),
                   "problems": problems}
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


def _trace_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        raise UsageError("cannot read trace %s: %s" % (path, exc))


def _check_notes(notes, path):
    ok = isinstance(notes, list) and all(
        isinstance(n, dict) and all(isinstance(n.get(k), str) for k in ("rule_id", "status", "detail"))
        for n in notes)
    if not ok:
        raise UsageError("bad notes file %s: notes must be a list of {rule_id, status, detail}" % path)
    return notes


def _read_findings(path, with_sidecar=False):
    """Findings from a file; lines that are not JSON objects become rejected
    findings so the report raises them (A5). With with_sidecar, also return
    the FILE.notes.json record (or None)."""
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
    notes = sidecar = None
    if os.path.exists(notes_path):
        try:
            sidecar = json.loads(_read_text(notes_path, "notes file"))
            notes = _check_notes(sidecar["notes"], notes_path)
        except (ValueError, KeyError, TypeError) as exc:
            raise UsageError("bad notes file %s: %s" % (notes_path, exc))
    return (found, notes, sidecar) if with_sidecar else (found, notes)


def _read_jsonl(path, what):
    items = []
    for raw in _read_text(path, what).split("\n"):
        if raw.strip():
            try:
                items.append(json.loads(raw))
            except ValueError:
                items.append(None)
    return items


def _read_suspicion(path):
    lines = _read_jsonl(path, "suspicion file")
    run = None
    if os.path.exists(path + ".run.json"):
        try:
            run = json.loads(_read_text(path + ".run.json", "suspicion run record"))
        except ValueError as exc:
            raise UsageError("bad suspicion run record %s.run.json: %s" % (path, exc))
    return lines, run


def _report(args):
    """(report dict, numbered, problems) for report and ui."""
    numbered, problems = _read_trace(args.trace)
    rules = _catalog(args.catalog)
    suspicion, suspicion_run = _read_suspicion(args.suspicion) if args.suspicion else (None, None)
    extra = []
    if args.findings:
        found, notes, sidecar = _read_findings(args.findings, with_sidecar=True)
        source = "file %s" % args.findings
        # A findings file proves nothing about another trace (A3).
        if sidecar is not None and sidecar.get("trace_sha256") != _trace_sha256(args.trace):
            extra.append({"kind": "findings-for-another-trace",
                          "detail": "%s.notes.json records trace %s with sha256 %s, but this trace's"
                                    " sha256 is %s: the findings do not describe it (re-run `rules`)"
                                    % (args.findings, sidecar.get("trace"), sidecar.get("trace_sha256"),
                                       _trace_sha256(args.trace))})
    else:
        records = [rec for _, rec in numbered]
        found, notes = run_rules(records, rules, _context(args), _gap_seconds(args))
        source = "rules run on this trace (catalog %s)" % os.path.relpath(args.catalog, ROOT) \
            if os.path.abspath(args.catalog).startswith(ROOT) else "rules run on this trace"
    rep = report.build(args.trace, numbered, problems, found, notes, report.rule_table(rules), source,
                       suspicion, suspicion_run, extra_alarms=extra)
    return rep, numbered, problems


def cmd_report(args, out):
    rep, _, _ = _report(args)
    if args.json:
        out.write(json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    else:
        out.write(report.render_text(rep))
    return rep["exit"]


def benign_default(root=ROOT):
    corpus = fixtures.benign_corpus(os.path.join(root, "tests", "fixtures", "rules", "benign"))
    real = sorted(os.path.join(root, "tests", "fixtures", n)
                  for n in os.listdir(os.path.join(root, "tests", "fixtures")) if n.endswith(".log"))
    return corpus + real


def cmd_check_rules(args, out):
    rules = _catalog(args.catalog)
    root = os.path.abspath(args.fixtures_root) if args.fixtures_root else ROOT
    if not os.path.isdir(os.path.join(root, "tests", "fixtures")):
        raise UsageError("no rule fixtures in %s: check-rules measures each rule on the fixtures of a Raqib"
                         " checkout, which an installed raqib does not carry; pass --fixtures-root CHECKOUT"
                         % os.path.join(root, "tests", "fixtures"))
    try:
        reports = fixtures.check_catalog(rules, root, benign_default(root))
    except (fixtures.FixtureError, OSError) as exc:
        raise UsageError(str(exc))
    if args.json:
        out.write(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    else:
        out.write("%-16s %-16s %-8s %-9s %s\n" % ("rule", "verdict", "fp_rate", "fp_budget", "fixtures"))
        for r in reports:
            rate = "-" if r["fp_rate"] is None else "%.3f" % r["fp_rate"]
            out.write("%-16s %-16s %-8s %-9g %d positive; negatives incl. benign: %d measured,"
                      " %d unmeasured (missing context or unjudgeable lines)\n" % (
                          r["rule_id"], r["verdict"], rate, r["fp_budget"], len(r["positives"]),
                          r["measured"], r["unmeasured"]))
    return 0 if all(r["verdict"] in ("ok", "disabled") for r in reports) else 1


def cmd_suspect(args, out):
    numbered, problems = _read_trace(args.trace)
    records = [rec for _, rec in numbered]
    if args.findings:
        found = _read_findings(args.findings)[0]
        for number, f in enumerate(found, start=1):
            try:
                engine.check_finding(f)
            except engine.FindingError as exc:
                raise UsageError("findings file %s, finding %d: %s" % (args.findings, number, exc))
    else:
        found, _ = run_rules(records, _catalog(args.catalog), _context(args), _gap_seconds(args))
    try:
        backend = suspect_backends.make_backend(args.backend, model=args.model, ollama_url=args.ollama_url,
                                                effort=args.effort, answers=args.answers,
                                                allow_fallback=args.allow_fallback)
        _remote_notice(backend)
        lines, summary = suspect_core.run(records, found, backend, args.threshold, args.window)
    except ValueError as exc:
        raise UsageError(str(exc))
    text = "".join(json.dumps(line, sort_keys=True, ensure_ascii=True) + "\n" for line in lines)
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
            with open(args.out + ".run.json", "w", encoding="ascii") as f:
                f.write(json.dumps(dict(summary, trace=args.trace), indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
    else:
        out.write(text)
    sys.stderr.write("raqib: %d windows judged by %s/%s: %d raised, %d errors, %d below threshold"
                     " (A2: below threshold is not a clearance)\n" % (
                         summary["windows"], summary["backend"], summary["model"], summary["raised"],
                         summary["errors"], summary["below_threshold"]))
    if summary["answered_by_other_model"]:
        sys.stderr.write("raqib: %d windows were answered by another model than %s (server-side fallback)\n"
                         % (summary["answered_by_other_model"], summary["model"]))
    if problems or not records:
        sys.stderr.write("raqib: the trace has %s; run `report` for the alarms\n"
                         % ("no records" if not records else "%d corrupt lines" % len(problems)))
        return 1
    if summary["raised"]:
        return 1
    return 3 if summary["errors"] else 0


def cmd_ui(args, out):
    gap = _gap_seconds(args)
    if args.serve:
        if args.out:
            raise UsageError("use either -o or --serve")
        _report(args)  # fail early on unreadable input

        def page():
            rep, numbered, problems = _report(args)
            return ui.render(rep, numbered, problems, gap)
        try:
            server = ui.make_server(page, args.port)
        except (OSError, OverflowError) as exc:
            raise UsageError("cannot serve on 127.0.0.1:%s: %s" % (args.port, exc))
        out.write("raqib: serving %s at http://127.0.0.1:%d/ (read-only; Ctrl-C to stop)\n"
                  % (args.trace, server.server_address[1]))
        out.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    rep, numbered, problems = _report(args)
    text = ui.render(rep, numbered, problems, gap)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: %s -> %s (%s)\n" % (args.trace, args.out, rep["result"]))
    else:
        out.write(text)
    return rep["exit"]


def _remote_notice(backend):
    if getattr(backend, "remote", False):
        sys.stderr.write("raqib: note: %s is not on this machine; trace metadata is sent to it\n"
                         % backend.url)
    elif backend.name == "anthropic":
        sys.stderr.write("raqib: note: trace metadata is sent to the Anthropic API\n")
        if getattr(backend, "allow_fallback", False):
            sys.stderr.write("raqib: note: server-side fallback is on; another model may answer\n")


def make_candidate(spec, args):
    name, _, rest = spec.partition(":")
    if name == "fake":
        if not rest:
            raise UsageError("candidate fake needs a file: fake:ANSWERS.json")
        return suspect_backends.make_backend("fake", answers=rest)
    if name not in ("ollama", "anthropic"):
        raise UsageError("unknown candidate %r (ollama[:MODEL], anthropic[:MODEL], fake:FILE)" % spec)
    return suspect_backends.make_backend(name, model=rest or None, ollama_url=args.ollama_url,
                                         effort=args.effort)


def cmd_eval(args, out):
    if args.events is None:
        if not os.path.isfile(EVENTS):
            raise UsageError("no labelled events at %s: eval reads %s; an installed raqib carries none"
                             % (EVENTS, EVENTS_SOURCE))
        args.events = EVENTS
    try:
        events = evaluation.load_events(args.events)
        backends = [make_candidate(spec, args) for spec in args.candidate]
        for backend in backends:
            _remote_notice(backend)
        suspect_core.check_threshold(args.threshold)
        result = evaluation.evaluate(events, _catalog(args.catalog), backends, args.threshold,
                                     args.window, silence.gap_seconds_from(os.environ))
    except ValueError as exc:
        raise UsageError(str(exc))
    source = os.path.relpath(args.events, ROOT) if os.path.abspath(args.events).startswith(ROOT) \
        else args.events
    text = (json.dumps(dict(result, source=source), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
            if args.json else evaluation.render_text(result, source))
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: evaluation of %d events -> %s\n" % (result["events"], args.out))
    else:
        out.write(text)
    # A row with errors is an incomplete evaluation (A3).
    return 3 if any(row["errors"] for row in result["rows"]) else 0


def cmd_discover(args, out):
    try:
        catalog = discover.load_catalog(args.catalog)
    except discover.CatalogError as exc:
        raise UsageError(str(exc))
    if not (args.window >= 0 and args.window != float("inf")):
        raise UsageError("--window must be a finite number of seconds >= 0")
    texts, holes = {}, []
    if args.from_dir:
        if not os.path.isdir(args.from_dir):
            raise UsageError("--from %s: not a directory" % args.from_dir)
        try:
            texts, holes = discover.read_dir(args.from_dir)
        except ValueError as exc:
            raise UsageError(str(exc))
        if not texts:
            raise UsageError("--from %s: none of %s is there" % (
                args.from_dir, ", ".join(discover.FILE_NAMES[k] for k in discover.SOURCES)))
    paths = {}
    for spec in args.read:
        kind, sep, path = spec.partition("=")
        if not sep or kind not in discover.SOURCES or not path:
            raise UsageError("--read %s: use KIND=FILE with KIND one of %s" % (spec, ", ".join(discover.SOURCES)))
        if kind in paths or kind in texts:
            raise UsageError("--read %s: source %s given twice" % (spec, kind))
        paths[kind] = path
    texts.update(discover.read_inputs(paths))
    if texts:
        if args.save or args.home:
            raise UsageError("--save and --home apply to a live run (no --from, no --read)")
        inv = discover.run(texts, catalog, window=args.window, holes=holes)
    else:
        texts, holes = discover.collect_live(catalog, window=args.window, homes=args.home)
        if args.save:
            try:
                written = discover.save(texts, args.save, holes)
            except OSError as exc:
                raise UsageError("cannot write %s: %s" % (args.save, exc))
            sys.stderr.write("raqib: texts read -> %s (repeat with --from %s)\n" % (", ".join(written), args.save))
        inv = discover.run(texts, catalog, holes=holes, live=True)
    text = (json.dumps(inv, indent=2, sort_keys=True, ensure_ascii=True) + "\n" if args.json
            else discover.render_text(inv))
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii", errors="backslashreplace") as f:
                f.write(text)
        except OSError as exc:
            raise UsageError("cannot write %s: %s" % (args.out, exc))
        out.write("raqib: inventory of %d records -> %s (%s)\n" % (inv["records"], args.out, inv["result"]))
    else:
        out.write(text)
    return inv["exit"]


def cmd_watch(args, out):
    rules = _catalog(CATALOG)
    try:
        gap = silence.gap_seconds_from(os.environ)
    except ValueError as exc:
        raise UsageError(str(exc))

    def evaluator(project):
        # ADR-0005 B-6: <project>/HANDOFF.md gives the scope, read as `report --handoff` reads it.
        handoff = os.path.join(project, "HANDOFF.md")
        if os.path.isfile(handoff):
            ctx = _context(argparse.Namespace(scope=[], root=None, handoff=handoff))
            note = ("%s Scope: %s (root %s), as report --handoff" % (handoff, ", ".join(ctx["scope"]), ctx["root"])
                    if ctx else "%s has no Scope: block: no scope; rules that need one do not run" % handoff)
        else:
            ctx, note = {}, "no HANDOFF.md in the project: no scope; rules that need one do not run"
        return (lambda records: run_rules(records, rules, ctx, gap)), note
    try:
        return watch.command(args.project, args.log, args.no_open, args.no_notify, args.port, out,
                             evaluator, rules, gap)
    except watch.WatchError as exc:
        raise UsageError(str(exc))


def cmd_doctor(args, out):
    return doctor.run(args.project, out)


def main(argv=None, out=None):
    """The `raqib` console script and python -m raqib (out None: stdout,
    where a path the console cannot encode is escaped, not a crash)."""
    if out is None:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        out = sys.stdout
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        command = {"rules": cmd_rules, "report": cmd_report, "check-rules": cmd_check_rules,
                   "suspect": cmd_suspect, "ui": cmd_ui, "eval": cmd_eval,
                   "discover": cmd_discover, "watch": cmd_watch, "doctor": cmd_doctor}[args.command]
        return command(args, out)
    except UsageError as exc:
        sys.stderr.write("raqib: %s\n" % exc)
        return 2
