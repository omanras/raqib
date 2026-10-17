"""Command-line entry: ``python3 -m mizan <command>`` (ADR-0001 section 9).

    python3 -m mizan check  [RULES_DIR] [--corpus DIR] [--json]
    python3 -m mizan test   RULE.yml [--json]
    python3 -m mizan match  RULE.yml EVENTS.jsonl [--json]
    python3 -m mizan corpus [RULES_DIR] [--corpus DIR] [--json]
    python3 -m mizan export RULE.yml --target splunk|elastic [--json]

Defaults: RULES_DIR ``rules/`` and corpus ``corpus/`` of the current
directory.  ``main(argv)`` returns the exit code and never raises: 0 green,
1 red, 2 usage error, 3 could not complete (a path unreadable, a corpus
file unparseable) -- 3 is also red.  Output goes to the streams given
(default: sys.stdout / sys.stderr), so tests call ``main`` directly.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

from mizan import condition, corpus as corpus_module, export, fixtures, loader, report

PROG = "python3 -m mizan"
DEFAULT_RULES_DIR = "rules"
DEFAULT_CORPUS_DIR = "corpus"


class _UsageError(Exception):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    """argparse that reports usage errors through the return code."""

    def __init__(self, *args, **kwargs):
        self._stream = kwargs.pop("stream", None)
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise _UsageError("%s: error: %s\n%s" % (self.prog, message, self.format_usage()))

    def _print_message(self, message, file=None):
        if message:
            (self._stream or sys.stderr).write(message)


def build_parser(stream=None) -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog=PROG, stream=stream,
                             description="Mizan: a deterministic, offline gate for Sigma rules.")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_check = sub.add_parser("check", help="fixtures and budget for every rule of a directory",
                             stream=stream)
    p_check.add_argument("rules_dir", metavar="RULES_DIR", nargs="?", default=DEFAULT_RULES_DIR)
    p_check.add_argument("--corpus", metavar="DIR", default=DEFAULT_CORPUS_DIR)
    p_check.add_argument("--json", action="store_true", help="JSON output")

    p_test = sub.add_parser("test", help="judge one rule by its sidecar fixtures", stream=stream)
    p_test.add_argument("rule", metavar="RULE.yml")
    p_test.add_argument("--json", action="store_true", help="JSON output")

    p_match = sub.add_parser("match", help="run one rule over a JSON Lines file", stream=stream)
    p_match.add_argument("rule", metavar="RULE.yml")
    p_match.add_argument("events", metavar="EVENTS.jsonl")
    p_match.add_argument("--json", action="store_true", help="JSON output")

    p_corpus = sub.add_parser("corpus", help="false-positive rate of every rule on the benign corpus",
                              stream=stream)
    p_corpus.add_argument("rules_dir", metavar="RULES_DIR", nargs="?", default=DEFAULT_RULES_DIR)
    p_corpus.add_argument("--corpus", metavar="DIR", default=DEFAULT_CORPUS_DIR)
    p_corpus.add_argument("--json", action="store_true", help="JSON output")

    p_export = sub.add_parser("export", help="convert one rule to a target query through pySigma",
                              stream=stream)
    p_export.add_argument("rule", metavar="RULE.yml")
    p_export.add_argument("--target", required=True, choices=sorted(export.TARGETS),
                          help="query language: %s" % "|".join(sorted(export.TARGETS)))
    p_export.add_argument("--json", action="store_true", help="JSON output")
    return parser


def _emit(results, as_json: bool, out, **extra) -> None:
    if as_json:
        out.write(report.render_json(results, **extra))
    else:
        out.write(report.render_text(results))


def _load_rule(path: str, err):
    """A Rule, a Problems list, or None after reporting an unreadable path."""
    rule = loader.load(path)
    if isinstance(rule, loader.Problems) and all(p.field == "path" for p in rule):
        for problem in rule:
            err.write("mizan: %s: %s\n" % (path, problem.reason))
        return None
    return rule


def _load_rules_dir(directory: str, err):
    """[(path, Rule | Problems)] or None after reporting an unreadable path."""
    if not os.path.isdir(directory):
        err.write("mizan: %s: %s\n" % (directory, "missing" if not os.path.exists(directory)
                                        else "not a directory"))
        return None
    paths = loader.find_rules(directory)
    if not paths:
        err.write("mizan: no *.yml rule under %s (nothing is green by default)\n" % directory)
        return []
    return [(path, loader.load(path)) for path in paths]


def _report_corpus_problems(corpus, err) -> None:
    if corpus.problem is not None:
        err.write("mizan: %s: corpus directory %s\n" % (corpus.directory, corpus.problem))
    for corpus_file in corpus.files.values():
        if corpus_file.problem is not None:
            err.write("mizan: %s: %s\n" % (corpus_file.path, corpus_file.problem))
        for number, reason in corpus_file.bad_lines:
            err.write("mizan: %s:%d: %s\n" % (corpus_file.path, number, reason))


def cmd_test(args, out, err) -> int:
    rule = _load_rule(args.rule, err)
    if rule is None:
        return report.EXIT_INCOMPLETE
    result = fixtures.judge(rule)
    _emit([result], args.json, out, command="test")
    return report.EXIT_GREEN if result.status == "pass" else report.EXIT_RED


def cmd_match(args, out, err) -> int:
    problem = fixtures.file_problem(args.events)
    if problem is not None:
        err.write("mizan: %s: %s\n" % (args.events, problem))
        return report.EXIT_INCOMPLETE
    rule = _load_rule(args.rule, err)
    if rule is None:
        return report.EXIT_INCOMPLETE
    result = fixtures.match_file(rule, args.events)
    _emit([result], args.json, out, command="match")
    if result.status == "ok":
        return report.EXIT_GREEN
    if result.details.get("file_error"):
        return report.EXIT_INCOMPLETE
    return report.EXIT_RED


def cmd_corpus(args, out, err) -> int:
    loaded = _load_rules_dir(args.rules_dir, err)
    if loaded is None:
        return report.EXIT_INCOMPLETE
    corpus = corpus_module.Corpus(args.corpus)
    _report_corpus_problems(corpus, err)
    results = []
    for _path, rule in loaded:
        result = corpus_module.measure(rule, corpus)
        result.headline = corpus_module.summary_line(result)
        results.append(result)
    results = report.sort_results(results)
    _emit(results, args.json, out, command="corpus", corpus=args.corpus)
    if not corpus.complete:
        return report.EXIT_INCOMPLETE
    return report.exit_code(results)


def cmd_check(args, out, err) -> int:
    loaded = _load_rules_dir(args.rules_dir, err)
    if loaded is None:
        return report.EXIT_INCOMPLETE
    corpus = corpus_module.Corpus(args.corpus)
    _report_corpus_problems(corpus, err)
    results = []
    for _path, rule in loaded:
        compiled = condition.compile_rule(rule) if isinstance(rule, loader.Rule) else None
        fixture_result = fixtures.judge(rule, compiled=compiled)
        corpus_result = corpus_module.measure(rule, corpus, compiled=compiled)
        results.append(report.combine(fixture_result, corpus_result))
    results = report.sort_results(results)
    _emit(results, args.json, out, command="check", rules_dir=args.rules_dir, corpus=args.corpus)
    if not corpus.complete:
        return report.EXIT_INCOMPLETE
    return report.exit_code(results)


def cmd_export(args, out, err) -> int:
    rule = _load_rule(args.rule, err)
    if rule is None:
        return report.EXIT_INCOMPLETE
    try:
        result = export.export_rule(rule, args.target)
    except export.MissingDependency as exc:
        err.write("mizan: %s\n" % exc)
        return report.EXIT_INCOMPLETE
    except export.UnknownTarget as exc:
        err.write("mizan: %s\n" % exc)
        return report.EXIT_USAGE
    except export.ExportError as exc:
        err.write("mizan: export failed: %s\n" % exc)
        return report.EXIT_RED
    if args.json:
        out.write(json.dumps(result, indent=2) + "\n")
    else:
        out.write(result["query"] + "\n")
    return report.EXIT_GREEN


COMMANDS = {
    "check": cmd_check,
    "test": cmd_test,
    "match": cmd_match,
    "corpus": cmd_corpus,
    "export": cmd_export,
}


def main(argv: Optional[List[str]] = None, stdout=None, stderr=None) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser(stream=err)
    try:
        args = parser.parse_args(list(argv))
    except _UsageError as exc:
        err.write(str(exc))
        return report.EXIT_USAGE
    except SystemExit as exc:  # --help
        return report.EXIT_GREEN if exc.code in (0, None) else report.EXIT_USAGE
    if not args.command:
        err.write(parser.format_help())
        return report.EXIT_USAGE
    handler = COMMANDS.get(args.command)
    if handler is None:
        err.write("mizan: unknown command %r\n" % args.command)
        return report.EXIT_USAGE
    try:
        return handler(args, out, err)
    except Exception as exc:  # never a traceback for the user
        err.write("mizan: could not complete: %s: %s\n" % (type(exc).__name__, exc))
        return report.EXIT_INCOMPLETE
