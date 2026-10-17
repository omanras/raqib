"""Command-line entry: ``python3 -m mizan <command>`` (ADR-0001 section 9).

    python3 -m mizan test   RULE.yml [--json]
    python3 -m mizan match  RULE.yml EVENTS.jsonl [--json]

``main(argv)`` returns the exit code and never raises: 0 green, 1 red,
2 usage error, 3 could not complete (a path unreadable).  Output goes to
the streams given (default: sys.stdout / sys.stderr), so tests call
``main`` directly without a subprocess.
"""

import argparse
import sys
from typing import List, Optional

from mizan import fixtures, loader, report

PROG = "python3 -m mizan"


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


class _UsageError(Exception):
    pass


def build_parser(stream=None) -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog=PROG, stream=stream,
                             description="Mizan: a deterministic, offline gate for Sigma rules.")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_test = sub.add_parser("test", help="judge one rule by its sidecar fixtures", stream=stream)
    p_test.add_argument("rule", metavar="RULE.yml")
    p_test.add_argument("--json", action="store_true", help="JSON output")

    p_match = sub.add_parser("match", help="run one rule over a JSON Lines file", stream=stream)
    p_match.add_argument("rule", metavar="RULE.yml")
    p_match.add_argument("events", metavar="EVENTS.jsonl")
    p_match.add_argument("--json", action="store_true", help="JSON output")
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


COMMANDS = {
    "test": cmd_test,
    "match": cmd_match,
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
