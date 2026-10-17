"""Command line (ADR-0001 section 8).

    python3 -m qayd check     [--dir DIR] [--as-of DATE] [--json]
    python3 -m qayd routine   [--dir DIR] [--period 2026-10] [--json]   (M1.2)
    python3 -m qayd decisions [--dir DIR] [--as-of DATE] [--json]       (M1.2)
    python3 -m qayd review    [--dir DIR] --period P -o FILE.html       (M2.1)
    python3 -m qayd init      [--dir DIR]                               (M1.3)

Exit codes: 0 green, 1 red, 2 usage, 3 a file could not be read or parsed
(also red). ``main(argv, stdout, stderr)`` never raises; tests call it
directly. Arguments are parsed by hand so that every message goes to the
streams given, deterministically, with no dependency on argparse's exit.
"""

import datetime
import os
import sys
from typing import NamedTuple, Optional

from . import decisions as decisions_mod
from . import ledger, measures, policies, rates, report, rules

COMMANDS = ("check", "routine", "decisions", "review", "init")
USAGE = (
    "usage: python3 -m qayd <command> [--dir DIR] [--as-of YYYY-MM-DD]\n"
    "                       [--period 2026-10|2026-Q3|2026] [--json] [-o FILE]\n"
    "commands: check, routine, decisions, review, init\n"
)
EXIT_GREEN, EXIT_RED, EXIT_USAGE, EXIT_FILE = 0, 1, 2, 3

FILES = ("policies.yml", "ledger.csv", "holdings.csv", "decisions.yml", "rates.csv")
FILE_LEVEL = ("FILE-MISSING", "FILE-UNREADABLE", "FILE-TOO-LARGE", "FILE-EMPTY",
              "BAD-HEADER", "BAD-YAML", "BAD-SHAPE", "INTERNAL")


class Options(NamedTuple):
    command: Optional[str]
    dir: str
    as_of: Optional[object]
    period: Optional[str]
    json: bool
    output: Optional[str]
    help: bool


class UsageError(Exception):
    pass


def parse_args(argv):
    command = None
    dir_ = "."
    as_of = None
    period = None
    json_ = False
    output = None
    help_ = False
    args = list(argv or ())
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            help_ = True
        elif a == "--json":
            json_ = True
        elif a in ("--dir", "--as-of", "--period", "-o", "--output"):
            if i + 1 >= len(args):
                raise UsageError("%s needs a value" % a)
            value = args[i + 1]
            i += 1
            if a == "--dir":
                dir_ = value
            elif a == "--as-of":
                as_of = policies.as_date(value)
                if as_of is None:
                    raise UsageError("--as-of must be YYYY-MM-DD, got %r" % value)
            elif a == "--period":
                period = value
            else:
                output = value
        elif a.startswith("-"):
            raise UsageError("unknown option %r" % a)
        elif command is None:
            if a not in COMMANDS:
                raise UsageError("unknown command %r" % a)
            command = a
        else:
            raise UsageError("unexpected argument %r" % a)
        i += 1
    return Options(command, dir_, as_of, period, json_, output, help_)


# ------------------------------------------------------------------- loading


class Household(NamedTuple):
    config: object
    ctx: object                     # measures.Context
    decisions: tuple
    problems: dict                  # file -> list of problems
    files: dict                     # file -> row count (None when absent)
    fatal: tuple                    # problems that stop the run (exit 3)


def _is_file_level(problem):
    return problem.get("line", 0) == 0 or problem.get("code") in FILE_LEVEL


def load_household(dir_, as_of):
    """Load every file of a household directory; never raises."""
    paths = dict((name, os.path.join(dir_, name)) for name in FILES)
    problems = {}
    files = {}
    fatal = []

    cfg, cfg_problems = policies.load(paths["policies.yml"])
    problems["policies.yml"] = list(cfg_problems)
    files["policies.yml"] = len(cfg.policies) if cfg is not None else None
    fatal.extend(p for p in cfg_problems if p.get("class") == "invalid")
    if cfg is None:
        return Household(None, None, (), problems, files, tuple(fatal))

    led = ledger.load_ledger(paths["ledger.csv"], cfg.accounts, cfg.categories)
    problems["ledger.csv"] = list(led.problems)
    files["ledger.csv"] = len(led.rows)
    fatal.extend(p for p in led.problems if _is_file_level(p))

    hol = ledger.load_holdings(paths["holdings.csv"], cfg.accounts, cfg.classes)
    problems["holdings.csv"] = list(hol.problems)
    files["holdings.csv"] = len(hol.rows)
    fatal.extend(p for p in hol.problems if _is_file_level(p))

    dec = decisions_mod.load(paths["decisions.yml"], cfg.policy_ids)
    problems["decisions.yml"] = list(dec.problems)
    files["decisions.yml"] = len(dec.decisions)
    fatal.extend(p for p in dec.problems if _is_file_level(p))

    rt = rates.load_optional(paths["rates.csv"], cfg.base_currency)
    problems["rates.csv"] = list(rt.problems)
    files["rates.csv"] = len(rt.table.rows) if os.path.exists(paths["rates.csv"]) else None
    fatal.extend(p for p in rt.problems if _is_file_level(p))

    ctx = measures.Context(cfg, led.rows, hol.rows, rt.table, as_of,
                           tuple(led.problems), tuple(hol.problems), dec.decisions)
    return Household(cfg, ctx, dec.decisions, problems, files, tuple(fatal))


def all_problems(household):
    out = []
    for name in FILES:
        out.extend(household.problems.get(name, ()))
    return tuple(out)


def _write_fatal(household, err):
    err.write("qayd: cannot read or parse the household files:\n")
    for p in household.fatal:
        where = "%s:%d" % (p["file"], p["line"]) if p.get("line") else p["file"]
        err.write("  %s %s: %s\n" % (where, p["code"], p["reason"]))


# ------------------------------------------------------------------ commands


def build_check(household, as_of):
    verdicts, findings = rules.check(household.ctx, as_of)
    findings = findings + rules.problem_findings(household.problems.get("decisions.yml"))
    findings = findings + rules.problem_findings(household.problems.get("rates.csv"))
    green = rules.is_green(verdicts, findings)
    return report.Report("check", as_of, household.config, verdicts, findings,
                         household.files, all_problems(household), green)


def cmd_check(opts, out, err):
    as_of = opts.as_of or datetime.date.today()
    household = load_household(opts.dir, as_of)
    if household.fatal:
        _write_fatal(household, err)
        return EXIT_FILE
    rep = build_check(household, as_of)
    out.write(report.render_json(rep) if opts.json else report.render_text(rep))
    return EXIT_GREEN if rep.green else EXIT_RED


def main(argv=None, stdout=None, stderr=None):
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    try:
        try:
            opts = parse_args(argv if argv is not None else sys.argv[1:])
        except UsageError as exc:
            err.write("qayd: %s\n%s" % (exc, USAGE))
            return EXIT_USAGE
        if opts.help or opts.command is None:
            (out if opts.help else err).write(USAGE)
            return EXIT_GREEN if opts.help else EXIT_USAGE
        if opts.command == "check":
            return cmd_check(opts, out, err)
        err.write("qayd: command %r is not available yet\n%s" % (opts.command, USAGE))
        return EXIT_USAGE
    except Exception as exc:  # the contract is "never raises"
        try:
            err.write("qayd: internal error: %s: %s\n" % (type(exc).__name__, exc))
        except Exception:
            pass
        return EXIT_FILE
