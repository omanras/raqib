"""Ledger and holdings loaders (ADR-0001 sections 3 and 4).

Both loaders read a strict CSV file and return ``Loaded(rows, problems)``.
They never raise: a file that cannot be read, a header that does not match,
a malformed row, an undeclared account, category or class, each becomes a
problem naming the file and the line, and the run continues past it.

A problem is a plain dict so it can be printed or serialised as is:

    {"file": "ledger.csv", "line": 17, "code": "BAD-DATE",
     "class": "invalid", "reason": "date '2026-13-01' is not YYYY-MM-DD"}

``line`` is 1-based (line 1 is the header); ``line`` 0 means the problem is
about the file as a whole (missing, unreadable, too large, empty).
``class`` is ``invalid`` (red; the row is not loaded) or ``warn`` (the row
is loaded; today only ``DUP-ROW``). Row-level problems carry the row's
``date`` as ISO text when it parsed, so later layers can mark the period.

Money is Decimal, never float (A5). Files are UTF-8 with an optional BOM;
CRLF line ends are tolerated. A line of 1 MiB or more and a file of 64 MiB
or more are problems, not work.
"""

import csv
import datetime
import os
import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import NamedTuple, Optional, Tuple

LEDGER_HEADER = "date,amount,currency,account,category,tags,note"
HOLDINGS_HEADER = "date,account,asset,class,quantity,value,currency"

MAX_LINE_BYTES = 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024

_BOM = b"\xef\xbb\xbf"
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_AMOUNT_RE = re.compile(r"^-?[0-9]+(\.[0-9]+)?$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_TAG_RE = re.compile(r"^[^\s;]+$")

INVALID = "invalid"
WARN = "warn"

# The csv module caps a single field at 128 KiB by default; a note may be as
# long as the line limit allows. The line limit above is the real bound.
if csv.field_size_limit() < MAX_LINE_BYTES:
    csv.field_size_limit(MAX_LINE_BYTES)


class LedgerRow(NamedTuple):
    date: datetime.date
    amount: Decimal
    currency: str
    account: str
    category: str
    tags: Tuple[str, ...]
    note: str
    line: int
    file: str

    @property
    def cite(self):
        return "%s:%d" % (self.file, self.line)


class HoldingRow(NamedTuple):
    date: datetime.date
    account: str
    asset: str
    asset_class: str
    quantity: Decimal
    value: Decimal
    currency: str
    line: int
    file: str

    @property
    def cite(self):
        return "%s:%d" % (self.file, self.line)


class Loaded(NamedTuple):
    rows: tuple
    problems: list


class Snapshot(NamedTuple):
    rows: tuple
    date: Optional[datetime.date]


def _declared(decl):
    """Flatten a declaration: a mapping group -> names, or an iterable of names."""
    if decl is None:
        return set()
    if isinstance(decl, Mapping):
        out = set()
        for value in decl.values():
            if isinstance(value, str):
                out.add(value)
            elif value is not None:
                out.update(str(v) for v in value)
        return out
    if isinstance(decl, str):
        return {decl}
    return set(str(v) for v in decl)


def _problem(file, line, code, reason, cls=INVALID, **extra):
    p = {"file": file, "line": line, "code": code, "class": cls, "reason": reason}
    p.update(extra)
    return p


def _parse_date(text):
    if not _DATE_RE.match(text):
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


def _parse_amount(text):
    if not _AMOUNT_RE.match(text):
        return None
    try:
        return Decimal(text)
    except InvalidOperation:
        return None


def _parse_tags(text):
    if text == "":
        return ()
    tokens = text.split(";")
    for token in tokens:
        if not _TAG_RE.match(token):
            return None
    return tuple(tokens)


def _read_lines(path, file):
    """Return (lines, problems, fatal). lines: list of (lineno, text|None)."""
    problems = []
    try:
        size = os.stat(path).st_size
    except FileNotFoundError:
        return [], [_problem(file, 0, "FILE-MISSING", "file not found: %s" % path)], True
    except (OSError, TypeError, ValueError) as exc:
        return [], [_problem(file, 0, "FILE-UNREADABLE", "cannot stat %s: %s" % (path, exc))], True
    if size >= MAX_FILE_BYTES:
        return [], [_problem(file, 0, "FILE-TOO-LARGE",
                             "file is %d bytes; the limit is %d" % (size, MAX_FILE_BYTES))], True
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES)
    except (OSError, TypeError, ValueError) as exc:
        return [], [_problem(file, 0, "FILE-UNREADABLE", "cannot read %s: %s" % (path, exc))], True
    if len(data) >= MAX_FILE_BYTES:
        return [], [_problem(file, 0, "FILE-TOO-LARGE",
                             "file is at least %d bytes; the limit is %d" % (len(data), MAX_FILE_BYTES))], True
    if not data:
        return [], [_problem(file, 0, "FILE-EMPTY", "file is empty: no header")], True
    if data.startswith(_BOM):
        data = data[len(_BOM):]
    raw = data.split(b"\n")
    if data.endswith(b"\n"):
        raw.pop()
    lines = []
    for index, chunk in enumerate(raw):
        lineno = index + 1
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if len(chunk) >= MAX_LINE_BYTES:
            problems.append(_problem(file, lineno, "LINE-TOO-LONG",
                                     "line is %d bytes; the limit is %d" % (len(chunk), MAX_LINE_BYTES)))
            lines.append((lineno, None))
            continue
        try:
            text = chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            problems.append(_problem(file, lineno, "BAD-ENCODING",
                                     "line is not UTF-8 (byte %d: %s)" % (exc.start, exc.reason)))
            lines.append((lineno, None))
            continue
        lines.append((lineno, text))
    return lines, problems, False


def _split(text, lineno, file, expected):
    """CSV-split one line. Returns (fields, problem)."""
    try:
        fields = next(csv.reader([text], strict=True))
    except csv.Error as exc:
        return None, _problem(file, lineno, "BAD-CSV", "malformed CSV: %s" % exc)
    if len(fields) != expected:
        return None, _problem(file, lineno, "COLUMN-COUNT",
                              "expected %d columns, got %d" % (expected, len(fields)))
    return fields, None


def _load(path, header, expected, parse_row):
    file = os.path.basename(os.fspath(path)) if path is not None else "?"
    rows = []
    try:
        lines, problems, fatal = _read_lines(path, file)
        if fatal:
            return Loaded(tuple(rows), problems)
        head_no, head = lines[0]
        if head is None:
            problems.append(_problem(file, head_no, "BAD-HEADER", "header line could not be read"))
            return Loaded(tuple(rows), problems)
        if head != header:
            problems.append(_problem(file, head_no, "BAD-HEADER",
                                     "header must be exactly '%s', got '%s'" % (header, head)))
            return Loaded(tuple(rows), problems)
        seen = {}
        for lineno, text in lines[1:]:
            if text is None:
                continue
            if text == "":
                problems.append(_problem(file, lineno, "EMPTY-LINE", "empty line"))
                continue
            fields, problem = _split(text, lineno, file, expected)
            if problem is not None:
                problems.append(problem)
                continue
            key = tuple(fields)
            first = seen.get(key)
            if first is None:
                seen[key] = lineno
            else:
                problems.append(_problem(file, lineno, "DUP-ROW",
                                         "exact duplicate of line %d" % first, WARN, dup_of=first))
            row, row_problems = parse_row(fields, lineno, file)
            problems.extend(row_problems)
            if row is not None:
                rows.append(row)
    except Exception as exc:  # the contract is "never raises"
        problems.append(_problem(file, 0, "INTERNAL", "loader failed: %s: %s" % (type(exc).__name__, exc)))
    return Loaded(tuple(rows), problems)


def _ledger_parser(accounts, categories):
    accounts = _declared(accounts)
    categories = _declared(categories)

    def parse(fields, lineno, file):
        d_text, a_text, cur, account, category, tags_text, note = fields
        problems = []
        extra = {}
        date = _parse_date(d_text)
        if date is None:
            problems.append(_problem(file, lineno, "BAD-DATE", "date '%s' is not YYYY-MM-DD" % d_text))
        else:
            extra["date"] = date.isoformat()
        amount = _parse_amount(a_text)
        if amount is None:
            problems.append(_problem(file, lineno, "BAD-AMOUNT",
                                     "amount '%s' is not decimal text" % a_text, **extra))
        if not _CURRENCY_RE.match(cur):
            problems.append(_problem(file, lineno, "BAD-CURRENCY",
                                     "currency '%s' is not a 3-letter ISO-4217 code" % cur, **extra))
        if account not in accounts:
            problems.append(_problem(file, lineno, "UNKNOWN-ACCOUNT",
                                     "account '%s' is not declared" % account, **extra))
        if category not in categories:
            problems.append(_problem(file, lineno, "UNKNOWN-CATEGORY",
                                     "category '%s' is not declared" % category, **extra))
        tags = _parse_tags(tags_text)
        if tags is None:
            problems.append(_problem(file, lineno, "BAD-TAGS",
                                     "tags '%s' must be ';'-separated non-empty tokens" % tags_text, **extra))
        if problems:
            return None, problems
        return LedgerRow(date, amount, cur, account, category, tags, note, lineno, file), []

    return parse


def _holdings_parser(accounts, classes):
    accounts = _declared(accounts)
    classes = _declared(classes)

    def parse(fields, lineno, file):
        d_text, account, asset, cls, q_text, v_text, cur = fields
        problems = []
        extra = {}
        date = _parse_date(d_text)
        if date is None:
            problems.append(_problem(file, lineno, "BAD-DATE", "date '%s' is not YYYY-MM-DD" % d_text))
        else:
            extra["date"] = date.isoformat()
        if account not in accounts:
            problems.append(_problem(file, lineno, "UNKNOWN-ACCOUNT",
                                     "account '%s' is not declared" % account, **extra))
        if asset == "":
            problems.append(_problem(file, lineno, "BAD-ASSET", "asset name is empty", **extra))
        if cls not in classes:
            problems.append(_problem(file, lineno, "UNKNOWN-CLASS",
                                     "class '%s' is not declared" % cls, **extra))
        quantity = _parse_amount(q_text)
        if quantity is None:
            problems.append(_problem(file, lineno, "BAD-QUANTITY",
                                     "quantity '%s' is not decimal text" % q_text, **extra))
        value = _parse_amount(v_text)
        if value is None:
            problems.append(_problem(file, lineno, "BAD-VALUE",
                                     "value '%s' is not decimal text" % v_text, **extra))
        if not _CURRENCY_RE.match(cur):
            problems.append(_problem(file, lineno, "BAD-CURRENCY",
                                     "currency '%s' is not a 3-letter ISO-4217 code" % cur, **extra))
        if problems:
            return None, problems
        return HoldingRow(date, account, asset, cls, quantity, value, cur, lineno, file), []

    return parse


def load_ledger(path, accounts, categories):
    """Read ledger.csv. Returns Loaded(rows, problems); never raises.

    ``accounts`` is an iterable of declared account names; ``categories`` is
    either an iterable of category names or the policies.yml mapping of
    group -> names (both are accepted, the mapping is flattened).
    """
    return _load(path, LEDGER_HEADER, 7, _ledger_parser(accounts, categories))


def load_holdings(path, accounts, classes):
    """Read holdings.csv. Returns Loaded(rows, problems); never raises."""
    return _load(path, HOLDINGS_HEADER, 7, _holdings_parser(accounts, classes))


def snapshot_dates(rows):
    """Sorted unique snapshot dates among holdings rows."""
    return tuple(sorted(set(r.date for r in rows)))


def latest_snapshot(rows, as_of):
    """Rows of the latest snapshot date <= as_of, and that date.

    Returns Snapshot(rows, date); Snapshot((), None) when no snapshot is on
    or before as_of. Rows keep their file order.
    """
    best = None
    for r in rows:
        if r.date <= as_of and (best is None or r.date > best):
            best = r.date
    if best is None:
        return Snapshot((), None)
    return Snapshot(tuple(r for r in rows if r.date == best), best)
