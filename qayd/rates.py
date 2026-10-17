"""rates.csv loader and currency conversion (ADR-0001 A5, section 2).

Header exactly ``date,currency,rate``; ``rate`` is how many base-currency
units one unit of ``currency`` buys on that date (positive decimal text).
``Table.convert(amount, currency, date)`` uses the latest rate on or before
the date and cites the rate row; the base currency needs no row; a missing
rate is ``Unknown`` (A5: without a rate the measure is unknown, never a
guess). Two different rates for the same currency and date are a conflict:
a load problem, and ``Unknown`` for that date.

``Unknown`` is defined here because conversion is the first place it
arises; ``measures`` re-exports it.
"""

import os
import re
from decimal import Decimal
from typing import NamedTuple, Optional

from .ledger import INVALID, _load, _parse_date, _problem

RATES_HEADER = "date,currency,rate"
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_RATE_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")


class Unknown(NamedTuple):
    """A value that cannot be known from the declared files. Red (A5).
    ``cause`` is ``invalid`` when an invalid row (a loader problem) is the
    reason, else ``unknown`` (undeclared measure, missing rate, no data)."""
    reason: str
    cites: tuple = ()
    cause: str = "unknown"


class RateRow(NamedTuple):
    date: object          # datetime.date
    currency: str
    rate: Decimal
    line: int
    file: str

    @property
    def cite(self):
        return "%s:%d" % (self.file, self.line)


class Conversion(NamedTuple):
    amount: Decimal
    rate: Optional[RateRow]   # None when no conversion was needed


class Table(object):
    """Rates by currency, each sorted by date."""

    def __init__(self, rows, base_currency):
        self.base = base_currency
        self.rows = tuple(rows)
        self._by_currency = {}
        for row in self.rows:
            self._by_currency.setdefault(row.currency, []).append(row)
        for rows_ in self._by_currency.values():
            rows_.sort(key=lambda r: (r.date, r.line))

    @property
    def currencies(self):
        return tuple(sorted(self._by_currency))

    def convert(self, amount, currency, date):
        """Decimal amount in ``currency`` on ``date`` -> Conversion or Unknown."""
        if currency == self.base:
            return Conversion(amount, None)
        if self.base is None:
            return Unknown("base currency is not declared; cannot convert %s" % currency)
        candidates = self._by_currency.get(currency)
        if not candidates:
            return Unknown("no rate for %s (no rows for that currency)" % currency)
        latest = None
        for row in candidates:
            if row.date <= date:
                latest = row
            else:
                break
        if latest is None:
            return Unknown("no rate for %s on or before %s (earliest is %s)"
                           % (currency, date.isoformat(), candidates[0].date.isoformat()))
        same_day = [r for r in candidates if r.date == latest.date]
        rates = set(r.rate for r in same_day)
        if len(rates) > 1:
            return Unknown("conflicting rates for %s on %s" % (currency, latest.date.isoformat()),
                           tuple(r.cite for r in same_day))
        return Conversion(amount * latest.rate, latest)


class Loaded(NamedTuple):
    table: Table
    problems: list


def _rates_parser(base_currency):
    def parse(fields, lineno, file):
        d_text, cur, r_text = fields
        problems = []
        extra = {}
        date = _parse_date(d_text)
        if date is None:
            problems.append(_problem(file, lineno, "BAD-DATE", "date '%s' is not YYYY-MM-DD" % d_text))
        else:
            extra["date"] = date.isoformat()
        if not _CURRENCY_RE.match(cur):
            problems.append(_problem(file, lineno, "BAD-CURRENCY",
                                     "currency '%s' is not a 3-letter ISO-4217 code" % cur, **extra))
        elif base_currency is not None and cur == base_currency:
            problems.append(_problem(file, lineno, "BASE-RATE",
                                     "the base currency %s needs no rate" % cur, **extra))
        rate = Decimal(r_text) if _RATE_RE.match(r_text) else None
        if rate is None or rate <= 0:
            problems.append(_problem(file, lineno, "BAD-RATE",
                                     "rate '%s' is not positive decimal text" % r_text, **extra))
        if problems:
            return None, problems
        return RateRow(date, cur, rate, lineno, file), []

    return parse


def load(path, base_currency):
    """Read rates.csv. Returns Loaded(table, problems); never raises."""
    rows, problems = _load(path, RATES_HEADER, 3, _rates_parser(base_currency))
    seen = {}
    for row in rows:
        key = (row.date, row.currency)
        first = seen.get(key)
        if first is None:
            seen[key] = row
        elif first.rate != row.rate:
            problems.append(_problem(row.file, row.line, "CONFLICT-RATE",
                                     "rate for %s on %s differs from line %d" % (
                                         row.currency, row.date.isoformat(), first.line),
                                     INVALID, date=row.date.isoformat()))
    return Loaded(Table(rows, base_currency), problems)


def load_optional(path, base_currency):
    """Like load, but a file that does not exist is an empty table and no
    problem (rates.csv is optional, ADR section 2)."""
    try:
        exists = os.path.exists(path)
    except (TypeError, ValueError):
        exists = True
    if not exists:
        return Loaded(Table((), base_currency), [])
    return load(path, base_currency)


def empty(base_currency):
    return Table((), base_currency)
