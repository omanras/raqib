"""Period math (ADR-0001 section 5: periods are month, quarter, year, ISO
calendar). Pure functions over datetime.date; no I/O, no state.

A Period is (start, end), both inclusive. ``kind`` and ``label`` are
derived from the bounds: a calendar month is ``month`` / ``2026-10``, a
calendar quarter ``quarter`` / ``2026-Q3``, a calendar year ``year`` /
``2026``; anything else (a trailing window) is ``window`` /
``2025-10-01..2026-09-30``.
"""

import datetime
import re
from typing import NamedTuple

KINDS = ("month", "quarter", "year")

_MONTH_RE = re.compile(r"^([0-9]{4})-(0[1-9]|1[0-2])$")
_QUARTER_RE = re.compile(r"^([0-9]{4})-Q([1-4])$")
_YEAR_RE = re.compile(r"^([0-9]{4})$")


def last_day(year, month):
    """The last calendar day of year-month."""
    if month == 12:
        return datetime.date(year, 12, 31)
    return datetime.date(year, month + 1, 1) - datetime.timedelta(days=1)


def add_months(d, n):
    """d shifted by n calendar months; the day is clamped to the month's end."""
    index = d.year * 12 + (d.month - 1) + n
    year, month = divmod(index, 12)
    month += 1
    day = min(d.day, last_day(year, month).day)
    return datetime.date(year, month, day)


class Period(NamedTuple):
    start: datetime.date
    end: datetime.date

    @property
    def kind(self):
        s, e = self.start, self.end
        if s.day != 1 or e != last_day(e.year, e.month):
            return "window"
        if s.year == e.year and s.month == e.month:
            return "month"
        if s.month in (1, 4, 7, 10) and e.year == s.year and e.month == s.month + 2:
            return "quarter"
        if s.month == 1 and e.year == s.year and e.month == 12:
            return "year"
        return "window"

    @property
    def label(self):
        kind = self.kind
        if kind == "month":
            return "%04d-%02d" % (self.start.year, self.start.month)
        if kind == "quarter":
            return "%04d-Q%d" % (self.start.year, (self.start.month - 1) // 3 + 1)
        if kind == "year":
            return "%04d" % self.start.year
        return "%s..%s" % (self.start.isoformat(), self.end.isoformat())

    @property
    def days(self):
        return (self.end - self.start).days + 1

    def contains(self, d):
        return self.start <= d <= self.end

    def months(self):
        """The calendar months (as month Periods) that overlap this period."""
        out = []
        cursor = datetime.date(self.start.year, self.start.month, 1)
        while cursor <= self.end:
            out.append(period_of(cursor, "month"))
            cursor = add_months(cursor, 1)
        return tuple(out)


def period_of(d, kind):
    """The calendar period of ``kind`` that contains date d."""
    if kind == "month":
        return Period(datetime.date(d.year, d.month, 1), last_day(d.year, d.month))
    if kind == "quarter":
        first = (d.month - 1) // 3 * 3 + 1
        return Period(datetime.date(d.year, first, 1), last_day(d.year, first + 2))
    if kind == "year":
        return Period(datetime.date(d.year, 1, 1), datetime.date(d.year, 12, 31))
    raise ValueError("unknown period kind: %r (expected one of %s)" % (kind, ", ".join(KINDS)))


def parse(text):
    """``2026-10`` -> month, ``2026-Q3`` -> quarter, ``2026`` -> year; else None."""
    if not isinstance(text, str):
        return None
    m = _MONTH_RE.match(text)
    if m:
        return period_of(datetime.date(int(m.group(1)), int(m.group(2)), 1), "month")
    m = _QUARTER_RE.match(text)
    if m:
        return period_of(datetime.date(int(m.group(1)), (int(m.group(2)) - 1) * 3 + 1, 1), "quarter")
    m = _YEAR_RE.match(text)
    if m:
        return period_of(datetime.date(int(m.group(1)), 1, 1), "year")
    return None


def trailing(as_of, months):
    """The trailing window of ``months`` calendar months ending at as_of.

    It starts on the first day of the month ``months - 1`` months before the
    month of as_of and ends on as_of itself (inclusive), so rows after as_of
    are never inside it. trailing(2026-09-30, 12) is 2025-10-01..2026-09-30.
    """
    if not isinstance(months, int) or isinstance(months, bool) or months < 1:
        raise ValueError("months must be a positive int, got %r" % (months,))
    first = add_months(datetime.date(as_of.year, as_of.month, 1), -(months - 1))
    return Period(first, as_of)


def periods_between(first, last, kind):
    """Every calendar period of ``kind`` from the one holding ``first`` to the
    one holding ``last``, in order; empty when first > last."""
    if first > last:
        return ()
    out = []
    current = period_of(first, kind)
    stop = period_of(last, kind)
    while current.start <= stop.start:
        out.append(current)
        current = period_of(current.end + datetime.timedelta(days=1), kind)
    return tuple(out)


def next_period(period):
    """The calendar period of the same kind that follows ``period``."""
    kind = period.kind
    if kind == "window":
        raise ValueError("a window has no next period")
    return period_of(period.end + datetime.timedelta(days=1), kind)


def previous_period(period):
    kind = period.kind
    if kind == "window":
        raise ValueError("a window has no previous period")
    return period_of(period.start - datetime.timedelta(days=1), kind)
