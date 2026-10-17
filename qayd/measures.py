"""Measures and limits in base currency, with citations (ADR-0001 section 5).

``evaluate(measure, ctx, period)`` returns one of
  Value(amount, rows, detail)  the measure, the rows it rests on (ledger,
                               holdings and rate rows), extra detail
  Unknown(reason, cites)       cannot be known from the declared files
  Stale(age_days, date, amount, rows)  a holdings snapshot older than
                               snapshot_max_age_days allows
``limit_value(limit, ctx, period)`` returns Value or Unknown the same way.

Rules that hold everywhere here:
- Money is Decimal; a foreign-currency row is converted with the rates
  table at the row's date and the rate row is cited; no rate -> Unknown.
- An Unknown anywhere makes the whole measure Unknown; never a partial sum.
- Rows tagged ``transfer`` never count as income or expense.
- Nothing after ``ctx.as_of`` is seen: every period is cut at as_of.
- An invalid ledger or holdings row (a loader problem of class invalid)
  dated inside the period, or without a date, makes the measure Unknown
  (ADR section 3: every policy touching that row's period is unknown).
- Expense sums are reported positive; income and other groups as recorded.
"""

import datetime
from decimal import Decimal
from typing import NamedTuple, Optional

from . import periods
from .ledger import latest_snapshot
from .rates import Unknown  # noqa: F401  (re-exported)

TRANSFER_TAG = "transfer"
DEBT_CLASS = "debt"
HUNDRED = Decimal(100)
ZERO = Decimal(0)


class Value(NamedTuple):
    amount: Decimal
    rows: tuple = ()
    detail: tuple = ()

    @property
    def cites(self):
        return _cites(self.rows)


class Stale(NamedTuple):
    age_days: int
    date: object                    # datetime.date of the snapshot
    amount: Optional[Decimal]       # the value the stale snapshot gives, if computable
    rows: tuple = ()

    @property
    def cites(self):
        return _cites(self.rows)


class Context(NamedTuple):
    config: object                  # policies.Config
    ledger: tuple = ()              # ledger.LedgerRow
    holdings: tuple = ()            # ledger.HoldingRow
    rates: object = None            # rates.Table
    as_of: object = None            # datetime.date; None = no cut
    ledger_problems: tuple = ()
    holdings_problems: tuple = ()


def _cites(rows):
    return tuple(dict.fromkeys(r.cite for r in rows))


def end_of(ctx, period):
    """The last date the measure may see: the period end, cut at as_of."""
    if ctx.as_of is None or ctx.as_of >= period.end:
        return period.end
    return ctx.as_of


def rows_in(ctx, period):
    """Valid ledger rows dated inside the period (cut at as_of), file order."""
    end = end_of(ctx, period)
    return tuple(r for r in ctx.ledger if period.start <= r.date <= end)


def invalid_in(problems, start, end):
    """Loader problems of class invalid dated in [start, end] or undated."""
    hits = []
    for p in problems or ():
        if p.get("class") != "invalid":
            continue
        text = p.get("date")
        if text is None:
            hits.append(p)
            continue
        d = datetime.date.fromisoformat(text)
        if start <= d <= end:
            hits.append(p)
    return hits


def _poisoned(problems, start, end, what):
    hits = invalid_in(problems, start, end)
    if not hits:
        return None
    first = hits[0]
    where = "%s:%d" % (first["file"], first["line"])
    return Unknown("invalid %s row %s (%s) touches %s..%s" % (
        what, where, first["code"], start.isoformat(), end.isoformat()),
        tuple("%s:%d" % (p["file"], p["line"]) for p in hits))


def _convert(ctx, amount, currency, date, row):
    conv = ctx.rates.convert(amount, currency, date) if ctx.rates is not None else None
    if conv is None:
        if currency == ctx.config.base_currency:
            return amount, None
        return Unknown("no rates table; cannot convert %s at %s" % (currency, row.cite), (row.cite,))
    if isinstance(conv, Unknown):
        return Unknown("%s at %s" % (conv.reason, row.cite), (row.cite,) + tuple(conv.cites))
    return conv.amount, conv.rate


def _sum_rows(ctx, rows):
    """Sum of rows converted to base; returns (total, cited rows) or Unknown."""
    total = ZERO
    cited = list(rows)
    for row in rows:
        amount = row.amount if hasattr(row, "amount") else row.value
        out = _convert(ctx, amount, row.currency, row.date, row)
        if isinstance(out, Unknown):
            return out
        converted, rate_row = out
        total += converted
        if rate_row is not None:
            cited.append(rate_row)
    return total, tuple(cited)


# ------------------------------------------------------------------------ sums


def _group_rows(ctx, group, category, period):
    end = end_of(ctx, period)
    names = ctx.config.categories.get(group, ())
    out = []
    for r in ctx.ledger:
        if not (period.start <= r.date <= end):
            continue
        if category is not None:
            if r.category != category:
                continue
        elif r.category not in names:
            continue
        if group in ("income", "expense") and TRANSFER_TAG in r.tags:
            continue
        out.append(r)
    return tuple(out)


def _sum(ctx, group, category, period):
    end = end_of(ctx, period)
    bad = _poisoned(ctx.ledger_problems, period.start, end, "ledger")
    if bad is not None:
        return bad
    rows = _group_rows(ctx, group, category, period)
    out = _sum_rows(ctx, rows)
    if isinstance(out, Unknown):
        return out
    total, cited = out
    if group == "expense":
        total = -total
    return Value(total, cited)


def income(ctx, period):
    """Sum of the income group over the period, transfers excluded."""
    return _sum(ctx, "income", None, period)


def expense(ctx, period):
    """Sum of the expense group over the period, as a positive number."""
    return _sum(ctx, "expense", None, period)


# -------------------------------------------------------------------- holdings


def _snapshot(ctx, date):
    """(snapshot rows, snapshot date) as of date, or Unknown / Stale."""
    snap = latest_snapshot(ctx.holdings, date)
    if snap.date is None:
        bad = _poisoned(ctx.holdings_problems, datetime.date.min, date, "holdings")
        if bad is not None:
            return bad
        return Unknown("no holdings snapshot on or before %s" % date.isoformat())
    bad = _poisoned(ctx.holdings_problems, snap.date, date, "holdings")
    if bad is not None:
        return bad
    return snap


def _stale(ctx, snap_date, as_of_date, amount, rows):
    max_age = ctx.config.snapshot_max_age_days
    if max_age is None:
        return Unknown("snapshot_max_age_days is not declared")
    age = (as_of_date - snap_date).days
    if age > max_age:
        return Stale(age, snap_date, amount, rows)
    return None


def _select(rows, by, name):
    if by == "class":
        return tuple(r for r in rows if r.asset_class == name)
    return tuple(r for r in rows if r.account == name)


def holdings(ctx, by, name, period):
    """Value of class.<name> or account.<name> as of the period end."""
    date = end_of(ctx, period)
    snap = _snapshot(ctx, date)
    if isinstance(snap, Unknown):
        return snap
    out = _sum_rows(ctx, _select(snap.rows, by, name))
    if isinstance(out, Unknown):
        return out
    total, cited = out
    stale = _stale(ctx, snap.date, date, total, cited)
    if stale is not None:
        return stale
    return Value(total, cited)


def share(ctx, name, period):
    """Value of class.<name> over total holdings (debt excluded), in percent."""
    date = end_of(ctx, period)
    snap = _snapshot(ctx, date)
    if isinstance(snap, Unknown):
        return snap
    part = _sum_rows(ctx, _select(snap.rows, "class", name))
    if isinstance(part, Unknown):
        return part
    whole = _sum_rows(ctx, tuple(r for r in snap.rows if r.asset_class != DEBT_CLASS))
    if isinstance(whole, Unknown):
        return whole
    part_total, part_rows = part
    whole_total, whole_rows = whole
    cited = tuple(dict.fromkeys(part_rows + whole_rows))
    if whole_total == 0:
        bad = Unknown("total holdings (debt excluded) is zero on %s" % snap.date.isoformat(),
                      _cites(cited))
        stale = _stale(ctx, snap.date, date, None, cited)
        return stale if stale is not None else bad
    pct = part_total / whole_total * HUNDRED
    stale = _stale(ctx, snap.date, date, pct, cited)
    if stale is not None:
        return stale
    return Value(pct, cited)


def drawdown(ctx, name, window_days, period):
    """Peak-to-latest drawdown of account.<name> over the last window_days,
    in percent. detail: one (date, value, drawdown_pct) per snapshot date in
    the window, with the running peak, so a crossing date can be found."""
    date = end_of(ctx, period)
    snap = _snapshot(ctx, date)
    if isinstance(snap, Unknown):
        return snap
    start = date - datetime.timedelta(days=window_days - 1)
    bad = _poisoned(ctx.holdings_problems, start, date, "holdings")
    if bad is not None:
        return bad
    stale = _stale(ctx, snap.date, date, None, ())
    if stale is not None:
        return stale
    dates = sorted(set(r.date for r in ctx.holdings if start <= r.date <= date))
    if not dates:
        return Unknown("no holdings snapshot within %d days of %s (latest is %s)"
                       % (window_days, date.isoformat(), snap.date.isoformat()))
    series = []
    cited = []
    peak = None
    for d in dates:
        rows = tuple(r for r in ctx.holdings if r.date == d and r.account == name)
        out = _sum_rows(ctx, rows)
        if isinstance(out, Unknown):
            return out
        value, rows_cited = out
        cited.extend(rows_cited)
        if peak is None or value > peak:
            peak = value
        if peak > 0:
            dd = (peak - value) / peak * HUNDRED
        else:
            dd = None
        series.append((d, value, dd))
    if peak is None or peak <= 0:
        return Unknown("peak value of account.%s in the window is not positive (%s)" % (name, peak),
                       _cites(cited))
    last = series[-1][2]
    if last is None:
        return Unknown("drawdown of account.%s is undefined before the first positive value" % name,
                       _cites(cited))
    return Value(last, tuple(dict.fromkeys(cited)), tuple(series))


# --------------------------------------------------------------------- entry


def evaluate(measure, ctx, period):
    """Evaluate a normalized measure (policies.Policy.measure)."""
    if not isinstance(measure, dict) or "kind" not in measure:
        return Unknown("measure is not declared")
    kind = measure["kind"]
    if kind == "sum":
        return _sum(ctx, measure["group"], measure["category"], period)
    if kind == "holdings":
        return holdings(ctx, measure["by"], measure["name"], period)
    if kind == "share":
        return share(ctx, measure["name"], period)
    if kind == "drawdown":
        return drawdown(ctx, measure["name"], measure["window_days"], period)
    return Unknown("measure kind %r is not declared" % (kind,))


def limit_value(limit, ctx, period):
    """Evaluate a normalized limit (policies.Policy.limit) -> Value or Unknown."""
    if not isinstance(limit, dict) or "kind" not in limit:
        return Unknown("limit is not declared")
    kind = limit["kind"]
    if kind == "value":
        return Value(limit["value"])
    if kind == "pct":
        return Value(limit["value"])
    if kind == "pct_of":
        base = income(ctx, period)
        if isinstance(base, Unknown):
            return base
        return Value(base.amount * limit["value"] / HUNDRED, base.rows)
    if kind == "months_of":
        avg = average_monthly_expense(ctx, period)
        if isinstance(avg, Unknown):
            return avg
        return Value(avg.amount * limit["value"], avg.rows, avg.detail)
    return Unknown("limit kind %r is not declared" % (kind,))


def average_monthly_expense(ctx, period, months=12):
    """Average expense per complete month over the trailing ``months`` months
    ending at the period end (cut at as_of). Only complete months count, and
    among them only those with at least one ledger row; fewer months than
    asked -> the months available. detail: the month labels used."""
    end = end_of(ctx, period)
    window = periods.trailing(end, months)
    complete = [m for m in window.months() if m.end <= end]
    used = []
    total = ZERO
    cited = []
    for m in complete:
        bad = _poisoned(ctx.ledger_problems, m.start, m.end, "ledger")
        if bad is not None:
            return bad
        if not rows_in(ctx, m):
            continue
        out = expense(ctx, m)
        if isinstance(out, Unknown):
            return out
        total += out.amount
        cited.extend(out.rows)
        used.append(m.label)
    if not used:
        return Unknown("no complete month with ledger rows in %s" % window.label)
    return Value(total / Decimal(len(used)), tuple(dict.fromkeys(cited)), tuple(used))
