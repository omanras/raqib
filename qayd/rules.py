"""Verdicts (ADR-0001 section 6). Deterministic, cited, never advising.

``verdict(policy, ctx, as_of)`` -> Verdict for one policy:
  cap         measure <= limit -> hold, else breach
  floor       measure >= limit -> hold, else breach
  allocation  band.min_pct <= share <= band.max_pct -> hold, else breach
  red_line    no matching row ever (up to as_of) -> hold; else breach,
              citing every matching row
  routine     a matching row in the current period -> hold; else missing
  kill        drawdown crossed the threshold on any snapshot date (rolling
              window) -> kill, and it stays kill until a decision with
              closes=<id> is dated after the crossing (then hold, with the
              closing noted)
Other verdicts: stale (holdings snapshot older than allowed), unknown
(undeclared shape, missing rate, no data), invalid (an invalid row touches
the period), missing (routine without its row, or a ledger-based policy
whose period has no ledger rows at all).

Findings (A3, A4): BREACH, KILL, ROUTINE-MISSING, EMPTY-PERIOD,
STALE-SNAPSHOT, UNKNOWN, INVALID, each naming the policy and citing rows
(or the period or date for the silence findings). ``check`` adds loader
problems as findings (class red for invalid rows, warn for DUP-ROW).
Green = every policy hold and no red finding.
"""

import datetime
from decimal import Decimal
from typing import NamedTuple, Optional

from . import measures, periods
from .ledger import latest_snapshot
from .measures import Stale, Unknown, Value
from .policies import band_text, match_text, measure_text

RED_VERDICTS = ("breach", "kill", "missing", "stale", "invalid", "unknown")
TRANSFER_TAG = measures.TRANSFER_TAG


class Finding(NamedTuple):
    code: str
    cls: str                    # "red" | "warn"
    policy: Optional[str]
    period: Optional[str]       # period label when the finding is about a period
    date: Optional[str]         # ISO date when the finding is about a date
    cites: tuple                # file:line
    reason: str


class Verdict(NamedTuple):
    policy: object              # policies.Policy
    verdict: str
    period: Optional[object]    # periods.Period, None for a red line ("ever")
    measure: object             # Value | Unknown | Stale | None
    limit: object               # Value | Unknown | None
    rows: tuple                 # rows the verdict rests on
    reason: Optional[str]
    findings: tuple

    @property
    def id(self):
        return self.policy.id

    @property
    def red(self):
        return self.verdict != "hold"

    @property
    def cites(self):
        return tuple(dict.fromkeys(r.cite for r in self.rows))


# ------------------------------------------------------------------- matching


def _amount_in_base(ctx, row):
    conv = ctx.rates.convert(row.amount, row.currency, row.date) if ctx.rates is not None else None
    if conv is None:
        return row.amount if row.currency == ctx.config.base_currency else None
    if isinstance(conv, Unknown):
        return None
    return conv.amount


def match_rows(match, rows, ctx):
    """Rows matching a normalized match spec. Returns (matched, undecided):
    undecided rows match every criterion except min_amount, whose foreign
    currency has no rate (A5: never a guess)."""
    matched = []
    undecided = []
    for r in rows:
        if "tags" in match and not all(t in r.tags for t in match["tags"]):
            continue
        if "tags_any" in match and not any(t in r.tags for t in match["tags_any"]):
            continue
        if "account" in match and r.account != match["account"]:
            continue
        if "category" in match and r.category != match["category"]:
            continue
        if "min_amount" in match:
            amount = _amount_in_base(ctx, r)
            if amount is None:
                undecided.append(r)
                continue
            if abs(amount) < match["min_amount"]:
                continue
        matched.append(r)
    return tuple(matched), tuple(undecided)


# -------------------------------------------------------------------- helpers


def _finding(code, policy, reason, cites=(), period=None, date=None, cls="red"):
    return Finding(code, cls, policy.id, period, date, tuple(cites), reason)


def _period_for(policy, as_of):
    measure = policy.measure
    if measure is not None and measure.get("kind") == "sum":
        return periods.period_of(as_of, measure["period"])
    if policy.period is not None:
        return periods.period_of(as_of, policy.period)
    return periods.period_of(as_of, "month")


def _ledger_based(policy):
    return policy.measure is not None and policy.measure.get("kind") == "sum"


def _unknown_verdict(policy, period, value, limit, reason_prefix):
    reason = "%s: %s" % (reason_prefix, value.reason)
    kind = "invalid" if value.cause == "invalid" else "unknown"
    f = _finding(kind.upper(), policy, reason, value.cites,
                 period=period.label if period is not None else None)
    return Verdict(policy, kind, period, value, limit, (), reason, (f,))


def _declared_unknown(policy, as_of):
    period = _period_for(policy, as_of)
    reason = "policy is not declared: %s" % policy.reason
    f = _finding("UNKNOWN", policy, reason, (policy.cite,), period=period.label)
    return Verdict(policy, "unknown", period, None, None, (), reason, (f,))


def _empty_period(policy, period):
    reason = "no ledger rows in %s" % period.label
    f = _finding("EMPTY-PERIOD", policy, reason, (), period=period.label)
    return Verdict(policy, "missing", period, None, None, (), reason, (f,))


def _stale_verdict(policy, period, stale, limit, max_age):
    reason = "holdings snapshot %s is %d days old; %d allowed" % (
        stale.date.isoformat(), stale.age_days, max_age)
    f = _finding("STALE-SNAPSHOT", policy, reason, stale.cites, date=stale.date.isoformat())
    return Verdict(policy, "stale", period, stale, limit, stale.rows, reason, (f,))


def _compare(policy, period, value, limit, ok, breach_text):
    if ok:
        return Verdict(policy, "hold", period, value, limit, value.rows + limit.rows, None, ())
    f = _finding("BREACH", policy, breach_text, value.cites + limit.cites, period=period.label)
    return Verdict(policy, "breach", period, value, limit, value.rows + limit.rows, breach_text, (f,))


# ---------------------------------------------------------------- rule types


def _cap_floor_allocation(policy, ctx, as_of):
    period = _period_for(policy, as_of)
    if _ledger_based(policy) and not measures.rows_in(ctx, period):
        return _empty_period(policy, period)
    value = measures.evaluate(policy.measure, ctx, period)
    if policy.type == "allocation":
        limit = None
    else:
        limit = measures.limit_value(policy.limit, ctx, period)
        if isinstance(limit, Unknown):
            return _unknown_verdict(policy, period, limit, None, "limit")
    if isinstance(value, Unknown):
        return _unknown_verdict(policy, period, value, limit, "measure")
    if isinstance(value, Stale):
        return _stale_verdict(policy, period, value, limit, ctx.config.snapshot_max_age_days)
    base = ctx.config.base_currency
    if policy.type == "cap":
        return _compare(policy, period, value, limit, value.amount <= limit.amount,
                        "%s = %s exceeds %s" % (measure_text(policy.measure), money(value.amount, base),
                                                money(limit.amount, base)))
    if policy.type == "floor":
        return _compare(policy, period, value, limit, value.amount >= limit.amount,
                        "%s = %s is below %s" % (measure_text(policy.measure), money(value.amount, base),
                                                 money(limit.amount, base)))
    band = policy.band
    ok = band["min_pct"] <= value.amount <= band["max_pct"]
    limit = Value(band["min_pct"], ())      # for the record: the band is the limit
    if ok:
        return Verdict(policy, "hold", period, value, limit, value.rows, None, ())
    text = "%s = %s is outside %s" % (measure_text(policy.measure), pct(value.amount), band_text(band))
    f = _finding("BREACH", policy, text, value.cites, period=period.label)
    return Verdict(policy, "breach", period, value, limit, value.rows, text, (f,))


def _red_line(policy, ctx, as_of):
    rows = tuple(r for r in ctx.ledger if r.date <= as_of)
    matched, undecided = match_rows(policy.match, rows, ctx)
    value = Value(len(matched), matched)
    if matched:
        text = "%d matching row%s (%s)" % (len(matched), "" if len(matched) == 1 else "s", match_text(policy.match))
        f = _finding("BREACH", policy, text, value.cites)
        return Verdict(policy, "breach", None, value, None, matched, text, (f,))
    bad = measures.invalid_in(ctx.ledger_problems, datetime.date.min, as_of)
    if bad:
        u = Unknown("invalid ledger row %s:%d (%s) may match" % (bad[0]["file"], bad[0]["line"], bad[0]["code"]),
                    tuple("%s:%d" % (p["file"], p["line"]) for p in bad), "invalid")
        return _unknown_verdict(policy, None, u, None, "red line")
    if undecided:
        u = Unknown("%d row%s cannot be converted for min_amount" % (
            len(undecided), "" if len(undecided) == 1 else "s"), tuple(r.cite for r in undecided))
        return _unknown_verdict(policy, None, u, None, "red line")
    return Verdict(policy, "hold", None, value, None, (), None, ())


def _routine(policy, ctx, as_of):
    period = periods.period_of(as_of, policy.period)
    rows = measures.rows_in(ctx, period)
    if not rows and not measures.invalid_in(ctx.ledger_problems, period.start, measures.end_of(ctx, period)):
        return _empty_period(policy, period)
    matched, undecided = match_rows(policy.match, rows, ctx)
    value = Value(len(matched), matched)
    if matched:
        return Verdict(policy, "hold", period, value, None, matched, None, ())
    bad = measures.invalid_in(ctx.ledger_problems, period.start, measures.end_of(ctx, period))
    if bad:
        u = Unknown("invalid ledger row %s:%d (%s) may be the routine row" % (
            bad[0]["file"], bad[0]["line"], bad[0]["code"]),
            tuple("%s:%d" % (p["file"], p["line"]) for p in bad), "invalid")
        return _unknown_verdict(policy, period, u, None, "routine")
    if undecided:
        u = Unknown("%d row%s cannot be converted for min_amount" % (
            len(undecided), "" if len(undecided) == 1 else "s"), tuple(r.cite for r in undecided))
        return _unknown_verdict(policy, period, u, None, "routine")
    text = "no row matching %s in %s" % (match_text(policy.match), period.label)
    f = _finding("ROUTINE-MISSING", policy, text, (), period=period.label)
    return Verdict(policy, "missing", period, value, None, (), text, (f,))


def _kill(policy, ctx, as_of):
    period = periods.period_of(as_of, "month")
    name = policy.measure["name"]
    window = policy.measure["window_days"]
    threshold = policy.limit["value"]
    limit = Value(threshold)
    snap = latest_snapshot(ctx.holdings, as_of)
    history = measures.drawdown_history(ctx, name, window, as_of)
    if isinstance(history, Unknown):
        return _unknown_verdict(policy, period, history, limit, "drawdown history")
    crossings = [p for p in history if p.drawdown is not None and p.drawdown >= threshold]
    last = history[-1]
    value = Value(last.drawdown, last.rows, history) if last.drawdown is not None else None
    if crossings:
        c = crossings[-1]
        closers = [d for d in ctx.decisions
                   if d.closes == policy.id and c.date < d.date <= as_of]
        if not closers:
            text = "drawdown %s on %s crossed %s (peak %s on %s)" % (
                pct(c.drawdown), c.date.isoformat(), pct(threshold), money(c.peak, ctx.config.base_currency),
                c.peak_date.isoformat())
            f = _finding("KILL", policy, text, tuple(r.cite for r in c.rows), date=c.date.isoformat())
            return Verdict(policy, "kill", period, value, limit, c.rows, text, (f,))
        closer = sorted(closers, key=lambda d: (d.date, d.line))[0]
        note = "kill of %s closed by %s (%s)" % (c.date.isoformat(), closer.id, closer.date.isoformat())
    else:
        note = None
    max_age = ctx.config.snapshot_max_age_days
    if max_age is None:
        u = Unknown("snapshot_max_age_days is not declared")
        return _unknown_verdict(policy, period, u, limit, "drawdown")
    age = (as_of - snap.date).days
    if age > max_age:
        stale = Stale(age, snap.date, last.drawdown, last.rows)
        v = _stale_verdict(policy, period, stale, limit, max_age)
        return v._replace(reason=(v.reason + "; " + note) if note else v.reason)
    if value is None:
        u = Unknown("peak value of account.%s is not positive" % name, tuple(r.cite for r in last.rows))
        return _unknown_verdict(policy, period, u, limit, "drawdown")
    return Verdict(policy, "hold", period, value, limit, last.rows, note, ())


def verdict(policy, ctx, as_of):
    """The verdict of one policy as of a date. Never raises for a declared
    policy shape; an undeclared policy is unknown."""
    if ctx.as_of != as_of:
        ctx = ctx._replace(as_of=as_of)
    if policy.status != "ok":
        return _declared_unknown(policy, as_of)
    if policy.type in ("cap", "floor", "allocation"):
        return _cap_floor_allocation(policy, ctx, as_of)
    if policy.type == "red_line":
        return _red_line(policy, ctx, as_of)
    if policy.type == "routine":
        return _routine(policy, ctx, as_of)
    if policy.type == "kill":
        return _kill(policy, ctx, as_of)
    return _declared_unknown(policy._replace(reason="type %r is not declared" % policy.type), as_of)


def check(ctx, as_of):
    """Verdicts for every policy, in file order, plus loader findings."""
    verdicts = tuple(verdict(p, ctx, as_of) for p in ctx.config.policies)
    findings = []
    for v in verdicts:
        findings.extend(v.findings)
    findings.extend(problem_findings(ctx.ledger_problems))
    findings.extend(problem_findings(ctx.holdings_problems))
    return verdicts, tuple(findings)


def decision_findings(decisions, as_of):
    """DECISION-DUE for every open decision whose review_by < as_of (ADR 7)."""
    out = []
    for d in decisions or ():
        if d.is_due(as_of):
            days = -d.days_until_review(as_of)
            reason = "decision %s is open and its review date %s is %d day%s past" % (
                d.id, d.review_by.isoformat(), days, "" if days == 1 else "s")
            out.append(Finding("DECISION-DUE", "red", d.policy, None, d.review_by.isoformat(),
                               (d.cite,), reason))
    return tuple(out)


class RoutineItem(NamedTuple):
    """One routine policy in one period: done | missing | unknown | invalid."""
    policy: object
    period: object
    status: str
    verdict: object            # the Verdict behind it

    @property
    def id(self):
        return self.policy.id

    @property
    def done(self):
        return self.status == "done"


def routine_periods(policy, period):
    """The periods of the policy's kind to look at for a requested period:
    the sub-periods inside it when the policy's kind is finer (a monthly
    routine over a quarter: three months), else the one period of the
    policy's kind that contains the requested period's end."""
    inside = periods.periods_between(period.start, period.end, policy.period)
    if inside and inside[0].start >= period.start and inside[-1].end <= period.end:
        return inside
    return (periods.period_of(period.end, policy.period),)


def routine(ctx, period, as_of):
    """Every routine policy over the requested period, cut at as_of."""
    items = []
    for policy in ctx.config.policies:
        if policy.type != "routine":
            continue
        if policy.status != "ok":
            v = verdict(policy, ctx, as_of)
            items.append(RoutineItem(policy, None, "unknown", v))
            continue
        for sub in routine_periods(policy, period):
            cut = sub.end if as_of is None or as_of >= sub.end else as_of
            if cut < sub.start:
                v = _empty_period(policy, sub)
                v = v._replace(reason="period %s starts after %s" % (sub.label, as_of.isoformat()))
                items.append(RoutineItem(policy, sub, "missing", v))
                continue
            v = verdict(policy, ctx, cut)
            status = {"hold": "done", "missing": "missing"}.get(v.verdict, v.verdict)
            items.append(RoutineItem(policy, sub, status, v))
    return tuple(items)


def problem_findings(problems):
    """Loader problems as findings: invalid rows red, DUP-ROW warn."""
    out = []
    for p in problems or ():
        cls = "warn" if p.get("class") == "warn" else "red"
        out.append(Finding(p["code"], cls, None, None, p.get("date"),
                           ("%s:%d" % (p["file"], p["line"]),), p["reason"]))
    return tuple(out)


def is_green(verdicts, findings):
    return all(v.verdict == "hold" for v in verdicts) and not any(f.cls == "red" for f in findings)


def order(verdicts):
    """Reds first (file order), then holds (file order)."""
    return tuple(v for v in verdicts if v.red) + tuple(v for v in verdicts if not v.red)


# ------------------------------------------------------------------ formatting


def money(amount, currency=""):
    """Exact decimal text without trailing zeros, with the currency."""
    text = format(amount, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text == "-0":
        text = "0"
    return (text + " " + currency).strip()


def pct(amount):
    """A percentage for display: two decimals (display only, A5 untouched)."""
    q = amount.quantize(Decimal("0.01"))
    text = format(q, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text + "%"
