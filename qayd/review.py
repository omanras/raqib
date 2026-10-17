"""The review page (ADR-0001 section 9): one self-contained HTML file for
a period. No script, no external resource, no inline event handler; every
colour is a CSS token on :root (light and dark via prefers-color-scheme);
inline SVG drawn here with viewBox, text in currentColor, axis ticks at
real values. float() is used for pixel geometry only; every printed amount
comes from Decimal (A5).

Sections, in order: period header; policy board (the verdict at the end
of every month of the period, the last column being the as-of date);
income vs expense per month (the trailing twelve months, the period's
months marked); spending by category over the period; allocation by class
as of the period end with the band lines of allocation policies; findings
of the period with citations; decisions open and due; details table of
every row a verdict cites.
"""

import html
from decimal import Decimal
from typing import NamedTuple

from . import measures, periods, rules
from .ledger import HoldingRow, LedgerRow
from .measures import Stale, Unknown, Value
from .policies import band_text, limit_text, match_text, measure_text
from .rates import RateRow
from .report import limit_display, measure_display
from .rules import money, pct

SECTIONS = ("period", "board", "income-expense", "spending", "allocation",
            "findings", "decisions", "details")


def esc(value):
    return html.escape(str(value), quote=True)


# ----------------------------------------------------------------------- data


class Column(NamedTuple):
    month: object           # periods.Period
    cut: object             # datetime.date
    verdicts: tuple
    findings: tuple


class Review(NamedTuple):
    period: object
    as_of: object
    household: object
    columns: tuple
    findings: tuple
    months12: tuple         # (Period, income Value|Unknown, expense Value|Unknown)
    spending: tuple         # (category, Value|Unknown), sorted
    allocation: tuple       # (class, Value|Stale|Unknown, share Value|Stale|Unknown)
    rows: dict              # "ledger" | "holdings" | "rates" -> sorted unique rows


def _unique(findings):
    out = []
    seen = set()
    for f in findings:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return tuple(out)


def build(household, period, as_of):
    ctx = household.ctx._replace(as_of=as_of)
    cfg = household.config
    columns = []
    for m in period.months():
        if m.start > as_of:
            break
        cut = m.end if m.end <= as_of else as_of
        verdicts, findings = rules.check(ctx, cut)
        columns.append(Column(m, cut, verdicts, findings))
    if not columns:
        verdicts, findings = rules.check(ctx, as_of)
        columns.append(Column(periods.period_of(as_of, "month"), as_of, verdicts, findings))
    findings = []
    for c in columns:
        findings.extend(c.findings)
    findings.extend(rules.decision_findings(household.decisions, as_of))
    findings.extend(rules.problem_findings(household.problems.get("decisions.yml")))
    findings.extend(rules.problem_findings(household.problems.get("rates.csv")))
    findings = _unique(findings)

    months12 = []
    for m in periods.trailing(as_of, 12).months():
        months12.append((m, measures.income(ctx, m), measures.expense(ctx, m)))

    spending = []
    for category in cfg.categories.get("expense", ()):
        measure = {"kind": "sum", "group": "expense", "category": category, "period": period.kind}
        spending.append((category, measures.evaluate(measure, ctx, period)))
    spending.sort(key=lambda item: (-(item[1].amount) if isinstance(item[1], Value) else Decimal(1), item[0]))

    allocation = []
    for cls in cfg.classes:
        value = measures.holdings(ctx, "class", cls, period)
        share = measures.share(ctx, cls, period)
        allocation.append((cls, value, share))

    rows = {"ledger": [], "holdings": [], "rates": []}
    for c in columns:
        for v in c.verdicts:
            for r in v.rows:
                _collect(rows, r)
    rows = dict((k, tuple(sorted(set(v), key=lambda r: (r.file, r.line)))) for k, v in rows.items())
    return Review(period, as_of, household, tuple(columns), tuple(findings), tuple(months12),
                  tuple(spending), tuple(allocation), rows)


def _collect(rows, r):
    if isinstance(r, LedgerRow):
        rows["ledger"].append(r)
    elif isinstance(r, HoldingRow):
        rows["holdings"].append(r)
    elif isinstance(r, RateRow):
        rows["rates"].append(r)


# ------------------------------------------------------------------------ SVG


def _nice_step(maximum, target=5):
    """A tick step from {1, 2, 5} x 10^k so that about ``target`` ticks
    cover ``maximum`` (a Decimal). Ticks are real values, not pixels."""
    if maximum <= 0:
        return Decimal(1)
    raw = maximum / Decimal(target)
    exponent = 0
    while raw >= 10:
        raw /= 10
        exponent += 1
    while raw < 1:
        raw *= 10
        exponent -= 1
    for base in (Decimal(1), Decimal(2), Decimal(5)):
        if raw <= base:
            return base * (Decimal(10) ** exponent)
    return Decimal(10) ** (exponent + 1)


def _ticks(maximum):
    step = _nice_step(maximum)
    ticks = []
    t = Decimal(0)
    while t <= maximum:
        ticks.append(t)
        t += step
    if not ticks or ticks[-1] < maximum:
        ticks.append(t)
    return ticks, ticks[-1]


def _px(value, top, length):
    """Pixel length for a Decimal value against the axis top (float geometry only)."""
    if top <= 0:
        return 0.0
    return float(value) / float(top) * length


def svg_income_expense(months12, period, base):
    w, h = 720, 270
    left, right, top_pad, bottom = 64, 16, 24, 44
    plot_w, plot_h = w - left - right, h - top_pad - bottom
    amounts = [x.amount for _, inc, exp in months12 for x in (inc, exp) if isinstance(x, Value)]
    ticks, axis_top = _ticks(max(amounts) if amounts else Decimal(0))
    n = max(len(months12), 1)
    slot = plot_w / n
    bar = max(slot * 0.36, 2.0)
    out = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-labelledby="t-ie">' % (w, h),
           '<title id="t-ie">Income vs expense per month, %s</title>' % esc(base)]
    for t in ticks:
        y = top_pad + plot_h - _px(t, axis_top, plot_h)
        out.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="var(--grid)" stroke-width="1"/>' % (left, y, w - right, y))
        out.append('<text x="%d" y="%.1f" font-size="11" text-anchor="end" fill="currentColor">%s</text>' % (left - 6, y + 4, esc(money(t))))
    for i, (m, inc, exp) in enumerate(months12):
        x0 = left + i * slot
        inside = period.contains(m.start)
        if inside:
            out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="var(--mark)" opacity="0.35"/>' % (x0, top_pad, slot, plot_h))
        for j, (value, token) in enumerate(((inc, "income"), (exp, "expense"))):
            x = x0 + slot * 0.12 + j * bar
            if isinstance(value, Value):
                hpx = _px(value.amount, axis_top, plot_h)
                y = top_pad + plot_h - hpx
                out.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="var(--%s)"><title>%s %s: %s</title></rect>'
                           % (x, y, bar, hpx, token, esc(m.label), token, esc(money(value.amount, base))))
            else:
                out.append('<text x="%.1f" y="%d" font-size="11" fill="var(--unknown)">?</text>' % (x + bar / 2 - 3, top_pad + plot_h - 4))
        out.append('<text x="%.1f" y="%d" font-size="11" text-anchor="middle" fill="currentColor">%s</text>'
                   % (x0 + slot / 2, h - bottom + 16, esc(m.label)))
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="currentColor" stroke-width="1"/>' % (left, top_pad + plot_h, w - right, top_pad + plot_h))
    lx = left
    for token, label in (("income", "income"), ("expense", "expense")):
        out.append('<rect x="%d" y="%d" width="12" height="12" fill="var(--%s)"/>' % (lx, h - 14, token))
        out.append('<text x="%d" y="%d" font-size="11" fill="currentColor">%s</text>' % (lx + 16, h - 4, label))
        lx += 90
    out.append("</svg>")
    return "\n".join(out)


def svg_hbars(items, base, title_id, title, bands=None, unit="money"):
    """Horizontal bars. items: (label, Value|other, extra_text). bands:
    {label: (min_pct, max_pct)} drawn as two tick lines when unit is pct."""
    row_h, left, right, top = 26, 140, 200, 20
    w = 760
    h = top + row_h * max(len(items), 1) + 36
    plot_w = w - left - right
    amounts = [v.amount for _, v, _ in items if isinstance(v, Value)]
    if unit == "pct":
        axis_top = Decimal(100)
        ticks = [Decimal(x) for x in (0, 25, 50, 75, 100)]
    else:
        ticks, axis_top = _ticks(max(amounts) if amounts else Decimal(0))
    out = ['<svg viewBox="0 0 %d %d" width="100%%" role="img" aria-labelledby="%s">' % (w, h, title_id),
           '<title id="%s">%s</title>' % (title_id, esc(title))]
    plot_h = row_h * max(len(items), 1)
    for t in ticks:
        x = left + _px(t, axis_top, plot_w)
        out.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="var(--grid)" stroke-width="1"/>' % (x, top, x, top + plot_h))
        label = (money(t) + "%") if unit == "pct" else money(t)
        out.append('<text x="%.1f" y="%d" font-size="11" text-anchor="middle" fill="currentColor">%s</text>' % (x, top + plot_h + 16, esc(label)))
    for i, (label, value, extra) in enumerate(items):
        y = top + i * row_h
        out.append('<text x="%d" y="%.1f" font-size="12" text-anchor="end" fill="currentColor">%s</text>' % (left - 8, y + row_h * 0.65, esc(label)))
        if isinstance(value, Value):
            wpx = _px(value.amount, axis_top, plot_w)
            shown = (pct(value.amount) if unit == "pct" else money(value.amount, base))
            out.append('<rect x="%d" y="%.1f" width="%.1f" height="%.1f" fill="var(--bar)"><title>%s: %s</title></rect>'
                       % (left, y + 4, wpx, row_h - 8, esc(label), esc(shown)))
            text = '<text x="%.1f" y="%.1f" font-size="11" fill="currentColor">%s</text>' % (
                left + wpx + 4, y + row_h * 0.65, esc(shown + ("  " + extra if extra else "")))
        else:
            kind = "stale" if isinstance(value, Stale) else "unknown"
            text = '<text x="%d" y="%.1f" font-size="11" fill="var(--unknown)">%s</text>' % (
                left + 4, y + row_h * 0.65, esc(kind + ("  " + extra if extra else "")))
        if bands and label in bands:
            lo, hi = bands[label]
            for b in (lo, hi):
                x = left + _px(b, axis_top, plot_w)
                out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--band)" stroke-width="2"><title>band %s..%s</title></line>'
                           % (x, y + 2, x, y + row_h - 2, esc(money(lo) + "%"), esc(money(hi) + "%")))
        out.append(text)
    out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="currentColor" stroke-width="1"/>' % (left, top + plot_h, w - right, top + plot_h))
    out.append("</svg>")
    return "\n".join(out)


# ----------------------------------------------------------------------- HTML


CSS = """
:root {
  --bg: #ffffff; --fg: #1d2330; --muted: #5d6675; --grid: #d9dde4; --panel: #f4f6f9;
  --hold: #2e8b57; --breach: #c0392b; --kill: #8e1b14; --missing: #d35400; --stale: #b8860b;
  --unknown: #6c5b9b; --invalid: #6c5b9b; --warn: #b8860b;
  --income: #2f6fb3; --expense: #c0392b; --bar: #2f6fb3; --band: #d35400; --mark: #ffe08a;
  --link: #1f5fa8;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14181f; --fg: #e6e9ef; --muted: #9aa3b2; --grid: #2d343f; --panel: #1c222b;
    --hold: #4cbf7a; --breach: #ef6a5a; --kill: #ff8f80; --missing: #f0954f; --stale: #e2b64a;
    --unknown: #a894e0; --invalid: #a894e0; --warn: #e2b64a;
    --income: #6ea2e4; --expense: #ef6a5a; --bar: #6ea2e4; --band: #f0954f; --mark: #5a4a12;
    --link: #8ab4f8;
  }
}
:root[data-theme="dark"] {
  --bg: #14181f; --fg: #e6e9ef; --muted: #9aa3b2; --grid: #2d343f; --panel: #1c222b;
  --hold: #4cbf7a; --breach: #ef6a5a; --kill: #ff8f80; --missing: #f0954f; --stale: #e2b64a;
  --unknown: #a894e0; --invalid: #a894e0; --warn: #e2b64a;
  --income: #6ea2e4; --expense: #ef6a5a; --bar: #6ea2e4; --band: #f0954f; --mark: #5a4a12;
  --link: #8ab4f8;
}
html { background: var(--bg); color: var(--fg); }
body { margin: 0 auto; max-width: 960px; padding: 16px; font: 14px/1.45 system-ui, sans-serif; background: var(--bg); color: var(--fg); }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 8px; border-bottom: 1px solid var(--grid); padding-bottom: 4px; }
section { margin-bottom: 8px; }
.muted { color: var(--muted); }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid var(--grid); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.cite { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); }
.v { display: inline-block; min-width: 56px; padding: 1px 6px; border-radius: 3px; color: var(--bg); font-weight: 600; font-size: 12px; text-align: center; }
.v-hold { background: var(--hold); } .v-breach { background: var(--breach); } .v-kill { background: var(--kill); }
.v-missing { background: var(--missing); } .v-stale { background: var(--stale); }
.v-unknown { background: var(--unknown); } .v-invalid { background: var(--invalid); }
.f-red { color: var(--breach); font-weight: 600; } .f-warn { color: var(--warn); font-weight: 600; }
.panel { background: var(--panel); padding: 8px 12px; border-radius: 6px; }
.wrap { overflow-x: auto; }
svg { display: block; max-width: 100%; height: auto; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 0; }
dt { color: var(--muted); } dd { margin: 0; }
"""


def _verdict_cell(v, base):
    text = "%s vs %s" % (measure_display(v, base), limit_display(v, base))
    note = ('<div class="muted"><em>%s</em></div>' % esc(v.reason)) if v.reason else ""
    return '<td><span class="v v-%s">%s</span><div class="muted">%s</div>%s</td>' % (
        esc(v.verdict), esc(v.verdict), esc(text), note)


def render(review):
    r = review
    cfg = r.household.config
    base = cfg.base_currency
    out = []
    out.append('<!DOCTYPE html>')
    out.append('<html lang="en">')
    out.append('<head>')
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    out.append('<meta name="color-scheme" content="light dark">')
    out.append('<title>Qayd review %s</title>' % esc(r.period.label))
    out.append('<style>%s</style>' % CSS)
    out.append('</head>')
    out.append('<body>')
    out.append('<header><h1>Qayd review %s</h1><p class="muted">Deterministic verdicts from declared policies and recorded rows. Qayd never advises and never moves money.</p></header>' % esc(r.period.label))
    out.append('<main>')

    # 1. period header
    out.append('<section id="period"><h2>Period</h2><div class="panel"><dl>')
    out.append('<dt>period</dt><dd>%s (%s to %s)</dd>' % (esc(r.period.label), esc(r.period.start.isoformat()), esc(r.period.end.isoformat())))
    out.append('<dt>as of</dt><dd>%s</dd>' % esc(r.as_of.isoformat()))
    out.append('<dt>base currency</dt><dd>%s</dd>' % esc(base))
    files = ", ".join("%s (%s)" % (name, "absent" if count is None else "%d rows" % count)
                      for name, count in r.household.files.items())
    out.append('<dt>data files</dt><dd>%s</dd>' % esc(files))
    out.append('<dt>policies</dt><dd>%d declared</dd>' % len(cfg.policies))
    out.append('</dl></div></section>')

    # 2. policy board
    out.append('<section id="board"><h2>Policy board</h2><div class="wrap"><table>')
    out.append('<thead><tr><th>policy</th><th>declared</th>')
    for c in r.columns:
        head = c.month.label if c.cut == c.month.end else "%s (to %s)" % (c.month.label, c.cut.isoformat())
        out.append('<th>%s</th>' % esc(head))
    out.append('</tr></thead><tbody>')
    by_id = [dict((v.id, v) for v in c.verdicts) for c in r.columns]
    for policy in cfg.policies:
        declared = _declared(policy, base)
        out.append('<tr><td><strong>%s</strong><br>%s</td><td class="muted">%s</td>' % (esc(policy.id), esc(policy.title), esc(declared)))
        for i, c in enumerate(r.columns):
            v = by_id[i].get(policy.id)
            out.append(_verdict_cell(v, base) if v is not None else '<td></td>')
        out.append('</tr>')
    out.append('</tbody></table></div></section>')

    # 3. income vs expense
    out.append('<section id="income-expense"><h2>Income vs expense per month</h2>')
    out.append('<p class="muted">Trailing twelve months to %s in %s; the months of %s are marked. Transfers are neither.</p>' % (esc(r.as_of.isoformat()), esc(base), esc(r.period.label)))
    out.append(svg_income_expense(r.months12, r.period, base))
    out.append('<div class="wrap"><table><thead><tr><th>month</th><th class="num">income</th><th class="num">expense</th></tr></thead><tbody>')
    for m, inc, exp in r.months12:
        out.append('<tr><td>%s</td><td class="num">%s</td><td class="num">%s</td></tr>' % (esc(m.label), esc(_amount(inc, base)), esc(_amount(exp, base))))
    out.append('</tbody></table></div></section>')

    # 4. spending by category
    out.append('<section id="spending"><h2>Spending by category</h2>')
    out.append('<p class="muted">Expense categories over %s, largest first, in %s.</p>' % (esc(r.period.label), esc(base)))
    out.append(svg_hbars([(c, v, "") for c, v in r.spending], base, "t-sp", "Spending by category, %s" % r.period.label))
    out.append('</section>')

    # 5. allocation by class
    bands = {}
    for policy in cfg.policies:
        if policy.type == "allocation" and policy.status == "ok":
            bands[policy.measure["name"]] = (policy.band["min_pct"], policy.band["max_pct"])
    items = []
    for cls, value, share in r.allocation:
        extra = _amount(value, base) if not isinstance(value, Value) or value.amount != 0 else ""
        items.append((cls, share, extra))
    out.append('<section id="allocation"><h2>Allocation by class</h2>')
    out.append('<p class="muted">Share of total holdings (debt excluded) as of %s; orange lines are the bands of allocation policies.</p>' % esc(r.as_of.isoformat()))
    out.append(svg_hbars(items, base, "t-al", "Allocation by class as of %s" % r.as_of.isoformat(), bands=bands, unit="pct"))
    out.append('</section>')

    # 6. findings of the period
    out.append('<section id="findings"><h2>Findings of the period</h2>')
    if r.findings:
        out.append('<div class="wrap"><table><thead><tr><th>class</th><th>finding</th><th>policy</th><th>when</th><th>reason</th><th>cites</th></tr></thead><tbody>')
        for f in r.findings:
            when = f.period or f.date or ""
            out.append('<tr><td class="f-%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="cite">%s</td></tr>' % (
                esc(f.cls), esc(f.cls), esc(f.code), esc(f.policy or ""), esc(when), esc(f.reason), esc(" ".join(f.cites))))
        out.append('</tbody></table></div>')
    else:
        out.append('<p>No finding: every policy held at the end of every month of the period and no decision is due.</p>')
    out.append('</section>')

    # 7. decisions open and due
    out.append('<section id="decisions"><h2>Decisions open and due</h2>')
    decisions = sorted(r.household.decisions, key=lambda d: (0 if d.is_due(r.as_of) else 1 if d.is_open else 2, d.date, d.line))
    if decisions:
        out.append('<div class="wrap"><table><thead><tr><th>status</th><th>id</th><th>title</th><th>policy</th><th>review by</th><th>days</th><th>cite</th></tr></thead><tbody>')
        for d in decisions:
            if d.is_open:
                status = "due" if d.is_due(r.as_of) else "open"
                days = str(d.days_until_review(r.as_of))
            else:
                status, days = "closed", ""
            cls = "f-red" if status == "due" else ""
            out.append('<tr><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">%s</td><td class="cite">%s</td></tr>' % (
                esc(cls), esc(status), esc(d.id), esc(d.title), esc(d.closes and ("closes " + d.closes) or d.policy or ""),
                esc(d.review_by.isoformat()), esc(days), esc(d.cite)))
        out.append('</tbody></table></div>')
    else:
        out.append('<p>No decision recorded.</p>')
    out.append('</section>')

    # 8. details
    out.append('<section id="details"><h2>Details: every row a verdict cites</h2>')
    led = r.rows["ledger"]
    out.append('<h3>ledger rows (%d)</h3>' % len(led))
    if led:
        out.append('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th class="num">amount</th><th>currency</th><th>account</th><th>category</th><th>tags</th><th>note</th></tr></thead><tbody>')
        for x in led:
            out.append('<tr><td class="cite">%s</td><td>%s</td><td class="num">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                esc(x.cite), esc(x.date.isoformat()), esc(money(x.amount)), esc(x.currency), esc(x.account), esc(x.category), esc(";".join(x.tags)), esc(x.note)))
        out.append('</tbody></table></div>')
    hol = r.rows["holdings"]
    out.append('<h3>holdings rows (%d)</h3>' % len(hol))
    if hol:
        out.append('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th>account</th><th>asset</th><th>class</th><th class="num">quantity</th><th class="num">value</th><th>currency</th></tr></thead><tbody>')
        for x in hol:
            out.append('<tr><td class="cite">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="num">%s</td><td class="num">%s</td><td>%s</td></tr>' % (
                esc(x.cite), esc(x.date.isoformat()), esc(x.account), esc(x.asset), esc(x.asset_class), esc(money(x.quantity)), esc(money(x.value)), esc(x.currency)))
        out.append('</tbody></table></div>')
    rat = r.rows["rates"]
    out.append('<h3>rate rows (%d)</h3>' % len(rat))
    if rat:
        out.append('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th>currency</th><th class="num">rate</th></tr></thead><tbody>')
        for x in rat:
            out.append('<tr><td class="cite">%s</td><td>%s</td><td>%s</td><td class="num">%s</td></tr>' % (
                esc(x.cite), esc(x.date.isoformat()), esc(x.currency), esc(money(x.rate))))
        out.append('</tbody></table></div>')
    out.append('</section>')

    out.append('</main>')
    out.append('<footer class="muted"><p>Generated by Qayd from the files above. Same files, same page, on every machine.</p></footer>')
    out.append('</body>')
    out.append('</html>')
    return "\n".join(out) + "\n"


def _declared(policy, base):
    if policy.status != "ok":
        return "undeclared: %s" % policy.reason
    if policy.type in ("cap", "floor"):
        op = "<=" if policy.type == "cap" else ">="
        return "%s %s %s" % (measure_text(policy.measure), op, limit_text(policy.limit, base))
    if policy.type == "allocation":
        return "%s within %s" % (measure_text(policy.measure), band_text(policy.band))
    if policy.type == "kill":
        return "%s crosses %s" % (measure_text(policy.measure), limit_text(policy.limit))
    if policy.type == "routine":
        return "every %s: %s" % (policy.period, match_text(policy.match))
    return "never: %s" % match_text(policy.match)


def _amount(value, base):
    if isinstance(value, Value):
        return money(value.amount, base)
    if isinstance(value, Stale):
        return "stale (%s, %d days)" % (money(value.amount, base) if value.amount is not None else "?", value.age_days)
    if isinstance(value, Unknown):
        return "unknown"
    return "?"


def write(household, period, as_of, path):
    page = render(build(household, period, as_of))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(page)
    return page
