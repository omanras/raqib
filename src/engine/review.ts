// The review page (reference engine ADR section 9, qayd/review.py, ported
// one to one so "Copy as HTML" is the page the CLI writes, byte for byte):
// one self-contained HTML file for a period. No script, no external
// resource, no inline event handler; every colour is a CSS token on :root
// (light and dark); inline SVG with viewBox, text in currentColor, axis
// ticks at real values. A JS number is used for pixel geometry only, never
// for an amount: every printed amount comes from Decimal (A5).
//
// Sections, in order: period header; policy board (the verdict at the end
// of every month of the period, the last column being the as-of date);
// income vs expense per month (the trailing twelve months, the period's
// months marked); spending by category over the period; allocation by
// class as of the period end with the band lines of allocation policies;
// findings of the period with citations; decisions open and due; details
// table of every row a verdict cites.
import { daysUntilReview, isDue } from "./decisions";
import { D, money, pct, ZERO, type Decimal } from "./decimal";
import { decisionFindings, problemFindings, sameFinding, type Finding } from "./findings";
import type { Household } from "./household";
import { evaluate, expense, holdings, income, share, type Context, type Measured } from "./measures";
import { inPeriod, monthPeriods, periodContaining, trailingWindow, type Period } from "./periods";
import { bandText, limitText, matchText, measureText } from "./policies";
import { limitDisplay, measureDisplay, orderDecisions } from "./report";
import { check, type Verdict } from "./rules";
import type { Citable, HoldingRow, LedgerRow, Policy, RateRow } from "./types";
import type { Unknown, Value } from "./values";

export const SECTIONS = ["period", "board", "income-expense", "spending", "allocation", "findings", "decisions", "details"] as const;

/** Python's html.escape(str(value), quote=True). */
export function esc(value: string | number): string {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// ---- data ---------------------------------------------------------------------

export interface Column {
  month: Period;
  cut: string;
  verdicts: Verdict[];
  findings: Finding[];
}

export interface Review {
  period: Period;
  asOf: string;
  household: Household;
  columns: Column[];
  findings: Finding[];
  /** the trailing twelve months: month, income, expense */
  months12: [Period, Value | Unknown, Value | Unknown][];
  /** expense categories over the period, largest first */
  spending: [string, Measured][];
  /** every class: its value and its share of holdings (debt excluded) */
  allocation: [string, Measured, Measured][];
  rows: { ledger: LedgerRow[]; holdings: HoldingRow[]; rates: RateRow[] };
}

/** The as-of date of a review: the period end, or the earlier date given. */
export function reviewAsOf(period: Period, today: string): string {
  return period.end <= today ? period.end : today;
}

function unique(findings: readonly Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const f of findings) if (!out.some((g) => sameFinding(g, f))) out.push(f);
  return out;
}

function cmpDec(a: Decimal, b: Decimal): number {
  return a.lt(b) ? -1 : a.gt(b) ? 1 : 0;
}

/** The review of a period as of a date (a readable household: no fatal problem). */
export function buildReview(h: Household, period: Period, asOf: string): Review {
  const ctx: Context = { ...(h.ctx as Context), asOf };
  const cfg = ctx.config;
  const columns: Column[] = [];
  for (const m of monthPeriods(period)) {
    if (m.start > asOf) break;
    const cut = m.end <= asOf ? m.end : asOf;
    const r = check(ctx, cut);
    columns.push({ month: m, cut, verdicts: r.verdicts, findings: r.findings });
  }
  if (columns.length === 0) {
    const r = check(ctx, asOf);
    columns.push({ month: periodContaining(asOf, "month"), cut: asOf, verdicts: r.verdicts, findings: r.findings });
  }
  const findings = unique([
    ...columns.flatMap((c) => c.findings),
    ...decisionFindings(h.decisions, asOf),
    ...problemFindings(h.problemsByFile["decisions.yml"] ?? []),
    ...problemFindings(h.problemsByFile["rates.csv"] ?? []),
  ]);
  const months12 = monthPeriods(trailingWindow(asOf, 12)).map((m) => [m, income(ctx, m), expense(ctx, m)] as [Period, Value | Unknown, Value | Unknown]);
  const kind = period.kind === "window" ? "month" : period.kind;
  const spending = (cfg.categories["expense"] ?? []).map((c) => [c, evaluate({ kind: "sum", group: "expense", category: c, period: kind }, ctx, period)] as [string, Measured]);
  const key = (m: Measured) => (m.tag === "value" ? m.amount.neg() : D("1"));
  spending.sort((a, b) => cmpDec(key(a[1]), key(b[1])) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const allocation = cfg.classes.map((c) => [c, holdings(ctx, "class", c, period), share(ctx, c, period)] as [string, Measured, Measured]);
  const sets = { ledger: new Set<LedgerRow>(), holdings: new Set<HoldingRow>(), rates: new Set<RateRow>() };
  for (const c of columns) {
    for (const v of c.verdicts) {
      for (const r of v.rows) {
        if ("amountText" in r) sets.ledger.add(r as LedgerRow);
        else if ("valueText" in r) sets.holdings.add(r as HoldingRow);
        else if ("rateText" in r) sets.rates.add(r as RateRow);
      }
    }
  }
  const byCite = <T extends Citable & { file: string; line: number }>(s: Set<T>) => [...s].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  return {
    period,
    asOf,
    household: h,
    columns,
    findings,
    months12,
    spending,
    allocation,
    rows: { ledger: byCite(sets.ledger), holdings: byCite(sets.holdings), rates: byCite(sets.rates) },
  };
}

// ---- pixels (geometry only) ------------------------------------------------------

/** Python's '%.1f': the exact binary value, rounded half to even. */
export function f1(x: number): string {
  const neg = x < 0 || Object.is(x, -0);
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, Math.abs(x));
  const hi = view.getUint32(0);
  const lo = view.getUint32(4);
  const expBits = (hi >>> 20) & 0x7ff;
  let mant = (BigInt(hi & 0xfffff) << 32n) | BigInt(lo);
  let e: number;
  if (expBits === 0) e = -1074;
  else {
    mant |= 1n << 52n;
    e = expBits - 1075;
  }
  let num = e >= 0 ? mant << BigInt(e) : mant;
  const den = e >= 0 ? 1n : 1n << BigInt(-e);
  num *= 10n;
  let q = num / den;
  const twice = (num % den) * 2n;
  if (twice > den || (twice === den && (q & 1n) === 1n)) q += 1n;
  const s = q.toString().padStart(2, "0");
  return (neg ? "-" : "") + s.slice(0, -1) + "." + s.slice(-1);
}

function px(value: Decimal, top: Decimal, length: number): number {
  if (top.lte(0)) return 0.0;
  // Python's -Decimal(0) is +0; decimal.js keeps -0 (an expense sum of no row)
  const v = value.isZero() ? 0 : value.toNumber();
  return (v / top.toNumber()) * length;
}

/** A tick step from {1, 2, 5} x 10^k so that about `target` ticks cover maximum. */
export function niceStep(maximum: Decimal, target = 5): Decimal {
  if (maximum.lte(0)) return D("1");
  let raw = maximum.div(target);
  let exponent = 0;
  while (raw.gte(10)) {
    raw = raw.div(10);
    exponent++;
  }
  while (raw.lt(1)) {
    raw = raw.times(10);
    exponent--;
  }
  for (const base of [D("1"), D("2"), D("5")]) if (raw.lte(base)) return base.times(D("10").pow(exponent));
  return D("10").pow(exponent + 1);
}

export function ticks(maximum: Decimal): [Decimal[], Decimal] {
  const step = niceStep(maximum);
  const out: Decimal[] = [];
  let t = ZERO;
  while (t.lte(maximum)) {
    out.push(t);
    t = t.plus(step);
  }
  if (out.length === 0 || (out[out.length - 1] as Decimal).lt(maximum)) out.push(t);
  return [out, out[out.length - 1] as Decimal];
}

function maxOf(xs: Decimal[]): Decimal {
  return xs.reduce((a, b) => (b.gt(a) ? b : a));
}

export function svgIncomeExpense(months12: Review["months12"], period: Period, base: string): string {
  const w = 720;
  const h = 270;
  const left = 64;
  const right = 16;
  const topPad = 24;
  const bottom = 44;
  const plotW = w - left - right;
  const plotH = h - topPad - bottom;
  const amounts = months12.flatMap(([, inc, exp]) => [inc, exp]).filter((x): x is Value => x.tag === "value").map((x) => x.amount);
  const [tk, axisTop] = ticks(amounts.length > 0 ? maxOf(amounts) : ZERO);
  const n = Math.max(months12.length, 1);
  const slot = plotW / n;
  const bar = Math.max(slot * 0.36, 2.0);
  const out = [`<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-labelledby="t-ie">`, `<title id="t-ie">Income vs expense per month, ${esc(base)}</title>`];
  for (const t of tk) {
    const y = topPad + plotH - px(t, axisTop, plotH);
    out.push(`<line x1="${left}" y1="${f1(y)}" x2="${w - right}" y2="${f1(y)}" stroke="var(--grid)" stroke-width="1"/>`);
    out.push(`<text x="${left - 6}" y="${f1(y + 4)}" font-size="11" text-anchor="end" fill="currentColor">${esc(money(t))}</text>`);
  }
  months12.forEach(([m, inc, exp], i) => {
    const x0 = left + i * slot;
    if (inPeriod(m.start, period)) out.push(`<rect x="${f1(x0)}" y="${topPad}" width="${f1(slot)}" height="${plotH}" fill="var(--mark)" opacity="0.35"/>`);
    ([[inc, "income"], [exp, "expense"]] as const).forEach(([value, token], j) => {
      const x = x0 + slot * 0.12 + j * bar;
      if (value.tag === "value") {
        const hpx = px(value.amount, axisTop, plotH);
        const y = topPad + plotH - hpx;
        out.push(`<rect x="${f1(x)}" y="${f1(y)}" width="${f1(bar)}" height="${f1(hpx)}" fill="var(--${token})"><title>${esc(m.text)} ${token}: ${esc(money(value.amount, base))}</title></rect>`);
      } else {
        out.push(`<text x="${f1(x + bar / 2 - 3)}" y="${topPad + plotH - 4}" font-size="11" fill="var(--unknown)">?</text>`);
      }
    });
    out.push(`<text x="${f1(x0 + slot / 2)}" y="${h - bottom + 16}" font-size="11" text-anchor="middle" fill="currentColor">${esc(m.text)}</text>`);
  });
  out.push(`<line x1="${left}" y1="${topPad + plotH}" x2="${w - right}" y2="${topPad + plotH}" stroke="currentColor" stroke-width="1"/>`);
  let lx = left;
  for (const token of ["income", "expense"]) {
    out.push(`<rect x="${lx}" y="${h - 14}" width="12" height="12" fill="var(--${token})"/>`);
    out.push(`<text x="${lx + 16}" y="${h - 4}" font-size="11" fill="currentColor">${token}</text>`);
    lx += 90;
  }
  out.push("</svg>");
  return out.join("\n");
}

/** Horizontal bars; bands {label: [min, max]} are drawn as two tick lines (pct unit). */
export function svgHbars(items: [string, Measured, string][], base: string, titleId: string, title: string, bands: Map<string, [Decimal, Decimal]> | null = null, unit: "money" | "pct" = "money"): string {
  const rowH = 26;
  const left = 140;
  const right = 200;
  const top = 20;
  const w = 760;
  const h = top + rowH * Math.max(items.length, 1) + 36;
  const plotW = w - left - right;
  const amounts = items.filter(([, v]) => v.tag === "value").map(([, v]) => (v as Value).amount);
  let tk: Decimal[];
  let axisTop: Decimal;
  if (unit === "pct") {
    axisTop = D("100");
    tk = ["0", "25", "50", "75", "100"].map(D);
  } else [tk, axisTop] = ticks(amounts.length > 0 ? maxOf(amounts) : ZERO);
  const out = [`<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-labelledby="${titleId}">`, `<title id="${titleId}">${esc(title)}</title>`];
  const plotH = rowH * Math.max(items.length, 1);
  for (const t of tk) {
    const x = left + px(t, axisTop, plotW);
    out.push(`<line x1="${f1(x)}" y1="${top}" x2="${f1(x)}" y2="${top + plotH}" stroke="var(--grid)" stroke-width="1"/>`);
    const label = unit === "pct" ? money(t) + "%" : money(t);
    out.push(`<text x="${f1(x)}" y="${top + plotH + 16}" font-size="11" text-anchor="middle" fill="currentColor">${esc(label)}</text>`);
  }
  items.forEach(([label, value, extra], i) => {
    const y = top + i * rowH;
    out.push(`<text x="${left - 8}" y="${f1(y + rowH * 0.65)}" font-size="12" text-anchor="end" fill="currentColor">${esc(label)}</text>`);
    let text: string;
    if (value.tag === "value") {
      const wpx = px(value.amount, axisTop, plotW);
      const shown = unit === "pct" ? pct(value.amount) : money(value.amount, base);
      out.push(`<rect x="${left}" y="${f1(y + 4)}" width="${f1(wpx)}" height="${f1(rowH - 8)}" fill="var(--bar)"><title>${esc(label)}: ${esc(shown)}</title></rect>`);
      text = `<text x="${f1(left + wpx + 4)}" y="${f1(y + rowH * 0.65)}" font-size="11" fill="currentColor">${esc(shown + (extra ? "  " + extra : ""))}</text>`;
    } else {
      const kind = value.tag === "stale" ? "stale" : "unknown";
      text = `<text x="${left + 4}" y="${f1(y + rowH * 0.65)}" font-size="11" fill="var(--unknown)">${esc(kind + (extra ? "  " + extra : ""))}</text>`;
    }
    const band = bands?.get(label);
    if (band) {
      const [lo, hi] = band;
      for (const b of [lo, hi]) {
        const x = left + px(b, axisTop, plotW);
        out.push(`<line x1="${f1(x)}" y1="${f1(y + 2)}" x2="${f1(x)}" y2="${f1(y + rowH - 2)}" stroke="var(--band)" stroke-width="2"><title>band ${esc(money(lo) + "%")}..${esc(money(hi) + "%")}</title></line>`);
      }
    }
    out.push(text);
  });
  out.push(`<line x1="${left}" y1="${top + plotH}" x2="${w - right}" y2="${top + plotH}" stroke="currentColor" stroke-width="1"/>`);
  out.push("</svg>");
  return out.join("\n");
}

// ---- HTML -----------------------------------------------------------------------

export const CSS = `
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
`;

/** The declared column of the board. */
export function declaredText(p: Policy, base: string): string {
  if (p.status !== "ok") return `undeclared: ${p.reason ?? "None"}`;
  if (p.type === "cap" || p.type === "floor") return `${measureText(p.measure)} ${p.type === "cap" ? "<=" : ">="} ${limitText(p.limit, base)}`;
  if (p.type === "allocation") return `${measureText(p.measure)} within ${bandText(p.band)}`;
  if (p.type === "kill") return `${measureText(p.measure)} crosses ${limitText(p.limit)}`;
  if (p.type === "routine") return `every ${p.period ?? "None"}: ${matchText(p.match)}`;
  return `never: ${matchText(p.match)}`;
}

/** An amount cell: money, "stale (... , N days)" or "unknown". */
export function amountCell(v: Measured, base: string): string {
  if (v.tag === "value") return money(v.amount, base);
  if (v.tag === "stale") return `stale (${v.amount !== null ? money(v.amount, base) : "?"}, ${v.ageDays} days)`;
  return "unknown";
}

/** A board column's head: the month, or "2026-09 (to 2026-09-14)" for a cut month. */
export function columnHead(c: Column): string {
  return c.cut === c.month.end ? c.month.text : `${c.month.text} (to ${c.cut})`;
}

function verdictCell(v: Verdict, base: string): string {
  const text = `${measureDisplay(v, base)} vs ${limitDisplay(v, base)}`;
  const note = v.reason ? `<div class="muted"><em>${esc(v.reason)}</em></div>` : "";
  return `<td><span class="v v-${esc(v.verdict)}">${esc(v.verdict)}</span><div class="muted">${esc(text)}</div>${note}</td>`;
}

/** The bands of the allocation policies, by class. */
export function allocationBands(review: Review): Map<string, [Decimal, Decimal]> {
  const bands = new Map<string, [Decimal, Decimal]>();
  for (const p of review.household.config?.policies ?? []) {
    if (p.type === "allocation" && p.status === "ok" && p.measure?.kind === "share" && p.band) bands.set(p.measure.name, [p.band.minPct.value, p.band.maxPct.value]);
  }
  return bands;
}

/** The allocation bars: share per class, with the value when it is not a plain zero. */
export function allocationItems(review: Review, base: string): [string, Measured, string][] {
  return review.allocation.map(([cls, value, s]) => [cls, s, value.tag !== "value" || !value.amount.isZero() ? amountCell(value, base) : ""]);
}

/** The page the CLI's `review` command writes. */
export function renderReviewPage(r: Review): string {
  const cfg = r.household.config;
  const base = cfg?.baseCurrency ?? "";
  const out: string[] = [];
  out.push("<!DOCTYPE html>");
  out.push('<html lang="en">');
  out.push("<head>");
  out.push('<meta charset="utf-8">');
  out.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
  out.push('<meta name="color-scheme" content="light dark">');
  out.push(`<title>Qayd review ${esc(r.period.text)}</title>`);
  out.push(`<style>${CSS}</style>`);
  out.push("</head>");
  out.push("<body>");
  out.push(`<header><h1>Qayd review ${esc(r.period.text)}</h1><p class="muted">Deterministic verdicts from declared policies and recorded rows. Qayd never advises and never moves money.</p></header>`);
  out.push("<main>");

  // 1. period header
  out.push('<section id="period"><h2>Period</h2><div class="panel"><dl>');
  out.push(`<dt>period</dt><dd>${esc(r.period.text)} (${esc(r.period.start)} to ${esc(r.period.end)})</dd>`);
  out.push(`<dt>as of</dt><dd>${esc(r.asOf)}</dd>`);
  out.push(`<dt>base currency</dt><dd>${esc(base)}</dd>`);
  const files = Object.entries(r.household.files)
    .map(([name, count]) => `${name} (${count === null || count === undefined ? "absent" : `${count} rows`})`)
    .join(", ");
  out.push(`<dt>data files</dt><dd>${esc(files)}</dd>`);
  out.push(`<dt>policies</dt><dd>${cfg?.policies.length ?? 0} declared</dd>`);
  out.push("</dl></div></section>");

  // 2. policy board
  out.push('<section id="board"><h2>Policy board</h2><div class="wrap"><table>');
  out.push("<thead><tr><th>policy</th><th>declared</th>");
  for (const c of r.columns) out.push(`<th>${esc(columnHead(c))}</th>`);
  out.push("</tr></thead><tbody>");
  for (const p of cfg?.policies ?? []) {
    out.push(`<tr><td><strong>${esc(p.id)}</strong><br>${esc(p.title)}</td><td class="muted">${esc(declaredText(p, base))}</td>`);
    for (const c of r.columns) {
      const v = c.verdicts.find((x) => x.policy.id === p.id);
      out.push(v ? verdictCell(v, base) : "<td></td>");
    }
    out.push("</tr>");
  }
  out.push("</tbody></table></div></section>");

  // 3. income vs expense
  out.push('<section id="income-expense"><h2>Income vs expense per month</h2>');
  out.push(`<p class="muted">Trailing twelve months to ${esc(r.asOf)} in ${esc(base)}; the months of ${esc(r.period.text)} are marked. Transfers are neither.</p>`);
  out.push(svgIncomeExpense(r.months12, r.period, base));
  out.push('<div class="wrap"><table><thead><tr><th>month</th><th class="num">income</th><th class="num">expense</th></tr></thead><tbody>');
  for (const [m, inc, exp] of r.months12) out.push(`<tr><td>${esc(m.text)}</td><td class="num">${esc(amountCell(inc, base))}</td><td class="num">${esc(amountCell(exp, base))}</td></tr>`);
  out.push("</tbody></table></div></section>");

  // 4. spending by category
  out.push('<section id="spending"><h2>Spending by category</h2>');
  out.push(`<p class="muted">Expense categories over ${esc(r.period.text)}, largest first, in ${esc(base)}.</p>`);
  out.push(svgHbars(r.spending.map(([c, v]) => [c, v, ""]), base, "t-sp", `Spending by category, ${r.period.text}`));
  out.push("</section>");

  // 5. allocation by class
  out.push('<section id="allocation"><h2>Allocation by class</h2>');
  out.push(`<p class="muted">Share of total holdings (debt excluded) as of ${esc(r.asOf)}; orange lines are the bands of allocation policies.</p>`);
  out.push(svgHbars(allocationItems(r, base), base, "t-al", `Allocation by class as of ${r.asOf}`, allocationBands(r), "pct"));
  out.push("</section>");

  // 6. findings of the period
  out.push('<section id="findings"><h2>Findings of the period</h2>');
  if (r.findings.length > 0) {
    out.push('<div class="wrap"><table><thead><tr><th>class</th><th>finding</th><th>policy</th><th>when</th><th>reason</th><th>cites</th></tr></thead><tbody>');
    for (const f of r.findings) {
      const when = f.period || f.date || "";
      out.push(`<tr><td class="f-${esc(f.cls)}">${esc(f.cls)}</td><td>${esc(f.code)}</td><td>${esc(f.policy || "")}</td><td>${esc(when)}</td><td>${esc(f.reason)}</td><td class="cite">${esc(f.cites.join(" "))}</td></tr>`);
    }
    out.push("</tbody></table></div>");
  } else {
    out.push("<p>No finding: every policy held at the end of every month of the period and no decision is due.</p>");
  }
  out.push("</section>");

  // 7. decisions open and due
  out.push('<section id="decisions"><h2>Decisions open and due</h2>');
  const decisions = orderDecisions(r.household.decisions, r.asOf);
  if (decisions.length > 0) {
    out.push('<div class="wrap"><table><thead><tr><th>status</th><th>id</th><th>title</th><th>policy</th><th>review by</th><th>days</th><th>cite</th></tr></thead><tbody>');
    for (const d of decisions) {
      const open = d.status === "open";
      const status = open ? (isDue(d, r.asOf) ? "due" : "open") : "closed";
      const days = open ? String(daysUntilReview(d, r.asOf)) : "";
      const cls = status === "due" ? "f-red" : "";
      out.push(
        `<tr><td class="${esc(cls)}">${esc(status)}</td><td>${esc(d.id)}</td><td>${esc(d.title)}</td><td>${esc((d.closes && "closes " + d.closes) || d.policy || "")}</td><td>${esc(d.reviewBy)}</td><td class="num">${esc(days)}</td><td class="cite">${esc(d.cite)}</td></tr>`,
      );
    }
    out.push("</tbody></table></div>");
  } else {
    out.push("<p>No decision recorded.</p>");
  }
  out.push("</section>");

  // 8. details
  out.push('<section id="details"><h2>Details: every row a verdict cites</h2>');
  const led = r.rows.ledger;
  out.push(`<h3>ledger rows (${led.length})</h3>`);
  if (led.length > 0) {
    out.push('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th class="num">amount</th><th>currency</th><th>account</th><th>category</th><th>tags</th><th>note</th></tr></thead><tbody>');
    for (const x of led) {
      out.push(`<tr><td class="cite">${esc(x.cite)}</td><td>${esc(x.date)}</td><td class="num">${esc(money(x.amount))}</td><td>${esc(x.currency)}</td><td>${esc(x.account)}</td><td>${esc(x.category)}</td><td>${esc(x.tags.join(";"))}</td><td>${esc(x.note)}</td></tr>`);
    }
    out.push("</tbody></table></div>");
  }
  const hol = r.rows.holdings;
  out.push(`<h3>holdings rows (${hol.length})</h3>`);
  if (hol.length > 0) {
    out.push('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th>account</th><th>asset</th><th>class</th><th class="num">quantity</th><th class="num">value</th><th>currency</th></tr></thead><tbody>');
    for (const x of hol) {
      out.push(`<tr><td class="cite">${esc(x.cite)}</td><td>${esc(x.date)}</td><td>${esc(x.account)}</td><td>${esc(x.asset)}</td><td>${esc(x.cls)}</td><td class="num">${esc(money(x.quantity))}</td><td class="num">${esc(money(x.value))}</td><td>${esc(x.currency)}</td></tr>`);
    }
    out.push("</tbody></table></div>");
  }
  const rat = r.rows.rates;
  out.push(`<h3>rate rows (${rat.length})</h3>`);
  if (rat.length > 0) {
    out.push('<div class="wrap"><table><thead><tr><th>cite</th><th>date</th><th>currency</th><th class="num">rate</th></tr></thead><tbody>');
    for (const x of rat) out.push(`<tr><td class="cite">${esc(x.cite)}</td><td>${esc(x.date)}</td><td>${esc(x.currency)}</td><td class="num">${esc(money(x.rate))}</td></tr>`);
    out.push("</tbody></table></div>");
  }
  out.push("</section>");

  out.push("</main>");
  out.push('<footer class="muted"><p>Generated by Qayd from the files above. Same files, same page, on every machine.</p></footer>');
  out.push("</body>");
  out.push("</html>");
  return out.join("\n") + "\n";
}
