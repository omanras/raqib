# ADR-0001 — Qayd architecture

Status: accepted (2026-10-17). Amendments are appended, never edited in place.

## 1. Purpose
A command-line tool that reads a household's policies and ledger and
reports, deterministically, which policies hold as of a date, which were
breached, which routines were skipped, which decisions are due, and a
period review as a static HTML page. Offline, stdlib + PyYAML, under a
second for ten years of monthly rows.

## 2. Files the owner keeps
- `policies.yml`  base currency, categories, accounts, and the policy list.
- `ledger.csv`    one row per money movement.
- `holdings.csv`  snapshots of balances and positions.
- `decisions.yml` decisions taken, each with a review date.
- `rates.csv`     optional: currency rates by date.
All paths default to the current directory; `--dir DIR` points elsewhere.

## 3. Ledger (`ledger.csv`)
Header exactly: `date,amount,currency,account,category,tags,note`.
- `date` ISO `YYYY-MM-DD`; `amount` decimal text, negative = money out of
  the household, positive = money in (income, refunds, sale proceeds);
  `currency` ISO-4217 code; `account` and `category` must be declared in
  policies.yml; `tags` is `;`-separated tokens or empty; `note` free text.
- A transfer between two own accounts is two rows with tag `transfer`
  (out of one, into the other) and is not spending nor income.
- Rows need not be sorted. Duplicate rows are allowed (two identical
  purchases happen); an exact duplicate on the same line is a finding
  `DUP-ROW` of class warn (never silently merged).
- A malformed row (bad date, bad amount, unknown account or category,
  wrong column count) is `invalid` with `file:line`; the run continues and
  every policy touching that row's period becomes `unknown`.

## 4. Holdings (`holdings.csv`)
Header exactly: `date,account,asset,class,quantity,value,currency`.
A snapshot is all rows of one date. `class` is declared in policies.yml
(`cash`, `equity`, `fund`, `property`, `gold`, `debt`, `other` by default).
`value` is the market value of the position in `currency` on that date.
The "current" snapshot as of D is the latest date <= D; its age in days is
measured against `snapshot_max_age_days` (section 6) and stale -> red.

## 5. Policies (`policies.yml`)
```yaml
version: 1
base_currency: OMR
accounts: [salary, savings, broker, cash]
categories:
  income: [salary, bonus, side]
  expense: [housing, food, transport, family, discretionary, fees]
  transfer: [transfer]
  invest: [buy, sell, dividend]
snapshot_max_age_days: 45
policies:
  - id: WLT-01
    type: cap           # measure <= limit
    title: discretionary spending per month
    measure: {sum: expense.discretionary, period: month}
    limit: {pct_of: income, value: 10}
  - id: WLT-02
    type: floor         # measure >= limit
    title: emergency fund
    measure: {holdings: class.cash}
    limit: {months_of: expense, value: 6}
  - id: WLT-03
    type: routine       # a matching row must exist every period
    title: monthly transfer to savings
    match: {tags: transfer, account: savings, min_amount: 300}
    period: month
  - id: WLT-04
    type: red_line      # no matching row may exist, ever
    title: no margin, no options
    match: {tags_any: [margin, options]}
  - id: WLT-05
    type: kill          # pilot ends when measure crosses the threshold
    title: broker pilot drawdown
    measure: {drawdown: account.broker, window_days: 90}
    limit: {pct: 15}
  - id: WLT-06
    type: allocation    # class share of holdings within a band
    title: equities band
    measure: {share: class.equity}
    band: {min_pct: 20, max_pct: 50}
```
Measures (v0.1): `sum: <group>.<category>` over a period; `holdings:
class.<c>` or `holdings: account.<a>` as of the date; `share: class.<c>`
(value of the class / total holdings, debts excluded); `drawdown:
account.<a>` (peak-to-current over `window_days` of snapshots); `income`
(sum of income categories in the period); `expense` (sum of all expense
categories, as a positive number). Limits: `{value: N}` absolute in base
currency; `{pct_of: income, value: P}`; `{months_of: expense, value: M}`
(M times the average monthly expense of the trailing 12 months);
`{pct: P}` for drawdown. Periods: `month`, `quarter`, `year`, ISO calendar.
Any other type, measure or limit -> policy `unknown` (A3/A5).

## 6. Verdicts
Per policy, as of a date D (default today, `--as-of` sets it):
`hold`, `breach`, `missing` (routine without its row in the period, or a
period with no ledger rows at all), `kill` (a kill policy whose threshold
is crossed; it stays `kill` on every later date until a decision in
decisions.yml with `closes: <policy id>` is dated after the crossing),
`stale` (holdings snapshot older than allowed), `unknown`, `invalid`.
Green = every policy `hold`. Exit codes: 0 green, 1 red, 2 usage, 3 a file
could not be read or parsed (also red).

## 7. Decisions (`decisions.yml`)
```yaml
- id: D-2026-10-01
  date: 2026-10-01
  title: start broker pilot with 500 OMR
  policy: WLT-05
  criteria: "stop if drawdown > 15% in any 90 days; review quarterly"
  review_by: 2027-01-01
  status: open        # open | closed
  closes: null        # policy id whose kill this decision answers
```
A decision with `status: open` and `review_by < D` is finding `DECISION-DUE`
(red). `closes` must name an existing policy.

## 8. Commands
```
python3 -m qayd check     [--dir DIR] [--as-of DATE] [--json]
python3 -m qayd routine   [--dir DIR] [--period 2026-10] [--json]
python3 -m qayd decisions [--dir DIR] [--as-of DATE] [--json]
python3 -m qayd review    [--dir DIR] --period 2026-Q3|2026-10|2026 -o FILE.html
python3 -m qayd init      [--dir DIR]       # writes the example household
```
Text output: one line per policy `<verdict> <id> <title> <measure> vs
<limit>` then indented citations. JSON: `{"version": 1, "as_of", "green",
"policies": [...], "findings": [...]}`.

## 9. Review page
`review` writes one self-contained HTML file: no script, inline SVG
charts drawn by Python (income vs expense by month, spending by category,
allocation by class, the policy board), the findings of the period, the
decisions due, and the rows behind every number in a details table.
