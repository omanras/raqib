# Qayd

Personal finance as code. A household declares its money policies in
YAML, keeps its ledger in CSV, and gets deterministic verdicts: which
policy holds, which is breached, which routine was skipped, which pilot
must be killed, which decision is due for review. Offline, stdlib +
PyYAML. It never advises, never moves money and never connects to anything.

Qayd lives on branch `qayd` of this repository; branches `main` (Raqib)
and `mizan` are other projects. Status: v0.1 (see `docs/DEVELOPMENT_PLAN.md`).

## Quickstart

```
git clone -b qayd https://github.com/omanras/raqib qayd && cd qayd
tools/gate.sh                                  # tests + self-check; needs python3 and PyYAML
python3 -m qayd init --dir ~/money             # copies the synthetic example household
$EDITOR ~/money/policies.yml                   # declare your accounts, categories, policies
$EDITOR ~/money/ledger.csv                     # append one row per money movement
python3 -m qayd check --dir ~/money            # verdicts as of today; exit 0 only when all hold
python3 -m qayd review --dir ~/money --period 2026-Q3 -o ~/money/review.html
```

Run the commands from the clone (or put the clone on `PYTHONPATH`). The
example household is synthetic; `examples/README.md` lists its planted
breach, kill, missing routine and due decision so you can see every
verdict before you write your own numbers. The transcript of this
quickstart from a fresh clone is in `docs/review/2026-10-17-M2.2-quickstart.md`.

## The files

All in one directory (the current one, or `--dir DIR`).

- `policies.yml` - `version: 1`, `base_currency`, `accounts`, `categories`
  by group (`income`, `expense`, `transfer`, `invest`), optional `classes`,
  `snapshot_max_age_days`, and the `policies` list. Six policy types:

  | type | needs | holds when |
  | --- | --- | --- |
  | `cap` | `measure`, `limit` | measure <= limit |
  | `floor` | `measure`, `limit` | measure >= limit |
  | `routine` | `match`, `period` | a matching row exists in every period |
  | `red_line` | `match` | no matching row exists, ever |
  | `kill` | `measure: {drawdown: account.X, window_days: N}`, `limit: {pct: P}` | the drawdown never crossed P, or a decision with `closes: <id>` is dated after the crossing |
  | `allocation` | `measure: {share: class.X}`, `band: {min_pct, max_pct}` | the share is inside the band |

  Measures: `{sum: expense.food, period: month}` (a category), `{sum:
  income, period: quarter}` (a whole group), `{holdings: class.cash}`,
  `{holdings: account.broker}`, `{share: class.equity}`, `{drawdown:
  account.broker, window_days: 90}`. Limits: `{value: N}` in the base
  currency, `{pct_of: income, value: P}`, `{months_of: expense, value: M}`
  (M times the average month of the trailing twelve), `{pct: P}`. Match:
  `tags`, `tags_any`, `account`, `category`, `min_amount`.
- `ledger.csv` - header exactly `date,amount,currency,account,category,tags,note`.
  Negative is money out, positive money in; `tags` are `;`-separated; a
  transfer between own accounts is two rows tagged `transfer` and is
  neither income nor expense. Rows need not be sorted.
- `holdings.csv` - `date,account,asset,class,quantity,value,currency`; all
  rows of one date are a snapshot; the latest snapshot on or before the
  as-of date is the current one, and older than `snapshot_max_age_days`
  is `stale`.
- `decisions.yml` - a list of `id, date, title, policy, criteria,
  review_by, status (open|closed), closes`; an open decision past its
  review date is `DECISION-DUE`.
- `rates.csv` - optional; `date,currency,rate` where rate is base units
  per one unit of the currency; the latest rate on or before the row's
  date is used; without one the measure is `unknown`.

## Commands

| command | does | exit 0 when |
| --- | --- | --- |
| `python3 -m qayd check [--dir D] [--as-of DATE] [--json]` | one line per policy, reds first, with citations | every policy holds and no finding is red |
| `python3 -m qayd routine [--dir D] [--period 2026-10] [--as-of DATE] [--json]` | every routine of the period: done or missing | every routine is done |
| `python3 -m qayd decisions [--dir D] [--as-of DATE] [--json]` | open decisions with days to review, closed ones with what they closed | none is due |
| `python3 -m qayd review [--dir D] --period 2026-Q3 -o FILE.html` | one self-contained HTML page: policy board by month, charts, findings, decisions, every cited row | the page was written |
| `python3 -m qayd init [--dir D]` | copies the example household; never overwrites | the files were written |

Periods are `2026-10`, `2026-Q3` or `2026`. `--as-of` defaults to today
and cuts every period: nothing dated after it is seen.

## Verdicts and exit codes

`hold` the policy is satisfied. `breach` a cap, floor or allocation is
not, or a red line has a matching row. `missing` a routine has no row in
its period, or the period has no ledger rows at all. `kill` the drawdown
crossed the threshold and no decision closed it. `stale` the holdings
snapshot is older than allowed. `unknown` and `invalid` below.

Every red verdict is a finding that names the policy and cites the rows
it rests on as `file:line`. Silence is a finding too: `EMPTY-PERIOD`,
`STALE-SNAPSHOT`, `DECISION-DUE`. Exact duplicate rows are `DUP-ROW`, a
warning that does not break green.

Exit codes: `0` green, `1` red, `2` usage, `3` a file could not be read
or parsed (a missing file, a wrong header, bad YAML, a policies.yml that
is missing its base currency). Row-level problems never stop the run.

## What is `unknown`

Qayd never guesses. A policy is `unknown` when its type, measure, limit,
match or band is not one of the declared shapes, or when a value cannot
be known from the files: a row in a currency with no rate on or before
its date, no holdings snapshot at all, a total of zero for a share, a
trailing window with no complete month. A policy is `invalid` when a
malformed ledger or holdings line (bad date, bad amount, undeclared
account or category, wrong column count) touches the period it looks
at; the line is named, and until it is fixed every policy that touches
that period stays red. Both are red: an answer Qayd cannot give is not
"fine".

`docs/FAILURE_MODEL.md` lists the ways the books lie and what Qayd does
about each today. `docs/CONSTITUTION.md` is the doctrine;
`docs/specs/ADR-0001-architecture.md` the design.
