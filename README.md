# Qayd Web

Qayd Web is personal finance as code, in one HTML file that runs in your browser.
You declare policies (a cap on spending, an emergency-fund floor, a monthly routine), keep a ledger and snapshots of what you hold, and record decisions with a review date.
A deterministic engine judges the files: every policy holds, breaches, is missing, stale or unknown, and every verdict cites the lines it rests on.
It never advises, never moves money, never connects to anything (no network after the page loads), and keeps no account or server.
It agrees byte for byte with the reference Python CLI (branch `qayd`) on the same files.

## Use it from the one file

1. Download `release/qayd.html` and open it in a browser (double-click, or
   drag it into a window). Open it directly, not inside another page or a
   preview pane: a sandboxed frame cannot store anything or download.
2. Press **Load the sample household** to see a synthetic household: on
   the Dashboard, set the as-of date to `2026-09-30` and read eight
   policies holding and one red finding (a decision past its review date).
3. Replace the sample with your own files on the **Files** screen: import
   each file, several at once, or paste the text.

**Where your data lives.** In this browser only, in its IndexedDB storage
for this page. Nothing is sent anywhere. Clearing the browser's site data
removes it; a private window may not keep it at all, and the app then says
so on every screen ("nothing will persist in this browser").
See `docs/FAILURE_MODEL.md` for every case.

**How to export.** The exported files are your household; the browser's
copy is a convenience. On **Files**, copy or download each of the five
files. On **Settings**, "Copy all files" or "Download all files" gives one
text bundle (`=== policies.yml ===` sections) that "Import the bundle"
reads back byte for byte. Keep the exported files under version control if
you want a history of your policies.

## Build from source

Needs Node 22 and npm.

```sh
npm ci                                  # exact dependencies from package-lock.json
npx vite build                          # dist/index.html, the one file (no other output)
npx vitest run                          # unit and differential tests
npx playwright test                     # end-to-end, Chromium (build first)
tools/gate.sh                           # everything CI runs, in order
cp dist/index.html release/qayd.html    # the release is the build, byte for byte
```

`npx playwright install chromium` fetches the browser once if it is
missing. The build is deterministic (no hash, no date in the output), so
`tools/gate.sh` requires `release/qayd.html` to be byte-equal to a fresh
build of the same commit.

Stack: Vite, TypeScript (strict), Preact, decimal.js (every amount is a
decimal, never a binary float), js-yaml, vitest, Playwright,
vite-plugin-singlefile. No CSS framework, chart library or state library.

## The five files

The full rules are the engine's: `reference/spec/ADR-0001-qayd-engine.md`.

| File | What it holds |
| --- | --- |
| `policies.yml` | base currency, accounts, categories (income, expense, transfer, invest), asset classes, the allowed snapshot age, and the policies: `cap`, `floor`, `allocation`, `kill`, `routine`, `red_line` |
| `ledger.csv` | one row per money movement; header `date,amount,currency,account,category,tags,note`; negative is money out |
| `holdings.csv` | snapshots of what you hold; header `date,account,asset,class,quantity,value,currency`; one snapshot is every row of one date |
| `decisions.yml` | decisions taken, each with criteria, a `review_by` date and `status: open` or `closed`; an open decision past its review date is a red finding |
| `rates.csv` | optional; header `date,currency,rate`; converts other currencies to the base currency |

Dates are ISO (`2026-09-30`). A malformed row is never dropped silently:
it is a problem with its `file:line`, and the policies it touches are
judged `unknown`.

## Screens

- **Dashboard**: the as-of date, the policy board (verdict, measure vs
  limit, every cited row on demand), the findings, the summary line.
- **Ledger**: rows newest first with filters; add a row; reverse a row
  (a new mirror row, never an edit); the raw CSV.
- **Holdings**: snapshots newest first, the current one's age; a new
  snapshot pre-filled from the latest; the raw CSV.
- **Decisions**: due first, then open, then closed; record and close
  decisions.
- **Policies**: grouped by type with today's verdicts; add, edit and
  remove through forms the engine checks; the raw YAML.
- **Review**: a month, quarter or year: the policy board month by month,
  income and expense, spending by category, allocation with its bands,
  findings, decisions, every cited row; "Copy as HTML" or "Download" give
  the same self-contained page the CLI writes.
- **Settings**: language (English, Arabic right to left), theme (system,
  light, dark), storage, export all, import all, erase all (two steps).
- **Files**: the five files with their counts; import, paste, copy,
  download.

## Keyboard

There are no keyboard shortcuts. Everything works with the keyboard
alone: the first Tab stop is "Skip to content", focus then follows the
page in reading order (right to left in Arabic) and is always visible;
Enter or Space opens a "why" or a raw panel; Enter submits a form.

## Accessibility

Every form control has a label, every verdict is a word (never colour
only), every chart has a title and a table beside it with the same
numbers, and nothing moves (motion is off under "reduce motion" in any
case). `e2e/a11y.spec.ts` checks labels, texts and tab order on every
screen in both languages.

Contrast ratios of the app's colours, measured from `src/ui/styles.css`
(WCAG 2 relative luminance; text needs 4.5:1, focus rings, bars and lines
3:1). A measurement of every rendered text on every screen, both themes
and both languages, found no text below 6.09:1 (light) and 7.09:1 (dark).

| Pair | Light | Dark |
| --- | ---: | ---: |
| text on page | 17.76 | 15.31 |
| text on panels | 16.28 | 13.86 |
| muted text on page / panels | 8.21 / 7.53 | 9.26 / 8.39 |
| placeholder on inputs | 8.21 | 7.82 |
| links, secondary buttons | 6.09 | 8.39 |
| primary button, current screen | 6.09 | 8.52 |
| danger button | 9.30 | 12.65 |
| chip hold (and green summary) | 7.84 | 9.49 |
| chip red (breach, due; red summary) | 7.60 | 10.12 |
| chip warn | 7.57 | 9.70 |
| chip neutral (open, closed) | 16.28 | 13.86 |
| red text (overdue, problems) | 9.30 | 12.65 |
| warn text (problems) | 8.56 | 14.63 |
| banner | 9.12 | 10.59 |
| focus ring on page / panels | 5.36 / 4.91 | 10.24 / 9.27 |
| chart bars income / expense | 5.19 / 5.44 | 6.98 / 6.04 |
| chart band line | 4.17 | 8.00 |
| chart "?" (no value) | 5.82 | 7.00 |

The page "Copy as HTML" gives is the CLI's own page, colours included, and
stays byte-equal to it; in its light theme the white text of four verdict
labels is below 4.5:1 (`hold` 4.25, `missing` 4.17, `stale` 3.25, and the
`warn` class text 3.25). That palette belongs to the reference engine and
is reported there, not changed here.

## Report an issue

Open an issue at <https://github.com/omanras/raqib/issues> with the
browser and its version, what you did, what you saw, and what you
expected. If a verdict looks wrong, attach the smallest household that
shows it, made up or with your numbers changed: never your real files.
Messages the app shows (`ledger.csv:273 UNKNOWN-CATEGORY ...`) can be
pasted as they are.
