# Qayd Web — failure model

Qayd Web is one HTML file that keeps five text files in the browser and
judges them with a deterministic engine. Everything that can go wrong
lives in two places: the browser holding the files, and the person
changing them. For each case below: what happens, what the app does
today (v0.1), and what is open. "Open" items are not built; they are
recorded so that nobody mistakes their absence for safety.

The rule behind every answer: the exported files are the household. The
browser's copy is a convenience. Silence (no banner, no finding) is only
as good as the case list below.

## 1. Browser storage cleared

**What happens.** The five files live in IndexedDB (database `qayd`) for
the page's origin. The person clearing "site data", a privacy extension,
or the browser evicting storage under disk pressure removes them. For a
page opened from disk, the origin is the browser's `file://` origin:
Chromium shares one storage for every `file://` page, so every copy of
`qayd.html` on that machine sees the same household; other browsers may
give each file its own origin (moving or renaming the file then leaves
the stored household behind) or refuse storage to `file://` entirely.

**Today.** After a clear, the app opens on the empty state with every file
"absent": it cannot know the files ever existed. Nothing is lost that was
exported. Settings shows the storage in use ("IndexedDB: the files persist
in this browser"). Only Chromium is tested (`e2e/file.spec.ts` records
that IndexedDB works from `file://` and survives a reload).

**Open.** The app does not ask the browser for persistent storage
(`navigator.storage.persist()`), so eviction under disk pressure stays
possible. There is no "last exported" date and no reminder to export.
Browsers other than Chromium are not verified for `file://`.

## 2. Private mode

**What happens.** Some browsers refuse IndexedDB in a private window
(the open request fails, or throws); some offer it and wipe it when the
window closes.

**Today.** When IndexedDB is missing, throws, fails to open, does not
answer within 4 seconds, or refuses a later write (quota), the app keeps
working in memory and shows a banner on every screen: "IndexedDB is not
available: nothing will persist in this browser. Export your files before
you close this tab." Settings says "Memory only". A reload then starts
empty, as the banner said. Each of these six ways is simulated in
`e2e/private-mode.spec.ts` with the full sample tour.

**Open.** A private window that does offer IndexedDB (and deletes it at
close) looks exactly like a normal window to the page: no banner shows
there, and closing the window loses the household. The app cannot detect
this; only the export protects against it.

## 3. Two tabs

**What happens.** The same household is open in two tabs (or two windows)
and both change it.

**Today.** Every write stores whole files and is announced to the other
tabs (BroadcastChannel, or a `storage` event). The other tab reloads the
files and says "Another tab changed the household; this tab now shows the
latest files." The last write wins, file by file. Forms (add a row, a
snapshot, a decision, a policy) are checked against the newest text when
they are submitted. Tested in `e2e/shell.spec.ts`.

**Open.** An unsaved edit in a raw panel is replaced by the other tab's
text when that tab writes the same file, without a warning. Two writes to
the same file within the announcement delay (milliseconds) are not merged:
the later one replaces the earlier. There is no lock and no merge.

## 4. A pasted or imported file with the wrong header

**What happens.** A CSV is pasted under the wrong name, exported from a
spreadsheet with its own header, or saved in a non-UTF-8 encoding.

**Today.** The file is refused before it reaches the store, with the
reason and what was expected: "Refused ledger.csv ... Expected header:
date,amount,currency,account,category,tags,note ... First line: ...".
Also refused: bytes that are not UTF-8, an empty file, a file of 64 MB or
more, a YAML file the engine cannot parse, a name that is not one of the
five. The stored file is unchanged. A file with the right header but bad
rows is accepted: every bad row is a problem with its `file:line`, and
every policy touching that row's period is judged `unknown`, not `hold`.
The raw panel cannot save a text with a blocking problem.

**Open.** A CSV whose columns are consistently shifted under a correct
header (amount in the note column, say) is caught only row by row, as
problems; the app does not guess what was meant.

## 5. A policy loosened to pass

**What happens.** A cap is breached; the owner raises the limit (or
removes the policy) until the dashboard is green.

**Today.** The edit is checked by the engine and saved; the dashboard
follows. Removal asks first and shows exactly what disappears as of the
as-of date (the verdict line, its findings, the decisions that name it).
An edit asks nothing. The review page prints each policy's declared text,
so a printed or exported review keeps the limit that was in force; the
exported `policies.yml` under the owner's own version control keeps the
history.

**Open.** The app keeps no history of `policies.yml`: an edit that turns a
breach into a hold leaves no trace in the browser. There is no "this edit
changes today's verdict from breach to hold" confirmation, and no rule
that a loosening needs a decision in `decisions.yml`. The app never
judges intent; the files are the record.

## 6. A reversal of a reversal

**What happens.** "Reverse" appends the mirror row (same date, opposite
amount, tagged `reversal`, note `reverses ledger.csv:N`). The owner may
reverse the reversal, or reverse the same row twice.

**Today.** Both are allowed and both are plain ledger rows; the arithmetic
is exact. Reversing the same row twice appends an exact duplicate of the
first reversal, which the engine reports as `DUP-ROW` (warn) and the
outcome says so. Reversing a reversal appends a row that re-applies the
original amount; it is also tagged `reversal` and cites the reversal it
undoes, so the chain can be read back line by line.

**Open.** The app does not follow the chain: it does not say "this row is
already reversed" and does not mark the re-applied row differently from a
reversal. Nothing deletes or edits a line; corrections are always new
lines.

## 7. Clock skew (as-of from the device clock)

**What happens.** The as-of date defaults to today by the device clock,
in the device's time zone. A wrong clock, or a time zone where the date
differs from the owner's, moves "today".

**Today.** The as-of date is printed on every judgement ("RED as of
2026-09-30: ...") and on the review page. It can be typed; once typed it
is kept (also across reloads) until "Today" is pressed. The engine never
reads the clock: the same files and the same as-of date give the same
verdicts on every machine.

**Open.** A kept as-of date does not move with the calendar: a household
judged at an old date shows no decision falling due after it. The app
does not warn that the as-of date is not today, nor that the device date
is earlier than the newest row in the files.

## 8. Inside a sandboxed iframe

**What happens.** The file is shown inside a sandboxed frame (a preview
pane, a web mail attachment viewer, an online HTML viewer).

**Today.** Without `allow-same-origin` the frame has no storage: the
in-memory banner shows (case 2). Without `allow-downloads` the Download
buttons do nothing, silently: the browser drops the object-URL download.
Copy always works: the clipboard API first, then a hidden selection, and
when both are refused the text is shown in a box to select and copy by
hand. Navigation uses the URL hash, so it works without a server.

**Open.** The app cannot tell that a download was dropped, so it cannot
say so. The advice in the README is to open the file directly in the
browser, not inside another page.

## What is never a failure mode here

No network: the page makes no request after it loads (`e2e/offline.spec.ts`
fails on any). No account, no server, no telemetry: nothing about the
household leaves the browser except what the owner copies or downloads.
