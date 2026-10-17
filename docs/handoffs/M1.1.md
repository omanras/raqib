# HANDOFF — M1.1  (phase 1: store, import/export, app shell)

Task: persistence and the application shell per docs/specs/ADR-0001-app.md
§2 and the shell parts of §3.

Scope:
  src/store/
  src/ui/
  src/main.tsx
  src/i18n/
  index.html
  tests/store/
  e2e/
  docs/review/

Exit criteria:
- E1 `src/store/household.ts`: load/save the five file texts and meta in
     IndexedDB (db `qayd`, stores `household`, `meta`); if IndexedDB is
     unavailable or throws, an in-memory store with a visible banner
     "nothing will persist in this browser"; two tabs: last write wins,
     and a `storage`-style broadcast (BroadcastChannel if present) reloads
     the other tab.
- E2 Import: per-file inputs and a paste panel; a file with the wrong
     header is refused with the expected header shown; export: copy
     button per file (clipboard API with fallback to a selected textarea)
     and a download link per file.
- E3 Sample loader bundles reference/examples/* as strings (`?raw` at
     build time); "Load the sample household" on the empty state.
- E4 Shell: left navigation (Dashboard, Ledger, Holdings, Decisions,
     Policies, Review, Settings), theme tokens on :root for light/dark
     (system + manual), `dir` and `lang` switch to Arabic ready (strings
     file with every key, Arabic values may be placeholders here, M1.3
     fills them), responsive to 400 px wide, keyboard focus visible.
- E5 e2e: empty state -> load sample -> the shell shows the five files'
     row counts; reload keeps them; export copies text equal to the
     bundled file. Gate green.

Not in scope: the screens' content (M1.2-M1.4).
Commit: `landed: M1.1 store, import/export, shell` or `STOP: M1.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
