# HANDOFF — M2.1  (phase 2: end-to-end proof)

Task: the full Playwright suite of docs/specs/ADR-0001-app.md §5 and the
file:// run of the single-file build.

Scope:
  e2e/
  playwright.config.ts
  tests/
  docs/review/

Exit criteria:
- E1 One spec per screen plus `offline.spec.ts`: `page.route('**/*')`
     records every request after load and asserts that none leaves the
     page origin (no http(s) request at all during a full tour of the
     app); `file.spec.ts` opens `dist/index.html` via `file://` and
     repeats the sample tour (IndexedDB may be unavailable there: the
     banner must appear and the app must still work).
- E2 A private-mode simulation: IndexedDB open rejected (inject a stub)
     -> in-memory banner, everything else works.
- E3 Mobile viewport (400x800) tour: no horizontal scroll, navigation
     reachable, forms usable.
- E4 Accessibility smoke: every form control has a label, every chip has
     text (not colour only), focus order follows the DOM.
- E5 All e2e green locally and in CI; gate green.

Not in scope: new features; fixes only inside the app code when a test
reveals a bug (list each fix in the questions file).
Commit: `landed: M2.1 end-to-end proof` or `STOP: M2.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
