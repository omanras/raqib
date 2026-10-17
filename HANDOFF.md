# HANDOFF — M2.1  (phase 2: client shell, auth, circles list)

Task: the client foundation per ADR §5: tokens, i18n, auth and account
screens, My circles, create circle, join by invite link.

Scope:
  client/
  tests/e2e/
  playwright.config.ts
  docs/review/

Exit criteria:
- E1 Design tokens on :root (light/dark via prefers-color-scheme and a
     manual switch), one accent, system font stack with an Arabic-capable
     fallback, spacing scale, focus-visible styles, reduced-motion
     respected; mobile-first layout (360 px up), bottom navigation on
     narrow screens.
- E2 i18n: `client/i18n/en.ts`, `ar.ts` with every string; `dir=rtl` and
     `lang=ar` when Arabic; numbers Latin digits; dates ISO; a missing-key
     test fails the build (a script compares the two files' keys).
- E3 Screens: Sign in, Sign up (shows the 8 recovery codes once with
     "I saved them" confirmation), Recovery, Account (name, change
     password, sessions with sign-out-everywhere), My circles (role and
     status chips, outstanding badge), Create circle (name, currency,
     amount, period, due day, start date, rules text, recipient_pays),
     Join (`/join/<token>`: shows the circle summary, Accept).
- E4 API client with CSRF handling, request id surfaced in error toasts,
     offline-honest banner when a request fails (A10).
- E5 e2e: sign up two users; A creates a circle; A creates an invite; B
     opens the link and joins; both see the circle; Arabic switch shows
     RTL. Gate green.

Not in scope: circle screens, ledger screens.
Commit: `landed: M2.1 client shell, auth, circles` or `STOP: M2.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
