# HANDOFF — M2.2  (phase 2: README, failure model, release build)

Task: documentation for a person who has never seen the CLI, the failure
model of a browser app, an accessibility pass, and the committed release.

Scope:
  README.md
  docs/FAILURE_MODEL.md
  release/
  src/ui/
  src/i18n/
  tools/gate.sh
  docs/review/

Exit criteria:
- E1 README: what Qayd Web is and what it never does (five lines); use
     it from the one file (`release/qayd.html`: open it, load the sample,
     where data lives, how to export); build from source; the five files
     in brief with a link to the engine spec; screens; keyboard shortcuts
     if any; how to report an issue.
- E2 docs/FAILURE_MODEL.md: browser storage cleared, private mode, two
     tabs, a pasted file with the wrong header, a policy loosened to pass,
     a reversal of a reversal, clock skew (as-of from the device clock),
     the sandboxed iframe case (downloads inert, copy works); what the app
     does today, what is open.
- E3 Accessibility pass on every screen: labels, roles, contrast of every
     chip in both themes (document the measured ratios), reduced-motion.
- E4 `release/qayd.html` = the gate's `dist/index.html` of this commit,
     committed; tools/gate.sh adds a check that release/qayd.html equals a
     fresh build (byte-equal, or equal after stripping a build hash,
     documented).
- E5 Gate green; CI green on the branch.

Not in scope: new screens or engine changes.
Commit: `landed: M2.2 readme, failure model, release` or `STOP: M2.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
