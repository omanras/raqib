# HANDOFF — M5.1  (phase 5: Windows support)

Task: make capture, installer, rules and gate work on Windows without any
change to the trace schema (ADR-0003, first candidate).

Scope:
  raqib/hooks/capture.py, raqib/rules/context.py, tools/, tests/,
  .github/workflows/, README.md (platform lines only), docs/review/

Exit criteria:
- E1 `tools/install_hooks.py` replaces install-hooks.sh (keep the .sh as a
     one-line wrapper calling it). Same merge semantics, same RAQIB-SILENCE
     behaviour, `python` or `python3` resolved at install time. Tests on a
     temp settings.json: fresh, merge, second run unchanged.
- E2 `capture.lock()` uses `msvcrt.locking` when `fcntl` is absent; no
     platform may fall through to "no lock". Test: two processes appending
     concurrently never produce a duplicate seq (run on both OSes).
- E3 One function `norm_path()` (hooks + rules) normalises separators and
     case for comparisons; SCOPE-CWD-*, SCOPE-PATH, DRIFT-FILES use it.
     Fixtures with `C:\...` paths, positive and negative.
- E4 `tools/gate.py` runs the same checks as gate.sh (gate.sh stays and
     calls it on POSIX). `.github/workflows/gate.yml`: ubuntu + windows,
     python 3.11 and 3.12, gate must be green on all four.
- E5 README: "Linux, macOS, Windows"; one line on Sysmon not being needed
     for M5.1. Gate green locally and in CI.

Not in scope: new sources or `source` field (M5.2), new rules, UI.
Commit: `landed: M5.1 windows support` or `STOP: M5.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
