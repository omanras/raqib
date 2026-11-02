# HANDOFF — M5.1  (phase 5: Windows plumbing - installer, lock, CI)

Task: capture + installer on Windows, gate proven there; no schema change, no
rule change (ADR-0003; ruling docs/review/2026-11-02-M5.1-ruling.md).

Scope:
  raqib/hooks/capture.py, tools/, tests/, .github/workflows/,
  README.md (platform lines only), docs/review/

Exit criteria:
- E1 `tools/install_hooks.py` replaces install-hooks.sh (.sh = one-line
     wrapper). Same merge semantics and idempotence; POSIX command unchanged;
     Windows command = interpreter + script path, quoted, no shell syntax
     (Q-7); modes/umask/symlink/fsync get a Windows branch. Tests: fresh,
     merge, second run unchanged, Windows command form.
- E2 `capture.lock()` uses `msvcrt.locking` on one byte far beyond EOF when
     `fcntl` is absent; no platform falls through to "no lock". Test: two
     processes appending concurrently never produce a duplicate seq.
- E3 `tests/test_capture.py` and any other test that imports POSIX-only
     modules at module level are platform-gated so the suite imports on
     Windows. Existing fixtures pass byte-for-byte.
- E4 `.github/workflows/gate.yml`: ubuntu + windows, Python 3.11 and 3.12;
     `tools/gate.py` runs the gate's checks (gate.sh stays and calls it on
     POSIX). Green on all four.
- E5 README: "Linux, macOS; Windows: capture and installer (path rules in
     M5.1b)". Note the Windows hook-error-not-block behaviour in one line.

Not in scope: any rule or engine change (M5.1b), `source` field (M5.2), UI.
Commit: `landed: M5.1 windows plumbing` or `STOP: M5.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
