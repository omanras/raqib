# HANDOFF — M9.1  (a stranger's first run: ADR-0010 decisions 1-6)

Task: what the outsider's rehearsal of 2026-11-11 found (docs/review/2026-11-11-outsider-rehearsal.md), fixed as
ADR-0010 rules it: a watch asked to stop ends with its report and its code; --version; a truer doctor line, finding
sentence, report line and quickstart.

Scope:
  raqib/watch.py, raqib/host.py, raqib/cli.py, raqib/doctor.py, raqib/report.py, raqib/rules/engine.py, raqib/rules/catalog/DESTRUCT-CMD.yaml and NET-TOOL.yaml (the summary line only), raqib/ruleform.py (B-6: the program form's summary line only), tests/, README.md, docs/review/

Exit criteria:
- E1 (decision 1) `raqib watch` and `raqib watch --host` from the terminal take SIGTERM and SIGHUP (where the platform has them) and SIGBREAK on Windows as a stop: "stopped (<signal's name>)", the final report, the registry row finished, exit 0 / 1 / 3. Handlers are installed by the CLI in the main thread only and the earlier ones restored; a second signal does not cut the report short; `raqib app` installs none; no process is signalled (A4). README says what stays out of reach (SIGKILL, TerminateProcess) and names `raqib report`.
- E2 (decision 2) `raqib --version` and `-V` print `raqib <version>`, exit 0; `raqib` alone still exits 2.
- E3 (decision 3) doctor: a working terminal fallback with no desktop notifier is UNSURE, said, and never fails the exit; notifications off stays MISSING.
- E4 (decision 4) DESTRUCT-CMD's and NET-TOOL's sentence names the program(s) the rule's list holds on the cited line, through the engine; the same lines fire, the same lines are cited, and no key of a finding (act registry, knock ledger, notification folding) changes - shown by tests on both sides.
- E5 (decision 5) the text report has one line under "ALARMS (A3, A5): N" saying what it counts and that a finding also makes the RESULT an ALARM; the JSON report, counts and codes unchanged.
- E6 (decision 6) README: the install block is clone, install, `pipx ensurepath`, `raqib watch`; doctor follows with the sentence about hooks MISSING before the first watch; the three first headings stay.
- E7 Tests, each decision's case and what it must not touch (D-8, Z-9), passing on the windows jobs: a real child process stopped by SIGTERM and by SIGHUP ends with RESULT and the right code (skipped with the reason where the platform has no such signal), SIGBREAK on Windows where the job can send it; Ctrl-C as before; the kinds 4 : 7 : 11 and every budget unchanged. Gate green, CI six green.
Not in scope: the README's restructuring (M9.2), a LICENSE (the commander's word), new rules, raqib/app.py, raqib/notify.py's behaviour.
Commit: `landed: M9.1 a stranger's first run` or `STOP: M9.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
