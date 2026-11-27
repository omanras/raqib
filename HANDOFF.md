# HANDOFF — none open  (M15.1, M14.1a, M15.2, M14.1b, M15.2b, M17.1, M15.3a, M13.1, M14.1c, M16.1, M15.3b, M14.1d, M17.2a, M17.2b, M12.4a, M12.4b, M12.4c1, M12.4c1b, M12.4c2a, M12.4c2a2, M12.4c2b1, M12.4c2b2a, M12.4c2b2b and M12.4c2b2c landed by 2026-11-27; the next tasks are on their own branches)

Task: none on main. Do not build here. Next, each on a branch of its own when the Table writes it: M12.4c2b3 (the service raises its check-point while its check walks; ADR-0013 U-4), M12.4c2b4 (`remove --purge` on Windows; ADR-0013 X-1), a live reader for macOS, M17.2c (the watch says at its start that a loader's variable was in its environment; ADR-0007 CI-4, CK-4), M15.3c (the watch reads Windows' autostart places and rules judge a change; ADR-0014 AL-6), M14.2 (a short connection given to its process; ADR-0007 CF-1, CF-4), M16.2 (a Splunk app from siem/).

From 0.2.0 on (ADR-0015): a merge into main that changes what Raqib does moves `raqib.__version__`, writes its entry at the top of CHANGELOG.md and runs `python3 tools/event_examples.py --write`. The Table does it in the merge.

Scope:
  (none)

If you were started as a builder on this file: STOP, commit nothing, and say that no task is open.
