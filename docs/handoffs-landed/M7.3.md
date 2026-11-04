# HANDOFF — M7.3  (phase 7: the window starts from the host, ADR-0007 decision 5)

Task: `raqib app` opens on the machine, not on a project: the agents found on this host (the
M7.2 rounds), one Start that watches the host, the knocks from the window; a project watch stays.

Scope:
  raqib/app.py, raqib/host.py (API only), raqib/tray.py (tooltip only), raqib/cli.py (app options),
  raqib/ui.py (host page from app), tests/, README.md, docs/review/

Exit criteria:
- E1 First screen = HOST: the doctor lines folded under a "Checks" toggle (MISSING still
     shown open); a first discover round at open (the reader in a thread, the band says
     "reading the host..."; a reader late = the hole in the band); a table of trees: image,
     pid, named / unknown / benign, first seen, acts, endpoints (no command lines); "no agent
     seen (N records, M holes). Not a clearance." when empty; one button "Watch this host".
- E2 Watching the host: the same HostWatch as `raqib watch --host` in a worker (every 10 s;
     --every from the CLI); the table updates per round; a NEW-AGENT / AGENT-DARK-LIVE line
     and its knock (the same Notifier path as the project watch; own rate-limit ids); the
     band: WATCHING HOST / READER LATE / HOST READER FAILED / NOTHING READ; Stop ends the
     host watch with its final report in the window; close as M6.4; one host watch per home (C-2's refusal = a hole shown).
- E3 Project mode: a "Watch a project" button opens the M6.4 project screen (unchanged); host and
     project watches may run together; the tray tooltip says "Raqib: N trees, K new".
- E4 Nothing in the window signals, attaches to, or writes into any process or project (A4); writes stay under ~/.raqib.
- E5 Tests: the host screen's state->text with fake rounds (empty, trees, new tree, late
     reader, refusal); the worker start/stop with a fake HostWatch; Tk tests of the host
     screen skip without a display and run on windows CI; `raqib app --help` in the install
     job still passes. README: the window section says it opens on the host (two lines).
Not in scope: source attachment (M7.2b), rhythm (M7.4), macOS, autostart, page controls.
Commit: `landed: M7.3 the window starts from the host` or `STOP: M7.3 <reason>`.
Read HANDOFF.md and do only the task it specifies.
