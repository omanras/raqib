# ADR-0007 - The host, not the name: Raqib watches a machine, not an agent it was told about

Status: proposed (the Table, on the commander's order, 2026-11-03).
Amendments appended, never edited in place.

## Problem
The commander's verdict after M6.4 (2026-11-03, 22:04): a watcher that
must be told which agent to watch, and which project, is not a watcher.
"How do I know there is no other agent on it?" Raqib has the mechanism
(ADR-0004: an agent is a process tree that talks to a model and acts on
the machine; `raqib discover`; AGENT-DARK), but it is a separate command,
on Windows it needs a PowerShell loop run by hand, it runs once, and
neither `raqib watch` nor the window starts from it. Everything that
watches starts from a name the commander already knows.

## Decision
Raqib's unit of watching becomes the host. The commander names nothing.
1. **Discovery is live and in-process on every platform.** On Windows
   the host's own records (processes and their parents, TCP connections
   with their owning process, DNS names where the host recorded them) are
   read through the OS API from Python's standard library (ctypes),
   read-only, with the least process right there is; no PowerShell, no
   loop by hand. Linux keeps /proc. The PowerShell loop stays as the
   fallback that an export can be repeated from (A5, A8).
2. **The host is watched continuously.** `raqib watch --host` (and the
   window) discovers at intervals for as long as it runs. A tree that
   starts talking and acting is a finding, NEW-AGENT, with a knock, named
   if the catalog knows it and "unknown" if not: an unknown agent is a
   finding, never a nothing. An agent footprint with no live tree is
   AGENT-DARK, live. "No agent seen" is said with the window and the
   records read, every time, never by silence (A3).
3. **Sources attach themselves.** For every tree discovered, Raqib
   attaches what it can without being told: a Claude Code image -> the
   hooks into the project that tree's cwd names; a Sysmon channel on
   the host -> the os source rooted at that tree; otherwise the host's
   own record of the tree (its connections, its children, its writes
   where the OS shows them) is a source of its own, judged by the rules
   that need no hook (NET-TOOL, DESTRUCT-CMD by program names, the
   silence rules, CROSS-SOURCE where two sources overlap). Nothing is
   signalled, attached to, or written to (A4).
4. **The unknown is judged by rhythm.** A tree that talks to an endpoint
   the catalog does not know is judged by the think-act cycle alone:
   periodic outbound traffic to one destination interleaved with process
   creation (ADR-0004 layer 3), thresholds not a model; the suspect layer
   may raise suspicion on it and never acquit (A2).
5. **The window starts from the host.** Its first screen is the machine:
   the agents found, each with its band, and one Start. The project
   field remains for a watch of one project.

What this does not promise, said now (A7): an agent that runs entirely
inside another program and acts only through that program's own hands
(a library in an IDE that never spawns a shell and never writes outside
its config) shows as a talker without an act, listed, not a candidate;
an agent that talks only to a local model with no socket at all is
invisible to layer 1 and 2 and is a named hole until layer 3 reads the
process's own file activity. These are recorded, not hidden.

## Consequences
- New `raqib/hostwin.py` (Windows live reader, ctypes), `raqib/host.py`
  (continuous discovery, NEW-AGENT, AGENT-DARK live, source attachment),
  the host record as a source (`source: host`), the rhythm anchor, the
  window's host screen. `raqib discover` with no files runs live on
  Windows as it does on Linux.
- CI: the live reader runs on both runners for a short window and must
  produce an inventory in which the reader itself is not a candidate.

## Candidates
- M7.1 Windows live discovery in-process (`raqib discover` live on
  Windows; `--save` keeps the samples as the CSV shapes).
- M7.2 `raqib watch --host`: continuous discovery, NEW-AGENT, AGENT-DARK
  live, source attachment, the host record as a source.
- M7.3 The window starts from the host.
- M7.4 Rhythm (layer 3) and suspicion on unknown trees.
Order: M7.1, M7.2, M7.3, M7.4. M5.4 (Kimi hooks) is no longer needed
for Kimi to be watched; it stays as a later convenience.
