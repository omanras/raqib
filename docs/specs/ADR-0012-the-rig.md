# ADR-0012 - The rig: Raqib watched while it watches

Status: accepted 2026-11-13, on the commander's order of that day: study, judge and run the development's own
experiments, so that the errors his field runs found are found before he is asked to try; and not with Kimi alone.
Amendments appended, never edited in place.

## Problem
Between 2026-11-10 and 2026-11-13 the commander's watches on two Windows machines found, one run after another:
a watch denied every read of the Sysmon channel that judged nothing; a report line that contradicted another; 216
lines of one hole; a tree's follow that never returned; Sysmon's times weeks behind; the same note three times.
Each had passed the gate, six CI jobs and one to three fresh reviewers. The gate runs the code on made-up records;
a reviewer reads what a path can do. Neither runs Raqib on a real machine beside a program whose acts are known and
reads what the whole report says. The first time that was done (a probe, 2026-11-13) it found in five minutes a
line of the report that contradicted another, and reproduced a question no test had been able to state.

## Decisions
1. The rig is a workflow of its own (`.github/workflows/rig.yml`), on every push to main and to a task's branch:
   Raqib installed from the checkout on a real Windows with a real Sysmon (installed by the job, every event of
   the kinds Raqib reads) and on Linux, running `raqib watch --host` while a stand-in agent works.
2. The stand-in agent (`tools/rig/workload.py`) is a program whose acts are known: it talks to a public host,
   starts a child that talks for twenty seconds, a short one, a shell, writes the clipboard, makes and deletes a
   file. What it prints is the ground truth.
3. The reader (`tools/rig/check.py`) states each expectation as MET, MISSED or OPEN, and each expectation names
   the field run that taught it. OPEN is a gap already recorded with its task: it is said every run until the
   task lands, and never fails anything. A new field finding becomes a new expectation in the commit that fixes it.
4. The rig reports; the gate decides. A MISSED expectation is a warning on the run and a line of its summary, not
   a failed job, until the Table makes it strict (a later amendment): a rig that fails merges for a slow network
   teaches people to ignore it. The Table reads the rig's summary before the commander is asked to try a build.
5. What the rig is not: it is no part of Raqib (nothing under raqib/ imports it) and no part of the capture path
   (CLAUDE.md rule 5 holds: the job, not Raqib, downloads Sysmon and reaches two public hosts). It needs no secret.
6. Next (each a task): real agents in place of the stand-in, each driven by a scripted model server on the
   runner itself (the agent is real, its instructions are fixed, no key and no cost), so more than one agent's
   own way of starting programs is watched; a watch that is not elevated; the window's opening time (M8.5).

## What the rig cannot show
A machine with a history: a Sysmon log that holds weeks, a clock that stood still while the machine was
suspended, an account that is not an administrator's, an agent that acts by its own choice. Those stay the
commander's field runs, and each one that finds something leaves an expectation or a made-up export behind.
