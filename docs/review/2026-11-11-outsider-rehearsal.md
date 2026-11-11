# The outsider's rehearsal of 2026-11-11 (issue drafts), as received

Filed by the Table, 2026-11-11. Made by another session at the commander's order, on main 0e8b007; handed to the
Table by the commander with the words "fix the errors". The text below is unedited from its second line on.
Checked by the Table against the tree before ruling: watch.py, host.py and cli.py install no signal handler (run:
`raqib watch` killed with SIGTERM ended 143 with no RESULT line); `raqib --version` exits 2; DESTRUCT-CMD's and
NET-TOOL's summary print command_head; report.py prints "ALARMS (A3, A5)" with no word on what it counts;
doctor's notifier is MISSING on a working terminal fallback; the README's quickstart runs doctor before watch and
names no `pipx ensurepath`; there is no LICENSE file and no license field. Rulings: ADR-0010.


Two drafts, ready to paste into GitHub: one behaviour bug, one first-run checklist.
Nothing here has been filed.

**How it was run.** Clean `HOME`, no prior Raqib state, README followed literally.

| | |
|---|---|
| Commit | `0e8b007` (2026-11-11), raqib 0.1.0 |
| OS / Python | Ubuntu 24.04, Linux 6.18, Python 3.13.18 |
| Installer | pipx 1.4.3 |
| Claude Code | 2.1.322 on PATH |

**Limit of this rehearsal.** No real Claude Code session was driven. Hook events
(SessionStart, PreToolUse, PostToolUse, Stop, SessionEnd) were piped as JSON into
the exact hook command that `raqib watch` installed in `.claude/settings.json`.
Capture, rules, page and report were exercised; Claude Code's own delivery of the
hooks was not.

---

## Issue 1 — `raqib watch`: SIGTERM and SIGHUP end the watch with no final report and no Raqib exit code

**Labels:** bug, watch

### What happens

| Signal | Process exit | `raqib watch: stopped` line | `RESULT:` line |
|---|---|---|---|
| SIGINT (Ctrl-C) | `1` (ALARM, correct) | yes | yes |
| SIGTERM (`kill`, `systemctl stop`, `docker stop`) | killed by signal 15 (shell sees 143) | no | no |
| SIGHUP (terminal closed, ssh dropped) | killed by signal 1 (shell sees 129) | no | no |

Same project, same trace (5 findings in it) for all three runs.

### Reproduce

```bash
raqib watch ~/my-project --no-open > out.txt 2>&1 &
sleep 4
kill -TERM $!        # or: kill -HUP $!
wait $!; echo "exit=$?"          # 143 (or 129)
grep -c '^RESULT:' out.txt       # 0
```

For comparison, Ctrl-C on a foreground `raqib watch` gives exit 1 and one
`RESULT: ALARM (exit 1)` line. (Compare in the foreground: a shell script starts
background jobs with SIGINT ignored, so `kill -INT $!` in a script does nothing.)

### Why it matters

- README, "Watch a project": *"Ctrl-C, or a crash, prints the final report"*. A reader
  takes `kill`, a closed terminal or a stopped service to be covered by that sentence.
  They are not.
- The exit codes are the contract (0 clean / 1 alarm / 3 incomplete). Under systemd,
  Docker or CI the watch is normally stopped by SIGTERM, so a supervisor sees 143 and
  never learns the verdict.
- `raqib/watch.py` handles `KeyboardInterrupt` and `Exception` (the B-4 crash path),
  and nothing registers a handler for SIGTERM or SIGHUP, so `conclude()` is skipped.

### What is *not* broken

- Nothing is lost. The trace is intact, and `raqib report <trace> --scope .` reproduces
  the same findings afterwards.
- The registry row stays `status: "watching"`, `finished: null`, but the watch page
  already reads such rows as GONE from pid and heartbeat.
- The review notes already record the in-process limit
  (`docs/review/2026-11-03-M6.1-redo.md`, X8). The gap is that the README promises more
  than that note allows.

### Suggested fix (either one closes it)

1. In `raqib watch`, treat SIGTERM and SIGHUP (where the platform has them) like Ctrl-C:
   run `conclude()`, print the final report, exit 0/1/3. SIGKILL stays out of reach and
   the README can say so.
2. Or keep the behaviour and correct the README: "Ctrl-C or a crash of the watcher prints
   the final report; a watch that is killed prints none: run `raqib report <trace>`."

---

## Issue 2 — First-run friction seen by an outsider (checklist)

**Labels:** docs, ux

What went well first, since it is most of the story: clone 1.2 s, `pipx install` 5.8 s,
zero dependencies pulled, `watch` installed all six hooks and served a page with no
`<script>` tag, the rules fired as documented (DESTRUCT-CMD, NET-TOOL, SCOPE-PATH,
SILENCE-HALF, SECRET-OUTPUT), placeholder keys were not alarmed, the trace held no
command text, no file content and no secret, and `tools/gate.sh` ended
`3479 passed, 72 skipped` and `[gate] GREEN` in 203 s.

The items below are small. Each cost a newcomer a moment of doubt.

- [ ] **Step 3 of the quickstart always fails on a first run.** The README order is
  `doctor` then `watch`, but `doctor` exits 1 with
  `MISSING hooks ... missing for all 6 events; raqib watch installs this raqib's`.
  That is true and documented ("exit 1 if anything is missing"), yet the first command
  a stranger runs after installing reports failure on a healthy setup.
  *Suggest:* swap the two lines, or add `# hooks MISSING is expected before the first watch`.

- [ ] **`MISSING notifier` on a headless Linux box.** Output:
  `MISSING notifier terminal bell and stderr only (no /usr/bin/notify-send ...)`.
  `watch` works with that fallback, so MISSING (and exit 1) overstates it.
  *Suggest:* a softer level for a working fallback, kept out of the exit code.

- [ ] **No `raqib --version`.** It exits 2 with
  `error: the following arguments are required: command`. The version is only visible
  inside `raqib doctor`. It is the first thing asked for in a bug report.

- [ ] **DESTRUCT-CMD names the wrong program.** For a command read as
  `["curl", "bash", "rm"]` the finding says
  `Bash runs curl at seq 3 (programs ["curl", "bash", "rm"])`.
  The summary template prints `command_head`, while the match came from `rm` in
  `command_programs`. *Suggest:* name the matching program(s) in the sentence.

- [ ] **`ALARMS (A3, A5): 0` above `FINDINGS: 5` and `RESULT: ALARM (exit 1)`.**
  A reader who does not know the constitution sees "zero alarms" and "alarm" in the
  same report, including a `[high]` finding. *Suggest:* one line under the header saying
  what the ALARMS count covers and that any finding also yields RESULT: ALARM.

- [ ] **pipx PATH warning is not mentioned.** On a fresh machine pipx warns that
  `~/.local/bin` is not on PATH and `raqib` is then "command not found".
  *Suggest:* add `pipx ensurepath` to the install block.

- [ ] **README density.** 547 lines, 51 KB; line 57 alone is 3,580 characters, line 80 is
  1,462. It reads as a ruling-by-ruling changelog. Everything in it is precise, but the
  stranger's questions (what is it, does it work on my machine, what does an alarm look
  like) are buried. *Suggest:* keep the top to one screen with a sample final report, and
  move the per-milestone detail to `docs/`.

- [ ] **No LICENSE file and no `license` field in `pyproject.toml`.** Without one the
  default is all rights reserved, so others have no clear permission to use, modify or
  redistribute a repository that presents itself as open. Separate from this rehearsal,
  listed so it is not lost.
