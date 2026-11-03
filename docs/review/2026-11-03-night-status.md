# Night status, 2026-11-03 (the Table, for the commander)

Written while the last builder of the night runs; updated at the stop.

## Landed on main tonight (each: builder -> reviewer -> ruling -> REDO -> merge --no-ff, CI six jobs green)
| Task | What it gives you | Merge |
|---|---|---|
| M4.1 | rule kinds signature / demand / anchor; evasions listed; gate prints the ratio | 1974306 |
| M4.2 | every program a Bash command runs is recorded (`command_programs`); NET-TOOL and DESTRUCT-CMD see past `&&`, `|`, `bash -c`; SILENCE-EMPTY (high) catches the two empty field sessions | 8a4ca95 |
| M5.1b | the four path rules judge Windows paths (drives, UNC, `\\?\`); ASCII-only case fold; Windows xfails 0 | 9808f0f |
| M6.2 | dashboard v2: live band (WATCHING / SILENT / AGENT GONE / CAPTURE FAILED), findings by severity, live silence windows, `~/.raqib/watches.json` registry, `/discover` tab, `--refresh` | 5c6d463 |
| M5.0b | discover after the Kimi field test: Windows sample loop, "recent talk" from TIME_WAIT + DNS, `act-root` class (names kimi from one sample), first fp numbers (`raqib discover --check`) | 721bb55 |
| M5.2 | `raqib proxy`: any OpenAI- or Anthropic-speaking agent watched through its base URL; conversation sessions; hashes only; recording never breaks relaying | ed64d86 |
| M4.2b | `require:` construct; LANDED-NO-GATE (high) and EDIT-NO-TEST (medium): a `landed:` commit with no gate run before it, an edit under raqib/ or tests/ with no test run before stop; this project's own close reads CLEAN | (merge after M5.3) |
| M5.3 | `raqib os-sysmon`: the os source from Sysmon (events 1/11/3, read-only) + CROSS-SOURCE, the first anchor: asked-not-done / done-not-asked across sources | (this merge) |

Gate on main after M4.2b: 2213 passed, 7 skipped; kinds signature=4 demand=7 anchor=4 (Phase 4 exit met: demand + anchor > signature).

## Not done tonight (in the order I would take them)
- M4.3: git state anchors (handoff exists).
- M5.4 (to write): capture.py as a Kimi Code CLI hook (Kimi has PreToolUse/PostToolUse/SessionStart/SessionEnd/Stop, tool `Bash`); SCOPE-PATH tool-name map for other agents; doctor checks common.py; every watch timestamp on the wall clock.
- Table items: CI does not exercise an autocrlf=true clone; the local scope-guard hook reads only a line that is exactly `Scope:` and treats annotated entries as literal prefixes (handoffs now keep the header plain); LICENSE (yours); third reader.

## Tomorrow's field tests (your part), in order
1. Ubuntu VM: `git pull`, `pip install .`, `raqib doctor`, then `raqib watch <project>` and one Claude Code session; expect the band, one toast, the page at 127.0.0.1:8765.
2. Windows + Kimi, blind: README's PowerShell sample loop (6 samples, 10 s), then `raqib discover --from <folder>` with a catalog copy WITHOUT the Moonshot hosts and the `.kimi` footprint (B-10). The question: does `act-root` name kimi by shape alone?
3. Windows + Kimi through the proxy: `raqib proxy --listen 127.0.0.1:<port> --upstream https://api.moonshot.ai --log <trace> --cwd <project>`, set `base_url` in `~/.kimi-code/config.toml` to `http://127.0.0.1:<port>/v1`, run one Kimi task, then `raqib report <trace>`. First thing to check: the shape of Kimi's tool_call ids (numbered or random). Set base_url back afterwards (the key travels in the clear to whatever binds that port).
4. If Sysmon is installed there: `raqib os-sysmon --root <kimi pid> --log <trace>` alongside the proxy, then `raqib report` for the first CROSS-SOURCE finding.

## Decisions that are yours
- LICENSE for the public tree.
- Whether act-root's budget (0.25) and the candidate anchor's "2 of 2 benign desktops fire" are acceptable for v0.2, or whether the anchor gets a budget.
- Whether the proxy's `localhost` refusal (only `127.0.0.1:PORT` as Host) is too strict for Kimi's client.

## Ledger of the Table tonight (my errors, recorded in the ADRs)
Scopes that omitted README/gate.yml/cli.py (three STOPs on counts and words); "medium" for a silence rule against A3; "partial never silence" for a judged negative; an fp source named an evasion (C-11); a RED merge undone before push.

## Note (2026-11-03, M4.2b REDO builder, ruling H-9; the paper above stays as written)
Field item for tomorrow's first trace, before anything else: does Claude Code
record a Bash call that exits non-zero as PostToolUseFailure (ok false), as
tests/fixtures/posttoolusefailure-bash.json assumes? LANDED-NO-GATE and
EDIT-NO-TEST take the line's ok as the gate's or the tests' verdict; until the
trace says otherwise that fixture stands.
