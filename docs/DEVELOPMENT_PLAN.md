# Development plan — three weeks, one credit

Budget: the cloud-session credit (expires 2026-11-05). Measure cost per loop
iteration on day 1 (`total_cost_usd` in `.loop/*.json`) before leaving the loop
unattended.

## Phase 0 — Capture (week 1, days 1–3)
- M0.1 capture hook (Pre/PostToolUse → JSONL)            exit: E1–E4 in HANDOFF
- M0.2 session boundary + gap detector (A3)              exit: a 60 s gap in a
       fixture log yields a `SILENCE` event with start/end/seq range
- M0.3 install script + README quickstart                 exit: fresh clone →
       `tools/install-hooks.sh` → one real Claude Code call → one log line

## Phase 1 — Rules (week 1–2)
- M1.1 rule schema (YAML) + loader + fixture runner       exit: 3 rules, each
       with ≥1 positive and ≥1 negative fixture, gate green
- M1.2 rule set v1: path-outside-scope, network-from-tool, destructive-command,
       secret-in-output, scope-drift (edits touching >N files not in HANDOFF)
- M1.3 findings format + `raqib report` CLI               exit: report cites
       trace lines (A5); FP budget per rule declared (A6)

## Phase 2 — Suspicion layer (week 2)
- M2.1 schema-constrained model call (local Ollama OR API, configurable);
       output: {suspicion: 0..1, reasons[], cited_seq[]}; A2 enforced in code
- M2.2 evaluation harness: 50 fixture events (25 benign / 20 suspicious /
       5 deceptive); report FN and FP; model choice decided by FN first

## Phase 3 — Dashboard + release (week 3)
- M3.1 minimal web UI: timeline, findings, silence windows (read-only)
- M3.2 docs: README (2-minute read), threat model, CONSTITUTION link
- M3.3 first external reader: one person outside the project runs the
       quickstart and files one issue. This is the real exit criterion.

Out of scope for v0.1: blocking/steering the agent (A4), multi-host, auth.

## Phase 4 — Rules that survive being read (v0.2, ADR-0002)
- M4.1 rule kinds: signature | demand | anchor; signatures list evasions;
       gate prints the ratio                           exit: E1–E5 in handoff
- M4.2 programs in Bash commands; LANDED-NO-GATE, EDIT-NO-TEST (demands)
- M4.3 git head/clean at start and stop; STOP-DIRTY-TREE, HEAD-UNMOVED (anchors)
       Phase exit: demand + anchor > signature, and every signature's
       evasion list is in the tree.
