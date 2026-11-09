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
- M4.2 programs in Bash commands; has_any; SILENCE-EMPTY (split 2026-11-03)
- M4.2b `require:` construct; LANDED-NO-GATE, EDIT-NO-TEST (demands)
- M4.3 git head/index at start and stop, read from files (no git process); HEAD-UNMOVED, INDEX-UNTOUCHED (anchors); STOP-DIRTY-TREE waits for a ruling on executing git
       Phase exit: demand + anchor > signature, and every signature's
       evasion list is in the tree.

## Phase 5 — Capture sources: hook, proxy, os (v0.2, ADR-0003, ADR-0004)
- M5.0 agent discovery: `raqib discover` finds a process tree that talks to a
       model and acts, with no prior knowledge of the agent (ADR-0004)
- M5.1 Windows plumbing: Python installer, lock fallback, CI matrix
- M5.1b Windows paths in the four path rules (norm_path in the engine)
- M5.0b discover after the Kimi field test: Windows sample loop, recent-talk evidence, act-root class, first fp numbers
- M5.2 proxy source + `source` field + hooks/common.py; first non-Claude
       agent (Kimi) watched through its model API           exit: E1–E6 in handoff
- M5.3 os source from Sysmon on Windows; CROSS-SOURCE anchor (landed 2026-11-03; asked-not-done,
       done-not-asked)
       Order: M5.1 (landed 2026-11-02), M5.0, M5.1b, M5.2, then rebase M4.2/M4.3 on the new capture shape, then M5.3.
       Phase exit: one agent other than Claude Code watched end to end, and
       one finding in the tree that no single source could have produced.

## Phase 6 — One command, a window, and a knock (ADR-0005)
Commander's verdict after the first field day (2026-11-02): use is the fatal
point. Phase 6 runs before the rest of Phase 5.
- M6.1 `raqib watch <project>`: install hooks, tail, incremental rules, OS
       notifications (Windows toast via file, notify-send, osascript), page
- M6.3 packaging: pyproject, `raqib` on PATH, `raqib doctor`, README around watch
- M6.2 dashboard v2: live band, severity order, several projects, discover tab
       Phase exit: a fresh machine goes from install to a toast on a real
       finding in under five minutes, by the README alone.

## Phase 7 — The host, not the name (ADR-0007; the commander's order, 2026-11-03)
- M7.1 Windows live discovery in-process (ctypes): `raqib discover` live on Windows; `--save` keeps the samples
- M7.1 landed 2026-11-04 (merge 4f6b6a5): the live reader found GitHub's own runner agents on the windows job by shape alone
- M7.2 `raqib watch --host`: continuous discovery, NEW-AGENT / NEW-AGENT-UNKNOWN / AGENT-DARK-LIVE (landed 2026-11-04, merge b3e5ba4; kinds 4 : 7 : 9)
- M7.2b reading sources attach themselves: os / host record per tree; hooks only with --attach-hooks (Amendment H; landed 2026-11-04, merge 0e0956d; kinds 4 : 7 : 10)
- M7.3 the window starts from the host (landed 2026-11-04, merge 843aa72; ADR-0007 accepted)
- M7.4 rhythm (HOST-RHYTHM) and suspicion on unknown trees (landed 2026-11-04 locally; kinds 4 : 7 : 11; CI held - Actions minutes)
- M7.5 after the first field run (ADR-0007 Amendment M): dark-after-live is a note; rhythm reads every source; the missing knock
- M7.6 the rules control panel in the window (which rules run, thresholds, on/off per rule; a rule off is said in the report); the window's look
