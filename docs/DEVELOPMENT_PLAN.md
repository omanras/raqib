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
- M7.5 after the first field run (landed 2026-11-09, merge 33c102d): dark-after-live a note within a 9-round window; rhythm reads every source; the KNOCKS ledger
- M7.6 the rules panel (ADR-0008; landed 2026-11-09, merge da57d36): overlay, `raqib rules`, the panel, rules off said everywhere
- M7.6b the window's look pass (landed 2026-11-09, merge d060c40; ADR-0008 accepted)
- M7.6c thresholds that can be measured (landed 2026-11-09): edge pairs per field, bounds in the YAMLs, k/w/r/streak/live_window editable on a sensitive measurement
- M7.7 os_sysmon writes ProcessId on process lines (ADR-0007 Amendment O); CROSS-SOURCE over host lines
- M7.8 the second field run's lessons (landed 2026-11-11; ADR-0007 Amendments P, R, T, V, W): os lines judged by NET-TOOL / DESTRUCT-CMD, one act one finding in every order, benign trees noted, quiet is not gone, Defender benign, THREAT_MODEL's host section
- M7.9 the round reads the channel (landed 2026-11-11; ADR-0007 Amendments X, Z, AA-AE; P-4): where Sysmon is read, a tree that lives between two rounds is a tree of that round, sourced, its acts judged; a named one knocks, an unknown one known only from the channel is listed and counted (AA-1: the field decides); footprints are judged without the channel (AD-1)
- M7.10 AGENT-CLIPBOARD (P-5, Sysmon event 24's header): waits for the commander's word and a real export
- M7.11 a benign host of a model client (ADR-0007 T-9): a benign program that talks to a model endpoint the catalog names is listed with that word
- M7.12 the tree ledger and its keys (ADR-0007 AB-11, AD-1, AD-2): a bound on by-the-channel trees in the state and the report; one tree for a process whose sampled start is unread and its guid; a footprint whose agent ran only between rounds Also recorded for it (ADR-0007 AL-4 to AL-6): an act's record names its source; one file name rule for a tree's host record; a feed attached again keeps its epoch; the property tests with a follow that reads.
- M7.13 the third field run (landed 2026-11-11; ADR-0007 Amendments AF, AG, AH; docs/review/2026-11-11-third-field-run.md): a watch that cannot read the channel judges by the host's own record, knocks once for it, and its report says it in one line
- M7.14 a follow that returns (landed 2026-11-12; ADR-0007 Amendments AI, AJ, AK, AL; the watches of 2026-11-12): a tree's os follow asks the channel a bounded question; a tree whose follow reads nothing is judged by the host's own record too
- M7.15 recorded: a process of another account whose start time the reader does not read though the system lists it
- M7.16 an event's time is when it was logged (landed 2026-11-13; ADR-0007 Amendments AM, AN, AO; docs/review/2026-11-13-the-elevated-watch.md): Sysmon's network events stamped weeks behind are no longer history; the lag is a note; a rule's not-judged note is one note
- M7.17 the rhythm of a tree that is not in the round (landed; ADR-0007 AP to AS): a beat is judged in the round that reads it, for a quiet, a kept and a gone tree, by the one code that writes a candidate's line; the ring has every round; the rig's X12
- M7.18 an unknown tree with an agent's rhythm is high (ADR-0007 Amendment AT; the commander's word, 2026-11-13): measured on two real agents the catalog does not name, on Windows with Sysmon and on Linux; the catalog is a label, never a condition
- M7.19 recorded: the seams of a source's life (ADR-0007 AS-5, AS-6): a follow's last pass at its stop; the beats carried over an attach; a quiet tree gone by an empty sample; a hooks source read per session; the sources of gone trees bounded on a long watch
- M7.20 one server, one os destination (landed; ADR-0007 AU, AW, AX): an os talk's destination is the hash of the server's address, port and protocol, written only where the host watch's follow asks; found on real agents on Windows; AU-3 withdrawn
- M7.21 in hand (the Table measures on the Windows runner first: what the tracing gives, and what starting it needs): the bytes of a connection on Windows, read by the kernel's tracing (ETW), listening only (ADR-0007 BK, the commander's word 2026-11-13): a kept connection's talks are then seen each turn, as on Linux
- M7.22 a process under the root of a tree the watch holds is that tree's, and no ancestor's (landed; ADR-0007 AX-4, AY, AZ, BA): the first false HOST-RHYTHM at high, on a runner's own tree, from a quiet agent's commands
- M7.23 recorded: the server's hash salted with a secret of the running watch (ADR-0007 AX-1)
- M7.24 landed: an os follow marks what is under another tree's root (`input_meta.under_root`) and a marked os line gives its tree no beat (ADR-0007 BB as BC and BD corrected it): the parent of an agent no longer makes HOST-RHYTHM from the agent's commands on Windows with Sysmon; nothing is left out of any file; held by a field run with a real agent under a talking launcher
- M7.25 recorded (ADR-0007 BA-2): a source of process and connection events on Linux, so that what happens between two samples is seen (an agent no sample saw talking; a connection for each turn)
- M7.26 landed: a reused pid is not a parent (ADR-0007 BE, BF, BG): a parent link holds only where the parent did not start after the child, and the watch's own tree is made of dated links only; on Windows a watch given a dead parent's pid took the whole machine for its own and saw nothing (the field, 2026-11-13, twice in twelve); held by a field run in which the watch was given a dead parent's pid and still listed its orphan
- M7.27 landed: the watch's own tree is what the watch started, by a record of pid, time and image (ADR-0007 BH, BI, BJ); a reused pid, a parent spoofed as the watch, or a clock set back no longer make it count its own as an agent or an agent as its own, as far as pid, time and image tell; held by a field run that started a talker beside the watch under their launcher and saw it listed
- M8.1 the look (landed 2026-11-11; ADR-0009 Amendments A-D, decisions 1-3 accepted): rail, verdict header, the round strip, switches, the watch's own code in its state, opens and fits on Windows
- M8.2 a rule made from a form, and Remove for user rules (landed 2026-11-11; ADR-0009 Amendments E-H, decisions 4-5 accepted): `raqib rules --new / --remove`, the form with its Test and "on your records", class USER, Remove by the row's own place, checks first
- M8.3 the window's notes after M8.2 (ADR-0009 H): a log of what the catch-alls caught, the orphan overlay entry's words, a real watch under the form's "running" test, a way for the person to name a program benign
- M8.4 the window opens (landed 2026-11-11; ADR-0009 Amendment I; the third field run's first minute): a stretched picture's middle is a tile wide, so a redraw is dozens of blits and not hundreds of thousands (the commander's white window, 19 to 87 s on Windows by scale); the painter samples only the pixels an arc crosses
- M8.5 recorded with it: a timing probe of the window's opening in CI on each system, reporting and never failing; Python 3.14 in CI's matrix

## Phase 9 — A stranger's first run (ADR-0010; the commander's order, 2026-11-11)
- M9.1 what the outsider's rehearsal found (landed 2026-11-11; ADR-0010 Amendments B-D, decisions 1-6 accepted): a watch asked to stop ends with its report, its record and its code (SIGTERM, SIGHUP, Ctrl-Break; a terminal that is gone costs the words only); `raqib --version`; doctor's notifier line; a finding names the program that made it; the ALARMS lines say what is counted; the quickstart's first command succeeds
- M9.2 the README's top is one screen (landed 2026-11-11; ADR-0010 Amendments E-F, decision 7 accepted): README 556 lines to 106, the code's own sample report, "Where it runs" written fresh and pinned, the window first among the commands; everything else word for word in docs/GUIDE.md, each pin following its sentence
- M9.3 a LICENSE and the `license` field (landed 2026-11-11; ADR-0010 Amendment A): CC0 1.0 Universal, the commander's word
- M9.4 the terminal's knock and its page (ADR-0010 C-6, D-3): a bell rung on a terminal that is gone is a failed knock (notify.py); the page shows the lost-words note; the record written once more after the report; signals after the first said; `raqib watch P >&-`

## Phase 10 — Below the agent, beside other watchers (ADR-0011, accepted 2026-11-13 with Amendment A)
Amendment A (his ruling): Raqib is passive toward other systems and may itself send its events, one way; it sends everything it judged; a finding stands with or without an agent's tree. Its order: the event (`raqib-event/1`, technique ids, a heartbeat); the
sinks (Event Log, syslog); the service; accounts, logons, tasks, services and a tree's reach; the proxy joined to
the host watch and PROXY-BYPASS; file reads, measured first.
- M10.1 the event (landed; ADR-0011 Amendments B to E): `raqib-event/1` as a shape, the one pure module that builds it, the rules' ATT&CK ids, docs/specs/EVENT.md with its mapping to OCSF and ECS
- M10.2 landed: the watch writes its events to a file beside its record, and a heartbeat on a fixed beat; it keeps each event's number and says a changed thing again (ADR-0011 F, G, H, I); `raqib events FILE` checks a file; the rig holds it (X16 to X18)
- M10.3 landed: `raqib forward`, a process of its own, sends the events file's lines to one HTTP collector (the line as written, or the Splunk-HEC envelope), at least once and in order, with its own state and `--status`, the token off every output, certificate verification that nothing turns off, and no line skipped however a collector or a writer of its files behaves (ADR-0011 Amendments J, K, L, M, N, O)
- M10.3b landed 2026-11-13: the forwarder over syslog (udp, tcp, tls), RFC 5424 with octet-count framing, the same cursor machine as HTTP, no token over syslog (J-6, J-14, P, Q); `written` is a connection ended in order, and what it cannot tell is said (Q-3); rig X23 to X25. Recorded: real collectors (rsyslog, syslog-ng) on the rig; the header's fallback counts nothing
- M10.3c recorded: the local sinks (the Windows event log, the journal); OCSF and ECS documents built by Raqib; a real Splunk on the rig (needs the commander's word on its licence); the forwarder as a service
- M10.4 recorded: the window's panel for the link

## Phase 11 — The rig (ADR-0012; the commander's order, 2026-11-13)
- M11.1 the rig (landed with ADR-0012): a workflow of its own; a real Windows with Sysmon and Linux; a stand-in agent whose acts are known; tools/rig/check.py states each expectation MET, MISSED or OPEN; reports, does not fail
- M11.2 real agents in the rig (ADR-0007 AT-4): Qwen Code and opencode under a scripted model on the runner (no key, no outside model), their expectations stated; proven on the probe branch first
- M11.3 recorded: a watch that is not elevated on the rig; the window's opening time (with M8.5)

