# ADR-0003 - Capture sources: hook, proxy, os

Status: accepted (M5.2, 2026-11-03). Proposed by the Table, 2026-11-02.
Amendments appended, never edited in place.

## Problem
Raqib v0.1 captures through Claude Code hooks only, on Linux and macOS
only. Three limits follow:
- Only one agent is watched. Other agents (Kimi, Codex, Gemini CLI, any
  OpenAI-compatible loop) offer no hook, or a different one.
- The hook runs inside the watched agent's process. The agent therefore
  takes part in writing its own record. For an agent that has read the
  rules this is the weakest possible anchor (ADR-0002).
- Windows, where most of the commander's machines live, is unsupported:
  the installer and gate are bash, and `capture.lock()` silently does
  nothing when `fcntl` is absent, so two concurrent hooks can hand out one
  seq.

## Decision
A trace record gains one field, `source`, with three values. Every source
writes the same record shape (ts, seq, session_id, phase, tool, hashes,
input_meta, cwd) so `raqib/rules/` does not change for a new source; the
engine judges records, not agents (A8). Records without `source` read as
`hook` (v0.1 traces stay valid).

- **hook** - today's capture. The agent calls Raqib. Cheapest, richest
  input_meta, weakest anchor.
- **proxy** - a local HTTP reverse proxy between the agent and its model
  API (OpenAI-compatible chat/completions and Anthropic messages). A tool
  call in a response becomes a `pre`; the tool result in the next request
  becomes its `post`. The proxy forwards bytes unchanged, adds nothing,
  initiates nothing (A4). It records what the model *asked for*. One
  bounded exception to "no network from the capture path": the proxy
  relays the agent's own connection and opens none of its own; a failed
  upstream still yields a record (A3).
- **os** - the operating system's own record of the agent's process tree:
  on Windows, Sysmon/ETW process-create, file-create and network events;
  on Linux, auditd or eBPF (later). The agent does not write this record
  and cannot move it. It records what *happened*.

Sessions stay per source. Joining them is a rule, not capture logic:
CROSS-SOURCE (anchor): a proxy `pre` with no os process within a window,
or an os process with no proxy `pre` - asked and not done, or done and not
asked. The gap between intent and act is the strongest signal Raqib can
have, and no signature is needed to read it.

## Consequences
- Schema: `source` optional in readers (default hook), required from
  writers after M5.2. `raqib report` groups by source.
- Windows is a supported platform from M5.1: Python installer, `msvcrt`
  lock fallback, one path-normalising function, CI on windows + ubuntu.
- Ordering with Phase 4: M4.2 and M4.3 edit `raqib/hooks/capture.py`.
  Land M5.1 (no schema change) and M5.2 (adds `source`) first, then
  rebase M4.2/M4.3 on the new shape. Shared helpers (hashing, input_meta,
  command_head) move to `raqib/hooks/common.py` in M5.2 so proxy and hook
  cannot drift apart.
- The first non-Claude agent watched is Kimi, through `proxy`. Whether
  Kimi also offers hooks is a fact to check in M5.2, not assumed.

## Candidates (each its own HANDOFF)
- M5.1 Windows: installer in Python, lock fallback, paths, CI matrix.
- M5.2 proxy source + `source` field + common.py; Kimi quickstart.
- M5.3 os source on Windows (Sysmon) + CROSS-SOURCE anchor rule.
- Later: Linux os source (auditd/eBPF); MCP shim as a fourth source only
  if a watched agent exposes nothing else.

## Builder note (2026-11-03, M5.2; the decision above stays as written)
As built. Record: docs/review/2026-11-03-M5.2.md.
- `source`: every hook line ends with `"source": "hook"` (last, so a line
  written before M5.2 is a byte prefix of today's line for the same
  event); proxy lines with `"proxy"`. `raqib/rules/trace.py` returns
  records as read, `source_of()` reads a missing field as `hook`, and an
  unknown value is a trace problem (an alarm). `raqib report` names the
  source on every finding and counts the records per source; the page has
  a source column. No rule reads the field.
- `raqib/hooks/common.py`: hashing, redaction, input_meta (command_head,
  command_programs), the output scan, error_class and ts, moved unchanged
  from capture.py, which keeps every name. Run as the hook (`python -I`),
  capture.py loads common.py next to it by path; if it cannot, one
  RAQIB-SILENCE line and exit 0.
- `raqib/hooks/proxy.py`, `raqib proxy --listen 127.0.0.1:PORT --upstream
  URL --log PATH`: a plain-HTTP listener on 127.0.0.1, HTTPS to the
  upstream with verification on (http only with --allow-plain-upstream and
  only to a loopback address); bytes unchanged, headers unchanged but for
  Host and hop-by-hop, no header added, no retry; streamed pieces pass as
  they arrive. Paths ending in /chat/completions (OpenAI) and /messages
  (Anthropic) are read: a tool call in an answer is a `pre`, written before
  the bytes that complete it pass; its result in a later request the `post`
  of the open proxy pre with that id anywhere in the trace; a result posted
  before is not posted again; a result with no call seen is a post with a
  new seq (SILENCE-HALF). One session per proxy run; cwd is the proxy's
  own. Hashes and common's extract only.
- Silence (A3): an upstream failure (no connection, TLS, timeout, an answer
  cut short, a 5xx answer) and a request or answer the proxy cannot read
  each append one RAQIB-SILENCE line to the trace and to stderr; a model
  request on any other path does so once per path. The agent gets the
  upstream's own status when there is one, else 502 (504 on a timeout).
- Kimi (checked, not assumed): Kimi CLI (Python) is archived and replaced
  by Kimi Code CLI. Its documentation (read 2026-11-03, not run) names a
  provider `base_url` in `~/.kimi-code/config.toml` (type `kimi`:
  OpenAI-compatible, `https://api.moonshot.ai/v1`), and lifecycle hooks
  with PreToolUse, PostToolUse, PostToolUseFailure, SessionStart,
  SessionEnd and Stop events, a JSON payload on stdin, and a shell tool
  named Bash. Whether capture.py runs as a Kimi hook is a question for the
  Table, not built here.

## Amendment A (the Table, 2026-11-03) - rulings on the M5.2 review (721126a)
- A-1 Recording never breaks relaying (catch-all + silence line; 64 MiB cap).
- A-2 `tool` / `tool_use_id` bounded; hashed with `tool_hashed` otherwise.
- A-3 Proxy sessions and pairing follow the conversation key (sha256 of
  model + messages[0]); start on first sight, stop on a no-tool answer,
  session_end at shutdown; `--cwd DIR`.
- A-4 Pre-proxy results are one `history` line per key. A-5 A re-sent
  result with another hash is a trace problem. A-6 Host/Origin refusal,
  folded silence lines, THREAT_MODEL names suppression, browsers, key in
  the clear. A-7 Missing common.py writes into the trace. A-8 Relay edge
  cases documented or refused. A-9 In-memory pre index. A-10 Golden hook
  line. A-11..A-13 as in docs/review/2026-11-03-M5.2-ruling.md.

## Builder note (2026-11-03, M5.2 REDO; Amendment A stays as written)
As built for A-1..A-13. Record: docs/review/2026-11-03-M5.2.md, section
"REDO". Where the first builder note above says otherwise, Amendment A
and this note hold: proxy sessions are conversation keys, not one per run
(A-3); the cwd is --cwd DIR, else the proxy's own; a result in a key's
first request with no pre is in the key's one `history` line (a new trace
phase, judged by no rule), never a half (A-4); the open pres are kept in
memory, the trace read once at start (A-9); a missing common.py writes its
RAQIB-SILENCE line into the trace too (A-7); trace.py reports a
RAQIB-SILENCE line as such (A-13). Lines carry `tool_hashed: true` when a
tool name or id was replaced by its hash (A-2).

## Amendment B (the Table, 2026-11-03) - judgement on M5.2 (721126a + 2b69c77)
- A-1..A-13 MET as cited; the Table read `_guard` (catch-all, silence line,
  bytes relayed) and `_allowed` (Host exact, no Origin, no Upgrade) on the
  branch; TLS context verified earlier.
- CI runs 41583717701 and 41589165262 success on six jobs each (read from
  api.github.com); gate 1792 passed, 7 skipped; scope clean.
- Builder readings accepted; recorded holes: Anthropic top-level system
  prompt not in the key; pairing by position on a repeated id; merge
  gated after commit (ledger, builder).
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Phase 5 exit, first half: an agent other than Claude Code can be watched
  end to end through the proxy; the field proof (Kimi) is the commander's.

## Amendment C (the Table, 2026-11-03) - rulings on the M5.3 STOP (4660b2a)
- C-1 CROSS-SOURCE is a code rule (raqib/rules/cross.py, anchor, high,
  class CROSS); the gate reads its RULE_KINDS.
- C-2 Judged only when the trace holds os lines; otherwise silent (the
  `sources:` line shows the absence).
- C-3 Window reading B; asked-not-done / done-not-asked as defined.
- C-4 Shell tool names and program folding fixed; done-not-asked excludes
  the agent's direct children (its helpers), named as a hole.
- C-5 os record shape; SECRET-OUTPUT / NET-TOOL guard `source != os`;
  os session `os-<root pid>`; GAP/ORDER skip all-os sessions; no dedup.
- C-6 One shared Sysmon helper in discover.py. C-7 Silence lines per
  failure; "no event 3" is INCOMPLETE not alarm. C-8 budget 0.1.
- C-9 Counts and docs. Full text: docs/review/2026-11-03-M5.3-ruling.md.

## Amendment D (the Table, 2026-11-03) - rulings on the M5.3 review (fd7452c)
- D-1 engine.CLASSES and cli.run_rules changes ratified (ledger: Table).
- D-2 Handoff Scope header is exactly `Scope:`.
- D-3 os file lines carry a redacted path like hook lines.
- D-4 No cwd key when none is observed (partial, never os-sysmon's own).
- D-5 `--root PID[:GUID]`; latest holder is the root, earlier ones named.
- D-7 "nothing to judge" note. D-8 Spans: per os session, intersection
  with the agent span; history outside is not judged and not noted.
- D-9 Asked covers descendants (npm -> node, forked bash). D-10 holes
  named; "cmd" matches "command". D-11 guards measured; check-rules lists
  CROSS-SOURCE; gate requires CROSS_RULES; YAML may not claim CROSS.
- D-12, D-13 as in docs/review/2026-11-03-M5.3-redo-ruling.md.
