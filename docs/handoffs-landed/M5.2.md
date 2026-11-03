# HANDOFF — M5.2  (phase 5: proxy source, first non-Claude agent)
Task: add the `proxy` capture source (ADR-0003): watch any HTTP-speaking agent; first Kimi.
Scope:
  raqib/hooks/ (capture.py, new common.py, new proxy.py), raqib/rules/trace.py, raqib/report.py,
  raqib/cli.py (proxy subcommand), raqib/ui.py (source column), tests/, tools/, README.md,
  docs/THREAT_MODEL.md (source lines), docs/specs/ADR-0003-*.md, docs/review/

Exit criteria:
- E1 `raqib/hooks/common.py`: hashing, redaction, input_meta, command_head;
     capture.py and proxy.py import it. Hook fixtures pass byte-for-byte.
- E2 `python -m raqib proxy --listen 127.0.0.1:PORT --upstream URL --log PATH`:
     plain HTTP in, HTTPS out, bytes forwarded unchanged, no header added, no
     retry, no call the agent did not make (A4). Streaming passes through.
     Upstream failure -> one silence-class record (A3).
- E3 OpenAI chat/completions (tool_calls) and Anthropic messages (tool_use /
     tool_result): a tool call -> `pre`, its result in the next request ->
     `post`, same seq. Hashes only. Records carry `source: "proxy"`; hook
     records gain `source: "hook"`; trace.py defaults a missing source to hook.
- E4 `raqib report` shows source per finding; mixed-source traces work.
     Fixtures: one OpenAI-style and one Anthropic-style recorded session,
     each with a positive and a negative finding.
- E5 README "Watch another agent": any OpenAI-compatible CLI pointed at the
     proxy via its base-URL setting (Kimi's setting named if known, else
     "see the agent's docs"); a synthetic recorded session as fixture (the
     real Kimi run is the commander's field test, recorded in docs/review).
     ADR-0003 status -> "accepted (M5.2, <date>)". Gate green, ubuntu + windows.

Not in scope: os source (M5.3), CROSS-SOURCE rule, TLS termination, auth.
Commit: `landed: M5.2 proxy source` or `STOP: M5.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
