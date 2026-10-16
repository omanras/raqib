# HANDOFF — M2.1  (phase 2: schema-constrained suspicion layer)

Task: `raqib/suspect/` sends windows of trace lines + findings to a model
backend whose output must be {suspicion: 0..1, reasons[], cited_seq[]}
(ADR-0001 §5); code enforces A2 and A5. `python -m raqib suspect` writes
suspicion.jsonl; `report --suspicion` shows it.

Scope:
  raqib/
  tests/test_suspect.py
  tests/fixtures/
  README.md
  docs/review/

Exit criteria:
- E1 Backends: ollama (default, stdlib HTTP), anthropic (official SDK, imported
     only when chosen; the rest stays stdlib, A-7), fake (canned, for tests).
- E2 Output validated in code: suspicion a number in [0,1], reasons strings,
     cited_seq inside the window and non-empty when raised; anything else is
     an error line, never suspicion (A5).
- E3 A2: below threshold (default 0.5) nothing is written, nothing is ever
     recorded as clean; failures and refusals are error lines (A3); rule
     findings are never altered.
- E4 Prompt holds only trace metadata (no hashes, no raw content) marked as
     untrusted data; tests run offline; gate green.

Not in scope: eval harness (M2.2), UI.
Commit: `landed: M2.1 suspicion layer` or `STOP: M2.1 <reason>`.
Read HANDOFF.md and do only the task it specifies.
