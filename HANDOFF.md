# HANDOFF — M0.2  (phase 0: silence)

Task: implement `raqib/rules/silence.py`: read a trace JSONL and emit SILENCE
events per docs/CONSTITUTION.md A3 and ADR-0001 §3/§6.

Scope:
  raqib/rules/
  tests/test_silence.py
  tests/fixtures/
  docs/review/

Exit criteria:
- E1 A gap > RAQIB_GAP_SECONDS (default 60) between consecutive `ts` inside one
     session_id yields one finding {rule_id:"SILENCE-GAP", severity:"high",
     cited_seq:[seq_before, seq_after], summary}.
- E2 A session with `session_start` but no `session_end` or `stop` within the
     file yields {rule_id:"SILENCE-OPEN", ...} citing the last seq.
- E3 A `pre` with no matching `post` (same seq) yields {rule_id:"SILENCE-HALF"}.
- E4 Pure function: `findings(lines) -> list[dict]`; no I/O inside; fixtures
     with at least one positive and one negative per rule; gate green.

Not in scope: capture, model layer, CLI, UI.
Commit: `landed: M0.2 silence rules` or `STOP: M0.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.

REDO: per docs/review/2026-10-16-M0.2.md - HALF counts pre/post per seq (S6);
  OPEN when the last line is not stop/session_end (S4); SILENCE-ORDER for seq/ts
  going back (S6/S7); trace.parse reports bad ts/phase/UTF-8 (S2/S3/S13).
