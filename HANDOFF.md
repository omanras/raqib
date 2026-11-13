# HANDOFF — M10.1 REDO  (ADR-0011 Amendment C on review 2026-11-13-M10.1.md)

Task: the REDO of M10.1 (3ff5c99). Amendment B stands where C does not change it; the `attack` keys, the engine, check-rules and the rule table stand as built. Rulings C-1 to C-12.

Scope:
  raqib/event.py, docs/specs/EVENT.md, tests/test_event.py (and helpers under tests/ it needs), docs/review/2026-11-13-M10.1-questions.md

Exit criteria:
- E1 (C-1) `about` and `rev` on every event, given by the caller; `snapshot` (was `ledger`) names each entry's `about` by C-1's words, n from 1, rev 1, and requires the knock rows (C-8). Tested: two snapshots of one watch at two moments (a tree and a finding arrive between them) give the same `about` to the same entry though its n moved.
- E2 (C-2) The keys of C-2, in its order; a key the entry does not hold is absent.
- E3 (C-3) A cite is {src, line} and {round, seq} where held; no event holds a cite's text or a sample's row under any key (tested on every fixture run by searching every line for every cite text of every entry). evidence.rounds on a rhythm finding; evidence.record on findings, trees and notes of the rounds.
- E4 (C-4) A source finding's state by the report's order and words (read host.py's `_word`, near "not settled", and say the same; a test compares the event's state with the word the report prints for the same entry, for each of the six); `alarm` as C-4 says, tested against the report's ALARMS for the same watch.
- E5 (C-5, C-6, C-7, C-8) The heartbeat's state and result, the watch's end; the `hole` part and blind spots as events; a tree's subject and time; subject.named a boolean on every kind; a knock's title, limit_id and called.
- E6 (C-10) `check` as C-10 says (types, closed lists, a real instant, required keys per kind); a builder function raises ValueError naming the key rather than build a half event. Tested by changing one value of a built event at a time.
- E7 (C-11) docs/specs/EVENT.md: a type and, where closed, the values of every key; required keys per kind; C-11's mapping table exactly (a test holds C-11's pairs as literals and reads the document); one example per kind and per source-finding state, each equal to what the module builds; that paths are the machine's; that an id is unique within a host; what `snapshot` is not.
- E8 (C-12) The tests of C-12: the entries listed there, made by fixture watches; no tautology; the same lines on Windows and Linux (the Windows CI failed on 3ff5c99: evidence.trace differed between two temporary homes).
- E9 Gate green; ASCII outside docs; no new test reads docs/review; no real host, user or address in an example.
Not in scope: raqib/host.py, raqib/watch.py, raqib/report.py, raqib/cli.py, the rules, any writer, sink or forwarder.
If an exit criterion needs a file outside Scope, or an entry the watch never makes: STOP or say so in the questions file.
Commit: `landed: M10.1 REDO the event` or `STOP: M10.1 REDO <reason>`.
Read HANDOFF.md and do only the task it specifies.
