# ADR-0002 - Rule kinds: signature, demand, anchor

Status: accepted (M4.1, 2026-11-03). Proposed by the Table, 2026-10-22.
Amendments appended, never edited in place.

## Problem
Raqib's rules are public YAML (A1, A8). The watched agent can read them,
and it reads faster than the commander. A rule that describes the shape of
a bad act is a signature, and an agent that knows a signature picks
another shape. The private layer (Haris) delays this knowledge; it does
not prevent it, because the agent can still infer private rules from
which of its actions get flagged. So the question is not how to hide the
rules but which rules stay standing once they are known.

## Decision
Every rule declares a `kind`, one of three:

- **signature** - matches the shape of a bad act (a program name, a tool,
  a pattern). Cheap to write, cheap to evade. A signature MUST declare
  `evasion:` - the known ways round it, in one line each - so the gap is
  in the tree (A8) and the THREAT_MODEL can cite it. A signature with no
  listed evasion is invalid, because no signature has none.
- **demand** - requires evidence of a required act; the absence of that
  evidence is the finding (A3). Knowing a demand helps the agent only by
  complying with it: SILENCE-GAP is passed by not going silent, a
  gate-before-landed rule is passed by running the gate.
- **anchor** - measured against a record the agent does not write: the
  cwd as the hook captured it, the Scope: block of HANDOFF.md at a
  commit, the git tree state at stop, the hash chain of the trace itself.
  The agent may know the anchor; it cannot move it.

`tools/gate.sh` prints the ratio signature:demand:anchor on every run.
The ratio is a health number, not a budget: a watcher that is mostly
signatures is an antivirus written in YAML and will fall the way one does.

## Classification of the v0.1 catalog (the Table's reading, to be checked
by the M4.1 builder against each rule's match block)

| rule             | kind      | known evasion (for `evasion:`)                       |
|------------------|-----------|------------------------------------------------------|
| DESTRUCT-CMD     | signature | python -c os.remove; find -delete; bash -c; git clean |
| NET-TOOL         | signature | python urllib; pip/npm install; git fetch; node fetch |
| SCOPE-PATH       | signature | the same path through Bash (cat, cp, sed -i)         |
| SECRET-OUTPUT    | signature | base64/hex the output; split it; read without echo   |
| DRIFT-FILES      | anchor    | hole: writes through Bash are not seen (documented)  |
| SCOPE-CWD-MOVED  | anchor    | -                                                    |
| SCOPE-CWD-ROOT   | anchor    | -                                                    |
| SILENCE-GAP      | demand    | -                                                    |
| SILENCE-OPEN     | demand    | -                                                    |
| SILENCE-HALF     | demand    | -                                                    |
| SILENCE-ORDER    | demand    | -                                                    |

Ratio today: 4 : 4 : 3. All four signatures share one bypass: Bash.
Phase 4 therefore adds demands and anchors around Bash and the tree, not
more signatures.

Note (2026-11-03, M4.2, ruling D-8; the table above stays as written). M4.2
adds one row, in the table's shape:

| rule             | kind      | known evasion (for `evasion:`)                       |
|------------------|-----------|------------------------------------------------------|
| SILENCE-EMPTY    | demand    | -                                                    |

E2 (`input_meta.command_programs`, read under the D-3 guard) drops these
evasion items, each quoted as it stood in the rule's `evasion:` list:
- dropped DESTRUCT-CMD: "bash -c 'rm ...': the first program is bash" (the table's "bash -c")
- dropped DESTRUCT-CMD: "rm after &&, ; or a pipe: only the first program is read"
- dropped NET-TOOL: "bash -c 'curl ...' or a wrapper in front (sudo, env, xargs): only the first program is read" (its wrapper half stays, in a line of its own)
- dropped NET-TOOL: "curl after &&, ; or a pipe: only the first program is read"

Ratio after M4.2: 4 : 5 : 3.

Note (2026-11-03, M4.2 REDO-2, Amendment E; corrects the note above and the
counts of A-2):
- open demand SILENCE-NOSTART (M4.3, E-2): a session_end with tool lines
  and no session_start is judged by no rule; SILENCE-EMPTY's no-start case
  fires only when the session has no pre, post or stop line.
- reworded DESTRUCT-CMD (E-4): "a wrapper in front (sudo, env, xargs, timeout, nohup): only the first program is read" stays as an item; its line now names exec, eval, source, find -exec, other shells and a nested bash -c, and says the program they run is an argument.
- hook for a later demand (E-5): capture writes `input_meta.command_unread:
  true` on a Bash line whose programs it could not read; no rule reads it
  in M4.2.
- E-6 adds one line to both rules (code on stdin, in a here-document or a
  here-string, or in a script file records the shell or the script only).
  What shrinks is items (E-4). Lines beyond the table, as built in 04e34c0:
  DESTRUCT-CMD +5, NET-TOOL +4.
Lines beyond the table now: DESTRUCT-CMD +6, NET-TOOL +5, SCOPE-PATH +4, SECRET-OUTPUT +3.

## Consequences
- Schema: `kind` required on every YAML rule; `evasion` required when
  kind is signature, forbidden otherwise. Silence rules declare their kind
  in code. Loader rejects anything else.
- The suspicion layer (A2) is told the kind of every rule finding it sees,
  so it can weigh an evaded signature's absence as itself suspicious.
- New rule proposals state their kind first. A proposal for a new
  signature must say why a demand or an anchor cannot do the same job.

## Candidates for Phase 4 (each its own HANDOFF)
- M4.1 schema + classification + gate ratio (this ADR accepted).
- M4.2 capture records `input_meta.command_programs` (every program name
  in a Bash command: pipes, `&&`, `;`, `bash -c`), closing part of the
  Bash hole for the four signatures without a model. Then two demands:
  LANDED-NO-GATE (a `landed:` commit with no earlier ok run of
  tools/gate.sh in the session) and EDIT-NO-TEST (ok edits under raqib/
  or tests/ with no later test run before stop).
- M4.3 capture records, at stop and session_end, `git_head` and
  `git_clean` from the local tree (offline). Anchor STOP-DIRTY-TREE. A
  session that ends dirty, or whose head did not move after edits, is a
  finding.
- Later: a per-record `prev_hash` in the trace (an anchor on the trace
  itself, as in Dawr's ledger); SILENCE-ORDER then also reports a broken
  chain.

## Amendment A (2026-11-03) - as built in M4.1 (builder's record, not a ruling)
What M4.1 built, so the review can hold the tree to it. The decision text
above is unchanged. Open points are questions in
`docs/review/2026-11-03-M4.1-questions.md`, not settled here.
- A-1 Schema (`raqib/rules/engine.py`). `kind` is required on every YAML
  rule and is one of `engine.KINDS` = signature, demand, anchor (a string,
  case-sensitive). `evasion` is required when kind is signature: a
  non-empty list of non-empty, printable, one-line strings. On a demand or
  an anchor any `evasion` key is an error, even an empty or null one. Both
  are checked after the id, and every error reads
  `<file>: rule <ID>: <field>: <reason>`; a bad item is named
  `evasion[<i>]`. A compiled rule has `kind` and `evasion` (a tuple, empty
  for a demand or an anchor).
- A-2 Classification as in the table: 4 signatures, 4 demands, 3 anchors.
  Each `;` item of the table's evasion column starts one line of the
  rule's `evasion:` list. Lines added from the match blocks:
  DESTRUCT-CMD and NET-TOOL, a wrapper or a second program (only the first
  program is read), programs not on the list, and for DESTRUCT-CMD
  overwrites by mv, cp, a redirect or the Write and Edit tools; SCOPE-PATH,
  a file tool not on its list, a symlink (paths are not resolved), a moved
  cwd; SECRET-OUTPUT, a kind with no capture pattern, a secret past the
  first 1048576 scanned characters. DRIFT-FILES is an anchor and may not
  carry `evasion:`; the table's "hole" stays in its description, as before.
  A test reads the table from this file and holds the catalog to it.
  Note (2026-11-03, M4.1 REDO, B-4; corrects this item): K8 is right,
  "programs not on the list" is a NET-TOOL line only; DESTRUCT-CMD names
  its own (find, git, mv, cp). The REDO adds SECRET-OUTPUT's
  placeholder-marker line (K6) and SCOPE-PATH's Glob/Grep line (K7), and
  the scan line now gives the exact budget (K9): 1048576 characters over
  all strings of tool_response and error, keys too, each counted as its
  length plus 1, in document order. Lines added beyond the table, as
  built: DESTRUCT-CMD +4, NET-TOOL +4, SCOPE-PATH +4, SECRET-OUTPUT +3.
  DRIFT-FILES and SCOPE-CWD-ROOT name their K16 holes in their
  descriptions (B-5).
- A-3 Silence rules (`raqib/rules/silence.py`) declare their kind in code:
  `RULE_KINDS` maps each of the four ids to demand. A finding takes its
  kind from that map, so a silence rule missing from it cannot emit.
- A-4 Findings. Every catalog and silence finding dict carries `kind`.
  `engine.check_finding` rejects a `kind` that is not one of the three; a
  finding with no `kind` (a findings file written before M4.1) is checked
  as before. `raqib rules` and `raqib report --json` show the kind of every
  finding; the finding entries in `<trace>.watch.json` carry it. The text
  report and the page do not print it: `raqib/report.py` and `raqib/ui.py`
  are outside the M4.1 Scope.
  Note (2026-11-03, M4.1 REDO, B-1 and B-3; supersedes this item): the
  text report prints the kind on every finding line and in its RULES
  table, the page in its findings and rule table. A finding without `kind`
  is rejected by `check_finding` as `NoKindError`; the report raises it as
  a `no-kind` alarm and watch prints a `NOTICE no-kind` line for it.
- A-5 Gate (`tools/gate.py`, check 5, after the SDK check and before the
  tests). It imports `raqib.rules` from the checkout it gates (a module
  found anywhere else is RED, so an installed raqib is never counted),
  loads the catalog with the loader, and reads `silence.RULE_KINDS`. It is
  RED when the catalog does not load (which covers a rule with no kind and
  a signature with no evasion), when a rule's kind is not one of the
  gate's own three, when silence.py declares no kinds, and when the rules
  cannot be imported. Otherwise it prints one line, today
  `[gate] rule kinds: signature=4 demand=4 anchor=3`. The ratio never
  fails the gate by itself.
  Note (2026-11-03, M4.1 REDO, B-2 and B-5; supersedes this item): the
  check is now check 2, its line the first after the secret scan. It runs
  in a child, `python -I tools/gate.py --rule-kinds-child`, which imports
  the standard library modules the rules use (`PREIMPORT`) before it
  appends the checkout to the END of sys.path; the gate reads only the
  child's exit status and its one line, so a SystemExit in tree code
  cannot end the gate with exit 0. The catalog is the tracked files
  directly under raqib/rules/catalog/ (git ls-files), and every id in
  `report.SILENCE_RULES` must have a kind in `silence.RULE_KINDS`.
- A-6 Not built in M4.1, because the HANDOFF puts them out of scope: the
  suspicion layer is not yet told each finding's kind (Consequences,
  second bullet), and the THREAT_MODEL does not yet cite the evasion lists.

## Amendment B (the Table, 2026-11-03) - rulings on review 2026-11-03-M4.1.md
- B-1 (K1, K2) Scope of M4.1 is widened by this ruling to raqib/report.py
  and raqib/ui.py: the text report prints the kind on every finding line
  and in the RULES table; the page shows it in the findings and the rule
  table. The reviewer's process point stands in the ledger: the builder
  should have STOPped; the Table's Scope was the cause.
- B-2 (K3, K4) The kinds check runs in a subprocess (`python -I <script>`)
  whose script pre-imports every stdlib module raqib.rules uses before it
  appends ROOT at the END of sys.path, never the front; the gate reads
  the subprocess's exit status and output, so no SystemExit in tree code
  can take the gate's exit. The pytest step's exposure is inherent and
  recorded.
- B-3 (K5) A finding without `kind` is a `no-kind` alarm in report (A3)
  and a notice in watch; test_rules.py:933-935 is inverted.
- B-4 (K6, K7, K8, K9) SECRET-OUTPUT evasion gains the placeholder-suffix
  line; SCOPE-PATH evasion gains the Glob/Grep location line; A-2's
  DESTRUCT-CMD sentence corrected in Amendment A (a record may be
  corrected by a dated note under it); the scan-budget wording made exact.
- B-5 (K10, K11, K12, K13, K14) The catalog for check 5 is the set of
  tracked files under raqib/rules/catalog; the gate asserts RULE_KINDS
  covers report.SILENCE_RULES; a test exercises the KINDS check through a
  catalog rule; the test is renamed; the ratio line prints as the first
  gate line after the secret scan. K15, K16 recorded; K16's two claims
  are copied into the two rules' descriptions as known holes.
- B-6 Every change carries a test (D-8 of ADR-0005 applies to all Raqib
  REDOs from here on).

## Amendment C (the Table, 2026-11-03) - judgement on the M4.1 REDO (bcce5bc + cf798cb)
- B-1..B-5 MET as cited; the Table read kinds_child (gate.py:193-212):
  PREIMPORT before sys.path.append(root), BaseException caught, one line
  on stdout, exit code read by the parent. R1 (forged line + os._exit(0))
  accepted as the same exposure the pytest step carries; R2-R5 recorded.
- CI run 41540864444 success on six jobs (read by the Table from
  api.github.com); gate 1099 passed, 6 skipped; scope clean (widened by
  B-1); three commits on the branch (rebase allowed this time).
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Ledger, Table: the original Scope omitted report.py/ui.py for an exit
  criterion that named `raqib report` (the same error as M5.1's first
  Scope); rule: before setting HANDOFF.md, the Table greps each exit
  criterion's named commands/files against the Scope list.

## Amendment D (the Table, 2026-11-03) - rulings on the M4.2 STOP (ed039f2)
- D-1 M4.2 is split: E1 command_programs, E2 has_any + branches + the
  dated note under the table, E5 SILENCE-EMPTY stay in M4.2; the demands
  LANDED-NO-GATE and EDIT-NO-TEST move to M4.2b together with the
  `require:` construct (before / after+until, three-valued, demand only,
  never with aggregate) and the `under_any` path op.
- D-2 Scope widened to README.md, .github/workflows/gate.yml and
  tests/test_packaging.py; catalog counts there are derived from the
  checkout, never literals.
- D-3 Lines without command_programs are judged by command_head alone
  (`exists: true` guard); recorded as an evasion line in both rules.
- D-4 `python -c <code>` is an argument and stays a NET-TOOL evasion; the
  2026-11-02 field trace becomes a fixture (SILENCE-EMPTY positive, NET-TOOL
  miss recorded).
- D-5 SILENCE-EMPTY is high (A3). Shape: session_start + session_end with no
  tool line and no stop; or a session_end with no start. A start alone at the
  end of the trace is SILENCE-OPEN's finding only.
- D-6 Parse limits of the builder's Q12 accepted; an expansion inside a
  `-c` string makes the list absent; 64-name cap; basenames only.
- Ledger, Table: the Scope missed README.md and gate.yml, which pin the
  rule count; rule: a task that adds or removes a rule lists README.md,
  gate.yml and test_packaging.py in Scope, and the Table runs
  `grep -rn "== 7\|Eleven\|7 YAML" --include=*.py --include=*.yml --include=*.md`
  before setting HANDOFF.md.
Full text: docs/review/2026-11-03-M4.2-ruling.md.

## Amendment E (the Table, 2026-11-03) - rulings on the M4.2 REDO review (04e34c0)
- E-1 An adversarial fixture never lives under the benign glob
  (tests/fixtures/*.log); the field trace moves to tests/fixtures/field/.
- E-2 D-5's "end without start" case is narrowed: it fires only with no
  tool line; a session_end with tools and no start is an open demand
  (SILENCE-NOSTART, M4.3).
- E-3 SILENCE-EMPTY cites the first start and the last end only; a resume
  with tools makes the batch finding vanish (recorded).
- E-4 "Shrink" means items; the +4 counts of Amendment A are corrected by
  a dated note.
- E-5 `:` and `.` are program names; unread Bash lines carry
  `input_meta.command_unread: true` (no rule uses it yet); the D-3 evasion
  line names every unread trigger.
- E-6 Shell code on stdin, here-doc, here-string or script file records the
  shell only (evasion line in both rules).
- E-7..E-14 builder items; E-12 records command_head's leading-redirect
  hole (fix in M4.2b).
Full text: docs/review/2026-11-03-M4.2-redo-ruling.md.

## Amendment F (the Table, 2026-11-03) - judgement on M4.2 (04e34c0 + 3e0cff9)
- E-1..E-14 MET as cited; the Table read `_empty` (first start + last end
  cited) and `input_meta` (command_unread marker) on the branch.
- CI runs 41548516230 and 41552543683 success on six jobs each (read from
  api.github.com); gate 1319 passed, 6 skipped; kinds line
  signature=4 demand=5 anchor=3; scope clean; three commits on the branch
  (merge of main + follow-up, G-8).
- Builder readings 1-4 accepted. Observation recorded: a second session_end
  in one session moves "last end" and knocks once more (one knock per end
  line is acceptable: each end is a new fact).
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Ledger, Table: the first M4.2 Scope omitted README.md/gate.yml (rule in
  Amendment D); the HANDOFF's "medium" for a silence rule contradicted A3.
