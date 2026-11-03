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

Note (2026-11-03, M5.3, ruling C-9 of ADR-0003 Amendment C; the table above
stays as written). M5.3 adds one row, in the table's shape. CROSS-SOURCE is
a code rule (raqib/rules/cross.py), class CROSS, that declares its kind in
its own RULE_KINDS, which the gate reads as it reads silence.py's (C-1):

| rule             | kind      | known evasion (for `evasion:`)                       |
|------------------|-----------|------------------------------------------------------|
| CROSS-SOURCE     | anchor    | -                                                    |

An anchor lists no evasion. Its known hole, named in cross.py, the README
and the THREAT_MODEL, is an agent that runs its acts as its own direct
children rather than through a shell (C-4). The same ruling (C-5) adds a
guard to two signatures, SECRET-OUTPUT and NET-TOOL: lines of the os source
are not judged by them; their evasion lists do not change.

Ratio after M5.3: 4 : 5 : 4.

Note (2026-11-03, M4.2b, ADR-0002 Amendment G; the table above stays as
written). M4.2b adds two rows, in the table's shape. Both are YAML rules of
kind demand built on the `require:` construct (D-1): LANDED-NO-GATE with
`require: {before: ...}`, EDIT-NO-TEST with `require: {after: ..., until:
...}`. A demand lists no evasion; its known holes are its `holes:` list
(G-6), quoted here one line each as they stand in the rule (G-5: v1 holes
accepted and listed):

| rule             | kind      | known evasion (for `evasion:`)                       |
|------------------|-----------|------------------------------------------------------|
| LANDED-NO-GATE   | demand    | -                                                    |
| EDIT-NO-TEST     | demand    | -                                                    |

- holes LANDED-NO-GATE: "a stale gate: any earlier ok gate run in the session counts, even one before later edits"
- holes LANDED-NO-GATE: "operators are not recorded: tools/gate.sh || git commit ... and tools/gate.sh; git commit ... look like tools/gate.sh && git commit ..., whatever the gate's status"
- holes LANDED-NO-GATE: "a RED gate piped into another program (tools/gate.sh 2>&1 | tail -5) is an ok line: a pipeline's status is its last program's"
- holes LANDED-NO-GATE: "a gate started in the background (the Bash tool's run_in_background) is ok when it starts; its verdict comes later through another tool"
- holes LANDED-NO-GATE: "names are basenames: any program or script called gate.sh or gate.py counts as the gate"
- holes LANDED-NO-GATE: "a commit with no commit_prefix is not judged: --amend, -F, -C, -c, a here-document with an unquoted delimiter or with CRLF line ends, a message whose first word is not literal, a commit after the first one in a command, an abbreviated option, a git option before the subcommand that is not literal (git $OPT commit), git merge, git commit-tree, an alias, git.exe, a wrapper in front (sudo, env, xargs), a command capture cannot read in full, and a first word that is not a lower-case word ending in a colon (STOP:, Landed:)"
- holes LANDED-NO-GATE: "--no-message, which makes git forget the messages before it, is not read: the prefix is that of the first non-empty -m, so git commit -m wip --no-message -m 'landed: x' is not judged"
- holes LANDED-NO-GATE: "a commit whose post line never came is not judged: unknown (partial), SILENCE-HALF has the call"
- holes LANDED-NO-GATE: "a gate run after the commit on the same line counts (git commit -m 'landed: x' && tools/gate.sh): the line is the evidence"
- holes LANDED-NO-GATE: "the trigger is the line's ok, not the commit's: a failing command after the commit on the same line (git commit -m 'landed: x' && false) makes the line not ok, so the landing is not judged"
- holes LANDED-NO-GATE: "a call that names the gate without running it counts as a gate run: bash -n tools/gate.sh (a syntax check), python -V tools/gate.py, python -I tools/gate.py --rule-kinds-child (the kinds check only)"
- holes LANDED-NO-GATE: "a Bash line capture cannot read at all (no command_programs and no command_head) and no gate run in the session make the landing unknown (partial), not a finding (H-2: a true gate line wins over such a line)"
- holes EDIT-NO-TEST: "a test or gate run piped into another program (pytest | tail) is an ok line: a pipeline's status is its last program's"
- holes EDIT-NO-TEST: "operators are not recorded: pytest || true is an ok line whatever the tests did"
- holes EDIT-NO-TEST: "a run started in the background (the Bash tool's run_in_background) is ok when it starts"
- holes EDIT-NO-TEST: "any python or python3 call counts as a test run (python3 -c 'print(1)', python3 --version), and any program or script called pytest, gate.sh or gate.py"
- holes EDIT-NO-TEST: "edits made through Bash (sed -i, a redirect, cp, mv) are not triggers: only Edit, Write, MultiEdit and NotebookEdit are"
- holes EDIT-NO-TEST: "an edit whose path cannot be read (no input_meta.path) is not a trigger"
- holes EDIT-NO-TEST: "a session that never reaches a stop or a session_end leaves its edits unjudged (partial); SILENCE-OPEN has the session"
- holes EDIT-NO-TEST: "an edit whose post line never came is not judged: unknown (partial), SILENCE-HALF has the call"
- holes EDIT-NO-TEST: "with no context root, raqib/ and tests/ are placed against each line's cwd: an edit made while the cwd is elsewhere is not under them (SCOPE-CWD-MOVED has the move)"
- holes EDIT-NO-TEST: "a call that names the gate without running it counts as a test run: bash -n tools/gate.sh (a syntax check), python -I tools/gate.py --rule-kinds-child (the kinds check only)"
- holes EDIT-NO-TEST: "a Bash line capture cannot read at all (no command_programs and no command_head) after an edit, with no test run after it, makes the edit unknown (partial), not a finding (H-2: a true test line wins over such a line)"

Also in M4.2b: command_head skips leading redirections and their targets
(E-12), so the "Known hole" sentence of DESTRUCT-CMD and NET-TOOL now names
the old lines only; their evasion items and counts do not change (the
script item's parenthesis names command_scripts, G-2).

REDO (2026-11-03, Amendment H): the holes above include those H-2 (an
unreadable Bash line and no true evidence), H-4 (--no-message) and H-5
(a gate after the commit on the same line, the line's ok, the commit forms
not read, calls that name the gate without running it, placement without a
context root) list. H-1 adds the Windows names and the wrapper pass-through
to command_scripts; H-7 accepts class DRIFT for both demands.

Ratio after M4.2b: 4 : 7 : 4.

Note (2026-11-03, M4.3, ADR-0002 Amendment J; the table above stays as
written). M4.3 adds two rows, in the table's shape. Both are code rules
(raqib/rules/tree.py, J-1), class DRIFT, medium, that declare their kinds in
its own RULE_KINDS, which the gate reads as it reads cross.py's. Each
compares a value of the session's closing line (its last stop or
session_end) with the same value of its session_start line, as the hook
read them from the files under cwd/.git (git_head, git_index_sha256,
git_error; nothing is run). An anchor lists no evasion; its known holes are
tree.HOLES, quoted here one line each as they stand in the code (J-10: the
draft holes accepted, plus J-4, J-7 and J-9):

| rule             | kind      | known evasion (for `evasion:`)                       |
|------------------|-----------|------------------------------------------------------|
| HEAD-UNMOVED     | anchor    | -                                                    |
| INDEX-UNTOUCHED  | anchor    | -                                                    |

- holes HEAD-UNMOVED: "the rule sees that the head moved, not why: an empty commit, a commit of other files, a checkout or switch, a reset, or a hash written into .git/HEAD or a ref all count as moved"
- holes HEAD-UNMOVED: "an unborn branch (no commit yet) is git_error "no ref": a session in a fresh repository is unknown (partial) (J-7)"
- holes HEAD-UNMOVED: "a symlinked .git or a link below it, a gitdir that is absolute, above the cwd, UNC or a device path, a head in a SHA-256 repository, or a head not read within 50 ms is null: unknown (partial)"
- holes HEAD-UNMOVED: "a reftable repository (HEAD names refs/heads/.invalid; its refs are in reftable/, which is not read) is unreadable: unknown (partial) (K-3)"
- holes HEAD-UNMOVED: "a packed-refs file over 1 MiB is unreadable: a head that is only there is unknown (partial) (K-3)"
- holes HEAD-UNMOVED: "only cwd/.git is read: a session started in a subdirectory, a second repository, a nested repository or a submodule edited from the parent's cwd is judged against the cwd's .git or not at all"
- holes HEAD-UNMOVED: "GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, git -C or --git-dir in the agent's commands act on another repository or index than the one the hook reads (K-3)"
- holes HEAD-UNMOVED: "a linked worktree, whose .git file names an absolute gitdir or (worktree.useRelativePaths) a relative one above the cwd, and a submodule (gitdir: ../.git/modules/<name>) are never followed (J-6, K-2), and a worktree's commondir is not read (J-7): the session is unknown (partial)"
- holes HEAD-UNMOVED: "a file system mounted under the project directory (a network share) looks like a directory to the hook, which reads it as one (K-2)"
- holes HEAD-UNMOVED: "a Windows device name written with a space before its extension (CON .txt) is not refused by name; it is lstat'ed and never opened, since it is not a regular file (K-3)"
- holes HEAD-UNMOVED: "edits whose path is not under the start line's cwd are not triggers: edits outside the repository, in a second repository, or with no readable path (J-4)"
- holes HEAD-UNMOVED: "edits made through Bash (sed -i, a redirect, cp, mv) are not triggers: only Edit, Write, MultiEdit and NotebookEdit are"
- holes HEAD-UNMOVED: "a session with no stop or session_end after an edit leaves that edit unjudged (partial); SILENCE-OPEN has the session"
- holes HEAD-UNMOVED: "an edit before the session's first session_start is unjudged (partial: edit before the start record), never dropped (K-4)"
- holes HEAD-UNMOVED: "the start is the session's first session_start line: a session resumed after the human committed or staged counts that as a move"
- holes INDEX-UNTOUCHED: "the index is hashed as raw bytes: git status, git diff or any command that refreshes stat data rewrites it with nothing staged, and that counts as touched, a false negative (J-9)"
- holes INDEX-UNTOUCHED: "staging any file counts, not the edited ones: git add of another file, git add -N, git update-index, git read-tree"
- holes INDEX-UNTOUCHED: "a commit rewrites the index: a commit of other files counts as touched"
- holes INDEX-UNTOUCHED: "a repository with no index yet (nothing ever staged) is null: unknown (partial) (J-7)"
- holes INDEX-UNTOUCHED: "a symlinked .git or a link below it, a gitdir that is absolute, above the cwd, UNC or a device path, an index over 64 MiB, or an index not hashed within 50 ms is null: unknown (partial)"
- holes INDEX-UNTOUCHED: "only cwd/.git is read: a session started in a subdirectory, a second repository, a nested repository or a submodule edited from the parent's cwd is judged against the cwd's .git or not at all"
- holes INDEX-UNTOUCHED: "GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, git -C or --git-dir in the agent's commands act on another repository or index than the one the hook reads (K-3)"
- holes INDEX-UNTOUCHED: "a linked worktree, whose .git file names an absolute gitdir or (worktree.useRelativePaths) a relative one above the cwd, and a submodule (gitdir: ../.git/modules/<name>) are never followed (J-6, K-2), and a worktree's commondir is not read (J-7): the session is unknown (partial)"
- holes INDEX-UNTOUCHED: "a file system mounted under the project directory (a network share) looks like a directory to the hook, which reads it as one (K-2)"
- holes INDEX-UNTOUCHED: "a Windows device name written with a space before its extension (CON .txt) is not refused by name; it is lstat'ed and never opened, since it is not a regular file (K-3)"
- holes INDEX-UNTOUCHED: "edits whose path is not under the start line's cwd are not triggers: edits outside the repository, in a second repository, or with no readable path (J-4)"
- holes INDEX-UNTOUCHED: "edits made through Bash (sed -i, a redirect, cp, mv) are not triggers: only Edit, Write, MultiEdit and NotebookEdit are"
- holes INDEX-UNTOUCHED: "a session with no stop or session_end after an edit leaves that edit unjudged (partial); SILENCE-OPEN has the session"
- holes INDEX-UNTOUCHED: "an edit before the session's first session_start is unjudged (partial: edit before the start record), never dropped (K-4)"
- holes INDEX-UNTOUCHED: "the start is the session's first session_start line: a session resumed after the human committed or staged counts that as a move"

REDO (2026-11-03, Amendment K): the holes above are tree.HOLES as K-2,
K-3 and K-4 leave them. K-2 amends J-6: a relative gitdir is followed only
when it resolves under the cwd, so a submodule's and a linked worktree's
gitdir (absolute or relative) are never followed, and a network mount
under the project is a named hole. K-3 names reftable, packed-refs over
1 MiB, GIT_INDEX_FILE, relative-path worktrees and the "CON .txt" device
form. K-4 makes an edit before the first session_start unknown.

Note (2026-11-03, M4.3 REDO, Amendment K, K-3; corrects the "open demand
SILENCE-NOSTART (M4.3, E-2)" line of the M4.2 REDO-2 note above): M4.3 did
not build SILENCE-NOSTART; it stays open for a later task.

Ratio after M4.3: 4 : 7 : 6.

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

## Amendment G (the Table, 2026-11-03) - rulings on the M4.2b STOP (129c071)
- G-1 Scope: common.py, capture.py, THREAT_MODEL; 15 rules; ratio 4 : 7 : 4.
- G-2 `command_scripts` = the script operand only (basename); -c/-m = none.
- G-3 `commit_prefix` only for `^[a-z]+:$` (<= 16 chars).
- G-4 Commit forms read / not read fixed. G-5 v1 holes accepted and listed.
- G-6 `holes:` key allowed on demand and anchor rules.
- G-7 Trigger = commit post line ok; no post = unknown. G-8 D-3 fallback
  applies to evidence. G-9 `command_scripts` only when non-empty.
- G-10 Edit/Write/MultiEdit/NotebookEdit; partial on no deadline.
- G-11 Baseline corrected by dated note.
Full text: docs/review/2026-11-03-M4.2b-ruling.md.

## Amendment H (the Table, 2026-11-03) - rulings on the M4.2b review (1643e32)
- H-1 Script operands split on `/` and `\`; python.exe/py; timeout/nohup/
  env pass through; `.`/`source` record; Windows landing fixture CLEAN.
- H-2 True evidence wins over unknown in `require`. H-3 An unknown trigger
  with true evidence is not partial. H-4 First non-empty -m.
- H-5 Holes listed (cwd placement without root, same-line gate after the
  commit, line-level ok, non-literal global option, CRLF here-doc, git.exe,
  -n/-V/--rule-kinds-child). H-6 `require: null` is an error.
- H-7 Class DRIFT accepted. H-8 THREAT_MODEL completeness. H-9 Field
  item: Claude Code's ok on a non-zero Bash exit. H-10 hostile-input tests.
Full text: docs/review/2026-11-03-M4.2b-redo-ruling.md.

## Amendment I (the Table, 2026-11-03) - judgement on M4.2b (1643e32 + 082bd45 + f50e989)
- G-1..G-11 and H-1..H-10 MET as cited; the Table read `_judge_require`
  (true evidence wins over unknown; causes per seq) on the branch.
- CI runs 41607191240 and 41612799519 success on six jobs each (read from
  api.github.com); gate 2213 passed, 7 skipped; kinds signature=4
  demand=7 anchor=4; scope clean; CI-fix commit accepted (G-8).
- Builder readings accepted (sourced `.sh` only; env literal; CR kept).
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Phase 4 exit met in the tree: demand + anchor (11) > signature (4) and
  every signature lists its evasions. The field proof is the commander's.

## Amendment J (the Table, 2026-11-03) - rulings on the M4.3 STOP (107f241)
- J-1 Tree anchors are code rules in raqib/rules/tree.py (cross.py pattern).
- J-2 trace.FIELDS gains the three git keys with shape checks.
- J-3 Not judged without git keys or "no repo" both ends; other nulls with
  edits are unknown. J-4 start/close, cwd change unknown, triggers under
  the start cwd. J-5 closed git_error set. J-6 gitdir only relative, under
  the cwd root, never UNC/device; no symlink followed. J-7 worktrees v1
  hole. J-8 50 ms monotonic budget, size caps. J-9 raw index bytes; git
  status refresh named. J-10 both may fire; holes accepted. J-11 counts.
Full text: docs/review/2026-11-03-M4.3-ruling.md.

## Amendment K (the Table, 2026-11-03) - rulings on the M4.3 review (74fea27)
- K-1 git_state never swallows the capture Deadline (narrow except tuple).
- K-2 (amends J-6) a relative gitdir must resolve under the cwd; linked
  worktrees are never followed; a network mount under the project is a
  named hole; the THREAT_MODEL claim narrowed to "nothing outside the
  project directory".
- K-3 Holes named (reftable, packed-refs > 1 MiB, GIT_INDEX_FILE,
  relative worktrees, device-name form); the SILENCE-NOSTART pointer moves
  to "a later task".
- K-4 Edits before the first start are unknown, not dropped. K-5 tests.
  K-6 budget before each lstat. K-7 Windows share-mode window named.
  K-8 report shows the git keys on cited boundary lines. K-9 recorded.
Full text: docs/review/2026-11-03-M4.3-redo-ruling.md.

## Amendment L (the Table, 2026-11-03) - judgement on M4.3 (74fea27 + 6f20c1a)
- J-1..J-11 and K-1..K-9 MET as cited; the Table read GIT_READ_ERRORS
  (narrow except; the Deadline propagates) and `_git_follow` (commonpath
  must equal the cwd) on the branch.
- CI runs 41620828224 and 41625450784 success on six jobs each (read from
  api.github.com); gate 2376 passed, 9 skipped; kinds signature=4
  demand=7 anchor=6; scope clean.
- Verdict: NEXT; merge --no-ff under the commander's standing word.
- Open for a ruling by the commander: executing `git status` from the
  hook for STOP-DIRTY-TREE (the hook executes nothing today); parsing
  index entries instead of raw bytes (J-9).
