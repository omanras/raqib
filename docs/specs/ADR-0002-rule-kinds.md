# ADR-0002 - Rule kinds: signature, demand, anchor

Status: proposed by the Table, 2026-10-22. Becomes accepted when M4.1 lands.
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
