# ADR-0015 — A number for every Raqib: versions and the changelog

Status: accepted (the Table, 2026-11-20, under the commander's word of 2026-11-20: "a product as if a great
company built it", and on his field test of the same day). Date: 2026-11-20.

## Context
On 2026-11-20 the commander ran two copies of Raqib, one from before 13 November and one of that morning. Both
said `raqib 0.1.0`. The Table told them apart only by reading their sentences: one printed no `events` line at
its start. He asked "what did you change in this version?" and there was no version to name. Every instruction
to update ended with "the last line of `git log` should begin with ...", which is a builder's word, not a
person's.

## Decision
- V-1 (the number). `raqib.__version__` is `0.MINOR.PATCH`. MINOR moves with every merge into `main` that
  changes what Raqib does for a person (a rule, a source, a command, a report); PATCH with a merge that only
  repairs. A merge of documents or tests alone moves nothing. The Table moves the number in the merge itself.
  FOR: two copies that differ in what they do never say the same number.
- V-2 (where it is said). `raqib --version`; the first line a watch prints and the first line of its report;
  the window (its title bar or its Host screen's head); every event (already: `watch.version`); `raqib doctor`
  (already). In each it is the one `raqib.__version__`, read, never typed again.
- V-3 (the changelog). `CHANGELOG.md` at the root, the newest entry first: the number and its date, what is
  new in a person's words, how to update, what was not measured. The Table writes the entry; a builder never
  invents one. The gate holds: the number of the first entry is `raqib.__version__`; the entries' numbers go
  down the page; each has its three parts.
- V-4 (what a number is not). It is not a promise of stability, and the events' schema has its own name
  (`raqib-event/1`), which moves by its own rule (ADR-0011). Packages, installers and signatures are the next
  tasks (M17.2), not this one.

## Consequences
- The examples in the events' spec and every fixture that holds an event's `version` are made again by their
  generators when the number moves: the gate must make that one command, or the number will not be moved.
- The session protocol gains a line: the merge moves the number and writes the entry.

## Amendment A (the Table, 2026-11-20) - the builder's STOP of M17.1 and its questions, ruled
The builder stopped rightly: the guide's new sentences are held by a registry in a test the HANDOFF's Scope
did not name. The Scope now names it. Its choices are ruled as it made them:
- VA-1 (the form). The number is joined to a first line by `; raqib X.Y.Z`. A watch's first printed line and
  the first line of its report carry it, for a project's watch and for the host's. `raqib report` is not a
  watch: its first line stays, and so does the README's sample.
- VA-2 (what the tests hold). The form `0.MINOR.PATCH` and the changelog's first heading, not the literal
  number; the date's form on the first heading alone (the oldest entry says "before" a date). A made-up event
  in a test that holds `0.1.0` as its own input stays as it is.
- VA-3 (the examples are made by a command). `tools/event_examples.py --write` rewrites the examples of
  docs/specs/EVENT.md from the code, and `--check` says whether they are the code's own; the test that holds
  them calls the same function. Without it every move of the number would fail the gate until eighteen lines
  were edited by hand, and a number that is hard to move is not moved.
