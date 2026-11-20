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
