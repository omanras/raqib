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

## Amendment B (the Table, 2026-11-20) - the review of M17.1 (docs/review/2026-11-20-M17.1.md): M17.1 lands
The reviewer's verdict is NEXT with two must-fix items; most of its findings are of the Table's own text.
- VB-1 (the update steps). The steps the Table wrote could not be followed on every install path the README
  gives. They are now by how Raqib was installed (pipx; pip in a venv or Windows' launcher; root's copy for the
  Linux service), they say first to stop what runs (a running watch keeps the number it started with: the
  very confusion this ADR is for), and the service's copy is a new folder for each number, never a copy over
  the old one. The service's steps are written from its spec and were not run on a machine: the entry and the
  guide say so, and M17.2 (packages) measures them. FOR: a person who follows the entry ends with the number
  it names. MUST NOT TOUCH: SERVICE.md's install steps.
- VB-2 (the tool's imports). The tool imports the standard library, raqib and tests/test_event.py, which needs
  pytest: VA-3 asks that the tool and the test share one builder, and the builder is the test's. The tool's
  words and its test's name now say so. E4's "the standard library and raqib alone" was the Table's wish and
  is withdrawn: a second copy of the fixture runs would be two builders that can disagree.
- VB-3 (an example's fence). The tool finds an example by its heading and the fence under it, and never
  crosses a heading or another fence on the way: an example whose fence is missing is no example of the
  document, is named, and nothing is written under a wrong label.
- VB-4 (one wording). `raqib --version` and the lines of a watch take the words "raqib <number>" from one
  function.
- VB-5 (the Consequences' sentence, put right). The gate does not move the examples:
  `tools/event_examples.py --write` does, run by the Table at the merge, and the gate stays red until it is
  run. The protocol's line says so, and that the tool needs pytest.
- VB-6 (the changelog's words). The 0.2.0 entry says the number's own lines as what is new (a script that
  matched a first line whole must match its beginning); it no longer says the reader "hears every process"
  (measured: it missed 0 to 2 of 200 programs that live under a millisecond), nor that the rig "holds" the
  rules (a missed claim is reported and does not fail a push), and the service is 0.1.0's, not new here.
- VB-7 (recorded). The events take the number when the module is imported (one value a process, so a real run
  is right; a test that moves the number does not move the events'). Run D's id, n and about are the
  document's and are never refreshed by the tool. An overlay's thresholds are measured again after every move
  of the number, by design (the stamp holds the version): the entry now says it.
