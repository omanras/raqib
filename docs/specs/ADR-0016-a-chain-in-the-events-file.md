# ADR-0016 — A chain in the events file

Status: accepted (the Table, 2026-11-20, under the commander's order of 2026-11-18, the second of his five: "a
chain of hashes in the events file; the heartbeat carries the chain's head"). Date: 2026-11-20.

## Context
The events file (`~/.raqib/host/events.jsonl`, docs/specs/EVENT.md) is the watch's word as it leaves the host. A
reader of it can tell a torn line, and a run that was killed. It cannot tell a line that was taken out of the
middle, or changed, or put there by another hand: `n` has gaps by design (a number is used even where its line
could not be written, so that the gap is seen), and so a gap proves nothing either way. A collector that holds
the lines cannot say that it holds all of them, nor that the file on the host is still the file it read.

Nothing was measured for this ruling: a hash a line is cheap (one sha256 of some hundreds of bytes), and what the
chain costs in bytes is known (about 80 a line). What needs the rig is the check on a real watch's file, and
that is the task's own exit criterion.

## Decision
- H-1 (a chain of each run). Every event holds `prev`: the sha256, in hexadecimal, of the bytes of the line the
  same run wrote before it, without its newline; a run's first line holds the word `first`. The chain is the
  run's, not the file's: the file holds many runs and two watches of one account append to it at once, so a
  chain over the file's order would be broken by two honest writers. FOR: within a run, a line removed,
  changed, added or moved is seen by anyone who holds the lines. MUST NOT TOUCH: what a line says and when it
  is said; `n` and its gaps; a line is still only appended.
- H-2 (a write that failed). The writer chains from the last line it knows it wrote. A write that raised and
  yet left its whole line in the file leaves two lines that name the same line before them. The check says
  that apart from a break, as what it may be: a line the writer did not count as written, or a line put there
  by another hand. It cannot tell the two, and it is a problem of the file either way. A torn line is no
  event and is no link, as it is no event today.
- H-3 (the head leaves the host). A heartbeat and a watch's end are events of the chain like any other: a
  collector that holds one holds the hash of all the run wrote before it. Nothing more is sent, and the
  forwarder is unchanged (it sends lines as the file holds them).
- H-4 (the check). `raqib events FILE` says of each run: its chain is whole (so many lines); or where it breaks (the
  line, and that a line before it was removed, changed, added or moved); or that the run holds no chain (written by
  a Raqib before this one). A break, and a line beside the chain (H-2), is a problem of the file as a line that is
  no event is: exit 1. The same command over the lines a collector holds of a run (its own export, the lines as they
  were sent) checks what the collector holds.
- H-5 (what it does not prove, said). The chain has no secret. Whoever can write the file can cut its end, or
  write a tail again from any line and compute the hashes again: the file alone then looks whole. What cannot
  be done unseen is to change what a collector already holds a later line of. Under the service the record is
  root's and the watched account cannot write it; a chain keyed by a secret that account cannot read is a
  later stage and is recorded, not built here.
- H-6 (the schema keeps its name). `prev` is an addition to `raqib-event/1`. `event.check` takes a line with it
  and a line without it (a file holds the runs of older builds); this build always writes it. A reader of the
  file must allow a key it does not know: the spec says so from now on, and an addition of this kind does not
  move the schema's name.

## Consequences
- Every example of the events' spec gains `prev`; `tools/event_examples.py --write` makes them (ADR-0015 VA-3).
- `raqib events FILE` reads a whole file as before and now says more; a file of an older build is not a
  problem (its runs are said as not chained).
- The mapping gains one line: `prev` is in the namespace (OCSF `unmapped.raqib.prev`, ECS `raqib.prev`).
- The search of a SOC for a broken chain is not a query of a search engine: it is this command over an
  export. The ready content (M16) says so.
