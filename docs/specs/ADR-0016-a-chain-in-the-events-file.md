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

## Amendment A (the Table, 2026-11-20) - the review of M13.1 (docs/review/2026-11-20-M13.1.md): a short REDO
The reviewer's verdict is NEXT with four must-fix items; two findings change what the check says and are ruled
here. The field's word (the rig on 14fef1b): on Linux X38 MET, the run whole over 20 lines; on Windows the run
whole over 66 lines by `raqib events`, and X38 MISSED by its own reader's fault (Windows' line ends; put right
by the Table in 4208d72).
- HA-1 (a link is told by its shape). A line is a link of its run where it is a JSON object that names its
  host and its run and holds a `prev` of the right shape, whether or not this build's `event.check` takes it
  as an event. A line a later Raqib wrote with a key this build does not know is still named by this build as
  a problem of that line, as today; it is a link all the same, and the line after it is not said broken for
  it. FOR: H-6's word that a reader allows a key it does not know holds for the chain itself. MUST NOT TOUCH:
  what `event.check` says of a line. The spec's sentence that a line which fails the check is a torn write is
  put right: a torn write is a line that is not whole JSON.
- HA-2 (a chain taken out is said). A run no line of which holds `prev` is not chained. Where its lines'
  `watch.version` is the first version that writes the chain or a later one, that is a problem of the file
  (exit 1), said as what it is: this version always writes `prev`, and no line of the run holds one. Where
  the version is older, or cannot be read, it is said as today (not a problem). The first version is one
  constant, set to the number of the merge that lands this.
- HA-3 (a run is its host's). The check keys a run by its host and its run word together.
- HA-4 (the run's last line). No line names a run's last line. Changed, or followed by a line added after the
  run ended that names it, it is not seen from the file alone. H-1's FOR is read so: a line removed, changed,
  added or moved before the run's last line is seen. Every place that says "changed, added" says this limit.
- HA-5 (what a collector can tell, made a command). `raqib events FILE` over one file cannot show that a line
  a collector holds was changed on the host afterwards: both files are whole by themselves. What shows it is
  the two side by side. `raqib events FILE --against OTHER` reads OTHER as the lines a collector holds and
  says, by host and id: how many are in FILE byte for byte, which are not in FILE, and which are there with
  other bytes, each by its line numbers; exit 1 where one is missing or differs. It asks that the collector
  kept the lines' bytes as they were sent, and says so. FOR: H-3's head that leaves the host is something a
  person can use. MUST NOT TOUCH: `raqib events FILE` without the argument, but for this amendment's items.
- HA-6 (what the check says of lines that are not the whole run). A run whose first line here holds a hash is
  said as beginning before this file (its first lines are not here: an export that starts late, or a file
  whose beginning was cut), apart from a break, exit 1. A line that is byte for byte a line of the run already
  read is a line said twice, counted, and is no break and no line beside the chain.
- HA-7 (every problem of a run, in the file's order). The answer for a run lists each break and each line
  beside the chain, up to a bound that is said; a later break does not hide an earlier line beside. A line
  beside the chain is cited with the line it names and the line that names that one again.
- HA-8 (the spec shows a chained line). The examples of the spec are the builder functions' own events and
  hold no `prev` (the Consequence that every example gains one is withdrawn). The spec gains a made-up run of
  two written lines, under a heading that is not an example's, and a test holds that each is an event, that
  the first says `first` and that the second names the sha256 of the first as the document writes it.
- HA-9 (a line that cannot be read does not end the reader). A line whose reading raises (JSON nested deeper
  than the interpreter reads) is named as not an event by `raqib events` and is no link; the forwarder takes
  it as a line it refuses, and is not ended by it. Whoever can write the events file must not be able to end
  either with one line.
- HA-10 (words and small things). The base keys' range in the spec leaves `prev` out. The threat model's
  sentence on a tail written again is held by a test of that very case, as the cut end's is. Tests: a run
  whose first write fails (the next written line says `first`); a file replaced under a running watch (the
  next line names a line that is not there: said). The rig keeps what `raqib events` wrote to its error
  stream. The tool of the examples says in its own words what `prev` in its list is for.

## Amendment B (the Table, 2026-11-21) - the second review (docs/review/2026-11-20-M13.1-redo.md): M13.1 lands
The reviewer's verdict is NEXT with five must-fix items. The field's word (the rig on 5d3e673): X38 MET on Linux
(20 lines) and on Windows (59 lines).
- HB-1 (a version is bounded). A part of a version is at most six digits: a longer one is no version, said as
  not read. Reading a version cannot raise (a number of thousands of digits ends a newer interpreter's int()).
- HB-2 (no line ends the command). A line whose values cannot be checked - a host that is a list, a result's
  word that is an object - is named as not an event and the command goes on; a line's id is keyed with its
  host only where the host is a text. HA-9's sentence now holds for `raqib events` as it did for the forwarder.
- HB-3 (nothing compared is said). `--against` over a file of which no line names its host and id - an empty
  export, another envelope, another encoding - compares nothing: that is said, and is a problem (exit 1),
  never "a collector behind" alone.
- HB-4 (FILE and OTHER are told by their place), so a file compared with itself under any name is compared.
- HB-5 (the version is the line's own word). `CHAIN_SINCE` is the number of the merge that lands the chain, and
  a test holds that this build's own number is not below it. Whoever removes every `prev` of a run and writes
  its lines' version again as an older one makes it read as an older build's: said in the spec and the threat
  model with H-5's other limits.
- HB-6 (words and the rig). A run that begins before the file is said as naming no line of its run before it
  here; a run is its host and its run word wherever the spec says what a run is; the spec says that one
  carriage return before a newline is part of the line's end to the check, and what that leaves unseen; a
  differing line says how many more of the file's lines hold its id; `--against` is said to see a cut or a
  tail written again only where the collector holds a line of that part. X38 is not MET where the watch's own
  run holds a line said twice: its writer writes none.
- HB-7 (recorded). After a break the walk goes on from the line that broke, so one act can give several
  breaks: each is true, the first is where the file was touched, and the answer does not say so yet. In a
  fork the earlier branch is the one said beside. "Chain whole" does not say whether the run said its end.
  The forwarder of this build skips a later build's line that holds a key it does not know. `raqib events`
  holds the file and the other whole in memory. Each waits for its own task.
