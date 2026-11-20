# ADR-0017 — Ready content for a SOC's tools

Status: accepted (the Table, 2026-11-20, under the commander's order of 2026-11-18, the fifth of his five: "ready
content for a SIEM", and his word of 2026-11-20 that the link to a SOC's own controls was not there to be found).
Date: 2026-11-20.

## Context
Raqib writes its events in one documented shape (`raqib-event/1`, docs/specs/EVENT.md) and sends them
(docs/specs/FORWARD.md). The spec holds a table that maps every key to OCSF and to ECS. A SOC still has to build
everything that makes the events useful in its own tool: the parsing, the field names, the searches, the alarm
for silence. Each SOC would build it again, and each would find the same traps.

Measured before ruling (the probe branch c08e0e2 and 3ea65ce, GitHub's Linux machine, Elasticsearch 8.15.3 and
OpenSearch 2.17.1 in a container on the machine's own port, the 18 examples of the spec and a real watch's
events file):
- The events as they are, the engine guessing the fields: 6 of 31 lines refused, in both engines. A tree's
  `subject.started` is an instant on Windows and `boot+N` on Linux; the engine takes the first for a date and
  then refuses the second. A SOC that indexes the file as it is loses tree events, in silence unless it reads
  its indexer's errors.
- The same lines through a pipeline that follows the spec's Mapping, with one template (strings as keywords;
  the parts whose shape differs from kind to kind kept whole): none refused, in both engines; every named
  field there (`@timestamp`, `event.id`, `event.action`, `event.severity`, `host.name`, `observer.version`,
  `rule.id`, `rule.category`, `threat.technique.id`, `process.pid`, `process.name`, and the rest under
  `raqib`); the searches for an alarm, a rule's finding, a hole, a heartbeat and a watch that ended with a
  result other than 0 each count what the file holds; the hosts' latest heartbeat by the engine's own clock of
  arrival is one aggregation.
- OpenSearch 2.17 does not take the `copy_from` of Elasticsearch's `set` processor, and names its whole-object
  field type `flat_object` where Elasticsearch says `flattened`: one pipeline can serve both, one template
  cannot.
- Three drafts of Sigma rules over the events' own keys, converted by sigma-cli with a small pipeline of
  names: to both engines' query strings, which ran and counted what the file holds; and to Splunk's search
  language, which was converted and not run (no Splunk on the machine).
- Not measured: Splunk, Microsoft Sentinel, Wazuh, a SOC's own agent tailing the file (Filebeat, Elastic
  Agent, Fluent Bit), volumes above some tens of lines.

## Decision
- S-1 (what it is). A folder of the tree, `siem/`: for each tool the files a SOC installs, made to the spec's
  Mapping and to nothing else, and one page that says how the events reach that tool (the forwarder's shapes;
  the tool's own agent tailing the file). FOR: a SOC wires Raqib in an hour and gets the same fields and the
  same searches as every other SOC. MUST NOT TOUCH: the events and the forwarder (a shape wraps a line and
  never rewrites it, ADR-0011 J-6); nothing in `siem/` is imported by raqib, and Raqib still sends nothing by
  itself.
- S-2 (the guard is the engine itself). A file of `siem/` that an engine reads is proved by that engine: the
  rig runs Elasticsearch and OpenSearch in containers on its Linux machine, puts the examples and the watch's
  own events through the content, and claims that none is refused, that every field the Mapping names is
  there with the value the event holds, and that each search counts what a count made without the engine
  says. The gate, which has no engine, holds what can be held without one: every file parses, every key a
  rule or a search names is a key of the spec, every rule of the catalog is in the tables, no file holds a
  host's or a person's name.
- S-3 (the stages). M16.1: Elasticsearch and OpenSearch (the pipeline, the two templates, the searches, the
  search for silence), the Sigma rules with their pipelines of names, the table of the catalog's rules and
  their ATT&CK techniques with a layer for the ATT&CK Navigator, both made from the catalog by a tool the gate
  checks, the page, and the rig's claims. M16.2: Splunk (an app: the source type, the fields, the searches, the
  search for silence, the data model's tags), proved against a Splunk where the commander agrees to its
  licence's terms, else written from its documentation and said as not run. M16.3: Wazuh and Microsoft
  Sentinel, each proved where it can be run and said where it cannot; OCSF documents built from the events by
  a command of Raqib's for the stores that take them.
- S-4 (the trap is said where a SOC reads). The spec's section for a reader says what the measurement found:
  an engine that guesses the kinds of the fields refuses lines, and why; the content's template is the answer.
- S-5 (silence stays the collector's alarm). The search for silence is in the content of every tool: no
  heartbeat of a host for more than two of its beats, by the tool's own clock of arrival (FORWARD.md). It is
  the one search that no event can carry.

## Consequences
- A new top folder, `siem/`, that is not part of the package: it is read from the checkout or the release.
- The rig gains a job with two engines; a push takes some minutes more.
- The content follows the spec: a key added to the events (ADR-0016's `prev`) is in the namespace by the
  pipeline's own rule and needs no change; a named key added to the Mapping needs its line in the pipeline,
  and the rig's claim fails until it is there.

## Amendment A (the Table, 2026-11-21) - the review of M16.1 (docs/review/2026-11-20-M16.1.md): STOP, ruled
The reviewer stopped at the search for silence. Measured before ruling (the probe branch 1a1b253, the content of
4599659 installed, Elasticsearch 8.15.3 and OpenSearch 2.17.1, made-up hosts under .example):
- A deadline for every line - its arrival by the engine's clock and two of its own beats - and a host silent
  where the engine's clock has passed the latest deadline any of its lines gave: one search on both engines,
  the engine reading its own clock inside the selector (no time given by the caller). At once: none silent.
  After 3.6 s: the three hosts with a beat of 1 s and the host whose watch said its end. After 8 s: also the
  host whose first line had a beat of 3 s and whose later line had 1 s. Never: the host with a beat of 600 s,
  nor one whose heartbeat carried a `time` of the year 2000. Listed as it should be: a host that said only its
  start and never a heartbeat, and one whose heartbeat carried a `time` of 2099.
- The runs that stopped with no end, by host and run with the same deadline and a count of ends: exactly the
  five made-up runs with no end, never the one that said its end. On both engines.
- A search on a key inside a part kept whole (`raqib.result.word:INCOMPLETE`): one of one, on both.
- Twelve lines that are not as the spec has them. Refused by the engine and so lost: an empty key; `watch.run`
  as an object; a key the spec does not know nested 25 deep (and, in Elasticsearch, `evidence` so nested); 1001
  keys the spec does not know; a word of 40000 characters inside a part kept whole. Kept as an ordinary event:
  a `kind` the spec does not have; no `n`; `alarm` as a text. Kept as an error document: `n` beyond a long; a
  line that is not JSON; another schema. The line after each was kept every time.
- A shipper's own `host.hostname` and `host.ip` on the document: gone after the pipeline, which writes
  `host` anew.

- SA-1 (silence is a deadline every line gives). The search for silence lists the hosts where the engine's own
  clock has passed the latest deadline that any line of the host gave: the line's arrival
  (`event.ingested`) and two of that line's own `watch.beat`. Every line counts, not heartbeats alone; the beat
  is the line's own, so a long beat holds only for two of itself after its own arrival and no longer; no time
  is given by the caller. The hosts nearest their deadline's passing come first, and the search says its
  bound of hosts. FOR: the one alarm no event can carry is not put off by an old line, a forged long beat's
  reach is two of that beat, and a watch killed before its first heartbeat is seen. MUST NOT TOUCH: an
  event's own `time` is never what silence is judged by.
- SA-2 (the runs that stopped with no end). A search of its own: by host and run, the same deadline, and no
  `watch` event of `state` end. It is the spec's word for a watch that was killed (EVENT.md), beside the
  host's silence (FORWARD.md): the first names the run, the second the host.
- SA-3 (what the content trusts, said). The page says it plainly: every key of a well-formed line is trusted,
  `watch.host`, `watch.beat` and `time` among them, and the watched account writes the file; a forged line
  can keep a host off the list for two of the beat it names and can say any host's name. The answer the
  collector holds is where a line came from: the shipper's own fields.
- SA-4 (the shipper's fields are kept). The pipeline sets `host.name` and leaves every other field a shipper
  set on the document, `host.*` among them, on an event and on an error document alike.
- SA-5 (a line is an event, or it is kept as what it is; none is lost). The pipeline keeps as an error
  document, with its reason and the whole line, any line that is not an event by what the pipeline can tell:
  not JSON, another schema, a `kind` the spec does not have, a base key missing or of another kind of value
  (`alarm` that is not true or false, a number where a text is due), and any shape an engine would refuse - a
  nesting deeper than a bound, a text longer than a bound, more keys than a bound, an empty key. A key the
  spec does not know is not indexed: its name is listed and its value stays in the whole line. The rig feeds
  each measured line and claims that none is refused by the engine. The page says that the full check of a
  line is `raqib events` on the host, and that the pipeline's is the part an engine needs.
- SA-6 (no identity from the line). The content sets no document id from a line: a forged line could then
  write over a true one. Lines sent twice are two documents; the page says so and how to count once.
- SA-7 (the searches say what they count). An alarm's search counts every saying; the page says to take a
  thing's latest `rev`. `@timestamp` is the event's own time, the host's clock: a rule or a view that windows
  on it misses a line that arrives late; `event.ingested` is the arrival. The page says both, and that the
  template must be there before the first line and what a shipper that names its own pipeline does.
- SA-8 (every rule a watch can say is in the table). The table of techniques and the layer take every rule the
  report lists - the catalog's and those the code holds outside it (the silence rules, the cross-source rule,
  the drift anchors) - from the code's own list, not from the catalog's folder alone.
- SA-9 (the Sigma rules). No shipped rule names `alarm: false` or `severity`, and the page says why a rule of a
  SOC's own must not (the pipeline of names cannot carry them rightly). One more rule: a heartbeat whose
  state says the watch is not watching. Each rule is shown on the rig to match an event of its kind and to
  pass over a near miss.
- SA-10 (the claims can fail). The rig feeds made-up events of every class the rules and searches name, the
  made-up hosts of the measurement above for silence and for the runs with no end, a line of each shape of
  SA-5, and a document with a shipper's fields; it holds `event.ingested` between its own clock before and
  after the send; it names in every row what was fed and the versions of the tools it installed, which are
  pinned; the real watch of the job says heartbeats (a short beat).
- SA-11 (said as not measured). The layer was never loaded into a Navigator; nothing of Splunk, Sentinel,
  Wazuh, an engine's own shipper tailing the file, or volume.

## Amendment B (the Table, 2026-11-21) - the second review of M16.1 (docs/review/2026-11-21-M16.1-redo.md): REDO 2
The reviewer's verdict is REDO with the claims all MET: what it suspects was never fed. Measured before this
ruling (the probe branch 56ab935, tools/rig/siem_probe4.py, the content of 4aaa17c installed, Elasticsearch
8.15.3 and OpenSearch 2.17.1, the same on both unless said):
- A key of 40000 characters - a top-level key the spec does not know, one inside `result` or `watch`, one
  inside an item of `evidence.cites` - passes the pipeline's check and the engine refuses the line (an immense
  term in `raqib.unknown_keys`, or in the part kept whole). A key of 300 and one of 2000 characters are kept.
- `watch.beat` or `rule.fp_budget` written `1e400` passes the check and is refused (the engine reads Infinity).
  A beat of `1e308` and a beat of `-5` are kept as events.
- Beside a shipper's own field that is a text where the content writes an object: `event`, `error`, `rule` or
  `process` a text - the line is refused, an event or not; `host` or `observer` a text - an event is kept and
  the shipper's text is gone without a word, an error document is refused.
- The runs with no end: a `multi_terms` takes the order `[{"ends": "asc"}, {"deadline": "desc"}]` (the runs
  that said no end first, the latest deadline first); `ends._count` and `ends>_count` are refused as paths. With
  a size of 3 over 9 runs the answer's `sum_other_doc_count` is 8: it counts lines, not runs, and is 0 only
  where nothing was cut. A `composite` of the two fields with the same selector, read in pages of 3, lists the
  same five runs in four pages.
- `Math.min(beat, 86400.0)` in the deadline's script is taken, and changes no deadline of a beat under a day.
- SB-1 (no line is lost: the two the check let through). The pipeline's check also refuses, as an error
  document: a key longer than 256 characters anywhere in the line, and a number that is not finite. The rig
  feeds both among its odd lines. FOR: SA-5 holds for what was measured to break it. MUST NOT TOUCH: a key of
  256 characters or fewer that the spec does not know is still an event with its name listed.
- SB-2 (a shipper's field of another shape is moved aside, not lost and not a reason to lose the line). Before
  anything else, where `host`, `event`, `error`, `observer`, `rule`, `process` or `threat` holds what is not an
  object, the pipeline moves it to `displaced.NAME` as a text (at most 1024 characters of it); `displaced` is a
  part kept whole. This runs first and cannot fail, so that an error document can always be written. The rig
  feeds a `host` and an `event` that are texts, each with an event and with a line that is not JSON. FOR: an
  old collector that writes `host` as a text loses neither its lines nor its host's name.
- SB-3 (what the pipeline does to a shipper's fields, said exactly). Q2: an error document's `host.name` is
  what the shipper set, never read from a line that could not be trusted as an event. Q3: `message` is the
  Mapping's field for an event's `summary`; the shipper's `message` (the line) is replaced by it or, where the
  event has none, removed - the line is whole in `event.original`. The page says each: which fields are set,
  which are replaced, that `message` is, what is moved aside. The test that claimed "no field removed" is named
  for what it holds.
- SB-4 (the bound of the two searches says what it cuts). `runs-no-end.json` takes the measured order: past its
  bound the runs that said an end are left out first, then the runs whose deadline is oldest. Its sentence and
  the page say so, and that `sum_other_doc_count` above 0 in the answer means lines of runs beyond the bound
  exist; the page gives the `composite` form as measured on the probe, not on the rig. `silence.json`'s
  sentence says the same of its own bound.
- SB-5 (a deadline counts a beat to a day). In both searches a line's deadline is its arrival and two of its
  beat, the beat counted as at most 86400 s. FOR: one forged line keeps a host off the search for silence for
  two days at most, not for as long as its number says. The page says it, and what it still trusts: a forged
  `watch` end takes a run off the runs with no end for good; two hosts of one name are one host to silence.
  Not measured: the two days themselves.
- SB-6 (the error documents are found). A search of its own, `not-events.json`: the error documents, the
  latest arrival first. The page says where to look for them again, that a host whose every line is an error
  document is in no other search unless it once sent an event, and that an alarm whose line became an error
  document is in that search and in no other.
- SB-7 (the claims can fail, again). A read of silence or of the runs with no end that holds a group not sure
  is not MET: it is said n/a with the reason. A connection that fails or an answer that is not JSON in the
  middle of the run is each remaining claim said n/a with the reason, never a traceback behind a green job.
  X39 holds, for each odd line, the reason its error document must name - a table of its own, not the same
  rule written twice - and that every line of the real watch's file is an event, and prints the longest text
  and the longest key of those lines. A host or run the engine lists that was never fed is MISSED. The runner
  counts a text's length as the engine does.
- SB-8 (words). Not said as fact: a `cardinality` of two fields; the names of an engine's paid features. The
  questions file's sentence that an error document has no `event.ingested` is corrected in the new one. The
  titles that still say "the catalog's rules" follow SA-8.
- SB-9 (kept as built). Q1 the engine's clock by `System.currentTimeMillis()` (the rig ran it); Q4 the rule of
  a heartbeat not WATCHING takes FINISHED too, said as a false positive; Q6, Q7, Q9, Q11; Q8 the pins equal
  what the rig printed. Recorded, not built: the images are pinned by tag; more than one shard or node, a
  clock skew between nodes, retention; a real shipper tailing the file.

## Amendment C (the Table, 2026-11-21) - the third review of M16.1 (docs/review/2026-11-21-M16.1-redo2.md): lands
The reviewer's verdict is NEXT. The field's word on 4a834f8 (the first run of REDO 2's pipeline): on Elasticsearch
X39 to X42 MET; on OpenSearch X40 to X42 MET and X39 MISSED on one reason of 23 - a whole number beyond a long
(`n` = 2**70) is refused by OpenSearch itself before the check, in its own words, and is an error document all
the same. That is what the hand-written table of SB-7 is for. On bea9a8a, with the table holding it: X39 to X42
MET on both, the gate green on six jobs.
- SC-1 (the field the step writes). A shipper's own `displaced` that is not an object is moved to
  `displaced.displaced` whether or not another field was moved (the template keeps `displaced` whole since
  SB-2, and a text there would be refused). The rig feeds it alone, with an event and with a line that is not
  JSON, and beside a `host` that is a text where it is an object. A shipper's own `displaced.host` is
  overwritten by a moved `host`: recorded, not built.
- SC-2 (the table holds what was measured). For a number beyond a long on OpenSearch, X39 holds the part of
  the engine's words that names what it could not take (`java.math.BigInteger`), not any words that are none
  of the pipeline's. The lines that are not JSON keep the looser mark: the engine's words for them are not
  yet printed by the rig (recorded).
- SC-3 (the page says what was measured). Moved aside, and so no reason to lose a line: the seven fields and
  `displaced`, measured for `host`, `event` and `displaced`. Named as not handled and not measured: a field
  below them of another kind than the template types, a `message` that is not a text, an `@timestamp` that is
  not a date, a key with a dot in its name (the builder's Q4). A number beyond a long: measured at `n`.
  `not-events.json` gives the engine's default ten and the exact count. "The earliest deadline first". The
  count of a cut was measured without the selector. A real beat over a day lists a live host after two days.
- SC-4 (kept as built). Q1 a number that is not finite anywhere in the line; Q2 a reason names no key; Q5 the
  engine's own words for a line that is not JSON; Q6 n/a where the real watch gave no line; Q7 one group not
  sure makes the row n/a; Q10; Q11.
- SC-5 (recorded debts). The order of the runs with no end is read by eye, not judged by the runner; the order
  check of silence trusts the engine's own deadlines; X39's two paths for the real watch's file have no test;
  an answer of an unexpected shape still ends the runner with a traceback; a line with two faults may be
  given another reason by an engine than by the runner; a line with a key twice (Q8); NaN and Infinity as
  words (Q9); the largest shape the bounds allow inside a part kept whole on `flat_object`; a text over 8000
  characters that a watch could write (the rig's own file: its longest text 650); the images pinned by tag.
