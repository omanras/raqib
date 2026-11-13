# EVENT - the event, raqib-event/1 (ADR-0011 Amendment B, as Amendments C and D rule it; M10.1 REDO 2)

An event is one line Raqib says about what its watch holds: a finding, a source finding, a note, a tree, a
hole or a blind spot, a knock, a heartbeat, or the watch's start and end. It is built once, in Raqib's own
shape, by one module (`raqib/event.py`, B-1); a collector's shape (OCSF, ECS) is a mapping of it, given below.
The watch does not write events yet (M10.2).

- An event is a thing said once (C-1). `id` ("<run>:<n>", n one more for each event the run says) names the
  saying and is never used twice in a run; a run id is not known to be unique across hosts, so an id is unique
  within a host, and a collector keys by `watch.host` and `id` and drops what it has seen. What the event is
  about is named apart: `about` (the ledger and the entry's place in it, or the tree's word, or the watch) and
  `rev` (1 the first time; one more each time it is said again because it changed: a finding that grew, a knock
  whose fold was decided, a tree that was knocked). Both are given by the caller.
- A name is a place in a list that only grows (D-1). The state shows the watch's holes followed by the
  notifier's, and the notes followed by one note that is always last: a place in a joined list moves, so each is
  named in its own list. A hole of the watch is "hole:i"; a hole of the notifier (the entry that holds a count)
  is "notifier-hole:i". A note is "note:i" over the watch's own notes; the note of the words a terminal lost
  (always last, and its text changes) is "note:lost-words" when `snapshot` is told its text (`lost`: the
  watch's `watch.lost_note` of its out); without it the note is numbered as any other. Findings, source
  findings, blind spots, knocks and trees are named as before: their lists only grow.
- `about` is a name within one run (D-2): two runs of one input may number the same thing differently, and two
  hosts may share a run's name. Outside its run a thing is called by the run and the name together,
  "<watch.run>/<about>" (see Mapping).
- `watch.host` is required on every event (D-3): `check` refuses an event without it and `event.facts` refuses
  to be called without it (ValueError); a collector keys by it.
- `event.snapshot(state, facts, time, knocks, rules, lost=None)` gives the events of one state of a watch in one call, n
  from 1 and rev 1. It is not how a running watch says events: a running watch (M10.2) keeps the count of its
  events and says a changed thing again with the next rev. `snapshot` must be given every knock row
  (`knock_rows()`: the state keeps only the newest) and the rule table (a finding needs its rule's `attack`).
- One line: JSON, keys sorted, compact (no spaces), ASCII (non-ASCII escaped). The same entries give the same
  lines byte for byte (B-3).
- Nothing new is said about the watched machine (B-4, C-9): an event holds only what its entry holds and the
  report prints; a text is the report's sentence. No command line, no file content, no row of a sample, no
  cite's text, no secret. A rule's own class, kind, budget and technique ids are the rule's, written in its
  file: they are in the event and need not be in the printed report. An empty `rule.attack` means the rule
  declares none: a catalog rule's file says why (its `attack_note`), and a person's own rule may declare none.
- A path is the machine's: a path (`evidence.record`, `evidence.trace`, `subject.path`) is said as the report
  says it, absolute, with the machine's separators; it holds the account's name where the machine's path does.
- A key the entry does not hold is absent: never null, never guessed (C-2); a value that is an empty string is
  not held (D-5), and a cite that lacks its src or its line is left out whole, never half. A builder that would
  build an event without what its kind requires raises ValueError naming the key instead (C-10).
- A source finding's `state` is C-4's word (D-5), and the report prints, for each of the six: "judged on another
  tree": the report prints "judged on another tree"; "history": the report prints "history"; "pending at exit":
  the report prints "pending at exit"; "noted": the report prints "noted (benign)"; "not settled": the report
  prints "not settled"; "settled": the report prints the rule's severity (high, medium or low).
- A heartbeat's `state` is the band's word without its number (D-4): "WATCHING", "SILENT", "AGENT GONE",
  "CAPTURE FAILED", "FINISHED" ("SILENT for 12 s" is SILENT). A band outside them (the host watch's "HOST
  READER FAILED" and "READER LATE") is refused: the builder raises ValueError naming `state`.
- `evidence.lines` counts the trace's lines from 1 (the first line of the file is 1). `subject.by` is carried by
  no event yet: no row of the watch says how a tree became a candidate (M10.2).
- A technique id in `rule.attack` says what a finding is consistent with, never that it happened (B-5).

## Keys

In C-2's order (a line sorts them). A dotted name is a key of the object named before the dot. Types:
`str` a non-empty string; `int` an integer; `pos` an integer from 1; `count` an integer from 0; `bool` true
or false; `number` an integer or a decimal; `instant` a string, UTC ISO 8601 with milliseconds and Z, that is
a real instant; `object` a non-empty object; `ints` a list of integers from 0; `ids` a list of technique ids (T
and four digits, a sub-technique's three after a dot), none twice; `cites` a list of cites, each {src: str,
line: count} and, where the cite holds them, {round: count, seq: count}. A round, a pid, a seq, a line and n
are never negative (D-5). A closed list's values are quoted. OCSF and ECS: the named
field (see Mapping), else the namespace.

| key | type | values and meaning | kinds | OCSF | ECS |
|---|---|---|---|---|---|
| `schema` | `str` | raqib-event/1, the shape's name and version | all | `unmapped.raqib.schema` | `raqib.schema` |
| `id` | `str` | <run>:<n>: names the saying; never used twice in a run; a collector keys by watch.host and id | all | `metadata.uid` | `event.id` |
| `n` | `pos` | the event's number in its run: one more for each event the run says | all | `unmapped.raqib.n` | `raqib.n` |
| `time` | `instant` | when Raqib said it: UTC, ISO 8601, milliseconds, Z; a real instant | all | `time` (epoch milliseconds), `time_dt` (as given) | `@timestamp` |
| `kind` | `str` | "finding", "source-finding", "note", "tree", "hole", "knock", "heartbeat", "watch" | all | `class_uid`, `category_uid` (the class: see Mapping) | `event.action` |
| `about` | `str` | what the event is about, a name within one run (D-2): finding:i, source-finding:i, hole:i (the watch's), notifier-hole:i (the notifier's), blind:i, note:i, knock:i (a place in a list that only grows, from 1, D-1); note:lost-words (the words a terminal lost); tree:<the tree's word>; watch | all | `finding_info.uid`, `metadata.correlation_uid` (each as "<watch.run>/<about>") | `raqib.about` |
| `rev` | `pos` | 1 the first time it is said; one more each time it is said again because it changed | all | `activity_id`, `type_uid` (see Mapping) | `raqib.rev` |
| `severity` | `str` | "high", "medium", "low" (the rule's: a finding and a source finding); "hole" (a hole); "info" (a blind spot and every other kind) | all | `severity_id` (high 4, medium 3, low 2, info 1, hole 3) | `event.severity` (the same number) |
| `alarm` | `bool` | true, false: whether the report counts it under ALARMS or INCOMPLETE (C-4) | finding, source-finding, hole | `is_alert` | `event.kind` (alert when true, else event) |
| `summary` | `str` | one sentence, the report's own (a hole: kind: detail; a knock: its body) | finding, source-finding, note, hole, knock | `message`, `finding_info.desc` | `message` |
| `rule` | `object` | the rule that fired | finding, source-finding | `unmapped.raqib.rule` | `raqib.rule` |
| `rule.id` | `str` | the rule's id | finding, source-finding | `finding_info.analytic.uid`, `finding_info.title` | `rule.id` |
| `rule.class` | `str` | the rule's class (NET, HOST, SILENCE, CROSS ...) | finding, source-finding | `unmapped.raqib.rule.class` | `rule.category` |
| `rule.kind` | `str` | signature, demand or anchor (ADR-0002) | finding, source-finding | `unmapped.raqib.rule.kind` | `raqib.rule.kind` |
| `rule.fp_budget` | `number` | the rule's false-positive budget, from the rule table | finding, source-finding | `unmapped.raqib.rule.fp_budget` | `raqib.rule.fp_budget` |
| `rule.attack` | `ids` | the ATT&CK technique ids the rule declares (B-5): what a finding is consistent with, never that it happened; empty: the rule declares none | finding, source-finding | `finding_info.attacks[].technique.uid` | `threat.technique.id` |
| `subject` | `object` | what the event is about; a key the entry does not hold is absent | finding, source-finding, note, tree | `unmapped.raqib.subject` | `raqib.subject` |
| `subject.tree` | `str` | the tree's word as the report says it, pid:image:started | finding, source-finding, note, tree | `unmapped.raqib.subject.tree` | `raqib.subject.tree` |
| `subject.pid` | `count` | the tree's root pid (from 0) | finding, source-finding, tree | `evidences[].process.pid` | `process.pid` |
| `subject.image` | `str` | the root's image name (discover's normalised form) | finding, source-finding, tree | `evidences[].process.name` | `process.name` |
| `subject.started` | `str` | the tree's start, the third part of its key, as the machine gave it | tree | `unmapped.raqib.subject.started` | `raqib.subject.started` |
| `subject.named` | `bool` | whether the tree is named (a finding's word named or unknown as the boolean it means) | finding, tree | `unmapped.raqib.subject.named` | `raqib.subject.named` |
| `subject.agent` | `str` | the agent a footprint is of | finding, note | `unmapped.raqib.subject.agent` | `raqib.subject.agent` |
| `subject.path` | `str` | the footprint's path (the machine's: it holds the account's name where the machine's does) | finding, note | `unmapped.raqib.subject.path` | `raqib.subject.path` |
| `subject.benign` | `bool` | whether the tree is benign (its acts are noted, not knocked) | tree | `unmapped.raqib.subject.benign` | `raqib.subject.benign` |
| `subject.history` | `bool` | whether the tree was there at the start | tree | `unmapped.raqib.subject.history` | `raqib.subject.history` |
| `subject.by` | `str` | how the tree became a candidate, where the row says (carried by no event yet) | tree | `unmapped.raqib.subject.by` | `raqib.subject.by` |
| `evidence` | `object` | where a person or a system can check it (A5); absent keys as for subject | finding, source-finding, note, tree, hole, knock | `unmapped.raqib.evidence` | `raqib.evidence` |
| `evidence.run` | `str` | the run the cited lines are of | finding, source-finding, note | `unmapped.raqib.evidence.run` | `raqib.evidence.run` |
| `evidence.round` | `count` | the round of the watch (from 0) | finding, note, hole, knock | `unmapped.raqib.evidence.round` | `raqib.evidence.round` |
| `evidence.rounds` | `ints` | a rhythm finding's cycle rounds | finding | `unmapped.raqib.evidence.rounds` | `raqib.evidence.rounds` |
| `evidence.record` | `str` | the file the seqs are in (the state's trace, the report's record) | finding, note, tree | `unmapped.raqib.evidence.record` | `raqib.evidence.record` |
| `evidence.source` | `str` | the source the cited lines are of (os, hooks, host) | source-finding | `unmapped.raqib.evidence.source` | `raqib.evidence.source` |
| `evidence.trace` | `str` | the source finding's own file the cited lines are in | source-finding | `unmapped.raqib.evidence.trace` | `raqib.evidence.trace` |
| `evidence.seqs` | `ints` | the seqs cited (a tree: its HostTree line's) | finding, source-finding, note, tree | `unmapped.raqib.evidence.seqs` | `raqib.evidence.seqs` |
| `evidence.lines` | `ints` | the line numbers cited in the trace (its lines counted from 1) | source-finding | `unmapped.raqib.evidence.lines` | `raqib.evidence.lines` |
| `evidence.cites` | `cites` | the record lines cited: each {src, line} and {round, seq} where the cite holds them (a cite without its src or its line is left out whole); never its text | finding, note, tree | `unmapped.raqib.evidence.cites` | `raqib.evidence.cites` |
| `hole` | `object` | the hole or the blind spot | hole | `unmapped.raqib.hole` | `raqib.hole` |
| `hole.kind` | `str` | the hole's own kind (reader-failed, notify-failed, bytes ...) | hole | `finding_info.title` (a hole) | `raqib.hole.kind` |
| `hole.class` | `str` | "hole", "blind spot" | hole | `unmapped.raqib.hole.class` | `raqib.hole.class` |
| `hole.count` | `count` | a notifier's hole: how many times it happened; a blind spot: the number of rounds it was seen in | hole | `unmapped.raqib.hole.count` | `raqib.hole.count` |
| `hole.last` | `str` | when the notifier's hole last happened | hole | `unmapped.raqib.hole.last` | `raqib.hole.last` |
| `knocked` | `object` | whether Raqib knocked a person for it and what became of the knock | finding, source-finding, tree, hole, knock | `unmapped.raqib.knocked` | `raqib.knocked` |
| `knocked.status` | `str` | the knock's status now (sent, off, failed, not notified: ..., a fold's outcome) | finding, source-finding, tree, hole, knock | `status_detail` | `raqib.knocked.status` |
| `knocked.event` | `str` | the knock's event (the KNOCKS ledger's event column) | knock | `unmapped.raqib.knocked.event` | `raqib.knocked.event` |
| `knocked.title` | `str` | the knock's title | knock | `unmapped.raqib.knocked.title` | `raqib.knocked.title` |
| `knocked.limit_id` | `str` | the knock's rate-limit id | knock | `unmapped.raqib.knocked.limit_id` | `raqib.knocked.limit_id` |
| `knocked.called` | `str` | what the notifier said at the call | knock | `unmapped.raqib.knocked.called` | `raqib.knocked.called` |
| `state` | `str` | "judged on another tree", "history", "pending at exit", "noted", "not settled", "settled" (a source finding: C-4's word, in the report's order); "start", "end" (a watch); "WATCHING", "SILENT", "AGENT GONE", "CAPTURE FAILED", "FINISHED" (a heartbeat: the band's word without its number) | source-finding, heartbeat, watch | `unmapped.raqib.state` | `raqib.state` |
| `result` | `object` | the exit and its word | heartbeat, watch end | `unmapped.raqib.result` | `raqib.result` |
| `result.word` | `str` | "CLEAN" (exit 0), "ALARM" (exit 1), "INCOMPLETE" (exit 3); another exit has no word | heartbeat, watch end | `unmapped.raqib.result.word` | `raqib.result.word` |
| `result.exit` | `int` | a heartbeat: the exit the watch would end with now (the state's code so far); a watch end: the exit the caller gives | heartbeat, watch end | `unmapped.raqib.result.exit` | `raqib.result.exit` |
| `counts` | `object` | what the ledger holds so far | heartbeat, watch end | `unmapped.raqib.counts` | `raqib.counts` |
| `counts.rounds` | `count` | rounds attempted | heartbeat, watch end | `unmapped.raqib.counts.rounds` | `raqib.counts.rounds` |
| `counts.findings` | `count` | findings of the rounds | heartbeat, watch end | `unmapped.raqib.counts.findings` | `raqib.counts.findings` |
| `counts.source_findings` | `count` | findings of the trees' sources | heartbeat, watch end | `unmapped.raqib.counts.source_findings` | `raqib.counts.source_findings` |
| `counts.holes` | `count` | holes (the watch's and the notifier's) | heartbeat, watch end | `unmapped.raqib.counts.holes` | `raqib.counts.holes` |
| `counts.blind` | `count` | blind spots | heartbeat, watch end | `unmapped.raqib.counts.blind` | `raqib.counts.blind` |
| `counts.notes` | `count` | notes | heartbeat, watch end | `unmapped.raqib.counts.notes` | `raqib.counts.notes` |
| `counts.trees` | `count` | trees seen | heartbeat, watch end | `unmapped.raqib.counts.trees` | `raqib.counts.trees` |
| `counts.knocks` | `count` | knocks, all of them | heartbeat, watch end | `unmapped.raqib.counts.knocks` | `raqib.counts.knocks` |
| `watch` | `object` | the watch's facts, on every event | all | `unmapped.raqib.watch` | `raqib.watch` |
| `watch.run` | `str` | the watch's run; required on every event | all | `unmapped.raqib.watch.run` | `raqib.watch.run` |
| `watch.mode` | `str` | the watch's mode (host) | all | `unmapped.raqib.watch.mode` | `raqib.watch.mode` |
| `watch.platform` | `str` | the platform the watch runs on | all | `unmapped.raqib.watch.platform` | `raqib.watch.platform` |
| `watch.version` | `str` | Raqib's version | all | `metadata.product.version` (`metadata.product.name` Raqib) | `observer.version` (`observer.product` Raqib) |
| `watch.host` | `str` | the host's name, as the caller gives it; required on every event (D-3) | all | `device.hostname` | `host.name` |

## Mapping

The Table's, checked against OCSF 1.5.0's Detection Finding and Finding Information (C-11). A key maps to a
named field or to the namespace: OCSF `unmapped.raqib.<key>`, ECS `raqib.<key>`. Named, and no others:

- finding, source-finding and hole are OCSF Detection Finding (`class_uid` 2004, `category_uid` 2;
  `activity_id` 1 Create at rev 1, 2 Update after; `type_uid` 200400 + `activity_id`); every other kind is
  OCSF Base Event (`class_uid` 0).
- `time` -> `time` as epoch milliseconds and `time_dt` as given; ECS `@timestamp`.
- `severity` -> `severity_id` high 4, medium 3, low 2, info 1, hole 3; ECS `event.severity` the same number.
- `alarm` -> `is_alert`; ECS `event.kind` "alert" when true, else "event".
- `about` is a name within one run: "<watch.run>/<about>" (the run and the name together) ->
  `finding_info.uid` and `metadata.correlation_uid`; ECS `event.id` stays the event's `id`.
- `id` -> `metadata.uid`; ECS `event.id`.
- `summary` -> `message` and `finding_info.desc`; ECS `message`.
- `rule.id` -> `finding_info.analytic.uid` and `finding_info.title`; ECS `rule.id`. `rule.class` -> ECS
  `rule.category`. `rule.attack` -> `finding_info.attacks[].technique.uid`; ECS `threat.technique.id`.
- `subject.pid`, `subject.image` -> `evidences[].process.pid`, `.process.name`; ECS `process.pid`,
  `process.name`.
- `watch.host` -> `device.hostname`; ECS `host.name`.
- `watch.version` -> `metadata.product.version` (`metadata.product.name` is "Raqib"); ECS `observer.version`
  (`observer.product` "Raqib").
- `kind` -> ECS `event.action`. `knocked.status` -> `status_detail`.
- For a hole, `hole.kind` -> `finding_info.title`.
- For the kinds that are Base Event (note, tree, knock, heartbeat, watch): `id` -> `metadata.uid`, `summary` ->
  `message`, the rest in the namespace.
- The whole line -> OCSF `raw_data`; ECS `event.original`.

## Required keys

Every event holds the base keys (`schema` to `severity`, and `watch` with `watch.run` and `watch.host`); each
kind adds its own; a dotted name is
required inside its part. A watch end (`state` end) holds `result` with `exit`, and `counts`; a watch start
holds neither. Any other key of the table is held only where the entry holds it. `event.check(obj)` names
every problem of an event, each beginning with its key; every event the module builds has none.

| kind | required keys |
|---|---|
| finding | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `alarm`, `summary`, `rule`, `rule.id`, `rule.attack`, `evidence` |
| source-finding | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `alarm`, `summary`, `rule`, `rule.id`, `rule.attack`, `subject`, `evidence`, `state` |
| note | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `summary` |
| tree | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `subject`, `subject.tree` |
| hole | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `alarm`, `summary`, `hole`, `hole.kind`, `hole.class` |
| knock | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `summary`, `knocked`, `knocked.status` |
| heartbeat | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `state`, `result`, `result.exit`, `counts` |
| watch | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `state` |
| watch end | `schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`, `watch.run`, `watch.host`, `state`, `result`, `result.exit`, `counts` |

## Examples

One line per kind and per source-finding state, each the line `raqib/event.py` builds (`event.snapshot`, host
`host.example`) from a fixture watch (B-7, C-12); `tests/test_event.py` builds them again and compares. The
machine's paths under the fixture's temporary home are written here `~/` and with `/`, and a trace directory
named by the hash of a temporary project's path is written `proj-HASH`: what the module says is the machine's
path (see above). Run A: the field run of `tests/test_field_run.py` (run `field-run`). Run B: the os source of
`net-windows` on powershell pid 5888 of `tests/test_acts_judged.py` (run `fixture-run`). Run C: a reader that
fails in round 2, as in `tests/test_host.py` (run `hole-run`). Run D: a person's and an agent's processes under
explorer, `tests/test_acts_judged.py` (run `fixture-run`). Run N: run B with a decision that raises. Run P: a
hooks source silent at stop, `tests/test_host_sources.py` (run `pending-run`). Run R: the rhythm cycle of
`tests/test_rhythm.py` with a notifier that fails (run `rhythm-run`).
Run D's source findings are read by two os follows, and which of them the watch lists first varies from
run to run: its examples' `id`, `n` and `about` are those of one run (the test compares the rest).
The heartbeat's and the watch end's examples are the last event of two snapshots of one watch (run B at its
last round, and after its end), so they share a number, and are never both in one stream.

### example: finding

From run B.

```json
{"about":"finding:1","alarm":true,"evidence":{"cites":[{"line":8,"src":"win-process-1"},{"line":4,"src":"win-tcp-1"},{"line":9,"src":"win-process-1"}],"record":"~/.raqib/host/rounds.jsonl","round":2,"run":"fixture-run","seqs":[1]},"id":"fixture-run:3","kind":"finding","knocked":{"status":"off"},"n":3,"rev":1,"rule":{"attack":["T1059"],"class":"HOST","fp_budget":0.4,"id":"NEW-AGENT-UNKNOWN","kind":"anchor"},"schema":"raqib-event/1","severity":"medium","subject":{"image":"powershell","named":false,"pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"summary":"unknown agent tree powershell pid 5888 (round 2, was absent)","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: finding: HOST-RHYTHM

From run R.

```json
{"about":"finding:1","alarm":true,"evidence":{"cites":[{"line":2,"round":1,"seq":1,"src":"win-tcp"},{"line":4,"round":2,"seq":2,"src":"win-process"},{"line":2,"round":2,"seq":2,"src":"win-tcp"},{"line":5,"round":3,"seq":3,"src":"win-process"},{"line":2,"round":3,"seq":3,"src":"win-tcp"},{"line":6,"round":4,"seq":4,"src":"win-process"}],"record":"~/.raqib/host/rounds.jsonl","round":4,"rounds":[2,3,4],"run":"rhythm-run","seqs":[4]},"id":"rhythm-run:3","kind":"finding","knocked":{"status":"failed"},"n":3,"rev":1,"rule":{"attack":["T1059","T1071"],"class":"HOST","fp_budget":0.0,"id":"HOST-RHYTHM","kind":"anchor"},"schema":"raqib-event/1","severity":"high","subject":{"image":"relay-bot","named":false,"pid":4400,"tree":"4400:relay-bot:2026-11-03T09:00:00.000000Z"},"summary":"unknown tree relay-bot pid 4400: 3 talk-then-act cycles to 192.0.2.10:443 in the last 10 rounds (round 4)","time":"2026-11-03T10:00:30.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"rhythm-run","version":"0.1.0"}}
```

### example: note

From run A (the dark note).

```json
{"about":"note:4","evidence":{"cites":[{"line":2,"src":"footprints"}],"record":"~/.raqib/host/rounds.jsonl","round":13,"run":"field-run","seqs":[27]},"id":"field-run:11","kind":"note","n":11,"rev":1,"schema":"raqib-event/1","severity":"info","subject":{"agent":"kimi","path":"C:\\Users\\user\\.kimi","tree":"10728:kimi:11/2/2026 10:21:05 AM"},"summary":"round 13: kimi footprint C:\\Users\\user\\.kimi: dark after a live tree (note): no live tree for 3 rounds since its tree 10728:kimi:11/2/2026 10:21:05 AM was live (round 10, within the live window of 9 rounds); not a knock, not an alarm (cites run field-run seq 27)","time":"2026-11-03T10:02:00.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"field-run","version":"0.1.0"}}
```

### example: tree

From run B.

```json
{"about":"tree:5888:powershell:2026-11-10T07:50:00.000Z","evidence":{"cites":[{"line":8,"src":"win-process-1"},{"line":4,"src":"win-tcp-1"},{"line":9,"src":"win-process-1"}],"record":"~/.raqib/host/rounds.jsonl","seqs":[2]},"id":"fixture-run:2","kind":"tree","knocked":{"status":"off"},"n":2,"rev":1,"schema":"raqib-event/1","severity":"info","subject":{"benign":false,"history":false,"image":"powershell","named":false,"pid":5888,"started":"2026-11-10T07:50:00.000Z","tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: hole

From run C.

```json
{"about":"hole:1","alarm":true,"evidence":{"round":2},"hole":{"class":"hole","kind":"reader-failed"},"id":"hole-run:6","kind":"hole","knocked":{"status":"sent"},"n":6,"rev":1,"schema":"raqib-event/1","severity":"hole","summary":"reader-failed: round 2: the reader failed: OSError: snapshot failed","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"hole-run","version":"0.1.0"}}
```

### example: hole: blind spot

From run B.

```json
{"about":"blind:1","alarm":false,"evidence":{"round":1},"hole":{"class":"blind spot","count":3,"kind":"bytes"},"id":"fixture-run:7","kind":"hole","n":7,"rev":1,"schema":"raqib-event/1","severity":"info","summary":"bytes: the reader gave no byte counts for the connections (no byte reader on fixture): bytes not read (does not change the result)","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: knock

From run B.

```json
{"about":"knock:1","evidence":{"round":2},"id":"fixture-run:11","kind":"knock","knocked":{"called":"off","event":"NEW-AGENT-UNKNOWN","limit_id":"NEW-AGENT-UNKNOWN pid 5888","status":"off","title":"Raqib: NEW-AGENT-UNKNOWN powershell"},"n":11,"rev":1,"schema":"raqib-event/1","severity":"info","summary":"host, powershell pid 5888 (unknown)","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: heartbeat

From run B (at its last round, before its end).

```json
{"about":"watch","counts":{"blind":1,"findings":1,"holes":0,"knocks":2,"notes":3,"rounds":3,"source_findings":3,"trees":1},"id":"fixture-run:13","kind":"heartbeat","n":13,"result":{"exit":1,"word":"ALARM"},"rev":1,"schema":"raqib-event/1","severity":"info","state":"WATCHING","time":"2026-11-03T10:00:20.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: watch start

From run B.

```json
{"about":"watch","id":"fixture-run:1","kind":"watch","n":1,"rev":1,"schema":"raqib-event/1","severity":"info","state":"start","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: watch end

From run B (after its end, exit 1).

```json
{"about":"watch","counts":{"blind":1,"findings":1,"holes":0,"knocks":2,"notes":3,"rounds":3,"source_findings":3,"trees":1},"id":"fixture-run:13","kind":"watch","n":13,"result":{"exit":1,"word":"ALARM"},"rev":1,"schema":"raqib-event/1","severity":"info","state":"end","time":"2026-11-03T10:00:30.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding: settled

From run B.

```json
{"about":"source-finding:1","alarm":true,"evidence":{"lines":[8,9],"run":"fixture-run","seqs":[5],"source":"os","trace":"~/.raqib/host/sources/fixture-run-5888-04cd10d3a5.jsonl"},"id":"fixture-run:4","kind":"source-finding","knocked":{"status":"off (knocked on tree pid 5888)"},"n":4,"rev":1,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"settled","subject":{"image":"powershell","pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"summary":"process may reach the network at seq 5 (host -, program bitsadmin, programs [\"bitsadmin.exe\"])","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding: history

From run D.

```json
{"about":"source-finding:4","alarm":false,"evidence":{"lines":[1],"run":"fixture-run","seqs":[1],"source":"host","trace":"~/.raqib/host/sources/fixture-run-5100-7a6e6a35c0-host.jsonl"},"id":"fixture-run:8","kind":"source-finding","knocked":{"status":"history: not knocked"},"n":8,"rev":1,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"history","subject":{"image":"explorer","pid":5100,"tree":"5100:explorer:2026-11-10T07:41:00.000Z"},"summary":"HostChild may reach the network at seq 1 (host -, program ssh, curl, programs [\"cmd\", \"ssh\", \"curl\"])","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding: judged on another tree

From run D.

```json
{"about":"source-finding:3","alarm":false,"evidence":{"lines":[14,15],"run":"fixture-run","seqs":[8],"source":"os","trace":"~/.raqib/host/sources/fixture-run-5100-7a6e6a35c0.jsonl"},"id":"fixture-run:7","kind":"source-finding","knocked":{"status":"judged on another tree: judged on tree pid 6100 (one act, one finding)"},"n":7,"rev":1,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"judged on another tree","subject":{"image":"explorer","pid":5100,"tree":"5100:explorer:2026-11-10T07:41:00.000Z"},"summary":"process may reach the network at seq 8 (host -, program curl, programs [\"curl.exe\"])","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding: noted

From run D.

```json
{"about":"source-finding:1","alarm":false,"evidence":{"lines":[6,7],"run":"fixture-run","seqs":[4],"source":"os","trace":"~/.raqib/host/sources/fixture-run-5100-7a6e6a35c0.jsonl"},"id":"fixture-run:5","kind":"source-finding","knocked":{"status":"noted on a benign tree, not knocked (c:/windows/*)"},"n":5,"rev":1,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"noted","subject":{"image":"explorer","pid":5100,"tree":"5100:explorer:2026-11-10T07:41:00.000Z"},"summary":"process may reach the network at seq 4 (host -, program ssh, programs [\"ssh.exe\"])","time":"2026-11-03T10:00:00.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

### example: source-finding: pending at exit

From run P.

```json
{"about":"source-finding:1","alarm":true,"evidence":{"lines":[1],"run":"pending-run","seqs":[1],"source":"hooks","trace":"~/.raqib/traces/proj-HASH/raqib.log.jsonl"},"id":"pending-run:4","kind":"source-finding","knocked":{"status":"pending at exit: pending for good is silence (ADR-0005 B-1): an alarm of the tree, exit 1"},"n":4,"rev":1,"rule":{"attack":["T1562"],"class":"SILENCE","id":"SILENCE-OPEN","kind":"demand"},"schema":"raqib-event/1","severity":"high","state":"pending at exit","subject":{"image":"claude","pid":95,"tree":"95:claude:-"},"summary":"session started but its trace ends at session_start seq 1 without session_end or stop","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"test","run":"pending-run","version":"0.1.0"}}
```

### example: source-finding: not settled

From run N.

```json
{"about":"source-finding:1","alarm":true,"evidence":{"lines":[8,9],"run":"fixture-run","seqs":[5],"source":"os","trace":"~/.raqib/host/sources/fixture-run-5888-04cd10d3a5.jsonl"},"id":"fixture-run:4","kind":"source-finding","knocked":{"status":"not settled (RuntimeError: cannot decide (test))"},"n":4,"rev":1,"rule":{"attack":["T1105","T1048"],"class":"NET","fp_budget":0.25,"id":"NET-TOOL","kind":"signature"},"schema":"raqib-event/1","severity":"medium","state":"not settled","subject":{"image":"powershell","pid":5888,"tree":"5888:powershell:2026-11-10T07:50:00.000Z"},"summary":"process may reach the network at seq 5 (host -, program bitsadmin, programs [\"bitsadmin.exe\"])","time":"2026-11-03T10:00:10.000Z","watch":{"host":"host.example","mode":"host","platform":"fixture","run":"fixture-run","version":"0.1.0"}}
```

## Not here

The watch writing events, the heartbeat's beat and a changed thing said again (M10.2); which finding a knock
was for (M10.2: the writer knows both); a kind for the model layer's suspicions and events for the watch's own
errors (M10.2); the forwarders, the local sinks and the stand-in collectors (M10.3); the window's panel
(M10.4). A time that does not parse is replaced by the caller's, unsaid (recorded, F12).
