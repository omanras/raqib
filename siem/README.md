# Raqib's events in a SOC's search engine

Ready content for a SOC (ADR-0017 and its Amendment A, M16.1): the files a SOC installs to read
Raqib's events (`raqib-event/1`, docs/specs/EVENT.md) in Elasticsearch or OpenSearch, Sigma rules
over the events, and a table of the rules with their ATT&CK techniques. Every file is made to the
spec's Mapping and to nothing else. Nothing here is part of the package: raqib never imports or
reads it, and Raqib still sends nothing by itself.

## What is here

| file | what it is |
|---|---|
| `elastic/pipeline.json`, `opensearch/pipeline.json` | the ingest pipeline `raqib-event-1`, the same text for both engines |
| `elastic/template.json` | the index template `raqib-events` for Elasticsearch (indices `raqib-events*`, priority 200) |
| `opensearch/template.json` | the same template for OpenSearch (`flat_object` where Elasticsearch says `flattened`) |
| `elastic/searches/*.json`, `opensearch/searches/*.json` | the searches, the same in both: `finds` (one sentence), `request`, `body` |
| `sigma/rules/*.yml` | Sigma rules over the events' own keys (`logsource: product: raqib`) |
| `sigma/pipeline-ecs.yml` | the pipeline of names: each key of the events to the field the ingest pipeline writes |
| `attack/rules.md`, `attack/raqib-layer.json` | every rule the report lists with its class, kind, severity and ATT&CK techniques, and a layer for the ATT&CK Navigator |

## What a document holds

Each document is one line of the events file, sent as a document whose `message` is the line. The
pipeline gives ECS as EVENT.md's Mapping names it:

- `time` to `@timestamp`; `id` to `event.id`; `kind` to `event.action`; `severity` to
  `event.severity` (high 4, medium 3, low 2, info 1, hole 3); `alarm` to `event.kind` (`alert` when
  true, else `event`); `summary` to `message`; `rule.id` to `rule.id`; `rule.class` to
  `rule.category`; `rule.attack` to `threat.technique.id`; `subject.pid` and `subject.image` to
  `process.pid` and `process.name`; `watch.host` to `host.name`; `watch.version` to
  `observer.version`, with `observer.product` Raqib.
- Every other key the spec knows under `raqib`, as the event holds it (`raqib.about`,
  `raqib.watch.run`, `raqib.prev`, `raqib.hole.kind`, `raqib.result.exit` ...).
- A key the spec does not know is not indexed: its name is listed in `raqib.unknown_keys` (at most
  50, sorted) and its value stays only in the whole line. A key added to the spec needs its line in
  the pipeline's lists before it is indexed.
- The whole line in `event.original` (kept, not searchable); the engine's own time of arrival in
  `event.ingested`.
- The pipeline sets `host.name` and removes no other field a shipper set (`host.hostname`,
  `host.ip`, `agent.*`, `log.*` ...), on an event and on an error document alike. It sets no
  document id: a line sent twice is two documents.

The template guesses nothing: strings are keywords (a string over 1024 characters is kept but not
searchable), a string that looks like a date is not taken for one, and the parts whose shape
differs from kind to kind (`raqib.subject`, `raqib.evidence`, `raqib.hole`, `raqib.knocked`,
`raqib.result`, `raqib.counts`) are kept whole (`flattened`, `flat_object`) and searched by their
dotted names; their values are keywords, so a number there compares as text. The template sets
the pipeline as the indices' default.

## Which lines become error documents

A line is kept as an error document - `event.kind` is `pipeline_error`, `error.message` says why,
`message` and `event.original` hold the line, `@timestamp` is its arrival unless a shipper set
one - when it is, by the pipeline's own checks:

- not JSON, or JSON that is not an object of schema `raqib-event/1`;
- of a shape an engine would refuse: deeper than 10 levels, a text longer than 8000 characters,
  more than 200 keys in all, or an empty key;
- missing a base key (`schema`, `id`, `n`, `time`, `kind`, `about`, `rev`, `severity`, `watch`,
  `watch.run`, `watch.host`, `watch.beat`);
- holding a key the spec knows with another kind of value: a top-level key, a key of `watch` or of
  `rule`, `subject.pid` or `subject.image` (`alarm` that is not true or false, `n` that is not a
  whole number from 1 within a long, a number where a text is due ...);
- of a `kind` that is not one of the spec's eight, or with a `time` the engine cannot read as an
  instant.

The pipeline checks what an engine needs and no more: the keys inside the parts kept whole are not
checked, nor the words of a closed list but `kind`. The full check of a line is `raqib events FILE`
on the host (docs/GUIDE.md, Commands).

## Install on Elasticsearch

Install the pipeline and the template before the first line reaches a `raqib-events*` index. An
index made earlier, an index of another name, or one matched by a template of higher priority than
200 keeps the engine's own guesses: that is the trap below. Run from the checkout's root, with the
engine at `http://HOST:PORT` (a cluster with security on takes `https://`, its CA and a user of its
own: add `--cacert FILE -u NAME`):

```sh
curl -X PUT "http://HOST:PORT/_ingest/pipeline/raqib-event-1" -H "Content-Type: application/json" --data-binary @siem/elastic/pipeline.json
curl -X PUT "http://HOST:PORT/_index_template/raqib-events" -H "Content-Type: application/json" --data-binary @siem/elastic/template.json
```

In Kibana's Dev Tools the same is `PUT _ingest/pipeline/raqib-event-1` and
`PUT _index_template/raqib-events`, each followed by the file's text.

## Install on OpenSearch

The same two requests, in the same order, with the files of `opensearch/`:

```sh
curl -X PUT "http://HOST:PORT/_ingest/pipeline/raqib-event-1" -H "Content-Type: application/json" --data-binary @siem/opensearch/pipeline.json
curl -X PUT "http://HOST:PORT/_index_template/raqib-events" -H "Content-Type: application/json" --data-binary @siem/opensearch/template.json
```

In OpenSearch Dashboards' Dev Tools: the same two `PUT` lines, each followed by the file's text.

## How the events reach it

Two ways, neither measured (see below):

- The engine's own shipper on the host, tailing `~/.raqib/host/events.jsonl` as lines (no JSON
  parsing in the shipper: the line is the `message`) into an index `raqib-events-...`. It reads
  whole lines only, from a cursor at the end of the last whole line (EVENT.md, "For a reader of the
  file"). A shipper that names a pipeline of its own skips the index's default pipeline: name
  `raqib-event-1`, or call it from the shipper's own pipeline.
- `raqib forward` to a collector (docs/specs/FORWARD.md, "The shapes"): with `--shape raqib` the
  body is the lines as the file holds them (`application/x-ndjson`), which a collector in front of
  the engine (its HTTP input with a line codec) turns into one document a line with the line as
  `message`; over syslog, the line is the message. The engine's own `_bulk` request is not that
  body: send to a collector, not to the engine's bulk address.

Delivery is at least once (FORWARD.md), and a shipper may send a line again after a restart: a line
sent twice is two documents, and the searches count both. To count once, count the distinct values
of `host.name` and `event.id` together (a `cardinality` of the two, or a `terms` on both); a thing
is `raqib.watch.run` and `raqib.about` together, and its latest saying is its highest `raqib.rev`.

## What the content trusts

The content trusts every key of a line that passes its checks, `watch.host`, `watch.beat` and
`time` among them, and the watched account can write the events file (docs/THREAT_MODEL.md). A
forged line can say any host's name, and a forged line with a long beat keeps its host off the
search for silence for two of that beat after its own arrival, and no longer. Where a line came
from is what the collector holds: the shipper's own fields (`host.hostname`, `host.ip`, `agent.*`),
which the pipeline keeps beside `host.name`.

## The searches

Each file of `searches/` is `{"finds": ..., "request": ..., "body": ...}`: paste `request` and
`body` into Dev Tools, or send the body with curl, for example:

```sh
python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['body']))" siem/elastic/searches/alarm.json | curl -X POST "http://HOST:PORT/raqib-events*/_search" -H "Content-Type: application/json" --data-binary @-
```

- `alarm.json`: every saying with alarm true - each rev, and each copy of a line sent twice. A
  thing's alarm is its latest rev: take the highest `raqib.rev` of each `raqib.watch.run` and
  `raqib.about`.
- `rule.json`: every finding of one rule (a search template; the parameter `rule_id`).
- `hole.json`: every hole of the capture and every blind spot (`raqib.hole.class` says which).
- `watch-not-0.json`: every watch that ended with a result other than 0.
- `silence.json`: the search for silence (ADR-0017 S-5 and SA-1). Every line gives a deadline: its
  arrival by the engine's clock (`event.ingested`) and two of that line's own `watch.beat`. A host
  is listed when the engine's own clock has passed the latest deadline any of its lines gave; the
  nearest deadline comes first, and at most 10000 hosts are judged. No time is given by the
  caller, and the event's `time` is never read. A host that has stopped, whose shipper or
  forwarder has, or whose wire is cut is listed; so is a host whose watch ended in order, while
  its lines are in the index.
- `runs-no-end.json`: the runs, by host and run, that said no watch end and whose latest deadline
  the engine's clock has passed (SA-2): a watch that was killed, or whose end could not be written.
  At most 10000 runs are judged.

`@timestamp` is the event's own `time`, the host's clock, and a first saying carries the entry's
own older time (EVENT.md): a rule or a view that windows on `@timestamp` misses a line that arrives
late. Window on `event.ingested`, the arrival, as the two searches above do.

The two searches of silence fill nothing in: each is a whole search, and a person or a schedule
runs it. Each engine has its own way to run a search on a schedule and alert on what it finds
(Elasticsearch: Kibana's alerting rules or Watcher; OpenSearch: its Alerting plugin's monitors).
None of them was set up or measured here.

## Sigma

The rules name the events' own keys; the pipeline of names turns them into the fields above
(`alarm: true` into `event.kind: alert`). With the versions the rig pins (`sigma-cli` 3.1.0,
`pySigma` 1.5.1, `pysigma-backend-elasticsearch` 2.1.1, `pysigma-backend-opensearch` 2.0.3):

```sh
sigma convert -t lucene -p siem/sigma/pipeline-ecs.yml siem/sigma/rules/
sigma convert -t opensearch_lucene -p siem/sigma/pipeline-ecs.yml siem/sigma/rules/
```

The rules: a finding that alarms; a hole of the capture; a finding of persistence (`PERSIST`), of
the network (`NET`), of destruction (`DESTRUCT`), of a secret (`SECRET`); a finding of an agent
nobody named (`NEW-AGENT-UNKNOWN`); a watch that ended INCOMPLETE; a heartbeat whose `state` is not
WATCHING (the watch says it is blind, or has finished). Each has an id of its own and a level; a
rule carries ATT&CK tags only where the rules it matches hold the technique. A technique is what a
finding is consistent with, never that it happened.

A rule of a SOC's own must not name `alarm: false` or `severity`: the pipeline of names turns every
value of `alarm` into `alert`, and the severities hole and medium are both 3. No rule here names
either.

## The ATT&CK table

`attack/rules.md` and `attack/raqib-layer.json` are made by `python3 tools/siem_content.py --write`
from every rule the report lists (`raqib/report.py`: the silence rules, the cross-source rule and
the drift anchors of the code, and the rules of `raqib/rules/catalog`); the gate runs `--check`, so
a rule added or changed fails the gate until they are made again. The layer was never loaded into
an ATT&CK Navigator.

## The trap: an engine that guesses the fields refuses lines

Measured (ADR-0017): the events indexed as they are, the engine guessing the kinds of the fields,
lose 6 of 31 lines in both engines. A tree's `subject.started` is an instant on Windows and
`boot+N` on Linux: the engine takes the first it sees for a date and then refuses the other. The
refused lines are lost in silence unless someone reads the indexer's errors. The template here is
the answer, if it is there before the first line: nothing is guessed, and the parts whose shape
differs are kept whole.

## What was measured, and where

- Before the ruling (ADR-0017, the Table's probe on GitHub's Linux machine): Elasticsearch 8.15.3
  and OpenSearch 2.17.1, each in a container on the machine's own port. The events as they are: 6
  of 31 lines refused in both. Through a draft of this content: none refused.
- M16.1's first content (the rig's job `siem`, both engines): X39 to X42 met on the 31 lines of
  the examples and a short watch's file.
- The review's measurement (ADR-0017 Amendment A, made-up hosts under .example, both engines): the
  deadline of every line and the engine's own clock in the selector, at once and after waits; the
  runs with no end by host and run; a search inside a part kept whole; twelve odd lines, of which
  some were refused and lost with that content; a shipper's host fields, removed by that content.
- This content, on every push: the rig's job `siem` (.github/workflows/rig.yml) starts both
  engines, installs these files and feeds them the examples, a short watch's file (a beat of 5 s),
  made-up events of each class the rules and searches name with a near miss for each, the made-up
  hosts of the silence measurement, each odd line with the line after it, and documents with a
  shipper's fields. `tools/rig/siem_run.py` says X39 to X42, MET or MISSED, each row with what was
  fed and the versions of the tools. When this page was written that job had not yet run this
  content: its rows are the rig's.

## What was not measured

Splunk, Microsoft Sentinel and Wazuh (their content is M16.2 and M16.3); a shipper of the engine's
own tailing the file (Filebeat, Elastic Agent, Fluent Bit) and a collector in front of the engine
for `raqib forward`; a search of silence run on a schedule by either engine's alerting; the layer
in an ATT&CK Navigator; volumes above some tens of lines and more than a few hosts; an engine with
its security on (the rig runs both with it off, on the machine's own port).
