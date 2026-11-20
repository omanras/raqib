# Raqib's events in a SOC's search engine

Ready content for a SOC (ADR-0017, M16.1): the files a SOC installs to read Raqib's events
(`raqib-event/1`, docs/specs/EVENT.md) in Elasticsearch or OpenSearch, Sigma rules over the events,
and a table of the catalog's rules with their ATT&CK techniques. Every file is made to the spec's
Mapping and to nothing else. Nothing here is part of the package: raqib never imports or reads it,
and Raqib still sends nothing by itself.

## What is here

| file | what it is |
|---|---|
| `elastic/pipeline.json`, `opensearch/pipeline.json` | the ingest pipeline `raqib-event-1`, the same text for both engines |
| `elastic/template.json` | the index template `raqib-events` for Elasticsearch (indices `raqib-events*`) |
| `opensearch/template.json` | the same template for OpenSearch (`flat_object` where Elasticsearch says `flattened`) |
| `elastic/searches/*.json`, `opensearch/searches/*.json` | the searches, the same in both: `finds` (one sentence), `request`, `body` |
| `sigma/rules/*.yml` | Sigma rules over the events' own keys (`logsource: product: raqib`) |
| `sigma/pipeline-ecs.yml` | the pipeline of names: each key of the events to the field the ingest pipeline writes |
| `attack/rules.md`, `attack/raqib-layer.json` | every rule of the catalog with its class, kind, severity and ATT&CK techniques, and a layer for the ATT&CK Navigator |

## What a document holds

Each document is one line of the events file, sent as a document whose `message` is the line. The
pipeline gives ECS as EVENT.md's Mapping names it:

- `time` to `@timestamp`; `id` to `event.id`; `kind` to `event.action`; `severity` to
  `event.severity` (high 4, medium 3, low 2, info 1, hole 3); `alarm` to `event.kind` (`alert` when
  true, else `event`); `summary` to `message`; `rule.id` to `rule.id`; `rule.class` to
  `rule.category`; `rule.attack` to `threat.technique.id`; `subject.pid` and `subject.image` to
  `process.pid` and `process.name`; `watch.host` to `host.name`; `watch.version` to
  `observer.version`, with `observer.product` Raqib.
- Every other key under `raqib`, as the event holds it (`raqib.about`, `raqib.watch.run`,
  `raqib.hole.kind`, `raqib.result.exit` ...). A key added to the events later lands there with no
  change here.
- The whole line in `event.original`; the engine's own time of arrival in `event.ingested`.
- A line that is not a `raqib-event/1` event (a torn write, JSON of another shape, an event whose
  named keys are not of their kind) is kept, never dropped: `event.kind` is `pipeline_error`,
  `error.message` says why, `message` and `event.original` hold the line, `@timestamp` is its
  arrival. Search for them: `event.kind: pipeline_error`.

The template guesses nothing: strings are keywords, a string that looks like a date is not taken
for one, and the parts whose shape differs from kind to kind (`raqib.subject`, `raqib.evidence`,
`raqib.hole`, `raqib.knocked`, `raqib.result`, `raqib.counts`) are kept whole (`flattened`,
`flat_object`) and searched by their dotted names. It sets the pipeline as the indices' default,
so a document sent to `raqib-events-...` goes through it without naming it.

## Install on Elasticsearch

Run from the checkout's root, with the engine at `http://HOST:PORT` (a cluster with security on
takes `https://`, its CA and a user of its own: add `--cacert FILE -u NAME`). The pipeline first,
then the template:

```sh
curl -X PUT "http://HOST:PORT/_ingest/pipeline/raqib-event-1" -H "Content-Type: application/json" --data-binary @siem/elastic/pipeline.json
curl -X PUT "http://HOST:PORT/_index_template/raqib-events" -H "Content-Type: application/json" --data-binary @siem/elastic/template.json
```

In Kibana's Dev Tools the same is `PUT _ingest/pipeline/raqib-event-1` and
`PUT _index_template/raqib-events`, each followed by the file's text.

## Install on OpenSearch

The same two requests with the files of `opensearch/`:

```sh
curl -X PUT "http://HOST:PORT/_ingest/pipeline/raqib-event-1" -H "Content-Type: application/json" --data-binary @siem/opensearch/pipeline.json
curl -X PUT "http://HOST:PORT/_index_template/raqib-events" -H "Content-Type: application/json" --data-binary @siem/opensearch/template.json
```

In OpenSearch Dashboards' Dev Tools: the same two `PUT` lines, each followed by the file's text.

## How the events reach it

Two ways, neither measured yet (see below):

- The engine's own agent on the host, tailing `~/.raqib/host/events.jsonl` as lines (no JSON
  parsing in the agent: the line is the `message`) into an index `raqib-events-...`. It reads the
  file as EVENT.md's "For a reader of the file" says: whole lines only, a cursor at the end of the
  last whole line, dedup by `watch.host` and `id`.
- `raqib forward` to a collector (docs/specs/FORWARD.md, "The shapes"): with `--shape raqib` the
  body is the lines as the file holds them (`application/x-ndjson`), which a collector in front of
  the engine (its HTTP input with a line codec) turns into one document a line with the line as
  `message`; over syslog, the line is the message. The engine's own `_bulk` request is not that
  body: send to a collector, not to the engine's bulk address.

## The searches

Each file of `searches/` is `{"finds": ..., "request": ..., "body": ...}`: paste `request` and
`body` into Dev Tools, or send the body with curl, for example:

```sh
python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))['body']))" siem/elastic/searches/alarm.json | curl -X POST "http://HOST:PORT/raqib-events*/_search" -H "Content-Type: application/json" --data-binary @-
```

- `alarm.json`: every event the watch counts as an alarm.
- `rule.json`: every finding of one rule of the catalog (a search template; the parameter
  `rule_id`).
- `hole.json`: every hole of the capture and every blind spot (`raqib.hole.class` says which).
- `watch-not-0.json`: every watch that ended with a result other than 0.
- `silence.json`: the search for silence (ADR-0017 S-5, FORWARD.md "On the collector's side"): the
  hosts whose latest heartbeat arrived more than two of its beats (`watch.beat`) before the time
  of the check, by the engine's own clock of arrival (`event.ingested`), never by the event's
  `time`. It is a search template: give `now` the time of the check in epoch milliseconds (an
  alerting tool's scheduled time). A host it lists has stopped, or its forwarder has, or its wire is
  cut: each is an alarm. It is the one search no event can carry.

## Sigma

The rules name the events' own keys; the pipeline of names turns them into the fields above
(`alarm: true` into `event.kind: alert`). With sigma-cli and its backends
(`pysigma-backend-elasticsearch`, `pysigma-backend-opensearch`):

```sh
sigma convert -t lucene -p siem/sigma/pipeline-ecs.yml siem/sigma/rules/
sigma convert -t opensearch_lucene -p siem/sigma/pipeline-ecs.yml siem/sigma/rules/
```

The rules: a finding that alarms; a hole of the capture; a finding of persistence (`PERSIST`),
of the network (`NET`), of destruction (`DESTRUCT`), of a secret (`SECRET`); a finding of an agent
nobody named (`NEW-AGENT-UNKNOWN`); a watch that ended INCOMPLETE. Each has an id of its own and a
level; a rule carries ATT&CK tags only where the catalog's rules it matches hold the technique. A
technique is what a finding is consistent with, never that it happened.

## The ATT&CK table

`attack/rules.md` and `attack/raqib-layer.json` are made from `raqib/rules/catalog` by
`python3 tools/siem_content.py --write`; the gate runs `--check`, so a rule added to the catalog
fails the gate until they are made again. Open the layer in the ATT&CK Navigator ("Open Existing
Layer", "Upload from local").

## The trap: an engine that guesses the fields refuses lines

Measured (ADR-0017): the events indexed as they are, the engine guessing the kinds of the fields,
lose 6 of 31 lines in both engines. A tree's `subject.started` is an instant on Windows and
`boot+N` on Linux: the engine takes the first it sees for a date and then refuses the other. The
refused lines are lost in silence unless someone reads the indexer's errors. The template here is
the answer: nothing is guessed, and the parts whose shape differs are kept whole.

## What was measured, and where

- Before the ruling (ADR-0017, the Table's probe on GitHub's Linux machine): Elasticsearch 8.15.3
  and OpenSearch 2.17.1, each in a container on the machine's own port, the 18 examples of
  EVENT.md and a real watch's events file. As they are: 6 of 31 lines refused in both. Through a
  draft of this pipeline and template: none refused in both, the named fields there, the searches
  for an alarm, a rule's finding, a hole, a heartbeat and a watch that ended with a result other
  than 0 counting what the file holds, the hosts' latest heartbeat by the engine's clock one
  aggregation. Three draft Sigma rules converted by sigma-cli to both engines' query strings ran
  and counted what the file holds. OpenSearch 2.17 refuses the `copy_from` of the `set`
  processor, which is why the pipeline copies the line by its value.
- This content, on every push: the rig's job `siem` (.github/workflows/rig.yml) starts both
  engines, installs these files, puts the examples and a short watch's events file through them,
  and `tools/rig/siem_run.py` says X39 (no line refused, none kept as an error), X40 (every named
  field holds the event's value), X41 (each search counts what a count made without the engine
  says) and X42 (each Sigma rule, converted, does the same), MET or MISSED with the numbers.

## What was not measured

Splunk, Microsoft Sentinel and Wazuh (their content is M16.2 and M16.3); an agent of the engine's
own tailing the file (Filebeat, Elastic Agent, Fluent Bit) and a collector in front of the engine
for `raqib forward`; volumes above some tens of lines; an engine with its security on (the rig
runs both with it off, on the machine's own port).
