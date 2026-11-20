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
