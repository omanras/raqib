# ADR-0001 — Mizan architecture

Status: accepted (2026-10-17). Amendments are appended at the end, never
edited in place.

## 1. Purpose
A command-line gate for Sigma detection rules. Input: a directory of rules
with sidecar fixtures and a directory of benign corpora. Output: per rule,
a status with citations; for the set, green or red. It is meant to run in
CI and in a detection engineer's shell, offline, in under a minute for a
few hundred rules.

## 2. Pipeline
```
rules/*.yml ──load──> Rule ──┐
                             ├──match──> fixtures ──> status per rule ──> report
corpus/*.jsonl ──load──> events ─┘            └──> fp per 10k vs budget
```
Modules (all under `mizan/`, stdlib + PyYAML unless stated):
- `loader.py`   reads a rule file; validates shape; returns `Rule` or a
                list of problems. Never raises on bad input.
- `matcher.py`  evaluates one selection (a Sigma search identifier) against
                one event. Field modifiers live here.
- `condition.py` parses and evaluates the Sigma `condition` string over the
                selection results of one event.
- `fixtures.py` finds and reads sidecar fixtures of a rule.
- `corpus.py`   reads corpus files; picks the files that belong to a rule's
                logsource; counts matches.
- `report.py`   text and JSON rendering of results; exit code.
- `export.py`   optional: Sigma -> target query via pySigma. The only module
                allowed to import `sigma` (pySigma). Imported lazily.
- `cli.py`      argparse entry: `python3 -m mizan <command>`.

## 3. Rule format
A Sigma rule file (YAML, one document) as in the public Sigma specification,
with these requirements:
- required: `title`, `id` (UUID string), `logsource` (with at least one of
  `product`, `category`, `service`), `detection` (with `condition`), `level`
  (informational|low|medium|high|critical).
- required Mizan extension: `x-mizan` mapping with `fp_budget` (number >= 0:
  matches allowed per 10,000 benign events). Optional `x-mizan.corpus`
  (list of corpus file names) to override logsource-based selection.
- Any other Sigma field is kept and ignored.
A file that is not valid YAML, not a mapping, or missing a required field is
status `invalid` with each problem named (field, reason).

## 4. Events
An event is one JSON object per line (JSON Lines). Field names are matched
exactly first; if the rule's field is not present and contains a dot, it is
resolved as a path through nested objects (`a.b.c`). Values that are not
strings are compared as their JSON text, except numbers under the numeric
modifiers (gt, gte, lt, lte) which are compared as numbers.
Limits (A7): a line longer than 1 MiB or a file over 256 MiB is a problem
with the line/file named; the run continues and the rule becomes `unknown`
if the problem is in its own fixtures.

## 5. Matching semantics (Sigma, the subset Mizan supports)
- A selection that is a mapping: all field conditions must hold (AND). A
  field with a list of values: any value may match (OR), unless the `all`
  modifier is present (AND).
- A selection that is a list of strings: keyword search; the event matches
  if any string value anywhere in the event contains the keyword
  (case-insensitive), with wildcards.
- String comparison is case-insensitive. `*` matches any run of characters,
  `?` one character; a backslash escapes `*`, `?` and `\`.
- Modifiers (`field|mod1|mod2`): `contains`, `startswith`, `endswith`,
  `all`, `re` (Python `re.search`, case-sensitive unless combined with
  `i`), `exists` (value true/false), `gt`, `gte`, `lt`, `lte` (numeric),
  `cidr` (IPv4/IPv6 via `ipaddress`), `windash` (also match `/` for `-`).
  A null value (`field: null`) matches when the field is absent or null.
- Any other modifier -> the rule is `unknown` and the unsupported modifier is
  named (A4). Never silently treated as plain equality.
- Condition grammar: identifiers, `and`, `or`, `not`, parentheses,
  `1 of <pattern>`, `all of <pattern>`, `1 of them`, `all of them`,
  where `<pattern>` is an identifier with an optional trailing `*`.
  Aggregations (`| count() ...`) and `near` are `unknown`.
  Precedence: `not` > `and` > `or`.

## 6. Fixtures
Sidecars next to the rule `<name>.yml`:
- `<name>.positive.jsonl`: every line must match the rule.
- `<name>.negative.jsonl`: no line may match.
Each file must have at least one non-empty line (A2). A rule is `pass` when
every positive line matches and no negative line matches; `fail` otherwise,
citing `<file>:<line>` for each wrong answer; `unknown` when any line could
not be judged (malformed JSON, unsupported feature).

## 7. Corpus and budget
Corpus files are `corpus/<product>[-<category>|-<service>].jsonl` with a
first line `{"_mizan": {"logsource": {...}}}` declaring the logsource; the
rest are benign events. A rule is measured on every corpus file whose
declared logsource is compatible with the rule's (every key the rule sets
must be equal in the corpus declaration), or on `x-mizan.corpus` if set.
fp_per_10k = matches * 10000 / events. Over budget -> `over_budget` (red).
No compatible corpus -> `no_corpus` (red, A4). Each corpus match is cited.

## 8. Statuses and exit codes
Per rule: `pass`, `fail`, `invalid`, `unknown`, `over_budget`, `no_corpus`.
`check` is green (exit 0) only when every rule is `pass` and within budget.
Exit codes: 0 green, 1 red, 2 usage error, 3 could not complete (a path
unreadable, a corpus file unparseable) -- 3 is also red.

## 9. CLI
```
python3 -m mizan check  [RULES_DIR] [--corpus DIR] [--json]
python3 -m mizan test   RULE.yml [--json]
python3 -m mizan match  RULE.yml EVENTS.jsonl [--json]
python3 -m mizan corpus [RULES_DIR] [--corpus DIR] [--json]
python3 -m mizan export RULE.yml --target splunk|elastic|... [--json]
```
Defaults: RULES_DIR `rules/`, corpus `corpus/` of the current directory.
Text output lists one line per rule: `<status> <id> <title>` then indented
citations. JSON output is `{"version": 1, "rules": [...], "green": bool}`.
