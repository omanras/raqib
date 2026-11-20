# The catalog's rules and their ATT&CK techniques

Made by `python3 tools/siem_content.py --write` from every rule the report lists (`raqib/report.py`,
`rule_table`: the silence rules, the cross-source rule and the drift anchors of the code, and the rules of
`raqib/rules/catalog`); `--check` holds it in the gate.
Do not edit it by hand. A technique is what a finding is consistent with, never that it happened
(docs/specs/EVENT.md, `rule.attack`); a finding carries its rule's in `threat.technique.id` (siem/README.md).
The same techniques, for the ATT&CK Navigator: `raqib-layer.json` beside this file (never loaded into a
Navigator yet).

| rule | title | class | kind | severity | ATT&CK techniques |
|---|---|---|---|---|---|
| AGENT-DARK-LIVE | An agent footprint has no live tree for three rounds | HOST | anchor | medium | none |
| CROSS-SOURCE | a shell call with no os process of its programs within 10 s, or an os process below the agent's own children that no shell call asked for | CROSS | anchor | high | T1562 |
| DESTRUCT-CMD | Destructive shell command | DESTRUCT | signature | medium | T1485 |
| DRIFT-FILES | Edits spread outside the declared scope | DRIFT | anchor | medium | none |
| EDIT-NO-TEST | Edits under raqib/ or tests/ with no test run before the next stop or session end | DRIFT | demand | medium | none |
| HEAD-UNMOVED | ok edits in a session whose closing git head equals its starting one (never committed) | DRIFT | anchor | medium | none |
| HOST-RHYTHM | A tree talks to one destination and then starts a child, again and again | HOST | anchor | high | T1059, T1071 |
| HOST-UNWATCHED | A discovered agent tree has no source | HOST | anchor | high | none |
| INDEX-UNTOUCHED | ok edits in a session whose closing git index equals its starting one (never staged) | DRIFT | anchor | medium | none |
| LANDED-NO-GATE | A landed commit with no gate run on it or before it | DRIFT | demand | high | none |
| NET-ADMIN-PORT | Connection to a login or administration port of the network | NET | signature | high | T1021 |
| NET-TOOL | Tool call reaches the network | NET | signature | medium | T1105, T1048 |
| NEW-AGENT | An agent tree appears on the host | HOST | anchor | high | T1059 |
| NEW-AGENT-UNKNOWN | An unknown agent tree appears on the host | HOST | anchor | medium | T1059 |
| PERSIST-AUTOSTART | File written in a Windows Startup folder | PERSIST | signature | high | T1547.001 |
| PERSIST-RUN-KEY | Value set under a Run or RunOnce key of the registry | PERSIST | signature | high | T1547.001 |
| SCOPE-CWD-MOVED | The working directory of a session changes | SCOPE | anchor | medium | none |
| SCOPE-CWD-ROOT | Session runs from the file system root or a home directory | SCOPE | anchor | medium | none |
| SCOPE-PATH | File tool touches a path outside the project | SCOPE | signature | medium | T1005 |
| SECRET-OUTPUT | Secret-like string in a tool's output | SECRET | signature | high | T1552 |
| SILENCE-EMPTY | a session that ended with no tool call and no stop, or ended with no start and no tool call | SILENCE | demand | high | T1562 |
| SILENCE-GAP | consecutive lines of a session more than RAQIB_GAP_SECONDS apart | SILENCE | demand | high | T1562 |
| SILENCE-HALF | a seq with more pre than post lines, or the reverse | SILENCE | demand | high | T1562 |
| SILENCE-OPEN | a started session whose last line is not a stop or session_end | SILENCE | demand | high | T1562 |
| SILENCE-ORDER | seq or ts going back: trace truncated, rotated or merged | SILENCE | demand | high | T1562 |

25 rules; 16 of them declare a technique; 10 techniques: T1005, T1021, T1048, T1059, T1071, T1105, T1485, T1547.001, T1552, T1562.
