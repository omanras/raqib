# The catalog's rules and their ATT&CK techniques

Made by `python3 tools/siem_content.py --write` from `raqib/rules/catalog`; `--check` holds it in the gate.
Do not edit it by hand. A technique is what a finding is consistent with, never that it happened
(docs/specs/EVENT.md, `rule.attack`); a finding carries its rule's in `threat.technique.id` (siem/README.md).
The same techniques, for the ATT&CK Navigator: `raqib-layer.json` beside this file.

| rule | title | class | kind | severity | ATT&CK techniques |
|---|---|---|---|---|---|
| AGENT-DARK-LIVE | An agent footprint has no live tree for three rounds | HOST | anchor | medium | none |
| DESTRUCT-CMD | Destructive shell command | DESTRUCT | signature | medium | T1485 |
| DRIFT-FILES | Edits spread outside the declared scope | DRIFT | anchor | medium | none |
| EDIT-NO-TEST | Edits under raqib/ or tests/ with no test run before the next stop or session end | DRIFT | demand | medium | none |
| HOST-RHYTHM | A tree talks to one destination and then starts a child, again and again | HOST | anchor | high | T1059, T1071 |
| HOST-UNWATCHED | A discovered agent tree has no source | HOST | anchor | high | none |
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

17 rules; 10 of them declare a technique; 9 techniques: T1005, T1021, T1048, T1059, T1071, T1105, T1485, T1547.001, T1552.
