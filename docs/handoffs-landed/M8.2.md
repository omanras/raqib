# HANDOFF — M8.2  (a rule made from a form, and Remove: ADR-0009 decisions 4-5)

Task: a person adds a rule from the window by answering a form; the package writes the YAML and the fixtures, the
loader and the fixture runner judge them as any rule (A6), and a user rule can be removed. The terminal does the same.

Scope:
  raqib/ruleform.py (new, no Tk), raqib/overlay.py, raqib/cli.py, raqib/app.py (the form, Remove), tests/, README.md, docs/review/

Exit criteria:
- E1 raqib/ruleform.py, pure: the answers (id, title, what to watch for: program | path | host | tool, the names or places, severity, an example that must fire, one that must not) give the rule's YAML text and its positive and negative fixture files, or a refusal that names the field and says why in a person's words. Kind signature; the evasions each form always has are written into the YAML (ADR-0002); the description says which lines the rule reads (which sources and tools). Names and places pass the capture's own name rules; nothing a person typed is written unchecked into a path.
- E2 The examples are judged by the engine, not by the form: the firing example must fire and the quiet one must not, through overlay's validate_rule and the same copy path as --add (ADR-0008 A-1's checks, class HOST refused, an id already taken refused); nothing is written when anything is refused.
- E3 Before Add the form shows the YAML it will write (read-only) and "on your records": the rule run over the traces and host source files already under ~/.raqib, read-only and bounded (the newest files, a line cap, both said): "would have fired on K of M lines in F files", with up to three cited lines; never a gate; no records is said, not hidden.
- E4 Remove: a user rule's directory under ~/.raqib/rules.d is removed after one confirmation in the window, its overlay lines dropped and said; a package rule is refused ("switch it off instead"); a running watch keeps the rules it started with, said. Nothing outside ~/.raqib/rules.d and rules.yaml is touched (A4), by realpath.
- E5 The window: "New rule" is the Rules screen's primary action (Add rule file... stays, secondary). The form is a screen in the M8.1 look: the four choices in words, the fields, the two examples prefilled from the first name, Test (E1-E3 without writing), Add enabled only after a passing Test of the same answers, each refusal beside its field; keyboard throughout; fits 900x600 measured on windows-latest; every key sequence from KEYS; no thread outlives a Tk test (conftest).
- E6 The terminal: `raqib rules --new ID --when program|path|host|tool --values A,B --severity S --fires X --quiet Y [--title T] [--dry-run]` and `--remove ID`, the same logic and the same words; exit 2 with the reason when refused.
- E7 Tests: per form the generated rule loads, its fixtures pass, the positive fires and the negative does not; each refusal; A-1's path checks on generated files; the dry run's counts on fixture traces; remove (user, package, running watch); the Tk test of the form (fill, Test, Add, the row appears with origin user, Remove); the AST and A4 guards. Gate green, CI six green. README's "Choose the rules" gains the form in a person's words.
Not in scope: editing a package rule, demand or anchor rules from the form, a rule of class HOST, sharing rules, the web page.
Commit: `landed: M8.2 a rule from a form` or `STOP: M8.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
