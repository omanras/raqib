# HANDOFF — M9.2  (the README's top is one screen: ADR-0010 decision 7)

Task: a stranger reads the first screen of README.md and knows what Raqib is, whether it runs on their machine, how to
start it and what an alarm looks like. The ruling-by-ruling detail moves under docs/, and no sentence or test is lost.

Scope:
  README.md, docs/GUIDE.md (new), tests/ (only what reads README.md: where it reads from, and the new tests), docs/review/

Exit criteria:
- E1 README.md is at most 120 lines, no line longer than 120 characters, in this order: the name and what it is (three lines); "Install and watch" (the block as M9.1 left it); "Watch a project"; "Doctor" - the three first headings stay and the first screen stays within its pinned 25 lines; then: what an alarm looks like (a sample final report); where it runs (Linux, Windows, Python 3.11+, Claude Code; what `raqib watch --host` and the window need); the commands in one short table; "More" with links into docs/GUIDE.md by heading; "Licence" as it is.
- E2 The sample final report in README is the code's own: a test renders the report of a fixture trace through the same function `raqib report` uses and asserts the README's block is that text, so it cannot rot.
- E3 docs/GUIDE.md holds everything else the README said, under the README's own headings, wrapped at 100 characters: every sentence that leaves README.md is in the guide word for word (whitespace aside). A test holds the list of README's headings before this task and asserts each is a heading of README.md or of docs/GUIDE.md.
- E4 Every test that pins a README sentence still pins it, in the file it now lives in, compared with whitespace flattened; none is deleted or weakened, and the commit's record lists each test that changed its file. A phrase that must stay on the first screen (the install block, the three headings, the licence) stays pinned to README.md.
- E5 Nothing else changes: no file under raqib/ is touched (a help text that cites README by section still names a section that exists - checked by a test over cli.py's docstring), no ADR, no rule.
- E6 Gate green, CI six green; the record docs/review/<date>-M9.2-questions.md says per criterion MET or not and returns design questions.
Not in scope: rewriting what the sentences say, new documentation, raqib/, the page, a website.
Commit: `landed: M9.2 the README's top is one screen` or `STOP: M9.2 <reason>`.
Read HANDOFF.md and do only the task it specifies.
