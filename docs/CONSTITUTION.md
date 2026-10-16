# Raqib Constitution (public doctrine)

Raqib watches agents. It does not become one.

## Articles
- **A1 Deterministic first.** Every judgement that can be made by a rule is made
  by a rule. The model layer never overrides a rule; it only adds suspicion.
- **A2 Asymmetry (R-27).** Intelligence may raise suspicion. It may never acquit.
  A model output of "benign" is recorded as *no finding*, not as clearance.
- **A3 Silence is an alarm.** Missing captures, empty windows, hooks that did not
  fire, and logs that stop are findings of the highest class.
- **A4 The watcher never touches the watched.** Raqib reads traces and emits
  findings. It does not message, steer, or patch the agent.
- **A5 Evidence over narrative.** A finding cites the exact trace lines. A finding
  without a citation is not a finding.
- **A6 False-positive economy.** Each rule declares its expected false-positive
  rate on the fixture set. A rule above its budget is disabled, not tuned live.
- **A7 n=1 does not generalise.** One exercise proves one path. Coverage claims
  require the fixture matrix.
- **A8 Tree is ground truth.** What is not in git did not happen. Errors by the
  reviewer are recorded against the tree, never absorbed.
- **A9 No secrets, no private trees.** Nothing from private projects is copied
  into Raqib. The pre-commit secret scan is mandatory.

## Roles
- **Builder** (Claude Code, cloud or local): executes one HANDOFF task.
- **Reviewer** (read-only agent + human reviewer): compares the diff to HANDOFF
  and this constitution; raises findings; never edits.
- **Judge** (structured agent): NEXT / REDO / STOP only. In doubt, STOP.
- **Commander** (the human): the only party that may widen scope or thaw a
  frozen rule.
