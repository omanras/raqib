# HANDOFF — no builder task (the next step waits for the commander's word)

Task: none. M10.4 landed: the link's state is read by raqib/link.py and shown by the window's Link screen
(ADR-0011 R to V). Next in the commander's order are the local sinks (the Windows event log, the journal) and
the service. Both write outside ~/.raqib, which the threat model says Raqib never does: that line is the
commander's to move, not the Table's. The Table has asked; meanwhile it works the recorded items that need no
such word.

Scope:
  (nothing)

A builder that reads this: STOP. Commit nothing.
