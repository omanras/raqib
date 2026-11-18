# HANDOFF — no builder task (the service's posture waits for the commander's word)

Task: none. M10.3c landed: the forwarder hands the events to the system's journal (`--to journal:`, Linux) and
to the Windows event log (`--to eventlog:`), by an explicit command only (ADR-0011 W to Z). Next in the
commander's order is the service, with the install that goes with it. Whose rights it runs with - the user's
own, or the system's - decides what the watch sees and who can stop it: that is the commander's to say, and
the Table has asked.

Scope:
  (nothing)

A builder that reads this: STOP. Commit nothing.
