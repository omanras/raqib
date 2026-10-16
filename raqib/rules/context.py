"""Context for rules that need more than the trace (M1.3), e.g. DRIFT-FILES's scope."""
from __future__ import annotations


def scope_from_handoff(text):
    """Paths in the `Scope:` block of a HANDOFF.md, read the way
    .claude/hooks/scope-guard.sh reads them: what follows `Scope:` on its line
    and on the indented lines right after it, split on commas. The block ends
    at the first line that is blank or not indented. Returns [] if none."""
    entries = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not line.startswith("Scope:"):
            continue
        block = [line[len("Scope:"):]]
        for follow in lines[i + 1:]:
            if not follow[:1].isspace() or not follow.strip():
                break
            block.append(follow)
        for part in block:
            entries += [e.strip() for e in part.split(",") if e.strip()]
    return entries
