# M-REV - questions for the commander

These are returned, not answered locally (CLAUDE.md rule 6). The findings
they come from are in `2026-10-17-M-REV.md`.

- **Q-1 (F2) How should "answered by another model" be decided?**
  - Today: `raqib/suspect/core.py:204` compares `response.model` with the
    requested model id as exact strings.
  - The Claude API reference used in this session gives another signal for a
    server-side fallback: a `fallback_message` entry in
    `response.usage.iterations`. The top-level `model` names the model that
    produced the message.
  - Options:
    - keep the exact comparison (it over-reports);
    - compare model-id prefixes;
    - read `usage.iterations` in `backends.py`.
  - Each changes what `answered_by` means, so the choice is yours.
- **Q-2 (R3) Which field does ADR-0001 B-2 call "the field"?**
  - B-2 says "absence of the field means 'not scanned'".
  - If it means `output_meta.scan`: capture always writes it on a post, so B-2
    holds.
  - If it means `secret_kinds`: capture also leaves that out when a partial
    scan found nothing. "Not scanned" then means "not fully scanned".
  - E5 asks for the amendment verbatim, so the text is not changed here.
