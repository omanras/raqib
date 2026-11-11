"""M9.2 (ADR-0010 decision 7): the README's text lives in two files now - README.md (what Raqib is, the
install block, a sample final report, where it runs, the commands) and docs/GUIDE.md (everything else,
under the README's own headings, wrapped at 100 characters). Every test that pins a README sentence reads
it through here, from the file it lives in. Both are read as UTF-8 on every system (README.md holds the
project's name in Arabic); the line ends are read the same on Windows and Linux."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
GUIDE_PATH = ROOT / "docs" / "GUIDE.md"
README = README_PATH.read_text(encoding="utf-8")
GUIDE = GUIDE_PATH.read_text(encoding="utf-8")


def flat(text):
    """Whitespace flattened: every run of spaces and line ends is one space, so a re-wrap changes nothing."""
    return " ".join(text.split())


def section(title, text=README):
    """The raw text under the heading `## title` up to the next `## ` heading, as the tests always cut it."""
    return text.split("## %s\n" % title, 1)[1].split("\n## ", 1)[0]


def flat_section(title, text=README):
    return flat(section(title, text))


def units(text):
    """The paragraphs of a text (blank-line separated), each flattened. A README line that held a whole
    paragraph before M9.2 and was longer than the wrap is a paragraph of its own now, so a test that counted
    or indexed the lines of a section counts and indexes these."""
    return [flat(p) for p in re.split(r"\n[ \t]*\n", text) if p.strip()]


def headings(text):
    return re.findall(r"^## (.+)$", text, re.M)
