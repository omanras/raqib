"""M2.1: the review page (ADR-0001 section 9), parsed with html.parser."""

import io
import re
from html.parser import HTMLParser
from pathlib import Path

from qayd import cli

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"
RULES = ROOT / "tests" / "fixtures" / "rules"
SECTIONS = ["period", "board", "income-expense", "spending", "allocation", "findings", "decisions", "details"]


class Page(HTMLParser):
    """Collects tags, attributes, section ids in order, style text, text."""

    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = []
        self.sections = []
        self.style = []
        self.text = []
        self._in_style = False
        self.svgs = 0
        self.svg_viewbox = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, k, v) for k, v in attrs)
        d = dict(attrs)
        if tag == "section" and "id" in d:
            self.sections.append(d["id"])
        if tag == "style":
            self._in_style = True
        if tag == "svg":
            self.svgs += 1
            if "viewbox" in d:
                self.svg_viewbox += 1

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        (self.style if self._in_style else self.text).append(data)


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


def review(period, dir_=EXAMPLES, *extra):
    code, out, err = run("review", "--dir", str(dir_), "--period", period, "-o", "-", *extra)
    assert code == 0 and err == "", err
    page = Page()
    page.feed(out)
    return out, page


# ---------------------------------------------------------------- the command


def test_review_writes_a_file_and_exit_codes(tmp_path):
    target = tmp_path / "q3.html"
    code, out, err = run("review", "--dir", str(EXAMPLES), "--period", "2026-Q3", "-o", str(target))
    assert code == 0 and err == ""
    assert out == "wrote %s (review of 2026-Q3 as of 2026-09-30)\n" % target
    html = target.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>") and html.endswith("</html>\n")
    stdout_html = run("review", "--dir", str(EXAMPLES), "--period", "2026-Q3", "-o", "-")[1]
    assert stdout_html == html
    assert run("review", "--dir", str(EXAMPLES), "-o", "-")[0] == 2                        # no period
    assert run("review", "--dir", str(EXAMPLES), "--period", "2026-13", "-o", "-")[0] == 2   # bad period
    assert run("review", "--dir", str(EXAMPLES), "--period", "2026-Q3")[0] == 2            # no output
    assert run("review", "--dir", str(RULES / "broken_policies"), "--period", "2026-Q3", "-o", "-")[0] == 3
    assert run("review", "--dir", str(RULES / "missing_ledger"), "--period", "2026-Q3", "-o", "-")[0] == 3
    code, out, err = run("review", "--dir", str(EXAMPLES), "--period", "2026-Q3", "-o", str(tmp_path / "no" / "dir" / "x.html"))
    assert code == 3 and "cannot write" in err


def test_review_accepts_month_and_year_periods():
    html, page = review("2026-07")
    assert "<title>Qayd review 2026-07</title>" in html and page.sections == SECTIONS
    html, page = review("2026")
    assert "<title>Qayd review 2026</title>" in html and page.sections == SECTIONS
    assert html.count("<th>2026-0") >= 9                             # one board column per month


def test_review_as_of_cuts_a_period_still_running():
    html, page = review("2026-Q3", EXAMPLES, "--as-of", "2026-08-15")
    assert "<dt>as of</dt><dd>2026-08-15</dd>" in html
    assert "<th>2026-08 (to 2026-08-15)</th>" in html and "<th>2026-09" not in html


# ----------------------------------------------------------------- the page


def test_no_script_no_external_resource_no_handlers():
    html, page = review("2026-Q3")
    assert "script" not in page.tags
    assert "link" not in page.tags and "img" not in page.tags and "iframe" not in page.tags
    for tag, k, v in page.attrs:
        assert not k.lower().startswith("on"), (tag, k)
        assert k not in ("src", "href"), (tag, k, v)
    assert "http://" not in html and "https://" not in html and "url(" not in html
    assert "@import" not in html


def test_eight_sections_in_order():
    html, page = review("2026-Q3")
    assert page.sections == SECTIONS


def test_every_colour_is_a_token_on_root_and_dark_mode_exists():
    html, page = review("2026-Q3")
    style = "".join(page.style)
    assert "prefers-color-scheme: dark" in style
    root_blocks = re.findall(r":root[^{]*\{[^}]*\}", style)
    assert len(root_blocks) == 3                                     # light, dark media, data-theme
    rest = style
    for block in root_blocks:
        rest = rest.replace(block, "")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", rest), "a colour literal outside :root"
    assert not re.search(r"\b(rgb|hsl)a?\(", rest)
    body = html.split("</style>", 1)[1]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", body), "a colour literal in the body"
    assert "var(--income)" in body and "var(--expense)" in body and "var(--bar)" in body


def test_svg_is_drawn_with_viewbox_currentcolor_and_real_ticks():
    html, page = review("2026-Q3")
    assert page.svgs == 3 and page.svg_viewbox == 3
    body = html.split("</style>", 1)[1]
    assert 'fill="currentColor"' in body
    assert 'stroke="currentColor"' in body
    assert "<script" not in body
    # spending axis ticks are real values from a 1-2-5 step
    spending = body.split('id="spending"', 1)[1].split("</section>", 1)[0]
    ticks = re.findall(r'text-anchor="middle" fill="currentColor">([0-9]+)</text>', spending)
    assert ticks == ["0", "200", "400", "600", "800", "1000"]
    allocation = body.split('id="allocation"', 1)[1].split("</section>", 1)[0]
    ticks = re.findall(r'text-anchor="middle" fill="currentColor">([0-9]+%)</text>', allocation)
    assert ticks == ["0%", "25%", "50%", "75%", "100%"]
    assert allocation.count('stroke="var(--band)"') == 2             # the equities band: two lines
    assert "band 2%..30%" in allocation


def test_amounts_are_decimal_text():
    html, page = review("2026-Q3")
    text = " ".join(page.text)
    assert "158.492 OMR" in text                                      # July discretionary, exact
    assert "10900 OMR" in text and "1947.2064 OMR" in text
    assert "0.3854 OMR" in text                                       # the USD custody fee, converted
    assert "e+" not in text.lower().replace("be+", "")                # never scientific notation


def test_planted_july_breach_is_visible_in_the_q3_page():
    html, page = review("2026-Q3")
    board = html.split('id="board"', 1)[1].split("</section>", 1)[0]
    assert "<th>2026-07</th>\n<th>2026-08</th>\n<th>2026-09</th>" in board
    wlt01 = board.split("<strong>WLT-01</strong>", 1)[1].split("</tr>", 1)[0]
    assert wlt01.count('class="v v-breach"') == 1 and wlt01.count('class="v v-hold"') == 2
    assert "158.492 OMR vs 120 OMR (10% of income)" in wlt01
    findings = html.split('id="findings"', 1)[1].split("</section>", 1)[0]
    assert "BREACH" in findings and "WLT-01" in findings and "2026-07" in findings
    assert "ledger.csv:248" in findings
    assert "DECISION-DUE" in findings and "D-2026-06-01" in findings
    # the closed kill is noted on the board
    wlt05 = board.split("<strong>WLT-05</strong>", 1)[1].split("</tr>", 1)[0]
    assert "closed by D-2025-12-05" in wlt05


def test_header_details_and_decisions_sections():
    html, page = review("2026-Q3")
    assert "<dt>base currency</dt><dd>OMR</dd>" in html
    assert "ledger.csv (271 rows)" in html and "rates.csv (24 rows)" in html
    details = html.split('id="details"', 1)[1]
    assert "<h3>ledger rows (" in details and "<h3>holdings rows (" in details and "<h3>rate rows (" in details
    assert "ledger.csv:248" in details and "holdings.csv:72" in details
    decisions = html.split('id="decisions"', 1)[1].split("</section>", 1)[0]
    assert '<td class="f-red">due</td><td>D-2026-06-01</td>' in decisions
    assert "closes WLT-05" in decisions


def test_html_escaping_of_notes():
    html, page = review("2026-09", RULES / "household")
    assert "&lt;" not in html or "<script" not in html
    # a household note with markup is escaped
    code, out, err = run("review", "--dir", str(RULES / "invalid_rows"), "--period", "2026-09", "-o", "-")
    assert code == 0 and "<script" not in out
    assert "BAD-AMOUNT" in out and "DUP-ROW" in out
    assert "amount &#x27;abc&#x27; is not decimal text" in out


def test_unknown_and_stale_render_without_bars():
    html, page = review("2026-09", RULES / "stale")
    allocation = html.split('id="allocation"', 1)[1].split("</section>", 1)[0]
    assert allocation.count(">stale") >= 1
    board = html.split('id="board"', 1)[1].split("</section>", 1)[0]
    assert 'class="v v-stale"' in board
    html, page = review("2026-09", RULES / "empty_period")
    assert "No finding" not in html and "EMPTY-PERIOD" in html
    html, page = review("2026-09", RULES / "green")
    assert "No finding: every policy held" in html and "No decision recorded." in html
