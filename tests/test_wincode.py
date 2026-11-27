"""M12.4c1 (ADR-0013 Amendment K, K-1 to K-7): `raqib service check`, whether the code a service of Windows would run
is the system's alone.

The owners and lists measured on GitHub's Windows machines are read from tests/fixtures/wincode/measured.txt (never
retyped here); each gets the verdict the Table ruled for it (EXPECTED_X64, EXPECTED_ARM64), in both roles. The texts
no machine gave are invented here. The walk and the command run on a made-up Windows (Machine, in place of
wincode.System): no test but one needs Windows, and that one only reads a system file's owner and list (E5).
"""
import ast
import io
import ntpath
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from raqib import cli, service, winservice, wincode  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "wincode" / "measured.txt"
T, R = "taken", "refused"
INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"


def measured():
    """{section: [(path, attributes or None, text, error or None)]} as the fixture file holds them."""
    out, section, path = {}, None, None
    for line in FIXTURE.read_text(encoding="ascii").splitlines():
        if line.startswith("## "):
            section = "x64" if "(x64)" in line else "arm64"
            out[section] = []
        elif line.startswith("#") or not line.strip():
            continue
        elif not line.startswith(" "):
            path = line.split("   (", 1)[0].strip()
        else:
            got = re.match(r"    a (folder|file) \(attributes (0x[0-9a-f]+)\); (\S+)\Z", line)
            if got:
                out[section].append((path, int(got.group(2), 16), got.group(3), None))
            else:
                error = re.match(r"    not opened: error (\d+)\Z", line)
                assert error, line
                out[section].append((path, None, None, int(error.group(1))))
    return out


# The Table's verdicts (M12.4c1-expected): (as the code itself, as a folder above; None: not asked, a file)
EXPECTED_X64 = {
    "C:\\": (R, T),
    "C:\\Program Files": (T, T),
    "C:\\Program Files\\RaqibProbe8": (T, T),
    "C:\\Program Files\\RaqibProbe8\\raqib.exe": (T, None),
    "C:\\Program Files\\RaqibProbe8\\_internal": (T, T),
    "C:\\Program Files\\RaqibProbe8\\_internal\\_bz2.pyd": (T, None),
    "C:\\Program Files\\RaqibProbe8\\_internal\\raqib": (T, T),
    "D:\\": (R, R),
    "C:\\Users": (T, T),
    "C:\\Users\\someone": (R, R),
    "C:\\Windows": (T, T),
    "C:\\Windows\\System32": (T, T),
    "C:\\Windows\\System32\\kernel32.dll": (T, None),
    "C:\\Windows\\System32\\sc.exe": (T, None),
    "C:\\ProgramData": (R, T),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\python.exe": (R, None),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\Lib\\site-packages": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\Lib\\os.py": (R, None),
    "C:\\Users\\someone\\AppData\\Local": (R, R),
    "C:\\Users\\SOMEON~1\\AppData\\Local\\Temp": (R, R),
    "C:\\hostedtoolcache\\windows\\Python": (R, R),
    "D:\\a\\raqib\\raqib\\raqib": (R, T),
    "D:\\a\\raqib\\raqib\\raqib\\cli.py": (T, None),
    "C:\\RaqibProbe8-at-root": (R, R),
    "C:\\ProgramData\\Raqib": (T, T),
}
EXPECTED_ARM64 = {
    "C:\\": (R, T),
    "D:\\": (R, R),   # not opened: error 3 - a name not read is refused in both roles
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\arm64\\python.exe": (R, None),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\arm64": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\arm64\\Lib\\site-packages": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\arm64\\Lib\\os.py": (R, None),
}
# What decides a refusal, in its words: {path: (in the code's words, in the above's words)}
PY = "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64"
DECIDES = {
    "C:\\": (["(A;;LC;;;AU)", "0x4"], []),
    "D:\\": (["owned by NS"], ["owned by NS"]),
    "C:\\Users\\someone": (["(A;OICI;FA;;;LA)"], ["(A;OICI;FA;;;LA)"]),
    "C:\\ProgramData": (["(A;CI;DCLCRPCR;;;BU)", "0x2, 0x4, 0x10, 0x100:"], []),
    PY + "\\python.exe": (["(A;ID;0x1301bf;;;AU)"], []),
    PY: (["(A;ID;0x1301bf;;;AU)"], ["(A;ID;0x1301bf;;;AU)", "0x10000"]),
    PY + "\\Lib\\os.py": (["(A;ID;0x1301bf;;;AU)"], []),
    "C:\\Users\\someone\\AppData\\Local": (["(A;OICIID;FA;;;LA)"], ["(A;OICIID;FA;;;LA)"]),
    "C:\\hostedtoolcache\\windows\\Python": (["(A;ID;0x1301bf;;;AU)"], ["(A;ID;0x1301bf;;;AU)"]),
    "D:\\a\\raqib\\raqib\\raqib": (["(A;CIID;LC;;;BU)"], []),
    "C:\\RaqibProbe8-at-root": (["owned by S-1-5-21-1004336348-1177238915-682003330-1001"],
                                ["owned by S-1-5-21-1004336348-1177238915-682003330-1001"]),
}


def verdict(got):
    return T if got is None else R


class Reader:
    """One name's reading as the fixture holds it: what the real reader returns, or its OSError."""

    def __init__(self, rows):
        self.rows = {ntpath.normcase(p): (a, t, e) for p, a, t, e in rows}

    def read(self, path):
        attributes, text, error = self.rows[ntpath.normcase(path)]
        if error is not None:
            raise OSError(error, "the name was not opened")
        return attributes, text


@pytest.mark.parametrize("section, expected", [("x64", EXPECTED_X64), ("arm64", EXPECTED_ARM64)])
def test_e1_every_measured_owner_and_list_gets_the_tables_verdict_in_both_roles(section, expected):
    rows = measured()[section]
    assert sorted(p for p, _, _, _ in rows) == sorted(expected) and len(rows) == len(expected)   # every row, once
    for path, attributes, text, error in rows:
        code, above = expected[path]
        if error is not None:   # a name not read: refused in both roles, by the walk's one read
            for role in (wincode.ROLE_CODE, wincode.ROLE_ABOVE):
                bad, _ = wincode._Walk(Reader(rows))._read(path, role)
                assert bad[0] == path and bad[1].startswith(role) and "not read (the name was not opened (error 3))" \
                    in bad[1] and wincode.NOT_READ in bad[1], bad
            continue
        got = wincode.as_code(attributes, text)
        assert verdict(got) == code, (path, got)
        if above is None:
            assert not attributes & winservice.ATTRIBUTE_FOLDER and wincode.as_above(attributes, text) is not None
        else:
            assert verdict(wincode.as_above(attributes, text)) == above, (path, wincode.as_above(attributes, text))
        for words, said in zip(DECIDES.get(path, ([], [])) if section == "x64" else ([], []),
                               (got, wincode.as_above(attributes, text))):
            for piece in words:
                assert said and piece in said, (path, piece, said)


def test_e1_the_x64_and_arm64_sections_differ_as_the_table_says():
    rows = measured()
    arm = {p: (a, t) for p, a, t, _ in rows["arm64"]}
    assert arm["C:\\"][1].split("D:", 1)[1].startswith("(") and "D:AI(" in dict(
        (p, t) for p, _, t, _ in rows["x64"])["C:\\"]
    assert len(rows["x64"]) == 27 and len(rows["arm64"]) == 7


def test_e1_the_rights_words_are_the_fixtures_table_and_the_allowed_bits_are_lists_of_what_is_allowed():
    text = FIXTURE.read_text(encoding="ascii")
    table = text.split("# The rights words in these texts", 1)[1]
    words = dict((w, int(n, 16)) for w, n in re.findall(r"\b([A-Z]{2}) (0x[0-9a-f]+)\b", table))
    assert words == wincode.RIGHTS and len(words) == 21
    assert [b for b, _ in wincode.CODE_ALLOWED] == [0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000, 0x80000000, 0x20000000]
    assert [b for b, _ in wincode.ABOVE_ALLOWED] == [b for b, _ in wincode.CODE_ALLOWED] + [0x2, 0x4, 0x10, 0x100]
    assert all(isinstance(w, str) and w for _, w in wincode.ABOVE_ALLOWED)
    assert wincode.SYSTEM_NAMES == ("SY", "S-1-5-18", "BA", "S-1-5-32-544", INSTALLER)
    assert wincode.CREATOR_NAMES == ("CO", "S-1-3-0")
    assert "the system's installer" in wincode.as_code(0x10, "O:LAD:") and INSTALLER in FIXTURE.read_text("ascii")


def test_e1_a_measured_text_is_read_into_its_owner_and_entries_by_position():
    text = dict((p, t) for p, _, t, _ in measured()["x64"])["C:\\ProgramData"]
    owner, entries, why = wincode.read_list(text)
    assert why is None and owner == "SY"
    assert [(e.kind, e.flags, e.rights, e.name) for e in entries] == [
        ("A", ("OI", "CI"), 0x1f01ff, "SY"), ("A", ("OI", "CI"), 0x1f01ff, "BA"),
        ("A", ("OI", "CI", "IO"), 0x10000000, "CO"), ("A", ("OI", "CI"), 0x1200a9, "BU"),
        ("A", ("CI",), 0x2 | 0x4 | 0x10 | 0x100, "BU")]
    assert entries[-1].text == "(A;CI;DCLCRPCR;;;BU)"   # CR a right in the third field; CI a flag in the second
    owner, entries, why = wincode.read_list("O:%sD:PAI(A;OICIIOID;SDGXGWGR;;;AU)" % INSTALLER)
    assert owner == INSTALLER and entries[0].rights == 0x10000 | 0x20000000 | 0x40000000 | 0x80000000
    assert wincode.read_list("O:BAD:") == ("BA", [], None)


CREATOR_LIKE = "O:BAD:(A;;GA;;;CO)"
SECOND = [   # (text, attributes, as the code itself, as a folder above, a piece of the code's words or None)
    ("O:BA", 0x10, R, R, "no list (no D: part)"),
    ("O:BAD:NO_ACCESS_CONTROL", 0x10, R, R, "a null list"),
    ("O:BAD:PNO_ACCESS_CONTROL", 0x10, R, R, "a null list"),
    ("O:BAD:(XA;;FA;;;BU;(Member_of {SID(BA)}))", 0x10, R, R, "a kind not judged (XA)"),
    ("O:BAD:(OA;;FA;;;BU)", 0x10, R, R, "a kind not judged (OA)"),
    ("O:BAD:(AU;SA;FA;;;BU)", 0x10, R, R, "a kind not judged (AU)"),
    ("O:BAD:(A;;FA;{00000000-0000-0000-0000-000000000001};;BU)", 0x10, R, R, "object or inherited-object"),
    ("O:BAD:(A;;FA;;{00000000-0000-0000-0000-000000000001};BU)", 0x10, R, R, "object or inherited-object"),
    ("O:BAD:(A;;FA;;;BU;)", 0x10, R, R, "of 7 fields, not six"),
    ("O:BAD:(A;;FA;;BU)", 0x10, R, R, "of 5 fields, not six"),
    ("O:BAD:(A;;ZZ;;;BU)", 0x10, R, R, "a word this Raqib does not know"),
    ("O:BAD:(D;;ZZ;;;BU)(A;;FA;;;SY)", 0x10, R, R, "a word this Raqib does not know"),
    ("O:BAD:(A;;;;;BU)", 0x10, R, R, "rights are not read"),
    ("O:BAD:(A;XX;FA;;;BU)", 0x10, R, R, "flags are not known (XX)"),
    ("O:BAD:(A;;FA;;;Everyone)", 0x10, R, R, "name is not read"),
    ("O:BAD:(A;;FA;;;SY", 0x10, R, R, "not closed"),
    ("O:BAD:(A;;FA;;;SY)S:(AU;SA;FA;;;WD)", 0x10, R, R, "where an entry should begin"),
    ("O:BAG:BAD:(A;;FA;;;SY)", 0x10, R, R, "where the list (D:) should be"),
    ("O:BAD:QQ(A;;FA;;;SY)", 0x10, R, R, "the list's flags are not known (QQ)"),
    ("D:(A;;FA;;;SY)", 0x10, R, R, "no owner"),
    (CREATOR_LIKE, 0x10, R, R, "the creator's entry (A;;GA;;;CO) is not inherit-only"),
    ("O:BAD:(A;;GA;;;S-1-3-0)", 0x10, R, R, "the creator's entry"),
    ("O:BAD:(A;OICIIO;GA;;;CO)", 0x10, T, T, None),
    ("O:BAD:(A;OICIIO;GA;;;S-1-3-0)", 0x10, T, T, None),
    ("O:BAD:(A;OICIIO;GW;;;BU)", 0x10, R, T, "0x40000000"),
    ("O:BAD:(A;;GW;;;BU)", 0x10, R, R, "0x40000000"),
    ("O:BAD:(D;;FA;;;BU)(A;;FA;;;SY)", 0x10, T, T, None),
    ("O:BAD:(D;;FA;;;WD)(A;;FA;;;BU)", 0x10, R, R, "(A;;FA;;;BU)"),
    ("O:BAD:", 0x10, T, T, None),
    ("O:BAD:P", 0x10, T, T, None),
    ("O:S-1-5-18D:(A;;FA;;;S-1-5-32-544)", 0x10, T, T, None),
    ("O:S-1-5-32-544D:(A;;FA;;;S-1-5-18)", 0x10, T, T, None),
    ("O:LAD:(A;;FA;;;SY)", 0x10, R, R, "owned by LA"),
    ("O:S-1-5-21-1-2-3-500D:(A;;FA;;;SY)", 0x10, R, R, "owned by S-1-5-21-1-2-3-500"),
    ("O:BAD:(A;;FA;;;SY)", 0x410, R, R, "a reparse point (attributes 0x410)"),
    ("O:BAD:(A;;FA;;;BU)", 0x420, R, R, "a reparse point"),
    ("not a text", 0x400, R, R, "a reparse point"),
    ("O:BAD:(A;;0x1200a9;;;BU)(A;;0x100;;;BU)", 0x10, R, T, "0x100:"),
    ("O:BAD:(A;;0x40;;;BU)", 0x10, R, R, "0x40:"),
    ("O:BAD:(A;;0x10000;;;BU)", 0x10, R, R, "0x10000:"),
    ("O:BAD:(A;;0x40000;;;BU)", 0x10, R, R, "0x40000:"),
    ("O:BAD:(A;;0x80000;;;BU)", 0x10, R, R, "0x80000:"),
    ("O:BAD:(A;;0x2000000;;;BU)", 0x10, R, R, "0x2000000:"),
    ("O:BAD:(A;;0x1200a9;;;BU)", 0x10, T, T, None),
    (None, 0x10, R, R, "no text"),
]


@pytest.mark.parametrize("text, attributes, code, above, piece", SECOND)
def test_e1_texts_no_machine_gave_get_their_verdict_in_both_roles(text, attributes, code, above, piece):
    got_code, got_above = wincode.as_code(attributes, text), wincode.as_above(attributes, text)
    assert (verdict(got_code), verdict(got_above)) == (code, above), (got_code, got_above)
    if got_code is not None:
        assert got_code.startswith(wincode.ROLE_CODE + ": ") and (piece is None or piece in got_code), got_code
    if got_above is not None:
        assert got_above.startswith(wincode.ROLE_ABOVE + ": "), got_above
    if text is not None and attributes == 0x10:   # a file asked as a folder above: refused, whatever its list
        got = wincode.as_above(0x20, text)
        assert got == wincode.ROLE_ABOVE + ": not a folder (attributes 0x20)"
        assert wincode.as_code(0x20, text) == got_code


def test_e1_attributes_not_read_are_refused():
    for attributes in (None, True, -1, "0x10"):
        assert wincode.as_code(attributes, "O:BAD:").startswith(wincode.ROLE_CODE + ": its attributes are not read")


# --- E2 (K-4, K-5, K-7): the walk, on a made-up Windows ----------------------------------------------------------
TOP = "C:\\Program Files\\RaqibProbe8"
PROGRAM = TOP + "\\raqib.exe"
MODULES = TOP + "\\_internal"
TREE_LISTS = {TOP: ["raqib.exe", "_internal"], MODULES: ["_bz2.pyd", "raqib"], MODULES + "\\raqib": []}
GOOD_FILE = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"


class Machine:
    """A made-up Windows: names read from the measured x64 rows (or as a test gives them), listings as given."""

    def __init__(self, names=None, lists=None, platform="win32", packed=True, program=PROGRAM, modules=MODULES):
        base = {p: (a, t) for p, a, t, _ in measured()["x64"]}
        self.names = {ntpath.normcase(p): v for p, v in dict(base, **(names or {})).items()}
        self.lists = {ntpath.normcase(p): v for p, v in dict(TREE_LISTS, **(lists or {})).items()}
        self._platform, self._packed, self._program, self._modules = platform, packed, program, modules
        self.reads, self.listed = [], []

    def platform(self):
        return self._platform

    def packed(self):
        return self._packed

    def program(self):
        return self._program

    def modules(self):
        return self._modules

    def read(self, path):
        self.reads.append(path)
        got = self.names.get(ntpath.normcase(path))
        if got is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        if isinstance(got, BaseException):
            raise got
        return got

    def listdir(self, path):
        self.listed.append(path)
        got = self.lists.get(ntpath.normcase(path))
        if isinstance(got, BaseException):
            raise got
        if got is None:
            raise AssertionError("listed a name the test did not give as a folder: %s" % path)
        return list(got)


MEASURED_READS = ["C:\\", "C:\\Program Files", TOP, PROGRAM, MODULES, MODULES + "\\_bz2.pyd", MODULES + "\\raqib"]


def test_e2_the_measured_packed_tree_is_taken_top_first_each_name_read_once_and_counted():
    m = Machine()
    assert wincode.check(m) == (None, {"folders": 3, "files": 2, "above": 2})
    assert m.reads == MEASURED_READS and m.listed == [TOP, MODULES, MODULES + "\\raqib"]
    assert wincode.checked_words({"folders": 3, "files": 2, "above": 2}).startswith(
        "checked 7 names, each the system's alone")


def test_e2_a_folder_met_twice_is_walked_once_names_compared_without_case():
    for modules in ("c:\\PROGRAM FILES\\raqibprobe8\\_INTERNAL", MODULES, TOP):
        m = Machine(modules=modules)
        assert wincode.check(m) == (None, {"folders": 3, "files": 2, "above": 2}) and m.reads == MEASURED_READS


BAD_OWNER = "O:LAD:(A;;FA;;;SY)"
BAD_BITS = "O:BAD:(A;;FA;;;SY)(A;;0x40;;;BU)"   # delete a child: refused in both roles
NAMED = {"above": "C:\\Program Files", "root": TOP, "below": MODULES + "\\raqib"}


@pytest.mark.parametrize("place", ["above", "root", "below"])
@pytest.mark.parametrize("rule, given, piece", [
    ("owner", (0x10, BAD_OWNER), "owned by LA, not the system (SY), the administrators (BA) or the system's"),
    ("reparse", (0x410, GOOD_FILE), "a reparse point (attributes 0x410)"),
    ("null list", (0x10, "O:BAD:NO_ACCESS_CONTROL"), "a null list (NO_ACCESS_CONTROL)"),
    ("a text not read", (0x10, "O:BAD:(XA;;FA;;;BU;(x))"), "not read whole: an entry of a kind not judged (XA)"),
    ("the bits", (0x10, BAD_BITS), "the entry (A;;0x40;;;BU) gives BU, a name outside the system's, 0x40: not"),
    ("not read", OSError(5, "Access is denied"), "not read (Access is denied (error 5)); " + wincode.NOT_READ),
])
def test_e2_one_refusal_for_each_rule_at_the_root_below_it_and_above_it(place, rule, given, piece):
    name = NAMED[place]
    m = Machine(names={name: given})
    bad, counts = wincode.check(m)
    role = wincode.ROLE_ABOVE if place == "above" else wincode.ROLE_CODE
    assert bad[0] == name and bad[1].startswith(role + ": ") and piece in bad[1], bad
    assert m.reads == MEASURED_READS[:MEASURED_READS.index(name) + 1]   # nothing read after the refusal
    assert counts == {"above": {"above": 1, "root": 2, "below": 2}[place], "folders": {"below": 2}.get(place, 0),
                      "files": {"below": 2}.get(place, 0)}


@pytest.mark.parametrize("place", ["above", "root", "below"])
def test_e2_a_folder_that_is_not_a_folder_as_read(place):
    name = NAMED[place]
    bad, _ = wincode.check(Machine(names={name: (0x20, GOOD_FILE)}, lists={name: []}))
    if place == "above":
        assert bad == (name, wincode.ROLE_ABOVE + ": not a folder (attributes 0x20)")
    elif place == "root":
        assert bad == (name, wincode.ROLE_CODE + ": the program's folder is not a folder as read (attributes 0x20)")
    else:   # below the root a name read as a file is a file: its kind comes from the reading, never the listing
        assert bad is None


@pytest.mark.parametrize("name", [TOP, MODULES])
def test_e2_a_folder_not_listed_is_refused_as_not_read(name):
    m = Machine(lists={name: PermissionError(5, "Access is denied")})
    bad, _ = wincode.check(m)
    assert bad == (name, wincode.ROLE_CODE + ": a folder that cannot be listed (Access is denied (error 5)); "
                   + wincode.NOT_READ)


def test_e2_a_name_longer_than_the_system_opens_plainly_is_refused_unread():
    long = "a" * (wincode.PLAIN_MAX - len(MODULES + "\\raqib\\") + 1)
    m = Machine(lists={MODULES + "\\raqib": [long]})
    bad, _ = wincode.check(m)
    assert bad[0].startswith(MODULES + "\\raqib\\aaa") and "260 characters, longer than the system opens plainly" \
        in bad[1] and bad[1].startswith(wincode.ROLE_CODE) and m.reads == MEASURED_READS   # never read
    assert wincode.PLAIN_MAX == 259


@pytest.mark.parametrize("name, why", [
    ("..", "an empty part, . or .."), ("a:b", "a character no name of Windows holds"),
    ("a/b", "a character no name of Windows holds"), ("x\x1by", "a character no name of Windows holds"),
    ("raqib.exe ", "a dot or a space"), ("raqib.", "a dot or a space"), ("NUL", "a device's name"),
    ("com1.txt", "a device's name"), ("", "an empty part"), (7, "no name"),
])
def test_e2_a_listed_name_that_is_not_one_plain_name_is_refused_unread(name, why):
    m = Machine(lists={MODULES + "\\raqib": [name]})
    bad, _ = wincode.check(m)
    assert bad[0] == MODULES + "\\raqib" and why in bad[1] and wincode.NOT_READ in bad[1]
    assert m.reads == MEASURED_READS
    assert bad[1].isprintable() and "\x1b" not in bad[1]


def test_e2_two_names_of_one_folder_that_differ_only_in_case_are_refused():
    m = Machine(lists={MODULES: ["_bz2.pyd", "raqib", "RAQIB"]})
    bad, _ = wincode.check(m)
    assert bad[0] == MODULES + "\\RAQIB" and "differ only in case" in bad[1]


@pytest.mark.parametrize("program", [
    "\\\\server.example\\share\\raqib\\raqib.exe", "\\\\?\\C:\\Program Files\\RaqibProbe8\\raqib.exe",
    "\\\\.\\C:\\raqib.exe", "C:\\Program Files\\..\\RaqibProbe8\\raqib.exe", "C:/Program Files/RaqibProbe8/raqib.exe",
    "Program Files\\RaqibProbe8\\raqib.exe", "C:raqib.exe", "C:\\Program Files\\\\RaqibProbe8\\raqib.exe",
    "C:\\Program Files\\RaqibProbe8.\\raqib.exe", "C:\\Program Files\\CON\\raqib.exe", "",
    "C:\\" + "a" * 300 + "\\raqib.exe", None,
])
def test_e2_the_programs_path_in_any_other_form_is_refused_and_nothing_is_read(program):
    m = Machine(program=program)
    bad, counts = wincode.check(m)
    assert bad[1].startswith("the program's path ") and m.reads == [] and sum(counts.values()) == 0, bad


def test_e2_modules_outside_the_programs_folder_or_not_said_are_refused_and_nothing_is_read():
    for modules, piece in (("C:\\Users\\someone\\AppData\\Local\\Temp\\_MEI40242", "outside the program's folder"),
                           ("C:\\Program Files\\RaqibProbe", "outside the program's folder"),
                           (None, "does not say where its modules are"),
                           ("\\\\server.example\\share\\_internal", "the modules' path")):
        m = Machine(modules=modules)
        bad, _ = wincode.check(m)
        assert piece in bad[1] and m.reads == [], bad
    assert "unpacks into a temporary folder at each start" in wincode.check(Machine(
        modules="C:\\Windows\\Temp\\_MEI1"))[0][1]


def test_e2_a_plain_interpreter_and_not_windows_are_each_their_own_refusal_and_nothing_is_read():
    m = Machine(packed=False, program=PY + "\\python.exe")
    assert wincode.check(m) == ((PY + "\\python.exe", wincode.NOT_PACKED), {"folders": 0, "files": 0, "above": 0})
    assert "not yet checked (ADR-0013 K-5)" in wincode.NOT_PACKED and m.reads == []
    m = Machine(platform="linux")
    assert wincode.check(m)[0] == (PROGRAM, "Windows only (it reads the owners and lists of Windows); this is linux")
    assert m.reads == []


def test_e2_a_walk_past_walk_max_names_is_refused(monkeypatch):
    assert wincode.WALK_MAX == service.WALK_MAX == 200000   # the Linux number
    monkeypatch.setattr(wincode, "WALK_MAX", 5)
    bad, counts = wincode.check(Machine())
    assert bad == (MODULES + "\\_bz2.pyd", "more than 5 names to walk (WALK_MAX): a walk that is not whole is not a"
                                           " pass") and sum(counts.values()) == 5


def test_e2_the_order_the_highest_refusal_is_said_first():
    two = Machine(names={"C:\\": (0x16, BAD_OWNER), "C:\\Program Files": (0x11, BAD_OWNER), TOP: (0x10, BAD_OWNER)})
    assert wincode.check(two)[0][0] == "C:\\" and two.reads == ["C:\\"]
    m = Machine(names={"C:\\Program Files": (0x11, BAD_BITS), MODULES: (0x10, BAD_OWNER)})
    assert wincode.check(m)[0][0] == "C:\\Program Files"
    m = Machine(names={PROGRAM: (0x20, BAD_OWNER), MODULES + "\\raqib": (0x10, BAD_OWNER)})
    assert wincode.check(m)[0][0] == PROGRAM


def test_e2_the_kind_comes_from_the_reading_never_the_listing():
    # a name the listing gives that reads as a reparse point is refused as itself; one that reads as a file is not
    # listed, whatever its name
    m = Machine(names={MODULES + "\\raqib": (0x20, GOOD_FILE)})
    assert wincode.check(m) == (None, {"folders": 2, "files": 3, "above": 2})
    assert MODULES + "\\raqib" not in m.listed


def test_e2_the_real_system_object_reads_by_winservices_one_reader(monkeypatch):
    got = []

    class Reader:
        def read_place(self, path):
            got.append(path)
            return 0x10, "O:BAD:"
    monkeypatch.setattr(winservice, "System", Reader)
    s = wincode.System()
    assert s.read("C:\\x") == (0x10, "O:BAD:") and s.read("C:\\y") and got == ["C:\\x", "C:\\y"]
    assert s.platform() == sys.platform and s.program() == sys.executable
    assert s.packed() is bool(getattr(sys, "frozen", False)) and s.modules() == getattr(sys, "_MEIPASS", None)


# --- E3 (K-6): the command through cli.main ----------------------------------------------------------------------
def through(monkeypatch, machine, argv=("service", "check")):
    monkeypatch.setattr(wincode, "System", lambda: machine)
    out = io.StringIO()
    return cli.main(list(argv), out), out.getvalue()


def test_e3_exit_0_one_sentence_of_what_was_checked_by_count(monkeypatch, capsys):
    m = Machine()
    code, out = through(monkeypatch, m)
    assert code == 0 and capsys.readouterr().err == ""
    assert out == ("raqib service check: the code a service would run is the system's alone: %s\n"
                   % wincode.checked_words({"folders": 3, "files": 2, "above": 2}))
    assert "checked 7 names" in out and "3 folders and 2 files" in out and "2 folders above it to the drive" in out


def test_e3_exit_1_the_name_refused_its_role_and_why(monkeypatch, capsys):
    code, out = through(monkeypatch, Machine(names={"C:\\": (0x16, "O:NSD:(A;OICI;FA;;;BA)")}))
    assert code == 1 and capsys.readouterr().err == ""
    assert out == ("raqib service check: NOT the system's alone: C:\\, as a folder above it (K-3): owned by NS, not"
                   " the system (SY), the administrators (BA) or the system's installer\n")
    code, out = through(monkeypatch, Machine(names={MODULES + "\\_bz2.pyd": OSError(32, "in use")}))
    assert code == 1 and out.startswith("raqib service check: NOT the system's alone: %s\\_bz2.pyd, as the code"
                                        " itself (K-2): not read (in use (error 32))" % MODULES)


def test_e3_names_and_texts_said_are_cut_and_made_printable(monkeypatch, capsys):
    sid = "S-1-5-21-" + "-".join(["1234567890"] * 30)
    code, out = through(monkeypatch, Machine(names={TOP: (0x10, "O:%sD:" % sid)}))
    assert code == 1 and out.isascii() and sid not in out and "..., not the system (SY)" in out
    assert len(out) < 2 * wincode.SAID_MAX + 200
    code, out = through(monkeypatch, Machine(lists={MODULES + "\\raqib": ["a\x1b[2Jb\x07"]}))
    assert code == 1 and "\x1b" not in out and "\x07" not in out and out[:-1].isprintable()


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_e3_not_windows_exit_2_said_which_never_a_pass(platform, monkeypatch, capsys):
    m = Machine(platform=platform)
    code, out = through(monkeypatch, m)
    assert code == 2 and out == "" and m.reads == []
    assert capsys.readouterr().err == "raqib: raqib service check: Windows only (it reads the owners and lists of" \
                                      " Windows); this is %s\n" % platform


def test_e3_not_packed_exit_2_its_road_not_yet_checked_never_a_pass(monkeypatch, capsys):
    m = Machine(packed=False, program=PY + "\\python.exe")
    code, out = through(monkeypatch, m)
    err = capsys.readouterr().err
    assert code == 2 and out == "" and m.reads == [] and err.count("\n") == 1
    assert err == "raqib: raqib service check: %s\\python.exe: %s\n" % (PY, wincode.NOT_PACKED)
    assert "a plain interpreter's roads" in err and "not yet checked" in err


@pytest.mark.parametrize("more", [["--purge"], ["--no-start"]])
def test_e3_install_and_removes_flags_are_theirs_only(more, monkeypatch, capsys):
    m = Machine()
    code, out = through(monkeypatch, m, ["service", "check"] + more)
    assert code == 2 and out == "" and m.reads == []
    assert capsys.readouterr().err == "raqib: raqib service: %s is %s's only\n" % (
        more[0], "remove" if more == ["--purge"] else "install")


@pytest.mark.skipif(sys.platform == "win32", reason="off Windows only: the real object's line of a Windows command")
def test_e3_the_real_command_off_windows_exit_2(capsys):
    assert cli.main(["service", "check"], io.StringIO()) == 2
    assert capsys.readouterr().err == "raqib: raqib service check: %s\n" % wincode.not_windows(sys.platform)


def test_e3_the_actions_help_says_check_and_the_cli_hands_it_to_wincode():
    sub = [a for a in cli._parser()._actions if getattr(a, "choices", None) and "service" in a.choices][0]
    action = [a for a in sub.choices["service"]._actions if a.dest == "action"][0]
    assert action.choices == ("install", "remove", "status", "run", "check")
    assert "check (Windows, Raqib packed with its own runtime; changes nothing, asks no right)" in action.help


# --- E5: the real reader, on Windows only -------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="the real reader is Windows' (winservice.System.read_place);"
                                                    " measured on GitHub's x64 and ARM64 machines (Amendment K)")
def test_e5_kernel32_is_taken_as_code_and_each_folder_above_it_as_a_folder_above():
    s = wincode.System()
    attributes, text = s.read("C:\\Windows\\System32\\kernel32.dll")
    assert wincode.as_code(attributes, text) is None, text
    for folder in ("C:\\Windows\\System32", "C:\\Windows", "C:\\"):
        attributes, text = s.read(folder)
        assert wincode.as_above(attributes, text) is None, (folder, text)


# --- E7: what the module is ----------------------------------------------------------------------------------------
def test_e7_ascii_ntpath_never_os_path_no_ctypes_nothing_at_import_nothing_written_no_process():
    source = (ROOT / "raqib" / "wincode.py").read_text(encoding="utf-8")
    assert source.isascii() and (ROOT / "tests" / "test_wincode.py").read_text(encoding="utf-8").isascii()
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {(n.value.id, n.attr) for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and isinstance(n.value, ast.Name)}
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    assert ("os", "path") not in attrs and "ctypes" not in imported and "subprocess" not in imported
    assert "open" not in names and not {("os", a) for a in ("remove", "mkdir", "makedirs", "replace", "rename",
                                                             "system", "startfile", "spawnl")} & attrs
    for node in tree.body:   # nothing runs at import: imports, names bound to constants, functions, classes
        kinds = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef, ast.Assign, ast.Expr)
        assert isinstance(node, kinds), node
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            assert ast.unparse(node.value.func) in ("re.compile", "namedtuple"), ast.unparse(node)
    assert max(len(line) for line in source.splitlines()) <= 118


# --- E6: the docs say the check as built ---------------------------------------------------------------------------
def test_e6_the_spec_the_guide_and_the_threat_model_say_the_check():
    def flat(path):
        return " ".join((ROOT / path).read_text(encoding="utf-8").split())
    spec = flat("docs/specs/SERVICE.md").split("## Windows: the check (`raqib service check`)", 1)[1]
    for words in ("`SY`, `S-1-5-18`", "`BA`, `S-1-5-32-544`", "by its whole SID only, `%s`" % INSTALLER,
                  "0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000, GR, GX",
                  "add a file 0x2, add a folder 0x4, write extended attributes 0x10, write attributes 0x100",
                  "begins with a drive's letter (`X:\\`)",
                  "longer than the system opens plainly (259 characters)", "what was not read is never the system's",
                  "a walk past 200000 names (WALK_MAX, the Linux number)", "`sys._MEIPASS`", "A plain interpreter is"
                  " refused for now", "| 0 | Windows, packed, and every name walked is the system's alone |",
                  "| 1 | a name is not the system's alone, or was not read |", "| 2 | not Windows, or not packed |",
                  "**What Amendment K measured, and by what.**", "Not read: rights a user holds apart from any list",
                  "Not measured: the kind of the drive", "an install of Python for all users",
                  "cut at 200 characters"):
        assert words in spec, words
    for bit, _ in wincode.CODE_ALLOWED:
        assert ("0x%x" % bit in spec) or bit in (0x80000000, 0x20000000)
    for word, number in wincode.RIGHTS.items():
        assert "%s 0x%x" % (word, number) in spec, word
    assert wincode.PLAIN_MAX == 259 and wincode.SAID_MAX == 200 and wincode.WALK_MAX == 200000
    guide = (ROOT / "docs" / "GUIDE.md").read_text(encoding="utf-8")
    commands = guide.split("## Commands\n", 1)[1].split("\n## ", 1)[0]
    (row,) = [r for r in commands.split("\n") if r.startswith("| `raqib service check` |")]
    assert "exit 0 the system's alone, with how many names of which kinds it checked, 1 not or not read" in row
    said = " ".join(commands.split())
    assert "Run `raqib service check` on Windows before a service of Windows is made to run" in said
    threat = flat("docs/THREAT_MODEL.md")
    assert "**What the check of the code does not read (`raqib service check`; ADR-0013 Amendment K).**" in threat
    assert "backup and restore, taking ownership, debugging programs" in threat
