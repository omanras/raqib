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
    "C:\\Users\\user": (R, R),
    "C:\\Windows": (T, T),
    "C:\\Windows\\System32": (T, T),
    "C:\\Windows\\System32\\kernel32.dll": (T, None),
    "C:\\Windows\\System32\\sc.exe": (T, None),
    "C:\\ProgramData": (R, R),   # L-1: 0x10 and 0x100 are no longer allowed above
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\python.exe": (R, None),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\Lib\\site-packages": (R, R),
    "C:\\hostedtoolcache\\windows\\Python\\3.12.10\\x64\\Lib\\os.py": (R, None),
    "C:\\Users\\user\\AppData\\Local": (R, R),
    "C:\\Users\\user\\AppData\\Local\\Temp": (R, R),
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
    "C:\\Users\\user": (["(A;OICI;FA;;;LA)"], ["(A;OICI;FA;;;LA)"]),
    "C:\\ProgramData": (["(A;CI;DCLCRPCR;;;BU)", "0x2, 0x4, 0x10, 0x100:"], ["(A;CI;DCLCRPCR;;;BU)", "0x10, 0x100:"]),
    PY + "\\python.exe": (["(A;ID;0x1301bf;;;AU)"], []),
    PY: (["(A;ID;0x1301bf;;;AU)"], ["(A;ID;0x1301bf;;;AU)", "0x10000"]),
    PY + "\\Lib\\os.py": (["(A;ID;0x1301bf;;;AU)"], []),
    "C:\\Users\\user\\AppData\\Local": (["(A;OICIID;FA;;;LA)"], ["(A;OICIID;FA;;;LA)"]),
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
    assert [b for b, _ in wincode.ABOVE_ALLOWED] == [b for b, _ in wincode.CODE_ALLOWED] + [0x2, 0x4]
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
    ("O:BAD:(A;;0x1200a9;;;BU)(A;;0x100;;;BU)", 0x10, R, R, "0x100:"),   # L-1
    ("O:BAD:(A;;0x1200a9;;;BU)(A;;0x10;;;BU)", 0x10, R, R, "0x10:"),      # L-1
    ("O:BAD:(A;;0x1200a9;;;BU)(A;;0x6;;;BU)", 0x10, R, T, "0x2, 0x4:"),   # adding a thing beside: above only
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

    def __init__(self, names=None, lists=None, platform="win32", packed=True, program=PROGRAM, modules=MODULES,
                 isolated=True, no_site=False, base=None, prefix=None, base_prefix=None, path=(), package=None,
                 files=None):
        base_names = {p: (a, t) for p, a, t, _ in measured()["x64"]}
        self.names = {ntpath.normcase(p): v for p, v in dict(base_names, **(names or {})).items()}
        self.lists = {ntpath.normcase(p): v for p, v in dict(TREE_LISTS, **(lists or {})).items()}
        self._platform, self._packed, self._program, self._modules = platform, packed, program, modules
        self._isolated, self._no_site, self._base, self._prefix = isolated, no_site, base, prefix
        self._base_prefix, self._path, self._package = base_prefix, list(path), package
        self.files = {ntpath.normcase(p): v for p, v in (files or {}).items()}
        self.reads, self.listed, self.asked, self.bytes_read = [], [], [], []

    # M-1, M-2: what the running interpreter says of itself (the plain road only)
    def isolated(self):
        self.asked.append("isolated")
        return self._isolated

    def no_site(self):
        self.asked.append("no_site")
        return self._no_site

    def base_executable(self):
        return self._base

    def prefix(self):
        return self._prefix

    def base_prefix(self):
        return self._base_prefix

    def sys_path(self):
        return list(self._path)

    def package_dir(self):
        return self._package

    def read_bytes(self, path, limit):
        self.bytes_read.append((path, limit))
        got = self.files.get(ntpath.normcase(path))
        if isinstance(got, BaseException):
            raise got
        if got is None:
            raise AssertionError("read the bytes of a file the test did not give: %s" % path)
        return got[:limit + 1]   # as the real object: at most one byte more than the bound

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


PLAIN_COUNTS = ("folders", "files", "above", "entries", "missing", "pth", "pth_lines")
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
    as_windows_raises = PermissionError(13, "Access is denied")   # L-5: listing a folder there gives both numbers;
    as_windows_raises.winerror = 5                                # the system's own is the one said
    bad, _ = wincode.check(Machine(lists={name: as_windows_raises}))
    assert "(Access is denied (error 5))" in bad[1] and "error 13" not in bad[1]


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


def test_e2_a_plain_interpreter_not_asked_with_i_and_not_windows_are_each_their_own_refusal_and_nothing_is_read():
    m = Machine(packed=False, program=PY + "\\python.exe", isolated=False)   # M-1 (was K-5's NOT_PACKED)
    assert wincode.check(m) == ((PY + "\\python.exe", wincode.not_asked(m)), dict.fromkeys(PLAIN_COUNTS, 0))
    assert "was not started with -I (isolated)" in wincode.not_asked(m) and m.reads == []
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


def test_e3_a_plain_interpreter_not_asked_with_i_exit_2_the_command_to_ask_by_never_a_pass(monkeypatch, capsys):
    m = Machine(packed=False, program=PY + "\\python.exe", isolated=False)   # M-1 (was K-5's "not packed")
    code, out = through(monkeypatch, m)
    err = capsys.readouterr().err
    assert code == 2 and out == "" and m.reads == [] and err.count("\n") == 1
    assert err == "raqib: raqib service check: %s\\python.exe: %s\n" % (PY, wincode.not_asked(m))
    assert err.endswith('; ask it as the service will run it: "%s\\python.exe" -I -m raqib service check\n' % PY)


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
    assert "check (Windows; changes nothing, asks no right)" in action.help
    assert "for a plain interpreter asked with -I, its folder, its base's, its prefixes, every entry of its path" \
           " and of its *.pth files, and the raqib package" in " ".join(action.help.split())


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
    assert not {("os", a) for a in ("remove", "mkdir", "makedirs", "replace", "rename", "system", "startfile",
                                    "spawnl", "open", "fdopen")} & attrs
    # M-4 (M12.4c1b): `open` is named once in the module, and that once is System.read_bytes's own call, in binary
    # mode, its one read bounded; nothing else opens a file, and nothing of a *.pth file can be run or imported
    opens = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "open"]
    (system,) = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System"]
    (method,) = [n for n in system.body if isinstance(n, ast.FunctionDef) and n.name == "read_bytes"]
    calls = [n for n in ast.walk(method) if isinstance(n, ast.Call)]
    (call,) = [c for c in calls if isinstance(c.func, ast.Name) and c.func.id == "open"]
    assert len(opens) == 1 and opens[0] is call.func and ast.unparse(call) == "open(path, 'rb')"
    assert [ast.unparse(c) for c in calls if ast.unparse(c.func).endswith(".read")] == ["f.read(limit + 1)"]
    assert not {("io", "open"), ("codecs", "open"), ("io", "FileIO")} & attrs
    assert not {"exec", "eval", "compile", "__import__"} & names
    assert not {"importlib", "io", "codecs", "pathlib", "runpy", "zipimport"} & imported
    for node in tree.body:   # nothing runs at import: imports, names bound to constants, functions, classes
        kinds = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef, ast.Assign, ast.Expr)
        assert isinstance(node, kinds), node
        if isinstance(node, ast.Expr):   # L-6: a bare expression at the top is the module's docstring, nothing else
            assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str), ast.unparse(node)
        if isinstance(node, ast.Assign):   # every call an assignment makes, anywhere in its value, is one of two
            for call in (n for n in ast.walk(node.value) if isinstance(n, ast.Call)):
                assert ast.unparse(call.func) in ("re.compile", "namedtuple"), ast.unparse(node)
    assert max(len(line) for line in source.splitlines()) <= 118


# --- E6: the docs say the check as built ---------------------------------------------------------------------------
def test_e6_the_spec_the_guide_and_the_threat_model_say_the_check():
    def flat(path):
        return " ".join((ROOT / path).read_text(encoding="utf-8").split())
    spec = flat("docs/specs/SERVICE.md").split("## Windows: the check (`raqib service check`)", 1)[1]
    for words in ("`SY`, `S-1-5-18`", "`BA`, `S-1-5-32-544`", "by its whole SID only, `%s`" % INSTALLER,
                  "0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000, GR, GX",
                  "add a file 0x2, add a folder 0x4, and no other bit", "(0x10, 0x100) refuses as well",
                  "the packed runtime's own roads", "what the drive's letter names",
                  "**What the check itself said on real machines (Amendment L).**",
                  "begins with a drive's letter (`X:\\`)",
                  "longer than the system opens plainly (259 characters)", "what was not read is never the system's",
                  "a walk past 200000 names (WALK_MAX, the Linux number)", "`sys._MEIPASS`",
                  "**The plain road (Amendment M).**", "the system's errors 2 and 3",
                  "at most 1048576 bytes (PTH_MAX)",
                  "| 0 | Windows, and every name walked of the road - packed, or a plain interpreter asked with `-I`"
                  " - is the system's alone |",
                  "| 1 | a name is not the system's alone, or was not read |",
                  "| 2 | not Windows, or a plain interpreter not started with `-I` or started with `-S` |",
                  "**What Amendment M measured, and by what.**",
                  "Not measured: whether `-I` reads the registry's paths",
                  "**What Amendment K measured, and by what.**", "Not read: rights a user holds apart from any list",
                  "Not measured: a denying entry on a real file", "python.org's installer for all users",
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
    assert "**What the check of the code does not read (`raqib service check`; ADR-0013 Amendments K and M).**" \
        in threat
    assert "whoever may add the missing thing decides what runs" in threat and "never passed (exit 2)" in threat
    assert "backup and restore, taking ownership, debugging programs" in threat


# --- M12.4c1b (ADR-0013 Amendment M, M-1 to M-5): a plain interpreter's road, on a made-up Windows ----------------
# The owners and lists of a Python under Program Files are read from tests/fixtures/wincode/python.txt (measured;
# never retyped here); each interpreter's path, as its comment lines say it, is written below from the rows' own
# folders. The folders above them (C:\, C:\Program Files) are measured.txt's x64 rows. What no machine gave - the
# venv's Lib folder, the installer's raqib package and its one *.pth file, every *.pth file's bytes - is a stand-in,
# said where it is made.
PYTHON = ROOT / "tests" / "fixtures" / "wincode" / "python.txt"


def python_measured():
    """{section: [(path, attributes, text)]} as python.txt holds them."""
    out, section, path = {}, None, None
    for line in PYTHON.read_text(encoding="ascii").splitlines():
        if line.startswith("## "):
            section = ("installer-x64" if "3.10.11" in line else "installer-arm64" if "3.11.9" in line
                       else "venv" if "a venv" in line else "copy")
            out[section] = []
        elif line.startswith("#") or not line.strip():
            continue
        elif not line.startswith(" "):
            path = line.strip()
        else:
            got = re.match(r"    a (folder|file) \(attributes (0x[0-9a-f]+)\); (\S+)\Z", line)
            assert got, line
            out[section].append((path, int(got.group(2), 16), got.group(3)))
    return out


ROWS = python_measured()
COPY, VENV = ROWS["copy"][0][0], ROWS["venv"][0][0]
SAID_OF_ITSELF = PYTHON.read_text(encoding="ascii").split("# What each said of itself", 1)[1]


def reading(path):
    (got,) = [(a, t) for rows in ROWS.values() for p, a, t in rows if p == path]
    return got


def tree(rows):
    """The listings the rows make: each folder lists the rows directly under it."""
    folders = [p for p, a, _ in rows if a & winservice.ATTRIBUTE_FOLDER]
    lists = {p: [] for p in folders}
    for p, _, _ in rows:
        for f in folders:
            if ntpath.normcase(ntpath.dirname(p)) == ntpath.normcase(f):
                lists[f].append(ntpath.basename(p))
    return lists


def road(section):
    """(rows, the machine's keywords) of one measured interpreter, its path as its comment lines say it."""
    rows = list(ROWS[section])
    if section.startswith("installer"):
        top = rows[0][0]
        site = top + "\\Lib\\site-packages"
        rows += [(site + "\\raqib", ) + reading(site),                                  # stand-ins: not measured
                 (site + "\\distutils-precedence.pth", ) + reading(top + "\\Lib\\os.py")]
        zipname = "python310.zip" if section == "installer-x64" else "python311.zip"   # the same shape on both
        return rows, dict(program=top + "\\python.exe", base=top + "\\python.exe", prefix=top, base_prefix=top,
                          path=[top + "\\" + zipname, top + "\\DLLs", top + "\\lib", top,
                                top + "\\lib\\site-packages"],
                          package=site + "\\raqib", files={site + "\\distutils-precedence.pth": b"import os\n"})
    copy_path = [COPY + "\\python312.zip", COPY + "\\DLLs", COPY + "\\Lib", COPY, COPY + "\\Lib\\site-packages"]
    if section == "copy":
        return rows, dict(program=COPY + "\\python.exe", base=COPY + "\\python.exe", prefix=COPY, base_prefix=COPY,
                          path=copy_path, package=COPY + "\\Lib\\site-packages\\raqib")
    rows = ROWS["copy"] + rows + [(VENV + "\\Lib", ) + reading(VENV + "\\Scripts"),     # stand-ins: not measured
                                  (VENV + "\\Lib\\site-packages\\raqib", ) + reading(VENV + "\\Scripts")]
    return rows, dict(program=VENV + "\\Scripts\\python.exe", base=COPY + "\\python.exe", prefix=VENV,
                      base_prefix=COPY, path=copy_path[:4] + [VENV, VENV + "\\Lib\\site-packages"],
                      package=VENV + "\\Lib\\site-packages\\raqib")


def plain(section="copy", names=None, lists=None, files=None, **kw):
    rows, given = road(section)
    given.update(kw)
    given["files"] = dict(given.get("files", {}), **(files or {}))
    return Machine(names=dict({p: (a, t) for p, a, t in rows}, **(names or {})),
                   lists=dict(tree(rows), **(lists or {})), packed=False, **given)


EXPECTED_PLAIN = {   # (folders, files, above, entries, missing, pth, pth_lines)
    "installer-x64": (6, 5, 2, 5, 1, 1, 0), "installer-arm64": (6, 5, 2, 5, 1, 1, 0),
    "copy": (6, 5, 2, 5, 1, 0, 0), "venv": (11, 7, 2, 6, 1, 0, 0)}


def test_m_every_line_of_the_measured_python_file_is_taken_as_code_and_each_folder_as_a_folder_above():
    assert sorted(ROWS) == sorted(EXPECTED_PLAIN) and sum(len(r) for r in ROWS.values()) == 34
    for rows in ROWS.values():
        for path, attributes, text in rows:
            assert wincode.as_code(attributes, text) is None, path
            if attributes & winservice.ATTRIBUTE_FOLDER:
                assert wincode.as_above(attributes, text) is None, path
    # the paths written above are the comment lines' own: each name there, each zip said "not there"
    for section in EXPECTED_PLAIN:
        rows, given = road(section)
        for entry in given["path"]:
            assert entry.endswith(".zip") or ntpath.normcase(entry) in {ntpath.normcase(p) for p, _, _ in rows}
    for said in ("python310.zip (not there)", "python312.zip (not there)", "pyvenv.cfg: home = " + COPY,
                 "executable " + VENV + "\\Scripts\\python.exe, base executable the copy's",
                 "executable and base executable " + COPY + "\\python.exe", "distutils-precedence.pth (one `import`"):
        assert said in " ".join(SAID_OF_ITSELF.replace("#", " ").split()), said


@pytest.mark.parametrize("section", sorted(EXPECTED_PLAIN))
def test_m_the_installers_tree_the_copy_and_the_venv_are_taken_each_name_read_once(section):
    m = plain(section)
    bad, counts = wincode.check(m)
    assert bad is None and tuple(counts[k] for k in PLAIN_COUNTS) == EXPECTED_PLAIN[section], (bad, counts)
    keys = [ntpath.normcase(p) for p in m.reads]
    assert len(keys) == len(set(keys))                 # each name read once, whatever the roles it was judged in
    assert m.asked == ["isolated", "no_site"] and m.reads[:2] == ["C:\\", "C:\\Program Files"]   # top first
    if section.startswith("installer"):                # its one *.pth file read once it was taken, by the bound
        site = road(section)[1]["path"][-1]           # joined to the entry as the path says it (its "lib")
        assert m.bytes_read == [(site + "\\distutils-precedence.pth", service.PTH_MAX)]
    else:
        assert m.bytes_read == []
    if section == "venv":                              # M-2's order: the interpreter, its base, the prefixes
        assert keys.index(ntpath.normcase(VENV + "\\Scripts\\python.exe")) < keys.index(ntpath.normcase(COPY)) \
            < keys.index(ntpath.normcase(VENV + "\\pyvenv.cfg"))
    assert wincode.plain_words(counts).startswith("checked %d names, each the system's alone" % sum(
        counts[k] for k in ("folders", "files", "above")))


def test_m_exit_0_on_the_plain_road_says_its_counts(monkeypatch, capsys):
    code, out = through(monkeypatch, plain("venv"))
    assert code == 0 and capsys.readouterr().err == ""
    counts = dict(zip(PLAIN_COUNTS, EXPECTED_PLAIN["venv"]))
    assert out == "raqib service check: the code a service would run is the system's alone: %s\n" % (
        wincode.plain_words(counts))
    for piece in ("checked 20 names", "6 entries of its path and the raqib package's folder, whole, 11 folders and 7"
                  " files", "(the creator's own inherit-only entry apart)", "1 of those entries not there",
                  "0 *.pth files read, 0 of their lines taken as entries, nothing of them run",
                  "and 2 folders above them to the drive's letter", "in the entries that apply to the folder itself"):
        assert piece in out, piece


@pytest.mark.parametrize("isolated, no_site, said", [
    (False, False, "a plain interpreter that was not started with -I (isolated): "),
    (True, True, "a plain interpreter that was started with -S (without its site): "),
    (0, 1, "a plain interpreter that was not started with -I (isolated) and was started with -S (without its site)"),
])
def test_m1_not_asked_with_i_or_asked_with_s_exit_2_nothing_read(isolated, no_site, said, monkeypatch, capsys):
    m = plain(isolated=isolated, no_site=no_site)
    code, out = through(monkeypatch, m)
    err = capsys.readouterr().err
    assert code == 2 and out == "" and m.reads == [] and m.bytes_read == []
    assert err == "raqib: raqib service check: %s\\python.exe: %s\n" % (COPY, wincode.not_asked(m))
    assert said in err and "the path it would walk is not the path the service gets" in err
    assert err.endswith('ask it as the service will run it: "%s\\python.exe" -I -m raqib service check\n' % COPY)


def test_m1_the_packed_road_is_chosen_first_and_its_flags_are_never_asked():
    m = Machine(isolated=False, no_site=True)
    assert wincode.check(m) == (None, {"folders": 3, "files": 2, "above": 2}) and m.asked == []


def refused(m):
    bad, counts = wincode.check(m)
    assert bad is not None, counts
    return bad


def test_m2_an_entry_in_a_folder_users_may_write_is_refused_by_that_folder():
    rows, given = road("copy")
    bad = refused(plain(path=given["path"] + ["C:\\ProgramData\\Raqib"]))
    assert bad[0] == "C:\\ProgramData" and bad[1].startswith(wincode.ROLE_ABOVE) and "0x10, 0x100:" in bad[1]


def test_m3_an_entry_not_there_under_c_is_judged_by_c_as_the_code_itself_and_refused():
    rows, given = road("copy")
    m = plain(path=given["path"] + ["C:\\made-later\\x"])
    bad = refused(m)
    assert bad[0] == "C:\\made-later\\x" and bad[1].startswith("not there (error 2): the deepest folder of it that is"
                                                               " there, C:\\, judged for it " + wincode.ROLE_CODE)
    assert "(A;;LC;;;AU)" in bad[1] and "0x4:" in bad[1] and m.reads.count("C:\\") == 1   # read once, judged twice


def test_m3_not_there_is_the_readers_errors_2_and_3_only():
    rows, given = road("copy")
    late = COPY + "\\later"
    for error, there in ((FileNotFoundError(2, "not found"), None), (OSError(3, "path not found"), None),
                         (PermissionError(5, "Access is denied"), "not read (Access is denied (error 5))"),
                         (OSError(1920, "cannot be accessed"), "not read (cannot be accessed (error 1920))"),
                         (OSError("2"), "not read"), (ValueError("a NUL"), "not read")):
        bad, counts = wincode.check(plain(path=given["path"] + [late + "\\x"], names={late: error}))
        if there is None:    # not there: judged by the copy's folder, the system's alone - taken, counted
            assert bad is None and counts["missing"] == 2 and counts["entries"] == 6, (error, bad)
        else:
            assert bad[0] == late and there in bad[1] and wincode.NOT_READ in bad[1], (error, bad)
    bad = refused(plain(path=["Q:\\x"]))
    assert bad == ("Q:\\x", "not there (error 2), and neither is its drive: no folder of it is there to be judged; "
                   + wincode.NOT_READ)


GOOD_PTH = reading(COPY + "\\Lib\\os.py")
SITE = COPY + "\\Lib\\site-packages"


def with_pth(data, name="x.pth", kind=GOOD_PTH):
    lists = {SITE: ["raqib", name], SITE + "\\" + name: []}   # the listing of a *.pth name that reads as a folder
    return plain(names={SITE + "\\" + name: kind}, lists=lists, files={SITE + "\\" + name: data})


def test_m4_the_lines_of_a_pth_file_by_sites_rule_with_ntpath():
    text = ("# a comment\n\n   \nimport os\nimport\tos\nimportx\nsub\\one  \n..\\..\\elsewhere\n"
            "C:\\Program Files\\Other\r\n\\\\server.example\\share\\x\n")
    assert wincode.pth_lines(text, SITE) == [SITE + "\\importx", SITE + "\\sub\\one", COPY + "\\elsewhere",
                                             "C:\\Program Files\\Other", "\\\\server.example\\share\\x"]
    assert wincode.PTH_MAX is service.PTH_MAX and wincode.PTH_ODD is service.PTH_ODD   # imported, not copied


def test_m4_a_pth_file_read_once_taken_its_path_lines_entries_its_import_line_nothing():
    m = with_pth(b"# a comment\n\nimport os\nLib\n")
    bad, counts = wincode.check(m)
    assert bad is None and (counts["pth"], counts["pth_lines"], counts["entries"], counts["missing"]) == (1, 1, 6, 2)
    assert m.bytes_read == [(SITE + "\\x.pth", service.PTH_MAX)]
    assert m.reads.index(SITE + "\\x.pth") < len(m.reads) and ntpath.normcase(SITE + "\\lib") in [
        ntpath.normcase(r) for r in m.reads]   # the line, not there, judged by its deepest folder (the site)


def test_m4_a_pth_line_that_leads_outside_is_refused_there_its_file_said():
    bad = refused(with_pth(b"..\\..\\..\\..\\Users\\user\n"))
    assert bad[0] == "C:\\Users\\user" and bad[1].startswith(wincode.ROLE_CODE) and "(A;OICI;FA;;;LA)" in bad[1]
    assert bad[1].endswith("(the entry C:\\Users\\user, a line of %s\\x.pth)" % SITE)
    bad = refused(with_pth(b"\\\\server.example\\share\\x\n"))
    assert bad[0] == "\\\\server.example\\share\\x" and bad[1].startswith("a line of %s\\x.pth, made whole: " % SITE)


@pytest.mark.parametrize("data, kind, said", [
    (b"#" * (service.PTH_MAX + 1), GOOD_PTH, "a *.pth file longer than 1048576 bytes (PTH_MAX): not read whole"),
    (b"#" * service.PTH_MAX, GOOD_PTH, None),
    (b"C:\\x\n\xe9", GOOD_PTH, "a *.pth file holding byte 0xe9 at offset 5, outside printable ASCII, tab, LF and CR"),
    (b"a\x00b\n", GOOD_PTH, "byte 0x00 at offset 1"),
    (PermissionError(5, "Access is denied"), GOOD_PTH,
     "a *.pth file that cannot be read (Access is denied (error 5))"),
    ("text, not bytes", GOOD_PTH, "a *.pth file whose bytes are not read"),
    (b"x\n", (0x20, "O:BAD:(A;;0x1301bf;;;AU)"), wincode.ROLE_CODE + ": the entry (A;;0x1301bf;;;AU)"),
    (b"x\n", (0x10, reading(SITE)[1]), "a *.pth name that is not a file as read"),
])
def test_m4_a_pth_file_too_long_with_an_odd_byte_not_read_or_not_taken_is_refused(data, kind, said):
    m = with_pth(data, kind=kind)
    bad, _ = wincode.check(m)
    if said is None:
        assert bad is None
        return
    assert bad[0] == SITE + "\\x.pth" and said in bad[1], bad
    if kind is not GOOD_PTH:
        assert m.bytes_read == []    # never read before it was taken as a file, the system's alone


def test_m2_a_base_executable_in_a_refused_folder_is_refused():
    stand_in = reading(COPY)   # not measured: the two folders above GitHub's Python, given a folder's taken list
    bad = refused(plain("venv", base=PY + "\\python.exe", names={"C:\\hostedtoolcache": stand_in,
                                                                 "C:\\hostedtoolcache\\windows": stand_in}))
    assert bad[0] == "C:\\hostedtoolcache\\windows\\Python" and bad[1].startswith(wincode.ROLE_ABOVE)
    assert "(A;ID;0x1301bf;;;AU)" in bad[1]


def test_m2_the_raqib_package_is_walked_outside_every_entry_and_refused_or_taken_by_its_own_lists():
    m = plain(package="D:\\a\\raqib\\raqib\\raqib")
    assert refused(m) == ("D:\\", wincode.ROLE_ABOVE + ": owned by NS, not the system (SY), the administrators (BA)"
                                                       " or the system's installer")
    assert m.reads[-1] == "D:\\" and SITE + "\\raqib\\cli.py" in m.reads   # every entry walked before it
    m = plain(package=MODULES + "\\raqib")    # the packed tree's measured raqib, outside every entry: taken
    bad, counts = wincode.check(m)
    assert bad is None and counts["folders"] == 7 and counts["above"] == 4 and m.reads[-1] == MODULES + "\\raqib"


def test_m2_an_entry_that_is_a_file_is_judged_as_itself():
    rows, given = road("copy")
    bad, counts = wincode.check(plain(path=given["path"] + [PROGRAM]))   # the packed program, measured: taken
    assert bad is None and counts["files"] == 6 and counts["above"] == 3 and counts["entries"] == 6
    bad = refused(plain(path=given["path"] + [COPY + "\\extra.zip"],
                        names={COPY + "\\extra.zip": (0x20, "O:BAD:(A;;0x1301bf;;;AU)")}))
    assert bad[0] == COPY + "\\extra.zip" and bad[1].startswith(wincode.ROLE_CODE + ": the entry (A;;0x1301bf;;;AU)")


@pytest.mark.parametrize("entry, said", [
    (7, "an entry of the interpreter's path that is not a string: not read"),
    (None, "an entry of the interpreter's path that is not a string"),
    ("", "an entry of the interpreter's path: is not said"),
    ("relative\\x", "does not begin with a drive's letter"),
    ("\\\\server.example\\share\\x", "does not begin with a drive's letter"),
    ("C:\\Program Files\\..\\x", "not a whole path of a drive: an empty part, . or .."),
    (COPY + "\\", "an empty part"), ("C:\\x\\NUL", "a device's name"),
    ("C:\\" + "a" * 300, "longer than the system opens plainly"),
])
def test_m2_an_entry_that_is_not_a_whole_drive_path_is_refused_with_its_own_words(entry, said):
    rows, given = road("copy")
    m = plain(path=[entry] + given["path"])
    bad = refused(m)
    assert said in bad[1] and len(m.reads) == 13, bad   # the roots read (2 above, 11 under the copy), no entry
    assert bad[1].startswith("an entry of the interpreter's path")


@pytest.mark.parametrize("which, said", [("program", "the interpreter's path"),
                                         ("base", "the base executable's path"),
                                         ("prefix", "the interpreter's prefix"),
                                         ("base_prefix", "the interpreter's base prefix")])
def test_m2_a_root_not_a_whole_drive_path_is_refused_and_nothing_is_read(which, said):
    m = plain(**{which: "\\\\server.example\\share\\python.exe"})
    bad = refused(m)
    assert bad[1].startswith(said + " \\\\server.example") and m.reads == []


def test_m2_names_compared_without_case_and_one_walk_max_for_the_whole_walk(monkeypatch):
    rows, given = road("copy")
    m = plain(path=given["path"] + [COPY.upper() + "\\LIB", "c:\\program files\\raqibprobe9py\\lib\\SITE-PACKAGES"])
    bad, counts = wincode.check(m)
    assert bad is None and counts["entries"] == 5 and len(m.reads) == 14   # met again, never read again
    monkeypatch.setattr(wincode, "WALK_MAX", 10)
    m = plain()
    bad, counts = wincode.check(m)
    assert bad[1] == "more than 10 names to walk (WALK_MAX): a walk that is not whole is not a pass"
    assert sum(counts[k] for k in ("folders", "files", "above")) == 10 and len(m.reads) == 10


def test_m_the_real_system_objects_answers_are_the_running_interpreters(tmp_path):
    import raqib
    s = wincode.System()
    assert s.isolated() is bool(sys.flags.isolated) and s.no_site() is bool(sys.flags.no_site)
    assert s.base_executable() == getattr(sys, "_base_executable", None) and s.sys_path() == list(sys.path)
    assert s.prefix() == sys.prefix and s.base_prefix() == sys.base_prefix
    assert s.package_dir() == ntpath.dirname(raqib.__file__) and Path(s.package_dir()) == Path(raqib.__file__).parent
    f = tmp_path / "x.pth"
    f.write_bytes(b"0123456789")
    assert s.read_bytes(str(f), 4) == b"01234" and s.read_bytes(str(f), 100) == b"0123456789"
