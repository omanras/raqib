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
    """One name's reading as the fixture holds it: what the real reader returns, or its OSError. Its drives (P-1,
    asked before any name of them is read) read as a disk: C: as measured (drives.txt), D: a stand-in (DISK_STAND_IN).
    """

    def __init__(self, rows):
        self.rows = {ntpath.normcase(p): (a, t, e) for p, a, t, e in rows}

    def drive(self, root):
        return MEASURED_C if root.upper() == "C:\\" else DISK_STAND_IN

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
# P-1, Q-1 (Amendments P, Q): what the system says of a drive (winservice.System.read_drive), measured on GitHub's
# machines and read from tests/fixtures/wincode/drives.txt (never retyped here)
DRIVES = ROOT / "tests" / "fixtures" / "wincode" / "drives.txt"


def drives_measured():
    """{"x64" or "arm64": [(letter, what it was, kind, the device's name or the reader's error)]} as drives.txt holds
    them; an error (`not read: error N`) is built in the words winservice.System.read_drive raises it with."""
    out, section = {}, None
    for line in DRIVES.read_text(encoding="ascii").splitlines():
        if line.startswith("#"):
            head = re.match(r"# windows-\S+ \((x64|ARM64)\)\Z", line)
            if head:
                section = head.group(1).lower()
                out[section] = []
            continue
        letter, what, kind, name = line.split("\t")
        error = re.match(r"not read: error ([0-9]+)\Z", name)
        if error:
            name = OSError(int(error.group(1)), "the device's name of %s was not read (the drive's kind %d)" % (
                letter, int(kind)))
        out[section].append((letter, what, int(kind), name))
    return out


DRIVE_ROWS = drives_measured()


def drive_row(letter, what, section="x64"):
    (got,) = [(k, n) for x, w, k, n in DRIVE_ROWS[section] if x == letter and w == what]
    return got


MEASURED_C = drive_row("C:", "the system's disk")    # kind 3, a disk's volume (its number varies)
FOLDER_LETTER = drive_row("R:", "a letter given to a folder (subst R: C:\\ProgramData)")   # kind 3, the folder's path
NOT_THERE_LETTER = drive_row("Q:", "a letter that is not there")[1]   # kind 1, error 2: the reader's error
DISK_STAND_IN = (3, "\\Device\\HarddiskVolume1")   # a stand-in, not measured: a letter no test gives, of Q-1's form
TOP = "C:\\Program Files\\RaqibProbe8"
PROGRAM = TOP + "\\raqib.exe"
MODULES = TOP + "\\_internal"
TREE_LISTS = {TOP: ["raqib.exe", "_internal"], MODULES: ["_bz2.pyd", "raqib"], MODULES + "\\raqib": []}
GOOD_FILE = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"


class Machine:
    """A made-up Windows: names read from the measured x64 rows (or as a test gives them), listings as given; its
    drives as a test gives them (P-1), else C: as measured (drives.txt) and any other letter a stand-in disk of Q-1's
    form (DISK_STAND_IN)."""

    def __init__(self, names=None, lists=None, platform="win32", packed=True, program=PROGRAM, modules=MODULES,
                 isolated=True, no_site=False, base=None, prefix=None, base_prefix=None, path=(), package=None,
                 files=None, exec_prefix=None, base_exec_prefix=None, version=(3, 12), drives=None):
        self._version = version
        self._drives = {k.upper(): v for k, v in (drives or {}).items()}
        self.drives_asked = []
        base_names = {p: (a, t) for p, a, t, _ in measured()["x64"]}
        self.names = {ntpath.normcase(p): v for p, v in dict(base_names, **(names or {})).items()}
        self.lists = {ntpath.normcase(p): v for p, v in dict(TREE_LISTS, **(lists or {})).items()}
        self._platform, self._packed, self._program, self._modules = platform, packed, program, modules
        self._isolated, self._no_site, self._base, self._prefix = isolated, no_site, base, prefix
        self._base_prefix, self._path, self._package = base_prefix, list(path), package
        self._exec_prefix, self._base_exec_prefix = exec_prefix, base_exec_prefix
        self.files = {ntpath.normcase(p): v for p, v in (files or {}).items()}
        self.reads, self.listed, self.asked, self.bytes_read = [], [], [], []
        self.events = []   # every read of a name, of a drive and of a file's bytes, in the order asked

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

    def exec_prefix(self):
        return self._exec_prefix

    def base_exec_prefix(self):
        return self._base_exec_prefix

    def sys_path(self):
        return list(self._path)

    def package_dir(self):
        return self._package

    def read_bytes(self, path, limit):
        self.bytes_read.append((path, limit))
        self.events.append(("bytes", path))
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

    def version(self):
        return self._version

    def program(self):
        return self._program

    def modules(self):
        return self._modules

    def read(self, path):
        self.reads.append(path)
        self.events.append(("read", path))
        got = self.names.get(ntpath.normcase(path))
        if got is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        if isinstance(got, BaseException):
            raise got
        return got

    def drive(self, root):
        self.drives_asked.append(root)
        self.events.append(("drive", root))
        letter = root[:2].upper()
        got = self._drives.get(letter, MEASURED_C if letter == "C:" else DISK_STAND_IN)
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


PLAIN_COUNTS = ("folders", "files", "above", "alone", "entries", "missing", "beneath", "own", "own_there", "pth",
                "pth_lines", "base", "exec")
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
                   % wincode.checked_words({"folders": 3, "files": 2, "above": 2}, [("C:", MEASURED_C[1])]))
    assert out.endswith(' and the drive asked before any name of it was read, each said by the system to be of the'
                        ' fixed kind with a device\'s name of the form \\Device\\HarddiskVolumeN:'
                        ' C: "\\Device\\HarddiskVolume3"\n')
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
    # mode, its one read bounded; nothing else opens a file, and the check can run or import nothing of a *.pth file
    opens = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "open"]
    (system,) = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "System"]
    (method,) = [n for n in system.body if isinstance(n, ast.FunctionDef) and n.name == "read_bytes"]
    calls = [n for n in ast.walk(method) if isinstance(n, ast.Call)]
    (call,) = [c for c in calls if isinstance(c.func, ast.Name) and c.func.id == "open"]
    assert len(opens) == 1 and opens[0] is call.func and ast.unparse(call) == "open(path, 'rb')"
    assert [ast.unparse(c) for c in calls if ast.unparse(c.func).endswith(".read")] == ["f.read(limit + 1)"]
    assert not {("io", "open"), ("codecs", "open"), ("io", "FileIO")} & attrs
    assert not {"exec", "eval", "compile", "__import__"} & names
    said = " ".join(source.split()).lower()   # N-2: run by the code it judges, the check says only its own part
    assert not [w for w in ("nothing of them run", "nothing of a *.pth file is run", "nothing of it is run",
                            "nothing of the text is run", "nothing is written") if w in said]
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
                  "the packed runtime's own roads", "what the drive's letter names",   # now in P-1's paragraph
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
                  "Not measured: whether `-I` reads the registry's paths on x64 or on a later version",
                  "**What Amendment O added, and what the names rest on.**", "is refused with those words (O-2)",
                  "**What Amendment K measured, and by what.**", "Not read: rights a user holds apart from any list",
                  "Not measured: a denying entry on a real file", "python.org's installer for all users",
                  "cut at 200 characters",
                  # N-1 to N-3 (M12.4c1b REDO): both roads, the three names, who runs the check, beneath a file, dots
                  "**The roads walked (K-5, M-2).** Two: the packed road, and the plain road below.",
                  "**The names the interpreter itself looks for (Amendment N, N-1).**",
                  "`pyvenv.cfg` in the folder above it, and `Modules\\Setup.local` and `Lib` two folders above it",
                  "read in its source (CPython 3.11.9, 3.12.10, 3.13.9 and 3.14.0", "Amendment N), not measured",
                  "it is refused on a machine whose root lets signed-in users add a folder",
                  "one folder deeper (`C:\\Program Files\\NAME\\Python311`) it is taken",
                  "**Who runs the check (Amendment N, N-2).**", "the check is run by the code it judges",
                  "a gate against a tree put in the wrong place, not a judgement of a tree another already changed",
                  "Ask it first as a plain user, who needs no rights for it",
                  "may write bytecode caches beside what it imports, where the asker may write there",
                  "is taken where that file was taken as the code itself",
                  "one beginning with a dot, which site skips, is read even so",
                  "none of their lines taken or run by the check",
                  # P-1, P-2 (M12.4c2a): the drive and the libraries loaded by name, moved to what is refused
                  "**The drive (Amendments P and Q, P-1 and Q-1).**", "the check asks what the drive's letter names",
                  "A path is judged only where its drive is of the fixed kind (3) and its device's name is, whole and"
                  " with its case, `\\Device\\HarddiskVolume` and one or more of the digits 0-9",
                  "(0 unknown, 1 no root, 2 removable, 3 fixed, 4 remote, 5 a disc, 6 a RAM disk;"
                  " another number said as it is)", "**What Amendment P measured and read, and what it did not.**",
                  "`\\??\\C:\\ProgramData`", "a letter given to a folder is refused by its drive (P-1, above)",
                  "Not measured, and said: a network drive, a removable disk and a disc",
                  "X51 (`tools/rig/check.py --service-check-drive FILE`",
                  # Q-1 to Q-3 (M12.4c2a REDO): the form, the session, the readers, a fixed disk, the third place
                  "a volume of another kind of disk (not measured, and refused until it is)",
                  "The letter is read as the session that runs the check names it",
                  "The device's name has that one reader in the tree; the kind has two",
                  "A disk the system calls fixed is taken as a disk whatever it is",
                  "The reading names three places a library is searched", "nothing holds what the interpreter's own"
                  " start adds", "**What Amendment Q measured, and what it changed.**"):
        assert words in spec, words
    assert "first met by" not in spec and "or a share reads so" not in spec
    assert "begins with `\\Device\\`." not in spec
    assert "a letter given to a folder is read as a drive of its own" not in spec
    assert "to be pinned by a test with the install" not in spec
    assert "Packed with its own runtime only" not in spec and "nothing of them run" not in spec
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
    assert "**What the check of the code does not read (`raqib service check`; ADR-0013 Amendments K to Q).**" \
        in threat
    for words in ("closed by Amendment P", "judges a path only on a drive of the fixed kind whose device's name is,"
                  " whole, a disk's volume in the form measured (`\\Device\\HarddiskVolume` and a number, nothing"
                  " after it", "tests/test_libraries.py", "a letter the system's account has and the asker has"
                  " not",   # M12.4c2a (P-1, P-2): moved from not read to what is refused
                  "The device's name has one reader in the tree; the kind has two", "a volume a program serves",
                  "The letter is read as the session that runs the check names it", "names three places",
                  "nothing holds what the interpreter's own start adds"):   # M12.4c2a REDO (Q-1 to Q-3)
        assert words in threat, words
    assert "not yet pinned by a test" not in threat and "refused with the install, not yet" not in threat
    assert "whoever may add the missing thing decides what runs" in threat and "never passed (exit 2)" in threat
    assert "backup and restore, taking ownership, debugging programs" in threat
    for words in ("the check is run by the code it judges", "a gate against a tree put in the wrong place",
                  "asked first by a plain user, who needs no rights for it", "may write bytecode caches",
                  "`Modules\\Setup.local` and `Lib` two folders above it", "one folder deeper it is taken"):
        assert words in threat, words
    assert "nothing of it is run" not in threat
    assert "A path is judged only on a drive the system says is of the fixed kind with a device's name" in said
    for words in ("is refused on a machine whose drive's root lets signed-in users add a folder",
                  "Put a Python a service will run one folder deeper instead", "Ask it first as a plain user",
                  "the check is run by the code it judges", "may write bytecode caches"):
        assert words in said, words


# --- M12.4c1b (ADR-0013 Amendments M and N): a plain interpreter's road, on a made-up Windows ----------------------
# The owners and lists of a Python under Program Files are read from tests/fixtures/wincode/python.txt (measured;
# never retyped here); each interpreter's path, as its comment lines say it, is written below from the rows' own
# folders. The folders above them (C:\, C:\Program Files) are measured.txt's x64 rows. What no machine gave is a
# stand-in, said where it is made: the venv's Lib folder, the installer's raqib package and its one *.pth file, every
# *.pth file's bytes, every folder's listing (tree()), and the folder that places the measured trees one folder deeper
# (RIG, N-1).
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
COPY_AT, VENV_AT = ROWS["copy"][0][0], ROWS["venv"][0][0]   # where the copy and the venv were measured
SAID_OF_ITSELF = PYTHON.read_text(encoding="ascii").split("# What each said of itself", 1)[1]
RIG = "C:\\Program Files\\Rig"   # a stand-in folder (N-1, N-5): the measured trees placed one folder deeper, in it


def reading(path):
    (got,) = [(a, t) for rows in ROWS.values() for p, a, t in rows if p == path]
    return got


def deeper(path):
    """A measured path placed one folder deeper: C:\\Program Files\\X\\... as C:\\Program Files\\Rig\\X\\..."""
    head = "C:\\Program Files\\"
    assert path.startswith(head), path
    return RIG + "\\" + path[len(head):]


COPY, VENV = deeper(COPY_AT), deeper(VENV_AT)


def tree(rows):
    """Stand-ins, not measured: the listings the rows make, each folder listing only the rows directly under it (one
    to three names). A real tree lists more - `__pycache__` folders, bytecode, other *.pth files - and may give
    another name refused first."""
    folders = [p for p, a, _ in rows if a & winservice.ATTRIBUTE_FOLDER]
    lists = {p: [] for p in folders}
    for p, _, _ in rows:
        for f in folders:
            if ntpath.normcase(ntpath.dirname(p)) == ntpath.normcase(f):
                lists[f].append(ntpath.basename(p))
    return lists


def measured_road(section):
    """(rows, the machine's keywords) of one measured interpreter where it was measured, its path as its comment
    lines say it; its exec prefixes its prefixes (N-3: not in the fixture)."""
    rows = list(ROWS[section])
    if section.startswith("installer"):
        top = rows[0][0]
        site = top + "\\Lib\\site-packages"
        rows += [(site + "\\raqib", ) + reading(site),                                  # stand-ins: not measured
                 (site + "\\distutils-precedence.pth", ) + reading(top + "\\Lib\\os.py")]
        zipname = "python310.zip" if section == "installer-x64" else "python311.zip"   # the same shape on both
        return rows, dict(program=top + "\\python.exe", base=top + "\\python.exe", prefix=top, base_prefix=top,
                          exec_prefix=top, base_exec_prefix=top,
                          path=[top + "\\" + zipname, top + "\\DLLs", top + "\\lib", top,
                                top + "\\lib\\site-packages"],
                          package=site + "\\raqib", files={site + "\\distutils-precedence.pth": b"import os\n"})
    copy_path = [COPY_AT + "\\python312.zip", COPY_AT + "\\DLLs", COPY_AT + "\\Lib", COPY_AT,
                 COPY_AT + "\\Lib\\site-packages"]
    if section == "copy":
        return rows, dict(program=COPY_AT + "\\python.exe", base=COPY_AT + "\\python.exe", prefix=COPY_AT,
                          base_prefix=COPY_AT, exec_prefix=COPY_AT, base_exec_prefix=COPY_AT, path=copy_path,
                          package=COPY_AT + "\\Lib\\site-packages\\raqib")
    rows = ROWS["copy"] + rows + [(VENV_AT + "\\Lib", ) + reading(VENV_AT + "\\Scripts"),   # stand-ins: not measured
                                  (VENV_AT + "\\Lib\\site-packages\\raqib", ) + reading(VENV_AT + "\\Scripts")]
    return rows, dict(program=VENV_AT + "\\Scripts\\python.exe", base=COPY_AT + "\\python.exe", prefix=VENV_AT,
                      base_prefix=COPY_AT, exec_prefix=VENV_AT, base_exec_prefix=COPY_AT,
                      path=copy_path[:4] + [VENV_AT, VENV_AT + "\\Lib\\site-packages"],
                      package=VENV_AT + "\\Lib\\site-packages\\raqib")


def road(section, places=None):
    """(rows, the machine's keywords) of one measured interpreter, each of its trees placed as `places` says
    ({measured top folder: its place}; None: every tree one folder deeper, under RIG; {}: where measured). The folder
    a tree is placed in, where it is not Program Files, reads as the measured copy's own folder row (a stand-in)."""
    rows, given = measured_road(section)
    if places is None:
        places = {t: deeper(t) for t in {"\\".join(p.split("\\")[:3]) for p, _, _ in rows}}

    def move(path):
        for old, new in places.items():
            if wincode._within(path, old):
                return new + path[len(old):]
        return path
    holders = {ntpath.dirname(new) for new in places.values()} - {"C:\\Program Files"}
    rows = [(move(p), a, t) for p, a, t in rows] + [(h, ) + reading(COPY_AT) for h in sorted(holders)]
    for key, value in list(given.items()):
        given[key] = ([move(e) for e in value] if key == "path" else {move(f): b for f, b in value.items()}
                      if key == "files" else move(value))
    return rows, given


def plain(section="copy", names=None, lists=None, files=None, places=None, **kw):
    rows, given = road(section, places)
    given.update(kw)
    given["files"] = dict(given.get("files", {}), **(files or {}))
    return Machine(names=dict({p: (a, t) for p, a, t in rows}, **(names or {})),
                   lists=dict(tree(rows), **(lists or {})), packed=False, **given)


EXPECTED_PLAIN = {   # PLAIN_COUNTS of each measured tree placed one folder deeper (N-1)
    "installer-x64": (6, 5, 1, 2, 5, 1, 0, 3, 0, 1, 0, 0, 0),
    "installer-arm64": (6, 5, 1, 2, 5, 1, 0, 3, 0, 1, 0, 0, 0),
    "copy": (6, 5, 1, 2, 5, 1, 0, 3, 0, 0, 0, 0, 0),
    "venv": (11, 7, 1, 2, 6, 1, 0, 6, 1, 0, 0, 1, 0)}


def test_m_every_line_of_the_measured_python_file_is_taken_as_code_and_each_folder_as_a_folder_above():
    assert sorted(ROWS) == sorted(EXPECTED_PLAIN) and sum(len(r) for r in ROWS.values()) == 34
    for rows in ROWS.values():
        for path, attributes, text in rows:
            assert wincode.as_code(attributes, text) is None, path
            if attributes & winservice.ATTRIBUTE_FOLDER:
                assert wincode.as_above(attributes, text) is None, path
    # the paths written above are the comment lines' own: each name there, each zip said "not there"
    for section in EXPECTED_PLAIN:
        for places in (None, {}):
            rows, given = road(section, places)
            for entry in given["path"]:
                assert entry.endswith(".zip") or ntpath.normcase(entry) in {ntpath.normcase(p) for p, _, _ in rows}
    for said in ("python310.zip (not there)", "python312.zip (not there)", "pyvenv.cfg: home = " + COPY_AT,
                 "executable " + VENV_AT + "\\Scripts\\python.exe, base executable the copy's",
                 "executable and base executable " + COPY_AT + "\\python.exe", "distutils-precedence.pth (one `import`"):
        assert said in " ".join(SAID_OF_ITSELF.replace("#", " ").split()), said


def own_reads(m):
    """The reads of N-1's names and of the folders made on the way to them, by normcase: each read at most once."""
    keys = [ntpath.normcase(p) for p in m.reads]
    assert len(keys) == len(set(keys)), m.reads
    return keys


@pytest.mark.parametrize("section", sorted(EXPECTED_PLAIN))
def test_n1_the_installers_tree_the_copy_and_the_venv_one_folder_deeper_are_taken_each_name_read_once(section):
    m = plain(section)
    bad, counts = wincode.check(m)
    assert bad is None and tuple(counts[k] for k in PLAIN_COUNTS) == EXPECTED_PLAIN[section], (bad, counts)
    keys = own_reads(m)                                # each name read once, whatever the roles it was judged in
    assert m.asked == ["isolated", "no_site"] and m.reads[:3] == ["C:\\", "C:\\Program Files", RIG]   # top first
    # N-1: Modules\Setup.local and Lib two folders above (the base's, for the venv): judged, not there, read once
    assert "c:\\program files\\modules" in keys and "c:\\program files\\lib" in keys
    assert "c:\\program files\\modules\\setup.local" not in keys   # its folder not there: never asked
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


@pytest.mark.parametrize("section", sorted(EXPECTED_PLAIN))
def test_n1_each_tree_where_it_was_measured_is_refused_for_c_modules_setup_local_judged_by_c(section):
    m = plain(section, places={})
    bad = refused(m)
    folder = COPY_AT if section in ("copy", "venv") else ROWS[section][0][0]   # the venv: refused for its base
    what = "the base executable's folder" if section == "venv" else "the interpreter's folder"
    assert bad == ("C:\\Modules\\Setup.local", "not there (error 2): the deepest folder of it that is there, C:\\,"
                   " judged for it " + wincode.ROLE_CODE + ": the entry (A;;LC;;;AU) gives AU, a name outside the"
                   " system's, 0x4: not allowed (" + wincode.CODE_MAY + ") (the name C:\\Modules\\Setup.local: "
                   + wincode.OWN_NAMES[1] + " " + what + " " + folder + ")")
    keys = own_reads(m)                                # each name read at most once; C:\Modules\Setup.local never
    assert "c:\\modules" in keys and "c:\\modules\\setup.local" not in keys and m.reads[-1] == "C:\\Modules"
    assert "c:\\program files\\pyvenv.cfg" in keys     # the first of the three: judged by Program Files, taken
    (c,) = [(a, t) for p, a, t, _ in measured()["x64"] if p == "C:\\"]
    (pf,) = [(a, t) for p, a, t, _ in measured()["x64"] if p == "C:\\Program Files"]
    assert wincode.as_code(*c) is not None and wincode.as_code(*pf) is None   # measured.txt, read as the code itself


def test_n1_a_venv_whose_base_is_one_folder_below_program_files_is_refused_one_folder_deeper_taken():
    assert refused(plain("venv", places={}))[1].endswith("the base executable's folder %s)" % COPY_AT)
    m = plain("venv", places={COPY_AT: COPY})          # the venv where measured, its base one folder deeper
    bad, counts = wincode.check(m)
    assert bad is None and (counts["own"], counts["own_there"], counts["base"], counts["alone"]) == (4, 1, 1, 2)
    own_reads(m)


def test_o1_the_base_prefixs_names_are_judged_where_no_base_executable_names_its_folder():
    """O-1: the interpreter keys a venv's build tree on the home its pyvenv.cfg names, which is the base prefix; the
    check asks the base prefix too, so a base executable unnamed, or said as the venv's own, hides nothing."""
    rows, given = road("venv", places={})              # the venv and its base where measured
    for base in (None, given["program"]):
        m = plain("venv", places={}, base=base)
        name, words = refused(m)
        assert name == "C:\\Modules\\Setup.local" and "there, C:\\, judged for it" in words, (base, name, words)
        assert words.endswith("the interpreter's base prefix %s)" % given["base_prefix"]), words
    m = plain("venv", places={COPY_AT: COPY}, base=None)   # the base one folder deeper: taken, its names asked
    bad, counts = wincode.check(m)
    assert bad is None and counts["base"] == 0 and counts["own"] == 4, (bad, counts)
    bad, counts = wincode.check(plain("copy"))             # a plain install: the base prefix is its own folder
    assert bad is None and counts["own"] == 3


@pytest.mark.parametrize("version", [(3, 14), (3, 15), (4, 0), None, "3.12", (3,), (3, 12, 1), (3.0, 12), (True, 12)])
def test_o2_a_packed_runtime_of_3_14_or_later_or_of_no_known_version_is_refused_and_nothing_read(version):
    m = Machine(version=version)
    bad, counts = wincode.check(m)
    assert bad[0] == PROGRAM and "pyvenv.cfg" in bad[1] and "from 3.14 on" in bad[1] and "O-2" in bad[1], bad
    assert m.reads == [] and m.listed == [] and counts == {"folders": 0, "files": 0, "above": 0}


@pytest.mark.parametrize("version", [(3, 11), (3, 12), (3, 13)])
def test_o2_a_packed_runtime_older_than_3_14_is_walked_as_before(version):
    bad, counts = wincode.check(Machine(version=version))
    assert bad is None and counts == wincode.check(Machine())[1] and wincode.PACKED_BELOW == (3, 14)
    assert wincode.check(plain("copy", version=(3, 14)))[0] is None   # the plain road judges that name (N-1)


def test_n1_a_pyvenv_cfg_there_in_the_folder_above_is_judged_as_a_file_taken_and_counted_or_refused():
    name = RIG + "\\pyvenv.cfg"
    bad, base = wincode.check(plain())
    m = plain(names={name: GOOD_PTH})                  # a stand-in reading: the measured os.py's
    bad, counts = wincode.check(m)
    assert bad is None and counts["files"] == base["files"] + 1 and counts["own_there"] == 1
    assert counts["alone"] == base["alone"] - 1 and own_reads(m).count(ntpath.normcase(name)) == 1
    m = plain(names={name: (0x20, "O:BAD:(A;;0x1301bf;;;AU)")})
    assert refused(m) == (name, wincode.ROLE_CODE + ": the entry (A;;0x1301bf;;;AU) gives AU, a name outside the"
                          " system's, 0x2, 0x4, 0x10, 0x100, 0x10000: not allowed (" + wincode.CODE_MAY + ") (the"
                          " name " + name + ": " + wincode.OWN_NAMES[0] + " the interpreter's folder " + COPY + ")")


def test_n1_a_folder_above_that_lets_users_add_a_file_is_refused_for_pyvenv_cfg_where_the_first_build_took_it():
    drop = "C:\\Program Files\\Drop"                   # the review's finding 1, its input exactly
    reading_of_drop = (0x10, "O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200ab;;;BU)")
    assert wincode.as_above(*reading_of_drop) is None   # K-3 takes it: the first build's walk passed this tree
    m = plain(places={COPY_AT: drop + "\\Py"}, names={drop: reading_of_drop})
    bad = refused(m)
    assert bad[0] == drop + "\\pyvenv.cfg" and bad[1].startswith(
        "not there (error 2): the deepest folder of it that is there, %s, judged for it %s: the entry"
        " (A;;0x1200ab;;;BU) gives BU, a name outside the system's, 0x2: not allowed" % (drop, wincode.ROLE_CODE))
    assert bad[1].endswith("(the name %s\\pyvenv.cfg: %s the interpreter's folder %s\\Py)" % (
        drop, wincode.OWN_NAMES[0], drop))
    own_reads(m)


def test_n1_lib_there_two_folders_above_is_walked_whole():
    lib = "C:\\Program Files\\Lib"
    bad, base = wincode.check(plain())
    m = plain(names={lib: reading(COPY_AT + "\\Lib"), lib + "\\x.py": GOOD_PTH}, lists={lib: ["x.py"]})
    bad, counts = wincode.check(m)
    assert bad is None and counts["own_there"] == 1 and lib + "\\x.py" in m.reads and lib in m.listed
    assert (counts["folders"], counts["files"]) == (base["folders"] + 1, base["files"] + 1)
    m = plain(names={lib: reading(COPY_AT + "\\Lib"), lib + "\\x.py": (0x20, "O:BAD:(A;;0x1301bf;;;AU)")},
              lists={lib: ["x.py"]})
    bad = refused(m)
    assert bad[0] == lib + "\\x.py" and bad[1].endswith("(the name %s: %s the interpreter's folder %s)" % (
        lib, wincode.OWN_NAMES[2], COPY))
    own_reads(m)


def test_n1_the_three_names_with_ntpath_and_the_packed_road_never_asks_them():
    assert wincode.own_names("C:\\Program Files\\Python311") == list(zip(
        ("C:\\Program Files\\pyvenv.cfg", "C:\\Modules\\Setup.local", "C:\\Lib"), wincode.OWN_NAMES))
    assert [n for n, _ in wincode.own_names("C:\\Python311")] == ["C:\\pyvenv.cfg", "C:\\Modules\\Setup.local",
                                                                   "C:\\Lib"]   # nearer the root: the root
    assert [n for n, _ in wincode.own_names("C:\\")] == ["C:\\pyvenv.cfg", "C:\\Modules\\Setup.local", "C:\\Lib"]
    m = Machine()
    assert wincode.check(m) == (None, {"folders": 3, "files": 2, "above": 2}) and m.reads == MEASURED_READS


def test_m_exit_0_on_the_plain_road_says_its_counts(monkeypatch, capsys):
    code, out = through(monkeypatch, plain("venv"))
    assert code == 0 and capsys.readouterr().err == ""
    counts = dict(zip(PLAIN_COUNTS, EXPECTED_PLAIN["venv"]))
    assert out == "raqib service check: the code a service would run is the system's alone: %s\n" % (
        wincode.plain_words(counts, [("C:", MEASURED_C[1])]))
    assert out.endswith('; and the drive asked before any name of it was read, each said by the system to be of the'
                        ' fixed kind with a device\'s name of the form \\Device\\HarddiskVolumeN:'
                        ' C: "\\Device\\HarddiskVolume3"\n')
    for piece in ("checked 19 names", "6 entries of its path and the raqib package's folder, whole, 11 folders and 7"
                  " files", "(the creator's own inherit-only entry apart)", "1 of those entries not there",
                  "0 *.pth files read, 0 of their lines walked as entries, none of their lines taken or run by the"
                  " check", "and 1 folders above them to the drive's letter", "in the entries that apply to the folder"
                  " itself", "and besides those 19 names, 2 folders judged themselves only"):
        assert piece in out, piece
    assert "nothing of them run" not in out


def test_n3_each_number_of_the_pass_on_a_tree_where_none_is_zero():
    vsite = VENV + "\\Lib\\site-packages"
    m = plain("venv", base_exec_prefix=MODULES, path=road("venv")[1]["path"] + [COPY + "\\Lib\\os.py\\sub"],
              names={vsite + "\\x.pth": GOOD_PTH, COPY + "\\Lib\\os.py\\sub": OSError(3, "path not found")},
              lists={vsite: ["raqib", "x.pth"]}, files={vsite + "\\x.pth": b"import os\nsub\n"})
    bad, counts = wincode.check(m)
    assert bad is None and tuple(counts[k] for k in PLAIN_COUNTS) == (13, 9, 2, 2, 8, 2, 1, 6, 1, 1, 1, 1, 1), counts
    assert all(counts.values())
    words = wincode.plain_words(counts)
    for piece in ("checked 24 names", "under the interpreter's folder, its base's, its prefix, base prefix and one"
                  " exec prefix apart from them, 8 entries of its path and the raqib package's folder, whole, 13"
                  " folders and 9 files,", "; 2 of those entries not there, each judged by the deepest folder of it"
                  " that is there, itself only, and 1 beneath a file, each judged by that file; 6 names the"
                  " interpreter itself looks for at every start for its folder, its base's (pyvenv.cfg in the folder"
                  " above it, Modules\\Setup.local and Lib two folders above it), each judged as an entry is, 1 of"
                  " them there; 1 *.pth files read, 1 of their lines walked as entries, none of their lines taken or"
                  " run by the check; and 2 folders above them", "; and besides those 24 names, 2 folders judged"
                  " themselves only, as the code itself"):
        assert piece in words, piece
    assert 24 == counts["folders"] + counts["files"] + counts["above"]
    words = wincode.plain_words(dict(counts, base=0, exec=0))   # no base walked: its base's is not said
    assert "its base's" not in words and "its prefix and base prefix (its exec prefixes among them)," in words
    assert "two exec prefixes apart from them" in wincode.plain_words(dict(counts, exec=2))


@pytest.mark.parametrize("which, said", [
    ("program", "the interpreter's path"), ("prefix", "the interpreter's prefix"),
    ("base_prefix", "the interpreter's base prefix"), ("exec_prefix", "the interpreter's exec prefix"),
    ("base_exec_prefix", "the interpreter's base exec prefix")])
@pytest.mark.parametrize("value", [None, 7, b"C:\\x"])
def test_n3_a_program_or_a_prefix_not_named_or_not_a_string_is_refused_never_skipped(which, said, value):
    m = plain(**{which: value})
    bad = refused(m)
    own = "is not named (None): only the base executable may be unnamed" if value is None else "is not a string ("
    assert bad[1].startswith("%s %s" % (said, own)) and wincode.NOT_READ in bad[1] and m.reads == [], bad


def test_n3_only_the_base_executable_may_be_unnamed_and_its_base_is_said_only_where_walked():
    bad, counts = wincode.check(plain(base=None))
    assert bad is None and counts["base"] == 0 and "its base's" not in wincode.plain_words(counts)
    bad, counts = wincode.check(plain())                # the copy: its base in its own folder, walked as itself
    assert bad is None and counts["base"] == 0
    bad, counts = wincode.check(plain("venv"))
    assert bad is None and counts["base"] == 1 and ", its base's, " in wincode.plain_words(counts)
    assert refused(plain(base=7))[1].startswith("the base executable's path is not a string (7)")


def test_n3_the_exec_prefixes_equal_are_one_walk_different_are_roots_and_refused_where_refused():
    bad, counts = wincode.check(plain())
    m = plain(exec_prefix=COPY.upper(), base_exec_prefix=COPY.lower())   # equal without case: one walk
    assert wincode.check(m) == (bad, counts) and counts["exec"] == 0 and len(m.reads) == 18
    bad = refused(plain(exec_prefix="C:\\ProgramData\\Raqib"))
    assert bad[0] == "C:\\ProgramData" and bad[1].startswith(wincode.ROLE_ABOVE) and "0x10, 0x100:" in bad[1]
    bad = refused(plain(base_exec_prefix=COPY + "\\later"))   # a root must be there
    assert bad[0] == COPY + "\\later" and "not read" in bad[1]
    bad, counts = wincode.check(plain(base_exec_prefix=MODULES))   # the packed tree's measured folder: taken
    assert bad is None and counts["exec"] == 1


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


GOOD_PTH = reading(COPY_AT + "\\Lib\\os.py")
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
    assert m.events.index(("read", SITE + "\\x.pth")) < m.events.index(("bytes", SITE + "\\x.pth"))   # judged, then read
    assert ntpath.normcase(SITE + "\\lib") in [ntpath.normcase(r) for r in m.reads]   # the line, not there, judged by
    # its deepest folder (the site)


def test_m4_a_pth_line_that_leads_outside_is_refused_there_its_file_said():
    bad = refused(with_pth(b"..\\..\\..\\..\\..\\Users\\user\n"))   # five up: the tree is one folder deeper
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
    (b"x\n", (0x10, reading(COPY_AT + "\\Lib\\site-packages")[1]), "a *.pth name that is not a file as read"),
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
    stand_in = reading(COPY_AT)   # not measured: the two folders above GitHub's Python, given a folder's taken list
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
    assert bad is None and counts["folders"] == 7 and m.reads[-1] == MODULES + "\\raqib"
    assert counts["above"] == 3 and counts["alone"] == 2   # C:\, RaqibProbe8, _internal; Program Files and RIG alone


def test_m2_an_entry_that_is_a_file_is_judged_as_itself():
    rows, given = road("copy")
    bad, counts = wincode.check(plain(path=given["path"] + [PROGRAM]))   # the packed program, measured: taken
    assert bad is None and counts["files"] == 6 and counts["above"] == 2 and counts["entries"] == 6   # C:\, its folder
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
    assert said in bad[1] and len(m.reads) == 17, bad   # the roots (3 above, 11 under the copy), N-1's 3; no entry
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
    m = plain(path=given["path"] + [COPY.upper() + "\\LIB", "c:\\program files\\rig\\raqibprobe9py\\lib\\SITE-PACKAGES"])
    bad, counts = wincode.check(m)
    assert bad is None and counts["entries"] == 5 and len(m.reads) == 18   # met again, never read again (RIG, N-1's 3)
    monkeypatch.setattr(wincode, "WALK_MAX", 10)
    m = plain()
    bad, counts = wincode.check(m)
    assert bad[1] == "more than 10 names to walk (WALK_MAX): a walk that is not whole is not a pass"
    assert sum(counts[k] for k in ("folders", "files", "above", "alone")) == 10 and len(m.reads) == 10


def test_m_the_real_system_objects_answers_are_the_running_interpreters(tmp_path):
    import raqib
    s = wincode.System()
    assert s.isolated() is bool(sys.flags.isolated) and s.no_site() is bool(sys.flags.no_site)
    assert s.base_executable() == getattr(sys, "_base_executable", None) and s.sys_path() == list(sys.path)
    assert s.prefix() == sys.prefix and s.base_prefix() == sys.base_prefix
    assert s.exec_prefix() == sys.exec_prefix and s.base_exec_prefix() == sys.base_exec_prefix
    assert s.version() == tuple(sys.version_info[:2]) and len(s.version()) == 2
    assert s.package_dir() == ntpath.dirname(raqib.__file__) and Path(s.package_dir()) == Path(raqib.__file__).parent
    f = tmp_path / "x.pth"
    f.write_bytes(b"0123456789")
    assert s.read_bytes(str(f), 4) == b"01234" and s.read_bytes(str(f), 100) == b"0123456789"


# --- M12.4c2a (ADR-0013 Amendment P, P-1): the drive a path is on, asked before any name of it is read -------------
# The readings are the measured ones above (MEASURED_C, FOLDER_LETTER, NOT_THERE_LETTER, DRIVE_ROWS: drives.txt) or
# invented here, said so.
def drive_head(letter):
    return "the drive %s, asked before any name of it is read (ADR-0013 P-1, Q-1): " % letter


def other_form(name):   # Q-2: the words of a fixed drive whose device's name is not of Q-1's form
    return ('the system says kind 3 (fixed) and names its device "%s", a device\'s name not of the form asked for'
            " (\\Device\\HarddiskVolumeN, N one or more of the digits 0-9, and nothing after it); %s" % (
                wincode._said(name), wincode.DRIVE_ONLY))


@pytest.mark.parametrize("name", [
    "\\Device\\HarddiskVolume3\\Users\\someone\\Rig",   # the review's finding 1, exactly
    "\\Device\\HarddiskVolume3\\", "\\Device\\HarddiskVolume3 ", "\\Device\\HarddiskVolume3\n",
    "\\device\\harddiskvolume3", "\\DEVICE\\HARDDISKVOLUME3", "\\Device\\HarddiskVolume",
    "\\Device\\HarddiskVolume\u0663", "\\Device\\HarddiskVolume\uff13", "\\Device\\HarddiskVolume3\u0663",
    "\\Device\\HarddiskDmVolumes\\x\\Volume1", "\\Device\\LanmanRedirector\\x", "\\??\\C:\\ProgramData",
    "x\\Device\\HarddiskVolume3", " \\Device\\HarddiskVolume3", "\\??\\\\Device\\HarddiskVolume3", "",
])
def test_q1_a_device_name_not_whole_of_the_form_measured_is_refused_with_the_name_and_the_form(name):
    m = Machine(drives={"C:": (3, name)})   # each of the fixed kind; invented but the folder's (drives.txt)
    bad, counts = wincode.check(m)
    assert bad == ("C:\\", drive_head("C:") + other_form(name)) and bad[1].isprintable()
    assert m.reads == [] and m.listed == [] and sum(counts.values()) == 0 and m.drives_asked == ["C:\\"]
    assert "first met" not in bad[1] and "share" not in bad[1]


def test_q1_the_form_is_one_pattern_matched_whole_with_its_case():
    assert wincode.DISK_DEVICE.pattern == r"\\Device\\HarddiskVolume[0-9]+" and wincode.DISK_FORM == \
        "\\Device\\HarddiskVolumeN" and not wincode.DISK_DEVICE.flags & re.IGNORECASE
    source = (ROOT / "raqib" / "wincode.py").read_text(encoding="utf-8")
    assert source.count("HarddiskVolume[0-9]+") == 1 and source.count("DISK_DEVICE.") == 1 and \
        "DISK_DEVICE.fullmatch(name)" in source


def test_q1_every_disks_line_of_drives_txt_is_taken_and_every_other_line_refused():
    taken, refused_lines = [], []
    for section, rows in sorted(DRIVE_ROWS.items()):
        for letter, what, kind, name in rows:
            disk = "disk" in what and "letter" not in what   # what it was, as the fixture says it
            got = name if isinstance(name, BaseException) else (kind, name)
            bad = wincode.drive_refused(letter, got)
            m = Machine(drives={"C:": got})                   # the line's reading given as the walk's own drive's
            walked, counts = wincode.check(m, [])
            if disk:
                taken.append((section, letter, what))
                assert bad is None and walked is None and m.reads == MEASURED_READS, (section, letter, what)
            else:
                refused_lines.append((section, letter, what))
                assert bad[0] == letter + "\\" and walked == ("C:\\", drive_head("C:") + bad[1][len(
                    drive_head(letter)):]) and m.reads == [] and sum(counts.values()) == 0, (section, letter, what)
                assert "first met" not in bad[1] and "share" not in bad[1]
    assert sorted(DRIVE_ROWS) == ["arm64", "x64"] and len(taken) == 7 and len(refused_lines) == 7
    assert [w for _, _, w in taken].count("the system's disk") == 2


def test_p1_the_measured_c_is_asked_once_before_any_name_of_it_and_said_in_the_pass(monkeypatch, capsys):
    m = Machine()
    drives = []
    assert wincode.check(m, drives) == (None, {"folders": 3, "files": 2, "above": 2})
    assert m.drives_asked == ["C:\\"] and m.events[0] == ("drive", "C:\\") and drives == [("C:", MEASURED_C[1])]
    assert m.reads == MEASURED_READS   # the drive asked; the names read as before
    m = plain("venv")
    assert wincode.check(m)[0] is None and m.drives_asked == ["C:\\"] and m.events[0] == ("drive", "C:\\")
    code, out = through(monkeypatch, Machine())
    assert code == 0 and out.endswith(': C: "\\Device\\HarddiskVolume3"\n') and "to the drive's letter" in out
    assert wincode.drive_refused("C:", MEASURED_C) is None and MEASURED_C == (3, "\\Device\\HarddiskVolume3")


def test_p1_a_letter_given_to_a_folder_is_refused_with_its_kind_and_device_and_nothing_of_it_read(monkeypatch):
    m = Machine(drives={"C:": FOLDER_LETTER})
    bad, counts = wincode.check(m)
    assert bad == ("C:\\", drive_head("C:") + other_form("\\??\\C:\\ProgramData")) and FOLDER_LETTER[0] == 3
    assert m.reads == [] and m.listed == [] and sum(counts.values()) == 0
    code, out = through(monkeypatch, Machine(drives={"C:": FOLDER_LETTER}))
    assert code == 1 and out.startswith("raqib service check: NOT the system's alone: C:\\, the drive C:, asked"
                                        " before")


@pytest.mark.parametrize("kind, word", [(0, "unknown"), (1, "no root"), (2, "removable"), (4, "remote"),
                                        (5, "a disc"), (6, "a RAM disk"), (7, "a number this check knows no word"),
                                        (-1, "a number this check knows no word")])
def test_p1_every_kind_but_the_fixed_is_refused_with_its_word(kind, word):
    m = Machine(drives={"C:": (kind, "\\Device\\HarddiskVolume3")})   # invented: a disk's name, another kind
    bad, _ = wincode.check(m)
    assert bad[0] == "C:\\" and bad[1].startswith(drive_head("C:") + "the system says kind %d (%s" % (
        kind, word)) and bad[1].endswith(' and names its device "\\Device\\HarddiskVolume3": not the fixed kind; '
                                         + wincode.DRIVE_ONLY)
    assert m.reads == []
    assert wincode.DRIVE_KINDS == {0: "unknown", 1: "no root", 2: "removable", 3: "fixed", 4: "remote", 5: "a disc",
                                   6: "a RAM disk"}


def test_p1_a_device_name_not_read_is_refused_with_the_systems_number():
    m = Machine(drives={"C:": NOT_THERE_LETTER})
    bad, _ = wincode.check(m)
    assert bad == ("C:\\", drive_head("C:") + "its device's name was not read (the device's name of Q: was"
                   " not read (the drive's kind 1) (error 2)); %s; %s" % (wincode.DRIVE_ONLY, wincode.NOT_READ))
    assert m.reads == []
    bad, _ = wincode.check(Machine(drives={"C:": ValueError("not a drive's root")}))
    assert "its device's name was not read (not a drive's root)" in bad[1]


@pytest.mark.parametrize("got, said", [
    ((3, ""), 'the system says kind 3 (fixed) and names its device "", a device\'s name not of the form asked for'),
    ((3, None), "a kind or a device's name of a type the check does not know (kind 3, device's name None): not read"),
    ((3, b"\\Device\\HarddiskVolume3"), "of a type the check does not know (kind 3, device's name b'"),
    (("3", "\\Device\\HarddiskVolume3"), "of a type the check does not know (kind '3', device's name"),
    ((True, "\\Device\\HarddiskVolume3"), "of a type the check does not know (kind True, device's name"),
    ((3.0, "\\Device\\HarddiskVolume3"), "of a type the check does not know (kind 3.0, device's name"),
    ((3,), "the system's answer is not a kind and a device's name ((3,)): not read"),
    ("\\Device\\HarddiskVolume3", "the system's answer is not a kind and a device's name ('"),
    (None, "the system's answer is not a kind and a device's name (None): not read"),
    ((3, "\\device\\HarddiskVolume3"), 'names its device "\\device\\HarddiskVolume3", a device\'s name not of the'),
])
def test_p1_a_name_or_kind_not_known_is_refused_unread(got, said):   # invented readings, each refused
    m = Machine(drives={"C:": got})
    bad, _ = wincode.check(m)
    if isinstance(got, tuple) and len(got) == 2 and got[0] == 3 and type(got[0]) is int and isinstance(got[1], str):
        assert said in bad[1] and wincode.DRIVE_ONLY in bad[1]
    else:
        assert said in bad[1] and bad[1].endswith(wincode.NOT_READ), bad
    assert bad[0] == "C:\\" and m.reads == [] and bad[1].isprintable()


def second_disk(**kw):
    """The copy's road with the raqib package on a second drive E: (stand-ins: E:\\ reads as the measured C:\\, a
    folder above; E:\\Rig and its raqib folder as the copy's own folder)."""
    names = {"E:\\": reading_c(), "E:\\Rig": reading(COPY_AT), "E:\\Rig\\raqib": reading(COPY_AT)}
    return plain(package="E:\\Rig\\raqib", names=names, lists={"E:\\Rig\\raqib": []}, **kw)


def reading_c():
    (got,) = [(a, t) for p, a, t, _ in measured()["x64"] if p == "C:\\"]
    return got


def test_p1_a_second_drive_that_is_a_folders_letter_is_refused_after_the_walks_earlier_names():
    m = second_disk(drives={"E:": (3, "\\??\\C:\\Program Files\\Rig")})   # invented: a letter given to a folder
    rows, given = road("copy")
    bad, _ = wincode.check(m)
    assert bad[0] == "E:\\" and bad[1].startswith(drive_head("E:")) and \
        'names its device "\\??\\C:\\Program Files\\Rig"' in bad[1]
    assert m.drives_asked == ["C:\\", "E:\\"] and not [r for r in m.reads if r.upper().startswith("E:")]
    assert ntpath.normcase(given["path"][-1]) in [ntpath.normcase(r) for r in m.reads]   # the walk's earlier names
    m = plain(path=road("copy")[1]["path"] + ["E:\\x"], drives={"E:": FOLDER_LETTER})   # an entry on it
    bad = refused(m)
    assert bad[0] == "E:\\" and bad[1].startswith(drive_head("E:")) and m.drives_asked == ["C:\\", "E:\\"]
    assert not [r for r in m.reads if r.upper().startswith("E:")]
    reads = [ntpath.normcase(r) for r in m.reads]   # Q-4: the walk's earlier names were read, the entries before E:
    assert all(ntpath.normcase(e) in reads for e in road("copy")[1]["path"]) and ntpath.normcase(COPY) in reads
    m = plain(path=["Q:\\x"], drives={"Q:": NOT_THERE_LETTER})   # measured: a letter that is not there
    bad = refused(m)
    assert bad[0] == "Q:\\" and "(the drive's kind 1) (error 2)" in bad[1] and bad[1].startswith(drive_head("Q:"))
    assert not [r for r in m.reads if r.upper().startswith("Q:")]


def test_p1_a_second_drive_that_is_a_disk_is_asked_once_and_said_in_the_pass(monkeypatch, capsys):
    m = second_disk()
    drives = []
    bad, counts = wincode.check(m, drives)
    assert bad is None and m.drives_asked == ["C:\\", "E:\\"] and drives == [("C:", MEASURED_C[1]),
                                                                            ("E:", DISK_STAND_IN[1])]
    assert m.events.index(("drive", "E:\\")) < m.events.index(("read", "E:\\"))
    code, out = through(monkeypatch, second_disk())
    assert code == 0 and out.endswith('; and the drives asked before any name of them was read, each said by the'
                                      ' system to be of the fixed kind with a device\'s name of the form'
                                      ' \\Device\\HarddiskVolumeN:'
                                      ' C: "\\Device\\HarddiskVolume3", E: "\\Device\\HarddiskVolume1"\n')
    assert check_counts().search(out)
    # Q-1: a device's name with more after a volume's is not taken; it is said made printable (invented)
    m = second_disk(drives={"E:": (3, "\\Device\\HarddiskVolume5\x1b[2J")})
    code, out = through(monkeypatch, m)
    assert code == 1 and 'names its device "\\Device\\HarddiskVolume5?[2J", a device\'s name not of the form' in out
    assert "\x1b" not in out and wincode.DISK_DEVICE.fullmatch(DISK_STAND_IN[1])   # the stand-in is of the form


def check_counts():
    sys.path.insert(0, str(ROOT / "tools" / "rig"))
    import check
    return check.CHECK_PLAIN_COUNTS


def test_p1_the_same_drive_in_two_letter_cases_is_asked_once(monkeypatch):
    met, drive = [], wincode._Walk._drive

    def recorded(self, path):   # what _Walk._drive itself is given, then the walk's own _drive
        met.append(path)
        return drive(self, path)
    monkeypatch.setattr(wincode._Walk, "_drive", recorded)
    entry = COPY.lower() + "\\new\\x"   # a stand-in entry, not there, on c:, in a folder the walk did not read before
    m = plain(path=road("copy")[1]["path"] + [entry])
    drives = []
    assert wincode.check(m, drives)[0] is None and drives == [("C:", MEASURED_C[1])]
    assert ntpath.dirname(entry) in met and [p for p in met if p.startswith("C:")]   # both cases reach _drive
    assert m.drives_asked == ["C:\\"]   # and the system was asked once: the letter is folded (Q-4)


def test_p1_the_real_system_object_asks_winservices_reader_of_a_drive(monkeypatch):
    got = []

    class Reader:
        def read_drive(self, root):
            got.append(root)
            return MEASURED_C
    monkeypatch.setattr(winservice, "System", Reader)
    s = wincode.System()
    assert s.drive("C:\\") == MEASURED_C and s.drive("D:\\") and got == ["C:\\", "D:\\"]


class Buffers:
    """A stand-in for ctypes' few names read_drive uses: the real unicode buffer, a last error given."""

    def __init__(self, error):
        import ctypes
        self.create_unicode_buffer, self.error = ctypes.create_unicode_buffer, error

    def get_last_error(self):
        return self.error


class Kernel:
    """A stand-in kernel32: the kind given, and the device's names written as the system writes them."""

    def __init__(self, kind, names):
        self.kind, self.names, self.asked = kind, names, []

    def GetDriveTypeW(self, root):
        self.asked.append(("kind", root))
        return self.kind

    def QueryDosDeviceW(self, letter, buffer, bound):
        self.asked.append(("device", letter, bound))
        if self.names is None:
            return 0
        buffer[:len(self.names)] = self.names
        return len(self.names)


def test_p1_read_drive_gives_the_kind_and_the_first_name_or_the_systems_error():
    from types import SimpleNamespace
    s = winservice.System()
    k = Kernel(3, "\\Device\\HarddiskVolume3\0\\Device\\Other\0\0")   # invented: a list of two names
    s._api = SimpleNamespace(ctypes=Buffers(0), k32=k)
    assert s.read_drive("C:\\") == (3, "\\Device\\HarddiskVolume3")
    assert k.asked == [("kind", "C:\\"), ("device", "C:", 1024)]
    s._api = SimpleNamespace(ctypes=Buffers(2), k32=Kernel(1, None))
    with pytest.raises(OSError) as e:
        s.read_drive("Q:\\")
    assert e.value.errno == 2 and "(the drive's kind 1)" in str(e.value)
    assert e.value.args == NOT_THERE_LETTER.args   # the reader's own words, of drives.txt's Q: (kind 1, error 2)
    for root in ("C:", "C:\\x", "\\\\?\\C:\\", "1:\\", None, b"C:\\", "\u00e9:\\"):
        s._api = SimpleNamespace(ctypes=Buffers(0), k32=Kernel(3, "\\Device\\X\0\0"))
        with pytest.raises(ValueError):
            s.read_drive(root)
        assert s._api.k32.asked == []   # refused before any call


@pytest.mark.skipif(sys.platform != "win32", reason="the real reader of a drive is Windows' (winservice.System."
                                                    "read_drive); measured on GitHub's x64 and ARM64 (Amendment P)")
def test_p1_the_real_system_drive_reads_kind_3_and_a_disks_device():
    import os
    root = (os.environ.get("SystemDrive") or "C:") + "\\"
    kind, name = winservice.System().read_drive(root)
    assert kind == 3 and wincode.DISK_DEVICE.fullmatch(name), (kind, name)
    assert wincode.drive_refused(root[:2].upper(), (kind, name)) is None
