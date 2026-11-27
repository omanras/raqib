"""`raqib service check` (ADR-0013 Amendment K, K-1 to K-7; M12.4c1): on Windows, is the code a service would run
the system's alone?

A service of Windows runs as the system what its command names, so before anything installs one (M12.4c2) this
says whether that code can be changed, added to or taken from by anybody but the system - by the owners and access
lists Windows gives, as Amendment K measured them, and by nothing else.

The system's text of an owner and list ("O:BAD:PAI(A;OICI;FA;;;SY)...", as winservice.System.read_place gives it)
is read whole by read_list: the owner (two letters or a whole SID), then "D:", the list's flags (P, AI, AR), then
its entries `(kind;flags;rights;object;inherited object;name)`. The flags of an entry are two-letter words (OI CI NP
IO ID), its rights hex or two-letter words run together (RIGHTS), its name two letters or a whole SID; the same two
letters are read by their place. Anything else - no owner, no list, a null list, a part after the list, an entry
of another kind than A and D, with more or fewer than its six fields, an object field, a word not known - is not
read, and what is not read is refused.

The three names of the system (K-1, SYSTEM_NAMES): the system (SY), the administrators (BA), and the system's
installer by its whole SID. A name is judged in one of two roles:
- the code itself (K-2, as_code): no reparse point; its owner one of the three; its list there; and every allowing
  entry for another name holds nothing but CODE_ALLOWED (reading and executing), its inherit-only entries too, but
  for the creator's own (CREATOR_NAMES), taken only where it is inherit-only;
- a folder above (K-3, as_above): a folder and no reparse point; its owner one of the three; its list there; and
  every allowing entry for another name that is not inherit-only holds nothing but ABOVE_ALLOWED (K-2's bits and
  adding a thing beside: a file, a folder, extended attributes, attributes).
Denying entries give nothing and are not counted. Each answers None or the words of its refusal: the role, the
owner or the entry as read, and the bits that refuse in hex.

The walk (K-4, K-5, check): only packed with its own runtime (sys.frozen) on Windows. The root is the folder the
program file is in; the folder the runtime says its modules are in (sys._MEIPASS) must be in it. Each folder above,
from the drive down (top first), by K-3; then the root, whole, and every file and folder below it, by K-2; then the
modules' folder and the program, met again and not read twice. A name is read by winservice's one reader (K-7):
its kind is the reading's, never the listing's. A path not of the form `X:\\...` (a share, a device path, `..`, `/`,
a name Windows would read as another: a trailing dot or space, a device's name), a path longer than the system opens
plainly, a name not read, a folder not listed, two names of one folder that differ only in case, a walk past
WALK_MAX names, modules outside the program's folder, a plain interpreter: each refused with its own words. Names
are compared without case where a set of what was walked is kept; paths are made with ntpath, on any system.

Every call of the system (the platform, whether packed, the program's path, the modules' folder, the one read of a
name, a folder's listing) goes through one object, System; a test hands its own. Nothing runs at import; ctypes is
only in winservice's reader, declared at its first call. The standard library only; nothing is written; no right is
asked; no program is started; no network.
"""
from __future__ import annotations

import ntpath
import os
import re
import sys
from collections import namedtuple

from raqib import winservice
from raqib.service import WALK_MAX   # AC-2: the Linux number (K-4)

INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"   # TrustedInstaller, by its whole SID
SYSTEM_NAMES = ("SY", "S-1-5-18", "BA", "S-1-5-32-544", INSTALLER)   # K-1: the system's three names, either spelling
CREATOR_NAMES = ("CO", "S-1-3-0")   # the creator's own: taken as code only where inherit-only (K-2)
# The rights words, as the file system means them (tests/fixtures/wincode/measured.txt, its last lines)
RIGHTS = {"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
          "SD": 0x10000, "RC": 0x20000, "WD": 0x40000, "WO": 0x80000, "GA": 0x10000000, "GX": 0x20000000,
          "GW": 0x40000000, "GR": 0x80000000, "FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0}
# K-2: what the code itself may give a name outside the system's - a list of what is allowed; a bit not on it refuses
CODE_ALLOWED = ((0x1, "read the data, or list the folder"), (0x8, "read extended attributes"),
                (0x20, "execute, or pass through the folder"), (0x80, "read attributes"), (0x20000, "read the list"),
                (0x100000, "wait on it (synchronize)"), (0x80000000, "read (GR)"), (0x20000000, "execute (GX)"))
# K-3: what a folder above may give: K-2's bits and adding a thing beside (never deleting, renaming, the list, owner)
ABOVE_ALLOWED = CODE_ALLOWED + ((0x2, "add a file"), (0x4, "add a folder"), (0x10, "write extended attributes"),
                                (0x100, "write attributes"))
ENTRY_FLAGS = ("OI", "CI", "NP", "IO", "ID")   # IO: inherit-only
INHERIT_ONLY = "IO"
LIST_FLAGS = re.compile(r"(?:P|AI|AR)*\Z")
NULL_LIST = "NO_ACCESS_CONTROL"
KINDS = ("A", "D")              # allowing, denying: no other kind is judged
PLAIN_MAX = 259                 # characters of a path the system opens plainly (MAX_PATH, less its end)
SAID_MAX = 200                  # characters of a name or a text said; a cut is marked "..."
ROLE_CODE = "as the code itself (K-2)"
ROLE_ABOVE = "as a folder above it (K-3)"
CODE_MAY = "the code itself may give any other name only reading and executing"
ABOVE_MAY = "a folder above may give any other name only reading, executing and adding a thing beside"
NOT_READ = "what was not read is never the system's"
NOT_PACKED = ("not packed with its own runtime: a plain interpreter's roads (its folder, a venv's base, every entry"
              " of sys.path, the lines of *.pth files) are not yet checked (ADR-0013 K-5), so it is never said to be"
              " the system's alone")
DEVICE_NAMES = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9\u00b9\u00b2\u00b3]"
                          r"|LPT[0-9\u00b9\u00b2\u00b3])(?:\..*)?\Z", re.I)   # a device's name, any extension
NOT_IN_A_NAME = '\\/:*?"<>|'

Entry = namedtuple("Entry", "kind flags rights name text")
_OWNER = re.compile(r"O:(S-1-[0-9]+(?:-[0-9]+)+|[A-Z]{2})")
_NAME = re.compile(r"(?:S-1-[0-9]+(?:-[0-9]+)+|[A-Z]{2})\Z")
_HEX = re.compile(r"0[xX][0-9A-Fa-f]{1,8}\Z")
_WORDS = re.compile(r"(?:[A-Z]{2})+\Z")
_DRIVE = re.compile(r"[A-Za-z]:\\")


def _said(value, limit=SAID_MAX):
    """A name or a text as one line of printable text, cut at `limit` and the cut marked (AJ-3)."""
    text = "".join(c if c.isprintable() else "?" for c in str(value))
    return text if len(text) <= limit else text[:limit] + "..."


def _bits(number):
    return ", ".join("0x%x" % (1 << k) for k in range(32) if number >> k & 1)


def _mask(allowed):
    out = 0
    for bit, _ in allowed:
        out |= bit
    return out


# --- E1 (K-1, K-2, K-3): the text read, and the two roles ---------------------------------------------------------

def _rights(text):
    if _HEX.match(text):
        return int(text, 16)
    if not _WORDS.match(text):
        return None
    words = [text[k:k + 2] for k in range(0, len(text), 2)]
    if any(w not in RIGHTS for w in words):
        return None
    out = 0
    for w in words:
        out |= RIGHTS[w]
    return out


def _entry(text):
    """(Entry, None) of one entry's text "(...)", or (None, why)."""
    inner = text[1:-1]
    kind = inner.split(";", 1)[0]
    if kind not in KINDS:
        return None, "an entry of a kind not judged (%s): %s" % (_said(kind, 20), _said(text))
    if "(" in inner or ")" in inner:
        return None, "an entry holding more than its six fields: %s" % _said(text)
    fields = inner.split(";")
    if len(fields) != 6:
        return None, "an entry of %d fields, not six: %s" % (len(fields), _said(text))
    _, flags, rights, obj, inherited, name = fields
    if obj or inherited:
        return None, "an entry whose object or inherited-object field is not empty: %s" % _said(text)
    words = [flags[k:k + 2] for k in range(0, len(flags), 2)]
    if len(flags) % 2 or any(w not in ENTRY_FLAGS for w in words):
        return None, "an entry whose flags are not known (%s): %s" % (_said(flags, 40), _said(text))
    number = _rights(rights)
    if number is None:
        return None, "an entry whose rights are not read (a word this Raqib does not know): %s" % _said(text)
    if not _NAME.match(name):
        return None, "an entry whose name is not read: %s" % _said(text)
    return Entry(kind, tuple(words), number, name, text), None


def _close(text, start):
    """The index of the ")" that closes the "(" at `start`, or -1."""
    depth = 0
    for k in range(start, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def read_list(text):
    """E1 (K-1, K-2): the system's text of an owner and list, "O:...D:...", read whole: (owner, entries, None), the
    entries a list of Entry (kind, flags as a tuple of words, rights as a number, name, the entry's text); or (None,
    None, why) where any part of it is not read."""
    if not isinstance(text, str):
        return None, None, "no text of an owner and list was given"
    found = _OWNER.match(text)
    if not found:
        return None, None, "no owner at its start: %s" % _said(text)
    owner, rest = found.group(1), text[found.end():]
    if not rest:
        return None, None, "no list (no D: part): %s" % _said(text)
    if not rest.startswith("D:"):
        return None, None, "after the owner %s, %s where the list (D:) should be" % (owner, _said(rest, 40))
    body = rest[2:]
    if NULL_LIST in body:
        return None, None, "a null list (%s): it gives every name everything" % NULL_LIST
    at = body.find("(")
    at = len(body) if at < 0 else at
    if not LIST_FLAGS.match(body[:at]):
        return None, None, "the list's flags are not known (%s)" % _said(body[:at], 40)
    entries = []
    while at < len(body):
        if body[at] != "(":
            return None, None, "%s where an entry should begin" % _said(body[at:], 40)
        end = _close(body, at)
        if end < 0:
            return None, None, "an entry that is not closed: %s" % _said(body[at:])
        entry, why = _entry(body[at:end + 1])
        if why:
            return None, None, why
        entries.append(entry)
        at = end + 1
    return owner, entries, None


def _judge(attributes, text, role):
    code = role == ROLE_CODE
    if isinstance(attributes, bool) or not isinstance(attributes, int) or attributes < 0:
        return "%s: its attributes are not read (%s)" % (role, _said(attributes, 40))
    if attributes & winservice.ATTRIBUTE_REPARSE:
        return "%s: a reparse point (attributes 0x%x): it is judged as itself, and what it points to is not read" % (
            role, attributes)
    if not code and not attributes & winservice.ATTRIBUTE_FOLDER:
        return "%s: not a folder (attributes 0x%x)" % (role, attributes)
    owner, entries, why = read_list(text)
    if why:
        return "%s: its owner and list are not read whole: %s" % (role, why)
    if owner not in SYSTEM_NAMES:
        return "%s: owned by %s, not the system (SY), the administrators (BA) or the system's installer" % (
            role, _said(owner))
    allowed = _mask(CODE_ALLOWED if code else ABOVE_ALLOWED)
    for e in entries:
        if e.kind != "A" or e.name in SYSTEM_NAMES:
            continue
        inherit_only = INHERIT_ONLY in e.flags
        if not code and inherit_only:
            continue        # K-3: what a folder on the way gives to new things beside the code is not the code
        if code and e.name in CREATOR_NAMES:
            if inherit_only:
                continue
            return "%s: the creator's entry %s is not inherit-only" % (role, _said(e.text))
        extra = e.rights & ~allowed
        if extra:
            return "%s: the entry %s gives %s, a name outside the system's, %s: not allowed (%s)" % (
                role, _said(e.text), _said(e.name), _bits(extra), CODE_MAY if code else ABOVE_MAY)
    return None


def as_code(attributes, text):
    """E1 (K-2): None where a file or folder so read is taken as the code itself; else the words of the refusal."""
    return _judge(attributes, text, ROLE_CODE)


def as_above(attributes, text):
    """E1 (K-3): None where a folder so read is taken as a folder above the code; else the words of the refusal."""
    return _judge(attributes, text, ROLE_ABOVE)


# --- E2 (K-4, K-5, K-7): the walk ---------------------------------------------------------------------------------

def _part_refused(part):
    if part in ("", ".", ".."):
        return "an empty part, . or .."
    if any(c in NOT_IN_A_NAME or not c.isprintable() for c in part):
        return "a character no name of Windows holds"
    if part.endswith((".", " ")):
        return "a name ending in a dot or a space (Windows would open another)"
    if DEVICE_NAMES.match(part):
        return "a device's name (Windows would open the device)"
    return None


def path_refused(path):
    """K-4: None where `path` is a whole path of a drive (X:\\ and plain names); else why not."""
    if not isinstance(path, str) or not path:
        return "is not said"
    if not _DRIVE.match(path):
        return "%s does not begin with a drive's letter (X:\\): a share, a device path or another form" % _said(path)
    if len(path) > PLAIN_MAX:
        return "%s is %d characters, longer than the system opens plainly (%d)" % (_said(path), len(path), PLAIN_MAX)
    if path[3:]:
        for part in path[3:].split("\\"):
            why = _part_refused(part)
            if why:
                return "%s is not a whole path of a drive: %s" % (_said(path), why)
    return None


def _within(path, root):
    p, r = ntpath.normcase(path), ntpath.normcase(root)
    return p == r or p.startswith(r.rstrip("\\") + "\\")


def _above(path):
    """The folders above `path`, the drive's own first."""
    out = []
    here = path
    while True:
        up = ntpath.dirname(here)
        if up == here:
            break
        out.append(up)
        here = up
    return out[::-1]


def _why(exc):
    number = exc.errno if getattr(exc, "errno", None) is not None else getattr(exc, "winerror", None)
    words = getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
    return "%s%s" % (_said(words, 80), " (error %s)" % number if number is not None else "")


class _Walk:
    """E2: one walk, each name read once (names compared without case), counted by kind and role."""

    def __init__(self, system):
        self.system, self.code, self.above, self.walked = system, set(), set(), 0
        self.counts = {"folders": 0, "files": 0, "above": 0}

    def _read(self, path, role):
        """(bad, attributes): bad the refusal (name, words) of one name in one role, or None."""
        self.walked += 1
        if self.walked > WALK_MAX:
            return (_said(path), "more than %d names to walk (WALK_MAX): a walk that is not whole is not a pass"
                    % WALK_MAX), None
        if len(path) > PLAIN_MAX:
            return (_said(path), "%s: not read: %d characters, longer than the system opens plainly (%d); %s" % (
                role, len(path), PLAIN_MAX, NOT_READ)), None
        try:
            attributes, text = self.system.read(path)
        except (OSError, ValueError) as exc:
            return (_said(path), "%s: not read (%s); %s" % (role, _why(exc), NOT_READ)), None
        why = _judge(attributes, text, role)
        return ((_said(path), why) if why else None), attributes

    def folder_above(self, path):
        key = ntpath.normcase(path)
        if key in self.code or key in self.above:   # judged already, as itself (K-2 holds K-3's bits) or above
            return None
        self.above.add(key)
        bad, _ = self._read(path, ROLE_ABOVE)
        if bad is None:
            self.counts["above"] += 1
        return bad

    def whole(self, top, folder):
        """The refusal (name, words) or None: `top` and, where it reads as a folder, everything below it, whole."""
        todo = [top]
        while todo:
            path = todo.pop(0)
            key = ntpath.normcase(path)
            if key in self.code:
                continue
            self.code.add(key)
            bad, attributes = self._read(path, ROLE_CODE)
            if bad:
                return bad
            if not attributes & winservice.ATTRIBUTE_FOLDER:
                if folder and path is top:
                    return _said(path), "%s: the program's folder is not a folder as read (attributes 0x%x)" % (
                        ROLE_CODE, attributes)
                self.counts["files"] += 1
                continue
            self.counts["folders"] += 1
            try:
                names = list(self.system.listdir(path))
            except (OSError, ValueError) as exc:
                return _said(path), "%s: a folder that cannot be listed (%s); %s" % (ROLE_CODE, _why(exc), NOT_READ)
            met = set()
            for name in names:
                why = _part_refused(name) if isinstance(name, str) else "no name"
                if why:
                    return _said(path), "%s: its listing gives %s, %s: not read; %s" % (
                        ROLE_CODE, _said(repr(name), 80), why, NOT_READ)
                if ntpath.normcase(name) in met:
                    return _said(ntpath.join(path, name)), (
                        "%s: two names of this folder differ only in case (a folder that tells case apart): which"
                        " one would run is not known; %s" % (ROLE_CODE, NOT_READ))
                met.add(ntpath.normcase(name))
                todo.append(ntpath.join(path, name))
        return None


def check(system):
    """E2 (K-4, K-5): (bad, counts). bad is (name, words) of the first name refused - or of the program, where it is
    not Windows' or not packed - or None where the code a service would run is the system's alone; counts says what
    was walked: folders and files below the program's folder (K-2), folders above it (K-3). Nothing is written."""
    walk = _Walk(system)

    def done(bad):
        return bad, dict(walk.counts)
    platform, program = system.platform(), system.program()
    if platform != "win32":
        return done((_said(program), not_windows(platform)))
    if not system.packed():
        return done((_said(program), NOT_PACKED))
    why = path_refused(program)
    if why:
        return done((_said(program), "the program's path %s" % why))
    root, modules = ntpath.dirname(program), system.modules()
    if modules is None:
        return done((_said(root), "the packed runtime does not say where its modules are (sys._MEIPASS): what would"
                                  " run is not known to be there to be read"))
    why = path_refused(modules)
    if why:
        return done((_said(modules), "the modules' path %s" % why))
    if not _within(modules, root):
        return done((_said(modules), "the runtime says its modules are here, outside the program's folder %s (a"
                                     " one-file packing unpacks into a temporary folder at each start): what would"
                                     " run is not there to be read" % _said(root)))
    for top, folder in ((root, True), (modules, True), (program, False)):
        for up in _above(top):
            bad = walk.folder_above(up)
            if bad:
                return done(bad)
        bad = walk.whole(top, folder)
        if bad:
            return done(bad)
    return done(None)


def checked_words(counts):
    """K-6 (service.checked_words' twin): what the check walked, by count (never a sentence without them)."""
    total = counts["folders"] + counts["files"] + counts["above"]
    return ("checked %d names, each the system's alone (its owner the system, the administrators or the system's"
            " installer, no reparse point, its list there): under the program's folder, whole, %d folders and %d"
            " files, each giving any other name only reading and executing, and %d folders above it to the drive,"
            " each giving any other name only that and adding a thing beside" % (
                total, counts["folders"], counts["files"], counts["above"]))


def not_windows(platform):
    return "Windows only (it reads the owners and lists of Windows); this is %s" % _said(platform, 40)


class System:
    """Every call the check makes of the system, here alone (a test hands an object of its own). The one read of a
    name is winservice's (K-7)."""

    def __init__(self):
        self._reader = None

    def platform(self):
        return sys.platform

    def packed(self):
        return bool(getattr(sys, "frozen", False))

    def program(self):
        return sys.executable

    def modules(self):
        return getattr(sys, "_MEIPASS", None)

    def read(self, path):
        if self._reader is None:
            self._reader = winservice.System()
        return self._reader.read_place(path)

    def listdir(self, path):
        return os.listdir(path)


# --- E3 (K-6): the command ----------------------------------------------------------------------------------------

def _say(text):
    try:
        sys.stderr.write("raqib: %s\n" % text)
        sys.stderr.flush()
    except Exception:
        pass


def cli_check(args, out, system=None):
    """`raqib service check` from raqib/cli.py (its only importer): exit 0 the system's alone (what was walked, by
    count), 1 not, or not read (the name, its role and why), 2 not Windows or not packed (on the error stream)."""
    system = system or System()
    platform = system.platform()
    if platform != "win32":
        _say("raqib service check: %s" % not_windows(platform))
        return 2
    for flag, owner in (("no_start", "install"), ("purge", "remove")):
        if getattr(args, flag, False):
            _say("raqib service: --%s is %s's only" % (flag.replace("_", "-"), owner))
            return 2
    if not system.packed():
        _say("raqib service check: %s: %s" % (_said(system.program()), NOT_PACKED))
        return 2
    bad, counts = check(system)
    if bad is None:
        out.write("raqib service check: the code a service would run is the system's alone: %s\n"
                  % checked_words(counts))
        return 0
    out.write("raqib service check: NOT the system's alone: %s, %s\n" % bad)
    return 1
