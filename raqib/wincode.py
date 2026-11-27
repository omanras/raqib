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

The walk (K-4, K-5, check), packed with its own runtime (sys.frozen) on Windows: the root is the folder the program
file is in; the folder the runtime says its modules are in (sys._MEIPASS) must be in it. Each folder above, from the
drive down (top first), by K-3; then the root, whole, and every file and folder below it, by K-2; then the modules'
folder and the program, met again and not read twice. A name is read by winservice's one reader (K-7): its kind is
the reading's, never the listing's. A path not of the form `X:\\...` (a share, a device path, `..`, `/`, a name
Windows would read as another: a trailing dot or space, a device's name), a path longer than the system opens
plainly, a name not read, a folder not listed, two names of one folder that differ only in case, a walk past
WALK_MAX names, modules outside the program's folder: each refused with its own words. Names are compared without
case where a set of what was walked is kept; paths are made with ntpath, on any system.

The plain road (Amendments M and N; the packed road is chosen first): a plain interpreter is walked only where
it was started with -I and with its site (no -S), so that its path is the path the service gets; otherwise exit 2,
with the command to ask it by. Then, each by K-2 and whole, the folders above each by K-3, top first, one WALK_MAX
for the whole walk and each name read once: the interpreter's folder, its base executable's (a venv's base) where
it is another, its prefix and base prefix, its exec prefix and base exec prefix where they are neither (N-3), then
the names the interpreter itself looks for at every start (N-1, OWN_NAMES) for its folder and its base's, every
entry of its path, the folder of the raqib package. Only the base executable may be unnamed: a program or a prefix
not named, or not a string, is refused (N-3). An entry that is a file is judged as itself; one that is not there
(the reader's errors 2 and 3, and no other) is judged by the deepest folder of it that is there, as the code itself,
itself only (M-3), or by the file it lies beneath where that is a file taken. N-1's names are judged so too, and
counted apart from the entries. In every entry that is a folder each *.pth file, once taken, is read - at most
PTH_MAX bytes, no byte PTH_ODD finds - and its lines that are paths by site's rule (pth_lines, with ntpath) become
entries; the check takes or runs none of its lines as code. The check is run by the code it judges (N-2): the
interpreter that asks has run its site, and the import lines of its *.pth files, at its start.

Every call of the system (the platform, whether packed, the program's path, the modules' folder, the running
interpreter's flags, base, prefixes, path and package, the one read of a name, a folder's listing, a *.pth file's
bytes) goes through one object, System; a test hands its own. The *.pth file's bytes are the only file this module
opens: one bounded read in binary mode, in System.read_bytes. Nothing runs at import; ctypes is only in winservice's
reader, declared at its first call. The standard library only; the check writes nothing (the interpreter that runs
it may write bytecode caches beside what it imports, where the asker may write); no right is asked; no program is
started; no network.
"""
from __future__ import annotations

import ntpath
import os
import re
import sys
from collections import namedtuple

import raqib
from raqib import winservice
from raqib.service import PTH_MAX, PTH_ODD, WALK_MAX   # AC-2, AD-4: the Linux numbers and byte rule (K-4, M-4)

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
# K-3, L-1: what a folder above may give: K-2's bits and adding a thing beside, and no other bit (never deleting,
# renaming, the list, the owner; never writing the folder's own attributes: allowed by K, measured nowhere, taken out)
ABOVE_ALLOWED = CODE_ALLOWED + ((0x2, "add a file"), (0x4, "add a folder"))
ENTRY_FLAGS = ("OI", "CI", "NP", "IO", "ID")   # IO: inherit-only
INHERIT_ONLY = "IO"
LIST_FLAGS = re.compile(r"(?:P|AI|AR)*\Z")
NULL_LIST = "NO_ACCESS_CONTROL"
KINDS = ("A", "D")              # allowing, denying: no other kind is judged
PLAIN_MAX = 259                 # characters of a path the system opens plainly (MAX_PATH, less its end)
SAID_MAX = 200                  # characters of a name or a text said; a cut is marked "..."
PACKED_BELOW = (3, 14)          # O-2: the packed road is walked for a runtime older than this; from it on, refused
ROLE_CODE = "as the code itself (K-2)"
ROLE_ABOVE = "as a folder above it (K-3)"
CODE_MAY = "the code itself may give any other name only reading and executing"
ABOVE_MAY = "a folder above may give any other name only reading, executing and adding a thing beside"
NOT_READ = "what was not read is never the system's"
NOT_THERE = (2, 3)              # M-3: the system's "file not found" and "path not found", the reader's first argument
ASK_BY = "-I -m raqib service check"   # M-1: the command the check of a plain interpreter is asked by
# N-1: the names a plain interpreter itself looks for at every start, for a folder it is in (own_names makes them),
# each with which of the three it is - read in the interpreter's source (Amendment N), not measured
OWN_NAMES = ("a venv's file pyvenv.cfg, which the interpreter itself looks for at every start in the folder above",
             "a build tree's marker Modules\\Setup.local, which the interpreter itself looks for at every start two"
             " folders above",
             "a build tree's library Lib, which the interpreter itself looks for at every start two folders above")
THERE, MISSING, BENEATH = "there", "not there", "beneath a file"   # how a road ended (M-3, N-3)
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
    number = getattr(exc, "winerror", None)   # L-5: the system's own number where there is one (listing a folder
    if number is None:                        # gives both; the reader raises with the system's alone)
        number = getattr(exc, "errno", None)
    words = getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
    return "%s%s" % (_said(words, 80), " (error %s)" % number if number is not None else "")


def _not_there(got):
    """M-3: True only where the reader said the name is not there (the system's errors 2 and 3, its first argument);
    a name that cannot be opened for any other reason is not read."""
    number = got.args[0] if isinstance(got, OSError) and got.args else None
    return type(number) is int and number in NOT_THERE


class _Walk:
    """E2: one walk, each name read once (names compared without case), counted by kind and role."""

    def __init__(self, system):
        self.system, self.code, self.above, self.alone, self.walked = system, set(), set(), set(), 0
        self.counts = {"folders": 0, "files": 0, "above": 0}   # the plain road adds "alone" (N-3)
        self.got, self.kind, self.lists = {}, {}, {}

    def _count(self, key, kind):
        """Each name counted once, by the strictest role it was taken in: as the code itself, whole (folders,
        files), over itself only (alone, N-3), over a folder above."""
        old = self.kind.get(key)
        if old == kind or (old is not None and kind == "above") or (old in ("folders", "files") and kind == "alone"):
            return
        if old is not None:
            self.counts[old] -= 1
        self.kind[key] = kind
        self.counts[kind] += 1

    def _reading(self, path, role):
        """(bad, got): got the name's reading, (attributes, text) or the error the reader raised, read once and kept
        (a name judged in two roles is read once); bad a refusal before any read (WALK_MAX, a path too long)."""
        key = ntpath.normcase(path)
        if key in self.got:
            return None, self.got[key]
        self.walked += 1
        if self.walked > WALK_MAX:
            return (_said(path), "more than %d names to walk (WALK_MAX): a walk that is not whole is not a pass"
                    % WALK_MAX), None
        if len(path) > PLAIN_MAX:
            return (_said(path), "%s: not read: %d characters, longer than the system opens plainly (%d); %s" % (
                role, len(path), PLAIN_MAX, NOT_READ)), None
        try:
            attributes, text = self.system.read(path)
            got = (attributes, text)
        except (OSError, ValueError) as exc:
            got = exc
        self.got[key] = got
        return None, got

    def _read(self, path, role):
        """(bad, attributes): bad the refusal (name, words) of one name in one role, or None."""
        bad, got = self._reading(path, role)
        if bad:
            return bad, None
        if isinstance(got, BaseException):
            return (_said(path), "%s: not read (%s); %s" % (role, _why(got), NOT_READ)), None
        why = _judge(got[0], got[1], role)
        return ((_said(path), why) if why else None), got[0]

    def folder_above(self, path):
        key = ntpath.normcase(path)
        if key in self.code or key in self.above or key in self.alone:   # judged already (K-2 holds K-3's bits)
            return None
        self.above.add(key)
        bad, _ = self._read(path, ROLE_ABOVE)
        if bad is None:
            self._count(key, "above")
        return bad

    def whole(self, top, folder):
        """The refusal (name, words) or None: `top` and, where it reads as a folder, everything below it, whole.
        folder: the words for a top that must be a folder (the program's folder), or None (an entry may be a file)."""
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
                    return _said(path), "%s: %s is not a folder as read (attributes 0x%x)" % (
                        ROLE_CODE, folder, attributes)
                self._count(key, "files")
                continue
            self._count(key, "folders")
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
            self.lists[key] = names
        return None

    def road(self, top, folder, missing_ok):
        """M-2, M-3, N-3: (bad, how). Each folder above `top`, top first, by K-3, then `top` whole by K-2, and how is
        THERE. Where missing_ok and a name of it is not there, the deepest folder of it that is there is judged as
        the code itself, itself only (its folders above by K-3; counted "alone"), and how is MISSING; where the
        deepest name of it that is there is a file taken as the code itself, that file judges it, and how is
        BENEATH."""
        chain = _above(top) + [top]
        for k, here in enumerate(chain):
            bad, got = self._reading(here, ROLE_ABOVE if k + 1 < len(chain) else ROLE_CODE)
            if bad:
                return bad, None
            if missing_ok and _not_there(got):
                return self._missing(top, chain[k - 1] if k else None, got)
            if k + 1 < len(chain):
                bad = self.folder_above(here)
                if bad:
                    return bad, None
        return self.whole(top, folder), THERE

    def _missing(self, entry, deepest, error):
        if deepest is None:
            return (_said(entry), "not there (error %d), and neither is its drive: no folder of it is there to be"
                                  " judged; %s" % (error.args[0], NOT_READ)), None
        key = ntpath.normcase(deepest)
        if self.kind.get(key) == "files":    # a file taken as the code itself, whole: what lies beneath it is its
            return None, BENEATH             # own (N-3)
        if key in self.code or key in self.alone:
            return None, MISSING
        self.alone.add(key)
        bad, attributes = self._read(deepest, ROLE_CODE)
        if bad:
            return (_said(entry), "not there (error %d): the deepest folder of it that is there, %s, judged for it"
                                  " %s" % (error.args[0], _said(deepest), bad[1])), None
        if not attributes & winservice.ATTRIBUTE_FOLDER:   # not met: a folder above is a folder, or refused
            self._count(key, "files")
            return None, BENEATH
        self._count(key, "alone")
        return None, MISSING


def check(system):
    """E2 (K-4, K-5; M-1 to M-5): (bad, counts). bad is (name, words) of the first name refused - or of the program,
    where it is not Windows', or a plain interpreter not asked with -I and its site - or None where the code a
    service would run is the system's alone; counts says what was walked: folders and files judged as the code itself
    (K-2), folders above (K-3), and on the plain road what plain_words says. Packed, the packed road; else the plain
    one. The check writes nothing."""
    walk = _Walk(system)

    def done(bad):
        return bad, dict(walk.counts)
    platform, program = system.platform(), system.program()
    if platform != "win32":
        return done((_said(program), not_windows(platform)))
    if not system.packed():
        return _plain(system, walk, program)
    why = path_refused(program)
    if why:
        return done((_said(program), "the program's path %s" % why))
    version = system.version()
    if (not isinstance(version, tuple) or len(version) != 2 or not all(type(n) is int for n in version)
            or version >= PACKED_BELOW):
        return done((_said(program), "packed with a Python that says its version as %s: from %d.%d on the runtime"
                                     " reads a venv file (pyvenv.cfg) in the folder above the program's though its"
                                     " home is set (ADR-0013 O-2), and the packed road does not judge that name yet,"
                                     " so it is never said to be the system's alone"
                                     % ((_said(repr(version), 40),) + PACKED_BELOW)))
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
    for top, folder in ((root, "the program's folder"), (modules, "the program's folder"), (program, None)):
        for up in _above(top):
            bad = walk.folder_above(up)
            if bad:
                return done(bad)
        bad = walk.whole(top, folder)
        if bad:
            return done(bad)
    return done(None)


def not_asked(system):
    """M-1: None where a plain interpreter was started with -I and with its site; else the words of exit 2: which is
    missing, and the command to ask it by."""
    missing = []
    if not system.isolated():
        missing.append("was not started with -I (isolated)")
    if system.no_site():
        missing.append("was started with -S (without its site)")
    if not missing:
        return None
    return ("a plain interpreter that %s: the path it would walk is not the path the service gets, which runs it with"
            " -I and its site (ADR-0013 M-1), so it is never said to be the system's alone; ask it as the service"
            " will run it: \"%s\" %s" % (" and ".join(missing), _said(system.program()), ASK_BY))


def pth_lines(text, folder):
    """M-4 (service.pth_entries' rule, with ntpath): the lines of a *.pth file's text that are paths, by site's own
    rule - not blank, not `#`, not `import` - each, its trailing whitespace stripped, joined to the folder the file is
    in and made whole lexically, there or not. This takes or runs no line as code."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip() or line.startswith(("import ", "import\t")):
            continue
        out.append(ntpath.normpath(ntpath.join(folder, line.rstrip())))
    return out


def own_names(folder):
    """N-1: [(name, which)] the names the interpreter itself looks for at every start, for a folder it is in:
    pyvenv.cfg in the folder above it; Modules\\Setup.local and Lib two folders above it (made with ntpath: for a
    folder nearer the drive's root than that, the root)."""
    up, top = ntpath.dirname(folder), ntpath.normpath(ntpath.join(folder, "..", ".."))
    return list(zip((ntpath.join(up, "pyvenv.cfg"), ntpath.join(top, "Modules", "Setup.local"),
                     ntpath.join(top, "Lib")), OWN_NAMES))


def _root_said(path):
    """N-3: None where a root the system object gave is a whole path of a drive; else why not, in its own words."""
    if path is None:
        return "is not named (None): only the base executable may be unnamed (ADR-0013 N-3); %s" % NOT_READ
    if not isinstance(path, str):
        return "is not a string (%s): not read; %s" % (_said(repr(path), 80), NOT_READ)
    return path_refused(path)


def _plain(system, walk, program):
    """M-1 to M-5, N-1, N-3: the plain interpreter's road, in M-2's order; (bad, counts) as check gives them."""
    counts = {"entries": 0, "missing": 0, "beneath": 0, "own": 0, "own_there": 0, "pth": 0, "pth_lines": 0,
              "base": 0, "exec": 0}
    walk.counts["alone"] = 0

    def done(bad):
        return bad, dict(walk.counts, **counts)
    words = not_asked(system)
    if words:
        return done((_said(program), words))
    base, prefixes = system.base_executable(), (system.prefix(), system.base_prefix())
    given = (("the interpreter's path", program, "the interpreter's folder"),
             ("the base executable's path", base, "the base executable's folder"),
             ("the interpreter's prefix", prefixes[0], "the interpreter's prefix"),
             ("the interpreter's base prefix", prefixes[1], "the interpreter's base prefix"),
             ("the interpreter's exec prefix", system.exec_prefix(), "the interpreter's exec prefix"),
             ("the interpreter's base exec prefix", system.base_exec_prefix(), "the interpreter's base exec prefix"))
    for said, path, _ in given:
        if path is None and said == given[1][0]:
            continue    # N-3: the base executable alone may be unnamed; its interpreter's own folder is walked
        why = _root_said(path)
        if why:
            return done((_said(path), "%s %s" % (said, why)))
    folders = [ntpath.dirname(program)]
    if base is not None and ntpath.normcase(ntpath.dirname(base)) != ntpath.normcase(folders[0]):
        folders.append(ntpath.dirname(base))    # a base in another folder (a venv's): walked, and its names judged
        counts["base"] = 1
    roots = list(zip(folders, ("the interpreter's folder", "the base executable's folder")))
    roots += [(path, what) for _, path, what in given[2:4]]
    for _, path, what in given[4:]:            # N-3: an exec prefix that is neither prefix is a root of its own
        if ntpath.normcase(path) not in [ntpath.normcase(p) for p in prefixes]:
            roots.append((path, what))
            counts["exec"] += 1
    for top, what in roots:
        bad, _ = walk.road(top, what, False)
        if bad:
            return done(bad)
    named = roots[:len(folders)]
    if ntpath.normcase(prefixes[1]) not in [ntpath.normcase(f) for f in folders]:
        named.append((prefixes[1], "the interpreter's base prefix"))   # O-1: a venv's home, whatever names its base
    judged = set()
    for folder, what in named:                  # N-1: judged as an entry is, counted apart from the entries
        for name, which in own_names(folder):
            if ntpath.normcase(name) in judged:
                continue
            judged.add(ntpath.normcase(name))
            counts["own"] += 1
            bad, how = walk.road(name, None, True)
            if bad:
                return done((bad[0], "%s (the name %s: %s %s %s)" % (bad[1], _said(name), which, what,
                                                                       _said(folder))))
            if how == THERE:
                counts["own_there"] += 1
    entries, seen = [(e, None) for e in list(system.sys_path())], set()
    while entries:
        entry, source = entries.pop(0)
        bad = _entry_said(entry, source)
        if bad is None:
            key = ntpath.normcase(entry)
            if key in seen:
                continue
            seen.add(key)
            counts["entries"] += 1
            bad, how = walk.road(entry, None, True)
            if bad:
                bad = bad if source is None else (bad[0], "%s (the entry %s, a line of %s)" % (
                    bad[1], _said(entry), _said(source)))
            elif how == MISSING:
                counts["missing"] += 1
            elif how == BENEATH:
                counts["beneath"] += 1
        if bad:
            return done(bad)
        if walk.kind.get(ntpath.normcase(entry)) != "folders" or ntpath.normcase(entry) not in walk.lists:
            continue
        for name in [n for n in walk.lists[ntpath.normcase(entry)] if n.endswith(".pth")]:
            pth = ntpath.join(entry, name)
            bad, data = _pth_read(system, walk, pth)
            if bad:
                return done(bad)
            counts["pth"] += 1
            lines = pth_lines(data.decode("ascii"), entry)
            counts["pth_lines"] += len(lines)
            entries += [(line, pth) for line in lines]
    package = system.package_dir()
    why = path_refused(package)
    if why:
        return done((_said(package), "the raqib package's folder %s" % why))
    bad, _ = walk.road(package, "the raqib package's folder", False)
    return done(bad)


def _entry_said(entry, source):
    """M-2: None where an entry of the path (or a *.pth line made whole) is a whole path of a drive; else why not."""
    of = "an entry of the interpreter's path" if source is None else "a line of %s, made whole" % _said(source)
    if not isinstance(entry, str):
        return _said(repr(entry), 80), "%s that is not a string: not read; %s" % (of, NOT_READ)
    why = path_refused(entry)
    if why:
        return _said(entry), "%s: %s" % (of, why)
    return None


def _pth_read(system, walk, pth):
    """M-4: (bad, data): a *.pth file's bytes, read only once it was taken as the code itself (a file, walked whole
    with its entry), at most PTH_MAX bytes, no byte PTH_ODD finds; else the refusal."""
    if walk.kind.get(ntpath.normcase(pth)) != "files" or ntpath.normcase(pth) not in walk.code:
        return (_said(pth), "a *.pth name that is not a file as read: what site would make of it is not read; %s"
                % NOT_READ), None
    try:
        data = system.read_bytes(pth, PTH_MAX)
    except (OSError, ValueError) as exc:
        return (_said(pth), "a *.pth file that cannot be read (%s); %s" % (_why(exc), NOT_READ)), None
    if not isinstance(data, bytes):
        return (_said(pth), "a *.pth file whose bytes are not read; %s" % NOT_READ), None
    if len(data) > PTH_MAX:
        return (_said(pth), "a *.pth file longer than %d bytes (PTH_MAX): not read whole; %s" % (
            PTH_MAX, NOT_READ)), None
    odd = PTH_ODD.search(data)
    if odd:   # AD-4: the versions of site split and decode such a file differently: not read into entries
        return (_said(pth), "a *.pth file holding byte 0x%02x at offset %d, outside printable ASCII, tab, LF and CR"
                            " (the versions of site split and decode such a file differently; it is not read)" % (
                                data[odd.start()], odd.start())), None
    return None, data


def checked_words(counts):
    """K-6 (service.checked_words' twin): what the check walked, by count (never a sentence without them)."""
    total = counts["folders"] + counts["files"] + counts["above"]
    return ("checked %d names, each the system's alone (its owner the system, the administrators or the system's"
            " installer, no reparse point, its list there): under the program's folder, whole, %d folders and %d"
            " files, each giving any other name only reading and executing (the creator's own inherit-only entry"
            " apart), and %d folders above it to the drive's letter, each giving any other name, in the entries that"
            " apply to the folder itself, only that and adding a thing beside" % (
                total, counts["folders"], counts["files"], counts["above"]))


def plain_words(counts):
    """M-5, N-2, N-3 (service.checked_words' twin, the plain road): what the check walked, by count. The first number
    is the names walked whole and the folders above; the folders judged themselves only are said apart, after it."""
    total = counts["folders"] + counts["files"] + counts["above"]
    base = ", its base's" if counts["base"] else ""
    prefixes = ("its prefix and base prefix (its exec prefixes among them)", "its prefix, base prefix and one exec"
                " prefix apart from them", "its prefix, base prefix and two exec prefixes apart from them")
    return ("checked %d names, each the system's alone (its owner the system, the administrators or the system's"
            " installer, no reparse point, its list there): under the interpreter's folder%s, %s, %d entries of its"
            " path and the raqib package's folder, whole, %d folders and %d files, each giving any other name only"
            " reading and executing (the creator's own inherit-only entry apart); %d of those entries not there, each"
            " judged by the deepest folder of it that is there, itself only, and %d beneath a file, each judged by"
            " that file; %d names the interpreter itself looks for at every start for its folder%s (pyvenv.cfg in the"
            " folder above it, Modules\\Setup.local and Lib two folders above it), each judged as an entry is, %d of"
            " them there; %d *.pth files read, %d of their lines walked as entries, none of their lines taken or run"
            " by the check; and %d folders above them to the drive's letter, each giving any other name, in the"
            " entries that apply to the folder itself, only that and adding a thing beside; and besides those %d"
            " names, %d folders judged themselves only, as the code itself, each the deepest folder that is there of"
            " a name not there" % (
                total, base, prefixes[counts["exec"]], counts["entries"], counts["folders"], counts["files"],
                counts["missing"], counts["beneath"], counts["own"], base, counts["own_there"], counts["pth"],
                counts["pth_lines"], counts["above"], total, counts["alone"]))


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

    def version(self):                       # O-2
        return tuple(sys.version_info[:2])

    def read(self, path):
        if self._reader is None:
            self._reader = winservice.System()
        return self._reader.read_place(path)

    def listdir(self, path):
        return os.listdir(path)

    # M-1, M-2: the plain road's answers, from the running interpreter itself (never worked out)
    def isolated(self):
        return bool(sys.flags.isolated)

    def no_site(self):
        return bool(sys.flags.no_site)

    def base_executable(self):
        return getattr(sys, "_base_executable", None)

    def prefix(self):
        return sys.prefix

    def base_prefix(self):
        return sys.base_prefix

    def exec_prefix(self):                   # N-3
        return sys.exec_prefix

    def base_exec_prefix(self):
        return sys.base_exec_prefix

    def sys_path(self):
        return list(sys.path)

    def package_dir(self):
        where = getattr(raqib, "__file__", None)   # raqib/__init__.py
        return ntpath.dirname(where) if isinstance(where, str) else None

    def read_bytes(self, path, limit):
        """M-4: a *.pth file's bytes, at most `limit` + 1 (so that a longer file is told and refused by the walk):
        one bounded read in binary mode, the only file this module opens; called only once the file was taken."""
        with open(path, "rb") as f:
            return f.read(limit + 1)


# --- E3 (K-6): the command ----------------------------------------------------------------------------------------

def _say(text):
    try:
        sys.stderr.write("raqib: %s\n" % text)
        sys.stderr.flush()
    except Exception:
        pass


def cli_check(args, out, system=None):
    """`raqib service check` from raqib/cli.py (its only importer): exit 0 the system's alone (what was walked, by
    count), 1 not, or not read (the name, its role and why), 2 not Windows, or a plain interpreter not started with
    -I or started with -S (on the error stream, with the command to ask it by)."""
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
        words = not_asked(system)
        if words:
            _say("raqib service check: %s: %s" % (_said(system.program()), words))
            return 2
    bad, counts = check(system)
    if bad is None:
        out.write("raqib service check: the code a service would run is the system's alone: %s\n"
                  % (plain_words(counts) if "entries" in counts else checked_words(counts)))
        return 0
    out.write("raqib service check: NOT the system's alone: %s, %s\n" % bad)
    return 1
