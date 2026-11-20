"""The autostart places of Windows, read by Raqib itself (ADR-0014 Amendments G to K; M15.3a, M15.3b).

read() reads, with the standard library alone and in this process, every place AG-1 names: the values under Run
and RunOnce of every loaded user's hive (HKU by its SID, in one view; a `_Classes` hive and `.DEFAULT` left out;
HKCU is not read a second time) and of the machine's, in both views, each view's entries its own (AI-7); the
files directly in the user's and all users' Startup folders (`desktop.ini` left out); each service's ImagePath,
Start and Type; each scheduled task of the scheduler's tree in the registry (its Actions, and its Triggers
apart: AI-5); Winlogon's Shell and Userinit.

An entry: `place` (run, runonce, startup, service, task, winlogon), `scope` (user or machine), `view32`, `name`
(as raqib.hooks.os_sysmon.value_name gives a value's name: redacted, bounded, a SID in it shown as [sid]),
`program` (as PERSIST-RUN-KEY's line names the program a value would run; None where the content is not a
command or was not read), `sure` (False where the text may name another program however it is read: AI-8,
AK-3), `list` (a Winlogon list of more than one program, which names none), `link` (a link in a Startup folder,
never followed: its content is a fixed word, AK-4), `sha256` (its content's hash: a value's data, a file, a
service's three values, a task's actions; None where it was not read),
`triggers` (a task's triggers' hash), `key` (where it is) and `part` (the key or folder it was read from). Every
hash is a keyed hash (HMAC-SHA256) under a salt that is random and never leaves the process (AI-9), over a
content's length and its first 64 KiB (AI-4). A value's text, a file's content, a SID and a user's name stay in
this process's memory.

What the rights or the bounds do not give is said per place, never read as empty (AG-2, AI-4): `refused` (the
whole place), `partly` (how many of its keys were not read, and why), `failed` (another error, with its
reason) or `unread` (the read's deadline passed before it was reached); a place that is not there is empty. The
deadline is looked at between keys and files, never inside one call. Six steps, `runonce` its own; a read begins
one step further than the read before, and inside a step the machine's key or folder comes first and the users'
hives turn once a whole turn of the steps (AK-2, AL-2): a slow key delays the keys after it in its step and the
steps after it in that read, which a later read reaches first - within six reads for each user's hive loaded,
where the slow keys are one user's own. Every key whose values are taken, and every Startup folder, is bounded at
1000 entries: one over it is a part not read, said each read, none of its entries compared while it is over (a
user can do that to its own Run key or Startup folder: said, and a lever that is left, AK-1). A Startup folder on
a share is not read at all; a Startup file is opened with every sharing and without following a link, or not
opened (AI-3, AK-4): what was measured is that another call's rename and delete do not fail while the read holds
a file; an open that asks for no sharing still fails for the instant of the read (not measured). read() never
raises and imports winreg and ctypes only inside the call. Off Windows it reads nothing and says so (Linux's places are ADR-0014 S4).

A Watcher takes reads one after another and compares each with what every place, and every key of it, last held
when it was read (AI-1): an entry that appears while a part that was read before is not read is said as added by
the first read that reads it again; a part first read late (a place the deadline cut, a key refused at first) is a
base, none of its entries said, and the watcher says once that it took it (AJ-1). A change made and undone while
a part is not read is not said. A key's enumeration reads each value whole and a folder's listing every name: the
bound (1000) is of the entries compared, and 64 KiB of what is hashed (AK-6). changes(before, after) compares two
reads, as in M15.3a.

    python -m raqib.autostart [--rounds N] [--every S]

prints one line of the first read, then at each later read one line per change. It writes no file and opens
no socket. Exit 0; 2 for arguments it does not take. Spec: docs/specs/AUTOSTART.md.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import math
import ntpath
import os
import re
import sys
import time

from raqib.hooks import os_sysmon

PLACES = ("run", "runonce", "startup", "service", "task", "winlogon")
HIVE = "hive"                         # the users' hives: a part of its own, so that a hive comes or goes (AI-6)
CURRENT_VERSION = "Microsoft\\Windows\\CurrentVersion"
RUN_KEYS = (("run", "Run"), ("runonce", "RunOnce"))
SERVICES = "SYSTEM\\CurrentControlSet\\Services"
TASK_CACHE = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache"
TASK_TREE = TASK_CACHE + "\\Tree"
TASK_BODIES = TASK_CACHE + "\\Tasks"
TASK_DEPTH = 32                       # the scheduler's folders, at most this deep; a deeper one is said (AH-2)
# ADR-0014 AH-1: a SID wherever it stands in a name an entry's maker chose (a per-user task of an updater holds one)
SID_IN_NAME = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+", re.I)
GONE_WHILE_OPEN = 1018                # ERROR_KEY_DELETED: a key deleted while it is read is not there (AH-5)
WINLOGON = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
WINLOGON_VALUES = ("Shell", "Userinit")
STARTUP = ("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
STARTUP_ROOTS = (("user", "APPDATA"), ("machine", "ProgramData"))
LEFT_OUT = ("desktop.ini",)           # AG-1, as A-3
SID = re.compile(r"S-1-[0-9]+(?:-[0-9]+)+\Z")   # a hive by its SID; `S-1-...-1001_Classes` does not match
NO_MORE_ITEMS = 259                   # ERROR_NO_MORE_ITEMS: an enumeration's end
HEAD_BYTES = 64 * 1024                # AI-4: a content is hashed by its length and its first 64 KiB
ENTRY_BOUND = 1000                    # AJ-2: a key's values or a folder's files, at most this many a read
PROGRAM_EXTENSIONS = (".exe", ".com", ".bat", ".cmd", ".scr", ".pif")   # AJ-3: a first word that names a program
FILE_ATTRIBUTE_REPARSE_POINT = 0x400  # AJ-4: a symbolic link or another reparse point
LOCAL_DRIVES = (2, 3, 5, 6)           # GetDriveTypeW: removable, fixed, CD-ROM, RAM disk; 0 and 1 are not known
STEPS = ("run", "runonce", "startup", "service", "task", "winlogon")   # AJ-2, AK-2: a read begins one step further
WINDOWS_BLANKS = " \t"                # AK-3: Windows splits a command at spaces and tabs alone
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000   # AK-4: the open itself does not follow a link
LINK_WORD = "a link: its content is not read"   # AK-4: a link's content, a fixed word of its own (hashed)
SALT_ID = "the salt's own name"       # AJ-6: hashed under the salt, it tells two salts apart and tells neither
DEADLINE_S = 5.0                      # AI-4: a read's deadline, by default
SALT_BYTES = 32
# AI-3: a Startup file is opened for reading with read, write and delete sharing (CreateFileW)
GENERIC_READ = 0x80000000
SHARE_ALL = 0x1 | 0x2 | 0x4           # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
DRIVE_REMOTE = 4                      # GetDriveTypeW: a drive Windows calls remote
WIN_NOT_THERE = (2, 3)                # ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
WIN_REFUSED = (5, 32, 33)             # ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
SEPARATORS = ("\\", "/")
REFUSED = "refused"
ON_SHARE = "on a share: not read (the capture path makes no network call)"
SHARE_UNKNOWN = "whether it is on a share is not known: not read"
NO_SHARING = "it cannot be opened with every sharing: not opened"
A_LINK = "a link: not opened or followed"
CASE_TWIN = "a second name of one key (equal but for case): not read"
NOT_FOUND = "not found when opened"
OVER_BOUND = "more than %d entries: not read whole" % ENTRY_BOUND
BELOW_BOUND = "below the depth bound"
CUT_BEFORE = "the read's deadline (%g s) passed before it was read"
CUT_WHILE = "the read's deadline (%g s) passed while it was read"
CUT_KEY = "the read's deadline (%g s) passed before it was reached"
NOT_WINDOWS = ("autostart: not Windows (%s): nothing is read; the autostart places read here are Windows',"
               " and Linux's are ADR-0014 S4.")


class WinRegistry:
    """The registry as read() asks it, over the standard library's winreg (handed in: imported by read() alone).
    subkeys() and values() open a key read-only, in the 64-bit view or the 32-bit one, and raise what winreg
    raises (FileNotFoundError: not there; PermissionError: refused; another OSError)."""

    def __init__(self, winreg):
        self.w = winreg
        self.roots = {"HKU": winreg.HKEY_USERS, "HKLM": winreg.HKEY_LOCAL_MACHINE}

    def _open(self, root, path, view32):
        w = self.w
        return w.OpenKey(self.roots[root], path, 0, w.KEY_READ | (w.KEY_WOW64_32KEY if view32 else w.KEY_WOW64_64KEY))

    def _each(self, root, path, view32, count_at, enum, limit=None):
        out = []
        with self._open(root, path, view32) as key:
            count = self.w.QueryInfoKey(key)[count_at]
            for i in range(count if limit is None else min(count, limit + 1)):
                try:
                    out.append(enum(key, i))
                except OSError as exc:
                    if getattr(exc, "winerror", None) == NO_MORE_ITEMS:   # fewer than counted: one went meanwhile
                        break
                    raise
        return out

    def subkeys(self, root, path, view32=False):
        return self._each(root, path, view32, 0, self.w.EnumKey)

    def values(self, root, path, view32=False):
        """[(name, data, type)] of the key's values, at most ENTRY_BOUND + 1 of them (AJ-2: one more says the
        bound was met)."""
        return [tuple(v) for v in self._each(root, path, view32, 1, self.w.EnumValue, ENTRY_BOUND)]


class CannotShare(Exception):
    """AI-3: there is no way here to open a file with every sharing, so it is not opened."""


class IsALink(Exception):
    """AK-4: the open's handle says the file is a link (a reparse point): its content is not read."""


def _handle_attributes(f):
    """The attributes of an open file's handle (Windows: st_file_attributes of fstat); 0 where there are none."""
    try:
        return getattr(os.fstat(f.fileno()), "st_file_attributes", 0) or 0
    except (AttributeError, OSError, ValueError):
        return 0


def _win_error(code):
    """An OSError of a Windows error number, of the kind Python gives it (no path, no text of the system's)."""
    kind = FileNotFoundError if code in WIN_NOT_THERE else PermissionError if code in WIN_REFUSED else OSError
    number = errno.ENOENT if kind is FileNotFoundError else errno.EACCES if kind is PermissionError else errno.EIO
    exc = kind(number, "CreateFileW failed")
    try:
        exc.winerror = code
    except Exception:
        pass
    return exc


def share_opener(kernel32, osfhandle, last_error, invalid=-1):
    """AI-3: an opener that opens a file for reading with read, write and delete sharing (CreateFileW, OPEN_EXISTING),
    so that another process's delete or rename of it does not fail while it is read; AK-4: it asks Windows not to
    follow a link (FILE_FLAG_OPEN_REPARSE_POINT), so a link opens as itself and Disk.head says it is one. kernel32, osfhandle
    (msvcrt.open_osfhandle) and last_error (ctypes.get_last_error) are handed in: Windows' own in read(), a test's
    elsewhere. It gives a binary file object; it raises what Windows refuses."""
    def open_shared(path):
        handle = kernel32.CreateFileW(path, GENERIC_READ, SHARE_ALL, None, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None)   # AK-4
        if handle is None or handle == invalid:
            raise _win_error(last_error())
        try:
            fd = osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except Exception:
            kernel32.CloseHandle(handle)
            raise
        try:
            return os.fdopen(fd, "rb")
        except Exception:   # the fd owns the handle: closing it closes both
            os.close(fd)
            raise
    return open_shared


def _windows_opener():
    """Windows' share_opener, by ctypes and msvcrt (the standard library); None where they cannot be had."""
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                  wintypes.DWORD, wintypes.HANDLE]
        k.CreateFileW.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        return share_opener(k, msvcrt.open_osfhandle, ctypes.get_last_error, ctypes.c_void_p(-1).value)
    except Exception:
        return None


def _windows_drive_kind(kernel32=None):
    """A folder's drive's kind as Windows tells it (GetDriveTypeW): "remote" (4), "local" (removable, fixed, CD-ROM,
    RAM disk), or None where it is not known (0: unknown, 1: no root, no drive letter) - AJ-4: such a drive is not
    read. kernel32 is Windows' own, by ctypes, unless a test hands in its own; None where none can be had."""
    k = kernel32
    if k is None:
        try:
            import ctypes
            from ctypes import wintypes
            k = ctypes.WinDLL("kernel32")
            k.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
            k.GetDriveTypeW.restype = wintypes.UINT
        except Exception:
            return None

    def kind(folder):
        m = re.match(r"(?:\\\\[?.]\\)?([A-Za-z]):", str(folder))
        if not m:
            return None
        got = k.GetDriveTypeW(m.group(1).upper() + ":\\")
        return "remote" if got == DRIVE_REMOTE else "local" if got in LOCAL_DRIVES else None
    return kind


def _local(folder):
    """Off Windows (a test's read): a folder is local; a UNC path is still a share (on_share)."""
    return "local"


def on_share(folder, drive_kind):
    """AI-4: True where a folder is on a share (a UNC path, or a drive Windows calls remote), False where it is
    not, None where that is not known (no drive_kind, or one that cannot tell)."""
    p = str(folder).replace("/", "\\")
    low = p.lower()
    if low.startswith(("\\\\?\\unc\\", "\\\\.\\unc\\")):
        return True
    if p.startswith("\\\\") and not low.startswith(("\\\\?\\", "\\\\.\\")):
        return True
    if drive_kind is None:
        return None
    try:
        kind = drive_kind(folder)
    except Exception:
        return None
    return True if kind == "remote" else False if kind == "local" else None


def long_path(folder, name):
    """AJ-4: the path of a file by the name its folder listed, in the long form (`\\\\?\\`), so that Windows reads no
    other name for it (a trailing dot or blank, a device's name); the folder's own path is made whole first."""
    f = str(folder).replace("/", "\\").rstrip("\\")
    if not f.startswith("\\\\?\\"):
        f = "\\\\?\\" + ntpath.normpath(f)
    return f + "\\" + name


def _reparse(entry):
    try:
        return bool(entry.stat(follow_symlinks=False).st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):   # off Windows there are no such attributes
        return False


class Disk:
    """The Startup folders as read() asks them: what is directly in a folder, and a file's length and first
    HEAD_BYTES, the file opened by the opener (AI-3: Windows' with every sharing; CannotShare where there is
    none) by its listed name in the long form on Windows (AJ-4). A test hands in its own, or its own opener."""

    def __init__(self, opener=None, long_form=None, scandir=None, attributes=None):
        self.opener = opener
        self.long_form = os.name == "nt" if long_form is None else long_form
        self.scandir = scandir or os.scandir                 # a test hands in made-up entries
        self.attributes = attributes or _handle_attributes   # a test hands in a handle's attributes

    def files(self, folder):
        """[(name, "file" | "link")] of what is directly in the folder, at most ENTRY_BOUND + 1 (AJ-2): a symbolic
        link or another reparse point is a "link" and is not followed (AJ-4); a folder is left out."""
        out = []
        with self.scandir(folder) as it:
            for e in it:
                if e.is_symlink() or _reparse(e):
                    out.append((e.name, "link"))
                elif e.is_file(follow_symlinks=False):
                    out.append((e.name, "file"))
                if len(out) > ENTRY_BOUND:
                    break
        return out

    def path(self, folder, name):
        return long_path(folder, name) if self.long_form else os.path.join(folder, name)

    def head(self, folder, name):
        if self.opener is None:
            raise CannotShare()
        with self.opener(self.path(folder, name)) as f:
            if self.attributes(f) & FILE_ATTRIBUTE_REPARSE_POINT:   # AK-4: opened as itself, a link is not read
                raise IsALink()
            return os.fstat(f.fileno()).st_size, f.read(HEAD_BYTES)


def _why(exc):
    """An error's reason without its text (a path in it could hold a user's name): its kind and its number."""
    code = getattr(exc, "winerror", None)
    code = getattr(exc, "errno", None) if code is None else code
    return "%s%s" % (type(exc).__name__, "" if code is None else " (%s)" % code)


def _body(data):
    """A value's data as bytes."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8", "surrogatepass")
    if isinstance(data, (list, tuple)):
        return "\0".join(str(x) for x in data).encode("utf-8", "surrogatepass")
    return b"" if data is None else str(data).encode("utf-8", "surrogatepass")


_PROCESS_SALT = []


def _process_salt():
    """AI-9: the salt of a read made without a watcher: random, made once in this process, never written."""
    if not _PROCESS_SALT:
        _PROCESS_SALT.append(os.urandom(SALT_BYTES))
    return _PROCESS_SALT[0]


class _Hasher:
    """AI-9, AI-4: keyed hashes (HMAC-SHA256) under a salt; a content by its length and its first 64 KiB."""

    def __init__(self, salt):
        self._salt = bytes(salt)

    def text(self, text):
        return hmac.new(self._salt, text.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()

    def content(self, *parts):
        """A value's content, or several (a service's three), each (type, data), None for one not there."""
        m = hmac.new(self._salt, b"content", hashlib.sha256)
        for part in parts:
            if part is None:
                m.update(b"\0-")
                continue
            typ, data = part
            body = _body(data)
            m.update(("\0+%s:%d:" % (typ, len(body))).encode("ascii", "replace"))
            m.update(body[:HEAD_BYTES])
        return m.hexdigest()

    def file(self, length, head):
        m = hmac.new(self._salt, ("file\0%d:" % length).encode("ascii"), hashlib.sha256)
        m.update(head[:HEAD_BYTES])
        return m.hexdigest()


def _split_list(text):
    """Winlogon's list: its items, split on commas outside double quotes, the empty ones left out (AK-3: blanks
    are spaces and tabs alone)."""
    items, cur, quoted = [], [], False
    for c in text:
        if c == '"':
            quoted = not quoted
        if c == "," and not quoted:
            items.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    items.append("".join(cur))
    return [i.strip(WINDOWS_BLANKS) for i in items if i.strip(WINDOWS_BLANKS)]


def _first_word(text):
    """The text up to its first space or tab (AK-3: Windows splits a command at those alone)."""
    return re.split(r"[ \t]", text, maxsplit=1)[0]


def _sure(text):
    """AJ-3, AK-3: whether the text names one program however it is read. Not sure: a text that holds a blank
    other than a space or a tab; a first word that holds a `%` (the read expands nothing); an unquoted text where
    more than one run from its start to a blank or to its end ends in a program's extension; an unquoted first
    word that holds a separator, is followed by a blank and ends in no program's extension. Sure: a quoted first
    word; an unquoted one that ends in a program's extension; any other (`cmd /c ...`)."""
    if any(c.isspace() and c not in WINDOWS_BLANKS for c in text):
        return False
    if text.startswith('"'):
        end = text.find('"', 1)
        return "%" not in (text[1:end] if end > 0 else text[1:])
    first = _first_word(text)
    if "%" in first:
        return False
    runs = {text[:m.start()].rstrip(WINDOWS_BLANKS) for m in re.finditer(r"[ \t]", text)} | {text}
    if sum(1 for r in runs if r and r.lower().endswith(PROGRAM_EXTENSIONS)) > 1:
        return False
    if first.lower().endswith(PROGRAM_EXTENSIONS):
        return True
    return not (len(text) > len(first) and any(s in first for s in SEPARATORS))


def _program(data, place):
    """(program, sure, listing): the program a content would run, as PERSIST-RUN-KEY's line names it, and whether
    that name is sure (AJ-3, AK-3). A Winlogon value is a list: one program is named; a list of more than one names
    none (`listing` True, AJ-3). (None, None, False) where the content is not text or names no program."""
    if not isinstance(data, str) or not data.strip(WINDOWS_BLANKS):
        return None, None, False
    text = data.strip(WINDOWS_BLANKS)
    if place == "winlogon":
        items = _split_list(text)
        if len(items) > 1:
            return None, None, True
        if not items:
            return None, None, False
        text = items[0]
    program = os_sysmon.registry_program(text)
    if program is None:
        return None, None, False
    return program, _sure(text), False


class _Deadline:
    def __init__(self, clock, t0, seconds):
        self.clock, self.t0, self.seconds = clock, t0, seconds

    def passed(self):
        if self.t0 is None or self.seconds is None:
            return False
        now = _now(self.clock)
        return now is not None and now - self.t0 >= self.seconds


class _Place:
    def __init__(self, name, hasher):
        self.name, self.h = name, hasher
        self.entries, self.opened, self.not_read, self.failed, self.cut, self.last = [], 0, [], None, None, None
        self.parts = {}

    def ask(self, ident, call):
        """call()'s answer; None where the key is not there (empty), refused (counted) or failed (the place
        failed, with its reason). `last` says which: ok, absent, refused or failed."""
        try:
            got = call()
        except FileNotFoundError:
            self.last = "absent"
            return None
        except PermissionError:
            self.last = REFUSED
            self.not_read.append((ident, REFUSED))
            return None
        except OSError as exc:
            if getattr(exc, "winerror", None) == GONE_WHILE_OPEN:   # AH-5: deleted while it was read: not there
                self.last = "absent"
                return None
            self.last = "failed"
            self.failed = self.failed or _why(exc)
            return None
        except Exception as exc:   # AG-2: another error is said with its reason
            self.last = "failed"
            self.failed = self.failed or _why(exc)
            return None
        self.last = "ok"
        self.opened += 1
        return got

    def given(self):
        return self.last in ("ok", "absent")

    def part(self, ident, parent=None, hive=False, read=True, lists=False):
        """A key or a folder of the place, by a keyed hash of where it is: the base of a comparison (AI-1). `lists`:
        its read lists the parts under it (the users' hives, the services' key, a key of the task tree, a Startup
        folder), so one under it that its last read did not list is new; a fixed key (Run, RunOnce) is not."""
        pid = self.h.text("part\0%s\0%s" % (self.name, ident))
        self.parts[pid] = {"place": self.name, "parent": parent, "hive": hive, "read": bool(read), "lists": lists}
        return pid

    def unreached(self, ident, parent, why):
        """AJ-2: a key the deadline did not let the read reach: a part not read, said with that reason."""
        self.cut = self.cut or why
        self.not_read.append((ident, why))
        return self.part(ident, parent, read=False)

    def bounded(self, got, ident, pid):
        """AJ-2, AK-1: a key or a folder with more than ENTRY_BOUND entries is not read whole: the first
        ENTRY_BOUND are given, the part is not read (none of its entries is compared), and the bound is said."""
        if got is not None and len(got) > ENTRY_BOUND:
            self.not_read.append((ident, OVER_BOUND))
            self.parts[pid]["read"] = False
            return list(got)[:ENTRY_BOUND]
        return got

    def add(self, scope, view32, raw_name, program, sure, digest, where, part, triggers=None, listing=False,
            link=False):
        shown = os_sysmon.value_name(SID_IN_NAME.sub("[sid]", raw_name))   # AH-1: a SID in a name is not shown
        self.entries.append({"place": self.name, "scope": scope, "view32": view32, "name": shown,
                             "program": program, "sure": sure, "list": listing, "link": link, "sha256": digest,
                             "triggers": triggers,
                             "key": self.h.text("\0".join((self.name, where, "32" if view32 else "64",
                                                           raw_name.lower()))),
                             "part": part})

    def said(self):
        why = {}
        for _, w in self.not_read:
            why[w] = why.get(w, 0) + 1
        reason = None
        if self.failed is not None:
            state, reason = "failed", self.failed
        elif self.not_read and not self.opened:
            state = REFUSED if set(why) == {REFUSED} else "unread"
            reason = None if state == REFUSED else "; ".join(sorted(why))
        elif self.cut is not None and not self.opened:
            state, reason = "unread", self.cut
        elif self.not_read:
            state = "partly"
        else:
            state = "read"
        return {"state": state, "entries": len(self.entries), "keys_refused": len(self.not_read),
                "keys_why": why, "reason": reason,
                "refused_sha256": self.h.text("\n".join(sorted(i for i, _ in self.not_read)))}


def _users(reg, places, hives, memo):
    """The users' hives (by SID), listed once a read by whichever of Run and RunOnce is read first (AK-2); a
    refusal or a failure of the listing is said for both."""
    if "users" not in memo:
        users = hives.ask("HKU", lambda: reg.subkeys("HKU", "", False))
        listing = hives.part("HKU", None, read=hives.given(), lists=True)
        if users is None:
            for p in ("run", "runonce"):
                places[p].not_read += [x for x in hives.not_read if x[0] == "HKU"]
                places[p].failed = places[p].failed or hives.failed
        memo["users"] = [(sid, hives.part("hive " + sid, listing, hive=True))
                         for sid in sorted(users or ()) if SID.match(sid)]
    return memo["users"]


def _run_key(kind, reg, places, hives, memo, deadline, limit, turn):
    """Run or RunOnce (AK-2: each its own step): the machine's key first, both views, each its own (AI-7); then
    every loaded user's hive (by its SID, one view), begun one further at each turn of the steps (`turn`). AJ-2:
    the deadline is looked at before each key; the keys it did not let the read reach are parts not read."""
    place, leaf = places[kind], dict(RUN_KEYS)[kind]
    users = _users(reg, places, hives, memo)
    if users:
        users = users[turn % len(users):] + users[:turn % len(users)]
    sources = [("HKLM", "SOFTWARE", "machine", "HKLM", None, (False, True))]
    sources += [("HKU", sid + "\\Software", "user", "HKU\\" + sid, pid, (False,)) for sid, pid in users]
    todo = [(src, view32) for src in sources for view32 in src[5]]
    for i, ((root, soft, scope, hive, parent, _), view32) in enumerate(todo):
        ident = "%s\\%s %d" % (hive, leaf, view32)
        if deadline.passed():
            for src2, view2 in todo[i:]:
                place.unreached("%s\\%s %d" % (src2[3], leaf, view2), src2[4], CUT_KEY % limit)
            return
        path = "%s\\%s\\%s" % (soft, CURRENT_VERSION, leaf)
        got = place.ask(ident, lambda: reg.values(root, path, view32))
        pid = place.part(ident, parent, read=place.given())
        for name, data, typ in place.bounded(got, ident, pid) or ():
            name = "" if name is None else str(name)
            program, sure, listing = _program(data, kind)
            place.add(scope, view32, name, program, sure, place.h.content((typ, data)), hive, pid, listing=listing)


def _startup(disk, folders, place, drive_kind, deadline, limit):
    """The machine's Startup folder, then the user's (AK-2)."""
    roots = [(scope, folders.get(scope)) for scope, _ in STARTUP_ROOTS[::-1]]
    for n, (scope, folder) in enumerate(roots):
        ident = "startup " + scope
        if not folder:
            if place.failed is None:
                place.failed = "the %s Startup folder is not known (its environment variable is not set)" % scope
            continue
        if deadline.passed():
            for scope2, folder2 in roots[n:]:
                if folder2:
                    place.unreached("startup " + scope2, None, CUT_KEY % limit)
            return
        share = on_share(folder, drive_kind)
        if share is not False:   # AI-4, AJ-4: a share is not listed or opened; nor is a folder whose kind is not known
            place.not_read.append((ident, ON_SHARE if share else SHARE_UNKNOWN))
            place.part(ident, None, read=False)
            continue
        listed = place.ask(ident, lambda: disk.files(folder))   # only the folder's own listing can fail the place
        pid = place.part(ident, None, read=place.given(), lists=True)
        listed = place.bounded(listed, ident, pid)
        cut, seen = False, set()
        for name, kind in sorted(listed or ()):
            if name.lower() in LEFT_OUT:
                continue
            if name.lower() in seen:   # AK-4: a second name of one key (equal but for case): a part not read
                place.not_read.append(("%s %s" % (ident, name), CASE_TWIN))
                place.part("%s %s" % (ident, name), pid, read=False)
                continue
            seen.add(name.lower())
            why, link = None, False
            if cut or deadline.passed():   # AJ-2: listed, not reached: an entry, its content not read
                cut, why = True, CUT_KEY % limit
                place.cut = place.cut or why
            elif kind == "link":           # AJ-4: a link is not opened or followed (it may lead to a share)
                why, link = A_LINK, True
            else:
                try:
                    length, head = disk.head(folder, name)
                except IsALink:             # AK-4: the handle says it is a link: its content is not read
                    why, link = A_LINK, True
                except FileNotFoundError:   # AJ-4: listed and not found: an entry with that reason, never dropped
                    why = NOT_FOUND
                except PermissionError:     # AI-2: listed, its content refused: an entry, its content not read
                    why = REFUSED
                except CannotShare:         # AI-3: not opened at all
                    why = NO_SHARING
                except Exception as exc:    # AJ-4: another reason, said; the place does not fail
                    why = _why(exc)
            if why is not None:
                place.not_read.append(("%s %s" % (ident, name), why))
            # AK-4: a link's content is a fixed word of its own, so that a file swapped for a link is a change
            digest = place.h.text(LINK_WORD) if link else None if why else place.h.file(length, head)
            place.add(scope, False, name, None, None, digest, ident, pid, link=link)


def _services(reg, place, deadline, limit):
    names = place.ask("services", lambda: reg.subkeys("HKLM", SERVICES, False))
    root = place.part("services", None, read=place.given(), lists=True)
    names = sorted(names or ())
    for n, name in enumerate(names):
        if deadline.passed():
            for later in names[n:]:
                place.unreached("service " + later, root, CUT_KEY % limit)
            return
        ident = "service " + name
        got = place.ask(ident, lambda: reg.values("HKLM", SERVICES + "\\" + name, False))
        pid = place.part(ident, root, read=place.given())
        got = place.bounded(got, ident, pid)   # AK-1: a key at the bound is a part not read
        if got is None:
            continue
        held = {str(n_).lower(): (t, d) for n_, d, t in got}
        if "imagepath" not in held:   # a key of the services with no ImagePath runs nothing: not an entry
            continue
        program, sure, _ = _program(held["imagepath"][1], "service")
        place.add("machine", False, name, program, sure,
                  place.h.content(held["imagepath"], held.get("start"), held.get("type")), "services", pid)


def _tasks(reg, place, path, rel, depth, parent, deadline, limit):
    subs = place.ask(("tree " if depth == 0 else "folder ") + rel, lambda: reg.subkeys("HKLM", path, False))
    if depth == 0:
        parent = place.part("tree", None, read=place.given(), lists=True)
    elif place.last == REFUSED:   # its folders not listed: what was under it is kept, never said as removed
        place.parts[parent]["read"] = False
    if subs is None:
        return
    subs = sorted(subs)
    for n, name in enumerate(subs):
        sub, sub_rel = path + "\\" + name, rel + "\\" + name
        if deadline.passed():   # AJ-2: the keys not reached at this depth are parts not read
            for later in subs[n:]:
                place.unreached("tree " + rel + "\\" + later, parent, CUT_KEY % limit)
            return
        got = place.ask("tree " + sub_rel, lambda: reg.values("HKLM", sub, False))
        pid = place.part("tree " + sub_rel, parent, read=place.given(), lists=True)
        got = place.bounded(got, "tree " + sub_rel, pid)   # AK-1
        if got is None:   # refused, failed or gone: its folder is not walked (a refused key is counted once)
            continue
        held = {str(n_).lower(): (t, d) for n_, d, t in got}
        ident = held.get("id", (None, None))[1]
        if isinstance(ident, str) and ident:
            body = place.ask("task " + ident, lambda: reg.values("HKLM", TASK_BODIES + "\\" + ident, False))
            refused = body is None and place.last == REFUSED
            body = place.bounded(body, "task " + ident, pid)   # AK-1: the body's bound is the tree key's part's
            if refused:
                actions = triggers = None
            else:   # AI-5: its actions are its content; its triggers are hashed apart
                parts = {str(n_).lower(): (t, d) for n_, d, t in body or ()}
                actions, triggers = place.h.content(parts.get("actions")), place.h.content(parts.get("triggers"))
            place.add("machine", False, sub_rel, None, None, actions, "tree", pid, triggers=triggers)
        if depth < TASK_DEPTH:
            _tasks(reg, place, sub, sub_rel, depth + 1, pid, deadline, limit)
        else:   # AH-2: a folder below the bound is not walked, and is counted as a key not read (the place: partly)
            deeper = place.ask("folder " + sub_rel, lambda: reg.subkeys("HKLM", sub, False))
            if deeper:
                place.not_read.append(("deeper " + sub_rel, BELOW_BOUND))
                place.parts[pid]["read"] = False


def _winlogon(reg, place):
    got = place.ask("winlogon", lambda: reg.values("HKLM", WINLOGON, False))
    pid = place.part("winlogon", None, read=place.given())
    got = place.bounded(got, "winlogon", pid)   # AK-1
    held = {str(n).lower(): (str(n), t, d) for n, d, t in got or ()}
    for want in WINLOGON_VALUES:
        if want.lower() in held:
            name, typ, data = held[want.lower()]
            program, sure, listing = _program(data, "winlogon")
            place.add("machine", False, name, program, sure, place.h.content((typ, data)), "winlogon", pid,
                      listing=listing)


def default_folders(environ=None):
    """The user's and all users' Startup folders, from APPDATA and ProgramData (None where one is not set)."""
    environ = os.environ if environ is None else environ
    return {scope: os.path.join(environ[var], *STARTUP) if environ.get(var) else None for scope, var in STARTUP_ROOTS}


def _default_disk(opener=None, system=None):
    """The Disk a read uses where none is handed in: on Windows the module's own opener (every sharing, no link
    followed) and the long form; elsewhere (a test's read) Python's open. `system` is os.name unless a test says."""
    system = os.name if system is None else system
    if opener is None:
        opener = _windows_opener() if system == "nt" else (lambda path: open(path, "rb"))
    return Disk(opener, long_form=(system == "nt"))


def read(registry=None, folders=None, platform=None, clock=None, disk=None, salt=None, deadline=DEADLINE_S,
         opener=None, drive_kind=None, begin=0):
    """One read of every place (AG-1): {"read", "said", "platform", "seconds", "deadline", "begin", "salt_id",
    "entries", "places", "parts"}. On Windows, with no registry handed in, winreg is imported here; off Windows
    with none handed in nothing is read and `said` is the sentence that says so. The salt is the watcher's (AI-9),
    else the process's own; `salt_id` is a hash of a constant under it, which tells two salts apart and neither.
    The deadline (seconds) bounds the read between keys and files, never inside one call (AI-4, AJ-2): a place it
    did not reach is `unread`, one it cut keeps what it reached and says the rest not read. `begin` is the read's
    number (0 or more): the read begins with the step it names (STEPS, turning), and the users' hives of a step
    are begun one further each whole turn of the steps (AK-2, AL-2). The opener and the drive's kind are Windows'
    own on Windows (AI-3, AI-4), a test's elsewhere. It never raises: a place whose read fails is `failed`, with
    its reason, and a bad `begin` or salt fails the read (AK-5)."""
    platform = sys.platform if platform is None else platform
    clock = clock or time.monotonic
    t0 = _now(clock)
    result = {"read": False, "said": None, "platform": platform, "seconds": 0.0, "deadline": deadline,
              "begin": None, "salt_id": None, "entries": [], "places": {}, "parts": {}}
    hasher = _Hasher(_process_salt())
    try:
        if isinstance(begin, bool) or not isinstance(begin, int) or begin < 0:
            raise ValueError("begin is a read's number, 0 or more")
        hasher = _Hasher(_process_salt() if salt is None else salt)
        result["salt_id"] = hasher.text(SALT_ID)
        first = begin % len(STEPS)
        result["begin"] = STEPS[first]
        places = {p: _Place(p, hasher) for p in PLACES}
        hives = _Place(HIVE, hasher)
        limit = deadline
        due = _Deadline(clock, t0, deadline)
        if registry is None:
            if not str(platform).startswith("win"):
                result["said"] = NOT_WINDOWS % platform
                return result
            try:
                import winreg   # Windows' alone: imported inside the call, never at the module's import
                registry = WinRegistry(winreg)
            except Exception as exc:
                for p in PLACES:
                    places[p].failed = "winreg cannot be used (%s)" % _why(exc)
        result["read"] = True
        folders = default_folders() if folders is None else folders
        disk = _default_disk(opener) if disk is None else disk
        if drive_kind is None:
            drive_kind = _windows_drive_kind() if os.name == "nt" else _local
        memo = {}
        turn = begin // len(STEPS)   # AL-2: the users are begun one further each whole turn of the steps
        steps = {"run": lambda: _run_key("run", registry, places, hives, memo, due, limit, turn),
                 "runonce": lambda: _run_key("runonce", registry, places, hives, memo, due, limit, turn),
                 "startup": lambda: _startup(disk, folders, places["startup"], drive_kind, due, limit),
                 "service": lambda: _services(registry, places["service"], due, limit),
                 "task": lambda: _tasks(registry, places["task"], TASK_TREE, "", 0, None, due, limit),
                 "winlogon": lambda: _winlogon(registry, places["winlogon"])}
        for name in STEPS[first:] + STEPS[:first]:
            if places[name].failed is not None:   # winreg could not be used
                continue
            if due.passed():   # AI-4: a place the read did not reach is said as not read, with that reason
                places[name].cut = places[name].cut or CUT_BEFORE % limit
                continue
            try:
                steps[name]()
            except Exception as exc:   # never raises: the place failed, and what it had listed is not read (AK-5)
                places[name].failed = places[name].failed or _why(exc)
                listing = [q for q in hives.parts.values() if not q["hive"]] if name in ("run", "runonce") else []
                for q in list(places[name].parts.values()) + listing:   # AL-1: never a hive's own part: a hive
                    q["read"] = False                                    # that came in this read is still said
        entries = []
        for p in PLACES:
            entries += places[p].entries
        result["entries"] = sorted(entries, key=lambda e: (PLACES.index(e["place"]), e["scope"], e["name"], e["key"]))
        result["places"] = {p: places[p].said() for p in PLACES}
        for owner in (hives,) + tuple(places[p] for p in PLACES):
            result["parts"].update(owner.parts)
    except Exception as exc:   # never raises
        result["read"] = True
        result["entries"] = []
        result["parts"] = {}
        result["places"] = {p: dict(_Place(p, hasher).said(), state="failed", reason=_why(exc)) for p in PLACES}
    t1 = _now(clock)
    result["seconds"] = None if t0 is None or t1 is None else round(max(0.0, t1 - t0), 3)
    return result


def _now(clock):
    """The clock's time, or None where it fails (a read never raises: its time is then not known)."""
    try:
        return float(clock())
    except Exception:
        return None


def unread(result, place):
    """Why a read gives no change for a place (AG-2, AI-4), or None where it was read (whole or in part)."""
    if not isinstance(result, dict) or not result.get("read"):
        return "not read"
    said = (result.get("places") or {}).get(place)
    if not isinstance(said, dict):
        return "not read"
    if said.get("state") == "refused":
        return "refused"
    if said.get("state") == "failed":
        return "failed (%s)" % said.get("reason")
    if said.get("state") == "unread":
        return "not read (%s)" % said.get("reason")
    return None


FIELDS = ("place", "scope", "view32", "name", "program", "sha256", "key")


def changes(before, after):
    """AG-3: {"changes": [...], "unread": {place: why}}. Every entry added, changed (its hash) or removed, with
    the entry's fields and `change` (a changed one carries the hash it had, `was`). A place refused or failed in
    either read, or whose refused keys are not the same in both, gives no change and is named in `unread`. An
    entry is known by its `key`: the same entry seen twice in one read is one entry."""
    gone = {}
    for p in PLACES:
        why = [w for w in (unread(before, p), unread(after, p)) if w]
        if why:
            gone[p] = "; ".join(sorted(set(why)))
            continue
        b, a = before["places"][p], after["places"][p]
        if b.get("refused_sha256") != a.get("refused_sha256"):
            gone[p] = "the keys refused are not the same in the two reads (%s, then %s)" % (
                b.get("keys_refused"), a.get("keys_refused"))

    def keyed(result):
        return {e["key"]: e for e in result.get("entries") or () if e.get("place") not in gone}
    old, new = keyed(before), keyed(after)
    out = []
    for key in set(old) | set(new):
        if key not in old:
            out.append(dict({f: new[key].get(f) for f in FIELDS}, change="added"))
        elif key not in new:
            out.append(dict({f: old[key].get(f) for f in FIELDS}, change="removed"))
        elif old[key].get("sha256") != new[key].get("sha256"):
            out.append(dict({f: new[key].get(f) for f in FIELDS}, change="changed", was=old[key].get("sha256")))
    out.sort(key=lambda c: (PLACES.index(c["place"]) if c["place"] in PLACES else len(PLACES), c["scope"] or "",
                            c["name"] or "", c["change"], c["key"]))
    return {"changes": out, "unread": gone}


WATCH_FIELDS = FIELDS + ("sure", "list", "link", "triggers")
KINDS = ("added", "changed", "rescheduled", "read", "removed", "hive loaded", "hive unloaded")
OTHER_SALT = "a read made with another salt: not taken, and nothing of the base changed (AJ-6)"


def _keys_words(said):
    why = said.get("keys_why") or {}
    if set(why) <= {REFUSED}:
        return "%d key(s) refused" % said.get("keys_refused", 0)
    return "%d key(s) not read: %s" % (said.get("keys_refused", 0),
                                       ", ".join("%s %d" % (w, why[w]) for w in sorted(why)))


class Watcher:
    """AI-1, AJ-1: takes reads one after another and gives the changes of each against what every place, and
    inside a place read in part every key, last held when it was read; its first read gives none, and a part it
    reads for the first time later (a place the deadline cut, a key refused at first) becomes the base then, said
    once as a base taken late, none of its entries said as added. Its salt (AI-9) is random and kept in this
    object alone: read() hands it to the module's read, and it is never printed, written or returned; a read of
    another salt is not taken (AJ-6). Each read begins with the step after the one the read before began with
    (AJ-2, AK-2). `given` is what read() takes besides (a test's registry, folders, clock, opener, drive's kind).
    It takes no salt (AK-5): `_process` is the command's own flag, for a reader of the process's own reads."""

    def __init__(self, deadline=DEADLINE_S, _process=False, **given):
        if "salt" in given or "begin" in given:   # AK-5: no caller gives a watcher its salt or its turn
            raise TypeError("a Watcher takes no salt and no begin: its salt is its own, random (AI-9)")
        self.__salt = _process_salt() if _process else os.urandom(SALT_BYTES)
        self.__id = _Hasher(self.__salt).text(SALT_ID)
        self.given = dict(given, deadline=deadline)
        self.base = None      # part -> {"place", "parent", "hive", "read", "entries": {key: entry}}
        self.pending = {}     # part -> (its parent, born new): a part seen in a read and never read yet (AJ-1)
        self.__begin = 0

    def __repr__(self):
        return "<autostart.Watcher>"

    def read(self):
        result = read(salt=self.__salt, begin=self.__begin, **self.given)
        self.__begin += 1   # AK-2: the read's number: the next read begins one step further
        return result

    def take(self, result):
        """{"changes": [...], "unread": {place: why}, "late": {place: {"parts", "entries"}}, "first": bool,
        "refused": None or why} of one read against the base."""
        if not isinstance(result, dict) or not result.get("read"):
            return {"changes": [], "unread": {p: "not read" for p in PLACES}, "late": {}, "first": self.base is None,
                    "refused": None}
        if result.get("salt_id") != self.__id:   # AJ-6: never compared, never taken into the base
            return {"changes": [], "unread": {}, "late": {}, "first": self.base is None, "refused": OTHER_SALT}
        places = result.get("places") or {}
        said = {}
        for p in PLACES:
            why = unread(result, p)
            if why is None and (places.get(p) or {}).get("state") == "partly":
                why = "in part: %s" % _keys_words(places[p])
            if why:
                said[p] = why
        parts = result.get("parts") or {}

        def usable(pid):
            q = parts.get(pid)
            if q is None or not q["read"]:
                return False
            return q["place"] == HIVE or unread(result, q["place"]) is None
        held = {}
        for e in result.get("entries") or ():
            held.setdefault(e.get("part"), {})[e["key"]] = e
        if self.base is None:
            self.base = {pid: dict(q, entries=held.get(pid, {})) for pid, q in parts.items() if usable(pid)}
            self.pending = {pid: (q["parent"], False) for pid, q in parts.items() if not usable(pid)}
            return {"changes": [], "unread": said, "late": {}, "first": True, "refused": None}
        base, known, memo, kind_of = self.base, set(self.base), {}, {}

        def gone(pid):   # absent now: gone where its nearest ancestor present now was read now and lists what
            if pid not in memo:   # is under it (a fixed key under a hive is not gone for not being asked)
                q = base.get(pid)
                parent = q["parent"] if q else (self.pending.get(pid) or (None,))[0]
                memo[pid] = False if parent is None else (usable(parent) and bool(parts[parent].get("lists"))) \
                    if parent in parts else gone(parent)
            return memo[pid]

        def kind(pid):
            """AJ-1: what a part the base does not hold is: "new" (made under a part read before: its entries are
            added), "loaded" (a hive, AI-6), "hive" (a part of a hive loaded now: the hive's), "late" (not read
            before: its entries become the base, none said)."""
            if pid not in kind_of:
                q = parts[pid]
                parent = q["parent"]
                if pid in self.pending:   # seen before, never read: made under a part read before, or there before
                    k = "new" if self.pending[pid][1] else "late"
                elif parent is None:
                    k = "late"
                elif parent in known:   # under a part read before: new where that part lists what is under it
                    k = ("loaded" if q["hive"] else "new") if base[parent].get("lists") else "late"
                elif parent in parts:
                    up = kind(parent)
                    k = "hive" if up in ("loaded", "hive") else up
                else:
                    k = "late"
                kind_of[pid] = k
            return kind_of[pid]

        def under(pid, hives, table):
            while pid is not None:
                if pid in hives:
                    return True
                q = table.get(pid) or base.get(pid)
                pid = q["parent"] if q else None
            return False
        out, late = [], {}
        loaded = {pid for pid, q in parts.items() if q["hive"] and usable(pid) and pid not in known
                  and kind(pid) == "loaded"}
        unloaded = {pid for pid, q in base.items() if q["hive"] and pid not in parts and gone(pid)}
        for pid in sorted(loaded):
            n = sum(len(held.get(c, {})) for c in parts
                    if c != pid and c not in known and usable(c) and under(c, {pid}, parts))
            out.append(self._hive("hive loaded", pid, n))
        for pid in sorted(unloaded):
            n = sum(len(q["entries"]) for c, q in base.items() if c != pid and under(c, {pid}, base))
            out.append(self._hive("hive unloaded", pid, n))
        for pid, q in parts.items():
            if not usable(pid):
                if pid not in known and pid not in self.pending:   # seen, not read: born under a part read
                    self.pending[pid] = (q["parent"], kind(pid) == "new")   # before (new), or there before (late)
                continue   # not read now: the base keeps what it last held
            now = held.get(pid, {})
            if pid in known:
                merged = {}
                old = base[pid]["entries"]
                for key, e in now.items():
                    o = old.get(key)
                    if o is None:
                        out.append(self._change("added", e))
                    elif bool(e.get("link")) != bool(o.get("link")):   # AL-3: a file became a link, or a link a
                        out.append(self._change("changed", e, was=o.get("sha256")))   # file, read or not
                    elif e.get("sha256") is None:   # its content not read now: the base keeps what it last read
                        e = dict(e, sha256=o.get("sha256"), triggers=o.get("triggers"))
                    elif o.get("sha256") is None:
                        out.append(self._change("read", e))
                    elif o.get("sha256") != e.get("sha256"):
                        out.append(self._change("changed", e, was=o.get("sha256")))
                    elif o.get("triggers") != e.get("triggers"):
                        out.append(self._change("rescheduled", e, was=o.get("triggers")))
                    merged[key] = e
                out += [self._change("removed", o) for key, o in old.items() if key not in now]
                now = merged
            elif kind(pid) == "new":   # a key made under one read before: its entries are added
                out += [self._change("added", e) for e in now.values()]
            elif kind(pid) == "late" and q["place"] != HIVE:   # AJ-1: its first read is its base, said once
                n = late.setdefault(q["place"], {"parts": 0, "entries": 0})
                n["parts"] += 1
                n["entries"] += len(now)
            base[pid] = dict(q, entries=now)
            self.pending.pop(pid, None)
        for pid in [p for p in base if p not in parts and gone(p)]:
            if not base[pid]["hive"] and not under(pid, unloaded, base):
                out += [self._change("removed", o) for o in base[pid]["entries"].values()]
        for pid in [p for p in base if p not in parts and gone(p)] + \
                [p for p in self.pending if p not in parts and gone(p)]:
            base.pop(pid, None)
            self.pending.pop(pid, None)
        order = PLACES + (HIVE,)
        out.sort(key=lambda c: (order.index(c["place"]), c["scope"] or "", c["name"] or "", KINDS.index(c["change"]),
                                c["key"]))
        return {"changes": out, "unread": said, "late": late, "first": False, "refused": None}

    @staticmethod
    def _change(kind, e, was=None):
        c = dict({f: e.get(f) for f in WATCH_FIELDS}, change=kind)
        if was is not None:
            c["was"] = was
        return c

    @staticmethod
    def _hive(kind, pid, n):
        return {"place": HIVE, "scope": "user", "view32": False, "name": "a user's hive", "program": None,
                "sure": None, "list": False, "link": False, "sha256": None, "triggers": None, "key": pid, "change": kind,
                "entries": n}


def _place_words(p, s):
    if s["state"] == "refused":
        return "%s refused" % p
    if s["state"] == "failed":
        return "%s failed" % p
    if s["state"] == "unread":
        return "%s not read" % p
    if s["state"] == "partly":
        return "%s %d (%s)" % (p, s["entries"], _keys_words(s))
    return "%s %d" % (p, s["entries"])


def first_line(result):
    """The first read in one ASCII line: entries per place, what is refused, what failed, the bounds it met
    (AI-4), the seconds it took."""
    if not result.get("read"):
        return os_sysmon.safe(result.get("said") or "autostart: nothing is read")
    places = result["places"]
    refused = [p for p in PLACES if places[p]["state"] == "refused"]
    failed = ["%s (%s)" % (p, places[p]["reason"]) for p in PLACES if places[p]["state"] == "failed"]
    bounds = ["%s (%s)" % (p, places[p]["reason"]) for p in PLACES if places[p]["state"] == "unread"]
    took = result.get("seconds")
    took = "in %.2f s" % took if isinstance(took, (int, float)) else "in an unknown time"
    return os_sysmon.safe("autostart round 1: %d entries %s: %s; refused: %s; failed: %s%s" % (
        len(result["entries"]), took, ", ".join(_place_words(p, places[p]) for p in PLACES),
        ", ".join(refused) or "none", "; ".join(failed) or "none",
        "; not read: %s" % "; ".join(bounds) if bounds else ""), 1000)


def change_line(round_no, c):
    """`CHANGE round 3: added service "name" (would run cmd.exe)`, ASCII; `may run` where the name is not sure,
    `a list of programs` where a Winlogon value lists more than one (AJ-3)."""
    if c["change"] in ("hive loaded", "hive unloaded"):
        return os_sysmon.safe("CHANGE round %d: %s (a user's hive, %d entries)" % (round_no, c["change"],
                                                                                  c.get("entries") or 0), 1000)
    words = '%s %s "%s"' % ("content read" if c["change"] == "read" else c["change"], c["place"], c["name"])
    if c["place"] in ("run", "runonce", "startup"):
        words += " of the %s" % c["scope"]
    if c.get("view32"):
        words += ", 32-bit view"
    if c.get("link"):
        words += ", a link (not opened or followed)"
    elif c["change"] == "added" and c.get("sha256") is None:
        words += ", content not read"
    if c.get("list"):
        words += " (a list of programs)"
    elif c.get("program"):
        words += " (%s %s)" % ("would run" if c.get("sure") is not False else "may run", c["program"])
    return os_sysmon.safe("CHANGE round %d: %s" % (round_no, words), 1000)


def late_line(round_no, late):
    """AJ-1: the parts read for the first time, taken as the base, per place: never a name, never a hive's."""
    return os_sysmon.safe("BASE round %d: taken late, none said as added: %s" % (round_no, "; ".join(
        "%s (%d key(s), %d entries)" % (p, late[p]["parts"], late[p]["entries"]) for p in PLACES if p in late)), 1000)


def unread_line(round_no, gone):
    return os_sysmon.safe("UNREAD round %d: %s" % (round_no, "; ".join("%s (%s)" % (p, gone[p]) for p in PLACES
                                                                       if p in gone)), 1000)


def main(argv=None, out=None, reader=None, sleep=None, watcher=None):
    out = out or sys.stdout
    sleep = sleep or time.sleep
    p = argparse.ArgumentParser(prog="python -m raqib.autostart",
                                description="Read Windows' autostart places, and say what changed between reads.")
    p.add_argument("--rounds", type=int, default=1, help="how many reads (1 or more; default 1)")
    p.add_argument("--every", type=float, default=5.0, help="seconds between two reads (default 5)")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 2
    if a.rounds < 1 or not math.isfinite(a.every) or a.every < 0:
        print("python -m raqib.autostart: --rounds is 1 or more and --every 0 or more", file=sys.stderr)
        return 2
    if watcher is None:   # a reader handed in reads with the process's salt; the watcher takes them so
        watcher = Watcher(_process=True) if reader is not None else Watcher()
    reader = reader or watcher.read
    first = reader()
    watcher.take(first)
    print(first_line(first), file=out, flush=True)
    if not first.get("read"):
        return 0
    for round_no in range(2, a.rounds + 1):
        sleep(a.every)
        got = watcher.take(reader())
        if got.get("refused"):
            print(os_sysmon.safe("REFUSED round %d: %s" % (round_no, got["refused"])), file=out, flush=True)
        for c in got["changes"]:
            print(change_line(round_no, c), file=out, flush=True)
        if got.get("late"):
            print(late_line(round_no, got["late"]), file=out, flush=True)
        if got["unread"]:
            print(unread_line(round_no, got["unread"]), file=out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
