"""What every capture source records the same way (M5.2 E1, ADR-0003).

The hook (capture.py) and the proxy (proxy.py) both import this module, so
the two sources cannot drift apart: a tool input is hashed, a Bash command
is read into command_head and command_programs, a path is redacted and an
output is scanned for secret patterns by the same code. Moved here from
capture.py unchanged (M5.2); capture.py keeps every name it had.

- canonical_sha256: sha256 of canonical JSON, the only form in which a tool
  input or output reaches the trace (ADR-0001 section 3).
- input_meta: the small extract of a tool input (path, url_host, and for a
  tool named Bash command_head and command_programs or command_unread).
- redact: a secret inside a path becomes [redacted:<kind>].
- output_meta / scan_output: the names of the secret patterns an output
  matched, never the text (M1.2).
- error_class: the class name of a failure (A-4), never message text.
- now_ts: the ISO-8601 UTC timestamp of a record.

Pure: stdlib only, no I/O, no network, nothing is run. This file is loaded
by path when capture.py runs as the hook script (python -I puts neither its
directory nor the checkout on sys.path), and imported as raqib.hooks.common
otherwise; it imports nothing from raqib.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import shlex
import urllib.parse

# The names capture.py has always had; it takes every one of them from here.
__all__ = (
    "ASSIGNMENT", "SHELL_WORD", "HEAD_NAME", "COMMAND_HEAD_MAX", "PROGRAMS_MAX", "PROGRAMS_DEPTH_MAX",
    "C_SHELLS", "BUILTIN_NAMES", "SKIP_WORDS", "UNREAD_WORDS", "NAME_WORD", "FD_REDIRECT", "REDIRECTS",
    "OPERATORS", "BLANKS", "WORD_END", "LEADING_WORD", "CLASS_NAME", "ERROR_CLASS_MAX", "SECRET_PATTERNS",
    "PLACEHOLDER_MARKERS", "PLACEHOLDER_MIN_DISTINCT", "MIXED_KINDS", "NO_DISTINCT_CHECK", "SCAN_MAX_CHARS",
    "COMMAND_SCAN_MAX", "canonical_sha256", "tool_use_id", "command_head", "looks_like_key",
    "command_programs", "redact", "input_meta", "error_class", "strings_in", "scan_output", "secret_part",
    "is_placeholder", "is_sample_jwt", "output_meta", "now_ts",
)

# A-1: leading shell assignments (NAME=value) are not the command. Words are
# read with shell quoting, so `A="x y" gh` has the head gh, never a fragment
# of the quoted value (M1.2 review F1).
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
SHELL_WORD = re.compile(
    r"""\s*((?:[^\s'"\\]|\\.|'[^']*'|"(?:[^"\\]|\\.)*")+)(?=\s|\Z)""", re.S)
HEAD_NAME = re.compile(r"[A-Za-z0-9_.+\[-]{1,64}\Z")
COMMAND_HEAD_MAX = 64

# M4.2 E1 (ADR-0002 Amendment D, ruling D-9): command_programs, the basename
# of every program a Bash command runs, read statically (nothing is run, no
# argument is kept). See command_programs() for what is read and what makes
# the list absent.
PROGRAMS_MAX = 64          # distinct names; more: the list is absent (D-9)
PROGRAMS_DEPTH_MAX = 8     # nested $(...) levels; deeper: the list is absent
C_SHELLS = ("bash", "sh")  # whose -c string is read, one level deep
BUILTIN_NAMES = (":", ".")  # program names outside HEAD_NAME (ruling E-5)
# Reserved words skipped in command position (D-9 / Q12) ...
SKIP_WORDS = frozenset(("if", "then", "else", "elif", "fi", "while", "until", "do", "done",
                        "!", "{", "}", "time"))
# ... and the other reserved words of bash, which make the list absent.
UNREAD_WORDS = frozenset(("for", "case", "esac", "select", "function", "coproc", "in", "[[", "]]"))
NAME_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")   # an assignment, as the shell reads it
FD_REDIRECT = re.compile(r"[0-9]+(?=[<>])")
REDIRECTS = ("&>>", "<<<", "<<-", "&>", ">>", ">|", ">&", "<&", "<>", "<<", ">", "<")
OPERATORS = ("&&", "||", "|&", "|", ";", "&")
BLANKS = " \t"
WORD_END = " \t\n;&|<>()"

# A-4: a whole class name ending in Error or Exception, such as the leading
# "TimeoutError" of "TimeoutError: ..." or a structured error's type; anything
# else, or a name over 64 chars, is recorded as "failure". Never message text.
LEADING_WORD = re.compile(r"\s*([A-Za-z0-9_.]+)")
CLASS_NAME = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_.]*)?(?:Error|Exception)\Z")
ERROR_CLASS_MAX = 64

# M1.2: names of the secret patterns found in a tool's output. Only the names
# reach the trace, never the matched text (A-5: no raw content). Every pattern
# runs in linear time: an unbounded repeat is either last in the pattern or
# cannot overlap the next start (review F8).
SECRET_PATTERNS = tuple((name, re.compile(rx)) for name, rx in (
    ("auth_header", r"(?i:\bauthorization)[\"']?\s{0,8}[:=]\s{0,8}[\"']?"
                    r"(?i:bearer|basic|token)\s{1,8}[A-Za-z0-9._~+/=-]{16,}"),
    ("aws_access_key_id", r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])"),
    ("aws_secret_access_key", r"(?i:aws_?secret_?access_?key)[\"']?\s{0,8}[:=]\s{0,8}[\"']?"
                              r"[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"),
    ("github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"),
    ("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{34,}"),
    ("jwt", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    # A header line alone (library code, docs) is not a key: key material
    # must follow, possibly after PEM/PGP header lines.
    # Lines end at a newline, real or JSON-escaped; a header line cannot hold
    # one, so each line is matched one way only (REDO 2 review 4.1).
    ("private_key", r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
                    r"(?:[ \t]*(?:\r?\n|(?:\\r)?\\n)){1,3}"
                    r"(?:[A-Za-z][A-Za-z-]{0,30}:[^\r\n\\]{0,200}(?:\r?\n|(?:\\r)?\\n)){0,8}"
                    r"(?:[ \t]*(?:\r?\n|(?:\\r)?\\n)){0,2}"
                    r"[ \t]*[A-Za-z0-9+/=]{40}"),
    ("pypi_token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    ("sk_api_key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    ("slack_token", r"\bxox[abeprs]-[0-9A-Za-z-]{10,}"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[0-9A-Z]{6,12}/B[0-9A-Z]{6,12}/[0-9A-Za-z]{20,}"),
    ("stripe_key", r"\b[rs]k_live_[0-9A-Za-z]{20,}"),
    ("url_credentials", r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s/:@\"'<>]{1,128}:[^\s/@\"'<>]{1,256}@[A-Za-z0-9.-]"),
))
# Text that marks a match as a placeholder or a documentation sample (review
# F6). Letters are matched all-lower or all-upper, so a random token rarely
# contains one by chance.
PLACEHOLDER_MARKERS = ("example", "xxxx", "your", "placeholder", "dummy", "sample", "redacted",
                       "changeme", "change_me", "password", "passwd", "secret", "fake", "test",
                       "${", "{{", "***", "...")
PLACEHOLDER_MIN_DISTINCT = 8  # fewer distinct characters: AKIAXXXX..., sk-aaaa...
# sk- keys mix digits and letters; kebab-case names do not.
MIXED_KINDS = ("sk_api_key",)
# A short real password has few distinct characters; only markers apply.
NO_DISTINCT_CHECK = ("url_credentials",)
SCAN_MAX_CHARS = 1 << 20      # characters of one post's output that are scanned (F10)
COMMAND_SCAN_MAX = 1 << 16    # characters of a Bash command read for its head


def canonical_sha256(value):
    """sha256 hex of canonical JSON: sorted keys, no whitespace, ASCII escapes."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def tool_use_id(value):
    """The pairing key (A-2) if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def command_head(command):
    """A-1: basename of the first word of a Bash command, skipping leading
    NAME=value assignments. Words follow shell quoting (`"rm"` and `\\rm` are
    rm). None, so that rules see "unknown" rather than a wrong or secret head,
    when the head cannot be read safely: unbalanced quotes, a word glued to an
    operator or substitution (`ls;rm`, `$(x)`), a name that is not made of
    [A-Za-z0-9_.+[-] or is over 64 chars, or one that looks like a key (it
    matches a secret pattern, or is 16+ chars mixing digits and both cases)."""
    if not isinstance(command, str):
        return None
    text = command[:COMMAND_SCAN_MAX]
    pos = 0
    while True:
        match = SHELL_WORD.match(text, pos)
        if match is None:
            return None
        if match.end() == len(text) and len(text) < len(command):
            return None  # the word may go on past the part that was read
        raw, pos = match.group(1), match.end()
        if ASSIGNMENT.match(raw):
            continue
        if len(raw) > 4 * COMMAND_HEAD_MAX:
            return None
        try:
            (word,) = shlex.split(raw)
        except ValueError:
            return None
        if not word:
            return None  # an empty quoted word ('' x) names no program
        # basename(1): trailing slashes do not count; "/" stays "/".
        name = word.rstrip("/").rsplit("/", 1)[-1] or "/"
        if name != "/" and not HEAD_NAME.match(name):
            return None
        if looks_like_key(name):
            return None
        return name


def looks_like_key(text):
    if any(pattern.search(text) for _, pattern in SECRET_PATTERNS):
        return True
    if len(text) >= 24 and all(c in "0123456789abcdefABCDEF" for c in text):
        return True  # a hex token
    return (len(text) >= 16 and any(c.isdigit() for c in text)
            and any(c.isupper() for c in text) and any(c.islower() for c in text))


def command_programs(command):
    """M4.2 E1: the basename of every program a Bash command runs, each once,
    in first-seen order; None (the field is left out, so rules judge the line
    by command_head alone, ruling D-3) when the command cannot be read in
    full. Pure: it reads the text, runs nothing and keeps no argument (D-10).

    Read: simple commands joined by |, |&, &&, ||, ;, & or a newline; ( )
    subshells; the reserved words in SKIP_WORDS, skipped; NAME=value
    assignments and redirections in front of the program; the commands of
    every $(...) in any word, nested up to PROGRAMS_DEPTH_MAX deep; the string
    after bash -c or sh -c, one level deep (clusters such as -lc, options
    before the string; -o, -O, --rcfile and --init-file take a value); a
    here-document body is skipped. A comment (#) ends its line.

    Absent (None, D-9): not a string, or longer than COMMAND_SCAN_MAX; a
    program word that is not literal ($X, "$(which rm)", a glob such as r?, a
    brace expansion such as {rm,x}) or not a plain name (HEAD_NAME or one of
    BUILTIN_NAMES, no leading -, nothing that looks like a key); an
    expansion among the arguments of
    bash or sh before the -c string is found, or a $ or a backtick in that
    string; a reserved word in UNREAD_WORDS, (( )), $(( )), a function
    definition, an array assignment, a process substitution <(...) or
    >(...), a backtick anywhere, a quote or $ inside ${...}; an unquoted
    here-document whose body holds $( or a backtick, or one with no end line;
    unbalanced quotes or parentheses; more than PROGRAMS_MAX names."""
    if not isinstance(command, str) or len(command) > COMMAND_SCAN_MAX:
        return None
    names = []
    try:
        _ProgramReader(command, 0, names, 0, False).run(closing=False)
    except _Unread:
        return None
    return names


class _Unread(Exception):
    """The command cannot be read in full: command_programs is absent."""


def _program_name(word):
    """The basename of a literal program word, or _Unread. `:` and `.` are
    builtins and are names like any other (ruling E-5)."""
    if word in BUILTIN_NAMES:
        return word
    name = word.rstrip("/").rsplit("/", 1)[-1]
    if not name or name.startswith("-") or not HEAD_NAME.match(name) or looks_like_key(name):
        raise _Unread()
    return name


class _ProgramReader:
    """One command list of command_programs(): the whole text, a $(...) in
    it, or a bash -c string (in_c: its own bash -c strings are not read)."""

    def __init__(self, text, pos, names, depth, in_c):
        self.text, self.pos, self.names, self.depth, self.in_c = text, pos, names, depth, in_c
        self.heredocs = []  # (delimiter, strip tabs, quoted) waiting for the next newline

    def add(self, name):
        if name not in self.names:
            if len(self.names) >= PROGRAMS_MAX:
                raise _Unread()
            self.names.append(name)

    def skip_blanks(self):
        text, pos = self.text, self.pos
        while pos < len(text):
            if text[pos] in BLANKS:
                pos += 1
            elif text.startswith("\\\n", pos):
                pos += 2
            else:
                break
        self.pos = pos
        return pos

    def run(self, closing):
        """Read up to the end of the text or, when closing, the ) of this
        $(...); return the position after it."""
        text, n = self.text, len(self.text)
        subshells = 0
        cmd = {"started": False, "program": None, "shell": None, "closed": False}
        while True:
            pos = self.skip_blanks()
            if pos >= n:
                if closing or subshells or self.heredocs:
                    raise _Unread()
                return pos
            ch = text[pos]
            if ch == "\n":
                self.pos = pos + 1
                self.read_heredocs()
                cmd = {"started": False, "program": None, "shell": None, "closed": False}
                continue
            if ch == "#":
                end = text.find("\n", pos)
                self.pos = n if end < 0 else end
                continue
            if ch == ")":
                self.pos = pos + 1
                if subshells:
                    subshells -= 1
                    cmd = {"started": False, "program": None, "shell": None, "closed": True}
                    continue
                if closing and not self.heredocs:
                    return self.pos
                raise _Unread()
            if ch == "(":
                if cmd["started"] or cmd["program"] is not None or cmd["closed"] or text.startswith("((", pos):
                    raise _Unread()  # f(), a=(...), (( )), or ( after a command
                self.pos = pos + 1
                subshells += 1
                continue
            fd = FD_REDIRECT.match(text, pos)
            at = fd.end() if fd else pos
            if text[at] in "<>" and text.startswith("(", at + 1):
                raise _Unread()  # process substitution
            redirect = next((r for r in REDIRECTS if text.startswith(r, at)), None)
            if redirect is not None:
                self.redirect(redirect, at)
                cmd["started"] = True
                continue
            if text.startswith(";;", pos) or text.startswith(";&", pos):
                raise _Unread()  # case
            operator = next((o for o in OPERATORS if text.startswith(o, pos)), None)
            if operator is not None:
                self.pos = pos + len(operator)
                cmd = {"started": False, "program": None, "shell": None, "closed": False}
                continue
            word, quoted, raw = self.read_word()
            if cmd["closed"]:
                raise _Unread()  # a word after the ) of a subshell
            if cmd["program"] is None:
                if NAME_WORD.match(raw):
                    cmd["started"] = True
                    continue
                if word is not None and not quoted and not cmd["started"]:
                    if word in SKIP_WORDS:
                        continue
                    if word in UNREAD_WORDS:
                        raise _Unread()
                if word is None:
                    raise _Unread()
                name = _program_name(word)
                self.add(name)
                cmd["program"] = name
                if name in C_SHELLS and not self.in_c:
                    cmd["shell"] = {"c": False, "skip": 0, "ended": False, "done": False}
            elif cmd["shell"] is not None and not cmd["shell"]["done"]:
                self.shell_argument(cmd["shell"], word)

    def redirect(self, op, at):
        self.pos = at + len(op)
        pos = self.skip_blanks()
        if pos >= len(self.text) or self.text[pos] in WORD_END:
            raise _Unread()  # a redirection with no target
        word, quoted, _ = self.read_word()
        if op in ("<<", "<<-"):
            if not word:
                raise _Unread()
            self.heredocs.append((word, op == "<<-", quoted))

    def read_heredocs(self):
        """Skip the bodies of the here-documents opened on the line just ended."""
        text = self.text
        for delimiter, strip, quoted in self.heredocs:
            while True:
                if self.pos >= len(text):
                    raise _Unread()  # no end line
                end = text.find("\n", self.pos)
                line = text[self.pos:] if end < 0 else text[self.pos:end]
                self.pos = len(text) if end < 0 else end + 1
                if (line.lstrip("\t") if strip else line) == delimiter:
                    break
                if not quoted and ("$(" in line or "`" in line):
                    raise _Unread()  # a substitution in an unquoted body runs a command
        self.heredocs = []

    def shell_argument(self, shell, word):
        """One argument of bash or sh: an option, its value, or the -c string."""
        if word is None:
            raise _Unread()  # an expansion before the -c string is known
        if shell["skip"]:
            shell["skip"] -= 1
            return
        if not shell["ended"]:
            if word in ("--", "-"):
                shell["ended"] = True
                return
            if word.startswith("--"):
                if word in ("--rcfile", "--init-file"):
                    shell["skip"] = 1
                return
            if len(word) > 1 and word[0] in "-+":
                for ch in word[1:]:
                    if ch == "c" and word[0] == "-":
                        shell["c"] = True
                    elif ch in "oO":
                        shell["skip"] += 1
                return
        shell["done"] = True
        if shell["c"]:
            if "$" in word or "`" in word:
                raise _Unread()  # D-9: a -c string holding an expansion
            _ProgramReader(word, 0, self.names, self.depth, True).run(closing=False)

    def read_word(self):
        """(literal text or None, quoted, raw) of the word at self.pos. The
        commands of every $(...) in it are read on the way."""
        text, n = self.text, len(self.text)
        start = pos = self.pos
        out = []
        literal, quoted, glob, brace, bracket = True, False, False, False, False
        while pos < n:
            ch = text[pos]
            if ch in WORD_END:
                break
            if ch == "\\":
                if pos + 1 >= n:
                    out.append(ch)
                    pos += 1
                elif text[pos + 1] == "\n":
                    pos += 2
                else:
                    out.append(text[pos + 1])
                    quoted = True
                    pos += 2
            elif ch == "'":
                end = text.find("'", pos + 1)
                if end < 0:
                    raise _Unread()
                out.append(text[pos + 1:end])
                quoted = True
                pos = end + 1
            elif ch == '"':
                quoted = True
                pos += 1
                while True:
                    if pos >= n:
                        raise _Unread()
                    c = text[pos]
                    if c == '"':
                        pos += 1
                        break
                    if c == "\\" and pos + 1 < n and text[pos + 1] in '$`"\\\n':
                        if text[pos + 1] != "\n":
                            out.append(text[pos + 1])
                        pos += 2
                    elif c == "$":
                        literal = False
                        pos = self.read_dollar(pos, True)
                    elif c == "`":
                        raise _Unread()
                    else:
                        out.append(c)
                        pos += 1
            elif ch == "$":
                literal = False
                pos = self.read_dollar(pos, False)
            elif ch == "`":
                raise _Unread()
            else:
                glob = glob or ch in "*?"
                bracket = bracket or ch == "["
                brace = brace or ch in "{}"
                out.append(ch)
                pos += 1
        self.pos = pos
        word = "".join(out)
        if glob or (bracket and word != "[") or (brace and word not in ("{", "}")):
            literal = False
        return (word if literal else None), quoted, text[start:pos]

    def read_dollar(self, pos, in_double):
        """Read the expansion at text[pos] == "$"; return the position after
        what was read. $(...) is read as a command list."""
        text, n = self.text, len(self.text)
        nxt = text[pos + 1] if pos + 1 < n else ""
        if nxt == "(":
            if text.startswith("((", pos + 1) or self.depth >= PROGRAMS_DEPTH_MAX:
                raise _Unread()  # $(( )), or nested too deep
            return _ProgramReader(text, pos + 2, self.names, self.depth + 1, self.in_c).run(closing=True)
        if nxt == "{":
            p = pos + 2
            while p < n:
                c = text[p]
                if c == "}":
                    return p + 1
                if c in "$`'\"":
                    raise _Unread()
                p += 2 if c == "\\" else 1
            raise _Unread()
        if nxt == "'" and not in_double:  # $'...': ANSI-C quoting, \' does not end it
            p = pos + 2
            while p < n and text[p] != "'":
                p += 2 if text[p] == "\\" else 1
            if p >= n:
                raise _Unread()
            return p + 1
        return pos + 1  # $name, $1, $?, $"...": the rest is read as text


def redact(text):
    """text with every non-placeholder secret match replaced by
    [redacted:<kind>], so a path keeps its place but not the secret."""
    for name, pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(0) if is_placeholder(name, m.group(0))
                           else "[redacted:%s]" % name, text)
    return text


def input_meta(tool, tool_input):
    """Small rule-relevant extract of tool_input: {path?, command_head?,
    command_programs? | command_unread?, url_host?}. A Bash line carries
    command_programs, or command_unread: true when its programs could not be
    read (ruling E-5), so it never looks like a line written before M4.2."""
    meta = {}
    if not isinstance(tool_input, dict):
        return {"command_unread": True} if tool == "Bash" else meta
    if tool == "Bash":
        head = command_head(tool_input.get("command"))
        if head is not None:
            meta["command_head"] = head
        programs = command_programs(tool_input.get("command"))
        if programs is not None:
            meta["command_programs"] = programs
        else:
            meta["command_unread"] = True
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            meta["path"] = redact(value)
            break
    url = tool_input.get("url")
    if isinstance(url, str):
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            meta["url_host"] = host
    return meta


def error_class(error):
    """A-4: the exception class name of a PostToolUseFailure error, else "failure"."""
    if isinstance(error, dict):
        candidates = [error.get(key) for key in ("type", "name", "class")]
    elif isinstance(error, str):
        match = LEADING_WORD.match(error)
        candidates = [match.group(1)] if match else []
    else:
        candidates = []
    for value in candidates:
        if (isinstance(value, str) and len(value) <= ERROR_CLASS_MAX
                and CLASS_NAME.match(value)):
            return value
    return "failure"


def strings_in(value):
    """Every string in a JSON value (keys included), depth-first."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            # Pushed in reverse, so strings come out in document order and a
            # capped scan covers the start of the output.
            for key, val in reversed(list(item.items())):
                stack.append(val)
                stack.append(key)
        elif isinstance(item, list):
            stack.extend(reversed(item))


def scan_output(values, limit=SCAN_MAX_CHARS):
    """(kinds found, placeholder-only kinds, complete) over every string of
    values, scanning at most `limit` characters in all (None: no cap)."""
    found, placeholders = set(), set()
    budget = limit
    complete = True
    for value in values:
        for text in strings_in(value):
            if budget is not None:
                if budget <= 0:
                    return sorted(found), sorted(placeholders - found), False
                if len(text) > budget:
                    text, complete = text[:budget], False
                budget -= len(text) + 1
            for name, pattern in SECRET_PATTERNS:
                if name in found:
                    continue
                for match in pattern.finditer(text):
                    if is_placeholder(name, match.group(0)):
                        placeholders.add(name)
                    else:
                        found.add(name)
                        break
    return sorted(found), sorted(placeholders - found), complete


def secret_part(name, text):
    """The part of a match that is the secret itself, without key names."""
    if name in ("aws_secret_access_key", "private_key"):
        return text[-40:]
    if name == "auth_header":
        return text.split()[-1]
    if name == "url_credentials":
        # The password only: a user name such as "testuser" says nothing.
        return text[text.index("://") + 3:text.rindex("@")].split(":", 1)[1]
    return text


def is_placeholder(name, text):
    """True if a match looks like a placeholder or a published sample (F6)."""
    part = secret_part(name, text)
    for marker in PLACEHOLDER_MARKERS:
        if marker in part or marker.upper() in part:
            return True
    if name not in NO_DISTINCT_CHECK and len(set(part)) < PLACEHOLDER_MIN_DISTINCT:
        return True
    if name in MIXED_KINDS and not (any(c.isdigit() for c in part) and any(c.isalpha() for c in part)):
        return True
    return name == "jwt" and is_sample_jwt(part)


def is_sample_jwt(token):
    """The jwt.io sample token: payload {"sub": "1234567890", "name": "John Doe", ...}."""
    try:
        body = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (IndexError, ValueError):
        return False
    return (isinstance(claims, dict) and claims.get("sub") == "1234567890"
            and claims.get("name") == "John Doe")


def output_meta(payload):
    """output_meta of a post line from payload's tool_response and error:
    scan full, partial or none, secret_kinds, placeholder_kinds (the shapes
    are listed in capture.py's module docstring, M1.2)."""
    values = [payload[key] for key in ("tool_response", "error") if payload.get(key) is not None]
    if not values:
        return {"scan": "none"}
    kinds, placeholders, complete = scan_output(values)
    meta = {"scan": "full" if complete else "partial"}
    if complete or kinds:
        meta["secret_kinds"] = kinds
    if placeholders:
        meta["placeholder_kinds"] = placeholders
    return meta


def now_ts():
    """The record's ts: ISO-8601 UTC with milliseconds and a Z."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
