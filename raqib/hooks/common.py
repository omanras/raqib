"""What every capture source records the same way (M5.2 E1, ADR-0003).

The hook (capture.py) and the proxy (proxy.py) both import this module, so
the two sources cannot drift apart: a tool input is hashed, a Bash command
is read into command_head and command_programs, a path is redacted and an
output is scanned for secret patterns by the same code. Moved here from
capture.py unchanged (M5.2); capture.py keeps every name it had.

- canonical_sha256: sha256 of canonical JSON, the only form in which a tool
  input or output reaches the trace (ADR-0001 section 3).
- input_meta: the small extract of a tool input (path, url_host, and for a
  tool named Bash command_head and command_programs or command_unread; since
  M4.2b also command_scripts and commit_prefix when there is one, ADR-0002
  Amendment G).
- redact: a secret inside a path becomes [redacted:<kind>].
- output_meta / scan_output: the names of the secret patterns an output
  matched, never the text (M1.2).
- error_class: the class name of a failure (A-4), never message text.
- now_ts: the ISO-8601 UTC timestamp of a record.
- git_state (M4.3, ADR-0002 Amendment J): the local git state of a cwd,
  read from files, for the hook's session_start, stop and session_end lines.

Pure but for git_state: stdlib only, no I/O, no network, nothing is run.
git_state is this file's one file reader (J-10): it reads at most a few
files under cwd/.git, executes nothing, and only capture.py calls it (the
proxy never does). This file is loaded
by path when capture.py runs as the hook script (python -I puts neither its
directory nor the checkout on sys.path), and imported as raqib.hooks.common
otherwise; it imports nothing from raqib.
"""
from __future__ import annotations

import base64
import datetime
import errno
import hashlib
import json
import os
import re
import shlex
import stat
import time
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
    # M4.2b (ADR-0002 Amendment G)
    "PYTHONS", "PYTHON_VALUE_OPTIONS", "PYTHON_VALUE_LONG", "PYTHON_NO_SCRIPT", "SHELL_NO_SCRIPT",
    "SCRIPTS_MAX", "COMMIT_PREFIX", "COMMIT_PREFIX_MAX", "GIT_VALUE_OPTIONS", "COMMIT_FLAGS",
    "COMMIT_VALUE_LONG", "COMMIT_NOT_READ", "HEREDOC_MESSAGE", "HEAD_TARGET_STOP", "read_command",
    "command_scripts", "commit_prefix", "SCRIPT_WRAPPERS", "TIMEOUT_VALUE_OPTIONS", "SOURCES",
    # M4.3 (ADR-0002 Amendment J)
    "GIT_KEYS", "GIT_ERRORS", "GIT_BUDGET_SECONDS", "GIT_FILE_MAX", "GIT_INDEX_MAX", "GIT_CHUNK", "GIT_HEX40",
    "GIT_HEX64", "GIT_DEVICE_NAMES", "GIT_READ_ERRORS", "git_state",
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

# M4.2b (ADR-0002 Amendment G), read by the same reader as command_programs.
# command_scripts (G-2, G-9): the basename of the script OPERAND of a python
# or python3 call (ending .py) and of a bash or sh call (ending .sh); never
# another argument. -c and -m (python), -c and -s (bash, sh) mean no script.
PYTHONS = ("python", "python3", "python.exe", "py", "py.exe")   # H-1: the Windows names too
PYTHON_VALUE_OPTIONS = "WX"                  # -W arg, -X opt: the value is glued or the next word
PYTHON_VALUE_LONG = ("--check-hash-based-pycs",)
PYTHON_NO_SCRIPT = "cm"                      # -c CODE, -m MODULE
SHELL_NO_SCRIPT = "cs"                       # -c STRING, -s (commands on stdin)
SCRIPTS_MAX = 64                             # distinct names; more: the command is not read (as D-9)
# H-1: for command_scripts only, these wrappers pass through to the command
# they run, one level: `timeout [opts] N cmd`, `nohup cmd`, `env cmd` (env
# with no option and no NAME=value). `.` and `source` record their script.
SCRIPT_WRAPPERS = ("timeout", "nohup", "env")
TIMEOUT_VALUE_OPTIONS = ("-s", "-k", "--signal", "--kill-after")
SOURCES = (".", "source")
# commit_prefix (G-3, G-4): the first word of the first -m message of the
# first `git ... commit` simple command, written only when it is a lower-case
# word ending in ":" of at most COMMIT_PREFIX_MAX characters.
COMMIT_PREFIX = re.compile(r"[a-z]+:\Z")
COMMIT_PREFIX_MAX = 16
GIT_VALUE_OPTIONS = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
                     "--attr-source")        # git's options before the subcommand that take the next word
COMMIT_FLAGS = "apsneiovqz"                  # git commit's short options without a value
COMMIT_VALUE_LONG = ("--author", "--date", "--cleanup", "--trailer", "--fixup", "--squash", "--template",
                     "--pathspec-from-file")  # long options of git commit that take the next word
COMMIT_NOT_READ = ("--amend", "--file", "--reuse-message", "--reedit-message")   # and -F, -C, -c (G-4)
# A message given as "$(cat <<'EOF' ... EOF)": a quoted delimiter, so the body
# is literal text (G-4). Group 1 is "-" for <<-, groups 2-4 the delimiter.
HEREDOC_MESSAGE = re.compile(
    r"\"\$\([ \t]*cat[ \t]+<<(-?)[ \t]*(?:'([^'\n]+)'|\"([^\"\n$`\\]+)\"|\\([A-Za-z0-9_]+))[ \t]*\n")

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
    NAME=value assignments and, since M4.2b (ruling E-12), leading
    redirections with their targets (`2>/dev/null rm x` has the head rm).
    Words follow shell quoting (`"rm"` and `\\rm` are rm). None, so that
    rules see "unknown" rather than a wrong or secret head, when the head
    cannot be read safely: unbalanced quotes, a word glued to an operator or
    substitution (`ls;rm`, `$(x)`), a leading redirection with no target or
    one whose target holds ; & | ( ) < > or a backtick, a name that is not made
    of [A-Za-z0-9_.+[-] or is over 64 chars, or one that looks like a key (it
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
        target = _leading_redirect(raw)
        if target is not None:   # E-12: [n]op target, glued or as the next word
            if target == "":
                match = SHELL_WORD.match(text, pos)
                if match is None or (match.end() == len(text) and len(text) < len(command)):
                    return None
                target, pos = match.group(1), match.end()
            if any(c in target for c in HEAD_TARGET_STOP):
                return None
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


HEAD_TARGET_STOP = ";&|()<>`"   # in a leading redirection's target: the head is not read (E-12)


def _leading_redirect(raw):
    """The target text of a word that is a redirection ([n]op target, "" when
    the target is the next word), or None when the word is not one."""
    fd = FD_REDIRECT.match(raw)
    at = fd.end() if fd else 0
    op = next((r for r in REDIRECTS if raw.startswith(r, at)), None)
    return None if op is None else raw[at + len(op):]


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
    unbalanced quotes or parentheses; more than PROGRAMS_MAX names; since
    M4.2b, more than SCRIPTS_MAX distinct script names (command_scripts)."""
    read = read_command(command)
    return None if read is None else read[0]


def read_command(command):
    """M4.2b (ADR-0002 Amendment G): (programs, scripts, prefix) of a Bash
    command in one reading, or None when it cannot be read in full (the
    cases of command_programs). programs is command_programs; scripts is
    command_scripts' list ([] when none); prefix is commit_prefix's word or
    None. Pure, like command_programs: nothing is run."""
    if not isinstance(command, str) or len(command) > COMMAND_SCAN_MAX:
        return None
    found = _Found()
    try:
        _ProgramReader(command, 0, found, 0, False).run(closing=False)
    except _Unread:
        return None
    return found.names, found.scripts, found.prefix


def command_scripts(command):
    """G-2: the basename of the script operand of every python call (PYTHONS:
    python, python3, python.exe, py, py.exe; a word ending .py) and every
    bash or sh call (a word ending .sh) that the reader of command_programs
    reads (top level, $(...), a bash -c string), each once, in first-seen
    order. The operand is the first word after the options and their values:
    python's -W and -X (glued or the next word) and --check-hash-based-pycs
    take a value, -- ends the options, and -c, -m or - mean there is no
    script; bash's and sh's -o, -O, +o, +O, --rcfile and --init-file take a
    value, -- and - end the options, and -c or -s mean there is no script. A
    word that is not literal where the operand could be ends the search:
    nothing is recorded for that call.

    H-1 (ADR-0002 Amendment H): the basename is split on / and on a backslash, and a
    backslash outside quotes is kept for it (`python -I tools\\gate.py`, as a
    Windows shell passes it, records gate.py; the shell's own reading drops
    that backslash). For scripts only, SCRIPT_WRAPPERS pass through one level
    to the command they run (timeout's options and its duration are skipped;
    env only with no option and no NAME=value): a python or shell call there
    is read as above, and a command word ending .py or .sh is recorded
    itself (`timeout 900 tools/gate.sh` records gate.sh). `.` and `source`
    record their script when it ends .sh. Basename only, under the name rules
    of a program (HEAD_NAME, no leading -, nothing that looks like a key). []
    when there is none; None when the command cannot be read (G-9:
    input_meta writes the key only when the list is not empty)."""
    read = read_command(command)
    return None if read is None else read[1]


def commit_prefix(command):
    """G-3, G-4: the first word of the message of the first `git ... commit`
    simple command, when it matches COMMIT_PREFIX (a lower-case word ending
    in ":") and has at most COMMIT_PREFIX_MAX characters; else None.

    git's options before the subcommand are skipped, those of
    GIT_VALUE_OPTIONS with the next word. The message is the value of the
    first non-empty (H-4: git drops an empty one) of -m MSG, -mMSG,
    --message=MSG, --message MSG, or a cluster of COMMIT_FLAGS ending in m
    (-am MSG; -amMSG likewise), read with shell quoting; a value that is not
    literal counts as not empty. --no-message, which makes git forget the
    messages before it, is not read (a listed hole). Its first word counts only when it lies in literal text (before
    any $), or when the whole value is "$(cat <<'EOF' ... EOF)" with a quoted
    delimiter ('EOF', "EOF" or \\EOF; <<- strips tabs), whose body is read as
    text (HEREDOC_MESSAGE). Leading blank lines do not count, as git strips
    them. Only the first commit of the command is read (a later one is not).
    None (not read) for that first commit when it has --amend, -F/--file,
    -C/--reuse-message or -c/--reedit-message (COMMIT_NOT_READ), a word
    that is not literal among its options (before --), a value-taking
    option with no value, or a message that is not read as above (an
    unquoted delimiter, an expansion before the first word ends); and when
    the command cannot be read in full."""
    read = read_command(command)
    return None if read is None else read[2]


class _Unread(Exception):
    """The command cannot be read in full: command_programs is absent."""


class _Found:
    """What one reading of a command found: program names, script names and
    the commit prefix (claimed by the first git commit simple command)."""

    def __init__(self):
        self.names, self.scripts = [], []
        self.commit_claimed = False
        self.prefix = None

    def add_script(self, name):
        if name not in self.scripts:
            if len(self.scripts) >= SCRIPTS_MAX:
                raise _Unread()
            self.scripts.append(name)


def _program_name(word):
    """The basename of a literal program word, or _Unread. `:` and `.` are
    builtins and are names like any other (ruling E-5)."""
    if word in BUILTIN_NAMES:
        return word
    name = word.rstrip("/").rsplit("/", 1)[-1]
    if not name or name.startswith("-") or not HEAD_NAME.match(name) or looks_like_key(name):
        raise _Unread()
    return name


def _script_name(path):
    """The basename of a script word, split on / and on \\ (H-1), under the
    name rules of a program, or None (not recorded; the command stays
    readable)."""
    name = re.split(r"[/\\]", path.rstrip("/\\"))[-1]
    if not name or name.startswith("-") or not HEAD_NAME.match(name) or looks_like_key(name):
        return None
    return name


def _base(path):
    """The last part of a word split on / and on \\ (H-1)."""
    return re.split(r"[/\\]", path.rstrip("/\\"))[-1]


class _Wrapped:
    """H-1: the words of one timeout/nohup/env (SCRIPT_WRAPPERS) or ./source
    (SOURCES) simple command, for command_scripts only. Once the wrapped
    command word is found it hands over to an _Operand (a python or shell
    call) or records the word itself (a script); one level, never a second
    wrapper."""

    def __init__(self, program):
        self.program, self.skip, self.duration, self.done, self.operand = program, 0, False, False, None

    def feed(self, word, path, raw, found):
        if self.operand is not None:
            self.operand.feed(word, path, found)
            return
        if self.done:
            return
        if word is None:
            self.done = True
            return
        if self.skip:
            self.skip -= 1
            return
        if self.program in SOURCES:
            if word == "--":
                return
            self.record(path, ".sh", found)
            return
        if self.program == "timeout":
            if not self.duration:
                if word in TIMEOUT_VALUE_OPTIONS:
                    self.skip = 1
                elif word.startswith("-") and len(word) > 1:
                    pass              # --preserve-status, --foreground, -v, --signal=SIG
                else:
                    self.duration = True
                return
        elif self.program == "nohup":
            if word == "--":
                return
        elif word.startswith("-") or NAME_WORD.match(raw):
            self.done = True          # env with an option or an assignment is not read (H-1)
            return
        self.done = True
        name = _base(path)
        if name in PYTHONS or name in C_SHELLS:
            self.operand = _Operand(".py" if name in PYTHONS else ".sh")
        elif name.endswith((".py", ".sh")):
            self.record(path, name[-3:], found)

    def record(self, path, suffix, found):
        self.done = True
        if path.endswith(suffix):
            name = _script_name(path)
            if name is not None:
                found.add_script(name)


class _Operand:
    """G-2: the script operand of one python/python3 (suffix .py) or bash/sh
    (suffix .sh) simple command, fed one argument word at a time."""

    def __init__(self, suffix):
        self.suffix, self.skip, self.ended, self.done = suffix, 0, False, False

    def feed(self, word, path, found):
        if self.done:
            return
        if word is None:
            self.done = True   # not literal: an option or the operand, it cannot be told
            return
        if self.skip:
            self.skip -= 1
            return
        if not self.ended and self.option(word):
            return
        self.done = True
        if path.endswith(self.suffix):
            name = _script_name(path)   # H-1: split on / and \, unquoted backslashes kept
            if name is not None:
                found.add_script(name)

    def option(self, word):
        """True when word is an option (or ends the options); may end the search."""
        if self.suffix == ".py":
            if word == "--":
                self.ended = True
                return True
            if word == "-":
                self.done = True   # the program is read from stdin
                return True
            if word.startswith("--"):
                if word in PYTHON_VALUE_LONG:
                    self.skip = 1
                return True
            if len(word) > 1 and word[0] == "-":
                for i, ch in enumerate(word[1:], 1):
                    if ch in PYTHON_NO_SCRIPT:
                        self.done = True
                        return True
                    if ch in PYTHON_VALUE_OPTIONS:
                        if i + 1 == len(word):
                            self.skip = 1
                        return True
                return True
            return False
        if word in ("--", "-"):
            self.ended = True
            return True
        if word.startswith("--"):
            if word in ("--rcfile", "--init-file"):
                self.skip = 1
            return True
        if len(word) > 1 and word[0] in "-+":
            for ch in word[1:]:
                if word[0] == "-" and ch in SHELL_NO_SCRIPT:
                    self.done = True
                    return True
                if ch in "oO":
                    self.skip += 1
            return True
        return False


class _Commit:
    """G-4: the arguments of one git simple command, fed one word at a time;
    finish() writes the commit prefix when this is the first commit."""

    def __init__(self):
        self.stage = "global"   # global: git's own options; args: commit's; done
        self.skip = 0
        self.claimed = False
        self.bad = False        # not read (COMMIT_NOT_READ, a non-literal option word, ...)
        self.ended = False      # after --: pathspecs
        self.want = False       # the next word is the message
        self.first = None       # the message's first word, once read
        self.message_seen = False

    def feed(self, word, raw, last, found):
        if self.stage == "global":
            if word is None:
                self.stage = "done"   # the subcommand cannot be told
            elif self.skip:
                self.skip -= 1
            elif word in GIT_VALUE_OPTIONS:
                self.skip = 1
            elif word.startswith("-"):
                pass                  # a flag, or --option=value
            elif word == "commit" and not found.commit_claimed:
                found.commit_claimed = self.claimed = True
                self.stage = "args"
            else:
                self.stage = "done"
            return
        if self.stage != "args" or self.ended:
            return
        if self.want:
            self.want = False
            self.message(word, raw, last, 0)
            return
        if self.skip:
            self.skip -= 1
            return
        if word is None:
            # -m"$(cat <<'EOF' ...)" or --message="$X": an -m form whose value is not literal.
            text, prefix_end, globbed = last
            lit = text[:prefix_end] if prefix_end is not None and not globbed else ""
            form = re.match(r"--message=|-[%s]*m" % COMMIT_FLAGS, lit)
            if form is not None and raw.startswith(form.group(0)):
                self.message(None, raw, last, form.end())
            else:
                self.bad = True       # it could be --amend or -F
            return
        if word == "--":
            self.ended = True
            return
        if word.startswith("--"):
            name, eq, _ = word.partition("=")
            if name == "--message":
                if eq:
                    self.message(word, raw, last, len("--message="))
                else:
                    self.want = True
            elif name in COMMIT_NOT_READ:
                self.bad = True
            elif name in COMMIT_VALUE_LONG and not eq:
                self.skip = 1
            return
        if len(word) > 1 and word[0] == "-":
            for i, ch in enumerate(word[1:], 1):
                if ch == "m":
                    if i + 1 < len(word):
                        self.message(word, raw, last, i + 1)
                    else:
                        self.want = True
                    return
                if ch in "FCc":
                    self.bad = True
                    return
                if ch == "t":         # -t FILE (template): the value is glued or the next word
                    if i + 1 == len(word):
                        self.skip = 1
                    return
                if ch not in COMMIT_FLAGS:
                    return            # -S[keyid], -u[mode]: the rest is their value
            return

    def message(self, word, raw, last, offset):
        """The value of an -m form: the word from offset on. The first -m
        that is not empty is the first paragraph: git drops an empty one
        (H-4), so `-m '' -m 'landed: x'` is read as landed:."""
        if self.message_seen:
            return
        text, prefix_end, globbed = last
        if word is not None:
            value = word[offset:]
            if value.split():
                self.message_seen = True
                self.first = _first_word(value, True)
            return
        self.message_seen = True      # not literal: whether it is empty cannot be told
        if globbed:
            return
        if prefix_end is not None and prefix_end >= offset:
            self.first = _first_word(text[offset:prefix_end], False)
        if self.first is None and raw[:offset] == text[:offset]:
            body = _heredoc_message(raw[offset:])
            if body is not None and not body.split():
                self.message_seen = False   # an empty here-document is an empty -m (H-4)
            elif body is not None:
                self.first = _first_word(body, True)

    def finish(self, found):
        if not self.claimed or self.stage != "args":
            return
        if self.bad or self.want or self.skip or self.first is None:
            return
        if COMMIT_PREFIX.match(self.first) and len(self.first) <= COMMIT_PREFIX_MAX:
            found.prefix = self.first


def _first_word(text, whole):
    """The first word of a message's literal text; when the text is only a
    prefix (whole False), the word must end before the text does."""
    match = re.match(r"\s*(\S+)(\s|\Z)", text)
    if match is None or (not whole and match.group(2) == ""):
        return None
    return match.group(1)


def _heredoc_message(raw):
    """The body of a value written "$(cat <<'EOF' ... EOF)" with a quoted
    delimiter (HEREDOC_MESSAGE), else None. Read as text: nothing is run."""
    match = HEREDOC_MESSAGE.match(raw)
    if match is None:
        return None
    strip = match.group(1) == "-"
    delimiter = next(g for g in match.groups()[1:] if g is not None)
    body = []
    rest = raw[match.end():]
    while True:
        end = rest.find("\n")
        if end < 0:
            return None               # no end line
        line, rest = rest[:end], rest[end + 1:]
        if strip:
            line = line.lstrip("\t")
        if line == delimiter:
            break
        body.append(line)
    if not re.match(r"[ \t\n]*\)\"\Z", rest):
        return None
    return "\n".join(body)


class _ProgramReader:
    """One command list of command_programs(): the whole text, a $(...) in
    it, or a bash -c string (in_c: its own bash -c strings are not read)."""

    def __init__(self, text, pos, found, depth, in_c):
        self.text, self.pos, self.found, self.depth, self.in_c = text, pos, found, depth, in_c
        self.heredocs = []  # (delimiter, strip tabs, quoted) waiting for the next newline
        self.last = ("", None, False)  # of the last word read: (text, end of its literal prefix, globbed)
        self.last_path = ""            # the same text with its unquoted backslashes kept (H-1)

    def add(self, name):
        names = self.found.names
        if name not in names:
            if len(names) >= PROGRAMS_MAX:
                raise _Unread()
            names.append(name)

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

    def new_command(self, cmd, closed=False):
        """End the simple command cmd (M4.2b: its commit, if any) and start
        the next one."""
        if cmd is not None and cmd["git"] is not None:
            cmd["git"].finish(self.found)
        return {"started": False, "program": None, "shell": None, "closed": closed, "operand": None,
                "git": None}

    def run(self, closing):
        """Read up to the end of the text or, when closing, the ) of this
        $(...); return the position after it."""
        text, n = self.text, len(self.text)
        subshells = 0
        cmd = self.new_command(None)
        while True:
            pos = self.skip_blanks()
            if pos >= n:
                if closing or subshells or self.heredocs:
                    raise _Unread()
                self.new_command(cmd)
                return pos
            ch = text[pos]
            if ch == "\n":
                self.pos = pos + 1
                self.read_heredocs()
                cmd = self.new_command(cmd)
                continue
            if ch == "#":
                end = text.find("\n", pos)
                self.pos = n if end < 0 else end
                continue
            if ch == ")":
                self.pos = pos + 1
                if subshells:
                    subshells -= 1
                    cmd = self.new_command(cmd, closed=True)
                    continue
                if closing and not self.heredocs:
                    self.new_command(cmd)
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
                cmd = self.new_command(cmd)
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
                if name in PYTHONS or name in C_SHELLS:   # M4.2b G-2
                    cmd["operand"] = _Operand(".py" if name in PYTHONS else ".sh")
                elif name in SCRIPT_WRAPPERS or name in SOURCES:   # H-1
                    cmd["operand"] = _Wrapped(name)
                elif name == "git" and not self.found.commit_claimed:   # M4.2b G-4
                    cmd["git"] = _Commit()
                continue
            if cmd["shell"] is not None and not cmd["shell"]["done"]:
                self.shell_argument(cmd["shell"], word)
            if isinstance(cmd["operand"], _Wrapped):
                cmd["operand"].feed(word, self.last_path, raw, self.found)
            elif cmd["operand"] is not None:
                cmd["operand"].feed(word, self.last_path, self.found)
            if cmd["git"] is not None:
                cmd["git"].feed(word, raw, self.last, self.found)

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
            _ProgramReader(word, 0, self.found, self.depth, True).run(closing=False)

    def read_word(self):
        """(literal text or None, quoted, raw) of the word at self.pos. The
        commands of every $(...) in it are read on the way. self.last keeps
        the word's text, where its literal prefix ends (the first $, or None)
        and whether it holds an unquoted glob or brace (M4.2b, commit_prefix)."""
        text, n = self.text, len(self.text)
        start = pos = self.pos
        out = []
        kept = []   # H-1: out, but an unquoted backslash stays in front of its character
        literal, quoted, glob, brace, bracket = True, False, False, False, False
        prefix_end = None
        while pos < n:
            ch = text[pos]
            if ch in WORD_END:
                break
            if ch == "\\":
                if pos + 1 >= n:
                    out.append(ch)
                    kept.append(ch)
                    pos += 1
                elif text[pos + 1] == "\n":
                    pos += 2
                else:
                    out.append(text[pos + 1])
                    kept.append(text[pos:pos + 2])
                    quoted = True
                    pos += 2
            elif ch == "'":
                end = text.find("'", pos + 1)
                if end < 0:
                    raise _Unread()
                out.append(text[pos + 1:end])
                kept.append(text[pos + 1:end])
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
                            kept.append(text[pos + 1])
                        pos += 2
                    elif c == "$":
                        literal = False
                        if prefix_end is None:
                            prefix_end = sum(len(x) for x in out)
                        pos = self.read_dollar(pos, True)
                    elif c == "`":
                        raise _Unread()
                    else:
                        out.append(c)
                        kept.append(c)
                        pos += 1
            elif ch == "$":
                literal = False
                if prefix_end is None:
                    prefix_end = sum(len(x) for x in out)
                pos = self.read_dollar(pos, False)
            elif ch == "`":
                raise _Unread()
            else:
                glob = glob or ch in "*?"
                bracket = bracket or ch == "["
                brace = brace or ch in "{}"
                out.append(ch)
                kept.append(ch)
                pos += 1
        self.pos = pos
        word = "".join(out)
        globbed = glob or (bracket and word != "[") or (brace and word not in ("{", "}"))
        if globbed:
            literal = False
        self.last = (word, prefix_end, globbed)
        self.last_path = "".join(kept)
        return (word if literal else None), quoted, text[start:pos]

    def read_dollar(self, pos, in_double):
        """Read the expansion at text[pos] == "$"; return the position after
        what was read. $(...) is read as a command list."""
        text, n = self.text, len(self.text)
        nxt = text[pos + 1] if pos + 1 < n else ""
        if nxt == "(":
            if text.startswith("((", pos + 1) or self.depth >= PROGRAMS_DEPTH_MAX:
                raise _Unread()  # $(( )), or nested too deep
            return _ProgramReader(text, pos + 2, self.found, self.depth + 1, self.in_c).run(closing=True)
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
    command_programs? | command_unread?, command_scripts?, commit_prefix?,
    url_host?}. A Bash line carries command_programs, or command_unread: true
    when its programs could not be read (ruling E-5), so it never looks like
    a line written before M4.2. M4.2b (ADR-0002 Amendment G): a read Bash
    line also carries command_scripts when the list is not empty (G-9) and
    commit_prefix when there is one (G-3); neither is written otherwise, so a
    line of a command with neither is byte for byte what M4.2 wrote."""
    meta = {}
    if not isinstance(tool_input, dict):
        return {"command_unread": True} if tool == "Bash" else meta
    if tool == "Bash":
        head = command_head(tool_input.get("command"))
        if head is not None:
            meta["command_head"] = head
        read = read_command(tool_input.get("command"))
        if read is not None:
            programs, scripts, prefix = read
            meta["command_programs"] = programs
            if scripts:
                meta["command_scripts"] = scripts
            if prefix is not None:
                meta["commit_prefix"] = prefix
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


# --- M4.3 git_state (ADR-0002 Amendment J, rulings J-5 to J-10) -----------------
# The local git state of a cwd, READ FROM FILES for the hook's session_start,
# stop and session_end lines: no git process, nothing is run (a test holds
# every function of this section to that). It reads at most cwd/.git (a
# directory, or a `.git` file naming a gitdir, followed once), HEAD, the one
# ref HEAD names (the loose ref, else packed-refs) and the index (sha256 of
# its raw bytes, J-9), and records only GIT_KEYS: the 40-hex head, the
# 64-hex index hash and one string of GIT_ERRORS, never a path or a name.
GIT_KEYS = ("git_head", "git_index_sha256", "git_error")   # J-5: all three on every boundary line
# J-5, the closed set. git_error names the FIRST failure in read order (.git,
# HEAD, the ref, the index); a value read before or after it is kept:
# - "no repo": cwd/.git does not exist (nothing walks up from cwd);
# - "symlink": a symlink (or, on Windows, a junction) at any component read
#   below cwd: .git, the gitdir, HEAD, the ref, packed-refs, index (J-6);
# - "gitdir": a `.git` file that is not one `gitdir: <path>` line, or whose
#   path is not relative, resolves above or outside the cwd (K-2), is UNC or
#   a device path, or does not name a directory (J-6: such a path is never
#   opened);
# - "unreadable": one of GIT_READ_ERRORS (K-1); a file that is not a
#   regular file or is over GIT_FILE_MAX; a HEAD that is neither 40-hex nor
#   `ref: refs/...` (a reftable repository's refs/heads/.invalid, K-3); a
#   ref that is not 40-hex (a symbolic ref, a SHA-256 repository);
# - "no ref": the ref HEAD names is neither a loose file nor in packed-refs
#   (an unborn branch, J-7);
# - "no index": there is no index yet (J-7);
# - "index too large": the index is over GIT_INDEX_MAX (J-8);
# - "budget": GIT_BUDGET_SECONDS ran out; the value being read is null (J-8).
GIT_ERRORS = ("no repo", "symlink", "gitdir", "unreadable", "no ref", "no index", "index too large", "budget")
# J-8: one budget per call, measured with time.monotonic (on Windows before
# Python 3.13 it ticks about every 15.6 ms, so 50 ms is measured in such
# steps). It is checked before each file and after each chunk, so a read that
# blocks is not cut short: capture's deadline (capture.DEADLINE_SECONDS) ends
# such a capture with RAQIB-SILENCE, and the boundary line is lost (A3).
GIT_BUDGET_SECONDS = 0.05
GIT_FILE_MAX = 1 << 20        # J-8: the .git file, HEAD, a loose ref and packed-refs, each at most 1 MiB
GIT_INDEX_MAX = 64 << 20      # J-8: the index is read as at most 64 MiB + 1 bytes
GIT_CHUNK = 1 << 20           # reads go in chunks of 1 MiB, the budget checked after each
GIT_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
GIT_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
# Windows device names (J-6: a device path is never opened), checked on every
# component of a gitdir and a ref on every platform: CON, CON.txt and "CON ." are
# all the console. The superscript digits are Windows' own COM and LPT names.
GIT_DEVICE_NAMES = re.compile("(?:CON|PRN|AUX|NUL|CONIN\\$|CONOUT\\$|COM[0-9\u00b9\u00b2\u00b3]"
                              "|LPT[0-9\u00b9\u00b2\u00b3])(?:\\..*)?\\Z", re.I)
_GIT_REF_PART = re.compile(r"[^\x00-\x20\x7f~^:?*\[\\/]+\Z")   # git's check_refname_format, per component
_GIT_REF_MAX = 1024
# K-1: the failures of a read that make a value "unreadable". Nothing else is
# caught: capture's Deadline (an Exception) must end the capture (A3).
GIT_READ_ERRORS = (OSError, ValueError, UnicodeError, RecursionError, MemoryError)
_GIT_NAME_SURROGATE = 0x20000000   # a Windows reparse tag with this bit is a link (a symlink or a junction)
_GIT_MISSING = "\0missing"         # internal: a component that is not there (never recorded)
_GIT_OPEN = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))


class _GitStop(Exception):
    """A read that cannot go on; args[0] is the git_error it names."""


def git_state(cwd, clock=time.monotonic):
    """{"git_head", "git_index_sha256", "git_error"} of cwd's .git, read from
    files within GIT_BUDGET_SECONDS of clock (see GIT_ERRORS). Never runs
    anything, and opens nothing outside cwd (K-2). A read that fails with
    one of GIT_READ_ERRORS is "unreadable"; every other exception, capture's
    Deadline above all, propagates (K-1, A3): the capture then ends with its
    one RAQIB-SILENCE line and writes no record."""
    out = dict.fromkeys(GIT_KEYS)
    start = clock()

    def check():
        if clock() - start > GIT_BUDGET_SECONDS:
            raise _GitStop("budget")

    def attempt(step, *args):
        """(value, None), or (None, the git_error that stopped it)."""
        try:
            return step(*args), None
        except _GitStop as stop:
            return None, stop.args[0]
        except GIT_READ_ERRORS:   # K-1: only these; a Deadline or anything else propagates
            return None, "unreadable"

    gitdir, why = attempt(_git_dir, cwd, check)
    if why is None:
        out["git_head"], why = attempt(_git_head, gitdir, check)
        if why != "budget":
            out["git_index_sha256"], later = attempt(_git_index, gitdir, check)
            why = why or later   # J-5: the first failure is named
    out["git_error"] = why
    return out


def _git_dir(cwd, check):
    """The gitdir of cwd: cwd/.git, or the directory a `.git` file names (J-6)."""
    if not isinstance(cwd, str) or not cwd:
        raise _GitStop("no repo")
    if "\0" in cwd:
        raise _GitStop("unreadable")
    dot = os.path.join(cwd, ".git")
    check()   # K-5: a budget spent before the first lstat opens nothing
    st = _git_lstat(dot, "no repo")
    if stat.S_ISDIR(st.st_mode):
        return dot
    if not stat.S_ISREG(st.st_mode):
        raise _GitStop("unreadable")
    data = _git_small(dot, st, check, "gitdir")
    try:
        text = data.decode("utf-8").rstrip(" \t\r\n")   # git strips trailing white space too
    except UnicodeDecodeError:
        raise _GitStop("gitdir")
    if not text.startswith("gitdir: ") or "\n" in text or "\r" in text:
        raise _GitStop("gitdir")
    return _git_follow(cwd, text[len("gitdir: "):], check)


def _git_follow(cwd, target, check):
    """J-6 as K-2 amends it: the gitdir a `.git` file names, followed once
    and only when it is relative and its lexical resolution stays UNDER the
    cwd (commonpath == cwd): `..` above the cwd, an absolute, UNC or device
    path, a drive or a stream is refused ("gitdir"). Every check before the
    first lstat is lexical, so a refused path is never touched: the hook
    opens nothing outside the project directory (no SMB connection to
    \\\\host\\share). A submodule (`gitdir: ../.git/modules/x`) and a linked
    worktree, absolute or relative, are therefore never followed."""
    if not target or "\0" in target or ":" in target or target[0] in "/\\":
        raise _GitStop("gitdir")   # absolute, UNC (\\ or //), \\?\ or \\.\, a drive (C:x) or a stream (x:y)
    if any(GIT_DEVICE_NAMES.match(part.rstrip(" .")) for part in re.split(r"[\\/]", target)):
        raise _GitStop("gitdir")
    base = os.path.normpath(cwd)
    full = os.path.normpath(os.path.join(base, target))
    if os.path.splitdrive(full)[0].lower() != os.path.splitdrive(base)[0].lower():
        raise _GitStop("gitdir")
    try:
        common = os.path.commonpath([base, full])
    except ValueError:
        raise _GitStop("gitdir")
    if os.path.normcase(common) != os.path.normcase(base):
        raise _GitStop("gitdir")   # K-2: above the cwd (`..`), a submodule's or a worktree's gitdir
    rel = os.path.relpath(full, base)
    if rel == os.curdir:   # `gitdir: .`: the cwd itself
        check()
        st = _git_lstat(full, "gitdir")
    else:
        _, st = _git_walk(base, rel.split(os.sep), "gitdir", check)
    if not stat.S_ISDIR(st.st_mode):   # followed once: a gitdir that is a file is not followed
        raise _GitStop("gitdir")
    return full


def _git_head(gitdir, check):
    """The 40-hex commit HEAD names: HEAD itself, the loose ref, else packed-refs."""
    check()
    path, st = _git_walk(gitdir, ["HEAD"], "unreadable", check)
    head = _git_text(_git_small(path, st, check, "unreadable")).rstrip(" \t\r\n")
    if GIT_HEX40.match(head):
        return head   # a detached HEAD
    if not head.startswith("ref: "):
        raise _GitStop("unreadable")
    name = head[len("ref: "):].strip()
    parts = name.split("/")
    if not _git_ref_ok(name, parts):
        raise _GitStop("unreadable")
    check()
    try:
        path, st = _git_walk(gitdir, parts, _GIT_MISSING, check)
    except _GitStop as stop:
        if stop.args[0] != _GIT_MISSING:
            raise
        st = None
    if st is not None and not stat.S_ISDIR(st.st_mode):
        value = _git_text(_git_small(path, st, check, "unreadable")).strip()
        if GIT_HEX40.match(value):
            return value
        raise _GitStop("unreadable")   # a symbolic ref, or not a SHA-1 object name
    check()
    try:
        path, st = _git_walk(gitdir, ["packed-refs"], _GIT_MISSING, check)
    except _GitStop as stop:
        raise _GitStop("no ref" if stop.args[0] == _GIT_MISSING else stop.args[0])
    for line in _git_text(_git_small(path, st, check, "unreadable")).splitlines():
        value, _, ref = line.rstrip("\r").partition(" ")
        if ref == name and line[:1] not in ("#", "^"):
            if GIT_HEX40.match(value):
                return value
            raise _GitStop("unreadable")
    raise _GitStop("no ref")   # J-7: an unborn branch


def _git_index(gitdir, check):
    """sha256 of the index's raw bytes (J-9), read as at most GIT_INDEX_MAX + 1 bytes (J-8)."""
    check()
    try:
        path, st = _git_walk(gitdir, ["index"], _GIT_MISSING, check)
    except _GitStop as stop:
        raise _GitStop("no index" if stop.args[0] == _GIT_MISSING else stop.args[0])
    if not stat.S_ISREG(st.st_mode):
        raise _GitStop("unreadable")
    if st.st_size > GIT_INDEX_MAX:
        raise _GitStop("index too large")
    digest = hashlib.sha256()
    if _git_read(path, st, GIT_INDEX_MAX, check, digest.update) > GIT_INDEX_MAX:
        raise _GitStop("index too large")
    return digest.hexdigest()


def _git_ref_ok(name, parts):
    """A ref name HEAD may name, as git's check_refname_format reads one,
    and no Windows device name: refs/heads/main, never ../../x or refs/a..b."""
    return (len(parts) >= 2 and parts[0] == "refs" and len(name) <= _GIT_REF_MAX and "@{" not in name
            and all(_GIT_REF_PART.match(p) and not p.startswith(".") and not p.endswith(".")
                    and not p.endswith(".lock") and ".." not in p and not GIT_DEVICE_NAMES.match(p.rstrip(" ."))
                    for p in parts))


def _git_link(st):
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_reparse_tag", 0) & _GIT_NAME_SURROGATE)


def _git_lstat(path, missing):
    """lstat of path: _GitStop(missing) when it is not there, "symlink" for
    a link (never followed, J-6), "unreadable" on any other error."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        raise _GitStop(missing)
    except (OSError, ValueError):
        raise _GitStop("unreadable")
    if _git_link(st):
        raise _GitStop("symlink")
    return st


def _git_walk(base, parts, missing, check):
    """(path, lstat) of base/parts..., every component below base lstat'ed
    in turn, so no symlink is followed at any of them (J-6), the budget
    checked before each lstat (K-6)."""
    path, st = base, None
    for part in parts:
        if st is not None and not stat.S_ISDIR(st.st_mode):
            raise _GitStop(missing)
        path = os.path.join(path, part)
        check()
        st = _git_lstat(path, missing)
    return path, st


def _git_small(path, st, check, over):
    """The bytes of a file of at most GIT_FILE_MAX; _GitStop(over) beyond."""
    chunks = []
    if _git_read(path, st, GIT_FILE_MAX, check, chunks.append) > GIT_FILE_MAX:
        raise _GitStop(over)
    return b"".join(chunks)


def _git_text(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise _GitStop("unreadable")


def _git_read(path, st, cap, check, sink):
    """Read the regular file at path (lstat'ed as st) once, at most cap + 1
    bytes, giving each chunk to sink; returns the count. Opened without
    following a link (O_NOFOLLOW where there is one) and without blocking on
    a FIFO; the budget is checked after each chunk."""
    if not stat.S_ISREG(st.st_mode):
        raise _GitStop("unreadable")
    try:
        fd = os.open(path, _GIT_OPEN)
    except OSError as exc:
        raise _GitStop("symlink" if exc.errno == getattr(errno, "ELOOP", None) else "unreadable")
    except ValueError:
        raise _GitStop("unreadable")
    total = 0
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _GitStop("unreadable")
        while total <= cap:
            chunk = os.read(fd, min(GIT_CHUNK, cap + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            sink(chunk)
            check()
    except OSError:
        raise _GitStop("unreadable")
    finally:
        os.close(fd)
    return total
