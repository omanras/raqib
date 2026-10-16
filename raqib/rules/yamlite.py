r"""A strict YAML subset for rule files (M1.1). Stdlib only (ADR-0001 A-7).

Supported:
- block mappings: `key: value`, or `key:` followed by a more indented block;
  plain keys match [A-Za-z0-9_./-]+, or are quoted
- block sequences: `- item`, `- key: value` items (a mapping), and a sequence
  written at the same indentation as its parent key
- one-line flow collections: `[a, b]`, `{k: v}`, nested
- scalars: "double" (escapes \\ \" \/ \n \t \r \0 \b \f \xXX \uXXXX),
  'single' ('' is a quote), and plain: null, ~ or nothing -> None;
  true/false -> bool; decimal ints; floats like 1.5 or .5; anything else is
  a string
- comments (# at line start or after whitespace) and one leading `---`

Everything else is a YamlError naming the line, never a silent misread:
tabs in indentation, anchors, aliases, tags, block scalars, directives,
multi-line flow collections or quoted scalars, multiple documents, duplicate
keys, ": " inside a plain value, bad indentation, and plain scalars whose
meaning differs between YAML 1.1 and 1.2 (yes/no/on/off, 017, 0x1F, 1_000,
1e3, 1:30, .inf, .nan, dates). Quote those to mean a string.
"""
from __future__ import annotations

import re

PLAIN_KEY = re.compile(r"[A-Za-z0-9_./-]+\Z")
INT = re.compile(r"[-+]?[0-9]+\Z")
FLOAT = re.compile(r"[-+]?[0-9]+\.[0-9]*\Z|\.[0-9]+\Z")
AMBIGUOUS = re.compile(
    r"(?:yes|no|on|off)\Z"                              # YAML 1.1 booleans
    r"|[-+]?0[0-9]+\Z"                                   # octal in YAML 1.1
    r"|[-+]?0[xXoObB][0-9A-Fa-f_]*\Z"                    # hex / octal / binary
    r"|[-+]?[0-9][0-9_]*_[0-9_]*(?:\.[0-9_]*)?\Z"        # digit separators
    r"|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?\Z"  # base 60
    r"|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+\Z"  # exponents
    r"|[-+]\.[0-9]+\Z"                                    # signed .5
    r"|[-+]?\.(?:inf|nan)\Z"
    r"|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt ].*)?\Z",     # dates, timestamps
    re.IGNORECASE)
NULLS = ("", "~", "null", "Null", "NULL")
TRUE = ("true", "True", "TRUE")
FALSE = ("false", "False", "FALSE")
UNSUPPORTED_START = "&*!|>%@`?"
ESCAPES = {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r",
           "0": "\0", "b": "\b", "f": "\f"}


class YamlError(ValueError):
    def __init__(self, message, line=None):
        self.line = line
        super().__init__("line %d: %s" % (line, message) if line else message)


def loads(text):
    """Parse one YAML document of the supported subset."""
    lines = _lines(text)
    for number, indent, content in lines:
        if indent == 0 and content.startswith("%"):
            raise YamlError("unsupported YAML directive %r" % content, number)
    if lines and lines[0][2] == "---":
        lines.pop(0)
    for number, _, content in lines:
        if content in ("---", "..."):
            raise YamlError("multiple documents are not supported", number)
    if not lines:
        return None
    if lines[0][1] != 0:
        raise YamlError("the document must start at column 0", lines[0][0])
    parser = _Parser(lines)
    node = parser.block(0)
    if parser.i < len(lines):
        raise YamlError("unexpected content (bad indentation?)", lines[parser.i][0])
    return node


def _lines(text):
    """[number, indent, content] for every line with content, comments removed."""
    out = []
    for number, raw in enumerate(text.splitlines(), start=1):
        lead = raw[:len(raw) - len(raw.lstrip(" \t"))]
        if "\t" in lead and raw.strip():
            raise YamlError("tab in indentation", number)
        content, tab = _strip_comment(raw)
        content = content.rstrip()
        if not content.strip():
            continue
        if tab:
            raise YamlError("tab outside a quoted scalar", number)
        indent = len(content) - len(content.lstrip(" "))
        out.append([number, indent, content.strip()])
    return out


def _strip_comment(raw):
    """(line without its comment, whether a tab occurs outside quotes)."""
    quote = None
    tab = False
    prev = None  # last non-space character outside quotes
    i = 0
    while i < len(raw):
        c = raw[i]
        if quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
                prev = c
        elif quote == "'":
            if c == "'":
                if raw[i + 1:i + 2] == "'":
                    i += 2
                    continue
                quote = None
                prev = c
        elif c in "\"'" and prev in (None, "-", ":", "[", "{", ","):
            quote = c
        elif c == "#" and (i == 0 or raw[i - 1] in " \t"):
            return raw[:i], tab
        elif c == "\t":
            tab = True
        elif c != " ":
            prev = c
        i += 1
    return raw, tab


def _is_seq_item(content):
    return content == "-" or content.startswith("- ")


class _Parser:
    def __init__(self, lines):
        self.lines = lines
        self.i = 0

    def block(self, indent):
        number, ind, content = self.lines[self.i]
        if ind != indent:
            raise YamlError("bad indentation", number)
        if _is_seq_item(content):
            return self.sequence(indent)
        if _split_key(content, number) is not None:
            return self.mapping(indent)
        self.i += 1
        return _inline(content, number)

    def mapping(self, indent):
        result = {}
        while self.i < len(self.lines):
            number, ind, content = self.lines[self.i]
            if ind < indent or (ind == indent and _is_seq_item(content)):
                break
            if ind > indent:
                raise YamlError("bad indentation", number)
            pair = _split_key(content, number)
            if pair is None:
                raise YamlError("expected 'key: value'", number)
            key, rest = pair
            if key in result:
                raise YamlError("duplicate key %r" % (key,), number)
            self.i += 1
            if rest:
                result[key] = _inline(rest, number)
            elif self.i < len(self.lines) and self.lines[self.i][1] > indent:
                result[key] = self.block(self.lines[self.i][1])
            elif (self.i < len(self.lines) and self.lines[self.i][1] == indent
                  and _is_seq_item(self.lines[self.i][2])):
                result[key] = self.sequence(indent)
            else:
                result[key] = None
        return result

    def sequence(self, indent):
        items = []
        while self.i < len(self.lines):
            number, ind, content = self.lines[self.i]
            if ind < indent or not _is_seq_item(content):
                break
            if ind > indent:
                raise YamlError("bad indentation", number)
            rest = content[1:].lstrip(" ")
            if not rest:
                self.i += 1
                if self.i < len(self.lines) and self.lines[self.i][1] > indent:
                    items.append(self.block(self.lines[self.i][1]))
                else:
                    items.append(None)
                continue
            column = indent + len(content) - len(rest)
            if _is_seq_item(rest) or _split_key(rest, number) is not None:
                # The item is a block that starts on this line, at `column`.
                self.lines[self.i] = [number, column, rest]
                items.append(self.block(column))
            else:
                self.i += 1
                items.append(_inline(rest, number))
        return items


def _split_key(content, number):
    """(key, rest) if the line is `key: rest` or `key:`, else None."""
    if content[0] in "[{":
        return None
    if content[0] in "\"'":
        key, end = _quoted(content, 0, number)
        rest = content[end:].lstrip(" ")
        if rest == ":" or rest.startswith(": "):
            return key, rest[1:].strip()
        return None
    match = re.search(r":(?: |\Z)", content)
    if match is None:
        return None
    key = content[:match.start()].rstrip()
    if not PLAIN_KEY.match(key):
        raise YamlError("unsupported key %r (quote it, or use [A-Za-z0-9_./-])" % (key,), number)
    return key, content[match.end():].strip()


def _inline(text, number):
    if text[0] in "[{":
        value, end = _flow(text, 0, number)
        if text[end:].strip():
            raise YamlError("unexpected text after a flow collection", number)
        return value
    if text[0] in "\"'":
        value, end = _quoted(text, 0, number)
        if text[end:].strip():
            raise YamlError("unexpected text after a quoted scalar", number)
        return value
    if ": " in text or text.endswith(":"):
        raise YamlError("':' inside a plain value; quote the value", number)
    return _plain(text, number)


def _plain(token, number):
    if token[0] in UNSUPPORTED_START:
        raise YamlError("unsupported YAML feature starting with %r" % token[0], number)
    if token in NULLS:
        return None
    if token in TRUE:
        return True
    if token in FALSE:
        return False
    if AMBIGUOUS.match(token):
        raise YamlError("ambiguous plain scalar %r; quote it" % (token,), number)
    if INT.match(token):
        return int(token)
    if FLOAT.match(token):
        return float(token)
    return token


def _quoted(text, start, number):
    """Parse a quoted scalar starting at text[start]; return (value, end)."""
    quote = text[start]
    out = []
    i = start + 1
    while i < len(text):
        c = text[i]
        if quote == "'":
            if c == "'":
                if text[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
        else:
            if c == '"':
                return "".join(out), i + 1
            if c == "\\":
                code = text[i + 1:i + 2]
                if code in ESCAPES:
                    out.append(ESCAPES[code])
                    i += 2
                    continue
                width = {"x": 2, "u": 4}.get(code)
                digits = text[i + 2:i + 2 + width] if width else ""
                if width and re.fullmatch(r"[0-9A-Fa-f]{%d}" % width, digits):
                    out.append(chr(int(digits, 16)))
                    i += 2 + width
                    continue
                raise YamlError("unsupported escape \\%s" % code, number)
        out.append(c)
        i += 1
    raise YamlError("unterminated quoted scalar (multi-line scalars are not supported)", number)


def _skip(text, i):
    while i < len(text) and text[i] == " ":
        i += 1
    return i


def _flow(text, i, number):
    i = _skip(text, i)
    if i >= len(text):
        raise YamlError("unterminated flow collection (multi-line flow is not supported)", number)
    c = text[i]
    if c == "[":
        return _flow_sequence(text, i, number)
    if c == "{":
        return _flow_mapping(text, i, number)
    if c in "\"'":
        return _quoted(text, i, number)
    j = i
    while j < len(text) and text[j] not in ",[]{}":
        if text[j] == ":" and (j + 1 == len(text) or text[j + 1] in " ,[]{}"):
            break
        j += 1
    token = text[i:j].strip()
    if not token:
        raise YamlError("empty value in a flow collection", number)
    return _plain(token, number), j


def _flow_sequence(text, i, number):
    items = []
    i = _skip(text, i + 1)
    if text[i:i + 1] == "]":
        return items, i + 1
    while True:
        value, i = _flow(text, i, number)
        items.append(value)
        i = _skip(text, i)
        c = text[i:i + 1]
        if c == ",":
            i += 1
        elif c == "]":
            return items, i + 1
        elif not c:
            raise YamlError("unterminated flow sequence (multi-line flow is not supported)", number)
        else:
            raise YamlError("expected ',' or ']' in a flow sequence", number)


def _flow_mapping(text, i, number):
    result = {}
    i = _skip(text, i + 1)
    if text[i:i + 1] == "}":
        return result, i + 1
    while True:
        i = _skip(text, i)
        if text[i:i + 1] in ("\"", "'"):
            key, i = _quoted(text, i, number)
        else:
            j = i
            while j < len(text) and text[j] not in ":,[]{}":
                j += 1
            key = text[i:j].strip()
            if not PLAIN_KEY.match(key):
                raise YamlError("unsupported key %r in a flow mapping" % (key,), number)
            i = j
        i = _skip(text, i)
        if text[i:i + 1] != ":" or text[i + 1:i + 2] not in (" ", ""):
            raise YamlError("expected ': ' after key %r in a flow mapping" % (key,), number)
        if key in result:
            raise YamlError("duplicate key %r" % (key,), number)
        result[key], i = _flow(text, i + 1, number)
        i = _skip(text, i)
        c = text[i:i + 1]
        if c == ",":
            i += 1
        elif c == "}":
            return result, i + 1
        elif not c:
            raise YamlError("unterminated flow mapping (multi-line flow is not supported)", number)
        else:
            raise YamlError("expected ',' or '}' in a flow mapping", number)
