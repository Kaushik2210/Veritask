"""Make the path or address the policy judges the same one the tool will act on.

A policy that judges one spelling while a tool opens another is bypassed by the difference. These helpers turn what the agent
typed into (a) a key the policy compares and (b) the value the tool receives, and report spellings no honest caller needs.

Paths: Unicode is normalised (NFKC), backslashes become slashes, `.` and `..` are resolved, trailing dots and spaces on a
component are dropped (Windows ignores them), a drive letter or leading slash is dropped (everything is relative to the
project root), and the key is case-folded (many file systems ignore case). Flagged as suspicious: control characters
(a NUL ends a C string early), percent-encoded dots, slashes or NULs (a URL-style tool decodes them), a colon inside a name
(an NTFS stream such as `file::$DATA`), and 8.3 short names (`HR~1`).

Addresses and URLs: surrounding space, angle brackets, `mailto:` and a display name are dropped; a URL is judged by its host
(user-info tricks such as `files.partner.org@evil.example` resolve to the real host); trailing dots and letter case are ignored;
non-ASCII domains become punycode so a look-alike never matches an approved name.

Not handled: symbolic links, hard links and mount points (the policy cannot see what a path resolves to on disk), and URL
hosts written as numbers (`2130706433`) or with an IPv6 zone. A caller whose tools resolve those should resolve them first.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from urllib.parse import urlsplit

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_PERCENT = re.compile(r"%(?:2e|2f|5c|00|25)", re.IGNORECASE)
_SHORT = re.compile(r"~\d")
SUSPICIOUS = {"control-character", "percent-encoding", "colon-in-name", "short-name", "bad-domain",
              "missing-argument", "unexpected-argument"}


def clean_path(raw: object) -> tuple[str, list[str]]:
    """(path to judge and to run, flags). The path keeps its letter case; compare with `fold`."""
    s = unicodedata.normalize("NFKC", str(raw))
    flags: set[str] = set()
    if _CTRL.search(s):
        flags.add("control-character")
        s = _CTRL.sub("", s)
    if _PERCENT.search(s):
        flags.add("percent-encoding")
    s = s.replace("\\", "/")
    s = re.sub(r"^[A-Za-z]:", "", s)  # a drive letter: everything is relative to the project root
    parts = []
    for comp in s.split("/"):
        if ":" in comp:
            flags.add("colon-in-name")
            comp = comp.split(":", 1)[0]
        if comp not in (".", ".."):
            comp = comp.rstrip(" .")
        if _SHORT.search(comp):
            flags.add("short-name")
        parts.append(comp)
    path = posixpath.normpath("/".join(parts)).lstrip("/") or "."
    return path, sorted(flags)


def fold(text: str) -> str:
    """The form two spellings are compared in."""
    return unicodedata.normalize("NFKC", str(text)).casefold()


def clean_destination(raw: object) -> tuple[str, str, list[str]]:
    """(key the policy compares, value the tool receives, flags)."""
    s = unicodedata.normalize("NFKC", str(raw)).strip()
    flags: set[str] = set()
    if _CTRL.search(s):
        flags.add("control-character")
        s = _CTRL.sub("", s).strip()
    named = re.search(r"<([^<>]+)>\s*$", s)  # Display Name <address>
    if named:
        s = named.group(1).strip()
    s = s.strip("<>\"' ")
    if s.lower().startswith("mailto:"):
        s = s[7:].strip()
    value = s
    if "://" in s or s.startswith("//"):
        try:
            key = urlsplit(s if "://" in s else "http:" + s).hostname or ""
        except ValueError:
            key = ""
            flags.add("bad-domain")
    else:
        key = s
    key = key.rstrip(".").casefold()
    local, at, domain = key.rpartition("@")
    if domain and any(ord(c) > 127 for c in domain):
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            flags.add("bad-domain")
    key = (local + at + domain) if at else domain
    return key, value, sorted(flags)


def domain_chain(key: str) -> list[str]:
    """For `a@b.example.com`: the address, then @b.example.com, b.example.com, example.com, com."""
    out = [key]
    domain = key.rpartition("@")[2]
    if "@" in key:
        out.append("@" + domain)
    labels = domain.split(".")
    out += [".".join(labels[i:]) for i in range(len(labels))]
    return list(dict.fromkeys(x for x in out if x))
