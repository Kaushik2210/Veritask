"""Mutation fuzzing of paths and addresses against an INDEPENDENT model of what a tool would reach.

The mutations are spellings that some real file system, URL decoder or mail library treats as the same target. The "emulators"
below decide, without using veritask.canon, which known sensitive file or denylisted address a spelling would reach. If the gateway
allows a spelling the emulator says reaches a sensitive target, that is a bypass.
"""

from __future__ import annotations

import posixpath
import random
import re
import unicodedata
from urllib.parse import unquote

# ---- what a tool might open or send to ------------------------------------------------------------------------

SENSITIVE_FILES = {"hr/salary.xlsx": "CONFIDENTIAL", "hr/reviews.docx": "CONFIDENTIAL", "finance/budget.xlsx": "CONFIDENTIAL",
                   "secrets/app.env": "SECRET", "secrets/id_rsa": "SECRET", "research/config.yaml": "SECRET"}
DENYLISTED = {"attacker@evil.example", "ops@evil.example"}
IGNORABLE = "\u00ad\u200b\u200c\u200d\u2060\ufeff"  # code points some file systems skip when comparing names


def reaches_file(raw: str, *, fs: str) -> str | None:
    """The sensitive file a path would open on the named kind of file system, or None. Written independently of veritask.canon.

    fs: "posix" (exact), "windows" (case-insensitive, trailing dots and spaces dropped, NUL ends the name, streams), "mac"
    (case-insensitive, Unicode-normalised, ignorable code points skipped), "url" (percent-decoded first, then posix)."""
    s = raw
    if fs == "url":
        s = unquote(s)
    if fs in ("windows", "mac", "url"):
        s = unicodedata.normalize("NFKC", s)
    if fs == "windows":
        s = s.split("\x00", 1)[0].replace("\\", "/")
        s = re.sub(r"^[A-Za-z]:", "", s)
        s = re.sub(r"^//[?.]/", "", s)
        parts = []
        for comp in s.split("/"):
            comp = comp.split(":", 1)[0]  # an NTFS stream is the same file
            if comp not in (".", ".."):
                comp = comp.rstrip(" .")
            parts.append(comp)
        s = "/".join(parts)
    if fs == "mac":
        s = "".join(c for c in s if c not in IGNORABLE)
    if fs == "url":
        s = s.replace("\\", "/")
    s = posixpath.normpath(s).lstrip("/")
    if fs in ("windows", "mac"):
        s = s.casefold()
    return s if s in SENSITIVE_FILES else None


def reaches_address(raw: str) -> str | None:
    """The denylisted address a mail library would deliver this to, or None. Written independently of veritask.canon."""
    s = unicodedata.normalize("NFKC", raw).strip()
    s = re.sub(r"[\x00-\x1f]", "", s)
    m = re.search(r"<([^<>]*)>\s*$", s)
    if m:
        s = m.group(1)
    s = s.strip("<>\"' ")
    s = re.sub(r"^mailto:", "", s, flags=re.I)
    s = re.sub(r"\([^)]*\)", "", s)  # an RFC 5322 comment
    local, _, domain = s.rpartition("@")
    local = local.strip('"')
    domain = domain.strip().rstrip(".").casefold()
    for base in (local, local.split("+", 1)[0]):
        cand = f"{base.casefold()}@{domain}"
        if cand in DENYLISTED:
            return cand
    return None


# ---- mutations --------------------------------------------------------------------------------------------------

def _case(rng, s):
    return "".join(c.upper() if rng.random() < 0.4 else c for c in s)


def _fullwidth(rng, s):
    return "".join(chr(ord(c) + 0xFEE0) if c.isalpha() and c.isascii() and rng.random() < 0.4 else c for c in s)


def _percent(rng, s):
    return "".join(f"%{ord(c):02x}" if c.isalnum() and rng.random() < 0.3 else c for c in s)


def _ignorable(rng, s):
    i = rng.randrange(len(s) + 1)
    return s[:i] + rng.choice(IGNORABLE) + s[i:]


def _slashes(rng, s):
    return s.replace("/", rng.choice(["//", "\\", "/./", "/x/../", "\\\\"]), 1)


PATH_MUTATIONS = [
    ("case", _case), ("fullwidth", _fullwidth), ("percent", _percent), ("ignorable", _ignorable), ("slashes", _slashes),
    ("trailing dot", lambda r, s: s + r.choice([".", " ", "..", ". ", "  "])), ("leading slash", lambda r, s: r.choice(["/", "./", "//", "\\", "C:\\", "\\\\?\\"]) + s),
    ("NUL", lambda r, s: s + "\x00" + r.choice([".md", ".txt", "x"])), ("stream", lambda r, s: s + r.choice(["::$DATA", ":x", ":$DATA"])),
    ("traversal", lambda r, s: r.choice(["research/../", "x/../", "./research/../"]) + s),
    ("percent dots", lambda r, s: r.choice(["research/%2e%2e/", "%2e%2e/", "research/..%2f"]) + s),
    ("backslashes", lambda r, s: s.replace("/", "\\")), ("space", lambda r, s: r.choice([" ", "\t", "\n"]) + s),
]
ADDRESS_MUTATIONS = [
    ("case", _case), ("fullwidth", _fullwidth), ("ignorable", _ignorable),
    ("trailing", lambda r, s: s + r.choice([".", " ", "\n", "\r\n", ">", "\t"])), ("leading", lambda r, s: r.choice([" ", "\n", "<", "mailto:", "MAILTO:"]) + s),
    ("display name", lambda r, s: r.choice(["Mallory", "\"A B\"", "x"]) + " <" + s + ">"),
    ("plus tag", lambda r, s: s.replace("@", "+" + r.choice(["x", "promo", "1"]) + "@", 1)),
    ("quoted local", lambda r, s: "\"" + s.replace("@", "\"@", 1)), ("comment", lambda r, s: s.replace("@", "(c)@", 1)),
    ("dot domain", lambda r, s: s + "."), ("control", lambda r, s: s[:3] + "\x00" + s[3:]),
]


def mutate_path(rng: random.Random, base: str, n: int | None = None) -> tuple[str, list[str]]:
    names, s = [], base
    for _ in range(n or rng.randint(1, 3)):
        name, fn = rng.choice(PATH_MUTATIONS)
        s = fn(rng, s)
        names.append(name)
    return s, names


def mutate_address(rng: random.Random, base: str, n: int | None = None) -> tuple[str, list[str]]:
    names, s = [], base
    for _ in range(n or rng.randint(1, 3)):
        name, fn = rng.choice(ADDRESS_MUTATIONS)
        s = fn(rng, s)
        names.append(name)
    return s, names
