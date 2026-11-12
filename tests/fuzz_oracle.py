"""An independent check of a fuzz run: recompute, from the catalog and each session's grants alone, whether every ALLOW respected
what the policy promises. It shares helper functions with the gateway (path and address cleaning) but none of the decision logic,
so a bug in the engine's rules shows up as a violation here."""

from __future__ import annotations

import fnmatch
import re
import shlex

from fuzz_support import Run

from intentguard.canon import clean_destination, clean_path, fold
from intentguard.models import Trust

SHELL_OK = ("ls", "cat", "echo", "pwd", "head", "wc")
SHELL_META = re.compile(r"[;&|<>`\n\r]|\$[({A-Za-z_]")
SQL_WRITE = re.compile(r"\b(drop|delete|truncate|alter|update|insert|create|attach|detach|pragma|vacuum|copy|exec|execute)\b", re.I)
KNOWN = ("read_file", "search_files", "send_email", "upload", "run_shell", "db_query")


def oracle(run: Run) -> list[str]:
    """A description of every ALLOW that broke a promise (an empty list means none)."""
    gw = run.gateway
    bad: list[str] = []
    for sid, tool, args, verdict, _ran in run.calls:
        if verdict != "ALLOW":
            continue
        sc = gw.sessions[sid].scope
        if tool not in KNOWN:
            bad.append(f"ALLOW of an unregistered tool {tool!r}")
        if tool == "read_file":
            raw = args.get("path")
            if raw is None or not str(raw).strip():
                bad.append(f"ALLOW read with no path: {raw!r}")
            else:
                path, flags = clean_path(raw)
                if flags:
                    bad.append(f"ALLOW read of a path flagged {flags}: {raw!r}")
                elif gw.catalog.classify(fold(path)) > sc.max_classification:
                    bad.append(f"ALLOW read of {path!r} above the ceiling {sc.max_classification.name}")
        if tool in ("send_email", "upload"):
            dest = args.get("to") if tool == "send_email" else args.get("url")
            if dest is None or not str(dest).strip():
                bad.append(f"ALLOW {tool} with no destination")
                continue
            trust = gw.catalog.trust_of(dest)
            if trust == Trust.DENYLISTED:
                bad.append(f"ALLOW {tool} to the denylisted {dest!r}")
            elif trust == Trust.UNKNOWN and not any(fnmatch.fnmatch(clean_destination(dest)[0], g) for g in sc.allowed_destinations):
                bad.append(f"ALLOW {tool} to the unknown, ungranted {dest!r}")
        if tool == "run_shell":
            cmd = str(args.get("cmd", ""))
            try:
                parts = shlex.split(cmd)
            except ValueError:
                parts = []
            if not parts or parts[0] not in SHELL_OK or SHELL_META.search(cmd):
                bad.append(f"ALLOW of the shell command {cmd[:60]!r}")
        if tool == "db_query" and SQL_WRITE.search(str(args.get("sql", ""))):
            bad.append(f"ALLOW of SQL that writes: {str(args.get('sql'))[:60]!r}")
    return bad


def frozen_then_allowed(run: Run) -> list[str]:
    """After a session is frozen (QUARANTINE), nothing in it may be allowed again."""
    bad: list[str] = []
    frozen: set[str] = set()
    for sid, tool, verdict, _rules in run.decisions:
        if sid == "open-refused":
            continue
        if sid in frozen and verdict == "ALLOW":
            bad.append(f"{sid}: ALLOW after QUARANTINE ({tool})")
        if verdict == "QUARANTINE":
            frozen.add(sid)
    return bad
