"""The gateway is the only holder of the tools. Agents get a GatewayClient with one method."""

from __future__ import annotations

import fnmatch
import inspect
import re
import shlex
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .canon import SUSPICIOUS, clean_destination, clean_path, domain_chain, fold
from .engine import PolicyEngine
from .models import (
    ActionRequest,
    Classification,
    Decision,
    Evidence,
    Op,
    Session,
    TaskScope,
    Trust,
    Verdict,
)


@dataclass
class Tool:
    name: str
    op: Op
    fn: Callable[..., Any]
    resource_arg: str | None = None
    dest_arg: str | None = None
    resource_optional: bool = False  # an empty or placeholder value means "no file", not a path


@dataclass
class Result:
    decision: Decision
    output: Any = None
    error: str | None = None  # the policy allowed the call but the tool itself failed


class Catalog:
    """Ground truth about resources and destinations. The agent cannot influence it."""

    def __init__(self, classes: dict[str, Classification] | None = None,
                 trust: dict[str, Trust] | None = None,
                 tables: dict[str, Classification] | None = None):
        self.classes = classes or {}
        self.trust = trust or {}
        self.tables = tables or {}

    def table_class(self, table: str) -> Classification:
        return self.tables.get(table.lower(), Classification.INTERNAL)

    def classify(self, resource: str) -> Classification:
        """Case-insensitive, like most file systems; an unknown resource is INTERNAL, never public."""
        key = fold(resource)
        for name, cls in self.classes.items():
            if fold(name) == key:
                return cls
        return Classification.INTERNAL

    def trust_of(self, dest: str) -> Trust:
        """Trust of an address or host, compared in its cleaned form. A denylisted domain also covers its addresses and subdomains."""
        key = clean_destination(dest)[0]
        known = {clean_destination(k)[0]: v for k, v in self.trust.items()}
        if key in known:
            return known[key]
        if any(known.get(k) == Trust.DENYLISTED for k in domain_chain(key)[1:]):
            return Trust.DENYLISTED
        local, at, domain = key.rpartition("@")
        if at and "+" in local and known.get(local.split("+", 1)[0] + "@" + domain) == Trust.DENYLISTED:
            return Trust.DENYLISTED  # attacker+tag@evil.example is attacker@evil.example
        return Trust.UNKNOWN


_WRITE_SQL = re.compile(r"\b(drop|delete|truncate|alter|update|insert|create|grant|revoke|merge|attach|detach|pragma|vacuum|"
                        r"copy|call|exec|execute|load_extension)\b|\binto\s+(outfile|dumpfile)\b|\bload\s+data\b", re.I)


def _argv_words(cmd: str) -> list[str]:
    """Words after the command name, read the way a POSIX shell reads them (quotes removed) and also by plain splitting,
    so a quoted trick such as research/"../hr/x" and a Windows path with backslashes are both seen."""
    words: list[str] = []
    try:
        words += shlex.split(cmd)[1:]
    except ValueError:
        pass
    words += [w.strip("\"'") for w in cmd.split()[1:]]
    return list(dict.fromkeys(words))


def canonical(path: str) -> str:
    """Normalise before any policy check so 'research/../hr/x' is judged as 'hr/x' (see canon.clean_path)."""
    return clean_path(path)[0]


class Gateway:
    def __init__(self, tools: list[Tool], catalog: Catalog, engine: PolicyEngine | None = None,
                 audit: AuditLog | None = None):
        self.__tools = {t.name: t for t in tools}
        self._params: dict[str, tuple[set[str], bool]] = {}
        for t in tools:  # which argument names a tool takes, and whether it takes any (**kwargs)
            try:
                sig = inspect.signature(t.fn).parameters.values()
                self._params[t.name] = ({p.name for p in sig if p.kind != p.VAR_KEYWORD},
                                        any(p.kind == p.VAR_KEYWORD for p in sig))
            except (TypeError, ValueError):
                self._params[t.name] = (set(), True)
        self.catalog = catalog
        self.engine = engine or PolicyEngine()
        self.audit = audit or AuditLog()
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, tuple[Session, Tool, dict, Classification, ActionRequest, Decision]] = {}
        self.memory: dict[str, dict] = {}  # per-agent risk and tags carried across sessions
        self.resolved: dict[str, tuple[str, Any]] = {}  # action id -> ("approved", output) | ("rejected", None) | ("error", msg)
        self.store: Any = None  # optional SessionStore: sessions survive a restart

    def attach_store(self, store: Any) -> int:
        """Load saved sessions from `store` and save every change from now on. Returns how many were restored."""
        self.store = store
        key, set_key = getattr(store, "key", b""), getattr(self.engine, "set_fingerprint_key", None)
        if key and set_key:  # before load: restored lineage was hashed with this key
            set_key(key)
        sessions, memory = store.load()
        self.sessions.update(sessions)
        self.memory.update(memory)
        return len(sessions)

    def _persist(self, session_id: str) -> None:
        if self.store is not None and session_id in self.sessions:
            self.store.save(self.sessions[session_id])

    def open_session(self, session_id: str, agent_id: str, scope: TaskScope) -> GatewayClient:
        s = Session(session_id, agent_id, scope)
        carry = getattr(self.engine, "carry", None)
        if carry and agent_id in self.memory:
            carry(s, self.memory[agent_id])
        self.sessions[session_id] = s
        self._persist(session_id)
        self.audit.append({"event": "session_open", "session": session_id, "agent": agent_id,
                           "task": scope.task_text})
        return GatewayClient(self, session_id)

    def call(self, session_id: str, tool_name: str, **args) -> Result:
        try:
            return self._call(session_id, tool_name, **args)
        finally:
            self._persist(session_id)

    def _call(self, session_id: str, tool_name: str, **args) -> Result:
        s = self.sessions[session_id]
        tool = self.__tools.get(tool_name)
        if s.closed:  # an administrator ended this session
            req = ActionRequest(session_id, s.agent_id, tool_name, Op.EXEC, args=args)
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["SESSION-001"],
                         [Evidence("SESSION-001", "This session was closed by an administrator", tool_name)],
                         "- This session was closed by an administrator", "block", s.caps)
            self._log(req, d)
            return Result(d)
        if tool is None:  # fail closed
            req = ActionRequest(session_id, s.agent_id, tool_name, Op.EXEC, args=args)
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["PERM-001"],
                         [Evidence("PERM-001", "Tool is not registered for this agent", tool_name)],
                         "- Tool is not registered for this agent", "block", s.caps)
            self._log(req, d)
            return Result(d)
        if (tool.resource_optional and tool.resource_arg
                and str(args.get(tool.resource_arg, "x")).strip().lower() in ("", "null", "none")):
            # models often fill an optional file argument with "" or "null"; drop it so "." or "null" is not
            # judged as a path (found when the gateway blocked legitimate emails with attachment="")
            args = {k: v for k, v in args.items() if k != tool.resource_arg}
        flags: list[str] = []
        names, takes_any = self._params.get(tool.name, (set(), True))
        if not takes_any and set(args) - names:
            flags.append("unexpected-argument")  # an argument the tool does not declare is not something the policy judged
        for needed in (tool.resource_arg if not tool.resource_optional else None, tool.dest_arg):
            if needed and (args.get(needed) is None or str(args.get(needed)).strip() == ""):
                flags.append("missing-argument")  # a call with no file or no recipient has nothing for the policy to judge
        if tool.resource_arg and args.get(tool.resource_arg) is not None:
            clean, f = clean_path(args[tool.resource_arg])  # the tool receives the path that was judged
            args, flags = {**args, tool.resource_arg: clean}, flags + f
        res = fold(args[tool.resource_arg]) if tool.resource_arg and args.get(tool.resource_arg) is not None else None
        if tool.op == Op.EXEC:  # files named inside a shell command are resources too
            found = [clean_path(w) for w in _argv_words(str(args.get("cmd", "")))
                     if not w.startswith("-") and ("/" in w or "." in w)]
            if found:
                flags += [x for _, f in found for x in f]
                res = self._judged_path([p for p, _ in found], s.scope.allowed_resources)
        dest = None
        if tool.dest_arg and args.get(tool.dest_arg) is not None:
            dest, value, f = clean_destination(args[tool.dest_arg])
            args, flags = {**args, tool.dest_arg: value}, flags + f
        req = ActionRequest(
            session_id, s.agent_id, tool.name, tool.op, resource=res,
            classification=self.catalog.classify(res) if res else Classification.PUBLIC,
            destination=dest, trust=self.catalog.trust_of(dest) if dest else None, args=args,
            flags=sorted(set(flags) & SUSPICIOUS))
        if tool.op == Op.QUERY:  # classify the tables a query touches, not just the tool
            sql = unicodedata.normalize("NFKC", str(args.get("sql", "")))  # judged in this form; the tool still gets the original
            req.tables = self._tables(sql)
            if req.tables:
                req.classification = max(self.catalog.table_class(t) for t in req.tables)
            if _WRITE_SQL.search(sql):
                req.op = Op.WRITE  # a statement that changes data, opens another database or runs code is a write, not a query
        try:
            d = self.engine.evaluate(req, s)
        except Exception as exc:  # fail closed on engine error
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["ENGINE-ERR"], [],
                         f"engine error: {exc!r}", "block", s.caps)
        self._log(req, d)
        if d.decision == Verdict.ALLOW:
            try:
                return Result(d, self._run(s, tool, args, req.classification))
            except Exception as exc:  # a failing tool is an answer, not a crash; keep it in the audit log
                self.audit.append({"event": "tool_error", "action": req.action_id, "session": session_id,
                                   "tool": tool.name, "error": f"{type(exc).__name__}: {exc}"})
                return Result(d, None, f"{type(exc).__name__}: {exc}")
        if d.decision == Verdict.REVIEW:
            self.pending[req.action_id] = (s, tool, args, req.classification, req, d)
        return Result(d)

    def _judged_path(self, paths: list[str], grants: list[str]) -> str:
        """The one path a multi-path command is judged on: a path outside the grants if there is one (so no allowed path
        hides it), otherwise the most sensitive."""
        folded = [fold(p) for p in paths]
        outside = [p for p in folded if not any(fnmatch.fnmatch(p, g) for g in grants)]
        return max(outside or folded, key=self.catalog.classify)

    def _tables(self, sql: str) -> list[str]:
        """Tables a query touches. Comments, string literals and quoting are stripped first; a table is
        found after FROM/JOIN/INTO/UPDATE/TABLE (schema prefix dropped, comma lists followed), and any
        known catalog table named anywhere in the text counts too, which covers subqueries, UNION and
        WITH. Over-approximate on purpose. Not a SQL parser: dynamic or encoded SQL is not handled."""
        s = re.sub(r"/\*.*?\*/|--[^\n]*|'[^']*'", " ", sql, flags=re.S)
        s = re.sub(r"[`\"\[\]]", "", s)
        found = []
        for m in re.finditer(r"\b(?:from|join|into|update|table)\s+([\w.]+(?:\s*,\s*[\w.]+)*)", s, re.I):
            found += [x.strip().rsplit(".", 1)[-1] for x in m.group(1).split(",")]
        found += [t for t in re.findall(r"[A-Za-z_]\w*", s) if t.lower() in self.catalog.tables]
        return list(dict.fromkeys(f for f in found if f and f.lower() not in ("select", "values")))

    def approve(self, action_id: str, approver: str) -> Any:
        s, tool, args, cls, req, d = self.pending.pop(action_id)
        self.audit.append({"event": "approved", "action": action_id, "by": approver})
        # remember only the two rules whose point is to ask once about a recipient or a file
        if "EGRESS-001" in d.fired_rules and req.destination:
            s.approved.add(("EGRESS-001", req.destination))
        if "SCOPE-005" in d.fired_rules:
            s.approved.update(("SCOPE-005", n) for n in ([req.resource] if req.resource else req.tables))
        try:
            out = self._run(s, tool, args, cls)
        except Exception as exc:  # the approved tool itself failed; the waiting caller must hear about it
            self.resolved[action_id] = ("error", str(exc))
            raise
        finally:
            self._persist(s.session_id)
        self.resolved[action_id] = ("approved", out)
        return out

    def release(self, session_id: str, approver: str, reason: str = "") -> dict:
        """A human lifts a session's lock-out: risk, denied count, sequence tags and the capability locks are reset,
        and the agent's carried-over risk is cleared. What the session has already read (taint, fingerprints of
        sensitive data, recent outbound text, approvals) is kept, so releasing never makes it forget an exposure."""
        s = self.sessions[session_id]
        before = {"risk": round(s.risk, 3), "caps": {k: getattr(s.caps, k) for k in ("network", "shell", "files_locked",
                                                                                      "db_needs_review")}}
        s.risk, s.denied, s.quarantined, s.tags = 0.0, 0, False, []
        s.caps = type(s.caps)()
        self.memory.pop(s.agent_id, None)
        if self.store is not None:
            self.store.delete_memory(s.agent_id)
        self._persist(session_id)
        self.audit.append({"event": "released", "session": session_id, "by": approver, "reason": reason,
                           "before": before})
        return before

    def close(self, session_id: str, approver: str, reason: str = "") -> None:
        """A human ends a session; every further call in it is blocked and audited."""
        self.sessions[session_id].closed = True
        self._persist(session_id)
        self.audit.append({"event": "closed", "session": session_id, "by": approver, "reason": reason})

    def reject(self, action_id: str, approver: str) -> None:
        self.pending.pop(action_id)
        self.audit.append({"event": "rejected", "action": action_id, "by": approver})
        self.resolved[action_id] = ("rejected", None)

    def _run(self, s: Session, tool: Tool, args: dict, cls: Classification | None = None) -> Any:
        out = tool.fn(**args)
        remember = getattr(self.engine, "remember", None)
        if remember and cls is not None and cls >= Classification.CONFIDENTIAL and tool.op in (Op.READ, Op.QUERY):
            remember(s, out, cls)  # fingerprint sensitive content so it is recognised if it leaves
        observe = getattr(self.engine, "observe", None)
        if observe and observe(s, out):
            self.audit.append({"event": "injection_flag", "session": s.session_id, "tool": tool.name,
                               "risk": round(s.risk, 3)})
        return out

    def _log(self, req: ActionRequest, d: Decision) -> None:
        sess = self.sessions[req.session_id]
        self.memory[req.agent_id] = {"risk": sess.risk, "tags": set(sess.tags)}
        if self.store is not None:
            self.store.save_memory(req.agent_id, self.memory[req.agent_id])
        self.audit.append({
            "event": "action", "action": req.action_id, "session": req.session_id,
            "agent": req.agent_id, "tool": req.tool, "op": req.op.value, "resource": req.resource,
            "destination": req.destination, "decision": d.decision.value, "risk": d.risk_score,
            "rules": d.fired_rules, "latency_ms": round(d.latency_ms, 3)})


class GatewayClient:
    """What the agent holds: no tool handles, only call()."""

    __slots__ = ("_gw", "_sid")

    def __init__(self, gw: Gateway, sid: str):
        self._gw, self._sid = gw, sid

    def call(self, tool: str, **args) -> Result:
        return self._gw.call(self._sid, tool, **args)
