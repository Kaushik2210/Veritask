"""Closing a session stops what it was waiting on, and the MCP gateway refuses malformed requests (F35)."""

import io
import json

import pytest
from fastapi.testclient import TestClient

from intentguard import Gateway, PolicyEngine, compile_scope
from intentguard.client import InProcessSession
from intentguard.gateway import SessionClosed
from intentguard.mcp_gateway import DEMO_TOOLS, MAX_BODY, McpGateway
from intentguard.mock_env import MockEnv
from intentguard.service.app import create_app

G = {"resources": ["research/*"], "destinations": ["advisor@university.edu"], "max_classification": "INTERNAL"}
TASK = "Read research/paper.pdf and email advisor@university.edu a summary"


def waiting():
    """A session with one action waiting for a human (an unknown recipient)."""
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    c = gw.open_session("s", "agent", compile_scope(TASK, G))
    c.call("read_file", path="research/paper.pdf")
    r = c.call("send_email", to="bob@newlab.org", body="hi")
    assert r.decision.decision.value == "REVIEW" and len(gw.pending) == 1
    return env, gw, c, r.decision.action_id


def test_closing_a_session_cancels_what_it_was_waiting_on():
    env, gw, _, aid = waiting()
    gw.close("s", "admin", "stop")
    assert gw.pending == {} and gw.resolved[aid] == ("rejected", None)
    events = [json.loads(e["payload"]) for e in gw.audit.entries]
    assert any(e.get("event") == "cancelled" and e["action"] == aid for e in events)
    with pytest.raises(KeyError):
        gw.approve(aid, "admin")
    assert env.outbox == []


def test_an_action_that_slipped_past_the_close_still_cannot_be_approved():
    env, gw, _, aid = waiting()
    gw.sessions["s"].closed = True  # the session was closed between listing the action and approving it
    with pytest.raises(SessionClosed):
        gw.approve(aid, "admin")
    assert env.outbox == [] and gw.resolved[aid] == ("rejected", None) and aid not in gw.pending
    assert any(json.loads(e["payload"]).get("event") == "approval_refused" for e in gw.audit.entries)


def test_an_open_session_still_approves_normally():
    env, gw, _, aid = waiting()
    assert gw.approve(aid, "admin") == "sent" and len(env.outbox) == 1


def test_the_service_answers_404_after_a_close_and_409_for_the_race():
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    http = TestClient(create_app(gw), raise_server_exceptions=False)
    http.post("/sessions", json={"session_id": "s", "agent_id": "a", "task": TASK, "grants": G})
    http.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}})
    r = http.post("/sessions/s/call", json={"tool": "send_email", "args": {"to": "bob@newlab.org", "body": "hi"}})
    aid = r.json()["decision"]["action_id"]
    gw.sessions["s"].closed = True
    assert http.post(f"/pending/{aid}/approve", json={"approver": "me"}).status_code == 409
    assert env.outbox == []
    assert http.post(f"/pending/{aid}/approve", json={"approver": "me"}).status_code == 404  # and it is gone


def test_a_negative_audit_offset_starts_at_the_beginning():
    gw = Gateway(MockEnv().tools(), MockEnv().catalog(), PolicyEngine())
    gw.open_session("s", "a", compile_scope(TASK, G))
    http = TestClient(create_app(gw))
    assert http.get("/audit?offset=-5").json()["entries"][0]["seq"] == 0


def server():
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    return McpGateway(InProcessSession(gw.open_session("s", "mcp", compile_scope(TASK, G))), DEMO_TOOLS)


def rpc(method="ping", mid=1, **extra):
    return {"jsonrpc": "2.0", "id": mid, "method": method, **extra}


@pytest.mark.parametrize("msg,code", [
    (rpc("tools/call", params={"name": "read_file", "arguments": [1]}), -32602),
    (rpc("tools/call", params={"name": "read_file", "arguments": "x"}), -32602),
    (rpc("tools/call", params=[1]), -32602),
    (rpc("initialize", params="x"), -32602),
    (rpc("tools/list", params=[1]), -32602),
    (rpc(mid={"a": 1}), -32600), (rpc(mid=[1]), -32600), (rpc(mid=True), -32600), (rpc(mid="x" * 257), -32600),
    ({"id": 1, "method": "ping"}, -32600), ({"jsonrpc": "1.0", "id": 1, "method": "ping"}, -32600),
    (rpc(method=5), -32601),
])
def test_malformed_requests_get_the_right_error_not_an_internal_one(msg, code):
    assert server().handle(msg)["error"]["code"] == code


def test_valid_requests_still_work_with_numeric_and_string_ids():
    s = server()
    assert s.handle(rpc(mid=7))["id"] == 7 and s.handle(rpc(mid="abc"))["id"] == "abc" and s.handle(rpc(mid=1.5))["id"] == 1.5
    ok = s.handle(rpc("tools/call", params={"name": "read_file", "arguments": {"path": "research/paper.pdf"}}))
    assert ok["result"]["isError"] is False
    assert s.handle(rpc("tools/call", params={"name": "read_file", "arguments": None}))["result"]["isError"] is True  # nothing to judge
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_internal_errors_do_not_describe_the_internals(capsys):
    s = server()

    def boom(*a, **k):
        raise RuntimeError("secret path /etc/shadow and a stack of detail")

    s.session.call = boom
    out = s.handle(rpc("tools/call", params={"name": "read_file", "arguments": {"path": "research/paper.pdf"}}))
    assert out["error"] == {"code": -32603, "message": "internal error"}
    assert "secret path" in capsys.readouterr().err  # the detail goes to the operator's log, not to the client


def test_an_oversize_line_on_stdio_is_refused_and_the_next_one_still_works():
    s = server()
    out = io.StringIO()
    big = json.dumps(rpc(params={"x": "a" * (MAX_BODY + 10)}))
    s.serve(io.StringIO(big + "\n" + json.dumps(rpc(mid=2)) + "\n"), out)
    first, second = (json.loads(x) for x in out.getvalue().splitlines())
    assert first["error"]["code"] == -32600 and second["id"] == 2 and second["result"] == {}
