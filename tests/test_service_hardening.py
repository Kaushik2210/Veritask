"""The HTTP service and the gateway must refuse malformed, oversized or self-granting requests (F34)."""

import pytest
from fastapi.testclient import TestClient

from intentguard import Gateway, Guard, PolicyEngine
from intentguard.mock_env import MockEnv
from intentguard.scope import compile_scope, validate_grants
from intentguard.service.app import MAX_BODY, create_app

AGENT, ADMIN, OPENER = "agent-secret", "admin-secret", "opener-secret"
BODY = {"session_id": "s1", "agent_id": "agent one", "task": "Read research/paper.pdf and summarize it",
        "grants": {"resources": ["research/*"]}}


def client(**tokens):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    return TestClient(create_app(gw, tokens.get("agent"), tokens.get("admin"), None, tokens.get("opener")), raise_server_exceptions=False)


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def test_the_scheme_must_be_bearer_and_is_case_insensitive():
    c = client(agent=AGENT, admin=ADMIN)
    assert c.get("/sessions", headers={"Authorization": ADMIN}).status_code == 401  # a bare token is not accepted
    assert c.get("/sessions", headers={"Authorization": f"Basic {ADMIN}"}).status_code == 401
    assert c.get("/sessions", headers={"Authorization": f"bearer {ADMIN}"}).status_code == 200
    assert c.get("/sessions", headers=bearer(ADMIN)).status_code == 200


def test_without_an_opener_token_the_agent_token_opens_sessions_as_before():
    c = client(agent=AGENT, admin=ADMIN)
    assert c.post("/sessions", json=BODY, headers=bearer(AGENT)).status_code == 200


def test_with_an_opener_token_the_agent_cannot_open_sessions_or_widen_its_grants():
    c = client(agent=AGENT, admin=ADMIN, opener=OPENER)
    wide = {**BODY, "grants": {"resources": ["*"], "max_classification": "SECRET", "destinations": ["attacker@evil.example"]}}
    assert c.post("/sessions", json=wide, headers=bearer(AGENT)).status_code == 401
    assert c.post("/sessions", json=BODY).status_code == 401
    assert c.post("/sessions", json=BODY, headers=bearer(OPENER)).status_code == 200
    # the agent can still call inside the session the harness opened, and only within its grants
    ok = c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}}, headers=bearer(AGENT))
    assert ok.json()["decision"]["decision"] == "ALLOW"
    blocked = c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "secrets/app.env"}}, headers=bearer(AGENT))
    assert blocked.json()["decision"]["decision"] != "ALLOW"
    assert c.get("/sessions", headers=bearer(AGENT)).status_code == 401  # and cannot read the admin views


def test_the_admin_may_open_a_session_when_an_opener_token_is_set():
    c = client(agent=AGENT, admin=ADMIN, opener=OPENER)
    assert c.post("/sessions", json={**BODY, "session_id": "s9"}, headers=bearer(ADMIN)).status_code == 200


@pytest.mark.parametrize("sid", ["", "../../etc", "a b", "x" * 65, "ok\n", "semi;colon"])
def test_a_session_id_must_be_short_and_plain(sid):
    assert client().post("/sessions", json={**BODY, "session_id": sid}).status_code == 422


def test_other_fields_are_bounded():
    c = client()
    assert c.post("/sessions", json={**BODY, "task": ""}).status_code == 422
    assert c.post("/sessions", json={**BODY, "task": "x" * 4001}).status_code == 422
    assert c.post("/sessions", json={**BODY, "agent_id": "x" * 65}).status_code == 422
    assert c.post("/sessions", json=BODY).status_code == 200
    assert c.post("/sessions/s1/call", json={"tool": "t" * 129, "args": {}}).status_code == 422


def test_a_large_body_is_refused_before_it_is_parsed():
    c = client()
    c.post("/sessions", json=BODY)
    r = c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "a" * (MAX_BODY + 1)}})
    assert r.status_code == 413
    chunks = (b"x" * 1000 for _ in range(MAX_BODY // 1000 + 5))  # no Content-Length: counted as it arrives
    assert c.post("/sessions/s1/call", content=chunks, headers={"Content-Type": "application/json"}).status_code == 413
    assert c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}}).status_code == 200


def test_interactive_docs_are_hidden_when_tokens_are_set_but_not_in_the_open_demo():
    assert client(agent=AGENT).get("/openapi.json").status_code == 404
    assert client(agent=AGENT).get("/docs").status_code == 404
    assert client().get("/openapi.json").status_code == 200


@pytest.mark.parametrize("grants", [{"resources": "research/*"}, {"resource": ["x"]}, {"max_classification": "TOP"}, {"ops": ["fly"]},
                                    {"resources": ["x"] * 201}, {"resources": [1]}, {"project_root": ["a"]}, "everything"])
def test_malformed_grants_are_refused(grants):
    with pytest.raises(ValueError):
        validate_grants(grants)
    with pytest.raises(ValueError):
        compile_scope("Read research/paper.pdf", grants)
    assert client().post("/sessions", json={**BODY, "grants": grants}).status_code in (422,)


def test_good_grants_pass_unchanged():
    g = {"resources": ["research/*"], "destinations": ["a@b.org"], "ops": ["read", "send"], "max_classification": "CONFIDENTIAL",
         "project_root": "research/"}
    assert validate_grants(g) is g


def guard():
    seen = []
    g = Guard(trust={"bob@x.org": "approved"})

    @g.tool("read", resource_arg="path")
    def read_file(path):
        seen.append(("read", path))
        return "text"

    @g.tool("send", dest_arg="to")
    def send_email(to="default@elsewhere.org", body=""):  # a default recipient the policy never sees
        seen.append(("send", to))
        return "sent"

    @g.tool("send", resource_arg="attachment", dest_arg="to", resource_optional=True, name="send_with_file")
    def send_with_file(to, body="", attachment=None):
        seen.append(("send_with_file", to, attachment))
        return "sent"

    s = g.session("Read research/paper.pdf and email bob@x.org a summary", {"resources": ["research/*"], "destinations": ["bob@x.org"]})
    return s, seen


@pytest.mark.parametrize("args", [{}, {"path": None}, {"path": ""}, {"path": "   "}])
def test_a_call_with_no_file_is_refused_not_waved_through(args):
    s, seen = guard()
    r = s.call("read_file", **args)
    assert r.decision == "BLOCK" and "INPUT-001" in r.rules and seen == []


def test_a_call_with_no_recipient_cannot_fall_back_to_a_default():
    s, seen = guard()
    r = s.call("send_email", body="hi")
    assert r.decision == "BLOCK" and "INPUT-001" in r.rules and seen == []
    assert s.call("send_email", to=None, body="hi").decision == "BLOCK"


def test_an_undeclared_argument_is_refused():
    s, seen = guard()
    r = s.call("read_file", path="research/paper.pdf", mode="w")
    assert r.decision == "BLOCK" and "INPUT-001" in r.rules and seen == []


def test_an_optional_attachment_may_be_left_out_and_normal_calls_still_work():
    s, seen = guard()
    assert s.call("read_file", path="research/paper.pdf").allowed
    assert s.call("send_with_file", to="bob@x.org", body="hi").allowed
    assert s.call("send_with_file", to="bob@x.org", body="hi", attachment="").allowed
    assert seen[-1] == ("send_with_file", "bob@x.org", None) or seen[-1][0] == "send_with_file"


def test_tools_that_take_any_keyword_are_not_blamed_for_extra_arguments():
    g = Guard()

    @g.tool("read", resource_arg="path")
    def proxied(path, **kw):  # like a proxied MCP tool, whose arguments are not known in advance
        return "ok"

    s = g.session("Read research/paper.pdf", {"resources": ["research/*"]})
    assert s.call("proxied", path="research/paper.pdf", anything="goes").allowed
