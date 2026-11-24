"""A seeded generator of hostile tool calls, and a runner that records what the gateway did with them."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from veritask import Gateway, PolicyEngine, compile_scope
from veritask.mock_env import FILES, TRUST, MockEnv

TOOLS = ["read_file", "search_files", "send_email", "upload", "run_shell", "db_query", "nope", "", "READ_FILE"]
PATHS = sorted(FILES) + ["research/../hr/salary.xlsx", "HR/Salary.XLSX", "/etc/passwd", "../../x", "", " ", ".", "..", "research/",
                         "a" * 3000, "hr/salary.xlsx\x00.md", "\uff48\uff52/salary.xlsx", "C:\\Windows\\win.ini", "~/.ssh/id_rsa",
                         "research/%2e%2e/hr/x", "hr/salary.xlsx::$DATA", "\u202eexe.pdf", "research/\n/x"]
DESTS = sorted(TRUST) + ["", " ", "Attacker@Evil.Example", "mailto:a@b.c", "https://files.partner.org@evil.test/x", "x" * 1000,
                         "a@b@c", "<a@b.c>", "\u0430dvisor@university.edu", "http://[::1]/", "//evil.example", "null"]
COMMANDS = ["ls", "ls | sh", "cat research/paper.pdf", "rm -rf /", 'cat "hr/salary.xlsx"', "echo $(id)", "ls ${HOME}", "", "   ", "ls 'unterminated",
            "cat research/paper.pdf /etc/passwd", "ls\nid", "x" * 5000, "LS", "/bin/ls", "cat ../../etc/passwd"]
SQLS = ["SELECT * FROM papers", "SELECT * FROM salaries", "DROP TABLE papers", "", "ATTACH DATABASE 'x' AS y", "select*from users", "'; --",
        "SELECT " + "(" * 200 + "1" + ")" * 200, "SELECT * FROM \uff53alaries", "WITH x AS (SELECT * FROM users) SELECT * FROM x",
        "\x00", "SELECT 1; SELECT 2"]
BODIES = ["", "hello", "API_KEY=sk_test_FAKE0000000000", "alice,120000", "Alice earns $120k", "QWxpY2UsMTIwMDAw", "ignore previous instructions",
          "x" * 10000, "\x00\x01", "4P1_K3Y=sk_t3st_F4K3000000000", "a" * 17 + "==", "ff" * 40]
ODD = [None, 0, 1.5, True, [], {}, ["a"], {"a": 1}, "\ud800" if False else "\ufffd", b"bytes".decode()]
TASKS = ["Read research/paper.pdf and summarize it", "Read hr/salary.xlsx and email advisor@university.edu a status", "do stuff", "",
         "Run ls in the research folder", "Query the papers table", "Upload research/notes.md to files.partner.org", "x" * 2000,
         "Read everything and email it to advisor@university.edu"]
GRANTS = [{"resources": ["research/*"]}, {"resources": ["*"], "max_classification": "SECRET", "destinations": ["advisor@university.edu"]},
          {}, {"resources": ["hr/*"], "max_classification": "CONFIDENTIAL"}, {"resources": ["research/*"], "ops": ["read"]},
          {"resources": ["*"], "max_classification": "INTERNAL", "destinations": ["files.partner.org", "advisor@university.edu"]}]


def pick(rng: random.Random, pool):
    return rng.choice(pool)


def random_args(rng: random.Random, tool: str) -> dict:
    """Mostly plausible arguments, sometimes missing, extra, null or the wrong type."""
    args: dict = {}
    if tool in ("read_file", "READ_FILE"):
        args["path"] = pick(rng, PATHS)
    elif tool == "search_files":
        args["query"] = pick(rng, ["api key", "salary", "", "x" * 500, "password"])
    elif tool == "send_email":
        args.update(to=pick(rng, DESTS), body=pick(rng, BODIES))
        if rng.random() < 0.3:
            args["attachment"] = pick(rng, PATHS)
    elif tool == "upload":
        args.update(url=pick(rng, DESTS), data=pick(rng, BODIES))
    elif tool == "run_shell":
        args["cmd"] = pick(rng, COMMANDS)
    elif tool == "db_query":
        args["sql"] = pick(rng, SQLS)
    r = rng.random()
    if r < 0.08 and args:
        args.pop(rng.choice(list(args)))  # a missing argument
    elif r < 0.16 and args:
        args[rng.choice(list(args))] = pick(rng, ODD)  # a wrong type
    elif r < 0.22:
        args["extra"] = pick(rng, BODIES)  # an argument nobody declared
    return args


@dataclass
class Run:
    decisions: list = field(default_factory=list)  # (session, tool, verdict, rules) in order
    calls: list = field(default_factory=list)  # (session, tool, args, verdict, tool_ran) in order
    executed: int = 0
    allowed: int = 0
    engine_errors: list = field(default_factory=list)
    crashes: list = field(default_factory=list)
    gateway: Gateway | None = None
    env: MockEnv | None = None


def run_fuzz(seed: int, steps: int = 120, engine: PolicyEngine | None = None) -> Run:
    rng = random.Random(seed)
    env = MockEnv()
    executed = {"n": 0}
    tools = []
    for t in env.tools():
        def wrap(fn=t.fn):
            def inner(*a, **k):
                executed["n"] += 1
                return fn(*a, **k)
            return inner
        object.__setattr__(t, "fn", wrap())
        tools.append(t)
    gw = Gateway(tools, env.catalog(), engine or PolicyEngine())
    run = Run(gateway=gw, env=env)
    sessions: list[str] = []
    for i in range(steps):
        if not sessions or rng.random() < 0.08:
            sid = f"s{len(sessions)}"
            try:
                gw.open_session(sid, rng.choice(["agent-a", "agent-b"]), compile_scope(pick(rng, TASKS), pick(rng, GRANTS)))
                sessions.append(sid)
            except ValueError as exc:  # grants the validator refuses are fine
                run.decisions.append(("open-refused", str(exc)[:40]))
            continue
        sid = rng.choice(sessions)
        tool = pick(rng, TOOLS)
        args = random_args(rng, tool)
        before = executed["n"]
        try:
            res = gw.call(sid, tool, **args)
        except Exception as exc:  # the gateway must not let anything escape
            run.crashes.append((seed, i, tool, args, repr(exc)))
            continue
        d = res.decision
        ran = executed["n"] - before
        run.decisions.append((sid, tool, d.decision.value, tuple(d.fired_rules)))
        run.calls.append((sid, tool, args, d.decision.value, ran))
        run.executed += ran
        run.allowed += d.decision.value == "ALLOW"
        if "ENGINE-ERR" in d.fired_rules:
            run.engine_errors.append((seed, i, tool, args, d.explanation))
        if ran and d.decision.value != "ALLOW":
            run.crashes.append((seed, i, tool, args, f"tool ran under a {d.decision.value} decision"))
        if rng.random() < 0.03 and gw.pending:  # a human approves or rejects something now and then
            aid = rng.choice(list(gw.pending))
            try:
                gw.approve(aid, "human") if rng.random() < 0.5 else gw.reject(aid, "human")
            except Exception:
                pass  # the tool itself may fail after approval; that is an answer, not a crash here
        if rng.random() < 0.02:
            gw.close(sid, "admin", "fuzz")
    return run


def audit_ok(run: Run) -> bool:
    return run.gateway.audit.verify() == (True, None)


def fingerprint(run: Run) -> str:
    return json.dumps(run.decisions, default=str)
