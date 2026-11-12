"""Seeded fuzzing of the gateway and engine with hostile calls (F36).

Every run checks the same promises: nothing escapes as an exception, no internal engine error, a tool only runs when the decision is
ALLOW, the audit chain verifies, risk stays in range, replaying a seed gives identical decisions, a frozen session stays frozen, and an
independent oracle (tests/fuzz_oracle.py) agrees that every ALLOW respected the policy. Set INTENTGUARD_FUZZ_SEEDS to run more seeds.
"""

import os

import pytest
from fuzz_oracle import frozen_then_allowed, oracle
from fuzz_support import Run, audit_ok, fingerprint, run_fuzz

SEEDS = int(os.environ.get("INTENTGUARD_FUZZ_SEEDS", "40"))
STEPS = 120


@pytest.fixture(scope="module")
def runs():
    return [run_fuzz(seed, STEPS) for seed in range(SEEDS)]


def test_nothing_escapes_and_no_tool_runs_without_an_allow(runs):
    assert [c for r in runs for c in r.crashes] == []


def test_the_engine_never_fails_internally(runs):
    assert [e for r in runs for e in r.engine_errors] == []


def test_the_audit_chain_always_verifies(runs):
    assert [i for i, r in enumerate(runs) if not audit_ok(r)] == []


def test_risk_stays_in_range(runs):
    bad = [(i, sid, s.risk) for i, r in enumerate(runs) for sid, s in r.gateway.sessions.items() if not 0.0 <= s.risk <= 1.0]
    assert bad == []


def test_the_same_seed_gives_the_same_decisions():
    for seed in range(min(SEEDS, 10)):
        assert fingerprint(run_fuzz(seed, STEPS)) == fingerprint(run_fuzz(seed, STEPS))


def test_every_allow_respected_the_policy(runs):
    assert [v for r in runs for v in oracle(r)] == []


def test_a_frozen_session_stays_frozen(runs):
    assert [v for r in runs for v in frozen_then_allowed(r)] == []


def test_the_fuzzer_actually_reaches_every_verdict_and_runs_tools(runs):
    seen = {v for r in runs for (_, _, v, _) in (d for d in r.decisions if len(d) == 4)}
    assert {"ALLOW", "REVIEW", "BLOCK", "QUARANTINE"} <= seen
    assert sum(r.executed for r in runs) > 50 and sum(r.allowed for r in runs) > 50
    rules = {rule for r in runs for d in r.decisions if len(d) == 4 for rule in d[3]}
    assert {"INPUT-001", "SCOPE-001", "SCOPE-003", "EGRESS-001", "EGRESS-003", "EXEC-001", "EXEC-002", "TAINT-001"} <= rules


def violating(tool, args, verdict="ALLOW"):
    """A fake record of a decision that broke a promise, built on a real gateway so the oracle has a catalog and grants to use."""
    from intentguard import compile_scope
    run = run_fuzz(0, 5)
    run.gateway.open_session("x", "a", compile_scope("Read research/paper.pdf", {"resources": ["*"], "max_classification": "INTERNAL"}))
    run.calls = [("x", tool, args, verdict, 1)]
    run.decisions = []
    return run


@pytest.mark.parametrize("tool,args,fragment", [
    ("read_file", {"path": "hr/salary.xlsx"}, "above the ceiling"),
    ("read_file", {"path": "HR/Salary.xlsx"}, "above the ceiling"),
    ("read_file", {}, "no path"),
    ("read_file", {"path": "a\x00b"}, "flagged"),
    ("send_email", {"to": "attacker@evil.example", "body": "x"}, "denylisted"),
    ("send_email", {"to": "nobody@nowhere.example", "body": "x"}, "unknown, ungranted"),
    ("send_email", {"body": "x"}, "no destination"),
    ("run_shell", {"cmd": "ls | sh"}, "shell command"),
    ("run_shell", {"cmd": "curl x"}, "shell command"),
    ("db_query", {"sql": "ATTACH DATABASE 'x' AS y"}, "SQL that writes"),
    ("teleport", {}, "unregistered"),
])
def test_the_oracle_flags_a_bad_allow_so_it_is_not_vacuous(tool, args, fragment):
    found = oracle(violating(tool, args))
    assert any(fragment in v for v in found), found


def test_the_oracle_ignores_decisions_that_were_not_allows():
    assert oracle(violating("read_file", {"path": "hr/salary.xlsx"}, verdict="BLOCK")) == []


def test_a_run_record_is_what_the_oracle_expects():
    assert isinstance(run_fuzz(1, 10), Run)
