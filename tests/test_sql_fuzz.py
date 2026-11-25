"""Mutation fuzzing of SQL against SQLite as the independent judge (F38). Set VERITASK_SQL_TRIALS to run more."""

import os
import random

import pytest
from fuzz_sql import BASES, CLASSES, MUTATIONS, WRITES, judge, mutate

from veritask import Guard

TRIALS = int(os.environ.get("VERITASK_SQL_TRIALS", "1500"))


def session(task="Query the papers table for recent titles"):
    g = Guard(tables=CLASSES)

    @g.tool("query")
    def db_query(sql):
        return "rows"

    return g.session(task, {"max_classification": "INTERNAL"})


def test_no_spelling_that_sqlite_reads_as_a_sensitive_table_gets_through():
    rng = random.Random(21)
    reached, escaped = 0, []
    for _ in range(TRIALS):
        sql, names = mutate(rng, rng.choice(BASES))
        verdict = judge(sql)
        if not verdict or not verdict[0]:
            continue
        reached += 1
        if session().call("db_query", sql=sql).decision == "ALLOW":
            escaped.append((names, sql))
    assert reached > TRIALS // 4, "the mutations rarely still reach a sensitive table, so the test proves little"
    assert escaped == [], escaped[:5]


def test_no_spelling_that_sqlite_treats_as_a_change_is_allowed_for_a_read_only_task():
    rng = random.Random(22)
    reached, escaped = 0, []
    for _ in range(TRIALS):
        sql, names = mutate(rng, rng.choice(WRITES))
        verdict = judge(sql)
        if not verdict or not verdict[1]:
            continue
        reached += 1
        if session().call("db_query", sql=sql).decision == "ALLOW":
            escaped.append((names, sql))
    assert reached > TRIALS // 4
    assert escaped == [], escaped[:5]


@pytest.mark.parametrize("sql,tables,changes", [
    ("SELECT * FROM salaries", {"salaries"}, False), ("SELECT * FROM 'salaries'", {"salaries"}, False),
    ('SELECT * FROM "main"."users"', {"users"}, False), ("SELECT * FROM papers", set(), False),
    ("DELETE FROM papers", set(), True), ("SELECT * FROM nothing_here", None, None), ("SELEC 1", None, None),
])
def test_the_sqlite_judge_agrees_with_what_is_known(sql, tables, changes):
    v = judge(sql)
    assert (v is None) if tables is None else v == (tables, changes)


def test_every_mutation_is_exercised_by_the_fuzzer():
    rng = random.Random(3)
    used = {n for _ in range(300) for n in mutate(rng, "SELECT * FROM salaries")[1]}
    assert used == {n for n, _ in MUTATIONS}
