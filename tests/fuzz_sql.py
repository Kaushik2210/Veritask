"""Mutation fuzzing of SQL against the real SQLite engine as an INDEPENDENT judge of what a statement reads and changes.

The gateway decides from a text scan (`Gateway._tables`, `_WRITE_SQL`). SQLite decides from its own parser: the authorizer callback it
runs while it prepares a statement names every table it will read and every kind of change it will make. That makes SQLite the
oracle, written without any Veritask code. A statement is a bypass if SQLite says it reads a sensitive table (or changes anything)
and the gateway ALLOWED it for a task that may only read the public `papers` table.
"""

from __future__ import annotations

import random
import re
import sqlite3

SCHEMA = ("CREATE TABLE papers (id INTEGER, title TEXT, year INTEGER);"
          "CREATE TABLE salaries (name TEXT, amount INTEGER);"
          "CREATE TABLE users (name TEXT, token TEXT);")
SENSITIVE = {"salaries", "users"}
CLASSES = {"salaries": "CONFIDENTIAL", "users": "SECRET"}

_READ, _SELECT, _FUNCTION, _RECURSIVE = 20, 21, 31, 33  # sqlite3 authorizer action codes that only read


def judge(sql: str) -> tuple[set[str], bool] | None:
    """(sensitive tables SQLite would read, whether it would change or open anything), or None if SQLite does not accept it."""
    seen: set[str] = set()
    changes = []

    def auth(action, a1, a2, db, source):
        if action == _READ and a1:
            seen.add(a1.lower())
        elif action not in (_SELECT, _FUNCTION, _RECURSIVE, 22):  # 22 is a transaction
            changes.append(action)
        return sqlite3.SQLITE_OK if action in (_READ, _SELECT, _FUNCTION, _RECURSIVE) else sqlite3.SQLITE_DENY

    con = sqlite3.connect(":memory:")
    try:
        con.executescript(SCHEMA)
        con.set_authorizer(auth)
        try:
            con.executescript(sql)
        except sqlite3.DatabaseError as exc:
            if "not authorized" not in str(exc) and not seen and not changes:
                return None  # a syntax error or an unknown name: nothing is reached
    finally:
        con.close()
    return seen & SENSITIVE, bool(changes)


# ---- statements that reach sensitive data, and the spelling tricks ----------------------------------------------------------------

BASES = [
    "SELECT * FROM salaries", "SELECT name FROM users", "SELECT amount FROM salaries WHERE amount > 10",
    "SELECT title FROM papers, salaries", "SELECT title FROM papers JOIN users ON 1", "SELECT title FROM papers CROSS JOIN salaries",
    "SELECT title FROM papers WHERE id IN (SELECT amount FROM salaries)", "SELECT title FROM papers WHERE EXISTS (SELECT 1 FROM users)",
    "SELECT * FROM (SELECT * FROM salaries)", "WITH t AS (SELECT * FROM users) SELECT * FROM t",
    "SELECT title FROM papers UNION SELECT name FROM users", "SELECT (SELECT token FROM users LIMIT 1)",
]
WRITES = ["DELETE FROM papers", "UPDATE papers SET year = 1", "INSERT INTO papers VALUES (1, 'a', 2)", "DROP TABLE papers",
          "CREATE TABLE copy AS SELECT * FROM papers", "ALTER TABLE papers ADD COLUMN x", "PRAGMA writable_schema = 1",
          "ATTACH DATABASE ':memory:' AS o", "CREATE INDEX i ON papers (id)", "REPLACE INTO papers VALUES (1, 'a', 2)",
          "CREATE TRIGGER t AFTER INSERT ON papers BEGIN SELECT 1; END", "CREATE VIEW v AS SELECT * FROM papers", "VACUUM",
          "ANALYZE", "REINDEX", "WITH x AS (SELECT 1) DELETE FROM papers", "INSERT OR REPLACE INTO papers VALUES (1, 'a', 2)",
          "CREATE VIRTUAL TABLE v USING fts5(a)"]
TABLE = r"(?i)\b(salaries|users|papers)\b"


def _case(rng, s):
    return "".join(c.upper() if rng.random() < 0.4 else c.lower() if rng.random() < 0.2 else c for c in s)


def _quote_name(rng, s):
    style = rng.choice(['"%s"', "[%s]", "`%s`", "'%s'", "main.%s", '"main"."%s"', "[main].[%s]", "main . %s"])
    return re.sub(TABLE, lambda m: style % m.group(1), s)


def _spaces(rng, s):
    return re.sub(r" ", lambda m: rng.choice([" ", "  ", "\t", "\n", "/**/", " /* x */ ", " -- c\n", "\r\n", "\x0c"]), s)


def _paren(rng, s):
    return rng.choice(["(%s)", "SELECT * FROM (%s)", "WITH w AS (%s) SELECT * FROM w", "%s;", "%s; SELECT 1", "SELECT 1; %s", "EXPLAIN %s"]) % s


def _alias(rng, s):
    return re.sub(TABLE, lambda m: m.group(1) + rng.choice([" AS a", " a", " AS \"x y\""]), s, count=1)


def _comment_in_word(rng, s):
    # a comment between keywords is legal; inside a word it is not, so cut only at spaces
    return s.replace(" FROM ", rng.choice([" FROM/**/", "/**/FROM ", " FROM -- c\n"]), 1)


MUTATIONS = [("case", _case), ("quote name", _quote_name), ("spaces", _spaces), ("wrap", _paren), ("alias", _alias),
             ("comment", _comment_in_word)]


def mutate(rng: random.Random, base: str) -> tuple[str, list[str]]:
    names, s = [], base
    for _ in range(rng.randint(1, 3)):
        name, fn = rng.choice(MUTATIONS)
        s = fn(rng, s)
        names.append(name)
    return s, names
