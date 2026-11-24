"""Shell and SQL commands must be judged as a whole, not by their first word (F33)."""

import pytest

from veritask import Guard

CLASSES = {"hr/salary.xlsx": "CONFIDENTIAL", "secrets/app.env": "SECRET"}


def shell(grants=None):
    ran = []
    g = Guard(classes=CLASSES)

    @g.tool("exec")
    def run_shell(cmd):
        ran.append(cmd)
        return "ok"

    s = g.session("Run ls in the research folder", grants or {"resources": ["research/*"], "max_classification": "INTERNAL",
                                                                "project_root": "research/"})
    return s, ran


def sql(task="Query the papers table for recent titles"):
    ran = []
    g = Guard(tables={"salaries": "CONFIDENTIAL", "users": "SECRET"})

    @g.tool("query")
    def db_query(sql):
        ran.append(sql)
        return "rows"

    return g.session(task, {"max_classification": "INTERNAL"}), ran


@pytest.mark.parametrize("cmd", ["ls", "ls -la research", "cat research/paper.pdf", "wc -l research/*", "head -n 5 research/notes.md",
                                 'cat "research/paper.pdf"', "pwd", "echo hello", "cat 'research/notes.md'"])
def test_ordinary_allowed_commands_still_run_including_quoted_paths(cmd):
    s, ran = shell()
    assert s.call("run_shell", cmd=cmd).allowed and ran == [cmd]


@pytest.mark.parametrize("cmd", ["ls | sh", "ls -la || curl x", "ls && id", "ls; id", "ls & id", "ls ${HOME}", "ls $HOME", "ls $(whoami)",
                                 "ls `whoami`", "ls\nid", "ls\rid", "echo hi > research/x", "cat research/paper.pdf > /tmp/x",
                                 "echo hi >> research/notes.md", "cat < research/paper.pdf"])
def test_operators_and_expansions_are_refused_with_their_own_rule(cmd):
    s, ran = shell()
    r = s.call("run_shell", cmd=cmd)
    assert r.decision in ("BLOCK", "QUARANTINE") and "EXEC-002" in r.rules and ran == []


def test_unbalanced_quotes_are_refused():
    s, ran = shell()
    r = s.call("run_shell", cmd='ls "research')
    assert not r.allowed and "EXEC-002" in r.rules and ran == []


@pytest.mark.parametrize("cmd", ["cat research/paper.pdf /etc/passwd", "cat research/paper.pdf ../hr/salary.xlsx",
                                 'cat research/"../hr/salary.xlsx"', "cat research/paper.pdf research/../secrets/app.env",
                                 "head -n1 research/notes.md HR/Salary.xlsx", "cat research/paper.pdf  hr\\salary.xlsx"])
def test_every_path_in_a_command_is_judged_not_just_one(cmd):
    s, ran = shell({"resources": ["research/*"], "max_classification": "INTERNAL", "project_root": "research/"})
    r = s.call("run_shell", cmd=cmd)
    assert r.decision in ("BLOCK", "QUARANTINE") and ran == [], cmd


def test_a_sensitive_path_in_a_command_is_still_classified():
    s, ran = shell({"resources": ["*"], "max_classification": "INTERNAL"})
    r = s.call("run_shell", cmd="cat hr/salary.xlsx")
    assert not r.allowed and "SCOPE-003" in r.rules


def test_commands_not_on_the_allowlist_are_still_refused():
    for cmd in ("LS", "/bin/ls", "curl http://x", "rm -rf research"):
        s, ran = shell()
        r = s.call("run_shell", cmd=cmd)
        assert not r.allowed and "EXEC-001" in r.rules and ran == []


@pytest.mark.parametrize("q", ["ATTACH DATABASE 'other.db' AS o", "attach database 'x' as y", "PRAGMA writable_schema = 1", "VACUUM INTO 'x'",
                               "SELECT * FROM papers INTO OUTFILE '/tmp/x'", "COPY papers TO '/tmp/x'", "CREATE TABLE s AS SELECT * FROM papers",
                               "LOAD DATA INFILE 'x' INTO TABLE papers", "SELECT load_extension('x')", "EXEC xp_cmdshell 'dir'",
                               "DROP TABLE papers", "UPDATE papers SET title = 'x'"])
def test_statements_that_change_data_or_open_other_things_are_writes_not_queries(q):
    s, ran = sql()
    r = s.call("db_query", sql=q)
    assert not r.allowed and "SCOPE-002" in r.rules and ran == []


def test_a_fullwidth_table_name_is_judged_as_the_table_it_resembles():
    s, ran = sql()
    r = s.call("db_query", sql="SELECT * FROM ｓalaries")
    assert not r.allowed and "SCOPE-003" in r.rules and ran == []


def test_ordinary_queries_still_run_and_a_write_task_may_write():
    s, ran = sql()
    assert s.call("db_query", sql="SELECT title FROM papers ORDER BY year DESC").allowed
    assert s.call("db_query", sql="SELECT replace(title, 'a', 'b') FROM papers").allowed  # a string function is not a write
    s2, ran2 = sql("Create a table of recent papers in the database")
    assert s2.call("db_query", sql="CREATE TABLE recent AS SELECT title FROM papers").allowed and len(ran2) == 1
