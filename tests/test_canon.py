"""The policy must judge the file or address the tool will act on, however the agent spells it (F32)."""

import pytest

from veritask import Guard, Verdict
from veritask.canon import clean_destination, clean_path, domain_chain, fold
from veritask.gateway import Catalog
from veritask.models import Classification, Trust

CLASSES = {"hr/salary.xlsx": "CONFIDENTIAL", "secrets/app.env": "SECRET"}
TRUST = {"advisor@university.edu": "approved", "attacker@evil.example": "denylisted", "me@lab.local": "local",
         "files.partner.org": "approved", "evil.test": "denylisted"}


def make(read_log=None, sent=None):
    g = Guard(classes=CLASSES, trust=TRUST)

    @g.tool("read", resource_arg="path")
    def read_file(path):
        if read_log is not None:
            read_log.append(path)
        return "alice,120000"

    @g.tool("send", dest_arg="to")
    def send_email(to, body=""):
        if sent is not None:
            sent.append(to)
        return "sent"

    @g.tool("upload", dest_arg="url")
    def upload(url, data=""):
        return "up"

    return g


def wide(g):
    return g.session("Read research/paper.pdf and summarize it", {"resources": ["*"], "max_classification": "INTERNAL"})


@pytest.mark.parametrize("raw,path,flags", [
    ("research/../hr/salary.xlsx", "hr/salary.xlsx", []), ("./hr//salary.xlsx", "hr/salary.xlsx", []),
    ("HR\\Salary.xlsx", "HR/Salary.xlsx", []), ("hr/salary.xlsx ", "hr/salary.xlsx", []), ("hr/salary.xlsx.", "hr/salary.xlsx", []),
    ("/hr/salary.xlsx", "hr/salary.xlsx", []), ("C:\\hr\\salary.xlsx", "hr/salary.xlsx", []),
    ("\uff48\uff52/salary.xlsx", "hr/salary.xlsx", []),
    ("hr/salary.xlsx\x00.md", "hr/salary.xlsx.md", ["control-character"]),
    ("research/%2e%2e/hr/x", "research/%2e%2e/hr/x", ["percent-encoding"]),
    ("hr/salary.xlsx::$DATA", "hr/salary.xlsx", ["colon-in-name"]), ("HR~1/SALARY~1.XLS", "HR~1/SALARY~1.XLS", ["short-name"]),
])
def test_paths_are_cleaned_and_odd_spellings_flagged(raw, path, flags):
    assert clean_path(raw) == (path, flags)


@pytest.mark.parametrize("raw,key,value,flags", [
    ("Advisor@University.EDU", "advisor@university.edu", "Advisor@University.EDU", []),
    ("  advisor@university.edu \n", "advisor@university.edu", "advisor@university.edu", []),
    ("mailto:attacker@evil.example", "attacker@evil.example", "attacker@evil.example", []),
    ("Mallory <attacker@evil.example>", "attacker@evil.example", "attacker@evil.example", []),
    ("attacker@evil.example.", "attacker@evil.example", "attacker@evil.example.", []),
    ("https://Files.Partner.org:8443/up?x=1", "files.partner.org", "https://Files.Partner.org:8443/up?x=1", []),
    ("https://files.partner.org@evil.test/x", "evil.test", "https://files.partner.org@evil.test/x", []),
    ("me@l\u0430b.local", "me@xn--lb-7kc.local", "me@l\u0430b.local", []),  # a Cyrillic a: never equals the real name
    ("a\x00b@evil.example", "ab@evil.example", "ab@evil.example", ["control-character"]),
])
def test_destinations_are_cleaned(raw, key, value, flags):
    assert clean_destination(raw) == (key, value, flags)


def test_domain_chain_and_fold():
    assert domain_chain("a@b.evil.test") == ["a@b.evil.test", "@b.evil.test", "b.evil.test", "evil.test", "test"]
    assert fold("HR/Salary.XLSX") == fold("\uff48\uff52/salary.xlsx")


def test_the_catalog_ignores_case_and_denylists_whole_domains():
    c = Catalog({"hr/salary.xlsx": Classification.CONFIDENTIAL}, {"evil.test": Trust.DENYLISTED, "bob@x.org": Trust.APPROVED,
                                                                  "attacker@evil.example": Trust.DENYLISTED})
    assert c.classify("HR/SALARY.XLSX") == Classification.CONFIDENTIAL and c.classify("nope") == Classification.INTERNAL
    assert c.trust_of("anyone@sub.evil.test") == Trust.DENYLISTED and c.trust_of("https://a.evil.test/x") == Trust.DENYLISTED
    assert c.trust_of("BOB@X.ORG") == Trust.APPROVED and c.trust_of("bob@x.org.evil.example") == Trust.UNKNOWN
    assert c.trust_of("attacker+promo@evil.example") == Trust.DENYLISTED


@pytest.mark.parametrize("path", ["HR/salary.xlsx", "hr/SALARY.XLSX", "hr/salary.xlsx ", "hr/salary.xlsx.", "\uff48\uff52/salary.xlsx",
                                  "/hr/salary.xlsx", "HR\\SALARY.XLSX", "Secrets/APP.ENV", "secrets/app.env."])
def test_a_sensitive_file_cannot_be_reached_by_spelling_it_differently(path):
    r = wide(make()).call("read_file", path=path)
    assert r.decision == "BLOCK" and ("SCOPE-003" in r.rules or "SCOPE-005" in r.rules)


@pytest.mark.parametrize("path", ["hr/salary.xlsx\x00.md", "research/%2e%2e/hr/salary.xlsx", "hr/salary.xlsx::$DATA", "HR~1/SALARY~1.XLS"])
def test_spellings_no_honest_caller_needs_are_refused_outright(path):
    r = wide(make()).call("read_file", path=path)
    assert r.decision == "BLOCK" and "INPUT-001" in r.rules


def test_the_tool_receives_the_path_that_was_judged():
    log = []
    r = wide(make(read_log=log)).call("read_file", path="./Research//paper.pdf ")
    assert r.allowed and log == ["Research/paper.pdf"]


@pytest.mark.parametrize("path", ["Research/Paper.PDF", "./research/paper.pdf", "research//notes.md", "research/paper.pdf ", "research\\notes.md"])
def test_odd_but_harmless_spellings_of_allowed_files_still_work(path):
    g = make()
    s = g.session("Read research/paper.pdf and summarize it", {"resources": ["Research/*"], "max_classification": "INTERNAL"})
    assert s.call("read_file", path=path).allowed


@pytest.mark.parametrize("dest", ["Attacker@Evil.Example", "attacker@evil.example ", "attacker@evil.example.", " attacker@evil.example",
                                  "attacker@evil.example\n", "mailto:attacker@evil.example", "Mallory <attacker@evil.example>",
                                  "attacker+promo@evil.example", "\uff41ttacker@evil.example", "anyone@evil.test", "anyone@sub.evil.test"])
def test_a_denylisted_address_is_refused_however_it_is_written(dest):
    sent = []
    g = make(sent=sent)
    s = g.session("Read research/paper.pdf and email advisor@university.edu a summary",
                  {"resources": ["research/*"], "destinations": ["advisor@university.edu"]})
    s.call("read_file", path="research/paper.pdf")
    r = s.call("send_email", to=dest, body="hi")
    assert r.decision in ("BLOCK", "QUARANTINE") and "EGRESS-003" in r.rules and sent == []


def test_an_approved_address_and_url_are_recognised_in_any_spelling_and_lookalikes_are_not():
    sent = []
    g = make(sent=sent)
    s = g.session("Read research/paper.pdf, email advisor@university.edu a summary and upload it to files.partner.org",
                  {"resources": ["research/*"], "destinations": ["Advisor@University.edu", "files.partner.org"]})
    s.call("read_file", path="research/paper.pdf")
    assert s.call("send_email", to="  ADVISOR@university.edu ", body="hi").allowed and sent == ["ADVISOR@university.edu"]
    assert s.call("upload", url="https://Files.Partner.org/up", data="x").allowed
    assert s.call("send_email", to="advisor@university.edu.evil.example", body="hi").decision != "ALLOW"
    assert s.call("send_email", to="advisor@univers\u0456ty.edu", body="hi").decision != "ALLOW"  # a Cyrillic i


def test_a_user_info_trick_in_a_url_is_judged_by_the_real_host():
    g = make()
    s = g.session("Read research/paper.pdf and upload it to files.partner.org", {"resources": ["research/*"],
                                                                                 "destinations": ["files.partner.org"]})
    s.call("read_file", path="research/paper.pdf")
    r = s.call("upload", url="https://files.partner.org@evil.test/x", data="x")
    assert r.decision in ("BLOCK", "QUARANTINE") and "EGRESS-003" in r.rules


def test_files_named_inside_a_shell_command_get_the_same_treatment():
    g = Guard(classes=CLASSES)

    @g.tool("exec")
    def run_shell(cmd):
        return "ok"

    s = g.session("Run ls", {"resources": ["*"], "max_classification": "INTERNAL"})
    r = s.call("run_shell", cmd="cat HR/Salary.xlsx")
    assert r.decision != Verdict.ALLOW.value
