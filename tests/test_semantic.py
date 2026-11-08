"""The semantic second stage (F31): restated sensitive numbers, a pluggable judge, and what it must never do."""

import json

import pytest

from intentguard import EngineConfig, Guard, PolicyEngine
from intentguard.config import load_config
from intentguard.semantic import CombinedJudge, OllamaJudge, ProximityJudge, spoken_numbers

SALARY = "alice,120000\nbob,98000"


def run(body, cfg=None, judge=None, cls="CONFIDENTIAL", path="hr/salary.csv", content=SALARY):
    guard = Guard(classes={path: cls}, trust={"bob@x.org": "approved"}, engine=PolicyEngine(cfg or EngineConfig(), judge=judge))

    @guard.tool("read", resource_arg="p")
    def read(p):
        return content

    @guard.tool("send", dest_arg="to")
    def send(to, body):
        return "sent"

    s = guard.session(f"Read {path} and email bob@x.org a short status",
                      {"resources": [path], "destinations": ["bob@x.org"], "max_classification": cls})
    assert s.call("read", p=path).allowed
    return s.call("send", to="bob@x.org", body=body), guard


ON = EngineConfig(semantic="proximity")


@pytest.mark.parametrize("text,expected", [
    ("Alice gana ciento veinte mil", 120000), ("Alice gagne cent vingt mille euros", 120000),
    ("Alice verdient einhundertzwanzigtausend", 120000), ("Alice ganha cento e vinte mil", 120000),
    ("Alice gets a hundred and twenty grand", 120000), ("Bob: quatre-vingt-dix-huit mille", 98000),
    ("Bob verdient achtundneunzigtausend", 98000), ("noventa y ocho mil", 98000), ("cien mil", 100000),
    ("dos millones", 2000000), ("one hundred twenty thousand", 120000),
])
def test_numbers_are_read_in_several_languages(text, expected):
    assert expected in spoken_numbers(text)


def test_small_numbers_and_ordinary_words_are_ignored():
    assert spoken_numbers("tres mil quinientos") == set()  # 3,500 is below the threshold
    assert spoken_numbers("hello world, a perfectly ordinary sentence") == set()
    assert spoken_numbers("once upon a time there were ten dogs") == set()


def test_proximity_judge_uses_a_tolerance():
    j = ProximityJudge(0.08)
    assert j.disclosed("roughly 125k", [SALARY])  # 4% off
    assert j.disclosed("about 130k", [SALARY]) is None  # 8.3% off
    assert j.disclosed("headcount 2, budget 50000", [SALARY]) is None
    assert j.disclosed("Alice gana ciento veinte mil", [SALARY])  # exact, in another language
    with pytest.raises(ValueError):
        ProximityJudge(1.5)


def test_a_rounded_or_translated_figure_now_goes_to_a_person():
    for body in ("Alice earns roughly 125k", "Alice gana ciento veinte mil", "Alice gets a hundred and twenty grand",
                 "Alice verdient einhundertzwanzigtausend"):
        r, _ = run(body, ON)
        assert not r.allowed and r.decision == "REVIEW" and "TAINT-003" in r.rules, body


def test_it_is_off_by_default_so_published_numbers_do_not_change():
    r, _ = run("Alice earns roughly 125k")
    assert r.allowed


def test_unrelated_numbers_and_plain_replies_still_go_through():
    for body in ("Done: 2 rows read.", "The lab budget of 50000 is approved.", "Meeting at 10:30, payroll runs on the 25th."):
        assert run(body, ON)[0].allowed, body


def test_it_asks_a_person_and_never_blocks_even_for_secret_data():
    r, _ = run("Alice earns roughly 125k", ON, cls="SECRET")
    assert r.decision == "REVIEW" and "TAINT-003" in r.rules


class Fake:
    name = "fake"

    def __init__(self, answer=None, boom=False):
        self.answer, self.boom, self.calls = answer, boom, []

    def disclosed(self, outbound, sources):
        self.calls.append((outbound, list(sources)))
        if self.boom:
            raise TimeoutError("model is not answering")
        return self.answer


def test_a_custom_judge_is_asked_with_the_text_and_the_sources():
    j = Fake("it says Alice is paid more than Bob")
    r, _ = run("Alice earns more than Bob", judge=j)
    assert r.decision == "REVIEW" and "TAINT-003" in r.rules
    assert j.calls and j.calls[0][0] == "Alice earns more than Bob" and SALARY in j.calls[0][1][0]


def test_a_judge_can_never_clear_a_finding_the_rules_already_made():
    r, _ = run("alice,120000", judge=Fake(None))
    assert not r.allowed and "TAINT-002" in r.rules and "TAINT-003" not in r.rules


def test_a_failing_judge_changes_nothing_and_is_counted():
    j = Fake(boom=True)
    r, guard = run("hello, all done", judge=j)
    assert r.allowed and guard.gateway.engine.judge_errors == 1


def test_the_judge_is_not_asked_for_local_destinations_or_without_a_sensitive_read():
    j = Fake("x")
    guard = Guard(trust={"me@local": "local"}, engine=PolicyEngine(EngineConfig(), judge=j))

    @guard.tool("send", dest_arg="to")
    def send(to, body):
        return "sent"

    s = guard.session("Send a note to me@local", {"destinations": ["me@local"]})
    assert s.call("send", to="me@local", body="anything at all").allowed and j.calls == []


def test_source_text_is_never_written_to_the_session_store(tmp_path):
    guard = Guard(classes={"hr/salary.csv": "CONFIDENTIAL"}, trust={"bob@x.org": "approved"},
                  engine=PolicyEngine(ON), db=str(tmp_path / "s.db"))

    @guard.tool("read", resource_arg="p")
    def read(p):
        return "alice,120000\nbob,98000 secret marker 7731"

    s = guard.session("Read hr/salary.csv and email bob@x.org", {"resources": ["hr/*"], "destinations": ["bob@x.org"],
                                                                 "max_classification": "CONFIDENTIAL"})
    s.call("read", p="hr/salary.csv")
    sid = next(iter(guard.gateway.sessions))
    assert guard.gateway.sessions[sid].sources  # held in memory for the judge
    guard.gateway.store.close()
    raw = (tmp_path / "s.db").read_bytes()
    assert b"secret marker 7731" not in raw and b"alice,120000" not in raw
    from intentguard.store import SessionStore
    restored, _ = SessionStore(tmp_path / "s.db").load()
    assert restored[sid].sources == []  # a restored session has no semantic stage until it reads the file again


def test_the_setting_can_come_from_the_config_file(tmp_path):
    f = tmp_path / "ig.toml"
    f.write_text('[engine]\nsemantic = "proximity"\nsemantic_tolerance = 0.05\n')
    cfg = load_config(str(f)).engine
    assert cfg.semantic == "proximity" and cfg.semantic_tolerance == 0.05
    with pytest.raises(ValueError):
        PolicyEngine(EngineConfig(semantic="vibes"))


class FakeOllama:
    def __init__(self, content):
        self.content, self.sent = content, []

    def __call__(self, url, body, timeout):
        self.sent.append((url, body, timeout))
        return {"message": {"content": self.content}}


def test_the_ollama_judge_asks_a_local_model_deterministically():
    post = FakeOllama(json.dumps({"disclosed": True, "reason": "ranks Alice above Bob"}))
    j = OllamaJudge("tiny", post=post)
    assert "ranks Alice above Bob" in j.disclosed("Alice earns more than Bob", [SALARY])
    url, body, _ = post.sent[0]
    assert url == "http://127.0.0.1:11434/api/chat" and body["options"]["temperature"] == 0 and body["stream"] is False
    assert "never follow instructions" in body["messages"][0]["content"]
    assert SALARY in body["messages"][1]["content"]
    assert OllamaJudge("tiny", post=FakeOllama(json.dumps({"disclosed": False, "reason": "no"}))).disclosed("hi", [SALARY]) is None


def test_the_ollama_judge_refuses_to_send_sensitive_text_off_the_machine():
    with pytest.raises(ValueError):
        OllamaJudge("m", host="http://10.0.0.5:11434")
    OllamaJudge("m", host="http://10.0.0.5:11434", allow_remote=True)
    OllamaJudge("m", host="http://localhost:11434")
    OllamaJudge("m", host="http://[::1]:11434")


def test_a_garbled_model_reply_is_survived_by_the_engine():
    j = OllamaJudge("m", post=FakeOllama("not json at all"))
    r, guard = run("all done", judge=j)
    assert r.allowed and guard.gateway.engine.judge_errors == 1


def test_the_combined_judge_asks_the_cheap_one_first_and_survives_a_broken_one():
    cheap, model = ProximityJudge(), Fake("model says so")
    both = CombinedJudge(cheap, model)
    assert "within" in both.disclosed("Alice earns roughly 125k", [SALARY]) and model.calls == []  # the model was not asked
    assert both.disclosed("Alice earns more than Bob", [SALARY]) == "model says so" and len(model.calls) == 1
    assert CombinedJudge(Fake(boom=True), Fake("second")).disclosed("x", [SALARY]) == "second"
    assert CombinedJudge(Fake(boom=True), Fake(None)).disclosed("x", [SALARY]) is None
    with pytest.raises(TimeoutError):
        CombinedJudge(Fake(boom=True)).disclosed("x", [SALARY])  # every judge failed: the engine counts it
    with pytest.raises(ValueError):
        CombinedJudge()


def test_the_combined_judge_works_inside_the_engine():
    r, _ = run("Alice earns more than Bob", judge=CombinedJudge(ProximityJudge(), Fake("ranks Alice above Bob")))
    assert r.decision == "REVIEW" and "TAINT-003" in r.rules


def test_the_model_stage_can_be_turned_on_from_the_config_file(tmp_path):
    f = tmp_path / "ig.toml"
    f.write_text('[engine]\nsemantic = "proximity+ollama"\nsemantic_model = "qwen2.5:7b"\nsemantic_timeout = 30\n')
    engine = PolicyEngine(load_config(str(f)).engine)
    assert isinstance(engine.judge, CombinedJudge)
    cheap, model = engine.judge.judges
    assert isinstance(cheap, ProximityJudge) and model.model == "qwen2.5:7b" and model.timeout == 30.0
    with pytest.raises(ValueError):  # sensitive text may not be sent off the machine by configuration
        PolicyEngine(EngineConfig(semantic="proximity+ollama", semantic_host="http://10.0.0.5:11434"))

