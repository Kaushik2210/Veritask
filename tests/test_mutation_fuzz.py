"""Mutation fuzzing of spellings against an independent model of what a tool would reach (F37).

Each trial takes a known sensitive file or denylisted address, applies one to three spelling tricks that some real file system, URL
decoder or mail library treats as the same target (tests/fuzz_mutate.py), and checks that the gateway never ALLOWS a spelling the
independent model says reaches the target. Set VERITASK_MUTATION_TRIALS to run more.
"""

import os
import random

import pytest
from fuzz_mutate import (
    ADDRESS_MUTATIONS,
    DENYLISTED,
    PATH_MUTATIONS,
    SENSITIVE_FILES,
    mutate_address,
    mutate_path,
    reaches_address,
    reaches_file,
)

from veritask import Guard
from veritask.canon import clean_path

TRIALS = int(os.environ.get("VERITASK_MUTATION_TRIALS", "800"))
FS = ("posix", "windows", "mac", "url")


def gateway_session():
    g = Guard(classes=SENSITIVE_FILES, trust={"advisor@university.edu": "approved", **{a: "denylisted" for a in DENYLISTED}})

    @g.tool("read", resource_arg="path")
    def read_file(path):
        return "x"

    @g.tool("send", dest_arg="to")
    def send_email(to, body=""):
        return "sent"

    return g.session("Read research/paper.pdf and summarize it",
                     {"resources": ["*"], "max_classification": "INTERNAL", "destinations": ["advisor@university.edu"]})


def test_no_spelling_of_a_sensitive_file_gets_through():
    rng = random.Random(7)
    reached, escaped = 0, []
    for _ in range(TRIALS):
        path, names = mutate_path(rng, rng.choice(sorted(SENSITIVE_FILES)))
        if not any(reaches_file(path, fs=fs) for fs in FS):
            continue
        reached += 1
        if gateway_session().call("read_file", path=path).decision == "ALLOW":
            escaped.append((names, path))
    assert reached > TRIALS // 3, "the mutations rarely reach a sensitive file, so the test proves little"
    assert escaped == [], escaped[:5]


def test_no_spelling_of_a_denylisted_address_is_delivered_or_left_to_a_person():
    rng = random.Random(11)
    reached, escaped = 0, []
    for _ in range(TRIALS):
        addr, names = mutate_address(rng, rng.choice(sorted(DENYLISTED)))
        if not reaches_address(addr):
            continue
        reached += 1
        s = gateway_session()
        s.call("read_file", path="research/paper.pdf")
        if s.call("send_email", to=addr, body="hi").decision not in ("BLOCK", "QUARANTINE"):
            escaped.append((names, addr))
    assert reached > TRIALS // 3
    assert escaped == [], escaped[:5]


@pytest.mark.parametrize("base", sorted(SENSITIVE_FILES))
def test_the_independent_model_recognises_every_sensitive_file_in_its_plain_form(base):
    assert all(reaches_file(base, fs=fs) == base for fs in FS)
    assert reaches_file("research/paper.pdf", fs="posix") is None


@pytest.mark.parametrize("path,fs", [("HR/Salary.XLSX", "windows"), ("hr/salary.xlsx. ", "windows"), ("hr/salary.xlsx\x00.md", "windows"),
                                     ("\\\\?\\hr\\salary.xlsx", "windows"), ("%68r/%73alary.xlsx", "url"), ("hr/‌salary.xlsx", "mac"),
                                     ("hr/salary.xlsx::$DATA", "windows")])
def test_the_independent_model_agrees_these_spellings_reach_the_file(path, fs):
    assert reaches_file(path, fs=fs) is not None


@pytest.mark.parametrize("path,flag", [
    ("\\\\?\\hr\\salary.xlsx", "device-path"), ("//./hr/salary.xlsx", "device-path"), ("\\\\?\\UNC\\server\\share\\x", "device-path"),
    ("%68r/%73alary.xlsx", "percent-encoding"), ("research/100%25.txt", "percent-encoding"), ("hr/‌salary.xlsx", "invisible-character"),
    ("hr/sal­ary.xlsx", "invisible-character"), ("hr/‮salary.xlsx", "invisible-character"), ("﻿hr/salary.xlsx", "invisible-character"),
])
def test_the_three_classes_the_mutation_fuzzer_found_are_flagged(path, flag):
    assert flag in clean_path(path)[1]
    r = gateway_session().call("read_file", path=path)
    assert r.decision == "BLOCK" and "INPUT-001" in r.rules


def test_ordinary_paths_with_a_literal_percent_sign_in_prose_are_not_a_problem_but_encoded_bytes_are():
    assert clean_path("research/notes.md")[1] == [] and clean_path("research/50% done.md")[1] == []  # a bare % is not an escape
    assert clean_path("research/a%20b.md")[1] == ["percent-encoding"]


def test_every_mutation_is_exercised_by_the_fuzzer():
    rng = random.Random(3)
    used = {n for _ in range(400) for n in mutate_path(rng, "hr/salary.xlsx")[1]}
    assert used == {n for n, _ in PATH_MUTATIONS}
    used = {n for _ in range(400) for n in mutate_address(rng, "attacker@evil.example")[1]}
    assert used == {n for n, _ in ADDRESS_MUTATIONS}
