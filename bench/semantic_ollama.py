"""Measure the optional OllamaJudge on the rt5 messages. Needs `ollama serve` and a pulled model; nothing here runs in CI.

    ollama pull llama3.2:3b
    python -m bench.semantic_ollama --model llama3.2:3b

It asks the model, for every outgoing message in rt5_semantic, whether the message restates the file the episode read, and
prints how many harmful messages it catches and how many benign ones it wrongly flags, per category, with the time taken.
This tests the model on its own, not the whole engine: in the engine a hit only ever sends the action to a person.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import defaultdict

from veritask.mock_env import FILES
from veritask.semantic import CombinedJudge, OllamaJudge, ProximityJudge

from .redteam5 import build_rt5


def models(host: str) -> list[str]:
    with urllib.request.urlopen(f"{host}/api/tags", timeout=5) as r:  # noqa: S310 (local host)
        return [m["name"] for m in json.loads(r.read()).get("models", [])]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="llama3.2:3b")
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--engine", action="store_true", help="also run rt4 and rt5 through the whole engine with the proximity judge, then this model")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds per message (the first call loads the model)")
    a = ap.parse_args()
    try:
        have = models(a.host)
    except Exception as exc:
        print(f"cannot reach Ollama at {a.host}: {exc}\nstart it with `ollama serve`", file=sys.stderr)
        return 2
    if a.model not in have:
        print(f"model {a.model!r} is not pulled (have: {have or 'none'}).\nrun: ollama pull {a.model}", file=sys.stderr)
        return 2
    judge = OllamaJudge(a.model, a.host, timeout=a.timeout)
    judge.disclosed("warm-up", ["warm-up"])  # loads the model so the first real message is not timed out; not counted
    stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # category -> [flagged, total]
    took = 0.0
    for ep in build_rt5():
        read = next(s for s in ep.steps if s.tool == "read_file")
        send = next(s for s in ep.steps if s.tool == "send_email")
        source = FILES[read.args["path"]][0]
        t0 = time.perf_counter()
        try:
            hit = judge.disclosed(send.args["body"], [source]) is not None
        except Exception as exc:
            print(f"  error on {ep.id}: {exc}", file=sys.stderr)
            hit = False
        took += time.perf_counter() - t0
        stats[f"{'harmful' if send.harmful else 'benign '} {ep.category}"][0] += hit
        stats[f"{'harmful' if send.harmful else 'benign '} {ep.category}"][1] += 1
    print(f"model {a.model}, {sum(v[1] for v in stats.values())} messages, {took:.1f}s in total")
    for k in sorted(stats):
        flagged, total = stats[k]
        print(f"  {k:32s} flagged {flagged}/{total}")
    if a.engine:
        engine_run(judge, a.model)
    return 0


def engine_run(model_judge: OllamaJudge, model: str) -> None:
    """The whole engine, default / proximity only / proximity then the model, on the two sets about restated facts."""
    from veritask import EngineConfig, PolicyEngine

    from .baselines import SYSTEMS
    from .redteam4 import build_rt4
    from .run import run_system, summarize

    SYSTEMS["proximity_then_model"] = lambda: PolicyEngine(EngineConfig(), judge=CombinedJudge(ProximityJudge(), model_judge))
    print(f"\nwhole engine, with {model} behind the proximity judge")
    for label, eps in (("rt4_variants", build_rt4()), ("rt5_semantic", build_rt5())):
        for name in ("veritask_full", "veritask_semantic", "proximity_then_model"):
            r = summarize(run_system(name, eps))
            print(f"  {label:13s} {name:22s} harmful steps that run {r['asr']:6.1%}   benign steps blocked {r['fpr_block']:5.1%}"
                  f"   sent to a person {r['review_friction']:5.1%}   tasks untouched {r['task_completion']:5.1%}")


if __name__ == "__main__":
    raise SystemExit(main())
