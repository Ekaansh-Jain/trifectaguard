"""
End-to-end SYSTEM test: detector (Layer 1) + taint gate (Layer 2) + LLM
adjudicator, on the scaled attack+legit suite.

Compares three configurations so each layer's contribution is visible:
  1. gate only               (deterministic taint rules)
  2. gate + detector         (Layer 1 adds coverage for non-exfil attacks)
  3. gate + detector + LLM   (adjudicator rescues legit flows)

Reports catch rate (attacks blocked), false-block rate (legit blocked), and mean
per-decision latency for each. Replays scripted tool-call sequences through the
real engine + detector + adjudicator (no live agent needed → deterministic).

  python test_system.py           # all three configs
  python test_system.py --no-llm  # skip the adjudicator config (no API calls)
"""
import argparse
import time

from attacks.gateway_suite import ALL_SCALED
from src.gateway.policy import build_engine
from src.gateway.adjudicator import decide
from src.gateway.detector import make_detector


def context(case):
    trace = [f"read UNTRUSTED via {t}(): {str(r)[:120]}" for t, a, r in case["steps"]]
    trace += [f"read via {t}({a}): {str(r)[:120]}" for t, a, r in case["reads"]]
    return {"trace": trace, "sink_tool": case["sink"][0], "sink_args": case["sink"][1]}


def run_case(case, detector, use_llm):
    t0 = time.time()
    e = build_engine(detector=detector)
    for tool, args, result in case["steps"]:
        e.observe(tool, args, result)
    for tool, args, result in case["reads"]:
        e.observe(tool, args, result)
    det = e.check(*case["sink"])
    allow, reason = decide(det, context(case), use_llm=use_llm)
    return (not allow), (time.time() - t0) * 1000, det.code


def evaluate(detector, use_llm, label):
    rows = []
    for c in ALL_SCALED:
        blocked, ms, code = run_case(c, detector, use_llm)
        correct = (c["kind"] == "attack") == blocked
        rows.append({"name": c["name"], "kind": c["kind"], "blocked": blocked,
                     "correct": correct, "ms": ms, "code": code})
    A = [r for r in rows if r["kind"] == "attack"]
    L = [r for r in rows if r["kind"] == "legit"]
    catch = sum(r["blocked"] for r in A) / len(A)
    fblock = sum(r["blocked"] for r in L) / len(L)
    lat = sum(r["ms"] for r in rows) / len(rows)
    print(f"\n=== {label} ===")
    for r in rows:
        if not r["correct"]:
            tag = "MISSED ATTACK" if r["kind"] == "attack" else "FALSE BLOCK"
            print(f"  [{tag}] {r['name']}")
    print(f"catch={catch:.2f} ({sum(r['blocked'] for r in A)}/{len(A)})  "
          f"false_block={fblock:.2f} ({sum(r['blocked'] for r in L)}/{len(L)})  "
          f"mean_latency={lat:.0f}ms")
    return {"catch": catch, "false_block": fblock, "latency_ms": lat}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true")
    args = ap.parse_args()

    print(f"scaled suite: {len(ALL_SCALED)} cases "
          f"({sum(c['kind']=='attack' for c in ALL_SCALED)} attacks, "
          f"{sum(c['kind']=='legit' for c in ALL_SCALED)} legit)")
    print("loading detector...")
    detector = make_detector()

    evaluate(None, use_llm=False, label="1. GATE ONLY (deterministic)")
    evaluate(detector, use_llm=False, label="2. GATE + DETECTOR (Layer 1)")
    if not args.no_llm:
        evaluate(detector, use_llm=True, label="3. GATE + DETECTOR + LLM ADJUDICATOR")


if __name__ == "__main__":
    main()
