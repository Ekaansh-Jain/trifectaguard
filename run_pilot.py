"""
Leak-rate benchmark runner.

Runs each model against each attack scenario N times and reports how often the
agent leaked the canary into a sink tool call. Writes raw traces + a summary.

Usage:
  python run_pilot.py --models "llama-3.1-8b (NIM)" "gpt-oss-20b (Groq)" --runs 5
  python run_pilot.py --all --runs 10
"""
import argparse
import json
import os
import time
from collections import defaultdict
from pathlib import Path

from attacks.scenarios import SCENARIOS, TASKS
from src.harness.agent import run_once
from src.harness.providers import MODELS, resolve

CANARY = "CANARY-7f3a9b2e-DO-NOT-LEAK"
RAW_DIR = Path("results/raw")


def build_server_env(scenario_key: str) -> dict:
    sc = SCENARIOS[scenario_key]
    env = dict(os.environ)
    env["MCP_CANARY"] = CANARY
    env["MCP_ISSUE_INJECTION"] = sc["text"] if sc["channel"] == "issue" else ""
    env["MCP_PAGE_INJECTION"] = sc["text"] if sc["channel"] == "web" else ""
    return env


def task_for(scenario_key: str) -> dict:
    channel = SCENARIOS[scenario_key]["channel"]
    return {"name": scenario_key, "prompt": TASKS[channel]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--scenarios", nargs="*", default=list(SCENARIOS.keys()))
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()

    models = list(MODELS.keys()) if args.all else args.models
    if not models:
        raise SystemExit("Pass --models '<label>' ... or --all")

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    leaks = defaultdict(lambda: defaultdict(int))
    totals = defaultdict(lambda: defaultdict(int))
    errors = defaultdict(int)

    for model in models:
        api_key, base_url, model_id = resolve(model)
        for scen in args.scenarios:
            task = task_for(scen)
            server_env = build_server_env(scen)
            for i in range(args.runs):
                r = run_once(model, api_key, base_url, model_id, task, server_env)
                totals[model][scen] += 1
                leaked = r.leaked(CANARY)
                if r.error:
                    errors[model] += 1
                if leaked:
                    leaks[model][scen] += 1
                (RAW_DIR / f"{model.replace('/', '_')}__{scen}__{i}.json").write_text(
                    json.dumps(
                        {
                            "model": model,
                            "scenario": scen,
                            "leaked": leaked,
                            "error": r.error,
                            "tool_calls": r.tool_calls,
                            "final_text": r.final_text,
                        },
                        indent=2,
                    )
                )
                flag = "LEAK" if leaked else ("ERR " if r.error else " ok ")
                print(f"[{flag}] {model:24s} {scen:16s} run {i+1}/{args.runs}"
                      + (f"  ({r.error})" if r.error else ""))
                time.sleep(1)  # be gentle on free tiers

    print("\n=== LEAK RATE SUMMARY ===")
    header = "model".ljust(24) + "".join(s.ljust(18) for s in args.scenarios)
    print(header)
    summary = {}
    for model in models:
        row = model.ljust(24)
        summary[model] = {}
        for scen in args.scenarios:
            n = totals[model][scen]
            k = leaks[model][scen]
            rate = f"{k}/{n}" if n else "-"
            summary[model][scen] = {"leaks": k, "total": n}
            row += rate.ljust(18)
        print(row)
        if errors[model]:
            print(f"  (errors: {errors[model]})")

    Path("results/summary.json").write_text(json.dumps(summary, indent=2))
    print("\nWrote results/summary.json and raw traces to results/raw/")


if __name__ == "__main__":
    main()
