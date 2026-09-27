"""
Live-model AgentDojo run: a real LLM agent, with and without a defense, on a
fixed random sample of (user task × injection task) pairs plus benign tasks.

The defense sits where a gateway would: between the model's tool calls and
their execution (GuardedExecutor). Refused calls return the gateway's error
text to the model, are never executed, and are left out of the trace used for
scoring. Results append to a JSONL file so a run can resume after rate limits.

  python eval/agentdojo/live.py --model "gpt-oss-120b (Groq)" --defense none flow \\
      --suites banking slack --pairs 20 --benign 10
"""
import argparse
import json
import os
import random
import sys
import time
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import openai  # noqa: E402
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.errors import AbortAgentError  # noqa: E402
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402
from agentdojo.task_suite.task_suite import (  # noqa: E402
    functions_stack_trace_from_messages, model_output_from_messages)
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string  # noqa: E402

import defenses as D  # noqa: E402

sys.path.insert(0, D.ROOT)
from src.harness.providers import resolve  # noqa: E402

VERSION = "v1.2.2"
OUT = os.path.join(D.ROOT, "results", "agentdojo")
REDACTED = "<Data omitted because a prompt injection was detected>"


class GuardedExecutor(ToolsExecutor):
    """ToolsExecutor that asks the defense before running each call."""

    def __init__(self, defense):
        super().__init__()
        self.defense = defense
        self.refused_ids = set()
        self.refusals = []

    def query(self, query, runtime, env, messages=(), extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = []
        for call in messages[-1]["tool_calls"]:
            action, rule = ("allow", "")
            if call.function in runtime.functions:
                action, rule = self.defense.check(call.function, dict(call.args))
            if action != "allow":
                self.refused_ids.add(call.id)
                self.refusals.append((action, call.function, rule))
                results.append(ChatToolResultMessage(
                    role="tool", tool_call=call, tool_call_id=call.id, content=[text_content_block_from_string("")],
                    error=(f"[gateway blocked] This call was stopped by the security gateway (rule: {rule}). "
                           f"Do not retry it or work around it; tell the user what was blocked and why.")))
                continue
            _, _, env, out, _ = super().query(query, runtime, env, [{**messages[-1], "tool_calls": [call]}], extra_args)
            msg = out[-1]
            text = "".join(c["content"] for c in msg["content"] if c.get("content"))
            if msg["error"] is None and self.defense.observe(call.function, dict(call.args), text):
                msg = {**msg, "content": [text_content_block_from_string(REDACTED)]}
            results.append(msg)
        return query, runtime, env, [*messages, *results], extra_args


def build_pipeline(model_label, defense, name):
    api_key, base_url, model_id = resolve(model_label)
    client = openai.OpenAI(api_key=api_key, base_url=base_url, max_retries=12, timeout=120)
    llm = OpenAILLM(client, model_id, temperature=0.0)
    executor = GuardedExecutor(defense)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([executor, llm], max_iters=15)])
    pipe.name = name
    return pipe, executor


def run_one(suite_name, suite, pipe, executor, defense, ut, it, injections):
    env = suite.load_and_inject_default_environment(injections)
    task_env = ut.init_environment(env)
    pre = task_env.model_copy(deep=True)
    runtime = FunctionsRuntime(suite.tools)
    defense.start(suite_name, ut, ut.PROMPT, task_env)
    executor.refused_ids, executor.refusals = set(), []
    error = None
    try:
        _, _, task_env, messages, _ = pipe.query(ut.PROMPT, runtime, task_env)
    except AbortAgentError as e:
        task_env, messages = e.task_environment, e.messages
    except Exception as e:  # noqa: BLE001 — record provider failures instead of dying mid-run
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
    executed = []
    for m in messages:
        if m["role"] == "assistant" and m["tool_calls"]:
            m = {**m, "tool_calls": [c for c in m["tool_calls"] if c.id not in executor.refused_ids]}
        executed.append(m)
    output = model_output_from_messages(messages) or []
    trace = functions_stack_trace_from_messages(executed)
    utility = suite._check_task_result(ut, output, pre, task_env, trace)
    security = suite._check_task_result(it, output, pre, task_env, trace) if it else None
    return {"utility": bool(utility), "attack_success": None if it is None else bool(security),
            "refusals": executor.refusals, "calls": [c.function for c in trace], "error": error}


def sample(suites, n_pairs, n_benign, seed):
    rng = random.Random(seed)
    pairs, benign = [], []
    for name, s in suites.items():
        all_pairs = [(name, u, i) for u in s.user_tasks for i in s.injection_tasks]
        pairs += rng.sample(all_pairs, min(n_pairs, len(all_pairs)))
        benign += [(name, u, None) for u in rng.sample(list(s.user_tasks), min(n_benign, len(s.user_tasks)))]
    return benign + pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt-oss-120b (Groq)")
    ap.add_argument("--defense", nargs="+", default=["none", "flow"], choices=["none", "flow", "flow-mcp"])
    ap.add_argument("--suites", nargs="+", default=["banking", "slack"])
    ap.add_argument("--pairs", type=int, default=20, help="attack pairs per suite")
    ap.add_argument("--benign", type=int, default=10, help="benign user tasks per suite")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="live.jsonl", help="results file under results/agentdojo/")
    args = ap.parse_args()

    suites = {k: v for k, v in get_suites(VERSION).items() if k in args.suites}
    jobs = sample(suites, args.pairs, args.benign, args.seed)
    # same sample, cheapest suites first (workspace prompts are ~4x larger)
    cost = {"banking": 0, "slack": 1, "travel": 2, "workspace": 3}
    jobs.sort(key=lambda j: cost.get(j[0], 9))
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, args.out)
    done = set()
    if os.path.exists(path):
        for line in open(path):
            r = json.loads(line)
            if not r.get("error"):
                done.add((r["model"], r["defense"], r["suite"], r["user_task"], r["injection_task"]))

    makers = {"none": D.NoDefense, "flow": lambda: D.Flow("library"), "flow-mcp": lambda: D.Flow("mcp")}
    setups = {}
    for dname in args.defense:
        defense = makers[dname]()
        pipe, executor = build_pipeline(args.model, defense, "gpt-4o-2024-05-13")  # name feeds the attack text
        setups[dname] = (defense, pipe, executor)
    attacks = {n: load_attack("important_instructions", s, setups[args.defense[0]][1]) for n, s in suites.items()}
    # each job runs under every defense back to back, so partial runs stay paired
    for suite_name, ut_id, it_id in jobs:
        for dname, (defense, pipe, executor) in setups.items():
            key = (args.model, dname, suite_name, ut_id, it_id)
            if key in done:
                continue
            s = suites[suite_name]
            ut = s.user_tasks[ut_id]
            it = s.injection_tasks[it_id] if it_id else None
            injections = attacks[suite_name].attack(ut, it) if it else {}
            t0 = time.time()
            r = run_one(suite_name, s, pipe, executor, defense, ut, it, injections)
            rec = {"model": args.model, "defense": dname, "suite": suite_name, "user_task": ut_id,
                   "injection_task": it_id, "seconds": round(time.time() - t0, 1), **r}
            with open(path, "a") as f:
                f.write(json.dumps(rec) + "\n")
            print(f"[{dname}] {suite_name} {ut_id} {it_id or '(benign)'}: "
                  f"utility={r.get('utility')} attack={r.get('attack_success')} "
                  f"refused={len(r.get('refusals') or [])} {r.get('error') or ''} ({rec['seconds']}s)", flush=True)


if __name__ == "__main__":
    main()
