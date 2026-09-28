"""
Run every scenario in catalog.yaml through all three front ends and check each
step against its expectation:

  library  src/gateway/guard.py (Guard.before/after), as an agent framework uses it
  hooks    src/gateway/hook.py, fed the events Claude Code sends
  proxy    the real MCP proxy over stdio, in front of scripted stdio servers;
           an ask becomes a block (this client shows no prompts), and a stopped
           call must never reach its server

Claude Code built-in scenarios (Bash, Read, WebFetch, …) run in hooks mode only.

  python eval/scenarios/run.py            # all modes, writes SCENARIOS.md
  python eval/scenarios/run.py --no-proxy # library + hooks only (fast)
"""
import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from catalog import expectation, load_catalog, parse_call  # noqa: E402
from src.gateway.config import Config  # noqa: E402
from src.gateway.guard import Guard  # noqa: E402
from src.gateway.hook import handle  # noqa: E402

RULE = re.compile(r"rule: ([\w-]+)")


def _servers_used(sc):
    return sorted({parse_call(s)[0] for s in sc["steps"]} - {"claude-code"})


def run_library(sc, cat):
    used = _servers_used(sc)
    specs = {n: cat["servers"][n] for n in used}
    guard = Guard({n: s["policy"] if isinstance(s["policy"], dict) else s["policy"] for n, s in specs.items()})
    for n, s in specs.items():  # preset vars (public repos etc.)
        if s.get("vars"):
            from src.gateway.rules import ServerPolicy
            guard.engine.policies[n] = ServerPolicy.load(s["policy"], s["vars"])
    guard.user_message(sc["user"])
    out = []
    for step in sc["steps"]:
        server, tool, args = parse_call(step)
        v = guard.before(tool, args, namespace=server)
        out.append(("allow", None) if v.action == "allow" else ("stop", v.rule))
        if v.action == "allow":
            guard.after(tool, args, step.get("result", "ok"), namespace=server)
    return out


def run_hooks(sc, cat):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(servers={n: dict(cat["servers"][n]) for n in _servers_used(sc)},
                     builtin={"policy": "claude-code"}, state_dir=Path(tmp))
        sid = "s-" + sc["id"]
        handle(cfg, {"hook_event_name": "UserPromptSubmit", "session_id": sid, "prompt": sc["user"]})
        out = []
        for i, step in enumerate(sc["steps"]):
            server, tool, args = parse_call(step)
            name = tool if server == "claude-code" else f"mcp__{server}__{tool}"
            ev = {"session_id": sid, "tool_name": name, "tool_input": args, "tool_use_id": f"t{i}"}
            d = handle(cfg, {"hook_event_name": "PreToolUse", **ev})
            if d:
                reason = d["hookSpecificOutput"]["permissionDecisionReason"]
                out.append(("stop", (RULE.search(reason) or [None, None])[1]))
                continue
            out.append(("allow", None))
            handle(cfg, {"hook_event_name": "PostToolUse", **ev, "tool_response": step.get("result", "ok")})
        return out


def run_proxy(sc, cat):
    import anyio
    import yaml
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from src.gateway.gateway import field

    used = _servers_used(sc)
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "exec.jsonl")
        servers = {n: {**cat["servers"][n], "command": sys.executable,
                       "args": [os.path.join(HERE, "scripted_server.py")], "cwd": ROOT,
                       "env": {"SCENARIO": sc["id"], "SERVER": n, "EXEC_LOG": log}} for n in used}
        cfg = os.path.join(tmp, "gateway.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            yaml.safe_dump({"state_dir": os.path.join(tmp, "state"), "servers": servers}, f)
        prefix = len(used) > 1

        async def go():
            p = StdioServerParameters(command=sys.executable, args=["-m", "src.gateway", "run", "-c", cfg],
                                      cwd=ROOT, env=dict(os.environ))
            out = []
            async with stdio_client(p) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    for step in sc["steps"]:
                        server, tool, args = parse_call(step)
                        res = await s.call_tool(f"{server}__{tool}" if prefix else tool, args)
                        text = " ".join(getattr(c, "text", "") for c in res.content)
                        if field(res, "isError") and "gateway" in text:
                            out.append(("stop", (RULE.search(text) or [None, None])[1]))
                        else:
                            out.append(("allow", None))
            return out
        out = anyio.run(go)
        executed = [json.loads(line) for line in open(log, encoding="utf-8")] if os.path.exists(log) else []
        # every stopped call must be absent from what the servers actually ran
        for step, (outcome, _) in zip(sc["steps"], out):
            if outcome == "stop":
                server, tool, args = parse_call(step)
                assert not any(e["server"] == server and e["tool"] == tool and e["args"] == args
                               for e in executed), f"{sc['id']}: stopped call reached the server"
        return out


def check(sc, mode, outcomes):
    problems = []
    for i, (step, (got, rule)) in enumerate(zip(sc["steps"], outcomes)):
        want, want_rule = expectation(step, mode)
        if got != want or (want_rule and rule != want_rule):
            problems.append(f"step {i + 1} {step['call']}: expected {want}"
                            f"{' (' + want_rule + ')' if want_rule else ''}, got {got}{' (' + str(rule) + ')' if rule else ''}")
    return problems


def run_all(modes=("library", "hooks", "proxy")):
    cat = load_catalog()
    runners = {"library": run_library, "hooks": run_hooks, "proxy": run_proxy}
    results = []
    for sc in cat["scenarios"]:
        row = {"scenario": sc, "modes": {}}
        for mode in modes:
            if sc.get("builtin") and mode != "hooks":
                row["modes"][mode] = None  # Claude Code built-in tools: hooks only
                continue
            outcomes = runners[mode](sc, cat)
            row["modes"][mode] = (outcomes, check(sc, mode, outcomes))
        results.append(row)
    return results


def final_outcome(outcomes):
    stops = [r for o, r in outcomes if o == "stop"]
    return f"stopped ({stops[0]})" if stops else "allowed"


def write_markdown(results, path):
    lines = ["# Scenarios", "",
             "What trifectaguard stops, and the look-alike legitimate work it lets through. Each",
             "scenario runs through the Python library, the Claude Code hooks and the MCP proxy",
             "(real stdio servers; a stopped call never reaches them). Generated by",
             "`python eval/scenarios/run.py` from `eval/scenarios/catalog.yaml`; ✅ means the",
             "front end did exactly what the scenario expects at every step.", "",
             "| | Scenario | Result | Library | Claude Code hooks | MCP proxy |", "|---|---|---|---|---|---|"]
    for row in results:
        sc = row["scenario"]
        cells = []
        for mode in ("library", "hooks", "proxy"):
            m = row["modes"].get(mode)
            cells.append("–" if m is None else ("✅" if not m[1] else "❌"))
        outcome = final_outcome(row["modes"]["hooks"][0])
        kind = "🛑 attack" if sc["kind"] == "attack" else "✔️ legit"
        lines.append(f"| {kind} | {sc['title']} | {outcome} | " + " | ".join(cells) + " |")
    lines += ["", "Notes:", "",
              "- *Legit* scenarios must run with no prompt; *attacks* must be stopped at the attacker's step.",
              "- The MCP proxy can't see your request, so an address you typed looks unverified to it: where",
              "  that changes the outcome, the catalog says so (`proxy:`) and the table checks that behaviour.",
              "- Sources for attack structures are in the catalog."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-proxy", action="store_true")
    args = ap.parse_args()
    modes = ("library", "hooks") if args.no_proxy else ("library", "hooks", "proxy")
    results = run_all(modes)
    failed = 0
    for row in results:
        sc = row["scenario"]
        marks = []
        for mode in modes:
            m = row["modes"].get(mode)
            marks.append(f"{mode}:" + ("-" if m is None else ("ok" if not m[1] else "FAIL")))
            if m and m[1]:
                failed += 1
                for p in m[1]:
                    print(f"   {sc['id']} [{mode}] {p}")
        print(f"{'ATTACK' if sc['kind'] == 'attack' else 'legit ':6s} {sc['id']:38s} {' '.join(marks)}")
    if not args.no_proxy:
        write_markdown(results, os.path.join(ROOT, "SCENARIOS.md"))
    print(f"\n{len(results)} scenarios, {failed} front-end mismatches")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
