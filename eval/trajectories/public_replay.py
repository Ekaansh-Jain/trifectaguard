"""
False alarms on other people's work: replay public coding-agent sessions
(OpenHands agents resolving real GitHub issues; nebius/SWE-rebench-openhands-
trajectories) through the Claude Code hooks and count what trifectaguard would
have asked or denied.

OpenHands tools map onto Claude Code's: execute_bash → Bash; the editor's
view → Read, create → Write, str_replace/insert → Edit; think/finish/
task_tracker are bookkeeping and skipped. Two readings of the GitHub issue that
starts every session:

  A  the user pasted the issue into their request (trusted)
  B  the agent fetched the issue (untrusted: anyone can open an issue), so every
     session starts with untrusted content in it: the stricter, realistic case

  python eval/trajectories/public_replay.py sessions.parquet [--limit N]
"""
import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from src.gateway.config import Config  # noqa: E402
from src.gateway.hook import handle  # noqa: E402
from src.gateway.replay import _brief  # noqa: E402

ISSUE = re.compile(r"<issue_description>(.*?)</issue_description>", re.S)


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
    return str(content or "")


def to_claude(name: str, args: dict):
    """OpenHands call → (Claude Code tool, input), or None to skip."""
    if name == "execute_bash":
        return "Bash", {"command": args.get("command", "")}
    if name == "str_replace_editor":
        cmd, path = args.get("command"), args.get("path", "")
        if cmd == "view":
            return "Read", {"file_path": path}
        if cmd == "create":
            return "Write", {"file_path": path, "content": args.get("file_text", "")}
        if cmd in ("str_replace", "insert", "undo_edit"):
            return "Edit", {"file_path": path, "old_string": args.get("old_str", ""),
                            "new_string": args.get("new_str", "")}
    return None  # think, finish, task_tracker


def events(session_id: str, repo: str, traj: list, variant: str):
    first_user = next((_text(m.get("content")) for m in traj if m.get("role") == "user"), "")
    m = ISSUE.search(first_user)
    issue = m.group(1) if m else first_user
    if variant == "A":
        yield {"hook_event_name": "UserPromptSubmit", "session_id": session_id, "prompt": first_user}
    else:
        yield {"hook_event_name": "UserPromptSubmit", "session_id": session_id,
               "prompt": first_user.replace(issue, "") if m else "Resolve the GitHub issue for this repository."}
        url = f"https://github.com/{repo}/issues"
        yield {"hook_event_name": "PostToolUse", "session_id": session_id, "tool_name": "WebFetch",
               "tool_input": {"url": url, "prompt": "read the issue"}, "tool_response": issue, "tool_use_id": "issue"}
    calls = {}
    for msg in traj:
        if msg.get("role") == "assistant":
            for c in msg.get("tool_calls") or []:
                try:
                    args = json.loads(c["function"].get("arguments") or "{}")
                except ValueError:
                    continue
                mapped = to_claude(c["function"]["name"], args)
                if mapped:
                    calls[c["id"]] = mapped
                    yield {"hook_event_name": "PreToolUse", "session_id": session_id, "tool_name": mapped[0],
                           "tool_input": mapped[1], "tool_use_id": c["id"]}
        elif msg.get("role") == "tool" and msg.get("tool_call_id") in calls:
            tool, inp = calls.pop(msg["tool_call_id"])
            yield {"hook_event_name": "PostToolUse", "session_id": session_id, "tool_name": tool, "tool_input": inp,
                   "tool_response": _text(msg.get("content")), "tool_use_id": msg["tool_call_id"]}


def run(rows, variant):
    stats = {"sessions": 0, "calls": 0, "asked": Counter(), "denied": Counter(),
             "sessions_asked": 0, "sessions_denied": 0, "examples": []}
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(servers={}, builtin={"policy": "claude-code"})
        cfg.state_dir = Path(tmp)
        for i, (repo, traj) in enumerate(rows):
            stats["sessions"] += 1
            any_ask = any_deny = False
            for ev in events(f"{variant}{i}", repo, traj, variant):
                out = handle(cfg, ev)
                if ev["hook_event_name"] != "PreToolUse":
                    continue
                stats["calls"] += 1
                if out:
                    d = out["hookSpecificOutput"]
                    rule = d["permissionDecisionReason"].rsplit("rule: ", 1)[-1].split(")")[0]
                    kind = "asked" if d["permissionDecision"] == "ask" else "denied"
                    stats[kind][(rule, ev["tool_name"])] += 1
                    any_ask |= kind == "asked"
                    any_deny |= kind == "denied"
                    if len(stats["examples"]) < 12:
                        stats["examples"].append((kind, rule, ev["tool_name"], _brief(ev["tool_input"])))
            stats["sessions_asked"] += any_ask
            stats["sessions_denied"] += any_deny
    return stats


def report(stats, title):
    n, s = max(stats["calls"], 1), max(stats["sessions"], 1)
    a, d = sum(stats["asked"].values()), sum(stats["denied"].values())
    lines = [f"== {title}: {stats['sessions']} sessions, {stats['calls']} tool calls",
             f"   calls asked  {a:6d} ({a / n:6.2%})   sessions with an ask  {stats['sessions_asked']:5d} "
             f"({stats['sessions_asked'] / s:6.1%})",
             f"   calls denied {d:6d} ({d / n:6.2%})   sessions with a deny  {stats['sessions_denied']:5d} "
             f"({stats['sessions_denied'] / s:6.1%})"]
    for (rule, tool), c in (stats["asked"] + stats["denied"]).most_common(8):
        lines.append(f"   {c:6d}  {rule:26s} {tool}")
    lines += [f"     e.g. {k:6s} {r:24s} {t:5s} {b}" for k, r, t, b in stats["examples"][:8]]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("parquet")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    import pyarrow.parquet as pq
    table = pq.read_table(args.parquet, columns=["repo", "trajectory"])
    rows = list(zip(table.column("repo").to_pylist(), table.column("trajectory").to_pylist()))
    if args.limit:
        rows = rows[:args.limit]
    results = {}
    for variant, title in (("A", "A: issue pasted by the user (trusted)"),
                           ("B", "B: issue fetched by the agent (untrusted)")):
        st = run(rows, variant)
        print(report(st, title), flush=True)
        results[variant] = {"sessions": st["sessions"], "calls": st["calls"],
                            "asked": sum(st["asked"].values()), "denied": sum(st["denied"].values()),
                            "sessions_asked": st["sessions_asked"], "sessions_denied": st["sessions_denied"],
                            "by_rule": {f"{r} | {t}": c for (r, t), c in (st["asked"] + st["denied"]).most_common()}}
    json.dump(results, open(os.path.join(ROOT, "results", "public_trajectories_replay.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
