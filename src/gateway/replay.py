"""
`trifectaguard replay`: run past Claude Code sessions through the hooks,
read-only, to see how often trifectaguard would have stepped in before you
install it.

Claude Code keeps each session as a JSONL transcript under
~/.claude/projects/<project>/. Replay feeds its events to the same code the
hooks run: your prompts → UserPromptSubmit, each tool call → PreToolUse
(decision recorded), its result → PostToolUse. Every call in a transcript did
run, so a call trifectaguard would have asked about counts as approved (which
is what remember_approvals then remembers).

Nothing leaves your machine; state goes to a temporary directory.
"""
import json
import tempfile
from collections import Counter
from pathlib import Path

from .config import Config
from .dlp import find_secrets
from .hook import handle

# long random-looking tokens (API keys pasted inline, often in quotes) that
# find_secrets' NAME=value / known-prefix rules don't catch
REDACT = __import__("re").compile(r"(?:sk|pk|rk|gsk|xai|nvapi|sk-or-v1|sk-ant|AIza|gh[pousr]|glpat)[-_A-Za-z0-9]{16,}")
SKIP_USER_TEXT = ("<system-reminder>", "<local-command", "<command-", "[SYSTEM NOTIFICATION", "<task-notification")


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return json.dumps(content, default=str)


def events(transcript: Path):
    """Yield hook events (dicts) in the order Claude Code would have fired them."""
    sid = transcript.stem
    for line in transcript.read_text(errors="replace").splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        msg, cwd = m.get("message") or {}, m.get("cwd", "")
        content = msg.get("content")
        if m.get("type") == "user":
            if isinstance(content, str):
                blocks = [{"type": "text", "text": content}]
            else:
                blocks = content or []
            for b in blocks:
                if b.get("type") == "tool_result":
                    yield {"hook_event_name": "PostToolUse", "session_id": sid, "cwd": cwd,
                           "tool_use_id": b.get("tool_use_id"), "tool_response": _text(b.get("content"))}
                elif b.get("type") == "text" and not b.get("text", "").lstrip().startswith(SKIP_USER_TEXT):
                    if not m.get("isMeta"):
                        yield {"hook_event_name": "UserPromptSubmit", "session_id": sid, "cwd": cwd,
                               "prompt": b["text"]}
        elif m.get("type") == "assistant" and isinstance(content, list):
            for b in content:
                if b.get("type") == "tool_use":
                    yield {"hook_event_name": "PreToolUse", "session_id": sid, "cwd": cwd,
                           "tool_name": b["name"], "tool_input": b.get("input") or {}, "tool_use_id": b["id"]}


def replay(transcripts: list[Path], cfg: Config) -> dict:
    stats = {"sessions": 0, "tool_calls": 0, "asked": Counter(), "denied": Counter(), "examples": []}
    calls = {}  # tool_use_id -> PreToolUse event, to pair results with their call
    with tempfile.TemporaryDirectory(prefix="trifectaguard-replay-") as tmp:
        cfg.state_dir, cfg.mode = Path(tmp), "enforce"
        for t in transcripts:
            stats["sessions"] += 1
            for ev in events(t):
                if ev["hook_event_name"] == "PreToolUse":
                    stats["tool_calls"] += 1
                    calls[ev["tool_use_id"]] = ev
                    out = handle(cfg, ev)
                    if out:
                        d = out["hookSpecificOutput"]
                        rule = d["permissionDecisionReason"].rsplit("rule: ", 1)[-1].rstrip(")").split(")")[0]
                        key = (rule, ev["tool_name"])
                        stats["asked" if d["permissionDecision"] == "ask" else "denied"][key] += 1
                        if len(stats["examples"]) < 40:
                            stats["examples"].append((d["permissionDecision"], rule, ev["tool_name"],
                                                      _brief(ev["tool_input"])))
                elif ev["hook_event_name"] == "PostToolUse":
                    call = calls.pop(ev["tool_use_id"], None)
                    if call:
                        handle(cfg, {**ev, "tool_name": call["tool_name"], "tool_input": call["tool_input"]})
                else:
                    handle(cfg, ev)
    return stats


def _redact(text: str) -> str:
    """Never echo credentials that a past session typed into a command."""
    for s in sorted(find_secrets(text), key=len, reverse=True):
        text = text.replace(s, s[:4] + "…[redacted]")
    return REDACT.sub(lambda m: m.group(0)[:4] + "…[redacted]", text)


def _brief(tool_input: dict) -> str:
    for k in ("command", "url", "file_path", "query", "pattern"):
        if k in tool_input:
            v = _redact(" ".join(str(tool_input[k]).split()))
            return v if len(v) <= 90 else v[:87] + "…"
    return _redact(json.dumps(tool_input, default=str))[:90]


def render(stats: dict, show_examples: bool = True) -> str:
    asked, denied = sum(stats["asked"].values()), sum(stats["denied"].values())
    n = max(stats["tool_calls"], 1)
    lines = [f"Replayed {stats['sessions']} session(s), {stats['tool_calls']} tool calls:",
             f"  would have asked:  {asked:4d}  ({asked / n:.1%} of calls)",
             f"  would have denied: {denied:4d}  ({denied / n:.1%})", ""]
    if asked or denied:
        lines.append("By rule and tool:")
        for (rule, tool), c in (stats["asked"] + stats["denied"]).most_common(12):
            lines.append(f"  {c:4d}  {rule:26s} {tool}")
    if show_examples and stats["examples"]:
        lines += ["", "Examples (decision, rule, tool, call):"]
        lines += [f"  {d:5s} {r:24s} {t:10s} {b}" for d, r, t, b in stats["examples"][:15]]
    return "\n".join(lines)


def default_transcripts(project_dir: Path) -> list[Path]:
    """Transcripts Claude Code stored for a project directory."""
    name = "-" + str(project_dir.resolve()).strip("/").replace("/", "-").replace(".", "-").replace("_", "-")
    folder = Path.home() / ".claude" / "projects" / name
    return sorted(folder.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
