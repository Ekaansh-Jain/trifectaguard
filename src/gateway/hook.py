"""
Claude Code hook mode: the flow engine runs inside Claude Code's own hooks
instead of as an MCP proxy.

  UserPromptSubmit → the user's request is trusted text (destinations they typed)
  PreToolUse       → check(): stay silent, or answer "ask" / "deny" with a reason
  PostToolUse      → observe(): add the result's labels; if the call was one we
                     asked about and it ran, the user approved it, so remember
                     that approval for this destination for the session

Compared with the proxy this sees the user's request (strict destinations, the
"library mode" numbers), covers Claude Code's built-in tools (Read, WebFetch,
Bash, …) as well as every MCP server, and uses Claude Code's own approval
prompt. It never answers "allow": it can only add scrutiny on top of the
user's permission settings, never remove it.

Each hook call is a fresh process, so session state lives in
<state_dir>/sessions/<session_id>.json behind a file lock (parallel tool calls
run their hooks concurrently).

  settings: python -m src.gateway hooks-snippet -c gateway.yaml
"""
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .engine import FlowEngine
from .rules import ServerPolicy

BUILTIN = "claude-code"  # server name used for Claude Code's own tools

try:  # an exclusive lock per session file: fcntl on macOS/Linux, msvcrt on Windows
    import fcntl

    def _lock(f):
        fcntl.flock(f, fcntl.LOCK_EX)

    def _unlock(f):
        fcntl.flock(f, fcntl.LOCK_UN)
except ImportError:
    import msvcrt

    def _lock(f):
        f.seek(0)
        while True:
            try:
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # retries for ~10 s, then raises
                return
            except OSError:
                continue

    def _unlock(f):
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
SESSION_TTL_S = 7 * 24 * 3600
_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")


def split_tool(tool_name: str) -> tuple[str, str]:
    """'mcp__github__get_issue' → ('github', 'get_issue'); 'Bash' → ('claude-code', 'Bash')."""
    if tool_name.startswith("mcp__"):
        server, _, tool = tool_name[len("mcp__"):].partition("__")
        return server, tool
    return BUILTIN, tool_name


def response_text(resp) -> str:
    if isinstance(resp, str):
        return resp
    return json.dumps(resp, default=str)


class ProjectApprovals:
    """Destinations the user approved in a project, kept across sessions when
    remember_approvals: project. Only destination-scoped approvals are stored
    (an email address, a URL, an account), never "allow this tool"."""

    def __init__(self, cfg: Config):
        self.path = cfg.state_dir / "project_approvals.json"

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def for_project(self, project: str) -> set:
        return {(s, t, tuple(d)) for s, t, d in self.load().get(project, [])}

    def add(self, project: str, entry: tuple):
        data = self.load()
        items = {tuple(map(lambda x: tuple(x) if isinstance(x, list) else x, e)) for e in data.get(project, [])}
        items.add(entry)
        data[project] = sorted([s, t, list(d)] for s, t, d in items)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def clear(self, project: str | None = None):
        data = {} if project is None else {k: v for k, v in self.load().items() if k != project}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))


class Session:
    """Load → mutate → save one session's engine under an exclusive lock."""

    def __init__(self, cfg: Config, session_id: str, project: str = ""):
        self.cfg = cfg
        self.project = project
        sid = _SAFE_ID.sub("_", session_id or "default")
        self.dir = cfg.state_dir / "sessions"
        self.path = self.dir / f"{sid}.json"
        self.lock_path = self.dir / f"{sid}.lock"

    def __enter__(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = open(self.lock_path, "a+")
        _lock(self.lock)
        policies = self.cfg.policies()
        builtin = self.cfg.builtin or {"policy": BUILTIN}
        policies[BUILTIN] = ServerPolicy.load(builtin.get("policy", BUILTIN), builtin.get("vars"))
        self.engine = FlowEngine(policies, self.cfg.flows, strict_destinations=True,
                                 strict_links=self.cfg.strict_links)
        self.pending = {}
        if self.path.exists():
            try:
                state = json.loads(self.path.read_text())
                self.engine.load_state(state.get("engine", {}))
                self.pending = state.get("pending", {})
            except (ValueError, TypeError, AttributeError) as e:
                # Lost state must not become a clean slate: set it aside and
                # assume the session has seen everything, so flows stay guarded.
                self.path.replace(self.path.with_suffix(f".corrupt-{int(time.time())}"))
                for label in ("untrusted", "private", "secret"):
                    self.engine.labels[label] = "unknown (session state was lost)"
                audit(self.cfg, "state_reset", session=self.path.stem, error=f"{type(e).__name__}: {e}")
        if self.cfg.remember_approvals == "project" and self.project:
            self.engine.approvals |= ProjectApprovals(self.cfg).for_project(self.project)
        return self

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"engine": self.engine.to_state(), "pending": self.pending}))
            os.chmod(tmp, 0o600)
            tmp.replace(self.path)
        _unlock(self.lock)
        self.lock.close()


def audit(cfg: Config, event: str, **fields):
    try:
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        with open(cfg.state_dir / "audit.jsonl", "a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event": event,
                                "source": "claude-code-hook", **fields}, default=str) + "\n")
    except OSError:
        pass


def prune(cfg: Config):
    """Drop session files nobody has touched for a week."""
    d = cfg.state_dir / "sessions"
    cutoff = time.time() - SESSION_TTL_S
    for p in d.glob("*.json") if d.exists() else []:
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                p.with_suffix(".lock").unlink(missing_ok=True)
        except OSError:
            pass


def decision(action: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": action,
                                   "permissionDecisionReason": reason}}


def handle(cfg: Config, data: dict) -> dict | None:
    """Process one hook event; returns the JSON to print, or None for no opinion."""
    event = data.get("hook_event_name")
    with Session(cfg, data.get("session_id"), data.get("cwd") or "") as s:
        if event == "UserPromptSubmit":
            s.engine.trust(data.get("prompt") or "")
            return None

        server, tool = split_tool(data.get("tool_name", ""))
        args = data.get("tool_input") or {}
        call_id = data.get("tool_use_id") or ""

        if event == "PreToolUse":
            v = s.engine.check(server, tool, args)
            if v.action == "allow":
                return None
            dests = s.engine._destinations(s.engine.role(server, tool, args), args)
            fields = dict(server=server, tool=tool, rule=v.rule, reason=v.reason, destinations=dests,
                          session=data.get("session_id"))
            if cfg.mode == "monitor":
                audit(cfg, f"would_{v.action}", **fields)
                return None
            audit(cfg, "asked" if v.action == "ask" else "denied", **fields)
            if v.action == "ask":
                s.pending[call_id] = [server, tool, args]
                return decision("ask", f"[flow gateway] {v.reason}. Allow this call? (rule: {v.rule})")
            return decision("deny", f"[flow gateway blocked] {v.reason} (rule: {v.rule}). Do not retry "
                                    f"this or send the data another way; tell the user what was blocked.")

        if event == "PostToolUse":
            asked = s.pending.pop(call_id, None)
            if asked:
                # it ran, so the user said yes: don't ask again for this destination
                # (sinks without a destination are approved one call at a time)
                a_server, a_tool, a_args = asked
                dests = s.engine._destinations(s.engine.role(a_server, a_tool, a_args), a_args)
                if dests:
                    s.engine.approve(None, a_server, a_tool, a_args)
                    if cfg.remember_approvals == "project" and data.get("cwd"):
                        ProjectApprovals(cfg).add(data["cwd"], (a_server, a_tool, s.engine._dest_key(dests)))
                audit(cfg, "approved", server=a_server, tool=a_tool, session=data.get("session_id"))
            s.engine.observe(server, tool, args, response_text(data.get("tool_response")))
            return None
    return None


def main(config_path: str):
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("hook input is not a JSON object")
    except ValueError as e:
        # We can't tell which event or call this is, so fail closed: exit 2 makes
        # Claude Code block the call (exit 1 would let it proceed).
        print(f"[trifectaguard] unreadable hook input ({e}); blocking to be safe", file=sys.stderr)
        sys.exit(2)
    try:
        cfg = Config.load(config_path)
    except Exception as e:  # noqa: BLE001
        cfg, err = None, f"{type(e).__name__}: {e}"
    else:
        err = None
    try:
        if cfg is None:
            raise RuntimeError(f"bad config: {err}")
        out = handle(cfg, data)
        if data.get("hook_event_name") == "UserPromptSubmit":
            prune(cfg)
    except Exception as e:  # noqa: BLE001
        # Fail safe but usable: an internal error before a tool call asks the
        # user rather than silently allowing it or bricking the session.
        print(f"[flow gateway] {type(e).__name__}: {e}", file=sys.stderr)
        if data.get("hook_event_name") == "PreToolUse":
            out = decision("ask", f"[flow gateway] internal error ({type(e).__name__}); "
                                  f"approve only if you expected this call")
        else:
            sys.exit(1)  # non-blocking: Claude Code shows a hook error notice
    if out is not None:
        print(json.dumps(out))
