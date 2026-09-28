"""
Gateway configuration, shared by the MCP proxy (gateway.py) and the Claude Code
hooks (hook.py). Kept free of MCP imports so a hook, which is a fresh process
per tool call, starts fast.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .engine import DEFAULT_FLOWS
from .rules import ServerPolicy


@dataclass
class Config:
    servers: dict  # name -> {command, args, env, cwd, policy, vars}; hooks only need policy/vars
    state_dir: Path = Path("~/.mcp-gateway").expanduser()
    mode: str = "enforce"  # enforce | monitor
    ask_fallback: str = "block"  # proxy only: when the client can't show approval prompts
    on_tool_change: str = "block"  # proxy only: block | warn
    strict_links: bool = True  # with private data in session, opening attacker-supplied links asks
    remember_approvals: str = "session"  # hooks: "project" keeps approved destinations across sessions
    flows: list = field(default_factory=lambda: list(DEFAULT_FLOWS))
    detector: dict | None = None
    builtin: dict | None = None  # hooks only: policy for Claude Code's own tools (Read, Bash, …)
    base_dir: Path = Path(".")

    @classmethod
    def load(cls, path: str) -> "Config":
        path = Path(path).expanduser().resolve()
        doc = yaml.safe_load(path.read_text()) or {}
        if not doc.get("servers") and not doc.get("builtin"):
            raise ValueError(f"{path}: no servers configured")
        cfg = cls(servers=doc.get("servers") or {}, base_dir=path.parent)
        cfg.state_dir = Path(os.path.expandvars(doc.get("state_dir", str(cfg.state_dir)))).expanduser()
        for key in ("mode", "ask_fallback", "on_tool_change", "detector", "strict_links", "builtin",
                    "remember_approvals"):
            if key in doc:
                setattr(cfg, key, doc[key])
        if "flows" in doc:
            cfg.flows = doc["flows"]
        cfg.validate()
        return cfg

    def validate(self):
        assert self.mode in ("enforce", "monitor"), f"mode must be enforce|monitor, not {self.mode!r}"
        assert self.ask_fallback in ("block", "allow"), "ask_fallback must be block|allow"
        assert self.on_tool_change in ("block", "warn"), "on_tool_change must be block|warn"
        assert self.remember_approvals in ("session", "project"), "remember_approvals must be session|project"
        for f in self.flows:
            assert f.get("action") in ("ask", "block", "allow"), f"flow {f.get('name')}: bad action"

    def policies(self) -> dict:
        return {
            name: ServerPolicy.load(s["policy"], s.get("vars"))
            for name, s in self.servers.items() if s.get("policy")
        }
