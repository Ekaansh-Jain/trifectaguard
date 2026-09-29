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


class ConfigError(Exception):
    """A config problem, explained in one line."""


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
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not doc.get("servers") and not doc.get("builtin"):
            raise ValueError("nothing to protect: add servers (MCP) or builtin: {policy: claude-code} (Claude Code)")
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

    @classmethod
    def load_checked(cls, path: str) -> "Config":
        """load(), with every policy loaded too and any problem reported as one
        ConfigError line: for commands, where a traceback helps nobody."""
        try:
            cfg = cls.load(path)
            cfg.policies()
            if cfg.builtin:
                cfg.builtin_policy()
            return cfg
        except FileNotFoundError as e:
            raise ConfigError(f"{e.filename or e}: file not found" if e.filename else str(e)) from None
        except yaml.YAMLError as e:
            raise ConfigError(f"{path}: not valid YAML ({str(e).splitlines()[0]})") from None
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise ConfigError(f"{path}: {e}") from None

    def validate(self):
        choices = {"mode": ("enforce", "monitor"), "ask_fallback": ("block", "allow"),
                   "on_tool_change": ("block", "warn"), "remember_approvals": ("session", "project")}
        for key, allowed in choices.items():
            if getattr(self, key) not in allowed:
                raise ValueError(f"{key} must be {' or '.join(allowed)}, not {getattr(self, key)!r}")
        if not isinstance(self.servers, dict):
            raise ValueError("servers must be a mapping of server name to settings")
        for name, spec in self.servers.items():
            if not isinstance(spec, dict):
                raise ValueError(f"server {name!r}: expected settings like {{policy: github}}, got {spec!r}")
        if self.builtin is not None and not isinstance(self.builtin, dict):
            raise ValueError("builtin must look like {policy: claude-code}")
        for f in self.flows:
            if not isinstance(f, dict) or f.get("action") not in ("ask", "block", "allow"):
                raise ValueError(f"flow {f.get('name') if isinstance(f, dict) else f!r}: action must be ask, block or allow")

    def policy_spec(self, spec: str) -> str:
        """A preset name as is; a policy file path relative to the config file's
        folder (apps start trifectaguard from their own working directory)."""
        s = str(spec)
        if not Path(s).suffix:
            return s
        path = Path(os.path.expandvars(s)).expanduser()
        return str(path if path.is_absolute() else self.base_dir / path)

    def builtin_policy(self) -> ServerPolicy:
        b = self.builtin or {}
        return ServerPolicy.load(self.policy_spec(b.get("policy", "claude-code")), b.get("vars"))

    def policies(self) -> dict:
        """policy: a preset name, a path, or an inline policy (a dict with tools)."""
        return {
            name: (ServerPolicy.from_dict(s["policy"], s.get("vars"), default_name=name)
                   if isinstance(s["policy"], dict) else ServerPolicy.load(self.policy_spec(s["policy"]), s.get("vars")))
            for name, s in self.servers.items() if s.get("policy")
        }
