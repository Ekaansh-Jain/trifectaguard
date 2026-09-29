"""Information-flow control for AI agents.

Three ways to run the same engine:
  - library:      `from trifectaguard import Guard` (see guard.py)
  - Claude Code:  hooks (`trifectaguard hooks-snippet -c config.yaml --write`)
  - any MCP app:  a proxy in front of your MCP servers (`trifectaguard run -c config.yaml`)

(In this repo the package is importable as `src.gateway`; proxy.py and
policy.py are the original single-server research proxy used by the
benchmarks.)
"""
from .engine import FlowEngine, Verdict
from .guard import ApprovalRequest, Blocked, Guard, ask_in_terminal
from .rules import ServerPolicy

__all__ = ["Guard", "Blocked", "ApprovalRequest", "ask_in_terminal", "FlowEngine", "Verdict", "ServerPolicy"]
