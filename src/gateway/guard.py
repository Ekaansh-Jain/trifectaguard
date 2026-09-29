"""
Library mode: guard the tools of any Python agent (LangChain/LangGraph, the
OpenAI Agents SDK, or your own loop) with the same flow engine the Claude Code
hooks and the MCP proxy use.

    from trifectaguard import Guard

    guard = Guard({"tools": {
        "read_inbox": {"reads": ["untrusted", "private"]},
        "send_email": {"writes": "external", "destination": ["to"]},
    }})
    guard.user_message(user_request)        # destinations the user typed are trusted

    @guard.tool
    def send_email(to: str, body: str) -> str: ...

Put framework decorators outside: `@tool` / `@function_tool` on top of
`@guard.tool` keep the original signature and docstring (functools.wraps), so
the framework builds the same schema.

A refused call does not run; by default the tool returns a short explanation
the model can relay (blocked="raise" raises Blocked instead). An "ask" goes to
`on_ask(request) -> bool`; the default denies, so nothing needing approval
runs unattended. `ask_in_terminal` is a ready-made prompt for CLI agents.

A Guard holds one session's state: create one per conversation.
"""
import asyncio
import functools
import inspect
import json
from dataclasses import dataclass
from pathlib import Path

from .engine import DEFAULT_FLOWS, FlowEngine, Verdict, plain_text
from .rules import ServerPolicy

DEFAULT_NS = "app"
_PLAIN = (str, int, float, bool, type(None), list, dict, tuple)


class Blocked(Exception):
    def __init__(self, verdict: Verdict, tool: str):
        super().__init__(f"{tool}: {verdict.reason} (rule: {verdict.rule})")
        self.verdict, self.tool = verdict, tool


@dataclass
class ApprovalRequest:
    tool: str
    args: dict
    rule: str
    reason: str


def ask_in_terminal(request: ApprovalRequest) -> bool:
    print(f"\n[trifectaguard] {request.reason}\n  call: {request.tool}({json.dumps(request.args, default=str)[:300]})")
    return input("  allow? [y/N] ").strip().lower() in ("y", "yes")


def _policy(spec) -> ServerPolicy:
    if isinstance(spec, ServerPolicy):
        return spec
    if isinstance(spec, dict):
        return ServerPolicy.from_dict(spec)
    return ServerPolicy.load(str(spec))  # preset name or path


def _text(result) -> str:
    try:
        return plain_text(result)
    except (TypeError, ValueError):
        return str(result)


class Guard:
    """One agent session's flow guard.

    policies: a single policy (preset name, path, or inline dict) for namespace
    "app", or {namespace: policy} when tools come from several sources.
    """

    def __init__(self, policies, *, on_ask=None, blocked: str = "return",
                 strict_destinations: bool = True, strict_links: bool = True, flows=None):
        if isinstance(policies, (str, Path, ServerPolicy)) or (
                isinstance(policies, dict) and "tools" in policies):
            policies = {DEFAULT_NS: policies}
        assert blocked in ("return", "raise")
        self.engine = FlowEngine({ns: _policy(p) for ns, p in policies.items()},
                                 flows=list(flows or DEFAULT_FLOWS),
                                 strict_destinations=strict_destinations, strict_links=strict_links)
        self.on_ask = on_ask
        self.blocked = blocked

    # ---- explicit API (for agent loops you control) -------------------------------
    def user_message(self, text: str):
        """Register what the user asked for: destinations they typed are trusted."""
        self.engine.trust(text)

    def before(self, tool: str, args: dict, namespace: str = DEFAULT_NS) -> Verdict:
        """Decide a call before running it; resolves "ask" through on_ask."""
        v = self.engine.check(namespace, tool, args)
        if v.action == "ask":
            ok = bool(self.on_ask and self.on_ask(ApprovalRequest(tool, args, v.rule, v.reason)))
            if ok:
                self.engine.approve(v, namespace, tool, args)
                return Verdict("allow", v.rule, "approved by the user")
            return Verdict("block", v.rule, v.reason + " (needs approval; not approved)")
        return v

    def after(self, tool: str, args: dict, result, namespace: str = DEFAULT_NS):
        """Record what a call returned (its labels, secrets, text for provenance)."""
        self.engine.observe(namespace, tool, args, _text(result))

    @property
    def labels(self) -> dict:
        return dict(self.engine.labels)

    # ---- decorator ----------------------------------------------------------------
    def tool(self, fn=None, *, name: str | None = None, namespace: str = DEFAULT_NS):
        """Wrap a tool function (sync or async). Usable as @guard.tool or
        @guard.tool(name="send_email", namespace="mail")."""
        if fn is None:
            return lambda f: self.tool(f, name=name, namespace=namespace)
        tool_name = name or fn.__name__
        sig = inspect.signature(fn)

        def call_args(a, kw) -> dict:
            bound = sig.bind_partial(*a, **kw)
            bound.apply_defaults()
            # drop framework context objects; policies reason about plain data
            return {k: v for k, v in bound.arguments.items() if isinstance(v, _PLAIN)}

        def refused(v: Verdict):
            if self.blocked == "raise":
                raise Blocked(v, tool_name)
            return (f"[trifectaguard blocked] {v.reason} (rule: {v.rule}). This call did not run. "
                    f"Do not retry it or send the data another way; tell the user what was blocked.")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*a, **kw):
                args = call_args(a, kw)
                v = await asyncio.to_thread(self.before, tool_name, args, namespace)
                if v.action != "allow":
                    return refused(v)
                result = await fn(*a, **kw)
                self.after(tool_name, args, result, namespace)
                return result
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*a, **kw):
            args = call_args(a, kw)
            v = self.before(tool_name, args, namespace)
            if v.action != "allow":
                return refused(v)
            result = fn(*a, **kw)
            self.after(tool_name, args, result, namespace)
            return result
        return wrapper
