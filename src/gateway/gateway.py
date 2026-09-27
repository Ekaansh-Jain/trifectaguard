"""
MCP flow-control gateway: ONE MCP server that fronts all of an agent's upstream
MCP servers and enforces information-flow rules across them.

    agent ──► gateway ──► github   (stdio)
                     ├──► filesystem
                     └──► fetch

Because every call goes through one process, the session's taint state spans
servers: an issue read via github, a file read via filesystem and a request made
via fetch are one flow. Per call:

  1. check()  — would this sink call move labelled data somewhere it shouldn't?
                allow → forward | ask → prompt the user (MCP elicitation) | block
  2. forward to the upstream server
  3. observe() — add the result's labels (untrusted, private, secret) to the session

Tool definitions are pinned on disk; a definition that changes between sessions
(a "rug pull") is quarantined until re-pinned. `mode: monitor` logs what would
have been blocked without blocking, for trying the gateway on real work first.
"""
import json
import os
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import anyio
import mcp.types as types
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from src.gateway.engine import DEFAULT_FLOWS, FlowEngine, Verdict
from src.gateway.pins import PinStore, fingerprint
from src.gateway.rules import ServerPolicy

ASK_CHOICES = ["allow once", "allow for this session", "block"]
CONNECT_TIMEOUT_S = 60


@dataclass
class Config:
    servers: dict  # name -> {command, args, env, cwd, policy, vars}
    state_dir: Path = Path("~/.mcp-gateway").expanduser()
    mode: str = "enforce"  # enforce | monitor
    ask_fallback: str = "block"  # when the client can't show approval prompts
    on_tool_change: str = "block"  # block | warn
    strict_links: bool = True  # with private data in session, opening attacker-supplied links asks
    flows: list = field(default_factory=lambda: list(DEFAULT_FLOWS))
    detector: dict | None = None
    base_dir: Path = Path(".")

    @classmethod
    def load(cls, path: str) -> "Config":
        path = Path(path).expanduser().resolve()
        doc = yaml.safe_load(path.read_text()) or {}
        if not doc.get("servers"):
            raise ValueError(f"{path}: no servers configured")
        cfg = cls(servers=doc["servers"], base_dir=path.parent)
        cfg.state_dir = Path(os.path.expandvars(doc.get("state_dir", str(cfg.state_dir)))).expanduser()
        for key in ("mode", "ask_fallback", "on_tool_change", "detector", "strict_links"):
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
        for f in self.flows:
            assert f.get("action") in ("ask", "block", "allow"), f"flow {f.get('name')}: bad action"

    def policies(self) -> dict:
        return {
            name: ServerPolicy.load(s["policy"], s.get("vars"))
            for name, s in self.servers.items() if s.get("policy")
        }


def _expand(value):
    if isinstance(value, str):
        return os.path.expandvars(os.path.expanduser(value))
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def result_text(result: types.CallToolResult) -> str:
    parts = []
    for c in result.content or []:
        if isinstance(c, types.TextContent):
            parts.append(c.text)
        elif isinstance(c, types.EmbeddedResource) and isinstance(c.resource, types.TextResourceContents):
            parts.append(c.resource.text)
    if result.structuredContent:
        parts.append(json.dumps(result.structuredContent, default=str))
    return "\n".join(parts)


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


class Gateway:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        detector = None
        if cfg.detector:
            from src.gateway.detector import make_detector
            detector = make_detector(cfg.detector.get("path", "detector-final"), chunked=True)
        self.engine = FlowEngine(cfg.policies(), cfg.flows, detector, strict_links=cfg.strict_links)
        self.pins = PinStore(cfg.state_dir / "pins.json")
        self.upstreams: dict[str, ClientSession] = {}
        self.routes: dict[str, tuple[str, str]] = {}
        self.quarantined: set[tuple[str, str]] = set()
        self.prefix = len(cfg.servers) > 1
        self.server = Server("mcp-flow-gateway")
        self.server.list_tools()(self.list_tools)
        self.server.call_tool(validate_input=False)(self.call_tool)

    # ---- audit ---------------------------------------------------------------
    def audit(self, event: str, **fields):
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        print(f"[gateway] {event}: {json.dumps(fields, default=str)}", file=sys.stderr, flush=True)
        try:
            self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cfg.state_dir / "audit.jsonl", "a") as f:
                f.write(json.dumps(rec, default=str) + "\n")
        except OSError:
            pass

    # ---- upstream connections ------------------------------------------------
    async def connect(self, stack: AsyncExitStack):
        for name, spec in self.cfg.servers.items():
            spec = _expand(spec)
            cwd = Path(spec.get("cwd", self.cfg.base_dir)).expanduser()
            if not cwd.is_absolute():
                cwd = self.cfg.base_dir / cwd
            params = StdioServerParameters(
                command=spec["command"], args=spec.get("args", []),
                env={**os.environ, **{k: str(v) for k, v in (spec.get("env") or {}).items()}},
                cwd=str(cwd),
            )
            try:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                with anyio.fail_after(CONNECT_TIMEOUT_S):
                    await session.initialize()
            except Exception as e:  # noqa: BLE001 — one bad server shouldn't take down the rest
                self.audit("upstream_failed", server=name, error=f"{type(e).__name__}: {e}"[:300])
                continue
            self.upstreams[name] = session
            self.audit("upstream_up", server=name, policy=spec.get("policy", "(none: all tools unclassified)"))

    async def upstream_tools(self, name: str) -> list[types.Tool]:
        tools, cursor = [], None
        while True:
            page = await self.upstreams[name].list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor = page.nextCursor
            if not cursor:
                return tools

    # ---- MCP handlers --------------------------------------------------------
    async def list_tools(self) -> list[types.Tool]:
        routes, exposed = {}, []
        for name in self.upstreams:
            tools = await self.upstream_tools(name)
            fps = {t.name: fingerprint(t.name, t.description, t.inputSchema) for t in tools}
            changed, new = self.pins.check(name, fps)
            if new:
                self.audit("tools_pinned", server=name, tools=new)
            if changed:
                self.audit("tool_definition_changed", server=name, tools=changed,
                           action=self.cfg.on_tool_change,
                           fix="review the change, then: python -m src.gateway repin -c <config> --server " + name)
                if self.cfg.on_tool_change == "block":
                    self.quarantined |= {(name, t) for t in changed}
            for t in tools:
                if (name, t.name) in self.quarantined:
                    continue
                public = f"{name}__{t.name}" if self.prefix else t.name
                routes[public] = (name, t.name)
                exposed.append(t.model_copy(update={"name": public}))
        self.routes = routes
        return exposed

    async def call_tool(self, name: str, arguments: dict):
        args = arguments or {}
        if name not in self.routes:
            await self.list_tools()
        if name not in self.routes:
            return _error(f"[gateway] unknown or quarantined tool: {name}")
        server, tool = self.routes[name]

        verdict = self.engine.check(server, tool, args)
        if verdict.action == "ask" and self.cfg.mode == "enforce":
            verdict = await self.ask(verdict, server, tool, args)
        if verdict.action != "allow":
            fields = dict(server=server, tool=tool, rule=verdict.rule, reason=verdict.reason)
            if self.cfg.mode == "monitor":
                self.audit(f"would_{verdict.action}", **fields)
            else:
                self.audit("blocked", **fields)
                return _error(
                    f"[gateway blocked] {verdict.reason}. This call was stopped by the "
                    f"MCP security gateway (rule: {verdict.rule}). Do not retry it or try "
                    f"another way to send this data; tell the user what was blocked and why."
                )
        elif verdict.rule:
            self.audit("approved", server=server, tool=tool, rule=verdict.rule)

        result = await self.upstreams[server].call_tool(tool, args)
        before = set(self.engine.labels)
        self.engine.observe(server, tool, args, result_text(result))
        added = sorted(set(self.engine.labels) - before)
        if added:
            self.audit("labels_added", server=server, tool=tool, labels=added,
                       session=sorted(self.engine.labels))
        return result

    async def ask(self, verdict: Verdict, server: str, tool: str, args: dict) -> Verdict:
        ctx = self.server.request_context
        caps = ctx.session.client_params.capabilities if ctx.session.client_params else None
        if not (caps and caps.elicitation):
            if self.cfg.ask_fallback == "allow":
                self.audit("ask_unsupported_allowed", server=server, tool=tool, rule=verdict.rule)
                return Verdict("allow", verdict.rule, "client cannot prompt; ask_fallback=allow")
            return Verdict("block", verdict.rule,
                           f"{verdict.reason} — this needs your approval, but the MCP client "
                           f"can't show approval prompts")
        preview = json.dumps(args, default=str)
        preview = preview if len(preview) <= 400 else preview[:400] + "…"
        try:
            res = await ctx.session.elicit(
                message=(f"Security gateway: {verdict.reason}.\n\n"
                         f"Call: {server}/{tool} {preview}\n\nAllow this call?"),
                requestedSchema={
                    "type": "object",
                    "properties": {"decision": {"type": "string", "title": "Decision",
                                                "enum": ASK_CHOICES}},
                    "required": ["decision"],
                },
                related_request_id=ctx.request_id,
            )
        except Exception as e:  # noqa: BLE001 — fail closed
            return Verdict("block", verdict.rule, f"{verdict.reason} — approval prompt failed ({type(e).__name__})")
        choice = (res.content or {}).get("decision") if res.action == "accept" else None
        if choice == "allow for this session":
            self.engine.approve(verdict, server, tool, args)
        if choice in ("allow once", "allow for this session"):
            return Verdict("allow", verdict.rule, f"user chose {choice!r}")
        return Verdict("block", verdict.rule, f"{verdict.reason} — declined by the user")

    # ---- run -----------------------------------------------------------------
    async def serve(self):
        async with AsyncExitStack() as stack:
            await self.connect(stack)
            if not self.upstreams:
                self.audit("no_upstreams", error="no upstream server started; exiting")
                return
            self.audit("gateway_up", servers=sorted(self.upstreams), mode=self.cfg.mode)
            async with stdio_server() as (read, write):
                await self.server.run(read, write, self.server.create_initialization_options())
