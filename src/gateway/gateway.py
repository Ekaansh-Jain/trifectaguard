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
import re
import sys
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path

import anyio
import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .config import Config  # noqa: F401 — re-exported for callers
from .engine import FlowEngine, Verdict
from .pins import PinStore, fingerprint

ASK_CHOICES = ["allow once", "allow for this session", "block"]
MCP_V2 = not hasattr(Server, "list_tools")  # the lowlevel Server API changed in mcp 2.0
CONNECT_TIMEOUT_S = 60


def _expand(value):
    if isinstance(value, str):
        return os.path.expandvars(os.path.expanduser(value))
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def field(obj, camel: str):
    """Read an MCP model field by its camelCase name: mcp 2.x renamed fields to
    snake_case (isError → is_error) but still accepts camelCase on construction."""
    snake = re.sub(r"(?<!^)([A-Z])", r"_\1", camel).lower()
    return getattr(obj, snake, None) if hasattr(obj, snake) else getattr(obj, camel, None)


def result_text(result: types.CallToolResult) -> str:
    parts = []
    for c in result.content or []:
        if isinstance(c, types.TextContent):
            parts.append(c.text)
        elif isinstance(c, types.EmbeddedResource) and isinstance(c.resource, types.TextResourceContents):
            parts.append(c.resource.text)
    if field(result, "structuredContent"):
        parts.append(json.dumps(field(result, "structuredContent"), default=str))
    return "\n".join(parts)


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


class Gateway:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        detector = None
        if cfg.detector:
            from .detector import make_detector
            detector = make_detector(cfg.detector.get("path", "detector-final"), chunked=True)
        self.engine = FlowEngine(cfg.policies(), cfg.flows, detector, strict_links=cfg.strict_links)
        self.pins = PinStore(cfg.state_dir / "pins.json")
        self.upstreams: dict[str, ClientSession] = {}
        self.routes: dict[str, tuple[str, str]] = {}
        self.quarantined: set[tuple[str, str]] = set()
        self.prefix = len(cfg.servers) > 1
        if hasattr(Server, "list_tools"):  # mcp 1.x: handlers registered with decorators
            self.server = Server("mcp-flow-gateway")
            self.server.list_tools()(self.list_tools)

            async def call_tool_v1(name: str, arguments: dict):
                return await self.call_tool(name, arguments, self.server.request_context)
            self.server.call_tool(validate_input=False)(call_tool_v1)
        else:  # mcp 2.x: handlers passed to the constructor, with a request context
            async def on_list_tools(ctx, params):
                return types.ListToolsResult(tools=await self.list_tools())

            async def on_call_tool(ctx, params):
                return await self.call_tool(params.name, params.arguments or {}, ctx)
            self.server = Server("mcp-flow-gateway", on_list_tools=on_list_tools, on_call_tool=on_call_tool)

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
    async def _open(self, stack: AsyncExitStack, spec: dict):
        """Transport for one upstream: a local command (stdio) or a remote URL
        (streamable HTTP by default, `transport: sse` for older servers)."""
        if "url" in spec:
            headers = {k: str(v) for k, v in (spec.get("headers") or {}).items()}
            if spec.get("transport", "http") == "sse":
                from mcp.client.sse import sse_client
                return await stack.enter_async_context(sse_client(spec["url"], headers=headers))
            import mcp.client.streamable_http as http
            if hasattr(http, "streamablehttp_client"):  # mcp 1.x
                streams = await stack.enter_async_context(http.streamablehttp_client(spec["url"], headers=headers))
            else:  # mcp 2.x: headers go on the HTTP client
                from mcp.shared._httpx_utils import create_mcp_http_client
                client = await stack.enter_async_context(create_mcp_http_client(headers=headers))
                streams = await stack.enter_async_context(http.streamable_http_client(spec["url"], http_client=client))
            return streams[0], streams[1]
        cwd = Path(spec.get("cwd", self.cfg.base_dir)).expanduser()
        if not cwd.is_absolute():
            cwd = self.cfg.base_dir / cwd
        params = StdioServerParameters(
            command=spec["command"], args=spec.get("args", []),
            # npx -y prints install messages on stdout, which is the MCP channel: keep npm quiet
            env={"npm_config_loglevel": "silent", "npm_config_update_notifier": "false",
                 **os.environ, **{k: str(v) for k, v in (spec.get("env") or {}).items()}},
            cwd=str(cwd),
        )
        return await stack.enter_async_context(stdio_client(params))

    async def connect(self, stack: AsyncExitStack):
        for name, spec in self.cfg.servers.items():
            spec = _expand(spec)
            try:
                read, write = await self._open(stack, spec)
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
            session = self.upstreams[name]
            if cursor is None:
                page = await session.list_tools()
            elif MCP_V2:
                page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor))
            else:
                page = await session.list_tools(cursor=cursor)
            tools.extend(page.tools)
            cursor = field(page, "nextCursor")
            if not cursor:
                return tools

    # ---- MCP handlers --------------------------------------------------------
    async def list_tools(self) -> list[types.Tool]:
        routes, exposed = {}, []
        for name in self.upstreams:
            tools = await self.upstream_tools(name)
            fps = {t.name: fingerprint(t.name, t.description, field(t, "inputSchema")) for t in tools}
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

    async def call_tool(self, name: str, arguments: dict, ctx=None):
        args = arguments or {}
        if name not in self.routes:
            await self.list_tools()
        if name not in self.routes:
            return _error(f"[gateway] unknown or quarantined tool: {name}")
        server, tool = self.routes[name]

        verdict = self.engine.check(server, tool, args)
        if verdict.action == "ask" and self.cfg.mode == "enforce":
            verdict = await self.ask(ctx, verdict, server, tool, args)
        if verdict.action != "allow":
            dests = self.engine._destinations(self.engine.role(server, tool, args), args)
            fields = dict(server=server, tool=tool, rule=verdict.rule, reason=verdict.reason, destinations=dests)
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

    async def ask(self, ctx, verdict: Verdict, server: str, tool: str, args: dict) -> Verdict:
        session = ctx.session if ctx is not None else None
        caps = None
        if session is not None:
            caps = getattr(session, "client_capabilities", None)  # mcp 2.x
            if caps is None and getattr(session, "client_params", None):  # mcp 1.x
                caps = session.client_params.capabilities
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
            # message and schema positionally: the schema keyword was renamed in mcp 2.x
            res = await session.elicit(
                f"Security gateway: {verdict.reason}.\n\nCall: {server}/{tool} {preview}\n\nAllow this call?",
                {"type": "object",
                 "properties": {"decision": {"type": "string", "title": "Decision", "enum": ASK_CHOICES}},
                 "required": ["decision"]},
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
