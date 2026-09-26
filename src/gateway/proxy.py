"""
MCP security gateway — a transparent stdio proxy that sits between an agent and
an upstream MCP server and enforces the deterministic taint policy.

Wrap any server:
    python -m src.gateway.proxy -- python src/servers/github_mock.py
    python -m src.gateway.proxy -- npx -y @some/mcp-server

In an agent's MCP config, point the server command at this proxy and pass the
real server after `--`. The agent sees the same tools; the proxy inspects every
tool result, blocks exfiltration sinks, and detects tool-description rug pulls.

Audit events go to stderr (visible in the demo) and to GATEWAY_LOG (JSONL).
"""
import contextlib
import json
import os
import sys
from datetime import datetime, timezone

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from src.gateway.policy import build_engine, diff_pins, pin_descriptions
from src.gateway.adjudicator import decide

LOG_PATH = os.environ.get("GATEWAY_LOG", "results/gateway_audit.jsonl")
# LLM adjudication on the trifecta path (the risky ~1% of calls). Off by default
# so the gateway needs no API key unless you opt in.
ADJUDICATE = os.environ.get("GATEWAY_ADJUDICATE", "0") == "1"


def audit(event: str, **fields):
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    line = json.dumps(rec)
    print(f"[gateway] {event}: " + json.dumps(fields), file=sys.stderr, flush=True)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _text_of(result: types.CallToolResult) -> str:
    parts = []
    for c in result.content or []:
        if isinstance(c, types.TextContent):
            parts.append(c.text)
    return "\n".join(parts)


async def run(upstream_cmd: list[str]):
    engine = build_engine()
    pinned: dict = {}

    server = Server("mcp-security-gateway")
    params = StdioServerParameters(
        command=upstream_cmd[0], args=upstream_cmd[1:], env=dict(os.environ)
    )

    async with stdio_client(params) as (u_read, u_write):
        async with ClientSession(u_read, u_write) as upstream:
            await upstream.initialize()

            @server.list_tools()
            async def list_tools() -> list[types.Tool]:
                nonlocal pinned
                tools = (await upstream.list_tools()).tools
                as_dicts = [
                    {"name": t.name, "description": t.description or ""} for t in tools
                ]
                current = pin_descriptions(as_dicts)
                if not pinned:
                    pinned = current
                    audit("pinned_tools", count=len(current))
                else:
                    changed = diff_pins(pinned, current)
                    if changed:
                        audit("rug_pull_detected", tools=changed)
                # Drop upstream output schemas: as a content-forwarding proxy we
                # return unstructured content, so advertising a structured schema
                # would make the low-level server reject our passthrough.
                for t in tools:
                    t.outputSchema = None
                return tools

            @server.call_tool()
            async def call_tool(name: str, arguments: dict):
                decision = engine.check(name, arguments or {})
                if not decision.allow:
                    ctx = {"trace": engine.events[-6:], "sink_tool": name,
                           "sink_args": arguments or {}}
                    allow, reason = decide(decision, ctx, use_llm=ADJUDICATE)
                    if not allow:
                        audit("blocked", tool=name, reason=reason,
                              code=decision.code, trace=engine.events[-3:])
                        return [types.TextContent(
                            type="text",
                            text=f"[GATEWAY BLOCKED] {reason}. "
                                 f"This action was stopped by the security gateway.",
                        )]
                    audit("adjudicated_allow", tool=name, reason=reason)
                result = await upstream.call_tool(name, arguments or {})
                text = _text_of(result)
                engine.observe(name, arguments or {}, text)
                return list(result.content or [])

            audit("gateway_up", upstream=" ".join(upstream_cmd))
            opts = server.create_initialization_options()
            async with stdio_server() as (a_read, a_write):
                await server.run(a_read, a_write, opts)


def main():
    argv = sys.argv[1:]
    if "--" in argv:
        upstream_cmd = argv[argv.index("--") + 1:]
    else:
        upstream_cmd = argv
    if not upstream_cmd:
        print("usage: python -m src.gateway.proxy -- <server cmd...>", file=sys.stderr)
        sys.exit(2)
    with contextlib.suppress(KeyboardInterrupt):
        anyio.run(run, upstream_cmd)


if __name__ == "__main__":
    main()
