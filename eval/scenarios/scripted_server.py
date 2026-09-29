"""
A real MCP server (stdio) that plays one server's part in one scenario of
catalog.yaml: it offers the tools the scenario calls on it, returns the
scripted results in order, and appends every call it actually executes to
EXEC_LOG, so a test can show that a stopped call never reached the server.

  SCENARIO=<id> SERVER=<name> EXEC_LOG=<file> python eval/scenarios/scripted_server.py
"""
import json
import os
import sys

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from catalog import load_catalog, parse_call  # noqa: E402


def main():
    scenario = next(s for s in load_catalog()["scenarios"] if s["id"] == os.environ["SCENARIO"])
    me, log = os.environ["SERVER"], os.environ["EXEC_LOG"]
    results = {}
    for step in scenario["steps"]:
        server, tool, _ = parse_call(step)
        if server == me:
            results.setdefault(tool, []).append(str(step.get("result", "ok")))
    tools = [types.Tool(name=t, description=f"scenario tool {t}",
                        inputSchema={"type": "object", "additionalProperties": True}) for t in results]

    async def list_tools():
        return tools

    async def call_tool(name, arguments):
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"server": me, "tool": name, "args": arguments or {}}) + "\n")
        queue = results.get(name) or ["ok"]
        text = queue.pop(0) if len(queue) > 1 else queue[0]
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=False)

    if hasattr(Server, "list_tools"):  # mcp 1.x
        server = Server(f"scripted-{me}")
        server.list_tools()(list_tools)
        server.call_tool(validate_input=False)(call_tool)
    else:  # mcp 2.x
        async def on_list(ctx, params):
            return types.ListToolsResult(tools=tools)

        async def on_call(ctx, params):
            return await call_tool(params.name, params.arguments)
        server = Server(f"scripted-{me}", on_list_tools=on_list, on_call_tool=on_call)

    async def serve():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    anyio.run(serve)


if __name__ == "__main__":
    main()
