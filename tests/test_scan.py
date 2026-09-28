"""trifectaguard scan against fake home directories (read-only audit of AI app configs)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.gateway.scan import discover, main, render  # noqa: E402

TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
DESKTOP = "Library/Application Support/Claude/claude_desktop_config.json"


def home_with(tmp_path, desktop_servers=None, claude_settings=None, creds=("~/.aws/credentials",)):
    home = tmp_path / "home"
    home.mkdir()
    for c in creds:
        p = home / c[2:]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("[default]\naws_secret_access_key = not-read-by-the-scanner\n")
    if desktop_servers is not None:
        p = home / DESKTOP
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"mcpServers": desktop_servers}))
    if claude_settings is not None:
        (home / ".claude").mkdir()
        (home / ".claude" / "settings.json").write_text(json.dumps(claude_settings))
    cwd = tmp_path / "project"
    cwd.mkdir()
    return home, cwd


def servers(home):
    return {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github", "--token", TOKEN],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN}},
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(home)]},
        "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
    }


def app(apps, name):
    return next(a for a in apps if a.name == name)


def test_desktop_setup_with_github_files_and_fetch_is_flagged(tmp_path):
    home, cwd = home_with(tmp_path)
    (home / DESKTOP).parent.mkdir(parents=True, exist_ok=True)
    (home / DESKTOP).write_text(json.dumps({"mcpServers": servers(home)}))
    apps, creds = discover(home, cwd)
    d = app(apps, "Claude Desktop")
    assert [s.preset for s in d.sources] == ["github", "filesystem", "fetch"]
    titles = {f.title for f in d.findings if not f.mitigated}
    assert any("credentials" in t for t in titles) and any("private data" in t for t in titles)
    assert creds == ["~/.aws/credentials"]


def test_tokens_in_server_config_are_never_printed(tmp_path):
    home, cwd = home_with(tmp_path, desktop_servers={})
    (home / DESKTOP).write_text(json.dumps({"mcpServers": servers(home)}))
    apps, creds = discover(home, cwd)
    out = render(apps, creds, color=False)
    assert TOKEN not in out and "not-read-by-the-scanner" not in out
    assert "server-github" in out


def test_filesystem_root_that_holds_no_credentials_is_not_a_credential_path(tmp_path):
    home, cwd = home_with(tmp_path)
    (home / "projects").mkdir()
    (home / DESKTOP).parent.mkdir(parents=True, exist_ok=True)
    (home / DESKTOP).write_text(json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(home / "projects")]},
        "web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}))
    titles = [f.title for f in app(discover(home, cwd)[0], "Claude Desktop").findings]
    assert not any("credentials" in t for t in titles)
    assert any("private data" in t for t in titles)  # project files can still leak


def test_servers_behind_trifectaguard_count_as_protected(tmp_path):
    home, cwd = home_with(tmp_path, desktop_servers={})
    cfg = tmp_path / "gateway.yaml"
    import yaml
    cfg.write_text(yaml.safe_dump({"servers": servers(home)}))
    (home / DESKTOP).write_text(json.dumps({"mcpServers": {
        "guard": {"command": "python", "args": ["-m", "trifectaguard", "run", "-c", str(cfg)]}}}))
    d = app(discover(home, cwd)[0], "Claude Desktop")
    assert d.protected and all(s.protected for s in d.sources)
    assert d.findings and all(f.mitigated for f in d.findings)


def test_unknown_server_is_assumed_risky(tmp_path):
    home, cwd = home_with(tmp_path, desktop_servers={})
    (home / DESKTOP).write_text(json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(home)]},
        "mystery": {"command": "node", "args": ["/opt/some-mcp/index.js"]}}}))
    d = app(discover(home, cwd)[0], "Claude Desktop")
    assert d.sources[1].preset is None
    assert any(f.severity == "HIGH" and not f.mitigated for f in d.findings)


def test_claude_code_hooks_auto_approvals_and_modes(tmp_path):
    hooks = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command",
                                                      "command": "python -m trifectaguard hook -c x.yaml"}]}]}
    home, cwd = home_with(tmp_path, claude_settings={
        "hooks": hooks, "permissions": {"allow": ["Bash(curl *)", "Read", "WebFetch"],
                                        "defaultMode": "bypassPermissions"}})
    c = app(discover(home, cwd)[0], "Claude Code")
    assert c.protected and all(f.mitigated for f in c.findings)
    assert c.auto_approved == ["Bash(curl *)", "WebFetch"]
    assert any("bypassPermissions" in n for n in c.notes)


def test_nothing_configured_exits_zero(tmp_path, capsys):
    home, cwd = home_with(tmp_path, creds=())
    assert main(home=str(home), cwd=str(cwd)) == 0
    assert "No Claude Code" in capsys.readouterr().out


def test_unprotected_high_risk_exits_nonzero_for_ci(tmp_path, capsys):
    home, cwd = home_with(tmp_path, claude_settings={})
    assert main(as_json=True, home=str(home), cwd=str(cwd)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["apps"][0]["name"] == "Claude Code" and report["apps"][0]["findings"]
