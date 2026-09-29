"""
`trifectaguard scan`: a read-only audit of the AI apps on this machine.

For each app (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code) it finds
the configured MCP servers, recognises the ones we have policies for, and
reports every combination that lets an injection move data or actions
somewhere they shouldn't go: the same rules the engine enforces, applied to
what the app *could* do rather than what it did.

It never changes a file, never starts a server, and never opens a credential
file (it only checks that common ones exist). Server commands are shown by
package name only, so tokens passed as arguments aren't printed.
"""
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .rules import ServerPolicy

# How to recognise a configured server as one we have a policy for.
KNOWN = [
    ("github", re.compile(r"server-github|github-mcp-server|api\.githubcopilot\.com", re.I)),
    ("filesystem", re.compile(r"server-filesystem", re.I)),
    ("fetch", re.compile(r"mcp-server-fetch|server-fetch", re.I)),
    ("slack", re.compile(r"server-slack", re.I)),
]
GATEWAY = re.compile(r"(trifectaguard|src\.gateway)\b.*\brun\b", re.I)
CREDENTIAL_FILES = ["~/.aws/credentials", "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.netrc", "~/.npmrc",
                    "~/.pypirc", "~/.docker/config.json", "~/.kube/config", "~/.config/gcloud/credentials.db"]
RISKY_AUTO_APPROVALS = re.compile(r"^(Bash|Bash\((\*|curl|wget|ssh|scp|nc|python|node|npx|gh).*\)|WebFetch.*|mcp__.*)$")


@dataclass
class Source:
    """One provider of tools inside an app: a server, or the app's built-ins."""
    name: str
    preset: str | None  # policy name, or None if we don't know this server
    detail: str = ""
    protected: bool = False
    untrusted: list = field(default_factory=list)
    private: list = field(default_factory=list)
    secret: list = field(default_factory=list)
    sinks: dict = field(default_factory=dict)  # write class -> [tool]


@dataclass
class App:
    name: str
    config_paths: list
    sources: list = field(default_factory=list)
    protected: bool = False  # trifectaguard hooks installed (Claude Code)
    auto_approved: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    findings: list = field(default_factory=list)


@dataclass
class Finding:
    severity: str  # HIGH | MEDIUM
    title: str
    how: str
    mitigated: bool


def _strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas (VS Code's and Cursor's config
    format) → plain JSON. Comment markers inside strings are left alone."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _read_config(path: Path) -> tuple[dict | None, str | None]:
    """(document, problem). A missing file is (None, None): the app isn't set up."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, f"can't read it ({e.strerror or e})"
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = json.loads(_strip_jsonc(text))
        except ValueError as e:
            return None, f"not valid JSON ({e})"
    if not isinstance(doc, dict):
        return None, f"expected a JSON object, found {type(doc).__name__}"
    return doc, None


def _load_json(path: Path):
    return _read_config(path)[0]


def _unreadable(path: Path, problem: str) -> str:
    return f"couldn't read {path}: {problem}. Servers configured there were NOT checked"


def _args(spec: dict) -> list:
    """A server's args as a list, however the config wrote them (missing, null, one string)."""
    a = spec.get("args")
    return [a] if isinstance(a, str) else list(a) if isinstance(a, (list, tuple)) else []


def _describe(spec: dict) -> str:
    """Package/URL only: never the full argument list (it may hold tokens)."""
    if spec.get("url"):
        return re.sub(r"\?.*$", "", str(spec["url"]))
    cmd = [str(spec.get("command", ""))] + [str(a) for a in _args(spec)]
    pkg = next((a for a in cmd[1:] if not a.startswith("-") and ("/" in a or "mcp" in a.lower())), "")
    return f"{Path(cmd[0]).name} {pkg}".strip()


def _identify(spec: dict) -> str | None:
    blob = " ".join([str(spec.get("command", "")), *map(str, _args(spec)), str(spec.get("url", ""))])
    return next((name for name, rx in KNOWN if rx.search(blob)), None)


def _gateway_upstreams(spec: dict) -> dict | None:
    """If this server is trifectaguard's own proxy, the servers it protects."""
    args = [str(a) for a in _args(spec)]
    if not GATEWAY.search(" ".join([str(spec.get("command", "")), *args])):
        return None
    cfg = args[args.index("-c") + 1] if "-c" in args[:-1] else None
    try:
        return (yaml.safe_load(Path(cfg).expanduser().read_text(encoding="utf-8")) or {}).get("servers") or {} if cfg else {}
    except OSError:
        return {}


def _fill(src: Source, policy: ServerPolicy, tools: list[str], secrets_reachable: bool):
    """Worst case over each tool's variants: what could this tool do?"""
    always_untrusted = []
    for tool in tools:
        variants = policy._exact.get(tool) or next((v for p, v in policy._globs if p == tool), [])
        if variants and variants[0].get("classifier") == "shell":  # a shell can do all of it
            variants = [{"reads": ["untrusted", "private", "secret"], "writes": w}
                        for w in ("external", "unknown", "destructive")]
        if variants and all("untrusted" in v.get("reads", []) for v in variants):
            always_untrusted.append(tool)
        for v in variants:
            reads, writes = set(v.get("reads", [])), v.get("writes")
            if "untrusted" in reads and tool not in src.untrusted:
                src.untrusted.append(tool)
            if "private" in reads and tool not in src.private:
                src.private.append(tool)
            if "secret" in reads and secrets_reachable and tool not in src.secret:
                src.secret.append(tool)
            if writes and tool not in src.sinks.setdefault(writes, []):
                src.sinks[writes].append(tool)
    src.untrusted.sort(key=lambda t: t not in always_untrusted)  # clearest examples first


def _source(name: str, spec: dict, creds: list[str], protected=False) -> Source:
    preset = _identify(spec)
    src = Source(name, preset, _describe(spec), protected)
    if preset is None:  # unknown server: assume it reads anything and sends anywhere
        src.untrusted, src.sinks = ["(any tool)"], {"unknown": ["(any tool)"]}
        return src
    policy = ServerPolicy.load(preset)
    roots = [Path(a).expanduser() for a in map(str, _args(spec))
             if a.startswith("~") or os.path.isabs(a)]  # /…, ~/…, and C:\… on Windows
    reachable = preset != "filesystem" or any(
        Path(c).expanduser().is_relative_to(r) for c in creds for r in roots)
    _fill(src, policy, list(policy._exact) + [p for p, _ in policy._globs], reachable)
    return src


def _servers_to_sources(servers: dict, creds: list[str]) -> tuple[list, bool]:
    out, wrapped = [], False
    for name, spec in (servers or {}).items():
        if not isinstance(spec, dict):
            continue
        upstreams = _gateway_upstreams(spec)
        if upstreams is not None:
            wrapped = True
            out += [_source(f"{name} → {u}", s or {}, creds, protected=True) for u, s in upstreams.items()]
        else:
            out.append(_source(name, spec, creds))
    return out, wrapped


def discover(home: Path, cwd: Path) -> tuple[list[App], list[str]]:
    creds = [c for c in CREDENTIAL_FILES if (home / c[2:]).exists()]
    if (cwd / ".env").exists():
        creds.append(str(cwd / ".env"))
    creds_abs = [str(home / c[2:]) if c.startswith("~/") else c for c in creds]
    apps = []

    # Claude Code: built-in tools + user/project MCP servers + hooks
    claude_json, settings = home / ".claude.json", home / ".claude" / "settings.json"
    if claude_json.exists() or settings.exists():
        app = App("Claude Code", [p for p in (claude_json, settings, cwd / ".mcp.json") if p.exists()])
        builtin = Source("built-in tools", "claude-code", "Read, Write, Edit, Bash, WebFetch, …")
        _fill(builtin, ServerPolicy.load("claude-code"), ["Read", "WebFetch", "WebSearch", "Bash", "Write"], bool(creds))
        servers = {}
        cj, problem = _read_config(claude_json)
        cj = cj or {}
        if problem:
            app.notes.append(_unreadable(claude_json, problem))
        mcp_json, problem = _read_config(cwd / ".mcp.json")
        if problem:
            app.notes.append(_unreadable(cwd / ".mcp.json", problem))
        project = (cj.get("projects") or {}).get(str(cwd))
        for group in (cj.get("mcpServers"), project.get("mcpServers") if isinstance(project, dict) else None,
                      (mcp_json or {}).get("mcpServers")):
            if isinstance(group, dict):
                servers.update(group)
        sources, _ = _servers_to_sources(servers, creds_abs)
        app.sources = [builtin, *sources]
        for s in (settings, home / ".claude" / "settings.local.json", cwd / ".claude" / "settings.json"):
            doc, problem = _read_config(s)
            doc = doc or {}
            if problem:
                app.notes.append(f"couldn't read {s}: {problem}")
            hooks = json.dumps(doc.get("hooks") or {})
            if "trifectaguard hook" in hooks or "src.gateway hook" in hooks:
                app.protected = True
            perms = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
            app.auto_approved += [p for p in perms.get("allow", []) if RISKY_AUTO_APPROVALS.match(p)]
            if perms.get("defaultMode") in ("bypassPermissions", "dontAsk"):
                app.notes.append(f"default permission mode is {perms['defaultMode']}: tool calls run without asking you")
        if not app.protected:
            app.notes.append("today the only guard is Claude Code's own permission prompt for each Bash/WebFetch "
                             "call; the risk is highest when you approve quickly or auto-approve")
        apps.append(app)

    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    desktop = next((p for p in (home / "Library/Application Support/Claude/claude_desktop_config.json",  # macOS
                                appdata / "Claude" / "claude_desktop_config.json",                      # Windows
                                home / ".config/Claude/claude_desktop_config.json")                     # Linux
                    if p.exists()), home / "Library/Application Support/Claude/claude_desktop_config.json")
    for name, path, key in [
        ("Claude Desktop", desktop, "mcpServers"),
        ("Cursor", home / ".cursor/mcp.json", "mcpServers"),
        ("Cursor (this project)", cwd / ".cursor/mcp.json", "mcpServers"),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json", "mcpServers"),
        ("VS Code (this project)", cwd / ".vscode/mcp.json", "servers"),
    ]:
        doc, problem = _read_config(path)
        if doc is None and problem is None:
            continue
        app = App(name, [path])
        if problem:
            app.notes.append(_unreadable(path, problem))
        servers = (doc or {}).get(key)
        app.sources, app.protected = _servers_to_sources(servers if isinstance(servers, dict) else {}, creds_abs)
        apps.append(app)

    for app in apps:
        app.findings = assess(app)
    return apps, creds


def _pick(sources, attr, classes=None):
    out = []
    for s in sources:
        items = getattr(s, attr) if classes is None else [t for c in classes for t in s.sinks.get(c, [])]
        out += [(s, t) for t in items]
    return out


def _fmt(pairs, n=2):
    shown = [f"{s.name}/{t}" if s.name != "built-in tools" else t for s, t in pairs[:n]]
    return ", ".join(shown) + (f" (+{len(pairs) - n} more)" if len(pairs) > n else "")


def assess(app: App) -> list[Finding]:
    """The engine's default flow rules, applied to what the app's tools could do."""
    src = app.sources
    untrusted, private, secret = _pick(src, "untrusted"), _pick(src, "private"), _pick(src, "secret")
    out = _pick(src, None, ["public", "external", "unknown"])
    findings = []

    def add(sev, title, *steps):
        pairs = [p for _, chain in steps for p in chain]
        guarded = app.protected or all(s.protected for s, _ in pairs)
        how = "  →  ".join(f"{label}: {_fmt(chain)}" for label, chain in steps)
        findings.append(Finding(sev, title, how, guarded))

    if untrusted and secret and out:
        add("HIGH", "An injected instruction could make the agent send your credentials out",
            ("untrusted input", untrusted), ("then reads credentials", secret), ("then sends via", out))
    if untrusted and private and out:
        add("HIGH", "An injected instruction could make the agent leak private data",
            ("untrusted input", untrusted), ("then reads", private), ("then sends via", out))
    for classes, sev, title, verb in [
        (["exec"], "MEDIUM", "Untrusted content could steer writes to files that run code (CI, shell startup, agent config)",
         "then writes via"),
        (["privileged", "destructive"], "MEDIUM", "Untrusted content could steer account changes or deletions",
         "then acts via"),
    ]:
        sinks = _pick(src, None, classes)
        if untrusted and sinks:
            add(sev, title, ("untrusted input", untrusted), (verb, sinks))
    return findings


def render(apps: list[App], creds: list[str], color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s
    lines = [c("1", "trifectaguard scan") + " — could an injected instruction make your AI agents leak data or take actions?", ""]
    if not apps:
        lines.append("No Claude Code, Claude Desktop, Cursor, Windsurf or VS Code MCP configuration found.")
    exposed = 0
    for app in apps:
        status = c("32", "protected by trifectaguard") if app.protected else c("33", "not protected")
        lines.append(f"{c('1', app.name)}  ({status})")
        for s in app.sources:
            kind = s.preset or c("33", "unknown server: assumed to read anything and send anywhere")
            lines.append(f"  • {s.name}  [{kind}]{'  ✓ behind trifectaguard' if s.protected else ''}"
                         + (f"  {c('2', s.detail)}" if s.detail else ""))
        if not app.sources:
            lines.append("  no MCP servers configured")
        for f in app.findings:
            if f.mitigated:
                lines.append(f"  {c('32', 'OK   ')} {f.title} — guarded by trifectaguard")
                continue
            exposed += 1
            tag = c("31;1", "HIGH ") if f.severity == "HIGH" else c("33;1", "MED  ")
            lines += [f"  {tag} {f.title}", f"        {c('2', f.how)}"]
        if app.auto_approved:
            lines.append(f"  {c('33', 'note ')} auto-approved without asking: {', '.join(app.auto_approved)}")
        for n in app.notes:
            lines.append(f"  {c('2', 'note ')} {c('2', n)}")
        if not app.findings and not any("NOT checked" in n for n in app.notes):
            lines.append(f"  {c('32', 'OK   ')} no risky combination of tools")
        lines.append("")
    if creds:
        lines.append(f"Credential files an agent could reach on this machine: {', '.join(creds)}")
        lines.append(c("2", "(checked for existence only; not opened)"))
        lines.append("")
    if exposed:
        lines += [c("1", "Protect these flows:"),
                  "  Claude Code:            trifectaguard hooks-snippet -c hooks.yaml   (see hooks.example.yaml)",
                  "  Claude Desktop/Cursor:  put your servers behind  trifectaguard run -c gateway.yaml",
                  "  Start with  mode: monitor  to see what it would stop before it stops anything."]
    elif any("NOT checked" in n for a in apps for n in a.notes):
        lines.append(c("33", "Nothing exposed in the configs that could be read (see the notes above)."))
    else:
        lines.append(c("32", "Nothing exposed."))
    return "\n".join(lines)


def to_json(apps: list[App], creds: list[str]) -> dict:
    return {"credential_files": creds, "apps": [{
        "name": a.name, "protected": a.protected, "config_paths": [str(p) for p in a.config_paths],
        "servers": [{"name": s.name, "preset": s.preset, "protected": s.protected} for s in a.sources],
        "auto_approved": a.auto_approved, "notes": a.notes,
        "findings": [{"severity": f.severity, "title": f.title, "how": f.how, "mitigated": f.mitigated}
                     for f in a.findings]} for a in apps]}


def main(as_json: bool = False, home: str | None = None, cwd: str | None = None) -> int:
    import sys
    apps, creds = discover(Path(home or Path.home()), Path(cwd or os.getcwd()).resolve())
    if as_json:
        print(json.dumps(to_json(apps, creds), indent=2))
    else:
        print(render(apps, creds, color=sys.stdout.isatty()))
    exposed = sum(1 for a in apps for f in a.findings if not f.mitigated and f.severity == "HIGH")
    return 1 if exposed else 0  # non-zero lets CI fail on unprotected high-risk setups
