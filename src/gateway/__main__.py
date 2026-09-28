"""
CLI for the MCP flow-control gateway.

  python -m src.gateway run -c gateway.yaml             # serve (point your MCP client here)
  python -m src.gateway run --policy github -- npx -y @modelcontextprotocol/server-github
  python -m src.gateway inspect -c gateway.yaml         # how is every tool classified?
  python -m src.gateway repin -c gateway.yaml [--server github]

Audit this machine (read-only; no config needed):
  python -m src.gateway scan [--json]
  python -m src.gateway replay [TRANSCRIPT.jsonl …]   # how often would it have stepped in on past Claude Code sessions?

Fewer prompts:
  python -m src.gateway suggest -c config.yaml            # config ideas from the audit log
  python -m src.gateway approvals -c config.yaml [--clear] [--project PATH]

Claude Code hook mode (no proxy; sees your request and Claude Code's own tools):
  python -m src.gateway hooks-snippet -c gateway.yaml   # settings.json block to paste
  python -m src.gateway hook -c gateway.yaml            # what the hooks run (reads JSON on stdin)
"""
import argparse
import contextlib
import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from .config import Config

ROOT = Path(__file__).resolve().parents[2]  # the checkout, when run as src.gateway


def load(args) -> Config:
    if args.config:
        return Config.load(args.config)
    if not args.command:
        sys.exit("need -c CONFIG, or an upstream command after --")
    spec = {"command": args.command[0], "args": args.command[1:]}
    if args.policy:
        spec["policy"] = args.policy
    return Config(servers={"upstream": spec})


def hooks_snippet(config_path: str) -> dict:
    """The settings.json "hooks" block that runs hook mode for every tool."""
    config_path = str(Path(config_path).expanduser().resolve())
    package = __package__ or "src.gateway"
    command = f"{sys.executable} -m {package} hook -c {config_path}"
    if package.startswith("src."):  # running from a checkout rather than an installed package
        command = f"cd {ROOT} && {command}"
    handler = [{"type": "command", "command": command, "timeout": 30}]
    return {"hooks": {
        "UserPromptSubmit": [{"hooks": handler}],
        "PreToolUse": [{"matcher": "*", "hooks": handler}],
        "PostToolUse": [{"matcher": "*", "hooks": handler}],
    }}


async def inspect(cfg: Config):
    from .gateway import Gateway, field
    from .pins import fingerprint
    gw = Gateway(cfg)
    async with AsyncExitStack() as stack:
        await gw.connect(stack)
        unclassified = 0
        for name in gw.upstreams:
            policy = gw.engine.policies.get(name)
            tools = await gw.upstream_tools(name)
            fps = {t.name: fingerprint(t.name, t.description, field(t, "inputSchema")) for t in tools}
            changed, new = gw.pins.diff(name, fps)
            print(f"\n{name}  (policy: {policy.name if policy else 'none'}, {len(tools)} tools)")
            print(f"  {'tool':38s} {'reads':28s} {'writes':10s} note")
            for t in tools:
                role = gw.engine.role(name, t.name, {})
                note = []
                if not (policy and policy.classified(t.name)):
                    note.append("UNCLASSIFIED (treated as untrusted + unknown sink)")
                    unclassified += 1
                if role.conditional:
                    note.append("depends on args")
                if t.name in changed:
                    note.append("DEFINITION CHANGED since pinned")
                elif t.name in new:
                    note.append("not pinned yet")
                reads = ",".join(sorted(role.reads)) or "-"
                print(f"  {t.name:38s} {reads:28s} {role.writes or '-':10s} {'; '.join(note)}")
        if unclassified:
            print(f"\n{unclassified} unclassified tool(s): add them to the server's policy "
                  f"to avoid unnecessary prompts.")


def main():
    ap = argparse.ArgumentParser(prog="trifectaguard" if not (__package__ or "").startswith("src.") else "python -m src.gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    scan = sub.add_parser("scan", help="read-only audit of the AI apps on this machine")
    scan.add_argument("--json", action="store_true")
    rp = sub.add_parser("replay", help="run past Claude Code sessions through the hooks (read-only)")
    rp.add_argument("transcripts", nargs="*", help="session .jsonl files (default: this directory's sessions)")
    rp.add_argument("-c", "--config", help="hooks config (default: Claude Code built-in tools only)")
    for name in ("run", "inspect", "repin", "hook", "hooks-snippet", "suggest", "approvals"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config")
        p.add_argument("--policy", help="policy preset/path for a single upstream given after --")
        if name == "repin":
            p.add_argument("--server", help="only re-pin this server (default: all)")
        if name == "approvals":
            p.add_argument("--clear", action="store_true")
            p.add_argument("--project", help="only this project directory")
    argv = sys.argv[1:]
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    args.command = command

    if args.cmd == "scan":
        from .scan import main as scan_main
        sys.exit(scan_main(as_json=args.json))
    if args.cmd == "replay":
        from .replay import default_transcripts, render, replay
        paths = [Path(t) for t in args.transcripts] or default_transcripts(Path.cwd())
        if not paths:
            sys.exit("no Claude Code sessions found for this directory; pass transcript paths "
                     "(~/.claude/projects/<project>/*.jsonl)")
        cfg = Config.load(args.config) if args.config else Config(servers={}, builtin={"policy": "claude-code"})
        print(render(replay(paths, cfg)))
        return

    if args.cmd in ("hook", "hooks-snippet"):
        path = args.config or os.environ.get("MCP_GATEWAY_CONFIG")
        if not path:
            sys.exit("need -c CONFIG (or MCP_GATEWAY_CONFIG)")
        if args.cmd == "hook":
            from .hook import main as hook_main
            hook_main(path)
        else:
            Config.load(path)  # fail now, not on the first tool call
            print(json.dumps(hooks_snippet(path), indent=2))
        return

    cfg = load(args)
    if args.cmd == "suggest":
        from .suggest import report
        print(report(cfg))
        return
    if args.cmd == "approvals":
        from .hook import ProjectApprovals
        store = ProjectApprovals(cfg)
        if args.clear:
            store.clear(args.project)
            print(f"cleared remembered approvals for {args.project or 'all projects'}")
            return
        data = store.load()
        for project, items in data.items():
            if args.project and project != args.project:
                continue
            print(project)
            for server, tool, dests in items:
                print(f"  {server}/{tool} → {', '.join(dests)}")
        if not data:
            print("no remembered approvals (set remember_approvals: project to keep them across sessions)")
        return
    if args.cmd == "run":
        import anyio
        from .gateway import Gateway
        with contextlib.suppress(KeyboardInterrupt):
            anyio.run(Gateway(cfg).serve)
    elif args.cmd == "inspect":
        import anyio
        anyio.run(inspect, cfg)
    elif args.cmd == "repin":
        from .pins import PinStore
        PinStore(cfg.state_dir / "pins.json").repin(args.server)
        print(f"cleared pins for {args.server or 'all servers'}; they re-pin on next start")


if __name__ == "__main__":
    main()
