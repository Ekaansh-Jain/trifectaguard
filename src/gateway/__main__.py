"""
CLI for the MCP flow-control gateway.

  python -m src.gateway run -c gateway.yaml             # serve (point your MCP client here)
  python -m src.gateway run --policy github -- npx -y @modelcontextprotocol/server-github
  python -m src.gateway inspect -c gateway.yaml         # how is every tool classified?
  python -m src.gateway repin -c gateway.yaml [--server github]
"""
import argparse
import contextlib
import sys
from contextlib import AsyncExitStack

import anyio

from src.gateway.gateway import Config, Gateway
from src.gateway.pins import fingerprint


def load(args) -> Config:
    if args.config:
        return Config.load(args.config)
    if not args.command:
        sys.exit("need -c CONFIG, or an upstream command after --")
    spec = {"command": args.command[0], "args": args.command[1:]}
    if args.policy:
        spec["policy"] = args.policy
    return Config(servers={"upstream": spec})


async def inspect(cfg: Config):
    gw = Gateway(cfg)
    async with AsyncExitStack() as stack:
        await gw.connect(stack)
        unclassified = 0
        for name in gw.upstreams:
            policy = gw.engine.policies.get(name)
            tools = await gw.upstream_tools(name)
            fps = {t.name: fingerprint(t.name, t.description, t.inputSchema) for t in tools}
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
    ap = argparse.ArgumentParser(prog="python -m src.gateway")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "inspect", "repin"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config")
        p.add_argument("--policy", help="policy preset/path for a single upstream given after --")
        if name == "repin":
            p.add_argument("--server", help="only re-pin this server (default: all)")
    argv = sys.argv[1:]
    command = []
    if "--" in argv:
        i = argv.index("--")
        argv, command = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    args.command = command
    cfg = load(args)

    if args.cmd == "run":
        with contextlib.suppress(KeyboardInterrupt):
            anyio.run(Gateway(cfg).serve)
    elif args.cmd == "inspect":
        anyio.run(inspect, cfg)
    elif args.cmd == "repin":
        from src.gateway.pins import PinStore
        PinStore(cfg.state_dir / "pins.json").repin(args.server)
        print(f"cleared pins for {args.server or 'all servers'}; they re-pin on next start")


if __name__ == "__main__":
    main()
