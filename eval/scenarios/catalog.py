"""Loading catalog.yaml and parsing its `server.tool {args}` calls."""
import os

import yaml

CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog.yaml")


def load_catalog(path: str = CATALOG) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_call(step: dict) -> tuple[str, str, dict]:
    """{call: github.get_issue, args: {...}} → ('github', 'get_issue', {...});
    {call: Bash, args: {...}} → ('claude-code', 'Bash', {...})."""
    name, args = step["call"], step.get("args")
    if "." in name:
        server, _, tool = name.partition(".")
    else:
        server, tool = "claude-code", name
    return server, tool, args or {}


def expectation(step: dict, mode: str) -> tuple[str, str | None]:
    """('allow', None) or ('stop', rule-or-None) for a step in a mode."""
    exp = step.get(mode, step.get("expect", "allow")) if mode == "proxy" else step.get("expect", "allow")
    if exp == "allow":
        return "allow", None
    if exp == "stop":
        return "stop", None
    return "stop", exp.get("stop")
