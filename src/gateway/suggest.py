"""
`trifectaguard suggest`: read the audit log (ideally after a few days in monitor
mode) and propose config that removes repeat prompts without weakening the
rules: links you keep opening become trusted_urls, destinations you keep
approving point at remember_approvals: project.

It only prints suggestions; it never edits your config.
"""
import json
import re
from collections import Counter
from urllib.parse import urlparse

from .config import Config

STOPPED = {"asked", "denied", "blocked", "would_ask", "would_block"}
TARGET = re.compile(r"targets '([^']+)'")


def _events(cfg: Config) -> list[dict]:
    path = cfg.state_dir / "audit.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def report(cfg: Config, min_count: int = 3) -> str:
    events = [e for e in _events(cfg) if e.get("event") in STOPPED]
    if not events:
        return (f"No stopped or would-be-stopped calls in {cfg.state_dir / 'audit.jsonl'} yet.\n"
                "Run with mode: monitor for a few days of normal work, then try again.")
    by_rule = Counter((e.get("rule", "?"), f"{e.get('server')}/{e.get('tool')}") for e in events)
    targets = Counter()
    for e in events:  # the destinations field; older logs only have it inside the reason text
        found = e.get("destinations") or [m.group(1) for m in [TARGET.search(e.get("reason", ""))] if m]
        targets.update(found)
    lines = [f"{len(events)} calls were (or would have been) stopped. Most frequent:", ""]
    for (rule, tool), n in by_rule.most_common(10):
        lines.append(f"  {n:4d}  {rule:26s} {tool}")

    hosts = Counter()
    for t, n in targets.items():
        u = urlparse(t if "://" in t else f"https://{t}")
        if u.netloc and "." in u.netloc and "@" not in t:
            hosts[f"{u.scheme or 'https'}://{u.netloc}/*"] += n
    repeat_dests = [(t, n) for t, n in targets.most_common()
                    if n >= min_count and not t.startswith(("http", "www"))]
    suggestions = []
    frequent_hosts = [h for h, n in hosts.most_common() if n >= min_count]
    if frequent_hosts:
        suggestions.append("Links you open repeatedly: if you trust these sites, add them to "
                           "builtin.vars.trusted_urls (hooks) or the fetch server's vars.trusted_urls (proxy):\n"
                           + "\n".join(f"      - \"{h}\"" for h in frequent_hosts[:10]))
    if repeat_dests and cfg.remember_approvals != "project":
        suggestions.append("You approve the same destinations again and again ("
                           + ", ".join(t for t, _ in repeat_dests[:5])
                           + "). Set  remember_approvals: project  so an approval in a project sticks.")
    if any(r == "lethal-trifecta" and "Bash" in t for (r, t) in by_rule):
        suggestions.append("Most Bash prompts come from commands that can reach the network after the session "
                           "read web content and private files. That's the intended check; if it's noisy, "
                           "Claude Code's /sandbox (OS-level network limits) is a stronger alternative for Bash.")
    lines += ["", "Suggestions (nothing is changed automatically):" if suggestions else
              "No config changes suggested: the prompts look like ones worth keeping."]
    lines += [f"  • {s}" for s in suggestions]
    return "\n".join(lines)
