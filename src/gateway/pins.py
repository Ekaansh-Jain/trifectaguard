"""
Tool-definition pinning ("rug pull" defence), persisted across sessions.

The first time the gateway sees a server's tools it records a hash of each
tool's name, description and input schema (trust on first use). If a later
session sees a different definition, the tool is reported as changed so the
gateway can quarantine it until the user re-pins. Schemas are hashed too because
parameter descriptions can carry injected instructions just like the tool
description.
"""
import hashlib
import json
from pathlib import Path


def fingerprint(name: str, description: str, input_schema: dict) -> str:
    blob = json.dumps([name, description or "", input_schema or {}], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class PinStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        try:
            self.pins = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.pins = {}

    def diff(self, server: str, tools: dict) -> tuple[list, list]:
        """tools: name -> fingerprint. Returns (changed, not_yet_pinned); read-only."""
        known = self.pins.get(server, {})
        changed = sorted(n for n, fp in tools.items() if n in known and known[n] != fp)
        new = sorted(n for n in tools if n not in known)
        return changed, new

    def check(self, server: str, tools: dict) -> tuple[list, list]:
        """Like diff(), then pins the new tools. Changed tools keep their old pin
        so they stay flagged until the user re-pins."""
        changed, new = self.diff(server, tools)
        if new:
            self.pins.setdefault(server, {}).update({n: tools[n] for n in new})
            self._save()
        return changed, new

    def repin(self, server: str | None = None):
        if server is None:
            self.pins = {}
        else:
            self.pins.pop(server, None)
        self._save()

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.pins, indent=2, sort_keys=True), encoding="utf-8")
