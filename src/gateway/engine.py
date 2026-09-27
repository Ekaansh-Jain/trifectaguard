"""
Session-wide information-flow engine.

Every tool result adds the labels its policy assigns (untrusted, private, …) to
the session; every sink call is checked against flow rules over those labels:

    session labels ⊇ rule.requires  AND  sink's write class ∈ rule.sinks
        ⇒ rule.action (ask | block)

Labels are tracked across ALL servers in the session, so "read an untrusted web
page (fetch) → read a private file (filesystem) → post to Slack" is one flow,
not three unrelated calls. A DLP check hard-blocks any sink call that carries a
secret the session has read, even encoded.

MCP-agnostic: the gateway calls check() before and observe() after each tool
call; any other agent runtime can do the same.
"""
import json
from dataclasses import dataclass, field

from src.gateway import dlp
from src.gateway.rules import UNCLASSIFIED, Role, ServerPolicy

SEVERITY = {"allow": 0, "ask": 1, "block": 2}
ALL_SINKS = ["public", "external", "internal", "local", "exec", "unknown"]

DEFAULT_FLOWS = [
    {"name": "secret-exfiltration", "requires": ["untrusted", "secret"],
     "sinks": ["public", "external", "unknown"], "action": "block",
     "why": "credentials were read after untrusted content entered the session"},
    {"name": "secret-after-untrusted", "requires": ["untrusted", "secret"],
     "sinks": ["internal"], "action": "ask",
     "why": "credentials were read after untrusted content entered the session"},
    {"name": "lethal-trifecta", "requires": ["untrusted", "private"],
     "sinks": ["public", "external", "unknown"], "action": "ask",
     "why": "private data was read after untrusted content entered the session"},
    {"name": "secret-to-public", "requires": ["secret"],
     "sinks": ["public"], "action": "ask",
     "why": "the session has read credentials"},
    {"name": "untrusted-to-exec", "requires": ["untrusted"],
     "sinks": ["exec"], "action": "ask",
     "why": "untrusted content could be steering a write to an executable location"},
    {"name": "flagged-injection", "requires": ["injection"],
     "sinks": ALL_SINKS, "action": "ask",
     "why": "the injection detector flagged content the agent read"},
]

LABEL_TEXT = {
    "untrusted": "untrusted content",
    "private": "private data",
    "secret": "credentials",
    "injection": "flagged injection",
}
SINK_TEXT = {
    "public": "a public destination",
    "external": "an external destination",
    "internal": "an internal destination",
    "local": "the local disk",
    "exec": "an executable/startup location",
    "unknown": "a destination of unknown visibility",
}


@dataclass
class Verdict:
    action: str  # allow | ask | block
    rule: str = ""
    reason: str = ""


@dataclass
class FlowEngine:
    policies: dict  # server name -> ServerPolicy
    flows: list = field(default_factory=lambda: list(DEFAULT_FLOWS))
    detector: object = None  # optional scan(text) -> bool

    labels: dict = field(default_factory=dict)  # label -> "server/tool" that introduced it
    secrets: set = field(default_factory=set)
    approvals: set = field(default_factory=set)  # (rule, server, tool) allowed for the session
    events: list = field(default_factory=list)

    def role(self, server: str, tool: str, args: dict) -> Role:
        policy: ServerPolicy | None = self.policies.get(server)
        return policy.role(tool, args or {}) if policy else UNCLASSIFIED

    # ---- before the call -----------------------------------------------------
    def check(self, server: str, tool: str, args: dict) -> Verdict:
        role = self.role(server, tool, args)
        if role.writes is None:
            return Verdict("allow")
        where = f"{server}/{tool}"
        # never echo any part of the secret: this text reaches the agent and logs
        if dlp.leaked(json.dumps(args, default=str), self.secrets):
            return Verdict(
                "block", "dlp",
                f"{where} would send a credential the session read from "
                f"{self.labels.get('secret', 'a private source')}",
            )
        worst = Verdict("allow")
        for flow in self.flows:
            if role.writes not in flow["sinks"]:
                continue
            if not all(label in self.labels for label in flow["requires"]):
                continue
            if SEVERITY[flow["action"]] <= SEVERITY[worst.action]:
                continue
            if flow["action"] == "ask" and (flow["name"], server, tool) in self.approvals:
                continue
            worst = Verdict(flow["action"], flow["name"], self._explain(flow, where, role))
        return worst

    def approve(self, verdict: Verdict, server: str, tool: str):
        """Remember a user's 'allow for this session' for this rule and tool."""
        self.approvals.add((verdict.rule, server, tool))

    # ---- after the call ------------------------------------------------------
    def observe(self, server: str, tool: str, args: dict, text: str):
        role = self.role(server, tool, args)
        where = f"{server}/{tool}"
        for label in role.reads:
            self._add(label, where)
        # Secrets only come from private data: a public doc page full of
        # example keys must not taint the session as holding credentials.
        if "private" in role.reads or "secret" in role.reads:
            found = dlp.find_secrets(text)
            if found or "secret" in role.reads:
                self._add("secret", where)
            self.secrets |= found
        if self.detector is not None and "untrusted" in role.reads and self.detector(text):
            self._add("injection", where)

    def _add(self, label: str, where: str):
        if label not in self.labels:
            self.labels[label] = where
            self.events.append(f"{LABEL_TEXT.get(label, label)} entered via {where}")

    def _explain(self, flow: dict, where: str, role: Role) -> str:
        sources = ", ".join(
            f"{LABEL_TEXT.get(l, l)} from {self.labels[l]}" for l in flow["requires"]
        )
        return (f"{where} sends data to {SINK_TEXT.get(role.writes, role.writes)}, "
                f"and {flow.get('why', 'the session state matches this rule')} "
                f"({sources})")
