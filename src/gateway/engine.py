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

Destination provenance: for sinks that name a destination (email recipient,
IBAN, URL, user), the engine checks where that value came from.
  - it appears in the user's request (trust()) or in output of a tool that
    reads no untrusted content      → the user chose it: "trusted destination"
  - it appears only in untrusted content → an injection may have chosen it: ask
  - it appears nowhere                → strict mode: ask. Lenient mode (the
    MCP default, since a gateway never sees the user's prompt) doesn't ask, but
    doesn't count it as trusted either.
Sending private data to a trusted destination over a non-public channel is what
the user asked for, so those flows skip the trifecta rules. Only a destination
positively seen in trusted text earns that: one the model assembled from
obfuscated text ("attacker at evil dot com") is unseen, not trusted. Publishing
is never exempt: a public destination exposes the data to the attacker too.

MCP-agnostic: the gateway calls check() before and observe() after each tool
call; any other agent runtime can do the same.
"""
import json
import re
from dataclasses import dataclass, field

from src.gateway import dlp
from src.gateway.rules import UNCLASSIFIED, Role, ServerPolicy

SEVERITY = {"allow": 0, "ask": 1, "block": 2}
ALL_SINKS = ["public", "external", "internal", "local", "exec", "privileged", "destructive", "unknown"]

DEFAULT_FLOWS = [
    {"name": "secret-exfiltration", "requires": ["untrusted", "secret"],
     "sinks": ["public", "external", "unknown"], "action": "block",
     "why": "credentials were read after untrusted content entered the session"},
    {"name": "secret-after-untrusted", "requires": ["untrusted", "secret"],
     "sinks": ["internal"], "action": "ask", "skip_if_destination_trusted": True,
     "why": "credentials were read after untrusted content entered the session"},
    {"name": "lethal-trifecta", "requires": ["untrusted", "private"],
     "sinks": ["public", "unknown"], "action": "ask",
     "why": "private data was read after untrusted content entered the session"},
    {"name": "lethal-trifecta", "requires": ["untrusted", "private"],
     "sinks": ["external"], "action": "ask", "skip_if_destination_trusted": True,
     "why": "private data was read after untrusted content entered the session"},
    {"name": "secret-to-public", "requires": ["secret"],
     "sinks": ["public"], "action": "ask",
     "why": "the session has read credentials"},
    {"name": "untrusted-to-exec", "requires": ["untrusted"],
     "sinks": ["exec"], "action": "ask",
     "why": "untrusted content could be steering a write to an executable location"},
    {"name": "untrusted-to-privileged", "requires": ["untrusted"],
     "sinks": ["privileged"], "action": "ask", "skip_if_destination_trusted": True,
     "why": "untrusted content could be steering an access or account change"},
    {"name": "untrusted-to-destructive", "requires": ["untrusted"],
     "sinks": ["destructive"], "action": "ask",
     "why": "untrusted content could be steering a deletion"},
    {"name": "flagged-injection", "requires": ["injection"],
     "sinks": ALL_SINKS, "action": "ask",
     "why": "the injection detector flagged content the agent read"},
]
DESTINATION_ACTION = "ask"  # a destination that came from untrusted content
# Destinations of these sinks are inside the trust boundary (a workspace member,
# your own disk), so they can't be attacker-owned; what's sent there is still
# covered by the label rules.
INSIDE_BOUNDARY = {"internal", "local"}

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
    "privileged": "an access or account change",
    "destructive": "a deletion",
    "unknown": "a destination of unknown visibility",
}
MIN_DEST_LEN = 3


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower())


def _norm_dest(value) -> str:
    v = _norm(value).strip()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)  # scheme
    return v.rstrip("/")


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
    strict_destinations: bool = False  # unseen destinations need approval too

    labels: dict = field(default_factory=dict)  # label -> "server/tool" that introduced it
    secrets: set = field(default_factory=set)
    approvals: set = field(default_factory=set)  # (rule, server, tool) allowed for the session
    events: list = field(default_factory=list)
    trusted_text: list = field(default_factory=list)  # user request + trusted tool output
    untrusted_text: list = field(default_factory=list)  # (source, text) an attacker could write

    def role(self, server: str, tool: str, args: dict) -> Role:
        policy: ServerPolicy | None = self.policies.get(server)
        return policy.role(tool, args or {}) if policy else UNCLASSIFIED

    def trust(self, text: str):
        """Register text the user wrote (their request), for destination checks."""
        self.trusted_text.append(_norm(text))

    # ---- before the call -----------------------------------------------------
    def check(self, server: str, tool: str, args: dict) -> Verdict:
        args = args or {}
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
        dests = self._destinations(role, args)
        worst = Verdict("allow")
        dest_trusted = False
        if dests and role.destination_carries_data:
            # a URL copied verbatim from something already seen carries no new data
            if all(self._seen_anywhere(d) for d in dests):
                return worst
        elif dests and role.writes not in INSIDE_BOUNDARY:
            origins = {d: self._origin(d) for d in dests}
            dest_trusted = all(o == "trusted" for o in origins.values())  # dests is non-empty
            bad = {d: o for d, o in origins.items()
                   if o not in ("trusted", "unseen") or (o == "unseen" and self.strict_destinations)}
            if bad:
                d, o = next(iter(bad.items()))
                worst = self._maybe(worst, DESTINATION_ACTION, "untrusted-destination", server, tool,
                                    f"{where} targets {d!r}, which "
                                    + (f"appears only in untrusted content from {o}"
                                       if o != "unseen" else
                                       "you didn't mention and no trusted source provided"))
        for flow in self.flows:
            if role.writes not in flow["sinks"]:
                continue
            if not all(label in self.labels for label in flow["requires"]):
                continue
            if flow.get("skip_if_destination_trusted") and dest_trusted:
                continue
            worst = self._maybe(worst, flow["action"], flow["name"], server, tool,
                                self._explain(flow, where, role))
        return worst

    def _maybe(self, worst: Verdict, action: str, rule: str, server: str, tool: str, reason: str) -> Verdict:
        if SEVERITY[action] <= SEVERITY[worst.action]:
            return worst
        if action == "ask" and (rule, server, tool) in self.approvals:
            return worst
        return Verdict(action, rule, reason)

    def approve(self, verdict: Verdict, server: str, tool: str):
        """Remember a user's 'allow for this session' for this rule and tool."""
        self.approvals.add((verdict.rule, server, tool))

    # ---- destination provenance -----------------------------------------------
    @staticmethod
    def _destinations(role: Role, args: dict) -> list[str]:
        out = []
        for name in role.destination:
            value = args.get(name)
            for v in value if isinstance(value, (list, tuple)) else [value]:
                if v is not None and len(str(v).strip()) >= MIN_DEST_LEN:
                    out.append(str(v))
        return out

    def _origin(self, dest: str) -> str:
        """'trusted' | '<server/tool>' (untrusted source) | 'unseen'."""
        d = _norm_dest(dest)
        if any(d in t for t in self.trusted_text):
            return "trusted"
        for source, text in self.untrusted_text:
            if d in text:
                return source
        return "unseen"

    def _seen_anywhere(self, dest: str) -> bool:
        d = _norm_dest(dest)
        return any(d in t for t in self.trusted_text) or any(d in t for _, t in self.untrusted_text)

    # ---- after the call ------------------------------------------------------
    def observe(self, server: str, tool: str, args: dict, text: str):
        role = self.role(server, tool, args)
        where = f"{server}/{tool}"
        for label in role.reads:
            self._add(label, where)
        if "untrusted" in role.reads:
            self.untrusted_text.append((where, _norm(text)))
        else:
            self.trusted_text.append(_norm(text))
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
