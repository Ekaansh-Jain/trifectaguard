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

from . import dlp
from .rules import UNCLASSIFIED, Role, ServerPolicy

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
MIN_DEST_LEN = 1
SHORT_DEST = 4  # shorter ids ("7", "42") count as trusted only if the user wrote them


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower())


def _norm_dest(value) -> str:
    v = _norm(value).strip()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)  # scheme
    return v.rstrip("/")


_TOKEN = r"a-z0-9_%+\-@"  # characters that continue an address/identifier


def _contains(dest: str, text: str) -> bool:
    """dest occurs in text as a whole token: 'smith@gmail.com' is not found in
    'john.smith@gmail.com', and 'evil.example/4' is not found in '…/45'."""
    pattern = rf"(?<![{_TOKEN}.]){re.escape(dest)}(?![{_TOKEN}]|\.[a-z0-9])"
    return re.search(pattern, text) is not None


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
    strict_links: bool = True  # with private data in session, opening attacker-supplied links asks

    labels: dict = field(default_factory=dict)  # label -> "server/tool" that introduced it
    secrets: set = field(default_factory=set)
    approvals: set = field(default_factory=set)  # (server, tool, destinations) allowed for the session
    events: list = field(default_factory=list)
    user_text: list = field(default_factory=list)  # the user's own words (trust())
    trusted_text: list = field(default_factory=list)  # output of tools that read no untrusted content
    untrusted_text: list = field(default_factory=list)  # (source, text) an attacker could write
    tainted_writes: list = field(default_factory=list)  # (where, text) the agent stored after reading untrusted content

    def role(self, server: str, tool: str, args: dict) -> Role:
        policy: ServerPolicy | None = self.policies.get(server)
        return policy.role(tool, args or {}) if policy else UNCLASSIFIED

    def trust(self, text: str):
        """Register text the user wrote (their request), for destination checks."""
        self.user_text.append(_norm(text))

    # ---- before the call -----------------------------------------------------
    def check(self, server: str, tool: str, args: dict) -> Verdict:
        args = args or {}
        role = self.role(server, tool, args)
        if role.writes is None:
            return Verdict("allow")
        where = f"{server}/{tool}"
        # never echo any part of the secret: this text reaches the agent and logs
        if role.writes != "local" and dlp.leaked(json.dumps(args, default=str), self.secrets):
            return Verdict(
                "block", "dlp",
                f"{where} would send a credential the session read from "
                f"{self.labels.get('secret', 'a private source')}",
            )
        dests = self._destinations(role, args)
        approved = (server, tool, self._dest_key(dests)) in self.approvals
        worst = Verdict("allow")
        dest_trusted = False
        if dests and role.destination_carries_data:
            # Re-fetching a URL already seen sends no new data. Once the session
            # holds private data, though, choosing WHICH attacker-supplied URL to
            # open can leak it bit by bit, so only trusted URLs stay free then.
            origins = [self._origin(d) for d in dests]
            holds_private = self.strict_links and bool({"private", "secret"} & set(self.labels))
            if all(o != "unseen" for o in origins) and (
                    not holds_private or all(o == "trusted" for o in origins)):
                return worst
        elif dests and role.writes not in INSIDE_BOUNDARY:
            origins = {d: self._origin(d) for d in dests}
            dest_trusted = all(o == "trusted" for o in origins.values())  # dests is non-empty
            # An unseen destination (not in anything the session read) is only
            # free in lenient mode and only before untrusted content arrived: an
            # injection can spell an address out for the model to reassemble.
            unseen_ok = not self.strict_destinations and "untrusted" not in self.labels
            bad = {d: o for d, o in origins.items()
                   if o != "trusted" and not (o == "unseen" and unseen_ok)}
            if bad:
                d, o = next(iter(bad.items()))
                worst = self._maybe(worst, DESTINATION_ACTION, "untrusted-destination", approved,
                                    f"{where} targets {d!r}, which "
                                    + (f"appears only in untrusted content from {o}"
                                       if o != "unseen" else
                                       "you didn't mention and no trusted source provided"))
        # a call that itself reads private data or secrets (curl -d @.env …) can
        # send them in the same step, so its own reads count too
        labels = set(self.labels) | (set(role.reads) & {"private", "secret"})
        # A page fetch sends only its URL, which the approval prompt shows in full,
        # and a secret inside it is already caught by the DLP check above. So for
        # fetch-like calls the flow rules ask rather than block: copied links
        # can only leak through which one gets opened, new ones the user can read.
        choice_only = bool(dests) and role.destination_carries_data
        for flow in self.flows:
            if role.writes not in flow["sinks"]:
                continue
            if not all(label in labels for label in flow["requires"]):
                continue
            if flow.get("skip_if_destination_trusted") and dest_trusted:
                continue
            action = "ask" if choice_only and flow["action"] == "block" else flow["action"]
            worst = self._maybe(worst, action, flow["name"], approved, self._explain(flow, where, role))
        return worst

    @staticmethod
    def _maybe(worst: Verdict, action: str, rule: str, approved: bool, reason: str) -> Verdict:
        if SEVERITY[action] <= SEVERITY[worst.action]:
            return worst
        if action == "ask" and approved:
            return worst
        return Verdict(action, rule, reason)

    def approve(self, verdict: Verdict, server: str, tool: str, args: dict | None = None):
        """Remember a user's 'allow for this session' for this tool AND these
        destinations: approving an email to bob must not approve one to mallory.
        Blocks are never approvable."""
        dests = self._destinations(self.role(server, tool, args or {}), args or {})
        self.approvals.add((server, tool, self._dest_key(dests)))

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

    @staticmethod
    def _dest_key(dests: list[str]) -> tuple:
        return tuple(sorted(_norm_dest(d) for d in dests))

    def _origin(self, dest: str) -> str:
        """'trusted' | '<where>' (attacker-influenced source) | 'unseen'.
        Precedence: the user's words, then anything the agent itself stored after
        reading untrusted content (so an injected address can't be laundered
        through a file and read back as "trusted"), then trusted tool output,
        then untrusted tool output."""
        d = _norm_dest(dest)
        if any(_contains(d, t) for t in self.user_text):
            return "trusted"
        for where, text in self.tainted_writes:
            if _contains(d, text):
                return f"{where} (written after reading untrusted content)"
        if len(d) >= SHORT_DEST and any(_contains(d, t) for t in self.trusted_text):
            return "trusted"
        for source, text in self.untrusted_text:
            if _contains(d, text):
                return source
        return "unseen"

    # ---- after the call ------------------------------------------------------
    def observe(self, server: str, tool: str, args: dict, text: str):
        role = self.role(server, tool, args)
        where = f"{server}/{tool}"
        if role.writes in INSIDE_BOUNDARY and "untrusted" in self.labels:
            # what the agent stores under untrusted influence stays untrusted when
            # read back (destination args excluded: they are where, not what)
            stored = {k: v for k, v in (args or {}).items() if k not in role.destination}
            self.tainted_writes.append((where, _norm(json.dumps(stored, default=str))))
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

    # ---- persistence (hooks run as a fresh process per tool call) ---------------
    MAX_TEXTS = 400  # per list; dropping old text only makes destinations "unseen"
    MAX_CHARS = 40_000  # per tool output

    def to_state(self) -> dict:
        cap = lambda xs: xs[-self.MAX_TEXTS:]  # noqa: E731
        return {
            "labels": self.labels,
            "secrets": sorted(self.secrets),
            "approvals": [[s, t, list(d)] for s, t, d in self.approvals],
            "events": self.events[-50:],
            "user_text": cap(self.user_text),
            "trusted_text": [t[:self.MAX_CHARS] for t in cap(self.trusted_text)],
            "untrusted_text": [[w, t[:self.MAX_CHARS]] for w, t in cap(self.untrusted_text)],
            "tainted_writes": [[w, t[:self.MAX_CHARS]] for w, t in cap(self.tainted_writes)],
        }

    def load_state(self, state: dict):
        self.labels = dict(state.get("labels", {}))
        self.secrets = set(state.get("secrets", []))
        self.approvals = {(s, t, tuple(d)) for s, t, d in state.get("approvals", [])}
        self.events = list(state.get("events", []))
        self.user_text = list(state.get("user_text", []))
        self.trusted_text = list(state.get("trusted_text", []))
        self.untrusted_text = [tuple(x) for x in state.get("untrusted_text", [])]
        self.tainted_writes = [tuple(x) for x in state.get("tainted_writes", [])]

    def _add(self, label: str, where: str):
        if label not in self.labels:
            self.labels[label] = where
            self.events.append(f"{LABEL_TEXT.get(label, label)} entered via {where}")

    def _explain(self, flow: dict, where: str, role: Role) -> str:
        sources = ", ".join(
            f"{LABEL_TEXT.get(l, l)} from {self.labels.get(l, where + ' itself')}" for l in flow["requires"]
        )
        return (f"{where} sends data to {SINK_TEXT.get(role.writes, role.writes)}, "
                f"and {flow.get('why', 'the session state matches this rule')} "
                f"({sources})")
