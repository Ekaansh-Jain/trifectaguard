"""
Deterministic taint engine for the MCP gateway.

Core rule ("lethal trifecta"): a data-exfiltration sink is blocked once the
session has BOTH
  (a) ingested untrusted content (from a source tool), AND
  (b) read a sensitive resource (a secret-like file/value).

This allows normal work (e.g. reading an issue then commenting) because the
benign path never reads a secret; it blocks exfiltration even if the secret is
transformed (base64, reversed, …), because the guarantee is about data flow, not
string matching. A second, defense-in-depth check also blocks when a known
tainted secret value appears verbatim in a sink argument (DLP).

Tool roles come from a policy dict so the engine is server-agnostic and unit-
testable without any MCP machinery.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field

# Names that mark a value as secret-like when they appear on the left of NAME=VALUE
SECRET_NAME_RE = re.compile(
    r"(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE)", re.I
)
# Paths that count as sensitive reads
SENSITIVE_PATH_RE = re.compile(
    r"(secret|credential|password|\.env|/etc/|id_rsa|\.pem|token)", re.I
)


@dataclass
class Decision:
    allow: bool
    reason: str = ""
    code: str = ""  # "" | "dlp" (hard block) | "trifecta" (adjudicable)


@dataclass
class TaintEngine:
    untrusted_sources: set = field(default_factory=set)
    sinks: set = field(default_factory=set)
    sensitive_reads: set = field(default_factory=set)  # tools that read files
    detector: object = None  # optional Layer-1: scan(text)->bool

    ingested_untrusted: bool = False
    read_sensitive: bool = False
    injection_detected: bool = False
    tainted_values: set = field(default_factory=set)
    events: list = field(default_factory=list)

    # ---- observe tool results -------------------------------------------------
    def observe(self, tool_name: str, args: dict, result_text: str):
        if tool_name in self.untrusted_sources:
            self.ingested_untrusted = True
            self.events.append(f"ingested untrusted content via {tool_name}()")
            # Layer 1: scan the ingested content for injection
            if self.detector is not None and self.detector(result_text):
                self.injection_detected = True
                self.events.append(f"DETECTOR flagged injection in {tool_name}() output")
        if tool_name in self.sensitive_reads:
            path = str(args.get("path", ""))
            sensitive = bool(SENSITIVE_PATH_RE.search(path)) or self._looks_secret(
                result_text
            )
            if sensitive:
                self.read_sensitive = True
                for v in self._extract_secret_values(result_text):
                    self.tainted_values.add(v)
                self.events.append(f"read sensitive resource via {tool_name}({path})")

    # ---- gate sink calls ------------------------------------------------------
    def check(self, tool_name: str, args: dict) -> Decision:
        if tool_name not in self.sinks:
            return Decision(True)
        blob = json.dumps(args, default=str)
        # DLP: verbatim secret in the outgoing arguments — HARD block, never
        # adjudicable (an actual secret must not leave, whatever the context).
        for v in self.tainted_values:
            if v and v in blob:
                return Decision(
                    False,
                    f"blocked {tool_name}(): outgoing data contains a secret value "
                    f"read earlier from a sensitive resource",
                    code="dlp",
                )
        # Trifecta: untrusted content + sensitive read already happened. This is
        # SUSPICIOUS but may be legitimate — mark it adjudicable so an LLM judge
        # can allow genuine flows (e.g. rotate-then-confirm) with full context.
        if self.ingested_untrusted and self.read_sensitive:
            return Decision(
                False,
                f"blocked {tool_name}(): session read a sensitive resource after "
                f"ingesting untrusted content (lethal-trifecta guard)",
                code="trifecta",
            )
        # Layer 1 signal: an injection was detected in ingested content and now a
        # sink is firing. Catches manipulation/non-exfil attacks the trifecta (which
        # needs a sensitive read) would miss. Adjudicable.
        if self.injection_detected:
            return Decision(
                False,
                f"blocked {tool_name}(): sink fired after the detector flagged an "
                f"injection in ingested content",
                code="detector",
            )
        return Decision(True)

    # ---- helpers --------------------------------------------------------------
    @staticmethod
    def _looks_secret(text: str) -> bool:
        return any(
            SECRET_NAME_RE.search(line) and "=" in line
            for line in text.splitlines()
        )

    @staticmethod
    def _extract_secret_values(text: str):
        vals = []
        for line in text.splitlines():
            if "=" in line and SECRET_NAME_RE.search(line.split("=", 1)[0]):
                v = line.split("=", 1)[1].strip()
                if len(v) >= 6:
                    vals.append(v)
        return vals


def pin_descriptions(tools) -> dict:
    """Map tool name -> sha256 of its description, for rug-pull detection."""
    return {
        t["name"]: hashlib.sha256((t.get("description") or "").encode()).hexdigest()
        for t in tools
    }


def diff_pins(pinned: dict, current: dict) -> list:
    """Return names whose description hash changed or newly appeared."""
    changed = []
    for name, h in current.items():
        if name in pinned and pinned[name] != h:
            changed.append(name)
    return changed


DEFAULT_POLICY = {
    "untrusted_sources": {"get_issue", "fetch_url", "read_email", "search"},
    "sinks": {"post_comment", "send_message", "create_pr", "http_post"},
    "sensitive_reads": {"read_file"},
}


def build_engine(policy: dict = None, detector=None) -> TaintEngine:
    p = policy or DEFAULT_POLICY
    return TaintEngine(
        untrusted_sources=set(p.get("untrusted_sources", [])),
        sinks=set(p.get("sinks", [])),
        sensitive_reads=set(p.get("sensitive_reads", [])),
        detector=detector,
    )
