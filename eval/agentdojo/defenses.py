"""
Defenses under test, behind one interface so the worst-case harness and the
live-LLM harness score them identically.

  start(suite, user_task, prompt, env)  — new session
  check(tool, args) -> (action, rule)   — before a call: allow | ask | block
  observe(tool, args, text) -> bool     — after a call: True = redact this output
                                          (what AgentDojo's PI-detector defense does)

"ask" has no human in a benchmark, so the harnesses treat it as a block and
report it separately: it is the approval burden a real user would see.
"""
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.gateway.engine import FlowEngine  # noqa: E402
from src.gateway.rules import ServerPolicy  # noqa: E402

POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policies")


class NoDefense:
    name = "no defense"

    def start(self, suite, user_task, prompt, env):
        pass

    def check(self, tool, args):
        return "allow", ""

    def observe(self, tool, args, text):
        return False


class OracleToolFilter(NoDefense):
    """AgentDojo's `tool_filter` defense lets an LLM pick the tools the task
    needs before any data is read. This is its best case: exactly the tools the
    task's ground truth uses."""
    name = "tool filter (oracle)"

    def start(self, suite, user_task, prompt, env):
        self.allowed = {c.function for c in user_task.ground_truth(env.model_copy(deep=True))}

    def check(self, tool, args):
        return ("allow", "") if tool in self.allowed else ("block", "tool-not-needed")


class Detector(NoDefense):
    """Flags injected tool outputs; a flagged output is redacted, as in AgentDojo's
    `transformers_pi_detector` defense. Scans in overlapping windows so long
    outputs are fully covered (more generous than AgentDojo, which truncates)."""

    def __init__(self, name, flag_fn):
        self.name, self.flag_fn, self.cache = name, flag_fn, {}

    def observe(self, tool, args, text):
        key = hashlib.sha1(text.encode()).hexdigest()
        if key not in self.cache:
            self.cache[key] = bool(self.flag_fn(text))
        return self.cache[key]


class Flow(NoDefense):
    """The flow-control engine from src/gateway with the suite's policy.

    library mode: the agent runtime passes the user's request (trust()) and
    unseen destinations need approval (strict).
    mcp mode: what the MCP gateway sees — no user prompt, lenient destinations."""

    def __init__(self, mode="library", detector=None):
        assert mode in ("library", "mcp")
        self.mode, self.detector = mode, detector
        self.name = f"flow control ({mode} mode)" + (" + detector" if detector else "")
        self.policies = {}

    def start(self, suite, user_task, prompt, env):
        if suite not in self.policies:
            self.policies[suite] = ServerPolicy.load(os.path.join(POLICY_DIR, f"{suite}.yaml"))
        self.suite = suite
        self.engine = FlowEngine({suite: self.policies[suite]},
                                 detector=self.detector.flag_cached if self.detector else None,
                                 strict_destinations=self.mode == "library")
        if self.mode == "library":
            self.engine.trust(prompt)

    def check(self, tool, args):
        v = self.engine.check(self.suite, tool, args)
        return v.action, v.rule

    def observe(self, tool, args, text):
        self.engine.observe(self.suite, tool, args, text)
        return False


# ---- detector backends -----------------------------------------------------------
def _chunked_classifier(model_dir, positive, maxlen):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).eval()
    dev = "mps" if torch.backends.mps.is_available() else "cpu"
    model.to(dev)
    labels = {i: str(l).upper() for i, l in model.config.id2label.items()}

    def flag(text):
        ids = tok(text[:60_000], add_special_tokens=False)["input_ids"]
        window, stride = maxlen - 2, (maxlen - 2) // 2
        chunks = [tok.decode(ids[s:s + window]) for s in range(0, max(len(ids) - stride, 1), stride)]
        for i in range(0, len(chunks), 16):
            enc = tok(chunks[i:i + 16], truncation=True, max_length=maxlen,
                      padding=True, return_tensors="pt").to(dev)
            with torch.no_grad():
                pred = model(**enc).logits.argmax(-1).cpu().tolist()
            if any(positive(labels.get(p, str(p)), p) for p in pred):
                return True
        return False

    return flag


def protectai_detector():
    """AgentDojo's PI-detector baseline model."""
    flag = _chunked_classifier("protectai/deberta-v3-base-prompt-injection-v2",
                               lambda label, idx: label == "INJECTION", 512)
    return Detector("PI detector (protectai deberta, AgentDojo baseline)", flag)


def our_detector():
    """This repo's fine-tuned ModernBERT (detector-final/)."""
    flag = _chunked_classifier(os.path.join(ROOT, "detector-final"), lambda label, idx: idx == 1, 128)
    d = Detector("our detector (ModernBERT, detector-final)", flag)
    d.flag_cached = lambda text: d.observe(None, None, text)
    return d


class HookFlow(NoDefense):
    """The flow engine through the Claude Code hook code path: every call is a
    UserPromptSubmit / PreToolUse / PostToolUse event handled by
    src/gateway/hook.py, with session state saved to disk and reloaded each
    time, exactly as in Claude Code (minus the process spawn)."""
    name = "flow control (Claude Code hook mode)"

    def __init__(self):
        import tempfile
        from pathlib import Path
        from src.gateway.hook import handle
        self.handle, self.state_dir, self.n = handle, Path(tempfile.mkdtemp(prefix="hookflow-")), 0

    def start(self, suite, user_task, prompt, env):
        from src.gateway.config import Config
        self.suite, self.n = suite, self.n + 1
        self.session = f"{suite}-{self.n}"
        self.cfg = Config(servers={suite: {"policy": os.path.join(POLICY_DIR, f"{suite}.yaml")}},
                          state_dir=self.state_dir)
        self.handle(self.cfg, {"hook_event_name": "UserPromptSubmit", "session_id": self.session,
                               "prompt": prompt})

    def _event(self, event, tool, args, **extra):
        return self.handle(self.cfg, {"hook_event_name": event, "session_id": self.session,
                                      "tool_name": f"mcp__{self.suite}__{tool}", "tool_input": args,
                                      "tool_use_id": f"{self.session}-{tool}-{id(args)}", **extra})

    def check(self, tool, args):
        out = self._event("PreToolUse", tool, args)
        if not out:
            return "allow", ""
        d = out["hookSpecificOutput"]
        return ("ask" if d["permissionDecision"] == "ask" else "block"), d["permissionDecisionReason"]

    def observe(self, tool, args, text):
        self._event("PostToolUse", tool, args, tool_response=text)
        return False
