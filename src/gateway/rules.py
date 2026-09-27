"""
Declarative tool policies: which tools bring labelled data INTO the session
(`reads`) and which send data OUT of it (`writes`, a destination class).

A policy is a YAML file, either a bundled preset (src/gateway/policies/<name>.yaml)
or a path. Each tool entry is one variant or an ordered list of variants; the
first variant whose `when` conditions hold decides the tool's role:

    tools:
      get_file_contents:
        - when: {"{owner}/{repo}": $public_repos}   # template over the call args
          reads: [untrusted]
        - reads: [untrusted, private]                # fallback: assume private
      add_issue_comment:
        - when: {"{owner}/{repo}": $private_repos}
          writes: internal
        - writes: public

Condition values are glob patterns (case-insensitive); `$name` expands to a list
from the policy's `vars`, which the gateway config can override per server. A
list-valued argument (e.g. `paths`) matches if any element does; "" matches an
absent or empty argument.

Labels are free-form, but the default flow rules understand:
  untrusted — content a third party could have written (issues, web pages)
  private   — data the user would not publish (private repos, local files)
  secret    — credentials (set by the engine when it sees secret values)
Write classes: public | external | internal | local | exec | privileged
(grants access / changes an account) | destructive (deletes) | unknown.

A sink can name its `destination` args (recipients, IBAN, URL, …) so the engine
can check where the destination came from: the user, trusted data, or text an
attacker could have written. Set `destination_carries_data: true` for fetch-like
tools whose destination (a URL) can itself smuggle data out.

This module knows nothing about MCP, so the same policies can guard any agent's
tool calls.
"""
import fnmatch
import string
from dataclasses import dataclass
from pathlib import Path

import yaml

PRESET_DIR = Path(__file__).parent / "policies"
WRITE_CLASSES = {"public", "external", "internal", "local", "exec", "privileged", "destructive", "unknown"}


@dataclass(frozen=True)
class Role:
    reads: frozenset = frozenset()
    writes: str | None = None  # destination class, or None if not a sink
    rule: str = ""  # which policy entry matched, for the audit log
    conditional: bool = False  # the entry has several variants (role depends on args)
    destination: tuple = ()  # arg names naming where the data/action goes
    destination_carries_data: bool = False  # e.g. a URL that can encode data


# A tool no policy mentions: its output could say anything and it could send
# data anywhere, so assume the worst on both sides.
UNCLASSIFIED = Role(frozenset({"untrusted"}), "unknown", "unclassified")


class _Args(string.Formatter):
    """str.format over tool args that renders missing keys as ''."""

    def get_value(self, key, args, kwargs):
        return kwargs.get(key, "")


_FMT = _Args()


def _glob_any(value, patterns) -> bool:
    values = value if isinstance(value, (list, tuple)) else [value]
    # an absent/empty argument matches the pattern "" (e.g. no participants)
    values = ["" if v is None else v for v in values] or [""]
    return any(
        fnmatch.fnmatchcase(str(v).lower(), str(p).lower())
        for v in values
        for p in patterns
    )


class ServerPolicy:
    def __init__(self, name: str, tools: dict, variables: dict, default: Role = UNCLASSIFIED):
        self.name = name
        self.vars = variables
        self.default = default
        self._exact = {}
        self._globs = []  # (pattern, variants), in file order
        for key, entry in (tools or {}).items():
            variants = entry if isinstance(entry, list) else [entry]
            for v in variants:
                w = v.get("writes")
                if w is not None and w not in WRITE_CLASSES:
                    raise ValueError(f"policy {name}: tool {key}: unknown writes class {w!r}")
            if any(c in key for c in "*?["):
                self._globs.append((key, variants))
            else:
                self._exact[key] = variants

    @classmethod
    def load(cls, spec: str, variables: dict | None = None) -> "ServerPolicy":
        path = Path(spec).expanduser()
        if not path.suffix:
            path = PRESET_DIR / f"{spec}.yaml"
        if not path.exists():
            presets = sorted(p.stem for p in PRESET_DIR.glob("*.yaml"))
            raise FileNotFoundError(f"no policy {spec!r} (presets: {', '.join(presets)})")
        doc = yaml.safe_load(path.read_text()) or {}
        return cls.from_dict(doc, variables, default_name=path.stem)

    @classmethod
    def from_dict(cls, doc: dict, variables: dict | None = None, default_name: str = "policy") -> "ServerPolicy":
        """A policy given inline, in the same shape as a policy file."""
        merged = {**(doc.get("vars") or {}), **(variables or {})}
        default = UNCLASSIFIED
        if "unclassified" in doc:
            u = doc["unclassified"] or {}
            default = Role(frozenset(u.get("reads", [])), u.get("writes"), "unclassified")
        return cls(doc.get("name", default_name), doc.get("tools"), merged, default)

    def classified(self, tool: str) -> bool:
        return tool in self._exact or any(fnmatch.fnmatchcase(tool, p) for p, _ in self._globs)

    def role(self, tool: str, args: dict) -> Role:
        variants, key = self._exact.get(tool), tool
        if variants is None:
            for pattern, vs in self._globs:
                if fnmatch.fnmatchcase(tool, pattern):
                    variants, key = vs, pattern
                    break
        if variants is None:
            return self.default
        for i, v in enumerate(variants):
            if self._holds(v.get("when"), args) and not self._holds(v.get("unless"), args, empty=False):
                return Role(
                    frozenset(v.get("reads", [])),
                    v.get("writes"),
                    f"{self.name}:{key}" + (f"#{i}" if len(variants) > 1 else ""),
                    len(variants) > 1,
                    tuple(v.get("destination", ())),
                    bool(v.get("destination_carries_data", False)),
                )
        # every variant was conditional and none matched: fall back to the
        # conservative default rather than silently treating it as harmless
        d = self.default
        return Role(d.reads, d.writes, f"{self.name}:{key}:no-variant", True)

    def _holds(self, cond: dict | None, args: dict, empty: bool = True) -> bool:
        if not cond:
            return empty
        for key, patterns in cond.items():
            value = _FMT.format(key, **args) if "{" in key else args.get(key, "")
            if not _glob_any(value, self._expand(patterns)):
                return False
        return True

    def _expand(self, patterns) -> list:
        patterns = patterns if isinstance(patterns, list) else [patterns]
        out = []
        for p in patterns:
            if isinstance(p, str) and p.startswith("$"):
                out.extend(self.vars.get(p[1:]) or [])
            else:
                out.append(p)
        return out
