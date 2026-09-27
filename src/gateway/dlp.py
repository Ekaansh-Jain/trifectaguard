"""
Secret discovery and leak checks.

`find_secrets` pulls credential values out of text the agent read from a private
source; `leaked` checks whether any of them is about to leave in a sink call —
verbatim or under a cheap disguise (base64, hex, URL-encoding, reversal, spaced
out). A model can still paraphrase or split a secret, which is why the flow
rules, not this check, are the primary guarantee.
"""
import base64
import binascii
import re
from urllib.parse import unquote

SECRET_NAME = re.compile(r"(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH)", re.I)
# NAME=value, NAME: value, "name": "value"
ASSIGNMENT = re.compile(
    r"""["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"',;]{8,})"""
)
KNOWN_FORMATS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),  # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic style keys
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google API key
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]{16,}"),
]
MIN_LEN = 8

_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")


def find_secrets(text: str) -> set[str]:
    found = set()
    for name, value in ASSIGNMENT.findall(text or ""):
        if SECRET_NAME.search(name) and len(value) >= MIN_LEN:
            found.add(value)
    for pattern in KNOWN_FORMATS:
        found.update(m.group(0) for m in pattern.finditer(text or ""))
    return found


def _decodings(blob: str):
    """The outgoing text plus every cheap decoding of it."""
    yield blob
    yield unquote(blob)
    yield blob[::-1]
    for run in _B64_RUN.findall(blob):
        for shift in range(4):  # the secret may sit mid-way through a b64 block
            chunk = run[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % 4]
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    yield decode(chunk).decode("utf-8", "ignore")
                except (binascii.Error, ValueError):
                    pass
    for run in _HEX_RUN.findall(blob):
        try:
            yield bytes.fromhex(run).decode("utf-8", "ignore")
        except ValueError:
            pass


def leaked(blob: str, secrets: set[str]) -> str | None:
    """Return the secret that appears (possibly encoded) in blob, else None."""
    if not secrets:
        return None
    squeezed = {s: _squeeze(s) for s in secrets}
    for text in _decodings(blob):
        flat = _squeeze(text)
        for s in secrets:
            # squeezing catches "s e c r e t" / "s-e-c-r-e-t"; require a long
            # enough core that punctuation-only differences can't collide
            if s in text or (len(squeezed[s]) >= MIN_LEN and squeezed[s] in flat):
                return s
    return None


def _squeeze(text: str) -> str:
    return re.sub(r"[\s.\-_:/|,]", "", text)
