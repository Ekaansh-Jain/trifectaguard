"""
Layer-1 injection detector for the gateway — the fine-tuned ModernBERT model.

Scans tool OUTPUTS (issue bodies, fetched pages, emails) for injection as they
are ingested. Complements the deterministic gate: the gate blocks the exfil data
flow; the detector flags manipulation/non-exfil attacks (SEO, output-manipulation,
destructive) that never touch a sensitive file and so slip the trifecta rule.

Lazy singleton so importing the gateway is cheap; the 600MB model loads only when
detection is enabled (GATEWAY_DETECT=1 or an explicit path).
"""
import os

_MODEL = None
_TOK = None
_DEVICE = None
DEFAULT_PATH = os.environ.get("DETECTOR_PATH", "detector-final")
MAXLEN = 128
MAX_CHARS = 60_000  # chunked mode: cap work per tool result


def _lazy_load(path):
    global _MODEL, _TOK, _DEVICE
    if _MODEL is not None:
        return
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    _TOK = AutoTokenizer.from_pretrained(path)
    _MODEL = AutoModelForSequenceClassification.from_pretrained(path).eval()
    _DEVICE = "mps" if torch.backends.mps.is_available() else "cpu"
    _MODEL.to(_DEVICE)


def make_detector(path=DEFAULT_PATH, chunked=False):
    """Return a scan(text)->bool callable, or None if the model can't load.

    chunked=True scans the whole text in overlapping MAXLEN-token windows instead
    of only the first MAXLEN tokens, so an injection at the bottom of a long page
    is still seen. (It does not fix the model's sensitivity to benign context
    inside a window.)"""
    try:
        _lazy_load(path)
    except Exception as e:  # noqa: BLE001 — no model -> gate runs without Layer 1
        print(f"[detector] disabled ({type(e).__name__}: {str(e)[:80]})")
        return None
    import numpy as np
    import torch

    def scan(text: str) -> bool:
        if not text:
            return False
        enc = _TOK(text[:4000], truncation=True, max_length=MAXLEN,
                   return_tensors="pt").to(_DEVICE)
        with torch.no_grad():
            logits = _MODEL(**enc).logits.cpu().numpy()
        return bool(np.argmax(logits, axis=1)[0] == 1)

    def scan_chunked(text: str) -> bool:
        if not text:
            return False
        ids = _TOK(text[:MAX_CHARS], add_special_tokens=False)["input_ids"]
        window, stride = MAXLEN - 2, (MAXLEN - 2) // 2
        starts = range(0, max(len(ids) - stride, 1), stride)
        chunks = [_TOK.decode(ids[s:s + window]) for s in starts]
        for i in range(0, len(chunks), 16):
            enc = _TOK(chunks[i:i + 16], truncation=True, max_length=MAXLEN,
                       padding=True, return_tensors="pt").to(_DEVICE)
            with torch.no_grad():
                logits = _MODEL(**enc).logits.cpu().numpy()
            if (np.argmax(logits, axis=1) == 1).any():
                return True
        return False

    return scan_chunked if chunked else scan
