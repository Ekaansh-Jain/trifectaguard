"""
Held-out-FAMILY evaluation = true novel-family transfer.

A model trained with HOLDOUT_FAMILIES excluded never saw those attack styles.
This generates attacks of exactly those families and measures detection — i.e.
can the detector catch a whole attack STYLE it never trained on (vs. the earlier
within-style generalization)?

  DETECTOR=detector-holdout FAMILIES=stego,fake_tool python scripts/holdout_eval.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from data.attack_styles import STYLE_FAMILIES, EXTRA_PAYLOADS
from data.seeds import PAYLOADS

MODEL_DIR = os.environ.get("DETECTOR", "detector-holdout")
FAMILIES = [x for x in os.environ.get("FAMILIES", "stego,fake_tool").split(",") if x]
MAXLEN = 160


def gen(fam):
    payloads = []
    for i in set(PAYLOADS) | set(EXTRA_PAYLOADS):
        payloads += list(PAYLOADS.get(i, [])) + list(EXTRA_PAYLOADS.get(i, []))
    out = []
    for tmpl in STYLE_FAMILIES[fam]:
        for p in payloads:
            out.append(tmpl.format(p=p))
    return out


def main():
    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).eval()
    dev = "mps" if torch.backends.mps.is_available() else "cpu"
    model.to(dev)

    def detect(texts):
        out = []
        for i in range(0, len(texts), 16):
            enc = tok(texts[i:i+16], truncation=True, max_length=MAXLEN,
                      padding=True, return_tensors="pt").to(dev)
            with torch.no_grad():
                out.extend(np.argmax(model(**enc).logits.cpu().numpy(), axis=1))
        return np.array(out)

    print(f"model: {MODEL_DIR}   held-out families: {FAMILIES}\n")
    print(f"{'family (never trained)':24s} n     detection")
    for fam in FAMILIES:
        texts = gen(fam)
        det = float(np.mean(detect(texts) == 1))
        print(f"{fam:24s} {len(texts):4d}  {det:.2f}")


if __name__ == "__main__":
    main()
