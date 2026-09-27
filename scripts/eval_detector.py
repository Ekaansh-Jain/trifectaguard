"""
Rigorous evaluation of the saved detector (detector-real/) on EXTERNAL held-out
data the model never trained on.

Sources:
  - neuralchemy/Prompt-injection-dataset (core/test): fully unseen dataset, has
    per-category labels and tricky benign (legit uses of injection trigger words)
  - deepset/prompt-injections (test split): held-out from a trained source
  - xTRam1/safe-guard-prompt-injection (test split): held-out from a trained source

Reports precision / recall(detection) / F1 / false-positive-rate at scale, per
source and per category, so the 15-item hand-set is no longer the basis of any
claim.

  python scripts/eval_detector.py            # full
  python scripts/eval_detector.py --cap 800  # cap rows per source
"""
import argparse
from collections import defaultdict

import numpy as np
import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_DIR = "detector-real"
MAXLEN = 160


def load_rows(cap):
    rows = []  # (text, label, source, category)

    def add(ds_id, config, split, cap_n, cat_key=None):
        try:
            d = load_dataset(ds_id, config, split=split, streaming=True) if config \
                else load_dataset(ds_id, split=split, streaming=True)
        except Exception as e:
            print(f"skip {ds_id}: {type(e).__name__}: {str(e)[:70]}")
            return
        n = 0
        for r in d:
            t = r.get("text")
            lab = r.get("label")
            if not t or lab is None or len(t) < 6:
                continue
            cat = (r.get(cat_key) if cat_key else None) or ("injection" if int(lab) == 1 else "benign")
            rows.append((t, int(lab), ds_id.split("/")[-1], cat))
            n += 1
            if n >= cap_n:
                break
        print(f"loaded {ds_id} [{split}]: {n}")

    add("neuralchemy/Prompt-injection-dataset", "core", "test", cap, cat_key="category")
    add("deepset/prompt-injections", None, "test", cap)
    add("xTRam1/safe-guard-prompt-injection", None, "test", cap)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=1500)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR).eval()
    dev = "mps" if torch.backends.mps.is_available() else "cpu"
    model.to(dev)

    rows = load_rows(args.cap)
    texts = [r[0] for r in rows]
    labels = np.array([r[1] for r in rows])

    preds = []
    for i in range(0, len(texts), 16):
        enc = tok(texts[i:i+16], truncation=True, max_length=MAXLEN,
                  padding=True, return_tensors="pt").to(dev)
        with torch.no_grad():
            preds.extend(np.argmax(model(**enc).logits.cpu().numpy(), axis=1))
    preds = np.array(preds)

    def metrics(mask):
        y, p = labels[mask], preds[mask]
        tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
        tn = int(((p == 0) & (y == 0)).sum()); fn = int(((p == 0) & (y == 1)).sum())
        rec = tp / (tp + fn) if tp + fn else None
        prec = tp / (tp + fp) if tp + fp else None
        fpr = fp / (fp + tn) if fp + tn else None
        f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
        return {"n": int(mask.sum()), "pos": tp + fn, "neg": tn + fp,
                "detection": rec, "precision": prec, "fpr": fpr, "f1": f1}

    def fmt(m):
        def g(x): return f"{x:.3f}" if isinstance(x, float) else " -- "
        return (f"n={m['n']:5d} pos={m['pos']:5d} neg={m['neg']:5d} | "
                f"detection={g(m['detection'])} fpr={g(m['fpr'])} "
                f"precision={g(m['precision'])} f1={g(m['f1'])}")

    print("\n==== OVERALL (external held-out) ====")
    print(fmt(metrics(np.ones(len(rows), bool))))

    print("\n==== BY SOURCE ====")
    srcs = sorted(set(r[2] for r in rows))
    for s in srcs:
        mask = np.array([r[2] == s for r in rows])
        print(f"{s:34s} {fmt(metrics(mask))}")

    print("\n==== neuralchemy BY CATEGORY ====")
    cats = defaultdict(list)
    for i, r in enumerate(rows):
        if r[2] == "Prompt-injection-dataset":
            cats[r[3]].append(i)
    for c in sorted(cats, key=lambda c: -len(cats[c])):
        idx = np.array(cats[c])
        mask = np.zeros(len(rows), bool); mask[idx] = True
        print(f"{c:26s} {fmt(metrics(mask))}")


if __name__ == "__main__":
    main()
