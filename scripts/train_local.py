"""
Local trainer (Apple MPS / CPU) — reuses the real-data pipeline from
kaggle_train_real.py but tuned for a Mac: no fp16 (CUDA-only), MPS batch size,
optional --quick validation run.

  python scripts/train_local.py --quick      # fast sanity run (small, 1 epoch)
  python scripts/train_local.py              # full run
"""
import argparse
import importlib.util
import os

import numpy as np
import torch


def load_pipeline():
    spec = importlib.util.spec_from_file_location(
        "ktr", os.path.join(os.path.dirname(__file__), "kaggle_train_real.py"))
    ktr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ktr)
    return ktr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--cap", type=int, default=6000, help="max rows per source")
    ap.add_argument("--maxlen", type=int, default=128)
    ap.add_argument("--bs", type=int, default=16)
    args = ap.parse_args()

    from torch import nn
    from datasets import Dataset
    from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                              TrainingArguments, Trainer, DataCollatorWithPadding)
    from sklearn.metrics import f1_score, recall_score, precision_score

    ktr = load_pipeline()
    ktr.CAP_PER_SOURCE = 1200 if args.quick else args.cap
    train_rows, test_rows = ktr.build()
    print(f"train={len(train_rows)} test={len(test_rows)} "
          f"train_inj={sum(r['label'] for r in train_rows)}")

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print("device:", device)

    BASE = "answerdotai/ModernBERT-base"
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForSequenceClassification.from_pretrained(BASE, num_labels=2)

    def prep(rows):
        ds = Dataset.from_list(rows)
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=args.maxlen),
                      batched=True)

    train_ds, test_ds = prep(train_rows), prep(test_rows)

    class FocalTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            ce = nn.functional.cross_entropy(out.logits, labels, reduction="none")
            pt = torch.exp(-ce)
            loss = (0.75 * (1 - pt) ** 2.0 * ce).mean()
            return (loss, out) if return_outputs else loss

    def compute(p):
        pred = np.argmax(p.predictions, axis=1)
        return {"f1": f1_score(p.label_ids, pred),
                "detection_rate": recall_score(p.label_ids, pred),
                "precision": precision_score(p.label_ids, pred)}

    targs = TrainingArguments(
        output_dir=os.environ.get("DETECTOR_OUT","detector-real"), num_train_epochs=1 if args.quick else args.epochs,
        per_device_train_batch_size=args.bs, per_device_eval_batch_size=8,
        learning_rate=2e-5, weight_decay=0.01, eval_strategy="no",
        save_strategy="no", logging_steps=25, fp16=False, bf16=False,
        use_cpu=(device == "cpu"), report_to="none")
    tkw = dict(model=model, args=targs, train_dataset=train_ds, eval_dataset=test_ds,
               data_collator=DataCollatorWithPadding(tok), compute_metrics=compute)
    try:
        trainer = FocalTrainer(**tkw, processing_class=tok)
    except TypeError:
        trainer = FocalTrainer(**tkw, tokenizer=tok)

    trainer.train()
    # SAVE first (before eval) so an eval OOM can't lose the trained model
    OUT=os.environ.get("DETECTOR_OUT","detector-real")
    trainer.save_model(OUT); tok.save_pretrained(OUT)
    print(f"saved model to {OUT}/")
    print("HELD-OUT METRICS:", trainer.evaluate())

    # frozen OOD
    model.eval()
    dev = next(model.parameters()).device

    def predict(texts):
        preds = []
        for i in range(0, len(texts), 4):  # small batches to avoid MPS OOM
            enc = tok(texts[i:i+4], truncation=True, max_length=args.maxlen,
                      padding=True, return_tensors="pt").to(dev)
            with torch.no_grad():
                preds.extend(np.argmax(model(**enc).logits.cpu().numpy(), axis=1))
        return np.array(preds)

    ip, bp = predict(ktr.OOD_INJECTIONS), predict(ktr.OOD_BENIGN)
    print(f"\n=== FROZEN OOD (novel styles) ===")
    print(f"OOD detection: {np.mean(ip==1):.2f} ({int(np.sum(ip==1))}/{len(ip)})   "
          f"OOD false-positive: {np.mean(bp==1):.2f} ({int(np.sum(bp==1))}/{len(bp)})")
    print("misses:", [t[:55] for t, p in zip(ktr.OOD_INJECTIONS, ip) if p == 0])
    print("false alarms:", [t[:55] for t, p in zip(ktr.OOD_BENIGN, bp) if p == 1])


if __name__ == "__main__":
    main()
