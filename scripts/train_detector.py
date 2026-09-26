"""
Fine-tune the Layer-1 tool-output injection detector.  Kaggle / Colab (free T4).

Base model: Laya is ModernBERT-large + a custom decision head. We fine-tune a
sequence-classification head on that same ModernBERT-large backbone, which is the
robust, portable path (the custom head isn't needed for binary detection). Set
BASE to the Laya checkpoint to initialize from its weights, or to
answerdotai/ModernBERT-large for a clean backbone — the notebook tries Laya first
and falls back automatically.

Upload data/injection_train.jsonl + data/injection_test.jsonl as a Kaggle dataset,
then run. Exports an ONNX model for fast on-device (CPU) inference in the gateway.

    pip install -U transformers datasets accelerate scikit-learn onnx onnxruntime
"""
import json
import numpy as np

BASE_CANDIDATES = ["convaiinnovations/laya", "answerdotai/ModernBERT-large"]
TRAIN = "data/injection_train.jsonl"
TEST = "data/injection_test.jsonl"
OUT = "laya-injection-detector"
MAXLEN = 512


def load_jsonl(path):
    return [json.loads(l) for l in open(path)]


def main():
    from datasets import Dataset
    from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                              TrainingArguments, Trainer, DataCollatorWithPadding)
    from sklearn.metrics import f1_score, recall_score, precision_score

    base = None
    tok = None
    for cand in BASE_CANDIDATES:
        try:
            tok = AutoTokenizer.from_pretrained(cand)
            model = AutoModelForSequenceClassification.from_pretrained(
                cand, num_labels=2, trust_remote_code=True)
            base = cand
            break
        except Exception as e:  # noqa: BLE001
            print(f"could not init from {cand}: {type(e).__name__}: {e}")
    if base is None:
        raise SystemExit("no usable base model")
    print("using base:", base)

    def prep(rows):
        ds = Dataset.from_list([{"text": r["text"], "label": r["label"]} for r in rows])
        return ds.map(lambda b: tok(b["text"], truncation=True, max_length=MAXLEN),
                      batched=True)

    train_ds, test_ds = prep(load_jsonl(TRAIN)), prep(load_jsonl(TEST))
    test_rows = load_jsonl(TEST)
    hard_idx = [i for i, r in enumerate(test_rows) if r["hard_negative"]]

    def compute(p):
        pred = np.argmax(p.predictions, axis=1)
        labels = p.label_ids
        hn_fp = np.mean([pred[i] == 1 for i in hard_idx]) if hard_idx else 0.0
        return {
            "f1": f1_score(labels, pred),
            "detection_rate": recall_score(labels, pred),
            "precision": precision_score(labels, pred),
            "hard_neg_fp_rate": float(hn_fp),
        }

    args = TrainingArguments(
        output_dir=OUT, num_train_epochs=4, per_device_train_batch_size=16,
        per_device_eval_batch_size=32, learning_rate=2e-5, weight_decay=0.01,
        eval_strategy="epoch", save_strategy="epoch", logging_steps=20,
        load_best_model_at_end=True, metric_for_best_model="f1", fp16=True,
        report_to="none")
    trainer = Trainer(
        model=model, args=args, train_dataset=train_ds, eval_dataset=test_ds,
        tokenizer=tok, data_collator=DataCollatorWithPadding(tok),
        compute_metrics=compute)
    trainer.train()
    print("FINAL:", trainer.evaluate())

    trainer.save_model(OUT)
    tok.save_pretrained(OUT)

    # Export ONNX (int8) for fast CPU inference inside the gateway.
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        ort = ORTModelForSequenceClassification.from_pretrained(OUT, export=True)
        ort.save_pretrained(OUT + "-onnx")
        print("exported ONNX ->", OUT + "-onnx")
    except Exception as e:  # noqa: BLE001
        print("ONNX export skipped:", e)


if __name__ == "__main__":
    main()
