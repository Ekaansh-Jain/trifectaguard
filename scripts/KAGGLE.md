# Training the detector on Kaggle (free GPU)

1. Build the dataset locally and commit it:
   ```bash
   python -m data.build_dataset   # writes data/injection_{train,test}.jsonl
   ```
2. On kaggle.com → **New Notebook** → Settings → Accelerator: **GPU T4**.
3. Add the two JSONL files as a Kaggle Dataset (or upload the repo).
4. In the notebook:
   ```python
   !pip install -U transformers datasets accelerate scikit-learn optimum[onnxruntime]
   # ensure data/injection_{train,test}.jsonl are present at these paths
   ```
   then paste `scripts/train_detector.py` and run it.
5. It fine-tunes the ModernBERT-large backbone (Laya's base) into a binary
   injection detector, prints F1 / detection-rate / hard-negative false-positive
   rate on the held-out families, saves the model, and exports ONNX (int8) for
   fast CPU inference in the gateway.
6. Download `laya-injection-detector-onnx/` and drop it into the repo; the
   gateway's Layer 1 will load it for ~20–30ms on-device scoring.

Compare the resulting numbers against `results/detector_scores.json` (the hosted
baselines: Prompt Guard 2, gpt-oss-safeguard, LLM judge, regex).
