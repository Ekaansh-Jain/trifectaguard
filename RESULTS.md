# Detector evaluation results

The Layer-1 injection detector, fine-tuned from ModernBERT-base, evaluated on data
it **never trained on**. Trained locally on Apple MPS. "Data beat architecture":
going from ~272 synthetic injections to a diverse real+synthetic corpus took
out-of-distribution detection from 33% to ~85–93% at the same architecture.

## Headline (detector-final)

| Metric | Value | Notes |
|---|---|---|
| External detection | **0.854** | 2,558 examples from datasets never trained on |
| External false-positive rate | **0.013** | ~4.5% on the hardest external benign |
| F1 | 0.912 | |
| Novel-family transfer | **0.90–0.97** | attack styles fully held out of training |
| Evasion robustness | **100%** | zero-width, homoglyph, spacing, leet, base64, **dilution** |

For reference, Prompt Guard 2 scored **0.14** detection on the tool-output task.

## External held-out (neuralchemy + deepset/xTRam1 test splits), n=2,558
- OVERALL: detection 0.854, FPR 0.013, precision 0.979, F1 0.912
- By category (neuralchemy, never trained on): direct_injection 0.77,
  adversarial 0.73, jailbreak 0.70, encoding 0.73, token_smuggling / rag_poisoning
  / multi_turn / instruction_override ~1.0.
- Benign FPR 0.045 on the tricky external benign ("Ignore the noise in this
  signal…" style legitimate uses of trigger words).

## Novel-family transfer (true generalization)
A model trained with `stego`, `fake_tool`, `social_eng` **excluded** still detects
them at 0.94 / 0.90 / 0.97 — it learned "injection-ness," not surface templates.

## Adaptive / evasion (detector-final)
All transforms retained ~100% detection: benign padding, instruction-at-end,
zero-width chars, homoglyphs, letter spacing, leetspeak, base64 wrap. The dilution
evasion that beat the pre-boost model (~25%) is fixed by dilution augmentation.

## Ablation
- **Dilution augmentation:** fixed dilution evasion 75/79% → 100%. Kept.
- **Jailbreak datasets (jackhhao/rubend18):** did not transfer to the external
  jailbreak category and regressed `encoding` + overall. Dropped (behind
  `USE_JAILBREAK=1`).

## Role in the system
The detector is a fast, high-recall **Layer-1 pre-filter**. Its residual (~15% of
novel injections, and genuinely novel families) is caught by the **deterministic
taint gate**; legitimate flows the gate would over-block are rescued by the **LLM
adjudicator** (false-block 20% → 0% in the gateway suite). Detection is unreliable
alone (see the thesis chart); the guarantee is the flow-control layer.

## Reproduce
```bash
python scripts/train_local.py --cap 3000 --epochs 2 --maxlen 128 --bs 8   # train
python scripts/eval_detector.py --cap 1500      # external, per-category
python scripts/adaptive_eval.py --n 200         # evasion
HOLDOUT_FAMILIES=stego,fake_tool,social_eng DETECTOR_OUT=detector-holdout \
  python scripts/train_local.py ...             # then holdout_eval.py
```

## End-to-end system test (scaled: 60 cases, 33 attacks / 27 legit)
Attacks span 4 untrusted sources × 4 sink types × exfil + 4 non-exfil intents
(SEO, output-manipulation, destructive, deterrence).

| Config | catch | false-block | latency |
|---|---|---|---|
| gate only | 0.52 | 0.04 | 0ms |
| + detector (Layer 1) | 1.00 | 0.04 | 23ms |
| + adjudicator (full) | 1.00 | 0.00 | 60ms |

Run everything: `python run_all_tests.py`  →  ALL PASS
(unit taint tests, gateway decision suite, end-to-end system).
