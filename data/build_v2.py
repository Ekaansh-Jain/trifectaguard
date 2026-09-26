"""
Build the v2 injection dataset -> data/injection_v2_{train,test}.jsonl

Big diversity upgrade over v1:
  - attacks span 10 style families (data.attack_styles) x many payloads x carriers,
    plus base64 and non-English transforms
  - benign = LLM-generated diverse samples (data/benign_aug.jsonl) + templates
Split is by content hash (80/20) so both classes are well represented; the
hand-written OOD set (scripts/kaggle_eval_ood.py) stays a separate frozen test.
"""
import hashlib
import json
import random
from pathlib import Path

from data.seeds import PAYLOADS, gen_benign, gen_hard_negatives
from data.attack_styles import (STYLE_FAMILIES, EXTRA_PAYLOADS, b64_variant,
                                foreign_variant)

RNG = random.Random(11)


def all_payloads():
    out = {}
    for intent, ps in PAYLOADS.items():
        out[intent] = list(ps) + list(EXTRA_PAYLOADS.get(intent, []))
    return out


def _embed(carrier, injected, where):
    if where == "start":
        return f"{injected}\n\n{carrier}"
    if where == "end":
        return f"{carrier}\n\n{injected}"
    mid = len(carrier) // 2
    cut = carrier.find(" ", mid); cut = cut if cut != -1 else mid
    return f"{carrier[:cut]} {injected} {carrier[cut:]}"


def _h(s):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)


def build():
    rows = []
    carriers = gen_benign(140, RNG)
    payloads = all_payloads()

    # --- attacks: styles x payloads x carriers ------------------------------
    for family, templates in STYLE_FAMILIES.items():
        for tmpl in templates:
            for intent, ps in payloads.items():
                for payload in RNG.sample(ps, min(4, len(ps))):
                    injected = tmpl.format(p=payload)
                    carrier = RNG.choice(carriers)
                    text = _embed(carrier, injected, RNG.choice(["start", "middle", "end"]))
                    rows.append({"text": text, "label": 1, "intent": intent,
                                 "hard_negative": False, "family": family})

    # --- transform variants: base64 + non-English on exfil/payment/destructive
    for intent in ["exfiltration", "payment", "destructive"]:
        for payload in payloads[intent]:
            for transform in (b64_variant, foreign_variant):
                injected = transform(payload)
                carrier = RNG.choice(carriers)
                text = _embed(carrier, injected, RNG.choice(["start", "end"]))
                rows.append({"text": text, "label": 1, "intent": intent,
                             "hard_negative": False,
                             "family": "b64" if transform is b64_variant else "foreign"})

    n_attacks = len(rows)

    # --- benign: LLM-generated + templates ---------------------------------
    aug = Path("data/benign_aug.jsonl")
    if aug.exists():
        for l in open(aug):
            r = json.loads(l)
            rows.append({"text": r["text"], "label": 0, "intent": "none",
                         "hard_negative": r.get("hard_negative", False),
                         "family": "llm_benign"})
    # top up with templates to roughly balance
    need = max(0, n_attacks - (len(rows) - n_attacks))
    for text in gen_benign(need // 2 + 40, RNG):
        rows.append({"text": text, "label": 0, "intent": "none",
                     "hard_negative": False, "family": "tmpl_benign"})
    for text in gen_hard_negatives(need // 2 + 40, RNG):
        rows.append({"text": text, "label": 0, "intent": "none",
                     "hard_negative": True, "family": "tmpl_hardneg"})

    # de-dup + split by hash
    seen, uniq = set(), []
    for r in rows:
        if r["text"] not in seen:
            seen.add(r["text"])
            r["split"] = "test" if _h(r["text"]) % 5 == 0 else "train"
            uniq.append(r)
    RNG.shuffle(uniq)
    return uniq


def main():
    rows = build()
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    for name, part in [("train", train), ("test", test)]:
        with open(f"data/injection_v2_{name}.jsonl", "w") as f:
            for r in part:
                f.write(json.dumps(r) + "\n")

    def stat(p):
        pos = sum(r["label"] for r in p)
        hn = sum(r["hard_negative"] for r in p)
        return f"{len(p)} rows | {pos} inj / {len(p)-pos} benign ({hn} hard-neg)"
    print("TRAIN:", stat(train))
    print("TEST :", stat(test))
    fams = {}
    for r in rows:
        if r["label"] == 1:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
    print("attack families:", fams)


if __name__ == "__main__":
    main()
