"""
Build the tool-output injection dataset -> data/injection_{train,test}.jsonl

Row: {text, label(0/1), intent, hard_negative(bool), family, split}

Balanced (~50/50) with a large hard-negative fraction. Generalization split:
whole attack families are held out of TRAIN so the test set measures transfer:
  - 2 wrappers (framings) are test-only
  - the last payload of each intent is test-only
Benign + hard-negatives are stratified into train/test by hash so both classes
are well represented on each side (needed to measure false-positive rate).
"""
import hashlib
import json
import random
from pathlib import Path

from data.seeds import (PAYLOADS, WRAPPERS, gen_benign, gen_hard_negatives)

RNG = random.Random(7)
TEST_WRAPPERS = set(WRAPPERS[-2:])

# target sizes (roughly balanced: ~50% injection, and within benign ~45% hard-neg)
N_BENIGN = 380
N_HARDNEG = 320


def _embed(carrier: str, injected: str, where: str) -> str:
    if where == "start":
        return f"{injected}\n\n{carrier}"
    if where == "end":
        return f"{carrier}\n\n{injected}"
    mid = len(carrier) // 2
    cut = carrier.find(" ", mid)
    cut = cut if cut != -1 else mid
    return f"{carrier[:cut]} {injected} {carrier[cut:]}"


def _h(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest(), 16)


def build():
    rows = []
    carriers = gen_benign(120, RNG)  # hosts to embed injections in

    # --- injections ---------------------------------------------------------
    for intent, payloads in PAYLOADS.items():
        for pi, payload in enumerate(payloads):
            held_payload = pi == len(payloads) - 1
            for wrapper in WRAPPERS:
                held_wrapper = wrapper in TEST_WRAPPERS
                injected = wrapper.format(p=payload)
                for carrier in RNG.sample(carriers, 2):
                    where = RNG.choice(["start", "middle", "end"])
                    text = _embed(carrier, injected, where)
                    split = "test" if (held_payload or held_wrapper) else "train"
                    rows.append({"text": text, "label": 1, "intent": intent,
                                 "hard_negative": False,
                                 "family": f"{intent}|{'heldP' if held_payload else 'seenP'}"
                                           f"|{'heldW' if held_wrapper else 'seenW'}",
                                 "split": split})

    # --- benign (label 0), stratified by hash ------------------------------
    for text in gen_benign(N_BENIGN, RNG):
        rows.append({"text": text, "label": 0, "intent": "none",
                     "hard_negative": False, "family": "benign",
                     "split": "test" if _h(text) % 5 == 0 else "train"})

    # --- hard negatives (label 0), stratified by hash ----------------------
    for text in gen_hard_negatives(N_HARDNEG, RNG):
        rows.append({"text": text, "label": 0, "intent": "none",
                     "hard_negative": True, "family": "hard_negative",
                     "split": "test" if _h(text) % 5 == 0 else "train"})

    seen, uniq = set(), []
    for r in rows:
        if r["text"] not in seen:
            seen.add(r["text"]); uniq.append(r)
    RNG.shuffle(uniq)
    return uniq


def _stats(part):
    pos = sum(r["label"] for r in part)
    hn = sum(r["hard_negative"] for r in part)
    return f"{len(part):4d} rows | {pos:4d} inj / {len(part)-pos:4d} benign " \
           f"({hn} hard-neg)"


def main():
    rows = build()
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    Path("data").mkdir(exist_ok=True)
    for name, part in [("train", train), ("test", test)]:
        with open(f"data/injection_{name}.jsonl", "w") as f:
            for r in part:
                f.write(json.dumps(r) + "\n")
    print("TRAIN:", _stats(train))
    print("TEST :", _stats(test))
    print("wrote data/injection_train.jsonl and data/injection_test.jsonl")


if __name__ == "__main__":
    main()
