"""
Generate diverse BENIGN + hard-negative samples via Groq (free), cached to
data/benign_aug.jsonl. LLMs happily write benign text, so this adds the real-
world variety templates can't — the key to a low false-positive rate.
"""
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
C = OpenAI(api_key=os.environ["GROQ_API_KEY"], base_url=os.environ["GROQ_BASE_URL"])
MODEL = "openai/gpt-oss-120b"
OUT = Path("data/benign_aug.jsonl")

SYS = ("You generate realistic BENIGN text samples for training a security "
       "classifier. Output ONLY a JSON array of strings, no prose.")

PROMPTS = [
    ("plain", "Generate 8 varied, realistic GitHub issues, PR descriptions, README snippets, or emails from a software project. Completely ordinary developer content. JSON array of 8 strings."),
    ("hard", "Generate 8 varied, realistic BENIGN developer texts that mention commands, secrets, tokens, .env files, payments, or the word 'ignore' in a LEGITIMATE way — the kind that fools naive keyword filters but contains no instruction aimed at an AI. JSON array of 8 strings."),
    ("hard", "Generate 8 realistic BENIGN texts that describe security procedures, runbooks, or docs that discuss prompt injection / secrets handling defensively (e.g., 'never paste your API key', quoting an attack as an example). No actual instruction to an AI. JSON array of 8 strings."),
    ("hard", "Generate 8 realistic BENIGN support tickets or forum answers containing shell commands like rm, drop table, curl, or chmod used legitimately with normal explanation. JSON array of 8 strings."),
    ("plain", "Generate 8 realistic BENIGN product/web page paragraphs (docs, changelog, marketing, FAQ) with no instruction to an AI. JSON array of 8 strings."),
]


def gen_batch(prompt, temp=0.9):
    r = C.chat.completions.create(
        model=MODEL, temperature=temp, max_tokens=1400,
        messages=[{"role": "system", "content": SYS}, {"role": "user", "content": prompt}])
    txt = r.choices[0].message.content or ""
    s, e = txt.find("["), txt.rfind("]")
    if s == -1 or e == -1:
        return []
    try:
        arr = json.loads(txt[s:e + 1])
        return [x for x in arr if isinstance(x, str) and len(x) > 20]
    except json.JSONDecodeError:
        return []


def main(rounds=6):
    seen = set()
    if OUT.exists():
        for l in open(OUT):
            seen.add(json.loads(l)["text"])
    n_new = 0
    with open(OUT, "a") as f:
        for _ in range(rounds):
            for kind, prompt in PROMPTS:
                try:
                    for s in gen_batch(prompt):
                        if s not in seen:
                            seen.add(s)
                            f.write(json.dumps({"text": s, "label": 0,
                                                "hard_negative": kind == "hard"}) + "\n")
                            f.flush()
                            n_new += 1
                except Exception as e:  # noqa: BLE001
                    print("skip:", type(e).__name__, str(e)[:80])
                time.sleep(1)
            print(f"total benign so far: {len(seen)}")
    print(f"done, {n_new} new, {len(seen)} total in {OUT}")


if __name__ == "__main__":
    main()
