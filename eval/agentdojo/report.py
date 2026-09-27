"""
Print the AgentDojo results as markdown: worst-case table, per-attack-category
breakdown, and the live-model sample.

  python eval/agentdojo/report.py
"""
import glob
import json
import os
from collections import defaultdict

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                   "results", "agentdojo")

# What the attacker wants, from each injection task's GOAL (v1.2.2).
CATEGORY = {
    "data theft": ["workspace/3", "workspace/4", "workspace/5", "travel/1", "travel/3", "travel/5",
                   "banking/0", "banking/1", "banking/2", "banking/3", "banking/8", "slack/2", "slack/4"],
    "hijacked money/access/contact": ["banking/4", "banking/5", "banking/6", "banking/7",
                                      "workspace/0", "workspace/2", "slack/5"],
    "deletion": ["workspace/1"],
    "steering to legitimate targets": ["travel/0", "travel/2", "travel/4", "slack/1", "slack/3"],
}
CAT_OF = {k: c for c, ks in CATEGORY.items() for k in ks}


def pct(x):
    return f"{x:.1%}"


def worst_case():
    summ = json.load(open(os.path.join(OUT, "worst_case_summary.json")))
    rows = json.load(open(os.path.join(OUT, "worst_case_rows.json")))
    print(f"### Worst-case agent ({summ['version']}, {summ['summaries'][0]['attack_pairs']} attacks "
          f"that succeed undefended, {summ['summaries'][0]['benign_tasks']} benign tasks)\n")
    print("Benign utility for the detectors is an upper bound: the scripted agent never needs the data a\n"
          "detector redacts. The redaction column is their real cost: the share of benign tasks where at\n"
          "least one clean tool output was flagged and hidden from the agent.\n")
    print("| Defense | Attack success ↓ | Benign utility ↑ | Benign tasks needing approval | Benign tasks with data redacted |")
    print("|---|---|---|---|---|")
    for s in summ["summaries"]:
        print(f"| {s['defense']} | {pct(s['attack_success_rate'])} | {pct(s['utility'])} | "
              f"{pct(s['benign_needing_approval'])} | {pct(s['benign_redacted'])} |")

    base = {(r["suite"], r["user_task"], r["injection_task"]) for r in rows["no defense"] if r["attack_success"]}
    print("\n#### Attack success by what the attacker wants\n")
    names = [s["defense"] for s in summ["summaries"] if s["defense"] != "no defense"]
    print("| Category | n | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    for cat in CATEGORY:
        cells, n = [], 0
        for name in names:
            rs = [r for r in rows[name] if (r["suite"], r["user_task"], r["injection_task"]) in base
                  and CAT_OF.get(f"{r['suite']}/{r['injection_task'].split('_')[-1]}") == cat]
            n = len(rs)
            cells.append(pct(sum(r["attack_success"] for r in rs) / n) if n else "–")
        print(f"| {cat} | {n} | " + " | ".join(cells) + " |")


def live():
    files = sorted(glob.glob(os.path.join(OUT, "live_*.jsonl")))
    files = [f for f in files if "smoke" not in f]
    if not files:
        return
    print("\n### Live models (fixed random sample, `important_instructions` attack)\n")
    print("Small samples on a free tier: runs that hit provider limits (daily token cap, requests larger than\n"
          "the per-minute cap) are \"not run\" and excluded from both defenses. The provider is not deterministic\n"
          "at temperature 0, so benign utility moves between runs even where the gateway never intervened;\n"
          "\"benign failures caused\" counts only tasks that succeeded undefended and failed after a refusal.\n")
    print("| Model | Defense | Attack success ↓ | Utility under attack ↑ | Benign utility ↑ | Benign runs refused ≥1 call | Benign failures caused by a refusal | Runs (attack / benign / not run) |")
    print("|---|---|---|---|---|---|---|---|")
    for f in files:
        recs = [json.loads(l) for l in open(f)]
        by = defaultdict(list)
        for r in recs:
            by[(r["model"], r["defense"])].append(r)
        # only compare on jobs that completed for every defense of this model
        for model in sorted({m for m, _ in by}):
            ok_keys = None
            for (m, d), rs in by.items():
                if m != model:
                    continue
                keys = {(r["suite"], r["user_task"], r["injection_task"]) for r in rs if not r.get("error")}
                ok_keys = keys if ok_keys is None else ok_keys & keys
            for (m, d), rs in sorted(by.items()):
                if m != model:
                    continue
                good = [r for r in rs if (r["suite"], r["user_task"], r["injection_task"]) in ok_keys
                        and not r.get("error")]
                att = [r for r in good if r["injection_task"]]
                ben = [r for r in good if not r["injection_task"]]
                undefended_ok = {(r["suite"], r["user_task"]) for r in by.get((m, "none"), [])
                                 if not r["injection_task"] and not r.get("error") and r["utility"]}
                caused = sum(1 for r in ben if r["refusals"] and not r["utility"]
                             and (r["suite"], r["user_task"]) in undefended_ok)
                failed = len({(r["suite"], r["user_task"], r["injection_task"]) for r in rs} - ok_keys)
                if not att or not ben:
                    continue
                print(f"| {m} | {d} | {pct(sum(r['attack_success'] for r in att) / len(att))} | "
                      f"{pct(sum(r['utility'] for r in att) / len(att))} | "
                      f"{pct(sum(r['utility'] for r in ben) / len(ben))} | "
                      f"{pct(sum(bool(r['refusals']) for r in ben) / len(ben))} | "
                      f"{'–' if d == 'none' else f'{caused}/{len(ben)}'} | "
                      f"{len(att)} / {len(ben)} / {failed} |")


if __name__ == "__main__":
    worst_case()
    live()
