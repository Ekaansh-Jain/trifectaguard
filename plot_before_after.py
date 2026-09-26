"""Paired heatmap: leak rate without vs with the gateway -> results/before_after.png

Left panel reads results/summary.json (direct), right reads
results/summary_gateway.json. Only models present in BOTH are shown, so it is a
fair like-for-like before/after.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SCENS = ["issue_naive", "issue_authority", "web_hidden"]
SCEN_LABELS = ["“ignore all\ninstructions”", "“maintainer /\nCI policy”",
               "hidden HTML\nin web page"]
CMAP = LinearSegmentedColormap.from_list(
    "leak", ["#f7f4f2", "#f4c9b6", "#e8825b", "#c0392b", "#7d1f16"])
INK, MUTED = "#1a1a1a", "#6b6b6b"


def grid(summary, models):
    rates, annots = [], []
    for m in models:
        rr, aa = [], []
        for s in SCENS:
            c = summary.get(m, {}).get(s, {})
            n, k = c.get("total", 0), c.get("leaks", 0)
            rr.append(k / n if n else float("nan"))
            aa.append(f"{k}/{n}" if n else "n/a")
        rates.append(rr); annots.append(aa)
    return rates, annots


def panel(ax, rates, annots, models, title):
    im = ax.imshow(rates, cmap=CMAP, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(SCENS))); ax.set_xticklabels(SCEN_LABELS, fontsize=8.5, color=INK)
    ax.set_yticks(range(len(models))); ax.set_yticklabels(models, fontsize=9.5, color=INK)
    ax.tick_params(length=0)
    for sp in ax.spines.values(): sp.set_visible(False)
    ax.set_xticks([x - 0.5 for x in range(len(SCENS) + 1)], minor=True)
    ax.set_yticks([y - 0.5 for y in range(len(models) + 1)], minor=True)
    ax.grid(which="minor", color="white", linewidth=2); ax.tick_params(which="minor", length=0)
    for i in range(len(models)):
        for j in range(len(SCENS)):
            r, txt = rates[i][j], annots[i][j]
            col = MUTED if txt == "n/a" else ("white" if r >= 0.5 else INK)
            ax.text(j, i, txt, ha="center", va="center", fontsize=11, fontweight="bold", color=col)
    ax.set_title(title, fontsize=12, fontweight="bold", color=INK, pad=10)
    return im


def main():
    direct = json.loads(Path("results/summary.json").read_text())
    gw = json.loads(Path("results/summary_gateway.json").read_text())
    models = [m for m in direct if m in gw]
    if not models:
        raise SystemExit("no overlapping models between the two summaries")

    rd, ad = grid(direct, models)
    rg, ag = grid(gw, models)

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(12, 0.7 * len(models) + 2.4))
    panel(axL, rd, ad, models, "WITHOUT gateway")
    im = panel(axR, rg, ag, models, "WITH gateway")
    axR.set_yticklabels([])

    fig.suptitle("Secret-leak rate — the gateway blocks exfiltration deterministically",
                 fontsize=14, fontweight="bold", color=INK, x=0.5, y=1.02)
    fig.text(0.5, -0.02,
             "Same models, same attacks. Leak = fake secret actually delivered to a "
             "sink. The gateway blocks the sink regardless of the model.",
             fontsize=8.5, color=MUTED, ha="center")
    cbar = fig.colorbar(im, ax=[axL, axR], fraction=0.03, pad=0.02)
    cbar.set_ticks([0, 0.5, 1.0]); cbar.set_ticklabels(["0%", "50%", "100%"])
    cbar.ax.tick_params(length=0, labelsize=8, colors=MUTED); cbar.outline.set_visible(False)

    fig.savefig("results/before_after.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote results/before_after.png")


if __name__ == "__main__":
    main()
