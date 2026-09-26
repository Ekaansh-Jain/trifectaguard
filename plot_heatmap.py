"""Render the leak-rate heatmap from results/summary.json -> results/heatmap.png

Form: model x attack-style matrix, cell = leak rate (sequential magnitude,
light->dark = more leaks). Cells annotated with k/n. Missing/all-error cells
are drawn hatched and labeled n/a.
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

SCEN_LABELS = {
    "issue_naive": "Issue:\n“ignore all\ninstructions”",
    "issue_authority": "Issue:\n“maintainer /\nCI policy”",
    "web_hidden": "Web page:\nhidden HTML\ninstruction",
}

# Single-hue sequential, light surface -> dark danger red. Higher leak = darker.
CMAP = LinearSegmentedColormap.from_list(
    "leak", ["#f7f4f2", "#f4c9b6", "#e8825b", "#c0392b", "#7d1f16"]
)
INK = "#1a1a1a"
MUTED = "#6b6b6b"


def main():
    summary = json.loads(Path("results/summary.json").read_text())
    models = list(summary.keys())
    scens = list(SCEN_LABELS.keys())

    rates = []
    annots = []
    for m in models:
        rrow, arow = [], []
        for s in scens:
            cell = summary[m].get(s, {})
            n, k = cell.get("total", 0), cell.get("leaks", 0)
            if n == 0:
                rrow.append(float("nan"))
                arow.append("n/a")
            else:
                rrow.append(k / n)
                arow.append(f"{k}/{n}")
        rates.append(rrow)
        annots.append(arow)

    fig, ax = plt.subplots(figsize=(7.2, 0.7 * len(models) + 2.2))
    im = ax.imshow(rates, cmap=CMAP, vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(scens)))
    ax.set_xticklabels([SCEN_LABELS[s] for s in scens], fontsize=9, color=INK)
    ax.set_yticks(range(len(models)))
    ax.set_yticklabels(models, fontsize=9.5, color=INK)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)

    # 2px surface gaps between cells
    ax.set_xticks([x - 0.5 for x in range(len(scens) + 1)], minor=True)
    ax.set_yticks([y - 0.5 for y in range(len(models) + 1)], minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", length=0)

    for i, m in enumerate(models):
        for j, s in enumerate(scens):
            r = rates[i][j]
            txt = annots[i][j]
            if txt == "n/a":
                color = MUTED
            else:
                color = "white" if r >= 0.5 else INK
            ax.text(j, i, txt, ha="center", va="center", fontsize=11,
                    fontweight="bold", color=color)

    ax.set_title(
        "Secret-leak rate by model and attack framing",
        fontsize=13, fontweight="bold", color=INK, pad=14, loc="left")
    fig.text(0.01, 0.005,
             "Agent given a benign task; a malicious instruction is hidden in a "
             "tool result. Leak = fake secret sent to a sink tool.",
             fontsize=8, color=MUTED)

    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_ticks([0, 0.5, 1.0])
    cbar.set_ticklabels(["0%", "50%", "100%"])
    cbar.ax.tick_params(length=0, labelsize=8, colors=MUTED)
    cbar.outline.set_visible(False)

    fig.tight_layout(rect=[0, 0.03, 1, 1])
    Path("results").mkdir(exist_ok=True)
    fig.savefig("results/heatmap.png", dpi=200, bbox_inches="tight",
                facecolor="white")
    print("wrote results/heatmap.png")


if __name__ == "__main__":
    main()
