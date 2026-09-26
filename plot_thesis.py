"""
Thesis figure -> results/thesis.png

One question: of exfiltration attacks that reach the agent, what fraction does
each defense actually PREVENT? A detection-based defense prevents an attack only
if it detects the injection, so its prevention rate = its detection rate. The
deterministic gateway blocks the dangerous data flow regardless of phrasing.
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

INK, MUTED = "#1a1a1a", "#6b6b6b"
DETECT = "#c0392b"   # detection-based (unreliable) — red family
FLOW = "#1f8a4c"     # flow-based (deterministic) — green accent

# (label, prevented %, color, the catch)
ROWS = [
    ("Prompt Guard 2 (86M)\ndetection-based", 14, DETECT, "misses 86% of injections"),
    ("Our fine-tuned detector\ndetection-based", 33, DETECT, "OOD ceiling; learns cues, not intent"),
    ("gpt-oss-safeguard 20B\ndetection-based (LLM)", 74, DETECT, "~2.5s per tool call — too slow"),
    ("LLM judge gpt-oss-20B\ndetection-based (LLM)", 76, DETECT, "flags 35% of benign; ~2.4s"),
    ("MCP taint gateway\nflow-based (deterministic)", 100, FLOW, "phrasing-independent, ~0ms overhead"),
]


def main():
    ROWS.sort(key=lambda r: r[1])
    labels = [r[0] for r in ROWS]
    vals = [r[1] for r in ROWS]
    colors = [r[2] for r in ROWS]
    notes = [r[3] for r in ROWS]
    y = range(len(ROWS))

    fig, ax = plt.subplots(figsize=(11.5, 5.2))
    ax.barh(list(y), vals, color=colors, height=0.6, zorder=3)
    NOTE_X = 112  # aligned annotation column to the right of all bars
    for i, (v, note) in enumerate(zip(vals, notes)):
        ax.text(v + 1.5, i, f"{v}%", va="center", ha="left", fontsize=12,
                fontweight="bold", color=INK)
        ax.text(NOTE_X, i, note, va="center", ha="left", fontsize=9,
                color=MUTED, style="italic")

    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9.5, color=INK)
    ax.set_xlim(0, 210)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0", "25", "50", "75", "100%"], color=MUTED, fontsize=9)
    ax.tick_params(length=0)
    for sp in ["top", "right", "left"]:
        ax.spines[sp].set_visible(False)
    ax.spines["bottom"].set_color("#dddddd")
    ax.set_axisbelow(True)
    ax.xaxis.grid(True, color="#eeeeee", zorder=0)
    ax.axvline(108, color="#dddddd", lw=1, zorder=1)

    ax.set_title("Of exfiltration attacks that reach the agent, how many are actually prevented?",
                 fontsize=13, fontweight="bold", color=INK, pad=14, loc="left")
    fig.text(0.01, -0.02,
             "Detection-based defenses prevent an attack only when they detect it. "
             "Learned detectors cap out and LLM judges are slow / over-flag. The "
             "deterministic taint gateway blocks the data flow regardless of phrasing.",
             fontsize=8.5, color=MUTED)

    fig.savefig("results/thesis.png", dpi=200, bbox_inches="tight", facecolor="white")
    print("wrote results/thesis.png")


if __name__ == "__main__":
    main()
