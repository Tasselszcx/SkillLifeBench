"""Generate Figure 2 (ASR heatmap) and RQ3 bar chart for SafeBench paper."""

import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# ── Data ──────────────────────────────────────────────────────────────────────
# 4 complete models (101 entries each); GLM-4.6 pending full rerun
MODELS = [
    ("qwen3-32b",              "results/docker_full_qwen3-32b_120/report.json"),
    ("kimi-k2.5",              "results/docker_full_kimi-k2.5_120/report.json"),
    ("gemini-3-flash",         "results/docker_full_gemini-3-flash-preview_120/report.json"),
    ("claude-sonnet-4-6",      "results/docker_full_claude-sonnet-4-6_120/report.json"),
]
CLASSES = ["A", "B", "C", "D", "E"]
CLASS_LABELS = [
    "A\n(Code-level)",
    "B\n(Interface)",
    "C\n(Runtime)",
    "D\n(Compositional)",
    "E\n(Lifecycle)",
]
MODEL_LABELS = [
    "Qwen3-32B",
    "Kimi-k2.5",
    "Gemini-3-Flash",
    "Claude-Sonnet-4.6",
]

# ── Load ──────────────────────────────────────────────────────────────────────
asr_matrix = []   # shape: [n_models, n_classes]
overall_asr = []

for _, path in MODELS:
    data = json.load(open(path, encoding="utf-8"))
    bc = data["scores"]["by_class"]
    row = [bc.get(c, {}).get("asr", 0.0) for c in CLASSES]
    asr_matrix.append(row)
    overall_asr.append(data["scores"]["security"]["asr"])

asr_matrix = np.array(asr_matrix)  # (4, 5)

# ── Figure 2: ASR Heatmap ─────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 3.6))

im = ax.imshow(asr_matrix, cmap="Blues", vmin=0.0, vmax=1.0, aspect="auto")

# Annotate cells
for i in range(len(MODELS)):
    for j in range(len(CLASSES)):
        val = asr_matrix[i, j]
        color = "white" if val > 0.65 else "black"
        ax.text(j, i, f"{val:.0%}", ha="center", va="center",
                fontsize=11, fontweight="bold", color=color)

ax.set_xticks(range(len(CLASSES)))
ax.set_xticklabels(CLASS_LABELS, fontsize=10)
ax.set_yticks(range(len(MODELS)))
ax.set_yticklabels(MODEL_LABELS, fontsize=10)

# Add overall ASR on right side
ax2 = ax.twinx()
ax2.set_ylim(ax.get_ylim())
ax2.set_yticks(range(len(MODELS)))
ax2.set_yticklabels([f"{v:.1%}" for v in overall_asr], fontsize=10,
                    color="#1D4ED8", fontweight="bold")
ax2.set_ylabel("Overall ASR", fontsize=10, color="#1D4ED8")

cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.01)
cbar.set_label("Attack Success Rate", fontsize=9)
cbar.ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f"{x:.0%}"))

ax.set_title("Figure 2: ASR Heatmap across Models and Vulnerability Classes",
             fontsize=11, pad=10)

plt.tight_layout()
out_heatmap = Path("figures/fig2_asr_heatmap.pdf")
out_heatmap.parent.mkdir(exist_ok=True)
plt.savefig(out_heatmap, dpi=300, bbox_inches="tight")
plt.savefig(out_heatmap.with_suffix(".png"), dpi=200, bbox_inches="tight")
print(f"Saved: {out_heatmap}")
plt.close()

# ── RQ3: D/E vs A/B/C gap bar chart ──────────────────────────────────────────
abc_asr = asr_matrix[:, :3].mean(axis=1)   # mean of A, B, C per model
de_asr  = asr_matrix[:, 3:].mean(axis=1)   # mean of D, E per model
gap     = de_asr - abc_asr

x = np.arange(len(MODELS))
width = 0.3

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))

# Left: grouped bar A/B/C vs D/E
bars1 = ax1.bar(x - width/2, abc_asr, width, label="A/B/C (execute-only)", color="#93C5FD")
bars2 = ax1.bar(x + width/2, de_asr,  width, label="D/E (compositional + lifecycle)", color="#1D4ED8")
ax1.set_xticks(x)
ax1.set_xticklabels(MODEL_LABELS, fontsize=9, rotation=12, ha="right")
ax1.set_ylabel("Mean ASR", fontsize=10)
ax1.set_ylim(0, 1.0)
ax1.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
ax1.legend(fontsize=9)
ax1.set_title("RQ3: D/E vs A/B/C Mean ASR", fontsize=11)
ax1.grid(axis="y", alpha=0.3)
for bar in bars1:
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f"{bar.get_height():.0%}", ha="center", va="bottom", fontsize=8)
for bar in bars2:
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f"{bar.get_height():.0%}", ha="center", va="bottom", fontsize=8, color="#1D4ED8")

# Right: gap (D/E - A/B/C)
colors = ["#1D4ED8" if g > 0 else "#DC2626" for g in gap]
ax2.bar(x, gap, color=colors, width=0.5)
ax2.axhline(0, color="black", linewidth=0.8)
ax2.set_xticks(x)
ax2.set_xticklabels(MODEL_LABELS, fontsize=9, rotation=12, ha="right")
ax2.set_ylabel("ASR Gap (D/E minus A/B/C)", fontsize=10)
ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:+.0%}"))
ax2.set_title("RQ3: Compositional/Lifecycle Uplift", fontsize=11)
ax2.grid(axis="y", alpha=0.3)
for i, (xi, g) in enumerate(zip(x, gap)):
    ax2.text(xi, g + (0.008 if g >= 0 else -0.018),
             f"{g:+.0%}", ha="center", va="bottom", fontsize=9, fontweight="bold")

plt.tight_layout()
out_rq3 = Path("figures/fig_rq3_de_gap.pdf")
plt.savefig(out_rq3, dpi=300, bbox_inches="tight")
plt.savefig(out_rq3.with_suffix(".png"), dpi=200, bbox_inches="tight")
print(f"Saved: {out_rq3}")
plt.close()

# ── Print summary stats for RQ3 write-up ─────────────────────────────────────
print("\n=== RQ3 Summary Stats ===")
print(f"{'Model':<22} {'A/B/C':>7} {'D/E':>7} {'Gap':>7}")
for i, (name, _) in enumerate(MODELS):
    print(f"{name:<22} {abc_asr[i]:>7.1%} {de_asr[i]:>7.1%} {gap[i]:>+7.1%}")
print(f"\nMean gap across models: {gap.mean():+.1%}")
print(f"All models show D/E > A/B/C: {all(gap > 0)}")
