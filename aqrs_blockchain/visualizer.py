"""
Module 6: Results and Visualization
Generates 6 matplotlib plots, saves individual PNGs to the plots/ directory,
shows all 6 in a combined figure, and prints a formatted summary table.
"""

import os
import matplotlib.pyplot as plt

_MODES = ["ECDSA", "DIL2", "DIL3", "DIL5", "AQRS"]
_COLORS = {
    "sign":       "steelblue",
    "verify":     "darkorange",
    "size":       "mediumseagreen",
    "score":      "mediumpurple",
    "throughput": "crimson",
}


def generate_all_plots(all_mode_results: dict, aqrs_scores: dict,
                       plots_dir: str = "plots") -> None:
    """Generate all 6 plots, save individual PNGs, then show combined figure.

    Args:
        all_mode_results: Dict mapping mode → simulation result dict.
        aqrs_scores:      Dict mapping mode → AQRS score float.
        plots_dir:        Directory path for saving PNG files.
    """
    os.makedirs(plots_dir, exist_ok=True)

    # ── extract per-mode series ──────────────────────────────────────────
    avg_sign     = [all_mode_results[m]["average_signing_time_ms"]     for m in _MODES]
    avg_verify   = [all_mode_results[m]["average_verification_time_ms"] for m in _MODES]
    avg_sig_size = [all_mode_results[m]["average_signature_size_bytes"] for m in _MODES]
    throughputs  = [all_mode_results[m]["throughput_tps"]               for m in _MODES]
    scores       = [aqrs_scores.get(m, 0.0)                             for m in _MODES]

    # ── AQRS mode level distribution ────────────────────────────────────
    level_counts, pie_labels, pie_sizes, pie_colors = _aqrs_pie_data(
        all_mode_results["AQRS"]["transactions"]
    )

    # ── save individual PNG files ────────────────────────────────────────
    _save_bar(avg_sign,     _MODES, "Average Signing Time (ms)",
              "Average Signing Time by Mode",
              _COLORS["sign"],    os.path.join(plots_dir, "signing_time.png"))

    _save_bar(avg_verify,   _MODES, "Average Verification Time (ms)",
              "Average Verification Time by Mode",
              _COLORS["verify"],  os.path.join(plots_dir, "verification_time.png"))

    _save_bar(avg_sig_size, _MODES, "Average Signature Size (bytes)",
              "Average Signature Size by Mode",
              _COLORS["size"],    os.path.join(plots_dir, "signature_size.png"))

    _save_aqrs_score_bar(scores, _MODES, aqrs_scores,
                         os.path.join(plots_dir, "aqrs_score.png"))

    _save_bar(throughputs,  _MODES, "Transactions per Second (TPS)",
              "Transaction Throughput by Mode",
              _COLORS["throughput"], os.path.join(plots_dir, "throughput.png"))

    _save_pie(pie_labels, pie_sizes, pie_colors,
              "AQRS Mode: Dilithium Level Distribution by Transaction Count",
              os.path.join(plots_dir, "level_distribution.png"))

    # ── combined 2×3 figure shown with plt.show() ────────────────────────
    fig, axes = plt.subplots(2, 3, figsize=(20, 11))
    fig.suptitle("AQRS Blockchain Simulation — All Results", fontsize=14, fontweight="bold")

    # Row 0
    _fill_bar(axes[0, 0], avg_sign,     _MODES,
              "Average Signing Time (ms)", "Average Signing Time by Mode",
              _COLORS["sign"])

    _fill_bar(axes[0, 1], avg_verify,   _MODES,
              "Average Verification Time (ms)", "Average Verification Time by Mode",
              _COLORS["verify"])

    _fill_bar(axes[0, 2], avg_sig_size, _MODES,
              "Average Signature Size (bytes)", "Average Signature Size by Mode",
              _COLORS["size"])

    # Row 1
    _fill_aqrs_score_bar(axes[1, 0], scores, _MODES, aqrs_scores)

    _fill_bar(axes[1, 1], throughputs, _MODES,
              "Transactions per Second (TPS)", "Transaction Throughput by Mode",
              _COLORS["throughput"])

    _fill_pie(axes[1, 2], pie_labels, pie_sizes, pie_colors,
              "AQRS Mode: Dilithium Level Distribution\nby Transaction Count")

    plt.tight_layout()
    combined_path = os.path.join(plots_dir, "all_plots_combined.png")
    plt.savefig(combined_path, dpi=150, bbox_inches="tight")
    print(f"  Combined plot saved → {combined_path}")
    plt.show()

    # ── summary table ────────────────────────────────────────────────────
    _print_summary_table(all_mode_results, aqrs_scores)


# ══════════════════════════════════════════════════════════════
# Individual-plot saving helpers
# ══════════════════════════════════════════════════════════════

def _save_bar(values, labels, ylabel, title, color, path):
    fig, ax = plt.subplots(figsize=(8, 5))
    _fill_bar(ax, values, labels, ylabel, title, color)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved → {path}")


def _save_aqrs_score_bar(scores, labels, aqrs_scores_dict, path):
    fig, ax = plt.subplots(figsize=(8, 5))
    _fill_aqrs_score_bar(ax, scores, labels, aqrs_scores_dict)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved → {path}")


def _save_pie(pie_labels, pie_sizes, pie_colors, title, path):
    fig, ax = plt.subplots(figsize=(7, 6))
    _fill_pie(ax, pie_labels, pie_sizes, pie_colors, title)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved → {path}")


# ══════════════════════════════════════════════════════════════
# Axes-filling helpers (used for both individual and combined)
# ══════════════════════════════════════════════════════════════

def _fill_bar(ax, values, labels, ylabel, title, color):
    bars = ax.bar(labels, values, color=color, edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Mode", fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_title(title, fontsize=11, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    ax.set_axisbelow(True)
    # Annotate bar tops
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.01,
            f"{val:.2f}",
            ha="center", va="bottom", fontsize=8,
        )


def _fill_aqrs_score_bar(ax, scores, labels, aqrs_scores_dict):
    bars = ax.bar(labels, scores, color=_COLORS["score"], edgecolor="white", linewidth=0.5)
    ax.axhline(y=1.0, color="red", linestyle="--", linewidth=1.5, label="ECDSA Baseline (1.0)")
    ax.set_xlabel("Mode", fontsize=10)
    ax.set_ylabel("AQRS Score", fontsize=10)
    ax.set_title("AQRS Feasibility Score by Mode (higher = better)",
                 fontsize=11, fontweight="bold")
    ax.legend(fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.6)
    ax.set_axisbelow(True)
    for bar, score in zip(bars, scores):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.01,
            f"{score:.2f}",
            ha="center", va="bottom", fontsize=9, fontweight="bold",
        )


def _fill_pie(ax, labels, sizes, colors, title):
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        wedgeprops={"edgecolor": "white", "linewidth": 1},
    )
    for at in autotexts:
        at.set_fontsize(9)
    ax.set_title(title, fontsize=11, fontweight="bold")


# ══════════════════════════════════════════════════════════════
# AQRS pie data helper
# ══════════════════════════════════════════════════════════════

def _aqrs_pie_data(aqrs_tx_records: list):
    level_counts = {2: 0, 3: 0, 5: 0}
    for tx in aqrs_tx_records:
        lvl = tx.get("dilithium_level_used")
        if lvl in level_counts:
            level_counts[lvl] += 1

    pie_labels = [f"Dilithium Level {lvl}" for lvl in [2, 3, 5]]
    pie_sizes  = [level_counts[2], level_counts[3], level_counts[5]]
    pie_colors = ["#66b3ff", "#ffcc99", "#ff6666"]
    return level_counts, pie_labels, pie_sizes, pie_colors


# ══════════════════════════════════════════════════════════════
# Summary table
# ══════════════════════════════════════════════════════════════

def _print_summary_table(all_mode_results: dict, aqrs_scores: dict) -> None:
    print("\n" + "=" * 96)
    print("  AQRS BLOCKCHAIN SIMULATION — SUMMARY TABLE")
    print("=" * 96)

    try:
        import pandas as pd

        rows = []
        for mode in _MODES:
            r = all_mode_results[mode]
            rows.append({
                "Mode":             mode,
                "Avg Sign (ms)":    round(r["average_signing_time_ms"],      4),
                "Avg Verify (ms)":  round(r["average_verification_time_ms"], 4),
                "Avg Sig (bytes)":  round(r["average_signature_size_bytes"], 1),
                "TPS":              round(r["throughput_tps"],               2),
                "Chain KB":         round(r["total_chain_size_bytes"] / 1024, 2),
                "AQRS Score":       round(aqrs_scores.get(mode, 0),          4),
            })

        df = pd.DataFrame(rows).set_index("Mode")
        print(df.to_string())

    except ImportError:
        # Fallback plain-text table when pandas is unavailable
        header = (
            f"{'Mode':<8}  {'Avg Sign(ms)':>14}  {'Avg Verify(ms)':>14}  "
            f"{'Avg Sig(B)':>11}  {'TPS':>10}  {'Chain KB':>9}  {'AQRS Score':>12}"
        )
        print(header)
        print("-" * 96)
        for mode in _MODES:
            r = all_mode_results[mode]
            print(
                f"{mode:<8}  "
                f"{r['average_signing_time_ms']:>14.4f}  "
                f"{r['average_verification_time_ms']:>14.4f}  "
                f"{r['average_signature_size_bytes']:>11.1f}  "
                f"{r['throughput_tps']:>10.2f}  "
                f"{r['total_chain_size_bytes'] / 1024:>9.2f}  "
                f"{aqrs_scores.get(mode, 0):>12.4f}"
            )

    print("=" * 96 + "\n")
