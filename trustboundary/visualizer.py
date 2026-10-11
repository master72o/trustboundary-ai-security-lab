"""
Publication-Quality Visualization Suite for TrustBoundary.
Generates high-resolution figures for security research reports.
"""

import os
from typing import Dict, Any, List
import matplotlib.pyplot as plt
import numpy as np


class TrustBoundaryVisualizer:
    """
    Renders research figures summarizing multi-tier defense performance.
    """

    COLOR_PALETTE = {
        "Baseline_Raw": "#e74c3c",                # Crimson Red
        "Keyword_Regex_Filter": "#e67e22",        # Orange
        "Ingress_Only_Guardrail": "#3498db",      # Blue
        "TrustBoundary_Dual_Defense": "#2ecc71",  # Emerald Green
    }

    @classmethod
    def plot_security_utility_tradeoff(
        cls,
        metrics_by_tier: Dict[str, Dict[str, Any]],
        output_path: str,
    ) -> None:
        """
        Plots Defense Rate (100 - ASR) vs Benign Utility Preservation (BUP).
        The ideal defense is in the top-right corner (100% Defense, 100% Utility).
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        fig, ax = plt.subplots(figsize=(8, 6), dpi=300)

        for tier_name, metrics in metrics_by_tier.items():
            defense_rate = metrics["defense_rate"]
            bup = metrics["benign_utility_preservation"]
            color = cls.COLOR_PALETTE.get(tier_name, "#95a5a6")
            f_sec = metrics["harmonic_security_score"]

            ax.scatter(
                bup,
                defense_rate,
                s=280,
                color=color,
                edgecolors="#2c3e50",
                linewidth=1.5,
                zorder=5,
                label=f"{tier_name} (F_sec: {f_sec}%)",
            )
            ax.annotate(
                f"  {tier_name.replace('_', ' ')}\n  ({defense_rate}% Def, {bup}% Util)",
                (bup, defense_rate),
                fontsize=9,
                fontweight="medium",
                xytext=(6, -5),
                textcoords="offset points",
            )

        # Plot Pareto frontier / reference grid
        ax.axhline(100, color="#bdc3c7", linestyle="--", alpha=0.6)
        ax.axvline(100, color="#bdc3c7", linestyle="--", alpha=0.6)

        ax.set_title("Security-Utility Pareto Frontier across Defense Tiers", fontsize=14, fontweight="bold", pad=12)
        ax.set_xlabel("Benign Utility Preservation Rate (%) [Higher is Better]", fontsize=11, fontweight="medium")
        ax.set_ylabel("Adversarial Defense Rate (%) (100 - ASR) [Higher is Better]", fontsize=11, fontweight="medium")
        ax.set_xlim(-5, 110)
        ax.set_ylim(-5, 110)
        ax.grid(True, linestyle=":", alpha=0.6)
        ax.legend(loc="lower left", frameon=True, framealpha=0.9, fontsize=9)

        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    @classmethod
    def plot_threat_category_breakdown(
        cls,
        metrics_by_tier: Dict[str, Dict[str, Any]],
        output_path: str,
    ) -> None:
        """
        Plots grouped bar chart of Attack Success Rate (ASR) per threat category.
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        tiers = list(metrics_by_tier.keys())
        first_tier = next(iter(metrics_by_tier.values()))
        categories = list(first_tier.get("category_asr", {}).keys())

        if not categories:
            return

        x = np.arange(len(categories))
        width = 0.8 / len(tiers)

        fig, ax = plt.subplots(figsize=(10, 6), dpi=300)

        for i, tier in enumerate(tiers):
            cat_asr = [metrics_by_tier[tier]["category_asr"].get(cat, 0.0) for cat in categories]
            offset = (i - len(tiers) / 2) * width + width / 2
            color = cls.COLOR_PALETTE.get(tier, "#95a5a6")
            bars = ax.bar(x + offset, cat_asr, width, label=tier.replace('_', ' '), color=color, edgecolor="#2c3e50", alpha=0.9)
            ax.bar_label(bars, fmt="%.0f%%", padding=2, fontsize=7)

        clean_cat_labels = [c.replace('_', '\n') for c in categories]
        ax.set_xticks(x)
        ax.set_xticklabels(clean_cat_labels, fontsize=9)
        ax.set_ylabel("Attack Success Rate (ASR %) [Lower is Better]", fontsize=11, fontweight="medium")
        ax.set_title("Attack Success Rate (ASR) by Threat Vector Across Defense Tiers", fontsize=14, fontweight="bold", pad=12)
        ax.set_ylim(0, 115)
        ax.grid(axis="y", linestyle=":", alpha=0.6)
        ax.legend(loc="upper right", frameon=True, framealpha=0.9, fontsize=8.5)

        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    @classmethod
    def plot_canary_and_tool_exfil(
        cls,
        metrics_by_tier: Dict[str, Dict[str, Any]],
        output_path: str,
    ) -> None:
        """
        Plots Canary Leakage Ratio (CLR) and Tool Hijacking Ratio (THR) by tier.
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5), dpi=300)

        tiers = list(metrics_by_tier.keys())
        short_names = [t.replace('TrustBoundary_', '').replace('_', '\n') for t in tiers]
        colors = [cls.COLOR_PALETTE.get(t, "#95a5a6") for t in tiers]

        clr_values = [metrics_by_tier[t]["canary_leakage_ratio"] for t in tiers]
        thr_values = [metrics_by_tier[t]["tool_hijacking_ratio"] for t in tiers]

        # Left: Canary Leakage
        b1 = ax1.bar(short_names, clr_values, color=colors, edgecolor="#2c3e50", width=0.6)
        ax1.bar_label(b1, fmt="%.1f%%", padding=3, fontsize=9, fontweight="bold")
        ax1.set_title("Canary Secret Leakage Ratio (CLR)", fontsize=12, fontweight="bold")
        ax1.set_ylabel("Exfiltration Rate (%) [0% Ideal]", fontsize=10)
        ax1.set_ylim(0, 115)
        ax1.grid(axis="y", linestyle=":", alpha=0.6)

        # Right: Tool Hijacking
        b2 = ax2.bar(short_names, thr_values, color=colors, edgecolor="#2c3e50", width=0.6)
        ax2.bar_label(b2, fmt="%.1f%%", padding=3, fontsize=9, fontweight="bold")
        ax2.set_title("Agentic Tool Hijacking Ratio (THR)", fontsize=12, fontweight="bold")
        ax2.set_ylabel("Execution Compromise Rate (%) [0% Ideal]", fontsize=10)
        ax2.set_ylim(0, 115)
        ax2.grid(axis="y", linestyle=":", alpha=0.6)

        plt.suptitle("Exfiltration & Privilege Escalation Mitigation Audit", fontsize=14, fontweight="bold", y=1.02)
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    @classmethod
    def plot_latency_overhead(
        cls,
        metrics_by_tier: Dict[str, Dict[str, Any]],
        output_path: str,
    ) -> None:
        """
        Plots latency comparison in milliseconds across defense tiers.
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        fig, ax = plt.subplots(figsize=(7, 4.5), dpi=300)

        tiers = list(metrics_by_tier.keys())
        short_names = [t.replace('TrustBoundary_', '').replace('_', ' ') for t in tiers]
        latencies = [metrics_by_tier[t]["avg_latency_ms"] for t in tiers]
        colors = [cls.COLOR_PALETTE.get(t, "#95a5a6") for t in tiers]

        bars = ax.barh(short_names, latencies, color=colors, edgecolor="#2c3e50", height=0.55)
        ax.bar_label(bars, fmt="%.2f ms", padding=5, fontsize=9, fontweight="bold")

        ax.set_xlabel("Mean Execution Latency Overhead (ms)", fontsize=10, fontweight="medium")
        ax.set_title("Per-Request Firewall Latency Overhead", fontsize=12, fontweight="bold", pad=10)
        ax.grid(axis="x", linestyle=":", alpha=0.6)

        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
