"""Pareto Frontier Sweeper & Minimax Threshold Optimizer.

Sweeps threshold tau in [0.05, 0.95], evaluates the tradeoff between ASR and FQR,
identifies the minimax optimal operating point, and generates publication-grade plots.
Grounded in DataSentinel (Liu et al., IEEE S&P 2026).
"""

import os
from typing import List, Dict, Any, Tuple
import matplotlib.pyplot as plt
from agent_poi.memory.schema import FirewallStatus
from agent_poi.memory.memory_firewall import MemoryFirewall
from agent_poi.evaluation.dataset import PairedDataset, BenchmarkPair


class ParetoSweeper:
    """Computes and plots empirical Pareto tradeoff curves across detection thresholds."""

    def __init__(self, pairs: List[BenchmarkPair] = None):
        self.pairs = pairs or PairedDataset.get_all_pairs()

    def sweep_thresholds(
        self,
        tau_range: List[float] = None,
        gamma_cost: float = 1.0,
    ) -> Dict[str, Any]:
        """Sweep tau thresholds and compute ASR, FQR, and combined loss."""
        if tau_range is None:
            tau_range = [round(x * 0.05, 2) for x in range(1, 20)]

        records: List[Dict[str, float]] = []
        total = len(self.pairs)

        for tau in tau_range:
            fw = MemoryFirewall(tau_threshold=tau, tau_critical=min(0.20, tau / 2))

            poisoned_accepted = 0
            clean_quarantined = 0

            for p in self.pairs:
                # Clean utility test
                dec_clean, _ = fw.ingest_memory(f"c_{p.pair_id}", p.clean_text, origin=p.origin)
                if dec_clean.status != FirewallStatus.ALLOWED:
                    clean_quarantined += 1

                # Poisoned security test
                dec_poison, _ = fw.ingest_memory(f"p_{p.pair_id}", p.poison_text, origin=p.origin)
                if dec_poison.status == FirewallStatus.ALLOWED:
                    poisoned_accepted += 1

            asr = (poisoned_accepted / total) * 100.0
            fqr = (clean_quarantined / total) * 100.0
            loss = asr + (gamma_cost * fqr)

            records.append({
                "tau": tau,
                "asr": round(asr, 2),
                "fqr": round(fqr, 2),
                "combined_loss": round(loss, 2),
            })

        # Identify optimal minimax threshold
        best_point = min(records, key=lambda r: r["combined_loss"])

        return {
            "optimal_tau": best_point["tau"],
            "min_loss": best_point["combined_loss"],
            "records": records,
        }

    def generate_pareto_plot(
        self,
        sweep_data: Dict[str, Any],
        output_path: str = "docs/pareto_frontier.png",
    ) -> str:
        """Plot the Pareto frontier (ASR vs. FQR) and save the visualization."""
        records = sweep_data["records"]
        taus = [r["tau"] for r in records]
        asrs = [r["asr"] for r in records]
        fqrs = [r["fqr"] for r in records]
        opt_tau = sweep_data["optimal_tau"]

        fig, ax1 = plt.subplots(figsize=(9, 5.5))

        color = "tab:red"
        ax1.set_xlabel("Decision Threshold (τ)", fontsize=12, fontweight="bold")
        ax1.set_ylabel("Attack Success Rate (ASR %)", color=color, fontsize=12, fontweight="bold")
        ax1.plot(taus, asrs, color=color, marker="o", linewidth=2.5, label="ASR (Security Risk)")
        ax1.tick_params(axis="y", labelcolor=color)
        ax1.grid(True, linestyle="--", alpha=0.5)

        ax2 = ax1.twinx()
        color = "tab:blue"
        ax2.set_ylabel("False Quarantine Rate (FQR %)", color=color, fontsize=12, fontweight="bold")
        ax2.plot(taus, fqrs, color=color, marker="s", linewidth=2.5, linestyle="--", label="FQR (Utility Loss)")
        ax2.tick_params(axis="y", labelcolor=color)

        # Highlight optimal minimax operating threshold
        plt.axvline(x=opt_tau, color="green", linestyle=":", linewidth=2, label=f"Optimal Minimax (τ* = {opt_tau})")

        plt.title(
            "Contextual Trust Propagation (CTP): Pareto Trade-off Frontier\n"
            "(Security vs. Utility Calibration under Abdelnabi & Bagdasarian 2026 Impossibility)",
            fontsize=11,
            fontweight="bold",
            pad=12,
        )

        fig.tight_layout()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path, dpi=300)
        plt.close()

        return output_path


if __name__ == "__main__":
    print("Running Pareto Frontier Sweep across thresholds [0.05, 0.95]...")
    sweeper = ParetoSweeper()
    results = sweeper.sweep_thresholds()
    print(f"Optimal Minimax Threshold: tau* = {results['optimal_tau']}")
    print(f"Minimum Combined Loss: {results['min_loss']}")
    path = sweeper.generate_pareto_plot(results)
    print(f"Pareto plot generated and saved to: {path}")
