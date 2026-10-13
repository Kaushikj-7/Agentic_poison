"""DataSentinel: Game-Theoretic Minimax Detection Threshold Optimizer (IEEE S&P 2025).

Calculates the minimax optimal detection threshold tau* that minimizes empirical risk
balancing False Positive Rate (business disruption) and False Negative Rate (unauthorized disbursement breach)
under asymmetric cost ratio gamma.
"""

from dataclasses import dataclass, field
from typing import List, Sequence

import numpy as np


@dataclass(frozen=True)
class DataSentinelResult:
    """Optimal threshold calculation output."""
    optimal_threshold: float
    minimax_risk: float
    fpr_at_optimal: float
    fnr_at_optimal: float
    candidate_thresholds: List[float] = field(default_factory=list)


class DataSentinelOptimizer:
    """Game-theoretic minimax optimizer for Contextual Invariant Verification thresholds."""

    def __init__(self, threshold_step: float = 0.01, min_tau: float = 0.05, max_tau: float = 0.95):
        self.threshold_step = threshold_step
        self.min_tau = min_tau
        self.max_tau = max_tau

    def compute_optimal_threshold(
        self,
        clean_scores: Sequence[float],
        adv_scores: Sequence[float],
        gamma: float = 5.0,
    ) -> DataSentinelResult:
        """Find optimal threshold tau* minimizing: Risk(tau) = FPR(tau) + gamma * FNR(tau)."""
        if not clean_scores or not adv_scores:
            return DataSentinelResult(
                optimal_threshold=0.35,
                minimax_risk=0.0,
                fpr_at_optimal=0.0,
                fnr_at_optimal=0.0,
            )

        clean_arr = np.array(clean_scores)
        adv_arr = np.array(adv_scores)

        thresholds = np.arange(self.min_tau, self.max_tau + self.threshold_step, self.threshold_step)
        best_tau = float(thresholds[0])
        min_risk = float("inf")
        best_fpr = 1.0
        best_fnr = 1.0

        for tau in thresholds:
            # Clean items scored >= tau are False Positives
            fpr = float(np.mean(clean_arr >= tau))
            # Adversarial items scored < tau are False Negatives (unintercepted breaches)
            fnr = float(np.mean(adv_arr < tau))

            risk = fpr + gamma * fnr
            if risk < min_risk:
                min_risk = risk
                best_tau = float(round(tau, 3))
                best_fpr = float(round(fpr, 4))
                best_fnr = float(round(fnr, 4))

        return DataSentinelResult(
            optimal_threshold=best_tau,
            minimax_risk=float(round(min_risk, 4)),
            fpr_at_optimal=best_fpr,
            fnr_at_optimal=best_fnr,
            candidate_thresholds=[float(round(t, 2)) for t in thresholds],
        )
