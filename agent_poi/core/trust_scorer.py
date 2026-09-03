"""Contextual Trust Propagation (CTP) Trust Scorer.

Implements the mathematical formulation:
T(c) = T_source(c) * exp(-lambda * R_ci(c)) * ( prod T(p_i) )^(1/n)
"""

import math
from typing import Dict, List, Optional, Tuple
from agent_poi.memory.schema import SourceOrigin, FirewallStatus, FirewallDecision, MemoryItem


class TrustScorer:
    """Computes non-dilutable contextual trust scores and classifies firewall actions."""

    DEFAULT_SOURCE_PRIORS: Dict[SourceOrigin, float] = {
        SourceOrigin.VERIFIED_USER: 0.95,
        SourceOrigin.SYSTEM_INSTRUCTION: 0.90,
        SourceOrigin.INTERNAL_TOOL: 0.65,
        SourceOrigin.EXTERNAL_API: 0.40,
        SourceOrigin.UNTRUSTED_WEB: 0.25,
        SourceOrigin.ANONYMOUS_PEER: 0.15,
    }

    def __init__(
        self,
        lambda_decay: float = 2.5,
        tau_threshold: float = 0.50,
        tau_critical: float = 0.25,
        source_priors: Optional[Dict[SourceOrigin, float]] = None,
    ):
        self.lambda_decay = float(lambda_decay)
        self.tau = float(tau_threshold)
        self.tau_crit = float(tau_critical)
        self.source_priors = source_priors or dict(self.DEFAULT_SOURCE_PRIORS)

    def compute_direct_trust(self, origin: SourceOrigin, r_ci: float) -> float:
        """Compute T_direct(c) = T_source(c) * exp(-lambda * R_ci(c))."""
        t_source = self.source_priors.get(origin, 0.30)
        penalty = math.exp(-self.lambda_decay * max(0.0, min(1.0, r_ci)))
        return float(t_source * penalty)

    def compute_ancestor_trust_factor(self, parent_trust_scores: List[float]) -> float:
        """Compute geometric mean of parent trust scores: ( prod T(p_i) )^(1/n).

        Guarantees non-dilution: A tainted ancestor permanently suppresses child trust.
        """
        if not parent_trust_scores:
            return 1.0

        n = len(parent_trust_scores)
        # Numerical stability using log sum
        log_sum = sum(math.log(max(1e-6, score)) for score in parent_trust_scores)
        geom_mean = math.exp(log_sum / n)
        return float(geom_mean)

    def compute_score(
        self,
        origin: SourceOrigin,
        r_ci: float,
        parent_trust_scores: Optional[List[float]] = None,
    ) -> float:
        """Calculate final Contextual Trust Propagation score T(c) in [0, 1]."""
        direct_trust = self.compute_direct_trust(origin, r_ci)
        parent_scores = parent_trust_scores or []
        ancestor_factor = self.compute_ancestor_trust_factor(parent_scores)
        final_score = direct_trust * ancestor_factor
        return float(max(0.0, min(1.0, final_score)))

    def evaluate(
        self,
        item_id: str,
        content: str,
        origin: SourceOrigin,
        r_ci: float,
        reasons: List[str],
        parent_trust_scores: Optional[List[float]] = None,
        custom_tau: Optional[float] = None,
    ) -> FirewallDecision:
        """Classify memory into ALLOWED, QUARANTINED, or BLOCKED."""
        tau = custom_tau if custom_tau is not None else self.tau
        score = self.compute_score(origin, r_ci, parent_trust_scores)

        eval_reasons = list(reasons)
        if score >= tau:
            status = FirewallStatus.ALLOWED
            eval_reasons.append(f"Trust score {score:.3f} >= threshold {tau:.3f} (Passed)")
        elif score >= self.tau_crit:
            status = FirewallStatus.QUARANTINED
            eval_reasons.append(f"Trust score {score:.3f} in quarantine range [{self.tau_crit:.2f}, {tau:.2f})")
        else:
            status = FirewallStatus.BLOCKED
            eval_reasons.append(f"Trust score {score:.3f} < critical threshold {self.tau_crit:.2f} (Strictly Blocked)")

        snippet = content[:80] + "..." if len(content) > 80 else content
        return FirewallDecision(
            status=status,
            trust_score=round(score, 4),
            reasons=eval_reasons,
            item_id=item_id,
            content_snippet=snippet,
            ci_risk_score=round(r_ci, 4),
        )
