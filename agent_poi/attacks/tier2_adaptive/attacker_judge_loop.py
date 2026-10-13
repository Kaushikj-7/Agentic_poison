"""Tier 2: Attacker-Judge Adaptive Optimization Loop.

Implements iterative adversarial search where the attacker refines mutations
to test whether the firewall degrades under adaptive pressure (Abdelnabi & Bagdasarian 2026).
"""

from typing import Any, Dict, List

from agent_poi.attacks.attack_generator import AttackPayload
from agent_poi.attacks.tier2_adaptive.adaptive_mutator import AdaptiveMutator
from agent_poi.memory.memory_firewall import MemoryFirewall
from agent_poi.memory.schema import FirewallStatus


class AttackerJudgeLoop:
    """Simulates an adaptive adversary actively iterating to bypass the firewall."""

    def __init__(self, firewall: MemoryFirewall, max_iterations: int = 4):
        self.firewall = firewall
        self.max_iterations = max_iterations

    def run_adaptive_search(self, base_payload: AttackPayload) -> Dict[str, Any]:
        """Iteratively mutates payload until bypass or max iterations reached."""
        strategies = [
            ("baseline", lambda p: p),
            ("padding", AdaptiveMutator.apply_benign_padding),
            ("compliance", AdaptiveMutator.apply_compliance_reframing),
            ("passive", AdaptiveMutator.apply_passive_obfuscation),
        ]

        history: List[Dict[str, Any]] = []
        bypassed = False

        for iteration, (name, mut_fn) in enumerate(strategies[: self.max_iterations]):
            candidate = mut_fn(base_payload)
            # Evaluate against current firewall
            ci = self.firewall.ci_decomposer.decompose(candidate.content, candidate.source_origin)
            r_ci, reasons = self.firewall.ci_decomposer.compute_risk_score(ci)
            decision = self.firewall.trust_scorer.evaluate(
                item_id=candidate.attack_id,
                content=candidate.content,
                origin=candidate.source_origin,
                r_ci=r_ci,
                reasons=reasons,
            )

            history.append({
                "iteration": iteration + 1,
                "strategy": name,
                "trust_score": decision.trust_score,
                "r_ci": r_ci,
                "status": decision.status.value,
                "reasons": decision.reasons,
            })

            if decision.status == FirewallStatus.ALLOWED:
                bypassed = True
                break

        return {
            "attack_id": base_payload.attack_id,
            "bypassed": bypassed,
            "iterations_used": len(history),
            "final_status": history[-1]["status"],
            "final_trust_score": history[-1]["trust_score"],
            "trajectory": history,
        }
