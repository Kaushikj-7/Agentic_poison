"""Deterministic escalation router — pure policy, no model involved."""

from __future__ import annotations

from dataclasses import dataclass

from agentpoi_scan.findings.model import Finding, severity_rank


@dataclass
class EscalationPolicy:
    severity_gte: str = "high"
    local_confidence_lt: float = 0.7
    on_autorun_surface: bool = True
    malware_score_gte: float = 0.6

    @classmethod
    def from_config(cls, router_cfg: dict | None) -> "EscalationPolicy":
        router_cfg = router_cfg or {}
        return cls(
            severity_gte=str(router_cfg.get("escalate_if", {}).get("severity_gte", "high")),
            local_confidence_lt=float(
                router_cfg.get("escalate_if", {}).get("local_confidence_lt", 0.7)
            ),
            on_autorun_surface=bool(
                router_cfg.get("escalate_if", {}).get("on_autorun_surface", True)
            ),
            malware_score_gte=float(
                router_cfg.get("escalate_if", {}).get("malware_score_gte", 0.6)
            ),
        )


class Router:
    """Decides which findings go to the frontier analyst."""

    def __init__(self, policy: EscalationPolicy | None = None) -> None:
        self.policy = policy or EscalationPolicy()

    def escalate(self, finding: Finding, triage_verdict: dict | None) -> bool:
        if triage_verdict is None:
            return True  # untriageable → escalate (fail-closed)
        if severity_rank(finding.severity) >= severity_rank(self.policy.severity_gte):
            return True
        confidence = float(triage_verdict.get("confidence", 1.0))
        if confidence < self.policy.local_confidence_lt:
            return True
        if triage_verdict.get("escalate"):
            return True
        if self.policy.on_autorun_surface and finding.category == "autorun":
            return True
        if finding.maliciousness >= self.policy.malware_score_gte:
            return True
        return False
