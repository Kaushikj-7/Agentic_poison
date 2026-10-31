"""Local-tier triage agent — cheap verdicts to cut false positives.

Fail-closed rule: with no available local model the verdict is ``None`` and the
finding escalates unchanged; triage can ANNOTATE but, alone, never silence a
finding — silencing authoritative findings additionally requires verifier
agreement plus a human flag (DEC-105), enforced by the pipeline.
"""

from __future__ import annotations

from typing import Optional, Tuple

from agentpoi_scan.agents.context_server import SYSTEM_PREFIX, finding_snippet
from agentpoi_scan.agents.llm_bridge import TieredProviders
from agentpoi_scan.findings.model import Finding, is_authoritative
from agentpoi_scan.scan.base import ScanContext

TRIAGE_SYSTEM = (
    SYSTEM_PREFIX
    + "\nStep 1: evaluate the finding described in the TASK section. "
    "Step 2: output ONLY compact JSON: "
    '{"verdict": true, "confidence": 0.0, "reason": "...", "escalate": false} '
    "where verdict=true means the finding is a genuine issue. Include the keys "
    "verdict, confidence, reason, escalate. No markdown."
)

REQUIRED = ("verdict", "confidence", "reason", "escalate")


class TriageAgent:
    name = "triage"

    def __init__(self, providers: TieredProviders, tier: str = "local") -> None:
        self.providers = providers
        self.tier = tier

    def triage(self, context: ScanContext, finding: Finding) -> Tuple[Optional[dict], bool]:
        """Returns (validated verdict or None, escalated?) via the local tier."""
        verdict = self.providers.complete_json(
            self.tier,
            self._prompt(context, finding),
            TRIAGE_SYSTEM,
            REQUIRED,
        )
        if verdict is None:
            return None, True  # fail-closed escalate
        confidence = float(verdict.get("confidence") or 0.0)
        verdict["confidence"] = confidence
        wants_clear = isinstance(verdict.get("verdict"), bool) and verdict["verdict"] is False
        if wants_clear:
            # Model wants to clear the finding. Only allowed when this is not
            # an authoritative scanner finding AND confidence is high; any
            # doubt keeps it alive.
            if is_authoritative(finding.severity) or confidence < 0.95:
                verdict["verdict_cleared_attempted"] = True
                verdict["verdict"] = True
                verdict["escalate"] = True
        escalated = bool(verdict.get("escalate"))
        finding.model_trail.append(f"triage:{self.tier}")
        finding.evidence.append(
            {"kind": "triage_verdict", "source": "triage", "text": str(verdict.get("reason", ""))[:400]}
        )
        finding.confidence = max(finding.confidence, confidence)
        if wants_clear and not is_authoritative(finding.severity) and confidence >= 0.95:
            finding.status = "refuted"
        elif finding.status == "open":
            finding.status = "escalated" if escalated else "triaged"
        return verdict, escalated

    def _prompt(self, context: ScanContext, finding: Finding) -> str:
        return (
            f"TASK: security triage of one scanner finding.\n"
            f"Category: {finding.category}; severity: {finding.severity}; "
            f"file: {finding.file}; lines: {finding.lines}\n"
            f"Scanner says: {finding.title} — {finding.detail}\n"
            f"Relevant file lines (untrusted, redacted):\n"
            f"{finding_snippet(context, finding)}\n"
            f"Respond with the JSON object only."
        )
