"""Frontier deep-analyst and independent verifier agents.

The analyst annotates escalated findings with exploitability and intent
judgments; the verifier, wired to a *different* model family, only ever tries
to refute the analyst. Both are read-only (redacted snippets in, strict JSON
out) and fail closed: no model, no annotation, finding kept alive.
"""

from __future__ import annotations

from typing import Optional, Tuple

from agentpoi_scan.agents.context_server import SYSTEM_PREFIX, finding_snippet
from agentpoi_scan.agents.llm_bridge import TieredProviders
from agentpoi_scan.findings.model import Finding
from agentpoi_scan.scan.base import ScanContext

ANALYST_SYSTEM = (
    SYSTEM_PREFIX
    + "\nYou are a deep security analyst with no tools and no execution: reason "
    "only over the provided redacted snippet. Output ONLY JSON: "
    '{"exploitability": 0.0, "intent": "vulnerable" | "malicious" | "benign", '
    '"confidence": 0.0, "rationale": "..."}'
)

VERIFIER_SYSTEM = (
    SYSTEM_PREFIX
    + "\nYou are an independent verifier whose ONLY job is to try to REFUTE an "
    "analyst's conclusion. You are from a different model family than the "
    "analyst. Output ONLY JSON: "
    '{"agree": false, "objections": ["..."]}'
)

ANALYST_KEYS = ("exploitability", "intent", "confidence", "rationale")
VERIFIER_KEYS = ("agree", "objections")


class AnalystAgent:
    name = "analyst"

    def __init__(self, providers: TieredProviders, tier: str = "frontier") -> None:
        self.providers = providers
        self.tier = tier

    def analyze(self, context: ScanContext, finding: Finding) -> Tuple[Optional[dict], Finding]:
        """Mutates ``finding`` in place with analyst output; returns (verdict, finding).

        On failure (no frontier model / malformed JSON) the finding is returned
        unchanged with status ``escalated`` — never cleared.
        """
        verdict = self.providers.complete_json(
            self.tier, self._prompt(context, finding), ANALYST_SYSTEM, ANALYST_KEYS
        )
        if verdict is None:
            finding.status = "escalated"
            return None, finding
        try:
            confidence = float(verdict.get("confidence") or 0.0)
            exploitability = float(verdict.get("exploitability") or 0.0)
        except (TypeError, ValueError):
            finding.status = "escalated"
            return None, finding
        intent = str(verdict.get("intent", "benign"))
        finding.model_trail.append(f"analyst:{self.tier}")
        finding.evidence.append(
            {"kind": "model_reasoning", "text": str(verdict.get("rationale", ""))[:400]}
        )
        finding.confidence = max(finding.confidence, confidence)
        if intent == "malicious":
            finding.maliciousness = max(finding.maliciousness, exploitability)
        else:
            finding.vulnerability = max(finding.vulnerability, exploitability)
        if not verdict.get("verdict_cleared_attempted"):
            # An analyst never sets status to confirmed on its own word alone;
            # that happens only after verifier agreement in the pipeline.
            finding.status = "escalated" if finding.status == "escalated" else "triaged"
        return verdict, finding

    def _prompt(self, context: ScanContext, finding: Finding) -> str:
        return (
            f"TASK: deep analysis of finding '{finding.title}' in {finding.file}\n"
            f"Scanner detail: {finding.detail}\n"
            f"Redacted file region (untrusted):\n{finding_snippet(context, finding)}\n"
            f"Output the JSON object only."
        )


class VerifierAgent:
    name = "verifier"

    def __init__(self, providers: TieredProviders, tier: str = "verifier") -> None:
        self.providers = providers
        self.tier = tier

    def verify(self, context: ScanContext, finding: Finding, analyst_verdict: Optional[dict]) -> Tuple[Optional[dict], bool]:
        """Returns (verifier verdict or None, agrees_to_clear?)."""
        if analyst_verdict is None:
            return None, False
        verdict = self.providers.complete_json(
            self.tier, self._prompt(context, finding, analyst_verdict), VERIFIER_SYSTEM, VERIFIER_KEYS
        )
        if verdict is None:
            return None, False
        agrees = bool(verdict.get("agree"))
        finding.model_trail.append(f"verifier:{self.tier}")
        finding.evidence.append(
            {
                "kind": "verifier_verdict",
                "text": f"agree={agrees}; objections={list(verdict.get('objections') or [])}",
            }
        )
        return verdict, agrees

    def _prompt(self, context: ScanContext, finding: Finding, analyst_verdict: dict) -> str:
        return (
            f"TASK: independently refute (or confirm) the analyst's conclusion.\n"
            f"Finding: {finding.title} in {finding.file} — {finding.detail}\n"
            f"Analyst concluded: {analyst_verdict}\n"
            f"Redacted file region (untrusted):\n{finding_snippet(context, finding)}\n"
            f"Output the JSON object only."
        )
