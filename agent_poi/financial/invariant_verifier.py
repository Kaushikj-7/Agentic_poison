"""Contextual Invariant Verification (CIV) Engine.

Evaluates extracted financial deltas Delta(c) against the Immutable State Anchor S0.
Guarantees that passive text cannot mutate financial state invariants without verified consensus.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from agent_poi.financial.state_anchor import FinancialStateAnchor
from agent_poi.financial.delta_extractor import ContextualFinancialDelta, FinancialDeltaExtractor


@dataclass
class InvariantVerificationResult:
    """The result of validating a contextual financial delta against S0."""
    is_admitted: bool
    is_executable: bool
    decision: str  # "ALLOWED", "QUARANTINED", "BLOCKED"
    violations: List[str] = field(default_factory=list)
    target_account: Optional[str] = None
    verified_payee_name: Optional[str] = None
    amount: Optional[float] = None
    claimed_authority: Optional[str] = None


class InvariantVerifier:
    """Evaluates contextual financial deltas against immutable invariants."""

    def __init__(self, state_anchor: Optional[FinancialStateAnchor] = None):
        self.anchor = state_anchor or FinancialStateAnchor()
        self.extractor = FinancialDeltaExtractor()

    def verify_text(self, text: str) -> InvariantVerificationResult:
        """Extract delta from text and verify against immutable state invariants."""
        delta = self.extractor.extract(text)
        return self.verify_delta(delta)

    def verify_delta(self, delta: ContextualFinancialDelta) -> InvariantVerificationResult:
        """Core verification logic for Contextual Financial Deltas."""
        violations: List[str] = []

        # If it's a passive memo with no account or amount, it's safe to admit into context
        if delta.intent == "passive_memo" and not delta.has_override_attempt:
            return InvariantVerificationResult(
                is_admitted=True,
                is_executable=True,
                decision="ALLOWED",
                violations=[],
            )

        # Invariant 1: Self-Asserted Authority in passive text is strictly prohibited
        if delta.has_override_attempt:
            violations.append(
                f"EPISTEMIC VIOLATION: Passive context asserts self-authorized override: '{delta.claimed_authority}'."
            )

        # Invariant 2: Account Verification
        verified_name = None
        if delta.target_account:
            if not self.anchor.is_payee_verified(delta.target_account):
                violations.append(
                    f"INVARIANT BREACH: Target account '{delta.target_account}' is NOT in verified payee registry."
                )
            else:
                payee = self.anchor.get_payee(delta.target_account)
                verified_name = payee.name

        # Invariant 3: Amount Limits
        if delta.amount is not None:
            if delta.amount > self.anchor.per_transaction_limit:
                violations.append(
                    f"LIMIT BREACH: Amount ${delta.amount:.2f} exceeds global ceiling (${self.anchor.per_transaction_limit:.2f})."
                )
            if delta.target_account and self.anchor.is_payee_verified(delta.target_account):
                payee = self.anchor.get_payee(delta.target_account)
                if delta.amount > payee.max_single_disbursement:
                    violations.append(
                        f"LIMIT BREACH: Amount ${delta.amount:.2f} exceeds '{payee.name}' single limit (${payee.max_single_disbursement:.2f})."
                    )

        # Decision routing
        has_critical_breach = any("NOT in verified payee registry" in v for v in violations)
        has_epistemic_breach = any("EPISTEMIC VIOLATION" in v for v in violations)

        if has_critical_breach or has_epistemic_breach:
            # Dangerous or poisoned context
            is_admitted = False
            is_executable = False
            decision = "BLOCKED" if has_critical_breach else "QUARANTINED"
        elif violations:
            # Minor limit breach or warning
            is_admitted = True
            is_executable = False
            decision = "QUARANTINED"
        else:
            is_admitted = True
            is_executable = True
            decision = "ALLOWED"

        return InvariantVerificationResult(
            is_admitted=is_admitted,
            is_executable=is_executable,
            decision=decision,
            violations=violations,
            target_account=delta.target_account,
            verified_payee_name=verified_name,
            amount=delta.amount,
            claimed_authority=delta.claimed_authority,
        )
