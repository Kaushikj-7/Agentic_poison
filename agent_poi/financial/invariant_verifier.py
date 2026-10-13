"""Contextual Invariant Verification (CIV) Engine.

Evaluates extracted financial deltas Delta(c) against the Immutable State Anchor S0.
Guarantees that passive text cannot mutate financial state invariants without verified consensus.
"""

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from agent_poi.financial.delta_extractor import ContextualFinancialDelta, FinancialDeltaExtractor
from agent_poi.financial.state_anchor import FinancialStateAnchor


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
        text = str(text or "")
        delta = self.extractor.extract(text)
        return self.verify_delta(delta)

    def _check_epistemic_invariants(self, delta: ContextualFinancialDelta) -> List[str]:
        """Check for unauthorized self-asserted authority overrides in context."""
        violations = []
        if delta.has_override_attempt:
            violations.append(
                f"EPISTEMIC VIOLATION: Passive context asserts self-authorized override: '{delta.claimed_authority}'."
            )
        return violations

    def _check_account_and_limits(
        self, delta: ContextualFinancialDelta
    ) -> Tuple[List[str], Optional[str]]:
        """Verify payee registration in S0 and disbursement ceilings."""
        violations = []
        verified_name = None

        if delta.target_account:
            if not self.anchor.is_payee_verified(delta.target_account):
                violations.append(
                    f"INVARIANT BREACH: Target account '{delta.target_account}' is NOT in verified payee registry."
                )
            else:
                payee = self.anchor.get_payee(delta.target_account)
                verified_name = payee.name

        if delta.amount is not None:
            is_valid_num = (
                isinstance(delta.amount, (int, float))
                and not isinstance(delta.amount, bool)
                and not math.isnan(delta.amount)
                and not math.isinf(delta.amount)
                and delta.amount > 0
            )
            if not is_valid_num:
                violations.append("LIMIT BREACH: Amount is not a valid positive finite number.")
            else:
                if delta.amount > self.anchor.per_transaction_limit:
                    violations.append(
                        f"LIMIT BREACH: Amount ${delta.amount:.2f} exceeds global ceiling (${self.anchor.per_transaction_limit:.2f})."
                    )
                daily_executed = self.anchor.get_recent_daily_disbursements(window_seconds=86400.0)
                if daily_executed + delta.amount > self.anchor.daily_limit:
                    violations.append(
                        f"LIMIT BREACH: Amount ${delta.amount:.2f} brings daily total (${daily_executed + delta.amount:.2f}) over daily ceiling (${self.anchor.daily_limit:.2f})."
                    )
                if delta.target_account and self.anchor.is_payee_verified(delta.target_account):
                    payee = self.anchor.get_payee(delta.target_account)
                    if delta.amount > payee.max_single_disbursement:
                        violations.append(
                            f"LIMIT BREACH: Amount ${delta.amount:.2f} exceeds '{payee.name}' single limit (${payee.max_single_disbursement:.2f})."
                        )

        return violations, verified_name

    def _resolve_decision(self, violations: List[str]) -> Tuple[bool, bool, str]:
        """Determine admission and execution state based on invariant violations."""
        has_critical_breach = any("NOT in verified payee registry" in v for v in violations)
        has_epistemic_breach = any("EPISTEMIC VIOLATION" in v for v in violations)

        if has_critical_breach or has_epistemic_breach:
            decision = "BLOCKED" if has_critical_breach else "QUARANTINED"
            return False, False, decision
        elif violations:
            return True, False, "QUARANTINED"
        return True, True, "ALLOWED"

    def verify_delta(self, delta: ContextualFinancialDelta) -> InvariantVerificationResult:
        """Core verification logic for Contextual Financial Deltas."""
        if delta.intent == "passive_memo" and not delta.has_override_attempt:
            return InvariantVerificationResult(
                is_admitted=True, is_executable=True, decision="ALLOWED", violations=[]
            )

        violations = self._check_epistemic_invariants(delta)
        acct_violations, verified_name = self._check_account_and_limits(delta)
        violations.extend(acct_violations)

        is_admitted, is_executable, decision = self._resolve_decision(violations)

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
