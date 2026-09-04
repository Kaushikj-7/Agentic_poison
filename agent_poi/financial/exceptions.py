"""Typed domain exceptions for financial agent invariant defense.

Provides structured, hierarchical exceptions for security breaches,
invariant violations, unverified payees, and limit breaches.
"""

from typing import Optional, Dict, Any


class FinancialSecurityError(Exception):
    """Base exception for all financial agent security and invariant violations."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class InvariantViolationError(FinancialSecurityError):
    """Raised when an ingested context or implied delta violates state invariants."""
    pass


class UnauthorizedPayeeError(InvariantViolationError):
    """Raised when a disbursement targets an account not in verified payee registry."""

    def __init__(self, target_account: str, details: Optional[Dict[str, Any]] = None):
        msg = f"Unauthorized Payee: Target account '{target_account}' is not registered in Immutable Anchor S0."
        super().__init__(msg, details)
        self.target_account = target_account


class DisbursementCeilingExceededError(InvariantViolationError):
    """Raised when an implied disbursement exceeds transaction or daily ceilings."""

    def __init__(self, amount: float, limit: float, details: Optional[Dict[str, Any]] = None):
        msg = f"Ceiling Exceeded: Requested disbursement ${amount:,.2f} exceeds limit of ${limit:,.2f}."
        super().__init__(msg, details)
        self.amount = amount
        self.limit = limit


class UntrustedLineageError(FinancialSecurityError):
    """Raised when AuthGraph detects unauthenticated or untrusted context ancestry."""

    def __init__(self, node_id: str, origin: str, details: Optional[Dict[str, Any]] = None):
        msg = f"Untrusted Lineage: Execution sink node '{node_id}' traces to unauthorized origin '{origin}'."
        super().__init__(msg, details)
        self.node_id = node_id
        self.origin = origin


class ImperativeDivergenceError(FinancialSecurityError):
    """Raised when Task Shield detects unprompted imperative directives in retrieved memory."""

    def __init__(self, divergence_score: float, threshold: float, details: Optional[Dict[str, Any]] = None):
        msg = f"Imperative Divergence: Directive score {divergence_score:.2f} exceeds threshold {threshold:.2f}."
        super().__init__(msg, details)
        self.divergence_score = divergence_score
        self.threshold = threshold

