"""High-Level Public Facade for the AgentPOI Defense Framework.

Provides intuitive, high-level abstractions (FinancialGuard, SecurityPolicy,
and GuardVerdict) so engineers can protect autonomous financial agent workflows
with a clean, professional API without exposing low-level plumbing.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from agent_poi.financial.financial_agent import FinancialAgent, FinancialTaskResult
from agent_poi.financial.state_anchor import FinancialStateAnchor, PayeeAccount
from agent_poi.memory.schema import SourceOrigin
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
    UntrustedLineageError,
    ImperativeDivergenceError,
)


class SecurityPolicy(str, Enum):
    """Operational security policy for autonomous financial agents."""
    STRICT = "strict"          # Contextual Invariant Verification, Task Shield, and AuthGraph active
    PERMISSIVE = "permissive"  # Invariant monitoring only; alerts logged without blocking execution


@dataclass
class GuardVerdict:
    """High-level verification verdict returned to external developers."""
    is_approved: bool
    status: str  # "APPROVED", "QUARANTINED", "BLOCKED"
    task_id: str
    violations: List[str] = field(default_factory=list)
    action_taken: str = "none"
    disbursement_executed: bool = False
    transaction_record: Optional[Dict[str, Any]] = None
    narrative: str = ""
    provenance_hash: Optional[str] = None

    @classmethod
    def from_task_result(cls, res: FinancialTaskResult) -> "GuardVerdict":
        """Convert internal FinancialTaskResult into a clean public GuardVerdict."""
        if res.action_taken == "process_disbursement":
            is_approved = bool(res.disbursement_executed and not res.is_malicious_divergence and not res.violations)
        else:
            is_approved = bool(res.context_admitted and not res.is_malicious_divergence and not res.violations)

        if is_approved:
            status = "APPROVED"
        else:
            status = res.context_decision if res.context_decision in ("BLOCKED", "QUARANTINED") else "BLOCKED"

        return cls(
            is_approved=is_approved,
            status=status,
            task_id=res.task_id,
            violations=res.violations,
            action_taken=res.action_taken,
            disbursement_executed=res.disbursement_executed,
            transaction_record=res.transaction_record,
            narrative=res.agent_narrative,
            provenance_hash=res.authgraph_hash,
        )


class FinancialGuard:
    """Production guard protecting autonomous financial agents against indirect prompt injection.

    Example:
        >>> from agent_poi import FinancialGuard, SecurityPolicy
        >>> guard = FinancialGuard(policy=SecurityPolicy.STRICT)
        >>> verdict = guard.protect(
        ...     task_query="Process vendor invoice",
        ...     context="Invoice INV-01: Transfer $5,000 to account 1122-3344-55"
        ... )
        >>> if verdict.is_approved:
        ...     print("Disbursement authorized:", verdict.transaction_record)
    """

    def __init__(
        self,
        policy: SecurityPolicy = SecurityPolicy.STRICT,
        per_transaction_limit: float = 25000.0,
        daily_limit: float = 100000.0,
        raise_on_violation: bool = False,
    ):
        self.policy = policy
        self.raise_on_violation = raise_on_violation
        self.anchor = FinancialStateAnchor(
            per_transaction_limit=per_transaction_limit,
            daily_limit=daily_limit,
        )
        self.agent = FinancialAgent(
            state_anchor=self.anchor,
            enable_civ_firewall=(policy == SecurityPolicy.STRICT),
        )

    def register_payee(
        self,
        account_number: str,
        name: str,
        category: str = "general_vendor",
        routing_number: str = "000000000",
        max_single_disbursement: float = 25000.0,
    ) -> None:
        """Register a pre-approved vendor payee in the immutable state anchor."""
        payee_id = f"PAYEE-{len(self.anchor.verified_payees) + 1:02d}"
        self.anchor.verified_payees[account_number] = PayeeAccount(
            payee_id=payee_id,
            name=name,
            account_number=account_number,
            routing_number=routing_number,
            category=category,
            max_single_disbursement=max_single_disbursement,
        )
        # Seed into AuthGraph DAG as authenticated root
        self.agent.auth_graph.add_node(
            content=f"Immutable Payee Anchor: {name} ({account_number})",
            origin=SourceOrigin.SYSTEM_INSTRUCTION,
            is_authorized_root=True,
            node_id=f"root_payee_{payee_id}",
        )

    def _raise_violation_error(self, verdict: GuardVerdict) -> None:
        """Raise appropriate typed domain exception based on detected violations."""
        viol_str = " ".join(verdict.violations)
        if "NOT in verified payee registry" in viol_str:
            target = next((v.split("'")[1] for v in verdict.violations if "'" in v), "unknown")
            raise UnauthorizedPayeeError(target_account=target, details={"violations": verdict.violations})
        if any(keyword in viol_str.lower() for keyword in ["exceeds", "ceiling", "limit"]):
            raise DisbursementCeilingExceededError(
                amount=verdict.transaction_record.get("amount", 0.0) if verdict.transaction_record else 0.0,
                limit=self.anchor.per_transaction_limit,
                details={"violations": verdict.violations},
            )
        if any(keyword in viol_str.lower() for keyword in ["lineage", "ancestry", "untrusted or unauthorized"]):
            raise UntrustedLineageError(node_id=verdict.task_id, origin="untrusted", details={"violations": verdict.violations})
        if "directive" in viol_str.lower() or "imperative" in viol_str.lower():
            raise ImperativeDivergenceError(divergence_score=1.0, threshold=0.35, details={"violations": verdict.violations})
        raise InvariantViolationError(f"Security invariant violated: {viol_str}", details={"violations": verdict.violations})

    def protect(
        self,
        task_query: str,
        context: str,
        task_id: str = "TASK-AUTO",
        origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
        raise_on_violation: Optional[bool] = None,
    ) -> GuardVerdict:
        """Evaluate an incoming task and retrieved context through all defense tiers."""
        task_result = self.agent.handle_financial_task(
            task_id=task_id,
            task_query=task_query,
            retrieved_context=context,
            context_origin=origin,
        )
        verdict = GuardVerdict.from_task_result(task_result)

        should_raise = self.raise_on_violation if raise_on_violation is None else raise_on_violation
        if should_raise and not verdict.is_approved:
            self._raise_violation_error(verdict)

        return verdict

    def get_audit_ledger(self) -> List[Dict[str, Any]]:
        """Retrieve the immutable execution and audit ledger records."""
        return list(self.anchor.execution_ledger)

    def is_payee_registered(self, account_number: str) -> bool:
        """Check whether an account number is in the verified payee registry."""
        return self.anchor.is_payee_verified(account_number)

    def get_payee(self, account_number: str) -> Optional[PayeeAccount]:
        """Look up verified payee details by account number."""
        return self.anchor.get_payee(account_number)

    def list_payees(self) -> List[Dict[str, Any]]:
        """List all verified payees currently anchored in the registry."""
        return [
            {
                "payee_id": p.payee_id,
                "name": p.name,
                "account_number": p.account_number,
                "category": p.category,
                "max_single_disbursement": p.max_single_disbursement,
            }
            for p in self.anchor.verified_payees.values()
        ]

    def get_limits(self) -> Dict[str, float]:
        """Return the current transaction and daily disbursement limits."""
        return {
            "per_transaction_limit": self.anchor.per_transaction_limit,
            "daily_limit": self.anchor.daily_limit,
        }
