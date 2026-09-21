"""High-Level Public Facade for the AgentPOI Defense Framework.

Provides intuitive, high-level abstractions (FinancialGuard, SecurityPolicy,
and GuardVerdict) so engineers can protect autonomous financial agent workflows
with a clean, professional API without exposing low-level plumbing.
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from agent_poi.financial.financial_agent import FinancialAgent, FinancialTaskResult
from agent_poi.financial.state_anchor import FinancialStateAnchor, PayeeAccount
from agent_poi.memory.schema import SourceOrigin
from agent_poi.financial.exceptions import (
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
    UntrustedLineageError,
    ImperativeDivergenceError,
)
from agent_poi.core.prompt_locate import PromptLocate, RedactionResult
from agent_poi.core.causal_armor import CausalArmor, CausalDominanceVerdict
from agent_poi.core.ace_planner import ACEPlanner, AbstractPlan, SubsumptionVerdict


class SecurityPolicy(str, Enum):
    """Operational security policy for autonomous financial agents."""
    STRICT = "strict"          # Contextual Invariant Verification, Task Shield, and AuthGraph active
    DEFENSIVE = "strict"       # Alias for strict defense
    MONITORING = "monitoring"  # Invariant monitoring only; alerts logged without executing unauthorized disbursements
    PERMISSIVE = "permissive"  # Baseline evaluation mode (all context admitted)


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
            enable_civ_firewall=(policy in (SecurityPolicy.STRICT, SecurityPolicy.DEFENSIVE)),
        )
        self.prompt_locator = PromptLocate()
        self.causal_armor = CausalArmor()
        self.ace_planner = ACEPlanner()

    def register_payee(
        self,
        account_number: str,
        name: str,
        category: str = "general_vendor",
        routing_number: str = "000000000",
        max_single_disbursement: float = 25000.0,
    ) -> None:
        """Register a pre-approved vendor payee in the immutable state anchor."""
        if account_number in self.anchor.verified_payees:
            payee_id = self.anchor.verified_payees[account_number].payee_id
        else:
            payee_id = f"PAYEE-{len(self.anchor.verified_payees) + 1:02d}"
        self.anchor.verified_payees[account_number] = PayeeAccount(
            payee_id=payee_id,
            name=name,
            account_number=account_number,
            routing_number=routing_number,
            category=category,
            max_single_disbursement=max_single_disbursement,
        )
        # Seed into AuthGraph DAG as authenticated root if not already registered
        nid = f"root_payee_{payee_id}"
        if nid not in self.agent.auth_graph.nodes:
            self.agent.auth_graph.add_node(
                content=f"Immutable Payee Anchor: {name} ({account_number})",
                origin=SourceOrigin.SYSTEM_INSTRUCTION,
                is_authorized_root=True,
                node_id=nid,
            )

    def _raise_violation_error(self, verdict: GuardVerdict) -> None:
        """Raise appropriate typed domain exception based on detected violations."""
        viol_str = " ".join(verdict.violations) if verdict.violations else ""
        if "NOT in verified payee registry" in viol_str:
            target = next((v.split("'")[1] for v in verdict.violations if "'" in v), "unknown")
            raise UnauthorizedPayeeError(target_account=target, details={"violations": verdict.violations})
        if any(keyword in viol_str.lower() for keyword in ["exceeds", "ceiling", "limit"]):
            raw_amt = verdict.transaction_record.get("amount") if verdict.transaction_record else 0.0
            raise DisbursementCeilingExceededError(
                amount=float(raw_amt or 0.0),
                limit=self.anchor.per_transaction_limit,
                details={"violations": verdict.violations},
            )
        if any(keyword in viol_str.lower() for keyword in ["lineage", "ancestry", "untrusted or unauthorized"]):
            raise UntrustedLineageError(node_id=verdict.task_id, origin="untrusted", details={"violations": verdict.violations})
        if "directive" in viol_str.lower() or "imperative" in viol_str.lower():
            raise ImperativeDivergenceError(divergence_score=1.0, threshold=0.35, details={"violations": verdict.violations})
        msg = (
            f"Security invariant violated: {viol_str}"
            if viol_str
            else f"Security policy rejected task '{verdict.task_id}' (status: {verdict.status})"
        )
        raise InvariantViolationError(msg, details={"violations": verdict.violations})

    def protect(
        self,
        task_query: str,
        context: str,
        task_id: str = "TASK-AUTO",
        origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
        raise_on_violation: Optional[bool] = None,
    ) -> GuardVerdict:
        """Evaluate an incoming task and retrieved context through all defense tiers."""
        task_query = str(task_query or "")
        context = str(context or "")
        task_result = self.agent.handle_financial_task(
            task_id=task_id,
            task_query=task_query,
            retrieved_context=context,
            context_origin=origin,
        )
        verdict = GuardVerdict.from_task_result(task_result)
        if self.policy == SecurityPolicy.MONITORING and not verdict.is_approved:
            verdict.disbursement_executed = False
            verdict.action_taken = "monitoring_logged"

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

    def register_purchase_order(
        self,
        po_number: str,
        vendor_account: str,
        authorized_amount: float,
        goods_receipt_confirmed: bool = False,
    ) -> None:
        """Register a pre-approved Purchase Order for 3-Way Matching enforcement.

        Once registered, use protect_with_po() to enforce that invoice amounts
        match the PO commitment and goods receipt is confirmed before disbursement.

        Args:
            po_number: Unique PO reference number (e.g., "PO-2026-001").
            vendor_account: Account number authorized for this PO.
            authorized_amount: Maximum disbursable amount for this PO.
            goods_receipt_confirmed: Whether goods/services have been received.
        """
        self.anchor.register_purchase_order(
            po_number=po_number,
            vendor_account=vendor_account,
            authorized_amount=authorized_amount,
            goods_receipt_confirmed=goods_receipt_confirmed,
        )

    def check_idempotency_key(self, key: str, tx_id: str) -> bool:
        """Check if an idempotency key is fresh (not a replay).

        Returns True if this is the first use of the key (safe to proceed).
        Returns False if the key was already seen — replay attack or duplicate.

        Args:
            key: Unique idempotency key (e.g., invoice_id hash).
            tx_id: Transaction identifier for this key's first use.
        """
        return self.anchor.register_idempotency_key(key, tx_id)

    def _validate_po_preflight(
        self,
        purchase_order_number: str,
        invoice_amount: float,
        vendor_account: str,
        idempotency_key: Optional[str],
        task_id: str,
    ) -> List[str]:
        """Validate idempotency freshness and 3-Way Matching constraints."""
        violations: List[str] = []
        if idempotency_key is not None:
            if not self.anchor.check_idempotency_key(idempotency_key, task_id):
                violations.append(
                    f"IDEMPOTENCY VIOLATION: Key '{idempotency_key}' was already processed. "
                    "Duplicate invoice submission or replay attack detected."
                )

        if not violations:
            _, match_violations = self.anchor.validate_three_way_match(
                po_number=purchase_order_number,
                invoice_amount=invoice_amount,
                to_account=vendor_account,
                mark_settled=False,
            )
            violations.extend(match_violations)
        return violations

    def _reconcile_context_with_po(
        self, context: str, vendor_account: str, invoice_amount: float
    ) -> List[str]:
        """Cross-reconcile context extracted delta with validated PO parameters."""
        violations = []
        delta = self.agent.delta_extractor.extract(context)
        if delta.target_account and delta.target_account != vendor_account:
            violations.append(
                f"CONTEXT DIVERGENCE: Context target account '{delta.target_account}' "
                f"diverges from validated PO vendor account '{vendor_account}'."
            )
        if delta.amount is not None:
            if math.isnan(delta.amount) or math.isinf(delta.amount):
                violations.append("CONTEXT DIVERGENCE: Context disbursement amount is non-finite.")
            elif delta.amount > invoice_amount + 0.01:
                violations.append(
                    f"CONTEXT DIVERGENCE: Context disbursement amount ${delta.amount:.2f} "
                    f"diverges from validated PO invoice amount ${invoice_amount:.2f}."
                )
        return violations

    def protect_with_po(
        self,
        task_query: str,
        context: str,
        purchase_order_number: str,
        invoice_amount: float,
        vendor_account: str,
        idempotency_key: Optional[str] = None,
        task_id: str = "TASK-AUTO",
        origin: Optional[SourceOrigin] = None,
        raise_on_violation: Optional[bool] = None,
    ) -> GuardVerdict:
        """Extended protection with 3-Way Matching, context reconciliation, and idempotency."""
        effective_origin = origin or SourceOrigin.UNTRUSTED_WEB
        extra_violations = self._validate_po_preflight(
            purchase_order_number=purchase_order_number,
            invoice_amount=invoice_amount,
            vendor_account=vendor_account,
            idempotency_key=idempotency_key,
            task_id=task_id,
        )

        if not extra_violations:
            extra_violations.extend(
                self._reconcile_context_with_po(context, vendor_account, invoice_amount)
            )

        if extra_violations:
            verdict = GuardVerdict(
                is_approved=False,
                status="BLOCKED",
                task_id=task_id,
                violations=extra_violations,
                action_taken="blocked_pre_flight",
                disbursement_executed=False,
            )
            should_raise = self.raise_on_violation if raise_on_violation is None else raise_on_violation
            if should_raise:
                self._raise_violation_error(verdict)
            return verdict

        verdict = self.protect(
            task_query=task_query,
            context=context,
            task_id=task_id,
            origin=effective_origin,
            raise_on_violation=raise_on_violation,
        )
        if verdict.is_approved:
            if idempotency_key is not None:
                self.anchor.register_idempotency_key(idempotency_key, task_id)
            if purchase_order_number in self.anchor.purchase_orders:
                self.anchor.purchase_orders[purchase_order_number]["is_settled"] = True
        return verdict

    def verify_invoice_and_disburse(
        self,
        task_query: str,
        context: str,
        purchase_order_number: str,
        invoice_amount: float,
        vendor_account: str,
        idempotency_key: Optional[str] = None,
        task_id: str = "TASK-AUTO",
        origin: Optional[SourceOrigin] = None,
        raise_on_violation: Optional[bool] = None,
    ) -> GuardVerdict:
        """Single-call high-level API to verify invoice with PO and disburse under fail-closed invariants."""
        return self.protect_with_po(
            task_query=task_query,
            context=context,
            purchase_order_number=purchase_order_number,
            invoice_amount=invoice_amount,
            vendor_account=vendor_account,
            idempotency_key=idempotency_key,
            task_id=task_id,
            origin=origin,
            raise_on_violation=raise_on_violation,
        )

    def protect_with_capseal(
        self,
        task_query: str,
        context: str,
        capability_token_id: str,
        expected_amount: float,
        expected_recipient: str,
        task_id: str = "TASK-AUTO",
        origin: Optional[SourceOrigin] = None,
        raise_on_violation: Optional[bool] = None,
    ) -> GuardVerdict:
        """Protect financial disbursement using CapSeal capability mediation tokens (arXiv:2604.16762)."""
        extra_violations = []
        token_ok, token_violations = self.anchor.validate_capability_token(
            token_id=capability_token_id,
            to_account=expected_recipient,
            amount=expected_amount,
        )
        if not token_ok:
            extra_violations.extend(token_violations)

        if extra_violations:
            verdict = GuardVerdict(
                is_approved=False,
                status="BLOCKED",
                task_id=task_id,
                violations=extra_violations,
                action_taken="blocked_capseal_preflight",
                disbursement_executed=False,
            )
            should_raise = self.raise_on_violation if raise_on_violation is None else raise_on_violation
            if should_raise:
                self._raise_violation_error(verdict)
            return verdict

        verdict = self.protect(
            task_query=task_query,
            context=context,
            task_id=task_id,
            origin=origin or SourceOrigin.UNTRUSTED_WEB,
            raise_on_violation=raise_on_violation,
        )
        if verdict.is_approved:
            self.anchor.consume_capability_token(capability_token_id)
        return verdict

    def sanitize_context_surgical(self, text: str) -> RedactionResult:
        """Surgically excise imperative injection spans while preserving legitimate financial data (arXiv:2510.12252)."""
        return self.prompt_locator.locate_and_redact(text)

    def evaluate_causal_dominance(
        self, user_goal: str, untrusted_context: str, proposed_action: str
    ) -> CausalDominanceVerdict:
        """Assess causal dominance ratio to prevent untrusted context hijacking (arXiv:2602.07918)."""
        return self.causal_armor.evaluate_dominance(
            user_goal=user_goal,
            untrusted_context=untrusted_context,
            proposed_action=proposed_action,
        )

    def verify_action_subsumption(
        self, task_query: str, concrete_action: Dict[str, Any]
    ) -> SubsumptionVerdict:
        """Verify concrete tool action parameters are strictly subsumed by abstract authorized plan (NDSS 2026 ACE)."""
        abstract_plan = self.ace_planner.synthesize_abstract_plan(task_query, self.anchor)
        return self.ace_planner.verify_subsumption(concrete_action, abstract_plan)


