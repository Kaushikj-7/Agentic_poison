"""ACE: Two-Phase Abstract Planning to Concrete Subsumption Engine (NDSS 2026).

Decouples agent execution into:
Phase 1: Abstract intention synthesis derived strictly from authenticated user query and State Anchor S0.
Phase 2: Subsumption verification ensuring concrete tool invocations do not escalate authority or divert funds.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agent_poi.financial.state_anchor import FinancialStateAnchor


@dataclass(frozen=True)
class AbstractPlan:
    """Authorized high-level plan synthesized exclusively from authenticated user intent."""
    is_valid: bool
    allowed_action: str
    target_account: Optional[str]
    ceiling_amount: float
    authorized_payee_name: Optional[str] = None


@dataclass(frozen=True)
class SubsumptionVerdict:
    """Evaluation of whether a concrete action is subsumed by the abstract plan."""
    is_subsumed: bool
    violations: List[str] = field(default_factory=list)
    abstract_plan: Optional[AbstractPlan] = None
    concrete_action: Optional[Dict[str, Any]] = None


class ACEPlanner:
    """Enforces two-phase abstract planning and concrete tool subsumption verification."""

    def synthesize_abstract_plan(
        self, task_query: str, state_anchor: FinancialStateAnchor
    ) -> AbstractPlan:
        """Phase 1: Synthesize abstract execution bounds strictly from user query and anchor S0."""
        # Detect authorized payee from query and verified payee registry
        detected_account: Optional[str] = None
        detected_name: Optional[str] = None

        for acc, payee in state_anchor.verified_payees.items():
            if acc in task_query or payee.name.lower() in task_query.lower():
                detected_account = acc
                detected_name = payee.name
                break

        # Detect authorized ceiling amount from query
        amt_match = re.search(r"\$([0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?)", task_query)
        if amt_match:
            try:
                ceiling = float(amt_match.group(1).replace(",", ""))
            except ValueError:
                ceiling = state_anchor.per_transaction_limit
        else:
            ceiling = state_anchor.per_transaction_limit

        # Validate action intention
        query_lower = task_query.lower()
        is_disbursement = any(k in query_lower for k in ("pay", "disburse", "wire", "transfer", "settle", "invoice"))
        allowed_action = "disburse_funds" if is_disbursement else "read_only_inquiry"

        return AbstractPlan(
            is_valid=True,
            allowed_action=allowed_action,
            target_account=detected_account,
            ceiling_amount=ceiling,
            authorized_payee_name=detected_name,
        )

    def verify_subsumption(
        self, concrete_action: Dict[str, Any], abstract_plan: AbstractPlan
    ) -> SubsumptionVerdict:
        """Phase 2: Verify that concrete action parameters are strictly subsumed by the abstract plan."""
        violations: List[str] = []

        action_name = concrete_action.get("action", "")
        if action_name != abstract_plan.allowed_action:
            violations.append(
                f"LATTICE_SUBSUMPTION_FAIL: Concrete action '{action_name}' is not subsumed "
                f"by abstract authorized intent '{abstract_plan.allowed_action}'."
            )

        concrete_account = concrete_action.get("to_account", "")
        if abstract_plan.target_account and concrete_account != abstract_plan.target_account:
            violations.append(
                f"LATTICE_SUBSUMPTION_FAIL: Concrete action payee account '{concrete_account}' "
                f"diverges from abstract planned payee '{abstract_plan.target_account}'."
            )

        concrete_amount = concrete_action.get("amount", 0.0)
        if isinstance(concrete_amount, (int, float)) and concrete_amount > abstract_plan.ceiling_amount:
            violations.append(
                f"LATTICE_SUBSUMPTION_FAIL: Concrete disbursement amount ${concrete_amount:.2f} "
                f"exceeds abstract authorized ceiling (${abstract_plan.ceiling_amount:.2f})."
            )

        is_subsumed = len(violations) == 0
        return SubsumptionVerdict(
            is_subsumed=is_subsumed,
            violations=violations,
            abstract_plan=abstract_plan,
            concrete_action=concrete_action,
        )
