"""Autonomous Financial Agent with Dual-State Epistemic Consensus (DSEC).

Coordinates financial task execution, Task Shield retrieval gating,
AuthGraph cryptographic provenance verification, and safe disbursement tool execution.
"""

import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from agent_poi.financial.state_anchor import FinancialStateAnchor
from agent_poi.financial.invariant_verifier import InvariantVerifier, InvariantVerificationResult
from agent_poi.financial.delta_extractor import ContextualFinancialDelta
from agent_poi.financial.logger import get_financial_logger, log_audit_event
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
)
from agent_poi.core.alignment_gate import TaskShieldGate
from agent_poi.core.taint_tracker import AuthGraphDAG
from agent_poi.core.config_loader import get_financial_domain_config
from agent_poi.memory.schema import SourceOrigin


@dataclass
class FinancialTaskResult:
    task_id: str
    query: str
    context_admitted: bool
    context_decision: str
    violations: List[str] = field(default_factory=list)
    action_taken: str = "none"
    disbursement_executed: bool = False
    transaction_record: Optional[Dict[str, Any]] = None
    is_malicious_divergence: bool = False
    agent_narrative: str = ""
    task_shield_score: Optional[float] = None
    authgraph_hash: Optional[str] = None


class FinancialAgent:
    """Enterprise financial agent with invariant conservation, Task Shield, and AuthGraph DAG."""

    def __init__(
        self,
        state_anchor: Optional[FinancialStateAnchor] = None,
        enable_civ_firewall: bool = True,
        raise_on_violation: bool = False,
        max_divergence_risk: Optional[float] = None,
    ):
        self.logger = get_financial_logger("agent_poi.financial.agent")
        self.anchor = state_anchor or FinancialStateAnchor()
        self.verifier = InvariantVerifier(self.anchor)

        fin_cfg = get_financial_domain_config()
        cfg_divergence = fin_cfg.get("max_divergence_risk", 0.35)
        divergence_limit = max_divergence_risk if max_divergence_risk is not None else cfg_divergence

        self.task_shield = TaskShieldGate(
            relevance_threshold=fin_cfg.get("relevance_threshold", 0.0),
            max_divergence_risk=divergence_limit,
        )
        self.auth_graph = AuthGraphDAG()
        self.enable_civ = enable_civ_firewall
        self.raise_on_violation = raise_on_violation

        # Seed authenticated root nodes in AuthGraph for all verified payees in S0
        for payee_acc, payee in self.anchor.verified_payees.items():
            self.auth_graph.add_node(
                content=f"Immutable Payee Anchor: {payee.name} ({payee_acc})",
                origin=SourceOrigin.SYSTEM_INSTRUCTION,
                is_authorized_root=True,
                node_id=f"root_payee_{payee.payee_id}",
            )

    # ─────────────────────────────────────────────────────────────
    # Safe Tool Operations (Sink Gate)
    # ─────────────────────────────────────────────────────────────

    def _validate_sink_invariants(
        self,
        to_account: str,
        amount: float,
        claimed_auth: Optional[str],
        contributing_node_ids: Optional[List[str]],
    ) -> Tuple[bool, List[str]]:
        """Validate disbursement against immutable anchor invariants and cryptographic ancestry."""
        violations = []
        is_valid, inv_violations = self.anchor.validate_disbursement(to_account, amount, claimed_auth)
        violations.extend(inv_violations)

        if self.enable_civ:
            if not contributing_node_ids:
                violations.append("Sink rejected: No contributing node IDs provided for provenance validation.")
                is_valid = False
            else:
                auth_ok, auth_violations = self.auth_graph.verify_sink_authorization(
                    contributing_node_ids=contributing_node_ids,
                    required_root_authority=SourceOrigin.SYSTEM_INSTRUCTION,
                )
                if not auth_ok:
                    violations.extend(auth_violations)
                    is_valid = False

        return is_valid, violations

    def _format_amount(self, amount: Any) -> str:
        """Safely format amount as currency string, handling non-numeric or special floats."""
        is_num = isinstance(amount, (int, float)) and not isinstance(amount, bool)
        if is_num and not (math.isnan(amount) or math.isinf(amount)):
            return f"${amount:.2f}"
        return f"'{amount}'"

    def _handle_blocked_disbursement(
        self, to_account: str, amount: float, invoice_id: str, violations: List[str]
    ) -> Dict[str, Any]:
        """Record and log an invariant-blocked disbursement attempt."""
        amt_str = self._format_amount(amount)
        record = self.anchor.record_disbursement(
            to_account=to_account,
            amount=amount,
            invoice_id=invoice_id,
            status="BLOCKED_INVARIANT_VIOLATION",
            reason="; ".join(violations),
        )
        log_audit_event(
            self.logger,
            "DISBURSEMENT_BLOCKED",
            f"Rejected {amt_str} to {to_account}: {'; '.join(violations)}",
            {"violations": violations, "account": to_account, "amount": amount},
        )
        return {
            "success": False,
            "executed": False,
            "error": "Disbursement rejected by Epistemic Invariant Law.",
            "violations": violations,
            "record": record,
        }

    def _handle_executed_disbursement(
        self, to_account: str, amount: float, invoice_id: str
    ) -> Dict[str, Any]:
        """Record and log an authorized (or baseline undefended) disbursement execution."""
        amt_str = self._format_amount(amount)
        status = "EXECUTED_BENIGN" if self.anchor.is_payee_verified(to_account) else "EXECUTED_MALICIOUS_HIJACK"
        record = self.anchor.record_disbursement(
            to_account=to_account,
            amount=amount,
            invoice_id=invoice_id,
            status=status,
            reason="Executed without invariant enforcement" if not self.enable_civ else "Passed verified invariants",
        )
        log_audit_event(
            self.logger,
            "DISBURSEMENT_SUCCESS" if status == "EXECUTED_BENIGN" else "DISBURSEMENT_HIJACK_BASELINE",
            f"Executed {amt_str} to {to_account} (status: {status})",
            {"account": to_account, "amount": amount, "status": status},
        )
        return {
            "success": True,
            "executed": True,
            "message": f"Successfully processed disbursement of {amt_str} to {to_account}.",
            "record": record,
        }

    def process_disbursement(
        self,
        to_account: str,
        amount: float,
        invoice_id: str,
        claimed_auth: Optional[str] = None,
        contributing_node_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute a funds disbursement subject to strict invariant and AuthGraph validation."""
        is_valid, violations = self._validate_sink_invariants(
            to_account, amount, claimed_auth, contributing_node_ids
        )
        if not is_valid and self.enable_civ:
            if self.raise_on_violation:
                if not self.anchor.is_payee_verified(to_account):
                    raise UnauthorizedPayeeError(to_account, details={"violations": violations})
                if isinstance(amount, (int, float)) and amount > self.anchor.per_transaction_limit:
                    raise DisbursementCeilingExceededError(amount, self.anchor.per_transaction_limit, details={"violations": violations})
                raise InvariantViolationError("; ".join(violations), details={"violations": violations})
            return self._handle_blocked_disbursement(to_account, amount, invoice_id, violations)
        return self._handle_executed_disbursement(to_account, amount, invoice_id)

    # ─────────────────────────────────────────────────────────────
    # Task Execution Loop
    # ─────────────────────────────────────────────────────────────

    def _evaluate_task_gates(
        self, task_query: str, retrieved_context: str
    ) -> Tuple[bool, str, List[str], Optional[float]]:
        """Evaluate Task Shield retrieval gate and Contextual Invariant Verification."""
        if not self.enable_civ:
            return True, "ALLOWED", [], None

        violations = []
        ts_eval = self.task_shield.evaluate_chunk(task_query, retrieved_context)
        if not ts_eval["admitted"]:
            violations.extend(ts_eval["reasons"])

        civ_res = self.verifier.verify_text(retrieved_context)
        violations.extend(civ_res.violations)

        context_admitted = ts_eval["admitted"] and civ_res.is_admitted
        context_decision = civ_res.decision if ts_eval["admitted"] else "QUARANTINED"
        return context_admitted, context_decision, violations, ts_eval["task_alignment_score"]

    def _resolve_contributing_nodes(
        self,
        task_id: str,
        delta: Any,
        context_node_id: str,
        context_admitted: bool,
        civ_violations: List[str],
    ) -> List[str]:
        """Determine contributing nodes for cryptographic provenance validation."""
        if (
            self.enable_civ
            and context_admitted
            and not civ_violations
            and self.anchor.is_payee_verified(delta.target_account)
        ):
            payee = self.anchor.get_payee(delta.target_account)
            root_node_id = f"root_payee_{payee.payee_id}"
            verified_action = self.auth_graph.add_node(
                content=f"Verified consensus disbursement: {delta.target_account} ${delta.amount:.2f}",
                origin=SourceOrigin.INTERNAL_TOOL,
                is_authorized_root=False,
                parent_ids=[root_node_id],
                node_id=f"action_{task_id}",
            )
            return [verified_action.node_id]
        return [context_node_id]

    def _dispatch_task_tool(
        self,
        task_id: str,
        delta: Any,
        context_node_id: str,
        context_admitted: bool,
        civ_violations: List[str],
    ) -> Tuple[bool, str, Optional[Dict[str, Any]], bool, str, List[str]]:
        """Execute or review financial tool action based on extracted delta."""
        if not (delta.intent == "disbursement" and delta.target_account and delta.amount):
            return False, "review_only", None, False, "Context reviewed. No valid disbursement action scheduled.", []

        contributing = self._resolve_contributing_nodes(
            task_id, delta, context_node_id, context_admitted, civ_violations
        )
        tool_res = self.process_disbursement(
            to_account=delta.target_account,
            amount=delta.amount,
            invoice_id=delta.invoice_id or f"AUTO-{task_id}",
            claimed_auth=delta.claimed_authority,
            contributing_node_ids=contributing if self.enable_civ else None,
        )
        done = tool_res["executed"]
        rec = tool_res["record"]
        tool_violations = tool_res.get("violations", [])

        if done and not self.anchor.is_payee_verified(delta.target_account):
            narrative = f"SECURITY BREACH: Unauthorized disbursement of ${delta.amount:.2f} sent to {delta.target_account}."
            return done, "process_disbursement", rec, True, narrative, tool_violations
        elif done:
            narrative = f"Completed verified disbursement of ${delta.amount:.2f} to {rec['payee_name']}."
            return done, "process_disbursement", rec, False, narrative, tool_violations
        else:
            all_reasons = civ_violations + tool_violations
            narrative = f"Disbursement blocked: {'; '.join(all_reasons)}"
            return done, "process_disbursement", rec, False, narrative, tool_violations

    def handle_financial_task(
        self,
        task_id: str,
        task_query: str,
        retrieved_context: str,
        context_origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
    ) -> FinancialTaskResult:
        """Process incoming financial instruction conditioned on retrieved memory/context."""
        task_query = str(task_query or "")
        retrieved_context = str(retrieved_context or "")
        context_node = self.auth_graph.add_node(
            content=retrieved_context,
            origin=context_origin,
            is_authorized_root=(context_origin == SourceOrigin.VERIFIED_USER),
            node_id=f"ctx_{task_id}",
        )

        admitted, decision, civ_violations, ts_score = self._evaluate_task_gates(
            task_query, retrieved_context
        )

        combined_text = f"{task_query} {retrieved_context if admitted else ''}"
        delta = self.verifier.extractor.extract(combined_text)

        done, action, rec, compromised, narrative, tool_violations = self._dispatch_task_tool(
            task_id, delta, context_node.node_id, admitted, civ_violations
        )

        all_violations = list(dict.fromkeys(civ_violations + tool_violations))

        # Update decision if sink blocked execution
        if action == "process_disbursement" and not done:
            has_critical = any("NOT in verified payee registry" in v for v in all_violations)
            has_invariant = any("INVARIANT VIOLATION" in v for v in all_violations)
            decision = "BLOCKED" if (has_critical or has_invariant) else "QUARANTINED"

        return FinancialTaskResult(
            task_id=task_id,
            query=task_query,
            context_admitted=admitted,
            context_decision=decision,
            violations=all_violations,
            action_taken=action,
            disbursement_executed=done,
            transaction_record=rec,
            is_malicious_divergence=compromised,
            agent_narrative=narrative,
            task_shield_score=ts_score,
            authgraph_hash=context_node.sha256_hash,
        )
