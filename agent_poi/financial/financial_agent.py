"""Autonomous Financial Agent with Dual-State Epistemic Consensus (DSEC).

Coordinates financial task execution, Task Shield retrieval gating,
AuthGraph cryptographic provenance verification, and safe disbursement tool execution.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from agent_poi.financial.state_anchor import FinancialStateAnchor
from agent_poi.financial.invariant_verifier import InvariantVerifier, InvariantVerificationResult
from agent_poi.financial.logger import get_financial_logger, log_audit_event
from agent_poi.financial.exceptions import (
    FinancialSecurityError,
    InvariantViolationError,
    UnauthorizedPayeeError,
    DisbursementCeilingExceededError,
)
from agent_poi.core.alignment_gate import TaskShieldGate
from agent_poi.core.taint_tracker import AuthGraphDAG
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
    ):
        self.logger = get_financial_logger("agent_poi.financial.agent")
        self.anchor = state_anchor or FinancialStateAnchor()
        self.verifier = InvariantVerifier(self.anchor)
        self.task_shield = TaskShieldGate(relevance_threshold=0.0, max_divergence_risk=0.50)
        self.auth_graph = AuthGraphDAG()
        self.enable_civ = enable_civ_firewall

        # Seed authenticated root nodes in AuthGraph for all verified payees in S0
        for payee_acc, payee in self.anchor.verified_payees.items():
            self.auth_graph.add_node(
                content=f"Immutable Payee Anchor: {payee.name} ({payee_acc})",
                origin=SourceOrigin.SYSTEM_INSTRUCTION,
                is_authorized_root=True,
                node_id=f"root_payee_{payee.payee_id}",
            )

    # ─────────────────────────────────────────────────────────────
    # Safe Tool Operations
    # ─────────────────────────────────────────────────────────────

    def process_disbursement(
        self,
        to_account: str,
        amount: float,
        invoice_id: str,
        claimed_auth: Optional[str] = None,
        contributing_node_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute a funds disbursement subject to strict invariant and AuthGraph validation."""
        violations = []

        # Invariant checks against S0
        is_valid, inv_violations = self.anchor.validate_disbursement(to_account, amount, claimed_auth)
        violations.extend(inv_violations)

        # AuthGraph Sink Invariant Validation
        if self.enable_civ and contributing_node_ids:
            auth_ok, auth_violations = self.auth_graph.verify_sink_authorization(
                contributing_node_ids=contributing_node_ids,
                required_root_authority=SourceOrigin.SYSTEM_INSTRUCTION,
            )
            if not auth_ok:
                violations.extend(auth_violations)
                is_valid = False

        if not is_valid and self.enable_civ:
            # Blocked by invariant conservation
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
                f"Rejected ${amount:.2f} to {to_account}: {'; '.join(violations)}",
                {"violations": violations, "account": to_account, "amount": amount},
            )
            return {
                "success": False,
                "executed": False,
                "error": "Disbursement rejected by Epistemic Invariant Law.",
                "violations": violations,
                "record": record,
            }

        # If CIV is disabled (baseline mode), unauthorized transfer executes
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
            f"Executed ${amount:.2f} to {to_account} (status: {status})",
            {"account": to_account, "amount": amount, "status": status},
        )
        return {
            "success": True,
            "executed": True,
            "message": f"Successfully processed disbursement of ${amount:.2f} to {to_account}.",
            "record": record,
        }

    # ─────────────────────────────────────────────────────────────
    # Task Execution Loop
    # ─────────────────────────────────────────────────────────────

    def handle_financial_task(
        self,
        task_id: str,
        task_query: str,
        retrieved_context: str,
        context_origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
    ) -> FinancialTaskResult:
        """Process incoming financial instruction conditioned on retrieved memory/context."""
        # 1. Register context node in AuthGraph
        is_user_root = context_origin == SourceOrigin.VERIFIED_USER
        context_node = self.auth_graph.add_node(
            content=retrieved_context,
            origin=context_origin,
            is_authorized_root=is_user_root,
            node_id=f"ctx_{task_id}",
        )

        task_shield_score = None
        civ_violations = []

        # 2. Task Shield Retrieval Gate Evaluation
        if self.enable_civ:
            ts_eval = self.task_shield.evaluate_chunk(task_query, retrieved_context)
            task_shield_score = ts_eval["task_alignment_score"]

            if not ts_eval["admitted"]:
                civ_violations.extend(ts_eval["reasons"])

            # 3. Contextual Invariant Verification (CIV)
            civ_res: InvariantVerificationResult = self.verifier.verify_text(retrieved_context)
            civ_violations.extend(civ_res.violations)

            context_admitted = ts_eval["admitted"] and civ_res.is_admitted
            context_decision = civ_res.decision if ts_eval["admitted"] else "QUARANTINED"
        else:
            context_admitted = True
            context_decision = "ALLOWED"

        # 4. Agent Planning & Invariant-Conserving Tool Dispatch
        combined_text = f"{task_query} {retrieved_context if context_admitted else ''}"
        delta = self.verifier.extractor.extract(combined_text)

        disbursement_done = False
        action_taken = "none"
        tx_record = None
        is_compromised = False
        narrative = ""

        if delta.intent == "disbursement" and delta.target_account and delta.amount:
            action_taken = "process_disbursement"

            # Determine contributing nodes for AuthGraph sink validation
            contributing_nodes = [context_node.node_id]
            if self.anchor.is_payee_verified(delta.target_account):
                payee = self.anchor.get_payee(delta.target_account)
                root_node_id = f"root_payee_{payee.payee_id}"
                contributing_nodes.append(root_node_id)
                # If context is verified and allowed against S0, authorize context node
                if self.enable_civ and civ_res and civ_res.is_admitted and not civ_violations:
                    context_node.is_authorized_root = True

            tool_res = self.process_disbursement(
                to_account=delta.target_account,
                amount=delta.amount,
                invoice_id=delta.invoice_id or f"AUTO-{task_id}",
                claimed_auth=delta.claimed_authority,
                contributing_node_ids=contributing_nodes if self.enable_civ else None,
            )
            disbursement_done = tool_res["executed"]
            tx_record = tool_res["record"]

            if disbursement_done and not self.anchor.is_payee_verified(delta.target_account):
                is_compromised = True
                narrative = f"SECURITY BREACH: Unauthorized disbursement of ${delta.amount:.2f} sent to {delta.target_account}."
            elif disbursement_done:
                narrative = f"Completed verified disbursement of ${delta.amount:.2f} to {tx_record['payee_name']}."
            else:
                all_reasons = civ_violations + tool_res.get("violations", [])
                narrative = f"Disbursement blocked: {'; '.join(all_reasons)}"
        else:
            action_taken = "review_only"
            narrative = "Context reviewed. No valid disbursement action scheduled."

        return FinancialTaskResult(
            task_id=task_id,
            query=task_query,
            context_admitted=context_admitted,
            context_decision=context_decision,
            violations=civ_violations,
            action_taken=action_taken,
            disbursement_executed=disbursement_done,
            transaction_record=tx_record,
            is_malicious_divergence=is_compromised,
            agent_narrative=narrative,
            task_shield_score=task_shield_score,
            authgraph_hash=context_node.sha256_hash,
        )
