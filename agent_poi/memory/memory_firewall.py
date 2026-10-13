"""Contextual Trust Propagation Memory Firewall.

Coordinates write-time CI decomposition, provenance taint tracking,
exponential trust decay, quarantine routing, and retrieval-time task alignment.
"""

from typing import Any, Dict, List, Optional, Tuple

from agent_poi.core.alignment_gate import AlignmentGate
from agent_poi.core.ci_decomposer import CIDecomposer
from agent_poi.core.taint_tracker import TaintTracker
from agent_poi.core.trust_scorer import TrustScorer
from agent_poi.memory.schema import (
    FirewallDecision,
    FirewallStatus,
    MemoryItem,
    SourceOrigin,
)
from agent_poi.memory.vector_store import VectorMemoryStore


class MemoryFirewall:
    """The central defense controller mediating all agent memory interactions."""

    def __init__(
        self,
        tau_threshold: float = 0.50,
        tau_critical: float = 0.25,
        lambda_decay: float = 2.5,
        enable_retrieval_gate: bool = True,
        vector_store: Optional[VectorMemoryStore] = None,
    ):
        self.ci_decomposer = CIDecomposer()
        self.trust_scorer = TrustScorer(
            lambda_decay=lambda_decay,
            tau_threshold=tau_threshold,
            tau_critical=tau_critical,
        )
        self.taint_tracker = TaintTracker()
        self.alignment_gate = AlignmentGate()
        self.enable_retrieval_gate = enable_retrieval_gate
        self.vector_store = vector_store or VectorMemoryStore()

    @property
    def tau(self) -> float:
        return self.trust_scorer.tau

    @tau.setter
    def tau(self, value: float):
        self.trust_scorer.tau = float(value)

    # ─────────────────────────────────────────────────────────────
    # Layer 1: Write-Time Ingestion Pipeline
    # ─────────────────────────────────────────────────────────────

    def _route_to_storage(
        self, decision: FirewallDecision, item: MemoryItem
    ) -> Tuple[FirewallDecision, Optional[MemoryItem]]:
        """Route evaluated memory item to active, quarantine, or blocked log."""
        if decision.status == FirewallStatus.ALLOWED:
            self.vector_store.add_active(item)
            return decision, item
        elif decision.status == FirewallStatus.QUARANTINED:
            self.vector_store.add_quarantine(item, decision)
            return decision, item
        self.vector_store.log_blocked(decision)
        return decision, None

    def _evaluate_and_record(
        self,
        item_id: str,
        content: str,
        origin: SourceOrigin,
        r_ci: float,
        reasons: List[str],
        parents: List[str],
    ) -> FirewallDecision:
        """Compute trust decision and record node in provenance DAG."""
        parent_scores = self.taint_tracker.get_parent_scores(parents)
        decision = self.trust_scorer.evaluate(
            item_id=item_id,
            content=content,
            origin=origin,
            r_ci=r_ci,
            reasons=reasons,
            parent_trust_scores=parent_scores,
        )
        direct_trust = self.trust_scorer.compute_direct_trust(origin, r_ci)
        self.taint_tracker.register_node(
            node_id=item_id,
            origin=origin,
            direct_trust=direct_trust,
            final_trust=decision.trust_score,
            parent_ids=parents,
        )
        return decision

    def ingest_memory(
        self,
        item_id: str,
        content: str,
        origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB,
        parent_ids: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[FirewallDecision, Optional[MemoryItem]]:
        """Evaluate and route an incoming context or memory candidate."""
        parents = parent_ids or []
        meta = metadata or {}

        ci_partition = self.ci_decomposer.decompose(content, declared_origin=origin)
        r_ci, reasons = self.ci_decomposer.compute_risk_score(ci_partition)
        decision = self._evaluate_and_record(item_id, content, origin, r_ci, reasons, parents)

        item = MemoryItem(
            id=item_id,
            content=content,
            origin=origin,
            parent_ids=parents,
            ci_partition=ci_partition,
            trust_score=decision.trust_score,
            status=decision.status,
            metadata=meta,
        )
        return self._route_to_storage(decision, item)

    # ─────────────────────────────────────────────────────────────
    # Layer 3: Retrieval-Time Alignment Pipeline
    # ─────────────────────────────────────────────────────────────

    def retrieve_context(
        self,
        query: str,
        k: int = 5,
    ) -> Tuple[List[MemoryItem], List[FirewallDecision]]:
        """Retrieve candidate memories and pass through the task alignment gate."""
        # Fetch raw candidates from active memory
        candidates = self.vector_store.query(query, k=k)

        if not self.enable_retrieval_gate or not candidates:
            # Bypass alignment gate if disabled
            decisions = [
                FirewallDecision(
                    status=FirewallStatus.ALLOWED,
                    trust_score=item.trust_score,
                    reasons=["Retrieved from active memory without alignment check"],
                    item_id=item.id,
                    content_snippet=item.content[:80] + "...",
                )
                for item in candidates
            ]
            return candidates, decisions

        # Pass through Retrieval-Time Task Alignment Gate
        admitted, decisions = self.alignment_gate.filter_context(query, candidates)
        return admitted, decisions

    def synthesize_summary_memory(
        self,
        summary_id: str,
        summary_content: str,
        source_memory_ids: List[str],
        origin: SourceOrigin = SourceOrigin.INTERNAL_TOOL,
    ) -> Tuple[FirewallDecision, Optional[MemoryItem]]:
        """Synthesize a new memory item from existing items, propagating ancestor taint."""
        return self.ingest_memory(
            item_id=summary_id,
            content=summary_content,
            origin=origin,
            parent_ids=source_memory_ids,
            metadata={"is_synthesized": True, "source_ids": source_memory_ids},
        )
