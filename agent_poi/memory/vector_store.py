"""Vector Memory Store with integrated active memory and quarantine partitions."""

import math
import re
from typing import Dict, List, Optional, Tuple
from agent_poi.memory.schema import MemoryItem, FirewallStatus, FirewallDecision


class VectorMemoryStore:
    """Self-contained local vector memory repository.

    Provides cosine similarity retrieval across active memories while keeping
    quarantined or blocked items safely isolated for security audits.
    """

    def __init__(self, use_chroma: bool = False, persist_dir: Optional[str] = None):
        self.use_chroma = use_chroma
        self.persist_dir = persist_dir
        
        # Primary storage structures
        self.active_store: Dict[str, MemoryItem] = {}
        self.quarantine_vault: Dict[str, Tuple[MemoryItem, FirewallDecision]] = {}
        self.blocked_audit_log: List[FirewallDecision] = []

    def _tokenize(self, text: str) -> Dict[str, float]:
        """Simple TF representation for fast local cosine similarity."""
        words = re.findall(r"\b\w{2,}\b", text.lower())
        if not words:
            return {}
        tf: Dict[str, float] = {}
        for w in words:
            tf[w] = tf.get(w, 0.0) + 1.0
        # Normalize
        norm = math.sqrt(sum(v * v for v in tf.values()))
        return {k: v / norm for k, v in tf.items()}

    def _cosine_similarity(self, tf1: Dict[str, float], tf2: Dict[str, float]) -> float:
        """Compute cosine similarity between two normalized TF vectors."""
        score = 0.0
        for term, val in tf1.items():
            if term in tf2:
                score += val * tf2[term]
        return float(score)

    def add_active(self, item: MemoryItem) -> None:
        """Store item in the active memory partition."""
        item.status = FirewallStatus.ALLOWED
        self.active_store[item.id] = item

    def add_quarantine(self, item: MemoryItem, decision: FirewallDecision) -> None:
        """Store item in the isolated quarantine vault."""
        item.status = FirewallStatus.QUARANTINED
        self.quarantine_vault[item.id] = (item, decision)

    def log_blocked(self, decision: FirewallDecision) -> None:
        """Log blocked attempt for audit trail."""
        self.blocked_audit_log.append(decision)

    def query(self, query_text: str, k: int = 5, min_trust: float = 0.0) -> List[MemoryItem]:
        """Retrieve top-k most relevant memories from the active partition."""
        if not self.active_store:
            return []

        q_tf = self._tokenize(query_text)
        scored_items: List[Tuple[float, MemoryItem]] = []

        for item in self.active_store.values():
            if item.trust_score < min_trust:
                continue
            item_tf = self._tokenize(item.content)
            sim = self._cosine_similarity(q_tf, item_tf)
            # Combine semantic similarity with trust score weight
            effective_rank = 0.7 * sim + 0.3 * item.trust_score
            scored_items.append((effective_rank, item))

        # Sort descending
        scored_items.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored_items[:k]]

    def get_all_active(self) -> List[MemoryItem]:
        """Get all memories currently in active partition."""
        return list(self.active_store.values())

    def get_all_quarantined(self) -> List[Tuple[MemoryItem, FirewallDecision]]:
        """Get all quarantined memories and their diagnostic decisions."""
        return list(self.quarantine_vault.values())

    def get_audit_log(self) -> List[FirewallDecision]:
        """Get the full security audit log."""
        return list(self.blocked_audit_log)

    def clear(self) -> None:
        """Clear memory contents."""
        self.active_store.clear()
        self.quarantine_vault.clear()
        self.blocked_audit_log.clear()
