"""Retrieval-Time Task Alignment Gate & Task Shield (ACL 2025).

Evaluates whether retrieved memories align with the active user task instruction
or attempt to hijack execution by introducing unsanctioned imperative directives.
Grounded in Task Shield (ACL 2025).
"""

import re
from typing import List, Tuple, Dict, Any
from agent_poi.memory.schema import MemoryItem, FirewallDecision, FirewallStatus


class TaskShieldGate:
    """Task Shield (ACL 2025) Retrieval-Time Task Alignment Gate.

    Evaluates candidate memory chunks against user task queries using:
    1. Semantic Task Relevance: cos(E(m), E(q))
    2. Imperative Directive Divergence: Penalizes memory containing unsolicited action commands.
    """

    IMPERATIVE_TRIGGERS = [
        r"\b(?:transfer|wire|send|remit|pay|disburse)(?:ment)?(?:_\w+)?\b.*?\b(?:funds|money|amount|account|\$|\d+)\b",
        r"\b(?:delete|drop|purge|wipe|remove_all)(?:_\w+)?\b.*?\b(?:record|table|users|database|all|\w+)\b",
        r"\b(?:override|bypass|disregard|ignore)\b.*?\b(?:limit|policy|rule|standard|safeguard)\b",
        r"\b(?:must|shall|execute|immediately|system instruction|urgent)\b",
    ]

    QUERY_ACTION_TRIGGERS = [
        r"\b(?:pay|payment|process|disburse|disbursement|wire|transfer|remit|remittance|settle|settlement|execute|delete|purge)\b",
    ]

    def __init__(self, relevance_threshold: float = 0.0, max_divergence_risk: float = 0.35):
        self.relevance_threshold = relevance_threshold
        self.max_divergence_risk = max_divergence_risk
        self.pattern = re.compile("|".join(self.IMPERATIVE_TRIGGERS), re.IGNORECASE)
        self.query_pattern = re.compile("|".join(self.QUERY_ACTION_TRIGGERS), re.IGNORECASE)

    def _compute_ngram_similarity(self, text_a: str, text_b: str) -> float:
        """Normalized word and character trigram similarity proxy."""
        words_a = set(re.findall(r"\b\w+\b", text_a.lower()))
        words_b = set(re.findall(r"\b\w+\b", text_b.lower()))

        if not words_a or not words_b:
            return 0.0

        word_sim = len(words_a.intersection(words_b)) / len(words_a.union(words_b))

        def trigrams(s):
            s = s.lower()
            return set(s[i : i + 3] for i in range(max(0, len(s) - 2)))

        tri_a = trigrams(text_a)
        tri_b = trigrams(text_b)
        tri_sim = len(tri_a.intersection(tri_b)) / max(1, len(tri_a.union(tri_b)))

        return float(0.6 * word_sim + 0.4 * tri_sim)

    def evaluate_chunk(self, query: str, memory_chunk: str) -> Dict[str, Any]:
        """Evaluate chunk against query using Task Shield dual-scoring."""
        relevance = self._compute_ngram_similarity(query, memory_chunk)
        matches = self.pattern.findall(memory_chunk)
        directive_density = min(1.0, len(matches) * 0.45)

        # Check if user query explicitly asked for action/settlement
        query_action_matches = self.query_pattern.findall(query)
        is_query_action = len(query_action_matches) > 0

        # Divergence penalty applies only if memory commands action unprompted by user
        if not is_query_action and directive_density > 0:
            divergence_penalty = directive_density * 0.85
        else:
            divergence_penalty = 0.0

        task_alignment_score = max(0.0, relevance - divergence_penalty)
        
        # In Task Shield, divergence penalty is the primary gatekeeper against sleeper payloads
        is_admitted = (divergence_penalty <= self.max_divergence_risk) and (relevance >= self.relevance_threshold)

        reasons = []
        if divergence_penalty > 0.20:
            reasons.append(
                f"Action divergence detected (Imperative directive divergence detected: {divergence_penalty:.2f} > {self.max_divergence_risk:.2f}): unprompted tool commands in memory."
            )
        if self.relevance_threshold > 0 and relevance < self.relevance_threshold:
            reasons.append(
                f"Low semantic task relevance ({relevance:.2f} < {self.relevance_threshold:.2f})."
            )
        if is_admitted:
            reasons.append(
                f"Task alignment admitted (score {task_alignment_score:.2f}, divergence {divergence_penalty:.2f} <= {self.max_divergence_risk:.2f})"
            )

        return {
            "admitted": is_admitted,
            "relevance": round(relevance, 4),
            "divergence_penalty": round(divergence_penalty, 4),
            "task_alignment_score": round(task_alignment_score, 4),
            "action": "PASS" if is_admitted else "GATE_SUPPRESS",
            "reasons": reasons,
        }


class AlignmentGate:
    """Retrieval-time task alignment filter incorporating Task Shield."""

    def __init__(
        self,
        min_task_similarity: float = 0.0,
        max_divergence_penalty: float = 0.35,
        alpha_penalty: float = 0.60,
    ):
        self.task_shield = TaskShieldGate(
            relevance_threshold=min_task_similarity,
            max_divergence_risk=max_divergence_penalty,
        )
        self.alpha = alpha_penalty

    def evaluate_retrieval_alignment(
        self,
        query: str,
        item: MemoryItem,
        tau_retrieval: float = 0.40,
    ) -> Tuple[bool, float, List[str]]:
        """Evaluate memory item using Task Shield dual scoring."""
        eval_res = self.task_shield.evaluate_chunk(query, item.content)
        is_safe = eval_res["admitted"]
        reasons = eval_res["reasons"]

        # Adjust trust score based on divergence penalty
        penalty_factor = max(0.0, 1.0 - (self.alpha * eval_res["divergence_penalty"]))
        adjusted_trust = item.trust_score * penalty_factor

        is_admitted = is_safe and (adjusted_trust >= tau_retrieval)
        return is_admitted, round(adjusted_trust, 4), reasons

    def filter_context(
        self,
        query: str,
        candidates: List[MemoryItem],
        tau_retrieval: float = 0.40,
    ) -> Tuple[List[MemoryItem], List[FirewallDecision]]:
        admitted: List[MemoryItem] = []
        decisions: List[FirewallDecision] = []

        for item in candidates:
            safe, adj_score, reasons = self.evaluate_retrieval_alignment(query, item, tau_retrieval)
            status = FirewallStatus.ALLOWED if safe else FirewallStatus.QUARANTINED

            decisions.append(
                FirewallDecision(
                    status=status,
                    trust_score=adj_score,
                    reasons=reasons,
                    item_id=item.id,
                    content_snippet=item.content[:80] + "...",
                    alignment_score=adj_score,
                )
            )

            if safe:
                admitted.append(item)

        return admitted, decisions
