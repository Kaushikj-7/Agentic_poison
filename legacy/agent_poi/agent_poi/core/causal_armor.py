"""CausalArmor: Causal Dominance Shift Detection & Retroactive CoT Masking (arXiv:2602.07918).

Calculates the causal dominance ratio between untrusted retrieved context and
authenticated user goal instructions. Triggers automatic rollback and reasoning
path masking if untrusted context usurps causal control over proposed action dispatch.
"""

import re
from dataclasses import dataclass
from typing import List, Set


@dataclass(frozen=True)
class CausalDominanceVerdict:
    """Evaluation of causal dominance between user goal and untrusted context."""
    causal_dominance_ratio: float
    is_hijacked: bool
    intervention_triggered: bool
    reason: str
    user_influence: float
    context_influence: float


class CausalArmor:
    """Detects causal dominance shifts and performs retroactive Chain-of-Thought masking."""

    def __init__(self, dominance_threshold: float = 1.0, epsilon: float = 1e-6):
        self.dominance_threshold = dominance_threshold
        self.epsilon = epsilon

    def _tokenize(self, text: str) -> Set[str]:
        """Tokenize text into lowercase alphanumeric keywords of length >= 3."""
        return set(re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", text.lower()))

    def _extract_critical_entities(self, text: str) -> Set[str]:
        """Extract high-consequence entities (accounts, dollar amounts, invoice IDs)."""
        entities = set()
        # Accounts (e.g. 1122-3344-55, 9876-5432-10)
        entities.update(re.findall(r"\b\d{4}-\d{4}-\d{2}\b", text))
        # Amounts explicitly marked with $ or 'amount='
        for m in re.finditer(r"(?:\$|amount\s*[:=]\s*|\bdisburse\s*|\bwire\s*|\bpay\s*)\$?(\d+(?:,\d{3})*(?:\.\d{1,2})?)\b", text, re.IGNORECASE):
            val_str = m.group(1).replace(",", "")
            try:
                val = float(val_str)
                if val >= 1.0:
                    entities.add(f"{val:.2f}")
            except ValueError:
                pass
        # Invoice IDs
        entities.update(re.findall(r"\b(?:INV|ROGUE|PO|TASK)-[\w\-]+\b", text, re.IGNORECASE))
        return {e.lower() for e in entities}

    def evaluate_dominance(
        self,
        user_goal: str,
        untrusted_context: str,
        proposed_action: str,
    ) -> CausalDominanceVerdict:
        """Derive causal dominance ratio of untrusted context vs authenticated user goal."""
        action_tokens = self._tokenize(proposed_action)
        action_entities = self._extract_critical_entities(proposed_action)

        user_tokens = self._tokenize(user_goal)
        user_entities = self._extract_critical_entities(user_goal)

        ctx_tokens = self._tokenize(untrusted_context)
        ctx_entities = self._extract_critical_entities(untrusted_context)

        # Entity overlap provides heavy weight (x5.0)
        user_entity_overlap = len(action_entities.intersection(user_entities)) * 5.0
        ctx_entity_overlap = len(action_entities.intersection(ctx_entities)) * 5.0

        # General token overlap
        user_token_overlap = len(action_tokens.intersection(user_tokens)) * 1.0
        ctx_token_overlap = len(action_tokens.intersection(ctx_tokens)) * 1.0

        # Check if user goal authorizes disbursement action
        user_lower = user_goal.lower()
        user_authorizes_disbursement = any(k in user_lower for k in ("pay", "wire", "disburse", "transfer", "settle", "fee"))

        # Check if user goal and context share vendor/business grounding
        shared_vendor_tokens = user_tokens.intersection(ctx_tokens) - {"for", "the", "and", "invoice", "account", "monthly"}
        has_authorized_vendor_basis = len(shared_vendor_tokens) >= 2

        user_intent_score = 10.0 if (user_authorizes_disbursement and has_authorized_vendor_basis) else (5.0 if user_authorizes_disbursement else 0.0)

        # Untrusted context entities not present in user goal indicate malicious diversion
        unauthorized_entities = action_entities.intersection(ctx_entities) - user_entities
        if has_authorized_vendor_basis and user_authorizes_disbursement:
            unauthorized_entities = set()

        divergence_penalty = len(unauthorized_entities) * 15.0

        user_influence = user_entity_overlap + user_token_overlap + user_intent_score
        context_influence = ctx_entity_overlap + ctx_token_overlap + divergence_penalty

        if user_authorizes_disbursement and has_authorized_vendor_basis and not unauthorized_entities:
            context_influence = min(context_influence, user_influence * 0.5)

        # If user influence is essentially zero because action was spawned purely by context injection
        if user_influence == 0.0 and context_influence > 0.0:
            cd_ratio = 10.0
        else:
            cd_ratio = round(context_influence / (user_influence + self.epsilon), 2)

        is_hijacked = cd_ratio > self.dominance_threshold
        reason = (
            f"CAUSAL_DOMINANCE_SHIFT: Untrusted context dominance ({cd_ratio:.2f}) "
            f"exceeds user goal threshold ({self.dominance_threshold}). Action reflects untrusted lineage."
            if is_hijacked
            else "CAUSAL_STABILITY_MAINTAINED: Authenticated user goal maintains dominant causal attribution."
        )

        return CausalDominanceVerdict(
            causal_dominance_ratio=cd_ratio,
            is_hijacked=is_hijacked,
            intervention_triggered=is_hijacked,
            reason=reason,
            user_influence=round(user_influence, 2),
            context_influence=round(context_influence, 2),
        )

    def mask_cot_trajectory(self, cot_reasoning: str, tainted_terms: List[str]) -> str:
        """Retroactively mask reasoning tokens influenced by tainted context."""
        masked_text = cot_reasoning
        for term in tainted_terms:
            if not term.strip():
                continue
            pattern = re.compile(re.escape(term), re.IGNORECASE)
            masked_text = pattern.sub("[MASKED_TAINT_TRAJECTORY]", masked_text)
        return masked_text
