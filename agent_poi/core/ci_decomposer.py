"""Contextual Integrity (CI) Parameter Decomposer.

Extracts the CI 5-tuple: <Sender, Receiver, Subject, InfoType, TransmissionPrinciple>
and detects self-asserted transmission principles and context manipulation.
Grounded in Abdelnabi & Bagdasarian (arXiv:2605.17634, May 2026).
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from agent_poi.memory.schema import CIPartition, SourceOrigin


class CIDecomposer:
    """Parses text chunks into CI parameters and computes contextual integrity risk."""

    # Explicit self-asserted transmission principles & authority claims
    SELF_ASSERTED_AUTH_PATTERNS = [
        r"(?:user|admin|administrator|manager|owner)\s+(?:has\s+)?(?:pre-?approved|authorized|confirmed|granted|permitted|agreed)",
        r"(?:policy|security|compliance|system)\s+(?:override|bypass|exception|clearance)",
        r"(?:ignore|disregard|forget|bypass)\s+(?:all\s+)?(?:prior|previous|existing)\s+(?:instructions|rules|guidelines|safety|prompts)",
        r"(?:mandatory|strictly\s+required|authorized)\s+(?:to\s+execute|to\s+perform|to\s+transfer|to\s+delete)",
        r"(?:you\s+must\s+execute\s+this\s+without\s+(?:asking|confirming|prompting))",
        r"(?:do\s+not\s+(?:ask|prompt|notify|warn)\s+(?:the\s+)?user)",
        r"(?:per\s+(?:internal\s+)?policy|as\s+instructed\s+by\s+(?:it|admin|security))",
        r"(?:already\s+authenticated|pre-?validated|auto-?approved)",
    ]

    # Sensitive directive / action verbs targeting critical tools
    IMPERATIVE_VERBS = [
        r"\b(?:transfer|send|forward|dispatch|wire)(?:_\w+)?\b",
        r"\b(?:delete|drop|purge|wipe|remove|erase)(?:_\w+)?\b",
        r"\b(?:execute|run|trigger|launch|invoke|call)(?:_\w+)?\b",
        r"\b(?:overwrite|modify|update|replace|alter)(?:_\w+)?\b",
        r"\b(?:exfiltrate|upload|post|curl|wget|fetch)(?:_\w+)?\b",
    ]

    # Framing / Delimiter Hijacking markers
    FRAMING_PATTERNS = [
        r"(?:```(?:system|admin|bash|cmd|eval))",
        r"(?:<\|im_start\|>|<\|system\|>|\[INST\]|<system>|<<SYS>>)",
        r"(?:---+\s*(?:system|admin|override)\s*---+)",
        r"(?:NEW\s+INSTRUCTION:|SYSTEM\s+PROMPT:|IMPORTANT\s+UPDATE:)",
    ]

    def __init__(
        self,
        weight_auth: Optional[float] = None,
        weight_imperative: Optional[float] = None,
        weight_type_mismatch: Optional[float] = None,
        weight_framing: Optional[float] = None,
    ):
        from agent_poi.core.config_loader import get_trust_model_config
        cfg_weights = get_trust_model_config().get("risk_weights", {})

        self.w_auth = weight_auth if weight_auth is not None else cfg_weights.get("self_asserted_auth", 0.45)
        self.w_imp = weight_imperative if weight_imperative is not None else cfg_weights.get("imperative_density", 0.25)
        self.w_mismatch = weight_type_mismatch if weight_type_mismatch is not None else cfg_weights.get("type_mismatch", 0.20)
        self.w_frame = weight_framing if weight_framing is not None else cfg_weights.get("suspicious_framing", 0.10)

    def _detect_signals(self, content: str) -> Dict[str, Any]:
        """Extract self-asserted auth, imperative density, and framing indicators."""
        text_lower = content.lower()
        auth_matches = []
        for pattern in self.SELF_ASSERTED_AUTH_PATTERNS:
            found = re.findall(pattern, text_lower)
            if found:
                auth_matches.extend(found)

        words = re.findall(r"\b\w+\b", text_lower)
        total_words = max(1, len(words))
        imp_count = sum(len(re.findall(p, text_lower)) for p in self.IMPERATIVE_VERBS)

        frame_matches = []
        for pattern in self.FRAMING_PATTERNS:
            found = re.findall(pattern, content, flags=re.IGNORECASE)
            if found:
                frame_matches.extend(found)

        return {
            "self_asserted_auth": len(auth_matches) > 0,
            "auth_intensity": min(1.0, len(auth_matches) * 0.50),
            "auth_matches": auth_matches,
            "imp_count": imp_count,
            "imperative_ratio": min(1.0, (imp_count / total_words) * 5.0),
            "framing_matches": frame_matches,
            "framing_risk": min(1.0, len(frame_matches) * 0.50),
        }

    def decompose(self, content: str, declared_origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB) -> CIPartition:
        """Decompose text into Contextual Integrity parameters and extract risk indicators."""
        sig = self._detect_signals(content)
        sender = self._infer_sender(content, declared_origin)
        subject = self._infer_subject(content)
        info_type = self._infer_info_type(content, sig["imperative_ratio"])
        trans_principle = "self_asserted_override" if sig["self_asserted_auth"] else "normal_retrieval_flow"

        return CIPartition(
            sender=sender,
            recipient="agent_scaffolding",
            subject=subject,
            info_type=info_type,
            transmission_principle=trans_principle,
            self_asserted_auth=sig["self_asserted_auth"],
            imperative_ratio=sig["imperative_ratio"],
            framing_risk=sig["framing_risk"],
            raw_signals={
                "auth_intensity": sig["auth_intensity"],
                "auth_matches": sig["auth_matches"],
                "imp_count": sig["imp_count"],
                "framing_matches": sig["framing_matches"],
            },
        )

    def compute_risk_score(self, ci_partition: CIPartition) -> Tuple[float, List[str]]:
        """Compute the aggregate Contextual Integrity risk score R_ci in [0, 1]."""
        reasons = []

        signals = ci_partition.raw_signals
        auth_score = signals.get("auth_intensity", 0.0)
        if ci_partition.self_asserted_auth:
            reasons.append(f"Self-asserted authorization principle detected: {signals.get('auth_matches')}")

        imp_score = ci_partition.imperative_ratio
        if imp_score > 0.35:
            reasons.append(f"High imperative command verb density ({imp_score:.2f})")

        frame_score = ci_partition.framing_risk
        if frame_score > 0.0:
            reasons.append(f"Adversarial delimiter / prompt boundary framing detected ({frame_score:.2f})")

        # Type mismatch: declared as passive data / note but functions as executive instruction
        type_mismatch_score = 0.0
        if ci_partition.info_type == "executive_instruction":
            type_mismatch_score = 0.8
            reasons.append("Type mismatch: Content claims to be passive note but contains executive instructions")

        # Aggregate weighted CI risk score
        r_ci = (
            self.w_auth * auth_score
            + self.w_imp * imp_score
            + self.w_mismatch * type_mismatch_score
            + self.w_frame * frame_score
        )

        r_ci = float(min(1.0, max(0.0, r_ci)))
        return r_ci, reasons

    def _infer_sender(self, text: str, declared_origin: SourceOrigin) -> str:
        if declared_origin == SourceOrigin.VERIFIED_USER:
            return "verified_user"
        if re.search(r"\b(?:admin|system|root)\b", text, re.I):
            return "claimed_administrator"
        if declared_origin == SourceOrigin.UNTRUSTED_WEB:
            return "external_web_source"
        return str(declared_origin.value)

    def _infer_subject(self, text: str) -> str:
        if re.search(r"\b(?:transfer|fund|account|dollar|wire|bank|balance)\b", text, re.I):
            return "financial_state"
        if re.search(r"\b(?:delete|drop|table|record|user_data|wipe)\b", text, re.I):
            return "database_integrity"
        if re.search(r"\b(?:email|message|forward|dispatch|inbox)\b", text, re.I):
            return "communication_channel"
        return "general_context"

    def _infer_info_type(self, text: str, imperative_ratio: float) -> str:
        if imperative_ratio > 0.40 or re.search(r"(?:you\s+must|execute|perform\s+action)", text, re.I):
            return "executive_instruction"
        if re.search(r"\b(?:prefer|like|always|usually|default\s+to)\b", text, re.I):
            return "user_preference"
        return "factual_context"
