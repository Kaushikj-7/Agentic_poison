"""PromptLocate: Semantic Span Localization & Surgical Redaction (arXiv:2510.12252).

Identifies exact character intervals [i, j] containing injected imperative
instructions within financial documents, enabling surgical redaction while
preserving benign business context (PO numbers, invoice totals, legitimate line items).
"""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class LocalizedSpan:
    """A detected contiguous span containing prompt injection or imperative hijack."""
    start: int
    end: int
    confidence: float
    text: str
    pattern_name: str


@dataclass(frozen=True)
class RedactionResult:
    """Result of surgical localization and redaction."""
    sanitized_text: str
    spans: List[LocalizedSpan] = field(default_factory=list)
    utility_retention_ratio: float = 1.0
    original_length: int = 0
    sanitized_length: int = 0


# Imperative and adversarial command patterns derived from Tier 1 & Tier 5 literature
_INJECTION_PATTERNS = [
    ("SYSTEM_OVERRIDE", re.compile(r"(?i)\b(?:system\s+override|admin\s+override|priority\s+override)\b[^\.\n]*[\.\n]?")),
    ("INSTRUCTION_RESET", re.compile(r"(?i)\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?)\b[^\.\n]*[\.\n]?")),
    ("DISBURSEMENT_DIVERSION", re.compile(r"(?i)\b(?:instead\s+)?(?:transfer|wire|disburse|pay|send)\s+(?:\$[\d,]+|\d+)\s+(?:to\s+(?:account|offshore|recipient)?\s*[\w\-]+)\b[^\.\n]*[\.\n]?")),
    ("EXECUTIVE_COMPLIANCE_HIJACK", re.compile(r"(?i)\b(?:divert\s+(?:all\s+)?(?:pending\s+)?payments?|executive\s+compliance\s+verification)\b[^\.\n]*[\.\n]?")),
    ("SECURITY_BYPASS", re.compile(r"(?i)\b(?:bypass\s+(?:all\s+)?(?:security|guardrails|checks)|execute\s+immediately\s+without\s+verification)\b[^\.\n]*[\.\n]?")),
]


class PromptLocate:
    """Surgically localizes and excises adversarial instruction spans from context."""

    def __init__(self, confidence_threshold: float = 0.75, delimiter: str = " [REDACTED_INJECTION_SPAN] "):
        self.confidence_threshold = confidence_threshold
        self.delimiter = delimiter

    def locate_spans(self, text: str) -> List[LocalizedSpan]:
        """Scan text and identify character offsets of malicious instruction spans."""
        spans: List[LocalizedSpan] = []
        for name, pattern in _INJECTION_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                matched_str = text[start:end].strip()
                if matched_str:
                    spans.append(
                        LocalizedSpan(
                            start=start,
                            end=end,
                            confidence=0.95,
                            text=matched_str,
                            pattern_name=name,
                        )
                    )
        return self._merge_overlapping_spans(spans)

    def locate_and_redact(self, text: str) -> RedactionResult:
        """Perform fine-grained span localization and surgical redaction."""
        if not text or not text.strip():
            return RedactionResult(sanitized_text=text, spans=[], utility_retention_ratio=1.0, original_length=0, sanitized_length=0)

        spans = self.locate_spans(text)
        if not spans:
            return RedactionResult(
                sanitized_text=text,
                spans=[],
                utility_retention_ratio=1.0,
                original_length=len(text),
                sanitized_length=len(text),
            )

        sanitized_parts: List[str] = []
        last_idx = 0
        total_excised_len = 0

        for span in spans:
            if span.start > last_idx:
                sanitized_parts.append(text[last_idx:span.start])
            sanitized_parts.append(self.delimiter)
            total_excised_len += (span.end - span.start)
            last_idx = span.end

        if last_idx < len(text):
            sanitized_parts.append(text[last_idx:])

        sanitized_text = "".join(sanitized_parts).strip()
        # Calculate utility retention as non-excised text ratio
        retained_len = max(len(text) - total_excised_len, 0)
        utility_ratio = round(retained_len / len(text), 3)

        return RedactionResult(
            sanitized_text=sanitized_text,
            spans=spans,
            utility_retention_ratio=utility_ratio,
            original_length=len(text),
            sanitized_length=len(sanitized_text),
        )

    def _merge_overlapping_spans(self, spans: List[LocalizedSpan]) -> List[LocalizedSpan]:
        """Merge overlapping or adjacent span intervals."""
        if not spans:
            return []
        sorted_spans = sorted(spans, key=lambda s: s.start)
        merged: List[LocalizedSpan] = [sorted_spans[0]]

        for current in sorted_spans[1:]:
            prev = merged[-1]
            if current.start <= prev.end:
                new_end = max(prev.end, current.end)
                merged[-1] = LocalizedSpan(
                    start=prev.start,
                    end=new_end,
                    confidence=max(prev.confidence, current.confidence),
                    text=f"{prev.text} ... {current.text}",
                    pattern_name=f"{prev.pattern_name}+{current.pattern_name}",
                )
            else:
                merged.append(current)
        return merged
