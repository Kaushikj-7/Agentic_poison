"""Text processing node - pure text transformations without side effects."""

from __future__ import annotations

import re
from typing import List


class TextTransformerNode:
    """Transforms and normalizes natural language text inputs."""

    @staticmethod
    def tokenize_words(text: str) -> List[str]:
        cleaned = re.sub(r"[^\w\s]", "", text)
        return cleaned.split()

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def truncate_string(text: str, max_chars: int = 256) -> str:
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "..."
