"""Mathematical operations component - safe, pure mathematical node."""

from __future__ import annotations

import math
from typing import List


class MathOperatorNode:
    """Executes deterministic mathematical and statistical functions."""

    @staticmethod
    def calculate_mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def calculate_standard_deviation(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    @staticmethod
    def scale_values(values: List[float], factor: float) -> List[float]:
        return [v * factor for v in values]
