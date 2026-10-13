"""Base definitions for attack generators and payloads."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from agent_poi.memory.schema import SourceOrigin


@dataclass
class AttackPayload:
    """Represents a generated attack payload with metadata and target goal."""
    attack_id: str
    attack_name: str
    tier: int  # 1 (Static) or 2 (Adaptive)
    content: str
    target_tool: str
    target_payload: Dict[str, Any]
    source_origin: SourceOrigin
    trigger_query: str
    clean_counterpart: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAttackGenerator(ABC):
    @abstractmethod
    def generate_payloads(self) -> List[AttackPayload]:
        """Generate test attack payloads."""
        pass
