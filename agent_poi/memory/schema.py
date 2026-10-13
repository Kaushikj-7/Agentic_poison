"""Data structures and schemas for CTP memory items, provenance, and firewall decisions."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SourceOrigin(str, Enum):
    VERIFIED_USER = "verified_user"
    SYSTEM_INSTRUCTION = "system_instruction"
    INTERNAL_TOOL = "internal_tool"
    EXTERNAL_API = "external_api"
    UNTRUSTED_WEB = "untrusted_web"
    ANONYMOUS_PEER = "anonymous_peer"


class FirewallStatus(str, Enum):
    ALLOWED = "allowed"
    QUARANTINED = "quarantined"
    BLOCKED = "blocked"


@dataclass
class CIPartition:
    """Contextual Integrity 5-tuple decomposition."""
    sender: str
    recipient: str
    subject: str
    info_type: str
    transmission_principle: str
    self_asserted_auth: bool = False
    imperative_ratio: float = 0.0
    framing_risk: float = 0.0
    raw_signals: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceNode:
    """Lineage node in the taint propagation graph."""
    node_id: str
    parent_ids: List[str] = field(default_factory=list)
    origin: SourceOrigin = SourceOrigin.UNTRUSTED_WEB
    direct_trust: float = 0.50
    final_trust: float = 0.50
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class MemoryItem:
    """Represents an atomic context/memory entry stored or evaluated."""
    id: str
    content: str
    origin: SourceOrigin = SourceOrigin.VERIFIED_USER
    parent_ids: List[str] = field(default_factory=list)
    ci_partition: Optional[CIPartition] = None
    trust_score: float = 1.0
    status: FirewallStatus = FirewallStatus.ALLOWED
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FirewallDecision:
    """Decision output from write-time or retrieval-time firewall."""
    status: FirewallStatus
    trust_score: float
    reasons: List[str]
    item_id: str
    content_snippet: str
    ci_risk_score: float = 0.0
    alignment_score: Optional[float] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_accepted(self) -> bool:
        """Convenience property for write-time acceptance."""
        return self.status == FirewallStatus.ALLOWED
