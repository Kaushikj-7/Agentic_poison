"""Memory subsystems: schema and vector store."""

from agent_poi.memory.schema import (
    SourceOrigin,
    FirewallStatus,
    CIPartition,
    ProvenanceNode,
    MemoryItem,
    FirewallDecision,
)
from agent_poi.memory.vector_store import VectorMemoryStore

def get_memory_firewall():
    from agent_poi.memory.memory_firewall import MemoryFirewall
    return MemoryFirewall

__all__ = [
    "SourceOrigin",
    "FirewallStatus",
    "CIPartition",
    "ProvenanceNode",
    "MemoryItem",
    "FirewallDecision",
    "VectorMemoryStore",
    "get_memory_firewall",
]
