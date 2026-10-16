"""Append-only cryptographic Architectural Ledger for autonomous software engineering.

Maintains an unforgeable hash-chained history of what the agent built,
how it was implemented, why decisions were made, and which components were connected.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


def _canonical_json(data: Any) -> str:
    """Produces deterministic canonical JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(data: str) -> str:
    """Computes SHA-256 digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class ArchConnection:
    """Connection between two architectural entities (e.g. Frontend to Backend)."""

    source: str
    target: str
    protocol: str  # REST_POST, REST_GET, RPC, IMPORT, IPC
    schema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArchLedgerBlock:
    """An immutable cryptographic block in the Architectural Ledger."""

    index: int
    prev_hash: str
    feature: str
    how: str
    why: str
    connections: List[ArchConnection]
    elements_used: List[str]
    graph_root: str
    timestamp: float = field(default_factory=time.time)
    block_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.recompute_hash()

    def recompute_hash(self) -> str:
        """Calculates cryptographic block hash."""
        payload = {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "feature": self.feature,
            "how": self.how,
            "why": self.why,
            "connections": [c.to_dict() for c in self.connections],
            "elements_used": sorted(self.elements_used),
            "graph_root": self.graph_root,
        }
        canonical = _canonical_json(payload)
        self.block_hash = _sha256(canonical)
        return self.block_hash


class ArchitecturalLedger:
    """Append-only cryptographic ledger of software architectural decisions."""

    def __init__(self) -> None:
        self._blocks: List[ArchLedgerBlock] = []

    @property
    def height(self) -> int:
        return len(self._blocks)

    @property
    def blocks(self) -> List[ArchLedgerBlock]:
        return self._blocks

    @property
    def latest_root(self) -> Optional[str]:
        """Return the Merkle graph root hash of the most recent block."""
        return self._blocks[-1].graph_root if self._blocks else None

    def record_decision(
        self,
        feature: str,
        how: str,
        why: str,
        connections: List[ArchConnection],
        elements_used: List[str],
        graph_root: str,
    ) -> ArchLedgerBlock:
        """Records an architectural decision into the append-only ledger."""
        idx = len(self._blocks) + 1
        prev_hash = self._blocks[-1].block_hash if self._blocks else "0" * 64

        block = ArchLedgerBlock(
            index=idx,
            prev_hash=prev_hash,
            feature=feature,
            how=how,
            why=why,
            connections=connections,
            elements_used=elements_used,
            graph_root=graph_root,
        )
        self._blocks.append(block)
        return block

    def verify_chain_integrity(self) -> bool:
        """Validates that all blocks in the ledger are correctly linked and uncorrupted."""
        for i, block in enumerate(self._blocks):
            # Check previous hash linkage
            expected_prev = "0" * 64 if i == 0 else self._blocks[i - 1].block_hash
            if block.prev_hash != expected_prev:
                return False

            # Check block's own hash integrity
            recorded_hash = block.block_hash
            calculated_hash = block.recompute_hash()
            if recorded_hash != calculated_hash:
                return False

        return True

    def find_connections_for_target(self, target: str) -> List[ArchConnection]:
        """Queries the ledger for all connections leading into a target entity."""
        matches: List[ArchConnection] = []
        for block in self._blocks:
            for conn in block.connections:
                if conn.target == target:
                    matches.append(conn)
        return matches

    def search_features(self, query: str) -> List[ArchLedgerBlock]:
        """Searches ledger history for decisions matching a feature keyword."""
        q_lower = query.lower()
        return [b for b in self._blocks if q_lower in b.feature.lower() or q_lower in b.how.lower()]
