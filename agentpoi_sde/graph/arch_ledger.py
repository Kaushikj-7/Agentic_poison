"""Append-only cryptographic Architectural Ledger for autonomous software engineering.

Maintains an unforgeable hash-chained history of what the agent built,
how it was implemented, why decisions were made, and which components were connected.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ArchConnection:
        """Reconstructs ArchConnection from dictionary."""
        return cls(
            source=data["source"],
            target=data["target"],
            protocol=data["protocol"],
            schema=data.get("schema", {}),
        )


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
        serialized_connections = []
        for c in self.connections:
            if hasattr(c, "to_dict"):
                serialized_connections.append(c.to_dict())
            elif isinstance(c, dict):
                serialized_connections.append(c)
            else:
                serialized_connections.append(asdict(c))

        payload = {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "feature": self.feature,
            "how": self.how,
            "why": self.why,
            "connections": serialized_connections,
            "elements_used": sorted(self.elements_used),
            "graph_root": self.graph_root,
        }
        canonical = _canonical_json(payload)
        self.block_hash = _sha256(canonical)
        return self.block_hash

    def to_dict(self) -> Dict[str, Any]:
        """Serializes block to a dictionary."""
        serialized_connections = []
        for c in self.connections:
            if hasattr(c, "to_dict"):
                serialized_connections.append(c.to_dict())
            elif isinstance(c, dict):
                serialized_connections.append(c)
            else:
                serialized_connections.append(asdict(c))

        return {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "feature": self.feature,
            "how": self.how,
            "why": self.why,
            "connections": serialized_connections,
            "elements_used": list(self.elements_used),
            "graph_root": self.graph_root,
            "timestamp": self.timestamp,
            "block_hash": self.block_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ArchLedgerBlock:
        """Deserializes block from a dictionary."""
        raw_conns = data.get("connections", [])
        connections: List[ArchConnection] = []
        for c in raw_conns:
            if isinstance(c, dict):
                connections.append(ArchConnection.from_dict(c))
            elif isinstance(c, ArchConnection):
                connections.append(c)
            else:
                connections.append(
                    ArchConnection(
                        source=c.source,
                        target=c.target,
                        protocol=c.protocol,
                        schema=c.schema,
                    )
                )

        block = cls(
            index=data["index"],
            prev_hash=data["prev_hash"],
            feature=data["feature"],
            how=data["how"],
            why=data["why"],
            connections=connections,
            elements_used=list(data.get("elements_used", [])),
            graph_root=data.get("graph_root", ""),
            timestamp=data.get("timestamp", time.time()),
        )
        if "block_hash" in data:
            block.block_hash = data["block_hash"]
        return block


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
        """Validates that all blocks in the ledger are correctly linked and uncorrupted.

        Fail-closed checks:
        - Strictly sequential block indexing: block.index == i + 1 (detects skipped, out-of-order, or duplicate indices).
        - Correct prev_hash linkage (genesis block requires 64 '0's; block i requires block i-1's hash).
        - Deterministic block hash integrity (recorded block_hash matches recomputed hash).
        """
        for i, block in enumerate(self._blocks):
            # Check strictly sequential block index
            if block.index != i + 1:
                return False

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

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the entire ledger into a dictionary."""
        return {
            "version": 1,
            "height": self.height,
            "blocks": [b.to_dict() for b in self._blocks],
        }

    @classmethod
    def from_dict(cls, data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> ArchitecturalLedger:
        """Deserializes a ledger from a dictionary or list of block dicts."""
        ledger = cls()
        if isinstance(data, list):
            blocks_data = data
        elif isinstance(data, dict):
            blocks_data = data.get("blocks", [])
        else:
            blocks_data = []

        for b_data in blocks_data:
            block = ArchLedgerBlock.from_dict(b_data)
            ledger._blocks.append(block)
        return ledger

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serializes the ledger to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> ArchitecturalLedger:
        """Deserializes a ledger from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def save_to_json(self, path: Union[str, Path]) -> None:
        """Saves the ledger to a JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load_from_json(cls, path: Union[str, Path]) -> ArchitecturalLedger:
        """Loads a ledger from a JSON file."""
        p = Path(path)
        content = p.read_text(encoding="utf-8")
        return cls.from_json(content)
