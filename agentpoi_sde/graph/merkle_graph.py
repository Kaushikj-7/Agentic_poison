"""Append-only cryptographic Merkle Knowledge Graph for software architecture.

Every node (file, symbol, API endpoint, schema) and edge is content-addressed
via SHA-256 and chained into a deterministic Merkle root.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(str, Enum):
    """Types of nodes in the architectural knowledge graph."""

    FILE = "FILE"
    SYMBOL = "SYMBOL"
    ENDPOINT = "ENDPOINT"
    SCHEMA = "SCHEMA"
    DECISION = "DECISION"
    COMPONENT = "COMPONENT"
    BUILD = "BUILD"


class EdgeType(str, Enum):
    """Types of directed relationships between architectural nodes."""

    CALLS = "CALLS"
    IMPLEMENTS = "IMPLEMENTS"
    IMPORTS = "IMPORTS"
    CONNECTS_TO = "CONNECTS_TO"
    CONSTRAINS = "CONSTRAINS"
    EXTRACTED_FROM = "EXTRACTED_FROM"


def _canonical_json(data: Any) -> str:
    """Produces canonical deterministic JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(data: str) -> str:
    """Computes SHA-256 hexadecimal digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class MerkleNode:
    """Content-addressed node in the Merkle Knowledge Graph."""

    node_id: str
    node_type: NodeType
    payload: Dict[str, Any]
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.recompute_hash()

    def recompute_hash(self) -> str:
        """Computes SHA-256 content hash of node_id, node_type, and payload."""
        canonical_payload = _canonical_json(self.payload)
        raw_repr = f"{self.node_id}:{self.node_type.value}:{canonical_payload}"
        self.content_hash = _sha256(raw_repr)
        return self.content_hash


@dataclass(frozen=True)
class MerkleEdge:
    """Cryptographic directed relationship between two nodes."""

    source: str
    target: str
    edge_type: EdgeType
    edge_hash: str = field(init=False)

    def __post_init__(self) -> None:
        raw_repr = f"{self.source}->{self.target}:{self.edge_type.value}"
        object.__setattr__(self, "edge_hash", _sha256(raw_repr))


@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof verifying that a node belongs to a specific Merkle root."""

    node_id: str
    node_hash: str
    sibling_hashes: List[Tuple[str, str]]  # list of (direction, sibling_hash)
    computed_root: str


class MerkleGraph:
    """Cryptographic append-only Directed Acyclic Graph."""

    def __init__(self) -> None:
        self._nodes: Dict[str, MerkleNode] = {}
        self._edges: Set[MerkleEdge] = set()
        self._adjacency: Dict[str, Set[str]] = {}

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def add_node(self, node_id: str, node_type: NodeType, payload: Dict[str, Any]) -> MerkleNode:
        """Adds or updates a content-addressed node in the graph."""
        node = MerkleNode(node_id=node_id, node_type=node_type, payload=payload)
        self._nodes[node_id] = node
        if node_id not in self._adjacency:
            self._adjacency[node_id] = set()
        return node

    def get_node(self, node_id: str) -> Optional[MerkleNode]:
        """Retrieves a node by identifier."""
        return self._nodes.get(node_id)

    def add_edge(self, source: str, target: str, edge_type: EdgeType) -> MerkleEdge:
        """Adds a directed cryptographic edge between source and target."""
        if source not in self._nodes:
            raise KeyError(f"Source node '{source}' does not exist in graph")
        if target not in self._nodes:
            raise KeyError(f"Target node '{target}' does not exist in graph")

        edge = MerkleEdge(source=source, target=target, edge_type=edge_type)
        self._edges.add(edge)
        self._adjacency[source].add(target)
        return edge

    def get_edges_from(self, source: str) -> List[MerkleEdge]:
        """Returns all outgoing edges from source."""
        return [e for e in self._edges if e.source == source]

    def compute_root_hash(self) -> str:
        """Computes the deterministic Merkle root hash across all nodes and edges."""
        if not self._nodes:
            return _sha256("EMPTY_GRAPH")

        # Sort nodes by node_id for strictly deterministic ordering
        sorted_nodes = sorted(self._nodes.values(), key=lambda n: n.node_id)
        node_hashes = [n.content_hash for n in sorted_nodes]

        # Sort edges by source and target
        sorted_edges = sorted(self._edges, key=lambda e: (e.source, e.target, e.edge_type.value))
        edge_hashes = [e.edge_hash for e in sorted_edges]

        # Combine nodes and edges
        combined_leaves = node_hashes + edge_hashes
        return self._build_merkle_root(combined_leaves)

    compute_merkle_root = compute_root_hash

    def _build_merkle_root(self, hashes: List[str]) -> str:
        """Reduces a list of hashes into a single root via binary tree folding."""
        if not hashes:
            return _sha256("EMPTY")
        current_layer = sorted(hashes)
        while len(current_layer) > 1:
            next_layer: List[str] = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left
                parent = _sha256(f"{left}:{right}")
                next_layer.append(parent)
            current_layer = next_layer
        return current_layer[0]

    def generate_merkle_proof(self, node_id: str) -> MerkleProof:
        """Generates an inclusion proof for a given node in the graph."""
        node = self.get_node(node_id)
        if node is None:
            raise KeyError(f"Node '{node_id}' not found in graph")

        sorted_nodes = sorted(self._nodes.values(), key=lambda n: n.node_id)
        leaves = [n.content_hash for n in sorted_nodes] + [
            e.edge_hash for e in sorted(self._edges, key=lambda e: (e.source, e.target))
        ]
        leaves = sorted(leaves)

        target_hash = node.content_hash
        target_idx = leaves.index(target_hash)

        siblings: List[Tuple[str, str]] = []
        current_layer = list(leaves)
        idx = target_idx

        while len(current_layer) > 1:
            next_layer: List[str] = []
            is_odd = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_odd else (idx + 1 if idx + 1 < len(current_layer) else idx)
            sibling_hash = current_layer[sibling_idx]
            direction = "left" if is_odd else "right"
            siblings.append((direction, sibling_hash))

            for i in range(0, len(current_layer), 2):
                left_hash = current_layer[i]
                right_hash = (
                    current_layer[i + 1] if i + 1 < len(current_layer) else left_hash
                )
                next_layer.append(_sha256(f"{left_hash}:{right_hash}"))
            current_layer = next_layer
            idx = idx // 2

        root = current_layer[0]
        return MerkleProof(node_id=node_id, node_hash=target_hash, sibling_hashes=siblings, computed_root=root)

    def verify_merkle_proof(self, proof: MerkleProof, expected_root: str) -> bool:
        """Verifies if the proof recalculates to the expected root hash."""
        current_hash = proof.node_hash
        for direction, sibling in proof.sibling_hashes:
            if direction == "left":
                current_hash = _sha256(f"{sibling}:{current_hash}")
            else:
                current_hash = _sha256(f"{current_hash}:{sibling}")
        return current_hash == expected_root


# Alias for backward and forward architectural compatibility
MerkleKnowledgeGraph = MerkleGraph
