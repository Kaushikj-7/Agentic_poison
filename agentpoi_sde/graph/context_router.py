"""Cryptographic Context Router traversing Merkle Knowledge Graph and Architectural Ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from agentpoi_sde.graph.arch_ledger import (
    ArchConnection,
    ArchitecturalLedger,
    ArchLedgerBlock,
)
from agentpoi_sde.graph.merkle_graph import (
    MerkleKnowledgeGraph,
    MerkleNode,
    MerkleProof,
    NodeType,
)


@dataclass
class RoutedContextBundle:
    """Cryptographically authenticated context bundle for an agent task."""

    task_query: str
    target_paths: List[str]
    nodes: List[MerkleNode]
    proofs: Dict[str, MerkleProof]
    merkle_root: str
    ledger_blocks: List[ArchLedgerBlock] = field(default_factory=list)
    connections: List[ArchConnection] = field(default_factory=list)
    formatted_context: str = ""
    is_verified: bool = True

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    def get_nodes_by_type(self, node_type: NodeType) -> List[MerkleNode]:
        """Filters collected nodes by node type."""
        return [n for n in self.nodes if n.node_type == node_type]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes bundle summary to a dictionary."""
        return {
            "task_query": self.task_query,
            "target_paths": list(self.target_paths),
            "merkle_root": self.merkle_root,
            "is_verified": self.is_verified,
            "node_count": len(self.nodes),
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type.value,
                    "content_hash": n.content_hash,
                }
                for n in self.nodes
            ],
            "ledger_blocks_count": len(self.ledger_blocks),
            "connections_count": len(self.connections),
        }


class CryptographicContextRouter:
    """Traverses Merkle Knowledge Graph and Architectural Ledger to generate verified context bundles."""

    def __init__(self, graph: MerkleKnowledgeGraph, ledger: ArchitecturalLedger) -> None:
        self.graph = graph
        self.ledger = ledger

    def route_context(
        self,
        task_query: str,
        target_paths: Optional[List[str]] = None,
        max_hops: int = 2,
    ) -> RoutedContextBundle:
        """Discovers graph neighborhood and relevant ledger records with Merkle inclusion proofs.

        1. Traverses graph neighborhood starting from target_paths up to max_hops,
           collecting relevant nodes (files, symbols, endpoints, schemas, decisions).
        2. Queries ledger for past architectural decisions and connections related to
           target paths via search_features and find_connections_for_target.
        3. Generates Merkle inclusion proofs for each collected node via graph.generate_merkle_proof(node_id).
        4. Validates every generated proof against the current Merkle root (graph.verify_merkle_proof).
        5. Returns RoutedContextBundle containing nodes, inclusion proofs, verified Merkle root,
           and formatted context text.
        """
        norm_targets = [p.replace("\\", "/").strip() for p in (target_paths or []) if p.strip()]

        # Step 1: Collect seed nodes in graph from target_paths or query
        seed_node_ids = self._find_seed_nodes(norm_targets, task_query)

        # Traverse graph neighborhood up to max_hops (undirected traversal)
        collected_node_ids = self._traverse_neighborhood(seed_node_ids, max_hops)
        collected_nodes: List[MerkleNode] = [
            self.graph.get_node(nid)
            for nid in sorted(collected_node_ids)
            if self.graph.get_node(nid) is not None
        ]

        # Step 2: Query ledger for related decisions and connections
        matched_blocks, matched_connections = self._query_ledger(norm_targets, task_query)

        # Step 3 & 4: Compute root hash and generate + verify Merkle inclusion proofs
        merkle_root = self.graph.compute_root_hash()
        proofs: Dict[str, MerkleProof] = {}
        all_proofs_valid = True

        for node in collected_nodes:
            try:
                proof = self.graph.generate_merkle_proof(node.node_id)
                proofs[node.node_id] = proof
                is_valid = self.graph.verify_merkle_proof(proof, merkle_root)
                if not is_valid:
                    all_proofs_valid = False
            except Exception:
                all_proofs_valid = False

        # Step 5: Format context text
        formatted_context = self._format_context_text(
            merkle_root=merkle_root,
            is_verified=all_proofs_valid,
            nodes=collected_nodes,
            blocks=matched_blocks,
            connections=matched_connections,
            max_hops=max_hops,
        )

        return RoutedContextBundle(
            task_query=task_query,
            target_paths=norm_targets,
            nodes=collected_nodes,
            proofs=proofs,
            merkle_root=merkle_root,
            ledger_blocks=matched_blocks,
            connections=matched_connections,
            formatted_context=formatted_context,
            is_verified=all_proofs_valid,
        )

    def _find_seed_nodes(self, targets: List[str], query: str) -> Set[str]:
        """Identifies initial seed nodes matching target paths or query keywords."""
        seeds: Set[str] = set()

        for target in targets:
            # Exact file node match
            file_node_id = f"file:{target}"
            if self.graph.get_node(file_node_id):
                seeds.add(file_node_id)

            # Match any node whose ID contains target path
            for nid, node in self.graph._nodes.items():
                if target in nid:
                    seeds.add(nid)
                elif node.payload.get("file") == target or node.payload.get("path") == target:
                    seeds.add(nid)

        # If no seeds from target paths, search by query keywords
        if not seeds and query:
            tokens = [w.lower() for w in query.split() if len(w) > 2]
            for nid, node in self.graph._nodes.items():
                nid_lower = nid.lower()
                name_lower = str(node.payload.get("name", "")).lower()
                desc_lower = str(node.payload.get("description", "")).lower()
                path_lower = str(node.payload.get("path", "")).lower()
                if any(t in nid_lower or t in name_lower or t in desc_lower or t in path_lower for t in tokens):
                    seeds.add(nid)

        return seeds

    def _traverse_neighborhood(self, seed_node_ids: Set[str], max_hops: int) -> Set[str]:
        """Traverses graph neighborhood up to max_hops using an undirected adjacency graph."""
        if not seed_node_ids:
            return set()

        # Build bidirectional adjacency
        adj: Dict[str, Set[str]] = {nid: set() for nid in self.graph._nodes}
        for edge in self.graph._edges:
            if edge.source in adj and edge.target in adj:
                adj[edge.source].add(edge.target)
                adj[edge.target].add(edge.source)

        visited: Set[str] = set(seed_node_ids)
        current_layer: Set[str] = set(seed_node_ids)

        for _ in range(max(0, max_hops)):
            next_layer: Set[str] = set()
            for nid in current_layer:
                for neighbor in adj.get(nid, set()):
                    if neighbor not in visited and neighbor in self.graph._nodes:
                        visited.add(neighbor)
                        next_layer.add(neighbor)
            current_layer = next_layer

        return visited

    def _query_ledger(
        self, targets: List[str], query: str
    ) -> tuple[List[ArchLedgerBlock], List[ArchConnection]]:
        """Queries the ledger for decisions and connections matching targets and query."""
        matched_blocks: List[ArchLedgerBlock] = []
        matched_connections: List[ArchConnection] = []
        seen_block_indices: Set[int] = set()

        # Query connections for target paths
        for target in targets:
            conns = self.ledger.find_connections_for_target(target)
            for c in conns:
                if c not in matched_connections:
                    matched_connections.append(c)

        # Also find connections where source matches target
        for block in self.ledger.blocks:
            for conn in block.connections:
                for target in targets:
                    if target in conn.source or target in conn.target:
                        if conn not in matched_connections:
                            matched_connections.append(conn)

        # Query decisions matching feature query
        if query:
            for b in self.ledger.search_features(query):
                if b.index not in seen_block_indices:
                    matched_blocks.append(b)
                    seen_block_indices.add(b.index)

            # Query by keywords if full query had no hits
            if not matched_blocks:
                for token in query.split():
                    if len(token) > 2:
                        for b in self.ledger.search_features(token):
                            if b.index not in seen_block_indices:
                                matched_blocks.append(b)
                                seen_block_indices.add(b.index)

        # Match decisions mentioning targets in elements_used
        for target in targets:
            for b in self.ledger.blocks:
                if b.index not in seen_block_indices:
                    if any(target in elem for elem in b.elements_used) or target in b.feature or target in b.how:
                        matched_blocks.append(b)
                        seen_block_indices.add(b.index)

        return matched_blocks, matched_connections

    def _format_context_text(
        self,
        merkle_root: str,
        is_verified: bool,
        nodes: List[MerkleNode],
        blocks: List[ArchLedgerBlock],
        connections: List[ArchConnection],
        max_hops: int,
    ) -> str:
        """Produces formatted markdown context string for LLM/agent consumption."""
        lines: List[str] = [
            "### Cryptographic Knowledge Context",
            f"- Merkle Root: {merkle_root}",
            f"- Cryptographic Verification: {'VERIFIED' if is_verified else 'FAIL_CLOSED'}",
            f"- Discovered Nodes: {len(nodes)} (Neighborhood Hops: {max_hops})",
            "",
            f"#### Verified Graph Nodes ({len(nodes)})",
        ]

        if not nodes:
            lines.append("*(No graph nodes discovered)*")
        else:
            for n in nodes:
                payload_str = ", ".join(f"{k}={v}" for k, v in sorted(n.payload.items()) if k != "size")
                lines.append(f"- [{n.node_type.value}] {n.node_id}: {payload_str}")

        lines.extend(["", f"#### Architectural Decisions ({len(blocks)})"])
        if not blocks:
            lines.append("*(No past architectural decisions matched)*")
        else:
            for b in blocks:
                lines.append(f"- Block #{b.index}: {b.feature}")
                lines.append(f"  Why: {b.why}")
                lines.append(f"  How: {b.how}")

        lines.extend(["", f"#### Architectural Connections ({len(connections)})"])
        if not connections:
            lines.append("*(No architectural connections recorded)*")
        else:
            for c in connections:
                lines.append(f"- {c.source} -> {c.target} [{c.protocol}]")

        return "\n".join(lines)
