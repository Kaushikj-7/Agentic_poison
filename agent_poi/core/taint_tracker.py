"""Provenance DAG, Ancestor Taint Tracking, and AuthGraph (arXiv:2605.26497).

Tracks context lineage using SHA-256 hash chaining and verifies cryptographic
authorization ancestry before executing high-consequence execution sinks.
"""

import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from agent_poi.memory.schema import ProvenanceNode, SourceOrigin


@dataclass
class AuthGraphNode:
    """Cryptographic provenance node in the AuthGraph DAG."""
    node_id: str
    content: str
    origin: SourceOrigin
    is_authorized_root: bool
    parent_ids: List[str] = field(default_factory=list)
    parent_hashes: List[str] = field(default_factory=list)
    sha256_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_sha256(self) -> str:
        """Compute SHA-256 hash chaining content, origin, parent_ids, and parent hashes."""
        p_ids = ",".join(sorted(self.parent_ids))
        p_hashes = ",".join(sorted(self.parent_hashes))
        data = f"{self.node_id}:{self.content}:{self.origin.value}:{self.is_authorized_root}:{p_ids}:{p_hashes}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()


class AuthGraphDAG:
    """AuthGraph (arXiv:2605.26497) Cryptographic Provenance & Sink Verifier."""

    def __init__(self):
        self.nodes: Dict[str, AuthGraphNode] = {}

    def add_node(
        self,
        content: str,
        origin: SourceOrigin,
        is_authorized_root: bool = False,
        parent_ids: Optional[List[str]] = None,
        node_id: Optional[str] = None,
    ) -> AuthGraphNode:
        """Register a node with cryptographic parent hash chaining."""
        parents = parent_ids or []
        nid = node_id or f"auth_node_{len(self.nodes) + 1:04d}"

        # Validate parents exist before referencing
        for p in parents:
            if p not in self.nodes:
                raise ValueError(f"Parent node '{p}' does not exist in AuthGraph DAG.")

        parent_hashes = [self.nodes[p].sha256_hash for p in parents]

        node = AuthGraphNode(
            node_id=nid,
            content=content,
            origin=origin,
            is_authorized_root=is_authorized_root,
            parent_ids=parents,
            parent_hashes=parent_hashes,
        )
        node.sha256_hash = node.compute_sha256()
        self.nodes[nid] = node
        return node

    def verify_sink_authorization(
        self,
        contributing_node_ids: Optional[List[str]],
        required_root_authority: Optional[SourceOrigin] = None,
    ) -> Tuple[bool, List[str]]:
        """Verify that an execution sink traces solely to authorized root ancestors."""
        violations = []
        if not contributing_node_ids:
            return False, ["Execution sink has no authenticated provenance root."]

        visited: Set[str] = set()
        queue = list(contributing_node_ids)

        has_authorized_root = False
        matching_root_authority = False if required_root_authority is not None else True

        while queue:
            curr_id = queue.pop(0)
            if curr_id in visited:
                continue
            visited.add(curr_id)

            if curr_id not in self.nodes:
                violations.append(f"Missing provenance ancestor node: '{curr_id}'.")
                continue

            node = self.nodes[curr_id]

            # Recalculate and verify SHA-256 integrity of ancestor node
            expected_hash = node.compute_sha256()
            if node.sha256_hash != expected_hash:
                violations.append(
                    f"Sink rejected: Cryptographic hash tampering detected on node '{node.node_id}'."
                )

            # Verify that claimed parent hashes match current hashes of parent nodes
            for pid in node.parent_ids:
                if pid not in self.nodes:
                    violations.append(f"Sink rejected: Referenced parent node '{pid}' not found in DAG.")
                elif self.nodes[pid].sha256_hash not in node.parent_hashes:
                    violations.append(
                        f"Sink rejected: Cryptographic hash tampering detected between child '{node.node_id}' and parent '{pid}'."
                    )

            # If node is marked as untrusted or external and is not an authorized root
            if node.origin in [SourceOrigin.UNTRUSTED_WEB, SourceOrigin.ANONYMOUS_PEER] and not node.is_authorized_root:
                violations.append(
                    f"Sink rejected: Node '{node.node_id}' has untrusted or unauthorized lineage ({node.origin.value})."
                )

            if node.is_authorized_root:
                has_authorized_root = True
                if required_root_authority is not None and node.origin == required_root_authority:
                    matching_root_authority = True

            queue.extend(node.parent_ids)

        if not has_authorized_root:
            violations.append("Sink rejected: Ancestor lineage contains no authenticated root authority.")
        elif required_root_authority is not None and not matching_root_authority:
            violations.append(
                f"Sink rejected: Ancestor lineage does not originate from required authority '{required_root_authority.value}'."
            )

        is_valid = len(violations) == 0
        return is_valid, violations



class TaintTracker:
    """Manages context provenance and coordinates with AuthGraphDAG."""

    def __init__(self):
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.auth_graph = AuthGraphDAG()

    def register_node(
        self,
        node_id: str,
        origin: SourceOrigin,
        direct_trust: float,
        final_trust: float,
        parent_ids: Optional[List[str]] = None,
        content: str = "",
    ) -> ProvenanceNode:
        """Add node to both scalar provenance table and cryptographic AuthGraph."""
        parents = parent_ids or []
        node = ProvenanceNode(
            node_id=node_id,
            parent_ids=parents,
            origin=origin,
            direct_trust=direct_trust,
            final_trust=final_trust,
        )
        self.nodes[node_id] = node

        # Mirror to AuthGraph
        is_root = origin in [SourceOrigin.SYSTEM_INSTRUCTION, SourceOrigin.VERIFIED_USER] and not parents
        self.auth_graph.add_node(
            content=content or f"Node {node_id}",
            origin=origin,
            is_authorized_root=is_root,
            parent_ids=parents,
            node_id=node_id,
        )

        return node

    def get_parent_scores(self, parent_ids: List[str]) -> List[float]:
        scores = []
        for pid in parent_ids:
            if pid in self.nodes:
                scores.append(self.nodes[pid].final_trust)
            else:
                scores.append(0.30)
        return scores

    def get_ancestors(self, node_id: str) -> Set[str]:
        ancestors = set()
        queue = list(self.nodes.get(node_id, ProvenanceNode(node_id=node_id)).parent_ids)

        while queue:
            curr = queue.pop(0)
            if curr not in ancestors:
                ancestors.add(curr)
                if curr in self.nodes:
                    queue.extend(self.nodes[curr].parent_ids)
        return ancestors

    def is_tainted_by(self, node_id: str, taint_threshold: float = 0.50) -> bool:
        ancestors = self.get_ancestors(node_id)
        for anc_id in ancestors:
            if anc_id in self.nodes and self.nodes[anc_id].final_trust < taint_threshold:
                return True
        return False
