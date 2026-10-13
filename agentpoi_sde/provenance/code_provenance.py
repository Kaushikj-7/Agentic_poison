"""Provenance DAG (P): SHA-256 hash-chained, tier-aware lineage over context artefacts.

Every artefact that contributes to a mutation (authenticated intent, repository ground truth,
or untrusted context) is registered as a node whose hash chains its parents. A mutation may
only be authored by a T0/T1 node whose ancestry contains at least one authenticated T0 root.
This is the software-engineering transfer of the AuthGraph lineage principle
(arXiv:2605.26497) with explicit trust-tier semantics.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from agent_poi.memory.schema import SourceOrigin
from agentpoi_sde.domain import TrustTier

_T0_ORIGINS = {SourceOrigin.VERIFIED_USER, SourceOrigin.SYSTEM_INSTRUCTION}
_T1_ORIGINS = {SourceOrigin.INTERNAL_TOOL}


def tier_for_origin(origin: SourceOrigin) -> TrustTier:
    """Map a context origin to its epistemic trust tier."""
    if origin in _T0_ORIGINS:
        return TrustTier.T0_AUTHENTICATED_INTENT
    if origin in _T1_ORIGINS:
        return TrustTier.T1_REPOSITORY_GROUND_TRUTH
    return TrustTier.T2_UNTRUSTED_CONTEXT


@dataclass
class ProvenanceNode:
    """A hash-chained provenance node."""

    node_id: str
    content: str
    origin: SourceOrigin
    tier: TrustTier
    is_authenticated_root: bool = False
    parent_ids: List[str] = field(default_factory=list)
    parent_hashes: List[str] = field(default_factory=list)
    sha256_hash: str = ""

    def compute_sha256(self) -> str:
        """Recompute the node digest over its content, tier and parent hashes."""
        payload = "|".join(
            [
                self.node_id,
                self.content,
                self.origin.value,
                self.tier.value,
                "1" if self.is_authenticated_root else "0",
                ",".join(sorted(self.parent_ids)),
                ",".join(sorted(self.parent_hashes)),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ProvenanceDAG:
    """Tier-aware cryptographic provenance graph for the mutation sink."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ProvenanceNode] = {}

    def add_node(
        self,
        content: str,
        origin: SourceOrigin,
        parent_ids: Optional[List[str]] = None,
        node_id: Optional[str] = None,
        is_authenticated_root: Optional[bool] = None,
    ) -> ProvenanceNode:
        """Register a node, validating parent existence and forbidding duplicate ids."""
        parents = list(parent_ids or [])
        nid = node_id or f"prov_{len(self.nodes) + 1:04d}"
        if nid in self.nodes:
            raise ValueError(f"Duplicate provenance node id '{nid}'.")
        if nid in parents:
            raise ValueError(f"Self-referential provenance node '{nid}'.")
        for parent in parents:
            if parent not in self.nodes:
                raise ValueError(f"Unknown provenance parent '{parent}' for node '{nid}'.")

        tier = tier_for_origin(origin)
        root = tier == TrustTier.T0_AUTHENTICATED_INTENT if is_authenticated_root is None else is_authenticated_root
        node = ProvenanceNode(
            node_id=nid,
            content=content,
            origin=origin,
            tier=tier,
            is_authenticated_root=root,
            parent_ids=parents,
            parent_hashes=[self.nodes[p].sha256_hash for p in parents],
        )
        node.sha256_hash = node.compute_sha256()
        self.nodes[nid] = node
        return node

    def ancestors(self, node_id: str) -> Set[str]:
        """Return the set of ancestor node ids (excluding ``node_id``)."""
        seen: Set[str] = set()
        stack = list(self.nodes.get(node_id, ProvenanceNode(
            node_id=node_id, content="", origin=SourceOrigin.UNTRUSTED_WEB,
            tier=TrustTier.T2_UNTRUSTED_CONTEXT,
        )).parent_ids)
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            if current in self.nodes:
                stack.extend(self.nodes[current].parent_ids)
        return seen

    def _integrity_violations(self, node: ProvenanceNode) -> List[str]:
        """Return hash-chain integrity violations for a node."""
        violations: List[str] = []
        if node.sha256_hash != node.compute_sha256():
            violations.append(f"P2: cryptographic hash tampering on node '{node.node_id}'.")
        for parent_id, parent_hash in zip(node.parent_ids, node.parent_hashes):
            parent = self.nodes.get(parent_id)
            if parent is None:
                violations.append(f"P2: missing provenance ancestor '{parent_id}'.")
            elif parent.sha256_hash != parent_hash:
                violations.append(
                    f"P2: broken hash chain between '{node.node_id}' and '{parent_id}'."
                )
        return violations

    def verify_mutation_authority(self, node_id: str) -> Tuple[bool, List[str]]:
        """Verify a mutation node is authored by a T0/T1 node with an authenticated root ancestor."""
        node = self.nodes.get(node_id)
        if node is None:
            return False, [f"P1: mutation provenance node '{node_id}' is not registered."]

        violations: List[str] = self._integrity_violations(node)
        for ancestor_id in self.ancestors(node_id):
            ancestor = self.nodes.get(ancestor_id)
            if ancestor is not None:
                violations.extend(self._integrity_violations(ancestor))

        if node.tier == TrustTier.T2_UNTRUSTED_CONTEXT:
            violations.append(
                f"P4: untrusted context node '{node_id}' may not author a mutation."
            )

        has_authenticated_root = node.is_authenticated_root
        for ancestor_id in self.ancestors(node_id):
            ancestor = self.nodes.get(ancestor_id)
            if ancestor and ancestor.is_authenticated_root and ancestor.tier == TrustTier.T0_AUTHENTICATED_INTENT:
                has_authenticated_root = True
        if not has_authenticated_root:
            violations.append(
                f"P3: mutation node '{node_id}' traces to no authenticated intent root."
            )

        return len(violations) == 0, violations
