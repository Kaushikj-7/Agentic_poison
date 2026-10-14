"""Tests for Phase P6: Cryptographic Knowledge Graph & Architectural Ledger.

Verifies:
- Append-only Merkle DAG construction (nodes, edges, SHA-256 content addressing).
- Cryptographic Merkle Root computation and tamper detection.
- Merkle inclusion proofs.
- Architectural Ledger recording (what, how, why, which connections).
- Ledger hash-chain integrity verification (detecting retroactive mutations).
- AST indexing into the cryptographic graph.
"""

from pathlib import Path

from agentpoi_sde.graph.arch_ledger import (
    ArchConnection,
    ArchitecturalLedger,
)
from agentpoi_sde.graph.graph_indexer import GraphIndexer
from agentpoi_sde.graph.merkle_graph import (
    EdgeType,
    MerkleGraph,
    MerkleNode,
    NodeType,
)


class TestMerkleGraph:
    """Test suite for the cryptographic Merkle Knowledge Graph."""

    def test_node_content_addressed_hashing(self):
        """Nodes with identical payload have identical hash; differing payload changes hash."""
        node1 = MerkleNode(
            node_id="symbol:calculate_tax",
            node_type=NodeType.SYMBOL,
            payload={"name": "calculate_tax", "args": ["amount", "rate"], "return_type": "float"},
        )
        node2 = MerkleNode(
            node_id="symbol:calculate_tax",
            node_type=NodeType.SYMBOL,
            payload={"name": "calculate_tax", "args": ["amount", "rate"], "return_type": "float"},
        )
        node3 = MerkleNode(
            node_id="symbol:calculate_tax",
            node_type=NodeType.SYMBOL,
            payload={"name": "calculate_tax", "args": ["amount", "rate"], "return_type": "int"},
        )

        assert node1.content_hash == node2.content_hash
        assert node1.content_hash != node3.content_hash
        assert len(node1.content_hash) == 64  # SHA-256 hex string

    def test_graph_root_hash_deterministic(self):
        """Graph root hash is strictly deterministic regardless of insertion order."""
        g1 = MerkleGraph()
        g1.add_node("sym:A", NodeType.SYMBOL, {"code": "def a(): pass"})
        g1.add_node("sym:B", NodeType.SYMBOL, {"code": "def b(): a()"})
        g1.add_edge("sym:B", "sym:A", EdgeType.CALLS)

        g2 = MerkleGraph()
        g2.add_node("sym:B", NodeType.SYMBOL, {"code": "def b(): a()"})
        g2.add_node("sym:A", NodeType.SYMBOL, {"code": "def a(): pass"})
        g2.add_edge("sym:B", "sym:A", EdgeType.CALLS)

        assert g1.compute_root_hash() == g2.compute_root_hash()
        assert len(g1.compute_root_hash()) == 64

    def test_tamper_detection_in_graph(self):
        """Modifying a node's payload alters the root hash immediately."""
        graph = MerkleGraph()
        graph.add_node("api:/users", NodeType.ENDPOINT, {"method": "GET", "auth": True})
        initial_root = graph.compute_root_hash()

        # Mutate the node's payload in place
        node = graph.get_node("api:/users")
        assert node is not None
        node.payload["auth"] = False
        node.recompute_hash()

        tampered_root = graph.compute_root_hash()
        assert initial_root != tampered_root

    def test_merkle_proof_verification(self):
        """Can generate and verify an inclusion proof for a node."""
        graph = MerkleGraph()
        graph.add_node("sym:1", NodeType.SYMBOL, {"v": 1})
        graph.add_node("sym:2", NodeType.SYMBOL, {"v": 2})
        graph.add_node("sym:3", NodeType.SYMBOL, {"v": 3})
        root = graph.compute_root_hash()

        proof = graph.generate_merkle_proof("sym:2")
        assert proof.node_id == "sym:2"
        assert graph.verify_merkle_proof(proof, root) is True

        # Bogus root fails proof verification
        fake_root = "0" * 64
        assert graph.verify_merkle_proof(proof, fake_root) is False


class TestArchitecturalLedger:
    """Test suite for the append-only Architectural Ledger."""

    def test_ledger_append_and_hash_chain(self):
        """Ledger blocks link via cryptographic hash chain."""
        ledger = ArchitecturalLedger()
        assert ledger.height == 0

        # Block 1
        b1 = ledger.record_decision(
            feature="User Auth API",
            how="Implemented JWT bearer auth with FastAPI middleware",
            why="Requirement for secure multi-tenant access",
            connections=[
                ArchConnection(
                    source="frontend/src/api/auth.ts",
                    target="backend/routers/auth.py",
                    protocol="REST_POST",
                    schema={"endpoint": "/auth/token", "body": ["username", "password"]},
                )
            ],
            elements_used=["jwt", "passlib", "fastapi"],
            graph_root="a" * 64,
        )

        assert b1.index == 1
        assert b1.prev_hash == "0" * 64
        assert len(b1.block_hash) == 64

        # Block 2
        b2 = ledger.record_decision(
            feature="Invoice Disbursement Gateway",
            how="Added 3-way matching engine with state anchor",
            why="Prevents unauthorized wire transfers",
            connections=[
                ArchConnection(
                    source="frontend/src/views/InvoiceView.tsx",
                    target="backend/routers/disburse.py",
                    protocol="REST_POST",
                    schema={"endpoint": "/disburse", "body": ["payee_id", "amount"]},
                )
            ],
            elements_used=["agent_poi.financial", "pydantic"],
            graph_root="b" * 64,
        )

        assert b2.index == 2
        assert b2.prev_hash == b1.block_hash
        assert ledger.height == 2
        assert ledger.verify_chain_integrity() is True

    def test_retroactive_tampering_breaks_chain(self):
        """Tampering with an earlier block in the ledger is detected immediately."""
        ledger = ArchitecturalLedger()
        ledger.record_decision("Feature 1", "How 1", "Why 1", [], ["elem1"], "a" * 64)
        ledger.record_decision("Feature 2", "How 2", "Why 2", [], ["elem2"], "b" * 64)
        ledger.record_decision("Feature 3", "How 3", "Why 3", [], ["elem3"], "c" * 64)

        assert ledger.verify_chain_integrity() is True

        # Tamper with block 1's rationale
        ledger.blocks[0].why = "Tampered malicious rationale"
        assert ledger.verify_chain_integrity() is False

    def test_query_ledger_by_feature_and_connection(self):
        """Agent can recall what it built and which connections were formed."""
        ledger = ArchitecturalLedger()
        conn = ArchConnection(
            source="ui/client.ts:fetchUser",
            target="api/users.py:get_user",
            protocol="HTTP_GET",
            schema={"endpoint": "/api/users/{id}"},
        )
        ledger.record_decision(
            feature="User Profile Retrieval",
            how="Added GET /api/users/{id} and frontend hook useUser()",
            why="Display user profile in dashboard",
            connections=[conn],
            elements_used=["react-query", "fastapi"],
            graph_root="c" * 64,
        )

        history = ledger.find_connections_for_target("api/users.py:get_user")
        assert len(history) == 1
        assert history[0].source == "ui/client.ts:fetchUser"

        features = ledger.search_features("User Profile")
        assert len(features) == 1
        assert features[0].feature == "User Profile Retrieval"
        assert "react-query" in features[0].elements_used


class TestGraphIndexer:
    """Test suite for AST indexing of code into the Merkle Knowledge Graph."""

    def test_index_python_module_into_graph(self, tmp_path: Path):
        """Indexes functions, classes, imports, and calls into Merkle Graph."""
        py_file = tmp_path / "service.py"
        py_file.write_text(
            """
import math

class Calculator:
    def add(self, a: float, b: float) -> float:
        return a + b

def compute(x: float) -> float:
    calc = Calculator()
    return calc.add(x, 10.0)
""",
            encoding="utf-8",
        )

        indexer = GraphIndexer()
        graph = indexer.index_file(py_file, relative_to=tmp_path)

        # Verify nodes exist
        assert graph.get_node("file:service.py") is not None
        assert graph.get_node("sym:service.py:Calculator") is not None
        assert graph.get_node("sym:service.py:compute") is not None

        # Verify root hash is non-empty
        root_hash = graph.compute_root_hash()
        assert len(root_hash) == 64
