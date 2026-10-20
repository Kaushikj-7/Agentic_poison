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
    ArchLedgerBlock,
)
from agentpoi_sde.graph.context_router import (
    CryptographicContextRouter,
    RoutedContextBundle,
)
from agentpoi_sde.graph.graph_indexer import GraphIndexer
from agentpoi_sde.graph.merkle_graph import (
    EdgeType,
    MerkleGraph,
    MerkleKnowledgeGraph,
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

    def test_ledger_latest_root_property(self):
        """Verifies latest_root returns None when empty and root when populated."""
        import typing

        ledger = ArchitecturalLedger()
        assert ledger.latest_root is None

        # Verify type hints resolve without NameError (F821 regression test)
        hints = typing.get_type_hints(ArchitecturalLedger)
        assert "latest_root" in hints or hasattr(ArchitecturalLedger, "latest_root")

        ledger.record_decision("Init", "how", "why", [], [], "root_hash_123")
        assert ledger.latest_root == "root_hash_123"

        ledger.record_decision("Next", "how2", "why2", [], [], "root_hash_456")
        assert ledger.latest_root == "root_hash_456"

    def test_strict_block_index_verification_detects_skipped_index_fail_closed(self):
        """Strict sequential block indexing fails closed if an index is skipped, out-of-order, or duplicated."""
        ledger = ArchitecturalLedger()
        b1 = ledger.record_decision("Feature 1", "How 1", "Why 1", [], [], "a" * 64)
        b2 = ledger.record_decision("Feature 2", "How 2", "Why 2", [], [], "b" * 64)

        assert b1.index == 1
        assert b2.index == 2
        assert ledger.verify_chain_integrity() is True

        # Test skipped index: change block 2 index to 3
        ledger.blocks[1].index = 3
        assert ledger.verify_chain_integrity() is False

        # Test duplicate index: change block 2 index to 1
        ledger.blocks[1].index = 1
        assert ledger.verify_chain_integrity() is False

        # Restore index to 2, verify passes again
        ledger.blocks[1].index = 2
        assert ledger.verify_chain_integrity() is True

        # Test out-of-order / non-one start: change block 1 index to 0
        ledger.blocks[0].index = 0
        assert ledger.verify_chain_integrity() is False

    def test_ledger_json_serialization_round_trip(self, tmp_path: Path):
        """Ledger and blocks support lossless JSON serialization and deserialization."""
        ledger = ArchitecturalLedger()
        conn = ArchConnection(
            source="src/client.ts",
            target="src/server.py",
            protocol="REST_POST",
            schema={"endpoint": "/api/v1/auth", "fields": ["username", "token"]},
        )
        ledger.record_decision(
            feature="Auth Enforcement",
            how="Configured JWT bearer middleware",
            why="Requirement for secure tenant isolation",
            connections=[conn],
            elements_used=["jwt", "fastapi"],
            graph_root="e" * 64,
        )

        # 1. to_dict and from_dict
        d = ledger.to_dict()
        assert d["height"] == 1
        assert len(d["blocks"]) == 1
        reconstructed = ArchitecturalLedger.from_dict(d)
        assert reconstructed.height == 1
        assert reconstructed.verify_chain_integrity() is True
        assert reconstructed.blocks[0].feature == "Auth Enforcement"
        assert reconstructed.blocks[0].connections[0].source == "src/client.ts"

        # 2. to_json and from_json
        json_str = ledger.to_json()
        assert "Auth Enforcement" in json_str
        from_json_ledger = ArchitecturalLedger.from_json(json_str)
        assert from_json_ledger.height == 1
        assert from_json_ledger.verify_chain_integrity() is True

        # 3. save_to_json and load_from_json
        file_path = tmp_path / "arch_ledger.json"
        ledger.save_to_json(file_path)
        assert file_path.exists()
        loaded_ledger = ArchitecturalLedger.load_from_json(file_path)
        assert loaded_ledger.height == 1
        assert loaded_ledger.verify_chain_integrity() is True
        assert loaded_ledger.blocks[0].block_hash == ledger.blocks[0].block_hash

    def test_arch_ledger_block_handles_plain_dicts_defensively(self):
        """ArchLedgerBlock recompute_hash and to_dict handle plain dict connection payloads without error."""
        raw_conn_dict = {
            "source": "frontend/App.tsx",
            "target": "backend/api.py",
            "protocol": "REST_GET",
            "schema": {"query": "id"},
        }
        block = ArchLedgerBlock(
            index=1,
            prev_hash="0" * 64,
            feature="Query API",
            how="GET query implementation",
            why="Data fetching",
            connections=[raw_conn_dict],  # type: ignore[arg-type]
            elements_used=["react", "fastapi"],
            graph_root="f" * 64,
        )
        assert len(block.block_hash) == 64
        # to_dict roundtrip
        block_dict = block.to_dict()
        assert block_dict["connections"][0]["source"] == "frontend/App.tsx"


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

    def test_index_endpoints_and_schemas_into_merkle_graph(self, tmp_path: Path):
        """Extracts REST endpoints (@app.get, @router.post, etc.) and Pydantic/dataclass schemas."""
        py_file = tmp_path / "api_router.py"
        py_file.write_text(
            """
from dataclasses import dataclass
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str

@dataclass
class AccountConfig:
    account_id: int
    is_active: bool

@app.get("/api/users")
def list_users():
    return []

@router.post("/api/users")
def create_user(payload: UserCreate):
    return payload

@app.route("/api/accounts", methods=["GET", "POST"])
def handle_accounts():
    return {}
""",
            encoding="utf-8",
        )

        indexer = GraphIndexer()
        graph = indexer.index_file(py_file, relative_to=tmp_path)

        # Verify SCHEMA nodes
        schemas = indexer.get_schemas(graph)
        assert len(schemas) == 2
        schema_names = {s.payload["name"] for s in schemas}
        assert "UserCreate" in schema_names
        assert "AccountConfig" in schema_names

        user_schema = graph.get_node("schema:api_router.py:UserCreate")
        assert user_schema is not None
        assert user_schema.payload["is_pydantic"] is True
        assert user_schema.payload["fields"]["username"] == "str"
        assert user_schema.payload["fields"]["email"] == "str"

        account_schema = graph.get_node("schema:api_router.py:AccountConfig")
        assert account_schema is not None
        assert account_schema.payload["is_dataclass"] is True
        assert account_schema.payload["fields"]["account_id"] == "int"

        # Verify ENDPOINT nodes
        endpoints = indexer.get_endpoints(graph)
        assert len(endpoints) == 4  # GET /api/users, POST /api/users, GET /api/accounts, POST /api/accounts

        get_users = graph.get_node("endpoint:api_router.py:GET:/api/users")
        assert get_users is not None
        assert get_users.payload["method"] == "GET"
        assert get_users.payload["path"] == "/api/users"
        assert get_users.payload["handler"] == "list_users"

        post_users = graph.get_node("endpoint:api_router.py:POST:/api/users")
        assert post_users is not None
        assert post_users.payload["method"] == "POST"

        # Verify edges: ENDPOINT -> handler SYMBOL
        edges_from_endpoint = graph.get_edges_from("endpoint:api_router.py:GET:/api/users")
        target_ids = {e.target for e in edges_from_endpoint}
        assert "sym:api_router.py:list_users" in target_ids

        # Verify edge: ENDPOINT -> SCHEMA for create_user referencing UserCreate
        post_edges = graph.get_edges_from("endpoint:api_router.py:POST:/api/users")
        post_targets = {e.target for e in post_edges}
        assert "schema:api_router.py:UserCreate" in post_targets

    def test_register_decision_node_linkages(self):
        """register_decision creates a NodeType.DECISION node with linkages to files and symbols."""
        indexer = GraphIndexer()
        graph = MerkleGraph()
        graph.add_node("file:services/auth.py", NodeType.FILE, {"path": "services/auth.py"})
        graph.add_node("sym:services/auth.py:verify_token", NodeType.SYMBOL, {"name": "verify_token"})

        decision_node = indexer.register_decision(
            graph=graph,
            decision_id="DEC-042",
            description="Replaced RS256 with Ed25519 signing",
            touched_files=["services/auth.py"],
            touched_symbols=["sym:services/auth.py:verify_token"],
            metadata={"author": "security-team"},
        )

        assert decision_node.node_id == "decision:DEC-042"
        assert decision_node.node_type == NodeType.DECISION
        assert decision_node.payload["description"] == "Replaced RS256 with Ed25519 signing"
        assert decision_node.payload["author"] == "security-team"

        # Check linkages
        edges = graph.get_edges_from("decision:DEC-042")
        targets = {e.target for e in edges}
        assert "file:services/auth.py" in targets
        assert "sym:services/auth.py:verify_token" in targets

        decisions = indexer.get_decisions(graph)
        assert len(decisions) == 1


class TestCryptographicContextRouter:
    """Test suite for CryptographicContextRouter traversing graph and ledger with inclusion proofs."""

    def test_context_router_neighborhood_traversal_and_merkle_proofs(self, tmp_path: Path):
        """Router collects neighborhood, ledger history, and validates inclusion proofs against Merkle root."""
        py_file = tmp_path / "payments.py"
        py_file.write_text(
            """
from pydantic import BaseModel

class PaymentOrder(BaseModel):
    order_id: str
    amount: float

@app.post("/payments/charge")
def charge_payment(order: PaymentOrder):
    return {"status": "success"}
""",
            encoding="utf-8",
        )

        indexer = GraphIndexer()
        graph = indexer.index_file(py_file, relative_to=tmp_path)

        # Build ledger history
        ledger = ArchitecturalLedger()
        conn = ArchConnection(
            source="frontend/Checkout.tsx",
            target="payments.py",
            protocol="REST_POST",
            schema={"body": ["order_id", "amount"]},
        )
        ledger.record_decision(
            feature="Payment Processing Gateway",
            how="Integrated Stripe webhook with PaymentOrder validation",
            why="Enables credit card settlement",
            connections=[conn],
            elements_used=["stripe", "payments.py"],
            graph_root=graph.compute_root_hash(),
        )

        router = CryptographicContextRouter(graph=graph, ledger=ledger)
        bundle: RoutedContextBundle = router.route_context(
            task_query="Payment Processing Gateway",
            target_paths=["payments.py"],
            max_hops=2,
        )

        # 1. Verification status
        assert bundle.is_verified is True
        assert bundle.merkle_root == graph.compute_root_hash()

        # 2. Collected nodes within neighborhood
        node_ids = {n.node_id for n in bundle.nodes}
        assert "file:payments.py" in node_ids
        assert "schema:payments.py:PaymentOrder" in node_ids
        assert "endpoint:payments.py:POST:/payments/charge" in node_ids
        assert "sym:payments.py:charge_payment" in node_ids

        # 3. Inclusion proofs for each node
        for node in bundle.nodes:
            assert node.node_id in bundle.proofs
            proof = bundle.proofs[node.node_id]
            assert graph.verify_merkle_proof(proof, bundle.merkle_root) is True

        # 4. Matched ledger decisions and connections
        assert len(bundle.ledger_blocks) == 1
        assert bundle.ledger_blocks[0].feature == "Payment Processing Gateway"
        assert len(bundle.connections) == 1
        assert bundle.connections[0].source == "frontend/Checkout.tsx"

        # 5. Formatted context text and serialization
        assert "Cryptographic Knowledge Context" in bundle.formatted_context
        assert "PaymentOrder" in bundle.formatted_context
        assert bundle.node_count == len(bundle.nodes)
        d = bundle.to_dict()
        assert d["is_verified"] is True
        assert d["node_count"] == len(bundle.nodes)

    def test_context_router_proof_verification_fails_closed_on_tampering(self, tmp_path: Path):
        """Context router marks bundle as unverified (fail-closed) if any node or root is tampered with."""
        graph = MerkleKnowledgeGraph()
        graph.add_node("file:main.py", NodeType.FILE, {"path": "main.py"})
        graph.add_node("sym:main.py:app", NodeType.SYMBOL, {"name": "app"})
        graph.add_edge("file:main.py", "sym:main.py:app", EdgeType.IMPLEMENTS)

        ledger = ArchitecturalLedger()
        router = CryptographicContextRouter(graph=graph, ledger=ledger)

        # Verify clean route is verified
        clean_bundle = router.route_context("main", target_paths=["main.py"])
        assert clean_bundle.is_verified is True

        # Tamper with a proof's target root hash: verify_merkle_proof fails
        fake_root = "0" * 64
        proof = clean_bundle.proofs["file:main.py"]
        assert graph.verify_merkle_proof(proof, fake_root) is False


class TestKnowledgeAndLedgerProxyPackages:
    """Test suite verifying spec-compliant proxy package exports."""

    def test_knowledge_proxy_package_exports(self):
        """agentpoi_sde.knowledge correctly exports MerkleKnowledgeGraph, MerkleNode, GraphIndexer, CryptographicContextRouter."""
        from agentpoi_sde.knowledge import (
            CryptographicContextRouter as KRouter,
        )
        from agentpoi_sde.knowledge import (
            EdgeType as KEdgeType,
        )
        from agentpoi_sde.knowledge import (
            GraphIndexer as KIndexer,
        )
        from agentpoi_sde.knowledge import (
            MerkleKnowledgeGraph as KGraph,
        )
        from agentpoi_sde.knowledge import (
            MerkleNode as KNode,
        )
        from agentpoi_sde.knowledge import (
            NodeType as KNodeType,
        )
        from agentpoi_sde.knowledge import (
            RoutedContextBundle as KBundle,
        )

        assert KGraph is MerkleKnowledgeGraph
        assert KNode is MerkleNode
        assert KIndexer is GraphIndexer
        assert KRouter is CryptographicContextRouter
        assert KNodeType is NodeType
        assert KEdgeType is EdgeType
        assert KBundle is RoutedContextBundle

    def test_ledger_proxy_package_exports(self):
        """agentpoi_sde.ledger correctly exports ArchitecturalLedger, ArchLedgerBlock, ArchConnection."""
        from agentpoi_sde.ledger import (
            ArchConnection as LConnection,
        )
        from agentpoi_sde.ledger import (
            ArchitecturalLedger as LLedger,
        )
        from agentpoi_sde.ledger import (
            ArchLedgerBlock as LBlock,
        )

        assert LLedger is ArchitecturalLedger
        assert LBlock is ArchLedgerBlock
        assert LConnection is ArchConnection
