"""Tests for the tier-aware provenance DAG (P)."""

import pytest

from agent_poi.memory.schema import SourceOrigin
from agentpoi_sde.domain import TrustTier
from agentpoi_sde.provenance.code_provenance import ProvenanceDAG, tier_for_origin


def test_tier_mapping_of_origins():
    assert tier_for_origin(SourceOrigin.VERIFIED_USER) == TrustTier.T0_AUTHENTICATED_INTENT
    assert tier_for_origin(SourceOrigin.SYSTEM_INSTRUCTION) == TrustTier.T0_AUTHENTICATED_INTENT
    assert tier_for_origin(SourceOrigin.INTERNAL_TOOL) == TrustTier.T1_REPOSITORY_GROUND_TRUTH
    assert tier_for_origin(SourceOrigin.UNTRUSTED_WEB) == TrustTier.T2_UNTRUSTED_CONTEXT
    assert tier_for_origin(SourceOrigin.EXTERNAL_API) == TrustTier.T2_UNTRUSTED_CONTEXT


def test_valid_lineage_with_authenticated_root_is_accepted():
    dag = ProvenanceDAG()
    root = dag.add_node("intent", SourceOrigin.VERIFIED_USER)
    context = dag.add_node("doc", SourceOrigin.UNTRUSTED_WEB)
    mutation = dag.add_node(
        "mutation", SourceOrigin.VERIFIED_USER, parent_ids=[root.node_id, context.node_id]
    )
    ok, messages = dag.verify_mutation_authority(mutation.node_id)
    assert ok is True
    assert messages == []


def test_untrusted_context_cannot_author_a_mutation():
    dag = ProvenanceDAG()
    root = dag.add_node("intent", SourceOrigin.VERIFIED_USER)
    mutation = dag.add_node("mutation", SourceOrigin.UNTRUSTED_WEB, parent_ids=[root.node_id])
    ok, messages = dag.verify_mutation_authority(mutation.node_id)
    assert ok is False
    assert any("P4" in message for message in messages)


def test_mutation_without_authenticated_root_ancestor_is_rejected():
    dag = ProvenanceDAG()
    context = dag.add_node("doc", SourceOrigin.UNTRUSTED_WEB)
    mutation = dag.add_node(
        "mutation",
        SourceOrigin.VERIFIED_USER,
        parent_ids=[context.node_id],
        is_authenticated_root=False,
    )
    ok, messages = dag.verify_mutation_authority(mutation.node_id)
    assert ok is False
    assert any("P3" in message for message in messages)


def test_hash_tampering_is_detected():
    dag = ProvenanceDAG()
    root = dag.add_node("intent", SourceOrigin.VERIFIED_USER)
    mutation = dag.add_node("mutation", SourceOrigin.VERIFIED_USER, parent_ids=[root.node_id])
    dag.nodes[mutation.node_id].content = "tampered after hashing"
    ok, messages = dag.verify_mutation_authority(mutation.node_id)
    assert ok is False
    assert any("P2" in message for message in messages)


def test_unknown_node_reports_p1():
    dag = ProvenanceDAG()
    ok, messages = dag.verify_mutation_authority("does-not-exist")
    assert ok is False
    assert any("P1" in message for message in messages)


def test_duplicate_ids_and_missing_parents_are_rejected():
    dag = ProvenanceDAG()
    dag.add_node("a", SourceOrigin.VERIFIED_USER, node_id="n1")
    with pytest.raises(ValueError):
        dag.add_node("b", SourceOrigin.VERIFIED_USER, node_id="n1")
    with pytest.raises(ValueError):
        dag.add_node("c", SourceOrigin.VERIFIED_USER, parent_ids=["missing"])
