"""Unit tests for ZeroHallucinationPaperTutor and Research Paper Corpus."""

import pytest
from agent_poi.research.paper_corpus import PAPER_CORPUS, LearningTier
from agent_poi.research.paper_tutor import ZeroHallucinationPaperTutor


@pytest.fixture
def tutor():
    return ZeroHallucinationPaperTutor()


def test_corpus_size_and_integrity(tutor):
    """Verify that all 21 research papers are properly indexed."""
    assert len(PAPER_CORPUS) == 21
    for paper_id, meta in PAPER_CORPUS.items():
        assert meta.paper_id == paper_id
        assert len(meta.title) > 0
        assert len(meta.authors) > 0
        assert meta.year >= 2023
        assert len(meta.verbatim_key_quotes) > 0
        assert len(meta.formal_invariants_or_math) > 0


def test_tier_listing(tutor):
    """Verify papers can be grouped by learning tier."""
    tier1 = tutor.list_by_tier(LearningTier.TIER_1_FOUNDATIONS)
    assert len(tier1) >= 4

    tier2 = tutor.list_by_tier(LearningTier.TIER_2_IMPOSSIBILITY)
    assert len(tier2) >= 3

    tier3 = tutor.list_by_tier(LearningTier.TIER_3_IFC_PROVENANCE)
    assert len(tier3) >= 4


def test_grounded_query_abdelnabi(tutor):
    """Verify accurate grounded query retrieval for Contextual Integrity paper."""
    resp = tutor.answer_query("Contextual Integrity 5-tuple impossibility")
    assert resp.is_grounded is True
    assert len(resp.primary_citations) > 0
    assert any("01_abdelnabi2026" in c.paper_id for c in resp.primary_citations)
    assert len(resp.formal_invariants) > 0
    assert any("\\kappa" in inv for inv in resp.formal_invariants)


def test_grounded_query_fides_ifc(tutor):
    """Verify query retrieval for Fides Information Flow Control."""
    resp = tutor.answer_query("Fides Information Flow Control taint tracking")
    assert resp.is_grounded is True
    assert any("09_costa2025" in c.paper_id for c in resp.primary_citations)
    assert any("Taint Lattice" in inv for inv in resp.formal_invariants)


def test_ungrounded_query_rejection(tutor):
    """Verify zero-hallucination rejection when asked about completely unrelated concepts."""
    resp = tutor.answer_query("quantum espresso crystal diffraction physics simulation xyz999")
    assert resp.is_grounded is False
    assert resp.grounding_confidence == 0.0
    assert "could not be verified" in resp.topic_summary
