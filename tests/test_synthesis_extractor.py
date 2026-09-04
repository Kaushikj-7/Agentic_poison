"""Unit tests for the research synthesis and paper metadata extractor."""

import pytest
from agent_poi.research.synthesis_extractor import (
    ResearchPaperMetadata,
    ResearchSynthesisExtractor,
    DomainAdaptationRecord,
)


def test_research_paper_metadata_validation():
    """Verify ResearchPaperMetadata initializes and validates fields."""
    meta = ResearchPaperMetadata(
        paper_id="REF-01",
        title="AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses on LLM Agents",
        authors=["Edoardo Debenedetti", "Javier Rando", "Daniel Paleka"],
        venue="NeurIPS",
        year=2024,
        arxiv_id="2406.13315",
        primary_focus="Dynamic multi-tool benchmark, banking environment, IPI",
        baseline_asr=82.4,
    )
    assert meta.paper_id == "REF-01"
    assert meta.year == 2024
    assert meta.baseline_asr == 82.4
    assert len(meta.authors) == 3


def test_synthesis_extractor_canonical_registry():
    """Verify ResearchSynthesisExtractor loads canonical literature registry."""
    extractor = ResearchSynthesisExtractor()
    papers = extractor.get_canonical_papers()

    assert len(papers) >= 6
    paper_ids = [p.paper_id for p in papers]
    assert "REF-01" in paper_ids  # AgentDojo
    assert "REF-02" in paper_ids  # InjecAgent
    assert "REF-03" in paper_ids  # Task Shield
    assert "REF-04" in paper_ids  # AuthGraph
    assert "REF-05" in paper_ids  # DataSentinel
    assert "REF-06" in paper_ids  # MINJA


def test_synthesis_extractor_domain_adaptation():
    """Verify domain adaptation records correctly define novelty boundaries."""
    extractor = ResearchSynthesisExtractor()
    adaptations = extractor.get_domain_adaptations()

    assert len(adaptations) >= 6
    authgraph_adapt = next(a for a in adaptations if a.paper_id == "REF-04")
    assert "disbursement" in authgraph_adapt.financial_specialization.lower()
    assert authgraph_adapt.novelty_boundary != ""
    assert authgraph_adapt.copyright_risk_level == "NONE"


def test_generate_bibtex_entries():
    """Verify automated BibTeX citation generation for arXiv research paper."""
    extractor = ResearchSynthesisExtractor()
    bibtex = extractor.generate_bibtex_file()

    assert "@inproceedings{debenedetti2024agentdojo" in bibtex
    assert "@article{zou2024injecagent" in bibtex
    assert "@article{taskshield2025" in bibtex
    assert "@article{authgraph2026" in bibtex
