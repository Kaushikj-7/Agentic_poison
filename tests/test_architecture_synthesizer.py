"""Unit tests for ArchitectureSynthesizer and CandidateArchitecture."""

import pytest

from agent_poi.research.architecture_synthesizer import (
    ArchitectureSynthesizer,
    CandidateArchitecture,
)


@pytest.fixture
def mock_paper_extracts():
    return [
        {
            "paper_id": "01",
            "title": "AI Agents May Always Fall for Prompt Injections",
            "defense_mechanisms": ["contextual integrity", "execution sink invariants"],
            "attack_vectors": ["indirect prompt injection", "norm evasion"],
            "architecture_patterns": ["DAG", "fail-closed"],
        },
        {
            "paper_id": "04",
            "title": "DataSentinel: Game-Theoretic Detection",
            "defense_mechanisms": ["minimax game detection", "memory firewall"],
            "attack_vectors": ["adaptive black-box mutator"],
            "architecture_patterns": ["minimax", "zero trust"],
        },
        {
            "paper_id": "06",
            "title": "Firewalls to Secure Dynamic LLM Agentic Networks",
            "defense_mechanisms": ["language converter", "data abstraction firewall"],
            "attack_vectors": ["agent-to-agent contagion"],
            "architecture_patterns": ["dual firewall", "pipeline"],
        },
    ]


class TestArchitectureSynthesizer:
    def test_candidate_synthesis_count(self, mock_paper_extracts):
        synthesizer = ArchitectureSynthesizer(mock_paper_extracts)
        candidates = synthesizer.synthesize_candidates()
        assert len(candidates) == 6
        arch_ids = [c.arch_id for c in candidates]
        assert arch_ids == ["ARCH-001", "ARCH-002", "ARCH-003", "ARCH-004", "ARCH-005", "ARCH-006"]

    def test_design_principles_and_papers(self, mock_paper_extracts):
        synthesizer = ArchitectureSynthesizer(mock_paper_extracts)
        candidates = synthesizer.synthesize_candidates()
        for c in candidates:
            assert isinstance(c, CandidateArchitecture)
            assert len(c.design_principles) >= 2
            assert len(c.components) >= 4
            assert len(c.inspired_by) >= 2
            assert "security" in c.expected_tradeoffs
            assert "utility" in c.expected_tradeoffs
            assert "latency" in c.expected_tradeoffs

    def test_arch006_unified_pareto_guard(self, mock_paper_extracts):
        synthesizer = ArchitectureSynthesizer(mock_paper_extracts)
        candidates = synthesizer.synthesize_candidates()
        arch6 = [c for c in candidates if c.arch_id == "ARCH-006"][0]
        assert arch6.name == "Unified Pareto-Optimal Financial Guard"
        assert len(arch6.components) == 5
        comp_names = [comp["name"] for comp in arch6.components]
        assert "CapSealBroker" in comp_names
        assert "ArgusInfluenceScorer" in comp_names
        assert "ReconciledStateAnchorVerifier" in comp_names
        assert "01" in arch6.inspired_by
        assert "17a" in arch6.inspired_by

    def test_comparison_table_generation(self, mock_paper_extracts):
        synthesizer = ArchitectureSynthesizer(mock_paper_extracts)
        candidates = synthesizer.synthesize_candidates()
        table = synthesizer.generate_comparison_table(candidates)
        assert "# Architecture Candidate Comparison Table" in table
        assert "ARCH-001" in table
        assert "ARCH-006" in table
        assert "Expected Security" in table
