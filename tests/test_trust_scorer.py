"""Unit tests for CTP Trust Scorer and Non-Dilutable Taint Formulation."""

import pytest

from agent_poi.core.trust_scorer import TrustScorer
from agent_poi.memory.schema import FirewallStatus, SourceOrigin


def test_trust_exponential_decay():
    scorer = TrustScorer(lambda_decay=2.5)
    # Origin prior = 0.95 (verified user)
    clean_score = scorer.compute_direct_trust(SourceOrigin.VERIFIED_USER, r_ci=0.0)
    assert clean_score == pytest.approx(0.95, rel=1e-2)

    # With high CI risk (r_ci = 0.9), trust should collapse exponentially
    poison_score = scorer.compute_direct_trust(SourceOrigin.VERIFIED_USER, r_ci=0.9)
    assert poison_score < 0.15


def test_geometric_mean_non_dilution():
    scorer = TrustScorer()
    # 1 tainted ancestor (0.10) combined with 3 clean ancestors (0.95)
    ancestor_scores = [0.10, 0.95, 0.95, 0.95]
    geom_factor = scorer.compute_ancestor_trust_factor(ancestor_scores)

    # In arithmetic mean this would be 0.7375 (laundered).
    # In geometric mean, it is (0.10 * 0.95^3)^0.25 ~ 0.54
    assert geom_factor < 0.55

    # With direct untrusted web prior (0.25), final score is severely depressed
    final_score = scorer.compute_score(SourceOrigin.UNTRUSTED_WEB, r_ci=0.3, parent_trust_scores=ancestor_scores)
    assert final_score < 0.20


def test_firewall_classification():
    scorer = TrustScorer(tau_threshold=0.50, tau_critical=0.25)

    # Clean verified user
    dec_clean = scorer.evaluate("item_clean", "clean text", SourceOrigin.VERIFIED_USER, r_ci=0.05, reasons=[])
    assert dec_clean.status == FirewallStatus.ALLOWED

    # Moderate risk item -> Quarantine
    dec_quarantine = scorer.evaluate("item_warn", "untrusted text", SourceOrigin.INTERNAL_TOOL, r_ci=0.35, reasons=[])
    assert dec_quarantine.status == FirewallStatus.QUARANTINED

    # High risk item -> Block
    dec_block = scorer.evaluate("item_block", "exploit text", SourceOrigin.UNTRUSTED_WEB, r_ci=0.85, reasons=[])
    assert dec_block.status == FirewallStatus.BLOCKED
