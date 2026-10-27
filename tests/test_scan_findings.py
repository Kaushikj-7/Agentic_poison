"""Tests for the canonical Finding model and repo risk scoring."""

import pytest

from agentpoi_scan.findings.model import (
    Finding,
    dedupe,
    is_authoritative,
    severity_rank,
)
from agentpoi_scan.findings.risk_score import repo_risk_score


def _finding(**kwargs):
    base = dict(
        file="src/app.py",
        lines=[10],
        category="sast",
        severity="high",
        title="os.system call",
        detail="uses os.system",
        scanner="python_sast",
    )
    base.update(kwargs)
    return Finding(**base)


def test_fingerprint_is_stable_and_input_sensitive():
    a = _finding()
    b = _finding()
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != _finding(title="other").fingerprint
    assert a.fingerprint != _finding(file="src/other.py").fingerprint


def test_invalid_category_and_severity_rejected():
    with pytest.raises(ValueError, match="category"):
        _finding(category="banana")
    with pytest.raises(ValueError, match="severity"):
        _finding(severity="banana")
    with pytest.raises(ValueError, match="confidence"):
        _finding(confidence=1.5)


def test_authoritative_threshold():
    assert not is_authoritative("medium")
    assert is_authoritative("high")
    assert is_authoritative("critical")


def test_severity_rank_ordering():
    assert severity_rank("low") < severity_rank("medium") < severity_rank("high") < severity_rank("critical")
    assert severity_rank("nonsense") == -1


def test_dedupe_keeps_most_severe_and_merges_evidence():
    low = _finding(severity="low", evidence=[{"kind": "scanner_output", "text": "a"}])
    crit = _finding(severity="critical", evidence=[{"kind": "model_reasoning", "text": "b"}])
    merged = dedupe([low, crit])
    assert len(merged) == 1
    assert merged[0].severity == "critical"
    assert len(merged[0].evidence) == 2


def test_dedupe_prefers_scanner_source():
    triage = _finding(source="llm_triage", scanner="python_sast")
    scanner = _finding()
    merged = dedupe([triage, scanner])
    assert merged[0].source == "scanner"


def test_roundtrip_via_dict():
    finding = _finding(evidence=[{"kind": "test", "text": "t"}], model_trail=["triage"])
    restored = Finding.from_dict(finding.to_dict())
    assert restored == finding


def test_risk_score_weighted_max_not_mean():
    clean_garbage = [_finding(vulnerability=0.2, severity="low") for _ in range(500)]
    backdoor = _finding(
        severity="critical", maliciousness=0.95, title="backdoor"
    )
    score_with = repo_risk_score(clean_garbage + [backdoor])
    score_only = repo_risk_score([backdoor])
    # a single critical backdoor must not be diluted by 500 clean files
    assert score_with["malicious"] >= 0.9 * 0.99
    assert score_with["malicious"] == score_only["malicious"]
    assert repo_risk_score([]) == {"vulnerable": 0.0, "malicious": 0.0}


def test_clean_repo_zero_risk():
    findings = [_finding(vulnerability=0.0, maliciousness=0.0) for _ in range(10)]
    assert repo_risk_score(findings) == {"vulnerable": 0.0, "malicious": 0.0}
