"""Repo-level risk scoring: weighted MAX on two separate axes (DEC-106).

One backdoor must not be diluted by 500 clean files, so the aggregate is a
severity-weighted maximum over findings, never a mean.
"""

from __future__ import annotations

from typing import Dict, List

from agentpoi_scan.findings.model import Finding, severity_rank

_WEIGHT: Dict[int, float] = {3: 1.0, 2: 0.9, 1: 0.6, 0: 0.3}


def _weighted_max(findings: List[Finding], attr: str) -> float:
    best = 0.0
    for finding in findings:
        base = float(getattr(finding, attr))
        if base <= 0.0:
            continue
        weighted = base * _WEIGHT[severity_rank(finding.severity)]
        best = max(best, min(1.0, weighted))
    return round(best, 3)


def repo_risk_score(findings: List[Finding]) -> Dict[str, float]:
    """Returns {'vulnerable': 0..1, 'malicious': 0..1} — independent axes."""
    vulnerable = _weighted_max(findings, "vulnerability")
    malicious = _weighted_max(findings, "maliciousness")
    # Pure vulnerability knowledge (e.g. an SQLi) has maliciousness 0 by
    # default; a finding that is malicious also counts as severe, so let the
    # malicious axis cover it and have a small bleed into 'vulnerable' when a
    # finding has ONLY maliciousness (intentional harm is still a risk).
    if malicious > 0.0:
        vulnerable = max(vulnerable, min(1.0, malicious * 0.9))
    return {"vulnerable": vulnerable, "malicious": malicious}
