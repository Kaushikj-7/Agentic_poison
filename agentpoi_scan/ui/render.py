"""Render helpers and view-model formatting for the scan dashboard.

All content originating from scanned code or scanners is sanitized with html.escape.
Raw code is never rendered as raw Markdown or unescaped HTML.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.findings.schemas import DashboardScanSummary, FindingDetailViewModel

AUTORUN_FILENAMES = (
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "tox.ini",
    "makefile",
    "gnumakefile",
)


def sanitize_snippet(code: str) -> str:
    """Escapes HTML entities in code snippets to eliminate XSS risks."""
    if not code:
        return ""
    return html.escape(code, quote=True)


def format_scan_summary(
    scan: Optional[Dict[str, Any]],
    counts: Dict[str, int],
    autorun_count: int = 0,
    isolation_level: str = "in-process (Weak)",
) -> DashboardScanSummary:
    """Constructs a validated DashboardScanSummary from store scan and counts."""
    scan_data = scan or {}
    total = sum(counts.get(sev, 0) for sev in ("critical", "high", "medium", "low"))
    risk = scan_data.get("risk") or {}
    return DashboardScanSummary(
        scan_id=int(scan_data.get("id", 0)),
        repo=str(scan_data.get("repo", "")),
        commit_sha=str(scan_data.get("commit_sha", "")),
        created_at=str(scan_data.get("created_at", "")),
        vulnerability_score=float(risk.get("vulnerable", 0.0)),
        maliciousness_score=float(risk.get("malicious", 0.0)),
        total_findings=total,
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        medium_count=counts.get("medium", 0),
        low_count=counts.get("low", 0),
        isolation_level="container" if isolation_level == "container" else "in-process (Weak)",
        autorun_count=autorun_count,
    )


def format_findings_for_table(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Converts findings into displayable row dicts."""
    rows: List[Dict[str, Any]] = []
    for f in findings:
        rows.append(
            {
                "fingerprint": f.fingerprint,
                "severity": f.severity.lower(),
                "category": f.category,
                "file": f.file,
                "lines": ", ".join(str(ln) for ln in f.lines) if f.lines else "all",
                "title": f.title,
                "scanner": f.scanner,
                "status": f.status,
                "confidence": round(f.confidence, 2),
                "maliciousness": round(f.maliciousness, 2),
                "vulnerability": round(f.vulnerability, 2),
            }
        )
    return rows


def is_autorun_finding(finding: Finding) -> bool:
    """True if finding lies on the repository's autorun execution surface."""
    if finding.category == "autorun":
        return True
    lower_path = finding.file.lower().replace("\\", "/")
    if any(lower_path.endswith(fn) for fn in AUTORUN_FILENAMES):
        return True
    if ".github/workflows/" in lower_path or ".circleci/" in lower_path:
        return True
    return False


def format_autorun_panel(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Filters findings relevant to execution on install/build/CI."""
    autorun_findings = [f for f in findings if is_autorun_finding(f)]
    return format_findings_for_table(autorun_findings)


def format_evidence_trail(finding: Finding) -> List[Dict[str, Any]]:
    """Formats evidence trail entries for audit trail display."""
    return list(finding.evidence)


def format_finding_detail(
    finding: Finding,
    raw_snippet: Optional[str] = None,
) -> FindingDetailViewModel:
    """Produces a sanitized FindingDetailViewModel safe for UI display."""
    snippet = raw_snippet if raw_snippet is not None else finding.detail
    return FindingDetailViewModel(
        fingerprint=finding.fingerprint,
        file=finding.file,
        lines=finding.lines,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        detail=finding.detail,
        scanner=finding.scanner,
        confidence=finding.confidence,
        maliciousness=finding.maliciousness,
        vulnerability=finding.vulnerability,
        status=finding.status,
        evidence_trail=finding.evidence,
        model_trail=finding.model_trail,
        escaped_snippet=sanitize_snippet(snippet),
    )
