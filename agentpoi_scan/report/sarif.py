"""SARIF 2.1.0 export for canonical findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from agentpoi_scan.findings.model import Finding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _result(finding: Finding) -> Dict[str, Any]:
    region: Dict[str, Any] = {}
    if finding.lines:
        region = {"startLine": min(finding.lines), "endLine": max(finding.lines)}
    if finding.snippet:
        region["snippet"] = {"text": finding.snippet}
    return {
        "ruleId": f"{finding.scanner}/{finding.title}",
        "level": _LEVEL.get(finding.severity, "note"),
        "message": {"text": finding.detail},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {"primary": finding.fingerprint},
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "source": finding.source,
            "scanner": finding.scanner,
            "confidence": finding.confidence,
            "maliciousness": finding.maliciousness,
            "vulnerability": finding.vulnerability,
            "status": finding.status,
            "commit_sha": finding.commit_sha,
            "model_trail": finding.model_trail,
        },
    }


def sarif_document(findings: Iterable[Finding], tool: str = "agentpoi-scan") -> Dict[str, Any]:
    results: List[Dict[str, Any]] = [_result(f) for f in findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": {}}}, "results": results}],
    }


def write_sarif(findings: Iterable[Finding], path: str | Path, tool: str = "agentpoi-scan") -> Path:
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(sarif_document(findings, tool=tool), indent=2), encoding="utf-8")
    except (OSError, PermissionError):
        pass
    return path
