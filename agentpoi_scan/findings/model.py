"""Canonical Finding model shared by every scanner and agent in the pipeline."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY_ORDER: Dict[str, int] = {CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0}

# Scanner findings at or above this rank are "authoritative-deterministic": the
# LLM triage/analyst layers may ANNOTATE them but must never silence them
# (DEC-105). Silencing additionally requires verifier agreement + human flag.
AUTHORITATIVE_RANK = _SEVERITY_ORDER[HIGH]

SOURCE_SCANNER = "scanner"
SOURCE_TRIAGE = "llm_triage"
SOURCE_ANALYST = "llm_analyst"
SOURCE_VERIFIER = "llm_verifier"

CATEGORIES = (
    "sast",
    "secrets",
    "deps",
    "malware",
    "ci_iac",
    "injection",
    "autorun",
    "unicode_trojan",
    "binary",
)


def severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, -1)


def is_authoritative(severity: str) -> bool:
    """True for deterministic scanner findings that models must never silence."""
    return severity_rank(severity) >= AUTHORITATIVE_RANK


@dataclass
class Finding:
    """One actionable observation about a scanned snapshot."""

    file: str
    lines: List[int]
    category: str
    severity: str
    title: str
    detail: str
    scanner: str
    commit_sha: str = ""
    source: str = SOURCE_SCANNER
    confidence: float = 0.9
    maliciousness: float = 0.0
    vulnerability: float = 0.0
    status: str = "open"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    model_trail: List[str] = field(default_factory=list)
    # Exact vulnerable source text (trimmed), persisted so the dashboard and
    # reports can show WHERE the problem lives, not just a description.
    snippet: str = ""

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category}")
        if self.severity not in _SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")

    @property
    def fingerprint(self) -> str:
        """Stable identity: rule (scanner+title), file, and normalized line span."""
        line_start = min(self.lines) if self.lines else 0
        raw = f"{self.scanner}|{self.title}|{self.file}|{line_start}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @property
    def location(self) -> str:
        """Human-readable source location, e.g. ``app/server.py:42``."""
        if self.lines:
            return f"{self.file}:{min(self.lines)}"
        return self.file

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "commit_sha": self.commit_sha,
            "file": self.file,
            "lines": self.lines,
            "source": self.source,
            "scanner": self.scanner,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "maliciousness": self.maliciousness,
            "vulnerability": self.vulnerability,
            "status": self.status,
            "evidence": self.evidence,
            "model_trail": list(self.model_trail),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        data = dict(data)
        data.pop("fingerprint", None)
        return cls(
            file=data["file"],
            lines=list(data.get("lines") or []),
            category=data["category"],
            severity=data["severity"],
            title=data["title"],
            detail=data.get("detail", ""),
            snippet=data.get("snippet", ""),
            scanner=data.get("scanner", "unknown"),
            commit_sha=data.get("commit_sha", ""),
            source=data.get("source", SOURCE_SCANNER),
            confidence=float(data.get("confidence", 0.9)),
            maliciousness=float(data.get("maliciousness", 0.0)),
            vulnerability=float(data.get("vulnerability", 0.0)),
            status=data.get("status", "open"),
            evidence=list(data.get("evidence") or []),
            model_trail=list(data.get("model_trail") or []),
        )


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Merge findings sharing a fingerprint, keeping the most severe/highest confidence."""
    best: Dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        scanner_wins = (
            finding.source == SOURCE_SCANNER and current.source != SOURCE_SCANNER
        )
        better = (
            severity_rank(finding.severity) > severity_rank(current.severity)
            or (
                severity_rank(finding.severity) == severity_rank(current.severity)
                and finding.confidence > current.confidence
            )
        )
        if better or scanner_wins:
            merged, other = finding, current
        else:
            merged, other = current, finding
        merged.evidence.extend(other.evidence)
        if not merged.snippet:
            merged.snippet = other.snippet
        best[key] = merged
    return list(best.values())
