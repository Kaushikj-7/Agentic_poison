"""Pydantic v2 schemas for scan UI boundaries and view-models."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanTargetRequest(BaseModel):
    """Schema for initiating an untrusted repository scan."""

    model_config = ConfigDict(extra="forbid", strict=True)

    repo_url: str = Field(..., description="GitHub repository URL or owner/repo format")
    ref: Optional[str] = Field(None, description="Pinned branch, tag, or commit SHA")
    enable_agentic_triage: bool = Field(True, description="Whether to run local/free LLM triage")
    enable_deep_analysis: bool = Field(True, description="Whether to escalate high-severity findings to analyst")


class FindingFilterQuery(BaseModel):
    """Schema for querying persisted findings in the dashboard."""

    model_config = ConfigDict(extra="forbid", strict=True)

    scan_id: int = Field(..., ge=1, description="Unique scan identifier")
    severity: Optional[Literal["critical", "high", "medium", "low"]] = Field(None)
    category: Optional[
        Literal[
            "sast",
            "secrets",
            "deps",
            "malware",
            "ci_iac",
            "injection",
            "autorun",
            "unicode_trojan",
            "binary",
        ]
    ] = Field(None)
    search_query: Optional[str] = Field(None, max_length=100)
    # Status values match analyst.py (sets "triaged", "confirmed", "escalated")
    # plus pipeline-level "open" and user-driven "refuted", "human_review"
    status: Optional[
        Literal["open", "triaged", "confirmed", "refuted", "escalated", "human_review"]
    ] = Field(None)


class DashboardScanSummary(BaseModel):
    """Schema for rendering the high-level scan scorecard."""

    model_config = ConfigDict(extra="forbid", strict=True)

    scan_id: int
    repo: str
    commit_sha: str
    created_at: str
    vulnerability_score: float = Field(..., ge=0.0, le=1.0)
    maliciousness_score: float = Field(..., ge=0.0, le=1.0)
    total_findings: int = Field(..., ge=0)
    critical_count: int = Field(..., ge=0)
    high_count: int = Field(..., ge=0)
    medium_count: int = Field(..., ge=0)
    low_count: int = Field(..., ge=0)
    isolation_level: Literal["container", "in-process (Weak)"]
    autorun_count: int = Field(..., ge=0)


class FindingDetailViewModel(BaseModel):
    """Safe view-model for presenting a finding without HTML/script injection risks."""

    model_config = ConfigDict(extra="forbid", strict=True)

    fingerprint: str
    file: str
    location: str = Field(..., description="Source location as file:line")
    lines: List[int]
    category: str
    severity: str
    title: str
    detail: str
    scanner: str
    confidence: float
    maliciousness: float
    vulnerability: float
    status: str
    evidence_trail: List[Dict[str, Any]]
    model_trail: List[str]
    escaped_snippet: str = Field(..., description="Sanitized, HTML-escaped code snippet")
