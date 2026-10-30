"""Tests for deterministic remediation guidance and severity badges."""

from __future__ import annotations

from agentpoi_scan.findings.model import CATEGORIES, Finding
from agentpoi_scan.findings.remediation import (
    CATEGORY_REMEDIATION,
    FALLBACK_REMEDIATION,
    SCANNER_REMEDIATION,
    file_remediation_notes,
    remediation_for_finding,
)
from agentpoi_scan.ui.render import (
    format_file_remediation,
    format_flagged_files,
    format_severity_badge,
)


def _finding(**overrides) -> Finding:
    base = {
        "file": "src/app.py",
        "lines": [10],
        "category": "sast",
        "severity": "high",
        "title": "Unsafe call",
        "detail": "detail",
        "scanner": "python_sast",
    }
    base.update(overrides)
    return Finding(**base)


def test_every_category_has_static_remediation_guidance():
    assert set(CATEGORY_REMEDIATION) == set(CATEGORIES)
    for category in CATEGORIES:
        note = remediation_for_finding(_finding(category=category, scanner="unknown_scanner"))
        assert note == CATEGORY_REMEDIATION[category]
        assert note != FALLBACK_REMEDIATION
        assert len(note) > 40


def test_scanner_specific_guidance_takes_precedence():
    finding = _finding(category="sast", scanner="taint_flow")
    assert remediation_for_finding(finding) == SCANNER_REMEDIATION["taint_flow"]

    secret = _finding(category="secrets", scanner="gitleaks")
    assert remediation_for_finding(secret) == SCANNER_REMEDIATION["gitleaks"]


def test_file_remediation_notes_prioritize_worst_and_dedupe():
    findings = [
        _finding(category="binary", severity="low", scanner="binflag", lines=[]),
        _finding(category="sast", severity="critical", scanner="python_sast", lines=[4]),
        _finding(category="sast", severity="critical", scanner="legacy_patterns", lines=[2]),
        _finding(category="secrets", severity="high", scanner="gitleaks", lines=[9]),
    ]
    notes = file_remediation_notes(findings)
    assert [item["category"] for item in notes] == ["sast", "secrets", "binary"]
    assert len({item["note"] for item in notes}) == 3

    limited = file_remediation_notes(findings, limit=2)
    assert [item["category"] for item in limited] == ["sast", "secrets"]


def test_severity_badge_mapping_is_plain_text():
    assert format_severity_badge("critical") == "🔴 CRITICAL"
    assert format_severity_badge("High") == "🟠 HIGH"
    assert format_severity_badge("medium") == "🟡 MEDIUM"
    assert format_severity_badge("low") == "🔵 LOW"
    assert format_severity_badge("unknown") == "⚪ UNKNOWN"
    for severity in ("critical", "high", "medium", "low", "unknown"):
        assert "<" not in format_severity_badge(severity)


def test_flagged_files_rows_include_badge_and_top_remediation():
    findings = [
        _finding(
            file="evil.py",
            category="malware",
            severity="critical",
            scanner="legacy_patterns",
            lines=[3],
        ),
        _finding(file="notes.py", category="sast", severity="low", scanner="python_sast"),
    ]
    rows = format_flagged_files(findings)
    assert rows[0]["file"] == "evil.py"
    assert rows[0]["badge"] == "🔴 CRITICAL"
    assert rows[0]["remediation"].startswith("[malware]")
    assert "quarantine" in rows[0]["remediation"]
    assert rows[1]["badge"] == "🔵 LOW"

    notes = format_file_remediation([findings[0]])
    assert len(notes) == 1
    assert notes[0].startswith("[malware]")
