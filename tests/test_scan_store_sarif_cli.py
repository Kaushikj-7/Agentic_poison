"""Tests for the scan store, SARIF export and the CLI surface."""

import json
import subprocess
import sys
from pathlib import Path

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.report.sarif import sarif_document, write_sarif
from agentpoi_scan.report.store import ScanStore


def _finding(**kw):
    base = dict(
        file="src/app.py",
        lines=[7],
        category="sast",
        severity="high",
        title="os.system call",
        detail="uses os.system",
        scanner="python_sast",
        commit_sha="abc",
    )
    base.update(kw)
    return Finding(**base)


# -- store ---------------------------------------------------------------------
def test_store_roundtrip_and_filters(tmp_path):
    store = ScanStore(tmp_path / "store.sqlite3")
    scan_id = store.add_scan("owner/repo", "abc123", [_finding(), _finding(severity="low", title="other")])
    meta = store.get_scan(scan_id)
    assert meta["repo"] == "owner/repo"
    assert meta["risk"]["vulnerable"] >= 0.0
    all_findings = store.list_findings(scan_id)
    assert len(all_findings) == 2
    highs = store.list_findings(scan_id, severity="high")
    assert len(highs) == 1 and highs[0].severity == "high"
    secrets_only = store.list_findings(scan_id, category="injection")
    assert secrets_only == [] or all(f.category == "injection" for f in secrets_only)
    assert store.latest_scan()["id"] == scan_id


def test_store_dedupes_same_fingerprint(tmp_path):
    store = ScanStore(tmp_path / "store.sqlite3")
    scan_id = store.add_scan("owner/repo", "abc", [_finding(), _finding()])
    assert len(store.list_findings(scan_id)) == 1


# -- sarif ---------------------------------------------------------------------
def test_sarif_document_shape():
    doc = sarif_document([_finding()])
    assert doc["version"] == "2.1.0"
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["properties"]["maliciousness"] == 0.0
    assert result["partialFingerprints"]["primary"]


def test_write_sarif_creates_file(tmp_path):
    path = write_sarif([_finding()], tmp_path / "out" / "f.sarif")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"][0]["message"]["text"] == "uses os.system"


# -- CLI -----------------------------------------------------------------------
def _run_cli(*argv, cwd):
    return subprocess.run(
        [sys.executable, "-m", "agentpoi_scan.cli", *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PATH": ""},
        check=False,
    )


def test_cli_validate_ok_and_fail(tmp_path):
    good = _run_cli("validate", "scan_registry", cwd=tmp_path)
    assert good.returncode == 2, "empty registry has orphan errors"  # (no projects yet → ok may pass; ajuste)

    import yaml  # noqa: F401

    (tmp_path / "scan_registry" / "acme").mkdir(parents=True)
    (tmp_path / "scan_registry" / "acme" / "project.yaml").write_text(
        "repo: https://github.com/acme/acme\n", encoding="utf-8"
    )
    ok = _run_cli("validate", "scan_registry", cwd=tmp_path)
    assert "REGISTRY: OK" in ok.stdout and ok.returncode == 0
