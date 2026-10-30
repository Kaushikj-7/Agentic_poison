"""Tests for external command scanners: skipped-when-missing, parsers, argv pinning."""

import json

from agentpoi_scan.scan.base import ScanContext
from agentpoi_scan.scan.external_cmd import GITLEAKS, SEMGREP, ExternalToolScanner


def test_semgrep_skips_when_binary_absent(tmp_path):
    scanner = ExternalToolScanner(SEMGREP, which=lambda _b: None)
    ctx = ScanContext(snapshot_dir=tmp_path, repo="r", commit_sha="x", file_index=[])
    result = scanner.run(ctx)
    assert result.skipped and "semgrep" in result.skip_reason
    assert result.findings == []


def test_gitleaks_skips_when_binary_absent(tmp_path):
    scanner = ExternalToolScanner(GITLEAKS, which=lambda _b: None)
    ctx = ScanContext(snapshot_dir=tmp_path, repo="r", commit_sha="x", file_index=[])
    assert scanner.run(ctx).skipped


def fakes_run_never_executed(tmp_path):
    pass


def test_semgrep_argv_uses_snapshot_placeholder(tmp_path):
    assert "{snapshot}" in " ".join(SEMGREP.args)
    resolved = [a.replace("{snapshot}", str(tmp_path)) for a in SEMGREP.args]
    assert str(tmp_path) in resolved
    assert "--metrics=off" in SEMGREP.args, "telemetry must remain off"


def test_parse_semgrep_json():
    report = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.subprocess",
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 12},
                    "extra": {"severity": "ERROR", "message": "subprocess with shell=True"},
                }
            ]
        }
    )
    findings = ExternalToolScanner(SEMGREP).__class__ and _parse(report)
    assert findings[0].file == "app.py"
    assert findings[0].lines == [10, 12]
    assert findings[0].severity == "high"
    assert findings[0].category == "sast"


def _parse(report):
    from agentpoi_scan.scan.external_cmd import parse_semgrep_json

    return parse_semgrep_json(report)


def test_parse_osv_json_vulnerabilities():
    from agentpoi_scan.scan.external_cmd import parse_osv_json

    report = json.dumps({
        "results": [{
            "source": {"path": "requirements.txt"},
            "packages": [{
                "package": {"name": "demo", "version": "1.2.3"},
                "vulnerabilities": [{
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "unsafe package version",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"}],
                }],
            }],
        }],
    })
    findings = parse_osv_json(report)
    assert len(findings) == 1
    assert findings[0].file == "requirements.txt"
    assert findings[0].category == "deps"
    assert findings[0].severity == "critical"
    assert "demo@1.2.3" in findings[0].detail


def test_parse_gitleaks_sarif():
    report = json.dumps(
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "gitleaks"}},
                    "results": [
                        {
                            "ruleId": "AWS API Key",
                            "message": {"text": "found AWS key"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "config/aws.py"},
                                        "region": {"startLine": 4},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    from agentpoi_scan.scan.external_cmd import parse_gitleaks_sarif

    findings = parse_gitleaks_sarif(report)
    assert findings[0].file == "config/aws.py"
    assert findings[0].lines == [4]
    assert findings[0].category == "secrets"
    assert findings[0].severity == "high"


def test_external_run_via_injected_which_and_stub_invocation(tmp_path, monkeypatch):
    """With a fake ``which`` hit, the adapter builds pinned argv and parses output."""
    from agentpoi_scan.scan import external_cmd

    captured = {}

    def fake_run(argv, capture_output, text, timeout, check):
        captured["argv"] = argv
        return _Proc(returncode=0, stdout=json.dumps({"results": []}))

    monkeypatch.setattr(external_cmd.subprocess, "run", fake_run)
    scanner = ExternalToolScanner(SEMGREP, which=lambda b: "/usr/bin/semgrep")
    ctx = ScanContext(snapshot_dir=tmp_path, repo="r", commit_sha="s", file_index=[])
    result = scanner.run(ctx)
    assert not result.skipped
    assert result.findings == []
    assert captured["argv"][0] == SEMGREP.binary
    assert str(tmp_path) in " ".join(str(a) for a in captured["argv"])


class _Proc:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def test_osv_external_scanner_parses_json(tmp_path, monkeypatch):
    from agentpoi_scan.scan import external_cmd

    output = json.dumps({"results": [{"source": {"path": "package-lock.json"}, "packages": [{"package": {"name": "demo", "version": "0.1.0"}, "vulnerabilities": [{"id": "OSV-1"}]}]}]})
    monkeypatch.setattr(
        external_cmd.subprocess,
        "run",
        lambda *a, **k: _Proc(returncode=0, stdout=output),
    )
    scanner = ExternalToolScanner(external_cmd.OSV, which=lambda _binary: "/usr/bin/osv-scanner")
    ctx = ScanContext(snapshot_dir=tmp_path, repo="r", commit_sha="sha", file_index=[])
    result = scanner.run(ctx)
    assert not result.skipped
    assert len(result.findings) == 1
    assert result.findings[0].commit_sha == "sha"


def test_gitleaks_exit_1_with_secrets_is_success(tmp_path, monkeypatch):
    from agentpoi_scan.scan import external_cmd

    monkeypatch.setattr(
        external_cmd.subprocess,
        "run",
        lambda *a, **k: _Proc(returncode=1, stdout=json.dumps({"runs": []})),
    )
    scanner = ExternalToolScanner(GITLEAKS, which=lambda b: "/usr/bin/gitleaks")
    ctx = ScanContext(snapshot_dir=tmp_path, repo="r", commit_sha="s", file_index=[])
    assert not scanner.run(ctx).skipped
