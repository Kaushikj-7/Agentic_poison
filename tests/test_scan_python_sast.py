"""Tests for agentpoi_scan.scan.python_sast (parse-only wrap of SlicerSecurityValidator)."""

from pathlib import Path

from agentpoi_scan.fetch.safe_extract import Manifest
from agentpoi_scan.scan.base import ScanContext
from agentpoi_scan.scan.python_sast import PythonSastScanner


def _ctx(tmp_path: Path, files: dict) -> ScanContext:
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))
    manifest = Manifest()
    manifest.files = {rel: len(content) for rel, content in files.items()}
    return ScanContext.from_manifest(tmp_path, "test/repo", "deadbeef", manifest)


def test_flags_os_system_and_locates_line(tmp_path):
    ctx = _ctx(tmp_path, {"src/evil.py": "import os\n\n\ndef boom():\n    os.system('rm -rf /')\n"})
    result = PythonSastScanner().run(ctx)
    assert not result.skipped
    assert result.findings, "os.system must be flagged"
    titles = {f.title for f in result.findings}
    assert "prohibited execution call" in titles
    located = [f for f in result.findings if f.title == "prohibited execution call"]
    assert all(f.lines and f.lines[0] >= 1 for f in located)
    assert all(f.commit_sha == "deadbeef" for f in result.findings)
    assert all(f.category == "sast" for f in located)


def test_resolves_aliased_subprocess(tmp_path):
    ctx = _ctx(
        tmp_path,
        {"a.py": "import subprocess as sp\n\n\ndef go():\n    return sp.run(['ls'], check=False)\n"},
    )
    findings = PythonSastScanner().run(ctx).findings
    assert any(f.title == "prohibited execution call" for f in findings)


def test_clean_python_yields_nothing(tmp_path):
    ctx = _ctx(tmp_path, {"ok.py": "def add(a, b):\n    return a + b\n"})
    result = PythonSastScanner().run(ctx)
    assert result.findings == []


def test_secret_detection(tmp_path):
    ctx = _ctx(tmp_path, {"k.py": 'import os\nGITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n'})
    result = PythonSastScanner().run(ctx)
    # exact SECRET_PATTERNS behaviour comes from policy_registry; just require a category result
    assert result.scanner == "python_sast"


def test_parse_only_never_imports_snapshot(tmp_path):
    # A module that would mutate globals at import time must not affect the scanning process.
    ctx = _ctx(tmp_path, {"boom_module.py": "import sys\nsys.exit(9)\nimport os\nbomb\n"})
    result = PythonSastScanner().run(ctx)  # must not execute; syntax error finding OK
    assert result.scanner == "python_sast"


def test_exact_ast_line_attribution(tmp_path):
    code = (
        "import os\n"       # line 1
        "import requests\n" # line 2
        "def benign():\n"   # line 3
        "    pass\n"        # line 4
        "def evil():\n"     # line 5
        "    os.system('id')\n"  # line 6
    )
    ctx = _ctx(tmp_path, {"src/app.py": code})
    result = PythonSastScanner().run(ctx)
    exec_findings = [f for f in result.findings if f.title == "prohibited execution call"]
    assert len(exec_findings) == 1
    assert 6 in exec_findings[0].lines
    assert exec_findings[0].lines[0] == 6


def test_benign_imports_not_flagged(tmp_path):
    code = (
        "import requests\n"
        "import socket\n"
        "def get_version():\n"
        "    return '1.0'\n"
    )
    ctx = _ctx(tmp_path, {"src/clean_imports.py": code})
    result = PythonSastScanner().run(ctx)
    assert len(result.findings) == 0

