"""Tests for AgentPOI-SDE public CLI tooling and packaging."""

import json

import pytest

from agentpoi_sde.anchor.repo_anchor import RepositoryStateAnchor
from agentpoi_sde.cli import main
from agentpoi_sde.eval.benchmark import BenchmarkReport, ScenarioOutcome, SDEMetrics


def test_cli_version(capsys):
    """Verify that --version exits 0 and prints version string."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "agentpoi-sde 0.1.0" in captured.out or "agentpoi-sde" in captured.out


def test_cli_help(capsys):
    """Verify that --help exits 0 and displays subcommand options."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "anchor" in captured.out
    assert "check-diff" in captured.out
    assert "benchmark" in captured.out


def test_repo_anchor_from_directory(tmp_path):
    """Verify RepositoryStateAnchor.from_directory scans directory ignoring excluded dirs."""
    proj = tmp_path / "project"
    proj.mkdir()
    (proj / "src").mkdir()
    (proj / ".git").mkdir()
    (proj / ".venv").mkdir()

    (proj / "src" / "app.py").write_text("import os\n", encoding="utf-8")
    (proj / ".git" / "config").write_text("dummy", encoding="utf-8")
    (proj / ".venv" / "pip.exe").write_text("bin", encoding="utf-8")

    anchor = RepositoryStateAnchor.from_directory(str(proj))
    assert "src/app.py" in anchor.files
    assert ".git/config" not in anchor.files
    assert ".venv/pip.exe" not in anchor.files
    assert anchor.tree_oid() != ""


def test_cli_anchor_human_output(tmp_path, capsys):
    """Verify CLI anchor command outputs human readable summary."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "main.py").write_text("print('hello')\n", encoding="utf-8")

    exit_code = main(["anchor", str(proj)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Root Tree OID" in captured.out
    assert "Indexed Files" in captured.out


def test_cli_anchor_json_output(tmp_path, capsys):
    """Verify CLI anchor command outputs valid JSON metadata with --json flag."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "main.py").write_text("print('hello')\n", encoding="utf-8")

    exit_code = main(["anchor", str(proj), "--json", "--manifest"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "tree_oid" in data
    assert data["files_count"] == 1
    assert "manifest" in data
    assert "main.py" in data["manifest"]


def test_cli_anchor_nonexistent(capsys):
    """Verify CLI anchor command exits with code 2 on nonexistent path."""
    exit_code = main(["anchor", "nonexistent_directory_xyz_123"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "does not exist" in captured.err.lower() or "error" in captured.err.lower()


def test_cli_check_diff_approved(tmp_path, capsys):
    """Verify check-diff passes clean diff with exit code 0."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    patch_file = tmp_path / "clean.patch"
    patch_file.write_text(
        """--- a/calc.py
+++ b/calc.py
@@ -1,2 +1,3 @@
 def add(a, b):
+    # comment
     return a + b
""",
        encoding="utf-8",
    )

    exit_code = main(["check-diff", str(patch_file), "--repo", str(proj)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "APPROVED" in captured.out


def test_cli_check_diff_blocked_policy_tampering(tmp_path, capsys):
    """Verify check-diff blocks policy file mutation fail-closed with exit code 1."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / ".github").mkdir()
    (proj / ".github" / "workflows").mkdir()
    (proj / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")

    patch_file = tmp_path / "tamper.patch"
    patch_file.write_text(
        """--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1,2 @@
 name: CI
+# backdoor
""",
        encoding="utf-8",
    )

    exit_code = main(["check-diff", str(patch_file), "--repo", str(proj)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "BLOCKED" in captured.out
    assert "I1" in captured.out or "policy" in captured.out.lower()


def test_cli_check_diff_blocked_secret_leak(tmp_path, capsys):
    """Verify check-diff blocks secret introduction with exit code 1."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "config.py").write_text("DEBUG = False\n", encoding="utf-8")

    patch_file = tmp_path / "secret.patch"
    patch_file.write_text(
        """--- a/config.py
+++ b/config.py
@@ -1 +1,2 @@
 DEBUG = False
+AWS_SECRET_ACCESS_KEY = "AKIA1234567890123456"
""",
        encoding="utf-8",
    )

    exit_code = main(["check-diff", str(patch_file), "--repo", str(proj)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "BLOCKED" in captured.out
    assert "I3" in captured.out or "secret" in captured.out.lower()


def test_cli_check_diff_malformed_fail_closed(tmp_path, capsys):
    """Verify check-diff fails closed with exit code 2 on malformed diff."""
    patch_file = tmp_path / "corrupt.patch"
    patch_file.write_text("--- invalid header @@ corrupted", encoding="utf-8")

    exit_code = main(["check-diff", str(patch_file)])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "error" in captured.err.lower() or "malformed" in captured.err.lower()


def test_cli_check_diff_json(tmp_path, capsys):
    """Verify check-diff --json outputs valid JSON verdict."""
    proj = tmp_path / "repo"
    proj.mkdir()
    (proj / "hello.py").write_text("x = 1\n", encoding="utf-8")

    patch_file = tmp_path / "clean.patch"
    patch_file.write_text(
        """--- a/hello.py
+++ b/hello.py
@@ -1 +1,2 @@
 x = 1
+y = 2
""",
        encoding="utf-8",
    )

    exit_code = main(["check-diff", str(patch_file), "--repo", str(proj), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["verdict"] == "APPROVED"
    assert "mutations" in data


def test_benchmark_report_to_dict_and_to_json():
    """Verify BenchmarkReport.to_dict and to_json methods."""
    metrics_base = SDEMetrics(
        emar=100.0,
        ltsr=100.0,
        cdr=0.0,
        avr=0.0,
        slr=0.0,
        adversarial_total=2,
        adversarial_landed=2,
        clean_total=2,
        clean_landed=2,
        mean_latency_ms=1.5,
    )
    metrics_def = SDEMetrics(
        emar=0.0,
        ltsr=100.0,
        cdr=0.0,
        avr=0.0,
        slr=0.0,
        adversarial_total=2,
        adversarial_landed=0,
        clean_total=2,
        clean_landed=2,
        mean_latency_ms=2.5,
    )
    outcome = ScenarioOutcome(
        scenario_id="sc-01",
        family="test",
        is_adversarial=True,
        landed=False,
        status="BLOCKED",
        violation_codes=["I1"],
        latency_ms=2.0,
    )
    report = BenchmarkReport(
        baseline=metrics_base,
        defended=metrics_def,
        baseline_outcomes=[outcome],
        defended_outcomes=[outcome],
    )

    d = report.to_dict()
    assert d["defended"]["emar"] == 0.0
    assert d["baseline"]["emar"] == 100.0
    assert len(d["defended_outcomes"]) == 1

    js = report.to_json(indent=2)
    assert '"emar": 0.0' in js
    loaded = json.loads(js)
    assert loaded["defended"]["ltsr"] == 100.0


def test_cli_benchmark(capsys):
    """Verify CLI benchmark command execution and markdown output."""
    exit_code = main(["benchmark", "--seed", "0", "--per-family", "1", "--clean-per-family", "1"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "AgentPOI-SDE" in captured.out
    assert "EMAR" in captured.out


def test_cli_benchmark_json_and_output_file(tmp_path, capsys):
    """Verify CLI benchmark command with --format json and --output file."""
    out_file = tmp_path / "bench_report.json"
    exit_code = main([
        "benchmark",
        "--seed", "0",
        "--per-family", "1",
        "--clean-per-family", "1",
        "--format", "json",
        "-o", str(out_file),
    ])
    assert exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    data = json.loads(content)
    assert "defended" in data
    assert data["defended"]["emar"] == 0.0
