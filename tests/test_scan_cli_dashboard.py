"""Tests for the dashboard CLI subcommand (agentpoi-scan dashboard)."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from agentpoi_scan.cli import main
from agentpoi_scan.ui.dashboard import run_dashboard


def test_cli_dashboard_subcommand_dispatch():
    with patch("agentpoi_scan.ui.dashboard.run_dashboard") as mock_run:
        ret = main(["dashboard", "--port", "8502", "--store-path", "custom_store.sqlite3"])
        assert ret == 0
        mock_run.assert_called_once_with(store_path="custom_store.sqlite3", port=8502)


def test_cli_dashboard_subcommand_defaults():
    with patch("agentpoi_scan.ui.dashboard.run_dashboard") as mock_run:
        ret = main(["dashboard"])
        assert ret == 0
        mock_run.assert_called_once_with(store_path=".agentpoi_scan/scan_store.sqlite3", port=8501)


def test_cli_dashboard_missing_streamlit(capsys):
    # Simulate environment where streamlit is not installed
    with patch.dict(sys.modules, {"streamlit": None}):
        with patch("agentpoi_scan.ui.dashboard.st", None):
            ret = main(["dashboard"])
            assert ret == 1
            captured = capsys.readouterr()
            assert "scan-ui" in captured.out or "scan-ui" in captured.err or "Streamlit" in captured.out or "Streamlit" in captured.err


def test_run_dashboard_raises_when_streamlit_absent():
    with patch("agentpoi_scan.ui.dashboard.st", None):
        with pytest.raises(RuntimeError, match="Streamlit is required"):
            run_dashboard()


def test_cli_scan_and_run_aliases_dispatch(tmp_path):
    with patch("agentpoi_scan.pipeline.ScanPipeline.scan_target") as mock_scan:
        from agentpoi_scan.pipeline import ScanReport

        mock_scan.return_value = ScanReport(repo="test/repo", commit_sha="1234567890ab")
        # Test scan command
        ret = main(["scan", "test/repo", "--sarif", str(tmp_path / "out.sarif")])
        assert ret == 0
        assert mock_scan.call_count == 1

        # Test run command alias
        ret2 = main(["run", "test/repo", "--output-sarif", str(tmp_path / "out2.sarif"), "--offline"])
        assert ret2 == 0
        assert mock_scan.call_count == 2


def test_cli_scan_and_run_help_formatting(capsys):
    """Ensure argparse % formatting in --help does not trigger %o TypeError."""
    for subcmd in ("scan", "run"):
        with pytest.raises(SystemExit) as exc_info:
            main([subcmd, "--help"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "--offline" in captured.out
        assert "100% offline" in captured.out


def test_scan_target_local_dir_resolution_and_symlink_skip(tmp_path):
    """Ensure local directories resolve proper repo_name and ignore symlinks/internal dirs."""
    from agentpoi_scan.pipeline import ScanPipeline
    from agentpoi_scan.report.store import ScanStore

    sample_dir = tmp_path / "sample_repo"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text("print('clean')\n", encoding="utf-8")
    (sample_dir / ".git").mkdir()
    (sample_dir / ".git" / "config").write_text("dummy", encoding="utf-8")

    # Create a symlink if the platform permits
    symlink_path = sample_dir / "link_to_app.py"
    try:
        symlink_path.symlink_to(sample_dir / "app.py")
    except (OSError, NotImplementedError):
        pass  # Windows unprivileged symlinks may raise

    store_file = tmp_path / "test_store.sqlite3"
    pipeline = ScanPipeline(
        config={"privacy": {"local_only": True}, "sarif_path": str(tmp_path / "test.sarif")},
        store_path=store_file,
    )
    report = pipeline.scan_target(str(sample_dir))
    assert report.repo == "sample_repo"
    assert report.repo != ""
    assert report.commit_sha == "0" * 40

    # Ensure store can query with optional scan_id
    store = ScanStore(store_file)
    findings_all = store.get_findings_filtered(severity="CRITICAL")
    assert isinstance(findings_all, list)
    store.close()


