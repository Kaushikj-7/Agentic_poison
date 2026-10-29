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
