"""Tests for the Experiment Runner and Git Branch Manager."""

from unittest.mock import MagicMock, patch

from agent_poi.research.experiment_runner import (
    ExperimentResult,
    GitBranchManager,
)


class TestExperimentResult:
    def test_default_status(self):
        r = ExperimentResult(
            experiment_id="EXP-001",
            branch_name="exp/test",
            architecture_id="ARCH-001",
            architecture_name="Test",
            timestamp="2026-09-07",
        )
        assert r.status == "pending"

    def test_fields(self):
        r = ExperimentResult(
            experiment_id="EXP-001",
            branch_name="exp/test",
            architecture_id="ARCH-001",
            architecture_name="Test Arch",
            timestamp="2026-09-07",
            status="passed",
            duration_seconds=12.5,
        )
        assert r.architecture_name == "Test Arch"
        assert r.duration_seconds == 12.5


class TestGitBranchManager:
    @patch("subprocess.run")
    def test_get_current_branch(self, mock_run):
        mock_run.return_value = MagicMock(stdout="main\n", returncode=0)
        mgr = GitBranchManager("E:/agent_poi")
        assert mgr.get_current_branch() == "main"

    @patch("subprocess.run")
    def test_list_experiment_branches(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="  exp/arch_001-20260907\n  exp/arch_002-20260907\n",
            returncode=0,
        )
        mgr = GitBranchManager("E:/agent_poi")
        branches = mgr.list_experiment_branches()
        assert len(branches) == 2
