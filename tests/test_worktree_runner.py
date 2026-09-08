"""TDD Unit Tests for Git Worktree Benchmark Orchestrator.

Verifies:
1. GitWorktreeManager creates isolated worktrees safely in .worktrees/.
2. Worktrees are cleanly removed and pruned without disk or lock leaks.
3. Space and time efficiency invariants (cleanup guaranteed in finally blocks).
4. WorktreeBenchmarkOrchestrator runs DeepTeam red team benchmarks across isolated worktrees.
5. Consolidated comparative report generation across worktrees.
"""

import os
import shutil
import pytest
from agent_poi.research.worktree_runner import (
    GitWorktreeManager,
    WorktreeBenchmarkOrchestrator,
)
from agent_poi.evaluation.deepteam_redteam import RedTeamBenchmarkResult


class TestGitWorktreeManager:
    """Tests low-level git worktree lifecycle operations."""

    @pytest.fixture
    def manager(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return GitWorktreeManager(workspace_root=root)

    def test_list_initial_worktrees(self, manager):
        wts = manager.list_worktrees()
        assert len(wts) >= 1
        # Root worktree should exist
        paths = [w["path"].replace("\\", "/").lower() for w in wts]
        assert any("agent_poi" in p for p in paths)

    def test_worktree_create_and_remove(self, manager):
        wt_path, branch = manager.create_worktree("unit-test")
        try:
            assert os.path.isdir(wt_path)
            assert os.path.exists(os.path.join(wt_path, "pyproject.toml"))
            # Must be listed in git worktrees
            current_wts = [w["path"] for w in manager.list_worktrees()]
            assert any(os.path.samefile(w, wt_path) for w in current_wts if os.path.exists(w))
        finally:
            success = manager.remove_worktree(wt_path, branch_to_delete=branch)
            assert success
            assert not os.path.isdir(wt_path)


class TestWorktreeBenchmarkOrchestrator:
    """Tests high-level red-team benchmarking isolated across worktrees."""

    @pytest.fixture
    def orchestrator(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return WorktreeBenchmarkOrchestrator(
            workspace_root=root,
            max_iterations_per_category=2,  # Strictly limited iterations
            cleanup=True,
        )

    def test_run_defended_in_worktree(self, orchestrator):
        result = orchestrator.run_isolated_worktree_benchmark(
            target_name="defended-test",
            is_baseline=False,
        )
        assert isinstance(result, RedTeamBenchmarkResult)
        assert result.asr_exec == 0.0
        assert result.vrr == 100.0
        assert result.avg_latency_ms < 50.0  # Time efficient

    def test_run_baseline_in_worktree(self, orchestrator):
        result = orchestrator.run_isolated_worktree_benchmark(
            target_name="baseline-test",
            is_baseline=True,
        )
        assert isinstance(result, RedTeamBenchmarkResult)
        assert result.asr_exec > 50.0
        assert result.vrr < 50.0

    def test_run_comparative_worktree_suite(self, orchestrator):
        summary = orchestrator.run_comparative_worktree_suite()
        assert "baseline" in summary
        assert "defended" in summary
        assert "markdown_report" in summary
        assert summary["defended"].asr_exec == 0.0
        assert summary["baseline"].asr_exec > 50.0
        assert "DeepTeam LLM Red Team Worktree Benchmark" in summary["markdown_report"]
