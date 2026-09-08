"""Evaluation suite: paired ground-truth dataset, benchmark runner, and Pareto sweeper."""

from agent_poi.evaluation.dataset import PairedDataset, BenchmarkPair
from agent_poi.evaluation.benchmark_runner import BenchmarkRunner
from agent_poi.evaluation.pareto_sweeper import ParetoSweeper
from agent_poi.evaluation.framework_comparison import (
    FrameworkComparisonRunner,
    FrameworkBenchmarkResult,
)
from agent_poi.evaluation.advanced_experiments import AdvancedExperimentRunner
from agent_poi.evaluation.deepteam_redteam import (
    DeepTeamFinancialAdapter,
    DeepTeamRedTeamRunner,
    RedTeamVulnerabilityCategory,
    RedTeamAttackMethod,
    RedTeamBenchmarkResult,
)

__all__ = [
    "PairedDataset",
    "BenchmarkPair",
    "BenchmarkRunner",
    "ParetoSweeper",
    "FrameworkComparisonRunner",
    "FrameworkBenchmarkResult",
    "AdvancedExperimentRunner",
    "DeepTeamFinancialAdapter",
    "DeepTeamRedTeamRunner",
    "RedTeamVulnerabilityCategory",
    "RedTeamAttackMethod",
    "RedTeamBenchmarkResult",
]

