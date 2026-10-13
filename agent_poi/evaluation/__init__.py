"""Evaluation suite: paired ground-truth dataset, benchmark runner, and Pareto sweeper."""

from agent_poi.evaluation.benchmark_runner import BenchmarkRunner
from agent_poi.evaluation.dataset import BenchmarkPair, PairedDataset
from agent_poi.evaluation.framework_comparison import (
    FrameworkBenchmarkResult,
    FrameworkComparisonRunner,
)
from agent_poi.evaluation.pareto_sweeper import ParetoSweeper

__all__ = [
    "PairedDataset",
    "BenchmarkPair",
    "BenchmarkRunner",
    "ParetoSweeper",
    "FrameworkComparisonRunner",
    "FrameworkBenchmarkResult",
]

