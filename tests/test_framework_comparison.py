"""Unit tests for the architectural ablation benchmark runner.

NOTE: The old test_framework_comparison_run_all() and test_format_markdown_and_latex_reports()
tested run_comparison() which called hash()-based fake competitor simulations.
Those methods have been removed as benchmark fraud.

These tests now verify the honest ablation study and report formatters.
"""

import pytest
from agent_poi.evaluation.framework_comparison import (
    FrameworkComparisonRunner,
    FrameworkBenchmarkResult,
)
from agent_poi.financial.eval.financial_dataset import FinancialBenchmarkDataset


def test_framework_comparison_initialization():
    """Verify that FrameworkComparisonRunner initializes with ground-truth scenarios."""
    scenarios = (
        FinancialBenchmarkDataset.get_adversarial_scenarios()[:5]
        + FinancialBenchmarkDataset.get_clean_scenarios()[:5]
    )
    runner = FrameworkComparisonRunner(scenarios=scenarios)
    assert len(runner.scenarios) == 10
    assert len(runner.adv_cases) == 5
    assert len(runner.clean_cases) == 5


def test_ablation_study_runs_all_tiers():
    """Honest ablation study must return 5 defense tier results."""
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:4]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:4]
    runner = FrameworkComparisonRunner(scenarios=adv_sample + clean_sample)

    results = runner.run_ablation_study()

    assert "1_baseline" in results
    assert "2_task_shield_only" in results
    assert "3_authgraph_only" in results
    assert "4_civ_only" in results
    assert "5_full_agent_poi" in results

    # Full AgentPOI must have lowest or equal ASR among all tiers
    full_res = results["5_full_agent_poi"]
    assert isinstance(full_res, FrameworkBenchmarkResult)
    assert full_res.framework_name == "AgentPOI (FinancialGuard)"
    assert full_res.asr_exec == 0.0
    assert full_res.ldsr == 100.0
    assert full_res.avg_latency_ms < 50.0

    # Baseline must show vulnerability
    baseline_res = results["1_baseline"]
    assert baseline_res.asr_exec > 0.0, (
        "Baseline (no defense) must show > 0% ASR-Exec on adversarial scenarios."
    )


def test_format_markdown_and_latex_reports():
    """Verify ablation markdown and LaTeX report formatters produce valid output."""
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:2]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:2]
    runner = FrameworkComparisonRunner(scenarios=adv_sample + clean_sample)
    results = runner.run_ablation_study()

    md_report = runner.generate_markdown_report(results)
    assert "CROSS-FRAMEWORK FINANCIAL AGENT SECURITY BENCHMARK" in md_report
    assert "AgentPOI" in md_report
    assert "ASR-Exec" in md_report

    latex_table = runner.generate_ablation_latex_table(results)
    assert "\\begin{table*}" in latex_table
    assert "\\begin{tabular}" in latex_table
    assert "\\end{tabular}" in latex_table
    assert "\\end{table*}" in latex_table
    assert "AgentPOI" in latex_table
