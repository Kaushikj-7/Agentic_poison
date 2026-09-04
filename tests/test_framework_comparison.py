"""Unit tests for the cross-framework benchmark comparison runner."""

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



def test_framework_comparison_run_all():
    """Verify running comparison across all four framework architectures."""
    # Test on a representative subset: 4 adv + 4 clean for fast unit testing
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:4]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:4]
    subset = adv_sample + clean_sample

    runner = FrameworkComparisonRunner(scenarios=subset)
    results = runner.run_comparison()

    assert "langchain_react" in results
    assert "crewai" in results
    assert "autogpt" in results
    assert "agent_poi" in results

    poi_res = results["agent_poi"]
    assert isinstance(poi_res, FrameworkBenchmarkResult)
    assert poi_res.framework_name == "AgentPOI (FinancialGuard)"
    # AgentPOI must have 0% unauthorized disbursements
    assert poi_res.asr_exec == 0.0
    assert poi_res.ldsr == 100.0
    assert poi_res.cdr == 0.0
    assert poi_res.avg_latency_ms < 50.0  # Fast offline CPU latency

    # Baseline frameworks must exhibit security vulnerabilities on adversarial injection
    lc_res = results["langchain_react"]
    assert lc_res.asr_exec > 0.0


def test_format_markdown_and_latex_reports():
    """Verify markdown and LaTeX report generators for arXiv / documentation."""
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:2]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:2]
    runner = FrameworkComparisonRunner(scenarios=adv_sample + clean_sample)
    results = runner.run_comparison()

    md_report = runner.generate_markdown_report(results)
    assert "CROSS-FRAMEWORK FINANCIAL AGENT SECURITY BENCHMARK" in md_report
    assert "AgentPOI" in md_report
    assert "LangChain ReAct" in md_report
    assert "ASR-Exec" in md_report

    latex_table = runner.generate_latex_table(results)
    assert "\\begin{table*}" in latex_table
    assert "\\begin{tabular}" in latex_table
    assert "\\end{tabular}" in latex_table
    assert "\\end{table*}" in latex_table
    assert "AgentPOI" in latex_table

