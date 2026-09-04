"""Unit tests for the architectural ablation study runner."""

import pytest
from agent_poi.evaluation.framework_comparison import FrameworkComparisonRunner
from agent_poi.financial.eval.financial_dataset import FinancialBenchmarkDataset


def test_ablation_study_execution():
    """Verify architectural ablation runs across all 5 defense configurations."""
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:4]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:4]
    subset = adv_sample + clean_sample

    runner = FrameworkComparisonRunner(scenarios=subset)
    ablations = runner.run_ablation_study()

    assert "1_baseline" in ablations
    assert "2_task_shield_only" in ablations
    assert "3_authgraph_only" in ablations
    assert "4_civ_only" in ablations
    assert "5_full_agent_poi" in ablations

    # Full AgentPOI must dominate all individual ablation stages
    full = ablations["5_full_agent_poi"]
    assert full.asr_exec == 0.0
    assert full.ldsr == 100.0
    assert full.cdr == 0.0


def test_ablation_latex_table_generation():
    """Verify generation of academic LaTeX ablation table for arXiv manuscript."""
    adv_sample = FinancialBenchmarkDataset.get_adversarial_scenarios()[:2]
    clean_sample = FinancialBenchmarkDataset.get_clean_scenarios()[:2]
    runner = FrameworkComparisonRunner(scenarios=adv_sample + clean_sample)
    ablations = runner.run_ablation_study()

    latex_table = runner.generate_ablation_latex_table(ablations)
    assert "\\begin{table}" in latex_table or "\\begin{table*}" in latex_table
    assert "Ablation Configuration" in latex_table or "Defense Component" in latex_table
    assert "Task Shield" in latex_table
    assert "AuthGraph" in latex_table
    assert "CIV" in latex_table
