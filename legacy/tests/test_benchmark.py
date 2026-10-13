"""Unit tests for BenchmarkRunner and ParetoSweeper."""

from agent_poi.evaluation.dataset import PairedDataset
from agent_poi.evaluation.benchmark_runner import BenchmarkRunner
from agent_poi.evaluation.pareto_sweeper import ParetoSweeper


def test_paired_dataset_consistency():
    pairs = PairedDataset.get_all_pairs()
    assert len(pairs) >= 5
    for p in pairs:
        assert p.pair_id
        assert p.clean_text != p.poison_text
        assert p.target_tool in ["transfer_funds", "delete_record", "send_email"]


def test_benchmark_runner_ablation():
    runner = BenchmarkRunner()
    results = runner.run_full_ablation()
    assert len(results) == 4

    # Baseline should have 100% ASR-write
    assert results[0].asr_write == 100.0

    # CTP should achieve significantly lower ASR than baseline
    ctp_res = results[2]
    assert ctp_res.asr_write < results[0].asr_write


def test_pareto_sweeper():
    sweeper = ParetoSweeper()
    sweep_data = sweeper.sweep_thresholds(tau_range=[0.3, 0.5, 0.7])
    assert "optimal_tau" in sweep_data
    assert len(sweep_data["records"]) == 3
