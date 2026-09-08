"""TDD Unit Tests for Advanced Experiment Runner.

Tests all advanced empirical experiment runners:
1. Attack family breakdown across 6 categories.
2. Operational enterprise accounting category breakdown.
3. 3-Way Matching PO & replay attack defense benchmark.
4. Candidate architecture comparisons (ARCH-001 through ARCH-005).
5. Scalability stress benchmarks across context length and DAG depth.
6. Anti-Cheat Oracle static AST inspection ensuring zero cheating.
"""

import os
import pytest
from agent_poi.evaluation.advanced_experiments import AdvancedExperimentRunner
from agent_poi.evaluation.anti_cheat_oracle import AntiCheatOracle


@pytest.fixture
def runner():
    return AdvancedExperimentRunner()


class TestAttackFamilyBreakdown:
    """Tests fine-grained adversarial breakdown across 6 attack families."""

    def test_attack_families_evaluated(self, runner):
        results = runner.run_attack_family_breakdown()
        assert len(results) == 6, f"Expected 6 attack families, got {len(results)}"

        expected_families = {
            "AgentDojo Banking",
            "Homoglyph Typosquat",
            "Payload Splitting",
            "Markdown Table Injection",
            "Compliance Camouflage",
            "Limit Escalation",
        }
        assert set(results.keys()) == expected_families

        for name, r in results.items():
            assert r.defended_asr == 0.0, f"Expected 0.0% ASR for {name}, got {r.defended_asr}%"
            assert r.baseline_asr > 0.0, f"Expected >0 baseline ASR for {name}"
            assert r.mitigation_rate > 0.0, f"Expected positive mitigation for {name}"

    def test_attack_families_latex_table(self, runner):
        results = runner.run_attack_family_breakdown()
        latex = runner.generate_attack_families_latex_table(results)
        assert "\\label{tab:attack_families}" in latex
        assert "\\begin{tabular}" in latex
        assert "\\end{table}" in latex
        assert "AgentDojo Banking" in latex


class TestOperationalCategoryBreakdown:
    """Tests clean operational utility across 6 transaction categories."""

    def test_operational_categories_evaluated(self, runner):
        results = runner.run_operational_category_breakdown()
        assert len(results) == 6, f"Expected 6 categories, got {len(results)}"

        expected_cats = {
            "Standard Recurring",
            "Urgent Legitimate",
            "Credit Memo Adjustment",
            "Itemized PO Table",
            "Milestone Disbursement",
            "Facility Maintenance",
        }
        assert set(results.keys()) == expected_cats

        for name, r in results.items():
            assert r.ldsr == 100.0, f"Expected 100% LDSR for {name}, got {r.ldsr}%"
            assert r.cdr == 0.0, f"Expected 0% CDR for {name}, got {r.cdr}%"
            assert r.disrupted_count == 0

    def test_operational_categories_latex_table(self, runner):
        results = runner.run_operational_category_breakdown()
        latex = runner.generate_operational_categories_latex_table(results)
        assert "\\label{tab:operational_categories}" in latex
        assert "Standard Recurring" in latex
        assert "100.0\\%" in latex


class TestThreeWayMatchingAndReplay:
    """Tests 3-Way Matching and Idempotency Replay defenses."""

    def test_three_way_matching_and_replay_detection(self, runner):
        res = runner.run_three_way_matching_and_replay_benchmark()
        assert res["total_cases"] == 9
        assert res["accuracy_pct"] == 100.0
        assert res["correct_decisions"] == 9

    def test_three_way_replay_latex_table(self, runner):
        res = runner.run_three_way_matching_and_replay_benchmark()
        latex = runner.generate_three_way_replay_latex_table(res)
        assert "\\label{tab:three_way_replay}" in latex
        assert "Valid 3-Way Match (Control)" in latex
        assert "\\checkmark~Pass" in latex


class TestCandidateArchitectureComparison:
    """Tests candidate architectures empirical evaluation."""

    def test_candidate_architectures_evaluated(self, runner):
        res = runner.run_candidate_architecture_comparison()
        assert len(res) == 5
        assert "ARCH-001" in res
        assert "ARCH-005" in res

        for aid, data in res.items():
            assert data["asr_exec"] == 0.0
            assert data["ldsr"] == 100.0
            assert data["cdr"] == 0.0
            assert data["avg_latency_ms"] > 0.0

    def test_candidate_architectures_latex_table(self, runner):
        res = runner.run_candidate_architecture_comparison()
        latex = runner.generate_candidate_architectures_latex_table(res)
        assert "\\label{tab:candidate_architectures}" in latex
        assert "ARCH-001" in latex
        assert "Fides IFC Minimal" in latex


class TestScalabilityStressBenchmark:
    """Tests CPU runtime scaling across context length and DAG depth."""

    def test_scalability_stress_records(self, runner):
        records = runner.run_scalability_stress_benchmark()
        assert len(records) == 11  # 6 context lengths + 5 DAG depths

        for r in records:
            assert r.avg_latency_ms < 150.0, f"Overhead {r.avg_latency_ms}ms exceeded 150ms for {r.dimension}"
            assert r.throughput_rps > 0.0

    def test_scalability_latex_table(self, runner):
        records = runner.run_scalability_stress_benchmark()
        latex = runner.generate_scalability_latex_table(records)
        assert "\\label{tab:scalability_stress}" in latex
        assert "Context Length" in latex
        assert "DAG Ancestor Depth" in latex


class TestAntiCheatIntegrity:
    """Verifies that advanced_experiments.py is strictly compliant with AntiCheatOracle."""

    def test_no_cheat_patterns_in_code(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        target_file = os.path.join(root, "agent_poi", "evaluation", "advanced_experiments.py")
        oracle = AntiCheatOracle()
        violations = oracle.scan_file(target_file)
        critical_violations = [v for v in violations if v.severity == "CRITICAL"]
        assert len(critical_violations) == 0, f"AntiCheatOracle flagged violations: {critical_violations}"
