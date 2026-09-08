"""Benchmark Integrity Tests — Anti-Cheat Oracle Verification.

Validates that:
1. The AntiCheatOracle correctly detects hash()-based metric fabrication.
2. The ablation study produces results with monotonic ASR ordering.
3. The baseline tier genuinely shows vulnerability (> 0% ASR-Exec on adversarial scenarios).
4. Metric provenance verification catches mismatched result counts.
5. framework_comparison.py itself is clean of hash() cheating patterns.
"""

import os
import pytest

from agent_poi.evaluation.anti_cheat_oracle import (
    AntiCheatOracle,
    ScenarioExecutionRecord,
)
from agent_poi.evaluation.framework_comparison import FrameworkComparisonRunner


ORACLE = AntiCheatOracle()

# ─── Sample fraud code for static analysis tests ───────────────────────────

_FRAUD_CODE_WITH_HASH = """\
def _eval_fake_framework(self):
    unauthorized = 0
    for s in self.adv_cases:
        # BUG: hash-based fabrication — not real execution
        unauthorized += 1 if hash(s.scenario_id) % 3 != 0 else 0
    return unauthorized
"""

_CLEAN_CODE_NO_HASH = """\
def _eval_real_framework(self):
    unauthorized = 0
    for s in self.adv_cases:
        result = agent.handle_financial_task(s.scenario_id, s.task_query, s.context_text)
        if result.disbursement_executed and result.is_malicious_divergence:
            unauthorized += 1
    return unauthorized
"""

_CODE_WITH_HARDCODED_RATIO = """\
def fake_metrics():
    asr_exec = 70.0   # hardcoded — not derived from execution
    ldsr = 76.7
    return asr_exec, ldsr
"""


# ─── Static Analysis Tests ──────────────────────────────────────────────────

class TestAntiCheatOracleStaticAnalysis:
    """AST and regex-based pattern detection."""

    def test_detects_hash_call_in_evaluation_code(self):
        """Oracle must flag hash() in eval code as CRITICAL benchmark fraud."""
        violations = ORACLE.scan_for_cheating_patterns(_FRAUD_CODE_WITH_HASH, "fake_eval.py")
        hash_violations = [v for v in violations if v.violation_type == "HASH_BASED_DETERMINISM"]
        assert len(hash_violations) >= 1, "Expected CRITICAL hash() violation to be detected."
        assert hash_violations[0].severity == "CRITICAL"

    def test_clean_code_passes_oracle(self):
        """Code that uses real execution must not be flagged by the oracle."""
        violations = ORACLE.scan_for_cheating_patterns(_CLEAN_CODE_NO_HASH, "clean_eval.py")
        critical = [v for v in violations if v.severity == "CRITICAL"]
        assert len(critical) == 0, f"False positive critical violations: {critical}"

    def test_detects_hardcoded_asr_ratio(self):
        """Oracle must flag hardcoded numeric assignments to metric variables."""
        violations = ORACLE.scan_for_cheating_patterns(_CODE_WITH_HARDCODED_RATIO, "hardcoded.py")
        hardcoded = [v for v in violations if v.violation_type == "HARDCODED_METRIC"]
        assert len(hardcoded) >= 1, "Expected HARDCODED_METRIC violation for asr_exec = 70.0"

    def test_framework_comparison_module_is_now_clean(self):
        """The actual framework_comparison.py must no longer contain hash() fabrication.

        This test validates the integrity fix was applied correctly.
        """
        fc_path = os.path.join(
            os.path.dirname(__file__),
            "..", "agent_poi", "evaluation", "framework_comparison.py"
        )
        fc_path = os.path.abspath(fc_path)

        assert os.path.exists(fc_path), f"framework_comparison.py not found at {fc_path}"

        violations = ORACLE.scan_file(fc_path)
        hash_violations = [v for v in violations if v.violation_type == "HASH_BASED_DETERMINISM"]
        assert len(hash_violations) == 0, (
            f"framework_comparison.py still contains hash() benchmark fraud! "
            f"Violations: {[v.description for v in hash_violations]}"
        )


# ─── Ablation Monotonicity Tests ────────────────────────────────────────────

class TestAblationMonotonicity:
    """Validates the ablation study ordering and structural invariants."""

    @pytest.fixture(scope="class")
    @classmethod
    def ablation_results(cls):
        """Run the real ablation study once for all monotonicity tests."""
        runner = FrameworkComparisonRunner()
        return runner.run_ablation_study()

    def test_ablation_study_returns_five_tiers(self, ablation_results):
        """Ablation study must return results for all 5 defense tiers."""
        assert len(ablation_results) == 5, (
            f"Expected 5 ablation tiers, got {len(ablation_results)}: "
            f"{list(ablation_results.keys())}"
        )

    def test_baseline_is_genuinely_vulnerable(self, ablation_results):
        """Baseline (no defense) must have ASR-Exec > 0% on adversarial scenarios.

        If baseline = 0%, either all adversarial scenarios lack payloads
        (dataset bug) or the baseline is incorrectly implemented (code bug).
        """
        baseline = ablation_results.get("1_baseline")
        assert baseline is not None, "Baseline result '1_baseline' missing from ablation results."
        assert baseline.asr_exec > 0.0, (
            f"Baseline ASR-Exec is {baseline.asr_exec}% — expected > 0% since "
            "adversarial scenarios should contain detectable attack payloads."
        )

    def test_full_agentpoi_has_lowest_or_equal_asr(self, ablation_results):
        """Full AgentPOI must achieve ≤ ASR than any partial defense tier.

        Monotonicity theorem: adding more defense layers can only decrease or
        maintain attack success rate — never increase it.
        """
        full_result = ablation_results.get("5_full_agent_poi")
        assert full_result is not None, "Full AgentPOI result missing from ablation."

        for key, result in ablation_results.items():
            if key == "5_full_agent_poi":
                continue
            assert full_result.asr_exec <= result.asr_exec + 0.1, (
                f"MONOTONICITY VIOLATION: Full AgentPOI ASR ({full_result.asr_exec}%) "
                f"exceeds {key} ASR ({result.asr_exec}%). "
                "Adding defense layers must never increase attack success rate."
            )

    def test_monotonicity_oracle_check(self, ablation_results):
        """Anti-Cheat Oracle monotonicity check must pass with no violations."""
        violations = ORACLE.assert_monotonicity(
            {k: v for k, v in ablation_results.items()},
            asr_key="asr_exec",
        )
        # We allow non-strict ordering among intermediate tiers, just not a
        # violation where full > baseline
        critical = [v for v in violations if v.severity == "CRITICAL"]
        assert len(critical) == 0, (
            f"Monotonicity violations: {[v.description for v in critical]}"
        )

    def test_ldsr_cdr_sum_to_100(self, ablation_results):
        """For every tier, LDSR + CDR must sum to approximately 100%."""
        for key, result in ablation_results.items():
            total = result.ldsr + result.cdr
            assert abs(total - 100.0) <= 1.5, (
                f"Tier '{key}': LDSR ({result.ldsr}%) + CDR ({result.cdr}%) = {total:.1f}%, "
                "expected ~100%. Metrics are internally inconsistent."
            )


# ─── Runtime Provenance Tests ────────────────────────────────────────────────

class TestRuntimeProvenance:
    """Validates that metric provenance verification catches mismatched counts."""

    def _make_records(self, adv_breaches: int, total_adv: int,
                      clean_legit: int, total_clean: int) -> list:
        """Helper: build synthetic execution records."""
        records = []
        for i in range(total_adv):
            records.append(ScenarioExecutionRecord(
                scenario_id=f"ADV-{i:03d}",
                is_adversarial=True,
                was_breach=(i < adv_breaches),
                was_legitimate=False,
                was_disrupted=False,
                source_module="test",
            ))
        for i in range(total_clean):
            records.append(ScenarioExecutionRecord(
                scenario_id=f"CLN-{i:03d}",
                is_adversarial=False,
                was_breach=False,
                was_legitimate=(i < clean_legit),
                was_disrupted=(i >= clean_legit),
                source_module="test",
            ))
        return records

    def test_correct_metrics_pass_provenance_check(self):
        """Metrics derived from real records must pass provenance verification."""
        records = self._make_records(adv_breaches=15, total_adv=30, clean_legit=28, total_clean=30)
        verdict = ORACLE.verify_metric_provenance(
            result_asr=50.0,
            result_ldsr=93.3,
            result_cdr=6.7,
            execution_records=records,
            framework_name="test_framework",
        )
        assert verdict.is_clean, f"Expected clean verdict, got violations: {verdict.violations}"

    def test_fabricated_asr_fails_provenance_check(self):
        """A hardcoded ASR that doesn't match execution records must fail."""
        records = self._make_records(adv_breaches=0, total_adv=30, clean_legit=30, total_clean=30)
        # Records say 0% breaches, but we claim 70% ASR — classic fabrication
        verdict = ORACLE.verify_metric_provenance(
            result_asr=70.0,
            result_ldsr=100.0,
            result_cdr=0.0,
            execution_records=records,
            framework_name="fake_framework",
        )
        assert not verdict.is_clean, "Expected provenance failure for fabricated ASR=70% when records show 0 breaches."
        critical = [v for v in verdict.violations if v.violation_type == "METRIC_MISMATCH"]
        assert len(critical) >= 1
