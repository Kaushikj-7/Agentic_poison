"""Tests for the dynamic SDE benchmark and the generated attack suite.

These tests assert *behaviour derived from execution*, never hardcoded outcomes: the
benchmark must demonstrate that the fail-closed policy blocks attacks that the genuinely
undefended baseline lets through.
"""

from agentpoi_sde.domain import MutationOp
from agentpoi_sde.eval.attack_generator import ATTACK_FAMILIES, generate_attacks
from agentpoi_sde.eval.benchmark import SDEBenchmarkRunner, run_benchmark
from agentpoi_sde.eval.scenario_dataset import build_scenarios


def test_attack_suite_covers_every_family_and_is_unique_per_seed():
    attacks = generate_attacks(seed=0, per_family=2)
    families = {attack.family for attack in attacks}
    assert families == set(ATTACK_FAMILIES)
    labels = [attack.label for attack in attacks]
    assert len(labels) == len(set(labels))

    other = generate_attacks(seed=7, per_family=2)
    assert [a.context_text for a in attacks] != [a.context_text for a in other]


def test_scenarios_are_paired_clean_and_adversarial():
    scenarios = build_scenarios(seed=0, per_family=1, clean_per_family=1)
    assert any(s.is_adversarial for s in scenarios)
    assert any(not s.is_adversarial for s in scenarios)
    for scenario in scenarios:
        assert scenario.mutation.path


def test_state_diff_oracle_is_defence_independent():
    scenario = build_scenarios(seed=0, per_family=1, clean_per_family=0)[0]
    empty = {}
    assert scenario.landed(empty) is False
    applied = {scenario.mutation.path: scenario.mutation.new_content}
    assert scenario.landed(applied) is True
    if scenario.mutation.op != MutationOp.DELETE:
        applied[scenario.mutation.path] = "something else"
        assert scenario.landed(applied) is False


def test_baseline_is_genuinely_undefended():
    report = run_benchmark(seed=0, per_family=1, clean_per_family=1)
    assert report.baseline.emar == 100.0, "the baseline must let every attack land"
    assert report.baseline.ltsr == 100.0
    assert report.baseline.cdr == 0.0


def test_fail_closed_policy_blocks_attacks_and_preserves_utility():
    report = run_benchmark(seed=0, per_family=2, clean_per_family=2)
    assert report.defended.emar == 0.0, "no adversarial mutation may land"
    assert report.defended.ltsr == 100.0, "legitimate work must not be disrupted"
    assert report.defended.cdr == 0.0
    assert report.defended.avr == 0.0
    assert report.defended.slr == 0.0


def test_metrics_are_computed_and_distinguish_the_two_policies():
    report = SDEBenchmarkRunner(seed=0, per_family=2, clean_per_family=2).run()
    # The undefended baseline genuinely allows architecture/secret violations to land.
    assert report.baseline.avr > report.defended.avr
    assert report.baseline.slr > report.defended.slr
    assert report.defended.adversarial_total == report.baseline.adversarial_total
    assert report.defended.clean_total == report.baseline.clean_total
    assert report.defended.mean_latency_ms >= 0.0
    assert "AgentPOI-SDE" in report.to_markdown()
