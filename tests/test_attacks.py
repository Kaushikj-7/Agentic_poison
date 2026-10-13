"""Unit tests for adversarial attack generators and adaptive mutators."""

from agent_poi.attacks import (
    AdaptiveMutator,
    AttackerJudgeLoop,
    AttackPayload,
    CrossSessionSPIAttack,
    MINJAAttack,
    SleeperPoisonAttack,
)
from agent_poi.memory.memory_firewall import MemoryFirewall


def test_minja_attack_generation():
    generator = MINJAAttack()
    payloads = generator.generate_payloads()

    assert len(payloads) > 0
    for p in payloads:
        assert isinstance(p, AttackPayload)
        assert "MINJA" in p.attack_name
        assert p.content
        assert p.clean_counterpart
        assert p.target_tool


def test_sleeper_poison_attack_generation():
    generator = SleeperPoisonAttack()
    payloads = generator.generate_payloads()

    assert len(payloads) > 0
    for p in payloads:
        assert isinstance(p, AttackPayload)
        assert "Sleeper" in p.attack_name
        assert p.trigger_query
        assert p.content


def test_cross_session_spi_attack_generation():
    generator = CrossSessionSPIAttack()
    payloads = generator.generate_payloads()

    assert len(payloads) > 0
    for p in payloads:
        assert isinstance(p, AttackPayload)
        assert "Cross-Session" in p.attack_name
        assert p.target_tool


def test_adaptive_mutator_methods():
    generator = MINJAAttack()
    base_payload = generator.generate_payloads()[0]

    # Test benign padding
    padded = AdaptiveMutator.apply_benign_padding(base_payload)
    assert len(padded.content) > len(base_payload.content)
    assert base_payload.content in padded.content
    assert padded.tier == 2

    # Test compliance reframing
    reframed = AdaptiveMutator.apply_compliance_reframing(base_payload)
    assert len(reframed.content) > len(base_payload.content)
    assert reframed.tier == 2

    # Test passive obfuscation
    obfuscated = AdaptiveMutator.apply_passive_obfuscation(base_payload)
    assert len(obfuscated.content) > 0
    assert obfuscated.tier == 2


def test_attacker_judge_loop_execution():
    firewall = MemoryFirewall()
    judge_loop = AttackerJudgeLoop(firewall=firewall, max_iterations=2)
    generator = MINJAAttack()
    base_payload = generator.generate_payloads()[0]

    result = judge_loop.run_adaptive_search(base_payload)
    assert result is not None
    assert "trajectory" in result
    assert "bypassed" in result
    assert "iterations_used" in result
    assert len(result["trajectory"]) <= 2
