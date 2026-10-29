"""Tests for all-tier non-frontier/free model providers and rate limits."""

from pathlib import Path

import yaml

from agentpoi_scan.agents.llm_bridge import (
    RateLimitedProvider,
    build_default_providers,
)


def _load_scanner_config() -> dict:
    cfg_path = Path(__file__).resolve().parents[1] / "agentpoi_scan" / "config" / "scanner_config.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8"))


def test_all_tiers_instantiate_from_openrouter_config(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-mock-key")
    cfg = _load_scanner_config()

    providers, unavailable = build_default_providers(cfg)

    # All three tiers should be available when key is set
    assert "local" in providers.providers
    assert "frontier" in providers.providers
    assert "verifier" in providers.providers
    assert unavailable == {}

    # Check models configured for each tier
    local_p = providers.providers["local"]
    frontier_p = providers.providers["frontier"]
    verifier_p = providers.providers["verifier"]

    assert isinstance(local_p, RateLimitedProvider)
    assert isinstance(frontier_p, RateLimitedProvider)
    assert isinstance(verifier_p, RateLimitedProvider)

    assert local_p.provider.model == "nvidia/nemotron-3.5-lightning:free"
    assert frontier_p.provider.model == "google/gemma-4-31b-it:free"
    assert verifier_p.provider.model == "qwen/qwen-2.5-coder-32b-instruct:free"


def test_all_tiers_have_independent_rate_limit_accounting(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-mock-key")
    cfg = _load_scanner_config()
    providers, _ = build_default_providers(cfg)

    local_p = providers.providers["local"]
    frontier_p = providers.providers["frontier"]
    verifier_p = providers.providers["verifier"]

    # Each tier must have distinct instance references and counters
    assert local_p is not frontier_p
    assert frontier_p is not verifier_p
    assert local_p is not verifier_p

    # Simulate usage on local tier
    local_p._total += 5
    assert local_p._total == 5
    assert frontier_p._total == 0
    assert verifier_p._total == 0


def test_missing_openrouter_api_key_fails_closed_across_all_tiers(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    cfg = _load_scanner_config()

    providers, unavailable = build_default_providers(cfg)

    assert "local" not in providers.providers
    assert "frontier" not in providers.providers
    assert "verifier" not in providers.providers

    assert unavailable.get("local") == "OPENROUTER_API_KEY not set"
    assert unavailable.get("frontier") == "OPENROUTER_API_KEY not set"
    assert unavailable.get("verifier") == "OPENROUTER_API_KEY not set"


def test_total_per_scan_cap_across_tiers_le_45(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-mock-key")
    cfg = _load_scanner_config()
    providers, _ = build_default_providers(cfg)

    local_cap = providers.providers["local"].max_requests_per_scan
    frontier_cap = providers.providers["frontier"].max_requests_per_scan
    verifier_cap = providers.providers["verifier"].max_requests_per_scan

    assert local_cap == 20
    assert frontier_cap == 15
    assert verifier_cap == 10
    assert local_cap + frontier_cap + verifier_cap == 45
    assert cfg["limits"]["max_requests_per_scan"] == 45
