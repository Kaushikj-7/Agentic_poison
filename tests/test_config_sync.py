"""Unit tests for configuration synchronization and YAML loading."""

import pytest

from agent_poi.core.config_loader import (
    get_financial_domain_config,
    get_trust_model_config,
    load_config,
)


def test_config_loader_reads_yaml():
    config = load_config()
    assert isinstance(config, dict)
    assert "trust_model" in config
    assert "financial_domain" in config
    assert config["version"] == "1.0.0"

    # Verify fallback on non-existent custom path
    fallback = load_config("/non/existent/config.yaml")
    assert isinstance(fallback, dict)
    assert "trust_model" in fallback
    assert fallback["financial_domain"]["per_transaction_limit"] == 25000.0



def test_trust_model_config_integrity():
    trust_cfg = get_trust_model_config()
    assert "lambda_decay" in trust_cfg
    assert trust_cfg["lambda_decay"] == 2.5
    assert "tau_threshold" in trust_cfg
    assert "risk_weights" in trust_cfg
    assert sum(trust_cfg["risk_weights"].values()) == pytest.approx(1.0)


def test_financial_domain_config_integrity():
    fin_cfg = get_financial_domain_config()
    assert fin_cfg["per_transaction_limit"] == 25000.0
    assert fin_cfg["daily_limit"] == 100000.0
    assert "relevance_threshold" in fin_cfg
    assert "max_divergence_risk" in fin_cfg
