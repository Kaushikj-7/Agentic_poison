"""Unit tests for OpenRouterProvider (TDD RED -> GREEN)."""

import os
import pytest
from unittest.mock import patch, MagicMock
from agent_poi.agent.llm_provider import OpenRouterProvider, MockLLMProvider


def test_openrouter_provider_availability():
    """Provider is available only when valid OpenRouter API key format is present."""
    provider_no_key = OpenRouterProvider(api_key="")
    assert not provider_no_key.is_available()

    provider_invalid_key = OpenRouterProvider(api_key="invalid_key")
    assert not provider_invalid_key.is_available()

    provider_valid_key = OpenRouterProvider(api_key="sk-or-v1-testkey123456")
    assert provider_valid_key.is_available()


def test_openrouter_provider_fallback_when_no_key():
    """Provider gracefully falls back to deterministic mock when no key is configured."""
    provider = OpenRouterProvider(api_key="")
    res = provider.generate("Summarize corporate notes")
    assert "Summary completed" in res["content"]


@patch("requests.post")
def test_openrouter_provider_successful_generate(mock_post):
    """Provider correctly queries OpenRouter and parses completion response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "id": "gen-12345",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Action: transfer_funds to_account=1122-3344-55 amount=$4500.00",
                }
            }
        ],
        "usage": {"total_tokens": 85},
    }
    mock_post.return_value = mock_resp

    provider = OpenRouterProvider(
        api_key="sk-or-v1-testkey123456",
        model="nvidia/llama-3.1-nemotron-70b-instruct:free",
    )
    res = provider.generate("Process vendor invoice INV-01")

    assert "1122-3344-55" in res["content"]
    assert res.get("tokens") == 85
    assert "nvidia/llama-3.1-nemotron-70b-instruct:free" in res.get("thought", "")


@patch("requests.post")
def test_openrouter_provider_model_fallback_on_failure(mock_post):
    """Provider falls back to alternative free candidate model on HTTP 429/500."""
    fail_resp = MagicMock()
    fail_resp.status_code = 429

    success_resp = MagicMock()
    success_resp.status_code = 200
    success_resp.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": "Approved wire"}}],
        "usage": {"total_tokens": 50},
    }

    # First call fails (primary model), second succeeds (fallback model)
    mock_post.side_effect = [fail_resp, success_resp]

    provider = OpenRouterProvider(
        api_key="sk-or-v1-testkey123456",
        model="nvidia/llama-3.1-nemotron-70b-instruct:free",
    )
    res = provider.generate("Process invoice")

    assert res["content"] == "Approved wire"
    assert mock_post.call_count == 2
