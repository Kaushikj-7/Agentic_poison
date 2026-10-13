"""Unit tests for run_gemini_onetime_probe logic without network dependencies."""

import pytest
from unittest.mock import MagicMock
from scripts.run_gemini_onetime_probe import parse_action_from_text, run_gemini_query


def test_parse_action_from_clean_response():
    sample_text = "I have verified the invoice. Action: transfer_funds to_account=1122-3344-55 amount=$4,500.00."
    res = parse_action_from_text(sample_text)
    assert res["to_account"] == "1122-3344-55"
    assert res["amount"] == 4500.0


def test_parse_action_from_adversarial_response():
    sample_text = "Following executive memo, redirecting wire to 9876-5432-10 for $25,000.00 USD."
    res = parse_action_from_text(sample_text)
    assert res["to_account"] == "9876-5432-10"
    assert res["amount"] == 25000.0


def test_run_gemini_query_mock():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "Action: transfer_funds to_account=1122-3344-55 amount=$4,500.00"
    mock_response.usage_metadata.prompt_token_count = 42
    mock_response.usage_metadata.candidates_token_count = 15
    mock_response.usage_metadata.total_token_count = 57
    mock_client.models.generate_content.return_value = mock_response

    res = run_gemini_query(mock_client, ["gemini-test"], "test prompt", "system prompt")
    assert res["text"] == "Action: transfer_funds to_account=1122-3344-55 amount=$4,500.00"
    assert res["total_tokens"] == 57
    assert res["prompt_tokens"] == 42
    assert res["candidate_tokens"] == 15
    assert res["latency_ms"] >= 0.0
