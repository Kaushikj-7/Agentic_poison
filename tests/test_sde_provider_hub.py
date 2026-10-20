"""Unit and integration test suite for ProviderRoutingHub, DeepSeek, and vLLM providers.

Requirement R2 & R6:
- Multi-Vendor Provider Hub managing OpenRouter, DeepSeek, vLLM, and deterministic fallback.
- Support for Qwen 2.5 Coder 32B, LLaMA 3.3 70B, DeepSeek Coder/Chat/Reasoner.
- Strict egress scrubbing prior to network calls.
- Joint Epistemic Verifier integration filtering untrusted model outputs.
- Fail-closed cascades on outages, timeouts, and unparsable responses.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from agentpoi_sde.agent.llm_provider import (
    DEFAULT_MODEL,
    LLAMA_3_3_MODEL,
    DeepSeekProvider,
    DeterministicProvider,
    ProviderRoutingHub,
    VLLMProvider,
    get_default_provider,
)
from agentpoi_sde.domain import CodeMutation, MutationOp

MOCK_API_KEY = "sk-deepseek-mock-test-key-12345"


def _build_mock_response(content: str, status_code: int = 200) -> MagicMock:
    """Helper to mock requests.post responses."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if status_code >= 400:
        http_err = requests.HTTPError(f"HTTP {status_code} Error", response=mock_resp)
        mock_resp.raise_for_status.side_effect = http_err
    else:
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": content}}]
        }
    return mock_resp


# =========================================================================
# DeepSeekProvider Tests
# =========================================================================

def test_deepseek_initialization_defaults():
    """Verify DeepSeekProvider defaults: base_url, model, headers."""
    provider = DeepSeekProvider(api_key=MOCK_API_KEY)
    assert provider.base_url == "https://api.deepseek.com/v1"
    assert provider.model == "deepseek-coder"
    assert provider.name == "deepseek:deepseek-coder"
    assert provider.available() is True


def test_deepseek_model_selection():
    """Verify supported DeepSeek models (chat, coder, reasoner)."""
    for model_name in ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"]:
        p = DeepSeekProvider(api_key=MOCK_API_KEY, model=model_name)
        assert p.model == model_name


def test_deepseek_rejects_insecure_remote_http():
    """Verify non-loopback HTTP base_url is rejected fail-closed (Rule 10)."""
    with pytest.raises(ValueError, match="HTTPS"):
        DeepSeekProvider(api_key=MOCK_API_KEY, base_url="http://api.deepseek.com/v1")


def test_deepseek_successful_proposal():
    """Verify DeepSeekProvider formats headers and parses mutation response."""
    provider = DeepSeekProvider(api_key=MOCK_API_KEY, model="deepseek-coder")
    resp_text = '[{"path": "svc/algo.py", "op": "create", "new_content": "def run(): return 42\\n"}]'

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(resp_text)
        muts = provider.propose_mutations("implement algo", "", {})
        assert len(muts) == 1
        assert muts[0].path == "svc/algo.py"
        assert muts[0].op == MutationOp.CREATE

        # Check call arguments
        mock_post.assert_called_once()
        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == f"Bearer {MOCK_API_KEY}"
        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["model"] == "deepseek-coder"


def test_deepseek_failure_cascades_to_fallback():
    """Verify HTTP 500 or timeout in DeepSeek cascades to fallback provider."""
    script_mut = CodeMutation("fallback.py", MutationOp.CREATE, "x = 1\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = DeepSeekProvider(api_key=MOCK_API_KEY, fallback_provider=fallback)

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timeout")):
        muts = provider.propose_mutations("task", "", {})
        assert muts == [script_mut]


# =========================================================================
# VLLMProvider Tests
# =========================================================================

def test_vllm_initialization_defaults():
    """Verify VLLMProvider defaults: loopback base_url and Qwen default model."""
    provider = VLLMProvider()
    assert provider.base_url == "http://localhost:8000/v1"
    assert provider.model == DEFAULT_MODEL
    assert provider.available() is True


def test_vllm_rejects_non_loopback_http():
    """Verify vLLM with external HTTP host is rejected fail-closed (Rule 10)."""
    with pytest.raises(ValueError, match="HTTPS"):
        VLLMProvider(base_url="http://192.168.1.100:8000/v1")


def test_vllm_allows_ipv4_and_ipv6_loopback():
    """Verify vLLM permits 127.0.0.1 and ::1 loopback addresses."""
    p1 = VLLMProvider(base_url="http://127.0.0.1:8000/v1")
    assert p1.base_url == "http://127.0.0.1:8000/v1"
    p2 = VLLMProvider(base_url="http://[::1]:8000/v1")
    assert p2.base_url == "http://[::1]:8000/v1"


def test_vllm_propose_mutations():
    """Verify VLLMProvider sends request to local inference server."""
    provider = VLLMProvider()
    resp_text = '[{"path": "core.py", "op": "modify", "new_content": "y = 2\\n"}]'

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(resp_text)
        muts = provider.propose_mutations("update y", "", {})
        assert len(muts) == 1
        assert muts[0].path == "core.py"


# =========================================================================
# Model Constants Test
# =========================================================================

def test_llama_3_3_model_constant():
    """Verify meta-llama/llama-3.3-70b-instruct is registered as a model constant."""
    assert LLAMA_3_3_MODEL == "meta-llama/llama-3.3-70b-instruct"
    assert DEFAULT_MODEL == "qwen/qwen-2.5-coder-32b-instruct"


# =========================================================================
# ProviderRoutingHub Tests
# =========================================================================

def test_provider_hub_routing_selection():
    """Verify ProviderRoutingHub routes to requested vendor."""
    hub = ProviderRoutingHub(
        provider_name="deepseek",
        api_key=MOCK_API_KEY,
    )
    assert hub.active_provider_name == "deepseek"
    assert isinstance(hub.active_provider, DeepSeekProvider)


def test_provider_hub_offline_deterministic_fallback():
    """Verify deterministic routing when specified."""
    hub = ProviderRoutingHub(provider_name="deterministic")
    assert hub.active_provider_name == "deterministic"
    assert isinstance(hub.active_provider, DeterministicProvider)


def test_provider_hub_scrubs_prompt_egress():
    """Verify ProviderRoutingHub scrubs prompt and context secrets before network egress (R6)."""
    hub = ProviderRoutingHub(
        provider_name="openrouter",
        api_key="sk-or-mock-key",
    )
    resp_text = '[{"path": "safe.py", "op": "create", "new_content": "a = 1\\n"}]'

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(resp_text)

        sensitive_goal = 'Fix bug with DEPLOY_API_KEY = "sk-live-supersecret12345"'
        sensitive_context = 'GITHUB_TOKEN = "ghp_mocktoken987654321"'
        sensitive_files = {"config.py": 'AWS_SECRET_KEY = "AKIA123456789EXAMPLE"'}

        hub.propose_mutations(sensitive_goal, sensitive_context, sensitive_files)

        mock_post.assert_called_once()
        user_prompt = mock_post.call_args[1]["json"]["messages"][1]["content"]

        # Ensure raw secrets were REDACTED before egress
        assert "sk-live-supersecret12345" not in user_prompt
        assert "ghp_mocktoken987654321" not in user_prompt
        assert "AKIA123456789EXAMPLE" not in user_prompt
        assert "[REDACTED_SECRET]" in user_prompt


def test_provider_hub_evaluates_proposals_through_jev():
    """Verify ProviderRoutingHub filters out model proposals failing JEV verification (R2)."""
    hub = ProviderRoutingHub(
        provider_name="vllm",
    )
    # Model returns 2 proposals: 1 invalid syntax, 1 clean syntax
    model_response = (
        '['
        '  {"path": "bad.py", "op": "create", "new_content": "def bad(:\\n    pass\\n"},'
        '  {"path": "good.py", "op": "create", "new_content": "def good():\\n    return True\\n"}'
        ']'
    )

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(model_response)
        muts = hub.propose_mutations("task", "", {})

        # The bad syntax proposal must be dropped by JEV
        assert len(muts) == 1
        assert muts[0].path == "good.py"


def test_provider_hub_rejects_credential_leaking_proposal():
    """Verify proposals leaking credentials in new content are dropped by JEV in hub."""
    hub = ProviderRoutingHub(
        provider_name="vllm",
    )
    model_response = (
        '['
        '  {"path": "leak.py", "op": "create", "new_content": "DEPLOY_API_KEY = \\"sk-live-12345\\"\\n"}'
        ']'
    )

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(model_response)
        muts = hub.propose_mutations("task", "", {})
        assert muts == []


def test_provider_hub_cascades_network_error_to_fallback():
    """Verify hub gracefully falls back to deterministic provider on network outage."""
    fallback_mut = CodeMutation("fallback.py", MutationOp.CREATE, "pass\n")
    hub = ProviderRoutingHub(
        provider_name="deepseek",
        api_key=MOCK_API_KEY,
        fallback_provider=DeterministicProvider(script=[fallback_mut]),
    )

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        muts = hub.propose_mutations("task", "", {})
        assert muts == [fallback_mut]


def test_get_default_provider_routing_hub_integration(monkeypatch):
    """Verify get_default_provider can instantiate ProviderRoutingHub."""
    monkeypatch.setenv("AGENTPOI_SDE_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", MOCK_API_KEY)
    provider = get_default_provider()
    assert isinstance(provider, (ProviderRoutingHub, DeepSeekProvider))
