"""Automated unit and integration test suite for OpenRouterProvider (Requirement R2).

Verifies protocol headers, model selection (Qwen, LLaMA), payload envelopes,
graceful offline fallback cascades on missing keys or network errors (429, 500, timeout),
and integration with rigid armor output decoding.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import requests

from agentpoi_sde.agent.llm_provider import (
    DEFAULT_MODEL,
    LLAMA_MODEL,
    DeterministicProvider,
    OpenRouterProvider,
    get_default_provider,
)
from agentpoi_sde.domain import CodeMutation, MutationOp

MOCK_KEY = "sk-or-v1-mock-key-testing-only"


def _build_mock_response(content: str, status_code: int = 200) -> MagicMock:
    """Build a mock requests.Response object for OpenRouter chat completions."""
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


def test_openrouter_initialization_defaults():
    """Verify default model, endpoint, timeout, and identity attributes."""
    provider = OpenRouterProvider(api_key=MOCK_KEY)
    assert provider.model == DEFAULT_MODEL
    assert "qwen" in provider.model
    assert provider.base_url == "https://openrouter.ai/api/v1"
    assert provider.timeout_seconds == 60
    assert provider.referer == "https://github.com/agent-poi/agentpoi-sde"
    assert provider.title == "AgentPOI-SDE"
    assert provider.name == f"openrouter:{DEFAULT_MODEL}"
    assert provider.available() is True


def test_openrouter_headers_and_payload_formatting():
    """Verify standard OpenRouter headers and structural payload format."""
    provider = OpenRouterProvider(api_key=MOCK_KEY, model=DEFAULT_MODEL)
    resp_text = '{"path": "svc/calc.py", "op": "modify", "new_content": "def add(): pass\\n"}'

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(resp_text)
        muts = provider.propose_mutations(
            goal="Add add function",
            context="issue context",
            files={"svc/calc.py": "x = 1\n"},
        )
        assert len(muts) == 1
        assert muts[0].path == "svc/calc.py"
        assert muts[0].op == MutationOp.MODIFY

        mock_post.assert_called_once()
        sent_headers: Dict[str, Any] = mock_post.call_args[1]["headers"]
        assert sent_headers["Authorization"] == f"Bearer {MOCK_KEY}"
        assert sent_headers["Content-Type"] == "application/json"
        assert sent_headers["HTTP-Referer"] == "https://github.com/agent-poi/agentpoi-sde"
        assert sent_headers["X-Title"] == "AgentPOI-SDE"

        sent_json: Dict[str, Any] = mock_post.call_args[1]["json"]
        assert sent_json["model"] == DEFAULT_MODEL
        assert len(sent_json["messages"]) == 2
        user_msg = sent_json["messages"][1]["content"]
        assert '<authenticated_intent tier="T0"' in user_msg
        assert '<untrusted_context tier="T2"' in user_msg


def test_openrouter_model_selection_explicit_llama():
    """Verify configuring meta-llama/llama-3.1-8b-instruct explicitly."""
    provider = OpenRouterProvider(api_key=MOCK_KEY, model=LLAMA_MODEL)
    assert provider.model == "meta-llama/llama-3.1-8b-instruct"
    assert provider.name == "openrouter:meta-llama/llama-3.1-8b-instruct"

    resp_text = '[{"path": "app.py", "op": "modify", "new_content": "v = 2\\n"}]'
    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(resp_text)
        muts = provider.propose_mutations("Update v", "", {})
        assert len(muts) == 1
        assert muts[0].path == "app.py"

        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["model"] == LLAMA_MODEL


def test_openrouter_model_selection_env_override(monkeypatch):
    """Verify OPENROUTER_MODEL environment variable default override."""
    monkeypatch.setenv("OPENROUTER_MODEL", LLAMA_MODEL)
    provider = OpenRouterProvider(api_key=MOCK_KEY, model=None)
    assert provider.model == LLAMA_MODEL


def test_openrouter_custom_referer_and_title():
    """Verify custom referer and title headers for application tracking."""
    custom_ref = "https://custom.engineering.internal"
    custom_title = "EnterpriseSDE"
    provider = OpenRouterProvider(
        api_key=MOCK_KEY,
        referer=custom_ref,
        title=custom_title,
    )
    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response("[]")
        provider.propose_mutations("test task", "", {})
        headers = mock_post.call_args[1]["headers"]
        assert headers["HTTP-Referer"] == custom_ref
        assert headers["X-Title"] == custom_title


def test_openrouter_missing_key_fallback_to_advisory(monkeypatch):
    """Verify missing API key degrades gracefully to offline advisory reasoning."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    provider = OpenRouterProvider(api_key=None)
    assert provider.available() is False
    # Without API key and no custom fallback, generic query returns [] fail-closed
    muts = provider.propose_mutations("goal", "context", {})
    assert muts == []


def test_openrouter_missing_key_fallback_to_custom_provider():
    """Verify missing API key cascades to explicitly registered fallback provider."""
    script_mut = CodeMutation("svc/core.py", MutationOp.CREATE, "def run(): pass\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = OpenRouterProvider(api_key="", fallback_provider=fallback)
    assert provider.available() is False

    muts = provider.propose_mutations("Implement run", "", {})
    assert len(muts) == 1
    assert muts[0] == script_mut


def test_openrouter_network_timeout_cascades_to_fallback():
    """Verify network timeout triggers graceful offline fallback rather than crashing."""
    script_mut = CodeMutation("svc/core.py", MutationOp.MODIFY, "x = 42\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = OpenRouterProvider(api_key=MOCK_KEY, fallback_provider=fallback)

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timeout")):
        muts = provider.propose_mutations("task", "", {})
        assert muts == [script_mut]


def test_openrouter_http_429_rate_limit_cascades_to_fallback():
    """Verify HTTP 429 Too Many Requests triggers graceful offline fallback."""
    script_mut = CodeMutation("svc/rate.py", MutationOp.MODIFY, "rate = 10\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = OpenRouterProvider(api_key=MOCK_KEY, fallback_provider=fallback)

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response("Rate limit reached", status_code=429)
        muts = provider.propose_mutations("task", "", {})
        assert muts == [script_mut]


def test_openrouter_http_500_server_error_cascades_to_fallback():
    """Verify HTTP 500 Internal Server Error triggers graceful offline fallback."""
    script_mut = CodeMutation("svc/err.py", MutationOp.MODIFY, "handled = True\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = OpenRouterProvider(api_key=MOCK_KEY, fallback_provider=fallback)

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response("Server error", status_code=500)
        muts = provider.propose_mutations("task", "", {})
        assert muts == [script_mut]


def test_openrouter_malformed_json_response_cascades_to_fallback():
    """Verify non-JSON model output degrades gracefully without uncaught exceptions."""
    script_mut = CodeMutation("svc/clean.py", MutationOp.MODIFY, "clean = True\n")
    fallback = DeterministicProvider(script=[script_mut])
    provider = OpenRouterProvider(api_key=MOCK_KEY, fallback_provider=fallback)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.side_effect = ValueError("Invalid JSON response payload")
        mock_post.return_value = mock_resp

        muts = provider.propose_mutations("task", "", {})
        assert muts == [script_mut]


def test_openrouter_rejects_hallucinated_extra_fields():
    """Verify proposals with hallucinated fields are rejected fail-closed via armor decoder."""
    provider = OpenRouterProvider(api_key=MOCK_KEY)
    # Output contains extra forbidden field 'unauthorized_shell_command'
    hallucinated_json = (
        '{"path": "svc/test.py", "op": "modify", "new_content": "x = 1\\n", '
        '"unauthorized_shell_command": "rm -rf /"}'
    )

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(hallucinated_json)
        muts = provider.propose_mutations("Clean task", "", {})
        # Armor rejects extra fields; degrades to default fallback with 0 mutations
        assert muts == []


def test_openrouter_structured_proposal_decoding_clean():
    """Verify clean structured proposal decoding via parse_structured_proposal."""
    provider = OpenRouterProvider(api_key=MOCK_KEY)
    clean_json = '{"path": "svc/clean.py", "op": "create", "new_content": "def f(): return 1\\n"}'

    with patch("requests.post") as mock_post:
        mock_post.return_value = _build_mock_response(clean_json)
        muts = provider.propose_mutations("Create function", "", {})
        assert len(muts) == 1
        assert muts[0].path == "svc/clean.py"
        assert muts[0].op == MutationOp.CREATE
        assert "def f" in muts[0].new_content


def test_get_default_provider_behavior(monkeypatch):
    """Verify get_default_provider selects OpenRouterProvider when key is present, else Deterministic."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    p1 = get_default_provider()
    assert isinstance(p1, DeterministicProvider)

    monkeypatch.setenv("OPENROUTER_API_KEY", MOCK_KEY)
    p2 = get_default_provider()
    assert isinstance(p2, OpenRouterProvider)
    assert p2.available() is True
