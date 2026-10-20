"""Pluggable LLM providers and Provider Routing Hub for the coding agent.

The provider's only job is to *propose* mutations from natural language. It can never
authorise them: every proposal is routed through ``DevGuard``'s fail-closed sink. Supported
providers:

* ``DeterministicProvider`` - an offline, scripted proposal source (no network, no keys, no cost).
* ``AdvisoryAgentProvider`` - simulated advisory LLM reasoning translating goals and context.
* ``OpenRouterProvider`` - a live, OpenAI-compatible provider targeting open-weight models
  (e.g. Qwen 2.5 Coder 32B, LLaMA 3.1 8B, LLaMA 3.3 70B) with graceful offline fallback.
* ``DeepSeekProvider`` - direct provider targeting DeepSeek API (deepseek-chat, deepseek-coder, deepseek-reasoner).
* ``VLLMProvider`` - local loopback provider targeting vLLM instance.
* ``ProviderRoutingHub`` - centralized hub routing across vendors, enforcing egress scrubbing,
  epistemic JEV pre-screening, and fail-closed cascades.

A missing key, a network failure, or unparsable output cascades to local deterministic
advisory reasoning - fail-closed at the agent boundary, never fail-open.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from agentpoi_sde.agent.armor import (
    parse_structured_proposal,
    parse_structured_proposals,
    wrap_envelopes,
)
from agentpoi_sde.agent.jev import JointEpistemicVerifier
from agentpoi_sde.agent.transport_security import (
    scrub_prompt_payload,
    scrub_repository_files,
    validate_transport_url,
)
from agentpoi_sde.config_loader import get_runtime_config
from agentpoi_sde.domain import CodeMutation, MutationOp

_CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

_SYSTEM_PROMPT = (
    "You are a software-engineering agent. Produce a MINIMAL, focused set of code "
    "mutations for the stated task, as a JSON array of objects with keys "
    '"path", "op" (one of create|modify|delete), and "new_content". '
    "Never modify CI, policy, or agent-configuration files unless the task explicitly "
    "requires it. Never delete or weaken tests. Output JSON only."
)

DEFAULT_MODEL = "qwen/qwen-2.5-coder-32b-instruct"
LLAMA_MODEL = "meta-llama/llama-3.1-8b-instruct"
LLAMA_3_3_MODEL = "meta-llama/llama-3.3-70b-instruct"
DEEPSEEK_MODELS = ("deepseek-chat", "deepseek-coder", "deepseek-reasoner")


def _decode_response(content: str) -> List[CodeMutation]:
    """Decode raw model response using strict armor decoder with fallback."""
    single = parse_structured_proposal(content)
    if single is not None:
        return [single.to_code_mutation()]

    multi = parse_structured_proposals(content)
    if multi:
        return [p.to_code_mutation() for p in multi]

    return []


def _parse_mutations(payload: str) -> List[CodeMutation]:
    """Parse a model response into mutations, tolerating code fences and stray prose."""
    text = payload.strip()
    if not text:
        return []
    fenced = _CODE_FENCE.search(text)
    if fenced:
        text = fenced.group(1).strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        raw = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    mutations: List[CodeMutation] = []
    if not isinstance(raw, list):
        return []
    for item in raw:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        op_raw = str(item.get("op", "modify")).lower()
        if not path:
            continue
        try:
            op = MutationOp(op_raw)
        except ValueError:
            continue
        mutations.append(
            CodeMutation(
                path=str(path),
                op=op,
                new_content=str(item.get("new_content", "")),
            )
        )
    return mutations


@dataclass
class DeterministicProvider:
    """Offline, scripted proposal source (the agent's reasoning in simulation)."""

    script: Sequence[CodeMutation] = field(default_factory=tuple)
    label: str = "deterministic-script"

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return self.label

    def available(self) -> bool:
        """The deterministic provider is always available."""
        return True

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Return the scripted proposals regardless of input (deterministic)."""
        return list(self.script)


@dataclass
class AdvisoryAgentProvider:
    """Advisory LLM reasoning provider simulating model output in autonomous coding loops.

    Translates engineering goals, prompt instructions, and untrusted context into proposed
    code mutations. When presented with prompt injection directives or malicious context,
    it models an unaligned or exploited model proposing the attacker's requested mutation.
    When given clean software engineering goals, it synthesises clean functional mutations.
    Output is strictly advisory and routed to DevGuard's fail-closed verification sink.
    """

    script_map: Dict[str, Sequence[CodeMutation]] = field(default_factory=dict)
    fallback_script: Sequence[CodeMutation] = field(default_factory=tuple)
    label: str = "advisory-llm-agent"

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return self.label

    def available(self) -> bool:
        """The advisory provider is always available for local execution."""
        return True

    def register_proposal(self, prompt_key: str, mutations: Sequence[CodeMutation]) -> None:
        """Register a deterministic proposal for a specific prompt key."""
        self.script_map[prompt_key.strip()] = list(mutations)

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Propose mutations from goal and context."""
        goal_str = str(goal or "").strip()
        ctx_str = str(context or "").strip()
        combined_key = f"{goal_str}\n{ctx_str}".strip()

        # 1. Exact key matching
        if combined_key in self.script_map:
            return list(self.script_map[combined_key])
        if ctx_str in self.script_map:
            return list(self.script_map[ctx_str])
        if goal_str in self.script_map:
            return list(self.script_map[goal_str])

        # 2. Check for fenced JSON mutations in context or goal
        fenced_mutations = _parse_mutations(ctx_str) or _parse_mutations(goal_str)
        if fenced_mutations:
            return fenced_mutations

        # 3. Partial matching across registered prompt snippets
        for key, mutations in self.script_map.items():
            if key and (key in combined_key or combined_key in key or key in ctx_str):
                return list(mutations)

        if self.fallback_script:
            return list(self.fallback_script)
        return []


class OpenRouterProvider:
    """Live OpenAI-compatible provider (OpenRouter, local mirrors)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_provider: Optional[Any] = None,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout_seconds: int = 60,
        referer: str = "https://github.com/agent-poi/agentpoi-sde",
        title: str = "AgentPOI-SDE",
    ) -> None:
        runtime = get_runtime_config()
        cfg = runtime.get("openrouter", {})
        if not isinstance(cfg, dict):
            cfg = {}
        default_base_url = cfg.get("base_url", "https://openrouter.ai/api/v1")
        default_timeout = int(cfg.get("timeout_seconds", 60))
        resolved_base_url = base_url if base_url != "https://openrouter.ai/api/v1" else default_base_url
        resolved_timeout = timeout_seconds if timeout_seconds != 60 else default_timeout

        raw_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY")
        self.api_key = raw_key if raw_key else None
        self.model = model or os.environ.get("OPENROUTER_MODEL") or cfg.get("model") or DEFAULT_MODEL
        self.fallback_provider = fallback_provider
        self.base_url = self._validate_base_url(str(resolved_base_url).rstrip("/"))
        self.timeout_seconds = resolved_timeout
        self.referer = referer
        self.title = title

    @staticmethod
    def _validate_base_url(base_url: str) -> str:
        """Accept HTTPS endpoints and explicitly local HTTP inference endpoints only."""
        return validate_transport_url(base_url)

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return f"openrouter:{self.model}"

    def available(self) -> bool:
        """Return True when an API key is configured."""
        return bool(self.api_key and self.api_key.strip())

    def _fallback(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Graceful offline fallback to deterministic advisory reasoning."""
        if self.fallback_provider is not None:
            try:
                return list(self.fallback_provider.propose_mutations(goal, context, files))
            except Exception:
                return []
        return []

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Request mutations from the live model; cascade to fallback on any failure."""
        if not self.available():
            return self._fallback(goal, context, files)

        import requests

        envelope_prompt = wrap_envelopes(
            intent_id="task",
            goal=goal,
            untrusted_contexts=[("context", context)] if context else [],
        )
        summarised_files = self._summarise(files)
        user_prompt = (
            f"{envelope_prompt}\n\n"
            f"REPOSITORY FILES (truncated):\n{summarised_files}\n"
        )
        # Scrub entire prompt payload prior to egress
        user_prompt = scrub_prompt_payload(user_prompt)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                timeout=self.timeout_seconds,
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            )
            response.raise_for_status()
            data: Dict[str, Any] = response.json()
            content = str(data["choices"][0]["message"]["content"])
        except Exception:
            return self._fallback(goal, context, files)

        mutations = _decode_response(content)
        if not mutations:
            return self._fallback(goal, context, files)
        return mutations

    @staticmethod
    def _summarise(files: Dict[str, str], per_file_chars: int = 400) -> str:
        """Summarise only safe repository material for a remote provider."""
        return scrub_repository_files(files, per_file_chars=per_file_chars)


class DeepSeekProvider:
    """Direct model provider targeting DeepSeek API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_provider: Optional[Any] = None,
        base_url: str = "https://api.deepseek.com/v1",
        timeout_seconds: int = 60,
    ) -> None:
        runtime = get_runtime_config()
        cfg = runtime.get("deepseek", {})
        if not isinstance(cfg, dict):
            cfg = {}
        default_base_url = cfg.get("base_url", "https://api.deepseek.com/v1")
        default_timeout = int(cfg.get("timeout_seconds", 60))
        resolved_base_url = base_url if base_url != "https://api.deepseek.com/v1" else default_base_url
        resolved_timeout = timeout_seconds if timeout_seconds != 60 else default_timeout

        raw_key = api_key if api_key is not None else os.environ.get("DEEPSEEK_API_KEY")
        self.api_key = raw_key if raw_key else None
        self.model = model or os.environ.get("DEEPSEEK_MODEL") or cfg.get("model") or "deepseek-coder"
        self.fallback_provider = fallback_provider
        self.base_url = validate_transport_url(str(resolved_base_url).rstrip("/"))
        self.timeout_seconds = resolved_timeout

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return f"deepseek:{self.model}"

    def available(self) -> bool:
        """Return True when an API key is configured."""
        return bool(self.api_key and self.api_key.strip())

    def _fallback(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Graceful offline fallback to deterministic advisory reasoning."""
        if self.fallback_provider is not None:
            try:
                return list(self.fallback_provider.propose_mutations(goal, context, files))
            except Exception:
                return []
        return []

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Request mutations from DeepSeek endpoint with fail-closed fallback."""
        if not self.available():
            return self._fallback(goal, context, files)

        import requests

        envelope_prompt = wrap_envelopes(
            intent_id="task",
            goal=goal,
            untrusted_contexts=[("context", context)] if context else [],
        )
        summarised_files = scrub_repository_files(files)
        user_prompt = (
            f"{envelope_prompt}\n\n"
            f"REPOSITORY FILES (truncated):\n{summarised_files}\n"
        )
        user_prompt = scrub_prompt_payload(user_prompt)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                timeout=self.timeout_seconds,
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            )
            response.raise_for_status()
            data: Dict[str, Any] = response.json()
            content = str(data["choices"][0]["message"]["content"])
        except Exception:
            return self._fallback(goal, context, files)

        mutations = _decode_response(content)
        if not mutations:
            return self._fallback(goal, context, files)
        return mutations


class VLLMProvider:
    """Local OpenAI-compatible provider targeting local loopback vLLM server."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        fallback_provider: Optional[Any] = None,
        base_url: str = "http://localhost:8000/v1",
        timeout_seconds: int = 60,
    ) -> None:
        runtime = get_runtime_config()
        cfg = runtime.get("vllm", {})
        if not isinstance(cfg, dict):
            cfg = {}
        default_base_url = cfg.get("base_url", "http://localhost:8000/v1")
        default_timeout = int(cfg.get("timeout_seconds", 60))
        resolved_base_url = base_url if base_url != "http://localhost:8000/v1" else default_base_url
        resolved_timeout = timeout_seconds if timeout_seconds != 60 else default_timeout

        raw_key = api_key if api_key is not None else os.environ.get("VLLM_API_KEY", "EMPTY")
        self.api_key = raw_key
        self.model = model or os.environ.get("VLLM_MODEL") or cfg.get("model") or DEFAULT_MODEL
        self.fallback_provider = fallback_provider
        self.base_url = validate_transport_url(str(resolved_base_url).rstrip("/"))
        self.timeout_seconds = resolved_timeout

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return f"vllm:{self.model}"

    def available(self) -> bool:
        """Local loopback vLLM provider is assumed available if configured."""
        return True

    def _fallback(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Graceful offline fallback to deterministic advisory reasoning."""
        if self.fallback_provider is not None:
            try:
                return list(self.fallback_provider.propose_mutations(goal, context, files))
            except Exception:
                return []
        return []

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Request mutations from local vLLM server with fail-closed fallback."""
        import requests

        envelope_prompt = wrap_envelopes(
            intent_id="task",
            goal=goal,
            untrusted_contexts=[("context", context)] if context else [],
        )
        summarised_files = scrub_repository_files(files)
        user_prompt = (
            f"{envelope_prompt}\n\n"
            f"REPOSITORY FILES (truncated):\n{summarised_files}\n"
        )
        user_prompt = scrub_prompt_payload(user_prompt)

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                timeout=self.timeout_seconds,
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                },
            )
            response.raise_for_status()
            data: Dict[str, Any] = response.json()
            content = str(data["choices"][0]["message"]["content"])
        except Exception:
            return self._fallback(goal, context, files)

        mutations = _decode_response(content)
        if not mutations:
            return self._fallback(goal, context, files)
        return mutations


class ProviderRoutingHub:
    """Multi-vendor provider routing hub.

    Manages provider selection across OpenRouter, DeepSeek, vLLM, and deterministic fallback.
    Enforces egress scrubbing prior to transport and evaluates responses via JointEpistemicVerifier.
    """

    def __init__(
        self,
        provider_name: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_provider: Optional[Any] = None,
        jev: Optional[JointEpistemicVerifier] = None,
        **kwargs: Any,
    ) -> None:
        runtime = get_runtime_config()
        resolved_name = (
            provider_name
            or os.environ.get("AGENTPOI_SDE_PROVIDER")
            or runtime.get("llm_provider", "auto")
        )
        resolved_name = str(resolved_name).lower().strip()

        self.fallback_provider = fallback_provider or DeterministicProvider()
        self.jev = jev or JointEpistemicVerifier()
        self._active_provider_name = resolved_name
        self._active_provider = self._init_provider(
            resolved_name,
            api_key=api_key,
            model=model,
            fallback_provider=self.fallback_provider,
            **kwargs,
        )

    def _init_provider(
        self,
        name: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_provider: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        if name in {"deterministic", "offline"}:
            return self.fallback_provider
        if name == "advisory":
            return AdvisoryAgentProvider(fallback_script=getattr(self.fallback_provider, "script", ()))
        if name == "deepseek":
            return DeepSeekProvider(
                api_key=api_key,
                model=model,
                fallback_provider=fallback_provider,
                **kwargs,
            )
        if name == "vllm":
            return VLLMProvider(
                api_key=api_key,
                model=model,
                fallback_provider=fallback_provider,
                **kwargs,
            )
        if name == "openrouter":
            return OpenRouterProvider(
                api_key=api_key,
                model=model,
                fallback_provider=fallback_provider,
                **kwargs,
            )
        if name == "auto":
            # Priority: DeepSeek -> OpenRouter -> Deterministic
            ds = DeepSeekProvider(
                api_key=api_key, model=model, fallback_provider=fallback_provider, **kwargs
            )
            if ds.available():
                self._active_provider_name = "deepseek"
                return ds
            orp = OpenRouterProvider(
                api_key=api_key, model=model, fallback_provider=fallback_provider, **kwargs
            )
            if orp.available():
                self._active_provider_name = "openrouter"
                return orp
            self._active_provider_name = "deterministic"
            return self.fallback_provider

        raise ValueError(f"Unsupported SDE LLM provider: {name}")

    @property
    def active_provider_name(self) -> str:
        """Return the identifier of the active provider."""
        return self._active_provider_name

    @property
    def active_provider(self) -> Any:
        """Return the underlying active provider instance."""
        return self._active_provider

    @property
    def name(self) -> str:
        """Return the hub provider label."""
        return f"hub:{self._active_provider.name}"

    def available(self) -> bool:
        """Return True when the active provider is available."""
        return bool(self._active_provider.available())

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Propose mutations, scrubbing outbound content and pre-screening through JEV."""
        # 1. Scrub prompt payloads and file contexts prior to network egress
        scrubbed_goal = scrub_prompt_payload(str(goal or ""))
        scrubbed_context = scrub_prompt_payload(str(context or ""))
        scrubbed_files = {p: scrub_prompt_payload(c) for p, c in files.items()}

        # 2. Invoke active provider with graceful cascade to fallback
        try:
            raw_mutations = self._active_provider.propose_mutations(
                scrubbed_goal, scrubbed_context, scrubbed_files
            )
        except Exception:
            raw_mutations = []

        if not raw_mutations and self.fallback_provider is not None and self._active_provider is not self.fallback_provider:
            try:
                raw_mutations = list(
                    self.fallback_provider.propose_mutations(
                        scrubbed_goal, scrubbed_context, scrubbed_files
                    )
                )
            except Exception:
                raw_mutations = []

        # 3. Epistemic verification sink (JEV) pre-screening
        verified_mutations: List[CodeMutation] = []
        for mut in raw_mutations:
            verdict = self.jev.verify_proposal(mut, workspace=files)
            if verdict.approved:
                verified_mutations.append(mut)

        return verified_mutations


def get_default_provider() -> (
    "OpenRouterProvider | DeterministicProvider | DeepSeekProvider | VLLMProvider | ProviderRoutingHub"
):
    """Return the configured provider or routing hub fail-closed."""
    runtime = get_runtime_config()
    provider_name = str(
        os.environ.get("AGENTPOI_SDE_PROVIDER") or runtime.get("llm_provider", "auto")
    ).lower().strip()

    if provider_name in {"deterministic", "offline"}:
        return DeterministicProvider()
    if provider_name == "deepseek":
        ds = DeepSeekProvider()
        return ds if ds.available() else DeterministicProvider()
    if provider_name == "vllm":
        return VLLMProvider()
    if provider_name in {"hub", "provider_hub"}:
        return ProviderRoutingHub()
    if provider_name in {"auto", "openrouter"}:
        provider = OpenRouterProvider()
        if provider.available():
            return provider
        return DeterministicProvider()
    raise ValueError(f"Unsupported SDE LLM provider: {provider_name}")
