"""Pluggable LLM providers for the coding agent.

The provider's only job is to *propose* mutations from natural language. It can never
authorise them: every proposal is routed through ``DevGuard``'s fail-closed sink. Three
providers ship here:

* ``DeterministicProvider`` - an offline, scripted proposal source. Reproducible and
  used by the simulation and test harness (no network, no keys, no cost).
* ``AdvisoryAgentProvider`` - simulated advisory LLM reasoning translating goals and context.
* ``OpenRouterProvider`` - a live, OpenAI-compatible provider targeting open-weight models
  (e.g. Qwen 2.5 Coder 32B, LLaMA 3.1 8B) with graceful offline fallback.

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
from agentpoi_sde.config_loader import load_sde_config
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
    """Live OpenAI-compatible provider (OpenRouter, local vLLM, or any mirror)."""

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
        cfg = load_sde_config().get("runtime", {}).get("openrouter", {})
        default_base_url = cfg.get("base_url", "https://openrouter.ai/api/v1")
        default_timeout = int(cfg.get("timeout_seconds", 60))
        resolved_base_url = base_url if base_url != "https://openrouter.ai/api/v1" else default_base_url
        resolved_timeout = timeout_seconds if timeout_seconds != 60 else default_timeout

        raw_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY")
        self.api_key = raw_key if raw_key else None
        self.model = model or os.environ.get("OPENROUTER_MODEL") or DEFAULT_MODEL
        self.fallback_provider = fallback_provider
        self.base_url = resolved_base_url.rstrip("/")
        self.timeout_seconds = resolved_timeout
        self.referer = referer
        self.title = title

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
        advisory = AdvisoryAgentProvider()
        return list(advisory.propose_mutations(goal, context, files))

    def _decode_response(self, content: str) -> List[CodeMutation]:
        """Decode raw model response using strict armor decoder with fallback."""
        single = parse_structured_proposal(content)
        if single is not None:
            return [single.to_code_mutation()]

        multi = parse_structured_proposals(content)
        if multi:
            return [p.to_code_mutation() for p in multi]

        # Return empty list fail-closed if decoding fails
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
        user_prompt = (
            f"{envelope_prompt}\n\n"
            f"REPOSITORY FILES (truncated):\n{self._summarise(files)}\n"
        )

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

        mutations = self._decode_response(content)
        if not mutations:
            return self._fallback(goal, context, files)
        return mutations

    @staticmethod
    def _summarise(files: Dict[str, str], per_file_chars: int = 400) -> str:
        """Summarise the repository cheaply for the prompt."""
        lines: List[str] = []
        for path in sorted(files):
            snippet = files[path][:per_file_chars].replace("\r", "")
            lines.append(f"--- {path} ---\n{snippet}")
        return "\n".join(lines)


def get_default_provider() -> "OpenRouterProvider | DeterministicProvider":
    """Return the configured default provider (deterministic unless a key is present)."""
    provider = OpenRouterProvider()
    if provider.available():
        return provider
    return DeterministicProvider()
