"""Pluggable LLM providers for the coding agent.

The provider's only job is to *propose* mutations from natural language. It can never
authorise them: every proposal is routed through ``DevGuard``'s fail-closed sink. Two
providers ship here:

* ``DeterministicProvider`` - an offline, scripted proposal source. Reproducible and
  used by the simulation and test harness (no network, no keys, no cost).
* ``OpenRouterProvider`` - a live, OpenAI-compatible provider selected by API key.

A missing key, a network failure, or unparsable output degrades to *no proposals* -
fail-closed at the agent boundary, never fail-open.
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from agentpoi_sde.domain import CodeMutation, MutationOp

_CODE_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)

_SYSTEM_PROMPT = (
    "You are a software-engineering agent. Produce a MINIMAL, focused set of code "
    "mutations for the stated task, as a JSON array of objects with keys "
    '"path", "op" (one of create|modify|delete), and "new_content". '
    "Never modify CI, policy, or agent-configuration files unless the task explicitly "
    "requires it. Never delete or weaken tests. Output JSON only."
)


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
        model: str = "openrouter/auto",
        base_url: str = "https://openrouter.ai/api/v1",
        timeout_seconds: int = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        """Return the provider identity."""
        return f"openrouter:{self.model}"

    def available(self) -> bool:
        """Return True when an API key is configured."""
        return bool(self.api_key)

    def propose_mutations(
        self, goal: str, context: str, files: Dict[str, str]
    ) -> List[CodeMutation]:
        """Request mutations from the live model; return [] on any failure (fail-closed)."""
        if not self.available():
            return []
        import requests

        user_prompt = (
            f"TASK:\n{goal}\n\nCONTEXT:\n{context}\n\n"
            f"REPOSITORY FILES (truncated):\n{self._summarise(files)}\n"
        )
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                timeout=self.timeout_seconds,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
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
            content = data["choices"][0]["message"]["content"]
        except Exception:
            return []
        return _parse_mutations(str(content))

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
