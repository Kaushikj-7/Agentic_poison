"""Schema-validated, fail-closed bridge from Zone 3 to the LLM provider stack.

Wraps the existing ``agent_poi.agent.llm_provider`` providers behind a
``complete_json(prompt, schema, tier)`` interface: responses are parsed as
strict JSON with required keys; any unavailable provider, network drop, or
malformed response degrades to ``None`` — never to a permissive default.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple


class TieredProviders:
    """Local / frontier / verifier tiers, each wired to a concrete provider."""

    def __init__(
        self,
        providers: Dict[str, Any],  # mapping tier -> provider with .generate(prompt, system_prompt)
        tiers: Tuple[str, ...] = ("local", "frontier", "verifier"),
    ) -> None:
        self.providers = providers
        self.tiers = tiers

    def available(self, tier: str) -> bool:
        provider = self.providers.get(tier)
        if provider is None:
            return False
        checker = getattr(provider, "is_available", None)
        if callable(checker):
            try:
                return bool(checker())
            except Exception:  # noqa: BLE001 fail-closed availability probe
                return False
        return True  # injected test doubles are considered available

    def complete_json(
        self,
        tier: str,
        prompt: str,
        system_prompt: str,
        required_keys: Tuple[str, ...],
    ) -> Optional[Dict[str, Any]]:
        """Returns validated JSON dict, or None (fail-closed) on any failure."""
        provider = self.providers.get(tier)
        if provider is None or not self.available(tier):
            return None
        try:
            response = provider.generate(prompt, system_prompt=system_prompt)
        except Exception:  # noqa: BLE001 - network/timeouts degrade to None
            return None
        content = ""
        if isinstance(response, dict):
            content = str(response.get("content") or response.get("text") or "")
        elif isinstance(response, str):
            content = response
        payload = extract_json(content)
        if payload is None or not isinstance(payload, dict):
            return None
        if all(key in payload for key in required_keys):
            return payload
        return None


_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extracts the first JSON object embedded in model output."""
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass
    match = _JSON_OBJ_RE.search(text)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            return None
    return None


def build_default_providers(config: Dict[str, Any]) -> Tuple[TieredProviders, Dict[str, str]]:
    """Builds the tiered providers from scanner_config.yaml-shaped data.

    Returns the providers plus a dictionary of tier -> reason unavailable.
    """
    import os

    from agent_poi.agent.llm_provider import OllamaProvider, OpenRouterProvider

    providers: Dict[str, Any] = {}
    unavailable: Dict[str, str] = {}

    local_cfg = (config.get("tiers") or {}).get("local") or {}
    if local_cfg.get("provider") == "ollama":
        providers["local"] = OllamaProvider(
            base_url=local_cfg.get("base_url", "http://localhost:11434"),
            model=local_cfg.get("model", "qwen2.5-coder:14b"),
        )
    else:
        unavailable["local"] = f"unsupported local provider: {local_cfg.get('provider')!r}"

    frontier_cfg = (config.get("tiers") or {}).get("frontier") or {}
    if frontier_cfg.get("provider") == "openrouter":
        key = os.environ.get("OPENROUTER_API_KEY", "")
        if key:
            providers["frontier"] = OpenRouterProvider(api_key=key, model=frontier_cfg.get("model", ""))
        else:
            unavailable["frontier"] = "OPENROUTER_API_KEY not set"
    else:
        unavailable["frontier"] = f"unsupported frontier provider: {frontier_cfg.get('provider')!r}"

    verifier_cfg = (config.get("tiers") or {}).get("verifier") or {}
    if verifier_cfg.get("provider") == "ollama":
        providers["verifier"] = OllamaProvider(
            base_url=verifier_cfg.get("base_url", "http://localhost:11434"),
            model=verifier_cfg.get("model", "llama3.2:3b"),
        )
    else:
        unavailable["verifier"] = f"unsupported verifier provider: {verifier_cfg.get('provider')!r}"

    return TieredProviders(providers), unavailable
