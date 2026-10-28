"""Schema-validated, fail-closed bridge from Zone 3 to the LLM provider stack.

Wraps the existing ``agent_poi.agent.llm_provider`` providers behind a
``complete_json(prompt, schema, tier)`` interface: responses are parsed as
strict JSON with required keys; any unavailable provider, network drop, or
malformed response degrades to ``None`` — never to a permissive default.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple

# Load the repo-root .env once at import time (same pattern as agent_poi.core.
# config_loader): makes OPENROUTER_API_KEY / OPENROUTER_MODEL available to the
# scanner without hardcoding secrets. Import-time only, so tests that delenv
# inside a test body still see the variable absent. python-dotenv is used when
# installed; otherwise a minimal stdlib parser fills the gap. Existing env vars
# always win — .env never overrides the caller's environment.
_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", ".env")


def _load_env_file(path: str) -> None:
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _sep, value = line.partition("=")
                key, value = key.strip(), value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                if key and not os.environ.get(key):
                    os.environ[key] = value
    except OSError:  # unreadable env file → proceed with whatever is in the env
        pass


try:
    from dotenv import load_dotenv

    load_dotenv(_ENV_PATH)
except ImportError:
    _load_env_file(_ENV_PATH)


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


class RateLimitedProvider:
    """Enforces free-tier request limits around an OpenRouter provider, fail-closed.

    OpenRouter's ``:free`` models allow ~20 requests/minute and a small daily
    quota. Two hard caps are enforced locally before any request leaves the
    machine:
    - ``requests_per_minute``: a sliding 60s window; when exhausted the caller
      sleeps once for the remainder (capped by ``max_backoff_seconds``), then
      degrades to unavailable — never spins all night.
    - ``max_requests_per_scan``: once the total cap is hit, ``is_available``
      turns False and every further call degrades to None (fail-closed).
    """

    def __init__(
        self,
        provider: Any,
        requests_per_minute: int = 15,
        max_requests_per_scan: int = 40,
        max_backoff_seconds: float = 60.0,
        _sleep: Any = time.sleep,
        _now: Any = time.monotonic,
    ) -> None:
        self.provider = provider
        self.requests_per_minute = int(requests_per_minute)
        self.max_requests_per_scan = int(max_requests_per_scan)
        self.max_backoff_seconds = float(max_backoff_seconds)
        self._sleep = _sleep
        self._now = _now
        self._lock = threading.Lock()
        self._window_start = self._now()
        self._window_count = 0
        self._total = 0

    def is_available(self) -> bool:
        return self._total < self.max_requests_per_scan

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        wait: float = 0.0
        with self._lock:
            if not self.is_available():
                raise RuntimeError("free-tier request cap for this scan exhausted")
            now = self._now()
            if now - self._window_start >= 60.0:
                self._window_start = now
                self._window_count = 0
            if self._window_count >= self.requests_per_minute:
                remainder = 60.0 - (now - self._window_start)
                if remainder > self.max_backoff_seconds:
                    raise RuntimeError("rate window exhausted beyond backoff budget")
                wait = max(remainder, 0.0)
            self._window_count += 1
            self._total += 1
        if wait > 0.0:
            self._sleep(wait)
        return self.provider.generate(prompt, system_prompt=system_prompt)


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
            # model resolution: explicit config value wins; otherwise the
            # provider falls back to OPENROUTER_MODEL (from .env), then its
            # built-in open-weight free default.
            frontier = OpenRouterProvider(api_key=key, model=frontier_cfg.get("model") or None)
            limits = config.get("limits") or {}
            providers["frontier"] = RateLimitedProvider(
                frontier,
                requests_per_minute=limits.get("requests_per_minute", 15),
                max_requests_per_scan=limits.get("max_requests_per_scan", 40),
                max_backoff_seconds=limits.get("max_backoff_seconds", 60.0),
            )
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
