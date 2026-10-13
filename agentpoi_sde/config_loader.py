"""Configuration loader for the AgentPOI-SDE platform.

Mirrors ``agent_poi.core.config_loader``: resolves a YAML config across package, repo and
environment locations, falling back to embedded deterministic defaults so the platform is
fully functional offline with zero external configuration.
"""

import copy
import os
from functools import lru_cache
from typing import Any, Dict, Optional

import yaml

DEFAULT_SDE_CONFIG: Dict[str, Any] = {
    "version": "1.0.0",
    "guard": {
        "policy": "strict",
        "raise_on_violation": False,
        "monitoring_applies_mutations": False,
    },
    "invariants": {
        "enforce_policy_files": True,
        "enforce_test_integrity": True,
        "enforce_secrets": True,
        "enforce_architecture": True,
        "enforce_blast_radius": True,
        "enforce_dependency_provenance": True,
    },
    "egress_allowlist": [
        "https://github.com/",
        "https://pypi.org/",
        "https://docs.python.org/",
    ],
    "protected_paths": [
        ".github/**",
        "**/.github/**",
        "AGENTS.md",
        "**/AGENTS.md",
        ".cursorrules",
        "**/.cursorrules",
        ".github/copilot-instructions.md",
        "**/CLAUDE.md",
        "**/SKILL.md",
        "pyproject.toml",
        "requirements.txt",
        "**/*.lock",
        "**/Dockerfile",
    ],
    "test_markers": ["tests/", "test_", "_test.py", "spec/"],
    "runtime": {
        "llm_provider": "deterministic",
        "openrouter": {
            "base_url": "https://openrouter.ai/api/v1",
            "model": "openrouter/auto",
            "timeout_seconds": 60,
        },
    },
}


def _resolve_config_path(override_path: Optional[str] = None) -> Optional[str]:
    """Resolve an SDE config path across override, env, package and cwd locations.

    The financial ``config.yaml`` at the repository root is deliberately *not* a candidate:
    the SDE platform must never inherit unrelated domain configuration.
    """
    candidates = []
    if override_path:
        candidates.append(override_path)
    env_path = os.environ.get("AGENTPOI_SDE_CONFIG")
    if env_path:
        candidates.append(env_path)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "sde_config.yaml"))
    candidates.append(os.path.join(os.getcwd(), "sde_config.yaml"))
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    return None


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base`` (nested keys preserved)."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


@lru_cache(maxsize=4)
def load_sde_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load the SDE configuration, falling back to embedded defaults."""
    target = _resolve_config_path(config_path)
    if target:
        try:
            with open(target, "r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            if isinstance(data, dict) and data:
                return _deep_merge(DEFAULT_SDE_CONFIG, data)
        except Exception as exc:  # pragma: no cover - defensive
            import logging

            logging.getLogger("agentpoi_sde.config_loader").warning(
                "Failed to parse SDE config at %s: %s. Using defaults.", target, exc
            )
    return copy.deepcopy(DEFAULT_SDE_CONFIG)


def get_invariant_config() -> Dict[str, bool]:
    """Return the invariant enablement flags."""
    return dict(load_sde_config().get("invariants", {}))


def get_protected_paths() -> list:
    """Return the protected (policy/CI/manifest) path patterns."""
    return list(load_sde_config().get("protected_paths", []))


def get_test_markers() -> list:
    """Return the path markers that identify test files."""
    return list(load_sde_config().get("test_markers", []))


def get_egress_allowlist() -> list:
    """Return the allow-listed egress prefixes."""
    return list(load_sde_config().get("egress_allowlist", []))
