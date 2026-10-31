"""Configuration Loader for CTP & CIV Defense Framework.

Provides centralized access to config.yaml parameters ensuring synchronized runtime defaults
across development trees, package wheels, and air-gapped environments.
"""

import copy
import os
from functools import lru_cache
from typing import Any, Dict, Optional

import yaml

try:
    from dotenv import load_dotenv
    # Auto-load the .env file from the repo root if it exists
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
except ImportError:
    pass


DEFAULT_CONFIG: Dict[str, Any] = {
    "version": "1.0.0",
    "trust_model": {
        "lambda_decay": 2.5,
        "tau_threshold": 0.50,
        "tau_critical": 0.25,
        "source_priors": {
            "verified_user": 0.95,
            "system_instruction": 0.90,
            "internal_tool": 0.65,
            "external_api": 0.40,
            "untrusted_web": 0.25,
            "anonymous_peer": 0.15,
        },
        "risk_weights": {
            "self_asserted_auth": 0.45,
            "imperative_density": 0.25,
            "type_mismatch": 0.20,
            "suspicious_framing": 0.10,
        },
    },
    "retrieval_gate": {
        "enabled": True,
        "min_task_similarity": 0.35,
        "max_divergence_penalty": 0.35,
    },
    "runtime": {
        "mode": "mock",
        "ollama": {
            "base_url": "http://localhost:11434",
            "model": "llama3.2:3b",
            "timeout_seconds": 30,
        },
    },
    "storage": {
        "vector_db_type": "fallback",
        "persist_directory": "data/memory_store",
        "embedding_dimension": 384,
    },
    "financial_domain": {
        "per_transaction_limit": 25000.0,
        "daily_limit": 100000.0,
        "relevance_threshold": 0.0,
        "max_divergence_risk": 0.35,
    },
}


def _resolve_config_path(override_path: Optional[str] = None) -> Optional[str]:
    """Resolve the path to config.yaml across package, repo, and environment locations."""
    if override_path and os.path.exists(override_path):
        return os.path.abspath(override_path)

    env_path = os.environ.get("AGENT_POI_CONFIG")
    if env_path and os.path.exists(env_path):
        return os.path.abspath(env_path)

    # 1. Look inside package directory: agent_poi/config.yaml
    pkg_config = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config.yaml"))
    if os.path.exists(pkg_config):
        return pkg_config

    # 2. Look in repository root: ../../config.yaml
    repo_config = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml"))
    if os.path.exists(repo_config):
        return repo_config

    # 3. Look in current working directory: ./config.yaml
    cwd_config = os.path.abspath(os.path.join(os.getcwd(), "config.yaml"))
    if os.path.exists(cwd_config):
        return cwd_config

    return None


class ConfigurationError(ValueError):
    """Raised when configuration validation encounters invalid or dead keys."""
    pass


def validate_config(data: Dict[str, Any]) -> None:
    """Validate that configuration dictionary contains only supported active keys."""
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a dictionary.")
    for section in data:
        if section not in DEFAULT_CONFIG and section not in ("scanners", "invariants", "models"):
            raise ConfigurationError(f"Unknown or dead configuration section: '{section}'.")


@lru_cache(maxsize=4)
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration dictionary from YAML file, falling back to embedded defaults."""
    target_path = _resolve_config_path(config_path)
    if target_path and os.path.exists(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and data:
                validate_config(data)
                return data
        except ConfigurationError:
            raise
        except Exception as exc:
            import logging
            logging.getLogger("agent_poi.core.config_loader").warning(
                "Failed to parse config YAML at %s: %s. Falling back to defaults.", target_path, exc
            )

    return copy.deepcopy(DEFAULT_CONFIG)


def get_trust_model_config() -> Dict[str, Any]:
    """Retrieve trust model configuration parameters."""
    cfg = load_config()
    return cfg.get("trust_model", {})


def get_financial_domain_config() -> Dict[str, Any]:
    """Retrieve financial domain parameters."""
    cfg = load_config()
    return cfg.get("financial_domain", {})
