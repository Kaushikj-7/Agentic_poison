"""Configuration Loader for CTP & CIV Defense Framework.

Provides centralized access to config.yaml parameters ensuring synchronized runtime defaults.
"""

import os
from functools import lru_cache
from typing import Any, Dict
import yaml


_CONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config.yaml")
)


@lru_cache(maxsize=1)
def load_config(config_path: str = _CONFIG_PATH) -> Dict[str, Any]:
    """Load configuration dictionary from YAML file."""
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def get_trust_model_config() -> Dict[str, Any]:
    """Retrieve trust model configuration parameters."""
    cfg = load_config()
    return cfg.get("trust_model", {})


def get_financial_domain_config() -> Dict[str, Any]:
    """Retrieve financial domain parameters."""
    cfg = load_config()
    return cfg.get("financial_domain", {})
