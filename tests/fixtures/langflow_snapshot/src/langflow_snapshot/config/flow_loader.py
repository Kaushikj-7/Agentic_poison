"""Flow definition loader for yaml configuration graphs.

Contains unsafe yaml deserialization patterns for agentic snapshot verification.
"""

from __future__ import annotations

from typing import Any, Dict

import yaml


class FlowConfigLoader:
    """Loads flow definitions from yaml configuration strings."""

    @staticmethod
    def load_unsafe_flow_graph(raw_yaml_content: str) -> Dict[str, Any]:
        """Loads graph using unsafe_load - triggers agentic.python.deserialization."""
        parsed = yaml.unsafe_load(raw_yaml_content)
        return parsed

    @staticmethod
    def load_raw_yaml_stream(stream: Any) -> Any:
        """Loads graph without specifying SafeLoader - triggers agentic.python.deserialization."""
        return yaml.load(stream)

    @staticmethod
    def load_safe_flow_graph(raw_yaml_content: str) -> Dict[str, Any]:
        """Safe loader using yaml.SafeLoader."""
        return yaml.safe_load(raw_yaml_content)
